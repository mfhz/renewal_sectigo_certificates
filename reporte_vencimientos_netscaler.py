#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reporte_vencimientos_netscaler.py

Lee los certificados (sslcertkey) instalados en el NetScaler y deja en
una lista de SharePoint los que están por vencer, con su dominio,
fecha de vencimiento y días restantes.

  - Un item por certkey del NetScaler. Si ya existe en la lista, se
    actualiza en vez de duplicarse (la llave es CertKey + NetScaler).
  - Los items que ya estaban en la lista se refrescan en cada corrida
    aunque ya no estén por vencer (por ejemplo, porque se renovaron),
    para que DiasParaVencer no quede desactualizado.
  - Si un certkey de la lista ya no existe en el NetScaler, se marca
    EstadoNetScaler = "No existe en NetScaler".
  - Los certificados de CA (intermedias/raíz) no tienen llave privada
    en el NetScaler y no se reportan.

Columnas de la lista (si faltan, el script intenta crearlas):
  Title (Dominio), CertKey, Archivo, Emisor, Serial, FechaVencimiento,
  DiasParaVencer, EstadoNetScaler, NetScaler, UltimaRevision

------------------------------------------------------------------
VARIABLES DE ENTORNO
------------------------------------------------------------------
  NS_HOST / NS_USER / NS_PASSWORD / NS_VERIFY_TLS   (igual que el script principal)
  GRAPH_TENANT_ID / GRAPH_CLIENT_ID / GRAPH_CLIENT_SECRET
  SP_LISTA_URL   URL de la lista, tal como se ve en el navegador, ej:
                 https://suramericana.sharepoint.com/sites/Gestion_DefenderEDR/Lists/Pruebas

------------------------------------------------------------------
USO
------------------------------------------------------------------
  # Simulación: muestra qué se crearía o actualizaría, sin escribir en la lista
  python reporte_vencimientos_netscaler.py --ventana-dias 60

  # Escribir en la lista
  python reporte_vencimientos_netscaler.py --ventana-dias 60 --ejecutar
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from renovacion_certificados_sectigo import (
    RUN_ID,
    ClienteNetScaler,
    ConfigNetScaler,
    NetScalerError,
    configurar_logging,
    log,
)
from sharepoint_graph import ClienteGraph, ConfigGraph, SharePointError, requerir_entorno

VENTANA_DIAS_DEFAULT = 60

# Title es la columna que trae toda lista por defecto; ahí va el dominio.
COLUMNAS_LISTA = {
    "CertKey": "texto",
    "Archivo": "texto",
    "Emisor": "texto",
    "Serial": "texto",
    "FechaVencimiento": "fecha",
    "DiasParaVencer": "numero",
    "EstadoNetScaler": "texto",
    "NetScaler": "texto",
    "UltimaRevision": "fechahora",
}

ESTADO_NO_EXISTE = "No existe en NetScaler"


def campo_dn(dn: str, clave: str) -> str:
    """Extrae un atributo (CN, O...) de un subject/issuer como 'C=CO,O=Sura,CN=host.sura.com'."""
    m = re.search(rf"(?:^|[,/]\s*){clave}=([^,/]+)", dn or "")
    return m.group(1).strip() if m else ""


def parsear_fecha_netscaler(valor: str) -> Optional[datetime]:
    """NITRO entrega las fechas como 'Apr  8 23:59:59 2027 GMT'."""
    try:
        return datetime.strptime(" ".join((valor or "").split()), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def construir_fila(certkey: dict, host_ns: str, ahora: datetime) -> dict:
    vence = parsear_fecha_netscaler(certkey.get("clientcertnotafter", ""))
    dias = certkey.get("daystoexpiration")
    if dias is None and vence is not None:
        dias = (vence - ahora.replace(tzinfo=None)).days

    return {
        "Title": campo_dn(certkey.get("subject", ""), "CN") or certkey.get("certkey"),
        "CertKey": certkey.get("certkey"),
        "Archivo": certkey.get("cert", ""),
        "Emisor": campo_dn(certkey.get("issuer", ""), "CN") or certkey.get("issuer", ""),
        "Serial": certkey.get("serial", ""),
        # A mediodía UTC para que la columna de solo fecha no muestre el día
        # anterior en la zona horaria de Colombia.
        "FechaVencimiento": f"{vence:%Y-%m-%d}T12:00:00Z" if vence else None,
        "DiasParaVencer": int(dias) if dias is not None else None,
        "EstadoNetScaler": certkey.get("status", ""),
        "NetScaler": host_ns,
        "UltimaRevision": ahora.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def a_campos_internos(fila: dict, internos: dict[str, str]) -> dict:
    """Traduce nombres visibles a internos y omite los valores vacíos (Graph rechaza null en algunos tipos)."""
    return {internos.get(k, k): v for k, v in fila.items() if v is not None}


def sincronizar(ns: ClienteNetScaler, graph: ClienteGraph, url_lista: str,
                ventana_dias: int, ejecutar: bool) -> None:
    host_ns = ns.config.host
    ahora = datetime.now(timezone.utc)

    certkeys = ns.listar_certkeys()
    servidores = [c for c in certkeys if c.get("key")]
    log.info(f"[NetScaler] {len(certkeys)} sslcertkey en {host_ns}; "
             f"{len(servidores)} de servidor (se omiten {len(certkeys) - len(servidores)} de CA).")

    filas = {c["certkey"]: construir_fila(c, host_ns, ahora) for c in servidores}

    lista = graph.resolver_lista(url_lista)
    log.info(f"[SharePoint] Lista '{lista.nombre}' resuelta.")
    internos = {"Title": "Title", **graph.asegurar_columnas(lista, COLUMNAS_LISTA)} if ejecutar \
        else {"Title": "Title", **{n: n for n in COLUMNAS_LISTA}}

    # Items que ya están en la lista para este NetScaler: certkey -> item_id
    existentes: dict[str, str] = {}
    for item in graph.listar_items(lista):
        campos = item.get("fields", {})
        if campos.get(internos["NetScaler"]) == host_ns and campos.get(internos["CertKey"]):
            existentes[campos[internos["CertKey"]]] = item["id"]

    por_vencer = {k: f for k, f in filas.items()
                  if f["DiasParaVencer"] is not None and f["DiasParaVencer"] <= ventana_dias}
    a_crear = [k for k in por_vencer if k not in existentes]
    a_actualizar = [k for k in existentes if k in filas]
    desaparecidos = [k for k in existentes if k not in filas]

    for k in sorted(por_vencer, key=lambda k: por_vencer[k]["DiasParaVencer"]):
        f = por_vencer[k]
        log.info(f"  Por vencer: {f['Title']} (certkey={k}) vence {f['FechaVencimiento'] or '?'} "
                 f"-> {f['DiasParaVencer']} días")
    log.info(f"Plan: crear {len(a_crear)}, actualizar {len(a_actualizar)}, "
             f"marcar {len(desaparecidos)} como '{ESTADO_NO_EXISTE}' (ventana {ventana_dias} días).")

    if not ejecutar:
        log.info("[DRY-RUN] No se escribe en la lista. Corre con --ejecutar para hacerlo.")
        return

    errores = 0
    for k in a_crear:
        try:
            graph.crear_item(lista, a_campos_internos(filas[k], internos))
        except SharePointError as e:
            errores += 1
            log.error(str(e))
    for k in a_actualizar:
        try:
            graph.actualizar_item(lista, existentes[k], a_campos_internos(filas[k], internos))
        except SharePointError as e:
            errores += 1
            log.error(str(e))
    for k in desaparecidos:
        try:
            graph.actualizar_item(lista, existentes[k], a_campos_internos(
                {"EstadoNetScaler": ESTADO_NO_EXISTE,
                 "UltimaRevision": ahora.strftime("%Y-%m-%dT%H:%M:%SZ")}, internos))
        except SharePointError as e:
            errores += 1
            log.error(str(e))

    log.info(f"RESULTADO run_id={RUN_ID} estado={'OK' if not errores else 'CON_ERRORES'} "
             f"creados={len(a_crear)} actualizados={len(a_actualizar)} "
             f"no_existen={len(desaparecidos)} errores={errores}")
    if errores:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reporta en una lista de SharePoint los certificados del NetScaler por vencer."
    )
    parser.add_argument("--ventana-dias", type=int, default=VENTANA_DIAS_DEFAULT,
                        help=f"Días antes del vencimiento para reportar (default {VENTANA_DIAS_DEFAULT}).")
    parser.add_argument("--ejecutar", action="store_true",
                        help="Sin esta bandera solo simula (no escribe en la lista).")
    parser.add_argument("--log-dir", default="./logs")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    configurar_logging(Path(args.log_dir), args.log_level, "reporte_vencimientos_netscaler.log")

    url_lista = requerir_entorno("SP_LISTA_URL")["SP_LISTA_URL"]
    ns = ClienteNetScaler(ConfigNetScaler.desde_entorno())
    graph = ClienteGraph(ConfigGraph.desde_entorno())

    try:
        sincronizar(ns, graph, url_lista, args.ventana_dias, args.ejecutar)
    except (NetScalerError, SharePointError) as e:
        log.error(f"RESULTADO run_id={RUN_ID} estado=ERROR mensaje={e}")
        sys.exit(1)
    except Exception:
        log.exception(f"RESULTADO run_id={RUN_ID} estado=ERROR_INESPERADO")
        sys.exit(1)
    finally:
        log.info(f"=== Fin de ejecución (run_id={RUN_ID}) ===")


if __name__ == "__main__":
    main()
