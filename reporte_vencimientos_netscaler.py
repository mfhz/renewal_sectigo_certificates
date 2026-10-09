#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reporte_vencimientos_netscaler.py

Gestiona los certificados del NetScaler a través de una lista de
SharePoint, con aprobación manual por la columna "Estado":

  1. EMISIONES APROBADAS: los items de la lista con Estado = "Emitir"
     se renuevan con el flujo completo del script principal (Sectigo ->
     .pfx -> NetScaler). El item pasa a "En proceso" antes de pedir el
     certificado y termina en "Emitido" o "Error" (motivo en Detalle).

  2. REPORTE: lee los sslcertkey del NetScaler y deja en la lista los
     que están por vencer, con Estado = "Pendiente".
       - Un item por certkey; si ya existe se actualiza (llave: CertKey +
         NetScaler). La actualización NUNCA toca Estado ni Referencia,
         que son de la persona.
       - Los items existentes se refrescan aunque ya no estén por vencer,
         para que DiasParaVencer no quede desactualizado.
       - Un item "Emitido" vuelve a "Pendiente" cuando el certificado
         renovado está por vencer otra vez (la emisión fue antes de que
         ese certificado entrara en la ventana).
       - Si un certkey ya no existe en el NetScaler, se marca
         EstadoNetScaler = "No existe en NetScaler".
       - Los certificados de CA no tienen llave privada en el NetScaler y
         no se reportan.
       - SslIdSectigo se llena buscando en Sectigo el mismo número de
         serie. Si queda vacío (no es de Sectigo o no se encontró), se
         puede escribir a mano antes de poner "Emitir".

Columnas de la lista (si faltan, el script intenta crearlas):
  Title (Dominio), Estado, Referencia, CertKey, SslIdSectigo, Archivo,
  Emisor, Serial, FechaVencimiento, DiasParaVencer, EstadoNetScaler,
  NetScaler, FechaEmision, Detalle, UltimaRevision

Para aprobar una renovación: escribir "Emitir" en Estado y la OC en
Referencia (si Referencia está vacía se usa --referencia).

------------------------------------------------------------------
VARIABLES DE ENTORNO
------------------------------------------------------------------
  SCM_BASE_URL / SCM_LOGIN / SCM_PASSWORD / SCM_CUSTOMER_URI
  NS_HOST / NS_USER / NS_PASSWORD / NS_VERIFY_TLS
  GRAPH_TENANT_ID / GRAPH_CLIENT_ID / GRAPH_CLIENT_SECRET
  SP_LISTA_URL   URL de la lista, tal como se ve en el navegador, ej:
                 https://suramericana.sharepoint.com/sites/Gestion_DefenderEDR/Lists/Pruebas

------------------------------------------------------------------
USO
------------------------------------------------------------------
  # Simulación: muestra qué emitiría y qué reportaría, sin escribir nada
  python reporte_vencimientos_netscaler.py --ventana-dias 60

  # Ejecución real
  python reporte_vencimientos_netscaler.py --ventana-dias 60 --referencia "OC-12345" --ejecutar
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from renovacion_certificados_sectigo import (
    ESTADO_EMITIDO,
    ESTADO_EN_PROCESO,
    ESTADO_ERROR,
    ESTADO_PENDIENTE,
    RUN_ID,
    ClienteNetScaler,
    ClienteSCM,
    ConfigNetScaler,
    ConfigSCM,
    DominioNoValidadoError,
    NetScalerError,
    OpenSSLError,
    SCMError,
    campo_dn,
    configurar_logging,
    es_emitir,
    flujo_renovacion,
    log,
    normalizar_serial,
)
from sharepoint_graph import ClienteGraph, ConfigGraph, ListaSharePoint, SharePointError, requerir_entorno

VENTANA_DIAS_DEFAULT = 60

# Title es la columna que trae toda lista por defecto; ahí va el dominio.
COLUMNAS_LISTA = {
    "Estado": "texto",
    "Referencia": "texto",
    "CertKey": "texto",
    "SslIdSectigo": "texto",
    "Archivo": "texto",
    "Emisor": "texto",
    "Serial": "texto",
    "FechaVencimiento": "fecha",
    "DiasParaVencer": "numero",
    "EstadoNetScaler": "texto",
    "NetScaler": "texto",
    "FechaEmision": "fechahora",
    "Detalle": "texto",
    "UltimaRevision": "fechahora",
}

ESTADO_NO_EXISTE = "No existe en NetScaler"


def ahora_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parsear_fecha_netscaler(valor: str) -> Optional[datetime]:
    """NITRO entrega las fechas como 'Apr  8 23:59:59 2027 GMT'."""
    try:
        return datetime.strptime(" ".join((valor or "").split()), "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def construir_fila(certkey: dict, host_ns: str, ahora: datetime) -> dict:
    """Campos que salen del NetScaler. No incluye Estado ni Referencia: esos son de la persona."""
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


def indexar_sectigo_por_serial(cliente: ClienteSCM) -> dict[str, int]:
    """{serial normalizado: sslId}. Si Sectigo no responde, se sigue sin SslIdSectigo."""
    try:
        certificados = cliente.listar_certificados()
    except SCMError as e:
        log.warning(f"[SCM] No se pudo listar certificados para cruzar con el NetScaler: {e}")
        return {}
    indice = {normalizar_serial(c.get("serialNumber", "")): c["sslId"]
              for c in certificados if c.get("serialNumber") and c.get("sslId")}
    log.info(f"[SCM] {len(certificados)} certificados listados para cruzar por número de serie.")
    return indice


class GestorLista:
    def __init__(self, graph: ClienteGraph, lista: ListaSharePoint, internos: dict[str, str], host_ns: str):
        self.graph = graph
        self.lista = lista
        self.internos = internos
        self.host_ns = host_ns

    def campo(self, item: dict, nombre: str):
        return item.get("fields", {}).get(self.internos[nombre])

    def items_del_netscaler(self) -> list[dict]:
        return [it for it in self.graph.listar_items(self.lista)
                if self.campo(it, "NetScaler") == self.host_ns and self.campo(it, "CertKey")]

    def actualizar(self, item_id: str, campos: dict) -> None:
        self.graph.actualizar_item(self.lista, item_id, a_campos_internos(campos, self.internos))

    def crear(self, campos: dict) -> None:
        self.graph.crear_item(self.lista, a_campos_internos(campos, self.internos))


def procesar_emisiones(gestor: GestorLista, cliente: ClienteSCM, indice_sectigo: dict[str, int],
                       referencia_default: Optional[str], directorio_trabajo: Path,
                       ejecutar: bool) -> tuple[int, int]:
    """Renueva los items con Estado = "Emitir". Devuelve (emitidos, errores)."""
    aprobados = [it for it in gestor.items_del_netscaler() if es_emitir(gestor.campo(it, "Estado"))]
    log.info(f"[Emisiones] {len(aprobados)} item(s) con Estado = 'Emitir'.")

    emitidos = errores = 0
    for item in aprobados:
        certkey = gestor.campo(item, "CertKey")
        dominio = gestor.campo(item, "Title")
        referencia = (gestor.campo(item, "Referencia") or referencia_default or "").strip()
        ssl_id_texto = str(gestor.campo(item, "SslIdSectigo") or "").strip()
        ssl_id = int(ssl_id_texto) if ssl_id_texto.isdigit() else \
            indice_sectigo.get(normalizar_serial(gestor.campo(item, "Serial") or ""))

        log.info(f"--- Emitir {dominio} (certkey={certkey}, sslId={ssl_id}, referencia={referencia!r}) ---")

        motivo = None
        if not ssl_id:
            motivo = ("No se encontró el certificado en Sectigo por número de serie. "
                      "Escribe el sslId en SslIdSectigo y vuelve a poner 'Emitir'.")
        elif not referencia:
            motivo = "Falta la Referencia (OC). Llénala y vuelve a poner 'Emitir'."
        if motivo:
            log.error(f"[{dominio}] {motivo}")
            if ejecutar:
                gestor.actualizar(item["id"], {"Estado": ESTADO_ERROR, "Detalle": motivo})
            errores += 1
            continue

        if not ejecutar:
            log.info(f"[DRY-RUN] Se renovaría sslId={ssl_id} y se subiría al NetScaler como '{certkey}'.")
            continue

        gestor.actualizar(item["id"], {"Estado": ESTADO_EN_PROCESO, "Detalle": f"Iniciado run_id={RUN_ID}"})
        try:
            resultado = flujo_renovacion(
                cliente=cliente,
                ssl_id_actual=ssl_id,
                referencia=referencia,
                domain_id=None,
                ventana_dias=0,
                directorio_trabajo=directorio_trabajo / certkey,
                ejecutar=True,
                subir_netscaler=True,
                netscaler_certkey=certkey,
                omitir_ventana=True,
            )
            gestor.actualizar(item["id"], {
                "Estado": ESTADO_EMITIDO,
                "SslIdSectigo": str(resultado.ssl_id_nuevo),
                "FechaEmision": ahora_iso(),
                "Detalle": f"Nuevo sslId {resultado.ssl_id_nuevo}, instalado en el NetScaler.",
            })
            emitidos += 1
        except (SCMError, DominioNoValidadoError, OpenSSLError, NetScalerError) as e:
            log.error(f"[{dominio}] {e}")
            gestor.actualizar(item["id"], {"Estado": ESTADO_ERROR, "Detalle": str(e)[:255]})
            errores += 1

    return emitidos, errores


def inicia_ciclo_nuevo(gestor: GestorLista, item: dict, dias: Optional[int], ventana_dias: int,
                       ahora: datetime) -> bool:
    """
    Un item "Emitido" vuelve a "Pendiente" cuando el certificado instalado
    entra otra vez en la ventana, pero solo si la emisión fue ANTES de que
    ese certificado entrara en la ventana. Así, uno recién emitido no se
    devuelve a Pendiente cuando la ventana es más larga que su vigencia
    (ej. --ventana-dias 400 con certificados de 199 días).
    """
    if str(gestor.campo(item, "Estado") or "").strip() != ESTADO_EMITIDO:
        return False
    if dias is None or dias > ventana_dias:
        return False
    try:
        fecha_emision = datetime.strptime(str(gestor.campo(item, "FechaEmision")), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return True  # Emitido sin fecha de emisión: no hay cómo saber, se trata como ciclo nuevo
    entrada_en_ventana = ahora.replace(tzinfo=None) + timedelta(days=dias - ventana_dias)
    return fecha_emision < entrada_en_ventana


def sincronizar_reporte(gestor: GestorLista, ns: ClienteNetScaler, indice_sectigo: dict[str, int],
                        ventana_dias: int, ejecutar: bool) -> int:
    """Crea/actualiza los items del reporte. Devuelve la cantidad de errores."""
    ahora = datetime.now(timezone.utc)

    certkeys = ns.listar_certkeys()
    servidores = [c for c in certkeys if c.get("key")]
    log.info(f"[NetScaler] {len(certkeys)} sslcertkey en {gestor.host_ns}; "
             f"{len(servidores)} de servidor (se omiten {len(certkeys) - len(servidores)} de CA).")

    filas = {}
    for c in servidores:
        fila = construir_fila(c, gestor.host_ns, ahora)
        ssl_id = indice_sectigo.get(normalizar_serial(fila["Serial"]))
        fila["SslIdSectigo"] = str(ssl_id) if ssl_id else None
        filas[c["certkey"]] = fila

    existentes = {gestor.campo(it, "CertKey"): it for it in gestor.items_del_netscaler()}

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
        return 0

    errores = 0
    operaciones = (
        [(None, {**filas[k], "Estado": ESTADO_PENDIENTE}) for k in a_crear] +
        [(existentes[k], filas[k]) for k in a_actualizar] +
        [(existentes[k], {"EstadoNetScaler": ESTADO_NO_EXISTE, "UltimaRevision": ahora_iso()})
         for k in desaparecidos]
    )
    for item, campos in operaciones:
        try:
            if item is None:
                gestor.crear(campos)
                continue
            if inicia_ciclo_nuevo(gestor, item, campos.get("DiasParaVencer"), ventana_dias, ahora):
                campos = {**campos, "Estado": ESTADO_PENDIENTE, "Detalle": ""}
            gestor.actualizar(item["id"], campos)
        except SharePointError as e:
            errores += 1
            log.error(str(e))

    log.info(f"[Reporte] creados={len(a_crear)} actualizados={len(a_actualizar)} "
             f"no_existen={len(desaparecidos)} errores={errores}")
    return errores


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reporta en SharePoint los certificados del NetScaler por vencer y renueva los aprobados ('Emitir')."
    )
    parser.add_argument("--ventana-dias", type=int, default=VENTANA_DIAS_DEFAULT,
                        help=f"Días antes del vencimiento para reportar (default {VENTANA_DIAS_DEFAULT}).")
    parser.add_argument("--referencia", default=None,
                        help="OC por defecto para los items aprobados que no tengan Referencia.")
    parser.add_argument("--ejecutar", action="store_true",
                        help="Sin esta bandera solo simula (no emite ni escribe en la lista).")
    parser.add_argument("--directorio-trabajo", default="./trabajo_certificados")
    parser.add_argument("--log-dir", default="./logs")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    configurar_logging(Path(args.log_dir), args.log_level, "reporte_vencimientos_netscaler.log")

    url_lista = requerir_entorno("SP_LISTA_URL")["SP_LISTA_URL"]
    cliente = ClienteSCM(ConfigSCM.desde_entorno())
    ns = ClienteNetScaler(ConfigNetScaler.desde_entorno())
    graph = ClienteGraph(ConfigGraph.desde_entorno())

    try:
        lista = graph.resolver_lista(url_lista)
        log.info(f"[SharePoint] Lista '{lista.nombre}' resuelta.")
        internos = {"Title": "Title", **(graph.asegurar_columnas(lista, COLUMNAS_LISTA) if args.ejecutar
                                         else {n: n for n in COLUMNAS_LISTA})}
        gestor = GestorLista(graph, lista, internos, ns.config.host)
        indice_sectigo = indexar_sectigo_por_serial(cliente)

        emitidos, errores_emision = procesar_emisiones(
            gestor, cliente, indice_sectigo, args.referencia, Path(args.directorio_trabajo), args.ejecutar)
        errores_reporte = sincronizar_reporte(gestor, ns, indice_sectigo, args.ventana_dias, args.ejecutar)

        errores = errores_emision + errores_reporte
        log.info(f"RESULTADO run_id={RUN_ID} estado={'OK' if not errores else 'CON_ERRORES'} "
                 f"emitidos={emitidos} errores_emision={errores_emision} errores_reporte={errores_reporte}")
        if errores:
            sys.exit(1)
    except (NetScalerError, SharePointError, SCMError) as e:
        log.error(f"RESULTADO run_id={RUN_ID} estado=ERROR mensaje={e}")
        sys.exit(1)
    except Exception:
        log.exception(f"RESULTADO run_id={RUN_ID} estado=ERROR_INESPERADO")
        sys.exit(1)
    finally:
        log.info(f"=== Fin de ejecución (run_id={RUN_ID}) ===")


if __name__ == "__main__":
    main()
