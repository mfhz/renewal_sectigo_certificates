#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
renovacion_certificados_nube.py

Renueva los certificados de Sectigo que están por vencer y que NO están
instalados en el NetScaler (certificados de nube). Para estos no hay
dónde instalarlos automáticamente, así que el resultado queda en
SharePoint para que el responsable lo instale:

  1. Lista los certificados de SCM y se queda con los Issued que
     vencen dentro de la ventana.
  2. Descarta los que ya están en el NetScaler (por CN o por número de
     serie); esos los gestiona renovacion_certificados_sectigo.py.
  3. Descarta los que ya tienen una renovación (otro certificado con el
     mismo CN emitido con vigencia de sobra, o en curso), para no
     renovar dos veces el mismo certificado.
  4. Para cada uno repite el flujo del script principal: llave + CSR,
     enroll, descarga, .pem -> .pfx y contraseña.
  5. Crea en SharePoint una carpeta con el nombre del certificado y sube
     ahí el .pfx y el .password.txt.
  6. Agrega una fila por certificado (OK o ERROR) al Excel de control.

------------------------------------------------------------------
VARIABLES DE ENTORNO
------------------------------------------------------------------
  SCM_BASE_URL / SCM_LOGIN / SCM_PASSWORD / SCM_CUSTOMER_URI
  NS_HOST / NS_USER / NS_PASSWORD / NS_VERIFY_TLS     (solo lectura, para descartar)
  GRAPH_TENANT_ID / GRAPH_CLIENT_ID / GRAPH_CLIENT_SECRET
  SP_DRIVE_ID           id de la biblioteca de documentos (mismo DRIVE_ID
                        del proyecto automatization_microsoft_defender_intune)
  SP_RUTA_CARPETA_NUBE  carpeta donde se crea una subcarpeta por certificado,
                        ej: IT-CIBER-SEGURIDAD/Defender/Pruebas
  SP_RUTA_EXCEL_NUBE    Excel de control,
                        ej: IT-CIBER-SEGURIDAD/Defender/Pruebas/Pruebas.xlsx

------------------------------------------------------------------
USO
------------------------------------------------------------------
  # Simulación: lista qué certificados se renovarían, sin tocar nada
  python renovacion_certificados_nube.py --referencia "OC-12345" --ventana-dias 30

  # Probar con un solo certificado
  python renovacion_certificados_nube.py --referencia "OC-12345" --ssl-id 12223558 --ejecutar

  # Ejecución real, máximo 5 certificados por corrida
  python renovacion_certificados_nube.py --referencia "OC-12345" --max-certificados 5 --ejecutar
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from renovacion_certificados_sectigo import (
    RUN_ID,
    VENTANA_RENOVACION_DIAS_DEFAULT,
    ClienteNetScaler,
    ClienteSCM,
    ConfigNetScaler,
    ConfigSCM,
    DominioNoValidadoError,
    NetScalerError,
    OpenSSLError,
    SCMError,
    configurar_logging,
    dias_para_expirar,
    extraer_sans,
    flujo_renovacion,
    log,
)
from reporte_vencimientos_netscaler import campo_dn
from sharepoint_graph import ClienteGraph, ConfigGraph, SharePointError, requerir_entorno

ENCABEZADOS_EXCEL = [
    "FechaRenovacion", "CommonName", "SANs", "SslIdAnterior", "VencimientoAnterior",
    "SslIdNuevo", "Referencia", "CarpetaSharePoint", "Estado", "Detalle",
]

# Estados de SCM que indican que ya hay una solicitud en curso para ese CN.
ESTADOS_EN_CURSO = {"applied", "requested", "approved", "under review", "pending"}


def nombre_seguro_sharepoint(nombre: str) -> str:
    """SharePoint no admite " * : < > ? / \\ | en nombres; un wildcard queda como 'wildcard.dominio.com'."""
    nombre = nombre.replace("*", "wildcard")
    return re.sub(r'["*:<>?/\\|#%]', "_", nombre).strip(" .")


def normalizar_serial(serial: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", serial or "").upper().lstrip("0")


def completar_detalle(cliente: ClienteSCM, cert: dict) -> dict:
    """El listado de SCM puede no traer status/expires: en ese caso se consulta el detalle."""
    if cert.get("expires") and cert.get("status"):
        return cert
    return {**cert, **cliente.obtener_certificado(cert["sslId"])}


def seleccionar_candidatos(cliente: ClienteSCM, ns: ClienteNetScaler,
                           ventana_dias: int, solo_ssl_id: Optional[int]) -> list[dict]:
    certkeys = ns.listar_certkeys()
    cns_netscaler = {campo_dn(c.get("subject", ""), "CN").lower() for c in certkeys} - {""}
    seriales_netscaler = {normalizar_serial(c.get("serial", "")) for c in certkeys} - {""}
    log.info(f"[NetScaler] {len(certkeys)} sslcertkey leídos para descartar los que ya están instalados.")

    if solo_ssl_id:
        certificados = [cliente.obtener_certificado(solo_ssl_id)]
    else:
        certificados = cliente.listar_certificados()
        log.info(f"[SCM] {len(certificados)} certificados listados; consultando estado y vencimiento...")
        certificados = [completar_detalle(cliente, c) for c in certificados]

    por_cn: dict[str, list[dict]] = {}
    for c in certificados:
        por_cn.setdefault((c.get("commonName") or "").lower(), []).append(c)

    candidatos = []
    for cert in certificados:
        cn = cert.get("commonName") or ""
        estado = (cert.get("status") or "").lower()
        if estado != "issued" or not cert.get("expires"):
            continue
        dias = dias_para_expirar(cert["expires"])
        if dias > ventana_dias:
            continue

        if cn.lower() in cns_netscaler or normalizar_serial(cert.get("serialNumber", "")) in seriales_netscaler:
            log.info(f"  Omitido {cn} (sslId={cert['sslId']}): está en el NetScaler, "
                     f"lo gestiona renovacion_certificados_sectigo.py.")
            continue

        otros = [o for o in por_cn.get(cn.lower(), []) if o.get("sslId") != cert.get("sslId")]
        ya_renovado = any(
            (o.get("status") or "").lower() in ESTADOS_EN_CURSO
            or ((o.get("status") or "").lower() == "issued" and o.get("expires")
                and dias_para_expirar(o["expires"]) > ventana_dias)
            for o in otros
        )
        if ya_renovado:
            log.info(f"  Omitido {cn} (sslId={cert['sslId']}): ya tiene otro certificado "
                     f"emitido o en curso con el mismo CN.")
            continue

        log.info(f"  Candidato: {cn} (sslId={cert['sslId']}) vence {cert['expires']} -> {dias} días")
        candidatos.append(cert)

    return candidatos


def renovar_y_publicar(cliente: ClienteSCM, graph: ClienteGraph, cert: dict, referencia: str,
                       ventana_dias: int, directorio_trabajo: Path, ejecutar: bool,
                       drive_id: str, ruta_carpeta: str) -> Optional[dict]:
    cn = cert["commonName"]
    fila = {
        "FechaRenovacion": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "CommonName": cn,
        "SANs": ", ".join(extraer_sans(cert)),
        "SslIdAnterior": cert["sslId"],
        "VencimientoAnterior": cert.get("expires", ""),
        "Referencia": referencia,
    }

    nombre_carpeta = nombre_seguro_sharepoint(cn)
    resultado = None
    try:
        resultado = flujo_renovacion(
            cliente=cliente,
            ssl_id_actual=cert["sslId"],
            referencia=referencia,
            domain_id=None,
            ventana_dias=ventana_dias,
            directorio_trabajo=directorio_trabajo / nombre_carpeta,
            ejecutar=ejecutar,
        )
        if resultado is None:
            return None  # dry-run

        fila["SslIdNuevo"] = resultado.ssl_id_nuevo
        carpeta = graph.crear_carpeta(drive_id, ruta_carpeta, nombre_carpeta)
        for ruta_local in (resultado.ruta_pfx, resultado.ruta_password):
            graph.subir_archivo(drive_id, f"{ruta_carpeta}/{nombre_carpeta}/{nombre_seguro_sharepoint(ruta_local.name)}",
                                ruta_local.read_bytes())
        fila["CarpetaSharePoint"] = carpeta.get("webUrl", f"{ruta_carpeta}/{nombre_carpeta}")
        fila["Estado"] = "OK"
    except (SCMError, DominioNoValidadoError, OpenSSLError, SharePointError) as e:
        log.error(f"[{cn}] {e}")
        if resultado is not None:
            log.error(f"[{cn}] El certificado SÍ se emitió (sslId={resultado.ssl_id_nuevo}); el .pfx "
                      f"quedó local en {resultado.ruta_pfx}. Súbelo a mano a SharePoint.")
        fila["Estado"] = "ERROR"
        fila["Detalle"] = str(e)[:500]
    return fila


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Renueva certificados de nube (los que no están en el NetScaler) y los deja en SharePoint."
    )
    parser.add_argument("--referencia", required=True,
                        help="Número de catálogo u OC, va en el campo de comentarios del enroll.")
    parser.add_argument("--ventana-dias", type=int, default=VENTANA_RENOVACION_DIAS_DEFAULT,
                        help=f"Días antes del vencimiento para renovar (default {VENTANA_RENOVACION_DIAS_DEFAULT}).")
    parser.add_argument("--ssl-id", type=int, default=None,
                        help="Procesa solo este certificado (útil para probar).")
    parser.add_argument("--max-certificados", type=int, default=None,
                        help="Tope de certificados a renovar en esta corrida.")
    parser.add_argument("--ejecutar", action="store_true",
                        help="Sin esta bandera solo simula (no hace enroll ni sube nada).")
    parser.add_argument("--directorio-trabajo", default="./trabajo_certificados_nube")
    parser.add_argument("--log-dir", default="./logs")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    configurar_logging(Path(args.log_dir), args.log_level, "renovacion_certificados_nube.log")

    sp = requerir_entorno("SP_DRIVE_ID", "SP_RUTA_CARPETA_NUBE", "SP_RUTA_EXCEL_NUBE")
    drive_id = sp["SP_DRIVE_ID"]
    ruta_carpeta = sp["SP_RUTA_CARPETA_NUBE"].strip("/")
    ruta_excel = sp["SP_RUTA_EXCEL_NUBE"].strip("/")

    cliente = ClienteSCM(ConfigSCM.desde_entorno())
    ns = ClienteNetScaler(ConfigNetScaler.desde_entorno())
    graph = ClienteGraph(ConfigGraph.desde_entorno())

    filas: list[dict] = []
    try:
        # Se valida el acceso a SharePoint antes de pedir ningún certificado a Sectigo.
        if graph.obtener_item_drive(drive_id, ruta_carpeta) is None:
            raise SharePointError(f"No existe la carpeta '{ruta_carpeta}' en la biblioteca (SP_RUTA_CARPETA_NUBE).")
        if graph.obtener_item_drive(drive_id, ruta_excel) is None:
            raise SharePointError(f"No existe el Excel '{ruta_excel}' (SP_RUTA_EXCEL_NUBE). Créalo, puede estar vacío.")
        log.info(f"[SharePoint] Carpeta destino y Excel OK: {ruta_carpeta}")

        candidatos = seleccionar_candidatos(cliente, ns, args.ventana_dias, args.ssl_id)
        if args.max_certificados is not None and len(candidatos) > args.max_certificados:
            log.info(f"Hay {len(candidatos)} candidatos; se procesan solo {args.max_certificados} "
                     f"(--max-certificados).")
            candidatos = candidatos[:args.max_certificados]
        log.info(f"{len(candidatos)} certificado(s) de nube para renovar.")

        for cert in candidatos:
            log.info(f"--- {cert['commonName']} (sslId={cert['sslId']}) ---")
            fila = renovar_y_publicar(cliente, graph, cert, args.referencia, args.ventana_dias,
                                      Path(args.directorio_trabajo), args.ejecutar, drive_id, ruta_carpeta)
            if fila is not None:
                filas.append(fila)

        if not args.ejecutar:
            log.info("[DRY-RUN] No se hizo enroll ni se subió nada. Corre con --ejecutar para hacerlo.")
    except (SCMError, NetScalerError, SharePointError) as e:
        log.error(f"RESULTADO run_id={RUN_ID} estado=ERROR mensaje={e}")
        sys.exit(1)
    except Exception:
        log.exception(f"RESULTADO run_id={RUN_ID} estado=ERROR_INESPERADO")
        sys.exit(1)
    finally:
        # Lo que alcanzó a procesarse se registra en el Excel aunque la corrida haya fallado a medias.
        if filas:
            try:
                graph.agregar_filas_excel(drive_id, ruta_excel, ENCABEZADOS_EXCEL, filas)
            except SharePointError as e:
                log.error(f"No se pudo actualizar el Excel {ruta_excel}: {e}. Filas no registradas: "
                          f"{[(f['CommonName'], f.get('SslIdNuevo'), f['Estado']) for f in filas]}")
        ok = sum(1 for f in filas if f.get("Estado") == "OK")
        log.info(f"RESULTADO run_id={RUN_ID} renovados_ok={ok} con_error={len(filas) - ok}")
        log.info(f"=== Fin de ejecución (run_id={RUN_ID}) ===")

    if any(f.get("Estado") == "ERROR" for f in filas):
        sys.exit(1)


if __name__ == "__main__":
    main()
