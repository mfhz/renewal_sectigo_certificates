#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
renovacion_certificados_nube.py

Gestiona los certificados de Sectigo que NO están instalados en el
NetScaler (certificados de nube) a través de un Excel en SharePoint, con
aprobación manual por la columna "Estado":

  1. EMISIONES APROBADAS: las filas con Estado = "Emitir" se renuevan
     repitiendo el flujo del script principal (llave + CSR, enroll,
     descarga, .pem -> .pfx y contraseña). En SharePoint queda:
         SP_RUTA_CARPETA_NUBE/<Mes-DD>_<OC>/<certificado>/{.pfx, .password.txt}
     (ej. Octubre-09_OC-12345) con el mes en letras y el día de la
     emisión, y la OC tomada de la Referencia de la fila;
     los certificados de la misma OC emitidos el mismo día quedan juntos.
     La fila pasa a "En proceso" antes de pedir el certificado y termina
     en "Emitido" o "Error" (motivo en Detalle).

  2. DETECCIÓN: busca en SCM los certificados Issued que vencen dentro
     de la ventana y los agrega al Excel con Estado = "Pendiente",
     descartando:
       - los que ya están en el Excel (por SslId),
       - los que están en el NetScaler (por CN o número de serie); esos
         los gestiona reporte_vencimientos_netscaler.py,
       - los que ya tienen otro certificado con el mismo CN emitido con
         vigencia de sobra, o una solicitud en curso.

Para aprobar una renovación: escribir "Emitir" en Estado y la OC en
Referencia (si Referencia está vacía se usa --referencia).

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
  SP_RUTA_EXCEL_NUBE    Excel de control (debe existir, puede estar vacío),
                        ej: IT-CIBER-SEGURIDAD/Defender/Pruebas/Pruebas.xlsx

------------------------------------------------------------------
USO
------------------------------------------------------------------
  # Simulación: muestra qué emitiría y qué agregaría al Excel, sin tocar nada
  python renovacion_certificados_nube.py --ventana-dias 30

  # Ejecución real
  python renovacion_certificados_nube.py --ventana-dias 30 --referencia "OC-12345" --ejecutar
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from renovacion_certificados_sectigo import (
    ESTADO_EMITIDO,
    ESTADO_EN_PROCESO,
    ESTADO_ERROR,
    ESTADO_PENDIENTE,
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
    campo_dn,
    configurar_logging,
    dias_para_expirar,
    es_emitir,
    extraer_sans,
    flujo_renovacion,
    log,
    normalizar_serial,
)
from sharepoint_graph import ClienteGraph, ConfigGraph, HojaExcel, SharePointError, requerir_entorno

ENCABEZADOS_EXCEL = [
    "SslId", "CommonName", "SANs", "Vencimiento", "Estado", "Referencia",
    "SslIdNuevo", "CarpetaSharePoint", "FechaEmision", "Detalle", "FechaDeteccion",
]

# Estados de SCM que indican que ya hay una solicitud en curso para ese CN.
ESTADOS_SCM_EN_CURSO = {"applied", "requested", "approved", "under review", "pending"}


def ahora_texto() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def fecha_iso_scm(expires: str) -> str:
    """SCM entrega 'MM/DD/YYYY'; en el Excel va como YYYY-MM-DD para que no se confunda día y mes."""
    try:
        return datetime.strptime(expires, "%m/%d/%Y").strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return expires or ""


def nombre_seguro_sharepoint(nombre: str) -> str:
    """SharePoint no admite " * : < > ? / \\ | en nombres; un wildcard queda como 'wildcard.dominio.com'."""
    nombre = nombre.replace("*", "wildcard")
    return re.sub(r'["*:<>?/\\|#%]', "_", nombre).strip(" .")


# No se usa %B porque depende del locale del servidor (saldría en inglés).
MESES = ["Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio",
         "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"]


def nombre_carpeta_oc(referencia: str) -> str:
    """Carpeta que agrupa los certificados de una OC: mes y día de la emisión + OC, ej. 'Octubre-09_OC-12345'."""
    hoy = datetime.now()
    return nombre_seguro_sharepoint(f"{MESES[hoy.month - 1]}-{hoy.day:02d}_{referencia}")


def a_entero(valor) -> Optional[int]:
    try:
        return int(float(str(valor).strip()))
    except (TypeError, ValueError):
        return None


def completar_detalle(cliente: ClienteSCM, cert: dict) -> dict:
    """El listado de SCM puede no traer status/expires: en ese caso se consulta el detalle."""
    if cert.get("expires") and cert.get("status"):
        return cert
    return {**cert, **cliente.obtener_certificado(cert["sslId"])}


# ============================================================
# 1. EMISIONES APROBADAS
# ============================================================

def procesar_emisiones(cliente: ClienteSCM, graph: ClienteGraph, hoja: HojaExcel,
                       referencia_default: Optional[str], directorio_trabajo: Path, ejecutar: bool,
                       drive_id: str, ruta_carpeta: str) -> tuple[int, int]:
    """Renueva las filas con Estado = "Emitir". Devuelve (emitidos, errores)."""
    aprobadas = [(n, f) for n, f in hoja.filas if es_emitir(f.get("Estado"))]
    log.info(f"[Emisiones] {len(aprobadas)} fila(s) con Estado = 'Emitir'.")

    emitidos = errores = 0
    for numero_fila, fila in aprobadas:
        ssl_id = a_entero(fila.get("SslId"))
        cn = str(fila.get("CommonName") or ssl_id)
        referencia = str(fila.get("Referencia") or referencia_default or "").strip()
        log.info(f"--- Emitir {cn} (fila {numero_fila}, sslId={ssl_id}, referencia={referencia!r}) ---")

        motivo = None
        if not ssl_id:
            motivo = "La fila no tiene un SslId válido."
        elif not referencia:
            motivo = "Falta la Referencia (OC). Llénala y vuelve a poner 'Emitir'."
        if motivo:
            log.error(f"[{cn}] {motivo}")
            if ejecutar:
                graph.actualizar_fila_excel(hoja, numero_fila, {"Estado": ESTADO_ERROR, "Detalle": motivo})
            errores += 1
            continue

        carpeta_oc = nombre_carpeta_oc(referencia)
        nombre_carpeta = nombre_seguro_sharepoint(cn)
        ruta_carpeta_cert = f"{ruta_carpeta}/{carpeta_oc}/{nombre_carpeta}"

        if not ejecutar:
            log.info(f"[DRY-RUN] Se renovaría sslId={ssl_id} y se dejaría en {ruta_carpeta_cert}.")
            continue

        graph.actualizar_fila_excel(hoja, numero_fila, {"Estado": ESTADO_EN_PROCESO,
                                                        "Detalle": f"Iniciado run_id={RUN_ID}"})
        resultado = None
        try:
            resultado = flujo_renovacion(
                cliente=cliente,
                ssl_id_actual=ssl_id,
                referencia=referencia,
                domain_id=None,
                ventana_dias=0,
                directorio_trabajo=directorio_trabajo / nombre_carpeta,
                ejecutar=True,
                omitir_ventana=True,
            )
            graph.crear_carpeta(drive_id, ruta_carpeta, carpeta_oc)
            carpeta = graph.crear_carpeta(drive_id, f"{ruta_carpeta}/{carpeta_oc}", nombre_carpeta)
            for ruta_local in (resultado.ruta_pfx, resultado.ruta_password):
                graph.subir_archivo(
                    drive_id,
                    f"{ruta_carpeta_cert}/{nombre_seguro_sharepoint(ruta_local.name)}",
                    ruta_local.read_bytes(),
                )
            graph.actualizar_fila_excel(hoja, numero_fila, {
                "Estado": ESTADO_EMITIDO,
                "SslIdNuevo": resultado.ssl_id_nuevo,
                "CarpetaSharePoint": carpeta.get("webUrl", ruta_carpeta_cert),
                "FechaEmision": ahora_texto(),
                "Detalle": "",
            })
            emitidos += 1
        except (SCMError, DominioNoValidadoError, OpenSSLError, SharePointError) as e:
            log.error(f"[{cn}] {e}")
            detalle = str(e)
            if resultado is not None:
                detalle = (f"El certificado SÍ se emitió (sslId={resultado.ssl_id_nuevo}) pero no se pudo "
                           f"subir a SharePoint; el .pfx quedó en el servidor: {resultado.ruta_pfx}. {e}")
                log.error(f"[{cn}] {detalle}")
            graph.actualizar_fila_excel(hoja, numero_fila, {
                "Estado": ESTADO_ERROR,
                "SslIdNuevo": resultado.ssl_id_nuevo if resultado else "",
                "Detalle": detalle[:500],
            })
            errores += 1

    return emitidos, errores


# ============================================================
# 2. DETECCIÓN DE CANDIDATOS
# ============================================================

def seleccionar_candidatos(cliente: ClienteSCM, ns: ClienteNetScaler, ventana_dias: int,
                           ssl_ids_en_excel: set[int]) -> list[dict]:
    certkeys = ns.listar_certkeys()
    cns_netscaler = {campo_dn(c.get("subject", ""), "CN").lower() for c in certkeys} - {""}
    seriales_netscaler = {normalizar_serial(c.get("serial", "")) for c in certkeys} - {""}
    log.info(f"[NetScaler] {len(certkeys)} sslcertkey leídos para descartar los que ya están instalados.")

    certificados = cliente.listar_certificados()
    log.info(f"[SCM] {len(certificados)} certificados listados; consultando estado y vencimiento...")
    certificados = [completar_detalle(cliente, c) for c in certificados]

    por_cn: dict[str, list[dict]] = {}
    for c in certificados:
        por_cn.setdefault((c.get("commonName") or "").lower(), []).append(c)

    candidatos = []
    for cert in certificados:
        cn = cert.get("commonName") or ""
        if (cert.get("status") or "").lower() != "issued" or not cert.get("expires"):
            continue
        dias = dias_para_expirar(cert["expires"])
        if dias > ventana_dias or cert["sslId"] in ssl_ids_en_excel:
            continue

        if cn.lower() in cns_netscaler or normalizar_serial(cert.get("serialNumber", "")) in seriales_netscaler:
            log.debug(f"  Omitido {cn} (sslId={cert['sslId']}): está en el NetScaler.")
            continue

        otros = [o for o in por_cn.get(cn.lower(), []) if o.get("sslId") != cert.get("sslId")]
        ya_renovado = any(
            (o.get("status") or "").lower() in ESTADOS_SCM_EN_CURSO
            or ((o.get("status") or "").lower() == "issued" and o.get("expires")
                and dias_para_expirar(o["expires"]) > ventana_dias)
            for o in otros
        )
        if ya_renovado:
            log.info(f"  Omitido {cn} (sslId={cert['sslId']}): ya tiene otro certificado "
                     f"emitido o en curso con el mismo CN.")
            continue

        log.info(f"  Nuevo candidato: {cn} (sslId={cert['sslId']}) vence {cert['expires']} -> {dias} días")
        candidatos.append(cert)

    return candidatos


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Registra en un Excel los certificados de nube por vencer y renueva los aprobados ('Emitir')."
    )
    parser.add_argument("--ventana-dias", type=int, default=VENTANA_RENOVACION_DIAS_DEFAULT,
                        help=f"Días antes del vencimiento para registrar (default {VENTANA_RENOVACION_DIAS_DEFAULT}).")
    parser.add_argument("--referencia", default=None,
                        help="OC por defecto para las filas aprobadas que no tengan Referencia.")
    parser.add_argument("--ejecutar", action="store_true",
                        help="Sin esta bandera solo simula (no emite ni escribe en el Excel).")
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

    try:
        if graph.obtener_item_drive(drive_id, ruta_carpeta) is None:
            raise SharePointError(f"No existe la carpeta '{ruta_carpeta}' en la biblioteca (SP_RUTA_CARPETA_NUBE).")
        hoja = graph.leer_excel(drive_id, ruta_excel, ENCABEZADOS_EXCEL)
        log.info(f"[SharePoint] Excel '{ruta_excel}' leído: {len(hoja.filas)} fila(s).")

        emitidos, errores = procesar_emisiones(
            cliente, graph, hoja, args.referencia, Path(args.directorio_trabajo),
            args.ejecutar, drive_id, ruta_carpeta)

        ssl_ids_en_excel = {a_entero(f.get("SslId")) for _, f in hoja.filas} - {None}
        candidatos = seleccionar_candidatos(cliente, ns, args.ventana_dias, ssl_ids_en_excel)
        nuevas = [{
            "SslId": c["sslId"],
            "CommonName": c.get("commonName", ""),
            "SANs": ", ".join(extraer_sans(c)),
            "Vencimiento": fecha_iso_scm(c.get("expires", "")),
            "Estado": ESTADO_PENDIENTE,
            "FechaDeteccion": ahora_texto(),
        } for c in candidatos]

        if args.ejecutar:
            graph.agregar_filas_excel(hoja, nuevas)
        else:
            log.info(f"[DRY-RUN] Se agregarían {len(nuevas)} fila(s) 'Pendiente' al Excel. "
                     f"Corre con --ejecutar para hacerlo.")

        log.info(f"RESULTADO run_id={RUN_ID} estado={'OK' if not errores else 'CON_ERRORES'} "
                 f"emitidos={emitidos} errores_emision={errores} nuevos_pendientes={len(nuevas)}")
        if errores:
            sys.exit(1)
    except (SCMError, NetScalerError, SharePointError) as e:
        log.error(f"RESULTADO run_id={RUN_ID} estado=ERROR mensaje={e}")
        sys.exit(1)
    except Exception:
        log.exception(f"RESULTADO run_id={RUN_ID} estado=ERROR_INESPERADO")
        sys.exit(1)
    finally:
        log.info(f"=== Fin de ejecución (run_id={RUN_ID}) ===")


if __name__ == "__main__":
    main()
