#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sharepoint_graph.py

Cliente mínimo de Microsoft Graph para SharePoint, compartido por:
  - reporte_vencimientos_netscaler.py  (escribe en una lista)
  - renovacion_certificados_nube.py    (sube archivos a una biblioteca
                                         y agrega filas a un Excel)

Usa la misma autenticación que automatization_microsoft_defender_intune:
un App Registration con client_credentials y permisos de aplicación
sobre SharePoint (Sites.ReadWrite.All).

------------------------------------------------------------------
VARIABLES DE ENTORNO
------------------------------------------------------------------
  GRAPH_TENANT_ID      id del tenant
  GRAPH_CLIENT_ID      id de la aplicación (App Registration)
  GRAPH_CLIENT_SECRET  secreto de la aplicación
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, unquote, urlparse

import requests

log = logging.getLogger("renovacion_sectigo.sharepoint")

GRAPH_URL = "https://graph.microsoft.com/v1.0"
TIMEOUT_HTTP_SEGUNDOS = 30
MAX_REINTENTOS = 5

# Tipos de columna que se pueden crear en una lista. "fecha" es solo
# fecha (sin hora); "fechahora" guarda fecha y hora.
_DEFINICION_COLUMNA = {
    "texto": {"text": {}},
    "numero": {"number": {}},
    "fecha": {"dateTime": {"format": "dateOnly"}},
    "fechahora": {"dateTime": {"format": "dateTime"}},
}
_TIPO_VISIBLE = {
    "texto": "Single line of text",
    "numero": "Number",
    "fecha": "Date and time (sin hora)",
    "fechahora": "Date and time (con hora)",
}


class SharePointError(Exception):
    """Error devuelto por Microsoft Graph al operar sobre SharePoint."""


def requerir_entorno(*nombres: str) -> dict[str, str]:
    """Lee variables de entorno obligatorias; si falta alguna, termina con un mensaje claro."""
    valores = {n: os.environ.get(n, "").strip() for n in nombres}
    faltantes = [n for n, v in valores.items() if not v]
    if faltantes:
        log.error(f"Faltan variables de entorno: {', '.join(faltantes)}")
        sys.exit("Faltan variables de entorno: " + ", ".join(faltantes) +
                 "\nAgrégalas al .env (ver el encabezado de cada script).")
    return valores


@dataclass
class ConfigGraph:
    tenant_id: str
    client_id: str
    client_secret: str

    @classmethod
    def desde_entorno(cls) -> "ConfigGraph":
        v = requerir_entorno("GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET")
        return cls(v["GRAPH_TENANT_ID"], v["GRAPH_CLIENT_ID"], v["GRAPH_CLIENT_SECRET"])


@dataclass
class ListaSharePoint:
    site_id: str
    list_id: str
    nombre: str


@dataclass
class HojaExcel:
    ruta: str
    url_hoja: str
    nombre: str
    encabezados: list[str]
    filas: list[tuple[int, dict]]  # (número de fila en Excel, {encabezado: valor})
    ultima_fila: int


class ClienteGraph:
    def __init__(self, config: ConfigGraph):
        self.config = config
        self.session = requests.Session()
        self._token: Optional[str] = None

    # ---- Autenticación / transporte ---------------------------------

    def _obtener_token(self) -> str:
        r = requests.post(
            f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=TIMEOUT_HTTP_SEGUNDOS,
        )
        if r.status_code != 200:
            raise SharePointError(f"No se pudo obtener el token de Graph: {r.status_code} {r.text}")
        return r.json()["access_token"]

    def request(self, metodo: str, url: str, **kwargs) -> requests.Response:
        """Llama a Graph renovando el token ante un 401 y respetando Retry-After ante 429/503."""
        if not url.startswith("http"):
            url = f"{GRAPH_URL}{url}"
        headers_base = kwargs.pop("headers", {})
        r = None
        for intento in range(1, MAX_REINTENTOS + 1):
            if self._token is None:
                self._token = self._obtener_token()
            headers = {"Authorization": f"Bearer {self._token}", **headers_base}
            log.debug(f"[Graph] {metodo} {url}")
            r = self.session.request(metodo, url, headers=headers,
                                     timeout=TIMEOUT_HTTP_SEGUNDOS, **kwargs)
            log.debug(f"[Graph] -> {r.status_code}")

            if r.status_code == 401 and intento < MAX_REINTENTOS:
                self._token = None
                continue
            if r.status_code in (429, 503) and intento < MAX_REINTENTOS:
                espera = int(r.headers.get("Retry-After", 5))
                log.warning(f"[Graph] {r.status_code} en {url}: reintentando en {espera}s...")
                time.sleep(espera)
                continue
            return r
        return r

    def _todas_las_paginas(self, url: str) -> list[dict]:
        resultados: list[dict] = []
        while url:
            r = self.request("GET", url)
            if r.status_code != 200:
                raise SharePointError(f"Error consultando {url}: {r.status_code} {r.text}")
            datos = r.json()
            resultados.extend(datos.get("value", []))
            url = datos.get("@odata.nextLink")
        return resultados

    # ---- Listas -------------------------------------------------------

    def resolver_lista(self, url_lista: str) -> ListaSharePoint:
        """
        Recibe la URL de la lista tal como se ve en el navegador, por ejemplo:
          https://suramericana.sharepoint.com/sites/Gestion_DefenderEDR/Lists/Pruebas/AllItems.aspx
        y devuelve los ids de sitio y de lista. Se busca por la URL y no
        por el nombre visible, así que renombrar la lista no rompe nada.
        """
        partes = urlparse(url_lista)
        ruta = unquote(partes.path)
        idx = ruta.lower().find("/lists/")
        if not partes.netloc or idx < 0:
            raise SharePointError(
                f"La URL de lista no es válida: {url_lista}. "
                f"Debe tener la forma https://<tenant>.sharepoint.com/sites/<sitio>/Lists/<lista>"
            )
        ruta_sitio = ruta[:idx].strip("/")
        segmento_lista = ruta[idx + len("/lists/"):].split("/")[0]

        r = self.request("GET", f"/sites/{partes.netloc}:/{quote(ruta_sitio)}")
        if r.status_code != 200:
            raise SharePointError(f"No se pudo resolver el sitio '{ruta_sitio}': {r.status_code} {r.text}")
        site_id = r.json()["id"]

        listas = self._todas_las_paginas(f"/sites/{site_id}/lists?$select=id,displayName,webUrl")
        sufijo = f"/lists/{segmento_lista.lower()}"
        for lista in listas:
            if unquote(lista.get("webUrl", "")).rstrip("/").lower().endswith(sufijo):
                return ListaSharePoint(site_id, lista["id"], lista.get("displayName", segmento_lista))
        for lista in listas:
            if lista.get("displayName", "").lower() == segmento_lista.lower():
                return ListaSharePoint(site_id, lista["id"], lista["displayName"])

        raise SharePointError(f"No se encontró la lista '{segmento_lista}' en el sitio '{ruta_sitio}'.")

    def asegurar_columnas(self, lista: ListaSharePoint, columnas: dict[str, str]) -> dict[str, str]:
        """
        columnas: {nombre_visible: tipo}, con tipo 'texto' | 'numero' | 'fecha' | 'fechahora'.
        Si falta alguna columna, intenta crearla. Devuelve {nombre_visible: nombre_interno}:
        el nombre interno es el que hay que usar al escribir los campos del item.
        """
        url_columnas = f"/sites/{lista.site_id}/lists/{lista.list_id}/columns"
        existentes = {c.get("displayName"): c.get("name") for c in self._todas_las_paginas(url_columnas)}

        for nombre, tipo in columnas.items():
            if nombre in existentes:
                continue
            log.info(f"[SharePoint] La lista '{lista.nombre}' no tiene la columna '{nombre}': se crea ({tipo}).")
            r = self.request("POST", url_columnas,
                             json={"name": nombre, "displayName": nombre, **_DEFINICION_COLUMNA[tipo]})
            if r.status_code not in (200, 201):
                raise SharePointError(
                    f"No existe la columna '{nombre}' y no se pudo crear ({r.status_code} {r.text}). "
                    f"Créala a mano en SharePoint (+ Add column > {_TIPO_VISIBLE[tipo]}) con ese "
                    f"nombre exacto, o dale a la aplicación permiso Sites.Manage.All."
                )
            existentes[nombre] = r.json().get("name", nombre)

        return {n: existentes[n] for n in columnas}

    def listar_items(self, lista: ListaSharePoint) -> list[dict]:
        return self._todas_las_paginas(
            f"/sites/{lista.site_id}/lists/{lista.list_id}/items?$expand=fields&$top=200"
        )

    def crear_item(self, lista: ListaSharePoint, campos: dict) -> None:
        r = self.request("POST", f"/sites/{lista.site_id}/lists/{lista.list_id}/items",
                         json={"fields": campos})
        if r.status_code not in (200, 201):
            raise SharePointError(f"No se pudo crear el item en '{lista.nombre}': {r.status_code} {r.text}")

    def actualizar_item(self, lista: ListaSharePoint, item_id: str, campos: dict) -> None:
        r = self.request("PATCH", f"/sites/{lista.site_id}/lists/{lista.list_id}/items/{item_id}/fields",
                         json=campos)
        if r.status_code != 200:
            raise SharePointError(f"No se pudo actualizar el item {item_id} de '{lista.nombre}': "
                                  f"{r.status_code} {r.text}")

    # ---- Bibliotecas de documentos -----------------------------------

    @staticmethod
    def _url_ruta(drive_id: str, ruta: str, accion: str = "") -> str:
        url = f"/drives/{drive_id}/root:/{quote(ruta.strip('/'))}"
        return f"{url}:/{accion}" if accion else url

    def obtener_item_drive(self, drive_id: str, ruta: str) -> Optional[dict]:
        r = self.request("GET", self._url_ruta(drive_id, ruta))
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise SharePointError(f"No se pudo consultar '{ruta}': {r.status_code} {r.text}")
        return r.json()

    def descargar_archivo(self, drive_id: str, ruta: str) -> Optional[bytes]:
        """Devuelve el contenido del archivo, o None si no existe."""
        r = self.request("GET", self._url_ruta(drive_id, ruta, "content"))
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise SharePointError(f"No se pudo descargar '{ruta}': {r.status_code} {r.text}")
        return r.content

    def crear_carpeta(self, drive_id: str, ruta_padre: str, nombre: str) -> dict:
        """Crea la carpeta; si ya existe, devuelve la existente sin tocar su contenido."""
        r = self.request("POST", self._url_ruta(drive_id, ruta_padre, "children"),
                         json={"name": nombre, "folder": {},
                               "@microsoft.graph.conflictBehavior": "fail"})
        if r.status_code in (200, 201):
            log.info(f"[SharePoint] Carpeta creada: {ruta_padre}/{nombre}")
            return r.json()
        if r.status_code == 409:
            existente = self.obtener_item_drive(drive_id, f"{ruta_padre}/{nombre}")
            if existente is not None:
                log.info(f"[SharePoint] La carpeta {ruta_padre}/{nombre} ya existía: se reutiliza.")
                return existente
        raise SharePointError(f"No se pudo crear la carpeta '{ruta_padre}/{nombre}': {r.status_code} {r.text}")

    def subir_archivo(self, drive_id: str, ruta: str, contenido: bytes) -> dict:
        """Sube (o reemplaza) un archivo. Si está bloqueado (423), fuerza check-in y reintenta una vez."""
        url = self._url_ruta(drive_id, ruta, "content")
        headers = {"Content-Type": "application/octet-stream"}
        r = self.request("PUT", url, headers=headers, data=contenido)

        if r.status_code == 423:
            log.warning(f"[SharePoint] '{ruta}' está bloqueado (423): se fuerza check-in y se reintenta.")
            self.request("POST", self._url_ruta(drive_id, ruta, "checkin"),
                         json={"comment": "Check-in automático por script"})
            r = self.request("PUT", url, headers=headers, data=contenido)

        if r.status_code not in (200, 201):
            raise SharePointError(f"No se pudo subir '{ruta}': {r.status_code} {r.text}")
        log.info(f"[SharePoint] Archivo subido: {ruta}")
        return r.json()

    # ---- Excel (API de workbook de Graph, sin librerías extra) --------
    #
    # Se edita el .xlsx en línea: no se descarga ni se reemplaza el archivo,
    # así que funciona aunque alguien lo tenga abierto. Se trabaja sobre la
    # primera hoja, con los encabezados en la fila 1.

    def leer_excel(self, drive_id: str, ruta: str, encabezados: list[str],
                   escribir_encabezados: bool = True) -> HojaExcel:
        """
        Lee la primera hoja del Excel y se asegura de que tenga los
        encabezados pedidos: si la hoja está vacía los escribe; si ya tiene
        encabezados, respeta su orden y agrega al final los que falten.
        Con escribir_encabezados=False (simulación) no escribe nada.
        """
        item = self.obtener_item_drive(drive_id, ruta)
        if item is None:
            raise SharePointError(f"No existe el Excel '{ruta}'. Créalo en SharePoint (puede estar vacío).")
        url_wb = f"/drives/{drive_id}/items/{item['id']}/workbook"

        r = self.request("GET", f"{url_wb}/worksheets?$select=id,name")
        if r.status_code != 200 or not r.json().get("value"):
            raise SharePointError(f"No se pudieron leer las hojas de '{ruta}': {r.status_code} {r.text}")
        hoja = r.json()["value"][0]
        url_hoja = f"{url_wb}/worksheets/{quote(hoja['id'], safe='')}"

        r = self.request("GET", f"{url_hoja}/usedRange(valuesOnly=true)?$select=address,values")
        if r.status_code != 200:
            raise SharePointError(f"No se pudo leer el rango usado de '{ruta}': {r.status_code} {r.text}")
        usado = r.json()
        valores = usado.get("values") or [[""]]
        hoja_vacia = all(v in ("", None) for fila in valores for v in fila)

        existentes = [] if hoja_vacia else [str(v).strip() for v in valores[0]]
        while existentes and existentes[-1] == "":
            existentes.pop()
        columnas = existentes + [h for h in encabezados if h not in existentes]
        if columnas != existentes and escribir_encabezados:
            self._escribir_rango(url_hoja, 1, 1, [columnas])

        # Rango usado, ej. "Sheet1!A1:J7": la primera fila son los encabezados.
        filas: list[tuple[int, dict]] = []
        ultima_fila = 1
        if not hoja_vacia:
            numeros = [int(n) for n in re.findall(r"[A-Z]+(\d+)", usado["address"].split("!")[-1])]
            primera_fila, ultima_fila = numeros[0], numeros[-1]
            for i, valores_fila in enumerate(valores[1:], start=primera_fila + 1):
                if any(v not in ("", None) for v in valores_fila):
                    filas.append((i, dict(zip(existentes, valores_fila))))

        return HojaExcel(ruta, url_hoja, hoja["name"], columnas, filas, ultima_fila)

    def agregar_filas_excel(self, hoja: HojaExcel, filas: list[dict]) -> None:
        if not filas:
            return
        datos = [["" if fila.get(c) is None else fila.get(c) for c in hoja.encabezados] for fila in filas]
        self._escribir_rango(hoja.url_hoja, hoja.ultima_fila + 1, 1, datos)
        hoja.ultima_fila += len(filas)
        log.info(f"[SharePoint] {len(filas)} fila(s) agregada(s) a {hoja.ruta} (hoja '{hoja.nombre}').")

    def actualizar_fila_excel(self, hoja: HojaExcel, numero_fila: int, cambios: dict) -> None:
        """Escribe solo las celdas que cambian, para no pisar lo que una persona haya editado en esa fila."""
        for columna, valor in cambios.items():
            indice = hoja.encabezados.index(columna) + 1
            self._escribir_rango(hoja.url_hoja, numero_fila, indice, [["" if valor is None else valor]])

    def _escribir_rango(self, url_hoja: str, fila_inicio: int, columna_inicio: int,
                        valores: list[list]) -> None:
        ancho = max(len(f) for f in valores)
        valores = [f + [""] * (ancho - len(f)) for f in valores]
        direccion = (f"{_letra_columna(columna_inicio)}{fila_inicio}:"
                     f"{_letra_columna(columna_inicio + ancho - 1)}{fila_inicio + len(valores) - 1}")
        r = self.request("PATCH", f"{url_hoja}/range(address='{direccion}')", json={"values": valores})
        if r.status_code != 200:
            raise SharePointError(f"No se pudo escribir el rango {direccion}: {r.status_code} {r.text}")


def _letra_columna(n: int) -> str:
    """1 -> A, 26 -> Z, 27 -> AA."""
    letras = ""
    while n:
        n, resto = divmod(n - 1, 26)
        letras = chr(65 + resto) + letras
    return letras
