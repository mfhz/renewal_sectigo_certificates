#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
renovacion_certificados_sectigo.py

Automatiza el flujo manual de renovación/emisión de certificados SSL en
Sectigo Certificate Manager (SCM), replicando paso a paso lo que hoy se
hace a mano en el portal:

  1. Consulta la fecha de expiración del certificado actual en SCM.
  2. Si está dentro de la ventana de renovación, genera la llave privada
     y el CSR con OpenSSL a partir de una plantilla .conf.
  3. Solicita el certificado a Sectigo vía API REST (/ssl/v1/enroll),
     detectando el Certificate Profile correcto (el que ya tenía el
     certificado si es una renovación, o "Instant SSL Certificate" si
     es una emisión nueva).
  4. Verifica que el dominio esté validado en SCM; si no lo está, no
     continúa y deja lista la notificación (stub de correo).
  5. Espera a que el certificado quede emitido y lo descarga.
  6. Normaliza el nombre del archivo descargado (Sectigo entrega el
     nombre con guion bajo donde debería ir un punto).
  7. Convierte P7B -> PEM -> PFX, generando una contraseña que cumple
     la política de complejidad exigida (mínimo 21 caracteres, con
     mayúsculas, minúsculas, dígitos y símbolos permitidos).

  8. (Opcional, con --subir-netscaler) Sube el .pfx al NetScaler por
     NITRO: lo copia a /nsconfig/ssl/, crea o actualiza el objeto
     sslcertkey correspondiente, y guarda la configuración.

------------------------------------------------------------------
REQUISITOS
------------------------------------------------------------------
  - Python 3.8+
  - pip install requests   (o, con uv: uv pip install -r requirements.txt)
  - OpenSSL disponible en el PATH del sistema

------------------------------------------------------------------
CREDENCIALES (variables de entorno — nunca las escriban en el código)
------------------------------------------------------------------
  SCM_BASE_URL      https://hard.cert-manager.com
  SCM_LOGIN         usuario de la cuenta de API
  SCM_PASSWORD      contraseña de la cuenta de API
  SCM_CUSTOMER_URI  gruposura

  Solo si usas --subir-netscaler:
  NS_HOST           IP o hostname del NetScaler (ej: 10.200.153.40)
  NS_USER           usuario con permiso de API (ej: CertificadosDig)
  NS_PASSWORD       contraseña de ese usuario
  NS_VERIFY_TLS     "true"/"false" (default false — el NetScaler usa
                     certificado autofirmado en su interfaz de gestión)

------------------------------------------------------------------
USO
------------------------------------------------------------------
  # Modo simulación (no llama a /enroll, solo muestra qué haría):
  python renovacion_certificados_sectigo.py --ssl-id 12223558 \\
      --referencia "PRUEBA-E2E-CONECTOR" --domain-id 279318 --ventana-dias 365

  # Ejecución real + subida al NetScaler de pruebas:
  python renovacion_certificados_sectigo.py --ssl-id 12223558 \\
      --referencia "PRUEBA-E2E-CONECTOR" --domain-id 279318 --ventana-dias 365 \\
      --ejecutar --subir-netscaler --netscaler-certkey pruebaclm.labsura.com_2026

  # Ejecución real:
  python renovacion_certificados_sectigo.py --ssl-id 12223558 \\
      --referencia "PRUEBA-E2E-CONECTOR" --domain-id 279318 \\
      --ventana-dias 365 --ejecutar

------------------------------------------------------------------
LOGS
------------------------------------------------------------------
  Cada ejecución escribe en:
    <log-dir>/renovacion_sectigo.log            (rotativo, uno por día,
                                                  se conservan 30 días)
  y también imprime en pantalla (mismo nivel de detalle).
  Cada línea trae un run_id (timestamp + pid) para poder aislar en el
  log todo lo que ocurrió en una corrida específica, por ejemplo:

    grep "run_id=20260927-153012-48213" logs/renovacion_sectigo.log

  La contraseña del .pfx NUNCA se escribe en el log ni en pantalla:
  se guarda en un archivo aparte, con permisos 600, junto al .pfx.

------------------------------------------------------------------
SUPUESTOS QUE HAY QUE VALIDAR ANTES DE CONFIAR ESTO A LOS 400 CERTIFICADOS
------------------------------------------------------------------
  - El código de formato exacto para descargar el PKCS#7 por API no
    está confirmado contra esta instancia. El script prueba varios
    candidatos conocidos (ver COLLECT_FORMAT_CANDIDATES) y reporta
    cuál funcionó. Corran una vez con --descubrir-formato y fijen el
    resultado en la variable de entorno SCM_COLLECT_FORMAT.
  - notificar_dominio_no_validado() es un stub: conecten aquí su SMTP
    real o su canal de notificaciones (Teams, correo, etc.).
  - El tamaño de llave por defecto es RSA 2048 (coincide con lo que
    permiten los perfiles ya consultados). Si necesitan otro tamaño,
    ajusten KEY_SIZE_DEFAULT.
"""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import secrets
import string
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("Falta la librería requests. Instala con: pip install requests "
              "(o: uv pip install -r requirements.txt)")


# ============================================================
# CONFIGURACIÓN
# ============================================================

KEY_SIZE_DEFAULT = 2048
VENTANA_RENOVACION_DIAS_DEFAULT = 30
COLLECT_MAX_INTENTOS = 20
COLLECT_ESPERA_SEGUNDOS = 30

CERT_PROFILE_NOMBRE_DEFAULT = "Instant SSL Certificate"

COLLECT_FORMAT_CANDIDATES = ["pkcs7", "PKCS7", "x509CO"]

# Caracteres especiales confirmados como permitidos en la contraseña
# del .pfx. Se excluyen a propósito: . , : ; ' " \ / | _ -
PWD_SPECIALS = "#$%&@^`~<>*+!?="
PWD_LONGITUD_DEFAULT = 21

PLANTILLA_CONF = """[ req ]
default_bits            = {key_size}
distinguished_name       = req_distinguished_name
req_extensions           = req_ext

[ req_distinguished_name ]
countryName                    = Country Name (2 letter code)
countryName_default            = CO
stateOrProvinceName            = State or Province Name (full name)
stateOrProvinceName_default     = Antioquia
localityName                   = Locality Name (eg, city)
localityName_default           = Medellin
organizationName               = Organization Name (eg, company)
organizationName_default       = {organization_name}
commonName                     = Common Name (e.g. server FQDN or YOUR name)
commonName_max                 = 64
commonName_default             = {common_name}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
{sans_block}
"""


# ============================================================
# LOGGING
# ============================================================

RUN_ID = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"

log = logging.getLogger("renovacion_sectigo")


def configurar_logging(directorio_logs: Path, nivel: str) -> None:
    directorio_logs.mkdir(parents=True, exist_ok=True)
    ruta_log = directorio_logs / "renovacion_sectigo.log"

    formato = logging.Formatter(
        f"%(asctime)s\trun_id={RUN_ID}\t%(levelname)s\t%(message)s"
    )

    log.setLevel(getattr(logging, nivel.upper(), logging.INFO))
    log.handlers.clear()

    handler_archivo = logging.handlers.TimedRotatingFileHandler(
        ruta_log, when="midnight", backupCount=30, encoding="utf-8"
    )
    handler_archivo.setFormatter(formato)
    log.addHandler(handler_archivo)

    handler_consola = logging.StreamHandler(sys.stdout)
    handler_consola.setFormatter(formato)
    log.addHandler(handler_consola)

    log.info(f"=== Inicio de ejecución (run_id={RUN_ID}) ===")


# ============================================================
# EXCEPCIONES PROPIAS
# ============================================================

class SCMError(Exception):
    """Error genérico devuelto por la API de SCM."""


class CertificadoPendienteError(Exception):
    """El certificado todavía no está listo para descargar."""


class DominioNoValidadoError(Exception):
    """El dominio no está validado en SCM; no se puede emitir."""


class OpenSSLError(Exception):
    """Un comando de OpenSSL terminó con error."""


class NetScalerError(Exception):
    """Error devuelto por la API NITRO del NetScaler."""


# ============================================================
# CONFIG / CREDENCIALES
# ============================================================

@dataclass
class ConfigSCM:
    base_url: str
    login: str
    password: str
    customer_uri: str

    @classmethod
    def desde_entorno(cls) -> "ConfigSCM":
        faltantes = []
        base_url = os.environ.get("SCM_BASE_URL")
        login = os.environ.get("SCM_LOGIN")
        password = os.environ.get("SCM_PASSWORD")
        customer_uri = os.environ.get("SCM_CUSTOMER_URI")

        for nombre, valor in [
            ("SCM_BASE_URL", base_url),
            ("SCM_LOGIN", login),
            ("SCM_PASSWORD", password),
            ("SCM_CUSTOMER_URI", customer_uri),
        ]:
            if not valor:
                faltantes.append(nombre)

        if faltantes:
            log.error(f"Faltan variables de entorno: {', '.join(faltantes)}")
            sys.exit(
                "Faltan variables de entorno: " + ", ".join(faltantes) +
                "\nDefínelas antes de correr el script, por ejemplo:\n"
                '  export SCM_BASE_URL="https://hard.cert-manager.com"\n'
                '  export SCM_LOGIN="tu_usuario"\n'
                '  export SCM_PASSWORD="tu_clave"\n'
                '  export SCM_CUSTOMER_URI="gruposura"'
            )

        return cls(
            base_url=base_url.rstrip("/"),
            login=login,
            password=password,
            customer_uri=customer_uri,
        )


# ============================================================
# CLIENTE DE LA API DE SCM
# ============================================================

class ClienteSCM:
    def __init__(self, config: ConfigSCM):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json;charset=UTF-8",
                "login": config.login,
                "password": config.password,
                "customerUri": config.customer_uri,
            }
        )

    def _get(self, path: str, **kwargs) -> requests.Response:
        log.debug(f"GET {path} params={kwargs.get('params')}")
        r = self.session.get(f"{self.config.base_url}{path}", **kwargs)
        log.debug(f"-> {r.status_code} ({len(r.content)} bytes)")
        return r

    def _post(self, path: str, json_body: dict) -> requests.Response:
        log.debug(f"POST {path}")
        r = self.session.post(f"{self.config.base_url}{path}", json=json_body)
        log.debug(f"-> {r.status_code}")
        return r

    # ---- Certificados ----------------------------------------------

    def obtener_certificado(self, ssl_id: int) -> dict:
        r = self._get(f"/api/ssl/v1/{ssl_id}")
        if r.status_code != 200:
            raise SCMError(f"No se pudo leer el certificado {ssl_id}: {r.status_code} {r.text}")
        return r.json()

    def listar_perfiles(self, org_id: int) -> list[dict]:
        r = self._get("/api/ssl/v1/types", params={"organizationId": org_id})
        if r.status_code != 200:
            raise SCMError(
                f"No se pudo listar perfiles para la organización {org_id}: "
                f"{r.status_code} {r.text}\n"
                "-> Probablemente falta habilitar 'Enable Web/REST API' para "
                "esa organización en el portal de SCM."
            )
        return r.json()

    def buscar_perfil_por_nombre(self, org_id: int, nombre: str) -> dict:
        for perfil in self.listar_perfiles(org_id):
            if perfil.get("name") == nombre:
                return perfil
        raise SCMError(f"No se encontró el perfil '{nombre}' en la organización {org_id}")

    def enroll(
        self,
        org_id: int,
        cert_type_id: int,
        csr: str,
        term_dias: int,
        comentario: str,
        subj_alt_names: str,
    ) -> dict:
        body = {
            "orgId": org_id,
            "subjAltNames": subj_alt_names,
            "certType": cert_type_id,
            "term": term_dias,
            "comments": comentario,
            "externalRequester": "",
            "csr": csr,
        }
        r = self._post("/api/ssl/v1/enroll", body)
        if r.status_code not in (200, 201):
            raise SCMError(f"Fallo el enroll: {r.status_code} {r.text}")
        return r.json()  # trae 'sslId' y 'renewId'

    def collect(self, ssl_id: int, formato: str) -> bytes:
        r = self._get(f"/api/ssl/v1/collect/{ssl_id}/{formato}")
        if r.status_code == 400:
            raise CertificadoPendienteError(r.text)
        if r.status_code != 200:
            raise SCMError(f"Fallo al descargar el certificado {ssl_id}: {r.status_code} {r.text}")
        return r.content

    def descubrir_formato_collect(self, ssl_id: int) -> str:
        for formato in COLLECT_FORMAT_CANDIDATES:
            try:
                contenido = self.collect(ssl_id, formato)
                if contenido:
                    log.info(f"[descubrir-formato] '{formato}' funcionó. "
                             f"Fija SCM_COLLECT_FORMAT={formato} para no repetir esta prueba.")
                    return formato
            except (SCMError, CertificadoPendienteError):
                continue
        raise SCMError(
            "Ninguno de los formatos candidatos funcionó. Prueba manualmente en "
            "Postman contra /api/ssl/v1/collect/{sslId}/{formato} con distintos "
            "valores y actualiza COLLECT_FORMAT_CANDIDATES."
        )

    # ---- Dominios ----------------------------------------------------

    def obtener_dominio(self, domain_id: int) -> dict:
        r = self._get(f"/api/domain/v1/{domain_id}")
        if r.status_code != 200:
            raise SCMError(f"No se pudo leer el dominio {domain_id}: {r.status_code} {r.text}")
        return r.json()


# ============================================================
# CONFIG / CLIENTE DE NETSCALER (NITRO) — opcional, solo si se usa
# --subir-netscaler
# ============================================================

@dataclass
class ConfigNetScaler:
    host: str
    usuario: str
    password: str
    verificar_tls: bool

    @classmethod
    def desde_entorno(cls) -> "ConfigNetScaler":
        faltantes = []
        host = os.environ.get("NS_HOST")
        usuario = os.environ.get("NS_USER")
        password = os.environ.get("NS_PASSWORD")

        for nombre, valor in [("NS_HOST", host), ("NS_USER", usuario), ("NS_PASSWORD", password)]:
            if not valor:
                faltantes.append(nombre)

        if faltantes:
            sys.exit(
                "Faltan variables de entorno para el NetScaler: " + ", ".join(faltantes) +
                "\nDefínelas, por ejemplo:\n"
                '  export NS_HOST="10.200.153.40"\n'
                '  export NS_USER="CertificadosDig"\n'
                '  export NS_PASSWORD="tu_clave"'
            )

        verificar_tls = os.environ.get("NS_VERIFY_TLS", "false").strip().lower() == "true"
        return cls(host=host, usuario=usuario, password=password, verificar_tls=verificar_tls)


class ClienteNetScaler:
    """
    Cliente mínimo de NITRO para el único propósito de este script:
    subir un .pfx a /nsconfig/ssl/ y crear o actualizar el objeto
    sslcertkey correspondiente.

    Deliberadamente NO reimplementa el conector completo de Sectigo
    para Citrix (bindings a vservers, HA, particiones, etc.) — eso es
    trabajo del conector oficial. Esto es solo para poder probar el
    ciclo de punta a punta contra el NetScaler de pruebas.
    """

    def __init__(self, config: ConfigNetScaler):
        self.config = config
        self.base_url = f"https://{config.host}/nitro/v1/config"
        self.auth = (config.usuario, config.password)
        if not config.verificar_tls:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            log.warning("NS_VERIFY_TLS=false: no se valida el certificado TLS del "
                        "NetScaler (normal si usa el autofirmado de gestión). "
                        "Para producción, considera instalar su CA y poner NS_VERIFY_TLS=true.")

    def _headers(self) -> dict:
        return {"Content-Type": "application/json"}

    def subir_archivo_ssl(self, nombre_archivo: str, contenido: bytes,
                           filelocation: str = "/nsconfig/ssl") -> None:
        import base64
        b64 = base64.b64encode(contenido).decode("ascii")
        body = {
            "systemfile": [{
                "filename": nombre_archivo,
                "filelocation": filelocation,
                "filecontent": b64,
                "fileencoding": "BASE64",
            }]
        }
        r = requests.post(f"{self.base_url}/systemfile", json=body,
                           auth=self.auth, headers=self._headers(),
                           verify=self.config.verificar_tls)
        if r.status_code not in (200, 201):
            raise NetScalerError(f"No se pudo subir {nombre_archivo} a {filelocation}: "
                                  f"{r.status_code} {r.text}")
        log.info(f"[NetScaler] Archivo subido: {filelocation}/{nombre_archivo}")

    def certkey_existe(self, certkey: str) -> bool:
        r = requests.get(f"{self.base_url}/sslcertkey/{certkey}",
                          auth=self.auth, headers=self._headers(),
                          verify=self.config.verificar_tls)
        return r.status_code == 200

    def crear_o_actualizar_certkey(self, certkey: str, nombre_archivo: str,
                                    password_pfx: str) -> None:
        cuerpo_certkey = {
            "certkey": certkey,
            "cert": nombre_archivo,
            "key": nombre_archivo,
            "inform": "PFX",
            "password": True,
            "passplain": password_pfx,
        }

        if self.certkey_existe(certkey):
            log.info(f"[NetScaler] '{certkey}' ya existe: se actualiza (renovación in-place).")
            r = requests.put(f"{self.base_url}/sslcertkey", json={"sslcertkey": cuerpo_certkey},
                              auth=self.auth, headers=self._headers(),
                              verify=self.config.verificar_tls)
        else:
            log.info(f"[NetScaler] '{certkey}' no existe: se crea nuevo.")
            r = requests.post(f"{self.base_url}/sslcertkey", json={"sslcertkey": cuerpo_certkey},
                               auth=self.auth, headers=self._headers(),
                               verify=self.config.verificar_tls)

        if r.status_code not in (200, 201):
            raise NetScalerError(f"No se pudo crear/actualizar sslcertkey '{certkey}': "
                                  f"{r.status_code} {r.text}")
        log.info(f"[NetScaler] sslcertkey '{certkey}' OK.")

    def guardar_configuracion(self) -> None:
        r = requests.post(f"{self.base_url}/nsconfig?action=save", json={},
                           auth=self.auth, headers=self._headers(),
                           verify=self.config.verificar_tls)
        if r.status_code not in (200, 201):
            raise NetScalerError(f"No se pudo guardar la configuración: {r.status_code} {r.text}")
        log.info("[NetScaler] Configuración guardada (save ns config).")


def subir_a_netscaler(ruta_pfx: Path, password_pfx: str, certkey: str) -> None:
    """
    Orquesta la subida completa: archivo -> sslcertkey -> save config.
    Requiere NS_HOST / NS_USER / NS_PASSWORD en el entorno.
    """
    config_ns = ConfigNetScaler.desde_entorno()
    cliente_ns = ClienteNetScaler(config_ns)

    nombre_archivo = ruta_pfx.name
    contenido = ruta_pfx.read_bytes()

    cliente_ns.subir_archivo_ssl(nombre_archivo, contenido)
    cliente_ns.crear_o_actualizar_certkey(certkey, nombre_archivo, password_pfx)
    cliente_ns.guardar_configuracion()

    log.info(f"[NetScaler] Certificado '{certkey}' actualizado con {nombre_archivo} "
             f"en {config_ns.host}.")


# ============================================================
# LÓGICA DE NEGOCIO
# ============================================================

def dias_para_expirar(fecha_expires: str) -> int:
    """fecha_expires viene de SCM como 'MM/DD/YYYY' (ej: '04/08/2027')."""
    fecha = datetime.strptime(fecha_expires, "%m/%d/%Y")
    return (fecha - datetime.now()).days


def necesita_renovacion(cert: dict, ventana_dias: int) -> bool:
    restantes = dias_para_expirar(cert["expires"])
    log.info(f"Certificado sslId={cert.get('sslId')} commonName={cert.get('commonName')} "
             f"expira en {restantes} días (expires={cert.get('expires')}).")
    return restantes <= ventana_dias


def verificar_dominio_validado(cliente: ClienteSCM, domain_id: int) -> None:
    dominio = cliente.obtener_dominio(domain_id)
    estado = dominio.get("status") or dominio.get("delegation", {}).get("status")
    log.info(f"Dominio '{dominio.get('name')}' (id {domain_id}): estado={estado}")
    if estado and estado.lower() not in ("validated", "approved", "active"):
        notificar_dominio_no_validado(dominio)
        raise DominioNoValidadoError(
            f"El dominio {dominio.get('name')} no está validado (estado: {estado})."
        )


def notificar_dominio_no_validado(dominio: dict) -> None:
    """
    STUB — reemplazar por el envío real (SMTP interno, Teams, etc.).
    """
    log.warning(
        f"ACCIÓN REQUERIDA: el dominio '{dominio.get('name')}' (id {dominio.get('id')}) "
        f"no está validado en SCM. Debe solicitarse su validación antes de poder emitir."
    )


# ---- Generación de llave y CSR con OpenSSL --------------------------

def _correr_openssl(args: list[str]) -> None:
    log.debug(f"openssl {' '.join(args)}")
    resultado = subprocess.run(["openssl"] + args, capture_output=True, text=True)
    if resultado.returncode != 0:
        log.error(f"openssl {' '.join(args)} -> FALLÓ\n{resultado.stderr}")
        raise OpenSSLError(f"Comando falló: openssl {' '.join(args)}\n{resultado.stderr}")
    log.debug("openssl -> OK")


def generar_archivo_conf(
    ruta_conf: Path,
    common_name: str,
    sans: list[str],
    organization_name: str,
    key_size: int = KEY_SIZE_DEFAULT,
) -> None:
    sans_block = "\n".join(f"DNS.{i+1} = {s}" for i, s in enumerate(sans))
    contenido = PLANTILLA_CONF.format(
        key_size=key_size,
        organization_name=organization_name,
        common_name=common_name,
        sans_block=sans_block,
    )
    ruta_conf.write_text(contenido, encoding="utf-8")
    log.debug(f"Archivo de configuración escrito en {ruta_conf}")


def generar_llave_y_csr(
    directorio: Path,
    common_name: str,
    sans: list[str],
    organization_name: str,
    key_size: int = KEY_SIZE_DEFAULT,
) -> tuple[Path, Path]:
    directorio.mkdir(parents=True, exist_ok=True)
    ruta_key = directorio / f"{common_name}.key"
    ruta_csr = directorio / f"{common_name}.csr"
    ruta_conf = directorio / "archivo.conf"

    generar_archivo_conf(ruta_conf, common_name, sans, organization_name, key_size)

    _correr_openssl(["genrsa", "-out", str(ruta_key), str(key_size)])
    _correr_openssl([
        "req", "-new", "-sha256",
        "-key", str(ruta_key),
        "-config", str(ruta_conf),
        "-out", str(ruta_csr),
    ])

    # La llave privada debe quedar restringida al usuario que corre el script.
    ruta_key.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600

    log.info(f"Llave privada generada: {ruta_key} (permisos 600)")
    log.info(f"CSR generado: {ruta_csr}")
    return ruta_key, ruta_csr


# ---- Normalización del archivo descargado ---------------------------

def normalizar_nombre_archivo(ruta: Path) -> Path:
    """
    Sectigo entrega el PKCS#7 con guiones bajos donde debería haber
    puntos (ej: pruebasura_com.p7b -> pruebasura.com.p7b).
    """
    nuevo_stem = ruta.stem.replace("_", ".")
    nueva_ruta = ruta.with_name(nuevo_stem + ruta.suffix)
    if nueva_ruta != ruta:
        ruta.rename(nueva_ruta)
        log.info(f"Archivo renombrado: {ruta.name} -> {nueva_ruta.name}")
    return nueva_ruta


# ---- Conversión P7B -> PEM -> PFX ------------------------------------

def convertir_p7b_a_pem(ruta_p7b: Path) -> Path:
    ruta_pem = ruta_p7b.with_suffix(".pem")

    with open(ruta_p7b, "rb") as f:
        inicio = f.read(20)
    inform = "PEM" if inicio.startswith(b"-----BEGIN") else "DER"

    _correr_openssl([
        "pkcs7", "-in", str(ruta_p7b), "-inform", inform,
        "-out", str(ruta_pem), "-print_certs",
    ])
    log.info(f"Convertido a PEM ({inform} -> PEM): {ruta_pem}")
    return ruta_pem


def convertir_pem_a_pfx(ruta_key: Path, ruta_pem: Path, password: str) -> Path:
    ruta_pfx = ruta_pem.with_suffix(".pfx")
    _correr_openssl([
        "pkcs12", "-export",
        "-inkey", str(ruta_key),
        "-in", str(ruta_pem),
        "-out", str(ruta_pfx),
        "-passout", f"pass:{password}",
    ])
    ruta_pfx.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
    log.info(f"PFX generado: {ruta_pfx} (permisos 600)")
    return ruta_pfx


def generar_password_pfx(longitud: int = PWD_LONGITUD_DEFAULT) -> str:
    mayus = string.ascii_uppercase
    minus = string.ascii_lowercase
    digitos = string.digits
    simbolos = PWD_SPECIALS

    obligatorios = [
        secrets.choice(mayus),
        secrets.choice(minus),
        secrets.choice(digitos),
        secrets.choice(simbolos),
    ]
    alfabeto = mayus + minus + digitos + simbolos
    resto = [secrets.choice(alfabeto) for _ in range(longitud - len(obligatorios))]

    password_chars = obligatorios + resto
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def guardar_password_en_archivo(ruta_pfx: Path, password: str) -> Path:
    """
    Guarda la contraseña en un archivo separado, con permisos 600,
    junto al .pfx. La contraseña NUNCA se imprime en consola ni se
    escribe en el log.
    """
    ruta_password = ruta_pfx.with_suffix(".password.txt")
    ruta_password.write_text(password, encoding="utf-8")
    ruta_password.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
    log.info(f"Contraseña del PFX guardada en {ruta_password} (permisos 600, "
             f"no se registra el valor en este log)")
    return ruta_password


# ============================================================
# FLUJO PRINCIPAL
# ============================================================

def flujo_renovacion(
    cliente: ClienteSCM,
    ssl_id_actual: int,
    referencia: str,
    domain_id: Optional[int],
    ventana_dias: int,
    directorio_trabajo: Path,
    ejecutar: bool,
    subir_netscaler: bool = False,
    netscaler_certkey: Optional[str] = None,
) -> Optional[Path]:
    cert_actual = cliente.obtener_certificado(ssl_id_actual)

    if not necesita_renovacion(cert_actual, ventana_dias):
        log.info("Todavía no entra en la ventana de renovación. No se hace nada.")
        return None

    org_id = cert_actual["orgId"]
    common_name = cert_actual["commonName"]
    cert_type_id = cert_actual["certTypeId"]
    cert_type_name = cert_actual.get("certTypeName", "desconocido")
    term_dias = cert_actual.get("term", 199)

    log.info(f"Perfil detectado del certificado existente: '{cert_type_name}' "
             f"(id {cert_type_id}), vigencia {term_dias} días.")

    if domain_id is not None:
        verificar_dominio_validado(cliente, domain_id)
    else:
        log.warning("No se indicó --domain-id: se omite la verificación de "
                    "validación de dominio. Recomendado pasarlo siempre.")

    sans = [common_name]

    if not ejecutar:
        log.info("[DRY-RUN] No se va a llamar a OpenSSL ni a /enroll. Esto es lo que se haría:")
        log.info(f"  - Generar llave + CSR para {common_name}")
        log.info(f"  - Enroll con orgId={org_id}, certType={cert_type_id}, "
                 f"term={term_dias}, comments='{referencia}'")
        log.info("  - Descargar, convertir a PEM y generar PFX")
        log.info("Corre con --ejecutar para hacerlo de verdad.")
        return None

    subject = cert_actual.get("subject", "")
    organization_name = subject.split("O=")[-1].split(",")[0] if "O=" in subject else ""

    ruta_key, ruta_csr = generar_llave_y_csr(
        directorio_trabajo, common_name, sans, organization_name
    )
    csr_texto = ruta_csr.read_text(encoding="utf-8")

    resultado_enroll = cliente.enroll(
        org_id=org_id,
        cert_type_id=cert_type_id,
        csr=csr_texto,
        term_dias=term_dias,
        comentario=referencia,
        subj_alt_names=",".join(sans),
    )
    nuevo_ssl_id = resultado_enroll["sslId"]
    log.info(f"Solicitud enviada. Nuevo sslId: {nuevo_ssl_id}")

    formato = os.environ.get("SCM_COLLECT_FORMAT") or cliente.descubrir_formato_collect(nuevo_ssl_id)

    contenido = None
    for intento in range(1, COLLECT_MAX_INTENTOS + 1):
        try:
            contenido = cliente.collect(nuevo_ssl_id, formato)
            break
        except CertificadoPendienteError:
            log.info(f"Certificado aún pendiente (intento {intento}/{COLLECT_MAX_INTENTOS}). "
                     f"Reintentando en {COLLECT_ESPERA_SEGUNDOS}s...")
            time.sleep(COLLECT_ESPERA_SEGUNDOS)

    if contenido is None:
        raise SCMError(
            f"El certificado {nuevo_ssl_id} sigue pendiente tras "
            f"{COLLECT_MAX_INTENTOS} intentos. Revísalo manualmente en el portal."
        )

    ruta_p7b = directorio_trabajo / f"{common_name}.p7b"
    ruta_p7b.write_bytes(contenido)
    ruta_p7b = normalizar_nombre_archivo(ruta_p7b)

    ruta_pem = convertir_p7b_a_pem(ruta_p7b)
    password = generar_password_pfx()
    ruta_pfx = convertir_pem_a_pfx(ruta_key, ruta_pem, password)
    guardar_password_en_archivo(ruta_pfx, password)

    if subir_netscaler:
        if not netscaler_certkey:
            raise NetScalerError(
                "--subir-netscaler requiere --netscaler-certkey con el nombre exacto "
                "del sslcertkey en el NetScaler (ej: pruebaclm.labsura.com_2026)."
            )
        subir_a_netscaler(ruta_pfx, password, netscaler_certkey)
    else:
        log.info("No se subió al NetScaler (usa --subir-netscaler para hacerlo).")

    log.info(f"RESULTADO run_id={RUN_ID} ssl_id_nuevo={nuevo_ssl_id} "
             f"commonName={common_name} estado=OK archivo_pfx={ruta_pfx} "
             f"subido_netscaler={subir_netscaler}")

    return ruta_pfx


# ============================================================
# CLI
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automatiza la renovación/emisión de certificados en Sectigo SCM."
    )
    parser.add_argument("--ssl-id", type=int, required=True,
                         help="sslId del certificado actual a renovar.")
    parser.add_argument("--referencia", required=True,
                         help="Número de catálogo (solicitud nueva) u OC (renovación), "
                              "va en el campo de comentarios.")
    parser.add_argument("--domain-id", type=int, default=None,
                         help="id del dominio en SCM, para validar antes de emitir.")
    parser.add_argument("--ventana-dias", type=int, default=VENTANA_RENOVACION_DIAS_DEFAULT,
                         help=f"Días antes del vencimiento para considerar renovación "
                              f"(default {VENTANA_RENOVACION_DIAS_DEFAULT}).")
    parser.add_argument("--directorio-trabajo", default="./trabajo_certificados",
                         help="Carpeta donde se generan llave, CSR, p7b, pem y pfx.")
    parser.add_argument("--log-dir", default="./logs",
                         help="Carpeta donde se escriben los logs (default ./logs).")
    parser.add_argument("--log-level", default="INFO",
                         choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                         help="Nivel de detalle del log (default INFO; usa DEBUG para "
                              "ver cada llamada HTTP y comando de OpenSSL).")
    parser.add_argument("--ejecutar", action="store_true",
                         help="Sin esta bandera, el script solo simula (dry-run).")
    parser.add_argument("--subir-netscaler", action="store_true",
                         help="Además de generar el .pfx, lo sube al NetScaler por NITRO. "
                              "Requiere NS_HOST/NS_USER/NS_PASSWORD en el entorno y "
                              "--netscaler-certkey.")
    parser.add_argument("--netscaler-certkey", default=None,
                         help="Nombre exacto del objeto sslcertkey a crear/actualizar en el "
                              "NetScaler (ej: pruebaclm.labsura.com_2026). Se ve con: "
                              "curl .../nitro/v1/config/sslcertkey")

    args = parser.parse_args()

    configurar_logging(Path(args.log_dir), args.log_level)

    config = ConfigSCM.desde_entorno()
    cliente = ClienteSCM(config)
    directorio_trabajo = Path(args.directorio_trabajo)

    try:
        flujo_renovacion(
            cliente=cliente,
            ssl_id_actual=args.ssl_id,
            referencia=args.referencia,
            domain_id=args.domain_id,
            ventana_dias=args.ventana_dias,
            directorio_trabajo=directorio_trabajo,
            ejecutar=args.ejecutar,
            subir_netscaler=args.subir_netscaler,
            netscaler_certkey=args.netscaler_certkey,
        )
    except (SCMError, DominioNoValidadoError, OpenSSLError, NetScalerError) as e:
        log.error(f"RESULTADO run_id={RUN_ID} estado=ERROR mensaje={e}")
        sys.exit(1)
    except Exception:
        log.exception(f"RESULTADO run_id={RUN_ID} estado=ERROR_INESPERADO")
        sys.exit(1)
    finally:
        log.info(f"=== Fin de ejecución (run_id={RUN_ID}) ===")


if __name__ == "__main__":
    main()