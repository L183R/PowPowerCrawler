# PowPowerCrawler - Web Recon Tool con funcionalidades avanzadas
import argparse
import json
import os
import re
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

EXTENSIONES_BINARIAS = (
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".odg",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".mp4", ".webm", ".mov",
    ".mp3", ".wav", ".ogg",
    ".css", ".js", ".html", ".htm",
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; PowPowerCrawler/1.0)",
}

HEADERS_CRITICOS = [
    "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy",
    "Strict-Transport-Security", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
]

PATHS_SENSIBLES = [
    "/robots.txt", "/admin", "/wp-admin", "/login", "/cpanel", "/phpmyadmin",
    "/.env", "/config.php", "/.git", "/.htaccess", "/readme.html",
    "/index.php.bak", "/wp-config.php.save", "/config.old", "/.backup",
]

TIPOS_DESCARGA = {
    "img": (".jpg", ".jpeg", ".png", ".gif", ".svg"),
    "vid": (".mp4", ".webm", ".mov"),
    "aud": (".mp3", ".wav", ".ogg"),
    "doc": (
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".odg",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ),
    "css": (".css",),
    "js": (".js",),
    "html": (".html", ".htm"),
}


class PowPowerCrawler:
    def __init__(self, args):
        self.args = args
        self.base_url = self._preparar_url(args.url)
        self.dominio = urlparse(self.base_url).netloc.replace("www.", "")
        self.archivo_salida = f"{self.dominio}.txt"
        self.archivo_estado = f"{self.dominio}_estado.json"
        self.verify_tls = not args.insecure
        self.lock = threading.Lock()
        self.visitados = set()
        self.pendientes = deque()
        self.urls_paginas = set()
        self.archivos = {}
        self.endpoints_detectados = set()
        self.formularios_detectados = {}
        self.cabeceras_inseguras = {}
        self.cookies_inseguras = {}
        self.paths_sensibles = set()
        self.paths_sensibles_probados = set()
        self.correos_encontrados = set()
        self.telefonos_encontrados = set()
        self.contador = 0

    @staticmethod
    def _preparar_url(url):
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url if url.endswith("/") else url + "/"

    def out(self, msg):
        if not self.args.quiet:
            print(msg)

    def request(self, metodo, url, **kwargs):
        if self.args.delay > 0:
            time.sleep(self.args.delay)
        return requests.request(
            metodo,
            url,
            timeout=self.args.timeout,
            verify=self.verify_tls,
            headers=HEADERS,
            **kwargs,
        )

    def guardar_archivo(self, url, contenido):
        ext = os.path.splitext(urlparse(url).path)[1].lower()
        if not ext:
            return
        carpeta = "descargas"
        for nombre_carpeta, extensiones in TIPOS_DESCARGA.items():
            if ext in extensiones:
                carpeta = nombre_carpeta
                break
        os.makedirs(carpeta, exist_ok=True)
        nombre = os.path.basename(urlparse(url).path) or "index"
        ruta = os.path.join(carpeta, nombre)
        with open(ruta, "wb") as f:
            f.write(contenido)

    def buscar_correos_telefonos(self, texto):
        correos = re.findall(r"[\w\.-]+@[\w\.-]+", texto)
        telefonos = re.findall(r"\b\+?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{4,}\b", texto)
        with self.lock:
            self.correos_encontrados.update(correos)
            self.telefonos_encontrados.update(telefonos)

    def guardar_estado(self):
        with self.lock:
            estado = {
                "visitados": list(self.visitados),
                "pendientes": list(self.pendientes),
                "urls_paginas": list(self.urls_paginas),
                "archivos": self.archivos,
                "endpoints": list(self.endpoints_detectados),
                "formularios": self.formularios_detectados,
                "cabeceras_inseguras": self.cabeceras_inseguras,
                "cookies_inseguras": self.cookies_inseguras,
                "paths_sensibles": list(self.paths_sensibles),
                "paths_sensibles_probados": list(self.paths_sensibles_probados),
                "correos": list(self.correos_encontrados),
                "telefonos": list(self.telefonos_encontrados),
            }
            with open(self.archivo_estado, "w", encoding="utf-8") as f:
                json.dump(estado, f, ensure_ascii=False, indent=2)

    def cargar_estado(self):
        if self.args.omitir and os.path.exists(self.archivo_estado):
            os.remove(self.archivo_estado)
            self.out(f"🗑️ Estado anterior eliminado: {self.archivo_estado}")
            return False
        if os.path.exists(self.archivo_estado) and self.args.continuar and not self.args.omitir:
            with open(self.archivo_estado, "r", encoding="utf-8") as f:
                estado = json.load(f)
            self.visitados.update(estado.get("visitados", []))
            self.pendientes.extend(estado.get("pendientes", []))
            self.urls_paginas.update(estado.get("urls_paginas", []))
            self.archivos.update(estado.get("archivos", {}))
            self.endpoints_detectados.update(estado.get("endpoints", []))
            self.formularios_detectados.update(estado.get("formularios", {}))
            self.cabeceras_inseguras.update(estado.get("cabeceras_inseguras", {}))
            self.cookies_inseguras.update(estado.get("cookies_inseguras", {}))
            self.paths_sensibles.update(estado.get("paths_sensibles", []))
            self.paths_sensibles_probados.update(estado.get("paths_sensibles_probados", []))
            self.correos_encontrados.update(estado.get("correos", []))
            self.telefonos_encontrados.update(estado.get("telefonos", []))
            self.out(f"✅ Estado anterior cargado desde: {self.archivo_estado}")
            return True
        return False

    def es_interno(self, url):
        netloc = urlparse(url).netloc.replace("www.", "")
        return netloc == "" or netloc == self.dominio

    @staticmethod
    def normalizar(url):
        return url.split("#")[0].split("?")[0].rstrip("/")

    def extensiones_activas(self):
        if self.args.estaticos:
            return TIPOS_DESCARGA["css"] + TIPOS_DESCARGA["js"] + TIPOS_DESCARGA["html"]
        if self.args.multimedia:
            return TIPOS_DESCARGA["img"] + TIPOS_DESCARGA["vid"] + TIPOS_DESCARGA["aud"] + TIPOS_DESCARGA["doc"]
        for flag, extensiones in TIPOS_DESCARGA.items():
            if getattr(self.args, flag):
                return extensiones
        return EXTENSIONES_BINARIAS

    def es_binario(self, url):
        return url.lower().endswith(self.extensiones_activas())

    def buscar_endpoints_ajax(self, html):
        endpoints = set()
        scripts = re.findall(r"https?://[^\"']+", html)
        for script_url in scripts:
            if any(x in script_url for x in ["ajax", "api", "json", "wp-json"]):
                endpoints.add(script_url)
        rels = re.findall(r"(\"|')(\/wp-json[^\"']+)", html)
        for _, ruta in rels:
            endpoints.add(urljoin(self.base_url, ruta))
        return endpoints

    def extraer_links(self, html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for tag in soup.find_all(["a", "link"], href=True):
            href = self.normalizar(urljoin(base_url, tag["href"]))
            if self.es_interno(href):
                links.add(href)
        for tag in soup.find_all(src=True):
            src = self.normalizar(urljoin(base_url, tag["src"]))
            if self.es_interno(src):
                links.add(src)
        for url in re.findall(r"https?://[^\s\"'<>]+", html):
            url = self.normalizar(url)
            if self.es_interno(url):
                links.add(url)
        return links

    @staticmethod
    def extraer_inputs(html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        inputs = []
        for form in soup.find_all("form"):
            form_info = {
                "action": urljoin(base_url, form.get("action", base_url)),
                "method": form.get("method", "get").lower(),
                "inputs": [],
            }
            for inp in form.find_all(["input", "button", "select", "textarea"]):
                form_info["inputs"].append(inp.get("name", ""))
            if form_info["inputs"]:
                inputs.append(form_info)
        return inputs

    def procesar_archivo(self, actual):
        head = self.request("HEAD", actual, allow_redirects=True)
        peso = int(head.headers.get("Content-Length", 0))
        with self.lock:
            self.archivos[actual] = peso
            self.out(f"  📦 Archivo detectado: {actual} ({peso / 1024:.1f} KB)")
        if self.args.descargar:
            respuesta = self.request("GET", actual, allow_redirects=True)
            respuesta.raise_for_status()
            self.guardar_archivo(actual, respuesta.content)
            self.out(f"  💾 Archivo descargado: {actual}")

    def revisar_paths_sensibles(self):
        for path in PATHS_SENSIBLES:
            url_sensible = urljoin(self.base_url, path)
            with self.lock:
                if url_sensible in self.paths_sensibles_probados:
                    continue
                self.paths_sensibles_probados.add(url_sensible)
            try:
                respuesta = self.request("GET", url_sensible)
                if respuesta.status_code == 200:
                    with self.lock:
                        self.paths_sensibles.add(url_sensible)
            except requests.RequestException as exc:
                self.out(f"   ⚠️ Error al revisar {url_sensible}: {exc}")

    def procesar_url(self, actual):
        with self.lock:
            actual = self.normalizar(actual)
            if actual in self.visitados:
                return
            if self.args.max_pages and self.contador >= self.args.max_pages:
                return
            self.visitados.add(actual)
            self.contador += 1
            self.out(f"[{self.contador}/{len(self.visitados) + len(self.pendientes)}] Visitando: {actual}")

        try:
            if self.es_binario(actual):
                self.procesar_archivo(actual)
                return

            respuesta = self.request("GET", actual)
            if "text/html" not in respuesta.headers.get("Content-Type", ""):
                self.out(f"  ⚠️ No es HTML, ignorado: {actual}")
                return

            self.buscar_correos_telefonos(respuesta.text)
            nuevos_links = self.extraer_links(respuesta.text, actual)
            with self.lock:
                self.urls_paginas.add(actual)
                for link in nuevos_links:
                    if link not in self.visitados and link not in self.pendientes:
                        self.pendientes.append(link)

            formularios = self.extraer_inputs(respuesta.text, actual)
            if formularios:
                with self.lock:
                    self.formularios_detectados[actual] = formularios

            self.procesar_endpoints(respuesta.text)

            inseguras = [h for h in HEADERS_CRITICOS if h not in respuesta.headers]
            if inseguras:
                with self.lock:
                    self.cabeceras_inseguras[actual] = inseguras

            for cookie in respuesta.cookies:
                if not cookie.secure or not cookie.has_nonstandard_attr("HttpOnly"):
                    with self.lock:
                        self.cookies_inseguras.setdefault(actual, []).append({
                            cookie.name: {
                                "secure": cookie.secure,
                                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                            }
                        })

        except requests.RequestException as exc:
            self.out(f"   ⚠️ Error de request en {actual}: {exc}")
        except ValueError as exc:
            self.out(f"   ⚠️ Error procesando {actual}: {exc}")

    def procesar_endpoints(self, html):
        for endpoint in self.buscar_endpoints_ajax(html):
            with self.lock:
                if endpoint in self.endpoints_detectados:
                    continue
                self.endpoints_detectados.add(endpoint)
            try:
                respuesta = self.request("GET", endpoint)
                links_json = re.findall(r"https?://[^\s\",]+", respuesta.text)
                with self.lock:
                    for link in links_json:
                        link = self.normalizar(link)
                        if self.es_interno(link) and link not in self.visitados and link not in self.pendientes:
                            self.pendientes.append(link)
            except requests.RequestException as exc:
                self.out(f"   ⚠️ Error al consultar endpoint {endpoint}: {exc}")

    def ejecutar(self):
        if not self.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if not self.cargar_estado():
            self.pendientes.append(self.base_url)
        self.revisar_paths_sensibles()

        while self.pendientes:
            if self.args.max_pages and self.contador >= self.args.max_pages:
                break
            batch = []
            with self.lock:
                while self.pendientes and len(batch) < self.args.threads:
                    batch.append(self.pendientes.popleft())
            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                list(executor.map(self.procesar_url, batch))

            if self.contador and self.contador % self.args.guardar_cada == 0:
                self.guardar_estado()

        self.guardar_estado()
        self.escribir_reporte()
        self.imprimir_resumen()

    def escribir_reporte(self):
        with open(self.archivo_salida, "w", encoding="utf-8") as f:
            f.write(f"Resumen de escaneo de {self.dominio}\n")
            f.write("=" * 60 + "\n\n")
            f.write("🌐 Páginas HTML encontradas:\n")
            f.write("-" * 40 + "\n")
            for url in sorted(self.urls_paginas):
                f.write(f"{url}\n")

            f.write("\n📦 Archivos detectados:\n")
            f.write("-" * 40 + "\n")
            for url, peso in sorted(self.archivos.items(), key=lambda x: x[1], reverse=True):
                peso_fmt = f"{peso / 1024 / 1024:.2f} MB" if peso >= 1024 * 1024 else f"{peso / 1024:.1f} KB"
                f.write(f"{url}  ->  {peso_fmt}\n")

            if self.archivos:
                mayor = max(self.archivos.items(), key=lambda x: x[1])
                peso_fmt = f"{mayor[1] / 1024 / 1024:.2f} MB" if mayor[1] >= 1024 * 1024 else f"{mayor[1] / 1024:.1f} KB"
                f.write(f"\n📁 Archivo más pesado:\n{'-' * 40}\n{mayor[0]}  ->  {peso_fmt}\n")

            f.write("\n📝 Formularios detectados:\n")
            f.write("-" * 40 + "\n")
            for pagina, forms in self.formularios_detectados.items():
                f.write(f"{pagina}\n")
                for form in forms:
                    f.write(f"  - Acción: {form['action']} | Método: {form['method']} | Inputs: {', '.join(form['inputs'])}\n")

            f.write("\n🔐 Headers de seguridad faltantes:\n")
            f.write("-" * 40 + "\n")
            for pagina, faltan in self.cabeceras_inseguras.items():
                f.write(f"{pagina}  ->  {', '.join(faltan)}\n")

            f.write("\n🍪 Cookies inseguras detectadas:\n")
            f.write("-" * 40 + "\n")
            for pagina, cookies in self.cookies_inseguras.items():
                f.write(f"{pagina}\n")
                for cookie in cookies:
                    for nombre, detalles in cookie.items():
                        f.write(f"  - {nombre}: {detalles}\n")

            f.write("\n🛡️ Rutas sensibles detectadas:\n")
            f.write("-" * 40 + "\n")
            for path in sorted(self.paths_sensibles):
                f.write(f"{path}\n")

            f.write("\n📧 Correos encontrados:\n")
            f.write("-" * 40 + "\n")
            for correo in sorted(self.correos_encontrados):
                f.write(f"{correo}\n")

            f.write("\n☎️ Teléfonos encontrados:\n")
            f.write("-" * 40 + "\n")
            for telefono in sorted(self.telefonos_encontrados):
                f.write(f"{telefono}\n")

    def imprimir_resumen(self):
        self.out("\n🚀 Escaneo terminado.")
        self.out(f"🌐 Páginas encontradas: {len(self.urls_paginas)}")
        self.out(f"📦 Archivos detectados: {len(self.archivos)}")
        if self.archivos:
            mayor = max(self.archivos.items(), key=lambda x: x[1])
            peso_fmt = f"{mayor[1] / 1024 / 1024:.2f} MB" if mayor[1] >= 1024 * 1024 else f"{mayor[1] / 1024:.1f} KB"
            self.out(f"📁 Archivo más pesado: {mayor[0]} ({peso_fmt})")
        self.out(f"📝 Formularios encontrados: {len(self.formularios_detectados)}")
        self.out(f"🔐 Headers inseguros: {len(self.cabeceras_inseguras)}")
        self.out(f"🍪 Cookies inseguras: {len(self.cookies_inseguras)}")
        self.out(f"🛡️ Rutas sensibles: {len(self.paths_sensibles)}")
        self.out(f"📧 Correos encontrados: {len(self.correos_encontrados)}")
        self.out(f"☎️ Teléfonos encontrados: {len(self.telefonos_encontrados)}")
        self.out(f"📍 Guardado en: {self.archivo_salida}")


def parse_args():
    parser = argparse.ArgumentParser(description="PowPowerCrawler - Web Recon Tool")
    parser.add_argument("-u", "--url", required=True, help="URL de la web a escanear (ej: https://ejemplo.com/)")
    parser.add_argument("--estaticos", action="store_true", help="Procesar solo archivos estáticos (CSS, JS, HTML)")
    parser.add_argument("--multimedia", action="store_true", help="Procesar solo archivos multimedia (imágenes, videos, audio, documentos)")
    parser.add_argument("--img", action="store_true", help="Procesar solo imágenes")
    parser.add_argument("--vid", action="store_true", help="Procesar solo videos")
    parser.add_argument("--aud", action="store_true", help="Procesar solo archivos de audio")
    parser.add_argument("--doc", action="store_true", help="Procesar solo documentos")
    parser.add_argument("--css", action="store_true", help="Procesar solo archivos CSS")
    parser.add_argument("--js", action="store_true", help="Procesar solo archivos JS")
    parser.add_argument("--html", action="store_true", help="Procesar solo archivos HTML")
    parser.add_argument("--descargar", action="store_true", help="Descargar archivos detectados, además de registrarlos")
    parser.add_argument("--continuar", action="store_true", help="Continuar un escaneo anterior si existe")
    parser.add_argument("--omitir", action="store_true", help="Omitir cualquier escaneo anterior y empezar desde cero")
    parser.add_argument("--delay", type=float, default=0.0, help="Tiempo de espera entre requests (en segundos)")
    parser.add_argument("--quiet", action="store_true", help="Modo silencioso, sin salida informativa en consola")
    parser.add_argument("--threads", type=int, default=10, help="Cantidad de hilos concurrentes")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout por request (en segundos)")
    parser.add_argument("--max-pages", type=int, default=0, help="Máximo de páginas a visitar (0 = sin límite)")
    parser.add_argument("--guardar-cada", type=int, default=100, help="Guardar estado cada N páginas procesadas")
    parser.add_argument("--insecure", action="store_true", help="Desactivar validación TLS y ocultar warnings de certificados")
    return parser.parse_args()


def main():
    args = parse_args()
    crawler = PowPowerCrawler(args)
    crawler.ejecutar()


if __name__ == "__main__":
    main()
