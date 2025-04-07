# PowPowerCrawler - Web Recon Tool con funcionalidades avanzadas
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import threading
import urllib3
import os
import json
import argparse
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description="PowPowerCrawler - Web Recon Tool")
parser.add_argument("-u", "--url", required=True, help="URL de la web a escanear (ej: https://ejemplo.com/)")
parser.add_argument("--estaticos", action="store_true", help="Descargar solo archivos estáticos (CSS, JS, HTML)")
parser.add_argument("--multimedia", action="store_true", help="Descargar solo archivos multimedia (imágenes, videos, audio, documentos)")
parser.add_argument("--img", action="store_true", help="Descargar solo imágenes")
parser.add_argument("--vid", action="store_true", help="Descargar solo videos")
parser.add_argument("--aud", action="store_true", help="Descargar solo archivos de audio")
parser.add_argument("--doc", action="store_true", help="Descargar solo documentos")
parser.add_argument("--css", action="store_true", help="Descargar solo archivos CSS")
parser.add_argument("--js", action="store_true", help="Descargar solo archivos JS")
parser.add_argument("--html", action="store_true", help="Descargar solo archivos HTML")
parser.add_argument("--continuar", action="store_true", help="Continuar un escaneo anterior si existe")
parser.add_argument("--omitir", action="store_true", help="Omitir cualquier escaneo anterior y empezar desde cero")
parser.add_argument("--delay", type=float, default=0.0, help="Tiempo de espera entre requests (en segundos)")
parser.add_argument("--quiet", action="store_true", help="Modo silencioso, sin salida en consola")
args = parser.parse_args()

MODO_ESTATICOS = args.estaticos
MODO_MULTIMEDIA = args.multimedia
CONTINUAR_ANTERIOR = args.continuar
OMITIR_ANTERIOR = args.omitir
DELAY = args.delay
MODO_SILENCIOSO = args.quiet

url_input = args.url.strip()
if not url_input.startswith("http"):
    url_input = "http://" + url_input
BASE_URL = url_input if url_input.endswith("/") else url_input + "/"
DOMINIO = urlparse(BASE_URL).netloc.replace("www.", "")
ARCHIVO_SALIDA = f"{DOMINIO}.txt"
ARCHIVO_ESTADO = f"{DOMINIO}_estado.json"

visitados = set()
pendientes = deque()
urls_paginas = set()
archivos = {}
endpoints_detectados = set()
formularios_detectados = {}
cabeceras_inseguras = {}
cookies_inseguras = {}
paths_sensibles = set()
correos_encontrados = set()
telefonos_encontrados = set()
lock = threading.Lock()

EXTENSIONES_BINARIAS = (
    '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp', '.odg',
    '.jpg', '.jpeg', '.png', '.gif', '.svg', '.mp4', '.webm', '.mov',
    '.mp3', '.wav', '.ogg',
    '.css', '.js', '.html', '.htm'
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; PowPowerCrawler/1.0)"
}

THREADS = 10
GUARDAR_CADA = 100

HEADERS_CRITICOS = [
    "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy",
    "Strict-Transport-Security", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy"
]

PATHS_SENSIBLES = [
    "/robots.txt", "/admin", "/wp-admin", "/login", "/cpanel", "/phpmyadmin",
    "/.env", "/config.php", "/.git", "/.htaccess", "/readme.html",
    "/index.php.bak", "/wp-config.php.save", "/config.old", "/.backup"
]

def out(msg):
    if not MODO_SILENCIOSO:
        print(msg)

def guardar_archivo(url, contenido):
    ext = os.path.splitext(urlparse(url).path)[1].lower()
    if not ext:
        return
    carpeta = "descargas"
    if ext in ('.jpg', '.jpeg', '.png', '.gif', '.svg'):
        carpeta = "img"
    elif ext in ('.mp4', '.webm', '.mov'):
        carpeta = "vid"
    elif ext in ('.mp3', '.wav', '.ogg'):
        carpeta = "aud"
    elif ext in ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp', '.odg', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'):
        carpeta = "doc"
    elif ext == '.css':
        carpeta = "css"
    elif ext == '.js':
        carpeta = "js"
    elif ext in ('.html', '.htm'):
        carpeta = "html"
    os.makedirs(carpeta, exist_ok=True)
    nombre = os.path.basename(urlparse(url).path)
    ruta = os.path.join(carpeta, nombre)
    with open(ruta, "wb") as f:
        f.write(contenido)

def buscar_correos_telefonos(texto):
    correos = re.findall(r"[\w\.-]+@[\w\.-]+", texto)
    telefonos = re.findall(r"\b\+?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{4,}\b", texto)
    with lock:
        correos_encontrados.update(correos)
        telefonos_encontrados.update(telefonos)

def guardar_estado():
    with lock:
        estado = {
            'visitados': list(visitados),
            'pendientes': list(pendientes),
            'urls_paginas': list(urls_paginas),
            'archivos': archivos,
            'endpoints': list(endpoints_detectados),
            'formularios': formularios_detectados
        }
        with open(ARCHIVO_ESTADO, 'w', encoding='utf-8') as f:
            json.dump(estado, f)

def cargar_estado():
    if OMITIR_ANTERIOR and os.path.exists(ARCHIVO_ESTADO):
        os.remove(ARCHIVO_ESTADO)
        print(f"🗑️ Estado anterior eliminado: {ARCHIVO_ESTADO}")
        return False
    if os.path.exists(ARCHIVO_ESTADO) and CONTINUAR_ANTERIOR and not OMITIR_ANTERIOR:
        with open(ARCHIVO_ESTADO, 'r', encoding='utf-8') as f:
            estado = json.load(f)
            visitados.update(estado['visitados'])
            pendientes.extend(estado['pendientes'])
            urls_paginas.update(estado['urls_paginas'])
            archivos.update(estado['archivos'])
            endpoints_detectados.update(estado['endpoints'])
            formularios_detectados.update(estado['formularios'])
        print(f"✅ Estado anterior cargado desde: {ARCHIVO_ESTADO}")
        return True
    return False

def es_interno(url):
    netloc = urlparse(url).netloc.replace("www.", "")
    return netloc == '' or netloc == DOMINIO

def normalizar(url):
    return url.split("#")[0].split("?")[0].rstrip("/")

def es_binario(url):
    url = url.lower()
    if MODO_ESTATICOS:
        return url.endswith(('.css', '.js', '.html', '.htm'))
    elif MODO_MULTIMEDIA:
        return url.endswith(('.jpg', '.jpeg', '.png', '.gif', '.svg',
                            '.mp4', '.webm', '.mov',
                            '.mp3', '.wav', '.ogg',
                            '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
                            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp', '.odg'))
    elif args.img:
        return url.endswith(('.jpg', '.jpeg', '.png', '.gif', '.svg'))
    elif args.vid:
        return url.endswith(('.mp4', '.webm', '.mov'))
    elif args.aud:
        return url.endswith(('.mp3', '.wav', '.ogg'))
    elif args.doc:
        return url.endswith(('.pdf', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
                            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp', '.odg'))
    elif args.css:
        return url.endswith('.css')
    elif args.js:
        return url.endswith('.js')
    elif args.html:
        return url.endswith(('.html', '.htm'))
    else:
        return url.endswith(EXTENSIONES_BINARIAS)

def buscar_endpoints_ajax(html):
    endpoints = set()
    scripts = re.findall(r'(https?://[^"\']+)', html)
    for s in scripts:
        if any(x in s for x in ['ajax', 'api', 'json', 'wp-json']):
            endpoints.add(s)
    rels = re.findall(r'("|\')(\/wp-json[^"\']+)', html)
    for _, r in rels:
        full = urljoin(BASE_URL, r)
        endpoints.add(full)
    return endpoints

def extraer_links(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for tag in soup.find_all(['a', 'link'], href=True):
        href = urljoin(base_url, tag['href'])
        href = normalizar(href)
        if es_interno(href):
            links.add(href)
    for tag in soup.find_all(src=True):
        src = urljoin(base_url, tag['src'])
        src = normalizar(src)
        if es_interno(src):
            links.add(src)
    urls_en_texto = re.findall(r'https?://[^\s"\'<>]+', html)
    for u in urls_en_texto:
        u = normalizar(u)
        if es_interno(u):
            links.add(u)
    return links

def extraer_inputs(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    inputs = []
    for form in soup.find_all('form'):
        form_info = {
            'action': form.get('action', base_url),
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        for inp in form.find_all(['input', 'button', 'select']):
            form_info['inputs'].append(inp.get('name', ''))
        if form_info['inputs']:
            inputs.append(form_info)
    return inputs

def procesar_url(actual):
    global contador
    with lock:
        actual = normalizar(actual)
        if actual in visitados:
            return
        visitados.add(actual)
        contador += 1
        print(f"[{contador}/{len(visitados) + len(pendientes)}] Visitando: {actual}")

    try:
        if es_binario(actual):
            head = requests.head(actual, allow_redirects=True, timeout=5, verify=False, headers=HEADERS)
            peso = int(head.headers.get("Content-Length", 0))
            with lock:
                archivos[actual] = peso
                print(f"  📦 Archivo detectado: {actual} ({peso/1024:.1f} KB)")
            return

        r = requests.get(actual, timeout=5, verify=False, headers=HEADERS)
        if 'text/html' not in r.headers.get('Content-Type', ''):
            print(f"  ⚠️ No es HTML, ignorado: {actual}")
            return

        nuevos_links = extraer_links(r.text, actual)
        with lock:
            urls_paginas.add(actual)
            for link in nuevos_links:
                if link not in visitados and link not in pendientes:
                    pendientes.append(link)

        formularios = extraer_inputs(r.text, actual)
        if formularios:
            with lock:
                formularios_detectados[actual] = formularios

        endpoints = buscar_endpoints_ajax(r.text)
        for ep in endpoints:
            with lock:
                if ep in endpoints_detectados:
                    continue
                endpoints_detectados.add(ep)
            try:
                rep = requests.get(ep, timeout=5, verify=False, headers=HEADERS)
                links_json = re.findall(r'https?://[^\s",]+', rep.text)
                with lock:
                    for l in links_json:
                        l = normalizar(l)
                        if es_interno(l) and l not in visitados and l not in pendientes:
                            pendientes.append(l)
            except:
                pass

        inseguras = [h for h in HEADERS_CRITICOS if h not in r.headers]
        if inseguras:
            with lock:
                cabeceras_inseguras[actual] = inseguras

        for c in r.cookies:
            if not c.secure or not c.has_nonstandard_attr("HttpOnly"):
                with lock:
                    cookies_inseguras.setdefault(actual, []).append({c.name: dict(secure=c.secure, httponly=c.has_nonstandard_attr("HttpOnly"))})

        for path in PATHS_SENSIBLES:
            url_sensible = urljoin(BASE_URL, path)
            try:
                rs = requests.get(url_sensible, timeout=5, verify=False, headers=HEADERS)
                if rs.status_code == 200:
                    with lock:
                        paths_sensibles.add(url_sensible)
            except:
                pass

    except Exception as e:
        print(f"   ⚠️ Error en {actual}: {e}")

contador = 0
if not cargar_estado():
    pendientes.append(BASE_URL)

while pendientes:
    batch = []
    with lock:
        while pendientes and len(batch) < THREADS:
            batch.append(pendientes.popleft())
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(procesar_url, batch)

    if contador % GUARDAR_CADA == 0:
        guardar_estado()

guardar_estado()

with open(ARCHIVO_SALIDA, "w", encoding="utf-8") as f:
    f.write(f"Resumen de escaneo de {DOMINIO}\n")
    f.write("=" * 60 + "\n\n")
    f.write("🌐 Páginas HTML encontradas:\n")
    f.write("-" * 40 + "\n")
    for u in sorted(urls_paginas):
        f.write(f"{u}\n")

    f.write("\n📦 Archivos detectados:\n")
    f.write("-" * 40 + "\n")
    for u, peso in sorted(archivos.items(), key=lambda x: x[1], reverse=True):
        peso_fmt = f"{peso/1024/1024:.2f} MB" if peso >= 1024*1024 else f"{peso/1024:.1f} KB"
        f.write(f"{u}  ->  {peso_fmt}\n")

    if archivos:
        mayor = max(archivos.items(), key=lambda x: x[1])
        peso_fmt = f"{mayor[1]/1024/1024:.2f} MB" if mayor[1] >= 1024*1024 else f"{mayor[1]/1024:.1f} KB"
        f.write(f"\n📁 Archivo más pesado:\n{'-' * 40}\n{mayor[0]}  ->  {peso_fmt}\n")

    f.write("\n📝 Formularios detectados:\n")
    f.write("-" * 40 + "\n")
    for pagina, forms in formularios_detectados.items():
        f.write(f"{pagina}\n")
        for form in forms:
            f.write(f"  - Acción: {form['action']} | Método: {form['method']} | Inputs: {', '.join(form['inputs'])}\n")

    f.write("\n🔐 Headers de seguridad faltantes:\n")
    f.write("-" * 40 + "\n")
    for pagina, faltan in cabeceras_inseguras.items():
        f.write(f"{pagina}  ->  {', '.join(faltan)}\n")

    f.write("\n🍪 Cookies inseguras detectadas:\n")
    f.write("-" * 40 + "\n")
    for pagina, cookies in cookies_inseguras.items():
        f.write(f"{pagina}\n")
        for cookie in cookies:
            for nombre, detalles in cookie.items():
                f.write(f"  - {nombre}: {detalles}\n")

    f.write("\n🛡️ Rutas sensibles detectadas:\n")
    f.write("-" * 40 + "\n")
    for p in sorted(paths_sensibles):
        f.write(f"{p}\n")

print(f"\n🚀 Escaneo terminado.")
print(f"🌐 Páginas encontradas: {len(urls_paginas)}")
print(f"📦 Archivos detectados: {len(archivos)}")
if archivos:
    mayor = max(archivos.items(), key=lambda x: x[1])
    peso_fmt = f"{mayor[1]/1024/1024:.2f} MB" if mayor[1] >= 1024*1024 else f"{mayor[1]/1024:.1f} KB"
    print(f"📁 Archivo más pesado: {mayor[0]} ({peso_fmt})")
print(f"📝 Formularios encontrados: {len(formularios_detectados)}")
print(f"🔐 Headers inseguros: {len(cabeceras_inseguras)}")
print(f"🍪 Cookies inseguras: {len(cookies_inseguras)}")
print(f"🛡️ Rutas sensibles: {len(paths_sensibles)}")
print(f"📍 Guardado en: {ARCHIVO_SALIDA}")
