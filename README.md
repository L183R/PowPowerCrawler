# PowPowerCrawler - Herramienta de recolección web

PowPowerCrawler es una herramienta CLI de reconocimiento web. Recorre URLs internas de un dominio, detecta páginas HTML, formularios, endpoints AJAX/API, archivos enlazados, cabeceras de seguridad faltantes, cookies inseguras, rutas sensibles, correos y teléfonos.

> Úsala únicamente sobre sitios propios o con autorización explícita.

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
python PowPowerCrawler.py -u <URL> [opciones]
```

## Ejemplos

### Escaneo básico

```bash
python PowPowerCrawler.py -u https://ejemplo.com
```

### Continuar un escaneo anterior

```bash
python PowPowerCrawler.py -u https://ejemplo.com --continuar
```

### Empezar desde cero y borrar el estado anterior

```bash
python PowPowerCrawler.py -u https://ejemplo.com --omitir
```

### Detectar solo archivos CSS, JS y HTML

```bash
python PowPowerCrawler.py -u https://ejemplo.com --estaticos --omitir
```

### Detectar solo multimedia

```bash
python PowPowerCrawler.py -u https://ejemplo.com --multimedia --omitir
```

### Descargar archivos detectados

Por defecto, PowPowerCrawler registra los archivos detectados. Para descargarlos, agrega `--descargar`:

```bash
python PowPowerCrawler.py -u https://ejemplo.com --multimedia --descargar --omitir
```

### Limitar concurrencia, páginas y velocidad

```bash
python PowPowerCrawler.py -u https://ejemplo.com --threads 4 --max-pages 200 --delay 0.5
```

### Ejecutar en modo silencioso

```bash
python PowPowerCrawler.py -u https://ejemplo.com --quiet
```

### Ignorar errores TLS de forma explícita

```bash
python PowPowerCrawler.py -u https://ejemplo.com --insecure
```

## Parámetros

| Parámetro | Descripción |
| --- | --- |
| `-u`, `--url <URL>` | Obligatorio. Dirección web que se desea escanear. Si no incluye esquema, se agrega `http://`. |
| `--estaticos` | Procesa únicamente `.css`, `.js`, `.html` y `.htm`. |
| `--multimedia` | Procesa imágenes, videos, audios y documentos. |
| `--img` | Procesa únicamente imágenes: `.jpg`, `.jpeg`, `.png`, `.gif`, `.svg`. |
| `--vid` | Procesa únicamente videos: `.mp4`, `.webm`, `.mov`. |
| `--aud` | Procesa únicamente audios: `.mp3`, `.wav`, `.ogg`. |
| `--doc` | Procesa únicamente documentos y comprimidos comunes. |
| `--css` | Procesa únicamente archivos `.css`. |
| `--js` | Procesa únicamente archivos `.js`. |
| `--html` | Procesa únicamente archivos `.html` y `.htm`. |
| `--descargar` | Descarga los archivos detectados en carpetas por tipo (`img`, `vid`, `aud`, `doc`, `css`, `js`, `html`). |
| `--continuar` | Carga el estado guardado y continúa desde donde se dejó. |
| `--omitir` | Elimina cualquier estado anterior y empieza desde cero. |
| `--delay <segundos>` | Espera entre requests. Útil para reducir la presión sobre el servidor. |
| `--quiet` | Oculta la salida informativa en consola. |
| `--threads <N>` | Define la cantidad de hilos concurrentes. Valor por defecto: `10`. |
| `--timeout <segundos>` | Define el timeout por request. Valor por defecto: `5`. |
| `--max-pages <N>` | Limita la cantidad máxima de páginas a visitar. `0` significa sin límite. |
| `--guardar-cada <N>` | Guarda estado cada N páginas procesadas. Valor por defecto: `100`. |
| `--insecure` | Desactiva la validación TLS y oculta warnings de certificados. |

## Salidas

- Reporte: `<dominio>.txt`
- Estado: `<dominio>_estado.json`
- Descargas opcionales: carpetas `img/`, `vid/`, `aud/`, `doc/`, `css/`, `js/`, `html/` o `descargas/`

## Notas

- Si no se especifica ningún filtro, se procesan páginas HTML y archivos con extensiones conocidas.
- La revisión de rutas sensibles se ejecuta una vez por dominio y se guarda en el estado.
- `--insecure` debe usarse solo cuando realmente necesites ignorar problemas de certificados TLS.
