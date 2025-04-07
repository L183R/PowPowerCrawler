PowPowerCrawler - Herramienta de Recolección Web
===============================================

Uso:
-----
python PowPowerCrawler.py -u <URL> [opciones]

Ejemplos:
---------
1. Escaneo básico:
   python PowPowerCrawler.py -u https://ejemplo.com

2. Continuar escaneo anterior:
   python PowPowerCrawler.py -u https://ejemplo.com --continuar

3. Empezar desde cero y borrar el estado anterior:
   python PowPowerCrawler.py -u https://ejemplo.com --omitir

4. Descargar solo archivos CSS, JS y HTML:
   python PowPowerCrawler.py -u https://ejemplo.com --estaticos --omitir

5. Descargar solo multimedia (imágenes, videos, audio, documentos):
   python PowPowerCrawler.py -u https://ejemplo.com --multimedia --omitir

6. Descargar solo imágenes:
   python PowPowerCrawler.py -u https://ejemplo.com --img --omitir

7. Descargar solo videos:
   python PowPowerCrawler.py -u https://ejemplo.com --vid --omitir

8. Descargar solo audios:
   python PowPowerCrawler.py -u https://ejemplo.com --aud --omitir

9. Descargar solo documentos:
   python PowPowerCrawler.py -u https://ejemplo.com --doc --omitir

10. Descargar solo CSS:
    python PowPowerCrawler.py -u https://ejemplo.com --css --omitir

11. Descargar solo JS:
    python PowPowerCrawler.py -u https://ejemplo.com --js --omitir

12. Descargar solo HTML:
    python PowPowerCrawler.py -u https://ejemplo.com --html --omitir


Parámetros:
-----------
-u / --url <URL>
    Obligatorio. Dirección web que se desea escanear. Debe comenzar con http:// o https://

--estaticos
    Descarga únicamente archivos estáticos: .css, .js, .html, .htm

--multimedia
    Descarga únicamente archivos multimedia: imágenes, videos, audios y documentos

--img
    Descarga únicamente imágenes: .jpg, .jpeg, .png, .gif, .svg

--vid
    Descarga únicamente videos: .mp4, .webm, .mov

--aud
    Descarga únicamente audios: .mp3, .wav, .ogg

--doc
    Descarga únicamente documentos: .pdf, .docx, .xls, .pptx, .zip, etc.

--css
    Descarga únicamente archivos .css

--js
    Descarga únicamente archivos .js

--html
    Descarga únicamente archivos .html y .htm

--continuar
    Carga el estado guardado del escaneo anterior y continúa desde donde se dejó

--omitir
    Ignora y elimina cualquier estado anterior. Empieza desde cero


Notas:
------
- Si no se especifica ningún filtro, se detectan páginas HTML, formularios, endpoints, cabeceras inseguras, cookies inseguras y rutas sensibles.
- Guarda el resultado en un archivo <dominio>.txt y el estado en <dominio>_estado.json

"""
