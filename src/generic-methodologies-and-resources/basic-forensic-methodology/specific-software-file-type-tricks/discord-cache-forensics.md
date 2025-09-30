# Forense de caché de Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Esta página resume cómo hacer triage de los artefactos de caché de Discord Desktop para recuperar archivos exfiltrados, endpoints de webhook y líneas de tiempo de actividad. Discord Desktop es una app Electron/Chromium y usa Chromium Simple Cache en disco.

## Dónde buscar (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Estructuras clave en disco dentro de Cache_Data:
- index: base de datos de índice de Simple Cache
- data_#: archivos binarios de bloques de caché que pueden contener múltiples objetos cacheados
- f_######: entradas cacheadas individuales almacenadas como archivos independientes (a menudo cuerpos más grandes)

Nota: Eliminar mensajes/canales/servidores en Discord no purga esta caché local. Los elementos cacheados a menudo permanecen y las marcas de tiempo de los archivos se alinean con la actividad del usuario, lo que permite reconstruir la línea de tiempo.

## Qué se puede recuperar

- Adjuntos exfiltrados y miniaturas obtenidas vía cdn.discordapp.com/media.discordapp.net
- Imágenes, GIFs, videos (por ejemplo, .jpg, .png, .gif, .webp, .mp4, .webm)
- URLs de webhook (https://discord.com/api/webhooks/…)
- Llamadas a la API de Discord (https://discord.com/api/vX/…)
- Útil para correlacionar actividad de beaconing/exfil y para hashear medios para matching de inteligencia

## Triage rápido (manual)

- Grep a la caché en busca de artefactos de alta señal:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordenar las entradas cacheadas por tiempo de modificación para crear una línea de tiempo rápida (mtime refleja cuando el objeto llegó a la caché):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (cuerpo HTTP + cabeceras)

Los archivos que comienzan con f_ contienen cabeceras de respuesta HTTP seguidas del cuerpo. El bloque de cabeceras normalmente termina con \r\n\r\n. Cabeceras de respuesta útiles incluyen:
- Content-Type: Para inferir el tipo de medio
- Content-Location or X-Original-URL: URL remota original para preview/correlación
- Content-Encoding: Puede ser gzip/deflate/br (Brotli)

Se pueden extraer medios separando las cabeceras del cuerpo y opcionalmente descomprimiendo según Content-Encoding. El sniffing por magic-bytes es útil cuando falta Content-Type.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Escanea recursivamente la carpeta de caché de Discord, encuentra webhook/API/attachment URLs, parses f_* bodies, optionally carves media, y genera informes HTML + CSV de timeline con hashes SHA‑256.

Ejemplo de uso CLI:
```bash
# Acquire cache (copy directory for offline parsing), then run:
python3 discord_forensic_suite_cli \
--cache "%AppData%\discord\Cache\Cache_Data" \
--outdir C:\IR\discord-cache \
--output discord_cache_report \
--format both \
--timeline \
--extra \
--carve \
--verbose
```
Opciones clave:
- --cache: Ruta a Cache_Data
- --format html|csv|both
- --timeline: Emitir un timeline CSV ordenado (por tiempo de modificación - mtime)
- --extra: También escanea las caches hermanas Code Cache y GPUCache
- --carve: Extrae medios desde bytes crudos cerca de coincidencias regex (imágenes/video)
- Output: reporte HTML, reporte CSV, timeline CSV, y una carpeta media con archivos extraídos/carved

## Consejos para analistas

- Correlaciona el tiempo de modificación (mtime) de los archivos f_* y data_* con las ventanas de actividad del usuario/atacante para reconstruir una cronología.
- Calcula el hash de los medios recuperados (SHA-256) y compáralos con datasets known-bad o de exfil.
- Las URLs de webhooks extraídas pueden probarse para verificar su liveness o rotarse; considera añadirlas a blocklists y retro-hunting proxies.
- La cache persiste después del “wiping” en el lado del servidor. Si es posible adquirirla, recopila todo el directorio Cache y las caches hermanas relacionadas (Code Cache, GPUCache).

## Referencias

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
