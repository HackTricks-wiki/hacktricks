# Forense de caché de Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Esta página resume cómo hacer triage de artefactos de caché de Discord Desktop para recuperar archivos exfiltrados, endpoints de webhook y cronologías de actividad. Discord Desktop es una aplicación Electron/Chromium y utiliza Chromium Simple Cache en el disco.

## Dónde buscar (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Estructuras clave en disco dentro de Cache_Data:<sup>[[1]](#references)</sup>
- index: base de datos de índice de Simple Cache
- data_#: archivos de bloques de caché binarios que pueden contener varios objetos en caché
- f_######: entradas individuales en caché almacenadas como archivos independientes (a menudo cuerpos de mayor tamaño)

Nota: Eliminar mensajes/canales/servidores en Discord no purga esta caché local. Los elementos en caché suelen permanecer y sus marcas de tiempo de archivo coinciden con la actividad del usuario, lo que permite reconstruir una cronología.<sup>[[1]](#references)</sup>

## Qué se puede recuperar

- Attachments exfiltrados y thumbnails obtenidos mediante cdn.discordapp.com/media.discordapp.net
- Imágenes, GIF, vídeos (por ejemplo, .jpg, .png, .gif, .webp, .mp4, .webm)
- URLs de webhook (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Llamadas a la API de Discord (https://discord.com/api/vX/…)
- Útil para correlacionar actividad de beaconing/exfil y calcular hashes de medios para compararlos con información de inteligencia<sup>[[1]](#references)</sup>

## Triage rápido (manual)

- Buscar en la caché artefactos de alto valor:
- Endpoints de webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URLs de attachments/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Llamadas a la API de Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordenar las entradas en caché por hora de modificación para crear rápidamente una cronología (mtime refleja cuándo el objeto llegó a la caché):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Análisis de entradas f_* (cuerpo y headers HTTP)

Los archivos que comienzan por f_ contienen headers de respuesta HTTP seguidos del cuerpo. El bloque de headers normalmente termina con \r\n\r\n. Entre los headers de respuesta útiles se incluyen:
- Content-Type: Para inferir el tipo de medio
- Content-Location o X-Original-URL: URL remota original para la previsualización/correlación
- Content-Encoding: Puede ser gzip/deflate/br (Brotli)

Los medios pueden extraerse separando los headers del cuerpo y, opcionalmente, descomprimiéndolos según Content-Encoding. El análisis de magic bytes es útil cuando Content-Type está ausente.

## DFIR automatizado: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Función: Analiza recursivamente la carpeta de caché de Discord, encuentra URLs de webhook/API/attachments, analiza cuerpos f_* y, opcionalmente, extrae medios, generando informes de cronología en HTML + CSV con hashes SHA-256.<sup>[[2]](#references)</sup>

Ejemplo de uso de la CLI:
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
- --timeline: Emitir una línea temporal CSV ordenada (por hora de modificación)
- --extra: Analizar también Code Cache y GPUCache adyacentes
- --carve: Extraer media de los bytes sin procesar cercanos a coincidencias de regex (imágenes/vídeo)
- Output: informe HTML, informe CSV, línea temporal CSV y una carpeta media con archivos extraídos/carved

## Consejos para el analista

- Correlaciona la hora de modificación (mtime) de los archivos f_* y data_* con las ventanas de actividad del usuario/atacante para reconstruir una línea temporal.
- Calcula el hash de la media recuperada (SHA-256) y compáralo con datasets conocidos como maliciosos o de exfiltración.
- Las URLs de webhook extraídas pueden comprobarse para verificar si siguen activas o si han sido rotadas; considera añadirlas a blocklists y realizar retro-hunting en proxies.
- La Cache persiste después de “borrarla” en el servidor. Si es posible realizar la adquisición, recopila todo el directorio Cache y las caches adyacentes relacionadas (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Referencias

- [1] [Discord como C2 y la evidencia almacenada en la cache](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
