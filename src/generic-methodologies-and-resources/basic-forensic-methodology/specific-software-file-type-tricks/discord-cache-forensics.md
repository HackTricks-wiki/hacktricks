# Forensics de la caché de Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Esta página resume cómo realizar el triaje de los artefactos de la caché de Discord Desktop para recuperar archivos exfiltrados, endpoints de webhook y líneas temporales de actividad. Discord Desktop es una app Electron/Chromium y utiliza Chromium Simple Cache en el disco.

## Dónde buscar (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Estructuras clave en disco dentro de Cache_Data:<sup>[[1]](#references)</sup>
- index: base de datos de índices de Simple Cache
- data_#: archivos binarios de bloques de caché que pueden contener varios objetos almacenados en caché
- f_######: entradas individuales de caché almacenadas como archivos independientes (a menudo con cuerpos de mayor tamaño)

Nota: eliminar mensajes/canales/servidores en Discord no purga esta caché local. Los elementos almacenados en caché suelen permanecer y las marcas de tiempo de sus archivos coinciden con la actividad del usuario, lo que permite reconstruir una línea temporal.<sup>[[1]](#references)</sup>

## Qué se puede recuperar

- Adjuntos exfiltrados y miniaturas obtenidas mediante cdn.discordapp.com/media.discordapp.net
- Imágenes, GIF, vídeos (p. ej., .jpg, .png, .gif, .webp, .mp4, .webm)
- URLs de webhook (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Llamadas a la API de Discord (https://discord.com/api/vX/…)
- Útil para correlacionar la actividad de beaconing/exfil y calcular hashes de medios para compararlos con inteligencia<sup>[[1]](#references)</sup>

## Triaje rápido (manual)

- Buscar en la caché artefactos de alta relevancia:
- Endpoints de webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URLs de adjuntos/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Llamadas a la API de Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordenar las entradas almacenadas en caché por hora de modificación para crear rápidamente una línea temporal (mtime refleja cuándo el objeto llegó a la caché):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Análisis de entradas f_* (cuerpo y headers HTTP)

Los archivos que comienzan por f_ contienen headers de respuesta HTTP seguidos del cuerpo. El bloque de headers normalmente termina con \r\n\r\n. Entre los headers de respuesta útiles se incluyen:
- Content-Type: Para inferir el tipo de medio
- Content-Location o X-Original-URL: URL remota original para la previsualización/correlación
- Content-Encoding: Puede ser gzip/deflate/br (Brotli)

Los medios se pueden extraer separando los headers del cuerpo y, opcionalmente, descomprimiéndolos según Content-Encoding. La detección mediante magic bytes es útil cuando Content-Type está ausente.

## DFIR automatizado: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Función: Explora recursivamente la carpeta de caché de Discord, encuentra URLs de webhook/API/adjuntos, analiza los cuerpos f_* y, opcionalmente, extrae medios, además de generar informes de línea temporal en HTML + CSV con hashes SHA‑256.<sup>[[2]](#references)</sup>

Ejemplo de uso de CLI:
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
- --timeline: Genera una línea de tiempo CSV ordenada (por hora de modificación)
- --extra: También analiza Code Cache y GPUCache adyacentes
- --carve: Extrae medios de bytes sin procesar cerca de coincidencias de regex (imágenes/vídeo)
- Output: informe HTML, informe CSV, línea de tiempo CSV y una carpeta de medios con archivos extraídos

## Consejos para el analista

- Correlaciona la hora de modificación (mtime) de los archivos f_* y data_* con los periodos de actividad del usuario/atacante para reconstruir una línea de tiempo.
- Calcula el hash de los medios recuperados (SHA-256) y compáralo con datasets conocidos como maliciosos o de exfiltración.
- Las URL de webhook extraídas pueden comprobarse para verificar si siguen activas o han sido rotadas; considera añadirlas a blocklists y realizar retro-hunting en proxies.
- La caché persiste después de un “borrado” en el servidor. Si es posible realizar la adquisición, recopila todo el directorio Cache y las cachés adyacentes relacionadas (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Referencias

- [1] [Discord como C2 y la evidencia en caché que deja atrás](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Ejecutar webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
