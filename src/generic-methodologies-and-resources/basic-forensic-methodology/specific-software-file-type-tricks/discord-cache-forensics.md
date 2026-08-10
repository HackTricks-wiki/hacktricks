# Forensics de la caché de Discord (caché de disco de Chromium)

Esta página resume cómo realizar un triage de los artefactos de la caché de Discord Desktop para localizar medios almacenados localmente en la caché, endpoints de webhook y correlacionar actividad. El cliente de escritorio de Discord usa Electron, y Electron almacena datos de sesión, como la caché de disco, bajo `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Dónde buscar (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Estas son las rutas predeterminadas utilizadas por el parser referenciado; Electron permite que una aplicación sobrescriba `sessionData`, por lo que se debe confirmar la ruta real del perfil durante la adquisición.<sup>[[2]](#references)[[4]](#references)</sup>

La estructura `index` + `data_#` + `f_######` coincide con el backend de caché de disco blockfile de Chromium; no se debe etiquetar como Simple Cache sin verificar el backend, ya que Chromium documenta implementaciones de caché distintas.<sup>[[5]](#references)</sup>

Estructuras clave en disco dentro de `Cache_Data`:
- `index`: índice de caché Blockfile utilizado para localizar entradas.
- `data_#`: archivos de bloques de tamaño fijo que pueden contener metadatos de caché, cabeceras HTTP y datos de respuesta.
- `f_######`: archivos independientes utilizados para datos mayores que el límite de los archivos de bloques; estos archivos contienen los datos almacenados sin las cabeceras de los archivos de bloques.

Eliminar mensajes, canales o servidores no garantiza la eliminación de los bytes que ya están almacenados localmente en la caché, pero Chromium puede expulsar o recrear los archivos de caché en cualquier momento. Se deben tratar los artefactos supervivientes como evidencia oportunista, y utilizar las horas de modificación de los archivos únicamente como señales aproximadas de escritura local que deben correlacionarse con otra telemetría.<sup>[[5]](#references)[[6]](#references)</sup>

## Qué se puede recuperar

Dependiendo de lo que se haya descargado y aún no se haya expulsado de la caché, el triage puede recuperar archivos adjuntos, medios, URLs y hashes de archivos almacenados en la caché; la caché por sí sola no demuestra que un elemento haya sido exfiltrado.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Archivos adjuntos y miniaturas referenciados por URLs del CDN de Discord.
- Imágenes, GIFs y vídeos (por ejemplo, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` y `.webm`).
- URLs de webhook como `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Llamadas a la API de Discord como `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hashes SHA-256 de los medios recuperados para compararlos con datasets conocidos o feeds de inteligencia.<sup>[[1]](#references)[[2]](#references)</sup>

## Triage rápido (manual)

- Buscar en la caché artefactos de alta relevancia. Estos patrones reflejan las expresiones de URL del parser referenciado y son filtros de triage, no indicadores exhaustivos.<sup>[[2]](#references)</sup>
- Endpoints de webhook:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URLs de archivos adjuntos/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Llamadas a la API de Discord:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordenar las entradas almacenadas en la caché por hora de modificación para crear una secuencia aproximada; mtime es una señal del sistema de archivos y por sí solo no establece cuándo se obtuvo o envió un objeto de Discord.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Análisis de entradas f_* (cuerpo + cabeceras HTTP)

En la estructura blockfile, los archivos `f_######` son flujos de datos independientes y no se garantiza que comiencen con una respuesta HTTP completa. Si un archivo adquirido contiene cabeceras HTTP serializadas seguidas de `\r\n\r\n`, dividir en el primer delimitador e inspeccionar:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Para inferir el tipo de medio
- Content-Location o X-Original-URL: URL remota original para previsualización/correlación
- Content-Encoding: Puede ser gzip/deflate/br (Brotli).

A continuación, los medios se pueden extraer separando las cabeceras del cuerpo y, opcionalmente, descomprimiéndolos según `Content-Encoding`; el parser referenciado gestiona Brotli, gzip y deflate. La identificación mediante magic bytes es útil cuando `Content-Type` está ausente, pero sigue siendo heurística.<sup>[[2]](#references)</sup>

## DFIR automatizado: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Función: Explora recursivamente la carpeta de caché de Discord, encuentra URLs de webhook/API/archivos adjuntos, analiza cuerpos `f_*`, opcionalmente extrae medios y genera informes HTML y CSV, además de una línea temporal cronológica opcional con hashes SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

Ejemplo de uso de CLI:
```powershell
# Acquire a copy of the cache for offline parsing, then run on Windows:
python discord_forensic_suite_cli `
--cache "$env:APPDATA\discord\Cache\Cache_Data" `
--outdir "C:\IR\discord-cache" `
--output discord_cache_report `
--format both `
--timeline `
--extra `
--carve `
--verbose
```
La CLI define estas opciones y nombres de salida:<sup>[[2]](#references)</sup>
- --cache: Ruta al directorio Discord Cache_Data
- --format html|csv|both
- --timeline: Genera una línea temporal CSV ordenada (por tiempo de modificación)
- --extra: También analiza los directorios hermanos Code Cache y GPUCache
- --carve: Extrae archivos multimedia de los bytes sin procesar de la cache mediante firmas multimedia reconocidas (imágenes/vídeo)
- Salida: `<output>.html`, `<output>.csv`, `<output>_timeline.csv` opcional y una carpeta `<output>_media` con archivos extraídos o recuperados.

## Consejos para analistas

- Correlaciona el tiempo de modificación (mtime) de los archivos `f_*` y `data_*` con los periodos de actividad del usuario o del atacante y con telemetría independiente; mtime no es una marca temporal de evento definitiva.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Calcula el hash de los archivos multimedia recuperados (SHA-256) y compáralo con datasets conocidos como maliciosos o de exfiltración.<sup>[[1]](#references)[[2]](#references)</sup>
- Trata las URLs de webhook extraídas como credenciales. No las invoques simplemente para comprobar si están activas; consérvalas de forma segura, coordina su revocación o rotación y utiliza la telemetría de red relacionada para realizar retro-hunting.<sup>[[7]](#references)</sup>
- La eliminación en el servidor no garantiza que los bytes almacenados localmente en la cache hayan sido destruidos. Si es posible realizar la adquisición, recopila todo el directorio `Cache` y las caches hermanas relacionadas (`Code Cache`, `GPUCache`) antes de su desalojo o recreación.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Suite forense de Discord (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [CLI de la suite forense de Discord](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Cómo Discord actualizó sin interrupciones a millones de usuarios a una arquitectura de 64 bits](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Cache de disco](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord como C2 y las evidencias almacenadas en cache que deja atrás](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Webhooks de Discord – Ejecutar webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
