# Análisis forense de la cache de Discord (cache en disco de Chromium)

{{#include ../../../banners/hacktricks-training.md}}

Esta página resume cómo hacer triage de artefactos de la cache de Discord Desktop para buscar archivos multimedia almacenados localmente, endpoints de webhook y correlacionar actividad. El cliente de escritorio de Discord usa Electron, y Electron almacena datos de sesión, como la cache en disco, en `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Dónde buscar (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Estas son las rutas predeterminadas que usa el parser citado; Electron permite que una aplicación sobrescriba `sessionData`, así que confirma la ruta real del perfil durante la adquisición.<sup>[[2]](#references)[[4]](#references)</sup>

La estructura `index` + `data_#` + `f_######` coincide con el backend de cache en disco blockfile de Chromium; no la clasifiques como Simple Cache sin verificar el backend, ya que Chromium documenta distintas implementaciones de cache.<sup>[[5]](#references)</sup>

Estructuras clave en disco dentro de `Cache_Data`:
- `index`: índice de cache Blockfile que se usa para localizar entradas.
- `data_#`: archivos de bloques de tamaño fijo que pueden contener metadatos de cache, encabezados HTTP y datos de respuesta.
- `f_######`: archivos separados que se usan para datos que superan el límite de los archivos de bloques; estos archivos contienen los datos almacenados sin los encabezados de los archivos de bloques.

Eliminar mensajes, canales o servidores no garantiza que se eliminen los bytes ya almacenados localmente en la cache, pero Chromium puede desalojar o recrear archivos de cache en cualquier momento. Trata los artefactos que sobrevivan como evidencia oportunista, y usa las horas de modificación de los archivos solo como señales aproximadas de escrituras locales que deben correlacionarse con otra telemetría.<sup>[[5]](#references)[[6]](#references)</sup>

## Qué se puede recuperar

Según lo que se haya descargado y aún no se haya desalojado, el triage puede recuperar archivos adjuntos, contenido multimedia, URL y hashes de archivos almacenados en la cache; la cache por sí sola no demuestra que un elemento haya sido exfiltrado.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Archivos adjuntos y miniaturas referenciados por URL de Discord CDN.
- Imágenes, GIF y videos (por ejemplo, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` y `.webm`).
- URL de webhook, como `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Llamadas a la API de Discord, como `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- Hashes SHA-256 de contenido multimedia recuperado para compararlos con conjuntos de datos conocidos o feeds de inteligencia.<sup>[[1]](#references)[[2]](#references)</sup>

## Triage rápido (manual)

- Usa grep en la cache para buscar artefactos de alta señal. Estos patrones reflejan las expresiones de URL del parser citado y son filtros de triage, no indicadores exhaustivos.<sup>[[2]](#references)</sup>
  - Endpoints de webhook:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - URL de archivos adjuntos/CDN:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Llamadas a la API de Discord:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Ordena las entradas de la cache por hora de modificación para construir una secuencia aproximada; mtime es una señal del sistema de archivos y por sí sola no establece cuándo se obtuvo o envió un objeto de Discord.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Análisis de entradas f_* (cuerpo + encabezados HTTP)

En la estructura blockfile, los archivos `f_######` son flujos de datos separados y no se garantiza que comiencen con una respuesta HTTP completa. Si un archivo adquirido contiene encabezados HTTP serializados seguidos de `\r\n\r\n`, separa el contenido en el primer delimitador e inspecciona:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Para inferir el tipo de contenido multimedia
- Content-Location o X-Original-URL: URL remota original para previsualización/correlación
- Content-Encoding: Puede ser gzip/deflate/br (Brotli).

Luego se puede extraer el contenido multimedia separando los encabezados del cuerpo y, opcionalmente, descomprimiéndolo según `Content-Encoding`; el parser citado admite Brotli, gzip y deflate. La inspección de bytes mágicos es útil cuando no hay `Content-Type`, pero sigue siendo una heurística.<sup>[[2]](#references)</sup>

## DFIR automatizado: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Función: Analiza recursivamente la carpeta de cache de Discord, encuentra URL de webhook/API/archivos adjuntos, analiza cuerpos `f_*`, opcionalmente extrae contenido multimedia y genera informes HTML y CSV, además de una cronología opcional con hashes SHA-256.<sup>[[1]](#references)[[2]](#references)</sup>

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
- --cache: Ruta al directorio Cache_Data de Discord
- --format html|csv|both
- --timeline: Genera una cronología CSV ordenada (por hora de modificación)
- --extra: También analiza Code Cache y GPUCache, que están en directorios adyacentes
- --carve: Extrae archivos multimedia de bytes de caché sin procesar mediante firmas de medios reconocidas (imágenes/vídeo)
- Output: `<output>.html`, `<output>.csv`, el archivo opcional `<output>_timeline.csv` y una carpeta `<output>_media` con archivos extraídos o recuperados.

## Consejos para el analista

- Correlaciona la hora de modificación (mtime) de los archivos `f_*` y `data_*` con periodos de actividad de usuarios o atacantes y con telemetría independiente; mtime no es una marca de tiempo definitiva del evento.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Calcula el hash de los archivos multimedia recuperados (SHA-256) y compáralos con conjuntos de datos de elementos maliciosos conocidos o de exfiltración.<sup>[[1]](#references)[[2]](#references)</sup>
- Trata las URL de webhook extraídas como credenciales. No las invoques solo para comprobar si están activas; consérvalas de forma segura, coordina su revocación o rotación y utiliza la telemetría de red relacionada para realizar búsquedas retrospectivas.<sup>[[7]](#references)</sup>
- La eliminación en el servidor no garantiza que se hayan destruido los bytes almacenados localmente en caché. Si es posible adquirirlos, recopila todo el directorio `Cache` y las cachés adyacentes relacionadas (`Code Cache`, `GPUCache`) antes de que se eliminen o se vuelva a crear la caché.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Suite forense de Discord (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [CLI de Discord Forensic Suite](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Cómo Discord actualizó sin problemas a millones de usuarios a una arquitectura de 64 bits](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Caché en disco](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord como C2 y las pruebas almacenadas en caché que deja atrás](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Webhooks de Discord: ejecutar un webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
