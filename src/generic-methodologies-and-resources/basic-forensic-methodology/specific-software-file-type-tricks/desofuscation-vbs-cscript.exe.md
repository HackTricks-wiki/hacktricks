# Técnicas de desofuscación para archivos VBS

{{#include ../../../banners/hacktricks-training.md}}

Algunas cosas que pueden ser útiles para depurar/desofuscar un archivo VBS malicioso:

## echo

`WScript.Echo` se puede usar para mostrar resultados de diagnóstico; con `cscript.exe`, se escriben en la consola.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Comentarios

Un solo apóstrofo inicia un comentario de VBScript.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Prueba

Ejecuta el archivo VBS en el host de línea de comandos con:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Escribir datos en un archivo

Este helper está adaptado de una respuesta de Stack Overflow y utiliza un flujo de texto `FileSystemObject`. `CreateTextFile` devuelve un `TextStream`, y `Write`/`Close` operan sobre datos de texto; considérelo un ejemplo de escritura de texto, no un escritor general seguro para datos binarios.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
```js
Function writeBinary(strBinary, strPath)

Dim oFSO: Set oFSO = CreateObject("Scripting.FileSystemObject")

' below lines purpose: checks that write access is possible!
Dim oTxtStream

On Error Resume Next
Set oTxtStream = oFSO.createTextFile(strPath)

If Err.number <> 0 Then MsgBox(Err.message) : Exit Function
On Error GoTo 0

Set oTxtStream = Nothing
' end check of write access

With oFSO.createTextFile(strPath)
.Write(strBinary)
.Close
End With

End Function
```
## References

- [1] [Ejecución de una consulta de Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Trabajo con lenguajes de scripting (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Leer y escribir archivos binarios en VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Método CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Objeto TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
