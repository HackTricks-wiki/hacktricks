{{#include ../../../banners/hacktricks-training.md}}

Algunas cosas que podrían ser útiles para depurar/desofuscar un archivo VBS malicioso:

## echo
```bash
Wscript.Echo "Like this?"
```
## Comentarios
```bash
' this is a comment
```
## Prueba
```bash
cscript.exe file.vbs
```
## Escribir datos en un archivo
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
{{#include ../../../banners/hacktricks-training.md}}
