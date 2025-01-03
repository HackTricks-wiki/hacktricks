{{#include ../../../banners/hacktricks-training.md}}

Certaines choses qui pourraient être utiles pour déboguer/déobfusquer un fichier VBS malveillant :

## echo
```bash
Wscript.Echo "Like this?"
```
## Commentaires
```bash
' this is a comment
```
## Test
```bash
cscript.exe file.vbs
```
## Écrire des données dans un fichier
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
