{{#include ../../../banners/hacktricks-training.md}}

Деякі речі, які можуть бути корисними для налагодження/дебофускації шкідливого VBS файлу:

## echo
```bash
Wscript.Echo "Like this?"
```
## Коментарі
```bash
' this is a comment
```
## Тест
```bash
cscript.exe file.vbs
```
## Записати дані у файл
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
