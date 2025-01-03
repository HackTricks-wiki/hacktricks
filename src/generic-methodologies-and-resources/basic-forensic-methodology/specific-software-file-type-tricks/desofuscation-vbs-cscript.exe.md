{{#include ../../../banners/hacktricks-training.md}}

Sommige dinge wat nuttig kan wees om 'n kwaadwillige VBS-lêer te debug/deobfuskeer:

## echo
```bash
Wscript.Echo "Like this?"
```
## Kommentaar
```bash
' this is a comment
```
## Toets
```bash
cscript.exe file.vbs
```
## Skryf data na 'n lêer
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
