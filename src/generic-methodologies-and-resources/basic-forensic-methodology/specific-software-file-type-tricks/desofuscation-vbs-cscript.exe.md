# Tehnike za deobfuskaciju VBS datoteka

{{#include ../../../banners/hacktricks-training.md}}

Neke stvari koje mogu biti korisne za otklanjanje grešaka/deobfuskaciju zlonamerne VBS datoteke:

## echo
```bash
Wscript.Echo "Like this?"
```
## Komentari
```bash
' this is a comment
```
## Test
```bash
cscript.exe file.vbs
```
## Upisivanje podataka u datoteku
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
