# Mbinu za Kuondoa Obfuscation kwenye Faili za VBS

{{#include ../../../banners/hacktricks-training.md}}

Baadhi ya mambo yanayoweza kusaidia kutatua hitilafu/kufanya deobfuscation ya faili hasidi ya VBS:

## echo
```bash
Wscript.Echo "Like this?"
```
## Maoni
```bash
' this is a comment
```
## Jaribio
```bash
cscript.exe file.vbs
```
## Andika data kwenye faili
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
