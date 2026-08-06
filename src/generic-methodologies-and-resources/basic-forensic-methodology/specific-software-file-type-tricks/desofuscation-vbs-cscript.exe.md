# Τεχνικές Αποσυσκότισης για Αρχεία VBS

{{#include ../../../banners/hacktricks-training.md}}

Μερικά πράγματα που θα μπορούσαν να φανούν χρήσιμα για το debugging/deobfuscation ενός κακόβουλου αρχείου VBS:

## echo
```bash
Wscript.Echo "Like this?"
```
## Σχόλια
```bash
' this is a comment
```
## Δοκιμή
```bash
cscript.exe file.vbs
```
## Εγγραφή δεδομένων σε αρχείο
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
