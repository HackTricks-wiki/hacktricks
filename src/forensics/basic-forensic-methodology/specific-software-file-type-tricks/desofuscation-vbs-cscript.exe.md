{{#include ../../../banners/hacktricks-training.md}}

कुछ चीजें जो एक दुर्भावनापूर्ण VBS फ़ाइल को डिबग/डिओबफस्केट करने के लिए उपयोगी हो सकती हैं:

## echo
```bash
Wscript.Echo "Like this?"
```
## टिप्पणियाँ
```bash
' this is a comment
```
## परीक्षण
```bash
cscript.exe file.vbs
```
## एक फ़ाइल में डेटा लिखें
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
