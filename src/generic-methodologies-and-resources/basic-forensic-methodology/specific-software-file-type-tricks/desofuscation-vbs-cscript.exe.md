# VBS Files के लिए Desobfuscation Techniques

कुछ चीज़ें malicious VBS file को debug/deobfuscate करने में उपयोगी हो सकती हैं:

## echo

`WScript.Echo` का उपयोग diagnostic output के लिए किया जा सकता है; `cscript.exe` के अंतर्गत, इसे console पर लिखा जाता है।<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## टिप्पणियाँ

एकल apostrophe से VBScript comment शुरू होता है।<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## परीक्षण

VBS फ़ाइल को command-line host में चलाएँ:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## फ़ाइल में डेटा लिखें

यह helper Stack Overflow के एक उत्तर से अनुकूलित है और `FileSystemObject` text stream का उपयोग करता है। `CreateTextFile` एक `TextStream` लौटाता है, और `Write`/`Close` text data पर कार्य करते हैं; इसे सामान्य binary-safe writer के बजाय text-writing example मानें।<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Visual Basic Scripting Edition Query चलाना (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Scripting Languages के साथ कार्य करना (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [VBScript में binary file पढ़ना और लिखना (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [CreateTextFile method (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [TextStream object (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
