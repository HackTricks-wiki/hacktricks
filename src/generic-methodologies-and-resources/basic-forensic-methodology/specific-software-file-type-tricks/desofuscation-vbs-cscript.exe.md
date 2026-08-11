# Mbinu za Kuondoa Obfuscation kwenye Faili za VBS

{{#include ../../../banners/hacktricks-training.md}}

Baadhi ya mambo yanayoweza kusaidia kutatua hitilafu/kufanya deobfuscation ya faili hasidi ya VBS:

## echo

`WScript.Echo` inaweza kutumika kutoa taarifa za uchunguzi; chini ya `cscript.exe`, huandikwa kwenye console.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Maoni

Apostrophe moja huanzisha comment ya VBScript.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Jaribio

Endesha faili la VBS katika command-line host kwa:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Andika data kwenye faili

Msaidizi huyu umechukuliwa kutoka kwenye jibu la Stack Overflow na hutumia text stream ya `FileSystemObject`. `CreateTextFile` hurejesha `TextStream`, na `Write`/`Close` hufanya kazi kwenye data ya maandishi; ichukulie kama mfano wa kuandika maandishi badala ya writer ya jumla iliyo salama kwa binary.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Kuendesha Query ya Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Kufanya kazi na Lugha za Scripting (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Kusoma na kuandika faili ya binary katika VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Mbinu ya CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Kipengee cha TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
