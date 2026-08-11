# Desobfuskeringstegnieke vir VBS-lêers

{{#include ../../../banners/hacktricks-training.md}}

Enkele dinge wat nuttig kan wees om ’n kwaadwillige VBS-lêer te ontfout/desobfuseer:

## echo

`WScript.Echo` kan vir diagnostiese uitvoer gebruik word; onder `cscript.exe` word dit na die konsole geskryf.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Kommentaar

'n Enkele apostrof begin 'n VBScript-kommentaar.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Toets

Run die VBS-lêer in die command-line host met:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Skryf data na 'n lêer

Hierdie helper is aangepas vanaf 'n Stack Overflow-antwoord en gebruik 'n `FileSystemObject`-teksstroom. `CreateTextFile` gee 'n `TextStream` terug, en `Write`/`Close` werk op teksdata; behandel dit as 'n voorbeeld van teks skryf eerder as 'n algemene binary-safe writer.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [’n Visual Basic Scripting Edition-navraag uitvoer (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Werk met Scripting Languages (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Lees en skryf ’n binêre lêer in VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [CreateTextFile-metode (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [TextStream-objek (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
