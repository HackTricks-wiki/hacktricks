# Tehnike deobfuskacije VBS datoteka

Neke stvari koje mogu biti korisne za otklanjanje grešaka/deobfuskaciju zlonamernog VBS fajla:

## echo

`WScript.Echo` može da se koristi za dijagnostički izlaz; pod `cscript.exe` se ispisuje na konzolu.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Komentari

Jedan apostrof započinje VBScript komentar.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Testiranje

Pokrenite VBS datoteku u command-line hostu pomoću:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Upis podataka u datoteku

Ovaj pomoćni kod je prilagođen iz odgovora na Stack Overflow-u i koristi tekstualni tok `FileSystemObject` objekta. `CreateTextFile` vraća `TextStream`, a `Write`/`Close` rade sa tekstualnim podacima; posmatrajte ga kao primer za upisivanje teksta, a ne kao opšti writer bezbedan za binarne podatke.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Pokretanje upita u Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Rad sa skriptnim jezicima (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Čitanje i upisivanje binarne datoteke u VBScript-u (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Metod CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Objekat TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
