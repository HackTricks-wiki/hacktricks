# Desobfuscation-Techniken für VBS-Dateien

{{#include ../../../banners/hacktricks-training.md}}

Einige Dinge, die beim Debuggen/Deobfuscation einer schädlichen VBS-Datei hilfreich sein könnten:

## echo

`WScript.Echo` kann für diagnostische Ausgaben verwendet werden; unter `cscript.exe` wird die Ausgabe in die Konsole geschrieben.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Kommentare

Ein einzelnes Apostroph leitet einen VBScript-Kommentar ein.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Test

Führe die VBS-Datei im Befehlszeilenhost aus mit:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Daten in eine Datei schreiben

Diese Hilfsfunktion ist an eine Stack-Overflow-Antwort angelehnt und verwendet einen `FileSystemObject`-Textstream. `CreateTextFile` gibt einen `TextStream` zurück, und `Write`/`Close` arbeiten mit Textdaten. Betrachte dies daher als Beispiel zum Schreiben von Text und nicht als allgemein binärsicheren Writer.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Ausführen einer Visual Basic Scripting Edition-Abfrage (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Arbeiten mit Skriptsprachen (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Binärdatei in VBScript lesen und schreiben (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [CreateTextFile-Methode (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [TextStream-Objekt (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
