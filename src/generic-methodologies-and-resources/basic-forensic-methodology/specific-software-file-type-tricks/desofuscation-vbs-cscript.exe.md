# Tecniche di desoffuscamento per file VBS

Alcune cose che potrebbero essere utili per eseguire il debug/desoffuscare un file VBS dannoso:

## echo

`WScript.Echo` può essere utilizzato per l'output diagnostico; con `cscript.exe`, viene scritto nella console.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Commenti

Un singolo apostrofo avvia un commento VBScript.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Test

Esegui il file VBS nell'host della riga di comando con:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Scrivere dati in un file

Questo helper è adattato da una risposta su Stack Overflow e utilizza un flusso di testo `FileSystemObject`. `CreateTextFile` restituisce un `TextStream`, mentre `Write`/`Close` operano sui dati testuali; consideralo un esempio di scrittura di testo, non un writer generico sicuro per i dati binari.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Esecuzione di una query Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Utilizzo dei linguaggi di scripting (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Lettura e scrittura di file binari in VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Metodo CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Oggetto TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
