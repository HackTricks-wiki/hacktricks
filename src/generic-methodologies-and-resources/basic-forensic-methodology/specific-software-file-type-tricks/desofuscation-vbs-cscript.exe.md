# Techniki desobfuskacji plików VBS

Kilka rzeczy, które mogą być przydatne podczas debugowania/desobfuskacji złośliwego pliku VBS:

## echo

`WScript.Echo` może być używane do wyświetlania danych diagnostycznych; w środowisku `cscript.exe` są one zapisywane w konsoli.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Komentarze

Pojedynczy apostrof rozpoczyna komentarz VBScript.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Testowanie

Uruchom plik VBS w hoście wiersza poleceń za pomocą:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Zapisz dane do pliku

Ten helper jest zaadaptowany z odpowiedzi na Stack Overflow i używa strumienia tekstowego `FileSystemObject`. `CreateTextFile` zwraca `TextStream`, a `Write`/`Close` operują na danych tekstowych; należy traktować to jako przykład zapisu tekstowego, a nie ogólnie bezpiecznego zapisu danych binarnych.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Uruchamianie zapytania Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Praca z językami skryptowymi (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Odczytywanie i zapisywanie pliku binarnego w VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Metoda CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Obiekt TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
