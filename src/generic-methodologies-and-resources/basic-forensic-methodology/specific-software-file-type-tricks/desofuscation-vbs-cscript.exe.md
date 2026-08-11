# VBS Dosyaları için Obfuscation Kaldırma Teknikleri

{{#include ../../../banners/hacktricks-training.md}}

Kötü amaçlı bir VBS dosyasını debug etmek veya obfuscation'ını kaldırmak için yararlı olabilecek bazı şeyler:

## echo

`WScript.Echo`, tanılama çıktısı için kullanılabilir; `cscript.exe` altında çıktı konsola yazılır.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Yorumlar

Tek bir kesme işareti VBScript yorumunu başlatır.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Test

VBS dosyasını command-line host içinde şu komutla çalıştırın:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Bir dosyaya veri yazma

Bu yardımcı, bir Stack Overflow yanıtından uyarlanmıştır ve `FileSystemObject` metin akışını kullanır. `CreateTextFile` bir `TextStream` döndürür; `Write`/`Close` metin verileri üzerinde çalışır. Bu nedenle bunu genel amaçlı, ikili verilerle güvenli bir yazıcıdan ziyade metin yazma örneği olarak değerlendirin.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Visual Basic Scripting Edition Sorgusu Çalıştırma (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Scripting Dilleriyle Çalışma (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [VBScript'te binary dosya okuma ve yazma (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [CreateTextFile metodu (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [TextStream nesnesi (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
