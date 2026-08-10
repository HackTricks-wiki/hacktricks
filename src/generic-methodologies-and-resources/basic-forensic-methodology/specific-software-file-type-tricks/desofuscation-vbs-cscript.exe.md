# Técnicas de Desofuscação para Arquivos VBS

Algumas coisas que podem ser úteis para depurar/desofuscar um arquivo VBS malicioso:

## echo

`WScript.Echo` pode ser usado para saída de diagnóstico; no `cscript.exe`, ela é escrita no console.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Comentários

Um único apóstrofo inicia um comentário VBScript.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## Teste

Execute o arquivo VBS no host de linha de comando com:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## Gravar dados em um arquivo

Este helper foi adaptado de uma resposta do Stack Overflow e usa um fluxo de texto `FileSystemObject`. `CreateTextFile` retorna um `TextStream`, e `Write`/`Close` operam em dados de texto; considere-o um exemplo de gravação de texto, e não um gravador geral seguro para dados binários.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Executando uma consulta da Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Trabalhando com linguagens de script (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Ler e gravar um arquivo binário no VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Método CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Objeto TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
