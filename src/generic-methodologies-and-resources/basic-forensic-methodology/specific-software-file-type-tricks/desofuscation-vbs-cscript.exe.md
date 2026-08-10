# VBSファイルのデオブファスケーション技法

悪意のあるVBSファイルをデバッグまたはデオブファスケーションする際に役立つ可能性がある方法：

## echo

`WScript.Echo`は診断出力に使用できます。`cscript.exe`では、コンソールに書き込まれます。<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## Comments

単一のアポストロフィは、VBScriptのコメントを開始します。<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## テスト

次のコマンドを使用して、command-line hostでVBSファイルを実行します:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## ファイルにデータを書き込む

このヘルパーは Stack Overflow の回答を元にしており、`FileSystemObject` のテキストストリームを使用します。`CreateTextFile` は `TextStream` を返し、`Write`/`Close` はテキストデータを操作します。そのため、一般的なバイナリ安全のライターではなく、テキスト書き込みの例として扱ってください。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Visual Basic Scripting Edition クエリの実行 (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [スクリプト言語の操作 (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [VBScript でバイナリファイルを読み書きする (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [CreateTextFile メソッド (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [TextStream オブジェクト (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
