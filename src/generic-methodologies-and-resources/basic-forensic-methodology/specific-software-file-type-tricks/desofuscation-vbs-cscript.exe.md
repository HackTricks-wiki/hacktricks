{{#include ../../../banners/hacktricks-training.md}}

悪意のあるVBSファイルをデバッグ/デオブフスケートするのに役立ついくつかのこと：

## echo
```bash
Wscript.Echo "Like this?"
```
## コメント
```bash
' this is a comment
```
## テスト
```bash
cscript.exe file.vbs
```
## ファイルにデータを書き込む
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
{{#include ../../../banners/hacktricks-training.md}}
