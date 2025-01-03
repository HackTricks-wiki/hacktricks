{{#include ../../../banners/hacktricks-training.md}}

一些可以用于调试/去混淆恶意 VBS 文件的有用工具：

## echo
```bash
Wscript.Echo "Like this?"
```
## 评论
```bash
' this is a comment
```
## 测试
```bash
cscript.exe file.vbs
```
## 将数据写入文件
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
