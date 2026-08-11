# VBS 文件的反混淆技术

{{#include ../../../banners/hacktricks-training.md}}

以下是一些可用于调试/反混淆恶意 VBS 文件的方法：

## echo

`WScript.Echo` 可用于输出诊断信息；在 `cscript.exe` 下，输出内容会写入控制台。<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## 注释

单个撇号用于开始 VBScript 注释。<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## 测试

使用以下命令在命令行主机中运行 VBS 文件：<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## 将数据写入文件

此 helper 改编自 Stack Overflow 的一个回答，并使用 `FileSystemObject` 文本流。`CreateTextFile` 返回一个 `TextStream`，而 `Write`/`Close` 操作的是文本数据；应将其视为文本写入示例，而不是通用的二进制安全写入器。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [运行 Visual Basic Scripting Edition 查询 (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [使用脚本语言 (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [在 VBScript 中读取和写入二进制文件 (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [CreateTextFile 方法 (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [TextStream 对象 (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
