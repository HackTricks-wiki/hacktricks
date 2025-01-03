{{#include ../../../banners/hacktricks-training.md}}

악성 VBS 파일을 디버깅/디오브스케이팅하는 데 유용할 수 있는 몇 가지 사항:

## echo
```bash
Wscript.Echo "Like this?"
```
## 댓글
```bash
' this is a comment
```
## 테스트
```bash
cscript.exe file.vbs
```
## 파일에 데이터 쓰기
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
