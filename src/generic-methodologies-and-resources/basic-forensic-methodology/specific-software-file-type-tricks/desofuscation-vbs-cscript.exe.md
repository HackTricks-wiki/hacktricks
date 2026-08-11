# VBS 파일을 난독화 해제하는 기법

{{#include ../../../banners/hacktricks-training.md}}

악성 VBS 파일을 디버깅하거나 난독화를 해제할 때 유용한 몇 가지 방법:

## echo

`WScript.Echo`는 진단 출력을 위해 사용할 수 있으며, `cscript.exe`에서 실행하면 콘솔에 기록됩니다.<sup>[[1]](#references)</sup>
```bash
Wscript.Echo "Like this?"
```
## 주석

작은따옴표 하나로 VBScript 주석을 시작합니다.<sup>[[2]](#references)</sup>
```bash
' this is a comment
```
## 테스트

다음과 같이 명령줄 호스트에서 VBS 파일을 실행합니다:<sup>[[3]](#references)</sup>
```bash
cscript.exe file.vbs
```
## 파일에 데이터 쓰기

이 helper는 Stack Overflow 답변을 기반으로 수정되었으며 `FileSystemObject` 텍스트 스트림을 사용합니다. `CreateTextFile`은 `TextStream`을 반환하고 `Write`/`Close`는 텍스트 데이터에 대해 작동하므로, 이를 범용 바이너리 안전 writer가 아닌 텍스트 작성 예제로 취급해야 합니다.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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

- [1] [Visual Basic Scripting Edition 쿼리 실행 (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [스크립팅 언어 사용 (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [VBScript에서 바이너리 파일 읽기 및 쓰기 (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [CreateTextFile 메서드 (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [TextStream 개체 (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
