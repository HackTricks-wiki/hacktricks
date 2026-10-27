# Kỹ thuật gỡ rối tệp VBS

{{#include ../../../banners/hacktricks-training.md}}

Một số cách có thể hữu ích để gỡ lỗi/gỡ rối một tệp VBS độc hại:

## echo

`WScript.Echo` có thể được dùng để xuất thông tin chẩn đoán; khi chạy bằng `cscript.exe`, nội dung sẽ được ghi ra console.<sup>[[1]](#references)</sup>

```bash
Wscript.Echo "Like this?"
```

## Chú thích

Một dấu nháy đơn bắt đầu chú thích trong VBScript.<sup>[[2]](#references)</sup>

```bash
' this is a comment
```

## Kiểm tra

Chạy tệp VBS trong command-line host bằng:<sup>[[3]](#references)</sup>

```bash
cscript.exe file.vbs
```

## Ghi dữ liệu vào tệp

Hàm trợ giúp này được điều chỉnh từ một câu trả lời trên Stack Overflow và sử dụng luồng văn bản `FileSystemObject`. `CreateTextFile` trả về một `TextStream`, còn `Write`/`Close` thao tác trên dữ liệu văn bản; hãy xem đây là ví dụ ghi văn bản, không phải trình ghi nhị phân an toàn tổng quát.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

- [1] [Chạy truy vấn Visual Basic Scripting Edition (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/indexsrv/running-a-visual-basic-scripting-edition-query)
- [2] [Làm việc với ngôn ngữ scripting (Microsoft Learn)](https://learn.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms525153%28v%3Dvs.90%29)
- [3] [cscript (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cscript)
- [4] [Đọc và ghi tệp nhị phân trong VBScript (Stack Overflow)](https://stackoverflow.com/questions/6060529/read-and-write-binary-file-in-vbscript/6087783)
- [5] [Phương thức CreateTextFile (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/createtextfile-method)
- [6] [Đối tượng TextStream (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/textstream-object)
{{#include ../../../banners/hacktricks-training.md}}
