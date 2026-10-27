# Persistence trong miền AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Đây là bản tóm tắt các kỹ thuật persistence trong miền được chia sẻ trong [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Hãy xem tài liệu để biết thêm chi tiết.<sup>[[5]](#references)</sup>

## Giả mạo chứng chỉ bằng chứng chỉ CA bị đánh cắp (Golden Certificate) - DPERSIST1

Làm thế nào để biết một chứng chỉ có phải là chứng chỉ CA hay không?

Có thể xác định một chứng chỉ là chứng chỉ CA nếu đáp ứng một số điều kiện sau:<sup>[[5]](#references)</sup>

- Chứng chỉ được lưu trên máy chủ CA, khóa riêng được bảo vệ bằng DPAPI của máy hoặc bằng phần cứng như TPM/HSM nếu hệ điều hành hỗ trợ.
- Cả trường Issuer và Subject của chứng chỉ đều khớp với tên phân biệt của CA.
- Phần mở rộng "CA Version" chỉ xuất hiện trong các chứng chỉ CA.
- Chứng chỉ không có trường Extended Key Usage (EKU).

Để trích xuất khóa riêng của chứng chỉ này, phương pháp được hỗ trợ là dùng công cụ `certsrv.msc` trên máy chủ CA thông qua giao diện GUI tích hợp. Tuy nhiên, chứng chỉ này không khác các chứng chỉ khác được lưu trong hệ thống; do đó, có thể áp dụng các phương pháp như kỹ thuật [THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) để trích xuất.

Cũng có thể lấy chứng chỉ và khóa riêng bằng Certipy với lệnh sau:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Sau khi thu thập được chứng chỉ CA và khóa riêng tương ứng ở định dạng `.pfx`, có thể sử dụng các công cụ như [ForgeCert](https://github.com/GhostPack/ForgeCert) để tạo chứng chỉ hợp lệ:

```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```

> [!WARNING]
> Người dùng được nhắm mục tiêu để giả mạo chứng chỉ phải đang hoạt động và có khả năng xác thực trong Active Directory thì quy trình mới thành công. Giả mạo chứng chỉ cho các tài khoản đặc biệt như krbtgt sẽ không hiệu quả.

Chứng chỉ giả mạo này sẽ **có hiệu lực** đến ngày kết thúc được chỉ định và **chừng nào chứng chỉ CA gốc còn hiệu lực** (thường từ 5 đến **hơn 10 năm**). Chứng chỉ này cũng có hiệu lực đối với **máy**, vì vậy khi kết hợp với **S4U2Self**, kẻ tấn công có thể **duy trì persistence trên bất kỳ máy nào trong domain** chừng nào chứng chỉ CA còn hiệu lực.\
Ngoài ra, **các chứng chỉ được tạo** bằng phương pháp này **không thể bị thu hồi** vì CA không biết đến chúng.

### Hoạt động khi áp dụng Strong Certificate Mapping Enforcement (2025+)

Kể từ ngày 11 tháng 2 năm 2025 (sau khi triển khai KB5014754), domain controller mặc định áp dụng **Full Enforcement** cho certificate mapping. Trên thực tế, điều này có nghĩa là chứng chỉ giả mạo của bạn phải đáp ứng một trong các điều kiện sau:

- Chứa liên kết mạnh với tài khoản mục tiêu (ví dụ: SID security extension), hoặc
- Đi kèm với một mapping tường minh, mạnh trên thuộc tính `altSecurityIdentities` của đối tượng mục tiêu.<sup>[[1]](#references)</sup>

Một cách tiếp cận đáng tin cậy để duy trì persistence là tạo chứng chỉ giả mạo được liên kết với Enterprise CA bị đánh cắp, sau đó thêm mapping tường minh, mạnh vào principal nạn nhân:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Ghi chú
- Nếu bạn có thể tạo chứng chỉ giả mạo có chứa tiện ích bảo mật SID, chúng sẽ được ánh xạ ngầm ngay cả khi bật Full Enforcement. Nếu không, hãy ưu tiên ánh xạ mạnh tường minh. Xem [account-persistence](account-persistence.md) để biết thêm về ánh xạ tường minh.
- Thu hồi không giúp ích cho bên phòng thủ trong trường hợp này: chứng chỉ giả mạo không có trong cơ sở dữ liệu CA nên không thể bị thu hồi.

#### Tạo chứng chỉ giả mạo tương thích với Full Enforcement (nhận biết SID)

Các công cụ mới cho phép nhúng SID trực tiếp, giúp golden certificates vẫn sử dụng được ngay cả khi DC từ chối các ánh xạ yếu:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Bằng cách nhúng SID, bạn tránh phải động đến `altSecurityIdentities`, thuộc tính có thể bị giám sát, nhưng vẫn đáp ứng các kiểm tra ánh xạ mạnh.

## Trusting Rogue CA Certificates - DPERSIST2

Đối tượng `NTAuthCertificates` được thiết kế để chứa một hoặc nhiều **chứng chỉ CA** trong thuộc tính `cacertificate`, được Active Directory (AD) sử dụng. Quá trình xác minh của **domain controller** bao gồm việc kiểm tra đối tượng `NTAuthCertificates` để tìm mục khớp với **CA được chỉ định** trong trường Issuer của **chứng chỉ** dùng để xác thực. Quá trình xác thực tiếp tục nếu tìm thấy kết quả khớp.<sup>[[5]](#references)</sup>

Kẻ tấn công có thể thêm chứng chỉ CA tự ký vào đối tượng `NTAuthCertificates` nếu kiểm soát được đối tượng AD này. Thông thường, chỉ thành viên của nhóm **Enterprise Admin**, cùng với **Domain Admins** hoặc **Administrators** trong **miền gốc của forest**, mới được cấp quyền sửa đổi đối tượng này. Họ có thể chỉnh sửa đối tượng `NTAuthCertificates` bằng `certutil.exe` với lệnh `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, hoặc sử dụng [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Các lệnh bổ sung hữu ích cho kỹ thuật này:

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

Khả năng này đặc biệt phù hợp khi kết hợp với phương pháp đã nêu trước đó, sử dụng ForgeCert để tạo chứng chỉ động.

> Các cân nhắc về mapping sau năm 2025: việc thêm CA giả mạo vào NTAuth chỉ thiết lập độ tin cậy đối với CA cấp chứng chỉ. Để dùng chứng chỉ leaf đăng nhập khi DC ở chế độ **Full Enforcement**, chứng chỉ leaf phải chứa SID security extension hoặc phải có strong explicit mapping trên đối tượng đích (ví dụ: Issuer+Serial trong `altSecurityIdentities`). Xem {{#ref}}account-persistence.md{{#endref}}.

## Cấu hình sai độc hại - DPERSIST3

Có rất nhiều cơ hội để duy trì **persistence** thông qua việc **sửa đổi security descriptor của các thành phần AD CS**. Kẻ tấn công có quyền truy cập nâng cao có thể triển khai độc hại các sửa đổi được mô tả trong phần "[Domain Escalation](domain-escalation.md)". Trong đó có việc thêm "quyền kiểm soát" (ví dụ: WriteOwner/WriteDACL/...) vào các thành phần nhạy cảm như:<sup>[[5]](#references)</sup>

- Đối tượng **máy tính AD của máy chủ CA**
- **Máy chủ RPC/DCOM của máy chủ CA**
- Bất kỳ **đối tượng AD hậu duệ hoặc container** nào trong **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (ví dụ: container Certificate Templates, container Certification Authorities, đối tượng NTAuthCertificates, v.v.)
- **Các nhóm AD được tổ chức ủy quyền rõ ràng quyền kiểm soát CA hoặc template**. Nhóm Cert Publishers tích hợp sẵn được phép phát hành chứng chỉ cho các đối tượng người dùng trong AD; chỉ là thành viên nhóm không cấp quyền kiểm soát CA hoặc template hay quyền enrollment. Hãy kiểm tra riêng các quyền liên quan của CA và template. Xem [Microsoft's description of Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) và [certificate template permissions](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Ví dụ về cách triển khai độc hại: kẻ tấn công có **quyền nâng cao** trong domain thêm quyền **`WriteOwner`** vào certificate template **`User`** mặc định, với principal của quyền này là chính kẻ tấn công. Để khai thác, trước tiên kẻ tấn công đổi chủ sở hữu template **`User`** thành chính mình. Sau đó, đặt **`mspki-certificate-name-flag`** thành **1** trên template để bật **`ENROLLEE_SUPPLIES_SUBJECT`**, cho phép người dùng cung cấp Subject Alternative Name trong yêu cầu. Tiếp theo, kẻ tấn công có thể **enroll** bằng **template**, chọn tên của **domain administrator** làm tên thay thế, rồi dùng chứng chỉ nhận được để xác thực với tư cách DA.

Các thiết lập thực tế mà kẻ tấn công có thể cấu hình để duy trì persistence lâu dài trong domain (xem {{#ref}}domain-escalation.md{{#endref}} để biết đầy đủ chi tiết và cách phát hiện):

- Các policy flag của CA cho phép requester chỉ định SAN (ví dụ: bật `EDITF_ATTRIBUTESUBJECTALTNAME2`). Điều này giúp các đường khai thác kiểu ESC1 tiếp tục khả dụng.
- DACL hoặc thiết lập của template cho phép cấp chứng chỉ có khả năng xác thực (ví dụ: thêm EKU Client Authentication, bật `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kiểm soát đối tượng `NTAuthCertificates` hoặc các container CA để liên tục thêm lại issuer giả mạo nếu bên phòng thủ tìm cách dọn dẹp.

> [!TIP]
> Trong các môi trường được harden sau KB5014754, kết hợp các cấu hình sai này với strong mapping tường minh (`altSecurityIdentities`) sẽ đảm bảo các chứng chỉ đã cấp hoặc giả mạo vẫn dùng được ngay cả khi DC thực thi strong mapping.

### Lạm dụng gia hạn chứng chỉ (ESC14) để duy trì persistence

Nếu bạn xâm phạm được một chứng chỉ có khả năng xác thực (hoặc chứng chỉ Enrollment Agent), bạn có thể **gia hạn nó vô thời hạn** miễn là template cấp chứng chỉ vẫn được publish và CA vẫn tin cậy chuỗi issuer. Việc gia hạn giữ nguyên các liên kết danh tính ban đầu nhưng kéo dài thời hạn hiệu lực, khiến việc loại bỏ trở nên khó khăn trừ khi template được sửa hoặc CA được publish lại.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Nếu domain controller đang ở chế độ **Full Enforcement**, hãy thêm `-sid <victim SID>` (hoặc dùng template vẫn bao gồm SID security extension) để certificate lá được gia hạn tiếp tục ánh xạ mạnh mà không cần chỉnh sửa `altSecurityIdentities`. Attacker có quyền CA admin cũng có thể điều chỉnh `policy\RenewalValidityPeriodUnits` để kéo dài thời hạn của certificate được gia hạn trước khi cấp certificate cho chính mình.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Các thay đổi về xác thực dựa trên certificate trên domain controller Windows (lộ trình enforcement và strong mapping)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Tham chiếu lệnh và cách dùng forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (forge tích hợp hỗ trợ SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Tổng quan về lạm dụng gia hạn ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Lạm dụng Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
