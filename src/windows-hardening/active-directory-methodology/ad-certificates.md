# Chứng chỉ AD

{{#include ../../banners/hacktricks-training.md}}

## Giới thiệu

### Các thành phần của chứng chỉ

- **Subject** của chứng chỉ cho biết chủ sở hữu.
- **Public Key** được ghép cặp với một khóa riêng tư để liên kết chứng chỉ với chủ sở hữu hợp pháp.
- **Validity Period**, được xác định bởi các ngày **NotBefore** và **NotAfter**, đánh dấu khoảng thời gian chứng chỉ có hiệu lực.
- **Serial Number** duy nhất do Certificate Authority (CA) cấp, dùng để nhận diện từng chứng chỉ.
- **Issuer** là CA đã cấp chứng chỉ.
- **SubjectAlternativeName** cho phép thêm các tên khác cho chủ thể, tăng tính linh hoạt trong việc nhận diện.
- **Basic Constraints** xác định chứng chỉ dành cho CA hay thực thể cuối, đồng thời quy định các giới hạn sử dụng.
- **Extended Key Usages (EKUs)** xác định mục đích cụ thể của chứng chỉ, chẳng hạn như ký mã hoặc mã hóa email, thông qua Object Identifiers (OIDs).
- **Signature Algorithm** chỉ định phương thức ký chứng chỉ.
- **Signature**, được tạo bằng khóa riêng tư của bên cấp, đảm bảo tính xác thực của chứng chỉ.<sup>[[4]](#references)</sup>

### Các lưu ý đặc biệt

- **Subject Alternative Names (SANs)** mở rộng phạm vi áp dụng của chứng chỉ cho nhiều danh tính, điều này rất quan trọng đối với các máy chủ có nhiều domain. Quy trình cấp chứng chỉ an toàn là thiết yếu để tránh nguy cơ bị attacker giả mạo danh tính bằng cách thao túng cấu hình SAN.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) trong Active Directory (AD)

AD CS ghi nhận chứng chỉ CA trong một forest AD thông qua các container được chỉ định, mỗi container đảm nhiệm một vai trò riêng:<sup>[[4]](#references)</sup>

- Container **Certification Authorities** lưu giữ chứng chỉ CA gốc đáng tin cậy.
- Container **Enrolment Services** cung cấp thông tin về Enterprise CA và các certificate template của chúng.
- Đối tượng **NTAuthCertificates** bao gồm các chứng chỉ CA được phép xác thực AD.
- Container **AIA (Authority Information Access)** hỗ trợ xác thực chuỗi chứng chỉ bằng các chứng chỉ CA trung gian và chéo.

### Nhận chứng chỉ: Luồng yêu cầu chứng chỉ từ client

1. Quá trình yêu cầu bắt đầu khi client tìm một Enterprise CA.
2. Sau khi tạo cặp khóa công khai-riêng tư, CSR được tạo với public key và các thông tin khác.
3. CA đánh giá CSR dựa trên các certificate template hiện có và cấp chứng chỉ theo quyền của template.
4. Sau khi được chấp thuận, CA ký chứng chỉ bằng khóa riêng tư của mình rồi gửi lại cho client.<sup>[[4]](#references)</sup>

### Certificate Template

Các template được định nghĩa trong AD, mô tả cấu hình và quyền cấp chứng chỉ, bao gồm EKU được phép cũng như quyền đăng ký hoặc chỉnh sửa. Đây là yếu tố thiết yếu để quản lý quyền truy cập vào các dịch vụ chứng chỉ.<sup>[[4]](#references)</sup>

**Phiên bản schema của template rất quan trọng.** Các template **v1** cũ (ví dụ, template tích hợp sẵn **WebServer**) thiếu một số cơ chế thực thi hiện đại. Nghiên cứu về **ESC15/EKUwu** cho thấy trên các template **v1**, requester có thể nhúng **Application Policies/EKUs** vào CSR; các giá trị này được **ưu tiên hơn** EKU được cấu hình trong template, cho phép tạo chứng chỉ client-auth, enrollment agent hoặc ký mã chỉ với quyền enrollment. Nên ưu tiên template **v2/v3**, loại bỏ hoặc thay thế các mặc định v1, và giới hạn chặt EKU theo mục đích sử dụng dự kiến.<sup>[[1]](#references)</sup>

## Đăng ký chứng chỉ

Quy trình đăng ký chứng chỉ do administrator khởi tạo bằng cách **tạo một certificate template**, sau đó được Enterprise Certificate Authority (CA) **publish**. Việc này giúp client có thể đăng ký template; để thực hiện, cần thêm tên template vào trường `certificatetemplates` của một đối tượng Active Directory.<sup>[[4]](#references)</sup>

Để client yêu cầu chứng chỉ, cần cấp **quyền enrollment**. Các quyền này được xác định bởi security descriptor trên certificate template và trên chính Enterprise CA. Cần cấp quyền ở cả hai vị trí để yêu cầu thành công.

### Quyền đăng ký template

Các quyền này được chỉ định thông qua Access Control Entry (ACE), nêu rõ những quyền như:

- Quyền **Certificate-Enrollment** và **Certificate-AutoEnrollment**, mỗi quyền gắn với một GUID cụ thể.
- **ExtendedRights**, cho phép tất cả quyền mở rộng.
- **FullControl/GenericAll**, cung cấp toàn quyền kiểm soát template.

### Quyền đăng ký trên Enterprise CA

Quyền của CA được xác định trong security descriptor của nó, có thể xem trong bảng điều khiển quản lý Certificate Authority. Một số cài đặt thậm chí cho phép người dùng có đặc quyền thấp truy cập từ xa, điều này có thể gây lo ngại về bảo mật.

### Các kiểm soát cấp chứng chỉ bổ sung

Một số kiểm soát có thể được áp dụng, chẳng hạn như:

- **Manager Approval**: Đưa yêu cầu vào trạng thái chờ cho đến khi certificate manager phê duyệt.
- **Enrolment Agents and Authorized Signatures**: Chỉ định số chữ ký cần thiết trên CSR và các Application Policy OID bắt buộc.

### Các phương thức yêu cầu chứng chỉ

Có thể yêu cầu chứng chỉ thông qua:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), sử dụng giao diện DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), thông qua named pipe hoặc TCP/IP.
3. **Giao diện web đăng ký chứng chỉ**, khi đã cài đặt role Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), kết hợp với dịch vụ Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dành cho thiết bị mạng, sử dụng Simple Certificate Enrollment Protocol (SCEP).

Người dùng Windows cũng có thể yêu cầu chứng chỉ qua GUI (`certmgr.msc` hoặc `certlm.msc`) hoặc công cụ dòng lệnh (`certreq.exe` hoặc lệnh PowerShell `Get-Certificate`).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Xác thực bằng chứng chỉ

Active Directory (AD) hỗ trợ xác thực bằng chứng chỉ, chủ yếu sử dụng các giao thức **Kerberos** và **Secure Channel (Schannel)**.

### Quy trình xác thực Kerberos

Trong quy trình xác thực Kerberos, yêu cầu của người dùng để lấy Ticket Granting Ticket (TGT) được ký bằng **private key** của chứng chỉ người dùng. Domain controller thực hiện một số bước xác thực đối với yêu cầu này, bao gồm kiểm tra **tính hợp lệ**, **đường dẫn** và **trạng thái thu hồi** của chứng chỉ. Các bước xác thực cũng bao gồm xác minh rằng chứng chỉ đến từ một nguồn đáng tin cậy và xác nhận rằng tổ chức phát hành có trong **NTAUTH certificate store**. Nếu các bước xác thực thành công, TGT sẽ được cấp. Đối tượng **`NTAuthCertificates`** trong AD, nằm tại:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

là yếu tố then chốt để thiết lập độ tin cậy cho xác thực bằng chứng chỉ.<sup>[[4]](#references)</sup>

Kể từ đợt triển khai **KB5014754**, xác thực chứng chỉ Kerberos hiện đại chủ yếu phụ thuộc vào **độ mạnh của ánh xạ**, chứ không chỉ EKU.<sup>[[2]](#references)</sup> Trong các forest được hardening:

- Chứng chỉ chỉ có **UPN/DNS SAN** có thể không còn đủ để đăng nhập.
- KDC ưu tiên **liên kết mạnh**, thường là **SID security extension** (`1.3.6.1.4.1.311.25.2`) hoặc ánh xạ tường minh mạnh trong `altSecurityIdentities`.
- Nếu chứng chỉ không có ánh xạ mạnh, DC ghi log **Kdcsvc Event ID 39/41** ở chế độ tương thích và từ chối xác thực ở chế độ enforcement.
- Trong các đường tấn công kết hợp, **ESC9/ESC16** rất đáng chú ý vì chúng loại bỏ SID extension khỏi chứng chỉ được cấp; khi đó, operator dựa vào ánh xạ tường minh hoặc định dạng SAN URL SID nếu đường tấn công hỗ trợ.

### Xác thực Secure Channel (Schannel)

Schannel hỗ trợ các kết nối TLS/SSL an toàn. Trong quá trình handshake, client gửi một chứng chỉ; nếu chứng chỉ được xác thực thành công, nó sẽ cấp quyền truy cập. Việc ánh xạ chứng chỉ sang tài khoản AD có thể sử dụng hàm **S4U2Self** của Kerberos hoặc **Subject Alternative Name (SAN)** của chứng chỉ, cùng các phương thức khác.<sup>[[4]](#references)</sup>

Schannel cũng là phương án dự phòng thực tế khi **PKINIT** không khả dụng. Ví dụ: nếu domain controller không có chứng chỉ **Smart Card Logon** phù hợp, các công cụ `certipy auth`/PKINIT có thể không lấy được TGT, nhưng vẫn có thể dùng cùng chứng chỉ đó để xác thực và thực hiện các thao tác LDAP qua **LDAPS** hoặc **LDAP StartTLS**.

### Liệt kê AD Certificate Services

Có thể liệt kê các dịch vụ chứng chỉ của AD thông qua truy vấn LDAP, qua đó phát hiện thông tin về **Enterprise Certificate Authorities (CA)** và cấu hình của chúng. Mọi người dùng đã xác thực trong domain đều có thể truy cập thông tin này mà không cần đặc quyền đặc biệt. Các công cụ như **[Certify](https://github.com/GhostPack/Certify)** và **[Certipy](https://github.com/ly4k/Certipy)** được dùng để liệt kê và đánh giá lỗ hổng trong môi trường AD CS.

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

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Các lỗ hổng bảo mật & bản cập nhật bảo mật gần đây (2022-2025)

| Năm | ID / Tên | Tác động | Điểm chính |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Leo thang đặc quyền* bằng cách giả mạo chứng chỉ tài khoản máy tính trong quá trình PKINIT. | Bản vá được đưa vào các bản cập nhật bảo mật ngày **10 tháng 5 năm 2022**. Các biện pháp kiểm tra và kiểm soát ánh xạ mạnh được giới thiệu qua **KB5014754**; hiện các môi trường nên ở chế độ *Full Enforcement*.  |
| 2023 | **CVE-2023-35350 / 35351** | *Thực thi mã từ xa* trong các vai trò AD CS Web Enrollment (certsrv) và CES. | Các PoC công khai còn hạn chế, nhưng các thành phần IIS dễ bị tấn công thường được phơi lộ trong mạng nội bộ. Cài bản vá trong đợt Patch Tuesday **tháng 7 năm 2023**.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Trên các template **v1**, người yêu cầu có quyền đăng ký có thể nhúng **Application Policies/EKUs** vào CSR; các giá trị này được ưu tiên hơn EKU của template, tạo ra chứng chỉ client-auth, enrollment agent hoặc code-signing. | Đã có bản vá kể từ **ngày 12 tháng 11 năm 2024**. Thay thế hoặc nâng cấp các template v1 (ví dụ: WebServer mặc định), giới hạn EKU theo mục đích sử dụng và hạn chế quyền đăng ký. |

### Lộ trình hardening của Microsoft (KB5014754)

Microsoft triển khai theo ba giai đoạn (Compatibility → Audit → Enforcement) để chuyển xác thực chứng chỉ Kerberos khỏi các ánh xạ ngầm yếu. Kể từ **ngày 11 tháng 2 năm 2025**, domain controller tự động chuyển sang **Full Enforcement** nếu không thiết lập giá trị registry `StrongCertificateBindingEnforcement`. Sau đó, Microsoft cập nhật lộ trình để vẫn cho phép quay lại chế độ compatibility cho đến bản cập nhật bảo mật **ngày 9 tháng 9 năm 2025**.<sup>[[2]](#references)</sup> Quản trị viên nên:

1. Cài bản vá cho tất cả DC và máy chủ AD CS (tháng 5 năm 2022 trở lên).
2. Theo dõi Event ID 39/41 để phát hiện ánh xạ yếu trong giai đoạn *Audit*.
3. Cấp lại chứng chỉ client-auth có **SID extension** mới hoặc cấu hình ánh xạ thủ công mạnh trước khi enforcement chặn các ánh xạ yếu.

### Ghi chú cho operator về các forest đã được hardening

- **Chỉ ESC1/ESC6 không còn là toàn bộ câu chuyện** trong các môi trường từ năm 2025 trở đi. Nếu yêu cầu chứng chỉ cho principal khác, thường bạn cũng cần một artifact ánh xạ mạnh như SID extension hoặc ánh xạ tường minh.
- **ESC15 (EKUwu)** chủ yếu hữu ích trong các môi trường chưa cài bản vá, vì nó biến các template **v1** vốn vô hại như **WebServer** thành chứng chỉ có khả năng xác thực hoặc làm enrollment agent bằng cách chèn **Application Policies**. Kerberos PKINIT vẫn kiểm tra EKU, nhưng **LDAP Schannel** cũng chấp nhận Application Policies, khiến việc lạm dụng dựa trên LDAP vẫn đáng lưu ý.<sup>[[1]](#references)</sup>
- **ESC16** là một thiết lập áp dụng trên toàn CA: nếu CA tắt SID security extension trên toàn cục, mọi chứng chỉ được cấp sẽ quay về hành vi ánh xạ yếu hơn, trừ khi chuỗi tấn công chèn SID bằng một định dạng khác được hỗ trợ.
- **Quyền ESC7 có phạm vi riêng:** quyền `ManageCA` trên CA có thể cho phép thay đổi các thiết lập như `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), trong khi `ManageCertificates` kiểm soát việc phê duyệt yêu cầu. Một quy tắc Deny tường minh đối với quyền certificate-manager có thể chặn đường phê duyệt đó ngay cả khi cũng có quy tắc Allow; hãy đánh giá ACL CA hiệu lực trước khi kết hợp các thiết lập và template. Xem [đánh giá ACL CA của Microsoft](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Cải tiến phát hiện & hardening

* **Cảm biến AD CS của Defender for Identity (2023-2024)** hiện cung cấp các đánh giá tư thế bảo mật cho ESC1-ESC8/ESC11 và tạo cảnh báo theo thời gian thực, chẳng hạn như *“Cấp chứng chỉ domain controller cho đối tượng không phải DC”* (ESC8) và *“Ngăn đăng ký chứng chỉ bằng Application Policies tùy ý”* (ESC15). Hãy triển khai cảm biến trên tất cả máy chủ AD CS để tận dụng các khả năng phát hiện này.<sup>[[3]](#references)</sup>
* Tắt hoặc giới hạn chặt chẽ tùy chọn **“Supply in the request”** trên tất cả template; ưu tiên các giá trị SAN/EKU được xác định tường minh.
* Gỡ **Any Purpose** hoặc **No EKU** khỏi template, trừ khi thực sự cần thiết (xử lý các tình huống ESC2).
* Yêu cầu **manager approval** hoặc quy trình Enrollment Agent chuyên biệt đối với các template nhạy cảm (ví dụ: WebServer / CodeSigning).
* Giới hạn các endpoint web enrollment (`certsrv`) và CES/NDES chỉ cho phép mạng đáng tin cậy hoặc đặt sau xác thực bằng client certificate.
* Bắt buộc mã hóa RPC enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) để giảm thiểu ESC11 (RPC relay). Flag này **được bật mặc định**, nhưng thường bị tắt để hỗ trợ client cũ, khiến nguy cơ relay xuất hiện trở lại.
* Bảo vệ các **endpoint enrollment dựa trên IIS** (CES/Certsrv): tắt NTLM khi có thể hoặc yêu cầu HTTPS + Extended Protection để chặn ESC8 relay.

Đánh giá ESC11 trên host chạy CA; host này có thể là máy chủ thành viên domain chứ không phải domain controller. Đọc `InterfaceFlags` của CA đang hoạt động tại `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`; giá trị không đọc được hoặc không tồn tại là kết quả chưa xác định, không phải bằng chứng rằng mã hóa RPC đã bị tắt. Nếu bit `IF_ENFORCEENCRYPTICERTREQUEST` không được bật, đó là dấu hiệu cần kiểm tra cấu hình thêm; vẫn cần có endpoint enrollment RPC truy cập được, thông tin xác thực có thể bị coercion và template chứng chỉ có thể sử dụng. Với ESC8, chỉ có phản hồi HTTP NTLM challenge là chưa đủ: hãy xác nhận rằng có endpoint enrollment hoạt động.

---

## References

- [1] [EKUwu: Không chỉ là một ESC AD CS khác](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Các thay đổi về xác thực dựa trên chứng chỉ trên domain controller Windows](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Đánh giá tư thế bảo mật chứng chỉ - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Lạm dụng Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
