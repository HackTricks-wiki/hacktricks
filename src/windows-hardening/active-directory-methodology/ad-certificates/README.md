# Chứng chỉ AD

{{#include ../../../banners/hacktricks-training.md}}

## Giới thiệu

### Các thành phần của chứng chỉ

- **Subject** của chứng chỉ cho biết chủ sở hữu.
- **Public Key** được ghép cặp với một khóa riêng tư để liên kết chứng chỉ với chủ sở hữu hợp pháp.
- **Validity Period**, được xác định bằng ngày **NotBefore** và **NotAfter**, đánh dấu khoảng thời gian chứng chỉ có hiệu lực.
- **Serial Number** duy nhất, do Certificate Authority (CA) cấp, dùng để nhận diện từng chứng chỉ.
- **Issuer** là CA đã cấp chứng chỉ.
- **SubjectAlternativeName** cho phép chỉ định thêm các tên cho subject, giúp linh hoạt hơn trong việc nhận diện.
- **Basic Constraints** xác định chứng chỉ dành cho CA hay thực thể cuối và đặt ra các giới hạn sử dụng.
- **Extended Key Usages (EKUs)** xác định mục đích cụ thể của chứng chỉ, chẳng hạn như ký mã hoặc mã hóa email, thông qua Object Identifiers (OIDs).
- **Signature Algorithm** chỉ định phương thức ký chứng chỉ.
- **Signature**, được tạo bằng khóa riêng tư của issuer, đảm bảo tính xác thực của chứng chỉ.<sup>[[1]](#references)</sup>

### Các điểm cần lưu ý đặc biệt

- **Subject Alternative Names (SANs)** mở rộng phạm vi áp dụng của chứng chỉ cho nhiều danh tính, đặc biệt quan trọng đối với máy chủ có nhiều domain. Quy trình cấp chứng chỉ an toàn là yếu tố thiết yếu để tránh nguy cơ bị giả mạo bởi kẻ tấn công thao túng thông tin SAN.<sup>[[1]](#references)</sup>

### Certificate Authority (CA) trong Active Directory (AD)

AD CS ghi nhận các chứng chỉ CA trong forest AD thông qua các container được chỉ định, mỗi container đảm nhiệm một vai trò riêng:<sup>[[1]](#references)</sup>

- Container **Certification Authorities** lưu trữ chứng chỉ CA gốc đáng tin cậy.
- Container **Enrolment Services** chứa thông tin về Enterprise CA và các certificate template của chúng.
- Đối tượng **NTAuthCertificates** chứa các chứng chỉ CA được phép dùng cho xác thực AD.
- Container **AIA (Authority Information Access)** hỗ trợ xác thực certificate chain bằng các chứng chỉ CA trung gian và CA chéo.

### Yêu cầu cấp chứng chỉ: Quy trình yêu cầu chứng chỉ từ client

1. Quy trình yêu cầu bắt đầu khi client tìm Enterprise CA.
2. Sau khi tạo cặp khóa công khai-riêng tư, CSR được tạo, chứa public key và các thông tin khác.
3. CA đối chiếu CSR với các certificate template hiện có và cấp chứng chỉ dựa trên quyền của template.
4. Khi được phê duyệt, CA ký chứng chỉ bằng khóa riêng tư của mình rồi gửi lại cho client.<sup>[[1]](#references)</sup>

### Certificate Template

Được định nghĩa trong AD, các template này mô tả cài đặt và quyền cấp chứng chỉ, bao gồm EKU được phép cùng quyền đăng ký hoặc chỉnh sửa. Chúng đóng vai trò thiết yếu trong việc quản lý quyền truy cập vào các dịch vụ chứng chỉ.<sup>[[1]](#references)</sup>

## Đăng ký chứng chỉ

Quy trình đăng ký chứng chỉ bắt đầu khi quản trị viên **tạo certificate template**, sau đó **công bố** template đó bằng Enterprise Certificate Authority (CA). Nhờ vậy, client có thể đăng ký sử dụng template; việc này được thực hiện bằng cách thêm tên template vào trường `certificatetemplates` của một đối tượng Active Directory.<sup>[[1]](#references)</sup>

Để client có thể yêu cầu chứng chỉ, client phải được cấp **quyền đăng ký**. Các quyền này được xác định bởi security descriptor trên certificate template và trên chính Enterprise CA. Cần cấp quyền ở cả hai nơi thì yêu cầu mới thành công.<sup>[[1]](#references)</sup>

### Quyền đăng ký template

Các quyền này được chỉ định thông qua Access Control Entry (ACE), mô tả những quyền như:<sup>[[1]](#references)</sup>

- Quyền **Certificate-Enrollment** và **Certificate-AutoEnrollment**, mỗi quyền gắn với GUID cụ thể.
- **ExtendedRights**, cho phép sử dụng tất cả quyền mở rộng.
- **FullControl/GenericAll**, cung cấp toàn quyền kiểm soát template.

### Quyền đăng ký của Enterprise CA

Các quyền của CA được nêu trong security descriptor của CA, có thể truy cập qua bảng điều khiển quản lý Certificate Authority. Một số cài đặt thậm chí cho phép người dùng có đặc quyền thấp truy cập từ xa, điều này có thể gây lo ngại về bảo mật.<sup>[[1]](#references)</sup>

### Các biện pháp kiểm soát cấp chứng chỉ bổ sung

Có thể áp dụng một số biện pháp kiểm soát như:<sup>[[1]](#references)</sup>

- **Manager Approval**: Đưa yêu cầu vào trạng thái chờ cho đến khi certificate manager phê duyệt.
- **Enrolment Agents and Authorized Signatures**: Chỉ định số chữ ký cần thiết trên CSR và các Application Policy OID bắt buộc.

### Các phương thức yêu cầu chứng chỉ

Có thể yêu cầu chứng chỉ thông qua:<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), sử dụng giao diện DCOM.
2. **ICertPassage Remote Protocol** (MS-ICPR), thông qua named pipe hoặc TCP/IP.
3. **Giao diện web đăng ký chứng chỉ**, khi đã cài đặt vai trò Certificate Authority Web Enrollment.
4. **Certificate Enrollment Service** (CES), kết hợp với dịch vụ Certificate Enrollment Policy (CEP).
5. **Network Device Enrollment Service** (NDES) dành cho thiết bị mạng, sử dụng Simple Certificate Enrollment Protocol (SCEP).

Người dùng Windows cũng có thể yêu cầu chứng chỉ qua GUI (`certmgr.msc` hoặc `certlm.msc`) hoặc công cụ dòng lệnh (`certreq.exe` hoặc lệnh `Get-Certificate` của PowerShell).

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Xác thực bằng chứng chỉ

Active Directory (AD) hỗ trợ xác thực bằng chứng chỉ, chủ yếu sử dụng các giao thức **Kerberos** và **Secure Channel (Schannel)**.<sup>[[1]](#references)</sup>

### Quy trình xác thực Kerberos

Trong quy trình xác thực Kerberos, yêu cầu Ticket Granting Ticket (TGT) của người dùng được ký bằng **private key** của chứng chỉ người dùng. Domain controller thực hiện một số bước xác thực đối với yêu cầu này, bao gồm kiểm tra **thời hạn hiệu lực**, **đường dẫn** và **trạng thái thu hồi** của chứng chỉ. Các bước xác thực cũng bao gồm việc xác minh chứng chỉ đến từ nguồn đáng tin cậy và xác nhận tổ chức phát hành có trong **kho chứng chỉ NTAUTH**. Nếu xác thực thành công, TGT sẽ được cấp. Đối tượng **`NTAuthCertificates`** trong AD, nằm tại:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

là yếu tố then chốt để thiết lập độ tin cậy cho việc xác thực bằng chứng chỉ.<sup>[[1]](#references)</sup>

### Xác thực Secure Channel (Schannel)

Schannel hỗ trợ các kết nối TLS/SSL an toàn. Trong quá trình bắt tay, client gửi một chứng chỉ và nếu chứng chỉ được xác thực thành công, chứng chỉ đó sẽ cấp quyền truy cập.<sup>[[2]](#references)</sup> Việc ánh xạ chứng chỉ với tài khoản AD có thể sử dụng hàm **S4U2Self** của Kerberos hoặc **Subject Alternative Name (SAN)** của chứng chỉ, cùng với các phương thức khác.<sup>[[1]](#references)</sup>

### Liệt kê AD Certificate Services

Có thể liệt kê các dịch vụ chứng chỉ của AD thông qua các truy vấn LDAP, qua đó thu thập thông tin về **Enterprise Certificate Authorities (CAs)** và cấu hình của chúng. Mọi người dùng đã xác thực trong domain đều có thể truy cập thông tin này mà không cần quyền đặc biệt.<sup>[[1]](#references)</sup> Các công cụ như **[Certify](https://github.com/GhostPack/Certify)** và **[Certipy](https://github.com/ly4k/Certipy)** được dùng để liệt kê và đánh giá lỗ hổng trong môi trường AD CS.<sup>[[3]](#references)</sup>

Các lệnh sử dụng những công cụ này gồm:

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

Rubeus cũng có thể sử dụng chứng chỉ PFX được bảo vệ bằng mật khẩu để xác thực PKINIT và yêu cầu TGT. Switch `/getcredentials` tùy chọn sẽ yêu cầu một vé dịch vụ U2U và cố gắng khôi phục NT hash của tài khoản:<sup>[[4]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

## References

- [1] [Đồ cũ được chứng nhận: Lạm dụng Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [Xác thực ứng dụng khách SSL/TLS là gì và hoạt động như thế nào?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
