# Đánh cắp chứng chỉ AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Đây là bản tóm tắt ngắn về các chương nói về hành vi đánh cắp trong nghiên cứu tuyệt vời tại [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Có thể làm gì với chứng chỉ

Trước khi tìm hiểu cách đánh cắp chứng chỉ, dưới đây là một số thông tin về cách xác định chứng chỉ có thể dùng vào việc gì:

```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```

## Xuất chứng chỉ bằng Crypto APIs – THEFT1

Trong **phiên desktop tương tác**, có thể dễ dàng trích xuất chứng chỉ người dùng hoặc máy tính cùng với private key, đặc biệt nếu **private key có thể xuất được**. Có thể thực hiện việc này bằng cách tìm chứng chỉ trong `certmgr.msc`, nhấp chuột phải vào chứng chỉ đó rồi chọn `All Tasks → Export` để tạo tệp .pfx được bảo vệ bằng mật khẩu.<sup>[[1]](#references)</sup>

Để thực hiện **theo cách lập trình**, có thể dùng các công cụ như PowerShell `ExportPfxCertificate` cmdlet hoặc các dự án như [dự án C# CertStealer của TheWover](https://github.com/TheWover/CertStealer). Các công cụ này sử dụng **Microsoft CryptoAPI** (CAPI) hoặc Cryptography API: Next Generation (CNG) để tương tác với kho chứng chỉ. Các API này cung cấp nhiều dịch vụ mật mã, bao gồm những dịch vụ cần thiết cho việc lưu trữ và xác thực chứng chỉ.

Tuy nhiên, nếu private key được đặt là không thể xuất, cả CAPI lẫn CNG thường sẽ chặn việc trích xuất chứng chỉ đó. Có thể dùng các công cụ như **Mimikatz** để vượt qua hạn chế này. Mimikatz có các lệnh `crypto::capi` và `crypto::cng` để patch các API tương ứng, cho phép xuất private key. Cụ thể, `crypto::capi` patch CAPI trong tiến trình hiện tại, còn `crypto::cng` nhắm đến bộ nhớ của **lsass.exe** để patch.

## Đánh cắp chứng chỉ người dùng qua DPAPI – THEFT2

Tìm hiểu thêm về DPAPI tại:

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Trong Windows, **private key của chứng chỉ được DPAPI bảo vệ**. Cần lưu ý rằng **vị trí lưu trữ private key của người dùng và máy tính** khác nhau, và cấu trúc tệp cũng thay đổi tùy theo cryptographic API mà hệ điều hành sử dụng. **SharpDPAPI** có thể tự động xử lý những khác biệt này khi giải mã các DPAPI blob.<sup>[[1]](#references)</sup>

**Chứng chỉ người dùng** chủ yếu được lưu trong registry tại `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, nhưng một số chứng chỉ cũng có thể nằm trong thư mục `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. **Private key** tương ứng với các chứng chỉ này thường được lưu tại `%APPDATA%\Microsoft\Crypto\RSA\User SID\` đối với khóa **CAPI** và `%APPDATA%\Microsoft\Crypto\Keys\` đối với khóa **CNG**.

Để **trích xuất chứng chỉ và private key liên kết với nó**, quy trình gồm:

1. **Chọn chứng chỉ mục tiêu** trong kho chứng chỉ của người dùng và lấy tên kho khóa của chứng chỉ đó.
2. **Tìm DPAPI masterkey cần thiết** để giải mã private key tương ứng.
3. **Giải mã private key** bằng DPAPI masterkey dạng plaintext.

Để **lấy DPAPI masterkey dạng plaintext**, có thể sử dụng các cách sau:

```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```

Để đơn giản hóa việc giải mã các tệp masterkey và tệp khóa riêng, lệnh `certificates` của [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) rất hữu ích. Lệnh này chấp nhận `/pvk`, `/mkfile`, `/password` hoặc `{GUID}:KEY` làm đối số để giải mã các khóa riêng và chứng chỉ được liên kết, sau đó tạo tệp `.pem`.

```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

## Đánh cắp chứng chỉ máy qua DPAPI – THEFT3

Các chứng chỉ máy được Windows lưu trong registry tại `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` và các khóa riêng tư liên quan nằm trong `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (đối với CAPI) và `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (đối với CNG) được mã hóa bằng các khóa master DPAPI của máy. Không thể giải mã các khóa này bằng khóa sao lưu DPAPI của domain; thay vào đó, cần có **bí mật LSA DPAPI_SYSTEM**, chỉ người dùng SYSTEM mới có thể truy cập.<sup>[[1]](#references)</sup>

Có thể giải mã thủ công bằng cách chạy lệnh `lsadump::secrets` trong **Mimikatz** để trích xuất bí mật LSA DPAPI_SYSTEM, sau đó dùng khóa này để giải mã các masterkey của máy. Ngoài ra, có thể dùng lệnh `crypto::certificates /export /systemstore:LOCAL_MACHINE` của Mimikatz sau khi vá CAPI/CNG như đã mô tả trước đó.

**SharpDPAPI** cung cấp cách tiếp cận tự động hơn với lệnh certificates. Khi dùng cờ `/machine` với quyền nâng cao, công cụ sẽ nâng quyền lên SYSTEM, trích xuất bí mật LSA DPAPI_SYSTEM, dùng bí mật đó để giải mã các masterkey DPAPI của máy, rồi sử dụng những khóa dạng plaintext này làm bảng tra cứu để giải mã các khóa riêng tư của mọi chứng chỉ máy.

## Tìm tệp chứng chỉ – THEFT4

Đôi khi có thể tìm thấy chứng chỉ trực tiếp trong hệ thống tệp, chẳng hạn trong các thư mục chia sẻ tệp hoặc thư mục Downloads. Các loại tệp chứng chỉ thường gặp nhất nhắm đến môi trường Windows là `.pfx` và `.p12`. Ít phổ biến hơn, các tệp có phần mở rộng `.pkcs12` và `.pem` cũng xuất hiện. Một số phần mở rộng đáng chú ý khác liên quan đến chứng chỉ gồm:<sup>[[1]](#references)</sup>

- `.key` dành cho khóa riêng tư,
- `.crt`/`.cer` chỉ chứa chứng chỉ,
- `.csr` dành cho yêu cầu ký chứng chỉ (Certificate Signing Request), không chứa chứng chỉ hoặc khóa riêng tư,
- `.jks`/`.keystore`/`.keys` dành cho Java Keystore, có thể lưu chứng chỉ cùng với khóa riêng tư được các ứng dụng Java sử dụng.

Có thể tìm các tệp này bằng PowerShell hoặc command prompt, dựa trên những phần mở rộng đã nêu.

Nếu tìm thấy tệp chứng chỉ PKCS#12 được bảo vệ bằng mật khẩu, có thể trích xuất hash bằng `pfx2john.py`, có tại [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Sau đó, có thể dùng JohnTheRipper để thử crack mật khẩu.

```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```

## Đánh cắp thông tin xác thực NTLM qua PKINIT – THEFT5 (UnPAC the hash)

Nội dung sau giải thích một phương pháp đánh cắp thông tin xác thực NTLM qua PKINIT, cụ thể là phương pháp có tên THEFT5. Dưới đây là phần diễn giải lại ở thể bị động, với nội dung được ẩn danh và tóm lược khi phù hợp:<sup>[[1]](#references)</sup>

Để hỗ trợ xác thực NTLM `MS-NLMP` cho các ứng dụng không hỗ trợ xác thực Kerberos, KDC được thiết kế để trả về hàm một chiều (OWF) NTLM của người dùng bên trong privilege attribute certificate (PAC), cụ thể là trong bộ đệm `PAC_CREDENTIAL_INFO`, khi PKCA được sử dụng. Do đó, nếu một tài khoản xác thực và nhận được Ticket-Granting Ticket (TGT) qua PKINIT, một cơ chế tích hợp sẽ cho phép máy chủ hiện tại trích xuất NTLM hash từ TGT nhằm hỗ trợ các giao thức xác thực cũ. Quá trình này bao gồm giải mã cấu trúc `PAC_CREDENTIAL_DATA`, về cơ bản là một biểu diễn NTLM plaintext được tuần tự hóa theo NDR.

Công cụ **Kekeo**, có tại [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), được nhắc đến như một công cụ có khả năng yêu cầu TGT chứa dữ liệu cụ thể này, qua đó hỗ trợ lấy NTLM của người dùng. Lệnh được sử dụng cho mục đích này như sau:

```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```

**`Rubeus`** cũng có thể lấy thông tin này bằng tùy chọn **`asktgt [...] /getcredentials`**.

Ngoài ra, tài liệu ghi nhận rằng Kekeo có thể xử lý các certificate được bảo vệ bằng smartcard nếu có thể lấy được mã PIN, đồng thời dẫn chiếu đến [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). **Rubeus** cũng được cho là hỗ trợ khả năng tương tự và có tại [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Phần giải thích này tóm lược quy trình và các công cụ liên quan đến việc đánh cắp thông tin xác thực NTLM thông qua PKINIT, tập trung vào việc lấy NTLM hash từ TGT nhận được bằng PKINIT và các tiện ích hỗ trợ quy trình này.

## References

- [1] [Certified Pre-Owned: Lạm dụng Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
