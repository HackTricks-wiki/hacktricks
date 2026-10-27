# TLS và chứng chỉ

{{#include ../../banners/hacktricks-training.md}}

Phần này trình bày cách kiểm tra X.509, các kiểu mã hóa, chuyển đổi và những lỗi xác thực liên quan đến bảo mật.

## Phân tích X.509

OpenSSL có thể in các trường đã giải mã của chứng chỉ, trong khi `asn1parse` hiển thị cấu trúc ASN.1 bên dưới.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

Kiểm tra ít nhất:

- subject, issuer và Subject Alternative Name (SAN);
- key usage và extended key usage;
- basic constraints và path-length constraints;
- thời hạn hiệu lực `notBefore` và `notAfter`;
- các tham số public key và thuật toán chữ ký.

Các chữ ký cũ như chữ ký chứng chỉ dựa trên MD5 hoặc SHA-1 đặc biệt đáng lưu ý, dù việc chấp nhận và mức độ ảnh hưởng cụ thể phụ thuộc vào bộ xác thực và ngữ cảnh tin cậy.<sup>[[3]](#references)</sup>

RFC 5280 định nghĩa hồ sơ Internet X.509 và các quy tắc xử lý những extension như SAN, key usage, name constraints và basic constraints.<sup>[[3]](#references)</sup>

## Mã hóa và Container

- **Mã hóa dạng văn bản kiểu PEM:** dữ liệu Base64 nằm giữa các ranh giới `BEGIN` và `END`.
- **DER:** biểu diễn nhị phân theo Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** thường chứa chứng chỉ và chuỗi chứng chỉ, nhưng không chứa private key.
- **PKCS#12 (`.p12` hoặc `.pfx`):** có thể chứa private key, chứng chỉ và các chứng chỉ hỗ trợ.

RFC 7468 quy định các dạng mã hóa văn bản được dùng cho cấu trúc PKIX, PKCS và CMS; lệnh `pkcs12` của OpenSSL tạo và phân tích các tệp PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

Coi `out.pem` là dữ liệu nhạy cảm: trừ khi dùng các tùy chọn như `-nokeys`, đầu ra có thể chứa thông tin khóa riêng tư.<sup>[[5]](#references)</sup>

## Danh sách kiểm tra đánh giá bảo mật

Áp dụng các yêu cầu xử lý chứng chỉ trong RFC 5280 khi đánh giá bộ xác thực hoặc quyết định tin cậy.<sup>[[3]](#references)</sup>

- Xác minh toàn bộ chuỗi chứng chỉ đến một trust anchor được tin cậy rõ ràng; không mặc nhiên tin cậy các root do người dùng cung cấp.
- Xác nhận hostname hoặc danh tính dịch vụ khớp với các giá trị SAN.<sup>[[8]](#references)</sup>
- Thực thi các ràng buộc cơ bản, ràng buộc tên, key usage và extended key usage.
- Từ chối chứng chỉ đã hết hạn hoặc chưa có hiệu lực, cũng như các thuật toán khóa hoặc chữ ký không được phép.
- Liên kết danh tính trong chứng chỉ máy khách với đúng tài khoản ứng dụng và ngữ cảnh phân quyền.

## Nhật ký Certificate Transparency

Certificate Transparency cung cấp các nhật ký công khai có thể kiểm tra về những chứng chỉ đã được cấp.<sup>[[6]](#references)</sup> Tìm kiếm miền bằng crt.sh trong quá trình phát hiện tài sản được ủy quyền.<sup>[[7]](#references)</sup>

## References

- [1] [Tài liệu OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Tài liệu OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Hồ sơ chứng chỉ và CRL của hạ tầng khóa công khai Internet X.509](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Mã hóa văn bản của các cấu trúc PKIX, PKCS và CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Tài liệu OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency phiên bản 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Tìm kiếm chứng chỉ](https://crt.sh/)
- [8] [RFC 9525 - Danh tính dịch vụ trong TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
