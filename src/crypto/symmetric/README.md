# Mật mã đối xứng

{{#include ../../banners/hacktricks-training.md}}

## Những điều cần chú ý trong CTF

- **Dùng sai mode**: các mẫu ECB, tính dễ bị sửa đổi của CBC, dùng lại nonce trong CTR/GCM.
- **Padding oracle**: lỗi/thời gian phản hồi khác nhau khi padding không hợp lệ.
- **Nhầm lẫn MAC**: dùng CBC-MAC với thông điệp có độ dài thay đổi, hoặc mắc lỗi MAC-then-encrypt.
- **XOR ở khắp nơi**: stream cipher và các cấu trúc tùy biến thường quy về XOR với keystream.

## Các mode AES và cách dùng sai

NIST quy định các mode bảo mật ECB, CBC và CTR trong SP 800-38A, cùng phương thức mã hóa xác thực GCM trong SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB làm lộ các mẫu: các khối plaintext giống nhau → các khối ciphertext giống nhau. Điều này cho phép:

- Cắt-dán / đổi thứ tự khối
- Xóa khối (nếu định dạng vẫn hợp lệ)

Nếu bạn có thể kiểm soát plaintext và quan sát ciphertext (hoặc cookie), hãy thử tạo các khối lặp lại (ví dụ: nhiều ký tự `A`) và tìm các khối trùng nhau.

### CBC: Cipher Block Chaining

- CBC **có thể bị sửa đổi**: lật các bit trong `C[i-1]` sẽ lật các bit tương ứng có thể dự đoán trong `P[i]`, đồng thời làm hỏng `P[i-1]`. Sửa IV sẽ tác động đến khối plaintext đầu tiên mà không làm hỏng khối plaintext đứng trước.
- Nếu hệ thống cho biết padding hợp lệ hay không hợp lệ, bạn có thể có **padding oracle**.

### CTR

CTR biến AES thành stream cipher: `C = P XOR keystream`.

Nếu nonce/IV được dùng lại với cùng một key:

- `C1 XOR C2 = P1 XOR P2` (điển hình của việc dùng lại keystream)
- Khi biết plaintext, bạn có thể khôi phục keystream và giải mã các dữ liệu khác.

**Các kiểu khai thác việc dùng lại nonce/IV**

- Khôi phục keystream ở những vị trí đã biết/có thể đoán plaintext:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Áp dụng các byte keystream đã khôi phục để giải mã bất kỳ ciphertext nào khác được tạo bằng cùng key+IV tại cùng các offset.
- Dữ liệu có cấu trúc cao (ví dụ: chứng chỉ ASN.1/X.509, file header, JSON/CBOR) tạo ra các vùng known-plaintext lớn. Bạn thường có thể XOR ciphertext của chứng chỉ với phần thân chứng chỉ có thể dự đoán để suy ra keystream, rồi giải mã các secret khác được mã hóa bằng IV bị tái sử dụng. Xem thêm [TLS & Certificates](../tls-and-certificates/README.md) để biết các bố cục chứng chỉ thường gặp.<sup>[[1]](#references)</sup>
- Khi nhiều secret có **cùng định dạng/kích thước tuần tự hóa** được mã hóa bằng cùng key+IV, việc căn chỉnh các trường sẽ làm lộ thông tin ngay cả khi không có known plaintext đầy đủ. Ví dụ: các RSA key PKCS#8 có cùng kích thước modulus đặt các thừa số nguyên tố tại những offset trùng nhau (độ căn chỉnh khoảng 99.6% với 2048-bit). XOR hai ciphertext dùng lại keystream sẽ cô lập `p ⊕ p'` / `q ⊕ q'`, có thể brute-force khôi phục trong vài giây.<sup>[[1]](#references)</sup>
- IV mặc định trong các thư viện (ví dụ, hằng số `000...01`) là một lỗi nghiêm trọng: mỗi lần mã hóa đều lặp lại cùng keystream, biến CTR thành one-time pad bị tái sử dụng.<sup>[[1]](#references)</sup>

**Tính khả biến của CTR**

- CTR chỉ cung cấp tính bảo mật: lật bit trong ciphertext sẽ xác định lật các bit tương ứng trong plaintext. Nếu không có authentication tag, attacker có thể sửa đổi dữ liệu (ví dụ: chỉnh key, flag hoặc message) mà không bị phát hiện.
- Dùng AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, v.v.) và bắt buộc xác minh tag để phát hiện việc lật bit.

### GCM

GCM cũng bị phá nghiêm trọng khi nonce bị tái sử dụng. Nếu cùng key+nonce được dùng nhiều lần, thường sẽ gặp:

- Keystream bị tái sử dụng khi mã hóa (giống CTR), cho phép khôi phục plaintext khi biết bất kỳ plaintext nào.
- Mất các đảm bảo về tính toàn vẹn. Tùy vào dữ liệu bị lộ (nhiều cặp message/tag dùng cùng nonce), attacker có thể giả mạo tag.

Hướng dẫn vận hành:

- Xem "nonce reuse" trong AEAD là một lỗ hổng nghiêm trọng.
- AEAD chống lỗi sử dụng như AES-GCM-SIV giúp giảm hậu quả khi nonce bị tái sử dụng. Caller vẫn nên cung cấp nonce duy nhất theo yêu cầu của interface của construction; việc vô tình tái sử dụng gây hậu quả giới hạn hơn so với GCM thông thường.<sup>[[3]](#references)[[4]](#references)</sup>
- Nếu có nhiều ciphertext dùng cùng nonce, hãy bắt đầu bằng cách kiểm tra các quan hệ dạng `C1 XOR C2 = P1 XOR P2`.

### Công cụ

- [CyberChef](https://gchq.github.io/CyberChef/) để thử nghiệm nhanh.<sup>[[8]](#references)</sup>
- Package [PyCryptodome](https://www.pycryptodome.org/) của Python để viết script.<sup>[[9]](#references)</sup>

## Các kiểu khai thác ECB

ECB (Electronic Code Book) mã hóa từng block độc lập:

- các block plaintext giống nhau → ciphertext giống nhau
- điều này làm lộ cấu trúc và cho phép thực hiện các kiểu tấn công cut-and-paste

![Sơ đồ khối giải mã chế độ ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ý tưởng phát hiện: kiểu token/cookie

Nếu bạn đăng nhập nhiều lần mà **lần nào cũng nhận được cùng một cookie**, ciphertext có thể mang tính xác định (ECB hoặc IV cố định).

Nếu bạn tạo hai user có bố cục plaintext gần như giống hệt nhau (ví dụ: nhiều ký tự lặp lại) và thấy các block ciphertext lặp lại tại cùng offset, ECB là một nghi phạm hàng đầu.

### Các kiểu khai thác

#### Xóa toàn bộ block

Nếu định dạng token có dạng `<username>|<password>` và ranh giới block được căn chỉnh, đôi khi bạn có thể tạo user sao cho block `admin` được căn chỉnh, rồi xóa các block phía trước để lấy token hợp lệ cho `admin`.

#### Di chuyển block

Nếu backend chấp nhận padding/khoảng trắng thừa (`admin` so với `admin    `), bạn có thể:

- Căn chỉnh một block chứa `admin   `
- Hoán đổi/tái sử dụng block ciphertext đó trong token khác

## Padding Oracle

### Khái niệm

Trong chế độ CBC, nếu server tiết lộ (trực tiếp hoặc gián tiếp) liệu plaintext sau giải mã có **PKCS#7 padding hợp lệ** hay không, bạn thường có thể:<sup>[[7]](#references)</sup>

- Giải mã ciphertext mà không cần key
- Tạo ciphertext giải mã thành plaintext tùy ý khi bạn có thể gửi các block đứng trước hoặc IV đã được tạo thủ công, đồng thời ứng dụng chấp nhận message có padding hợp lệ

Oracle có thể là:

- Một thông báo lỗi cụ thể
- HTTP status / kích thước response khác biệt
- Chênh lệch thời gian

### Khai thác thực tế

PadBuster là công cụ kinh điển:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Ví dụ:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
  -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

Ghi chú:

- Kích thước block thường là `16` đối với AES.
- `-encoding 0` nghĩa là Base64.
- Dùng `-error` nếu oracle trả về một chuỗi cụ thể.

### Vì sao cách này hoạt động

CBC giải mã bằng công thức `P[i] = D(C[i]) XOR C[i-1]`. Bằng cách sửa các byte trong `C[i-1]` và quan sát xem padding có hợp lệ hay không, bạn có thể khôi phục `P[i]` từng byte một.

## Bit-flipping trong CBC

Ngay cả khi không có padding oracle, CBC vẫn có thể bị thay đổi có chủ đích. Nếu bạn có thể sửa các block ciphertext và ứng dụng sử dụng plaintext sau giải mã làm dữ liệu có cấu trúc (ví dụ: `role=user`), bạn có thể lật các bit cụ thể để thay đổi những byte plaintext được chọn tại một vị trí xác định trong block kế tiếp.

Mẫu CTF thường gặp:

- Token = `IV || C1 || C2 || ...`
- Bạn kiểm soát các byte trong `C[i]`
- Bạn nhắm đến các byte plaintext trong `P[i+1]` vì `P[i+1] = D(C[i+1]) XOR C[i]`

Bản thân cách này không phá vỡ tính bí mật, nhưng là một thủ thuật leo thang đặc quyền thường gặp khi thiếu tính toàn vẹn.

## CBC-MAC

CBC-MAC chỉ an toàn trong một số điều kiện cụ thể (đáng chú ý là **thông điệp có độ dài cố định** và phân tách miền đúng cách). AES-CMAC là một cấu trúc chuẩn hóa xử lý an toàn đầu vào có độ dài thay đổi.<sup>[[5]](#references)</sup>

### Mẫu giả mạo độ dài thay đổi kinh điển

CBC-MAC thường được tính như sau:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Nếu có thể lấy được tag cho các thông điệp tùy chọn, bạn thường có thể tạo tag cho một phép nối (hoặc cấu trúc liên quan) mà không cần biết key, bằng cách khai thác cách CBC nối chuỗi các block.

Điều này thường xuất hiện trong cookie/token CTF dùng CBC-MAC để xác thực username hoặc role.

### Các lựa chọn an toàn hơn

- Dùng HMAC (SHA-256/512)
- Dùng CMAC (AES-CMAC) đúng cách
- Thêm độ dài thông điệp / phân tách miền

## Mật mã dòng: XOR và RC4

### Mô hình tư duy

Phần lớn tình huống dùng mật mã dòng có thể quy về:

`ciphertext = plaintext XOR keystream`

Do đó:

- Nếu biết plaintext, bạn có thể khôi phục keystream.
- Nếu keystream được dùng lại (cùng key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Mã hóa dựa trên XOR

Nếu biết bất kỳ đoạn plaintext nào tại vị trí `i`, bạn có thể khôi phục các byte keystream và giải mã các ciphertext khác tại những vị trí tương ứng.

Công cụ tự động:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 là một mật mã dòng cũ; thao tác mã hóa/giải mã đều là cùng một phép XOR. Các bias đã biết của nó khiến RC4 không phù hợp với hệ thống mới, và TLS nghiêm cấm rõ ràng các bộ mã hóa của RC4.<sup>[[6]](#references)</sup>

Nếu có thể lấy được ciphertext RC4 của plaintext đã biết với cùng key, bạn có thể khôi phục keystream và giải mã các thông điệp khác có cùng độ dài/vị trí offset.

Bài writeup tham khảo (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Sự cẩu thả và sự tỉ mỉ trong mật mã học](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Khuyến nghị về các chế độ hoạt động của block cipher](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Khuyến nghị về Galois/Counter Mode (GCM) và GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Mã hóa xác thực chống chịu việc dùng sai nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - Thuật toán AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Cấm các bộ mã hóa RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Kiểm thử Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Tài liệu PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
