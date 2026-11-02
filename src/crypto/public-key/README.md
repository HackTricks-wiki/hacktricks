# Mật mã khóa công khai

{{#include ../../banners/hacktricks-training.md}}

Nhiều thử thách CTF về mật mã nâng cao liên quan đến RSA, mật mã đường cong elliptic (ECC), ECDSA, lattice hoặc tính ngẫu nhiên yếu.

## Công cụ được đề xuất

- [SageMath](https://www.sagemath.org/) để tính số học modulo, xử lý đường cong elliptic và giảm lattice<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) để kiểm tra các điểm yếu RSA phổ biến<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) để kiểm tra xem một số nguyên có các thừa số đã biết hay không<sup>[[3]](#references)</sup>
- Thư viện Python [`ecdsa`](https://ecdsa.readthedocs.io/) để phân tích khóa, ký và xác minh<sup>[[7]](#references)</sup>

## RSA

Hãy bắt đầu từ đây khi thử thách cung cấp `n`, `e` và `c`, cùng với gợi ý như modulus dùng chung, số mũ nhỏ, một phần bit của khóa hoặc các thông điệp có liên hệ với nhau.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Nếu có chữ ký, hãy kiểm tra nonce có bị tái sử dụng, thiên lệch hoặc rò rỉ hay không trước khi cho rằng phải giải bài toán logarithm rời rạc nền tảng.

### Tái sử dụng nonce / thiên lệch nonce trong ECDSA

ECDSA yêu cầu một số bí mật `k` mới cho mỗi thông điệp. Nếu cùng một `k` được dùng để ký hai giá trị băm thông điệp khác nhau, có thể khôi phục khóa riêng từ các giá trị chữ ký công khai.<sup>[[4]](#references)</sup>

Ngay cả khi `k` không giống hệt nhau, sự thiên lệch hoặc rò rỉ các bit nonce qua nhiều chữ ký có thể cho phép khôi phục bằng lattice.<sup>[[5]](#references)</sup>

Cách khôi phục về mặt kỹ thuật khi `k` bị tái sử dụng:<sup>[[4]](#references)</sup>

Các phương trình chữ ký ECDSA (bậc nhóm `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Nếu cùng một `k` được tái sử dụng cho hai thông điệp `m1, m2`, tạo ra các chữ ký `(r, s1)` và `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Tấn công đường cong không hợp lệ

Nếu giao thức không xác thực rằng điểm đầu vào nằm trên đường cong dự kiến và thuộc đúng nhóm con, kẻ tấn công có thể buộc các phép toán được thực hiện trong một nhóm yếu hơn và khôi phục thông tin về scalar bí mật. SEC 1 quy định các bước kiểm tra khóa công khai nhằm ngăn chặn những đầu vào như vậy.<sup>[[6]](#references)</sup>

Lưu ý kỹ thuật:

- Xác thực rằng điểm không phải là điểm ở vô cực, có tọa độ hợp lệ, thỏa mãn phương trình đường cong và thuộc nhóm con bắt buộc.<sup>[[6]](#references)</sup>
- Trong các thử thách CTF, tình huống này thường được mô phỏng bằng một máy chủ nhân điểm do kẻ tấn công chọn với scalar bí mật rồi trả về một giá trị dẫn xuất.

## Khóa ký ML-DSA sai định dạng và rò rỉ qua lấy mẫu loại bỏ

Khóa riêng đã khai triển của ML-DSA mã hóa các vector đa thức `s1` và `s2` với các hệ số nằm trong `[-η, η]`. FIPS 204 lưu ý rằng việc giải mã các byte khóa bí mật sai định dạng có thể tạo ra các hệ số nằm ngoài khoảng này. Bản thân thuật toán ký không yêu cầu thêm bước kiểm tra tính nhất quán của khóa riêng.<sup>[[8]](#references)</sup>

Điều kiện tiên quyết liên quan là kiểm soát một **khóa ký đã khai triển trước khi khóa được nhập hoặc dùng để ký**, chứ không phải gửi khóa công khai sai định dạng cho bên xác minh. Một quy trình nhập khóa dễ dãi có thể chấp nhận các hệ số đóng gói đã bị sửa đổi mà chữ ký tạo ra vẫn xác minh được. So sánh việc chấp nhận ở bước nhập khóa và ký, sau đó kiểm tra các chữ ký thu được bằng [quy trình fuzzing mã hóa khóa mật mã](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings).<sup>[[9]](#references)[[10]](#references)</sup>

Quá trình ký tính `z = y + c·s1` và `r0 = LowBits(w − c·s2)`, rồi loại bỏ ứng viên nếu `||z||∞ ≥ γ1 − β` hoặc `||r0||∞ ≥ γ2 − β`. Các phép kiểm tra này khiến đầu ra được chấp nhận độc lập với các khóa bí mật nhỏ hợp lệ. Các hệ số khóa bí mật nằm ngoài phạm vi có thể làm sai lệch lập luận về lấy mẫu loại bỏ này và tạo ra thiên lệch phụ thuộc vào bí mật. Đây là cơ chế rò rỉ có điều kiện, **không phải** bằng chứng về việc khôi phục toàn bộ khóa từ sự khác biệt thư viện đã được báo cáo.<sup>[[8]](#references)[[10]](#references)</sup>

Việc xác thực khóa riêng khác với việc xác minh chữ ký. Trong phép so sánh được báo cáo, OpenSSL, BoringSSL và SymCrypt thực hiện thêm các bước kiểm tra khóa riêng, trong khi liboqs chấp nhận khóa đã khai triển sai định dạng khi ký; `mldsa-native` bên dưới cung cấp bộ xác thực `pk_from_sk()` mà liboqs không đưa ra bên ngoài. FIPS 204 không bắt buộc các bước kiểm tra bổ sung này.<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Tiêu chuẩn chữ ký số](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner và Heninger: Nonce thiên lệch — Tấn công lattice nhằm vào chữ ký ECDSA yếu](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Mật mã đường cong elliptic](https://www.secg.org/sec1-v2.pdf)
- [7] [Tài liệu Python `ecdsa`](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Tiêu chuẩn chữ ký số dựa trên lattice mô-đun](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Thiếu các bước kiểm tra khóa ML-DSA và ML-KEM - vấn đề #2517 của liboqs](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [Tình hình triển khai mật mã hậu lượng tử](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
