# Mật mã khóa công khai

{{#include ../../banners/hacktricks-training.md}}

Nhiều thử thách CTF về mật mã nâng cao liên quan đến RSA, mật mã đường cong elliptic (ECC), ECDSA, mạng hoặc tính ngẫu nhiên yếu.

## Công cụ được khuyến nghị

- [SageMath](https://www.sagemath.org/) để tính toán số học modulo, đường cong elliptic và rút gọn mạng<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) để kiểm tra các điểm yếu RSA phổ biến<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) để kiểm tra xem một số nguyên có các thừa số đã biết hay không<sup>[[3]](#references)</sup>
- Thư viện Python [`ecdsa`](https://ecdsa.readthedocs.io/) để phân tích khóa, ký và xác minh<sup>[[7]](#references)</sup>

## RSA

Bắt đầu từ đây khi thử thách cung cấp `n`, `e` và `c`, cùng một gợi ý như modulus dùng chung, số mũ thấp, một phần bit của khóa hoặc các thông điệp có liên quan.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Nếu có chữ ký, hãy kiểm tra việc tái sử dụng nonce, độ lệch hoặc rò rỉ trước khi cho rằng cần giải bài toán logarit rời rạc nền tảng.

### Tái sử dụng / độ lệch nonce trong ECDSA

ECDSA yêu cầu một số bí mật `k` mới cho mỗi thông điệp. Nếu cùng một `k` được dùng để ký hai hash thông điệp khác nhau, có thể khôi phục khóa riêng từ các giá trị chữ ký công khai.<sup>[[4]](#references)</sup>

Ngay cả khi `k` không giống hệt nhau, độ lệch hoặc rò rỉ các bit nonce qua nhiều chữ ký có thể cho phép khôi phục bằng phương pháp mạng.<sup>[[5]](#references)</sup>

Khôi phục kỹ thuật khi `k` được tái sử dụng:<sup>[[4]](#references)</sup>

Các phương trình chữ ký ECDSA (bậc nhóm `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Nếu cùng một `k` được tái sử dụng cho hai thông điệp `m1, m2`, tạo ra các chữ ký `(r, s1)` và `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Tấn công đường cong không hợp lệ

Nếu một giao thức không xác thực rằng điểm đầu vào nằm trên đường cong mong đợi và trong nhóm con phù hợp, kẻ tấn công có thể buộc các phép toán diễn ra trong một nhóm yếu hơn và khôi phục thông tin về một scalar bí mật. SEC 1 quy định các bước kiểm tra xác thực khóa công khai nhằm ngăn chặn những đầu vào như vậy.<sup>[[6]](#references)</sup>

Ghi chú kỹ thuật:

- Xác thực rằng các điểm không phải là điểm vô cực, có tọa độ hợp lệ, thỏa mãn phương trình đường cong và thuộc nhóm con bắt buộc.<sup>[[6]](#references)</sup>
- Trong các thử thách CTF, điều này thường được mô phỏng bằng một máy chủ nhân điểm do kẻ tấn công chọn với một scalar bí mật rồi trả về một giá trị được suy ra.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Tiêu chuẩn chữ ký số](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner và Heninger: Nonce lệch — Tấn công bằng mạng nhằm vào chữ ký ECDSA yếu](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Mật mã đường cong elliptic](https://www.secg.org/sec1-v2.pdf)
- [7] [Tài liệu Python `ecdsa`](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
