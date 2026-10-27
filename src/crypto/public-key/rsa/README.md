# Các cuộc tấn công RSA

{{#include ../../../banners/hacktricks-training.md}}

## Sàng lọc nhanh

Thu thập:

- `n`, `e`, `c` (và mọi ciphertext bổ sung)
- Mọi mối quan hệ giữa các thông điệp (cùng plaintext? dùng chung modulus? plaintext có cấu trúc?)
- Mọi leak (một phần `p/q`, các bit của `d`, `dp/dq`, padding đã biết)

Sau đó thử:

- Kiểm tra phân tích thừa số (Factordb / `sage: factor(n)` nếu `n` tương đối nhỏ)
- Các mẫu số mũ thấp (`e=3`, broadcast)
- Common modulus / các prime bị lặp
- Các phương pháp lattice (Coppersmith/LLL) khi đã biết gần hết một giá trị

## Các cuộc tấn công RSA phổ biến

### Common modulus

Nếu hai ciphertext `c1, c2` mã hóa **cùng một thông điệp** bằng **cùng modulus** `n` nhưng dùng các số mũ khác nhau `e1, e2` (và `gcd(e1,e2)=1`), bạn có thể khôi phục `m` bằng thuật toán Euclid mở rộng:

`m = c1^a * c2^b mod n` với `a*e1 + b*e2 = 1`.

Các bước ví dụ:

1. Tính `(a, b) = xgcd(e1, e2)` để có `a*e1 + b*e2 = 1`
2. Nếu `a < 0`, hiểu `c1^a` là `inv(c1)^{-a} mod n` (tương tự với `b`)
3. Nhân các giá trị rồi lấy modulo

### Các modulus dùng chung prime

Nếu có nhiều modulus RSA từ cùng một thử thách, hãy kiểm tra xem chúng có dùng chung một prime hay không:

- `gcd(n1, n2) != 1` cho thấy lỗi nghiêm trọng trong quá trình tạo khóa.

Điều này thường xuất hiện trong CTF với lời giải thích kiểu như "chúng tôi tạo nhiều khóa thật nhanh" hoặc "randomness kém".

### Modulus thưa / short-sleeve

Một số bộ tạo số nguyên lớn bị lỗi làm lộ trực tiếp cấu trúc trong modulus công khai: mỗi limb chỉ chứa một trường con ngẫu nhiên nhỏ, phần bit còn lại là `0`. Trên thực tế, hiện tượng này thường biểu hiện dưới dạng **các khối số 0 cách đều nhau** trong `n`, thường căn chỉnh theo các limb 32-bit hoặc 128-bit.<sup>[[1]](#references)</sup>

Kiểm tra nhanh:

- Xuất `n` ở dạng hex và tìm các vùng số 0 lặp lại theo một khoảng cách cố định.
- Chia `n` lại thành các limb (`2^32`, `2^64`, `2^128`) và kiểm tra xem mỗi limb có nhỏ bất thường hay không.
- Kiểm tra các khóa SSH/TLS công khai bằng công cụ như **badkeys** khi nghi ngờ quá trình tạo host key yếu.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Đây là vấn đề nghiêm trọng hơn thiên lệch thống kê: nếu cả hai thừa số bí mật `p` và `q` đều có dạng short-sleeve, modulus có thể **dễ phân tích thừa số**.<sup>[[1]](#references)</sup>

### Phân tích đa thức của các khóa RSA có cấu trúc

Với độ rộng limb nghi ngờ là `w`, viết modulus theo cơ số `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Vì phép tính giá trị có tính nhân, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Nếu các thừa số cũng có hệ số limb thưa, thì:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Các bước tấn công:

1. Đoán độ rộng limb `w`.
2. Chuyển modulus công khai `n` thành `f_n(x)` bằng cơ số `2^w`.
3. Phân tích `f_n(x)` thành thừa số trên tập số nguyên.
4. Tính giá trị các thừa số ứng viên tại `B = 2^w`.
5. Xác minh ứng viên nào nhân với nhau cho ra `n`.

Cách này **không phá được RSA thông thường**. Nó chỉ hiệu quả khi bản thân các thừa số nguyên tố có hệ số limb rất nhỏ và cấu trúc rõ rệt.<sup>[[1]](#references)</sup>

### Leak limb bị dịch chuyển

Các byte thưa không phải lúc nào cũng căn chỉnh ở đầu thấp của mỗi limb. Nếu chuyển đổi trực tiếp sang cơ số `2^w` tạo ra các hệ số lớn, hãy tìm các độ dịch `i,j` sao cho `2^i p` và `2^j q` trở nên thưa trong cơ số limb đó. Vẫn có thể suy ra đa thức tích từ modulus công khai, phân tích đa thức thành thừa số, rồi ghép lại thành các thừa số nguyên ban đầu.<sup>[[1]](#references)</sup>

### Dấu hiệu lỗi triển khai: lỗi RNG khi chuyển byte sang limb

Một mẫu nguy hiểm là tính số lượng **limb 32-bit**, chỉ cấp phát số lượng **byte** tương ứng, rồi chép chúng vào mảng limb:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

This khiến mỗi limb 32-bit chỉ có **8 bit entropy**, cộng thêm một bit cao bị ép đặt ở limb cuối. Các số nguyên tố RSA tạo ra có thể thường được nhận diện và phân tích thành thừa số chỉ từ public key.<sup>[[1]](#references)</sup>

### Chế độ lỗi DSA liên quan

Nếu cùng routine số nguyên lớn bị lỗi được dùng lại để tạo private exponent cho DSA, public key `y = g^x` có thể làm lộ không gian tìm kiếm **bị thu hẹp đáng kể và có cấu trúc** của `x`. Khi đã biết mẫu limb, các tấn công discrete-log như **baby-step giant-step** có thể trở nên khả thi đối với các tham số public.<sup>[[1]](#references)</sup>

### Håstad broadcast / số mũ nhỏ

Nếu cùng một plaintext được gửi cho nhiều người nhận với `e` nhỏ (thường là `e=3`) và không có padding phù hợp, bạn có thể khôi phục `m` bằng CRT và căn nguyên.

Điều kiện kỹ thuật:

Nếu bạn có `e` ciphertext của cùng một thông điệp, với các modulus `n_i` đôi một nguyên tố cùng nhau:

- Dùng CRT để khôi phục `M = m^e` trên tích `N = Π n_i`
- Nếu `m^e < N`, thì `M` là lũy thừa nguyên thực sự, và `m = integer_root(M, e)`

### Tấn công Wiener: private exponent nhỏ

Nếu `d` quá nhỏ, phân số liên tục có thể khôi phục nó từ `e/n`.

### Cạm bẫy của Textbook RSA

Nếu bạn thấy:

- Không có OAEP/PSS, chỉ dùng phép lũy thừa modulo thô
- Mã hóa xác định

thì các tấn công đại số và lạm dụng oracle có khả năng xảy ra cao hơn nhiều.

### Công cụ

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, căn, CF): https://www.sagemath.org/

## Các mẫu thông điệp liên quan

Nếu bạn thấy hai ciphertext dùng cùng một modulus với các thông điệp có quan hệ đại số (ví dụ: `m2 = a*m1 + b`), hãy tìm các tấn công "related-message" như Franklin–Reiter. Các tấn công này thường yêu cầu:

- cùng modulus `n`
- cùng exponent `e`
- biết quan hệ giữa các plaintext

Trên thực tế, việc này thường được giải bằng Sage: thiết lập các đa thức modulo `n` và tính GCD.

## Lattice / Coppersmith

Hãy dùng phương pháp này khi bạn có các bit từng phần, plaintext có cấu trúc hoặc các quan hệ gần nhau khiến phần chưa biết có giá trị nhỏ.

Các phương pháp lattice (LLL/Coppersmith) thường xuất hiện khi có thông tin từng phần:

- Plaintext đã biết một phần (thông điệp có cấu trúc với phần đuôi chưa biết)
- `p`/`q` đã biết một phần (các bit cao bị leak)
- Sai khác chưa biết nhỏ giữa các giá trị liên quan

### Dấu hiệu cần nhận biết

Các gợi ý thường gặp trong thử thách:

- "Chúng tôi đã leak các bit trên/dưới của p"
- "Flag được nhúng theo dạng: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Chúng tôi dùng RSA nhưng với padding ngẫu nhiên nhỏ"

### Công cụ

Trên thực tế, bạn sẽ dùng Sage cho LLL và một template có sẵn cho trường hợp cụ thể.

Các tài liệu khởi đầu hữu ích:

- Template crypto CTF cho Sage: https://github.com/defund/coppersmith
- Tài liệu tham khảo dạng khảo sát: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Phân tích thừa số các khóa RSA "short-sleeve" bằng đa thức](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [Công cụ badkeys độc lập](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

