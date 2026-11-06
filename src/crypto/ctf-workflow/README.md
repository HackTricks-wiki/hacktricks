# Quy trình CTF Crypto

{{#include ../../banners/hacktricks-training.md}}

## Danh sách kiểm tra phân loại ban đầu

1. Xác định bạn đang có gì: encoding, encryption, hash, chữ ký hay MAC.
2. Xác định những gì có thể kiểm soát: plaintext/ciphertext, IV/nonce, key, oracle (padding/lỗi/timing), thông tin rò rỉ một phần.
3. Phân loại: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Trước tiên, thực hiện các bước kiểm tra có xác suất thành công cao nhất: giải mã các lớp, XOR với known-plaintext, nonce reuse, sử dụng sai mode, hành vi của oracle.
5. Chỉ chuyển sang các phương pháp nâng cao khi cần: lattice (LLL/Coppersmith), SMT/Z3, side-channel.

## Tài nguyên trực tuyến & tiện ích

Những công cụ này hữu ích khi cần nhận diện và bóc tách các lớp, hoặc nhanh chóng xác nhận một giả thuyết.

### Tra cứu hash

- Tìm kiếm hash của challenge nếu biết hash đó là dữ liệu giả lập/công khai.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Tìm kiếm trên hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Không gửi hash mật khẩu thật hoặc dữ liệu challenge bảo mật đến các dịch vụ tra cứu của bên thứ ba. Nếu lo ngại về việc tiết lộ thông tin, điều khoản dịch vụ hoặc quy định cuộc thi, hãy ưu tiên tấn công wordlist/rule offline.

### Công cụ hỗ trợ nhận diện

- CyberChef (Magic, giải mã và chuyển đổi).<sup>[[7]](#references)</sup>
- dCode (công cụ thử cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (công cụ giải substitution).<sup>[[9]](#references)</sup>

### Nền tảng luyện tập / tài liệu tham khảo

- CryptoHack (các challenge cryptography thực hành).<sup>[[10]](#references)</sup>
- Cryptopals (các lỗi thường gặp trong cryptography hiện đại).<sup>[[11]](#references)</sup>

### Tự động giải mã

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (thử nhiều base/encoding).<sup>[[13]](#references)</sup>

Với mã nguồn ngôn ngữ lập dị và trạng thái interpreter tùy chỉnh, xem [Crypto CTF Misc](../ctf-misc/).

## Encoding & classical cipher

### Kỹ thuật

Nhiều bài crypto CTF là các phép biến đổi nhiều lớp: base encoding + substitution đơn giản + compression. Mục tiêu là nhận diện các lớp và bóc tách chúng một cách an toàn.

### Encoding: thử nhiều base

Nếu nghi ngờ encoding nhiều lớp (base64 → base32 → …), hãy thử:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Các dấu hiệu thường gặp:

- Base64: `A-Za-z0-9+/=` (thường có padding `=`)
- Base32: `A-Z2-7=` (thường có nhiều padding `=`)
- Ascii85/Base85: nhiều dấu câu; đôi khi được bao bởi `<~ ~>`

### Substitution / đơn bảng chữ cái

- Trình giải cryptogram Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Khôi phục bằng known-plaintext tên tệp Base32 đã substitution

Khi tên tệp bị làm rối chỉ chứa `a-z2-7`, có độ dài khoảng `ceil(8 * byte_length / 5)` ký tự sau khi bỏ hậu tố cố định, và cùng một plaintext tạo ra cùng một đầu ra trên các tệp, hãy thử **Base32 không padding, sau đó áp dụng phép thay thế ký hiệu cố định**. Những manh mối này tự chúng chưa đủ để chứng minh. Thu thập các tên tệp có thể dự đoán và ciphertext tương ứng, giữ nguyên kiểu chữ, mã hóa Base32 từng plaintext rồi căn chỉnh các ký hiệu theo từng vị trí. Mỗi ký hiệu plaintext lặp lại phải ánh xạ đến cùng một ký hiệu ciphertext, và ánh xạ ngược cũng phải là duy nhất. Trong một vụ ransomware, `ntuser.ini` và `NTUSER.DAT` đã cung cấp các cặp như vậy; cách này khôi phục được tên tệp, **không phải nội dung tệp hay encryption key**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

Nếu mục tiêu chứa các ký hiệu chưa được ánh xạ, hãy thu thập thêm các cặp đã biết hoặc chỉ hoán vị các ánh xạ Base32 chưa dùng. Khôi phục padding để độ dài đạt bội số của tám, loại Base32 không hợp lệ và các tên giải mã không in được, sau đó mã hóa lại các ứng viên còn lại và so sánh với **toàn bộ** ciphertext ban đầu. Các khối ciphertext lặp lại có thể cung cấp thêm manh mối: trong trường hợp trên, `3gpng2wv` được ánh xạ ngược thành Base32 `gaydambq`, giải mã thành năm số 0 ASCII. Chỉ riêng một ứng viên in được không phải là bằng chứng duy nhất.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Công cụ phá mã Caesar tự động của Nayuki.<sup>[[15]](#references)</sup>
- Công cụ Atbash của Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Công cụ Vigenère của dCode.<sup>[[8]](#references)</sup>
- Công cụ giải Vigenère của Guballa.<sup>[[17]](#references)</sup>

### Bacon cipher

Thường xuất hiện dưới dạng các nhóm gồm 5 bit hoặc 5 chữ cái:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes thường là các bảng chữ cái thay thế; hãy tìm kiếm "futhark cipher" và thử các bảng ánh xạ.

## Nén trong các thử thách

### Kỹ thuật

Nén liên tục xuất hiện như một lớp bổ sung (zlib/deflate/gzip/xz/zstd), đôi khi được lồng nhiều lớp. Nếu đầu ra gần như phân tích được nhưng trông như dữ liệu rác, hãy nghi ngờ có nén.

### Nhận diện nhanh

- `file <blob>`
- Tìm các byte magic:
  - gzip: `1f 8b`
  - zlib: thường là `78 01`, `78 5e`, `78 9c` hoặc `78 da` (byte thứ hai phụ thuộc vào các cờ nén)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef có **Raw Deflate/Raw Inflate**, thường là cách nhanh nhất khi blob trông như đã được nén nhưng `zlib` không hoạt động.

### CLI hữu ích

```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
  try:
    print(zlib.decompress(data, wbits=wbits)[:200])
  except Exception:
    pass
PY
```

## Các cấu trúc crypto thường gặp trong CTF

### Kỹ thuật

Các cấu trúc này thường xuất hiện vì chúng phản ánh những lỗi thực tế của nhà phát triển hoặc việc sử dụng sai các thư viện phổ biến. Mục tiêu thường là nhận diện và áp dụng quy trình trích xuất hoặc tái tạo đã biết.

### Fernet

Gợi ý thường gặp: hai chuỗi Base64 (token + key).

- Bộ giải mã/ghi chú: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Trong Python: `from cryptography.fernet import Fernet`

### Chia sẻ bí mật Shamir

Nếu bạn thấy nhiều share và có nhắc đến ngưỡng `t`, nhiều khả năng đó là Shamir.

- Công cụ tái tạo trực tuyến (chỉ dùng với các share CTF không nhạy cảm).<sup>[[19]](#references)</sup>

### Định dạng OpenSSL có salt

CTF đôi khi cung cấp đầu ra từ `openssl enc` (header thường bắt đầu bằng `Salted__`).

Các công cụ hỗ trợ brute-force:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Bộ công cụ tổng quát

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Thiết lập cục bộ được đề xuất

Bộ công cụ CTF thực tế:

- Python cùng `pycryptodome` cho các primitive đối xứng và tạo mẫu nhanh.<sup>[[25]](#references)</sup>
- SageMath cho số học mô-đun, CRT, lattice và các bài toán RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 cho các thử thách dựa trên ràng buộc (khi bài toán crypto có thể quy về các ràng buộc).<sup>[[27]](#references)</sup>

Các package Python được đề xuất:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```



## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [tìm kiếm hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [công cụ dCode](https://www.dcode.fr/tools-list)
- [9] [công cụ phá mã Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - công cụ tự động phá Caesar cipher](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [trình giải Vigenère của Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - trình giải mã Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [công cụ dựng lại chia sẻ bí mật Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [tài liệu PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – phá các hệ mã hóa theo cách lười biếng](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
