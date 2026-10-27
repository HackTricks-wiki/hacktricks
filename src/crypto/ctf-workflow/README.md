# Quy trình Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Danh sách kiểm tra phân loại

1. Xác định bạn đang có gì: encoding, encryption, hash, signature hay MAC.
2. Xác định những gì có thể kiểm soát: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Phân loại: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Thử các bước có xác suất thành công cao nhất trước: giải mã các lớp, known-plaintext XOR, nonce reuse, mode misuse, hành vi của oracle.
5. Chỉ chuyển sang các phương pháp nâng cao khi cần: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Tài nguyên trực tuyến & tiện ích

Những tài nguyên này hữu ích khi cần nhận diện và bóc tách các lớp, hoặc xác nhận nhanh một giả thuyết.

### Tra cứu hash

- Tìm kiếm hash của challenge nếu biết hash đó là dữ liệu tổng hợp/công khai.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Tìm kiếm trên hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Không gửi hash mật khẩu thật hoặc dữ liệu challenge mật cho dịch vụ tra cứu của bên thứ ba. Nếu lo ngại về việc tiết lộ dữ liệu, điều khoản dịch vụ hoặc quy định cuộc thi, hãy ưu tiên tấn công wordlist/rule ngoại tuyến.

### Công cụ hỗ trợ nhận diện

- CyberChef (Magic, giải mã và chuyển đổi).<sup>[[7]](#references)</sup>
- dCode (công cụ thử nghiệm cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (công cụ giải substitution).<sup>[[9]](#references)</sup>

### Nền tảng luyện tập / tài liệu tham khảo

- CryptoHack (các challenge cryptography thực hành).<sup>[[10]](#references)</sup>
- Cryptopals (các cạm bẫy kinh điển của modern cryptography).<sup>[[11]](#references)</sup>

### Tự động giải mã

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (thử nhiều base/encoding).<sup>[[13]](#references)</sup>

## Encoding & cipher cổ điển

### Kỹ thuật

Nhiều bài crypto CTF sử dụng các phép biến đổi lồng nhau: base encoding + substitution đơn giản + compression. Mục tiêu là nhận diện các lớp và bóc tách chúng một cách an toàn.

### Encoding: thử nhiều base

Nếu nghi ngờ encoding nhiều lớp (base64 → base32 → …), hãy thử:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Các dấu hiệu thường gặp:

- Base64: `A-Za-z0-9+/=` (thường có padding `=`)
- Base32: `A-Z2-7=` (thường có nhiều padding `=`)
- Ascii85/Base85: nhiều dấu câu; đôi khi được bao bởi `<~ ~>`

### Substitution / monoalphabetic

- Công cụ giải cryptogram của Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Công cụ phá Caesar cipher tự động của Nayuki.<sup>[[15]](#references)</sup>
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

Rune thường là các bảng chữ cái thay thế; hãy tìm kiếm "futhark cipher" và thử các bảng ánh xạ.

## Nén trong thử thách

### Kỹ thuật

Nén thường xuyên xuất hiện như một lớp bổ sung (zlib/deflate/gzip/xz/zstd), đôi khi lồng nhau. Nếu đầu ra gần như phân tích được nhưng trông như dữ liệu rác, hãy nghi ngờ có nén.

### Nhận diện nhanh

- `file <blob>`
- Tìm magic bytes:
  - gzip: `1f 8b`
  - zlib: thường là `78 01`, `78 5e`, `78 9c` hoặc `78 da` (byte thứ hai phụ thuộc vào các cờ nén)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef có **Raw Deflate/Raw Inflate**, thường là cách nhanh nhất khi blob trông như đã được nén nhưng `zlib` không xử lý được.

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

### Technique

Những cấu trúc này xuất hiện thường xuyên vì chúng bắt nguồn từ các lỗi phổ biến của developer hoặc việc sử dụng sai các thư viện thông dụng. Mục tiêu thường là nhận diện và áp dụng quy trình trích xuất hoặc tái dựng đã biết.

### Fernet

Gợi ý thường gặp: hai chuỗi Base64 (token + key).

- Decoder/ghi chú: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Trong Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Nếu bạn thấy nhiều shares và có nhắc đến ngưỡng `t`, nhiều khả năng đó là Shamir.

- Công cụ tái dựng trực tuyến (chỉ dành cho shares CTF không nhạy cảm).<sup>[[19]](#references)</sup>

### Định dạng OpenSSL có salt

Đôi khi CTF cung cấp đầu ra từ `openssl enc` (header thường bắt đầu bằng `Salted__`).

Công cụ hỗ trợ brute force:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Bộ công cụ tổng quát

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Thiết lập môi trường local được đề xuất

Bộ công cụ CTF thực tế:

- Python cùng `pycryptodome` cho các primitive đối xứng và tạo mẫu nhanh.<sup>[[25]](#references)</sup>
- SageMath cho số học modulo, CRT, lattice và các bài toán RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 cho các thử thách dựa trên ràng buộc (khi bài toán crypto có thể được quy về các ràng buộc).<sup>[[27]](#references)</sup>

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
- [6] [Bộ công cụ Hash](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [công cụ dCode](https://www.dcode.fr/tools-list)
- [9] [công cụ giải mã của Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - công cụ tự động giải mã Caesar](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - mật mã Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [trình giải Vigenère của Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - trình giải mã Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [công cụ khôi phục chia sẻ bí mật Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [tài liệu PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
