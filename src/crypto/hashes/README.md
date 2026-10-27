# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Các mẫu CTF thường gặp

- "Signature" thực chất là `hash(secret || message)` → length extension.
- Hash mật khẩu không có salt → crack lặp lại nhanh hơn và dễ bị tấn công tra cứu bằng dữ liệu tính trước.
- Nhầm lẫn giữa hash và MAC (hash != xác thực).

## Tìm kiếm hash MD5 với đầu vào được chọn

Các ví dụ Python này tìm hai mẫu đầu ra khác nhau: hậu tố MD5 được chọn và giá trị MD5 bắt đầu bằng `0e`, theo sau chỉ là các chữ số. Mẫu thứ hai liên quan khi ứng dụng so sánh lỏng các chuỗi số; xem hành vi riêng của PHP và các lưu ý về phiên bản trong [so sánh lỏng của PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force hậu tố hash MD5

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Tạo hash MD5 0e để so sánh lỏng lẻo

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Kỹ thuật

Tấn công length-extension có thể xảy ra khi máy chủ tính một "chữ ký" như:

`sig = HASH(secret || message)`

và sử dụng hàm băm Merkle-Damgård như MD5, SHA-1 hoặc SHA-256.

Nếu biết:

- `message`
- `sig`
- hàm băm
- (hoặc có thể brute-force) `len(secret)`

thì bạn có thể tính chữ ký hợp lệ cho:

`message || padding || appended_data`

mà không cần biết secret.<sup>[[1]](#references)</sup>

### Hạn chế quan trọng: HMAC không bị ảnh hưởng

Tấn công length-extension áp dụng cho các cấu trúc tiền tố dễ bị tấn công như `HASH(secret || message)`. Chúng không làm lộ cấu trúc HMAC (ví dụ: HMAC-SHA256), vốn kết hợp một key với các lần áp dụng hàm băm riêng biệt ở bên trong và bên ngoài.<sup>[[1]](#references)[[2]](#references)</sup>

Để biết cách tìm và kiểm tra các chữ ký này trong web API, xem [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Công cụ

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings Python cho công cụ length-extension HashPump<sup>[[7]](#references)</sup>

### Giải thích hay

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Băm tuple không phân biệt ranh giới và MAC

### Boundary-confusion attack

Các API hash tăng dần không xác thực ranh giới giữa các lần gọi. `update(A); update(B)` băm cùng một chuỗi byte như `update(A + B)`. Do đó, việc băm hoặc tạo MAC từ phép nối thô không xác thực được một tuple. Nếu các trường liền kề có độ dài thay đổi, kẻ tấn công có thể phân chia lại các byte thành một tuple khác mà không cần tìm collision trong hàm băm nền tảng:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Điều này trở nên có thể khai thác khi verifier cho rằng digest ràng buộc ý nghĩa của các trường, nhưng dữ liệu đầu vào do attacker kiểm soát có thể đi đến một parser hoặc bước giao thức khác, nơi các ranh giới được xác định khác đi. Commitments có thể có các cách mở khác, còn các transcript Fiat-Shamir có thể được diễn giải thành những statement khác. HMAC ngăn [hash length extension](#hash-length-extension-attack), nhưng `HMAC(K, A || B)` vẫn có sự mơ hồ về mã hóa tuple này vì cả hai tuple đều tạo ra cùng một chuỗi byte thông điệp.<sup>[[8]](#references)[[9]](#references)</sup>

Dùng quy trình audit này để kiểm tra xem việc mã hóa tuple mơ hồ có vượt qua ranh giới bảo mật hay không.<sup>[[8]](#references)[[9]](#references)</sup>

1. Tìm `HASH(A || B)`, `HMAC(K, A || B)` và các lệnh gọi `update()`/`Write()` liên tiếp trên hai trường trở lên.
2. Đánh dấu mọi trường do attacker kiểm soát hoặc có độ dài thay đổi. Thử chuyển byte qua từng ranh giới trong khi giữ nguyên toàn bộ chuỗi nối. Bao gồm cả các trường rỗng.
3. Kiểm tra các phương thức phân cách để tìm byte phân cách mà đầu vào có thể chứa, sự không nhất quán trong xử lý escape và các thiết kế chỉ mã hóa độ dài cho một số trường.
4. Truy vết cách mọi consumer phân tích cú pháp các byte đã được xác thực. Một trường hợp tiềm năng chỉ có ý nghĩa nếu cách phân chia khác làm thay đổi quyết định bảo mật, proof statement, bản ghi, giao dịch hoặc cách mở commitment. Các trường có độ dài cố định hoặc serialization chuẩn tắc, đơn ánh sẽ ngăn chặn cuộc tấn công cụ thể này.
5. Kiểm tra xem cùng một digest đã mã hóa có được chấp nhận trong phiên bản giao thức, loại thông điệp, vòng hoặc ứng dụng khác hay không. Ràng buộc rõ ràng các ngữ cảnh này thay vì dựa vào caller để giữ chúng tách biệt.

### SequenceHash và SequenceMAC

SequenceHash là một cấu trúc không phụ thuộc vào hash dành cho các chuỗi byte. Mỗi thao tác `add()` là nguyên tử: nó thêm giá trị cùng một hậu tố độ dài cố định 16 byte, theo thứ tự little-endian, vào inner hash. Các giá trị rỗng vẫn là những đối tượng riêng biệt. Một outer hash ngăn việc làm lộ trạng thái inner có thể mở rộng độ dài, còn chuỗi tùy chỉnh tùy chọn cung cấp domain separation. Không thay `add()` bằng các lệnh ghi thông thường của API hash nền.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Chọn customizer như một phần của định nghĩa giao thức, bao gồm đủ thông tin để phân biệt ứng dụng, phiên bản giao thức, loại thông điệp và vòng. SequenceHash vẫn yêu cầu tất cả các bên thống nhất về thứ tự trường, cách mã hóa byte và cách tuần tự hóa chuẩn tắc, đồng thời không thể bảo vệ trường bị bỏ sót. Cần kiểm tra các bản triển khai bằng bộ test vector trung gian và cuối cùng của C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Để xác thực, SequenceMAC cung cấp cùng giao diện mã hóa nguyên tử và tùy chỉnh. Khóa phải dài ít nhất 32 byte. Không giống bước tiền xử lý khóa của HMAC, phần header của nó cam kết với độ dài chính xác của khóa: khóa thô dài không tương đương với giá trị băm trước của khóa, và việc thêm byte 0 sẽ làm thay đổi khóa. Sự khác biệt này quan trọng khi các thành phần chấp nhận những dạng biểu diễn khóa hoặc metadata về độ dài khác nhau.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API cùng các bản triển khai tương đương bằng Go và Rust được cung cấp làm tài liệu tham khảo, nhưng các bản triển khai giao thức nên tuân theo đặc tả C2SP hiện hành thay vì dựng lại cách mã hóa dựa trên phần tóm tắt này.<sup>[[8]](#references)[[10]](#references)</sup>

## Băm mật khẩu và crack

### Các câu hỏi đầu tiên<sup>[[4]](#references)</sup>

- Có **salt** không? (tìm các định dạng `salt$hash`)
- Đây là **hash nhanh** (MD5/SHA1/SHA256) hay **KDF chậm** (bcrypt/scrypt/argon2/PBKDF2)?
- Bạn có **gợi ý về định dạng** không (chế độ hashcat / định dạng John)?

### Quy trình thực tế<sup>[[5]](#references)[[6]](#references)</sup>

1. Xác định hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Nếu không có salt và là loại phổ biến: thử tra cứu trong các DB trực tuyến và dùng công cụ nhận diện trong phần quy trình làm việc với crypto.
3. Nếu không, hãy crack:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Các lỗi thường gặp có thể khai thác

- Nhiều người dùng dùng lại cùng một mật khẩu → crack một tài khoản rồi pivot.
- Hash bị cắt cụt / phép biến đổi tùy chỉnh → chuẩn hóa rồi thử lại.
- Tham số KDF yếu (ví dụ: số vòng PBKDF2 thấp) → vẫn có thể crack.

### Oracle bcrypt với đầu vào tùy chọn và secret được nối thêm

Một helper có thể gọi được, trả về `bcrypt(user_input || secret)`, có thể làm lộ thông tin về secret được nối thêm nếu bản triển khai bcrypt âm thầm cắt cụt đầu vào sau 72 **byte**. Giới hạn số ký tự trước khi mã hóa UTF-8 không đảm bảo giới hạn byte đó: các ký tự nhiều byte có thể chiếm hết phần đầu vào bcrypt, chỉ chừa chỗ cho một tiền tố ngắn của secret. Khi đó, các đầu vào tùy chọn cùng hash trả về có thể cho phép kiểm tra offline các byte hậu tố ứng viên. Điều này đòi hỏi bạn kiểm soát được đầu vào của helper, biết chính xác phép biến đổi và cách mã hóa mà nó dùng, đồng thời bản triển khai thực sự có cắt cụt; chỉ riêng việc có một helper gọi được hoặc một hash bcrypt không chứng minh được chuỗi điều kiện này. [pyca/bcrypt ghi rõ](https://github.com/pyca/bcrypt#maximum-password-length) rằng `hashpw` hiện tại báo lỗi với đầu vào dài hơn 72 byte, trong khi các phiên bản trước âm thầm cắt cụt đầu vào. Các wrapper khác có thể băm trước hoặc từ chối đầu vào dài, vì vậy hãy xác minh bản triển khai đã cài đặt thay vì mặc định rằng nó sẽ cắt cụt.

Để dùng secret đã khôi phục cho một tài khoản khác, cũng cần có bằng chứng rằng hash bị lộ của tài khoản đó được tạo bằng **cùng** secret và phép biến đổi, cùng với một thông tin xác thực hoặc đường đăng nhập riêng biệt. Chỉ nên xem helper băm chạy bằng quyền root là một oracle nếu người dùng có quyền thấp hơn có thể gọi nó theo chính sách quyền hiện hành; việc liệt kê máy chủ một cách thụ động không nhất thiết phải gọi helper hoặc gửi mật khẩu tùy chọn.

## References

- [1] [SkullSecurity - Mọi điều cần biết về các cuộc tấn công mở rộng độ dài hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Mã xác thực thông điệp bằng hash có khóa](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Bảng hướng dẫn lưu trữ mật khẩu](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - Các hash mẫu](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Các tùy chọn dòng lệnh](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` - Các binding Python cho HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Đặc tả SequenceHash và SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: băm nhiều dữ liệu dành cho tất cả chúng ta](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Bản triển khai SequenceHash bằng Python](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Các vector kiểm thử SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
