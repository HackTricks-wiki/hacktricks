# Mẹo với ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Các công cụ dòng lệnh** để quản lý **tệp zip** rất cần thiết khi chẩn đoán, sửa chữa và bẻ khóa tệp zip. Sau đây là một số tiện ích chính:<sup>[[1]](#references)</sup>

- **`unzip`**: Cho biết lý do tệp zip có thể không giải nén được.
- **`zipdetails -v`**: Phân tích chi tiết các trường định dạng tệp zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Liệt kê nội dung tệp zip mà không giải nén.
- **`zip -F input.zip --out output.zip`** và **`zip -FF input.zip --out output.zip`**: Thử sửa các tệp zip bị hỏng.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Công cụ thực hiện tấn công từ điển và brute-force mật khẩu ZIP; tính khả thi phụ thuộc vào không gian tìm kiếm mật khẩu.<sup>[[15]](#references)</sup>

[Đặc tả định dạng tệp Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) cung cấp thông tin toàn diện về cấu trúc và tiêu chuẩn của tệp zip.<sup>[[4]](#references)</sup>

Các tệp ZIP truyền thống được bảo vệ bằng mật khẩu thường để lộ tên tệp và kích thước tệp, không giống các chế độ mã hóa header được RAR và 7z hỗ trợ. Tấn công known-plaintext ZipCrypto khôi phục **các khóa mã hóa nội bộ**, không nhất thiết là mật khẩu ban đầu; các khóa này đủ để giải mã những mục được mã hóa bằng cùng mật khẩu.<sup>[[13]](#references)</sup> Tấn công này cần biết các byte của luồng **trước khi mã hóa**: với một mục được lưu trữ, đó là byte của tệp gốc; nhưng với mục DEFLATE, đó là các byte đã nén, có thể cần tái tạo chính xác kết quả nén.<sup>[[13]](#references)[[14]](#references)</sup> Xem [Tấn công ZIP known plaintext](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) để biết quy trình thực hiện. Để tìm hiểu nền tảng mật mã học, xem [bài báo](https://math.ucr.edu/~mike/zipattacks.pdf) và [hướng dẫn từng bước](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Tấn công ZipCrypto này không áp dụng cho các mục ZIP được mã hóa bằng AES.<sup>[[13]](#references)</sup>

---

## Thủ thuật chống dịch ngược trong APK bằng cách thao túng header ZIP

Các malware dropper Android hiện đại sử dụng metadata ZIP không hợp lệ để khiến các công cụ phân tích tĩnh (jadx/apktool/unzip) gặp lỗi, trong khi APK vẫn có thể cài đặt trên thiết bị. Các thủ thuật phổ biến nhất gồm:<sup>[[2]](#references)</sup>

- Giả mã hóa bằng cách đặt bit 0 của ZIP General Purpose Bit Flag (GPBF)
- Lạm dụng các trường Extra lớn/tùy chỉnh để gây nhầm lẫn cho parser
- Tên tệp/thư mục trùng nhau để che giấu artifact thật (ví dụ: thư mục tên `classes.dex/` nằm cạnh `classes.dex` thật)

### 1) Giả mã hóa (đặt bit 0 của GPBF) mà không mã hóa thật

Triệu chứng:
- `jadx-gui` gặp lỗi như:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` yêu cầu mật khẩu đối với các tệp cốt lõi của APK, mặc dù APK hợp lệ không thể mã hóa `classes*.dex`, `resources.arsc` hoặc `AndroidManifest.xml`:
  
  ```bash
  unzip sample.apk
  [sample.apk] classes3.dex password:
    skipping: classes3.dex                          incorrect password
    skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
    skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
    skipping: classes2.dex                          incorrect password
  ```

Phát hiện bằng zipdetails:

```bash
zipdetails -v sample.apk | less
```

Kiểm tra General Purpose Bit Flag trong local header và central header. Một giá trị đáng chú ý là bit 0 được bật (Encryption), kể cả với các entry cốt lõi:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heuristic: Nếu một APK cài đặt và chạy trên thiết bị nhưng các mục cốt lõi lại hiển thị là "được mã hóa" trong các công cụ, thì GPBF đã bị can thiệp.

Khắc phục bằng cách xóa bit 0 của GPBF trong cả Local File Headers (LFH) lẫn các mục Central Directory (CD). Bộ sửa byte tối giản:

<details>
<summary>Bộ sửa tối giản để xóa bit GPBF</summary>

```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
    out = bytearray(buf)
    i = 0
    patched = 0
    while True:
        i = out.find(sig, i)
        if i == -1:
            break
        flags, = struct.unpack_from('<H', out, i + flag_off)
        if flags & 1:  # encryption bit set
            struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
            patched += 1
        i += 4  # move past signature to continue search
    return bytes(out), patched

if __name__ == '__main__':
    inp, outp = sys.argv[1], sys.argv[2]
    data = open(inp, 'rb').read()
    data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
    data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
    open(outp, 'wb').write(data)
    print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```

</details>

Cách sử dụng:

```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```

Chỉ bit 0 được thay đổi: ví dụ, `0A09` trở thành `0A08`, không phải `0000`. Patcher tối giản này quét các signature header trong raw bytes, vì vậy các byte giống signature bên trong dữ liệu file có thể gây khớp nhầm; hãy thao tác trên một bản sao và xác nhận danh sách entry cùng các header trước khi sử dụng đầu ra.<sup>[[4]](#references)</sup>

### 2) Các trường Extra lớn/tùy chỉnh để làm parser gặp lỗi

Attacker nhồi các trường Extra quá lớn và ID bất thường vào header để khiến decompiler gặp lỗi. Trong thực tế, bạn có thể thấy các marker tùy chỉnh (ví dụ: các chuỗi như `JADXBLOCK`) được nhúng ở đó.

Kiểm tra:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Các ví dụ được ghi nhận: ID lạ như `0xCAFE` ("Java Executable") hoặc `0x414A` ("JA:") chứa payload lớn.<sup>[[2]](#references)</sup>

Heuristics DFIR:
- Cảnh báo khi các trường Extra có kích thước bất thường trên những mục cốt lõi (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Xem các ID Extra không xác định trên những mục đó là đáng ngờ.

Biện pháp giảm thiểu thiết thực: dựng lại archive (ví dụ: nén lại các tệp đã giải nén) để loại bỏ các trường Extra độc hại. Nếu công cụ từ chối giải nén do mã hóa giả, trước tiên hãy xóa bit 0 của GPBF như trên, rồi đóng gói lại:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Xung đột tên file/thư mục (che giấu hiện vật thật)

Một ZIP có thể chứa cả file `X` và thư mục `X/`. Một số trình giải nén và trình dịch ngược có thể bị nhầm lẫn, khiến mục thư mục ghi đè hoặc che khuất file thật. Điều này đã được ghi nhận với các mục xung đột tên với những tên APK cốt lõi như `classes.dex`.

Phân loại và giải nén an toàn:

```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```

Phát hiện bằng lập trình sau khi sửa:

```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
    names = z.namelist()

collisions = defaultdict(list)
for n in names:
    base = n[:-1] if n.endswith('/') else n
    collisions[base].append(n)

for base, variants in collisions.items():
    if len(variants) > 1:
        print('COLLISION', base, '->', variants)
```

Ý tưởng phát hiện của blue team:
- Đánh dấu các APK có local header ghi nhận mã hóa (GPBF bit 0 = 1) nhưng vẫn cài đặt/chạy được.
- Đánh dấu các Extra field lớn/không xác định trong các entry cốt lõi (tìm các marker như `JADXBLOCK`).
- Đánh dấu các đường dẫn bị trùng lặp (`X` và `X/`), đặc biệt với `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Các thủ thuật ZIP độc hại khác (2024–2026)

### Nối các central directory (né tránh bằng nhiều EOCD)

Trong một chiến dịch phishing năm 2024, kẻ tấn công phát tán một blob duy nhất, thực chất là **hai file ZIP được nối với nhau**. Mỗi file có bản ghi End of Central Directory (EOCD) và central directory riêng. Các công cụ giải nén khác nhau phân tích các directory khác nhau (7-Zip đọc directory đầu tiên, còn WinRAR đọc directory cuối cùng), cho phép kẻ tấn công ẩn payload mà chỉ một số công cụ hiển thị; các trình quét chỉ kiểm tra một directory có thể bỏ sót archive còn lại.<sup>[[5]](#references)[[6]](#references)</sup>

**Lệnh phân loại sơ bộ**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Nếu có nhiều EOCD hoặc cảnh báo "data after payload", hãy tách blob và kiểm tra từng phần:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs (không đệ quy)

Quoted-overlap ZIP bombs tạo một **kernel** nhỏ (một khối DEFLATE được nén mạnh) rồi tái sử dụng nó trong các entry chồng lấn. Các biến thể Full-overlap trỏ nhiều entry trong central directory đến cùng một local header, còn các biến thể quoted-overlap trích dẫn local header bên trong các luồng DEFLATE; cấu trúc được công bố đạt tỷ lệ hơn 28M:1 mà không cần archive lồng nhau.<sup>[[7]](#references)</sup>

**Phát hiện nhanh (offset LFH trùng lặp)**

```python
# detect full-overlap variants by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
    i = buf.find(b'PK\x01\x02', off)
    if i<0: break
    rel = struct.unpack_from('<I', buf, i+42)[0]
    if rel in seen:
        print('OVERLAP at offset', rel)
        break
    seen.add(rel); off = i+4
```

**Xử lý**
- Thực hiện một lượt kiểm tra dry-run: `zipdetails -v file.zip | grep -n "Local Header Offset"` rồi so sánh các offset local-header được tham chiếu và phạm vi dữ liệu đã nén; các offset trùng nhau là dấu hiệu của biến thể full-overlap.<sup>[[7]](#references)[[8]](#references)</sup>
- Dùng parser giới hạn tổng kích thước sau giải nén và số lượng entry được chấp nhận trước khi giải nén; `zipinfo -t file.zip` báo cáo tổng nhưng không áp dụng giới hạn an toàn.<sup>[[8]](#references)</sup>
- Khi bắt buộc phải giải nén, hãy thực hiện bên trong cgroup/VM có giới hạn CPU và dung lượng đĩa (tránh sự cố do giải nén không giới hạn).<sup>[[8]](#references)</sup>

---

### Lỗi nhầm lẫn giữa parser local-header và central-directory

Nghiên cứu parser differential gần đây cho thấy sự nhập nhằng của ZIP vẫn có thể bị khai thác trong các toolchain hiện đại. Ý tưởng chính rất đơn giản: một số phần mềm tin vào **Local File Header (LFH)**, trong khi phần mềm khác tin vào **Central Directory (CD)**, nên cùng một archive có thể hiển thị tên file, đường dẫn, chú thích, offset hoặc tập entry khác nhau cho các công cụ khác nhau.<sup>[[9]](#references)</sup>

Các cách sử dụng tấn công thực tế:
- Khiến bộ lọc upload, bước quét trước của AV hoặc trình xác thực package thấy một file vô hại trong CD, trong khi trình giải nén lại tuân theo tên/đường dẫn LFH khác.
- Lợi dụng tên trùng lặp, entry chỉ có trong một cấu trúc hoặc metadata đường dẫn Unicode nhập nhằng (ví dụ, Info-ZIP Unicode Path Extra Field `0x7075`) để các parser khác nhau dựng lại cây thư mục khác nhau.
- Kết hợp cách này với path traversal để biến chế độ xem archive "vô hại" thành primitive ghi trong lúc giải nén. Xem [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) để biết về phía giải nén.

Phân loại DFIR:

```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
    n, e = struct.unpack_from('<HH', b, i + 26)
    lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
    i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
    n = struct.unpack_from('<H', b, i + 28)[0]
    off = struct.unpack_from('<I', b, i + 42)[0]
    cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
    if off in lfh and cd != lfh[off]:
        print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
    i += 4
```

Bổ sung thêm với:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Heuristics:
- Với hoạt động tiếp nhận dữ liệu nhạy cảm về bảo mật, hãy từ chối hoặc cách ly các archive có tên LFH/CD không khớp nhau, tên tệp trùng lặp, nhiều bản ghi EOCD hoặc dữ liệu thừa sau EOCD cuối cùng.<sup>[[9]](#references)[[10]](#references)</sup>
- Hãy xem các ZIP sử dụng extra field đường dẫn Unicode bất thường hoặc comment không nhất quán là đáng ngờ nếu các công cụ khác nhau cho kết quả cây tệp được giải nén khác nhau.<sup>[[4]](#references)[[9]](#references)</sup>
- Nếu việc phân tích quan trọng hơn việc giữ nguyên các byte gốc, hãy giải nén archive trong sandbox, rồi đóng gói lại bằng parser nghiêm ngặt và so sánh danh sách tệp thu được với metadata ban đầu.

Điều này không chỉ quan trọng với các hệ sinh thái package: cùng một kiểu nhập nhằng có thể che giấu payload khỏi mail gateway, scanner tĩnh và các pipeline tiếp nhận dữ liệu tùy chỉnh vốn “xem lướt” nội dung ZIP trước khi một trình giải nén khác xử lý archive.<sup>[[9]](#references)</sup>

---





## References

- [1] [Cẩm nang thực địa về pháp y CTF (Blog của Mike, danh mục CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Phần 1 – Dropper nhiều giai đoạn (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Đặc tả định dạng tệp ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Cấu trúc linh hoạt của archive Zip bị khai thác để che giấu malware mà không bị phát hiện (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hacker giấu malware trong cuộc tấn công bằng tệp ZIP mới — các central directory ZIP được nối lại](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Một zip bomb tốt hơn (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Tìm hiểu về Zip Bomb: cấu trúc kernel chồng lấp/chồng lấp được trích dẫn](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [ZIP của tôi không phải ZIP của bạn: Nhận diện và khai thác khoảng cách ngữ nghĩa giữa các ZIP parser (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Ngăn chặn các cuộc tấn công gây nhầm lẫn ZIP parser nhắm vào trình cài đặt package Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Các cuộc tấn công ZIP với lượng plaintext đã biết ít hơn (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Nhiệm vụ Web thực tế, Cấp độ 15 (tấn công ZIP với plaintext đã biết)](https://www.hackthissite.org/articles/read/793)
- [13] [Cách sử dụng bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [Hướng dẫn tấn công bkcrack với plaintext đã biết](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [Kho lưu trữ fcrackzip](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
