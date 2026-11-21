# Steganography trong hình ảnh

{{#include ../../banners/hacktricks-training.md}}

Phần lớn bài stego hình ảnh trong CTF thuộc một trong các nhóm sau:

- LSB/bit-planes (PNG/BMP)
- Payload trong metadata/comment
- Bất thường trong chunk PNG / sửa lỗi hỏng
- Công cụ miền DCT JPEG (OutGuess, v.v.)
- Dựa trên khung hình (GIF/APNG)

## Phân loại nhanh

Ưu tiên kiểm tra bằng chứng ở cấp container trước khi phân tích sâu nội dung. Xem [quy trình stego tổng quát](../workflow/) để nhận diện và carving file trước khi chạy các kiểm tra riêng cho hình ảnh.

- Xác thực file và kiểm tra cấu trúc: `file`, `magick identify -verbose`, công cụ xác thực định dạng (ví dụ: `pngcheck`).
- Trích xuất metadata và chuỗi hiển thị được: `exiftool -a -u -g1`, `strings`.
- Kiểm tra nội dung được nhúng/nối thêm: `binwalk` và kiểm tra cuối file (`tail | xxd`).
- Phân nhánh theo container:
  - PNG/BMP: bit-planes/LSB và các bất thường ở cấp chunk.
  - JPEG: metadata + công cụ miền DCT (các họ kiểu OutGuess/F5).
  - GIF/APNG: trích xuất khung hình, so sánh khác biệt giữa các khung hình, thủ thuật bảng màu.

## Bit-planes / LSB

### Kỹ thuật

PNG/BMP phổ biến trong CTF vì cách lưu trữ pixel giúp **thao tác ở cấp bit** trở nên dễ dàng. Cơ chế ẩn/trích xuất cổ điển là:

- Mỗi kênh pixel (R/G/B/A) có nhiều bit.
- **Bit ít quan trọng nhất** (LSB) của mỗi kênh chỉ làm thay đổi hình ảnh rất ít.
- Attacker ẩn dữ liệu trong các bit bậc thấp đó, đôi khi dùng bước nhảy, hoán vị hoặc lựa chọn kênh riêng.

Những điều thường gặp trong thử thách:

- Payload chỉ nằm trong một kênh (ví dụ: LSB của `R`).
- Payload nằm trong kênh alpha.
- Payload được nén/mã hóa sau khi trích xuất.
- Thông điệp được phân bố trên các plane hoặc ẩn bằng XOR giữa các plane.

Các họ kỹ thuật khác bạn có thể gặp (tùy cách triển khai):

- **LSB matching** (không chỉ lật bit mà còn điều chỉnh +/-1 để khớp bit đích)
- **Ẩn dựa trên palette/index** (PNG/GIF dạng indexed: payload nằm trong chỉ số màu thay vì RGB thô)
- **Payload chỉ trong alpha** (hoàn toàn vô hình khi xem RGB)

### Chỉ số palette màu indexed

PNG hoặc GIF dạng indexed lưu một **chỉ số** palette cho mỗi pixel, chứ không phải bộ ba RGB. Hai chỉ số có thể ánh xạ tới cùng một màu hiển thị, nên chuyển sang RGB trước khi phân tích có thể xóa mất khác biệt ẩn. Kiểm tra các mục palette trùng lặp hoặc gần giống nhau, sau đó dựng mặt nạ nhị phân cho các pixel dùng từng chỉ số đáng ngờ. Cách này đã giúp phát hiện văn bản ẩn và các thay đổi dạng mã QR trong những thử thách GIF gần đây.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Với PNG indexed một khung hình (hoặc **khung hình đầu tiên** của GIF), hãy giữ chế độ `P` của Pillow và đổi `target` thành một chỉ số đáng chú ý được script báo cáo. Khi chọn chỉ số, hãy kiểm tra cả độ trong suốt (`tRNS` hoặc chỉ số trong suốt của GIF) lẫn RGB.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Với GIF động, hãy kiểm tra từng khung hình riêng. Pillow thường chuyển các khung hình sau sang RGB/RGBA trong quá trình ghép; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` chỉ giữ chế độ `P` khi bảng màu không thay đổi. Nếu khung hình có bảng màu cục bộ hoặc đã được ghép, hãy kiểm tra dữ liệu khung hình gốc được lập chỉ mục thay vì coi các pixel đã chuyển đổi sang RGB là chỉ số.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Công cụ

#### zsteg

`zsteg` liệt kê nhiều mẫu trích xuất LSB/bit-plane cho PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: chạy một loạt phép biến đổi (metadata, biến đổi ảnh, brute force các biến thể LSB).
- `stegsolve`: các bộ lọc trực quan để kiểm tra thủ công (tách kênh, kiểm tra plane, XOR, v.v.).

Tải Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Các thủ thuật tăng khả năng hiển thị dựa trên FFT

FFT không phải là trích xuất LSB; nó được dùng trong các trường hợp nội dung được cố ý ẩn trong miền tần số hoặc trong các mẫu tinh vi.

- Bản demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Các công cụ phân tích sơ bộ trên web thường được dùng trong CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Cấu trúc bên trong PNG: chunk, dữ liệu lỗi và dữ liệu ẩn

### Kỹ thuật

PNG là định dạng được chia thành các chunk. Trong nhiều thử thách, payload được lưu ở cấp container/chunk thay vì trong giá trị pixel:

- **Byte thừa sau `IEND`** (nhiều trình xem bỏ qua các byte ở cuối)
- **Các chunk phụ không theo chuẩn** chứa payload; xem [quy trình duyệt chunk và trích xuất dữ liệu PNG](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Header bị hỏng** che giấu kích thước hoặc khiến parser lỗi cho đến khi được sửa

Các vị trí chunk đáng chú ý cần kiểm tra:

- `tEXt` / `iTXt` / `zTXt` (metadata văn bản, đôi khi được nén)
- `iCCP` (ICC profile) và các chunk phụ khác được dùng làm vật mang dữ liệu
- `eXIf` (dữ liệu EXIF trong PNG)

### Byte bộ lọc scanline PNG làm vật mang dữ liệu

PNG lưu một byte loại bộ lọc (0–4) trước mỗi scanline trong luồng `IDAT` đã giải nén. Các byte này không phải giá trị pixel; pixel RGB đã giải mã không giữ lại lựa chọn bộ lọc ban đầu, và việc mã hóa lại có thể thay đổi chúng. Một encoder có thể thay đổi bộ lọc một cách hợp lệ, nhưng các mẫu được tạo có chủ ý có thể mã hóa một thông điệp ngắn; một thử thách gần đây đã dùng các giá trị bộ lọc 1–4 làm ký hiệu hai bit. Hãy kiểm tra **file gốc** và nối toàn bộ dữ liệu `IDAT` trước khi giải nén. Với trường hợp RGB/RGBA 8-bit, không xen kẽ dưới đây, stride bằng chiều rộng nhân với số kênh; ảnh Adam7 cần chiều rộng scanline riêng cho từng pass.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Liệt kê byte bộ lọc scanline PNG mà không mã hóa lại</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Chạy bằng `python3 filters.py suspect.png`. Kiểm tra xem chuỗi bộ lọc, thay vì các pixel đã giải mã, có tuân theo một phép ánh xạ ký hiệu hợp lý hay không. Phép ánh xạ được chọn phụ thuộc vào từng thử thách; chỉ riêng sự biến đổi không phải là bằng chứng của steganography.<sup>[[3]](#references)[[7]](#references)</sup>

### Các lệnh phân loại ban đầu

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Cần chú ý:

- Các tổ hợp width/height/bit-depth/colour-type bất thường
- Lỗi CRC/chunk (pngcheck thường chỉ ra chính xác offset)
- Cảnh báo về dữ liệu bổ sung sau `IEND`

Nếu cần xem chi tiết hơn về chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Tài liệu tham khảo hữu ích:

- Đặc tả PNG (cấu trúc, các chunk): https://www.w3.org/TR/PNG/
- Thủ thuật định dạng tệp (các trường hợp đặc biệt của PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, công cụ miền DCT và hạn chế của ELA

### Kỹ thuật

JPEG không được lưu dưới dạng pixel thô; nó được nén trong miền DCT. Vì vậy, các công cụ stego cho JPEG khác với công cụ PNG LSB:

- Payload trong metadata/comment ở cấp tệp (dễ nhận biết và kiểm tra nhanh)
- Công cụ stego miền DCT nhúng bit vào các hệ số tần số

Khi phân tích, hãy xem JPEG là:

- Một container chứa các phân đoạn metadata (dễ nhận biết, kiểm tra nhanh)
- Một miền tín hiệu đã nén (các hệ số DCT), nơi các công cụ stego chuyên dụng hoạt động

### Kiểm tra nhanh

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Các vị trí có tín hiệu cao:

- Metadata EXIF/XMP/IPTC
- Segment comment JPEG (`COM`)
- Các segment ứng dụng (`APP1` cho EXIF, `APPn` cho dữ liệu của nhà cung cấp)

### Công cụ phổ biến

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Nếu bạn đang xử lý payload steghide trong JPEG, hãy cân nhắc dùng `stegseek` (bruteforce nhanh hơn các script cũ):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA làm nổi bật các dấu vết tái nén khác nhau; nó có thể chỉ ra những vùng đã bị chỉnh sửa, nhưng bản thân nó không phải là công cụ phát hiện stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Ảnh động

### Kỹ thuật

Với ảnh động, hãy giả định thông điệp:

- Nằm trong một frame duy nhất (dễ), hoặc
- Được trải ra qua nhiều frame (thứ tự rất quan trọng), hoặc
- Chỉ hiển thị khi bạn lấy hiệu giữa các frame liên tiếp

### Trích xuất frame

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Sau đó xử lý các frame như PNG thông thường: `zsteg`, `pngcheck`, tách riêng từng kênh.

Các công cụ thay thế:

- `gifsicle --explode anim.gif` (trích xuất frame nhanh)
- `imagemagick`/`magick` để biến đổi từng frame

So sánh sự khác biệt giữa các frame thường mang tính quyết định:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Mã hóa bằng số lượng pixel APNG

- Phát hiện các container APNG: `exiftool -a -G1 file.png | grep -i animation` hoặc `file`.
- Trích xuất các frame mà không thay đổi thời gian: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Khôi phục payload được mã hóa dưới dạng số lượng pixel theo từng frame:

```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
    counts = Image.open(f).getcolors()
    target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
    out.append(target or 0)
print(bytes(out).decode('latin1'))
```

Các thử thách dạng ảnh động có thể mã hóa mỗi byte thành số lượng pixel có một màu cụ thể trong mỗi khung hình; ghép các số lượng này lại sẽ khôi phục thông điệp.<sup>[[1]](#references)</sup>

## Nhúng có bảo vệ bằng mật khẩu

Nếu bạn nghi ngờ nội dung được nhúng bằng passphrase thay vì chỉnh sửa ở cấp pixel, đây thường là cách nhanh nhất.

### steghide

Hỗ trợ `JPEG, BMP, WAV, AU` và có thể nhúng/trích xuất payload đã mã hóa.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Hỗ trợ PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — pink, Danh sách mong ước của Santa, Metadata Giáng sinh, Nhiễu được ghi lại](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [Bài viết hướng dẫn HackVent 2024 — Twisted Colors](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Đặc tả Portable Network Graphics (PNG), Phiên bản thứ ba](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Sâu bên dưới, có thứ gì đó trong nước](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Các định dạng tệp ảnh Pillow — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Đặc tả GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Giao thức Afterimage — bài viết giải CTF](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
