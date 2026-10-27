# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Hầu hết stego ảnh trong CTF đều thuộc một trong các nhóm sau:

- LSB/bit-planes (PNG/BMP)
- Payload trong metadata/comment
- PNG chunk bất thường / sửa lỗi hỏng
- Công cụ trên miền DCT của JPEG (OutGuess, v.v.)
- Dựa trên frame (GIF/APNG)

## Phân loại nhanh

Ưu tiên kiểm tra bằng chứng ở cấp container trước khi phân tích sâu nội dung:

- Xác thực file và kiểm tra cấu trúc: `file`, `magick identify -verbose`, công cụ xác thực định dạng (ví dụ: `pngcheck`).
- Trích xuất metadata và các chuỗi có thể đọc được: `exiftool -a -u -g1`, `strings`.
- Kiểm tra nội dung được nhúng/nối thêm: `binwalk` và kiểm tra cuối file (`tail | xxd`).
- Chọn hướng theo container:
  - PNG/BMP: bit-planes/LSB và bất thường ở cấp chunk.
  - JPEG: metadata + công cụ trên miền DCT (các họ kiểu OutGuess/F5).
  - GIF/APNG: trích xuất frame, so sánh sai khác giữa các frame, thủ thuật palette.

## Bit-planes / LSB

### Kỹ thuật

PNG/BMP phổ biến trong CTF vì cách lưu pixel giúp **thao tác ở cấp bit** trở nên dễ dàng. Cơ chế ẩn/trích xuất kinh điển là:

- Mỗi kênh pixel (R/G/B/A) có nhiều bit.
- **Bit ít quan trọng nhất** (LSB) của mỗi kênh chỉ làm thay đổi hình ảnh rất ít.
- Attacker giấu dữ liệu trong các bit bậc thấp đó, đôi khi dùng bước nhảy, hoán vị hoặc lựa chọn kênh riêng.

Những điều cần lưu ý trong các thử thách:

- Payload chỉ nằm trong một kênh (ví dụ: LSB của `R`).
- Payload nằm trong kênh alpha.
- Payload được nén/mã hóa sau khi trích xuất.
- Thông điệp được trải trên nhiều plane hoặc được ẩn bằng XOR giữa các plane.

Các nhóm khác bạn có thể gặp (tùy cách triển khai):

- **LSB matching** (không chỉ lật bit mà còn điều chỉnh +/-1 để khớp bit đích)
- **Ẩn dựa trên palette/index** (PNG/GIF dạng indexed: payload nằm trong chỉ số màu thay vì RGB thô)
- **Payload chỉ trong alpha** (hoàn toàn không nhìn thấy khi xem RGB)

### Công cụ

#### zsteg

`zsteg` liệt kê nhiều mẫu trích xuất LSB/bit-plane cho PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: chạy một loạt phép biến đổi (metadata, biến đổi ảnh, brute forcing các biến thể LSB).
- `stegsolve`: các bộ lọc trực quan để kiểm tra thủ công (tách kênh, kiểm tra plane, XOR, v.v.).

Tải Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Thủ thuật làm nội dung dễ thấy bằng FFT

FFT không dùng để trích xuất LSB; kỹ thuật này áp dụng khi nội dung được cố ý ẩn trong miền tần số hoặc trong các mẫu tinh vi.

- Bản demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Các công cụ triage trên web thường được dùng trong CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Cấu trúc bên trong PNG: chunk, lỗi hỏng và dữ liệu ẩn

### Kỹ thuật

PNG là định dạng chia thành các chunk. Trong nhiều thử thách, payload được lưu ở cấp container/chunk thay vì trong giá trị pixel:

- **Byte thừa sau `IEND`** (nhiều trình xem bỏ qua các byte ở cuối)
- **Các chunk phụ trợ không chuẩn** chứa payload; xem [quy trình duyệt chunk PNG và trích xuất dữ liệu](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Header bị hỏng** làm ẩn kích thước hoặc khiến parser gặp lỗi cho đến khi được sửa

Các vị trí chunk cần ưu tiên kiểm tra:

- `tEXt` / `iTXt` / `zTXt` (metadata văn bản, đôi khi được nén)
- `iCCP` (ICC profile) và các chunk phụ trợ khác được dùng làm vật mang dữ liệu
- `eXIf` (dữ liệu EXIF trong PNG)

### Lệnh triage

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Cần tìm gì:

- Các tổ hợp width/height/bit-depth/colour-type bất thường
- Lỗi CRC/chunk (pngcheck thường chỉ rõ offset chính xác)
- Cảnh báo về dữ liệu bổ sung sau `IEND`

Nếu cần xem chi tiết hơn về chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Tài liệu tham khảo hữu ích:

- Đặc tả PNG (cấu trúc, chunk): https://www.w3.org/TR/PNG/
- Thủ thuật định dạng tệp (các trường hợp đặc biệt của PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, công cụ trên miền DCT và hạn chế của ELA

### Kỹ thuật

JPEG không được lưu dưới dạng pixel thô; nó được nén trong miền DCT. Đó là lý do các công cụ stego cho JPEG khác với công cụ LSB cho PNG:

- Payload metadata/comment nằm ở cấp tệp (dễ nhận biết và kiểm tra nhanh)
- Công cụ stego trên miền DCT nhúng bit vào các hệ số tần số

Về mặt vận hành, hãy xem JPEG là:

- Một container chứa các phân đoạn metadata (dễ nhận biết và kiểm tra nhanh)
- Một miền tín hiệu đã nén (các hệ số DCT), nơi các công cụ stego chuyên dụng hoạt động

### Kiểm tra nhanh

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Vị trí có tín hiệu rõ:

- Metadata EXIF/XMP/IPTC
- Segment comment JPEG (`COM`)
- Các segment ứng dụng (`APP1` cho EXIF, `APPn` cho dữ liệu của nhà cung cấp)

### Công cụ phổ biến

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Nếu bạn đang xử lý payload steghide trong JPEG, hãy cân nhắc dùng `stegseek` (bruteforce nhanh hơn các script cũ):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA làm nổi bật các tạo tác nén lại khác nhau; phương pháp này có thể chỉ ra các vùng đã bị chỉnh sửa, nhưng bản thân nó không phải là công cụ phát hiện stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Ảnh động

### Kỹ thuật

Với ảnh động, hãy giả định thông điệp:

- Nằm trong một khung hình duy nhất (dễ), hoặc
- Được phân bố qua nhiều khung hình (thứ tự rất quan trọng), hoặc
- Chỉ hiển thị khi bạn lấy hiệu giữa các khung hình liên tiếp

### Trích xuất các khung hình

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Sau đó xử lý các frame như PNG thông thường: `zsteg`, `pngcheck`, cô lập kênh.

Các công cụ thay thế:

- `gifsicle --explode anim.gif` (trích xuất frame nhanh)
- `imagemagick`/`magick` để biến đổi từng frame

So sánh sai khác giữa các frame thường mang tính quyết định:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Mã hóa bằng số lượng pixel APNG

- Phát hiện container APNG: `exiftool -a -G1 file.png | grep -i animation` hoặc `file`.
- Trích xuất frame mà không thay đổi thời gian: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

Các thử thách dạng ảnh động có thể mã hóa mỗi byte thành số lượng của một màu cụ thể trong mỗi khung hình; nối các số lượng này lại sẽ khôi phục thông điệp.<sup>[[1]](#references)</sup>

## Nhúng được bảo vệ bằng mật khẩu

Nếu bạn nghi ngờ dữ liệu được nhúng bằng cụm mật khẩu thay vì chỉnh sửa ở cấp pixel, đây thường là cách nhanh nhất.

### steghide

Hỗ trợ `JPEG, BMP, WAV, AU` và có thể nhúng/trích xuất dữ liệu được mã hóa.

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

- [1] [Flagvent 2025 (Trung bình) — màu hồng, Danh sách mong ước của Santa, Siêu dữ liệu Giáng sinh, Nhiễu được ghi lại](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
