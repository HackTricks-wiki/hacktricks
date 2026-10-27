# Quy trình Stego

{{#include ../../banners/hacktricks-training.md}}

Hầu hết các bài toán stego được giải quyết nhanh hơn bằng cách phân loại có hệ thống thay vì thử ngẫu nhiên các công cụ.

## Quy trình cốt lõi

### Danh sách kiểm tra phân loại nhanh

Mục tiêu là nhanh chóng trả lời hai câu hỏi:

1. Container/định dạng thực sự là gì?
2. Payload nằm trong metadata, các byte được nối thêm, các file nhúng hay stego ở cấp nội dung?

#### 1) Xác định container

```bash
file target
ls -lah target
```

Nếu `file` và phần mở rộng không khớp, hãy kiểm tra chữ ký thay vì tin vào hậu tố. `file` cũng dựa trên heuristic và có thể bị đánh lừa bởi dữ liệu đầu vào sai định dạng hoặc polyglot. Khi phù hợp, hãy xem các định dạng phổ biến như những container (ví dụ: tài liệu OOXML là các gói ZIP).<sup>[[2]](#references)</sup>

#### 2) Tìm metadata và các chuỗi dễ nhận thấy

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Thử nhiều cách mã hóa:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Kiểm tra dữ liệu được nối thêm / tệp được nhúng

```bash
binwalk target
binwalk -e target
```

Nếu trích xuất thất bại nhưng có báo cáo signature, hãy dùng `dd` để trích thủ công theo offset rồi chạy lại `file` trên vùng đã trích.

#### 4) Nếu là ảnh

- Kiểm tra các điểm bất thường: `magick identify -verbose file`
- Nếu là PNG/BMP, liệt kê bit-plane/LSB: `zsteg -a file.png`
- Xác thực cấu trúc PNG: `pngcheck -v file.png`
- Dùng bộ lọc hình ảnh (Stegsolve / StegoVeritas) khi nội dung có thể được tiết lộ qua các phép biến đổi channel/plane

#### 5) Nếu là âm thanh

- Tạo spectrogram trước (Sonic Visualiser)
- Giải mã/kiểm tra các stream: `ffmpeg -v info -i file -f null -`
- Nếu âm thanh giống các âm đơn có cấu trúc, hãy thử giải mã DTMF

### Công cụ thiết yếu

Các công cụ này phát hiện những trường hợp phổ biến ở cấp container: payload trong metadata, byte được nối thêm và file nhúng bị ngụy trang bằng phần mở rộng.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk

```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```

Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost

```bash
foremost -i file
```

Kho lưu trữ dự án: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2

```bash
exiftool file
exiv2 file
```

#### file / strings

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### Container, dữ liệu nối thêm và thủ thuật polyglot

Nhiều thử thách steganography liên quan đến các byte thừa sau một tệp hợp lệ hoặc các archive được nhúng nhưng ngụy trang bằng phần mở rộng.

#### Payload nối thêm

Nhiều định dạng bỏ qua các byte ở cuối. Có thể nối ZIP/PDF/script vào một container hình ảnh/âm thanh.

Kiểm tra nhanh:

```bash
binwalk file
tail -c 200 file | xxd
```

Nếu bạn biết offset, hãy carve bằng `dd`:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Magic bytes

Khi `file` bị nhầm lẫn, hãy dùng `xxd` để tìm magic bytes và so sánh với các chữ ký đã biết:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Hãy thử `7z` và `unzip` ngay cả khi phần mở rộng không cho biết đây là file zip:

```bash
7z l file
unzip -l file
```

### Những điều bất thường liên quan đến stego

Các liên kết nhanh đến những dạng thường xuất hiện bên cạnh stego (QR tạo từ dữ liệu nhị phân, braille, v.v.).

#### QR codes từ dữ liệu nhị phân

Nếu độ dài của blob là một số chính phương, blob đó có thể là dữ liệu pixel thô của một hình ảnh/QR.

```python
import math
math.isqrt(2500)  # 50
```

Trợ lý chuyển đổi nhị phân sang hình ảnh:

- Trợ lý chuyển đổi nhị phân sang hình ảnh của dCode.<sup>[[5]](#references)</sup>

#### Braille

- Công cụ dịch Braille của Branah.<sup>[[6]](#references)</sup>

Để xem thêm các bộ sưu tập công cụ steganography và tài nguyên chuyên biệt theo kỹ thuật, hãy tham khảo stego-toolkit đi kèm và danh sách được 0xRick tuyển chọn.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker image với các công cụ steganography phổ biến nhất được đóng gói cùng nhau](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston và cộng sự — Các quy ước đóng gói mở ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Hình ảnh nhị phân](https://www.dcode.fr/binary-image)
- [6] [Branah — Công cụ dịch Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Tài nguyên Steganography](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
