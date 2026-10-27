# Steganography âm thanh

{{#include ../../banners/hacktricks-training.md}}

Các dạng phổ biến:

- Thông điệp trên spectrogram
- Nhúng LSB trong WAV
- Mã hóa bằng DTMF / âm quay số
- Payload trong metadata

## Phân loại nhanh

Trước khi dùng công cụ chuyên dụng:

- Xác nhận thông tin codec/container và các điểm bất thường:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Nếu âm thanh có nội dung giống nhiễu hoặc cấu trúc âm sắc, hãy kiểm tra spectrogram sớm.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Steganography bằng spectrogram

### Kỹ thuật

Stego bằng spectrogram ẩn dữ liệu bằng cách định hình năng lượng theo thời gian/tần số để dữ liệu hiển thị trên đồ thị thời gian-tần số, trong khi âm thanh có thể nghe như âm đơn hoặc nhiễu.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Công cụ chính để kiểm tra spectrogram:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Các lựa chọn thay thế

- Audacity (chế độ xem spectrogram và bộ lọc).<sup>[[6]](#references)</sup>
- `sox` có thể tạo spectrogram từ CLI:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## Giải mã FSK / modem

Âm thanh điều chế khóa dịch tần thường trông giống các tone đơn xen kẽ trên phổ đồ. Khi đã ước lượng sơ bộ tần số trung tâm/độ dịch và baud, hãy brute force bằng `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` hỗ trợ Bell và các chế độ FSK khác, cùng tần số mark/space tùy chỉnh; hãy xem các tùy chọn của công cụ thay vì cho rằng mọi bản ghi đều có thể tự động nhận dạng. Thử `--rx-invert`, một chế độ baud cụ thể hoặc `--samplerate <Hz>` nếu đầu ra bị lỗi.<sup>[[4]](#references)</sup>

## WAV LSB

### Kỹ thuật

Với PCM không nén (WAV), mỗi mẫu là một số nguyên. Việc sửa đổi các bit thấp làm thay đổi dạng sóng rất ít, vì vậy kẻ tấn công có thể giấu dữ liệu:

- 1 bit trên mỗi mẫu (hoặc nhiều hơn)
- Xen kẽ giữa các kênh
- Với một stride/permutation

Các phương pháp ẩn dữ liệu âm thanh khác bạn có thể gặp:

- Mã hóa pha
- Ẩn dữ liệu bằng tiếng vọng
- Nhúng spread-spectrum
- Các kênh bên ở cấp codec (tùy định dạng và công cụ)

### WavSteg

Các lệnh sau sử dụng WavSteg từ bộ công cụ `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Kho lưu trữ chính thức và các bản phát hành của DeepSound.<sup>[[7]](#references)</sup>

## DTMF / âm báo quay số

### Kỹ thuật

DTMF biểu diễn mỗi tín hiệu trên bàn phím bằng một tần số từ nhóm thấp và một tần số từ nhóm cao. Nếu âm thanh giống tiếng bấm phím hoặc các tiếng bíp hai tần số đều đặn, hãy thử giải mã DTMF sớm.<sup>[[5]](#references)</sup>

Các công cụ giải mã trực tuyến:

- Công cụ trên trình duyệt `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, công cụ giải mã tệp âm thanh ngoại tuyến.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — tài liệu](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem FSK dòng lệnh](https://github.com/kamalmostafa/minimodem)
- [5] [Khuyến nghị ITU-T Q.23 — đặc tính kỹ thuật của điện thoại nút bấm](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — kho lưu trữ chính thức và các bản phát hành](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}
