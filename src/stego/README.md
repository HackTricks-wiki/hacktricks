# Stego

{{#include ../banners/hacktricks-training.md}}

Phần này tập trung vào **tìm và trích xuất dữ liệu ẩn** trong hình ảnh, âm thanh, video, tài liệu, archive và văn bản. Steganography che giấu sự tồn tại của một cuộc giao tiếp bằng cách nhúng dữ liệu vào bên trong dữ liệu khác.<sup>[[1]](#references)</sup>

Nếu bạn đang tìm các cuộc tấn công cryptographic, hãy đến phần **Crypto**.

## Điểm bắt đầu

Tiếp cận steganography như một vấn đề pháp chứng: xác định container thực sự, kiểm tra các vị trí có tín hiệu cao (metadata, dữ liệu được nối thêm, file nhúng), sau đó mới áp dụng các kỹ thuật trích xuất ở cấp nội dung.

### Quy trình & phân loại ban đầu

Quy trình có cấu trúc, ưu tiên xác định container, kiểm tra metadata/chuỗi, carving và phân nhánh theo định dạng.

{{#ref}}
workflow/README.md
{{#endref}}

### Hình ảnh

Phần lớn stego trong CTF nằm ở đây: LSB/bit-plane (PNG/BMP), các điểm bất thường trong chunk/định dạng file, công cụ JPEG và thủ thuật GIF nhiều frame.

{{#ref}}
images/README.md
{{#endref}}

### Âm thanh

Thông điệp trong spectrogram, nhúng LSB vào sample và âm báo bàn phím điện thoại (DTMF) là những dạng thường gặp.

{{#ref}}
audio/README.md
{{#endref}}

### Văn bản

Nếu văn bản hiển thị bình thường nhưng hoạt động bất thường, hãy xem xét homoglyph Unicode, ký tự zero-width hoặc mã hóa dựa trên khoảng trắng.

{{#ref}}
text/README.md
{{#endref}}

### Tài liệu

PDF và file Office trước hết là các container; các cuộc tấn công thường xoay quanh file/stream nhúng, đồ thị object/relationship và giải nén ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Malware và steganography kiểu phân phối payload

Việc phân phối payload có thể sử dụng các file trông hợp lệ, chẳng hạn như hình ảnh GIF hoặc PNG, chứa payload văn bản được phân tách bằng marker thay vì ẩn dữ liệu trong pixel.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Bảng thuật ngữ NIST CSRC - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
