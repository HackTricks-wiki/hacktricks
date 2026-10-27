# Steganography văn bản

{{#include ../../banners/hacktricks-training.md}}

## Quy trình thực hành

Nếu văn bản thuần hoạt động bất thường, hãy giữ nguyên bằng chứng gốc, kiểm tra các điểm mã và chỉ chuẩn hóa một bản sao.

### Kỹ thuật

Steganography văn bản thường dựa vào các ký tự hiển thị giống nhau hoặc vô hình:

- Homoglyphs: các điểm mã Unicode khác nhau nhưng trông giống nhau (ví dụ: `a` trong bảng chữ cái Latin và `а` trong bảng chữ cái Cyrillic)<sup>[[1]](#references)</sup>
- Ký tự độ rộng bằng không: ký tự nối, ký tự không nối và dấu cách độ rộng bằng không<sup>[[2]](#references)</sup>
- Mã hóa khoảng trắng: dấu cách so với tab, mẫu khoảng trắng ở cuối dòng và mẫu độ dài dòng có chủ ý<sup>[[3]](#references)[[4]](#references)</sup>

Các trường hợp khác có tín hiệu rõ:

- Ký tự điều khiển hai chiều, có thể làm thay đổi thứ tự hiển thị của văn bản<sup>[[1]](#references)</sup>
- Bộ chọn biến thể và ký tự kết hợp, có thể mang trạng thái ẩn trong khi gần như không làm thay đổi văn bản hiển thị<sup>[[1]](#references)</sup>

### Công cụ giải mã

- [Công cụ mã hóa/giải mã homoglyph Unicode và ký tự độ rộng bằng không](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Kiểm tra điểm mã

```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
  if ord(ch) > 127 or ch.isspace():
    print(i, hex(ord(ch)), repr(ch))
PY
```

## Kênh `unicode-range` của CSS

Có thể lạm dụng các quy tắc `@font-face` để mã hóa byte trong các mục `unicode-range: U+..`. Trích xuất các codepoint, nối các giá trị thập lục phân rồi giải mã chúng:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Nếu các khoảng chứa nhiều giá trị trong mỗi khai báo, trước tiên hãy tách theo dấu phẩy rồi chuẩn hóa (`tr ',+' '\n'`). Python có thể phân tích và xuất các byte khi định dạng không nhất quán.<sup>[[3]](#references)</sup>

## References

- [1] [Báo cáo kỹ thuật Unicode #36: Các cân nhắc về bảo mật Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Steganography Unicode bằng ký tự có độ rộng bằng không và homoglyph](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Danh sách mong muốn của Santa](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Hướng dẫn Debian: steganography khoảng trắng với `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
