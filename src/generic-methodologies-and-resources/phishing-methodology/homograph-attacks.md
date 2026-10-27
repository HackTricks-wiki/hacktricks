# Tấn công Homograph / Homoglyph trong Phishing

{{#include ../../banners/hacktricks-training.md}}

## Tổng quan

Tấn công homograph (còn gọi là homoglyph) lợi dụng thực tế rằng nhiều **điểm mã Unicode thuộc các hệ chữ phi Latin trông giống hệt hoặc rất giống các ký tự ASCII**. Bằng cách thay một hoặc nhiều ký tự Latin bằng các ký tự tương tự về hình thức, kẻ tấn công có thể tạo ra:

* Tên hiển thị, chủ đề hoặc nội dung thư trông hợp pháp với mắt người nhưng vượt qua các cơ chế phát hiện dựa trên từ khóa.
* Tên miền, tên miền phụ hoặc đường dẫn URL đánh lừa nạn nhân, khiến họ tin rằng mình đang truy cập một trang đáng tin cậy.<sup>[[1]](#references)</sup>

Vì mỗi ký tự được nhận diện nội bộ bằng **điểm mã Unicode**, chỉ cần thay thế một ký tự là đủ để đánh bại các phép so sánh chuỗi đơn giản (ví dụ: `"Παypal.com"` so với `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Quy trình Phishing điển hình

1. **Tạo nội dung thông điệp** – Thay thế một số chữ cái Latin trong thương hiệu / từ khóa bị mạo danh bằng các ký tự trông không thể phân biệt được thuộc hệ chữ khác (Hy Lạp, Cyrillic, Armenia, Cherokee, v.v.).
2. **Đăng ký hạ tầng hỗ trợ** – Có thể đăng ký tên miền homoglyph và lấy chứng chỉ TLS (hầu hết CA không kiểm tra độ tương đồng về hình thức).
3. **Gửi email / SMS** – Thông điệp chứa homoglyph ở một hoặc nhiều vị trí sau:
   * Tên hiển thị của người gửi (ví dụ: `Ηеlрdеѕk`)
   * Dòng chủ đề (`Urgеnt Аctіon Rеquіrеd`)
   * Văn bản liên kết hoặc tên miền đầy đủ
4. **Chuỗi chuyển hướng** – Nạn nhân được chuyển qua các trang web có vẻ vô hại hoặc dịch vụ rút gọn URL trước khi đến máy chủ độc hại dùng để thu thập thông tin xác thực / phát tán malware.<sup>[[1]](#references)</sup>

## Các dải Unicode thường bị lạm dụng

Các ví dụ sau là những khối Unicode chứa các ký tự thường được dùng để tạo ra các ký tự trông giống nhau giữa các hệ chữ.<sup>[[2]](#references)[[3]](#references)</sup>

| Hệ chữ | Dải | Ký tự ví dụ | Trông giống |
|--------|-------|---------------|------------|
| Hy Lạp  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Hy Lạp  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenia | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Mẹo: Tra cứu các khối và điểm mã trong biểu đồ mã Unicode.

## Kỹ thuật phát hiện

### 1. Kiểm tra hệ chữ hỗn hợp

Email Phishing nhắm đến một tổ chức nói tiếng Anh hiếm khi nên trộn ký tự từ nhiều hệ chữ. Một heuristic đơn giản nhưng hiệu quả là:

1. Duyệt từng ký tự trong chuỗi cần kiểm tra.
2. Ánh xạ điểm mã sang tên hệ chữ hoặc khối Unicode tương ứng.
3. Cảnh báo nếu có nhiều hơn một hệ chữ **hoặc** nếu xuất hiện hệ chữ phi Latin ở nơi không được mong đợi (tên hiển thị, tên miền, chủ đề, URL, v.v.).<sup>[[3]](#references)</sup>

Proof-of-concept Python:

```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
    "display_name": "Ηоmоgraph Illusion",     # example data
    "subject": "Finаnꮯiаl Տtatеmеnt",
    "url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
    blocks = defaultdict(int)
    for ch in value:
        if ch.isascii():
            blocks['Latin'] += 1
        else:
            name = ud.name(ch, 'UNKNOWN')
            block = name.split(' ')[0]     # e.g., 'CYRILLIC'
            blocks[block] += 1
    if len(blocks) > 1:
        print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```

### 2. Chuẩn hóa Punycode (Tên miền)

Tên miền quốc tế hóa (IDN) có dạng Unicode và dạng **Punycode** tương thích với ASCII, có tiền tố `xn--`. Hãy chuyển hostname sang dạng IDNA/Punycode trước khi đưa vào allow-list hoặc so sánh, đồng thời giữ lại dạng Unicode để hiển thị.<sup>[[6]](#references)</sup>

```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```

### 3. Từ điển / thuật toán Homoglyph

Các công cụ như **dnstwist** (`--fuzzers homoglyph`) hoặc **urlcrazy** có thể liệt kê các biến thể tên miền trông giống nhau và hữu ích cho việc chủ động yêu cầu gỡ bỏ / giám sát.<sup>[[4]](#references)[[5]](#references)</sup>

## Phòng ngừa & giảm thiểu

* Thực thi các chính sách DMARC/DKIM/SPF nghiêm ngặt – ngăn giả mạo từ các tên miền trái phép.
* Triển khai logic phát hiện ở trên trong **Secure Email Gateways** và các playbook **SIEM/XSOAR**.
* Gắn cờ hoặc cách ly các thư có tên miền trong tên hiển thị ≠ tên miền người gửi.
* Hướng dẫn người dùng: sao chép-dán văn bản đáng ngờ vào công cụ kiểm tra Unicode, di chuột qua các liên kết, không bao giờ tin tưởng các dịch vụ rút gọn URL.

## Ví dụ thực tế

* Tên hiển thị: `Сonfidеntiаl Ꭲiꮯkеt` (chữ Cyrillic `С`, `е`, `а`; chữ Cherokee `Ꭲ`; chữ Latin viết hoa nhỏ `ꮯ`).
* Chuỗi tên miền: `bestseoservices.com` ➜ thư mục `/templates` của một đô thị ➜ `kig.skyvaulyt.ru` ➜ trang đăng nhập Microsoft giả mạo tại `mlcorsftpsswddprotcct.approaches.it.com`, được bảo vệ bằng CAPTCHA OTP tùy chỉnh.
* Mạo danh Spotify: người gửi `Sρօtifս` với liên kết ẩn sau `redirects.ca`.

Các mẫu này xuất phát từ nghiên cứu của Unit 42 (tháng 7 năm 2025) và minh họa cách lạm dụng homograph kết hợp chuyển hướng URL và né tránh CAPTCHA để vượt qua phân tích tự động.<sup>[[1]](#references)</sup>

## References

- [1] [Ảo ảnh Homograph: Không phải mọi thứ đều như vẻ ngoài](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Bảng mã ký tự Unicode](https://www.unicode.org/charts/)
- [3] [Tiêu chuẩn kỹ thuật Unicode #39: Cơ chế bảo mật Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – công cụ tạo biến thể tên miền](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – công cụ tạo lỗi chính tả và biến thể tên miền](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Tên miền quốc tế hóa cho ứng dụng (IDNA): Định nghĩa và khuôn khổ tài liệu](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
