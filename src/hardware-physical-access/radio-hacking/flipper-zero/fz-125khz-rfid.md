# FZ - RFID 125kHz

{{#include ../../../banners/hacktricks-training.md}}

## Giới thiệu

Để tìm hiểu về cách hoạt động của thẻ 125 kHz, xem:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[Phần giới thiệu về RFID tần số thấp](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) giải thích các họ thẻ phổ biến và định dạng dữ liệu của chúng.

## Thao tác

### Đọc

Dùng **Read** để thu thập dữ liệu thẻ. Sau khi đọc thành công, Flipper Zero có thể mô phỏng thẻ đã lưu.<sup>[[1]](#references)</sup>

> [!WARNING]
> Một số đầu đọc intercom thử phát hiện thẻ sao chép có thể ghi được bằng cách gửi lệnh ghi trước khi đọc. Flipper Zero không mô phỏng bộ nhớ có thể ghi của thẻ theo cách tương tự.<sup>[[1]](#references)</sup>

### Thêm thủ công

Bạn có thể nhập dữ liệu thẻ vào Flipper Zero theo cách thủ công, lưu lại rồi mô phỏng thẻ đó.<sup>[[1]](#references)</sup>

#### ID trên thẻ

Đôi khi, toàn bộ hoặc một phần ID của thẻ được in ở mặt ngoài.

- **EM Marin**

Ví dụ, thẻ EM-Marin trong hình hiển thị ba byte cuối trong tổng số năm byte ID. Nếu không đọc được thẻ, có thể brute-force hai byte còn thiếu.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Tương tự, thẻ HID trong hình chỉ in hai trong ba byte ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Mô phỏng/Ghi

Sau khi đọc thẻ hoặc nhập ID theo cách thủ công, Flipper Zero có thể mô phỏng thông tin xác thực đã lưu. Với các thẻ có thể ghi được hỗ trợ, thiết bị cũng có thể ghi dữ liệu đã lưu lên thẻ tương thích.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Tìm hiểu sâu về các giao thức RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
