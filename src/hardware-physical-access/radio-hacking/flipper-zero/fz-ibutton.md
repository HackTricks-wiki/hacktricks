# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Giới thiệu

Để tìm hiểu thông tin cơ bản về công nghệ iButton, xem:

{{#ref}}
../ibutton.md
{{#endref}}

## Thiết kế

Trong hình bên dưới, vùng **màu xanh dương** minh họa cách đặt iButton vật lý lên các tiếp điểm của Flipper Zero để đọc. Vùng **màu xanh lá** minh họa các tiếp điểm cần chạm vào đầu đọc khi mô phỏng.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Thao tác

### Đọc

Ở chế độ Đọc, Flipper Zero chờ khóa chạm vào các tiếp điểm, phát hiện giao thức và hiển thị giao thức phía trên ID khóa. Ứng dụng tích hợp hỗ trợ các khóa kiểm soát truy cập dùng giao thức Dallas, Cyfral và Metakom.<sup>[[2]](#references)</sup>

### Thêm thủ công

Bạn có thể nhập thủ công dữ liệu khóa cho các giao thức Dallas, Cyfral và Metakom.<sup>[[2]](#references)</sup>

### Mô phỏng

Bạn có thể mô phỏng khóa đã lưu, dù khóa đó được đọc từ khóa vật lý hay được nhập thủ công.<sup>[[2]](#references)</sup>

> [!TIP]
> Nếu các tiếp điểm tích hợp không chạm tới được đầu đọc, hãy nối các tiếp điểm data và ground thông qua các chân GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Kiểm soát khóa iButton bằng Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Tài liệu Flipper Zero - Đọc khóa iButton](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

