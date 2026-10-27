# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Giới thiệu <a href="#introduction" id="introduction"></a>

Flipper Zero có thể **thu và phát các tần số vô tuyến trong dải 300-928 MHz** bằng module tích hợp, tùy thuộc vào giới hạn tần số của khu vực đã cấu hình. Thiết bị có thể đọc, lưu và mô phỏng các điều khiển từ xa tương thích dùng cho cổng, thanh chắn, khóa vô tuyến, công tắc, chuông cửa không dây, đèn thông minh và các thiết bị khác.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Phần cứng Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero có module dưới 1 GHz tích hợp, dựa trên bộ thu phát CC1101 và một ăng-ten vô tuyến. Phạm vi thực tế phụ thuộc vào tần số, ăng-ten, môi trường và bộ phát; theo tài liệu của Flipper, phạm vi có thể lên đến khoảng 50 mét trong điều kiện thuận lợi. Phần cứng hỗ trợ các dải 300-348 MHz, 387-464 MHz và 779-928 MHz, trong khi firmware và quy định khu vực tiếp tục giới hạn việc phát tín hiệu.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Thao tác

### Frequency Analyzer

> [!TIP]
> Cách tìm tần số mà điều khiển từ xa đang sử dụng

Khi phân tích, Flipper Zero quét cường độ tín hiệu (RSSI) trên tất cả các tần số có trong cấu hình tần số. Flipper Zero hiển thị tần số có giá trị RSSI cao nhất, với cường độ tín hiệu lớn hơn -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Để xác định tần số của điều khiển từ xa, hãy làm như sau:

1. Đặt điều khiển từ xa thật gần bên trái Flipper Zero.
2. Vào **Main Menu** **→ Sub-GHz**.
3. Chọn **Frequency Analyzer**, sau đó nhấn và giữ nút trên điều khiển từ xa bạn muốn phân tích.
4. Xem giá trị tần số trên màn hình.

### Read

> [!TIP]
> Tìm thông tin về tần số đang dùng (cũng là một cách khác để tìm tần số đang dùng)

Tùy chọn **Read** lắng nghe trên tần số và kiểu điều chế đã cấu hình (mặc định là 433.92 MHz AM). Khi nhận diện được tín hiệu được hỗ trợ, màn hình sẽ hiển thị thông tin có thể lưu và phát lại sau.<sup>[[1]](#references)</sup>

Trong khi dùng Read, bạn có thể nhấn **nút trái** để **cấu hình**.\
Hiện tại có **4 kiểu điều chế** (AM270, AM650, FM328 và FM476), cùng **một số tần số thường dùng** được lưu sẵn:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Bạn có thể chọn bất kỳ tần số nào được phép. Nếu chưa biết điều khiển từ xa sử dụng tần số nào, hãy đặt **Hopping thành ON** (mặc định tắt), sau đó nhấn nút điều khiển từ xa vài lần cho đến khi Flipper thu được tín hiệu và hiển thị tần số.

> [!CAUTION]
> Việc chuyển đổi giữa các tần số mất một khoảng thời gian, vì vậy có thể bỏ lỡ tín hiệu được phát đúng lúc chuyển đổi. Để thu tín hiệu tốt hơn, hãy đặt tần số cố định đã xác định bằng Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Thu trộm (và phát lại) tín hiệu trên tần số đã cấu hình

Tùy chọn **Read Raw** ghi lại tín hiệu được phát trên tần số đã chọn. Có thể dùng tùy chọn này để thu và phát lại tín hiệu trong quá trình kiểm thử được ủy quyền.<sup>[[1]](#references)</sup>

Mặc định, **Read Raw cũng sử dụng 433.92 MHz với AM650**. Nếu tùy chọn Read tìm thấy tín hiệu ở tần số hoặc kiểu điều chế khác, hãy nhấn Left trong Read Raw để thay đổi các cài đặt đó.

### Brute-Force

Nếu biết giao thức mà thiết bị như cửa garage sử dụng, có thể **tạo các mã ứng viên và phát chúng bằng Flipper Zero**. Dự án `flipperzero-bruteforce` hỗ trợ một số giao thức mã tĩnh phổ biến.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Thêm tín hiệu từ danh sách giao thức đã cấu hình

#### Danh sách giao thức được hỗ trợ <a href="#id-3iglu" id="id-3iglu"></a>

Menu Add Manually cung cấp các cấu hình sẵn cho giao thức được ghi trong tài liệu Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (hoạt động với phần lớn hệ thống mã tĩnh) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Các nhà cung cấp Sub-GHz được hỗ trợ

Xem danh sách nhà cung cấp được Flipper Zero hỗ trợ.<sup>[[5]](#references)</sup>

### Tần số được hỗ trợ theo khu vực

Hãy kiểm tra danh sách tần số chính thức theo khu vực trước khi phát tín hiệu.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Xem giá trị dBm của các tần số đã lưu

## References

- [1] [Sub-GHz - Tài liệu hướng dẫn sử dụng Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Bảng dữ liệu CC1101 của Texas Instruments](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Thêm điều khiển từ xa được tạo thủ công](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Các nhà cung cấp Sub-GHz được hỗ trợ](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Tần số Sub-GHz theo khu vực](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
