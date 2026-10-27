# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

Với thiết bị có thể tiếp cận vật lý, hãy bắt đầu từ giao diện được bo mạch hoặc các tín hiệu của thiết bị đưa ra: [UART serial consoles](uart.md), [JTAG/SWD debug access](jtag.md), [CoreSight instruction tracing](arm-coresight-instruction-tracing.md), các bus [I²C](i2c.md) và [SPI flash](spi.md). [Side-channel analysis](side_channel_analysis.md) và [fault injection](fault_injection_attacks.md) phục vụ các tác vụ đo lường và tạo glitch khác nhau; [radio signal analysis](radio.md) bao quát một điểm xâm nhập qua sóng vô tuyến. Với các quy trình cụ thể theo mục tiêu dành cho RFID/NFC, sub-GHz, hồng ngoại, BLE, LoRaWAN và iButton, hãy xem [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Hãy kiểm tra mức điện áp của mục tiêu và các giới hạn được nêu trong chương liên quan trước khi kết nối công cụ.

## JTAG

JTAG (IEEE 1149.1) hỗ trợ kiểm thử boundary-scan thông qua các cell được đặt quanh các chân I/O của thiết bị. Nhiều bộ xử lý cũng cung cấp các chức năng debug riêng của nhà cung cấp thông qua cùng Test Access Port (TAP); boundary scan và debug CPU là những cách sử dụng JTAG có liên quan, nhưng không đồng nghĩa với nhau.<sup>[[1]](#references)</sup>

Tiêu chuẩn JTAG định nghĩa **các lệnh cụ thể để thực hiện boundary scan**, bao gồm:

- **BYPASS** chọn một thanh ghi bypass một bit để có thể truy cập các thiết bị khác trong scan chain với mức overhead tối thiểu.
- **SAMPLE/PRELOAD** ghi nhận giá trị chân trong quá trình hoạt động bình thường và có thể nạp trước thanh ghi boundary-scan trước khi thực hiện một lệnh khác.
- **EXTEST** thiết lập và đọc trạng thái chân.

JTAG cũng có thể hỗ trợ các lệnh khác như:

- **IDCODE** dùng để nhận dạng thiết bị
- **INTEST** dùng để kiểm thử nội bộ thiết bị

Bạn có thể gặp các lệnh này khi sử dụng công cụ như JTAGulator.

### Test Access Port

**Test Access Port (TAP)** cung cấp quyền truy cập vào logic kiểm thử JTAG của một linh kiện. Cần có bốn tín hiệu; `TRST` là tùy chọn:<sup>[[1]](#references)</sup>

- Đầu vào xung nhịp kiểm thử (**TCK**) TCK là **xung nhịp** xác định tần suất bộ điều khiển TAP thực hiện một hành động (nói cách khác, chuyển sang trạng thái tiếp theo trong máy trạng thái).
- Đầu vào chọn chế độ kiểm thử (**TMS**) TMS điều khiển **máy trạng thái hữu hạn**. Ở mỗi nhịp xung nhịp, bộ điều khiển JTAG TAP của thiết bị kiểm tra điện áp trên chân TMS. Nếu điện áp thấp hơn một ngưỡng nhất định, tín hiệu được xem là mức thấp và được hiểu là 0; nếu điện áp cao hơn ngưỡng đó, tín hiệu được xem là mức cao và được hiểu là 1.
- Đầu vào dữ liệu kiểm thử (**TDI**) dịch nối tiếp lệnh hoặc dữ liệu kiểm thử vào thanh ghi TAP được chọn. IEEE 1149.1 định nghĩa cách truyền dữ liệu của TAP, còn các nhà cung cấp định nghĩa những lệnh tùy chọn và thanh ghi debug.
- Đầu ra dữ liệu kiểm thử (**TDO**) TDO là chân gửi **dữ liệu ra khỏi chip**.
- Đầu vào reset kiểm thử (**TRST**) TRST tùy chọn sẽ đưa máy trạng thái về **trạng thái tốt đã biết**. Ngoài ra, nếu giữ TMS ở mức 1 trong năm chu kỳ xung nhịp liên tiếp, thiết bị sẽ được reset tương tự như khi dùng chân TRST; vì vậy TRST là tùy chọn.

Đôi khi bạn có thể tìm thấy các chân đó được đánh dấu trên PCB. Trong những trường hợp khác, bạn có thể cần **tìm chúng**.

### Xác định các chân JTAG

Một lựa chọn nhanh, được thiết kế chuyên dụng nhưng tương đối đắt để phát hiện cổng JTAG là **JTAGulator**; công cụ này cũng có thể xác định sơ đồ chân UART.<sup>[[2]](#references)</sup>

Thiết bị có **24 kênh** có thể kết nối với các điểm kiểm tra trên bo mạch. Thiết bị liệt kê các tổ hợp chân khả dĩ bằng các lần quét **IDCODE** và **BYPASS**, rồi báo cáo các kênh tương ứng với những tín hiệu JTAG được phát hiện.

Một cách rẻ hơn nhưng chậm hơn nhiều để xác định sơ đồ chân JTAG là dùng [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) được nạp lên một vi điều khiển tương thích Arduino.

Với **JTAGenum**, trước tiên hãy xác định các chân của vi điều khiển dùng để thăm dò khi liệt kê. Tham khảo sơ đồ chân của thiết bị, sau đó nối các chân đó với những điểm kiểm tra khả dĩ trên bo mạch mục tiêu.<sup>[[3]](#references)</sup>

**Cách thứ ba** để xác định các chân JTAG là **kiểm tra PCB** để tìm footprint đã biết. Một số bo mạch có footprint **Tag-Connect**, nhưng Tag-Connect là một hệ thống đầu nối có thể mang JTAG, SWD, UART hoặc giao diện khác — bản thân nó không chứng minh các chân đó là JTAG. Sau đó, có thể dùng datasheet của linh kiện và phép đo thông mạch để xác định các tín hiệu thực tế.<sup>[[5]](#references)</sup>

## SDW

SWD là giao diện debug dạng gói hai chân của Arm.<sup>[[4]](#references)</sup>

Giao diện này sử dụng **SWDIO** hai chiều để truyền dữ liệu và **SWCLK** làm xung nhịp. Nhiều thiết bị triển khai **Serial Wire/JTAG Debug Port (SWJ-DP)**, cho phép chọn giữa SWD và JTAG trên các chân dùng chung.<sup>[[4]](#references)</sup>

## References

- [1] [Nhóm công tác IEEE 1149.1 — JTAG và boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Tài liệu JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Liệt kê chân JTAG trên Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Giao diện debug ít chân cho các hệ thống đa thiết bị](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprint cáp debug và lập trình](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
