# Tính toàn vẹn của firmware

{{#include ../../banners/hacktricks-training.md}}

Khi một đợt đánh giá được ủy quyền phát hiện cơ chế xác minh chữ ký firmware yếu hoặc không có, có thể dùng một image firmware đã chỉnh sửa để minh họa tác động đến tính toàn vẹn. Quy trình lab sau đây thêm một bind shell đồng thời giữ nguyên các bước trích xuất, mô phỏng và đóng gói lại ban đầu.<sup>[[2]](#references)[[3]](#references)</sup>

1. Có thể trích xuất firmware bằng firmware-mod-kit (FMK).
2. Cần xác định kiến trúc và thứ tự byte của firmware mục tiêu.
3. Có thể xây dựng cross compiler bằng Buildroot hoặc phương pháp phù hợp khác với môi trường.
4. Có thể dùng cross compiler để xây dựng backdoor.
5. Có thể sao chép backdoor vào thư mục /usr/bin của firmware đã trích xuất.
6. Có thể sao chép binary QEMU phù hợp vào rootfs của firmware đã trích xuất.
7. Có thể mô phỏng backdoor bằng chroot và QEMU.
8. Có thể truy cập backdoor qua netcat.
9. Cần xóa binary QEMU khỏi rootfs của firmware đã trích xuất.
10. Có thể đóng gói lại firmware đã chỉnh sửa bằng FMK.
11. Có thể kiểm thử firmware đã cài backdoor bằng cách mô phỏng với firmware analysis toolkit (FAT), rồi kết nối đến IP và cổng của backdoor mục tiêu bằng netcat.

Nếu đã có root shell thông qua dynamic analysis, thao túng bootloader hoặc kiểm thử bảo mật phần cứng, có thể chạy các binary kiểm thử biên dịch sẵn như implant hoặc reverse shell. `msfvenom` của Metasploit có thể tạo payload dành riêng cho kiến trúc để phục vụ quy trình xác thực này:<sup>[[4]](#references)</sup>

1. Cần xác định kiến trúc và thứ tự byte của firmware mục tiêu.
2. Có thể dùng Msfvenom để chỉ định payload mục tiêu, IP của host tấn công, số cổng lắng nghe, filetype, kiến trúc, nền tảng và file đầu ra.
3. Có thể chuyển payload đến thiết bị đã bị xâm nhập và đảm bảo payload có quyền thực thi.
4. Có thể chuẩn bị Metasploit để xử lý các yêu cầu đến bằng cách khởi chạy msfconsole và cấu hình các thiết lập theo payload.
5. Có thể chạy meterpreter reverse shell trên thiết bị đã bị xâm nhập.

## Cầu nối truyền tải không xác thực đến các giao thức cập nhật có đặc quyền

Một lỗi thiết kế phổ biến ở các thiết bị nhúng là để lộ **cùng một giao thức lệnh nội bộ qua nhiều phương thức truyền tải**, nhưng chỉ yêu cầu xác thực trên một phương thức. Ví dụ: USB có thể yêu cầu challenge-response, trong khi BLE chỉ chuyển tiếp các **GATT write** không xác thực đến cùng một trình xử lý cập nhật firmware có đặc quyền.<sup>[[1]](#references)</sup>

Quy trình tấn công thường gặp:

1. Liệt kê cơ sở dữ liệu BLE GATT và xác định các characteristic có thể ghi mà ứng dụng di động chính thức sử dụng.
2. Bắt lưu lượng ứng dụng và tìm các **magic bytes / opcode** trùng khớp với giao thức có dây.
3. Phát lại các lệnh có đặc quyền qua BLE **mà không pairing** và xác minh xem các thao tác nhạy cảm có còn hoạt động hay không.
4. Nếu có thể truy cập các opcode nâng cấp firmware, ghi cấu hình, debug hoặc kiểm thử tại nhà máy, hãy xem BLE như một **cổng quản trị có thể truy cập qua sóng vô tuyến**.

Kiểm tra nhanh:

```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```

Những điều cần xác minh khi reverse:

- BLE có yêu cầu **pairing/bonding** hay chỉ cần kết nối thông thường?
- Tất cả transport có được định tuyến đến cùng một bảng dispatcher nội bộ không?
- Các opcode đặc quyền có bị lọc khác nhau trên USB / BLE / UART / Wi-Fi không?
- Ứng dụng di động có thể kích hoạt từ xa các handler cập nhật firmware, khôi phục hoặc chẩn đoán không?

## Các firmware container chỉ có checksum vẫn chứa firmware do attacker kiểm soát

Firmware container chỉ được bảo vệ bằng **checksum không khóa** (CRC32, SHA-256, MD5, v.v.) chỉ phát hiện lỗi dữ liệu, **không xác thực tính xác thực**. Nếu attacker có thể truy cập routine cập nhật, họ có thể vá image, tính lại checksum rồi flash mã tùy ý.<sup>[[1]](#references)</sup>

Dấu hiệu đáng ngờ trong quá trình RE:

- Code cập nhật chỉ xác thực một blob checksum ở cuối, chẳng hạn `CHK2`, `CRC` hoặc `SHA256`.
- Không có xác minh chữ ký hoặc root of trust cho secure boot.
- Không sử dụng MAC / HMAC gắn với thiết bị hoặc mã hóa có xác thực.
- Chế độ recovery chấp nhận cùng định dạng image không xác thực.

Quy trình xác thực thực tế:

1. Trích xuất firmware container và xác định bootloader, firmware chính cùng metadata về tính toàn vẹn.
2. Sửa một chuỗi hoặc banner vô hại trong image.
3. Tính lại checksum chính xác theo cách updater yêu cầu.
4. Flash lại image qua quy trình cập nhật thông thường.
5. Xác nhận thay đổi sau khi khởi động để chứng minh có thể thay thế firmware bằng mã tùy ý.

Nếu cách này hoạt động qua transport có thể truy cập từ xa như BLE/Wi-Fi, lỗi này về bản chất là **thay thế firmware OTA không cần xác thực**.

## Biến thiết bị ngoại vi USB đáng tin cậy thành BadUSB bằng cách flash lại firmware

Khi host đã tin cậy thiết bị mục tiêu qua USB, firmware độc hại có thể không cần triển khai một USB stack hoàn toàn mới. Một hướng đi dễ hơn thường là **tái sử dụng hỗ trợ HID sẵn có**.<sup>[[1]](#references)</sup>

Cách thực hiện hữu ích:

1. Kiểm tra xem thiết bị đã enumerate dưới dạng giao diện **HID Consumer Control** / media / vendor HID hay chưa.
2. Tìm **HID report descriptor** hiện có trong firmware.
3. Thêm hoặc thay thế các mục descriptor để thiết bị cũng khai báo khả năng **keyboard**.
4. Tái sử dụng các routine firmware hiện có để gửi HID report thay vì viết phần triển khai transport mới.
5. Gửi report nhấn phím + nhả phím để nhập lệnh trên host.

Việc này biến việc chiếm quyền firmware thành **chiếm quyền host** vì PC sẽ tin thiết bị ngoại vi đã flash lại như một bàn phím hợp lệ.

### Checklist đánh giá tối thiểu

- `dmesg`, Device Manager hoặc USB descriptor có hiển thị giao diện HID hiện có không?
- Có chỗ trống gần report descriptor hoặc một bảng descriptor có thể relocate không?
- Có thể tái sử dụng các routine gửi media-control hiện có để gửi keyboard report không?
- Host có tự động chấp nhận giao diện keyboard mới sau khi flash lại không?

## Thực thi payload đáng tin cậy trong firmware RTOS

Thay vì chèn các trampoline dễ lỗi vào những code path bất kỳ, hãy tìm **các RTOS task hiện có** nhưng không được sử dụng hoặc ít ảnh hưởng trong hoạt động bình thường.<sup>[[1]](#references)</sup>

Lý do cách này hữu ích:

- Scheduler khởi chạy payload tự nhiên trong quá trình boot.
- Tránh làm hỏng luồng điều khiển quan trọng.
- Payload chạy trễ ít có khả năng kích hoạt watchdog reset hơn so với khi chạy bên trong handler USB/network nhạy với độ trễ.

Các mục tiêu phù hợp là task chẩn đoán, kiểm thử tại nhà máy, telemetry hoặc dịch vụ coprocessor có vẻ đang ở trạng thái chờ trong quá trình sử dụng bình thường.

## Lặp nhanh quá trình khai thác: tái sử dụng handler giao thức vô hại

Khi đã có thể vá firmware, một cách gọn nhẹ để đẩy nhanh RE là ghi đè một command handler vô hại (ví dụ **echo/debug opcode**) bằng các primitive **đọc / ghi / thực thi bộ nhớ** tùy chỉnh. Cách này tránh phải flash lại toàn bộ firmware cho mỗi thử nghiệm và đặc biệt hữu ích khi thiết bị hỗ trợ handler đã sửa đổi qua transport có dây tốc độ cao.<sup>[[1]](#references)</sup>

Dùng cách này để:

- Xác minh memory map được scatter-load
- Kiểm tra trực tiếp trạng thái heap/task
- Thử payload nhỏ trước khi ghi chúng vào flash
- An toàn khôi phục function pointer, chuỗi và bảng descriptor

## References

- [1] [Pwnd Blaster: Hack PC của bạn bằng loa mà không cần chạm vào máy](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Bộ công cụ phân tích firmware](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Cách sử dụng `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
