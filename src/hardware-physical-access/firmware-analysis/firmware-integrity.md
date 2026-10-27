# Tính toàn vẹn của firmware

{{#include ../../banners/hacktricks-training.md}}

Khi một đánh giá được ủy quyền phát hiện việc xác minh chữ ký firmware yếu hoặc không có, có thể dùng một image firmware đã sửa đổi để chứng minh tác động đến tính toàn vẹn. Quy trình lab sau đây thêm một bind shell đồng thời giữ nguyên các bước trích xuất, giả lập và đóng gói lại ban đầu.<sup>[[2]](#references)[[3]](#references)</sup>

1. Có thể trích xuất firmware bằng firmware-mod-kit (FMK).
2. Cần xác định kiến trúc và endianness của firmware mục tiêu.
3. Có thể build một cross compiler bằng Buildroot hoặc phương pháp phù hợp khác cho môi trường.
4. Có thể build backdoor bằng cross compiler.
5. Có thể sao chép backdoor vào thư mục /usr/bin của firmware đã trích xuất.
6. Có thể sao chép binary QEMU phù hợp vào rootfs của firmware đã trích xuất.
7. Có thể giả lập backdoor bằng chroot và QEMU.
8. Có thể truy cập backdoor qua netcat.
9. Cần xóa binary QEMU khỏi rootfs của firmware đã trích xuất.
10. Có thể đóng gói lại firmware đã sửa đổi bằng FMK.
11. Có thể kiểm thử firmware đã cài backdoor bằng cách giả lập nó với firmware analysis toolkit (FAT), sau đó dùng netcat kết nối đến IP và port của backdoor mục tiêu.

Nếu đã có được root shell thông qua dynamic analysis, thao túng bootloader hoặc kiểm thử bảo mật phần cứng, có thể chạy các binary kiểm thử được biên dịch sẵn, chẳng hạn như implant hoặc reverse shell. `msfvenom` của Metasploit có thể tạo payload dành riêng cho kiến trúc để phục vụ quy trình xác thực này:<sup>[[4]](#references)</sup>

1. Cần xác định kiến trúc và endianness của firmware mục tiêu.
2. Có thể dùng Msfvenom để chỉ định payload mục tiêu, IP host của attacker, số port lắng nghe, filetype, kiến trúc, nền tảng và file đầu ra.
3. Có thể chuyển payload đến thiết bị đã bị xâm nhập và đảm bảo payload có quyền thực thi.
4. Có thể chuẩn bị Metasploit để xử lý các yêu cầu đến bằng cách khởi động msfconsole và cấu hình các thiết lập theo payload.
5. Có thể chạy meterpreter reverse shell trên thiết bị đã bị xâm nhập.

## Cầu nối transport không xác thực đến các giao thức cập nhật có đặc quyền

Một lỗi thiết kế phổ biến trong hệ thống nhúng là để lộ **cùng một giao thức lệnh nội bộ qua nhiều transport** nhưng chỉ thực thi xác thực trên một transport. Ví dụ, USB có thể yêu cầu challenge-response trong khi BLE chỉ chuyển tiếp các **GATT writes** chưa xác thực đến cùng một trình xử lý cập nhật firmware có đặc quyền.<sup>[[1]](#references)</sup>

Quy trình tấn công điển hình:

1. Liệt kê cơ sở dữ liệu BLE GATT và xác định các characteristic có thể ghi mà ứng dụng di động chính thức sử dụng.
2. Sniff lưu lượng của ứng dụng và tìm các **magic bytes / opcode** tương ứng với giao thức có dây.
3. Phát lại các lệnh có đặc quyền qua BLE **mà không pairing** và xác minh xem các thao tác nhạy cảm có vẫn hoạt động hay không.
4. Nếu có thể truy cập các opcode nâng cấp firmware, ghi cấu hình, debug hoặc kiểm thử tại nhà máy, hãy xem BLE là một **cổng quản trị có thể truy cập qua sóng vô tuyến**.

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

## Container firmware chỉ có checksum vẫn chứa firmware do attacker kiểm soát

Container firmware chỉ được bảo vệ bằng **checksum không khóa** (CRC32, SHA-256, MD5, v.v.) có thể phát hiện hỏng dữ liệu, **nhưng không xác thực được nguồn gốc**. Nếu attacker truy cập được quy trình cập nhật, họ có thể chỉnh sửa image, tính lại checksum rồi flash mã tùy ý.<sup>[[1]](#references)</sup>

Các dấu hiệu đáng ngờ khi RE:

- Mã cập nhật chỉ xác thực một blob checksum ở cuối, chẳng hạn `CHK2`, `CRC` hoặc `SHA256`.
- Không có xác minh chữ ký hoặc root of trust cho secure boot.
- Không sử dụng MAC / HMAC gắn với thiết bị hoặc mã hóa có xác thực.
- Chế độ khôi phục chấp nhận cùng định dạng image không xác thực.

Quy trình kiểm tra thực tế:

1. Trích xuất container firmware và xác định bootloader, firmware chính cùng metadata toàn vẹn.
2. Sửa một chuỗi hoặc banner vô hại trong image.
3. Tính lại checksum chính xác theo cách updater yêu cầu.
4. Flash lại image qua quy trình cập nhật thông thường.
5. Xác nhận thay đổi sau khi khởi động để chứng minh có thể thay thế firmware bằng mã tùy ý.

Nếu cách này hoạt động qua transport có thể truy cập từ xa như BLE/Wi-Fi, lỗ hổng này thực chất là **thay thế firmware OTA không cần xác thực**.

## Trạng thái cập nhật phân mảnh và metadata toàn vẹn có thể ghi

Updater có thể xác minh header đã ký trong lúc cài đặt nhưng khi khởi động lại chỉ dùng hash toàn vẹn đã lưu để kiểm tra image. Trên Cypherock X1, Bootloader gọi riêng các tác vụ Firewall để xác minh header và đưa phiên bản/kích thước vào RAM, lưu chữ ký firmware trong RAM, xác minh image đã ghi, rồi cuối cùng hash image vào Primary Bootloader Data lưu trữ lâu dài. Bản thân chữ ký không được lưu lại. Các tác vụ này có thể được gọi độc lập, thay vì buộc phải thực hiện một giao dịch nâng cấp đã xác thực xuyên suốt.<sup>[[5]](#references)</sup>

Khi đã thực thi mã MCU và có quyền ghi Flash, cuộc tấn công được báo cáo đã ghi đè image ứng dụng, thay đổi giá trị phiên bản/kích thước trong RAM của Bootloader được chia sẻ với Firewall, rồi gọi tác vụ metadata cuối cùng để lưu hash của image độc hại và khôi phục trạng thái khởi động bình thường. Kiểm tra toàn vẹn khi khởi động thông thường chấp nhận hash đó mà không xác minh lại chữ ký. Khi đánh giá một updater tương tự, hãy lần theo **thành phần nào có thể gọi từng tác vụ**, các giá trị đã xác minh được lưu ở đâu và quyết định lúc khởi động có xác thực *chính image* được lưu hash hay không. Lỗ hổng này cụ thể hơn định dạng image chỉ có checksum: có xác minh chữ ký, nhưng quá trình chuyển trạng thái không được ràng buộc với chữ ký đó.<sup>[[5]](#references)</sup>

## Chữ ký của secure element trên các phép đo firmware không đáng tin cậy

Secure element không chứng thực mã đang chạy chỉ bằng cách ký một hash do chính mã đó cung cấp. Trên cùng ví điện tử này, secure element ký số sê-ri thiết bị rồi ký kết quả XOR giữa nonce từ cloud và hash firmware do MCU cung cấp. Firmware đã bị xâm phạm có thể đưa ra hash dự kiến để được ký trong khi thực tế chạy các byte khác. Client đi kèm cũng gửi phiên bản firmware lên cloud, nên phép so sánh hash dự kiến của bên xác minh vẫn dựa vào phép đo từ MCU thay vì đọc Flash độc lập.<sup>[[5]](#references)</sup>

Kết quả phía thiết bị tạo thành một ranh giới tin cậy riêng: cloud kiểm tra thiết bị, nhưng thiết bị không xác thực kết luận của cloud. Client đã bị chỉnh sửa có thể báo thành công cục bộ cho một thiết bị đã bị can thiệp. Hãy kiểm tra riêng nguồn gốc phép đo và xác thực phản hồi; chữ ký secure element hợp lệ cùng màn hình báo thành công tự chúng không chứng minh ứng dụng đã cài là xác thực.<sup>[[5]](#references)</sup>

Để xem thông tin về việc tiết lộ mã được bảo vệ giúp phân tích updater này, xem [Thu thập firmware bằng tác vụ sao chép Firewall](index.html#disclosing-protected-code-through-a-firewall-copy-task).<sup>[[5]](#references)</sup>

## Biến thiết bị ngoại vi USB đáng tin cậy thành BadUSB bằng cách flash lại firmware

Khi host đã tin cậy thiết bị mục tiêu qua USB, firmware độc hại có thể không cần triển khai cả một USB stack mới. Một hướng chuyển đổi dễ hơn thường là **tái sử dụng hỗ trợ HID sẵn có**.<sup>[[1]](#references)</sup>

Mẫu hữu ích:

1. Kiểm tra xem thiết bị đã được nhận diện là giao diện **HID Consumer Control** / media / vendor HID chưa.
2. Tìm **HID report descriptor** hiện có trong firmware.
3. Thêm hoặc thay thế các mục descriptor để thiết bị cũng khai báo khả năng **keyboard**.
4. Tái sử dụng các routine firmware hiện có vốn đã gửi HID report, thay vì viết một phần triển khai transport mới.
5. Chèn report nhấn phím và nhả phím để nhập lệnh trên host.

Cách này biến việc xâm phạm firmware thành **xâm phạm host** vì PC sẽ tin thiết bị ngoại vi được flash lại như một bàn phím hợp lệ.

### Danh sách kiểm tra đánh giá tối thiểu

- `dmesg`, Device Manager hoặc USB descriptor có hiển thị giao diện HID hiện có không?
- Có chỗ trống gần report descriptor hoặc một bảng descriptor có thể di dời không?
- Có thể tái sử dụng routine gửi media-control hiện có để gửi keyboard report không?
- Host có tự động chấp nhận giao diện bàn phím mới sau khi flash lại không?

## Thực thi payload đáng tin cậy bên trong firmware RTOS

Thay vì chèn các trampoline dễ lỗi vào những nhánh mã ngẫu nhiên, hãy tìm **các RTOS task sẵn có** nhưng không được dùng hoặc ít ảnh hưởng trong hoạt động thông thường.<sup>[[1]](#references)</sup>

Vì sao cách này hữu ích:

- Scheduler tự khởi chạy payload của bạn khi boot.
- Tránh làm hỏng luồng điều khiển quan trọng.
- Payload chạy trễ ít có khả năng kích hoạt watchdog reset hơn so với khi chạy bên trong handler USB/network nhạy với độ trễ.

Các mục tiêu phù hợp gồm task chẩn đoán, kiểm thử tại nhà máy, telemetry hoặc dịch vụ coprocessor có vẻ không hoạt động trong quá trình sử dụng bình thường.

## Lặp nhanh exploit: tái sử dụng các protocol handler vô hại

Khi có thể patch firmware, một cách gọn để đẩy nhanh RE là ghi đè handler của một lệnh vô hại (chẳng hạn **echo/debug opcode**) bằng các primitive **đọc / ghi / thực thi bộ nhớ** tùy chỉnh. Cách này tránh phải flash lại toàn bộ cho từng thử nghiệm và đặc biệt hữu ích khi thiết bị hỗ trợ handler đã sửa đổi qua transport có dây tốc độ cao.<sup>[[1]](#references)</sup>

Dùng cách này để:

- Xác minh memory map được nạp rải rác
- Kiểm tra trực tiếp trạng thái heap/task
- Thử payload nhỏ trước khi ghi chúng vào flash
- Khôi phục function pointer, chuỗi và bảng descriptor một cách an toàn

## References

- [1] [Pwnd Blaster: Hack PC bằng loa mà không cần chạm vào máy](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Bộ công cụ phân tích firmware](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - Cách sử dụng `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
- [5] [Chúng tôi hack ví phần cứng Cypherock như thế nào và vì sao: Toàn bộ câu chuyện](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
