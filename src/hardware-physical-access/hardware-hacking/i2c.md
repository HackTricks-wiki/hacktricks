# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Hãy xác minh điện áp mục tiêu, sơ đồ chân, cách bố trí điện trở kéo lên và nối đất chung trước khi kết nối Bus Pirate. Không bật nguồn cấp của Bus Pirate trên bus đang được cấp nguồn bởi thiết bị mục tiêu chỉ để nghe lén; hai nguồn có thể xung đột và làm hỏng phần cứng. Bản ghi bên dưới là ví dụ dành riêng cho thiết bị, sử dụng Bus Pirate v3/firmware cộng đồng, không phải hướng dẫn nối dây áp dụng chung.<sup>[[1]](#references)[[2]](#references)</sup>

Để kiểm tra Bus Pirate có hoạt động hay không, hãy kết nối +5V với VPU và 3.3V với ADC, sau đó truy cập Bus Pirate (ví dụ bằng Tera Term) và dùng lệnh `~`:

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

Như bạn có thể thấy trong dòng lệnh trước đó, chương trình báo tìm thấy 0 lỗi. Điều này rất hữu ích để xác nhận thiết bị hoạt động sau khi mua hoặc flash firmware.

Để kết nối với Bus Pirate, bạn có thể làm theo tài liệu hướng dẫn:

![Dùng lệnh - Nhấn phím cách: Để kết nối với Bus Pirate, bạn có thể làm theo tài liệu hướng dẫn](<../../images/image (484).png>)

Trong trường hợp này, mục tiêu là EEPROM I²C thuộc dòng 24C256. Hãy xác nhận chính xác hậu tố và datasheet vì điện áp nguồn được hỗ trợ sẽ khác nhau tùy theo linh kiện.<sup>[[3]](#references)</sup>

![Dùng lệnh - Nhấn phím cách: Trong trường hợp này, tôi sẽ kết nối với một EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Để giao tiếp với Bus Pirate, tôi dùng Tera Term, kết nối với cổng COM của Bus Pirate và đặt tốc độ trong Setup --> Serial Port --> Speed thành 115200.\
Trong phần giao tiếp bên dưới, bạn có thể xem cách chuẩn bị Bus Pirate để giao tiếp qua I²C, cũng như cách ghi và đọc dữ liệu từ bộ nhớ (chú thích được viết bằng "#", đừng mong đợi phần đó xuất hiện trong nội dung giao tiếp):

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

Trong tình huống này, chúng ta sẽ nghe lén giao tiếp I2C giữa Arduino và EPROM trước đó. Bạn chỉ cần giao tiếp với cả hai thiết bị, sau đó kết nối bus pirate với các chân SCL, SDA và GND:

![Read 20B from address 0x69 configured before - Sniffer: In this scenario we are going to sniff the I2C communication between the arduino and the previous EPROM, you just need to...](<../../images/image (166).png>)

```bash
I2C>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## Tái dựng giao thức I2C hộp đen

### Nhận diện bus qua các chân đang hoạt động

Khi thiết bị ngoại vi không có sơ đồ chân hoặc datasheet, hãy bắt đầu bằng cách thụ động theo dõi bằng máy phân tích logic trở kháng cao trong khi máy chủ ban đầu đang hoạt động. Sau khi thiết lập mass chung và mức logic an toàn, phân loại các chân có tín hiệu không đổi là đường nguồn, mass hoặc tín hiệu có điện trở kéo lên; sau đó so sánh các đường đang hoạt động với những bus phổ biến: UART có TX/RX không đồng bộ, hoạt động độc lập theo từng hướng; SPI thông thường có clock, chip select và các đường dữ liệu riêng cho từng hướng; I2C có clock đều đặn cùng một đường dữ liệu hai chiều. Khi giải mã I2C, bạn sẽ thấy địa chỉ đích 7 bit, hướng đọc/ghi, ACK/NACK và các payload lặp lại.<sup>[[2]](#references)[[4]](#references)</sup>

Ghi lại một số trao đổi hợp lệ và lưu cả các byte đã giải mã lẫn thời gian thô. Các frame lặp lại là những bộ kiểm thử có đáp án đã biết hữu ích cho các bộ tuần tự hóa về sau, còn những thay đổi giữa các yêu cầu có thể giúp xác định các trường opcode, chỉ mục, độ lệch, độ dài, số thứ tự hoặc checksum.<sup>[[4]](#references)</sup>

### Khôi phục định dạng frame từ firmware máy chủ

Nếu không thể truy cập firmware của thiết bị ngoại vi, hãy trích xuất firmware **máy chủ** và tìm thành phần mở thiết bị I2C. Tìm chuỗi và ký hiệu liên quan đến tên thiết bị ngoại vi, `/dev/i2c-`, hàm tạo lệnh, hàm phân tích phản hồi, quy trình reset/khởi tạo và hàm checksum. Với mỗi hàm tạo frame, hãy ghi lại chính xác độ lệch của từng trường, hằng số, kích thước đối số được chấp nhận, độ dài payload, phạm vi tính checksum, thứ tự byte của checksum và độ dài frame trả về, thay vì suy đoán định dạng từ tên hàm.<sup>[[4]](#references)</sup>

Tên hàm checksum `crc16_ccitt` chưa đủ để chọn một preset. Hãy xác định hướng dịch bit, byte chỉ mục của bảng, đa thức được biểu diễn trong bảng, thanh ghi khởi tạo, phép phản chiếu đầu vào/đầu ra, phép XOR/đảo bit cuối cùng và thứ tự byte trên dây của bộ tuần tự hóa. Ví dụ, bảng tra cứu byte thấp dịch phải dựa trên đa thức đảo `0x8408`, khởi tạo bằng `0xFFFF` và lấy phần bù ở cuối cho biết đây là **CRC-16/X-25 (IBM-SDLC)**. Checksum chính xác thường cần thiết để vượt qua bước xác thực tính toàn vẹn và đi vào bộ phân tích lệnh.<sup>[[4]](#references)</sup>

Sau khi tái dựng định dạng, hãy tìm các tên ký hiệu và hằng số đặc trưng trong mã nguồn công khai. Trong trường hợp MJA1, một lớp bọc SDK được tìm thấy độc lập đã xác nhận ID lệnh, kiểm tra tính hợp lệ của đối số, định nghĩa phản hồi và cách triển khai CRC đối xứng; hãy dùng mã nguồn đó để kiểm chứng, không phải để thay thế việc kiểm tra chính xác binary mục tiêu và thứ tự byte trên dây.<sup>[[4]](#references)[[5]](#references)</sup>

### Gửi frame từ máy chủ Linux đã root

Máy chủ Linux nhúng bị xâm nhập có thể tương tác với thiết bị ngoại vi mà không cần thêm một bộ điều khiển bus khác. Mở bộ chuyển đổi tương ứng, chọn địa chỉ 7 bit bằng `I2C_SLAVE` và gửi frame được tạo bởi một bộ tuần tự hóa chuyên dụng; giữ lại chế độ frame thô để sửa đổi và fuzzing.<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

Cross-compile bằng toolchain tương thích với CPU và libc của mục tiêu, rồi so sánh các trace analyzer từ test client với lưu lượng hợp lệ. Ranh giới giao dịch, thứ tự ghi/đọc, độ trễ và trạng thái thiết bị ngoại vi đều có thể quan trọng, ngay cả khi các byte hiển thị giống nhau.<sup>[[4]](#references)</sup>

### Liệt kê opcode dựa trên phản hồi

Sau khi xác định được frame hợp lệ ngắn nhất và checksum, hãy liệt kê toàn bộ độ rộng opcode và dùng phản hồi **unsupported-command** tường minh của giao thức làm baseline âm. Kết quả khác—chẳng hạn như đối số không hợp lệ, trạng thái không hợp lệ hoặc status chưa được tài liệu hóa—cho thấy quá trình giải mã đã đi đến một handler được triển khai hoặc triển khai một phần. Điều này **không** chứng minh có thể khai thác; hãy ưu tiên kiểm thử ứng viên đó bằng fuzzing có cấu trúc với độ dài, đối số, trạng thái và chuỗi lệnh.<sup>[[4]](#references)</sup>

Nếu một bài kiểm thử khiến thiết bị ngoại vi bị treo, hãy tự động hóa mỗi lần khởi động chỉ một trường hợp riêng biệt từ bộ điều khiển bên ngoài: kết nối qua SSH, chạy trường hợp kiểm thử, lưu request/response thô cùng thời gian, khởi động lại hoặc ngắt rồi cấp lại nguồn, chờ các bước kiểm tra tình trạng hoạt động hoàn tất rồi tiếp tục. Sau này, chuyển linh kiện sang bộ gá được điều khiển bằng vi điều khiển có thể giúp reset ổn định, điều khiển nguồn trực tiếp và fuzzing nhanh hơn.<sup>[[4]](#references)</sup>

## References

- [1] [Tài liệu Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Đặc tả và hướng dẫn sử dụng bus I²C](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Datasheet EEPROM nối tiếp I²C AT24C256C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Thăm dò hộp đen: phân tích bảo mật chip bảo mật MJA1 của Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Wrapper mật mã MJA1 của Mijia BLE SDK](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
