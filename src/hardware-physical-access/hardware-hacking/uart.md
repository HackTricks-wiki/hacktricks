# UART

{{#include ../../banners/hacktricks-training.md}}

## Thông tin cơ bản

UART là giao diện nối tiếp bất đồng bộ, truyền một luồng bit được đóng khung mà không cần clock dùng chung. Không nên nhầm UART mức logic với RS-232: RS-232 sử dụng mức điện áp khác, thường là điện áp âm, và cần bộ thu phát.<sup>[[1]](#references)[[3]](#references)</sup>

Thông thường, đường tín hiệu được giữ ở mức cao (giá trị logic 1) khi UART ở trạng thái idle. Sau đó, để báo hiệu bắt đầu truyền dữ liệu, bộ phát gửi một bit start đến bộ nhận; trong khoảng thời gian này, tín hiệu được giữ ở mức thấp (giá trị logic 0). Tiếp theo, bộ phát gửi từ năm đến tám bit dữ liệu chứa thông điệp thực tế, sau đó là một bit parity tùy chọn và một hoặc hai bit stop (giá trị logic 1), tùy cấu hình. Bit parity dùng để kiểm tra lỗi nhưng hiếm khi xuất hiện trong thực tế. Bit (hoặc các bit) stop báo hiệu kết thúc quá trình truyền.

Cấu hình phổ biến nhất là 8N1: tám bit dữ liệu, không có parity và một bit stop. UART gửi bit dữ liệu có trọng số thấp nhất trước, vì vậy ký tự ASCII `C` (`0x43`) được truyền như sau: start `0`; dữ liệu `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Cấu hình phổ biến nhất được gọi là 8N1: tám bit dữ liệu, không có parity và một bit stop. Ví dụ, nếu muốn gửi ký tự C, hay 0x43 trong ASCII, bằng UART 8N1](<../../images/image (764).png>)

Các công cụ phần cứng để giao tiếp với UART:

- Bộ chuyển đổi USB-to-serial
- Bộ chuyển đổi dùng chip CP2102 hoặc PL2303
- Công cụ đa năng như: Bus Pirate, Adafruit FT232H, Shikra hoặc Attify Badge

### Nhận diện cổng UART

Một header debug điển hình có các chân **TX**, **RX** và **GND**; đôi khi còn có chân **Vcc/Vref**, reset hoặc điều khiển luồng. Vcc không phải tín hiệu UART và thông thường chỉ nên dùng làm tham chiếu điện áp, không dùng làm nguồn cấp—trừ khi đã biết sơ đồ mạch và yêu cầu dòng điện của bo mạch.<sup>[[2]](#references)[[3]](#references)</sup>

Bắt đầu khi thiết bị **đã tắt nguồn** và được ngắt kết nối:

- Dùng chế độ đo thông mạch để xác định **GND** bằng cách đối chiếu với mặt phẳng ground, vỏ đầu nối hoặc ground nguồn đã biết. Không bao giờ dùng chế độ đo thông mạch/điện trở trên bo mạch đang được cấp nguồn.
- Chuyển sang chế độ đo điện áp DC trước khi cấp nguồn cho thiết bị cần kiểm tra. Đo các chân nghi vấn so với ground để xác định điện áp logic. Một đường điện áp ổn định có thể là Vcc/Vref; đừng cho rằng việc kết nối vào đó là an toàn.
- Quan sát các chân nghi vấn bằng logic analyzer hoặc oscilloscope trong lúc khởi động. **TX** thường ở mức cao khi idle và có các đợt dữ liệu được đóng khung. Đồng hồ vạn năng có thể cho thấy điện áp trung bình dao động nhưng không thể xác thực framing hoặc baud rate.
- **RX** có thể vẫn ở trạng thái idle và không thể được xác định an toàn chỉ vì nó nằm cạnh TX. Hãy dò đường mạch PCB, tham khảo datasheet của SoC hoặc dùng analyzer trở kháng cao trước khi cấp tín hiệu vào chân này.

Đổi chéo TX và RX thường sẽ khiến giao tiếp không hoạt động; nhầm lẫn giữa nguồn, ground hoặc mức tín hiệu có thể làm hỏng vĩnh viễn thiết bị cần kiểm tra hoặc adapter. Kết nối ground trước và bắt đầu ở chế độ **chỉ nhận** (TX của thiết bị cần kiểm tra nối với RX của adapter).

Nhà sản xuất có thể bỏ header, không lắp điện trở nối tiếp, vô hiệu hóa console trong firmware hoặc chỉ đưa TX ra ngoài. Dò các test pad và vị trí điện trở gần đó đến SoC; chỉ tạo kết nối tạm thời trở kháng cao sau khi xác nhận mức điện áp. Việc thiết bị còn bảo hành không có nghĩa là chắc chắn có thể truy cập UART.

### Khôi phục pad TX có mức điện áp thấp

Một pad TX được dán nhãn nhưng luôn ở mức thấp trong lần chụp tín hiệu ban đầu chưa đủ để kết luận đó không phải UART. Sau khi xác nhận điện áp logic của thiết bị và ground chung, hãy thử dùng điện trở kéo lên yếu (ví dụ được ghi nhận sử dụng **10 kΩ đến 3.3 V**) rồi chụp lại tín hiệu trong khi nhấn nút hoặc khởi động thiết bị. Chỉ dùng đường nguồn logic đã xác minh của thiết bị; không nối điện trở kéo lên vào tín hiệu chưa rõ hoặc đang được chủ động điều khiển. Nếu xuất hiện các chuyển trạng thái được đóng khung, hãy đo khoảng thời gian bit ngắn nhất, rõ ràng để ước tính baud rate trước khi kết nối pad ở chế độ chỉ nhận với adapter serial. Trong ví dụ, cách này khôi phục được log sự kiện nút bấm ở 115200 baud, nhưng không lấy được firmware dump.<sup>[[8]](#references)</sup>

### Xác định baud rate UART

Cách dễ nhất để xác định baud rate phù hợp là xem đầu ra của chân **TX** và thử đọc dữ liệu. Nếu dữ liệu nhận được không đọc được, hãy chuyển sang baud rate khả dĩ tiếp theo cho đến khi dữ liệu đọc được. Bạn có thể dùng bộ chuyển đổi USB-to-serial hoặc thiết bị đa năng như Bus Pirate cùng với script hỗ trợ, chẳng hạn [baudrate.py](https://github.com/devttys0/baudrate/). Các baud rate phổ biến nhất là 9600, 38400, 19200, 57600 và 115200.

> [!CAUTION]
> Cần lưu ý rằng trong giao thức này, bạn phải nối TX của thiết bị này với RX của thiết bị kia!

### Tự động hóa việc ghi nhận UART lúc khởi động bằng SCPI

Nếu đầu ra lúc khởi động xuất hiện trong thời gian ngắn hoặc chưa xác định được pad TX, hãy tự động hóa việc khởi động lặp lại thay vì thao tác nguồn cấp và oscilloscope bằng tay. Kết nối nguồn cấp lập trình có giới hạn dòng với đầu vào nguồn đã xác minh của thiết bị cần kiểm tra. Dùng đầu vào oscilloscope trở kháng cao và ground chung để thăm dò từng pad TX nghi vấn; không cấp tín hiệu vào pad đó.<sup>[[5]](#references)</sup>

VISA mở các phiên thiết bị qua serial hoặc Ethernet, còn SCPI điều khiển đầu ra, trigger và việc đọc waveform.<sup>[[5]](#references)[[6]](#references)</sup> Cài `pyvisa` và `pyvisa-py` (cùng với `pyserial` cho tài nguyên VISA serial); `ResourceManager('@py')` sẽ chọn rõ ràng backend Python.<sup>[[5]](#references)[[7]](#references)</sup> Thay chuỗi tài nguyên và lệnh bằng những giá trị được các thiết bị đang dùng hỗ trợ.<sup>[[5]](#references)</sup>

Trong ví dụ với Rigol MSO5000, hãy kích hoạt trigger cạnh xuống một lần trước khi cấp nguồn cho bo mạch: TX UART đang idle ở mức cao sẽ chuyển xuống thấp trước tiên để tạo bit start.<sup>[[5]](#references)</sup> Đặt ngưỡng trigger nằm giữa mức idle và mức thấp đã đo, đồng thời đặt timebase để bao phủ khoảng thời gian khởi động cần quan sát.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` có thể ngăn các cạnh lặp lại trong chế độ capture liên tục, nhưng không thay thế việc kiểm tra xem capture một lần đã thực sự hoàn tất hay chưa.<sup>[[5]](#references)</sup> Đoạn dưới đây ghi lại một lần khởi động và lưu cả các mẫu byte không dấu lẫn metadata về tỷ lệ của chúng; khi hết thời gian chờ, nó sẽ tắt nguồn thiết bị thay vì chờ vô hạn.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>Ghi nhận waveform UART một lần khi cấp nguồn bằng PyVISA</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

Để khảo sát các pad, lặp lại lần capture một lần sau khi di chuyển probe, hoặc giữ phiên cấp nguồn mở và bật/tắt đầu ra với khoảng chờ khởi động và khoảng tắt nguồn. Arm lại oscilloscope trước mỗi lần bật nguồn để mỗi tệp tương ứng với một lần khởi động và một pad.<sup>[[5]](#references)</sup>

Preamble của Rigol có dạng `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> Giá trị **thứ ba** là số điểm, không phải sample rate như bài viết đã nêu.<sup>[[5]](#references)[[6]](#references)</sup> Trong ví dụ, `25,000,000` điểm và `xincrement = 2e-8` giây suy ra `1 / xincrement = 50,000,000` mẫu/giây, không phải 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Giữ preamble cùng với tệp nhị phân và kiểm tra độ dài dữ liệu đọc khớp với `<points>`; hướng dẫn mô tả cách đọc theo phân đoạn/theo lô cho các bản ghi lớn.<sup>[[6]](#references)</sup>

Để giải mã tín hiệu đã capture, nhập `capture.bin` vào PulseView dưới dạng **Raw Analog Data Without Header**, chọn giá trị unsigned 8-bit (`U8`) và nhập sample rate được tính từ `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Áp dụng **Logic via Threshold** cho kênh analog, chọn ngưỡng nằm giữa giá trị mẫu thấp và cao.<sup>[[5]](#references)</sup> Đo độ rộng của một start bit rõ ràng để ước tính baud rate (khoảng 17.36 µs ở 57,600 baud), sau đó áp dụng bộ giải mã UART của PulseView và xác minh rằng nhiều frame được giải mã nhất quán.<sup>[[5]](#references)</sup> Chỉ một cạnh xuống không đủ để chứng minh pad đó là UART.

## Adapter CP210X UART sang TTY

Các bridge USB-to-UART CP210x xuất hiện trên nhiều board tạo mẫu và adapter giá rẻ. Các module phổ biến có các chân nguồn bên cạnh GND, RXD và TXD, nhưng header và mức I/O khác nhau. Hãy xác nhận điện áp thực tế từ thiết kế board hoặc data sheet. Thông thường, chỉ kết nối GND, RX của adapter với TX của target và—sau khi xác nhận chỉ nhận—TX của adapter với RX của target. Không kết nối chân nguồn 5 V/3.3 V của adapter trừ khi bạn chủ ý cấp nguồn cho target đã được xác nhận là chịu được mức điện áp đó.<sup>[[3]](#references)</sup>

Nếu adapter không được nhận diện, hãy đảm bảo rằng driver CP210X đã được cài trên hệ thống host. Sau khi adapter được nhận diện và kết nối, có thể dùng các công cụ như picocom, minicom hoặc screen.

Để liệt kê các thiết bị được kết nối với hệ thống Linux/MacOS:

```
ls /dev/
```

Để tương tác cơ bản với giao diện UART, hãy sử dụng lệnh sau:

```
picocom /dev/<adapter> --baud <baudrate>
```

Để cấu hình minicom, hãy sử dụng lệnh sau:

```
minicom -s
```

Cấu hình các thiết lập như baudrate và tên thiết bị trong tùy chọn `Serial port setup`.

Sau khi cấu hình, chạy `minicom` để mở UART console.

## UART Qua Arduino UNO R3 (Bo mạch có chip Atmel 328p tháo rời được)

Nếu không có sẵn bộ chuyển đổi UART Serial sang USB, có thể dùng Arduino UNO R3 với một thủ thuật nhanh. Vì Arduino UNO R3 thường có ở khắp nơi, cách này có thể giúp tiết kiệm nhiều thời gian.

Arduino UNO R3 có sẵn bộ chuyển đổi USB sang Serial trên bo mạch. Để kết nối UART, chỉ cần rút chip vi điều khiển Atmel 328p khỏi bo mạch. Thủ thuật này dùng được với các biến thể Arduino UNO R3 có Atmel 328p không được hàn trên bo mạch (phiên bản sử dụng chip SMD). Kết nối chân RX của Arduino (Digital Pin 0) với chân TX của UART Interface, và chân TX của Arduino (Digital Pin 1) với chân RX của UART interface.

Dùng **Serial Monitor** của Arduino IDE hoặc một terminal chuyên dụng được đặt ở baud rate mục tiêu. Tín hiệu Serial của Uno R3 đời đầu dùng mức logic 5 V, vì vậy hãy dùng bộ chuyển mức hoặc mạch chia áp trước khi kết nối với thiết bị mục tiêu 3.3 V hoặc có điện áp thấp hơn.

## Bus Pirate

Bản ghi sau đây sử dụng giao diện firmware Bus Pirate cũ để theo dõi đầu ra UART. Firmware Bus Pirate mới hơn dùng các lệnh như `m uart`, `{`/`}`, `monitor` hoặc `bridge`; hãy tham khảo tài liệu dành cho phiên bản đã cài đặt.<sup>[[2]](#references)</sup>

```bash
# Check the modes
UART>m
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

# Select UART
(1)>3
Set serial port speed: (bps)
 1. 300
 2. 1200
 3. 2400
 4. 4800
 5. 9600
 6. 19200
 7. 38400
 8. 57600
 9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
 1. 8, NONE *default
 2. 8, EVEN
 3. 8, ODD
 4. 9, NONE

 # From now on pulse enter for default
(1)>
Stop bits:
 1. 1 *default
 2. 2
(1)>
Receive polarity:
 1. Idle 1 *default
 2. Idle 0
(1)>
Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```

## Dump firmware bằng UART Console

UART console cung cấp quyền truy cập trong thời gian chạy vào boot log và đôi khi là bootloader hoặc shell của hệ điều hành. Ngay cả console chỉ đọc cũng tiết lộ memory map, flash driver, boot argument, bố cục phân vùng và phiên bản firmware. Firmware có thể nằm trong SPI NOR/NAND, eMMC hoặc thiết bị khác; thông thường firmware không được thực thi từ EEPROM, và các tệp được ghi vào filesystem persistent đã mount không nhất thiết sẽ biến mất sau khi khởi động lại.

Có một số cách thu thập; phần SPI trình bày việc đọc trực tiếp từ flash ngoài. Thu thập qua console có thể ít xâm lấn hơn nếu bootloader đã có sẵn lệnh đọc an toàn, nhưng việc ngắt quá trình boot hoặc chạy lệnh flash có thể ảnh hưởng đến khả năng hoạt động, vì vậy hãy ghi lại trạng thái ban đầu và tránh các thao tác ghi/xóa.

Việc dump firmware qua console thường bắt đầu bằng cách ngắt bootloader. Nhiều thiết bị Linux nhúng sử dụng **Das U-Boot**, nhưng các thiết bị khác dùng bootloader độc quyền hoặc tắt console tương tác.

Để kiểm tra bootloader có tương tác được hay không, hãy kết nối đường nhận UART và terminal khi target chưa được cấp nguồn, bắt đầu ghi log rồi bật nguồn. Làm theo lời nhắc autoboot hiển thị; tùy theo bản dựng, có thể cần nhấn một phím, một chuỗi phím ngắn để ngắt, hoặc tính năng này có thể bị tắt hoàn toàn.

Nếu ngắt thành công, hãy dùng `help`, `printenv` và các lệnh dò tìm chỉ đọc để tìm hiểu bố cục bộ nhớ và lưu trữ của nhà cung cấp đó trước khi truy cập các địa chỉ.

Trong U-Boot, `md` hiển thị **bộ nhớ có thể định địa chỉ**, không tự động là “EEPROM”. Trước tiên, hãy dùng các lệnh dành riêng cho bo mạch như `mtd list`, `sf probe`, `mmc info`, `part list`, các biến môi trường và boot log để xác định địa chỉ ánh xạ phù hợp hoặc nạp một vùng flash vào RAM. Sau đó hiển thị một phạm vi đã biết theo từng byte:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Ghi lại đầu ra serial trước khi bắt đầu. Đầu ra `md.b` chứa địa chỉ và cột ASCII, nên đây là biểu diễn dạng văn bản chứ không phải ảnh ROM thô.

Loại bỏ cột địa chỉ và ASCII, nối các trường byte dạng hexadecimal, rồi giải mã thành binary (ví dụ bằng `xxd -r -p`). Xác minh số byte mong đợi và ghi lại hash trước khi phân tích:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk sau đó nhận diện các chữ ký đã biết trong binary được tái dựng. Đọc flash trực tiếp qua giao diện SPI/eMMC/NAND phù hợp thường nhanh hơn và ít lỗi hơn khi console không thể truyền dữ liệu ổn định.

U-Boot có thể tắt chức năng ngắt, yêu cầu chuỗi phím riêng của nhà cung cấp hoặc khóa các lệnh bộ nhớ/flash. Hãy làm theo lời nhắc autoboot và log khởi động thay vì gửi ký tự một cách mù quáng. Nếu không thể ngắt console, hãy lưu lại log khởi động và chuyển sang phương thức thu thập firmware không xâm lấn.

## References

- [1] [Sổ tay tham khảo dòng Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Tài liệu Bus Pirate - chế độ UART và giới hạn điện](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - bảng dữ liệu CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Tài liệu U-Boot - lệnh hiển thị bộ nhớ `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI và thiết bị đo phần cứng dành cho kỹ sư reverse, Phần 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Hướng dẫn lập trình Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Cấu hình backend](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — Ôn lại hardware hacking, Phần 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
