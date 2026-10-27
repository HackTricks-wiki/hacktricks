# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Dò tìm chân và thiết lập phần cứng an toàn hơn

- Trước tiên, dùng đồng hồ vạn năng xác định Vtref và GND. Nhiều adapter cần Vtref để thiết lập điện áp I/O.
- Chuyển mức: ưu tiên bộ chuyển mức hai chiều được thiết kế cho tín hiệu push-pull (các đường JTAG không phải open-drain). Tránh dùng bộ chuyển mức I2C tự nhận hướng cho JTAG.
- Adapter hữu ích: bo mạch FT2232H/FT232H (ví dụ: Tigard), CMSIS-DAP, J-Link, ST-LINK (tùy nhà sản xuất), ESP-USB-JTAG (trên ESP32-Sx). Kết nối tối thiểu TCK, TMS, TDI, TDO, GND và Vtref; có thể kết nối thêm TRST và SRST.

Với header chưa có tài liệu, hãy xác định GND bằng cách kiểm tra thông mạch với một mặt phẳng nối đất đã biết **khi mục tiêu chưa được cấp nguồn**. Sau khi chuyển sang chế độ đo điện áp và cấp nguồn cho thiết bị, đừng xem mọi chân có điện áp cao là Vtref: các đầu vào số mức cao có thể cho kết quả tương tự trên đồng hồ. Nối các đường nguồn tiềm năng tới những tụ khử ghép gần đó, rồi so sánh dạng sóng lúc bật/tắt nguồn bằng máy hiện sóng. Điện áp tăng hoặc giảm chậm theo dạng đường cong của tụ là dấu hiệu cho thấy đó có thể là đường nguồn/đường tham chiếu, nhưng hãy xác minh điện áp và cách đấu dây trước khi kết nối đầu dò có chuyển mức. Trên PiFex, có thể chọn nguồn tham chiếu bên ngoài có điện áp thấp hơn cho mục tiêu qua `VCCA_IN` thay vì dùng mức mặc định 3.3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** là công cụ có thể nạp lên MCU tương thích Arduino hoặc, trong thử nghiệm, Raspberry Pi để brute-force sơ đồ chân JTAG chưa biết và liệt kê các thanh ghi lệnh.<sup>[[3]](#references)</sup>

- Arduino: kết nối các chân số D2–D11 với tối đa 10 pad/testpoint JTAG khả nghi, và nối GND của Arduino với GND của mục tiêu. Cấp nguồn riêng cho mục tiêu, trừ khi bạn biết chắc đường nguồn an toàn. Ưu tiên logic 3.3 V (ví dụ: Arduino Due) hoặc dùng bộ chuyển mức/điện trở nối tiếp khi dò các mục tiêu 1.8–3.3 V.
- Raspberry Pi: bản dựng cho Pi có ít GPIO khả dụng hơn (nên quá trình quét chậm hơn); hãy kiểm tra repo để biết sơ đồ chân và các giới hạn hiện tại.

Sau khi nạp firmware, mở serial monitor ở tốc độ 115200 baud và gửi `h` để xem trợ giúp. Quy trình thường dùng:

- `l` tìm loopback để tránh kết quả dương tính giả
- `r` bật/tắt pull-up nội bộ nếu cần
- `s` quét TCK/TMS/TDI/TDO (và đôi khi cả TRST/SRST)
- `y` brute-force IR để tìm các opcode chưa được tài liệu hóa
- `x` chụp trạng thái chân bằng boundary-scan

![JTAG - JTAGenum: x chụp trạng thái chân bằng boundary-scan](<../../images/image (939).png>)

![JTAG - JTAGenum: x chụp trạng thái chân bằng boundary-scan](<../../images/image (578).png>)

![JTAG - JTAGenum: x chụp trạng thái chân bằng boundary-scan](<../../images/image (774).png>)



Nếu tìm thấy TAP hợp lệ, bạn sẽ thấy các dòng bắt đầu bằng `FOUND!` cho biết những chân đã được phát hiện.

### Mẹo an toàn khi dùng JTAGenum

- Luôn nối chung GND và không bao giờ cấp tín hiệu vào chân chưa biết với điện áp cao hơn Vtref của mục tiêu. Nếu không chắc chắn, hãy mắc điện trở nối tiếp 100–470 Ω trên các chân khả nghi.
- Nếu thiết bị dùng SWD/SWJ thay vì JTAG 4 dây, JTAGenum có thể không phát hiện được; hãy thử công cụ SWD hoặc adapter hỗ trợ SWJ-DP.

## Tìm chân GPIO bằng go-jtagenum

Trên mục tiêu đang được cấp nguồn, có GND chung đã xác minh và điện áp I/O tương thích, `go-jtagenum` có thể liệt kê các tín hiệu JTAG khả nghi từ GPIO của Raspberry Pi. JSON `-pins` ánh xạ nhãn tới **số GPIO**, không phải vị trí chân vật lý trên header.<sup>[[5]](#references)</sup> Trong ví dụ SSD, lần quét IDCODE đầu tiên cũng báo một chuỗi dài bất thường gồm các giá trị thay đổi: chỉ riêng một đường TDO khả nghi có giá trị thay đổi không chứng minh được rằng có TAP hợp lệ. Hãy kiểm tra lại kết quả có vẻ hợp lý bằng lần quét BYPASS, trong đó một mẫu bit đã biết được dịch từ TDI qua thanh ghi bypass một bit tới TDO.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Với bo mạch đó, BYPASS xác nhận `TCK=10`, `TMS=14`, `TDI=9` và `TDO=15`; các chân bổ sung chỉ là những ứng viên nTRST **có thể** đúng. Nếu một ứng viên trả về toàn số 0 hoặc một mẫu không nhất quán, hãy kiểm tra tiếp xúc, nguồn điện của thiết bị đích, điện trở kéo lên và độ trễ clock/reset trước khi gán tín hiệu cho chân đó.<sup>[[4]](#references)[[5]](#references)</sup> Công cụ cũng chấp nhận `-known-pins` cùng với `test_bypass` để kiểm tra lại sơ đồ chân đã khôi phục.<sup>[[5]](#references)</sup>

## Characterize an undocumented TAP with UrJTAG

Sơ đồ chân đã tìm ra không cho biết các opcode của instruction-register (IR) hoặc độ rộng data-register (DR) cần thiết để debug. Với bản dựng UrJTAG hỗ trợ cáp Raspberry Pi GPIO, hãy thiết lập sơ đồ chân đã khôi phục rồi chạy `idcode`, `detect`, sau đó là `discover`. Ví dụ SSD phát hiện một TAP, IR bốn bit và các độ rộng DR khác nhau ứng với những giá trị IR khác nhau. Độ dài DR `-1` hoặc thông báo “TDO stuck at 0” không phải là định nghĩa thanh ghi có thể sử dụng; hãy kiểm tra timing, dây nối và instruction đang được chọn thay vì tự gán độ rộng cho nó.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Đây là hoạt động trinh sát TAP, không phải tính năng tự động nhận dạng CPU: hãy so sánh IDCODE thu được với tài liệu thiết bị và các target được OpenOCD hỗ trợ. Cơ sở dữ liệu nhà sản xuất cục bộ của UrJTAG có thể gắn nhãn một ID hợp lệ là unknown.<sup>[[4]](#references)</sup>

## Kết nối OpenOCD lần đầu (quét và IDCODE)

OpenOCD là OSS de facto cho JTAG/SWD. Với adapter được hỗ trợ, bạn có thể quét chain và đọc IDCODE:<sup>[[1]](#references)</sup>

- Ví dụ chung với J‑Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- USB-JTAG tích hợp sẵn trên ESP32‑S3 (không cần probe bên ngoài):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Ghi chú

- Nếu nhận được IDCODE có giá trị "all ones/zeros", hãy kiểm tra dây nối, nguồn, Vtref và xem cổng có bị khóa bằng fuse/option byte hay không.
- Xem `irscan`/`drscan` cấp thấp của OpenOCD để tương tác thủ công với TAP khi thiết lập các chain chưa rõ.<sup>[[1]](#references)</sup>

## Đưa target chưa được tài liệu hóa vào OpenOCD

Khi đã biết TAP ID và độ dài IR, hãy kiểm tra các script `cpu/`, `target/` và `board/` của OpenOCD để tìm **kiến trúc CPU phù hợp**, sau đó tạo cấu hình adapter và target riêng.<sup>[[4]](#references)[[6]](#references)</sup> Mapping Pi GPIO và target ARCv2 dưới đây là ví dụ SSD đã được kiểm thử, không phải cấu hình JTAG phổ quát. Lựa chọn target ARC và các thiết lập debug là những giả định đã hoạt động với thiết bị này; trên bo mạch khác, hãy thay bằng ID, độ dài IR, kiến trúc và số GPIO đã đo của target đó.<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

Chạy `openocd -f raspberrypi-io.cfg -f target.cfg` và xác nhận quá trình kiểm tra TAP thành công trước khi đọc bộ nhớ. Ví dụ này mở Telnet trên cổng `4444` và máy chủ GDB trên cổng `3333`; chỉ nhận diện được IDCODE không chứng minh rằng có thể kiểm tra hoặc debug CPU target đã chọn.<sup>[[4]](#references)</sup> GPIO trên Raspberry Pi không nhất thiết phải là các chân được ghi nhãn JTAG trên bo mạch breakout nếu adapter cho phép ánh xạ lại bằng `adapter gpio`.<sup>[[4]](#references)[[6]](#references)</sup>

## Dừng CPU và dump bộ nhớ/flash

Sau khi nhận diện được TAP và chọn script target, bạn có thể dừng core và dump các vùng bộ nhớ hoặc flash nội bộ. Ví dụ (điều chỉnh target, địa chỉ cơ sở và kích thước):<sup>[[1]](#references)</sup>

- Target chung sau khi init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- SoC RISC‑V (ưu tiên SBA nếu khả dụng):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, nạp chương trình hoặc đọc bằng trợ giúp của OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Mẹo dump bộ nhớ

- Dùng `mdw/mdh/mdb` để kiểm tra nhanh bộ nhớ trước khi dump dài.
- Với chuỗi nhiều thiết bị, đặt BYPASS trên các thiết bị không phải mục tiêu hoặc dùng tệp board định nghĩa tất cả TAP.

Với memory map chưa được tài liệu hóa, nghiên cứu SSD đã kiểm tra một bản dump 1 MiB để tìm các chuỗi controller dễ nhận biết, sau đó dùng GDB hỗ trợ kiến trúc thông qua OpenOCD để kiểm tra `$pc`, disassembly và các thanh ghi. Các địa chỉ trực tiếp này giúp định hướng lần dump vùng thứ hai, rồi đối chiếu với các lệnh tương ứng trong bản Ghidra hỗ trợ ARC. Chỉ riêng các chuỗi không đủ để chứng minh image hoàn chỉnh hoặc được ánh xạ chính xác.<sup>[[4]](#references)</sup> Xem [phân tích firmware](../firmware-analysis/) để biết thêm các bước phân tích tĩnh tổng quát.

## Thủ thuật boundary-scan (EXTEST/SAMPLE)

Ngay cả khi quyền truy cập debug của CPU bị khóa, boundary-scan vẫn có thể được mở. Với UrJTAG/OpenOCD, bạn có thể:<sup>[[1]](#references)</sup>
- SAMPLE để chụp trạng thái các chân khi hệ thống đang chạy (tìm hoạt động trên bus, xác nhận ánh xạ chân).
- EXTEST để điều khiển các chân (ví dụ: bit-bang các đường SPI flash bên ngoài thông qua MCU để đọc flash ngoại tuyến nếu cách đi dây trên board cho phép).

Quy trình UrJTAG tối giản với adapter FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Bạn cần BSDL của thiết bị để biết thứ tự bit của boundary register. Lưu ý rằng một số nhà cung cấp khóa các boundary-scan cell trong quá trình sản xuất.

## Các mục tiêu hiện đại và lưu ý

- ESP32‑S3/C3 tích hợp cầu nối USB‑JTAG; OpenOCD có thể giao tiếp trực tiếp qua USB mà không cần probe ngoài. Rất tiện để phân loại sự cố và dump dữ liệu.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) được OpenOCD hỗ trợ rộng rãi; ưu tiên SBA để truy cập bộ nhớ khi không thể halt core một cách an toàn.
- Nhiều MCU triển khai xác thực debug và các trạng thái vòng đời. Nếu JTAG có vẻ không hoạt động dù nguồn đúng, thiết bị có thể đã bị fuse sang trạng thái đóng hoặc yêu cầu probe đã được xác thực.

## Biện pháp phòng thủ và gia cố (điều cần dự kiến trên thiết bị thực tế)

- Vô hiệu hóa vĩnh viễn hoặc khóa JTAG/SWD trong quá trình sản xuất (ví dụ: STM32 RDP level 2, eFuse của ESP vô hiệu hóa PAD JTAG, APPROTECT/DPAP của NXP/Nordic).
- Yêu cầu xác thực debug (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response do OEM quản lý) nhưng vẫn duy trì quyền truy cập trong quá trình sản xuất.
- Tránh bố trí test pad dễ tiếp cận; chôn test via, tháo/lắp điện trở để cô lập TAP, sử dụng đầu nối có định hướng hoặc đồ gá pogo-pin.
- Khóa debug khi bật nguồn: đặt TAP sau một ROM sớm thực thi secure boot.

## References

- [1] [Hướng dẫn sử dụng OpenOCD – Lệnh và cấu hình JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Gỡ lỗi JTAG trên Espressif ESP32‑S3 (USB‑JTAG, cách dùng OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Công cụ quét pinout JTAG dựa trên Arduino](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — Hacking JTAG bằng Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — Dò tìm JTAG qua GPIO](https://github.com/gremwell/go-jtagenum)
- [6] [Hướng dẫn sử dụng OpenOCD — Cấu hình Debug Adapter](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
