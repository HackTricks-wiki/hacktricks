# SPI

{{#include ../../banners/hacktricks-training.md}}

## Thông tin cơ bản

SPI (Serial Peripheral Interface) là một bus nối tiếp đồng bộ thường được dùng để giao tiếp ở khoảng cách ngắn giữa các mạch tích hợp. Controller cung cấp xung clock và chọn một peripheral, chẳng hạn như EEPROM, cảm biến hoặc thiết bị điều khiển, bằng tín hiệu chip-select.<sup>[[1]](#references)</sup>

Nhiều peripheral có thể dùng chung các đường clock và data, thường với một chip-select riêng cho mỗi peripheral. Controller điều phối các lần truyền; các peripheral thường không giao tiếp trực tiếp với nhau qua bus SPI. Cực tính và timing của chip-select tùy thuộc vào thiết bị; chọn mức thấp là kiểu phổ biến nhưng không phải luôn đúng. SPI không quy định cơ chế phát hiện thiết bị, địa chỉ, lệnh hay độ dài truyền tối đa cố định, vì vậy hãy luôn tham khảo datasheet của thiết bị đích.<sup>[[1]](#references)</sup>

MOSI/COPI truyền dữ liệu từ controller đến peripheral, còn MISO/CIPO truyền dữ liệu từ peripheral đến controller. Hai chiều có thể dịch chuyển đồng thời. Mối quan hệ giữa lệnh, địa chỉ, chu kỳ dummy và dữ liệu trả về do peripheral quy định—không phải SPI—và phụ thuộc vào cực tính, pha của clock (mode 0–3). Đừng cho rằng dữ liệu đầu ra bắt đầu ngay sau một xung clock kể từ khi dữ liệu đầu vào kết thúc.<sup>[[1]](#references)</sup>

## Dump Firmware từ EEPROM

Dump firmware có thể hữu ích cho việc phân tích và tìm lỗ hổng. Có thể không tìm được image phù hợp trên mạng hoặc image đó khác theo model, phiên bản phần cứng hay phiên bản firmware, vì vậy trích xuất trực tiếp từ thiết bị vật lý sẽ cung cấp mục tiêu đánh giá chính xác.

Serial console có thể hữu ích, nhưng filesystem của nó có thể chỉ đọc và thiết bị đích có thể thiếu các công cụ phân tích, bao gồm cả tiện ích cần thiết để gửi/nhận lưu lượng kiểm thử hoặc trích xuất binary một cách thuận tiện. Image ngoại tuyến giữ nguyên toàn bộ bố cục flash và cho phép trích xuất filesystem, reverse engineering mà không cần sửa đổi thiết bị đích đang chạy.

Trong quá trình đánh giá vật lý được ủy quyền, bản dump đã xác minh cũng có thể hỗ trợ việc sửa đổi có kiểm soát và kiểm thử nạp lại firmware. Việc này bao gồm thay đổi file hoặc chèn payload/backdoor kiểm thử để chứng minh khả năng duy trì ở cấp firmware. Hãy giữ lại nhiều bản đọc trùng khớp và image gốc trước khi ghi: sai điện áp, chọn nhầm chip, bố cục hoặc image có thể khiến thiết bị bị brick.

### Bộ lập trình và đọc EEPROM CH341A

Công cụ USB giá rẻ này có thể dump và nạp lại các thiết bị serial EEPROM và SPI flash tương thích. Công cụ thường được dùng với các chip SPI NOR flash lưu firmware BIOS/UEFI của PC và rất tiện lợi khi thời gian truy cập vật lý bị giới hạn.

![drawing](../../images/board_image_ch341a.jpg)

Kết nối flash memory với CH341A, sau đó kết nối bộ lập trình với máy tính. Nếu máy tính không nhận bộ lập trình, hãy kiểm tra cáp USB, quyền của OS và driver CH341A phù hợp trước khi xử lý sự cố với chip đích. Xác nhận điện áp của chip, chân 1, cách đấu adapter và đầu ra của bộ lập trình bằng datasheet hoặc đồng hồ đo—**không** dựa vào quy tắc như đặt VCC đối diện với đầu nối USB. Cắm sai chiều hoặc cấp 5 V cho linh kiện 3.3/1.8 V có thể phá hỏng linh kiện. Việc đọc trong mạch cũng có thể thất bại vì các thành phần còn lại trên bo mạch gây tải lên hoặc cấp nguồn cho bus.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Dùng phần mềm như `flashrom` hoặc G-Flash để đọc chip. G-Flash là GUI tối giản và có thể tự phát hiện thiết bị tương thích, tiện lợi khi cần thu thập nhanh, nhưng hãy tự xác nhận model và điện áp đã phát hiện. Chỉ định chính xác bộ lập trình và, khi cần, model chip cụ thể; đọc ít nhất hai lần rồi so sánh hash trước khi xem bản dump là đáng tin cậy.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Sau khi dump firmware, có thể phân tích các file binary. Có thể dùng các công cụ như strings, hexdump, xxd, binwalk, v.v. để trích xuất nhiều thông tin về firmware cũng như toàn bộ filesystem.

Để phân tích sơ bộ, Binwalk có thể quét các signature đã biết và trích xuất nội dung nhúng được hỗ trợ:

```
binwalk -e <filename>
```

Tệp đầu ra có thể dùng phần mở rộng `.bin`, `.rom` hoặc phần mở rộng khác; phần mở rộng không xác định định dạng tệp.

> [!CAUTION]
> Lưu ý rằng trích xuất firmware là một quy trình phức tạp, đòi hỏi nhiều kiên nhẫn. Bất kỳ thao tác sai nào cũng có thể làm hỏng firmware, thậm chí xóa hoàn toàn firmware và khiến thiết bị không thể sử dụng. Bạn nên tìm hiểu kỹ thiết bị cụ thể trước khi thử trích xuất firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Một số datasheet ghi các chân mục tiêu là `DI` và `DO`: với kết nối flash thông thường dùng một đường dữ liệu, chân **MOSI/COPI của bộ điều khiển kết nối với DI** và chân **MISO/CIPO của bộ điều khiển kết nối với DO**. Hãy kiểm tra datasheet của thiết bị mục tiêu vì các linh kiện hỗ trợ I/O kép/tứ phân dùng lại các chân này ở những chế độ khác.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Lưu ý rằng dù sơ đồ chân của Bus Pirate chỉ các chân MOSI và MISO để kết nối SPI, một số SPI có thể...](<../../images/image (360).png>)

Trên Windows hoặc Linux, bạn có thể dùng chương trình [**`flashrom`**](https://www.flashrom.org/Flashrom) để dump nội dung của bộ nhớ flash bằng cách chạy lệnh tương tự như sau:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Tài liệu Bus Pirate gần đây cũng cho thấy các tham số tùy chọn `serialspeed` và `spispeed`. Hãy bắt đầu với tốc độ thấp để thận trọng nếu dây dài hoặc tải trong mạch khiến việc đọc không ổn định.<sup>[[3]](#references)</sup>

### Đọc trong mạch khi bộ điều khiển dùng chung bus flash

Kẹp SOIC có thể cấp nguồn cho flash vào phần còn lại của PCB. Nếu MCU được cấp nguồn và truy cập cùng chip, các giao dịch SPI của nó có thể xung đột với giao dịch của bộ lập trình bên ngoài. Vì vậy, kết quả `No EEPROM/flash device found` không chứng minh rằng flash không có mặt hoặc không được hỗ trợ. Trước tiên, hãy kiểm tra sơ đồ chân, điện áp và tiếp xúc, sau đó xác định xem bộ điều khiển trên bo mạch có đang hoạt động hay không.<sup>[[4]](#references)</sup>

Nếu có điểm kiểm tra reset, hãy dùng đồng hồ đo xác nhận cực tính và điện áp trước khi kích hoạt nó. Giữ MCU ở trạng thái reset có thể giúp flash vẫn truy cập được, đồng thời ngăn host SPI cạnh tranh hoạt động. Các lựa chọn khác là tháo chip ra hoặc ghi lại thụ động các lần đọc của MCU; cách sau không thể truy cập các vùng chưa được đọc hoặc ghi vào chip, và dây đầu dò bổ sung có thể gây nhiễu bus tốc độ cao. Can thiệp vào bộ dao động hoặc chế độ khởi động phụ thuộc vào mục tiêu cụ thể, không thể thay thế việc kiểm tra sơ đồ mạch và tín hiệu.<sup>[[4]](#references)</sup>

Khi MCU được giữ ở trạng thái không hoạt động, Raspberry Pi có giao diện `spidev` đã bật có thể đọc bằng programmer `linux_spi` của flashrom. Thay đổi `-p` nếu dùng adapter khác. Đọc lại và so sánh hash trước khi tin tưởng kết quả; tính năng tự nhận diện SFDP và việc đọc thành công **không** chứng minh rằng các thao tác xóa, ghi hoặc bảo vệ ghi hoạt động trên một linh kiện vốn không được hỗ trợ.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Tái dựng dữ liệu đọc SPI flash bằng logic analyzer

Khi không thể đọc chủ động, hãy ghi lại chip select, clock, dữ liệu từ controller đến flash và dữ liệu từ flash đến controller trong lúc khởi động hoặc thực hiện một thao tác UI đã chọn. Trong PulseView, trước tiên xác định khoảng chip-select đang hoạt động và clock, sau đó cấu hình các kênh dữ liệu của bộ giải mã SPI theo sơ đồ chân flash và xác minh có lệnh/địa chỉ hợp lý, theo sau là các byte được trả về. Xuất các byte **MISO/flash-output** bằng Binary Decoder Output View và lưu lại các địa chỉ đọc đã giải mã để có thể đặt từng phản hồi tại offset flash tương ứng. Chỉ ghi lại các lần đọc do menu điều khiển sẽ chỉ thu được những vùng được yêu cầu, chứ không phải toàn bộ ảnh flash; đừng nối các phản hồi lại như thể chúng liên tiếp nhau mà không kiểm tra địa chỉ.<sup>[[4]](#references)</sup>

Nếu bản dump có vẻ chứa đồ họa thay vì mã thực thi, hãy tiếp tục với [phân loại ban đầu tài nguyên hiển thị thô](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy và bản ghi SPI/QSPI hỗn hợp

Với các probe không được gắn nhãn, hãy phân biệt MOSI với MISO bằng cách xác định đường truyền opcode trước dữ liệu phản hồi, sau đó đối chiếu lệnh với datasheet của flash. Các xung ngắn hơn chu kỳ clock có thể là nhiễu từ probe chứ không phải bit được lấy mẫu; dây nối bổ sung của clip cũng có thể khiến bản ghi tốc độ cao không đáng tin cậy.<sup>[[5]](#references)</sup>

Tệp CSV xuất từ Saleae SPI dùng `enable` và `disable` để đánh dấu khoảng chip-select, với các byte MOSI/MISO nằm trong các hàng `result`. Hãy nhóm các byte theo khoảng trước khi giải mã; nối toàn bộ dữ liệu MISO sẽ làm mất địa chỉ giao dịch.<sup>[[5]](#references)</sup> Một Scapy `Packet` có thể mô hình hóa header MOSI bằng opcode `ByteEnumField` cùng các trường địa chỉ và dummy có điều kiện. Với lệnh đọc NOR 24-bit, `0x03` gồm một opcode và ba byte địa chỉ, còn `0x0B` có thêm một byte dummy. `len(req.self_build())` cho biết độ dài header đã mô hình hóa: trong một lần đọc một lane, `miso[header_length:]` là phản hồi của flash, còn MOSI sau header là dữ liệu don't-care ở phía controller.<sup>[[5]](#references)</sup> Đặt các phản hồi tại địa chỉ đã giải mã trong ảnh được điền `0xFF` và theo dõi riêng các offset đã đọc được. Một byte chưa được quan sát không chứng minh rằng flash lưu `0xFF` tại vị trí đó.<sup>[[5]](#references)[[6]](#references)</sup>

Lệnh đọc `0x6B` (1-1-4) kiểu W25Q dùng một lane cho opcode và địa chỉ, nhưng dùng IO0–IO3 cho dữ liệu phản hồi. Hoạt động trên các chân `/WP` và `/HOLD` trước đây là bằng chứng mạnh hơn cho việc chuyển sang chế độ quad so với chỉ riêng clock nhanh hơn; analyzer một lane có thể giải mã sai phản hồi quad.<sup>[[5]](#references)</sup> Xuất pha đó bằng analyzer QSPI được cấu hình theo độ rộng lane và chu kỳ dummy của lệnh, rồi hợp nhất các lần đọc một lane và quad lane theo địa chỉ flash.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` tự động nhận diện cả hai định dạng xuất, loại bỏ các lần đọc được giải mã sai độ rộng lane và báo cáo độ phủ dữ liệu đọc.<sup>[[6]](#references)</sup> Từ repository của công cụ, sau khi cài đặt các dependency, hãy hợp nhất các bản ghi bằng lệnh sau:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

Kết quả vẫn chỉ là một quan sát thưa, không phải bản dump đầy đủ của chip.<sup>[[5]](#references)[[6]](#references)</sup> Để kiểm tra riêng các thao tác ghi, hãy đối chiếu lệnh bật ghi `0x06`, các lần thăm dò trạng thái `0x05`, opcode xóa và lệnh ghi trang `0x02`. Dữ liệu ghi trang đi theo địa chỉ trên MOSI và không được đưa vào quá trình tái dựng chỉ đọc.<sup>[[5]](#references)</sup> Phân tích image thu được bằng [firmware analysis](../firmware-analysis/) và lưu giữ thông tin về phạm vi đọc.

## References

- [1] [Analog Devices — Giới thiệu về giao diện SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Hướng dẫn sử dụng flashrom — Bộ lập trình SPI CH341A và các tùy chọn đọc/ghi](https://flashrom.org/classic_cli_manpage.html)
- [3] [Tài liệu Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Ôn lại hardware hacking, phần 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Mở rộng Scapy cho kỹ thuật đảo ngược phần cứng](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — Ghi lại và tái dựng trace SPI/QSPI](https://github.com/wrongbaud/spidump)
- [7] [Bộ phân tích QSPI cho Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
