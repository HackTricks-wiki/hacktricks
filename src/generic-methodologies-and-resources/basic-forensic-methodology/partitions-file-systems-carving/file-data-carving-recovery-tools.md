# Công cụ carving và khôi phục tệp/dữ liệu

{{#include ../../../banners/hacktricks-training.md}}

## Công cụ carving và khôi phục

Luôn thực hiện carving trên **bản sao đã xác minh**, không phải thiết bị gốc. Xem [Thu thập ảnh & Mount](../image-acquisition-and-mount.md) để biết quy trình thu thập chỉ đọc và tạo hash.

Xem thêm công cụ tại [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Công cụ phổ biến nhất dùng trong pháp chứng để trích xuất tệp từ image là [**Autopsy**](https://www.autopsy.com/download/). Tải xuống, cài đặt và yêu cầu công cụ xử lý tệp để tìm các tệp “ẩn”. Lưu ý rằng Autopsy được xây dựng để hỗ trợ image đĩa và các loại image khác, nhưng không hỗ trợ các tệp đơn giản.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** là công cụ phân tích tệp nhị phân để tìm nội dung được nhúng. **Binwalk v3** là phiên bản viết lại bằng Rust, hỗ trợ tự động trích xuất (`-e`), carving thô các đối tượng đã biết và chưa biết (`-c`), quét đệ quy/Matryoshka (`-M`) và cấu hình số luồng worker. Dự án khuyến nghị dùng bản Docker khi cần tất cả trình trích xuất bên ngoài; `cargo install binwalk` cài đặt CLI Rust nhưng không cài các dependency bên ngoài đó.<sup>[[11]](#references)</sup>

**Các lệnh v3 hữu ích**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Công thức `--dd='.*'` của v2 cũ **không** tương đương với `-c` của v3; trước tiên hãy kiểm tra `binwalk --version` khi làm theo các lệnh cũ trong CTF/write-up.<sup>[[11]](#references)</sup>

⚠️  **Lưu ý bảo mật** – Các phiên bản từ **2.1.2b đến 2.3.3** bị ảnh hưởng bởi lỗ hổng **Path Traversal** (CVE-2022-4510); thông báo bảo mật không liệt kê phiên bản pip nào đã được vá. Tránh giải nén các mẫu không đáng tin cậy bằng những phiên bản bị ảnh hưởng, hoặc cô lập công cụ bằng container/UID không có đặc quyền.<sup>[[4]](#references)</sup>

### Foremost

Một công cụ phổ biến khác để tìm các tệp ẩn là **foremost**. Bạn có thể tìm tệp cấu hình của foremost tại `/etc/foremost.conf`. Nếu chỉ muốn tìm một số loại tệp cụ thể, hãy bỏ chú thích các mục tương ứng. Nếu không bỏ chú thích mục nào, foremost sẽ tìm các loại tệp được cấu hình mặc định.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** là một công cụ khác có thể dùng để tìm và trích xuất **các tệp được nhúng trong một tệp**. Trong trường hợp này, bạn cần bỏ chú thích các loại tệp muốn trích xuất trong tệp cấu hình (_/etc/scalpel/scalpel.conf_).

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3 phục hồi phân mảnh

Khi phục hồi ưu tiên metadata và các công cụ carve liên tục không khôi phục đầy đủ được các tệp bị chia tách, **Scalpel3** có thể ghép lại các định dạng được hỗ trợ bằng trình xác thực tệp/khối. Đây là codebase khác với lệnh `scalpel` cũ ở trên. Trước tiên, hãy tạo blockmap cần thiết với **cùng kích thước khối** được dùng khi carve; nếu đã biết, hãy dùng kích thước cluster của hệ thống tệp từ `fsstat`, hoặc xác định giá trị có cơ sở trước khi quét ảnh phân vùng. Chỉ chạy trên bản sao đã xác minh và lưu kết quả trên một volume riêng.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Thay `4096` bằng kích thước block đã chọn. `-w` giữ lại các ứng viên **PROMISING** cũng như các ứng viên đã được xác thực, còn `-b` ghi blockvector để hỗ trợ kiểm tra bố cục được tái dựng. Một tệp nằm trong PROMISING, hoặc có phần mở rộng quen thuộc, không chứng minh rằng dữ liệu đã được khôi phục hoàn chỉnh; hãy xác thực nội dung trước khi sử dụng.<sup>[[13]](#references)[[14]](#references)</sup> Để tìm các phân vùng đã xóa hoặc khoảng trống trước khi carving, xem [Tìm dữ liệu bên ngoài các phân vùng được liệt kê](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Công cụ này có sẵn trong Kali, nhưng bạn cũng có thể tìm thấy tại đây: <https://github.com/simsong/bulk_extractor>

Bulk Extractor có thể quét ảnh chứng cứ và carving **các mảnh pcap**, **các tạo tác mạng (URL, domain, IP, MAC, e-mail)** cùng nhiều đối tượng khác **song song bằng nhiều scanner**.

Bản phát hành v2.1.1 ghi lại cách build bằng Autotools và thiết lập `-S jpeg_carve_mode=2` để carving tất cả JPEG liền kề nhau.<sup>[[2]](#references)</sup>

```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```

Tệp `bulk_diff.py` đi kèm dùng để so sánh hai lần chạy bulk_extractor, còn `bulk_extractor_reader.py` đọc các tệp báo cáo và feature.<sup>[[3]](#references)</sup>

### PhotoRec

Bạn có thể tải công cụ tại <https://www.cgsecurity.org/wiki/TestDisk_Download>

Công cụ có cả phiên bản GUI và CLI. Bạn có thể chọn **các loại tệp** mà mình muốn PhotoRec tìm kiếm.

![Chạy mọi scanner, carve JPEG thật mạnh và tạo bodyfile - PhotoRec: Công cụ có cả phiên bản GUI và CLI. Bạn có thể chọn các loại tệp mà mình muốn PhotoRec tìm kiếm](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (ưu tiên metadata)

Trước khi raw signature carving, hãy thử khôi phục dựa trên filesystem khi metadata của volume vẫn có thể phân tích được. Theo mặc định, `tsk_recover` chỉ xuất các tệp chưa được cấp phát; `-a` chọn các tệp đã được cấp phát và `-e` xuất cả hai loại. Với ảnh toàn bộ ổ đĩa, hãy truyền **sector bắt đầu** của partition lấy từ `mmls` vào `-o` (không chuyển đổi sang byte). Nếu đầu vào đã là ảnh partition, hãy bỏ qua `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Lượt xử lý này có thể giữ lại tên và đường dẫn lấy từ hệ thống tệp mà kỹ thuật carving header/footer không thể giữ; sau đó chạy Foremost, Scalpel hoặc PhotoRec cho các mục bị thiếu metadata hoặc có metadata không sử dụng được.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (tạo image từ ổ đĩa đang hỏng)

Khi ổ đĩa vật lý không ổn định, thông lệ tốt nhất là **tạo image trước** rồi chỉ chạy các công cụ carving trên image. `ddrescue` (dự án GNU) tập trung vào việc sao chép ổ đĩa bị lỗi một cách đáng tin cậy, đồng thời lưu nhật ký các sector không thể đọc.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

Tùy chọn **`--cluster-size`** kiểm soát số sector được sao chép mỗi lần; giá trị nhỏ hơn có thể hữu ích với ổ đĩa chậm.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (khôi phục tệp đã xóa trên EXT 3/4)

Nếu hệ thống tệp nguồn dựa trên Linux EXT, bạn có thể khôi phục các tệp mới bị xóa **mà không cần carving toàn bộ**; những công cụ dựa trên journal này hoạt động trên hệ thống tệp đã tháo gắn hoặc ảnh chỉ đọc.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Ghi chú về khả năng tương thích** – ext4magic đã bị bỏ dở; trang dự án cảnh báo rằng các hệ thống tệp hiện nay không còn tương thích với nó.<sup>[[10]](#references)</sup>

> 🛈 Nếu hệ thống tệp được mount sau khi xóa, các khối dữ liệu có thể đã được tái sử dụng – trong trường hợp đó vẫn cần thực hiện carving đúng cách (Foremost/Scalpel).

### binvis

Xem [mã nguồn](https://code.google.com/archive/p/binvis/) và [công cụ trên trang web](https://binvis.io/#/).

#### Tính năng của BinVis

- **Trình xem cấu trúc** trực quan và tương tác
- Nhiều biểu đồ cho các điểm cần tập trung khác nhau
- Tập trung vào từng phần của mẫu
- **Xem các chuỗi và tài nguyên**, chẳng hạn trong tệp thực thi PE hoặc ELF
- Tìm **mẫu** để phân tích mật mã trên các tệp
- **Phát hiện** thuật toán đóng gói hoặc mã hóa
- **Nhận diện** Steganography qua các mẫu
- **So sánh nhị phân** bằng hình ảnh

BinVis là một **điểm khởi đầu** tuyệt vời để làm quen với một mục tiêu chưa biết trong tình huống black-boxing.

## Công cụ Data Carving chuyên dụng

### FindAES

Tìm kiếm khóa AES bằng cách dò các lịch khóa tương ứng. Có thể tìm khóa 128, 192 và 256 bit, chẳng hạn như các khóa được TrueCrypt và BitLocker sử dụng.

Tải xuống [tại đây](https://sourceforge.net/projects/findaes/).

### YARA-X (phân loại sơ bộ các artefact đã carve)

[YARA-X](https://github.com/VirusTotal/yara-x) là bản viết lại YARA bằng Rust, được giới thiệu vào năm 2024; VirusTotal cho biết một số quy tắc biểu thức chính quy và vòng lặp phức tạp có thể chạy nhanh hơn đáng kể.<sup>[[5]](#references)</sup> CLI của nó có tên là `yr`, và lệnh `scan` hỗ trợ quét đệ quy, chỉ định số luồng và xuất metadata.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Công cụ bổ trợ

Bạn có thể dùng [**viu** ](https://github.com/atanunq/viu)để xem hình ảnh từ terminal.  \
Bạn có thể dùng công cụ dòng lệnh **pdftotext** của Linux để chuyển đổi PDF thành văn bản rồi đọc.







## References

- [1] [Ghi chú phát hành Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README các công cụ Python của bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal trong binwalk (CVE-2022-4510) - Cơ sở dữ liệu tư vấn bảo mật GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA đã chết, YARA-X trường tồn - Blog VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Các lệnh CLI của YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Sổ tay GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Sổ tay ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Trạng thái dự án ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: sổ tay tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [README Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Sổ tay Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Quy trình kiểm thử Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
