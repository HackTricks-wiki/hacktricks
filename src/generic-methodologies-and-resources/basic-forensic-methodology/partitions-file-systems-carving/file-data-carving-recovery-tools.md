# Công cụ Carving và khôi phục file/dữ liệu

{{#include ../../../banners/hacktricks-training.md}}

## Công cụ Carving và khôi phục

Luôn thực hiện carving trên **bản sao đã xác minh**, không phải thiết bị gốc. Xem [Image Acquisition & Mount](../image-acquisition-and-mount.md) để biết quy trình thu thập chỉ đọc và tạo hash.

Xem thêm công cụ tại [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Công cụ phổ biến nhất được dùng trong pháp chứng để trích xuất file từ image là [**Autopsy**](https://www.autopsy.com/download/). Tải xuống, cài đặt và yêu cầu công cụ quét file để tìm các file "ẩn". Lưu ý rằng Autopsy được xây dựng để hỗ trợ disk image và các loại image khác, nhưng không hỗ trợ các file thông thường.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** là công cụ phân tích file nhị phân để tìm nội dung được nhúng. **Binwalk v3** là phiên bản viết lại bằng Rust, có khả năng tự động trích xuất (`-e`), carving thô các đối tượng đã biết và chưa biết (`-c`), quét đệ quy/Matryoshka (`-M`) và cấu hình số luồng worker. Dự án khuyến nghị dùng bản Docker khi cần tất cả extractor bên ngoài; `cargo install binwalk` cài CLI Rust nhưng không cài các dependency bên ngoài đó.<sup>[[11]](#references)</sup>

**Các lệnh v3 hữu ích**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Recipe cũ `--dd='.*'` của v2 **không** tương đương với `-c` của v3; hãy kiểm tra `binwalk --version` trước khi chạy các lệnh từ CTF/write-up cũ.<sup>[[11]](#references)</sup>

⚠️  **Lưu ý bảo mật** – Các phiên bản từ **2.1.2b đến 2.3.3** bị ảnh hưởng bởi lỗ hổng **Path Traversal** (CVE-2022-4510); advisory không liệt kê phiên bản pip nào đã vá lỗi. Tránh giải nén các mẫu không đáng tin cậy bằng những bản phát hành bị ảnh hưởng, hoặc cô lập công cụ bằng container/UID không có đặc quyền.<sup>[[4]](#references)</sup>

### Foremost

Một công cụ phổ biến khác để tìm các tệp ẩn là **foremost**. Bạn có thể tìm tệp cấu hình của foremost tại `/etc/foremost.conf`. Nếu chỉ muốn tìm một số loại tệp cụ thể, hãy bỏ chú thích các mục tương ứng. Nếu không bỏ chú thích mục nào, foremost sẽ tìm kiếm các loại tệp được cấu hình mặc định.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** là một công cụ khác có thể dùng để tìm và trích xuất **các tệp được nhúng trong một tệp**. Trong trường hợp này, bạn cần bỏ dấu chú thích trong tệp cấu hình (_/etc/scalpel/scalpel.conf_) ở các loại tệp mà bạn muốn trích xuất.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Bulk Extractor 2.x   

Công cụ này có sẵn trong kali, nhưng bạn có thể tìm thấy tại đây: <https://github.com/simsong/bulk_extractor>

Bulk Extractor có thể quét ảnh chứng cứ và carve **các mảnh pcap**, **các tạo tác mạng (URL, domain, IP, MAC, e-mail)** cùng nhiều đối tượng khác **song song bằng nhiều scanner**.

Bản phát hành v2.1.1 ghi lại cách build bằng Autotools và thiết lập `-S jpeg_carve_mode=2` để carve tất cả các ảnh JPEG liền kề.<sup>[[2]](#references)</sup>

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

The đi kèm `bulk_diff.py` so sánh hai lần chạy `bulk_extractor`, trong khi `bulk_extractor_reader.py` đọc các tệp báo cáo và đặc trưng.<sup>[[3]](#references)</sup>

### PhotoRec

Bạn có thể tìm thấy công cụ này tại <https://www.cgsecurity.org/wiki/TestDisk_Download>

Công cụ này có phiên bản GUI và CLI. Bạn có thể chọn **các loại tệp** mà PhotoRec cần tìm.

![Chạy mọi scanner, carve JPEG thật mạnh và tạo bodyfile - PhotoRec: Công cụ này có phiên bản GUI và CLI. Bạn có thể chọn các loại tệp mà PhotoRec cần tìm](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (khôi phục ưu tiên metadata)

Trước khi carve chữ ký thô, hãy thử khôi phục có xét đến hệ thống tệp khi metadata của volume vẫn có thể phân tích được. Theo mặc định, `tsk_recover` chỉ xuất các tệp chưa được cấp phát; `-a` chọn các tệp đã được cấp phát, còn `-e` xuất cả hai loại. Với ảnh toàn bộ đĩa, hãy truyền **sector bắt đầu** của phân vùng lấy từ `mmls` cho `-o` (không chuyển đổi sang byte). Nếu đầu vào đã là ảnh phân vùng, hãy bỏ qua `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Lượt xử lý này có thể giữ lại tên và đường dẫn lấy từ filesystem mà phương pháp carving header/footer không thể giữ; sau đó chạy Foremost, Scalpel hoặc PhotoRec cho các mục bị thiếu hoặc có metadata không sử dụng được.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (tạo image cho ổ đĩa đang bị lỗi)

Khi ổ đĩa vật lý không ổn định, cách làm tốt nhất là **tạo image trước** rồi chỉ chạy các công cụ carving trên image đó. `ddrescue` (dự án GNU) tập trung vào việc sao chép các đĩa bị lỗi một cách đáng tin cậy, đồng thời lưu nhật ký các sector không thể đọc được.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

Tùy chọn **`--cluster-size`** kiểm soát số sector được sao chép mỗi lần; giá trị nhỏ hơn có thể hữu ích với các ổ đĩa chậm.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (khôi phục file đã xóa trên EXT 3/4)

Nếu hệ thống tệp nguồn dựa trên Linux EXT, bạn có thể khôi phục các file mới bị xóa **mà không cần carving toàn bộ**; các công cụ dựa trên journal này hoạt động trên hệ thống tệp đã unmount hoặc image chỉ đọc.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Lưu ý về khả năng tương thích** – ext4magic đã bị bỏ rơi; trang dự án cảnh báo rằng các hệ thống tệp hiện tại không còn tương thích với công cụ này.<sup>[[10]](#references)</sup>

> 🛈 Nếu hệ thống tệp đã được mount sau khi xóa, các khối dữ liệu có thể đã được sử dụng lại – trong trường hợp đó, vẫn cần thực hiện carving đúng cách (Foremost/Scalpel).

### binvis

Xem [mã nguồn](https://code.google.com/archive/p/binvis/) và [công cụ trên trang web](https://binvis.io/#/).

#### Các tính năng của BinVis

- **Trình xem cấu trúc** trực quan và tương tác
- Nhiều biểu đồ tập trung vào các điểm khác nhau
- Tập trung vào các phần của mẫu
- **Xem các chuỗi và tài nguyên**, ví dụ trong tệp thực thi PE hoặc ELF
- Tìm **mẫu** để cryptanalysis trên các tệp
- **Phát hiện** thuật toán packer hoặc encoder
- **Nhận diện** Steganography qua các mẫu
- **So sánh khác biệt** nhị phân trực quan

BinVis là một điểm khởi đầu tuyệt vời để làm quen với một mục tiêu chưa biết trong kịch bản black-box.

## Công cụ Data Carving chuyên dụng

### FindAES

Tìm kiếm các khóa AES bằng cách tìm kiếm key schedule của chúng. Có thể tìm các khóa 128, 192 và 256 bit, chẳng hạn như các khóa được TrueCrypt và BitLocker sử dụng.

Tải xuống [tại đây](https://sourceforge.net/projects/findaes/).

### YARA-X (phân loại sơ bộ các artefact đã carve)

[YARA-X](https://github.com/VirusTotal/yara-x) là bản viết lại YARA bằng Rust, được giới thiệu vào năm 2024; VirusTotal cho biết một số quy tắc biểu thức chính quy và vòng lặp phức tạp có thể chạy nhanh hơn đáng kể.<sup>[[5]](#references)</sup> CLI của công cụ có tên `yr`, và lệnh `scan` hỗ trợ quét đệ quy, chỉ định số luồng và xuất metadata.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Công cụ bổ trợ

Bạn có thể dùng [**viu** ](https://github.com/atanunq/viu)để xem hình ảnh từ terminal.  \
Bạn có thể dùng công cụ dòng lệnh **pdftotext** trên Linux để chuyển PDF thành văn bản và đọc.





## References

- [1] [Ghi chú phát hành Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README của bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README của các công cụ Python cho bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal trong binwalk (CVE-2022-4510) - Cơ sở dữ liệu tư vấn bảo mật GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA đã chết, YARA-X muôn năm - Blog VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Các lệnh CLI của YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Hướng dẫn sử dụng GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Hướng dẫn sử dụng ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Trạng thái dự án ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README của Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: hướng dẫn sử dụng tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
