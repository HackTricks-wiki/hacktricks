# Phân vùng/Hệ thống tệp/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Phân vùng

Một ổ đĩa có thể chứa nhiều **phân vùng**: các dải khối logic, không phải vùng lưu trữ tách biệt về mặt vật lý. Điểm bắt đầu và độ dài của phân vùng được tính bằng **sector logic**; đừng mặc định mọi image đều dùng sector 512 byte, vì cũng có sector logic 4096 byte.<sup>[[4]](#references)</sup>

### MBR (master Boot Record)

MBR chiếm sector logic đầu tiên (LBA 0); bốn mục phân vùng, mỗi mục 16 byte, bắt đầu tại byte 446. Vùng đứng trước đó chứa mã khởi động và có thể có chữ ký ổ đĩa.<sup>[[4]](#references)</sup>\
MBR hỗ trợ tối đa **4 phân vùng** (nhiều nhất **chỉ 1** phân vùng có thể được đánh dấu là active/**bootable**). Tuy nhiên, nếu cần thêm phân vùng, bạn có thể dùng **phân vùng mở rộng**. **Hai byte** cuối của MBR 512 byte là chữ ký khởi động **0x55 0xAA**. Chỉ một phân vùng có thể được đánh dấu là active.\
Với sector logic 512 byte, các trường sector 32-bit của MBR giới hạn khả năng định địa chỉ ở khoảng **2 TiB** (2.2 TB).<sup>[[4]](#references)</sup>

![Phân vùng - MBR (master Boot Record): MBR hỗ trợ tối đa 2.2TB](<../../../images/image (350).png>)

![Phân vùng - MBR (master Boot Record): MBR hỗ trợ tối đa 2.2TB](<../../../images/image (304).png>)

Trong các **byte từ 440 đến 443** của MBR, bạn có thể tìm thấy **Windows Disk Signature** (nếu dùng Windows). Ký tự ổ đĩa logic phụ thuộc vào Windows Disk Signature. Thay đổi chữ ký này có thể khiến Windows không khởi động được (công cụ: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Phân vùng - MBR (master Boot Record): Trong các byte từ 440 đến 443 của MBR, bạn có thể tìm thấy Windows Disk Signature (nếu dùng Windows). Ký tự ổ đĩa logic của ổ cứng...](<../../../images/image (310).png>)

**Định dạng**

| Offset      | Length     | Item                     |
| ----------- | ---------- | ------------------------ |
| 0 (0x00)    | 446(0x1BE) | Mã khởi động             |
| 446 (0x1BE) | 16 (0x10)  | Phân vùng thứ nhất       |
| 462 (0x1CE) | 16 (0x10)  | Phân vùng thứ hai        |
| 478 (0x1DE) | 16 (0x10)  | Phân vùng thứ ba         |
| 494 (0x1EE) | 16 (0x10)  | Phân vùng thứ tư         |
| 510 (0x1FE) | 2 (0x2)    | Chữ ký 0x55 0xAA         |

**Định dạng bản ghi phân vùng**

| Offset    | Length   | Item                                                          |
| --------- | -------- | ------------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Cờ active (0x80 = bootable)                                   |
| 1 (0x01)  | 1 (0x01) | Head bắt đầu                                                  |
| 2 (0x02)  | 1 (0x01) | Sector bắt đầu (bit 0-5); các bit cao của cylinder (6- 7)     |
| 3 (0x03)  | 1 (0x01) | 8 bit thấp nhất của cylinder bắt đầu                         |
| 4 (0x04)  | 1 (0x01) | Mã loại phân vùng (0x83 = Linux)                              |
| 5 (0x05)  | 1 (0x01) | Head kết thúc                                                 |
| 6 (0x06)  | 1 (0x01) | Sector kết thúc (bit 0-5); các bit cao của cylinder (6- 7)    |
| 7 (0x07)  | 1 (0x01) | 8 bit thấp nhất của cylinder kết thúc                        |
| 8 (0x08)  | 4 (0x04) | Số sector trước phân vùng (little endian)                     |
| 12 (0x0C) | 4 (0x04) | Số sector trong phân vùng                                     |

Để kiểm tra một phân vùng trong image MBR của toàn bộ ổ đĩa, trước tiên hãy lấy LBA bắt đầu và kích thước sector logic của phân vùng đó. `mount` nhận **độ lệch tính bằng byte**, không phải LBA; ví dụ bên dưới chỉ hợp lệ với image có sector 512 byte và phân vùng bắt đầu tại LBA 63. Với image không đáng tin cậy hoặc hệ thống tệp có journal, hãy sử dụng quy trình cách ly, chỉ đọc trong [Image Acquisition & Mount](../image-acquisition-and-mount.md).<sup>[[5]](#references)[[11]](#references)</sup>

![Phân vùng - MBR (master Boot Record): Để mount MBR trong Linux, trước tiên bạn cần lấy offset bắt đầu (có thể dùng fdisk và lệnh p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Định địa chỉ khối logic** (**LBA**) là một phương thức phổ biến dùng để **chỉ định vị trí các khối** dữ liệu được lưu trên thiết bị lưu trữ máy tính, thường là các hệ thống lưu trữ thứ cấp như ổ đĩa cứng. LBA là một phương thức định địa chỉ tuyến tính đặc biệt đơn giản; **các khối được xác định bằng chỉ số nguyên**, trong đó khối đầu tiên là LBA 0, khối thứ hai là LBA 1, v.v.

### GPT (GUID Partition Table)

GUID Partition Table (GPT) lưu một GUID duy nhất cho mỗi phân vùng và sử dụng metadata chính cùng bản sao lưu. Bố cục của nó khác với MBR như sau:<sup>[[4]](#references)</sup>

- **Vị trí và kích thước**: LBA 0 chứa một **protective MBR**. Header GPT chính nằm tại LBA 1; mảng mục phân vùng nằm ngay sau đó, còn mảng và header sao lưu nằm ở cuối đĩa. GPT sử dụng các trường LBA 64-bit, trong khi các mục phân vùng MBR sử dụng trường LBA 32-bit.
- **Giới hạn phân vùng**: Một mảng mục 16-KiB phổ biến chứa **128 mục, mỗi mục 128 byte**, nhưng số lượng mục được ghi trong header thay vì được GPT cố định. Kích thước có thể định địa chỉ cũng phụ thuộc vào kích thước sector logic (khoảng **9.4 ZB** với sector 512 byte).<sup>[[4]](#references)</sup>
- **Tên phân vùng**: Cho phép đặt tên phân vùng bằng tối đa 36 ký tự Unicode.

**Khả năng phục hồi và khôi phục dữ liệu**:

- **Dư thừa**: Không giống MBR, GPT không giới hạn dữ liệu phân vùng và khởi động ở một vị trí duy nhất. GPT sao chép dữ liệu này trên toàn đĩa, giúp tăng tính toàn vẹn và khả năng phục hồi dữ liệu.
- **Kiểm tra dư thừa tuần hoàn (CRC)**: Header và mảng mục phân vùng đều có CRC32. CRC phát hiện sự không nhất quán; nó không liên tục giám sát hoặc tự sửa chữa đĩa. Nếu bản sao chính không hợp lệ, hãy xác thực bản sao lưu tại LBA cuối cùng trước khi khôi phục trên một bản sao đang hoạt động.<sup>[[4]](#references)</sup>

**Protective MBR (LBA0)**:

- GPT duy trì khả năng tương thích ngược thông qua protective MBR. Tính năng này nằm trong vùng MBR cũ, nhưng được thiết kế để ngăn các tiện ích dựa trên MBR đời cũ vô tình ghi đè lên đĩa GPT, nhờ đó bảo vệ tính toàn vẹn dữ liệu trên các đĩa được định dạng GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Trong các hệ điều hành hỗ trợ **khởi động dựa trên GPT thông qua** dịch vụ **BIOS** thay vì EFI, sector đầu tiên vẫn có thể được dùng để lưu mã giai đoạn đầu của **bootloader**, nhưng được **chỉnh sửa** để nhận diện các **phân vùng** **GPT**. Bootloader trong MBR không được giả định rằng kích thước sector là 512 byte.

**Header bảng phân vùng (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Header bảng phân vùng xác định các khối có thể sử dụng trên đĩa. Header cũng xác định số lượng và kích thước của các mục phân vùng tạo nên bảng phân vùng (offset 80 và 84 trong bảng).

| Offset    | Độ dài   | Nội dung                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 byte   | Chữ ký ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h hoặc 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)trên máy little-endian) |
| 8 (0x08)  | 4 byte   | Revision 1.0 (00h 00h 01h 00h) cho UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 byte   | Kích thước header theo little-endian (tính bằng byte, thường là 5Ch 00h 00h 00h hoặc 92 byte)                                                                                |
| 16 (0x10) | 4 byte   | [CRC32](https://en.wikipedia.org/wiki/CRC32) của header (từ offset +0 đến hết kích thước header), theo little-endian; trường này được đặt thành zero trong quá trình tính toán |
| 20 (0x14) | 4 byte   | Dành riêng; phải bằng zero                                                                                                                                                   |
| 24 (0x18) | 8 byte   | LBA hiện tại (vị trí của bản sao header này)                                                                                                                                 |
| 32 (0x20) | 8 byte   | LBA sao lưu (vị trí của bản sao header còn lại)                                                                                                                              |
| 40 (0x28) | 8 byte   | LBA đầu tiên có thể sử dụng cho các phân vùng (LBA cuối cùng của bảng phân vùng chính + 1)                                                                                   |
| 48 (0x30) | 8 byte   | LBA cuối cùng có thể sử dụng (LBA đầu tiên của bảng phân vùng phụ − 1)                                                                                                       |
| 56 (0x38) | 16 byte  | GUID đĩa theo mixed-endian                                                                                                                                                   |
| 72 (0x48) | 8 byte   | LBA bắt đầu của mảng mục phân vùng (luôn là 2 trong bản sao chính)                                                                                                           |
| 80 (0x50) | 4 byte   | Số lượng mục phân vùng trong mảng                                                                                                                                           |
| 84 (0x54) | 4 byte   | Kích thước của một mục phân vùng (thường là 80h hoặc 128)                                                                                                                    |
| 88 (0x58) | 4 byte   | CRC32 của mảng mục phân vùng theo little-endian                                                                                                                              |
| 92 (0x5C) | \*       | Dành riêng; phần còn lại của khối phải là zero (420 byte với sector có kích thước 512 byte; có thể lớn hơn nếu sector có kích thước lớn hơn)                                |

**Các mục phân vùng (LBA 2–33)**

| Định dạng mục phân vùng GUID |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Độ dài   | Nội dung                                                                                                      |
| 0 (0x00)                    | 16 byte  | [GUID loại phân vùng](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed-endian) |
| 16 (0x10)                   | 16 byte  | GUID phân vùng duy nhất (mixed-endian)                                                                        |
| 32 (0x20)                   | 8 byte   | LBA đầu tiên ([little-endian](https://en.wikipedia.org/wiki/Little_endian))                                    |
| 40 (0x28)                   | 8 byte   | LBA cuối cùng (bao gồm, thường là số lẻ)                                                                       |
| 48 (0x30)                   | 8 byte   | Cờ thuộc tính (ví dụ: bit 60 biểu thị chỉ đọc)                                                                 |
| 56 (0x38)                   | 72 byte  | Tên phân vùng (36 đơn vị mã [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                                 |

**Các loại phân vùng**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Xem thêm các loại phân vùng tại [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Kiểm tra

Sau khi gắn image forensics bằng [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), bạn có thể kiểm tra sector đầu tiên bằng công cụ Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Trong hình sau, một **MBR** được phát hiện tại **sector 0** và được diễn giải:

![GPT (GUID Partition Table) - Kiểm tra: Sau khi gắn image forensics bằng ArsenalImageMounter, bạn có thể kiểm tra sector đầu tiên bằng công cụ Windows Active Disk Editor. Trong hình...](<../../../images/image (354).png>)

Với GPT, hãy tìm chữ ký _EFI PART_ trong header chính tại **LBA 1**; LBA 0 vẫn chứa protective MBR.<sup>[[4]](#references)</sup>

### Tìm dữ liệu bên ngoài các phân vùng được liệt kê

Một mục phân vùng đã xóa hoặc khoảng trống cố ý để lại có thể khiến filesystem nằm ngoài bản đồ phân vùng hiện tại. Trên một **bản sao làm việc thô đã được xác minh**, hãy liệt kê các phạm vi chưa được cấp phát, sau đó kiểm tra một LBA bắt đầu tiềm năng như một filesystem. `mmls` và `fsstat` sử dụng **offset sector**; hãy cung cấp kích thước sector logic thực tế cho cả hai. Đừng nhầm các sector metadata GPT với một volume ẩn.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

Nếu `fsstat` không thể xác định hệ thống tệp tại đầu khoảng trống, hãy dùng TestDisk **Analyse → Quick Search**, rồi **Deeper Search** nếu cần. Nhấn `P` trên phân vùng tiềm năng để kiểm tra tệp; không chọn **Write** trên bằng chứng. Với ảnh GPT, `sgdisk --verify disk.img` kiểm tra CRC và sự nhất quán giữa bản chính/bản sao lưu, nhưng header sao lưu có thể đã cũ sau khi phân vùng lại, vì vậy hãy đối chiếu ranh giới phân vùng tiềm năng với các cấu trúc hệ thống tệp trước khi khôi phục.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Hệ thống tệp

### Danh sách hệ thống tệp Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Hệ thống tệp **FAT (File Allocation Table)** được thiết kế xoay quanh thành phần cốt lõi là bảng cấp phát tệp, nằm ở đầu volume. Volume thường có **hai bản sao FAT**, dù BPB cho phép chỉ có một. FAT12/16 đặt thư mục gốc trong một vùng cố định; FAT32 lưu thư mục gốc trong vùng dữ liệu, tại cluster được chỉ định bởi `BPB_RootClus`.<sup>[[7]](#references)</sup>

Đơn vị cấp phát là một **cluster**: `BPB_BytsPerSec × BPB_SecPerClus`, không nhất thiết là 512 byte. Loại FAT được xác định dựa trên số lượng cluster dữ liệu, không phải chuỗi phiên bản trong boot sector. Các ngưỡng số lượng cluster là:<sup>[[7]](#references)</sup>

- **FAT12**: ít hơn 4,085 cluster dữ liệu.
- **FAT16**: từ 4,085 đến 65,524 cluster dữ liệu.
- **FAT32**: ít nhất 65,525 cluster dữ liệu; chỉ 28 bit trong mỗi mục FAT 32 bit được dùng làm số cluster.

Trường kích thước tệp 32 bit giới hạn tệp thông thường ở mức **2³²−1 byte** (chưa đến 4 GiB).<sup>[[7]](#references)</sup>

Các thành phần chính của thư mục gốc, đặc biệt với FAT12 và FAT16, bao gồm:

- **Tên tệp/thư mục** (tối đa 8 ký tự)
- **Thuộc tính**
- **Ngày tạo, sửa đổi và truy cập gần nhất**
- **Địa chỉ bảng FAT** (cho biết cluster bắt đầu của tệp)
- **Kích thước tệp**

### EXT

**Ext2** là hệ thống tệp phổ biến nhất cho các phân vùng **không dùng journaling** (**các phân vùng ít thay đổi**) như phân vùng boot. **Ext3/4** dùng **journaling** và thường được sử dụng cho **các phân vùng còn lại**.

## **Metadata**

Một số tệp chứa metadata. Thông tin này mô tả nội dung tệp và đôi khi có thể hữu ích với chuyên viên phân tích; tùy loại tệp, metadata có thể chứa những thông tin như:

- Tiêu đề
- Phiên bản MS Office được sử dụng
- Tác giả
- Ngày tạo và sửa đổi gần nhất
- Kiểu máy ảnh
- Tọa độ GPS
- Thông tin hình ảnh

Bạn có thể dùng các công cụ như [**exiftool**](https://exiftool.org) và [**Metadiver**](https://www.easymetadata.com/metadiver-2/) để lấy metadata của tệp.

## **Khôi phục tệp đã xóa**

### Tệp đã xóa được ghi nhận

Như đã thấy trước đó, có một số nơi mà tệp vẫn được lưu sau khi bị “xóa”. Lý do là thao tác xóa tệp khỏi hệ thống tệp thường chỉ đánh dấu tệp là đã xóa, chứ không đụng đến dữ liệu. Vì vậy, có thể kiểm tra các bản ghi của tệp (chẳng hạn như MFT) để tìm các tệp đã xóa.<sup>[[2]](#references)</sup>

Ngoài ra, hệ điều hành thường lưu nhiều thông tin về các thay đổi của hệ thống tệp và bản sao lưu, nên có thể thử dùng chúng để khôi phục tệp hoặc càng nhiều thông tin càng tốt.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** là kỹ thuật tìm **tệp trong khối dữ liệu**. Các công cụ dạng này hoạt động theo 3 cách chính: **dựa trên header và footer của loại tệp**, dựa trên **cấu trúc** của loại tệp và dựa trên chính **nội dung**.

File carving đơn giản dựa trên header/footer giả định dữ liệu nằm trong các khối liên tục và có thể chỉ trả về một phần nếu tệp bị phân mảnh. Đây không phải là giới hạn tuyệt đối: PhotoRec có tùy chọn **Paranoid → bruteforce** tốn nhiều CPU cho một số JPEG bị phân mảnh, trong khi phương pháp ghép lại các mảnh có nhận biết định dạng có thể khôi phục những loại tệp được hỗ trợ khác. Xem [các công cụ file carving và khôi phục](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) để biết quy trình ghép lại các mảnh hiện hành.<sup>[[8]](#references)</sup>

Có một số công cụ bạn có thể dùng để file carving bằng cách chỉ định các loại tệp cần tìm.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **Data Stream C**arving

Data Stream Carving tương tự File Carving nhưng **thay vì tìm các tệp hoàn chỉnh, kỹ thuật này tìm các mảnh thông tin đáng chú ý**.\
Ví dụ, thay vì tìm một tệp hoàn chỉnh chứa các URL được ghi lại, kỹ thuật này sẽ tìm URL.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Xóa an toàn

Rõ ràng, có những cách để **xóa tệp và một phần nhật ký về chúng một cách “an toàn”**. Ví dụ, có thể **ghi đè nội dung** của tệp bằng dữ liệu rác nhiều lần, rồi **xóa** các **nhật ký** về tệp khỏi **$MFT** và **$LOGFILE**, đồng thời **xóa Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Bạn có thể nhận thấy rằng ngay cả khi thực hiện thao tác đó, vẫn có thể còn **những nơi khác ghi lại sự tồn tại của tệp**. Điều này là đúng, và tìm ra chúng là một phần công việc của chuyên viên pháp chứng.



## References

- [1] [Bảng phân vùng GUID - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Cách quét các mục NTFS $I30 (thư mục) để tìm bằng chứng về tệp đã xóa](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Dịch vụ Volume Shadow Copy (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [Đặc tả UEFI: bố cục đĩa GPT](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [Tài liệu hướng dẫn mmls của The Sleuth Kit](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [Tài liệu hướng dẫn fsstat của The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Đặc tả FAT của Microsoft](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [Các tùy chọn khôi phục của PhotoRec](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [Khôi phục phân vùng đã xóa bằng TestDisk](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [Tài liệu hướng dẫn sgdisk](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [Tài liệu hướng dẫn mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
