# Phân vùng/Hệ thống tệp/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Phân vùng

Ổ cứng hoặc **ổ SSD có thể chứa nhiều phân vùng khác nhau** nhằm mục đích tách biệt dữ liệu về mặt vật lý.\
Đơn vị **nhỏ nhất** của đĩa là **sector** (thường có kích thước 512B). Vì vậy, kích thước mỗi phân vùng phải là bội số của kích thước đó.

### MBR (master Boot Record)

Nó được lưu trong **sector đầu tiên của đĩa, sau 446B mã khởi động**. Sector này rất quan trọng vì cho PC biết cần gắn kết phân vùng nào và từ đâu.\
MBR cho phép tối đa **4 phân vùng** (nhiều nhất **chỉ 1 phân vùng** có thể được đánh dấu là active/**bootable**). Tuy nhiên, nếu cần thêm phân vùng, bạn có thể dùng **extended partitions**. **Byte cuối cùng** của sector đầu tiên này là chữ ký bản ghi khởi động **0x55AA**. Chỉ một phân vùng có thể được đánh dấu là active.\
MBR hỗ trợ tối đa **2.2TB**.

![Phân vùng - MBR (master Boot Record): MBR hỗ trợ tối đa 2.2TB](<../../../images/image (350).png>)

![Phân vùng - MBR (master Boot Record): MBR hỗ trợ tối đa 2.2TB](<../../../images/image (304).png>)

Trong **các byte từ 440 đến 443** của MBR, bạn có thể tìm thấy **Windows Disk Signature** (nếu dùng Windows). Ký tự ổ đĩa logic của ổ cứng phụ thuộc vào Windows Disk Signature. Việc thay đổi chữ ký này có thể khiến Windows không khởi động được (công cụ: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Phân vùng - MBR (master Boot Record): Trong các byte từ 440 đến 443 của MBR, bạn có thể tìm thấy Windows Disk Signature (nếu dùng Windows). Ký tự ổ đĩa logic của ổ cứng...](<../../../images/image (310).png>)

**Định dạng**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Mã khởi động        |
| 446 (0x1BE) | 16 (0x10)  | Phân vùng thứ nhất  |
| 462 (0x1CE) | 16 (0x10)  | Phân vùng thứ hai   |
| 478 (0x1DE) | 16 (0x10)  | Phân vùng thứ ba    |
| 494 (0x1EE) | 16 (0x10)  | Phân vùng thứ tư    |
| 510 (0x1FE) | 2 (0x2)    | Chữ ký 0x55 0xAA    |

**Định dạng bản ghi phân vùng**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Cờ active (0x80 = bootable)                            |
| 1 (0x01)  | 1 (0x01) | Head bắt đầu                                           |
| 2 (0x02)  | 1 (0x01) | Sector bắt đầu (bit 0-5); các bit cao của cylinder (6-7) |
| 3 (0x03)  | 1 (0x01) | 8 bit thấp nhất của cylinder bắt đầu                   |
| 4 (0x04)  | 1 (0x01) | Mã loại phân vùng (0x83 = Linux)                       |
| 5 (0x05)  | 1 (0x01) | Head kết thúc                                          |
| 6 (0x06)  | 1 (0x01) | Sector kết thúc (bit 0-5); các bit cao của cylinder (6-7) |
| 7 (0x07)  | 1 (0x01) | 8 bit thấp nhất của cylinder kết thúc                  |
| 8 (0x08)  | 4 (0x04) | Số sector nằm trước phân vùng (little endian)           |
| 12 (0x0C) | 4 (0x04) | Số sector trong phân vùng                              |

Để gắn kết một MBR trong Linux, trước tiên bạn cần lấy offset bắt đầu (có thể dùng `fdisk` và lệnh `p`)

![Phân vùng - MBR (master Boot Record): Để gắn kết một MBR trong Linux, trước tiên bạn cần lấy offset bắt đầu (có thể dùng fdisk và lệnh p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Sau đó dùng đoạn mã sau

```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) là một sơ đồ phổ biến dùng để **xác định vị trí các block** dữ liệu được lưu trên thiết bị lưu trữ máy tính, thường là các hệ thống lưu trữ thứ cấp như ổ cứng. LBA là một sơ đồ địa chỉ tuyến tính đặc biệt đơn giản; **các block được xác định bằng một chỉ số nguyên**, trong đó block đầu tiên là LBA 0, block thứ hai là LBA 1, v.v.

### GPT (GUID Partition Table)

GUID Partition Table, thường gọi là GPT, được ưa chuộng nhờ các khả năng nâng cao so với MBR (Master Boot Record). GPT nổi bật với **mã định danh duy nhất toàn cục** cho các phân vùng và có một số điểm khác biệt:

- **Vị trí và kích thước**: GPT và MBR đều bắt đầu tại **sector 0**. Tuy nhiên, GPT hoạt động trên **64 bit**, trong khi MBR dùng 32 bit.
- **Giới hạn phân vùng**: GPT hỗ trợ tối đa **128 phân vùng** trên hệ thống Windows và có thể chứa tối đa **9.4ZB** dữ liệu.
- **Tên phân vùng**: Cho phép đặt tên phân vùng dài tối đa 36 ký tự Unicode.

**Khả năng phục hồi và khôi phục dữ liệu**:

- **Dự phòng**: Khác với MBR, GPT không giới hạn dữ liệu phân vùng và khởi động ở một vị trí duy nhất. GPT sao chép dữ liệu này trên toàn bộ đĩa, tăng tính toàn vẹn và khả năng phục hồi dữ liệu.
- **Kiểm tra dư thừa tuần hoàn (CRC)**: GPT sử dụng CRC để đảm bảo tính toàn vẹn dữ liệu. GPT chủ động giám sát tình trạng hỏng dữ liệu và khi phát hiện lỗi, sẽ cố gắng khôi phục dữ liệu bị hỏng từ một vị trí khác trên đĩa.

**Protective MBR (LBA0)**:

- GPT duy trì khả năng tương thích ngược thông qua một protective MBR. Tính năng này nằm trong vùng MBR cũ nhưng được thiết kế để ngăn các tiện ích cũ dựa trên MBR vô tình ghi đè lên đĩa GPT, qua đó bảo vệ tính toàn vẹn dữ liệu trên các đĩa được định dạng GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Trích từ Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Trong các hệ điều hành hỗ trợ **khởi động dựa trên GPT thông qua** dịch vụ **BIOS** thay vì EFI, sector đầu tiên vẫn có thể được dùng để lưu mã giai đoạn đầu của **bootloader**, nhưng được **chỉnh sửa** để nhận diện các **phân vùng** **GPT**. Bootloader trong MBR không được giả định kích thước sector là 512 byte.

**Partition table header (LBA 1)**

[Trích từ Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Partition table header xác định các block có thể sử dụng trên đĩa. Nó cũng xác định số lượng và kích thước của các mục phân vùng tạo nên partition table (offset 80 và 84 trong bảng).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Chữ ký ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h hoặc 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)trên máy little-endian) |
| 8 (0x08)  | 4 bytes  | Bản sửa đổi 1.0 (00h 00h 01h 00h) cho UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Kích thước header theo little endian (tính bằng byte, thường là 5Ch 00h 00h 00h hoặc 92 byte)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) của header (từ offset +0 đến hết kích thước header) theo little endian; trường này được đặt thành 0 trong quá trình tính toán                             |
| 20 (0x14) | 4 bytes  | Dành riêng; phải bằng 0                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | LBA hiện tại (vị trí của bản sao header này)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | LBA dự phòng (vị trí của bản sao header còn lại)                                                                                                                               |
| 40 (0x28) | 8 bytes  | LBA đầu tiên có thể sử dụng cho phân vùng (LBA cuối cùng của partition table chính + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | LBA cuối cùng có thể sử dụng (LBA đầu tiên của partition table phụ − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | GUID của đĩa theo mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | LBA bắt đầu của mảng các mục phân vùng (luôn là 2 trong bản sao chính)                                                                                                     |
| 80 (0x50) | 4 bytes  | Số lượng mục phân vùng trong mảng                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Kích thước của một mục phân vùng (thường là 80h hoặc 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 của mảng mục phân vùng theo little endian                                                                                                                            |
| 92 (0x5C) | \*       | Dành riêng; phần còn lại của block phải bằng 0 (420 byte với sector 512 byte; có thể nhiều hơn nếu sector lớn hơn)                                      |

**Partition entries (LBA 2–33)**

| Định dạng mục phân vùng GUID |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [GUID loại phân vùng](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | GUID phân vùng duy nhất (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | LBA đầu tiên ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | LBA cuối cùng (bao gồm, thường là số lẻ)                                                                             |
| 48 (0x30)                   | 8 bytes  | Cờ thuộc tính (ví dụ: bit 60 biểu thị chỉ đọc)                                                               |
| 56 (0x38)                   | 72 bytes | Tên phân vùng (36 đơn vị mã [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Tên phân vùng (36 đơn vị mã UTF-16LE)](<../../../images/image (83).png>)

Xem thêm các loại phân vùng tại [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Kiểm tra

Sau khi mount forensic image bằng [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), bạn có thể kiểm tra sector đầu tiên bằng công cụ Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Trong hình sau, một **MBR** đã được phát hiện tại **sector 0** và được diễn giải:

![GPT (GUID Partition Table) - Kiểm tra: Sau khi mount forensic image bằng ArsenalImageMounter, bạn có thể kiểm tra sector đầu tiên bằng công cụ Windows Active Disk Editor. Trong hình...](<../../../images/image (354).png>)

Nếu đây là **bảng GPT thay vì MBR**, chữ ký _EFI PART_ sẽ xuất hiện ở **sector 1** (đang trống trong hình trước).

## Hệ thống tệp

### Danh sách hệ thống tệp Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Hệ thống tệp **FAT (File Allocation Table)** được thiết kế xoay quanh thành phần cốt lõi là file allocation table, nằm ở đầu volume. Hệ thống này bảo vệ dữ liệu bằng cách duy trì **hai bản sao** của bảng, đảm bảo tính toàn vẹn dữ liệu ngay cả khi một bản bị hỏng. Bảng này cùng với thư mục gốc phải nằm ở **vị trí cố định**, điều thiết yếu cho quá trình khởi động của hệ thống.

Đơn vị lưu trữ cơ bản của hệ thống tệp là **cluster, thường là 512B**, gồm nhiều sector. FAT đã phát triển qua các phiên bản:

- **FAT12**, hỗ trợ địa chỉ cluster 12 bit và quản lý tối đa 4078 cluster (4084 với UNIX).
- **FAT16**, nâng lên địa chỉ 16 bit, cho phép quản lý tối đa 65,517 cluster.
- **FAT32**, tiếp tục nâng cấp với địa chỉ 32 bit, cho phép mỗi volume chứa tới 268,435,456 cluster.

Một hạn chế đáng kể của các phiên bản FAT là **kích thước tệp tối đa 4GB**, do trường 32 bit dùng để lưu kích thước tệp.

Các thành phần chính của thư mục gốc, đặc biệt với FAT12 và FAT16, gồm:

- **Tên tệp/thư mục** (tối đa 8 ký tự)
- **Thuộc tính**
- **Ngày tạo, ngày sửa đổi và ngày truy cập gần nhất**
- **Địa chỉ FAT Table** (cho biết cluster bắt đầu của tệp)
- **Kích thước tệp**

### EXT

**Ext2** là hệ thống tệp phổ biến nhất cho các phân vùng **không journaling** (**các phân vùng ít thay đổi**) như phân vùng boot. **Ext3/4** có journaling và thường được dùng cho **các phân vùng còn lại**.

## **Metadata**

Một số tệp chứa metadata. Đây là thông tin về nội dung tệp, đôi khi có thể hữu ích cho nhà phân tích; tùy loại tệp, thông tin này có thể bao gồm:

- Tiêu đề
- Phiên bản MS Office được sử dụng
- Tác giả
- Ngày tạo và ngày sửa đổi gần nhất
- Kiểu máy ảnh
- Tọa độ GPS
- Thông tin hình ảnh

Bạn có thể dùng các công cụ như [**exiftool**](https://exiftool.org) và [**Metadiver**](https://www.easymetadata.com/metadiver-2/) để lấy metadata của tệp.

## **Khôi phục tệp đã xóa**

### Tệp đã xóa được ghi lại

Như đã đề cập trước đó, có một số nơi tệp vẫn còn được lưu sau khi bị "xóa". Điều này là do thao tác xóa tệp khỏi hệ thống tệp thường chỉ đánh dấu tệp là đã xóa, chứ không đụng đến dữ liệu. Vì vậy, có thể kiểm tra các bản ghi của tệp (như MFT) để tìm các tệp đã xóa.<sup>[[2]](#references)</sup>

Ngoài ra, hệ điều hành thường lưu nhiều thông tin về các thay đổi của hệ thống tệp và bản sao lưu, vì vậy có thể thử dùng chúng để khôi phục tệp hoặc nhiều thông tin nhất có thể.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** là kỹ thuật tìm cách **tìm tệp trong khối dữ liệu lớn**. Có 3 cách chính để các công cụ loại này hoạt động: **dựa trên header và footer của loại tệp**, dựa trên **cấu trúc** của loại tệp và dựa trên chính **nội dung**.

Lưu ý rằng kỹ thuật này **không thể khôi phục các tệp bị phân mảnh**. Nếu tệp **không được lưu trong các sector liền kề**, kỹ thuật này sẽ không thể tìm thấy tệp hoặc ít nhất là một phần của tệp.

Có một số công cụ bạn có thể dùng để thực hiện File Carving bằng cách chỉ định loại tệp muốn tìm.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **Carving**

Data Stream Carving tương tự File Carving, nhưng **thay vì tìm các tệp hoàn chỉnh, kỹ thuật này tìm các đoạn thông tin đáng chú ý**.\
Ví dụ, thay vì tìm một tệp hoàn chỉnh chứa các URL đã ghi lại, kỹ thuật này sẽ tìm kiếm các URL.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Xóa an toàn

Rõ ràng, có những cách để **xóa tệp và một phần log về tệp đó một cách "an toàn"**. Ví dụ, có thể **ghi đè nội dung** của một tệp bằng dữ liệu rác nhiều lần, sau đó **xóa** các **log** về tệp khỏi **$MFT** và **$LOGFILE**, rồi **xóa Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Bạn có thể nhận thấy rằng ngay cả sau khi thực hiện các thao tác này, **vẫn có thể còn những nơi khác ghi lại sự tồn tại của tệp**. Điều đó là đúng, và một phần công việc của chuyên gia forensic là tìm ra chúng.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Cách quét các mục NTFS $I30 (thư mục) để tìm bằng chứng về tệp đã xóa](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Dịch vụ Volume Shadow Copy (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
