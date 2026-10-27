# UEFI IFR và vá cài đặt bảo mật NVRAM

{{#include ../../banners/hacktricks-training.md}}

Mật khẩu thiết lập bảo vệ giao diện người dùng firmware, nhưng không nhất thiết xác thực các byte cấu hình được lưu trong SPI flash. Khi có quyền ghi vật lý, chuyên gia đánh giá có thể ánh xạ một cài đặt UEFI ẩn hoặc bị khóa từ **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** đến biến NVRAM chứa giá trị tương ứng, vá giá trị đó khi offline rồi flash lại. Trên một hệ thống Dell bị ảnh hưởng, thao tác này đã thay đổi trạng thái IOMMU trước khi khởi động, trong khi giao diện thiết lập đồ họa vẫn hiển thị rằng tính năng bảo vệ DMA đang bật.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Việc ghi firmware có thể khiến thiết bị mục tiêu bị brick vĩnh viễn. Chỉ thao tác trên thiết bị thử nghiệm được cấp phép và có thể khôi phục; giữ lại image gốc; và thực hiện ít nhất ba lần đọc độc lập có hash mật mã trùng khớp trước khi chỉnh sửa bất cứ thứ gì.<sup>[[3]](#references)</sup>

## Thu thập firmware image

Chỉ đọc vùng BIOS khi flash descriptor của Intel cho phép host truy cập, hoặc dùng programmer bên ngoài có điện áp phù hợp và clip gắn trực tiếp vào mạch. Thông thường cần programmer bên ngoài để khôi phục máy không còn khởi động được.<sup>[[3]](#references)[[9]](#references)</sup>

```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```

Đừng cho rằng capsule cập nhật của nhà cung cấp tương đương với nội dung chip: nó có thể không chứa NVRAM, có lớp đóng gói hoặc được mã hóa. [UEFITool](https://github.com/LongSoft/UEFITool) có thể phân tích ảnh UEFI thô thành các firmware volume, file và section.<sup>[[7]](#references)</sup>

## Ánh xạ câu hỏi IFR sang NVRAM

[IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) chuyển đổi các gói biểu mẫu HII thành văn bản và hiển thị những cài đặt mà GUI của nhà cung cấp ẩn, đổi tên hoặc loại bỏ. Đầu ra có thể xác định câu hỏi, kho biến, độ lệch byte, độ rộng lưu trữ, các giá trị hợp lệ và điều kiện hiển thị.<sup>[[8]](#references)</sup>

1. Mở bản dump trong UEFITool, tìm file firmware có tên `Setup`, mở rộng đến section ảnh PE32 và chọn **Extract body**.
2. Chạy IFRExtractor-RS trên phần thân EFI/PE32 đã trích xuất, sau đó tìm trong văn bản được tạo ra các điều khiển như `DMA`, `IOMMU`, `VT-d`, `Secure Boot` hoặc nhãn hiển thị cho người dùng của nhà cung cấp.
3. Ghi lại `VarStoreId`, `VarOffset`, `Size`, các tùy chọn hợp lệ và ID câu hỏi. Đừng suy luận ý nghĩa của giá trị chỉ dựa vào `Flags`.
4. Tìm khai báo `VarStore`/`VarStoreEfi` tương ứng và ánh xạ ID kho số sang **tên và GUID** của biến.
5. Tìm GUID đó trong UEFITool cho đến khi tới đối tượng NVRAM tương ứng. Mở **Body hex view** và chuyển đến `VarOffset` tính từ phần thân của biến—không phải từ toàn bộ ảnh flash.<sup>[[3]](#references)</sup>

```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```

Ví dụ, một image Dell mô tả câu hỏi liên quan là `Control Iommu Pre-boot Behavior`, với `VarStoreId: 0x1`, `VarOffset: 0x975` và trường 8-bit. Store `0x1` ánh xạ tới biến `Setup` và GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`; các bản dump vi sai xác định `01` là bật và `00` là tắt trên firmware đó.<sup>[[3]](#references)</sup>

> [!WARNING]
> GUID, offset, bố cục cấu trúc, các bản sao biến trùng lặp và cách mã hóa giá trị có thể thay đổi tùy theo model và phiên bản firmware. Không bao giờ dùng lại offset trong ví dụ như một giá trị chung cho mọi thiết bị Dell.

## Xác minh bằng bản dump vi sai

Khi có giao diện setup trên một thiết bị thử nghiệm tương đương, hãy tạo một bản dump khi tùy chọn được bật và một bản khác khi tùy chọn đó bị tắt. So sánh phần thân biến suy ra từ IFR và xác nhận rằng chỉ trường dự kiến thay đổi. Việc này xác định cách mã hóa thực tế và phân biệt biến đang hoạt động với các bản sao cũ/mặc định/khôi phục. Vá một bản sao của image gốc đã xác minh, mở lại trong UEFITool và xác nhận rằng chỉnh sửa nằm ngoài các vùng code được xác thực hoặc đo lường trước khi flash lại.<sup>[[3]](#references)[[4]](#references)</sup>

Chỉnh sửa có mục tiêu có thể gây ít tác dụng phụ hơn việc xóa mật khẩu firmware, vốn có thể đưa thiết bị về trạng thái xuất xưởng, yêu cầu nhập lại dữ liệu riêng của thiết bị hoặc làm thay đổi các phép đo TPM PCR. Tuy nhiên, chỉnh sửa offline có mục tiêu cũng có thể tạo ra **sự bất nhất giữa trạng thái hiển thị và trạng thái hiệu lực**, trong đó giao diện và công cụ quản lý hiển thị giá trị cũ, còn firmware giai đoạn đầu lại sử dụng byte đã được vá. Thay đổi được minh họa không yêu cầu khôi phục BitLocker và vẫn tồn tại sau khi cập nhật BIOS của nhà sản xuất vì bản cập nhật giữ nguyên trạng thái NVRAM đã bị thay đổi.<sup>[[3]](#references)</sup>

[Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) của tác giả minh họa một công cụ vá dành riêng cho từng model, có thể tìm các vùng Intel Boot Guard Initial Boot Block và từ chối các thao tác ghi thông thường bên trong những vùng đó. Hãy dùng chế độ phân tích trước khi chạy `--apply`, kiểm tra mọi kết quả khớp tiềm năng và xem các giá trị mặc định của công cụ là ví dụ, không phải các offset có thể dùng chung.<sup>[[4]](#references)</sup>

```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```

## Tự động hóa việc ánh xạ bằng NVRAMap

[NVRAMap](https://github.com/PN-Tester/NVRAMap) tự động trích xuất IFR, xác định GUID/tên NVRAM tương ứng với `VarStoreId` của câu hỏi, hiển thị các giá trị tùy chọn hiện tại và có thể chỉnh sửa trường được chọn. Công cụ này có thể hoạt động với bản dump firmware đầy đủ hoặc các blob EFI và NVRAM được trích xuất riêng.<sup>[[5]](#references)</sup>

```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```

Tự động hóa không loại bỏ nhu cầu phải có các bản dump phù hợp, phần cứng phục hồi, kiểm tra tính toàn vẹn của vùng và xác thực sau khi flash.

## Kết hợp hạ cấp IOMMU trước khi khởi động với quyền truy cập DMA trong Windows

Nếu giá trị đã patch cho phép PCIe DMA trước ExitBootServices, [DMAReaper](https://github.com/PN-Tester/DMAReaper) có thể lần theo EFI System Table qua các bảng gốc ACPI, tìm bảng `DMAR` và ghi đè lên bảng đó trước khi Windows phân tích nó. Nếu không có dữ liệu DMAR khả dụng, Windows có thể không khởi tạo được Kernel DMA Protection dựa trên IOMMU. Bản thân DMAReaper **không** vô hiệu hóa VBS/HVCI.<sup>[[1]](#references)</sup>

Trong chuỗi tấn công được minh họa, mục tiêu sau đó được khởi động vào Safe Mode để loại bỏ rào cản VBS còn lại, rồi [PCILeech](https://github.com/ufrisk/pcileech) patch bộ nhớ vật lý bằng chữ ký Sticky Keys:<sup>[[2]](#references)[[3]](#references)</sup>

```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```

Sau một bản vá thành công và tương thích với bản build, gọi Sticky Keys tại màn hình đăng nhập Windows đã mở command prompt dưới quyền `NT AUTHORITY\SYSTEM`. Chữ ký và các phạm vi bộ nhớ có thể truy cập phụ thuộc vào mục tiêu/bản build/phần cứng; một kết quả khớp được báo cáo không chứng minh rằng mọi phiên bản Windows đều có thể bị khai thác.<sup>[[2]](#references)[[3]](#references)</sup>

Đừng tin vào menu firmware như một cách xác thực. Kiểm tra **System Information (`msinfo32.exe`) → Kernel DMA Protection**, xác minh riêng VBS, kiểm tra xem hệ điều hành có nhận được bảng DMAR hợp lệ hay không, và kiểm tra khả năng truy cập DMA thực tế. Windows chỉ báo cáo Kernel DMA Protection khi nền tảng và firmware hỗ trợ cấu hình IOMMU bắt buộc.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Vô hiệu hóa Kernel DMA Protection bằng cách ghi đè DMAR trước khi khởi động](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Phần mềm tấn công Direct Memory Access](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Vô hiệu hóa các tính năng bảo mật trong BIOS bị khóa](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - Vá NVRAM nhận biết IBB](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Ánh xạ cài đặt EFI sang giá trị NVRAM](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Trình xem và phân tích ảnh firmware UEFI](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Trích xuất IFR UEFI thành văn bản dễ đọc](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [Tài liệu flashrom - Programmer và các thao tác đọc/ghi](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
