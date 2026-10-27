# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Hệ thống tệp độc quyền của Apple (APFS)

**Apple File System (APFS)** là hệ thống tệp hiện đại được thiết kế để thay thế Hierarchical File System Plus (HFS+). Hệ thống này được phát triển nhằm đáp ứng nhu cầu về **hiệu suất, bảo mật và hiệu quả cao hơn**.

Một số tính năng đáng chú ý của APFS:<sup>[[1]](#references)</sup>

1. **Chia sẻ dung lượng**: APFS cho phép nhiều volume **chia sẻ cùng dung lượng lưu trữ trống trên một thiết bị vật lý**. Nhờ đó, việc sử dụng dung lượng hiệu quả hơn vì các volume có thể tự động tăng hoặc giảm dung lượng mà không cần thay đổi kích thước hay phân vùng lại thủ công.
   1. Điều này có nghĩa là, khác với các phân vùng truyền thống trên đĩa, **các phân vùng (volume) trong APFS chia sẻ toàn bộ dung lượng đĩa**, trong khi phân vùng thông thường thường có kích thước cố định.
2. **Snapshot**: APFS hỗ trợ **tạo snapshot** — các bản thể hiện **chỉ đọc** của hệ thống tệp tại một thời điểm cụ thể. Snapshot giúp sao lưu hiệu quả và dễ dàng khôi phục hệ thống, vì chúng chỉ sử dụng thêm rất ít dung lượng và có thể được tạo hoặc khôi phục nhanh chóng.
3. **Clone**: APFS có thể **tạo bản clone của tệp hoặc thư mục dùng chung dung lượng lưu trữ với bản gốc** cho đến khi bản clone hoặc tệp gốc được sửa đổi. Tính năng này giúp tạo bản sao tệp hoặc thư mục hiệu quả mà không cần nhân đôi dung lượng lưu trữ.
4. **Mã hóa**: APFS **hỗ trợ mã hóa toàn bộ ổ đĩa ngay từ đầu**, cũng như mã hóa từng tệp và thư mục, tăng cường bảo mật dữ liệu trong nhiều trường hợp sử dụng.
5. **Bảo vệ khi gặp sự cố**: APFS sử dụng **cơ chế metadata copy-on-write để đảm bảo tính nhất quán của hệ thống tệp**, ngay cả khi mất điện đột ngột hoặc hệ thống bị treo, qua đó giảm nguy cơ hỏng dữ liệu.

Nhìn chung, APFS cung cấp hệ thống tệp hiện đại, linh hoạt và hiệu quả hơn cho các thiết bị Apple, tập trung vào việc cải thiện hiệu suất, độ tin cậy và bảo mật.

```bash
diskutil list # Get overview of the APFS volumes
```

## Firmlinks

Volume `Data` được gắn tại **`/System/Volumes/Data`** (bạn có thể kiểm tra bằng `diskutil apfs list`).

Danh sách firmlinks có thể tìm thấy trong tệp **`/usr/share/firmlinks`**.

```bash

```

## References

- [1] [Hướng dẫn APFS - Tính năng - Tài liệu dành cho nhà phát triển Apple](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)
{{#include ../../banners/hacktricks-training.md}}
