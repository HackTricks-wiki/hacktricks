# Windows MDL-Mapped User Buffer Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

Một Windows kernel driver tạo ra double-fetch khi xác thực dữ liệu trong các page do caller kiểm soát, rồi chuyển pointer trỏ vào chính các page đó cho một API nhạy cảm về bảo mật. Việc khóa và map các page không khiến nội dung của chúng bất biến. CVE-2025-55680 trong `cldflt.sys` minh họa kiểu lỗi này: driver xác thực relative name của Cloud Files placeholder, rồi tạo object trong khi vẫn tham chiếu buffer có thể bị caller thay đổi.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` tạo file hoặc directory bên dưới một Cloud Files sync root đã đăng ký. Trong luồng xử lý dễ bị tấn công, việc thay đổi name sau khi xác thực có thể chuyển hướng thao tác tạo với đặc quyền cao ra ngoài root đó.<sup>[[1]](#references)[[2]](#references)</sup>

## Vì sao khóa các page không khóa dữ liệu

Luồng `HsmpOpCreatePlaceholders()` dễ bị tấn công cấp phát MDL cho payload của caller, gọi `ProbeForRead()` và `MmProbeAndLockPages()`, rồi map các page đó vào kernel virtual address space. MDL mô tả và khóa các physical page để chúng luôn ở trạng thái resident. Nó **không** snapshot các byte trong đó. Vì vậy, user mode có thể sửa đổi cùng vùng physical memory trong khi driver đọc nó qua system mapping.<sup>[[1]](#references)[[3]](#references)</sup>

Luồng request và sử dụng liên quan như sau:<sup>[[1]](#references)</sup>

1. `cldapi.dll` gửi Cloud Files control code `0x903BC` với tag `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) và thao tác tạo placeholder `0xC0000001`.
2. Mỗi payload record chứa các cặp offset/length 16-bit cho relative name và file identity. Hầu hết các field cố định được copy vào stack record, nhưng name có độ dài thay đổi vẫn nằm trong các user page đã được map.
3. Driver quét name UTF-16 và từ chối nếu có backslash hoặc colon.
4. Sau đó, driver tạo một `UNICODE_STRING` có `Buffer` vẫn trỏ vào payload đã map, rồi gán nó cho `OBJECT_ATTRIBUTES.ObjectName`.
5. `FltCreateFileEx2()` đọc lại pointer đó. Do vậy, một writer chạy đồng thời có thể khiến bước xác thực thấy một string, còn bước tạo file lại thấy string khác.

Đây là một **double-fetch** dù cả hai lần đọc đều sử dụng kernel virtual address: ranh giới bảo mật phụ thuộc vào vùng lưu trữ nền, chứ không phụ thuộc vào mapping virtual nào được driver dereference.<sup>[[1]](#references)</sup>

## Bố cục race trong Cloud Files

Chiến lược khai thác được công bố sử dụng các request lặp lại, mutator thread và một junction để biến double-fetch thành path redirection:<sup>[[1]](#references)</sup>

1. Đăng ký một directory do attacker kiểm soát bằng `CfRegisterSyncRoot()` và tạo `JUSTASTRING` bên dưới nó dưới dạng junction trỏ đến một destination được bảo vệ.
2. Chuẩn bị một placeholder record dùng chung với name hợp lệ chỉ gồm một component: `JUSTASTRINGDnewfile.dll`.
3. Cho các mutator thread liên tục chuyển đổi UTF-16 code unit `D` giữa `D` và `\`. Biểu diễn thứ hai là `JUSTASTRING\newfile.dll`.
4. Đồng thời, cho các worker thread liên tục gửi create-placeholder request tham chiếu đến cùng payload, trong khi một monitor kiểm tra destination được bảo vệ.
5. Một lần thực thi thành công sẽ xác thực biểu diễn không có separator, rồi đi theo junction khi thao tác tạo sau đó đọc thấy biểu diễn có `\`.

Primitive này chỉ cho phép tạo file hoặc directory được bảo vệ. Để biến nó thành code execution vẫn cần kiểm soát nội dung file được tạo và có một thành phần đặc quyền sử dụng file đó, chẳng hạn một mục tiêu DLL side-loading phù hợp. Phân tích ban đầu sử dụng kiểu chuỗi khai thác cuối cùng này nhưng không công bố loader, payload hay một exploit độc lập hoàn chỉnh.<sup>[[1]](#references)</sup>

Để xem các kỹ thuật bổ trợ nhằm chủ động kéo dài race trong Windows path lookup, hãy xem [Khai thác race condition trong kernel qua slow path của Object Manager](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Lỗ hổng leo thang đặc quyền TOCTOU trong Windows Cloud Files Minifilter của Microsoft](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - Hàm CfCreatePlaceholders](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - Hàm MmProbeAndLockPages](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
