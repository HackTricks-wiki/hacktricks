# Rootkit nhân Windows và DKOM

{{#include ../../banners/hacktricks-training.md}}

## Phạm vi

Một implant hậu xâm nhập có thể tải một kernel driver đã ký dưới dạng service và cung cấp mặt phẳng điều khiển user-mode thông qua `IRP_MJ_DEVICE_CONTROL`. Việc ký driver chỉ xác nhận rằng Windows chấp nhận image; điều đó không khiến việc phân quyền IOCTL, thao tác bộ nhớ, callback hay hook trở nên an toàn. Một rootkit được phân tích sử dụng ba handler trong hoạt động bình thường nhưng cung cấp thêm hàng chục primitive hậu khai thác, vì vậy việc reverse engineering phải bao quát toàn bộ dispatcher thay vì chỉ các request quan sát được trong một dấu vết malware.<sup>[[1]](#references)</sup>

## Phân loại driver đã ký và IOCTL

Bắt đầu từ `DriverEntry`, ghi lại các device object và symbolic link DOS, tìm routine `MajorFunction[IRP_MJ_DEVICE_CONTROL]`, rồi lập bản đồ mọi phép so sánh/mục trong bảng dẫn đến một handler. Đối chiếu tên mà user-mode mở với tên mà driver thực sự tạo: một chuỗi được quan sát đã mở `\\.\msagent`, trong khi driver tạo `\Device\ToolTool` và `\DosDevices\ToolTool`. Sự không khớp này có thể cho thấy có một sample/cấu hình khác, thiếu logic thiết lập hoặc có điểm không nhất quán trong quá trình phân tích.<sup>[[1]](#references)</sup>

Giải mã từng control code trước khi tái dựng cấu trúc input của nó.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

Ba mã này giải mã thành `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` và `METHOD_BUFFERED`. Điều đó **không** chứng minh người gọi không có đặc quyền có thể truy cập chúng: hãy kiểm tra thêm DACL của thiết bị, các hàm dispatch create/open, kiểm tra caller trên từng request, độ dài buffer được yêu cầu, con trỏ nhúng, cách xử lý vòng đời PID và liệu handler có tin PID hoặc flag do caller cung cấp hay không.<sup>[[1]](#references)</sup>

Khi implant chỉ dùng một tập hợp lệnh con, hãy nhóm các handler còn lại theo primitive thay vì coi chúng là code chết. Một driver đa chức năng duy nhất đã để lộ tất cả các nhóm sau:<sup>[[1]](#references)</sup>

- **Điều khiển/cấu hình:** bật/tắt trạng thái rootkit; thêm, xóa, truy vấn hoặc xóa sạch các đường dẫn, tiến trình và địa chỉ C2 được bảo vệ.
- **Thao túng tiến trình:** chấm dứt một PID, unmap image của nó, inject bằng `NtCreateThreadEx`, ẩn/khôi phục tiến trình hoặc user module, và gỡ bỏ bảo vệ PPL.
- **Thao túng kernel:** unlink một driver đã load, liệt kê/vô hiệu hóa/khôi phục notification callback, map thủ công một driver khác và ghi vào địa chỉ kernel tùy ý.
- **Thao túng object:** xóa/giải mã file và tạo hoặc sửa registry value.

## Map kernel thủ công thông qua vulnerable signed driver

Một signed driver có các thao tác đọc/ghi kernel memory có thể cung cấp loader cho một unsigned driver image mà không yêu cầu Windows load image đó như một driver thông thường.<sup>[[2]](#references)[[7]](#references)</sup> Ví dụ LocalStranger mở một thiết bị `\\.\WinNotify` có sẵn; source của nó không cho thấy người dùng không có đặc quyền có thể cài đặt, khởi động hoặc mở driver trên một host bất kỳ.<sup>[[2]](#references)[[3]](#references)</sup> Mapper nhận đường dẫn image, truy vấn base của kernel đã load và sử dụng các IOCTL đọc/ghi virtual memory của thiết bị.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Để biến quyền đọc/ghi đó thành một lời gọi kernel, mapper đọc một immediate chứa PTE-base từ `MmGetVirtualForPhysical` rồi duyệt các paging entry bao phủ `NtAddAtom`.<sup>[[5]](#references)[[7]](#references)</sup> Phép tính PTE là `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`; code cũng kiểm tra PDE của large page.<sup>[[5]](#references)[[7]](#references)</sup> Nó tạm thời cho phép ghi vào entry bao phủ, thay syscall entry bằng một jump đến kernel function mong muốn, gọi user-mode stub `NtAddAtom`, sau đó khôi phục cả byte ban đầu lẫn page entry.<sup>[[6]](#references)</sup>

Mapper dùng đường gọi đó cho `ExAllocatePool`, map các PE section, import và relocation vào image, ghi image vào vùng cấp phát rồi gọi entry point của nó.<sup>[[7]](#references)[[8]](#references)</sup> Triển khai này chỉ chấp nhận PE image x64 có thể relocation; thao tác đọc PTE-base cũng giả định layout cố định `MmGetVirtualForPhysical + 34`.<sup>[[5]](#references)[[8]](#references)</sup> Hãy xem đây là kỹ thuật phụ thuộc vào build, không phải cách bypass KASLR độc lập hay bằng chứng rằng HVCI hoặc PatchGuard cho phép việc map này.<sup>[[5]](#references)[[8]](#references)</sup> Để dùng kernel R/W chỉ nhằm thao tác dữ liệu, xem [SYSTEM token theft](arbitrary-kernel-rw-token-theft.md).

## Miễn trừ cho tiến trình đáng tin cậy

Một mẫu thiết kế hữu ích là IOCTL đăng ký PID cùng một flag **trusted**. Cùng một cơ chế tra cứu trust sau đó được dùng trong các bộ lọc file, registry, process và thread: công cụ không đáng tin cậy nhận kết quả liệt kê đã lọc, quyền handle bị giảm hoặc `STATUS_ACCESS_DENIED`, trong khi implant vẫn có thể cập nhật các object ẩn của chính nó. Hãy xem đây là ranh giới ủy quyền và xác minh cách các entry được xác thực, đồng bộ hóa và xóa sau khi tiến trình kết thúc hoặc PID được tái sử dụng.<sup>[[1]](#references)</sup>

Rootkit có thể lưu policy trong các giá trị `REG_MULTI_SZ` và biên dịch danh sách file, directory, registry key, registry value, image bị bỏ qua, image được bảo vệ và image bị ẩn thành AVL tree. Khi phân tích, hãy lần theo mọi nơi đọc và ghi các tree dùng chung này; chúng kết nối cấu hình registry, IOCTL, callback và logic lọc ngay cả khi tên function đã bị loại bỏ.<sup>[[1]](#references)</sup>

## Ẩn process và module bằng DKOM

### `EPROCESS.ActiveProcessLinks`

Offset của `ActiveProcessLinks` thay đổi theo Windows build. Rootkit tương thích nhiều phiên bản có thể kiểm tra các offset đã biết rồi quét `EPROCESS` để tìm một `LIST_ENTRY` nhất quán, có các node lân cận trỏ ngược về candidate. Nó lưu offset tìm được, ẩn một tiến trình bằng cách nối lại `Flink`/`Blink` của các node lân cận và giữ trạng thái để liên kết lại entry sau đó. Tiến trình vẫn chạy nhưng biến mất khỏi các enumerator duyệt active-process list.<sup>[[1]](#references)</sup>

Đây là **DKOM**, không phải chấm dứt tiến trình. Việc phát hiện cần đối chiếu kết quả dựa trên list với các bằng chứng độc lập như quét pool/object, quyền sở hữu thread, handle table, dấu vết scheduler và kiểm tra kernel memory. Một tiến trình xuất hiện trong kết quả quét nhưng không có trong list chuẩn có ý nghĩa hơn khi xem riêng từng góc nhìn.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Primitive ẩn module tương tự tìm entry mục tiêu trong `PsLoadedModuleList` rồi sửa các con trỏ `Flink`/`Blink` liền kề. Driver vẫn được map và có thể thực thi, nhưng các truy vấn module dựa trên list sẽ không liệt kê nó. Hãy đối chiếu loader list với executable kernel mapping, pool tag, device/driver object, service key, callback address và dispatch pointer trỏ ra ngoài image được liệt kê.<sup>[[1]](#references)</sup>

## Bảo vệ và che giấu bằng callback

Rootkit có thể kết hợp các callback framework được tài liệu hóa với DKOM và hook:<sup>[[1]](#references)</sup>

- Handler pre-operation của `ObRegisterCallbacks` dành cho `PsProcessType` và `PsThreadType` loại bỏ các quyền dùng để chấm dứt, truy cập VM, duplicate hoặc thao túng thread khi caller không đáng tin cậy mở một target được bảo vệ. Ghi lại altitude của callback và xác định module sở hữu từng callback address.
- `PsSetCreateProcessNotifyRoutineEx` và `PsSetLoadImageNotifyRoutine` duy trì trạng thái tiến trình được bảo vệ/bỏ qua/ẩn khi tiến trình và image xuất hiện; một lần duyệt tiến trình có thể bổ sung các object đã tồn tại trước khi đăng ký.
- Filesystem minifilter từ chối truy cập vào các đường dẫn được cấu hình. Một triển khai khác thường có thể tạo key `Instances`, chọn altitude động và tăng giá trị/thử lại khi `FltRegisterFilter` báo xung đột.
- Routine `CmRegisterCallbackEx` có thể ẩn các tên được bảo vệ khỏi kết quả liệt kê và từ chối thao tác mở trực tiếp, đổi tên, đặt hoặc xóa, đồng thời miễn trừ các tiến trình đáng tin cậy đã đăng ký.

Đối chiếu các đăng ký `ObRegisterCallbacks`, registry-callback altitude, kết quả `fltmc filters`, service `Instances` key và callback address. Nếu các công cụ thông thường bị lọc, hãy kiểm tra những cấu trúc này từ offline memory image hoặc một lớp thu thập đáng tin cậy khác.<sup>[[1]](#references)</sup>

## Lọc kết quả Nsiproxy

Cơ chế che giấu mạng có thể nhắm đến `\Driver\Nsiproxy`: lấy driver object bằng `ObReferenceObjectByName`, lưu handler pointer, thay nó bằng một wrapper rồi loại bỏ các IPv4 record được trả về nếu khớp với danh sách C2 do IOCTL quản lý, trước khi dữ liệu đến user mode. Các ứng dụng dựa trên dữ liệu NSI đã lọc có thể không còn hiển thị kết nối dù traffic vẫn tồn tại.<sup>[[1]](#references)</sup>

Đối chiếu chế độ xem kết nối trên host với packet capture, WFP/ETW telemetry và network object trong kernel memory. Đồng thời kiểm tra dispatch/handler pointer của `Nsiproxy` và xác nhận mỗi pointer đều trỏ vào signed module dự kiến; một pointer nằm trong mapping không được liệt kê có thể kết nối việc lọc mạng với DKOM trên `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Checklist điều tra

Dấu hiệu mạnh nhất là sự bất nhất giữa các lớp, không phải một filename hay hash đơn lẻ. Hãy đối chiếu:<sup>[[1]](#references)</sup>

1. Việc tạo kernel service và một signed driver có tuổi chứng chỉ, publisher hoặc đường dẫn không phù hợp với sản phẩm đã cài đặt.
2. Việc tạo device, DOS link và IOCTL traffic, bao gồm tên device phía user mode và kernel không khớp nhau.
3. Một request đăng ký PID, sau đó là việc các tiến trình khác không thể mở, liệt kê, sửa đổi hoặc xóa cùng những object đó.
4. Object/registry/process/image callback, minifilter instance và hook có address không thuộc về driver được liệt kê bình thường.
5. Khác biệt giữa inventory process, module, callback và network dựa trên list với dựa trên scan.

## References

- [1] [Kaspersky Securelist - HoneyMyte cải tiến CoolClient bằng Windows kernel rootkit có chữ ký](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [README LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [Khởi tạo driver LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [Command line của LocalStranger mapper](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Giải quyết kernel export và PTE-base của LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Kernel-call trampoline của LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [Cấp phát và gọi entry của LocalStranger mapper](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [PE mapping của LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Ngữ cảnh kernel và syscall của LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Virtual-memory IOCTL wrapper của LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
