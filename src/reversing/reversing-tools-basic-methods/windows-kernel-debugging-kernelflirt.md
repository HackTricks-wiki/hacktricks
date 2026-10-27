# Debugging Windows Kernel với KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt là debugger Windows x64 dành cho các lab reverse-engineering có kiểm soát. Giao diện WPF phía host hoặc `KfConsole.exe` gửi lệnh đến `KfRelay.exe` trong một Windows VM đã bật chế độ test signing. Relay chuyển các lệnh đó thành yêu cầu `DeviceIoControl` gửi đến `KernelFlirt.sys`, cung cấp các thao tác về bộ nhớ, thanh ghi, breakpoint, điều khiển thực thi và module kernel. Driver cũng chỉnh sửa đường dẫn debugging của kernel bằng inline hook `KdpStub`/`KdTrap`, vì vậy chỉ sử dụng nó trong VM dùng một lần.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

Relay là một ranh giới gỡ lỗi có đặc quyền, không phải dịch vụ từ xa thông thường. Giữ TCP `31337` trong mạng chỉ dành cho máy chủ và không bao giờ để lộ driver được ký thử nghiệm hoặc relay ra mạng không đáng tin cậy.<sup>[[1]](#references)</sup>

Các kỹ thuật khai thác Windows liên quan:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Thiết lập phòng lab và bước đầu tiên

Để build, cần Windows 10/11 x64, Visual Studio 2022 có C++, WDK 10.0.26100.0 trở lên và .NET 9. Hãy tải driver và relay bên trong VM, sau đó kết nối từ máy chủ. Giao diện có thể mở EXE hoặc SYS từ xa, còn chế độ xem **Kernel Modules** cho phép đặt breakpoint trong các driver đã được tải.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Sử dụng `KfLoader.exe unload` khi hoàn tất lab. Console hỗ trợ REPL không kết nối, truy cập trực tiếp thiết bị cục bộ và truy cập relay; chỉ relay mode triển khai quy trình `open` có tính xác định được mô tả bên dưới.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Quy trình làm việc tối giản trên console là:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Địa chỉ là các biểu thức. Số trần được hiểu là số thập lục phân, còn biểu thức có thể dùng thanh ghi, phép toán, phép giải tham chiếu như `[rsp]` và ký hiệu như `ntdll!NtCreateFile`. Chỉ nên đặt breakpoint theo ký hiệu sau khi `open` hoặc `attach` đã liệt kê các module và tải PDB của chúng.<sup>[[2]](#references)</sup>

## Đặt bẫy tại entry point một cách xác định bằng `EB FE`

`open` ở phía relay tạo tiến trình ở trạng thái suspended, lưu các byte đầu tiên tại entry point, ghi `EB FE`, tiếp tục luồng entry rồi thăm dò cho đến khi instruction pointer của luồng đến địa chỉ đó. `EB FE` là lệnh nhảy ngắn hai byte quay lại chính nó, nên nó chặn việc thực thi mà không phụ thuộc vào việc nhận được debug exception ở user mode. Sau đó, relay khôi phục các byte ban đầu và để tiến trình mục tiêu dừng tại entry point.<sup>[[2]](#references)</sup>

Mẫu này cũng hữu ích khi cần quan sát một đường đi sớm của loader trước khi hoàn tất quá trình thiết lập debugger thông thường.<sup>[[2]](#references)</sup>

1. Tạo tiến trình ở trạng thái suspended và xác định entry point thực tế sau khi ánh xạ image.
2. Lưu các byte ban đầu tại entry point và thay chúng bằng vòng lặp tự nhảy dài hai byte.
3. Tiếp tục luồng entry và thăm dò instruction pointer cho đến khi nó đến địa chỉ đã được vá.
4. Suspend tiến trình mục tiêu và khôi phục chính xác các byte ban đầu trước khi tiếp tục phân tích.

Kỹ thuật này cố ý can thiệp sâu. Nếu debugger hoặc relay thoát trước khi khôi phục, tiến trình mục tiêu có thể tiếp tục quay vòng. Chế độ local của KernelFlirt không hỗ trợ vá entry point ở phía relay; hãy khởi chạy tiến trình thủ công rồi dùng `attach <pid>`.<sup>[[2]](#references)</sup>

## Chọn primitive breakpoint

KernelFlirt cung cấp một số cơ chế breakpoint với các tác động phụ khác nhau. Các lệnh sau cho phép nhà phân tích đổi primitive khi code đã pack tự viết lại, các trang executable ở chế độ chỉ đọc hoặc các byte software breakpoint bị kiểm tra tính toàn vẹn.<sup>[[1]](#references)[[2]](#references)</sup>

| Primitive | Command | Cơ chế và cách dùng |
| --- | --- | --- |
| Phần mềm | `bp <expr>` | `INT3` được hỗ trợ bởi MDL; có thể instrument các trang RX `.text` |
| Phần mềm có điều kiện | `bp <expr> if <condition>` | Đánh giá ở mỗi lần hit và tiếp tục chạy im lặng khi điều kiện sai |
| Thực thi bằng phần cứng | `ba e1 <expr>` | Dùng một trong DR0-DR3 mà không thay đổi các byte code |
| Dữ liệu bằng phần cứng | `ba w4 <expr>` / `ba r8 <expr>` | Theo dõi thao tác ghi hoặc đọc/ghi 1, 2, 4 hoặc 8 byte |
| Guard page | `bm <expr> [size]` | Dùng `PAGE_GUARD` để đặt breakpoint cho một vùng nhớ |
| Tạm thời | `g <expr>`, `p` hoặc `o` | Breakpoint hỗ trợ chạy đến địa chỉ, step-over và step-out |

Dùng `bl` để phân biệt các mục phần mềm, phần cứng, bộ nhớ và tạm thời; dùng `bc <address|handle|all>` để xóa chúng. Số slot phần cứng có hạn và được áp dụng thông qua trạng thái debug-register, trong khi guard page bao phủ vùng lớn hơn nhưng sẽ kích hoạt khi có truy cập không liên quan trên cùng trang.

## Step trên x64 native và WoW64

Single-step trên x64 native đặt cờ trap của bộ xử lý thông qua `IOCTL_KF_SINGLE_STEP`. Step Over giải mã lệnh hiện tại và đặt breakpoint tạm thời tại các địa chỉ tiếp theo có thể có. Step Out đọc địa chỉ trả về từ đỉnh stack hiện tại. Ở prologue của hàm, giả định về stack này có thể sai, vì vậy hãy ưu tiên đặt breakpoint nội bộ tại một vị trí đã biết.<sup>[[2]](#references)</sup>

Hook `KdTrap` không bắt được các exception 32-bit theo cùng cách đó. Với các target WoW64, debugger giải mã lệnh bằng Iced, ghi `EB FE` tại `EIP` tiếp theo đã tính toán rồi thăm dò instruction pointer của các luồng. Vì vậy, `g <address>` không khả dụng với WoW64, còn `g` không có đối số sẽ chặn console cho đến khi gặp breakpoint. Hãy đặt breakpoint có thể đạt tới trước và tránh chạy vô thời hạn, vì `Ctrl+C` sẽ kết thúc console thay vì hủy thao tác thăm dò.<sup>[[2]](#references)</sup>

## Phân tích có hỗ trợ bộ nhớ, thanh ghi và ký hiệu

Console có thể kết hợp điểm dừng theo ký hiệu với việc kiểm tra bộ nhớ và vá có kiểm soát. Các lệnh tìm kiếm chấp nhận wildcard byte, ASCII hoặc UTF-16, đồng thời giới hạn ở 4 MB và tối đa 256 kết quả được báo cáo. Các lệnh cấp phát và bảo vệ ánh xạ tới những IOCTL allocate, free và protect của driver.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

Việc tải PDB đọc thư mục debug PE của từng module từ xa, trích xuất định danh RSDS, tìm PDB khớp thông qua DbgHelp/SymSrv và xác minh rằng tệp được tải là PDB. Đặt các PDB riêng tư cạnh mục tiêu trên máy relay hoặc thêm thư mục của chúng vào `_NT_SYMBOL_PATH` trên host.<sup>[[2]](#references)</sup>

## Thay đổi trạng thái anti-debug dựa trên kernel

Quyền truy cập kernel cho phép debugger loại bỏ các dấu hiệu mà debugger ở user mode không thể ẩn một cách đáng tin cậy. Mỗi lần chỉ áp dụng một thay đổi, xác nhận kiểm tra của mục tiêu, rồi hoàn nguyên hook tương ứng trước khi kết thúc phiên.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` xóa `EPROCESS.DebugPort`.
- `clr_thread_hide` xóa `HideFromDebugger` khỏi các thread mục tiêu.
- `ntqsi on` giả mạo lớp `0x23` (`SystemKernelDebuggerInformation`) của `NtQuerySystemInformation`.
- `spoof on` khiến các thao tác đọc ở user-mode đối với `KUSER_SHARED_DATA.KdDebuggerEnabled` nhận giá trị false, đồng thời giữ nguyên trạng thái kernel cần thiết cho cơ chế trap.
- `stats` kiểm tra bộ đếm hook và trạng thái đã ghi nhận của `KiDebugRoutine`, `KdpStub` và `KdTrap`.

Các thao tác này làm thay đổi trạng thái của process và kernel. Sự cố crash, inline hook lỗi thời, offset cấu trúc không chính xác hoặc quá trình khôi phục patch chưa hoàn tất có thể khiến VM mất ổn định. Vì vậy, bắt buộc phải có snapshot và môi trường test-signing biệt lập.<sup>[[1]](#references)</sup>

## References

- [1] [Kho lưu trữ KernelFlirt và tài liệu chính](https://github.com/AkaTorich/KernelFlirt)
- [2] [Tài liệu tham khảo console KernelFlirt](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
