# Luồng điều khiển dựa trên Exception của Windows và Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Một chương trình Windows được bảo vệ có thể dùng một exception có chủ đích làm nhánh: instruction gây lỗi chỉ là điểm vào một handler chọn địa chỉ user-code tiếp theo. Cách này che giấu các cạnh trong quá trình disassembly tuyến tính và chuyển bước tiếp theo sang exception dispatch.<sup>[[1]](#references)</sup>

## Dispatch rất quan trọng

Debugger gắn vào process nhận exception **first-chance** trước các handler của ứng dụng. Nếu debugger chuyển sự kiện đi như chưa được xử lý, Windows sẽ tìm kiếm các handler của process; exception không có handler sẽ quay lại debugger dưới dạng **last-chance**. Vì vậy, debugger xử lý breakpoint hoặc sự kiện single-step có thể làm thay đổi việc handler của chương trình có chạy hay không.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` đăng ký một VEH toàn process ở đầu danh sách vectored. VEH chạy trước SEH dựa trên frame, nhưng một đăng ký ưu tiên cao hơn được tạo sau đó có thể đưa handler khác lên trước nó. Trả về `EXCEPTION_CONTINUE_SEARCH` sẽ để exception cho các handler khác xử lý; `EXCEPTION_CONTINUE_EXECUTION` sẽ tiếp tục thực thi từ `CONTEXT` đã lưu, bao gồm mọi thay đổi thanh ghi do handler thực hiện.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

SEH cổ điển trên x86 dùng các đăng ký liên kết trên stack, có thể kiểm tra bằng `!exchain`. Native x64 dùng các mục `RUNTIME_FUNCTION` trong `.pdata` cùng dữ liệu unwind trong `.xdata`, chứ không dùng chuỗi x86 đó. Không áp dụng [quy trình ghi đè SEH trên x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) cho process native x64.<sup>[[5]](#references)[[6]](#references)</sup>

## Biến lỗi thành cạnh trong luồng điều khiển

Ví dụ, phép chia cho số 0 có thể cố ý kích hoạt `EXCEPTION_INT_DIVIDE_BY_ZERO` thay vì là một bug. Handler phải nhận diện exception và địa chỉ gây lỗi, sau đó đặt `ContextRecord->Rip` (hoặc `Eip` trên x86) thành một điểm tiếp tục hợp lệ trước khi trả về `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Phần lõi của handler bên dưới giả định `fault_site` và `continuation` là các địa chỉ đã biết trong cùng một ngữ cảnh luồng điều khiển. Một triển khai thực tế phải bảo toàn stack và các thanh ghi như mong đợi, đồng thời không được tiếp tục tại chính lệnh gây lỗi, nếu không lỗi sẽ xảy ra lần nữa.<sup>[[7]](#references)</sup>

```c
if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO &&
    e->ExceptionRecord->ExceptionAddress == fault_site) {
#ifdef _M_X64
    e->ContextRecord->Rip = (DWORD64)continuation;
#else
    e->ContextRecord->Eip = (DWORD)continuation;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
return EXCEPTION_CONTINUE_SEARCH;
```

Cơ chế tương tự có thể xử lý một `INT3`/`__debugbreak()` có chủ đích (`EXCEPTION_BREAKPOINT`) và chuyển hướng quá trình thực thi. **Không** tăng `Rip` một cách mù quáng để “bỏ qua breakpoint”: địa chỉ được lưu và mức điều chỉnh cần thiết phụ thuộc vào trap, mã hóa lệnh và hành vi của debugger. So sánh `ExceptionRecord->ExceptionAddress` với con trỏ lệnh đã lưu và disassemble các byte trước khi chọn vị trí tiếp tục.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) là một ví dụ riêng về hardware breakpoint, thay đổi trạng thái trả về của một syscall trong loader.

## Tạo trang theo nhu cầu bằng lỗi

VEH có thể biến lỗi trang thành một **lazy loader**, chứ không chỉ là một cú nhảy. Dành riêng một vùng image riêng với các trang chưa được commit, hoặc dùng các trang mapped có guard nếu được hỗ trợ. Trước khi chạy image, lập chỉ mục các vị trí relocation và IAT thunk theo trang đích của chúng. Khi xảy ra lỗi trong vùng đó, handler commit trang được truy cập hoặc cấp quyền ghi cho trang, sao chép byte của section, áp dụng relocation và import của trang đó, đặt protection cuối cùng cho trang rồi trả về `EXCEPTION_CONTINUE_EXECUTION`. Lệnh ban đầu sẽ được thử lại; **không** tăng `Rip` như trong handler bỏ qua lỗi. Các trang chưa từng được truy cập không cần chứa payload trong bộ nhớ.<sup>[[11]](#references)</sup>

Với access violation, `ExceptionRecord->ExceptionAddress` xác định **lệnh** gây lỗi, còn `ExceptionInformation[1]` xác định địa chỉ được truy cập.<sup>[[10]](#references)</sup> Kiểm tra mã exception, số lượng tham số và phạm vi địa chỉ được truy cập trước khi tạo trang; nếu không, một lỗi không liên quan có thể bị nhầm là yêu cầu từ loader.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` phát sinh `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) ở lần truy cập đầu tiên và Windows tự động xóa bit guard, vì vậy việc bật lại guard là một bước riêng, không phải hook liên tục.<sup>[[12]](#references)</sup> Đảm bảo VEH và mọi metadata mà nó cần đều có thể truy cập trong lúc dispatch.<sup>[[11]](#references)</sup> Trên x64, dữ liệu unwind có thể cần sẵn sàng trước lỗi đầu tiên; loader được trích dẫn sẽ tạo trang một cách eager trước khi gọi `DllMain` để tránh race condition khi khởi tạo.<sup>[[11]](#references)</sup> Flush instruction cache sau khi ghi mã và trước khi thực thi mã đó.<sup>[[13]](#references)</sup>

Để khôi phục luồng này khi reverse, đặt breakpoint tại các guard-page violation và access violation xảy ra lần đầu, kiểm tra exception record, rồi chuyển sự kiện cho handler của ứng dụng bằng `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Dùng `!vprot` trên địa chỉ được truy cập để kiểm tra protection hiện tại của trang.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Sau khi handler materialize page, dump các byte của nó và so sánh với file image.<sup>[[11]](#references)</sup> Lệnh `!vprot` sau fault không thể chứng minh page đã được guard từ trước vì trạng thái guard chỉ dùng một lần.<sup>[[11]](#references)[[12]](#references)</sup> Thu hẹp các exception filter hoặc handler breakpoint sau khi xác định được image range liên quan để tránh các fault không liên quan.<sup>[[16]](#references)</sup> Xem [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) để thiết lập filter.<sup>[[16]](#references)</sup>

## Trap Flag làm cổng phụ thuộc vào debugger

Bit `0x100` trong `EFLAGS`/`RFLAGS` là Trap Flag (TF). Việc đặt bit này khiến ranh giới lệnh tiếp theo phát sinh `STATUS_SINGLE_STEP` (`0x80000004`). Một nhánh VEH hoặc SEH có thể phân biệt sự kiện single-step được chuyển đến ứng dụng với sự kiện bị debugger xử lý, nhưng đây chỉ là **heuristic chịu ảnh hưởng bởi exception policy của debugger**, không phải bằng chứng đáng tin cậy rằng có debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Nếu handler chỉ muốn thực hiện một bước, hãy xóa `0x100` trong `EFlags` của context được tiếp tục trước khi tiếp tục chạy. Đồng thời phân biệt các bước do TF kích hoạt với sự kiện hardware-breakpoint bằng cách kiểm tra địa chỉ kích hoạt và trạng thái debug; cả hai đều có thể xuất hiện dưới dạng `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Để biết về các thiết lập first-chance/second-chance của `sxe`, `sxd` và `sxi` trong WinDbg, xem [Tự động hóa exception trong WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Xử lý exception của debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Xử lý exception vectored](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Xử lý exception x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Sử dụng Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Lệnh Assembly](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Kiến trúc x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Tải image dựa trên lỗi](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Tạo Guard Page](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Hiển thị bản ghi exception)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - Bộ lọc exception sx](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Tiếp tục khi exception chưa được xử lý)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
