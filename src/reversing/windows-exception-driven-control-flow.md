# Luồng điều khiển dựa trên Exception của Windows và Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Một chương trình Windows được bảo vệ có thể dùng một exception có chủ đích làm nhánh: instruction gây lỗi chỉ là điểm vào một handler chọn địa chỉ user-code tiếp theo. Cách này che giấu các cạnh luồng điều khiển khỏi linear disassembly và chuyển bước tiếp theo vào quá trình dispatch exception.<sup>[[1]](#references)</sup>

## Dispatch rất quan trọng

Debugger gắn vào process sẽ nhận exception **first-chance** trước các handler của ứng dụng. Nếu debugger chuyển event đi dưới dạng chưa được xử lý, Windows sẽ tìm các handler của process; exception không có handler sẽ quay lại debugger dưới dạng **last-chance**. Do đó, debugger xử lý breakpoint hoặc event single-step có thể làm thay đổi việc handler của chương trình có chạy hay không.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` đăng ký một VEH toàn process ở đầu danh sách vectored. VEH chạy trước SEH dựa trên frame, nhưng một đăng ký khác có độ ưu tiên cao nhất được tạo sau đó có thể đưa handler khác lên trước nó. Việc trả về `EXCEPTION_CONTINUE_SEARCH` sẽ để exception cho các handler khác xử lý; `EXCEPTION_CONTINUE_EXECUTION` sẽ tiếp tục thực thi từ `CONTEXT` đã lưu, bao gồm mọi thay đổi thanh ghi do handler thực hiện.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

SEH x86 cổ điển sử dụng các đăng ký liên kết trên stack mà `!exchain` có thể kiểm tra. x64 native dùng các entry `RUNTIME_FUNCTION` trong `.pdata` với dữ liệu unwind trong `.xdata`, không dùng chain của x86. Không áp dụng [quy trình ghi đè SEH x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) cho process x64 native.<sup>[[5]](#references)[[6]](#references)</sup>

## Biến lỗi thành một cạnh luồng điều khiển

Ví dụ, phép chia cho số không có thể cố ý gây ra `EXCEPTION_INT_DIVIDE_BY_ZERO` thay vì là một bug. Handler phải nhận diện exception và địa chỉ gây lỗi, sau đó đặt `ContextRecord->Rip` (hoặc `Eip` trên x86) thành một điểm tiếp tục hợp lệ trước khi trả về `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Phần lõi của handler bên dưới giả định `fault_site` và `continuation` là các địa chỉ đã biết trong cùng một ngữ cảnh control-flow. Một triển khai thực tế phải giữ nguyên stack và các thanh ghi như mong đợi, đồng thời không được tiếp tục tại chính instruction gây lỗi, nếu không lỗi sẽ xảy ra lần nữa.<sup>[[7]](#references)</sup>

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

Cơ chế tương tự có thể xử lý một `INT3`/`__debugbreak()` có chủ đích (`EXCEPTION_BREAKPOINT`) và chuyển hướng thực thi. **Không** tùy tiện tăng `Rip` để “bỏ qua breakpoint”: địa chỉ đã lưu và mức điều chỉnh cần thiết phụ thuộc vào trap, mã hóa lệnh và hành vi của debugger. Hãy so sánh `ExceptionRecord->ExceptionAddress` với con trỏ lệnh đã lưu, đồng thời disassemble các byte trước khi chọn điểm tiếp tục.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) là một ví dụ riêng về hardware breakpoint, làm thay đổi trạng thái trả về của syscall loader.

## Trap Flag làm cổng phụ thuộc vào debugger

Bit `0x100` trong `EFLAGS`/`RFLAGS` là Trap Flag (TF). Bật bit này khiến ranh giới lệnh tiếp theo phát sinh `STATUS_SINGLE_STEP` (`0x80000004`). Nhánh VEH hoặc SEH có thể phân biệt sự kiện single-step được chuyển đến ứng dụng với sự kiện bị debugger xử lý, nhưng đây là một **heuristic chịu ảnh hưởng của chính sách xử lý exception trong debugger**, không phải bằng chứng đáng tin cậy cho thấy debugger tồn tại.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Nếu handler chỉ muốn thực hiện một bước, hãy xóa `0x100` khỏi `EFlags` của context được tiếp tục trước khi tiếp tục. Đồng thời phân biệt các bước do TF điều khiển với các sự kiện hardware breakpoint bằng cách kiểm tra địa chỉ gây kích hoạt và trạng thái debug; cả hai đều có thể xuất hiện dưới dạng `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Để xem các thiết lập first-/second-chance `sxe`, `sxd` và `sxi` của WinDbg, xem [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Chống debug: Exceptions](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Xử lý exception của debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Xử lý exception vectored](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Xử lý exception x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Sử dụng Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Chống debug: Các lệnh Assembly](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Kiến trúc x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
