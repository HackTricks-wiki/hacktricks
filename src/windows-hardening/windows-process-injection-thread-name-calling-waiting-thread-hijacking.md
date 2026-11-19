# Windows Process Injection qua Thread Names và Waiting Threads

{{#include ../banners/hacktricks-training.md}}

Thread Name-Calling (TNC) chuyển các byte vào một process đang chạy mà không cần `WriteProcessMemory`; Waiting Thread Hijacking (WTH) thực thi chúng trên một thread hiện có mà không cần `SetThreadContext` hoặc tạo remote thread.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Đây là **các primitive process-injection, không phải lỗ hổng leo thang đặc quyền**: injector vẫn cần quyền truy cập vào process và thread mục tiêu. Các API mô tả thread yêu cầu Windows 10 version 1607 trở lên.<sup>[[1]](#references)[[3]](#references)</sup> Xem [Antivirus (AV) Bypass](av-bypass.md) để biết các phương pháp injection và né tránh khác.

## Thread Name-Calling: sao chép payload ở phía mục tiêu

`NtSetInformationThread(ThreadNameInformation)` sao chép `UNICODE_STRING` được cung cấp vào vùng lưu trữ tên thread. Sau đó, gọi `GetThreadDescription` **bên trong mục tiêu** sẽ tạo một bản sao của tên trên user-mode heap. Cách này tách việc truyền payload khỏi lần sao chép bộ nhớ cuối cùng: injector có thể đọc **con trỏ** heap được trả về, trong khi một APC chạy `RtlMoveMemory` bên trong mục tiêu sao chép các byte đến đích.<sup>[[1]](#references)</sup> Kỹ thuật gốc cũng hỗ trợ special user APC; thay vào đó, implementation WhisperHijack dùng `NtQueueApcThread` thông thường trên một waiting thread.<sup>[[1]](#references)[[3]](#references)</sup>

Với mỗi chunk tối đa `0xFFFE` byte, PoC thực hiện theo thứ tự sau. Một event auto-reset được duplicate sẽ báo hiệu hoàn tất chỉ sau khi mục tiêu đã điền scratch slot; injector chờ tín hiệu đó trước khi đọc con trỏ. Event xác nhận APC lấy con trỏ heap, chứ không phải APC sao chép tiếp theo. PoC alert cùng thread sau khi xếp hàng APC sao chép và dựa vào thứ tự APC thay vì tín hiệu hoàn tất thứ hai.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Địa chỉ scratch phải có quyền ghi trong tiến trình đích và injector phải biết địa chỉ đó mà không cần ghi vào trước. PoC gốc sử dụng `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> WhisperHijack cũng cung cấp tùy chọn `PEB.PostProcessInitRoutine` và mặc định dùng `TEB.TlsSlots[63]` (được xác định bằng `NtQueryInformationThread(ThreadBasicInformation)`). TLS slot này **không được đảm bảo là chưa sử dụng** trong mọi tiến trình đích; ghi đè một slot đang hoạt động có thể làm hỏng thread đó. Bật chính xác một tùy chọn trong `Main.c`. Các kiểm tra tại thời điểm biên dịch sẽ từ chối nếu thiếu hoặc có xung đột trong lựa chọn PEB/TEB.<sup>[[4]](#references)</sup>

Lệnh gọi `RtlInitUnicodeString` thông thường sẽ dừng tại ký tự null wide nằm giữa chuỗi. Để truyền dữ liệu nhị phân, hãy khởi tạo độ dài `UNICODE_STRING` bằng một buffer đệm không null có cùng kích thước, thay các byte trong `Buffer` bằng chunk thực, rồi truyền nó cho `NtSetInformationThread`. Cách truyền dựa trên độ dài này khác với việc truyền trực tiếp shellcode cho `SetThreadDescription` dưới dạng chuỗi kết thúc bằng null.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: quay lại sau khi chờ queue

Liệt kê thread bằng `NtQuerySystemInformation(SystemProcessInformation)` và tìm thread có `ThreadState == Waiting` cùng `WaitReason == WrQueue`. Một thread bị chặn trong syscall wrapper như `NtWaitForWorkViaWorkerFactory` có địa chỉ trả về của caller được lưu tại `[Rsp]`. Thay slot trên stack đó sẽ chuyển hướng lệnh `ret` của wrapper đến một stub mà không thay đổi `Rip` qua `SetThreadContext`. Stub phải lưu flags và registers, **gọi** một payload có thể trả về, khôi phục trạng thái, rồi nhảy đến địa chỉ trả về ban đầu đã lưu.<sup>[[2]](#references)[[3]](#references)</sup>

Trong PoC x64, stub có slot lưu địa chỉ trả về dài 8 byte tại `+0x00`, các instruction tại `+0x08`, và payload tại `+0x45`. Slot trên stack nhận `allocation_base + 0x08`, không phải địa chỉ của data slot. Chỉ riêng `WrQueue` **không chứng minh** thread đang chờ worker-factory: nghiên cứu ban đầu cũng xác định `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` là một đường chờ queue. Hãy kiểm tra stack chờ/call thực tế và xác nhận `[Rsp]` là slot trả về dự kiến trước khi dựa vào bố cục này.<sup>[[2]](#references)[[3]](#references)</sup>

## Kết hợp TNC và WTH mà không ghi xuyên tiến trình

WhisperHijack trình bày workflow kết hợp này trên một tiến trình x64 native đang tồn tại. Writer chọn một tiến trình/thread phù hợp, còn một tiến trình con Flipper kế thừa các handle cần thiết cho bước chuyển giao cuối cùng. Handle tiến trình yêu cầu `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **không** yêu cầu `PROCESS_VM_WRITE`; tuy nhiên, PoC hiện tại vẫn mở thread với `THREAD_ALL_ACCESS`. Các kiểm tra quyền truy cập và biện pháp giảm thiểu của tiến trình vẫn được áp dụng.<sup>[[3]](#references)[[4]](#references)</sup>

PoC kết hợp sử dụng chuỗi thao tác sau; các APC sao chép bộ nhớ được thực thi trong tiến trình đích thay vì thông qua handle có quyền ghi từ xa.<sup>[[4]](#references)</sup>

1. Dành trước các block trống được căn chỉnh 64 KB trong tiến trình đích, rồi commit các page 4 KB của chúng với quyền `PAGE_READWRITE`. PoC dò các địa chỉ ứng viên cố định bằng `NtQueryVirtualMemory`; đây là lựa chọn triển khai, không phải yêu cầu của TNC hoặc WTH.
2. Tạo `[stub WTH dài 0x45 byte][payload x64 có thể trả về][con trỏ vào stub dài 8 byte]`, trong đó con trỏ cuối cùng là `allocation_base + 0x08`. Gửi buffer này bằng vòng lặp chunk TNC.
3. Trong Flipper, lấy `Rsp` của thread đang chờ bằng `NtGetContextThread(CONTEXT_CONTROL)`. Xếp hàng một APC `RtlMoveMemory` chạy trong tiến trình đích để sao chép giá trị 8 byte ban đầu tại `[Rsp]` vào data slot của stub.
4. Dùng `NtProtectVirtualMemory` để chuyển vùng đã staging thành vùng có quyền thực thi. PoC chọn `PAGE_EXECUTE_READWRITE` vì payload đa hình tự giải mã; bản thân WTH không yêu cầu payload tự sửa đổi.
5. Xếp hàng một APC `RtlMoveMemory` khác chạy trong tiến trình đích để sao chép **con trỏ đuôi đã staging trước** vào `[Rsp]`, rồi gọi `NtAlertThread`. Thứ tự APC FIFO sẽ lưu địa chỉ trả về ban đầu trước khi thay thế nó; khi wrapper trả về, luồng thực thi đi vào stub và tiếp tục tại caller ban đầu sau khi payload trả về.

Việc không có `NtWriteVirtualMemory` **không** có nghĩa là không có thao tác ghi vào tiến trình đích: `GetThreadDescription` và `RtlMoveMemory` thực hiện các thao tác đó bên trong tiến trình đích.<sup>[[1]](#references)[[3]](#references)</sup> Việc phân phối user APC thông thường cũng phụ thuộc vào việc thread được chọn xử lý hàng đợi APC của nó; snapshot `WrQueue` và một lệnh alert không đảm bảo APC sẽ được thực thi ngay lập tức trong mọi trường hợp.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Ví dụ này tránh tạo remote thread, suspend thread và thay thế context trực tiếp, nhưng vẫn có thể bị phát hiện thông qua APC và thay đổi quyền bảo vệ bộ nhớ.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Thread Name-Calling](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Waiting Thread Hijacking](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC và README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – triển khai WhisperHijack Main.c](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
