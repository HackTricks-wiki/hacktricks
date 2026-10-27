# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Ban đầu, hàm `task_threads()` được gọi trên task port để lấy danh sách thread từ task từ xa. Một thread được chọn để chiếm quyền điều khiển. Cách tiếp cận này khác với các phương pháp code injection thông thường vì không thể tạo thread từ xa mới do cơ chế giảm thiểu ngăn `thread_create_running()`.<sup>[[1]](#references)</sup>

Để điều khiển thread, `thread_suspend()` được gọi nhằm tạm dừng quá trình thực thi của nó.<sup>[[1]](#references)</sup>

Các thao tác duy nhất được phép trên thread từ xa là **dừng**, **khởi chạy**, **lấy** và **sửa đổi** các giá trị thanh ghi của nó. Các lệnh gọi hàm từ xa được khởi chạy bằng cách đặt các thanh ghi `x0` đến `x7` thành các **đối số**, cấu hình `pc` trỏ đến hàm mong muốn, rồi tiếp tục chạy thread. Để đảm bảo thread không bị crash sau khi hàm trả về, cần phát hiện thời điểm hàm trả về.<sup>[[1]](#references)</sup>

Một chiến lược là đăng ký **exception handler** cho thread từ xa bằng `thread_set_exception_ports()`, đồng thời đặt thanh ghi `lr` thành một địa chỉ không hợp lệ trước khi gọi hàm. Điều này kích hoạt một exception sau khi hàm thực thi xong, gửi thông điệp đến exception port, cho phép kiểm tra trạng thái thread để lấy giá trị trả về. Một cách khác, được áp dụng từ exploit *triple_fetch* của Ian Beer, là đặt `lr` để lặp vô hạn; sau đó, các thanh ghi của thread được giám sát liên tục cho đến khi `pc` trỏ đến lệnh đó.<sup>[[1]](#references)</sup>

## 2. Mach ports để giao tiếp

Giai đoạn tiếp theo là thiết lập Mach ports để hỗ trợ giao tiếp với thread từ xa. Các port này giúp chuyển các quyền send/receive tùy ý giữa các task.<sup>[[1]](#references)</sup>

Để giao tiếp hai chiều, hai quyền receive Mach được tạo: một trong task cục bộ và một trong task từ xa. Sau đó, quyền send cho mỗi port được chuyển đến task còn lại để có thể trao đổi thông điệp.<sup>[[1]](#references)</sup>

Xét port cục bộ: quyền receive được giữ bởi task cục bộ. Port được tạo bằng `mach_port_allocate()`. Thách thức là chuyển quyền send đến port này vào task từ xa.<sup>[[1]](#references)</sup>

Một chiến lược là dùng `thread_set_special_port()` để đặt quyền send đến port cục bộ trong `THREAD_KERNEL_PORT` của thread từ xa. Sau đó, yêu cầu thread từ xa gọi `mach_thread_self()` để lấy quyền send.<sup>[[1]](#references)</sup>

Với port từ xa, quy trình về cơ bản được đảo ngược. Thread từ xa được yêu cầu tạo Mach port bằng `mach_reply_port()` (vì `mach_port_allocate()` không phù hợp do cách hàm trả về). Sau khi tạo port, `mach_port_insert_right()` được gọi trong thread từ xa để tạo quyền send. Quyền này sau đó được lưu tạm trong kernel bằng `thread_set_special_port()`. Trở lại task cục bộ, `thread_get_special_port()` được gọi trên thread từ xa để lấy quyền send đến Mach port vừa được cấp phát trong task từ xa.<sup>[[1]](#references)</sup>

Hoàn tất các bước này sẽ thiết lập các Mach port, tạo nền tảng cho giao tiếp hai chiều.<sup>[[1]](#references)</sup>

## 3. Các primitive đọc/ghi bộ nhớ cơ bản

Trong phần này, trọng tâm là sử dụng primitive thực thi để tạo các primitive đọc/ghi bộ nhớ cơ bản. Những bước ban đầu này rất quan trọng để kiểm soát tiến trình từ xa tốt hơn, dù các primitive ở giai đoạn này chưa có nhiều công dụng. Chúng sẽ sớm được nâng cấp thành các phiên bản nâng cao hơn.<sup>[[1]](#references)</sup>

### Đọc và ghi bộ nhớ bằng primitive thực thi

Mục tiêu là đọc và ghi bộ nhớ bằng các hàm cụ thể. Để **đọc bộ nhớ**:

```c
uint64_t read_func(uint64_t *address) {
    return *address;
}
```

Để **ghi vào bộ nhớ**:

```c
void write_func(uint64_t *address, uint64_t value) {
    *address = value;
}
```

Các hàm này tương ứng với mã assembly sau:

```
_read_func:
    ldr x0, [x0]
    ret
_write_func:
    str x1, [x0]
    ret
```

### Xác định các hàm phù hợp

Quét các thư viện phổ biến cho thấy có những hàm phù hợp để thực hiện các thao tác này:<sup>[[1]](#references)</sup>

1. **Đọc bộ nhớ — `property_getName()`** (libobjc):

```c
const char *property_getName(objc_property_t prop) {
    return prop->name;
}
```

2. **Ghi vào bộ nhớ — `_xpc_int64_set_value()`** (libxpc):

```c
__xpc_int64_set_value:
    str x1, [x0, #0x18]
    ret
```

Để thực hiện thao tác ghi 64-bit tại một địa chỉ bất kỳ:

```c
_xpc_int64_set_value(address - 0x18, value);
```

Khi đã thiết lập các primitive này, bước tiếp theo là tạo shared memory, đánh dấu một bước tiến đáng kể trong việc kiểm soát process từ xa.<sup>[[1]](#references)</sup>

## 4. Thiết lập Shared Memory

Mục tiêu là thiết lập shared memory giữa các task cục bộ và từ xa, giúp đơn giản hóa việc truyền dữ liệu và hỗ trợ gọi các function có nhiều tham số. Phương pháp này tận dụng `libxpc` và kiểu object `OS_xpc_shmem`, được xây dựng dựa trên Mach memory entry.<sup>[[1]](#references)</sup>

### Tổng quan quy trình

1. **Cấp phát bộ nhớ**
   * Cấp phát bộ nhớ để chia sẻ bằng `mach_vm_allocate()`.  
   * Dùng `xpc_shmem_create()` để tạo object `OS_xpc_shmem` cho vùng đã cấp phát.
2. **Tạo shared memory trong process từ xa**
   * Cấp phát bộ nhớ cho object `OS_xpc_shmem` trong process từ xa (`remote_malloc`).  
   * Sao chép object mẫu cục bộ; vẫn cần fix-up Mach send right được nhúng tại offset `0x18`.
3. **Điều chỉnh Mach memory entry**
   * Thêm một send right bằng `thread_set_special_port()` và ghi đè trường `0x18` bằng tên của entry từ xa.
4. **Hoàn tất**
   * Xác thực object từ xa và map nó bằng một lời gọi từ xa tới `xpc_shmem_remote()`.

## 5. Đạt được toàn quyền kiểm soát

Khi đã có khả năng thực thi tùy ý và kênh liên lạc back-channel qua shared memory, về cơ bản bạn nắm quyền kiểm soát process mục tiêu:<sup>[[1]](#references)</sup>

* **Đọc/ghi bộ nhớ tùy ý** — dùng `memcpy()` giữa các vùng cục bộ và shared.  
* **Gọi function với hơn 8 tham số** — đặt các tham số bổ sung lên stack theo quy ước gọi hàm arm64.  
* **Chuyển Mach port** — truyền các quyền trong Mach message thông qua các port đã thiết lập.  
* **Chuyển file descriptor** — tận dụng fileport (xem *triple_fetch*).

Toàn bộ quy trình này được đóng gói trong thư viện [`threadexec`](https://github.com/bazad/threadexec) để dễ dàng tái sử dụng.

---

## 6. Các điểm cần lưu ý trên Apple Silicon (arm64e)

Trên các thiết bị Apple Silicon (arm64e), **Pointer Authentication Codes (PAC)** bảo vệ mọi địa chỉ trả về và nhiều function pointer. Các kỹ thuật chiếm quyền điều khiển thread bằng cách *tái sử dụng code có sẵn* vẫn hoạt động vì các giá trị gốc trong `lr`/`pc` đã có chữ ký PAC hợp lệ. Vấn đề phát sinh khi bạn cố nhảy tới bộ nhớ do attacker kiểm soát:

1. Cấp phát bộ nhớ có quyền thực thi bên trong target (`mach_vm_allocate` từ xa + `mprotect(PROT_EXEC)`).
2. Sao chép payload của bạn.
3. Bên trong process *từ xa*, ký pointer này:

```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```

4. Đặt `pc = ptr` trong trạng thái của thread bị chiếm quyền.

Ngoài ra, để tuân thủ PAC, hãy nối chuỗi các gadget/function có sẵn (ROP truyền thống).

## 7. Phát hiện & Hardening với EndpointSecurity

Framework **EndpointSecurity (ES)** cung cấp các sự kiện kernel, cho phép bên phòng thủ giám sát hoặc chặn các nỗ lực thread injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – được kích hoạt khi một process yêu cầu port của task khác (ví dụ: `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – được phát ra mỗi khi một thread được tạo trong một task *khác*.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (được thêm vào macOS 14 Sonoma) – cho biết có thao tác chỉnh sửa register của một thread hiện có.

Client Swift tối giản in các sự kiện remote-thread:

```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
    (_, msg) in
    if let evt = msg.remoteThreadCreate {
        print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
    }
}
RunLoop.main.run()
```

Truy vấn bằng **osquery** ≥ 5.8:

```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```

### Các lưu ý về hardened runtime

Phân phối ứng dụng của bạn **mà không có** entitlement `com.apple.security.get-task-allow` sẽ ngăn kẻ tấn công không có quyền root lấy task-port của ứng dụng. System Integrity Protection (SIP) vẫn chặn quyền truy cập vào nhiều binary của Apple, nhưng phần mềm bên thứ ba phải chủ động opt-out.

## 8. Công cụ công khai gần đây (2023-2025)

| Công cụ | Năm | Ghi chú |
|------|---------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC gọn nhẹ minh họa kỹ thuật chiếm quyền điều khiển thread có xét đến PAC trên Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | Công cụ hỗ trợ EndpointSecurity được một số nhà cung cấp EDR sử dụng để phát hiện các sự kiện `REMOTE_THREAD_CREATE` |

> Đọc mã nguồn của các dự án này sẽ giúp hiểu những thay đổi API được giới thiệu trong macOS 13/14 và duy trì khả năng tương thích giữa Intel ↔ Apple Silicon.

## References

- [1] [Vượt qua các hạn chế đối với platform binary bằng task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Tài liệu dành cho nhà phát triển của Apple](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
