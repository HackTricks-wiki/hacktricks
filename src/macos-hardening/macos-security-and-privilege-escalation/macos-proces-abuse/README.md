# Lạm dụng tiến trình macOS

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản về tiến trình

Tiến trình là một thực thể của chương trình thực thi đang chạy, tuy nhiên tiến trình không chạy mã mà các thread mới chạy mã. Vì vậy, **tiến trình chỉ là các vùng chứa các thread đang chạy**, cung cấp bộ nhớ, bộ mô tả, cổng, quyền...

Theo cách truyền thống, các tiến trình được khởi chạy bên trong các tiến trình khác (ngoại trừ PID 1) bằng cách gọi **`fork`**, thao tác này tạo một bản sao chính xác của tiến trình hiện tại, sau đó **tiến trình con** thường gọi **`execve`** để tải chương trình thực thi mới và chạy nó. Sau đó, **`vfork`** được giới thiệu để tăng tốc quá trình này mà không cần sao chép bộ nhớ.\
Tiếp đó, **`posix_spawn`** được giới thiệu, kết hợp **`vfork`** và **`execve`** trong một lần gọi và chấp nhận các cờ:

- `POSIX_SPAWN_RESETIDS`: Đặt lại ID hiệu lực thành ID thực
- `POSIX_SPAWN_SETPGROUP`: Đặt nhóm tiến trình
- `POSUX_SPAWN_SETSIGDEF`: Đặt hành vi mặc định của tín hiệu
- `POSIX_SPAWN_SETSIGMASK`: Đặt mặt nạ tín hiệu
- `POSIX_SPAWN_SETEXEC`: Thực thi trong cùng tiến trình (như `execve` với nhiều tùy chọn hơn)
- `POSIX_SPAWN_START_SUSPENDED`: Khởi chạy ở trạng thái tạm dừng
- `_POSIX_SPAWN_DISABLE_ASLR`: Khởi chạy mà không có ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Sử dụng bộ cấp phát Nano của libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Cho phép `rwx` trên các phân đoạn dữ liệu
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Mặc định đóng mọi mô tả tệp khi thực thi `exec(2)`
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Ngẫu nhiên hóa các bit cao của độ dịch ASLR

Ngoài ra, `posix_spawn` chấp nhận các thiết lập **`posix_spawnattr`** để kiểm soát các khía cạnh của tiến trình được tạo và các mục **`posix_spawn_file_actions`** để sửa đổi các bộ mô tả tệp.

Khi một tiến trình kết thúc, nó gửi **mã trả về cho tiến trình cha** (nếu tiến trình cha đã kết thúc, tiến trình cha mới là PID 1) bằng tín hiệu `SIGCHLD`. Tiến trình cha cần lấy giá trị này bằng cách gọi `wait4()` hoặc `waitid()`; cho đến khi việc đó xảy ra, tiến trình con vẫn ở trạng thái zombie, vẫn được liệt kê nhưng không tiêu tốn tài nguyên.

### PID

PID (mã định danh tiến trình) xác định một tiến trình duy nhất. Trong XNU, **PID** có độ dài **64 bit**, tăng đơn điệu và **không bao giờ quay vòng** (để tránh bị lạm dụng).

### Nhóm tiến trình, phiên và coalition

**Các tiến trình** có thể được đưa vào **nhóm** để dễ quản lý hơn. Ví dụ, các lệnh trong một shell script sẽ nằm trong cùng một nhóm tiến trình, nhờ đó có thể **gửi tín hiệu đến chúng cùng lúc**, chẳng hạn bằng `kill`.\
Cũng có thể **nhóm các tiến trình thành các phiên**. Khi một tiến trình bắt đầu một phiên (`setsid(2)`), các tiến trình con sẽ thuộc phiên đó, trừ khi chúng bắt đầu phiên riêng.

Coalition là một cách khác để nhóm các tiến trình trong Darwin. Một tiến trình tham gia coalition có thể truy cập các tài nguyên dùng chung, chia sẻ một sổ cái hoặc chịu sự điều phối của Jetsam. Coalition có các vai trò khác nhau: Leader, dịch vụ XPC, Extension.

### Thông tin xác thực và persona

Mỗi tiến trình đều có **thông tin xác thực** để **xác định các đặc quyền** của nó trong hệ thống. Mỗi tiến trình có một `uid` chính và một `gid` chính (mặc dù có thể thuộc nhiều nhóm).\
Cũng có thể thay đổi ID người dùng và nhóm nếu tệp nhị phân có bit `setuid/setgid`.\
Có một số hàm để **đặt uid/gid mới**.

Lệnh gọi hệ thống **`persona`** cung cấp một bộ **thông tin xác thực** **thay thế**. Áp dụng persona sẽ đồng thời sử dụng uid, gid và các nhóm thành viên của persona đó. Trong [**mã nguồn**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), có thể tìm thấy cấu trúc sau:

```c
struct kpersona_info { uint32_t persona_info_version;
    uid_t    persona_id; /* overlaps with UID */
    int      persona_type;
    gid_t    persona_gid;
    uint32_t persona_ngroups;
    gid_t    persona_groups[NGROUPS];
    uid_t    persona_gmuid;
    char     persona_name[MAXLOGNAME + 1];

    /* TODO: MAC policies?! */
}
```

## Thông tin cơ bản về luồng

1. **POSIX Threads (pthreads):** macOS hỗ trợ POSIX threads (`pthreads`), một phần của API luồng tiêu chuẩn dành cho C/C++. Phần triển khai pthreads trong macOS nằm tại `/usr/lib/system/libsystem_pthread.dylib`, có nguồn gốc từ dự án `libpthread` được cung cấp công khai. Thư viện này cung cấp các hàm cần thiết để tạo và quản lý luồng.
2. **Tạo luồng:** Hàm `pthread_create()` được dùng để tạo luồng mới. Bên trong, hàm này gọi `bsdthread_create()`, một lời gọi hệ thống cấp thấp dành riêng cho kernel XNU (kernel làm nền tảng cho macOS). Lời gọi hệ thống này nhận nhiều cờ khác nhau, được lấy từ `pthread_attr` (các thuộc tính), để chỉ định cách luồng hoạt động, bao gồm chính sách lập lịch và kích thước stack.
   - **Kích thước stack mặc định:** Kích thước stack mặc định cho luồng mới là 512 KB, đủ cho các hoạt động thông thường nhưng có thể điều chỉnh thông qua thuộc tính luồng nếu cần thêm hoặc bớt dung lượng.
3. **Khởi tạo luồng:** Hàm `__pthread_init()` đóng vai trò quan trọng trong quá trình thiết lập luồng, sử dụng đối số `env[]` để phân tích các biến môi trường có thể chứa thông tin về vị trí và kích thước stack.

#### Kết thúc luồng trong macOS

1. **Thoát khỏi luồng:** Luồng thường được kết thúc bằng cách gọi `pthread_exit()`. Hàm này cho phép luồng thoát một cách an toàn, thực hiện các bước dọn dẹp cần thiết và gửi giá trị trả về cho bất kỳ luồng nào đang chờ nó.
2. **Dọn dẹp luồng:** Khi gọi `pthread_exit()`, hàm `pthread_terminate()` sẽ được gọi để xử lý việc loại bỏ tất cả cấu trúc dữ liệu liên quan đến luồng. Hàm này giải phóng các cổng Mach của luồng (Mach là hệ thống con giao tiếp trong kernel XNU) và gọi `bsdthread_terminate`, một syscall loại bỏ các cấu trúc ở cấp kernel gắn với luồng.

#### Cơ chế đồng bộ hóa

Để quản lý quyền truy cập vào tài nguyên dùng chung và tránh race condition, macOS cung cấp một số primitive đồng bộ hóa. Đây là những thành phần quan trọng trong môi trường đa luồng, giúp đảm bảo tính toàn vẹn dữ liệu và độ ổn định của hệ thống:

1. **Mutex:**
   - **Mutex thông thường (Chữ ký: 0x4D555458):** Mutex tiêu chuẩn có dung lượng bộ nhớ là 60 byte (56 byte cho mutex và 4 byte cho chữ ký).
   - **Fast Mutex (Chữ ký: 0x4d55545A):** Tương tự mutex thông thường nhưng được tối ưu để thực hiện thao tác nhanh hơn, cũng có kích thước 60 byte.
2. **Biến điều kiện:**
   - Được dùng để chờ một số điều kiện xảy ra, có kích thước 44 byte (40 byte cộng với chữ ký 4 byte).
   - **Thuộc tính biến điều kiện (Chữ ký: 0x434e4441):** Các thuộc tính cấu hình cho biến điều kiện, có kích thước 12 byte.
3. **Biến Once (Chữ ký: 0x4f4e4345):**
   - Đảm bảo một đoạn mã khởi tạo chỉ được thực thi một lần. Kích thước của nó là 12 byte.
4. **Read-Write Lock:**
   - Cho phép nhiều luồng đọc hoặc một luồng ghi tại một thời điểm, giúp truy cập dữ liệu dùng chung hiệu quả.
   - **Read Write Lock (Chữ ký: 0x52574c4b):** Có kích thước 196 byte.
   - **Thuộc tính Read Write Lock (Chữ ký: 0x52574c41):** Các thuộc tính dành cho read-write lock, có kích thước 20 byte.

> [!TIP]
> 4 byte cuối cùng của các đối tượng này được dùng để phát hiện tràn bộ đệm.

### Biến cục bộ theo luồng (TLV)

**Biến cục bộ theo luồng (TLV)** trong các tệp Mach-O (định dạng tệp thực thi trong macOS) được dùng để khai báo các biến dành riêng cho **từng luồng** trong ứng dụng đa luồng. Điều này đảm bảo mỗi luồng có một bản sao riêng của biến, giúp tránh xung đột và duy trì tính toàn vẹn dữ liệu mà không cần các cơ chế đồng bộ hóa tường minh như mutex.

Trong C và các ngôn ngữ liên quan, bạn có thể khai báo biến cục bộ theo luồng bằng từ khóa **`__thread`**. Ví dụ sau hoạt động như sau:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Đoạn mã này định nghĩa `tlv_var` là một biến cục bộ của luồng. Mỗi luồng chạy đoạn mã này sẽ có `tlv_var` riêng, và các thay đổi mà một luồng thực hiện với `tlv_var` sẽ không ảnh hưởng đến `tlv_var` của luồng khác.

Trong binary Mach-O, dữ liệu liên quan đến các biến cục bộ của luồng được tổ chức trong những section cụ thể:

- **`__DATA.__thread_vars`**: Section này chứa metadata về các biến cục bộ của luồng, chẳng hạn như kiểu và trạng thái khởi tạo của chúng.
- **`__DATA.__thread_bss`**: Section này dành cho các biến cục bộ của luồng chưa được khởi tạo tường minh. Đây là một vùng bộ nhớ dành riêng cho dữ liệu được khởi tạo bằng giá trị 0.

Mach-O cũng cung cấp API riêng có tên **`tlv_atexit`** để quản lý các biến cục bộ của luồng khi một luồng kết thúc. API này cho phép bạn **đăng ký hàm hủy** — các hàm đặc biệt dùng để dọn dẹp dữ liệu cục bộ của luồng khi luồng chấm dứt.

### Ưu tiên luồng

Để hiểu về mức ưu tiên của luồng, cần xem xét cách hệ điều hành quyết định luồng nào sẽ chạy và chạy khi nào. Quyết định này chịu ảnh hưởng bởi mức ưu tiên được gán cho từng luồng. Trong macOS và các hệ thống giống Unix, việc này được xử lý bằng các khái niệm như `nice`, `renice` và các lớp Quality of Service (QoS).

#### Nice và Renice

1. **Nice:**
   - Giá trị `nice` của một tiến trình là một con số ảnh hưởng đến mức ưu tiên của tiến trình đó. Mỗi tiến trình có giá trị `nice` trong khoảng từ -20 (mức ưu tiên cao nhất) đến 19 (mức ưu tiên thấp nhất). Giá trị `nice` mặc định khi tạo tiến trình thường là 0.
   - Giá trị `nice` càng thấp (càng gần -20) thì tiến trình càng “ích kỷ”, được cấp nhiều thời gian CPU hơn các tiến trình có giá trị `nice` cao hơn.
2. **Renice:**
   - `renice` là lệnh dùng để thay đổi giá trị `nice` của một tiến trình đang chạy. Lệnh này có thể được dùng để điều chỉnh động mức ưu tiên của tiến trình, tăng hoặc giảm thời gian CPU được cấp tùy theo giá trị `nice` mới.
   - Ví dụ, nếu một tiến trình tạm thời cần thêm tài nguyên CPU, bạn có thể giảm giá trị `nice` của nó bằng `renice`.

#### Các lớp Quality of Service (QoS)

Các lớp QoS là cách tiếp cận hiện đại hơn để xử lý mức ưu tiên của luồng, đặc biệt trên những hệ thống như macOS hỗ trợ **Grand Central Dispatch (GCD)**. Các lớp QoS cho phép nhà phát triển **phân loại** công việc thành nhiều mức khác nhau dựa trên tầm quan trọng hoặc tính khẩn cấp. macOS tự động quản lý mức ưu tiên của luồng dựa trên các lớp QoS này:

1. **User Interactive:**
   - Lớp này dành cho các tác vụ đang tương tác với người dùng hoặc cần có kết quả ngay lập tức để mang lại trải nghiệm tốt. Các tác vụ này được ưu tiên cao nhất để giao diện luôn phản hồi nhanh (ví dụ: hoạt ảnh hoặc xử lý sự kiện).
2. **User Initiated:**
   - Các tác vụ do người dùng khởi chạy và cần có kết quả ngay, chẳng hạn như mở tài liệu hoặc nhấp vào nút cần thực hiện tính toán. Đây là các tác vụ có mức ưu tiên cao, nhưng thấp hơn User Interactive.
3. **Utility:**
   - Các tác vụ này chạy trong thời gian dài và thường hiển thị chỉ báo tiến độ (ví dụ: tải tệp xuống, nhập dữ liệu). Chúng có mức ưu tiên thấp hơn các tác vụ do người dùng khởi chạy và không cần hoàn tất ngay lập tức.
4. **Background:**
   - Lớp này dành cho các tác vụ chạy nền và người dùng không nhìn thấy. Các tác vụ này có thể bao gồm lập chỉ mục, đồng bộ hóa hoặc sao lưu. Chúng có mức ưu tiên thấp nhất và ảnh hưởng tối thiểu đến hiệu năng hệ thống.

Với các lớp QoS, nhà phát triển không cần quản lý các con số ưu tiên cụ thể mà chỉ cần tập trung vào tính chất của tác vụ; hệ thống sẽ tối ưu hóa tài nguyên CPU tương ứng.

Ngoài ra còn có các **chính sách lập lịch luồng** khác nhau, cho phép chỉ định tập hợp tham số lập lịch mà bộ lập lịch sẽ cân nhắc. Có thể thực hiện việc này bằng `thread_policy_[set/get]`. Điều này có thể hữu ích trong các cuộc tấn công race condition.

## Lạm dụng tiến trình macOS

macOS cung cấp nhiều cơ chế để **các tiến trình tương tác, giao tiếp và chia sẻ dữ liệu**. Dù những cơ chế này thiết yếu cho hoạt động bình thường của hệ thống, kẻ tấn công có thể lạm dụng chúng để injection, thực thi mã hoặc truy cập dữ liệu.

### Library Injection

Library Injection là kỹ thuật trong đó kẻ tấn công **buộc một tiến trình tải thư viện độc hại**. Sau khi được inject, thư viện chạy trong ngữ cảnh của tiến trình mục tiêu, giúp kẻ tấn công có cùng quyền và khả năng truy cập như tiến trình đó.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking là kỹ thuật **chặn các lệnh gọi hàm** hoặc thông điệp trong mã phần mềm. Bằng cách hook các hàm, kẻ tấn công có thể **thay đổi hành vi** của tiến trình, quan sát dữ liệu nhạy cảm hoặc thậm chí kiểm soát luồng thực thi.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Trang này trình bày metadata unwind của ARM64, các ràng buộc PAC của arm64e và các chuỗi lệnh gọi tổng hợp.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Giao tiếp liên tiến trình

Giao tiếp liên tiến trình (IPC) là các phương thức khác nhau để các tiến trình riêng biệt **chia sẻ và trao đổi dữ liệu**. Dù IPC là nền tảng của nhiều ứng dụng hợp pháp, nó cũng có thể bị lạm dụng để phá vỡ cơ chế cô lập tiến trình, làm rò rỉ thông tin nhạy cảm hoặc thực hiện các hành động trái phép.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection ứng dụng Electron

Các ứng dụng Electron chạy với những biến môi trường cụ thể có thể dễ bị process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Có thể sử dụng các flag `--load-extension` và `--use-fake-ui-for-media-stream` để thực hiện **tấn công man in the browser**, qua đó đánh cắp thao tác gõ phím, lưu lượng mạng, cookie, inject script vào các trang...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Các tệp NIB **định nghĩa các thành phần giao diện người dùng (UI)** và cách chúng tương tác trong một ứng dụng. Tuy nhiên, chúng có thể **thực thi các lệnh tùy ý**, và **Gatekeeper không ngăn** một ứng dụng đã được thực thi chạy lại nếu **tệp NIB bị sửa đổi**. Vì vậy, chúng có thể được dùng để khiến các chương trình tùy ý thực thi lệnh tùy ý:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection ứng dụng Java

Có thể inject các tùy chọn JVM thông qua **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** hoặc **`JDK_JAVA_OPTIONS`** để tải một Java agent hoặc native agent trước khi ứng dụng khởi chạy.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** preload JavaScript do kẻ tấn công kiểm soát thông qua `--require` (tệp) hoặc `--import data:text/javascript,…` (không cần tệp, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** tải một module vào REPL tương tác, còn **`ELECTRON_RUN_AS_NODE`** bật lại tất cả các cách này trên binary Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection ứng dụng .Net

Có thể inject mã vào ứng dụng .NET thông qua **`DOTNET_STARTUP_HOOKS`** trước khi chạy `Main`, hoặc lạm dụng chức năng debug của .NET khi đáp ứng đủ điều kiện cần thiết.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash không tương tác đọc **`BASH_ENV`**; các shell POSIX tương tác đọc **`ENV`**; zsh đọc **`$ZDOTDIR/.zshenv`**; còn fish đọc cấu hình bên dưới **`XDG_CONFIG_HOME`** hoặc **`XDG_DATA_DIRS`**. Mỗi shell đều có thể thực thi một tệp khởi động do kẻ tấn công kiểm soát trước khi chạy lệnh dự kiến. Bash cũng chạy một command substitution được đặt trong **`PS4`** mỗi khi bật xtrace (ví dụ: **`SHELLOPTS=xtrace`** được kế thừa):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Lén đưa lệnh qua stdin của shell

Khởi chạy `/bin/zsh -s` khiến shell đọc chương trình từ standard input. Vì vậy, nếu một trình tải sao chép tài liệu có cấu trúc không đáng tin cậy vào stdin của tiến trình con mà không phân tích trước, toàn bộ tài liệu sẽ trở thành mã nguồn shell. Một loader từng được ghi nhận đã chuyển từng dòng của một tệp iCalendar công khai qua một anonymous pipe. Metadata lịch bị lỗi khi chạy dưới dạng lệnh, nhưng zsh vẫn tiếp tục cho đến khi gặp các dòng có thể thực thi được đặt sau `DESCRIPTION:`. Những dòng đó tải xuống và khởi chạy application bundle tiếp theo. Content type dự kiến của dữ liệu và việc lưu trữ trên máy chủ đáng tin cậy không khiến cách làm này an toàn; ranh giới nguy hiểm nằm ở việc chuyển các byte của dữ liệu cho một trình thông dịch.<sup>[[5]](#references)</sup>

Các giai đoạn liên quan được trình bày trong [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) và [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** hoặc **`PHP_INI_SCAN_DIR`** có thể tải cấu hình PHP do kẻ tấn công kiểm soát, trong đó **`auto_prepend_file`** thực thi trước script mục tiêu.

[Cấu hình PHP và injection khi khởi động bằng `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Trình thông dịch Lua độc lập thực thi mã hoặc một `@file` từ **`LUA_INIT`** (hoặc biến thể dành riêng cho phiên bản) trước khi xử lý script mục tiêu.

[Injection khi khởi động Lua bằng `LUA_INIT` (tệp và mã inline)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** và **`R_PROFILE`** chuyển hướng đến các profile khởi động chứa mã R. Ngoài ra, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** kết hợp với đường dẫn thư viện R có thể tự động tải một package đã cài đặt.

[Profile khởi động R và tải package](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** chuyển hướng đến depot có `config/startup.jl` được tự động thực thi.

[Injection bằng `JULIA_DEPOT_PATH` và `startup.jl` của Julia](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang và Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** hoặc **`ERL_ZFLAGS`** có thể inject một biểu thức Erlang VM **`-eval`** mà không cần tệp payload; các workload Elixir thường khởi chạy cùng VM này.

[Injection bằng flag Erlang/Elixir VM](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** và **`OCTAVE_VERSION_INITFILE`** chuyển hướng đến các script khởi động của Octave.

[Injection bằng tệp khởi động GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` là ứng dụng .NET đa nền tảng, vì vậy một số biến môi trường có thể khiến mã chạy trước lệnh: **`XDG_CONFIG_HOME`** chuyển hướng đến các script profile chạy lúc khởi động, **`PSModulePath`** chiếm quyền cơ chế tự động tải module (một tệp `.psm1` được cài sẵn sẽ chạy khi import và có thể che khuất các cmdlet tích hợp sẵn), còn các biến .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** và **`DOTNET_STARTUP_HOOKS`** tải mã của kẻ tấn công vào tiến trình trước khi chạy `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Kiểm tra các tùy chọn khác nhau để khiến một script Perl thực thi mã tùy ý trong:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Cũng có thể lạm dụng các biến môi trường của Ruby (**`RUBYOPT`**, **`RUBYLIB`**) để khiến các script tùy ý thực thi mã tùy ý:


[Tùy chọn loader Ruby `RUBYOPT`/`RUBYLIB`](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Chuỗi kết hợp **`PYTHONWARNINGS`** và **`BROWSER`** trong standard library có thể thực thi một lệnh khi phân tích bộ lọc cảnh báo. Một phương án dùng tệp đặt `sitecustomize.py` trên **`PYTHONPATH`**, để quá trình khởi tạo `site` thông thường import tệp này trước script mục tiêu. **`PYTHONBREAKPOINT`** chạy callable/module được chọn khi mã gọi đến `breakpoint()`.

Trên CPython 3.13+, **`PYTHONINSPECT`** cũng có thể chạy một tệp **`PYTHONSTARTUP`** sau khi script kết thúc, khi PyREPL khởi chạy trong terminal.<sup>[[6]](#references)</sup>

Lưu ý rằng các executable được biên dịch bằng **`pyinstaller`** sẽ không sử dụng những biến môi trường này, ngay cả khi chúng chạy bằng Python nhúng.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (và biến dự phòng `EXINIT`) được thực thi dưới dạng lệnh Ex khi khởi động thông thường, nên `:!cmd` / `:call system(...)` sẽ cho phép thực thi mã khi nạn nhân mở Vim/Neovim với môi trường do kẻ tấn công kiểm soát:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Riêng biệt, Homebrew thường cài Python bên dưới `/opt/homebrew`, nơi các thành viên trong nhóm `admin` cục bộ có thể thay thế launcher. Đây là chiếm quyền binary có thể ghi được, không phải injection qua biến môi trường; hãy xác minh quyền sở hữu và ACL trước khi kết luận rằng có thể khai thác.


## Phát hiện

### Shield

[**Shield**](https://github.com/theevilbit/Shield) là ứng dụng mã nguồn mở dựa trên **EndpointSecurity**, có khả năng phát hiện và chặn process injection. Đây là tài liệu tham khảo hữu ích về những tín hiệu có thể quan sát qua Endpoint Security, vì ứng dụng này cảnh báo khi phát hiện:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Các biến môi trường injection** khi thực thi tiến trình: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` và `ELECTRON_RUN_AS_NODE`.
- Các lệnh gọi **`task_for_pid`** — một tiến trình yêu cầu task port của tiến trình khác; đây là điều kiện tiên quyết để inject vào tiến trình đó.
- **Các đối số debug của Electron** — `--inspect`, `--inspect-brk` và `--remote-debugging-port`, dùng để khởi chạy ứng dụng Electron ở chế độ debug và cho phép bất kỳ ai attach vào rồi thực thi mã bên trong ứng dụng.<sup>[[3]](#references)</sup>
- **Tạo symlink/hardlink giữa các cấp quyền** — primitive kinh điển “tạo link với tư cách người dùng thông thường rồi trỏ nó đến một vị trí đặc quyền”. Lưu ý rằng **có thể cảnh báo về symlink nhưng không thể chặn**: EndpointSecurity không cung cấp đích đến của link trước khi nó được tạo.

### Các lệnh gọi do tiến trình khác thực hiện

Trong [**bài blog này**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), bạn có thể tìm hiểu cách sử dụng hàm **`task_name_for_pid`** để lấy thông tin về các **tiến trình khác đang inject mã vào một tiến trình**, sau đó lấy thông tin về tiến trình đó.<sup>[[4]](#references)</sup>

Lưu ý rằng để gọi hàm này, bạn cần có **cùng uid** với người dùng chạy tiến trình hoặc phải là **root** (hàm trả về thông tin về tiến trình, chứ không cung cấp cách inject mã).



## References

- [1] [Shield — phát hiện process injection trên macOS, mã nguồn mở (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Vì sao ứng dụng Electron không thể lưu trữ bí mật một cách bảo mật: tùy chọn --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Phát hiện các sửa đổi task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Phiên bản mới của trình đánh cắp macOS MacSync nhắm vào những người đam mê tiền mã hóa và nhà phát triển](https://securelist.com/macsync-new-version/121383/)
- [6] [Dòng lệnh và môi trường Python — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
