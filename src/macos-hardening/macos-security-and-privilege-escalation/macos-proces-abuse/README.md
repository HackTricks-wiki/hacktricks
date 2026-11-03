# Lạm dụng tiến trình macOS

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản về tiến trình

Một tiến trình là một thực thể của tệp thực thi đang chạy, tuy nhiên tiến trình không chạy mã; các luồng mới chạy mã. Vì vậy, **tiến trình chỉ là vùng chứa các luồng đang chạy**, cung cấp bộ nhớ, bộ mô tả, cổng, quyền...

Theo cách truyền thống, tiến trình được khởi chạy bên trong các tiến trình khác (ngoại trừ PID 1) bằng cách gọi **`fork`**, tạo một bản sao chính xác của tiến trình hiện tại. Sau đó, **tiến trình con** thường gọi **`execve`** để tải tệp thực thi mới và chạy nó. Tiếp theo, **`vfork`** được giới thiệu để tăng tốc quá trình này mà không cần sao chép bộ nhớ.\
Sau đó, **`posix_spawn`** được giới thiệu, kết hợp **`vfork`** và **`execve`** trong một lần gọi và chấp nhận các cờ:

- `POSIX_SPAWN_RESETIDS`: Đặt lại các ID hiệu lực thành ID thực
- `POSIX_SPAWN_SETPGROUP`: Đặt nhóm tiến trình
- `POSUX_SPAWN_SETSIGDEF`: Đặt hành vi mặc định của tín hiệu
- `POSIX_SPAWN_SETSIGMASK`: Đặt mặt nạ tín hiệu
- `POSIX_SPAWN_SETEXEC`: Thực thi trong cùng tiến trình (như `execve` với nhiều tùy chọn hơn)
- `POSIX_SPAWN_START_SUSPENDED`: Khởi chạy ở trạng thái tạm dừng
- `_POSIX_SPAWN_DISABLE_ASLR`: Khởi chạy mà không có ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Dùng trình cấp phát Nano của libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Cho phép `rwx` trên các phân đoạn dữ liệu
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Đóng tất cả mô tả tệp theo mặc định khi gọi exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Ngẫu nhiên hóa các bit cao của độ lệch ASLR

Ngoài ra, `posix_spawn` chấp nhận các thiết lập **`posix_spawnattr`** để kiểm soát các khía cạnh của tiến trình được khởi chạy và các mục **`posix_spawn_file_actions`** để sửa đổi bộ mô tả tệp.

Khi một tiến trình kết thúc, nó gửi **mã trả về cho tiến trình cha** (nếu tiến trình cha đã kết thúc, tiến trình cha mới là PID 1) cùng với tín hiệu `SIGCHLD`. Tiến trình cha cần lấy giá trị này bằng cách gọi `wait4()` hoặc `waitid()`. Cho đến khi việc đó xảy ra, tiến trình con vẫn ở trạng thái zombie: vẫn được liệt kê nhưng không tiêu thụ tài nguyên.

### PID

PID, tức mã định danh tiến trình, xác định một tiến trình duy nhất. Trong XNU, **PID** có độ dài **64 bit**, tăng đơn điệu và **không bao giờ quay vòng** (để tránh bị lạm dụng).

### Nhóm tiến trình, phiên và Coalition

**Các tiến trình** có thể được đưa vào **nhóm** để dễ quản lý hơn. Ví dụ, các lệnh trong một shell script sẽ thuộc cùng một nhóm tiến trình, nhờ đó có thể **gửi tín hiệu cho chúng cùng lúc**, chẳng hạn bằng `kill`.\
Các tiến trình cũng có thể được **nhóm thành các phiên**. Khi một tiến trình bắt đầu một phiên (`setsid(2)`), các tiến trình con sẽ nằm trong phiên đó, trừ khi chúng tự bắt đầu phiên riêng.

Coalition là một cách khác để nhóm các tiến trình trong Darwin. Một tiến trình tham gia Coalition có thể truy cập tài nguyên chung, dùng chung sổ cái hoặc chịu sự quản lý của Jetsam. Coalition có các vai trò khác nhau: Leader, dịch vụ XPC, Extension.

### Thông tin xác thực và Persona

Mỗi tiến trình đều giữ **thông tin xác thực** để **xác định các quyền của nó** trong hệ thống. Mỗi tiến trình có một `uid` chính và một `gid` chính (mặc dù nó có thể thuộc nhiều nhóm).\
Cũng có thể thay đổi ID người dùng và nhóm nếu tệp nhị phân có bit `setuid/setgid`.\
Có một số hàm để **đặt uid/gid mới**.

System call **`persona`** cung cấp một bộ **thông tin xác thực** **thay thế**. Việc tiếp nhận một persona đồng thời giả định uid, gid và các nhóm thành viên của persona đó. Trong [**mã nguồn**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), có thể tìm thấy cấu trúc:

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

1. **POSIX Threads (pthreads):** macOS hỗ trợ POSIX threads (`pthreads`), một phần của API luồng tiêu chuẩn dành cho C/C++. Bản triển khai pthreads trong macOS nằm ở `/usr/lib/system/libsystem_pthread.dylib`, được phát triển từ dự án `libpthread` có sẵn công khai. Thư viện này cung cấp các hàm cần thiết để tạo và quản lý luồng.
2. **Tạo luồng:** Hàm `pthread_create()` được dùng để tạo luồng mới. Bên trong, hàm này gọi `bsdthread_create()`, một system call cấp thấp dành riêng cho kernel XNU (kernel làm nền tảng cho macOS). System call này nhận nhiều cờ được lấy từ `pthread_attr` (các thuộc tính), dùng để chỉ định cách hoạt động của luồng, bao gồm chính sách lập lịch và kích thước stack.
   - **Kích thước stack mặc định:** Kích thước stack mặc định của luồng mới là 512 KB, đủ cho các thao tác thông thường nhưng có thể điều chỉnh qua thuộc tính luồng nếu cần thêm hoặc bớt không gian.
3. **Khởi tạo luồng:** Hàm `__pthread_init()` đóng vai trò quan trọng trong quá trình thiết lập luồng. Hàm này sử dụng đối số `env[]` để phân tích các biến môi trường, trong đó có thể chứa thông tin về vị trí và kích thước của stack.

#### Kết thúc luồng trong macOS

1. **Thoát khỏi luồng:** Luồng thường được kết thúc bằng cách gọi `pthread_exit()`. Hàm này cho phép luồng thoát một cách gọn gàng, thực hiện các bước dọn dẹp cần thiết và gửi giá trị trả về cho các luồng đang chờ bằng `join`.
2. **Dọn dẹp luồng:** Khi gọi `pthread_exit()`, hàm `pthread_terminate()` sẽ được gọi để xử lý việc gỡ bỏ mọi cấu trúc liên quan đến luồng. Hàm này giải phóng các Mach thread port (Mach là hệ thống con giao tiếp trong kernel XNU) và gọi `bsdthread_terminate`, một syscall xóa các cấu trúc cấp kernel liên quan đến luồng.

#### Cơ chế đồng bộ hóa

Để quản lý quyền truy cập vào tài nguyên dùng chung và tránh race condition, macOS cung cấp một số primitive đồng bộ hóa. Chúng rất quan trọng trong môi trường đa luồng để đảm bảo tính toàn vẹn dữ liệu và sự ổn định của hệ thống:

1. **Mutex:**
   - **Mutex thông thường (Signature: 0x4D555458):** Mutex tiêu chuẩn có kích thước bộ nhớ 60 byte (56 byte cho mutex và 4 byte cho signature).
   - **Fast Mutex (Signature: 0x4d55545A):** Tương tự mutex thông thường nhưng được tối ưu để thao tác nhanh hơn; kích thước cũng là 60 byte.
2. **Biến điều kiện:**
   - Dùng để chờ một số điều kiện xảy ra, có kích thước 44 byte (40 byte cộng 4 byte cho signature).
   - **Thuộc tính biến điều kiện (Signature: 0x434e4441):** Các thuộc tính cấu hình cho biến điều kiện, có kích thước 12 byte.
3. **Biến Once (Signature: 0x4f4e4345):**
   - Đảm bảo một đoạn mã khởi tạo chỉ được thực thi một lần. Kích thước của biến là 12 byte.
4. **Read-Write Lock:**
   - Cho phép nhiều reader hoặc một writer tại một thời điểm, giúp truy cập dữ liệu dùng chung hiệu quả hơn.
   - **Read Write Lock (Signature: 0x52574c4b):** Có kích thước 196 byte.
   - **Thuộc tính Read Write Lock (Signature: 0x52574c41):** Các thuộc tính của read-write lock, có kích thước 20 byte.

> [!TIP]
> 4 byte cuối cùng của các đối tượng này được dùng để phát hiện overflow.

### Biến cục bộ theo luồng (Thread Local Variables, TLV)

**Biến cục bộ theo luồng (Thread Local Variables, TLV)** trong ngữ cảnh của tệp Mach-O (định dạng tệp thực thi trong macOS) được dùng để khai báo các biến dành riêng cho **từng luồng** trong ứng dụng đa luồng. Nhờ đó, mỗi luồng có một bản sao riêng của biến, giúp tránh xung đột và duy trì tính toàn vẹn dữ liệu mà không cần các cơ chế đồng bộ hóa tường minh như mutex.

Trong C và các ngôn ngữ liên quan, bạn có thể khai báo biến cục bộ theo luồng bằng từ khóa **`__thread`**. Cách hoạt động trong ví dụ của bạn như sau:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Đoạn mã này định nghĩa `tlv_var` là một biến thread-local. Mỗi thread chạy đoạn mã này sẽ có `tlv_var` riêng, và những thay đổi mà một thread thực hiện với `tlv_var` sẽ không ảnh hưởng đến `tlv_var` của thread khác.

Trong binary Mach-O, dữ liệu liên quan đến các biến thread-local được tổ chức thành những section cụ thể:

- **`__DATA.__thread_vars`**: Section này chứa metadata về các biến thread-local, chẳng hạn như kiểu dữ liệu và trạng thái khởi tạo.
- **`__DATA.__thread_bss`**: Section này dành cho các biến thread-local chưa được khởi tạo tường minh. Đây là một phần bộ nhớ được dành riêng cho dữ liệu được khởi tạo bằng 0.

Mach-O cũng cung cấp API **`tlv_atexit`** để quản lý các biến thread-local khi một thread kết thúc. API này cho phép bạn **đăng ký các hàm hủy**—những hàm đặc biệt dùng để dọn dẹp dữ liệu thread-local khi một thread chấm dứt.

### Độ ưu tiên của thread

Để hiểu về độ ưu tiên của thread, cần xem xét cách hệ điều hành quyết định thread nào sẽ chạy và chạy vào lúc nào. Quyết định này chịu ảnh hưởng bởi mức độ ưu tiên được gán cho mỗi thread. Trong macOS và các hệ thống giống Unix, việc này được xử lý bằng các khái niệm như `nice`, `renice` và các lớp Quality of Service (QoS).

#### Nice và Renice

1. **Nice:**
   - Giá trị `nice` của một process là một con số ảnh hưởng đến độ ưu tiên của nó. Mỗi process có giá trị nice trong khoảng từ -20 (độ ưu tiên cao nhất) đến 19 (độ ưu tiên thấp nhất). Giá trị nice mặc định khi tạo process thường là 0.
   - Giá trị nice thấp hơn (gần -20 hơn) khiến process trở nên “ích kỷ” hơn, giúp nó có nhiều thời gian CPU hơn so với các process có giá trị nice cao hơn.
2. **Renice:**
   - `renice` là lệnh dùng để thay đổi giá trị nice của một process đang chạy. Lệnh này có thể được dùng để điều chỉnh động độ ưu tiên của các process, tăng hoặc giảm phần thời gian CPU được cấp dựa trên giá trị nice mới.
   - Ví dụ, nếu một process tạm thời cần thêm tài nguyên CPU, bạn có thể giảm giá trị nice của nó bằng `renice`.

#### Các lớp Quality of Service (QoS)

Các lớp QoS là cách tiếp cận hiện đại hơn để xử lý độ ưu tiên của thread, đặc biệt trên các hệ thống như macOS có hỗ trợ **Grand Central Dispatch (GCD)**. Các lớp QoS cho phép nhà phát triển **phân loại** công việc thành những mức khác nhau tùy theo tầm quan trọng hoặc mức độ khẩn cấp. macOS tự động quản lý độ ưu tiên của thread dựa trên các lớp QoS này:

1. **User Interactive:**
   - Lớp này dành cho các tác vụ đang tương tác với người dùng hoặc cần trả kết quả ngay để mang lại trải nghiệm tốt. Các tác vụ này có độ ưu tiên cao nhất nhằm giữ cho giao diện phản hồi nhanh (ví dụ: hoạt ảnh hoặc xử lý sự kiện).
2. **User Initiated:**
   - Các tác vụ do người dùng khởi chạy và cần có kết quả ngay, chẳng hạn như mở tài liệu hoặc nhấp vào nút yêu cầu thực hiện tính toán. Các tác vụ này có độ ưu tiên cao nhưng thấp hơn User Interactive.
3. **Utility:**
   - Đây là các tác vụ chạy lâu và thường hiển thị chỉ báo tiến trình (ví dụ: tải file xuống, nhập dữ liệu). Chúng có độ ưu tiên thấp hơn các tác vụ do người dùng khởi chạy và không cần hoàn thành ngay lập tức.
4. **Background:**
   - Lớp này dành cho các tác vụ chạy nền và người dùng không nhìn thấy. Những tác vụ này có thể là lập chỉ mục, đồng bộ hóa hoặc sao lưu. Chúng có độ ưu tiên thấp nhất và ảnh hưởng tối thiểu đến hiệu năng hệ thống.

Với các lớp QoS, nhà phát triển không cần quản lý các con số độ ưu tiên cụ thể mà chỉ cần tập trung vào tính chất của tác vụ; hệ thống sẽ tối ưu hóa tài nguyên CPU cho phù hợp.

Ngoài ra còn có các **chính sách lập lịch thread** khác nhau để quy định một tập hợp tham số lập lịch mà scheduler sẽ cân nhắc. Có thể thực hiện việc này bằng `thread_policy_[set/get]`. Điều này có thể hữu ích trong các cuộc tấn công race condition.

## Lạm dụng process trên macOS

macOS cung cấp nhiều cơ chế để **các process tương tác, giao tiếp và chia sẻ dữ liệu**. Dù các cơ chế này rất cần thiết cho hoạt động bình thường của hệ thống, kẻ tấn công có thể lạm dụng chúng để injection, thực thi mã hoặc truy cập dữ liệu.

### Library Injection

Library Injection là kỹ thuật trong đó kẻ tấn công **buộc một process tải một library độc hại**. Sau khi được inject, library chạy trong ngữ cảnh của process mục tiêu, giúp kẻ tấn công có cùng quyền và khả năng truy cập như process đó.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking là kỹ thuật **chặn các lời gọi hàm** hoặc thông điệp trong mã phần mềm. Bằng cách hook các hàm, kẻ tấn công có thể **thay đổi hành vi** của một process, quan sát dữ liệu nhạy cảm hoặc thậm chí kiểm soát luồng thực thi.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Giả mạo call stack ARM64/ARM64e

Trang này đề cập đến metadata unwind của ARM64, các ràng buộc PAC của arm64e và các chuỗi lời gọi tổng hợp.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Giao tiếp liên process

Giao tiếp liên process (IPC) là các phương thức khác nhau để những process riêng biệt **chia sẻ và trao đổi dữ liệu**. Dù IPC là nền tảng của nhiều ứng dụng hợp pháp, nó cũng có thể bị lạm dụng để phá vỡ sự cô lập giữa các process, làm leak thông tin nhạy cảm hoặc thực hiện hành động trái phép.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection vào ứng dụng Electron

Các ứng dụng Electron chạy với một số biến môi trường cụ thể có thể dễ bị process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Injection vào Chromium

Có thể dùng các flag `--load-extension` và `--use-fake-ui-for-media-stream` để thực hiện **tấn công man in the browser**, cho phép đánh cắp thao tác gõ phím, traffic, cookie, inject script vào trang...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Các file NIB **định nghĩa các thành phần giao diện người dùng (UI)** và cách chúng tương tác trong một ứng dụng. Tuy nhiên, chúng có thể **thực thi các lệnh tùy ý**, và **Gatekeeper không ngăn** một ứng dụng đã được thực thi chạy lại nếu **file NIB bị sửa đổi**. Vì vậy, chúng có thể được dùng để khiến các chương trình tùy ý thực thi lệnh tùy ý:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection vào ứng dụng Java

Có thể inject các tùy chọn JVM thông qua **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** hoặc **`JDK_JAVA_OPTIONS`** để tải một Java agent hoặc native agent trước khi ứng dụng khởi chạy.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Injection vào Node.js

**`NODE_OPTIONS`** preload JavaScript của kẻ tấn công thông qua `--require` (file) hoặc `--import data:text/javascript,…` (không cần file, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** tải một module vào REPL tương tác, còn **`ELECTRON_RUN_AS_NODE`** bật lại tất cả các cơ chế này trên binary Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### Injection vào ứng dụng .Net

Có thể inject mã vào ứng dụng .NET thông qua **`DOTNET_STARTUP_HOOKS`** trước khi chạy `Main`, hoặc lạm dụng chức năng debug của .NET khi đáp ứng đủ các điều kiện tiên quyết.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash không tương tác đọc **`BASH_ENV`**; các shell POSIX tương tác đọc **`ENV`**; zsh đọc **`$ZDOTDIR/.zshenv`**; còn fish đọc cấu hình trong **`XDG_CONFIG_HOME`** hoặc **`XDG_DATA_DIRS`**. Mỗi biến đều có thể khiến một file khởi động do kẻ tấn công kiểm soát được thực thi trước lệnh dự kiến. Bash cũng chạy command substitution đặt trong **`PS4`** mỗi khi bật xtrace (ví dụ: **`SHELLOPTS=xtrace`** được kế thừa):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Nhúng lệnh qua stdin của shell

Khởi chạy `/bin/zsh -s` khiến shell đọc chương trình từ standard input. Vì vậy, nếu một downloader sao chép tài liệu có cấu trúc không đáng tin cậy vào stdin của tiến trình con mà không phân tích trước, toàn bộ tài liệu sẽ trở thành mã nguồn shell. Một loader từng được quan sát đã đưa từng dòng của một file iCalendar công khai qua anonymous pipe. Metadata của lịch không chạy được như lệnh, nhưng zsh vẫn tiếp tục cho đến khi gặp các dòng có thể thực thi được đặt sau `DESCRIPTION:`. Những dòng đó tải xuống và khởi chạy application bundle tiếp theo. Content type dự kiến của dữ liệu và nơi lưu trữ đáng tin cậy không khiến cách làm này an toàn; ranh giới nguy hiểm nằm ở việc đưa các byte của dữ liệu cho một interpreter.<sup>[[5]](#references)</sup>

Các giai đoạn liên quan được đề cập trong [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) và [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** hoặc **`PHP_INI_SCAN_DIR`** có thể tải cấu hình PHP do kẻ tấn công kiểm soát, trong đó **`auto_prepend_file`** thực thi trước script mục tiêu.

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Trình thông dịch Lua độc lập thực thi mã hoặc một `@file` từ **`LUA_INIT`** (hoặc biến thể dành riêng cho phiên bản) trước khi xử lý script mục tiêu.

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** và **`R_PROFILE`** chuyển hướng đến các profile khởi động chứa mã R. Thay vào đó, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** kết hợp với đường dẫn thư viện R có thể tự động tải một package đã cài đặt.

[R startup profiles and package loading](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`** chuyển hướng đến depot có `config/startup.jl` được tự động thực thi.

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang và Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** hoặc **`ERL_ZFLAGS`** có thể inject một biểu thức Erlang VM **`-eval`** mà không cần file payload; các workload Elixir thường khởi chạy cùng VM này.

[Erlang/Elixir VM flag injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** và **`OCTAVE_VERSION_INITFILE`** chuyển hướng đến các script khởi động của Octave.

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` là ứng dụng .NET đa nền tảng, vì vậy một số biến môi trường có thể khiến mã được thực thi trước lệnh: **`XDG_CONFIG_HOME`** chuyển hướng đến các script profile chạy lúc khởi động, **`PSModulePath`** chiếm quyền tự động tải module (một file `.psm1` được đặt sẵn sẽ chạy khi import và có thể thay thế các cmdlet tích hợp sẵn), còn các biến .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** và **`DOTNET_STARTUP_HOOKS`** tải mã của kẻ tấn công vào process trước khi chạy `Main`.

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


[Ruby `RUBYOPT`/`RUBYLIB` loader options](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

Chuỗi kết hợp **`PYTHONWARNINGS`** và **`BROWSER`** trong standard library có thể thực thi lệnh trong quá trình phân tích bộ lọc cảnh báo. Một cách khác dùng file là đặt `sitecustomize.py` trong **`PYTHONPATH`** để quá trình khởi tạo `site` thông thường import file này trước script mục tiêu. **`PYTHONBREAKPOINT`** chạy callable/module được chọn khi mã đi đến `breakpoint()`. Các biến chỉ dùng trong chế độ tương tác như **`PYTHONSTARTUP`** có phạm vi áp dụng hẹp hơn.

Lưu ý rằng các executable được biên dịch bằng **`pyinstaller`** sẽ không dùng các biến môi trường này, ngay cả khi chúng chạy bằng Python nhúng.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (và biến dự phòng `EXINIT`) được thực thi dưới dạng lệnh Ex khi khởi động thông thường, vì vậy `:!cmd` / `:call system(...)` có thể dẫn đến thực thi mã khi nạn nhân mở Vim/Neovim trong một môi trường bị kiểm soát:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ngoài ra, Homebrew thường cài Python trong `/opt/homebrew`, nơi các thành viên của nhóm `admin` cục bộ có thể thay thế launcher. Đây là chiếm quyền binary có thể ghi được, không phải injection qua biến môi trường; hãy xác minh quyền sở hữu và ACL trước khi xem đây là lỗ hổng có thể khai thác.


## Phát hiện

### Shield

[**Shield**](https://github.com/theevilbit/Shield) là ứng dụng mã nguồn mở dựa trên **EndpointSecurity**, có chức năng phát hiện và chặn process injection. Đây là tài liệu tham khảo hữu ích về các tín hiệu có thể quan sát qua Endpoint Security, vì ứng dụng cảnh báo khi phát hiện:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Các biến môi trường dùng cho injection** khi process được thực thi: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` và `ELECTRON_RUN_AS_NODE`.
- Các lệnh gọi **`task_for_pid`** — một process yêu cầu task port của process khác; đây là điều kiện tiên quyết để inject vào process đó.
- **Các đối số debug của Electron** — `--inspect`, `--inspect-brk` và `--remote-debugging-port`, dùng để khởi chạy ứng dụng Electron ở chế độ debug và cho phép bất kỳ ai attach vào rồi chạy mã trong ứng dụng đó.<sup>[[3]](#references)</sup>
- **Tạo symlink/hardlink giữa các mức quyền** — primitive kinh điển: “tạo một link với tư cách người dùng thông thường rồi trỏ nó đến một vị trí có đặc quyền”. Lưu ý rằng **có thể cảnh báo về symlink nhưng không thể chặn**: EndpointSecurity không cung cấp đích của link trước khi nó được tạo.

### Các lệnh gọi do process khác thực hiện

Trong [**bài blog này**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), bạn có thể tìm hiểu cách dùng hàm **`task_name_for_pid`** để lấy thông tin về các **process khác đang inject mã vào một process**, rồi lấy thông tin về process đó.<sup>[[4]](#references)</sup>

Lưu ý rằng để gọi hàm này, bạn cần có cùng **uid** với người dùng đang chạy process hoặc là **root** (hàm trả về thông tin về process, không cung cấp cách inject mã).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — phát hiện process injection trên macOS mã nguồn mở (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Vì sao ứng dụng Electron không thể lưu giữ bí mật của bạn một cách bảo mật: tùy chọn --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Phát hiện các sửa đổi task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Phiên bản mới của phần mềm đánh cắp dữ liệu MacSync trên macOS nhắm đến những người đam mê tiền mã hóa và nhà phát triển](https://securelist.com/macsync-new-version/121383/)
