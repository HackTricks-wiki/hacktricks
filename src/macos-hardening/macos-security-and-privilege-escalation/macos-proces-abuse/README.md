# Lạm dụng tiến trình trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản về tiến trình

Tiến trình là một phiên bản của tệp thực thi đang chạy, tuy nhiên tiến trình không chạy mã; các luồng mới làm việc đó. Vì vậy, **tiến trình chỉ là các vùng chứa để chạy luồng**, cung cấp bộ nhớ, bộ mô tả, cổng, quyền...

Theo cách truyền thống, tiến trình được khởi chạy bên trong các tiến trình khác (ngoại trừ PID 1) bằng cách gọi **`fork`**, thao tác này tạo một bản sao chính xác của tiến trình hiện tại. Sau đó, **tiến trình con** thường gọi **`execve`** để tải tệp thực thi mới và chạy nó. Tiếp đến, **`vfork`** được giới thiệu để tăng tốc quá trình này mà không cần sao chép bộ nhớ.\
Sau đó, **`posix_spawn`** được giới thiệu, kết hợp **`vfork`** và **`execve`** trong một lệnh gọi, đồng thời chấp nhận các cờ:

- `POSIX_SPAWN_RESETIDS`: Đặt lại ID hiệu lực thành ID thực
- `POSIX_SPAWN_SETPGROUP`: Đặt nhóm tiến trình
- `POSUX_SPAWN_SETSIGDEF`: Đặt hành vi mặc định của tín hiệu
- `POSIX_SPAWN_SETSIGMASK`: Đặt mặt nạ tín hiệu
- `POSIX_SPAWN_SETEXEC`: Thực thi trong cùng tiến trình (như `execve` với nhiều tùy chọn hơn)
- `POSIX_SPAWN_START_SUSPENDED`: Khởi chạy ở trạng thái tạm dừng
- `_POSIX_SPAWN_DISABLE_ASLR`: Khởi chạy mà không có ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Sử dụng bộ cấp phát Nano của libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Cho phép `rwx` trên các phân đoạn dữ liệu
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Theo mặc định, đóng tất cả mô tả tệp khi thực thi `exec(2)`
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Ngẫu nhiên hóa các bit cao của độ dịch ASLR

Ngoài ra, `posix_spawn` chấp nhận các thiết lập **`posix_spawnattr`** để kiểm soát các khía cạnh của tiến trình được tạo và các mục **`posix_spawn_file_actions`** để sửa đổi bộ mô tả tệp.

Khi một tiến trình kết thúc, nó gửi **mã trả về cho tiến trình cha** (nếu tiến trình cha đã kết thúc, tiến trình cha mới sẽ là PID 1) bằng tín hiệu `SIGCHLD`. Tiến trình cha cần lấy giá trị này bằng cách gọi `wait4()` hoặc `waitid()`; cho đến khi điều đó xảy ra, tiến trình con ở trạng thái zombie: nó vẫn được liệt kê nhưng không tiêu thụ tài nguyên.

### PID

PID, tức mã định danh tiến trình, xác định một tiến trình duy nhất. Trong XNU, **PID** có độ dài **64 bit**, tăng đơn điệu và **không bao giờ quay vòng** (để tránh bị lạm dụng).

### Nhóm tiến trình, phiên và coalition

**Tiến trình** có thể được đưa vào **nhóm** để dễ quản lý hơn. Ví dụ: các lệnh trong một shell script sẽ nằm trong cùng một nhóm tiến trình, nhờ đó có thể **gửi tín hiệu cho chúng cùng lúc**, chẳng hạn bằng `kill`.\
Cũng có thể **nhóm tiến trình thành các phiên**. Khi một tiến trình bắt đầu một phiên (`setsid(2)`), các tiến trình con sẽ thuộc phiên đó, trừ khi chúng tự bắt đầu phiên riêng.

Coalition là một cách khác để nhóm tiến trình trong Darwin. Tiến trình tham gia một coalition có thể truy cập các tài nguyên dùng chung, chia sẻ một sổ cái hoặc chịu tác động của Jetsam. Coalition có các vai trò khác nhau: Leader, dịch vụ XPC, Extension.

### Thông tin xác thực và persona

Mỗi tiến trình có **thông tin xác thực** để **xác định các quyền của nó** trong hệ thống. Mỗi tiến trình có một `uid` chính và một `gid` chính (mặc dù có thể thuộc nhiều nhóm).\
Cũng có thể thay đổi ID người dùng và nhóm nếu tệp nhị phân có bit `setuid/setgid`.\
Có một số hàm để **đặt uid/gid mới**.

Lời gọi hệ thống **`persona`** cung cấp một bộ **thông tin xác thực** thay thế. Khi sử dụng persona, tiến trình sẽ đồng thời nhận uid, gid và tư cách thành viên nhóm của persona đó. Trong [**mã nguồn**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), có thể tìm thấy cấu trúc:

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

## Thông tin cơ bản về Threads

1. **POSIX Threads (pthreads):** macOS hỗ trợ POSIX threads (`pthreads`), một phần của API threading tiêu chuẩn dành cho C/C++. Phần triển khai pthreads trong macOS nằm trong `/usr/lib/system/libsystem_pthread.dylib`, có nguồn gốc từ dự án `libpthread` được công khai. Thư viện này cung cấp các hàm cần thiết để tạo và quản lý threads.
2. **Tạo Threads:** Hàm `pthread_create()` được dùng để tạo threads mới. Bên trong, hàm này gọi `bsdthread_create()`, một lệnh gọi hệ thống cấp thấp hơn dành riêng cho kernel XNU (kernel làm nền tảng cho macOS). Lệnh gọi hệ thống này nhận nhiều cờ được tạo từ `pthread_attr` (các thuộc tính), dùng để chỉ định cách thread hoạt động, bao gồm chính sách lập lịch và kích thước stack.
   - **Kích thước Stack mặc định:** Kích thước stack mặc định cho threads mới là 512 KB, đủ cho các hoạt động thông thường nhưng có thể điều chỉnh thông qua thuộc tính thread nếu cần thêm hoặc ít không gian hơn.
3. **Khởi tạo Thread:** Hàm `__pthread_init()` đóng vai trò quan trọng trong quá trình thiết lập thread; hàm sử dụng đối số `env[]` để phân tích các biến môi trường, trong đó có thể bao gồm thông tin về vị trí và kích thước của stack.

#### Kết thúc Thread trong macOS

1. **Thoát khỏi Threads:** Threads thường được kết thúc bằng cách gọi `pthread_exit()`. Hàm này cho phép một thread thoát gọn gàng, thực hiện các bước dọn dẹp cần thiết và gửi giá trị trả về cho các thread đang chờ join.
2. **Dọn dẹp Thread:** Khi gọi `pthread_exit()`, hàm `pthread_terminate()` sẽ được gọi để xử lý việc xóa tất cả cấu trúc thread liên quan. Hàm này giải phóng các Mach thread port (Mach là hệ thống con giao tiếp trong kernel XNU) và gọi `bsdthread_terminate`, một syscall xóa các cấu trúc ở cấp kernel gắn với thread.

#### Cơ chế đồng bộ hóa

Để quản lý quyền truy cập vào tài nguyên dùng chung và tránh race condition, macOS cung cấp một số primitive đồng bộ hóa. Chúng rất quan trọng trong môi trường đa luồng để đảm bảo tính toàn vẹn dữ liệu và sự ổn định của hệ thống:

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** Mutex tiêu chuẩn, chiếm 60 bytes (56 bytes cho mutex và 4 bytes cho signature).
   - **Fast Mutex (Signature: 0x4d55545A):** Tương tự regular mutex nhưng được tối ưu để thực hiện nhanh hơn, cũng có kích thước 60 bytes.
2. **Condition Variables:**
   - Dùng để chờ một số điều kiện nhất định xảy ra, có kích thước 44 bytes (40 bytes cộng thêm signature 4 bytes).
   - **Condition Variable Attributes (Signature: 0x434e4441):** Các thuộc tính cấu hình cho condition variables, có kích thước 12 bytes.
3. **Once Variable (Signature: 0x4f4e4345):**
   - Đảm bảo một đoạn mã khởi tạo chỉ được thực thi một lần. Kích thước của nó là 12 bytes.
4. **Read-Write Locks:**
   - Cho phép nhiều reader hoặc một writer tại một thời điểm, giúp truy cập dữ liệu dùng chung hiệu quả.
   - **Read Write Lock (Signature: 0x52574c4b):** Có kích thước 196 bytes.
   - **Read Write Lock Attributes (Signature: 0x52574c41):** Các thuộc tính cho read-write locks, có kích thước 20 bytes.

> [!TIP]
> 4 bytes cuối của các object này được dùng để phát hiện tràn bộ đệm.

### Thread Local Variables (TLV)

**Thread Local Variables (TLV)** trong các tệp Mach-O (định dạng dành cho tệp thực thi trong macOS) được dùng để khai báo các biến chỉ dành riêng cho **từng thread** trong ứng dụng đa luồng. Nhờ vậy, mỗi thread có một phiên bản biến riêng, giúp tránh xung đột và duy trì tính toàn vẹn dữ liệu mà không cần các cơ chế đồng bộ hóa tường minh như mutexes.

Trong C và các ngôn ngữ liên quan, bạn có thể khai báo biến thread-local bằng từ khóa **`__thread`**. Cách hoạt động trong ví dụ sau:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Đoạn mã này định nghĩa `tlv_var` là một biến thread-local. Mỗi thread chạy đoạn mã này sẽ có `tlv_var` riêng, và những thay đổi mà một thread thực hiện với `tlv_var` sẽ không ảnh hưởng đến `tlv_var` ở thread khác.

Trong binary Mach-O, dữ liệu liên quan đến biến thread-local được sắp xếp vào các section cụ thể:

- **`__DATA.__thread_vars`**: Section này chứa metadata về các biến thread-local, chẳng hạn như kiểu dữ liệu và trạng thái khởi tạo.
- **`__DATA.__thread_bss`**: Section này dùng cho các biến thread-local chưa được khởi tạo tường minh. Đây là vùng bộ nhớ dành riêng cho dữ liệu được khởi tạo bằng 0.

Mach-O cũng cung cấp API riêng có tên **`tlv_atexit`** để quản lý các biến thread-local khi một thread thoát. API này cho phép bạn **đăng ký hàm hủy** — các hàm đặc biệt dùng để dọn dẹp dữ liệu thread-local khi một thread kết thúc.

### Ưu tiên luồng

Để hiểu về ưu tiên luồng, cần xem xét cách hệ điều hành quyết định thread nào sẽ chạy và khi nào. Quyết định này chịu ảnh hưởng bởi mức ưu tiên được gán cho từng thread. Trên macOS và các hệ thống giống Unix, việc này được xử lý bằng các khái niệm như `nice`, `renice` và các lớp Quality of Service (QoS).

#### Nice và Renice

1. **Nice:**
   - Giá trị `nice` của một process là con số ảnh hưởng đến mức ưu tiên của process đó. Mỗi process có giá trị nice từ -20 (ưu tiên cao nhất) đến 19 (ưu tiên thấp nhất). Giá trị nice mặc định khi tạo process thường là 0.
   - Giá trị nice càng thấp (càng gần -20) thì process càng “ích kỷ”, được cấp nhiều thời gian CPU hơn so với các process có giá trị nice cao hơn.
2. **Renice:**
   - `renice` là lệnh dùng để thay đổi giá trị nice của một process đang chạy. Lệnh này có thể được dùng để điều chỉnh động mức ưu tiên của process, tăng hoặc giảm thời lượng CPU được cấp dựa trên giá trị nice mới.
   - Ví dụ, nếu tạm thời cần thêm tài nguyên CPU cho một process, bạn có thể giảm giá trị nice bằng `renice`.

#### Các lớp Quality of Service (QoS)

Các lớp QoS là cách hiện đại hơn để xử lý ưu tiên luồng, đặc biệt trên các hệ thống như macOS hỗ trợ **Grand Central Dispatch (GCD)**. Các lớp QoS cho phép nhà phát triển **phân loại** công việc thành những mức khác nhau dựa trên tầm quan trọng hoặc mức độ khẩn cấp. macOS tự động quản lý việc ưu tiên thread dựa trên các lớp QoS này:

1. **User Interactive:**
   - Lớp này dành cho các tác vụ đang tương tác với người dùng hoặc cần có kết quả ngay để đảm bảo trải nghiệm người dùng tốt. Các tác vụ này có mức ưu tiên cao nhất để giao diện luôn phản hồi nhanh (ví dụ: hoạt ảnh hoặc xử lý sự kiện).
2. **User Initiated:**
   - Các tác vụ do người dùng khởi chạy và cần có kết quả ngay, chẳng hạn như mở tài liệu hoặc nhấp vào nút cần thực hiện tính toán. Các tác vụ này có ưu tiên cao nhưng thấp hơn User Interactive.
3. **Utility:**
   - Các tác vụ này chạy lâu và thường hiển thị chỉ báo tiến trình (ví dụ: tải file xuống, nhập dữ liệu). Chúng có ưu tiên thấp hơn các tác vụ do người dùng khởi chạy và không cần hoàn tất ngay.
4. **Background:**
   - Lớp này dành cho các tác vụ chạy nền và không hiển thị với người dùng. Ví dụ như lập chỉ mục, đồng bộ hóa hoặc sao lưu. Chúng có mức ưu tiên thấp nhất và ảnh hưởng tối thiểu đến hiệu năng hệ thống.

Với các lớp QoS, nhà phát triển không cần quản lý các giá trị ưu tiên cụ thể mà chỉ cần tập trung vào tính chất của tác vụ; hệ thống sẽ tối ưu tài nguyên CPU tương ứng.

Ngoài ra còn có các **chính sách lập lịch thread** xác định một tập hợp tham số lập lịch để scheduler xem xét. Có thể thiết lập các tham số này bằng `thread_policy_[set/get]`. Điều này có thể hữu ích trong các cuộc tấn công race condition.

## Lạm dụng process trên macOS

macOS cung cấp nhiều cơ chế để **các process tương tác, giao tiếp và chia sẻ dữ liệu**. Dù các cơ chế này thiết yếu cho hoạt động bình thường của hệ thống, kẻ tấn công có thể lạm dụng chúng để injection, thực thi mã hoặc truy cập dữ liệu.

### Library Injection

Library Injection là kỹ thuật trong đó kẻ tấn công **buộc một process tải một thư viện độc hại**. Sau khi được inject, thư viện chạy trong ngữ cảnh của process mục tiêu, giúp kẻ tấn công có cùng quyền và khả năng truy cập như process đó.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking là kỹ thuật **chặn các lời gọi hàm** hoặc thông điệp bên trong mã phần mềm. Bằng cách hook các hàm, kẻ tấn công có thể **thay đổi hành vi** của một process, theo dõi dữ liệu nhạy cảm hoặc thậm chí kiểm soát luồng thực thi.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Trang này đề cập đến metadata unwind của ARM64, các giới hạn PAC của arm64e và các chuỗi lời gọi tổng hợp.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Giao tiếp liên process

Giao tiếp liên process (IPC) là các phương thức khác nhau để những process riêng biệt **chia sẻ và trao đổi dữ liệu**. Dù IPC là nền tảng của nhiều ứng dụng hợp pháp, nó cũng có thể bị lạm dụng để phá vỡ cơ chế cô lập process, làm lộ thông tin nhạy cảm hoặc thực hiện các hành động trái phép.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection ứng dụng Electron

Các ứng dụng Electron chạy với một số biến môi trường nhất định có thể dễ bị process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Có thể sử dụng các flag `--load-extension` và `--use-fake-ui-for-media-stream` để thực hiện **tấn công man-in-the-browser**, qua đó đánh cắp thao tác gõ phím, lưu lượng mạng, cookie, inject script vào trang...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Các file NIB **định nghĩa các phần tử giao diện người dùng (UI)** và cách chúng tương tác trong một ứng dụng. Tuy nhiên, chúng có thể **thực thi lệnh tùy ý**, và **Gatekeeper không ngăn** một ứng dụng đã được thực thi chạy lại nếu **file NIB bị sửa đổi**. Vì vậy, chúng có thể được dùng để khiến các chương trình tùy ý thực thi lệnh tùy ý:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Có thể inject các tùy chọn JVM thông qua **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** hoặc **`JDK_JAVA_OPTIONS`** để tải Java agent hoặc native agent trước khi ứng dụng khởi chạy.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** preload JavaScript do kẻ tấn công kiểm soát thông qua `--require` (file) hoặc `--import data:text/javascript,…` (không cần file, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** tải một module vào REPL tương tác, còn **`ELECTRON_RUN_AS_NODE`** bật lại toàn bộ khả năng này trên các binary Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Có thể inject mã vào ứng dụng .NET thông qua **`DOTNET_STARTUP_HOOKS`** trước khi chạy `Main`, hoặc lạm dụng chức năng gỡ lỗi .NET khi đáp ứng đủ các điều kiện tiên quyết.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash không tương tác đọc **`BASH_ENV`**; các shell POSIX tương tác đọc **`ENV`**; zsh đọc **`$ZDOTDIR/.zshenv`**; còn fish đọc cấu hình bên dưới **`XDG_CONFIG_HOME`** hoặc **`XDG_DATA_DIRS`**. Mỗi cơ chế này đều có thể thực thi file khởi động do kẻ tấn công kiểm soát trước khi chạy lệnh dự kiến. Bash cũng chạy command substitution được đặt trong **`PS4`** mỗi khi bật xtrace (ví dụ: kế thừa **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Nhúng lệnh vào stdin của shell

Khởi chạy `/bin/zsh -s` khiến shell đọc chương trình từ standard input. Do đó, downloader sao chép một tài liệu có cấu trúc không đáng tin cậy vào stdin của tiến trình con mà không phân tích trước sẽ biến toàn bộ tài liệu thành mã nguồn shell. Một loader từng được phát hiện đã đọc từng dòng của một file iCalendar công khai qua anonymous pipe. Metadata của lịch bị lỗi khi chạy dưới dạng lệnh, nhưng zsh vẫn tiếp tục cho đến khi gặp các dòng có thể thực thi được đặt sau `DESCRIPTION:`. Những dòng đó tải xuống và khởi chạy application bundle tiếp theo. Content type dự kiến của dữ liệu và việc lưu trữ trên một máy chủ đáng tin cậy không khiến cách làm này an toàn; ranh giới nguy hiểm nằm ở việc chuyển các byte đó cho một interpreter.<sup>[[5]](#references)</sup>

Các giai đoạn liên quan được trình bày trong [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper và quarantine](../macos-security-protections/macos-gatekeeper.md) và [các vị trí tự khởi động trên macOS](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** hoặc **`PHP_INI_SCAN_DIR`** có thể tải cấu hình PHP do kẻ tấn công kiểm soát, trong đó **`auto_prepend_file`** được thực thi trước script mục tiêu.

[Cấu hình PHP và injection lúc khởi động qua `auto_prepend_file`](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Trình thông dịch Lua độc lập thực thi mã hoặc `@file` từ **`LUA_INIT`** (hoặc biến thể dành riêng cho phiên bản) trước khi xử lý script mục tiêu.

[Injection lúc khởi động bằng `LUA_INIT` của Lua (file và mã inline)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** và **`R_PROFILE`** chuyển hướng đến các profile khởi động chứa mã R. Ngoài ra, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** kết hợp với đường dẫn thư viện R có thể tự động tải một package đã cài đặt.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** chuyển hướng đến depot có `config/startup.jl` được tự động thực thi.

[Injection qua `JULIA_DEPOT_PATH` và `startup.jl` của Julia](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** hoặc **`ERL_ZFLAGS`** có thể inject biểu thức Erlang VM **`-eval`** mà không cần file payload; các workload Elixir thường khởi chạy cùng VM đó.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** và **`OCTAVE_VERSION_INITFILE`** chuyển hướng đến các script khởi động của Octave.

[Injection qua file khởi động GNU Octave](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` là ứng dụng .NET đa nền tảng, vì vậy một số biến môi trường có thể thực thi mã trước lệnh: **`XDG_CONFIG_HOME`** chuyển hướng đến các script profile chạy lúc khởi động, **`PSModulePath`** chiếm quyền quá trình tự động tải module (một file `.psm1` được cài vào sẽ chạy lúc import và có thể che khuất các cmdlet tích hợp sẵn), còn các biến .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** và **`DOTNET_STARTUP_HOOKS`** tải mã của kẻ tấn công vào process trước khi chạy `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Kiểm tra các tùy chọn khác nhau để khiến script Perl thực thi mã tùy ý tại:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Cũng có thể lạm dụng các biến môi trường của ruby (**`RUBYOPT`**, **`RUBYLIB`**) để khiến các script tùy ý thực thi mã tùy ý:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Chuỗi kết hợp **`PYTHONWARNINGS`** và thư viện chuẩn **`BROWSER`** có thể thực thi lệnh trong lúc phân tích bộ lọc cảnh báo. Một phương án khác dùng file là đặt `sitecustomize.py` trong **`PYTHONPATH`** để quá trình khởi tạo `site` thông thường import file này trước script mục tiêu. **`PYTHONBREAKPOINT`** chạy callable/module được chỉ định khi mã gọi `breakpoint()`. Các biến chỉ dùng trong chế độ tương tác, chẳng hạn **`PYTHONSTARTUP`**, có phạm vi áp dụng hẹp hơn.

Lưu ý rằng các executable được biên dịch bằng **`pyinstaller`** sẽ không sử dụng những biến môi trường này, ngay cả khi chúng chạy bằng Python nhúng.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (và biến dự phòng `EXINIT`) được thực thi dưới dạng lệnh Ex khi khởi động thông thường, vì vậy `:!cmd` / `:call system(...)` có thể thực thi mã khi nạn nhân mở Vim/Neovim trong môi trường do kẻ tấn công kiểm soát:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Riêng biệt, Homebrew thường cài Python bên dưới `/opt/homebrew`, nơi các thành viên trong nhóm `admin` cục bộ có thể thay thế launcher. Đây là hành vi chiếm quyền binary có thể ghi, chứ không phải injection qua biến môi trường; hãy xác minh quyền sở hữu và ACL trước khi xem đây là lỗ hổng có thể khai thác.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) là ứng dụng mã nguồn mở dựa trên **EndpointSecurity**, có khả năng phát hiện và chặn process injection. Đây là tài liệu tham khảo hữu ích về những tín hiệu có thể quan sát được qua Endpoint Security, vì ứng dụng cảnh báo khi phát hiện:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Các biến môi trường injection** khi thực thi process: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` và `ELECTRON_RUN_AS_NODE`.
- Các lời gọi **`task_for_pid`** — một process yêu cầu task port của process khác; đây là điều kiện tiên quyết để inject vào process đó.
- **Các tham số gỡ lỗi Electron** — `--inspect`, `--inspect-brk` và `--remote-debugging-port`, dùng để khởi chạy ứng dụng Electron ở chế độ gỡ lỗi và cho phép bất kỳ ai attach rồi chạy mã trong ứng dụng đó.<sup>[[3]](#references)</sup>
- **Tạo symlink/hardlink giữa các mức quyền** — thủ thuật kinh điển “tạo link với tư cách người dùng thông thường rồi trỏ nó đến vị trí có đặc quyền”. Lưu ý rằng **có thể phát cảnh báo về symlink nhưng không thể chặn chúng**: EndpointSecurity không cung cấp đích của link trước khi nó được tạo.

### Lời gọi do process khác thực hiện

Trong [**bài blog này**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), bạn có thể tìm hiểu cách sử dụng hàm **`task_name_for_pid`** để lấy thông tin về các **process khác đang inject mã vào một process**, sau đó lấy thông tin về process đó.<sup>[[4]](#references)</sup>

Lưu ý rằng để gọi hàm này, bạn cần có **cùng uid** với uid đang chạy process đó hoặc là **root** (hàm trả về thông tin về process, không phải cách để inject mã).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — phát hiện process injection trên macOS mã nguồn mở (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Vì sao ứng dụng Electron không thể lưu giữ bí mật của bạn một cách bảo mật: tùy chọn --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Phát hiện các sửa đổi task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Phiên bản mới của malware đánh cắp dữ liệu MacSync trên macOS nhắm vào những người đam mê tiền mã hóa và nhà phát triển](https://securelist.com/macsync-new-version/121383/)
