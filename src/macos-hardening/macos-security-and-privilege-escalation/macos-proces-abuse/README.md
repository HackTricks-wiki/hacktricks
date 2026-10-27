# Lạm dụng Process trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản về Process

Một process là một phiên bản của executable đang chạy, tuy nhiên process không chạy code; các thread mới chạy code. Vì vậy, **process chỉ là container để chạy các thread**, cung cấp bộ nhớ, descriptor, port, quyền...

Theo cách truyền thống, process được khởi chạy bên trong các process khác (ngoại trừ PID 1) bằng cách gọi **`fork`**, tạo một bản sao chính xác của process hiện tại; sau đó **child process** thường gọi **`execve`** để tải executable mới và chạy nó. Tiếp đó, **`vfork`** được giới thiệu để tăng tốc quy trình này mà không cần sao chép bộ nhớ.\
Sau đó, **`posix_spawn`** được giới thiệu, kết hợp **`vfork`** và **`execve`** trong một lần gọi và chấp nhận các flag:

- `POSIX_SPAWN_RESETIDS`: Đặt lại effective id thành real id
- `POSIX_SPAWN_SETPGROUP`: Đặt nhóm process
- `POSUX_SPAWN_SETSIGDEF`: Đặt hành vi mặc định của signal
- `POSIX_SPAWN_SETSIGMASK`: Đặt mặt nạ signal
- `POSIX_SPAWN_SETEXEC`: Exec trong cùng process (giống `execve` nhưng có thêm tùy chọn)
- `POSIX_SPAWN_START_SUSPENDED`: Khởi chạy ở trạng thái tạm dừng
- `_POSIX_SPAWN_DISABLE_ASLR`: Khởi chạy mà không có ASLR
- `_POSIX_SPAWN_NANO_ALLOCATOR:` Sử dụng Nano allocator của libmalloc
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Cho phép `rwx` trên các segment dữ liệu
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Mặc định đóng tất cả file description khi exec(2)
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` Ngẫu nhiên hóa các bit cao của ASLR slide

Ngoài ra, `posix_spawn` chấp nhận các thiết lập **`posix_spawnattr`** để kiểm soát các khía cạnh của process được tạo và các mục **`posix_spawn_file_actions`** để sửa đổi file descriptor.

Khi một process kết thúc, nó gửi **return code cho process cha** (nếu process cha đã kết thúc, process cha mới là PID 1) bằng signal `SIGCHLD`. Process cha cần lấy giá trị này bằng cách gọi `wait4()` hoặc `waitid()`; cho đến khi việc đó xảy ra, process con ở trạng thái zombie: vẫn được liệt kê nhưng không tiêu thụ tài nguyên.

### PID

PID (process identifier) dùng để nhận diện một process duy nhất. Trong XNU, **PID** có độ dài **64 bit**, tăng đơn điệu và **không bao giờ quay vòng** (để tránh bị lạm dụng).

### Nhóm Process, Session và Coalition

Có thể đưa **process** vào **nhóm** để dễ quản lý hơn. Ví dụ, các lệnh trong một shell script sẽ thuộc cùng một nhóm process, do đó có thể **gửi signal đến tất cả cùng lúc**, chẳng hạn dùng kill.\
Cũng có thể **nhóm các process thành session**. Khi một process khởi tạo session (`setsid(2)`), các process con sẽ thuộc session đó, trừ khi chúng tự khởi tạo session riêng.

Coalition là một cách khác để nhóm các process trong Darwin. Một process tham gia coalition có thể truy cập tài nguyên của pool, chia sẻ một ledger hoặc chịu sự xử lý của Jetsam. Coalition có các vai trò khác nhau: Leader, XPC service, Extension.

### Thông tin xác thực và Persona

Mỗi process đều có **thông tin xác thực** để **xác định các quyền của nó** trong hệ thống. Mỗi process có một `uid` chính và một `gid` chính (mặc dù có thể thuộc nhiều nhóm).\
Cũng có thể thay đổi user id và group id nếu binary có bit `setuid/setgid`.\
Có một số hàm để **đặt uid/gid mới**.

System call **`persona`** cung cấp một bộ **thông tin xác thực** **thay thế**. Khi sử dụng persona, process đồng thời nhận uid, gid và các nhóm thành viên của persona đó. Trong [**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h), có thể tìm thấy struct:

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

1. **POSIX Threads (pthreads):** macOS hỗ trợ POSIX threads (`pthreads`), một phần của API luồng tiêu chuẩn cho C/C++. Bản triển khai pthreads trong macOS nằm tại `/usr/lib/system/libsystem_pthread.dylib`, bắt nguồn từ dự án `libpthread` được cung cấp công khai. Thư viện này cung cấp các hàm cần thiết để tạo và quản lý luồng.
2. **Tạo luồng:** Hàm `pthread_create()` được dùng để tạo luồng mới. Bên trong, hàm này gọi `bsdthread_create()`, một lệnh gọi hệ thống cấp thấp dành riêng cho kernel XNU (kernel làm nền tảng cho macOS). Lệnh gọi hệ thống này nhận nhiều cờ được lấy từ `pthread_attr` (các thuộc tính), dùng để xác định hành vi của luồng, bao gồm chính sách lập lịch và kích thước stack.
   - **Kích thước stack mặc định:** Kích thước stack mặc định cho luồng mới là 512 KB, đủ cho các hoạt động thông thường nhưng có thể điều chỉnh thông qua các thuộc tính luồng nếu cần thêm hoặc bớt dung lượng.
3. **Khởi tạo luồng:** Hàm `__pthread_init()` đóng vai trò quan trọng trong quá trình thiết lập luồng, sử dụng đối số `env[]` để phân tích các biến môi trường, có thể chứa thông tin về vị trí và kích thước của stack.

#### Kết thúc luồng trong macOS

1. **Thoát luồng:** Luồng thường được kết thúc bằng cách gọi `pthread_exit()`. Hàm này cho phép luồng thoát một cách an toàn, thực hiện các bước dọn dẹp cần thiết và gửi giá trị trả về cho các luồng đang chờ kết quả.
2. **Dọn dẹp luồng:** Khi gọi `pthread_exit()`, hàm `pthread_terminate()` sẽ được gọi để xử lý việc loại bỏ tất cả cấu trúc dữ liệu liên quan đến luồng. Hàm này giải phóng các Mach thread port (Mach là hệ thống con giao tiếp trong kernel XNU) và gọi `bsdthread_terminate`, một syscall loại bỏ các cấu trúc ở cấp kernel liên kết với luồng.

#### Cơ chế đồng bộ hóa

Để quản lý quyền truy cập vào tài nguyên dùng chung và tránh race condition, macOS cung cấp một số primitive đồng bộ hóa. Chúng rất quan trọng trong môi trường đa luồng, giúp đảm bảo tính toàn vẹn dữ liệu và độ ổn định của hệ thống:

1. **Mutex:**
   - **Mutex thông thường (Signature: 0x4D555458):** Mutex tiêu chuẩn có kích thước bộ nhớ 60 byte (56 byte cho mutex và 4 byte cho signature).
   - **Fast Mutex (Signature: 0x4d55545A):** Tương tự mutex thông thường nhưng được tối ưu để thao tác nhanh hơn, cũng có kích thước 60 byte.
2. **Biến điều kiện:**
   - Dùng để chờ một số điều kiện nhất định xảy ra, có kích thước 44 byte (40 byte cộng thêm signature 4 byte).
   - **Thuộc tính biến điều kiện (Signature: 0x434e4441):** Các thuộc tính cấu hình cho biến điều kiện, có kích thước 12 byte.
3. **Biến Once (Signature: 0x4f4e4345):**
   - Đảm bảo một đoạn mã khởi tạo chỉ được thực thi một lần. Kích thước của biến là 12 byte.
4. **Read-Write Lock:**
   - Cho phép nhiều reader hoặc một writer hoạt động cùng lúc, giúp truy cập dữ liệu dùng chung hiệu quả.
   - **Read Write Lock (Signature: 0x52574c4b):** Có kích thước 196 byte.
   - **Thuộc tính Read Write Lock (Signature: 0x52574c41):** Các thuộc tính cho read-write lock, có kích thước 20 byte.

> [!TIP]
> 4 byte cuối cùng của các đối tượng này được dùng để phát hiện tràn bộ đệm.

### Biến cục bộ của luồng (TLV)

**Biến cục bộ của luồng (TLV)** trong ngữ cảnh các tệp Mach-O (định dạng tệp thực thi trong macOS) được dùng để khai báo các biến dành riêng cho **từng luồng** trong ứng dụng đa luồng. Điều này đảm bảo mỗi luồng có một bản sao riêng của biến, giúp tránh xung đột và duy trì tính toàn vẹn dữ liệu mà không cần các cơ chế đồng bộ hóa tường minh như mutex.

Trong C và các ngôn ngữ liên quan, bạn có thể khai báo biến cục bộ của luồng bằng từ khóa **`__thread`**. Cách hoạt động trong ví dụ của bạn như sau:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Đoạn mã này định nghĩa `tlv_var` là một biến thread-local. Mỗi thread chạy đoạn mã này sẽ có `tlv_var` riêng; những thay đổi mà một thread thực hiện với `tlv_var` sẽ không ảnh hưởng đến `tlv_var` của thread khác.

Trong binary Mach-O, dữ liệu liên quan đến các biến thread-local được sắp xếp vào những section cụ thể:

- **`__DATA.__thread_vars`**: Section này chứa metadata về các biến thread-local, chẳng hạn như kiểu và trạng thái khởi tạo.
- **`__DATA.__thread_bss`**: Section này dành cho các biến thread-local chưa được khởi tạo tường minh. Đây là một phần bộ nhớ được dành riêng cho dữ liệu được khởi tạo bằng 0.

Mach-O cũng cung cấp API riêng có tên **`tlv_atexit`** để quản lý các biến thread-local khi một thread kết thúc. API này cho phép bạn **đăng ký hàm hủy** — các hàm đặc biệt dùng để dọn dẹp dữ liệu thread-local khi một thread chấm dứt.

### Ưu tiên của Thread

Để hiểu về mức ưu tiên của thread, cần xem xét cách hệ điều hành quyết định thread nào sẽ chạy và vào thời điểm nào. Quyết định này chịu ảnh hưởng bởi mức ưu tiên được gán cho mỗi thread. Trong macOS và các hệ thống tương tự Unix, việc này được xử lý bằng các khái niệm như `nice`, `renice` và các lớp Quality of Service (QoS).

#### Nice và Renice

1. **Nice:**
   - Giá trị `nice` của một process là một số ảnh hưởng đến mức ưu tiên của nó. Mỗi process có giá trị nice trong khoảng từ -20 (mức ưu tiên cao nhất) đến 19 (mức ưu tiên thấp nhất). Giá trị nice mặc định khi tạo process thường là 0.
   - Giá trị nice thấp hơn (gần -20 hơn) khiến process “ích kỷ” hơn, giúp nó nhận được nhiều thời gian CPU hơn so với các process có giá trị nice cao hơn.
2. **Renice:**
   - `renice` là lệnh dùng để thay đổi giá trị nice của một process đang chạy. Lệnh này có thể được dùng để điều chỉnh linh hoạt mức ưu tiên của process, tăng hoặc giảm thời lượng CPU được cấp phát dựa trên giá trị nice mới.
   - Ví dụ, nếu tạm thời cần thêm tài nguyên CPU cho một process, bạn có thể giảm giá trị nice của nó bằng `renice`.

#### Các lớp Quality of Service (QoS)

Các lớp QoS là cách tiếp cận hiện đại hơn để xử lý mức ưu tiên của thread, đặc biệt trên các hệ thống như macOS hỗ trợ **Grand Central Dispatch (GCD)**. Các lớp QoS cho phép nhà phát triển **phân loại** công việc thành nhiều mức dựa trên tầm quan trọng hoặc mức độ khẩn cấp. macOS tự động quản lý mức ưu tiên của thread dựa trên các lớp QoS này:

1. **User Interactive:**
   - Lớp này dành cho các tác vụ đang tương tác với người dùng hoặc cần trả về kết quả ngay lập tức để mang lại trải nghiệm tốt. Những tác vụ này được ưu tiên cao nhất để giao diện luôn phản hồi nhanh (ví dụ: hoạt ảnh hoặc xử lý sự kiện).
2. **User Initiated:**
   - Các tác vụ do người dùng khởi chạy và cần có kết quả ngay, chẳng hạn như mở tài liệu hoặc nhấp vào nút cần thực hiện tính toán. Những tác vụ này có mức ưu tiên cao, nhưng thấp hơn User Interactive.
3. **Utility:**
   - Đây là các tác vụ chạy lâu và thường hiển thị chỉ báo tiến trình (ví dụ: tải file xuống, nhập dữ liệu). Chúng có mức ưu tiên thấp hơn các tác vụ do người dùng khởi chạy và không cần hoàn tất ngay lập tức.
4. **Background:**
   - Lớp này dành cho các tác vụ chạy nền và không hiển thị với người dùng. Ví dụ: lập chỉ mục, đồng bộ hoặc sao lưu. Chúng có mức ưu tiên thấp nhất và ảnh hưởng tối thiểu đến hiệu năng hệ thống.

Với các lớp QoS, nhà phát triển không cần quản lý các con số ưu tiên cụ thể mà chỉ cần tập trung vào bản chất của tác vụ; hệ thống sẽ tối ưu tài nguyên CPU tương ứng.

Ngoài ra còn có các **chính sách lập lịch thread** khác nhau, cho phép chỉ định một tập hợp tham số lập lịch mà bộ lập lịch sẽ cân nhắc. Có thể thực hiện việc này bằng `thread_policy_[set/get]`. Điều này có thể hữu ích trong các cuộc tấn công race condition.

## Lạm dụng Process trên macOS

macOS cung cấp nhiều cơ chế để **các process tương tác, giao tiếp và chia sẻ dữ liệu**. Dù những cơ chế này thiết yếu đối với hoạt động bình thường của hệ thống, attacker có thể lạm dụng chúng để injection, thực thi mã hoặc truy cập dữ liệu.

### Library Injection

Library Injection là kỹ thuật trong đó attacker **buộc một process tải một thư viện độc hại**. Sau khi được inject, thư viện chạy trong context của process mục tiêu, giúp attacker có cùng quyền hạn và quyền truy cập như process đó.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking là việc **chặn các lời gọi hàm** hoặc thông điệp bên trong mã phần mềm. Bằng cách hook các hàm, attacker có thể **thay đổi hành vi** của process, quan sát dữ liệu nhạy cảm hoặc thậm chí kiểm soát luồng thực thi.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Giả mạo Call Stack ARM64/ARM64e

Trang này đề cập đến metadata unwind của ARM64, các ràng buộc PAC của arm64e và các chuỗi lời gọi tổng hợp.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Giao tiếp liên process

Inter Process Communication (IPC) là các phương thức khác nhau để những process riêng biệt **chia sẻ và trao đổi dữ liệu**. Dù IPC là nền tảng của nhiều ứng dụng hợp pháp, nó cũng có thể bị lạm dụng để phá vỡ sự cô lập giữa các process, leak thông tin nhạy cảm hoặc thực hiện các hành động trái phép.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Injection ứng dụng Electron

Các ứng dụng Electron chạy với một số biến môi trường nhất định có thể dễ bị process injection:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Có thể sử dụng các flag `--load-extension` và `--use-fake-ui-for-media-stream` để thực hiện **man in the browser attack**, cho phép đánh cắp thao tác gõ phím, traffic, cookie, inject script vào trang...:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

Các file NIB **định nghĩa các thành phần giao diện người dùng (UI)** và cách chúng tương tác trong một ứng dụng. Tuy nhiên, chúng có thể **thực thi các lệnh tùy ý** và **Gatekeeper không ngăn** một ứng dụng đã được thực thi chạy lại nếu **file NIB bị sửa đổi**. Vì vậy, chúng có thể được dùng để khiến các chương trình tùy ý thực thi lệnh tùy ý:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Injection ứng dụng Java

Có thể inject tùy chọn JVM thông qua **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** hoặc **`JDK_JAVA_OPTIONS`**, rồi tải Java agent hoặc native agent trước khi ứng dụng khởi chạy.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** preload JavaScript của attacker qua `--require` (file) hoặc `--import data:text/javascript,…` (không cần file, Node ≥ 20.6); **`NODE_REPL_EXTERNAL_MODULE`** tải một module vào REPL tương tác, còn **`ELECTRON_RUN_AS_NODE`** kích hoạt lại toàn bộ các cơ chế này trên binary Electron.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

Có thể inject mã vào ứng dụng .NET thông qua **`DOTNET_STARTUP_HOOKS`** trước `Main`, hoặc lạm dụng chức năng debugging của .NET khi đáp ứng các điều kiện cần thiết.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Bash không tương tác đọc **`BASH_ENV`**; các shell POSIX tương tác đọc **`ENV`**; zsh đọc **`$ZDOTDIR/.zshenv`**; còn fish đọc cấu hình bên dưới **`XDG_CONFIG_HOME`** hoặc **`XDG_DATA_DIRS`**. Mỗi shell đều có thể thực thi một file khởi động do attacker kiểm soát trước khi chạy lệnh dự kiến. Bash cũng chạy command substitution được đặt trong **`PS4`** mỗi khi bật xtrace (ví dụ: kế thừa **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Lén đưa lệnh qua stdin của Shell

Khởi chạy `/bin/zsh -s` khiến shell đọc chương trình từ standard input. Vì vậy, nếu một downloader sao chép tài liệu có cấu trúc không đáng tin cậy vào stdin của tiến trình con mà không phân tích trước, toàn bộ tài liệu sẽ trở thành mã nguồn shell. Một loader từng được quan sát đã truyền từng dòng của một file iCalendar công khai qua một pipe ẩn danh. Metadata lịch không chạy được như lệnh, nhưng zsh vẫn tiếp tục cho đến khi gặp các dòng thực thi được đặt sau `DESCRIPTION:`. Những dòng đó tải xuống và khởi chạy bundle ứng dụng tiếp theo. Loại nội dung dự kiến của dữ liệu và việc lưu trữ trên một dịch vụ đáng tin cậy không khiến cách làm này an toàn; ranh giới nguy hiểm nằm ở việc chuyển các byte của nó cho một interpreter.<sup>[[5]](#references)</sup>

Các giai đoạn liên quan được đề cập trong [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) và [macOS auto-start locations](../../macos-auto-start-locations.md).

### PHP Injection

**`PHPRC`** hoặc **`PHP_INI_SCAN_DIR`** có thể tải cấu hình PHP do attacker kiểm soát, trong đó **`auto_prepend_file`** thực thi trước script mục tiêu.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Trình thông dịch Lua độc lập thực thi mã hoặc một `@file` từ **`LUA_INIT`** (hoặc biến thể dành riêng cho phiên bản) trước khi xử lý script mục tiêu.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** và **`R_PROFILE`** chuyển hướng đến các profile khởi động chứa mã R. Ngoài ra, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** kết hợp với đường dẫn thư viện R có thể tự động tải một package đã cài đặt.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** chuyển hướng đến depot có `config/startup.jl` được tự động thực thi.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** hoặc **`ERL_ZFLAGS`** có thể inject biểu thức Erlang VM **`-eval`** mà không cần file payload; các workload Elixir thường khởi chạy cùng VM đó.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** và **`OCTAVE_VERSION_INITFILE`** chuyển hướng đến các script khởi động của Octave.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` là ứng dụng .NET đa nền tảng, vì vậy một số biến môi trường có thể thực thi mã trước lệnh: **`XDG_CONFIG_HOME`** chuyển hướng đến các script profile chạy lúc khởi động, **`PSModulePath`** chiếm quyền tự động tải module (một file `.psm1` được cài cắm sẽ chạy khi import và có thể che khuất các cmdlet tích hợp sẵn), còn các biến .NET **`CORECLR_PROFILER`**/**`COR_PROFILER`** và **`DOTNET_STARTUP_HOOKS`** tải mã của attacker vào process trước `Main`.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Tìm hiểu các tùy chọn khác nhau để khiến một script Perl thực thi mã tùy ý:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Cũng có thể lạm dụng các biến môi trường của Ruby (**`RUBYOPT`**, **`RUBYLIB`**) để khiến các script tùy ý thực thi mã tùy ý:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

Chuỗi **`PYTHONWARNINGS`** và **`BROWSER`** thuộc standard library có thể thực thi một lệnh trong quá trình phân tích bộ lọc cảnh báo. Một lựa chọn khác dựa trên file là đặt `sitecustomize.py` trong **`PYTHONPATH`** để quá trình khởi tạo `site` thông thường import file này trước script mục tiêu. **`PYTHONBREAKPOINT`** chạy callable/module được chọn khi mã gọi đến `breakpoint()`. Các biến chỉ dành cho chế độ tương tác như **`PYTHONSTARTUP`** có phạm vi áp dụng hẹp hơn.

Lưu ý rằng các executable được biên dịch bằng **`pyinstaller`** sẽ không sử dụng những biến môi trường này, ngay cả khi chúng đang chạy bằng Python nhúng.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (và biến dự phòng `EXINIT`) được thực thi dưới dạng lệnh Ex khi khởi động thông thường, vì vậy `:!cmd` / `:call system(...)` có thể thực thi mã khi nạn nhân mở Vim/Neovim với môi trường do attacker kiểm soát:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ngoài ra, Homebrew thường cài Python bên dưới `/opt/homebrew`, nơi các thành viên trong nhóm `admin` cục bộ có thể thay thế launcher. Đây là một kiểu chiếm quyền binary có thể ghi được, chứ không phải injection qua biến môi trường; hãy xác minh quyền sở hữu và ACL trước khi xem đây là lỗ hổng có thể khai thác.


## Phát hiện

### Shield

[**Shield**](https://github.com/theevilbit/Shield) là ứng dụng mã nguồn mở dựa trên **EndpointSecurity**, có khả năng phát hiện và chặn process injection. Đây là tài liệu tham khảo hữu ích về những tín hiệu có thể quan sát qua Endpoint Security, vì ứng dụng cảnh báo khi phát hiện:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Các biến môi trường injection** khi process thực thi: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` và `ELECTRON_RUN_AS_NODE`.
- Các lệnh gọi **`task_for_pid`** — một process yêu cầu task port của process khác; đây là điều kiện tiên quyết để inject vào process đó.
- **Các đối số debugging của Electron** — `--inspect`, `--inspect-brk` và `--remote-debugging-port`, dùng để khởi chạy ứng dụng Electron ở chế độ debug, cho phép bất kỳ ai attach vào và chạy mã trong đó.<sup>[[3]](#references)</sup>
- **Tạo symlink/hardlink giữa các mức quyền** — primitive kinh điển “tạo link với tư cách người dùng thường rồi trỏ link đến một vị trí có đặc quyền”. Lưu ý rằng **có thể cảnh báo về symlink nhưng không thể chặn**: EndpointSecurity không cung cấp đích của link trước khi nó được tạo.

### Các lệnh gọi do process khác thực hiện

Trong [**bài blog này**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), bạn có thể tìm hiểu cách sử dụng hàm **`task_name_for_pid`** để lấy thông tin về các **process đang inject mã vào một process**, rồi lấy thông tin về process kia.<sup>[[4]](#references)</sup>

Lưu ý rằng để gọi hàm này, bạn phải có **cùng uid** với uid đang chạy process hoặc là **root** (hàm này trả về thông tin về process, chứ không cung cấp cách inject mã).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — phát hiện process injection trên macOS mã nguồn mở (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — framework EndpointSecurity](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Vì sao ứng dụng Electron không thể lưu giữ bí mật của bạn một cách an toàn: tùy chọn --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Phát hiện các sửa đổi task](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - Phiên bản mới của malware đánh cắp thông tin MacSync trên macOS nhắm vào những người đam mê tiền mã hóa và nhà phát triển](https://securelist.com/macsync-new-version/121383/)
