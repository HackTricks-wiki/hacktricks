# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

macOS Sandbox (ban đầu có tên là Seatbelt) **giới hạn các ứng dụng** chạy bên trong sandbox ở **những hành động được cho phép trong profile Sandbox** mà ứng dụng đang sử dụng. Điều này giúp đảm bảo **ứng dụng chỉ truy cập các tài nguyên dự kiến**.

Mọi ứng dụng có **entitlement** **`com.apple.security.app-sandbox`** sẽ được thực thi bên trong sandbox. **Các binary của Apple** thường được thực thi bên trong Sandbox, và tất cả ứng dụng từ **App Store đều có entitlement đó**. Vì vậy, nhiều ứng dụng sẽ được thực thi bên trong sandbox.<sup>[[4]](#references)</sup>

Để kiểm soát những việc một process có thể hoặc không thể thực hiện, **Sandbox có các hook** trong hầu hết mọi thao tác mà process có thể thử (bao gồm hầu hết syscall), sử dụng **MACF**. Tuy nhiên, t**ùy thuộc** vào **entitlement** của ứng dụng, Sandbox có thể cho phép process thực hiện nhiều hành động hơn.

Một số thành phần quan trọng của Sandbox:

- **Kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **Private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Một **daemon** chạy trong userland `/usr/libexec/sandboxd`
- Các **container** `~/Library/Containers`

### Container

Mỗi ứng dụng được sandbox sẽ có container riêng tại `~/Library/Containers/{CFBundleIdentifier}` :

```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```

Bên trong mỗi thư mục bundle id, bạn có thể tìm thấy **plist** và **thư mục Data** của ứng dụng, với cấu trúc mô phỏng thư mục Home:

```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```

> [!CAUTION]
> Lưu ý rằng ngay cả khi có các symlink để "thoát" khỏi Sandbox và truy cập các thư mục khác, ứng dụng vẫn cần **có quyền** truy cập chúng. Các quyền này nằm trong **`.plist`** ở `RedirectablePaths`.

**`SandboxProfileData`** là CFData của sandbox profile đã biên dịch, được mã hóa thành B64.

```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
	<dict>
		<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
		<true/>
		<key>com.apple.accounts.appleaccount.fullaccess</key>
		<true/>
		<key>com.apple.appattest.spi</key>
		<true/>
		<key>keychain-access-groups</key>
		<array>
			<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
			<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
		</array>
[...]

# Some parameters
<key>Parameters</key>
	<dict>
		<key>_HOME</key>
		<string>/Users/username</string>
		<key>_UID</key>
		<string>501</string>
		<key>_USER</key>
		<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
	<array>
		<string>/Users/username/Downloads</string>
		<string>/Users/username/Documents</string>
		<string>/Users/username/Library/Calendars</string>
		<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
	<array/>
[...]
```

> [!WARNING]
> Mọi thứ được tạo hoặc sửa đổi bởi ứng dụng chạy trong sandbox đều nhận **quarantine attribute**. Điều này có thể ngăn sandbox escape bằng cách kích hoạt Gatekeeper nếu ứng dụng chạy trong sandbox cố thực thi thứ gì đó bằng **`open`**.

## Sandbox Profiles

Các profile Sandbox là các tệp cấu hình cho biết những gì sẽ được **cho phép/bị cấm** trong **Sandbox** đó. Chúng sử dụng **Sandbox Profile Language (SBPL)**, dựa trên ngôn ngữ lập trình [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Dưới đây là một ví dụ:

```scheme
(version 1) ; First you get the version

(deny default) ; Then you should indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
    (subpath "/Users/username/")
    (literal "/tmp/afile")
    (regex #"^/private/etc/.*")
)

(allow mach-lookup
    (global-name "com.apple.analyticsd")
)
```

> [!TIP]
> Xem [**nghiên cứu**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) này để tìm hiểu thêm về những hành động có thể được cho phép hoặc bị từ chối.<sup>[[5]](#references)</sup>
>
> Lưu ý rằng trong phiên bản đã biên dịch của một profile, tên các thao tác được thay bằng các mục tương ứng trong một mảng mà dylib và kext biết đến, khiến phiên bản đã biên dịch ngắn hơn và khó đọc hơn.

Các **system service** quan trọng cũng chạy bên trong **sandbox** tùy chỉnh riêng, chẳng hạn như dịch vụ `mdnsresponder`. Bạn có thể xem các **sandbox profile** tùy chỉnh này tại:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Có thể xem các sandbox profile khác tại [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- Trên iOS, platform profile nằm trong sandbox `.kext`, bên trong `_platform_profile_data` của binary.

Các ứng dụng **App Store** sử dụng **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Trong profile này, bạn có thể xem các entitlement như **`com.apple.security.network.server`** cho phép một process sử dụng mạng như thế nào.

Tiếp theo, một số **Apple daemon service** sử dụng các profile khác nhau nằm trong `/System/Library/Sandbox/Profiles/*.sb` hoặc `/usr/share/sandbox/*.sb`. Các sandbox này được áp dụng trong hàm chính thông qua API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

**SIP** là một sandbox profile có tên platform_profile trong `/System/Library/Sandbox/rootless.conf`.

### Ví dụ về Sandbox Profile

Để khởi chạy một ứng dụng với **sandbox profile cụ thể**, bạn có thể dùng:

```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
```

{{#tabs}}
{{#tab name="touch"}}

```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```

{{#endtab}}
{{#endtabs}}

> [!TIP]
> Lưu ý rằng **phần mềm** do **Apple phát triển** chạy trên **Windows** **không có các biện pháp bảo mật bổ sung**, chẳng hạn như application sandboxing.

Ví dụ về bypass:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (chúng có thể ghi các file bên ngoài sandbox có tên bắt đầu bằng `~$`).<sup>[[7]](#references)</sup>

### Truy vết Sandbox

#### Qua profile

Có thể theo dõi tất cả các lần kiểm tra mà sandbox thực hiện mỗi khi một hành động được kiểm tra. Để làm vậy, chỉ cần tạo profile sau:

```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```

Sau đó chỉ cần thực thi thứ gì đó bằng profile đó:

```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```

Trong `/tmp/trace.out`, bạn có thể xem từng lần kiểm tra sandbox được thực hiện mỗi khi nó được gọi (vì vậy sẽ có rất nhiều bản trùng lặp).

Cũng có thể trace sandbox bằng tham số **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Qua API

Hàm `sandbox_set_trace_path` được export bởi `libsystem_sandbox.dylib` cho phép chỉ định tên file trace để ghi lại các lần kiểm tra sandbox.\
Bạn cũng có thể làm điều tương tự bằng cách gọi `sandbox_vtrace_enable()` rồi lấy log lỗi từ buffer bằng cách gọi `sandbox_vtrace_report()`.

### Kiểm tra Sandbox

`libsandbox.dylib` export hàm có tên sandbox_inspect_pid, cung cấp danh sách trạng thái sandbox của một tiến trình (bao gồm cả extensions). Tuy nhiên, chỉ các binary thuộc nền tảng mới có thể sử dụng hàm này.

### Hồ sơ Sandbox của macOS & iOS

macOS lưu trữ các hồ sơ sandbox của hệ thống ở hai vị trí: **/usr/share/sandbox/** và **/System/Library/Sandbox/Profiles**.

Và nếu một ứng dụng bên thứ ba có entitlement _**com.apple.security.app-sandbox**_, hệ thống sẽ áp dụng hồ sơ **/System/Library/Sandbox/Profiles/application.sb** cho tiến trình đó.

Trong iOS, hồ sơ mặc định có tên **container** và chúng ta không có biểu diễn dạng văn bản SBPL. Trong bộ nhớ, sandbox này được biểu diễn dưới dạng cây nhị phân Allow/Deny cho từng quyền của sandbox.

### SBPL tùy chỉnh trong ứng dụng App Store

Các công ty có thể chạy ứng dụng của họ **với hồ sơ Sandbox tùy chỉnh** (thay vì hồ sơ mặc định). Họ cần sử dụng entitlement **`com.apple.security.temporary-exception.sbpl`**, vốn cần được Apple cấp phép.

Có thể kiểm tra định nghĩa của entitlement này trong **`/System/Library/Sandbox/Profiles/application.sb:`**

```scheme
(sandbox-array-entitlement
  "com.apple.security.temporary-exception.sbpl"
  (lambda (string)
    (let* ((port (open-input-string string)) (sbpl (read port)))
      (with-transparent-redirection (eval sbpl)))))
```

This sẽ **eval chuỗi sau entitlement này** dưới dạng profile Sandbox.

### Biên dịch và giải biên dịch một Sandbox Profile

Công cụ **`sandbox-exec`** sử dụng các hàm `sandbox_compile_*` từ `libsandbox.dylib`. Các hàm chính được export gồm: `sandbox_compile_file` (nhận đường dẫn tệp, tham số `-f`), `sandbox_compile_string` (nhận chuỗi, tham số `-p`), `sandbox_compile_name` (nhận tên container, tham số `-n`), `sandbox_compile_entitlements` (nhận entitlements plist).

Phiên bản đã reverse và [**được open source của công cụ sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) cho phép **`sandbox-exec`** ghi Sandbox profile đã biên dịch vào một tệp.

Ngoài ra, để giới hạn một process bên trong container, nó có thể gọi `sandbox_spawnattrs_set[container/profilename]` và truyền vào một container hoặc profile đã tồn tại.

## Debug và Bypass Sandbox

Trên macOS, không giống như iOS, nơi các process được kernel sandbox ngay từ đầu, **các process phải tự chọn tham gia Sandbox**. Điều này có nghĩa là trên macOS, một process không bị Sandbox hạn chế cho đến khi nó chủ động chọn vào Sandbox, mặc dù các ứng dụng App Store luôn được Sandbox.

Các process sẽ tự động được Sandbox từ userland khi khởi chạy nếu chúng có entitlement: `com.apple.security.app-sandbox`. Để biết giải thích chi tiết về quy trình này, hãy xem:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions cho phép cấp thêm quyền cho một đối tượng và được cấp bằng cách gọi một trong các hàm sau:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Các extension được lưu trong slot nhãn MACF thứ hai, có thể truy cập từ thông tin xác thực của process. **`sbtool`** sau đây có thể truy cập thông tin này.

Lưu ý rằng extension thường được cấp bởi các process có quyền cho phép; ví dụ, `tccd` sẽ cấp token extension `com.apple.tcc.kTCCServicePhotos` khi một process thử truy cập ảnh và được cho phép trong một thông điệp XPC. Sau đó, process cần tiêu thụ token extension để token được thêm vào process đó.\
Lưu ý rằng token extension là các chuỗi hex dài mã hóa những quyền đã cấp. Tuy nhiên, chúng không mã hóa sẵn PID được phép, nghĩa là bất kỳ process nào có quyền truy cập token đều có thể **được nhiều process tiêu thụ**.

Lưu ý rằng extension cũng có liên quan mật thiết đến entitlements, vì vậy một số entitlements nhất định có thể tự động cấp một số extension nhất định.

### **Kiểm tra quyền của PID**

[**Theo nguồn này**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), các hàm **`sandbox_check`** (đây là một `__mac_syscall`) có thể kiểm tra **một thao tác có được Sandbox cho phép hay không** đối với một PID, audit token hoặc unique ID cụ thể.<sup>[[8]](#references)</sup>

[**Công cụ sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (có thể tìm bản [đã biên dịch tại đây](https://newosxbook.com/articles/hitsb.html)) có thể kiểm tra PID có thể thực hiện một số thao tác nhất định hay không:

```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```

### \[un]suspend

Cũng có thể suspend và unsuspend sandbox bằng các hàm `sandbox_suspend` và `sandbox_unsuspend` từ `libsystem_sandbox.dylib`.

Lưu ý rằng để gọi hàm suspend, một số entitlement sẽ được kiểm tra nhằm xác thực quyền gọi hàm của caller, chẳng hạn:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

System call này (#381) yêu cầu một chuỗi làm đối số đầu tiên để chỉ định module cần chạy, sau đó là một mã ở đối số thứ hai để chỉ định hàm cần chạy. Đối số thứ ba sẽ phụ thuộc vào hàm được thực thi.<sup>[[2]](#references)</sup>

Hàm `___sandbox_ms` là wrapper gọi `mac_syscall` với đối số đầu tiên là `"Sandbox"`, tương tự như `___sandbox_msp` là wrapper của `mac_set_proc` (#387). Một số mã được `___sandbox_ms` hỗ trợ có trong bảng sau:

- **set_profile (#0)**: Áp dụng profile đã biên dịch hoặc được đặt tên cho một process.
- **platform_policy (#1)**: Thực thi các kiểm tra policy dành riêng cho nền tảng (khác nhau giữa macOS và iOS).
- **check_sandbox (#2)**: Thực hiện kiểm tra thủ công một thao tác sandbox cụ thể.
- **note (#3)**: Thêm chú thích vào Sandbox.
- **container (#4)**: Gắn chú thích vào sandbox, thường dùng để debug hoặc nhận diện.
- **extension_issue (#5)**: Tạo extension mới cho một process.
- **extension_consume (#6)**: Sử dụng một extension được chỉ định.
- **extension_release (#7)**: Giải phóng vùng nhớ gắn với một extension đã được sử dụng.
- **extension_update_file (#8)**: Sửa đổi các tham số của một file extension hiện có trong sandbox.
- **extension_twiddle (#9)**: Điều chỉnh hoặc sửa đổi một file extension hiện có (ví dụ: TextEdit, rtf, rtfd).
- **suspend (#10)**: Tạm thời suspend mọi kiểm tra sandbox (cần entitlement phù hợp).
- **unsuspend (#11)**: Tiếp tục mọi kiểm tra sandbox đã bị suspend trước đó.
- **passthrough_access (#12)**: Cho phép truy cập trực tiếp vào một tài nguyên, bỏ qua các kiểm tra sandbox.
- **set_container_path (#13)**: (Chỉ iOS) Đặt đường dẫn container cho app group hoặc signing ID.
- **container_map (#14)**: (Chỉ iOS) Lấy đường dẫn container từ `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Đặt metadata ở user mode trong sandbox.
- **inspect (#16)**: Cung cấp thông tin debug về một process đang bị sandbox.
- **dump (#18)**: (macOS 11) Dump profile hiện tại của sandbox để phân tích.
- **vtrace (#19)**: Theo dõi các thao tác sandbox để giám sát hoặc debug.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Vô hiệu hóa các profile được đặt tên (ví dụ: `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Thực hiện nhiều thao tác `sandbox_check` trong một lần gọi.
- **reference_retain_by_audit_token (#28)**: Tạo reference cho một audit token để dùng trong các kiểm tra sandbox.
- **reference_release (#29)**: Giải phóng một reference audit token đã được retain trước đó.
- **rootless_allows_task_for_pid (#30)**: Xác minh liệu `task_for_pid` có được cho phép hay không (tương tự các kiểm tra `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Áp dụng file manifest System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Kiểm tra file manifest SIP trước khi thực thi.
- **rootless_protected_volume (#33)**: (macOS) Áp dụng các bảo vệ SIP cho một ổ đĩa hoặc phân vùng.
- **rootless_mkdir_protected (#34)**: Áp dụng bảo vệ SIP/DataVault cho quá trình tạo thư mục.

## Sandbox.kext

Lưu ý rằng trên iOS, kernel extension chứa **toàn bộ profile được hardcode** bên trong segment `__TEXT.__const` để tránh bị sửa đổi. Sau đây là một số hàm đáng chú ý trong kernel extension:

- **`hook_policy_init`**: Hook `mpo_policy_init` và được gọi sau `mac_policy_register`. Hàm này thực hiện phần lớn việc khởi tạo Sandbox. Nó cũng khởi tạo SIP.
- **`hook_policy_initbsd`**: Thiết lập giao diện sysctl, đăng ký `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` và `security.mac.sandbox.debug_mode` (nếu được boot với `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Được `mac_syscall` gọi với `"Sandbox"` làm đối số đầu tiên và mã biểu thị thao tác làm đối số thứ hai. Một switch được dùng để tìm mã cần chạy tương ứng với mã được yêu cầu.

### Các hook MACF

**`Sandbox.kext`** sử dụng hơn một trăm hook thông qua MACF. Hầu hết các hook chỉ kiểm tra một số trường hợp đơn giản; nếu thao tác không được phép, chúng sẽ gọi **`cred_sb_evalutate`** với **credentials** từ MACF, một số tương ứng với **operation** cần thực hiện và một **buffer** chứa đầu ra.<sup>[[1]](#references)</sup>

Một ví dụ điển hình là hàm **`_mpo_file_check_mmap`**, hook **`mmap`**. Hàm này bắt đầu bằng cách kiểm tra xem vùng nhớ mới có thể ghi được hay không (nếu không thì cho phép thực thi), tiếp theo kiểm tra xem vùng nhớ đó có được dùng cho dyld shared cache hay không và nếu có thì cho phép thực thi, cuối cùng gọi **`sb_evaluate_internal`** (hoặc một trong các wrapper của hàm này) để thực hiện thêm các kiểm tra cấp quyền.

Ngoài hàng trăm hook Sandbox sử dụng, có 3 hook đặc biệt đáng chú ý:

- `mpo_proc_check_for`: Áp dụng profile nếu cần và nếu profile đó chưa được áp dụng trước đó.
- `mpo_vnode_check_exec`: Được gọi khi một process tải binary tương ứng; sau đó thực hiện kiểm tra profile và kiểm tra để cấm thực thi SUID/SGID.
- `mpo_cred_label_update_execve`: Được gọi khi label được gán. Đây là hook dài nhất vì nó được gọi khi binary đã được tải hoàn toàn nhưng chưa được thực thi. Hook này thực hiện các tác vụ như tạo đối tượng sandbox, gắn struct sandbox vào credentials của kauth, xóa quyền truy cập vào các mach port...

Lưu ý rằng **`_cred_sb_evalutate`** là wrapper của **`sb_evaluate_internal`**. Hàm này nhận credentials được truyền vào rồi thực hiện đánh giá bằng hàm **`eval`**, thường đánh giá **platform profile** (mặc định được áp dụng cho mọi process), sau đó là **profile riêng của process**. Lưu ý rằng platform profile là một trong những thành phần chính của **SIP** trên macOS.

## Sandboxd

Sandbox cũng có một user daemon đang chạy, cung cấp XPC Mach service `com.apple.sandboxd` và liên kết với special port 14 (`HOST_SEATBELT_PORT`), được kernel extension dùng để giao tiếp với daemon này. Daemon cung cấp một số hàm thông qua MIG.

## References

- [1] [XNU — `security/mac_policy.h` (các hook MACF mà Sandbox kext đăng ký)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, điểm vào phía sau `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` — trang man](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Hướng dẫn Apple Sandbox v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Thoát khỏi Mac sandbox](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Thoát khỏi MacOS Sandbox của Office365](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - Apple Sandbox: Đi sâu hơn vào vũng lầy - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
