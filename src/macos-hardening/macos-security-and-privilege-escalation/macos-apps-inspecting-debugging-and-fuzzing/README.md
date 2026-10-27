# Ứng dụng macOS - Kiểm tra, gỡ lỗi và Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Phân tích tĩnh

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (jtool2 cũ)

Bạn có thể [**tải disarm tại đây**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Lưu ý rằng **`disarm`** cũng có thể hoạt động với các tệp IM4P đã nén (như `kernelcache`) và chỉ trích xuất các phần cần thiết hoặc thậm chí phân tích phần cần thiết mà không cần trích xuất.

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> **`Codesign`** có thể được tìm thấy trên **macOS**, còn **`ldid`** có thể được tìm thấy trên **iOS**.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) là công cụ hữu ích để kiểm tra các tệp **.pkg** (trình cài đặt) và xem bên trong có gì trước khi cài đặt.\
Các trình cài đặt này có các script bash `preinstall` và `postinstall` mà tác giả malware thường lạm dụng để **duy trì** **mã độc**.

### hdiutil

Công cụ này **gắn kết** các tệp ảnh đĩa Apple (`.dmg`) để có thể kiểm tra trước khi chạy bất cứ thứ gì:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Nó sẽ được gắn tại `/Volumes`

### Binary được đóng gói

- Kiểm tra entropy cao
- Kiểm tra các chuỗi (nếu hầu như không có chuỗi nào dễ hiểu thì binary đã được đóng gói)
- Packer UPX cho macOS tạo ra một section có tên `__XHDR`.

## Phân tích Objective-C tĩnh

### Metadata

> [!CAUTION]
> Lưu ý rằng các chương trình viết bằng Objective-C **giữ lại** khai báo lớp **khi** được **biên dịch** thành [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Các khai báo lớp này **bao gồm** tên và kiểu của:

- Các interface được định nghĩa
- Các phương thức của interface
- Các biến instance của interface
- Các protocol được định nghĩa

Lưu ý rằng những tên này có thể bị làm rối để khiến việc reverse binary khó hơn.

### Gọi hàm

Khi một hàm được gọi trong binary sử dụng Objective-C, thay vì gọi hàm đó, mã đã biên dịch sẽ gọi **`objc_msgSend`**. Hàm này sẽ gọi hàm cuối cùng:

![Metadata - Gọi hàm: Khi một hàm được gọi trong binary sử dụng Objective-C, thay vì gọi hàm đó, mã đã biên dịch sẽ gọi objc msgSend . Hàm này sẽ...](<../../../images/image (305).png>)

Các tham số mà hàm này yêu cầu là:

- Tham số đầu tiên (**self**) là "một con trỏ trỏ đến **instance của lớp sẽ nhận message**". Nói đơn giản hơn, đó là object mà phương thức được gọi trên đó. Nếu phương thức là phương thức lớp, tham số này sẽ là một instance của object lớp (toàn bộ lớp); còn với phương thức instance, `self` sẽ trỏ đến một instance đã được khởi tạo của lớp dưới dạng object.
- Tham số thứ hai, (**op**), là "selector của phương thức xử lý message". Nói đơn giản hơn, đây chỉ là **tên của phương thức**.
- Các tham số còn lại là mọi **giá trị mà phương thức yêu cầu** (op).

Xem cách **lấy thông tin này dễ dàng bằng `lldb` trên ARM64** tại trang này:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Đối số**         | **Register**                                                    | **(cho) objc_msgSend**                              |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **Đối số thứ 1**  | **rdi**                                                         | **self: object mà phương thức được gọi trên đó** |
| **Đối số thứ 2**  | **rsi**                                                         | **op: tên phương thức**                             |
| **Đối số thứ 3**  | **rdx**                                                         | **Đối số thứ 1 của phương thức**                         |
| **Đối số thứ 4**  | **rcx**                                                         | **Đối số thứ 2 của phương thức**                         |
| **Đối số thứ 5**  | **r8**                                                          | **Đối số thứ 3 của phương thức**                         |
| **Đối số thứ 6**  | **r9**                                                          | **Đối số thứ 4 của phương thức**                         |
| **Đối số thứ 7+** | <p><strong>rsp+</strong><br><strong>(trên stack)</strong></p> | **Đối số thứ 5+ của phương thức**                        |

### Trích xuất metadata Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) là công cụ class-dump các binary Objective-C. GitHub ghi rằng công cụ này dành cho dylibs, nhưng nó cũng hoạt động với executable.

```bash
./dynadump dump /path/to/bin
```

Vào thời điểm viết bài này, **đây hiện là công cụ hoạt động tốt nhất**.

#### Công cụ thông thường

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) là công cụ đầu tiên tạo các khai báo cho class, category và protocol trong mã Objective-C đã được định dạng.

Công cụ này đã cũ và không còn được duy trì, nên có thể sẽ không hoạt động đúng cách.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) là công cụ dump class Objective-C hiện đại, đa nền tảng. So với các công cụ hiện có, iCDump có thể chạy độc lập với hệ sinh thái Apple và cung cấp các liên kết Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Phân tích Swift tĩnh

Với các binary Swift, do có khả năng tương thích với Objective-C, đôi khi bạn có thể trích xuất các khai báo bằng [class-dump](https://github.com/nygard/class-dump/) nhưng không phải lúc nào cũng được.

Dùng các dòng lệnh **`jtool -l`** hoặc **`otool -l`**, bạn có thể tìm thấy một số section bắt đầu bằng tiền tố **`__swift5`**:

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

Bạn có thể tìm thêm thông tin về [**thông tin được lưu trong các section này trong bài viết trên blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Ngoài ra, **các binary Swift có thể chứa symbols** (ví dụ: các thư viện cần lưu symbols để có thể gọi các hàm của chúng). **Symbols thường chứa thông tin về tên hàm** và thuộc tính theo cách khó đọc, vì vậy chúng rất hữu ích và có các công cụ "**demanglers"** có thể khôi phục tên ban đầu:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Phân tích động

> [!WARNING]
> **Không tắt SIP như một bước gỡ lỗi mặc định.** Có thể gỡ lỗi các bản dựng phát triển có `com.apple.security.get-task-allow` khi SIP vẫn bật. Kiểm tra mục tiêu bằng `codesign -d --entitlements :- /path/to/binary` trước khi thử LLDB. Chỉ có entitlement của trình gỡ lỗi không đủ để cấp quyền truy cập vào các mục tiêu được SIP bảo vệ.<sup>[[15]](#references)</sup>
>
> Ứng dụng được phân phối với hardened runtime thường không có `get-task-allow` và chặn việc gắn trình gỡ lỗi. Nếu có thể, hãy dùng bản dựng gỡ lỗi do nhà phát triển cung cấp; ký lại một bản sao dùng một lần có thể làm thay đổi hành vi đang được kiểm tra. Nếu mục tiêu được bảo vệ yêu cầu tắt SIP, hãy dùng máy thử nghiệm hoặc máy ảo chuyên dụng thay vì máy bạn vẫn dựa vào.<sup>[[16]](#references)</sup>
>
> Hướng dẫn trước đây dành cho mục tiêu được bảo vệ trong môi trường thử nghiệm cô lập liệt kê các lựa chọn sau:
>
> Lưu ý rằng để gỡ lỗi các binary, cần tắt SIP (`csrutil disable` hoặc `csrutil enable --without debug`), hoặc sao chép các binary vào một thư mục tạm thời rồi xóa chữ ký bằng `codesign --remove-signature <binary-path>`, hoặc cho phép gỡ lỗi binary (bạn có thể dùng [script này](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
>
> Đây không phải là yêu cầu chung của SIP: hãy ưu tiên bản dựng gỡ lỗi và lưu ý rằng việc sao chép hoặc thay đổi chữ ký có thể làm thay đổi hành vi đang được kiểm tra.

> [!WARNING]
> Lưu ý rằng để **instrument các binary hệ thống** (chẳng hạn như `cloudconfigurationd`) trên macOS, **phải tắt SIP** (chỉ xóa chữ ký sẽ không có tác dụng).

### APIs

macOS cung cấp một số API thú vị để lấy thông tin về các tiến trình:

- `proc_info`: API chính, cung cấp nhiều thông tin về từng tiến trình. Bạn cần quyền root để lấy thông tin về các tiến trình khác, nhưng không cần entitlement đặc biệt hoặc mach port.
- `libsysmon.dylib`: Cung cấp thông tin tiến trình thông qua các hàm XPC, nhưng bên gọi cần entitlement `com.apple.sysmond.client`.

### Stackshot & microstackshots

**Stackshotting** là kỹ thuật dùng để ghi lại trạng thái của các tiến trình, bao gồm call stack của tất cả các luồng đang chạy. Kỹ thuật này đặc biệt hữu ích khi gỡ lỗi, phân tích hiệu năng và tìm hiểu hành vi của hệ thống tại một thời điểm cụ thể. Trên iOS và macOS, có thể thực hiện stackshotting bằng một số công cụ và phương pháp, chẳng hạn như các công cụ **`sample`** và **`spindump`**.

### Sysdiagnose

Công cụ này (`/usr/bini/ysdiagnose`) về cơ bản thu thập nhiều thông tin từ máy tính bằng cách thực thi hàng chục lệnh khác nhau như `ps`, `zprint`...

Công cụ này phải được chạy với quyền **root**; daemon `/usr/libexec/sysdiagnosed` có các entitlement rất đáng chú ý như `com.apple.system-task-ports` và `get-task-allow`.

Plist của nó nằm tại `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, khai báo 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Xóa các archive cũ trong /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Cổng đặc biệt 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Giao diện user mode thông qua class Obj-C `Libsysdiagnose`. Có thể truyền ba đối số trong một dict (`compress`, `display`, `run`)

### Unified Logs

macOS tạo ra lượng log lớn, hữu ích khi phân tích hành vi của ứng dụng.

Một số trường log có thẻ `<private>` để ẩn thông tin nhận dạng người dùng hoặc thiết bị. Các hướng dẫn cũ đôi khi mô tả việc cài đặt chứng chỉ để hiển thị những trường này; hướng dẫn gỡ lỗi hiện tại thay vào đó dùng configuration profile được giới hạn rõ ràng với `Enable-Private-Data`, hoặc `OSLogPreferences` theo từng ứng dụng, và hành vi có thể khác nhau tùy subsystem và phiên bản macOS. Nội dung trao đổi về chứng chỉ/profile cũ được giữ lại trong phần tài liệu tham khảo. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Bảng bên trái

Trong bảng bên trái của hopper, có thể xem các symbol (**Labels**) của binary, danh sách các procedure và function (**Proc**) cùng các string (**Str**). Đây không phải toàn bộ string, mà là những string được định nghĩa trong một số phần của tệp Mac-O (như _cstring hoặc `objc_methname`).

#### Bảng giữa

Trong bảng giữa, bạn có thể xem **mã đã disassemble**. Bạn cũng có thể xem mã dưới dạng disassemble **thô**, **graph**, **decompiled** và **binary** bằng cách nhấp vào biểu tượng tương ứng:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Nhấp chuột phải vào một đối tượng mã để xem **các tham chiếu đến/từ đối tượng đó**, hoặc thậm chí đổi tên đối tượng (tính năng này không hoạt động trong pseudocode decompiled):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Ngoài ra, bạn có thể **viết lệnh python ở phần giữa phía dưới**.

#### Bảng bên phải

Trong bảng bên phải, bạn có thể xem các thông tin hữu ích như **lịch sử điều hướng** (để biết bạn đã đến trạng thái hiện tại bằng cách nào), **call graph** cho biết tất cả **các function gọi function này** và tất cả các function **được function này gọi**, cùng thông tin về **biến cục bộ**.

### dtrace

Công cụ này cho phép người dùng truy cập ứng dụng ở mức **rất thấp**, đồng thời cung cấp cách để người dùng **trace** **chương trình** và thậm chí thay đổi luồng thực thi. Dtrace sử dụng **probe** được **đặt khắp kernel**, tại các vị trí như đầu và cuối của system call.

DTrace dùng hàm **`dtrace_probe_create`** để tạo probe cho mỗi system call. Các probe này có thể được kích hoạt tại **điểm vào và điểm thoát của mỗi system call**. Việc tương tác với DTrace diễn ra thông qua /dev/dtrace, chỉ người dùng root mới có thể truy cập.<sup>[[1]](#references)</sup>

> [!TIP]
> Để bật Dtrace mà không tắt hoàn toàn cơ chế bảo vệ SIP, bạn có thể thực thi lệnh sau trong recovery mode: `csrutil enable --without dtrace`
>
> Bạn cũng có thể dùng **`dtrace`** hoặc **`dtruss`** với các binary **do chính bạn biên dịch**.

Có thể lấy danh sách probe khả dụng của dtrace bằng lệnh:

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Tên probe gồm bốn phần: provider, module, function và name (`fbt:mach_kernel:ptrace:entry`). Nếu bạn không chỉ định một phần nào đó, DTrace sẽ áp dụng ký tự đại diện cho phần đó.

Để cấu hình DTrace kích hoạt các probe và chỉ định hành động cần thực hiện khi chúng được kích hoạt, chúng ta cần sử dụng ngôn ngữ D.

Có thể xem giải thích chi tiết hơn và nhiều ví dụ khác tại [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Ví dụ

Chạy `man -k dtrace` để liệt kê **các script DTrace hiện có**. Ví dụ: `sudo dtruss -n binary`

- Trong dòng

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- script

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

Đây là một tiện ích theo dõi kernel. Có thể tìm thấy các mã được tài liệu hóa trong **`/usr/share/misc/trace.codes`**.

Các công cụ như `latency`, `sc_usage`, `fs_usage` và `trace` sử dụng tiện ích này ở bên trong.

Để tương tác với `kdebug`, người ta dùng `sysctl` trong namespace `kern.kdebug`; các MIB cần dùng có thể tìm thấy trong `sys/sysctl.h`, còn các hàm được triển khai trong `bsd/kern/kdebug.c`.

Các bước thường thực hiện để tương tác với kdebug bằng client tùy chỉnh:

- Xóa các thiết lập hiện có bằng KERN_KDSETREMOVE
- Thiết lập trace bằng KERN_KDSETBUF và KERN_KDSETUP
- Dùng KERN_KDGETBUF để lấy số lượng mục trong buffer
- Lấy client của chính mình ra khỏi trace bằng KERN_KDPINDEX
- Bật tracing bằng KERN_KDENABLE
- Đọc buffer bằng cách gọi KERN_KDREADTR
- Để ánh xạ từng thread với process tương ứng, gọi KERN_KDTHRMAP.

Có thể dùng công cụ của Apple **`trace`** hoặc công cụ tùy chỉnh [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)** để lấy thông tin này.

**Lưu ý rằng mỗi lần chỉ có một khách hàng được dùng Kdebug.** Vì vậy, mỗi lần chỉ có thể chạy một công cụ sử dụng k-debug.

### ktrace

Các API `ktrace_*` đến từ `libktrace.dylib`, thư viện này bọc các API của `Kdebug`. Sau đó, client chỉ cần gọi `ktrace_session_create` và `ktrace_events_[single/class]` để thiết lập callback cho các mã cụ thể, rồi khởi động bằng `ktrace_start`.

Bạn có thể dùng công cụ này ngay cả khi **SIP được bật**

Bạn có thể dùng tiện ích `ktrace` làm client:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Hoặc `tailspin`.

### kperf

Công cụ này được dùng để profiling ở cấp kernel và được xây dựng bằng các callout `Kdebug`.

Về cơ bản, biến toàn cục `kernel_debug_active` được kiểm tra và nếu được bật, nó sẽ gọi `kperf_kdebug_handler` với mã `Kdebug` và địa chỉ của kernel frame thực hiện lệnh gọi. Nếu mã `Kdebug` khớp với một mã đã chọn, nó sẽ nhận các "actions" được cấu hình dưới dạng bitmap (xem `osfmk/kperf/action.h` để biết các tùy chọn).

Kperf cũng có bảng sysctl MIB: (với quyền root) `sysctl kperf`. Có thể tìm thấy đoạn code này trong `osfmk/kperf/kperfbsd.c`.

Ngoài ra, một phần chức năng của Kperf nằm trong `kpc`, cung cấp thông tin về các machine performance counter.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) là một công cụ rất hữu ích để kiểm tra các hành động liên quan đến process mà một process đang thực hiện (ví dụ: theo dõi process đang tạo ra những process mới nào).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) là công cụ in ra mối quan hệ giữa các process.\
Bạn cần theo dõi máy Mac bằng một lệnh như **`sudo eslogger fork exec rename create > cap.json`** (Terminal chạy lệnh này cần có FDA). Sau đó, bạn có thể tải file json vào công cụ này để xem tất cả các mối quan hệ:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) theo dõi các sự kiện trên file như tạo, chỉnh sửa và xóa.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) là công cụ GUI có giao diện và cảm giác sử dụng mà người dùng Windows có thể quen thuộc từ _Procmon_ của Microsoft Sysinternal. Công cụ này cho phép bắt đầu và dừng ghi lại nhiều loại sự kiện, lọc các sự kiện này theo danh mục như file, process, network, v.v., và lưu các sự kiện đã ghi ở định dạng json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) là một phần của công cụ Developer tools trong Xcode – được dùng để theo dõi hiệu suất ứng dụng, xác định memory leak và theo dõi hoạt động của filesystem.

![Crescendo - Apple Instruments: Apple Instruments là một phần của công cụ Developer tools trong Xcode – được dùng để theo dõi hiệu suất ứng dụng, xác định memory leak và theo dõi hoạt động của filesystem](<../../../images/image (1138).png>)

### fs_usage

Cho phép theo dõi các hành động do process thực hiện:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) hữu ích để xem **các thư viện** được một binary sử dụng, **các tệp** mà nó đang dùng và các kết nối **mạng**.\
Nó cũng kiểm tra các tiến trình binary với **virustotal** và hiển thị thông tin về binary.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Trong [**bài blog này**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), bạn có thể tìm thấy một ví dụ về cách **debug một daemon đang chạy** sử dụng **`PT_DENY_ATTACH`** để ngăn việc debug ngay cả khi SIP đã bị tắt.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` là một yêu cầu `ptrace(2)` dành riêng cho Darwin với giá trị **31** (`0x1f`); các đối số khác bị bỏ qua. Một tiến trình có thể gọi trực tiếp yêu cầu này mà không cần fork để từ chối việc truy vết từ tiến trình cha về sau.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### Trạng thái XNU và thứ tự gọi

Kết quả phụ thuộc vào yêu cầu `ptrace` nào đến XNU trước:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB attach trước:** `debugserver` dùng `PT_ATTACHEXC`; XNU chuyển đổi nó thành `PT_ATTACH`, thực hiện kiểm tra ủy quyền `KAUTH_PROCESS_CANTRACE` và đặt `P_LTRACED` trên tiến trình đích. Lệnh `PT_DENY_ATTACH` tiếp theo thấy flag đó và kết thúc tiến trình đích bằng `W_EXITCODE(ENOTSUP, 0)`, thường được LLDB hiển thị với trạng thái **45** (`0x2d`).
- **Tiến trình đích từ chối trước:** XNU đặt `P_LNOATTACH`. Lần attach sau đó bị từ chối trong quá trình kiểm tra ủy quyền theo dõi tiến trình; đường dẫn xử lý lỗi attach thấy `P_LNOATTACH` và gửi `SIGSEGV` đến tiến trình đang attach, khiến LLDB có thể hiển thị kết nối `debugserver` bị mất.

Để phân biệt các trường hợp này, hãy bật logging của `debugserver` trước khi khởi chạy hoặc attach, rồi kiểm tra các yêu cầu `ptrace` của nó:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Nhận diện tĩnh và bypass trên ARM64

Với Mach-O ARM64 không bị làm rối mã, hãy tìm stub `_ptrace` được import và kiểm tra các vị trí gọi. Đối số nguyên đầu tiên được truyền qua `w0`, vì vậy chuỗi lệnh này trực tiếp cho thấy yêu cầu anti-debug. Không thể kết luận chắc chắn chỉ vì không có import này, do mã có thể phân giải `ptrace` một cách động. `_sysctl` được import cũng có thể cho thấy có kiểm tra anti-debug, dù nó cũng có thể được phân giải động.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

Trong mẫu minh họa, sửa giá trị immediate từ `0x1f` thành `0x0` sẽ đổi request thành `PT_TRACE_ME` và cho phép chương trình tiếp tục chạy trong LLDB. Đây là một **bypass chỉ áp dụng cho mẫu cụ thể này**, không phải no-op dùng chung: hãy kiểm tra các bước kiểm tra giá trị trả về và luồng điều khiển của hàm gọi trước khi quyết định đổi request, bỏ qua lời gọi hay ép trả về thành công.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** là **công cụ de facto** để **debugging** binary trên **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Bạn có thể đặt intel flavour khi dùng lldb bằng cách tạo một tệp có tên **`.lldbinit`** trong thư mục home của mình với dòng sau:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Trong lldb, dump một process bằng `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Mô tả</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Bắt đầu thực thi; quá trình sẽ tiếp tục cho đến khi breakpoint được kích hoạt hoặc process kết thúc.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Bắt đầu thực thi và dừng tại điểm vào.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Tiếp tục thực thi process đang được debug.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Thực thi lệnh tiếp theo. Lệnh này bỏ qua các lời gọi hàm.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Thực thi lệnh tiếp theo. Khác với lệnh <code>nexti</code>, lệnh này đi vào các lời gọi hàm.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Thực thi các lệnh còn lại trong hàm (frame) hiện tại, trả về rồi dừng.</td></tr>
<tr><td><strong>control + c</strong></td><td>Tạm dừng thực thi. Nếu process đã được chạy (<code>r</code>) hoặc tiếp tục (<code>c</code>), lệnh này sẽ dừng process tại vị trí đang thực thi.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Bất kỳ hàm nào có tên main</p>
<p><code>b &lt;binname&gt;`main</code> # Hàm main của binary</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Hàm main của binary được chỉ định</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Bất kỳ phương thức NSFileManager nào</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Đặt breakpoint trong tất cả hàm của thư viện đó</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Danh sách breakpoint</p>
<p><code>br e/dis &lt;num&gt;</code> # Bật/tắt breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Xem trợ giúp cho lệnh breakpoint</p>
<p><code>help memory write</code> # Xem trợ giúp về ghi vào memory</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Hiển thị memory dưới dạng chuỗi kết thúc bằng null.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Hiển thị memory dưới dạng lệnh assembly.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Hiển thị memory dưới dạng byte.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Lệnh này in object được tham chiếu bởi tham số.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>Hầu hết API hoặc phương thức Objective-C của Apple trả về object, vì vậy nên hiển thị chúng bằng lệnh “print object” (<code>po</code>). Nếu <code>po</code> không cho ra kết quả có ý nghĩa, hãy dùng <code>x/b</code>.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Ghi AAAA tại địa chỉ đó<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Ghi AAAA tại địa chỉ đó
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Disassemble hàm hiện tại</p>
<p><code>dis -n &lt;funcname&gt;</code> # Disassemble một hàm</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Disassemble một hàm<br>
<code>dis -c 6</code> # Disassemble sáu dòng<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Disassemble từ địa chỉ này đến địa chỉ kia<br>
<code>dis -p -c 4</code> # Bắt đầu disassemble tại địa chỉ hiện tại</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Kiểm tra mảng gồm ba phần tử trong thanh ghi <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>In sơ đồ memory của process hiện tại.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Lấy địa chỉ của từng symbol trong CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Khi gọi hàm **`objc_sendMsg`**, thanh ghi **rsi** chứa **tên phương thức** dưới dạng chuỗi kết thúc bằng null (chuỗi “C”). Để in tên bằng lldb, hãy dùng:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Chống phân tích động

#### Phát hiện VM

- Lệnh **`sysctl hw.model`** thường trả về mã định danh model Mac trên phần cứng vật lý và có thể trả về giá trị khác trong VM.<sup>[[3]](#references)</sup>
- Một số malware thử phát hiện VM bằng cách thay đổi các giá trị **`hw.logicalcpu`** và **`hw.physicalcpu`**.<sup>[[4]](#references)</sup>
- Khi kiểm tra VM trước khi giải nén stage tiếp theo, loader cũng có thể truy vấn `kern.hv_vmm_present` và `machdep.cpu.brand_string` thông qua `sysctl`. Các bước kiểm tra này bổ trợ cho, chứ không thay thế, bước kiểm tra debugger được mô tả bên dưới.<sup>[[20]](#references)</sup>
- Một số malware cũng có thể **phát hiện** máy đang chạy **VMware** dựa trên địa chỉ MAC (00:50:56).
- Cũng có thể kiểm tra **process có đang được debug hay không** bằng đoạn code đơn giản như sau:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Nó cũng có thể gọi system call `ptrace` với flag `PT_DENY_ATTACH`. Việc này ngăn debugger attach và trace. Xem [phần PT_DENY_ATTACH](#page-title) để biết về hành vi phụ thuộc thứ tự của XNU, log của `debugserver` và quy trình patch ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
- Nó cũng có thể gọi system call **`ptrace`** với flag **`PT_DENY_ATTACH`**. Xem [phần PT_DENY_ATTACH](#page-title) để biết về hành vi phụ thuộc thứ tự của XNU, log của `debugserver` và quy trình patch ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
  - Bạn có thể kiểm tra xem hàm **`sysctl`** hoặc **`ptrace`** có được **import** hay không (nhưng malware có thể import hàm đó một cách động)
  - Như được đề cập trong bài viết này, “[Đánh bại các kỹ thuật chống debug: các biến thể macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_The message Process # exited with **status = 45 (0x0000002d)** is usually a tell-tale sign that the debug target is using **PT_DENY_ATTACH**_”
#### Chuyển giao process bằng `fork()`

Một process có thể né debugger vẫn đang attach vào PID ban đầu bằng cách gọi `fork()` gần lúc khởi động, kết thúc process cha (`fork()` trả về PID dương của process con) và chỉ tiếp tục logic được bảo vệ trong process con (`fork()` trả về `0`). Việc phân giải `fork` bằng `dlsym(RTLD_DEFAULT, "fork")` cũng xóa lời gọi trực tiếp `_fork`, nhưng đây chỉ là trở ngại cho việc phân tích: chuỗi tên symbol và luồng dữ liệu phân giải động vẫn có thể thấy trong binary Mach-O.<sup>[[13]](#references)[[14]](#references)</sup>

Trên arm64, hãy phát hiện mẫu này bằng cách theo dõi luồng dữ liệu thay vì địa chỉ cố định: hai đối số đầu tiên của `dlsym` được truyền trong `x0` và `x1`, `RTLD_DEFAULT` có thể xuất hiện dưới dạng `-2` (ví dụ: `movn x0, #1`), còn một cặp `adrp`/`add` thường dùng để tạo địa chỉ của chuỗi `"fork"`. Sau lệnh `bl` gọi stub của `dlsym`, hãy theo dõi con trỏ trả về từ `x0` qua bước kiểm tra null và bước lưu trữ cho đến lệnh `blr` gián tiếp ở phía sau. Tiếp đó, theo dõi kết quả `fork()` trong `w0`: giá trị zero chọn nhánh tiếp tục của process con, còn các giá trị dương và `-1` chọn nhánh của process cha/lỗi.<sup>[[13]](#references)[[14]](#references)</sup>

Một cách bypass tĩnh là vô hiệu hóa lời gọi gián tiếp và buộc bước kiểm tra kết quả hiện có chọn nhánh của process con. Ví dụ, nếu compiler tạo ra chuỗi lệnh như bên dưới, hãy patch `blr` và lệnh lưu kết quả thành `nop`, đặt kết quả giả bằng zero và giữ nguyên logic so sánh/nhánh. Khi đó, ứng dụng tiếp tục chạy dưới PID ban đầu mà không tạo process con; cần điều chỉnh các thanh ghi lệnh và đích nhánh cho phù hợp với bản build đang phân tích.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

Core dumps được tạo nếu:

- sysctl `kern.coredump` được đặt thành 1 (mặc định)
- Nếu tiến trình không chạy với suid/sgid hoặc `kern.sugid_coredump` là 1 (mặc định là 0)
- Giới hạn `AS_CORE` cho phép thao tác này. Có thể ngăn tạo core dump bằng cách gọi `ulimit -c 0` và bật lại bằng `ulimit -c unlimited`.

Trong những trường hợp đó, core dump được tạo theo sysctl `kern.corefile` và thường được lưu tại `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **phân tích các tiến trình bị crash và lưu báo cáo crash vào đĩa**. Báo cáo crash chứa thông tin có thể **giúp nhà phát triển chẩn đoán** nguyên nhân gây ra sự cố.\
Đối với các ứng dụng và tiến trình khác **chạy trong ngữ cảnh launchd của từng người dùng**, ReportCrash chạy dưới dạng LaunchAgent và lưu báo cáo crash trong `~/Library/Logs/DiagnosticReports/` của người dùng.\
Đối với các daemon, tiến trình khác **chạy trong ngữ cảnh launchd của hệ thống** và các tiến trình có đặc quyền khác, ReportCrash chạy dưới dạng LaunchDaemon và lưu báo cáo crash trong `/Library/Logs/DiagnosticReports` của hệ thống.

Nếu lo ngại báo cáo crash **được gửi đến Apple**, bạn có thể tắt tính năng này. Nếu không, báo cáo crash có thể hữu ích để **tìm hiểu cách máy chủ bị crash**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Chế độ ngủ

Khi fuzzing trên macOS, hãy ngăn máy Mac chuyển sang chế độ ngủ:

- systemsetup -setsleep Never
- pmset, System Preferences
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Ngắt kết nối SSH

Nếu bạn fuzzing qua kết nối SSH, điều quan trọng là phải đảm bảo phiên không bị ngắt. Vì vậy, hãy sửa tệp sshd_config bằng các dòng sau:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Bộ xử lý nội bộ

**Xem trang sau** để biết cách tìm ứng dụng nào chịu trách nhiệm **xử lý scheme hoặc protocol được chỉ định:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Liệt kê các tiến trình mạng

Điều này hữu ích để tìm các tiến trình đang quản lý dữ liệu mạng:

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Hoặc dùng `netstat` hoặc `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzing Mach IPC có trạng thái

Các Mach service do daemon có đặc quyền cung cấp là mục tiêu fuzzing hữu ích khi client không có đặc quyền hoặc bị sandbox có thể lấy được send right. Bắt đầu từ mục `MachServices` trong launchd của daemon và dùng [quy trình phân tích MIG](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) để ánh xạ message ID tới các handler. Trước khi thay đổi byte, hãy đặt breakpoint tại routine phía server của MIG trong khi một client bình thường sử dụng service, rồi lưu các message request hợp lệ làm seed input. Giữ nguyên các trường header cần thiết, kích thước message và bố cục descriptor để các mutation đi tới handler thay vì bị loại ngay trong quá trình dispatch.<sup>[[17]](#references)</sup>

Nhiều handler phụ thuộc vào các lời gọi trước đó. Hãy để harness khởi tạo trạng thái service, rồi xử lý mỗi fuzz input như một chuỗi **operation và argument**: gửi các request thiết lập (chẳng hạn open hoặc create), giữ lại các identifier được trả về và dùng chúng trong các request tiếp theo. Cách này giúp coverage feedback khám phá các chuyển đổi trạng thái thay vì liên tục gặp kiểm tra đối tượng chưa được khởi tạo.<sup>[[17]](#references)</sup>

Với mục tiêu closed-source, có thể instrument một harness chạy trong tiến trình gọi routine dispatch của MIG bằng Jackalope/TinyInst. [Harness CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) là một triển khai cụ thể, không phải harness dùng ngay được cho các service khác.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Xác thực mọi crash qua đường IPC thực.** Harness gọi dispatch trực tiếp bỏ qua bước kernel xác thực Mach message và có thể tạo false positive, đặc biệt khi cung cấp bộ nhớ out-of-line (OOL) hoặc port descriptor không hợp lệ. Hãy cấp phát bộ nhớ OOL hợp lệ trong harness, sau đó chạy lại testcase đã rút gọn qua `mach_msg` từ một client có quyền truy cập service ban đầu và xác minh daemon vẫn crash.<sup>[[17]](#references)</sup>

### Fuzzer

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Dùng được cho các công cụ CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Nó "**chạy được ngay**" với nhiều công cụ GUI trên macOS. Một số ứng dụng có yêu cầu bổ sung, chẳng hạn như tên file phải là duy nhất, cần một phần mở rộng cụ thể hoặc phải đọc file từ sandbox container của chúng (`~/Library/Containers/com.apple.Safari/Data`).

Một số ví dụ:

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### Thông tin bổ sung về fuzzing macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Ứng phó sự cố OS X: Scripting và phân tích](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Mùa hè của Fuzz: MacOS - Làng AppSec DEF CON 29](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [Nghệ thuật phân tích malware trên Mac, Tập I](https://taomm.org/)
- [4] [No Starch Press - Nghệ thuật phân tích malware trên Mac: Hướng dẫn phân tích phần mềm độc hại](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - thông tin được lưu trong các section này trong bài đăng blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Gỡ lỗi các binary của Apple sử dụng Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Vượt qua kỹ thuật Anti-Debug: các biến thể ptrace trên macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Diễn đàn nhà phát triển Apple - Log có cấu trúc của Xcode và `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Hiển thị dữ liệu riêng tư trong unified log của macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Các định nghĩa request trong `ptrace.h` của Apple XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Triển khai `ptrace` của Apple XNU trong `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - Nội bộ ptrace: Cách ngăn debugger attach](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - các ví dụ fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - Kỹ thuật Anti-Debug sử dụng dlsym và fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Quyền entitlement cho công cụ gỡ lỗi](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Diễn đàn nhà phát triển Apple - Gỡ lỗi ứng dụng bên thứ ba đã được harden](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Phá vỡ rào cản âm thanh, Phần I: Fuzzing CoreAudio bằng Mach Messages](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - Harness CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Fuzzer Jackalope](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - Phiên bản mới của malware đánh cắp dữ liệu MacSync trên macOS nhắm đến những người đam mê crypto và nhà phát triển](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
