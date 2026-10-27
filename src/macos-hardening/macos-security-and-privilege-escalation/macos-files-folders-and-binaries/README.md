# macOS Files, Folders, Binaries & Memory

{{#include ../../../banners/hacktricks-training.md}}

## Bố cục hệ thống tệp

Apple mô tả hệ thống tệp macOS dưới dạng phân cấp gồm các miền hệ thống, cục bộ, mạng và người dùng. Nội dung chính xác thay đổi tùy theo phiên bản hệ điều hành, và các vị trí hệ thống ngày càng được bảo vệ hoặc tổng hợp. <sup>[[1]](#references)</sup>

- **/Applications**: Các app đã cài đặt thường nằm ở đây. Tất cả người dùng đều có thể truy cập chúng.
- **/bin**: Các binary dòng lệnh
- **/cores**: Nếu tồn tại, thư mục này dùng để lưu core dump
- **/dev**: Mọi thứ đều được xử lý như một tệp, vì vậy bạn có thể thấy các thiết bị phần cứng được lưu ở đây.
- **/etc**: Các tệp cấu hình
- **/Library**: Có thể tìm thấy nhiều thư mục con và tệp liên quan đến tùy chọn, cache và log ở đây. Thư mục Library tồn tại ở thư mục gốc và trong thư mục của từng người dùng.
- **/private**: Không được tài liệu hóa, nhưng nhiều thư mục đã đề cập là symbolic link đến thư mục private.
- **/sbin**: Các binary hệ thống thiết yếu (liên quan đến quản trị)
- **/System**: Các tệp cần thiết cho macOS; cây thư mục này chủ yếu chứa các thành phần do Apple cung cấp.
- **/tmp**: Các tệp tạm thời (symbolic link đến `/private/tmp`). Các bản cài đặt trước đây thường định kỳ xóa các tệp tạm cũ, đôi khi được mô tả là sau ba ngày, nhưng thời điểm dọn dẹp hiện nay phụ thuộc vào hệ thống và chính sách; đừng dựa vào việc dữ liệu sẽ tồn tại ở đó.
- **/Users**: Thư mục home của người dùng.
- **/usr**: Các tệp cấu hình và binary hệ thống
- **/var**: Các tệp log
- **/Volumes**: Các volume được mount sẽ xuất hiện ở đây.
- **/.vol**: Khi chạy `stat a.txt`, bạn sẽ nhận được kết quả tương tự `16777223 7545753 -rw-r--r-- 1 username wheel ...`; số đầu tiên là ID của volume chứa tệp, còn số thứ hai là số inode. Bạn có thể truy cập nội dung của tệp này qua `/.vol/` bằng thông tin đó, với lệnh `cat /.vol/16777223/7545753`

### Thư mục Applications

- Các **app hệ thống** nằm trong `/System/Applications`
- Các app đã **cài đặt** thường được cài trong `/Applications` hoặc `~/Applications`
- **Dữ liệu ứng dụng** có thể nằm trong `/Library/Application Support` đối với các app chạy với quyền root và `~/Library/Application Support` đối với các app chạy với quyền người dùng.
- **Daemon** của ứng dụng bên thứ ba **cần chạy với quyền root** thường nằm trong `/Library/PrivilegedHelperTools/`.
- Các app **sandbox** được ánh xạ vào thư mục `~/Library/Containers`. Mỗi app có một thư mục được đặt tên theo bundle ID của ứng dụng (`com.apple.Safari`).
- **Kernel** nằm trong `/System/Library/Kernels/kernel`
- **Kernel extension của Apple** nằm trong `/System/Library/Extensions`
- **Kernel extension của bên thứ ba** được lưu trong `/Library/Extensions`

### Tệp chứa thông tin nhạy cảm

macOS lưu trữ thông tin nhạy cảm, bao gồm cả thông tin xác thực, ở một số vị trí:


{{#ref}}
macos-sensitive-locations.md
{{#endref}}

### Trình cài đặt pkg dễ bị tấn công


{{#ref}}
macos-installers-abuse.md
{{#endref}}

Để biết sự khác biệt giữa volume Data có thể ghi và volume System được niêm phong trong hệ thống phân cấp này, xem [macOS Sealed System Volume & DataVault](../macos-security-protections/macos-sealed-system-volume-and-datavault.md).

## Các phần mở rộng riêng của OS X

- **`.dmg`**: Tệp Apple Disk Image rất phổ biến trong các trình cài đặt.
- **`.kext`**: Tệp này phải tuân theo một cấu trúc cụ thể và là phiên bản driver của OS X. (đây là một bundle)
- **`.plist`**: Property list lưu trữ thông tin có cấu trúc ở định dạng XML hoặc binary.
  - Có thể ở dạng XML hoặc binary. Có thể đọc các tệp binary bằng:
    - `defaults read config.plist`
    - `/usr/libexec/PlistBuddy -c print config.plist`
    - `plutil -p ~/Library/Preferences/com.apple.screensaver.plist`
    - `plutil -convert xml1 ~/Library/Preferences/com.apple.screensaver.plist -o -`
    - `plutil -convert json ~/Library/Preferences/com.apple.screensaver.plist -o -`
- **`.app`**: Một application bundle tuân theo cấu trúc thư mục macOS tiêu chuẩn.
- **`.dylib`**: Các thư viện động (tương tự tệp DLL của Windows)
- **`.pkg`**: Các gói cài đặt dạng flat hiện đại là XAR archive, nhưng `.pkg` là định dạng trình cài đặt, không phải từ đồng nghĩa với XAR. Các gói cài đặt kiểu bundle cũ là thư mục. Xem [macOS installers](macos-installers-abuse.md) để biết cấu trúc gói và cách kiểm tra. <sup>[[9]](#references)[[12]](#references)</sup>
- **`.DS_Store`**: Tệp này nằm trong mỗi thư mục, dùng để lưu thuộc tính và tùy chỉnh của thư mục.
- **`.Spotlight-V100`**: Thư mục này xuất hiện ở thư mục gốc của mọi volume trên hệ thống.
- **`.metadata_never_index`**: Nếu tệp này nằm ở thư mục gốc của một volume, Spotlight sẽ không lập chỉ mục volume đó.
- **`.noindex`**: Các tệp và thư mục có phần mở rộng này sẽ không được Spotlight lập chỉ mục.
- **`.sdef`**: Tệp định nghĩa scripting mô tả cách AppleScript có thể tương tác với một ứng dụng.

### Bundle macOS

Bundle là một thư mục có hệ thống phân cấp tiêu chuẩn mà Finder có thể hiển thị như một đối tượng duy nhất; application bundle sử dụng phần mở rộng `.app`. <sup>[[2]](#references)</sup>


{{#ref}}
macos-bundles.md
{{#endref}}

## Dyld Shared Library Cache (SLC)

Trên macOS và iOS, các thư viện hệ thống và framework thường dùng được liên kết trước vào **dyld shared cache**, giúp cải thiện hiệu suất khởi chạy ứng dụng. Dù được xem như một cache logic duy nhất, các bản phát hành hiện nay có thể lưu cache này dưới dạng cache chính cùng nhiều tệp subcache, thay vì thực sự nằm trong một tệp duy nhất. Định dạng và vị trí của nó là các chi tiết triển khai thay đổi theo từng bản phát hành hệ điều hành. <sup>[[3]](#references)</sup>

Trên macOS, cache này nằm trong `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`; ở các phiên bản cũ hơn, bạn có thể tìm thấy **shared cache** trong **`/System/Library/dyld/`**.\
Trên iOS, bạn có thể tìm thấy chúng trong **`/System/Library/Caches/com.apple.dyld/`**.

Tương tự dyld shared cache, kernel và các kernel extension cũng được biên dịch vào kernel cache, rồi được tải khi khởi động.

Các bản phát hành cũ có thể được trích xuất bằng [dyld_shared_cache_util](https://www.mbsplugins.de/files/dyld_shared_cache_util-dyld-733.8.zip). Bản build đó có thể không hỗ trợ các định dạng cache hiện tại; [**dyldextractor**](https://github.com/arandomdev/dyldextractor) là một lựa chọn khác:

```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```

> [!TIP]
> Lưu ý rằng ngay cả khi công cụ `dyld_shared_cache_util` không hoạt động, bạn vẫn có thể truyền **shared dyld binary vào Hopper** để Hopper nhận diện tất cả thư viện và cho phép bạn **chọn thư viện** muốn kiểm tra:

<figure><img src="../../../images/image (1152).png" alt="" width="563"><figcaption></figcaption></figure>

Một số extractor sẽ không hoạt động vì dylib được prelink với các địa chỉ hard-coded, do đó chúng có thể nhảy đến các địa chỉ không xác định.

> [!TIP]
> Bạn cũng có thể tải Shared Library Cache của các thiết bị \*OS khác trong macOS bằng trình giả lập trong Xcode. Các tệp này sẽ được tải xuống bên trong: ls `$HOME/Library/Developer/Xcode/<*>OS\ DeviceSupport/<version>/Symbols/System/Library/Caches/com.apple.dyld/`, như:`$HOME/Library/Developer/Xcode/iOS\ DeviceSupport/14.1\ (18A8395)/Symbols/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64`

### Mapping SLC

**`dyld`** dùng syscall **`shared_region_check_np`** để kiểm tra xem SLC đã được map hay chưa (syscall này trả về địa chỉ) và **`shared_region_map_and_slide_np`** để map SLC.

Lưu ý rằng dù SLC được slide trong lần sử dụng đầu tiên, tất cả **tiến trình** đều dùng **cùng một bản sao**, điều này **loại bỏ** cơ chế bảo vệ ASLR nếu attacker có thể chạy tiến trình trên hệ thống. Điều này từng bị khai thác trong quá khứ và được khắc phục bằng shared region pager.

Branch pools là các dylib Mach-O nhỏ tạo ra những khoảng trống nhỏ giữa các image mapping, khiến việc interpose các hàm trở nên bất khả thi.

### Các hạn chế môi trường của shared cache

`DYLD_SHARED_CACHE_DIR` chỉ định một thư mục cache, còn `DYLD_SHARED_REGION` chọn chế độ shared region. Cách viết `DYLD_DHARED_REGION` trước đây không hợp lệ, và `avoid` không phải là giá trị của `DYLD_SHARED_CACHE_DIR`. dyld hiện yêu cầu quyền AMFI cho phép dùng shared cache tùy chỉnh khi bật chế độ `private`, vì vậy chỉ đặt biến môi trường không đảm bảo tiến trình có thể tải một cache thay thế. <sup>[[10]](#references)</sup>

## Quyền đặc biệt của tệp

### Quyền thư mục

Đối với thư mục, quyền **read** cho phép liệt kê các mục bên trong, **write** cho phép tạo hoặc xóa mục, còn **execute** cho phép duyệt qua thư mục. Vì vậy, người dùng có thể đọc một tệp nhưng không thể truy cập tệp đó bằng đường dẫn nếu không có quyền duyệt qua thư mục cha. <sup>[[4]](#references)</sup>

### Các modifier của flag

Tệp có thể mang các flag làm thay đổi hành vi của chúng. Kiểm tra flag trong một thư mục bằng `ls -lO /path/directory`.

- **`uchg`**: Còn gọi là flag **uchange**, flag này sẽ **ngăn mọi thao tác** sửa đổi hoặc xóa **tệp**. Để đặt flag này, dùng: `chflags uchg file.txt`
  - Chủ sở hữu tệp hoặc root có thể gỡ flag **user** này bằng `chflags nouchg file.txt`; đây không phải là biện pháp bảo vệ trước họ. Flag immutable **system** riêng biệt (`schg`) chỉ dành cho root. <sup>[[11]](#references)</sup>
- **`restricted`**: Flag này khiến tệp được **SIP bảo vệ** (bạn không thể thêm flag này vào tệp).
- **`Sticky bit`**: Trong thư mục có sticky bit, chỉ chủ sở hữu tệp, chủ sở hữu thư mục hoặc root mới có thể đổi tên hoặc xóa một mục. Sticky bit thường được bật trên `/tmp` để ngăn người dùng xóa hoặc di chuyển tệp của người dùng khác.

Có thể tìm tất cả flag trong tệp `sys/stat.h` (tìm bằng `mdfind stat.h | grep stat.h`), gồm:

- `UF_SETTABLE` 0x0000ffff: Mask của các flag mà chủ sở hữu có thể thay đổi.
- `UF_NODUMP` 0x00000001: Không dump tệp.
- `UF_IMMUTABLE` 0x00000002: Không thể sửa đổi tệp.
- `UF_APPEND` 0x00000004: Chỉ có thể ghi thêm vào tệp.
- `UF_OPAQUE` 0x00000008: Thư mục là opaque đối với union.
- `UF_COMPRESSED` 0x00000020: Tệp được nén (trên một số file system).
- `UF_TRACKED` 0x00000040: Không gửi thông báo khi xóa/đổi tên các tệp được đặt flag này.
- `UF_DATAVAULT` 0x00000080: Cần entitlement để đọc và ghi.
- `UF_HIDDEN` 0x00008000: Gợi ý rằng mục này không nên được hiển thị trong GUI.
- `SF_SUPPORTED` 0x009f0000: Mask của các flag được hỗ trợ bởi superuser.
- `SF_SETTABLE` 0x3fff0000: Mask của các flag mà superuser có thể thay đổi.
- `SF_SYNTHETIC` 0xc0000000: Mask của các flag synthetic chỉ đọc thuộc hệ thống.
- `SF_ARCHIVED` 0x00010000: Tệp đã được lưu trữ.
- `SF_IMMUTABLE` 0x00020000: Không thể sửa đổi tệp.
- `SF_APPEND` 0x00040000: Chỉ có thể ghi thêm vào tệp.
- `SF_RESTRICTED` 0x00080000: Cần entitlement để ghi.
- `SF_NOUNLINK` 0x00100000: Không thể xóa, đổi tên hoặc mount mục này.
- `SF_FIRMLINK` 0x00800000: Tệp là firmlink.
- `SF_DATALESS` 0x40000000: Tệp là đối tượng dataless.

### **ACL của tệp**

**ACL** của tệp chứa **ACE** (Access Control Entries), cho phép gán **quyền chi tiết hơn** cho những người dùng khác nhau.

Có thể cấp cho một **thư mục** các quyền sau: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Đối với **tệp**: `read`, `write`, `append` và `execute`.

Khi tệp chứa ACL, bạn sẽ **thấy dấu "+" khi liệt kê quyền, như trong ví dụ sau**:

```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```

Bạn có thể **đọc ACL** của tệp bằng:

```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
 0: group:everyone deny delete
```

Bạn có thể tìm **tất cả các tệp có ACL** bằng lệnh sau (lệnh này chạy rất chậm):

```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```

### Extended Attributes

Extended attributes là các giá trị metadata có tên, được lưu riêng biệt với các thuộc tính thông thường của tệp. Liệt kê chúng bằng `ls -l@` và kiểm tra hoặc sửa đổi chúng bằng `xattr`. <sup>[[5]](#references)</sup> Một số extended attributes phổ biến:

- `com.apple.resourceFork`: Khả năng tương thích với resource fork. Cũng có thể xem tại `filename/..namedfork/rsrc`
- `com.apple.quarantine`: Metadata cách ly của macOS Gatekeeper
- `metadata:*`: Metadata của macOS, chẳng hạn như `_backup_excludeItem` hoặc `kMD*`
- `com.apple.lastuseddate` (#PS): Ngày sử dụng tệp gần nhất
- `com.apple.FinderInfo`: Thông tin của macOS Finder, chẳng hạn như thẻ màu
- `com.apple.TextEncoding`: Chỉ định mã hóa văn bản của các tệp văn bản ASCII
- `com.apple.logd.metadata`: Được logd sử dụng trên các tệp trong `/var/db/diagnostics`
- `com.apple.genstore.*`: Bộ nhớ lưu trữ theo thế hệ (`/.DocumentRevisions-V100` trong thư mục gốc của hệ thống tệp)
- `com.apple.rootless`: Metadata của macOS liên quan đến System Integrity Protection
- `com.apple.uuidb.boot-uuid`: Dấu đánh dấu của logd cho các giai đoạn khởi động, dùng UUID duy nhất
- `com.apple.decmpfs`: Metadata nén tệp trong suốt của macOS
- `com.apple.cprotect`: \*OS: Dữ liệu mã hóa theo từng tệp (III/11)
- `com.apple.installd.*`: \*OS: Metadata được installd sử dụng, ví dụ: `installType`, `uniqueInstallID`

### Resource Forks | macOS ADS

Resource fork cung cấp một luồng dữ liệu thay thế trên macOS. Nội dung có thể được lưu trong extended attribute `com.apple.ResourceFork` và truy cập thông qua `file/..namedfork/rsrc`.

```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt # The data-fork length is still 6 bytes
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```

Bạn có thể **tìm tất cả các tệp chứa extended attribute này** bằng cách:

```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```

### decmpfs

Thuộc tính mở rộng `com.apple.decmpfs` lưu metadata cho tính năng nén trong suốt; nó không cho biết dữ liệu đã được mã hóa. Tùy định dạng nén, dữ liệu nén có thể được lưu trong thuộc tính hoặc trong resource fork và sẽ được giải nén trong suốt khi đọc.

Flag `UF_COMPRESSED` hiển thị là `compressed` trong `ls -lO`. Đừng tự xóa flag này: việc đó có thể khiến hệ thống diễn giải sai dạng biểu diễn đã nén.

Lệnh xóa flag được hiển thị ở đây vì hữu ích khi xem xét pháp chứng, nhưng chạy lệnh này trên tệp đã nén có thể khiến tệp trông như rỗng hoặc không thể truy cập cho đến khi metadata được sửa chữa:

```bash
chflags nocompressed /path/to/file
```

Tiện ích tích hợp `/usr/bin/afscexpand` có thể buộc mở rộng các tệp được nén trong suốt. Tiện ích bên thứ ba riêng biệt `afsctool` cũng có thể kiểm tra hoặc giải nén dữ liệu nén của Apple filesystem, nhưng không nên nhầm nó với lệnh tích hợp sẵn. <sup>[[8]](#references)</sup>


### Các vị trí cấu hình đáng chú ý (macOS)

| Path / Location | Purpose / What it configures | Security / Attack-Potential |
|---|---|---|
| `/System/Library/FeatureFlags/Domain/` | Lưu các tệp plist feature-flag của Apple, điều khiển hành vi tùy chọn hoặc thử nghiệm trong system daemons / frameworks | Nếu attacker có thể bypass SIP hoặc giành được đặc quyền, việc sửa đổi các tệp này có thể bật những code path ẩn hoặc vô hiệu hóa các biện pháp bảo vệ |
| `/System/Library/CoreServices/systemVersion.plist` | Chứa metadata phiên bản macOS (ProductVersion, BuildVersion) được ứng dụng / trình cài đặt dùng để quyết định hành vi | Việc sửa đổi có thể đánh lừa ứng dụng hoặc trình cài đặt chấp nhận các phiên bản OS không được hỗ trợ hoặc mở khóa tính năng |
| `/Library/Preferences/com.apple.*.plist` & `~/Library/Preferences/*.plist` | Tùy chọn ứng dụng / toàn hệ thống | Nếu có quyền ghi, attacker có thể chèn cài đặt để điều hướng hành vi ứng dụng, vô hiệu hóa biện pháp bảo vệ hoặc gây cấu hình sai |
| `/Library/LaunchDaemons/` / `/Library/LaunchAgents/` | Các định nghĩa plist cho daemon và agent chạy nền | Chèn hoặc thao túng plist độc hại (nếu quyền cho phép) có thể tạo persistence hoặc leo thang đặc quyền |
| `/etc/hosts` | Ánh xạ hostname ↔ IP được system DNS resolver sử dụng | Chuyển hướng tên miền, chặn lưu lượng, giả mạo dịch vụ trong phạm vi kiểm soát cục bộ |
| `/etc/sudoers` | Xác định ai có thể chạy lệnh bằng `sudo` và trong điều kiện nào | Tệp sudoers bị sửa đổi có thể cấp quyền root hoặc đặc quyền không phù hợp cho tài khoản attacker |
| `/private/var/db/dslocal/nodes/Default/users/` | Các tệp plist định nghĩa tài khoản người dùng cục bộ | Thao túng cho phép tạo hoặc sửa đổi tài khoản người dùng, password hash hoặc metadata người dùng |
| `/System/Library/Extensions/` / `/Library/Extensions/` | Kernel extension / driver | Cài đặt hoặc sửa đổi kext có thể dẫn đến quyền kiểm soát ở cấp kernel; được bảo vệ nghiêm ngặt bởi SIP / chính sách chữ ký |
| `/private/var/db/SystemPolicyConfiguration/` | Lưu cấu hình thực thi chính sách hệ thống (ví dụ: Gatekeeper, notarization) | Thao túng các tệp này có thể cho phép vượt qua các bước kiểm tra chính sách hoặc quy tắc tin cậy |
| `/usr/libexec/ssh-keysign`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config` | Các tệp nhị phân trợ giúp và tệp cấu hình SSH | Cấu hình sai dẫn đến bảo mật SSH yếu, truy cập trái phép hoặc sử dụng thuật toán không an toàn |
| `/System/Library/Sandbox/Profiles` | Các system sandbox profile (SBPL) dùng để hạn chế hành động của process | Thay thế hoặc sửa đổi profile có thể mở ra các hướng sandbox escape hoặc làm suy yếu cơ chế cô lập |

> **Lưu ý**: Nhiều path trong số này nằm dưới các thư mục được SIP bảo vệ (ví dụ: `/System`) và được bảo vệ khỏi thao tác ghi, trừ khi SIP bị tắt hoặc bị bypass.  


## Universal Binaries Và Định dạng Mach-O

Mach-O là định dạng executable gốc trên macOS. Universal binary, hay fat binary, đóng gói nhiều Mach-O slice dành cho từng kiến trúc vào một tệp; trang riêng giải thích cả hai định dạng:

{{#ref}}
universal-binaries-and-mach-o-format.md
{{#endref}}


## Dump bộ nhớ macOS

{{#ref}}
macos-memory-dumping.md
{{#endref}}

## Rủi ro tệp và Metadata của Handler

LaunchServices, file quarantine và Gatekeeper cùng ảnh hưởng đến cách macOS xử lý các tệp đã tải xuống và chọn ứng dụng cho phần mở rộng tệp cũng như URL scheme. Database và tệp tài nguyên nội bộ của chúng thay đổi theo từng bản phát hành; hãy dùng các trang chuyên biệt thay vì xem một path CoreTypes riêng tư là giao diện chính sách ổn định:

Trên các bản phát hành có metadata rủi ro CoreTypes cũ tại `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System`, các category thường gặp là:<sup>[[7]](#references)</sup>

- **`LSRiskCategorySafe`**: Nội dung được xem là đủ an toàn để tự động mở theo chính sách ứng dụng hiện hành.
- **`LSRiskCategoryNeutral`**: Nội dung thường không kích hoạt cảnh báo và không được tự động mở.
- **`LSRiskCategoryUnsafeExecutable`**: Nội dung executable mà người dùng cần nhận cảnh báo từ ứng dụng.
- **`LSRiskCategoryMayContainUnsafeExecutable`**: Các container như archive có thể chứa nội dung executable và cần được kiểm tra thêm.

Đây là chi tiết triển khai, không phải public policy API ổn định; hãy xác nhận metadata thực tế và hành vi của Safari/Gatekeeper trên phiên bản macOS đang kiểm thử.

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}

## Tệp log

- **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Chứa thông tin về các tệp đã tải xuống, chẳng hạn URL nơi chúng được tải xuống.
- **Unified log**: Trên các phiên bản macOS hiện tại, dùng `log show` và `log stream` để truy vấn sự kiện hệ thống và ứng dụng. <sup>[[6]](#references)</sup>
- **`/var/log/system.log`** và **`/private/var/log/asl/*.asl`**: Các tạo tác log cũ vẫn có thể liên quan trên hệ thống đời cũ. Trên các bản phát hành đó, `/System/Library/LaunchDaemons/com.apple.syslogd.plist` cấu hình `syslogd`; `launchctl list | grep com.apple.syslogd` có thể giúp xác định dịch vụ có đang được tải hay không.
- **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Lưu các tệp và ứng dụng được truy cập gần đây thông qua "Finder".
- **`$HOME/Library/Preferences/com.apple.loginitems.plist`**: Path tùy chọn cũ liên quan đến login item; các phiên bản macOS hiện đại sử dụng thêm những cơ chế khác.
- **`$HOME/Library/Logs/DiskUtility.log`**: Log Disk Utility cũ có thể chứa thông tin về ổ đĩa, bao gồm thiết bị USB.
- **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Dữ liệu về các điểm truy cập không dây.
- **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Dữ liệu override launchd cũ.



## References

- [1] [Apple - Hướng dẫn lập trình hệ thống tệp](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/)
- [2] [Apple - Hướng dẫn lập trình Bundle](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/AboutBundles/AboutBundles.html)
- [3] [Diễn đàn Apple Developer - Tổng quan về dyld shared cache](https://developer.apple.com/forums/thread/692383)
- [4] [Apple - Hướng dẫn lập trình hệ thống tệp: Bảo mật hệ thống tệp macOS](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemDetails/FileSystemDetails.html)
- [5] [`xattr(1)` - Trang hướng dẫn macOS](https://manp.gs/mac/1/xattr)
- [6] [`log(1)` - Trang hướng dẫn macOS](https://manp.gs/mac/1/log)
- [7] [Apple Developer - Launch Services](https://developer.apple.com/documentation/coreservices/launch_services)
- [8] [`afscexpand(1)` - Trang hướng dẫn macOS](https://manp.gs/mac/1/afscexpand)
- [9] [Diễn đàn Apple Developer - Giải nén Apple Archive](https://developer.apple.com/forums/thread/133985)
- [10] [Apple dyld - DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [11] [Apple - Bảo mật Shell Script: các cờ quyền đặc biệt của tệp](https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html)
- [12] [Apple - Các tác vụ Code Signing: gói trình cài đặt](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)
{{#include ../../../banners/hacktricks-training.md}}
