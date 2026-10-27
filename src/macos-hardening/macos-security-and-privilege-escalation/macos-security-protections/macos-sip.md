# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Thông tin cơ bản**

**Bảo vệ tính toàn vẹn hệ thống (System Integrity Protection, SIP)** trong macOS là một cơ chế được thiết kế để ngăn cả những người dùng có đặc quyền cao nhất thực hiện các thay đổi trái phép đối với những thư mục hệ thống quan trọng. Tính năng này đóng vai trò thiết yếu trong việc duy trì tính toàn vẹn của hệ thống bằng cách hạn chế các hành động như thêm, sửa đổi hoặc xóa tệp trong những khu vực được bảo vệ. Các thư mục chính được SIP bảo vệ gồm:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Các quy tắc chi phối hoạt động của SIP được xác định trong tệp cấu hình tại **`/System/Library/Sandbox/rootless.conf`**. Trong tệp này, những đường dẫn có tiền tố là dấu hoa thị (\*) được xem là ngoại lệ đối với các hạn chế nghiêm ngặt khác của SIP.

Hãy xem ví dụ dưới đây:

```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```

Đoạn trích này cho thấy mặc dù SIP thường bảo vệ thư mục **`/usr`**, vẫn có một số thư mục con cụ thể (`/usr/libexec/cups`, `/usr/local` và `/usr/share/man`) cho phép sửa đổi, như dấu hoa thị (\*) đứng trước các đường dẫn này cho biết.

Để xác minh một thư mục hoặc tệp có được SIP bảo vệ hay không, bạn có thể dùng lệnh **`ls -lOd`** để kiểm tra xem có cờ **`restricted`** hoặc **`sunlnk`** hay không. Ví dụ:

```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```

Trong trường hợp này, flag **`sunlnk`** có nghĩa là không thể xóa chính thư mục `/usr/libexec/cups`, dù có thể tạo, sửa đổi hoặc xóa các tệp bên trong.

Mặt khác:

```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```

Ở đây, cờ **`restricted`** cho biết thư mục `/usr/libexec` được SIP bảo vệ. Trong thư mục được SIP bảo vệ, không thể tạo, sửa đổi hoặc xóa tệp.

Ngoài ra, nếu một tệp có **extended attribute** **`com.apple.rootless`**, thì tệp đó cũng sẽ được **SIP bảo vệ**.

> [!TIP]
> Lưu ý rằng hook **Sandbox** **`hook_vnode_check_setextattr`** ngăn mọi nỗ lực sửa đổi extended attribute **`com.apple.rootless`.**

**SIP cũng giới hạn các thao tác root khác**, chẳng hạn như:

- Tải các kernel extension không đáng tin cậy
- Lấy task-port của các tiến trình do Apple ký
- Sửa đổi các biến NVRAM
- Cho phép kernel debugging

Các tùy chọn được lưu trong biến NVRAM dưới dạng bitflag (`csr-active-config` trên Intel và `lp-sip0` được đọc từ Device Tree đã khởi động trên ARM). Bạn có thể tìm các cờ trong mã nguồn XNU tại `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Trạng thái SIP

Bạn có thể kiểm tra xem SIP có được bật trên hệ thống của mình hay không bằng lệnh sau:

```bash
csrutil status
```

Nếu cần tắt SIP, bạn phải khởi động lại máy tính ở chế độ recovery (bằng cách nhấn Command+R trong khi khởi động), sau đó chạy lệnh sau:

```bash
csrutil disable
```

Nếu bạn muốn giữ SIP bật nhưng loại bỏ các biện pháp bảo vệ chống gỡ lỗi, bạn có thể thực hiện như sau:

```bash
csrutil enable --without debug
```

### Các hạn chế khác

- **Không cho phép tải các kernel extension (kext) chưa được ký**, đảm bảo chỉ các extension đã được xác minh mới tương tác với kernel hệ thống.
- **Ngăn debug các tiến trình hệ thống macOS**, bảo vệ các thành phần cốt lõi của hệ thống khỏi bị truy cập và chỉnh sửa trái phép.
- **Ngăn các công cụ** như dtrace kiểm tra tiến trình hệ thống, qua đó tiếp tục bảo vệ tính toàn vẹn trong hoạt động của hệ thống.

[**Tìm hiểu thêm về SIP trong bài nói chuyện này**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **Entitlements liên quan đến SIP**

- `com.apple.rootless.xpc.bootstrap`: Điều khiển launchd
- `com.apple.rootless.install[.heritable]`: Truy cập hệ thống tệp
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Quản lý UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Các khả năng thiết lập XPC
- `com.apple.rootless.xpc.effective-root`: Quyền root thông qua launchd XPC
- `com.apple.rootless.restricted-block-devices`: Truy cập các thiết bị block thô
- `com.apple.rootless.internal.installer-equivalent`: Toàn quyền truy cập hệ thống tệp
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Toàn quyền truy cập NVRAM
- `com.apple.rootless.storage.label`: Sửa đổi các tệp bị hạn chế bởi xattr com.apple.rootless có nhãn tương ứng
- `com.apple.rootless.volume.VM.label`: Duy trì bộ nhớ hoán đổi VM trên volume

## Bypass SIP

Bypass SIP cho phép kẻ tấn công:

- **Truy cập dữ liệu người dùng**: Đọc dữ liệu nhạy cảm như thư, tin nhắn và lịch sử Safari từ tất cả tài khoản người dùng.
- **Bypass TCC**: Trực tiếp thao túng cơ sở dữ liệu TCC (Transparency, Consent, and Control) để cấp quyền truy cập trái phép vào webcam, microphone và các tài nguyên khác.
- **Thiết lập persistence**: Đặt malware vào các vị trí được SIP bảo vệ, khiến việc gỡ bỏ trở nên khó khăn ngay cả với quyền root. Việc này cũng có thể bao gồm thao túng Malware Removal Tool (MRT).
- **Tải kernel extension**: Dù có thêm các biện pháp bảo vệ, bypass SIP sẽ đơn giản hóa quá trình tải các kernel extension chưa được ký.

### Gói cài đặt

**Các gói cài đặt được ký bằng chứng chỉ của Apple** có thể bypass các biện pháp bảo vệ của SIP. Điều này có nghĩa là ngay cả các gói được ký bởi nhà phát triển thông thường cũng sẽ bị chặn nếu cố sửa đổi các thư mục được SIP bảo vệ.

### Tệp SIP không tồn tại

Một lỗ hổng tiềm ẩn là nếu một tệp được chỉ định trong **`rootless.conf` nhưng hiện không tồn tại**, tệp đó vẫn có thể được tạo. Malware có thể khai thác điều này để **thiết lập persistence** trên hệ thống. Ví dụ, một chương trình độc hại có thể tạo tệp .plist trong `/System/Library/LaunchDaemons` nếu đường dẫn này được liệt kê trong `rootless.conf` nhưng tệp chưa tồn tại.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** cho phép bypass SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Người ta phát hiện có thể **thay thế gói cài đặt sau khi hệ thống xác minh chữ ký** code của gói, khiến hệ thống cài đặt gói độc hại thay vì gói ban đầu. Vì các thao tác này được thực hiện bởi **`system_installd`**, chúng có thể bypass SIP.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Nếu một gói được cài đặt từ image đã mount hoặc ổ đĩa ngoài, **installer** sẽ **thực thi** binary từ **hệ thống tệp đó** (thay vì từ vị trí được SIP bảo vệ), khiến **`system_installd`** thực thi một binary tùy ý.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Các nhà nghiên cứu trong bài viết này**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) phát hiện một lỗ hổng trong cơ chế System Integrity Protection (SIP) của macOS, được đặt tên là lỗ hổng “Shrootless”. Lỗ hổng này liên quan đến daemon **`system_installd`**, có entitlement **`com.apple.rootless.install.heritable`**, cho phép mọi tiến trình con của nó bypass các hạn chế hệ thống tệp của SIP.<sup>[[4]](#references)</sup>

Daemon **`system_installd`** sẽ cài đặt các gói được **Apple** ký.

Các nhà nghiên cứu phát hiện rằng trong quá trình cài đặt một gói được Apple ký (tệp .pkg), **`system_installd`** **chạy** mọi script **post-install** có trong gói. Các script này được thực thi bởi shell mặc định, **`zsh`**, và shell này tự động **chạy** các lệnh trong tệp **`/etc/zshenv`** nếu tệp tồn tại, kể cả ở chế độ không tương tác. Kẻ tấn công có thể khai thác hành vi này bằng cách tạo tệp `/etc/zshenv` độc hại rồi chờ **`system_installd` gọi `zsh`** để thực hiện các thao tác tùy ý trên thiết bị.<sup>[[4]](#references)</sup>

Ngoài ra, người ta phát hiện **`/etc/zshenv` có thể được dùng như một kỹ thuật tấn công tổng quát**, không chỉ để bypass SIP. Mỗi hồ sơ người dùng đều có tệp `~/.zshenv`, hoạt động tương tự `/etc/zshenv` nhưng không cần quyền root. Tệp này có thể được dùng làm cơ chế persistence, kích hoạt mỗi khi `zsh` khởi chạy, hoặc làm cơ chế nâng quyền. Nếu người dùng admin nâng quyền lên root bằng `sudo -s` hoặc `sudo <command>`, tệp `~/.zshenv` sẽ được kích hoạt, qua đó nâng quyền lên root.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

Trong [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/), người ta phát hiện tiến trình **`system_installd`** vẫn có thể bị khai thác vì nó đặt **script post-install vào một thư mục có tên ngẫu nhiên được SIP bảo vệ bên trong `/tmp`**. Vấn đề là bản thân **`/tmp` không được SIP bảo vệ**, nên có thể **mount** một **virtual image lên đó**. Sau đó, **installer** sẽ đặt **script post-install** vào đó, **unmount** virtual image, **tạo lại** các **thư mục**, rồi **thêm** script **post-install** chứa **payload** cần thực thi.<sup>[[5]](#references)</sup>

#### [Tiện ích fsck_cs](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Một lỗ hổng được phát hiện khi **`fsck_cs`** bị đánh lừa để làm hỏng một tệp quan trọng do có thể lần theo **symbolic link**. Cụ thể, kẻ tấn công tạo một liên kết từ _`/dev/diskX`_ đến tệp `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Chạy **`fsck_cs`** trên _`/dev/diskX`_ sẽ làm hỏng `Info.plist`. Tính toàn vẹn của tệp này rất quan trọng đối với SIP (System Integrity Protection) của hệ điều hành, cơ chế kiểm soát việc tải kernel extension. Khi tệp bị hỏng, khả năng quản lý các kernel extension bị loại trừ của SIP sẽ bị ảnh hưởng.<sup>[[6]](#references)</sup>

Các lệnh để khai thác lỗ hổng này là:

```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```

Việc khai thác lỗ hổng này gây ra những hậu quả nghiêm trọng. Tệp `Info.plist`, vốn chịu trách nhiệm quản lý quyền cho các kernel extension, trở nên vô hiệu. Điều này bao gồm việc không thể đưa một số extension vào blacklist, chẳng hạn như `AppleHWAccess.kext`. Do cơ chế kiểm soát của SIP bị vô hiệu hóa, extension này có thể được tải, cấp quyền đọc và ghi trái phép vào RAM của hệ thống.<sup>[[6]](#references)</sup>

#### [Mount đè lên các thư mục được SIP bảo vệ](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Có thể mount một hệ thống tệp mới đè lên **các thư mục được SIP bảo vệ để bypass cơ chế bảo vệ**.<sup>[[1]](#references)</sup>

```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```

#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Hệ thống được thiết lập để khởi động từ image đĩa trình cài đặt được nhúng trong `Install macOS Sierra.app` nhằm nâng cấp hệ điều hành, sử dụng tiện ích `bless`. Lệnh được dùng như sau:<sup>[[7]](#references)</sup>

```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```

Tính bảo mật của quy trình này có thể bị xâm phạm nếu kẻ tấn công sửa đổi ảnh nâng cấp (`InstallESD.dmg`) trước khi khởi động. Chiến lược này thay thế dynamic loader (dyld) bằng một phiên bản độc hại (`libBaseIA.dylib`). Việc thay thế này khiến mã của kẻ tấn công được thực thi khi trình cài đặt khởi chạy.<sup>[[7]](#references)</sup>

Mã của kẻ tấn công giành quyền kiểm soát trong quá trình nâng cấp, khai thác sự tin cậy của hệ thống đối với trình cài đặt. Cuộc tấn công tiến hành bằng cách sửa đổi ảnh `InstallESD.dmg` thông qua method swizzling, đặc biệt nhắm vào phương thức `extractBootBits`. Cách này cho phép chèn mã độc trước khi ảnh đĩa được sử dụng.<sup>[[7]](#references)</sup>

Ngoài ra, bên trong `InstallESD.dmg` còn có `BaseSystem.dmg`, đóng vai trò là hệ thống tệp gốc của mã nâng cấp. Chèn một dynamic library vào đây cho phép mã độc hoạt động trong một process có khả năng sửa đổi các tệp cấp OS, làm tăng đáng kể nguy cơ hệ thống bị xâm phạm.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

Trong bài nói chuyện tại [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk), họ trình bày cách **`systemmigrationd`** (có thể bypass SIP) thực thi một script **bash** và một script **perl**. Các script này có thể bị khai thác thông qua các biến môi trường **`BASH_ENV`** và **`PERL5OPT`**.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Như [**được trình bày chi tiết trong bài viết này**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), một script `postinstall` trong các gói `InstallAssistant.pkg` được phép thực thi:<sup>[[9]](#references)</sup>

```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```

và có thể tạo một symlink tại `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, cho phép người dùng **gỡ hạn chế đối với bất kỳ tệp nào, qua mặt cơ chế bảo vệ SIP**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** cho phép qua mặt SIP

Entitlement `com.apple.rootless.install` được biết đến là có thể qua mặt System Integrity Protection (SIP) trên macOS. Điều này được đề cập đáng chú ý liên quan đến [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[[10]](#references)</sup>

Trong trường hợp cụ thể này, dịch vụ XPC của hệ thống tại `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` sở hữu entitlement này. Điều này cho phép tiến trình liên quan vượt qua các ràng buộc của SIP. Hơn nữa, dịch vụ này có một phương thức cho phép di chuyển tệp mà không áp dụng bất kỳ biện pháp bảo mật nào.<sup>[[10]](#references)</sup>

## Sealed System Snapshots

Sealed System Snapshots là một tính năng được Apple giới thiệu trong **macOS Big Sur (macOS 11)** như một phần của cơ chế **System Integrity Protection (SIP)**, nhằm cung cấp thêm một lớp bảo mật và độ ổn định cho hệ thống. Về cơ bản, chúng là các phiên bản chỉ đọc của volume hệ thống.

Dưới đây là giải thích chi tiết hơn:

1. **Hệ thống bất biến**: Sealed System Snapshots khiến volume hệ thống macOS trở nên "bất biến", nghĩa là không thể sửa đổi. Điều này ngăn chặn những thay đổi trái phép hoặc vô tình đối với hệ thống, vốn có thể làm ảnh hưởng đến bảo mật hoặc độ ổn định của hệ thống.
2. **Cập nhật phần mềm hệ thống**: Khi bạn cài đặt bản cập nhật hoặc nâng cấp macOS, macOS tạo một system snapshot mới. Volume khởi động macOS sau đó dùng **APFS (Apple File System)** để chuyển sang snapshot mới này. Toàn bộ quá trình áp dụng bản cập nhật trở nên an toàn và đáng tin cậy hơn, vì hệ thống luôn có thể quay lại snapshot trước đó nếu xảy ra sự cố trong quá trình cập nhật.
3. **Tách biệt dữ liệu**: Kết hợp với khái niệm tách biệt volume Data và System được giới thiệu trong macOS Catalina, tính năng Sealed System Snapshot đảm bảo rằng tất cả dữ liệu và cài đặt của bạn được lưu trên một volume "**Data**" riêng. Việc tách biệt này giúp dữ liệu độc lập với hệ thống, đơn giản hóa quá trình cập nhật hệ thống và tăng cường bảo mật hệ thống.

Hãy nhớ rằng macOS tự động quản lý các snapshot này và chúng không chiếm thêm dung lượng trên đĩa nhờ khả năng chia sẻ dung lượng của APFS. Cũng cần lưu ý rằng các snapshot này khác với **Time Machine snapshots**, vốn là các bản sao lưu toàn bộ hệ thống mà người dùng có thể truy cập.

### Kiểm tra Snapshots

Lệnh **`diskutil apfs list`** liệt kê **thông tin chi tiết về các volume APFS** và cách bố trí của chúng:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
    |   ---------------------------------------------------
    |   APFS Volume Disk (Role):   disk3s5 (Data)
    |   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
    |   FileVault:                 Yes (Unlocked)
</code></pre>

Trong kết quả trên, có thể thấy các **vị trí người dùng có thể truy cập** được gắn kết dưới `/System/Volumes/Data`.

Ngoài ra, **snapshot của volume hệ thống macOS** được gắn kết tại `/` và được **seal** (được hệ điều hành ký bằng mật mã). Vì vậy, nếu SIP bị qua mặt và snapshot này bị sửa đổi, **hệ điều hành sẽ không thể khởi động**.

Cũng có thể **xác minh seal đã được bật** bằng cách chạy:

```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```

Hơn nữa, ổ đĩa snapshot cũng được mount ở chế độ **chỉ đọc**:

```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```

## References

- [1] [SyScan360 - Stefan Esser - OS X El Capitan đang đánh chìm S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Blog Objective-See](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: “Unauthd” (ba) lỗi logic FTW! - Blog Objective-See](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft phát hiện lỗ hổng macOS mới Shrootless có thể bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Phân tích kỹ thuật: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Bảo mật rootless vô ích của Apple bị phá vỡ bởi đoạn code vừa trong một tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Bypass System Integrity Protection của Apple - Blog Objective-See](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Đau đầu - SIP Bypass độc đáo trên MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple giảm thiểu lỗ hổng trong Installer Scripts - Blog Kandji](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: POC cho SIP-Bypass thậm chí còn vừa trong một tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)
{{#include ../../../banners/hacktricks-training.md}}
