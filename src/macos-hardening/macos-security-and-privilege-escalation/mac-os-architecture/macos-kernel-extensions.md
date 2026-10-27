# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

Kernel extensions (Kexts) là các **package** có phần mở rộng **`.kext`**, được **nạp trực tiếp vào không gian kernel của macOS** để cung cấp chức năng bổ sung cho hệ điều hành chính.

### Trạng thái ngừng hỗ trợ & DriverKit / System Extensions  
Bắt đầu từ **macOS Catalina (10.15)**, Apple đánh dấu hầu hết KPI cũ là *deprecated* và giới thiệu các framework **System Extensions & DriverKit**, chạy trong **user-space**. Từ **macOS Big Sur (11)**, hệ điều hành sẽ *từ chối nạp* kext của bên thứ ba dựa vào KPI đã deprecated, trừ khi máy được khởi động ở chế độ **Reduced Security**. Trên Apple Silicon, để bật kext, người dùng còn phải:

1. Khởi động lại vào **Recovery** → *Startup Security Utility*.
2. Chọn **Reduced Security** và đánh dấu **“Allow user management of kernel extensions from identified developers”**.
3. Khởi động lại và phê duyệt kext trong **System Settings → Privacy & Security**.

Driver ở user-land được viết bằng DriverKit/System Extensions giúp **giảm đáng kể bề mặt tấn công**, vì sự cố hoặc lỗi hỏng bộ nhớ sẽ chỉ nằm trong một tiến trình sandbox thay vì không gian kernel.<sup>[[1]](#references)</sup>  

> 📝 Từ macOS Sequoia (15), Apple đã loại bỏ hoàn toàn một số KPI mạng và USB cũ – giải pháp duy nhất tương thích với các phiên bản tương lai dành cho nhà cung cấp là chuyển sang System Extensions.

### Yêu cầu

Rõ ràng, khả năng này mạnh đến mức **việc nạp kernel extension** khá **phức tạp**. Sau đây là các **yêu cầu** mà kernel extension phải đáp ứng để được nạp:

- Khi **vào chế độ recovery**, phải cho phép nạp **kernel extensions**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Kernel extension phải được **ký bằng chứng chỉ ký mã kernel**, chỉ có thể được **Apple cấp**. Apple sẽ xem xét kỹ công ty và lý do cần đến extension này.
- Kernel extension cũng phải được **notarized** để Apple có thể kiểm tra malware.
- Sau đó, chỉ người dùng **root** mới có thể **nạp kernel extension**, và các tệp bên trong package phải **thuộc sở hữu của root**.
- Trong quá trình tải lên, package phải được chuẩn bị tại một **vị trí không phải root được bảo vệ**: `/Library/StagedExtensions` (yêu cầu grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Cuối cùng, khi cố gắng nạp extension, người dùng sẽ [**nhận được yêu cầu xác nhận**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html). Nếu chấp thuận, máy tính phải được **khởi động lại** để nạp extension.

### Quy trình nạp

Trên Catalina, quy trình diễn ra như sau: Đáng chú ý là quá trình **xác minh** diễn ra trong **userland**. Tuy nhiên, chỉ các ứng dụng có grant **`com.apple.private.security.kext-management`** mới có thể **yêu cầu kernel nạp một extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **khởi chạy** quy trình **xác minh** để nạp extension.
   - Công cụ này sẽ giao tiếp với **`kextd`** thông qua một **Mach service**.
2. **`kextd`** sẽ kiểm tra một số điều, chẳng hạn như **chữ ký**.
   - Công cụ này sẽ giao tiếp với **`syspolicyd`** để **kiểm tra** xem extension có thể được **nạp** hay không.
3. **`syspolicyd`** sẽ **nhắc** **người dùng** nếu extension chưa từng được nạp trước đó.
   - **`syspolicyd`** sẽ báo kết quả cho **`kextd`**.
4. Cuối cùng, **`kextd`** có thể **yêu cầu kernel nạp** extension.

Nếu **`kextd`** không khả dụng, **`kextutil`** có thể thực hiện các bước kiểm tra tương tự.

### Liệt kê & quản lý (kext đã nạp)

`kextstat` từng là công cụ tiêu chuẩn nhưng đã **deprecated** trong các phiên bản macOS gần đây. Giao diện hiện đại là **`kmutil`**:

```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```

Cú pháp cũ vẫn có sẵn để tham khảo:

```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```

`kmutil inspect` cũng có thể được dùng để **dump nội dung của Kernel Collection (KC)** hoặc xác minh rằng một kext phân giải được tất cả các dependency về symbol:

```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```

## Kernelcache

> [!CAUTION]
> Mặc dù các kernel extension được cho là nằm trong `/System/Library/Extensions/`, nếu truy cập thư mục này bạn **sẽ không tìm thấy binary nào**. Đó là vì **kernelcache**; để reverse một `.kext`, bạn cần tìm cách lấy được nó.

**Kernelcache** là **phiên bản kernel XNU đã được biên dịch và liên kết trước**, cùng với các **driver** thiết yếu của thiết bị và **kernel extension**. Nó được lưu trữ ở định dạng **nén** và được giải nén vào bộ nhớ trong quá trình khởi động. Kernelcache giúp **khởi động nhanh hơn** bằng cách có sẵn phiên bản kernel và các driver quan trọng đã sẵn sàng chạy, giảm thời gian và tài nguyên vốn sẽ phải dùng để tải và liên kết động những thành phần này khi khởi động.

Lợi ích chính của kernelcache là **tốc độ tải** và việc tất cả module đã được liên kết trước (không bị cản trở thời gian tải). Ngoài ra, sau khi tất cả module đã được liên kết trước, KXLD có thể được gỡ khỏi bộ nhớ, vì vậy **XNU không thể tải KEXT mới.**

> [!TIP]
> Công cụ [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) giải mã các container AEA của Apple (Apple Encrypted Archive / AEA asset) — định dạng container được mã hóa mà Apple dùng cho các OTA asset và một số thành phần IPSW — và có thể tạo ra file .dmg/asset archive bên trong để bạn giải nén bằng các công cụ aastuff được cung cấp.


### Kernelcache cục bộ
  
Trong iOS, nó nằm tại **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; trong macOS, bạn có thể tìm bằng: **`find / -name "kernelcache" 2>/dev/null`** \
Trong trường hợp của tôi, trên macOS, tôi tìm thấy nó tại:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Xem thêm [**kernelcache của phiên bản 14 có symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### Nén IMG4 / BVX2 (LZFSE)

Định dạng file IMG4 là định dạng container được Apple sử dụng trên các thiết bị iOS và macOS để **lưu trữ và xác minh firmware** một cách an toàn (chẳng hạn như **kernelcache**). Định dạng IMG4 gồm một header và nhiều tag chứa các phần dữ liệu khác nhau, bao gồm payload thực tế (như kernel hoặc bootloader), chữ ký và một tập hợp các thuộc tính manifest. Định dạng này hỗ trợ xác minh bằng mật mã, cho phép thiết bị xác nhận tính xác thực và toàn vẹn của thành phần firmware trước khi thực thi.

Định dạng này thường gồm các thành phần sau:

- **Payload (IM4P)**:
  - Thường được nén (LZFSE4, LZSS, …)
  - Có thể được mã hóa tùy chọn
- **Manifest (IM4M)**:
  - Chứa chữ ký
  - Từ điển Key/Value bổ sung
- **Restore Info (IM4R)**:
  - Còn được gọi là APNonce
  - Ngăn phát lại một số bản cập nhật
  - TÙY CHỌN: Thường không có thành phần này

Giải nén Kernelcache:

```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23 
```

#### Disarm symbols cho kernel

**`Disarm`** cho phép phân giải symbol của các hàm từ kernelcache bằng các matcher. Các matcher này chỉ là những quy tắc mẫu đơn giản (dòng văn bản), hướng dẫn disarm cách nhận diện và tự động phân giải symbol của các hàm, đối số và chuỗi panic/log bên trong binary.

Về cơ bản, bạn chỉ cần chỉ định chuỗi mà một hàm sử dụng, rồi disarm sẽ tìm và **phân giải symbol** của hàm đó.

Bạn có thể tìm một số `xnu.matchers` trong phần **`Matchers`** tại [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html). Bạn cũng có thể tự tạo matcher.

```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```

### Tải xuống

**IPSW (iPhone/iPad Software)** là định dạng gói firmware của Apple, được dùng để khôi phục và cập nhật thiết bị, cũng như cung cấp các gói firmware đầy đủ. Trong đó có **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Tại [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases), bạn có thể tìm thấy tất cả các bộ công cụ debug kernel. Bạn có thể tải xuống, mount, mở bằng công cụ [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), truy cập thư mục **`.kext`** và **extract** thư mục đó.

Kiểm tra symbols bằng lệnh:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Đôi khi Apple phát hành **kernelcache** có **symbols**. Bạn có thể tải một số firmware có symbols theo các liên kết trên những trang đó. Các firmware sẽ chứa **kernelcache** cùng với những tệp khác.

Để **extract** kernel cache, bạn có thể thực hiện:

```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Một cách khác để **trích xuất** các tệp là đổi phần mở rộng từ `.ipsw` thành `.zip`, rồi **giải nén** tệp đó.

Sau khi trích xuất firmware, bạn sẽ nhận được một tệp như: **`kernelcache.release.iphone14`**. Tệp này ở định dạng **IMG4**. Bạn có thể trích xuất thông tin đáng chú ý bằng:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

### Kiểm tra kernelcache

Kiểm tra xem kernelcache có symbol hay không bằng cách dùng

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

Nhờ vậy, giờ đây chúng ta có thể **trích xuất tất cả các extension** hoặc **extension mà bạn quan tâm:**

```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Các lỗ hổng gần đây & kỹ thuật khai thác

| Năm | CVE | Tóm tắt |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Lỗi logic trong **`storagekitd`** cho phép kẻ tấn công có quyền *root* đăng ký một bundle hệ thống tệp độc hại, cuối cùng tải một **kext chưa được ký**, **vượt qua System Integrity Protection (SIP)** và cho phép cài rootkit tồn tại lâu dài. Đã được vá trong macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Daemon cài đặt có entitlement `com.apple.rootless.install` có thể bị lạm dụng để thực thi các script sau khi cài đặt tùy ý, vô hiệu hóa SIP và tải các kext tùy ý. <sup>[[3]](#references)</sup> |

**Điểm cần lưu ý cho red team**

1. **Tìm các daemon có entitlement (`codesign -dvv /path/bin | grep entitlements`) tương tác với Disk Arbitration, Installer hoặc Kext Management.**  
2. **Lạm dụng các lỗ hổng bypass SIP hầu như luôn cho phép tải kext → thực thi mã trong kernel**.

**Mẹo phòng thủ**

*Bật SIP*, theo dõi các lệnh `kmutil load`/`kmutil create -n aux` được gọi từ các binary không thuộc Apple và cảnh báo khi có thao tác ghi vào `/Library/Extensions`. Các sự kiện Endpoint Security `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` cung cấp khả năng quan sát gần như theo thời gian thực.

## Gỡ lỗi kernel & kext trên macOS

Quy trình được Apple khuyến nghị là tạo **Kernel Debug Kit (KDK)** khớp với bản build đang chạy, sau đó kết nối **LLDB** qua phiên mạng **KDP (Kernel Debugging Protocol)**.

### Gỡ lỗi cục bộ một lần khi xảy ra panic

```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Gỡ lỗi từ xa trực tiếp từ một máy Mac khác

1. Tải xuống và cài đặt đúng phiên bản **KDK** dành cho máy đích.
2. Kết nối máy Mac đích với máy Mac chủ bằng **cáp USB-C hoặc Thunderbolt**.
3. Trên **máy đích**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. Trên **máy chủ**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```

### Gắn LLDB vào một kext cụ thể đã được tải

```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️ KDP chỉ cung cấp **giao diện chỉ đọc**. Để dynamic instrumentation, bạn cần patch binary trên ổ đĩa, tận dụng **kernel function hooking** (ví dụ: `mach_override`) hoặc chuyển driver sang **hypervisor** để có đầy đủ khả năng đọc/ghi.

## References

- [1] [Bảo mật DriverKit cho macOS - Hướng dẫn Bảo mật Nền tảng Apple](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Phân tích CVE-2024-44243, một cách bypass System Integrity Protection trên macOS thông qua kernel extensions - Blog Bảo mật Microsoft](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft phát hiện lỗ hổng macOS mới, Shrootless, có thể bypass System Integrity Protection - Blog Bảo mật Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
{{#include ../../../banners/hacktricks-training.md}}
