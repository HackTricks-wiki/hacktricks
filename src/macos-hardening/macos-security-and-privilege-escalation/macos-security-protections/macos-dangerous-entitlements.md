# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

Entitlements khai báo các khả năng và ngoại lệ bảo mật mà hệ điều hành cấp cho mã đã ký. Các mục bên dưới tập trung vào những entitlement đặc biệt hữu ích khi rà soát bảo mật theo hướng tấn công.<sup>[[13]](#references)</sup>

> [!WARNING]
> Lưu ý rằng các entitlement bắt đầu bằng **`com.apple`** không dành cho bên thứ ba; chỉ Apple mới có thể cấp chúng... Hoặc nếu đang sử dụng chứng chỉ doanh nghiệp, bạn thực sự có thể tự tạo entitlement bắt đầu bằng **`com.apple`** để vượt qua các biện pháp bảo vệ dựa trên entitlement này.

## High

### `com.apple.rootless.install.heritable`

Entitlement **`com.apple.rootless.install.heritable`** cho phép một process **bypass SIP**. Xem [thông tin thêm tại đây](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Entitlement **`com.apple.rootless.install`** cho phép một process **bypass SIP**. Xem [thông tin thêm tại đây](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (trước đây có tên là `task_for_pid-allow`)**

Entitlement này cho phép một process lấy **task port của bất kỳ** process nào, ngoại trừ kernel. Xem [**thông tin thêm tại đây**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Entitlement này cho phép các process khác có entitlement **`com.apple.security.cs.debugger`** lấy task port của process được chạy bởi binary có entitlement này và **inject code vào đó**. Xem [**thông tin thêm tại đây**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Các ứng dụng có Debugging Tool Entitlement có thể gọi `task_for_pid()` để lấy task port hợp lệ của các ứng dụng unsigned và bên thứ ba có `Get Task Allow` được đặt thành `true`. Tuy nhiên, ngay cả khi có debugging tool entitlement, debugger **không thể lấy task port** của các process **không có entitlement `Get Task Allow`**, do đó được System Integrity Protection bảo vệ. Xem [**thông tin thêm tại đây**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Entitlement này cho phép ứng dụng **tải framework, plug-in hoặc library mà không cần chúng được Apple ký hoặc có cùng Team ID** với executable chính, vì vậy attacker có thể lợi dụng việc tải library tùy ý để inject code. Xem [**thông tin thêm tại đây**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Entitlement này rất giống **`com.apple.security.cs.disable-library-validation`**, nhưng **thay vì** **vô hiệu hóa trực tiếp** library validation, nó cho phép process **gọi system call `csops` để vô hiệu hóa tính năng này** khi đang chạy.

Tên entitlement được hardcode trong XNU, ngay cạnh thao tác `csops` sử dụng nó:<sup>[[1]](#references)</sup>

```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```

Bộ xử lý kernel cho `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) cho thấy primitive này bị giới hạn đến mức nào:<sup>[[2]](#references)</sup>

```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
        // We only support dropping library validation on macOS
        error = ENOTSUP;
#else
        if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
                proc_lock(pt);
                if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
                        proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
                        error = 0;
```

Vì vậy, thao tác này:

- Chỉ dành cho **macOS** (`ENOTSUP` trên mọi nền tảng khác).
- Chỉ hoạt động trên chính tiến trình đó (`forself == 1`) — bạn không thể dùng nó để gỡ library validation khỏi tiến trình khác.
- Yêu cầu tiến trình thực sự **có entitlement này**, đồng thời từ chối nếu tiến trình được đánh dấu `CS_INSTALLER` hoặc đang chạy trong đường dẫn root của subsystem.
- Xóa **`CS_REQUIRE_LV | CS_FORCED_LV`** khỏi các cờ code-signing của tiến trình.

Comment trong XNU giải thích trường hợp sử dụng dự kiến, đồng thời cho thấy vì sao điều này đáng chú ý với attacker:

> Tùy chọn này được dùng để gỡ library validation khỏi một tiến trình đang chạy. Tùy chọn này được dùng trong các kiến trúc plugin khi chương trình cần tải các thư viện không đáng tin cậy. [...] Sau khi tiến trình đã tải thư viện không đáng tin cậy, việc dựa vào library validation về sau sẽ không còn hiệu quả.

Nói cách khác, **bất kỳ binary nào có entitlement này đều là mục tiêu dylib-injection**: chạy code bên trong nó (hoặc thuyết phục nó tải plugin của bạn) sau khi nó đã bỏ `CS_REQUIRE_LV`, và bạn sẽ thừa hưởng mọi quyền mà tiến trình host được tin cậy để thực hiện.

### `com.apple.security.cs.allow-dyld-environment-variables`

Entitlement này cho phép **sử dụng các biến môi trường DYLD**, vốn có thể được dùng để inject library và code. Xem [**thông tin chi tiết tại đây**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` hoặc `com.apple.rootless.storage`.`TCC`

[**Theo blog này**](https://objective-see.org/blog/blog_0x4C.html) **và** [**blog này**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), các entitlement này cho phép tiến trình **chỉnh sửa** cơ sở dữ liệu **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### Các quyền Authorization **`system.install.apple-software`** và **`system.install.apple-software.standard-user`**

Các quyền Authorization Services này kiểm soát việc cài đặt phần mềm do Apple cung cấp. Tiến trình được cấp quyền để nhận các quyền này có thể bỏ qua luồng authorization thông thường, điều này có thể hữu ích cho **privilege escalation**.<sup>[[14]](#references)</sup>

### `com.apple.private.security.kext-management`

Entitlement cần thiết để yêu cầu **kernel tải một kernel extension**.

### **`com.apple.private.icloud-account-access`**

Entitlement **`com.apple.private.icloud-account-access`** cho phép giao tiếp với dịch vụ XPC **`com.apple.iCloudHelper`**, dịch vụ này sẽ **cung cấp iCloud token**.

**iMovie** và **Garageband** từng có entitlement này.

Để biết thêm **thông tin** về exploit dùng entitlement này để **lấy iCloud token**, hãy xem bài nói chuyện: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Tôi không biết entitlement này cho phép làm gì

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Báo cáo này**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) đề cập rằng entitlement này có thể được dùng để cập nhật nội dung được SSV bảo vệ sau khi khởi động lại. Nếu bạn biết cách thực hiện, hãy gửi PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Báo cáo tương tự**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) đề cập rằng việc tạo sealed snapshot có thể được dùng để cập nhật nội dung được SSV bảo vệ sau khi khởi động lại. Nếu bạn biết cách thực hiện, hãy gửi PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Danh sách entitlement này liệt kê các nhóm **keychain** mà ứng dụng có quyền truy cập:

```xml
<key>keychain-access-groups</key>
<array>
        <string>ichat</string>
        <string>apple</string>
        <string>appleaccount</string>
        <string>InternetAccounts</string>
        <string>IMCore</string>
</array>
```

### **`kTCCServiceSystemPolicyAllFiles`**

Cấp quyền **Truy cập toàn bộ ổ đĩa**, một trong những quyền cao nhất của TCC.

### **`kTCCServiceAppleEvents`**

Cho phép ứng dụng gửi sự kiện đến các ứng dụng khác thường được dùng để **tự động hóa tác vụ**. Bằng cách kiểm soát các ứng dụng khác, nó có thể lạm dụng những quyền được cấp cho các ứng dụng đó.

Chẳng hạn, khiến chúng yêu cầu người dùng nhập mật khẩu:

```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```

Hoặc khiến chúng thực hiện **các hành động tùy ý**.

### **`kTCCServiceEndpointSecurityClient`**

Cho phép, cùng với các quyền khác, **ghi vào cơ sở dữ liệu TCC của người dùng**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Cho phép **thay đổi** thuộc tính **`NFSHomeDirectory`** của người dùng, làm thay đổi đường dẫn thư mục home của họ và do đó cho phép **bypass TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Cho phép sửa đổi các tệp bên trong app bundle (bên trong app.app), vốn **bị cấm theo mặc định**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

Có thể kiểm tra ứng dụng nào được cấp quyền này trong _System Settings_ > _Privacy & Security_ > _App Management._

### `kTCCServiceAccessibility`

Process có thể **abuse các tính năng trợ năng của macOS**. Điều này có nghĩa là, chẳng hạn, process có thể nhấn các phím. Vì vậy, nó có thể yêu cầu quyền kiểm soát một ứng dụng như Finder rồi dùng quyền này để chấp thuận hộp thoại.

## Các entitlement liên quan đến Trustcache/CDhash

Một số entitlement có thể được dùng để bypass các biện pháp bảo vệ Trustcache/CDhash, vốn ngăn thực thi các phiên bản cũ hơn của binary Apple.

## Trung bình

### `com.apple.security.cs.allow-jit`

Entitlement này cho phép process **tạo vùng nhớ có thể ghi và thực thi** bằng cách truyền cờ `MAP_JIT` cho hàm hệ thống `mmap()`. Xem [**tại đây để biết thêm thông tin**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Entitlement này cho phép **ghi đè hoặc vá mã C**, sử dụng **`NSCreateObjectFileImageFromMemory`** đã bị ngừng hỗ trợ từ lâu (vốn không an toàn về bản chất), hoặc sử dụng framework **DVDPlayback**. Xem [**tại đây để biết thêm thông tin**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Việc đưa entitlement này vào khiến ứng dụng của bạn dễ gặp các lỗ hổng phổ biến trong những ngôn ngữ lập trình không an toàn về bộ nhớ. Hãy cân nhắc kỹ xem ứng dụng có cần ngoại lệ này hay không.

### `com.apple.security.cs.disable-executable-page-protection`

Entitlement này cho phép **sửa đổi các phần trong tệp thực thi của chính ứng dụng trên đĩa** để buộc ứng dụng thoát. Xem [**tại đây để biết thêm thông tin**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> Entitlement Disable Executable Memory Protection là một entitlement cực đoan, loại bỏ một biện pháp bảo vệ an ninh cơ bản khỏi ứng dụng, khiến kẻ tấn công có thể viết lại mã thực thi của ứng dụng mà không bị phát hiện. Nếu có thể, hãy ưu tiên các entitlement có phạm vi hẹp hơn.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Entitlement này cho phép mount hệ thống tệp nullfs (bị cấm theo mặc định). Công cụ: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

Theo bài blog này, quyền TCC này thường có dạng:

```
[Key] com.apple.private.tcc.allow-prompting
	[Value]
		[Array]
			[String] kTCCServiceAll
```

Cho phép tiến trình **yêu cầu tất cả quyền TCC**.

### **`kTCCServicePostEvent`**

Cho phép **inject các sự kiện bàn phím và chuột giả lập** trên toàn hệ thống thông qua `CGEventPost()`. Tiến trình có quyền này có thể giả lập thao tác nhấn phím, nhấp chuột và cuộn trong bất kỳ ứng dụng nào — về cơ bản là **điều khiển từ xa** desktop.

Điều này đặc biệt nguy hiểm khi kết hợp với `kTCCServiceAccessibility` hoặc `kTCCServiceListenEvent`, vì cho phép vừa đọc VỪA inject dữ liệu đầu vào.

```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```

### **`kTCCServiceListenEvent`**

Cho phép **chặn mọi sự kiện bàn phím và chuột** trên toàn hệ thống (theo dõi đầu vào / keylogging). Một tiến trình có thể đăng ký `CGEventTap` để thu thập mọi lần nhấn phím trong bất kỳ ứng dụng nào, bao gồm mật khẩu, số thẻ tín dụng và tin nhắn riêng tư.

Để biết các kỹ thuật khai thác chi tiết, xem:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Cho phép **đọc bộ đệm hiển thị** — chụp ảnh màn hình và quay video màn hình của bất kỳ ứng dụng nào, kể cả các trường văn bản bảo mật. Kết hợp với OCR, quyền này có thể tự động trích xuất mật khẩu và dữ liệu nhạy cảm trên màn hình.

> [!WARNING]
> Kể từ macOS Sonoma, tính năng quay màn hình hiển thị một chỉ báo liên tục trên thanh menu. Trên các phiên bản cũ hơn, có thể quay màn hình hoàn toàn im lặng.

### **`kTCCServiceCamera`**

Cho phép **chụp ảnh và quay video** bằng camera tích hợp hoặc camera USB được kết nối. Chèn code vào một binary có quyền truy cập camera sẽ cho phép giám sát hình ảnh một cách im lặng.

### **`kTCCServiceMicrophone`**

Cho phép **ghi âm** từ mọi thiết bị đầu vào. Các daemon chạy nền có quyền truy cập mic cho phép giám sát âm thanh xung quanh liên tục mà không có cửa sổ ứng dụng hiển thị.

### **`kTCCServiceLocation`**

Cho phép truy vấn **vị trí thực tế** của thiết bị thông qua định vị tam giác Wi-Fi hoặc beacon Bluetooth. Việc giám sát liên tục có thể tiết lộ địa chỉ nhà/nơi làm việc, lịch trình di chuyển và thói quen hằng ngày.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Quyền truy cập vào **Danh bạ** (tên, email, số điện thoại — hữu ích cho spear-phishing), **Lịch** (lịch họp, danh sách người tham dự) và **Ảnh** (ảnh cá nhân, ảnh chụp màn hình có thể chứa thông tin xác thực, siêu dữ liệu vị trí).

Để biết đầy đủ các kỹ thuật khai thác nhằm đánh cắp thông tin xác thực qua quyền TCC, xem:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Quyền Sandbox và Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Các ngoại lệ tạm thời của Sandbox** làm suy yếu App Sandbox bằng cách cho phép giao tiếp với các dịch vụ Mach/XPC trên toàn hệ thống mà sandbox thường chặn. Đây là **cơ chế chính để thoát sandbox** — một ứng dụng sandbox bị xâm nhập có thể dùng các ngoại lệ mach-lookup để tiếp cận daemon có đặc quyền và khai thác các giao diện XPC của chúng.

```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
  binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
  [ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```

For exploitation chain chi tiết: ứng dụng sandbox → ngoại lệ mach-lookup → daemon dễ bị tấn công → sandbox escape, xem:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** cho phép các binary driver trong user space giao tiếp trực tiếp với kernel thông qua các giao diện IOKit. Các binary DriverKit quản lý phần cứng: USB, Thunderbolt, PCIe, thiết bị HID, âm thanh và mạng.

Xâm nhập một binary DriverKit cho phép:
- **Bề mặt tấn công kernel** thông qua các lệnh gọi `IOConnectCallMethod` được tạo sai định dạng
- **Giả mạo thiết bị USB** (mô phỏng bàn phím để HID injection)
- **Tấn công DMA** thông qua các giao diện PCIe/Thunderbolt

```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```

Để xem chi tiết về khai thác IOKit/DriverKit, hãy xem:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## References

- [1] [XNU — `bsd/sys/codesign.h` (các thao tác `CS_OPS_*` và `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (trình xử lý `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement Công cụ gỡ lỗi (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement Tắt Xác thực Thư viện](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement Cho phép Biến Môi trường DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypass TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Phát nhạc và bypass TCC, hay CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "Điều gì xảy ra trên máy Mac của bạn sẽ nằm lại trên iCloud của Apple?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [Cơn ác mộng về bản cập nhật OTA của Apple: Bypass xác minh chữ ký và chiếm quyền Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement Cho phép Thực thi Mã JIT-compiled (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement Cho phép Bộ nhớ Thực thi Không có Chữ ký](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement Tắt Bảo vệ Bộ nhớ Thực thi](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [14] [Apple Developer Archive — Hướng dẫn Lập trình Authorization Services](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/01introduction/introduction.html)
{{#include ../../../banners/hacktricks-training.md}}
