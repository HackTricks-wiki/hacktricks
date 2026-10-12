# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Основна інформація

XPC — це фреймворк для **взаємодії між процесами** в macOS та iOS. Він надає механізми для **безпечних асинхронних викликів між процесами**. XPC підтримує **застосунки з розділенням привілеїв**, у яких кожен **компонент** працює **лише з необхідними йому дозволами**, обмежуючи потенційну шкоду від скомпрометованого процесу.<sup>[[1]](#references)</sup>

XPC використовує різновид міжпроцесної взаємодії (IPC) — набір методів, що дають змогу різним програмам, запущеним в одній системі, обмінюватися даними.

Основні переваги XPC:

1. **Безпека**: розподіл роботи між різними процесами дає змогу надати кожному процесу лише необхідні йому дозволи. Це означає, що навіть у разі компрометації процес матиме обмежені можливості завдати шкоди.
2. **Стабільність**: XPC допомагає локалізувати збої в компоненті, де вони виникають. Якщо процес аварійно завершується, його можна перезапустити, не впливаючи на решту системи.
3. **Продуктивність**: XPC спрощує паралельне виконання, оскільки різні завдання можна виконувати одночасно в різних процесах.

Головний **недолік** полягає в тому, що **поділ застосунку на кілька процесів** і налагодження взаємодії між ними через XPC створює додаткові витрати. У сучасних системах ці витрати зазвичай незначні порівняно з перевагами для безпеки та стабільності.<sup>[[1]](#references)</sup>

## XPC-служби для окремих застосунків

Компоненти XPC застосунку розташовані **всередині самого застосунку**. Наприклад, у Safari їх можна знайти в **`/Applications/Safari.app/Contents/XPCServices`**. Вони мають розширення **`.xpc`** (наприклад, **`com.apple.Safari.SandboxBroker.xpc`**) і також є **пакетами**, що містять основний двійковий файл і `Info.plist`. Наприклад: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` і `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**Компонент XPC може мати інші entitlements і привілеї**, ніж інші компоненти XPC або основний двійковий файл застосунку. Винятком є служба XPC, для якої в **Info.plist** встановлено **`JoinExistingSession`** зі значенням `true`. У такому разі служба XPC приєднується до **того самого сеансу безпеки, що й застосунок**, який її викликав.<sup>[[4]](#references)</sup>

Служби XPC **запускаються** програмою **launchd** за потреби й можуть **завершувати роботу** після **виконання** завдань, щоб звільнити системні ресурси. **Компоненти XPC, специфічні для застосунку, можуть використовуватися лише застосунком, у якому вони містяться**, що зменшує ризик використання потенційних вразливостей.<sup>[[2]](#references)</sup>

## Загальносистемні XPC-служби

На відміну від служб для окремих застосунків, загальносистемні XPC-служби не обмежені застосунком, у якому вони містяться. Залежно від домену launchd і власних перевірок авторизації служби, вони можуть бути доступними клієнтам із кількох облікових записів. Ці Mach-служби, якими керує launchd, потрібно **визначати у файлах plist**, розташованих у каталогах на кшталт **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** або **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Ці файли plist містять ключ **`MachServices`** з назвою служби та ключ **`Program`** зі шляхом до двійкового файлу:

```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Program</key>
	<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
	<key>AbandonProcessGroup</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>com.jamf.management.daemon</string>
	<key>MachServices</key>
	<dict>
		<key>com.jamf.management.daemon.aad</key>
		<true/>
		<key>com.jamf.management.daemon.agent</key>
		<true/>
		<key>com.jamf.management.daemon.binary</key>
		<true/>
		<key>com.jamf.management.daemon.selfservice</key>
		<true/>
		<key>com.jamf.management.daemon.service</key>
		<true/>
	</dict>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
```

Сервіси в **`LaunchDaemons`** зазвичай запускаються від root. Тому, якщо непривілейований процес може викликати вразливий метод, доступний через один із цих сервісів, він може підвищити свої привілеї.

## XPC-об’єкти

- **`xpc_object_t`**

Дані запитів і відповідей XPC зазвичай передаються у вигляді словників, що спрощує серіалізацію та десеріалізацію. `libxpc.dylib` також оголошує типи даних, потрібні для перевірки очікуваного типу отриманих даних. У C API кожен об’єкт має тип `xpc_object_t` (його тип можна перевірити за допомогою `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Крім того, функцію `xpc_copy_description(object)` можна використовувати, щоб отримати рядкове представлення об’єкта, корисне для налагодження.\
Ці об’єкти також мають методи на кшталт `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Об’єкти `xpc_object_t` створюються викликом функції `xpc_<objectType>_create`, яка всередині викликає `_xpc_base_create(Class, Size)`, вказуючи клас об’єкта (один із `XPC_TYPE_*`) і його розмір. Для метаданих додається ще 40 байтів, тому дані об’єкта починаються зі зміщення 40 байтів.\
Отже, `xpc_<objectType>_t` — це свого роду підклас `xpc_object_t`, який, своєю чергою, є підкласом `os_object_t*`.

> [!WARNING]
> Зверніть увагу: саме розробник має використовувати `xpc_dictionary_[get/set]_<objectType>`, щоб отримувати або задавати тип і фактичне значення ключа.

- **`xpc_pipe`**

**`xpc_pipe`** — це FIFO-канал, який процеси можуть використовувати для зв’язку (для обміну даними використовуються Mach-повідомлення).\
XPC-сервер можна створити за допомогою `xpc_pipe_create()` або `xpc_pipe_create_from_port()`, передавши конкретний порт Mach. Потім для отримання повідомлень можна викликати `xpc_pipe_receive` і `xpc_pipe_try_receive`.

Зверніть увагу, що об’єкт **`xpc_pipe`** є об’єктом **`xpc_object_t`**, у структурі якого зберігаються дані про два використовувані порти Mach і назву (якщо вона є). Наприклад, у plist демона `secinitd` — `/System/Library/LaunchDaemons/com.apple.secinitd.plist` — налаштовано канал із назвою `com.apple.secinitd`.

Приклад **`xpc_pipe`** — це **bootstrap-канал**, створений **`launchd`**, який дає змогу спільно використовувати порти Mach.

- **`NSXPC*`**

Це високорівневі об’єкти Objective-C, які абстрагують XPC-з’єднання.\
Крім того, ці об’єкти простіше налагоджувати за допомогою DTrace, ніж попередні.

- **Черги GCD**

XPC використовує GCD для передавання повідомлень, а також створює певні черги диспетчеризації, як-от `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC-сервіси

Це **бандли з розширенням `.xpc`**, розташовані в папці **`XPCServices`** інших проєктів. У файлі `Info.plist` для них задано `CFBundlePackageType` зі значенням **`XPC!`**.\
Цей файл містить й інші ключі конфігурації, як-от `ServiceType`, значенням якого може бути Application, User або System; `_SandboxProfile`, який може визначати sandbox; і `_AllowedClients`, який може вказувати на entitlements або ідентичність, потрібні для зв’язку із сервісом. Ці та інші параметри конфігурують сервіс під час запуску.<sup>[[2]](#references)</sup>

### Запуск сервісу

Програма намагається **підключитися** до XPC-сервісу за допомогою `xpc_connection_create_mach_service`; після цього launchd знаходить демон і запускає **`xpcproxy`**. **`xpcproxy`** застосовує налаштовані обмеження та запускає сервіс із переданими файловими дескрипторами й портами Mach.<sup>[[3]](#references)</sup>

Щоб пришвидшити пошук XPC-сервісу, використовується кеш.

Відстежувати дії `xpcproxy` можна за допомогою:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

Бібліотека XPC використовує `kdebug` для журналювання дій, викликаючи `xpc_ktrace_pid0` і `xpc_ktrace_pid1`. Коди, які вона використовує, не задокументовані, тому їх потрібно додати до `/usr/share/misc/trace.codes`. Вони мають префікс `0x29`; наприклад, `0x29000004` — це `XPC_serializer_pack`.\
Утиліта `xpcproxy` використовує префікс `0x22`, наприклад: `0x2200001c: xpcproxy:will_do_preexec`.

## Аудит XPC-хелперів типу Application

Значення `Application` для `XPCService.ServiceType` — корисна відправна точка для аудиту хелперів, що постачаються з фреймворками: перелічіть пакети, збережіть запущені служби та перевірте ідентифікатор і entitlements хелпера. Шукайте в `/System/Library/Frameworks` і `/System/Library/PrivateFrameworks`; точний перелік змінюється між випусками macOS.<sup>[[7]](#references)</sup>

```bash
find /System/Library/Frameworks /System/Library/PrivateFrameworks \
  -type d -name '*.xpc' -print0 2>/dev/null |
while IFS= read -r -d '' bundle; do
    plist="$bundle/Contents/Info.plist"
    [ "$(plutil -extract XPCService.ServiceType raw -o - "$plist" 2>/dev/null)" = Application ] || continue

    exe=$(plutil -extract CFBundleExecutable raw -o - "$plist" 2>/dev/null) || continue
    bin="$bundle/Contents/MacOS/$exe"
    ps -axo comm= | awk -v b="$bin" '{sub(/^[[:space:]]+/, ""); if ($0==b) found=1} END {exit !found}' || continue

    printf '\n%s\n  id: %s\n' "$bundle" \
      "$(plutil -extract CFBundleIdentifier raw -o - "$plist" 2>/dev/null)"
    codesign -d --entitlements :- "$bundle" 2>&1
done
```

### Виконайте тріаж listener і відновіть мінімальний протокол

Знайдіть `-[<delegate> listener:shouldAcceptNewConnection:]` у helper. Якщо код задає `exportedInterface` і `exportedObject`, відновлює з’єднання та повертає `YES`/`1`, не перевіряючи audit token, code requirement або entitlement клієнта, RPC-інтерфейс стає доступним будь-якому клієнту, який може знайти сервіс. Це доводить лише **досяжність**: для впливу потрібен експортований метод, який виконує привілейовану операцію без належної авторизації для кожного клієнта/методу або небезпечно обробляє контрольовані зловмисником дані.<sup>[[7]](#references)</sup>

Відновіть лише селектори, потрібні для тестування. Метадані селекторів Objective-C показують кількість аргументів; використання аргументів у декомпіляторі зазвичай допомагає уточнити типи (наприклад, значення, передані в `-[EKEvent setStartDate:]` і `setEndDate:`, мають тип `NSDate *`), а непрямий виклик наприкінці методу показує параметри reply-блоку. Для `NSXPCInterface` достатньо часткового локального протоколу; відновлювати весь приватний протокол не потрібно.<sup>[[7]](#references)</sup>

### Підключіться за допомогою відновленого інтерфейсу

Для XPC-сервісу застосунку завантажте будь-який framework, що визначає потрібні приватні класи, створіть з’єднання за допомогою `initWithServiceName:`, призначте відновлений віддалений інтерфейс, установіть обробники помилок, переривання та анулювання, і лише тоді відновіть з’єднання. Для асинхронних відповідей цикл подій має залишатися активним. Повторно запустіть клієнт у застосунку з sandbox під час тестування межі sandbox — успішний запуск окремого клієнта не є доказом обходу sandbox.<sup>[[7]](#references)</sup>

<details>
<summary>Мінімальний клієнт Objective-C</summary>

```objectivec
@protocol RecoveredProtocol
- (void)createEventIntentWithStartDate:(NSDate *)start
                               endDate:(NSDate *)end
                             withReply:(void (^)(id object, id error))reply;
@end

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AppPredictionFoundation.framework"] load];
NSXPCConnection *c = [[NSXPCConnection alloc]
    initWithServiceName:@"com.apple.proactive.AppPredictionIntentsHelperService"];
c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
c.interruptionHandler = ^{ NSLog(@"interrupted"); };
c.invalidationHandler = ^{ NSLog(@"invalidated"); };
[c resume];
id proxy = [c remoteObjectProxyWithErrorHandler:^(NSError *e) { NSLog(@"%@", e); }];
[proxy createEventIntentWithStartDate:[NSDate date]
                              endDate:[NSDate dateWithTimeIntervalSinceNow:3600]
                            withReply:^(id obj, id err) { NSLog(@"%@ %@", obj, err); }];
[[NSRunLoop currentRunLoop] run];
```

Скомпілюйте за допомогою `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Використовуйте помилки secure coding як оракули типів

Помилка `NSCocoaErrorDomain`, наприклад із кодом `4101`, може приховувати корисний виняток серіалізації. Знайдіть у macOS unified log/Console назву сервісу: виняток вказує як на неочікуваний клас, так і на класи, дозволені для аргументу цього селектора. Для відповіді розширте allowlist інтерфейсу **на боці клієнта** за допомогою `setClasses:forSelector:argumentIndex:ofReply:`; якщо `ofReply:YES`, індекс `0` означає перший параметр блоку відповіді, а не перший параметр методу.<sup>[[7]](#references)</sup>

Налаштуйте інтерфейс до того, як призначити його з’єднанню та викликати `[c resume]`:<sup>[[7]](#references)</sup>

```objectivec
NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
NSMutableSet *classes = [NSMutableSet setWithArray:@[
    NSDate.class, NSString.class, NSNumber.class,
    NSDictionary.class, NSArray.class, NSData.class
]];
Class intentClass = NSClassFromString(@"INIntent");
if (intentClass) [classes addObject:intentClass];
[iface setClasses:classes
      forSelector:@selector(createEventIntentWithStartDate:endDate:withReply:)
    argumentIndex:0
          ofReply:YES];
c.remoteObjectInterface = iface;
```

Зворотний випадок теж корисний: якщо сервер відхиляє вхідні дані Foundation і записує в журнал один дозволений приватний клас, із журналу можна дізнатися очікуваний тип у протоколі передачі та його фреймворк. Завантажте цей фреймворк, перегляньте методи/властивості класу, щоб уточнити загальні типи `id`, і динамічно створіть приватний об’єкт. Аргументи `NSInvocation` починаються з індексу `2`, оскільки індекси `0` і `1` — це приховані аргументи `self` і `_cmd`.<sup>[[7]](#references)</sup>

<details>
<summary>Створення приватного аргументу за допомогою NSInvocation</summary>

```objectivec
Class cls = NSClassFromString(@"LNStaticDeferredLocalizedString");
id allocated = [cls alloc];
SEL initializer = NSSelectorFromString(@"initWithKey:table:bundleURL:");
NSMethodSignature *signature = [allocated methodSignatureForSelector:initializer];
NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
[invocation setTarget:allocated];
[invocation setSelector:initializer];

NSString *key = @"KEY";
NSString *table = @"Localizable";
NSURL *bundleURL = NSBundle.mainBundle.bundleURL;
[invocation setArgument:&key atIndex:2];
[invocation setArgument:&table atIndex:3];
[invocation setArgument:&bundleURL atIndex:4];
[invocation invoke];

__unsafe_unretained id privateObject = nil;
[invocation getReturnValue:&privateObject];
```

</details>

Відомості про пов’язаний процес для служб Mach, зареєстрованих у launchd і доступних усій системі, дивіться тут:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## Повідомлення подій XPC

Програми можуть **підписуватися** на різні **повідомлення** про події, завдяки чому їх можна **запускати на вимогу**, коли такі події відбуваються. **Налаштування** цих служб виконується у **файлах launchd plist**, розташованих у **тих самих каталогах, що й попередні файли**, і які містять додатковий ключ **`LaunchEvent`**.

### Перевірка процесу, що підключається до XPC

Коли процес намагається викликати метод через з’єднання XPC, **служба XPC має перевірити, чи дозволено цьому процесу підключатися**. Нижче наведено поширені методи перевірки та їхні недоліки:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Авторизація XPC

Apple також дозволяє програмам **налаштовувати права авторизації та спосіб їх отримання викликачами**, щоб процес із необхідними правами **міг викликати метод**, наданий службою XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Для перехоплення повідомлень XPC можна використовувати **xpcspy**, який працює на базі **Frida**.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Іншим можливим інструментом є **XPoCe2**.<sup>[[6]](#references)</sup>

## Приклад коду C для комунікації XPC

{{#tabs}}
{{#tab name="xpc_server.c"}}

```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        // Print received message
        const char* received_message = xpc_dictionary_get_string(event, "message");
        printf("Received message: %s\n", received_message);

        // Create a response dictionary
        xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(response, "received", "received");

        // Send response
        xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
        xpc_connection_send_message(remote, response);

        // Clean up
        xpc_release(response);
    }
}

static void handle_connection(xpc_connection_t connection) {
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        handle_event(event);
    });
    xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
    xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
                                                                   dispatch_get_main_queue(),
                                                                   XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!service) {
        fprintf(stderr, "Failed to create service.\n");
        exit(EXIT_FAILURE);
    }

    xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_CONNECTION) {
            handle_connection(event);
        }
    });

    xpc_connection_resume(service);
    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xpc_client.c"}}

```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            // Print received message
            const char* received_message = xpc_dictionary_get_string(event, "received");
            printf("Received message: %s\n", received_message);
        }
    });

    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "message", "Hello, Server!");

    xpc_connection_send_message(connection, message);

    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.service.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.service</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save the server in its configured location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```

## Приклад коду Objective-C для комунікації через XPC

{{#tabs}}
{{#tab name="oc_xpc_server.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
    NSLog(@"Received message: %@", some_string);
    NSString *response = @"Received";
    reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

    MyXPCObject *my_object = [MyXPCObject new];

    newConnection.exportedObject = my_object;

    [newConnection resume];
    return YES;
}
@end

int main(void) {

    NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

    id <NSXPCListenerDelegate> delegate = [MyDelegate new];
    listener.delegate = delegate;
    [listener resume];

    sleep(10); // Fake something is done and then it ends
}
```

{{#endtab}}

{{#tab name="oc_xpc_client.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
    [connection resume];

    [[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
        NSLog(@"Received response: %@", response);
    }];

    [[NSRunLoop currentRunLoop] run];

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.svcoc.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.svcoc</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/oc_xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/oc_xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```

## Клієнт усередині Dylib

```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
        NSString*  _serviceName = @"xyz.hacktricks.svcoc";

        NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

        [_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

        [_agentConnection resume];

        [[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
            (void)error;
            NSLog(@"Connection Failure");
        }] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
            NSLog(@"Received response: %@", response);
    }    ];
        NSLog(@"Done!");

    return;
}
```

## Remote XPC

Функціональність, яку надає `RemoteXPC.framework` (із `libxpc`), дає змогу здійснювати XPC-комунікацію між різними хостами.\
Служби, що підтримують remote XPC, мають ключ `UsesRemoteXPC` у своєму plist-файлі, як-от `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Хоча службу зареєстровано в `launchd`, функціональність забезпечують `UserEventAgent` і його плагіни `com.apple.remoted.plugin` та `com.apple.remoteservicediscovery.events.plugin`.

Крім того, `RemoteServiceDiscovery.framework` отримує інформацію з `com.apple.remoted.plugin`, надаючи такі функції, як `get_device`, `get_unique_device` і `connect`.

Після того як `connect` поверне дескриптор сокетного файла служби, можна використовувати клас `remote_xpc_connection_*`.

Інформацію про віддалені служби можна отримати за допомогою CLI `/usr/libexec/remotectl`, використовуючи такі команди:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

Зв’язок між bridgeOS і хостом відбувається через спеціальний IPv6-інтерфейс. `MultiverseSupport.framework` створює сокети, файлові дескриптори яких використовуються для зв’язку.\
Цей трафік можна знайти за допомогою `netstat`, `nettop` або альтернативи з відкритим вихідним кодом `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Архів Apple Developer — Створення служб XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society — Атака на допоміжні XPC-процеси macOS: зворотне проєктування протоколу](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
