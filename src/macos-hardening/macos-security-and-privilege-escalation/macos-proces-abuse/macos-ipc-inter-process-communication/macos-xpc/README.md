# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Основна інформація

XPC — це framework для **комунікації між процесами** у macOS та iOS. Він надає механізми для виконання **безпечних асинхронних викликів між процесами**. XPC підтримує **застосунки з розділеними привілеями**, у яких кожен **компонент** працює **лише з потрібними йому дозволами**, тим самим обмежуючи потенційну шкоду від скомпрометованого процесу.<sup>[[1]](#references)</sup>

XPC використовує форму Inter-Process Communication (IPC) — набір методів, за допомогою яких різні програми, що працюють в одній системі, можуть обмінюватися даними.

Основні переваги XPC:

1. **Безпека**: завдяки розподілу роботи між різними процесами кожному процесу можна надати лише потрібні йому дозволи. Це означає, що навіть у разі компрометації процес матиме обмежені можливості для завдання шкоди.
2. **Стабільність**: XPC допомагає ізолювати аварійне завершення роботи в компоненті, де воно сталося. Якщо процес аварійно завершується, його можна перезапустити без впливу на решту системи.
3. **Продуктивність**: XPC спрощує конкурентне виконання, оскільки різні завдання можуть виконуватися одночасно в різних процесах.

Основним **недоліком** є те, що **поділ застосунку на кілька процесів** і забезпечення їхньої комунікації через XPC створює додаткові накладні витрати. У сучасних системах ці витрати зазвичай невеликі порівняно з перевагами безпеки та стабільності.<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

XPC-компоненти застосунку розташовані **всередині самого застосунку**. Наприклад, у Safari їх можна знайти в **`/Applications/Safari.app/Contents/XPCServices`**. Вони мають розширення **`.xpc`** (наприклад, **`com.apple.Safari.SandboxBroker.xpc`**) і також є **bundle**, що містять основний binary та `Info.plist`. Наприклад: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` і `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**XPC-компонент може мати інші entitlements і привілеї**, ніж інші XPC-компоненти або основний binary застосунку. Винятком є XPC service, налаштований із параметром **`JoinExistingSession`**, встановленим у значення `true` у його файлі **Info.plist**. У цьому випадку XPC service приєднується до **тієї самої security session, що й застосунок**, який його викликав.<sup>[[4]](#references)</sup>

XPC services **запускаються** через **launchd**, коли це необхідно, і можуть бути **завершені**, щойно їхні завдання **виконано**, щоб звільнити системні ресурси. **Application-specific XPC components можуть використовуватися лише застосунком, якому вони належать**, що зменшує exposed-поверхню потенційних вразливостей.<sup>[[2]](#references)</sup>

## System-Wide XPC Services

System-wide XPC services доступні за межами одного застосунку. Ці Mach services, якими керує launchd, мають бути **визначені у plist**-файлах, розташованих у таких каталогах, як **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** або **`/Library/LaunchAgents`**.<sup>[[3]](#references)</sup>

Ці plist-файли містять ключ **`MachServices`** із назвою service і ключ **`Program`** зі шляхом до binary:
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
Сервіси в **`LaunchDaemons`** зазвичай запускаються від імені root. Тому, якщо непривілейований процес може звернутися до вразливого методу, який надає один із цих сервісів, він може підвищити привілеї.

## XPC Objects

- **`xpc_object_t`**

Payloads XPC-запитів і відповідей зазвичай є об’єктами-словниками, що спрощує серіалізацію та десеріалізацію. `libxpc.dylib` також оголошує типи даних, необхідні для перевірки того, що отримані дані мають очікуваний тип. У C API кожен об’єкт є `xpc_object_t` (його тип можна перевірити за допомогою `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Крім того, функцію `xpc_copy_description(object)` можна використовувати для отримання рядкового представлення об’єкта, що може бути корисним для налагодження.\
Ці об’єкти також мають методи на кшталт `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Об’єкти `xpc_object_t` створюються викликом функції `xpc_<objectType>_create`, яка всередині викликає `_xpc_base_create(Class, Size)`, вказуючи клас об’єкта (один із `XPC_TYPE_*`) і розмір. Для метаданих додається ще 40 байтів, тому дані об’єкта починаються зі зміщення 40 байтів.\
Отже, `xpc_<objectType>_t` є своєрідним підкласом `xpc_object_t`, який, своєю чергою, був би підкласом `os_object_t*`.

> [!WARNING]
> Зверніть увагу, що саме розробник має використовувати `xpc_dictionary_[get/set]_<objectType>`, щоб отримувати або встановлювати тип і фактичне значення ключа.

- **`xpc_pipe`**

**`xpc_pipe`** — це FIFO pipe, який процеси можуть використовувати для комунікації (комунікація здійснюється за допомогою Mach-повідомлень).\
Можна створити XPC server, викликавши `xpc_pipe_create()` або `xpc_pipe_create_from_port()`, щоб створити його з використанням певного Mach port. Потім для отримання повідомлень можна викликати `xpc_pipe_receive` і `xpc_pipe_try_receive`.

Зверніть увагу, що об’єкт **`xpc_pipe`** є **`xpc_object_t`**, у структурі якого міститься інформація про два використовувані Mach ports і назву (якщо вона є). Наприклад, daemon `secinitd` у своєму plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` налаштовує pipe під назвою `com.apple.secinitd`.

Прикладом **`xpc_pipe`** є **bootstrap pipe**, створений **`launchd`**, який дає змогу спільно використовувати Mach ports.

- **`NSXPC*`**

Це високорівневі Objective-C objects, які абстрагують XPC connections.\
Крім того, ці objects легше налагоджувати за допомогою DTrace, ніж попередні.

- **`GCD Queues`**

XPC використовує GCD для передавання повідомлень; крім того, він генерує певні dispatch queues, такі як `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Це **bundles із розширенням `.xpc`**, розташовані в папці **`XPCServices`** інших projects; у їхньому `Info.plist` ключ `CFBundlePackageType` має значення **`XPC!`**.\
Цей файл містить інші configuration keys, зокрема `ServiceType`, який може мати значення Application, User або System; `_SandboxProfile`, який може визначати sandbox; і `_AllowedClients`, який може вказувати entitlements або identity, необхідні для звернення до service. Ці та інші options налаштовують service під час його запуску.<sup>[[2]](#references)</sup>

### Starting a Service

App намагається **підключитися** до XPC service за допомогою `xpc_connection_create_mach_service`; після цього launchd знаходить daemon і запускає **`xpcproxy`**. **`xpcproxy`** застосовує налаштовані restrictions і запускає service з наданими file descriptors і Mach ports.<sup>[[3]](#references)</sup>

Щоб пришвидшити пошук XPC service, використовується cache.

Дії `xpcproxy` можна відстежувати за допомогою:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Бібліотека XPC використовує `kdebug` для журналювання дій, викликаючи `xpc_ktrace_pid0` і `xpc_ktrace_pid1`. Коди, які вона використовує, не документовані, тому їх потрібно додати до `/usr/share/misc/trace.codes`. Вони мають префікс `0x29`; наприклад, `0x29000004` — це `XPC_serializer_pack`.\
Утиліта `xpcproxy` використовує префікс `0x22`, наприклад: `0x2200001c: xpcproxy:will_do_preexec`.

## Повідомлення подій XPC

Програми можуть **підписуватися** на різні **повідомлення** про події, що дає змогу **ініціювати їх on-demand**, коли такі події відбуваються. **Налаштування** цих сервісів виконується у **файлах launchd plist**, розташованих у **тих самих каталогах, що й попередні**, і які містять додатковий ключ **`LaunchEvent`**.

### Перевірка процесу, що підключається до XPC

Коли процес намагається викликати метод через XPC-з’єднання, **XPC-сервіс повинен перевірити, чи дозволено цьому процесу підключатися**. Ось поширені методи перевірки та їхні підводні камені:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Авторизація XPC

Apple також дозволяє програмам **налаштовувати права авторизації та спосіб їх отримання викликачами**, щоб процес із необхідними правами **міг викликати метод**, доступний через XPC-сервіс:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Для sniff XPC-повідомлень можна використовувати **xpcspy**, який використовує **Frida**.<sup>[[5]](#references)</sup>
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
## Приклад коду Objective-C для XPC-комунікації

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

Функціональність, яку надає `RemoteXPC.framework` (із `libxpc`), забезпечує XPC-комунікацію між різними хостами.\
Сервіси, що підтримують remote XPC, мають ключ `UsesRemoteXPC` у своєму plist, як у випадку з `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Хоча сервіс зареєстрований у `launchd`, функціональність забезпечують `UserEventAgent` і його плагіни `com.apple.remoted.plugin` та `com.apple.remoteservicediscovery.events.plugin`.

Крім того, `RemoteServiceDiscovery.framework` отримує інформацію з `com.apple.remoted.plugin`, відкриваючи такі функції, як `get_device`, `get_unique_device` і `connect`.

Після того як `connect` повернув дескриптор socket-файлу сервісу, можна використовувати клас `remote_xpc_connection_*`.

Отримати інформацію про remote-сервіси можна за допомогою CLI `/usr/libexec/remotectl`, використовуючи такі команди:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Communication між bridgeOS і host відбувається через виділений IPv6 інтерфейс. `MultiverseSupport.framework` встановлює sockets, чиї file descriptors використовуються для communication.\
Ці communications можна виявити за допомогою `netstat`, `nettop` або open-source альтернативи `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Створення XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
