# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Основна інформація

XPC, що розшифровується як XNU (ядро, яке використовується macOS) inter-Process Communication, — це framework для **комунікації між процесами** у macOS та iOS. XPC надає механізм для виконання **безпечних асинхронних викликів методів між різними процесами** в системі. Це частина security paradigm Apple, яка дозволяє **створювати applications із розділеними привілеями**, де кожен **компонент** працює **лише з дозволами, необхідними** для виконання своєї роботи, тим самим обмежуючи потенційну шкоду від скомпрометованого процесу.

XPC використовує форму Inter-Process Communication (IPC) — набір методів, за допомогою яких різні програми, що працюють в одній системі, можуть обмінюватися даними.

Основні переваги XPC:

1. **Безпека**: Завдяки розподілу роботи між різними процесами кожному процесу можна надати лише необхідні дозволи. Це означає, що навіть у разі компрометації процесу його можливість завдати шкоди буде обмеженою.
2. **Стабільність**: XPC допомагає ізолювати збої в компоненті, де вони виникають. Якщо процес аварійно завершується, його можна перезапустити, не впливаючи на решту системи.
3. **Продуктивність**: XPC спрощує concurrency, оскільки різні завдання можуть одночасно виконуватися в різних процесах.

Єдиним **недоліком** є те, що **розділення application на кілька процесів** і забезпечення їхньої комунікації через XPC є **менш ефективним**. Однак у сучасних системах це майже непомітно, а переваги є вагомішими.

## Application Specific XPC services

XPC-компоненти application розташовані **всередині самої application.** Наприклад, у Safari їх можна знайти в **`/Applications/Safari.app/Contents/XPCServices`**. Вони мають розширення **`.xpc`** (наприклад, **`com.apple.Safari.SandboxBroker.xpc`**) і також є **bundles** з основним binary всередині: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`, а також `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Як ви могли здогадатися, **XPC component матиме інші entitlements та privileges**, ніж інші XPC components або основний binary application. ВИНЯТОК — якщо XPC service налаштований із [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession), встановленим у значення “True” у його файлі **Info.plist**. У такому разі XPC service працюватиме в **тій самій security session, що й application**, яка його викликала.

XPC services **запускаються** через **launchd**, коли це необхідно, і **завершують роботу**, щойно всі завдання **виконано**, щоб звільнити системні ресурси. **Application-specific XPC components можуть використовуватися лише application**, що зменшує ризик, пов’язаний із потенційними вразливостями.

## System Wide XPC services

System-wide XPC services доступні всім користувачам. Ці services, незалежно від того, чи є вони launchd- або Mach-type, мають бути **визначені у plist**-файлах, розташованих у спеціальних директоріях, таких як **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** або **`/Library/LaunchAgents`**.

Ці plist-файли міститимуть ключ **`MachServices`** з назвою service і ключ **`Program`** зі шляхом до binary:
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
Ті, що знаходяться в **`LaunchDameons`**, запускаються від імені root. Тому якщо непривілейований process може взаємодіяти з одним із них, він може отримати можливість підвищити привілеї.

## XPC Objects

- **`xpc_object_t`**

Кожне XPC-повідомлення є об'єктом-словником, що спрощує серіалізацію та десеріалізацію. Крім того, `libxpc.dylib` оголошує більшість типів даних, тому можна перевірити, що отримані дані мають очікуваний тип. У C API кожен об'єкт є `xpc_object_t` (його тип можна перевірити за допомогою `xpc_get_type(object)`).\
Крім того, функцію `xpc_copy_description(object)` можна використати для отримання рядкового представлення об'єкта, що може бути корисним для debugging.\
Ці об'єкти також мають методи для виклику, як-от `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` створюються викликом функції `xpc_<objetType>_create`, яка всередині викликає `_xpc_base_create(Class, Size)`, де вказуються тип класу об'єкта (один із `XPC_TYPE_*`) і його розмір (до розміру буде додано ще 40B для metadata). Це означає, що дані об'єкта починатимуться зі зміщення 40B.\
Отже, `xpc_<objectType>_t` є своєрідним підкласом `xpc_object_t`, який, своєю чергою, був би підкласом `os_object_t*`.

> [!WARNING]
> Зверніть увагу, що саме developer має використовувати `xpc_dictionary_[get/set]_<objectType>`, щоб отримувати або встановлювати тип і фактичне значення ключа.

- **`xpc_pipe`**

**`xpc_pipe`** — це FIFO pipe, який processes можуть використовувати для взаємодії (для комунікації використовуються Mach-повідомлення).\
XPC server можна створити викликом `xpc_pipe_create()` або `xpc_pipe_create_from_port()`, щоб створити його з використанням певного Mach port. Потім для отримання повідомлень можна викликати `xpc_pipe_receive` і `xpc_pipe_try_receive`.

Зверніть увагу, що об'єкт **`xpc_pipe`** є **`xpc_object_t`**, у структурі якого міститься інформація про два використані Mach ports і name (якщо він є). Наприклад, daemon `secinitd` у своєму plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` налаштовує pipe під назвою `com.apple.secinitd`.

Прикладом **`xpc_pipe`** є **bootstrap pipe**, створений **`launchd`**, що дає змогу спільно використовувати Mach ports.

- **`NSXPC*`**

Це high-level Objective-C objects, які абстрагують XPC connections.\
Крім того, ці objects легше debugging за допомогою DTrace, ніж попередні.

- **`GCD Queues`**

XPC використовує GCD для передавання повідомлень, а також генерує певні dispatch queues, як-от `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Це **bundles із розширенням `.xpc`**, розташовані в папці **`XPCServices`** інших проєктів, у яких у `Info.plist` параметр `CFBundlePackageType` має значення **`XPC!`**.\
Цей файл містить інші configuration keys, як-от `ServiceType`, який може мати значення Application, User або System, чи `_SandboxProfile`, який може визначати sandbox, або `_AllowedClients`, що може вказувати entitlements чи ID, необхідні для взаємодії із service. Ці та інші configuration options будуть корисними для налаштування service під час запуску.

### Starting a Service

App намагається **підключитися** до XPC service за допомогою `xpc_connection_create_mach_service`, після чого launchd знаходить daemon і запускає **`xpcproxy`**. **`xpcproxy`** застосовує налаштовані restrictions і запускає service із наданими FDs та Mach ports.

Для пришвидшення пошуку XPC service використовується cache.

Дії `xpcproxy` можна відстежувати за допомогою:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Бібліотека XPC використовує `kdebug` для журналювання дій, викликаючи `xpc_ktrace_pid0` і `xpc_ktrace_pid1`. Коди, які вона використовує, не документовані, тому їх потрібно додати до `/usr/share/misc/trace.codes`. Вони мають префікс `0x29`; наприклад, `0x29000004`: `XPC_serializer_pack`.\
Утиліта `xpcproxy` використовує префікс `0x22`, наприклад: `0x2200001c: xpcproxy:will_do_preexec`.

## Повідомлення подій XPC

Програми можуть **підписуватися** на різні **повідомлення подій**, що дає змогу **запускати їх на вимогу**, коли такі події відбуваються. **Налаштування** цих служб виконується у l**файлах plist launchd**, розташованих у **тих самих каталогах, що й попередні**, і які містять додатковий ключ **`LaunchEvent`**.

### Перевірка процесу, що підключається до XPC

Коли процес намагається викликати метод через XPC connection, **служба XPC повинна перевірити, чи дозволено цьому процесу підключатися**. Нижче наведені поширені способи виконання цієї перевірки та типові помилки:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Авторизація XPC

Apple також дозволяє програмам **налаштовувати певні права та спосіб їх отримання**, щоб процес, який викликає метод, **міг викликати метод** служби XPC, якщо він має ці права:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Для перехоплення XPC messages можна використати [**xpcspy**](https://github.com/hot3eed/xpcspy), який використовує **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Ще одним можливим інструментом для використання є [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Приклад коду C для XPC Communication

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

# Save server on it's location
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
## Приклад коду XPC Communication Objective-C

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
## Client усередині коду Dylb
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

Ця функціональність, яку надає `RemoteXPC.framework` (з `libxpc`), дозволяє обмінюватися даними через XPC між різними хостами.\
Сервіси, що підтримують remote XPC, матимуть у своєму plist ключ UsesRemoteXPC, як у випадку `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Однак, хоча сервіс буде зареєстрований у `launchd`, саме `UserEventAgent` з плагінами `com.apple.remoted.plugin` і `com.apple.remoteservicediscovery.events.plugin` забезпечує цю функціональність.

Крім того, `RemoteServiceDiscovery.framework` дозволяє отримувати інформацію від `com.apple.remoted.plugin`, відкриваючи такі функції, як `get_device`, `get_unique_device`, `connect`...

Після використання `connect` і отримання socket `fd` сервісу можна використовувати клас `remote_xpc_connection_*`.

Інформацію про remote services можна отримати за допомогою cli tool `/usr/libexec/remotectl`, використовуючи такі параметри:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Комунікація між BridgeOS і host відбувається через виділений IPv6-інтерфейс. `MultiverseSupport.framework` дає змогу встановлювати сокети, чиї `fd` використовуватимуться для комунікації.\
Ці комунікації можна знайти за допомогою `netstat`, `nettop` або open source-варіанта `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
