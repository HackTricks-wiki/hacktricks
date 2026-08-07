# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

XPC, skrót od XNU (jądra używanego przez macOS) inter-Process Communication, to framework służący do **komunikacji między procesami** w macOS i iOS. XPC zapewnia mechanizm wykonywania **bezpiecznych, asynchronicznych wywołań metod między różnymi procesami** w systemie. Jest częścią modelu bezpieczeństwa Apple, umożliwiając **tworzenie aplikacji z separacją uprawnień**, w których każdy **komponent** działa z **tylko tymi uprawnieniami, których potrzebuje** do wykonania swojego zadania, ograniczając tym samym potencjalne szkody wynikające ze skompromitowanego procesu.

XPC korzysta z formy Inter-Process Communication (IPC), czyli zestawu metod umożliwiających różnym programom działającym w tym samym systemie przesyłanie danych w obu kierunkach.

Główne zalety XPC obejmują:

1. **Bezpieczeństwo**: Dzięki podzieleniu pracy na różne procesy każdy proces może otrzymać tylko uprawnienia, których potrzebuje. Oznacza to, że nawet jeśli proces zostanie skompromitowany, jego możliwości wyrządzenia szkód są ograniczone.
2. **Stabilność**: XPC pomaga ograniczyć skutki awarii do komponentu, w którym wystąpiła. Jeśli proces ulegnie awarii, można go ponownie uruchomić bez wpływu na resztę systemu.
3. **Wydajność**: XPC ułatwia współbieżność, ponieważ różne zadania mogą być wykonywane jednocześnie w różnych procesach.

Jedyną **wadą** jest to, że **podzielenie aplikacji na kilka procesów** i komunikowanie ich za pośrednictwem XPC jest **mniej wydajne**. Jednak we współczesnych systemach nie jest to prawie zauważalne, a korzyści są większe.

## Application Specific XPC services

Komponenty XPC aplikacji znajdują się **wewnątrz samej aplikacji**. Na przykład w Safari można je znaleźć w **`/Applications/Safari.app/Contents/XPCServices`**. Mają rozszerzenie **`.xpc`** (np. **`com.apple.Safari.SandboxBroker.xpc`**) i są **również bundle'ami** zawierającymi główny binary: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`, a także `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Jak można się domyślić, **komponent XPC będzie miał inne entitlements i uprawnienia** niż pozostałe komponenty XPC lub główny binary aplikacji. WYJĄTKIEM jest sytuacja, gdy usługa XPC jest skonfigurowana z [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) ustawionym na „True” w pliku **`Info.plist`**. W takim przypadku usługa XPC będzie działać w **tej samej sesji bezpieczeństwa co aplikacja**, która ją wywołała.

Usługi XPC są **uruchamiane** przez **launchd**, gdy są potrzebne, i **wyłączane**, gdy wszystkie zadania zostaną **zakończone**, aby zwolnić zasoby systemowe. **Komponenty XPC specyficzne dla aplikacji mogą być wykorzystywane wyłącznie przez tę aplikację**, co zmniejsza ryzyko związane z potencjalnymi lukami.

## System Wide XPC services

System-wide XPC services są dostępne dla wszystkich użytkowników. Usługi te, typu launchd lub Mach, muszą być **zdefiniowane w plikach plist** znajdujących się w określonych katalogach, takich jak **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** lub **`/Library/LaunchAgents`**.

Pliki plist będą zawierać klucz **`MachServices`** z nazwą usługi oraz klucz **`Program`** ze ścieżką do binary:
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
Te znajdujące się w **`LaunchDameons`** są uruchamiane przez root. Jeśli więc nieuprzywilejowany proces może komunikować się z jednym z nich, może być w stanie eskalować uprawnienia.

## Obiekty XPC

- **`xpc_object_t`**

Każda wiadomość XPC jest obiektem słownikowym, który upraszcza serializację i deserializację. Ponadto `libxpc.dylib` definiuje większość typów danych, dzięki czemu można sprawdzić, czy odebrane dane mają oczekiwany typ. W API C każdy obiekt jest typu `xpc_object_t` (a jego typ można sprawdzić za pomocą `xpc_get_type(object)`).\
Ponadto funkcji `xpc_copy_description(object)` można użyć do uzyskania tekstowej reprezentacji obiektu, która może być przydatna do debugowania.\
Obiekty te mają również metody, takie jak `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Obiekty `xpc_object_t` są tworzone przez wywołanie funkcji `xpc_<objetType>_create`, która wewnętrznie wywołuje `_xpc_base_create(Class, Size)`, gdzie określany jest typ klasy obiektu (jedna z wartości `XPC_TYPE_*`) oraz jego rozmiar (do rozmiaru zostanie dodane dodatkowe 40 B na metadane). Oznacza to, że dane obiektu będą rozpoczynać się od offsetu 40 B.\
Dlatego `xpc_<objectType>_t` jest swego rodzaju podklasą `xpc_object_t`, która z kolei byłaby podklasą `os_object_t*`.

> [!WARNING]
> Należy pamiętać, że to developer powinien używać `xpc_dictionary_[get/set]_<objectType>` do pobierania lub ustawiania typu i rzeczywistej wartości klucza.

- **`xpc_pipe`**

**`xpc_pipe`** to potok FIFO, którego procesy mogą używać do komunikacji (komunikacja wykorzystuje komunikaty Mach).\
Serwer XPC można utworzyć, wywołując `xpc_pipe_create()` lub `xpc_pipe_create_from_port()` w celu utworzenia go przy użyciu określonego portu Mach. Następnie, aby odbierać wiadomości, można wywołać `xpc_pipe_receive` oraz `xpc_pipe_try_receive`.

Należy pamiętać, że obiekt **`xpc_pipe`** jest obiektem **`xpc_object_t`**, którego struktura zawiera informacje o dwóch używanych portach Mach oraz nazwie (jeśli istnieje). Nazwa, na przykład daemon `secinitd` w swoim pliku plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`, konfiguruje potok o nazwie `com.apple.secinitd`.

Przykładem **`xpc_pipe`** jest **bootstrap pipe** utworzony przez **`launchd`**, który umożliwia współdzielenie portów Mach.

- **`NSXPC*`**

Są to wysokopoziomowe obiekty Objective-C umożliwiające abstrakcję połączeń XPC.\
Ponadto łatwiej debugować te obiekty za pomocą DTrace niż poprzednie.

- **`GCD Queues`**

XPC używa GCD do przekazywania wiadomości, a ponadto generuje określone kolejki dispatch, takie jak `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Usługi XPC

Są to **bundles z rozszerzeniem `.xpc`** znajdujące się w folderze **`XPCServices`** innych projektów, które w pliku `Info.plist` mają wartość **`XPC!`** ustawioną dla `CFBundlePackageType`.\
Plik ten zawiera również inne klucze konfiguracyjne, takie jak `ServiceType`, który może przyjmować wartości Application, User lub System, a także `_SandboxProfile`, który może definiować sandbox, oraz `_AllowedClients`, który może wskazywać entitlements lub ID wymagane do kontaktowania się z usługą. Te i inne opcje konfiguracji będą przydatne do konfigurowania usługi podczas jej uruchamiania.

### Uruchamianie usługi

Aplikacja próbuje **połączyć się** z usługą XPC za pomocą `xpc_connection_create_mach_service`, a następnie launchd lokalizuje daemon i uruchamia **`xpcproxy`**. **`xpcproxy`** egzekwuje skonfigurowane ograniczenia i uruchamia usługę z przekazanymi FD oraz portami Mach.

W celu zwiększenia szybkości wyszukiwania usługi XPC używana jest pamięć podręczna.

Działania **`xpcproxy`** można śledzić za pomocą:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Biblioteka XPC używa `kdebug` do logowania działań, wywołując `xpc_ktrace_pid0` i `xpc_ktrace_pid1`. Używane przez nią kody są nieudokumentowane, dlatego należy dodać je do `/usr/share/misc/trace.codes`. Mają prefiks `0x29`, a jednym z przykładów jest `0x29000004`: `XPC_serializer_pack`.\
Narzędzie `xpcproxy` używa prefiksu `0x22`, na przykład: `0x2200001c: xpcproxy:will_do_preexec`.

## Komunikaty zdarzeń XPC

Aplikacje mogą **subskrybować** różne **komunikaty** zdarzeń, umożliwiając ich **uruchamianie na żądanie**, gdy wystąpią takie zdarzenia. **Konfiguracja** tych usług odbywa się w plikach l**aunchd plist files**, znajdujących się w **tych samych katalogach co poprzednie** i zawierających dodatkowy klucz **`LaunchEvent`**.

### Sprawdzanie procesu łączącego się z XPC

Gdy proces próbuje wywołać metodę za pośrednictwem połączenia XPC, **usługa XPC powinna sprawdzić, czy dany proces może się połączyć**. Oto typowe sposoby wykonywania tego sprawdzenia oraz typowe pułapki:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autoryzacja XPC

Apple umożliwia również aplikacjom **konfigurowanie określonych uprawnień oraz sposobu ich uzyskiwania**, aby proces wywołujący, który je posiada, był **uprawniony do wywołania metody** usługi XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Do przechwytywania komunikatów XPC można użyć [**xpcspy**](https://github.com/hot3eed/xpcspy), który korzysta z **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Innym możliwym narzędziem jest [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Przykład komunikacji XPC w kodzie C

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
## Przykład kodu Objective-C komunikacji XPC

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
## Client wewnątrz kodu Dylb
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

Ta funkcjonalność dostarczana przez `RemoteXPC.framework` (z `libxpc`) umożliwia komunikację za pośrednictwem XPC pomiędzy różnymi hostami.\
Usługi obsługujące remote XPC będą miały w swoim pliku plist klucz UsesRemoteXPC, jak ma to miejsce w przypadku `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Jednak mimo że usługa zostanie zarejestrowana przez `launchd`, to `UserEventAgent` wraz z pluginami `com.apple.remoted.plugin` i `com.apple.remoteservicediscovery.events.plugin` zapewnia tę funkcjonalność.

Ponadto `RemoteServiceDiscovery.framework` umożliwia uzyskiwanie informacji z `com.apple.remoted.plugin`, udostępniając funkcje takie jak `get_device`, `get_unique_device`, `connect`...

Po użyciu `connect` i uzyskaniu socketu `fd` usługi można użyć klasy `remote_xpc_connection_*`.

Informacje o zdalnych usługach można uzyskać za pomocą narzędzia CLI `/usr/libexec/remotectl`, używając parametrów takich jak:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Komunikacja między BridgeOS a hostem odbywa się za pośrednictwem dedykowanego interfejsu IPv6. `MultiverseSupport.framework` umożliwia ustanawianie socketów, których `fd` będzie używany do komunikacji.\
Możliwe jest znalezienie tych komunikacji za pomocą `netstat`, `nettop` lub opcji open source, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
