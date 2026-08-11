# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

XPC to framework służący do **komunikacji między procesami** w systemach macOS i iOS. Udostępnia mechanizmy umożliwiające wykonywanie **bezpiecznych, asynchronicznych wywołań między procesami**. XPC obsługuje **aplikacje z separacją uprawnień**, w których każdy **komponent** działa z **tylko tymi uprawnieniami, których potrzebuje**, ograniczając tym samym potencjalne szkody wynikające z przejęcia procesu.<sup>[[1]](#references)</sup>

XPC wykorzystuje formę Inter-Process Communication (IPC), czyli zestaw metod umożliwiających różnym programom działającym w tym samym systemie wzajemne przesyłanie danych.

Główne zalety XPC to:

1. **Bezpieczeństwo**: Dzięki podzieleniu pracy na różne procesy każdemu procesowi można przyznać tylko potrzebne mu uprawnienia. Oznacza to, że nawet po przejęciu procesu jego możliwości wyrządzenia szkód są ograniczone.
2. **Stabilność**: XPC pomaga ograniczyć skutki awarii do komponentu, w którym wystąpiła. Jeśli proces ulegnie awarii, można go uruchomić ponownie bez wpływu na resztę systemu.
3. **Wydajność**: XPC ułatwia współbieżność, ponieważ różne zadania mogą być wykonywane jednocześnie w różnych procesach.

Główną **wadą** jest to, że **podzielenie aplikacji na kilka procesów** i umożliwienie im komunikacji za pośrednictwem XPC powoduje dodatkowy narzut. We współczesnych systemach narzut ten jest zwykle niewielki w porównaniu z korzyściami dotyczącymi bezpieczeństwa i stabilności.<sup>[[1]](#references)</sup>

## Usługi XPC specyficzne dla aplikacji

Komponenty XPC aplikacji znajdują się **wewnątrz samej aplikacji**. Na przykład w Safari można je znaleźć w **`/Applications/Safari.app/Contents/XPCServices`**. Mają rozszerzenie **`.xpc`** (np. **`com.apple.Safari.SandboxBroker.xpc`**) i również są **bundle**, zawierającymi główny plik binarny oraz `Info.plist`. Na przykład: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` oraz `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**Komponent XPC może mieć inne entitlements i uprawnienia** niż pozostałe komponenty XPC lub główny plik binarny aplikacji. Wyjątkiem jest usługa XPC skonfigurowana z ustawieniem **`JoinExistingSession`** na wartość `true` w pliku **Info.plist**. W takim przypadku usługa XPC dołącza do **tej samej sesji bezpieczeństwa co aplikacja**, która ją wywołała.<sup>[[4]](#references)</sup>

Usługi XPC są **uruchamiane** przez **launchd** w razie potrzeby i mogą zostać **wyłączone**, gdy ich zadania zostaną **ukończone**, aby zwolnić zasoby systemowe. **Komponenty XPC specyficzne dla aplikacji mogą być używane tylko przez aplikację, w której się znajdują**, co ogranicza możliwość wykorzystania potencjalnych podatności.<sup>[[2]](#references)</sup>

## Usługi XPC obejmujące cały system

W przeciwieństwie do usług specyficznych dla aplikacji usługi XPC obejmujące cały system nie są ograniczone do aplikacji, w której się znajdują. Mogą być dostępne dla klientów z wielu użytkowników, zależnie od domeny launchd i własnych mechanizmów kontroli autoryzacji usługi. Te zarządzane przez launchd usługi Mach muszą być **zdefiniowane w plikach plist** znajdujących się w katalogach takich jak **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** lub **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Te pliki plist zawierają klucz **`MachServices`** z nazwą usługi oraz klucz **`Program`** ze ścieżką do pliku binarnego:
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
Usługi w **`LaunchDaemons`** często działają jako root. Dlatego jeśli nieuprzywilejowany proces może uzyskać dostęp do podatnej metody udostępnianej przez jedną z tych usług, może być w stanie eskalować uprawnienia.

## Obiekty XPC

- **`xpc_object_t`**

Payloady żądań i odpowiedzi XPC są zazwyczaj obiektami typu dictionary, co upraszcza serializację i deserializację. `libxpc.dylib` deklaruje również typy danych potrzebne do sprawdzenia, czy odebrane dane mają oczekiwany typ. W C API każdy obiekt jest typu `xpc_object_t` (a jego typ można sprawdzić za pomocą `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Ponadto funkcja `xpc_copy_description(object)` może być używana do uzyskania tekstowej reprezentacji obiektu, która może być przydatna do debugowania.\
Obiekty te mają również metody, takie jak `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Obiekty `xpc_object_t` są tworzone przez wywołanie funkcji `xpc_<objectType>_create`, która wewnętrznie wywołuje `_xpc_base_create(Class, Size)`, wskazując klasę obiektu (jedną z `XPC_TYPE_*`) oraz jego rozmiar. Na metadane dodawane jest dodatkowe 40 bajtów, dlatego dane obiektu zaczynają się od offsetu wynoszącego 40 bajtów.\
Dlatego `xpc_<objectType>_t` jest czymś w rodzaju podklasy `xpc_object_t`, która byłaby podklasą `os_object_t*`.

> [!WARNING]
> Należy pamiętać, że to developer powinien używać `xpc_dictionary_[get/set]_<objectType>` do pobierania lub ustawiania typu i rzeczywistej wartości klucza.

- **`xpc_pipe`**

**`xpc_pipe`** to potok FIFO, którego procesy mogą używać do komunikacji (komunikacja wykorzystuje komunikaty Mach).\
Można utworzyć serwer XPC, wywołując `xpc_pipe_create()` lub `xpc_pipe_create_from_port()`, aby utworzyć go przy użyciu określonego portu Mach. Następnie do odbierania komunikatów można wywołać `xpc_pipe_receive` oraz `xpc_pipe_try_receive`.

Należy pamiętać, że obiekt **`xpc_pipe`** jest obiektem **`xpc_object_t`** zawierającym w swojej strukturze informacje o dwóch używanych portach Mach oraz nazwie (jeśli istnieje). Nazwa jest na przykład konfigurowana przez daemon `secinitd` w jego pliku plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`; pipe nosi nazwę `com.apple.secinitd`.

Przykładem **`xpc_pipe`** jest **bootstrap pipe** tworzony przez **`launchd`**, który umożliwia współdzielenie portów Mach.

- **`NSXPC*`**

Są to wysokopoziomowe obiekty Objective-C abstrakcjonujące połączenia XPC.\
Ponadto debugowanie tych obiektów za pomocą DTrace jest łatwiejsze niż w przypadku poprzednich.

- **`GCD Queues`**

XPC używa GCD do przekazywania komunikatów, a ponadto generuje określone kolejki dispatch, takie jak `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Usługi XPC

Są to **pakiety z rozszerzeniem `.xpc`** znajdujące się w folderze **`XPCServices`** innych projektów; w pliku `Info.plist` mają ustawioną wartość `CFBundlePackageType` na **`XPC!`**.\
Plik ten zawiera również inne klucze konfiguracyjne, takie jak `ServiceType`, który może przyjmować wartość Application, User lub System; `_SandboxProfile`, który może definiować sandbox; oraz `_AllowedClients`, który może wskazywać entitlements lub tożsamość wymaganą do skontaktowania się z usługą. Te i inne opcje konfigurują usługę podczas jej uruchamiania.<sup>[[2]](#references)</sup>

### Uruchamianie usługi

Aplikacja próbuje **połączyć się** z usługą XPC za pomocą `xpc_connection_create_mach_service`; następnie launchd lokalizuje daemon i uruchamia **`xpcproxy`**. **`xpcproxy`** egzekwuje skonfigurowane ograniczenia i uruchamia usługę z dostarczonymi deskryptorami plików oraz portami Mach.<sup>[[3]](#references)</sup>

Aby przyspieszyć wyszukiwanie usługi XPC, używana jest pamięć podręczna.

Działania `xpcproxy` można śledzić za pomocą:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Biblioteka XPC używa `kdebug` do rejestrowania działań, wywołując `xpc_ktrace_pid0` i `xpc_ktrace_pid1`. Używane przez nią kody nie są udokumentowane, dlatego należy dodać je do `/usr/share/misc/trace.codes`. Mają prefiks `0x29`; na przykład `0x29000004` to `XPC_serializer_pack`.\
Narzędzie `xpcproxy` używa prefiksu `0x22`, na przykład: `0x2200001c: xpcproxy:will_do_preexec`.

## Komunikaty zdarzeń XPC

Aplikacje mogą **subskrybować** różne **komunikaty** zdarzeń, dzięki czemu mogą być **uruchamiane na żądanie**, gdy takie zdarzenia wystąpią. **Konfiguracja** tych usług znajduje się w **plikach plist launchd**, umieszczonych w **tych samych katalogach co poprzednie** i zawierających dodatkowy klucz **`LaunchEvent`**.

### Sprawdzanie procesu łączącego się z XPC

Gdy proces próbuje wywołać metodę za pośrednictwem połączenia XPC, **usługa XPC powinna sprawdzić, czy ten proces może się połączyć**. Oto typowe metody weryfikacji oraz związane z nimi problemy:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autoryzacja XPC

Apple umożliwia również aplikacjom **konfigurowanie uprawnień autoryzacyjnych oraz sposobu ich uzyskiwania przez wywołujących**, dzięki czemu proces posiadający wymagane uprawnienia **może wywołać metodę** udostępnianą przez usługę XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Do sniffowania komunikatów XPC można użyć **xpcspy**, który korzysta z **Frida**.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Innym możliwym narzędziem jest **XPoCe2**.<sup>[[6]](#references)</sup>

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
## Przykład kodu komunikacji XPC w Objective-C

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
## Klient wewnątrz Dylib
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

Funkcjonalność udostępniana przez `RemoteXPC.framework` (z `libxpc`) umożliwia komunikację XPC między różnymi hostami.\
Usługi obsługujące remote XPC mają klucz `UsesRemoteXPC` w swoim pliku plist, tak jak `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Chociaż usługa jest zarejestrowana w `launchd`, funkcjonalność zapewniają `UserEventAgent` oraz jego pluginy `com.apple.remoted.plugin` i `com.apple.remoteservicediscovery.events.plugin`.

Ponadto `RemoteServiceDiscovery.framework` uzyskuje informacje z `com.apple.remoted.plugin`, udostępniając funkcje takie jak `get_device`, `get_unique_device` i `connect`.

Po zwróceniu przez `connect` deskryptora pliku socketu usługi możliwe jest użycie klasy `remote_xpc_connection_*`.

Informacje o usługach zdalnych można uzyskać za pomocą CLI `/usr/libexec/remotectl`, używając poleceń takich jak:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Komunikacja między bridgeOS a hostem odbywa się za pośrednictwem dedykowanego interfejsu IPv6. `MultiverseSupport.framework` ustanawia sockets, których file descriptors są używane do komunikacji.\
Te komunikacje można znaleźć za pomocą `netstat`, `nettop` lub open-source’owej alternatywy `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Archiwum Apple Developer — Tworzenie usług XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
