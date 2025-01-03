# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

XPC, co oznacza XNU (jądro używane przez macOS) inter-Process Communication, to framework do **komunikacji między procesami** na macOS i iOS. XPC zapewnia mechanizm do **bezpiecznych, asynchronicznych wywołań metod między różnymi procesami** w systemie. Jest częścią paradygmatu bezpieczeństwa Apple, umożliwiając **tworzenie aplikacji z oddzielonymi uprawnieniami**, gdzie każdy **komponent** działa z **tylko tymi uprawnieniami, które są mu potrzebne** do wykonania swojej pracy, ograniczając w ten sposób potencjalne szkody wynikające z kompromitacji procesu.

XPC używa formy Inter-Process Communication (IPC), która jest zestawem metod dla różnych programów działających w tym samym systemie do przesyłania danych w obie strony.

Główne korzyści z XPC obejmują:

1. **Bezpieczeństwo**: Dzięki oddzieleniu pracy na różne procesy, każdy proces może otrzymać tylko te uprawnienia, które są mu potrzebne. Oznacza to, że nawet jeśli proces zostanie skompromitowany, ma ograniczone możliwości wyrządzenia szkody.
2. **Stabilność**: XPC pomaga izolować awarie do komponentu, w którym występują. Jeśli proces ulegnie awarii, może zostać uruchomiony ponownie bez wpływu na resztę systemu.
3. **Wydajność**: XPC umożliwia łatwą współbieżność, ponieważ różne zadania mogą być wykonywane jednocześnie w różnych procesach.

Jedynym **minusem** jest to, że **oddzielanie aplikacji na kilka procesów** i ich komunikacja za pomocą XPC jest **mniej wydajne**. Jednak w dzisiejszych systemach jest to prawie niezauważalne, a korzyści są lepsze.

## Usługi XPC specyficzne dla aplikacji

Komponenty XPC aplikacji są **wewnątrz samej aplikacji.** Na przykład, w Safari można je znaleźć w **`/Applications/Safari.app/Contents/XPCServices`**. Mają rozszerzenie **`.xpc`** (jak **`com.apple.Safari.SandboxBroker.xpc`**) i są **również pakietami** z głównym binarnym w środku: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` oraz `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Jak możesz pomyśleć, **komponent XPC będzie miał różne uprawnienia i przywileje** niż inne komponenty XPC lub główny plik binarny aplikacji. Z WYJĄTKIEM, gdy usługa XPC jest skonfigurowana z [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) ustawionym na „True” w swoim **pliku Info.plist**. W takim przypadku usługa XPC będzie działać w **tej samej sesji bezpieczeństwa co aplikacja**, która ją wywołała.

Usługi XPC są **uruchamiane** przez **launchd** w razie potrzeby i **zatrzymywane** po zakończeniu wszystkich zadań, aby zwolnić zasoby systemowe. **Specyficzne dla aplikacji komponenty XPC mogą być wykorzystywane tylko przez aplikację**, co zmniejsza ryzyko związane z potencjalnymi lukami.

## Usługi XPC w systemie

Usługi XPC w systemie są dostępne dla wszystkich użytkowników. Te usługi, czy to launchd, czy typu Mach, muszą być **zdefiniowane w plikach plist** znajdujących się w określonych katalogach, takich jak **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, lub **`/Library/LaunchAgents`**.

Te pliki plist będą miały klucz o nazwie **`MachServices`** z nazwą usługi oraz klucz o nazwie **`Program`** z ścieżką do pliku binarnego:
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
Te w **`LaunchDameons`** są uruchamiane przez root. Jeśli więc proces bez uprawnień może komunikować się z jednym z nich, może być w stanie podnieść swoje uprawnienia.

## Obiekty XPC

- **`xpc_object_t`**

Każda wiadomość XPC jest obiektem słownika, który upraszcza serializację i deserializację. Ponadto, `libxpc.dylib` deklaruje większość typów danych, więc możliwe jest upewnienie się, że otrzymane dane są oczekiwanego typu. W API C każdy obiekt jest `xpc_object_t` (a jego typ można sprawdzić za pomocą `xpc_get_type(object)`).\
Ponadto, funkcja `xpc_copy_description(object)` może być używana do uzyskania reprezentacji tekstowej obiektu, co może być przydatne do celów debugowania.\
Te obiekty mają również pewne metody do wywołania, takie jak `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Obiekty `xpc_object_t` są tworzone przez wywołanie funkcji `xpc_<objetType>_create`, która wewnętrznie wywołuje `_xpc_base_create(Class, Size)`, gdzie wskazany jest typ klasy obiektu (jeden z `XPC_TYPE_*`) oraz jego rozmiar (do rozmiaru dodawane jest dodatkowe 40B na metadane). Oznacza to, że dane obiektu będą zaczynać się od przesunięcia 40B.\
Dlatego `xpc_<objectType>_t` jest rodzajem podklasy `xpc_object_t`, która byłaby podklasą `os_object_t*`.

> [!WARNING]
> Należy pamiętać, że to deweloper powinien używać `xpc_dictionary_[get/set]_<objectType>`, aby uzyskać lub ustawić typ i rzeczywistą wartość klucza.

- **`xpc_pipe`**

**`xpc_pipe`** to rura FIFO, którą procesy mogą używać do komunikacji (komunikacja wykorzystuje wiadomości Mach).\
Możliwe jest utworzenie serwera XPC, wywołując `xpc_pipe_create()` lub `xpc_pipe_create_from_port()`, aby utworzyć go za pomocą konkretnego portu Mach. Następnie, aby odbierać wiadomości, można wywołać `xpc_pipe_receive` i `xpc_pipe_try_receive`.

Należy zauważyć, że obiekt **`xpc_pipe`** jest **`xpc_object_t`** z informacjami w swojej strukturze o dwóch używanych portach Mach oraz nazwie (jeśli istnieje). Nazwa, na przykład, demona `secinitd` w jego plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` konfiguruje rurę o nazwie `com.apple.secinitd`.

Przykładem **`xpc_pipe`** jest **bootstrap pipe** utworzona przez **`launchd`**, co umożliwia udostępnianie portów Mach.

- **`NSXPC*`**

To są obiekty wysokiego poziomu Objective-C, które umożliwiają abstrakcję połączeń XPC.\
Ponadto łatwiej jest debugować te obiekty za pomocą DTrace niż poprzednie.

- **`GCD Queues`**

XPC używa GCD do przesyłania wiadomości, ponadto generuje pewne kolejki dyspozycyjne, takie jak `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Usługi XPC

To są **bundles z rozszerzeniem `.xpc`** znajdujące się w folderze **`XPCServices`** innych projektów, a w `Info.plist` mają ustawiony `CFBundlePackageType` na **`XPC!`**.\
Ten plik ma inne klucze konfiguracyjne, takie jak `ServiceType`, które mogą być Application, User, System lub `_SandboxProfile`, które mogą definiować piaskownicę, lub `_AllowedClients`, które mogą wskazywać uprawnienia lub ID wymagane do kontaktu z serwisem. Te i inne opcje konfiguracyjne będą przydatne do skonfigurowania usługi podczas uruchamiania.

### Uruchamianie usługi

Aplikacja próbuje **połączyć się** z usługą XPC, używając `xpc_connection_create_mach_service`, następnie launchd lokalizuje demona i uruchamia **`xpcproxy`**. **`xpcproxy`** egzekwuje skonfigurowane ograniczenia i uruchamia usługę z podanymi FD i portami Mach.

Aby poprawić szybkość wyszukiwania usługi XPC, używana jest pamięć podręczna.

Możliwe jest śledzenie działań `xpcproxy` za pomocą:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Biblioteka XPC używa `kdebug` do rejestrowania działań, wywołując `xpc_ktrace_pid0` i `xpc_ktrace_pid1`. Kody, których używa, są niedokumentowane, więc należy je dodać do `/usr/share/misc/trace.codes`. Mają prefiks `0x29`, a na przykład jeden z nich to `0x29000004`: `XPC_serializer_pack`.\
Narzędzie `xpcproxy` używa prefiksu `0x22`, na przykład: `0x2200001c: xpcproxy:will_do_preexec`.

## Wiadomości Zdarzeń XPC

Aplikacje mogą **subskrybować** różne **wiadomości** zdarzeń, co umożliwia ich **inicjowanie na żądanie**, gdy takie zdarzenia występują. **Konfiguracja** tych usług odbywa się w plikach **launchd plist**, znajdujących się w **tych samych katalogach co poprzednie** i zawierających dodatkowy klucz **`LaunchEvent`**.

### Sprawdzenie Procesu Łączącego XPC

Gdy proces próbuje wywołać metodę za pośrednictwem połączenia XPC, **usługa XPC powinna sprawdzić, czy ten proces ma prawo się połączyć**. Oto powszechne sposoby sprawdzania tego oraz typowe pułapki:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autoryzacja XPC

Apple pozwala również aplikacjom na **konfigurowanie pewnych praw i sposobów ich uzyskania**, więc jeśli wywołujący proces je ma, będzie **mógł wywołać metodę** z usługi XPC:

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Aby podsłuchiwać wiadomości XPC, możesz użyć [**xpcspy**](https://github.com/hot3eed/xpcspy), który wykorzystuje **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Innym możliwym narzędziem do użycia jest [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Przykład kodu C komunikacji XPC

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
## XPC Komunikacja Przykład kodu Objective-C

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
## Klient wewnątrz kodu Dylb
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

Funkcjonalność ta dostarczana przez `RemoteXPC.framework` (z `libxpc`) pozwala na komunikację za pomocą XPC między różnymi hostami.\
Usługi, które obsługują zdalne XPC, będą miały w swoim plist klucz UsesRemoteXPC, jak ma to miejsce w przypadku `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Jednakże, chociaż usługa będzie zarejestrowana w `launchd`, to `UserEventAgent` z wtyczkami `com.apple.remoted.plugin` i `com.apple.remoteservicediscovery.events.plugin` zapewnia tę funkcjonalność.

Ponadto, `RemoteServiceDiscovery.framework` pozwala na uzyskanie informacji z `com.apple.remoted.plugin`, udostępniając funkcje takie jak `get_device`, `get_unique_device`, `connect`...

Gdy `connect` zostanie użyty i gniazdo `fd` usługi zostanie zebrane, możliwe jest użycie klasy `remote_xpc_connection_*`.

Możliwe jest uzyskanie informacji o zdalnych usługach za pomocą narzędzia cli `/usr/libexec/remotectl`, używając parametrów takich jak:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Komunikacja między BridgeOS a hostem odbywa się za pośrednictwem dedykowanego interfejsu IPv6. `MultiverseSupport.framework` umożliwia nawiązywanie gniazd, których `fd` będzie używane do komunikacji.\
Można znaleźć te komunikacje za pomocą `netstat`, `nettop` lub opcji open source, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
