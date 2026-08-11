# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

XPC ist ein Framework für die **Kommunikation zwischen Prozessen** unter macOS und iOS. Es bietet Mechanismen für **sichere, asynchrone Aufrufe zwischen Prozessen**. XPC unterstützt **privilege-separated applications**, bei denen jede **Komponente** mit **nur den benötigten Berechtigungen** ausgeführt wird, wodurch der potenzielle Schaden durch einen kompromittierten Prozess begrenzt wird.<sup>[[1]](#references)</sup>

XPC verwendet eine Form der Inter-Process Communication (IPC), eine Reihe von Methoden, mit denen verschiedene Programme, die auf demselben System ausgeführt werden, Daten senden und empfangen können.

Zu den wichtigsten Vorteilen von XPC gehören:

1. **Sicherheit**: Durch die Aufteilung der Arbeit auf verschiedene Prozesse kann jedem Prozess nur die benötigte Berechtigung gewährt werden. Das bedeutet, dass ein kompromittierter Prozess nur begrenzte Möglichkeiten hat, Schaden anzurichten.
2. **Stabilität**: XPC hilft dabei, Abstürze auf die Komponente zu begrenzen, in der sie auftreten. Wenn ein Prozess abstürzt, kann er neu gestartet werden, ohne den Rest des Systems zu beeinträchtigen.
3. **Performance**: XPC ermöglicht eine einfache Nebenläufigkeit, da verschiedene Aufgaben gleichzeitig in unterschiedlichen Prozessen ausgeführt werden können.

Der größte **Nachteil** besteht darin, dass die **Aufteilung einer Anwendung in mehrere Prozesse** und deren Kommunikation über XPC zusätzlichen Overhead verursacht. Auf modernen Systemen ist dieser Overhead im Vergleich zu den Vorteilen hinsichtlich Sicherheit und Stabilität normalerweise gering.<sup>[[1]](#references)</sup>

## Anwendungsspezifische XPC Services

Die XPC-Komponenten einer Anwendung befinden sich **innerhalb der Anwendung selbst**. In Safari sind sie beispielsweise unter **`/Applications/Safari.app/Contents/XPCServices`** zu finden. Sie haben die Erweiterung **`.xpc`** (wie **`com.apple.Safari.SandboxBroker.xpc`**) und sind ebenfalls **Bundles** mit der Haupt-Binärdatei und einer `Info.plist` darin. Beispiele: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` und `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Eine **XPC-Komponente kann andere Entitlements und Privilegien** als andere XPC-Komponenten oder die Binärdatei der Hauptanwendung besitzen. Eine Ausnahme ist ein XPC service, das mit **`JoinExistingSession`** auf `true` in seiner **Info.plist**-Datei konfiguriert ist. In diesem Fall tritt der XPC service **derselben Security Session wie die Anwendung** bei, die ihn aufgerufen hat.<sup>[[4]](#references)</sup>

XPC services werden bei Bedarf von **launchd** **gestartet** und können nach **Abschluss** ihrer Aufgaben **beendet** werden, um Systemressourcen freizugeben. **Anwendungsspezifische XPC-Komponenten können nur von der sie enthaltenden Anwendung verwendet werden**, wodurch die Angriffsfläche potenzieller Schwachstellen reduziert wird.<sup>[[2]](#references)</sup>

## Systemweite XPC Services

Im Gegensatz zu anwendungsspezifischen Services sind systemweite XPC Services nicht auf die sie enthaltende Anwendung beschränkt. Je nach launchd-Domain und den eigenen Autorisierungsprüfungen des Services können sie für Clients mehrerer Benutzer erreichbar sein. Diese von launchd verwalteten Mach Services müssen in **plist**-Dateien definiert werden, die sich in Verzeichnissen wie **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** oder **`/Library/LaunchAgents`** befinden.<sup>[[2]](#references)[[3]](#references)</sup>

Diese plist-Dateien enthalten einen **`MachServices`**-Schlüssel mit dem Servicenamen und einen **`Program`**-Schlüssel mit dem Pfad zur Binärdatei:
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
Dienste in **`LaunchDaemons`** laufen üblicherweise als root. Wenn ein unprivilegierter Prozess daher eine verwundbare Methode erreichen kann, die von einem dieser Dienste bereitgestellt wird, kann er möglicherweise seine Privilegien eskalieren.

## XPC Objects

- **`xpc_object_t`**

XPC-Anfrage- und Antwort-Payloads sind üblicherweise Dictionary-Objekte, was die Serialisierung und Deserialisierung vereinfacht. `libxpc.dylib` deklariert außerdem die Datentypen, die benötigt werden, um zu überprüfen, ob empfangene Daten den erwarteten Typ besitzen. In der C API ist jedes Objekt ein `xpc_object_t` (und sein Typ kann mit `xpc_get_type(object)` überprüft werden).<sup>[[2]](#references)</sup>\
Außerdem kann die Funktion `xpc_copy_description(object)` verwendet werden, um eine String-Darstellung des Objekts abzurufen, die zu Debugging-Zwecken nützlich sein kann.\
Diese Objekte verfügen auch über einige Methoden, die aufgerufen werden können, wie `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` ...

Die `xpc_object_t`-Objekte werden durch den Aufruf einer `xpc_<objectType>_create`-Funktion erstellt, die intern `_xpc_base_create(Class, Size)` aufruft und dabei die Klasse des Objekts (eine von `XPC_TYPE_*`) sowie dessen Größe angibt. Für Metadaten werden zusätzlich 40 Bytes hinzugefügt, daher beginnen die Objektdaten am Offset 40 Bytes.\
Daher ist `xpc_<objectType>_t` gewissermaßen eine Subklasse von `xpc_object_t`, die wiederum eine Subklasse von `os_object_t*` wäre.

> [!WARNING]
> Zu beachten ist, dass der Entwickler `xpc_dictionary_[get/set]_<objectType>` verwenden sollte, um den Typ und den tatsächlichen Wert eines Schlüssels abzurufen oder festzulegen.

- **`xpc_pipe`**

Ein **`xpc_pipe`** ist eine FIFO-Pipe, die Prozesse zur Kommunikation verwenden können (die Kommunikation erfolgt über Mach-Nachrichten).\
Es ist möglich, einen XPC-Server zu erstellen, indem `xpc_pipe_create()` oder `xpc_pipe_create_from_port()` aufgerufen wird, um ihn mithilfe eines bestimmten Mach-Ports zu erstellen. Zum Empfangen von Nachrichten können anschließend `xpc_pipe_receive` und `xpc_pipe_try_receive` aufgerufen werden.

Beachte, dass das **`xpc_pipe`**-Objekt ein **`xpc_object_t`** ist, dessen Struktur Informationen über die beiden verwendeten Mach-Ports sowie den Namen (falls vorhanden) enthält. Der Name wird beispielsweise vom Daemon `secinitd` in dessen Plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` festgelegt, die die Pipe `com.apple.secinitd` konfiguriert.

Ein Beispiel für ein **`xpc_pipe`** ist die von **`launchd`** erstellte **bootstrap pipe**, die das Teilen von Mach-Ports ermöglicht.

- **`NSXPC*`**

Dies sind hochrangige Objective-C-Objekte, die XPC-Verbindungen abstrahieren.\
Außerdem lassen sich diese Objekte mit DTrace einfacher debuggen als die vorherigen.

- **`GCD Queues`**

XPC verwendet GCD zum Weiterleiten von Nachrichten und erzeugt außerdem bestimmte Dispatch-Queues wie `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` ...

## XPC Services

Dies sind Bundles mit der Erweiterung `.xpc`, die sich im Ordner `XPCServices` anderer Projekte befinden. In der `Info.plist` ist für sie `CFBundlePackageType` auf **`XPC!`** gesetzt.\
Diese Datei enthält weitere Konfigurationsschlüssel wie `ServiceType`, das auf Application, User oder System gesetzt werden kann; `_SandboxProfile`, mit dem eine Sandbox definiert werden kann; und `_AllowedClients`, das die erforderlichen Entitlements oder die erforderliche Identität für die Kontaktaufnahme mit dem Service angeben kann. Diese und weitere Optionen konfigurieren den Service beim Start.<sup>[[2]](#references)</sup>

### Starting a Service

Die App versucht, mithilfe von `xpc_connection_create_mach_service` eine **Verbindung** zu einem XPC-Service herzustellen. Anschließend sucht launchd den Daemon und startet **`xpcproxy`**. **`xpcproxy`** setzt die konfigurierten Einschränkungen durch und startet den Service mit den bereitgestellten File Descriptors und Mach-Ports.<sup>[[3]](#references)</sup>

Um die Suche nach dem XPC-Service zu beschleunigen, wird ein Cache verwendet.

Die Aktionen von `xpcproxy` können mit folgendem Befehl nachvollzogen werden:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Die XPC library verwendet `kdebug`, um Aktionen zu protokollieren, indem sie `xpc_ktrace_pid0` und `xpc_ktrace_pid1` aufruft. Die verwendeten Codes sind undokumentiert und müssen daher zu `/usr/share/misc/trace.codes` hinzugefügt werden. Sie haben das Präfix `0x29`; beispielsweise ist `0x29000004` `XPC_serializer_pack`.\
Das Dienstprogramm `xpcproxy` verwendet das Präfix `0x22`, beispielsweise: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC-Ereignismeldungen

Anwendungen können verschiedene Ereignis-**Nachrichten** **abonnieren**, wodurch sie **bei Bedarf gestartet** werden können, sobald solche Ereignisse eintreten. Das **Setup** für diese Dienste erfolgt in l**aunchd-Plist-Dateien**, die sich in den **gleichen Verzeichnissen wie die vorherigen** befinden und einen zusätzlichen **`LaunchEvent`**-Schlüssel enthalten.

### Überprüfung des verbindenden XPC-Prozesses

Wenn ein Prozess versucht, eine Methode über eine XPC-Verbindung aufzurufen, sollte der **XPC-Dienst prüfen, ob dieser Prozess eine Verbindung herstellen darf**. Hier sind gängige Überprüfungsmethoden und ihre Fallstricke:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC-Autorisierung

Apple ermöglicht es Anwendungen außerdem, **Autorisierungsrechte und die Art und Weise zu konfigurieren, wie Aufrufer diese erhalten**, sodass ein Prozess mit den erforderlichen Rechten **eine vom XPC-Dienst bereitgestellte Methode aufrufen darf**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC-Sniffer

Zum Sniffen von XPC-Nachrichten kann **xpcspy** verwendet werden, das **Frida** nutzt.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Ein weiteres mögliches Tool ist **XPoCe2**.<sup>[[6]](#references)</sup>

## C-Codebeispiel für XPC-Kommunikation

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
## XPC-Kommunikation Objective-C-Codebeispiel

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
## Client innerhalb einer Dylib
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

Die von `RemoteXPC.framework` (aus `libxpc`) bereitgestellte Funktionalität ermöglicht die XPC-Kommunikation zwischen verschiedenen Hosts.\
Dienste, die Remote XPC unterstützen, enthalten den Schlüssel `UsesRemoteXPC` in ihrer plist, wie dies bei `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` der Fall ist. Obwohl der Dienst bei `launchd` registriert ist, stellen `UserEventAgent` und seine Plugins `com.apple.remoted.plugin` und `com.apple.remoteservicediscovery.events.plugin` die Funktionalität bereit.

Darüber hinaus ruft `RemoteServiceDiscovery.framework` Informationen von `com.apple.remoted.plugin` ab und stellt Funktionen wie `get_device`, `get_unique_device` und `connect` bereit.

Sobald `connect` den Socket-Dateideskriptor des Dienstes zurückgegeben hat, kann die Klasse `remote_xpc_connection_*` verwendet werden.

Mit der CLI `/usr/libexec/remotectl` können mithilfe von Befehlen wie den folgenden Informationen über Remote-Dienste abgerufen werden:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Die Kommunikation zwischen bridgeOS und dem Host erfolgt über eine dedizierte IPv6-Schnittstelle. `MultiverseSupport.framework` erstellt Sockets, deren Dateideskriptoren für die Kommunikation verwendet werden.\
Diese Kommunikation lässt sich mit `netstat`, `nettop` oder der Open-Source-Alternative `netbottom` finden.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPC-Dienste erstellen](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
