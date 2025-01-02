# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Grundinformationen

XPC, was für XNU (den von macOS verwendeten Kernel) Inter-Process Communication steht, ist ein Framework für **Kommunikation zwischen Prozessen** auf macOS und iOS. XPC bietet einen Mechanismus für **sichere, asynchrone Methodenaufrufe zwischen verschiedenen Prozessen** im System. Es ist Teil von Apples Sicherheitsparadigma und ermöglicht die **Erstellung von privilegierten Anwendungen**, bei denen jede **Komponente** nur mit **den Berechtigungen läuft, die sie benötigt**, um ihre Aufgabe zu erfüllen, wodurch der potenzielle Schaden durch einen kompromittierten Prozess begrenzt wird.

XPC verwendet eine Form der Inter-Process Communication (IPC), die eine Reihe von Methoden umfasst, damit verschiedene Programme, die auf demselben System laufen, Daten hin und her senden können.

Die wichtigsten Vorteile von XPC sind:

1. **Sicherheit**: Durch die Trennung der Arbeit in verschiedene Prozesse kann jedem Prozess nur die Berechtigung gewährt werden, die er benötigt. Das bedeutet, dass selbst wenn ein Prozess kompromittiert wird, er nur begrenzte Möglichkeiten hat, Schaden anzurichten.
2. **Stabilität**: XPC hilft, Abstürze auf die Komponente zu isolieren, in der sie auftreten. Wenn ein Prozess abstürzt, kann er neu gestartet werden, ohne den Rest des Systems zu beeinträchtigen.
3. **Leistung**: XPC ermöglicht eine einfache Parallelität, da verschiedene Aufgaben gleichzeitig in verschiedenen Prozessen ausgeführt werden können.

Der einzige **Nachteil** ist, dass **die Trennung einer Anwendung in mehrere Prozesse**, die über XPC kommunizieren, **weniger effizient** ist. Aber in heutigen Systemen ist dies kaum bemerkbar und die Vorteile überwiegen.

## Anwendungsspezifische XPC-Dienste

Die XPC-Komponenten einer Anwendung befinden sich **innerhalb der Anwendung selbst.** Zum Beispiel finden Sie sie in **`/Applications/Safari.app/Contents/XPCServices`**. Sie haben die Erweiterung **`.xpc`** (wie **`com.apple.Safari.SandboxBroker.xpc`**) und sind **auch Bundles** mit der Haupt-Binärdatei darin: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` und eine `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Wie Sie vielleicht denken, wird eine **XPC-Komponente andere Berechtigungen und Privilegien** haben als die anderen XPC-Komponenten oder die Hauptanwendungs-Binärdatei. AUSGENOMMEN, wenn ein XPC-Dienst mit [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) auf „Wahr“ in seiner **Info.plist**-Datei konfiguriert ist. In diesem Fall wird der XPC-Dienst in der **gleichen Sicherheits-Sitzung wie die Anwendung** ausgeführt, die ihn aufgerufen hat.

XPC-Dienste werden von **launchd** gestartet, wenn sie benötigt werden, und **heruntergefahren**, sobald alle Aufgaben **abgeschlossen** sind, um Systemressourcen freizugeben. **Anwendungsspezifische XPC-Komponenten können nur von der Anwendung** genutzt werden, wodurch das Risiko im Zusammenhang mit potenziellen Schwachstellen verringert wird.

## Systemweite XPC-Dienste

Systemweite XPC-Dienste sind für alle Benutzer zugänglich. Diese Dienste, entweder launchd oder Mach-Typ, müssen in plist-Dateien definiert werden, die sich in bestimmten Verzeichnissen wie **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** oder **`/Library/LaunchAgents`** befinden.

Diese plist-Dateien haben einen Schlüssel namens **`MachServices`** mit dem Namen des Dienstes und einen Schlüssel namens **`Program`** mit dem Pfad zur Binärdatei:
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
Die in **`LaunchDameons`** sind unter root aktiv. Wenn ein unprivilegierter Prozess mit einem dieser kommunizieren kann, könnte er in der Lage sein, Privilegien zu eskalieren.

## XPC-Objekte

- **`xpc_object_t`**

Jede XPC-Nachricht ist ein Dictionary-Objekt, das die Serialisierung und Deserialisierung vereinfacht. Darüber hinaus deklariert `libxpc.dylib` die meisten Datentypen, sodass sichergestellt werden kann, dass die empfangenen Daten vom erwarteten Typ sind. In der C-API ist jedes Objekt ein `xpc_object_t` (und sein Typ kann mit `xpc_get_type(object)` überprüft werden).\
Darüber hinaus kann die Funktion `xpc_copy_description(object)` verwendet werden, um eine String-Darstellung des Objekts zu erhalten, die für Debugging-Zwecke nützlich sein kann.\
Diese Objekte haben auch einige Methoden, die aufgerufen werden können, wie `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Die `xpc_object_t` werden durch den Aufruf der Funktion `xpc_<objetType>_create` erstellt, die intern `_xpc_base_create(Class, Size)` aufruft, wobei der Typ der Klasse des Objekts (einer von `XPC_TYPE_*`) und die Größe angegeben werden. (Es werden einige zusätzliche 40B zur Größe für Metadaten hinzugefügt). Das bedeutet, dass die Daten des Objekts bei der Offset von 40B beginnen.\
Daher ist der `xpc_<objectType>_t` eine Art Unterklasse von `xpc_object_t`, die eine Unterklasse von `os_object_t*` wäre.

> [!WARNING]
> Beachten Sie, dass es der Entwickler sein sollte, der `xpc_dictionary_[get/set]_<objectType>` verwendet, um den Typ und den tatsächlichen Wert eines Schlüssels zu erhalten oder festzulegen.

- **`xpc_pipe`**

Ein **`xpc_pipe`** ist ein FIFO-Rohr, das Prozesse zur Kommunikation verwenden können (die Kommunikation verwendet Mach-Nachrichten).\
Es ist möglich, einen XPC-Server zu erstellen, indem `xpc_pipe_create()` oder `xpc_pipe_create_from_port()` aufgerufen wird, um ihn mit einem bestimmten Mach-Port zu erstellen. Um Nachrichten zu empfangen, ist es möglich, `xpc_pipe_receive` und `xpc_pipe_try_receive` aufzurufen.

Beachten Sie, dass das **`xpc_pipe`**-Objekt ein **`xpc_object_t`** mit Informationen in seiner Struktur über die beiden verwendeten Mach-Ports und den Namen (falls vorhanden) ist. Der Name, zum Beispiel, der Daemon `secinitd` in seiner plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` konfiguriert das Rohr mit dem Namen `com.apple.secinitd`.

Ein Beispiel für ein **`xpc_pipe`** ist das von **`launchd`** erstellte **Bootstrap-Pipe**, das das Teilen von Mach-Ports ermöglicht.

- **`NSXPC*`**

Dies sind hochgradige Objective-C-Objekte, die die Abstraktion von XPC-Verbindungen ermöglichen.\
Darüber hinaus ist es einfacher, diese Objekte mit DTrace zu debuggen als die vorherigen.

- **`GCD Queues`**

XPC verwendet GCD, um Nachrichten zu übermitteln, außerdem generiert es bestimmte Dispatch-Warteschlangen wie `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC-Dienste

Dies sind **Bundles mit der Erweiterung `.xpc`**, die sich im **`XPCServices`**-Ordner anderer Projekte befinden und in der `Info.plist` den `CFBundlePackageType` auf **`XPC!`** gesetzt haben.\
Diese Datei hat andere Konfigurationsschlüssel wie `ServiceType`, die Application, User, System oder `_SandboxProfile` sein können, die einen Sandbox oder `_AllowedClients` definieren können, die Berechtigungen oder IDs angeben könnten, die erforderlich sind, um den Dienst zu kontaktieren. Diese und andere Konfigurationsoptionen sind nützlich, um den Dienst beim Start zu konfigurieren.

### Einen Dienst starten

Die App versucht, sich mit einem XPC-Dienst zu **verbinden**, indem sie `xpc_connection_create_mach_service` verwendet, dann lokalisiert launchd den Daemon und startet **`xpcproxy`**. **`xpcproxy`** setzt die konfigurierten Einschränkungen durch und startet den Dienst mit den bereitgestellten FDs und Mach-Ports.

Um die Geschwindigkeit der Suche nach dem XPC-Dienst zu verbessern, wird ein Cache verwendet.

Es ist möglich, die Aktionen von `xpcproxy` zu verfolgen mit:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Die XPC-Bibliothek verwendet `kdebug`, um Aktionen zu protokollieren, indem `xpc_ktrace_pid0` und `xpc_ktrace_pid1` aufgerufen werden. Die verwendeten Codes sind nicht dokumentiert, daher müssen sie in `/usr/share/misc/trace.codes` hinzugefügt werden. Sie haben das Präfix `0x29`, und zum Beispiel ist einer `0x29000004`: `XPC_serializer_pack`.\
Das Dienstprogramm `xpcproxy` verwendet das Präfix `0x22`, zum Beispiel: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC-Ereignisnachrichten

Anwendungen können **sich** für verschiedene Ereignis-**nachrichten** **anmelden**, sodass sie **auf Abruf** initiiert werden können, wenn solche Ereignisse eintreten. Die **Einrichtung** für diese Dienste erfolgt in **launchd plist-Dateien**, die sich in den **gleichen Verzeichnissen wie die vorherigen** befinden und einen zusätzlichen **`LaunchEvent`**-Schlüssel enthalten.

### XPC-Verbindungsprozessprüfung

Wenn ein Prozess versucht, eine Methode über eine XPC-Verbindung aufzurufen, sollte der **XPC-Dienst überprüfen, ob dieser Prozess berechtigt ist, sich zu verbinden**. Hier sind die gängigen Methoden zur Überprüfung und die häufigen Fallstricke:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC-Autorisierung

Apple erlaubt es auch, dass Apps **einige Rechte konfigurieren und wie man sie erhält**, sodass, wenn der aufrufende Prozess diese hat, er **berechtigt wäre, eine Methode** vom XPC-Dienst aufzurufen:

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC-Sniffer

Um die XPC-Nachrichten abzuhören, können Sie [**xpcspy**](https://github.com/hot3eed/xpcspy) verwenden, das **Frida** nutzt.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Ein weiteres mögliches Werkzeug ist [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## XPC Kommunikations C Code Beispiel

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
## XPC-Kommunikation Objective-C Codebeispiel

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
## Client innerhalb eines Dylb-Codes
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

Diese Funktionalität, die von `RemoteXPC.framework` (aus `libxpc`) bereitgestellt wird, ermöglicht die Kommunikation über XPC zwischen verschiedenen Hosts.\
Die Dienste, die Remote XPC unterstützen, haben in ihrer plist den Schlüssel UsesRemoteXPC, wie es bei `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` der Fall ist. Allerdings wird der Dienst zwar mit `launchd` registriert, es ist jedoch `UserEventAgent` mit den Plugins `com.apple.remoted.plugin` und `com.apple.remoteservicediscovery.events.plugin`, die die Funktionalität bereitstellen.

Darüber hinaus ermöglicht das `RemoteServiceDiscovery.framework`, Informationen von dem `com.apple.remoted.plugin` abzurufen, das Funktionen wie `get_device`, `get_unique_device`, `connect`... bereitstellt.

Sobald `connect` verwendet wird und der Socket `fd` des Dienstes gesammelt ist, ist es möglich, die Klasse `remote_xpc_connection_*` zu verwenden.

Es ist möglich, Informationen über Remote-Dienste mit dem CLI-Tool `/usr/libexec/remotectl` unter Verwendung von Parametern wie:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Die Kommunikation zwischen BridgeOS und dem Host erfolgt über eine dedizierte IPv6-Schnittstelle. Das `MultiverseSupport.framework` ermöglicht die Einrichtung von Sockets, deren `fd` für die Kommunikation verwendet wird.\
Es ist möglich, diese Kommunikationen mit `netstat`, `nettop` oder der Open-Source-Option `netbottom` zu finden.

{{#include ../../../../../banners/hacktricks-training.md}}
