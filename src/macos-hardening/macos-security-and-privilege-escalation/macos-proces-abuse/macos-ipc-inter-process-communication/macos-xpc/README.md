# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

XPC, kurz für XNU (der von macOS verwendete Kernel) inter-Process Communication, ist ein Framework für die **Kommunikation zwischen Prozessen** unter macOS und iOS. XPC bietet einen Mechanismus für **sichere, asynchrone Methodenaufrufe zwischen verschiedenen Prozessen** auf dem System. Es ist Teil von Apples Sicherheitsparadigma und ermöglicht die **Erstellung von Anwendungen mit getrennten Berechtigungen**, bei denen jede **Komponente** nur mit den **Berechtigungen ausgeführt wird, die sie für ihre Aufgabe benötigt**, wodurch der potenzielle Schaden durch einen kompromittierten Prozess begrenzt wird.

XPC verwendet eine Form der Inter-Process Communication (IPC), also eine Reihe von Methoden, mit denen verschiedene Programme, die auf demselben System ausgeführt werden, Daten hin und her senden können.

Zu den wichtigsten Vorteilen von XPC gehören:

1. **Sicherheit**: Durch die Aufteilung der Arbeit auf verschiedene Prozesse kann jedem Prozess nur die benötigte Berechtigung erteilt werden. Das bedeutet, dass ein kompromittierter Prozess nur begrenzte Möglichkeiten hat, Schaden anzurichten.
2. **Stabilität**: XPC hilft dabei, Abstürze auf die betroffene Komponente zu begrenzen. Wenn ein Prozess abstürzt, kann er neu gestartet werden, ohne den Rest des Systems zu beeinträchtigen.
3. **Leistung**: XPC ermöglicht eine einfache Nebenläufigkeit, da verschiedene Aufgaben gleichzeitig in unterschiedlichen Prozessen ausgeführt werden können.

Der einzige **Nachteil** besteht darin, dass die **Aufteilung einer Anwendung auf mehrere Prozesse**, die über XPC miteinander kommunizieren, **weniger effizient** ist. In heutigen Systemen ist dies jedoch kaum bemerkbar, und die Vorteile überwiegen.

## Anwendungsspezifische XPC services

Die XPC-Komponenten einer Anwendung befinden sich **innerhalb der Anwendung selbst.** In Safari sind sie beispielsweise unter **`/Applications/Safari.app/Contents/XPCServices`** zu finden. Sie haben die Erweiterung **`.xpc`** (wie **`com.apple.Safari.SandboxBroker.xpc`**) und sind **ebenfalls bundles**, die die Haupt-Binary enthalten: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` sowie ein `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Wie du dir vielleicht denkst, verfügt eine **XPC-Komponente über andere Entitlements und Berechtigungen** als die anderen XPC-Komponenten oder die Haupt-Binary der Anwendung. AUSNAHME: Ein XPC service ist mit [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) konfiguriert und in seiner **`Info.plist`**-Datei auf „True“ gesetzt. In diesem Fall wird der XPC service in derselben **Sicherheitssitzung wie die Anwendung** ausgeführt, die ihn aufgerufen hat.

XPC services werden bei Bedarf von **launchd** **gestartet** und nach Abschluss aller **Aufgaben** **beendet**, um Systemressourcen freizugeben. **Anwendungsspezifische XPC-Komponenten können nur von der jeweiligen Anwendung verwendet werden**, wodurch das mit potenziellen Schwachstellen verbundene Risiko verringert wird.

## Systemweite XPC services

Systemweite XPC services sind für alle Benutzer zugänglich. Diese services, entweder vom Typ launchd oder Mach, müssen in **plist**-Dateien definiert sein, die sich in bestimmten Verzeichnissen wie **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** oder **`/Library/LaunchAgents`** befinden.

Diese plist-Dateien enthalten einen Schlüssel namens **`MachServices`** mit dem Namen des service sowie einen Schlüssel namens **`Program`** mit dem Pfad zur Binary:
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
Diejenigen in **`LaunchDameons`** werden als root ausgeführt. Wenn ein nicht privilegierter Prozess mit einem dieser Prozesse kommunizieren kann, könnte er möglicherweise seine Privilegien erweitern.

## XPC Objects

- **`xpc_object_t`**

Jede XPC-Nachricht ist ein Dictionary-Objekt, das die Serialisierung und Deserialisierung vereinfacht. Außerdem deklariert `libxpc.dylib` die meisten Datentypen, sodass sich überprüfen lässt, ob die empfangenen Daten den erwarteten Typ besitzen. In der C API ist jedes Objekt ein `xpc_object_t` (und sein Typ kann mit `xpc_get_type(object)` überprüft werden).\
Außerdem kann die Funktion `xpc_copy_description(object)` verwendet werden, um eine String-Darstellung des Objekts abzurufen, die zu Debugging-Zwecken nützlich sein kann.\
Diese Objekte besitzen auch einige Methoden, die aufgerufen werden können, etwa `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` ...

Die `xpc_object_t` werden durch den Aufruf der Funktion `xpc_<objetType>_create` erstellt, die intern `_xpc_base_create(Class, Size)` aufruft. Dabei werden der Typ der Klasse des Objekts (einer von `XPC_TYPE_*`) und dessen Größe angegeben (zur Größe werden weitere 40 B für Metadaten hinzugefügt). Das bedeutet, dass die Daten des Objekts am Offset 40 B beginnen.\
Daher ist `xpc_<objectType>_t` eine Art Subklasse von `xpc_object_t`, das wiederum eine Subklasse von `os_object_t*` wäre.

> [!WARNING]
> Beachte, dass der Entwickler `xpc_dictionary_[get/set]_<objectType>` verwenden sollte, um den Typ und den tatsächlichen Wert eines Schlüssels abzurufen oder zu setzen.

- **`xpc_pipe`**

Ein **`xpc_pipe`** ist eine FIFO-Pipe, die Prozesse zur Kommunikation verwenden können (die Kommunikation nutzt Mach-Nachrichten).\
Es ist möglich, einen XPC-Server durch den Aufruf von `xpc_pipe_create()` oder `xpc_pipe_create_from_port()` zu erstellen, um ihn mit einem bestimmten Mach-Port zu erstellen. Zum Empfangen von Nachrichten können anschließend `xpc_pipe_receive` und `xpc_pipe_try_receive` aufgerufen werden.

Beachte, dass das **`xpc_pipe`**-Objekt ein **`xpc_object_t`** ist, dessen Struktur Informationen über die beiden verwendeten Mach-Ports sowie den Namen (falls vorhanden) enthält. Der Name wird beispielsweise in der plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` des Daemons `secinitd` verwendet, um die Pipe `com.apple.secinitd` zu konfigurieren.

Ein Beispiel für einen **`xpc_pipe`** ist die **Bootstrap-Pipe**, die von **`launchd`** erstellt wird und das Teilen von Mach-Ports ermöglicht.

- **`NSXPC*`**

Dies sind hochrangige Objective-C-Objekte, die eine Abstraktion von XPC-Verbindungen ermöglichen.\
Außerdem lassen sich diese Objekte mit DTrace leichter debuggen als die vorherigen.

- **`GCD Queues`**

XPC verwendet GCD zum Übertragen von Nachrichten und erzeugt außerdem bestimmte Dispatch-Queues wie `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` ...

## XPC Services

Dabei handelt es sich um **Bundles mit der Erweiterung `.xpc`**, die sich im Ordner **`XPCServices`** anderer Projekte befinden. In der `Info.plist` ist `CFBundlePackageType` auf **`XPC!`** gesetzt.\
Diese Datei enthält weitere Konfigurationsschlüssel wie `ServiceType`, der auf Application, User oder System gesetzt werden kann, oder `_SandboxProfile`, mit dem eine Sandbox definiert werden kann. `_AllowedClients` kann Entitlements oder eine ID angeben, die für die Kontaktaufnahme mit dem Service erforderlich ist. Diese und weitere Konfigurationsoptionen sind nützlich, um den Service beim Start zu konfigurieren.

### Starten eines Service

Die App versucht, über `xpc_connection_create_mach_service` eine **Verbindung** zu einem XPC-Service herzustellen. Anschließend sucht launchd den Daemon und startet **`xpcproxy`**. **`xpcproxy`** setzt die konfigurierten Einschränkungen durch und startet den Service mit den bereitgestellten FDs und Mach-Ports.

Um die Suche nach dem XPC-Service zu beschleunigen, wird ein Cache verwendet.

Die Aktionen von `xpcproxy` können mit folgendem Befehl verfolgt werden:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Die XPC library verwendet `kdebug`, um Aktionen zu protokollieren, indem sie `xpc_ktrace_pid0` und `xpc_ktrace_pid1` aufruft. Die von ihr verwendeten Codes sind undokumentiert, daher müssen sie zu `/usr/share/misc/trace.codes` hinzugefügt werden. Sie haben das Präfix `0x29`; einer davon ist beispielsweise `0x29000004`: `XPC_serializer_pack`.\
Das Utility `xpcproxy` verwendet das Präfix `0x22`, zum Beispiel: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Anwendungen können verschiedene Event-**Nachrichten** **abonnieren**, wodurch sie **bei Bedarf gestartet werden**, sobald solche Events eintreten. Das **Setup** für diese Services erfolgt in **l**aunchd-Plist-Dateien**, die sich in denselben Verzeichnissen wie die vorherigen befinden und einen zusätzlichen **`LaunchEvent`**-Key enthalten.

### XPC Connecting Process Check

Wenn ein Prozess versucht, eine Methode über eine XPC-Verbindung aufzurufen, sollte der **XPC service prüfen, ob dieser Prozess eine Verbindung herstellen darf**. Dies sind die gängigen Möglichkeiten zur Überprüfung sowie die häufigsten Fallstricke:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple erlaubt es Apps außerdem, einige Berechtigungen und deren Erhalt zu **konfigurieren**, sodass der aufrufende Prozess, wenn er über diese verfügt, **eine Methode** des XPC service aufrufen **darf**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Zum Sniffen der XPC-Nachrichten kann [**xpcspy**](https://github.com/hot3eed/xpcspy) verwendet werden, das **Frida** nutzt.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Ein weiteres mögliches Tool ist [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## C-Code-Beispiel für XPC-Kommunikation

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
## XPC-Kommunikation: Objective-C-Codebeispiel

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

Diese von `RemoteXPC.framework` (aus `libxpc`) bereitgestellte Funktionalität ermöglicht die Kommunikation über XPC zwischen verschiedenen Hosts.\
Dienste, die Remote XPC unterstützen, enthalten in ihrer plist den Schlüssel UsesRemoteXPC, wie dies beispielsweise bei `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` der Fall ist. Obwohl der Dienst bei `launchd` registriert wird, sind es jedoch `UserEventAgent` mit den Plugins `com.apple.remoted.plugin` und `com.apple.remoteservicediscovery.events.plugin`, die diese Funktionalität bereitstellen.

Darüber hinaus ermöglicht `RemoteServiceDiscovery.framework`, Informationen von `com.apple.remoted.plugin` abzurufen, wobei Funktionen wie `get_device`, `get_unique_device`, `connect` ... bereitgestellt werden.

Sobald `connect` verwendet und der Socket-`fd` des Dienstes ermittelt wurde, kann die Klasse `remote_xpc_connection_*` verwendet werden.

Mit dem CLI-Tool `/usr/libexec/remotectl` können mithilfe von Parametern wie den folgenden Informationen über Remote-Dienste abgerufen werden:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Die Kommunikation zwischen BridgeOS und dem Host erfolgt über eine dedizierte IPv6-Schnittstelle. Das `MultiverseSupport.framework` ermöglicht die Einrichtung von Sockets, deren `fd` für die Kommunikation verwendet wird.\
Diese Kommunikation lässt sich mit `netstat`, `nettop` oder der Open-Source-Option `netbottom` finden.

{{#include ../../../../../banners/hacktricks-training.md}}
