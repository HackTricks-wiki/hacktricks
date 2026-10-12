# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

XPC ist ein Framework für die **Kommunikation zwischen Prozessen** unter macOS und iOS. Es bietet Mechanismen für **sichere, asynchrone Aufrufe zwischen Prozessen**. XPC unterstützt **Anwendungen mit getrennten Berechtigungen**, bei denen jede **Komponente** nur mit den **Berechtigungen ausgeführt wird, die sie benötigt**. Dadurch wird der potenzielle Schaden durch einen kompromittierten Prozess begrenzt.<sup>[[1]](#references)</sup>

XPC verwendet eine Form der Interprozesskommunikation (IPC), also eine Reihe von Methoden, mit denen verschiedene Programme auf demselben System Daten austauschen können.

Die wichtigsten Vorteile von XPC sind:

1. **Sicherheit**: Durch die Aufteilung der Arbeit auf verschiedene Prozesse kann jeder Prozess nur die benötigten Berechtigungen erhalten. Selbst wenn ein Prozess kompromittiert wird, kann er daher nur begrenzt Schaden anrichten.
2. **Stabilität**: XPC hilft dabei, Abstürze auf die betroffene Komponente zu beschränken. Wenn ein Prozess abstürzt, kann er neu gestartet werden, ohne den Rest des Systems zu beeinträchtigen.
3. **Leistung**: XPC ermöglicht einfache Nebenläufigkeit, da verschiedene Aufgaben gleichzeitig in unterschiedlichen Prozessen ausgeführt werden können.

Der größte **Nachteil** ist, dass die **Aufteilung einer Anwendung in mehrere Prozesse** und deren Kommunikation über XPC zusätzlichen Aufwand verursacht. Auf modernen Systemen ist dieser Aufwand im Vergleich zu den Vorteilen für Sicherheit und Stabilität meist gering.<sup>[[1]](#references)</sup>

## Anwendungsspezifische XPC-Services

Die XPC-Komponenten einer Anwendung befinden sich **in der Anwendung selbst**. In Safari findet man sie beispielsweise unter **`/Applications/Safari.app/Contents/XPCServices`**. Sie haben die Erweiterung **`.xpc`** (wie **`com.apple.Safari.SandboxBroker.xpc`**) und sind ebenfalls **Bundles** mit der Haupt-Binärdatei und einer `Info.plist` darin. Zum Beispiel: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` und `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Eine **XPC-Komponente kann andere Entitlements und Berechtigungen haben** als andere XPC-Komponenten oder die Haupt-Binärdatei der Anwendung. Eine Ausnahme ist ein XPC-Service, für den in seiner **Info.plist**-Datei **`JoinExistingSession`** auf `true` gesetzt ist. In diesem Fall tritt der XPC-Service derselben **Sicherheitssitzung wie die aufrufende Anwendung** bei.<sup>[[4]](#references)</sup>

XPC-Services werden bei Bedarf von **launchd** **gestartet** und können nach **Abschluss** ihrer Aufgaben **beendet** werden, um Systemressourcen freizugeben. **Anwendungsspezifische XPC-Komponenten können nur von der Anwendung verwendet werden, zu der sie gehören**, wodurch die Angriffsfläche für potenzielle Schwachstellen verringert wird.<sup>[[2]](#references)</sup>

## Systemweite XPC-Services

Im Gegensatz zu anwendungsspezifischen Services sind systemweite XPC-Services nicht auf die Anwendung beschränkt, zu der sie gehören. Je nach launchd-Domain und den eigenen Autorisierungsprüfungen des Services können Clients mehrerer Benutzer darauf zugreifen. Diese von launchd verwalteten Mach-Services müssen in plist-Dateien definiert sein, die sich in Verzeichnissen wie **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** oder **`/Library/LaunchAgents`** befinden.<sup>[[2]](#references)[[3]](#references)</sup>

Diese plist-Dateien enthalten einen Schlüssel **`MachServices`** mit dem Namen des Services und einen Schlüssel **`Program`** mit dem Pfad zur Binärdatei:

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

Dienste in **`LaunchDaemons`** laufen häufig als root. Wenn ein unprivilegierter Prozess daher eine verwundbare Methode erreichen kann, die von einem dieser Dienste bereitgestellt wird, kann er möglicherweise seine Privilegien erhöhen.

## XPC-Objekte

- **`xpc_object_t`**

XPC-Anfrage- und Antwort-Payloads sind häufig Dictionary-Objekte, die die Serialisierung und Deserialisierung vereinfachen. `libxpc.dylib` deklariert außerdem die Datentypen, die benötigt werden, um zu überprüfen, ob empfangene Daten den erwarteten Typ haben. In der C API ist jedes Objekt ein `xpc_object_t` (und sein Typ kann mit `xpc_get_type(object)` überprüft werden).<sup>[[2]](#references)</sup>\
Außerdem kann die Funktion `xpc_copy_description(object)` verwendet werden, um eine Zeichenfolgendarstellung des Objekts abzurufen, die beim Debugging nützlich sein kann.\
Diese Objekte haben auch Methoden wie `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` ...

Die Objekte vom Typ `xpc_object_t` werden durch Aufruf einer Funktion `xpc_<objectType>_create` erstellt, die intern `_xpc_base_create(Class, Size)` aufruft und dabei die Klasse des Objekts (eine von `XPC_TYPE_*`) und seine Größe angibt. Für Metadaten werden zusätzlich 40 Byte hinzugefügt, sodass die Objektdaten bei Offset 40 Byte beginnen.\
Daher ist `xpc_<objectType>_t` gewissermaßen eine Unterklasse von `xpc_object_t`, das wiederum eine Unterklasse von `os_object_t*` wäre.

> [!WARNING]
> Beachte, dass der Entwickler `xpc_dictionary_[get/set]_<objectType>` verwenden sollte, um den Typ und den tatsächlichen Wert eines Schlüssels abzurufen oder festzulegen.

- **`xpc_pipe`**

Ein **`xpc_pipe`** ist eine FIFO-Pipe, über die Prozesse kommunizieren können (die Kommunikation erfolgt über Mach-Nachrichten).\
Ein XPC-Server lässt sich mit `xpc_pipe_create()` oder mit `xpc_pipe_create_from_port()` unter Verwendung eines bestimmten Mach-Ports erstellen. Zum Empfangen von Nachrichten können anschließend `xpc_pipe_receive` und `xpc_pipe_try_receive` aufgerufen werden.

Beachte, dass das Objekt **`xpc_pipe`** ein **`xpc_object_t`** ist, dessen Struct Informationen zu den beiden verwendeten Mach-Ports und dem Namen (falls vorhanden) enthält. Der Daemon `secinitd` konfiguriert beispielsweise in seiner Plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` die Pipe mit dem Namen `com.apple.secinitd`.

Ein Beispiel für ein **`xpc_pipe`** ist die von **`launchd`** erstellte **Bootstrap-Pipe**, über die Mach-Ports gemeinsam genutzt werden können.

- **`NSXPC*`**

Dies sind hochrangige Objective-C-Objekte, die XPC-Verbindungen abstrahieren.\
Außerdem lassen sich diese Objekte mit DTrace einfacher debuggen als die zuvor genannten.

- **`GCD Queues`**

XPC verwendet GCD zum Übermitteln von Nachrichten und erzeugt außerdem bestimmte Dispatch-Queues wie `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` ...

## XPC-Dienste

Dies sind **Bundles mit der Erweiterung `.xpc`**, die sich im Ordner **`XPCServices`** anderer Projekte befinden. In ihrer `Info.plist` ist `CFBundlePackageType` auf **`XPC!`** gesetzt.\
Diese Datei enthält weitere Konfigurationsschlüssel, etwa `ServiceType`, dessen Wert `Application`, `User` oder `System` sein kann; `_SandboxProfile`, mit dem eine Sandbox definiert werden kann; und `_AllowedClients`, das möglicherweise die erforderlichen Entitlements oder die Identität zum Kontaktieren des Dienstes angibt. Diese und weitere Optionen konfigurieren den Dienst beim Start.<sup>[[2]](#references)</sup>

### Starten eines Dienstes

Die App versucht, mithilfe von `xpc_connection_create_mach_service` eine **Verbindung** zu einem XPC-Dienst herzustellen. Anschließend sucht launchd den Daemon und startet **`xpcproxy`**. **`xpcproxy`** setzt die konfigurierten Einschränkungen durch und startet den Dienst mit den bereitgestellten Dateideskriptoren und Mach-Ports.<sup>[[3]](#references)</sup>

Um die Suche nach dem XPC-Dienst zu beschleunigen, wird ein Cache verwendet.

Die Aktionen von `xpcproxy` lassen sich wie folgt nachverfolgen:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

Die XPC-Bibliothek verwendet `kdebug`, um Aktionen durch Aufruf von `xpc_ktrace_pid0` und `xpc_ktrace_pid1` zu protokollieren. Die verwendeten Codes sind undokumentiert und müssen daher zu `/usr/share/misc/trace.codes` hinzugefügt werden. Sie haben das Präfix `0x29`; beispielsweise steht `0x29000004` für `XPC_serializer_pack`.\
Das Dienstprogramm `xpcproxy` verwendet das Präfix `0x22`, zum Beispiel: `0x2200001c: xpcproxy:will_do_preexec`.

## Audit von XPC-Helpern des Typs Application

Ein `XPCService.ServiceType` mit dem Wert `Application` ist ein nützlicher Ausgangspunkt für das Audit von frameworkseitig bereitgestellten Helpern: Zähle die Bundles auf, berücksichtige die laufenden Dienste und untersuche die Kennung und Entitlements des Helpers. Durchsuche sowohl `/System/Library/Frameworks` als auch `/System/Library/PrivateFrameworks`; der genaue Bestand ändert sich je nach macOS-Version.<sup>[[7]](#references)</sup>

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

### Den Den Listener analysieren und ein minimales Protokoll rekonstruieren

Suche im Helper nach `-[<delegate> listener:shouldAcceptNewConnection:]`. Ein Pfad, der `exportedInterface` und `exportedObject` setzt, die Verbindung fortsetzt und `YES`/`1` zurückgibt, ohne das Audit-Token, die Code-Anforderung oder die Entitlements des Peers zu prüfen, macht die RPC-Schnittstelle für jeden Client verfügbar, der den Service finden kann. Das belegt lediglich die **Erreichbarkeit**: Für einen tatsächlichen Impact ist weiterhin eine exportierte Methode erforderlich, die eine privilegierte Operation ohne ausreichende Autorisierung pro Client bzw. Methode ausführt oder nicht sicher Eingaben verarbeitet, die vom Angreifer kontrolliert werden.<sup>[[7]](#references)</sup>

Rekonstruiere nur die Selektoren, die für den Test erforderlich sind. Die Metadaten der Objective-C-Selektoren geben die Anzahl der Argumente preis; die Verwendung der Argumente im Decompiler präzisiert üblicherweise die Typen (zum Beispiel sind die an `-[EKEvent setStartDate:]` und `setEndDate:` übergebenen Werte `NSDate *`), während der indirekte Aufruf am Ende der Methode die Parameter des Reply-Blocks offenlegt. Für `NSXPCInterface` genügt ein partielles lokales Protokoll; das vollständige private Protokoll muss nicht rekonstruiert werden.<sup>[[7]](#references)</sup>

### Mit der rekonstruierten Schnittstelle verbinden

Lade bei einem XPC-Service einer Anwendung alle Frameworks, die erforderliche private Klassen definieren, erstelle die Verbindung mit `initWithServiceName:`, weise ihr die rekonstruierte Remote-Schnittstelle zu, installiere Error-, Interruption- und Invalidation-Handler und setze sie erst danach fort. Halte den Run Loop für asynchrone Replies am Laufen. Führe den Client zum Testen einer Sandbox-Grenze erneut innerhalb einer sandboxed application aus – ein erfolgreicher Standalone-Client ist kein Beleg für einen Sandbox-Escape.<sup>[[7]](#references)</sup>

<details>
<summary>Minimaler Objective-C-Client</summary>

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

Mit `clang -fblocks -framework Foundation -o xpc_client xpc_client.m` kompilieren.<sup>[[7]](#references)</sup>

</details>

### Fehler beim Secure Coding als Typ-Orakel verwenden

Ein Fehler in `NSCocoaErrorDomain`, beispielsweise mit dem Code `4101`, kann die nützliche Serialisierungsausnahme verbergen. Durchsuche das vereinheitlichte macOS-Protokoll/Console nach dem Dienstnamen: Die Ausnahme gibt sowohl die unerwartete Klasse als auch die für dieses Selektorargument zulässigen Klassen an. Erweitere bei einer Antwort die Allowlist der **clientseitigen** Schnittstelle mit `setClasses:forSelector:argumentIndex:ofReply:`; bei `ofReply:YES` bezeichnet Index `0` den ersten Parameter des Antwortblocks, nicht den ersten Methodenparameter.<sup>[[7]](#references)</sup>

Konfiguriere die Schnittstelle, bevor du sie der Verbindung zuweist und `[c resume]` aufrufst:<sup>[[7]](#references)</sup>

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

Der umgekehrte Fall ist ebenfalls nützlich: Wenn der Server eine Foundation-Eingabe ablehnt und eine einzelne zulässige private Klasse protokolliert, verrät das Protokoll den erwarteten Wire-Typ und sein Framework. Lade dieses Framework, untersuche die Methoden/Eigenschaften der Klasse, um generische `id`-Typen genauer zu bestimmen, und erstelle das private Objekt dynamisch. Die Argumente von `NSInvocation` beginnen bei Index `2`, da die Indizes `0` und `1` die verborgenen Argumente `self` und `_cmd` sind.<sup>[[7]](#references)</sup>

<details>
<summary>Ein privates Argument mit NSInvocation erstellen</summary>

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

Den entsprechenden Workflow für launchd-registrierte, systemweite Mach-Services findest du hier:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## XPC-Ereignisnachrichten

Anwendungen können verschiedene Ereignis**nachrichten abonnieren**, sodass sie **bei Bedarf gestartet werden**, wenn solche Ereignisse eintreten. Die **Konfiguration** dieser Services erfolgt in l**aunchd-Plist-Dateien**, die sich in denselben Verzeichnissen wie die vorherigen befinden und einen zusätzlichen Schlüssel **`LaunchEvent`** enthalten.

### Überprüfung des verbindenden Prozesses bei XPC

Wenn ein Prozess versucht, eine Methode über eine XPC-Verbindung aufzurufen, **sollte der XPC-Service prüfen, ob dieser Prozess eine Verbindung herstellen darf**. Hier sind gängige Überprüfungsmethoden und ihre Fallstricke:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC-Autorisierung

Apple ermöglicht es Apps außerdem, **Autorisierungsrechte und die Art ihrer Vergabe an Aufrufer zu konfigurieren**, sodass ein Prozess mit den erforderlichen Rechten **eine vom XPC-Service bereitgestellte Methode aufrufen darf**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC-Sniffer

Zum Abfangen von XPC-Nachrichten kannst du **xpcspy** verwenden, das **Frida** nutzt.<sup>[[5]](#references)</sup>

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

## XPC-Kommunikation: C-Code-Beispiel

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

Die von `RemoteXPC.framework` (aus `libxpc`) bereitgestellte Funktionalität ermöglicht XPC-Kommunikation zwischen verschiedenen Hosts.\
Dienste, die Remote XPC unterstützen, haben den Schlüssel `UsesRemoteXPC` in ihrer plist. Das ist beispielsweise bei `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` der Fall. Obwohl der Dienst bei `launchd` registriert ist, stellen `UserEventAgent` und seine Plugins `com.apple.remoted.plugin` und `com.apple.remoteservicediscovery.events.plugin` die Funktionalität bereit.

Außerdem ruft `RemoteServiceDiscovery.framework` Informationen von `com.apple.remoted.plugin` ab und stellt Funktionen wie `get_device`, `get_unique_device` und `connect` bereit.

Sobald `connect` den Socket-Dateideskriptor des Dienstes zurückgegeben hat, kann die Klasse `remote_xpc_connection_*` verwendet werden.

Mit der CLI `/usr/libexec/remotectl` und Befehlen wie den folgenden lassen sich Informationen über Remote-Dienste abrufen:

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
- [7] [Reverse Society - macOS-XPC-Helpers angreifen: Protocol Reverse Engineering](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
