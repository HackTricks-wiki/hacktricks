# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Informazioni di base

XPC è un framework per la **comunicazione tra processi** su macOS e iOS. Fornisce meccanismi per effettuare **chiamate sicure e asincrone tra processi**. XPC supporta le **applicazioni con privilegi separati**, in cui ogni **componente** viene eseguito con **solo i permessi necessari**, limitando così i potenziali danni causati da un processo compromesso.<sup>[[1]](#references)</sup>

XPC utilizza una forma di Inter-Process Communication (IPC), ovvero un insieme di metodi che consente a diversi programmi in esecuzione sullo stesso sistema di scambiarsi dati.

I principali vantaggi di XPC includono:

1. **Sicurezza**: separando il lavoro in processi diversi, a ogni processo possono essere concessi solo i permessi necessari. Ciò significa che, anche se un processo viene compromesso, la sua capacità di causare danni è limitata.
2. **Stabilità**: XPC aiuta a isolare i crash nel componente in cui si verificano. Se un processo si arresta, può essere riavviato senza influire sul resto del sistema.
3. **Prestazioni**: XPC facilita la concorrenza, poiché attività diverse possono essere eseguite simultaneamente in processi differenti.

Il principale **svantaggio** è che **separare un'applicazione in diversi processi** e farli comunicare tramite XPC aggiunge overhead. Sui sistemi moderni questo overhead è generalmente ridotto rispetto ai vantaggi in termini di sicurezza e stabilità.<sup>[[1]](#references)</sup>

## Servizi XPC specifici dell'applicazione

I componenti XPC di un'applicazione si trovano **all'interno dell'applicazione stessa**. Ad esempio, in Safari è possibile trovarli in **`/Applications/Safari.app/Contents/XPCServices`**. Hanno l'estensione **`.xpc`** (come **`com.apple.Safari.SandboxBroker.xpc`**) e sono **anch'essi bundle**, contenenti il binario principale e un `Info.plist`. Ad esempio: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` e `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Un **componente XPC può avere entitlement e privilegi diversi** rispetto ad altri componenti XPC o al binario principale dell'applicazione. Un'eccezione è rappresentata da un servizio XPC configurato con **`JoinExistingSession`** impostato su `true` nel relativo file **Info.plist**. In questo caso, il servizio XPC entra nella **stessa sessione di sicurezza dell'applicazione** che lo ha chiamato.<sup>[[4]](#references)</sup>

I servizi XPC vengono **avviati** da **launchd** quando necessario e possono essere **arrestati** al **completamento** delle loro attività per liberare risorse di sistema. I **componenti XPC specifici dell'applicazione possono essere utilizzati solo dall'applicazione che li contiene**, riducendo così l'esposizione a potenziali vulnerabilità.<sup>[[2]](#references)</sup>

## Servizi XPC a livello di sistema

A differenza dei servizi specifici dell'applicazione, i servizi XPC a livello di sistema non sono limitati all'applicazione che li contiene. Possono essere raggiungibili da client appartenenti a più utenti, a seconda del dominio launchd e dei controlli di autorizzazione propri del servizio. Questi servizi Mach gestiti da launchd devono essere **definiti in file plist** situati in directory come **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** o **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Questi file plist contengono una chiave **`MachServices`** con il nome del servizio e una chiave **`Program`** contenente il percorso del binario:
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
I servizi in **`LaunchDaemons`** vengono comunemente eseguiti come root. Pertanto, se un processo non privilegiato può raggiungere un metodo vulnerabile esposto da uno di questi servizi, potrebbe essere in grado di effettuare un'escalation dei privilegi.

## XPC Objects

- **`xpc_object_t`**

I payload delle richieste e delle risposte XPC sono comunemente oggetti dizionario, che semplificano la serializzazione e la deserializzazione. `libxpc.dylib` dichiara inoltre i tipi di dati necessari per verificare che i dati ricevuti abbiano il tipo previsto. Nell'API C ogni oggetto è un `xpc_object_t` (e il suo tipo può essere verificato usando `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Inoltre, la funzione `xpc_copy_description(object)` può essere utilizzata per ottenere una rappresentazione testuale dell'oggetto, utile per il debugging.\
Questi oggetti dispongono anche di alcuni metodi da chiamare, come `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Gli oggetti `xpc_object_t` vengono creati chiamando una funzione `xpc_<objectType>_create`, che internamente chiama `_xpc_base_create(Class, Size)`, indicando la classe dell'oggetto (una delle `XPC_TYPE_*`) e la dimensione. Per i metadata vengono aggiunti altri 40 byte, quindi i dati dell'oggetto iniziano all'offset 40 byte.\
Pertanto, `xpc_<objectType>_t` è una sorta di sottoclasse di `xpc_object_t`, che a sua volta sarebbe una sottoclasse di `os_object_t*`.

> [!WARNING]
> Si noti che dovrebbe essere lo sviluppatore a utilizzare `xpc_dictionary_[get/set]_<objectType>` per ottenere o impostare il tipo e il valore effettivo di una chiave.

- **`xpc_pipe`**

Un **`xpc_pipe`** è una FIFO che i processi possono utilizzare per comunicare (la comunicazione usa messaggi Mach).\
È possibile creare un server XPC chiamando `xpc_pipe_create()` o `xpc_pipe_create_from_port()` per crearlo usando una porta Mach specifica. Per ricevere messaggi è quindi possibile chiamare `xpc_pipe_receive` e `xpc_pipe_try_receive`.

Si noti che l'oggetto **`xpc_pipe`** è un **`xpc_object_t`** con informazioni nella propria struct sulle due porte Mach utilizzate e sul nome (se presente). Il nome, ad esempio, nel proprio plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` il daemon `secinitd` configura la pipe chiamata `com.apple.secinitd`.

Un esempio di **`xpc_pipe`** è la **bootstrap pipe** creata da **`launchd`**, che consente di condividere porte Mach.

- **`NSXPC*`**

Si tratta di oggetti Objective-C di alto livello che astraggono le connessioni XPC.\
Inoltre, questi oggetti sono più facili da sottoporre a debugging con DTrace rispetto ai precedenti.

- **`GCD Queues`**

XPC utilizza GCD per passare i messaggi; inoltre, genera alcune dispatch queue come `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Si tratta di **bundle con estensione `.xpc`** situati nella cartella **`XPCServices`** di altri progetti e nel relativo `Info.plist` hanno `CFBundlePackageType` impostato su **`XPC!`**.\
Questo file contiene altre chiavi di configurazione, come `ServiceType`, che può essere Application, User o System; `_SandboxProfile`, che può definire una sandbox; e `_AllowedClients`, che può indicare gli entitlements o l'identità necessari per contattare il servizio. Queste e altre opzioni configurano il servizio quando viene avviato.<sup>[[2]](#references)</sup>

### Avvio di un servizio

L'app tenta di **connettersi** a un servizio XPC usando `xpc_connection_create_mach_service`; launchd individua quindi il daemon e avvia **`xpcproxy`**. **`xpcproxy`** applica le restrizioni configurate e avvia il servizio con i file descriptor e le porte Mach forniti.<sup>[[3]](#references)</sup>

Per migliorare la velocità della ricerca del servizio XPC, viene utilizzata una cache.

È possibile tracciare le azioni di `xpcproxy` usando:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
La libreria XPC usa `kdebug` per registrare le azioni chiamando `xpc_ktrace_pid0` e `xpc_ktrace_pid1`. I codici che utilizza non sono documentati, quindi devono essere aggiunti a `/usr/share/misc/trace.codes`. Hanno il prefisso `0x29`; ad esempio, `0x29000004` è `XPC_serializer_pack`.\
L'utility `xpcproxy` usa il prefisso `0x22`, ad esempio: `0x2200001c: xpcproxy:will_do_preexec`.

## Messaggi degli eventi XPC

Le applicazioni possono **sottoscriversi** a diversi **messaggi** di eventi, consentendo loro di essere **avviate su richiesta** quando tali eventi si verificano. La **configurazione** di questi servizi viene eseguita nei **file plist di launchd**, situati nelle **stesse directory di quelli precedenti** e contenenti una chiave aggiuntiva **`LaunchEvent`**.

### Verifica del processo di connessione XPC

Quando un processo tenta di chiamare un metodo tramite una connessione XPC, il **servizio XPC dovrebbe verificare se tale processo è autorizzato a connettersi**. Di seguito sono riportati metodi di verifica comuni e i relativi svantaggi:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorizzazione XPC

Apple consente inoltre alle app di **configurare i diritti di autorizzazione e il modo in cui i chiamanti li ottengono**, in modo che un processo con i diritti richiesti sia **autorizzato a chiamare un metodo** esposto dal servizio XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Per intercettare i messaggi XPC, puoi usare **xpcspy**, che utilizza **Frida**.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Un altro possibile tool è **XPoCe2**.<sup>[[6]](#references)</sup>

## Esempio di codice C per la comunicazione XPC

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
## Esempio di codice Objective-C per la comunicazione XPC

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
## Client all'interno di una Dylib
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

La funzionalità fornita da `RemoteXPC.framework` (da `libxpc`) consente la comunicazione XPC tra host diversi.\
I servizi che supportano Remote XPC hanno la chiave `UsesRemoteXPC` nel proprio plist, come nel caso di `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Sebbene il servizio sia registrato con `launchd`, `UserEventAgent` e i suoi plugin `com.apple.remoted.plugin` e `com.apple.remoteservicediscovery.events.plugin` forniscono la funzionalità.

Inoltre, `RemoteServiceDiscovery.framework` ottiene informazioni da `com.apple.remoted.plugin`, esponendo funzioni come `get_device`, `get_unique_device` e `connect`.

Una volta che `connect` ha restituito il file descriptor del socket del servizio, è possibile utilizzare la classe `remote_xpc_connection_*`.

È possibile ottenere informazioni sui servizi remoti con la CLI `/usr/libexec/remotectl` usando comandi come:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
La comunicazione tra bridgeOS e l'host avviene tramite un'interfaccia IPv6 dedicata. `MultiverseSupport.framework` stabilisce socket i cui file descriptor vengono utilizzati per la comunicazione.\
È possibile individuare queste comunicazioni utilizzando `netstat`, `nettop` o l'alternativa open-source `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Creazione di servizi XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
