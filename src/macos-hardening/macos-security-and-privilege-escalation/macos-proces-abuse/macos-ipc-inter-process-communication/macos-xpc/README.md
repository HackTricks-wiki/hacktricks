# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Informazioni di base

XPC, acronimo di XNU (il kernel utilizzato da macOS) inter-Process Communication, è un framework per la **comunicazione tra processi** su macOS e iOS. XPC fornisce un meccanismo per effettuare **chiamate a metodi sicure e asincrone tra processi diversi** nel sistema. Fa parte del paradigma di sicurezza di Apple e consente la **creazione di applicazioni con privilegi separati**, in cui ogni **componente** viene eseguito con **solo i permessi necessari** per svolgere il proprio lavoro, limitando così i potenziali danni causati da un processo compromesso.

XPC utilizza una forma di Inter-Process Communication (IPC), ovvero un insieme di metodi che consentono a programmi diversi in esecuzione sullo stesso sistema di scambiarsi dati.

I principali vantaggi di XPC includono:

1. **Sicurezza**: separando il lavoro in processi diversi, a ogni processo possono essere concessi solo i permessi di cui necessita. Ciò significa che, anche se un processo viene compromesso, la sua capacità di causare danni è limitata.
2. **Stabilità**: XPC aiuta a isolare i crash nel componente in cui si verificano. Se un processo va in crash, può essere riavviato senza influire sul resto del sistema.
3. **Prestazioni**: XPC consente una facile concorrenza, poiché task diversi possono essere eseguiti simultaneamente in processi differenti.

L'unico **svantaggio** è che **separare un'applicazione in diversi processi** facendoli comunicare tramite XPC è **meno efficiente**. Tuttavia, nei sistemi odierni questo è quasi impercettibile e i vantaggi sono maggiori.

## Application Specific XPC services

I componenti XPC di un'applicazione si trovano **all'interno dell'applicazione stessa.** Ad esempio, in Safari si trovano in **`/Applications/Safari.app/Contents/XPCServices`**. Hanno estensione **`.xpc`** (come **`com.apple.Safari.SandboxBroker.xpc`**) e sono **anch'essi bundle** con il binario principale al loro interno: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` e un `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Come si potrebbe immaginare, un **componente XPC avrà entitlement e privilegi diversi** rispetto agli altri componenti XPC o al binario principale dell'app. ECCETTO se un servizio XPC è configurato con [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) impostato su “True” nel suo file **`Info.plist`**. In questo caso, il servizio XPC verrà eseguito nella **stessa sessione di sicurezza dell'applicazione** che lo ha chiamato.

I servizi XPC vengono **avviati** da **launchd** quando necessario e **arrestati** una volta che tutti i task sono **completati**, per liberare risorse di sistema. I **componenti XPC specifici dell'applicazione** possono essere utilizzati **solo dall'applicazione**, riducendo così il rischio associato a potenziali vulnerabilità.

## System Wide XPC services

I servizi XPC a livello di sistema sono accessibili da tutti gli utenti. Questi servizi, di tipo launchd o Mach, devono essere **definiti in file plist** situati in directory specifiche come **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** o **`/Library/LaunchAgents`**.

Questi file plist avranno una chiave chiamata **`MachServices`** con il nome del servizio e una chiave **`Program`** con il percorso del binario:
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
Quelli in **`LaunchDameons`** vengono eseguiti da root. Quindi, se un processo senza privilegi può comunicare con uno di questi, potrebbe essere in grado di effettuare un'escalation dei privilegi.

## XPC Objects

- **`xpc_object_t`**

Ogni messaggio XPC è un oggetto dictionary che semplifica la serializzazione e la deserializzazione. Inoltre, `libxpc.dylib` dichiara la maggior parte dei data type, quindi è possibile verificare che i dati ricevuti siano del tipo previsto. Nell'API C ogni oggetto è un `xpc_object_t` (e il suo tipo può essere verificato usando `xpc_get_type(object)`).\
Inoltre, la funzione `xpc_copy_description(object)` può essere usata per ottenere una rappresentazione sotto forma di stringa dell'oggetto, utile per il debugging.\
Questi oggetti hanno anche alcuni metodi da chiamare, come `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Gli `xpc_object_t` vengono creati chiamando la funzione `xpc_<objetType>_create`, che internamente chiama `_xpc_base_create(Class, Size)`, dove vengono indicati il tipo della classe dell'oggetto (uno tra `XPC_TYPE_*`) e la sua dimensione (alla dimensione verranno aggiunti 40B extra per i metadata). Ciò significa che i dati dell'oggetto inizieranno all'offset 40B.\
Pertanto, `xpc_<objectType>_t` è una sorta di sottoclasse di `xpc_object_t`, che a sua volta sarebbe una sottoclasse di `os_object_t*`.

> [!WARNING]
> Si noti che dovrebbe essere lo sviluppatore a usare `xpc_dictionary_[get/set]_<objectType>` per ottenere o impostare il tipo e il valore effettivo di una chiave.

- **`xpc_pipe`**

Un **`xpc_pipe`** è una FIFO pipe che i processi possono usare per comunicare (la comunicazione utilizza messaggi Mach).\
È possibile creare un XPC server chiamando `xpc_pipe_create()` o `xpc_pipe_create_from_port()` per crearlo usando una porta Mach specifica. In seguito, per ricevere messaggi è possibile chiamare `xpc_pipe_receive` e `xpc_pipe_try_receive`.

Si noti che l'oggetto **`xpc_pipe`** è un **`xpc_object_t`** con informazioni nella sua struct sulle due porte Mach utilizzate e sul nome (se presente). Il nome, ad esempio, il daemon `secinitd` nel suo plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` configura la pipe chiamata `com.apple.secinitd`.

Un esempio di **`xpc_pipe`** è la **bootstrap pipe** creata da **`launchd`**, che consente di condividere porte Mach.

- **`NSXPC*`**

Questi sono oggetti Objective-C di alto livello che consentono l'astrazione delle connessioni XPC.\
Inoltre, questi oggetti sono più facili da sottoporre a debugging con DTrace rispetto ai precedenti.

- **`GCD Queues`**

XPC usa GCD per passare i messaggi; inoltre, genera alcune dispatch queue come `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Si tratta di **bundle con estensione `.xpc`** situati nella cartella **`XPCServices`** di altri progetti e, nel loro `Info.plist`, hanno `CFBundlePackageType` impostato su **`XPC!`**.\
Questo file contiene altre chiavi di configurazione come `ServiceType`, che può essere Application, User o System, oppure `_SandboxProfile`, che può definire una sandbox, o `_AllowedClients`, che potrebbe indicare gli entitlement o l'ID necessari per contattare il servizio. Queste e altre opzioni di configurazione saranno utili per configurare il servizio al momento del suo avvio.

### Starting a Service

L'app tenta di **connettersi** a un XPC service usando `xpc_connection_create_mach_service`, quindi launchd individua il daemon e avvia **`xpcproxy`**. **`xpcproxy`** applica le restrizioni configurate e avvia il servizio con i file descriptor e le porte Mach forniti.

Per migliorare la velocità di ricerca dell'XPC service, viene utilizzata una cache.

È possibile tracciare le azioni di `xpcproxy` usando:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
La libreria XPC usa `kdebug` per registrare le azioni chiamando `xpc_ktrace_pid0` e `xpc_ktrace_pid1`. I codici che usa non sono documentati, quindi è necessario aggiungerli a `/usr/share/misc/trace.codes`. Hanno il prefisso `0x29` e, ad esempio, uno di essi è `0x29000004`: `XPC_serializer_pack`.\
L'utility `xpcproxy` usa il prefisso `0x22`, ad esempio: `0x2200001c: xpcproxy:will_do_preexec`.

## Messaggi degli eventi XPC

Le applicazioni possono **sottoscriversi** a diversi **messaggi** di evento, consentendo loro di essere **avviate on-demand** quando tali eventi si verificano. Il **setup** di questi servizi viene eseguito nei **file plist di launchd**, situati nelle **stesse directory di quelli precedenti** e contenenti una chiave aggiuntiva **`LaunchEvent`**.

### Verifica del processo di connessione XPC

Quando un processo tenta di chiamare un metodo tramite una connessione XPC, il **servizio XPC dovrebbe verificare se quel processo è autorizzato a connettersi**. Ecco i metodi comuni per eseguire questa verifica e le insidie più comuni:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorizzazione XPC

Apple consente inoltre alle app di **configurare alcuni diritti e come ottenerli**, in modo che, se il processo chiamante li possiede, **sia autorizzato a chiamare un metodo** del servizio XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Per intercettare i messaggi XPC puoi usare [**xpcspy**](https://github.com/hot3eed/xpcspy), che utilizza **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Un altro possibile strumento da usare è [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

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
## Client all'interno di un codice Dylb
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

Questa funzionalità fornita da `RemoteXPC.framework` (da `libxpc`) consente di comunicare tramite XPC attraverso host diversi.\
I servizi che supportano il remote XPC avranno nel loro plist la chiave UsesRemoteXPC, come nel caso di `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Tuttavia, sebbene il servizio venga registrato con `launchd`, è `UserEventAgent`, con i plugin `com.apple.remoted.plugin` e `com.apple.remoteservicediscovery.events.plugin`, a fornire la funzionalità.

Inoltre, `RemoteServiceDiscovery.framework` consente di ottenere informazioni da `com.apple.remoted.plugin`, esponendo funzioni come `get_device`, `get_unique_device`, `connect`...

Una volta usato connect e ottenuto il socket `fd` del servizio, è possibile usare la classe `remote_xpc_connection_*`.

È possibile ottenere informazioni sui servizi remoti usando il tool CLI `/usr/libexec/remotectl` con parametri come:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
La comunicazione tra BridgeOS e l'host avviene tramite un'interfaccia IPv6 dedicata. `MultiverseSupport.framework` consente di stabilire socket il cui `fd` verrà utilizzato per comunicare.\
È possibile individuare queste comunicazioni usando `netstat`, `nettop` oppure l'opzione open source, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
