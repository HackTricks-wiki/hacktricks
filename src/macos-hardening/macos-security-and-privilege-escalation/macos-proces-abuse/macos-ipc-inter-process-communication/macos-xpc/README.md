# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Informazioni di base

XPC, che sta per comunicazione inter-processo XNU (il kernel utilizzato da macOS), è un framework per **la comunicazione tra processi** su macOS e iOS. XPC fornisce un meccanismo per effettuare **chiamate a metodi sicure e asincrone tra diversi processi** sul sistema. Fa parte del paradigma di sicurezza di Apple, consentendo la **creazione di applicazioni separate per privilegi** in cui ogni **componente** viene eseguito con **solo i permessi necessari** per svolgere il proprio lavoro, limitando così il potenziale danno derivante da un processo compromesso.

XPC utilizza una forma di comunicazione inter-processo (IPC), che è un insieme di metodi per diversi programmi in esecuzione sullo stesso sistema per inviare dati avanti e indietro.

I principali vantaggi di XPC includono:

1. **Sicurezza**: Separando il lavoro in diversi processi, a ciascun processo possono essere concessi solo i permessi necessari. Ciò significa che anche se un processo è compromesso, ha una capacità limitata di fare danni.
2. **Stabilità**: XPC aiuta a isolare i crash al componente in cui si verificano. Se un processo si blocca, può essere riavviato senza influenzare il resto del sistema.
3. **Prestazioni**: XPC consente una facile concorrenza, poiché diversi compiti possono essere eseguiti simultaneamente in processi diversi.

L'unico **svantaggio** è che **separare un'applicazione in più processi** facendoli comunicare tramite XPC è **meno efficiente**. Ma nei sistemi odierni questo non è quasi percepibile e i benefici sono migliori.

## Servizi XPC specifici per l'applicazione

I componenti XPC di un'applicazione sono **all'interno dell'applicazione stessa.** Ad esempio, in Safari puoi trovarli in **`/Applications/Safari.app/Contents/XPCServices`**. Hanno estensione **`.xpc`** (come **`com.apple.Safari.SandboxBroker.xpc`**) e sono **anche bundle** con il binario principale al suo interno: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` e un `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Come potresti pensare, un **componente XPC avrà diritti e privilegi diversi** rispetto agli altri componenti XPC o al binario principale dell'app. ECCETTO se un servizio XPC è configurato con [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) impostato su “True” nel suo **Info.plist**. In questo caso, il servizio XPC verrà eseguito nella **stessa sessione di sicurezza dell'applicazione** che lo ha chiamato.

I servizi XPC sono **avviati** da **launchd** quando necessario e **chiusi** una volta completati tutti i compiti per liberare risorse di sistema. **I componenti XPC specifici per l'applicazione possono essere utilizzati solo dall'applicazione**, riducendo così il rischio associato a potenziali vulnerabilità.

## Servizi XPC a livello di sistema

I servizi XPC a livello di sistema sono accessibili a tutti gli utenti. Questi servizi, sia launchd che di tipo Mach, devono essere **definiti in file plist** situati in directory specifiche come **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, o **`/Library/LaunchAgents`**.

Questi file plist avranno una chiave chiamata **`MachServices`** con il nome del servizio, e una chiave chiamata **`Program`** con il percorso del binario:
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
Quelli in **`LaunchDameons`** vengono eseguiti da root. Quindi, se un processo non privilegiato può comunicare con uno di questi, potrebbe essere in grado di elevare i privilegi.

## Oggetti XPC

- **`xpc_object_t`**

Ogni messaggio XPC è un oggetto dizionario che semplifica la serializzazione e deserializzazione. Inoltre, `libxpc.dylib` dichiara la maggior parte dei tipi di dati, quindi è possibile garantire che i dati ricevuti siano del tipo previsto. Nell'API C, ogni oggetto è un `xpc_object_t` (e il suo tipo può essere verificato usando `xpc_get_type(object)`).\
Inoltre, la funzione `xpc_copy_description(object)` può essere utilizzata per ottenere una rappresentazione stringa dell'oggetto che può essere utile per scopi di debug.\
Questi oggetti hanno anche alcuni metodi da chiamare come `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Gli `xpc_object_t` vengono creati chiamando la funzione `xpc_<objetType>_create`, che internamente chiama `_xpc_base_create(Class, Size)` dove viene indicato il tipo della classe dell'oggetto (uno di `XPC_TYPE_*`) e la sua dimensione (alcuni extra 40B verranno aggiunti alla dimensione per i metadati). Ciò significa che i dati dell'oggetto inizieranno all'offset di 40B.\
Pertanto, il `xpc_<objectType>_t` è una sorta di sottoclasse di `xpc_object_t` che sarebbe una sottoclasse di `os_object_t*`.

> [!WARNING]
> Nota che dovrebbe essere lo sviluppatore a utilizzare `xpc_dictionary_[get/set]_<objectType>` per ottenere o impostare il tipo e il valore reale di una chiave.

- **`xpc_pipe`**

Un **`xpc_pipe`** è un tubo FIFO che i processi possono utilizzare per comunicare (la comunicazione utilizza messaggi Mach).\
È possibile creare un server XPC chiamando `xpc_pipe_create()` o `xpc_pipe_create_from_port()` per crearlo utilizzando una porta Mach specifica. Poi, per ricevere messaggi, è possibile chiamare `xpc_pipe_receive` e `xpc_pipe_try_receive`.

Nota che l'oggetto **`xpc_pipe`** è un **`xpc_object_t`** con informazioni nella sua struct riguardo le due porte Mach utilizzate e il nome (se presente). Il nome, ad esempio, il demone `secinitd` nel suo plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` configura il tubo chiamato `com.apple.secinitd`.

Un esempio di **`xpc_pipe`** è il **bootstrap pipe** creato da **`launchd`** che rende possibile la condivisione delle porte Mach.

- **`NSXPC*`**

Questi sono oggetti di alto livello Objective-C che consentono l'astrazione delle connessioni XPC.\
Inoltre, è più facile eseguire il debug di questi oggetti con DTrace rispetto a quelli precedenti.

- **`GCD Queues`**

XPC utilizza GCD per inviare messaggi, inoltre genera alcune code di dispatch come `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Servizi XPC

Questi sono **pacchetti con estensione `.xpc`** situati all'interno della cartella **`XPCServices`** di altri progetti e nel `Info.plist` hanno il `CFBundlePackageType` impostato su **`XPC!`**.\
Questo file ha altre chiavi di configurazione come `ServiceType` che può essere Application, User, System o `_SandboxProfile` che può definire un sandbox o `_AllowedClients` che potrebbe indicare diritti o ID richiesti per contattare il ser. queste e altre opzioni di configurazione saranno utili per configurare il servizio al momento del lancio.

### Avviare un Servizio

L'app tenta di **connettersi** a un servizio XPC utilizzando `xpc_connection_create_mach_service`, quindi launchd localizza il demone e avvia **`xpcproxy`**. **`xpcproxy`** applica le restrizioni configurate e genera il servizio con i FDs e le porte Mach forniti.

Per migliorare la velocità di ricerca del servizio XPC, viene utilizzata una cache.

È possibile tracciare le azioni di `xpcproxy` utilizzando:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
La libreria XPC utilizza `kdebug` per registrare azioni chiamando `xpc_ktrace_pid0` e `xpc_ktrace_pid1`. I codici che utilizza non sono documentati, quindi è necessario aggiungerli in `/usr/share/misc/trace.codes`. Hanno il prefisso `0x29` e, ad esempio, uno è `0x29000004`: `XPC_serializer_pack`.\
L'utilità `xpcproxy` utilizza il prefisso `0x22`, ad esempio: `0x2200001c: xpcproxy:will_do_preexec`.

## Messaggi di Evento XPC

Le applicazioni possono **iscriversi** a diversi **messaggi di evento**, consentendo loro di essere **iniziati su richiesta** quando si verificano tali eventi. La **configurazione** per questi servizi è effettuata nei file **plist di launchd**, situati nelle **stesse directory di quelli precedenti** e contenenti una chiave **`LaunchEvent`** aggiuntiva.

### Controllo del Processo di Connessione XPC

Quando un processo tenta di chiamare un metodo tramite una connessione XPC, il **servizio XPC dovrebbe controllare se quel processo è autorizzato a connettersi**. Ecco i modi comuni per controllarlo e le insidie comuni:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorizzazione XPC

Apple consente anche alle app di **configurare alcuni diritti e come ottenerli**, quindi se il processo chiamante li possiede, sarebbe **autorizzato a chiamare un metodo** dal servizio XPC:

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Per intercettare i messaggi XPC, puoi utilizzare [**xpcspy**](https://github.com/hot3eed/xpcspy) che utilizza **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Un altro strumento possibile da utilizzare è [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

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

Questa funzionalità fornita da `RemoteXPC.framework` (da `libxpc`) consente di comunicare tramite XPC tra diversi host.\
I servizi che supportano XPC remoto avranno nel loro plist la chiave UsesRemoteXPC come nel caso di `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Tuttavia, sebbene il servizio sia registrato con `launchd`, è `UserEventAgent` con i plugin `com.apple.remoted.plugin` e `com.apple.remoteservicediscovery.events.plugin` a fornire la funzionalità.

Inoltre, il `RemoteServiceDiscovery.framework` consente di ottenere informazioni dal `com.apple.remoted.plugin` esponendo funzioni come `get_device`, `get_unique_device`, `connect`...

Una volta utilizzato connect e raccolto il socket `fd` del servizio, è possibile utilizzare la classe `remote_xpc_connection_*`.

È possibile ottenere informazioni sui servizi remoti utilizzando lo strumento cli `/usr/libexec/remotectl` utilizzando parametri come:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
La comunicazione tra BridgeOS e l'host avviene attraverso un'interfaccia IPv6 dedicata. Il `MultiverseSupport.framework` consente di stabilire socket i cui `fd` saranno utilizzati per comunicare.\
È possibile trovare queste comunicazioni utilizzando `netstat`, `nettop` o l'opzione open source, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
