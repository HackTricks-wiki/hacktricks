# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Informazioni di base

XPC è un framework per la **comunicazione tra processi** su macOS e iOS. Fornisce meccanismi per effettuare **chiamate asincrone sicure tra processi**. XPC supporta **applicazioni con privilegi separati**, in cui ogni **componente** viene eseguito con **solo i permessi necessari**, limitando così i potenziali danni causati da un processo compromesso.<sup>[[1]](#references)</sup>

XPC utilizza una forma di comunicazione inter-processo (IPC), ovvero un insieme di metodi che consente a programmi diversi, in esecuzione sullo stesso sistema, di scambiarsi dati.

I principali vantaggi di XPC includono:

1. **Sicurezza**: suddividendo il lavoro tra processi diversi, a ciascun processo possono essere concessi solo i permessi necessari. Questo significa che, anche se un processo viene compromesso, la sua capacità di causare danni è limitata.
2. **Stabilità**: XPC aiuta a circoscrivere i crash al componente in cui si verificano. Se un processo va in crash, può essere riavviato senza influire sul resto del sistema.
3. **Prestazioni**: XPC facilita la concorrenza, consentendo di eseguire simultaneamente attività diverse in processi distinti.

Il principale **svantaggio** è che **suddividere un'applicazione in più processi** e farli comunicare tramite XPC comporta un overhead. Nei sistemi moderni, questo overhead è solitamente ridotto rispetto ai vantaggi in termini di sicurezza e stabilità.<sup>[[1]](#references)</sup>

## Servizi XPC specifici per un'applicazione

I componenti XPC di un'applicazione si trovano **all'interno dell'applicazione stessa**. Per esempio, in Safari si trovano in **`/Applications/Safari.app/Contents/XPCServices`**. Hanno l'estensione **`.xpc`** (come **`com.apple.Safari.SandboxBroker.xpc`**) e sono **a loro volta bundle**, con all'interno il binario principale e un `Info.plist`. Per esempio: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` e `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Un **componente XPC può avere entitlement e privilegi diversi** da altri componenti XPC o dal binario principale dell'applicazione. Un'eccezione è un servizio XPC configurato con **`JoinExistingSession`** impostato su `true` nel suo file **Info.plist**. In questo caso, il servizio XPC entra nella **stessa sessione di sicurezza dell'applicazione** che lo ha chiamato.<sup>[[4]](#references)</sup>

I servizi XPC vengono **avviati** da **launchd** quando necessario e possono essere **arrestati** al **completamento** delle loro attività, per liberare risorse di sistema. **I componenti XPC specifici di un'applicazione possono essere utilizzati solo dall'applicazione che li contiene**, riducendo così l'esposizione a potenziali vulnerabilità.<sup>[[2]](#references)</sup>

## Servizi XPC a livello di sistema

A differenza dei servizi specifici di un'applicazione, i servizi XPC a livello di sistema non sono limitati all'applicazione che li contiene. Potrebbero essere raggiungibili da client appartenenti a più utenti, a seconda del dominio launchd e dei controlli di autorizzazione del servizio. Questi servizi Mach gestiti da launchd devono essere **definiti in file plist** situati in directory come **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** o **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Questi file plist hanno una chiave **`MachServices`** che contiene il nome del servizio e una chiave **`Program`** che contiene il percorso del binario:

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

I servizi in **`LaunchDaemons`** vengono comunemente eseguiti come root. Di conseguenza, se un processo non privilegiato può raggiungere un metodo vulnerabile esposto da uno di questi servizi, potrebbe riuscire a elevare i propri privilegi.

## Oggetti XPC

- **`xpc_object_t`**

I payload delle richieste e delle risposte XPC sono comunemente oggetti dictionary, che semplificano la serializzazione e la deserializzazione. `libxpc.dylib` dichiara anche i tipi di dati necessari per verificare che i dati ricevuti abbiano il tipo previsto. Nell'API C ogni oggetto è un `xpc_object_t` (e il suo tipo può essere verificato usando `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Inoltre, è possibile usare la funzione `xpc_copy_description(object)` per ottenere una rappresentazione stringa dell'oggetto, utile per il debug.\
Questi oggetti dispongono anche di metodi da chiamare, come `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Gli oggetti `xpc_object_t` vengono creati chiamando una funzione `xpc_<objectType>_create`, che al suo interno chiama `_xpc_base_create(Class, Size)`, indicando la classe dell'oggetto (una delle `XPC_TYPE_*`) e la dimensione. Vengono aggiunti altri 40 byte per i metadati, quindi i dati dell'oggetto iniziano all'offset di 40 byte.\
Di conseguenza, `xpc_<objectType>_t` è una sorta di sottoclasse di `xpc_object_t`, che a sua volta sarebbe una sottoclasse di `os_object_t*`.

> [!WARNING]
> Si noti che spetta allo sviluppatore usare `xpc_dictionary_[get/set]_<objectType>` per ottenere o impostare il tipo e il valore effettivo di una chiave.

- **`xpc_pipe`**

Un **`xpc_pipe`** è una pipe FIFO che i processi possono usare per comunicare (la comunicazione usa messaggi Mach).\
È possibile creare un server XPC chiamando `xpc_pipe_create()` oppure `xpc_pipe_create_from_port()` per crearlo usando una porta Mach specifica. Per ricevere messaggi, è quindi possibile chiamare `xpc_pipe_receive` e `xpc_pipe_try_receive`.

Si noti che l'oggetto **`xpc_pipe`** è un **`xpc_object_t`** la cui struct contiene informazioni sulle due porte Mach usate e sul nome, se presente. Per esempio, nel proprio plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`, il daemon `secinitd` configura la pipe chiamata `com.apple.secinitd`.

Un esempio di **`xpc_pipe`** è la **bootstrap pipe** creata da **`launchd`**, che consente di condividere porte Mach.

- **`NSXPC*`**

Sono oggetti Objective-C di alto livello che astraggono le connessioni XPC.\
Inoltre, è più facile eseguire il debug di questi oggetti con DTrace rispetto ai precedenti.

- **`GCD Queues`**

XPC usa GCD per passare i messaggi e genera anche determinate dispatch queue, come `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Servizi XPC

Sono **bundle con estensione `.xpc`** situati nella cartella **`XPCServices`** di altri progetti; nel loro `Info.plist` hanno `CFBundlePackageType` impostato su **`XPC!`**.\
Questo file contiene altre chiavi di configurazione, come `ServiceType`, che può essere Application, User o System; `_SandboxProfile`, che può definire una sandbox; e `_AllowedClients`, che può indicare gli entitlement o l'identità necessari per contattare il servizio. Queste e altre opzioni configurano il servizio al suo avvio.<sup>[[2]](#references)</sup>

### Avvio di un servizio

L'app tenta di **connettersi** a un servizio XPC usando `xpc_connection_create_mach_service`; launchd individua quindi il daemon e avvia **`xpcproxy`**. **`xpcproxy`** applica le restrizioni configurate e avvia il servizio con i descrittori di file e le porte Mach forniti.<sup>[[3]](#references)</sup>

Per velocizzare la ricerca del servizio XPC, viene usata una cache.

È possibile tracciare le azioni di `xpcproxy` usando:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

La libreria XPC usa `kdebug` per registrare le azioni chiamando `xpc_ktrace_pid0` e `xpc_ktrace_pid1`. I codici che usa non sono documentati, quindi vanno aggiunti a `/usr/share/misc/trace.codes`. Hanno il prefisso `0x29`; per esempio, `0x29000004` corrisponde a `XPC_serializer_pack`.\
L'utility `xpcproxy` usa il prefisso `0x22`; per esempio: `0x2200001c: xpcproxy:will_do_preexec`.

## Audit degli helper XPC di tipo Application

Un `XPCService.ServiceType` con valore `Application` è un buon punto di partenza per l'audit degli helper forniti dai framework: elenca i bundle, conserva i servizi in esecuzione e controlla l'identificatore e gli entitlement dell'helper. Cerca sia in `/System/Library/Frameworks` sia in `/System/Library/PrivateFrameworks`; l'inventario esatto varia tra le versioni di macOS.<sup>[[7]](#references)</sup>

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

### Analizza il listener e ricostruisci un protocollo minimo

Individua `-[<delegate> listener:shouldAcceptNewConnection:]` nell'helper. Un percorso che imposta `exportedInterface` e `exportedObject`, riprende la connessione e restituisce `YES`/`1` senza verificare l'audit token, il code requirement o l'entitlement del peer espone l'interfaccia RPC a qualsiasi client in grado di risolvere il servizio. Questo dimostra solo la **raggiungibilità**: l'impatto richiede comunque un metodo esportato che esegua un'operazione privilegiata senza un'adeguata autorizzazione per client/metodo o che elabori in modo non sicuro input controllati dall'attaccante.<sup>[[7]](#references)</sup>

Ricostruisci solo i selector necessari per i test. I metadati dei selector Objective-C rivelano il numero di argomenti; gli usi degli argomenti nel decompiler aiutano di solito a precisarne i tipi (ad esempio, i valori passati a `-[EKEvent setStartDate:]` e `setEndDate:` sono `NSDate *`), mentre l'invocazione indiretta alla fine del metodo rivela i parametri del reply block. Per `NSXPCInterface` è sufficiente un protocollo locale parziale; non è necessario ricostruire l'intero protocollo privato.<sup>[[7]](#references)</sup>

### Connettersi con l'interfaccia ricostruita

Per un servizio XPC di un'applicazione, carica qualsiasi framework che definisca le classi private necessarie, crea la connessione con `initWithServiceName:`, assegna l'interfaccia remota ricostruita, installa gli handler per errori/interruzioni/invalidazioni e solo allora riprendila. Mantieni attivo il run loop per le risposte asincrone. Esegui di nuovo il client all'interno di un'applicazione sandboxed quando testi un confine sandbox: il successo di un client standalone non dimostra un sandbox escape.<sup>[[7]](#references)</sup>

<details>
<summary>Client Objective-C minimo</summary>

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

Compila con `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Usare gli errori di secure coding come oracoli di tipo

Un errore `NSCocoaErrorDomain`, ad esempio il codice `4101`, può nascondere l’eccezione di serializzazione utile. Cerca nel log unificato di macOS/Console il nome del servizio: l’eccezione identifica sia la classe imprevista sia le classi consentite per quell’argomento del selector. Per una risposta, estendi l’allowlist dell’interfaccia **lato client** con `setClasses:forSelector:argumentIndex:ofReply:`; con `ofReply:YES`, l’indice `0` indica il primo parametro del blocco di risposta, non il primo parametro del metodo.<sup>[[7]](#references)</sup>

Configura l’interfaccia prima di assegnarla alla connessione e chiamare `[c resume]`:<sup>[[7]](#references)</sup>

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

Anche il caso inverso è utile: se il server rifiuta un input Foundation e registra una singola classe privata consentita, il log rivela il tipo atteso sul wire e il relativo framework. Carica quel framework, esamina i metodi e le proprietà della classe per definire meglio i tipi generici `id` e costruisci dinamicamente l'oggetto privato. Gli argomenti di `NSInvocation` iniziano dall'indice `2`, perché gli indici `0` e `1` corrispondono agli argomenti nascosti `self` e `_cmd`.<sup>[[7]](#references)</sup>

<details>
<summary>Costruire un argomento privato con NSInvocation</summary>

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

Per il workflow correlato che riguarda i servizi Mach a livello di sistema registrati con launchd, vedi:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## Messaggi di eventi XPC

Le applicazioni possono **sottoscriversi** a diversi **messaggi** di eventi, consentendo di **avviarsi su richiesta** quando si verificano tali eventi. La **configurazione** di questi servizi viene effettuata nei file plist di **launchd**, situati nelle **stesse directory dei precedenti** e contenenti una chiave aggiuntiva **`LaunchEvent`**.

### Verifica del processo che si connette a XPC

Quando un processo prova a chiamare un metodo tramite una connessione XPC, il **servizio XPC dovrebbe verificare se il processo è autorizzato a connettersi**. Ecco alcuni metodi di verifica comuni e i relativi problemi:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorizzazione XPC

Apple consente anche alle app di **configurare i diritti di autorizzazione e il modo in cui i chiamanti li ottengono**, così che un processo con i diritti richiesti sia **autorizzato a chiamare un metodo** esposto dal servizio XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Per sniffare i messaggi XPC, puoi usare **xpcspy**, che utilizza **Frida**.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Un altro possibile strumento è **XPoCe2**.<sup>[[6]](#references)</sup>

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

Le funzionalità fornite da `RemoteXPC.framework` (da `libxpc`) consentono la comunicazione XPC tra host diversi.\
I servizi che supportano Remote XPC hanno la chiave `UsesRemoteXPC` nel proprio plist, come nel caso di `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Sebbene il servizio sia registrato con `launchd`, la funzionalità è fornita da `UserEventAgent` e dai suoi plugin `com.apple.remoted.plugin` e `com.apple.remoteservicediscovery.events.plugin`.

Inoltre, `RemoteServiceDiscovery.framework` ottiene informazioni da `com.apple.remoted.plugin`, esponendo funzioni come `get_device`, `get_unique_device` e `connect`.

Una volta che `connect` ha restituito il file descriptor del socket del servizio, è possibile usare la classe `remote_xpc_connection_*`.

È possibile ottenere informazioni sui servizi remoti tramite la CLI `/usr/libexec/remotectl`, usando comandi come:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

La comunicazione tra bridgeOS e l'host avviene tramite un'interfaccia IPv6 dedicata. `MultiverseSupport.framework` stabilisce socket i cui file descriptor vengono utilizzati per la comunicazione.\
È possibile individuare queste comunicazioni usando `netstat`, `nettop` o l'alternativa open source `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Creazione di servizi XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - Attaccare gli helper XPC di macOS: reverse engineering del protocollo](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
