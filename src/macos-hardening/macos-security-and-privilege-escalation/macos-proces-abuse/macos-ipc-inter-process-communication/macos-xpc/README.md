# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Informations de base

XPC est un framework pour la **communication entre processus** sur macOS et iOS. Il fournit des mécanismes permettant d'effectuer des **appels sûrs et asynchrones entre processus**. XPC prend en charge les **applications à privilèges séparés**, dans lesquelles chaque **composant** s'exécute avec **uniquement les permissions dont il a besoin**, limitant ainsi les dommages potentiels causés par un processus compromis.<sup>[[1]](#references)</sup>

XPC utilise une forme de communication inter-processus (IPC), qui est un ensemble de méthodes permettant à différents programmes exécutés sur le même système de s'échanger des données.

Les principaux avantages de XPC sont les suivants :

1. **Sécurité** : En séparant le travail entre différents processus, chaque processus peut recevoir uniquement les permissions dont il a besoin. Ainsi, même si un processus est compromis, sa capacité à causer des dommages reste limitée.
2. **Stabilité** : XPC aide à isoler les crashs dans le composant où ils se produisent. Si un processus crash, il peut être redémarré sans affecter le reste du système.
3. **Performance** : XPC facilite la concurrence, car différentes tâches peuvent être exécutées simultanément dans différents processus.

Le principal **inconvénient** est que **séparer une application en plusieurs processus** et les faire communiquer via XPC ajoute une surcharge. Sur les systèmes modernes, cette surcharge est généralement faible par rapport aux avantages en matière de sécurité et de stabilité.<sup>[[1]](#references)</sup>

## Services XPC spécifiques aux applications

Les composants XPC d'une application se trouvent **à l'intérieur de l'application elle-même**. Par exemple, dans Safari, vous pouvez les trouver dans **`/Applications/Safari.app/Contents/XPCServices`**. Ils ont l'extension **`.xpc`** (comme **`com.apple.Safari.SandboxBroker.xpc`**) et sont **également des bundles**, contenant le binaire principal et un fichier `Info.plist`. Par exemple : `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` et `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Un **composant XPC peut avoir des entitlements et des privilèges différents** de ceux des autres composants XPC ou du binaire principal de l'application. Une exception concerne un service XPC configuré avec **`JoinExistingSession`** défini sur `true` dans son fichier **Info.plist**. Dans ce cas, le service XPC rejoint la **même session de sécurité que l'application** qui l'a appelé.<sup>[[4]](#references)</sup>

Les services XPC sont **démarrés** par **launchd** lorsque cela est nécessaire et peuvent être **arrêtés** une fois leurs tâches **terminées**, afin de libérer des ressources système. **Les composants XPC spécifiques aux applications ne peuvent être utilisés que par l'application qui les contient**, ce qui réduit l'exposition aux vulnérabilités potentielles.<sup>[[2]](#references)</sup>

## Services XPC à l'échelle du système

Contrairement aux services spécifiques aux applications, les services XPC à l'échelle du système ne sont pas limités à l'application qui les contient. Ils peuvent être accessibles à des clients appartenant à plusieurs utilisateurs, selon le domaine launchd et les propres contrôles d'autorisation du service. Ces services Mach gérés par launchd doivent être **définis dans des fichiers plist** situés dans des répertoires tels que **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ou **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Ces fichiers plist possèdent une clé **`MachServices`** contenant le nom du service et une clé **`Program`** contenant le chemin vers le binaire :
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
Les services dans **`LaunchDaemons`** s’exécutent généralement avec les privilèges de root. Par conséquent, si un processus non privilégié peut atteindre une méthode vulnérable exposée par l’un de ces services, il peut être en mesure d’élever ses privilèges.

## Objets XPC

- **`xpc_object_t`**

Les payloads de requête et de réponse XPC sont généralement des objets dictionnaire, ce qui simplifie la sérialisation et la désérialisation. `libxpc.dylib` déclare également les types de données nécessaires pour vérifier que les données reçues ont le type attendu. Dans l’API C, chaque objet est un `xpc_object_t` (et son type peut être vérifié à l’aide de `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
De plus, la fonction `xpc_copy_description(object)` peut être utilisée pour obtenir une représentation sous forme de chaîne de l’objet, ce qui peut être utile à des fins de debugging.\
Ces objets disposent également de certaines méthodes pouvant être appelées, comme `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Les objets `xpc_object_t` sont créés en appelant une fonction `xpc_<objectType>_create`, qui appelle en interne `_xpc_base_create(Class, Size)`, en indiquant la classe de l’objet (l’une des `XPC_TYPE_*`) et sa taille. 40 octets supplémentaires sont ajoutés pour les métadonnées, de sorte que les données de l’objet commencent à l’offset de 40 octets.\
Par conséquent, `xpc_<objectType>_t` est une sorte de sous-classe de `xpc_object_t`, qui serait elle-même une sous-classe de `os_object_t*`.

> [!WARNING]
> Notez que c’est le développeur qui doit utiliser `xpc_dictionary_[get/set]_<objectType>` pour obtenir ou définir le type et la valeur réelle d’une clé.

- **`xpc_pipe`**

Un **`xpc_pipe`** est un tuyau FIFO que les processus peuvent utiliser pour communiquer (la communication utilise des messages Mach).\
Il est possible de créer un serveur XPC en appelant `xpc_pipe_create()` ou `xpc_pipe_create_from_port()` pour le créer à l’aide d’un port Mach spécifique. Ensuite, pour recevoir des messages, il est possible d’appeler `xpc_pipe_receive` et `xpc_pipe_try_receive`.

Notez que l’objet **`xpc_pipe`** est un **`xpc_object_t`** contenant dans sa structure des informations sur les deux ports Mach utilisés et sur le nom, le cas échéant. Le nom, par exemple, est configuré par le daemon `secinitd` dans son plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` pour le pipe appelé `com.apple.secinitd`.

Un exemple d’**`xpc_pipe`** est le **bootstrap pipe** créé par **`launchd`**, qui permet de partager des ports Mach.

- **`NSXPC*`**

Il s’agit d’objets Objective-C de haut niveau qui abstraient les connexions XPC.\
De plus, il est plus facile de debugger ces objets avec DTrace que les précédents.

- **`GCD Queues`**

XPC utilise GCD pour transmettre les messages. Il génère également certaines dispatch queues comme `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Services XPC

Il s’agit de **bundles portant l’extension `.xpc`**, situés dans le dossier **`XPCServices`** d’autres projets, et dont le `CFBundlePackageType` est défini sur **`XPC!`** dans le `Info.plist`.\
Ce fichier contient d’autres clés de configuration, telles que `ServiceType`, qui peut être Application, User ou System ; `_SandboxProfile`, qui peut définir une sandbox ; et `_AllowedClients`, qui peut indiquer les entitlements ou l’identité nécessaires pour contacter le service. Ces options, ainsi que d’autres, configurent le service lors de son lancement.<sup>[[2]](#references)</sup>

### Démarrage d’un service

L’application tente de **se connecter** à un service XPC à l’aide de `xpc_connection_create_mach_service` ; launchd localise ensuite le daemon et démarre **`xpcproxy`**. **`xpcproxy`** applique les restrictions configurées et lance le service avec les descripteurs de fichiers et les ports Mach fournis.<sup>[[3]](#references)</sup>

Afin d’accélérer la recherche du service XPC, un cache est utilisé.

Il est possible de tracer les actions de `xpcproxy` à l’aide de :
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
La bibliothèque XPC utilise `kdebug` pour journaliser les actions en appelant `xpc_ktrace_pid0` et `xpc_ktrace_pid1`. Les codes qu’elle utilise ne sont pas documentés ; ils doivent donc être ajoutés à `/usr/share/misc/trace.codes`. Ils ont le préfixe `0x29` ; par exemple, `0x29000004` correspond à `XPC_serializer_pack`.\
L’utilitaire `xpcproxy` utilise le préfixe `0x22`, par exemple : `0x2200001c: xpcproxy:will_do_preexec`.

## Messages d’événements XPC

Les applications peuvent **s’abonner** à différents **messages** d’événements, ce qui permet de les **déclencher à la demande** lorsque de tels événements se produisent. La **configuration** de ces services est effectuée dans des **fichiers plist de launchd**, situés dans les **mêmes répertoires que les précédents** et contenant une clé **`LaunchEvent`** supplémentaire.

### Vérification du processus de connexion XPC

Lorsqu’un processus tente d’appeler une méthode via une connexion XPC, le **service XPC doit vérifier si ce processus est autorisé à se connecter**. Voici des méthodes de vérification courantes ainsi que leurs pièges :


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorisation XPC

Apple permet également aux applications de **configurer les droits d’autorisation et la manière dont les appelants les obtiennent**, afin qu’un processus disposant des droits requis soit **autorisé à appeler une méthode** exposée par le service XPC :


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Pour sniffer les messages XPC, vous pouvez utiliser **xpcspy**, qui utilise **Frida**.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Un autre outil possible est **XPoCe2**.<sup>[[6]](#references)</sup>

## Exemple de code C de communication XPC

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
## Exemple de code Objective-C de communication XPC

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
## Client à l’intérieur d’une Dylib
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

La fonctionnalité fournie par `RemoteXPC.framework` (depuis `libxpc`) permet la communication XPC entre différents hôtes.\
Les services qui prennent en charge le remote XPC possèdent la clé `UsesRemoteXPC` dans leur plist, comme c'est le cas pour `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Bien que le service soit enregistré auprès de `launchd`, `UserEventAgent` ainsi que ses plugins `com.apple.remoted.plugin` et `com.apple.remoteservicediscovery.events.plugin` fournissent cette fonctionnalité.

De plus, `RemoteServiceDiscovery.framework` obtient des informations depuis `com.apple.remoted.plugin`, en exposant des fonctions telles que `get_device`, `get_unique_device` et `connect`.

Une fois que `connect` a renvoyé le descripteur de fichier socket du service, il est possible d'utiliser la classe `remote_xpc_connection_*`.

Il est possible d'obtenir des informations sur les services distants avec la CLI `/usr/libexec/remotectl` en utilisant des commandes telles que :
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
La communication entre bridgeOS et le host s’effectue via une interface IPv6 dédiée. `MultiverseSupport.framework` établit des sockets dont les descripteurs de fichiers sont utilisés pour la communication.\
Il est possible de trouver ces communications à l’aide de `netstat`, `nettop` ou de l’alternative open source `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Création de services XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
