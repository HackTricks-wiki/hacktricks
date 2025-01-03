# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Informations de base

XPC, qui signifie XNU (le noyau utilisé par macOS) inter-Process Communication, est un cadre pour **la communication entre processus** sur macOS et iOS. XPC fournit un mécanisme pour effectuer des **appels de méthode sûrs et asynchrones entre différents processus** sur le système. C'est une partie du paradigme de sécurité d'Apple, permettant la **création d'applications séparées par privilèges** où chaque **composant** fonctionne avec **seulement les permissions dont il a besoin** pour faire son travail, limitant ainsi les dommages potentiels d'un processus compromis.

XPC utilise une forme de communication inter-processus (IPC), qui est un ensemble de méthodes permettant à différents programmes s'exécutant sur le même système d'échanger des données.

Les principaux avantages de XPC incluent :

1. **Sécurité** : En séparant le travail en différents processus, chaque processus peut se voir accorder uniquement les permissions dont il a besoin. Cela signifie que même si un processus est compromis, il a une capacité limitée à causer des dommages.
2. **Stabilité** : XPC aide à isoler les plantages au composant où ils se produisent. Si un processus plante, il peut être redémarré sans affecter le reste du système.
3. **Performance** : XPC permet une concurrence facile, car différentes tâches peuvent être exécutées simultanément dans différents processus.

Le seul **inconvénient** est que **séparer une application en plusieurs processus** les faisant communiquer via XPC est **moins efficace**. Mais dans les systèmes d'aujourd'hui, cela n'est presque pas perceptible et les avantages sont meilleurs.

## Services XPC spécifiques à l'application

Les composants XPC d'une application sont **à l'intérieur de l'application elle-même.** Par exemple, dans Safari, vous pouvez les trouver dans **`/Applications/Safari.app/Contents/XPCServices`**. Ils ont l'extension **`.xpc`** (comme **`com.apple.Safari.SandboxBroker.xpc`**) et sont **également des bundles** avec le binaire principal à l'intérieur : `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` et un `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Comme vous pourriez le penser, un **composant XPC aura des droits et privilèges différents** des autres composants XPC ou du binaire principal de l'application. SAUF si un service XPC est configuré avec [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) défini sur “True” dans son **fichier Info.plist**. Dans ce cas, le service XPC s'exécutera dans la **même session de sécurité que l'application** qui l'a appelé.

Les services XPC sont **démarrés** par **launchd** lorsque nécessaire et **arrêtés** une fois toutes les tâches **terminées** pour libérer des ressources système. **Les composants XPC spécifiques à l'application ne peuvent être utilisés que par l'application**, réduisant ainsi le risque associé aux vulnérabilités potentielles.

## Services XPC à l'échelle du système

Les services XPC à l'échelle du système sont accessibles à tous les utilisateurs. Ces services, soit launchd soit de type Mach, doivent être **définis dans des fichiers plist** situés dans des répertoires spécifiés tels que **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, ou **`/Library/LaunchAgents`**.

Ces fichiers plist auront une clé appelée **`MachServices`** avec le nom du service, et une clé appelée **`Program`** avec le chemin vers le binaire :
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
Les éléments dans **`LaunchDameons`** sont exécutés par root. Donc, si un processus non privilégié peut communiquer avec l'un d'eux, il pourrait être capable d'escalader les privilèges.

## Objets XPC

- **`xpc_object_t`**

Chaque message XPC est un objet dictionnaire qui simplifie la sérialisation et la désérialisation. De plus, `libxpc.dylib` déclare la plupart des types de données, il est donc possible de s'assurer que les données reçues sont du type attendu. Dans l'API C, chaque objet est un `xpc_object_t` (et son type peut être vérifié en utilisant `xpc_get_type(object)`).\
De plus, la fonction `xpc_copy_description(object)` peut être utilisée pour obtenir une représentation sous forme de chaîne de l'objet, ce qui peut être utile à des fins de débogage.\
Ces objets ont également certaines méthodes à appeler comme `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Les `xpc_object_t` sont créés en appelant la fonction `xpc_<objetType>_create`, qui appelle en interne `_xpc_base_create(Class, Size)` où le type de la classe de l'objet (l'un de `XPC_TYPE_*`) et sa taille sont indiqués (40B supplémentaires seront ajoutés à la taille pour les métadonnées). Ce qui signifie que les données de l'objet commenceront à l'offset de 40B.\
Par conséquent, le `xpc_<objectType>_t` est en quelque sorte une sous-classe du `xpc_object_t` qui serait une sous-classe de `os_object_t*`.

> [!WARNING]
> Notez qu'il devrait être le développeur qui utilise `xpc_dictionary_[get/set]_<objectType>` pour obtenir ou définir le type et la valeur réelle d'une clé.

- **`xpc_pipe`**

Un **`xpc_pipe`** est un tuyau FIFO que les processus peuvent utiliser pour communiquer (la communication utilise des messages Mach).\
Il est possible de créer un serveur XPC en appelant `xpc_pipe_create()` ou `xpc_pipe_create_from_port()` pour le créer en utilisant un port Mach spécifique. Ensuite, pour recevoir des messages, il est possible d'appeler `xpc_pipe_receive` et `xpc_pipe_try_receive`.

Notez que l'objet **`xpc_pipe`** est un **`xpc_object_t`** avec des informations dans sa structure sur les deux ports Mach utilisés et le nom (le cas échéant). Le nom, par exemple, le démon `secinitd` dans son plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` configure le tuyau appelé `com.apple.secinitd`.

Un exemple de **`xpc_pipe`** est le **bootstrap pipe** créé par **`launchd`** rendant possible le partage des ports Mach.

- **`NSXPC*`**

Ce sont des objets de haut niveau Objective-C qui permettent l'abstraction des connexions XPC.\
De plus, il est plus facile de déboguer ces objets avec DTrace que les précédents.

- **`GCD Queues`**

XPC utilise GCD pour passer des messages, de plus, il génère certaines files d'attente de dispatch comme `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Services XPC

Ce sont des **bundles avec l'extension `.xpc`** situés dans le dossier **`XPCServices`** d'autres projets et dans le `Info.plist`, ils ont le `CFBundlePackageType` défini sur **`XPC!`**.\
Ce fichier a d'autres clés de configuration comme `ServiceType` qui peut être Application, User, System ou `_SandboxProfile` qui peut définir un sandbox ou `_AllowedClients` qui pourrait indiquer des droits ou des ID requis pour contacter le service. Ces options de configuration et d'autres seront utiles pour configurer le service lors de son lancement.

### Démarrer un Service

L'application tente de **se connecter** à un service XPC en utilisant `xpc_connection_create_mach_service`, puis launchd localise le démon et démarre **`xpcproxy`**. **`xpcproxy`** applique les restrictions configurées et crée le service avec les FDs et ports Mach fournis.

Afin d'améliorer la vitesse de recherche du service XPC, un cache est utilisé.

Il est possible de tracer les actions de `xpcproxy` en utilisant :
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
La bibliothèque XPC utilise `kdebug` pour enregistrer des actions en appelant `xpc_ktrace_pid0` et `xpc_ktrace_pid1`. Les codes qu'elle utilise ne sont pas documentés, il est donc nécessaire de les ajouter dans `/usr/share/misc/trace.codes`. Ils ont le préfixe `0x29` et par exemple, l'un d'eux est `0x29000004`: `XPC_serializer_pack`.\
L'utilitaire `xpcproxy` utilise le préfixe `0x22`, par exemple : `0x2200001c: xpcproxy:will_do_preexec`.

## Messages d'événements XPC

Les applications peuvent **s'abonner** à différents **messages** d'événements, leur permettant d'être **initiés à la demande** lorsque de tels événements se produisent. La **configuration** de ces services se fait dans les fichiers **plist launchd**, situés dans les **mêmes répertoires que les précédents** et contenant une clé **`LaunchEvent`** supplémentaire.

### Vérification du processus de connexion XPC

Lorsqu'un processus essaie d'appeler une méthode via une connexion XPC, le **service XPC doit vérifier si ce processus est autorisé à se connecter**. Voici les méthodes courantes pour vérifier cela et les pièges courants :

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorisation XPC

Apple permet également aux applications de **configurer certains droits et comment les obtenir**, donc si le processus appelant les a, il serait **autorisé à appeler une méthode** du service XPC :

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Pour intercepter les messages XPC, vous pouvez utiliser [**xpcspy**](https://github.com/hot3eed/xpcspy) qui utilise **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Un autre outil possible à utiliser est [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Exemple de code C pour la communication XPC

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
## Exemple de code Objective-C pour la communication XPC

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
## Client à l'intérieur d'un code Dylb
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

Cette fonctionnalité fournie par `RemoteXPC.framework` (de `libxpc`) permet de communiquer via XPC entre différents hôtes.\
Les services qui prennent en charge le XPC distant auront dans leur plist la clé UsesRemoteXPC comme c'est le cas de `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Cependant, bien que le service soit enregistré avec `launchd`, c'est `UserEventAgent` avec les plugins `com.apple.remoted.plugin` et `com.apple.remoteservicediscovery.events.plugin` qui fournit la fonctionnalité.

De plus, le `RemoteServiceDiscovery.framework` permet d'obtenir des informations à partir du `com.apple.remoted.plugin` exposant des fonctions telles que `get_device`, `get_unique_device`, `connect`...

Une fois que connect est utilisé et que le socket `fd` du service est récupéré, il est possible d'utiliser la classe `remote_xpc_connection_*`.

Il est possible d'obtenir des informations sur les services distants en utilisant l'outil cli `/usr/libexec/remotectl` avec des paramètres tels que :
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
La communication entre BridgeOS et l'hôte se fait via une interface IPv6 dédiée. Le `MultiverseSupport.framework` permet d'établir des sockets dont le `fd` sera utilisé pour communiquer.\
Il est possible de trouver ces communications en utilisant `netstat`, `nettop` ou l'option open source, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
