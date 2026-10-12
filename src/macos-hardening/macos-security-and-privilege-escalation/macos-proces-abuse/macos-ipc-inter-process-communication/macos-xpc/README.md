# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Informations de base

XPC est un framework de **communication entre processus** sur macOS et iOS. Il fournit des mécanismes permettant d'effectuer des **appels asynchrones sécurisés entre processus**. XPC prend en charge les **applications à privilèges séparés**, dans lesquelles chaque **composant** s'exécute avec **uniquement les permissions dont il a besoin**, limitant ainsi les dégâts potentiels causés par la compromission d'un processus.<sup>[[1]](#references)</sup>

XPC utilise une forme de communication inter-processus (IPC), c'est-à-dire un ensemble de méthodes permettant à différents programmes exécutés sur le même système de s'échanger des données.

Les principaux avantages de XPC sont les suivants :

1. **Sécurité** : En répartissant le travail entre différents processus, chacun peut recevoir uniquement les permissions dont il a besoin. Ainsi, même si un processus est compromis, sa capacité à causer des dommages reste limitée.
2. **Stabilité** : XPC aide à isoler les plantages au composant où ils se produisent. Si un processus plante, il peut être redémarré sans affecter le reste du système.
3. **Performances** : XPC facilite l'exécution simultanée de plusieurs tâches dans différents processus.

Le principal **inconvénient** est que **la séparation d'une application en plusieurs processus** et leur communication via XPC entraînent une surcharge. Sur les systèmes modernes, cette surcharge est généralement faible par rapport aux avantages en matière de sécurité et de stabilité.<sup>[[1]](#references)</sup>

## Services XPC propres aux applications

Les composants XPC d'une application se trouvent **à l'intérieur de l'application elle-même**. Par exemple, dans Safari, on peut les trouver dans **`/Applications/Safari.app/Contents/XPCServices`**. Ils portent l'extension **`.xpc`** (comme **`com.apple.Safari.SandboxBroker.xpc`**) et sont **également des bundles**, contenant le binaire principal et un fichier `Info.plist`. Par exemple : `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` et `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Un **composant XPC peut avoir des entitlements et des privilèges différents** de ceux des autres composants XPC ou du binaire principal de l'application. Une exception concerne un service XPC configuré avec **`JoinExistingSession`** défini sur `true` dans son fichier **Info.plist**. Dans ce cas, le service XPC rejoint la **même session de sécurité que l'application** qui l'a appelé.<sup>[[4]](#references)</sup>

Les services XPC sont **démarrés** par **launchd** lorsque nécessaire et peuvent être **arrêtés** une fois leurs tâches **terminées** afin de libérer des ressources système. **Les composants XPC propres à une application ne peuvent être utilisés que par l'application qui les contient**, réduisant ainsi l'exposition aux vulnérabilités potentielles.<sup>[[2]](#references)</sup>

## Services XPC à l'échelle du système

Contrairement aux services propres aux applications, les services XPC à l'échelle du système ne sont pas réservés à l'application qui les contient. Ils peuvent être accessibles aux clients de plusieurs utilisateurs, selon le domaine launchd et les contrôles d'autorisation propres au service. Ces services Mach gérés par launchd doivent être **définis dans des fichiers plist** situés dans des répertoires tels que **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ou **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Ces fichiers plist contiennent une clé **`MachServices`** avec le nom du service et une clé **`Program`** avec le chemin du binaire :

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

Les services dans **`LaunchDaemons`** s’exécutent souvent en tant que root. Par conséquent, si un processus non privilégié peut accéder à une méthode vulnérable exposée par l’un de ces services, il peut être en mesure d’élever ses privilèges.

## Objets XPC

- **`xpc_object_t`**

Les payloads des requêtes et des réponses XPC sont généralement des objets dictionnaire, ce qui simplifie leur sérialisation et leur désérialisation. `libxpc.dylib` déclare également les types de données nécessaires pour vérifier que les données reçues sont du type attendu. Dans l’API C, chaque objet est un `xpc_object_t` (et son type peut être vérifié à l’aide de `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
De plus, la fonction `xpc_copy_description(object)` permet d’obtenir une représentation textuelle de l’objet, utile à des fins de débogage.\
Ces objets disposent également de méthodes telles que `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Les objets `xpc_object_t` sont créés en appelant une fonction `xpc_<objectType>_create`, qui appelle en interne `_xpc_base_create(Class, Size)` en indiquant la classe de l’objet (l’une des valeurs `XPC_TYPE_*`) et sa taille. 40 octets supplémentaires sont ajoutés pour les métadonnées, les données de l’objet commencent donc à l’offset 40 octets.\
Par conséquent, `xpc_<objectType>_t` est une sorte de sous-classe de `xpc_object_t`, qui serait elle-même une sous-classe de `os_object_t*`.

> [!WARNING]
> Notez que c’est au développeur d’utiliser `xpc_dictionary_[get/set]_<objectType>` pour récupérer ou définir le type et la valeur réelle d’une clé.

- **`xpc_pipe`**

Un **`xpc_pipe`** est un canal FIFO que les processus peuvent utiliser pour communiquer (la communication utilise des messages Mach).\
Il est possible de créer un serveur XPC en appelant `xpc_pipe_create()` ou `xpc_pipe_create_from_port()` pour le créer à partir d’un port Mach spécifique. Ensuite, pour recevoir des messages, il est possible d’appeler `xpc_pipe_receive` et `xpc_pipe_try_receive`.

Notez que l’objet **`xpc_pipe`** est un **`xpc_object_t`** dont la structure contient des informations sur les deux ports Mach utilisés et le nom, le cas échéant. Par exemple, dans son plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`, le daemon `secinitd` configure le canal nommé `com.apple.secinitd`.

Le **bootstrap pipe** créé par **`launchd`** est un exemple de **`xpc_pipe`**. Il permet de partager des ports Mach.

- **`NSXPC*`**

Ce sont des objets Objective-C de haut niveau qui abstraient les connexions XPC.\
De plus, ces objets sont plus faciles à déboguer avec DTrace que les précédents.

- **Files d’attente GCD**

XPC utilise GCD pour transmettre des messages et génère également certaines files d’attente dispatch, telles que `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Services XPC

Il s’agit de **bundles avec l’extension `.xpc`**, situés dans le dossier **`XPCServices`** d’autres projets. Dans leur `Info.plist`, la clé `CFBundlePackageType` est définie sur **`XPC!`**.\
Ce fichier contient d’autres clés de configuration, comme `ServiceType`, qui peut prendre les valeurs Application, User ou System ; `_SandboxProfile`, qui peut définir un sandbox ; et `_AllowedClients`, qui peut indiquer les entitlements ou l’identité requis pour contacter le service. Ces options, ainsi que d’autres, configurent le service lors de son lancement.<sup>[[2]](#references)</sup>

### Démarrer un service

L’application tente de **se connecter** à un service XPC à l’aide de `xpc_connection_create_mach_service` ; launchd localise alors le daemon et démarre **`xpcproxy`**. **`xpcproxy`** applique les restrictions configurées et lance le service avec les descripteurs de fichiers et les ports Mach fournis.<sup>[[3]](#references)</sup>

Pour accélérer la recherche du service XPC, un cache est utilisé.

Il est possible de tracer les actions de `xpcproxy` à l’aide de :

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

La bibliothèque XPC utilise `kdebug` pour journaliser les actions en appelant `xpc_ktrace_pid0` et `xpc_ktrace_pid1`. Les codes utilisés ne sont pas documentés ; il faut donc les ajouter à `/usr/share/misc/trace.codes`. Ils ont le préfixe `0x29` ; par exemple, `0x29000004` correspond à `XPC_serializer_pack`.\
L’utilitaire `xpcproxy` utilise le préfixe `0x22`, par exemple : `0x2200001c: xpcproxy:will_do_preexec`.

## Audit des helpers XPC de type Application

Un `XPCService.ServiceType` de type `Application` constitue un bon point de départ pour auditer les helpers fournis par les frameworks : répertoriez les bundles, conservez les services en cours d’exécution, puis examinez l’identifiant et les entitlements du helper. Recherchez dans `/System/Library/Frameworks` et `/System/Library/PrivateFrameworks` ; l’inventaire exact varie selon les versions de macOS.<sup>[[7]](#references)</sup>

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

### Trier le listener et retrouver un protocole minimal

Repérez `-[<delegate> listener:shouldAcceptNewConnection:]` dans le helper. Si le code définit `exportedInterface` et `exportedObject`, reprend la connexion et renvoie `YES`/`1` sans vérifier l’audit token, l’exigence de code ou l’entitlement du pair, il expose l’interface RPC à tout client capable de résoudre le service. Cela prouve uniquement l’**accessibilité** : pour établir l’impact, il faut encore qu’une méthode exportée effectue une opération privilégiée sans autorisation adéquate par client ou par méthode, ou qu’elle traite de façon non sécurisée des données contrôlées par l’attaquant.<sup>[[7]](#references)</sup>

Retrouvez uniquement les selectors nécessaires aux tests. Les métadonnées des selectors Objective-C révèlent le nombre d’arguments ; l’utilisation des arguments dans le décompilateur permet généralement d’affiner les types (par exemple, les valeurs passées à `-[EKEvent setStartDate:]` et `setEndDate:` sont des `NSDate *`), tandis que l’invocation indirecte à la fin de la méthode révèle les paramètres du reply block. Un protocole local partiel suffit pour `NSXPCInterface` ; il n’est pas nécessaire de reconstituer l’intégralité du protocole privé.<sup>[[7]](#references)</sup>

### Se connecter avec l’interface reconstituée

Pour un service XPC d’application, chargez tout framework qui définit les classes privées requises, créez la connexion avec `initWithServiceName:`, assignez l’interface distante reconstituée, installez les gestionnaires d’erreur, d’interruption et d’invalidation, puis reprenez la connexion. Maintenez la run loop active pour recevoir les réponses asynchrones. Pour tester une limite de sandbox, relancez le client depuis une application sandboxée : la réussite d’un client autonome ne prouve pas qu’il y a eu échappement de sandbox.<sup>[[7]](#references)</sup>

<details>
<summary>Client Objective-C minimal</summary>

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

Compilez avec `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Utiliser les échecs de secure coding comme oracles de type

Une erreur `NSCocoaErrorDomain` telle que le code `4101` peut masquer l’exception de sérialisation utile. Recherchez le nom du service dans le journal unifié macOS/Console : l’exception indique à la fois la classe inattendue et les classes autorisées pour cet argument du sélecteur. Pour une réponse, étendez l’allowlist de l’interface côté **client** avec `setClasses:forSelector:argumentIndex:ofReply:` ; avec `ofReply:YES`, l’index `0` désigne le premier paramètre du bloc de réponse, et non le premier paramètre de la méthode.<sup>[[7]](#references)</sup>

Configurez l’interface avant de l’affecter à la connexion et d’appeler `[c resume]` :<sup>[[7]](#references)</sup>

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

Le cas inverse est également utile : si le serveur rejette une entrée Foundation et consigne une seule classe privée autorisée, le journal révèle le type attendu sur le wire et son framework. Chargez ce framework, examinez les méthodes/propriétés de la classe pour préciser les types génériques `id`, puis construisez dynamiquement l’objet privé. Les arguments de `NSInvocation` commencent à l’index `2`, car les index `0` et `1` correspondent aux arguments cachés `self` et `_cmd`.<sup>[[7]](#references)</sup>

<details>
<summary>Construire un argument privé avec NSInvocation</summary>

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

Pour le workflow associé aux services Mach à l’échelle du système enregistrés auprès de launchd, voir :

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## Messages d’événement XPC

Les applications peuvent **s’abonner** à différents **messages** d’événement, ce qui permet de les **lancer à la demande** lorsque ces événements se produisent. La **configuration** de ces services se fait dans les fichiers plist de **launchd**, situés dans les **mêmes répertoires que les précédents** et contenant une clé **`LaunchEvent`** supplémentaire.

### Vérification du processus de connexion XPC

Lorsqu’un processus tente d’appeler une méthode via une connexion XPC, le **service XPC doit vérifier si ce processus est autorisé à se connecter**. Voici des méthodes de vérification courantes et leurs pièges :

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorisation XPC

Apple permet également aux applications de **configurer des droits d’autorisation et la manière dont les appelants les obtiennent**, afin qu’un processus possédant les droits requis soit **autorisé à appeler une méthode** exposée par le service XPC :

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Pour intercepter les messages XPC, vous pouvez utiliser **xpcspy**, qui s’appuie sur **Frida**.<sup>[[5]](#references)</sup>

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

## Exemple de code de communication XPC en Objective-C

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

## Client dans une Dylib

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

Les fonctionnalités fournies par `RemoteXPC.framework` (de `libxpc`) permettent la communication XPC entre différents hôtes.\
Les services prenant en charge Remote XPC possèdent la clé `UsesRemoteXPC` dans leur plist, comme c'est le cas pour `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Bien que le service soit enregistré auprès de `launchd`, `UserEventAgent` et ses plugins `com.apple.remoted.plugin` et `com.apple.remoteservicediscovery.events.plugin` fournissent cette fonctionnalité.

De plus, `RemoteServiceDiscovery.framework` obtient des informations depuis `com.apple.remoted.plugin` et expose des fonctions telles que `get_device`, `get_unique_device` et `connect`.

Une fois que `connect` a renvoyé le descripteur de fichier de socket du service, il est possible d'utiliser la classe `remote_xpc_connection_*`.

Il est possible d'obtenir des informations sur les services distants avec la CLI `/usr/libexec/remotectl`, à l'aide de commandes telles que :

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

La communication entre bridgeOS et l’hôte passe par une interface IPv6 dédiée. `MultiverseSupport.framework` établit des sockets dont les descripteurs de fichier sont utilisés pour la communication.\
Il est possible de trouver ces communications avec `netstat`, `nettop` ou l’alternative open source `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Création de services XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - Attaquer les helpers XPC de macOS : rétro-ingénierie de protocole](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
