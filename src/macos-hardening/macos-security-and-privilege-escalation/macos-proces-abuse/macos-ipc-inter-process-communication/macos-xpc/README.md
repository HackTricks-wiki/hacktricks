# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Información básica

XPC es un framework para la **comunicación entre procesos** en macOS e iOS. Proporciona mecanismos para realizar **llamadas seguras y asíncronas entre procesos**. XPC admite **aplicaciones con privilegios separados**, en las que cada **componente** se ejecuta con **solo los permisos que necesita**, lo que limita los posibles daños causados por un proceso comprometido.<sup>[[1]](#references)</sup>

XPC utiliza una forma de comunicación entre procesos (IPC), que consiste en un conjunto de métodos para que distintos programas que se ejecutan en el mismo sistema intercambien datos.

Las principales ventajas de XPC son:

1. **Seguridad**: Al separar el trabajo en distintos procesos, cada proceso puede recibir únicamente los permisos que necesita. Esto significa que, aunque un proceso se vea comprometido, su capacidad para causar daños será limitada.
2. **Estabilidad**: XPC ayuda a aislar los fallos en el componente donde se producen. Si un proceso falla, se puede reiniciar sin afectar al resto del sistema.
3. **Rendimiento**: XPC facilita la concurrencia, ya que se pueden ejecutar distintas tareas simultáneamente en diferentes procesos.

El principal **inconveniente** es que **separar una aplicación en varios procesos** y hacer que se comuniquen mediante XPC añade sobrecarga. En los sistemas modernos, esta sobrecarga suele ser pequeña en comparación con las ventajas de seguridad y estabilidad.<sup>[[1]](#references)</sup>

## Servicios XPC específicos de la aplicación

Los componentes XPC de una aplicación se encuentran **dentro de la propia aplicación**. Por ejemplo, en Safari se pueden encontrar en **`/Applications/Safari.app/Contents/XPCServices`**. Tienen la extensión **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) y **también son bundles**, con el binario principal y un `Info.plist` en su interior. Por ejemplo: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` y `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Un **componente XPC puede tener entitlements y privilegios distintos** de los de otros componentes XPC o del binario principal de la aplicación. Una excepción es un servicio XPC configurado con **`JoinExistingSession`** establecido en `true` en su archivo **Info.plist**. En este caso, el servicio XPC se une a la **misma sesión de seguridad que la aplicación** que lo llamó.<sup>[[4]](#references)</sup>

Los servicios XPC los **inicia** **launchd** cuando se necesitan y se pueden **detener** cuando sus tareas **terminan** para liberar recursos del sistema. **Los componentes XPC específicos de una aplicación solo pueden ser utilizados por la aplicación que los contiene**, lo que reduce la exposición a posibles vulnerabilidades.<sup>[[2]](#references)</sup>

## Servicios XPC de todo el sistema

A diferencia de los servicios específicos de una aplicación, los servicios XPC de todo el sistema no están restringidos a la aplicación que los contiene. Pueden ser accesibles para clientes de varios usuarios, según el dominio de launchd y las comprobaciones de autorización del propio servicio. Estos servicios Mach gestionados por launchd deben estar **definidos en archivos plist** ubicados en directorios como **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** o **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Estos archivos plist tienen una clave **`MachServices`** que contiene el nombre del servicio y una clave **`Program`** que contiene la ruta al binario:

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

Los servicios de **`LaunchDaemons`** suelen ejecutarse como root. Por lo tanto, si un proceso sin privilegios puede acceder a un método vulnerable expuesto por uno de estos servicios, podría escalar privilegios.

## Objetos XPC

- **`xpc_object_t`**

Las cargas útiles de las solicitudes y respuestas XPC suelen ser objetos de tipo diccionario, lo que simplifica la serialización y deserialización. `libxpc.dylib` también declara los tipos de datos necesarios para verificar que los datos recibidos sean del tipo esperado. En la API de C, cada objeto es un `xpc_object_t` (y se puede comprobar su tipo mediante `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Además, se puede usar la función `xpc_copy_description(object)` para obtener una representación en forma de cadena del objeto, que puede resultar útil para la depuración.\
Estos objetos también tienen métodos que se pueden llamar, como `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Los objetos `xpc_object_t` se crean llamando a una función `xpc_<objectType>_create`, que internamente llama a `_xpc_base_create(Class, Size)` e indica la clase del objeto (una de `XPC_TYPE_*`) y su tamaño. Se añaden 40 bytes adicionales para los metadatos, por lo que los datos del objeto comienzan en el desplazamiento de 40 bytes.\
Por lo tanto, `xpc_<objectType>_t` es una especie de subclase de `xpc_object_t`, que a su vez sería una subclase de `os_object_t*`.

> [!WARNING]
> Ten en cuenta que el desarrollador debe usar `xpc_dictionary_[get/set]_<objectType>` para obtener o establecer el tipo y el valor real de una clave.

- **`xpc_pipe`**

Un **`xpc_pipe`** es una tubería FIFO que los procesos pueden usar para comunicarse (la comunicación utiliza mensajes Mach).\
Se puede crear un servidor XPC llamando a `xpc_pipe_create()` o a `xpc_pipe_create_from_port()` para crearlo con un puerto Mach específico. Luego, para recibir mensajes, se puede llamar a `xpc_pipe_receive` y `xpc_pipe_try_receive`.

Ten en cuenta que el objeto **`xpc_pipe`** es un **`xpc_object_t`** cuya estructura contiene información sobre los dos puertos Mach utilizados y el nombre, si lo hay. Por ejemplo, el daemon `secinitd` configura la tubería llamada `com.apple.secinitd` en su plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`.

Un ejemplo de **`xpc_pipe`** es la **tubería bootstrap** creada por **`launchd`**, que permite compartir puertos Mach.

- **`NSXPC*`**

Son objetos Objective-C de alto nivel que abstraen las conexiones XPC.\
Además, estos objetos son más fáciles de depurar con DTrace que los anteriores.

- **`GCD Queues`**

XPC usa GCD para pasar mensajes y, además, genera determinadas colas de dispatch, como `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Servicios XPC

Son **bundles con la extensión `.xpc`** ubicados dentro de la carpeta **`XPCServices`** de otros proyectos; en su `Info.plist`, tienen `CFBundlePackageType` establecido en **`XPC!`**.\
Este archivo tiene otras claves de configuración, como `ServiceType`, que puede ser Application, User o System; `_SandboxProfile`, que puede definir un sandbox; y `_AllowedClients`, que puede indicar los entitlements o la identidad necesarios para contactar con el servicio. Estas y otras opciones configuran el servicio cuando se inicia.<sup>[[2]](#references)</sup>

### Iniciar un servicio

La app intenta **conectarse** a un servicio XPC mediante `xpc_connection_create_mach_service`; entonces, launchd localiza el daemon e inicia **`xpcproxy`**. **`xpcproxy`** aplica las restricciones configuradas y genera el servicio con los descriptores de archivo y puertos Mach proporcionados.<sup>[[3]](#references)</sup>

Para agilizar la búsqueda del servicio XPC, se utiliza una caché.

Es posible rastrear las acciones de `xpcproxy` usando:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

La biblioteca XPC usa `kdebug` para registrar acciones mediante llamadas a `xpc_ktrace_pid0` y `xpc_ktrace_pid1`. Los códigos que usa no están documentados, así que hay que añadirlos a `/usr/share/misc/trace.codes`. Tienen el prefijo `0x29`; por ejemplo, `0x29000004` es `XPC_serializer_pack`.\
La utilidad `xpcproxy` usa el prefijo `0x22`; por ejemplo: `0x2200001c: xpcproxy:will_do_preexec`.

## Auditoría de helpers XPC de tipo Application

Un `XPCService.ServiceType` de `Application` es un buen punto de partida para auditar helpers proporcionados por frameworks: enumera los bundles, conserva los servicios en ejecución e inspecciona el identificador y los entitlements del helper. Busca tanto en `/System/Library/Frameworks` como en `/System/Library/PrivateFrameworks`; el inventario exacto cambia según la versión de macOS.<sup>[[7]](#references)</sup>

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

### Analizar el listener y recuperar un protocolo mínimo

Localiza `-[<delegate> listener:shouldAcceptNewConnection:]` en el helper. Una ruta que establece `exportedInterface` y `exportedObject`, reanuda la conexión y devuelve `YES`/`1` sin comprobar el audit token, el code requirement ni los entitlements del peer expone la interfaz RPC a cualquier cliente que pueda resolver el servicio. Esto solo demuestra **accesibilidad**: para que haya impacto, sigue siendo necesario que un método exportado realice una operación privilegiada sin autorización adecuada por cliente o método, o que procese de forma insegura datos controlados por un atacante.<sup>[[7]](#references)</sup>

Recupera solo los selectors necesarios para las pruebas. Los metadatos de los selectors de Objective-C revelan el número de argumentos; los usos de los argumentos en el decompilador suelen permitir precisar los tipos (por ejemplo, los valores que se pasan a `-[EKEvent setStartDate:]` y `setEndDate:` son `NSDate *`), mientras que la invocación indirecta al final del método revela los parámetros del reply-block. Un protocolo local parcial es suficiente para `NSXPCInterface`; no es necesario reconstruir el protocolo privado completo.<sup>[[7]](#references)</sup>

### Conectarse con la interfaz reconstruida

Para un servicio XPC de una aplicación, carga cualquier framework que defina las clases privadas necesarias, crea la conexión con `initWithServiceName:`, asigna la interfaz remota reconstruida e instala los handlers de error, interrupción e invalidación; solo entonces reanúdala. Mantén activo el run loop para recibir respuestas asíncronas. Vuelve a ejecutar el cliente dentro de una aplicación sandboxed al probar un límite del sandbox: que un cliente independiente funcione no demuestra que se haya escapado del sandbox.<sup>[[7]](#references)</sup>

<details>
<summary>Cliente mínimo de Objective-C</summary>

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

Compile with `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Usa los fallos de secure-coding como oráculos de tipo

Un error de `NSCocoaErrorDomain`, como el código `4101`, puede ocultar la excepción de serialización útil. Busca el nombre del servicio en el registro unificado de macOS o en Console: la excepción identifica tanto la clase inesperada como las clases permitidas para ese argumento del selector. Para una respuesta, amplía la allowlist de la interfaz **del cliente** con `setClasses:forSelector:argumentIndex:ofReply:`; con `ofReply:YES`, el índice `0` corresponde al primer parámetro del bloque de respuesta, no al primer parámetro del método.<sup>[[7]](#references)</sup>

Configura la interfaz antes de asignarla a la conexión y llamar a `[c resume]`:<sup>[[7]](#references)</sup>

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

El caso inverso también es útil: si el servidor rechaza una entrada de Foundation y registra una única clase privada permitida, el registro revela el tipo esperado en el wire y su framework. Carga ese framework, inspecciona los métodos y las propiedades de la clase para precisar los tipos genéricos `id` y construye dinámicamente el objeto privado. Los argumentos de `NSInvocation` empiezan en el índice `2`, porque los índices `0` y `1` corresponden a los argumentos ocultos `self` y `_cmd`.<sup>[[7]](#references)</sup>

<details>
<summary>Construir un argumento privado con NSInvocation</summary>

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

Para ver el flujo de trabajo relacionado con los servicios Mach registrados en launchd y disponibles en todo el sistema, consulta:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## Mensajes de eventos XPC

Las aplicaciones pueden **suscribirse** a distintos **mensajes** de eventos, lo que permite **iniciarlas bajo demanda** cuando ocurren esos eventos. La **configuración** de estos servicios se realiza en **archivos plist de launchd**, ubicados en los **mismos directorios que los anteriores** y que contienen una clave adicional **`LaunchEvent`**.

### Comprobación del proceso que se conecta a XPC

Cuando un proceso intenta llamar a un método mediante una conexión XPC, el **servicio XPC debe comprobar si ese proceso tiene permiso para conectarse**. Estos son algunos métodos de verificación habituales y sus inconvenientes:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorización XPC

Apple también permite que las aplicaciones **configuren los derechos de autorización y cómo los obtienen los llamadores**, para que un proceso con los derechos necesarios **pueda llamar a un método** expuesto por el servicio XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Para capturar mensajes XPC, puedes usar **xpcspy**, que utiliza **Frida**.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Otra herramienta posible es **XPoCe2**.<sup>[[6]](#references)</sup>

## Ejemplo de código C de comunicación XPC

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

## Ejemplo de código Objective-C de comunicación XPC

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

## Cliente dentro de una Dylib

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

La funcionalidad que proporciona `RemoteXPC.framework` (de `libxpc`) permite la comunicación XPC entre distintos hosts.\
Los servicios compatibles con Remote XPC tienen la clave `UsesRemoteXPC` en su plist, como ocurre con `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Aunque el servicio está registrado con `launchd`, `UserEventAgent` y sus plugins `com.apple.remoted.plugin` y `com.apple.remoteservicediscovery.events.plugin` proporcionan la funcionalidad.

Además, `RemoteServiceDiscovery.framework` obtiene información de `com.apple.remoted.plugin` y expone funciones como `get_device`, `get_unique_device` y `connect`.

Una vez que `connect` devuelve el descriptor de archivo del socket del servicio, es posible usar la clase `remote_xpc_connection_*`.

Se puede obtener información sobre servicios remotos con la CLI `/usr/libexec/remotectl`, usando comandos como:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

La comunicación entre bridgeOS y el host se realiza a través de una interfaz IPv6 dedicada. `MultiverseSupport.framework` establece sockets cuyos descriptores de archivo se utilizan para la comunicación.\
Es posible encontrar estas comunicaciones con `netstat`, `nettop` o la alternativa de código abierto `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Archivo de Apple Developer — Creación de servicios XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - Ataques a los helpers XPC de macOS: ingeniería inversa de protocolos](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
