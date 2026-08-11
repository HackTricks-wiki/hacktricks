# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Información básica

XPC es un framework para la **comunicación entre procesos** en macOS e iOS. Proporciona mecanismos para realizar **llamadas seguras y asíncronas entre procesos**. XPC admite **aplicaciones con privilegios separados**, donde cada **componente** se ejecuta con **solo los permisos que necesita**, limitando así el daño potencial causado por un proceso comprometido.<sup>[[1]](#references)</sup>

XPC utiliza una forma de comunicación entre procesos (IPC), que es un conjunto de métodos para que diferentes programas que se ejecutan en el mismo sistema intercambien datos.

Los principales beneficios de XPC incluyen:

1. **Seguridad**: Al separar el trabajo en diferentes procesos, a cada proceso se le pueden conceder solo los permisos que necesita. Esto significa que, incluso si un proceso se ve comprometido, su capacidad para causar daños es limitada.
2. **Estabilidad**: XPC ayuda a aislar los crashes en el componente donde se producen. Si un proceso falla, puede reiniciarse sin afectar al resto del sistema.
3. **Rendimiento**: XPC permite una concurrencia sencilla, ya que diferentes tareas pueden ejecutarse simultáneamente en distintos procesos.

El principal **inconveniente** es que **separar una aplicación en varios procesos** y hacer que se comuniquen mediante XPC añade sobrecarga. En los sistemas modernos, esta sobrecarga suele ser pequeña en comparación con los beneficios de seguridad y estabilidad.<sup>[[1]](#references)</sup>

## Servicios XPC específicos de una aplicación

Los componentes XPC de una aplicación se encuentran **dentro de la propia aplicación**. Por ejemplo, en Safari se pueden encontrar en **`/Applications/Safari.app/Contents/XPCServices`**. Tienen la extensión **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) y también son **bundles**, con el binario principal y un `Info.plist` en su interior. Por ejemplo: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` y `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Un **componente XPC puede tener diferentes entitlements y privilegios** de los de otros componentes XPC o del binario principal de la aplicación. Una excepción es un servicio XPC configurado con **`JoinExistingSession`** establecido en `true` en su archivo **Info.plist**. En este caso, el servicio XPC se une a la **misma sesión de seguridad que la aplicación** que lo llamó.<sup>[[4]](#references)</sup>

Los servicios XPC son **iniciados** por **launchd** cuando es necesario y pueden **apagarse** una vez que sus tareas se **completan** para liberar recursos del sistema. **Los componentes XPC específicos de una aplicación solo pueden ser utilizados por la aplicación que los contiene**, reduciendo así la exposición a posibles vulnerabilidades.<sup>[[2]](#references)</sup>

## Servicios XPC de todo el sistema

A diferencia de los servicios específicos de una aplicación, los servicios XPC de todo el sistema no están restringidos a la aplicación que los contiene. Pueden ser accesibles para clientes de varios usuarios, según el dominio de launchd y las propias comprobaciones de autorización del servicio. Estos servicios Mach gestionados por launchd deben estar **definidos en archivos plist** ubicados en directorios como **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** o **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

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
Los servicios en **`LaunchDaemons`** suelen ejecutarse como root. Por lo tanto, si un proceso sin privilegios puede acceder a un método vulnerable expuesto por uno de estos servicios, podría escalar privilegios.

## XPC Objects

- **`xpc_object_t`**

Las cargas de solicitud y respuesta de XPC suelen ser objetos de tipo diccionario, lo que simplifica la serialización y deserialización. `libxpc.dylib` también declara los tipos de datos necesarios para verificar que los datos recibidos tengan el tipo esperado. En la API de C, cada objeto es un `xpc_object_t` (y su tipo puede comprobarse usando `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Además, la función `xpc_copy_description(object)` puede utilizarse para obtener una representación en forma de cadena del objeto, lo que puede resultar útil para fines de debugging.\
Estos objetos también tienen algunos métodos que se pueden invocar, como `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Los objetos `xpc_object_t` se crean llamando a una función `xpc_<objectType>_create`, que internamente llama a `_xpc_base_create(Class, Size)`, indicando la clase del objeto (una de `XPC_TYPE_*`) y su tamaño. Se añaden 40 bytes adicionales para los metadatos, por lo que los datos del objeto comienzan en el offset de 40 bytes.\
Por lo tanto, `xpc_<objectType>_t` es una especie de subclase de `xpc_object_t`, que a su vez sería una subclase de `os_object_t*`.

> [!WARNING]
> Ten en cuenta que debe ser el developer quien utilice `xpc_dictionary_[get/set]_<objectType>` para obtener o establecer el tipo y el valor real de una clave.

- **`xpc_pipe`**

Un **`xpc_pipe`** es una tubería FIFO que los procesos pueden utilizar para comunicarse (la comunicación usa mensajes Mach).\
Es posible crear un servidor XPC llamando a `xpc_pipe_create()` o `xpc_pipe_create_from_port()` para crearlo usando un puerto Mach específico. Después, para recibir mensajes, es posible llamar a `xpc_pipe_receive` y `xpc_pipe_try_receive`.

Ten en cuenta que el objeto **`xpc_pipe`** es un **`xpc_object_t`** con información en su struct sobre los dos puertos Mach utilizados y el nombre, si existe. El nombre, por ejemplo, del daemon `secinitd` en su plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` configura la tubería llamada `com.apple.secinitd`.

Un ejemplo de un **`xpc_pipe`** es la **bootstrap pipe** creada por **`launchd`**, que permite compartir puertos Mach.

- **`NSXPC*`**

Estos son objetos Objective-C de alto nivel que abstraen las conexiones XPC.\
Además, es más fácil hacer debugging de estos objetos con DTrace que de los anteriores.

- **`GCD Queues`**

XPC utiliza GCD para pasar mensajes; además, genera determinadas dispatch queues como `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Son **bundles con extensión `.xpc`** ubicados dentro de la carpeta **`XPCServices`** de otros proyectos y, en el `Info.plist`, tienen `CFBundlePackageType` establecido como **`XPC!`**.\
Este archivo contiene otras claves de configuración, como `ServiceType`, que puede ser Application, User o System; `_SandboxProfile`, que puede definir un sandbox; y `_AllowedClients`, que puede indicar los entitlements o la identidad necesarios para contactar con el servicio. Estas y otras opciones configuran el servicio cuando se inicia.<sup>[[2]](#references)</sup>

### Iniciar un Service

La app intenta **conectarse** a un servicio XPC usando `xpc_connection_create_mach_service`; launchd localiza entonces el daemon e inicia **`xpcproxy`**. **`xpcproxy`** aplica las restricciones configuradas y ejecuta el servicio con los file descriptors y puertos Mach proporcionados.<sup>[[3]](#references)</sup>

Para mejorar la velocidad de búsqueda del servicio XPC, se utiliza una caché.

Es posible rastrear las acciones de `xpcproxy` usando:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
La biblioteca XPC utiliza `kdebug` para registrar acciones llamando a `xpc_ktrace_pid0` y `xpc_ktrace_pid1`. Los códigos que utiliza no están documentados, por lo que deben añadirse a `/usr/share/misc/trace.codes`. Tienen el prefijo `0x29`; por ejemplo, `0x29000004` es `XPC_serializer_pack`.\
La utilidad `xpcproxy` utiliza el prefijo `0x22`; por ejemplo: `0x2200001c: xpcproxy:will_do_preexec`.

## Mensajes de eventos XPC

Las aplicaciones pueden **suscribirse** a distintos **mensajes** de eventos, lo que permite que se **inicien bajo demanda** cuando ocurran dichos eventos. La **configuración** de estos servicios se realiza en l**archivos plist de launchd**, ubicados en los **mismos directorios que los anteriores** y que contienen una clave adicional **`LaunchEvent`**.

### Comprobación del proceso que conecta mediante XPC

Cuando un proceso intenta llamar a un método a través de una conexión XPC, el **servicio XPC debería comprobar si ese proceso tiene permiso para conectarse**. Estos son métodos de verificación habituales y sus inconvenientes:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorización XPC

Apple también permite que las aplicaciones **configuren derechos de autorización y cómo los obtienen los callers**, de modo que un proceso con los derechos requeridos **pueda llamar a un método** expuesto por el servicio XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Para sniff XPC messages, puedes utilizar **xpcspy**, que usa **Frida**.<sup>[[5]](#references)</sup>
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

La funcionalidad proporcionada por `RemoteXPC.framework` (de `libxpc`) permite la comunicación XPC entre distintos hosts.\
Los servicios compatibles con Remote XPC tienen la clave `UsesRemoteXPC` en su plist, como ocurre con `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Aunque el servicio está registrado con `launchd`, `UserEventAgent` y sus plugins `com.apple.remoted.plugin` y `com.apple.remoteservicediscovery.events.plugin` proporcionan la funcionalidad.

Además, `RemoteServiceDiscovery.framework` obtiene información de `com.apple.remoted.plugin`, exponiendo funciones como `get_device`, `get_unique_device` y `connect`.

Una vez que `connect` ha devuelto el descriptor de archivo del socket del servicio, es posible utilizar la clase `remote_xpc_connection_*`.

Es posible obtener información sobre servicios remotos con la CLI `/usr/libexec/remotectl` mediante comandos como:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
La comunicación entre bridgeOS y el host se realiza a través de una interfaz IPv6 dedicada. `MultiverseSupport.framework` establece sockets cuyos file descriptors se utilizan para la comunicación.\
Es posible encontrar estas comunicaciones mediante `netstat`, `nettop` o la alternativa open-source `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Archivo de Apple Developer — Creación de servicios XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
