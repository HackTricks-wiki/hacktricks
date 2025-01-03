# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Información Básica

XPC, que significa XNU (el núcleo utilizado por macOS) inter-Process Communication, es un marco para **la comunicación entre procesos** en macOS e iOS. XPC proporciona un mecanismo para realizar **llamadas a métodos seguras y asíncronas entre diferentes procesos** en el sistema. Es parte del paradigma de seguridad de Apple, permitiendo la **creación de aplicaciones con separación de privilegios** donde cada **componente** se ejecuta con **solo los permisos que necesita** para hacer su trabajo, limitando así el daño potencial de un proceso comprometido.

XPC utiliza una forma de Inter-Process Communication (IPC), que es un conjunto de métodos para que diferentes programas que se ejecutan en el mismo sistema envíen datos de ida y vuelta.

Los principales beneficios de XPC incluyen:

1. **Seguridad**: Al separar el trabajo en diferentes procesos, a cada proceso se le pueden otorgar solo los permisos que necesita. Esto significa que incluso si un proceso se ve comprometido, tiene una capacidad limitada para causar daño.
2. **Estabilidad**: XPC ayuda a aislar los bloqueos al componente donde ocurren. Si un proceso falla, puede reiniciarse sin afectar al resto del sistema.
3. **Rendimiento**: XPC permite una fácil concurrencia, ya que diferentes tareas pueden ejecutarse simultáneamente en diferentes procesos.

El único **inconveniente** es que **separar una aplicación en varios procesos** que se comunican a través de XPC es **menos eficiente**. Pero en los sistemas actuales esto no es casi notable y los beneficios son mejores.

## Servicios XPC Específicos de la Aplicación

Los componentes XPC de una aplicación están **dentro de la propia aplicación.** Por ejemplo, en Safari puedes encontrarlos en **`/Applications/Safari.app/Contents/XPCServices`**. Tienen la extensión **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) y **también son paquetes** con el binario principal dentro de él: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` y un `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Como podrías estar pensando, un **componente XPC tendrá diferentes derechos y privilegios** que los otros componentes XPC o el binario principal de la aplicación. EXCEPTO si un servicio XPC está configurado con [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) establecido en “True” en su **Info.plist**. En este caso, el servicio XPC se ejecutará en la **misma sesión de seguridad que la aplicación** que lo llamó.

Los servicios XPC son **iniciados** por **launchd** cuando se requieren y **se apagan** una vez que todas las tareas están **completas** para liberar recursos del sistema. **Los componentes XPC específicos de la aplicación solo pueden ser utilizados por la aplicación**, reduciendo así el riesgo asociado con posibles vulnerabilidades.

## Servicios XPC de Todo el Sistema

Los servicios XPC de todo el sistema son accesibles para todos los usuarios. Estos servicios, ya sean launchd o de tipo Mach, deben estar **definidos en archivos plist** ubicados en directorios específicos como **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, o **`/Library/LaunchAgents`**.

Estos archivos plist tendrán una clave llamada **`MachServices`** con el nombre del servicio, y una clave llamada **`Program`** con la ruta al binario:
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
Los que están en **`LaunchDameons`** son ejecutados por root. Así que si un proceso no privilegiado puede comunicarse con uno de estos, podría ser capaz de escalar privilegios.

## Objetos XPC

- **`xpc_object_t`**

Cada mensaje XPC es un objeto diccionario que simplifica la serialización y deserialización. Además, `libxpc.dylib` declara la mayoría de los tipos de datos, por lo que es posible hacer que los datos recibidos sean del tipo esperado. En la API de C, cada objeto es un `xpc_object_t` (y su tipo se puede verificar usando `xpc_get_type(object)`).\
Además, la función `xpc_copy_description(object)` se puede usar para obtener una representación en cadena del objeto que puede ser útil para fines de depuración.\
Estos objetos también tienen algunos métodos que se pueden llamar como `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Los `xpc_object_t` se crean llamando a la función `xpc_<objetType>_create`, que internamente llama a `_xpc_base_create(Class, Size)` donde se indica el tipo de la clase del objeto (uno de `XPC_TYPE_*`) y el tamaño de este (se agregarán 40B extra al tamaño para metadatos). Lo que significa que los datos del objeto comenzarán en el desplazamiento de 40B.\
Por lo tanto, el `xpc_<objectType>_t` es una especie de subclase del `xpc_object_t`, que sería una subclase de `os_object_t*`.

> [!WARNING]
> Tenga en cuenta que debe ser el desarrollador quien use `xpc_dictionary_[get/set]_<objectType>` para obtener o establecer el tipo y el valor real de una clave.

- **`xpc_pipe`**

Un **`xpc_pipe`** es un tubo FIFO que los procesos pueden usar para comunicarse (la comunicación utiliza mensajes Mach).\
Es posible crear un servidor XPC llamando a `xpc_pipe_create()` o `xpc_pipe_create_from_port()` para crearlo utilizando un puerto Mach específico. Luego, para recibir mensajes, es posible llamar a `xpc_pipe_receive` y `xpc_pipe_try_receive`.

Tenga en cuenta que el objeto **`xpc_pipe`** es un **`xpc_object_t`** con información en su estructura sobre los dos puertos Mach utilizados y el nombre (si lo hay). El nombre, por ejemplo, el demonio `secinitd` en su plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` configura el tubo llamado `com.apple.secinitd`.

Un ejemplo de un **`xpc_pipe`** es el **bootstrap pipe** creado por **`launchd`**, lo que hace posible compartir puertos Mach.

- **`NSXPC*`**

Estos son objetos de alto nivel de Objective-C que permiten la abstracción de conexiones XPC.\
Además, es más fácil depurar estos objetos con DTrace que los anteriores.

- **`GCD Queues`**

XPC utiliza GCD para pasar mensajes, además genera ciertas colas de despacho como `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Servicios XPC

Estos son **paquetes con extensión `.xpc`** ubicados dentro de la carpeta **`XPCServices`** de otros proyectos y en el `Info.plist` tienen el `CFBundlePackageType` configurado como **`XPC!`**.\
Este archivo tiene otras claves de configuración como `ServiceType`, que puede ser Application, User, System o `_SandboxProfile`, que puede definir un sandbox, o `_AllowedClients`, que podría indicar derechos o ID requeridos para contactar al servicio. Estas y otras opciones de configuración serán útiles para configurar el servicio al ser lanzado.

### Iniciando un Servicio

La aplicación intenta **conectarse** a un servicio XPC usando `xpc_connection_create_mach_service`, luego launchd localiza el demonio y comienza **`xpcproxy`**. **`xpcproxy`** aplica las restricciones configuradas y genera el servicio con los FDs y puertos Mach proporcionados.

Para mejorar la velocidad de búsqueda del servicio XPC, se utiliza una caché.

Es posible rastrear las acciones de `xpcproxy` usando:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
La biblioteca XPC utiliza `kdebug` para registrar acciones llamando a `xpc_ktrace_pid0` y `xpc_ktrace_pid1`. Los códigos que utiliza no están documentados, por lo que es necesario agregarlos a `/usr/share/misc/trace.codes`. Tienen el prefijo `0x29` y, por ejemplo, uno es `0x29000004`: `XPC_serializer_pack`.\
La utilidad `xpcproxy` utiliza el prefijo `0x22`, por ejemplo: `0x2200001c: xpcproxy:will_do_preexec`.

## Mensajes de Evento XPC

Las aplicaciones pueden **suscribirse** a diferentes **mensajes** de evento, lo que les permite ser **iniciadas bajo demanda** cuando ocurren tales eventos. La **configuración** para estos servicios se realiza en los **archivos plist de launchd**, ubicados en los **mismos directorios que los anteriores** y que contienen una clave adicional **`LaunchEvent`**.

### Verificación del Proceso Conectado XPC

Cuando un proceso intenta llamar a un método a través de una conexión XPC, el **servicio XPC debe verificar si ese proceso tiene permitido conectarse**. Aquí están las formas comunes de verificar eso y las trampas comunes:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorización XPC

Apple también permite que las aplicaciones **configuren algunos derechos y cómo obtenerlos**, por lo que si el proceso que llama los tiene, se le **permitiría llamar a un método** del servicio XPC:

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Para espiar los mensajes XPC, podrías usar [**xpcspy**](https://github.com/hot3eed/xpcspy) que utiliza **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Otra herramienta posible para usar es [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

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
## Ejemplo de código Objective-C para comunicación XPC

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
## Cliente dentro de un código Dylb
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

Esta funcionalidad proporcionada por `RemoteXPC.framework` (de `libxpc`) permite comunicarse a través de XPC entre diferentes hosts.\
Los servicios que admiten XPC remoto tendrán en su plist la clave UsesRemoteXPC como es el caso de `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Sin embargo, aunque el servicio estará registrado con `launchd`, es `UserEventAgent` con los plugins `com.apple.remoted.plugin` y `com.apple.remoteservicediscovery.events.plugin` los que proporcionan la funcionalidad.

Además, el `RemoteServiceDiscovery.framework` permite obtener información del `com.apple.remoted.plugin` exponiendo funciones como `get_device`, `get_unique_device`, `connect`...

Una vez que se utiliza connect y se recopila el socket `fd` del servicio, es posible usar la clase `remote_xpc_connection_*`.

Es posible obtener información sobre servicios remotos utilizando la herramienta cli `/usr/libexec/remotectl` con parámetros como:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
La comunicación entre BridgeOS y el host ocurre a través de una interfaz IPv6 dedicada. El `MultiverseSupport.framework` permite establecer sockets cuyos `fd` se utilizarán para comunicarse.\
Es posible encontrar estas comunicaciones utilizando `netstat`, `nettop` o la opción de código abierto, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
