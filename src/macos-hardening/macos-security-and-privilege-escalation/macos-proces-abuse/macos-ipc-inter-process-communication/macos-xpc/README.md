# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Información básica

XPC, siglas de XNU (el kernel utilizado por macOS) inter-Process Communication, es un framework para la **comunicación entre procesos** en macOS e iOS. XPC proporciona un mecanismo para realizar **llamadas a métodos seguras y asíncronas entre diferentes procesos** del sistema. Forma parte del paradigma de seguridad de Apple y permite la **creación de aplicaciones con privilegios separados**, donde cada **componente** se ejecuta con **únicamente los permisos que necesita** para realizar su trabajo, limitando así los posibles daños derivados de un proceso comprometido.

XPC utiliza una forma de Inter-Process Communication (IPC), que es un conjunto de métodos para que diferentes programas ejecutándose en el mismo sistema intercambien datos.

Los principales beneficios de XPC incluyen:

1. **Seguridad**: Al separar el trabajo en diferentes procesos, cada proceso puede recibir únicamente los permisos que necesita. Esto significa que, incluso si un proceso se ve comprometido, su capacidad para causar daños es limitada.
2. **Estabilidad**: XPC ayuda a aislar los crashes en el componente donde se producen. Si un proceso falla, puede reiniciarse sin afectar al resto del sistema.
3. **Rendimiento**: XPC facilita la concurrencia, ya que diferentes tareas pueden ejecutarse simultáneamente en distintos procesos.

El único **inconveniente** es que **separar una aplicación en varios procesos** y hacer que se comuniquen mediante XPC es **menos eficiente**. Sin embargo, en los sistemas actuales esto apenas resulta perceptible y los beneficios son mayores.

## Servicios XPC específicos de la aplicación

Los componentes XPC de una aplicación están **dentro de la propia aplicación**. Por ejemplo, en Safari puedes encontrarlos en **`/Applications/Safari.app/Contents/XPCServices`**. Tienen la extensión **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) y también son **bundles** con el binario principal dentro: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` y un `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Como probablemente estés pensando, un **componente XPC tendrá entitlements y privilegios diferentes** a los de los demás componentes XPC o del binario principal de la aplicación. EXCEPTO si un servicio XPC está configurado con [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) establecido en “True” en su archivo **Info.plist**. En este caso, el servicio XPC se ejecutará en la **misma sesión de seguridad que la aplicación** que lo llamó.

Los servicios XPC son **iniciados** por **launchd** cuando es necesario y se **detienen** una vez que todas las tareas se han **completado**, para liberar recursos del sistema. **La aplicación solo puede utilizar sus propios componentes XPC**, lo que reduce el riesgo asociado a posibles vulnerabilidades.

## Servicios XPC de todo el sistema

Los servicios XPC de todo el sistema son accesibles para todos los usuarios. Estos servicios, ya sean de tipo launchd o Mach, deben estar **definidos en archivos plist** ubicados en directorios específicos como **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** o **`/Library/LaunchAgents`**.

Estos archivos plist tendrán una clave llamada **`MachServices`** con el nombre del servicio y una clave llamada **`Program`** con la ruta al binario:
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
Los que se encuentran en **`LaunchDameons`** se ejecutan como root. Por lo tanto, si un proceso sin privilegios puede comunicarse con uno de ellos, podría ser capaz de escalar privilegios.

## XPC Objects

- **`xpc_object_t`**

Cada mensaje XPC es un objeto de diccionario que simplifica la serialización y deserialización. Además, `libxpc.dylib` declara la mayoría de los tipos de datos, por lo que es posible comprobar que los datos recibidos sean del tipo esperado. En la API de C, cada objeto es un `xpc_object_t` (y su tipo puede comprobarse usando `xpc_get_type(object)`).\
Además, la función `xpc_copy_description(object)` puede utilizarse para obtener una representación en forma de cadena del objeto, lo que puede ser útil para fines de depuración.\
Estos objetos también tienen algunos métodos que se pueden invocar, como `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Los `xpc_object_t` se crean invocando la función `xpc_<objetType>_create`, que internamente llama a `_xpc_base_create(Class, Size)`, donde se indica el tipo de la clase del objeto (uno de `XPC_TYPE_*`) y su tamaño (se añadirán 40 B adicionales al tamaño para los metadatos). Esto significa que los datos del objeto comenzarán en el desplazamiento de 40 B.\
Por lo tanto, `xpc_<objectType>_t` es una especie de subclase de `xpc_object_t`, que sería una subclase de `os_object_t*`.

> [!WARNING]
> Ten en cuenta que debe ser el desarrollador quien utilice `xpc_dictionary_[get/set]_<objectType>` para obtener o establecer el tipo y el valor real de una clave.

- **`xpc_pipe`**

Un **`xpc_pipe`** es una tubería FIFO que los procesos pueden utilizar para comunicarse (la comunicación utiliza mensajes Mach).\
Es posible crear un servidor XPC llamando a `xpc_pipe_create()` o `xpc_pipe_create_from_port()` para crearlo usando un puerto Mach específico. Después, para recibir mensajes, se puede llamar a `xpc_pipe_receive` y `xpc_pipe_try_receive`.

Ten en cuenta que el objeto **`xpc_pipe`** es un **`xpc_object_t`** con información en su estructura sobre los dos puertos Mach utilizados y el nombre, si existe. El nombre, por ejemplo, se configura en el daemon `secinitd`, dentro de su plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`, para la tubería llamada `com.apple.secinitd`.

Un ejemplo de **`xpc_pipe`** es la **tubería bootstrap** creada por **`launchd`**, que permite compartir puertos Mach.

- **`NSXPC*`**

Estos son objetos Objective-C de alto nivel que permiten abstraer las conexiones XPC.\
Además, estos objetos son más fáciles de depurar con DTrace que los anteriores.

- **`GCD Queues`**

XPC utiliza GCD para pasar mensajes; además, genera determinadas dispatch queues, como `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Son **bundles con la extensión `.xpc`** ubicados dentro de la carpeta `XPCServices` de otros proyectos y, en el `Info.plist`, tienen `CFBundlePackageType` establecido en **`XPC!`**.\
Este archivo contiene otras claves de configuración, como `ServiceType`, que puede ser Application, User o System, o `_SandboxProfile`, que puede definir un sandbox, o `_AllowedClients`, que podría indicar los entitlements o el ID necesarios para contactar con el servicio. Estas y otras opciones de configuración serán útiles para configurar el servicio cuando se inicie.

### Starting a Service

La aplicación intenta **conectarse** a un servicio XPC usando `xpc_connection_create_mach_service`; después, launchd localiza el daemon e inicia **`xpcproxy`**. **`xpcproxy`** aplica las restricciones configuradas y crea el servicio con los FDs y puertos Mach proporcionados.

Para mejorar la velocidad de búsqueda del servicio XPC, se utiliza una cache.

Es posible rastrear las acciones de `xpcproxy` usando:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
La biblioteca XPC usa `kdebug` para registrar acciones llamando a `xpc_ktrace_pid0` y `xpc_ktrace_pid1`. Los códigos que utiliza no están documentados, por lo que es necesario añadirlos a `/usr/share/misc/trace.codes`. Tienen el prefijo `0x29` y, por ejemplo, uno de ellos es `0x29000004`: `XPC_serializer_pack`.\
La utilidad `xpcproxy` utiliza el prefijo `0x22`; por ejemplo: `0x2200001c: xpcproxy:will_do_preexec`.

## Mensajes de eventos XPC

Las aplicaciones pueden **suscribirse** a distintos **mensajes** de eventos, lo que permite **iniciarlas bajo demanda** cuando ocurren dichos eventos. La **configuración** de estos servicios se realiza en archivos plist de l**aunchd**, ubicados en los **mismos directorios que los anteriores** y que contienen una clave **`LaunchEvent`** adicional.

### Comprobación del proceso que se conecta a XPC

Cuando un proceso intenta llamar a un método mediante una conexión XPC, el **servicio XPC debería comprobar si ese proceso tiene permiso para conectarse**. Estas son las formas habituales de comprobarlo y los errores comunes:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorización XPC

Apple también permite que las aplicaciones **configuren ciertos derechos y cómo obtenerlos**, de modo que, si el proceso que realiza la llamada los tiene, estaría **autorizado a llamar a un método** del servicio XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Para sniffear los mensajes XPC puedes utilizar [**xpcspy**](https://github.com/hot3eed/xpcspy), que usa **Frida**.
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

Esta funcionalidad proporcionada por `RemoteXPC.framework` (de `libxpc`) permite comunicarse mediante XPC entre diferentes hosts.\
Los servicios que admiten Remote XPC tendrán en su plist la key `UsesRemoteXPC`, como es el caso de `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Sin embargo, aunque el servicio estará registrado con `launchd`, es `UserEventAgent`, junto con los plugins `com.apple.remoted.plugin` y `com.apple.remoteservicediscovery.events.plugin`, quien proporciona la funcionalidad.

Además, `RemoteServiceDiscovery.framework` permite obtener información de `com.apple.remoted.plugin`, exponiendo funciones como `get_device`, `get_unique_device`, `connect`...

Una vez utilizado `connect` y obtenido el `fd` del socket del servicio, es posible utilizar la clase `remote_xpc_connection_*`.

Es posible obtener información sobre los servicios remotos utilizando la herramienta CLI `/usr/libexec/remotectl` con parámetros como:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
La comunicación entre BridgeOS y el host se realiza mediante una interfaz IPv6 dedicada. `MultiverseSupport.framework` permite establecer sockets cuyo `fd` se utilizará para la comunicación.\
Es posible encontrar estas comunicaciones mediante `netstat`, `nettop` o la opción open source, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
