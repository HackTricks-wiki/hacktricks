# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basiese inligting

XPC, wat staan vir XNU (die kernel wat deur macOS gebruik word) inter-Process Communication, is ’n framework vir **kommunikasie tussen prosesse** op macOS en iOS. XPC verskaf ’n meganisme om **veilige, asinchrone metode-oproepe tussen verskillende prosesse** op die stelsel te maak. Dit is deel van Apple se sekuriteitsparadigma en maak die **skepping van toepassings met geskeide privileges** moontlik, waar elke **komponent** slegs met **die permissions loop wat dit nodig het** om sy taak uit te voer, en sodoende die potensiële skade van ’n gekompromitteerde proses beperk.

XPC gebruik ’n vorm van Inter-Process Communication (IPC), wat ’n stel metodes is waarmee verskillende programme wat op dieselfde stelsel loop, data heen en weer kan stuur.

Die belangrikste voordele van XPC sluit in:

1. **Sekuriteit**: Deur werk in verskillende prosesse te skei, kan elke proses slegs die permissions kry wat dit nodig het. Dit beteken dat selfs indien ’n proses gekompromitteer word, dit ’n beperkte vermoë het om skade aan te rig.
2. **Stabiliteit**: XPC help om crashes te isoleer tot die komponent waar dit voorkom. Indien ’n proses crash, kan dit herbegin word sonder om die res van die stelsel te beïnvloed.
3. **Performance**: XPC maak concurrency maklik moontlik, aangesien verskillende take gelyktydig in verskillende prosesse uitgevoer kan word.

Die enigste **nadeel** is dat dit **minder doeltreffend** is om **’n toepassing in verskeie prosesse te skei** en hulle via XPC te laat kommunikeer. In vandag se stelsels is dit egter skaars merkbaar, en die voordele is groter.

## Toepassing-spesifieke XPC services

Die XPC-komponente van ’n toepassing is **binne die toepassing self.** In Safari kan jy hulle byvoorbeeld vind in **`/Applications/Safari.app/Contents/XPCServices`**. Hulle het die uitbreiding **`.xpc`** (soos **`com.apple.Safari.SandboxBroker.xpc`**) en is **ook bundles** met die hoofbinary daarin: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` en ’n `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Soos jy dalk dink, sal ’n **XPC-komponent ander entitlements en privileges hê** as die ander XPC-komponente of die hoof-app-binary. BEHALWE indien ’n XPC service met [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) op “True” in sy **Info.plist**-lêer gekonfigureer is. In hierdie geval sal die XPC service in dieselfde **security session as die toepassing** loop wat dit geroep het.

XPC services word deur **launchd** **gestart** wanneer dit vereis word en **afgeskakel** sodra alle take **voltooi** is, om stelselhulpbronne vry te stel. **Toepassing-spesifieke XPC-komponente kan slegs deur die toepassing gebruik word**, wat die risiko wat met potensiële vulnerabilities geassosieer word, verminder.

## Stelselwye XPC services

Stelselwye XPC services is vir alle gebruikers toeganklik. Hierdie services, hetsy launchd- of Mach-tipe, moet in plist-lêers **gedefinieer** word wat in gespesifiseerde directories geleë is, soos **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, of **`/Library/LaunchAgents`**.

Hierdie plist-lêers sal ’n sleutel genaamd **`MachServices`** met die naam van die service hê, asook ’n sleutel genaamd **`Program`** met die pad na die binary:
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
Die in **`LaunchDameons`** word deur root uitgevoer. Indien ’n unprivileged process met een hiervan kan kommunikeer, kan dit moontlik privileges eskaleer.

## XPC Objects

- **`xpc_object_t`**

Elke XPC-boodskap is ’n dictionary object wat die serialisering en deserialisering vereenvoudig. Daarbenewens verklaar `libxpc.dylib` die meeste datatipes, sodat dit moontlik is om seker te maak dat die ontvangde data van die verwagte tipe is. In die C API is elke object ’n `xpc_object_t` (en die tipe daarvan kan met `xpc_get_type(object)` nagegaan word).\
Daarbenewens kan die funksie `xpc_copy_description(object)` gebruik word om ’n stringverteenwoordiging van die object te verkry, wat nuttig kan wees vir debugging-doeleindes.\
Hierdie objects het ook sekere metodes wat geroep kan word, soos `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Die `xpc_object_t`-objects word geskep deur die `xpc_<objetType>_create`-funksie te roep, wat intern `_xpc_base_create(Class, Size)` roep, waar die tipe van die object se class (een van `XPC_TYPE_*`) en die grootte daarvan aangedui word (sommige ekstra 40B word by die grootte gevoeg vir metadata). Dit beteken dat die data van die object by offset 40B sal begin.\
Daarom is die `xpc_<objectType>_t` soortgelyk aan ’n subclass van die `xpc_object_t`, wat weer ’n subclass van `os_object_t*` sou wees.

> [!WARNING]
> Let daarop dat dit die developer behoort te wees wat `xpc_dictionary_[get/set]_<objectType>` gebruik om die tipe en werklike waarde van ’n key te verkry of in te stel.

- **`xpc_pipe`**

’n **`xpc_pipe`** is ’n FIFO-pipe wat processes kan gebruik om te kommunikeer (die kommunikasie gebruik Mach messages).\
Dit is moontlik om ’n XPC-server te skep deur `xpc_pipe_create()` of `xpc_pipe_create_from_port()` te roep om dit met ’n spesifieke Mach-port te skep. Om messages te ontvang, kan `xpc_pipe_receive` en `xpc_pipe_try_receive` geroep word.

Let daarop dat die **`xpc_pipe`**-object ’n **`xpc_object_t`** is met inligting in sy struct oor die twee Mach-ports wat gebruik word en die naam (indien enige). Die naam, byvoorbeeld die daemon `secinitd` in sy plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`, konfigureer die pipe genaamd `com.apple.secinitd`.

’n Voorbeeld van ’n **`xpc_pipe`** is die **bootstrap pip**e wat deur **`launchd`** geskep word en dit moontlik maak om Mach-ports te deel.

- **`NSXPC*`**

Hierdie is hoëvlak-Objective-C-objects wat die abstraksie van XPC-connections moontlik maak.\
Daarbenewens is dit makliker om hierdie objects met DTrace te debug as die vorige ones.

- **`GCD Queues`**

XPC gebruik GCD om messages deur te gee. Daarbenewens genereer dit sekere dispatch queues soos `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Hierdie is **bundles met die `.xpc`**-extension wat binne die **`XPCServices`**-folder van ander projects geleë is, en in die `Info.plist` het hulle die `CFBundlePackageType` op **`XPC!`** gestel.\
Hierdie file het ander configuration keys soos `ServiceType`, wat Application, User of System kan wees, of `_SandboxProfile`, wat ’n sandbox kan definieer, of `_AllowedClients`, wat entitlements of ’n ID kan aandui wat vereis word om die service te kontak. Hierdie en ander configuration options sal nuttig wees om die service te konfigureer wanneer dit geloods word.

### Starting a Service

Die app probeer om met ’n XPC-service te **connect** deur `xpc_connection_create_mach_service` te gebruik. Daarna lokaliseer launchd die daemon en begin **`xpcproxy`**. **`xpcproxy`** dwing gekonfigureerde restrictions af en spawn die service met die verskafde FDs en Mach-ports.

Om die soektog na die XPC-service te versnel, word ’n cache gebruik.

Dit is moontlik om die actions van `xpcproxy` te traceer met:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Die XPC library gebruik `kdebug` om aksies te log deur `xpc_ktrace_pid0` en `xpc_ktrace_pid1` te roep. Die kodes wat dit gebruik, is ongedokumenteerd, dus moet hulle by `/usr/share/misc/trace.codes` gevoeg word. Hulle het die prefix `0x29`, en een voorbeeld is `0x29000004`: `XPC_serializer_pack`.\
Die utility `xpcproxy` gebruik die prefix `0x22`, byvoorbeeld: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Applications kan op verskillende event **messages** **subscribe**, wat hulle in staat stel om **on-demand geïnisieer** te word wanneer sulke events plaasvind. Die **setup** vir hierdie services word in l**aunchd plist-lêers** gedoen, wat in dieselfde directories as die voriges geleë is en ’n ekstra **`LaunchEvent`**-key bevat.

### XPC Connecting Process Check

Wanneer ’n process probeer om ’n metode via ’n XPC connection te roep, behoort die **XPC service te kontroleer of daardie process toegelaat word om te connect**. Hier is die algemene maniere om dit te kontroleer en die algemene pitfalls:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple laat apps ook toe om sommige regte en hoe om dit te verkry te **configure**, sodat die calling process, indien dit hierdie regte het, **toegelaat sal word om ’n metode** van die XPC service te roep:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Om die XPC messages te sniff, kan jy [**xpcspy**](https://github.com/hot3eed/xpcspy) gebruik, wat **Frida** gebruik.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Nog ’n moontlike tool om te gebruik is [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## XPC-kommunikasie C-kodevoorbeeld

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
## XPC-kommunikasie Objective-C-kodevoorbeeld

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
## Kliënt binne 'n Dylb-kode
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

Hierdie funksionaliteit wat deur `RemoteXPC.framework` (van `libxpc`) verskaf word, laat kommunikasie via XPC deur verskillende hosts toe.\
Die dienste wat remote XPC ondersteun, sal die sleutel `UsesRemoteXPC` in hul plist hê, soos in die geval van `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Hoewel die diens met `launchd` geregistreer sal word, is dit egter `UserEventAgent` met die plugins `com.apple.remoted.plugin` en `com.apple.remoteservicediscovery.events.plugin` wat die funksionaliteit verskaf.

Daarbenewens laat die `RemoteServiceDiscovery.framework` jou toe om inligting van die `com.apple.remoted.plugin` te verkry, wat funksies soos `get_device`, `get_unique_device`, `connect`... blootstel.

Sodra `connect` gebruik is en die socket `fd` van die diens verkry is, is dit moontlik om die `remote_xpc_connection_*`-klas te gebruik.

Dit is moontlik om inligting oor remote dienste te verkry deur die CLI tool `/usr/libexec/remotectl` te gebruik met parameters soos:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Die kommunikasie tussen BridgeOS en die host vind deur ’n toegewyde IPv6-interface plaas. Die `MultiverseSupport.framework` laat toe dat sockets gevestig word waarvan die `fd` vir kommunikasie gebruik sal word.\
Dit is moontlik om hierdie kommunikasie met `netstat`, `nettop` of die open source-opsie, `netbottom`, te vind.

{{#include ../../../../../banners/hacktricks-training.md}}
