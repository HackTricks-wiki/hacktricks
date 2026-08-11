# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basiese Inligting

XPC is ’n framework vir **kommunikasie tussen prosesse** op macOS en iOS. Dit verskaf meganismes om **veilige, asynchrone oproepe tussen prosesse** te maak. XPC ondersteun **toepassings met geskeide privileges**, waar elke **komponent** met **slegs die permissions wat dit benodig** loop, waardeur die potensiële skade van ’n gekompromitteerde proses beperk word.<sup>[[1]](#references)</sup>

XPC gebruik ’n vorm van Inter-Process Communication (IPC), wat ’n stel metodes is waarmee verskillende programme wat op dieselfde stelsel loop, data heen en weer kan stuur.

Die belangrikste voordele van XPC sluit in:

1. **Security**: Deur werk tussen verskillende prosesse te verdeel, kan elke proses slegs die permissions kry wat dit benodig. Dit beteken dat selfs al word ’n proses gekompromitteer, dit beperkte vermoë het om skade te veroorsaak.
2. **Stability**: XPC help om crashes te isoleer tot die komponent waar hulle voorkom. As ’n proses crash, kan dit herbegin word sonder om die res van die stelsel te beïnvloed.
3. **Performance**: XPC maak concurrency maklik, aangesien verskillende take gelyktydig in verskillende prosesse uitgevoer kan word.

Die belangrikste **nadeel** is dat **die verdeling van ’n toepassing in verskeie prosesse** en die kommunikasie tussen hulle deur XPC overhead toevoeg. Op moderne stelsels is hierdie overhead gewoonlik klein in vergelyking met die voordele vir security en stability.<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

Die XPC-komponente van ’n toepassing is **binne die toepassing self**. In Safari kan jy hulle byvoorbeeld in **`/Applications/Safari.app/Contents/XPCServices`** vind. Hulle het die uitbreiding **`.xpc`** (soos **`com.apple.Safari.SandboxBroker.xpc`**) en is **ook bundles**, met die hoofbinary en ’n `Info.plist` daarin. Byvoorbeeld: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` en `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

’n **XPC-komponent kan ander entitlements en privileges hê** as ander XPC-komponente of die hoofapplication binary. Een uitsondering is ’n XPC-service wat met **`JoinExistingSession`** op `true` gestel is in sy **Info.plist**-lêer. In hierdie geval sluit die XPC-service aan by **dieselfde security session as die toepassing** wat dit geroep het.<sup>[[4]](#references)</sup>

XPC-services word deur **launchd** **gestart** wanneer dit benodig word en kan **afgeskakel** word sodra hul take **voltooi** is om stelselhulpbronne vry te stel. **Application-specific XPC-komponente kan slegs deur hul bevattende toepassing gebruik word**, waardeur die blootstelling aan potensiële vulnerabilities verminder word.<sup>[[2]](#references)</sup>

## System-Wide XPC Services

Anders as application-specific services, is system-wide XPC-services nie beperk tot hul bevattende toepassing nie. Hulle kan bereikbaar wees deur clients van verskeie users, afhangend van die launchd-domain en die service se eie authorization checks. Hierdie launchd-managed Mach-services moet in **plist**-lêers gedefinieer word wat in directories soos **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, of **`/Library/LaunchAgents`** geleë is.<sup>[[2]](#references)[[3]](#references)</sup>

Hierdie plist-lêers het ’n **`MachServices`**-key wat die service name bevat en ’n **`Program`**-key wat die path na die binary bevat:
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
Dienste in **`LaunchDaemons`** loop gewoonlik as root. Daarom, indien 'n onbevoorregte proses toegang kan verkry tot 'n kwesbare metode wat deur een van hierdie dienste blootgestel word, kan dit moontlik voorregte eskaleer.

## XPC-objekte

- **`xpc_object_t`**

XPC-versoek- en antwoord-payloads is gewoonlik woordeboekobjekte, wat serialisering en deserialisering vereenvoudig. `libxpc.dylib` verklaar ook die datatipes wat nodig is om te verifieer dat ontvangde data die verwagte tipe het. In die C API is elke objek 'n `xpc_object_t` (en die tipe daarvan kan nagegaan word met `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Verder kan die funksie `xpc_copy_description(object)` gebruik word om 'n stringvoorstelling van die objek te verkry wat nuttig kan wees vir debugging-doeleindes.\
Hierdie objekte het ook metodes wat geroep kan word, soos `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Die `xpc_object_t`-objekte word geskep deur 'n `xpc_<objectType>_create`-funksie te roep, wat intern `_xpc_base_create(Class, Size)` roep en die objek se klas (een van `XPC_TYPE_*`) en grootte aandui. 'n Bykomende 40 grepe word vir metadata bygevoeg, dus begin die objekdata by offset 40 grepe.\
Daarom is die `xpc_<objectType>_t`-tipe soortgelyk aan 'n subklas van die `xpc_object_t`, wat op sy beurt 'n subklas van `os_object_t*` sou wees.

> [!WARNING]
> Let daarop dat dit die ontwikkelaar moet wees wat `xpc_dictionary_[get/set]_<objectType>` gebruik om die tipe en werklike waarde van 'n sleutel te verkry of in te stel.

- **`xpc_pipe`**

'n **`xpc_pipe`** is 'n FIFO-pyp wat prosesse kan gebruik om te kommunikeer (die kommunikasie gebruik Mach-boodskappe).\
Dit is moontlik om 'n XPC-bediener te skep deur `xpc_pipe_create()` of `xpc_pipe_create_from_port()` te roep om dit met 'n spesifieke Mach-poort te skep. Om boodskappe te ontvang, kan `xpc_pipe_receive` en `xpc_pipe_try_receive` geroep word.

Let daarop dat die **`xpc_pipe`**-objek 'n **`xpc_object_t`** is met inligting in sy struktuur oor die twee Mach-poorte wat gebruik word en die naam (indien enige). Die naam, byvoorbeeld, konfigureer die daemon `secinitd` in sy plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` die pyp genaamd `com.apple.secinitd`.

'n Voorbeeld van 'n **`xpc_pipe`** is die **bootstrap pipe** wat deur **`launchd`** geskep word, wat dit moontlik maak om Mach-poorte te deel.

- **`NSXPC*`**

Hierdie is hoëvlak-Objective-C-objekte wat XPC-verbindings abstraheer.\
Verder is dit makliker om hierdie objekte met DTrace te debug as die voriges.

- **`GCD Queues`**

XPC gebruik GCD om boodskappe deur te gee; dit genereer ook sekere dispatch queues soos `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC-dienste

Hierdie is **bundels met die `.xpc`**-uitbreiding wat binne die **`XPCServices`**-vouer van ander projekte geleë is, en in die `Info.plist` het hulle `CFBundlePackageType` op **`XPC!`** gestel.\
Hierdie lêer het ander konfigurasiesleutels, soos `ServiceType`, wat Application, User of System kan wees; `_SandboxProfile`, wat 'n sandbox kan definieer; en `_AllowedClients`, wat die entitlements of identiteit kan aandui wat nodig is om die diens te kontak. Hierdie en ander opsies konfigureer die diens wanneer dit geloods word.<sup>[[2]](#references)</sup>

### Begin van 'n diens

Die toepassing probeer om met 'n XPC-diens te **connect** deur `xpc_connection_create_mach_service` te gebruik; launchd soek dan die daemon op en begin **`xpcproxy`**. **`xpcproxy`** dwing die gekonfigureerde beperkings af en spawn die diens met die verskafde lêerdeskriptors en Mach-poorte.<sup>[[3]](#references)</sup>

Om die soektog na die XPC-diens te versnel, word 'n cache gebruik.

Dit is moontlik om die aksies van `xpcproxy` na te spoor met:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Die XPC-biblioteek gebruik `kdebug` om aksies aan te teken deur `xpc_ktrace_pid0` en `xpc_ktrace_pid1` aan te roep. Die kodes wat dit gebruik, is ongedokumenteer, dus moet hulle by `/usr/share/misc/trace.codes` gevoeg word. Hulle het die voorvoegsel `0x29`; byvoorbeeld, `0x29000004` is `XPC_serializer_pack`.\
Die nutsprogram `xpcproxy` gebruik die voorvoegsel `0x22`, byvoorbeeld: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC-gebeurtenisboodskappe

Toepassings kan op verskillende gebeurtenis**boodskappe** **inteken**, sodat hulle **op aanvraag geïnisieer** kan word wanneer sulke gebeurtenisse plaasvind. Die **opstelling** vir hierdie dienste word in **launchd plist-lêers** gedoen, wat in die **selfde gidse as die voriges** geleë is en ’n bykomende **`LaunchEvent`**-sleutel bevat.

### Kontrole van die XPC-verbindingsproses

Wanneer ’n proses probeer om ’n metode deur ’n XPC-verbinding aan te roep, behoort die **XPC-diens te kontroleer of daardie proses toegelaat word om te verbind**. Hier is algemene verifikasiemetodes en hul slaggate:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC-magtiging

Apple laat toepassings ook toe om **magtigingsregte en hoe callers dit verkry, te konfigureer**, sodat ’n proses met die vereiste regte **toegelaat word om ’n metode aan te roep** wat deur die XPC-diens blootgestel word:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC-snuffelaar

Om XPC-boodskappe te sniff, kan jy **xpcspy** gebruik, wat **Frida** gebruik.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Nog 'n moontlike hulpmiddel is **XPoCe2**.<sup>[[6]](#references)</sup>

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
## Kliënt binne 'n Dylib
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

Die funksionaliteit wat deur `RemoteXPC.framework` (van `libxpc`) verskaf word, laat XPC-kommunikasie tussen verskillende gashere toe.\
Dienste wat remote XPC ondersteun, het die `UsesRemoteXPC`-sleutel in hul plist, soos die geval is met `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Hoewel die diens met `launchd` geregistreer is, verskaf `UserEventAgent` en sy `com.apple.remoted.plugin`- en `com.apple.remoteservicediscovery.events.plugin`-plugins die funksionaliteit.

Boonop verkry `RemoteServiceDiscovery.framework` inligting van `com.apple.remoted.plugin`, wat funksies soos `get_device`, `get_unique_device` en `connect` blootstel.

Sodra `connect` die diens se socket-lêerbeskrywer teruggestuur het, is dit moontlik om die `remote_xpc_connection_*`-klas te gebruik.

Dit is moontlik om inligting oor remote dienste met die `/usr/libexec/remotectl` CLI te verkry deur opdragte soos:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Kommunikasie tussen bridgeOS en die host vind plaas deur ’n toegewyde IPv6-koppelvlak. `MultiverseSupport.framework` stel sockets daar waarvan die lêerbeskrywers vir kommunikasie gebruik word.\
Dit is moontlik om hierdie kommunikasie met `netstat`, `nettop` of die open-source alternatief `netbottom` te vind.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Skep van XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
