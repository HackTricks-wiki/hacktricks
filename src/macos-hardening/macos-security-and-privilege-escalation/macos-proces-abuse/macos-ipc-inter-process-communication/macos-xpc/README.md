# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basic Information

XPC ni framework ya **mawasiliano kati ya processes** kwenye macOS na iOS. Hutoa mbinu za kufanya **calls salama, za asynchronous kati ya processes**. XPC inasaidia **applications zenye privilege separation**, ambapo kila **component** huendeshwa kwa **permissions inazohitaji tu**, hivyo kupunguza madhara yanayoweza kusababishwa na process iliyoathiriwa.<sup>[[1]](#references)</sup>

XPC hutumia aina ya Inter-Process Communication (IPC), ambayo ni seti ya mbinu zinazowezesha programs tofauti zinazoendeshwa kwenye mfumo mmoja kutumiana data.

Faida kuu za XPC ni pamoja na:

1. **Security**: Kwa kugawanya kazi katika processes tofauti, kila process inaweza kupewa permissions inazohitaji tu. Hii inamaanisha kwamba hata process ikiathiriwa, uwezo wake wa kusababisha madhara huwa mdogo.
2. **Stability**: XPC husaidia kutenga crashes kwenye component ambako zimetokea. Ikiwa process ita-crash, inaweza kuanzishwa upya bila kuathiri sehemu nyingine ya mfumo.
3. **Performance**: XPC hurahisisha concurrency, kwa kuwa tasks tofauti zinaweza kuendeshwa kwa wakati mmoja katika processes tofauti.

**Drawback** kuu ni kwamba **kugawa application katika processes kadhaa** na kuzifanya ziwasiliane kupitia XPC huongeza overhead. Kwenye systems za kisasa, overhead hii kwa kawaida huwa ndogo ikilinganishwa na faida za security na stability.<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

XPC components za application ziko **ndani ya application yenyewe**. Kwa mfano, katika Safari unaweza kuzipata kwenye **`/Applications/Safari.app/Contents/XPCServices`**. Zina extension **`.xpc`** (kama **`com.apple.Safari.SandboxBroker.xpc`**) na pia ni **bundles**, zikiwa na binary kuu na `Info.plist` ndani yake. Kwa mfano: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` na `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**XPC component inaweza kuwa na entitlements na privileges tofauti** na XPC components nyingine au binary kuu ya application. Isipokuwa moja ni XPC service iliyosanidiwa kwa **`JoinExistingSession`** kuwekwa kuwa `true` kwenye faili yake ya **Info.plist**. Katika hali hii, XPC service hujiunga na **security session ileile ya application** iliyoiita.<sup>[[4]](#references)</sup>

XPC services **huanzishwa** na **launchd** zinapohitajika na zinaweza **kuzimwa** baada ya tasks zake **kukamilika** ili kuachilia system resources. **Application-specific XPC components zinaweza kutumiwa tu na application iliyozibeba**, hivyo kupunguza uwezekano wa vulnerabilities kutumiwa vibaya.<sup>[[2]](#references)</sup>

## System-Wide XPC Services

Tofauti na services za application-specific, system-wide XPC services hazizuiliwi kwa application iliyozibeba. Zinaweza kufikiwa na clients kutoka kwa users wengi, kulingana na launchd domain na authorization checks za service yenyewe. Services hizi za Mach zinazosimamiwa na launchd zinahitaji **kufafanuliwa katika** faili za **plist** zilizo kwenye directories kama **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, au **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Faili hizi za plist zina key ya **`MachServices`** iliyo na jina la service na key ya **`Program`** iliyo na path ya binary:
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
Huduma zilizo katika **`LaunchDaemons`** kwa kawaida huendeshwa kama root. Kwa hiyo, ikiwa mchakato usio na privileged unaweza kufikia method iliyo hatarini iliyo exposed na mojawapo ya huduma hizi, unaweza kuongeza privileges.

## Objekti za XPC

- **`xpc_object_t`**

Payload za maombi na majibu za XPC kwa kawaida huwa dictionary objects, ambazo hurahisisha serialization na deserialization. `libxpc.dylib` pia hutangaza data types zinazohitajika kuthibitisha kuwa data iliyopokelewa ina type inayotarajiwa. Katika C API, kila object ni `xpc_object_t` (na type yake inaweza kukaguliwa kwa kutumia `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Zaidi ya hayo, function `xpc_copy_description(object)` inaweza kutumika kupata string representation ya object, ambayo inaweza kuwa muhimu kwa madhumuni ya debugging.\
Objekti hizi pia zina methods za kuita kama `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Objekti za `xpc_object_t` huundwa kwa kuita function ya `xpc_<objectType>_create`, ambayo ndani yake huita `_xpc_base_create(Class, Size)`, ikionyesha class ya object (moja ya `XPC_TYPE_*`) na size. Bytes 40 za ziada huongezwa kwa metadata, kwa hiyo data ya object huanza kwenye offset ya bytes 40.\
Kwa hiyo, `xpc_<objectType>_t` ni kama subclass ya `xpc_object_t`, ambayo yenyewe ingekuwa subclass ya `os_object_t*`.

> [!WARNING]
> Kumbuka kwamba developer ndiye anayepaswa kutumia `xpc_dictionary_[get/set]_<objectType>` kupata au kuweka type na value halisi ya key.

- **`xpc_pipe`**

**`xpc_pipe`** ni FIFO pipe ambayo processes zinaweza kutumia kuwasiliana (mawasiliano hayo hutumia Mach messages).\
Inawezekana kuunda XPC server kwa kuita `xpc_pipe_create()` au `xpc_pipe_create_from_port()` ili kuiunda kwa kutumia Mach port maalum. Kisha, ili kupokea messages, inawezekana kuita `xpc_pipe_receive` na `xpc_pipe_try_receive`.

Kumbuka kwamba object ya **`xpc_pipe`** ni **`xpc_object_t`** yenye taarifa katika struct yake kuhusu Mach ports mbili zinazotumika na jina (ikiwa lipo). Jina hilo, kwa mfano, daemon `secinitd` katika plist yake `/System/Library/LaunchDaemons/com.apple.secinitd.plist` husanidi pipe inayoitwa `com.apple.secinitd`.

Mfano wa **`xpc_pipe`** ni **bootstrap pipe** inayoundwa na **`launchd`**, ambayo hufanya iwezekane kushiriki Mach ports.

- **`NSXPC*`**

Hizi ni Objective-C objects za kiwango cha juu zinazofanya abstraction ya XPC connections.\
Zaidi ya hayo, ni rahisi zaidi ku-debug objekti hizi kwa kutumia DTrace kuliko za awali.

- **`GCD Queues`**

XPC hutumia GCD kupitisha messages, na pia huunda dispatch queues fulani kama `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Huduma za XPC

Hizi ni **bundles zenye extension ya `.xpc`** zinazopatikana ndani ya folder ya **`XPCServices`** ya miradi mingine, na katika `Info.plist` zina `CFBundlePackageType` iliyowekwa kuwa **`XPC!`**.\
Faili hii ina configuration keys nyingine, kama vile `ServiceType`, ambayo inaweza kuwa Application, User, au System; `_SandboxProfile`, ambayo inaweza kufafanua sandbox; na `_AllowedClients`, ambayo inaweza kuonyesha entitlements au identity inayohitajika kuwasiliana na huduma hiyo. Chaguo hizi na nyingine husanidi huduma inapoanzishwa.<sup>[[2]](#references)</sup>

### Kuanzisha Huduma

App hujaribu **ku-connect** kwenye huduma ya XPC kwa kutumia `xpc_connection_create_mach_service`; kisha launchd hutafuta daemon na kuanzisha **`xpcproxy`**. **`xpcproxy`** hutekeleza restrictions zilizosanidiwa na hu-spawn huduma ikiwa na file descriptors na Mach ports zilizotolewa.<sup>[[3]](#references)</sup>

Ili kuboresha speed ya utafutaji wa huduma ya XPC, cache hutumika.

Inawezekana kufuatilia actions za `xpcproxy` kwa kutumia:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Maktaba ya XPC hutumia `kdebug` kurekodi vitendo kwa kuita `xpc_ktrace_pid0` na `xpc_ktrace_pid1`. Misimbo inayotumia haijaandikwa katika nyaraka, kwa hiyo inahitaji kuongezwa kwenye `/usr/share/misc/trace.codes`. Ina kiambishi awali `0x29`; kwa mfano, `0x29000004` ni `XPC_serializer_pack`.\
Utility `xpcproxy` hutumia kiambishi awali `0x22`, kwa mfano: `0x2200001c: xpcproxy:will_do_preexec`.

## Ujumbe wa Matukio ya XPC

Applications zinaweza **kujiandikisha** kwa **ujumbe** tofauti wa matukio, na hivyo kuwezesha **kuanzishwa on-demand** matukio kama hayo yanapotokea. **Usanidi** wa huduma hizi hufanywa katika **launchd plist files**, zilizoko katika **directories zilezile kama za awali** na zilizo na key ya ziada ya **`LaunchEvent`**.

### Ukaguzi wa Mchakato Unaounganisha wa XPC

Mchakato unapojaribu kuita method kupitia muunganisho wa XPC, **XPC service inapaswa kuangalia ikiwa mchakato huo unaruhusiwa kuunganisha**. Hapa kuna mbinu za kawaida za uthibitishaji na mapungufu yake:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Uidhinishaji wa XPC

Apple pia huruhusu apps **kusidi configure haki za uidhinishaji na jinsi callers wanavyozipata**, ili mchakato wenye haki zinazohitajika **uruhusiwe kuita method** iliyo exposed na XPC service:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Ili kunasa ujumbe wa XPC, unaweza kutumia **xpcspy**, ambayo hutumia **Frida**.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Zana nyingine inayowezekana ni **XPoCe2**.<sup>[[6]](#references)</sup>

## Mfano wa Msimbo wa Mawasiliano ya XPC

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
## Mfano wa Code ya Mawasiliano ya XPC katika Objective-C

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
## Client Ndani ya Dylib
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

Utendaji unaotolewa na `RemoteXPC.framework` (kutoka `libxpc`) unawezesha mawasiliano ya XPC kati ya hosts tofauti.\
Services zinazotumia remote XPC huwa na key ya `UsesRemoteXPC` katika plist yao, kama ilivyo kwa `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Ingawa service imesajiliwa na `launchd`, `UserEventAgent` pamoja na plugins zake za `com.apple.remoted.plugin` na `com.apple.remoteservicediscovery.events.plugin` ndizo zinazotoa utendaji huo.

Zaidi ya hayo, `RemoteServiceDiscovery.framework` hupata taarifa kutoka kwa `com.apple.remoted.plugin`, ikifichua functions kama `get_device`, `get_unique_device`, na `connect`.

Baada ya `connect` kurudisha service's socket file descriptor, inawezekana kutumia class ya `remote_xpc_connection_*`.

Inawezekana kupata taarifa kuhusu remote services kwa kutumia `/usr/libexec/remotectl` CLI pamoja na commands kama:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Mawasiliano kati ya bridgeOS na host hufanyika kupitia interface maalum ya IPv6. `MultiverseSupport.framework` huanzisha sockets ambazo file descriptors zake hutumika kwa mawasiliano.\
Inawezekana kupata mawasiliano haya kwa kutumia `netstat`, `nettop`, au mbadala wa open-source `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Kuunda Huduma za XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
