# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

XPC, ambayo inawakilisha XNU (kernel inayotumiwa na macOS) inter-Process Communication, ni framework ya **mawasiliano kati ya processes** kwenye macOS na iOS. XPC hutoa utaratibu wa kufanya **method calls salama na za asynchronous kati ya processes tofauti** kwenye mfumo. Ni sehemu ya security paradigm ya Apple, inayowezesha **kuunda applications zilizotenganishwa kwa privileges** ambapo kila **component** huendeshwa kwa **permissions inazohitaji tu** ili kutekeleza kazi yake, hivyo kupunguza madhara yanayoweza kusababishwa na process iliyo-compromise.

XPC hutumia aina ya Inter-Process Communication (IPC), ambayo ni seti ya methods zinazowezesha programs tofauti zinazoendesha kwenye mfumo mmoja kutumiana data.

Faida kuu za XPC ni:

1. **Security**: Kwa kutenganisha kazi katika processes tofauti, kila process inaweza kupewa permissions inazohitaji tu. Hii inamaanisha kuwa hata ikiwa process ime-compromise, uwezo wake wa kusababisha madhara huwa mdogo.
2. **Stability**: XPC husaidia kuzuia crashes kwenye component zinakotokea. Ikiwa process ita-crash, inaweza kuanzishwa upya bila kuathiri sehemu nyingine ya mfumo.
3. **Performance**: XPC hurahisisha concurrency, kwa kuwa tasks tofauti zinaweza kuendeshwa kwa wakati mmoja katika processes tofauti.

**Hasara** pekee ni kwamba **kutenganisha application katika processes kadhaa** na kuzifanya ziwasiliane kupitia XPC huwa **si efficient**. Lakini katika mifumo ya leo hili karibu halionekani, na faida zake ni kubwa zaidi.

## Application Specific XPC services

XPC components za application ziko **ndani ya application yenyewe.** Kwa mfano, katika Safari unaweza kuzipata kwenye **`/Applications/Safari.app/Contents/XPCServices`**. Zina extension **`.xpc`** (kama **`com.apple.Safari.SandboxBroker.xpc`**) na pia ni **bundles** zenye binary kuu ndani yake: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` na `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Kama unavyoweza kufikiria, **XPC component itakuwa na entitlements na privileges tofauti** na XPC components nyingine au main app binary. ISIPOKUWA ikiwa XPC service imesanidiwa na [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) ikiwa “True” kwenye faili lake la **Info.plist**. Katika hali hii, XPC service itaendeshwa katika **security session ileile na application** iliyoiita.

XPC services **huanzishwa** na **launchd** zinapohitajika na **huzimwa** mara tu tasks zote zinapokuwa **zimekamilika**, ili kuachilia system resources. **Application-specific XPC components zinaweza kutumiwa na application hiyo pekee**, hivyo kupunguza risk inayohusishwa na vulnerabilities zinazoweza kuwepo.

## System Wide XPC services

System-wide XPC services zinapatikana kwa users wote. Services hizi, ziwe za launchd au za aina ya Mach, zinahitaji **kufafanuliwa katika** files za **plist** zilizo kwenye directories maalum kama **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, au **`/Library/LaunchAgents`**.

Files hizi za plist zitakuwa na key inayoitwa **`MachServices`** yenye jina la service, na key inayoitwa **`Program`** yenye path ya binary:
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
Zile zilizo katika **`LaunchDameons`** huendeshwa na root. Kwa hivyo, ikiwa mchakato usio na privileges unaweza kuwasiliana na mojawapo ya hizi, unaweza kuwa na uwezo wa kufanya privilege escalation.

## XPC Objects

- **`xpc_object_t`**

Kila ujumbe wa XPC ni dictionary object inayorahisisha serialization na deserialization. Zaidi ya hayo, `libxpc.dylib` hutangaza data types nyingi, hivyo inawezekana kuhakikisha kuwa data iliyopokelewa ni ya type inayotarajiwa. Katika C API, kila object ni `xpc_object_t` (na type yake inaweza kukaguliwa kwa kutumia `xpc_get_type(object)`).\
Zaidi ya hayo, function `xpc_copy_description(object)` inaweza kutumiwa kupata string representation ya object, ambayo inaweza kuwa muhimu kwa madhumuni ya debugging.\
Objects hizi pia zina methods za kuitwa kama `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` huundwa kwa kuita function ya `xpc_<objetType>_create`, ambayo kwa ndani huita `_xpc_base_create(Class, Size)`, ambapo type ya class ya object (moja ya `XPC_TYPE_*`) na size yake huonyeshwa (40B za ziada zitaongezwa kwenye size kwa ajili ya metadata). Hii inamaanisha kuwa data ya object itaanza kwenye offset ya 40B.\
Kwa hivyo, `xpc_<objectType>_t` ni aina ya subclass ya `xpc_object_t`, ambayo nayo ni subclass ya `os_object_t*`.

> [!WARNING]
> Kumbuka kwamba developer ndiye anayepaswa kutumia `xpc_dictionary_[get/set]_<objectType>` kupata au kuweka type na value halisi ya key.

- **`xpc_pipe`**

**`xpc_pipe`** ni FIFO pipe ambayo processes zinaweza kutumia kuwasiliana (mawasiliano hutumia Mach messages).\
Inawezekana kuunda XPC server kwa kuita `xpc_pipe_create()` au `xpc_pipe_create_from_port()` ili kuiunda kwa kutumia Mach port maalum. Kisha, ili kupokea messages, inawezekana kuita `xpc_pipe_receive` na `xpc_pipe_try_receive`.

Kumbuka kwamba object ya **`xpc_pipe`** ni **`xpc_object_t`** yenye taarifa katika struct yake kuhusu Mach ports mbili zinazotumiwa na jina (ikiwa lipo). Jina hilo, kwa mfano, daemon `secinitd` katika plist yake `/System/Library/LaunchDaemons/com.apple.secinitd.plist` husanidi pipe inayoitwa `com.apple.secinitd`.

Mfano wa **`xpc_pipe`** ni **bootstrap pip**e iliyoundwa na **`launchd`**, inayowezesha kushiriki Mach ports.

- **`NSXPC*`**

Hizi ni high-level Objective-C objects zinazowezesha abstraction ya XPC connections.\
Zaidi ya hayo, ni rahisi zaidi ku-debug objects hizi kwa kutumia DTrace kuliko zilizotajwa awali.

- **`GCD Queues`**

XPC hutumia GCD kupitisha messages; zaidi ya hayo, huzalisha dispatch queues fulani kama `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Hizi ni **bundles zenye extension ya `.xpc`** zinazopatikana ndani ya folder ya `XPCServices` ya projects nyingine, na katika `Info.plist` zina `CFBundlePackageType` iliyowekwa kuwa **`XPC!`**.\
File hii ina configuration keys nyingine kama `ServiceType`, ambayo inaweza kuwa Application, User, System, au `_SandboxProfile`, ambayo inaweza kufafanua sandbox, au `_AllowedClients`, ambayo inaweza kuonyesha entitlements au ID inayohitajika kuwasiliana na service. Hizi na configuration options nyingine zitakuwa muhimu katika kusanidi service wakati inapozinduliwa.

### Starting a Service

App hujaribu **kuunganisha** na XPC service kwa kutumia `xpc_connection_create_mach_service`, kisha launchd hutafuta daemon na kuanzisha **`xpcproxy`**. **`xpcproxy`** hutekeleza restrictions zilizosanidiwa na kuzindua service ikiwa na FDs na Mach ports zilizotolewa.

Ili kuboresha speed ya kutafuta XPC service, cache hutumiwa.

Inawezekana kufuatilia actions za `xpcproxy` kwa kutumia:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Maktaba ya XPC hutumia `kdebug` kurekodi vitendo kwa kuita `xpc_ktrace_pid0` na `xpc_ktrace_pid1`. Codes inazotumia hazijaandikwa, kwa hivyo zinahitaji kuongezwa kwenye `/usr/share/misc/trace.codes`. Zina prefix `0x29`, na kwa mfano moja ni `0x29000004`: `XPC_serializer_pack`.\
Utility ya `xpcproxy` hutumia prefix `0x22`, kwa mfano: `0x2200001c: xpcproxy:will_do_preexec`.

## Ujumbe wa Matukio wa XPC

Applications zinaweza **kujiandikisha kupokea** **ujumbe** mbalimbali wa matukio, na kuziwezesha **kuanzishwa on-demand** matukio hayo yanapotokea. **Usanidi** wa services hizi hufanywa kwenye **launchd plist files**, zilizo katika **directories zilezile kama zilizotangulia** na zilizo na key ya ziada ya **`LaunchEvent`**.

### Ukaguzi wa Mchakato Unaounganishwa wa XPC

Mchakato unapojaribu kuita method kupitia connection ya XPC, **XPC service inapaswa kukagua ikiwa mchakato huo unaruhusiwa kuunganishwa**. Hizi ndizo njia za kawaida za kufanya ukaguzi huo pamoja na makosa ya kawaida:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Uidhinishaji wa XPC

Apple pia huruhusu apps **kus configurar baadhi ya haki na jinsi ya kuzipata**, hivyo ikiwa mchakato unaopiga simu unazo, **ungeruhusiwa kuita method** kutoka kwenye XPC service:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Ili kunasa ujumbe wa XPC unaweza kutumia [**xpcspy**](https://github.com/hot3eed/xpcspy), ambayo hutumia **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Chombo kingine kinachoweza kutumika ni [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Mfano wa Code ya Mawasiliano ya XPC

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
## Client ndani ya code ya Dylb
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

Utendaji huu unaotolewa na `RemoteXPC.framework` (kutoka `libxpc`) unaruhusu kuwasiliana kupitia XPC kati ya hosts tofauti.\
Services zinazotumia remote XPC zitakuwa na key ya `UsesRemoteXPC` kwenye plist yao, kama ilivyo kwa `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Hata hivyo, ingawa service itasajiliwa na `launchd`, ni `UserEventAgent` pamoja na plugins za `com.apple.remoted.plugin` na `com.apple.remoteservicediscovery.events.plugin` zinazotoa utendaji huo.

Zaidi ya hayo, `RemoteServiceDiscovery.framework` inaruhusu kupata taarifa kutoka kwa `com.apple.remoted.plugin` kwa kufichua functions kama vile `get_device`, `get_unique_device`, `connect`...

Baada ya kutumia `connect` na kupata socket `fd` ya service, inawezekana kutumia class ya `remote_xpc_connection_*`.

Inawezekana kupata taarifa kuhusu remote services kwa kutumia CLI tool `/usr/libexec/remotectl` na parameters kama vile:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Mawasiliano kati ya BridgeOS na host hufanyika kupitia interface maalum ya IPv6. `MultiverseSupport.framework` inaruhusu kuanzisha sockets ambazo `fd` yake itatumika kwa mawasiliano.\
Inawezekana kupata mawasiliano haya kwa kutumia `netstat`, `nettop` au chaguo la open source, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
