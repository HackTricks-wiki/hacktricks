# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basic Information

XPC, ambayo inasimama kwa XNU (kernel inayotumiwa na macOS) mawasiliano kati ya Mchakato, ni mfumo wa **mawasiliano kati ya michakato** kwenye macOS na iOS. XPC inatoa mekanismu ya kufanya **kuitana kwa njia salama, zisizo za wakati mmoja kati ya michakato tofauti** kwenye mfumo. Ni sehemu ya mtindo wa usalama wa Apple, ikiruhusu **kuundwa kwa programu zenye ruhusa tofauti** ambapo kila **kipengele** kinakimbia na **ruhusa pekee zinazohitajika** kufanya kazi yake, hivyo kupunguza uharibifu unaoweza kutokea kutokana na mchakato ulioathirika.

XPC inatumia aina ya Mawasiliano kati ya Mchakato (IPC), ambayo ni seti ya mbinu za programu tofauti zinazokimbia kwenye mfumo mmoja kutuma data kwa pande zote.

Faida kuu za XPC ni pamoja na:

1. **Usalama**: Kwa kutenganisha kazi katika michakato tofauti, kila mchakato unaweza kupewa ruhusa pekee zinazohitajika. Hii inamaanisha kwamba hata kama mchakato umeathirika, ina uwezo mdogo wa kufanya madhara.
2. **Utulivu**: XPC husaidia kutenga ajali kwenye kipengele ambapo zinatokea. Ikiwa mchakato utaanguka, unaweza kuanzishwa upya bila kuathiri mfumo mzima.
3. **Utendaji**: XPC inaruhusu urahisi wa ushirikiano, kwani kazi tofauti zinaweza kufanywa kwa wakati mmoja katika michakato tofauti.

Pungufu pekee ni kwamba **kutenganisha programu katika michakato kadhaa** na kuwafanya komunikate kupitia XPC ni **kasi kidogo**. Lakini katika mifumo ya leo hii haionekani sana na faida ni bora.

## Application Specific XPC services

Vipengele vya XPC vya programu viko **ndani ya programu yenyewe.** Kwa mfano, katika Safari unaweza kuvikuta katika **`/Applications/Safari.app/Contents/XPCServices`**. Vina kiendelezi **`.xpc`** (kama **`com.apple.Safari.SandboxBroker.xpc`**) na pia ni **bundles** na binary kuu ndani yake: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` na `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Kama unavyofikiria, **kipengele cha XPC kitakuwa na ruhusa na haki tofauti** na vipengele vingine vya XPC au binary kuu ya programu. ISIPOKUWA huduma ya XPC imewekwa na [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) kuwekwa kuwa “True” katika **faili yake ya Info.plist**. Katika kesi hii, huduma ya XPC itakimbia katika **sehemu sawa ya usalama kama programu** iliyoiita.

Huduma za XPC **zinanzishwa** na **launchd** inapohitajika na **zinazimwa** mara tu kazi zote **zinapokamilika** ili kuachilia rasilimali za mfumo. **Vipengele vya XPC vya programu vinaweza kutumiwa tu na programu**, hivyo kupunguza hatari inayohusiana na udhaifu unaoweza kutokea.

## System Wide XPC services

Huduma za XPC za mfumo mzima zinapatikana kwa watumiaji wote. Huduma hizi, ama launchd au aina ya Mach, zinahitaji **kufafanuliwa katika faili za plist** zilizoko katika directories maalum kama **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, au **`/Library/LaunchAgents`**.

Hizi faili za plists zitakuwa na ufunguo unaoitwa **`MachServices`** wenye jina la huduma, na ufunguo unaoitwa **`Program`** wenye njia ya binary:
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
Wale katika **`LaunchDameons`** wanatekelezwa na root. Hivyo kama mchakato usio na mamlaka unaweza kuzungumza na mmoja wa hawa unaweza kuwa na uwezo wa kupandisha mamlaka.

## XPC Objects

- **`xpc_object_t`**

Kila ujumbe wa XPC ni kitu cha kamusi ambacho kinarahisisha uhamasishaji na uhamasishaji wa data. Zaidi ya hayo, `libxpc.dylib` inatangaza aina nyingi za data hivyo inawezekana kuhakikisha kuwa data iliyopokelewa ni ya aina inayotarajiwa. Katika API ya C kila kitu ni `xpc_object_t` (na aina yake inaweza kuangaliwa kwa kutumia `xpc_get_type(object)`).\
Zaidi ya hayo, kazi `xpc_copy_description(object)` inaweza kutumika kupata uwakilishi wa maandiko wa kitu ambacho kinaweza kuwa na manufaa kwa madhumuni ya urekebishaji.\
Vitu hivi pia vina baadhi ya mbinu za kuita kama `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` zinaundwa kwa kuita kazi `xpc_<objetType>_create`, ambayo kwa ndani inaita `_xpc_base_create(Class, Size)` ambapo inaonyeshwa aina ya darasa la kitu (moja ya `XPC_TYPE_*`) na ukubwa wake (baadhi ya 40B za ziada zitaongezwa kwenye ukubwa kwa metadata). Hii inamaanisha kuwa data ya kitu itaanza kwenye ofset 40B.\
Hivyo, `xpc_<objectType>_t` ni aina ya darasa ndogo la `xpc_object_t` ambayo itakuwa darasa ndogo la `os_object_t*`.

> [!WARNING]
> Kumbuka kwamba inapaswa kuwa mbunifu anayetumia `xpc_dictionary_[get/set]_<objectType>` kupata au kuweka aina na thamani halisi ya funguo.

- **`xpc_pipe`**

**`xpc_pipe`** ni bomba la FIFO ambalo michakato inaweza kutumia kuwasiliana (mawasiliano hutumia ujumbe wa Mach).\
Inawezekana kuunda seva ya XPC kwa kuita `xpc_pipe_create()` au `xpc_pipe_create_from_port()` kuunda kwa kutumia bandari maalum ya Mach. Kisha, kupokea ujumbe inawezekana kuita `xpc_pipe_receive` na `xpc_pipe_try_receive`.

Kumbuka kwamba kitu cha **`xpc_pipe`** ni **`xpc_object_t`** chenye taarifa katika muundo wake kuhusu bandari mbili za Mach zinazotumika na jina (ikiwa ipo). Jina, kwa mfano, daemoni `secinitd` katika plist yake `/System/Library/LaunchDaemons/com.apple.secinitd.plist` inakamilisha bomba linaloitwa `com.apple.secinitd`.

Mfano wa **`xpc_pipe`** ni **bootstrap pipe** iliyoundwa na **`launchd`** ikifanya iwezekane kushiriki bandari za Mach.

- **`NSXPC*`**

Hizi ni vitu vya kiwango cha juu vya Objective-C ambavyo vinaruhusu uhamasishaji wa muunganisho wa XPC.\
Zaidi ya hayo, ni rahisi kurekebisha vitu hivi na DTrace kuliko zile za awali.

- **`GCD Queues`**

XPC inatumia GCD kupitisha ujumbe, zaidi ya hayo inazalisha foleni fulani za dispatch kama `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Hizi ni **bundles zenye kiendelezi `.xpc`** zilizoko ndani ya folda ya **`XPCServices`** ya miradi mingine na katika `Info.plist` zina `CFBundlePackageType` iliyowekwa kuwa **`XPC!`**.\
Hii faili ina funguo nyingine za usanidi kama `ServiceType` ambayo inaweza kuwa Programu, Mtumiaji, Mfumo au `_SandboxProfile` ambayo inaweza kufafanua sandbox au `_AllowedClients` ambayo inaweza kuashiria haki au ID inayohitajika kuwasiliana na seva. hizi na chaguzi nyingine za usanidi zitakuwa na manufaa kuunda huduma wakati inazinduliwa.

### Kuanzisha Huduma

Programu inajaribu **kuunganisha** na huduma ya XPC kwa kutumia `xpc_connection_create_mach_service`, kisha launchd inapata daemoni na kuanzisha **`xpcproxy`**. **`xpcproxy`** inatekeleza vizuizi vilivyowekwa na inazalisha huduma hiyo kwa FDs na bandari za Mach zilizotolewa.

Ili kuboresha kasi ya kutafuta huduma ya XPC, cache inatumika.

Inawezekana kufuatilia vitendo vya `xpcproxy` kwa kutumia:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Maktaba ya XPC inatumia `kdebug` kurekodi vitendo vinavyopiga simu `xpc_ktrace_pid0` na `xpc_ktrace_pid1`. Mifumo inayotumika haijaandikwa, hivyo inahitajika kuiongeza kwenye `/usr/share/misc/trace.codes`. Ina kiambishi `0x29` na kwa mfano moja ni `0x29000004`: `XPC_serializer_pack`.\
Kifaa `xpcproxy` kinatumia kiambishi `0x22`, kwa mfano: `0x2200001c: xpcproxy:will_do_preexec`.

## Ujumbe wa Tukio la XPC

Programu zinaweza **kujiandikisha** kwa ujumbe tofauti wa **tukio**, na kuwapa uwezo wa **kuanzishwa kwa mahitaji** wakati matukio kama hayo yanapotokea. **Mpangilio** wa huduma hizi unafanywa katika **faili za plist za launchd**, zilizoko katika **directories sawa na zile za awali** na zinafunguo ya ziada **`LaunchEvent`**.

### Ukaguzi wa Mchakato wa Kuungana wa XPC

Wakati mchakato unajaribu kupiga simu njia kutoka kupitia muunganisho wa XPC, **huduma ya XPC inapaswa kukagua kama mchakato huo unaruhusiwa kuungana**. Hapa kuna njia za kawaida za kukagua hiyo na mtego wa kawaida:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Uidhinishaji wa XPC

Apple pia inaruhusu programu **kuunda haki fulani na jinsi ya kuzipata** hivyo ikiwa mchakato unaopiga simu una hizo itaruhusiwa **kupiga simu njia** kutoka huduma ya XPC:

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer ya XPC

Ili kunusa ujumbe za XPC unaweza kutumia [**xpcspy**](https://github.com/hot3eed/xpcspy) ambayo inatumia **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Zana nyingine inayoweza kutumika ni [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Mfano wa Kode ya C ya Mawasiliano ya XPC

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
## Mfano wa Kode ya XPC Mawasiliano ya Objective-C

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
## Mteja ndani ya Dylb code
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

Hii kazi inayotolewa na `RemoteXPC.framework` (kutoka `libxpc`) inaruhusu kuwasiliana kupitia XPC kati ya mwenyeji tofauti.\
Huduma zinazounga mkono XPC ya mbali zitakuwa na katika plist yao ufunguo UsesRemoteXPC kama ilivyo katika `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Hata hivyo, ingawa huduma itasajiliwa na `launchd`, ni `UserEventAgent` pamoja na plugins `com.apple.remoted.plugin` na `com.apple.remoteservicediscovery.events.plugin` ambazo zinatoa kazi hiyo.

Zaidi ya hayo, `RemoteServiceDiscovery.framework` inaruhusu kupata taarifa kutoka kwa `com.apple.remoted.plugin` ikionyesha kazi kama `get_device`, `get_unique_device`, `connect`...

Mara tu `connect` inapotumika na socket `fd` ya huduma inakusanywa, inawezekana kutumia darasa la `remote_xpc_connection_*`.

Inawezekana kupata taarifa kuhusu huduma za mbali kwa kutumia zana ya cli `/usr/libexec/remotectl` kwa kutumia vigezo kama:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Mawasiliano kati ya BridgeOS na mwenyeji hufanyika kupitia kiunganishi maalum cha IPv6. `MultiverseSupport.framework` inaruhusu kuanzisha soketi ambazo `fd` zitatumika kwa mawasiliano.\
Inawezekana kupata mawasiliano haya kwa kutumia `netstat`, `nettop` au chaguo la chanzo wazi, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
