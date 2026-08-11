# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basic Information

XPC macOS और iOS पर **processes के बीच communication** के लिए एक framework है। यह **processes के बीच सुरक्षित, asynchronous calls** करने के लिए mechanisms प्रदान करता है। XPC **privilege-separated applications** को support करता है, जहाँ प्रत्येक **component** केवल **उन्हीं permissions के साथ चलता है जिनकी उसे आवश्यकता होती है**, जिससे compromised process से होने वाले संभावित नुकसान को सीमित किया जा सकता है।<sup>[[1]](#references)</sup>

XPC, Inter-Process Communication (IPC) के एक रूप का उपयोग करता है, जो एक ही system पर चलने वाले अलग-अलग programs द्वारा data को एक-दूसरे को भेजने और वापस प्राप्त करने के methods का समूह है।

XPC के मुख्य लाभों में शामिल हैं:

1. **Security**: Work को अलग-अलग processes में विभाजित करके, प्रत्येक process को केवल आवश्यक permissions दी जा सकती हैं। इसका अर्थ है कि यदि कोई process compromised भी हो जाए, तो भी उसकी नुकसान पहुँचाने की क्षमता सीमित रहती है।
2. **Stability**: XPC crashes को उस component तक सीमित रखने में मदद करता है जहाँ वे होते हैं। यदि कोई process crash हो जाता है, तो उसे बाकी system को प्रभावित किए बिना restart किया जा सकता है।
3. **Performance**: XPC आसान concurrency की अनुमति देता है, क्योंकि अलग-अलग tasks को अलग-अलग processes में एक साथ चलाया जा सकता है।

मुख्य **drawback** यह है कि **किसी application को कई processes में विभाजित करना** और उन्हें XPC के माध्यम से communicate कराना overhead बढ़ाता है। आधुनिक systems पर यह overhead आमतौर पर security और stability से मिलने वाले लाभों की तुलना में छोटा होता है।<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

किसी application के XPC components **उसी application के अंदर** होते हैं। उदाहरण के लिए, Safari में आप इन्हें **`/Applications/Safari.app/Contents/XPCServices`** में पा सकते हैं। इनका extension **`.xpc`** होता है (जैसे **`com.apple.Safari.SandboxBroker.xpc`**) और ये **bundles** भी होते हैं, जिनके अंदर main binary और एक `Info.plist` होता है। उदाहरण के लिए: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` और `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`।<sup>[[2]](#references)</sup>

एक **XPC component** के entitlements और privileges अन्य XPC components या main application binary से **अलग हो सकते हैं**। इसका एक अपवाद वह XPC service है जिसमें उसकी **Info.plist** file में **`JoinExistingSession`** को `true` पर set किया गया हो। इस स्थिति में, XPC service उस **application के समान security session में शामिल हो जाती है** जिसने उसे call किया है।<sup>[[4]](#references)</sup>

XPC services को आवश्यकता होने पर **launchd** द्वारा **start** किया जाता है और system resources को मुक्त करने के लिए उनके tasks **पूरा होने** के बाद उन्हें **shut down** किया जा सकता है। **Application-specific XPC components का उपयोग केवल उन्हें contain करने वाली application द्वारा किया जा सकता है**, जिससे संभावित vulnerabilities का exposure कम होता है।<sup>[[2]](#references)</sup>

## System-Wide XPC Services

System-wide XPC services किसी एक application के बाहर भी accessible होती हैं। ये launchd-managed Mach services **plist** files में defined होनी चाहिए, जो **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, या **`/Library/LaunchAgents`** जैसी directories में स्थित होती हैं।<sup>[[3]](#references)</sup>

इन plist files में एक **`MachServices`** key होती है, जिसमें service name होता है, और एक **`Program`** key होती है, जिसमें binary का path होता है:
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
Services in **`LaunchDaemons`** आमतौर पर root के रूप में चलते हैं। इसलिए, यदि कोई unprivileged process इन Services में से किसी एक द्वारा exposed vulnerable method तक पहुँच सकता है, तो वह privileges escalate करने में सक्षम हो सकता है।

## XPC Objects

- **`xpc_object_t`**

XPC request और reply payloads आमतौर पर dictionary objects होते हैं, जो serialization और deserialization को सरल बनाते हैं। `libxpc.dylib` received data के expected type को verify करने के लिए आवश्यक data types भी declare करता है। C API में प्रत्येक object एक `xpc_object_t` होता है (और इसके type को `xpc_get_type(object)` का उपयोग करके check किया जा सकता है)।<sup>[[2]](#references)</sup>\
इसके अलावा, `xpc_copy_description(object)` का उपयोग object की string representation प्राप्त करने के लिए किया जा सकता है, जो debugging purposes के लिए उपयोगी हो सकती है।\
इन objects में call करने के लिए कुछ methods भी होते हैं, जैसे `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` objects को `xpc_<objectType>_create` function call करके बनाया जाता है, जो internally `_xpc_base_create(Class, Size)` को call करता है और object की class (जो `XPC_TYPE_*` में से एक होती है) तथा size बताता है। Metadata के लिए अतिरिक्त 40 bytes जोड़े जाते हैं, इसलिए object data 40 bytes के offset पर शुरू होता है।\
इसलिए, `xpc_<objectType>_t`, `xpc_object_t` का एक प्रकार का subclass है, जो स्वयं `os_object_t*` का subclass होगा।

> [!WARNING]
> ध्यान दें कि type और key की वास्तविक value प्राप्त या set करने के लिए `xpc_dictionary_[get/set]_<objectType>` का उपयोग developer को ही करना चाहिए।

- **`xpc_pipe`**

एक **`xpc_pipe`** एक FIFO pipe है, जिसका उपयोग processes communicate करने के लिए कर सकते हैं (इस communication में Mach messages का उपयोग होता है)।\
`xpc_pipe_create()` या `xpc_pipe_create_from_port()` को call करके XPC server बनाया जा सकता है; दूसरा function इसे किसी specific Mach port का उपयोग करके बनाता है। फिर, messages receive करने के लिए `xpc_pipe_receive` और `xpc_pipe_try_receive` को call किया जा सकता है।

ध्यान दें कि **`xpc_pipe`** object एक **`xpc_object_t`** है, जिसके struct में उपयोग किए गए दोनों Mach ports और name (यदि कोई हो) की information होती है। उदाहरण के लिए, daemon `secinitd` अपनी plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` में `com.apple.secinitd` नामक pipe को configure करता है।

**`xpc_pipe`** का एक उदाहरण **bootstrap pipe** है, जिसे **`launchd`** create करता है और जो Mach ports share करना संभव बनाता है।

- **`NSXPC*`**

ये high-level Objective-C objects हैं, जो XPC connections को abstract करते हैं।\
इसके अलावा, पिछले objects की तुलना में इन objects को DTrace के साथ debug करना आसान है।

- **`GCD Queues`**

XPC messages pass करने के लिए GCD का उपयोग करता है; इसके अलावा, यह कुछ dispatch queues generate करता है, जैसे `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

ये `.xpc` extension वाले **bundles** हैं, जो अन्य projects के `XPCServices` folder के अंदर स्थित होते हैं; इनके `Info.plist` में `CFBundlePackageType` को **`XPC!`** पर set किया जाता है।\
इस file में अन्य configuration keys भी होती हैं, जैसे `ServiceType`, जो Application, User या System हो सकता है; `_SandboxProfile`, जो sandbox define कर सकता है; और `_AllowedClients`, जो Service से contact करने के लिए आवश्यक entitlements या identity को indicate कर सकता है। ये और अन्य options Service को launch किए जाने पर configure करते हैं।<sup>[[2]](#references)</sup>

### Starting a Service

App `xpc_connection_create_mach_service` का उपयोग करके XPC Service से **connect** करने का प्रयास करता है; इसके बाद launchd daemon को locate करता है और **`xpcproxy`** को start करता है। **`xpcproxy`** configured restrictions लागू करता है और provided file descriptors तथा Mach ports के साथ Service को spawn करता है।<sup>[[3]](#references)</sup>

XPC Service की search को तेज करने के लिए cache का उपयोग किया जाता है।

`xpcproxy` की actions को निम्नलिखित का उपयोग करके trace किया जा सकता है:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC library `kdebug` का उपयोग `xpc_ktrace_pid0` और `xpc_ktrace_pid1` को call करके actions को log करने के लिए करती है। इसके द्वारा उपयोग किए जाने वाले codes undocumented हैं, इसलिए उन्हें `/usr/share/misc/trace.codes` में जोड़ना आवश्यक है। इनमें `0x29` prefix होता है; उदाहरण के लिए, `0x29000004` `XPC_serializer_pack` है।\
utility `xpcproxy` `0x22` prefix का उपयोग करती है, उदाहरण के लिए: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Applications अलग-अलग event **messages** को **subscribe** कर सकती हैं, जिससे ऐसी घटनाएं होने पर उन्हें **on-demand initiate** किया जा सके। इन services का **setup** l**aunchd plist files** में किया जाता है, जो **previous ones के समान directories** में स्थित होती हैं और इनमें एक अतिरिक्त **`LaunchEvent`** key होती है।

### XPC Connecting Process Check

जब कोई process XPC connection के माध्यम से किसी method को call करने का प्रयास करता है, तो **XPC service को जांचना चाहिए कि क्या उस process को connect करने की अनुमति है**। यहां सामान्य verification methods और उनकी कमियां दी गई हैं:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple apps को **authorization rights और callers द्वारा उन्हें प्राप्त करने का तरीका configure करने की अनुमति भी देता है**, ताकि आवश्यक rights वाला process **XPC service द्वारा exposed method को call कर सके**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC messages को sniff करने के लिए आप **xpcspy** का उपयोग कर सकते हैं, जो **Frida** का उपयोग करता है।<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
एक अन्य संभावित tool **XPoCe2** है।<sup>[[6]](#references)</sup>

## XPC Communication C Code Example

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
## XPC Communication का Objective-C Code Example

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
## Dylib के अंदर Client
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

`RemoteXPC.framework` ( `libxpc` से) द्वारा प्रदान की गई functionality अलग-अलग hosts के बीच XPC communication की अनुमति देती है।\
जो services remote XPC को support करती हैं, उनके plist में `UsesRemoteXPC` key होती है, जैसा कि `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` के मामले में है। हालांकि service `launchd` के साथ registered है, `UserEventAgent` और इसके `com.apple.remoted.plugin` तथा `com.apple.remoteservicediscovery.events.plugin` plugins यह functionality प्रदान करते हैं।

इसके अलावा, `RemoteServiceDiscovery.framework`, `com.apple.remoted.plugin` से information प्राप्त करता है और `get_device`, `get_unique_device` तथा `connect` जैसे functions expose करता है।

जब `connect` service का socket file descriptor return कर देता है, तब `remote_xpc_connection_*` class का उपयोग करना संभव होता है।

`/usr/libexec/remotectl` CLI का उपयोग करके `remote services` के बारे में information प्राप्त की जा सकती है, इसके लिए निम्न जैसे commands का उपयोग करें:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
bridgeOS और host के बीच communication एक dedicated IPv6 interface के माध्यम से होता है। `MultiverseSupport.framework` ऐसे sockets स्थापित करता है जिनके file descriptors communication के लिए उपयोग किए जाते हैं।\
इन communications को `netstat`, `nettop` या open-source alternative `netbottom` का उपयोग करके ढूँढना संभव है।

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPC Services बनाना](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
