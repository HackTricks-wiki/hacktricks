# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basic Information

XPC, जिसका अर्थ XNU (macOS द्वारा उपयोग किया जाने वाला kernel) inter-Process Communication है, macOS और iOS पर **processes के बीच communication** के लिए एक framework है। XPC system पर मौजूद **different processes के बीच safe, asynchronous method calls** करने का mechanism प्रदान करता है। यह Apple के security paradigm का एक हिस्सा है, जो **privilege-separated applications** बनाने की अनुमति देता है, जहां प्रत्येक **component** अपना कार्य करने के लिए आवश्यक **only permissions** के साथ चलता है, जिससे compromised process से होने वाले संभावित नुकसान को सीमित किया जा सकता है।

XPC, Inter-Process Communication (IPC) के एक रूप का उपयोग करता है, जो एक ही system पर चल रहे different programs के बीच data भेजने और प्राप्त करने के methods का एक set है।

XPC के primary benefits में शामिल हैं:

1. **Security**: Work को different processes में अलग करके, प्रत्येक process को केवल आवश्यक permissions दी जा सकती हैं। इसका अर्थ है कि यदि कोई process compromised हो भी जाए, तो भी उसमें नुकसान पहुंचाने की क्षमता सीमित रहती है।
2. **Stability**: XPC crashes को उस component तक सीमित रखने में सहायता करता है जहां वे होते हैं। यदि कोई process crash हो जाता है, तो उसे system के बाकी हिस्से को प्रभावित किए बिना restart किया जा सकता है।
3. **Performance**: XPC आसान concurrency की अनुमति देता है, क्योंकि different tasks को different processes में simultaneously run किया जा सकता है।

एकमात्र **drawback** यह है कि **application को कई processes में अलग करना** और उन्हें XPC के माध्यम से communicate कराना **less efficient** होता है। लेकिन आज के systems में यह लगभग noticeable नहीं है और इसके benefits बेहतर हैं।

## Application Specific XPC services

किसी application के XPC components **application के अंदर ही होते हैं।** उदाहरण के लिए, Safari में आप इन्हें **`/Applications/Safari.app/Contents/XPCServices`** में पा सकते हैं। इनके पास **`.xpc`** extension होती है (जैसे **`com.apple.Safari.SandboxBroker.xpc`**) और ये **bundles** भी होते हैं, जिनके अंदर main binary होती है: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` और एक `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

जैसा कि आप सोच सकते हैं, एक **XPC component के entitlements और privileges** अन्य XPC components या main app binary से **different** होंगे। EXCEPT यदि किसी XPC service को उसके **Info.plist** file में [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) को “True” पर set करके configure किया गया हो। इस स्थिति में, XPC service उसी **security session** में run होगी जिस security session में उसे call करने वाली **application** run कर रही है।

XPC services को आवश्यकता पड़ने पर **launchd द्वारा start** किया जाता है और system resources को free करने के लिए सभी tasks **complete** होने के बाद **shut down** कर दिया जाता है। **Application-specific XPC components का उपयोग केवल application द्वारा किया जा सकता है**, जिससे potential vulnerabilities से जुड़े risk को कम किया जा सकता है।

## System Wide XPC services

System-wide XPC services सभी users के लिए accessible होती हैं। ये services, चाहे launchd-type हों या Mach-type, **plist** files में defined होनी चाहिए, जो **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, या **`/Library/LaunchAgents`** जैसी specified directories में स्थित होती हैं।

इन plist files में service के name वाली **`MachServices`** नामक key और binary के path वाली **`Program`** नामक key होगी:
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
वे **`LaunchDameons`** में root द्वारा run किए जाते हैं। इसलिए यदि कोई unprivileged process इनमें से किसी के साथ communicate कर सके, तो वह privileges escalate करने में सक्षम हो सकता है।

## XPC Objects

- **`xpc_object_t`**

हर XPC message एक dictionary object होता है, जो serialization और deserialization को सरल बनाता है। इसके अलावा, `libxpc.dylib` अधिकांश data types declare करता है, इसलिए यह verify करना संभव है कि received data expected type का है। C API में हर object एक `xpc_object_t` होता है (और इसके type को `xpc_get_type(object)` का उपयोग करके check किया जा सकता है)।\
इसके अलावा, `xpc_copy_description(object)` function का उपयोग object का string representation प्राप्त करने के लिए किया जा सकता है, जो debugging purposes के लिए उपयोगी हो सकता है।\
इन objects में call करने के लिए कुछ methods भी होते हैं, जैसे `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` को `xpc_<objetType>_create` function call करके create किया जाता है, जो internally `_xpc_base_create(Class, Size)` call करता है। इसमें object की class का type (इनमें से एक `XPC_TYPE_*`) और उसका size दिया जाता है (metadata के लिए size में अतिरिक्त 40B जोड़े जाएंगे)। इसका अर्थ है कि object का data offset 40B से शुरू होगा।\
इसलिए, `xpc_<objectType>_t`, `xpc_object_t` का एक प्रकार का subclass है, जो स्वयं `os_object_t*` का subclass होगा।

> [!WARNING]
> ध्यान दें कि type और किसी key की वास्तविक value को प्राप्त या set करने के लिए `xpc_dictionary_[get/set]_<objectType>` का उपयोग developer को ही करना चाहिए।

- **`xpc_pipe`**

एक **`xpc_pipe`** एक FIFO pipe है, जिसका उपयोग processes communicate करने के लिए कर सकते हैं (communication में Mach messages का उपयोग होता है)।\
`xpc_pipe_create()` या `xpc_pipe_create_from_port()` call करके XPC server create किया जा सकता है, जिसमें इसे किसी specific Mach port का उपयोग करके create किया जाता है। इसके बाद messages receive करने के लिए `xpc_pipe_receive` और `xpc_pipe_try_receive` call किए जा सकते हैं।

ध्यान दें कि **`xpc_pipe`** object एक **`xpc_object_t`** है, जिसकी struct में उपयोग किए गए दो Mach ports और name (यदि कोई हो) की information होती है। उदाहरण के लिए, daemon `secinitd` अपनी plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` में `com.apple.secinitd` नामक pipe को configure करता है।

एक **`xpc_pipe`** का उदाहरण **bootstrap pipe** है, जिसे **`launchd`** create करता है और जिससे Mach ports share करना संभव होता है।

- **`NSXPC*`**

ये Objective-C के high-level objects हैं, जो XPC connections का abstraction प्रदान करते हैं।\
इसके अलावा, पिछले objects की तुलना में इन objects को DTrace से debug करना आसान होता है।

- **`GCD Queues`**

XPC messages pass करने के लिए GCD का उपयोग करता है। इसके अलावा, यह कुछ dispatch queues generate करता है, जैसे `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

ये `.xpc` extension वाले **bundles** होते हैं, जो अन्य projects के **`XPCServices`** folder के अंदर located होते हैं। इनके `Info.plist` में `CFBundlePackageType` को **`XPC!`** पर set किया जाता है।\
इस file में `ServiceType` जैसी अन्य configuration keys भी होती हैं, जो Application, User या System हो सकती हैं, या `_SandboxProfile`, जो sandbox define कर सकती है, या `_AllowedClients`, जो service से contact करने के लिए आवश्यक entitlements या ID का संकेत दे सकती है। ये और अन्य configuration options service को launch करते समय configure करने में उपयोगी होंगे।

### Starting a Service

App `xpc_connection_create_mach_service` का उपयोग करके XPC service से **connect** करने का प्रयास करता है। इसके बाद launchd daemon को locate करके **`xpcproxy`** start करता है। **`xpcproxy`** configured restrictions enforce करता है और provided FDs तथा Mach ports के साथ service को spawn करता है।

XPC service की search speed बेहतर करने के लिए cache का उपयोग किया जाता है।

`xpcproxy` की actions को trace करना संभव है:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC library actions को log करने के लिए `kdebug` का उपयोग करती है और `xpc_ktrace_pid0` तथा `xpc_ktrace_pid1` को call करती है। इसके द्वारा उपयोग किए जाने वाले codes undocumented हैं, इसलिए उन्हें `/usr/share/misc/trace.codes` में add करना आवश्यक है। इनमें `0x29` prefix होता है और, उदाहरण के लिए, एक code `0x29000004` है: `XPC_serializer_pack`.\
`xpcproxy` utility `0x22` prefix का उपयोग करती है, उदाहरण के लिए: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Applications अलग-अलग event **messages** को **subscribe** कर सकती हैं, जिससे ऐसे events होने पर उन्हें **on-demand initiate** किया जा सके। इन services का **setup** l**aunchd plist files** में किया जाता है, जो **previous ones** वाली **same directories** में स्थित होती हैं और इनमें एक अतिरिक्त **`LaunchEvent`** key होती है।

### XPC Connecting Process Check

जब कोई process XPC connection के माध्यम से किसी method को call करने का प्रयास करता है, तो **XPC service को check करना चाहिए कि क्या उस process को connect करने की अनुमति है**। इसे check करने के common तरीके और common pitfalls यहां दिए गए हैं:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple apps को कुछ rights और उन्हें प्राप्त करने का तरीका **configure** करने की अनुमति भी देता है, ताकि यदि calling process के पास वे rights हों, तो उसे XPC service से किसी method को **call करने की अनुमति** हो:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC messages को sniff करने के लिए आप [**xpcspy**](https://github.com/hot3eed/xpcspy) का उपयोग कर सकते हैं, जो **Frida** का उपयोग करता है।
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
एक अन्य संभावित tool जिसका उपयोग किया जा सकता है, वह [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html) है।

## XPC Communication C Code का उदाहरण

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
## XPC Communication Objective-C Code Example

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
## Dylb code के अंदर Client
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

`RemoteXPC.framework` (from `libxpc`) द्वारा प्रदान की गई यह functionality विभिन्न hosts के माध्यम से XPC के जरिए communicate करने की अनुमति देती है।\
Remote XPC को support करने वाली services के plist में `UsesRemoteXPC` key होगी, जैसा कि `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` के मामले में है। हालांकि service `launchd` के साथ registered होगी, functionality `UserEventAgent` द्वारा उसके plugins `com.apple.remoted.plugin` और `com.apple.remoteservicediscovery.events.plugin` के साथ प्रदान की जाती है।

इसके अलावा, `RemoteServiceDiscovery.framework` `com.apple.remoted.plugin` से info प्राप्त करने की अनुमति देता है और `get_device`, `get_unique_device`, `connect` जैसी functions expose करता है।

एक बार `connect` का उपयोग करके service का socket `fd` प्राप्त कर लिया जाए, तो `remote_xpc_connection_*` class का उपयोग करना संभव है।

`/usr/libexec/remotectl` CLI tool का उपयोग करके parameters के साथ remote services के बारे में information प्राप्त करना संभव है:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS और host के बीच communication एक dedicated IPv6 interface के माध्यम से होता है। `MultiverseSupport.framework` ऐसे sockets स्थापित करने की अनुमति देता है जिनका `fd` communication के लिए उपयोग किया जाएगा।\
इन communications को `netstat`, `nettop` या open source विकल्प `netbottom` का उपयोग करके ढूंढना संभव है।

{{#include ../../../../../banners/hacktricks-training.md}}
