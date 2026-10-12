# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

XPC, macOS और iOS पर **प्रोसेस के बीच communication** के लिए एक framework है। यह **प्रोसेस के बीच सुरक्षित, asynchronous calls** करने के तरीके प्रदान करता है। XPC **privilege-separated applications** को support करता है, जहाँ हर **component** केवल **उन्हीं permissions के साथ चलता है जिनकी उसे ज़रूरत होती है**। इससे compromised प्रोसेस से होने वाला संभावित नुकसान सीमित रहता है।<sup>[[1]](#references)</sup>

XPC, Inter-Process Communication (IPC) के एक रूप का उपयोग करता है। IPC उन तरीकों का समूह है जिनसे एक ही सिस्टम पर चल रहे अलग-अलग प्रोग्राम डेटा भेज और प्राप्त कर सकते हैं।

XPC के मुख्य लाभों में शामिल हैं:

1. **सुरक्षा**: काम को अलग-अलग प्रोसेस में बाँटने से, हर प्रोसेस को केवल वे permissions दी जा सकती हैं जिनकी उसे ज़रूरत है। इसका अर्थ है कि कोई प्रोसेस compromised होने पर भी, उससे नुकसान पहुँचाने की क्षमता सीमित रहती है।
2. **स्थिरता**: XPC crashes को उसी component तक सीमित रखने में मदद करता है जहाँ वे होते हैं। कोई प्रोसेस crash होने पर, बाकी सिस्टम को प्रभावित किए बिना उसे restart किया जा सकता है।
3. **Performance**: XPC concurrency को आसान बनाता है, क्योंकि अलग-अलग प्रोसेस में कई tasks एक साथ चलाए जा सकते हैं।

इसका मुख्य **नुकसान** यह है कि **किसी application को कई प्रोसेस में बाँटने** और उन्हें XPC के ज़रिए communicate कराने से overhead बढ़ता है। आधुनिक सिस्टम पर, सुरक्षा और स्थिरता के लाभों की तुलना में यह overhead आमतौर पर कम होता है।<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

किसी application के XPC components **उसी application के अंदर होते हैं**। उदाहरण के लिए, Safari में आप इन्हें **`/Applications/Safari.app/Contents/XPCServices`** में पा सकते हैं। इनके extension **`.xpc`** होते हैं (जैसे **`com.apple.Safari.SandboxBroker.xpc`**) और ये **bundles भी होते हैं**, जिनके अंदर मुख्य binary और एक `Info.plist` होती है। उदाहरण के लिए: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` और `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`।<sup>[[2]](#references)</sup>

किसी **XPC component के entitlements और privileges**, अन्य XPC components या मुख्य application binary से **अलग हो सकते हैं**। इसका एक अपवाद वह XPC service है जिसमें उसकी **Info.plist** फ़ाइल में **`JoinExistingSession`** को `true` पर सेट किया गया हो। ऐसी स्थिति में, XPC service उसे call करने वाले **application के समान security session में शामिल हो जाती है**।<sup>[[4]](#references)</sup>

XPC services को ज़रूरत पड़ने पर **launchd शुरू करता है** और सिस्टम resources खाली करने के लिए, उनके tasks **पूरे होने के बाद उन्हें बंद किया जा सकता है**। **Application-specific XPC components का उपयोग केवल उन्हें रखने वाला application ही कर सकता है**, जिससे संभावित vulnerabilities के जोखिम कम होते हैं।<sup>[[2]](#references)</sup>

## System-Wide XPC Services

Application-specific services के विपरीत, system-wide XPC services केवल उन्हें रखने वाले application तक सीमित नहीं होतीं। launchd domain और service के अपने authorization checks के आधार पर, कई users के clients उन तक पहुँच सकते हैं। इन launchd-managed Mach services को **plist** फ़ाइलों में परिभाषित करना ज़रूरी है। ये फ़ाइलें **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, या **`/Library/LaunchAgents`** जैसी directories में होती हैं।<sup>[[2]](#references)[[3]](#references)</sup>

इन plist फ़ाइलों में service name वाली **`MachServices`** key और binary का path रखने वाली **`Program`** key होती है:

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

Services in **`LaunchDaemons`** आमतौर पर root के रूप में चलते हैं। इसलिए, अगर कोई unprivileged process इन Services में से किसी के exposed vulnerable method तक पहुँच सकता है, तो वह privileges escalate कर सकता है।

## XPC Objects

- **`xpc_object_t`**

XPC request और reply payloads आमतौर पर dictionary objects होते हैं, जो serialization और deserialization को आसान बनाते हैं। `libxpc.dylib` में ऐसे data types भी घोषित हैं जिनसे यह verify किया जा सकता है कि मिले हुए data का type अपेक्षित है। C API में हर object एक `xpc_object_t` होता है (और उसका type `xpc_get_type(object)` का उपयोग करके जाँचा जा सकता है)।<sup>[[2]](#references)</sup>\
इसके अलावा, `xpc_copy_description(object)` function का उपयोग object का string representation पाने के लिए किया जा सकता है, जो debugging के लिए उपयोगी हो सकता है।\
इन objects में call करने के लिए कुछ methods भी होते हैं, जैसे `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` objects, `xpc_<objectType>_create` function को call करके बनाए जाते हैं, जो internally `_xpc_base_create(Class, Size)` call करता है। इसमें object की class (इनमें से एक `XPC_TYPE_*`) और size दी जाती है। Metadata के लिए अतिरिक्त 40 bytes जोड़े जाते हैं, इसलिए object data 40 bytes के offset से शुरू होता है।\
इसलिए, `xpc_<objectType>_t`, `xpc_object_t` का एक तरह का subclass है, जो स्वयं `os_object_t*` का subclass है।

> [!WARNING]
> ध्यान दें कि key का type और वास्तविक value पाने या set करने के लिए `xpc_dictionary_[get/set]_<objectType>` का उपयोग developer को ही करना चाहिए।

- **`xpc_pipe`**

**`xpc_pipe`** एक FIFO pipe है, जिसका उपयोग processes संवाद करने के लिए कर सकते हैं (यह संवाद Mach messages का उपयोग करता है)।\
`xpc_pipe_create()` या `xpc_pipe_create_from_port()` call करके XPC server बनाया जा सकता है; दूसरे function से इसे किसी खास Mach port का उपयोग करके बनाया जा सकता है। फिर, messages receive करने के लिए `xpc_pipe_receive` और `xpc_pipe_try_receive` call किए जा सकते हैं।

ध्यान दें कि **`xpc_pipe`** object एक **`xpc_object_t`** है, जिसकी struct में उपयोग किए गए दोनों Mach ports और name (अगर कोई हो) की जानकारी होती है। उदाहरण के लिए, daemon `secinitd` अपनी plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` में `com.apple.secinitd` नाम की pipe configure करता है।

**`xpc_pipe`** का एक उदाहरण **bootstrap pipe** है, जिसे **`launchd`** बनाता है। इससे Mach ports share करना संभव होता है।

- **`NSXPC*`**

ये high-level Objective-C objects हैं, जो XPC connections को abstract करते हैं।\
इसके अलावा, पिछले objects की तुलना में DTrace के साथ इन objects को debug करना आसान है।

- **`GCD Queues`**

XPC messages भेजने के लिए GCD का उपयोग करता है। इसके अलावा, यह कुछ dispatch queues भी बनाता है, जैसे `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

ये `.xpc` extension वाले **bundles** हैं, जो दूसरे projects के **`XPCServices`** folder में होते हैं। उनकी `Info.plist` में `CFBundlePackageType` को **`XPC!`** पर set किया जाता है।\
इस file में अन्य configuration keys भी होती हैं, जैसे `ServiceType`, जिसकी value Application, User या System हो सकती है; `_SandboxProfile`, जिससे sandbox define किया जा सकता है; और `_AllowedClients`, जो service से संपर्क करने के लिए आवश्यक entitlements या identity बता सकता है। ये और अन्य options service को launch किए जाने पर configure करते हैं।<sup>[[2]](#references)</sup>

### Starting a Service

App, `xpc_connection_create_mach_service` का उपयोग करके XPC service से **connect** करने की कोशिश करता है; इसके बाद launchd daemon को ढूँढ़ता है और **`xpcproxy`** शुरू करता है। **`xpcproxy`** configure किए गए restrictions लागू करता है और दिए गए file descriptors तथा Mach ports के साथ service को spawn करता है।<sup>[[3]](#references)</sup>

XPC service को खोजने की गति बढ़ाने के लिए cache का उपयोग किया जाता है।

`xpcproxy` की actions को इस तरह trace किया जा सकता है:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

XPC library `xpc_ktrace_pid0` और `xpc_ktrace_pid1` को call करके actions log करने के लिए `kdebug` का उपयोग करती है। इसमें उपयोग किए गए codes undocumented हैं, इसलिए उन्हें `/usr/share/misc/trace.codes` में जोड़ना होगा। इनका prefix `0x29` है; उदाहरण के लिए, `0x29000004` का अर्थ `XPC_serializer_pack` है।\
`xpcproxy` utility `0x22` prefix का उपयोग करती है; उदाहरण के लिए: `0x2200001c: xpcproxy:will_do_preexec`.

## Application-type XPC helpers का ऑडिट करना

`XPCService.ServiceType` का `Application` होना framework द्वारा दिए गए helpers का ऑडिट शुरू करने के लिए उपयोगी है: bundles की सूची बनाएँ, चल रही services को बनाए रखें, और helper के identifier तथा entitlements की जाँच करें। `/System/Library/Frameworks` और `/System/Library/PrivateFrameworks` दोनों में खोजें; macOS releases के अनुसार सटीक inventory बदलती रहती है।<sup>[[7]](#references)</sup>

```bash
find /System/Library/Frameworks /System/Library/PrivateFrameworks \
  -type d -name '*.xpc' -print0 2>/dev/null |
while IFS= read -r -d '' bundle; do
    plist="$bundle/Contents/Info.plist"
    [ "$(plutil -extract XPCService.ServiceType raw -o - "$plist" 2>/dev/null)" = Application ] || continue

    exe=$(plutil -extract CFBundleExecutable raw -o - "$plist" 2>/dev/null) || continue
    bin="$bundle/Contents/MacOS/$exe"
    ps -axo comm= | awk -v b="$bin" '{sub(/^[[:space:]]+/, ""); if ($0==b) found=1} END {exit !found}' || continue

    printf '\n%s\n  id: %s\n' "$bundle" \
      "$(plutil -extract CFBundleIdentifier raw -o - "$plist" 2>/dev/null)"
    codesign -d --entitlements :- "$bundle" 2>&1
done
```

### listener की जांच करें और एक न्यूनतम protocol प्राप्त करें

Helper में `-[<delegate> listener:shouldAcceptNewConnection:]` खोजें। यदि कोई path `exportedInterface` और `exportedObject` सेट करता है, connection को resume करता है, और peer के audit token, code requirement या entitlement की जांच किए बिना `YES`/`1` लौटाता है, तो RPC interface उस हर client के लिए खुला है जो service को resolve कर सकता है। इससे केवल **पहुंच-क्षमता** साबित होती है: प्रभाव के लिए अब भी किसी exported method का ऐसा privileged operation करना ज़रूरी है जिसमें पर्याप्त per-client/per-method authorization न हो, या जो attacker-controlled input को असुरक्षित तरीके से process करे।<sup>[[7]](#references)</sup>

Testing के लिए केवल ज़रूरी selectors प्राप्त करें। Objective-C selector metadata से argument की संख्या पता चलती है; decompiler में argument के उपयोग से आम तौर पर types का पता और बेहतर तरीके से चलता है (उदाहरण के लिए, `-[EKEvent setStartDate:]` और `setEndDate:` को पास की गई values `NSDate *` होती हैं), जबकि method के अंत में indirect invocation से reply-block के parameters पता चलते हैं। `NSXPCInterface` के लिए एक आंशिक local protocol पर्याप्त है; पूरे private protocol को फिर से बनाना ज़रूरी नहीं है।<sup>[[7]](#references)</sup>

### पुनर्निर्मित interface से connect करें

Application XPC service के लिए, ज़रूरी private classes को परिभाषित करने वाला कोई भी framework load करें, `initWithServiceName:` से connection बनाएँ, पुनर्निर्मित remote interface assign करें, error/interruption/invalidation handlers install करें, और उसके बाद ही उसे resume करें। Asynchronous replies के लिए run loop को चालू रखें। Sandbox boundary की जांच करते समय client को sandboxed application के भीतर फिर से चलाएँ—एक standalone client का सफल होना sandbox escape का सबूत नहीं है।<sup>[[7]](#references)</sup>

<details>
<summary>न्यूनतम Objective-C client</summary>

```objectivec
@protocol RecoveredProtocol
- (void)createEventIntentWithStartDate:(NSDate *)start
                               endDate:(NSDate *)end
                             withReply:(void (^)(id object, id error))reply;
@end

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AppPredictionFoundation.framework"] load];
NSXPCConnection *c = [[NSXPCConnection alloc]
    initWithServiceName:@"com.apple.proactive.AppPredictionIntentsHelperService"];
c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
c.interruptionHandler = ^{ NSLog(@"interrupted"); };
c.invalidationHandler = ^{ NSLog(@"invalidated"); };
[c resume];
id proxy = [c remoteObjectProxyWithErrorHandler:^(NSError *e) { NSLog(@"%@", e); }];
[proxy createEventIntentWithStartDate:[NSDate date]
                              endDate:[NSDate dateWithTimeIntervalSinceNow:3600]
                            withReply:^(id obj, id err) { NSLog(@"%@ %@", obj, err); }];
[[NSRunLoop currentRunLoop] run];
```

`clang -fblocks -framework Foundation -o xpc_client xpc_client.m` से compile करें।<sup>[[7]](#references)</sup>

</details>

### type oracle के रूप में secure-coding failures का उपयोग करें

`NSCocoaErrorDomain` error, जैसे code `4101`, उपयोगी serialization exception को छिपा सकता है। Service name के लिए macOS unified log/Console में खोजें: exception से unexpected class और उस selector argument के लिए allowed classes—दोनों का पता चलता है। Reply के लिए, `setClasses:forSelector:argumentIndex:ofReply:` की मदद से **client-side** interface allowlist को बढ़ाएँ; `ofReply:YES` के साथ, index `0` reply block के पहले parameter को दर्शाता है, method के पहले parameter को नहीं।<sup>[[7]](#references)</sup>

Interface को connection को assign करने और `[c resume]` call करने से पहले configure करें:<sup>[[7]](#references)</sup>

```objectivec
NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
NSMutableSet *classes = [NSMutableSet setWithArray:@[
    NSDate.class, NSString.class, NSNumber.class,
    NSDictionary.class, NSArray.class, NSData.class
]];
Class intentClass = NSClassFromString(@"INIntent");
if (intentClass) [classes addObject:intentClass];
[iface setClasses:classes
      forSelector:@selector(createEventIntentWithStartDate:endDate:withReply:)
    argumentIndex:0
          ofReply:YES];
c.remoteObjectInterface = iface;
```

इसका उलटा मामला भी उपयोगी है: यदि server किसी Foundation input को अस्वीकार करके केवल एक स्वीकृत private class को log करता है, तो log से अपेक्षित wire type और उसका framework पता चलता है। उस framework को load करें, generic `id` types को और बेहतर समझने के लिए class के methods/properties की जाँच करें, और private object को dynamically बनाएँ। `NSInvocation` arguments, index `2` से शुरू होते हैं, क्योंकि indexes `0` और `1` छिपे हुए `self` और `_cmd` arguments होते हैं।<sup>[[7]](#references)</sup>

<details>
<summary>NSInvocation से private argument बनाएँ</summary>

```objectivec
Class cls = NSClassFromString(@"LNStaticDeferredLocalizedString");
id allocated = [cls alloc];
SEL initializer = NSSelectorFromString(@"initWithKey:table:bundleURL:");
NSMethodSignature *signature = [allocated methodSignatureForSelector:initializer];
NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
[invocation setTarget:allocated];
[invocation setSelector:initializer];

NSString *key = @"KEY";
NSString *table = @"Localizable";
NSURL *bundleURL = NSBundle.mainBundle.bundleURL;
[invocation setArgument:&key atIndex:2];
[invocation setArgument:&table atIndex:3];
[invocation setArgument:&bundleURL atIndex:4];
[invocation invoke];

__unsafe_unretained id privateObject = nil;
[invocation getReturnValue:&privateObject];
```

</details>

launchd-registered, system-wide Mach services के लिए संबंधित workflow देखने हेतु, देखें:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## XPC इवेंट संदेश

Applications अलग-अलग इवेंट संदेशों की **सदस्यता ले सकती हैं**, जिससे ऐसे इवेंट होने पर उन्हें **मांग पर शुरू किया जा सकता है**। इन सेवाओं का **सेटअप** l**aunchd plist files** में किया जाता है, जो **पहले बताए गए समान डायरेक्टरीज़ में** स्थित होती हैं और जिनमें एक अतिरिक्त **`LaunchEvent`** key होती है।

### XPC कनेक्टिंग प्रोसेस की जांच

जब कोई process XPC connection के ज़रिए किसी method को call करने की कोशिश करता है, तो **XPC service को जांचना चाहिए कि उस process को connect करने की अनुमति है या नहीं**। यहां आम verification methods और उनकी कमियां दी गई हैं:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple apps को **authorization rights कॉन्फ़िगर करने और यह तय करने की भी अनुमति देता है कि callers उन्हें कैसे प्राप्त करें**, ताकि आवश्यक rights वाला process **XPC service द्वारा उपलब्ध कराए गए method को call कर सके**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC messages को sniff करने के लिए, आप **xpcspy** का उपयोग कर सकते हैं, जो **Frida** का उपयोग करता है।<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

एक अन्य संभावित टूल **XPoCe2** है।<sup>[[6]](#references)</sup>

## XPC कम्युनिकेशन C कोड उदाहरण

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

## XPC Communication Objective-C कोड उदाहरण

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

`libxpc` से `RemoteXPC.framework` द्वारा प्रदान की जाने वाली कार्यक्षमता अलग-अलग hosts के बीच XPC communication की अनुमति देती है।\
Remote XPC को support करने वाली services के plist में `UsesRemoteXPC` key होती है, जैसा कि `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` के मामले में है। हालांकि service `launchd` के साथ registered होती है, लेकिन यह कार्यक्षमता `UserEventAgent` और उसके `com.apple.remoted.plugin` तथा `com.apple.remoteservicediscovery.events.plugin` plugins प्रदान करते हैं।

इसके अलावा, `RemoteServiceDiscovery.framework`, `com.apple.remoted.plugin` से जानकारी प्राप्त करता है और `get_device`, `get_unique_device` तथा `connect` जैसे functions उपलब्ध कराता है।

`connect` द्वारा service का socket file descriptor लौटाए जाने के बाद, `remote_xpc_connection_*` class का उपयोग किया जा सकता है।

`/usr/libexec/remotectl` CLI से commands का उपयोग करके remote services के बारे में जानकारी प्राप्त की जा सकती है, जैसे:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

bridgeOS और host के बीच communication एक dedicated IPv6 interface के ज़रिए होता है। `MultiverseSupport.framework` ऐसे sockets स्थापित करता है जिनके file descriptors का उपयोग communication के लिए किया जाता है।\
इन communications को `netstat`, `nettop` या open-source विकल्प `netbottom` का उपयोग करके ढूँढ़ा जा सकता है।

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPC Services बनाना](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - macOS XPC Helpers पर हमला: Protocol Reverse Engineering](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
