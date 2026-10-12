# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

XPC ni framework ya **mawasiliano kati ya michakato** kwenye macOS na iOS. Inatoa mbinu za kufanya **miito salama na isiyosubiri kati ya michakato**. XPC inasaidia **programu zilizotenganishwa kwa ruhusa**, ambapo kila **kipengele** huendeshwa kwa **ruhusa inazohitaji tu**, hivyo kupunguza madhara yanayoweza kusababishwa na mchakato uliodukuliwa.<sup>[[1]](#references)</sup>

XPC hutumia aina ya Inter-Process Communication (IPC), ambayo ni mkusanyiko wa mbinu zinazowezesha programu tofauti zinazoendeshwa kwenye mfumo mmoja kutuma data huku na huko.

Faida kuu za XPC ni pamoja na:

1. **Usalama**: Kwa kutenganisha kazi katika michakato tofauti, kila mchakato unaweza kupewa ruhusa unazohitaji tu. Hii inamaanisha kwamba hata mchakato ukidukuliwa, uwezo wake wa kusababisha madhara huwa mdogo.
2. **Uthabiti**: XPC husaidia kuzuia athari za kuharibika kwa mchakato zisiathiri zaidi ya kipengele ambamo kunatokea. Mchakato ukiharibika, unaweza kuwashwa tena bila kuathiri mfumo uliosalia.
3. **Utendaji**: XPC hurahisisha concurrency, kwa kuwa kazi tofauti zinaweza kuendeshwa kwa wakati mmoja katika michakato tofauti.

**Hasara** kuu ni kwamba **kutenganisha programu katika michakato kadhaa** na kuifanya iwasiliane kupitia XPC huongeza gharama ya ziada. Kwenye mifumo ya kisasa gharama hii kwa kawaida huwa ndogo ikilinganishwa na faida za usalama na uthabiti.<sup>[[1]](#references)</sup>

## Huduma za XPC Maalum kwa Programu

Vipengele vya XPC vya programu **vimo ndani ya programu yenyewe**. Kwa mfano, katika Safari unaweza kuvipata kwenye **`/Applications/Safari.app/Contents/XPCServices`**. Vinatumia kiendelezi **`.xpc`** (kama **`com.apple.Safari.SandboxBroker.xpc`**) na **pia ni bundles**, zikiwa na binary kuu na `Info.plist` ndani yake. Kwa mfano: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` na `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**Kipengele cha XPC kinaweza kuwa na entitlements na ruhusa tofauti** na vipengele vingine vya XPC au binary kuu ya programu. Isipokuwa moja ni huduma ya XPC iliyosanidiwa kwa kuweka **`JoinExistingSession`** kuwa `true` kwenye faili yake ya **Info.plist**. Katika hali hii, huduma ya XPC hujiunga na **security session ileile ya programu** iliyoiita.<sup>[[4]](#references)</sup>

Huduma za XPC **huanzishwa** na **launchd** zinapohitajika na zinaweza **kuzimwa** baada ya kazi zake **kukamilika** ili kuachia rasilimali za mfumo. **Vipengele vya XPC maalum kwa programu vinaweza kutumiwa tu na programu vilivyomo ndani yake**, hivyo kupunguza uwezekano wa kukumbwa na udhaifu.<sup>[[2]](#references)</sup>

## Huduma za XPC za Mfumo Mzima

Tofauti na huduma maalum kwa programu, huduma za XPC za mfumo mzima hazizuiliwi kwa programu zilimo. Zinaweza kufikiwa na wateja kutoka kwa watumiaji wengi, kutegemea domain ya launchd na ukaguzi wa idhini wa huduma yenyewe. Huduma hizi za Mach zinazosimamiwa na launchd zinahitaji **kufafanuliwa katika** faili za plist zilizo kwenye saraka kama vile **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, au **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Faili hizi za plist zina ufunguo wa **`MachServices`** wenye jina la huduma na ufunguo wa **`Program`** wenye njia ya binary:

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

Huduma katika **`LaunchDaemons`** kwa kawaida huendeshwa kama root. Kwa hiyo, ikiwa mchakato usio na privileged unaweza kufikia method iliyo hatarini inayotolewa na mojawapo ya huduma hizi, unaweza kuweza kuongeza privileges.

## XPC Objects

- **`xpc_object_t`**

Payload za maombi na majibu ya XPC kwa kawaida ni dictionary objects, ambazo hurahisisha serialization na deserialization. `libxpc.dylib` pia hutangaza data types zinazohitajika kuthibitisha kuwa data iliyopokelewa ina type inayotarajiwa. Katika C API, kila object ni `xpc_object_t` (na type yake inaweza kukaguliwa kwa kutumia `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Zaidi ya hayo, function `xpc_copy_description(object)` inaweza kutumiwa kupata uwakilishi wa string wa object ambao unaweza kusaidia kwa madhumuni ya debugging.\
Pia objects hizi zina baadhi ya methods za kuita, kama vile `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Objects za `xpc_object_t` huundwa kwa kuita function ya `xpc_<objectType>_create`, ambayo ndani yake huita `_xpc_base_create(Class, Size)`, ikionyesha class ya object (moja ya `XPC_TYPE_*`) na ukubwa wake. Bytes 40 za ziada huongezwa kwa metadata, kwa hivyo data ya object huanza kwenye offset ya byte 40.\
Kwa hiyo, `xpc_<objectType>_t` ni kama subclass ya `xpc_object_t`, ambayo nayo ni subclass ya `os_object_t*`.

> [!WARNING]
> Kumbuka kuwa developer ndiye anayepaswa kutumia `xpc_dictionary_[get/set]_<objectType>` kupata au kuweka type na value halisi ya key.

- **`xpc_pipe`**

**`xpc_pipe`** ni FIFO pipe ambayo michakato inaweza kutumia kuwasiliana (mawasiliano hayo hutumia Mach messages).\
Inawezekana kuunda XPC server kwa kuita `xpc_pipe_create()` au `xpc_pipe_create_from_port()` ili kuiunda kwa kutumia Mach port maalum. Kisha, ili kupokea messages, inawezekana kuita `xpc_pipe_receive` na `xpc_pipe_try_receive`.

Kumbuka kuwa object ya **`xpc_pipe`** ni **`xpc_object_t`** yenye taarifa katika struct yake kuhusu Mach ports mbili zinazotumiwa na jina (ikiwa lipo). Kwa mfano, daemon `secinitd` katika plist yake `/System/Library/LaunchDaemons/com.apple.secinitd.plist` husanidi pipe inayoitwa `com.apple.secinitd`.

Mfano wa **`xpc_pipe`** ni **bootstrap pipe** inayoundwa na **`launchd`**, inayowezesha kushiriki Mach ports.

- **`NSXPC*`**

Hizi ni Objective-C objects za kiwango cha juu zinazoficha ugumu wa XPC connections.\
Zaidi ya hayo, ni rahisi zaidi kufanya debugging ya objects hizi kwa kutumia DTrace kuliko zile zilizotangulia.

- **`GCD Queues`**

XPC hutumia GCD kupitisha messages, na pia hutengeneza dispatch queues fulani kama vile `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Hizi ni **bundles zenye extension ya `.xpc`** zilizopo ndani ya folder ya **`XPCServices`** ya miradi mingine, na katika `Info.plist` zina `CFBundlePackageType` iliyowekwa kuwa **`XPC!`**.\
Faili hii ina configuration keys nyingine, kama vile `ServiceType`, ambayo inaweza kuwa Application, User, au System; `_SandboxProfile`, ambayo inaweza kufafanua sandbox; na `_AllowedClients`, ambayo inaweza kuonyesha entitlements au identity inayohitajika ili kuwasiliana na huduma. Chaguo hizi na nyingine husanidi huduma inapoanzishwa.<sup>[[2]](#references)</sup>

### Kuanzisha Huduma

App hujaribu **kuunganisha** na XPC service kwa kutumia `xpc_connection_create_mach_service`; kisha launchd hutafuta daemon na kuwasha **`xpcproxy`**. **`xpcproxy`** hutekeleza vizuizi vilivyos configured na kuanzisha service ikiwa na file descriptors na Mach ports zilizotolewa.<sup>[[3]](#references)</sup>

Ili kuboresha kasi ya kutafuta XPC service, cache hutumiwa.

Inawezekana kufuatilia vitendo vya `xpcproxy` kwa kutumia:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

Maktaba ya XPC hutumia `kdebug` kurekodi vitendo kwa kuita `xpc_ktrace_pid0` na `xpc_ktrace_pid1`. Codes inazotumia hazijaandikwa kwenye nyaraka, kwa hiyo zinahitaji kuongezwa kwenye `/usr/share/misc/trace.codes`. Zina prefix `0x29`; kwa mfano, `0x29000004` ni `XPC_serializer_pack`.\
Utility ya `xpcproxy` hutumia prefix `0x22`, kwa mfano: `0x2200001c: xpcproxy:will_do_preexec`.

## Kukagua helpers za XPC za aina ya Application

`XPCService.ServiceType` yenye thamani ya `Application` ni mahali pazuri pa kuanzia unapokagua helpers zinazotolewa na framework: orodhesha bundles, weka services zinazoendesha kwa sasa, kisha kagua kitambulisho na entitlements za helper. Tafuta kwenye `/System/Library/Frameworks` na `/System/Library/PrivateFrameworks`; orodha kamili hubadilika kadiri matoleo ya macOS yanavyotoka.<sup>[[7]](#references)</sup>

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

### Chunguza listener na urejeshe protocol ya msingi

Tafuta `-[<delegate> listener:shouldAcceptNewConnection:]` ndani ya helper. Ikiwa njia inaweka `exportedInterface` na `exportedObject`, inarejesha connection, na kurudisha `YES`/`1` bila kukagua audit token, code requirement, au entitlement ya peer, basi RPC interface inafikiwa na client yeyote anayeweza kupata service. Hii inathibitisha **reachability** pekee: ili kuwe na athari, bado kunahitajika exported method inayotekeleza operesheni yenye ruhusa za juu bila authorization ya kutosha kwa kila client au method, au inayochakata vibaya ingizo linalodhibitiwa na mshambulizi.<sup>[[7]](#references)</sup>

Rejesha selectors zinazohitajika kwa ajili ya testing pekee. Metadata ya Objective-C selector hufichua idadi ya arguments; matumizi ya arguments kwenye decompiler kwa kawaida husaidia kubaini aina zake (kwa mfano, thamani zinazopitishwa kwa `-[EKEvent setStartDate:]` na `setEndDate:` ni `NSDate *`), huku indirect invocation mwishoni mwa method ikifichua vigezo vya reply block. Protocol ya sehemu tu inatosha kwa `NSXPCInterface`; hakuna haja ya kuunda upya protocol yote ya faragha.<sup>[[7]](#references)</sup>

### Unganisha kwa kutumia interface iliyoundwa upya

Kwa XPC service ya application, pakia framework yoyote inayofafanua private classes zinazohitajika, unda connection kwa kutumia `initWithServiceName:`, weka remote interface iliyoundwa upya, weka handlers za error/interruption/invalidation, kisha ndipo uirejeshe connection. Acha run loop iendelee kufanya kazi ili kupokea majibu ya asynchronous. Endesha client tena ndani ya application iliyowekewa sandbox unapojaribu mpaka wa sandbox—client ya kawaida inayofanikiwa si ushahidi wa sandbox escape.<sup>[[7]](#references)</sup>

<details>
<summary>Client ndogo ya Objective-C</summary>

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

Compile kwa kutumia `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Tumia hitilafu za secure coding kama type oracles

Hitilafu ya `NSCocoaErrorDomain` kama vile code `4101` inaweza kuficha serialization exception yenye manufaa. Tafuta jina la service kwenye macOS unified log/Console: exception hutambua class isiyotarajiwa na class zinazoruhusiwa kwa argument hiyo ya selector. Kwa jibu, panua allowlist ya interface ya **client-side** kwa kutumia `setClasses:forSelector:argumentIndex:ofReply:`; ukitumia `ofReply:YES`, index `0` humaanisha parameter ya kwanza ya reply block, si parameter ya kwanza ya method.<sup>[[7]](#references)</sup>

Sanidi interface kabla ya kuiweka kwenye connection na kuita `[c resume]`:<sup>[[7]](#references)</sup>

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

Kisa cha kinyume pia kinafaa: ikiwa server inakataa ingizo la Foundation na kurekodi class moja tu ya private inayoruhusiwa, log hufichua aina inayotarajiwa kwenye wire na framework yake. Pakia framework hiyo, kagua methods/properties za class ili kuboresha aina za jumla za `id`, kisha unda object ya private kwa njia ya dynamic. Arguments za `NSInvocation` huanza kwenye index `2` kwa sababu indexes `0` na `1` ni arguments zilizofichwa za `self` na `_cmd`.<sup>[[7]](#references)</sup>

<details>
<summary>Unda argument ya private kwa kutumia NSInvocation</summary>

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

Kwa workflow inayohusiana na huduma za Mach za mfumo mzima zilizosajiliwa na launchd, angalia:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## Ujumbe wa Matukio ya XPC

Programu zinaweza **kujisajili** kupokea **ujumbe** tofauti wa matukio, na hivyo kuweza **kuanzishwa inapohitajika** matukio hayo yanapotokea. **Usanidi** wa huduma hizi hufanywa kwenye l**aunchd plist files**, zilizo katika **directories zilezile kama zilizotangulia** na zenye ufunguo wa ziada wa **`LaunchEvent`**.

### Ukaguzi wa Mchakato Unaounganisha wa XPC

Mchakato unapojaribu kuita method kupitia muunganisho wa XPC, **huduma ya XPC inapaswa kuangalia ikiwa mchakato huo unaruhusiwa kuunganisha**. Hizi hapa ni njia za kawaida za uthibitishaji na mapungufu yake:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Uidhinishaji wa XPC

Apple pia huruhusu programu **kusanidi haki za uidhinishaji na jinsi wapigaji huzipata**, ili mchakato wenye haki zinazohitajika **uruhusiwe kuita method** inayotolewa na huduma ya XPC:

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Ili kunusa ujumbe wa XPC, unaweza kutumia **xpcspy**, inayotumia **Frida**.<sup>[[5]](#references)</sup>

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

## Mfano wa Msimbo wa Mawasiliano ya XPC kwa C

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

## Mfano wa Msimbo wa Mawasiliano ya XPC katika Objective-C

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

## Mteja Ndani ya Dylib

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

Utendaji unaotolewa na `RemoteXPC.framework` (kutoka `libxpc`) huruhusu mawasiliano ya XPC kati ya hosts tofauti.\
Services zinazotumia remote XPC huwa na key ya `UsesRemoteXPC` kwenye plist yao, kama ilivyo kwa `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Ingawa service imesajiliwa kwenye `launchd`, `UserEventAgent` na plugins zake za `com.apple.remoted.plugin` na `com.apple.remoteservicediscovery.events.plugin` ndizo zinazotoa utendaji huo.

Aidha, `RemoteServiceDiscovery.framework` hupata taarifa kutoka kwa `com.apple.remoted.plugin`, na kufichua functions kama vile `get_device`, `get_unique_device`, na `connect`.

Baada ya `connect` kurudisha file descriptor ya socket ya service, inawezekana kutumia class ya `remote_xpc_connection_*`.

Inawezekana kupata taarifa kuhusu remote services kwa kutumia CLI ya `/usr/libexec/remotectl` na commands kama vile:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

Mawasiliano kati ya bridgeOS na host hufanyika kupitia interface maalum ya IPv6. `MultiverseSupport.framework` huunda sockets ambazo file descriptors zake hutumika kwa mawasiliano.\
Inawezekana kupata mawasiliano haya kwa kutumia `netstat`, `nettop`, au mbadala wa open-source `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Kuunda XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - Attacking macOS XPC Helpers: Uhandisi wa Reverse wa Itifaki](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
