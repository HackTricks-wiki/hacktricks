# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Basiese inligting

XPC is ’n framework vir **kommunikasie tussen prosesse** op macOS en iOS. Dit bied meganismes om **veilige, asinchrone oproepe tussen prosesse** te maak. XPC ondersteun **toepassings met geskeide voorregte**, waar elke **komponent** met **slegs die toestemmings loop wat dit nodig het**, en sodoende die moontlike skade van ’n gekompromitteerde proses beperk.<sup>[[1]](#references)</sup>

XPC gebruik ’n vorm van Inter-Process Communication (IPC), ’n stel metodes waarmee verskillende programme wat op dieselfde stelsel loop data heen en weer kan stuur.

Die belangrikste voordele van XPC sluit in:

1. **Sekuriteit**: Deur werk oor verskillende prosesse te verdeel, kan elke proses slegs die toestemmings kry wat dit nodig het. Dit beteken dat selfs al word ’n proses gekompromitteer, die vermoë daarvan om skade aan te rig beperk is.
2. **Stabiliteit**: XPC help om ineenstortings te beperk tot die komponent waar dit plaasvind. As ’n proses ineenstort, kan dit herbegin word sonder om die res van die stelsel te beïnvloed.
3. **Werkverrigting**: XPC maak gelyktydige uitvoering maklik, aangesien verskillende take gelyktydig in verskillende prosesse uitgevoer kan word.

Die belangrikste **nadeel** is dat **die verdeling van ’n toepassing in verskeie prosesse** en die kommunikasie tussen hulle deur XPC oorhoofse koste meebring. Op moderne stelsels is hierdie koste gewoonlik klein in vergelyking met die voordele vir sekuriteit en stabiliteit.<sup>[[1]](#references)</sup>

## Toepassingspesifieke XPC-dienste

Die XPC-komponente van ’n toepassing is **binne die toepassing self**. In Safari kan jy hulle byvoorbeeld vind in **`/Applications/Safari.app/Contents/XPCServices`**. Hulle het die uitbreiding **`.xpc`** (soos **`com.apple.Safari.SandboxBroker.xpc`**) en is **ook bundles**, met die hoofbinêre lêer en ’n `Info.plist` daarin. Byvoorbeeld: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` en `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

’n **XPC-komponent kan ander entitlements en voorregte hê** as ander XPC-komponente of die hoofbinêre lêer van die toepassing. Een uitsondering is ’n XPC-diens wat met **`JoinExistingSession`** op `true` gestel in sy **Info.plist**-lêer gekonfigureer is. In hierdie geval sluit die XPC-diens aan by **dieselfde sekuriteitsessie as die toepassing** wat dit opgeroep het.<sup>[[4]](#references)</sup>

XPC-dienste word **deur launchd begin** wanneer dit nodig is, en kan **afgesluit word** sodra hul take **voltooi is**, om stelselhulpbronne vry te maak. **Toepassingspesifieke XPC-komponente kan slegs deur die toepassing wat dit bevat gebruik word**, wat die blootstelling aan potensiële kwesbaarhede verminder.<sup>[[2]](#references)</sup>

## Stelselwye XPC-dienste

Anders as toepassingspesifieke dienste, is stelselwye XPC-dienste nie beperk tot die toepassing wat dit bevat nie. Kliënte van verskeie gebruikers kan moontlik toegang daartoe hê, afhangend van die launchd-domein en die diens se eie magtigingskontroles. Hierdie launchd-bestuurde Mach-dienste moet **in plist**-lêers gedefinieer word wat in gidse soos **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** of **`/Library/LaunchAgents`** geleë is.<sup>[[2]](#references)[[3]](#references)</sup>

Hierdie plist-lêers het ’n **`MachServices`**-sleutel wat die diensnaam bevat, en ’n **`Program`**-sleutel wat die pad na die binêre lêer bevat:

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

Dienste in **`LaunchDaemons`** loop gewoonlik as root. As ’n onbevoorregte proses dus ’n kwesbare metode kan bereik wat deur een van hierdie dienste blootgestel word, kan dit moontlik voorregte eskaleer.

## XPC-objekte

- **`xpc_object_t`**

XPC-versoek- en antwoordladings is gewoonlik woordeboekobjekte, wat serialisering en deserialisering vereenvoudig. `libxpc.dylib` verklaar ook die datatipes wat nodig is om te verifieer dat ontvangde data die verwagte tipe het. In die C-API is elke objek ’n `xpc_object_t` (en die tipe daarvan kan nagegaan word met `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Boonop kan die funksie `xpc_copy_description(object)` gebruik word om ’n stringvoorstelling van die objek te kry, wat nuttig kan wees vir ontfouting.\
Hierdie objekte het ook metodes wat opgeroep kan word, soos `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Die `xpc_object_t`-objekte word geskep deur ’n `xpc_<objectType>_create`-funksie aan te roep, wat intern `_xpc_base_create(Class, Size)` aanroep om die objek se klas (een van `XPC_TYPE_*`) en grootte aan te dui. ’n Bykomende 40 grepe word vir metadata bygevoeg, dus begin die objekdata by ’n verskuiwing van 40 grepe.\
Daarom is `xpc_<objectType>_t` ’n soort subklas van `xpc_object_t`, wat weer ’n subklas van `os_object_t*` is.

> [!WARNING]
> Let daarop dat dit die ontwikkelaar se verantwoordelikheid is om `xpc_dictionary_[get/set]_<objectType>` te gebruik om die tipe en werklike waarde van ’n sleutel te kry of in te stel.

- **`xpc_pipe`**

’n **`xpc_pipe`** is ’n FIFO-pyp wat prosesse kan gebruik om te kommunikeer (die kommunikasie gebruik Mach-boodskappe).\
Dit is moontlik om ’n XPC-bediener te skep deur `xpc_pipe_create()` aan te roep, of `xpc_pipe_create_from_port()` om dit met ’n spesifieke Mach-poort te skep. Daarna kan `xpc_pipe_receive` en `xpc_pipe_try_receive` aangeroep word om boodskappe te ontvang.

Let daarop dat die **`xpc_pipe`**-objek ’n **`xpc_object_t`** is met inligting in sy struktuur oor die twee Mach-poorte wat gebruik word en die naam (indien enige). Die daemon `secinitd` stel byvoorbeeld in sy plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` die pyp met die naam `com.apple.secinitd` op.

’n Voorbeeld van ’n **`xpc_pipe`** is die **bootstrap-pyp** wat deur **`launchd`** geskep word. Dit maak dit moontlik om Mach-poorte te deel.

- **`NSXPC*`**

Dit is hoëvlak-Objective-C-objekte wat XPC-verbindings abstraheer.\
Boonop is dit makliker om hierdie objekte met DTrace te ontfout as die vorige objekte.

- **`GCD Queues`**

XPC gebruik GCD om boodskappe deur te gee. Dit genereer ook sekere dispatch-rye, soos `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC-dienste

Dit is **bundels met die `.xpc`**-uitbreiding wat in die **`XPCServices`**-lêergids van ander projekte voorkom. In hul `Info.plist` is `CFBundlePackageType` op **`XPC!`** gestel.\
Hierdie lêer bevat ander konfigurasiesleutels, soos `ServiceType`, wat Application, User of System kan wees; `_SandboxProfile`, wat ’n sandbox kan definieer; en `_AllowedClients`, wat die entitlements of identiteit kan aandui wat vereis word om die diens te kontak. Hierdie en ander opsies stel die diens op wanneer dit begin word.<sup>[[2]](#references)</sup>

### ’n Diens begin

Die app probeer met ’n XPC-diens **verbind** deur `xpc_connection_create_mach_service` te gebruik; launchd spoor dan die daemon op en begin **`xpcproxy`**. **`xpcproxy`** dwing die opgestelde beperkings af en skep die diens met die verskafte lêerbeskrywers en Mach-poorte.<sup>[[3]](#references)</sup>

’n Kas word gebruik om die soektog na die XPC-diens te versnel.

Dit is moontlik om die aksies van `xpcproxy` na te spoor met:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

Die XPC-biblioteek gebruik `kdebug` om aksies aan te teken deur `xpc_ktrace_pid0` en `xpc_ktrace_pid1` aan te roep. Die kodes wat dit gebruik, is nie gedokumenteer nie, dus moet hulle by `/usr/share/misc/trace.codes` gevoeg word. Hulle het die voorvoegsel `0x29`; byvoorbeeld, `0x29000004` is `XPC_serializer_pack`.\
Die hulpprogram `xpcproxy` gebruik die voorvoegsel `0x22`, byvoorbeeld: `0x2200001c: xpcproxy:will_do_preexec`.

## Ouditering van Application-tipe XPC-hulpprogramme

’n `XPCService.ServiceType` van `Application` is ’n nuttige beginpunt wanneer raamwerkverskafte hulpprogramme geoudit word: lys die bundles, behou die lopende dienste en inspekteer die helper se identifiseerder en entitlements. Soek in beide `/System/Library/Frameworks` en `/System/Library/PrivateFrameworks`; die presiese inventaris verander tussen macOS-vrystellings.<sup>[[7]](#references)</sup>

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

### Triageer die listener en herwin ’n minimale protokol

Vind `-[<delegate> listener:shouldAcceptNewConnection:]` in die helper. ’n Pad wat `exportedInterface` en `exportedObject` instel, die verbinding hervat en `YES`/`1` terugstuur sonder om die eweknie se audit-token, code requirement of entitlement na te gaan, stel die RPC-koppelvlak bloot aan enige kliënt wat die diens kan vind. Dit bewys slegs **bereikbaarheid**: impak vereis steeds ’n uitgevoerde metode wat ’n bevoorregte bewerking sonder voldoende magtiging per kliënt/metode uitvoer, of aanvallerbeheerde invoer onveilig verwerk.<sup>[[7]](#references)</sup>

Herwin slegs die selectors wat vir toetsing nodig is. Objective-C-selector-metadata onthul die aantal argumente; die gebruik van argumente in die decompiler verfyn gewoonlik die tipes (byvoorbeeld, waardes wat aan `-[EKEvent setStartDate:]` en `setEndDate:` deurgegee word, is `NSDate *`), terwyl die indirekte aanroeping aan die einde van die metode die reply-block-parameters onthul. ’n Gedeeltelike plaaslike protokol is voldoende vir `NSXPCInterface`; dit is onnodig om die volledige private protokol te rekonstrueer.<sup>[[7]](#references)</sup>

### Koppel met die gerekonstrueerde koppelvlak

Vir ’n toepassing se XPC-diens, laai enige framework wat die vereiste private klasse definieer, skep die verbinding met `initWithServiceName:`, ken die gerekonstrueerde afgeleë koppelvlak daaraan toe, installeer fout-/onderbrekings-/ongeldigmaking-hanteerders, en hervat dit eers daarna. Hou die run loop aktief vir asynchrone antwoorde. Voer die kliënt weer binne ’n sandbox-toepassing uit wanneer jy ’n sandbox-grens toets—’n suksesvolle selfstandige kliënt is nie bewys van ’n sandbox-ontsnapping nie.<sup>[[7]](#references)</sup>

<details>
<summary>Minimale Objective-C-kliënt</summary>

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

Kompileer met `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Gebruik secure-coding-foute as tipe-orakels

’n `NSCocoaErrorDomain`-fout soos kode `4101` kan die nuttige serialiseringsuitsondering verberg. Soek in die macOS unified log/Console na die diensnaam: die uitsondering identifiseer sowel die onverwagte klas as die klasse wat vir daardie selector-argument toegelaat word. Vir ’n antwoord, brei die **kliëntkant**-koppelvlak se allowlist uit met `setClasses:forSelector:argumentIndex:ofReply:`; met `ofReply:YES` beteken indeks `0` die eerste parameter van die antwoordblok, nie die eerste metodeparameter nie.<sup>[[7]](#references)</sup>

Stel die koppelvlak op voordat jy dit aan die verbinding toeken en `[c resume]` aanroep:<sup>[[7]](#references)</sup>

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

Die omgekeerde geval is ook nuttig: as die bediener ’n Foundation-invoer verwerp en ’n enkele toegelate private klas aanteken, onthul die logboek die verwagte wire-tipe en sy framework. Laai daardie framework, ondersoek die klas se metodes/eienskappe om generiese `id`-tipes te verfyn, en konstrueer die private objek dinamies. `NSInvocation`-argumente begin by indeks `2`, omdat indekse `0` en `1` die verborge `self`- en `_cmd`-argumente is.<sup>[[7]](#references)</sup>

<details>
<summary>Konstrueer ’n private argument met NSInvocation</summary>

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

Vir die verwante werkvloei teen stelselwye Mach-dienste wat by launchd geregistreer is, sien:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## XPC-gebeurtenisboodskappe

Toepassings kan op verskillende gebeurtenis**boodskappe** inteken, sodat hulle **op aanvraag begin kan word** wanneer sulke gebeurtenisse plaasvind. Die **opstelling** van hierdie dienste word in l**aunchd plist-lêers** gedoen, wat in **dieselfde gidse as die voriges** geleë is en ’n ekstra **`LaunchEvent`**-sleutel bevat.

### Kontrole van die XPC-verbindingsproses

Wanneer ’n proses ’n metode deur ’n XPC-verbinding probeer aanroep, behoort die **XPC-diens te kontroleer of daardie proses toegelaat word om te koppel**. Hier is algemene verifikasiemetodes en hul slaggate:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC-magtiging

Apple laat toepassings ook toe om **magtigingsregte op te stel en te bepaal hoe oproepers dit verkry**, sodat ’n proses met die vereiste regte **toegelaat word om ’n metode aan te roep** wat deur die XPC-diens beskikbaar gestel word:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

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

Nog ’n moontlike hulpmiddel is **XPoCe2**.<sup>[[6]](#references)</sup>

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

## Kliënt binne ’n Dylib

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

Die funksionaliteit wat deur `RemoteXPC.framework` (van `libxpc`) verskaf word, maak XPC-kommunikasie tussen verskillende gashere moontlik.\
Dienste wat remote XPC ondersteun, het die `UsesRemoteXPC`-sleutel in hul plist, soos die geval is met `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Hoewel die diens by `launchd` geregistreer is, verskaf `UserEventAgent` en sy `com.apple.remoted.plugin`- en `com.apple.remoteservicediscovery.events.plugin`-inproppe die funksionaliteit.

Daarbenewens verkry `RemoteServiceDiscovery.framework` inligting van `com.apple.remoted.plugin` en stel dit funksies soos `get_device`, `get_unique_device` en `connect` bloot.

Sodra `connect` die diens se sokkel-lêerbeskrywer teruggestuur het, is dit moontlik om die `remote_xpc_connection_*`-klas te gebruik.

Dit is moontlik om inligting oor afgeleë dienste te verkry met die `/usr/libexec/remotectl`-CLI deur opdragte soos die volgende te gebruik:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

Kommunikasie tussen bridgeOS en die gasheer vind deur ’n toegewyde IPv6-koppelvlak plaas. `MultiverseSupport.framework` stel sokkies op waarvan die lêerbeskrywers vir kommunikasie gebruik word.\
Dit is moontlik om hierdie kommunikasie met `netstat`, `nettop` of die oopbron-alternatief `netbottom` te vind.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Skep XPC-dienste](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - Aanval op macOS XPC Helpers: Protokol-omgekeerde ingenieurswese](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
