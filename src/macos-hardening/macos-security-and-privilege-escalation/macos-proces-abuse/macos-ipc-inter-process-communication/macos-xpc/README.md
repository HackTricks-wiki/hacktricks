# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Osnovne informacije

XPC je framework za **komunikaciju između procesa** na macOS-u i iOS-u. Obezbeđuje mehanizme za obavljanje **bezbednih, asinhronih poziva između procesa**. XPC podržava **aplikacije sa odvojenim privilegijama**, gde svaka **komponenta** radi sa **samo onim dozvolama koje su joj potrebne**, čime se ograničava potencijalna šteta od kompromitovanog procesa.<sup>[[1]](#references)</sup>

XPC koristi oblik Inter-Process Communication (IPC), odnosno skup metoda pomoću kojih različiti programi koji rade na istom sistemu mogu međusobno slati podatke.

Glavne prednosti XPC-a obuhvataju:

1. **Bezbednost**: Razdvajanjem rada na različite procese, svakom procesu mogu se dodeliti samo dozvole koje su mu potrebne. To znači da, čak i ako je proces kompromitovan, njegova mogućnost da nanese štetu ostaje ograničena.
2. **Stabilnost**: XPC pomaže da se padovi ograniče na komponentu u kojoj se dešavaju. Ako se proces sruši, može se ponovo pokrenuti bez uticaja na ostatak sistema.
3. **Performanse**: XPC omogućava jednostavnu konkurentnost, jer različiti zadaci mogu istovremeno da se izvršavaju u različitim procesima.

Glavni **nedostatak** je to što **razdvajanje aplikacije na više procesa** i njihova komunikacija putem XPC-a povećavaju overhead. Na modernim sistemima ovaj overhead je obično mali u poređenju sa prednostima u pogledu bezbednosti i stabilnosti.<sup>[[1]](#references)</sup>

## XPC Services specifični za aplikaciju

XPC komponente aplikacije nalaze se **unutar same aplikacije**. Na primer, u Safariju se mogu pronaći u **`/Applications/Safari.app/Contents/XPCServices`**. Imaju ekstenziju **`.xpc`** (kao **`com.apple.Safari.SandboxBroker.xpc`**) i takođe su **bundles**, sa glavnim binary-em i datotekom `Info.plist` unutar njih. Na primer: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` i `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**XPC komponenta može imati različite entitlements i privilegije** u odnosu na druge XPC komponente ili glavni binary aplikacije. Izuzetak je XPC service konfigurisan tako da mu je **`JoinExistingSession`** podešen na `true` u njegovoj **Info.plist** datoteci. U tom slučaju XPC service se pridružuje **istoj security sesiji kao aplikacija** koja ga je pozvala.<sup>[[4]](#references)</sup>

XPC services **pokreće** **launchd** kada je to potrebno, a mogu se **isključiti** kada su njihovi zadaci **završeni**, kako bi se oslobodili sistemski resursi. **XPC komponente specifične za aplikaciju mogu koristiti samo aplikacije koje ih sadrže**, čime se smanjuje izloženost potencijalnim ranjivostima.<sup>[[2]](#references)</sup>

## XPC Services na nivou celog sistema

Za razliku od services specifičnih za aplikaciju, XPC services na nivou celog sistema nisu ograničeni na aplikaciju koja ih sadrži. Klijenti iz više korisničkih naloga mogu im pristupiti, u zavisnosti od launchd domena i sopstvenih authorization provera service-a. Ovi launchd-managed Mach services moraju biti **definisani u plist** datotekama koje se nalaze u direktorijumima kao što su **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ili **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Ove plist datoteke imaju ključ **`MachServices`** koji sadrži naziv service-a i ključ **`Program`** koji sadrži putanju do binary-ja:
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
Servisi u **`LaunchDaemons`** obično se pokreću kao root. Zato, ako neprivilegovani proces može da pristupi ranjivoj metodi koju izlaže neki od ovih servisa, možda će moći da eskalira privilegije.

## XPC Objects

- **`xpc_object_t`**

XPC payload-i zahteva i odgovora obično su dictionary objekti, što pojednostavljuje serialization i deserialization. `libxpc.dylib` takođe deklariše tipove podataka potrebne za proveru da li primljeni podaci imaju očekivani tip. U C API-ju svaki objekat je `xpc_object_t` (a njegov tip može da se proveri pomoću `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Pored toga, funkcija `xpc_copy_description(object)` može da se koristi za dobijanje string reprezentacije objekta, koja može biti korisna za debugging.\
Ovi objekti takođe imaju određene metode koje mogu da se pozivaju, kao što su `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` objekti se kreiraju pozivanjem funkcije `xpc_<objectType>_create`, koja interno poziva `_xpc_base_create(Class, Size)`, navodeći klasu objekta (jednu od `XPC_TYPE_*`) i veličinu. Za metadata se dodaje još 40 bajtova, tako da podaci objekta počinju na offset-u od 40 bajtova.\
Zato je `xpc_<objectType>_t` neka vrsta subclass-a objekta `xpc_object_t`, koji bi bio subclass objekta `os_object_t*`.

> [!WARNING]
> Imajte na umu da developer treba da koristi `xpc_dictionary_[get/set]_<objectType>` za dobijanje ili postavljanje tipa i stvarne vrednosti ključa.

- **`xpc_pipe`**

**`xpc_pipe`** je FIFO pipe koji procesi mogu da koriste za komunikaciju (komunikacija koristi Mach messages).\
Moguće je kreirati XPC server pozivanjem `xpc_pipe_create()` ili `xpc_pipe_create_from_port()` kako bi se kreirao pomoću konkretnog Mach port-a. Zatim, za prijem poruka moguće je pozvati `xpc_pipe_receive` i `xpc_pipe_try_receive`.

Imajte na umu da je objekat **`xpc_pipe`** objekat tipa **`xpc_object_t`**, sa informacijama u svojoj strukturi o dva korišćena Mach port-a i nazivu, ako postoji. Naziv, na primer, daemon `secinitd` u svom plist-u `/System/Library/LaunchDaemons/com.apple.secinitd.plist` konfiguriše pipe pod nazivom `com.apple.secinitd`.

Primer **`xpc_pipe`** objekta je **bootstrap pipe**, koji kreira **`launchd`** i koji omogućava deljenje Mach port-ova.

- **`NSXPC*`**

Ovo su high-level Objective-C objekti koji apstrahuju XPC connections.\
Pored toga, ove objekte je lakše debug-ovati pomoću DTrace-a nego prethodne.

- **`GCD Queues`**

XPC koristi GCD za prosleđivanje poruka, a takođe generiše određene dispatch queues, kao što su `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Ovo su **bundle-ovi sa ekstenzijom `.xpc`** koji se nalaze unutar foldera **`XPCServices`** drugih projekata, a u datoteci `Info.plist` imaju `CFBundlePackageType` postavljen na **`XPC!`**.\
Ova datoteka sadrži i druge konfiguracione ključeve, kao što su `ServiceType`, koji može biti Application, User ili System; `_SandboxProfile`, koji može da definiše sandbox; i `_AllowedClients`, koji može da ukaže na entitlements ili identity potrebne za kontaktiranje servisa. Ove i druge opcije konfigurišu servis kada se pokrene.<sup>[[2]](#references)</sup>

### Starting a Service

Aplikacija pokušava da se **poveže** sa XPC servisom pomoću `xpc_connection_create_mach_service`; launchd zatim pronalazi daemon i pokreće **`xpcproxy`**. **`xpcproxy`** primenjuje konfigurisana ograničenja i pokreće servis sa prosleđenim file descriptor-ima i Mach port-ovima.<sup>[[3]](#references)</sup>

Da bi se poboljšala brzina pretrage XPC servisa, koristi se cache.

Moguće je pratiti akcije programa `xpcproxy` pomoću:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC biblioteka koristi `kdebug` za evidentiranje radnji pozivanjem funkcija `xpc_ktrace_pid0` i `xpc_ktrace_pid1`. Kodovi koje koristi nisu dokumentovani, pa ih treba dodati u `/usr/share/misc/trace.codes`. Imaju prefiks `0x29`; na primer, `0x29000004` je `XPC_serializer_pack`.\
Uslužni program `xpcproxy` koristi prefiks `0x22`, na primer: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC poruke događaja

Aplikacije mogu da se **pretplate** na različite **poruke** događaja, čime se omogućava da budu **pokrenute na zahtev** kada se takvi događaji dogode. **Podešavanje** ovih servisa obavlja se u **launchd plist datotekama**, koje se nalaze u **istim direktorijumima kao prethodne** i sadrže dodatni ključ **`LaunchEvent`**.

### Provera procesa koji se povezuje na XPC

Kada proces pokuša da pozove metodu putem XPC veze, **XPC servis treba da proveri da li tom procesu dozvoljeno povezivanje**. U nastavku su navedeni uobičajeni načini provere i njihovi nedostaci:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC autorizacija

Apple takođe omogućava aplikacijama da **podesе prava autorizacije i način na koji ih pozivaoci dobijaju**, tako da procesu sa potrebnim pravima bude **dozvoljeno da pozove metodu** koju izlaže XPC servis:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Za presretanje XPC poruka možete koristiti **xpcspy**, koji koristi **Frida**.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Još jedan mogući alat je **XPoCe2**.<sup>[[6]](#references)</sup>

## Primer XPC komunikacije u C kodu

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
## Primer Objective-C koda za XPC komunikaciju

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
## Klijent unutar Dylib-a
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

Funkcionalnost koju pruža `RemoteXPC.framework` (iz `libxpc`) omogućava XPC komunikaciju između različitih hostova.\
Servisi koji podržavaju remote XPC imaju ključ `UsesRemoteXPC` u svom plist-u, kao što je slučaj sa `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Iako je servis registrovan kod `launchd`, `UserEventAgent` i njegovi plugin-ovi `com.apple.remoted.plugin` i `com.apple.remoteservicediscovery.events.plugin` pružaju ovu funkcionalnost.

Pored toga, `RemoteServiceDiscovery.framework` dobavlja informacije iz `com.apple.remoted.plugin`, izlažući funkcije kao što su `get_device`, `get_unique_device` i `connect`.

Kada `connect` vrati deskriptor socket datoteke servisa, moguće je koristiti klasu `remote_xpc_connection_*`.

Moguće je dobiti informacije o remote servisima pomoću `/usr/libexec/remotectl` CLI-ja, koristeći komande kao što su:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Komunikacija između bridgeOS-a i hosta odvija se putem namenski izdvojenog IPv6 interfejsa. `MultiverseSupport.framework` uspostavlja socket-e čiji se file descriptor-i koriste za komunikaciju.\
Ove komunikacije je moguće pronaći pomoću alata `netstat`, `nettop` ili open-source alternative `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Kreiranje XPC usluga](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
