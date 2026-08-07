# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Osnovne informacije

XPC, što je skraćenica za XNU (kernel koji koristi macOS) inter-Process Communication, predstavlja framework za **komunikaciju između procesa** na macOS-u i iOS-u. XPC pruža mehanizam za izvršavanje **bezbednih, asinhronih poziva metoda između različitih procesa** na sistemu. To je deo Apple-ove bezbednosne paradigme, koji omogućava **kreiranje aplikacija sa odvojenim privilegijama**, gde svaka **komponenta** radi sa **samo onim dozvolama koje su joj potrebne** za obavljanje zadatka, čime se ograničava potencijalna šteta od kompromitovanog procesa.

XPC koristi oblik Inter-Process Communication (IPC), što predstavlja skup metoda pomoću kojih različiti programi koji rade na istom sistemu mogu međusobno da šalju podatke.

Glavne prednosti XPC-a uključuju:

1. **Bezbednost**: Razdvajanjem rada u različite procese, svakom procesu mogu biti dodeljene samo dozvole koje su mu potrebne. To znači da čak i ako je proces kompromitovan, njegova mogućnost da napravi štetu je ograničena.
2. **Stabilnost**: XPC pomaže u izolovanju crash-eva na komponentu u kojoj se dešavaju. Ako se proces sruši, može biti ponovo pokrenut bez uticaja na ostatak sistema.
3. **Performanse**: XPC omogućava jednostavnu konkurentnost, jer različiti zadaci mogu istovremeno da se izvršavaju u različitim procesima.

Jedina **mana** je to što je **razdvajanje aplikacije u nekoliko procesa** koji međusobno komuniciraju putem XPC-a **manje efikasno**. Međutim, u današnjim sistemima to gotovo da nije primetno, a prednosti su veće.

## Application Specific XPC services

XPC komponente aplikacije nalaze se **unutar same aplikacije.** Na primer, u Safariju ih možete pronaći u **`/Applications/Safari.app/Contents/XPCServices`**. Imaju ekstenziju **`.xpc`** (kao **`com.apple.Safari.SandboxBroker.xpc`**) i takođe su **bundles** sa glavnim binary-jem unutar njih: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` i `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Kao što možda pretpostavljate, **XPC komponenta će imati drugačije entitlements i privileges** od drugih XPC komponenti ili glavnog binary-ja aplikacije. IZUZETAK je ako je XPC service konfigurisan sa opcijom [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) postavljenom na „True“ u njegovom **Info.plist** fajlu. U tom slučaju, XPC service će raditi u **istoj security session kao aplikacija** koja ga je pozvala.

XPC services **pokreće** **launchd** kada je to potrebno, a **isključuju se** kada su svi zadaci **završeni**, kako bi se oslobodili sistemski resursi. **Application-specific XPC komponente može koristiti samo aplikacija**, čime se smanjuje rizik povezan sa potencijalnim vulnerabilities.

## System Wide XPC services

System-wide XPC services dostupni su svim korisnicima. Ovi services, bilo launchd ili Mach-type, moraju biti **definisani u plist** fajlovima koji se nalaze u određenim direktorijumima, kao što su **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ili **`/Library/LaunchAgents`**.

Ovi plist fajlovi imaće ključ pod nazivom **`MachServices`** sa imenom service-a i ključ pod nazivom **`Program`** sa putanjom do binary-ja:
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
Onei u **`LaunchDameons`** se pokreću sa root privilegijama. Dakle, ako neprivilegovan proces može da komunicira sa jednim od njih, mogao bi da eskalira privilegije.

## XPC Objects

- **`xpc_object_t`**

Svaka XPC poruka je dictionary objekat koji pojednostavljuje serialization i deserialization. Pored toga, `libxpc.dylib` definiše većinu data types, pa je moguće proveriti da li su primljeni podaci očekivanog tipa. U C API-ju svaki objekat je `xpc_object_t` (a njegov tip se može proveriti pomoću `xpc_get_type(object)`).\
Pored toga, funkcija `xpc_copy_description(object)` može da se koristi za dobijanje string reprezentacije objekta, što može biti korisno za debugging.\
Ovi objekti takođe imaju metode koje mogu da se pozivaju, kao što su `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` objekti se kreiraju pozivanjem funkcije `xpc_<objetType>_create`, koja interno poziva `_xpc_base_create(Class, Size)`, gde se navode tip klase objekta (jedan od `XPC_TYPE_*`) i njegova veličina (veličini će biti dodato dodatnih 40B za metadata). To znači da će podaci objekta počinjati na offsetu 40B.\
Zbog toga je `xpc_<objectType>_t` svojevrsna subclass klasa `xpc_object_t`, koja bi bila subclass klasa `os_object_t*`.

> [!WARNING]
> Imajte na umu da developer treba da koristi `xpc_dictionary_[get/set]_<objectType>` za dobijanje ili postavljanje tipa i stvarne vrednosti ključa.

- **`xpc_pipe`**

**`xpc_pipe`** je FIFO pipe koji procesi mogu da koriste za komunikaciju (komunikacija koristi Mach messages).\
XPC server je moguće kreirati pozivanjem `xpc_pipe_create()` ili `xpc_pipe_create_from_port()`, kako bi se kreirao pomoću određenog Mach porta. Zatim, za primanje poruka moguće je pozvati `xpc_pipe_receive` i `xpc_pipe_try_receive`.

Imajte na umu da je objekat **`xpc_pipe`** zapravo **`xpc_object_t`**, sa informacijama u svojoj strukturi o dva korišćena Mach porta i nazivu, ako postoji. Naziv, na primer, daemon `secinitd` u svom plist fajlu `/System/Library/LaunchDaemons/com.apple.secinitd.plist` konfiguriše pipe pod nazivom `com.apple.secinitd`.

Primer **`xpc_pipe`** objekta je **bootstrap pip**e koji kreira **`launchd`**, čime se omogućava deljenje Mach portova.

- **`NSXPC*`**

Ovo su high-level Objective-C objekti koji omogućavaju apstrakciju XPC connections.\
Pored toga, ove objekte je lakše debug-ovati pomoću DTrace-a nego prethodne.

- **`GCD Queues`**

XPC koristi GCD za prosleđivanje poruka; pored toga, generiše određene dispatch queues, kao što su `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Ovo su **bundles sa ekstenzijom `.xpc`** koji se nalaze unutar foldera **`XPCServices`** drugih projekata, a u `Info.plist` fajlu imaju `CFBundlePackageType` podešen na **`XPC!`**.\
Ovaj fajl ima druge configuration keys, kao što je `ServiceType`, koji može biti Application, User ili System, ili `_SandboxProfile`, koji može definisati sandbox, odnosno `_AllowedClients`, koji može ukazivati na entitlements ili ID potreban za kontaktiranje service-a. Ove i druge configuration options biće korisne za konfigurisanje service-a prilikom njegovog pokretanja.

### Starting a Service

Aplikacija pokušava da se **poveže** sa XPC service-om pomoću `xpc_connection_create_mach_service`, zatim launchd pronalazi daemon i pokreće **`xpcproxy`**. **`xpcproxy`** primenjuje konfigurisana ograničenja i pokreće service sa prosleđenim FDs i Mach portovima.

Radi poboljšanja brzine pretrage XPC service-a koristi se cache.

Radnje programa `xpcproxy` moguće je pratiti pomoću:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Biblioteka XPC koristi `kdebug` za beleženje radnji pozivanjem `xpc_ktrace_pid0` i `xpc_ktrace_pid1`. Kodovi koje koristi nisu dokumentovani, pa ih je potrebno dodati u `/usr/share/misc/trace.codes`. Imaju prefiks `0x29`, a jedan primer je `0x29000004`: `XPC_serializer_pack`.\
Usitni program `xpcproxy` koristi prefiks `0x22`, na primer: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Aplikacije mogu da se **pretplate** na različite **poruke događaja**, čime se omogućava da budu **pokrenute na zahtev** kada se takvi događaji dese. **Podešavanje** ovih servisa vrši se u l**aunchd plist datotekama**, koje se nalaze u **istim direktorijumima kao prethodne** i sadrže dodatni ključ **`LaunchEvent`**.

### Provera procesa koji se povezuje na XPC

Kada proces pokuša da pozove metod putem XPC veze, **XPC servis treba da proveri da li je tom procesu dozvoljeno povezivanje**. Ovo su uobičajeni načini za tu proveru i uobičajene greške:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC autorizacija

Apple takođe omogućava aplikacijama da **konfigurišu određena prava i način njihovog dobijanja**, tako da proces koji poziva servis može da **pozove metod** iz XPC servisa ako poseduje ta prava:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Za presretanje XPC poruka možete koristiti [**xpcspy**](https://github.com/hot3eed/xpcspy), koji koristi **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Još jedan mogući alat koji možete koristiti je [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Primer C koda za XPC komunikaciju

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
## Klijent unutar Dylb koda
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

Ova funkcionalnost koju pruža `RemoteXPC.framework` (iz `libxpc`) omogućava komunikaciju putem XPC-a između različitih hostova.\
Servisi koji podržavaju remote XPC u svom plist-u imaju ključ UsesRemoteXPC, kao što je slučaj sa `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Međutim, iako će servis biti registrovan kod `launchd`, funkcionalnost obezbeđuje `UserEventAgent` sa plugin-ovima `com.apple.remoted.plugin` i `com.apple.remoteservicediscovery.events.plugin`.

Pored toga, `RemoteServiceDiscovery.framework` omogućava dobijanje informacija od `com.apple.remoted.plugin`, izlažući funkcije kao što su `get_device`, `get_unique_device`, `connect`...

Kada se upotrebi `connect` i dobije socket `fd` servisa, moguće je koristiti klasu `remote_xpc_connection_*`.

Informacije o remote servisima moguće je dobiti korišćenjem CLI alata `/usr/libexec/remotectl` uz parametre kao što su:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Komunikacija između BridgeOS-a i hosta odvija se putem namenski posvećenog IPv6 interfejsa. `MultiverseSupport.framework` omogućava uspostavljanje sockets čiji će se `fd` koristiti za komunikaciju.\
Ove komunikacije moguće je pronaći pomoću `netstat`, `nettop` ili opcije otvorenog koda, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
