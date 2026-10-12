# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Osnovne informacije

XPC je framework za **komunikaciju između procesa** u macOS-u i iOS-u. Pruža mehanizme za **bezbedno, asinhrono pozivanje između procesa**. XPC podržava **aplikacije sa razdvojenim privilegijama**, u kojima svaka **komponenta** radi sa **samo onim dozvolama koje su joj potrebne**, čime se ograničava potencijalna šteta od kompromitovanog procesa.<sup>[[1]](#references)</sup>

XPC koristi oblik komunikacije između procesa (IPC), odnosno skup metoda kojima različiti programi pokrenuti na istom sistemu mogu međusobno da razmenjuju podatke.

Glavne prednosti XPC-a su:

1. **Bezbednost**: Razdvajanjem posla na različite procese, svakom procesu mogu se dodeliti samo dozvole koje su mu potrebne. To znači da čak i ako je proces kompromitovan, njegove mogućnosti da nanese štetu su ograničene.
2. **Stabilnost**: XPC pomaže da se padovi ograniče na komponentu u kojoj se dogode. Ako se proces sruši, može se ponovo pokrenuti bez uticaja na ostatak sistema.
3. **Performanse**: XPC omogućava jednostavan konkurentni rad, jer se različiti zadaci mogu istovremeno izvršavati u različitim procesima.

Glavni **nedostatak** je to što **razdvajanje aplikacije na više procesa** i njihova komunikacija putem XPC-a donose dodatno opterećenje. Na modernim sistemima to opterećenje je obično malo u poređenju sa prednostima po bezbednost i stabilnost.<sup>[[1]](#references)</sup>

## XPC servisi specifični za aplikaciju

XPC komponente aplikacije nalaze se **u samoj aplikaciji**. Na primer, u Safariju možete ih pronaći u **`/Applications/Safari.app/Contents/XPCServices`**. Imaju ekstenziju **`.xpc`** (kao što je **`com.apple.Safari.SandboxBroker.xpc`**) i takođe su **bundle-ovi**, koji u sebi sadrže glavnu binarnu datoteku i `Info.plist`. Na primer: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` i `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**XPC komponenta može imati drugačija entitlements i privilegije** od drugih XPC komponenti ili glavne binarne datoteke aplikacije. Izuzetak je XPC servis za koji je u njegovoj datoteci **Info.plist** opcija **`JoinExistingSession`** postavljena na `true`. U tom slučaju, XPC servis se pridružuje **istoj bezbednosnoj sesiji kao aplikacija** koja ga je pozvala.<sup>[[4]](#references)</sup>

XPC servise **pokreće** **launchd** kada su potrebni, a mogu biti i **ugašeni** po **završetku** zadataka radi oslobađanja sistemskih resursa. **XPC komponente specifične za aplikaciju može koristiti samo aplikacija koja ih sadrži**, čime se smanjuje izloženost potencijalnim ranjivostima.<sup>[[2]](#references)</sup>

## Sistemski XPC servisi

Za razliku od servisa specifičnih za aplikaciju, sistemski XPC servisi nisu ograničeni na aplikaciju koja ih sadrži. U zavisnosti od launchd domena i sopstvenih provera autorizacije servisa, mogu im pristupati klijenti sa više korisničkih naloga. Ovi Mach servisi kojima upravlja launchd moraju biti **definisani u** plist datotekama smeštenim u direktorijumima kao što su **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ili **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Ove plist datoteke imaju ključ **`MachServices`**, koji sadrži naziv servisa, i ključ **`Program`**, koji sadrži putanju do binarne datoteke:

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

Servisi u **`LaunchDaemons`** često se izvršavaju kao root. Zato, ako neprivilegovani proces može da pristupi ranjivoj metodi koju izlaže neki od ovih servisa, možda će moći da eskalira privilegije.

## XPC Objects

- **`xpc_object_t`**

XPC payload-i zahteva i odgovora obično su dictionary objekti, što pojednostavljuje serijalizaciju i deserijalizaciju. `libxpc.dylib` takođe definiše tipove podataka potrebne za proveru da li primljeni podaci imaju očekivani tip. U C API-ju, svaki objekat je `xpc_object_t` (a njegov tip može da se proveri pomoću `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Pored toga, funkcija `xpc_copy_description(object)` može da se koristi za dobijanje tekstualnog prikaza objekta koji može biti koristan za otklanjanje grešaka.\
Ovi objekti imaju i metode koje mogu da se pozivaju, kao što su `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Objekti `xpc_object_t` kreiraju se pozivanjem funkcije `xpc_<objectType>_create`, koja interno poziva `_xpc_base_create(Class, Size)`, navodeći klasu objekta (jednu od `XPC_TYPE_*`) i njegovu veličinu. Za metapodatke se dodaje još 40 bajtova, tako da podaci objekta počinju na pomeraju od 40 bajtova.\
Dakle, `xpc_<objectType>_t` je neka vrsta podklase `xpc_object_t`, koja bi bila podklasa `os_object_t*`.

> [!WARNING]
> Imajte na umu da bi programer trebalo da koristi `xpc_dictionary_[get/set]_<objectType>` za dobijanje ili postavljanje tipa i stvarne vrednosti ključa.

- **`xpc_pipe`**

**`xpc_pipe`** je FIFO cev koju procesi mogu da koriste za komunikaciju (komunikacija se odvija pomoću Mach poruka).\
XPC server može da se kreira pozivanjem `xpc_pipe_create()` ili `xpc_pipe_create_from_port()` da bi se kreirao pomoću određenog Mach porta. Zatim, za prijem poruka, mogu da se pozovu `xpc_pipe_receive` i `xpc_pipe_try_receive`.

Imajte na umu da je objekat **`xpc_pipe`** objekat **`xpc_object_t`** čija struktura sadrži informacije o dva korišćena Mach porta i nazivu, ako postoji. Na primer, daemon `secinitd` u svom plist-u `/System/Library/LaunchDaemons/com.apple.secinitd.plist` konfiguriše cev pod nazivom `com.apple.secinitd`.

Primer **`xpc_pipe`** objekta je **bootstrap pipe** koji kreira **`launchd`** i koji omogućava deljenje Mach portova.

- **`NSXPC*`**

Ovo su visok nivo Objective-C objekti koji apstrahuju XPC konekcije.\
Pored toga, ove objekte je lakše otklanjati pomoću DTrace-a nego prethodne.

- **`GCD Queues`**

XPC koristi GCD za prosleđivanje poruka, a generiše i određene dispatch redove kao što su `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

To su **bundle-ovi sa ekstenzijom `.xpc`** koji se nalaze u fascikli **`XPCServices`** drugih projekata, a u svom `Info.plist` fajlu imaju `CFBundlePackageType` postavljen na **`XPC!`**.\
Ova datoteka sadrži i druge konfiguracione ključeve, kao što je `ServiceType`, čija vrednost može biti Application, User ili System; `_SandboxProfile`, kojim se može definisati sandbox; i `_AllowedClients`, koji može da označava entitlements ili identitet potrebne za povezivanje sa servisom. Ove i druge opcije konfigurišu servis prilikom pokretanja.<sup>[[2]](#references)</sup>

### Starting a Service

Aplikacija pokušava da se **poveže** sa XPC servisom pomoću `xpc_connection_create_mach_service`; zatim launchd pronalazi daemon i pokreće **`xpcproxy`**. **`xpcproxy`** sprovodi konfigurisana ograničenja i pokreće servis sa prosleđenim deskriptorima fajlova i Mach portovima.<sup>[[3]](#references)</sup>

Za brže pronalaženje XPC servisa koristi se keš.

Moguće je pratiti radnje procesa `xpcproxy` pomoću:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

XPC biblioteka koristi `kdebug` za beleženje radnji pozivanjem funkcija `xpc_ktrace_pid0` i `xpc_ktrace_pid1`. Kodovi koje koristi nisu dokumentovani, pa ih treba dodati u `/usr/share/misc/trace.codes`. Imaju prefiks `0x29`; na primer, `0x29000004` je `XPC_serializer_pack`.\
Alatka `xpcproxy` koristi prefiks `0x22`, na primer: `0x2200001c: xpcproxy:will_do_preexec`.

## Provera XPC pomoćnih aplikacija tipa Application

Vrednost `Application` za `XPCService.ServiceType` korisna je kao polazna tačka pri proveri pomoćnih aplikacija koje pruža framework: popišite pakete, zadržite pokrenute servise i pregledajte identifikator i entitlements pomoćne aplikacije. Pretražite i `/System/Library/Frameworks` i `/System/Library/PrivateFrameworks`; tačan spisak se menja između izdanja macOS-a.<sup>[[7]](#references)</sup>

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

### Analizirajte listener i utvrdite minimalni protokol

Pronađite `-[<delegate> listener:shouldAcceptNewConnection:]` u helper-u. Ako putanja postavlja `exportedInterface` i `exportedObject`, nastavlja vezu i vraća `YES`/`1` bez provere audit token-a, code requirement-a ili entitlement-a peer-a, RPC interfejs je dostupan svakom klijentu koji može da pronađe servis. Ovo dokazuje samo **dostupnost**: za utvrđivanje uticaja i dalje je neophodan eksportovani metod koji obavlja privilegovanu operaciju bez odgovarajuće autorizacije po klijentu ili metodu, ili koji nebezbedno obrađuje ulazne podatke pod kontrolom napadača.<sup>[[7]](#references)</sup>

Utvrdite samo selektore potrebne za testiranje. Metapodaci Objective-C selektora otkrivaju broj argumenata; mesta na kojima se argumenti koriste u dekompajleru obično pomažu da se preciznije odrede njihovi tipovi (na primer, vrednosti prosleđene metodama `-[EKEvent setStartDate:]` i `setEndDate:` su `NSDate *`), dok indirektni poziv na kraju metoda otkriva parametre reply bloka. Delimična lokalna definicija protokola dovoljna je za `NSXPCInterface`; nije potrebno rekonstruisati ceo privatni protokol.<sup>[[7]](#references)</sup>

### Povežite se pomoću rekonstruisanog interfejsa

Za XPC servis aplikacije učitajte svaki framework koji definiše potrebne privatne klase, kreirajte vezu pomoću `initWithServiceName:`, dodelite joj rekonstruisani udaljeni interfejs, postavite obrađivače grešaka, prekida i poništavanja, pa tek onda nastavite vezu. Ostavite run loop aktivan da biste primali asinhrone odgovore. Prilikom testiranja granice sandbox-a, ponovo pokrenite klijent unutar sandbox-ovane aplikacije — uspešno pokretanje samostalnog klijenta nije dokaz izlaska iz sandbox-a.<sup>[[7]](#references)</sup>

<details>
<summary>Minimalni Objective-C klijent</summary>

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

Compile with `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Koristite greške secure-coding-a kao type oracle

Greška `NSCocoaErrorDomain`, poput koda `4101`, može da sakrije korisni izuzetak pri serijalizaciji. Potražite naziv servisa u macOS unified log/Console: izuzetak navodi i neočekivanu klasu i klase dozvoljene za argument tog selektora. Za odgovor, proširite **client-side** allowlist interfejsa pomoću `setClasses:forSelector:argumentIndex:ofReply:`; kada je `ofReply:YES`, indeks `0` označava prvi parametar reply bloka, a ne prvi parametar metode.<sup>[[7]](#references)</sup>

Podesite interfejs pre nego što ga dodelite konekciji i pozovete `[c resume]`:<sup>[[7]](#references)</sup>

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

Obrnuti slučaj je takođe koristan: ako server odbije Foundation ulaz i zabeleži jednu dozvoljenu privatnu klasu, zapis otkriva očekivani tip na wire-u i njegov framework. Učitajte taj framework, pregledajte metode/svojstva klase da biste precizirali generičke tipove `id` i dinamički kreirajte privatni objekat. Argumenti `NSInvocation` počinju od indeksa `2`, jer su indeksi `0` i `1` skriveni argumenti `self` i `_cmd`.<sup>[[7]](#references)</sup>

<details>
<summary>Kreiranje privatnog argumenta pomoću NSInvocation</summary>

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

Za povezani workflow koji se odnosi na Mach servise registrovane u launchd i dostupne celom sistemu, pogledajte:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## XPC Event Messages

Aplikacije mogu da se **pretplate** na različite **poruke** događaja, čime se omogućava da budu **pokrenute na zahtev** kada do takvih događaja dođe. **Podešavanje** ovih servisa vrši se u l**aunchd plist datotekama**, koje se nalaze u **istim direktorijumima kao prethodne** i sadrže dodatni ključ **`LaunchEvent`**.

### Provera procesa koji se povezuje putem XPC-a

Kada proces pokuša da pozove metodu putem XPC veze, **XPC servis treba da proveri da li je tom procesu dozvoljeno povezivanje**. U nastavku su navedeni uobičajeni načini provere i njihove zamke:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple takođe omogućava aplikacijama da **konfigurišu prava za autorizaciju i način na koji ih pozivaoci dobijaju**, tako da proces sa potrebnim pravima **može da pozove metodu** koju izlaže XPC servis:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Za sniffovanje XPC poruka možete da koristite **xpcspy**, koji koristi **Frida**.<sup>[[5]](#references)</sup>

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
Servisi koji podržavaju remote XPC imaju ključ `UsesRemoteXPC` u svom plist-u, kao što je slučaj sa `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Iako je servis registrovan u `launchd`, funkcionalnost pružaju `UserEventAgent` i njegovi dodaci `com.apple.remoted.plugin` i `com.apple.remoteservicediscovery.events.plugin`.

Pored toga, `RemoteServiceDiscovery.framework` preuzima informacije iz `com.apple.remoted.plugin` i izlaže funkcije kao što su `get_device`, `get_unique_device` i `connect`.

Kada `connect` vrati deskriptor socket fajla servisa, moguće je koristiti klasu `remote_xpc_connection_*`.

Informacije o udaljenim servisima moguće je dobiti pomoću CLI alata `/usr/libexec/remotectl` i komandi kao što su:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

Komunikacija između bridgeOS-a i hosta odvija se preko namenskog IPv6 interfejsa. `MultiverseSupport.framework` uspostavlja sokete čiji se deskriptori datoteka koriste za komunikaciju.\
Ovu komunikaciju je moguće pronaći pomoću alata `netstat`, `nettop` ili otvorene alternative `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Kreiranje XPC servisa](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - Napadi na macOS XPC pomoćne procese: reverzno inženjerstvo protokola](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
