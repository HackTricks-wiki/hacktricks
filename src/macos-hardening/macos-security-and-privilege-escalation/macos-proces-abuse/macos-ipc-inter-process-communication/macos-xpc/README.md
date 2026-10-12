# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

XPC to framework służący do **komunikacji między procesami** w macOS i iOS. Zapewnia mechanizmy umożliwiające **bezpieczne, asynchroniczne wywołania między procesami**. XPC obsługuje **aplikacje z separacją uprawnień**, w których każdy **komponent** działa z **uprawnieniami ograniczonymi do niezbędnego minimum**, co ogranicza potencjalne szkody spowodowane przez przejęty proces.<sup>[[1]](#references)</sup>

XPC korzysta z formy komunikacji międzyprocesowej (IPC), czyli zestawu metod umożliwiających różnym programom działającym w tym samym systemie wymianę danych.

Główne zalety XPC to:

1. **Bezpieczeństwo**: Podział pracy na różne procesy pozwala przyznać każdemu procesowi tylko niezbędne uprawnienia. Oznacza to, że nawet jeśli proces zostanie przejęty, jego możliwości wyrządzenia szkód są ograniczone.
2. **Stabilność**: XPC pomaga ograniczyć awarie do komponentu, w którym wystąpiły. Jeśli proces ulegnie awarii, można go uruchomić ponownie bez wpływu na resztę systemu.
3. **Wydajność**: XPC ułatwia współbieżność, ponieważ różne zadania mogą być wykonywane jednocześnie w odrębnych procesach.

Główną **wadą** jest to, że **podział aplikacji na kilka procesów** i zapewnienie im komunikacji przez XPC wiąże się z dodatkowym narzutem. W nowoczesnych systemach jest on zwykle niewielki w porównaniu z korzyściami w zakresie bezpieczeństwa i stabilności.<sup>[[1]](#references)</sup>

## Usługi XPC specyficzne dla aplikacji

Komponenty XPC aplikacji znajdują się **wewnątrz samej aplikacji**. Na przykład w Safari można je znaleźć w **`/Applications/Safari.app/Contents/XPCServices`**. Mają rozszerzenie **`.xpc`** (na przykład **`com.apple.Safari.SandboxBroker.xpc`**) i **również są pakietami**, zawierającymi główny plik binarny oraz plik `Info.plist`. Na przykład: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` i `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

**Komponent XPC może mieć inne entitlements i uprawnienia** niż pozostałe komponenty XPC lub główny plik binarny aplikacji. Wyjątkiem jest usługa XPC skonfigurowana tak, by **`JoinExistingSession`** miało w jej pliku **Info.plist** wartość `true`. W takim przypadku usługa XPC dołącza do **tej samej sesji bezpieczeństwa co aplikacja**, która ją wywołała.<sup>[[4]](#references)</sup>

Usługi XPC są **uruchamiane** przez **launchd**, gdy są potrzebne, i mogą zostać **zatrzymane** po **zakończeniu** zadań, aby zwolnić zasoby systemowe. **Komponenty XPC specyficzne dla aplikacji mogą być używane tylko przez aplikację, która je zawiera**, co ogranicza ekspozycję na potencjalne luki.<sup>[[2]](#references)</sup>

## Usługi XPC dostępne w całym systemie

W przeciwieństwie do usług specyficznych dla aplikacji, usługi XPC dostępne w całym systemie nie są ograniczone do aplikacji, która je zawiera. Mogą być osiągalne dla klientów z wielu kont użytkowników, w zależności od domeny launchd i własnych mechanizmów autoryzacji usługi. Te zarządzane przez launchd usługi Mach muszą być **zdefiniowane w plikach plist** znajdujących się w katalogach takich jak **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** lub **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Te pliki plist zawierają klucz **`MachServices`** z nazwą usługi oraz klucz **`Program`** ze ścieżką do pliku binarnego:

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

Usługi w **`LaunchDaemons`** często działają jako root. Dlatego jeśli nieuprzywilejowany proces może uzyskać dostęp do podatnej metody udostępnianej przez jedną z tych usług, może być w stanie eskalować uprawnienia.

## XPC Objects

- **`xpc_object_t`**

Payloady żądań i odpowiedzi XPC to często obiekty słownikowe, które upraszczają serializację i deserializację. `libxpc.dylib` deklaruje również typy danych potrzebne do weryfikacji, czy odebrane dane mają oczekiwany typ. W C API każdy obiekt jest typu `xpc_object_t` (a jego typ można sprawdzić za pomocą `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Ponadto funkcji `xpc_copy_description(object)` można użyć do uzyskania tekstowej reprezentacji obiektu, która może być przydatna do debugowania.\
Obiekty te mają również metody, które można wywołać, takie jak `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Obiekty `xpc_object_t` tworzy się, wywołując funkcję `xpc_<objectType>_create`, która wewnętrznie wywołuje `_xpc_base_create(Class, Size)`, określając klasę obiektu (jedną z `XPC_TYPE_*`) i jego rozmiar. Na metadane dodawane jest dodatkowe 40 bajtów, dlatego dane obiektu zaczynają się z przesunięciem 40 bajtów.\
Dlatego `xpc_<objectType>_t` jest swego rodzaju podklasą `xpc_object_t`, która z kolei jest podklasą `os_object_t*`.

> [!WARNING]
> Należy pamiętać, że to deweloper powinien używać `xpc_dictionary_[get/set]_<objectType>`, aby pobierać lub ustawiać typ i rzeczywistą wartość klucza.

- **`xpc_pipe`**

**`xpc_pipe`** to potok FIFO, którego procesy mogą używać do komunikacji (komunikacja odbywa się za pomocą komunikatów Mach).\
Serwer XPC można utworzyć, wywołując `xpc_pipe_create()` lub `xpc_pipe_create_from_port()`, aby utworzyć go z użyciem określonego portu Mach. Następnie do odbierania komunikatów można wywołać `xpc_pipe_receive` i `xpc_pipe_try_receive`.

Należy pamiętać, że obiekt **`xpc_pipe`** jest obiektem **`xpc_object_t`** zawierającym w swojej strukturze informacje o używanych dwóch portach Mach oraz nazwę (jeśli istnieje). Na przykład demon `secinitd` konfiguruje w swoim pliku plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` potok o nazwie `com.apple.secinitd`.

Przykładem **`xpc_pipe`** jest **bootstrap pipe** utworzony przez **`launchd`**, który umożliwia udostępnianie portów Mach.

- **`NSXPC*`**

Są to wysokopoziomowe obiekty Objective-C, które abstrakcyjnie reprezentują połączenia XPC.\
Ponadto debugowanie tych obiektów za pomocą DTrace jest łatwiejsze niż w przypadku poprzednich.

- **`GCD Queues`**

XPC używa GCD do przekazywania komunikatów, a także tworzy określone kolejki dispatch, takie jak `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Są to **bundles z rozszerzeniem `.xpc`**, znajdujące się w folderze **`XPCServices`** innych projektów. W pliku `Info.plist` mają ustawioną wartość **`XPC!`** dla `CFBundlePackageType`.\
Plik ten zawiera inne klucze konfiguracyjne, takie jak `ServiceType`, który może przyjmować wartość Application, User lub System; `_SandboxProfile`, który może definiować sandbox; oraz `_AllowedClients`, który może określać wymagane uprawnienia lub tożsamość do nawiązania połączenia z usługą. Te i inne opcje konfigurują usługę podczas jej uruchamiania.<sup>[[2]](#references)</sup>

### Starting a Service

Aplikacja próbuje **nawiązać połączenie** z usługą XPC za pomocą `xpc_connection_create_mach_service`; następnie launchd lokalizuje demona i uruchamia **`xpcproxy`**. **`xpcproxy`** egzekwuje skonfigurowane ograniczenia i uruchamia usługę, przekazując jej podane deskryptory plików i porty Mach.<sup>[[3]](#references)</sup>

Aby przyspieszyć wyszukiwanie usługi XPC, używana jest pamięć podręczna.

Działania `xpcproxy` można śledzić za pomocą:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

Biblioteka XPC używa `kdebug` do rejestrowania działań, wywołując `xpc_ktrace_pid0` i `xpc_ktrace_pid1`. Używane przez nią kody nie są udokumentowane, dlatego należy dodać je do `/usr/share/misc/trace.codes`. Mają prefiks `0x29`; na przykład `0x29000004` oznacza `XPC_serializer_pack`.\
Narzędzie `xpcproxy` używa prefiksu `0x22`, na przykład: `0x2200001c: xpcproxy:will_do_preexec`.

## Audytowanie pomocników XPC typu Application

Warto zacząć audytowanie pomocników dostarczanych przez framework od usług, których `XPCService.ServiceType` ma wartość `Application`: wyliczyć pakiety, zachować działające usługi i sprawdzić identyfikator pomocnika oraz jego entitlements. Przeszukaj zarówno `/System/Library/Frameworks`, jak i `/System/Library/PrivateFrameworks`; dokładny wykaz zmienia się między wydaniami macOS.<sup>[[7]](#references)</sup>

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

### Przeanalizuj listener i odtwórz minimalny protokół

Znajdź w helperze `-[<delegate> listener:shouldAcceptNewConnection:]`. Jeśli ścieżka ustawia `exportedInterface` i `exportedObject`, wznawia połączenie i zwraca `YES`/`1`, nie sprawdzając tokenu audytu, wymagań dotyczących kodu ani entitlementów peera, udostępnia interfejs RPC każdemu klientowi, który może odnaleźć usługę. Dowodzi to jedynie **osiągalności**: aby wykazać wpływ, potrzebna jest jeszcze eksportowana metoda, która wykonuje uprzywilejowaną operację bez odpowiedniej autoryzacji per klient/per metodę albo niebezpiecznie przetwarza dane kontrolowane przez atakującego.<sup>[[7]](#references)</sup>

Odtwórz tylko selektory potrzebne do testów. Metadane selektorów Objective-C ujawniają liczbę argumentów; użycia argumentów w dekompilatorze zwykle pozwalają doprecyzować typy (na przykład wartości przekazywane do `-[EKEvent setStartDate:]` i `setEndDate:` mają typ `NSDate *`), a pośrednie wywołanie na końcu metody ujawnia parametry bloku reply. Częściowy lokalny protokół wystarczy dla `NSXPCInterface`; odtwarzanie całego prywatnego protokołu nie jest konieczne.<sup>[[7]](#references)</sup>

### Połącz się z odtworzonym interfejsem

W przypadku usługi XPC aplikacji załaduj dowolny framework definiujący wymagane klasy prywatne, utwórz połączenie za pomocą `initWithServiceName:`, przypisz odtworzony zdalny interfejs, zainstaluj handlery błędów, przerwania i unieważnienia, a dopiero potem wznów połączenie. Pozostaw aktywną pętlę zdarzeń, aby odbierać asynchroniczne odpowiedzi. Testując granicę sandboxa, uruchom klienta ponownie wewnątrz aplikacji działającej w sandboxie — powodzenie samodzielnego klienta nie świadczy o ucieczce z sandboxa.<sup>[[7]](#references)</sup>

<details>
<summary>Minimalny klient Objective-C</summary>

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

Compile z użyciem `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Wykorzystanie błędów secure-coding jako wyroczni typów

Błąd `NSCocoaErrorDomain`, taki jak kod `4101`, może ukrywać przydatny wyjątek serializacji. Wyszukaj nazwę usługi w ujednoliconym logu macOS lub w aplikacji Console: wyjątek wskazuje zarówno nieoczekiwaną klasę, jak i klasy dozwolone dla argumentu danego selektora. W przypadku odpowiedzi rozszerz allowlistę interfejsu **po stronie klienta** za pomocą `setClasses:forSelector:argumentIndex:ofReply:`; przy `ofReply:YES` indeks `0` oznacza pierwszy parametr bloku odpowiedzi, a nie pierwszy parametr metody.<sup>[[7]](#references)</sup>

Skonfiguruj interfejs przed przypisaniem go do połączenia i wywołaniem `[c resume]`:<sup>[[7]](#references)</sup>

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

Odwrotna sytuacja też jest przydatna: jeśli serwer odrzuca dane wejściowe Foundation i loguje nazwę jednej dozwolonej klasy prywatnej, log ujawnia oczekiwany typ przesyłany przez łącze oraz jego framework. Załaduj ten framework, sprawdź metody i właściwości klasy, aby doprecyzować typy ogólnego `id`, a następnie utwórz dynamicznie obiekt prywatny. Argumenty `NSInvocation` zaczynają się od indeksu `2`, ponieważ indeksy `0` i `1` odpowiadają ukrytym argumentom `self` i `_cmd`.<sup>[[7]](#references)</sup>

<details>
<summary>Skonstruuj prywatny argument za pomocą NSInvocation</summary>

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

Informacje o powiązanym przebiegu działania dotyczącym zarejestrowanych w launchd usług Mach dostępnych w całym systemie znajdziesz tutaj:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## Komunikaty zdarzeń XPC

Aplikacje mogą **subskrybować** różne **komunikaty** zdarzeń, dzięki czemu mogą być **uruchamiane na żądanie**, gdy takie zdarzenia wystąpią. **Konfiguracja** tych usług odbywa się w plikach **plist launchd**, znajdujących się w **tych samych katalogach co poprzednie** i zawierających dodatkowy klucz **`LaunchEvent`**.

### Weryfikacja procesu łączącego się przez XPC

Gdy proces próbuje wywołać metodę za pośrednictwem połączenia XPC, **usługa XPC powinna sprawdzić, czy dany proces może się z nią połączyć**. Oto typowe metody weryfikacji i ich pułapki:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autoryzacja XPC

Apple umożliwia również aplikacjom **konfigurowanie uprawnień autoryzacyjnych oraz sposobu ich uzyskiwania przez wywołujących**, dzięki czemu proces mający wymagane uprawnienia **może wywołać metodę** udostępnianą przez usługę XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Do sniffowania komunikatów XPC można użyć **xpcspy**, które korzysta z **Frida**.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Another possible tool is **XPoCe2**.<sup>[[6]](#references)</sup>

## Przykład kodu komunikacji XPC w C

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

## Przykład kodu komunikacji XPC w Objective-C

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

## Klient wewnątrz Dylib

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

Funkcjonalność udostępniana przez `RemoteXPC.framework` (z `libxpc`) umożliwia komunikację XPC między różnymi hostami.\
Usługi obsługujące Remote XPC mają w swoim pliku plist klucz `UsesRemoteXPC`, tak jak `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Chociaż usługa jest zarejestrowana w `launchd`, funkcjonalność tę zapewniają `UserEventAgent` oraz jego wtyczki `com.apple.remoted.plugin` i `com.apple.remoteservicediscovery.events.plugin`.

Ponadto `RemoteServiceDiscovery.framework` pobiera informacje z `com.apple.remoted.plugin`, udostępniając funkcje takie jak `get_device`, `get_unique_device` i `connect`.

Gdy `connect` zwróci deskryptor pliku gniazda usługi, można użyć klasy `remote_xpc_connection_*`.

Informacje o usługach zdalnych można uzyskać za pomocą CLI `/usr/libexec/remotectl`, używając poleceń takich jak:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

Komunikacja między bridgeOS a hostem odbywa się przez dedykowany interfejs IPv6. `MultiverseSupport.framework` tworzy gniazda, których deskryptory plików służą do komunikacji.\
Komunikację tę można wykryć za pomocą `netstat`, `nettop` lub open-source’owej alternatywy — `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Tworzenie usług XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society — Atakowanie pomocników XPC w macOS: inżynieria wsteczna protokołu](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
