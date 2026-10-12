# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

XPC, macOS ve iOS'ta **process'ler arası iletişim** için kullanılan bir framework'tür. **Process'ler arasında güvenli, asenkron çağrılar** yapma mekanizmaları sağlar. XPC, her **bileşenin** **yalnızca ihtiyaç duyduğu izinlerle** çalıştığı **ayrıcalıkları birbirinden ayrılmış uygulamaları** destekler; böylece ele geçirilmiş bir process'in yol açabileceği olası zarar sınırlandırılır.<sup>[[1]](#references)</sup>

XPC, aynı sistemde çalışan farklı programların veri gönderip almasını sağlayan yöntemlerden oluşan bir küme olan Inter-Process Communication (IPC) biçimini kullanır.

XPC'nin başlıca faydaları şunlardır:

1. **Güvenlik**: İşleri farklı process'lere ayırarak her process'e yalnızca ihtiyaç duyduğu izinler verilebilir. Böylece bir process ele geçirilse bile zarar verme kabiliyeti sınırlı olur.
2. **Kararlılık**: XPC, çökmeleri meydana geldikleri bileşene yalıtmaya yardımcı olur. Bir process çökerse sistemin geri kalanını etkilemeden yeniden başlatılabilir.
3. **Performans**: Farklı görevlerin ayrı process'lerde eşzamanlı çalıştırılabilmesi sayesinde XPC, concurrency kullanımını kolaylaştırır.

Başlıca **dezavantajı**, **bir uygulamayı birden çok process'e ayırmanın** ve bunların XPC aracılığıyla iletişim kurmasını sağlamanın ek yük oluşturmasıdır. Modern sistemlerde bu yük, güvenlik ve kararlılık faydalarıyla karşılaştırıldığında genellikle küçüktür.<sup>[[1]](#references)</sup>

## Uygulamaya Özel XPC Servisleri

Bir uygulamanın XPC bileşenleri **uygulamanın kendisinin içindedir**. Örneğin Safari'de bunları **`/Applications/Safari.app/Contents/XPCServices`** içinde bulabilirsiniz. **`.xpc`** uzantısına sahiptirler (**`com.apple.Safari.SandboxBroker.xpc`** gibi) ve ana binary ile bir `Info.plist` dosyasını içeren **bundle'lardır**. Örneğin: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` ve `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Bir **XPC bileşeni, diğer XPC bileşenlerinden veya ana uygulama binary'sinden farklı entitlement'lara ve ayrıcalıklara sahip olabilir**. Bunun bir istisnası, **Info.plist** dosyasında **`JoinExistingSession`** değeri `true` olarak yapılandırılmış bir XPC servisidir. Bu durumda XPC servisi, onu çağıran **uygulamayla aynı güvenlik oturumuna** katılır.<sup>[[4]](#references)</sup>

XPC servisleri gerektiğinde **launchd** tarafından **başlatılır** ve sistem kaynaklarını boşaltmak için görevleri **tamamlandığında** kapatılabilir. **Uygulamaya özel XPC bileşenleri yalnızca onları içeren uygulama tarafından kullanılabilir**; böylece olası güvenlik açıklarının maruz kalma alanı daraltılır.<sup>[[2]](#references)</sup>

## Sistem Genelindeki XPC Servisleri

Uygulamaya özel servislerin aksine, sistem genelindeki XPC servisleri onları içeren uygulamayla sınırlı değildir. launchd domain'ine ve servisin kendi yetkilendirme kontrollerine bağlı olarak, birden fazla kullanıcının istemcileri tarafından erişilebilir olabilirler. launchd tarafından yönetilen bu Mach servislerinin **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** veya **`/Library/LaunchAgents`** gibi dizinlerde bulunan plist dosyalarında **tanımlanması** gerekir.<sup>[[2]](#references)[[3]](#references)</sup>

Bu plist dosyalarında servis adını içeren bir **`MachServices`** anahtarı ve binary'nin yolunu içeren bir **`Program`** anahtarı bulunur:

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

**`LaunchDaemons`** içindeki servisler genellikle root olarak çalışır. Bu nedenle, ayrıcalıksız bir süreç bu servislerden birinin sunduğu savunmasız bir yönteme erişebiliyorsa, ayrıcalıklarını yükseltebilir.

## XPC Nesneleri

- **`xpc_object_t`**

XPC istek ve yanıt payload'ları genellikle serileştirme ve serileştirmeyi geri alma işlemlerini kolaylaştıran sözlük nesneleridir. `libxpc.dylib`, alınan verinin beklenen türde olduğunu doğrulamak için gereken veri türlerini de tanımlar. C API'de her nesne bir `xpc_object_t`'dir (ve türü `xpc_get_type(object)` kullanılarak kontrol edilebilir).<sup>[[2]](#references)</sup>\
Ayrıca, nesnenin hata ayıklama amacıyla kullanışlı olabilecek bir dize gösterimini almak için `xpc_copy_description(object)` işlevi kullanılabilir.\
Bu nesnelerin çağrılabilecek bazı yöntemleri de vardır: `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` nesneleri, nesnenin sınıfını (`XPC_TYPE_*` değerlerinden biri) ve boyutunu belirten `_xpc_base_create(Class, Size)` işlevini dahili olarak çağıran bir `xpc_<objectType>_create` işlevi çağrılarak oluşturulur. Metadata için fazladan 40 bayt eklenir; bu nedenle nesne verisi 40. bayt ofsetinde başlar.\
Bu nedenle `xpc_<objectType>_t`, `os_object_t*` alt sınıfı olan `xpc_object_t`'nin bir tür alt sınıfıdır.

> [!WARNING]
> Anahtarın türünü ve gerçek değerini almak veya ayarlamak için `xpc_dictionary_[get/set]_<objectType>` işlevlerini kullanması gerekenin geliştirici olduğuna dikkat edin.

- **`xpc_pipe`**

Bir **`xpc_pipe`**, süreçlerin iletişim kurmak için kullanabileceği bir FIFO pipe'tır (iletişimde Mach mesajları kullanılır).\
`xpc_pipe_create()` veya belirli bir Mach portu kullanarak oluşturmak için `xpc_pipe_create_from_port()` çağrısıyla bir XPC server oluşturmak mümkündür. Ardından mesaj almak için `xpc_pipe_receive` ve `xpc_pipe_try_receive` çağrılabilir.

**`xpc_pipe`** nesnesinin, kullandığı iki Mach portu ve varsa adını içeren yapısıyla bir **`xpc_object_t`** olduğuna dikkat edin. Örneğin, `secinitd` daemon'u `/System/Library/LaunchDaemons/com.apple.secinitd.plist` plist dosyasında `com.apple.secinitd` adlı pipe'ı yapılandırır.

Bir **`xpc_pipe`** örneği, **`launchd`** tarafından oluşturulan ve Mach portlarının paylaşılmasını mümkün kılan **bootstrap pipe**'tır.

- **`NSXPC*`**

Bunlar XPC bağlantılarını soyutlayan üst düzey Objective-C nesneleridir.\
Ayrıca, bu nesnelerde hata ayıklamak DTrace ile öncekilere kıyasla daha kolaydır.

- **`GCD Queues`**

XPC, mesajları iletmek için GCD kullanır; ayrıca `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` gibi belirli dispatch queue'lar oluşturur...

## XPC Servisleri

Bunlar, diğer projelerin **`XPCServices`** klasöründe bulunan **`.xpc`** uzantılı bundle'lardır ve `Info.plist` dosyalarında `CFBundlePackageType` değeri **`XPC!`** olarak ayarlanmıştır.\
Bu dosyada `ServiceType` (Application, User veya System olabilir), bir sandbox tanımlayabilen `_SandboxProfile` ve servisle iletişim kurmak için gereken entitlement'ları veya kimliği belirtebilen `_AllowedClients` gibi başka yapılandırma anahtarları da bulunur. Bu ve diğer seçenekler, servis başlatıldığında onu yapılandırır.<sup>[[2]](#references)</sup>

### Servis Başlatma

Uygulama, `xpc_connection_create_mach_service` kullanarak bir XPC servisine **bağlanmaya** çalışır; ardından launchd daemon'u bulur ve **`xpcproxy`**'yi başlatır. **`xpcproxy`**, yapılandırılmış kısıtlamaları uygular ve sağlanan dosya tanıtıcıları ile Mach portlarını kullanarak servisi başlatır.<sup>[[3]](#references)</sup>

XPC servisini aramayı hızlandırmak için bir cache kullanılır.

`xpcproxy` işlemlerini şu komutla izlemek mümkündür:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

XPC library, `xpc_ktrace_pid0` ve `xpc_ktrace_pid1` çağrılarıyla eylemleri günlüğe kaydetmek için `kdebug` kullanır. Kullandığı kodlar belgelenmemiştir; bu nedenle `/usr/share/misc/trace.codes` dosyasına eklenmeleri gerekir. `0x29` önekini kullanırlar; örneğin, `0x29000004`, `XPC_serializer_pack` kodudur.\
`xpcproxy` yardımcı programı `0x22` önekini kullanır; örneğin: `0x2200001c: xpcproxy:will_do_preexec`.

## Application Türündeki XPC Yardımcılarını Denetleme

`XPCService.ServiceType` değerinin `Application` olması, framework tarafından sağlanan yardımcıları denetlemek için iyi bir başlangıç noktasıdır: bundle'ları listeleyin, çalışan servisleri tespit edin ve yardımcının identifier'ını ve entitlements'ını inceleyin. Hem `/System/Library/Frameworks` hem de `/System/Library/PrivateFrameworks` içinde arama yapın; tam envanter macOS sürümleri arasında değişir.<sup>[[7]](#references)</sup>

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

### Listener'ı inceleyin ve minimal bir protokolü çıkarın

Helper içindeki `-[<delegate> listener:shouldAcceptNewConnection:]` metodunu bulun. `exportedInterface` ve `exportedObject` değerlerini ayarlayan, bağlantıyı devam ettiren ve eşin audit token'ını, code requirement'ını veya entitlement'ını kontrol etmeden `YES`/`1` döndüren bir yol, RPC arayüzünü servisi bulabilen tüm istemcilere açar. Bu yalnızca **erişilebilirliği** kanıtlar: Etki için hâlâ yeterli istemci/yöntem başına yetkilendirme olmadan ayrıcalıklı işlem gerçekleştiren veya saldırgan denetimindeki girdileri güvenli olmayan biçimde işleyen bir dışa aktarılmış yöntem gerekir.<sup>[[7]](#references)</sup>

Test için yalnızca gerekli selector'ları çıkarın. Objective-C selector metadata'sı argüman sayısını gösterir; decompiler'daki argüman kullanımları genellikle türleri belirginleştirir (örneğin, `-[EKEvent setStartDate:]` ve `setEndDate:` metotlarına aktarılan değerler `NSDate *` türündedir); metodun sonundaki dolaylı çağrı ise reply block parametrelerini gösterir. `NSXPCInterface` için kısmi bir yerel protokol yeterlidir; tüm private protokolü yeniden oluşturmak gerekmez.<sup>[[7]](#references)</sup>

### Yeniden oluşturulan arayüzle bağlanın

Bir uygulamanın XPC servisi için gerekli private sınıfları tanımlayan herhangi bir framework'ü yükleyin, `initWithServiceName:` ile bağlantıyı oluşturun, yeniden oluşturulan uzak arayüzü atayın, hata/kesinti/geçersizleştirme handler'larını kurun ve ancak bundan sonra bağlantıyı devam ettirin. Asenkron yanıtlar için run loop'u çalışır durumda tutun. Bir sandbox sınırını test ederken istemciyi sandbox'lı bir uygulama içinde yeniden çalıştırın; bağımsız bir istemcinin başarılı olması sandbox kaçışına kanıt değildir.<sup>[[7]](#references)</sup>

<details>
<summary>Minimal Objective-C istemcisi</summary>

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

`clang -fblocks -framework Foundation -o xpc_client xpc_client.m` ile derleyin.<sup>[[7]](#references)</sup>

</details>

### Secure-coding hatalarını type oracle olarak kullanın

`NSCocoaErrorDomain` hatası (ör. kod `4101`), yararlı serileştirme exception'ını gizliyor olabilir. Servis adını macOS unified log/Console'da arayın: exception, beklenmeyen sınıfı ve o selector argümanı için izin verilen sınıfları belirtir. Yanıt için **client-side** arayüz allowlist'ini `setClasses:forSelector:argumentIndex:ofReply:` ile genişletin; `ofReply:YES` kullanıldığında `index 0`, ilk metot parametresini değil, yanıt bloğunun ilk parametresini belirtir.<sup>[[7]](#references)</sup>

Arayüzü bağlantıya atamadan ve `[c resume]` çağırmadan önce yapılandırın:<sup>[[7]](#references)</sup>

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

Tersi de işe yarar: Sunucu bir Foundation girdisini reddedip izin verilen tek bir private class'ı günlüğe kaydederse, günlük beklenen wire türünü ve ait olduğu framework'ü ortaya çıkarır. Bu framework'ü yükleyin, generic `id` türlerini netleştirmek için class'ın yöntemlerini/özelliklerini inceleyin ve private object'i dinamik olarak oluşturun. `NSInvocation` argümanları `2` indeksinden başlar; çünkü `0` ve `1` indeksleri gizli `self` ve `_cmd` argümanlarıdır.<sup>[[7]](#references)</sup>

<details>
<summary>NSInvocation ile bir private argüman oluşturma</summary>

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

launchd tarafından kaydedilmiş, sistem genelindeki Mach hizmetlerine yönelik ilgili iş akışı için bkz.:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## XPC Olay Mesajları

Uygulamalar farklı olay **mesajlarına** **abone olabilir**; böylece bu olaylar gerçekleştiğinde **istek üzerine başlatılabilirler**. Bu hizmetlerin **kurulumu**, **öncekilerle aynı dizinlerde** bulunan ve ek bir **`LaunchEvent`** anahtarı içeren l**aunchd plist dosyalarında** yapılır.

### XPC Bağlanan Süreç Denetimi

Bir süreç, XPC bağlantısı üzerinden bir yöntemi çağırmaya çalıştığında **XPC hizmeti, bu sürecin bağlanmasına izin verilip verilmediğini denetlemelidir**. Yaygın doğrulama yöntemleri ve bunların tuzakları şunlardır:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Yetkilendirme

Apple ayrıca uygulamaların **yetkilendirme haklarını ve çağıranların bu hakları nasıl edineceğini yapılandırmasına** izin verir; böylece gerekli haklara sahip bir süreç **XPC hizmetinin sunduğu bir yöntemi çağırabilir**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC mesajlarını dinlemek için **Frida** kullanan **xpcspy** aracını kullanabilirsiniz.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Başka bir olası araç **XPoCe2**'dir.<sup>[[6]](#references)</sup>

## XPC İletişimi C Kod Örneği

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

## XPC İletişimi Objective-C Kod Örneği

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

## Dylib İçindeki İstemci

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

`RemoteXPC.framework`'in (`libxpc` içinden) sağladığı işlevsellik, farklı host'lar arasında XPC iletişimine olanak tanır.\
Remote XPC'yi destekleyen servislerin plist dosyalarında `UsesRemoteXPC` anahtarı bulunur; `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` bunun bir örneğidir. Servis `launchd` ile kaydedilmiş olsa da bu işlevselliği `UserEventAgent` ile onun `com.apple.remoted.plugin` ve `com.apple.remoteservicediscovery.events.plugin` eklentileri sağlar.

Ayrıca `RemoteServiceDiscovery.framework`, `com.apple.remoted.plugin`'dan bilgi alarak `get_device`, `get_unique_device` ve `connect` gibi işlevleri kullanıma sunar.

`connect` servisinin socket dosya tanımlayıcısını döndürdükten sonra `remote_xpc_connection_*` sınıfını kullanmak mümkündür.

`/usr/libexec/remotectl` CLI'sini aşağıdaki gibi komutlarla kullanarak remote servisler hakkında bilgi edinmek mümkündür:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

bridgeOS ile host arasındaki iletişim, özel bir IPv6 arayüzü üzerinden gerçekleşir. `MultiverseSupport.framework`, dosya tanımlayıcıları iletişim için kullanılan soketler oluşturur.\
Bu iletişimleri `netstat`, `nettop` veya açık kaynaklı alternatif `netbottom` ile bulmak mümkündür.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPC Hizmetleri Oluşturma](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - macOS XPC Yardımcılarına Saldırı: Protokol Tersine Mühendisliği](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
