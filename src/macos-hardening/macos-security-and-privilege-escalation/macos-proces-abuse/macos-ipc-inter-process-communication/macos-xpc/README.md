# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

XPC, macOS tarafından kullanılan XNU (çekirdek) arasındaki İletişim için bir çerçevedir ve **işlemler arasında iletişim** sağlar. XPC, sistemdeki farklı işlemler arasında **güvenli, asenkron yöntem çağrıları** yapma mekanizması sunar. Bu, her **bileşenin** işini yapmak için **sadece ihtiyaç duyduğu izinlerle** çalıştığı **ayrılmış ayrıcalıklarla uygulamaların** oluşturulmasına olanak tanıyan Apple'ın güvenlik paradigmasının bir parçasıdır ve böylece tehlikeye atılmış bir işlemin potansiyel zararını sınırlamaktadır.

XPC, aynı sistemde çalışan farklı programların veri göndermesi ve alması için bir dizi yöntem olan bir İletişim (IPC) biçimi kullanır.

XPC'nin temel faydaları şunlardır:

1. **Güvenlik**: Çalışmayı farklı işlemlere ayırarak, her işleme yalnızca ihtiyaç duyduğu izinler verilebilir. Bu, bir işlem tehlikeye atılsa bile, zarar verme yeteneğinin sınırlı olduğu anlamına gelir.
2. **Kararlılık**: XPC, çökme durumlarını meydana geldiği bileşene izole etmeye yardımcı olur. Bir işlem çökerse, sistemin geri kalanını etkilemeden yeniden başlatılabilir.
3. **Performans**: XPC, farklı görevlerin farklı işlemlerde aynı anda çalıştırılmasına olanak tanıyarak kolay eşzamanlılık sağlar.

Tek **dezavantaj**, **bir uygulamayı birkaç işleme ayırmanın** ve bunların XPC aracılığıyla iletişim kurmasının **daha az verimli** olmasıdır. Ancak günümüz sistemlerinde bu neredeyse fark edilmez ve faydalar daha iyidir.

## Uygulama Özel XPC hizmetleri

Bir uygulamanın XPC bileşenleri **uygulamanın kendisinin içindedir.** Örneğin, Safari'de bunları **`/Applications/Safari.app/Contents/XPCServices`** içinde bulabilirsiniz. **`.xpc`** uzantısına sahiptirler (örneğin **`com.apple.Safari.SandboxBroker.xpc`**) ve ana ikili dosya ile birlikte **paketler**: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` ve bir `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Bir **XPC bileşeninin diğer XPC bileşenlerinden veya ana uygulama ikili dosyasından farklı haklara ve ayrıcalıklara sahip olacağını** düşünebilirsiniz. BİR XPC hizmeti, **Info.plist** dosyasında **JoinExistingSession** [**True**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) olarak ayarlandığında hariçtir. Bu durumda, XPC hizmeti, onu çağıran uygulama ile **aynı güvenlik oturumunda** çalışacaktır.

XPC hizmetleri, gerektiğinde **launchd** tarafından **başlatılır** ve tüm görevler **tamamlandığında** sistem kaynaklarını serbest bırakmak için **kapalı** tutulur. **Uygulama özel XPC bileşenleri yalnızca uygulama tarafından kullanılabilir**, böylece potansiyel güvenlik açıklarıyla ilişkili riski azaltır.

## Sistem Genelinde XPC hizmetleri

Sistem genelindeki XPC hizmetleri tüm kullanıcılar tarafından erişilebilir. Bu hizmetler, ya launchd ya da Mach türünde olup, **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** veya **`/Library/LaunchAgents`** gibi belirli dizinlerde bulunan plist dosyalarında **tanımlanmalıdır.**

Bu plist dosyalarında, hizmetin adıyla birlikte **`MachServices`** adında bir anahtar ve ikili dosyanın yolunu içeren **`Program`** adında bir anahtar bulunacaktır:
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
**`LaunchDameons`** içindekiler root tarafından çalıştırılır. Bu nedenle, yetkisiz bir süreç bunlardan biriyle iletişim kurabiliyorsa, yetkileri artırma olanağına sahip olabilir.

## XPC Nesneleri

- **`xpc_object_t`**

Her XPC mesajı, serileştirmeyi ve serileştirmeyi basitleştiren bir sözlük nesnesidir. Ayrıca, `libxpc.dylib` çoğu veri türünü tanımlar, bu nedenle alınan verilerin beklenen türde olması sağlanabilir. C API'sinde her nesne bir `xpc_object_t`'dir (ve türü `xpc_get_type(object)` kullanılarak kontrol edilebilir).\
Ayrıca, `xpc_copy_description(object)` fonksiyonu, hata ayıklama amaçları için yararlı olabilecek nesnenin bir dize temsilini almak için kullanılabilir.\
Bu nesnelerin ayrıca `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` gibi çağrılacak bazı yöntemleri vardır...

`xpc_object_t` nesneleri, `xpc_<objetType>_create` fonksiyonu çağrılarak oluşturulur; bu, nesnenin sınıf türünü (bir `XPC_TYPE_*`'dan biri) ve boyutunu (metadata için ekstra 40B eklenir) belirten `_xpc_base_create(Class, Size)` fonksiyonunu içten çağırır. Bu, nesnenin verilerinin 40B'lik bir ofsetten başlayacağı anlamına gelir.\
Bu nedenle, `xpc_<objectType>_t`, `xpc_object_t`'nin bir alt sınıfı gibi olup, `os_object_t*`'nin bir alt sınıfıdır.

> [!WARNING]
> Anahtarın türünü ve gerçek değerini almak veya ayarlamak için `xpc_dictionary_[get/set]_<objectType>` kullananın geliştirici olması gerektiğini unutmayın.

- **`xpc_pipe`**

Bir **`xpc_pipe`**, süreçlerin iletişim kurmak için kullanabileceği bir FIFO borusudur (iletişim Mach mesajlarını kullanır).\
Bir XPC sunucusu oluşturmak için `xpc_pipe_create()` veya belirli bir Mach portu kullanarak oluşturmak için `xpc_pipe_create_from_port()` çağrısı yapılabilir. Ardından, mesaj almak için `xpc_pipe_receive` ve `xpc_pipe_try_receive` çağrılabilir.

**`xpc_pipe`** nesnesinin, kullanılan iki Mach portu ve adı (varsa) hakkında bilgileri içeren bir **`xpc_object_t`** olduğunu unutmayın. Örneğin, plist'inde `/System/Library/LaunchDaemons/com.apple.secinitd.plist` bulunan `secinitd` daemon'u, `com.apple.secinitd` adında bir boru yapılandırır.

Bir **`xpc_pipe`** örneği, **`launchd`** tarafından oluşturulan **bootstrap pipe**'dır ve Mach portlarının paylaşılmasını mümkün kılar.

- **`NSXPC*`**

Bunlar, XPC bağlantılarının soyutlanmasını sağlayan Objective-C yüksek seviyeli nesnelerdir.\
Ayrıca, bu nesneleri DTrace ile önceki nesnelerden daha kolay hata ayıklamak mümkündür.

- **`GCD Kuyrukları`**

XPC, mesajları iletmek için GCD kullanır, ayrıca `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` gibi belirli dağıtım kuyrukları oluşturur...

## XPC Hizmetleri

Bunlar, diğer projelerin **`XPCServices`** klasöründe bulunan **`.xpc`** uzantılı paketlerdir ve `Info.plist` dosyasında `CFBundlePackageType` **`XPC!`** olarak ayarlanmıştır.\
Bu dosya, uygulama, kullanıcı, sistem veya bir sandbox tanımlayabilen `_SandboxProfile` gibi diğer yapılandırma anahtarlarına sahiptir veya hizmete erişmek için gerekli olan yetkilendirmeleri veya kimlikleri belirtebilen `_AllowedClients` anahtarına sahiptir. Bu ve diğer yapılandırma seçenekleri, hizmet başlatıldığında yapılandırmak için yararlı olacaktır.

### Bir Hizmeti Başlatma

Uygulama, `xpc_connection_create_mach_service` kullanarak bir XPC hizmetine **bağlanmaya** çalışır, ardından launchd daemon'u bulur ve **`xpcproxy`**'yi başlatır. **`xpcproxy`**, yapılandırılmış kısıtlamaları uygular ve sağlanan FD'ler ve Mach portları ile hizmeti başlatır.

XPC hizmetinin arama hızını artırmak için bir önbellek kullanılır.

`xpcproxy`'nin eylemlerini izlemek mümkündür:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC kütüphanesi, `xpc_ktrace_pid0` ve `xpc_ktrace_pid1` çağrılarıyla eylemleri günlüğe kaydetmek için `kdebug` kullanır. Kullandığı kodlar belgelenmemiştir, bu nedenle bunları `/usr/share/misc/trace.codes` dosyasına eklemek gereklidir. Ön ekleri `0x29`'dur ve örneğin biri `0x29000004`: `XPC_serializer_pack`'dır.\
`xpcproxy` aracı `0x22` ön ekini kullanır, örneğin: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Olay Mesajları

Uygulamalar, böyle olaylar gerçekleştiğinde **talep üzerine başlatılmalarını** sağlayan farklı olay **mesajlarına** **abone** olabilirler. Bu hizmetlerin **kurulumu**, **önceki dosyalarla aynı dizinlerde** bulunan **launchd plist dosyalarında** yapılır ve ekstra bir **`LaunchEvent`** anahtarı içerir.

### XPC Bağlantı Süreci Kontrolü

Bir süreç, bir XPC bağlantısı aracılığıyla bir yöntemi çağırmaya çalıştığında, **XPC hizmeti o sürecin bağlanmasına izin verilip verilmediğini kontrol etmelidir**. Bunu kontrol etmenin yaygın yolları ve yaygın tuzaklar şunlardır:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Yetkilendirmesi

Apple, uygulamaların **bazı hakları yapılandırmalarına ve bunları nasıl alacaklarına** izin verir, böylece çağrılan süreç bu haklara sahipse, XPC hizmetinden bir yöntemi **çağırmasına izin verilir**:

{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC mesajlarını dinlemek için [**xpcspy**](https://github.com/hot3eed/xpcspy) kullanabilirsiniz, bu araç **Frida** kullanır.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Başka bir kullanılabilir araç [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## XPC İletişim C Kodu Örneği

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
## XPC İletişim Objective-C Kod Örneği

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
## Dylb kodu içindeki İstemci
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

`RemoteXPC.framework` (from `libxpc`) tarafından sağlanan bu işlevsellik, farklı ana bilgisayarlar aracılığıyla XPC ile iletişim kurmayı sağlar.\
Uzaktan XPC'yi destekleyen hizmetler, plist'lerinde `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` durumunda olduğu gibi UsesRemoteXPC anahtarına sahip olacaktır. Ancak, hizmet `launchd` ile kaydedilmiş olsa da, işlevselliği sağlayan `UserEventAgent`'dir ve `com.apple.remoted.plugin` ile `com.apple.remoteservicediscovery.events.plugin` eklentilerini kullanır.

Ayrıca, `RemoteServiceDiscovery.framework`, `get_device`, `get_unique_device`, `connect` gibi işlevleri sergileyen `com.apple.remoted.plugin`'den bilgi almayı sağlar...

Bağlantı kullanıldığında ve hizmetin soket `fd`'si toplandığında, `remote_xpc_connection_*` sınıfı kullanılabilir.

Uzaktan hizmetler hakkında bilgi almak için `/usr/libexec/remotectl` cli aracını şu parametrelerle kullanmak mümkündür:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS ile ana bilgisayar arasındaki iletişim, özel bir IPv6 arayüzü üzerinden gerçekleşir. `MultiverseSupport.framework`, iletişim için kullanılacak `fd`'ye sahip soketlerin kurulmasına olanak tanır.\
Bu iletişimleri `netstat`, `nettop` veya açık kaynak seçeneği `netbottom` kullanarak bulmak mümkündür.

{{#include ../../../../../banners/hacktricks-training.md}}
