# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

XPC, macOS ve iOS üzerinde **process'ler arası iletişim** için kullanılan bir framework'tür. **Process'ler arasında güvenli, asynchronous çağrılar** yapmak için mekanizmalar sağlar. XPC, her **component'in** yalnızca **ihtiyaç duyduğu izinlerle** çalıştığı **privilege-separated uygulamaları** destekler; böylece ele geçirilmiş bir process'in verebileceği potansiyel zarar sınırlandırılır.<sup>[[1]](#references)</sup>

XPC, aynı sistemde çalışan farklı programların birbirlerine veri gönderip alması için kullanılan bir yöntemler kümesi olan Inter-Process Communication (IPC) biçimini kullanır.

XPC'nin başlıca faydaları şunlardır:

1. **Güvenlik**: Çalışmalar farklı process'lere ayrıldığında her process'e yalnızca ihtiyaç duyduğu izinler verilebilir. Bu, bir process ele geçirilse bile zarar verme kabiliyetinin sınırlı olduğu anlamına gelir.
2. **Stabilite**: XPC, crash'lerin oluştukları component ile sınırlanmasına yardımcı olur. Bir process crash olursa sistemin geri kalanını etkilemeden yeniden başlatılabilir.
3. **Performans**: XPC, farklı görevlerin farklı process'lerde eş zamanlı olarak çalıştırılabilmesi sayesinde concurrency kullanımını kolaylaştırır.

Temel **dezavantaj**, **bir uygulamanın birkaç process'e ayrılmasının** ve bunların XPC üzerinden iletişim kurmasının ek yük oluşturmasıdır. Modern sistemlerde bu ek yük genellikle güvenlik ve stabilite faydalarına kıyasla küçüktür.<sup>[[1]](#references)</sup>

## Uygulamaya Özel XPC Services

Bir uygulamanın XPC component'leri **uygulamanın kendisinin içindedir**. Örneğin Safari'de bunları **`/Applications/Safari.app/Contents/XPCServices`** altında bulabilirsiniz. Bunlar **`.xpc`** uzantısına sahiptir (örneğin **`com.apple.Safari.SandboxBroker.xpc`**) ve ana binary ile içlerinde bir `Info.plist` bulunan **bundle'lardır**. Örneğin: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` ve `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Bir **XPC component'i**, diğer XPC component'lerinden veya ana uygulama binary'sinden **farklı entitlement'lara ve privilege'lara** sahip olabilir. Bir istisna, **Info.plist** dosyasında **`JoinExistingSession`** değeri **`true`** olarak yapılandırılmış bir XPC service'tir. Bu durumda XPC service, kendisini çağıran **uygulamayla aynı security session'a** katılır.<sup>[[4]](#references)</sup>

XPC service'leri gerektiğinde **launchd** tarafından **başlatılır** ve sistem kaynaklarını serbest bırakmak için görevleri **tamamlandığında** kapatılabilir. **Uygulamaya özel XPC component'leri yalnızca onları içeren uygulama tarafından kullanılabilir**; böylece potansiyel vulnerability'lerin maruz kalma alanı azaltılır.<sup>[[2]](#references)</sup>

## Sistem Genelindeki XPC Services

Sistem genelindeki XPC service'lerine tek bir uygulamanın dışından erişilebilir. launchd tarafından yönetilen bu Mach service'lerinin, **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** veya **`/Library/LaunchAgents`** gibi dizinlerde bulunan **plist** dosyalarında tanımlanması gerekir.<sup>[[3]](#references)</sup>

Bu plist dosyaları, service adını içeren bir **`MachServices`** anahtarına ve binary'nin yolunu içeren bir **`Program`** anahtarına sahiptir:
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
`LaunchDaemons` içindeki **`LaunchDaemons`** hizmetleri genellikle root olarak çalışır. Bu nedenle, ayrıcalıksız bir process bu hizmetlerden biri tarafından açığa çıkarılan güvenlik açığı bulunan bir metoda erişebiliyorsa, privilege escalation gerçekleştirebilir.

## XPC Nesneleri

- **`xpc_object_t`**

XPC request ve reply payload'ları genellikle dictionary nesneleridir; bu da serialization ve deserialization işlemlerini kolaylaştırır. `libxpc.dylib` ayrıca alınan verinin beklenen tipe sahip olduğunu doğrulamak için gereken veri tiplerini de tanımlar. C API'de her nesne bir `xpc_object_t`'dir (tipi `xpc_get_type(object)` kullanılarak kontrol edilebilir).<sup>[[2]](#references)</sup>\
Ayrıca `xpc_copy_description(object)`, debugging amacıyla yararlı olabilecek nesnenin string gösterimini almak için kullanılabilir.\
Bu nesnelerin ayrıca `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` gibi çağrılabilecek bazı method'ları vardır...

`xpc_object_t` nesneleri, dahili olarak `_xpc_base_create(Class, Size)` fonksiyonunu çağıran bir `xpc_<objectType>_create` fonksiyonu çağrılarak oluşturulur; bu fonksiyon nesnenin class'ını (`XPC_TYPE_*` değerlerinden biri) ve boyutunu belirtir. Metadata için fazladan 40 byte eklenir; bu nedenle nesne verisi 40 byte offset'te başlar.\
Bu nedenle `xpc_<objectType>_t`, `xpc_object_t`'nin bir subclass'ı olan ve kendisi de `os_object_t*`'nin subclass'ı sayılabilecek bir yapıdadır.

> [!WARNING]
> Tipi ve bir key'in gerçek değerini almak veya ayarlamak için `xpc_dictionary_[get/set]_<objectType>` kullanması gereken kişi developer'dır.

- **`xpc_pipe`**

Bir **`xpc_pipe`**, process'lerin iletişim kurmak için kullanabildiği bir FIFO pipe'dır (iletişim Mach message'ları kullanır).\
`xpc_pipe_create()` veya belirli bir Mach port kullanarak oluşturmak için `xpc_pipe_create_from_port()` çağrılarak bir XPC server oluşturulabilir. Ardından message'ları almak için `xpc_pipe_receive` ve `xpc_pipe_try_receive` çağrılabilir.

**`xpc_pipe`** nesnesinin, kullanılan iki Mach port ve name (varsa) hakkındaki bilgileri struct'ında bulunduran bir **`xpc_object_t`** olduğunu unutmayın. Örneğin `secinitd` daemon'ı, `/System/Library/LaunchDaemons/com.apple.secinitd.plist` plist dosyasında `com.apple.secinitd` adlı pipe'ı yapılandırır.

Bir **`xpc_pipe`** örneği, **`launchd`** tarafından oluşturulan ve Mach port'larının paylaşılmasını mümkün kılan **bootstrap pipe**'dır.

- **`NSXPC*`**

Bunlar XPC connection'larını soyutlayan high-level Objective-C nesneleridir.\
Ayrıca bu nesneleri DTrace ile debug etmek öncekilere göre daha kolaydır.

- **`GCD Queues`**

XPC, message'ları iletmek için GCD kullanır; ayrıca `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` gibi belirli dispatch queue'ları oluşturur...

## XPC Services

Bunlar diğer project'lerin **`XPCServices`** klasörü içinde bulunan ve `.xpc` uzantısına sahip bundle'lardır; `Info.plist` dosyalarında `CFBundlePackageType` değeri **`XPC!`** olarak ayarlanmıştır.\
Bu dosyada ayrıca `ServiceType` (Application, User veya System olabilir), sandbox tanımlayabilen `_SandboxProfile` ve service'e erişmek için gereken entitlement'ları veya identity'yi belirtebilen `_AllowedClients` gibi configuration key'leri bulunur. Bu ve diğer seçenekler, service başlatıldığında nasıl yapılandırılacağını belirler.<sup>[[2]](#references)</sup>

### Service Başlatma

App, `xpc_connection_create_mach_service` kullanarak bir XPC service'e **connect** olmaya çalışır; ardından launchd daemon'ı bulur ve **`xpcproxy`**'yi başlatır. **`xpcproxy`**, yapılandırılmış kısıtlamaları uygular ve service'i sağlanan file descriptor'lar ve Mach port'larıyla başlatır.<sup>[[3]](#references)</sup>

XPC service aramasının hızını artırmak için bir cache kullanılır.

`xpcproxy`'nin işlemlerini şu şekilde trace etmek mümkündür:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
The XPC library, `xpc_ktrace_pid0` ve `xpc_ktrace_pid1` çağrılarını kullanarak eylemleri `kdebug` ile günlüğe kaydeder. Kullandığı kodlar belgelenmemiştir; bu nedenle `/usr/share/misc/trace.codes` dosyasına eklenmeleri gerekir. `0x29` önekini kullanırlar; örneğin, `0x29000004`, `XPC_serializer_pack` değeridir.\
`xpcproxy` utility'si `0x22` önekini kullanır; örneğin: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Uygulamalar farklı event **mesajlarına** **subscribe** olabilir; böylece bu tür olaylar gerçekleştiğinde **on-demand** olarak **başlatılabilirler**. Bu servislerin **setup** işlemi, önceki dosyalarla **aynı dizinlerde** bulunan ve ek bir **`LaunchEvent`** anahtarı içeren **launchd plist dosyalarında** yapılır.

### XPC Connecting Process Check

Bir process, bir XPC connection üzerinden method çağırmaya çalıştığında, **XPC service bu process'in bağlanmasına izin verilip verilmediğini kontrol etmelidir**. Yaygın doğrulama yöntemleri ve bunların sorunları şunlardır:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple ayrıca uygulamaların **authorization haklarını ve caller'ların bunları nasıl elde edeceğini yapılandırmasına** izin verir; böylece gerekli haklara sahip bir process, XPC service tarafından sunulan bir method'u **çağırabilir**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC mesajlarını sniff etmek için **Frida** kullanan **xpcspy** aracını kullanabilirsiniz.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Bir diğer olası araç **XPoCe2**.<sup>[[6]](#references)</sup>

## XPC Communication C Code Example

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
## Bir Dylib İçindeki Client
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

`libxpc` içindeki `RemoteXPC.framework` tarafından sağlanan işlevsellik, farklı host'lar arasında XPC iletişimine olanak tanır.\
Remote XPC desteği sunan servisler, `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` dosyasında olduğu gibi plist'lerinde `UsesRemoteXPC` anahtarına sahiptir. Servis `launchd` ile kaydedilmiş olsa da işlevselliği `UserEventAgent` ile onun `com.apple.remoted.plugin` ve `com.apple.remoteservicediscovery.events.plugin` eklentileri sağlar.

Ayrıca `RemoteServiceDiscovery.framework`, `com.apple.remoted.plugin` üzerinden bilgi alarak `get_device`, `get_unique_device` ve `connect` gibi işlevleri dışa sunar.

`connect` servis için socket dosya tanımlayıcısını döndürdüğünde, `remote_xpc_connection_*` sınıfını kullanmak mümkündür.

`/usr/libexec/remotectl` CLI kullanılarak, aşağıdakiler gibi komutlarla remote servisler hakkında bilgi alınabilir:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
bridgeOS ile host arasındaki iletişim, özel bir IPv6 arayüzü üzerinden gerçekleşir. `MultiverseSupport.framework`, iletişim için kullanılan file descriptor'lara sahip socket'ler oluşturur.\
Bu iletişimleri `netstat`, `nettop` veya open-source alternatif olan `netbottom` kullanarak bulmak mümkündür.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — XPC Servisleri Oluşturma](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
