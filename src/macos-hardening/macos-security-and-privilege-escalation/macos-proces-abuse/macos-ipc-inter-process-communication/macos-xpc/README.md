# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

XPC, XNU (macOS tarafından kullanılan kernel) inter-Process Communication ifadesinin kısaltmasıdır ve macOS ile iOS üzerinde **process'ler arasındaki iletişim** için kullanılan bir framework'tür. XPC, sistemdeki farklı process'ler arasında **güvenli, asenkron method çağrıları** yapmak için bir mekanizma sağlar. Apple'ın security paradigmasının bir parçasıdır ve her **component**'in işini yapmak için **yalnızca ihtiyaç duyduğu izinlerle** çalıştığı, böylece ele geçirilmiş bir process'ten kaynaklanabilecek olası hasarın sınırlandırıldığı **ayrıcalıkları ayrıştırılmış uygulamaların oluşturulmasına** olanak tanır.

XPC, aynı sistemde çalışan farklı programların veri gönderip almasını sağlayan method'lar kümesi olan Inter-Process Communication (IPC) biçimlerinden birini kullanır.

XPC'nin temel faydaları şunlardır:

1. **Security**: Çalışmanın farklı process'lere ayrılması sayesinde her process'e yalnızca ihtiyaç duyduğu izinler verilebilir. Böylece bir process ele geçirilse bile zarar verme yeteneği sınırlı olur.
2. **Stability**: XPC, crash'leri meydana geldikleri component ile sınırlandırmaya yardımcı olur. Bir process çökerse sistemin geri kalanını etkilemeden yeniden başlatılabilir.
3. **Performance**: XPC, farklı görevlerin farklı process'lerde eş zamanlı olarak çalıştırılabilmesini sağlayarak kolay concurrency sunar.

Tek **dezavantaj**, bir uygulamanın birden fazla process'e **ayrılması ve bunların XPC üzerinden iletişim kurmasının** **daha az verimli** olmasıdır. Ancak günümüz sistemlerinde bu durum neredeyse fark edilmez ve faydaları daha ağır basar.

## Uygulamaya Özel XPC services

Bir uygulamanın XPC component'leri **uygulamanın kendisinin içindedir.** Örneğin Safari'de bunları **`/Applications/Safari.app/Contents/XPCServices`** altında bulabilirsiniz. **`.xpc`** uzantısına sahiptirler (örneğin **`com.apple.Safari.SandboxBroker.xpc`**) ve içlerinde main binary bulunan **bundle**'lardır: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` ve bir `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Tahmin edebileceğiniz gibi bir **XPC component**, diğer XPC component'lerinden veya main app binary'sinden **farklı entitlements ve privileges**'lara sahip olur. Bunun İSTİSNASI, bir XPC service'in **Info.plist** dosyasında [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) değerinin “True” olarak ayarlanmış olmasıdır. Bu durumda XPC service, onu çağıran **application** ile **aynı security session** içinde çalışır.

XPC services, gerektiğinde **launchd** tarafından **başlatılır** ve sistem kaynaklarını serbest bırakmak için tüm görevler **tamamlandığında** kapatılır. **Uygulamaya özel XPC component'leri yalnızca uygulama tarafından kullanılabilir**, böylece olası vulnerabilities ile ilişkili risk azaltılır.

## System Wide XPC services

System-wide XPC services tüm kullanıcılar tarafından erişilebilir. launchd veya Mach-type olan bu services, **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** veya **`/Library/LaunchAgents`** gibi belirtilen dizinlerde bulunan **plist** dosyalarında tanımlanmalıdır.

Bu plist dosyalarında service'in adını içeren **`MachServices`** adlı bir key ve binary'nin path'ini içeren **`Program`** adlı bir key bulunur:
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
The **`LaunchDameons`** içindekiler root tarafından çalıştırılır. Bu nedenle ayrıcalıksız bir process bunlardan biriyle iletişim kurabilirse privilege escalation gerçekleştirebilir.

## XPC Objects

- **`xpc_object_t`**

Her XPC mesajı, serialization ve deserialization işlemlerini kolaylaştıran bir dictionary object'tir. Ayrıca `libxpc.dylib`, data type'ların çoğunu tanımlar; böylece alınan data'nın beklenen type'ta olduğu doğrulanabilir. C API'de her object bir `xpc_object_t`'dir (type'ı `xpc_get_type(object)` kullanılarak kontrol edilebilir).\
Ayrıca `xpc_copy_description(object)` fonksiyonu, debugging amaçlarıyla kullanılabilecek bir string representation elde etmek için kullanılabilir.\
Bu object'lerin ayrıca `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize` gibi çağrılabilecek bazı method'ları vardır...

`xpc_object_t`'ler, dahili olarak `_xpc_base_create(Class, Size)` fonksiyonunu çağıran `xpc_<objetType>_create` fonksiyonu çağrılarak oluşturulur. Bu fonksiyonda object class'ının type'ı (`XPC_TYPE_*` değerlerinden biri) ve boyutu belirtilir (metadata için boyuta ekstra 40B eklenir). Bunun anlamı, object'in data'sının 40B offset'inden başlayacağıdır.\
Dolayısıyla `xpc_<objectType>_t`, `xpc_object_t`'nin bir subclass'ı, o da `os_object_t*`'ın bir subclass'ı gibidir.

> [!WARNING]
> Type'ı ve bir key'in gerçek value'sunu almak veya ayarlamak için `xpc_dictionary_[get/set]_<objectType>` kullanması gereken kişinin developer olduğunu unutmayın.

- **`xpc_pipe`**

Bir **`xpc_pipe`**, process'lerin iletişim kurmak için kullanabileceği bir FIFO pipe'tır (iletişim Mach message'larını kullanır).\
`xpc_pipe_create()` veya belirli bir Mach port kullanarak oluşturmak için `xpc_pipe_create_from_port()` çağrılarak bir XPC server oluşturulabilir. Ardından message'ları almak için `xpc_pipe_receive` ve `xpc_pipe_try_receive` çağrılabilir.

**`xpc_pipe`** object'inin, kullanılan iki Mach port ve name (varsa) hakkında struct'ında bilgi bulunan bir **`xpc_object_t`** olduğunu unutmayın. Örneğin `secinitd` daemon'ı, `/System/Library/LaunchDaemons/com.apple.secinitd.plist` içindeki plist configuration'ında `com.apple.secinitd` adlı pipe'ı yapılandırır.

Bir **`xpc_pipe`** örneği, **`launchd`** tarafından oluşturulan ve Mach port'larının paylaşılmasını mümkün kılan **bootstrap pipe**'ıdır.

- **`NSXPC*`**

Bunlar, XPC connection'larının abstraction'ını sağlayan high-level Objective-C object'leridir.\
Ayrıca bu object'lerin debugging işlemi, öncekilere kıyasla DTrace ile daha kolaydır.

- **`GCD Queues`**

XPC, message'ları iletmek için GCD kullanır; ayrıca `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance` gibi belirli dispatch queue'ları oluşturur...

## XPC Services

Bunlar, diğer project'lerin **`XPCServices`** folder'ı içinde bulunan ve `.xpc` extension'ına sahip **bundle**'lardır; `Info.plist` içinde `CFBundlePackageType` değerleri **`XPC!`** olarak ayarlanmıştır.\
Bu file, Application, User veya System olabilen `ServiceType`; bir sandbox tanımlayabilen `_SandboxProfile`; ya da service ile iletişim kurmak için gereken entitlements veya ID'leri belirtebilen `_AllowedClients` gibi başka configuration key'lerine de sahiptir. Bu ve diğer configuration option'ları, service başlatılırken yapılandırılmasında kullanışlıdır.

### Starting a Service

App, `xpc_connection_create_mach_service` kullanarak bir XPC service'e **connect** olmaya çalışır; ardından launchd daemon'ı bulur ve **`xpcproxy`**'yi başlatır. **`xpcproxy`**, yapılandırılmış restriction'ları uygular ve service'i sağlanan FD'ler ve Mach port'larıyla spawn eder.

XPC service aramasının hızını artırmak için bir cache kullanılır.

`xpcproxy`'nin action'larını şu şekilde trace etmek mümkündür:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC library, `xpc_ktrace_pid0` ve `xpc_ktrace_pid1` çağrılarını kullanarak eylemleri günlüğe kaydetmek için `kdebug` kullanır. Kullandığı kodlar belgelenmemiştir; bu nedenle bunları `/usr/share/misc/trace.codes` dosyasına eklemek gerekir. `0x29` ön ekine sahiptirler ve örneğin biri `0x29000004`: `XPC_serializer_pack` şeklindedir.\
`xpcproxy` utility'si `0x22` ön ekini kullanır; örneğin: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Uygulamalar farklı event **messages**'larına **subscribe** olabilir; böylece bu tür olaylar gerçekleştiğinde **on-demand** olarak **başlatılabilirler**. Bu servislerin **kurulumu**, önceki dosyalarla **aynı dizinlerde** bulunan ve ekstra bir **`LaunchEvent`** anahtarı içeren l**aunchd plist dosyalarında** yapılır.

### XPC Connecting Process Check

Bir process, bir XPC connection üzerinden bir method çağırmaya çalıştığında, **XPC service bu process'in bağlanmasına izin verilip verilmediğini kontrol etmelidir**. Bu kontrolü yapmanın yaygın yolları ve sık karşılaşılan hatalar şunlardır:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## XPC Authorization

Apple ayrıca uygulamaların bazı hakları ve bunların nasıl alınacağını **yapılandırmasına** izin verir; böylece çağrıyı yapan process bu haklara sahipse XPC service içindeki bir **method'u çağırmasına izin verilir**:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

XPC mesajlarını izlemek için **Frida** kullanan [**xpcspy**](https://github.com/hot3eed/xpcspy) aracını kullanabilirsiniz.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Başka bir olası araç da [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html)'dir.

## XPC Communication C Code Örneği

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
## XPC Communication Objective-C Code Örneği

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
## Dylb kodunun içindeki Client
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

`libxpc` tarafından sağlanan bu işlevsellik, `RemoteXPC.framework` aracılığıyla farklı host'lar üzerinden XPC ile iletişim kurulmasına olanak tanır.\
Remote XPC'yi destekleyen servislerin plist dosyalarında, `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist` örneğinde olduğu gibi `UsesRemoteXPC` anahtarı bulunur. Ancak servis `launchd` ile kaydedilse de bu işlevselliği sağlayan, `com.apple.remoted.plugin` ve `com.apple.remoteservicediscovery.events.plugin` plugin'lerine sahip `UserEventAgent`'dır.

Ayrıca `RemoteServiceDiscovery.framework`, `com.apple.remoted.plugin` üzerinden `get_device`, `get_unique_device`, `connect` gibi işlevleri açığa çıkararak bilgi alınmasını sağlar.

`connect` kullanılıp servisin socket `fd`'si elde edildiğinde, `remote_xpc_connection_*` class'ını kullanmak mümkündür.

`/usr/libexec/remotectl` CLI tool'u, aşağıdaki gibi parametreler kullanılarak remote servisler hakkında bilgi almak için kullanılabilir:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS ile ana sistem arasındaki iletişim, özel bir IPv6 arayüzü üzerinden gerçekleşir. `MultiverseSupport.framework`, `fd` değeri iletişim için kullanılacak socket'lerin oluşturulmasını sağlar.\
Bu iletişimleri `netstat`, `nettop` veya açık kaynaklı seçenek olan `netbottom` kullanarak bulmak mümkündür.

{{#include ../../../../../banners/hacktricks-training.md}}
