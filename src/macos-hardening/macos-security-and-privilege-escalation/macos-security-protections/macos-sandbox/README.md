# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

MacOS Sandbox (początkowo nazywany Seatbelt) **ogranicza aplikacje** uruchomione wewnątrz sandboxa do **dozwolonych działań określonych w profilu Sandbox**, z którym uruchomiona jest aplikacja. Pomaga to zapewnić, że **aplikacja będzie uzyskiwać dostęp wyłącznie do oczekiwanych zasobów**.

Każda aplikacja posiadająca **entitlement** **`com.apple.security.app-sandbox`** będzie wykonywana wewnątrz sandboxa. **Apple binaries** są zwykle uruchamiane wewnątrz Sandbox, a wszystkie aplikacje z **App Store mają ten entitlement**. Oznacza to, że kilka aplikacji będzie uruchamianych wewnątrz sandboxa.<sup>[[4]](#references)</sup>

Aby kontrolować, co proces może, a czego nie może robić, **Sandbox ma hooks** w niemal każdej operacji, którą proces może próbować wykonać (w tym w większości syscalli), korzystając z **MACF**. Jednak **w zależności** od **entitlements** aplikacji Sandbox może być bardziej pobłażliwy wobec procesu.

Niektóre ważne komponenty Sandbox to:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **daemon** działający w userlandzie `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

Każda aplikacja działająca w sandboxie będzie mieć własny container w `~/Library/Containers/{CFBundleIdentifier}` :
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
W każdym folderze bundle id można znaleźć plik **plist** oraz katalog **Data** aplikacji, ze strukturą odwzorowującą folder Home:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> Należy pamiętać, że nawet jeśli symlinki umożliwiają „ucieczkę” z Sandbox i dostęp do innych folderów, aplikacja nadal musi **mieć uprawnienia** do uzyskania do nich dostępu. Te uprawnienia znajdują się w pliku **`.plist`**, w `RedirectablePaths`.

**`SandboxProfileData`** to skompilowany profil Sandbox CFData zakodowany w B64.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> Wszystko utworzone/zmodyfikowane przez aplikację działającą w Sandbox otrzyma **atrybut kwarantanny**. Uniemożliwi to utworzenie przestrzeni Sandbox poprzez uruchomienie Gatekeeper, jeśli aplikacja Sandbox spróbuje wykonać coś za pomocą **`open`**.

## Profile Sandbox

Profile Sandbox to pliki konfiguracyjne wskazujące, co będzie **dozwolone/zabronione** w danym **Sandbox**. Wykorzystują one **Sandbox Profile Language (SBPL)**, która korzysta z języka programowania [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Tutaj znajdziesz przykład:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> Sprawdź te [**badania**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **aby poznać więcej akcji, które mogą być dozwolone lub zablokowane.**<sup>[[5]](#references)</sup>
>
> Należy zauważyć, że w skompilowanej wersji profilu nazwy operacji są zastępowane ich wpisami w tablicy znanej dylib i kext, dzięki czemu skompilowana wersja jest krótsza i trudniejsza do odczytania.

Ważne **system services** również działają we własnym niestandardowym **sandbox**, takim jak usługa `mdnsresponder`. Te niestandardowe **sandbox profiles** można znaleźć w:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Inne sandbox profiles można sprawdzić pod adresem [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- W iOS platform profile znajdują się wewnątrz sandbox `.kext`, w `_platform_profile_data`, wewnątrz pliku binarnego.

Aplikacje **App Store** używają **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. W tym profilu można sprawdzić, jak entitlements takie jak **`com.apple.security.network.server`** pozwalają procesowi korzystać z sieci.

Następnie niektóre **Apple daemon services** używają różnych profili znajdujących się w `/System/Library/Sandbox/Profiles/*.sb` lub `/usr/share/sandbox/*.sb`. Te sandbox są stosowane w głównej funkcji wywołującej API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

**SIP** to Sandbox profile o nazwie platform_profile w `/System/Library/Sandbox/rootless.conf`.

### Przykłady Sandbox Profile

Aby uruchomić aplikację z **określonym sandbox profile**, można użyć:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Zauważ, że **oprogramowanie** **autorstwa Apple**, które działa w systemie **Windows**, **nie ma dodatkowych zabezpieczeń**, takich jak sandbox aplikacji.

Przykłady obejść:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (mogą zapisywać pliki poza sandboxem, których nazwa zaczyna się od `~$`).<sup>[[7]](#references)</sup>

### Śledzenie Sandbox

#### Przez profil

Możliwe jest śledzenie wszystkich kontroli wykonywanych przez sandbox za każdym razem, gdy sprawdzana jest akcja. W tym celu utwórz następujący profil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
A następnie po prostu wykonaj coś przy użyciu tego profilu:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
W `/tmp/trace.out` można zobaczyć każdą kontrolę sandbox wykonaną za każdym razem, gdy została wywołana (czyli bardzo wiele duplikatów).

Możliwe jest również śledzenie sandbox przy użyciu parametru **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Przez API

Funkcja `sandbox_set_trace_path` eksportowana przez `libsystem_sandbox.dylib` pozwala określić nazwę pliku śledzenia, do którego będą zapisywane kontrole sandbox.\
Możliwe jest również wykonanie czegoś podobnego przez wywołanie `sandbox_vtrace_enable()` i następnie pobranie logów błędów z bufora za pomocą `sandbox_vtrace_report()`.

### Inspekcja Sandbox

`libsandbox.dylib` eksportuje funkcję o nazwie sandbox_inspect_pid, która zwraca listę informacji o stanie sandbox procesu (w tym rozszerzenia). Jednak z tej funkcji mogą korzystać wyłącznie binaria platformowe.

### Profile Sandbox MacOS i iOS

MacOS przechowuje systemowe profile sandbox w dwóch lokalizacjach: **/usr/share/sandbox/** oraz **/System/Library/Sandbox/Profiles**.

Jeśli aplikacja innej firmy posiada entitlement _**com.apple.security.app-sandbox**_, system stosuje do tego procesu profil **/System/Library/Sandbox/Profiles/application.sb**.

W iOS domyślny profil nazywa się **container**, a jego tekstowa reprezentacja SBPL nie jest dostępna. W pamięci ten sandbox jest reprezentowany jako binarne drzewo Allow/Deny dla każdego uprawnienia sandbox.

### Niestandardowy SBPL w aplikacjach App Store

Firmy mogą potencjalnie sprawić, aby ich aplikacje działały z **niestandardowymi profilami Sandbox** (zamiast z profilem domyślnym). Muszą w tym celu użyć entitlement **`com.apple.security.temporary-exception.sbpl`**, który musi zostać autoryzowany przez Apple.

Definicję tego entitlement można sprawdzić w **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
This will **eval string po tym entitlement** jako profil Sandbox.

### Kompilowanie i dekompilowanie profilu Sandbox

Narzędzie **`sandbox-exec`** używa funkcji `sandbox_compile_*` z `libsandbox.dylib`. Główne eksportowane funkcje to: `sandbox_compile_file` (oczekuje ścieżki pliku, parametr `-f`), `sandbox_compile_string` (oczekuje stringu, parametr `-p`), `sandbox_compile_name` (oczekuje nazwy kontenera, parametr `-n`), `sandbox_compile_entitlements` (oczekuje entitlements plist).

Ta odwrócona i [**udostępniona jako open source wersja narzędzia sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) pozwala sprawić, aby **`sandbox-exec`** zapisał skompilowany profil Sandbox do pliku.

Ponadto, aby ograniczyć proces do kontenera, może on wywołać `sandbox_spawnattrs_set[container/profilename]` i przekazać kontener lub istniejący wcześniej profil.

## Debugowanie i omijanie Sandbox

W macOS, w przeciwieństwie do iOS, gdzie procesy są od początku sandboxowane przez kernel, **procesy muszą samodzielnie zdecydować się na wejście do Sandbox**. Oznacza to, że w macOS proces nie jest ograniczany przez Sandbox, dopóki aktywnie nie zdecyduje się do niego wejść, chociaż aplikacje z App Store są zawsze sandboxowane.

Procesy są automatycznie sandboxowane z poziomu userland podczas uruchamiania, jeśli mają entitlement: `com.apple.security.app-sandbox`. Szczegółowe wyjaśnienie tego procesu znajduje się tutaj:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Rozszerzenia Sandbox**

Extensions umożliwiają nadanie obiektowi dodatkowych uprawnień i są przyznawane przez wywołanie jednej z funkcji:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions są przechowywane w drugim slocie etykiety MACF, dostępnym z poziomu credentials procesu. Poniższe narzędzie **`sbtool`** umożliwia dostęp do tych informacji.

Należy pamiętać, że extensions są zwykle przyznawane przez dozwolone procesy. Na przykład `tccd` przyzna token extension `com.apple.tcc.kTCCServicePhotos`, gdy proces spróbuje uzyskać dostęp do zdjęć i otrzyma na to zgodę w komunikacie XPC. Następnie proces musi skonsumować token extension, aby został on do niego dodany.\
Należy pamiętać, że tokeny extensions są długimi wartościami szesnastkowymi kodującymi przyznane uprawnienia. Nie mają jednak na stałe zakodowanego dozwolonego PID, co oznacza, że każdy proces mający dostęp do tokena może zostać **skonsumowany przez wiele procesów**.

Należy również pamiętać, że extensions są ściśle powiązane z entitlements, więc posiadanie określonych entitlements może automatycznie przyznawać określone extensions.

### **Sprawdzanie uprawnień PID**

[**Zgodnie z tym**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s) funkcje **`sandbox_check`** (jest to `__mac_syscall`) mogą sprawdzać, **czy dana operacja jest dozwolona przez Sandbox**, dla określonego PID, tokena audytowego lub unikalnego ID.<sup>[[8]](#references)</sup>

Narzędzie [**sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (znajduje się [tutaj w wersji skompilowanej](https://newosxbook.com/articles/hitsb.html)) może sprawdzać, czy PID może wykonać określone działania:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Możliwe jest również zawieszenie i wznowienie sandboxa za pomocą funkcji `sandbox_suspend` i `sandbox_unsuspend` z `libsystem_sandbox.dylib`.

Należy pamiętać, że aby wywołać funkcję zawieszania, sprawdzane są określone entitlements w celu autoryzacji wywołującego:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

To wywołanie systemowe (#381) oczekuje jako pierwszego argumentu jednego stringa wskazującego moduł do uruchomienia, a następnie kodu w drugim argumencie wskazującego funkcję do uruchomienia. Trzeci argument będzie zależeć od wykonanej funkcji.<sup>[[2]](#references)</sup>

Funkcja `___sandbox_ms` opakowuje wywołanie `mac_syscall`, przekazując w pierwszym argumencie `"Sandbox"`, podobnie jak `___sandbox_msp` jest wrapperem dla `mac_set_proc` (#387). Następnie niektóre kody obsługiwane przez `___sandbox_ms` można znaleźć w tej tabeli:

- **set_profile (#0)**: Zastosowanie skompilowanego lub nazwanego profilu do procesu.
- **platform_policy (#1)**: Wymuszenie kontroli polityki specyficznych dla platformy (różniących się między macOS i iOS).
- **check_sandbox (#2)**: Wykonanie ręcznej kontroli określonej operacji sandboxa.
- **note (#3)**: Dodanie adnotacji do sandboxa.
- **container (#4)**: Dołączenie adnotacji do sandboxa, zazwyczaj w celach debugowania lub identyfikacji.
- **extension_issue (#5)**: Wygenerowanie nowego rozszerzenia dla procesu.
- **extension_consume (#6)**: Skonsumowanie danego rozszerzenia.
- **extension_release (#7)**: Zwolnienie pamięci powiązanej ze skonsumowanym rozszerzeniem.
- **extension_update_file (#8)**: Modyfikacja parametrów istniejącego rozszerzenia pliku w sandboxie.
- **extension_twiddle (#9)**: Dostosowanie lub modyfikacja istniejącego rozszerzenia pliku (np. TextEdit, rtf, rtfd).
- **suspend (#10)**: Tymczasowe zawieszenie wszystkich kontroli sandboxa (wymaga odpowiednich entitlements).
- **unsuspend (#11)**: Wznowienie wszystkich wcześniej zawieszonych kontroli sandboxa.
- **passthrough_access (#12)**: Zezwolenie na bezpośredni dostęp passthrough do zasobu z pominięciem kontroli sandboxa.
- **set_container_path (#13)**: (tylko iOS) Ustawienie ścieżki kontenera dla app group lub signing ID.
- **container_map (#14)**: (tylko iOS) Pobranie ścieżki kontenera z `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Ustawienie metadanych trybu użytkownika w sandboxie.
- **inspect (#16)**: Udostępnienie informacji debugowania o procesie działającym w sandboxie.
- **dump (#18)**: (macOS 11) Zrzut bieżącego profilu sandboxa do analizy.
- **vtrace (#19)**: Śledzenie operacji sandboxa na potrzeby monitorowania lub debugowania.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Dezaktywacja nazwanych profili (np. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Wykonanie wielu operacji `sandbox_check` w jednym wywołaniu.
- **reference_retain_by_audit_token (#28)**: Utworzenie referencji dla tokena audytowego do użycia w kontrolach sandboxa.
- **reference_release (#29)**: Zwolnienie wcześniej zachowanej referencji tokena audytowego.
- **rootless_allows_task_for_pid (#30)**: Weryfikacja, czy `task_for_pid` jest dozwolone (podobnie do kontroli `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Zastosowanie pliku manifestu System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Sprawdzenie pliku manifestu SIP przed wykonaniem.
- **rootless_protected_volume (#33)**: (macOS) Zastosowanie ochrony SIP do dysku lub partycji.
- **rootless_mkdir_protected (#34)**: Zastosowanie ochrony SIP/DataVault do procesu tworzenia katalogu.

## Sandbox.kext

Należy pamiętać, że w iOS rozszerzenie jądra zawiera **hardcoded wszystkie profile** wewnątrz segmentu `__TEXT.__const`, aby zapobiec ich modyfikacji. Poniżej przedstawiono kilka interesujących funkcji rozszerzenia jądra:

- **`hook_policy_init`**: Hookuje `mpo_policy_init` i jest wywoływana po `mac_policy_register`. Wykonuje większość inicjalizacji sandboxa. Inicjalizuje również SIP.
- **`hook_policy_initbsd`**: Konfiguruje interfejs sysctl, rejestrując `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` i `security.mac.sandbox.debug_mode` (jeśli system został uruchomiony z `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Jest wywoływana przez `mac_syscall` z `"Sandbox"` jako pierwszym argumentem i kodem wskazującym operację jako drugim. Do znalezienia kodu, który ma zostać uruchomiony zgodnie z żądanym kodem, używany jest switch.

### MACF Hooks

**`Sandbox.kext`** używa ponad stu hooków za pośrednictwem MACF. Większość hooków sprawdza jedynie kilka trywialnych przypadków, które pozwalają wykonać akcję; jeśli nie, wywołują **`cred_sb_evalutate`** z **credentials** z MACF, numerem odpowiadającym **operacji**, która ma zostać wykonana, oraz **bufferem** na dane wyjściowe.<sup>[[1]](#references)</sup>

Dobrym przykładem jest funkcja **`_mpo_file_check_mmap`**, która hookuje **`mmap`** i rozpoczyna od sprawdzenia, czy nowa pamięć będzie zapisywalna (a jeśli nie, zezwala na wykonanie), następnie sprawdza, czy jest używana przez dyld shared cache i jeśli tak, zezwala na wykonanie, a na końcu wywołuje **`sb_evaluate_internal`** (lub jeden z jego wrapperów), aby przeprowadzić dalsze kontrole uprawnień.

Ponadto spośród setek hooków używanych przez Sandbox trzy są szczególnie interesujące:

- `mpo_proc_check_for`: Stosuje profil, jeśli jest to wymagane i jeśli nie został on wcześniej zastosowany.
- `mpo_vnode_check_exec`: Wywoływany, gdy proces ładuje powiązany binary; następnie wykonywana jest kontrola profilu, a także kontrola zabraniająca wykonań SUID/SGID.
- `mpo_cred_label_update_execve`: Wywoływany, gdy przypisywana jest label. Jest najdłuższy, ponieważ wywoływany jest po pełnym załadowaniu binary, ale przed jego wykonaniem. Wykonuje działania takie jak utworzenie obiektu sandboxa, dołączenie struktury sandboxa do credentials kauth, usunięcie dostępu do portów mach...

Należy pamiętać, że **`_cred_sb_evalutate`** jest wrapperem nad **`sb_evaluate_internal`**, a ta funkcja otrzymuje przekazane credentials, a następnie przeprowadza ewaluację za pomocą funkcji **`eval`**, która zwykle ocenia **platform profile**, domyślnie stosowany do wszystkich procesów, a następnie **specific process profile**. Należy pamiętać, że platform profile jest jednym z głównych komponentów **SIP** w macOS.

## Sandboxd

Sandbox ma również działający w przestrzeni użytkownika daemon, który udostępnia usługę XPC Mach `com.apple.sandboxd` i wiąże specjalny port 14 (`HOST_SEATBELT_PORT`), używany przez rozszerzenie jądra do komunikacji z nim. Udostępnia niektóre funkcje za pomocą MIG.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
