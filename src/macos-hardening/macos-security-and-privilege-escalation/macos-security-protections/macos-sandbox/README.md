# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

MacOS Sandbox (początkowo nazywany Seatbelt) **ogranicza aplikacje** działające w sandboxie do **dozwolonych działań określonych w profilu Sandbox**, z którym działa aplikacja. Pomaga to zapewnić, że **aplikacja będzie miała dostęp tylko do oczekiwanych zasobów**.

Każda aplikacja z **uprawnieniem** **`com.apple.security.app-sandbox`** będzie uruchamiana w sandboxie. **Binarne pliki Apple** są zazwyczaj uruchamiane w Sandboxie, a wszystkie aplikacje z **App Store mają to uprawnienie**. Tak więc kilka aplikacji będzie uruchamianych w sandboxie.

Aby kontrolować, co proces może lub nie może robić, **Sandbox ma haki** w prawie każdej operacji, którą proces może próbować wykonać (w tym większości wywołań systemowych) przy użyciu **MACF**. Jednak w zależności od **uprawnień** aplikacji Sandbox może być bardziej liberalny w stosunku do procesu.

Niektóre ważne komponenty Sandbox to:

- **rozszerzenie jądra** `/System/Library/Extensions/Sandbox.kext`
- **prywatny framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **demon** działający w przestrzeni użytkownika `/usr/libexec/sandboxd`
- **kontenery** `~/Library/Containers`

### Kontenery

Każda aplikacja działająca w sandboxie będzie miała swój własny kontener w `~/Library/Containers/{CFBundleIdentifier}` :
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
Wewnątrz każdego folderu identyfikatora pakietu można znaleźć **plist** oraz **katalog danych** aplikacji o strukturze, która naśladuje folder domowy:
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
> Zauważ, że nawet jeśli symlinki są tam, aby "uciec" z Sandbox i uzyskać dostęp do innych folderów, aplikacja nadal musi **mieć uprawnienia** do ich dostępu. Te uprawnienia znajdują się w **`.plist`** w `RedirectablePaths`.

**`SandboxProfileData`** to skompilowany profil sandbox CFData zakodowany w B64.
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
> Wszystko, co zostało utworzone/zmodyfikowane przez aplikację w piaskownicy, otrzyma **atrybut kwarantanny**. To uniemożliwi przestrzeni piaskownicy uruchomienie czegoś za pomocą **`open`**, wywołując Gatekeeper.

## Profile Piaskownicy

Profile piaskownicy to pliki konfiguracyjne, które wskazują, co będzie **dozwolone/zabronione** w tej **piaskownicy**. Używa języka **Sandbox Profile Language (SBPL)**, który wykorzystuje język programowania [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

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
> Sprawdź to [**badanie**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **aby zobaczyć więcej działań, które mogą być dozwolone lub zabronione.**
>
> Zauważ, że w skompilowanej wersji profilu nazwy operacji są zastępowane ich wpisami w tablicy znanej przez dylib i kext, co sprawia, że skompilowana wersja jest krótsza i trudniejsza do odczytania.

Ważne **usługi systemowe** również działają w swoich własnych niestandardowych **sandboxach**, takich jak usługa `mdnsresponder`. Możesz zobaczyć te niestandardowe **profile sandboxów** w:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Inne profile sandboxów można sprawdzić w [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Aplikacje z **App Store** używają **profilu** **`/System/Library/Sandbox/Profiles/application.sb`**. Możesz sprawdzić w tym profilu, jak uprawnienia takie jak **`com.apple.security.network.server`** pozwalają procesowi na korzystanie z sieci.

Następnie niektóre **usługi demonów Apple** używają różnych profili znajdujących się w `/System/Library/Sandbox/Profiles/*.sb` lub `/usr/share/sandbox/*.sb`. Te sandboxy są stosowane w głównej funkcji wywołującej API `sandbox_init_XXX`.

**SIP** to profil Sandbox o nazwie platform_profile w `/System/Library/Sandbox/rootless.conf`.

### Przykłady profili Sandbox

Aby uruchomić aplikację z **konkretnym profilem sandboxa**, możesz użyć:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
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

> [!NOTE]
> Zauważ, że **oprogramowanie** **napisane przez Apple**, które działa na **Windows**, **nie ma dodatkowych środków bezpieczeństwa**, takich jak sandboxing aplikacji.

Przykłady obejść:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (są w stanie zapisywać pliki poza sandboxem, których nazwa zaczyna się od `~$`).

### Śledzenie Sandboxa

#### Poprzez profil

Możliwe jest śledzenie wszystkich kontroli, które sandbox wykonuje za każdym razem, gdy sprawdzana jest akcja. W tym celu wystarczy utworzyć następujący profil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
A następnie po prostu wykonaj coś za pomocą tego profilu:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
W `/tmp/trace.out` będziesz mógł zobaczyć każdy sprawdzany sandbox za każdym razem, gdy był wywoływany (więc wiele duplikatów).

Możliwe jest również śledzenie sandboxa za pomocą parametru **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Poprzez API

Funkcja `sandbox_set_trace_path` eksportowana przez `libsystem_sandbox.dylib` pozwala określić nazwę pliku śledzenia, do którego będą zapisywane sprawdzenia sandboxa.\
Możliwe jest również zrobienie czegoś podobnego, wywołując `sandbox_vtrace_enable()` i następnie uzyskując logi błędów z bufora, wywołując `sandbox_vtrace_report()`.

### Inspekcja Sandboxa

`libsandbox.dylib` eksportuje funkcję o nazwie sandbox_inspect_pid, która daje listę stanu sandboxa procesu (w tym rozszerzenia). Jednak tylko binaria platformy mogą korzystać z tej funkcji.

### Profile Sandboxa MacOS i iOS

MacOS przechowuje profile sandboxa systemu w dwóch lokalizacjach: **/usr/share/sandbox/** i **/System/Library/Sandbox/Profiles**.

A jeśli aplikacja firm trzecich posiada uprawnienie _**com.apple.security.app-sandbox**_, system stosuje profil **/System/Library/Sandbox/Profiles/application.sb** do tego procesu.

W iOS domyślny profil nazywa się **container** i nie mamy tekstowej reprezentacji SBPL. W pamięci ten sandbox jest reprezentowany jako drzewo binarne Allow/Deny dla każdego uprawnienia z sandboxa.

### Niestandardowy SBPL w aplikacjach App Store

Możliwe jest, aby firmy uruchamiały swoje aplikacje **z niestandardowymi profilami Sandbox** (zamiast z domyślnym). Muszą używać uprawnienia **`com.apple.security.temporary-exception.sbpl`**, które musi być autoryzowane przez Apple.

Możliwe jest sprawdzenie definicji tego uprawnienia w **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
To będzie **eval string po tym uprawnieniu** jako profil Sandbox.

### Kompilacja i dekompilacja profilu Sandbox

Narzędzie **`sandbox-exec`** używa funkcji `sandbox_compile_*` z `libsandbox.dylib`. Główne funkcje eksportowane to: `sandbox_compile_file` (oczekuje ścieżki do pliku, parametr `-f`), `sandbox_compile_string` (oczekuje stringa, parametr `-p`), `sandbox_compile_name` (oczekuje nazwy kontenera, parametr `-n`), `sandbox_compile_entitlements` (oczekuje plist uprawnień).

Ta odwrócona i [**otwarta wersja narzędzia sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) pozwala na zapisanie przez **`sandbox-exec`** skompilowanego profilu sandbox w pliku.

Ponadto, aby ograniczyć proces w kontenerze, może wywołać `sandbox_spawnattrs_set[container/profilename]` i przekazać kontener lub istniejący profil.

## Debugowanie i omijanie Sandbox

Na macOS, w przeciwieństwie do iOS, gdzie procesy są od początku izolowane przez jądro, **procesy muszą same zdecydować o wejściu do sandboxu**. Oznacza to, że na macOS proces nie jest ograniczany przez sandbox, dopóki aktywnie nie zdecyduje się do niego wejść, chociaż aplikacje z App Store są zawsze izolowane.

Procesy są automatycznie izolowane z userland, gdy się uruchamiają, jeśli mają uprawnienie: `com.apple.security.app-sandbox`. Aby uzyskać szczegółowe wyjaśnienie tego procesu, sprawdź:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Rozszerzenia Sandbox**

Rozszerzenia pozwalają na nadanie dodatkowych uprawnień obiektowi i są nadawane przez wywołanie jednej z funkcji:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Rozszerzenia są przechowywane w drugim slocie etykiety MACF, dostępnym z poświadczeń procesu. Następujące **`sbtool`** może uzyskać dostęp do tych informacji.

Należy zauważyć, że rozszerzenia są zazwyczaj przyznawane przez dozwolone procesy, na przykład `tccd` przyzna token rozszerzenia `com.apple.tcc.kTCCServicePhotos`, gdy proces próbował uzyskać dostęp do zdjęć i został dozwolony w wiadomości XPC. Następnie proces będzie musiał wykorzystać token rozszerzenia, aby został do niego dodany.\
Należy zauważyć, że tokeny rozszerzeń są długimi szesnastkowymi, które kodują przyznane uprawnienia. Jednak nie mają one twardo zakodowanego dozwolonego PID, co oznacza, że każdy proces z dostępem do tokena może być **wykorzystywany przez wiele procesów**.

Należy zauważyć, że rozszerzenia są również bardzo związane z uprawnieniami, więc posiadanie określonych uprawnień może automatycznie przyznać określone rozszerzenia.

### **Sprawdź uprawnienia PID**

[**Zgodnie z tym**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), funkcje **`sandbox_check`** (to jest `__mac_syscall`), mogą sprawdzić **czy operacja jest dozwolona czy nie** przez sandbox w danym PID, tokenie audytu lub unikalnym ID.

Narzędzie [**sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (znajdź je [skompilowane tutaj](https://newosxbook.com/articles/hitsb.html)) może sprawdzić, czy PID może wykonać określone działania:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Możliwe jest również zawieszenie i wznowienie piaskownicy za pomocą funkcji `sandbox_suspend` i `sandbox_unsuspend` z `libsystem_sandbox.dylib`.

Należy zauważyć, że aby wywołać funkcję zawieszenia, sprawdzane są pewne uprawnienia w celu autoryzacji wywołującego, takie jak:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

To wywołanie systemowe (#381) oczekuje jednego argumentu typu string, który wskaże moduł do uruchomienia, a następnie kod w drugim argumencie, który wskaże funkcję do uruchomienia. Trzeci argument będzie zależał od wykonanej funkcji.

Wywołanie funkcji `___sandbox_ms` opakowuje `mac_syscall`, wskazując w pierwszym argumencie `"Sandbox"`, podobnie jak `___sandbox_msp` jest opakowaniem `mac_set_proc` (#387). Następnie niektóre z obsługiwanych kodów przez `___sandbox_ms` można znaleźć w tej tabeli:

- **set_profile (#0)**: Zastosuj skompilowany lub nazwany profil do procesu.
- **platform_policy (#1)**: Wymuś kontrole polityki specyficzne dla platformy (różni się między macOS a iOS).
- **check_sandbox (#2)**: Wykonaj ręczną kontrolę konkretnej operacji piaskownicy.
- **note (#3)**: Dodaje notację do piaskownicy.
- **container (#4)**: Dołącz notację do piaskownicy, zazwyczaj w celach debugowania lub identyfikacji.
- **extension_issue (#5)**: Generuje nową rozszerzenie dla procesu.
- **extension_consume (#6)**: Konsumuje dane rozszerzenie.
- **extension_release (#7)**: Zwolnij pamięć związaną z konsumowanym rozszerzeniem.
- **extension_update_file (#8)**: Modyfikuje parametry istniejącego rozszerzenia pliku w piaskownicy.
- **extension_twiddle (#9)**: Dostosowuje lub modyfikuje istniejące rozszerzenie pliku (np. TextEdit, rtf, rtfd).
- **suspend (#10)**: Tymczasowo zawiesza wszystkie kontrole piaskownicy (wymaga odpowiednich uprawnień).
- **unsuspend (#11)**: Wznawia wszystkie wcześniej zawieszone kontrole piaskownicy.
- **passthrough_access (#12)**: Zezwala na bezpośredni dostęp do zasobu, omijając kontrole piaskownicy.
- **set_container_path (#13)**: (tylko iOS) Ustaw ścieżkę kontenera dla grupy aplikacji lub identyfikatora podpisu.
- **container_map (#14)**: (tylko iOS) Pobierz ścieżkę kontenera z `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Ustaw metadane trybu użytkownika w piaskownicy.
- **inspect (#16)**: Dostarcz informacje debugowe o procesie w piaskownicy.
- **dump (#18)**: (macOS 11) Zrzut aktualnego profilu piaskownicy do analizy.
- **vtrace (#19)**: Śledź operacje piaskownicy w celu monitorowania lub debugowania.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Dezaktywuj nazwane profile (np. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Wykonaj wiele operacji `sandbox_check` w jednym wywołaniu.
- **reference_retain_by_audit_token (#28)**: Utwórz odniesienie do tokena audytu do użycia w kontrolach piaskownicy.
- **reference_release (#29)**: Zwolnij wcześniej zachowane odniesienie do tokena audytu.
- **rootless_allows_task_for_pid (#30)**: Sprawdź, czy `task_for_pid` jest dozwolone (podobnie jak kontrole `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Zastosuj plik manifestu System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Sprawdź plik manifestu SIP przed wykonaniem.
- **rootless_protected_volume (#33)**: (macOS) Zastosuj ochrony SIP do dysku lub partycji.
- **rootless_mkdir_protected (#34)**: Zastosuj ochronę SIP/DataVault do procesu tworzenia katalogu.

## Sandbox.kext

Należy zauważyć, że w iOS rozszerzenie jądra zawiera **wbudowane wszystkie profile** wewnątrz segmentu `__TEXT.__const`, aby uniknąć ich modyfikacji. Oto niektóre interesujące funkcje z rozszerzenia jądra:

- **`hook_policy_init`**: Hookuje `mpo_policy_init` i jest wywoływana po `mac_policy_register`. Wykonuje większość inicjalizacji piaskownicy. Inicjalizuje również SIP.
- **`hook_policy_initbsd`**: Ustawia interfejs sysctl rejestrując `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` i `security.mac.sandbox.debug_mode` (jeśli uruchomione z `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Jest wywoływana przez `mac_syscall` z "Sandbox" jako pierwszy argument i kod wskazujący operację w drugim. Używany jest switch do znalezienia kodu do uruchomienia zgodnie z żądanym kodem.

### MACF Hooks

**`Sandbox.kext`** używa ponad stu hooków za pośrednictwem MACF. Większość hooków sprawdzi tylko niektóre trywialne przypadki, które pozwalają na wykonanie akcji, jeśli nie, wywołają **`cred_sb_evalutate`** z **poświadczeniami** z MACF i numerem odpowiadającym **operacji** do wykonania oraz **buforem** na wyjście.

Dobrym przykładem jest funkcja **`_mpo_file_check_mmap`**, która hookuje **`mmap`** i która zacznie sprawdzać, czy nowa pamięć będzie zapisywalna (a jeśli nie, pozwoli na wykonanie), następnie sprawdzi, czy jest używana dla wspólnej pamięci dyld, a jeśli tak, pozwoli na wykonanie, a na koniec wywoła **`sb_evaluate_internal`** (lub jeden z jego wrapperów), aby przeprowadzić dalsze kontrole zezwolenia.

Ponadto, spośród setek hooków, które używa Sandbox, są 3, które są szczególnie interesujące:

- `mpo_proc_check_for`: Zastosowuje profil, jeśli to konieczne i jeśli nie był wcześniej zastosowany.
- `mpo_vnode_check_exec`: Wywoływana, gdy proces ładuje powiązany binarny plik, następnie przeprowadzana jest kontrola profilu oraz kontrola zabraniająca wykonywania SUID/SGID.
- `mpo_cred_label_update_execve`: Wywoływana, gdy przypisywana jest etykieta. Jest to najdłuższa, ponieważ jest wywoływana, gdy binarny plik jest w pełni załadowany, ale jeszcze nie został wykonany. Wykona takie działania jak tworzenie obiektu piaskownicy, dołączenie struktury piaskownicy do poświadczeń kauth, usunięcie dostępu do portów mach...

Należy zauważyć, że **`_cred_sb_evalutate`** jest wrapperem nad **`sb_evaluate_internal`** i ta funkcja pobiera przekazane poświadczenia, a następnie wykonuje ocenę za pomocą funkcji **`eval`**, która zazwyczaj ocenia **profil platformy**, który domyślnie jest stosowany do wszystkich procesów, a następnie **specyficzny profil procesu**. Należy zauważyć, że profil platformy jest jednym z głównych komponentów **SIP** w macOS.

## Sandboxd

Piaskownica ma również działającego demona użytkownika, który udostępnia usługę XPC Mach `com.apple.sandboxd` i wiąże specjalny port 14 (`HOST_SEATBELT_PORT`), którego rozszerzenie jądra używa do komunikacji z nim. Udostępnia niektóre funkcje za pomocą MIG.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
