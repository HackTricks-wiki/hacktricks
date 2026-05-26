# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Skupia się na egzekwowaniu integralności kodu działającego w systemie, dostarczając logikę stojącą za weryfikacją signature kodu w XNU. Potrafi też sprawdzać entitlements i obsługiwać inne wrażliwe zadania, takie jak zezwalanie na debugowanie lub uzyskiwanie task ports.

Ponadto, dla niektórych operacji kext woli kontaktować się z działającym w user space demonem `/usr/libexec/amfid`. Ta relacja zaufania była nadużywana w kilku jailbreaks.

W nowszych wersjach macOS AMFI nie jest już wygodnie dostępne jako samodzielny kext na dysku, więc reverse zwykle oznacza pracę z **kernelcache** albo **KDK** zamiast przeglądania `/System/Library/Extensions`.

AMFI używa polityk **MACF** i rejestruje swoje hooki w momencie uruchomienia. Ponadto zablokowanie jego ładowania lub jego usunięcie może wywołać kernel panic. Istnieją jednak pewne boot arguments, które pozwalają osłabić AMFI:

- `amfi_unrestricted_task_for_pid`: Pozwala na task_for_pid bez wymaganych entitlements
- `amfi_allow_any_signature`: Pozwala na dowolny code signature
- `cs_enforcement_disable`: Argument systemowy używany do wyłączenia egzekwowania code signing
- `amfi_prevent_old_entitled_platform_binaries`: Unieważnia platform binaries z entitlements
- `amfi_get_out_of_my_way`: Całkowicie wyłącza amfi

To są niektóre z polityk MACF, które rejestruje:

- **`cred_check_label_update_execve:`** Aktualizacja etykiety zostanie wykonana i zwróci 1
- **`cred_label_associate`**: Aktualizuje slot mac label AMFI etykietą
- **`cred_label_destroy`**: Usuwa slot mac label AMFI
- **`cred_label_init`**: Ustawia 0 w slocie mac label AMFI
- **`cred_label_update_execve`:** Sprawdza entitlements procesu, aby zobaczyć, czy powinno mu być wolno modyfikować etykiety.
- **`file_check_mmap`:** Sprawdza, czy mmap pobiera pamięć i ustawia ją jako wykonywalną. W takim przypadku sprawdza, czy potrzebna jest library validation, a jeśli tak, wywołuje funkcję library validation.
- **`file_check_library_validation`**: Wywołuje funkcję library validation, która sprawdza m.in., czy platform binary ładuje inny platform binary albo czy proces i nowo załadowany plik mają ten sam TeamID. Niektóre entitlements również pozwalają ładować dowolną bibliotekę.
- **`policy_initbsd`**: Konfiguruje zaufane klucze NVRAM
- **`policy_syscall`**: Sprawdza polityki DYLD, np. czy binary ma unrestricted segments, czy powinno zezwalać na zmienne środowiskowe... jest to także wywoływane, gdy proces jest uruchamiany przez `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Sprawdza, czy gdy proces wykonuje nowy binary, inne procesy z prawami SEND do task port procesu powinny je zachować czy nie. Platform binaries są dozwolone, entitlement `get-task-allow` na to pozwala, entitlements `task_for_pid-allow` są dozwolone oraz binary z tym samym TeamID.
- **`proc_check_expose_task`**: egzekwuje entitlements
- **`amfi_exc_action_check_exception_send`**: Wysyłana jest wiadomość exception do debuggera
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Cykl życia etykiety podczas obsługi exception (debugging)
- **`proc_check_get_task`**: Sprawdza entitlements takie jak `get-task-allow`, które pozwala innym procesom uzyskać task port, oraz `task_for_pid-allow`, które pozwala procesowi uzyskiwać task porty innych procesów. Jeśli nie ma żadnego z nich, przechodzi do `amfid permitunrestricteddebugging`, aby sprawdzić, czy jest to dozwolone.
- **`proc_check_mprotect`**: Odmawia, jeśli `mprotect` jest wywołane z flagą `VM_PROT_TRUSTED`, która wskazuje, że obszar musi być traktowany tak, jakby miał prawidłowy code signature.
- **`vnode_check_exec`**: Jest wywoływane, gdy wykonywalne pliki są ładowane do pamięci i ustawia `cs_hard | cs_kill`, co zabije proces, jeśli którakolwiek ze stron becomes invalid
- **`vnode_check_getextattr`**: MacOS: Sprawdza `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Jak get + `com.apple.private.allow-bless` oraz entitlement `internal-installer-equivalent`
- **`vnode_check_signature`**: Kod, który wywołuje XNU, aby sprawdzić code signature przy użyciu entitlements, trust cache i `amfid`
- **`proc_check_run_cs_invalid`**: Przechwytuje wywołania `ptrace()` (`PT_ATTACH` i `PT_TRACE_ME`). Sprawdza entitlements `get-task-allow`, `run-invalid-allow` i `run-unsigned-code`, a jeśli nie ma żadnego z nich, sprawdza, czy debugging jest dozwolony.
- **`proc_check_map_anon`**: Jeśli `mmap` jest wywołane z flagą **`MAP_JIT`**, AMFI sprawdzi entitlement `dynamic-codesigning`.

`AMFI.kext` udostępnia też API dla innych rozszerzeń jądra i można znaleźć jego zależności za pomocą:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

To jest demon działający w trybie user mode, którego `AMFI.kext` używa do sprawdzania podpisów kodu w user mode.\
Aby `AMFI.kext` komunikował się z demonem, używa wiadomości mach przez port `HOST_AMFID_PORT`, który jest specjalnym portem `18`.

Zwróć uwagę, że w macOS nie jest już możliwe, aby procesy root przejmowały specjalne porty, ponieważ są chronione przez `SIP` i tylko launchd może je uzyskać. W iOS sprawdzane jest, czy proces odsyłający odpowiedź ma hardcoded CDHash `amfid`.

Można zobaczyć, kiedy `amfid` jest proszony o sprawdzenie binarki i jaka jest jego odpowiedź, debugując go i ustawiając breakpoint w `mach_msg`.

Gdy wiadomość zostanie odebrana przez specjalny port, do wysłania każdej funkcji do wywoływanej funkcji używany jest **MIG**. Główne funkcje zostały odwrócone i opisane wewnątrz książki.

### DYLD policy and library validation

Nowsze wersje `dyld` bardzo wcześnie wywołują `amfi_check_dyld_policy_self()` z `configureProcessRestrictions()`, aby zapytać AMFI, czy proces może używać zmiennych ścieżek `DYLD_*`, interposing, ścieżek fallback, osadzonych zmiennych lub tolerować nieudaną iniekcję biblioteki. Dlatego podczas triage powierzchni iniekcji nie wystarczy sprawdzić tylko komendy ładowania Mach-O: trzeba też sprawdzić entitlements i flagi runtime, które AMFI przetłumaczy na politykę `dyld`.

Praktyczna pętla triage to:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Na nowoczesnym macOS wiele binarek Apple nie zawiera już bezpośrednio `com.apple.security.cs.disable-library-validation`, a zamiast tego korzysta z `com.apple.private.security.clear-library-validation`. W takim przypadku library validation nie jest wyłączane w czasie `execve`: proces musi wywołać `csops(..., CS_OPS_CLEAR_LV, ...)` na samym sobie, a XNU pozwala na tę operację tylko dla procesu wywołującego, gdy obecny jest odpowiedni entitlement. Z ofensywnego punktu widzenia ma to znaczenie, ponieważ cel może stać się podatny na injekcję dopiero **po** osiągnięciu ścieżki kodu, która jawnie czyści LV (na przykład tuż przed załadowaniem opcjonalnych pluginów).

## Provisioning Profiles

Provisioning profile może być użyty do podpisywania code. Istnieją profile **Developer**, których można użyć do podpisywania code i testowania go, oraz profile **Enterprise**, które mogą być używane na wszystkich urządzeniach.

Po przesłaniu App do Apple Store, jeśli zostanie zatwierdzona, jest podpisywana przez Apple i provisioning profile nie jest już potrzebny.

Profil zwykle używa rozszerzenia `.mobileprovision` lub `.provisionprofile` i można go zrzucić za pomocą:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Chociaż czasem określane jako certificated, te provisioning profiles zawierają więcej niż certyfikat:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: Oznacza to jako Apple Internal profile
- **ApplicationIdentifierPrefix**: Dodawany przed AppIDName (tak samo jak TeamIdentifier)
- **CreationDate**: Data w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Tablica (zwykle jednego) certificate(s), zakodowanych jako Base64 data
- **Entitlements**: Entitlements dozwolone z entitlements dla tego profilu
- **ExpirationDate**: Data wygaśnięcia w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Application Name, taka sama jak AppIDName
- **ProvisionedDevices**: Tablica (dla developer certificates) UDIDs, dla których ten profil jest ważny
- **ProvisionsAllDevices**: Wartość logiczna (true dla enterprise certificates)
- **TeamIdentifier**: Tablica (zwykle jednego) alfanumerycznego string(s) używanego do identyfikacji developera do celów inter-app interaction
- **TeamName**: Czytelna dla człowieka nazwa używana do identyfikacji developera
- **TimeToLive**: Ważność (w dniach) certificate
- **UUID**: Universally Unique Identifier dla tego profilu
- **Version**: Obecnie ustawione na 1

Zwróć uwagę, że wpis entitlements będzie zawierał ograniczony zestaw entitlements, a provisioning profile będzie mógł nadać tylko te konkretne entitlements, aby zapobiec przyznawaniu prywatnych entitlements Apple.

Zwróć uwagę, że profiles zwykle znajdują się w `/var/MobileDeviceProvisioningProfiles` i można je sprawdzić za pomocą **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

To jest zewnętrzna biblioteka, którą wywołuje `amfid`, aby zapytać, czy powinien coś zezwolić, czy nie. Historycznie była nadużywana w jailbreaking poprzez uruchamianie backdoored wersji, która pozwalała na wszystko.

W macOS znajduje się to w `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches to nie tylko koncepcja iOS. Na nowoczesnym macOS, szczególnie na **Apple silicon**, static trust cache i loadable trust caches są częścią Secure Boot chain. Gdy **CodeDirectory hash** Mach-O znajduje się tam, AMFI może nadać mu **platform privilege** bez wykonywania dalszych authenticity checks podczas launch time. Oznacza to też, że Apple może przypiąć platform binaries do konkretnej wersji OS i uniemożliwić odtwarzanie starszych binaries podpisanych przez Apple na nowszych systemach.

W nowszych wersjach macOS metadata trust-cache jest również powiązana z **launch constraints**, więc skopiowane system apps i binaries uruchamiane z niewłaściwego parent/location mogą zostać odrzucone przez AMFI, nawet jeśli nadal są podpisane przez Apple. Szczegółowy workflow extraction i reversing jest opisany w:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

W iOS i badaniach jailbreak nadal można znaleźć tradycyjny model **loadable trust caches** używany do whitelistowania ad-hoc signed binaries.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
