# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Skupia się na egzekwowaniu integralności kodu uruchamianego w systemie, dostarczając logikę stojącą za weryfikacją podpisu kodu w XNU. Potrafi też sprawdzać entitlements i obsługiwać inne wrażliwe zadania, takie jak zezwalanie na debugowanie lub uzyskiwanie portów task.

Ponadto, w przypadku niektórych operacji kext woli kontaktować się z daemon działającym w user space `/usr/libexec/amfid`. Ta relacja zaufania została nadużyta w kilku jailbreaks.

W nowszych wersjach macOS AMFI nie jest już wygodnie dostępne jako samodzielny kext na dysku, więc reverse zwykle oznacza pracę z **kernelcache** albo **KDK** zamiast przeglądania `/System/Library/Extensions`.

AMFI używa polityk **MACF** i rejestruje swoje hooki w momencie uruchomienia. Ponadto uniemożliwienie jego załadowania lub jego unload może wywołać kernel panic. Istnieją jednak pewne boot arguments, które pozwalają osłabić AMFI:

- `amfi_unrestricted_task_for_pid`: Zezwala na task_for_pid bez wymaganych entitlements
- `amfi_allow_any_signature`: Zezwala na dowolny code signature
- `cs_enforcement_disable`: Systemowy argument używany do wyłączenia egzekwowania code signing
- `amfi_prevent_old_entitled_platform_binaries`: Unieważnia platform binaries z entitlements
- `amfi_get_out_of_my_way`: Całkowicie wyłącza amfi

Oto niektóre z polityk MACF, które rejestruje:

- **`cred_check_label_update_execve:`** Aktualizacja etykiety zostanie wykonana i zwróci 1
- **`cred_label_associate`**: Aktualizuje slot mac label AMFI etykietą
- **`cred_label_destroy`**: Usuwa slot mac label AMFI
- **`cred_label_init`**: Ustawia 0 w slocie mac label AMFI
- **`cred_label_update_execve`:** Sprawdza entitlements procesu, aby ocenić, czy powinien mieć अनुमति na modyfikację etykiet.
- **`file_check_mmap`:** Sprawdza, czy mmap uzyskuje pamięć i ustawia ją jako executable. W takim przypadku sprawdza, czy potrzebna jest library validation, a jeśli tak, wywołuje funkcję library validation.
- **`file_check_library_validation`**: Wywołuje funkcję library validation, która sprawdza między innymi, czy platform binary ładuje inny platform binary albo czy proces i nowo załadowany plik mają ten sam TeamID. Pewne entitlements pozwolą też na załadowanie dowolnej biblioteki.
- **`policy_initbsd`**: Konfiguruje zaufane klucze NVRAM
- **`policy_syscall`**: Sprawdza polityki DYLD, takie jak to, czy binary ma unrestricted segments, czy powinien zezwalać na env vars... jest to także wywoływane, gdy proces jest uruchamiany przez `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Sprawdza, czy gdy proces wykonuje nowy binary, inne procesy z uprawnieniami SEND do task port tego procesu powinny je zachować czy nie. Platform binaries są dozwolone, entitlement `get-task-allow` to umożliwia, entitlements `task_for_pid-allow` są dozwolone oraz binaries z tym samym TeamID.
- **`proc_check_expose_task`**: egzekwuje entitlements
- **`amfi_exc_action_check_exception_send`**: Message exception jest wysyłany do debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Cykl życia etykiety podczas obsługi exception (debugging)
- **`proc_check_get_task`**: Sprawdza entitlements takie jak `get-task-allow`, które pozwala innym procesom uzyskać port task, oraz `task_for_pid-allow`, które pozwalają procesowi uzyskiwać porty task innych procesów. Jeśli żaden z nich nie występuje, wywołuje `amfid permitunrestricteddebugging`, aby sprawdzić, czy jest to dozwolone.
- **`proc_check_mprotect`**: Odmawia, jeśli `mprotect` jest wywoływane z flagą `VM_PROT_TRUSTED`, która wskazuje, że region musi być traktowany tak, jakby miał prawidłowy code signature.
- **`vnode_check_exec`**: Wywoływane, gdy executable files są ładowane do pamięci, i ustawia `cs_hard | cs_kill`, co zabije proces, jeśli którakolwiek ze stron stanie się nieprawidłowa
- **`vnode_check_getextattr`**: MacOS: Sprawdza `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Jak get + `com.apple.private.allow-bless` oraz entitlement `internal-installer-equivalent`
- **`vnode_check_signature`**: Kod, który wywołuje XNU, aby sprawdzić code signature używając entitlements, trust cache i `amfid`
- **`proc_check_run_cs_invalid`**: Przechwytuje wywołania `ptrace()` (`PT_ATTACH` i `PT_TRACE_ME`). Sprawdza entitlements `get-task-allow`, `run-invalid-allow` i `run-unsigned-code`, a jeśli żadnego nie ma, sprawdza, czy debugging jest dozwolony.
- **`proc_check_map_anon`**: Jeśli `mmap` jest wywoływane z flagą **`MAP_JIT`**, AMFI sprawdzi entitlement `dynamic-codesigning`.

`AMFI.kext` udostępnia też API dla innych rozszerzeń kernel i możliwe jest znalezienie jego zależności za pomocą:
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

To jest daemon działający w trybie user mode, z którego `AMFI.kext` korzysta do sprawdzania podpisów kodu w user mode.\
Aby `AMFI.kext` mógł komunikować się z daemonem, używa wiadomości mach przez port `HOST_AMFID_PORT`, który jest specjalnym portem `18`.

Zwróć uwagę, że w macOS nie jest już możliwe, aby procesy root przejmowały specjalne porty, ponieważ są chronione przez `SIP` i tylko `launchd` może je dostać. W iOS sprawdzane jest, czy proces odsyłający odpowiedź ma hardcoded CDHash `amfid`.

Można zobaczyć, kiedy `amfid` jest proszony o sprawdzenie binarki i jaka jest jego odpowiedź, debugując go i ustawiając breakpoint w `mach_msg`.

Gdy wiadomość zostanie odebrana przez specjalny port, używany jest **MIG** do przekazania każdej funkcji do funkcji, którą wywołuje. Główne funkcje zostały odwrócone i wyjaśnione wewnątrz książki.

### DYLD policy and library validation

Nowsze wersje `dyld` bardzo wcześnie wywołują `amfi_check_dyld_policy_self()` z `configureProcessRestrictions()`, aby zapytać AMFI, czy proces może używać zmiennych ścieżek `DYLD_*`, interposing, fallback paths, embedded variables albo tolerować nieudaną insercję biblioteki. Dlatego podczas triage powierzchni injection samo sprawdzenie load commands Mach-O nie wystarcza: trzeba też sprawdzić entitlements i flagi runtime, które AMFI przetłumaczy na `dyld` policy.

Praktyczna pętla triage to:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Na nowoczesnym macOS wiele binarek Apple nie zawiera już bezpośrednio `com.apple.security.cs.disable-library-validation`, tylko zamiast tego używa `com.apple.private.security.clear-library-validation`. W takim przypadku library validation nie jest wyłączane w czasie `execve`: proces musi wywołać `csops(..., CS_OPS_CLEAR_LV, ...)` na samym sobie, a XNU zezwala na tę operację tylko na proces wywołujący, gdy entitlement jest obecny. Z ofensywnego punktu widzenia ma to znaczenie, ponieważ target może stać się injectable dopiero **po** wejściu w ścieżkę kodu, która jawnie czyści LV (na przykład tuż przed załadowaniem opcjonalnych plugins).

## Provisioning Profiles

Provisioning profile może być używany do podpisywania code. Istnieją profile **Developer**, które można użyć do podpisywania code i testowania go, oraz profile **Enterprise**, które mogą być używane na wszystkich urządzeniach.

Po przesłaniu App do Apple Store, jeśli zostanie zatwierdzona, jest podpisywana przez Apple i provisioning profile nie jest już potrzebny.

Profile zwykle używają rozszerzenia `.mobileprovision` lub `.provisionprofile` i można je zrzucić za pomocą:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Chociaż czasami nazywane certificated, te provisioning profiles mają więcej niż certyfikat:

- **AppIDName:** Identyfikator aplikacji
- **AppleInternalProfile**: Oznacza to jako Apple Internal profile
- **ApplicationIdentifierPrefix**: Dodawane przed AppIDName (tak samo jak TeamIdentifier)
- **CreationDate**: Data w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Tablica (zwykle jednego) certificate(s), zakodowanych jako dane Base64
- **Entitlements**: Dozwolone entitlements wraz z entitlements dla tego profilu
- **ExpirationDate**: Data wygaśnięcia w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Nazwa aplikacji, taka sama jak AppIDName
- **ProvisionedDevices**: Tablica (dla developer certificates) UDID-ów, dla których ten profil jest ważny
- **ProvisionsAllDevices**: Wartość logiczna (true dla enterprise certificates)
- **TeamIdentifier**: Tablica (zwykle jednego) alfanumerycznego string(s) używanego do identyfikacji developera na potrzeby inter-app interaction
- **TeamName**: Czytelna dla człowieka nazwa używana do identyfikacji developera
- **TimeToLive**: Ważność (w dniach) certyfikatu
- **UUID**: Universally Unique Identifier dla tego profilu
- **Version**: Obecnie ustawione na 1

Zwróć uwagę, że wpis entitlements będzie zawierał ograniczony zestaw entitlements i provisioning profile będzie mógł przyznać tylko te konkretne entitlements, aby zapobiec nadawaniu prywatnych entitlements Apple.

Zwróć uwagę, że profiles zwykle znajdują się w `/var/MobileDeviceProvisioningProfiles` i można je sprawdzić za pomocą **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

To jest zewnętrzna biblioteka, którą wywołuje `amfid`, aby zapytać, czy powinien coś dopuścić, czy nie. Historycznie było to nadużywane w jailbreaking przez uruchamianie backdoored wersji, która pozwalałaby na wszystko.

W macOS znajduje się to w `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches to nie tylko pojęcie z iOS. Na nowoczesnym macOS, zwłaszcza na **Apple silicon**, static trust cache i loadable trust caches są częścią łańcucha Secure Boot. Gdy **CodeDirectory hash** Mach-O znajduje się w nich, AMFI może przyznać mu **platform privilege** bez wykonywania dalszych sprawdzeń autentyczności przy uruchomieniu. Oznacza to też, że Apple może zablokować platform binaries do konkretnej wersji OS i uniemożliwić odtwarzanie starszych Apple-signed binaries na nowszych systemach.

W nowszych wydaniach macOS metadane trust-cache są również powiązane z **launch constraints**, więc skopiowane system apps i binaries uruchamiane z niewłaściwego parent/location mogą zostać odrzucone przez AMFI, nawet jeśli nadal są Apple-signed. Szczegółowy workflow ekstrakcji i analizy jest opisany w:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

W badaniach nad iOS i jailbreaking nadal można znaleźć tradycyjny model **loadable trust caches** używany do whitelistowania ad-hoc signed binaries.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
