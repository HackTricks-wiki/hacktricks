# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Skupia się na wymuszaniu integralności kodu działającego w systemie, dostarczając logikę stojącą za weryfikacją code signature w XNU. Potrafi też sprawdzać entitlements i obsługiwać inne wrażliwe zadania, takie jak zezwalanie na debugowanie albo uzyskiwanie task ports.

Ponadto, przy niektórych operacjach kext woli kontaktować się z demonem działającym w user space `/usr/libexec/amfid`. Ta relacja zaufania była nadużywana w kilku jailbreaks.

W nowszych wersjach macOS AMFI nie jest już wygodnie dostępne jako samodzielny kext na dysku, więc reverse zwykle oznacza pracę z **kernelcache** albo **KDK** zamiast przeglądania `/System/Library/Extensions`.

AMFI używa polityk **MACF** i rejestruje swoje hooki w momencie uruchomienia. Również uniemożliwienie jego załadowania albo jego usunięcie może wywołać kernel panic. Istnieją jednak pewne boot arguments, które pozwalają osłabić AMFI:

- `amfi_unrestricted_task_for_pid`: Pozwala na task_for_pid bez wymaganych entitlements
- `amfi_allow_any_signature`: Zezwala na dowolny code signature
- `cs_enforcement_disable`: Argument systemowy używany do wyłączenia egzekwowania code signing
- `amfi_prevent_old_entitled_platform_binaries`: Unieważnia platform binaries z entitlements
- `amfi_get_out_of_my_way`: Całkowicie wyłącza amfi

To są niektóre z polityk MACF, które rejestruje:

- **`cred_check_label_update_execve:`** Aktualizacja etykiety zostanie wykonana i zwróci 1
- **`cred_label_associate`**: Aktualizuje slot mac label AMFI etykietą
- **`cred_label_destroy`**: Usuwa slot mac label AMFI
- **`cred_label_init`**: Ustawia 0 w slocie mac label AMFI
- **`cred_label_update_execve`:** Sprawdza entitlements procesu, aby zobaczyć, czy powinien mieć اجازه na modyfikację etykiet.
- **`file_check_mmap`:** Sprawdza, czy mmap pobiera pamięć i ustawia ją jako wykonywalną. W takim przypadku sprawdza, czy potrzebna jest library validation, a jeśli tak, wywołuje funkcję library validation.
- **`file_check_library_validation`**: Wywołuje funkcję library validation, która sprawdza między innymi, czy platform binary ładuje inny platform binary albo czy proces i nowo załadowany plik mają ten sam TeamID. Niektóre entitlements również pozwolą załadować dowolną bibliotekę.
- **`policy_initbsd`**: Konfiguruje zaufane klucze NVRAM
- **`policy_syscall`**: Sprawdza polityki DYLD, na przykład czy binary ma unrestricted segments, czy powinien pozwalać na env vars... jest to też wywoływane, gdy proces jest uruchamiany przez `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Sprawdza, czy gdy proces wykonuje nowy binary, inne procesy z prawami SEND do task portu procesu powinny je zachować czy nie. Platform binaries są dozwolone, entitlement `get-task-allow` na to pozwala, entitlements `task_for_pid-allow` są dozwolone oraz binaries z tym samym TeamID.
- **`proc_check_expose_task`**: Wymusza entitlements
- **`amfi_exc_action_check_exception_send`**: Wiadomość exception jest wysyłana do debuggera
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Cykl życia etykiety podczas obsługi exception (debugging)
- **`proc_check_get_task`**: Sprawdza entitlements takie jak `get-task-allow`, które pozwala innym procesom uzyskać port taska, oraz `task_for_pid-allow`, które pozwala procesowi uzyskiwać porty tasków innych procesów. Jeśli nie ma żadnego z nich, wywołuje `amfid permitunrestricteddebugging`, aby sprawdzić, czy jest to dozwolone.
- **`proc_check_mprotect`**: Odrzuca, jeśli `mprotect` jest wywołane z flagą `VM_PROT_TRUSTED`, która wskazuje, że region musi być traktowany tak, jakby miał prawidłowy code signature.
- **`vnode_check_exec`**: Wywoływane, gdy pliki wykonywalne są ładowane do pamięci, i ustawia `cs_hard | cs_kill`, co zabije proces, jeśli którakolwiek ze stron stanie się nieprawidłowa
- **`vnode_check_getextattr`**: MacOS: Sprawdza `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Jak get + `com.apple.private.allow-bless` oraz internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Kod, który wywołuje XNU, aby sprawdzić code signature przy użyciu entitlements, trust cache i `amfid`
- **`proc_check_run_cs_invalid`**: Przechwytuje wywołania `ptrace()` (`PT_ATTACH` i `PT_TRACE_ME`). Sprawdza entitlements `get-task-allow`, `run-invalid-allow` i `run-unsigned-code`, a jeśli żadnego nie ma, sprawdza, czy debugging jest dozwolony.
- **`proc_check_map_anon`**: Jeśli `mmap` jest wywołane z flagą **`MAP_JIT`**, AMFI sprawdzi entitlement `dynamic-codesigning`.

`AMFI.kext` udostępnia też API dla innych kernel extensions i można znaleźć jego zależności za pomocą:
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

To demon demon uruchamiany w trybie użytkownika, którego `AMFI.kext` użyje do sprawdzania podpisów kodu w trybie użytkownika.\
Aby `AMFI.kext` mógł komunikować się z demonem, używa komunikatów mach przez port `HOST_AMFID_PORT`, który jest specjalnym portem `18`.

Zwróć uwagę, że w macOS nie jest już możliwe, aby procesy root przejmowały specjalne porty, ponieważ są chronione przez `SIP` i tylko launchd może je otrzymać. W iOS sprawdzane jest, czy proces wysyłający odpowiedź ma zakodowany na stałe CDHash `amfid`.

Możliwe jest zobaczenie, kiedy `amfid` zostaje poproszony o sprawdzenie binarki, oraz jego odpowiedzi, poprzez debugowanie go i ustawienie breakpointu w `mach_msg`.

Gdy wiadomość zostanie odebrana przez specjalny port, używany jest **MIG** do przekazania każdej funkcji do funkcji, którą wywołuje. Główne funkcje zostały zreverse-engineerowane i wyjaśnione w książce.

### DYLD policy and library validation

Nowsze wersje `dyld` bardzo wcześnie wywołują `amfi_check_dyld_policy_self()` z `configureProcessRestrictions()`, aby zapytać AMFI, czy proces może używać zmiennych ścieżek `DYLD_*`, interposing, fallback paths, embedded variables albo tolerować nieudaną bibliotekę insertion. Dlatego podczas triage powierzchni injection nie wystarczy sprawdzić tylko komendy load Mach-O: trzeba też sprawdzić entitlements oraz flagi runtime, które AMFI przetłumaczy na politykę `dyld`.

Praktyczna pętla triage to:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Na nowoczesnym macOS wiele binarek Apple nie zawiera już bezpośrednio `com.apple.security.cs.disable-library-validation`, a zamiast tego używa `com.apple.private.security.clear-library-validation`. W takim przypadku library validation nie jest wyłączane w czasie `execve`: proces musi wywołać `csops(..., CS_OPS_CLEAR_LV, ...)` na samym sobie, a XNU pozwala na tę operację tylko na proces wywołujący, gdy obecny jest entitlement. Z ofensywnego punktu widzenia ma to znaczenie, ponieważ cel może stać się podatny na inject tylko **po** wejściu w ścieżkę kodu, która explicite czyści LV (na przykład tuż przed załadowaniem opcjonalnych pluginów).

## Provisioning Profiles

Provisioning profile może być używany do podpisywania code. Istnieją profile **Developer**, których można użyć do podpisywania code i testowania go, oraz profile **Enterprise**, których można używać na wszystkich devices.

Po przesłaniu App do Apple Store, jeśli zostanie zatwierdzona, jest podpisywana przez Apple i provisioning profile nie jest już potrzebny.

Profile zwykle używa rozszerzenia `.mobileprovision` lub `.provisionprofile` i można go zrzucić za pomocą:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Choć czasami określane jako certificated, te provisioning profiles mają więcej niż tylko certificate:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: Oznacza to jako Apple Internal profile
- **ApplicationIdentifierPrefix**: Dodawane przed AppIDName (tak samo jak TeamIdentifier)
- **CreationDate**: Data w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Tablica (zwykle jednego) certificate(s), zakodowanych jako dane Base64
- **Entitlements**: entitlements dozwolone z entitlements dla tego profilu
- **ExpirationDate**: Data wygaśnięcia w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Application Name, taka sama jak AppIDName
- **ProvisionedDevices**: Tablica (dla developer certificates) UDID, dla których ten profil jest ważny
- **ProvisionsAllDevices**: Wartość logiczna (true dla enterprise certificates)
- **TeamIdentifier**: Tablica (zwykle jednego) alfanumerycznego string(s) używanego do identyfikacji developer do celów inter-app interaction
- **TeamName**: Czytelna dla człowieka nazwa używana do identyfikacji developer
- **TimeToLive**: Ważność (w dniach) certificate
- **UUID**: Universally Unique Identifier dla tego profilu
- **Version**: Obecnie ustawione na 1

Zwróć uwagę, że wpis entitlements będzie zawierał ograniczony zestaw entitlements, a provisioning profile będzie mógł nadać tylko te konkretne entitlements, aby zapobiec nadawaniu prywatnych entitlements Apple.

Zwróć uwagę, że profiles zwykle znajdują się w `/var/MobileDeviceProvisioningProfiles` i można je sprawdzić za pomocą **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

To jest zewnętrzna biblioteka, którą wywołuje `amfid`, aby zapytać, czy powinien coś dopuścić, czy nie. Historycznie było to nadużywane w jailbreaking przez uruchamianie zmodyfikowanej wersji z backdoor, która pozwalałaby na wszystko.

W macOS znajduje się to w `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches to nie tylko koncept iOS. We współczesnym macOS, szczególnie na **Apple silicon**, static trust cache i loadable trust caches są częścią łańcucha Secure Boot. Gdy **CodeDirectory hash** Mach-O jest tam obecny, AMFI może przyznać mu **platform privilege** bez wykonywania dodatkowych sprawdzeń autentyczności przy uruchomieniu. Oznacza to również, że Apple może zablokować platform binaries do konkretnej wersji OS i uniemożliwić odtwarzanie starszych binaries podpisanych przez Apple na nowszych systemach.

W nowszych wydaniach macOS metadane trust-cache są też powiązane z **launch constraints**, więc skopiowane system apps i binaries uruchamiane z niewłaściwego parent/location mogą zostać odrzucone przez AMFI, nawet jeśli nadal są podpisane przez Apple. Szczegółowy workflow ekstrakcji i reverse-engineeringu jest opisany w:

{{#ref}}
macos-launch-environment-constraints.md
{{endref}}

W badaniach nad iOS i jailbreak nadal spotkasz tradycyjny model **loadable trust caches** używany do whitelistowania binary signed ad-hoc.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
