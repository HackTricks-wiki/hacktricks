# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext i amfid

Koncentruje się na egzekwowaniu integralności kodu uruchomionego w systemie, zapewniając logikę stojącą za weryfikacją podpisów kodu XNU. Może również sprawdzać entitlements i obsługiwać inne wrażliwe zadania, takie jak zezwalanie na debugging lub uzyskiwanie task ports.

Ponadto w przypadku niektórych operacji kext preferuje kontakt z daemonem działającym w user space: `/usr/libexec/amfid`. Ta relacja zaufania była wykorzystywana w kilku jailbreakach.

W nowszych wersjach macOS AMFI nie jest już wygodnie dostępne jako samodzielny kext na dysku, dlatego reverse engineering zwykle oznacza pracę z **kernelcache** lub **KDK**, zamiast przeglądania `/System/Library/Extensions`.

AMFI używa polityk **MACF** i rejestruje swoje hooki w momencie uruchomienia. Uniemożliwienie jego załadowania lub jego wyładowanie może również wywołać kernel panic. Istnieją jednak argumenty boot, które pozwalają osłabić działanie AMFI:

- `amfi_unrestricted_task_for_pid`: Zezwala na użycie task_for_pid bez wymaganych entitlements
- `amfi_allow_any_signature`: Zezwala na dowolny podpis kodu
- `cs_enforcement_disable`: Argument systemowy używany do wyłączenia egzekwowania podpisywania kodu
- `amfi_prevent_old_entitled_platform_binaries`: Unieważnia platform binaries posiadające entitlements
- `amfi_get_out_of_my_way`: Całkowicie wyłącza amfi

Oto niektóre z rejestrowanych przez niego polityk MACF:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Aktualizacja etykiety zostanie wykonana i zwróci wartość 1
- **`cred_label_associate`**: Aktualizuje slot mac label AMFI etykietą
- **`cred_label_destroy`**: Usuwa slot mac label AMFI
- **`cred_label_init`**: Umieszcza wartość 0 w slocie mac label AMFI
- **`cred_label_update_execve`:** Sprawdza entitlements procesu, aby określić, czy powinien on mieć możliwość modyfikowania etykiet.
- **`file_check_mmap`:** Sprawdza, czy mmap pozyskuje pamięć i ustawia ją jako wykonywalną. W takim przypadku sprawdza, czy wymagana jest library validation, a jeśli tak, wywołuje funkcję library validation.
- **`file_check_library_validation`**: Wywołuje funkcję library validation, która sprawdza między innymi, czy platform binary ładuje inną platform binary albo czy proces i nowo załadowany plik mają ten sam TeamID. Określone entitlements pozwalają również na załadowanie dowolnej biblioteki.
- **`policy_initbsd`**: Konfiguruje zaufane klucze NVRAM
- **`policy_syscall`**: Sprawdza polityki DYLD, takie jak to, czy binary ma unrestricted segments oraz czy powinien zezwalać na env vars... Jest również wywoływana, gdy proces jest uruchamiany za pomocą `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Sprawdza, czy gdy proces wykonuje nowy binary, inne procesy posiadające prawa SEND do task port procesu powinny je zachować. Platform binaries mają na to zezwolenie, entitlement `get-task-allow` na to pozwala, entitlements `task_for_pid-allow` są dozwolone, podobnie jak binaries z tym samym TeamID.
- **`proc_check_expose_task`**: Egzekwuje entitlements
- **`amfi_exc_action_check_exception_send`**: Wiadomość wyjątku jest wysyłana do debuggera
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Cykl życia etykiety podczas obsługi wyjątków (debugging)
- **`proc_check_get_task`**: Sprawdza entitlements, takie jak `get-task-allow`, które pozwala innym procesom uzyskać task port procesu, oraz `task_for_pid-allow`, które pozwala procesowi uzyskać task porty innych procesów. Jeśli żaden z nich nie występuje, wywołuje `amfid permitunrestricteddebugging`, aby sprawdzić, czy jest to dozwolone.
- **`proc_check_mprotect`**: Odmawia, jeśli `mprotect` zostanie wywołane z flagą `VM_PROT_TRUSTED`, która wskazuje, że region powinien być traktowany tak, jakby posiadał prawidłowy podpis kodu.
- **`vnode_check_exec`**: Jest wywoływana podczas ładowania plików wykonywalnych do pamięci i ustawia `cs_hard | cs_kill`, co zakończy proces, jeśli którakolwiek ze stron stanie się nieprawidłowa<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Sprawdza `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Tak jak get + entitlement `com.apple.private.allow-bless` i `internal-installer-equivalent`
- **`vnode_check_signature`**: Kod, który wywołuje XNU w celu sprawdzenia podpisu kodu przy użyciu entitlements, trust cache i `amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Przechwytuje wywołania `ptrace()` (`PT_ATTACH` i `PT_TRACE_ME`). Sprawdza, czy występuje którykolwiek z entitlements `get-task-allow`, `run-invalid-allow` lub `run-unsigned-code`, a jeśli nie, sprawdza, czy debugging jest dozwolony.
- **`proc_check_map_anon`**: Jeśli mmap zostanie wywołany z flagą **`MAP_JIT`**, AMFI sprawdzi entitlement `dynamic-codesigning`.

`AMFI.kext` udostępnia również API dla innych rozszerzeń kernela i można znaleźć jego zależności za pomocą:
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

Jest to daemon działający w trybie użytkownika, którego `AMFI.kext` używa do sprawdzania podpisów kodu w trybie użytkownika.\
Aby `AMFI.kext` mógł komunikować się z daemonem, używa komunikatów mach przesyłanych przez port `HOST_AMFID_PORT`, którym jest specjalny port `18`.

Należy pamiętać, że w macOS procesy root nie mogą już przejmować specjalnych portów, ponieważ są one chronione przez `SIP` i tylko launchd może uzyskać do nich dostęp. W iOS sprawdzane jest, czy proces wysyłający odpowiedź ma zahardkodowany CDHash procesu `amfid`.

Można obserwować, kiedy `amfid` otrzymuje żądanie sprawdzenia pliku binarnego oraz jego odpowiedź, debugując go i ustawiając breakpoint w `mach_msg`.

Po odebraniu komunikatu przez specjalny port używany jest **MIG**, aby przekazać każdą funkcję do funkcji, którą wywołuje. Główne funkcje zostały odwrócone i wyjaśnione w książce.

### DYLD policy and library validation

Nowsze wersje `dyld` bardzo wcześnie wywołują `amfi_check_dyld_policy_self()` z `configureProcessRestrictions()`, aby zapytać AMFI, czy proces może używać zmiennych ścieżek `DYLD_*`, interposing, fallback paths, embedded variables lub tolerować nieudane wstawianie bibliotek. Dlatego podczas triage powierzchni injection nie wystarczy sprawdzić wyłącznie Mach-O load commands: trzeba również sprawdzić entitlements i runtime flags, które AMFI przekształci w `dyld` policy.

Praktyczna pętla triage wygląda następująco:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Na współczesnym macOS wiele binariów Apple nie zawiera już bezpośrednio `com.apple.security.cs.disable-library-validation`, lecz zamiast tego korzysta z `com.apple.private.security.clear-library-validation`. W takim przypadku library validation nie jest wyłączane w czasie `execve`: proces musi wywołać `csops(..., CS_OPS_CLEAR_LV, ...)` na sobie, a XNU zezwala na tę operację dla procesu wywołującego tylko wtedy, gdy obecny jest entitlement. Z perspektywy ofensywnej ma to znaczenie, ponieważ cel może stać się podatny na code injection dopiero po osiągnięciu ścieżki kodu, która jawnie wyłącza LV (na przykład krótko przed załadowaniem opcjonalnych pluginów).<sup>[[4]](#references)[[5]](#references)</sup>

## Profile provisioningowe

Profil provisioningowy może służyć do podpisywania kodu. Istnieją profile **Developer**, których można używać do podpisywania kodu i jego testowania, oraz profile **Enterprise**, których można używać na wszystkich urządzeniach.

Po przesłaniu aplikacji do Apple Store, jeśli zostanie zaakceptowana, jest podpisywana przez Apple, a profil provisioningowy nie jest już potrzebny.

Profil zwykle używa rozszerzenia `.mobileprovision` lub `.provisionprofile` i można go zrzucić za pomocą:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Chociaż czasami określa się je jako certyfikowane, te provisioning profiles zawierają więcej niż tylko certyfikat:

- **AppIDName:** Identyfikator aplikacji
- **AppleInternalProfile**: Oznacza profil wewnętrzny Apple
- **ApplicationIdentifierPrefix**: Dodawany przed AppIDName (taki sam jak TeamIdentifier)
- **CreationDate**: Data w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Tablica zawierająca (zwykle jeden) certyfikat(y), zakodowane jako dane Base64
- **Entitlements**: entitlements dozwolone dla tego profilu
- **ExpirationDate**: Data wygaśnięcia w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Nazwa aplikacji, taka sama jak AppIDName
- **ProvisionedDevices**: Tablica (dla certyfikatów deweloperskich) UDID-ów, dla których ten profil jest ważny
- **ProvisionsAllDevices**: Wartość logiczna (true dla certyfikatów enterprise)
- **TeamIdentifier**: Tablica zawierająca (zwykle jeden) ciąg alfanumeryczny używany do identyfikowania dewelopera na potrzeby interakcji między aplikacjami
- **TeamName**: Czytelna dla człowieka nazwa używana do identyfikowania dewelopera
- **TimeToLive**: Ważność certyfikatu (w dniach)
- **UUID**: Uniwersalnie unikatowy identyfikator tego profilu
- **Version**: Obecnie ustawione na 1

Należy pamiętać, że wpis entitlements będzie zawierał ograniczony zestaw entitlements, a provisioning profile będzie mógł nadać tylko te konkretne entitlements, aby uniemożliwić nadawanie prywatnych entitlements Apple.

Profile zwykle znajdują się w `/var/MobileDeviceProvisioningProfiles` i można je sprawdzić za pomocą **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

To zewnętrzna biblioteka, którą `amfid` wywołuje, aby sprawdzić, czy powinien coś zezwolić, czy nie. Historycznie była nadużywana w jailbreaking poprzez uruchamianie jej zmodyfikowanej wersji, która zezwalała na wszystko.

W macOS znajduje się ona wewnątrz `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches nie są koncepcją ograniczoną wyłącznie do iOS. We współczesnym macOS, szczególnie na **Apple silicon**, statyczny trust cache oraz loadable trust caches stanowią część łańcucha Secure Boot. Gdy znajduje się w nich **hash CodeDirectory** pliku Mach-O, AMFI może nadać mu **platform privilege** bez wykonywania dodatkowych kontroli autentyczności podczas uruchamiania. Oznacza to również, że Apple może przypisać pliki binarne platformy do konkretnej wersji systemu operacyjnego i uniemożliwić ponowne użycie starszych plików binarnych podpisanych przez Apple w nowszych systemach.<sup>[[6]](#references)</sup>

W nowszych wydaniach macOS metadane trust cache są również powiązane z **launch constraints**, dlatego skopiowane aplikacje systemowe i pliki binarne uruchomione z niewłaściwego procesu nadrzędnego/lokalizacji mogą zostać odrzucone przez AMFI, nawet jeśli nadal są podpisane przez Apple. Szczegółowy proces ekstrakcji i reverse engineeringu opisano tutaj:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

W badaniach iOS oraz jailbreak nadal można znaleźć tradycyjny model **loadable trust caches** używanych do tworzenia whitelisty dla plików binarnych podpisanych ad hoc.

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
