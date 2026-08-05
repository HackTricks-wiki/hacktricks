# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Skupia się na egzekwowaniu integralności kodu uruchomionego w systemie, zapewniając logikę leżącą u podstaw weryfikacji podpisu kodu przez XNU. Potrafi również sprawdzać entitlements i obsługiwać inne wrażliwe zadania, takie jak zezwalanie na debugging lub uzyskiwanie task ports.

Ponadto w przypadku niektórych operacji kext preferuje kontakt z daemonem działającym w user space: `/usr/libexec/amfid`. Ta relacja zaufania była wykorzystywana w kilku jailbreakach.

W nowszych wersjach macOS AMFI nie jest już wygodnie dostępny jako samodzielny kext na dysku, dlatego reverse engineering zwykle oznacza pracę z **kernelcache** lub **KDK**, zamiast przeglądania `/System/Library/Extensions`.

AMFI używa polityk **MACF** i rejestruje swoje hooki w momencie uruchomienia. Próba uniemożliwienia jego załadowania lub wyładowania może również wywołać kernel panic. Istnieją jednak argumenty rozruchowe, które pozwalają osłabić AMFI:

- `amfi_unrestricted_task_for_pid`: Zezwala na task_for_pid bez wymaganych entitlements
- `amfi_allow_any_signature`: Zezwala na dowolny code signature
- `cs_enforcement_disable`: Argument systemowy używany do wyłączenia egzekwowania code signing
- `amfi_prevent_old_entitled_platform_binaries`: Unieważnia platform binaries z entitlements
- `amfi_get_out_of_my_way`: Całkowicie wyłącza amfi

Oto niektóre z rejestrowanych przez niego polityk MACF:<sup>[1]</sup>

- **`cred_check_label_update_execve:`** Aktualizacja label zostanie wykonana i zwróci 1
- **`cred_label_associate`**: Aktualizuje slot mac label AMFI za pomocą label
- **`cred_label_destroy`**: Usuwa slot mac label AMFI
- **`cred_label_init`**: Przenosi 0 do slotu mac label AMFI
- **`cred_label_update_execve:`** Sprawdza entitlements procesu, aby ustalić, czy powinien on mieć możliwość modyfikowania labels.
- **`file_check_mmap:`** Sprawdza, czy mmap uzyskuje pamięć i ustawia ją jako wykonywalną. W takim przypadku sprawdza, czy wymagana jest library validation, a jeśli tak, wywołuje funkcję library validation.
- **`file_check_library_validation`**: Wywołuje funkcję library validation, która sprawdza między innymi, czy platform binary ładuje inną platform binary oraz czy proces i nowo załadowany plik mają ten sam TeamID. Niektóre entitlements pozwalają również na załadowanie dowolnej library.
- **`policy_initbsd`**: Konfiguruje zaufane NVRAM Keys
- **`policy_syscall`**: Sprawdza polityki DYLD, takie jak to, czy binary ma unrestricted segments i czy powinien zezwalać na env vars. Jest również wywoływana, gdy proces jest uruchamiany za pomocą `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Sprawdza, czy gdy proces wykonuje nowy binary, inne procesy posiadające prawa SEND do task port procesu powinny je zachować. Platform binaries są dozwolone, entitlement `get-task-allow` na to pozwala, entitlements `task_for_pid-allow` są dozwolone, podobnie jak binaries z tym samym TeamID.
- **`proc_check_expose_task`**: Egzekwuje entitlements
- **`amfi_exc_action_check_exception_send`**: Wiadomość exception jest wysyłana do debuggera
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Cykl życia label podczas obsługi exception (debugging)
- **`proc_check_get_task`**: Sprawdza entitlements, takie jak `get-task-allow`, które pozwala innym procesom uzyskać task port procesu, oraz `task_for_pid-allow`, które pozwala procesowi uzyskać task porty innych procesów. Jeśli nie występuje żadne z nich, wywołuje `amfid permitunrestricteddebugging`, aby sprawdzić, czy jest to dozwolone.
- **`proc_check_mprotect`**: Odmawia, jeśli `mprotect` zostanie wywołane z flagą `VM_PROT_TRUSTED`, która wskazuje, że region musi być traktowany tak, jakby posiadał prawidłowy code signature.
- **`vnode_check_exec`**: Jest wywoływana podczas ładowania executable files do pamięci i ustawia `cs_hard | cs_kill`, co zakończy proces, jeśli którakolwiek ze stron stanie się nieprawidłowa<sup>[2]</sup>
- **`vnode_check_getextattr`**: MacOS: Sprawdza `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Tak jak get + entitlement `com.apple.private.allow-bless` i `internal-installer-equivalent`
- **`vnode_check_signature`**: Kod, który wywołuje XNU w celu sprawdzenia code signature przy użyciu entitlements, trust cache i `amfid`<sup>[3]</sup>
- **`proc_check_run_cs_invalid`**: Przechwytuje wywołania `ptrace()` (`PT_ATTACH` i `PT_TRACE_ME`). Sprawdza entitlements `get-task-allow`, `run-invalid-allow` i `run-unsigned-code`, a jeśli nie występuje żaden z nich, sprawdza, czy debugging jest dozwolony.
- **`proc_check_map_anon`**: Jeśli `mmap` zostanie wywołane z flagą **`MAP_JIT`**, AMFI sprawdzi entitlement `dynamic-codesigning`.

`AMFI.kext` udostępnia również API dla innych kernel extensions. Jego dependencies można znaleźć za pomocą:
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

Jest to daemon działający w trybie użytkownika, którego `AMFI.kext` używa do sprawdzania code signatures w trybie użytkownika.\
Aby `AMFI.kext` mógł komunikować się z daemonem, używa komunikatów mach przez port `HOST_AMFID_PORT`, którym jest specjalny port `18`.

Należy zauważyć, że w macOS procesy root nie mogą już przejmować specjalnych portów, ponieważ są one chronione przez `SIP` i tylko launchd może uzyskać do nich dostęp. W iOS sprawdzane jest, czy proces wysyłający odpowiedź ma hardcoded CDHash procesu `amfid`.

Można obserwować, kiedy `amfid` otrzymuje żądanie sprawdzenia binary oraz jego odpowiedź, debugując go i ustawiając breakpoint w `mach_msg`.

Po odebraniu komunikatu przez specjalny port używany jest **MIG** do skierowania każdej funkcji do wywoływanej przez nią funkcji. Główne funkcje zostały odwrócone i wyjaśnione w książce.

### Polityka DYLD i walidacja bibliotek

Nowsze wersje `dyld` wywołują `amfi_check_dyld_policy_self()` bardzo wcześnie, z poziomu `configureProcessRestrictions()`, aby zapytać AMFI, czy proces może używać zmiennych ścieżek `DYLD_*`, interposing, fallback paths, embedded variables lub tolerować nieudane library insertion. Dlatego podczas triage injection surface nie wystarczy sprawdzić wyłącznie load commands Mach-O: należy również sprawdzić entitlements i runtime flags, które AMFI przekształci w politykę `dyld`.

Praktyczny triage loop wygląda następująco:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
We współczesnym macOS wiele binariów Apple nie zawiera już bezpośrednio `com.apple.security.cs.disable-library-validation`, lecz zamiast tego korzysta z `com.apple.private.security.clear-library-validation`. W takim przypadku library validation nie jest wyłączane w czasie `execve`: proces musi wywołać na sobie `csops(..., CS_OPS_CLEAR_LV, ...)`, a XNU zezwala na tę operację w odniesieniu do procesu wywołującego tylko wtedy, gdy jest obecny entitlement. Z perspektywy offensive ma to znaczenie, ponieważ cel może stać się podatny na injection dopiero **po** dotarciu do ścieżki kodu, która jawnie wyłącza LV (na przykład krótko przed załadowaniem opcjonalnych pluginów).<sup>[4][5]</sup>

## Profile provisioning

Profil provisioning może służyć do podpisywania kodu. Istnieją profile **Developer**, których można używać do podpisywania kodu i jego testowania, oraz profile **Enterprise**, których można używać na wszystkich urządzeniach.

Po przesłaniu aplikacji do Apple Store, jeśli zostanie zaakceptowana, jest ona podpisywana przez Apple, a profil provisioning nie jest już potrzebny.

Profil zwykle używa rozszerzenia `.mobileprovision` lub `.provisionprofile` i można go zrzucić za pomocą:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Chociaż czasami określa się je jako certificated, te provisioning profiles zawierają więcej niż tylko certyfikat:

- **AppIDName:** Identyfikator aplikacji
- **AppleInternalProfile**: Oznacza, że jest to wewnętrzny profil Apple
- **ApplicationIdentifierPrefix**: Dodawany przed AppIDName (taki sam jak TeamIdentifier)
- **CreationDate**: Data w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Tablica (zwykle jednego) certyfikatu(-ów), zakodowanych jako dane Base64
- **Entitlements**: Dozwolone entitlements zawarte w tym profilu
- **ExpirationDate**: Data wygaśnięcia w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Nazwa aplikacji, taka sama jak AppIDName
- **ProvisionedDevices**: Tablica (dla certyfikatów deweloperskich) identyfikatorów UDID, dla których ten profil jest ważny
- **ProvisionsAllDevices**: Wartość logiczna (true dla certyfikatów enterprise)
- **TeamIdentifier**: Tablica (zwykle jednego) ciągu alfanumerycznego(-ych), używanego(-ych) do identyfikowania dewelopera na potrzeby interakcji między aplikacjami
- **TeamName**: Czytelna dla człowieka nazwa używana do identyfikowania dewelopera
- **TimeToLive**: Okres ważności certyfikatu (w dniach)
- **UUID**: Universally Unique Identifier tego profilu
- **Version**: Obecnie ustawione na 1

Należy pamiętać, że wpis entitlements będzie zawierał ograniczony zestaw entitlements, a provisioning profile będzie mógł nadać tylko te konkretne entitlements, aby zapobiec nadawaniu prywatnych entitlements Apple.

Należy pamiętać, że profile zwykle znajdują się w `/var/MobileDeviceProvisioningProfiles` i można je sprawdzić za pomocą **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Jest to zewnętrzna biblioteka, którą `amfid` wywołuje, aby zapytać, czy powinien coś zezwolić, czy nie. Historycznie była nadużywana w jailbreaking poprzez uruchamianie jej backdoored wersji, która zezwalała na wszystko.

W macOS znajduje się ona wewnątrz `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches nie są wyłącznie koncepcją iOS. We współczesnym macOS, szczególnie na **Apple silicon**, static trust cache i loadable trust caches są częścią łańcucha Secure Boot. Gdy **CodeDirectory hash** pliku Mach-O jest w nich obecny, AMFI może nadać mu **platform privilege** bez wykonywania dodatkowych kontroli autentyczności podczas uruchamiania. Oznacza to również, że Apple może przypisać binaries platformy do konkretnej wersji systemu operacyjnego i uniemożliwić odtwarzanie starszych binaries podpisanych przez Apple na nowszych systemach.<sup>[6]</sup>

W nowszych wydaniach macOS metadane trust-cache są również powiązane z **launch constraints**, dlatego skopiowane aplikacje systemowe i binaries uruchamiane z niewłaściwego procesu nadrzędnego/lokalizacji mogą zostać odrzucone przez AMFI, nawet jeśli nadal są podpisane przez Apple. Szczegółowy workflow extraction i reversing został opisany w:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

W badaniach iOS i jailbreak nadal można znaleźć tradycyjny model **loadable trust caches**, używany do tworzenia whitelisty binaries podpisanych ad hoc.

## Referencje

- [1] [XNU — `security/mac_policy.h` (operacje polityki MACF rejestrowane przez AMFI, w tym `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (flagi podpisywania kodu `CS_*` ustawiane przez AMFI)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (parsowanie i walidacja code-signature blob)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (operacje `CS_OPS_*` i `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (handler `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
