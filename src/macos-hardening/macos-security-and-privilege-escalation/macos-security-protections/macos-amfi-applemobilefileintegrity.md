# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext i amfid

Skupia się na egzekwowaniu integralności kodu działającego w systemie, zapewniając logikę stojącą za weryfikacją podpisu kodu XNU. Może również sprawdzać uprawnienia i obsługiwać inne wrażliwe zadania, takie jak umożliwienie debugowania lub uzyskiwanie portów zadań.

Ponadto, w przypadku niektórych operacji, kext woli kontaktować się z działającym w przestrzeni użytkownika demonem `/usr/libexec/amfid`. Ta relacja zaufania była nadużywana w kilku jailbreakach.

AMFI używa **MACF** polityk i rejestruje swoje haki w momencie uruchomienia. Ponadto, zapobieganie jego ładowaniu lub odładowaniu może wywołać panikę jądra. Istnieją jednak pewne argumenty rozruchowe, które pozwalają osłabić AMFI:

- `amfi_unrestricted_task_for_pid`: Pozwala na task_for_pid bez wymaganych uprawnień
- `amfi_allow_any_signature`: Pozwala na dowolny podpis kodu
- `cs_enforcement_disable`: Argument systemowy używany do wyłączenia egzekwowania podpisu kodu
- `amfi_prevent_old_entitled_platform_binaries`: Unieważnia platformowe binaria z uprawnieniami
- `amfi_get_out_of_my_way`: Całkowicie wyłącza amfi

Oto niektóre z polityk MACF, które rejestruje:

- **`cred_check_label_update_execve:`** Aktualizacja etykiety zostanie przeprowadzona i zwróci 1
- **`cred_label_associate`**: Aktualizuje slot etykiety mac AMFI
- **`cred_label_destroy`**: Usuwa slot etykiety mac AMFI
- **`cred_label_init`**: Ustawia 0 w slocie etykiety mac AMFI
- **`cred_label_update_execve`:** Sprawdza uprawnienia procesu, aby zobaczyć, czy powinien mieć możliwość modyfikacji etykiet.
- **`file_check_mmap`:** Sprawdza, czy mmap uzyskuje pamięć i ustawia ją jako wykonywalną. W takim przypadku sprawdza, czy potrzebna jest walidacja biblioteki i, jeśli tak, wywołuje funkcję walidacji biblioteki.
- **`file_check_library_validation`**: Wywołuje funkcję walidacji biblioteki, która sprawdza między innymi, czy platformowe binarne ładują inne platformowe binarne lub czy proces i nowo załadowany plik mają ten sam TeamID. Niektóre uprawnienia również pozwalają na ładowanie dowolnej biblioteki.
- **`policy_initbsd`**: Ustawia zaufane klucze NVRAM
- **`policy_syscall`**: Sprawdza polityki DYLD, takie jak to, czy binarny ma nieograniczone segmenty, czy powinien zezwolić na zmienne środowiskowe... to jest również wywoływane, gdy proces jest uruchamiany przez `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Sprawdza, czy gdy proces wykonuje nowy binarny, inne procesy z prawami SEND nad portem zadania procesu powinny je zachować, czy nie. Platformowe binaria są dozwolone, uprawnienie `get-task-allow` to umożliwia, uprawnienia `task_for_pid-allow` są dozwolone, a binaria z tym samym TeamID.
- **`proc_check_expose_task`**: egzekwuje uprawnienia
- **`amfi_exc_action_check_exception_send`**: Wiadomość o wyjątku jest wysyłana do debuggera
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Cykl życia etykiety podczas obsługi wyjątków (debugowanie)
- **`proc_check_get_task`**: Sprawdza uprawnienia, takie jak `get-task-allow`, które pozwala innym procesom uzyskać porty zadań, oraz `task_for_pid-allow`, które pozwala procesowi uzyskać porty zadań innych procesów. Jeśli żadne z tych nie jest spełnione, wywołuje `amfid permitunrestricteddebugging`, aby sprawdzić, czy jest to dozwolone.
- **`proc_check_mprotect`**: Odrzuca, jeśli `mprotect` jest wywoływane z flagą `VM_PROT_TRUSTED`, co wskazuje, że region musi być traktowany tak, jakby miał ważny podpis kodu.
- **`vnode_check_exec`**: Jest wywoływane, gdy pliki wykonywalne są ładowane do pamięci i ustawia `cs_hard | cs_kill`, co zabije proces, jeśli którakolwiek z stron stanie się nieważna
- **`vnode_check_getextattr`**: MacOS: Sprawdza `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Jak get + com.apple.private.allow-bless i uprawnienie równoważne wewnętrznemu instalatorowi
- **`vnode_check_signature`**: Kod, który wywołuje XNU, aby sprawdzić podpis kodu przy użyciu uprawnień, pamięci zaufania i `amfid`
- **`proc_check_run_cs_invalid`**: Przechwytuje wywołania `ptrace()` (`PT_ATTACH` i `PT_TRACE_ME`). Sprawdza, czy którakolwiek z uprawnień `get-task-allow`, `run-invalid-allow` i `run-unsigned-code` jest spełniona, a jeśli nie, sprawdza, czy debugowanie jest dozwolone.
- **`proc_check_map_anon`**: Jeśli mmap jest wywoływane z flagą **`MAP_JIT`**, AMFI sprawdzi uprawnienie `dynamic-codesigning`.

`AMFI.kext` udostępnia również API dla innych rozszerzeń jądra, a jego zależności można znaleźć za pomocą:
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

To jest demon działający w trybie użytkownika, który `AMFI.kext` wykorzysta do sprawdzania podpisów kodu w trybie użytkownika.\
Aby `AMFI.kext` mogło komunikować się z demonem, używa wiadomości mach przez port `HOST_AMFID_PORT`, który jest specjalnym portem `18`.

Należy zauważyć, że w macOS nie jest już możliwe, aby procesy root przejmowały specjalne porty, ponieważ są one chronione przez `SIP`, a tylko launchd może je uzyskać. W iOS sprawdzane jest, czy proces wysyłający odpowiedź ma twardo zakodowany CDHash `amfid`.

Można zobaczyć, kiedy `amfid` jest proszony o sprawdzenie binarnego pliku oraz jego odpowiedź, debugując go i ustawiając punkt przerwania w `mach_msg`.

Gdy wiadomość jest odbierana przez specjalny port, **MIG** jest używane do wysyłania każdej funkcji do funkcji, którą wywołuje. Główne funkcje zostały odwrócone i wyjaśnione w książce.

## Provisioning Profiles

Profil provisioningowy może być używany do podpisywania kodu. Istnieją profile **Developer**, które mogą być używane do podpisywania kodu i testowania go, oraz profile **Enterprise**, które mogą być używane na wszystkich urządzeniach.

Po przesłaniu aplikacji do Apple Store, jeśli zostanie zatwierdzona, jest podpisywana przez Apple, a profil provisioningowy nie jest już potrzebny.

Profil zazwyczaj używa rozszerzenia `.mobileprovision` lub `.provisionprofile` i można go zrzucić za pomocą:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Chociaż czasami nazywane certyfikowanymi, te profile provisioningowe mają więcej niż tylko certyfikat:

- **AppIDName:** Identyfikator aplikacji
- **AppleInternalProfile**: Określa to jako profil wewnętrzny Apple
- **ApplicationIdentifierPrefix**: Dodawany do AppIDName (taki sam jak TeamIdentifier)
- **CreationDate**: Data w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Tablica (zwykle jeden) certyfikat(ów), zakodowanych jako dane Base64
- **Entitlements**: Uprawnienia dozwolone z uprawnieniami dla tego profilu
- **ExpirationDate**: Data wygaśnięcia w formacie `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Nazwa aplikacji, taka sama jak AppIDName
- **ProvisionedDevices**: Tablica (dla certyfikatów dewelopera) UDID-ów, dla których ten profil jest ważny
- **ProvisionsAllDevices**: Wartość logiczna (prawda dla certyfikatów korporacyjnych)
- **TeamIdentifier**: Tablica (zwykle jeden) alfanumeryczny ciąg(ów) używanych do identyfikacji dewelopera w celach interakcji między aplikacjami
- **TeamName**: Nazwa czytelna dla człowieka używana do identyfikacji dewelopera
- **TimeToLive**: Ważność (w dniach) certyfikatu
- **UUID**: Uniwersalny unikalny identyfikator dla tego profilu
- **Version**: Obecnie ustawione na 1

Zauważ, że wpis uprawnień będzie zawierał ograniczony zestaw uprawnień, a profil provisioningowy będzie mógł przyznać tylko te konkretne uprawnienia, aby zapobiec przyznawaniu prywatnych uprawnień Apple.

Zauważ, że profile zazwyczaj znajdują się w `/var/MobileDeviceProvisioningProfiles` i można je sprawdzić za pomocą **`security cms -D -i /path/to/profile`**

## **libmis.dyld**

To zewnętrzna biblioteka, którą `amfid` wywołuje, aby zapytać, czy powinien coś zezwolić, czy nie. Historycznie była nadużywana w jailbreakingu poprzez uruchamianie jej z backdoorem, który pozwalał na wszystko.

W macOS znajduje się w `MobileDevice.framework`.

## AMFI Trust Caches

iOS AMFI utrzymuje listę znanych hashy, które są podpisane ad-hoc, nazywaną **Trust Cache** i znajdującą się w sekcji `__TEXT.__const` kextu. Zauważ, że w bardzo specyficznych i wrażliwych operacjach możliwe jest rozszerzenie tej Trust Cache za pomocą zewnętrznego pliku.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
