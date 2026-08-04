# Podatności jądra macOS

{{#include ../../../banners/hacktricks-training.md}}

Współczesne exploitowanie jądra macOS polega w mniejszym stopniu na „załadowaniu trywialnego, niepodpisanego kexta i uzyskaniu ring-0”, a w większym na wykorzystywaniu **parserów Mach/MIG**, **IOKit user clients**, **wyścigów typu data-only wewnątrz XNU** oraz **specjalnie uprzywilejowanych daemonów**, które nadal mogą ponownie otwierać powierzchnię ataku jądra. Podczas analizy konkretnych interfejsów sprawdź również strony dotyczące [**IOKit**](macos-iokit.md) oraz [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Powierzchnie ataku, które nadal mają znaczenie

- **Handlery Mach/MIG** w systemowych daemonach i usługach komunikujących się z jądrem: nieprawidłowe deskryptory, dane out-of-line (OOL) oraz stanowe przepływy obejmujące wiele komunikatów.
- **IOKit user clients**: parsowanie zależne od selektora, metody wymagające entitlementów oraz biblioteki wrapperów/daemony ukrywające rzeczywisty graf wywołań.
- **Primitives typu data-only w XNU**: wyścigi dotyczące credentials, wskaźników chronionych przez SMR, stref tylko do odczytu oraz innych miejsc, w których korupcja zmienia zasady bez konieczności wcześniejszego przejęcia kontroli nad RIP/PC.
- **Kod jądra firm trzecich / pomocniczy kod jądra**: starsze kexty są rzadsze, ale floty systemów firmowych, systemy Apple Silicon z obniżonym poziomem zabezpieczeń oraz pakiety `.fs` / helper nadal tworzą wartościowe ścieżki sąsiadujące z jądrem.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) połączono kilka błędów w łańcuchu OTA/update, aby doprowadzić do kompromitacji jądra poprzez nadużycie pipeline'u aktualizacji oprogramowania i możliwości związanych z rootless.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: łańcuch obejścia ochrony jądra wykorzystany in-the-wild (CVE-2024-23225 i CVE-2024-23296)

[**Wydania zabezpieczeń macOS z marca 2024 r.**](https://support.apple.com/en-us/120895) firmy Apple naprawiły dwa problemy, które były **aktywnie wykorzystywane**:

- **CVE-2024-23225 – Kernel**: błąd korupcji pamięci, który umożliwiał atakującemu posiadającemu arbitrary kernel read/write obejście zabezpieczeń pamięci jądra.
- **CVE-2024-23296 – RTKit**: drugi błąd korupcji pamięci z takim samym publicznym opisem wpływu.

Publicznie dostępne informacje o przyczynie źródłowej nadal są skąpe, ale ta para przypomina, że współczesne łańcuchy exploitów Apple często wymagają **czegoś więcej niż „tylko” kernel R/W**: działania post-exploitation przeciwko zabezpieczeniom pamięci, kodowi sąsiadującemu z coprocessorem lub dodatkowym granicom zaufania często stanowią etap, na którym stabilizowany jest rzeczywisty łańcuch.

Szybki triage poprawek:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + wyścig read-only credential (CVE-2025-24118)

[**Opracowanie TRAVERTINE**](https://jprx.io/cve-2025-24118/) autorstwa Josepha Ravichandrana to bardzo dobry współczesny case study XNU, ponieważ nie jest to **klasyczny buffer overflow**:

- `proc_ro.p_ucred` to wskaźnik chroniony przez **SMR**, przechowywany w obiekcie `proc_ro` oznaczonym jako **read-only**.
- Procesy zapisujące muszą aktualizować ten wskaźnik **atomowo**.
- `kauth_cred_proc_update()` używało `zalloc_ro_mut(...)` do modyfikowania `p_ucred`; na x86_64 ta ścieżka ostatecznie wywołuje `memcpy` / `rep movsb`, więc współbieżny odczyt może zaobserwować **częściowo zapisany wskaźnik**.
- Błąd prowadzi do **eskalacji uprawnień typu data-only**: jeśli uszkodzony wskaźnik wskaże na inny prawidłowy obiekt credential, bieżący wątek może odziedziczyć bardziej uprzywilejowany stan bez wcześniejszego przejęcia oczywistej kontroli nad przepływem wykonania.

Minimalny wzorzec wyzwalania:
```c
// writer thread: force frequent credential swaps
while (1) {
setgid(real_gid);
setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
(void)getgid();
}
```
Przydatna heurystyka audytowa: gdy ścieżka kernela łączy **SMR readers**, **read-only zone mutation** oraz **credential lub task metadata**, sprawdź, czy aktualizacje używają atomowych wariantów `zalloc_ro_mut_*`, a nie helperów opartych na kopiowaniu.

---

## 2024-2025: SIP bypass ponownie otwierający ścieżki ładowania kernela (CVE-2024-44243)

Microsoft pokazał, że `storagekitd` można było wykorzystać do **bypass SIP**, a następnie ponownie uaktywnić kod kernela firm trzecich na maszynach, które w innym przypadku wyglądałyby na "post-kext". Kluczowy pomysł:

1. Umieścić lub nadpisać złośliwy bundle `.fs` w `/Library/Filesystems`.
2. Uruchomić `storagekitd` za pośrednictwem Disk Utility lub `diskutil`.
3. Pozwolić daemonowi, posiadającemu specjalne uprawnienia, uruchomić executables bundle **bez prawidłowego obniżenia uprawnień / sprawdzenia ścieżki**.
4. Wykorzystać uzyskany SIP bypass do zmodyfikowania chronionego stanu systemu plików i, w demonstracji Microsoftu, nadpisać listę wykluczeń rozszerzeń kernela.

Dla badaczy kernela ważna lekcja jest taka, że **powierzchnia ataku kernela może zostać ponownie wprowadzona z userlandowych daemonów zarządzających**, nawet gdy bezpośrednie ładowanie kextów firm trzecich jest silnie ograniczone.

Przydatny triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow fuzzingu i researchu

Jeśli aktywnie szukasz tego rodzaju błędów, najnowsze publiczne prace wskazują ten sam kierunek:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) nadal jest jednym z najlepszych punktów odniesienia dla researchu kernela w erze Apple Silicon. Wykorzystuje **static binary rewriting** do odzyskiwania pokrycia, wyłącza podczas testów ścieżki **entitlement-gated** i wnioskuje strukturę interfejsów na podstawie userspace wrappers.
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) autorstwa Project Zero przedstawia bardzo praktyczny workflow **rebasingu kext / fileset do userspace**, dzięki czemu kod intensywnie korzystający z parserów można fuzzować ze znacznie większą szybkością, a następnie odtwarzać problemy na urządzeniu.
- W przypadku celów opartych na Mach buduj harnessy wokół **rzeczywistych układów komunikatów i maszyn stanów wykonujących wiele wywołań**, a nie tylko pojedynczych blobów selektorów. Najnowsze badania Project Zero dotyczące CoreAudio/Mach oraz wystąpienia konferencyjne, takie jak **Fuzzing at Mach Speed**, pokazują, dlaczego sekwencje komunikatów ze stanem nadal przynoszą dobre rezultaty.

Szybkie lokalne polecenia, których będziesz często używać:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Szybka ściągawka enumeracji
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Referencje

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “Analiza CVE-2024-44243, obejścia System Integrity Protection w macOS za pomocą kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
