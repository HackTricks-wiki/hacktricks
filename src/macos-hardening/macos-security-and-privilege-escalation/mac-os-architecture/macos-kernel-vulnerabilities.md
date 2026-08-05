# Podatności kernela macOS

{{#include ../../../banners/hacktricks-training.md}}

Współczesne exploity kernela macOS dotyczą w mniejszym stopniu „załadowania banalnego, niepodpisanego kexta i uzyskania ring-0”, a w większym stopniu wykorzystywania **parserów Mach/MIG**, **IOKit user clients**, **wyścigów data-only wewnątrz XNU** oraz **specjalnie uprzywilejowanych daemonów**, które nadal mogą ponownie otwierać powierzchnię ataku kernela. Przy analizie konkretnych interfejsów sprawdź również strony dotyczące [**IOKit**](macos-iokit.md) oraz [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Powierzchnie ataku, które nadal mają znaczenie

- **Handlery Mach/MIG** w systemowych daemonach i usługach komunikujących się z kernelem: nieprawidłowe descriptory, dane out-of-line (OOL) oraz stanowe przepływy obejmujące wiele wiadomości.
- **IOKit user clients**: parsowanie zależne od selectora, metody wymagające entitlementów oraz biblioteki wrapperów/daemony, które ukrywają rzeczywisty call graph.
- **Primitives data-only XNU**: wyścigi dotyczące credentials, wskaźników chronionych przez SMR, stref tylko do odczytu oraz innych miejsc, w których corruption zmienia zasady dostępu bez konieczności wcześniejszego przejęcia kontroli nad RIP/PC.
- **Third-party / auxiliary kernel code**: starsze kexty są rzadsze, ale floty enterprise, systemy Apple Silicon z obniżonym poziomem security oraz vendorskie bundlery `.fs` / helper nadal tworzą wartościowe ścieżki powiązane z kernelem.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) połączono kilka bugów w łańcuchu OTA/update, aby osiągnąć compromise kernela poprzez wykorzystanie pipeline'u aktualizacji software'u oraz capabilities związanych z rootless.<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Łańcuch omijający ochronę kernela wykorzystany in-the-wild (CVE-2024-23225 i CVE-2024-23296)

[**Wydania security macOS z marca 2024 roku**](https://support.apple.com/en-us/120895) firmy Apple naprawiły dwa problemy, które były **aktywnie wykorzystywane**:

- **CVE-2024-23225 – Kernel**: bug powodujący memory corruption, w którym attacker dysponujący arbitrary kernel read/write mógł ominąć zabezpieczenia pamięci kernela.
- **CVE-2024-23296 – RTKit**: drugi bug powodujący memory corruption, z takim samym publicznym opisem wpływu.

Publiczne informacje o root cause nadal są skąpe, ale ta para dobrze przypomina, że współczesne łańcuchy exploitów Apple często wymagają czegoś więcej niż „tylko” kernel R/W: prace post-exploitation przeciwko zabezpieczeniom pamięci, kodowi sąsiadującemu z coprocessorem lub dodatkowym granicom zaufania często stanowią etap, na którym rzeczywisty łańcuch zostaje ustabilizowany.

Szybki triage patchy:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) autorstwa Josepha Ravichandrana to bardzo dobre współczesne studium przypadku XNU, ponieważ **nie jest** to klasyczny buffer overflow:<sup>[1]</sup>

- `proc_ro.p_ucred` to **SMR-protected pointer**, przechowywany w obiekcie `proc_ro` o właściwości **read-only**.
- Writerzy muszą aktualizować ten pointer **atomowo**.
- `kauth_cred_proc_update()` używało `zalloc_ro_mut(...)` do modyfikacji `p_ucred`; na x86_64 ta ścieżka ostatecznie trafia do `memcpy` / `rep movsb`, więc współbieżny reader może zaobserwować **torn pointer**.
- Bug przeradza się w **data-only privilege escalation**: jeśli uszkodzony credential pointer wskaże inny prawidłowy credential object, bieżący thread może odziedziczyć bardziej uprzywilejowany stan bez wcześniejszego uzyskania oczywistego control-flow hijack.

Minimalny wzorzec triggera:
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
Przydatna heurystyka audytowa: za każdym razem, gdy ścieżka kernela łączy **czytelników SMR**, **modyfikację stref tylko do odczytu** oraz **metadane poświadczeń lub zadań**, sprawdź, czy aktualizacje używają atomowych wariantów `zalloc_ro_mut_*`, a nie helperów opartych na kopiowaniu.

---

## 2024-2025: SIP bypass ponownie otwierający ścieżki ładowania kernela (CVE-2024-44243)

Microsoft pokazał, że `storagekitd` można wykorzystać do **bypassu SIP**, a następnie ponownie sprawić, że kod kernela innych firm stanie się istotny na maszynach, które w przeciwnym razie wyglądałyby na systemy „post-kext”. Kluczowy pomysł:<sup>[2]</sup>

1. Umieścić lub nadpisać złośliwy bundle `.fs` w `/Library/Filesystems`.
2. Uruchomić `storagekitd` za pośrednictwem Disk Utility lub `diskutil`.
3. Pozwolić daemonowi, któremu przyznano specjalne uprawnienia, uruchamiać pliki wykonywalne bundle **bez prawidłowego obniżenia uprawnień / sprawdzenia ścieżki**.
4. Wykorzystać uzyskany SIP bypass do zmodyfikowania chronionego stanu systemu plików oraz — w demonstracji Microsoftu — nadpisania listy wykluczeń rozszerzeń kernela.

Dla badaczy kernela ważny wniosek jest taki, że **powierzchnia ataku kernela może zostać ponownie otwarta z poziomu userlandowych daemonów zarządzających**, nawet gdy bezpośrednie ładowanie kextów innych firm jest silnie ograniczone.

Przydatna wstępna analiza:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow fuzzingu i researchu

Jeśli aktywnie szukasz tego typu błędów, najnowsze publiczne prace wskazują ten sam kierunek:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) nadal jest jednym z najlepszych punktów odniesienia dla badań nad kernelem w erze Apple Silicon. Wykorzystuje **static binary rewriting** do odzyskiwania coverage, wyłącza ścieżki **entitlement-gated** podczas testów oraz wnioskuje strukturę interfejsu na podstawie wrapperów userspace.<sup>[4]</sup>
- Projekt Zero w [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) pokazuje bardzo praktyczny workflow **rebasingu kext / fileset do userspace**, dzięki czemu kod intensywnie wykorzystujący parsery można fuzzować ze znacznie większą szybkością, a następnie odtwarzać problemy na urządzeniu.<sup>[5]</sup>
- W przypadku celów opartych intensywnie na Mach buduj harnessy wokół **rzeczywistych układów komunikatów i maszyn stanów obejmujących wiele wywołań**, a nie tylko pojedynczych blobów selectorów. Najnowsze badania CoreAudio/Mach prowadzone przez Projekt Zero oraz prezentacje konferencyjne, takie jak **Fuzzing at Mach Speed**, pokazują, dlaczego sekwencje komunikatów ze stanem nadal przynoszą dobre rezultaty.

Szybkie lokalne komendy, których będziesz często używać:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Ściągawka szybkiej enumeracji
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

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Analiza CVE-2024-44243, obejścia macOS System Integrity Protection za pomocą kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Koszmar aktualizacji OTA firmy Apple: omijanie weryfikacji sygnatury i przejęcie kernela](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin i in. - KextFuzz: fuzzing macOS Kernel EXTensions na Apple Silicon poprzez wykorzystywanie mechanizmów ochronnych (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Prosty fuzzing macOS kernel extension w userspace za pomocą IDA i TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
