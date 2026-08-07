# Podatności macOS Kernel

{{#include ../../../banners/hacktricks-training.md}}

Współczesne kernel exploitation w macOS polega w mniejszym stopniu na „załadowaniu trywialnego, niepodpisanego kexta i uzyskaniu ring-0”, a częściej na wykorzystywaniu **parserów Mach/MIG**, **IOKit user clients**, **data-only races wewnątrz XNU** oraz **specjalnie uprzywilejowanych daemonów**, które nadal mogą ponownie otwierać kernel attack surface. Przy analizie konkretnych interfejsów sprawdź również strony dotyczące [**IOKit**](macos-iokit.md) oraz [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces, które nadal mają znaczenie

- **Mach/MIG handlers** w systemowych daemonach i usługach komunikujących się z kernelem: nieprawidłowe deskryptory, dane out-of-line (OOL) oraz stanowe przepływy wielu komunikatów.
- **IOKit user clients**: parsowanie zależne od selektora, metody chronione przez entitlementy oraz biblioteki wrapperów/daemony ukrywające rzeczywisty call graph.
- **XNU data-only primitives**: race conditions dotyczące credentials, wskaźników chronionych przez SMR, stref tylko do odczytu oraz innych miejsc, w których corruption zmienia politykę bez wcześniejszego uzyskania kontroli nad RIP/PC.
- **Third-party / auxiliary kernel code**: starsze kexty występują rzadziej, ale floty enterprise, systemy Apple Silicon z obniżonym poziomem bezpieczeństwa oraz pakiety vendorów `.fs` / helper nadal tworzą wartościowe ścieżki sąsiadujące z kernelem.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) połączono kilka bugów w łańcuchu OTA/update chain, aby uzyskać kernel compromise poprzez nadużycie pipeline'u aktualizacji oprogramowania oraz możliwości związanych z rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Łańcuch obejścia ochrony kernela wykorzystany in-the-wild (CVE-2024-23225 i CVE-2024-23296)

Marcowe [**wydania aktualizacji bezpieczeństwa macOS z 2024 roku**](https://support.apple.com/en-us/120895) firmy Apple naprawiły dwa problemy, które były **aktywnie wykorzystywane**:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: bug związany z corruption pamięci, w którym attacker posiadający arbitrary kernel read/write mógł obejść ochronę pamięci kernela.
- **CVE-2024-23296 – RTKit**: drugi bug związany z corruption pamięci, z takim samym publicznym opisem wpływu.

Publiczne informacje o root cause nadal są skąpe, ale ta para stanowi dobre przypomnienie, że współczesne exploit chains Apple często wymagają czegoś więcej niż „tylko” kernel R/W: prace post-exploitation dotyczące ochrony pamięci, kodu sąsiadującego z coprocessorem lub dodatkowych trust boundaries często stanowią etap, na którym rzeczywisty chain zostaje ustabilizowany.

Szybki triage poprawek:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + wyścig read-only credential (CVE-2025-24118)

[**Write-up TRAVERTINE** autorstwa Josepha Ravichandrana](https://jprx.io/cve-2025-24118/) jest bardzo dobrym współczesnym case study XNU, ponieważ nie jest to klasyczny buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` to pointer chroniony przez **SMR**, przechowywany w obiekcie `proc_ro` oznaczonym jako **read-only**.
- Writers muszą aktualizować ten pointer **atomically**.
- `kauth_cred_proc_update()` używało `zalloc_ro_mut(...)` do modyfikowania `p_ucred`; na x86_64 ta ścieżka ostatecznie trafia do `memcpy` / `rep movsb`, więc współbieżny reader może zaobserwować **torn pointer**.
- Bug zmienia się w **data-only privilege escalation**: jeśli uszkodzony credential pointer wskazuje na inny prawidłowy credential object, bieżący thread może odziedziczyć bardziej uprzywilejowany stan bez wcześniejszego przejęcia kontroli nad flow wykonania.

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
Przydatna heurystyka audytu: za każdym razem, gdy ścieżka kernel miesza **czytniki SMR**, **mutację stref tylko do odczytu** oraz **metadane poświadczeń lub zadań**, sprawdź, czy aktualizacje używają wariantów atomowych `zalloc_ro_mut_*`, a nie helperów opartych na kopiowaniu.

---

## 2024-2025: obejście SIP, które ponownie otwiera ścieżki ładowania kernel (CVE-2024-44243)

Microsoft pokazał, że `storagekitd` można było wykorzystać do **obejścia SIP**, a następnie ponownie uczynić kod kernel firm trzecich istotnym na maszynach, które w innym przypadku wyglądałyby na systemy „post-kext”. Kluczowy pomysł:<sup>[[2]](#references)</sup>

1. Upuść lub nadpisz złośliwy bundle `.fs` w `/Library/Filesystems`.
2. Wywołaj `storagekitd` za pośrednictwem Disk Utility lub `diskutil`.
3. Pozwól daemonowi ze specjalnymi uprawnieniami uruchamiać pliki wykonywalne bundle **bez prawidłowego zrzucenia uprawnień / zweryfikowania ścieżki**.
4. Wykorzystaj uzyskane obejście SIP do zmodyfikowania chronionego stanu file systemu oraz, w demonstracji Microsoftu, nadpisania listy wykluczeń kernel extension.

Dla badaczy kernel najważniejsza lekcja jest taka, że **powierzchnia ataku kernel może zostać ponownie wprowadzona z poziomu daemonów zarządzających userland**, nawet gdy bezpośrednie ładowanie kextów firm trzecich jest silnie ograniczone.

Przydatny triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow fuzzingu i researchu

Jeśli aktywnie polujesz na tę klasę błędów, najnowsze publiczne prace wskazują w tym samym kierunku:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) nadal jest jednym z najlepszych punktów odniesienia dla badań nad kernelami ery Apple Silicon. Wykorzystuje **static binary rewriting** do odzyskiwania coverage, wyłącza ścieżki **entitlement-gated** podczas testów i wnioskuje strukturę interfejsu na podstawie wrapperów userspace.<sup>[[4]](#references)</sup>
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) autorstwa Project Zero pokazuje bardzo praktyczny workflow **rebasingu kext / fileset do userspace**, dzięki czemu kod intensywnie wykorzystujący parsery można fuzzować ze znacznie większą szybkością, zanim zostanie odtworzony na urządzeniu.<sup>[[5]](#references)</sup>
- W przypadku targetów intensywnie wykorzystujących Mach buduj harnessy wokół **rzeczywistych układów wiadomości i maszyn stanów z wieloma wywołaniami**, a nie tylko pojedynczych blobów selektorów. Najnowsze badania nad CoreAudio/Mach prowadzone przez Project Zero oraz prezentacje konferencyjne, takie jak **Fuzzing at Mach Speed**, pokazują, dlaczego sekwencje wiadomości ze stanem nadal przynoszą dobre rezultaty.

Szybkie lokalne komendy, których faktycznie będziesz często używać:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Szybka ściągawka z enumeracji
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Odnośniki

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Analiza CVE-2024-44243, obejścia macOS System Integrity Protection za pomocą kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Koszmar OTA Update firmy Apple: obejście weryfikacji podpisu i przejęcie kernela](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: fuzzing kernel extensions systemu macOS na Apple Silicon poprzez wykorzystanie mechanizmów mitigacji (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Prosty fuzzing kernel extensions systemu macOS w userspace za pomocą IDA i TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [Informacje o zawartości zabezpieczeń macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
