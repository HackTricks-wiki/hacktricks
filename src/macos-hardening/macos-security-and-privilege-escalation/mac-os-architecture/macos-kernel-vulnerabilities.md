# Luki w kernelu macOS

{{#include ../../../banners/hacktricks-training.md}}

Najnowsze exploity kernela macOS dotyczą w mniejszym stopniu „załadowania trywialnego, niepodpisanego kexta i uzyskania ring-0”, a w większym stopniu nadużywania **parserów Mach/MIG**, **user clientów IOKit**, **data-only races wewnątrz XNU** oraz **daemonów z określonymi entitlementami**, które nadal mogą ponownie otwierać attack surface kernela. Przy analizie konkretnych interfejsów sprawdź również strony dotyczące [**IOKit**](macos-iokit.md) oraz [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces, które nadal mają znaczenie

- **Handlery Mach/MIG** w systemowych daemonach i usługach komunikujących się z kernelem: nieprawidłowo sformowane deskryptory, dane out-of-line (OOL) oraz stanowe przepływy obejmujące wiele komunikatów.
- **User clienty IOKit**: parsowanie zależne od selectora, metody wymagające entitlementów oraz biblioteki wrapperów/daemony, które ukrywają rzeczywisty call graph.
- **Data-only primitives XNU**: races dotyczące credentials, wskaźników chronionych przez SMR, stref tylko do odczytu oraz innych miejsc, w których corruption zmienia zasady dostępu bez wcześniejszego uzyskania kontroli nad RIP/PC.
- **Third-party / auxiliary kernel code**: starsze kexty występują rzadziej, ale floty enterprise, systemy Apple Silicon z obniżonym poziomem security oraz pakiety pomocnicze `.fs` / helper vendorów nadal tworzą wartościowe ścieżki sąsiadujące z kernelem.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

W [**tym raporcie**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) połączono kilka bugów w łańcuchu OTA/update, aby uzyskać kompromitację kernela poprzez nadużycie pipeline'u aktualizacji software'u oraz możliwości powiązanych z rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Chain bypassu ochrony kernela wykorzystany in-the-wild (CVE-2024-23225 i CVE-2024-23296)

[**Marcowe wydania security macOS z 2024 roku**](https://support.apple.com/en-us/120895) firmy Apple naprawiły dwa problemy, które były **aktywnie wykorzystywane**:

- **CVE-2024-23225 – Kernel**: bug związany z memory corruption, w którym attacker posiadający arbitrary kernel read/write mógł ominąć zabezpieczenia pamięci kernela.
- **CVE-2024-23296 – RTKit**: drugi bug związany z memory corruption, z takim samym publicznym opisem wpływu.

Publicznie dostępnych informacji o root cause nadal jest niewiele, ale ta para dobrze przypomina, że współczesne chainy exploitów Apple często wymagają czegoś więcej niż „tylko” kernel R/W: praca post-exploitation nad zabezpieczeniami pamięci, kodem sąsiadującym z coprocessorem lub dodatkowymi granicami zaufania często stanowi etap, na którym rzeczywisty chain zostaje ustabilizowany.

Szybki triage poprawek:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) Josepha Ravichandrana to bardzo dobre współczesne studium przypadku XNU, ponieważ **nie jest** klasycznym buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` to **SMR-protected pointer** przechowywany w obiekcie `proc_ro` **read-only**.
- Writers muszą aktualizować ten pointer **atomically**.
- `kauth_cred_proc_update()` używało `zalloc_ro_mut(...)` do modyfikowania `p_ucred`; na x86_64 ta ścieżka ostatecznie trafia do `memcpy` / `rep movsb`, więc równoczesny reader może zaobserwować **torn pointer**.
- Bug przekształca się w **data-only privilege escalation**: jeśli uszkodzony credential pointer wskazuje na inny prawidłowy credential object, bieżący thread może odziedziczyć bardziej uprzywilejowany stan bez wcześniejszego uzyskania oczywistego control-flow hijack.

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
Przydatna heurystyka audytowa: za każdym razem, gdy ścieżka kernela łączy **SMR readers**, **read-only zone mutation** oraz **credential lub task metadata**, sprawdź, czy aktualizacje używają atomowych wariantów `zalloc_ro_mut_*`, a nie helperów opartych na kopiowaniu.

---

## 2024-2025: SIP bypass ponownie otwierający ścieżki ładowania kernela (CVE-2024-44243)

Microsoft pokazał, że `storagekitd` można wykorzystać do **bypass SIP**, a następnie ponownie uczynić kod kernela innych firm istotnym na maszynach, które w przeciwnym razie wyglądałyby na systemy "post-kext". Kluczowa idea:<sup>[[2]](#references)</sup>

1. Umieść lub nadpisz złośliwy bundle `.fs` w `/Library/Filesystems`.
2. Uruchom `storagekitd` za pośrednictwem Disk Utility lub `diskutil`.
3. Pozwól daemonowi z odpowiednimi entitlementami uruchomić executables z bundle **bez prawidłowego odbierania uprawnień / walidowania ścieżki**.
4. Wykorzystaj uzyskany SIP bypass do zmodyfikowania chronionego stanu file systemu oraz, w demonstracji Microsoftu, nadpisania listy wykluczeń kernel extensions.

Dla badaczy kernela ważnym wnioskiem jest to, że **kernel attack surface może zostać ponownie wprowadzony z poziomu userland management daemons**, nawet gdy bezpośrednie ładowanie kextów innych firm jest silnie ograniczone.

Przydatny triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing i workflow badawczy

Jeśli aktywnie polujesz na tę klasę bugów, ostatnie publiczne prace wskazują ten sam kierunek:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) nadal jest jednym z najlepszych punktów odniesienia dla badań nad kernelem ery Apple Silicon. Wykorzystuje **static binary rewriting** do odzyskiwania coverage, wyłącza ścieżki **entitlement-gated** podczas testów i wnioskuje o strukturze interfejsu na podstawie userspace wrappers.<sup>[[4]](#references)</sup>
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) zespołu Project Zero pokazuje bardzo praktyczny workflow **rebasowania kext / fileset do userspace**, dzięki czemu kod intensywnie przetwarzający dane wejściowe można fuzzować ze znacznie większą szybkością, a następnie odtworzyć problem na urządzeniu.<sup>[[5]](#references)</sup>
- W przypadku celów intensywnie wykorzystujących Mach buduj harnessy wokół **rzeczywistych układów komunikatów i maszyn stanów obejmujących wiele wywołań**, a nie tylko pojedynczych selector blobs. Najnowsze badania nad CoreAudio/Mach prowadzone przez Project Zero oraz prezentacje konferencyjne, takie jak **Fuzzing at Mach Speed**, pokazują, dlaczego stateful message sequences nadal przynoszą dobre rezultaty.

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
## Referencje

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Analiza CVE-2024-44243, obejścia macOS System Integrity Protection za pośrednictwem rozszerzeń kernela](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Koszmar OTA Update firmy Apple: obejście weryfikacji podpisu i przejęcie kernela](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: fuzzing macOS Kernel EXTensions na Apple Silicon poprzez wykorzystanie mechanizmów łagodzących (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Prosty fuzzing rozszerzeń kernela macOS w userspace za pomocą IDA i TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
