# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**NVRAM** (Non-Volatile Random-Access Memory) przechowuje stan firmware'u i wczesnego uruchamiania systemu poza standardowym systemem plików macOS. Wpływ na bezpieczeństwo zależy zarówno od zmiennej, jak i architektury uruchamiania:

| Zmienna | Cel / znaczenie dla bezpieczeństwa |
|---|---|
| `boot-args` | Argumenty przekazywane do kernela. Argumenty debugowania lub zmniejszające poziom bezpieczeństwa są filtrowane, chyba że boot policy na nie zezwala. |
| `csr-active-config` | Maska bitowa SIP na komputerach Mac z procesorem Intel. Na Apple silicon równoważna polityka jest przechowywana w `LocalPolicy` dla poszczególnych woluminów i nie jest bezpośrednio uznawana na podstawie tej zmiennej. |
| `efi-boot-device` / `efi-boot-device-data` | Cel uruchamiania Intel EFI. |
| `boot-volume` | Stan wyboru woluminu uruchamiania na Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Przykłady zwykłych ustawień trwałych. |

Istotne jest rozróżnienie między **danymi przechowywanymi w NVRAM** a **polityką bezpieczeństwa zaakceptowaną przez łańcuch uruchamiania**. Na Apple silicon Secure Enclave podpisuje `LocalPolicy` dla każdej grupy woluminów uruchamiania; nonce przechowywany w Secure Storage Component zapewnia ochronę przed replay. W związku z tym zmiana właściwości NVRAM o podobnej nazwie sama w sobie nie przepisuje zaakceptowanej boot policy.<sup>[[1]](#references)[[4]](#references)</sup>

## Dostęp do NVRAM z przestrzeni użytkownika

### Odczyt i zebranie wartości bazowych
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
Nie klasyfikuj każdego nieznanego klucza jako złośliwego. Sprzęt, recoveryOS, aktualizacje, Find My i nieudane uruchomienia tworzą zmienne zależne od modelu i wersji. Porównaj przechwycone dane z wcześniejszym punktem odniesienia z **tego samego Maca** i traktuj nieoczekiwane binarne bloby, zmieniony wybór uruchamiania lub argumenty obniżające poziom bezpieczeństwa jako wskazówki, a nie dowód włamania.

### Writing NVRAM

Root może tworzyć lub zmieniać wiele zwykłych zmiennych, ale zmienne chronione zależą dodatkowo od przestrzeni nazw zmiennej, SIP, reguł jądra dotyczących poszczególnych zmiennych oraz ograniczonych uprawnień Apple. Dlatego pomyślne wykonanie `sudo` dla nieszkodliwego niestandardowego klucza **nie** dowodzi, że proces może modyfikować `boot-args`, SIP lub zmienne regionu systemowego.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Unikaj `nvram -c` podczas testów: żąda usunięcia wszystkich usuwalnych zmiennych i może zmienić zachowanie podczas uruchamiania lub odzyskiwania systemu. Niektóre zmienne są dostępne wyłącznie dla kernela, chronione przez entitlement, ukryte podczas odczytu lub możliwe do usunięcia tylko podczas resetowania NVRAM.

## Entitlements NVRAM i `CS_NVRAM_UNRESTRICTED`

W czasie exec XNU mapuje `com.apple.rootless.restricted-nvram-variables.heritable` na flagę procesu **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Nie jest to równoważne zwykłemu sprawdzeniu efektywnego UID 0. Istnieją również węższe prywatne entitlements dotyczące określonych zmiennych lub operacji.

Sprawdzaj entitlements zamiast polegać na ogólnym wierszu flag wyświetlanym przez `codesign`:
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
Podczas audytu uprzywilejowanego helpera prześledź **rzeczywistą tożsamość klienta i ścieżkę żądania**. Błąd confused-deputy w usłudze z entitlementem może być bardziej użyteczny niż bezpośrednie wywołanie `nvram`, ale dostępna zmienna/operacja może nadal podlegać ograniczeniom XNU.

## Stan SIP w systemie Intel a `LocalPolicy` w Apple Silicon

### Intel: `csr-active-config`

W systemach Intel `csr-active-config` koduje wyjątki `CSR_ALLOW_*`. Powszechnie istotne pozycje bitów to:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Odczytaj obowiązujące ustawienie za pomocą `csrutil status`; surowe dane wyjściowe `nvram` mogą używać bajtów little-endian zakodowanych procentowo. Zobacz [macOS SIP](../macos-security-protections/macos-sip.md), aby poznać implikacje dotyczące ochrony i bypass.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: sprawdzanie zaakceptowanej polityki uruchamiania

Na urządzeniach Apple silicon `sip0` w podpisanej przez Secure Enclave `LocalPolicy` zawiera bity polityki SIP, które wcześniej były przechowywane w NVRAM. Pozostałe istotne pola polityki to `sip1` (zezwalanie na niepowodzenie weryfikacji root-hash SSV), `sip2` (nieblokowanie pamięci jądra za pomocą CTRR) oraz `sip3` (wyłączenie listy dozwolonych `boot-args` w iBoot). Te pola można modyfikować wyłącznie z powiązanego One True recoveryOS (1TR); włączenie `sip3` wymaga również przejścia na Permissive Security.<sup>[[4]](#references)</sup>

Podczas enumeracji używaj wyłącznie operacji wyświetlania:
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> Nie używaj opcji zmieniających politykę `bputil` podczas audytu. Zwykłe przejęcie systemu macOS nie powinno umożliwiać cichego włączenia powyższych pól: ścieżka downgrade celowo wymaga fizycznego dostępu do sparowanego 1TR oraz uwierzytelnienia właściciela.<sup>[[4]](#references)</sup>

## Implikacje bezpieczeństwa

### `boot-args` jako wzmacniacz po przejęciu

Argumenty takie jak opcje debugowania kernela, `kcsuffix=development` lub `amfi_get_out_of_my_way=1` mogą osłabić późniejsze etapy bootowania, ale tylko wtedy, gdy platforma je zaakceptuje. Na Apple silicon w trybie Full lub Reduced Security iBoot filtruje argumenty zmniejszające bezpieczeństwo; nieograniczone argumenty wymagają opisanego wyżej downgrade polityki `sip3`. Na Intel ograniczenie NVRAM przez SIP podobnie uniemożliwia traktowanie powłoki root jako automatycznej kontroli nad `boot-args`.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Zobacz [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) oraz [kernel debugging](macos-kernel-extensions.md), zamiast zakładać, że historyczny argument zachowuje się identycznie w każdej wersji macOS.

### Wykonywanie `rc.trampoline` z użyciem NVRAM

Niedawne badania udokumentowały konkretny komponent korzystający z danych NVRAM: binarny plik platformy Apple `/System/Library/CoreServices/rc.trampoline`. Gdy launchd wykryje argument rozruchowy `rc.trampoline=1`, to zadanie rozruchowe odczytuje właściwość `apple-trusted-trampoline` z `IODeviceTree:/options`, zapisuje ją do tymczasowego pliku wykonywalnego, uruchamia go w stanie wstrzymania, sprawdza jego stan code-signing, usuwa go za pomocą unlink, a następnie wznawia jego działanie. Zadanie rozruchowe blokuje launchd do momentu zakończenia procesu potomnego.<sup>[[5]](#references)</sup>

Jest to **prymityw persistence po downgrade, a nie obejście SIP**. Zademonstrowana ścieżka wymagała wyłączenia SIP, aby zadanie rozruchowe zostało uruchomione i można było ustawić `boot-args`. Badania zaobserwowały również przybliżony limit rozmiaru wartości wynoszący 390 KB. Wartość tego rozwiązania polega na tym, że bajty pliku wykonywalnego mogą znajdować się poza zwykłym filesystemem i zostać zmaterializowane podczas bootowania, gdy atakujący uzyskał już wymagany security downgrade.<sup>[[5]](#references)</sup>

Szukaj obu wymaganych artefaktów oraz zdarzenia launchd:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Niestandardowe zmienne NVRAM są w przeciwnym razie wyłącznie **magazynem danych**: nie wykonują żadnych działań, chyba że wykorzysta je firmware, komponent rozruchowy Apple lub oddzielny mechanizm persistence. To rozróżnienie zapobiega przecenianiu znaczenia znacznika takiego jak `nvram attacker-config=...` jako wykonania kodu firmware.

## Skrypt enumeracji

<details>
<summary>Audyt NVRAM i boot-policy dla Apple silicon</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Przewodnik Apple Platform Security — Proces uruchamiania](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Aktualizacje zabezpieczeń Apple — CVE związane z NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Bezpieczeństwo Apple T2](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Zawartość pliku LocalPolicy dla Maca z układem Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Poza dobrymi starymi LaunchAgents — Utrwalanie za pomocą NVRAM z apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
