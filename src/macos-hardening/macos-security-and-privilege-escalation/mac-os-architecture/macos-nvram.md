# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**NVRAM** (Non-Volatile Random-Access Memory) przechowuje **konfigurację uruchamiania i konfigurację na poziomie firmware** na sprzęcie Mac. Najważniejsze z punktu widzenia bezpieczeństwa zmienne obejmują:

| Zmienna | Przeznaczenie |
|---|---|
| `boot-args` | Argumenty uruchamiania kernela (flagi debugowania, tryb verbose podczas uruchamiania, AMFI bypass) |
| `csr-active-config` | **Maska bitowa konfiguracji SIP** — kontroluje, które zabezpieczenia są aktywne |
| `SystemAudioVolume` | Głośność dźwięku podczas uruchamiania |
| `prev-lang:kbd` | Preferowany język / układ klawiatury |
| `efi-boot-device-data` | Wybór urządzenia rozruchowego |

Na współczesnych komputerach Mac zmienne NVRAM są podzielone na zmienne **systemowe** (chronione przez Secure Boot) oraz **niesystemowe**. Komputery Mac z układami Apple Silicon używają **Secure Storage Component (SSC)** do kryptograficznego powiązania stanu NVRAM z łańcuchem uruchamiania.<sup>[1]</sup>

## Dostęp do NVRAM z przestrzeni użytkownika

### Odczytywanie NVRAM
```bash
# List all NVRAM variables
nvram -p

# Read a specific variable
nvram boot-args

# Export all NVRAM as XML plist
nvram -xp

# Read SIP configuration
nvram csr-active-config
csrutil status
```
### Zapisywanie NVRAM

Zapisywanie zmiennych NVRAM wymaga **uprawnień root**, a w przypadku zmiennych krytycznych dla systemu (takich jak `csr-active-config`) proces musi mieć określone flagi podpisywania kodu lub uprawnienia:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Flaga CS_NVRAM_UNRESTRICTED

Pliki binarne z flagą podpisywania kodu **`CS_NVRAM_UNRESTRICTED`** mogą modyfikować zmienne NVRAM, które są zwykle chronione nawet przed root.

### Znajdowanie plików binarnych z ograniczeniem NVRAM usuniętym
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Konsekwencje dla bezpieczeństwa

### Osłabianie SIP za pośrednictwem NVRAM

Jeśli atakujący może zapisywać dane w NVRAM (np. za pośrednictwem przejętego pliku binarnego `NVRAM-unrestricted` lub wykorzystując lukę w zabezpieczeniach), może zmodyfikować `csr-active-config`, aby **wyłączyć zabezpieczenia SIP przy następnym uruchomieniu systemu**:
```bash
# SIP configuration is a bitmask stored in NVRAM
# Each bit controls a different SIP protection:
#   Bit 0 (0x1):  Filesystem protection
#   Bit 1 (0x2):  Kext signing
#   Bit 2 (0x4):  Task-for-pid restriction
#   Bit 3 (0x8):  Unrestricted filesystem
#   Bit 4 (0x10): Apple Internal (debug)
#   Bit 5 (0x20): Unrestricted DTrace
#   Bit 6 (0x40): Unrestricted NVRAM
#   Bit 7 (0x80): Device configuration

# Current SIP configuration
nvram csr-active-config | xxd

# On older hardware, a compromised NVRAM-unrestricted binary could:
# nvram csr-active-config=%7f%00%00%00   # Disable most SIP protections
```
> [!WARNING]
> Na nowoczesnych komputerach Mac z układem Apple Silicon **Secure Boot chain** sprawdza zmiany w NVRAM i uniemożliwia modyfikację SIP w czasie działania systemu. Zmiany `csr-active-config` zaczynają obowiązywać wyłącznie za pośrednictwem recoveryOS. Jednak na komputerach Mac z procesorami **Intel** lub w systemach z **reduced security mode** manipulowanie NVRAM nadal może osłabić SIP.

### Włączanie debugowania kernela
```bash
# Enable kernel debug flags via boot-args
sudo nvram boot-args="debug=0x144"

# Common debug flags:
#   0x01  DB_HALT      — Wait for debugger at boot
#   0x04  DB_KPRT      — Send kernel printf to serial
#   0x40  DB_KERN_DUMP — Dump kernel core on NMI
#   0x100 DB_REBOOT_POST_PANIC — Reboot after panic

# Use development kernel
sudo nvram boot-args="kcsuffix=development"
```
### Persistence w firmware

Modyfikacje NVRAM **przetrwają ponowną instalację systemu operacyjnego** — utrzymują się na poziomie firmware. Atakujący może zapisać niestandardowe zmienne NVRAM, które mechanizm persistence odczyta podczas uruchamiania systemu:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> Persistence w NVRAM przetrwa wyczyszczenie dysku i ponowną instalację systemu operacyjnego. Do jej usunięcia wymagany jest **reset PRAM/NVRAM** (Command+Option+P+R na komputerach Mac z procesorem Intel) lub **DFU restore** (Apple Silicon).

### AMFI Bypass

Argument startowy `amfi_get_out_of_my_way=1` wyłącza **Apple Mobile File Integrity**, umożliwiając wykonywanie niepodpisanego kodu:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE z rzeczywistych przypadków

| CVE | Opis |
|---|---|
| CVE-2020-9839 | Manipulacja NVRAM umożliwiająca trwałe obejście SIP |
| CVE-2019-8779 | Trwałość na poziomie firmware NVRAM na komputerach Mac z układem T2 |
| CVE-2022-22583 | Eskalacja uprawnień związana z NVRAM w PackageKit |
| CVE-2020-10004 | Problem logiczny w obsłudze NVRAM umożliwiający modyfikację systemu |

## Skrypt enumeracji
```bash
#!/bin/bash
echo "=== NVRAM Security Audit ==="

# Current SIP status
echo -e "\n[*] SIP Status:"
csrutil status

# Current boot-args
echo -e "\n[*] Boot Arguments:"
nvram boot-args 2>/dev/null || echo "  (none set)"

# All NVRAM variables
echo -e "\n[*] All NVRAM Variables:"
nvram -p | grep -v "^$" | wc -l
echo "  variables total"

# Security-relevant variables
echo -e "\n[*] Security-Relevant Variables:"
for var in csr-active-config boot-args StartupMute SystemAudioVolume efi-boot-device; do
echo "  $var: $(nvram "$var" 2>/dev/null || echo 'not set')"
done

# Check for custom (non-Apple) variables
echo -e "\n[*] Non-Standard Variables (potential persistence):"
nvram -p | grep -v "^$" | grep -vE "^(SystemAudioVolume|boot-args|csr-active-config|prev-lang|LocationServicesEnabled|fmm-mobileme-token|bluetoothInternalControllerAddress|bluetoothActiveControllerInfo|SystemAudioVolumeExtension|efi-)" | head -20
```
## Odnośniki

- [1] [Apple Platform Security Guide — Proces uruchamiania](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — CVE związane z NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Bezpieczeństwo Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
