# NVRAM w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**NVRAM** (pamięć nieulotna o losowym dostępie) przechowuje **konfigurację uruchomienia i ustawienia na poziomie firmware** na sprzęcie Mac. Najbardziej krytyczne z punktu widzenia bezpieczeństwa zmienne to:

| Zmienna | Przeznaczenie |
|---|---|
| `boot-args` | Argumenty rozruchowe kernela (flagi debugowania, verbose boot, omijanie AMFI) |
| `csr-active-config` | **maska bitowa konfiguracji SIP** — kontroluje, które ochrony są aktywne |
| `SystemAudioVolume` | Poziom głośności przy uruchamianiu |
| `prev-lang:kbd` | Preferowany język / układ klawiatury |
| `efi-boot-device-data` | Wybór urządzenia rozruchowego |

W nowoczesnych Macach zmienne NVRAM są podzielone na **zmienne systemowe** (chronione przez Secure Boot) i **zmienne niesystemowe**. Maci z Apple Silicon używają **Secure Storage Component (SSC)** do kryptograficznego powiązania stanu NVRAM z łańcuchem rozruchowym.

## Dostęp do NVRAM z przestrzeni użytkownika

### Odczyt NVRAM
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

Zapis zmiennych NVRAM wymaga **root privileges** i — dla zmiennych krytycznych dla systemu (takich jak `csr-active-config`) — proces musi posiadać konkretne flagi podpisu kodu lub entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Flaga CS_NVRAM_UNRESTRICTED

Pliki binarne z code-signing flagą **`CS_NVRAM_UNRESTRICTED`** mogą modyfikować zmienne NVRAM, które normalnie są chronione nawet przed użytkownikiem root.

### Wyszukiwanie NVRAM-Unrestricted Binaries
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Implikacje bezpieczeństwa

### Osłabienie SIP przez NVRAM

Jeśli atakujący może zapisywać do NVRAM (np. poprzez skompromitowany NVRAM-unrestricted binary lub wykorzystując lukę), może zmodyfikować `csr-active-config`, aby **wyłączyć ochrony SIP przy następnym uruchomieniu**:
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
> Na nowoczesnych Apple Silicon Macach **łańcuch Secure Boot weryfikuje zmiany NVRAM** i zapobiega modyfikacjom SIP w czasie działania. Zmiany `csr-active-config` wchodzą w życie tylko przez recoveryOS. Jednak na **Intel Macs** lub systemach w **trybie zredukowanego bezpieczeństwa**, manipulacja NVRAM nadal może osłabić SIP.

### Włączanie debugowania jądra
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
### Trwałość firmware'u

Modyfikacje NVRAM **przetrwają reinstalację systemu operacyjnego** — utrzymują się na poziomie firmware. Atakujący może zapisać niestandardowe zmienne NVRAM, które są odczytywane przy rozruchu przez persistence mechanism:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> Zawartość NVRAM przetrwa wymazywanie dysku i ponowną instalację systemu. Aby ją wyczyścić, wymagana jest **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) lub **DFU restore** (Apple Silicon).

### AMFI Bypass

Argument rozruchowy `amfi_get_out_of_my_way=1` wyłącza **Apple Mobile File Integrity**, pozwalając na wykonanie niesignowanego kodu:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## Rzeczywiste CVE

| CVE | Opis |
|---|---|
| CVE-2020-9839 | Manipulacja NVRAM umożliwiająca trwałe obejście SIP |
| CVE-2019-8779 | Trwałość NVRAM na poziomie firmware w Macach z T2 |
| CVE-2022-22583 | PackageKit NVRAM-related privilege escalation |
| CVE-2020-10004 | Błąd logiczny w obsłudze NVRAM umożliwiający modyfikację systemu |

## Skrypt do enumeracji
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
## Źródła

* [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
