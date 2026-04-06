# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

**NVRAM** (Non-Volatile Random-Access Memory) stores **boot-time and firmware-level configuration** on Mac hardware. Najkritičnije promenljive za bezbednost uključuju:

| Variable | Svrha |
|---|---|
| `boot-args` | Kernel boot arguments (debug flags, verbose boot, AMFI bypass) |
| `csr-active-config` | **SIP configuration bitmask** — kontroliše koje zaštite su aktivne |
| `SystemAudioVolume` | Jačina zvuka pri pokretanju |
| `prev-lang:kbd` | Preferirani jezik / raspored tastature |
| `efi-boot-device-data` | Izbor uređaja za pokretanje |

Na modernim Mac računarima, NVRAM promenljive su podeljene između **system** promenljivih (zaštićenih pomoću Secure Boot) i **non-system** promenljivih. Apple Silicon Macs koriste **Secure Storage Component (SSC)** da kriptografski vežu NVRAM stanje za boot lanac.

## NVRAM Access from User Space

### Reading NVRAM
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
### Pisanje u NVRAM

Pisanje promenljivih u NVRAM zahteva **root privileges** i, za sistemski kritične promenljive (kao `csr-active-config`), proces mora imati određene code-signing flags ili entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Flag

Binaries sa **`CS_NVRAM_UNRESTRICTED`** code-signing flag mogu da menjaju NVRAM promenljive koje su obično zaštićene čak i od root korisnika.

### Pronalaženje NVRAM-Unrestricted Binaries
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Bezbednosne implikacije

### Slabljenje SIP-a putem NVRAM-a

Ako napadač može da piše u NVRAM (bilo putem kompromitovanog NVRAM-unrestricted binary ili iskorišćavanjem ranjivosti), može da izmeni `csr-active-config` kako bi **onemogućio SIP zaštite pri narednom pokretanju**:
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
> Na modernim Apple Silicon Mac-ovima, **Secure Boot chain** validira promene u NVRAM-u i sprečava runtime modifikaciju SIP-a. Promene u `csr-active-config` stupaju na snagu samo kroz recoveryOS. Međutim, na **Intel Macs** ili sistemima sa **reduced security mode**, manipulacija NVRAM-om i dalje može oslabiti SIP.

### Enabling Kernel Debugging
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
### Firmware Persistence

NVRAM izmene **prežive reinstalaciju OS-a** — one ostaju na nivou firmvera. Napadač može upisati prilagođene NVRAM promenljive koje mehanizam za persistenciju učitava pri pokretanju:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> Postojanost NVRAM-a preživi brisanje diska i ponovnu instalaciju OS-a. Za njegovo brisanje je potreban **PRAM/NVRAM reset** (Command+Option+P+R na Intel Macs) ili **DFU restore** (Apple Silicon) to clear.

### AMFI Bypass

Boot argument `amfi_get_out_of_my_way=1` onemogućava **Apple Mobile File Integrity**, omogućavajući izvršavanje unsigned code:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE-ovi iz stvarnog sveta

| CVE | Opis |
|---|---|
| CVE-2020-9839 | Manipulacija NVRAM-om koja omogućava trajno zaobilaženje SIP-a |
| CVE-2019-8779 | Perzistencija NVRAM-a na nivou firmvera na T2 Macs |
| CVE-2022-22583 | PackageKit, vezano za NVRAM, privilege escalation |
| CVE-2020-10004 | Logička greška u rukovanju NVRAM-om koja omogućava modifikaciju sistema |

## Skript za enumeraciju
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
## Izvori

* [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
