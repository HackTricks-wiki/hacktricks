# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

**NVRAM** (Non-Volatile Random-Access Memory) čuva **konfiguraciju pri pokretanju i na nivou firmware-a** na Mac hardveru. Najvažnije promenljive sa stanovišta bezbednosti uključuju:

| Promenljiva | Svrha |
|---|---|
| `boot-args` | Argumenti za pokretanje kernela (debug zastavice, verbose boot, AMFI bypass) |
| `csr-active-config` | **Bitmask za SIP konfiguraciju** — kontroliše koje su zaštite aktivne |
| `SystemAudioVolume` | Jačina zvuka pri pokretanju |
| `prev-lang:kbd` | Preferirani jezik / raspored tastature |
| `efi-boot-device-data` | Izbor uređaja za pokretanje |

Na modernim Mac računarima, NVRAM promenljive su podeljene na **system** promenljive (zaštićene pomoću Secure Boot-a) i **non-system** promenljive. Mac računari sa Apple Silicon čipovima koriste **Secure Storage Component (SSC)** za kriptografsko povezivanje stanja NVRAM-a sa lancem pokretanja.<sup>[[1]](#references)</sup>

## Pristup NVRAM-u iz korisničkog prostora

### Čitanje NVRAM-a
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
### Upisivanje NVRAM-a

Upisivanje NVRAM promenljivih zahteva **root privilegije** i, za sistemski kritične promenljive (kao što je `csr-active-config`), proces mora imati određene flags za potpisivanje koda ili entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED zastavica

Binarni fajlovi sa **`CS_NVRAM_UNRESTRICTED`** zastavicom za potpisivanje koda mogu da menjaju NVRAM promenljive koje su obično zaštićene čak i od root korisnika.

### Pronalaženje binarnih fajlova sa ograničenjem NVRAM-a uklonjenim
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Bezbednosne implikacije

### Slabljenje SIP-a putem NVRAM-a

Ako napadač može da upisuje u NVRAM (bilo putem kompromitovanog NVRAM-unrestricted binary-ja ili iskorišćavanjem ranjivosti), može da izmeni `csr-active-config` kako bi **onemogućio SIP zaštite pri sledećem pokretanju sistema**:
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
> Na modernim Mac računarima sa Apple Silicon čipovima, **Secure Boot chain validira promene NVRAM-a** i sprečava izmene SIP-a tokom rada sistema. Promene `csr-active-config` imaju efekta samo kroz recoveryOS. Međutim, na **Intel Mac računarima** ili sistemima sa **reduced security mode**, manipulacija NVRAM-om i dalje može oslabiti SIP.

### Omogućavanje Kernel Debugging-a
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

NVRAM modifikacije **preživljavaju ponovnu instalaciju OS-a** — ostaju sačuvane na nivou firmvera. Napadač može da upiše prilagođene NVRAM promenljive koje mehanizam za persistence učitava pri pokretanju:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM persistence preživljava brisanje diskova i ponovne instalacije OS-a. Za njeno uklanjanje potreban je **PRAM/NVRAM reset** (Command+Option+P+R na Intel Mac računarima) ili **DFU restore** (Apple Silicon).

### AMFI Bypass

`amfi_get_out_of_my_way=1` boot argument onemogućava **Apple Mobile File Integrity**, omogućavajući izvršavanje nepotpisanog koda:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE-ovi iz stvarnog sveta

| CVE | Description |
|---|---|
| CVE-2020-9839 | Manipulacija NVRAM-om koja omogućava trajni SIP bypass <sup>[[2]](#references)</sup> |
| CVE-2019-8779 | NVRAM persistence na nivou firmware-a na T2 Mac računarima <sup>[[3]](#references)</sup> |
| CVE-2022-22583 | Privilege escalation povezan sa NVRAM-om u PackageKit-u |
| CVE-2020-10004 | Logički problem u rukovanju NVRAM-om koji omogućava izmenu sistema |

## Enumeration Script
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
## Reference

- [1] [Apple vodič za bezbednost platforme — proces pokretanja](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple bezbednosne ispravke — CVE-ovi povezani sa NVRAM-om](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 bezbednost](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
