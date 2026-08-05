# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

**NVRAM** (Non-Volatile Random-Access Memory) stoor **opstarttyd- en firmware-vlak-konfigurasie** op Mac-hardeware. Die sekuriteitskritiekste veranderlikes sluit in:

| Veranderlike | Doel |
|---|---|
| `boot-args` | Kernel-opstartargumente (debug-vlae, verbose boot, AMFI bypass) |
| `csr-active-config` | **SIP-konfigurasiebitmasker** — beheer watter beskermings aktief is |
| `SystemAudioVolume` | Klankvolume tydens opstart |
| `prev-lang:kbd` | Voorkeurtaal / sleutelborduitleg |
| `efi-boot-device-data` | Keuse van opstarttoestel |

Op moderne Macs word NVRAM-veranderlikes tussen **stelsel**-veranderlikes (beskerm deur Secure Boot) en **nie-stelsel**-veranderlikes verdeel. Apple Silicon Macs gebruik ’n **Secure Storage Component (SSC)** om NVRAM-toestand kriptografies aan die boot chain te bind.<sup>[[1]](#references)</sup>

## NVRAM-toegang vanuit User Space

### Lees van NVRAM
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
### Skryf na NVRAM

Om NVRAM-veranderlikes te skryf, word **root-voorregte** vereis, en vir stelsel-kritieke veranderlikes (soos `csr-active-config`) moet die proses spesifieke code-signing flags of entitlements hê:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Flag

Binaries met die **`CS_NVRAM_UNRESTRICTED`** code-signing flag kan NVRAM-veranderlikes wysig wat normaalweg selfs teen root beskerm word.

### Vind NVRAM-Unrestricted Binaries
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Sekuriteitsimplikasies

### Verswakking van SIP via NVRAM

As ’n aanvaller na NVRAM kan skryf (hetsy deur ’n gekompromitteerde NVRAM-unrestricted binary of deur ’n kwesbaarheid uit te buit), kan hulle `csr-active-config` wysig om **SIP-beskerming tydens die volgende selflaai te deaktiveer**:
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
> Op moderne Apple Silicon Macs valideer die **Secure Boot chain** veranderinge aan NVRAM en voorkom dit runtime SIP-wysigings. `csr-active-config`-veranderinge tree slegs deur recoveryOS in werking. Op **Intel Macs** of stelsels met **reduced security mode** kan NVRAM-manipulasie SIP egter steeds verswak.

### Aktivering van Kernel Debugging
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

NVRAM-wysigings **oorleef OS-herinstallasie** — hulle bly op firmware-vlak behoue. ’n Aanvaller kan pasgemaakte NVRAM-veranderlikes skryf wat ’n persistence-meganisme tydens selflaai lees:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM-volharding oorleef skyfuitwissings en OS-herinstallasies. Dit vereis **PRAM/NVRAM reset** (Command+Option+P+R op Intel Macs) of **DFU restore** (Apple Silicon) om dit te verwyder.

### AMFI Bypass

Die `amfi_get_out_of_my_way=1`-selflaaiargument deaktiveer **Apple Mobile File Integrity**, wat toelaat dat ongetekende code uitgevoer word:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## Werklike CVEs

| CVE | Beskrywing |
|---|---|
| CVE-2020-9839 | NVRAM-manipulasie wat persistente SIP bypass moontlik maak |
| CVE-2019-8779 | Firmware-vlak NVRAM-persistensie op T2 Macs |
| CVE-2022-22583 | PackageKit NVRAM-verwante privilege escalation |
| CVE-2020-10004 | Logika-kwessie in NVRAM-hantering wat stelselwysiging moontlik maak |

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
## References

- [1] [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
