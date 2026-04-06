# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

**NVRAM** (Nie-volatiel lukraaktoeganggeheue) stoor **opstart- en firmwarevlak-konfigurasie** op Mac-hardware. Die mees sekuriteit-kritiese veranderlikes sluit in:

| Veranderlike | Doel |
|---|---|
| `boot-args` | Kernel opstart-argumente (debug-vlae, uitvoerige opstart, AMFI-omseiling) |
| `csr-active-config` | **SIP-konfigurasie-bitmasker** — beheer watter beskermings aktief is |
| `SystemAudioVolume` | Geluidsvolume tydens opstart |
| `prev-lang:kbd` | Voorkeurtaal / sleutelbordindeling |
| `efi-boot-device-data` | Keuse van opstartapparaat |

Op moderne Macs is NVRAM-veranderlikes verdeel tussen **stelsel**-veranderlikes (beskerm deur Secure Boot) en **nie-stelsel**-veranderlikes. Apple Silicon Macs gebruik 'n **Secure Storage Component (SSC)** om NVRAM-status kriptografies aan die opstartketting te bind.

## NVRAM-toegang vanaf gebruikersruimte

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
### Skryf NVRAM

Om NVRAM-veranderlikes te skryf vereis **root privileges**, en vir stelselkritieke veranderlikes (soos `csr-active-config`) moet die proses spesifieke code-signing flags of entitlements hê:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Flag

Binêre met die **`CS_NVRAM_UNRESTRICTED`** code-signing flag kan NVRAM-veranderlikes wysig wat normaalweg selfs deur root beskerm is.

### NVRAM-Unrestricted binêre opspoor
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Sekuriteitsimplikasies

### Verswakking van SIP via NVRAM

Indien 'n aanvaller na NVRAM kan skryf (hetsy deur 'n gekompromitteerde NVRAM-unrestricted binary of deur 'n kwetsbaarheid uit te buit), kan hulle `csr-active-config` wysig om **SIP-beskermings by die volgende opstart uit te skakel**:
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
> Op moderne Apple Silicon Macs valideer die **Secure Boot-ketting** NVRAM-wijzigings en verhoed dat SIP tydens runtime gewysig word. Veranderinge aan `csr-active-config` tree slegs in werking via recoveryOS. Op **Intel Macs** of stelsels met **reduced security mode** kan NVRAM-manipulasie egter steeds SIP verswak.

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

NVRAM-wysigings **oorleef OS-herinstallering** — hulle bly op die firmwarevlak. ’n aanvaller kan pasgemaakte NVRAM-variabeles skryf wat ’n persistence mechanism by opstart lees:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM-persistensie oorleef die uitvee van skywe en herinstallering van die OS. Dit vereis **PRAM/NVRAM reset** (Command+Option+P+R op Intel Macs) of **DFU restore** (Apple Silicon) om dit skoon te maak.

### AMFI Bypass

Die `amfi_get_out_of_my_way=1` boot-argument deaktiveer **Apple Mobile File Integrity**, wat ongesigneerde kode toelaat om uitgevoer te word:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## Werklike CVEs

| CVE | Beskrywing |
|---|---|
| CVE-2020-9839 | NVRAM-manipulasie wat 'n volgehoue SIP-omseiling moontlik maak |
| CVE-2019-8779 | Firmwarevlak NVRAM-persistentie op T2 Macs |
| CVE-2022-22583 | PackageKit NVRAM-verwant privilege escalation |
| CVE-2020-10004 | Logika-kwessie in NVRAM-hantering wat stelselmodifikasie toelaat |

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
## Verwysings

* [Apple Platform Security Guide — Opstartproses](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Sekuriteitsopdaterings — NVRAM-verwante CVEs](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 Sekuriteit](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
