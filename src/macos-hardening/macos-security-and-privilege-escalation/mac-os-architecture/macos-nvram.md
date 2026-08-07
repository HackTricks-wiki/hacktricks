# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

**NVRAM** (Non-Volatile Random-Access Memory) Mac hardware पर **boot-time और firmware-level configuration** को store करता है। सबसे security-critical variables में शामिल हैं:

| Variable | Purpose |
|---|---|
| `boot-args` | Kernel boot arguments (debug flags, verbose boot, AMFI bypass) |
| `csr-active-config` | **SIP configuration bitmask** — यह नियंत्रित करता है कि कौन-सी protections active हैं |
| `SystemAudioVolume` | Boot के समय audio volume |
| `prev-lang:kbd` | Preferred language / keyboard layout |
| `efi-boot-device-data` | Boot device selection |

Modern Macs पर, NVRAM variables को **system** variables (Secure Boot द्वारा protected) और **non-system** variables के बीच विभाजित किया जाता है। Apple Silicon Macs NVRAM state को boot chain के साथ cryptographically bind करने के लिए **Secure Storage Component (SSC)** का उपयोग करते हैं।<sup>[[1]](#references)</sup>

## User Space से NVRAM Access

### NVRAM पढ़ना
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
### NVRAM लिखना

NVRAM variables को लिखने के लिए **root privileges** आवश्यक हैं और system-critical variables (जैसे `csr-active-config`) के लिए process में specific code-signing flags या entitlements होने चाहिए:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Flag

**`CS_NVRAM_UNRESTRICTED`** code-signing flag वाली binaries उन NVRAM variables को modify कर सकती हैं जो सामान्यतः root से भी protected होती हैं।

### NVRAM-Unrestricted Binaries को ढूँढना
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Security Implications

### NVRAM के माध्यम से SIP को कमजोर करना

यदि कोई attacker NVRAM में write कर सकता है (या तो किसी compromised NVRAM-unrestricted binary के माध्यम से या किसी vulnerability का exploitation करके), तो वह `csr-active-config` को modify करके **next boot पर SIP protections को disable** कर सकता है:
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
> आधुनिक Apple Silicon Macs पर **Secure Boot chain NVRAM** में किए गए बदलावों को validate करती है और runtime SIP modification को रोकती है। `csr-active-config` में किए गए बदलाव केवल recoveryOS के माध्यम से प्रभावी होते हैं। हालांकि, **Intel Macs** या **reduced security mode** वाले systems पर NVRAM manipulation अब भी SIP को कमजोर कर सकती है।

### Kernel Debugging सक्षम करना
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

NVRAM में किए गए modifications **OS reinstallation के बाद भी survive करते हैं** — वे firmware level पर persist रहते हैं। Attacker custom NVRAM variables लिख सकता है, जिन्हें कोई persistence mechanism boot के समय read करता है:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM persistence disk wipes और OS reinstalls के बाद भी बनी रहती है। इसे clear करने के लिए **PRAM/NVRAM reset** (Intel Macs पर Command+Option+P+R) या **DFU restore** (Apple Silicon) आवश्यक है।

### AMFI Bypass

`amfi_get_out_of_my_way=1` boot argument **Apple Mobile File Integrity** को disable कर देता है, जिससे unsigned code execute हो सकता है:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## वास्तविक दुनिया के CVEs

| CVE | विवरण |
|---|---|
| CVE-2020-9839 | लगातार SIP bypass सक्षम करने वाला NVRAM manipulation <sup>[[2]](#references)</sup> |
| CVE-2019-8779 | T2 Macs पर firmware-level NVRAM persistence <sup>[[3]](#references)</sup> |
| CVE-2022-22583 | PackageKit से संबंधित NVRAM privilege escalation |
| CVE-2020-10004 | NVRAM handling में logic issue, जिससे system modification संभव हुआ |

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
## संदर्भ

- [1] [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM-संबंधित CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
