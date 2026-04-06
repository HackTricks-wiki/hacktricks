# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

**NVRAM** (Non-Volatile Random-Access Memory) मैक हार्डवेयर पर बूट-समय और फर्मवेयर-स्तर की कॉन्फ़िगरेशन संग्रहीत करता है। सबसे अधिक सुरक्षा-सम्वेदनशील वेरिएबल्स में शामिल हैं:

| Variable | प्रयोजन |
|---|---|
| `boot-args` | Kernel बूट आर्ग्यूमेंट्स (डेबग फ़्लैग्स, verbose boot, AMFI bypass) |
| `csr-active-config` | **SIP configuration bitmask** — कौन-सी सुरक्षा सक्रिय हैं यह नियंत्रित करता है |
| `SystemAudioVolume` | बूट पर ऑडियो वॉल्यूम |
| `prev-lang:kbd` | प्राथमिक भाषा / कीबोर्ड लेआउट |
| `efi-boot-device-data` | बूट डिवाइस चयन |

आधुनिक Macs पर, NVRAM वेरिएबल्स सिस्टम वेरिएबल्स (जो Secure Boot द्वारा संरक्षित होते हैं) और non-system वेरिएबल्स में विभाजित होते हैं। Apple Silicon Macs एक Secure Storage Component (SSC) का उपयोग करते हैं जो NVRAM स्टेट को बूट श्रृंखला से क्रिप्टोग्राफ़िक रूप से बाँधता है।

## User Space से NVRAM एक्सेस

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
### NVRAM में लिखना

NVRAM वेरिएबल्स को लिखने के लिए **root privileges** की आवश्यकता होती है और सिस्टम-क्रिटिकल वेरिएबल्स (जैसे `csr-active-config`) के लिए, प्रोसेस के पास विशिष्ट code-signing flags या entitlements होना चाहिए:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED फ़्लैग

**`CS_NVRAM_UNRESTRICTED`** code-signing फ़्लैग वाले बाइनरी NVRAM वेरिएबल्स को संशोधित कर सकते हैं जो सामान्यतः root से भी संरक्षित होते हैं।

### NVRAM-Unrestricted Binaries की खोज
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## सुरक्षा निहितार्थ

### NVRAM के माध्यम से SIP कमजोर करना

यदि कोई हमलावर NVRAM में लिख सकता है (या तो किसी समझौता किए गए NVRAM-अप्रतिबंधित बाइनरी के माध्यम से या किसी कमज़ोरी का लाभ उठाकर), तो वे `csr-active-config` को संशोधित करके **अगली बूट पर SIP सुरक्षा को अक्षम** कर सकते हैं:
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
> आधुनिक Apple Silicon Macs पर, **Secure Boot chain NVRAM परिवर्तनों का सत्यापन करती है** और runtime पर SIP में संशोधन को रोकती है। `csr-active-config` के परिवर्तन केवल recoveryOS के माध्यम से ही प्रभावी होते हैं। हालांकि, **Intel Macs** या उन सिस्टमों में जिनमें **reduced security mode** है, NVRAM में हेरफेर फिर भी SIP को कमजोर कर सकता है।

### कर्नेल डिबगिंग सक्षम करना
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

NVRAM modifications **OS पुनर्स्थापना के बाद भी बचे रहते हैं** — वे फ़र्मवेयर स्तर पर बने रहते हैं। एक हमलावर कस्टम NVRAM variables लिख सकता है जिन्हें एक persistence mechanism बूट के समय पढ़ता है:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM persistence डिस्क वाइप और OS को फिर से इंस्टॉल करने के बाद भी बरकरार रहती है। इसे साफ़ करने के लिए **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) या **DFU restore** (Apple Silicon) की आवश्यकता होती है।

### AMFI Bypass

The `amfi_get_out_of_my_way=1` boot argument disables **Apple Mobile File Integrity**, allowing unsigned code to execute:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## वास्तविक दुनिया के CVEs

| CVE | विवरण |
|---|---|
| CVE-2020-9839 | NVRAM में हेरफेर जो स्थायी SIP bypass सक्षम करती है |
| CVE-2019-8779 | T2 Macs पर firmware-स्तर की NVRAM persistence |
| CVE-2022-22583 | PackageKit के NVRAM-संबंधित privilege escalation |
| CVE-2020-10004 | NVRAM हैंडलिंग में लॉजिक समस्या जो system modification की अनुमति देती है |

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

* [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
