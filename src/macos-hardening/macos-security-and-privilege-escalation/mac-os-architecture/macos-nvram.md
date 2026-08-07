# NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

**NVRAM** (Non-Volatile Random-Access Memory) huhifadhi **usanidi wa wakati wa kuwasha na wa kiwango cha firmware** kwenye hardware ya Mac. Vigezo muhimu zaidi vya usalama ni pamoja na:

| Kigezo | Kusudi |
|---|---|
| `boot-args` | Hoja za kuwasha kernel (debug flags, kuwasha kwa verbose, AMFI bypass) |
| `csr-active-config` | **SIP configuration bitmask** — hudhibiti ni ulinzi gani ulio hai |
| `SystemAudioVolume` | Kiwango cha sauti wakati wa kuwasha |
| `prev-lang:kbd` | Lugha inayopendelewa / mpangilio wa keyboard |
| `efi-boot-device-data` | Uchaguzi wa kifaa cha kuwasha |

Kwenye Mac za kisasa, vigezo vya NVRAM hugawanywa kati ya vigezo vya **system** (vinavyolindwa na Secure Boot) na vigezo **visivyo vya system**. Mac zenye Apple Silicon hutumia **Secure Storage Component (SSC)** kuunganisha hali ya NVRAM kwa njia ya cryptographic na boot chain.<sup>[[1]](#references)</sup>

## Kufikia NVRAM kutoka User Space

### Kusoma NVRAM
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
### Kuandika NVRAM

Kuandika vigezo vya NVRAM kunahitaji **mapendeleo ya root** na, kwa vigezo muhimu vya mfumo (kama `csr-active-config`), mchakato lazima uwe na flags au entitlements maalum za code-signing:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## Bendera ya CS_NVRAM_UNRESTRICTED

Binaries zenye code-signing flag ya **`CS_NVRAM_UNRESTRICTED`** zinaweza kurekebisha variables za NVRAM ambazo kwa kawaida hulindwa hata dhidi ya root.

### Kutafuta Binaries Zisizo na Vizuizi vya NVRAM
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Athari za Usalama

### Kudhoofisha SIP kupitia NVRAM

Iwapo mshambuliaji anaweza kuandika kwenye NVRAM (ama kupitia binary iliyoathiriwa ya NVRAM-unrestricted au kwa kutumia vulnerability), anaweza kurekebisha `csr-active-config` ili **kuzima ulinzi wa SIP wakati wa boot inayofuata**:
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
> Kwenye Mac za kisasa zenye Apple Silicon, **Secure Boot chain** huthibitisha mabadiliko ya NVRAM na huzuia marekebisho ya SIP wakati wa runtime. Mabadiliko ya `csr-active-config` huanza kutumika tu kupitia recoveryOS. Hata hivyo, kwenye **Intel Macs** au mifumo yenye **reduced security mode**, manipulation ya NVRAM bado inaweza kudhoofisha SIP.

### Kuwezesha Kernel Debugging
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

Marekebisho ya NVRAM **yanaendelea kuwepo baada ya kusakinisha upya OS** — yanaendelea kuwepo katika kiwango cha firmware. Mshambuliaji anaweza kuandika variables maalum za NVRAM ambazo persistence mechanism husoma wakati wa boot:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> Uendelevu wa NVRAM hudumu hata baada ya kufuta disk na kusakinisha upya OS. Unahitaji **PRAM/NVRAM reset** (Command+Option+P+R kwenye Intel Macs) au **DFU restore** (Apple Silicon) ili kuufuta.

### AMFI Bypass

Boot argument ya `amfi_get_out_of_my_way=1` huzima **Apple Mobile File Integrity**, na kuruhusu code isiyotiwa saini kutekelezwa:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE za Ulimwengu Halisi

| CVE | Maelezo |
|---|---|
| CVE-2020-9839 | Udhibiti wa NVRAM unaowezesha SIP bypass endelevu <sup>[[2]](#references)</sup> |
| CVE-2019-8779 | Persistence ya NVRAM katika kiwango cha firmware kwenye Mac zenye T2 <sup>[[3]](#references)</sup> |
| CVE-2022-22583 | Privilege escalation inayohusiana na NVRAM katika PackageKit |
| CVE-2020-10004 | Tatizo la kimantiki katika ushughulikiaji wa NVRAM linaloruhusu marekebisho ya mfumo |

## Script ya Enumeration
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
## Marejeleo

- [1] [Apple Platform Security Guide — Mchakato wa kuwasha](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — CVEs zinazohusiana na NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Usalama wa Apple T2](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
