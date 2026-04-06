# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

**NVRAM** (Non-Volatile Random-Access Memory) huhifadhi **usanidi wa wakati wa boot na wa kiwango cha firmware** kwenye vifaa vya Mac. Vigezo muhimu zaidi kwa usalama ni pamoja na:

| Kigezo | Madhumuni |
|---|---|
| `boot-args` | Hoja za kuanzisha Kernel (bendera za debug, verbose boot, AMFI bypass) |
| `csr-active-config` | **SIP configuration bitmask** — inadhibiti ni ulinzi gani ziko hai |
| `SystemAudioVolume` | Kiasi cha sauti wakati wa boot |
| `prev-lang:kbd` | Lugha inayopendekezwa / mpangilio wa kibodi |
| `efi-boot-device-data` | Uteuzi wa kifaa cha boot |

Kwenye Mac za kisasa, vigezo vya NVRAM vimegawanywa kati ya vigezo vya **system** (vilivyo salama kwa Secure Boot) na vigezo vya **non-system**. Apple Silicon Macs hutumia **Secure Storage Component (SSC)** kuunga kwa kriptografia hali ya NVRAM kwenye mnyororo wa boot.

## NVRAM Access from User Space

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

Kuandika vigezo vya NVRAM kunahitaji **idhini za root**, na kwa vigezo muhimu kwa mfumo (kama `csr-active-config`), mchakato lazima uwe na bendera maalum za code-signing au entitlements:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED Flag

Binaries zilizo na **`CS_NVRAM_UNRESTRICTED`** code-signing flag zinaweza kubadilisha NVRAM variables ambazo kwa kawaida zinalindwa hata dhidi ya root.

### Kupata NVRAM-Unrestricted Binaries
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## Madhara ya Usalama

### Kudhoofisha SIP kupitia NVRAM

Ikiwa mshambuliaji anaweza kuandika kwenye NVRAM (ama kupitia binary iliyovamiwa ambayo haina vizuizi vya NVRAM au kwa kutumia udhaifu), wanaweza kubadili `csr-active-config` ili **kuzima ulinzi wa SIP kwenye uzinduzi ujao**:
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
> Kwenye Macs za Apple Silicon za kisasa, **mnyororo wa Secure Boot unathibitisha mabadiliko ya NVRAM** na unazuia urekebishaji wa SIP wakati wa runtime. Mabadiliko ya `csr-active-config` yataanza kufanya kazi tu kupitia recoveryOS. Hata hivyo, kwenye **Macs za Intel** au mifumo yenye **reduced security mode**, uendeshaji wa NVRAM bado unaweza kudhoofisha SIP.
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
### Uendelevu wa Firmware

Marekebisho ya NVRAM **huishi hata baada ya kusakinisha upya OS** — yanadumu katika ngazi ya firmware. Mshambuliaji anaweza kuandika vigezo maalum vya NVRAM ambavyo mekanismo ya uendelevu husoma wakati wa boot:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> Uendelevu wa NVRAM hudumu licha ya kufutwa kwa diski na ufungaji upya wa OS. Inahitaji **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) au **DFU restore** (Apple Silicon) ili kufutwa.

### AMFI Bypass

The `amfi_get_out_of_my_way=1` boot argument disables **Apple Mobile File Integrity**, ikiruhusu unsigned code kuendesha:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## CVE za Maisha Halisi

| CVE | Maelezo |
|---|---|
| CVE-2020-9839 | Ubadilishaji wa NVRAM unaowezesha persistent SIP bypass |
| CVE-2019-8779 | Firmware-level NVRAM persistence kwenye T2 Macs |
| CVE-2022-22583 | PackageKit privilege escalation zinazohusiana na NVRAM |
| CVE-2020-10004 | Tatizo la mantiki katika kushughulikia NVRAM linaloruhusu mabadiliko ya mfumo |

## Skiripti ya Uorodheshaji
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
## Marejeo

* [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
