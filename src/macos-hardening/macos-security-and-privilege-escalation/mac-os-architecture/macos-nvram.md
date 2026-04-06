# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**NVRAM** (Non-Volatile Random-Access Memory) stores **boot-time and firmware-level configuration** on Mac hardware. The most security-critical variables include:

| Variable | Purpose |
|---|---|
| `boot-args` | Kernel boot arguments (debug flags, verbose boot, AMFI bypass) |
| `csr-active-config` | **SIP configuration bitmask** — controls which protections are active |
| `SystemAudioVolume` | Audio volume at boot |
| `prev-lang:kbd` | Preferred language / keyboard layout |
| `efi-boot-device-data` | Boot device selection |

On modern Macs, NVRAM variables are split between **system** variables (protected by Secure Boot) and **non-system** variables. Apple Silicon Macs use a **Secure Storage Component (SSC)** to cryptographically bind NVRAM state to the boot chain.

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

### Writing NVRAM

Writing NVRAM variables requires **root privileges** and, for system-critical variables (like `csr-active-config`), the process must have specific code-signing flags or entitlements:

```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```

## CS_NVRAM_UNRESTRICTED Flag

Binaries with the **`CS_NVRAM_UNRESTRICTED`** code-signing flag can modify NVRAM variables that are normally protected even from root.

### Finding NVRAM-Unrestricted Binaries

```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```

## Security Implications

### Weakening SIP via NVRAM

If an attacker can write to NVRAM (either through a compromised NVRAM-unrestricted binary or by exploiting a vulnerability), they can modify `csr-active-config` to **disable SIP protections on next boot**:

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
> On modern Apple Silicon Macs, the **Secure Boot chain validates NVRAM** changes and prevents runtime SIP modification. `csr-active-config` changes only take effect through recoveryOS. However, on **Intel Macs** or systems with **reduced security mode**, NVRAM manipulation can still weaken SIP.

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

NVRAM modifications **survive OS reinstallation** — they persist at the firmware level. An attacker can write custom NVRAM variables that a persistence mechanism reads at boot:

```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```

> [!CAUTION]
> NVRAM persistence survives disk wipes and OS reinstalls. It requires **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) or **DFU restore** (Apple Silicon) to clear.

### AMFI Bypass

The `amfi_get_out_of_my_way=1` boot argument disables **Apple Mobile File Integrity**, allowing unsigned code to execute:

```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```

## Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2020-9839 | NVRAM manipulation enabling persistent SIP bypass |
| CVE-2019-8779 | Firmware-level NVRAM persistence on T2 Macs |
| CVE-2022-22583 | PackageKit NVRAM-related privilege escalation |
| CVE-2020-10004 | Logic issue in NVRAM handling allowing system modification |

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

* [Apple Platform Security Guide — Boot process](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM-related CVEs](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
