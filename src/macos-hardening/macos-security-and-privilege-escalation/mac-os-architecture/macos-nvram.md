# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

**NVRAM**(Non-Volatile Random-Access Memory)은 Mac 하드웨어의 **부팅 시점 및 firmware 수준 구성**을 저장합니다. 보안상 가장 중요한 변수는 다음과 같습니다.

| 변수 | 목적 |
|---|---|
| `boot-args` | Kernel 부팅 인수(debug flags, verbose boot, AMFI bypass) |
| `csr-active-config` | **SIP 구성 bitmask** — 활성화된 보호 기능을 제어 |
| `SystemAudioVolume` | 부팅 시 오디오 볼륨 |
| `prev-lang:kbd` | 선호 언어 / 키보드 레이아웃 |
| `efi-boot-device-data` | 부팅 장치 선택 |

최신 Mac에서는 NVRAM 변수가 **system** 변수(Secure Boot로 보호됨)와 **non-system** 변수로 나뉩니다. Apple Silicon Mac은 **Secure Storage Component (SSC)**를 사용하여 NVRAM 상태를 boot chain에 암호학적으로 바인딩합니다.<sup>[[1]](#references)</sup>

## User Space에서의 NVRAM Access

### NVRAM 읽기
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
### NVRAM 쓰기

NVRAM 변수를 쓰려면 **root 권한**이 필요하며, 시스템 핵심 변수(예: `csr-active-config`)의 경우 프로세스에 특정 code-signing flags 또는 entitlements가 있어야 합니다:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED 플래그

**`CS_NVRAM_UNRESTRICTED`** code-signing 플래그가 있는 바이너리는 일반적으로 root로부터도 보호되는 NVRAM 변수를 수정할 수 있습니다.

### NVRAM-Unrestricted 바이너리 찾기
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## 보안 영향

### NVRAM을 통한 SIP 약화

공격자가 NVRAM에 쓸 수 있다면(손상된 `NVRAM-unrestricted` binary를 통하거나 취약점을 악용하여), `csr-active-config`를 수정해 **다음 부팅 시 SIP protections를 비활성화**할 수 있습니다:
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
> 최신 Apple Silicon Mac에서는 **Secure Boot chain이 NVRAM** 변경 사항을 검증하고 runtime SIP 수정을 방지합니다. `csr-active-config` 변경 사항은 recoveryOS를 통해서만 적용됩니다. 그러나 **Intel Mac** 또는 **reduced security mode**가 적용된 시스템에서는 NVRAM 조작으로 여전히 SIP가 약화될 수 있습니다.

### Kernel Debugging 활성화
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

NVRAM 수정은 **OS 재설치 후에도 유지**되며, firmware 레벨에서 지속됩니다. 공격자는 persistence mechanism이 부팅 시 읽는 custom NVRAM 변수를 작성할 수 있습니다:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM persistence는 디스크 삭제 및 OS 재설치 후에도 유지됩니다. 이를 제거하려면 **PRAM/NVRAM reset**(Intel Mac에서는 Command+Option+P+R) 또는 **DFU restore**(Apple Silicon)가 필요합니다.

### AMFI Bypass

`amfi_get_out_of_my_way=1` boot argument는 **Apple Mobile File Integrity**를 비활성화하여 unsigned code가 실행되도록 합니다:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## 실제 CVE

| CVE | 설명 |
|---|---|
| CVE-2020-9839 | 지속적인 SIP 우회를 가능하게 하는 NVRAM manipulation <sup>[[2]](#references)</sup> |
| CVE-2019-8779 | T2 Mac에서 firmware-level NVRAM persistence <sup>[[3]](#references)</sup> |
| CVE-2022-22583 | PackageKit NVRAM 관련 privilege escalation |
| CVE-2020-10004 | system modification을 가능하게 하는 NVRAM handling의 logic issue |

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
## 참고 자료

- [1] [Apple Platform Security Guide — 부팅 프로세스](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — NVRAM 관련 CVE](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 보안](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
