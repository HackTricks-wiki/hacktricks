# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

**NVRAM** (비휘발성 랜덤 액세스 메모리)은 Mac 하드웨어에서 **부팅 시 및 펌웨어 수준 설정**을 저장합니다. 보안상 가장 중요한 변수는 다음과 같습니다:

| Variable | Purpose |
|---|---|
| `boot-args` | 커널 부팅 인수 (디버그 플래그, verbose 부팅, AMFI bypass) |
| `csr-active-config` | **SIP 구성 비트마스크** — 어떤 보호 기능이 활성화되어 있는지 제어합니다 |
| `SystemAudioVolume` | 부팅 시 오디오 볼륨 |
| `prev-lang:kbd` | 선호 언어 / 키보드 레이아웃 |
| `efi-boot-device-data` | 부팅 장치 선택 |

최신 Mac에서는 NVRAM 변수들이 **system** 변수(Secure Boot으로 보호됨)와 **non-system** 변수로 분리됩니다. Apple Silicon Mac은 NVRAM 상태를 부팅 체인에 암호학적으로 바인딩하기 위해 **Secure Storage Component (SSC)**를 사용합니다.

## 사용자 공간에서의 NVRAM 접근

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

NVRAM 변수를 쓰려면 **루트 권한**이 필요하며, 시스템에 중요한 변수(예: `csr-active-config`)의 경우 프로세스에 특정 코드 서명 플래그나 권한이 있어야 합니다:
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED 플래그

**`CS_NVRAM_UNRESTRICTED`** 코드 서명 플래그가 있는 바이너리는 보통 root로부터도 보호되는 NVRAM 변수를 수정할 수 있습니다.

### NVRAM 제한 해제 바이너리 찾기
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## 보안 영향

### NVRAM을 통한 SIP 약화

공격자가 NVRAM에 쓸 수 있다면 (침해된 NVRAM-unrestricted binary를 통해서든, 취약점을 이용하든), `csr-active-config`를 수정하여 **다음 부팅 시 SIP 보호를 비활성화할 수 있습니다**:
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
> 최신 Apple Silicon Mac에서는 **Secure Boot 체인이 NVRAM 변경을 검증**하여 런타임에서의 SIP 수정을 방지합니다. `csr-active-config` 변경은 recoveryOS를 통해서만 적용됩니다. 그러나 **Intel Macs**이나 **reduced security mode**인 시스템에서는 NVRAM 조작이 여전히 SIP를 약화시킬 수 있습니다.

### 커널 디버깅 활성화
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
### 펌웨어 지속성

NVRAM 수정을 하면 **OS 재설치 후에도 유지된다** — 이들은 펌웨어 레벨에 남아있다. 공격자는 부팅 시 영속성 메커니즘이 읽는 커스텀 NVRAM 변수를 쓸 수 있다:
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM의 지속성은 디스크 초기화 및 OS 재설치 이후에도 유지됩니다. 이를 지우려면 **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) 또는 **DFU restore** (Apple Silicon)가 필요합니다.

### AMFI Bypass

부트 인자 `amfi_get_out_of_my_way=1`은 **Apple Mobile File Integrity**를 비활성화하여 서명되지 않은 코드가 실행되도록 허용합니다:
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## 실제 CVE

| CVE | 설명 |
|---|---|
| CVE-2020-9839 | 영구적인 SIP 우회를 가능하게 하는 NVRAM 조작 |
| CVE-2019-8779 | T2 Mac에서 펌웨어 수준의 NVRAM 지속성 |
| CVE-2022-22583 | PackageKit의 NVRAM 관련 권한 상승 |
| CVE-2020-10004 | 시스템 수정을 허용하는 NVRAM 처리의 논리적 문제 |

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
## 참고자료

* [Apple Platform Security Guide — 부트 프로세스](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple Security Updates — NVRAM 관련 CVE](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 보안](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
