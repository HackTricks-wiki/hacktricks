# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**NVRAM** (非易失性随机存取存储器) 在 Mac 硬件上存储 **启动时和固件级别的配置**。最安全关键的变量包括：

| 变量 | 目的 |
|---|---|
| `boot-args` | 内核启动参数（debug flags，verbose boot，AMFI bypass） |
| `csr-active-config` | **SIP configuration bitmask** — 控制哪些保护处于启用状态 |
| `SystemAudioVolume` | 启动时的音量 |
| `prev-lang:kbd` | 首选语言 / 键盘布局 |
| `efi-boot-device-data` | 启动设备选择 |

在现代 Mac 上，NVRAM 变量在 **system** 变量（受 Secure Boot 保护）和 **non-system** 变量之间划分。Apple Silicon Macs 使用 **Secure Storage Component (SSC)** 将 NVRAM 状态以加密方式绑定到引导链。

## NVRAM 在用户空间的访问

### 读取 NVRAM
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
### 写入 NVRAM

写入 NVRAM 变量需要 **root privileges**，并且对于系统关键变量（例如 `csr-active-config`），进程必须具有特定的代码签名标志或 entitlements：
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED 标志

带有 **`CS_NVRAM_UNRESTRICTED`** 代码签名标志的二进制文件可以修改通常即使是 root 也受保护的 NVRAM 变量。

### 查找 NVRAM-Unrestricted 二进制文件
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## 安全影响

### 通过 NVRAM 弱化 SIP

如果攻击者能够写入 NVRAM（无论是通过被攻破的 NVRAM-unrestricted binary，还是通过利用某个 vulnerability），他们可以修改 `csr-active-config` 以**在下一次启动时禁用 SIP 保护**：
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
> 在现代 Apple Silicon Macs 上，**Secure Boot chain 验证 NVRAM** 更改并阻止运行时 SIP 修改。`csr-active-config` 更改仅通过 `recoveryOS` 生效。然而，在 **Intel Macs** 或处于 **reduced security mode** 的系统上，NVRAM 操作仍可能削弱 SIP。
 
### 启用内核调试 (Enabling Kernel Debugging)
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
### 固件持久性

NVRAM 修改 **在 OS 重新安装后仍然保留** — 它们在固件级别持久存在。攻击者可以写入自定义 NVRAM 变量，持久化机制在 boot 时读取：
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM 持久性在擦除磁盘和重新安装操作系统后仍然存在。要清除它，需要 **PRAM/NVRAM reset** (Command+Option+P+R on Intel Macs) 或 **DFU restore** (Apple Silicon)。

### AMFI Bypass

该 `amfi_get_out_of_my_way=1` boot argument 禁用 **Apple Mobile File Integrity**，允许运行未签名的代码：
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## 真实世界的 CVEs

| CVE | 描述 |
|---|---|
| CVE-2020-9839 | NVRAM 操作导致 持久性 SIP bypass |
| CVE-2019-8779 | 在 T2 Macs 上的固件级别 NVRAM 持久化 |
| CVE-2022-22583 | PackageKit 与 NVRAM 相关的 privilege escalation |
| CVE-2020-10004 | NVRAM 处理中的逻辑问题，允许系统修改 |

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
## 参考资料

* [Apple 平台安全指南 — 启动过程](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
* [Apple 安全更新 — 与 NVRAM 相关的 CVEs](https://support.apple.com/en-us/HT201222)
* [Duo Labs — Apple T2 安全](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
