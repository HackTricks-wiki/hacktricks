# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**NVRAM**（Non-Volatile Random-Access Memory，非易失性随机存取存储器）用于在 Mac 硬件上存储**启动时和固件级别的配置**。其中最关键的安全变量包括：

| 变量 | 用途 |
|---|---|
| `boot-args` | Kernel 启动参数（调试标志、详细启动、AMFI bypass） |
| `csr-active-config` | **SIP 配置位掩码**——控制哪些保护处于启用状态 |
| `SystemAudioVolume` | 启动时的音量 |
| `prev-lang:kbd` | 首选语言 / 键盘布局 |
| `efi-boot-device-data` | 启动设备选择 |

在现代 Mac 上，NVRAM 变量分为受 Secure Boot 保护的**系统**变量和**非系统**变量。Apple Silicon Mac 使用 **Secure Storage Component (SSC)**，通过加密方式将 NVRAM 状态绑定到启动链。<sup>[[1]](#references)</sup>

## 从 User Space 访问 NVRAM

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

写入 NVRAM 变量需要 **root 权限**；对于系统关键变量（如 `csr-active-config`），进程必须具有特定的 code-signing flags 或 entitlements：
```bash
# Set boot-args (requires root)
sudo nvram boot-args="debug=0x144 kcsuffix=development"

# Clear boot-args
sudo nvram -d boot-args

# Set a custom variable
sudo nvram MyCustomVar="persistence-value"
```
## CS_NVRAM_UNRESTRICTED 标志

带有 **`CS_NVRAM_UNRESTRICTED`** code-signing 标志的 Binaries 可以修改通常即使 root 也无法访问的受保护 NVRAM 变量。

### 查找 NVRAM-Unrestricted Binaries
```bash
# Check code signing flags for a binary
codesign -dvvv /usr/sbin/nvram 2>&1 | grep "flags="
```
## 安全影响

### 通过 NVRAM 弱化 SIP

如果攻击者能够写入 NVRAM（通过已被入侵的 NVRAM-unrestricted binary，或利用漏洞），他们就可以修改 `csr-active-config`，从而**在下次启动时禁用 SIP 保护**：
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
> 在现代 Apple Silicon Mac 上，**Secure Boot chain 会验证 NVRAM** 更改，并阻止在运行时修改 SIP。`csr-active-config` 更改只有通过 recoveryOS 才会生效。但是，在 **Intel Mac** 或处于 **reduced security mode** 的系统上，NVRAM 操作仍可能削弱 SIP。

### 启用 Kernel Debugging
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

NVRAM 修改**可在 OS 重新安装后继续存在**——它们会在 firmware 层面持久化。攻击者可以写入自定义 NVRAM 变量，某个 persistence mechanism 会在启动时读取这些变量：
```bash
# Write a persistence marker
nvram attacker-payload-config="base64_encoded_config_here"

# A startup script or LaunchDaemon could read this:
nvram attacker-payload-config 2>/dev/null && /path/to/payload
```
> [!CAUTION]
> NVRAM persistence 可在磁盘擦除和 OS 重装后继续存在。必须执行 **PRAM/NVRAM reset**（Intel Mac 上按下 Command+Option+P+R）或 **DFU restore**（Apple Silicon）才能清除。

### AMFI Bypass

`amfi_get_out_of_my_way=1` boot argument 会禁用 **Apple Mobile File Integrity**，从而允许 unsigned code 执行：
```bash
# This requires NVRAM write access AND reduced security boot:
sudo nvram boot-args="amfi_get_out_of_my_way=1"
```
## 真实世界中的 CVE

| CVE | 描述 |
|---|---|
| CVE-2020-9839 | 操纵 NVRAM，从而实现持久化 SIP 绕过 |
| CVE-2019-8779 | 在 T2 Mac 上实现固件级 NVRAM 持久化 |
| CVE-2022-22583 | 与 PackageKit NVRAM 相关的权限提升 |
| CVE-2020-10004 | NVRAM 处理中的逻辑问题，允许修改系统 |

## 枚举脚本
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

- [1] [Apple Platform Security Guide — 启动过程](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — 与 NVRAM 相关的 CVE](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 Security](https://duo.com/labs/research/apple-t2-xpc)

{{#include ../../../banners/hacktricks-training.md}}
