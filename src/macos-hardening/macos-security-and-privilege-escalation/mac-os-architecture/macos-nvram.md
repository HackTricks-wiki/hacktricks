# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**NVRAM**（Non-Volatile Random-Access Memory，非易失性随机访问存储器）在正常 macOS 文件系统之外存储固件和早期启动状态。其安全影响取决于变量本身以及启动架构：

| Variable | Purpose / security relevance |
|---|---|
| `boot-args` | 提供给 kernel 的参数。除非 boot policy 允许，否则会过滤调试参数或降低安全性的参数。 |
| `csr-active-config` | Intel Mac 上的 SIP 位掩码。在 Apple silicon 上，对应的 policy 存储在每个卷的 `LocalPolicy` 中，不会直接信任此变量。 |
| `efi-boot-device` / `efi-boot-device-data` | Intel EFI 启动目标。 |
| `boot-volume` | Apple silicon 启动卷选择状态。 |
| `SystemAudioVolume`、`prev-lang:kbd` | 普通持久化设置的示例。 |

重要区别在于，**存储在 NVRAM 中的数据**与**启动链接受的安全 policy**并不相同。在 Apple silicon 上，Secure Enclave 会为每个启动卷组签署 `LocalPolicy`；由 Secure Storage Component 保存的 nonce 提供 anti-replay 保护。因此，仅修改名称相似的 NVRAM property，并不会自行重写已接受的启动 policy。<sup>[[1]](#references)[[4]](#references)</sup>

## NVRAM Access from User Space

### Reading and Baseline Collection
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
不要将每个不熟悉的 key 都归类为恶意。Hardware、recoveryOS、updates、Find My 和 boot failures 都会创建依赖于型号和版本的 variables。将一次 capture 与来自**同一台 Mac**的较早 baseline 进行比较，并将意外的 binary blobs、发生变化的 boot selection 或会降低安全性的 arguments 视为线索，而非 compromise 的证据。

### Writing NVRAM

Root 可以创建或更改许多普通 variables，但受保护的 variables 还取决于 variable namespace、SIP、针对每个 variable 的 kernel rules 以及受限的 Apple entitlements。因此，`sudo` 能够成功处理一个无害的 custom key，**并不**证明该进程可以修改 `boot-args`、SIP 或 system-region variables。
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> 测试期间避免使用 `nvram -c`：它会请求删除所有可删除的变量，并可能改变启动/恢复行为。某些变量仅供 kernel 使用、受 entitlement 保护、读取时隐藏，或只能在 NVRAM 重置期间删除。

## NVRAM Entitlements 和 `CS_NVRAM_UNRESTRICTED`

在 exec 时，XNU 会将 `com.apple.rootless.restricted-nvram-variables.heritable` 映射到进程标志 **`CS_NVRAM_UNRESTRICTED`**（`0x00008000`）。这并不等同于普通的有效 UID 0 检查。此外，针对特定变量或操作，还存在范围更窄的私有 entitlements。

检查 entitlements，而不要依赖 `codesign` 打印的通用 flags 行：
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
审计特权 helper 时，应追踪**实际客户端身份和请求路径**。entitled service 中的 confused-deputy bug 可能比直接调用 `nvram` 更有用，但可访问的变量/操作仍可能受到 XNU 限制。

## Intel SIP 状态与 Apple Silicon `LocalPolicy`

### Intel：`csr-active-config`

在 Intel 上，`csr-active-config` 对 `CSR_ALLOW_*` 例外进行编码。通常相关的位位置如下：
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
使用 `csrutil status` 读取生效的设置；原始 `nvram` 输出可能使用百分号编码的小端字节。有关保护机制及 bypass 影响，请参阅 [macOS SIP](../macos-security-protections/macos-sip.md)。
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon：检查已接受的启动策略

在 Apple silicon 上，Secure Enclave 签名的 `LocalPolicy` 中的 `sip0` 保存了之前存储在 NVRAM 中的 SIP 策略位。其他相关的策略字段包括 `sip1`（允许 SSV root-hash 验证失败）、`sip2`（不使用 CTRR 锁定 kernel memory）和 `sip3`（禁用 iBoot 的 `boot-args` allowlist）。这些字段只能从配对的 One True recoveryOS（1TR）中修改；启用 `sip3` 还需要降级到 Permissive Security。<sup>[[4]](#references)</sup>

枚举期间仅使用 display 操作：
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> 在审计期间不要使用会更改 policy 的 `bputil` 选项。正常的 macOS compromise 不应能够静默开启上述字段：降级路径明确要求进入已配对的 1TR，并通过 owner authentication。<sup>[[4]](#references)</sup>

## Security Implications

### `boot-args` as a Post-Compromise Amplifier

诸如 kernel-debugging options、`kcsuffix=development` 或 `amfi_get_out_of_my_way=1` 之类的参数可能削弱后续 boot stages，但前提是 platform 接受这些参数。在 Full 或 Reduced Security 下的 Apple silicon 上，iBoot 会过滤降低 security 的 arguments；unrestricted arguments 需要使用上述描述的 `sip3` policy downgrade。在 Intel 上，SIP 的 NVRAM restriction 同样会阻止将 root shell 视为自动获得 `boot-args` 控制权。
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
参见 [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) 和 [kernel debugging](macos-kernel-extensions.md)，不要假设某个历史论点在每个 macOS 版本上的行为都完全相同。

### NVRAM-backed `rc.trampoline` Execution

近期研究记录了一个 NVRAM 数据的具体使用者：Apple platform binary `/System/Library/CoreServices/rc.trampoline`。当 launchd 看到 `rc.trampoline=1` boot argument 时，该 boot task 会从 `IODeviceTree:/options` 读取 `apple-trusted-trampoline` property，将其写入临时 executable，suspended 启动它，检查其 code-signing 状态，取消链接该文件，然后恢复它的执行。该 boot task 会阻塞 launchd，直到子进程退出。<sup>[[5]](#references)</sup>

这是一个**post-downgrade persistence primitive，而不是 SIP bypass**。演示的路径要求先禁用 SIP，以便 boot task 能够运行并设置 `boot-args`。研究还观察到，value size 上限约为 390 KB。其价值在于：在 attacker 已经获得所需 security downgrade 后，executable bytes 可以存放在 normal filesystem 之外，并在 boot 期间被 materialize。<sup>[[5]](#references)</sup>

同时搜索所需的两个 artifacts 和 launchd event：
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
任意的自定义 NVRAM 变量本质上仅用于**存储**：除非固件、Apple 启动组件或单独的持久化机制读取并使用它们，否则它们不会执行任何操作。这一区分可避免夸大诸如 `nvram attacker-config=...` 这样的标记，将其误认为是固件代码执行。

## Enumeration Script

<details>
<summary>NVRAM 和 Apple silicon 启动策略审计</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Apple Platform Security Guide — 启动过程](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Apple Security Updates — 与 NVRAM 相关的 CVE](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Apple T2 安全性](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Apple Platform Security — Apple silicon Mac 的 LocalPolicy 文件内容](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Beyond the good ol' LaunchAgents — 通过 apple-trusted-trampoline 使用 NVRAM 实现持久化](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
