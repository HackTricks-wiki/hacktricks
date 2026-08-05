# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext 和 amfid

它专注于强制执行系统上运行代码的完整性，为 XNU 的代码签名验证提供背后的逻辑。它还能够检查 entitlements，并处理其他敏感任务，例如允许 debugging 或获取 task ports。

此外，对于某些操作，该 kext 更倾向于联系运行在 user space 中的 daemon `/usr/libexec/amfid`。这种信任关系已在多个 jailbreak 中被滥用。

在较新的 macOS 版本中，AMFI 不再以独立的、方便访问的磁盘上 kext 形式存在，因此逆向分析通常需要使用 **kernelcache** 或 **KDK**，而不是浏览 `/System/Library/Extensions`。

AMFI 使用 **MACF** policies，并在启动时立即注册其 hooks。此外，阻止其加载或将其卸载可能触发 kernel panic。不过，有一些 boot arguments 可以削弱 AMFI：

- `amfi_unrestricted_task_for_pid`：允许 task_for_pid 在没有所需 entitlements 的情况下被允许
- `amfi_allow_any_signature`：允许任何 code signature
- `cs_enforcement_disable`：用于禁用全系统 code signing enforcement 的参数
- `amfi_prevent_old_entitled_platform_binaries`：使带有 entitlements 的 platform binaries 失效
- `amfi_get_out_of_my_way`：完全禁用 amfi

以下是它注册的一些 MACF policies：<sup>[1]</sup>

- **`cred_check_label_update_execve:`**：执行 label update 并返回 1
- **`cred_label_associate`**：使用 label 更新 AMFI 的 mac label slot
- **`cred_label_destroy`**：移除 AMFI 的 mac label slot
- **`cred_label_init`**：将 AMFI 的 mac label slot 移动到 0
- **`cred_label_update_execve:`**：检查进程的 entitlements，以确定是否应允许其修改 labels。
- **`file_check_mmap:`**：检查 mmap 是否正在获取内存并将其设置为 executable。在这种情况下，它会检查是否需要 library validation，如果需要，则调用 library validation function。
- **`file_check_library_validation`**：调用 library validation function，该函数会检查多个事项，包括 platform binary 是否正在加载另一个 platform binary，以及进程和新加载的文件是否具有相同的 TeamID。某些 entitlements 也允许加载任意 library。
- **`policy_initbsd`**：设置受信任的 NVRAM Keys
- **`policy_syscall`**：检查 DYLD policies，例如 binary 是否具有 unrestricted segments、是否应允许 env vars 等……当进程通过 `amfi_check_dyld_policy_self()` 启动时，也会调用此函数。
- **`proc_check_inherit_ipc_ports`**：检查进程执行新 binary 时，其他拥有该进程 task port 的 SEND rights 的进程是否应继续保留这些 rights。platform binaries 被允许；具有 `get-task-allow` entitlement、`task_for_pid-allow` entitlement 的 binaries，以及具有相同 TeamID 的 binaries 也被允许。
- **`proc_check_expose_task`**：强制执行 entitlements
- **`amfi_exc_action_check_exception_send`**：向 debugger 发送 exception message
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**：exception handling（debugging）期间的 label 生命周期
- **`proc_check_get_task`**：检查诸如 `get-task-allow` 之类的 entitlements，该 entitlement 允许其他进程获取该进程的 task port；以及 `task_for_pid-allow`，该 entitlement 允许进程获取其他进程的 task ports。如果两者都不存在，则向上调用 `amfid permitunrestricteddebugging`，以检查是否允许该操作。
- **`proc_check_mprotect`**：如果使用标志 `VM_PROT_TRUSTED` 调用 `mprotect`，则拒绝该操作；该标志表示该区域必须被视为具有有效的 code signature。
- **`vnode_check_exec`**：在 executable files 被加载到内存时调用，并设置 `cs_hard | cs_kill`；如果任意 page 变为无效，这将终止进程<sup>[2]</sup>
- **`vnode_check_getextattr`**：MacOS：检查 `com.apple.root.installed` 和 `isVnodeQuarantined()`
- **`vnode_check_setextattr`**：与 get 相同，并检查 `com.apple.private.allow-bless` 和 internal-installer-equivalent entitlement
- **`vnode_check_signature`**：调用 XNU，使用 entitlements、trust cache 和 `amfid` 检查 code signature 的代码<sup>[3]</sup>
- **`proc_check_run_cs_invalid`**：拦截 `ptrace()` 调用（`PT_ATTACH` 和 `PT_TRACE_ME`）。它会检查是否具有 `get-task-allow`、`run-invalid-allow` 和 `run-unsigned-code` 中的任意 entitlement；如果都没有，则检查是否允许 debugging。
- **`proc_check_map_anon`**：如果使用 **`MAP_JIT`** 标志调用 mmap，AMFI 将检查 `dynamic-codesigning` entitlement。

`AMFI.kext` 还会为其他 kernel extensions 暴露 API，并且可以通过以下方式查找其 dependencies：
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

这是运行在 user mode 中的 daemon，`AMFI.kext` 会使用它在 user mode 中检查 code signatures。\
为了让 `AMFI.kext` 与该 daemon 通信，它会通过端口 `HOST_AMFID_PORT` 使用 mach messages，该端口是特殊端口 `18`。

请注意，在 macOS 中，root processes 已无法再劫持特殊端口，因为这些端口受 `SIP` 保护，只有 launchd 能够获取它们。在 iOS 中，系统会检查发送响应的 process 是否具有硬编码的 `amfid` CDHash。

通过对 `amfid` 进行 debugging 并在 `mach_msg` 中设置 breakpoint，可以查看 `amfid` 何时被请求检查 binary，以及它返回的响应。

通过特殊端口接收到 message 后，会使用 **MIG** 将每个 function 分发到其调用的 function。书中对主要 functions 进行了逆向分析和解释。

### DYLD policy and library validation

Recent `dyld` versions 会在 `configureProcessRestrictions()` 中非常早地调用 `amfi_check_dyld_policy_self()`，询问 AMFI 该 process 是否可以使用 `DYLD_*` path variables、interposing、fallback paths、embedded variables，或容忍 library insertion 失败。因此，在 triaging injection surface 时，仅检查 Mach-O load commands 是不够的：还需要检查 AMFI 将转换为 `dyld` policy 的 entitlements 和 runtime flags。

一个实用的 triage loop 是：
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
在现代 macOS 中，许多 Apple binary 不再直接携带 `com.apple.security.cs.disable-library-validation`，而是改为携带 `com.apple.private.security.clear-library-validation`。在这种情况下，library validation 不会在 `execve` 时被禁用：进程必须对自身调用 `csops(..., CS_OPS_CLEAR_LV, ...)`，而 XNU 仅在调用进程具有该 entitlement 时才允许执行此操作。从 offensive 角度来看，这一点很重要，因为目标可能只有在执行到显式清除 LV 的代码路径后才会变得可注入（例如，即将加载可选 plugins 之前）。<sup>[4][5]</sup>

## Provisioning Profiles

provisioning profile 可用于签署 code。有 **Developer** profiles 可用于签署 code 并进行测试，也有可在所有设备上使用的 **Enterprise** profiles。

App 提交到 Apple Store 后，如果审核通过，Apple 会对其进行签名，此时不再需要 provisioning profile。

profile 通常使用 `.mobileprovision` 或 `.provisionprofile` 扩展名，并可通过以下命令 dump：
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
虽然有时被称为 certificated，但这些 provisioning profiles 包含的不仅仅是证书：

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: 将其标记为 Apple Internal profile
- **ApplicationIdentifierPrefix**: 添加在 AppIDName 前（与 TeamIdentifier 相同）
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 格式的日期
- **DeveloperCertificates**: 由 Base64 data 编码的证书数组（通常包含一个证书）
- **Entitlements**: 允许此 profile 使用的 entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 格式的过期日期
- **Name**: Application Name，与 AppIDName 相同
- **ProvisionedDevices**: 一个 UDID 数组（针对 developer certificates），表示此 profile 对哪些设备有效
- **ProvisionsAllDevices**: 布尔值（enterprise certificates 为 true）
- **TeamIdentifier**: 一个由字母数字字符串组成的数组（通常包含一个字符串），用于在 inter-app interaction 中识别 developer
- **TeamName**: 用于识别 developer 的人类可读名称
- **TimeToLive**: certificate 的有效期（天数）
- **UUID**: 此 profile 的 Universally Unique Identifier
- **Version**: 当前设置为 1

请注意，entitlements 条目只包含一组受限的 entitlements，并且 provisioning profile 只能授予这些特定的 entitlements，从而防止授予 Apple private entitlements。

请注意，profiles 通常位于 `/var/MobileDeviceProvisioningProfiles`，可以使用 **`security cms -D -i /path/to/profile`** 检查它们。

## **libmis.dylib**

这是 `amfid` 调用的 external library，用于询问是否应允许某项操作。过去，jailbreaking 经常通过运行其 backdoored 版本滥用这一机制，使其允许所有操作。

在 macOS 中，它位于 `MobileDevice.framework` 内部。

## AMFI Trust Caches

Trust caches 并非 iOS 专属概念。在现代 macOS 中，尤其是在 **Apple silicon** 上，static trust cache 和 loadable trust caches 属于 Secure Boot chain 的一部分。当 Mach-O 的 **CodeDirectory hash** 存在于其中时，AMFI 可以在启动时无需进一步进行 authenticity checks，直接授予其 **platform privilege**。这也意味着 Apple 可以将 platform binaries 锁定到特定 OS version，并阻止较旧的 Apple-signed binaries 在较新的系统上被 replay。<sup>[6]</sup>

在近期的 macOS releases 中，trust-cache metadata 还与 **launch constraints** 绑定，因此，即使复制的 system apps 和 binaries 仍然由 Apple 签名，如果它们从错误的 parent/location 启动，也可能被 AMFI 拒绝。详细的提取和 reversing workflow 见：

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

在 iOS 和 jailbreak research 中，你仍然会看到传统的 **loadable trust caches** 模型被用于将 ad-hoc signed binaries 列入 whitelist。

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
