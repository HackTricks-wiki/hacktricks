# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext 和 amfid

它专注于强制执行系统上运行代码的完整性，为 XNU 的代码签名验证提供底层逻辑。它还能够检查 entitlements，并处理允许 debugging 或获取 task ports 等其他敏感任务。

此外，对于某些操作，该 kext 更倾向于联系用户空间中运行的 daemon `/usr/libexec/amfid`。这种信任关系已在多个 jailbreak 中被滥用。

在较新的 macOS 版本中，AMFI 不再以独立的磁盘上 kext 形式方便地暴露，因此 reversing 通常意味着从 **kernelcache** 或 **KDK** 中进行，而不是浏览 `/System/Library/Extensions`。

AMFI 使用 **MACF** policies，并在启动时立即注册其 hooks。阻止其加载或卸载它都可能触发 kernel panic。不过，有一些 boot arguments 可以削弱 AMFI：

- `amfi_unrestricted_task_for_pid`: 允许在没有所需 entitlements 的情况下使用 task_for_pid
- `amfi_allow_any_signature`: 允许任何 code signature
- `cs_enforcement_disable`: 用于禁用全系统 code signing enforcement 的参数
- `amfi_prevent_old_entitled_platform_binaries`: 使带有 entitlements 的 platform binaries 失效
- `amfi_get_out_of_my_way`: 完全禁用 amfi

以下是它注册的一些 MACF policies：<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** 将执行 label update，并返回 1
- **`cred_label_associate`**: 使用 label 更新 AMFI 的 mac label slot
- **`cred_label_destroy`**: 移除 AMFI 的 mac label slot
- **`cred_label_init`**: 将 0 移入 AMFI 的 mac label slot
- **`cred_label_update_execve`:** 检查进程的 entitlements，以确认其是否应被允许修改 labels。
- **`file_check_mmap`:** 检查 mmap 是否正在获取内存并将其设置为 executable。如果是，则检查是否需要 library validation；如果需要，则调用 library validation function。
- **`file_check_library_validation`**: 调用 library validation function，该函数会检查 platform binary 是否正在加载另一个 platform binary，或进程与新加载文件是否具有相同的 TeamID。某些 entitlements 也允许加载任意 library。
- **`policy_initbsd`**: 设置受信任的 NVRAM Keys
- **`policy_syscall`**: 检查 DYLD policies，例如 binary 是否具有 unrestricted segments、是否应允许 env vars 等。当进程通过 `amfi_check_dyld_policy_self()` 启动时，也会调用此函数。
- **`proc_check_inherit_ipc_ports`**: 检查进程执行新的 binary 时，其他拥有该进程 task port 的 SEND 权限的进程是否应继续保留这些权限。Platform binaries 被允许；具有 `get-task-allow` entitlement 的进程被允许；具有 `task_for_pid-allow` entitlement 的进程被允许；具有相同 TeamID 的 binaries 也被允许。
- **`proc_check_expose_task`**: 强制执行 entitlements
- **`amfi_exc_action_check_exception_send`**: 向 debugger 发送 exception message
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: exception handling（debugging）期间的 label 生命周期管理
- **`proc_check_get_task`**: 检查诸如 `get-task-allow` 等 entitlements，该 entitlement 允许其他进程获取该进程的 task port；以及 `task_for_pid-allow`，该 entitlement 允许进程获取其他进程的 task ports。如果两者都不存在，则向上调用 `amfid permitunrestricteddebugging`，以检查是否允许该操作。
- **`proc_check_mprotect`**: 如果使用标志 `VM_PROT_TRUSTED` 调用 `mprotect`，则拒绝该操作；该标志表示该区域必须被视为具有有效 code signature。
- **`vnode_check_exec`**: executable files 被加载到内存时调用，并设置 `cs_hard | cs_kill`；如果任何页面变为无效，这将终止进程<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS：检查 `com.apple.root.installed` 和 `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: 与 get 相同，并检查 `com.apple.private.allow-bless` 和 `internal-installer-equivalent` entitlement
- **`vnode_check_signature`**: 调用 XNU，使用 entitlements、trust cache 和 `amfid` 检查 code signature 的代码<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: 它拦截 `ptrace()` 调用（`PT_ATTACH` 和 `PT_TRACE_ME`）。它检查是否存在 `get-task-allow`、`run-invalid-allow` 和 `run-unsigned-code` 中的任一 entitlement；如果都不存在，则检查是否允许 debugging。
- **`proc_check_map_anon`**: 如果使用 **`MAP_JIT`** flag 调用 mmap，AMFI 将检查 `dynamic-codesigning` entitlement。

`AMFI.kext` 还会向其他 kernel extensions 暴露 API，并且可以通过以下方式查找其 dependencies：
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

这是运行在用户态的 daemon，`AMFI.kext` 将使用它在用户态检查代码签名。\
为了让 `AMFI.kext` 与该 daemon 通信，它会通过端口 `HOST_AMFID_PORT` 使用 mach messages，该端口是特殊端口 `18`。

请注意，在 macOS 中，root 进程已经无法再劫持特殊端口，因为这些端口受 `SIP` 保护，只有 launchd 能够获取它们。在 iOS 中，系统会检查发送响应的进程是否具有硬编码的 `amfid` CDHash。

可以通过调试 `amfid` 并在 `mach_msg` 中设置断点，查看 `amfid` 何时被请求检查某个二进制文件，以及它返回的响应。

通过特殊端口接收到消息后，会使用 **MIG** 将每个函数分派到其调用的函数。书中对主要函数进行了逆向分析和说明。

### DYLD 策略和库验证

近期版本的 `dyld` 会在 `configureProcessRestrictions()` 中非常早地调用 `amfi_check_dyld_policy_self()`，以请求 AMFI 判断进程是否可以使用 `DYLD_*` 路径变量、interposing、fallback paths、embedded variables，或容忍库插入失败。因此，在评估 injection surface 时，仅检查 Mach-O load commands 是不够的：还需要检查 AMFI 将转换为 `dyld` policy 的 entitlements 和 runtime flags。

一个实用的 triage loop 是：
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
在现代 macOS 中，许多 Apple 二进制文件不再直接携带 `com.apple.security.cs.disable-library-validation`，而是改为携带 `com.apple.private.security.clear-library-validation`。在这种情况下，library validation 不会在 `execve` 时被禁用：进程必须对自身调用 `csops(..., CS_OPS_CLEAR_LV, ...)`，并且 XNU 仅在调用进程拥有该 entitlement 时才允许执行此操作。从攻击角度来看，这一点很重要，因为目标可能只有在执行到显式清除 LV 的代码路径后才变得可注入（例如，在加载可选插件之前不久）。<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profile 可用于签署代码。有 **Developer** profiles 可用于签署代码并进行测试，还有可在所有设备上使用的 **Enterprise** profiles。

App 提交到 Apple Store 后，如果获得批准，Apple 会对其进行签名，此时不再需要 provisioning profile。

Profile 通常使用 `.mobileprovision` 或 `.provisionprofile` 扩展名，并可使用以下命令 dump：
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
尽管有时被称为 certificated，但这些 provisioning profiles 不仅包含一个 certificate：

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: 将其标记为 Apple Internal profile
- **ApplicationIdentifierPrefix**: 添加在 AppIDName 前（与 TeamIdentifier 相同）
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 格式的日期
- **DeveloperCertificates**: 由 Base64 数据编码的 certificate 数组（通常包含一个）
- **Entitlements**: 允许与此 profile 关联的 entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 格式的过期日期
- **Name**: Application Name，与 AppIDName 相同
- **ProvisionedDevices**: 一个 UDID 数组（适用于 developer certificates），表示此 profile 对哪些设备有效
- **ProvisionsAllDevices**: 一个布尔值（enterprise certificates 为 true）
- **TeamIdentifier**: 一个字母数字字符串数组（通常包含一个），用于标识 developer，以实现 app 间交互
- **TeamName**: 用于标识 developer 的人类可读名称
- **TimeToLive**: certificate 的有效期（天数）
- **UUID**: 此 profile 的 Universally Unique Identifier
- **Version**: 当前设置为 1

请注意，entitlements 条目将包含一组受限的 entitlements，并且 provisioning profile 只能授予这些特定的 entitlements，从而防止授予 Apple private entitlements。

请注意，profiles 通常位于 `/var/MobileDeviceProvisioningProfiles`，可以使用 **`security cms -D -i /path/to/profile`** 检查它们。

## **libmis.dylib**

这是 `amfid` 调用的外部 library，用于询问是否应允许某项操作。过去，jailbreaking 曾滥用这一点，通过运行 backdoored 版本来允许所有操作。

在 macOS 中，它位于 `MobileDevice.framework` 内部。

## AMFI Trust Caches

Trust caches 并不只是 iOS 的概念。在现代 macOS 中，尤其是在 **Apple silicon** 上，static trust cache 和 loadable trust caches 都是 Secure Boot chain 的组成部分。当 Mach-O 的 **CodeDirectory hash** 存在其中时，AMFI 可以在启动时授予它 **platform privilege**，而无需进一步执行 authenticity checks。这也意味着 Apple 可以将 platform binaries 锁定到特定的 OS version，并阻止较旧的 Apple-signed binaries 在较新的系统上被 replay。<sup>[[6]](#references)</sup>

在近期的 macOS releases 中，trust-cache metadata 也与 **launch constraints** 绑定，因此，即使复制的 system apps 和 binaries 仍然是 Apple-signed，如果它们从错误的 parent/location 启动，也可能被 AMFI 拒绝。详细的提取和 reversing workflow 参见：

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

在 iOS 和 jailbreak research 中，你仍会看到传统的 **loadable trust caches** 模型被用于将 ad-hoc signed binaries 加入 whitelist。

## References

- [1] [XNU — `security/mac_policy.h`（MACF policy ops AMFI registers，包括 `mpo_policy_syscall`）](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h`（AMFI 设置的 `CS_*` code-signing flags）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c`（code-signature blob parsing and validation）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` operations 和 `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` handler）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
