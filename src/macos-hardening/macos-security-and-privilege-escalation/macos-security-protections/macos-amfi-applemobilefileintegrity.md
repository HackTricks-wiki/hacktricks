# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

它专注于强制执行系统上运行代码的完整性，提供 XNU 代码签名验证背后的逻辑。它也能够检查 entitlements 并处理其他敏感任务，例如允许调试或获取 task ports。

此外，对于某些操作，kext 更倾向于联系运行在用户空间的守护进程 `/usr/libexec/amfid`。这种信任关系已在多个 jailbreak 中被滥用。

在较新的 macOS 版本中，AMFI 不再方便地以独立的磁盘上 kext 形式暴露，因此逆向通常意味着基于 **kernelcache** 或 **KDK** 工作，而不是浏览 `/System/Library/Extensions`。

AMFI 使用 **MACF** policies，并在启动的瞬间注册其 hooks。另外，阻止其加载或卸载可能会触发 kernel panic。不过，有一些 boot arguments 可以削弱 AMFI：

- `amfi_unrestricted_task_for_pid`: 允许 `task_for_pid` 在不需要所需 entitlements 的情况下被允许
- `amfi_allow_any_signature`: 允许任何 code signature
- `cs_enforcement_disable`: 用于全系统禁用 code signing enforcement 的参数
- `amfi_prevent_old_entitled_platform_binaries`: 使带有 entitlements 的 platform binaries 失效
- `amfi_get_out_of_my_way`: 完全禁用 amfi

以下是它注册的一些 MACF policies：

- **`cred_check_label_update_execve:`** 将执行 label update 并返回 1
- **`cred_label_associate`**: 用 label 更新 AMFI 的 mac label slot
- **`cred_label_destroy`**: 移除 AMFI 的 mac label slot
- **`cred_label_init`**: 将 0 放入 AMFI 的 mac label slot
- **`cred_label_update_execve`:** 它检查进程的 entitlements，以确认是否应允许其修改 labels。
- **`file_check_mmap`:** 它检查 mmap 是否正在获取内存并将其设为可执行。在这种情况下，它会检查是否需要 library validation；如果需要，它会调用 library validation 函数。
- **`file_check_library_validation`**: 调用 library validation 函数，该函数会检查诸如 platform binary 是否正在加载另一个 platform binary，或者进程与新加载的文件是否具有相同的 TeamID 等。某些 entitlements 也会允许加载任何 library。
- **`policy_initbsd`**: 设置受信任的 NVRAM Keys
- **`policy_syscall`**: 它检查 DYLD policies，例如 binary 是否具有 unrestricted segments、是否应该允许 env vars... 当进程通过 `amfi_check_dyld_policy_self()` 启动时也会调用它。
- **`proc_check_inherit_ipc_ports`**: 它检查当一个进程执行新的 binary 时，其他对该进程 task port 拥有 SEND 权限的进程是否应保留这些权限。Platform binaries 被允许，拥有 `get-task-allow` entitlement 的被允许，`task_for_pid-allow` entitles 被允许，以及具有相同 TeamID 的 binaries。
- **`proc_check_expose_task`**: 强制执行 entitlements
- **`amfi_exc_action_check_exception_send`**: 向 debugger 发送 exception message
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: 调试期间 exception handling 中的 label 生命周期
- **`proc_check_get_task`**: 检查诸如 `get-task-allow` 之类的 entitlements，它允许其他进程获取该进程的 task port，以及 `task_for_pid-allow`，它允许该进程获取其他进程的 task ports。如果两者都没有，它会调用 `amfid permitunrestricteddebugging` 来检查是否被允许。
- **`proc_check_mprotect`**: 如果 `mprotect` 带有 `VM_PROT_TRUSTED` 标志被调用，则拒绝；该标志表示该区域必须被视为具有有效的 code signature。
- **`vnode_check_exec`**: 当可执行文件被加载到内存中时调用，并设置 `cs_hard | cs_kill`，如果任何页面变为无效，它将杀死进程
- **`vnode_check_getextattr`**: MacOS: 检查 `com.apple.root.installed` 和 `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: 与 get 相同 + `com.apple.private.allow-bless` 和 internal-installer-equivalent entitlement
- **`vnode_check_signature`**: 调用 XNU 通过 entitlements、trust cache 和 `amfid` 检查 code signature 的代码
- **`proc_check_run_cs_invalid`**: 它拦截 `ptrace()` 调用（`PT_ATTACH` 和 `PT_TRACE_ME`）。它检查 `get-task-allow`、`run-invalid-allow` 和 `run-unsigned-code` 这些 entitlements，如果都没有，则检查是否允许 debugging。
- **`proc_check_map_anon`**: 如果 `mmap` 带有 **`MAP_JIT`** 标志调用，AMFI 将检查 `dynamic-codesigning` entitlement。

`AMFI.kext` 也为其他 kernel extensions 暴露了一个 API，并且可以通过以下方式找到它的依赖关系：
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

这是 `AMFI.kext` 将用于在用户模式下检查代码签名的用户模式运行守护进程。\
为了让 `AMFI.kext` 与该守护进程通信，它使用通过端口 `HOST_AMFID_PORT` 的 mach 消息，而该端口是特殊端口 `18`。

注意，在 macOS 中，root 进程已经不能再劫持特殊端口，因为它们受到 `SIP` 保护，只有 launchd 可以获取它们。在 iOS 中，会检查发送响应的进程是否具有硬编码的 `amfid` CDHash。

可以通过调试它并在 `mach_msg` 中设置断点，来查看何时请求 `amfid` 检查某个 binary 以及它的响应。

一旦通过特殊端口接收到消息，**MIG** 会被用来将每个函数分发到它所调用的函数。主要函数已在书中被逆向并解释。

### DYLD policy and library validation

较新的 `dyld` 版本会在 `configureProcessRestrictions()` 很早的时候调用 `amfi_check_dyld_policy_self()`，以询问 AMFI 进程是否可以使用 `DYLD_*` path variables、interposing、fallback paths、embedded variables，或者是否允许容忍失败的 library insertion。因此，在梳理 injection surface 时，仅检查 Mach-O load commands 还不够：你还需要检查 AMFI 会转换为 `dyld` policy 的 entitlements 和 runtime flags。

一个实用的梳理循环是：
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
在现代 macOS 上，许多 Apple 二进制文件不再直接携带 `com.apple.security.cs.disable-library-validation`，而是改为使用 `com.apple.private.security.clear-library-validation`。在这种情况下，library validation 不会在 `execve` 时被禁用：进程必须在自身上调用 `csops(..., CS_OPS_CLEAR_LV, ...)`，而且只有在存在该 entitlement 时，XNU 才允许对调用进程执行这个操作。从攻击角度看，这很重要，因为目标可能只有在到达显式清除 LV 的代码路径之后才会变得可注入（例如，在加载可选 plugins 之前不久）。

## Provisioning Profiles

provisioning profile 可用于给代码签名。有 **Developer** profiles，可以用来给代码签名和测试；还有 **Enterprise** profiles，可用于所有设备。

当一个 App 提交到 Apple Store 后，如果被批准，它会由 Apple 签名，因此不再需要 provisioning profile。

一个 profile 通常使用扩展名 `.mobileprovision` 或 `.provisionprofile`，可以通过以下方式 dump：
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
虽然有时被称为 certificated，但这些 provisioning profiles 不止包含 certificate：

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: 将其指定为 Apple Internal profile
- **ApplicationIdentifierPrefix**: 追加到 AppIDName 前缀（与 TeamIdentifier 相同）
- **CreationDate**: 格式为 `YYYY-MM-DDTHH:mm:ssZ` 的日期
- **DeveloperCertificates**: 一个（通常是一个）certificate 的数组，编码为 Base64 data
- **Entitlements**: 该 profile 允许的 entitlements
- **ExpirationDate**: 格式为 `YYYY-MM-DDTHH:mm:ssZ` 的到期日期
- **Name**: Application Name，与 AppIDName 相同
- **ProvisionedDevices**: 一个数组（用于 developer certificates），包含该 profile 有效的 UDID
- **ProvisionsAllDevices**: 一个布尔值（enterprise certificates 为 true）
- **TeamIdentifier**: 一个（通常是一个）用于跨 app 交互目的识别 developer 的字母数字字符串数组
- **TeamName**: 用于识别 developer 的可读名称
- **TimeToLive**: certificate 的有效期（天）
- **UUID**: 该 profile 的 Universally Unique Identifier
- **Version**: 当前设置为 1

注意，entitlements 条目只会包含一组受限的 entitlements，provisioning profile 只能授予这些特定 entitlements，以防止赋予 Apple private entitlements。

注意，profiles 通常位于 `/var/MobileDeviceProvisioningProfiles`，并且可以使用 **`security cms -D -i /path/to/profile`** 检查它们

## **libmis.dylib**

这是 `amfid` 调用的外部 library，用来询问是否应该允许某些内容。历史上这一直被 jailbreak 利用，通过运行一个带后门的版本来允许一切。

在 macOS 中，它位于 `MobileDevice.framework` 内。

## AMFI Trust Caches

Trust caches 不只是 iOS 的概念。在现代 macOS 上，尤其是 **Apple silicon**，static trust cache 和 loadable trust caches 是 Secure Boot 链的一部分。当某个 Mach-O 的 **CodeDirectory hash** 出现在其中时，AMFI 可以在启动时不再进行进一步真实性检查，就授予它 **platform privilege**。这也意味着 Apple 可以将 platform binaries 锁定到特定的 OS version，并防止旧的 Apple-signed binaries 在新系统上被 replay。

在较新的 macOS 版本中，trust-cache metadata 也与 **launch constraints** 绑定，因此，即使仍然是 Apple-signed，从错误的 parent/location 启动的复制系统 app 和 binary 也可能被 AMFI 拒绝。详细的提取和 reversing 流程在这里说明：

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

在 iOS 和 jailbreak research 中，你仍然会看到传统的 **loadable trust caches** 模型被用于将 ad-hoc signed binaries 加入白名单。

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
