# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

它专注于强制执行系统上运行代码的完整性，提供 XNU 代码签名验证背后的逻辑。它也能检查 entitlements，并处理其他敏感任务，例如允许调试或获取 task ports。

此外，对于某些操作，kext 更倾向于联系用户空间运行的守护进程 `/usr/libexec/amfid`。这种信任关系已在多个 jailbreak 中被滥用。

在较新的 macOS 版本中，AMFI 不再方便地作为独立的磁盘上的 kext 暴露出来，因此逆向通常意味着要从 **kernelcache** 或 **KDK** 入手，而不是浏览 `/System/Library/Extensions`。

AMFI 使用 **MACF** policies，并在启动的瞬间注册其 hooks。另外，阻止其加载或卸载它都可能触发 kernel panic。不过，有一些 boot arguments 可以削弱 AMFI：

- `amfi_unrestricted_task_for_pid`: 允许在不需要必要 entitlements 的情况下允许 task_for_pid
- `amfi_allow_any_signature`: 允许任何 code signature
- `cs_enforcement_disable`: 用于全系统范围禁用 code signing enforcement 的参数
- `amfi_prevent_old_entitled_platform_binaries`: 使带有 entitlements 的 platform binaries 失效
- `amfi_get_out_of_my_way`: 完全禁用 amfi

以下是它注册的一些 MACF policies：

- **`cred_check_label_update_execve:`** 将执行 label update 并返回 1
- **`cred_label_associate`**: 使用 label 更新 AMFI 的 mac label slot
- **`cred_label_destroy`**: 删除 AMFI 的 mac label slot
- **`cred_label_init`**: 将 0 移入 AMFI 的 mac label slot
- **`cred_label_update_execve`:** 它检查进程的 entitlements，以判断是否应允许其修改 labels。
- **`file_check_mmap`:** 它检查 mmap 是否正在获取内存并将其设为可执行。在这种情况下，它会检查是否需要 library validation；如果需要，就调用 library validation 函数。
- **`file_check_library_validation`**: 调用 library validation 函数，该函数会检查诸如 platform binary 是否正在加载另一个 platform binary，或者进程与新加载文件是否具有相同的 TeamID 等。某些 entitlements 也会允许加载任意 library。
- **`policy_initbsd`**: 设置受信任的 NVRAM Keys
- **`policy_syscall`**: 它检查 DYLD policies，例如 binary 是否有 unrestricted segments、是否应该允许 env vars……当进程通过 `amfi_check_dyld_policy_self()` 启动时也会调用这里。
- **`proc_check_inherit_ipc_ports`**: 它检查当一个进程执行新的 binary 时，其他对该进程 task port 拥有 SEND 权限的进程是否应保留这些权限。platform binaries 被允许，拥有 `get-task-allow` entitlement 的也被允许，`task_for_pid-allow` entitles 也被允许，以及具有相同 TeamID 的 binaries。
- **`proc_check_expose_task`**: 强制执行 entitlements
- **`amfi_exc_action_check_exception_send`**: 向 debugger 发送 exception message
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: debugging 期间的 label 生命周期
- **`proc_check_get_task`**: 检查诸如 `get-task-allow` 之类的 entitlements，它允许其他进程获取该进程的 task port；以及 `task_for_pid-allow`，它允许该进程获取其他进程的 task ports。如果这两者都没有，它会向上调用 `amfid permitunrestricteddebugging` 来检查是否被允许。
- **`proc_check_mprotect`**: 如果 `mprotect` 带着 `VM_PROT_TRUSTED` flag 调用则拒绝；这表示该区域必须被视为具有有效 code signature。
- **`vnode_check_exec`**: 当可执行文件被加载到内存中时调用，并设置 `cs_hard | cs_kill`，这会在任何 page 变为无效时杀死进程
- **`vnode_check_getextattr`**: MacOS: 检查 `com.apple.root.installed` 和 `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: 同 get + `com.apple.private.allow-bless` 和 internal-installer-equivalent entitlement
- **`vnode_check_signature`**: 调用 XNU 使用 entitlements、trust cache 和 `amfid` 检查 code signature 的代码
- **`proc_check_run_cs_invalid`**: 它拦截 `ptrace()` 调用（`PT_ATTACH` 和 `PT_TRACE_ME`）。它会检查 `get-task-allow`、`run-invalid-allow` 和 `run-unsigned-code` 这些 entitlements；如果都没有，就检查是否允许 debugging。
- **`proc_check_map_anon`**: 如果 mmap 带着 **`MAP_JIT`** flag 调用，AMFI 会检查 `dynamic-codesigning` entitlement。

`AMFI.kext` 也为其他 kernel extensions 暴露了一个 API，并且可以通过以下方式找到它的依赖项：
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

这是 `AMFI.kext` 会用来在用户态检查代码签名的用户态运行守护进程。\
为了让 `AMFI.kext` 与该守护进程通信，它使用通过端口 `HOST_AMFID_PORT` 的 mach 消息，而这个端口是特殊端口 `18`。

注意，在 macOS 中，root 进程已经不能再劫持特殊端口，因为它们受 `SIP` 保护，只有 launchd 可以获取它们。在 iOS 中，会检查发送响应回来的进程是否具有硬编码的 `amfid` CDHash。

可以通过调试 `amfid` 并在 `mach_msg` 中设置断点来观察何时请求 `amfid` 检查某个二进制文件，以及它的响应内容。

一旦通过特殊端口接收到消息，**MIG** 会被用来把每个函数分发到它正在调用的函数。主要函数已在书中被逆向并解释。

### DYLD policy and library validation

较新的 `dyld` 版本会在 `configureProcessRestrictions()` 中很早地调用 `amfi_check_dyld_policy_self()`，以询问 AMFI 该进程是否可以使用 `DYLD_*` 路径变量、interposing、fallback paths、embedded variables，或者是否允许失败的库注入。因此，在分析 injection surface 时，仅仅检查 Mach-O load commands 还不够：你还需要检查 AMFI 会转换为 `dyld` policy 的 entitlements 和运行时标志。

一个实用的 triage 循环是：
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
在现代 macOS 上，许多 Apple 二进制文件不再直接携带 `com.apple.security.cs.disable-library-validation`，而是改为使用 `com.apple.private.security.clear-library-validation`。在这种情况下，library validation 不会在 `execve` 时被禁用：进程必须对自身调用 `csops(..., CS_OPS_CLEAR_LV, ...)`，而且只有在存在该 entitlement 时，XNU 才允许对调用进程执行这个操作。从攻击角度来看，这很重要，因为目标可能只有在到达显式清除 LV 的代码路径之后才会变得可注入（例如，在加载可选 plugins 之前不久）。

## Provisioning Profiles

provisioning profile 可用于对代码进行签名。存在可用于对代码签名和测试的 **Developer** profiles，以及可在所有 devices 上使用的 **Enterprise** profiles。

当一个 App 提交到 Apple Store 并通过审核后，它会由 Apple 签名，此时 provisioning profile 就不再需要了。

profile 通常使用扩展名 `.mobileprovision` 或 `.provisionprofile`，并且可以通过以下方式 dump：
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
虽然有时被称为 certificated，这些 provisioning profiles 不止包含一个 certificate：

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: 指定这是一个 Apple Internal profile
- **ApplicationIdentifierPrefix**: 追加到 AppIDName 前面（与 TeamIdentifier 相同）
- **CreationDate**: `YYYY-MM-DDTHH:mm:ssZ` 格式的日期
- **DeveloperCertificates**: 一个（通常为一个）certificate 的数组，使用 Base64 data 编码
- **Entitlements**: 该 profile 允许的 entitlements，以及此 profile 的 entitlements
- **ExpirationDate**: `YYYY-MM-DDTHH:mm:ssZ` 格式的过期日期
- **Name**: Application Name，与 AppIDName 相同
- **ProvisionedDevices**: 一个数组（针对 developer certificates），包含此 profile 有效的 UDIDs
- **ProvisionsAllDevices**: 一个布尔值（enterprise certificates 为 true）
- **TeamIdentifier**: 一个（通常为一个）字母数字字符串数组，用于在 app 间交互时识别 developer
- **TeamName**: 用于识别 developer 的人类可读名称
- **TimeToLive**: certificate 的有效期（天）
- **UUID**: 此 profile 的 Universally Unique Identifier
- **Version**: 当前设为 1

注意，entitlements 条目会包含一组受限的 entitlements，而 provisioning profile 只能授予这些特定 entitlements，以防止授予 Apple private entitlements。

注意，profiles 通常位于 `/var/MobileDeviceProvisioningProfiles`，并且可以使用 **`security cms -D -i /path/to/profile`** 检查它们

## **libmis.dylib**

这是 `amfid` 调用的外部 library，用来询问是否应该允许某个东西。历史上在 jailbreaking 中经常滥用它，通过运行一个带后门的版本来允许一切。

在 macOS 中，它位于 `MobileDevice.framework` 内。

## AMFI Trust Caches

Trust caches 不只是 iOS 的概念。在现代 macOS，尤其是在 **Apple silicon** 上，static trust cache 和 loadable trust caches 是 Secure Boot 链的一部分。当一个 Mach-O 的 **CodeDirectory hash** 存在于其中时，AMFI 可以在启动时不做进一步真实性检查就授予它 **platform privilege**。这也意味着 Apple 可以将 platform binaries 锁定到特定的 OS version，并阻止旧的 Apple-signed binaries 在新系统上被 replay。

在较新的 macOS 版本中，trust-cache metadata 也与 **launch constraints** 绑定，因此从错误的 parent/location 启动的已复制 system apps 和 binaries 可能会被 AMFI 拒绝，即使它们仍然是 Apple-signed。详细的 extraction 和 reversing workflow 在以下内容中说明：

{{#ref}}
macos-launch-environment-constraints.md
{{endref}}

在 iOS 和 jailbreaking 研究中，你仍然会发现传统的 **loadable trust caches** 模型被用于将 ad-hoc signed binaries 加入白名单。

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
