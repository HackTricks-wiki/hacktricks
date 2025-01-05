# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext 和 amfid

它专注于强制执行系统上运行代码的完整性，提供 XNU 代码签名验证背后的逻辑。它还能够检查权限并处理其他敏感任务，例如允许调试或获取任务端口。

此外，对于某些操作，kext 更倾向于联系用户空间运行的守护进程 `/usr/libexec/amfid`。这种信任关系在多个越狱中被滥用。

AMFI 使用 **MACF** 策略，并在启动时注册其钩子。此外，防止其加载或卸载可能会触发内核崩溃。然而，有一些启动参数可以削弱 AMFI：

- `amfi_unrestricted_task_for_pid`: 允许在没有所需权限的情况下使用 task_for_pid
- `amfi_allow_any_signature`: 允许任何代码签名
- `cs_enforcement_disable`: 用于禁用代码签名强制执行的系统范围参数
- `amfi_prevent_old_entitled_platform_binaries`: 作废具有权限的平台二进制文件
- `amfi_get_out_of_my_way`: 完全禁用 amfi

以下是它注册的一些 MACF 策略：

- **`cred_check_label_update_execve:`** 标签更新将被执行并返回 1
- **`cred_label_associate`**: 用标签更新 AMFI 的 mac 标签槽
- **`cred_label_destroy`**: 移除 AMFI 的 mac 标签槽
- **`cred_label_init`**: 在 AMFI 的 mac 标签槽中移动 0
- **`cred_label_update_execve`:** 它检查进程的权限，以查看是否允许修改标签。
- **`file_check_mmap`:** 它检查 mmap 是否获取内存并将其设置为可执行。如果是这种情况，它会检查是否需要库验证，如果需要，则调用库验证函数。
- **`file_check_library_validation`**: 调用库验证函数，该函数检查其他内容，例如平台二进制文件是否加载另一个平台二进制文件，或者进程和新加载的文件是否具有相同的 TeamID。某些权限也将允许加载任何库。
- **`policy_initbsd`**: 设置受信任的 NVRAM 密钥
- **`policy_syscall`**: 它检查 DYLD 策略，例如二进制文件是否具有不受限制的段，是否应允许环境变量……当通过 `amfi_check_dyld_policy_self()` 启动进程时也会调用此函数。
- **`proc_check_inherit_ipc_ports`**: 它检查当进程执行新二进制文件时，是否应保留其他具有发送权限的进程对该进程的任务端口的权限。平台二进制文件是允许的，`get-task-allow` 权限允许它，`task_for_pid-allow` 权限是允许的，具有相同 TeamID 的二进制文件。
- **`proc_check_expose_task`**: 强制执行权限
- **`amfi_exc_action_check_exception_send`**: 向调试器发送异常消息
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: 异常处理（调试）期间的标签生命周期
- **`proc_check_get_task`**: 检查权限，如 `get-task-allow`，允许其他进程获取任务端口，以及 `task_for_pid-allow`，允许进程获取其他进程的任务端口。如果都没有，它会调用 `amfid permitunrestricteddebugging` 来检查是否被允许。
- **`proc_check_mprotect`**: 如果调用 `mprotect` 时带有 `VM_PROT_TRUSTED` 标志，则拒绝，该标志表示该区域必须被视为具有有效的代码签名。
- **`vnode_check_exec`**: 当可执行文件加载到内存中时被调用，并设置 `cs_hard | cs_kill`，如果任何页面变为无效，将终止该进程
- **`vnode_check_getextattr`**: MacOS: 检查 `com.apple.root.installed` 和 `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: 作为获取 + com.apple.private.allow-bless 和内部安装程序等效权限
- **`vnode_check_signature`**: 调用 XNU 检查代码签名的代码，使用权限、信任缓存和 `amfid`
- **`proc_check_run_cs_invalid`**: 拦截 `ptrace()` 调用（`PT_ATTACH` 和 `PT_TRACE_ME`）。它检查任何权限 `get-task-allow`、`run-invalid-allow` 和 `run-unsigned-code`，如果都没有，它会检查是否允许调试。
- **`proc_check_map_anon`**: 如果 mmap 使用 **`MAP_JIT`** 标志被调用，AMFI 将检查 `dynamic-codesigning` 权限。

`AMFI.kext` 还为其他内核扩展公开了一个 API，可以通过以下方式找到其依赖项：
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

这是用户模式下运行的守护进程，`AMFI.kext` 将使用它来检查用户模式中的代码签名。\
为了使 `AMFI.kext` 与守护进程通信，它使用通过端口 `HOST_AMFID_PORT` 的 mach 消息，该端口是特殊端口 `18`。

请注意，在 macOS 中，根进程不再能够劫持特殊端口，因为它们受到 `SIP` 的保护，只有 launchd 可以获取它们。在 iOS 中，会检查发送响应的进程是否具有硬编码的 `amfid` 的 CDHash。

可以通过调试 `amfid` 并在 `mach_msg` 中设置断点来查看何时请求 `amfid` 检查二进制文件及其响应。

一旦通过特殊端口接收到消息，**MIG** 将用于将每个函数发送到它所调用的函数。主要函数已被逆向并在书中进行了说明。

## Provisioning Profiles

配置文件可用于签署代码。有 **Developer** 配置文件可用于签署代码并进行测试，还有 **Enterprise** 配置文件可用于所有设备。

在应用程序提交到 Apple Store 后，如果获得批准，它将由 Apple 签署，并且不再需要配置文件。

配置文件通常使用扩展名 `.mobileprovision` 或 `.provisionprofile`，可以通过以下方式转储：
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
虽然有时被称为证书，这些配置文件不仅仅包含一个证书：

- **AppIDName:** 应用程序标识符
- **AppleInternalProfile**: 指定为苹果内部配置文件
- **ApplicationIdentifierPrefix**: 预加到 AppIDName（与 TeamIdentifier 相同）
- **CreationDate**: 日期格式为 `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: 一个（通常是一个）证书的数组，编码为 Base64 数据
- **Entitlements**: 此配置文件允许的权限
- **ExpirationDate**: 过期日期格式为 `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: 应用程序名称，与 AppIDName 相同
- **ProvisionedDevices**: 一个数组（针对开发者证书），此配置文件有效的 UDID
- **ProvisionsAllDevices**: 布尔值（企业证书为 true）
- **TeamIdentifier**: 一个（通常是一个）字母数字字符串的数组，用于识别开发者以便进行应用间交互
- **TeamName**: 用于识别开发者的人类可读名称
- **TimeToLive**: 证书的有效期（以天为单位）
- **UUID**: 此配置文件的通用唯一标识符
- **Version**: 当前设置为 1

请注意，权限条目将包含一组受限的权限，配置文件只能提供这些特定的权限，以防止提供苹果的私有权限。

请注意，配置文件通常位于 `/var/MobileDeviceProvisioningProfiles`，可以使用 **`security cms -D -i /path/to/profile`** 检查它们。

## **libmis.dyld**

这是 `amfid` 调用的外部库，用于询问是否应该允许某些操作。历史上，这在越狱中被滥用，通过运行一个后门版本来允许所有操作。

在 macOS 中，这在 `MobileDevice.framework` 内部。

## AMFI 信任缓存

iOS AMFI 维护一个已知哈希的列表，这些哈希是临时签名的，称为 **信任缓存**，位于 kext 的 `__TEXT.__const` 部分。请注意，在非常特定和敏感的操作中，可以使用外部文件扩展此信任缓存。

## 参考

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
