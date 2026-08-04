# macOS 内核漏洞

{{#include ../../../banners/hacktricks-training.md}}

近期 macOS kernel exploitation 已不再主要是“加载一个简单的 unsigned kext 并获得 ring-0”，而更多是滥用 **Mach/MIG parsers**、**IOKit user clients**、XNU 内部的 **data-only races**，以及仍可能重新打开 kernel attack surface 的**特殊 entitlement 守护进程**。如需逆向具体接口，也请查看关于 [**IOKit**](macos-iokit.md) 和 [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) 的页面。

## 仍然重要的攻击面

- 系统守护进程和面向 kernel 的服务中的 **Mach/MIG handlers**：格式错误的 descriptors、out-of-line (OOL) data，以及有状态的多消息流程。
- **IOKit user clients**：特定 selector 的 parsing、由 entitlement 控制的方法，以及隐藏真实调用图的 wrapper libraries/daemons。
- **XNU data-only primitives**：围绕 credentials、受 SMR 保护的 pointers、只读 zones，以及其他可通过 corruption 改变策略而无需先取得 RIP/PC 控制权的位置。
- **Third-party / auxiliary kernel code**：legacy kext 虽然更加少见，但企业设备群、降低安全性的 Apple Silicon 系统，以及厂商的 `.fs` / helper bundles 仍会形成高价值的 kernel-adjacent 路径。

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

在[**这份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)中，研究人员通过滥用 software update pipeline 和 rootless 相关 capabilities，结合多个 OTA/update-chain bugs，最终实现 kernel compromise。

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722)。

---

## 2024：野外利用的 kernel protection bypass chain（CVE-2024-23225 与 CVE-2024-23296）

Apple 的 [**2024 年 3 月 macOS security releases**](https://support.apple.com/en-us/120895) 修复了两个已被**实际利用**的问题：

- **CVE-2024-23225 – Kernel**：一种 memory-corruption bug，拥有 arbitrary kernel read/write 的攻击者可利用它绕过 kernel memory protections。
- **CVE-2024-23296 – RTKit**：另一种具有相同公开影响描述的 memory-corruption bug。

目前公开的 root-cause 细节仍然很少，但这两个漏洞很好地提醒我们：现代 Apple exploit chains 通常需要的不仅仅是“kernel R/W”：针对 memory protections、与 coprocessor 相邻的代码，或次级 trust boundaries 的 post-exploitation 工作，往往才是稳定整个 chain 的关键。

快速补丁排查：
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025：SMR + 只读 credential race（CVE-2025-24118）

Joseph Ravichandran 的 [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) 是一个非常优秀的现代 XNU 案例研究，因为它**不是**经典的 buffer overflow：

- `proc_ro.p_ucred` 是存储在**只读** `proc_ro` 对象中的 **SMR-protected pointer**。
- Writers 必须**原子地**更新该 pointer。
- `kauth_cred_proc_update()` 使用 `zalloc_ro_mut(...)` 修改 `p_ucred`；在 x86_64 上，该路径最终会触发 `memcpy` / `rep movsb`，因此并发 reader 可能观察到一个 **torn pointer**。
- 该 bug 会转化为一种 **data-only privilege escalation**：如果损坏后的 credential pointer 解析到另一个有效的 credential object，当前 thread 就可能继承更高权限的状态，而无需先实现明显的 control-flow hijack。

最小 trigger pattern：
```c
// writer thread: force frequent credential swaps
while (1) {
setgid(real_gid);
setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
(void)getgid();
}
```
实用的 audit heuristic：每当 kernel path 同时涉及 **SMR readers**、**read-only zone mutation** 以及 **credential 或 task metadata** 时，请确认更新使用的是 atomic `zalloc_ro_mut_*` variants，而不是基于复制的 helpers。

---

## 2024-2025：重新开启 kernel loading paths 的 SIP bypass（CVE-2024-44243）

Microsoft 展示了如何滥用 `storagekitd` 来 **bypass SIP**，从而让第三方 kernel code 在原本看似已进入 "post-kext" 状态的机器上重新变得相关。核心思路是：

1. 在 `/Library/Filesystems` 下放置或覆盖恶意 `.fs` bundle。
2. 通过 Disk Utility 或 `diskutil` 触发 `storagekitd`。
3. 让具有特殊 entitlement 的 daemon 在**未正确 drop privileges / validate path** 的情况下 spawn bundle executables。
4. 利用由此产生的 SIP bypass 修改受保护的 file-system state；在 Microsoft 的演示中，还可覆盖 kernel extension exclusion list。

对于 kernel researchers，重要经验是：即使 direct third-party kext loading 受到严格限制，**kernel attack surface 仍可能由 userland management daemons 重新引入**。

实用的 triage：
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing 与研究工作流

如果你正在主动寻找这类 bug，近期的公开研究基本都指向同一个方向：

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) 仍然是 Apple Silicon 时代 kernel research 的最佳参考之一。它使用 **static binary rewriting** 来恢复 coverage，在测试期间禁用 **entitlement-gated** 路径，并从 userspace wrappers 推断接口结构。
- Project Zero 的 [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) 展示了一套非常实用的工作流：将 **kext / fileset rebase 到 userspace**，从而在设备上复现之前，以更高速度对以 parser 为主的代码进行 fuzz。
- 对于以 Mach 为主的目标，应围绕 **真实的 message layouts 和 multi-call state machines** 构建 harness，而不只是单个 selector blob。Project Zero 最近关于 CoreAudio/Mach 的研究，以及 **Fuzzing at Mach Speed** 等会议演讲，都说明了为什么有状态的 message sequences 能持续带来收益。

以下是你实际会经常使用的本地命令：
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## 快速枚举速查表
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## 参考资料

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “分析 CVE-2024-44243：通过 kernel extensions 绕过 macOS System Integrity Protection。” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
