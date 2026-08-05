# macOS Kernel 漏洞

{{#include ../../../banners/hacktricks-training.md}}

近期 macOS kernel exploitation 已不再主要是“加载一个简单的 unsigned kext 并获得 ring-0”，而更多是滥用 **Mach/MIG parsers**、**IOKit user clients**、XNU 内部的 **data-only races**，以及仍可能重新暴露 kernel attack surface 的 **specially entitled daemons**。如需逆向具体接口，也请查看关于 [**IOKit**](macos-iokit.md) 和 [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) 的页面。

## 仍然重要的 attack surfaces

- 系统 daemons 和面向 kernel 的 services 中的 **Mach/MIG handlers**：格式错误的 descriptors、out-of-line (OOL) data，以及有状态的多消息流程。
- **IOKit user clients**：特定 selector 的 parsing、由 entitlement 控制的方法，以及隐藏真实调用图的 wrapper libraries/daemons。
- **XNU data-only primitives**：围绕 credentials、SMR-protected pointers、read-only zones 的 races，以及其他可在尚未取得 RIP/PC 控制权之前，通过 corruption 改变 policy 的位置。
- **Third-party / auxiliary kernel code**：legacy kexts 更为少见，但 enterprise fleets、reduced-security Apple Silicon systems，以及 vendor `.fs` / helper bundles 仍会产生高价值的 kernel-adjacent paths。

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

在[**这份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)中，多个 OTA/update-chain bugs 被组合起来，通过滥用 software update pipeline 和与 rootless 相关的 capabilities，最终实现 kernel compromise。<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722)。

---

## 2024：野外利用的 kernel protection bypass chain（CVE-2024-23225 和 CVE-2024-23296）

Apple 的[**2024 年 3 月 macOS security releases**](https://support.apple.com/en-us/120895)修复了两个曾被**主动利用**的问题：

- **CVE-2024-23225 – Kernel**：一个 memory-corruption bug，拥有 arbitrary kernel read/write 的 attacker 可利用该漏洞绕过 kernel memory protections。
- **CVE-2024-23296 – RTKit**：另一个具有相同公开影响描述的 memory-corruption bug。

目前公开的 root-cause details 仍然很少，但这两个漏洞很好地提醒我们：现代 Apple exploit chains 往往需要的不只是“单纯的” kernel R/W：针对 memory protections、coprocessor-adjacent code 或 secondary trust boundaries 的 post-exploitation 工作，通常才是稳定整个 chain 的关键所在。

快速进行 patch triage：
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025：SMR + 只读 credential race（CVE-2025-24118）

Joseph Ravichandran 的 [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) 是一个非常好的现代 XNU 案例研究，因为它**不是**经典的 buffer overflow：<sup>[1]</sup>

- `proc_ro.p_ucred` 是存储在**只读** `proc_ro` 对象中的 **SMR-protected pointer**。
- 写入者必须**原子地**更新该 pointer。
- `kauth_cred_proc_update()` 使用 `zalloc_ro_mut(...)` 修改 `p_ucred`；在 x86_64 上，该路径最终会执行 `memcpy` / `rep movsb`，因此并发 reader 可能观察到一个 **torn pointer**。
- 该 bug 最终会变成一种**仅通过数据实现的 privilege escalation**：如果损坏后的 credential pointer 解析到另一个有效的 credential object，当前 thread 就可以继承更高权限的状态，而无需先成功实现明显的 control-flow hijack。

最小触发模式：
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
实用的审计启发：每当 kernel 路径同时涉及 **SMR readers**、**read-only zone mutation** 以及 **credential 或 task metadata** 时，请确认更新使用的是 atomic `zalloc_ro_mut_*` variants，而不是基于副本的 helpers。

---

## 2024-2025：重新打开 kernel loading paths 的 SIP bypass（CVE-2024-44243）

Microsoft 展示了如何滥用 `storagekitd` 来 **bypass SIP**，从而让 third-party kernel code 在原本看似已进入 "post-kext" 状态的机器上重新变得相关。核心思路是：<sup>[2]</sup>

1. 在 `/Library/Filesystems` 下放置或覆盖恶意 `.fs` bundle。
2. 通过 Disk Utility 或 `diskutil` 触发 `storagekitd`。
3. 让具有特殊 entitlement 的 daemon 在**未正确丢弃 privileges / 验证路径**的情况下 spawn bundle executables。
4. 利用由此产生的 SIP bypass 修改受保护的 file-system state，并在 Microsoft 的演示中覆盖 kernel extension exclusion list。

对于 kernel researchers 来说，重要经验是：即使 direct third-party kext loading 受到严格限制，**kernel attack surface 仍可能由 userland management daemons 重新引入**。

实用的 triage：
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing 与研究工作流

如果你正在积极寻找这类 bug，近期的公开研究基本都指向同一方向：

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) 仍然是 Apple Silicon 时代 kernel research 最佳的参考资料之一。它使用 **static binary rewriting** 来恢复 coverage，在测试期间禁用 **entitlement-gated** 路径，并从 userspace wrappers 推断 interface 结构。<sup>[4]</sup>
- Project Zero 的 [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) 展示了一套非常实用的 workflow：将 kext / fileset **rebasing 到 userspace**，这样就能以更高速度 fuzz 以 parser 为主的代码，然后再在设备上复现。<sup>[5]</sup>
- 对于以 Mach 为主的 targets，应围绕 **real message layouts 和 multi-call state machines** 构建 harness，而不只是使用 single selector blobs。Project Zero 最近针对 CoreAudio/Mach 的 research，以及 **Fuzzing at Mach Speed** 等 conference talks，都说明了 stateful message sequences 为何能持续带来更好的效果。

以下是你实际会经常使用的快速本地命令：
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

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - 分析 CVE-2024-44243：通过 kernel extensions 绕过 macOS System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Apple OTA Update 的噩梦：绕过 Signature Verification 并攻陷 Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin 等 - KextFuzz：通过利用 Mitigations 在 Apple Silicon 上对 macOS Kernel EXTensions 进行 Fuzzing（USENIX Security '23）](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric（Project Zero）- 使用 IDA 和 TinyInst 在 Userspace 中对 macOS Kernel Extension 进行简单 Fuzzing](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
