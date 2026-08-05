# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

近期 macOS kernel exploitation 已不再主要是“加载一个简单的 unsigned kext 并获得 ring-0”，而更多是滥用 **Mach/MIG parsers**、**IOKit user clients**、XNU 内部的 **data-only races**，以及仍可能重新打开 kernel attack surface 的**特殊 entitlement daemons**。要逆向具体接口，还可以查看关于 [**IOKit**](macos-iokit.md) 和 [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) 的页面。

## 仍然重要的攻击面

- 系统 daemons 和面向 kernel 的服务中的 **Mach/MIG handlers**：格式错误的 descriptors、out-of-line (OOL) data，以及有状态的多消息流程。
- **IOKit user clients**：特定 selector 的 parsing、由 entitlement 控制的方法，以及隐藏真实调用图的 wrapper libraries/daemons。
- **XNU data-only primitives**：围绕 credentials、受 SMR 保护的 pointers、只读 zones，以及其他可通过 corruption 改变策略、而无需先取得 RIP/PC 控制权的位置所产生的 races。
- **Third-party / auxiliary kernel code**：legacy kexts 虽然更加少见，但 enterprise fleets、reduced-security Apple Silicon systems，以及 vendor `.fs` / helper bundles 仍会创建高价值的 kernel-adjacent paths。

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

在[**这份报告**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)中，通过滥用 software update pipeline 和与 rootless 相关的 capabilities，组合多个 OTA/update-chain bugs，最终实现 kernel compromise。<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722)。

---

## 2024：野外利用的 kernel protection bypass chain（CVE-2024-23225 和 CVE-2024-23296）

Apple 的 [**2024 年 3 月 macOS security releases**](https://support.apple.com/en-us/120895) 修复了两个曾被**积极利用**的问题：

- **CVE-2024-23225 – Kernel**：一个 memory-corruption bug，拥有 arbitrary kernel read/write 的 attacker 可利用该漏洞绕过 kernel memory protections。
- **CVE-2024-23296 – RTKit**：第二个 memory-corruption bug，公开影响说明相同。

目前公开的 root-cause 细节仍然很少，但这两个漏洞很好地提醒我们：现代 Apple exploit chains 往往需要的不只是“kernel R/W”：针对 memory protections、coprocessor-adjacent code 或 secondary trust boundaries 的 post-exploitation 工作，通常才是稳定整个 chain 的关键所在。

快速 patch triage：
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025：SMR + 只读 credential race（CVE-2025-24118）

Joseph Ravichandran 的 [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) 是一个非常优秀的现代 XNU 案例研究，因为它**不是**经典的 buffer overflow：<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` 是存储在**只读** `proc_ro` 对象中的 **SMR-protected pointer**。
- Writer 必须以**原子方式**更新该 pointer。
- `kauth_cred_proc_update()` 使用 `zalloc_ro_mut(...)` 修改 `p_ucred`；在 x86_64 上，该路径最终会进入 `memcpy` / `rep movsb`，因此并发 reader 可能观察到一个 **torn pointer**。
- 该 bug 会转化为一种**仅数据型 privilege escalation**：如果损坏后的 credential pointer 解析到另一个有效的 credential object，当前 thread 就能继承更高权限的状态，而无需先明显劫持 control flow。

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
有用的 audit heuristic：每当 kernel path 混合使用 **SMR readers**、**read-only zone mutation** 以及 **credential 或 task metadata** 时，请确认更新使用的是 atomic `zalloc_ro_mut_*` variants，而不是基于复制的 helpers。

---

## 2024-2025：重新开启 kernel loading paths 的 SIP bypass（CVE-2024-44243）

Microsoft 证明，`storagekitd` 可被滥用于 **bypass SIP**，从而让 third-party kernel code 在原本看似 "post-kext" 的机器上重新变得相关。核心思路是：<sup>[[2]](#references)</sup>

1. 在 `/Library/Filesystems` 下放置或覆盖恶意 `.fs` bundle。
2. 通过 Disk Utility 或 `diskutil` 触发 `storagekitd`。
3. 让具有特殊 entitlement 的 daemon spawn bundle executables，同时**未正确 drop privileges / validate path**。
4. 利用由此产生的 SIP bypass 修改受保护的 file-system state；在 Microsoft 的演示中，还可覆盖 kernel extension exclusion list。

对于 kernel researchers，重要教训是：即使 direct third-party kext loading 受到严格限制，**kernel attack surface 仍可能通过 userland management daemons 被重新引入**。

有用的 triage：
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing 与 research workflow

如果你正在主动寻找这一类 bugs，近期的公开研究正指向相同方向：

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) 仍然是 Apple-Silicon 时代 kernel research 的最佳参考之一。它使用 **static binary rewriting** 来恢复 coverage，在测试期间禁用 **entitlement-gated** 路径，并从 userspace wrappers 推断 interface 结构。<sup>[[4]](#references)</sup>
- Project Zero 的 [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) 展示了一种非常实用的 workflow：将 **kext / fileset rebasing 到 userspace**，从而在设备上复现之前，以更高速度对以 parser 为主的代码进行 fuzzing。<sup>[[5]](#references)</sup>
- 对于以 Mach 为主的 targets，应围绕 **real message layouts and multi-call state machines** 构建 harness，而不只是使用单个 selector blobs。Project Zero 最近针对 CoreAudio/Mach 的 research，以及 **Fuzzing at Mach Speed** 等 conference talks，说明了为什么 stateful message sequences 能持续带来收益。

你实际会经常使用的快速本地命令：
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
- [3] [Mickey Jin - Apple OTA Update 的噩梦：绕过签名验证并 Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz：通过利用缓解措施在 Apple Silicon 上对 macOS Kernel EXTensions 进行 fuzzing（USENIX Security '23）](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - 使用 IDA 和 TinyInst 在 userspace 中对 macOS kernel extension 进行简单 fuzzing](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
