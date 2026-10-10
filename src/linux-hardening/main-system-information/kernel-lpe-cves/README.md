# 内核、LPE 和 CVE 资料

{{#include ../../../banners/hacktricks-training.md}}

这些案例研究涵盖了不同的本地权限提升原语。使用每篇文章中的技术前，请检查受影响的产品或内核、配置及前置条件。若要更广泛地枚举主机，请使用 [Linux 权限提升检查清单](../linux-privilege-escalation-checklist.md)。

对于 Dirty Pipe (CVE-2022-0847)，[原始研究](https://dirtypipe.cm4all.com/)指出，上游稳定版的修复版本为 5.10.102、5.15.25 和 5.16.11。内核版本处于较早的受影响范围，只能作为进一步检查的线索：发行版内核可能会以不同的发行版本号回移植修复，而且页缓存写入原语要求目标文件可读。当 set-ID 转换仍然有效时，覆盖可读的 SUID 可执行文件是一种可能的提权路径；修改 `/etc/passwd` 后再进行身份验证，也可能取决于本地 PAM 配置栈。在评估是否可利用前，请检查已安装的厂商内核软件包、重启后运行的内核、目标权限、挂载选项 `nosuid` 以及 `no_new_privs`。被动枚举期间不要执行写入探测。另请参阅 [Ubuntu 针对具体发行版的状态说明](https://ubuntu.com/security/CVE-2022-0847)。

- [VMware Tools 服务发现，CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md)：通过不可信的进程路径发现实现特权执行。
- [AF_ALG splice 页缓存覆盖，CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md)：一种内核页缓存覆盖路径。
- [POSIX CPU timers TOCTOU，CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md)：定时器处理中的竞态。
- [Linux ptrace 退出竞态和 `pidfd_getfd` 文件描述符窃取](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)：在进程退出竞态期间访问文件描述符。

## 相关二进制利用案例

Binary Exploitation 部分将深入介绍这些 Linux 内核目标的利用原语、内存布局和缓解措施绕过方法：

- [AF_UNIX 带外 SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md)：将 socket 漏洞发展为内核读写原语。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md)：通过 pipe 缓冲区和 workqueue 扩展指针写入原语。
- [ksmbd streams 越界写入，CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md)：内核堆利用和缓解措施绕过。
- [POSIX CPU timers TOCTOU，CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md)：对上述定时器竞态的二进制利用分析。
- [Arm64 静态线性映射 KASLR 绕过](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md)：用于 arm64 内核利用的地址发现。
- [Adreno A7xx GPU/SMMU 权限绕过](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md)：通过 Android GPU 路径访问内核内存。
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md)：用于内核写入的 Android 加速器漏洞。
{{#include ../../../banners/hacktricks-training.md}}
