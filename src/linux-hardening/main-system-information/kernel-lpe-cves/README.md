# Kernel、LPE 与 CVE 资料

{{#include ../../../banners/hacktricks-training.md}}

这些案例介绍了不同的本地权限提升原语。应用技术前，请在各篇文章中核对受影响的产品或内核、配置和前置条件。如需进行更广泛的主机枚举，请使用 [Linux 权限提升检查清单](../linux-privilege-escalation-checklist.md)。

对于 Dirty Pipe（CVE-2022-0847），[原始研究](https://dirtypipe.cm4all.com/)指出，上游稳定版的修复版本分别为 5.10.102、5.15.25 和 5.16.11。旧版受影响范围内的内核版本只能作为进一步检查的线索：发行版内核可能会以不同的版本号回移修复，而且要使用 page-cache 写入原语，目标文件必须可读。覆盖可读的 SUID 可执行文件，是一种可能的提权路径，前提是其 set-ID 转换仍然有效；修改 `/etc/passwd` 后再进行身份验证，也可能取决于本地 PAM 配置栈。在评估是否可利用之前，请检查已安装的厂商内核包、重启后运行的内核、目标权限、挂载选项 `nosuid` 和 `no_new_privs`。被动枚举期间不要执行写入探测。另请参阅 [Ubuntu 针对各发行版版本的状态说明](https://ubuntu.com/security/CVE-2022-0847)。

- [VMware Tools 服务发现，CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md)：通过不可信的进程路径发现机制实现特权执行。
- [AF_ALG splice page-cache 覆盖，CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md)：一种内核 page-cache 覆盖路径。
- [POSIX CPU timers TOCTOU 竞态与利用，CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit)：任务退出时的计时器到期/删除问题，包括 IRQ 路径的前置条件和利用研究。
- [Linux ptrace 退出竞态与 `pidfd_getfd` 文件描述符窃取](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)：在进程退出竞态期间访问文件描述符。

## 相关二进制利用案例

Binary Exploitation 部分将深入介绍这些 Linux 内核目标的利用原语、内存布局和缓解措施绕过方法：

- [AF_UNIX 带外 SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md)：将一个 socket 漏洞发展为内核读写原语。
- [AF_ALG 并发写入器 scatterlist 下溢](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md)：将 skcipher 写入器竞态发展为内核写入。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md)：通过 pipe buffers 和 workqueues 扩展指针写入原语。
- [ksmbd streams 越界写入，CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md)：内核堆利用与缓解措施绕过。
- [Arm64 静态线性映射 KASLR 绕过](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md)：为 arm64 内核利用发现地址。
- [Adreno A7xx GPU/SMMU 权限绕过](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md)：通过 Android GPU 路径访问内核内存。
- [Pixel Bigwave 作业超时 use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md)：利用 Android 加速器漏洞执行内核写入。
{{#include ../../../banners/hacktricks-training.md}}
