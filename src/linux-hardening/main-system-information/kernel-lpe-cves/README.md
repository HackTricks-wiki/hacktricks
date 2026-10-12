# 内核、LPE 与 CVE 资料

{{#include ../../../banners/hacktricks-training.md}}

这些案例研究涵盖了不同的本地权限提升原语。在应用技术前，请先在各篇文章中检查受影响的产品或内核、配置及前置条件。如需更全面的主机枚举，请使用 [Linux 权限提升检查清单](../linux-privilege-escalation-checklist.md)。

对于 Dirty Pipe (CVE-2022-0847)，[原始研究](https://dirtypipe.cm4all.com/)指出，上游稳定版的修复版本为 5.10.102、5.15.25 和 5.16.11。旧版受影响范围内的内核版本只能作为进一步检查的线索：发行版内核可能以不同的版本名称回移修复，而且 page-cache 写入原语要求目标文件可读。如果 SUID 可执行文件仍能有效完成 set-ID 转换，覆盖该文件是可能的提权路径之一；修改 `/etc/passwd` 后再进行身份验证，也可能取决于本地 PAM 配置栈。在评估漏洞是否可利用前，请检查已安装的厂商内核包、重启后的运行内核、目标权限、挂载选项 `nosuid` 以及 `no_new_privs`。被动枚举时不要运行写入探测。请参阅 [Ubuntu 针对各发行版的状态说明](https://ubuntu.com/security/CVE-2022-0847)。

- [VMware Tools 服务发现，CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md)：通过不可信的进程路径发现机制实现特权执行。
- [AF_ALG splice page-cache 覆写，CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md)：一种内核 page-cache 覆写路径。
- [POSIX CPU 定时器 TOCTOU，CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md)：定时器处理中的竞争条件。
- [Linux ptrace 退出竞争与 `pidfd_getfd` 文件描述符窃取](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)：在进程退出竞争期间访问文件描述符。

## 相关二进制利用案例研究

Binary Exploitation 章节深入介绍了这些 Linux 内核目标的利用原语、内存布局和缓解措施绕过方法：

- [AF_UNIX 带外 SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md)：将 socket 漏洞发展为内核读写原语。
- [AF_ALG 并发写入者 scatterlist 下溢](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md)：将 skcipher 写入者竞争发展为内核写入。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md)：通过 pipe buffers 和 workqueues 扩展指针写入原语。
- [ksmbd streams 越界写入，CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md)：内核堆利用与缓解措施绕过。
- [POSIX CPU 定时器 TOCTOU，CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md)：对上文所概述的定时器竞争问题进行二进制利用分析。
- [Arm64 静态线性映射 KASLR 绕过](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md)：为 arm64 内核利用发现地址。
- [Adreno A7xx GPU/SMMU 权限绕过](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md)：通过 Android GPU 路径访问内核内存。
- [Pixel Bigwave 作业超时 use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md)：利用 Android 加速器漏洞执行内核写入。
{{#include ../../../banners/hacktricks-training.md}}
