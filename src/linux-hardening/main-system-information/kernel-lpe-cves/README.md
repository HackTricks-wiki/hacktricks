# 内核、LPE 和 CVE 资料

{{#include ../../../banners/hacktricks-training.md}}

这些案例研究涵盖了不同的本地权限提升原语。应用技术前，请先在每篇文章中核实受影响的产品或内核、配置和前置条件。如需更全面的主机枚举，请使用 [Linux 权限提升检查清单](../linux-privilege-escalation-checklist.md)。

对于 Dirty Pipe (CVE-2022-0847)，[原始研究](https://dirtypipe.cm4all.com/)指出，上游稳定版修复版本为 5.10.102、5.15.25 和 5.16.11。内核版本处于较早的受影响范围只能作为进一步检查的线索：发行版内核可能以不同的版本名称回移植修复，并且要使用 page-cache 写入原语，相关目标文件必须可读。当 set-ID 转换仍然有效时，覆盖可读的 SUID 可执行文件是可能的提权路径之一；修改 `/etc/passwd` 后进行身份验证，也可能受本地 PAM 堆栈影响。评估该漏洞是否可利用前，请检查已安装的供应商内核软件包、重启后运行的内核、目标权限、挂载选项 `nosuid` 和 `no_new_privs`。被动枚举期间不要执行写入探测。请参阅 [Ubuntu 按发行版提供的状态信息](https://ubuntu.com/security/CVE-2022-0847)。

- [VMware Tools 服务发现，CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md)：通过不可信的进程路径发现机制执行特权操作。
- [AF_ALG splice page-cache 覆盖，CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md)：一种内核 page-cache 覆盖路径。
- [POSIX CPU timers TOCTOU，CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md)：计时器处理中的竞争条件。
- [Linux ptrace 退出竞争与 `pidfd_getfd` 文件描述符窃取](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)：在进程退出竞争期间访问文件描述符。

## 相关二进制漏洞利用案例研究

Binary Exploitation 部分将深入讲解这些 Linux 内核目标的漏洞利用原语、内存布局和缓解措施绕过方法：

- [AF_UNIX 带外 SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md)：将套接字漏洞发展为内核读写原语。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md)：通过 pipe 缓冲区和 workqueue 扩展指针写入原语。
- [ksmbd streams 越界写入，CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md)：内核堆利用和缓解措施绕过。
- [POSIX CPU timers TOCTOU，CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md)：对上文概述的计时器竞争条件进行二进制漏洞利用分析。
- [Arm64 静态线性映射 KASLR 绕过](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md)：用于 arm64 内核利用的地址发现。
- [Adreno A7xx GPU/SMMU 权限绕过](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md)：通过 Android GPU 路径访问内核内存。
- [Pixel Bigwave 任务超时 use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md)：利用 Android 加速器漏洞写入内核。
{{#include ../../../banners/hacktricks-training.md}}
