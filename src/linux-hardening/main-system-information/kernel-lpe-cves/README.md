# Kernel、LPE 和 CVE 资料

{{#include ../../../banners/hacktricks-training.md}}

这些案例研究涵盖了不同的本地提权原语。应用技术前，请在各篇文章中检查受影响的产品或 kernel、配置和前置条件。如需更全面的主机枚举，请使用 [Linux privilege escalation checklist](../linux-privilege-escalation-checklist.md)。

对于 Dirty Pipe（CVE-2022-0847），[原始研究](https://dirtypipe.cm4all.com/)指出，上游稳定版的修复版本为 5.10.102、5.15.25 和 5.16.11。旧版受影响范围内的 kernel 版本只能作为进一步检查的线索：发行版 kernel 可能以不同的版本名称回移修复，而且 page-cache write primitive 所需的目标文件必须可读。若 SUID 可执行文件的 set-ID 转换仍然有效，覆盖该文件是可能的提权途径之一；修改 `/etc/passwd` 后再进行身份验证，也可能受本地 PAM 配置影响。评估可利用性前，请检查已安装的厂商 kernel 软件包、重启后的运行中 kernel、目标权限、挂载选项 `nosuid` 和 `no_new_privs`。被动枚举期间不要执行写入探测。参见 [Ubuntu 针对具体版本的状态说明](https://ubuntu.com/security/CVE-2022-0847)。

- [VMware Tools 服务发现，CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md)：通过不可信的进程路径发现实现特权执行。
- [AF_ALG splice page-cache 覆盖，CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md)：一种 kernel page-cache 覆盖途径。
- [POSIX CPU timers TOCTOU，CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md)：timer 处理中的竞态。
- [Linux ptrace 退出竞态与 `pidfd_getfd` 文件描述符窃取](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)：跨进程退出竞态访问文件描述符。

## 相关二进制漏洞利用案例研究

Binary Exploitation 章节将深入讲解这些 Linux kernel 目标的 exploit primitives、内存布局和缓解措施绕过方法：

- [AF_UNIX 带外 SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md)：将 socket 漏洞发展为 kernel 读写 primitives。
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md)：通过 pipe buffers 和 workqueues 扩展 pointer-write primitive。
- [ksmbd streams 越界写入，CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md)：kernel heap exploitation 和缓解措施绕过方法。
- [POSIX CPU timers TOCTOU，CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md)：对上文总结的 timer 竞态进行二进制漏洞利用分析。
- [Arm64 static linear-map KASLR 绕过](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md)：为 arm64 kernel exploitation 发现地址。
- [Adreno A7xx GPU/SMMU 权限绕过](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md)：通过 Android GPU 途径访问 kernel 内存。
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md)：利用 Android 加速器漏洞写入 kernel。
{{#include ../../../banners/hacktricks-training.md}}
