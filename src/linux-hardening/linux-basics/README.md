# Linux 基础

{{#include ../../banners/hacktricks-training.md}}

这是 Linux 主机评估的起点。以下页面涵盖广泛的提权工作流、实用命令、环境变量，以及影响主机上可运行内容的常见限制。

- [Linux privilege escalation](linux-privilege-escalation/README.md) 介绍枚举和潜在的本地提权路径。若需要更精简的任务清单，请使用[提权检查清单](../main-system-information/linux-privilege-escalation-checklist.md)。
- [Shell 启动、别名和历史记录](shell-startup-aliases-and-history.md) 介绍命令解析、启动文件执行和历史记录中的线索。
- [实用 Linux 命令](useful-linux-commands.md) 汇集了用于检查文件、进程、服务和环境的命令。
- [Linux 环境变量](linux-environment-variables.md) 介绍环境变量如何影响执行，以及敏感值可能出现的位置。
- [绕过 Linux 限制](bypass-linux-restrictions/README.md) 涵盖受限 shell 和执行环境，包括文件系统保护、`noexec` 和 distroless 系统。

## 原生二进制利用

如果评估发现存在漏洞的 Linux 可执行文件，请参考 Binary Exploitation 中的相关资料：

- [ELF 格式和加载器行为](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md)以及[二进制保护和绕过方法](../../binary-exploitation/common-binary-protections-and-bypasses/README.md)介绍可执行文件布局和缓解措施。
- [栈利用](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md)和 [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md)介绍控制流攻击。
- [Libc 堆利用](../../binary-exploitation/libc-heap/README.md)和[格式字符串](../../binary-exploitation/format-strings/README.md)介绍其他常见的内存破坏路径。

内核相关案例研究见 [Kernel/LPE/CVE 资料](../main-system-information/kernel-lpe-cves/README.md)。
{{#include ../../banners/hacktricks-training.md}}
