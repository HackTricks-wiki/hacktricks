# 主系统信息

{{#include ../../banners/hacktricks-training.md}}

在选择本地提权技术前，先检查主机的内核、文件系统、特权辅助程序和可用的逃逸路径。[提权检查清单](linux-privilege-escalation-checklist.md)提供了简明的操作顺序。

- [内核漏洞评估与运行时暴露面](kernel-vulnerability-assessment.md)检查构建版本适用性、可达性和已启用的缓解措施。
- [内核模块与 modprobe 滥用](kernel-modules-and-modprobe.md)介绍模块加载和辅助程序路径暴露。
- [Sudo 命令滥用](sudo-command-abuse.md)探查委派命令跨越权限边界的方式。
- [符号链接、硬链接和文件描述符](filesystem-links-and-file-descriptors.md)介绍路径重定向，以及继承的或已删除但仍打开的文件。
- [文件系统、inode 与恢复](filesystem-inodes-and-recovery.md)解释调查过程中可能派上用场的文件系统行为。
- [检查清单：Linux 提权](linux-privilege-escalation-checklist.md)列出主机检查项，并链接到更深入的内容。
- [逃离受限环境](escaping-from-limited-bash.md)介绍受限 shell 和受限环境。
- [内核/LPE/CVE 资料](kernel-lpe-cves/README.md)汇集了针对本地提权和漏洞的专题文章。
{{#include ../../banners/hacktricks-training.md}}
