# Linux 加固

{{#include ../banners/hacktricks-training.md}}

使用本节调查 Linux 主机、了解权限边界，并检查限制本地访问的控制措施。进行一般性评估时，请先查看 [Linux 基础知识](linux-basics/README.md)和[权限提升检查清单](main-system-information/linux-privilege-escalation-checklist.md)，然后继续阅读下面相关主题。

- [Linux 基础知识](linux-basics/README.md)：权限提升方法、实用命令、环境变量和限制绕过。
- [主要系统信息](main-system-information/README.md)：内核、模块、sudo、文件系统行为、jail 和权限提升检查清单。
- [用户信息](user-information/README.md)：Linux 身份、组、SSH agent 转发和 Active Directory 集成。
- [有趣的文件和权限](interesting-files-permissions/README.md)：可写路径、capabilities、SUID 行为、NFS、通配符展开和 SELinux。
- [网络信息](network-information/README.md)：本地服务、套接字和网络相关的利用示例。
- [软件信息](software-information/README.md)：身份验证模块和特定于应用程序的攻击面。
- [进程、crontab、systemd 和 D-Bus](processes-crontab-systemd-dbus/README.md)：计划执行和进程间通信。
- [容器和命名空间](containers-namespaces/README.md)：运行时、隔离边界和容器加固。
- [滥用 AppArmor 策略控制文件](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive)：评估特权 helper 是否能写入由本地用户打开的 AppArmor 控制文件。
- [Post-exploitation](post-exploitation/README.md)：凭据发现、持久化和主机级后续技术。

在受影响的内核上，非特权用户打开 securityfs 中的 AppArmor 策略控制文件可能会成功，即使直接写入会被拒绝。如果特权 helper 继承该文件作为 stdout，其写入就可能改变已加载的策略；这是一种独立的本地攻击路径，不同于仅仅发现较弱的容器配置文件。测试前，请检查供应商内核和 helper 的修复情况。<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Qualys CrackArmor 技术公告](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Ubuntu CrackArmor 漏洞知识库](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
