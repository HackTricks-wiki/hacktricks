# 有趣的文件与权限

{{#include ../../banners/hacktricks-training.md}}

文件所有权、写入权限、挂载选项和可执行权限都可能改变本地用户的实际访问范围。先确定目标文件或执行路径，然后参考相关页面：

- [SUID、SGID、ACL 和敏感文件](suid-sgid-and-acl-triage.md)介绍可执行权限和隐藏访问授权的初步排查流程。
- [任意文件写入 root](write-to-root.md)介绍如何利用对特权路径的写入权限实现提权。
- [Linux capabilities](linux-capabilities.md)介绍进程级和文件级 capabilities。
- [SUID 共享库和链接器滥用](suid-shared-library-and-linker-abuse.md)介绍特权二进制文件相关的动态加载利用。
- [`ld.so` 提权示例](ld.so.conf-example.md)分析一个链接器配置案例。
- [NFS `no_root_squash` 和 `no_all_squash` 配置错误](nfs-no_root_squash-misconfiguration-pe.md)介绍远程文件系统中的身份映射。
- [通配符参数技巧](wildcards-spare-tricks.md)介绍特权命令中的参数展开。
- [SELinux](selinux.md)介绍策略实施和相关调查步骤。
{{#include ../../banners/hacktricks-training.md}}
