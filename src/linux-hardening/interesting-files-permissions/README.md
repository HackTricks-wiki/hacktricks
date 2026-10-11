# 有趣的文件与权限

{{#include ../../banners/hacktricks-training.md}}

文件所有权、写入权限、挂载选项和可执行权限都可能改变本地用户的实际权限范围。先确定目标文件或执行路径，然后查看相关页面：

- [SUID、SGID、ACL 和敏感文件](suid-sgid-and-acl-triage.md)介绍了检查可执行权限和隐藏访问授权的入门流程。
- [任意文件写入 root 路径](write-to-root.md)介绍了如何利用对特权路径的写入实现权限提升。
- [Linux capabilities](linux-capabilities.md)解释了进程级和文件级 capabilities。
- [SUID 共享库与 linker 滥用](suid-shared-library-and-linker-abuse.md)介绍了特权二进制文件周围的动态加载。
- [`ld.so` 权限提升示例](ld.so.conf-example.md)分析了一个 linker 配置案例。
- [NFS `no_root_squash` 和 `no_all_squash` 错误配置](nfs-no_root_squash-misconfiguration-pe.md)介绍了远程文件系统的身份映射。
- [通配符技巧](wildcards-spare-tricks.md)介绍了特权命令中的参数展开。
- [SELinux](selinux.md)解释了策略执行机制和相关调查步骤。
{{#include ../../banners/hacktricks-training.md}}
