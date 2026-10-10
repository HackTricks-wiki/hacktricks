# 容器和命名空间

{{#include ../../banners/hacktricks-training.md}}

容器是以隔离和权限配置运行的 Linux 进程。应结合评估运行时、挂载的主机资源、授予的 capabilities 以及命名空间设置。[容器安全概述](container-security/README.md)介绍了这些层面，并链接到各项控制措施。

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md)重点介绍对 containerd 管理接口的访问。
- [RunC privilege escalation](runc-privilege-escalation.md)介绍特定于运行时的 privilege escalation 内容。
- [容器安全](container-security/README.md)介绍运行时、暴露的 API、镜像风险、敏感挂载、特权容器、评估，以及命名空间、seccomp 和强制访问控制等保护措施。
{{#include ../../banners/hacktricks-training.md}}
