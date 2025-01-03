# 清单 - Linux 权限提升

{{#include ../banners/hacktricks-training.md}}

### **查找 Linux 本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](privilege-escalation/#system-information)

- [ ] 获取 **操作系统信息**
- [ ] 检查 [**PATH**](privilege-escalation/#path)，是否有 **可写文件夹**？
- [ ] 检查 [**环境变量**](privilege-escalation/#env-info)，是否有敏感信息？
- [ ] 搜索 [**内核漏洞**](privilege-escalation/#kernel-exploits) **使用脚本**（DirtyCow？）
- [ ] **检查** [**sudo 版本是否存在漏洞**](privilege-escalation/#sudo-version)
- [ ] [**Dmesg** 签名验证失败](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] 更多系统枚举（[日期，系统统计，CPU 信息，打印机](privilege-escalation/#more-system-enumeration)）
- [ ] [枚举更多防御措施](privilege-escalation/#enumerate-possible-defenses)

### [驱动器](privilege-escalation/#drives)

- [ ] **列出已挂载**的驱动器
- [ ] **有未挂载的驱动器吗？**
- [ ] **fstab 中有任何凭据吗？**

### [**已安装软件**](privilege-escalation/#installed-software)

- [ ] **检查是否有**[ **有用的软件**](privilege-escalation/#useful-software) **已安装**
- [ ] **检查是否有** [**易受攻击的软件**](privilege-escalation/#vulnerable-software-installed) **已安装**

### [进程](privilege-escalation/#processes)

- [ ] 是否有 **未知软件在运行**？
- [ ] 是否有软件以 **超出其应有的权限**运行？
- [ ] 搜索 **正在运行进程的漏洞**（特别是正在运行的版本）。
- [ ] 你能 **修改任何正在运行进程的二进制文件**吗？
- [ ] **监控进程**并检查是否有任何有趣的进程频繁运行。
- [ ] 你能 **读取**一些有趣的 **进程内存**（可能保存密码的地方）吗？

### [计划任务/Cron 任务？](privilege-escalation/#scheduled-jobs)

- [ ] [**PATH**](privilege-escalation/#cron-path) 是否被某些 cron 修改且你可以 **写入**？
- [ ] 在 cron 任务中有任何 [**通配符**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) 吗？
- [ ] 有一些 [**可修改的脚本**](privilege-escalation/#cron-script-overwriting-and-symlink) 正在 **执行**或在 **可修改文件夹**中？
- [ ] 你是否检测到某些 **脚本** 可能或正在被 [**频繁执行**](privilege-escalation/#frequent-cron-jobs)？（每 1、2 或 5 分钟）

### [服务](privilege-escalation/#services)

- [ ] 有任何 **可写的 .service** 文件吗？
- [ ] 有任何 **可写的二进制文件** 被 **服务** 执行吗？
- [ ] 在 systemd PATH 中有任何 **可写文件夹**？

### [定时器](privilege-escalation/#timers)

- [ ] 有任何 **可写的定时器**？

### [套接字](privilege-escalation/#sockets)

- [ ] 有任何 **可写的 .socket** 文件吗？
- [ ] 你能 **与任何套接字通信**吗？
- [ ] **HTTP 套接字**中有有趣的信息吗？

### [D-Bus](privilege-escalation/#d-bus)

- [ ] 你能 **与任何 D-Bus 通信**吗？

### [网络](privilege-escalation/#network)

- [ ] 枚举网络以了解你的位置
- [ ] **打开的端口你之前无法访问**，现在可以在机器内部获取 shell 吗？
- [ ] 你能使用 `tcpdump` **嗅探流量**吗？

### [用户](privilege-escalation/#users)

- [ ] 通用用户/组 **枚举**
- [ ] 你有一个 **非常大的 UID** 吗？该 **机器** **易受攻击**吗？
- [ ] 你能 [**通过你所属的组提升权限**](privilege-escalation/interesting-groups-linux-pe/)吗？
- [ ] **剪贴板** 数据？
- [ ] 密码策略？
- [ ] 尝试 **使用**你之前发现的每个 **已知密码** 登录 **每个** 可能的 **用户**。也尝试不带密码登录。

### [可写 PATH](privilege-escalation/#writable-path-abuses)

- [ ] 如果你对 **PATH 中的某个文件夹有写权限**，你可能能够提升权限

### [SUDO 和 SUID 命令](privilege-escalation/#sudo-and-suid)

- [ ] 你能执行 **任何带 sudo 的命令**吗？你能用它来以 root 身份读取、写入或执行任何东西吗？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] 是否有任何 **可利用的 SUID 二进制文件**？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** 命令是否 **受限**于 **路径**？你能 **绕过** 限制吗](privilege-escalation/#sudo-execution-bypassing-paths)？
- [ ] [**Sudo/SUID 二进制文件没有指定路径**](privilege-escalation/#sudo-command-suid-binary-without-command-path)？
- [ ] [**SUID 二进制文件指定路径**](privilege-escalation/#suid-binary-with-command-path)？绕过
- [ ] [**LD_PRELOAD 漏洞**](privilege-escalation/#ld_preload)
- [ ] [**SUID 二进制文件中缺少 .so 库**](privilege-escalation/#suid-binary-so-injection)来自可写文件夹？
- [ ] [**可用的 SUDO 令牌**](privilege-escalation/#reusing-sudo-tokens)？[**你能创建 SUDO 令牌吗**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] 你能 [**读取或修改 sudoers 文件**](privilege-escalation/#etc-sudoers-etc-sudoers-d)吗？
- [ ] 你能 [**修改 /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)吗？
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) 命令

### [能力](privilege-escalation/#capabilities)

- [ ] 是否有任何二进制文件具有 **意外的能力**？

### [ACLs](privilege-escalation/#acls)

- [ ] 是否有任何文件具有 **意外的 ACL**？

### [开放的 Shell 会话](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL 可预测 PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH 有趣的配置值**](privilege-escalation/#ssh-interesting-configuration-values)

### [有趣的文件](privilege-escalation/#interesting-files)

- [ ] **配置文件** - 读取敏感数据？写入权限提升？
- [ ] **passwd/shadow 文件** - 读取敏感数据？写入权限提升？
- [ ] **检查常见的有趣文件夹**以查找敏感数据
- [ ] **奇怪的位置/拥有的文件，**你可能有权限访问或更改可执行文件
- [ ] **最近修改**的文件
- [ ] **Sqlite 数据库文件**
- [ ] **隐藏文件**
- [ ] **PATH 中的脚本/二进制文件**
- [ ] **Web 文件**（密码？）
- [ ] **备份**？
- [ ] **已知包含密码的文件**：使用 **Linpeas** 和 **LaZagne**
- [ ] **通用搜索**

### [**可写文件**](privilege-escalation/#writable-files)

- [ ] **修改 Python 库**以执行任意命令？
- [ ] 你能 **修改日志文件**吗？**Logtotten** 漏洞
- [ ] 你能 **修改 /etc/sysconfig/network-scripts/** 吗？Centos/Redhat 漏洞
- [ ] 你能 [**写入 ini、int.d、systemd 或 rc.d 文件**](privilege-escalation/#init-init-d-systemd-and-rc-d)吗？

### [**其他技巧**](privilege-escalation/#other-tricks)

- [ ] 你能 [**利用 NFS 提升权限**](privilege-escalation/#nfs-privilege-escalation)吗？
- [ ] 你需要 [**逃离限制性 shell**](privilege-escalation/#escaping-from-restricted-shells)吗？

{{#include ../banners/hacktricks-training.md}}
