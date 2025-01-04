# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **查找Linux本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](privilege-escalation/index.html#system-information)

- [ ] 获取 **操作系统信息**
- [ ] 检查 [**PATH**](privilege-escalation/index.html#path)，是否有 **可写文件夹**？
- [ ] 检查 [**环境变量**](privilege-escalation/index.html#env-info)，是否有敏感信息？
- [ ] 搜索 [**内核漏洞**](privilege-escalation/index.html#kernel-exploits) **使用脚本**（DirtyCow？）
- [ ] **检查** [**sudo版本是否存在漏洞**](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** 签名验证失败](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] 更多系统枚举（[日期，系统统计，CPU信息，打印机](privilege-escalation/index.html#more-system-enumeration)）
- [ ] [枚举更多防御措施](privilege-escalation/index.html#enumerate-possible-defenses)

### [驱动器](privilege-escalation/index.html#drives)

- [ ] **列出已挂载**的驱动器
- [ ] **有未挂载的驱动器吗？**
- [ ] **fstab中有任何凭据吗？**

### [**已安装软件**](privilege-escalation/index.html#installed-software)

- [ ] **检查是否安装了** [**有用的软件**](privilege-escalation/index.html#useful-software)
- [ ] **检查是否安装了** [**易受攻击的软件**](privilege-escalation/index.html#vulnerable-software-installed)

### [进程](privilege-escalation/index.html#processes)

- [ ] 是否有 **未知软件在运行**？
- [ ] 是否有软件以 **超出其应有的权限**运行？
- [ ] 搜索 **正在运行进程的漏洞**（特别是正在运行的版本）。
- [ ] 你能 **修改任何正在运行进程的二进制文件**吗？
- [ ] **监控进程**，检查是否有任何有趣的进程频繁运行。
- [ ] 你能 **读取** 一些有趣的 **进程内存**（可能保存密码的地方）吗？

### [计划任务/Cron作业？](privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH**](privilege-escalation/index.html#cron-path)是否被某些cron修改且你可以 **写入**？
- [ ] 在cron作业中有任何 [**通配符**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)吗？
- [ ] 是否有某个 [**可修改的脚本**](privilege-escalation/index.html#cron-script-overwriting-and-symlink)正在 **执行**或在 **可修改文件夹**中？
- [ ] 你是否检测到某个 **脚本** 可能或正在被 [**频繁执行**](privilege-escalation/index.html#frequent-cron-jobs)？（每1、2或5分钟）

### [服务](privilege-escalation/index.html#services)

- [ ] 有任何 **可写的.service** 文件吗？
- [ ] 有任何 **可写的二进制文件** 被 **服务** 执行吗？
- [ ] 在systemd PATH中有任何 **可写文件夹**？

### [定时器](privilege-escalation/index.html#timers)

- [ ] 有任何 **可写的定时器**？

### [套接字](privilege-escalation/index.html#sockets)

- [ ] 有任何 **可写的.socket** 文件吗？
- [ ] 你能 **与任何套接字通信**吗？
- [ ] **HTTP套接字**中有有趣的信息吗？

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] 你能 **与任何D-Bus通信**吗？

### [网络](privilege-escalation/index.html#network)

- [ ] 枚举网络以了解你的位置
- [ ] **打开的端口你之前无法访问**，现在可以在机器内部获取shell吗？
- [ ] 你能使用 `tcpdump` **嗅探流量**吗？

### [用户](privilege-escalation/index.html#users)

- [ ] 通用用户/组 **枚举**
- [ ] 你有一个 **非常大的UID** 吗？ **机器** **易受攻击**吗？
- [ ] 你能 [**通过你所属的组提升权限**](privilege-escalation/interesting-groups-linux-pe/index.html)吗？
- [ ] **剪贴板** 数据？
- [ ] 密码策略？
- [ ] 尝试 **使用** 你之前发现的每个 **已知密码** 登录 **每个** 可能的 **用户**。 也尝试不带密码登录。

### [可写的PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] 如果你对某个PATH中的文件夹 **具有写权限**，你可能能够提升权限

### [SUDO和SUID命令](privilege-escalation/index.html#sudo-and-suid)

- [ ] 你能执行 **任何带sudo的命令**吗？ 你能用它 **读取、写入或执行** 任何东西作为root吗？ ([**GTFOBins**](https://gtfobins.github.io))
- [ ] 是否有任何 **可利用的SUID二进制文件**？ ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** 命令是否 **受限于** **路径**？你能 **绕过** 限制吗](privilege-escalation/index.html#sudo-execution-bypassing-paths)？
- [ ] [**没有指定路径的Sudo/SUID二进制文件**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**指定路径的SUID二进制文件**](privilege-escalation/index.html#suid-binary-with-command-path)？ 绕过
- [ ] [**LD_PRELOAD漏洞**](privilege-escalation/index.html#ld_preload)
- [ ] [**SUID二进制文件中缺少.so库**](privilege-escalation/index.html#suid-binary-so-injection)来自可写文件夹？
- [ ] [**可用的SUDO令牌**](privilege-escalation/index.html#reusing-sudo-tokens)？ [**你能创建SUDO令牌吗**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] 你能 [**读取或修改sudoers文件**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)吗？
- [ ] 你能 [**修改/etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)吗？
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) 命令

### [能力](privilege-escalation/index.html#capabilities)

- [ ] 是否有任何二进制文件具有 **意外的能力**？

### [ACLs](privilege-escalation/index.html#acls)

- [ ] 是否有任何文件具有 **意外的ACL**？

### [开放Shell会话](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL可预测PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH有趣的配置值**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [有趣的文件](privilege-escalation/index.html#interesting-files)

- [ ] **配置文件** - 读取敏感数据？ 写入权限提升？
- [ ] **passwd/shadow文件** - 读取敏感数据？ 写入权限提升？
- [ ] **检查常见的有趣文件夹**以查找敏感数据
- [ ] **奇怪的位置/拥有的文件，**你可能有权限访问或更改可执行文件
- [ ] **最近几分钟内修改**
- [ ] **Sqlite数据库文件**
- [ ] **隐藏文件**
- [ ] **PATH中的脚本/二进制文件**
- [ ] **Web文件**（密码？）
- [ ] **备份**？
- [ ] **已知包含密码的文件**：使用 **Linpeas** 和 **LaZagne**
- [ ] **通用搜索**

### [**可写文件**](privilege-escalation/index.html#writable-files)

- [ ] **修改python库**以执行任意命令？
- [ ] 你能 **修改日志文件**吗？ **Logtotten** 漏洞
- [ ] 你能 **修改/etc/sysconfig/network-scripts/**吗？ Centos/Redhat 漏洞
- [ ] 你能 [**写入ini、int.d、systemd或rc.d文件**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)吗？

### [**其他技巧**](privilege-escalation/index.html#other-tricks)

- [ ] 你能 [**利用NFS提升权限**](privilege-escalation/index.html#nfs-privilege-escalation)吗？
- [ ] 你需要 [**逃离限制性shell**](privilege-escalation/index.html#escaping-from-restricted-shells)吗？

{{#include ../banners/hacktricks-training.md}}
