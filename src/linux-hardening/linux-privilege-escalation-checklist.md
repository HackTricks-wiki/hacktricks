# 清单 - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] 获取 **OS information**
- [ ] 检查 [**PATH**](privilege-escalation/index.html#path)，有没有 **可写的文件夹**？
- [ ] 检查 [**env variables**](privilege-escalation/index.html#env-info)，有没有敏感信息？
- [ ] 使用脚本搜索 [**kernel exploits**](privilege-escalation/index.html#kernel-exploits)（DirtyCow？）
- [ ] **检查** [**sudo version** 是否存在漏洞](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] 更多系统枚举（[date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration)）
- [ ] [枚举更多防御措施](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **列出已挂载** 驱动器
- [ ] 有没有 **未挂载的驱动器**？
- [ ] **fstab** 中有没有凭证？

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **检查是否安装** 任何[ **有用的软件**](privilege-escalation/index.html#useful-software)
- [ ] **检查是否安装** 任何[**易受攻击的软件**](privilege-escalation/index.html#vulnerable-software-installed)

### [Processes](privilege-escalation/index.html#processes)

- [ ] 是否有任何 **未知软件在运行**？
- [ ] 是否有软件以 **比应有更多的权限运行**？
- [ ] 搜索正在运行进程的 **漏洞**（尤其是运行的版本）。
- [ ] 你能否 **修改任何正在运行进程的二进制文件**？
- [ ] **监控进程** 并检查是否有任何有趣的进程频繁运行。
- [ ] 你能否 **读取** 某些有趣的 **进程内存**（可能保存密码）？

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] 是否有 cron 修改了 [**PATH** ](privilege-escalation/index.html#cron-path) 且你可以 **写入**？
- [ ] 有没有 cron 作业使用 [**通配符** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)？
- [ ] 是否有可[**修改的脚本** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) 被 **执行** 或位于 **可修改的文件夹** 中？
- [ ] 你是否发现某些 **脚本** 被[**非常频繁地**](privilege-escalation/index.html#frequent-cron-jobs) 执行？（每 1、2 或 5 分钟）

### [Services](privilege-escalation/index.html#services)

- [ ] 有没有 **可写的 .service** 文件？
- [ ] 有没有由 **service** 执行的 **可写二进制**？
- [ ] systemd PATH 中有没有 **可写文件夹**？
- [ ] `/etc/systemd/system/<unit>.d/*.conf` 中有没有 **可写的 systemd unit drop-in** 可以覆盖 `ExecStart`/`User`？

### [Timers](privilege-escalation/index.html#timers)

- [ ] 有没有 **可写的 timer**？

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] 有没有 **可写的 .socket** 文件？
- [ ] 你能否 **与任意 socket 通信**？
- [ ] 有包含有趣信息的 **HTTP sockets**？

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] 你能否 **与任意 D-Bus 通信**？

### [Network](privilege-escalation/index.html#network)

- [ ] 枚举网络以了解你的所在位置
- [ ] 在获取机器 shell 后，是否出现了之前无法访问的 **开放端口**？
- [ ] 你能否使用 `tcpdump` **嗅探流量**？

### [Users](privilege-escalation/index.html#users)

- [ ] 对通用用户/组进行 **枚举**
- [ ] 你有非常大的 UID 吗？机器是否 **易受攻击**？
- [ ] 你能否通过你所属的一个[**组来升级权限**](privilege-escalation/interesting-groups-linux-pe/index.html)？
- [ ] **剪贴板** 数据？
- [ ] 密码策略？
- [ ] 尝试对每个可能的用户使用你之前发现的每一个 **已知密码** 登录。也尝试无密码登录。

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] 如果你对 PATH 中的某个文件夹有 **写入权限**，你可能能够升级权限

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] 你能以 sudo 执行 **任何命令** 吗？你能否利用它以 root 身份 READ、WRITE 或 EXECUTE 任何东西？([**GTFOBins**](https://gtfobins.github.io))
- [ ] 如果 `sudo -l` 允许 `sudoedit`，检查是否存在通过 `SUDO_EDITOR`/`VISUAL`/`EDITOR` 的 **sudoedit 参数注入**（CVE-2023-22809），可以在易受攻击的版本（`sudo -V` < 1.9.12p2）上编辑任意文件。例如：`SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] 有没有 **可利用的 SUID 二进制文件**？([**GTFOBins**](https://gtfobins.github.io))
- [ ] 是否有 [**sudo 命令被 path 限制** 的情况？你能否**绕过**限制](privilege-escalation/index.html#sudo-execution-bypassing-paths)？
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? 绕过方法
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] 来自可写文件夹的 [**SUID 二进制缺失 .so 库**](privilege-escalation/index.html#suid-binary-so-injection)？
- [ ] [**可用的 SUDO tokens**](privilege-escalation/index.html#reusing-sudo-tokens)？[**你能创建 SUDO token 吗**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] 你能否 [**读取或修改 sudoers 文件**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] 你能否 [**修改 /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)？
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) 命令

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] 有没有二进制具有任何 **意外的 capability**？

### [ACLs](privilege-escalation/index.html#acls)

- [ ] 有没有文件具有任何 **意外的 ACL**？

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - 读取敏感数据？可写用于 privesc？
- [ ] **passwd/shadow files** - 读取敏感数据？可写用于 privesc？
- [ ] 检查常见的有趣文件夹以查找敏感数据
- [ ] **奇怪位置/属主文件**，你可能可以访问或修改可执行文件
- [ ] **最近几分钟被修改**
- [ ] **Sqlite DB 文件**
- [ ] **隐藏文件**
- [ ] **位于 PATH 中的脚本/二进制**
- [ ] **Web 文件**（密码？）
- [ ] **备份**？
- [ ] **已知包含密码的文件**：使用 **Linpeas** 和 **LaZagne**
- [ ] **通用搜索**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] 修改 python 库以执行任意命令？
- [ ] 你能否 **修改日志文件**？ **Logtotten** 漏洞
- [ ] 你能否 **修改 /etc/sysconfig/network-scripts/**？Centos/Redhat 漏洞
- [ ] 你能否[**在 ini, init.d, systemd 或 rc.d 文件中写入**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] 你能否[**滥用 NFS 提权**](privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] 你是否需要[**从受限 shell 逃逸**](privilege-escalation/index.html#escaping-from-restricted-shells)？


## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
