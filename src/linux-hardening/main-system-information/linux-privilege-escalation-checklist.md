# Linux 权限提升清单

{{#include ../../banners/hacktricks-training.md}}

# 清单 - Linux 权限提升



### **查找 Linux 本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] 获取 **OS 信息**
- [ ] 检查 [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path)，是否存在**可写文件夹**？
- [ ] 检查 [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info)，是否存在敏感信息？
- [ ] **使用脚本**搜索 [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits)（DirtyCow？）
- [ ] **检查** [**sudo version** 是否存在漏洞](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** 签名验证失败](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] 检查 [**kernel module and module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations)：`insmod`、`modinfo`、`lsmod`、`dmesg`、签名强制机制以及 `modules_disabled`。
- [ ] 如果 helper 路径可以被修改或触发，检查 [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks)。
- [ ] 检查 [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review)，包括可写的 `.ko*` 文件和 `modules.*` 元数据。
- [ ] 更多系统枚举（[date、system stats、cpu info、printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration)）
- [ ] [枚举更多防御机制](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [驱动器](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **列出已挂载的**驱动器
- [ ] **是否存在未挂载的驱动器？**
- [ ] **fstab 中是否存在凭据？**

### [**已安装的软件**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **检查是否已安装**[ **有用的软件**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **检查是否已安装** [**存在漏洞的软件**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)

### [进程](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] 是否有**未知软件正在运行**？
- [ ] 是否有软件以**超出其应有权限的权限运行**？
- [ ] 搜索**正在运行的进程的 exploits**（尤其是当前运行的版本）。
- [ ] 是否可以**修改**某个正在运行的进程的**二进制文件**？
- [ ] **监控进程**，检查是否有有趣的进程频繁运行。
- [ ] 是否可以**读取**某些有趣的**进程内存**（密码可能保存在其中）？

### [Scheduled/Cron jobs？](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] 某个 cron 是否正在修改 [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)，并且你可以在其中**写入**？
- [ ] cron job 中是否存在[**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)？
- [ ] 某个[**可修改的脚本** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)是否正在被**执行**，或位于**可修改文件夹**中？
- [ ] 是否发现某个**脚本**可能会或正在被[**非常**频繁地**执行**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)？（每 1、2 或 5 分钟）

### [服务](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] 是否存在**可写的 .service** 文件？
- [ ] 是否存在由某个**服务**执行的**可写二进制文件**？
- [ ] systemd PATH 中是否存在**可写文件夹**？
- [ ] `/etc/systemd/system/<unit>.d/*.conf` 中是否存在可写的 **systemd unit drop-in**，可以覆盖 `ExecStart`/`User`？

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] 是否存在**可写的 timer**？

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] 是否存在**可写的 .socket** 文件？
- [ ] 是否可以**与某个 socket 通信**？
- [ ] 是否存在包含有趣信息的 **HTTP sockets**？

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] 是否可以**与某个 D-Bus 通信**？

### [网络](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 枚举网络以了解你所在的位置
- [ ] 在获得机器内部的 shell 后，是否出现了之前无法访问的**开放端口**？
- [ ] 是否可以使用 `tcpdump`**嗅探流量**？

### [用户](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **枚举**通用用户/组
- [ ] 你是否拥有一个**非常大的 UID**？该**机器**是否**存在漏洞**？
- [ ] 是否可以利用你所属的[**组来提升权限**](../user-information/interesting-groups-linux-pe/index.html)？
- [ ] **Clipboard** 数据？
- [ ] 密码策略？
- [ ] 尝试使用之前发现的每个**已知密码**，以每个可能的**用户**进行登录。也尝试不使用密码登录。

### [可写 PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] 如果你对 PATH 中的某个文件夹拥有**写权限**，可能可以提升权限

### [SUDO 和 SUID 命令](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] 是否可以使用 sudo 执行**任何命令**？是否可以利用它以 root 身份读取、写入或执行任何内容？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] 如果 `sudo -l` 允许使用 `sudoedit`，请通过 `SUDO_EDITOR`/`VISUAL`/`EDITOR` 检查 **sudoedit argument injection**（CVE-2023-22809），在存在漏洞的版本（`sudo -V` < 1.9.12p2）上编辑任意文件。例如：`SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] 是否存在可**利用的 SUID binary**？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** 命令是否受**路径**限制？是否可以[绕过限制](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)？
- [ ] [**未指示路径的 Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**指定路径的 SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)？绕过
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] 可写文件夹中是否存在 [**SUID binary 缺少 .so library**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)？
- [ ] 是否存在 [**SUID RPATH/RUNPATH 或可写 library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)？
- [ ] 是否存在 [**可用的 SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)？[**是否可以创建 SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] 是否可以[**读取或修改 sudoers 文件**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] 是否可以[**修改 /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)？
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) 命令

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] 是否有 binary 具有任何**非预期的 capability**？

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] 是否有文件具有任何**非预期的 ACL**？

### [打开的 Shell 会话](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [有趣的文件](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - 读取敏感数据？写入以进行权限提升？
- [ ] **passwd/shadow files** - 读取敏感数据？写入以进行权限提升？
- [ ] **检查通常包含敏感信息的文件夹**
- [ ] **异常位置/归属异常的文件，**你可能可以访问或修改可执行文件
- [ ] 最近几分钟内**修改的文件**
- [ ] **Sqlite DB files**
- [ ] **隐藏文件**
- [ ] **PATH 中的 Script/Binaries**
- [ ] **Web files**（密码？）
- [ ] **Backups**？
- [ ] **包含密码的已知文件**：使用 **Linpeas** 和 **LaZagne**
- [ ] **通用搜索**

### [**可写文件**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **修改 python library** 以执行任意命令？
- [ ] 是否可以**修改日志文件**？**Logtotten** exploit
- [ ] 是否可以**修改 /etc/sysconfig/network-scripts/**？Centos/Redhat exploit
- [ ] 是否可以[**写入 ini、int.d、systemd 或 rc.d 文件**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**其他技巧**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] 是否可以[**滥用 NFS 提升权限**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] 是否需要[**逃逸 restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)？



## 参考资料

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
