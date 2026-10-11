# Linux 权限提升检查清单

{{#include ../../banners/hacktricks-training.md}}

# 检查清单 - Linux 权限提升



### **查找 Linux 本地权限提升途径的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] 获取 **OS 信息**
- [ ] 检查 [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path)，其中是否有**可写目录**？
- [ ] 检查 [**环境变量**](../linux-basics/linux-privilege-escalation/index.html#env-info)，其中是否有敏感信息？
- [ ] **使用脚本**搜索[**内核漏洞利用**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits)（DirtyCow？）
- [ ] 运行内核 PoC 前，验证其**实际前提条件**，而不只是检查 `uname -r`：架构、所需的 `CONFIG_*` 选项/模块、命名空间创建能力以及已启用的缓解措施。例如，可通过 `unshare -Urn true` 测试用户/网络命名空间是否可用；现代 netfilter 漏洞利用可能需要 `CONFIG_USER_NS`、非特权用户命名空间和 `CONFIG_NF_TABLES`。<sup>[[3]](#references)</sup>
- [ ] **检查**[**sudo 版本**是否存在漏洞](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** 签名验证失败](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] 检查[**内核模块和模块加载配置错误**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations)：`insmod`、`modinfo`、`lsmod`、`dmesg`、签名强制执行和 `modules_disabled`。
- [ ] 如果 helper 路径可以被修改或触发，请检查 [**kernel.modprobe / modprobe_path 滥用途径**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks)。
- [ ] 检查[**可写的 /lib/modules 路径**](kernel-modules-and-modprobe.md#writable-libmodules-review)，包括可写的 `.ko*` 文件和 `modules.*` 元数据。
- [ ] 更多系统信息枚举（[日期、系统统计数据、CPU 信息、打印机](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration)）
- [ ] [枚举更多防御措施](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [驱动器](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **列出已挂载的**驱动器
- [ ] 是否有**未挂载的驱动器**？
- [ ] fstab 中是否有**凭据**？

### [**已安装软件**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **检查是否安装了**[**有用的软件**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **检查是否安装了**[**存在漏洞的软件**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] 在 Debian/Ubuntu 上，检查是否安装/启用了 **needrestart 解释器扫描**：`dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`。存在漏洞的版本会跨越权限边界：APT 或 `unattended-upgrades` 以 root 身份调用 needrestart 时，重用攻击者控制的 `PYTHONPATH`/`RUBYLIB`、竞争 `/proc/<pid>/exe`，或扫描攻击者控制的 Perl 路径。<sup>[[4]](#references)</sup>

### [进程](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] 是否有**未知软件正在运行**？
- [ ] 是否有软件以**高于预期的权限**运行？
- [ ] 搜索**正在运行的进程的漏洞利用**（尤其是当前运行的版本）。
- [ ] 能否**修改**任何正在运行进程的**二进制文件**？
- [ ] **监控进程**，检查是否有有趣的进程频繁运行。
- [ ] 能否**读取**某些有趣的**进程内存**（其中可能保存着密码）？

### [计划任务/Cron 任务？](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] 是否有 cron 修改 [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)，并且你可以向其中**写入**？
- [ ] Cron 任务中是否有[**通配符** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)？
- [ ] 是否有[**可修改的脚本** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)正在被**执行**，或位于**可修改的目录**中？
- [ ] 是否发现某些**脚本**可能正在或已经[**频繁**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)**执行**？（每 1、2 或 5 分钟）

### [服务](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] 是否有**可写的 .service** 文件？
- [ ] 是否有被**服务**执行的**可写二进制文件**？
- [ ] root unit 引用的 helper、配置或环境文件是否可写（`ExecStartPre=`、`ExecStartPost=`、`EnvironmentFile=`）？使用 `systemctl cat <unit>` 检查合并后的 unit，并查看[服务/socket 文件滥用](../interesting-files-permissions/write-to-root.md)。
- [ ] 按需运行的特权工作流是否会在低权限可写目录下运行 helper？检查 helper 及其父目录，排查[以 root 身份执行用户可修改的路径](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries)；短暂运行的 helper 可能只会在工作流执行期间出现。
- [ ] systemd PATH 中是否有**可写目录**？
- [ ] `/etc/systemd/system/<unit>.d/*.conf` 中是否有可覆盖 `ExecStart`/`User` 的**可写 systemd unit drop-in**？<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] 是否有**可写的 timer**？

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] 是否有**可写的 .socket** 文件？
- [ ] 能否**与任何 socket 通信**？
- [ ] 是否有包含有趣信息的 **HTTP sockets**？
- [ ] 能否访问[**容器运行时或节点代理 API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)，例如 `docker.sock`、`containerd.sock`、`crio.sock`、`podman.sock`、`buildkitd.sock` 或 kubelet 端点？即使没有常用 CLI，也要测试原始 HTTP/gRPC API。

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] 能否**与任何 D-Bus 通信**？

### [网络](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 枚举网络，了解自己所处的位置
- [ ] 在机器内获得 shell 后，是否能访问之前无法访问的**开放端口**？
- [ ] 能否使用 `tcpdump` **嗅探流量**？

### [用户](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] 枚举常规用户/组
- [ ] 你是否有一个**非常大的 UID**？这台**机器**是否**存在漏洞**？
- [ ] 能否[**利用所属组提升权限**](../user-information/interesting-groups-linux-pe/index.html)？
- [ ] **剪贴板**数据？
- [ ] 密码策略？
- [ ] 尝试使用之前发现的**所有已知密码**，以每个可能的**用户**身份登录。也尝试不使用密码登录。

### [可写的 PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] 如果你对 PATH 中的某个目录有**写权限**，或许就能提升权限

### [SUDO 和 SUID 命令](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] 能否通过 sudo 执行**任何命令**？能否用它以 root 身份读取、写入或执行任何内容？([**GTFOBins**](https://gtfobins.github.io))
- [ ] 如果 `sudo -l` 允许使用 `sudoedit`，请检查是否可通过 `SUDO_EDITOR`/`VISUAL`/`EDITOR` 进行 **sudoedit 参数注入**（CVE-2023-22809），从而在存在漏洞的版本（`sudo -V` < 1.9.12p2）上编辑任意文件。例如：`SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`。<sup>[[1]](#references)</sup>
- [ ] 是否有**可利用的 SUID 二进制文件**？([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** 命令是否受**路径**限制？能否**绕过**限制](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)？
- [ ] [**未指明路径的 Sudo/SUID 二进制文件**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**指定路径的 SUID 二进制文件**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)？绕过
- [ ] [**LD_PRELOAD 漏洞**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**SUID 二进制文件缺少 .so 库**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)，且该库本应来自可写目录？
- [ ] [**SUID RPATH/RUNPATH 或可写的库路径**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)？
- [ ] 是否有[**可用的 SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)？[**能否创建 SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] 能否[**读取或修改 sudoers 文件**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] 能否[**修改 /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)？
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) 命令

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] 是否有二进制文件带有任何**意外的 capability**？

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] 是否有文件带有任何**意外的 ACL**？

### [打开的 Shell 会话](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL 可预测 PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH 有趣的配置值**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [有趣的文件](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile 文件** - 能否读取敏感数据？能否写入以提升权限？
- [ ] **passwd/shadow 文件** - 能否读取敏感数据？能否写入以提升权限？
- [ ] **检查常见的有趣目录**，查找敏感数据
- [ ] **位于奇怪位置/归属异常的文件**，你可能可以访问或修改可执行文件
- [ ] 最近几分钟内有文件被**修改**
- [ ] **Sqlite DB 文件**
- [ ] **隐藏文件**
- [ ] **PATH 中的脚本/二进制文件**
- [ ] **Web 文件**（密码？）
- [ ] **备份**？
- [ ] **已知包含密码的文件**：使用 **Linpeas** 和 **LaZagne**
- [ ] **常规搜索**

### [**可写文件**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] 能否**修改 python 库**以执行任意命令？
- [ ] 能否**修改日志文件**？**Logtotten** exploit
- [ ] 能否**修改 /etc/sysconfig/network-scripts/**？Centos/Redhat exploit
- [ ] 能否[**写入 ini、int.d、systemd 或 rc.d 文件**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**其他技巧**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] 能否[**利用 NFS 提升权限**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] 是否需要[**逃逸受限 shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)？



## References

- [1] [Sudo 安全公告：sudoedit 可编辑任意文件](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux 文档：systemd drop-in 配置](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn：CVE-2024-1086 exploit 前提条件与研究](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys 安全公告：needrestart 中的 LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
