# Linux 提权检查清单

{{#include ../../banners/hacktricks-training.md}}

# 检查清单 - Linux 提权



### **查找 Linux 本地提权 vector 的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] 获取 **OS 信息**
- [ ] 检查 [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path)，是否存在**可写文件夹**？
- [ ] 检查 [**环境变量**](../linux-basics/linux-privilege-escalation/index.html#env-info)，是否存在敏感信息？
- [ ] 使用**脚本**搜索 [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits)（DirtyCow？）
- [ ] 在运行 kernel PoC 前，验证其**实际前置条件**，而不只是检查 `uname -r`：架构、所需的 `CONFIG_*` 选项/模块、namespace 创建能力以及已启用的缓解措施。例如，使用 `unshare -Urn true` 测试 user/network namespace 是否可用；现代 netfilter exploits 可能需要 `CONFIG_USER_NS`、非特权 user namespaces 和 `CONFIG_NF_TABLES`。<sup>[[3]](#references)</sup>
- [ ] **检查** [**sudo 版本**是否存在漏洞](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** 签名验证失败](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] 检查 [**kernel module 和 module-loading 配置错误**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations)：`insmod`、`modinfo`、`lsmod`、`dmesg`、签名强制机制和 `modules_disabled`。
- [ ] 检查 [**kernel.modprobe / modprobe_path abuse 路径**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks)，确认 helper 路径是否可被修改或触发。
- [ ] 检查 [**可写的 /lib/modules 路径**](kernel-modules-and-modprobe.md#writable-libmodules-review)，包括可写的 `.ko*` 文件和 `modules.*` metadata。
- [ ] 更多 system enum（[date、system stats、cpu info、printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration)）
- [ ] [枚举更多防御机制](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [磁盘](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **列出已挂载的**磁盘
- [ ] **是否存在未挂载的磁盘？**
- [ ] **fstab 中是否存在 creds？**

### [**已安装的软件**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **检查是否安装了**[**有用的软件**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **检查是否安装了**[**存在漏洞的软件**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] 在 Debian/Ubuntu 上，检查是否安装/启用了 **needrestart interpreter scanning**：`dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`。存在漏洞的构建版本会通过复用攻击者控制的 `PYTHONPATH`/`RUBYLIB`、竞争 `/proc/<pid>/exe`，或在 APT 或 `unattended-upgrades` 以 root 身份调用 needrestart 时扫描攻击者控制的 Perl 路径，跨越 privilege boundary。<sup>[[4]](#references)</sup>

### [进程](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] 是否有**未知软件正在运行**？
- [ ] 是否有软件以**超出其应有权限的权限运行**？
- [ ] 搜索**正在运行的进程的 exploits**（尤其是正在运行的版本）。
- [ ] 是否可以**修改**某个正在运行的进程的**二进制文件**？
- [ ] **监控进程**，检查是否有有趣的进程频繁运行。
- [ ] 是否可以**读取**某些有趣的**进程内存**（其中可能保存了密码）？

### [计划任务/Cron？](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#cron-path)是否被某个 cron 修改，并且你可以对其进行**写入**？
- [ ] Cron job 中是否存在[**通配符**](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)？
- [ ] 是否有某个[**可修改的脚本**](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)正在被**执行**，或位于**可修改的文件夹**中？
- [ ] 是否发现某个**脚本**可能会或正在被[**非常频繁地执行**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)？（每 1、2 或 5 分钟）

### [服务](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] 是否存在**可写的 .service** 文件？
- [ ] 是否存在由某个**服务执行的可写二进制文件**？
- [ ] root unit 引用的 helper、config 或 environment 文件是否可写（`ExecStartPre=`、`ExecStartPost=`、`EnvironmentFile=`）？使用 `systemctl cat <unit>` 检查合并后的 unit，并检查[service/socket 文件 abuse](../interesting-files-permissions/write-to-root.md)。
- [ ] systemd PATH 中是否存在**可写文件夹**？
- [ ] `/etc/systemd/system/<unit>.d/*.conf` 中是否存在可写的 **systemd unit drop-in**，可以覆盖 `ExecStart`/`User`？<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] 是否存在**可写的 timer**？

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] 是否存在**可写的 .socket** 文件？
- [ ] 是否可以**与某个 socket 通信**？
- [ ] 是否存在包含有趣信息的 **HTTP sockets**？
- [ ] 是否可以访问 [**container-runtime 或 node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)，例如 `docker.sock`、`containerd.sock`、`crio.sock`、`podman.sock`、`buildkitd.sock` 或 kubelet endpoint？即使常用 CLI 不存在，也要测试原始 HTTP/gRPC API。

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] 是否可以**与某个 D-Bus 通信**？

### [网络](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 枚举网络以了解你所在的位置
- [ ] 在机器内部获取 shell 后，是否出现了之前无法访问的**开放端口**？
- [ ] 是否可以使用 `tcpdump`**嗅探流量**？

### [用户](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] 通用用户/组**枚举**
- [ ] 是否拥有**非常大的 UID**？该**机器**是否存在**漏洞**？
- [ ] 是否可以利用你所属的某个**组来提权**？](../user-information/interesting-groups-linux-pe/index.html)
- [ ] 是否存在 **Clipboard** 数据？
- [ ] Password Policy？
- [ ] 尝试使用此前发现的每个**已知密码**，以每个可能的**用户**登录。也尝试不使用密码登录。

### [可写 PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] 如果你对 PATH 中的某个文件夹拥有**写权限**，可能就能够提权

### [SUDO 和 SUID 命令](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] 是否可以使用 sudo 执行**任意命令**？是否可以使用它以 root 身份读取、写入或执行任何内容？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] 如果 `sudo -l` 允许使用 `sudoedit`，请通过 `SUDO_EDITOR`/`VISUAL`/`EDITOR` 检查 **sudoedit argument injection**（CVE-2023-22809），在存在漏洞的版本（`sudo -V` < 1.9.12p2）上编辑任意文件。例如：`SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`。<sup>[[1]](#references)</sup>
- [ ] 是否存在**可利用的 SUID 二进制文件**？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** 命令是否受到**路径**限制？是否可以**绕过限制**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)？
- [ ] [**未指明路径的 Sudo/SUID 二进制文件**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**指定路径的 SUID 二进制文件**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)？绕过
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**SUID 二进制文件缺少 .so library**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)，且该 library 来自可写文件夹？
- [ ] [**SUID RPATH/RUNPATH 或可写的 library 路径**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)？
- [ ] 是否存在[**可用的 SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)？[**是否可以创建 SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] 是否可以[**读取或修改 sudoers 文件**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] 是否可以[**修改 /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)？
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) 命令

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] 是否有二进制文件拥有**非预期 capability**？

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] 是否有文件拥有**非预期 ACL**？

### [已打开的 Shell 会话](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH 有趣的配置值**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [有趣的文件](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile 文件** - 是否可以读取敏感数据？是否可以写入以提权？
- [ ] **passwd/shadow 文件** - 是否可以读取敏感数据？是否可以写入以提权？
- [ ] **检查通常值得关注的文件夹**，查找敏感数据
- [ ] **异常位置/归属异常的文件**，你可能可以访问或修改可执行文件
- [ ] 最近几分钟内被**修改**的文件
- [ ] **Sqlite DB 文件**
- [ ] **隐藏文件**
- [ ] **PATH 中的脚本/二进制文件**
- [ ] **Web 文件**（密码？）
- [ ] **备份**？
- [ ] **包含密码的已知文件**：使用 **Linpeas** 和 **LaZagne**
- [ ] **通用搜索**

### [**可写文件**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **修改 Python library** 以执行任意命令？
- [ ] 是否可以**修改日志文件**？**Logtotten** exploit
- [ ] 是否可以**修改 /etc/sysconfig/network-scripts/**？Centos/Redhat exploit
- [ ] 是否可以[**写入 ini、int.d、systemd 或 rc.d 文件**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**其他技巧**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] 是否可以[**滥用 NFS 来提权**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] 是否需要[**逃逸受限 Shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)？



## References

- [1] [Sudo advisory：sudoedit 任意文件编辑](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux 文档：systemd drop-in 配置](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn：CVE-2024-1086 exploit 要求与研究](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory：needrestart 中的 LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
