# Linux 提权检查清单

# 检查清单 - Linux 提权



### **查找 Linux 本地提权向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [系统信息](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] 获取 **OS 信息**
- [ ] 检查 [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path)，是否存在**可写目录**？
- [ ] 检查 [**环境变量**](../linux-basics/linux-privilege-escalation/index.html#env-info)，是否存在敏感信息？
- [ ] 使用 **scripts** 搜索 [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits)（DirtyCow？）
- [ ] 运行 kernel PoC 前，验证其**实际前置条件**，不要只检查 `uname -r`：架构、所需的 `CONFIG_*` 选项/模块、namespace 创建能力以及已启用的 mitigations。例如，使用 `unshare -Urn true` 测试 user/network namespace 是否可用；现代 netfilter exploits 可能需要 `CONFIG_USER_NS`、非特权 user namespaces 以及 `CONFIG_NF_TABLES`。<sup>[[3]](#references)</sup>
- [ ] **检查** [**sudo 版本**是否存在漏洞](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** 签名验证失败](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] 检查 [**kernel module 和 module-loading 配置错误**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations)：`insmod`、`modinfo`、`lsmod`、`dmesg`、签名强制以及 `modules_disabled`。
- [ ] 检查 [**kernel.modprobe / modprobe_path abuse 路径**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks)，确认 helper 路径是否可被修改或触发。
- [ ] 检查 [**可写的 /lib/modules 路径**](kernel-modules-and-modprobe.md#writable-libmodules-review)，包括可写的 `.ko*` 文件和 `modules.*` metadata。
- [ ] 更多 system enum（[date、system stats、cpu info、printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration)）
- [ ] [枚举更多防御机制](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [磁盘](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **列出已挂载的**磁盘
- [ ] **是否存在未挂载的磁盘？**
- [ ] **fstab 中是否存在 creds？**

### [**已安装的软件**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **检查是否已安装**[**有用的软件**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **检查是否已安装**[**存在漏洞的软件**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] 在 Debian/Ubuntu 上，检查是否安装/启用了 **needrestart interpreter scanning**：`dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`。存在漏洞的 builds 通过复用攻击者控制的 `PYTHONPATH`/`RUBYLIB`、竞争 `/proc/<pid>/exe`，或在 APT 或 `unattended-upgrades` 以 root 调用 needrestart 时扫描攻击者控制的 Perl 路径，跨越了 privilege boundary。<sup>[[4]](#references)</sup>

### [进程](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] 是否有**未知软件正在运行**？
- [ ] 是否有软件以**超出其应有权限的权限运行**？
- [ ] 搜索**正在运行的进程的 exploits**（尤其是当前运行的版本）。
- [ ] 你能否**修改**任意正在运行的进程的**binary**？
- [ ] **监控进程**，检查是否有有趣的进程频繁运行。
- [ ] 你能否**读取**某些有趣的**进程内存**（其中可能保存了密码）？

### [计划任务/Cron 任务？](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] 是否有某个 cron 修改了 [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)，并且你可以对其进行**写入**？
- [ ] Cron 任务中是否存在[**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)？
- [ ] 某个[**可修改的 script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)是否正在被**执行**，或位于**可修改目录**中？
- [ ] 你是否发现某个**script**可能或正在被[**非常频繁地执行**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)？（每 1、2 或 5 分钟）

### [服务](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] 是否存在**可写的 .service** 文件？
- [ ] 是否存在由**服务**执行的**可写 binary**？
- [ ] root unit 引用的 helper、config 或 environment 文件是否可写（`ExecStartPre=`、`ExecStartPost=`、`EnvironmentFile=`）？使用 `systemctl cat <unit>` 检查合并后的 unit，并检查 [service/socket file abuse](../interesting-files-permissions/write-to-root.md)。
- [ ] systemd PATH 中是否存在**可写目录**？
- [ ] `/etc/systemd/system/<unit>.d/*.conf` 中是否存在可写的 systemd unit drop-in，能够覆盖 `ExecStart`/`User`？<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] 是否存在**可写的 timer**？

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] 是否存在**可写的 .socket** 文件？
- [ ] 你能否**与任意 socket 通信**？
- [ ] 是否存在包含有趣信息的 **HTTP sockets**？
- [ ] 你能否访问 [**container-runtime 或 node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)，例如 `docker.sock`、`containerd.sock`、`crio.sock`、`podman.sock`、`buildkitd.sock` 或 kubelet endpoint？即使通常使用的 CLI 不存在，也应测试原始 HTTP/gRPC API。

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] 你能否**与任意 D-Bus 通信**？

### [网络](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 枚举网络以了解你所在的位置
- [ ] 在机器内部获得 shell 后，是否出现了之前无法访问的**开放端口**？
- [ ] 你能否使用 `tcpdump` **嗅探流量**？

### [用户](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] 通用用户/组**枚举**
- [ ] 你是否拥有**非常大的 UID**？该**机器**是否存在**漏洞**？
- [ ] 你能否利用所属的某个**组来[提权](../user-information/interesting-groups-linux-pe/index.html)**？
- [ ] **Clipboard** 数据？
- [ ] Password Policy？
- [ ] 尝试使用之前发现的每个**已知密码**，以每个可能的**用户**进行登录。也尝试不使用密码登录。

### [可写的 PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] 如果你对 PATH 中的某个目录拥有**写权限**，可能就能够提权

### [SUDO 和 SUID 命令](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] 你能否使用 sudo 执行**任意命令**？能否使用它以 root 身份读取、写入或执行任何内容？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] 如果 `sudo -l` 允许使用 `sudoedit`，请通过 `SUDO_EDITOR`/`VISUAL`/`EDITOR` 检查 **sudoedit argument injection**（CVE-2023-22809），在存在漏洞的版本（`sudo -V` < 1.9.12p2）中编辑任意文件。例如：`SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`。<sup>[[1]](#references)</sup>
- [ ] 是否存在**可利用的 SUID binary**？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** 命令是否受**路径**限制？能否](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)**绕过限制**？
- [ ] [**未指示路径的 Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**指定路径的 SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)？尝试绕过
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**SUID binary 缺少 .so library**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)，且该 library 来自可写目录？
- [ ] [**SUID RPATH/RUNPATH 或可写的 library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)？
- [ ] 是否存在[**可用的 SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)？[**能否创建 SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] 你能否[**读取或修改 sudoers 文件**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] 你能否[**修改 /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)？
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) 命令

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] 是否有 binary 具有任何**意外的 capability**？

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] 是否有文件具有任何**意外的 ACL**？

### [打开的 Shell 会话](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH 有趣的配置值**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [有趣的文件](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile 文件** - 读取敏感数据？写入以进行 privesc？
- [ ] **passwd/shadow 文件** - 读取敏感数据？写入以进行 privesc？
- [ ] **检查常见的有趣目录**，寻找敏感数据
- [ ] **奇怪位置/归属的文件**，你可能可以访问或修改可执行文件
- [ ] 最近几分钟内被**修改**
- [ ] **Sqlite DB 文件**
- [ ] **隐藏文件**
- [ ] **PATH 中的 Script/Binaries**
- [ ] **Web 文件**（密码？）
- [ ] **备份**？
- [ ] **包含密码的已知文件**：使用 **Linpeas** 和 **LaZagne**
- [ ] **通用搜索**

### [**可写文件**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **修改 python library** 以执行任意命令？
- [ ] 你能否**修改日志文件**？**Logtotten** exploit
- [ ] 你能否**修改 /etc/sysconfig/network-scripts/**？Centos/Redhat exploit
- [ ] 你能否[**写入 ini、int.d、systemd 或 rc.d 文件**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**其他技巧**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] 你能否[**滥用 NFS 进行提权**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] 你是否需要[**逃逸受限 shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)？



## References

- [1] [Sudo advisory：sudoedit 任意文件编辑](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux 文档：systemd drop-in 配置](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn：CVE-2024-1086 exploit 要求与研究](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory：needrestart 中的 LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
