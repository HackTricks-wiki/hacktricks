# Linux Privilege Escalation チェックリスト

{{#include ../../banners/hacktricks-training.md}}

# チェックリスト - Linux Privilege Escalation



### **Linux local privilege escalation vector を探すための最適な tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS information** を取得
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) を確認。**writable folder** はあるか？
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info) を確認。sensitive detail はあるか？
- [ ] **scripts を使用して** [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) を検索（DirtyCow？）
- [ ] [**sudo version** に脆弱性があるか](../linux-basics/linux-privilege-escalation/index.html#sudo-version)**確認**
- [ ] [**Dmesg** の signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module と module-loading の misconfiguration**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) を確認：`insmod`、`modinfo`、`lsmod`、`dmesg`、signature enforcement、`modules_disabled`。
- [ ] helper path を変更または trigger できる場合、[**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) を確認。
- [ ] [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review) を確認。writable な `.ko*` files と `modules.*` metadata を含む。
- [ ] さらに system enum（[date、system stats、cpu info、printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration)）
- [ ] [さらに defenses を enumerate](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **mounted** drives を一覧表示
- [ ] **unmounted drive はあるか？**
- [ ] **fstab に creds はあるか？**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **インストール済みの**[ **useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **を確認**
- [ ] **インストール済みの** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **を確認**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **unknown software が running しているか？**
- [ ] **本来よりも多くの privileges で running している software はあるか？**
- [ ] **running processes の exploits** を検索（特に running 中の version）。
- [ ] running process の **binary を modify できるか？**
- [ ] **processes を monitor** し、頻繁に running している interesting process がないか確認。
- [ ] interesting な **process memory を read できるか**（passwords が保存されている可能性がある場所）？

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] 何らかの cron によって [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)が変更されており、そこに **write** できるか？
- [ ] cron job に [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)はあるか？
- [ ] 何らかの [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)が**実行**されている、または **modifiable folder** 内にあるか？
- [ ] **script** が [**非常に** **頻繁に**実行](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)される、または実行されている可能性を検出したか？（1、2、5 分ごと）

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **writable .service** file はあるか？
- [ ] **service** によって実行される **writable binary** はあるか？
- [ ] systemd PATH に **writable folder** はあるか？
- [ ] `/etc/systemd/system/<unit>.d/*.conf` に、`ExecStart`/`User` を override できる **writable systemd unit drop-in** はあるか？

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] **writable timer** はあるか？

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] **任意の socket と communicate できるか？**
- [ ] **任意の socket と communicate できるか？**
- [ ] interesting な情報を持つ **HTTP sockets** はあるか？

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] **任意の D-Bus と communicate できるか？**

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 自分がどこにいるか把握するため network を enumerate
- [ ] machine 内で shell を取得する**前には access できなかった open ports** はあるか？
- [ ] `tcpdump` を使用して **traffic を sniff できるか？**

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] users/groups を **generic enumeration**
- [ ] **非常に大きな UID** を持っているか？ **machine** に **vulnerability** はあるか？
- [ ] 所属している group を利用して[**privileges を escalate できるか**](../user-information/interesting-groups-linux-pe/index.html)？
- [ ] **Clipboard** data はあるか？
- [ ] Password Policy は？
- [ ] 以前に discover した **known password** をすべて、可能性のある**各** **user** で login **に使用**してみる。password なしで login も試す。

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH 内の folder に **write privileges** がある場合、privileges を escalate できる可能性がある

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo で任意の command を execute できるか？** root として何かを READ、WRITE、EXECUTE するために利用できるか？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] `sudo -l` で `sudoedit` が許可されている場合、`SUDO_EDITOR`/`VISUAL`/`EDITOR` を介した **sudoedit argument injection**（CVE-2023-22809）を確認し、vulnerable な version（`sudo -V` < 1.9.12p2）で arbitrary files を edit する。例：`SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] **exploitable SUID binary** はあるか？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** commands が **path** によって **limited** されているか？](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths) restrictions を **bypass できるか**
- [ ] [**path が indicated されていない Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**path を指定する SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)？bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] writable folder にある [**SUID binary の .so library が不足**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)しているか？
- [ ] [**SUID RPATH/RUNPATH または writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)？
- [ ] [**SUDO tokens が available か**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)？[**SUDO token を create できるか**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] [**sudoers files を read または modify できるか**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] [**/etc/ld.so.conf.d/ を modify できるか**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)？
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] binary に **unexpected capability** が付与されているか？

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] file に **unexpected ACL** が設定されているか？

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - sensitive data を read できるか？privesc のために write できるか？
- [ ] **passwd/shadow files** - sensitive data を read できるか？privesc のために write できるか？
- [ ] sensitive data がないか **commonly interesting folders を確認**
- [ ] **Weird Location/Owned files**。executable files に access または alter できる可能性がある
- [ ] **直近数分以内に Modified**
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **PATH 内の Script/Binaries**
- [ ] **Web files**（passwords？）
- [ ] **Backups**？
- [ ] **passwords を含むことが known な files**：**Linpeas** と **LaZagne** を使用
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **python library を modify** して arbitrary commands を execute できるか？
- [ ] **log files を modify できるか？** **Logtotten** exploit
- [ ] **/etc/sysconfig/network-scripts/ を modify できるか？** Centos/Redhat exploit
- [ ] [**ini、int.d、systemd または rc.d files に write できるか**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**NFS を abuse して privileges を escalate できるか**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] [**restrictive shell から escape する必要があるか**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)？



## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
