# Checklist - Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Linux のローカルな privilege escalation ベクトルを探す最適な tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS information** を取得
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) を確認し、**writable folder** がないか確認
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info) を確認し、機密情報がないか確認
- [ ] **scripts を使用して** [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) を検索（DirtyCow?）
- [ ] [**sudo version** に脆弱性があるか](../linux-basics/linux-privilege-escalation/index.html#sudo-version) **確認**
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module and module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) を確認: `insmod`、`modinfo`、`lsmod`、`dmesg`、signature enforcement、`modules_disabled`。
- [ ] helper path を変更または trigger できる場合、[**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) を確認。
- [ ] **writable `.ko*` files** と `modules.*` metadata を含む、[**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review) を確認。
- [ ] 追加の system enum（[date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration)）
- [ ] [追加の defenses を列挙](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **mounted drives** を一覧表示
- [ ] **Unmounted drive はあるか**
- [ ] **fstab に creds はあるか**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **インストールされている** [**useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **を確認**
- [ ] **インストールされている** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **を確認**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **unknown software が実行されているか**
- [ ] 本来よりも**高い privileges で実行されている software があるか**
- [ ] **実行中の processes の exploits** を検索（特に実行中の version）。
- [ ] 実行中の process の **binary を modify できるか**
- [ ] **processes を monitor** し、興味深い process が頻繁に実行されていないか確認
- [ ] 興味深い **process memory**（passwords が保存されている可能性がある場所）を**読み取れるか**

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] cron によって [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)が変更されており、そこに **write** できるか
- [ ] cron job に[**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)があるか
- [ ] [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)が**実行**されているか、または**modifiable folder** 内にあるか
- [ ] **script** が[非常に**頻繁に実行**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)される可能性がある、または実際に実行されていることを検出したか（1、2、5分ごとなど）

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **writable `.service` file** があるか
- [ ] **service によって実行される writable binary** があるか
- [ ] **systemd PATH 内に writable folder** があるか
- [ ] `ExecStart`/`User` を override できる **writable systemd unit drop-in** が `/etc/systemd/system/<unit>.d/*.conf` にあるか

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] **writable timer** があるか

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] **writable `.socket` file** があるか
- [ ] **任意の socket と communicate できるか**
- [ ] 興味深い情報を持つ **HTTP sockets** があるか

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] **任意の D-Bus と communicate できるか**

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 自分がどこにいるか把握するため network を enumerate
- [ ] マシン内部で shell を取得する**前には access できなかった open ports** があるか
- [ ] `tcpdump` を使用して **traffic を sniff できるか**

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generic users/groups の **enumeration**
- [ ] **非常に大きな UID** を持っているか。**machine** に**脆弱性**があるか
- [ ] 所属している [**group を利用して privileges を escalate できるか**](../user-information/interesting-groups-linux-pe/index.html)
- [ ] **Clipboard** data があるか
- [ ] Password Policy はどうなっているか
- [ ] これまでに発見した**既知の password** をすべて、可能性のある**各 user** で login に**使用**してみる。password なしでも login を試す。

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] **PATH 内のいずれかの folder に対する write privileges** がある場合、privileges を escalate できる可能性がある

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo で任意の command を実行できるか**。root として何かを READ、WRITE、EXECUTE するために使用できるか（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] `sudo -l` で `sudoedit` が許可されている場合、脆弱な version（`sudo -V` < 1.9.12p2）で任意の files を edit するため、`SUDO_EDITOR`/`VISUAL`/`EDITOR` 経由の **sudoedit argument injection**（CVE-2023-22809）を確認。例: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] **exploitable SUID binary** があるか（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** commands が **path** によって**制限**されているか](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)。**制限を bypass できるか**
- [ ] [**path が指定されていない Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) があるか
- [ ] [**path を指定している SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path) があるか。Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] writable folder に [**SUID binary 内で不足している `.so` library**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) があるか
- [ ] [**SUID RPATH/RUNPATH または writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) があるか
- [ ] [**SUDO tokens が利用可能か**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)。[**SUDO token を作成できるか**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)
- [ ] [**sudoers files を read または modify できるか**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)
- [ ] [**/etc/ld.so.conf.d/ を modify できるか**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] binary に**予期しない capability** があるか

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] file に**予期しない ACL** があるか

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - 機密データを read できるか。privesc のために write できるか
- [ ] **passwd/shadow files** - 機密データを read できるか。privesc のために write できるか
- [ ] 機密データがないか、**一般的に興味深い folders** を確認
- [ ] **Weird Location/Owned files**。executable files に access または alter できる可能性がある
- [ ] **直近数分以内に Modified** されたもの
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **PATH 内の Script/Binaries**
- [ ] **Web files**（passwords?）
- [ ] **Backups**?
- [ ] **passwords を含む既知の files**: **Linpeas** と **LaZagne** を使用
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **python library を modify** して arbitrary commands を execute できるか
- [ ] **log files を modify できるか**。**Logtotten** exploit
- [ ] **/etc/sysconfig/network-scripts/ を modify できるか**。Centos/Redhat exploit
- [ ] [**ini、int.d、systemd、または rc.d files に write できるか**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**NFS を abuse して privileges を escalate できるか**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)
- [ ] [**restrictive shell から escape する必要があるか**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)



## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
