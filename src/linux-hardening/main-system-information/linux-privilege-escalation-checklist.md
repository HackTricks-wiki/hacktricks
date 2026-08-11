# Linux Privilege Escalation Checklist

# Checklist - Linux Privilege Escalation



### **Linux local privilege escalation vector を探すための最適な tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS 情報**を取得する
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path)を確認する。**書き込み可能な folder**はあるか？
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info)を確認する。機密情報はあるか？
- [ ] **scripts を使用して**[**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits)を検索する（DirtyCow など）
- [ ] kernel PoC を実行する前に、`uname -r` だけでなく、**実際の prerequisites**を確認する。architecture、必要な `CONFIG_*` options/modules、namespace creation、active mitigations を確認する。たとえば、`unshare -Urn true` を使用して user/network namespace の利用可能性をテストする。modern netfilter exploits では、`CONFIG_USER_NS`、unprivileged user namespaces、`CONFIG_NF_TABLES` が必要になる場合がある。<sup>[[3]](#references)</sup>
- [ ] [**sudo version** が vulnerable か](../linux-basics/linux-privilege-escalation/index.html#sudo-version)を**確認**する
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module と module-loading の misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations)を確認する：`insmod`、`modinfo`、`lsmod`、`dmesg`、signature enforcement、`modules_disabled`
- [ ] helper path を変更または trigger できる場合は、[**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks)を確認する
- [ ] **書き込み可能な /lib/modules paths**を確認する。書き込み可能な `.ko*` files と `modules.*` metadata も含む
- [ ] さらに system enum（[date、system stats、cpu info、printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration)）
- [ ] [さらに defenses を列挙する](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **mount されている** drives を一覧表示する
- [ ] **mount されていない drive はあるか？**
- [ ] fstab に **creds はあるか？**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **有用な software が**[ **install されているか**](../linux-basics/linux-privilege-escalation/index.html#useful-software)を**確認**する
- [ ] [**vulnerable software が**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **install されているか**を**確認**する
- [ ] Debian/Ubuntu では、**needrestart interpreter scanning** が install/enabled されているか確認する：`dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`。vulnerable builds は、attacker-controlled な `PYTHONPATH`/`RUBYLIB` の再利用、`/proc/<pid>/exe` との race、または APT や `unattended-upgrades` が root として needrestart を invoke した際に attacker-controlled な Perl paths を scanning することで、privilege boundary を越えていた。<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **未知の software が running しているか？**
- [ ] **本来持つべき以上の privileges で software が running しているか？**
- [ ] **running processes の exploits**を検索する（特に running 中の version）
- [ ] running process の **binary を modify できるか？**
- [ ] **processes を monitor**し、興味深い process が頻繁に running していないか確認する
- [ ] 興味深い **process memory**（passwords が保存されている可能性がある）を**read できるか？**

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] 何らかの cron によって [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)が modify されており、そこに **write できるか？**
- [ ] cron job に [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)はあるか？
- [ ] **modify 可能な script** が[**execute されている**](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)か、または **modify 可能な folder** 内にあるか？
- [ ] 何らかの **script** が[**非常に頻繁に execute されている**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)、または execute される可能性があることを検出したか？（1、2、5 分ごとなど）

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **書き込み可能な .service** file はあるか？
- [ ] **service によって execute される writable binary** はあるか？
- [ ] **root unit が参照する writable な helper、config、environment file**（`ExecStartPre=`、`ExecStartPost=`、`EnvironmentFile=`）はあるか？`systemctl cat <unit>` で merged unit を inspect し、[service/socket file abuse](../interesting-files-permissions/write-to-root.md)を確認する
- [ ] systemd PATH に **writable folder** はあるか？
- [ ] `/etc/systemd/system/<unit>.d/*.conf` に、`ExecStart`/`User` を override できる **writable systemd unit drop-in** はあるか？<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] **writable timer** はあるか？

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] **writable .socket** file はあるか？
- [ ] **任意の socket と communicate できるか？**
- [ ] 興味深い情報を持つ **HTTP sockets** はあるか？
- [ ] `docker.sock`、`containerd.sock`、`crio.sock`、`podman.sock`、`buildkitd.sock`、または kubelet endpoint などの [**container-runtime または node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) に access できるか？通常の CLI が存在しない場合でも、raw HTTP/gRPC API を test する

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] **任意の D-Bus と communicate できるか？**

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 自分がどこにいるか把握するために network を enumerate する
- [ ] machine 内で shell を取得する前には access できなかった **open ports** はあるか？
- [ ] `tcpdump` を使用して **traffic を sniff できるか？**

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] users/groups の **generic enumeration**
- [ ] **非常に大きな UID** を持っているか？ **machine** は **vulnerable** か？
- [ ] 所属している group のおかげで[**privileges を escalate できるか**](../user-information/interesting-groups-linux-pe/index.html)？
- [ ] **Clipboard** data はあるか？
- [ ] Password Policy は？
- [ ] 以前に発見した **known password** をすべて使用して、可能性のある**各** **user** として login **できるか**試す。password なしでの login も試す

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] **PATH 内の folder に対する write privileges**がある場合、privileges を escalate できる可能性がある

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] `sudo` で **任意の command を execute できるか？** root として何かを READ、WRITE、EXECUTE するために使用できるか？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] `sudo -l` が `sudoedit` を許可している場合、vulnerable versions（`sudo -V` < 1.9.12p2）で任意の files を edit するため、`SUDO_EDITOR`/`VISUAL`/`EDITOR` を介した **sudoedit argument injection**（CVE-2023-22809）を確認する。例：`SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`。<sup>[[1]](#references)</sup>
- [ ] **exploitable SUID binary** はあるか？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** commands は **path** によって **制限**されているか？制限を[**bypass できるか**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)？
- [ ] [**path が指定されていない Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**path を指定する SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)？bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] writable folder にある [**SUID binary に .so library がない**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)？
- [ ] [**SUID RPATH/RUNPATH または writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)？
- [ ] [**SUDO tokens が利用可能か**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)？[**SUDO token を作成できるか**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] [**sudoers files を read または modify できるか**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] [**/etc/ld.so.conf.d/ を modify できるか**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)？
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] binary に **unexpected capability** が付与されていないか？

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] file に **unexpected ACL** が設定されていないか？

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - 機密データを read できるか？privesc のために write できるか？
- [ ] **passwd/shadow files** - 機密データを read できるか？privesc のために write できるか？
- [ ] 機密データがないか、**一般的に興味深い folders を確認**する
- [ ] **奇妙な location/owned files**。executable files に access または alter できる可能性がある
- [ ] **直近数分以内に modified** されたもの
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **PATH 内の Script/Binaries**
- [ ] **Web files**（passwords など）
- [ ] **Backups** はあるか？
- [ ] **passwords を含む known files**：**Linpeas** と **LaZagne** を使用する
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] 任意の commands を execute するために **python library を modify** できるか？
- [ ] **log files を modify できるか？** **Logtotten** exploit
- [ ] **/etc/sysconfig/network-scripts/ を modify できるか？** Centos/Redhat exploit
- [ ] [**ini、int.d、systemd、または rc.d files に write できるか**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**NFS を abuse して privileges を escalate できるか**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] [**restrictive shell から escape する必要があるか**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)？



## References

- [1] [Sudo advisory: sudoedit による任意の file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit requirements と research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: needrestart における LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
