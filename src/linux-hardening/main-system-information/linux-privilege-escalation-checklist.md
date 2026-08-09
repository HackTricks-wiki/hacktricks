# Linux 権限昇格チェックリスト

{{#include ../../banners/hacktricks-training.md}}

# チェックリスト - Linux 権限昇格



### **Linux のローカル権限昇格ベクトルを探す最適な tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS 情報**を取得する
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) を確認する。**書き込み可能なフォルダ**はあるか？
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info) を確認する。機密情報はあるか？
- [ ] **scripts を使用して** [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) を検索する（DirtyCow など）
- [ ] kernel PoC を実行する前に、`uname -r` だけでなく、**実際の前提条件**を確認する。architecture、必要な `CONFIG_*` オプション/modules、namespace の作成可否、active mitigations を確認する。例えば、`unshare -Urn true` を使って user/network namespace が利用可能かテストする。modern netfilter exploits では、`CONFIG_USER_NS`、unprivileged user namespaces、`CONFIG_NF_TABLES` が必要になる場合がある。<sup>[[3]](#references)</sup>
- [ ] [**sudo version**](../linux-basics/linux-privilege-escalation/index.html#sudo-version) が vulnerable か**確認**する
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module と module-loading の misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) を確認する: `insmod`、`modinfo`、`lsmod`、`dmesg`、signature enforcement、`modules_disabled`。
- [ ] helper path を変更または trigger できる場合、[**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) を確認する。
- [ ] **書き込み可能な `/lib/modules` paths**を確認する。書き込み可能な `.ko*` files と `modules.*` metadata も含む。
- [ ] さらに system enum を行う（[date、system stats、cpu info、printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration)）
- [ ] [さらに defenses を列挙する](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **mounted** drives を一覧表示する
- [ ] **unmounted drive はあるか？**
- [ ] fstab に **creds はあるか？**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **有用な software** が**インストールされているか確認**する
- [ ] [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) が**インストールされているか確認**する
- [ ] Debian/Ubuntu では、**needrestart interpreter scanning** がインストールまたは有効化されているか確認する: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`。vulnerable builds では、APT または `unattended-upgrades` が needrestart を root として invoke した際に、attacker-controlled な `PYTHONPATH`/`RUBYLIB` を再利用したり、`/proc/<pid>/exe` の race condition を利用したり、attacker-controlled な Perl paths を scanning したりすることで privilege boundary を越えていた。<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **unknown software が実行されているか？**
- [ ] **本来よりも高い privileges で実行されている software はあるか？**
- [ ] **実行中の processes の exploits**を検索する（特に実行中の version）。
- [ ] 実行中の process の **binary を modify できるか？**
- [ ] **processes を monitor**し、興味深い process が頻繁に実行されているか確認する。
- [ ] 興味深い **process memory**（passwords が保存されている可能性がある）を**read できるか？**

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] cron によって [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)が変更されており、そこに **write できるか？**
- [ ] cron job に [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)はあるか？
- [ ] **modifiable script** が[**executed**](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)されているか、または **modifiable folder** 内にあるか？
- [ ] **script** が[**非常に頻繁に executed**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)される可能性がある、または実際に実行されていることを検出したか？（1、2、5 分ごとなど）

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **書き込み可能な `.service` file はあるか？**
- [ ] **service によって executed される writable binary はあるか？**
- [ ] **root unit が参照する writable な helper、config、environment file**（`ExecStartPre=`、`ExecStartPost=`、`EnvironmentFile=`）はあるか？`systemctl cat <unit>` で merged unit を調査し、[service/socket file abuse](../interesting-files-permissions/write-to-root.md) を確認する。
- [ ] systemd PATH に **writable folder はあるか？**
- [ ] `/etc/systemd/system/<unit>.d/*.conf` に、`ExecStart`/`User` を override できる **writable systemd unit drop-in** はあるか？<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] **writable timer はあるか？**

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] **writable `.socket` file はあるか？**
- [ ] いずれかの **socket と communicate できるか？**
- [ ] 興味深い情報を含む **HTTP sockets** はあるか？
- [ ] `docker.sock`、`containerd.sock`、`crio.sock`、`podman.sock`、`buildkitd.sock`、または kubelet endpoint などの [**container-runtime または node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) に access できるか？通常の CLI が存在しない場合でも、raw HTTP/gRPC API を test する。

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] いずれかの **D-Bus と communicate できるか？**

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 自分がどこにいるか把握するため network を列挙する
- [ ] machine 内で shell を取得する前には access できなかった **open ports はあるか？**
- [ ] `tcpdump` を使って traffic を **sniff できるか？**

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] users/groups の **generic enumeration**
- [ ] **非常に大きな UID** を持っているか？**machine** は **vulnerable** か？
- [ ] 所属している [**group のおかげで privilege を escalate できるか？**](../user-information/interesting-groups-linux-pe/index.html)
- [ ] **Clipboard** data はあるか？
- [ ] Password Policy は？
- [ ] これまでに発見したすべての **known password** を使って、可能性のある**各 user で login**を試す。password なしでの login も試す。

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH 内のいずれかの folder に **write privileges がある場合、privileges を escalate できる可能性がある**

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] sudo で **任意の command を execute できるか？** root として何かを READ、WRITE、EXECUTE するために利用できるか？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] `sudo -l` で `sudoedit` が許可されている場合、vulnerable versions（`sudo -V` < 1.9.12p2）で `SUDO_EDITOR`/`VISUAL`/`EDITOR` を介した **sudoedit argument injection**（CVE-2023-22809）を確認し、arbitrary files を edit する。例: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] **exploitable SUID binary はあるか？**（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** commands が **path** によって **limited** されているか？制限を **bypass できるか**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)？
- [ ] [**path が indicated されていない Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**path を指定している SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)？bypass できるか
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] writable folder にある、[**SUID binary に .so library がない**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)状態はあるか？
- [ ] [**SUID RPATH/RUNPATH または writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) はあるか？
- [ ] [**SUDO tokens が available か？**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens) [**SUDO token を create できるか**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] [**sudoers files を read または modify できるか**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] [**`/etc/ld.so.conf.d/` を modify できるか**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)？
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] いずれかの binary に **unexpected capability** があるか？

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] いずれかの file に **unexpected ACL** があるか？

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - sensitive data を Read できるか？privesc のために Write できるか？
- [ ] **passwd/shadow files** - sensitive data を Read できるか？privesc のために Write できるか？
- [ ] sensitive data がないか、**commonly interesting folders を確認**する
- [ ] access または alter できる executable files が、**weird location にあるか、または自分が owner の files** か？
- [ ] **直近数分以内に Modified** されたもの
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **PATH 内の Script/Binaries**
- [ ] **Web files**（passwords はあるか？）
- [ ] **Backups** はあるか？
- [ ] **passwords を含むことが知られている files**: **Linpeas** と **LaZagne** を使用する
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **python library を modify**して arbitrary commands を execute できるか？
- [ ] **log files を modify できるか？** **Logtotten** exploit
- [ ] **`/etc/sysconfig/network-scripts/` を modify できるか？** Centos/Redhat exploit
- [ ] [**ini、int.d、systemd、または rc.d files に write できるか**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**NFS を abuse して privileges を escalate できるか**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] [**restrictive shell から escape する必要があるか**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)？



## References

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit requirements and research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
