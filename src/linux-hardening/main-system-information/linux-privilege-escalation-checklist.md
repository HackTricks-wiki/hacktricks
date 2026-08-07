# Linux Privilege Escalation チェックリスト

{{#include ../../banners/hacktricks-training.md}}

# チェックリスト - Linux Privilege Escalation



### **Linux のローカル Privilege Escalation ベクトルを探す最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS 情報を取得**
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) を確認。**書き込み可能なフォルダ**はあるか？
- [ ] [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info) を確認。機密情報はあるか？
- [ ] **scripts を使用して** [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) を検索（DirtyCow？）
- [ ] [**sudo version** に脆弱性があるか](../linux-basics/linux-privilege-escalation/index.html#sudo-version) **確認**
- [ ] [**Dmesg** signature verification failed](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module and module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations) を確認: `insmod`、`modinfo`、`lsmod`、`dmesg`、signature enforcement、`modules_disabled`。
- [ ] helper path を変更または trigger できる場合は、[**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) を確認。
- [ ] [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review) を確認。書き込み可能な `.ko*` ファイルや `modules.*` metadata を含む。
- [ ] さらに system enum（[date、system stats、cpu info、printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration)）
- [ ] [さらに defenses を列挙](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **mount 済みの** drives を一覧表示
- [ ] **mount されていない drive はあるか？**
- [ ] **fstab に creds はあるか？**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **インストール済みの**[ **useful software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **を確認**
- [ ] **インストール済みの** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **を確認**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **未知の software が実行されているか？**
- [ ] 本来よりも**高い権限で実行されている software はあるか？**
- [ ] **実行中の processes に対する exploits** を検索（特に実行中の version）。
- [ ] 実行中の process の **binary を変更できるか？**
- [ ] **processes を monitor** し、興味深い process が頻繁に実行されていないか確認。
- [ ] 興味深い **process memory**（passwords が保存されている可能性がある場所）を**読み取れるか？**

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] 何らかの cron によって [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)が変更され、そこに**書き込み可能か？**
- [ ] cron job に [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)はあるか？
- [ ] **変更可能な** [**script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)が**実行**されているか、または**変更可能な folder** 内にあるか？
- [ ] 何らかの **script** が[**非常に** **頻繁に**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) **実行**される、または実行されている可能性を検出したか？（1、2、5 分ごと）

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] 書き込み可能な **.service** file はあるか？
- [ ] **service** によって実行される**書き込み可能な binary** はあるか？
- [ ] systemd PATH 内に**書き込み可能な folder** はあるか？
- [ ] `/etc/systemd/system/<unit>.d/*.conf` に、`ExecStart`/`User` を override できる**書き込み可能な systemd unit drop-in** はあるか？<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] 書き込み可能な **timer** はあるか？

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] 書き込み可能な **.socket** file はあるか？
- [ ] **任意の socket と communication できるか？**
- [ ] 興味深い情報を持つ **HTTP sockets** はあるか？

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] **任意の D-Bus と communication できるか？**

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 自分の位置を把握するために network を enum
- [ ] machine 内で shell を取得する前には access できなかった**open ports** はあるか？
- [ ] `tcpdump` を使用して**traffic を sniff できるか？**

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] users/groups を**一般的に enumeration**
- [ ] **非常に大きな UID** を持っているか？ **machine** に**脆弱性**はあるか？
- [ ] 所属している [**group を利用して privilege escalation できるか**](../user-information/interesting-groups-linux-pe/index.html)？
- [ ] **Clipboard** data はあるか？
- [ ] Password Policy は？
- [ ] 以前に発見した**既知の password**をすべて、可能性のある**各 user**で login に**使用**してみる。password なしでの login も試す。

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH 内のいずれかの folder に対する**書き込み権限**がある場合、privilege escalation できる可能性がある

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo で任意の command を実行できるか？** root として何かを READ、WRITE、EXECUTE するために使用できるか？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] `sudo -l` で `sudoedit` が許可されている場合、脆弱な version（`sudo -V` < 1.9.12p2）で任意の file を edit するため、`SUDO_EDITOR`/`VISUAL`/`EDITOR` を介した **sudoedit argument injection**（CVE-2023-22809）を確認。例: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] **exploitable な SUID binary** はあるか？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** commands が **path** によって**制限**されているか？制限を [**bypass できるか**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)？
- [ ] [**path が指定されていない Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path) はあるか？
- [ ] [**path を指定している SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path) はあるか？bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] 書き込み可能な folder にある、[**SUID binary に .so library がない**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)状態か？
- [ ] [**SUID RPATH/RUNPATH または書き込み可能な library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath) はあるか？
- [ ] [**SUDO tokens が利用可能**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)か？[**SUDO token を作成できるか**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] [**sudoers files を読み取りまたは変更できるか**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] [**/etc/ld.so.conf.d/ を変更できるか**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)？
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] いずれかの binary に**予期しない capability** があるか？

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] いずれかの file に**予期しない ACL** があるか？

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - 機密データを読み取れるか？privesc のために書き込めるか？
- [ ] **passwd/shadow files** - 機密データを読み取れるか？privesc のために書き込めるか？
- [ ] 機密データがないか、**一般的に興味深い folder を確認**
- [ ] **奇妙な場所にある/所有されている files**。executable files に access または変更ができる可能性がある
- [ ] 過去数分以内に**変更された**もの
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **PATH 内の Script/Binaries**
- [ ] **Web files**（passwords？）
- [ ] **Backups**？
- [ ] **passwords を含む既知の files**: **Linpeas** と **LaZagne** を使用
- [ ] **一般的な検索**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] arbitrary commands を実行するために **python library を変更**できるか？
- [ ] **log files を変更できるか？** **Logtotten** exploit
- [ ] **/etc/sysconfig/network-scripts/ を変更できるか？** Centos/Redhat exploit
- [ ] [**ini、int.d、systemd、または rc.d files に書き込めるか**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**NFS を abuse して privilege escalation できるか**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] [**restrictive shell から escape する必要があるか**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)？

## References

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
