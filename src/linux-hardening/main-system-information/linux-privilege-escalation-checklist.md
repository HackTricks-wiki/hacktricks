# Linux Privilege Escalation Checklist

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Linux Privilege Escalation



### **Linux のローカル権限昇格ベクトルを探す最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS 情報**を取得する
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path)を確認する。**書き込み可能なフォルダー**はあるか？
- [ ] [**env 変数**](../linux-basics/linux-privilege-escalation/index.html#env-info)を確認する。機密情報はあるか？
- [ ] [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits)を**スクリプトで**検索する（DirtyCow？）
- [ ] kernel PoC を実行する前に、`uname -r`だけでなく、**実際の前提条件**を確認する。アーキテクチャ、必要な`CONFIG_*`オプション/モジュール、namespace の作成可否、アクティブな緩和策を確認する。例えば、`unshare -Urn true`で user/network namespace の利用可能性をテストする。最新の netfilter exploit では、`CONFIG_USER_NS`、unprivileged user namespace、`CONFIG_NF_TABLES`が必要になる場合がある。<sup>[[3]](#references)</sup>
- [ ] [**sudo version**](../linux-basics/linux-privilege-escalation/index.html#sudo-version)が脆弱か**確認**する
- [ ] [**Dmesg** の署名検証に失敗](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module と module-loading の設定ミス**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations)を確認する: `insmod`、`modinfo`、`lsmod`、`dmesg`、署名強制、`modules_disabled`。
- [ ] helper path を変更またはトリガーできる場合、[**kernel.modprobe / modprobe_path の abuse path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks)を確認する。
- [ ] **書き込み可能な/lib/modules path**](kernel-modules-and-modprobe.md#writable-libmodules-review)を確認する。書き込み可能な`.ko*`ファイルと`modules.*`メタデータも含む。
- [ ] 追加の system enum ([date、system stats、cpu info、printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [追加の防御機構を列挙する](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **マウント済み**の drive を一覧表示する
- [ ] **未マウントの drive はあるか？**
- [ ] **fstab に creds はあるか？**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **有用な software**が**インストールされているか確認**する
- [ ] [**脆弱な software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)が**インストールされているか確認**する
- [ ] Debian/Ubuntu では、**needrestart interpreter scanning**がインストール/有効化されているか確認する: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`。脆弱な build では、APT や`unattended-upgrades`が needrestart を root として呼び出した際に、攻撃者が制御する`PYTHONPATH`/`RUBYLIB`を再利用したり、`/proc/<pid>/exe`との race を発生させたり、攻撃者が制御する Perl path をスキャンしたりすることで、privilege boundary を越えていた。<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **未知の software が実行されているか？**
- [ ] software が、本来持つべき以上の**権限で実行されているか？**
- [ ] **実行中の process の exploit**を検索する（特に実行中の version）。
- [ ] 実行中の process の**binary を変更できるか？**
- [ ] **process を monitor**し、興味深い process が頻繁に実行されていないか確認する。
- [ ] 興味深い**process memory**（password が保存されている可能性がある場所）を**読み取れるか？**

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] 何らかの cron によって[**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)が変更されており、そこに**書き込み可能か？**
- [ ] cron job に[**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)があるか？
- [ ] **変更可能な script**が[**実行**されている](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)か、または**変更可能な folder**内にあるか？
- [ ] ある**script**が[**非常に頻繁に**実行](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)されている、または実行される可能性があることを検出したか？（1、2、5分ごとなど）

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **書き込み可能な.service**ファイルはあるか？
- [ ] **service**によって実行される**書き込み可能な binary**はあるか？
- [ ] root unit が参照する、書き込み可能な**helper、config、environment file**（`ExecStartPre=`、`ExecStartPost=`、`EnvironmentFile=`）はあるか？`systemctl cat <unit>`で統合済みの unit を確認し、[service/socket file abuse](../interesting-files-permissions/write-to-root.md)を確認する。
- [ ] systemd PATH 内に**書き込み可能な folder**はあるか？
- [ ] `/etc/systemd/system/<unit>.d/*.conf`に、`ExecStart`/`User`を上書きできる**書き込み可能な systemd unit drop-in**はあるか？<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] **書き込み可能な timer**はあるか？

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] **書き込み可能な.socket**ファイルはあるか？
- [ ] いずれかの**socket と通信できるか？**
- [ ] 興味深い情報を持つ**HTTP socket**はあるか？
- [ ] `docker.sock`、`containerd.sock`、`crio.sock`、`podman.sock`、`buildkitd.sock`、または kubelet endpoint などの[**container-runtime または node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)にアクセスできるか？通常の CLI が存在しない場合でも、raw HTTP/gRPC API をテストする。

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] いずれかの**D-Bus と通信できるか？**

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 自分がどこにいるか把握するため network を列挙する
- [ ] machine 内で shell を取得する前にはアクセスできなかった**open port**はあるか？
- [ ] `tcpdump`を使用して**traffic を sniff できるか？**

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] users/groups の一般的な**列挙**
- [ ] **非常に大きな UID**を持っているか？その**machine**は**脆弱か？**
- [ ] 所属している[**group のおかげで privilege を escalate できるか**](../user-information/interesting-groups-linux-pe/index.html)？
- [ ] **Clipboard** data はあるか？
- [ ] Password Policy は？
- [ ] これまでに発見した**既知の password**をすべて、可能性のある**各 user**でログインするために**使用**してみる。password なしでのログインも試す。

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH 内の folder に対する**書き込み権限**がある場合、privilege を escalate できる可能性がある

### [SUDO and SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] `sudo`で**任意の command を実行できるか？** root として何かを READ、WRITE、EXECUTE するために使用できるか？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] `sudo -l`で`sudoedit`が許可されている場合、脆弱な version（`sudo -V` < 1.9.12p2）で任意の file を編集するため、`SUDO_EDITOR`/`VISUAL`/`EDITOR`を介した**sudoedit argument injection**（CVE-2023-22809）を確認する。例: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`。<sup>[[1]](#references)</sup>
- [ ] **exploitable な SUID binary**はあるか？（[**GTFOBins**](https://gtfobins.github.io)）
- [ ] [**sudo** command が**path**によって**制限**されている](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)か？制限を**bypass できるか**？
- [ ] [**path が指定されていない Sudo/SUID binary**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**path を指定する SUID binary**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)？Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] 書き込み可能な folder に[**SUID binary に不足している.so library**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)はあるか？
- [ ] [**SUID RPATH/RUNPATH または書き込み可能な library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)？
- [ ] [**利用可能な SUDO token**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)はあるか？[**SUDO token を作成できるか**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] [**sudoers file を読み取りまたは変更できるか**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)？
- [ ] [**/etc/ld.so.conf.d/を変更できるか**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)？
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas) command

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] binary に**想定外の capability**があるか？

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] file に**想定外の ACL**があるか？

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**予測可能な OpenSSL PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH の興味深い configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile file** - 機密データを読み取れるか？privesc のために書き込めるか？
- [ ] **passwd/shadow file** - 機密データを読み取れるか？privesc のために書き込めるか？
- [ ] 機密データがないか、**一般的に興味深い folder**を確認する
- [ ] **奇妙な場所にある file/所有 file**にアクセスまたは executable file を変更できる可能性がある
- [ ] 直近数分以内に**変更された**もの
- [ ] **Sqlite DB file**
- [ ] **Hidden file**
- [ ] **PATH 内の Script/Binary**
- [ ] **Web file**（password？）
- [ ] **Backup**？
- [ ] **password を含む既知の file**: **Linpeas**と**LaZagne**を使用する
- [ ] **一般的な検索**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] 任意の command を実行するために**python library を変更**できるか？
- [ ] **log file を変更できるか？** **Logtotten** exploit
- [ ] **/etc/sysconfig/network-scripts/**を変更できるか？Centos/Redhat exploit
- [ ] [**ini、int.d、systemd、または rc.d file に書き込めるか**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**Other tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**NFS を abuse して privilege を escalate できるか**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)？
- [ ] [**restrictive shell から escape する必要があるか**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)？



## References

- [1] [Sudo advisory: sudoedit による任意 file 編集](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit の要件と research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: needrestart における LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
