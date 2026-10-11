# Linux 権限昇格チェックリスト

{{#include ../../banners/hacktricks-training.md}}

# チェックリスト - Linux 権限昇格



### **Linux のローカル権限昇格ベクトルを探すのに最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] **OS 情報**を取得する
- [ ] [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path)を確認する。**書き込み可能なフォルダ**はあるか？
- [ ] [**環境変数**](../linux-basics/linux-privilege-escalation/index.html#env-info)を確認する。機密情報はあるか？
- [ ] **スクリプトを使って**[**kernel exploit**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits)を探す（DirtyCow など）
- [ ] kernel PoC を実行する前に、`uname -r` だけでなく、**実際の前提条件**を確認する。アーキテクチャ、必要な `CONFIG_*` オプション／モジュール、namespace の作成可否、有効な緩和策を確認する。たとえば、`unshare -Urn true` で user/network namespace が利用可能かテストする。最新の netfilter exploit には、`CONFIG_USER_NS`、非特権 user namespace、`CONFIG_NF_TABLES` が必要な場合がある。<sup>[[3]](#references)</sup>
- [ ] [**sudo のバージョン**に脆弱性があるか](../linux-basics/linux-privilege-escalation/index.html#sudo-version)**確認**する
- [ ] [**Dmesg**の署名検証失敗](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] [**kernel module と module 読み込みの設定ミス**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations)を確認する: `insmod`、`modinfo`、`lsmod`、`dmesg`、署名の強制、`modules_disabled`。
- [ ] helper のパスを変更またはトリガーできる場合、[**kernel.modprobe / modprobe_path の悪用経路**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks)を確認する。
- [ ] [**書き込み可能な /lib/modules のパス**](kernel-modules-and-modprobe.md#writable-libmodules-review)を確認する。書き込み可能な `.ko*` ファイルや `modules.*` メタデータも対象。
- [ ] その他のシステム情報を列挙する ([日時、システム統計、CPU 情報、プリンター](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [その他の防御策を列挙する](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [ドライブ](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] マウント済みのドライブを**一覧表示**する
- [ ] **マウントされていないドライブはあるか？**
- [ ] fstab に**認証情報はあるか？**

### [**インストール済みソフトウェア**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **役立つソフトウェア**](../linux-basics/linux-privilege-escalation/index.html#useful-software)がインストールされているか**確認**する
- [ ] **脆弱なソフトウェア**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)がインストールされているか**確認**する
- [ ] Debian/Ubuntu では、**needrestart の interpreter scanning** がインストール／有効化されているか確認する: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`。脆弱なビルドでは、APT または `unattended-upgrades` が root として needrestart を呼び出した際に、攻撃者が制御する `PYTHONPATH`/`RUBYLIB` の再利用、`/proc/<pid>/exe` との race、攻撃者が制御する Perl パスのスキャンによって、権限境界を越えられた。<sup>[[4]](#references)</sup>

### [プロセス](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] **不明なソフトウェアが実行中か？**
- [ ] 本来よりも**高い権限で実行されているソフトウェアはあるか？**
- [ ] **実行中のプロセスに対する exploit**を探す（特に実行中のバージョン）。
- [ ] 実行中のプロセスの**バイナリを変更できるか？**
- [ ] **プロセスを監視**し、興味深いプロセスが頻繁に実行されていないか確認する。
- [ ] パスワードが保存されている可能性のある、興味深い**プロセスメモリを読み取れるか？**

### [スケジュール／Cron ジョブ](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] cron によって[**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)が変更されており、その中に**書き込み可能な場所があるか？**
- [ ] cron ジョブに[**ワイルドカード** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)はあるか？
- [ ] [**変更可能なスクリプト** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)が**実行されている**、または**変更可能なフォルダ内にあるか？**
- [ ] **スクリプト**が[**頻繁に実行**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)されている、または実行される可能性があると検出したか？（1、2、5 分ごとなど）

### [サービス](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] **書き込み可能な .service ファイル**はあるか？
- [ ] **サービスによって実行される書き込み可能なバイナリ**はあるか？
- [ ] **root unit が参照する書き込み可能な helper、config、または環境ファイル** (`ExecStartPre=`、`ExecStartPost=`、`EnvironmentFile=`) はあるか？`systemctl cat <unit>` でマージ済み unit を確認し、[service/socket ファイルの悪用](../interesting-files-permissions/write-to-root.md)を調べる。
- [ ] オンデマンドの特権ワークフローが、権限の低いユーザーが書き込み可能なディレクトリ内の helper を実行していないか？helper とその親ディレクトリの両方について、[ユーザーが変更可能なパスを root が実行するケース](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries)を確認する。短時間しか実行されない helper は、ワークフローの実行中にしか見つからない場合がある。
- [ ] systemd の PATH に**書き込み可能なフォルダ**はあるか？
- [ ] `ExecStart`/`User` を上書きできる、`/etc/systemd/system/<unit>.d/*.conf` 内の**書き込み可能な systemd unit drop-in**はあるか？<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] **書き込み可能な timer**はあるか？

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] **書き込み可能な .socket ファイル**はあるか？
- [ ] **いずれかの socket と通信できるか？**
- [ ] 興味深い情報を持つ**HTTP socket**はあるか？
- [ ] `docker.sock`、`containerd.sock`、`crio.sock`、`podman.sock`、`buildkitd.sock`、kubelet endpoint などの[**container runtime または node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)にアクセスできるか？通常の CLI がなくても、生の HTTP/gRPC API をテストする。

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] **いずれかの D-Bus と通信できるか？**

### [ネットワーク](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] 現在の位置を把握するためにネットワークを列挙する
- [ ] マシン内で shell を取得する**前にはアクセスできなかったポートが開いているか？**
- [ ] `tcpdump` で**トラフィックを sniff できるか？**

### [ユーザー](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] ユーザー／グループを一般的な方法で**列挙**する
- [ ] **非常に大きな UID** を持っているか？**マシン**に**脆弱性があるか？**
- [ ] 所属する[**グループを利用して権限昇格**](../user-information/interesting-groups-linux-pe/index.html)できるか？
- [ ] **クリップボード**のデータはあるか？
- [ ] パスワードポリシーは？
- [ ] これまでに発見した既知の**パスワードをすべて**使って、可能性のある**各ユーザーで**ログインを**試す**。パスワードなしでのログインも試す。

### [書き込み可能な PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH 内のフォルダに**書き込み権限**があれば、権限昇格できる可能性がある

### [SUDO と SUID コマンド](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudo で任意のコマンドを実行できるか？**それを使って root として何かを読み取り、書き込み、実行できるか？([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l` で `sudoedit` が許可されている場合、脆弱なバージョン（`sudo -V` < 1.9.12p2）では `SUDO_EDITOR`/`VISUAL`/`EDITOR` を使った**sudoedit の引数 injection** (CVE-2023-22809) により任意のファイルを編集できるか確認する。例: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`。<sup>[[1]](#references)</sup>
- [ ] **exploit 可能な SUID バイナリ**はあるか？([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo**コマンドが**パスで制限**されているか？その制限を**回避**できるか](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**パスの指定がない Sudo/SUID バイナリ**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)はあるか？
- [ ] [**パスを指定した SUID バイナリ**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)はあるか？回避を試す
- [ ] [**LD_PRELOAD の脆弱性**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] 書き込み可能なフォルダに、SUID バイナリが必要とする **.so ライブラリがない**か？[**SUID バイナリ内の .so ライブラリ欠落**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)
- [ ] [**SUID RPATH/RUNPATH または書き込み可能なライブラリパス**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)はあるか？
- [ ] [**利用可能な SUDO token**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)はあるか？[**SUDO token を作成できるか**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoers ファイルを読み取る、または変更できるか**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] [**/etc/ld.so.conf.d/ を変更できるか**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)コマンド

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] 予期しない **capability** を持つバイナリはあるか？

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] 予期しない **ACL** を持つファイルはあるか？

### [開いている shell セッション](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH の興味深い設定値**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [興味深いファイル](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile ファイル** - 機密データを読み取れるか？権限昇格に利用できるよう書き込めるか？
- [ ] **passwd/shadow ファイル** - 機密データを読み取れるか？権限昇格に利用できるよう書き込めるか？
- [ ] 機密データがありそうな**一般的に興味深いフォルダを確認**する
- [ ] **奇妙な場所にある／所有されているファイル**。実行可能ファイルにアクセスしたり変更したりできる可能性がある
- [ ] 直近数分以内に**変更されたファイル**
- [ ] **SQLite DB ファイル**
- [ ] **隠しファイル**
- [ ] PATH 内の**スクリプト／バイナリ**
- [ ] **Web ファイル**（パスワードなど）
- [ ] **バックアップ**はあるか？
- [ ] **パスワードを含む既知のファイル**: **Linpeas** と **LaZagne** を使う
- [ ] **一般的な検索**

### [**書き込み可能なファイル**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Python library を変更**して任意のコマンドを実行できるか？
- [ ] **ログファイルを変更できるか？** **Logtotten** exploit
- [ ] **/etc/sysconfig/network-scripts/ を変更できるか？** Centos/Redhat exploit
- [ ] [**ini、int.d、systemd、または rc.d ファイルに書き込めるか**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**その他の手法**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] [**NFS を悪用して権限昇格できるか**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] [**制限付き shell から脱出する必要があるか**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Sudo のセキュリティ勧告: sudoedit による任意ファイルの編集](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux ドキュメント: systemd drop-in の設定](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 の exploit 要件と調査](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys セキュリティ勧告: needrestart の LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
