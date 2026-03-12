# チェックリスト - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Linux ローカル privilege escalation ベクトルを探すための最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] **OS information** を取得する
- [ ] [**PATH**](privilege-escalation/index.html#path)、書き込み可能なフォルダはあるか？
- [ ] [**env variables**](privilege-escalation/index.html#env-info)、機密情報はないか？
- [ ] スクリプトを使って [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) を検索する（DirtyCow など）
- [ ] [**sudo version** が脆弱か確認する](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] 追加のシステム列挙（date、system stats、cpu info、printers など）(privilege-escalation/index.html#more-system-enumeration)
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] マウント済みドライブを一覧表示する
- [ ] マウントされていないドライブはあるか？
- [ ] fstab に資格情報は含まれていないか？

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] [**useful software**](privilege-escalation/index.html#useful-software) がインストールされているか確認する
- [ ] [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) がインストールされているか確認する

### [Processes](privilege-escalation/index.html#processes)

- [ ] 不明なソフトウェアが動作していないか？
- [ ] 正常より高い権限で動作しているソフトウェアはないか？
- [ ] 実行中プロセスのエクスプロイト（特に実行バージョン）を検索する
- [ ] 実行中のプロセスのバイナリを変更できるか？
- [ ] プロセスを監視し、頻繁に実行される興味深いプロセスがないか確認する
- [ ] パスワードが保存されている可能性のあるプロセスメモリを**読み取れるか？**

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] cron が [**PATH** ](privilege-escalation/index.html#cron-path) を変更しており、そのパスに書き込み可能か？
- [ ] cron ジョブに [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) が使われているか？
- [ ] 実行されている、または書き込み可能フォルダ内にある [**modifiable script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) はあるか？
- [ ] あるスクリプトが非常に短い間隔で [**頻繁に実行されている**](privilege-escalation/index.html#frequent-cron-jobs)（1、2、5分毎など）と判定できるか？

### [Services](privilege-escalation/index.html#services)

- [ ] 書き込み可能な .service ファイルはあるか？
- [ ] サービスが実行する書き込み可能なバイナリはあるか？
- [ ] systemd の PATH に書き込み可能なフォルダはあるか？
- [ ] `/etc/systemd/system/<unit>.d/*.conf` にある systemd unit drop-in が `ExecStart`/`User` を上書きできるか？

### [Timers](privilege-escalation/index.html#timers)

- [ ] 書き込み可能な timer はあるか？

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] 書き込み可能な .socket ファイルはあるか？
- [ ] 任意のソケットと通信できるか？
- [ ] 興味深い情報を返す HTTP ソケットはあるか？

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] 任意の D-Bus と通信できるか？

### [Network](privilege-escalation/index.html#network)

- [ ] 自分がどこにいるかを知るためにネットワークを列挙する
- [ ] シェルを取得する前にはアクセスできなかった開放ポートはあるか？
- [ ] `tcpdump` を使ってトラフィックをスニッフできるか？

### [Users](privilege-escalation/index.html#users)

- [ ] 一般的なユーザー/グループの列挙
- [ ] とても大きな UID を持っているか？ マシンは脆弱か？
- [ ] 自分が属するグループを利用して権限を昇格できるか？([privilege-escalation/interesting-groups-linux-pe/index.html](privilege-escalation/interesting-groups-linux-pe/index.html))
- [ ] クリップボードのデータはあるか？
- [ ] パスワードポリシーは？
- [ ] これまでに発見した既知のパスワードを使って、可能な限り各ユーザーでログインを試みる。パスワード無しでのログインも試す。

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] PATH 内のフォルダに書き込み権がある場合、権限昇格できる可能性がある

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] sudo で任意のコマンドを実行できるか？それを使って root として何かを READ, WRITE, EXECUTE できるか？ ([**GTFOBins**](https://gtfobins.github.io))
- [ ] `sudo -l` が `sudoedit` を許可している場合、`SUDO_EDITOR`/`VISUAL`/`EDITOR` を介した **sudoedit argument injection** (CVE-2023-22809) をチェックして、脆弱なバージョン(`sudo -V` < 1.9.12p2)で任意のファイルを編集できるか確認する。例: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] 利用可能な攻撃対象の SUID バイナリはあるか？ ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo** コマンドが path によって制限されているか？制限をバイパスできるか](privilege-escalation/index.html#sudo-execution-bypassing-paths)？
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)？
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)？バイパス可能か
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] 書き込み可能なフォルダからの [**.so ライブラリ挿入不足**](privilege-escalation/index.html#suid-binary-so-injection) に該当する SUID バイナリはないか？
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)？[**SUDO トークンを作成できるか**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)？
- [ ] sudoers ファイルを [**読み取り/変更**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d) できるか？
- [ ] `/etc/ld.so.conf.d/` を [**変更**](privilege-escalation/index.html#etc-ld-so-conf-d) できるか？
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) コマンド

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] 予期しない capability を持つバイナリはあるか？

### [ACLs](privilege-escalation/index.html#acls)

- [ ] 予期しない ACL を持つファイルはあるか？

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** の [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - 機密データを読む/privesc に利用できるか？
- [ ] **passwd/shadow files** - 機密データを読む/書き換えて privesc に利用できるか？
- [ ] 機密データがないか、**一般的に興味深いフォルダ** を確認する
- [ ] **変な場所/所有ファイル**、実行ファイルにアクセスまたは変更できる可能性があるか
- [ ] 直近数分で **変更** されたファイル
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files**（パスワード等）
- [ ] **Backups**？
- [ ] パスワードを含む既知ファイル：**Linpeas** と **LaZagne** を使う
- [ ] 一般的な検索

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] 任意コマンドを実行するために **python library** を改変できるか？
- [ ] **ログファイル** を改変できるか？ **Logtotten** エクスプロイト
- [ ] `/etc/sysconfig/network-scripts/` を変更できるか？ Centos/Redhat 向けのエクスプロイト
- [ ] ini、init.d、systemd、rc.d ファイルに [**書き込み可能か**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)？

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] [**NFS を悪用して権限昇格する**](privilege-escalation/index.html#nfs-privilege-escalation) ことは可能か？
- [ ] 制限付きシェルからの [**脱出が必要か**](privilege-escalation/index.html#escaping-from-restricted-shells)？

## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
