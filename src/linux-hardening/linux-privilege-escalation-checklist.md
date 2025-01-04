# チェックリスト - Linux特権昇格

{{#include ../banners/hacktricks-training.md}}

### **Linuxローカル特権昇格ベクトルを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](privilege-escalation/index.html#system-information)

- [ ] **OS情報**を取得
- [ ] [**PATH**](privilege-escalation/index.html#path)を確認し、**書き込み可能なフォルダ**はあるか？
- [ ] [**環境変数**](privilege-escalation/index.html#env-info)を確認し、機密情報はあるか？
- [ ] [**カーネルエクスプロイト**](privilege-escalation/index.html#kernel-exploits)を**スクリプトを使用して**検索（DirtyCow？）
- [ ] [**sudoバージョン**が脆弱かどうか](privilege-escalation/index.html#sudo-version)を**確認**
- [ ] [**Dmesg**の署名検証に失敗](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] さらなるシステム列挙（[日付、システム統計、CPU情報、プリンタ](privilege-escalation/index.html#more-system-enumeration)）
- [ ] [さらなる防御を列挙](privilege-escalation/index.html#enumerate-possible-defenses)

### [ドライブ](privilege-escalation/index.html#drives)

- [ ] **マウントされた**ドライブをリスト
- [ ] **アンマウントされたドライブはあるか？**
- [ ] **fstabにクレデンシャルはあるか？**

### [**インストールされたソフトウェア**](privilege-escalation/index.html#installed-software)

- [ ] **インストールされた**[ **有用なソフトウェア**](privilege-escalation/index.html#useful-software)を**確認**
- [ ] **インストールされた**[ **脆弱なソフトウェア**](privilege-escalation/index.html#vulnerable-software-installed)を**確認**

### [プロセス](privilege-escalation/index.html#processes)

- [ ] **不明なソフトウェアが実行中か？**
- [ ] **必要以上の特権で実行されているソフトウェアはあるか？**
- [ ] **実行中のプロセスのエクスプロイトを検索**（特に実行中のバージョン）。
- [ ] **実行中のプロセスのバイナリを変更**できるか？
- [ ] **プロセスを監視**し、興味深いプロセスが頻繁に実行されているか確認。
- [ ] **興味深いプロセスメモリを**（パスワードが保存されている可能性がある場所）**読み取ることができるか？**

### [スケジュールされた/cronジョブ？](privilege-escalation/index.html#scheduled-jobs)

- [ ] [**PATH**](privilege-escalation/index.html#cron-path)がcronによって変更されており、**書き込み**できるか？
- [ ] cronジョブに[**ワイルドカード**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)はあるか？
- [ ] **実行中の**[**変更可能なスクリプト**](privilege-escalation/index.html#cron-script-overwriting-and-symlink)があるか、または**変更可能なフォルダ**内にあるか？
- [ ] 何らかの**スクリプトが非常に頻繁に実行されている**ことを検出したか？（1、2、または5分ごと）

### [サービス](privilege-escalation/index.html#services)

- [ ] **書き込み可能な.service**ファイルはあるか？
- [ ] **サービスによって実行される書き込み可能なバイナリ**はあるか？
- [ ] **systemd PATH内の書き込み可能なフォルダ**はあるか？

### [タイマー](privilege-escalation/index.html#timers)

- [ ] **書き込み可能なタイマー**はあるか？

### [ソケット](privilege-escalation/index.html#sockets)

- [ ] **書き込み可能な.socket**ファイルはあるか？
- [ ] **任意のソケットと通信**できるか？
- [ ] **興味深い情報を持つHTTPソケット**はあるか？

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] **任意のD-Busと通信**できるか？

### [ネットワーク](privilege-escalation/index.html#network)

- [ ] ネットワークを列挙して自分の位置を把握
- [ ] **シェルを取得する前にアクセスできなかったオープンポート**はあるか？
- [ ] `tcpdump`を使用して**トラフィックをスニッフィング**できるか？

### [ユーザー](privilege-escalation/index.html#users)

- [ ] 一般的なユーザー/グループの**列挙**
- [ ] **非常に大きなUID**を持っているか？**マシンは脆弱か？**
- [ ] 所属する[**グループのおかげで特権を昇格**](privilege-escalation/interesting-groups-linux-pe/index.html)できるか？
- [ ] **クリップボード**データはあるか？
- [ ] パスワードポリシーは？
- [ ] 以前に発見した**すべての既知のパスワードを使用して、各**可能な**ユーザーでログインを試みる。パスワードなしでもログインを試みる。

### [書き込み可能なPATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] **PATH内のいくつかのフォルダに書き込み権限がある場合**、特権を昇格できる可能性がある

### [SUDOおよびSUIDコマンド](privilege-escalation/index.html#sudo-and-suid)

- [ ] **sudoで任意のコマンドを実行**できるか？それを使用して、rootとして何かを**読み取り、書き込み、または実行**できるか？ ([**GTFOBins**](https://gtfobins.github.io))
- [ ] **エクスプロイト可能なSUIDバイナリ**はあるか？ ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo**コマンドが**パスによって制限されている**か？制限を**バイパス**できるか](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**パスが示されていないSudo/SUIDバイナリ**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)はあるか？
- [ ] [**パスを指定したSUIDバイナリ**](privilege-escalation/index.html#suid-binary-with-command-path)は？ バイパス
- [ ] [**LD_PRELOAD脆弱性**](privilege-escalation/index.html#ld_preload)
- [ ] **書き込み可能なフォルダからのSUIDバイナリにおける.soライブラリの欠如**はあるか？](privilege-escalation/index.html#suid-binary-so-injection)
- [ ] [**利用可能なSUDOトークン**](privilege-escalation/index.html#reusing-sudo-tokens)はあるか？ [**SUDOトークンを作成できるか**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoersファイルを読み取るまたは変更することができるか**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] [**/etc/ld.so.conf.d/**を**変更できるか**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas)コマンド

### [能力](privilege-escalation/index.html#capabilities)

- [ ] いかなるバイナリにも**予期しない能力**はあるか？

### [ACL](privilege-escalation/index.html#acls)

- [ ] いかなるファイルにも**予期しないACL**はあるか？

### [オープンシェルセッション](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL予測可能PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSHの興味深い設定値**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [興味深いファイル](privilege-escalation/index.html#interesting-files)

- [ ] **プロファイルファイル** - 機密データを読み取る？特権昇格のために書き込む？
- [ ] **passwd/shadowファイル** - 機密データを読み取る？特権昇格のために書き込む？
- [ ] 機密データのために**一般的に興味深いフォルダを確認**
- [ ] **奇妙な場所/所有ファイル、**アクセスまたは実行可能ファイルを変更できるかもしれない
- [ ] **最近数分で変更された**
- [ ] **Sqlite DBファイル**
- [ ] **隠しファイル**
- [ ] **PATH内のスクリプト/バイナリ**
- [ ] **Webファイル**（パスワード？）
- [ ] **バックアップ**？
- [ ] **パスワードを含む既知のファイル**: **Linpeas**と**LaZagne**を使用
- [ ] **一般的な検索**

### [**書き込み可能なファイル**](privilege-escalation/index.html#writable-files)

- [ ] **任意のコマンドを実行するためにpythonライブラリを変更**できるか？
- [ ] **ログファイルを変更できるか？** **Logtotten**エクスプロイト
- [ ] **/etc/sysconfig/network-scripts/**を**変更できるか？** Centos/Redhatエクスプロイト
- [ ] [**ini、int.d、systemdまたはrc.dファイルに書き込むことができるか**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**その他のトリック**](privilege-escalation/index.html#other-tricks)

- [ ] [**NFSを悪用して特権を昇格できるか**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] **制限されたシェルから脱出する必要があるか**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
