# チェックリスト - Linux特権昇格

{{#include ../banners/hacktricks-training.md}}

### **Linuxローカル特権昇格ベクトルを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [システム情報](privilege-escalation/#system-information)

- [ ] **OS情報**を取得
- [ ] [**PATH**](privilege-escalation/#path)を確認し、**書き込み可能なフォルダー**はありますか？
- [ ] [**env変数**](privilege-escalation/#env-info)を確認し、機密情報はありますか？
- [ ] [**カーネルエクスプロイト**](privilege-escalation/#kernel-exploits)を**スクリプトを使用して**検索（DirtyCow？）
- [ ] [**sudoバージョン**が脆弱かどうか](privilege-escalation/#sudo-version)を**確認**
- [ ] [**Dmesg**の署名検証に失敗しました](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] さらなるシステム列挙（[日付、システム統計、CPU情報、プリンター](privilege-escalation/#more-system-enumeration)）
- [ ] [さらなる防御を列挙](privilege-escalation/#enumerate-possible-defenses)

### [ドライブ](privilege-escalation/#drives)

- [ ] **マウントされた**ドライブをリスト
- [ ] **アンマウントされたドライブはありますか？**
- [ ] **fstabにクレデンシャルはありますか？**

### [**インストールされたソフトウェア**](privilege-escalation/#installed-software)

- [ ] **インストールされた**[ **便利なソフトウェア**](privilege-escalation/#useful-software)を**確認**
- [ ] **インストールされた**[ **脆弱なソフトウェア**](privilege-escalation/#vulnerable-software-installed)を**確認**

### [プロセス](privilege-escalation/#processes)

- [ ] **不明なソフトウェアが実行されていますか？**
- [ ] **必要以上の特権で実行されているソフトウェアはありますか？**
- [ ] **実行中のプロセスのエクスプロイトを検索**（特に実行中のバージョン）。
- [ ] **実行中のプロセスのバイナリを変更**できますか？
- [ ] **プロセスを監視**し、興味深いプロセスが頻繁に実行されているか確認します。
- [ ] **興味深いプロセスメモリを**（パスワードが保存されている可能性がある場所）**読み取る**ことができますか？

### [スケジュールされた/cronジョブ？](privilege-escalation/#scheduled-jobs)

- [ ] [**PATH**](privilege-escalation/#cron-path)がcronによって変更されており、**書き込み**できるか？
- [ ] cronジョブに**ワイルドカード**はありますか？[**ワイルドカードインジェクション**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)
- [ ] **変更可能なスクリプト**が**実行されている**か、**変更可能なフォルダー**内にありますか？
- [ ] **スクリプトが非常に頻繁に実行されている**ことを検出しましたか？（毎分1回、2回、または5回）

### [サービス](privilege-escalation/#services)

- [ ] **書き込み可能な.service**ファイルはありますか？
- [ ] **サービスによって実行される書き込み可能なバイナリ**はありますか？
- [ ] **systemd PATH内の書き込み可能なフォルダー**はありますか？

### [タイマー](privilege-escalation/#timers)

- [ ] **書き込み可能なタイマー**はありますか？

### [ソケット](privilege-escalation/#sockets)

- [ ] **書き込み可能な.socket**ファイルはありますか？
- [ ] **任意のソケットと通信**できますか？
- [ ] **興味深い情報を持つHTTPソケット**はありますか？

### [D-Bus](privilege-escalation/#d-bus)

- [ ] **任意のD-Busと通信**できますか？

### [ネットワーク](privilege-escalation/#network)

- [ ] ネットワークを列挙して、どこにいるかを知る
- [ ] **シェルを取得する前にアクセスできなかったオープンポート**はありますか？
- [ ] `tcpdump`を使用して**トラフィックをスニッフィング**できますか？

### [ユーザー](privilege-escalation/#users)

- [ ] 一般的なユーザー/グループの**列挙**
- [ ] **非常に大きなUID**を持っていますか？ **マシンは脆弱ですか？**
- [ ] **所属するグループ**のおかげで[**特権を昇格**](privilege-escalation/interesting-groups-linux-pe/)できますか？
- [ ] **クリップボード**データは？
- [ ] パスワードポリシーは？
- [ ] **以前に発見したすべての既知のパスワードを使用して、各**可能な**ユーザー**でログインを試みます。パスワードなしでのログインも試みてください。

### [書き込み可能なPATH](privilege-escalation/#writable-path-abuses)

- [ ] **PATH内のフォルダーに書き込み権限がある場合、特権を昇格できる可能性があります**

### [SUDOおよびSUIDコマンド](privilege-escalation/#sudo-and-suid)

- [ ] **sudoで任意のコマンドを実行**できますか？ rootとして何かをREAD、WRITE、またはEXECUTEできますか？ ([**GTFOBins**](https://gtfobins.github.io))
- [ ] **エクスプロイト可能なSUIDバイナリ**はありますか？ ([**GTFOBins**](https://gtfobins.github.io))
- [ ] [**sudo**コマンドは**パス**によって**制限されています**か？制限を**バイパス**できますか](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**パスが指定されていないSudo/SUIDバイナリ**](privilege-escalation/#sudo-command-suid-binary-without-command-path)はありますか？
- [ ] [**パスを指定したSUIDバイナリ**](privilege-escalation/#suid-binary-with-command-path)？ バイパス
- [ ] [**LD_PRELOAD脆弱性**](privilege-escalation/#ld_preload)
- [ ] **書き込み可能なフォルダーからのSUIDバイナリにおける.soライブラリの欠如**はありますか？ 
- [ ] [**SUDOトークンが利用可能**](privilege-escalation/#reusing-sudo-tokens)ですか？ [**SUDOトークンを作成できますか**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] [**sudoersファイルを読み取るまたは変更する**](privilege-escalation/#etc-sudoers-etc-sudoers-d)ことができますか？
- [ ] [**/etc/ld.so.conf.d/**を**変更**できますか](privilege-escalation/#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas)コマンド

### [能力](privilege-escalation/#capabilities)

- [ ] どのバイナリにも**予期しない能力**がありますか？

### [ACL](privilege-escalation/#acls)

- [ ] どのファイルにも**予期しないACL**がありますか？

### [オープンシェルセッション](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL予測可能PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSHの興味深い設定値**](privilege-escalation/#ssh-interesting-configuration-values)

### [興味深いファイル](privilege-escalation/#interesting-files)

- [ ] **プロファイルファイル** - 機密データを読み取る？ privescに書き込む？
- [ ] **passwd/shadowファイル** - 機密データを読み取る？ privescに書き込む？
- [ ] 機密データのために**一般的に興味深いフォルダー**を確認
- [ ] **奇妙な場所/所有ファイル、**アクセスできるか、実行可能ファイルを変更できるかもしれません
- [ ] **最後の数分で変更された**
- [ ] **Sqlite DBファイル**
- [ ] **隠しファイル**
- [ ] **PATH内のスクリプト/バイナリ**
- [ ] **Webファイル**（パスワード？）
- [ ] **バックアップ**？
- [ ] **パスワードを含む既知のファイル**: **Linpeas**と**LaZagne**を使用
- [ ] **一般的な検索**

### [**書き込み可能なファイル**](privilege-escalation/#writable-files)

- [ ] **任意のコマンドを実行するためにpythonライブラリを変更**できますか？
- [ ] **ログファイルを変更**できますか？ **Logtotten**エクスプロイト
- [ ] **/etc/sysconfig/network-scripts/**を**変更**できますか？ Centos/Redhatエクスプロイト
- [ ] [**ini、int.d、systemdまたはrc.dファイルに書き込む**](privilege-escalation/#init-init-d-systemd-and-rc-d)ことができますか？

### [**その他のトリック**](privilege-escalation/#other-tricks)

- [ ] [**NFSを悪用して特権を昇格**](privilege-escalation/#nfs-privilege-escalation)できますか？
- [ ] [**制限されたシェルから脱出する必要がありますか**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
