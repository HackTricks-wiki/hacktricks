# Linux ホスト上のデータベースとシークレット情報

{{#include ../../banners/hacktricks-training.md}}

データベースやアプリケーションの認証情報は、それらが利用するサービスの近くに置かれていることがよくあります。アカウントがデータを読み取れるか、特権操作を実行できるかをテストする前に、プロセス、ローカルソケットまたはポート、設定、認証情報ファイルを特定しましょう。

## ローカルのデータサービスと認証情報を特定する

```bash
ss -lntup
ss -lnx
ps -eo user,pid,args | grep -E '[m]ysqld|[m]ariadbd|[p]ostgres|[r]edis-server|[m]ongod'
find /etc /opt /var/www /home -type f \( -name '*.env' -o -name '*config*' -o -name '.my.cnf' -o -name '.pgpass' \) -ls 2>/dev/null | head -100
```

読み取り可能なアプリケーション設定、デプロイ用ファイル、サービス環境ファイル、バックアップを調べ、接続文字列やキーを探します。DBプロセスのUnixソケットは、TCPリスナーとは異なるアクセスルールが適用される場合があります。データベースの権限はOSの権限とは異なります。回収したDBパスワードで利用できるのは、そのDBアカウントに割り当てられたロールだけです。別の経路が確認されない限り、それ以上のアクセスはできません。PostgreSQLでは、行レベルセキュリティポリシーによって、あるロールからレコードを見えなくできます。一方、ポリシー管理権限を持つロールは、その見え方を変更できます。データへのアクセスとポリシーの管理は区別してください。[MySQL/MariaDB](../../network-services-pentesting/pentesting-mysql.md)、[PostgreSQL](../../network-services-pentesting/pentesting-postgresql.md)、[Redis](../../network-services-pentesting/6379-pentesting-redis.md)のサービス別ガイドを参照してください。

別のアカウントのホームディレクトリにある読み取り可能な自動化スクリプトに、ファイル名にパスワードの記載がなくても認証情報が埋め込まれている場合があります。たとえば、Pythonスクリプトが`su`を起動し、[`pexpect.sendline`](https://pexpect.readthedocs.io/en/latest/api/pexpect.html)でパスワードプロンプトにリテラル値を渡すことがあります。[`su`](https://man7.org/linux/man-pages/man1/su.1.html)には引き続き認証ポリシーが適用されます。現在のユーザーがディレクトリをたどって対象のスクリプトを読み取れること、そのリテラル値が対象アカウントのパスワードとして意図されたものであること、アカウント移行の手段とみなす前に認証情報がまだ有効であることを確認してください。スクリプトは正常に実行できなくても、内容から秘密情報が漏れる場合があります。受動的な出力では、値を表示したりログインを試みたりせず、パスと権限だけを示してください。

読み取り可能なSQLiteアプリケーションデータベースには、リスニング中のデータベースサービスがなくても、ユーザー名やパスワードハッシュが含まれている場合があります。ハッシュをオフライン監査の手掛かりとして扱う前に、スキーマとファイル権限を確認してください。回収したアプリケーションパスワードをOSアカウントやローカル管理パネルへのアクセスに使えるのは、パスワードの再利用が別途確認された場合に限られます。ハッシュ形式や一致するユーザー名だけでは、再利用の証拠になりません。

Apache OFBizは、`runtime/data/derby/<database>/`に組み込みのDerbyデータベースを使用する場合があります。Derbyの`service.properties`ファイルがデータベースディレクトリを示し、その兄弟ディレクトリである`seg0`にテーブルファイルが格納されます。`USER_LOGIN`などのアプリケーションレコードを確認する前に、データベースディレクトリ全体の権限を確認してください。マーカーファイルが読み取り可能でも、テーブルを読み取れること、パスワードを回収できること、アプリケーション認証情報がUnixアカウントで有効であることの証明にはなりません。通常の列挙出力にデータベースの内容やパスワードハッシュを含めないでください。[Derbyデータベースディレクトリのドキュメント](https://db.apache.org/derby/docs/10.4/devguide/cdevdvlp40724.html)と[OFBizログインAPI](https://nightlies.apache.org/ofbiz/stable/javadoc/org/apache/ofbiz/common/login/LoginServices.html)を参照してください。

TeamCityは、サーバーデータを設定可能なデータディレクトリ（多くの場合`.BuildServer`）に保存します。`config/projects/<project>/pluginData/ssh_keys`、`config/database.properties`、組み込みHSQLDBを使用する場合の`system/buildserver.*`、および`backup/TeamCity_Backup_*.zip`の権限を確認してください。アップロードされたSSHキーなどのセキュアな設定は暗号化されている場合があるため、パスが読み取り可能なだけでは、秘密鍵を使用できるとは限りません。データベースやバックアップには、アプリケーションユーザーやパスワードハッシュが含まれている場合があります。それらをUnixアカウントに使用するには、パスワード再利用の別個の証拠が必要です。列挙時にはキー、ハッシュ、データベースの行を表示せず、パスとアクセス権を記録してください。TeamCityの[データディレクトリ](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)、[SSHキー](https://www.jetbrains.com/help/teamcity/ssh-keys-management.html)、[バックアップ](https://www.jetbrains.com/help/teamcity/manual-backup-and-restore.html)のドキュメントを参照してください。

Duplicatiバックアップサーバーは、設定を`Duplicati-server.sqlite`に保存します。データディレクトリは、サービスアカウントのホームディレクトリ、`/var/lib/Duplicati`、またはコンテナボリューム内にある場合があり、`--server-datafolder`や`DUPLICATI_HOME`で変更できます。読み取り可能なデータベースは、接続認証情報やサーバー署名用マテリアルを含む可能性があるため、価値の高い手掛かりです。ただし、新しいインストールでは機密フィールドが暗号化され、ディレクトリへのアクセスが制限されている場合があります。権限を実際のサーバーアカウント、および認証済みUIやServerUtilへのアクセス状況と照合してください。そのサーバーがrootとして実行され、ホストの`/`がコンテナ内にマウントされている場合、承認済みのバックアップ復元やジョブフックによってホストのファイルシステム境界を越えられることがあります。ループバックリスナーやデータベースファイル名だけでは、制御できる証拠になりません。旧リリースのnonceベースのログイン動作が現行バージョンにも当てはまると想定しないでください。現行バージョンでは別の[認証モデル](https://docs.duplicati.com/technical-details/server-authentication-model)が使われています。バージョンごとの詳細は、Duplicatiの[サーバーデータベース](https://docs.duplicati.com/database-and-storage/the-server-database)および[ServerUtil](https://docs.duplicati.com/duplicati-programs/command-line-interface-cli-1/serverutil)のドキュメントを参照してください。

PostgreSQLでは、`pg_policies`と`pg_class.relrowsecurity`を調べ、クエリで絞り込まれている状態とレコードが存在しない状態を区別してください。ポリシーの変更や無効化には、適切なテーブル所有権または管理者権限が必要です。アプリケーションアカウントにその権限がなくても、別途漏えいしたメンテナンスアカウントが権限を持つ場合があります。認証なしで接続できるRedisリスナーは、これとは別の指摘事項です。秘密情報の取得元とみなす前に、ループバックにのみバインドされているか、保護モードやACLによって現在の接続が制限されているかを確認してください。

## キーとトークンの保存場所を確認する

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.ppk' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdb' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

SSH private key、agent socket、Kerberos cache、GPG keyring、または PKCS#12 bundle が役立つのは、現在のユーザーがアクセスでき、必要な passphrase やポリシーによって使用が許可されている場合に限られます。まず所有者と permissions を確認してください。[users and sessions](../user-information/user-and-session-triage.md)、[Linux AD](../user-information/linux-active-directory.md)、[post-exploitation](../post-exploitation/README.md) のページでは、対応するアクセス経路を説明しています。Git history、古いバックアップ、shell history にも、現在の config から削除した後で secrets が残ることがあります。`.git` ディレクトリを読み取れる場合、working tree が空でも削除済みの source や過去に commit された credentials が残っている可能性があります。自動列挙中に内容を一括出力せず、アクセス権を確認して history を手動で調べてください。

`/boot` に読み取り可能な boot image がある場合も、アーカイブ調査の手掛かりになります。[Initramfs boot scripts and copied helpers](https://manpages.debian.org/testing/initramfs-tools-core/initramfs-tools.7.en.html) には、[`cryptsetup --key-file=-`](https://manpages.debian.org/testing/cryptsetup-bin/cryptsetup.8.en.html) に key を渡すカスタム処理が含まれている場合があります。image のアクセス権を確認し、認可されたオフラインコピーで関連する boot script と helper のみを調べてください。埋め込まれた、またはそこから導出された disk-unlock passphrase が、Unix account password と自動的に同じとは限りません。これを account の切り替えに利用できると判断する前に、helper の入力、実際の boot path、別途 password が再利用されているかを確認してください。通常の列挙では、image の展開、helper の実行、候補 key の表示は行わないでください。

Vault CLI は[通常、認証 token を `~/.vault-token` にキャッシュします](https://developer.hashicorp.com/vault/docs/commands/token-helper)が、カスタム token helper によって別の場所に保存される場合があります。読み取り可能な path は credential の手掛かりにすぎません。secret engine へのアクセスを推測する前に、token の有効性と policy を確認してください。[Vault SSH one-time passwords](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords) を使うには、その token に、対象の account と host を含む user および CIDR を持つ role の credentials を発行する権限が必要です。また、その host で SSH verification helper が設定され、login が許可されている必要があります。role の名前に `root` があることや token file が存在することだけでは、root access の証明になりません。受動的な列挙では、token を読み取ったり OTP を要求したりせず、file path のみを報告してください。

[KeePass 1.x は `.kdb`、KeePass 2.x は `.kdbx` を使用します](https://keepass.info/help/v2/version.html)。他の製品でも `.kdb` suffix が使われる場合があるため、一致する filename は暗号化された vault の可能性として扱ってください。読み取り可能な vault でも、必要な master password または key file がなければ entries は見られません。attachment として保存された SSH key は別の手掛かりであり、その host への access を検証する必要があります。[KeePass は画像など任意の file を key file として受け入れます](https://keepass.info/help/base/keys.html)が、近くにある file は候補にすぎません。その役割、必要な master-key components のすべて、およびより高い権限を持つ account での login を個別に確認してください。

support archive には KeePass vault と process memory dump の両方が含まれていることがあります。[2.54 より前の KeePass 2.x では、CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784) により、対応する dump から master password を復元できる可能性があります。暗号化された vault だけ、または無関係な dump だけでは不十分です。通常の列挙中に一括展開したり secrets を表示したりせず、archive の entries とアクセス権を手動で確認してください。PuTTY private key は `.ppk` file として、または vault entry 内の `PuTTY-User-Key-File` text として存在する場合があります。key の対象 account、暗号化の有無、接続先 host が受け入れるかを個別に確認してください。

読み取り可能な `.har` HTTP archive には、authentication headers、cookies、form fields を含む browser requests と responses が残っている場合があります。直接保存されていることも、support attachment 内に含まれていることもあります。まず所有者とアクセス権を確認し、関連する entries のみを調べてください。filename だけでは、再利用可能な credential が含まれている証拠にはなりません。自動列挙では、取得値を表示せず archive path のみを列挙してください。[Microsoft Edge documentation](https://learn.microsoft.com/en-us/microsoft-edge/devtools/network/reference#save-all-network-requests-to-a-har-file) では、機密データの export option について説明しています。

暗号化された database backup について結論を出す前に、読み取り可能な archive、アクセス可能な private-key material、passphrase の要否を照合してください。認可されている場合でも、保護された key の passphrase の復元と、復号した backup data の調査は別々の手動作業です。database の `root` credential は Unix の `root` credential ではありません。これらの account 間で password が再利用されているかどうかは、別途、認可を得て検証する必要があります。web application の filesystem trust boundary により、これらの material を所有する account が露出することもあります。[Django file-cache review](../../network-services-pentesting/pentesting-web/django.md#cache-manipulation-to-rce) を参照してください。

container root と host root は別の identity です。container 内で root になった後にだけ読み取れる private SSH key でも、host がその key を受け入れる場合は host account への認証に使える可能性があります。ただし、key の filename や public-key comment は、その access を証明しません。同様に、timestamp 付きの password-change record のそばで見つかったカスタム password generator は、手動分析の手掛かりにすぎません。time-seeded の非暗号学的 generator では候補 seed の範囲が狭い場合がありますが、timezone、clock precision、library の挙動、その後の password 変更が復元結果に影響します。認可されている場合に限り候補 credentials を検証してください。生成した候補を確認済みの password として扱わないでください。

container 内の service account でも、ディレクトリを traverse でき、file permissions が許せば、名目上は特権ユーザーの home directory にある古い provisioning script を読み取れる場合があります。埋め込まれた application-admin password は credential exposure の手掛かりであり、host root access を意味するものではありません。script と credential が有効だったか、その値がどの account に属するか、host account が現在も同じ password を受け入れるかを確認してください。受動的な列挙では、secret を表示したり host authentication を試みたりせず、file path とアクセス権を記録してください。

読み取り可能な `.p12` または `.pfx` bundle の password が application configuration に露出している場合は、`openssl pkcs12 -info -in bundle.p12 -noout` で調べてください。bundle に export 可能な private key が含まれている場合、`openssl pkcs12 -in bundle.p12 -nocerts -nodes -out extracted.key` を実行すると、その key は暗号化されずに書き出されます。出力 file を保護し、分析後に削除してください。復元した key は、実際に一致する service または ciphertext にのみ使用してください。bundle があるだけでは、その private key が別の application に役立つとは限りません。
{{#include ../../banners/hacktricks-training.md}}
