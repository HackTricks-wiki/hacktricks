# Linux ホスト上のデータベースと秘密情報

{{#include ../../banners/hacktricks-training.md}}

データベースやアプリケーションの認証情報は、多くの場合、それらが支えるサービスの近くに置かれています。アカウントがデータを読み取れるか、特権操作を実行できるかをテストする前に、プロセス、ローカルソケットまたはポート、設定、認証情報ファイルを特定してください。

## ローカルのデータサービスと認証情報を特定する

```bash
ss -lntup
ss -lnx
ps -eo user,pid,args | grep -E '[m]ysqld|[m]ariadbd|[p]ostgres|[r]edis-server|[m]ongod'
find /etc /opt /var/www /home -type f \( -name '*.env' -o -name '*config*' -o -name '.my.cnf' -o -name '.pgpass' \) -ls 2>/dev/null | head -100
```

読み取り可能なアプリケーション設定ファイル、デプロイ用ファイル、サービス環境ファイル、バックアップを調べ、接続文字列やキーがないか確認します。DBプロセスのUnixソケットとTCPリスナーでは、アクセスルールが異なる場合があります。データベースの権限はOSの権限とは異なります。復元したDBパスワードでアクセスできるのは、そのDBアカウントに割り当てられたロールの範囲に限られます。別の経路が実証されない限り、それ以上のアクセスはできません。PostgreSQLでは、行レベルセキュリティポリシーによって、あるロールからレコードを隠せる一方、ポリシー管理権限を持つロールはその見え方を変更できます。データへのアクセスとポリシー管理を区別してください。[MySQL/MariaDB](../../network-services-pentesting/pentesting-mysql.md)、[PostgreSQL](../../network-services-pentesting/pentesting-postgresql.md)、[Redis](../../network-services-pentesting/6379-pentesting-redis.md)のサービス固有ガイドを参照してください。

他のアカウントのホームディレクトリにある読み取り可能な自動化スクリプトには、ファイル名にパスワードを示す語がなくても、認証情報が埋め込まれていることがあります。たとえば、Pythonスクリプトが`su`を起動し、[`pexpect.sendline`](https://pexpect.readthedocs.io/en/latest/api/pexpect.html)でパスワードプロンプトにリテラル値を渡す場合があります。ただし、[`su`](https://man7.org/linux/man-pages/man1/su.1.html)には引き続き認証ポリシーが適用されます。これをアカウント切り替えとみなす前に、現在のユーザーがそのディレクトリをたどって該当スクリプトを読み取れること、そのリテラル値が対象アカウントのパスワードとして意図されたものであること、そして認証情報が現在も有効であることを確認してください。スクリプトが正常に動作しなくても、その内容から秘密情報が漏れることはあります。受動的な出力では、値を表示したりログインを試したりせず、パスと権限を示してください。

読み取り可能なSQLiteアプリケーションデータベースには、待ち受け中のデータベースサービスがなくても、ユーザー名とパスワードハッシュが含まれていることがあります。ハッシュをオフライン監査の手がかりとして扱う前に、スキーマとファイル権限を確認してください。復元したアプリケーションパスワードでOSアカウントやローカル管理パネルにアクセスできるのは、パスワードの再利用が別途確認された場合に限られます。ハッシュ形式やユーザー名の一致だけでは、再利用の証拠になりません。

Apache OFBizでは、`runtime/data/derby/<database>/`に埋め込みDerbyデータベースを使用することがあります。`service.properties`ファイルがデータベースディレクトリを示し、隣接する`seg0`ディレクトリにテーブルファイルがあります。`USER_LOGIN`などのアプリケーションレコードを確認する前に、データベースディレクトリ全体の権限を確認してください。目印となるファイルが読み取り可能でも、テーブルが読み取り可能であること、パスワードを復元できること、またはアプリケーションの認証情報がUnixアカウントで使えることの証明にはなりません。通常の列挙出力にデータベースの内容やパスワードハッシュを含めないでください。[Derbyのデータベースディレクトリに関するドキュメント](https://db.apache.org/derby/docs/10.4/devguide/cdevdvlp40724.html)と[OFBizのログインAPI](https://nightlies.apache.org/ofbiz/stable/javadoc/org/apache/ofbiz/common/login/LoginServices.html)を参照してください。

TeamCityは、設定可能なデータディレクトリ（多くの場合`.BuildServer`）にサーバーデータを保存します。`config/projects/<project>/pluginData/ssh_keys`、`config/database.properties`、組み込みHSQLDBを使用している場合は`system/buildserver.*`、および`backup/TeamCity_Backup_*.zip`の権限を確認してください。アップロードされたSSHキーなどのセキュア設定は暗号化されている場合があるため、パスが読み取り可能というだけでは、秘密鍵が使える証拠にはなりません。データベースやバックアップには、アプリケーションユーザーやパスワードハッシュが含まれることがあります。それらをUnixアカウントに使うには、パスワードの再利用を示す別の証拠が必要です。列挙時にはキー、ハッシュ、データベースの行を表示せず、パスとアクセス権を記録してください。TeamCityの[データディレクトリ](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)、[SSHキー](https://www.jetbrains.com/help/teamcity/ssh-keys-management.html)、[バックアップ](https://www.jetbrains.com/help/teamcity/manual-backup-and-restore.html)に関するドキュメントを参照してください。

Duplicatiバックアップサーバーは設定を`Duplicati-server.sqlite`に保存します。データディレクトリはサービスアカウントのホームディレクトリ、`/var/lib/Duplicati`、またはコンテナボリュームにある場合があり、`--server-datafolder`や`DUPLICATI_HOME`で場所を変更できます。読み取り可能なデータベースは、接続認証情報やサーバー署名用の情報を含むことがあるため、価値の高い手がかりです。ただし、新しいインストールでは機密フィールドが暗号化され、ディレクトリへのアクセスが制限されている場合があります。データベースの権限を実際のサーバーアカウントと照合し、認証済みUIやServerUtilへのアクセスも確認してください。そのサーバーがrootとして動作し、ホストの`/`がコンテナにマウントされている場合、許可されたバックアップ復元やジョブフックによってホストのファイルシステム境界を越えられることがあります。ループバックリスナーやデータベースのファイル名だけでは、制御できる証拠になりません。旧リリースのnonceベースのログイン動作を現行バージョンに当てはめてはいけません。現行バージョンでは別の[認証モデル](https://docs.duplicati.com/technical-details/server-authentication-model)を使用します。バージョンごとの詳細は、Duplicatiの[サーバーデータベース](https://docs.duplicati.com/database-and-storage/the-server-database)と[ServerUtil](https://docs.duplicati.com/duplicati-programs/command-line-interface-cli-1/serverutil)のドキュメントを参照してください。

PostgreSQLでは、`pg_policies`と`pg_class.relrowsecurity`を調べ、クエリで絞り込まれているのか、レコードが存在しないのかを区別してください。ポリシーの変更や無効化には、適切なテーブル所有者権限または管理者権限が必要です。別途leakした保守用アカウントに、アプリケーションアカウントにはない権限がある場合もあります。認証なしで接続できるRedisリスナーは、これとは別の問題です。秘密情報の取得元とみなす前に、ループバックのみにバインドされているか、保護モードまたはACLによって現在の接続が制限されているかを確認してください。

## キーとトークンの保管場所を確認する**

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.ppk' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdb' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

SSH private key、agent socket、Kerberos cache、GPG keyring、またはPKCS#12 bundleは、現在のユーザーがアクセスでき、必要なpassphraseやポリシーによって使用が許可されている場合にのみ役立ちます。まず所有者と権限を確認してください。[ユーザーとセッション](../user-information/user-and-session-triage.md)、[Linux AD](../user-information/linux-active-directory.md)、および[post-exploitation](../post-exploitation/README.md)のページでは、対応するアクセス経路について説明しています。Gitの履歴、古いバックアップ、shell historyにも、稼働中の設定から削除された後にsecretが残っていることがあります。読み取り可能な`.git` directoryには、作業ツリーが空でも削除済みのソースや以前にcommitされたcredentialが残っている可能性があります。自動列挙中に内容を一括出力せず、アクセス権を確認して履歴を手動で調査してください。

`/boot`内の読み取り可能なboot imageも、アーカイブの手掛かりになります。[Initramfsのboot scriptやコピーされたhelper](https://manpages.debian.org/testing/initramfs-tools-core/initramfs-tools.7.en.html)には、[`cryptsetup --key-file=-`](https://manpages.debian.org/testing/cryptsetup-bin/cryptsetup.8.en.html)にkeyを渡すカスタムロジックが含まれる場合があります。imageのアクセス権を確認し、認可されたオフラインコピー内で、関連するboot scriptとhelperのみを調査してください。埋め込まれた、またはそこから導出されたdisk unlock passphraseが、自動的にUnix account passwordになるわけではありません。これをaccountへの移行手段とみなす前に、helperの入力、実際のboot path、別途のcredential再利用を確認してください。通常の列挙では、imageを展開したり、helperを実行したり、候補となるkeyを出力したりしないでください。

Vault CLIは[通常、認証tokenを`~/.vault-token`にcacheします](https://developer.hashicorp.com/vault/docs/commands/token-helper)が、カスタムtoken helperによって別の場所に保存される場合があります。pathが読み取り可能でも、それはcredentialの手掛かりにすぎません。secret engineへのアクセスを推測する前に、tokenの有効性とpolicyを確認してください。[Vault SSH one-time password](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords)の場合、tokenには、ユーザーとCIDRが対象のaccountおよびhostに合致するroleのcredentialを発行する権限が必要です。また、そのhostにはSSH verification helperが設定され、loginが受け入れられる必要があります。`root`を指定するroleやtoken fileだけでは、root accessがある証拠にはなりません。受動的な列挙では、tokenを読み取ったりOTPを要求したりせず、file pathのみを報告してください。

[KeePass 1.xは`.kdb`、KeePass 2.xは`.kdbx`を使用します](https://keepass.info/help/v2/version.html)。他の製品も`.kdb` suffixを使う場合があるため、一致するfilenameは暗号化されたvaultの可能性として扱ってください。読み取り可能なvaultでも、必要なmaster passwordまたはkey fileがなければentryは確認できません。attachmentとして保存されたSSH keyは別の手掛かりであり、そのhostへのaccessを検証する必要があります。[KeePassは画像を含む任意のfileをkey fileとして受け付けます](https://keepass.info/help/base/keys.html)が、近くにあるfileは、用途、必要なmaster keyのすべてのcomponent、さらに特権の高いaccountへのloginをそれぞれ独立して確認するまでは、候補にすぎません。

support archiveには、KeePass vaultとprocess memory dumpの両方が含まれている場合があります。[KeePass 2.xの2.54より前のバージョンでは、CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)により、対応するdumpからmaster passwordを復元できる可能性があります。暗号化されたvaultだけ、または無関係なdumpだけでは不十分です。通常の列挙中に一括展開したりsecretを出力したりせず、archive内のentryとアクセス権を手動で確認してください。PuTTY private keyは、`.ppk` file、またはvault entry内の`PuTTY-User-Key-File`というtextとして存在する場合があります。keyの対象account、暗号化の有無、受け入れられるhostをそれぞれ確認してください。

読み取り可能な`.har` HTTP archiveには、認証header、cookie、form fieldなど、browserのrequestとresponseが保存されている場合があります。単独のfileとして、またはsupport attachment内に保存されることがあります。まず所有者とアクセス権を確認し、関連するentryのみを調査してください。filenameだけでは、再利用可能なcredentialが含まれている証拠にはなりません。自動列挙では、取得した値を出力せず、archiveのpathを一覧表示してください。[Microsoft Edgeのドキュメント](https://learn.microsoft.com/en-us/microsoft-edge/devtools/network/reference#save-all-network-requests-to-a-har-file)で、機密データのexport optionについて説明しています。

暗号化されたdatabase backupについて結論を出す前に、読み取り可能なarchive、アクセス可能なprivate-key material、passphraseの要否を照合してください。認可されている場合、保護されたkeyのpassphrase復元と、復号したbackup dataの調査は、別々の手動作業です。databaseの`root` credentialはUnixの`root` credentialではありません。これらのaccount間でpasswordが再利用されているかどうかは、別途、認可を得て検証する必要があります。web applicationのfilesystem trust boundaryから、これらのmaterialを所有するaccountが露出することもあります。[Django file-cache review](../../network-services-pentesting/pentesting-web/django.md#cache-manipulation-to-rce)を参照してください。

container内のrootとhostのrootは別のidentityです。container内でrootになった後にのみ読み取り可能なprivate SSH keyでも、hostがそのkeyを受け入れる場合はhost accountへの認証に使える可能性がありますが、keyのfilenameやpublic-key commentは、そのaccessの証拠にはなりません。同様に、timestamp付きのpassword変更記録の横にあるカスタムpassword generatorは、手動調査の手掛かりにすぎません。時刻をseedにした非暗号論的なgeneratorでは、seed候補の範囲が狭い場合がありますが、timezone、clockの精度、libraryの挙動、その後のpassword変更によって復元結果が左右されます。認可された場合に限り候補credentialを検証してください。生成された候補を、確認済みpasswordとして扱わないでください。

container内のservice accountは、directoryを通過でき、fileの権限が許可していれば、名目上は特権ユーザーのhome directoryにある古いprovisioning scriptを読み取れる場合があります。埋め込まれたapplication-admin passwordはcredential exposureの手掛かりであり、host root accessを示すものではありません。scriptとcredentialが有効だったか、その値がどのaccountのものか、別のhost accountが現在も同じpasswordを受け入れるかを確認してください。受動的な列挙では、secretを出力したりhostへの認証を試みたりせず、file pathとアクセス権を記録してください。

読み取り可能な`.p12`または`.pfx` bundleのpasswordがapplication configurationに含まれている場合は、`openssl pkcs12 -info -in bundle.p12 -noout`で調査してください。bundleにexport可能なprivate keyが含まれている場合、`openssl pkcs12 -in bundle.p12 -nocerts -nodes -out extracted.key`を実行すると、暗号化されていないkeyが書き出されます。出力fileを保護し、調査後に削除してください。復元したkeyは、実際に一致するserviceまたはciphertextにのみ使用してください。bundleがあるだけでは、そのprivate keyが別のapplicationにも役立つとは限りません。
{{#include ../../banners/hacktricks-training.md}}
