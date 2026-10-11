# Linuxホスト上のデータベースと秘密情報

{{#include ../../banners/hacktricks-training.md}}

データベースやアプリケーションの認証情報は、多くの場合、それらを支えるサービスのそばに保存されています。アカウントがデータを読み取ったり、特権操作を実行したりできるかテストする前に、プロセス、ローカルソケットまたはポート、設定、認証情報ファイルを特定してください。

## ローカルのデータサービスと認証情報を特定する

```bash
ss -lntup
ss -lnx
ps -eo user,pid,args | grep -E '[m]ysqld|[m]ariadbd|[p]ostgres|[r]edis-server|[m]ongod'
find /etc /opt /var/www /home -type f \( -name '*.env' -o -name '*config*' -o -name '.my.cnf' -o -name '.pgpass' \) -ls 2>/dev/null | head -100
```

読み取り可能なアプリケーション設定、デプロイファイル、サービスの環境ファイル、バックアップを調べ、接続文字列やキーがないか確認します。DBプロセスのUnixソケットとTCPリスナーでは、アクセスルールが異なる場合があります。データベースの権限はOSの権限とは異なります。回収したDBパスワードで利用できるのは、そのDBアカウントに割り当てられたロールのみです。別の経路が実証されている場合はこの限りではありません。PostgreSQLでは、行レベルセキュリティポリシーによって、あるロールからレコードを隠せる一方、ポリシー管理権限を持つロールはその見え方を変更できます。データへのアクセスとポリシー管理を区別してください。[MySQL/MariaDB](../../network-services-pentesting/pentesting-mysql.md)、[PostgreSQL](../../network-services-pentesting/pentesting-postgresql.md)、[Redis](../../network-services-pentesting/6379-pentesting-redis.md)のサービス固有ガイドを参照してください。

別のアカウントのホームにある読み取り可能な自動化スクリプトには、ファイル名にパスワードが含まれていなくても、認証情報が埋め込まれている場合があります。たとえばPythonスクリプトが`su`を起動し、[`pexpect.sendline`](https://pexpect.readthedocs.io/en/latest/api/pexpect.html)でパスワードプロンプトにリテラル値を渡すことがあります。ただし、[`su`](https://man7.org/linux/man-pages/man1/su.1.html)には引き続き認証ポリシーが適用されます。現在のユーザーがディレクトリをたどって対象のスクリプトを読めること、そのリテラル値が対象アカウントのパスワードとして意図されたものであること、そして認証情報が現在も有効であることを確認してから、アカウント移行と判断してください。秘密情報がテキストに含まれていれば、スクリプトが正常に実行できなくても漏えいにつながります。受動的な出力では、値を表示したりログインを試したりせず、パスと権限のみを示してください。

読み取り可能なSQLiteアプリケーションデータベースには、データベースサービスがリッスンしていなくても、ユーザー名やパスワードハッシュが含まれている場合があります。ハッシュをオフライン監査の手掛かりとして扱う前に、スキーマとファイル権限を確認してください。回収したアプリケーションパスワードでOSアカウントやローカル管理パネルにアクセスできるのは、パスワードの再利用が別途確認された場合のみです。ハッシュ形式やユーザー名の一致だけでは、再利用の証拠になりません。

Apache OFBizは、`runtime/data/derby/<database>/`に組み込みDerbyデータベースを使用することがあります。Derbyの`service.properties`ファイルがデータベースディレクトリを示し、同階層の`seg0`ディレクトリにテーブルファイルがあります。`USER_LOGIN`などのアプリケーションレコードを確認する前に、データベースディレクトリ全体の権限を確認してください。マーカーファイルが読み取り可能でも、テーブルが読めること、パスワードを回収できること、アプリケーション認証情報がUnixアカウントに有効であることの証明にはなりません。通常の列挙出力にデータベースの内容やパスワードハッシュを含めないでください。[Derbyのデータベースディレクトリに関するドキュメント](https://db.apache.org/derby/docs/10.4/devguide/cdevdvlp40724.html)と[OFBizのログインAPI](https://nightlies.apache.org/ofbiz/stable/javadoc/org/apache/ofbiz/common/login/LoginServices.html)を参照してください。

TeamCityは、設定可能なデータディレクトリ（多くの場合`.BuildServer`）にサーバーデータを保存します。`config/projects/<project>/pluginData/ssh_keys`、`config/database.properties`、組み込みHSQLDBを使用する場合の`system/buildserver.*`、および`backup/TeamCity_Backup_*.zip`の権限を確認してください。アップロードされたSSHキーなどのセキュア設定は暗号化されている場合があるため、パスが読み取り可能なだけでは、使用可能な秘密鍵があるとは限りません。データベースやバックアップには、アプリケーションユーザーやパスワードハッシュが含まれることがあります。それらをUnixアカウントに使用するには、パスワード再利用の別個の証拠が必要です。列挙時には、キー、ハッシュ、データベースの行を表示せず、パスとアクセス権を記録してください。TeamCityの[データディレクトリ](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)、[SSHキー](https://www.jetbrains.com/help/teamcity/ssh-keys-management.html)、[バックアップ](https://www.jetbrains.com/help/teamcity/manual-backup-and-restore.html)に関するドキュメントを参照してください。

Duplicatiのバックアップサーバーは、`Duplicati-server.sqlite`に設定を保存します。データディレクトリは、サービスアカウントのホーム、`/var/lib/Duplicati`、またはコンテナボリューム内にある場合があります。また、`--server-datafolder`や`DUPLICATI_HOME`で場所を変更できます。読み取り可能なデータベースは、接続認証情報やサーバー署名用の情報を含む可能性があるため、重要な手掛かりとなります。ただし、新しいインストールでは機密フィールドが暗号化され、ディレクトリへのアクセスが制限されている場合があります。権限を実際のサーバーアカウント、および認証済みUIやServerUtilへのアクセス状況と照合してください。そのサーバーがrootとして実行され、コンテナにホストの`/`がマウントされている場合、認可されたバックアップ復元やジョブフックによってホストのファイルシステム境界を越えられることがあります。ループバックリスナーやデータベースのファイル名だけでは、制御できることの証明になりません。古いリリースのnonceベースのログイン動作を現行バージョンにも当てはめてはなりません。現行バージョンでは異なる[認証モデル](https://docs.duplicati.com/technical-details/server-authentication-model)が使われています。バージョンごとの詳細は、Duplicatiの[サーバーデータベース](https://docs.duplicati.com/database-and-storage/the-server-database)と[ServerUtil](https://docs.duplicati.com/duplicati-programs/command-line-interface-cli-1/serverutil)のドキュメントを参照してください。

PostgreSQLでは、`pg_policies`と`pg_class.relrowsecurity`を調べ、クエリで絞り込まれているのか、レコードが存在しないのかを区別してください。ポリシーの変更や無効化には、適切なテーブル所有者権限または管理者権限が必要です。アプリケーションアカウントにはなくても、別途 leak した保守用アカウントがその権限を持つ場合があります。認証のないRedisリスナーは、これとは別の所見です。秘密情報の取得元と判断する前に、loopbackのみにバインドされているか、保護モードやACLによって現在の接続が制限されているかを確認してください。

## キーとトークンのストアを確認する

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.ppk' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdb' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

SSH private key、agent socket、Kerberos cache、GPG keyring、PKCS#12 bundleは、現在のユーザーがアクセスでき、必要なpassphraseやポリシーが使用を許可している場合にのみ有用です。まず所有者とpermissionsを確認してください。[users and sessions](../user-information/user-and-session-triage.md)、[Linux AD](../user-information/linux-active-directory.md)、[post-exploitation](../post-exploitation/README.md)のページでは、それぞれに対応するアクセス経路を説明しています。Git history、古いバックアップ、shell historyにも、稼働中の設定から削除された後のsecretが残っている場合があります。読み取り可能な`.git` directoryには、working treeが空でも削除済みのソースや以前commitされたcredentialsが残っている可能性があります。自動enumerationで内容をdumpするのではなく、アクセス可否を確認し、historyを手動で調べてください。

`/boot`にある読み取り可能なboot imageも、archiveの手掛かりになります。[Initramfs boot scripts and copied helpers](https://manpages.debian.org/testing/initramfs-tools-core/initramfs-tools.7.en.html)には、[`cryptsetup --key-file=-`](https://manpages.debian.org/testing/cryptsetup-bin/cryptsetup.8.en.html)にkeyを渡すカスタムロジックが含まれている場合があります。imageのアクセスpermissionsを確認し、認可されたoffline copyで、関連するboot scriptとhelperのみを確認してください。埋め込みまたは派生したdisk-unlock passphraseが、自動的にUnix account passwordになるわけではありません。accountの移行とみなす前に、helperの入力、実際のboot path、別途credentialが再利用されているかを確認してください。通常のenumerationでは、imageを展開したり、helperを実行したり、keyの候補を表示したりしないでください。

Vault CLIは[通常、認証tokenを`~/.vault-token`にcacheします](https://developer.hashicorp.com/vault/docs/commands/token-helper)が、custom token helperを使って別の場所に保存することもあります。読み取り可能なpathはcredentialの手掛かりにすぎません。secret engineへのアクセスを推測する前に、tokenの有効性とpolicyを確認してください。[Vault SSH one-time passwords](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords)では、tokenに、対象のaccountとhostを含むuserおよびCIDRを設定したrole向けのcredentialsを発行する権限が必要です。また、そのhostにはSSH verification helperが設定され、loginが受け付けられなければなりません。roleに`root`と記載されていることやtoken fileが存在することだけでは、root accessの証明になりません。受動的なenumerationでは、tokenを読み取ったりOTPを要求したりせず、file pathのみを報告してください。

[KeePass 1.xは`.kdb`を、KeePass 2.xは`.kdbx`を使用します](https://keepass.info/help/v2/version.html)。他の製品も`.kdb` suffixを使う場合があるため、一致するfilenameは暗号化されたvaultの可能性として扱ってください。必要なmaster passwordまたはkey fileがなければ、読み取り可能なvaultからentryを確認することはできません。attachmentとして保存されたSSH keyは別の手掛かりであり、host accessを検証する必要があります。[KeePassでは画像を含む任意のfileをkey fileとして使用できます](https://keepass.info/help/base/keys.html)が、近くにあるfileは候補にすぎません。その役割、必要なmaster-key componentすべて、さらに高いprivilegeを持つaccountでloginできるかを、それぞれ独立して確認してください。

support archiveには、KeePass vaultとprocess memory dumpの両方が含まれている場合があります。[KeePass 2.xの2.54より前のバージョンでは、CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)により、対応するdumpからmaster passwordを復元できる可能性があります。暗号化されたvault単体、または無関係なdumpだけでは不十分です。通常のenumerationでは、大量展開やsecretの表示をせず、archiveのentryとアクセス権を手動で確認してください。PuTTY private keyは、`.ppk` file、またはvault entry内の`PuTTY-User-Key-File`というtextとして見つかる場合があります。keyが想定するaccount、暗号化の有無、接続先hostで受け入れられるかをそれぞれ確認してください。

読み取り可能な`.har` HTTP archiveには、authentication header、cookie、form fieldなど、browserのrequestとresponseが保存されている場合があります。直接保存されていることも、support attachment内に含まれていることもあります。まず所有者とアクセス権を確認し、関連するentryのみを調べてください。filenameだけでは、再利用可能なcredentialが含まれている証明になりません。自動enumerationでは、取得した値を表示せず、archive pathを一覧表示してください。[Microsoft Edge documentation](https://learn.microsoft.com/en-us/microsoft-edge/devtools/network/reference#save-all-network-requests-to-a-har-file)では、機密データのexport optionについて説明しています。

暗号化されたdatabase backupについて結論を出す前に、読み取り可能なarchive、アクセス可能なprivate-key material、passphraseの要否を照合してください。認可されている場合、保護されたkeyのpassphraseを復元することと、復号されたbackup dataを調べることは、それぞれ別の手動作業です。databaseの`root` credentialはUnixの`root` credentialとは異なります。これらのaccount間でpasswordが再利用されているかは、別途、認可された方法で検証する必要があります。web applicationのfilesystem trust boundaryによって、これらのmaterialを所有するaccountが露出することもあります。[Django file-cache review](../../network-services-pentesting/pentesting-web/django.md#cache-manipulation-to-rce)を参照してください。

containerのrootとhostのrootは別のidentityです。container内でrootになった後にのみ読み取れるprivate SSH keyでも、hostがそのkeyを受け入れればhost accountの認証に使える可能性がありますが、keyのfilenameやpublic-key commentだけでは、そのaccessを証明できません。同様に、timestamp付きのpassword-change recordのそばで見つかったcustom password generatorは、手動分析の手掛かりにすぎません。time-seededのnon-cryptographic generatorではseedの候補範囲が狭い可能性がありますが、timezone、clock precision、libraryの動作、その後のpassword変更が復元に影響します。candidate credentialは認可されている場合にのみ検証し、生成された候補を確認済みのpasswordとして扱わないでください。

container内のservice accountは、directoryをtraverseでき、file permissionsが許せば、名目上はprivilegedなhome directoryにある古いprovisioning scriptを読み取れる場合があります。埋め込まれたapplication-admin passwordはcredential露出の手掛かりであり、host-root accessを意味しません。scriptとcredentialが実際に有効だったか、その値がどのaccountに属するか、別のhost accountで同じpasswordが今も受け入れられるかを確認してください。受動的なenumerationでは、secretを表示したりhostへの認証を試みたりせず、file pathとアクセス権を記録してください。

読み取り可能な`.p12`または`.pfx` bundleのpasswordがapplication configurationに露出している場合は、`openssl pkcs12 -info -in bundle.p12 -noout`で確認してください。bundleにexport可能なprivate keyが含まれる場合、`openssl pkcs12 -in bundle.p12 -nocerts -nodes -out extracted.key`を実行すると、そのkeyは暗号化されずに書き出されます。出力fileを保護し、分析後に削除してください。復元したkeyは、実際に対応するserviceまたはciphertextにのみ使用してください。bundleがあるだけでは、そのprivate keyが別のapplicationで有用だとは限りません。
{{#include ../../banners/hacktricks-training.md}}
