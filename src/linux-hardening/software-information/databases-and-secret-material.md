# Linuxホスト上のデータベースと秘密情報

{{#include ../../banners/hacktricks-training.md}}

データベースやアプリケーションの認証情報は、多くの場合、それらを支えるサービスの近くにあります。アカウントがデータを読み取れるか、特権操作を実行できるかをテストする前に、プロセス、ローカルソケットまたはポート、設定、認証情報ファイルを特定しましょう。

## ローカルのデータサービスと認証情報を探す

```bash
ss -lntup
ss -lnx
ps -eo user,pid,args | grep -E '[m]ysqld|[m]ariadbd|[p]ostgres|[r]edis-server|[m]ongod'
find /etc /opt /var/www /home -type f \( -name '*.env' -o -name '*config*' -o -name '.my.cnf' -o -name '.pgpass' \) -ls 2>/dev/null | head -100
```

読み取り可能なアプリケーション設定、デプロイ用ファイル、サービス環境ファイル、バックアップから、接続文字列やキーを探します。DBプロセスのUnix socketには、TCP listenerとは異なるアクセスルールが適用される場合があります。データベースの権限とOSの権限は異なります。復元したDB passwordで利用できるのは、そのDBアカウントに割り当てられたroleだけです。別の経路が実証されていない限り、権限が広がるとは限りません。PostgreSQLでは、row-level security policyによってあるroleからレコードを隠せる一方、policy管理権限を持つroleはその見え方を変更できます。データアクセスとpolicy管理を区別してください。[MySQL/MariaDB](../../network-services-pentesting/pentesting-mysql.md)、[PostgreSQL](../../network-services-pentesting/pentesting-postgresql.md)、[Redis](../../network-services-pentesting/6379-pentesting-redis.md)のサービス別ガイドを参照してください。

別のアカウントのhomeにある読み取り可能なautomation scriptには、ファイル名にpasswordが含まれていなくてもcredentialが埋め込まれていることがあります。たとえばPython scriptが`su`を起動し、[`pexpect.sendline`](https://pexpect.readthedocs.io/en/latest/api/pexpect.html)でpassword promptに文字列を渡す場合があります。[`su`](https://man7.org/linux/man-pages/man1/su.1.html)には引き続き認証ポリシーが適用されます。現在のuserがそのディレクトリをたどって該当scriptを読めること、文字列が対象アカウントのpasswordとして使われること、そしてaccountへの切り替えとみなす前にcredentialが有効であることを確認してください。secretがテキストに含まれていれば、script自体が正常に動作しなくても漏えいにつながることがあります。受動的な出力には、値を表示したりログインを試みたりせず、pathとpermissionだけを表示してください。

読み取り可能なSQLiteアプリケーションdatabaseには、listening database serviceがなくても、usernameとpassword hashが含まれていることがあります。hashをオフライン監査の手がかりとみなす前に、schemaとファイルpermissionを確認してください。復元したアプリケーションpasswordでOS accountやローカル管理panelにアクセスできるのは、使い回しが別途確認された場合に限られます。hashの形式や一致するusernameだけでは、使い回しの証拠になりません。

Apache OFBizでは、`runtime/data/derby/<database>/`に埋め込みDerby databaseが使われる場合があります。Derbyの`service.properties`ファイルはdatabase directoryを示し、その隣の`seg0` directoryにtable fileがあります。`USER_LOGIN`などのアプリケーションrecordを確認する前に、database directory全体のpermissionを確認してください。markerが読み取り可能でも、tableが読み取れること、passwordを復元できること、アプリケーションcredentialがUnix accountで使えることの証明にはなりません。通常のenumeration出力にdatabaseの内容やpassword hashを含めないでください。[Derby database-directory documentation](https://db.apache.org/derby/docs/10.4/devguide/cdevdvlp40724.html)と[OFBiz login API](https://nightlies.apache.org/ofbiz/stable/javadoc/org/apache/ofbiz/common/login/LoginServices.html)を参照してください。

TeamCityはserver dataを設定可能なdata directory（多くの場合`.BuildServer`）に保存します。`config/projects/<project>/pluginData/ssh_keys`、`config/database.properties`、埋め込みHSQLDBを使用する場合は`system/buildserver.*`、および`backup/TeamCity_Backup_*.zip`のpermissionを確認してください。アップロードされたSSH keyなどのsecure settingは暗号化されている場合があるため、pathが読み取り可能というだけでは、使用可能なprivate keyがあるとは限りません。databaseやbackupにはアプリケーションuserやpassword hashが含まれることがあります。それらをUnix accountで使うには、passwordの使い回しを示す別の証拠が必要です。enumeration中はpathとアクセス権を記録し、key、hash、database rowは表示しないでください。TeamCityの[data-directory](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)、[SSH-key](https://www.jetbrains.com/help/teamcity/ssh-keys-management.html)、[backup](https://www.jetbrains.com/help/teamcity/manual-backup-and-restore.html)のドキュメントを参照してください。

Duplicati backup serverは設定を`Duplicati-server.sqlite`に保存します。data directoryはサービスaccountのhome、`/var/lib/Duplicati`、またはcontainer volumeにある場合があり、`--server-datafolder`や`DUPLICATI_HOME`で変更されることもあります。読み取り可能なdatabaseは、接続credentialやserver signing materialを含む可能性があるため、価値の高い手がかりです。ただし、新しいinstallationでは機密fieldが暗号化され、directory accessが制限されている場合があります。permissionを実際のserver accountや、認証済みUIまたはServerUtilからのアクセスと照合してください。そのserverがrootで実行され、hostの`/`がcontainerにmountされている場合、認可されたbackup restoreやjob hookによってhost filesystemの境界を越えることができます。loopback listenerやdatabase filenameだけでは、制御できる証拠になりません。古いreleaseのnonceベースのログイン動作を現行versionに当てはめないでください。現行versionでは異なる[authentication model](https://docs.duplicati.com/technical-details/server-authentication-model)が使われます。versionごとの詳細はDuplicatiの[server database](https://docs.duplicati.com/database-and-storage/the-server-database)と[ServerUtil](https://docs.duplicati.com/duplicati-programs/command-line-interface-cli-1/serverutil)のドキュメントを参照してください。

PostgreSQLでは、`pg_policies`と`pg_class.relrowsecurity`を調べ、queryでfilterされた結果とレコード自体が存在しない状態を区別してください。policyの変更や無効化には、適切なtable ownershipまたは管理権限が必要です。別途漏えいしたmaintenance accountが、アプリケーションaccountにはない権限を持っている場合があります。認証されていないRedis listenerは、これとは別のfindingです。secretの入手元とみなす前に、loopbackだけにbindしているか、またprotected modeやACLが現在の接続を制限しているかを確認してください。

## Keyおよびtoken storeを確認する

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.ppk' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdb' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

An SSH private key、agent socket、Kerberos cache、GPG keyring、またはPKCS#12 bundleが役立つのは、現在のユーザーがアクセスでき、必要なpassphraseやpolicyによって使用が許可される場合に限られます。まず所有者とpermissionsを確認してください。[users and sessions](../user-information/user-and-session-triage.md)、[Linux AD](../user-information/linux-active-directory.md)、[post-exploitation](../post-exploitation/README.md)のページでは、対応するアクセス経路を説明しています。Git history、古いbackup、shell historyには、稼働中のconfigから削除された後もsecretが残っていることがあります。読み取り可能な`.git` directoryには、working treeが空でも削除済みのsourceや、以前commitされたcredentialが残っている可能性があります。自動enumerationで内容を出力するのではなく、アクセス権を確認し、historyを手動で調査してください。

`/boot`内で読み取り可能なboot imageも、archiveを探す手掛かりになります。[Initramfs boot scripts and copied helpers](https://manpages.debian.org/testing/initramfs-tools-core/initramfs-tools.7.en.html)には、[`cryptsetup --key-file=-`](https://manpages.debian.org/testing/cryptsetup-bin/cryptsetup.8.en.html)にkeyを渡すcustom logicが含まれることがあります。imageのアクセスpermissionsを確認し、許可されたoffline copyで関連するboot scriptとhelperのみを調査してください。埋め込まれた、または導出されたdisk-unlock passphraseが、自動的にUnix account passwordになるわけではありません。accountへの移行と判断する前に、helperの入力、実際のboot path、別途のcredential再利用を確認してください。通常のenumerationでは、imageの展開、helperの実行、候補keyの出力は避けてください。

Vault CLIは、[通常、authentication tokenを`~/.vault-token`にcacheします](https://developer.hashicorp.com/vault/docs/commands/token-helper)。ただし、custom token helperでは別の場所に保存されることがあります。読み取り可能なpathはcredentialの手掛かりにすぎません。secret engineへのアクセスを推測する前に、tokenの有効性とpolicyを確認してください。[Vault SSH one-time passwords](https://developer.hashicorp.com/vault/docs/secrets/ssh/one-time-ssh-passwords)の場合、tokenには、対象accountとhostを含むuserとCIDRを持つroleのcredentialを発行する権限が必要です。また、そのhostではSSH verification helperが設定され、loginが許可されている必要があります。roleが`root`を指定していることやtoken fileがあることだけでは、root accessの証明になりません。passive enumerationでは、tokenを読んだりOTPを要求したりせず、file pathを報告してください。

[KeePass 1.xでは`.kdb`、KeePass 2.xでは`.kdbx`が使われます](https://keepass.info/help/v2/version.html)。他の製品も`.kdb` suffixを使うことがあるため、一致するfilenameは暗号化vaultの可能性として扱ってください。読み取り可能なvaultでも、必要なmaster passwordまたはkey fileがなければentryを確認できません。attachmentとして保存されたSSH keyは別の手掛かりであり、host accessを検証する必要があります。[KeePassは画像を含む任意のfileをkey fileとして受け付けます](https://keepass.info/help/base/keys.html)。ただし、近くにあるfileは候補にすぎません。その役割、必要なmaster-key componentすべて、さらに高いprivilegeを持つaccountでのloginを、それぞれ独立して確認してください。

support archiveには、KeePass vaultとprocess memory dumpの両方が含まれていることがあります。[KeePass 2.x 2.54より前のバージョンでは、CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)により、対応するdumpからmaster passwordを復元できる可能性があります。暗号化vaultだけ、または無関係なdumpだけでは不十分です。通常のenumerationでは一括展開やsecretの出力を行わず、archive内のentryとアクセス権を手動で調査してください。PuTTY private keyは、`.ppk` fileまたはvault entry内の`PuTTY-User-Key-File` textとして存在する場合があります。keyが対象とするaccount、暗号化の有無、受け入れるhostを個別に確認してください。

読み取り可能な`.har` HTTP archiveには、authentication header、cookie、form fieldを含むbrowserのrequestとresponseが残っていることがあります。直接保存されている場合も、support attachment内にある場合もあります。まず所有者とアクセス権を確認し、関連するentryだけを調査してください。filenameだけでは、再利用可能なcredentialがあるとは限りません。自動enumerationでは、取得した値を出力せずarchive pathを一覧表示してください。[Microsoft Edge documentation](https://learn.microsoft.com/en-us/microsoft-edge/devtools/network/reference#save-all-network-requests-to-a-har-file)では、sensitive dataのexport optionについて説明しています。

暗号化されたdatabase backupについて結論を出す前に、読み取り可能なarchive、アクセス可能なprivate-key material、passphraseの要否を照合してください。許可されている場合、保護されたkeyのpassphrase復元と、復号したbackup dataの調査は別々の手動作業です。databaseの`root` credentialはUnixの`root` credentialではありません。これらのaccount間でpasswordが再利用されているかどうかは、別途、許可を得て検証する必要があります。web applicationのfilesystem trust boundaryによって、これらのmaterialを所有するaccountが露出することもあります。[Django file-cache review](../../network-services-pentesting/pentesting-web/django.md#cache-manipulation-to-rce)を参照してください。

container内のrootとhostのrootは別のidentityです。container内でrootになった後にのみ読み取り可能なprivate SSH keyでも、hostが受け入れる場合はhost accountへの認証に使える可能性がありますが、keyのfilenameやpublic-key commentだけでは、そのアクセスは証明されません。同様に、timestamp付きのpassword-change recordの隣に見つかったcustom password generatorは、手動分析の手掛かりにすぎません。time-seededの非cryptographic generatorでは、候補seedの範囲が狭い可能性がありますが、timezone、clock precision、libraryの挙動、その後のpassword変更が再構築に影響します。credential候補の検証は、許可されている場合に限って行ってください。生成された候補を確認済みpasswordとして扱わないでください。

container内のservice accountは、directoryをtraverseでき、file permissionsが許せば、名目上privilegedなhome directoryにある古いprovisioning scriptを読み取れる場合があります。埋め込まれたapplication-admin passwordはcredential exposureの手掛かりであり、host-root accessを意味しません。そのscriptとcredentialが有効だったか、その値がどのaccountに属するか、host accountが今も同じpasswordを受け入れるかを確認してください。passive enumerationでは、secretの出力やhostへの認証を試みず、file pathとアクセス権を記録してください。

読み取り可能な`.p12`または`.pfx` bundleのpasswordがapplication configurationに露出している場合は、`openssl pkcs12 -info -in bundle.p12 -noout`で調査してください。bundleにexport可能なprivate keyが含まれる場合、`openssl pkcs12 -in bundle.p12 -nocerts -nodes -out extracted.key`を実行すると、暗号化されていないkeyが書き出されます。出力fileを保護し、分析後に削除してください。復元したkeyは、実際に対応するserviceまたはciphertextにのみ使用してください。bundleがあるだけでは、そのprivate keyが別のapplicationにも役立つとは限りません。
{{#include ../../banners/hacktricks-training.md}}
