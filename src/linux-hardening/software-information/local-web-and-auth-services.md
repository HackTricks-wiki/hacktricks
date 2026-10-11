# ローカル Web サービスと認証サービス

{{#include ../../banners/hacktricks-training.md}}

Linux shell では、プロセスの引数、リスナー、ユニットファイル、設定、ログ、ローカル専用インターフェースなど、ホスト側から Web サービスと認証サービスを確認できます。この視点を使って、アクセス可能なサービスと、そのサービスが実際に使用するアカウントやファイルを結び付けましょう。

## ローカル Web スタックを把握する

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

仮想ホスト名、ドキュメントルート、proxy route、アップロードディレクトリ、PHP execution settings、認証情報を含む設定ファイルを調べます。loopback listenerは、proxyやSSH tunnel経由で到達できる場合があります。ローカルlistenerに対して名前付き仮想ホストをテストするには、意図した`Host` headerを送るか、正しいaddressとportを指定して`curl --resolve`を使用します。仮想ホストの列挙によって、デフォルトの応答に含まれない名前が見つかることもあります。Apacheで`.htaccess`による上書きが許可されているか、また書き込み可能なアップロードディレクトリでPHPを実行できるかを確認してから、コード実行が可能と判断してください。デプロイ済みのJavaScript source mapから、ソースパスやクライアント側の秘密情報が漏れる場合があります。復元した値は手がかりとして扱い、実際の権限を確認してください。web固有の確認については、[Apache](../../network-services-pentesting/pentesting-web/apache.md)と[Nginx](../../network-services-pentesting/pentesting-web/nginx.md)を参照してください。

Apacheで[mpm-itk](https://mpm-itk.sesse.net/)を使用している場合、有効な`AssignUserID`によって、仮想ホストを別のユーザーおよびグループとして実行できます。低権限アカウントがそのホストの`DocumentRoot`にスクリプトを書き込める場合、到達可能なrouteが、割り当てられたidentityで実際にスクリプトを実行するか確認してください。モジュールがロードされていること、有効な仮想ホスト設定（expressionによるidentityの上書きを含む）、ディレクトリへの書き込み権限と検索権限、スクリプトhandler、listenerへのアクセスを確認します。強調表示されたdirectiveや書き込み可能なディレクトリだけでは、ユーザーをまたいだ実行の証明にはなりません。

web serverで公開されているホームディレクトリから、稼働中の`.ssh`ディレクトリが非公開でも、SSH identity fileのバックアップアーカイブが漏れる場合があります。たとえば、[Nostromoの`homedirs_public`設定](https://www.nazgul.ch/dev/nostromo_man.html)は、ユーザーのホームディレクトリ内で公開するサブディレクトリを選択します。パスだけでアーカイブが見つかった場合は、手がかりとして扱います。serverの有効なmapping、ローカルでの読み取り可否またはHTTP authorization、アーカイブの内容、秘密鍵のpassphrase、対応するアカウントが実際にその鍵を受け入れるかを確認してください。通常のホスト列挙では、アーカイブを展開したり鍵の内容を出力したりしないでください。

高権限のローカルweb appの読み取り可能なバックアップから、稼働中のソースにアクセスできなくても、認証やファイル読み取りのロジックが判明する場合があります。バックアップに基づいて判断する前に、稼働中のserviceと比較してください。特に、呼び出し元が制御するテキストの後ろに秘密情報とrole flagを付けて暗号化し、cookieを作成する仕組みは、appが決定的なECB blockを使い、指定したテキストに対して新しいcookieを返し、後から復号値をエスケープされていない区切り文字で分割する場合、精査が必要です。[NISTは、ECBのblockごとの独立した再現可能なmappingについて説明しています](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)。この特性は、選択入力を使った比較に利用できる場合がありますが、それだけで高いroleが得られるわけではありません。稼働中のroute、sessionの前提条件、正確なparserとdata flow、serviceのidentity、および別個の特権操作またはファイル読み取り経路を確認してください。受動的なインベントリでは、アーカイブの内容を読んだり認証probeを送ったりせず、バックアップのmetadataとlistenerの所有者を報告してください。

同じソースレビューの方法は、カスタムのSSHベースinterfaceなど、特権を持つ**非HTTP**のloopback serviceにも適用できます。アクセス可能なソースバックアップに、呼び出し元が選んだファイルパスを受け取るコマンドがあれば、認証条件、そのパスの解決方法、開く前に解決後のファイルが意図したディレクトリ配下にあることを確認しているかを調べます。Goの[`filepath.Join`](https://pkg.go.dev/path/filepath#Join)はパスを正規化しますが、指定範囲内に収まることは保証しません。バックアップが実行中のbuildと一致すること、listenerに到達可能であること、低権限アカウントがそのコマンドを使用できること、processが対象を読み取れることを確認してください。読み取り可能なSSH keyを持っていることは、別個のlogin policyに関する問題です。自動出力では、アーカイブの内容や鍵を展開せずに、ソースアーカイブのパスとserviceの所有者を報告してください。

TCP loopbackで待ち受けるPHP-FPM poolには、webサイトに認証があっても、別のローカルアカウントから接続できる場合があります。[PHPは、FastCGIに接続できるクライアントが`auto_prepend_file`を含むrequest設定を制御できると警告しています](https://www.php.net/manual/en/install.fpm.php)。poolの`listen`および`listen.allowed_clients`設定を、稼働中のlistener、worker UID、既存のスクリプトパス、`security.limit_extensions`や`php_admin_value`による制限とあわせて確認してください。poolの設定ファイルには`env[...]` directiveに認証情報が含まれる場合があるため、自動インベントリでは内容ではなくパスを報告してください。設定ファイルやportだけでは、ユーザーをまたぐ実行経路の証明にはなりません。protocolの詳細は[FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md)を参照してください。

特権を持つローカルAPIでは、コード実行だけでなくauthorizationも追跡してください。低権限アカウントが変更できるdatabase roleによってAPI routeが利用可能になる場合もありますが、次の境界はrouteの実装によって異なります。たとえば、request JSONをJavaScript objectにmergeしてから[`child_process.exec`](https://nodejs.org/api/child_process.html)を呼び出す処理は、[prototype pollutionから実行に至るdata flow](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)の観点で精査が必要です。実際のmerge library/version、入力検証、到達可能なroute、processのidentity、child processのoptionsを確認してください。root所有のNode listenerや脆弱なdependency名だけでは、手がかりにすぎません。

ファイルベースのCMSでは、一般的な`.php`設定ファイル以外に、administratorのpassword verifierが保存されている場合があります。例として、サイトの`data/database.js`や`data/settings/pass.php`があります。手動で確認する前にファイルの所有者と読み取り可否を確認し、hashを自動生成される共有出力に含めないでください。復元可能なapp passwordは、Unixアカウントとは別の権限境界です。passwordの再利用が主張されている場合は、対象のアカウントと許可された認証方法で確認してください。

appの認証controllerには、設定ファイルではなくソースコードに平文のlogin passwordが含まれている場合もあります。低権限ユーザーがデプロイ済みcontrollerを読み取れる場合は、ローカルで認証比較処理を確認し、値を共有用の列挙出力に含めないでください。コードパスが有効であること、そのpasswordがappで有効であること、さらに高権限のUnixアカウントが同じpasswordを実際に受け入れることを確認してから、ローカル権限昇格を主張してください。controllerのファイル名だけなら、確認すべき手がかりにすぎません。

Dolibarrは`dolibarr_main_db_pass`を含むdatabase接続設定を`htdocs/conf/conf.php`に保存します（[configuration reference](https://wiki.dolibarr.org/index.php/Configuration_file)）。読み取り可能なファイルは認証情報の手がかりになりますが、別途確認されたアカウントpasswordの再利用や、ほかのdatabase権限がなければ、ローカル権限昇格にはつながりません。まず権限を確認し、自動出力に値を表示しないでください。

GitLab Linux packageの設定ファイルは通常`/etc/gitlab/gitlab.rb`ですが、別の場所に読み取り可能なコピーが残っている場合があります。[GitLabの説明](https://docs.gitlab.com/omnibus/settings/smtp/)によると、このファイルには`gitlab_rails['smtp_password']`が含まれる場合があります。ただし、暗号化されたSMTP設定ではpasswordが平文ファイルの外に保存されることがあります。読み取り可能な設定は認証情報の手がかりとして扱い、それが有効であること、認証情報が現在も有効であること、特定の高権限アカウントがその認証情報を受け入れることを確認してから、password再利用を主張してください。また、[GitLabは`gitlab-ctl reconfigure`の実行時にrootとして`gitlab.rb`をRuby codeとして実行します](https://docs.gitlab.com/omnibus/settings/configuration/)。書き込み可能な有効ファイル、または`from_file`で読み込まれるファイルが実行上の問題になるには、実際に特権でreconfigureされる経路が必要です。設定のpreviewで認証情報が露出する場合があるため、出力は機密情報として扱い、代わりにパスと権限を共有してください。

セルフホスト型Mattermostでは、`SqlSettings.DataSource`が`/opt/mattermost/config/config.json`に保存されている場合があります。[Mattermostの説明](https://docs.mattermost.com/deployment-guide/server/troubleshooting)には、この一般的なパスと、稼働中の設定をdatabaseに保存するdeploymentの両方が記載されています。読み取り可能なファイルからappのdatabase認証情報が判明する場合がありますが、それだけではdatabaseへのアクセスやUnix root権限が得られるとは限りません。有効な設定の保存元、database roleが持つ実際の権限、別途復元されたapp passwordの有無、そのpasswordが特定の高権限Unixアカウントで使えるかを確認してください。password hashの形式はMattermostのversionによって変わることがあります。列挙時には接続文字列を表示したりdatabaseをqueryしたりせず、設定ファイルのパスとアクセスmetadataを記録してください。

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

仮想ホストの結果は、デフォルト応答サイズまたは別の安定した基準と照合し、推測した名前がすべて有効に見えないようにします。ソースマップは、実際にデプロイされているか、別の方法で読み取り可能な場合にのみ役立ちます。

リバースプロキシによって、アプリケーションが信頼するクライアントヘッダーが変わることがあります。`X-Forwarded-For`、`X-Forwarded-Host`、または類似のヘッダーが呼び出し元の識別に使えると決めつける前に、直接リクエストとプロキシ経由のリクエストを比較してください。プロキシとアプリケーションの設定を合わせて確認します。

PHP が `$_SERVER['HTTP_X_FORWARDED_FOR']` を [`system()`](https://www.php.net/manual/en/function.system.php) に渡す文字列にコピーしている場合、到達可能なリクエスト経路で呼び出し元が指定したヘッダーを渡せるか、シェルのメタ文字がその文字列に変更されず届くかを確認してください。先頭に `sudo iptables` を含むコマンドでも、その後にシェルで区切られたコマンドが root で実行されるわけではありません。別途、有効な sudo ルールで権限昇格が許可されていない限り、後続のコマンドは Web ワーカーとして実行されます。root への経路を主張する前に、ワーカーの実行ユーザー、正確な `sudo -l` の許可内容と認証要件、コマンドの引数境界を確認してください。通常のホスト列挙では、インジェクションを試さずにソースとポリシーを調査します。

## アクセスログ内のログイン認証情報

アプリケーションがログインフォームを `GET` で送信すると、ユーザー名とパスワードがリクエスト URI のクエリパラメーターになることがあります。`POST` リクエストにもクエリ文字列を含められます。`POST` を使っても、無関係なフォームフィールドに入力したパスワードなど、URI に誤って含まれた秘密情報は隠せません。[Apache の一般的なアクセスログのリクエスト行](https://httpd.apache.org/docs/2.4/logs.html)は、設定された書式で `%r` を使用している場合、メソッドとクエリ文字列を含む URI を記録します。そのため、一部の Linux システムでの `adm` グループなど、これらのログを読み取れるアカウントから、認証情報につながる手掛かりが見つかる可能性があります。実際のログ書式と権限を確認し、その値が秘密情報であること、アカウントで受け付けられること、権限境界を越えることを検証してください。リクエスト本文がログに記録されたと決めつけず、候補の値を共有出力にコピーしないでください。

読み取り可能なアクセスログだけを調査し、認証情報の値を共有コマンド出力に含めないでください。長いリクエスト行にはリファラーやユーザーエージェントも含まれるため、短い行だけを抽出するフィルターでは、確認すべきリクエストが隠れることがあります。Apache、httpd、Nginx の一般的なアクセスログの場所は、`/var/log/apache2/access.log`、`/var/log/httpd/access_log`、`/var/log/nginx/access.log` です。ローテーションされたログに古い認証情報が残っていることもあります。[LFI によるログファイルへのアクセス](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)も、同じデータにたどり着く別の経路です。

アプリケーションの認証ログには、ログイン失敗時に**ユーザー名**欄へ誤って入力されたパスワードが記録されることもあります。まず、そのログが読み取り可能で、送信されたユーザー名を記録する書式かを確認してください。関連する範囲だけをローカルで少量確認し、候補の認証情報を共有出力にコピーしないでください。パスワードらしいユーザー名は手掛かりであり、有効なパスワードや高い権限の証拠ではありません。移行を主張する前に、対象アカウントと、特定のサービスまたは Unix アカウントでの認証情報の再利用を検証してください。

別の ID で動くスケジュール済みクライアントがエンドポイントに認証情報を送信している場合、書き込み可能な Web ログインハンドラーは別途調査が必要です。**実際に稼働中の**ハンドラーへの書き込み権限、クライアントの実際のスケジュールとリクエスト経路、送信される認証情報の所有者、そのアプリケーションパスワードが高い権限を持つオペレーティングシステムアカウントでも有効かを確認してください。書き込み可能なページや定期実行プロセスだけでは、その移行が成立するとは言えません。受動的なインベントリでは、ハンドラーを変更したりパスワードを収集したりせずに、パスの権限とジョブのメタデータを報告してください。

Suricata の EVE JSON ログには、FTP イベントのログ記録が有効な場合、FTP の `USER` および `PASS` コマンドとその `command_data` が記録されることもあります。少量の関連範囲をローカルで確認する前に、ローテーション済みまたは圧縮済みのファイルも含め、`/var/log/suricata/eve*.json*` の読み取り可否を確認してください。EVE ファイルが読み取り可能であることは手掛かりにすぎません。FTP イベントが記録されていること、データに利用可能な認証情報が含まれること、権限境界を越えることを確認してください。共有列挙出力に `command_data` を表示しないでください。Suricata のドキュメントには、[FTP イベントフィールド](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)と[EVE のローテーションおよびファイル名の種類](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)が記載されています。

## 生成された Apache 設定とパイプログ

[remco](https://github.com/HeavyHorst/remco) は、キー/値バックエンドを監視し、テンプレートを Apache 設定ファイルにレンダリングして、リロードコマンドを実行できます。実行中の remco プロセスの ID、設定されたテンプレートの入力元と出力先、監視対象のキー接頭辞、バックエンド値が `ServerName` などの Apache ディレクティブに直接挿入されるかを確認してください。ローカルのバックエンドリスナーがあるだけでは、現在のユーザーが監視対象のキーを書き込めるとは言えません。権限昇格を主張する前に、バックエンドの認証と権限を確認してください。

書き込み可能なバックエンド値にエスケープされていない改行があると、意図したディレクティブ値が複数の Apache ディレクティブに分割されることがあります。[Apache のパイプログ](https://httpd.apache.org/docs/2.4/logs.html#piped)は特に注意が必要です。`CustomLog` または `ErrorLog` に `|` コマンドが指定されていると、親の httpd プロセスと同じ ID（多くの場合 root）でヘルパーが起動します。`|$` は Apache にシェルを使わせます。列挙中にバックエンドデータを変更したりサービスを再起動したりせず、生成された設定とリロード経路を確認してください。引数に秘密情報が含まれる可能性があるため、パイプコマンド全体は非公開にしてください。

## 認証とサービス ID

Monit の制御ファイルは通常 `~/.monitrc` または `/etc/monitrc` ですが、`monit -c` で別のパスを指定できます。読み取り可能なファイルには、Web インターフェイス用の `set httpd` や `allow user:password` の設定が含まれていることがあり、通常はローカルポート 2812 で待ち受けます。確認する前にファイルの所有者と権限を調べ、パスワードの値を共有列挙出力に含めないでください。Web 認証情報で付与されるのは、設定された Monit ロールのみです。読み取り専用ユーザーは制御操作を実行できません。Unix アカウントへの別の権限昇格を主張するには、パスワードの再利用、または認証済みロールが実際に実行できる特権 Monit アクションを確認する必要があります。[Monit の制御ファイルと認証に関するドキュメント](https://www.mmonit.com/monit/documentation/monit.html)を参照してください。

Webmin では、`/etc/webmin/miniserv.conf` にサーバー設定が記載され、`/etc/webmin/webmin.acl` にユーザーがアクセスできるモジュールが記録されます。[Webmin のドキュメントにはモジュール許可の境界が記載されています](https://webmin.com/docs/development/creating-modules/)。Unix パスワードや読み取り可能な ACL ファイルだけでは、Webmin セッションを取得できません。実際の認証マッピング、到達可能なリスナー、認証済みアカウント、Package Updates モジュールに対する有効な権限、インストール済みコードまたはベンダー修正、Webmin のプロセス ID を確認してください。1.910 までの影響を受けるビルドでは、[CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840) により、そのモジュール権限を持つアカウントが更新ハンドラーを介してコマンドを実行できました。受動的な列挙では、認証情報を表示したり更新を試みたりせず、設定パスと権限を報告してください。

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) はサービス固有の認証を管理します。書き込み可能なポリシーまたはモジュールのパスを変更すると、ログイン動作を変えられる可能性があります。
- LDAP/SSSD の設定から、ディレクトリエンドポイント、bind identity、アクセスルールが分かることがあります。取得した bind password により、現在の OS アカウントを超える LDAP クエリが可能になる場合があります。正確な bind identity とディレクトリ ACL をテストしてください。secret を調べる前にファイルの権限を確認してください。[Linux Active Directory](../user-information/linux-active-directory.md) と [FreeIPA](freeipa-pentesting.md) では、ticket とディレクトリの利用方法を扱っています。
- Postfix の alias は、受信メールをローカルコマンドにパイプできます。権限の低いユーザーが参照先のスクリプトを変更できる場合、メール配信によって、そのユーザーのコードが配信時の identity で実行される可能性があります。この経路を主張する前に、alias map とスクリプトの所有者を確認してください。[SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md) を参照してください。
- Jenkins やその他の CI サービスでは、強い権限を持つローカルアカウントで job が実行される場合があります。Pipeline や plugin をテストする前に、サービスユーザー、書き込み可能な job/workspace パス、ローカル管理インターフェースを確認してください。また、**job が利用できる credentials** と、それらで認証できるアカウントも確認してください。[SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) を使う Pipeline は、Jenkins 自体が権限の低い Unix アカウントで実行されていても、SSH credential のユーザーとしてホストにアクセスできます。ホストの privilege escalation を主張する前に、現在の Jenkins identity が Pipeline を変更できる `Job/Create`、`Job/Configure`、またはその他の有効な手段を持つこと、その job の scope 内で credential が利用可能であること、対象の SSH アカウントがその key を受け入れることを確認してください。credential の表示名や ID だけでは、これらの条件を満たす証拠にはなりません。Jenkins は、job の作成者や多くの場合 job の設定者が、scope 内で利用可能な credential を任意に使用できると警告しています。そのため、サービス UID と同様に、[credential scope](https://www.jenkins.io/doc/book/security/credentials/) と [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/) も重要です。credential の値や private key を共有される enumeration 出力に含めないでください。

## Gogs repository file writes

ローカルの Gogs サービスでは、`gogs web` プロセスの所有者を実行ファイルのバージョンおよび `custom/conf/app.ini` と照合してください。設定から、サービス identity、repository root、listener address、registration が無効化されているかどうかが分かる場合があります。loopback のみで待ち受ける listener にも、ローカルユーザーはアクセスできます。0.13.3 以前の Gogs には、認証済みの `PutContents` symlink file-write issue ([CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)) があります。repository writer は symlink を commit し、その後 API write の出力先を経由させられます。ファイルアクセス権限は Gogs プロセスの権限に従うため、root 所有のインスタンスには速やかな対応が必要です。利用可能な経路を主張する前に、適用済みの修正と認証要件を検証してください。API error が返っても、ファイル書き込みが失敗した証拠にはなりません。

## Gitea repository-description XSS and privileged viewers

Gitea 1.22.0 では、repository description に stored JavaScript を埋め込むことができました ([CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh))。1.22.1 で修正されています。description を編集できるユーザーは、より権限の高いユーザーが repository を閲覧して悪意のあるリンクを有効化した場合、そのブラウザーセッションに影響を与える可能性があります。そのブラウザー identity を通じて、非公開の repository コンテンツやその他のアプリケーションデータが漏えいすることがあります。これとは別に、ローカルで privilege escalation するには、そのコンテンツを通じて到達可能な credential または権限が必要です。たとえば、再利用された administrator password などです。Gitea プロセスの所有者だけでは、root への影響を示す根拠になりません。この連鎖を主張する前に、導入済みのバージョン、description の編集権限、閲覧者のワークフロー、実際のブラウザー操作を確認してください。

## Cobbler provisioning API

Cobbler の管理サービスは XML-RPC API を公開しており、通常は port `25151` で待ち受けます。影響を評価する前に、listener と `cobblerd` プロセスの所有者を確認してください。loopback のみで待ち受ける API にも、ホスト上のユーザーはアクセスできます。`/etc/cobbler/modules.conf` にある認証・認可モジュール、`/etc/cobbler/settings` または `/etc/cobbler/settings.yaml` にあるサービス設定、`/etc/cobbler/users.conf`、`/etc/cobbler/users.digest`、`/var/lib/cobbler/web.ss` の権限を確認してください。digest および shared-secret ファイルには credential 情報が含まれるため、デフォルトでは内容を表示せず、読み取り可能かどうかを記録してください。

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** は、Cobbler 3.0.0〜3.2.2 および 3.3.0〜3.3.6 における XML-RPC 認証 bypass です。共有 secret の読み取りエラーで予測可能な値 `-1` が返され、API はこれを password として受け入れていました。対応する修正版は 3.2.3 および 3.3.7 です。パッケージのバージョンは手掛かりにすぎません。脆弱性を報告する前に、実際に配置されているコードとバックポートされた修正の有無を確認してください。

認証済み API session は、`cobblerd` が root で実行されている場合、特権実行経路になり得ます。影響を受ける実装では、`background_import` がユーザー制御の `rsync_flags` を shell command に渡し、ユーザー制御の Cheetah autoinstall template のレンダリング時に Python を評価できます。どちらの経路をテストする場合も、API の権限とインストール済みバージョンを事前に確認してください。管理 API へのアクセスを制限し、認証 bypass にパッチを適用し、設定ファイルと credential ファイルをサービス管理者だけが読み取れるようにしてください。

## Motion および motionEye の設定

`/etc/motioneye/motioneye.conf` で `conf_path` を確認し、そのディレクトリにある `motion.conf` と少数の `camera-*.conf` ファイルを調べてください。読み取り可能な `# @admin_password` hash が存在するかどうかを、値を表示せずに報告してください。[古い motionEye リリースでは、これらのファイルに広範な読み取り権限が設定されていました](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67)。修正は 0.44.0 に含まれています。Motion の `webcontrol_port`、`webcontrol_parms`、`webcontrol_auth_method`、`webcontrol_localhost` の各設定を合わせて確認してください。認証が無効で高度な制御（`2` または `3`）が有効になっていると、loopback listener を含め、ローカルユーザーに強力な操作を許す可能性があります。[Motion のドキュメントで値とデフォルトを確認できます](https://motion-project.github.io/motion_config.html)。

0.43.1b5 より前の motionEye では、admin session を利用して camera のファイル名設定を変更すると、Motion による処理時に command execution が可能でした（[CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)）。権限昇格を主張する前に、実行中のバージョン、service identity、利用可能な認証経路、および camera が設定されているかを確認してください。設定だけでは、サービスが実行中または特権を持つことの証明にはなりません。

サービス名やインストール済みパッケージは、手掛かりにすぎません。権限境界を見極めるには、到達可能な入力、プロセスの identity、書き込み可能な設定、および最終的に制御される command やファイルを組み合わせて評価する必要があります。

## ローカル AWS emulator と保存された credential

ホストユーザーは、container 内で動作する AWS 互換 emulator に、公開された loopback endpoint 経由でアクセスできる場合があります。[Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) や [KMS](https://docs.localstack.cloud/aws/services/kms/) へのアクセスを評価する前に、稼働中の listener、client が選択する endpoint と account、emulator にインストールされている authorization 設定を照合してください。LocalStack では、[IAM policy enforcement は独立した設定です](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/)。credential ファイル、IAM policy、または listener だけから、実効 API 権限を推定しないでください。インストール済みリリースと設定での動作を確認してください。

保存された secret がローカルでの権限昇格に役立つのは、現在の API identity がそれを取得でき、かつ別のより高い権限を持つ account が復元された credential を受け入れる場合に限られます。暗号化されたローカル blob の場合も、ファイルの読み取り権限、対応する利用可能な KMS key と algorithm、実効的な decrypt 権限が必要です。[非対称 KMS key](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html) では、decrypt request に blob の暗号化に使用した algorithm を指定する必要があります。通常の列挙では、ホストの自動 inventory をプロセス、listener、設定パス、ファイル権限の証拠にとどめてください。secret の値や復号された平文を要求または表示しないでください。
{{#include ../../banners/hacktricks-training.md}}
