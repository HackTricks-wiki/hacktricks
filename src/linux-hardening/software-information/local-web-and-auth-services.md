# ローカル Web および認証サービス

{{#include ../../banners/hacktricks-training.md}}

Linux shell からは、プロセス引数、リスナー、unit ファイル、設定、ログ、ローカル専用インターフェースなど、ホスト側から Web サービスや認証サービスを確認できます。この情報を使って、アクセス可能なサービスと、実際に使用されているアカウントやファイルを結び付けます。

## ローカルの Web スタックを把握する

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

仮想ホスト名、ドキュメントルート、プロキシルート、アップロードディレクトリ、PHPの実行設定、認証情報を含む設定ファイルを調査します。ループバックで待ち受けているサービスが、プロキシやSSHトンネル経由で到達可能な場合があります。ローカルリスナーに対して名前付き仮想ホストをテストするには、意図した`Host`ヘッダーを送信するか、正しいアドレスとポートを指定して`curl --resolve`を使います。仮想ホストの列挙によって、デフォルトの応答には含まれない名前が見つかることもあります。Apacheで`.htaccess`による上書きが許可されているか、また、書き込み可能なアップロードディレクトリをコード実行とみなす前に、そのパスでPHPを実行できるかを確認します。デプロイ済みのJavaScript source mapから、ソースパスやクライアント側の秘密情報が明らかになることがあります。回収した値は手掛かりとして扱い、実際にどの権限で使えるかを検証します。Web固有の確認については、[Apache](../../network-services-pentesting/pentesting-web/apache.md)および[Nginx](../../network-services-pentesting/pentesting-web/nginx.md)を参照してください。

[mpm-itk](https://mpm-itk.sesse.net/)を使うApacheでは、有効な`AssignUserID`によって、仮想ホストを別のユーザーおよびグループとして実行できます。低権限アカウントがそのホストの`DocumentRoot`にスクリプトを書き込める場合、到達可能なルートが実際に割り当てられたIDでそのスクリプトを実行するかを確認します。モジュールが読み込まれていること、仮想ホストの有効な設定（式によるID上書きを含む）、ディレクトリへの書き込み権限と検索権限、スクリプトハンドラー、リスナーへのアクセスを確認してください。強調表示されたディレクティブや書き込み可能なディレクトリだけでは、ユーザーをまたいだ実行の証明にはなりません。

Webサーバーで公開されているホームディレクトリからは、実際の`.ssh`ディレクトリが非公開でも、SSH認証情報ファイルのバックアップアーカイブが漏れることがあります。たとえば、[Nostromoの`homedirs_public`設定](https://www.nazgul.ch/dev/nostromo_man.html)は、ユーザーのホームディレクトリから配信するサブディレクトリを指定します。パスだけでアーカイブが見つかった場合は手掛かりにとどめ、サーバーの有効なマッピング、ローカルでの読み取り可否またはHTTP認可、アーカイブの内容、秘密鍵のパスフレーズ、対応するアカウントが実際にその鍵を受け付けるかを検証します。通常のホスト列挙では、アーカイブを展開したり鍵の内容を出力したりしないでください。

高権限のローカルWebアプリのバックアップを読み取れる場合、稼働中のソースにアクセスできなくても、認証やファイル読み取りのロジックが明らかになることがあります。バックアップに依存する前に、デプロイ済みのサービスと比較してください。特に、呼び出し側が制御するテキストの後ろに秘密情報とロールフラグを付けて暗号化してCookieを作成する仕組みは、アプリが決定論的なECBブロックを使い、選択したテキストに対して新しいCookieを返し、後で復号した値をエスケープされていない区切り文字で分割する場合、精査が必要です。[NISTはECBの独立した再現可能なブロックマッピングについて説明しています](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)。この性質は選択入力の比較に利用できる場合がありますが、それだけで高いロールを取得できるわけではありません。稼働中のルート、セッションの前提条件、正確なパーサーおよびデータフロー、サービスの実行ID、別個の特権操作またはファイル読み取り経路を確認してください。受動的なインベントリでは、アーカイブの内容を読んだり認証プローブを送信したりせず、バックアップのメタデータとリスナーの所有者を報告してください。

同じソースレビューの手法は、カスタムのSSHバックエンドインターフェースなど、特権を持つ**非HTTP**のループバックサービスにも適用できます。アクセス可能なソースバックアップに、呼び出し側が選択したファイルパスを受け付けるコマンドが記載されている場合は、認証ゲート、そのパスの解決方法、解決後のファイルが意図したディレクトリ配下にあることを確認してから開くかを調べます。Goの[`filepath.Join`](https://pkg.go.dev/path/filepath#Join)はパスを正規化しますが、そのパスが指定ディレクトリ内に収まることは保証しません。バックアップが実行中のビルドと一致すること、リスナーに到達できること、低権限アカウントがそのコマンドを利用できること、プロセスが対象を読み取れることを確認してください。読み取り可能なSSH鍵を所持していることは、別個のログインポリシーに関する問題です。自動出力には、アーカイブの内容や鍵を展開せず、ソースアーカイブのパスとサービスの所有者を報告してください。

TCPループバックで待ち受けるPHP-FPMプールには、Webサイトに認証があっても、別のローカルアカウントからアクセスできる場合があります。[PHPは、FastCGIに接続できるクライアントが`auto_prepend_file`など、リクエスト設定を制御できると警告しています](https://www.php.net/manual/en/install.fpm.php)。プールの`listen`および`listen.allowed_clients`の設定を、稼働中のリスナー、ワーカーのUID、既存のスクリプトパス、`security.limit_extensions`や`php_admin_value`による制限と照らして確認します。プールの設定ファイルには`env[...]`ディレクティブ内に認証情報が含まれることがあるため、自動インベントリでは内容ではなくパスを報告してください。設定ファイルやポートが存在するだけでは、ユーザーをまたいだ実行経路の証明にはなりません。プロトコルの詳細は[FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md)を参照してください。

特権を持つローカルAPIでは、コード実行だけでなく認可も追跡します。低権限アカウントが変更できるデータベースロールによってAPIルートが利用可能になる場合でも、その先の境界はルートの実装によって決まります。たとえば、リクエストのJSONをJavaScriptオブジェクトにマージしてから[`child_process.exec`](https://nodejs.org/api/child_process.html)を呼び出す処理は、[prototype pollutionから実行に至るデータフロー](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)の観点で調査する必要があります。実際のマージライブラリとバージョン、入力検証、到達可能なルート、プロセスの実行ID、子プロセスのオプションを確認してください。root所有のNodeリスナーや脆弱な依存関係の名前だけでは、手掛かりにすぎません。

ファイルベースのCMSでは、従来の`.php`設定ファイル以外に、管理者パスワードの検証子が保存されていることがあります。たとえば、サイトの`data/database.js`や`data/settings/pass.php`などです。手動で確認する前にファイルの所有者と読み取り権限を調べ、ハッシュを自動共有出力に含めないでください。復元可能なアプリケーションパスワードは、Unixアカウントとは別の権限境界です。再利用されていると主張する場合は、対象アカウントと許可された認証方式に対して検証してください。

アプリケーションの認証コントローラーには、設定ファイルではなくソースコードにログインパスワードが直接記述されていることもあります。低権限ユーザーがデプロイ済みのコントローラーを読める場合は、認証比較処理をローカルで確認し、その値を共有列挙出力に含めないでください。該当コードパスが有効であること、パスワードがアプリケーションで有効であること、さらに高権限のUnixアカウントが同じパスワードを実際に受け付けることを確認してから、ローカル権限昇格を主張してください。コントローラーのファイル名だけでは、確認の手掛かりにすぎません。

Dolibarrは、`dolibarr_main_db_pass`を含むデータベース接続設定を`htdocs/conf/conf.php`に保存します（[設定リファレンス](https://wiki.dolibarr.org/index.php/Configuration_file)）。読み取り可能なファイルは認証情報の手掛かりです。別途検証されたアカウントパスワードの再利用や、ほかのデータベース権限がなければ、ローカル権限昇格にはなりません。まず権限を確認し、自動出力に値を表示しないでください。

GitLab Linux packageの設定ファイルは通常`/etc/gitlab/gitlab.rb`ですが、デプロイによっては読み取り可能なコピーが別の場所に残っていることがあります。[GitLabの説明](https://docs.gitlab.com/omnibus/settings/smtp/)によると、このファイルには`gitlab_rails['smtp_password']`が含まれる場合があります。ただし、暗号化されたSMTP設定では、パスワードが平文ファイルの外部に保存されることがあります。読み取り可能な設定は認証情報の手掛かりとして扱い、有効な設定であること、認証情報が現在も有効であること、特定の高権限アカウントが実際にその認証情報を受け付けることを確認してから、パスワードの再利用を主張してください。別途、[GitLabは`gitlab-ctl reconfigure`中にrootとして`gitlab.rb`をRubyコードとして実行します](https://docs.gitlab.com/omnibus/settings/configuration/)。書き込み可能な有効ファイルや読み込み先の`from_file`が実行上の問題になるには、実際に特権で再構成を行う経路が必要です。設定のプレビューで認証情報が表示される場合があるため、その出力は機密情報として扱い、代わりにパスと権限を共有してください。

Self-hosted Mattermostでは、`SqlSettings.DataSource`が`/opt/mattermost/config/config.json`に保存されていることがあります。[Mattermostの説明](https://docs.mattermost.com/deployment-guide/server/troubleshooting)には、通常のパスと、稼働中の設定をデータベースに保存するデプロイの両方が記載されています。読み取り可能なファイルからアプリケーションのデータベース認証情報が明らかになることはありますが、それだけでデータベースやUnixのrootへのアクセスが確立するわけではありません。有効な設定ソース、データベースロールの実際の権限、別途回収したアプリケーションパスワードの有無、そのパスワードが特定の高権限Unixアカウントで使えるかを確認してください。パスワードハッシュの形式はMattermostのバージョンによって変わる場合があります。列挙時には、接続文字列を表示したりデータベースに問い合わせたりせず、設定ファイルのパスとアクセスメタデータを記録してください。

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

仮想ホストの結果は、デフォルトのレスポンスサイズまたは別の安定した基準値と照合し、推測した名前がすべて有効に見えないようにします。source map は、実際にデプロイされているか、別の方法で読み取り可能な場合にのみ役立ちます。

Reverse proxy によって、アプリケーションが信頼するクライアントヘッダーが変わることがあります。`X-Forwarded-For`、`X-Forwarded-Host` などのヘッダーが呼び出し元のIDを確立すると決めつける前に、直接リクエストと proxy 経由のリクエストを比較してください。proxy とアプリケーションの設定をあわせて確認してください。

PHP が `$_SERVER['HTTP_X_FORWARDED_FOR']` を [`system()`](https://www.php.net/manual/en/function.system.php) に渡す文字列にコピーしている場合、到達可能なリクエスト経路で呼び出し元が指定したヘッダーを渡せるか、またシェルのメタ文字がその文字列に変更されず届くかを確認してください。先頭に `sudo iptables` を含むコマンドであっても、後続のシェル区切りコマンドが root で実行されるわけではありません。それらは、別途有効な sudo ルールで権限昇格が許可されていない限り、web worker として実行されます。root への経路があると主張する前に、worker のID、正確な `sudo -l` の許可内容と認証要件、コマンドの引数境界を確認してください。通常のホスト列挙では、注入プローブを送信せずにソースとポリシーを調査してください。

## Web foothold 後の特権 loopback API

web プロセスの shell は、リスナーが `127.0.0.1` にバインドされていても、ローカル HTTP サービスを呼び出せます。報告された脆弱な Control Web Panel のビルドでは、アカウントダッシュボードはホスティングユーザーとして実行されますが、`https://127.0.0.1:2302` のユーザーAPIは root として実行されます。その `/v1/restoredatabase/` POST route はアクセストークンのチェックを省略し、`file` フィールドを `shell_exec('mysql ... < ' . $file)` に渡します。そのため、ホスティングユーザーの foothold から `file` にシェル区切り文字を含めると、root として実行されます。route のアクセス制御と、API プロセスの実効IDの両方を確認してください。loopback へのバインドだけでは認証になりません。この foothold を得る方法の一例は、[PHP execution after redirect](../../pentesting-web/login-bypass/#php-execution-after-redirect) を参照してください。報告された脆弱性は CWP 1.29 で完全に修正されました。<sup>[[1]](#references)</sup>

```bash
curl -sk 'https://127.0.0.1:2302/v1/restoredatabase/' \
  --data-urlencode 'file=/dev/null ; id > /tmp/root-proof ; echo'
```

同じ API には、別個の認証ゲートの脆弱性もあります。`access_token()` は、渡された token を `WHERE authorization_code='$access_token' AND client_id='$user'` に補間します。期待される列を持ち、将来の有効期限を設定した `UNION` 行によって token チェックを通過し、元の client-ID 条件をコメントアウトできます。これにより、`user` の値を root 所有の `passwd` shell コマンドにそのまま追加する `/v1/newpass/` などの保護されたルートが利用可能になります。token injection は認証ゲートを回避しますが、コマンド実行には依然として二つ目の sink が必要です。詳細は[SQL injection authentication bypass](../../pentesting-web/login-bypass/#sql-injection-authentication-bypass)を参照してください。<sup>[[1]](#references)</sup>

開示された6列のゲートでは、注入した token に将来の有効期限を設定し、残りの条件式を無効化できます。列の構成はそのビルドに固有です。<sup>[[1]](#references)</sup>

```sql
' UNION SELECT 'a','x','c','d','2099-01-01 00:00:00','f' -- -
```

別個の tokenless `/v1/user_panel_dashboard/` route は、`user` を `oauth_clients` の検索に補間します。これは API の MySQL-root 接続を使った盲目的なデータベース読み取りであり、root OS execution ではありません。MySQL server は `mysql` OS user として実行されています。検索対象の table が空の場合は、[constant derived-table timing probe](../../pentesting-web/sql-injection/#exploiting-time-based-sqli) を使うことで、行が存在しないために delay が失われるのを避けられます。<sup>[[1]](#references)</sup>

## アクセスログ内のログイン認証情報

アプリケーションが `GET` でログインフォームを送信すると、username と password が request URI の query parameters になることがあります。`POST` request にも query string を含められます。`POST` を使っても、無関係なフォームフィールドに入力した password を含め、URI に誤って配置された secret は隠されません。[Apache の一般的な access-log request line](https://httpd.apache.org/docs/2.4/logs.html) は、設定された format が `%r` を使う場合、query string を含む method と URI を記録します。そのため、一部の Linux system で `adm` group を通じてログを読み取れる account が、認証情報につながる手がかりを見つける可能性があります。実際の log format と permissions を確認し、その値が secret であること、その account が受け付けること、そして privilege boundary を越えることを検証してください。request body がログに記録されたと決めつけたり、候補値を共有出力にコピーしたりしないでください。

読み取り可能な access logs のみを調査し、認証情報の値を共有コマンド出力に含めないでください。長い request line には referrer や user agent が含まれることもあるため、短い行だけを抽出する filter では、目的の request が隠れる場合があります。Apache、httpd、Nginx の一般的な access-log の場所は `/var/log/apache2/access.log`、`/var/log/httpd/access_log`、`/var/log/nginx/access.log` です。ローテーションされた logs に古い認証情報が含まれている場合があります。[LFI によるログファイルへのアクセス](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)も、同じデータにたどり着く関連ルートです。

アプリケーションの認証 logs には、ログイン失敗時に **username** field に誤って入力された password が記録されることもあります。まず、その log が読み取り可能で、形式上、送信された username が記録されることを確認してください。該当箇所の小さな範囲だけをローカルで調べ、候補の認証情報を共有出力にコピーしないでください。password のように見える username は手がかりであり、有効な password やより高い privilege の証拠ではありません。移行を主張する前に、想定される account と、特定の service または Unix account における認証情報の再利用を検証してください。

別の identity で実行される scheduled client が認証情報を送信する endpoint を扱う場合、書き込み可能な web login handler は個別に確認する必要があります。**active** handler への書き込み権限、client の実際の schedule と request path、送信される認証情報の所有者、さらにその application password がより高い privilege を持つ operating-system account でも個別に有効かどうかを確認してください。書き込み可能な page や定期的に実行される process だけでは、その移行が成立するとは限りません。受動的な inventory では、handler を変更したり password を収集したりせずに、path permissions と job metadata を報告してください。

Suricata の EVE JSON logs には、FTP event logging が有効な場合、FTP の `USER` および `PASS` commands とその `command_data` が記録されることもあります。関連する範囲をローカルで少しだけ確認する前に、ローテーションまたは圧縮されたファイルも含め、`/var/log/suricata/eve*.json*` が読み取り可能か確認してください。EVE file が読み取り可能であることは、あくまで手がかりです。FTP events がログに記録されたこと、データに利用可能な認証情報が含まれること、そして privilege boundary を越えることを確認してください。共有の enumeration 出力に `command_data` を表示しないでください。Suricata のドキュメントには、[FTP event fields](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html) と [EVE rotation and filename variants](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html) が記載されています。

## 生成された Apache 設定と pipe 経由の logs

[remco](https://github.com/HeavyHorst/remco) は key/value backend を監視し、template を Apache configuration file にレンダリングして、reload command を実行できます。実行中の remco process の identity、設定された template の source と destination、監視対象の key prefixes、そして backend value が `ServerName` などの Apache directive に直接挿入されるかを確認してください。ローカルの backend listener があるだけでは、現在の user が監視対象の key に書き込めることの証明にはなりません。escalation を主張する前に、backend の authentication と permissions を確認してください。

書き込み可能な backend value にエスケープされていない改行があると、意図された directive value が複数の Apache directives に変わることがあります。[Apache piped logs](https://httpd.apache.org/docs/2.4/logs.html#piped) は特に注意が必要です。`|` command を指定した `CustomLog` または `ErrorLog` は、親の httpd identity、多くの場合 root として helper を起動します。`|$` を指定すると Apache は shell を使います。enumeration 中に backend data を変更したり service を再起動したりせず、生成された configuration とその reload path を確認してください。引数に secrets が含まれる可能性があるため、pipe 経由で実行される command 全体は非公開にしてください。

## Authentication と service identities

Monit の control file は通常 `~/.monitrc` または `/etc/monitrc` ですが、`monit -c` で別の path を指定できます。読み取り可能な file に、web interface 用の `set httpd` や `allow user:password` の entries が含まれていることがあります。多くの場合、local port 2812 で待ち受けています。内容を確認する前に file の owner と permissions をチェックし、password の値を共有の enumeration 出力に含めないでください。web credentials で使用できるのは、設定された Monit role の機能に限られます。read-only users は control actions を実行できません。別の Unix account への escalation を主張するには、password の再利用、または認証済み role が実際に実行できる privileged Monit action を確認する必要があります。[Monit control-file and authentication documentation](https://www.mmonit.com/monit/documentation/monit.html)を参照してください。

Webmin では、`/etc/webmin/miniserv.conf` に server settings が記載され、`/etc/webmin/webmin.acl` に各 user がアクセスできる modules が記録されます。[Webmin の module-grant boundary に関するドキュメント](https://webmin.com/docs/development/creating-modules/)を参照してください。Unix password や読み取り可能な ACL file があっても、それだけで Webmin session が得られるわけではありません。実際の authentication mapping、到達可能な listener、認証済み account、Package Updates module に対する有効な permission、インストール済みコードまたは vendor fix、Webmin process の identity を確認してください。1.910 までの影響を受ける build では、[CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840) により、その module permission を持つ account が update handler を介して commands を実行できました。受動的な enumeration では、credentials を表示したり update を試みたりせず、configuration paths と permissions を報告してください。

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) はサービスごとの認証を管理します。書き込み可能なポリシーまたはモジュールのパスを変更すると、ログイン動作を変えられる可能性があります。
- LDAP/SSSD の設定から、ディレクトリエンドポイント、bind identity、アクセスルールが判明することがあります。取得した bind password を使うと、現在の OS アカウントの範囲を超えて LDAP クエリを実行できる可能性があります。正確な bind identity とディレクトリ ACL をテストしてください。secret を調べる前にファイル権限を確認してください。[Linux Active Directory](../user-information/linux-active-directory.md) と [FreeIPA](freeipa-pentesting.md) では、ticket とディレクトリの利用方法を扱っています。
- Postfix の alias は、受信メールをローカルコマンドにパイプできます。低権限ユーザーが参照先の script を変更できる場合、メール配信によって、そのユーザーのコードが配信時の identity で実行される可能性があります。この経路を主張する前に、alias map と script の所有者を確認してください。[SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md) を参照してください。
- Jenkins やその他の CI サービスは、強い権限を持つローカルアカウントで job を実行する場合があります。Pipeline や plugin をテストする前に、サービスユーザー、書き込み可能な job/workspace のパス、ローカルの管理インターフェースを調べてください。また、**job が利用できる credentials** と、それらを使って認証できるアカウントも確認してください。[SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) を使う Pipeline は、Jenkins 自体がより低権限の Unix アカウントで動作していても、SSH credential のユーザーとしてホストにアクセスできます。ホストの privilege escalation を主張する前に、現在の Jenkins identity に `Job/Create`、`Job/Configure`、または Pipeline を変更できる別の実効的な手段があること、その job の scope 内で credential を利用できること、対象の SSH アカウントがその key を受け入れることを確認してください。credential の表示名や ID だけでは、これらの条件が満たされているとは言えません。Jenkins は、job の作成者や、多くの場合 job の設定者が、自身の scope 内で利用できる credentials を任意に使用できると警告しています。そのため、サービス UID と同様に、[credential scope](https://www.jenkins.io/doc/book/security/credentials/) と [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/) も重要です。共有する列挙結果に credential の値や private key を含めないでください。

## Gogs repository file writes

ローカルの Gogs サービスでは、`gogs web` プロセスの所有者を、実行ファイルのバージョンおよび `custom/conf/app.ini` と照合してください。設定から、サービス identity、repository root、listener address、registration が無効かどうかが判明する場合があります。loopback のみで待ち受けていても、ローカルユーザーからアクセス可能です。0.13.3 までの Gogs には、認証が必要な `PutContents` の symlink file-write の問題があります（[CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)）。repository に書き込めるユーザーは symlink を commit し、その後 API の書き込み先を経由させることができます。これによるファイルアクセス権限は Gogs プロセスの権限に従うため、root 所有のインスタンスは速やかに対処する必要があります。利用可能な経路があると主張する前に、修正が適用されていることと認証要件を確認してください。API エラーだけでは、ファイル書き込みが失敗した証拠にはなりません。

## Gitea repository-description XSS and privileged viewers

Gitea 1.22.0 では、repository description に保存された JavaScript が許可されていました（[CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)）。1.22.1 で修正されています。description を編集できるユーザーは、より高権限のユーザーが repository を閲覧して悪意あるリンクを有効化した場合、そのブラウザーセッションに影響を与えることができます。そのブラウザー identity により、非公開の repository の内容やその他のアプリケーションデータが露出する可能性があります。別途、ローカルでの権限昇格には、その内容を通じてアクセス可能な credential や権限（再利用された administrator password など）が必要です。Gitea プロセスの所有者であることだけでは、root への影響を示す根拠になりません。この連鎖を主張する前に、導入済みのバージョン、description の編集権限、閲覧者のワークフロー、実際のブラウザー操作を確認してください。

## Cobbler provisioning API

Cobbler の管理サービスは XML-RPC API を公開しており、一般的なポートは `25151` です。影響を評価する前に、listener と `cobblerd` プロセスの所有者を確認してください。loopback のみで待ち受ける API でも、ホスト上のユーザーからアクセスできる場合があります。`/etc/cobbler/modules.conf` の認証および認可モジュール、`/etc/cobbler/settings` または `/etc/cobbler/settings.yaml` のサービス設定、ならびに `/etc/cobbler/users.conf`、`/etc/cobbler/users.digest`、`/var/lib/cobbler/web.ss` の権限を確認してください。digest と共有 secret のファイルには credential の情報が含まれるため、デフォルトでは内容を表示せず、読み取り可能かどうかを記録してください。

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** は、Cobbler 3.0.0〜3.2.2 および 3.3.0〜3.3.6 における XML-RPC 認証バイパスです。共有シークレットの読み取りエラーにより予測可能な値 `-1` が返され、API はこれをパスワードとして受け入れていました。対応する修正バージョンは 3.2.3 および 3.3.7 です。パッケージのバージョンは手掛かりにすぎません。脆弱性を報告する前に、デプロイされたコードとバックポート済みの修正の有無を確認してください。

認証済みの API セッションは、`cobblerd` が root として実行されている場合、特権実行への経路になり得ます。影響を受ける実装では、`background_import` がユーザー制御の `rsync_flags` をシェルコマンドに渡し、ユーザー制御の Cheetah autoinstall template をレンダリングすると Python が評価される可能性があります。いずれかの経路をテストする前に、API の権限とインストール済みバージョンを確認してください。管理 API へのアクセスを制限し、認証バイパスにパッチを適用し、設定ファイルと認証情報ファイルはサービス管理者のみが読み取れるようにしてください。

## Motion と motionEye の設定

`/etc/motioneye/motioneye.conf` の `conf_path` を確認し、そのディレクトリ内の `motion.conf` と少数の `camera-*.conf` ファイルを調べてください。読み取り可能な `# @admin_password` ハッシュが存在するかを、値を表示せずに報告してください。[古い motionEye リリースでは、これらのファイルに広範な読み取り権限が設定されていました](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67)。修正は 0.44.0 に含まれています。Motion の `webcontrol_port`、`webcontrol_parms`、`webcontrol_auth_method`、`webcontrol_localhost` の設定を併せて確認してください。認証が無効で、高度な制御（`2` または `3`）が有効な場合、ループバックリスナー上であっても、ローカルユーザーに強力な操作を許してしまう可能性があります。[Motion のドキュメントで値とデフォルトを確認できます](https://motion-project.github.io/motion_config.html)。

0.43.1b5 より前の motionEye では、Motion がカメラのファイル名設定を処理する際に、admin セッションからコマンド実行に至る可能性がありました（[CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)）。権限昇格を主張する前に、実行中のバージョン、サービスの実行ユーザー、利用可能な認証経路、カメラが設定されているかを確認してください。設定だけでは、サービスが実行中であることや特権を持つことの証明にはなりません。

サービス名やインストール済みパッケージは手掛かりにすぎません。権限境界を判断するには、到達可能な入力、プロセスの実行ユーザー、書き込み可能な設定、そして最終的に制御されるコマンドまたはファイルを併せて確認する必要があります。

## ローカル AWS エミュレーターと保存された認証情報

ホストユーザーは、コンテナ内で実行されている AWS 互換エミュレーターに、公開されたループバックエンドポイント経由でアクセスできる場合があります。[Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) または [KMS](https://docs.localstack.cloud/aws/services/kms/) へのアクセスを評価する前に、稼働中のリスナー、クライアントが選択したエンドポイントとアカウント、エミュレーターにインストールされた認可設定を照合してください。LocalStack では、[IAM ポリシーの適用は独立した設定です](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/)。認証情報ファイル、IAM ポリシー、またはリスナーだけから、有効な API 権限を推測しないでください。インストール済みのリリースと設定で実際の動作を確認してください。

保存されたシークレットがローカルでの権限昇格に役立つのは、現在の API ID にそのシークレットを取得する権限があり、かつ別の高権限アカウントが復元された認証情報を受け入れる場合に限られます。暗号化されたローカルデータにも、ファイルの読み取りアクセス、対応する使用可能な KMS キーとアルゴリズム、および有効な復号権限が必要です。[非対称 KMS キー](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)の場合、復号リクエストでデータの暗号化に使用したアルゴリズムを指定する必要があります。通常の列挙では、ホストの自動インベントリをプロセス、リスナー、設定パス、ファイル権限の証拠に限定してください。シークレットの値や復号された平文を要求または表示しないでください。

## References

- [1] [VulnCheck - CWP2Shell：決して「No」と言わないログインページ](https://www.vulncheck.com/blog/control-web-panel-pre-auth-module-dispatch-rce)
