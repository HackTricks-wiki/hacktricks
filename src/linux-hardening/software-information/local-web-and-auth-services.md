# ローカルのWebサービスと認証サービス

{{#include ../../banners/hacktricks-training.md}}

Linux shellでは、プロセスの引数、リスナー、ユニットファイル、設定、ログ、ローカル専用インターフェースを通じて、Webサービスや認証サービスをホスト側から確認できます。この視点を使って、到達可能なサービスと、実際にそのサービスが使用するアカウントやファイルを結び付けます。

## ローカルのWebスタックを把握する

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

仮想ホスト名、ドキュメントルート、プロキシルート、アップロードディレクトリ、PHPの実行設定、認証情報を含む設定ファイルを調べます。ループバックリスナーがプロキシやSSHトンネル経由で到達可能な場合があります。ローカルリスナーに対して名前付き仮想ホストをテストするには、意図した`Host`ヘッダーを送信するか、正しいアドレスとポートを指定して`curl --resolve`を使用します。仮想ホストの列挙によって、デフォルト応答にはない名前が見つかることもあります。書き込み可能なアップロードディレクトリをコード実行と見なす前に、Apacheで`.htaccess`による上書きが許可されているか、アップロード先でPHPを実行できるかを確認します。デプロイ済みのJavaScriptソースマップから、ソースパスやクライアント側のシークレットが漏れる場合があります。見つかった値は手掛かりとして扱い、実際の権限を検証してください。Web固有の確認項目については、[Apache](../../network-services-pentesting/pentesting-web/apache.md)と[Nginx](../../network-services-pentesting/pentesting-web/nginx.md)を参照してください。

Apacheで[mpm-itk](https://mpm-itk.sesse.net/)を使用している場合、有効な`AssignUserID`により、仮想ホストを別のユーザーおよびグループとして実行できます。低い権限のアカウントがそのホストの`DocumentRoot`にスクリプトを書き込める場合、到達可能なルートが実際に割り当てられたIDでそのスクリプトを実行するかを確認します。モジュールが読み込まれていること、実効的な仮想ホスト設定（式によるIDの上書きを含む）、ディレクトリの書き込み権限と検索権限、スクリプトハンドラー、リスナーへのアクセスを確認してください。強調表示されたディレクティブや書き込み可能なディレクトリだけでは、ユーザーをまたいだ実行が可能だとは証明できません。

Webサーバー経由で公開されているホームディレクトリから、実際の`.ssh`ディレクトリが非公開でも、SSH認証情報ファイルのバックアップアーカイブが見つかる場合があります。たとえば、[Nostromoの`homedirs_public`設定](https://www.nazgul.ch/dev/nostromo_man.html)は、ユーザーのホームディレクトリ内で配信するサブディレクトリを指定します。パスだけを根拠に見つかったアーカイブは手掛かりです。サーバーの実効的なマッピング、ローカルでの読み取り可否またはHTTP認可、アーカイブの内容、秘密鍵のパスフレーズ、対応するアカウントが実際にその鍵を受け入れるかを確認してください。通常のホスト列挙では、アーカイブを展開したり鍵の内容を出力したりしないでください。

権限の高いローカルWebアプリの読み取り可能なバックアップから、稼働中のソースにアクセスできなくても、認証やファイル読み取りのロジックが判明する場合があります。バックアップに依存する前に、デプロイ済みサービスと照合してください。特に、アプリが呼び出し側の制御するテキストの後にシークレットとロールフラグを連結して暗号化し、決定論的なECBブロックを使用し、指定したテキストに対する新しいCookieを返し、後で復号値をエスケープされていない区切り文字で分割する場合、そのCookieの仕組みは精査が必要です。[NISTはECBにおける独立かつ再現可能なブロック変換について説明しています](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)。この性質は選択入力による比較に利用できる場合がありますが、それだけで上位ロールが得られるわけではありません。稼働中のルート、セッションの前提条件、正確なパーサーとデータフロー、サービスの実行ID、別個の特権操作またはファイル読み取り経路を確認してください。受動的なインベントリでは、アーカイブの内容を読んだり認証プローブを送信したりせず、バックアップのメタデータとリスナーの所有者を報告してください。

同じソースレビューの手法は、カスタムのSSHバックエンドインターフェースなど、特権を持つ**非HTTP**のループバックサービスにも適用できます。アクセス可能なソースバックアップに、呼び出し側が選択したファイルパスを受け取るコマンドが含まれている場合、認証チェック、そのパスの解決方法、開く前に解決後のファイルが意図したディレクトリ内にあると確認しているかを調べてください。Goの[`filepath.Join`](https://pkg.go.dev/path/filepath#Join)はパスを正規化しますが、そのパスが指定範囲内にあることは強制しません。バックアップが稼働中のビルドと一致すること、リスナーに到達できること、低い権限のアカウントがコマンドを使用できること、プロセスが対象を読み取れることを確認してください。読み取り可能なSSH鍵を持っていることは、別途ログインポリシーの問題です。自動出力には、アーカイブの内容や鍵を展開せず、ソースアーカイブのパスとサービスの所有者を報告してください。

TCPループバックで待ち受けるPHP-FPMプールには、Webサイトに認証があっても、別のローカルアカウントから到達できる場合があります。[PHPは、FastCGIに接続できるクライアントが`auto_prepend_file`を含むリクエスト設定を制御できると警告しています](https://www.php.net/manual/en/install.fpm.php)。プールの`listen`と`listen.allowed_clients`の設定を、稼働中のリスナー、ワーカーのUID、既存のスクリプトパス、および`security.limit_extensions`や`php_admin_value`による制限と併せて確認してください。プールの設定ファイルには`env[...]`ディレクティブに認証情報が含まれる場合があるため、自動インベントリでは内容ではなくパスを報告してください。設定ファイルやポートが存在するだけでは、ユーザーをまたいだ実行経路があるとは証明できません。プロトコルの詳細は[FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md)を参照してください。

特権を持つローカルAPIでは、コード実行だけでなく認可も追跡してください。低い権限のアカウントが変更できるデータベースロールによってAPIルートが利用可能になる場合でも、次の境界はルートの実装によって決まります。たとえば、リクエストのJSONをJavaScriptオブジェクトにマージしてから[`child_process.exec`](https://nodejs.org/api/child_process.html)を呼び出す処理は、[prototype-pollution-to-execution dataflow](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)の観点で精査が必要です。実際のマージライブラリとバージョン、入力検証、到達可能なルート、プロセスの実行ID、子プロセスのオプションを確認してください。root所有のNodeリスナーや脆弱な依存関係名だけでは、手掛かりにすぎません。

ファイルベースのCMSでは、従来の`.php`設定ファイル以外に、管理者パスワードの検証値が保存されている場合があります。例として、サイトの`data/database.js`や`data/settings/pass.php`があります。手動で調べる前にファイルの所有者と読み取り可否を確認し、ハッシュを自動化された共有出力に含めないでください。復元可能なアプリケーションパスワードは、Unixアカウントとは別の権限境界です。再利用が主張されている場合は、該当アカウントと許可された認証方式で検証してください。

アプリケーションの認証コントローラーには、設定ファイルではなくソースコードにログインパスワードが直書きされている場合もあります。低い権限のユーザーがデプロイ済みコントローラーを読み取れる場合は、認証時の比較処理をローカルで調べ、値を共有インベントリ出力に含めないでください。コードパスが有効であること、そのパスワードがアプリケーションで有効であること、さらに権限の高いUnixアカウントが同じパスワードを実際に受け入れることを確認してから、ローカル権限昇格と判断してください。コントローラーのファイル名だけなら、調査の手掛かりにすぎません。

Dolibarrは、データベース接続設定（`dolibarr_main_db_pass`を含む）を`htdocs/conf/conf.php`に保存します（[configuration reference](https://wiki.dolibarr.org/index.php/Configuration_file)）。読み取り可能なファイルは認証情報の手掛かりです。別途確認済みのアカウントパスワードの再利用、または別のデータベース権限がなければ、ローカル権限昇格にはつながりません。まずアクセス権を確認し、自動出力に値を表示しないでください。

GitLabのLinuxパッケージの設定ファイルは通常`/etc/gitlab/gitlab.rb`ですが、デプロイによっては読み取り可能なコピーが別の場所に残っている場合があります。[GitLabのドキュメント](https://docs.gitlab.com/omnibus/settings/smtp/)によると、このファイルには`gitlab_rails['smtp_password']`が含まれる場合があります。ただし、暗号化されたSMTP設定では、パスワードが平文ファイルの外部に保存されることがあります。読み取り可能な設定は認証情報の手掛かりとして扱い、パスワード再利用を主張する前に、有効な設定であること、認証情報が現在も有効であること、特定の権限の高いアカウントがそれを受け入れることを確認してください。また、[GitLabは`gitlab-ctl reconfigure`の実行中にrootとして`gitlab.rb`をRubyコードとして実行します](https://docs.gitlab.com/omnibus/settings/configuration/)。書き込み可能な有効ファイル、または読み込まれる`from_file`がコード実行につながるには、実際に特権で再設定が行われる経路が必要です。設定プレビューで認証情報が表示される場合があるため、出力を機密情報として扱い、代わりにパスとアクセス権を共有してください。

セルフホスト型のMattermostでは、`SqlSettings.DataSource`が`/opt/mattermost/config/config.json`に保存される場合があります。[Mattermostのドキュメント](https://docs.mattermost.com/deployment-guide/server/troubleshooting)には、通常のパスと、有効な設定をデータベースに保存するデプロイの両方が記載されています。読み取り可能なファイルからアプリケーションのデータベース認証情報が漏れる場合がありますが、それだけではデータベースへのアクセスもUnixのroot権限も確立されません。有効な設定の保存元、データベースロールの実際の権限、別途復元したアプリケーションパスワードの有無、そのパスワードが特定の権限の高いUnixアカウントで使えるかを確認してください。パスワードハッシュの形式はMattermostのバージョンによって変わる場合があります。列挙時には、接続文字列を出力したりデータベースを照会したりせず、設定ファイルのパスとアクセス情報を記録してください。

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

仮想ホストの結果は、デフォルト応答サイズまたは別の安定した基準と照合し、推測したすべての名前が有効に見える状態を避けます。source map は、実際にデプロイされているか、ほかの方法で読み取り可能な場合にのみ役立ちます。

Reverse proxy によって、アプリケーションが信頼するクライアントヘッダーが変わることがあります。`X-Forwarded-For`、`X-Forwarded-Host` などのヘッダーが呼び出し元の身元を確立すると決めつける前に、直接リクエストと proxied request を比較してください。proxy とアプリケーションの設定を併せて確認してください。

PHP が `$_SERVER['HTTP_X_FORWARDED_FOR']` を [`system()`](https://www.php.net/manual/en/function.system.php) に渡す文字列にコピーしている場合、到達可能なリクエスト経路で呼び出し元が指定したヘッダーを送れるか、また shell のメタ文字が変更されずにその文字列へ渡るかを確認してください。先頭に `sudo iptables` を埋め込んでも、後続の shell 区切りコマンドが root で実行されるわけではありません。別途有効な sudo ルールによる権限昇格がなければ、それらは web worker の権限で実行されます。root への経路を主張する前に、worker の実行ユーザー、正確な `sudo -l` の許可内容と認証要件、コマンドの引数境界を確認してください。通常のホスト列挙では、injection probe を送らずにソースとポリシーを調べてください。

## アクセスログ内のログイン認証情報

アプリケーションが `GET` でログインフォームを送信すると、ユーザー名とパスワードがリクエスト URI のクエリパラメーターになることがあります。`POST` リクエストにもクエリ文字列を含められます。`POST` を使っても、無関係なフォームフィールドに入力されたパスワードなど、誤って URI に含めた秘密情報は隠れません。[Apache の一般的なアクセスログのリクエスト行](https://httpd.apache.org/docs/2.4/logs.html)は、設定されたフォーマットで `%r` を使う場合、クエリ文字列を含むメソッドと URI を記録します。そのため、一部の Linux システムでの `adm` グループなど、これらのログを読み取れるアカウントから認証情報の手掛かりが見つかることがあります。実際のログ形式と権限を確認したうえで、その値が秘密情報であること、アカウントがその値を受け付けること、権限境界を越えることを検証してください。リクエスト本文が記録されていると決めつけず、候補値を共有出力にコピーしないでください。

読み取り可能なアクセスログだけを調べ、認証情報の値を共有コマンド出力に含めないでください。長いリクエスト行には Referer や User-Agent も含まれることがあるため、短い行だけを抽出するフィルターでは、調べたいリクエストが隠れる可能性があります。Apache、httpd、Nginx の一般的なアクセスログの場所は、`/var/log/apache2/access.log`、`/var/log/httpd/access_log`、`/var/log/nginx/access.log` です。ローテーションされたログに古い認証情報が含まれている場合もあります。[LFI によるログファイルへのアクセス](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)も、同じデータに到達する関連経路です。

アプリケーションの認証ログには、ログイン失敗時に**ユーザー名**フィールドへ誤って入力されたパスワードが記録されることもあります。まずログが読み取り可能であることと、その形式が送信されたユーザー名を記録することを確認してください。関連する小さな範囲だけをローカルで調べ、候補の認証情報を共有出力にコピーしないでください。パスワードらしいユーザー名は手掛かりにすぎず、有効なパスワードやより高い権限の証拠ではありません。遷移を主張する前に、想定されたアカウントと、対象のサービスまたは Unix アカウントでの認証情報の再利用を確認してください。

別の身元で実行されるスケジュール済みクライアントがエンドポイントに認証情報を送信する場合、書き込み可能な web ログインハンドラーは別途確認が必要です。有効なハンドラーへの書き込み権限、クライアントの実際のスケジュールとリクエスト経路、送信される認証情報の持ち主、そのアプリケーションパスワードがより高い権限を持つオペレーティングシステムアカウントでも個別に有効かどうかを確認してください。書き込み可能なページや定期実行されるプロセスだけでは、その遷移の証拠になりません。受動的なインベントリでは、ハンドラーを変更したりパスワードを収集したりせずに、パスの権限とジョブのメタデータを報告してください。

FTP イベントのログ記録が有効な場合、Suricata の EVE JSON ログには、FTP の `USER` および `PASS` コマンドとその `command_data` が記録されることもあります。関連する範囲だけをローカルで確認する前に、ローテーション済みまたは圧縮済みのファイルを含め、`/var/log/suricata/eve*.json*` が読み取り可能かを確認してください。読み取り可能な EVE ファイルは手掛かりにすぎません。FTP イベントが記録されていること、データに利用可能な認証情報が含まれること、権限境界を越えることを確認してください。共有列挙出力に `command_data` を表示しないでください。Suricata のドキュメントには、[FTP イベントフィールド](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)と[EVE のローテーションおよびファイル名の種類](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)が記載されています。

## 生成された Apache 設定とパイプログ

[remco](https://github.com/HeavyHorst/remco) は key/value backend を監視し、テンプレートを Apache 設定ファイルにレンダリングして、reload コマンドを実行できます。実行中の remco プロセスの実行ユーザー、設定されたテンプレートのソースと出力先、監視対象の key prefix、backend の値が `ServerName` などの Apache ディレクティブに直接挿入されるかを確認してください。ローカルの backend listener があるだけでは、現在のユーザーが監視対象の key を書き込める証拠にはなりません。権限昇格を主張する前に、backend の認証と権限を確認してください。

書き込み可能な backend 値にエスケープされていない改行が含まれると、1 つのディレクティブ値が複数の Apache ディレクティブとして解釈されることがあります。[Apache のパイプログ](https://httpd.apache.org/docs/2.4/logs.html#piped)は特に注意が必要です。コマンドに `|` を付けた `CustomLog` または `ErrorLog` は、親の httpd の実行ユーザー（多くの場合 root）で helper を起動します。`|$` を指定すると、Apache は shell を使います。列挙中に backend データを変更したり、サービスを再起動したりせずに、生成された設定とその reload 経路を確認してください。引数に秘密情報が含まれる可能性があるため、パイプコマンド全体は公開しないでください。

## 認証とサービスの実行ユーザー

Monit の制御ファイルは通常 `~/.monitrc` または `/etc/monitrc` ですが、`monit -c` で別のパスを指定できます。読み取り可能なファイルに、web インターフェース用の `set httpd` や `allow user:password` の項目が含まれていることがあります。ポート 2812 のローカルで待ち受ける構成が一般的です。内容を確認する前にファイルの所有者と権限を確認し、パスワードの値を共有列挙出力に含めないでください。web 認証情報で許可されるのは設定済みの Monit ロールの操作のみです。読み取り専用ユーザーは制御アクションを実行できません。Unix アカウントへの別の権限昇格を主張するには、パスワードの再利用、または認証済みのロールが実際に実行できる特権付き Monit アクションを確認する必要があります。[Monit の制御ファイルと認証に関するドキュメント](https://www.mmonit.com/monit/documentation/monit.html)を参照してください。

Webmin では、`/etc/webmin/miniserv.conf` にサーバー設定が記載され、`/etc/webmin/webmin.acl` にユーザーがアクセスできるモジュールが記録されます。[Webmin のドキュメントにはモジュール許可の境界が記載されています](https://webmin.com/docs/development/creating-modules/)。Unix パスワードや読み取り可能な ACL ファイルがあるだけでは、Webmin セッションを取得できません。実際の認証マッピング、到達可能な listener、認証済みアカウント、実効的な Package Updates モジュールの権限、インストール済みコードまたはベンダーの修正、Webmin プロセスの実行ユーザーを確認してください。1.910 以前の影響を受けるビルドでは、[CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840) により、そのモジュール権限を持つアカウントが更新ハンドラーを通じてコマンドを実行できました。受動的な列挙では、認証情報を表示したり更新を試みたりせず、設定ファイルのパスと権限を報告してください。

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) はサービス固有の認証を管理します。書き込み可能なポリシーやモジュールのパスを変更すると、ログイン動作を変えられる可能性があります。
- LDAP/SSSD の設定から、ディレクトリエンドポイント、バインドID、アクセスルールが判明することがあります。取得したバインドパスワードを使うと、現在の OS アカウントの権限を超えて LDAP クエリを実行できる場合があります。正確なバインドIDとディレクトリ ACL をテストしてください。秘密情報を調べる前にファイル権限を確認してください。[Linux Active Directory](../user-information/linux-active-directory.md) と [FreeIPA](freeipa-pentesting.md) では、チケットとディレクトリの利用方法を説明しています。
- Postfix のエイリアスは、受信メールをローカルコマンドにパイプできます。低権限ユーザーが参照先のスクリプトを変更できる場合、メールの配信によって、その配信IDの権限でコードを実行できる可能性があります。この経路を主張する前に、エイリアスマップとスクリプトの所有者を確認してください。[SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md) も参照してください。
- Jenkins などの CI サービスは、強力なローカルアカウントでジョブを実行する場合があります。パイプラインやプラグインをテストする前に、サービスユーザー、書き込み可能なジョブ/ワークスペースのパス、ローカル管理インターフェースを調べてください。また、**ジョブから利用できる認証情報**と、その認証情報で認証可能なアカウントも確認してください。[SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) を使用する Pipeline は、Jenkins 自体が低権限の Unix アカウントで実行されていても、SSH 認証情報のユーザーとしてホストにアクセスできます。ホストの権限昇格を主張する前に、現在の Jenkins ID が `Job/Create`、`Job/Configure`、または Pipeline を変更できる別の有効な経路を持つこと、そのジョブで認証情報を利用できること、対象の SSH アカウントがその鍵を受け入れることを確認してください。認証情報の表示名や ID だけでは、これらの条件が成立しているとは判断できません。Jenkins は、ジョブの作成者や、多くの場合ジョブの設定者が、スコープ内で利用可能な認証情報を任意に使用できると警告しています。そのため、[credential scope](https://www.jenkins.io/doc/book/security/credentials/) と [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/) はサービス UID と同じくらい重要です。認証情報の値や秘密鍵を、共有する列挙結果に含めないでください。

## Gogs リポジトリのファイル書き込み

ローカルの Gogs サービスでは、`gogs web` プロセスの所有者を、実行ファイルのバージョンおよび `custom/conf/app.ini` と照合してください。この設定から、サービスID、リポジトリのルート、待受アドレス、登録が無効になっているかどうかが判明することがあります。ループバックのみで待ち受けている場合でも、ローカルユーザーからアクセスできます。0.13.3 までの Gogs には、認証済みの `PutContents` におけるシンボリックリンク経由のファイル書き込み問題があります（[CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)）。リポジトリへの書き込み権限を持つユーザーは、シンボリックリンクをコミットし、その後 API の書き込み先をそのリンク経由にできます。結果として生じるファイルアクセスは Gogs プロセスの権限で行われるため、root 所有のインスタンスは速やかに対処する必要があります。利用可能な経路を主張する前に、修正が適用されていることと認証要件を確認してください。API エラーが返っても、ファイル書き込みに失敗したとは限りません。

## Gitea のリポジトリ説明欄における XSS と特権ユーザーの閲覧

Gitea 1.22.0 では、リポジトリの説明欄に保存型 JavaScript を埋め込めました（[CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)）。この問題は 1.22.1 で修正されました。説明欄を編集できるユーザーは、より高い権限を持つユーザーがリポジトリを閲覧し、悪意のあるリンクを有効にすると、そのブラウザーセッションに影響を与えられます。そのブラウザーIDを利用して、非公開リポジトリの内容やその他のアプリケーションデータを取得できる可能性があります。これとは別に、ローカルでの権限昇格には、そのコンテンツから到達可能な認証情報や権限（再利用された管理者パスワードなど）が必要です。Gitea プロセスの所有者だけでは、root への影響を立証できません。この連鎖を主張する前に、導入済みバージョン、説明欄の編集権限、閲覧者の操作手順、実際のブラウザー操作を確認してください。

## Cobbler プロビジョニング API

Cobbler の管理サービスは XML-RPC API を公開しており、通常はポート `25151` で待ち受けます。影響を評価する前に、待受状態と `cobblerd` プロセスの所有者を確認してください。ループバックのみで待ち受ける API でも、ホスト上のユーザーからアクセスできます。`/etc/cobbler/modules.conf` の認証・認可モジュール、`/etc/cobbler/settings` または `/etc/cobbler/settings.yaml` のサービス設定、`/etc/cobbler/users.conf`、`/etc/cobbler/users.digest`、`/var/lib/cobbler/web.ss` の権限を確認してください。ダイジェストファイルと共有秘密ファイルには認証情報が含まれるため、既定では内容を表示せず、読み取り可能かどうかを記録してください。

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** は、Cobbler 3.0.0～3.2.2 および 3.3.0～3.3.6 における XML-RPC authentication bypass です。共有シークレットの読み取りエラーで予測可能な値 `-1` が返され、API はこれをパスワードとして受け入れていました。修正バージョンは 3.2.3 と 3.3.7 です。パッケージのバージョンは手掛かりにすぎません。露出を報告する前に、デプロイされたコードとバックポートされた修正の有無を確認してください。

`cobblerd` が root として実行されている場合、認証済み API セッションが特権実行経路になることがあります。影響を受ける実装では、`background_import` がユーザー制御の `rsync_flags` を shell コマンドに渡し、ユーザー制御の Cheetah autoinstall template をレンダリングすると Python が評価されることがあります。いずれかの経路をテストする前に、API の権限とインストール済みバージョンを確認してください。管理 API へのアクセスを制限し、authentication bypass にパッチを適用してください。また、設定ファイルと認証情報ファイルはサービス管理者だけが読み取れるようにしてください。

## Motion と motionEye の設定

`/etc/motioneye/motioneye.conf` の `conf_path` を確認し、そのディレクトリにある `motion.conf` と少数の `camera-*.conf` ファイルを調べてください。読み取り可能な `# @admin_password` ハッシュが存在するかどうかを、ハッシュを表示せずに報告してください。[古い motionEye リリースでは、これらのファイルに広範な読み取り権限が設定されていました](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67)。修正は 0.44.0 に含まれています。Motion の `webcontrol_port`、`webcontrol_parms`、`webcontrol_auth_method`、`webcontrol_localhost` の設定をまとめて確認してください。認証が無効で高度な制御（`2` または `3`）が有効な場合、loopback listener 上であっても、ローカルユーザーに強力な操作を許すおそれがあります。[Motion のドキュメントで設定値とデフォルトを確認できます](https://motion-project.github.io/motion_config.html)。

0.43.1b5 より前の motionEye では、admin セッションを使うと、Motion が処理するカメラのファイル名設定を介して command execution が可能でした（[CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)）。権限昇格を主張する前に、実行中のバージョン、サービスの実行ユーザー、利用可能な認証経路、カメラが設定されているかを確認してください。設定だけでは、サービスが稼働中であることや特権を持つことの証明にはなりません。

サービス名やインストール済みパッケージは手掛かりにすぎません。特権境界は、到達可能な入力、プロセスの実行ユーザー、書き込み可能な設定、そして最終的に制御されるコマンドまたはファイルの組み合わせで決まります。

## ローカル AWS emulator と保存済み認証情報

ホストユーザーは、コンテナ内で稼働する AWS-compatible emulator に、公開された loopback endpoint 経由でアクセスできる場合があります。[Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) または [KMS](https://docs.localstack.cloud/aws/services/kms/) へのアクセスを評価する前に、稼働中の listener、クライアントが選択する endpoint と account、emulator に設定された認可設定を照合してください。LocalStack では、[IAM policy enforcement は独立した設定です](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/)。認証情報ファイル、IAM policy、または listener だけから、実効 API 権限を推測しないでください。インストール済みリリースと設定での動作を確認してください。

保存済み secret がローカルでの権限昇格に役立つのは、現在の API identity がそれを取得でき、かつ別の高権限アカウントが復元した認証情報を受け入れる場合に限られます。暗号化されたローカル blob の場合も、ファイルの読み取り権限、対応する利用可能な KMS key と algorithm、実効的な decrypt 権限が必要です。[非対称 KMS key](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html) では、decrypt request に blob の暗号化に使用した algorithm を指定する必要があります。通常の列挙では、ホストの自動 inventory をプロセス、listener、設定パス、ファイル権限の証拠に限定してください。secret の値や復号済みの平文を要求したり表示したりしないでください。
{{#include ../../banners/hacktricks-training.md}}
