# ローカルのWebサービスと認証サービス

{{#include ../../banners/hacktricks-training.md}}

Linux shellからは、プロセスの引数、リスナー、unitファイル、設定、ログ、ローカル専用インターフェースなど、ホスト側からWebサービスや認証サービスを確認できます。この情報を使って、アクセス可能なサービスと、実際にそのサービスが使用するアカウントやファイルを結び付けましょう。

## ローカルのWebスタックを把握する

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

仮想ホスト名、ドキュメントルート、プロキシルート、アップロードディレクトリ、PHP の実行設定、認証情報を含む設定ファイルを確認します。loopback リスナーは、プロキシや SSH トンネル経由で到達できる場合があります。ローカルリスナーに対して名前付き仮想ホストをテストするには、意図した `Host` ヘッダーを送信するか、正しいアドレスとポートを指定して `curl --resolve` を使います。仮想ホストの列挙によって、デフォルトの応答に含まれない名前が見つかることもあります。Apache が `.htaccess` による上書きを許可しているか、また、書き込み可能なアップロードディレクトリをコード実行とみなす前に、そのパスで PHP を実行できるかを確認してください。デプロイ済みの JavaScript source map からソースパスやクライアント側の秘密情報が見つかることがあります。取得した値は手掛かりとして扱い、実際の権限を検証してください。Web 固有の確認事項については、[Apache](../../network-services-pentesting/pentesting-web/apache.md) と [Nginx](../../network-services-pentesting/pentesting-web/nginx.md) を参照してください。

[mpm-itk](https://mpm-itk.sesse.net/) を使用している Apache では、有効な `AssignUserID` によって、仮想ホストを別のユーザーおよびグループで実行できます。低権限アカウントがそのホストの `DocumentRoot` にスクリプトを書き込める場合、到達可能なルートが実際に割り当てられた ID でスクリプトを実行するか確認してください。モジュールがロードされていること、有効な仮想ホスト設定（式ベースの ID 上書きを含む）、ディレクトリへの書き込み権限と検索権限、スクリプトハンドラー、リスナーへのアクセスを確認します。ディレクティブが見つかったことやディレクトリが書き込み可能であることだけでは、ユーザーをまたいだ実行の証明にはなりません。

Web サーバーで公開されているホームディレクトリには、実際の `.ssh` ディレクトリが非公開でも、SSH identity ファイルのバックアップアーカイブが公開されている場合があります。たとえば、[Nostromo の `homedirs_public` 設定](https://www.nazgul.ch/dev/nostromo_man.html)は、ユーザーのホームディレクトリから配信するサブディレクトリを指定します。パスだけで見つかったアーカイブは手掛かりです。サーバーの有効なマッピング、ローカルでの読み取り可否または HTTP 認可、アーカイブの内容、秘密鍵のパスフレーズ、対応するアカウントがその鍵を実際に受け入れるかを確認してください。通常のホスト列挙では、アーカイブを展開したり鍵の内容を表示したりしないでください。

高い権限で動作するローカル Web アプリの読み取り可能なバックアップから、稼働中のソースにアクセスできなくても、認証やファイル読み取りのロジックが判明することがあります。バックアップを根拠にする前に、稼働中のサービスと照合してください。特に、呼び出し側が制御するテキストに秘密情報とロールフラグを続けて暗号化して Cookie を作成する仕組みは、アプリが決定論的な ECB ブロックを使用し、任意のテキストに対する新しい Cookie を返し、後にエスケープされていない区切り文字で復号後の値を分割する場合、詳しく確認する必要があります。[NIST は ECB における独立した再現可能なブロック対応について説明しています](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)。この性質は選択入力の比較に利用できる場合がありますが、それだけで高いロールが付与されるわけではありません。稼働中のルート、セッションの前提条件、正確なパーサーおよびデータフロー、サービス ID、別個の特権アクションまたはファイル読み取り経路を確認してください。受動的なインベントリでは、アーカイブの内容を読んだり認証プローブを送信したりせず、バックアップのメタデータとリスナーの所有者を報告してください。

同じソースレビューの方法は、カスタム SSH ベースのインターフェースなど、特権で動作する **非 HTTP** の loopback サービスにも適用できます。アクセス可能なソースバックアップに、呼び出し側が指定したファイルパスを受け取るコマンドが記載されている場合は、その認証ゲート、パスの解決方法、ファイルを開く前に解決後のパスが意図したディレクトリ配下に留まることを検証しているかを確認してください。Go の [`filepath.Join`](https://pkg.go.dev/path/filepath#Join) はパスを正規化しますが、その配下に留まることまでは強制しません。バックアップが稼働中のビルドと一致すること、リスナーに到達できること、低権限アカウントがコマンドを利用できること、プロセスが対象を読み取れることを確認してください。読み取り可能な SSH 鍵を所持していることは、別途ログインポリシーの問題です。自動出力には、アーカイブの内容や鍵を展開せず、ソースアーカイブのパスとサービスの所有者を報告してください。

TCP loopback でリッスンする PHP-FPM pool には、Web サイトに認証が設定されていても、別のローカルアカウントから接続できる場合があります。[PHP は、FastCGI に接続できるクライアントが `auto_prepend_file` を含むリクエスト設定を制御できると警告しています](https://www.php.net/manual/en/install.fpm.php)。pool の `listen` と `listen.allowed_clients` の設定を、稼働中のリスナー、worker UID、既存のスクリプトパス、および `security.limit_extensions` や `php_admin_value` による制限と合わせて確認してください。pool の設定ファイルには `env[...]` ディレクティブ内に認証情報が含まれる場合があるため、自動インベントリでは内容ではなくパスを報告してください。設定ファイルやポートがあるだけでは、ユーザーをまたぐ実行経路の証明にはなりません。プロトコルの詳細は [FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md) を参照してください。

特権ローカル API では、コード実行だけでなく認可も追跡してください。低権限アカウントが変更できるデータベースロールによって API ルートが利用可能になる場合でも、その先の境界はルートの実装によって異なります。たとえば、リクエスト JSON を JavaScript オブジェクトにマージしてから [`child_process.exec`](https://nodejs.org/api/child_process.html) を呼び出す処理は、[prototype pollution から実行に至るデータフロー](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)の観点から確認する必要があります。実際のマージライブラリとバージョン、入力検証、到達可能なルート、プロセス ID、子プロセスのオプションを検証してください。root 所有の Node リスナーや脆弱な依存関係の名前だけでは、手掛かりにすぎません。

ファイルベースの CMS ストアには、従来の `.php` 設定ファイル以外に管理者パスワードの検証情報が保存されている場合があります。例として、サイトの `data/database.js` や `data/settings/pass.php` があります。手動レビューの前にファイルの所有者と読み取り可否を確認し、ハッシュを自動共有出力に含めないでください。復元可能なアプリケーションパスワードは Unix アカウントとは別の権限境界です。再利用が主張されている場合は、対象アカウントと許可されている認証方式で検証してください。

アプリケーションの認証コントローラーには、設定ファイルではなくソースコード内にログインパスワードがそのまま記載されている場合もあります。低権限ユーザーがデプロイ済みコントローラーを読み取れる場合は、認証時の比較処理をローカルで確認し、値を共有される列挙出力に含めないでください。コードパスが有効であること、そのパスワードがアプリケーションで有効であること、さらに高い権限を持つ Unix アカウントが同じパスワードを実際に受け入れることを確認してから、ローカル権限昇格を主張してください。コントローラーのファイル名だけでは、レビューの手掛かりにすぎません。

Dolibarr は、`dolibarr_main_db_pass` を含むデータベース接続設定を `htdocs/conf/conf.php` に保存します（[設定リファレンス](https://wiki.dolibarr.org/index.php/Configuration_file)）。読み取り可能なファイルは認証情報の手掛かりですが、別途検証されたアカウントパスワードの再利用や、他のデータベース権限がなければ、ローカル権限昇格にはつながりません。まず権限を確認し、自動出力に値を表示しないでください。

GitLab の Linux package の設定ファイルは通常 `/etc/gitlab/gitlab.rb` ですが、デプロイ環境によっては読み取り可能なコピーが別の場所に残っていることがあります。[GitLab のドキュメント](https://docs.gitlab.com/omnibus/settings/smtp/)によると、このファイルには `gitlab_rails['smtp_password']` が含まれる場合があります。ただし、SMTP 設定が暗号化されている場合、パスワードは平文ファイルの外に保存されることがあります。読み取り可能な設定ファイルは認証情報の手掛かりとして扱い、それが有効であること、認証情報が現在も有効であること、特定の高権限アカウントが受け入れることを確認してから、パスワード再利用を主張してください。また、[GitLab は `gitlab-ctl reconfigure` 中に root 権限で `gitlab.rb` を Ruby コードとして実行します](https://docs.gitlab.com/omnibus/settings/configuration/)。書き込み可能な有効ファイルや、読み込み先の `from_file` が実行上の問題となるには、実際に特権で再構成が行われる経路が必要です。設定のプレビューで認証情報が露出することがあるため、出力は機密情報として扱い、代わりにパスと権限を共有してください。

セルフホストの Mattermost では、`SqlSettings.DataSource` が `/opt/mattermost/config/config.json` に保存されている場合があります。[Mattermost のドキュメント](https://docs.mattermost.com/deployment-guide/server/troubleshooting)には、この一般的なパスと、稼働中の設定をデータベースに保存するデプロイ方法の両方が記載されています。読み取り可能なファイルからアプリケーションのデータベース認証情報が分かることはありますが、それだけではデータベースへのアクセスや Unix root 権限は証明されません。有効な設定の保存先、データベースロールの実際の権限、別途取得したアプリケーションパスワード、さらにそのパスワードが特定の高権限 Unix アカウントで使えるかを確認してください。パスワードハッシュの形式は Mattermost のバージョンによって変わることがあります。列挙時には接続文字列を表示したりデータベースに問い合わせたりせず、設定ファイルのパスとアクセスメタデータを記録してください。

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

virtual-host の結果をデフォルトの応答サイズまたは別の安定したベースラインと比較し、推測した名前がすべて有効に見える事態を防ぎます。source map は、実際にデプロイされているか、別の方法で読み取り可能な場合にのみ役立ちます。

Reverse proxy によって、アプリケーションが信頼するクライアントヘッダーが変わることがあります。`X-Forwarded-For`、`X-Forwarded-Host` などのヘッダーが呼び出し元のIDを示すと決めつける前に、直接リクエストとプロキシ経由のリクエストを比較してください。proxy とアプリケーションの設定を併せて確認します。

PHP が `$_SERVER['HTTP_X_FORWARDED_FOR']` を [`system()`](https://www.php.net/manual/en/function.system.php) に渡す文字列にコピーしている場合、到達可能なリクエスト経路で呼び出し元が指定したヘッダーが許されるか、シェルのメタ文字がその文字列に変更されずに渡されるかを確認してください。先頭に `sudo iptables` を埋め込んだコマンドがあっても、後続のシェル区切りコマンドが root で実行されるわけではありません。別途、有効な sudo ルールで昇格が許可されない限り、それらは web worker の権限で実行されます。root への経路を主張する前に、worker の実行ユーザー、正確な `sudo -l` の許可内容と認証要件、コマンド引数の境界を確認してください。通常のホスト列挙では、injection probe を送信せずにソースとポリシーを調べます。

## アクセスログ内のログイン認証情報

アプリケーションがログインフォームを `GET` で送信すると、ユーザー名とパスワードがリクエストURIのクエリパラメーターになることがあります。`POST` リクエストにもクエリ文字列を含められます。`POST` を使っても、無関係なフォームフィールドに入力したパスワードなど、URIに誤って含まれた秘密情報は隠せません。[Apache の一般的なアクセスログのリクエスト行](https://httpd.apache.org/docs/2.4/logs.html)は、設定された形式で `%r` を使う場合、クエリ文字列を含むメソッドとURIを記録します。そのため、一部のLinuxシステムの `adm` グループなど、ログの読み取りを許可されたアカウントから認証情報につながる手掛かりが見つかることがあります。実際のログ形式とアクセス権を確認したうえで、その値が秘密情報であること、アカウントがその値を受け付けること、権限境界を越えることを検証してください。リクエスト本文がログに記録されていると決めつけず、候補の値を共有出力にコピーしないでください。

読み取り可能なアクセスログだけを調べ、認証情報の値を共有コマンド出力に含めないでください。長いリクエスト行にはリファラーやユーザーエージェントも含まれる場合があるため、短い行だけを抽出するフィルターでは、調べるべきリクエスト自体が隠れることがあります。Apache、httpd、Nginx の一般的なアクセスログの場所は `/var/log/apache2/access.log`、`/var/log/httpd/access_log`、`/var/log/nginx/access.log` です。ローテーションされたログに古い認証情報が含まれることもあります。[LFI を通じたログファイルへのアクセス](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)も、同じデータにたどり着く関連経路です。

アプリケーションの認証ログには、ログイン失敗時に**ユーザー名**フィールドへ誤って入力されたパスワードが記録されることもあります。まず、ログが読み取り可能で、形式上、送信されたユーザー名が記録されることを確認してください。該当箇所だけをローカルで少量確認し、候補の認証情報を共有出力にコピーしないでください。パスワードらしいユーザー名は手掛かりであり、有効なパスワードやより高い権限の証明ではありません。権限移行を主張する前に、想定されたアカウントと、対象サービスまたはUnixアカウントでの再利用を確認してください。

別のIDで動作するスケジュール済みクライアントがエンドポイントに認証情報を送信する場合、書き込み可能なwebログインハンドラーは別途調査が必要です。**稼働中の**ハンドラーへの書き込み権限、クライアントの実際のスケジュールとリクエスト経路、送信される認証情報の所有者、そのアプリケーションパスワードがより高い権限を持つOSアカウントでも個別に有効かを確認してください。書き込み可能なページや定期実行プロセスだけでは、その権限移行は証明されません。受動的なインベントリでは、ハンドラーを変更したりパスワードを収集したりせず、パスのアクセス権とジョブのメタデータを報告してください。

Suricata の EVE JSON ログには、FTP イベントロギングが有効な場合、`command_data` とともに FTP の `USER` および `PASS` コマンドが記録されることもあります。該当箇所をローカルで少量確認する前に、ローテーションまたは圧縮されたファイルを含め、`/var/log/suricata/eve*.json*` が読み取り可能か確認してください。読み取り可能な EVE ファイルはあくまで手掛かりです。FTP イベントが記録されていること、データに使用可能な認証情報が含まれること、権限境界を越えることを確認してください。共有列挙出力に `command_data` を表示しないでください。Suricata のドキュメントでは、[FTP イベントフィールド](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)と[EVE のローテーションおよびファイル名のバリエーション](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)が説明されています。

## 生成された Apache 設定とパイプログ

[remco](https://github.com/HeavyHorst/remco) は、key/value backend を監視し、テンプレートを Apache 設定ファイルにレンダリングして、reload コマンドを実行できます。稼働中の remco プロセスのID、設定されたテンプレートのソースと出力先、監視対象のキーのプレフィックス、backend の値が `ServerName` などの Apache ディレクティブに直接挿入されるかを確認してください。ローカルの backend listener が存在するだけでは、現在のユーザーが監視対象のキーを書き込めるとは限りません。権限昇格を主張する前に、backend の認証とアクセス権を確認してください。

書き込み可能な backend の値にエスケープされていない改行があると、意図した1つのディレクティブ値が複数の Apache ディレクティブに変わることがあります。[Apache のパイプログ](https://httpd.apache.org/docs/2.4/logs.html#piped)は特に注意が必要です。`CustomLog` または `ErrorLog` に `|` コマンドを指定すると、親 httpd のID、多くの場合は root でヘルパーが起動します。`|$` を指定すると、Apache に shell を使わせます。列挙中は backend のデータを変更したりサービスを再起動したりせずに、生成された設定とその reload 経路を確認してください。引数に秘密情報が含まれる可能性があるため、パイプコマンド全体は共有しないでください。

## 認証とサービスID

Monit の制御ファイルは通常 `~/.monitrc` または `/etc/monitrc` ですが、`monit -c` で別のパスを指定できます。読み取り可能なファイルには、web インターフェース用の `set httpd` や `allow user:password` エントリーが含まれることがあります。多くの場合、ローカルポート 2812 で待ち受けます。確認する前にファイルの所有者とアクセス権を調べ、パスワードの値を共有列挙出力に含めないでください。web 認証情報で付与されるのは、設定された Monit のロールだけです。読み取り専用ユーザーは制御操作を実行できません。Unixアカウントへの別の権限昇格を主張するには、パスワードの再利用、または認証済みのロールが実際に実行できる特権 Monit アクションを確認する必要があります。[Monit の制御ファイルと認証に関するドキュメント](https://www.mmonit.com/monit/documentation/monit.html)を参照してください。

Webmin では、`/etc/webmin/miniserv.conf` にサーバー設定が記載され、`/etc/webmin/webmin.acl` にユーザーがアクセスできるモジュールが記録されています。[Webmin のドキュメントでは、モジュール付与の境界が説明されています](https://webmin.com/docs/development/creating-modules/)。Unix パスワードや読み取り可能な ACL ファイルだけでは、Webmin セッションは取得できません。実際の認証マッピング、到達可能な listener、認証されたアカウント、有効な Package Updates モジュールの権限、インストール済みコードまたはベンダー修正、Webmin プロセスのIDを確認してください。1.910 までの影響を受けるビルドでは、[CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840) により、そのモジュール権限を持つアカウントが update handler 経由でコマンドを実行できました。受動的な列挙中は、認証情報を表示したり update を試みたりせず、設定パスとアクセス権を報告してください。

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) はサービス固有の認証を制御します。書き込み可能なポリシーまたはモジュールのパスを変更すると、ログイン時の動作を変えられる可能性があります。
- LDAP/SSSD の設定から、ディレクトリのエンドポイント、bind identity、アクセスルールが判明することがあります。取得した bind password により、現在の OS アカウントを超える LDAP クエリが可能になる場合があります。実際の bind identity とディレクトリ ACL を確認してください。秘密情報を調べる前にファイルの権限を確認してください。[Linux Active Directory](../user-information/linux-active-directory.md) と [FreeIPA](freeipa-pentesting.md) では、チケットとディレクトリの利用方法を扱っています。
- Postfix の alias は、受信メールをローカルコマンドにパイプできます。権限の低いユーザーが参照先のスクリプトを変更できる場合、メールの配信によって、そのユーザーのコードが配信時の identity で実行される可能性があります。この経路を指摘する前に、alias map とスクリプトの所有者を確認してください。[SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md) を参照してください。
- Jenkins などの CI サービスでは、強力なローカルアカウントでジョブが実行される場合があります。Pipeline やプラグインをテストする前に、サービスユーザー、書き込み可能なジョブ/workspace のパス、ローカル管理インターフェースを確認してください。また、**ジョブが利用できる credentials** と、それらを使って認証できるアカウントも確認してください。[SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) を使用する Pipeline は、Jenkins 自体がより権限の低い Unix アカウントで実行されていても、SSH credential のユーザーとしてホストにアクセスできます。ホストの権限昇格を指摘する前に、現在の Jenkins identity に `Job/Create`、`Job/Configure`、または Pipeline を変更できる別の有効な経路があること、そのジョブで credential を利用できること、対象の SSH アカウントがその鍵を受け入れることを確認してください。credential の表示名や ID だけでは、これらの条件が満たされているとは判断できません。Jenkins は、ジョブ作成者や、多くの場合ジョブ設定者が、自分のスコープ内で利用可能な credentials を任意に使用できると警告しています。そのため、サービス UID と同様に、[credential scope](https://www.jenkins.io/doc/book/security/credentials/) と [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/) も重要です。共有する列挙結果に credential の値や秘密鍵を含めないでください。

## Gogs repository file writes

ローカルの Gogs サービスでは、`gogs web` プロセスの所有者を、実行ファイルのバージョンおよび `custom/conf/app.ini` と照合してください。設定から、サービス identity、repository root、listener address、登録が無効になっているかどうかが判明する場合があります。loopback のみで待ち受けていても、ローカルユーザーからアクセスできます。0.13.3 までの Gogs には、認証済みの `PutContents` による symlink file-write の問題があります（[CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)）。repository writer は symlink を commit し、その後 API write を経由させることができます。結果として生じるファイルアクセス権限は Gogs プロセスのものになるため、root 所有のインスタンスは速やかに調査する必要があります。利用可能な経路があると指摘する前に、適用済みの修正と認証要件を検証してください。API エラーだけでは、ファイル書き込みが失敗した証拠にはなりません。

## Gitea repository-description XSS and privileged viewers

Gitea 1.22.0 では repository description に保存された JavaScript が許可されていました（[CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)）。1.22.1 で修正されています。description を編集できるユーザーは、より権限の高いユーザーがその repository を表示して悪意あるリンクを有効にした場合、そのブラウザーセッションに影響を与えられます。そのブラウザーの identity を利用して、非公開 repository のコンテンツやその他のアプリケーションデータを漏えいさせることができます。このコンテンツを通じてアクセス可能な credential や権限（再利用された administrator password など）がなければ、別途ローカルでの権限昇格は成立しません。Gitea プロセスの所有者だけでは、root への影響があるとは判断できません。この連鎖を指摘する前に、導入済みバージョン、description の編集権限、閲覧者の操作手順、実際のブラウザー操作を確認してください。

## Cobbler provisioning API

Cobbler の管理サービスは XML-RPC API を公開しており、一般的なポートは `25151` です。影響を評価する前に、listener と `cobblerd` プロセスの所有者を確認してください。loopback のみで待ち受けている API でも、ホスト上のユーザーからアクセスできます。`/etc/cobbler/modules.conf` の認証・認可モジュール、`/etc/cobbler/settings` または `/etc/cobbler/settings.yaml` のサービス設定、`/etc/cobbler/users.conf`、`/etc/cobbler/users.digest`、`/var/lib/cobbler/web.ss` の権限を確認してください。digest と共有秘密ファイルには credential の情報が含まれるため、デフォルトでは内容を出力せず、読み取り可能かどうかを記録してください。

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** は、Cobbler 3.0.0〜3.2.2 および 3.3.0〜3.3.6 における XML-RPC authentication bypass です。共有シークレットの読み取りエラーによって予測可能な値 `-1` が返され、API はこれをパスワードとして受け入れていました。対応する修正バージョンは 3.2.3 および 3.3.7 です。パッケージのバージョンは手がかりにすぎません。脆弱性を報告する前に、デプロイされたコードとバックポートされた修正の有無を確認してください。

`cobblerd` が root として実行されている場合、認証済み API セッションが特権実行経路になることがあります。影響を受ける実装では、`background_import` がユーザー制御の `rsync_flags` をシェルコマンドに渡し、ユーザー制御の Cheetah autoinstall template のレンダリングで Python が評価される可能性があります。いずれかの経路をテストする前に、API の権限とインストール済みバージョンを確認してください。管理 API へのアクセスを制限し、authentication bypass にパッチを適用し、設定ファイルと認証情報ファイルをサービス管理者のみが読み取れるようにしてください。

## Motion と motionEye の設定

`/etc/motioneye/motioneye.conf` で `conf_path` を確認し、そのディレクトリ内の `motion.conf` と少数の `camera-*.conf` ファイルを調べてください。読み取り可能な `# @admin_password` ハッシュが存在するかを報告し、値自体は表示しないでください。[古い motionEye リリースでは、これらのファイルに広範な読み取り権限が設定されていました](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67)。修正は 0.44.0 で行われています。Motion の `webcontrol_port`、`webcontrol_parms`、`webcontrol_auth_method`、`webcontrol_localhost` の設定を併せて確認してください。認証が無効で高度な制御（`2` または `3`）が有効な場合、loopback listener 上であっても、ローカルユーザーが強力な操作を実行できる可能性があります。[Motion のドキュメントには値とデフォルトが記載されています](https://motion-project.github.io/motion_config.html)。

0.43.1b5 より前の motionEye では、管理者セッションを使ってカメラのファイル名設定をコマンド実行につなげられる可能性があり、Motion がその設定を処理した際に実行されました（[CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)）。権限昇格を主張する前に、実行中のバージョン、サービスの実行ユーザー、利用可能な認証経路、カメラが設定されているかを確認してください。設定だけでは、サービスが実行中であることや特権を持つことの証明にはなりません。

サービス名やインストール済みパッケージは手がかりにすぎません。権限境界を判断するには、到達可能な入力、プロセスの実行ユーザー、書き込み可能な設定、および最終的に制御されるコマンドやファイルを併せて考慮します。

## ローカル AWS エミュレーターと保存済み認証情報

ホストユーザーは、コンテナ内で実行されている AWS 互換エミュレーターに、公開された loopback endpoint 経由でアクセスできる場合があります。アクセスを評価する前に、稼働中の listener、クライアントが選択する endpoint とアカウント、エミュレーターに設定された認可の設定を照合してください。[Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) や [KMS](https://docs.localstack.cloud/aws/services/kms/) へのアクセスを評価する際も同様です。LocalStack では、[IAM policy enforcement は独立した設定です](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/)。認証情報ファイル、IAM policy、または listener だけから、実効 API 権限を推定しないでください。インストール済みリリースと設定で実際の動作を確認してください。

保存されたシークレットがローカルでの権限昇格に役立つのは、現在の API identity がそのシークレットを取得でき、かつ別の高権限アカウントが復元した認証情報を受け入れる場合に限られます。暗号化されたローカル blob の利用には、ファイルの読み取り権限、対応する利用可能な KMS key とアルゴリズム、実効的な復号権限も必要です。[非対称 KMS key](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html) の場合、復号リクエストでは blob の暗号化に使われたアルゴリズムを指定する必要があります。通常の列挙で自動的に収集するホスト情報は、プロセス、listener、設定パス、ファイル権限の証拠に限定してください。シークレット値や復号した平文を要求したり表示したりしないでください。
{{#include ../../banners/hacktricks-training.md}}
