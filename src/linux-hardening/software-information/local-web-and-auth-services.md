# ローカル Web および認証サービス

{{#include ../../banners/hacktricks-training.md}}

Linux shell からは、プロセス引数、リスナー、unit ファイル、設定、ログ、ローカル専用インターフェースなど、ホスト側から Web サービスや認証サービスを確認できます。この視点を使って、アクセス可能なサービスと、実際にそのサービスが使用するアカウントやファイルを結び付けましょう。

## ローカルの Web スタックを把握する

```bash
ss -lntup
ps -eo user,pid,args | grep -E '[a]pache|[n]ginx|[p]hp-fpm|[j]enkins'
systemctl list-units --type=service --state=running 2>/dev/null
find /etc/apache2 /etc/httpd /etc/nginx -maxdepth 3 -type f 2>/dev/null | head -80
```

仮想ホスト名、ドキュメントルート、proxyルート、アップロードディレクトリ、PHPの実行設定、認証情報を含む設定ファイルを調査します。loopback listenerは、proxyやSSH tunnel経由で到達できる場合があります。ローカルlistenerに対して名前付き仮想ホストをテストするには、想定する`Host` headerを送信するか、正しいアドレスとポートを指定して`curl --resolve`を使用します。仮想ホストの列挙により、デフォルト応答に含まれない名前が見つかることもあります。書き込み可能なアップロードディレクトリをコード実行とみなす前に、Apacheで`.htaccess`による上書きが許可されているか、アップロード先のパスでPHPを実行できるかを確認します。デプロイ済みのJavaScript source mapから、ソースパスやクライアント側の秘密情報が見つかる場合があります。見つかった値は手がかりとして扱い、実際の権限を確認してください。Web固有のチェックについては、[Apache](../../network-services-pentesting/pentesting-web/apache.md)および[Nginx](../../network-services-pentesting/pentesting-web/nginx.md)を参照してください。

Apacheで[mpm-itk](https://mpm-itk.sesse.net/)を使用している場合、有効な`AssignUserID`によって、仮想ホストを別のユーザーおよびグループとして実行できます。低権限アカウントがそのホストの`DocumentRoot`にスクリプトを書き込める場合、到達可能なルートがそのスクリプトを割り当てられたIDで実際に実行するか確認してください。モジュールがロードされていること、有効な仮想ホスト設定（式ベースのID上書きを含む）、ディレクトリへの書き込み権限と検索権限、スクリプトハンドラー、listenerへのアクセスを確認します。強調表示されたディレクティブや書き込み可能なディレクトリだけでは、ユーザーをまたいだ実行の証明にはなりません。

Webサーバーで公開されているホームディレクトリから、実際の`.ssh`ディレクトリが非公開でも、SSH identityファイルのバックアップアーカイブが漏えいすることがあります。たとえば、[Nostromo's `homedirs_public` setting](https://www.nazgul.ch/dev/nostromo_man.html)は、ユーザーのホーム内で公開するサブディレクトリを指定します。パスだけがアーカイブに一致した場合は、手がかりとして扱います。サーバーの有効なマッピング、ローカルでの読み取り可否またはHTTP認可、アーカイブの内容、秘密鍵のpassphrase、対応するアカウントが実際にその鍵を受け入れるかを確認してください。通常のホスト列挙では、アーカイブを展開したり鍵の内容を表示したりしないでください。

権限の高いローカルWebアプリのバックアップが読み取り可能であれば、稼働中のソースにアクセスできなくても、認証やファイル読み取りのロジックがわかることがあります。バックアップに依存する前に、デプロイ済みのサービスと比較してください。特に、呼び出し元が制御できるテキストの後ろに秘密情報とロールフラグを付けて暗号化するcookieについては、アプリが決定論的なECB blockを使い、指定したテキストに対して新しいcookieを返し、後で復号値をエスケープされていない区切り文字で分割する場合、検証が必要です。[NIST explains ECB's independent, repeatable block mapping](https://csrc.nist.gov/news/2022/proposal-to-revise-sp-800-38a)によれば、この性質は選択入力の比較に利用できる場合がありますが、それだけで高いロールが得られるわけではありません。稼働中のルート、セッションの前提条件、正確なパーサーとデータフロー、サービスID、および別個の特権操作またはファイル読み取り経路を確認してください。受動的なインベントリでは、アーカイブの内容を読んだり認証プローブを送信したりせず、バックアップのメタデータとlistenerの所有者を報告してください。

同じソースレビューの手法は、カスタムのSSHベースのインターフェースなど、特権を持つ**非HTTP**のloopback serviceにも適用できます。アクセス可能なソースバックアップから、呼び出し元がファイルパスを指定できるコマンドが見つかった場合は、認証ゲート、パスの解決方法、ファイルを開く前に解決後のパスが意図したディレクトリ配下にあることを確認しているかを調べます。Goの[`filepath.Join`](https://pkg.go.dev/path/filepath#Join)はパスを正規化しますが、配下にあることまでは保証しません。バックアップが実行中のビルドと一致すること、listenerに到達できること、低権限アカウントからコマンドを使用できること、プロセスが対象を読み取れることを確認してください。読み取り可能なSSH keyを持っていることは、別途ログインポリシーの確認が必要な問題です。自動出力には、アーカイブの内容や鍵を展開せず、ソースアーカイブのパスとサービスの所有者を記録してください。

TCP loopbackでlistenするPHP-FPM poolには、Webサイトに認証があっても別のローカルアカウントから到達できる場合があります。[PHP warns that a client able to connect to FastCGI can control request settings, including `auto_prepend_file`](https://www.php.net/manual/en/install.fpm.php)。poolの`listen`および`listen.allowed_clients`設定を、稼働中のlistener、worker UID、既存のスクリプトパス、`security.limit_extensions`や`php_admin_value`による制限と合わせて確認してください。poolの設定ファイルには`env[...]`ディレクティブ内に認証情報が含まれる場合があるため、自動インベントリでは内容ではなくパスを報告してください。設定ファイルやポートがあるだけでは、ユーザーをまたいだ実行経路の証明にはなりません。プロトコルの詳細は[FastCGI guide](../../network-services-pentesting/9000-pentesting-fastcgi.md)を参照してください。

特権を持つローカルAPIでは、コード実行だけでなく認可も追跡してください。低権限アカウントが変更できるデータベースロールによってAPIルートが利用可能になる場合もありますが、その先の境界はルートの実装によって異なります。たとえば、リクエストのJSONをJavaScript objectにマージしてから[`child_process.exec`](https://nodejs.org/api/child_process.html)を呼び出す処理は、[prototype-pollution-to-execution dataflow](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)の観点から調査が必要です。実際に使用されているマージライブラリとバージョン、入力検証、到達可能なルート、プロセスID、child-processのオプションを確認してください。root所有のNode listenerや、脆弱性があるとされる依存関係名だけでは、あくまで手がかりにすぎません。

ファイルベースのCMSストアには、従来型の`.php`設定ファイル以外に、管理者パスワードの検証値が保存されていることがあります。例として、サイトの`data/database.js`や`data/settings/pass.php`があります。手動で確認する前にファイルの所有者と読み取り可否を確認し、hashを自動出力や共有出力に含めないでください。復元可能なアプリケーションパスワードとUnixアカウントの権限境界は別です。パスワードの使い回しが疑われる場合は、対象のアカウントと許可されている認証方式で確認してください。

アプリケーションの認証controllerには、設定ファイルではなくソースコード内にログインパスワードが直接記述されている場合もあります。低権限ユーザーがデプロイ済みcontrollerを読み取れる場合は、認証時の比較処理をローカルで確認し、値を共有される列挙結果に含めないでください。該当するコードパスが有効であること、そのパスワードがアプリケーションで有効であること、さらに別の高権限Unixアカウントが同じパスワードを実際に受け入れることを確認してから、ローカルでの権限昇格を主張してください。controllerのファイル名だけなら、確認の手がかりにすぎません。

Dolibarrはデータベース接続設定（`dolibarr_main_db_pass`を含む）を`htdocs/conf/conf.php`に保存します（[configuration reference](https://wiki.dolibarr.org/index.php/Configuration_file)）。読み取り可能なファイルは認証情報の手がかりになりますが、別途確認されたアカウントパスワードの使い回しか、別のデータベース権限がなければ、ローカルでの権限昇格にはつながりません。まず権限を確認し、自動出力に値を表示しないでください。

GitLabのLinux packageの設定ファイルは通常`/etc/gitlab/gitlab.rb`ですが、デプロイ方法によっては別の場所に読み取り可能なコピーが残っていることがあります。[GitLab documents](https://docs.gitlab.com/omnibus/settings/smtp/)によると、このファイルには`gitlab_rails['smtp_password']`が含まれる場合があります。ただし、暗号化されたSMTP設定では、パスワードが平文ファイルの外部に保存されることもあります。読み取り可能な設定ファイルは認証情報の手がかりとして扱い、有効な設定であること、認証情報が現在も有効であること、特定の高権限アカウントがその認証情報を受け入れることを確認してから、パスワードの使い回しを主張してください。また、[GitLab runs `gitlab.rb` as Ruby code under root during `gitlab-ctl reconfigure`](https://docs.gitlab.com/omnibus/settings/configuration/)ため、書き込み可能な有効ファイルや読み込まれる`from_file`が実行につながるfindingと判断するには、実際に特権で再設定される経路が必要です。設定のpreviewで認証情報の値が露出する場合があるため、出力は機密情報として扱い、代わりにパスと権限を共有してください。

セルフホスト型Mattermostのインストールでは、`SqlSettings.DataSource`が`/opt/mattermost/config/config.json`に保存されている場合があります。[Mattermost documents](https://docs.mattermost.com/deployment-guide/server/troubleshooting)には、通常のパスと、稼働中の設定がデータベースに保存されるデプロイ方法の両方が記載されています。ファイルが読み取り可能であればアプリケーションのデータベース認証情報が漏れることがありますが、それだけではデータベースへのアクセスやUnix rootへのアクセスを証明できません。有効な設定の保存先、データベースロールの実際の権限、別途復元したアプリケーションパスワードの有無、およびそのパスワードが特定の高権限Unixアカウントで使えるかを確認してください。パスワードhashの形式はMattermostのバージョンによって変わることがあります。列挙時には、接続文字列を表示したりデータベースに問い合わせたりせず、設定パスとアクセスに関するメタデータを記録してください。

```bash
curl -i -H 'Host: admin.example.local' http://127.0.0.1:8080/
ffuf -w wordlist.txt -u http://127.0.0.1:8080/ -H 'Host: FUZZ.example.local' -fs 1234 # replace 1234 with the default response size
grep -R 'sourceMappingURL' /var/www /opt 2>/dev/null | head
```

デフォルト応答のサイズまたは別の安定した基準と照合して virtual-host の結果をフィルタリングし、推測した名前がすべて有効に見えるのを防ぎます。source map は、実際にデプロイされているか、別の方法で読み取り可能な場合にのみ役立ちます。

Reverse proxy によって、アプリケーションが信頼するクライアントヘッダーが変わることがあります。`X-Forwarded-For`、`X-Forwarded-Host` などのヘッダーが呼び出し元の ID を確立すると決めつける前に、直接リクエストとプロキシ経由のリクエストを比較してください。プロキシとアプリケーションの設定を合わせて確認します。

PHP が `$_SERVER['HTTP_X_FORWARDED_FOR']` を `system()` に渡す文字列へコピーしている場合、呼び出し可能なリクエスト経路でユーザー指定ヘッダーを送れるか、シェルメタ文字がその文字列に変更されずに渡るかを確認してください。先頭に `sudo iptables` を埋め込んだコマンドがあっても、後続のシェル区切りコマンドが root で実行されるわけではありません。別途有効な sudo ルールで権限昇格が許可されない限り、それらは web worker として実行されます。root への経路を主張する前に、worker の ID、正確な `sudo -l` の許可内容と認証要件、コマンドの引数境界を確認してください。通常のホスト列挙中に injection probe を送らず、ソースとポリシーを調査します。

## アクセスログ内のログイン認証情報

アプリケーションが `GET` でログインフォームを送信すると、ユーザー名とパスワードがリクエスト URI のクエリパラメーターになることがあります。`POST` リクエストにもクエリ文字列を含められます。`POST` を使っても、無関係なフォームフィールドに入力したパスワードなど、URI に誤って含まれたシークレットは隠せません。[Apache の一般的なアクセスログのリクエスト行](https://httpd.apache.org/docs/2.4/logs.html)は、設定された形式で `%r` を使う場合、クエリ文字列を含むメソッドと URI を記録します。そのため、一部の Linux システムでの `adm` グループのように、これらのログを読み取れるアカウントから認証情報の手掛かりが見つかることがあります。実際のログ形式と権限を確認し、その値がシークレットであること、アカウントで受け入れられること、権限境界を越えることを検証してください。リクエストボディがログに記録されたと決めつけたり、候補値を共有出力にコピーしたりしないでください。

読み取り可能なアクセスログだけを調査し、認証情報の値を共有コマンド出力に含めないでください。長いリクエスト行には Referer と User-Agent も含まれることがあるため、短い行だけを対象にするフィルターでは、確認対象のリクエスト自体が見えなくなる場合があります。Apache、httpd、Nginx の一般的なアクセスログの場所は、それぞれ `/var/log/apache2/access.log`、`/var/log/httpd/access_log`、`/var/log/nginx/access.log` です。ローテーション済みログに古い認証情報が残っていることもあります。[LFI によるログファイルへのアクセス](../../pentesting-web/file-inclusion/README.md#read-access-logs-to-harvest-get-based-auth-tokens-token-replay)も、同じデータにたどり着く関連経路です。

アプリケーションの認証ログには、ログイン失敗時にパスワードを誤って**ユーザー名**フィールドへ入力した場合、そのパスワードが記録されることもあります。まずログが読み取り可能であることと、形式上、送信されたユーザー名が記録されることを確認してください。関連する範囲をローカルで少量だけ調べ、候補の認証情報を共有出力にコピーしないでください。パスワードらしいユーザー名は手掛かりであり、有効なパスワードや高い権限の証明ではありません。権限移行を主張する前に、対象アカウントと、特定のサービスまたは Unix アカウント間での認証情報の再利用を確認してください。

別の ID で動作するスケジュール実行クライアントがエンドポイントに認証情報を送信している場合、書き込み可能な web ログインハンドラーは別途調査が必要です。**稼働中の**ハンドラーへの書き込み権限、クライアントの実際のスケジュールとリクエスト経路、送信される認証情報の所有者、そしてそのアプリケーションパスワードが高い権限を持つオペレーティングシステムアカウントでも独立して有効かを確認してください。書き込み可能なページや定期実行プロセスがあるだけでは、その権限移行は立証されません。受動的なインベントリでは、ハンドラーを変更したりパスワードを収集したりせず、パスの権限とジョブのメタデータを報告してください。

Suricata の EVE JSON ログには、FTP イベントのログ記録が有効な場合、`command_data` とともに FTP の `USER` コマンドと `PASS` コマンドが記録されることもあります。関連部分をローカルで少量だけ調べる前に、ローテーション済みまたは圧縮済みのファイルも含めて `/var/log/suricata/eve*.json*` の読み取り可否を確認してください。EVE ファイルが読み取り可能でも、それは手掛かりにすぎません。FTP イベントが記録されていたこと、データに利用可能な認証情報が含まれること、権限境界を越えることを確認してください。共有列挙出力に `command_data` を表示しないでください。Suricata は[FTP イベントのフィールド](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)と[EVE のローテーションおよびファイル名のバリエーション](https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-output.html)を説明しています。

## 生成された Apache 設定とパイプログ

[remco](https://github.com/HeavyHorst/remco) は key/value backend を監視し、テンプレートを Apache 設定ファイルに展開して、reload コマンドを実行できます。実行中の remco プロセスの ID、設定されたテンプレートのソースと出力先、監視対象の key prefix、backend の値が `ServerName` などの Apache ディレクティブに直接挿入されるかを調べてください。ローカルの backend リスナーがあるだけでは、現在のユーザーが監視対象の key を書き込めるとは言えません。権限昇格を主張する前に、backend の認証と権限を確認してください。

書き込み可能な backend の値にエスケープされていない改行があると、意図されたディレクティブ値が複数の Apache ディレクティブに変わることがあります。[Apache のパイプログ](https://httpd.apache.org/docs/2.4/logs.html#piped)は特に注意が必要です。`|` コマンドを指定した `CustomLog` または `ErrorLog` は、親 httpd の ID（多くの場合 root）でヘルパーを起動し、`|$` を使うと Apache に shell を使わせます。列挙中は backend のデータを変更したりサービスを再起動したりせず、生成された設定と reload の経路を確認してください。パイプコマンドの引数にシークレットが含まれる場合があるため、コマンド全体を非公開にしてください。

## 認証とサービス ID

Monit の制御ファイルは通常 `~/.monitrc` または `/etc/monitrc` ですが、`monit -c` で別のパスを指定できます。読み取り可能なファイルには、web インターフェース用の `set httpd` と `allow user:password` の設定が含まれることがあり、ポート 2812 のローカルで待ち受けるケースがよくあります。内容を確認する前にファイルの所有者と権限を調べ、パスワードを共有列挙出力に含めないでください。web 認証情報で使えるのは、設定された Monit のロールに限られます。読み取り専用ユーザーは制御操作を実行できません。別の Unix アカウントへの権限昇格を主張するには、パスワードの再利用、または認証済みロールが実際に実行できる特権 Monit アクションを確認する必要があります。[Monit の制御ファイルと認証に関するドキュメント](https://www.mmonit.com/monit/documentation/monit.html)を参照してください。

Webmin では、`/etc/webmin/miniserv.conf` にサーバー設定が記録され、`/etc/webmin/webmin.acl` にユーザーがアクセスできるモジュールが記録されます。[Webmin のドキュメントではモジュール権限の境界が説明されています](https://webmin.com/docs/development/creating-modules/)。Unix パスワードや読み取り可能な ACL ファイルだけでは、Webmin セッションは得られません。実際の認証マッピング、到達可能な listener、認証済みアカウント、有効な Package Updates モジュールの権限、インストール済みコードまたはベンダーの修正、Webmin プロセスの ID を確認してください。1.910 までの影響を受けるビルドでは、[CVE-2019-12840](https://nvd.nist.gov/vuln/detail/CVE-2019-12840) により、そのモジュール権限を持つアカウントが更新ハンドラーを通じてコマンドを実行できました。受動的な列挙では、認証情報を表示したり更新を試みたりせず、設定パスと権限を報告してください。

```bash
find /etc/pam.d /etc/sssd /etc/postfix -maxdepth 2 -type f -ls 2>/dev/null
systemctl cat sssd postfix jenkins 2>/dev/null
getent passwd
```

- [PAM](pam-pluggable-authentication-modules.md) はサービス固有の認証を管理します。書き込み可能なポリシーまたはモジュールのパスを変更すると、ログイン動作が変わる可能性があります。
- LDAP/SSSD の設定から、ディレクトリのエンドポイント、バインド ID、アクセスルールが分かることがあります。バインドパスワードを入手できれば、現在の OS アカウントを超える LDAP クエリが可能な場合があります。正確なバインド ID とディレクトリ ACL をテストしてください。シークレットを調べる前にファイル権限を確認してください。[Linux Active Directory](../user-information/linux-active-directory.md) と [FreeIPA](freeipa-pentesting.md) では、チケットとディレクトリの利用方法を扱っています。
- Postfix のエイリアスは、受信メールをローカルコマンドにパイプできます。権限の低いユーザーが参照先のスクリプトを変更できる場合、メールの配信によって、そのユーザーのコードが配信時の ID で実行される可能性があります。この経路を主張する前に、エイリアスマップとスクリプトの所有権を確認してください。[SMTP and mail service testing](../../network-services-pentesting/pentesting-smtp/README.md) を参照してください。
- Jenkins などの CI サービスは、強力なローカルアカウントでジョブを実行する場合があります。パイプラインやプラグインをテストする前に、サービスユーザー、書き込み可能なジョブ/ワークスペースのパス、ローカル管理インターフェースを調べてください。また、**ジョブが利用できる認証情報**と、その認証情報で認証できるアカウントも確認してください。[SSH Agent step](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) を使う Pipeline は、Jenkins 自体が権限の低い Unix アカウントで動作していても、SSH 認証情報のユーザーとしてホストにアクセスできます。ホストの権限昇格を主張する前に、現在の Jenkins ID が `Job/Create`、`Job/Configure`、または Pipeline を変更できる別の有効な手段を持つこと、そのジョブで認証情報を利用できること、対象の SSH アカウントがその鍵を受け入れることを確認してください。認証情報の表示名や ID だけでは、これらの条件が満たされることは証明できません。Jenkins は、ジョブの作成者や、多くの場合はジョブの設定者が、そのスコープ内で利用可能な認証情報を任意に使用できると警告しています。そのため、[credential scope](https://www.jenkins.io/doc/book/security/credentials/) と [Pipeline trust](https://www.jenkins.io/doc/book/security/securing-org-folders-and-multibranch-pipelines/) はサービス UID と同じくらい重要です。共有する列挙結果には、認証情報の値や秘密鍵を含めないでください。

## Gogs リポジトリのファイル書き込み

ローカルの Gogs サービスでは、`gogs web` プロセスの所有者を、実行ファイルのバージョンおよび `custom/conf/app.ini` と照合してください。設定から、サービス ID、リポジトリのルート、リスナーアドレス、登録が無効になっているかどうかが分かることがあります。ループバック限定のリスナーでも、ローカルユーザーから到達できます。0.13.3 までの Gogs には、認証済みの `PutContents` におけるシンボリックリンク経由のファイル書き込み問題があります（[CVE-2025-8110](https://github.com/advisories/GHSA-mq8m-42gh-wq7r)）。リポジトリへの書き込み権限を持つユーザーは、シンボリックリンクをコミットした後、API の書き込み先をそのリンク経由にできます。結果として発生するファイルアクセスは Gogs プロセスの権限で行われるため、root 所有のインスタンスは速やかに対処する必要があります。利用可能な経路があると主張する前に、導入済みバージョンで修正されているか、認証要件を確認してください。API エラーが返っただけでは、ファイル書き込みに失敗した証拠にはなりません。

## Gitea のリポジトリ説明における XSS と特権ユーザーの閲覧

Gitea 1.22.0 では、リポジトリの説明に保存型 JavaScript を含めることができました（[CVE-2024-6886](https://github.com/advisories/GHSA-4h4p-553m-46qh)）。1.22.1 で修正されています。説明を編集できるユーザーは、より特権の高いユーザーがリポジトリを閲覧し、悪意のあるリンクを有効にした場合、そのブラウザーセッションに影響を与えられます。そのブラウザーの ID を利用して、非公開リポジトリの内容やその他のアプリケーションデータを漏洩させることができます。別個のローカル権限昇格には、そのコンテンツから利用できる認証情報や権限（再利用された管理者パスワードなど）が必要です。Gitea プロセスの所有者であることだけでは、root への影響は証明できません。この連鎖を主張する前に、導入済みバージョン、説明の編集権限、閲覧者の操作手順、実際のブラウザー操作を確認してください。

## Cobbler プロビジョニング API

Cobbler の管理サービスは XML-RPC API を公開しており、一般的にはポート `25151` で待ち受けています。影響を評価する前に、リスナーと `cobblerd` プロセスの所有者を確認してください。ループバック限定の API でも、ホスト上のユーザーからアクセスできる場合があります。`/etc/cobbler/modules.conf` の認証および認可モジュール、`/etc/cobbler/settings` または `/etc/cobbler/settings.yaml` のサービス設定、ならびに `/etc/cobbler/users.conf`、`/etc/cobbler/users.digest`、`/var/lib/cobbler/web.ss` の権限を確認してください。ダイジェストファイルと共有シークレットファイルには認証情報が含まれるため、既定では内容を表示せず、読み取り可能かどうかを記録してください。

```bash
ps -eo user,pid,args | grep '[c]obblerd'
ss -ltn 2>/dev/null | grep ':25151'
for file in /etc/cobbler/modules.conf /etc/cobbler/settings /etc/cobbler/settings.yaml \
            /etc/cobbler/users.conf /etc/cobbler/users.digest /var/lib/cobbler/web.ss; do
    [ -e "$file" ] && ls -l "$file"
done
```

**CVE-2024-47533** は、Cobbler 3.0.0〜3.2.2 および 3.3.0〜3.3.6 における XML-RPC authentication bypass です。共有シークレットの読み取りエラーによって予測可能な値 `-1` が返され、API はこれをパスワードとして受け入れていました。対応する修正版は 3.2.3 および 3.3.7 です。パッケージのバージョンは手掛かりにすぎません。脆弱性を報告する前に、実際にデプロイされているコードと、バックポートされた修正の有無を確認してください。

`cobblerd` が root として実行されている場合、認証済み API セッションは特権実行経路になり得ます。影響を受ける実装では、`background_import` がユーザー制御の `rsync_flags` をシェルコマンドに渡し、ユーザー制御の Cheetah autoinstall template のレンダリング時に Python が評価される可能性があります。どちらの経路もテストする前に、API の権限とインストール済みバージョンを確認してください。管理 API へのアクセスを制限し、authentication bypass にパッチを適用し、設定ファイルと認証情報ファイルはサービス管理者だけが読み取れるようにしてください。

## Motion と motionEye の設定

`/etc/motioneye/motioneye.conf` の `conf_path` を確認し、そのディレクトリにある `motion.conf` と少数の `camera-*.conf` ファイルを調べてください。読み取り可能な `# @admin_password` ハッシュが存在するかどうかを報告し、ハッシュ自体は出力しないでください。[古い motionEye リリースでは、これらのファイルに広範な読み取り権限が設定されていました](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-rhgp-6wq6-9j67)。この問題は 0.44.0 で修正されています。Motion の `webcontrol_port`、`webcontrol_parms`、`webcontrol_auth_method`、`webcontrol_localhost` の設定をまとめて確認してください。認証が無効な状態で高度な制御（`2` または `3`）が有効になっていると、ループバックリスナーであっても、ローカルユーザーが強力な操作を実行できる可能性があります。[Motion のドキュメントに値とデフォルトが記載されています](https://motion-project.github.io/motion_config.html)。

0.43.1b5 より前の motionEye で管理者セッションを取得されると、Motion が処理する際に、カメラのファイル名設定を通じてコマンド実行が可能になる場合がありました（[CVE-2025-60787](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)）。権限昇格を主張する前に、実行中のバージョン、サービスの実行ユーザー、利用可能な認証経路、およびカメラが設定されているかを確認してください。設定が存在するだけでは、サービスが稼働中または特権で実行中であることの証明にはなりません。

サービス名やインストール済みパッケージは、あくまで手掛かりにすぎません。権限境界は、到達可能な入力、プロセスの実行ユーザー、書き込み可能な設定、および最終的に制御されるコマンドやファイルの組み合わせによって決まります。

## ローカル AWS エミュレーターと保存された認証情報

ホスト上のユーザーは、公開されたループバックエンドポイントを通じて、コンテナ内で稼働する AWS 互換エミュレーターにアクセスできる場合があります。[Secrets Manager](https://docs.localstack.cloud/aws/services/secretsmanager/) または [KMS](https://docs.localstack.cloud/aws/services/kms/) へのアクセスを評価する前に、稼働中のリスナー、クライアントが選択しているエンドポイントとアカウント、およびエミュレーターにインストールされている認可設定を照合してください。LocalStack では、[IAM ポリシーの強制は独立した設定です](https://docs.localstack.cloud/aws/developer-tools/security-testing/iam-policy-enforcement/)。認証情報ファイル、IAM ポリシー、またはリスナーだけから、実効 API 権限を推測しないでください。インストール済みのリリースと設定での動作を確認してください。

保存されたシークレットがローカル権限昇格に役立つのは、現在の API ID でそのシークレットを取得でき、かつ別のより高い権限を持つアカウントが復元した認証情報を受け入れる場合に限られます。暗号化されたローカルデータも、ファイルの読み取り権限、対応する利用可能な KMS キーとアルゴリズム、および有効な復号権限が必要です。[非対称 KMS キー](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html)の場合、復号リクエストでは、データの暗号化に使用したアルゴリズムを指定する必要があります。通常の列挙でホストから自動収集する情報は、プロセス、リスナー、設定パス、ファイル権限の証拠にとどめてください。定常的な列挙中に、シークレットの値や復号後の平文を要求したり出力したりしないでください。
{{#include ../../banners/hacktricks-training.md}}
