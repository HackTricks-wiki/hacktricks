# プロセスの列挙とサービスパス

{{#include ../../banners/hacktricks-training.md}}

重要なのは、低い権限のユーザーが影響を与えられるデータやコードを、どの特権プロセスが利用するかです。プロセスツリー、実行中の環境、開いているファイル、候補となる各プロセスを起動したユニットまたはスクリプトを調べてください。

## プロセスと所有者を把握する

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

異なるユーザー間の親子関係は正常な場合もありますが、予期しない遷移があれば、親プロセスのコマンド、引数、実行ファイル、作業ディレクトリ、参照ファイルを確認してください。所有者とログイン状況を把握するには、[ユーザーとセッション](../user-information/user-and-session-triage.md)を参照してください。

### ローカル仮想マシンのコンソール

QEMUプロセスの`-spice`オプションを、リスニングアドレスとあわせて確認してください。[QEMUのドキュメント](https://www.qemu.org/docs/master/system/qemu-manpage.html)によると、`disable-ticketing`を指定すると、SPICEクライアントは認証なしで接続できます。ループバックにバインドされたリスナーにも、同じホスト上の他のユーザーが到達できる可能性があります。このコマンドラインを公開コンソールとみなす前に、実際のリスナー、認証オプション、ローカルからのアクセス可否を確認してください。コンソールの操作が影響するのは**ゲスト**です。ゲストアカウントの取得や起動状態の変更には、別途ゲスト側の条件が必要であり、仮想化ホストのroot権限が得られるわけではありません。パッシブな列挙中は、ゲストに接続したり再起動したりせず、プロセスの引数とソケットのメタデータを読み取ってください。

ローカルからアクセスできるWebインターフェースは、最初に取得したシェルからサービスアカウントのファイルにアクセスできなくても、そのアカウントの権限でコードを実行できる場合があります。たとえば、CVE-2023-0297は、信頼できないJavaScriptがPythonのimportを有効にした状態でJs2Pyに渡された際の、pyLoadの`/flash/addcrypted2`の処理に影響しました。[upstreamの修正](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)では`pyimport`が無効化されました。pyLoadプロセスを権限昇格の経路とみなす前に、実行中のプロセスの所有者、リスニングアドレス、エンドポイントの公開状況、インストール済みのパッチまたはベンダーによるバックポートを照合してください。プロセス名、開いているポート、パッケージのバージョンだけでは、脆弱な状態であることは証明できません。パッシブな列挙では、コード実行ペイロードを送信しないでください。

### 端末を共有する特権ログインシェル

独立した疑似端末を使わずに`su --login <user>`を実行する特権対話シェルは、低い権限のログインシェルと端末を共有したままになる場合があります。そのユーザーの起動ファイルを制御でき、そこから`TIOCSTI`を使って端末入力を注入できる場合、特権シェルの再開時にその入力が届く可能性があります。[util-linuxの`su`マニュアル](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES)では端末共有のリスクを説明し、対話的な利用では`su --pty`/`-P`を推奨しています。`su -c`は制御端末のない別セッションを開始します。このリスクの評価には、実際の親シェル、端末の関係、対象の起動ファイル、カーネルのポリシーを確認する必要があります。プロセス名や`su -l`引数だけでは、確認の手掛かりにすぎません。

確認したプロセスツリーとTTY列を調べた後、読み取り可能な起動スクリプト、および起動ファイルの所有者と権限を確認してください。Linuxでは、存在する場合、`/proc/sys/dev/tty/legacy_tiocsti`をポリシーの把握に利用できます。これが存在しないことは、安全の証明にはなりません。[Linuxの`TIOCSTI`マニュアル](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)によると、Linux 6.2以降では、このsysctlがfalseの場合に操作に`CAP_SYS_ADMIN`が必要となることがあります。ホストの列挙だけを目的にioctlを呼び出さないでください。

データベースアカウントが、ファイルシステムへの直接書き込み権限を持たずに、対象ユーザーの起動ファイルを変更できる場合があります。PostgreSQLのサーバー側の`COPY ... TO 'filename'`は、データベースサーバーのOSアカウントとして書き込みます。ただし、[PostgreSQLの制限](https://www.postgresql.org/docs/current/sql-copy.html)により、この形式を利用できるのはデータベースのスーパーユーザー、または`pg_write_server_files`などのロールに限られます。データベースロールとサーバーOS側のファイル権限の両方を確認してください。アプリケーションの接続文字列だけでは、ファイルを書き込む権限は得られません。この経路を評価する際は、特権ランチャーとデータベースアカウントの権限を分けて考えてください。

## ランタイムのアーティファクトを調べる

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

削除された実行ファイルや、削除後も開かれているファイルは、最後のファイルディスクリプタが閉じられるまで参照されたままです。これらには証拠やアクセス可能な秘密情報が保持されていることがあります。プロセスの環境変数やメモリに認証情報が含まれている場合もありますが、別のプロセスの読み取りは、所有者、`/proc` のマウントオプション、Yama ptrace ポリシー、その他のセキュリティ制御によって制限されます。関連する手法については、[ファイルディスクリプタ](../main-system-information/filesystem-links-and-file-descriptors.md)および[post-exploitation credential hunting](../post-exploitation/README.md)を参照してください。

保存された syscall trace も、ファイル権限による境界の一つです。[`strace` は syscall の引数を出力ファイルに記録します](https://man7.org/linux/man-pages/man1/strace.1.html)。そのため、[`execve` の引数](https://man7.org/linux/man-pages/man2/execve.2.html)を含む trace を読み取れると、特権ジョブがコマンドラインで渡したパスワードが漏れるおそれがあります。まず、現在のユーザーが対象の trace を読み取れることと、引数に実際に認証情報が含まれていることを確認してください。その後 Unix アカウントに切り替えるには、その認証情報がそこで受け入れられるという別の証明が必要です。通常の列挙では、すべての trace をスキャンしたり内容を表示したりせずとも、ファイルのメタデータを受動的な手掛かりとして活用できます。

## 特権 office automation ソケット

LibreOffice と OpenOffice は、`--accept=socket,host=<host>,port=<port>;urp;` 引数を通じて UNO API を公開できます。root が所有する office プロセスに到達可能なエンドポイントがある場合、権限の低いローカルユーザーが、そのプロセスのセキュリティコンテキストで API サービスを呼び出せる可能性があります。`SystemShellExecute` サービスには、システムコマンドを起動する操作が含まれています。loopback にバインドすればリモートからの到達性は制限できますが、別の制御でアクセスを阻止しない限り、ローカルユーザーは引き続きソケットに接続できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

プロセスの所有者、正確な `--accept` 引数、現在のリスニングアドレスとポートを照合します。bind に失敗した acceptor は手掛かりにすぎません。passive enumeration 中に API へ接続したり、API を呼び出したりしないでください。この条件を試すだけのために、特権付きの office インスタンスを起動するのも避けてください。

## 特権プロセスが使用する System V shared memory

root 所有の helper が、別のユーザーによる書き込みが可能な System V shared-memory segment を作成することがあります。その helper が後で、その segment のデータを shell command やその他の機密性の高い処理で信頼すると、実行ファイルとそのファイルが保護されていても、segment は権限境界をまたぎます。`shmget()` はフラグの下位 9 ビットからアクセス権限を取得します。mode `0666` では他のユーザーも書き込み可能ですが、`IPC_CREAT` フラグを指定してもアクセス権限は狭まりません。`ipcs -m` を使って稼働中の segment を受動的に調査し、所有者、mode、存続期間を、特権プロセスおよびその入力処理と照合します。world-writable な segment があるだけでは、command execution の証拠にはなりません。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V セグメントは、`/dev/shm` 配下の POSIX shared-memory ファイルとは別物です。一時的にしか存在しないセグメントは、単一の `ipcs` スナップショットには現れないことがあるため、出力が空でも、shared memory を使用する helper がないとは言い切れません。そのソースまたはバイナリの挙動と、それを起動する `sudo` ルールを確認してください。列挙中にセグメントを作らせるためだけに、特権 helper を実行してはいけません。[IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) では、namespace が可視性に及ぼす影響について説明しています。<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent のスクリプトチェック

Consul は、agent の OS identity でスクリプトによる health check を実行できます。agent が root として実行され、`enable_script_checks` が有効で、権限の低いユーザーがローカル HTTP API 経由でスクリプトチェック付きの service を登録できる場合、そのユーザーは root 権限で実行されるコマンドを起動できる可能性があります。API を `127.0.0.1` のみに bind しても、ローカルユーザーはアクセスできます。`enable_local_script_checks` 設定はより限定的で、HTTP API による登録で送信されたスクリプトチェックを除外します。Consul ACL が有効な場合、service の登録には `service:write` が必要です。`acl.default_policy=allow` の行だけでは、匿名ユーザーが登録できることの証明にはなりません。agent の実行 identity、読み込まれた設定、API の bind 先、認可設定をまとめて確認してください。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

実行中の agent の `-config-dir` および `-config-file` 引数をたどって該当する設定を確認し、script-check と ACL のフィールド名および設定のみを調べてください。設定ファイルには gossip key や token が含まれている場合もあります。共有ログに貼り付けないでください。この状況を列挙するだけの目的で、サービスを登録したり health check を実行したりしないでください。

低権限ユーザーが root で実行されている agent の `-config-dir` で指定されたディレクトリに対して**書き込み権限と検索権限**を持つ場合、別のローカルファイルパスが存在します。そのディレクトリから新しい `.hcl` または `.json` のサービス定義が読み込まれる可能性があります。ディレクトリの検索権限と書き込み権限があれば、ディレクトリ一覧の表示が拒否されていてもファイルを追加できる場合があります。root としてコマンドを実行できるか確認するには、agent が実際にそのディレクトリを読み込むこと、**実効的な** script-check 設定がローカル定義を許可していること、その定義が読み込まれること、そして agent が root 権限を保持していることを確認してください。[Consul のドキュメント](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations)には、再読み込み可能な設定と health check 定義が記載されています。script check の有効化自体には再起動が必要な場合があるため、インストールされているバージョンの動作を確認してください。ACL で agent が保護されている場合、[`consul reload` には `agent:write` が必要です](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent)。KV の書き込み権限だけでは、この権限を得られません。書き込み可能なディレクトリのメタデータは確認のきっかけとして扱い、許可された再読み込み、再起動、またはコマンド実行の証拠とみなさないでください。設定を書き込んだり API を呼び出したりせずに、パス、権限、ポリシーを調べてください。

## サービス実行チェーンをたどる

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

ユニット、drop-in、`EnvironmentFile=`、ヘルパースクリプト、相対パスで指定されたコマンド、書き込み可能なディレクトリ、socket activationを確認します。root所有のユニットでも、ユーザーが書き込み可能な設定ファイルやスクリプトを読み込む場合は安全とは限りません。[任意のファイル書き込み](../interesting-files-permissions/write-to-root.md)のページでは、サービスやユニットを悪用する一般的な経路を扱っています。1回の`ps`一覧では見つからない短時間のジョブは、[pspy](https://github.com/DominicBreuker/pspy)やaudit／プロセステレメトリで監視します。

カスタムの**xinetd**サービスでは、有効なstanzaの`server`、`user`、アクセス制御を、実際に待ち受けているソケットと正確な実行ファイルに照らし合わせます。[`user`設定](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html)は起動されるプロセスの実行ユーザーを選択します。一方、実行ファイルにset-user-ID bitが設定されている場合、[`execve`がその遷移を許可すれば](https://man7.org/linux/man-pages/man2/execve.2.html)、実効ユーザーが別途変更されることがあります。信頼できない入力を受け付ける、外部から到達可能な特権バイナリは、固定バッファーに対する上限のない[`scanf`の文字列変換](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)など、メモリ安全性のバグがないか、オフラインでソースや逆アセンブル結果を確認する価値があります。サービスのマッピングやset-user-IDのメタデータは手掛かりであり、そのようなバグの証明ではありません。受動的な列挙中にクラッシュを起こす入力を送信したり、実行中の特権サービスをデバッグしたりしないでください。

ソースを読めるカスタムの特権リスナーでは、[`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html)などのコピー処理で、呼び出し元が制御できる長さをすべて確認します。現在の書き込みインデックスが固定バッファーの範囲内であることを確認しても、**コピー長**が残りの領域に収まるとは限りません。インデックスが範囲内であることを確認したうえで、`copy_length <= capacity - index`を検証し、符号の扱いと算術オーバーフローも確認してください。これは、入力がその処理に到達し、低い権限のユーザーがリスナーにアクセスでき、プロセスがより高い実効IDを保持している場合に限った調査の手掛かりです。列挙中は、ソースとプロセスのメタデータをオフラインで調べ、実行中のサービスにクラッシュを起こす入力を送らないでください。

**Upstart**を使用するシステムでは、システムジョブの定義が`/etc/init/*.conf`に置かれていることがあります。現在のユーザーがジョブファイルを書き換えられることが問題になるのは、稼働中のinitデーモンがそのファイルを実際に読み込み、`script`または`exec` stanzaがより高い権限で実行され、そのユーザーが許可された`initctl`コマンドまたは他の実際のトリガーを通じてジョブを起動できる場合です。sudoで`initctl`の実行が許可されているだけでは、ジョブファイルを書き換えられることや、変更したジョブが実行されることの証明にはなりません。列挙中にジョブを編集したり起動したりせず、該当するジョブファイルの正確な権限、実効的な実行ユーザー設定、稼働中のデーモン、トリガーを確認してください。[Upstartのジョブ設定](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html)および[`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html)のマニュアルを参照してください。

システムの[起動ジョブがそのパスを実際に読み込む](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf)場合、`/etc/autologin/passwd`のような自動ログイン用パスワードファイルを読み取れることは、認証情報漏えいの手掛かりになります。起動ジョブがインストールされ、そのファイルを使用していることを確認したうえで、そのパスワードが別のローカルアカウントやサービスでも有効かを個別に検証します。ファイル名だけではパスワードの使い回しは証明されません。パスとアクセス権のメタデータを記録し、パスワードを共有の列挙出力に含めないでください。

ユニットの`ExecStart=`やスケジュールされたコマンドから、一覧を取得できないディレクトリ内のスクリプトの正確なパスが分かることがあります。[ディレクトリのsearch権限](https://man7.org/linux/man-pages/man7/path_resolution.7.html)があれば、現在のIDでその既知のパスをたどれる場合があります。ディレクトリ一覧の取得に失敗したからといって保護されていると決めつけず、すべての親ディレクトリにsearch権限があり、ファイルにread権限があることを確認してください。読み取り可能なスクリプトに、他のアカウントへ移るための認証情報が含まれている場合もありますが、その認証情報が引き続き有効で、移行先でも独立して受け入れられる必要があります。秘密の値を共有ログに出力せず、パスと権限の証拠を記録してください。

スケジュールされたCommonJSのNode.jsスクリプトでは、スクリプト自体が読み取り専用でも、`require('package')`のようなbare importを確認します。[Nodeは、import元ファイルの隣接ディレクトリから親ディレクトリへ順に`node_modules`を検索し](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)、その後に設定済みのglobal pathを検索します。低い権限のユーザーが、これらの親ディレクトリのいずれかに**書き込みおよびsearchできる**場合、より優先順位の高い場所に一致するパッケージを作成できる可能性があります。該当するimportが実際に処理されること、選択されるパッケージが組み込みモジュールではないこと、対象のパスを作成または変更できること、インストール済みランタイムでその場所にモジュールが解決されること、より高い権限のジョブが今後そのモジュールを読み込むことを確認してください。親ディレクトリが書き込み可能というだけなら調査の手掛かりにすぎません。モジュールを設置したりジョブを実行させたりせず、スクリプトとスケジューラーを受動的に調べてください。

自動化されたジョブが別のOS IDでパッケージをインストールする場合、プライベートPythonパッケージインデックスも信頼境界になります。該当するジョブと実行ユーザーを、設定済みのインデックス、選択されるパッケージ名、低い権限のユーザーがジョブによって実際にインストールされるパッケージを公開または置き換えられるかどうかと照合します。source distributionのビルドでは、インストーラーのIDでビルドバックエンドや従来の`setup.py`が実行される場合があります。インストール済みパッケージをimportするのは別の実行経路です。インデックスの待ち受け、読み取り可能なアップロード用パスワードハッシュ、パッケージファイル名だけでは、その一連の経路は証明されません。列挙中はアップロードやインストールを行わず、ジョブ、インデックスの認可、パッケージの来歴を調べてください。[pipのビルドシステムインターフェイス](https://pip.pypa.io/en/stable/reference/build-system/)と[安全なインストールのガイダンス](https://pip.pypa.io/en/stable/topics/secure-installs/)を参照してください。

特権エージェントが、別のWebサービスやコンテナによって管理されるタスクキューをポーリングする場合があります。低い信頼レベルのIDでサービスのタスクデータベースに書き込めるなら、その行が実際にエージェントへ配信されるか、command taskがエージェントのOS IDで実行されるかを確認します。データベースへの書き込み権限、対象のセッションまたはrouting key、実際のポーリング、タスク認可、エージェントの実効ユーザーをそれぞれ確認してください。コンテナ内のrootは、それだけでホストのroot権限を意味しません。攻撃者が制御するタスクデータをホスト特権のコンシューマーが実行する場合にのみ、境界を越えます。列挙中にキューを変更したりタスクを送信したりせず、プロセス、データベースファイル、サービスのメタデータを調べてください。

スケジュールされたジョブが、アプリケーションデータベースの設定行からコマンドを読み取る場合もあります。低い権限のデータベースロールでその特定の行を変更できること、変更後に稼働中のジョブがその行を読み取ること、値がより高いOS IDでshellまたは同等のコマンド実行機構に渡されることを確認してください。データベースへの書き込み権限や、コマンドに見える値だけでは実行は証明されません。受動的な列挙中に行を変更せず、ジョブと権限を調べてください。

キューに入るメッセージには、コードではなくURLが含まれることもあります。特権コンシューマーがそのURLを取得し、応答をLuaなどの実行可能なプラグインとして読み込む場合、パブリッシャーが該当するexchangeとrouting keyに対して持つ権限、消費されるキューへのbinding、取得からプラグイン読み込みまでの経路、ワーカーの実効IDを確認してください。[RabbitMQはexchangeを通じて公開メッセージをルーティングします](https://www.rabbitmq.com/docs/exchanges)。ブローカーの待ち受けや有効なログイン情報だけでは、このワーカーへの配信は証明されません。平文のブローカー認証情報を捕捉できた場合も、それを利用するには実際にパケットキャプチャへアクセスでき、通信が読み取り可能である必要があります。また、それだけではpublish権限の証明にはなりません。Luaプラグインが[`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute)でshellコマンドを実行できるのは、実行環境でそのAPIが利用可能な場合に限られます。受動的な列挙中は、通信をキャプチャしたり、メッセージを公開したり、プラグインを取得したりせず、設定とコードを調べてください。

特権PythonサービスがローカルのHTTPまたはsocket endpointを公開している場合、ファイル権限により変更できなくても、読み取り可能なスクリプトから入力がコードに到達する経路が分かることがあります。稼働中のプロセスとユニットのIDを、該当するスクリプト、リスナー、ルートの認可、呼び出し元が制御できるフィールドと照合します。次に、パースと検証から動的な`eval()`または`exec()`のsinkまで、そのフィールドの流れを追います。特に、リクエストのテキストから新しいf-stringを作って評価すると、攻撃者が指定した置換フィールドがPython式として解釈される可能性があります（[Pythonの`eval`に関する警告](https://docs.python.org/3/library/functions.html#eval)、[f-stringの動作](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)）。`eval`の単独の一致やloopbackへのbindだけでは、信頼できない呼び出し元がsinkに到達できる証明にはなりません。列挙中はテスト用payloadを送信せず、実際のデータフローとアクセス制御を確認してください。

そのルートにある署名付きリクエストのゲートも、個別に調査する必要があります。読み取り可能なソースから、署名鍵の出力空間が明らかに小さい、または予測可能であることが分かり、サービスが有効な署名サンプルを公開している場合、その署名は特権`eval()` sinkを保護できなくなっている可能性があります。鍵の導出方法と検証処理、稼働中のサービスのIDとローカルからの呼び出し可否、署名されたフィールドがsinkに到達するかを確認してください。Pythonの[`random`モジュール](https://docs.python.org/3/library/random.html)のimportや署名サンプルだけでは、いずれの条件も証明されません。Pythonは、`__builtins__`を制限しても、信頼できない`eval()`入力に対する[セキュリティ境界にはならない](https://docs.python.org/3/library/functions.html#eval)と警告しています。鍵の分析はオフラインで行い、受動的な列挙中に偽造リクエストを送信しないでください。

空でも書き込み可能な`/etc/systemd/system/<unit>.service.d`ディレクトリは、ユニットファイルと既存のdrop-inがすべて保護されていても問題になることがあります。ユーザーが新しい`.conf` overrideを作成できるためです。現在のIDでそのディレクトリに書き込みおよびsearchできること、ユニットが読み込まれていてrootとして実行されること、daemon reload後にrestartされるかを確認してください。reloadまたはrestartの権限、timer、あるいは後の起動によって変更が有効になることがあります。ディレクトリへの書き込み権限だけでは、直ちに実行されるわけではありません。

稼働中のサービスでは、ユニットの`[Service]`セクションにある`EnvironmentFile=`のパスを文字どおり追跡します。ファイル名が`.env`で始まらないファイルも対象です。低い権限のユーザーがそのファイルを読める場合、`API_TOKEN`や`APP_SECRET_KEY`など、認証情報らしいキー名を列挙し、値を共有ログに出力しないでください。実効的なユニットを評価する際は、drop-in overrideと任意指定を表す`-`接頭辞も確認します。読み取り可能であることは認証情報漏えいの手掛かりです。権限昇格につなげるには、その値が特権操作に対して有効でなければなりません。

### 信頼できないアップロードの特権処理

rootで実行されるファイル監視プロセスが、ユーザー書き込み可能なアップロードディレクトリ内のファイルを、短時間だけ動作するパーサーや展開ツールに渡すことがあります。稼働中の監視プロセスの親スクリプトまたはサービスをたどり、対象ディレクトリ、そこにファイルを配置できるユーザー、子プロセスのコマンドと引数、子プロセスの実行IDを確認します。プロセスのスナップショットでは、監視プロセスは見えても、アップロードの合間に動作する展開プロセスを見逃すことがあります。受動的な列挙中にテスト用payloadを置いたり、監視プロセスを起動させたりしないでください。

具体例として、Binwalkの展開モード（`-e`）で攻撃者が制御するPFSデータを処理するケースがあります。[CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617)では、PFS extractorが意図されたディレクトリの外に書き込みでき、Binwalkが後で読み込む可能性のあるプラグインのパスにも書き込めました。upstreamは[2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4)で修正しましたが、ディストリビューションによるbackportのため、表示上は古いバージョンのままの場合があります。適用可否を判断する前に、[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510)などで、インストール済みパッケージのセキュリティ状況を確認してください。Binwalkがインストールされているだけでは、権限昇格経路の証明にはなりません。低い権限のユーザーが制御できる入力に対して、より高い権限のプロセスが実際に展開処理を実行する必要があります。

### ローカル依存関係を使うスケジュール済みビルド

スケジュールされた`cargo run`は、ジョブの実行ユーザーでソースを再コンパイルします。マニフェストにある`{ path = "..." }`形式のローカル依存関係について、メインのcrateだけでなく、各依存関係のソースと親ディレクトリの権限も調べてください。低い権限のユーザーがCargoによってコンパイルされる依存関係を変更でき、そのコンパイル結果をスケジュール済みジョブが実行する場合、コードはその実行ユーザーとして動作できます。実効的なスケジューラーコマンド、作業ディレクトリ、依存関係の解決方法、再ビルドが行われるかを確認してください。それ以外の場所に書き込み可能なRustソースがあるだけなら、手掛かりにすぎません。受動的な初期調査には、マニフェストとパスのメタデータを読むだけで十分です。[Cargoのpath依存関係に関するドキュメント](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)を参照してください。

## Xvfbのフレームバッファーファイル

`Xvfb -fbdir <directory>`は、仮想スクリーン用に`Xvfb_screen<n>`という名前のmemory-mappedファイルを使用します。別のユーザーが実行中のXvfbプロセスで指定したディレクトリ内のスクリーンファイルを、現在のユーザーが読み取れる場合、そのフレームバッファーからユーザーのデスクトップ内容が見える可能性があります。プロセス、ファイル所有者、権限を併せて確認してください。ファイルが読めるだけでは、有用な内容がスクリーンに表示されているとは証明できません。共有の列挙出力に画像データをコピーせず、まずパスとメタデータを調べてください。[Xvfbのマニュアル](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html)に`-fbdir`の動作が記載されています。

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` マニュアル](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` マニュアル](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` マニュアル](https://man.openbsd.org/ipcs.1)
4. [Consul agentの設定: スクリプトチェック](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agentのサービス登録API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACLの設定](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOfficeヘルプ: 外部APIクライアント用のソケットを開く](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
