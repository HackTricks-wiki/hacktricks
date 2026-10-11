# プロセスの列挙とサービスパス

{{#include ../../banners/hacktricks-training.md}}

重要なのは、低い権限のユーザーが影響を与えられるデータやコードを、どの特権プロセスが使用するかです。プロセスツリー、実行中の環境、開いているファイル、各候補を起動したユニットまたはスクリプトを調べます。

## プロセスと所有者を把握する

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

異なるユーザー間の親子関係は正常な場合もありますが、予期しない遷移があれば、親プロセスのコマンド、引数、実行ファイル、作業ディレクトリ、参照ファイルを確認してください。[ユーザーとセッション](../user-information/user-and-session-triage.md)を使って、所有者とログイン状況を判断します。

### ローカル仮想マシンのコンソール

QEMUプロセスの`-spice`オプションを、リスニングアドレスとあわせて確認します。[QEMUのドキュメント](https://www.qemu.org/docs/master/system/qemu-manpage.html)によると、`disable-ticketing`を指定すると、SPICEクライアントは認証なしで接続できます。ループバックにバインドされたリスナーでも、同じホスト上の他のローカルユーザーから到達できる可能性があります。コマンドラインからコンソールが公開されていると判断する前に、実際のリスナー、認証オプション、ローカルからのアクセス可否を確認してください。コンソールの操作対象は**ゲスト**です。ゲストアカウントの取得や起動状態の変更には、別途ゲスト側の条件が必要であり、仮想化ホストのroot権限が得られるわけではありません。パッシブ列挙中は、ゲストに接続したり再起動したりせず、プロセス引数とソケットのメタデータを確認してください。

ローカルからアクセスできるWebインターフェースは、最初のシェルからサービスアカウントのファイルにアクセスできない場合でも、そのアカウント権限でコードを実行できることがあります。たとえばCVE-2023-0297では、信頼できないJavaScriptがPythonインポートを有効にしたJs2Pyに渡された際の、pyLoadの`/flash/addcrypted2`処理が影響を受けました。[上流の修正](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)では`pyimport`が無効化されました。pyLoadプロセスを権限昇格の経路とみなす前に、実行中のプロセス所有者、リスニングアドレス、エンドポイントの公開状況、インストール済みパッチまたはベンダーのバックポートを照合してください。プロセス名、開いているポート、パッケージのバージョンだけでは、脆弱な状態である証拠にはなりません。パッシブ列挙中にコード実行ペイロードを送信しないでください。

### 端末を共有する特権ログインシェル

独立した疑似端末を使わずに`su --login <user>`を実行する特権対話型シェルでは、端末が低権限ユーザーのログインシェルと共有されたままになることがあります。そのユーザーが起動ファイルを制御でき、そこにあるコードが`TIOCSTI`を使って端末入力を注入できる場合、特権シェルの再開時にその入力が届く可能性があります。[util-linuxの`su`マニュアル](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES)では、端末共有のリスクを説明し、対話的な使用には`su --pty`/`-P`を推奨しています。`su -c`は、制御端末のない別セッションを開始します。このリスクを評価するには、実際の親シェル、端末の関係、対象となる起動ファイル、カーネルのポリシーを確認する必要があります。プロセス名や`su -l`引数だけでは、確認の手掛かりにしかなりません。

確認されたプロセスツリーとTTY列を調べたうえで、読み取り可能なランチャー、および起動ファイルの所有者と権限を確認してください。Linuxでは、存在する場合、`/proc/sys/dev/tty/legacy_tiocsti`からポリシーを判断する手掛かりが得られますが、これが存在しないからといって安全とは限りません。[Linuxの`TIOCSTI`マニュアル](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)によると、Linux 6.2以降では、このsysctlがfalseの場合、操作に`CAP_SYS_ADMIN`が必要となることがあります。ホストの列挙目的でioctlを呼び出さないでください。

データベースアカウントが、ファイルシステムへの直接の書き込み権限なしに、対象ユーザーの起動ファイルを変更できる場合があります。PostgreSQLのサーバー側の`COPY ... TO 'filename'`は、データベースサーバーのOSアカウントとして書き込みますが、[PostgreSQLの制限](https://www.postgresql.org/docs/current/sql-copy.html)により、この形式を使えるのはデータベースのスーパーユーザー、または`pg_write_server_files`などのロールに限られます。データベースロールとサーバーOS上のファイル権限の両方を確認してください。アプリケーションの接続文字列だけでは、ファイルへの書き込み権限は得られません。この連鎖を評価するときは、特権ランチャーとデータベースアカウントの権限を分けて考えてください。

## 実行時アーティファクトを調べる

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

削除済みの実行ファイルや、削除済みでも開かれたままのファイルは、最後のファイルディスクリプタが閉じられるまで参照されたままです。証拠やアクセス可能な秘密情報が保持されている可能性があります。プロセスの環境変数やメモリに認証情報が含まれていることもありますが、別のプロセスを読み取れるかどうかは、所有者、`/proc` のマウントオプション、Yama ptrace ポリシー、その他のセキュリティ制御によって制限されます。関連する手法については、[ファイルディスクリプタ](../main-system-information/filesystem-links-and-file-descriptors.md)と[post-exploitation credential hunting](../post-exploitation/README.md)を参照してください。

保存された syscall トレースにも、ファイル権限の境界があります。[`strace` は syscall の引数を出力ファイルに記録するため](https://man7.org/linux/man-pages/man1/strace.1.html)、[`execve` の引数](https://man7.org/linux/man-pages/man2/execve.2.html)を読み取れるトレースから、特権ジョブがコマンドラインで渡したパスワードが漏れる可能性があります。まず、現在のユーザーがそのトレースを読み取れることと、その引数に実際に認証情報が含まれていることを確認してください。その後、Unix アカウントを切り替えるには、その認証情報が移行先で受け入れられることを別途証明する必要があります。ファイルのメタデータは、通常の列挙時にすべてのトレースをスキャンしたり内容を出力したりせずに得られる、有用な受動的手がかりです。

## 特権で動作するオフィス自動化ソケット

LibreOffice と OpenOffice は、`--accept=socket,host=<host>,port=<port>;urp;` 引数を通じて UNO API を公開できます。到達可能なエンドポイントを持つ root 所有のオフィスプロセスがある場合、権限の低いローカルユーザーが、そのプロセスのセキュリティコンテキストで API サービスを呼び出せる可能性があります。`SystemShellExecute` サービスには、システムコマンドを起動する操作が含まれています。loopback にバインドすればリモートからの到達性は制限されますが、別の制御によってアクセスが防がれない限り、ローカルユーザーは引き続きソケットに到達できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

プロセスの所有者、正確な `--accept` 引数、現在の待ち受けアドレスとポートを照合します。bind に失敗した設定済み acceptor は手掛かりにすぎません。受動的な列挙中に API へ接続したり、API を呼び出したりしないでください。この状況をテストするだけのために、特権を持つ office インスタンスを起動するのは避けてください。

## 特権プロセスが使用する System V shared memory

root 所有のヘルパーが、別のユーザーから書き込み可能な System V shared-memory セグメントを作成することがあります。そのヘルパーが後に、そのセグメントのデータを shell command やその他の機密性の高い操作で信頼する場合、実行ファイルやそのファイルが保護されていても、セグメントは権限境界をまたぎます。`shmget()` はフラグの下位 9 ビットからアクセス権限を取得します。モード `0666` では他のユーザーも書き込み可能ですが、`IPC_CREAT` フラグによってその権限が制限されることはありません。`ipcs -m` を使って稼働中のセグメントを受動的に調査し、所有者、モード、存続期間を、特権プロセスおよびその入力処理と照合します。全ユーザーが書き込み可能なセグメントが存在するだけでは、コマンド実行の証明にはなりません。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V segments は、`/dev/shm` にある POSIX shared-memory files とは別物です。一瞬だけ作成される segment は、単一の `ipcs` snapshot には表示されないことがあるため、出力が空でも shared memory を使う helper の存在は否定できません。ソースまたはバイナリの動作と、それを起動する `sudo` rule を確認してください。列挙中に segment を表示させるためだけに、特権 helper を実行してはいけません。[IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md)では、namespace が可視性に与える影響を説明しています。<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul は、agent の operating-system identity で script health checks を実行できます。agent が root として実行され、`enable_script_checks` が有効で、権限の低い user がローカル HTTP API 経由で script check 付きの service を登録できる場合、その user が root 権限で実行される command を実行させられる可能性があります。API を `127.0.0.1` のみに bind しても、ローカル user は引き続きアクセスできます。`enable_local_script_checks` 設定はより限定的で、HTTP API 経由で登録された script check を除外します。Consul ACL が有効な場合、service の登録には `service:write` が必要です。`acl.default_policy=allow` の行だけでは、anonymous caller が登録できることの証明にはなりません。agent の実際の identity、読み込まれた設定、API の bind 設定、および認可をあわせて確認してください。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

稼働中の agent の `-config-dir` と `-config-file` 引数をたどって該当する設定を確認し、script-check と ACL のフィールド名および設定だけを調べます。設定ファイルには gossip keys や tokens が含まれている場合もあるため、共有ログに貼り付けないでください。この条件を列挙するだけの目的で、サービスを登録したり health check を実行したりしないでください。

root で実行される agent の `-config-dir` で指定されたディレクトリに、権限の低いユーザーが**書き込みと検索の両方を行える**場合、別のローカルファイル経由の経路が存在します。そのディレクトリから、新しい `.hcl` または `.json` のサービス定義が読み込まれる可能性があります。ディレクトリの検索と書き込みが可能なら、ディレクトリ一覧の表示が拒否されていてもファイルを追加できる場合があります。root でコマンドを実行できるか確認するには、agent が実際にそのディレクトリを読み込んでいること、**実効的な** script-check 設定がローカル定義を許可していること、その定義が読み込まれていること、そして agent が root 権限を維持していることを確認してください。[Consul のドキュメント](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations)では、再読み込み可能な設定と health-check 定義が説明されています。script check の有効化自体には再起動が必要な場合があるため、インストールされているバージョンの動作を確認してください。ACL で agent が保護されている場合、[`consul reload` には `agent:write` が必要です](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent)。KV の書き込み権限だけでは、これを行えません。書き込み可能なディレクトリのメタデータは確認の手掛かりであり、許可された再読み込み、再起動、またはコマンド実行の証明ではありません。設定を書き込んだり API を呼び出したりせず、パス、権限、ポリシーを確認してください。

## サービス実行チェーンをたどる

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

ユニット、drop-in、`EnvironmentFile=`、ヘルパースクリプト、相対コマンド、書き込み可能なディレクトリ、socket activationを確認します。root所有のユニットでも、ユーザーが書き込み可能な設定ファイルやスクリプトを読み込む場合は安全とは限りません。[arbitrary file write](../interesting-files-permissions/write-to-root.md)のページでは、サービスやユニットを悪用する一般的な経路を解説しています。1回限りの`ps`一覧では見逃す短命なジョブは、[pspy](https://github.com/DominicBreuker/pspy)やaudit/process telemetryで監視します。

カスタムの**xinetd**サービスでは、有効なstanzaの`server`、`user`、アクセス制御を、実際のlistenerと正確な実行ファイルに照らし合わせます。[`user`設定](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html)は起動されるプロセスのIDを選びます。一方、[`execve`がその遷移を許可する](https://man7.org/linux/man-pages/man2/execve.2.html)場合、実行ファイルのset-user-IDビットによって実効IDが別途変わることがあります。信頼できない入力を受け付ける、到達可能な特権バイナリは、固定バッファーへの制限のない[`scanf`文字列変換](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)など、メモリ安全性のバグがないか、オフラインでソースや逆アセンブル結果を確認する価値があります。サービスの対応関係やset-user-IDのメタデータは手掛かりであり、そのようなバグの証拠ではありません。受動的な列挙中にクラッシュを起こす入力を送ったり、稼働中の特権サービスをデバッグしたりしないでください。

ソースを読めるカスタム特権listenerでは、[`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html)などのコピー操作で使われる、呼び出し元が制御可能な長さをすべて確認します。現在の書き込みインデックスが固定バッファー内にあることを確認しても、**コピー長**が残りの領域に収まるとは限りません。インデックスが範囲内であることを確認したうえで、`copy_length <= capacity - index`を検証し、符号の扱いと算術オーバーフローも確認してください。これは、入力が実際にその処理へ到達し、低権限ユーザーがlistenerにアクセスでき、プロセスがより高い実効IDを保持している場合に限られる調査の手掛かりです。列挙中に稼働中のサービスへクラッシュを起こす入力を送らず、ソースとプロセスのメタデータをオフラインで確認してください。

**Upstart**を使うシステムでは、システムジョブの定義が`/etc/init/*.conf`に置かれる場合があります。現在のユーザーがジョブファイルに書き込めることが問題となるのは、稼働中のinitデーモンがそのファイルを読み込み、`script`または`exec` stanzaがより高い権限のIDで実行され、さらにユーザーが許可された`initctl`コマンドまたは別の実際のトリガーでジョブを起動できる場合です。sudoで`initctl`が許可されているだけでは、ジョブファイルに書き込めることも、変更したジョブが実行されることも証明できません。列挙中に編集や起動をせず、対象のジョブファイルの権限、実効的な実行ユーザー設定、稼働中のデーモン、トリガーを確認してください。[Upstartのジョブ設定](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html)と[`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html)のマニュアルを参照してください。

システムの[boot jobがそのパスを実際に読み込む](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf)場合、`/etc/autologin/passwd`のような読み取り可能なautologinパスワードファイルは、認証情報露出の手掛かりになります。boot jobがインストールされ、そのファイルを使うことを確認したうえで、そのパスワードが別のローカルアカウントやサービスでも有効かを個別に検証します。ファイル名だけではパスワードの再利用を証明できません。パスワードを共有の列挙出力に含めず、パスとアクセスのメタデータを記録してください。

ユニットの`ExecStart=`やスケジュール済みコマンドから、一覧表示できないディレクトリ内にあるスクリプトの正確なパスが分かることがあります。[ディレクトリの検索権限](https://man7.org/linux/man-pages/man7/path_resolution.7.html)があれば、現在のIDで既知のパスをたどれる場合があります。ディレクトリ一覧の取得に失敗したからといってアクセスできないと判断せず、すべての親ディレクトリに検索権限があり、ファイルに読み取り権限があることを確認してください。読み取り可能なスクリプトに転送用の認証情報が含まれている場合もありますが、別アカウントに移るには、その認証情報が有効であり、移行先で別途受け入れられる必要があります。秘密の値を共有ログに出さず、パスと権限の根拠を記録してください。

スケジュールされたCommonJS Node.jsスクリプトでは、スクリプト自体が読み取り専用でも、`require('package')`のようなbare importを確認します。[Nodeは、import元のファイルとその親ディレクトリにある`node_modules`を検索](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)してから、設定済みのグローバルパスを参照します。低権限ユーザーが親ディレクトリのいずれかに**書き込みと検索**の両方を行える場合、先に見つかるパッケージを作成できる可能性があります。対象のimportが実行されること、選択されたパッケージが組み込みモジュールではないこと、該当パスに作成または変更が可能なこと、インストール済みランタイムでその場所からモジュールが解決されること、そして将来の実行時により高い権限のジョブがそのモジュールを読み込むことを確認してください。書き込み可能な親ディレクトリのメタデータは調査の手掛かりにすぎません。モジュールを配置したりジョブを起動したりせず、スクリプトとスケジューラーを受動的に確認してください。

自動ジョブが別のOS IDでパッケージをインストールする場合、private Python package indexも信頼境界となります。対象のジョブと実行ユーザーを、設定されたindex、選択されるパッケージ名、低権限ユーザーがジョブに実際にインストールされるパッケージを公開または置き換えられるかどうかと照合してください。source distributionのビルドでは、インストーラーのIDでbuild backendや旧式の`setup.py`が実行される場合があります。インストール済みパッケージのimportは別の実行経路です。indexのlistener、読み取り可能なアップロード用パスワードハッシュ、パッケージのファイル名だけでは、この一連の経路が成立する証拠にはなりません。列挙中にアップロードやインストールをせず、ジョブ、indexの認可、パッケージのprovenanceを確認してください。[pipのbuild-systemインターフェース](https://pip.pypa.io/en/stable/reference/build-system/)と[安全なインストールのガイダンス](https://pip.pypa.io/en/stable/topics/secure-installs/)を参照してください。

特権agentが、別のweb serviceやcontainerで管理されるtask queueをポーリングする場合があります。低信頼のIDでそのサービスのtask databaseに書き込めるなら、その行が実際にagentへ配信されるか、command taskがagentのOS IDで実行されるかを確認してください。databaseへの書き込み権限、対象のsessionまたはrouting key、ポーリングの稼働状況、taskの認可、agentの実効ユーザーをそれぞれ確認します。container内のrootは、それだけでホストのrootアクセスを意味しません。ホスト特権を持つconsumerが攻撃者制御のtaskデータを実行する場合に限り、境界を越えます。列挙中にqueueを変更したりtaskを送信したりせず、プロセス、databaseファイル、サービスのメタデータを確認してください。

定期ジョブが、代わりにapplication databaseの設定行からコマンドを読み込むこともあります。低権限のdatabase roleがその行を実際に変更できること、変更後に稼働中のジョブがそれを読み込むこと、その値がより高いOS IDでshellまたは同等のコマンド実行機構に渡ることを確認してください。databaseへの書き込み権限やコマンドに見える値だけでは、実行される証拠になりません。受動的な列挙中に行を変更せず、ジョブと権限を確認してください。

キュー内のメッセージにコードではなくURLが含まれる場合もあります。特権consumerがそのURLを取得し、応答をLuaなどの実行可能なpluginとして読み込むなら、publisherが対象のexchangeとrouting keyに対する権限を持つこと、consumerが使用するqueueへのbinding、取得とplugin読み込みの経路、workerの実効IDを確認してください。[RabbitMQはexchangeを通じて公開メッセージをルーティングします](https://www.rabbitmq.com/docs/exchanges)。brokerのlistenerや有効なログイン情報だけでは、このworkerへの配信は証明できません。キャプチャされた平文のbroker認証情報は別の手掛かりであり、実際のpacket-captureへのアクセスと読み取り可能なtrafficが必要です。それだけではpublish権限は証明できません。Lua pluginが[`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute)でshellコマンドを呼び出せるのは、実行環境でそのAPIが利用可能な場合に限られます。受動的な列挙中にtrafficをキャプチャしたり、メッセージを公開したり、pluginを取得したりせず、設定とコードを確認してください。

特権PythonサービスがローカルのHTTPまたはsocket endpointを公開している場合、ファイルを変更できなくても、読み取り可能なスクリプトから入力がコードに到達する経路が分かることがあります。稼働中のプロセスとユニットのIDを、対象スクリプト、listener、routeの認可、呼び出し元が制御するフィールドと照合してください。次に、解析と検証を経て動的な`eval()`または`exec()`のsinkに至るまで、そのフィールドを追跡します。特に、requestのテキストから新しいf-stringを組み立てて評価すると、攻撃者が指定したreplacement fieldがPython式として解釈されることがあります（[Pythonの`eval`に関する警告](https://docs.python.org/3/library/functions.html#eval); [f-stringの仕様](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)）。`eval`が含まれることやloopback bindingだけでは、信頼できない呼び出し元がsinkに到達する証拠になりません。列挙中にテストpayloadを送信せず、実際のdataflowとアクセス制御を確認してください。

そのrouteにある署名付きrequestのゲートも個別に確認が必要です。読み取り可能なソースから、署名キーが明らかに小さい、または予測可能な出力空間から導出され、サービスが有効な署名サンプルを公開している場合、その署名では特権`eval()`のsinkを保護できない可能性があります。正確な鍵導出とverifier、稼働中のサービスのIDとローカルからの呼び出し可否、署名対象フィールドがsinkに到達するかを確認してください。Pythonの[`random` module](https://docs.python.org/3/library/random.html)をimportしていることや署名サンプルだけでは、これらの条件は証明できません。またPythonは、`__builtins__`の制限は信頼できない`eval()`入力に対する[セキュリティ境界ではない](https://docs.python.org/3/library/functions.html#eval)と警告しています。鍵の分析はオフラインで行い、受動的な列挙中に偽造requestを送信しないでください。

空でも書き込み可能な`/etc/systemd/system/<unit>.service.d`ディレクトリは、ユニットファイルや既存のdrop-inがすべて保護されていても注意が必要です。ユーザーが新しい`.conf` overrideを作成できる可能性があります。現在のIDでそのディレクトリに書き込みと検索の両方ができること、ユニットが読み込まれてrootとして実行されること、daemon reload後にrestartが発生するかを確認してください。reloadまたはrestartの権限、timer、後のbootにより変更が有効になる場合があります。ディレクトリへの書き込み権限だけでは、変更が直ちに実行されるわけではありません。

稼働中のサービスでは、ユニットの`[Service]` sectionにある`EnvironmentFile=`のパスをそのまま確認してください。名前が`.env`で始まらないファイルも対象です。低権限ユーザーがファイルを読める場合、値を共有ログに出さずに`API_TOKEN`や`APP_SECRET_KEY`などの認証情報らしいキー名を列挙します。実効的なユニットを評価する際は、drop-in overrideと任意の`-` prefixも確認してください。読み取り可能であることは認証情報露出の手掛かりです。権限昇格には、その値が特権操作で有効である必要があります。

### 信頼できないアップロードの特権処理

rootで動作するfile watcherが、ユーザー書き込み可能なuploadディレクトリ内のファイルを、短命なparserやextractorに渡すことがあります。稼働中のwatcherの親スクリプトまたはserviceをたどり、対象ディレクトリ、そこにファイルを置けるユーザー、子プロセスのcommandと引数、子プロセスの実行IDを確認してください。プロセスのsnapshotにはwatcherが表示されても、uploadの間に起動するextractorが見逃される場合があります。受動的な列挙中にテストpayloadを置いたり、watcherを起動したりしないでください。

具体例として、Binwalkのextraction mode（`-e`）が攻撃者制御のPFSデータを処理するケースがあります。[CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617)により、PFS extractorがplugin pathを含む意図されたディレクトリ外に書き込み、Binwalkが後でそのpluginを読み込める可能性がありました。upstreamは[2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4)で修正しましたが、distributionのbackportにより表示上は古いバージョンのまま修正が含まれていることがあります。適用可能か判断する前に、[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510)などでインストール済みパッケージのセキュリティ状況を確認してください。Binwalkのバージョンがインストールされているだけでは、権限昇格の経路は証明できません。低権限ユーザーが制御できる入力に対して、より高い権限のプロセスが実際にextractionを実行する必要があります。

### ローカル依存関係を使うスケジュール済みbuild

スケジュールされた`cargo run`は、ジョブの実行ユーザーとしてソースを再コンパイルします。main crateだけでなく、manifestにあるローカルの`{ path = "..." }`依存関係と、各依存関係のソースおよび親ディレクトリの権限を確認してください。低権限ユーザーがCargoによってコンパイルされる依存関係を変更でき、スケジュール済みジョブがその結果を実行するなら、コンパイルされたコードはその実行ユーザーとして動作します。実効的なscheduler command、作業ディレクトリ、依存関係の解決、再buildの有無を確認してください。それ以外の場所に書き込み可能なRustソースファイルがあるだけでは、手掛かりにすぎません。受動的な初期調査ではmanifestとパスのメタデータを読むだけで十分です。[Cargoのpath dependencyに関するドキュメント](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)を参照してください。

## Xvfb framebufferファイル

`Xvfb -fbdir <directory>`は、仮想screen用に`Xvfb_screen<n>`という名前のmemory-mapped fileを使います。別ユーザーの稼働中のXvfbプロセスが指定するディレクトリ内のscreen fileを、現在のユーザーが読み取れる場合、そのframebufferから別ユーザーのdesktopの内容が漏れる可能性があります。プロセス、ファイルの所有者、権限を合わせて確認してください。ファイルを読み取れるだけでは、有用な内容がscreen上にある証拠にはなりません。画像データを共有の列挙出力にコピーせず、まずパスとメタデータを確認してください。[Xvfbのマニュアル](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html)に`-fbdir`の動作が記載されています。

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` マニュアル](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` マニュアル](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` マニュアル](https://man.openbsd.org/ipcs.1)
4. [Consul agent の設定: script checks](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent の service registration API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL の設定](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice ヘルプ: 外部 API クライアント用の socket を開く](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
