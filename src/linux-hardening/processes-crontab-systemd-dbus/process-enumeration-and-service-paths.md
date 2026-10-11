# プロセスの列挙とサービスのパス

{{#include ../../banners/hacktricks-training.md}}

重要なのは、権限の低いユーザーが操作できるデータやコードを、どの特権プロセスが使用しているかを特定することです。プロセスツリー、実行中の環境変数、開いているファイル、および各候補プロセスを起動したユニットやスクリプトを調べます。

## プロセスと所有者を把握する

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

ユーザーをまたぐ親子関係は正常な場合もありますが、予期しない遷移があれば、親プロセスのコマンド、引数、実行ファイル、作業ディレクトリ、参照ファイルを確認してください。所有者とログインの状況を解釈するには、[ユーザーとセッション](../user-information/user-and-session-triage.md)を参照してください。

### ローカル仮想マシンのコンソール

QEMUプロセスの`-spice`オプションを、リッスンアドレスとあわせて確認してください。[QEMUのドキュメント](https://www.qemu.org/docs/master/system/qemu-manpage.html)によると、`disable-ticketing`を指定すると、SPICEクライアントは認証なしで接続できます。loopbackにバインドされたリスナーでも、同じホストの他のローカルユーザーから到達できる可能性があります。コマンドラインを公開されたコンソールとして扱う前に、実際のリスナー、認証オプション、ローカルからのアクセス可否を確認してください。コンソールの操作が影響するのは**ゲスト**です。ゲストアカウントの取得や起動状態の変更には、ゲスト側で別途条件を満たす必要があり、それによって仮想化ホストのroot権限が得られるわけではありません。受動的な列挙では、ゲストに接続したり再起動したりせずに、プロセス引数とソケットのメタデータを読み取ってください。

ローカルからアクセスできるWebインターフェースは、最初のshellからサービスアカウントのファイルにアクセスできなくても、そのアカウント権限でコードを実行する可能性があります。たとえばCVE-2023-0297は、信頼できないJavaScriptがPythonのimportを有効にしたJs2Pyに渡される場合の、pyLoadの`/flash/addcrypted2`の処理に影響しました。[上流の修正](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)では`pyimport`が無効化されました。pyLoadのプロセスを権限昇格の経路として扱う前に、実行中のプロセス所有者、リッスンアドレス、エンドポイントへの露出、適用済みパッチまたはベンダーによるバックポートを照合してください。プロセス名、開いているポート、パッケージバージョンだけでは、脆弱性が露出している証拠にはなりません。受動的な列挙では、コード実行payloadを送信しないでください。

### 端末を共有する特権ログインshell

独立したpseudo-terminalを使わずに`su --login <user>`を実行する特権対話型shellは、権限の低いログインshellと端末を共有したままになる場合があります。そのユーザーのstartupファイルを操作でき、そこからのコードが`TIOCSTI`で端末入力を注入できる場合、特権shellが再開したときに、その入力が届く可能性があります。[util-linuxの`su`マニュアル](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES)では、端末共有のリスクを説明し、対話型利用では`su --pty`/`-P`を推奨しています。`su -c`は、制御端末のない別のセッションを開始します。このリスクが成立するには、実際の親shell、端末の関係、対象のstartupファイル、カーネルポリシーが条件になります。プロセス名や`su -l`引数だけなら、調査の手がかりにすぎません。

確認できたプロセスツリーとTTY列を調べたうえで、読み取り可能なlauncherとstartupファイルの所有者・権限を確認してください。Linuxでは、存在する場合、`/proc/sys/dev/tty/legacy_tiocsti`がポリシーの解釈に役立ちます。これが存在しないからといって、安全であるとは限りません。[Linuxの`TIOCSTI`マニュアル](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)によると、Linux 6.2以降では、このsysctlがfalseの場合、操作に`CAP_SYS_ADMIN`が必要になることがあります。ホストを列挙する目的でioctlを実行しないでください。

データベースアカウントが、ファイルシステムへの直接の書き込み権限なしに、対象ユーザーのstartupファイルを変更できる場合があります。PostgreSQLのサーバー側の`COPY ... TO 'filename'`は、データベースサーバーのOSアカウントで書き込みます。ただし、[PostgreSQLの制限](https://www.postgresql.org/docs/current/sql-copy.html)により、この形式を利用できるのはデータベースのsuperuserまたは`pg_write_server_files`などのロールに限られます。データベースロールとサーバー上のOSファイル権限の両方を確認してください。アプリケーションの接続文字列だけでは、ファイルへの書き込み権限は得られません。この経路を評価する際は、特権launcherとデータベースアカウントの権限を分けて考えてください。

## 実行時のアーティファクトを調査する

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

削除された実行ファイルや、削除後も開かれたままのファイルは、最後のファイルディスクリプターが閉じられるまで参照されたままです。これらには証拠やアクセス可能な秘密情報が残っている場合があります。プロセスの環境変数やメモリに認証情報が含まれていることもありますが、他のプロセスの読み取りは、所有者、`/proc` のマウントオプション、Yama ptrace ポリシー、その他のセキュリティ制御によって制限されます。関連する手法については、[file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) と [post-exploitation credential hunting](../post-exploitation/README.md) を参照してください。

保存されたシステムコールのトレースも、ファイル権限の境界となります。[`strace` はシステムコールの引数を出力ファイルに記録します](https://man7.org/linux/man-pages/man1/strace.1.html)。そのため、[`execve` の引数](https://man7.org/linux/man-pages/man2/execve.2.html)を読み取れるトレースから、特権ジョブがコマンドラインで渡したパスワードが漏れる可能性があります。まず、現在のユーザーが対象のトレースを読み取れることと、その引数に実際に認証情報が含まれていることを確認してください。その後、Unixアカウントへの移行を行うには、その認証情報がそこで受け入れられることを別途証明する必要があります。ファイルのメタデータは、定期的な列挙時にすべてのトレースをスキャンしたり内容を表示したりすることなく、有用な受動的手がかりとなります。

## 特権で動作するオフィス自動化ソケット

LibreOffice と OpenOffice は、`--accept=socket,host=<host>,port=<port>;urp;` 引数を通じて UNO API を公開できます。到達可能なエンドポイントを持つ root 所有のオフィスプロセスがある場合、権限の低いローカルユーザーが、そのプロセスのセキュリティコンテキストで API サービスを呼び出せる可能性があります。`SystemShellExecute` サービスには、システムコマンドを起動する操作が含まれています。loopback にバインドすればリモートからの到達性は制限されますが、別の制御によってアクセスが阻止されない限り、ローカルユーザーは引き続きソケットに接続できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

プロセスの所有者、正確な `--accept` 引数、現在の待ち受けアドレスとポートを関連付けて確認します。設定された acceptor が bind に失敗している場合は手掛かりにすぎません。受動的な列挙中に API へ接続したり、API を呼び出したりしないでください。この状態をテストするだけのために、特権を持つ office インスタンスを起動するのは避けてください。

## 特権プロセスが使用する System V shared memory

root 所有の helper が、別のユーザーによる書き込みが可能な System V shared-memory セグメントを作成する場合があります。その後、helper がそのセグメントのデータを shell command やその他の機密性の高い操作で信頼すると、実行ファイルやそのファイルが保護されていても、このセグメントは権限境界をまたぎます。`shmget()` はフラグの下位 9 ビットからアクセス権限を取得します。mode `0666` では他のユーザーも書き込み可能ですが、`IPC_CREAT` フラグによってその権限が制限されることはありません。`ipcs -m` を使ってアクティブなセグメントを受動的に調査し、所有者、mode、存続期間を、特権プロセスおよびその入力処理と関連付けて確認してください。world-writable なセグメントが存在するだけでは、command execution の証拠にはなりません。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V セグメントは、`/dev/shm` にある POSIX 共有メモリファイルとは別物です。一瞬だけ作成されるセグメントは、単一の `ipcs` スナップショットには表示されないことがあるため、出力が空でも、共有メモリを使うヘルパーの存在は否定できません。そのソースまたはバイナリの動作と、それを起動する `sudo` ルールを確認してください。列挙中にセグメントを表示させるためだけに、特権ヘルパーを実行してはいけません。[IPC namespace guide](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md)では、namespace が可視性にどう影響するかを説明しています。<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul は、agent の OS 上の ID で script health check を実行できます。agent が root として動作し、`enable_script_checks` が有効で、権限の低いユーザーがローカル HTTP API を通じて script check 付きのサービスを登録できる場合、そのユーザーが root 権限でコマンドを実行させるおそれがあります。API のバインド先を `127.0.0.1` のみにしても、ローカルユーザーからのアクセスは可能です。`enable_local_script_checks` はより制限的で、HTTP API の登録を通じて送信された script check を除外します。Consul ACL が有効な場合、サービス登録には `service:write` が必要です。`acl.default_policy=allow` の行だけでは、匿名の呼び出し元が登録できることの証明にはなりません。agent の実際の ID、読み込まれた設定、API のバインド先、認可設定をあわせて確認してください。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

実行中の agent の `-config-dir` および `-config-file` 引数をたどって該当する設定を確認し、script-check と ACL のフィールド名および設定だけを調べてください。設定ファイルには gossip キーやトークンが含まれている場合もあるため、共有ログに貼り付けないでください。この条件を列挙するだけの目的で、サービスを登録したりヘルスチェックを実行したりしないでください。

root で実行されている agent の `-config-dir` で指定されたディレクトリに、権限の低いユーザーが**書き込みと検索を行える**場合、別のローカルファイル経由のパスが存在します。そのディレクトリから、新しい `.hcl` または `.json` のサービス定義が読み込まれる可能性があります。ディレクトリの検索権限と書き込み権限があれば、ディレクトリの一覧表示が拒否されていてもファイルを追加できる場合があります。root でのコマンド実行について確認するには、agent が実際にそのディレクトリを読み込むこと、**有効な** script-check 設定がローカル定義を許可していること、定義が読み込まれること、そして agent が root 権限を維持することが必要です。[Consul のドキュメント](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations)には、再読み込み可能な設定とヘルスチェック定義が記載されています。script check の有効化自体には再起動が必要な場合があるため、インストール済みバージョンの動作を確認してください。ACL で agent が保護されている場合、[`consul reload` には `agent:write` が必要です](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent)。KV の書き込み権限だけでは、この権限は得られません。書き込み可能なディレクトリのメタデータはレビューの手がかりとして扱い、許可された再読み込み、再起動、またはコマンド実行の証拠とは見なさないでください。設定を書き込んだり API を呼び出したりせずに、パス、権限、ポリシーを確認してください。

## サービス実行チェーンをたどる

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

unit、drop-in、`EnvironmentFile=`、helper script、相対コマンド、書き込み可能なディレクトリ、socket activationを確認してください。root所有のunitでも、ユーザーが書き込み可能な設定ファイルやscriptを読み込む場合は安全とは限りません。[arbitrary file write](../interesting-files-permissions/write-to-root.md)のページでは、よくあるserviceやunitの悪用経路を説明しています。1回の`ps`一覧では見つからない短時間のjobは、[pspy](https://github.com/DominicBreuker/pspy)やaudit/process telemetryで監視してください。

カスタムの**xinetd** serviceでは、有効なstanzaの`server`、`user`、アクセス制御を、実際に待ち受けているlistenerと正確な実行ファイルに関連付けて確認してください。[`user`設定](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html)は起動されるprocessのidentityを選びます。一方、実行ファイルにset-user-ID bitが設定されている場合、[`execve`がその遷移を許可すれば](https://man7.org/linux/man-pages/man2/execve.2.html)、別個にeffective identityが変わることがあります。信頼できない入力を受け付ける、到達可能な特権binaryは、固定長bufferへの無制限な[`scanf`文字列変換](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)など、memory-safety bugがないかオフラインでsourceやdisassemblyを調べる価値があります。serviceの対応関係やset-user-ID metadataは手掛かりであり、そのようなbugの証明ではありません。受動的な列挙中に、crashを起こす入力を送信したり、実行中の特権serviceをdebugしたりしないでください。

sourceを読めるカスタム特権listenerでは、[`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html)のようなcopy操作で使われる、callerが制御可能な長さをすべて確認してください。現在のwrite indexが固定buffer内にあることを確認しただけでは、**copy length**が残りの領域に収まるとは限りません。indexが範囲内であることを確認したうえで、`copy_length <= capacity - index`を検証し、符号の扱いと算術オーバーフローも確認してください。これは、入力がその操作に到達し、listenerが低権限ユーザーからアクセス可能で、processがより高いeffective identityを保持している場合に限った調査の手掛かりです。sourceとprocess metadataをオフラインで調べ、列挙中に実行中のserviceへcrashを起こす入力を送信しないでください。

**Upstart**を使うシステムでは、system job定義が`/etc/init/*.conf`に置かれていることがあります。現在のユーザーがjob fileに書き込み可能であることが問題になるのは、稼働中のinit daemonがそのjob fileを実際に読み込み、その`script`または`exec` stanzaがより高い特権identityで実行され、さらにユーザーが許可された`initctl`コマンドなどの実際のtriggerを通じて起動できる場合です。sudoで`initctl`が許可されているだけでは、job fileに書き込み可能であることや、変更したjobが実行されることの証明にはなりません。列挙中にjobを編集または起動せず、正確なjob fileのpermission、実効的なrun-as設定、稼働中のdaemon、triggerを確認してください。[Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html)および[`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html)のmanualを参照してください。

`/etc/autologin/passwd`のような、読み取り可能なautologin password fileは、[boot jobがその正確なpathを読み込むシステム](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf)では、credential漏えいの手掛かりになります。boot jobがインストールされ、そのfileを使用していることを確認したうえで、そのpasswordが別のlocal accountまたはserviceでも有効かどうかを個別に検証してください。filenameだけではpasswordの再利用は証明できません。passwordを共有の列挙出力に含めず、pathとアクセスmetadataを記録してください。

unitの`ExecStart=`やscheduled commandから、一覧表示できないディレクトリ内にあるscriptの正確なpathnameが分かることがあります。[ディレクトリのsearch permission](https://man7.org/linux/man-pages/man7/path_resolution.7.html)があれば、現在のidentityは既知のpathをたどれる場合があります。ディレクトリ一覧の取得に失敗したからといって保護されていると決めつけず、すべての親ディレクトリに対するsearch accessと、fileに対するread permissionを確認してください。読み取り可能なscriptにtransfer credentialが含まれている可能性はありますが、別のaccountへ移るには、そのcredentialが引き続き有効で、移行先でも個別に受け入れられる必要があります。secret値を共有ログに出さず、pathとpermissionの証拠を記録してください。

scheduled CommonJS Node.js scriptでは、script自体が読み取り専用でも、`require('package')`のようなbare importを確認してください。[Nodeは、import元fileの隣にある`node_modules`、次にその祖先ディレクトリを検索します](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)。その後、設定済みのglobal pathにフォールバックします。低権限ユーザーが祖先ディレクトリのいずれかに**書き込みとsearch**を行える場合、先に一致するpackageを作成できる可能性があります。正確なimportが実行されること、選択されたpackageがbuilt-in moduleではないこと、該当pathを作成または変更できること、インストール済みruntimeでmoduleがその場所にresolveされること、さらに将来の実行時により高い特権のjobがそのmoduleを読み込むことを確認してください。親ディレクトリが書き込み可能というmetadataは調査の手掛かりにすぎません。moduleを配置したりjobを起動したりせず、scriptとschedulerを受動的に調べてください。

自動jobが別のOS identityでpackageをinstallする場合、private Python package indexも信頼境界になります。正確なjobとrun-as accountを、設定されたindex、選択されるpackage名、低権限ユーザーがjobによって実際にinstallされるpackageをpublishまたは置き換えられるかどうかに関連付けて確認してください。source distributionのbuild時には、installerのidentityでbuild backendやlegacy `setup.py`が実行される場合があります。installされたpackageのimportは別の実行経路です。index listener、読み取り可能なupload password hash、またはpackage filenameだけでは、その一連の条件が成立するとは限りません。列挙中に何もuploadまたはinstallせず、job、indexのauthorization、packageのprovenanceを調べてください。[pipのbuild-system interface](https://pip.pypa.io/en/stable/reference/build-system/)と[secure-installのガイダンス](https://pip.pypa.io/en/stable/topics/secure-installs/)を参照してください。

特権agentが、別のweb serviceやcontainerによって管理されるtask queueをpollすることがあります。低い信頼レベルのidentityがserviceのtask databaseに書き込める場合、そのrowが実際にagentへ提供されるか、command taskがagentのOS identityで実行されるかを確認してください。列挙中にqueueを変更したりtaskを送信したりせず、databaseへのwrite access、対象sessionまたはrouting key、pollingの実行状況、taskのauthorization、agentのeffective userをそれぞれ確認してください。container内のrootであることだけでは、host-root accessを意味しません。attackerが制御するtask dataをhost特権のconsumerが実行する場合に限り、境界を越えます。process、database file、serviceのmetadataを調べてください。

代わりに、定期実行jobがapplication databaseの設定rowからcommandを読み込む場合もあります。低権限のdatabase roleがその正確なrowを変更できること、変更後に稼働中のjobがそれを読み込むこと、その値がより高いOS identityでshellまたは同等のcommand runnerに渡されることを確認してください。databaseへのwrite accessやcommandらしき値だけでは、実行される証拠にはなりません。受動的な列挙中にrowを変更せず、jobとpermissionを調べてください。

queued messageにはcodeではなくURLが含まれることもあります。特権consumerがそのURLを取得し、応答をLuaなどの実行可能なpluginとして読み込む場合は、publisherが正確なexchangeとrouting keyに対して持つpermission、消費対象queueへのbinding、fetchとplugin-loadの経路、workerのeffective identityを確認してください。[RabbitMQはexchangeを通じてpublishされたmessageをrouteします](https://www.rabbitmq.com/docs/exchanges)。broker listenerや有効なloginだけでは、このworkerへのdeliveryは証明されません。平文で取得されたbroker credentialは、実際のpacket-capture accessと読み取り可能なtrafficが必要となる別の手掛かりであり、publish authorizationの証明にはなりません。Lua pluginは、runtimeでそのAPIが利用可能な場合に限り、[`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute)を通じてshell commandを実行できます。受動的な列挙中にtrafficをcaptureしたり、messageをpublishしたり、pluginをfetchしたりせず、設定とcodeを調べてください。

特権Python serviceがlocal HTTPまたはsocket endpointを公開している場合、fileのpermissionによって変更できなくても、読み取り可能なscriptからinput-to-codeの経路が分かることがあります。稼働中のprocessとunitのidentityを、正確なscript、listener、route authorization、callerが制御するfieldに関連付けて確認してください。次に、そのfieldがparsingとvalidationを通じて、動的な`eval()`または`exec()`のsinkに到達するかを追跡します。特に、request textから新しいf-stringを構築して評価すると、attackerが提供したreplacement fieldがPython expressionとして解釈される可能性があります（[Pythonの`eval`に関する警告](https://docs.python.org/3/library/functions.html#eval)、[f-stringの意味](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)）。`eval`が単に見つかったことやloopback bindingだけでは、信頼できないcallerがsinkに到達する証拠にはなりません。列挙中にtest payloadを送らず、実際のdataflowとアクセス制御を調べてください。

そのrouteにあるsigned-request gateも個別に調べる必要があります。読み取り可能なsourceから、署名keyが明らかに小さい、または予測可能な出力空間から導出されていると確認でき、serviceが有効な署名付きsampleを公開している場合、署名が特権`eval()` sinkを保護できなくなっている可能性があります。正確なkey導出方法とverifier、稼働中のserviceのidentityとlocal caller access、署名されたfieldがsinkに到達するかを確認してください。Pythonの[`random` module](https://docs.python.org/3/library/random.html)をimportしていることや、sample signatureがあることだけでは、いずれの条件も証明されません。またPythonは、`__builtins__`の制限が、信頼できない`eval()`入力に対する[セキュリティ境界にはならない](https://docs.python.org/3/library/functions.html#eval)と警告しています。keyの分析はオフラインで行い、受動的な列挙中に偽造requestを送信しないでください。

空でも書き込み可能な`/etc/systemd/system/<unit>.service.d`ディレクトリは、unit fileと既存のdrop-inがすべて保護されていても問題になります。ユーザーが新しい`.conf` overrideを作成できる可能性があるためです。現在のidentityがそのディレクトリに書き込みとsearchを行えること、unitがload済みでrootとして実行されること、daemon reloadの後にrestartされるかどうかを確認してください。reloadまたはrestartのpermission、timer、後のbootによって変更が有効になることがあります。ディレクトリへのwrite accessだけで直ちに実行されるわけではありません。

稼働中のserviceでは、unitの`[Service]` sectionにある、名前が`.env`で始まらないfileも含め、文字どおりの`EnvironmentFile=` pathをたどってください。低権限ユーザーが読み取れる場合は、`API_TOKEN`や`APP_SECRET_KEY`などcredentialらしいkey名を列挙し、値は共有ログに出さないでください。実効的なunitを評価するときは、drop-in overrideと省略可能な`-` prefixを確認してください。読み取り可能であることはcredential漏えいの手掛かりですが、特権操作による権限昇格には、その値が引き続き有効である必要があります。

### 信頼できないuploadの特権処理

rootで動作するfile watcherが、ユーザー書き込み可能なuploadディレクトリ内のfileを、短時間で終了するparserやextractorに渡すことがあります。実行中のwatcherの親scriptまたはserviceをたどり、正確なディレクトリ、その場所にfileを置けるユーザー、child commandとその引数、childが実行されるidentityを確認してください。process snapshotにはwatcherが表示されても、uploadの間に実行されるextractorは見逃すことがあります。受動的な列挙中にtest payloadを配置したり、watcherを起動したりしないでください。

具体例の1つは、Binwalkのextraction mode（`-e`）がattackerの制御するPFS dataを処理する場合です。[CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617)により、PFS extractorが想定されたディレクトリの外部に書き込みできました。その中には、Binwalkが後でloadできるplugin pathも含まれます。upstreamでは[2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4)に修正が含まれましたが、distributionのbackportによって、表示されるversionが古いままの場合があります。適用可能か判断する前に、[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510)などで、インストール済みpackageのsecurity statusを確認してください。Binwalkがインストールされているだけでは権限昇格の経路は成立しません。より高い特権のprocessが、低権限ユーザーの制御するinputに対してextractionを実際に実行する必要があります。

### local dependencyを使うscheduled build

scheduled `cargo run`は、jobのrun-as userとしてsourceを再コンパイルします。manifestにあるローカルの`{ path = "..." }` dependencyと、各dependencyのsourceおよび親ディレクトリのpermissionを確認してください。main crateだけでは不十分です。低権限ユーザーがCargoによってcompileされるdependencyを変更でき、scheduled jobがその結果を実行する場合、compiled codeはそのrun-as userとして実行される可能性があります。schedulerの実効command、working directory、dependency resolution、rebuildが発生するかを確認してください。別の場所にある書き込み可能なRust source fileは、あくまで手掛かりにすぎません。受動的なtriageには、manifestとpath metadataを読むだけで十分です。[Cargoのpath dependencyに関するドキュメント](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)を参照してください。

## Xvfb framebuffer file

`Xvfb -fbdir <directory>`は、virtual screen用に`Xvfb_screen<n>`という名前のmemory-mapped fileを使用します。別のユーザーが実行しているXvfb processが指定するディレクトリ内のscreen fileを現在のユーザーが読み取れる場合、framebufferからそのユーザーのdesktop内容が漏れる可能性があります。process、fileの所有者、permissionをまとめて確認してください。fileを読み取れるだけでは、有用な内容がscreenに表示されている証拠にはなりません。共有の列挙出力にimage dataをコピーせず、まずpathとmetadataを調べてください。[Xvfb manual](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html)に`-fbdir`の動作が記載されています。

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` マニュアル](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` マニュアル](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` マニュアル](https://man.openbsd.org/ipcs.1)
4. [Consul agent の設定: script checks](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent のサービス登録 API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL の設定](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice ヘルプ: 外部 API クライアント向けのソケットを開く](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
