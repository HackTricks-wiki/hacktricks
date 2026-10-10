# プロセスの列挙とサービスパス

{{#include ../../banners/hacktricks-training.md}}

重要なのは、低い権限のユーザーが影響を与えられるデータやコードを、どの特権プロセスが利用するかです。プロセスツリー、実行中の環境、開いているファイル、および候補となる各プロセスを起動した unit やスクリプトを調べます。

## プロセスと所有者を把握する

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

異なるユーザー間の親子関係は正常な場合もありますが、想定外の遷移があれば、親プロセスのコマンド、引数、実行ファイル、作業ディレクトリ、参照ファイルを確認してください。[ユーザーとセッション](../user-information/user-and-session-triage.md)を使って、所有者とログイン状況を解釈します。

### ローカル仮想マシンのコンソール

QEMUプロセスの`-spice`オプションを、待ち受けアドレスと併せて確認してください。[QEMUのドキュメント](https://www.qemu.org/docs/master/system/qemu-manpage.html)によると、`disable-ticketing`を指定すると、SPICEクライアントは認証なしで接続できます。ループバックにバインドされた待ち受けサービスでも、同じホスト上の他のユーザーから到達できる可能性があります。このコマンドラインを公開されたコンソールと判断する前に、実際の待ち受け状態、認証オプション、ローカルからのアクセス可否を確認してください。コンソールの操作が影響するのは**ゲスト**です。ゲストアカウントの取得や起動状態の変更には、ゲスト側の別個の条件が必要であり、仮想化ホストのroot権限は得られません。受動的な列挙中は、ゲストに接続したり再起動したりせずに、プロセス引数とソケットのメタデータを読み取ってください。

ローカルからアクセス可能なWebインターフェースは、最初のシェルからサービスアカウントのファイルにアクセスできない場合でも、そのアカウント権限でコードを実行する可能性があります。たとえば、CVE-2023-0297は、信頼できないJavaScriptがPythonのimportを有効にしたJs2Pyに渡された場合のpyLoadの`/flash/addcrypted2`処理に影響しました。[上流の修正](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)では`pyimport`が無効化されています。pyLoadプロセスを権限昇格の経路と見なす前に、実行中のプロセス所有者、待ち受けアドレス、エンドポイントの公開状況、インストール済みのパッチまたはベンダーによるバックポートを照合してください。プロセス名、開いているポート、パッケージのバージョンだけでは、脆弱な状態にあるとは証明できません。受動的な列挙では、コード実行ペイロードを送信しないでください。

### 特権ログインシェルと端末の共有

独立した疑似端末を使わずに`su --login <user>`を実行する特権対話型シェルでは、下位権限のログインシェルと端末が共有されたままになる場合があります。そのユーザーが制御可能な起動ファイルに、`TIOCSTI`を使って端末入力を注入するコードが含まれていると、特権シェルが再開した際にその入力が届く可能性があります。[util-linuxの`su`マニュアル](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES)は端末共有のリスクを説明し、対話的な使用では`su --pty`/`-P`を推奨しています。`su -c`は制御端末のない別セッションを開始します。このリスクが実際にあるかどうかは、親シェル、端末の関係、対象の起動ファイル、カーネルポリシーを確認する必要があります。プロセス名や`su -l`引数だけでは、確認の手がかりにしかなりません。

確認できたプロセスツリーとTTY列を調べた後、読み取り可能なランチャーと起動ファイルの所有者・権限を確認してください。Linuxでは、`/proc/sys/dev/tty/legacy_tiocsti`が存在する場合、ポリシーの解釈に役立ちます。これが存在しないからといって安全とは限りません。[Linuxの`TIOCSTI`マニュアル](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html)によると、Linux 6.2以降では、このsysctlがfalseの場合、操作に`CAP_SYS_ADMIN`が必要となることがあります。ホストの列挙だけを目的に、このioctlを呼び出さないでください。

データベースアカウントが、直接ファイルシステムに書き込む権限を持たなくても、対象ユーザーの起動ファイルを変更できる場合があります。PostgreSQLのサーバー側`COPY ... TO 'filename'`は、データベースサーバーのOSアカウントとして書き込みます。ただし、[PostgreSQLの制限](https://www.postgresql.org/docs/current/sql-copy.html)により、この形式を使えるのはデータベースのスーパーユーザー、または`pg_write_server_files`などのロールに限られます。データベースのロールとサーバーOS上のファイル権限の両方を確認してください。アプリケーションの接続文字列だけでは、ファイルへの書き込み権限は得られません。この経路を評価する際は、特権ランチャーとデータベースアカウントの能力を分けて考えてください。

## ランタイムアーティファクトを調べる

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

削除された実行ファイルや、削除済みでも開かれたままのファイルは、最後のファイルディスクリプターが閉じられるまで参照され続けます。証拠やアクセス可能な秘密情報が残っていることがあります。プロセスの環境変数やメモリに認証情報が含まれている可能性がありますが、別のプロセスを読み取れるかどうかは、所有者、`/proc` のマウントオプション、Yama ptrace ポリシー、その他のセキュリティ制御によって制限されます。関連する手法については、[ファイルディスクリプター](../main-system-information/filesystem-links-and-file-descriptors.md)と[post-exploitation における認証情報の探索](../post-exploitation/README.md)を参照してください。

保存された syscall trace も、ファイル権限の境界になります。[`strace` は syscall の引数を出力ファイルに記録するため](https://man7.org/linux/man-pages/man1/strace.1.html)、[`execve` の引数](https://man7.org/linux/man-pages/man2/execve.2.html)を含む trace を読み取れると、特権ジョブがコマンドラインで渡したパスワードが漏れる可能性があります。まず、現在のユーザーが対象の trace を読み取れることと、その引数に実際に認証情報が含まれていることを確認してください。その後、Unix アカウントへの切り替えにその認証情報が使えることは、別途実証する必要があります。通常の列挙では、すべての trace をスキャンしたり内容を表示したりせずに、ファイルのメタデータを受動的な手がかりとして利用できます。

## 特権ユーザーで動作するオフィス自動化ソケット

LibreOffice と OpenOffice は、`--accept=socket,host=<host>,port=<port>;urp;` 引数を介して UNO API を公開できます。到達可能なエンドポイントを持つ root 所有のオフィスプロセスがあると、権限の低いローカルユーザーが、そのプロセスのセキュリティコンテキストで API サービスを呼び出せる可能性があります。`SystemShellExecute` サービスには、システムコマンドを起動する操作が含まれています。loopback にバインドすればリモートからの到達性は制限されますが、別の制御によってアクセスが防止されない限り、ローカルユーザーからは引き続きソケットに接続できます。<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

プロセスの所有者、正確な `--accept` 引数、現在の待ち受けアドレスとポートを関連付けて確認します。設定された acceptor が bind に失敗している場合、それは調査の手掛かりにすぎません。受動的な列挙中に API へ接続したり、API を呼び出したりしないでください。この状態をテストするだけの目的で、特権を持つ office インスタンスを起動するのも避けてください。

## 特権プロセスが利用する System V shared memory

root 所有の helper が、別のユーザーも書き込める System V shared-memory segment を作成することがあります。helper が後に、その segment のデータを shell command や別の機密操作で信頼する場合、実行ファイルとそのファイルが保護されていても、この segment は権限境界を越える経路になります。`shmget()` はフラグの下位 9 ビットからアクセス権限を取得します。モード `0666` では他のユーザーも書き込み可能ですが、`IPC_CREAT` フラグによってその権限が狭められることはありません。`ipcs -m` を使ってアクティブな segment を受動的に調査し、所有者、モード、存続期間を特権プロセスとその入力処理に関連付けて確認します。world-writable な segment があるだけでは、command execution が成立するとは限りません。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

System V セグメントは、`/dev/shm` 配下の POSIX shared-memory ファイルとは別のものです。ごく短時間だけ作成されるセグメントは、単一の `ipcs` スナップショットには表示されないことがあるため、出力が空でも shared memory を使う helper の存在は否定できません。そのソースコードやバイナリの挙動、およびそれを起動する `sudo` ルールを確認してください。列挙中にセグメントを表示させる目的で、特権 helper を実行してはいけません。[IPC namespace ガイド](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md)では、namespace が可視性に与える影響を説明しています。<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent の script check

Consul は、agent の OS 上の identity で script health check を実行できます。agent が root として実行され、`enable_script_checks` が有効で、権限の低いユーザーがローカル HTTP API を通じて script check 付きの service を登録できる場合、そのユーザーが root 権限で実行されるコマンドを実行させる可能性があります。API のバインド先を `127.0.0.1` のみにしても、ローカルユーザーは引き続きアクセスできます。`enable_local_script_checks` 設定は、HTTP API による登録で送信された script check を除外するため、より対象が限定されています。Consul ACL が有効な場合、service の登録には `service:write` が必要です。`acl.default_policy=allow` という行だけでは、匿名ユーザーが登録できることの証明にはなりません。agent の実際の identity、読み込まれた設定、API のバインド先、認可設定を併せて確認してください。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

実行中の agent の `-config-dir` および `-config-file` 引数をたどって該当する設定を確認し、script-check と ACL のフィールド名および設定だけを調べてください。設定ファイルには gossip key や token が含まれている場合もあるため、共有ログに貼り付けないでください。この条件を列挙するだけの目的で、サービスを登録したり health check を実行したりしないでください。

低い権限のユーザーが、root で実行されている agent の `-config-dir` で指定されたディレクトリに対する**書き込み権限と検索権限**を持つ場合、別のローカルファイル経由の経路が存在します。そのディレクトリに新しい `.hcl` または `.json` のサービス定義を置くと、読み込まれる可能性があります。ディレクトリの一覧表示が拒否されていても、検索権限と書き込み権限があればファイルを追加できる場合があります。root でのコマンド実行につながるか確認するには、agent が実際にそのディレクトリを読み込むこと、**有効な** script-check 設定でローカル定義が許可されていること、定義が読み込まれること、そして agent が root 権限を維持することを確認してください。[Consul のドキュメント](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations)では、再読み込み可能な設定と health check 定義が説明されています。script check の有効化には再起動が必要な場合があるため、インストールされているバージョンの動作を確認してください。ACL で agent が保護されている場合、[`consul reload` には `agent:write` が必要です](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent)。KV の書き込み権限だけでは、この権限は得られません。書き込み可能なディレクトリのメタデータはレビューの手掛かりとして扱い、許可された再読み込み、再起動、またはコマンド実行の証拠とはみなさないでください。設定を書き込んだり API を呼び出したりせずに、パス、権限、ポリシーを確認してください。

## サービス実行チェーンをたどる

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

unit、drop-in、`EnvironmentFile=`、helper script、相対パスのコマンド、書き込み可能なディレクトリ、socket activationを確認します。root所有のunitでも、ユーザーが書き込み可能な設定ファイルやスクリプトを読み込む場合は安全とは限りません。[arbitrary file write](../interesting-files-permissions/write-to-root.md)のページでは、よくあるserviceやunitの悪用経路を解説しています。1回だけの`ps`一覧では見逃す短時間のジョブは、[pspy](https://github.com/DominicBreuker/pspy)やaudit/process telemetryで監視します。

カスタム**xinetd** serviceでは、有効なstanzaの`server`、`user`、アクセス制御を、実際に待ち受けているポートと正確な実行ファイルに照らし合わせます。[`user`設定](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html)は起動するプロセスのidentityを決めます。一方、実行ファイルにset-user-ID bitが設定されていると、[`execve`がその遷移を許可する場合](https://man7.org/linux/man-pages/man2/execve.2.html)、実効identityが別途変わることがあります。信頼できない入力を受け取る、外部から到達可能な特権バイナリについては、固定長bufferへの無制限な[`scanf`文字列変換](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html)など、memory-safety bugがないか、オフラインでソースや逆アセンブル結果を調べる価値があります。serviceの対応関係やset-user-ID metadataは調査の手掛かりであり、バグの証拠ではありません。受動的なenumeration中に、クラッシュさせる入力を送ったり、稼働中の特権serviceをdebugしたりしないでください。

ソースを読めるカスタム特権listenerでは、[`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html)などのcopy処理に使われる、呼び出し元が制御する各lengthを確認します。現在のwrite indexが固定bufferの範囲内かだけを確認しても、**copy length**が残りの領域に収まるとは限りません。indexが範囲内であることを確認したうえで、`copy_length <= capacity - index`を検証し、符号の扱いと算術オーバーフローも確認します。これは、入力がその処理に到達し、listenerが低権限ユーザーからアクセス可能で、プロセスがより高い実効identityを保持している場合に限った調査の手掛かりです。ソースとプロセスmetadataをオフラインで調べ、enumeration中に稼働中のserviceへクラッシュさせる入力を送らないでください。

**Upstart**を使用するシステムでは、システムのjob定義が`/etc/init/*.conf`に置かれていることがあります。現在のユーザーが書き込み可能なjobファイルが問題になるのは、稼働中のinit daemonがそのjobを実際に読み込み、その`script`または`exec` stanzaがより高い権限で実行され、さらにユーザーが許可された`initctl`コマンドや実際の別のtriggerを使って起動できる場合です。sudoで`initctl`が許可されているだけでは、jobファイルが書き込み可能であることも、変更したjobが実行されることも証明できません。enumeration中にjobを編集または起動せず、正確なjobファイルのpermission、実効run-as設定、稼働中のdaemon、triggerを確認してください。[Upstart job configuration](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html)と[`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html)のマニュアルを参照してください。

`/etc/autologin/passwd`のような、読み取り可能なautologin password fileは、[boot jobがその正確なpathを読み込むシステム](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf)では、credential漏えいの手掛かりになります。boot jobがインストールされ、そのファイルを使用していることを確認したうえで、そのpasswordが別のローカルアカウントやserviceでも有効かを個別に検証します。ファイル名だけではpasswordの使い回しは証明できません。passwordを共有のenumeration出力に含めず、pathとアクセスmetadataを記録してください。

unitの`ExecStart=`やスケジュールされたコマンドから、一覧表示できないディレクトリ内のスクリプトの正確なpathnameが分かることがあります。[ディレクトリのsearch permission](https://man7.org/linux/man-pages/man7/path_resolution.7.html)があれば、現在のidentityでその既知のpathをたどれる場合があります。ディレクトリ一覧の取得に失敗してもファイルを保護できているとは限らないため、すべての親ディレクトリに対するsearch accessと、ファイルのread permissionを確認してください。読み取り可能なスクリプトには転送用credentialが含まれている可能性がありますが、別アカウントへアクセスするには、そのcredentialが引き続き有効で、別途そのアカウントでも受け入れられる必要があります。共有ログにsecretの値を出力せず、pathとpermissionの証拠を記録してください。

スケジュールされたCommonJS Node.jsスクリプトでは、スクリプト自体がread-onlyでも、`require('package')`のようなbare importを調べます。[Nodeはimport元ファイルの隣にある`node_modules`を検索し、次に親ディレクトリを検索します](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)。その後、設定されたglobal pathを検索します。低権限ユーザーが、これらの親ディレクトリのいずれかに対して**writeとsearch**の両方が可能なら、先に見つかるpackageを作成できる場合があります。正確なimportが実行されること、選択されるpackageが組み込みmoduleではないこと、該当pathに作成または変更が可能であること、インストール済みruntimeでその場所からmoduleが解決されること、より高権限のjobが次回実行時にそれを読み込むことを確認します。親ディレクトリが書き込み可能というmetadataは、調査の手掛かりにすぎません。moduleを配置したりjobを起動したりせず、スクリプトとschedulerを受動的に調べてください。

自動化されたjobが別のOS identityでpackageをインストールする場合、private Python package indexもtrust boundaryになります。正確なjobとrun-asアカウントを、設定されたindex、選択されるpackage名、そして低権限ユーザーがjobで実際にインストールされるpackageをpublishまたは置換できるかどうかと照合します。source distributionのbuild時に、installerのidentityでbuild backendや旧式の`setup.py`が実行される場合があります。インストール済みpackageのimportは別の実行経路です。indexのlistener、読み取り可能なupload password hash、packageのファイル名だけでは、こうした連鎖は証明できません。enumeration中に何もuploadやinstallせず、job、indexの認可、packageのprovenanceを調べてください。[pipのbuild-system interface](https://pip.pypa.io/en/stable/reference/build-system/)と[secure-installのガイダンス](https://pip.pypa.io/en/stable/topics/secure-installs/)を参照してください。

特権agentが、別のweb serviceやcontainerによって管理されるtask queueをpollする場合があります。低いtrust levelのidentityでserviceのtask databaseに書き込めるなら、その行が実際にagentへ配信されるか、command taskがagentのOS identityで実行されるかを確認します。databaseへのwrite access、対象のsessionまたはrouting key、pollingが有効であること、taskの認可、agentの実効userをそれぞれ確認してください。container内のrootは、それだけではhost-root accessを意味しません。host-privileged consumerが攻撃者制御のtask dataを実行する場合にのみ、境界を越えます。enumeration中にqueueを変更したりtaskを送信したりせず、プロセス、database file、serviceのmetadataを調べてください。

繰り返し実行されるjobが、application databaseの設定行からコマンドを読み込む場合もあります。低権限のdatabase roleでその正確な行を変更できること、変更後に稼働中のjobがその値を読み込むこと、その値がより高いOS identityでshellまたは同等のcommand runnerに渡されることを確認します。databaseへのwrite accessや、コマンドに見える値だけでは実行は証明できません。受動的なenumeration中に行を変更せず、jobとpermissionを調べてください。

queueに入るmessageにコードではなくURLが含まれる場合もあります。特権consumerがそのURLを取得し、応答をLuaなどの実行可能なpluginとして読み込むなら、publisherが正確なexchangeとrouting keyでpublishできるか、消費されるqueueへのbindingがあるか、fetchとplugin-loadの経路があるか、workerの実効identityは何かを確認します。[RabbitMQはexchange経由でpublishされたmessageをルーティングします](https://www.rabbitmq.com/docs/exchanges)。brokerのlistenerや有効なloginだけでは、このworkerへの配信は証明できません。盗聴したbroker credentialが平文であっても、それは実際にpacket captureへアクセスでき、trafficが読み取り可能である場合の別の手掛かりであり、publishの認可を証明するものではありません。Lua pluginが[`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute)経由でshell commandを実行できるのは、そのAPIがruntimeで利用可能な場合に限られます。受動的なenumeration中にtrafficをcaptureしたり、messageをpublishしたり、pluginをfetchしたりせず、設定とコードを調べてください。

特権Python serviceがローカルのHTTPまたはsocket endpointを公開している場合、ファイルのpermission上は変更できなくても、読み取り可能なスクリプトから入力がcodeへ到達する経路を発見できることがあります。稼働中のプロセスとunitのidentityを、正確なスクリプト、listener、routeの認可、呼び出し元が制御するfieldと照合します。次に、それらのfieldがparseとvalidationを経て、動的な`eval()`または`exec()`のsinkに到達するかを追跡します。特に、request textから新たなf-stringを作って評価すると、攻撃者が指定したreplacement fieldがPython expressionとして解釈される可能性があります（[Pythonの`eval`に関する警告](https://docs.python.org/3/library/functions.html#eval)、[f-stringの仕様](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)）。`eval`という文字列の一致やloopback bindingだけでは、信頼できない呼び出し元がsinkに到達できるとは証明できません。enumeration中にテストpayloadを送らず、実際のdataflowとアクセス制御を調べてください。

このrouteにある署名付きrequestのgateも、個別に調査する必要があります。読み取り可能なソースから、署名keyが明らかに小さい、または予測可能な出力空間で生成されると分かり、さらにserviceが有効な署名付きサンプルを公開しているなら、その署名では特権`eval()` sinkを保護できない可能性があります。正確なkey導出と検証処理、稼働中のserviceのidentityとローカルからのアクセス可否、署名対象のfieldがsinkに到達するかを確認します。Pythonの[`random` module](https://docs.python.org/3/library/random.html)をimportしていることや署名サンプルがあることだけでは、どの条件も証明できません。またPythonは、`__builtins__`を制限しても、信頼できない`eval()`入力に対する[セキュリティ境界にはならない](https://docs.python.org/3/library/functions.html#eval)と警告しています。keyの分析はオフラインで行い、受動的なenumeration中に偽造requestを送信しないでください。

空でも書き込み可能な`/etc/systemd/system/<unit>.service.d`ディレクトリは、unit fileと既存のdrop-inがすべて保護されていても問題になります。ユーザーが新しい`.conf` overrideを作成できるためです。現在のidentityでそのディレクトリにwriteとsearchが可能か、unitがload済みでrootとして実行されるか、daemon reload後にrestartされるかを確認します。reloadまたはrestartの権限、timer、後のbootによって変更が有効になることがあります。ディレクトリへのwrite accessだけでは、変更がすぐに実行されるわけではありません。

稼働中のserviceでは、unitの`[Service]`セクションにある文字どおりの`EnvironmentFile=`のpathをたどります。名前が`.env`で始まらないファイルも対象です。低権限ユーザーが読み取れる場合は、`API_TOKEN`や`APP_SECRET_KEY`など、credentialらしいkey名を一覧表示し、値を共有ログに出力しないでください。有効なunitを評価する際は、drop-in overrideと任意の`-` prefixも確認します。読み取り可能であることはcredential漏えいの手掛かりですが、特権操作によるescalationには、その値が実際に有効である必要があります。

### 信頼できないuploadの特権処理

rootで実行されるfile watcherが、ユーザー書き込み可能なupload directory内のファイルを、短時間だけ実行されるparserやextractorに渡すことがあります。稼働中のwatcherの親scriptまたはserviceをたどり、正確なdirectory、その場所にファイルを置けるユーザー、子processのcommandと引数、子processの実行identityを確認します。process snapshotにはwatcherが表示されても、upload間に実行されるextractorは見逃すことがあります。受動的なenumeration中にテストpayloadを置いたり、watcherを起動したりしないでください。

具体例として、Binwalkのextractモード（`-e`）で攻撃者制御のPFS dataを処理するケースがあります。[CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617)では、PFS extractorが想定されたdirectoryの外に書き込める可能性があり、Binwalkが後で読み込むplugin pathも対象でした。upstreamでは[2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4)で修正されましたが、distributionのbackportによって表示上は古いversionのままの場合があります。該当するかを判断する前に、[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2022-4510)などでインストール済みpackageのsecurity statusを確認してください。Binwalkがインストールされているだけではprivilege-escalationの経路は証明できません。低権限ユーザーが制御できる入力に対して、より高い権限のプロセスが実際にextractを実行する必要があります。

### ローカル依存関係を使うスケジュール済みbuild

スケジュールされた`cargo run`は、jobのrun-asユーザーとしてsourceを再コンパイルします。main crateだけでなく、manifest内のローカルな`{ path = "..." }` dependencyと、各dependencyのsourceおよび親directoryのpermissionを調べてください。低権限ユーザーがCargoによってcompileされるdependencyを変更でき、そのscheduled jobが実行結果を動かす場合、compiled codeはそのrun-asユーザーとして実行されます。有効なscheduler command、working directory、dependencyの解決方法、rebuildが発生するかを確認してください。別の場所に書き込み可能なRust source fileがあるだけでは手掛かりにすぎません。受動的なtriageではmanifestとpathのmetadataを読むだけで十分です。[Cargoのpath dependencyに関するドキュメント](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies)を参照してください。

## Xvfbのframebuffer file

`Xvfb -fbdir <directory>`は、仮想screen用に`Xvfb_screen<n>`という名前のmemory-mapped fileを使用します。別のユーザーが実行中のXvfb processで指定したdirectory内のscreen fileを、現在のユーザーが読み取り可能なら、そのframebufferからユーザーのdesktop内容が漏れる可能性があります。process、fileのownership、permissionをあわせて確認してください。fileが読み取り可能なだけでは、有用な内容が画面に表示されている証拠にはなりません。共有のenumeration出力に画像dataをコピーせず、まずpathとmetadataを調べてください。[Xvfbのマニュアル](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html)に`-fbdir`の動作が記載されています。

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Linux `shmget(2)` マニュアル](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Linux `ipcs(1)` マニュアル](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [OpenBSD `ipcs(1)` マニュアル](https://man.openbsd.org/ipcs.1)
4. [Consul agent の設定: script checks](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [Consul agent の service 登録 API](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Consul ACL の設定](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [LibreOffice ヘルプ: 外部 API クライアント用の socket を開く](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
