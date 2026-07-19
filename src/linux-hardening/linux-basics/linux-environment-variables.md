# Linux 環境変数

{{#include ../../banners/hacktricks-training.md}}

## グローバル変数

グローバル変数は**子プロセス**に継承されます。

現在のセッション用のグローバル変数は、次のように作成できます。
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションとその子プロセスからアクセス可能です。

以下を実行して変数を**削除**できます:
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
## 現在の変数を一覧表示
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ` の内容は **NUL区切り** なので、通常、次のバリエーションのほうが読みやすくなります：
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
継承された環境内で **credentials** や **interesting service configuration** を探している場合は、[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) も確認してください。

## Common variables

出典: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** で使用されるディスプレイ。通常、この変数は **:0.0** に設定されます。これは、現在のコンピューター上の最初のディスプレイを意味します。
- **EDITOR** – ユーザーが優先するテキストエディター。
- **HISTFILESIZE** – history file に含められる行数の最大値。
- **HISTSIZE** – ユーザーがセッションを終了したときに history file に追加される行数。
- **HOME** – ホームディレクトリ。
- **HOSTNAME** – コンピューターの hostname。
- **LANG** – 現在の言語。
- **MAIL** – ユーザーの mail spool の場所。通常は **/var/spool/mail/USER**。
- **MANPATH** – manual pages の検索対象となるディレクトリのリスト。
- **OSTYPE** – operating system の種類。
- **PS1** – bash のデフォルト prompt。
- **PATH** – 相対パスや絶対パスを指定せず、ファイル名だけを指定して実行できる binary files を含むすべてのディレクトリのパスを格納します。
- **PWD** – 現在の working directory。
- **SHELL** – 現在の command shell へのパス（例: **/bin/bash**）。
- **TERM** – 現在の terminal type（例: **xterm**）。
- **TZ** – タイムゾーン。
- **USER** – 現在の username。

## Interesting variables for hacking

すべての変数が同じように有用なわけではありません。offensive の観点では、**search paths**、**startup files**、**dynamic linker behavior**、または **audit/logging** を変更する変数を優先してください。

### **HISTFILESIZE**

**この変数の値を 0 に変更**すると、**セッションを終了**したときに **history file** (\~/.bash_history) が **0 行に truncate** されます。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**この変数の値を 0 に変更**すると、コマンドが**メモリ上の履歴に保持されなくなり**、**履歴ファイル**（\~/.bash_history）にも書き戻されません。
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

**history file** を **`/dev/null`** に設定するか、完全に unset します。これは、history size だけを変更するよりも、通常は信頼性が高くなります。
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

プロセスは、**http または https** を介してインターネットに接続するため、ここで宣言された **proxy** を使用します。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: これを使用するツールやプロトコルのデフォルトプロキシ。
- `no_proxy`: 直接接続するホスト、ドメイン、CIDRのバイパスリスト。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
ツールに応じて、小文字と大文字のバリアント（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）が使用される場合があります。

### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは、**これらの env variables**で指定された証明書を信頼します。これは、**`curl`**、**`git`**、Python HTTP clients、または package managers などのツールに、attacker が制御する CA を信頼させるのに役立ちます（たとえば、interception proxy を正規のものに見せかけるため）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

特権ラッパー／スクリプトが**絶対パスなし**でコマンドを実行する場合、`PATH` 内で**攻撃者が制御する最初のディレクトリ**が優先されます。これは、`sudo`、cron ジョブ、シェルラッパー、カスタム SUID ヘルパーにおける多くの **PATH hijacks** の基盤となる仕組みです。`env_keep+=PATH`、脆弱な `secure_path`、または `tar`、`service`、`cp`、`python` などを名前だけで呼び出すラッパーを探してください。
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
`PATH`を悪用した完全な privilege-escalation chain については、[Linux Privilege Escalation](linux-privilege-escalation/README.md)を確認してください。

### **HOME & XDG_CONFIG_HOME**

`HOME`は単なるディレクトリ参照ではありません。多くのツールは、`$HOME`または`$XDG_CONFIG_HOME`から**dotfiles**、**plugins**、**ユーザーごとの設定**を自動的に読み込みます。特権ワークフローがこれらの値を保持している場合、**config injection**はbinary hijackingよりも容易になる可能性があります。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
興味深いターゲットには、`.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`、および `.terraformrc` のようなツール固有のファイルがあります。

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

これらの変数は **dynamic linker** に影響を与えます。

- `LD_PRELOAD`: 追加の shared object を先にロードする。
- `LD_LIBRARY_PATH`: library の検索ディレクトリを先頭に追加する。
- `LD_AUDIT`: library のロードと symbol resolution を監視する auditor library をロードする。

特権付きコマンドがこれらを保持する場合、**hooking**、**instrumentation**、および **privilege escalation** に非常に有用です。**secure-execution** mode（`AT_SECURE`、例: setuid/setgid/capabilities）では、loader がこれらの変数の多くを削除または制限します。しかし、その初期の loader stage で発生する parser bug は、ターゲットプログラムより**前**に実行されるため、依然として影響が大きくなります。
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` は glibc の初期動作（allocator tunables など）を変更するもので、exploit labs で非常に便利です。セキュリティの観点でも重要です。**dynamic loader が非常に早い段階で解析する**ためです。2023 年の **Looney Tunables** bug は、loader で解析される単一の environment variable が、SUID プログラムに対する **local privilege-escalation primitive** になり得ることを改めて示しました。
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** が **非対話的** に起動されると、対象スクリプトを実行する前に `BASH_ENV` を確認し、そのファイルを source します。Bash が `sh` として呼び出された場合や、POSIX-style の対話モードでは、`ENV` も参照されることがあります。これは、環境が攻撃者に制御されている場合に、shell wrapper を code execution に変える典型的な方法です。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash自体は、`-p`が使用されない限り、**real/effective IDsが異なる**場合にこれらのstartup filesを無効化するため、正確な挙動はwrapperがshellをどのように起動するかによって異なります。

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

これらのvariablesはPythonのstartup方法を変更します：

- `PYTHONPATH`: import search pathsを先頭に追加します。
- `PYTHONHOME`: standard library treeの場所を変更します。
- `PYTHONSTARTUP`: interactive promptの前にfileを実行します。
- `PYTHONINSPECT=1`: scriptの終了後にinteractive modeへ移行します。

これらは、制御可能なenvironmentでPythonを呼び出すmaintenance scripts、debuggers、shells、wrappersに対して有用です。`python -E`と`python -I`は、すべての`PYTHON*` variablesを無視します。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl には、同様に有用な startup variables があります。

- `PERL5LIB`: library directories を prepend する。
- `PERL5OPT`: すべての `perl` command line に指定されているかのように switches を inject する。

これにより、**automatic module loading** を強制したり、対象の script が重要な処理を始める前に interpreter の動作を変更したりできます。Perl は **taint / setuid / setgid** contexts ではこれらの variables を無視しますが、通常の root-run wrappers、CI jobs、installers、custom sudoers rules では依然として非常に重要です。
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
同じ考え方は他の runtime（`RUBYOPT`、`NODE_OPTIONS` など）にも当てはまります。特権 wrapper によって interpreter が起動される場合は、**module loading** や **startup behavior** を変更する環境変数を探してください。

post-exploitation の観点では、継承された環境に **credentials**、**proxy settings**、**service tokens**、**cloud keys** が含まれていることも忘れないでください。`/proc/<PID>/environ` と `systemd` の `Environment=` の調査については、[Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) を確認してください。

### PS1

prompt の表示方法を変更します。

[**これは例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: これは例です](<../images/image (897).png>)

一般ユーザー:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つ](<../images/image (740).png>)

バックグラウンドで実行中のジョブが1つ、2つ、3つ:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドで実行中のジョブが1つ、2つ、3つ](<../images/image (145).png>)

バックグラウンドジョブが1つあり、1つが停止中で、最後のコマンドが正常に終了しなかった場合:

![PERL5OPT & PERL5LIB - PS1: バックグラウンドジョブが1つあり、1つが停止中で、最後のコマンドが正常に終了しなかった場合](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
