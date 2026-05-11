# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## グローバル変数

グローバル変数は**子プロセス**に**継承されます**。

現在のセッションに対してグローバル変数を作成するには、次のようにします:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションとその子プロセスからアクセス可能になります。

変数を**削除**するには、次のようにします:
```bash
unset MYGLOBAL
```
## ローカル変数

**ローカル変数**は、**現在の shell/script** からのみ**アクセス**できます。
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
`/proc/*/environ` の内容は **NUL区切り** なので、通常は以下の形式のほうが読みやすいです:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** が使用するディスプレイ。通常この変数は **:0.0** に設定され、現在のコンピュータ上の最初のディスプレイを意味します。
- **EDITOR** – ユーザーが好むテキストエディタ。
- **HISTFILESIZE** – history file に含まれる最大行数。
- **HISTSIZE** – ユーザーがセッションを終了したときに history file に追加される行数
- **HOME** – あなたの home directory。
- **HOSTNAME** – コンピュータの hostname。
- **LANG** – 現在の言語。
- **MAIL** – ユーザーの mail spool の場所。通常は **/var/spool/mail/USER**。
- **MANPATH** – manual pages を検索するための directories の一覧。
- **OSTYPE** – operating system の種類。
- **PS1** – bash のデフォルトプロンプト。
- **PATH** – 実行したい binary files が置かれているすべての directories の path を、相対 path や absolute path を指定せずに名前だけで実行できるように保持する。
- **PWD** – 現在の working directory。
- **SHELL** – 現在の command shell への path（例: **/bin/bash**）。
- **TERM** – 現在の terminal type（例: **xterm**）。
- **TZ** – あなたの time zone。
- **USER** – 現在の username。

## Interesting variables for hacking

すべての変数が同じくらい有用なわけではありません。攻撃者の視点では、**search paths**、**startup files**、**dynamic linker behavior**、または **audit/logging** を変更する変数を優先してください。

### **HISTFILESIZE**

**この変数の値を 0 に変更**すると、**セッション終了時**に **history file**（\~/.bash_history）が **0 行に切り詰められます**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**この変数の値を0に変更**すると、コマンドは**メモリ上の履歴に保持されず**、**履歴ファイル**（\~/.bash_history）にも書き戻されなくなります。
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**この変数の値が `ignorespace` または `ignoreboth` に設定されている場合**、先頭に余分なスペースが付いたコマンドは履歴に保存されません。
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file** を **`/dev/null`** に向けるか、完全に unset します。これは通常、history size だけを変更するよりも信頼性が高いです。
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

プロセスは、インターネットへ **http または https** 経由で接続するために、ここで宣言された **proxy** を使用します。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: それを尊重するツール/プロトコルのデフォルトプロキシ。
- `no_proxy`: 直接接続すべきバイパスリスト（hosts/domains/CIDRs）。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
小文字版と大文字版の両方が、ツールに応じて使われる場合があります (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`)。

### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは、**これらの env variables** で指定された証明書を信頼します。これは、**`curl`**、**`git`**、Python の HTTP クライアント、または package manager などのツールに、攻撃者が制御する CA を信頼させるのに役立ちます（たとえば、interception proxy を正当なものに見せかけるため）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

特権付きの wrapper/script がコマンドを**絶対パスなしで**実行すると、`PATH` 内の**最初の攻撃者制御ディレクトリ**が勝ちます。これは、`sudo`、cron jobs、shell wrappers、カスタム SUID helpers における多くの**PATH hijacks**の基盤となる primitive です。`env_keep+=PATH`、弱い `secure_path`、または `tar`、`service`、`cp`、`python` などを名前で呼び出す wrappers を探してください。
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
[Linux Privilege Escalation](privilege-escalation/README.md) を確認してください。`PATH` を悪用する完全な privilege-escalation chain については。

### **HOME & XDG_CONFIG_HOME**

`HOME` は単なるディレクトリ参照ではありません。多くのツールは `$HOME` や `$XDG_CONFIG_HOME` から **dotfiles**、**plugins**、およびユーザーごとの設定を自動的に読み込みます。特権のある workflow がこれらの値を保持する場合、**config injection** は binary hijacking よりも容易なことがあります。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
興味深い対象には `.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`、および `.terraformrc` のようなツール固有のファイルが含まれます。

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

これらの変数は **dynamic linker** に影響します:

- `LD_PRELOAD`: 追加の shared objects を先に強制的に読み込む。
- `LD_LIBRARY_PATH`: library search directories を先頭に追加する。
- `LD_AUDIT`: library loading と symbol resolution を監視する auditor libraries を読み込む。

これらは **hooking**、**instrumentation**、そして特権コマンドがそれらを保持する場合の **privilege escalation** に非常に有用です。**secure-execution** モード (`AT_SECURE`、たとえば setuid/setgid/capabilities) では、loader はこれらの変数の多くを削除または制限します。ただし、その初期 loader stage にある parser bugs は、**target program** の **before** に実行されるため、依然として重大な影響を持ちます。
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` は early glibc の挙動（たとえば allocator tunables）を変更し、exploit labs で非常に便利です。また、**dynamic loader が非常に早い段階でこれを解析する**ため、セキュリティの観点でも重要です。2023年の **Looney Tunables** バグは、loader で解析される単一の environment variable が SUID programs に対する **local privilege-escalation primitive** になり得ることを改めて示しました。
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** が **非対話的** に起動されると、`BASH_ENV` を確認し、そのファイルを source してから対象スクリプトを実行します。Bash が `sh` として呼び出される場合や、POSIX 形式の対話モードでは、`ENV` も参照されることがあります。これは、環境が攻撃者に制御されている場合に、shell wrapper を code execution に変える定番の方法です。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash自体は、`-p` が使われない限り、**real/effective IDs が異なる**場合にこれらの startup files を無効化するため、正確な挙動は wrapper が shell をどう起動するかに依存します。

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

これらの変数は、Python の起動方法を変えます:

- `PYTHONPATH`: import の search paths を先頭に追加する。
- `PYTHONHOME`: standard library tree の場所を変更する。
- `PYTHONSTARTUP`: interactive prompt の前に file を実行する。
- `PYTHONINSPECT=1`: script の終了後に interactive mode に入る。

これらは、Python を controllable environment で呼び出す maintenance scripts、debuggers、shells、wrappers に対して有用です。`python -E` と `python -I` はすべての `PYTHON*` variables を無視します。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl には同様に便利な起動時変数があります:

- `PERL5LIB`: ライブラリディレクトリを先頭に追加します。
- `PERL5OPT`: すべての `perl` コマンドラインに指定されているかのようにスイッチを挿入します。

これにより、対象スクリプトが何かをする前に **automatic module loading** を強制したり、インタプリタの動作を変更したりできます。Perl は **taint / setuid / setgid** のコンテキストではこれらの変数を無視しますが、通常の root 実行ラッパー、CI ジョブ、インストーラ、カスタム sudoers ルールでは依然として非常に重要です。
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
同じ考え方は他の runtime にも当てはまります（`RUBYOPT`、`NODE_OPTIONS` など）：特権付き wrapper によって interpreter が起動されるときは、**module loading** や **startup behavior** を変更する env vars を探してください。

post-exploitation の観点では、継承された environment にはしばしば **credentials**、**proxy settings**、**service tokens**、または **cloud keys** が含まれていることも忘れないでください。`/proc/<PID>/environ` と `systemd` の `Environment=` を探す方法については [Linux Post Exploitation](linux-post-exploitation/README.md) を確認してください。

### PS1

prompt の見た目を変更します。

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

One, two and three backgrounded jobs:

![](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
