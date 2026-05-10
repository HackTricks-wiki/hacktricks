# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## グローバル変数

グローバル変数は、**子プロセス**に**継承されます**。

現在のセッションに対してグローバル変数を作成するには、次のようにします:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションとその子プロセスからアクセスできます。

次の方法で変数を**削除**できます:
```bash
unset MYGLOBAL
```
## ローカル変数

**ローカル変数** は **現在のシェル/スクリプト** からのみ **アクセス** できます。
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
`/proc/*/environ` の内容は **NUL区切り** なので、通常は次のバリアントのほうが読みやすいです:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
もし **credentials** や継承された環境内の **interesting service configuration** を探しているなら、[Linux Post Exploitation](linux-post-exploitation/README.md) も確認してください。

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** が使用するディスプレイ。この変数は通常 **:0.0** に設定され、現在のコンピュータ上の最初のディスプレイを意味します。
- **EDITOR** – ユーザーが好むテキストエディタ。
- **HISTFILESIZE** – history file に含まれる行数の最大値。
- **HISTSIZE** – ユーザーがセッションを終了したときに history file に追加される行数
- **HOME** – あなたのホームディレクトリ。
- **HOSTNAME** – コンピュータのホスト名。
- **LANG** – 現在の言語。
- **MAIL** – ユーザーの mail spool の場所。通常は **/var/spool/mail/USER**。
- **MANPATH** – manual pages を検索するディレクトリ一覧。
- **OSTYPE** – operating system の種類。
- **PS1** – bash のデフォルトプロンプト。
- **PATH** – 実行したい binary files の名前だけを指定して、相対パスや絶対パスなしで実行できるようにする、すべてのディレクトリの path を保存する。
- **PWD** – 現在の作業ディレクトリ。
- **SHELL** – 現在の command shell への path（例: **/bin/bash**）。
- **TERM** – 現在の terminal type（例: **xterm**）。
- **TZ** – あなたの time zone。
- **USER** – 現在の username。

## Interesting variables for hacking

すべての変数が同じくらい有用というわけではありません。攻撃者の観点では、**search paths**、**startup files**、**dynamic linker behavior**、または **audit/logging** を変更する変数を優先してください。

### **HISTFILESIZE**

この変数の **value を 0 に変更**すると、**セッション終了時**に **history file**（\~/.bash_history）が **0行まで切り詰められます**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**この変数の値を0に変更**すると、コマンドは**メモリ上の履歴に保持されず**、**history file**（\~/.bash_history）にも書き戻されません。
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**この変数の値が** `ignorespace` **または** `ignoreboth` **に設定されている場合**、先頭に余分なスペースを付けたコマンドは履歴に保存されません。
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file** を **`/dev/null`** に向けるか、完全に unset します。これは通常、history size だけを変更するよりも信頼性があります。
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

プロセスは、インターネットへ **http** または **https** 経由で接続するために、ここで宣言された **proxy** を使用します。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: それを尊重するツール/プロトコルのデフォルト proxy。
- `no_proxy`: 直接接続すべきバイパスリスト（hosts/domains/CIDRs）。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
ツールに応じて、小文字と大文字の両方の変種が使われる場合があります（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは、**これらのenv variables**で指定された証明書を信頼します。これは、**`curl`**、**`git`**、PythonのHTTPクライアント、またはpackage managersが、攻撃者が制御するCAを信頼するようにするのに便利です（たとえば、interception proxyを正当なものに見せるため）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

特権ラッパー/スクリプトがコマンドを**絶対パスなし**で実行すると、`PATH` 内の**最初の攻撃者制御ディレクトリ**が勝ちます。これは、`sudo`、cron ジョブ、shell wrappers、カスタム SUID helpers における多くの **PATH hijacks** の基本原理です。`env_keep+=PATH`、弱い `secure_path`、または `tar`、`service`、`cp`、`python` などを名前で呼び出す wrappers を探してください。
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
フルの権限昇格チェーンで `PATH` を悪用する場合は、[Linux Privilege Escalation](privilege-escalation/README.md) を確認してください。

### **HOME & XDG_CONFIG_HOME**

`HOME` は単なるディレクトリ参照ではありません。多くのツールは `$HOME` や `$XDG_CONFIG_HOME` から **dotfiles**、**plugins**、および **per-user configuration** を自動的に読み込みます。権限のあるワークフローがこれらの値を保持する場合、**config injection** は binary hijacking より簡単なことがあります。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
注目すべき対象には `.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`、および `.terraformrc` のようなツール固有のファイルが含まれます。

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

これらの変数は **dynamic linker** に影響します:

- `LD_PRELOAD`: 追加の shared objects を先に読み込ませる。
- `LD_LIBRARY_PATH`: library search directories を先頭に追加する。
- `LD_AUDIT`: library loading と symbol resolution を監視する auditor libraries を読み込む。

これらは、特権コマンドが保持する場合、**hooking**、**instrumentation**、および **privilege escalation** に非常に有用です。**secure-execution** モード (`AT_SECURE`、例: setuid/setgid/capabilities) では、loader はこれらの変数の多くを削除または制限します。ただし、その初期 loader stage にある parser bugs は、**target program** の前に実行されるため、依然として非常に重大です。
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` は、glibc の初期動作（たとえば allocator tunables）を変更でき、exploit labs で非常に便利です。また、セキュリティの観点でも重要です。なぜなら、**dynamic loader がそれを非常に早い段階で解析する**からです。2023年の **Looney Tunables** バグは、loader で解析される単一の environment variable が、SUID programs に対する **local privilege-escalation primitive** になり得ることを改めて示しました。
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash** が **非対話的** に起動されると、`BASH_ENV` を確認し、対象スクリプトを実行する前にそのファイルを source します。Bash が `sh` として起動された場合や、POSIX スタイルの対話モードでは、`ENV` も参照されることがあります。これは、環境が attacker-controlled の場合に shell wrapper を code execution に変える典型的な方法です。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash自体は、**実ID/実効IDが異なる**場合、`-p` が使用されない限りこれらの起動時ファイルを無効化するため、正確な挙動はラッパーがシェルをどう起動するかに依存します。

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

これらの変数はPythonの起動方法を変更します:

- `PYTHONPATH`: import の検索パスを先頭に追加する。
- `PYTHONHOME`: 標準ライブラリツリーの場所を変更する。
- `PYTHONSTARTUP`: 対話プロンプトの前にファイルを実行する。
- `PYTHONINSPECT=1`: スクリプト終了後に対話モードへ入る。

これらは、制御可能な環境変数でPythonを呼び出すメンテナンススクリプト、デバッガ、シェル、ラッパーに対して有用です。`python -E` と `python -I` はすべての `PYTHON*` 変数を無視します。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perlには同様に便利な起動時変数があります:

- `PERL5LIB`: ライブラリディレクトリを先頭に追加する。
- `PERL5OPT`: すべての `perl` コマンドラインに含まれているかのようにスイッチを注入する。

これにより、対象スクリプトが何か面白い処理を始める前に、**自動的なモジュール読み込み**を強制したり、インタプリタの挙動を変更したりできます。Perlは **taint / setuid / setgid** のコンテキストではこれらの変数を無視しますが、通常の root 実行ラッパー、CI ジョブ、インストーラ、そしてカスタムの sudoers ルールでは依然として非常に重要です。
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
同じ考え方は他の runtime (`RUBYOPT`, `NODE_OPTIONS` など)にも当てはまる: privileged wrapper によって interpreter が起動されるたびに、**module loading** や **startup behavior** を変更する env vars を探すこと。

post-exploitation の観点からは、継承された environment にはしばしば **credentials**, **proxy settings**, **service tokens**, **cloud keys** が含まれることも忘れないでください。`/proc/<PID>/environ` と `systemd` `Environment=` の調査については [Linux Post Exploitation](linux-post-exploitation/README.md) を確認してください。

### PS1

プロンプトの見た目を変更します。

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
