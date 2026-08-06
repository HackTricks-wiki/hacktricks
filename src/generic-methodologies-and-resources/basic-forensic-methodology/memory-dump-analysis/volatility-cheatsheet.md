# Volatility - チートシート

{{#include ../../../banners/hacktricks-training.md}}

異なるスキャンレベルでメモリ解析を自動化し、複数の Volatility3 plugins を並列で実行するツールが必要な場合は、autoVolatility3:: [https://github.com/H3xKatana/autoVolatility3/](https://github.com/H3xKatana/autoVolatility3/) を使用できます。
```bash
# Full scan (runs all plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s full

# Minimal scan (runs a limited set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s minimal

# Normal scan (runs a balanced set of plugins)
python3 autovol3.py -f MEMFILE -o OUT_DIR -s normal

```
**高速でぶっ飛んだ**方法で、複数の Volatility plugins を並列実行したい場合は、次を使用できます：[https://github.com/carlospolop/autoVolatility](https://github.com/carlospolop/autoVolatility)
```bash
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -e /home/user/tools/volatility/vol.py # It will use the most important plugins (could use a lot of space depending on the size of the memory)
```
## インストール

### volatility3
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
python3 vol.py —h
```
### volatility2

{{#tabs}}
{{#tab name="Method1"}}
```
Download the executable from https://www.volatilityfoundation.org/26
```
{{#endtab}}

{{#tab name="Method 2"}}
```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```
{{#endtab}}
{{#endtabs}}

## Volatilityコマンド

公式ドキュメントは[Volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#kdbgscan)を参照してください。

### 「list」pluginと「scan」pluginに関する注意

Volatilityには、pluginに対する2つの主なアプローチがあり、それらが名前に反映されていることがあります。「list」pluginは、Windows Kernelの構造体をたどって、プロセス（メモリ内の`_EPROCESS`構造体のリンクリストを見つけてたどる）、OS handles（handle tableを見つけて一覧表示し、見つかったポインタをdereferenceするなど）といった情報を取得しようとします。これらは、おおむねWindows APIに対して、たとえばプロセス一覧の取得を要求した場合と同じように動作します。

そのため、「list」pluginは非常に高速ですが、malwareによる操作に対してWindows APIと同程度に脆弱です。たとえばmalwareがDKOMを使って`_EPROCESS`リンクリストからプロセスのリンクを解除すると、そのプロセスはTask Managerにもpslistにも表示されません。

一方、「scan」pluginは、特定の構造体としてdereferenceしたときに意味を持ちそうなものをメモリからcarvingするのに似たアプローチを取ります。たとえば`psscan`はメモリを読み取り、そこから`_EPROCESS`オブジェクトを作成しようとします（pool-tag scanningを使用します。これは、対象の構造体が存在することを示す4バイト文字列を検索する処理です）。この方法の利点は、終了したプロセスを掘り起こせることです。また、malwareが`_EPROCESS`リンクリストを改変しても、プロセスの実行には構造体が存在している必要があるため、pluginはメモリ上に残っている構造体を見つけられます。欠点は、「scan」pluginが「list」pluginより少し遅く、ときどきfalse positiveを生成することです（かなり前に終了し、他の処理によって構造体の一部が上書きされたプロセスなど）。

出典: [http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)<sup>[[6]](#references)</sup>

## OSプロファイル

### Volatility3

readmeに記載されているとおり、サポートしたいOSの**symbol table**を _volatility3/volatility/symbols_ 内に配置する必要があります。\
各種OS用のsymbol table packは、以下から**download**できます。

- [https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip)
- [https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip](https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip)

### Volatility2

#### External Profile

以下を実行すると、サポートされているprofileの一覧を取得できます。
```bash
./volatility_2.6_lin64_standalone --info | grep "Profile"
```
**ダウンロードした新しいプロファイル**（例：linux one）を使用する場合は、次のフォルダー構造をどこかに作成します： _plugins/overlays/linux_ 。その後、このフォルダー内にプロファイルを含む zip file を配置します。次に、以下を使用してプロファイルの数を取得します：
```bash
./vol --plugins=/home/kali/Desktop/ctfs/final/plugins --info
Volatility Foundation Volatility Framework 2.6


Profiles
--------
LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 - A Profile for Linux CentOS7_3.10.0-123.el7.x86_64_profile x64
VistaSP0x64                                   - A Profile for Windows Vista SP0 x64
VistaSP0x86                                   - A Profile for Windows Vista SP0 x86
```
[https://github.com/volatilityfoundation/profiles](https://github.com/volatilityfoundation/profiles) から **Linux と Mac の profile** を download できます。

前の chunk では、profile が `LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64` という名前であることが確認できます。これを使用して、次のようなコマンドを実行できます。
```bash
./vol -f file.dmp --plugins=. --profile=LinuxCentOS7_3_10_0-123_el7_x86_64_profilex64 linux_netscan
```
#### プロファイルの検出
```
volatility imageinfo -f file.dmp
volatility kdbgscan -f file.dmp
```
#### **imageinfo と kdbgscan の違い**

[**こちらから**](https://www.andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/): 単に profile の候補を提示する imageinfo とは異なり、**kdbgscan** は正しい profile と正しい KDBG アドレス（複数存在する場合）を確実に特定するよう設計されています。この plugin は Volatility profiles に関連付けられた KDBGHeader シグネチャをスキャンし、sanity checks を適用して false positives を減らします。出力の詳細度と実行可能な sanity checks の数は、Volatility が DTB を検出できるかどうかによって異なります。そのため、正しい profile をすでに把握している場合（または imageinfo から profile の候補が提示されている場合）は、必ずそれを .<sup>[[1]](#references)</sup>

**kdbgscan が検出したプロセス数**を必ず確認してください。imageinfo と kdbgscan は、適切な **profile** を複数検出することがありますが、**有効なものだけがプロセスに関連する情報を持ちます**（プロセスを抽出するには正しい KDBG アドレスが必要なためです）<sup>[[1]](#references)</sup>
```bash
# GOOD
PsActiveProcessHead           : 0xfffff800011977f0 (37 processes)
PsLoadedModuleList            : 0xfffff8000119aae0 (116 modules)
```

```bash
# BAD
PsActiveProcessHead           : 0xfffff800011947f0 (0 processes)
PsLoadedModuleList            : 0xfffff80001197ac0 (0 modules)
```
#### KDBG

**kernel debugger block** は、Volatility によって **KDBG** と呼ばれており、Volatility やさまざまな debugger が実行する forensic task に不可欠です。`KdDebuggerDataBlock` として識別され、`_KDDEBUGGER_DATA64` 型であるこのブロックには、`PsActiveProcessHead` などの重要な参照が含まれています。この特定の参照は process list の先頭を指しており、すべての process を一覧表示できます。これは、徹底的な memory analysis の基本です。<sup>[[2]](#references)</sup>

## OS 情報
```bash
#vol3 has a plugin to give OS information (note that imageinfo from vol2 will give you OS info)
./vol.py -f file.dmp windows.info.Info
```
The plugin `banners.Banners` can be used in **vol3 to try to find linux banners** in the dump.

## ハッシュ/パスワード

Extract SAM ハッシュ、[ドメインキャッシュ済み認証情報](../../../windows-hardening/stealing-credentials/credentials-protections.md#cached-credentials) and [LSA secrets](../../../windows-hardening/authentication-credentials-uac-and-efs/index.html#lsa-secrets).

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets
```
{{#endtab}}
{{#endtabs}}

## メモリダンプ

プロセスのメモリダンプは、プロセスの現在の状態に関する**すべてを抽出**します。**procdump**モジュールは**コード**のみを**抽出**します。
```
volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/
```
## プロセス

### プロセスの一覧表示

**疑わしい**プロセス（名前による）や、**予期しない**子**プロセス**（例：iexplorer.exe の子プロセスである cmd.exe）を見つけます。\
pslist の結果と psscan の結果を**比較**して、隠しプロセスを特定することも有用です。

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list
```
{{#endtab}}
{{#endtabs}}

### proc のダンプ

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

### コマンドライン

不審なものが実行されましたか？

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.cmdline.CmdLine #Display process command-line arguments
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments
volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION
```
{{#endtab}}
{{#endtabs}}

`cmd.exe` で実行されたコマンドは、**`conhost.exe`**（Windows 7 より前のシステムでは **`csrss.exe`**）によって管理されます。つまり、メモリダンプを取得する前に攻撃者によって **`cmd.exe`** が終了させられた場合でも、**`conhost.exe`** のメモリからセッションのコマンド履歴を復元できる可能性があります。これを行うには、コンソールのモジュール内で不審なアクティビティが検出された場合、関連する **`conhost.exe`** プロセスのメモリをダンプする必要があります。その後、このダンプ内で **strings** を検索することで、セッションで使用されたコマンドラインを抽出できる可能性があります。

### Environment

実行中の各プロセスの環境変数を取得します。興味深い値が含まれている可能性があります。

{{#tabs}}
{{#tab name="vol3"}}
```bash
python3 vol.py -f file.dmp windows.envars.Envars [--pid <pid>] #Display process environment variables
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=PROFILE envars -f file.dmp [--pid <pid>] #Display process environment variables

volatility --profile=PROFILE -f file.dmp linux_psenv [-p <pid>] #Get env of process. runlevel var means the runlevel where the proc is initated
```
{{#endtab}}
{{#endtabs}}

### Token privileges

予期しないサービスで privilege tokens を確認します。\
特権トークンを使用しているプロセスを一覧表示すると興味深い場合があります。

{{#tabs}}
{{#tab name="vol3"}}
```bash
#Get enabled privileges of some processes
python3 vol.py -f file.dmp windows.privileges.Privs [--pid <pid>]
#Get all processes with interesting privileges
python3 vol.py -f file.dmp windows.privileges.Privs | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get enabled privileges of some processes
volatility --profile=Win7SP1x86_23418 privs --pid=3152 -f file.dmp | grep Enabled
#Get all processes with interesting privileges
volatility --profile=Win7SP1x86_23418 privs -f file.dmp | grep "SeImpersonatePrivilege\|SeAssignPrimaryPrivilege\|SeTcbPrivilege\|SeBackupPrivilege\|SeRestorePrivilege\|SeCreateTokenPrivilege\|SeLoadDriverPrivilege\|SeTakeOwnershipPrivilege\|SeDebugPrivilege"
```
{{#endtab}}
{{#endtabs}}

### SIDs

各プロセスが所有するSIDを確認します。\
特権SIDを使用しているプロセス（および一部のサービスSIDを使用しているプロセス）を一覧表示すると、有用な情報が得られる可能性があります。

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.getsids.GetSIDs [--pid <pid>] #Get SIDs of processes
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 getsids -f file.dmp #Get the SID owned by each process
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp #Get the SID of each service
```
{{#endtab}}
{{#endtabs}}

### ハンドル

**process has a handle**（開いている）対象となる他のファイル、キー、スレッド、プロセスなどを把握するのに役立ちます

{{#tabs}}
{{#tab name="vol3"}}
```bash
vol.py -f file.dmp windows.handles.Handles [--pid <pid>]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp handles [--pid=<pid>]
```
{{#endtab}}
{{#endtabs}}

### DLLs

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.dlllist.DllList [--pid <pid>] #List dlls used by each
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --pid <pid> #Dump the .exe and dlls of the process in the current directory process
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 dlllist --pid=3152 -f file.dmp #Get dlls of a proc
volatility --profile=Win7SP1x86_23418 dlldump --pid=3152 --dump-dir=. -f file.dmp #Dump dlls of a proc
```
{{#endtab}}
{{#endtabs}}

### プロセスごとの文字列

Volatility を使用すると、文字列がどのプロセスに属しているかを確認できます。

{{#tabs}}
{{#tab name="vol3"}}
```bash
strings file.dmp > /tmp/strings.txt
./vol.py -f /tmp/file.dmp windows.strings.Strings --strings-file /tmp/strings.txt
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
strings file.dmp > /tmp/strings.txt
volatility -f /tmp/file.dmp windows.strings.Strings --string-file /tmp/strings.txt

volatility -f /tmp/file.dmp --profile=Win81U1x64 memdump -p 3532 --dump-dir .
strings 3532.dmp > strings_file
```
{{#endtab}}
{{#endtabs}}

yarascan moduleを使用して、プロセス内の文字列を検索することもできます。

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-rules "https://" --pid 3692 3840 3976 3312 3084 2784
./vol.py -f file.dmp yarascan.YaraScan --yara-rules "https://"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 yarascan -Y "https://" -p 3692,3840,3976,3312,3084,2784
```
{{#endtab}}
{{#endtabs}}

### UserAssist

**Windows** は、レジストリにある **UserAssist keys** と呼ばれる機能を使用して、実行したプログラムを追跡します。これらのキーには、各プログラムの実行回数と最後に実行された日時が記録されます。<sup>[[3]](#references)</sup>

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.userassist.UserAssist
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp userassist
```
{{#endtab}}
{{#endtabs}}

## サービス

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.svcscan.SvcScan #List services
./vol.py -f file.dmp windows.getservicesids.GetServiceSIDs #Get the SID of services
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#Get services and binary path
volatility --profile=Win7SP1x86_23418 svcscan -f file.dmp
#Get name of the services and SID (slow)
volatility --profile=Win7SP1x86_23418 getservicesids -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## ネットワーク

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.netscan.NetScan
#For network info of linux use volatility2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 netscan -f file.dmp
volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only
volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections
volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets
volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

volatility --profile=SomeLinux -f file.dmp linux_ifconfig
volatility --profile=SomeLinux -f file.dmp linux_netstat
volatility --profile=SomeLinux -f file.dmp linux_netfilter
volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table
volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)
volatility --profile=SomeLinux -f file.dmp linux_route_cache
```
{{#endtab}}
{{#endtabs}}

## Registry hive

### 利用可能な hive を表示

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.hivelist.HiveList #List roots
./vol.py -f file.dmp windows.registry.printkey.PrintKey #List roots and get initial subkeys
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist #List roots
volatility --profile=Win7SP1x86_23418 -f file.dmp printkey #List roots and get initial subkeys
```
{{#endtab}}
{{#endtabs}}

### 値を取得する

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows NT\CurrentVersion" -f file.dmp
# Get Run binaries registry value
volatility -f file.dmp --profile=Win7SP1x86 printkey -o 0x9670e9d0 -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
{{#endtab}}
{{#endtabs}}

### ダンプ
```bash
#Dump a hive
volatility --profile=Win7SP1x86_23418 hivedump -o 0x9aad6148 -f file.dmp #Offset extracted by hivelist
#Dump all hives
volatility --profile=Win7SP1x86_23418 hivedump -f file.dmp
```
## ファイルシステム

### マウント

{{#tabs}}
{{#tab name="vol3"}}
```bash
#See vol2
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=SomeLinux -f file.dmp linux_mount
volatility --profile=SomeLinux -f file.dmp linux_recover_filesystem #Dump the entire filesystem (if possible)
```
{{#endtab}}
{{#endtabs}}

### スキャン/ダンプ

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.filescan.FileScan #Scan for files inside the dump
./vol.py -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA> #Offset from previous command
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 filescan -f file.dmp #Scan for files inside the dump
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -f file.dmp #Dump all files
volatility --profile=Win7SP1x86_23418 dumpfiles -n --dump-dir=/tmp -Q 0x000000007dcaa620 -f file.dmp

volatility --profile=SomeLinux -f file.dmp linux_enumerate_files
volatility --profile=SomeLinux -f file.dmp linux_find_file -F /path/to/file
volatility --profile=SomeLinux -f file.dmp linux_find_file -i 0xINODENUMBER -O /path/to/dump/file
```
{{#endtab}}
{{#endtabs}}

### マスターファイルテーブル

{{#tabs}}
{{#tab name="vol3"}}
```bash
# I couldn't find any plugin to extract this information in volatility3
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mftparser -f file.dmp
```
{{#endtab}}
{{#endtabs}}

**NTFS file system** は、_master file table_ (MFT) と呼ばれる重要なコンポーネントを使用します。このテーブルには、MFT 自体も含め、ボリューム上のすべてのファイルについて少なくとも 1 つのエントリが含まれます。各ファイルに関する **size、timestamps、permissions、actual data** などの重要な詳細は、MFT エントリ内、またはこれらのエントリから参照される MFT 外部の領域に格納されています。詳細については、[official documentation](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table) を参照してください。<sup>[[4]](#references)</sup>

### SSL Keys/Certs

{{#tabs}}
{{#tab name="vol3"}}
```bash
#vol3 allows to search for certificates inside the registry
./vol.py -f file.dmp windows.registry.certificates.Certificates
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
#vol2 allos you to search and dump certificates from memory
#Interesting options for this modules are: --pid, --name, --ssl
volatility --profile=Win7SP1x86_23418 dumpcerts --dump-dir=. -f file.dmp
```
{{#endtab}}
{{#endtabs}}

## マルウェア

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.malfind.Malfind [--dump] #Find hidden and injected code, [dump each suspicious section]
#Malfind will search for suspicious structures related to malware
./vol.py -f file.dmp windows.driverirp.DriverIrp #Driver IRP hook detection
./vol.py -f file.dmp windows.ssdt.SSDT #Check system call address from unexpected addresses

./vol.py -f file.dmp linux.check_afinfo.Check_afinfo #Verifies the operation function pointers of network protocols
./vol.py -f file.dmp linux.check_creds.Check_creds #Checks if any processes are sharing credential structures
./vol.py -f file.dmp linux.check_idt.Check_idt #Checks if the IDT has been altered
./vol.py -f file.dmp linux.check_syscall.Check_syscall #Check system call table for hooks
./vol.py -f file.dmp linux.check_modules.Check_modules #Compares module list to sysfs info, if available
./vol.py -f file.dmp linux.tty_check.tty_check #Checks tty devices for hooks
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
volatility --profile=Win7SP1x86_23418 -f file.dmp driverirp #Driver IRP hook detection
volatility --profile=Win7SP1x86_23418 -f file.dmp ssdt #Check system call address from unexpected addresses

volatility --profile=SomeLinux -f file.dmp linux_check_afinfo
volatility --profile=SomeLinux -f file.dmp linux_check_creds
volatility --profile=SomeLinux -f file.dmp linux_check_fop
volatility --profile=SomeLinux -f file.dmp linux_check_idt
volatility --profile=SomeLinux -f file.dmp linux_check_syscall
volatility --profile=SomeLinux -f file.dmp linux_check_modules
volatility --profile=SomeLinux -f file.dmp linux_check_tty
volatility --profile=SomeLinux -f file.dmp linux_keyboard_notifiers #Keyloggers
```
{{#endtab}}
{{#endtabs}}

### yaraによるスキャン

このスクリプトを使用して、githubからすべてのyaraマルウェアルールをダウンロードして統合します: [https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9](https://gist.github.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9)\
_**rules**_ディレクトリを作成して実行します。これにより、マルウェア用のすべてのyaraルールを含む_**malware_rules.yar**_というファイルが作成されます。

{{#tabs}}
{{#tab name="vol3"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
#Only Windows
./vol.py -f file.dmp windows.vadyarascan.VadYaraScan --yara-file /tmp/malware_rules.yar
#All
./vol.py -f file.dmp yarascan.YaraScan --yara-file /tmp/malware_rules.yar
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
wget https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py
mkdir rules
python malware_yara_rules.py
volatility --profile=Win7SP1x86_23418 yarascan -y malware_rules.yar -f ch2.dmp | grep "Rule:" | grep -v "Str_Win32" | sort | uniq
```
{{#endtab}}
{{#endtabs}}

## MISC

### 外部プラグイン

外部プラグインを使用する場合は、プラグイン関連のフォルダを最初に使用するパラメーターに指定してください。

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py --plugin-dirs "/tmp/plugins/" [...]
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatilitye --plugins="/tmp/plugins/" [...]
```
{{#endtab}}
{{#endtabs}}

#### Autoruns

[https://github.com/tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) からダウンロードします。
```
volatility --plugins=volatility-autoruns/ --profile=WinXPSP2x86 -f file.dmp autoruns
```
### Mutexes

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.mutantscan.MutantScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 mutantscan -f file.dmp
volatility --profile=Win7SP1x86_23418 -f file.dmp handles -p <PID> -t mutant
```
{{#endtab}}
{{#endtabs}}

### シンボリックリンク

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp windows.symlinkscan.SymlinkScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp symlinkscan
```
{{#endtab}}
{{#endtabs}}

### Bash

**メモリから bash の履歴を読み取ることが可能です。** _.bash_history_ ファイルを dump することもできますが、それが無効化されていた場合は、この Volatility module を使用できてよかったと思うでしょう。

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp linux.bash.Bash
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f file.dmp linux_bash
```
{{#endtab}}
{{#endtabs}}

### タイムライン

{{#tabs}}
{{#tab name="vol3"}}
```bash
./vol.py -f file.dmp timeLiner.TimeLiner
```
{{#endtab}}

{{#tab name="vol2"}}
```
volatility --profile=Win7SP1x86_23418 -f timeliner
```
{{#endtab}}
{{#endtabs}}

### ドライバー

{{#tabs}}
{{#tab name="vol3"}}
```
./vol.py -f file.dmp windows.driverscan.DriverScan
```
{{#endtab}}

{{#tab name="vol2"}}
```bash
volatility --profile=Win7SP1x86_23418 -f file.dmp driverscan
```
{{#endtab}}
{{#endtabs}}

### クリップボードの取得
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 clipboard -f file.dmp
```
### IEの履歴を取得
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 iehistory -f file.dmp
```
### notepadのテキストを取得
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 notepad -f file.dmp
```
翻訳するテキストまたは画像が提供されていません。
```bash
#Just vol2
volatility --profile=Win7SP1x86_23418 screenshot -f file.dmp
```
### マスターブートレコード（MBR）
```bash
volatility --profile=Win7SP1x86_23418 mbrparser -f file.dmp
```
**Master Boot Record (MBR)** は、異なる [file systems](https://en.wikipedia.org/wiki/File_system) で構成されたストレージメディアの論理パーティションを管理するうえで重要な役割を果たします。パーティションレイアウト情報を保持するだけでなく、boot loader として機能する実行可能なコードも含まれています。この boot loader は、OS の第2段階の読み込み処理（[second-stage boot loader](https://en.wikipedia.org/wiki/Second-stage_boot_loader) を参照）を直接開始するか、各パーティションの [volume boot record](https://en.wikipedia.org/wiki/Volume_boot_record)（VBR）と連携して動作します。詳しくは [MBR Wikipedia page](https://en.wikipedia.org/wiki/Master_boot_record) を参照してください。<sup>[[5]](#references)</sup>

## References

- [1] [Volatility、私の cheatsheet（Part 1）：Image Identification](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/)
- [2] [Kernel Debugger Block の発見](https://scudette.blogspot.com/2012/11/finding-kernel-debugger-block.html)
- [3] [Windows UserAssist Keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [4] [Master File Table（Local File Systems）- Win32 apps](https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [5] [UEFI-based PC、protective MBR：これは何か？ - Microsoft Community](https://answers.microsoft.com/en-us/windows/forum/all/uefi-based-pc-protective-mbr-what-is-it/0fc7b558-d8d4-4a7d-bae2-395455bb19aa)
- [6] [Tutorial：malware analysis 用 Volatility plugins](http://tomchop.me/2016/11/21/tutorial-volatility-plugins-malware-analysis/)

{{#include ../../../banners/hacktricks-training.md}}
