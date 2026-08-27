# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes の基本情報

プロセスは実行中の executable のインスタンスですが、実際に code を実行するのはプロセスではなく thread です。したがって、**processes は実行中の threads のための単なる container** であり、memory、descriptors、ports、permissions などを提供します。

従来、プロセスは PID 1 を除き、**`fork`** を呼び出して他のプロセス内で開始されていました。`fork` は現在のプロセスの完全なコピーを作成し、その後、**child process** は通常 **`execve`** を呼び出して新しい executable をロードし、実行していました。その後、memory のコピーを行わずにこのプロセスを高速化するため、**`vfork`** が導入されました。\
続いて、**`vfork`** と **`execve`** を1回の call に統合し、flags を受け付ける **`posix_spawn`** が導入されました。

- `POSIX_SPAWN_RESETIDS`: effective ids を real ids にリセット
- `POSIX_SPAWN_SETPGROUP`: process group の所属を設定
- `POSUX_SPAWN_SETSIGDEF`: signal のデフォルト動作を設定
- `POSIX_SPAWN_SETSIGMASK`: signal mask を設定
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内で Exec（より多くの options を持つ `execve` と同様）
- `POSIX_SPAWN_START_SUSPENDED`: suspended 状態で開始
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR なしで開始
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc の Nano allocator を使用
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segments 上で `rwx` を許可
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトで exec(2) 時にすべての file descriptions を close
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide の high bits を randomize

さらに、`posix_spawn` は、spawn されたプロセスの各種要素を制御する **`posix_spawnattr`** settings と、file descriptors を変更する **`posix_spawn_file_actions`** entries を受け付けます。

プロセスが終了すると、signal `SIGCHLD` とともに **return code を parent process に送信** します（parent が終了していた場合、新しい parent は PID 1 です）。parent は `wait4()` または `waitid()` を呼び出してこの値を取得する必要があり、それが行われるまで child は zombie state に留まります。この状態では child は引き続き一覧に表示されますが、resources は消費しません。

### PIDs

PIDs（process identifiers）は、一意のプロセスを識別します。XNU における **PIDs** は **64bits** で、単調増加し、**wrap することはありません**（abuses を防ぐため）。

### Process Groups, Sessions & Coalations

**Processes** は、扱いやすくするために **groups** に含めることができます。たとえば、shell script 内の commands は同じ process group に属するため、kill などを使用して **まとめて signal を送信** できます。\
processes を **sessions に group 化** することもできます。ある process が session（`setsid(2)`）を開始すると、children processes は独自の session を開始しない限り、その session 内に設定されます。

Coalition は Darwin における、processes を group 化する別の方法です。process が coalition に参加すると、pool resources にアクセスし、ledger を共有したり、Jetsam の対象になったりできます。Coalitions には、Leader、XPC service、Extension という異なる roles があります。

### Credentials & Personae

各 process は、system 内での **privileges を識別する** **credentials** を保持します。各 process には primary `uid` と primary `gid` が1つずつあります（ただし、複数の groups に所属する場合があります）。\
binary に **`setuid/setgid`** bit がある場合、user と group id を変更することもできます。\
**新しい uids/gids を設定する** functions がいくつか存在します。

syscall **`persona`** は、**credentials** の **alternate** set を提供します。persona を採用すると、その uid、gid、group memberships を **同時に** 引き継ぎます。[**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) には、struct を確認できます。
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## スレッドの基本情報

1. **POSIX Threads (pthreads):** macOS は POSIX threads（`pthreads`）をサポートしています。これは C/C++ 用の標準 threading API の一部です。macOS における pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、公開されている `libpthread` project に由来します。この library は、スレッドの作成と管理に必要な関数を提供します。
2. **スレッドの作成:** `pthread_create()` function は、新しいスレッドの作成に使用されます。内部的には、この function は `bsdthread_create()` を呼び出します。これは XNU kernel（macOS の基盤となる kernel）固有の、より低レベルな system call です。この system call は、スレッドの動作を指定する `pthread_attr`（attributes）から派生したさまざまな flags を受け取ります。これには scheduling policies や stack size が含まれます。
- **Default Stack Size:** 新しいスレッドの default stack size は 512 KB です。通常の操作には十分なサイズですが、必要に応じて thread attributes で増減できます。
3. **スレッドの初期化:** `__pthread_init()` function はスレッドの setup において重要です。この function は `env[]` argument を使用して environment variables を解析します。environment variables には、stack の location や size に関する情報を含めることができます。

#### macOS におけるスレッドの終了

1. **スレッドの終了:** スレッドは通常、`pthread_exit()` を呼び出して終了します。この function により、スレッドは必要な cleanup を実行して正常に終了し、joiner に return value を返すことができます。
2. **スレッドの cleanup:** `pthread_exit()` を呼び出すと、`pthread_terminate()` function が呼び出され、関連するすべての thread structures の削除を処理します。この function は Mach thread ports（Mach は XNU kernel の communication subsystem）を deallocate し、`bsdthread_terminate` を呼び出します。これは、スレッドに関連付けられた kernel-level structures を削除する syscall です。

#### Synchronization Mechanisms

shared resources への access を管理し、race conditions を回避するため、macOS は複数の synchronization primitives を提供しています。これらは、data integrity と system stability を確保するために、multi-threading environments で重要です。

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** memory footprint が 60 bytes（mutex が 56 bytes、signature が 4 bytes）の標準 mutex です。
- **Fast Mutex (Signature: 0x4d55545A):** Regular Mutex に似ていますが、より高速な操作向けに最適化されており、size も 60 bytes です。
2. **Condition Variables:**
- 特定の条件が発生するまで待機するために使用され、size は 44 bytes（40 bytes と 4-byte signature）です。
- **Condition Variable Attributes (Signature: 0x434e4441):** condition variables の configuration attributes で、size は 12 bytes です。
3. **Once Variable (Signature: 0x4f4e4345):**
- initialization code の一部が一度だけ実行されることを保証します。size は 12 bytes です。
4. **Read-Write Locks:**
- 複数の reader または 1 つの writer が同時に access でき、shared data への効率的な access を可能にします。
- **Read Write Lock (Signature: 0x52574c4b):** size は 196 bytes です。
- **Read Write Lock Attributes (Signature: 0x52574c41):** read-write locks の attributes で、size は 20 bytes です。

> [!TIP]
> これらの objects の最後の 4 bytes は、overflow を検出するために使用されます。

### Thread Local Variables (TLV)

Mach-O files（macOS の executables の format）の context における **Thread Local Variables (TLV)** は、multi-threaded application の **各スレッド** に固有の variables を宣言するために使用されます。これにより、各スレッドが variable の独立した instance を持つことができ、mutexes のような明示的な synchronization mechanisms を必要とせずに、conflicts を回避して data integrity を維持できます。

C および関連する languages では、**`__thread`** keyword を使用して thread-local variable を宣言できます。以下のように、example では動作します：
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
このスニペットでは、`tlv_var`をスレッドローカル変数として定義しています。このコードを実行する各スレッドは、それぞれ独自の`tlv_var`を持ち、あるスレッドが`tlv_var`に加えた変更は、別のスレッドの`tlv_var`には影響しません。

Mach-Oバイナリでは、スレッドローカル変数に関連するデータは、特定のセクションに整理されています。

- **`__DATA.__thread_vars`**: このセクションには、型や初期化状態など、スレッドローカル変数に関するメタデータが含まれます。
- **`__DATA.__thread_bss`**: このセクションは、明示的に初期化されていないスレッドローカル変数に使用されます。ゼロ初期化データ用に確保されたメモリの一部です。

Mach-Oには、スレッド終了時にスレッドローカル変数を管理するための`tlv_atexit`という専用APIもあります。このAPIを使用すると、スレッド終了時にスレッドローカルデータをクリーンアップする**destructorを登録**できます。

### スレッドの優先度

スレッドの優先度を理解するには、オペレーティングシステムがどのスレッドをいつ実行するかを決定する方法を確認する必要があります。この決定には、各スレッドに割り当てられた優先度レベルが影響します。macOSおよびUnix系システムでは、これは`nice`、`renice`、Quality of Service（QoS）クラスなどの概念を使用して処理されます。

#### NiceとRenice

1. **Nice:**
- プロセスの`nice`値は、その優先度に影響する数値です。すべてのプロセスには、-20（最高優先度）から19（最低優先度）までのnice値があります。プロセス作成時のデフォルトのnice値は通常0です。
- より低いnice値（-20に近い値）にすると、プロセスはより「利己的」になり、nice値が高い他のプロセスと比べて多くのCPU時間を取得します。
2. **Renice:**
- `renice`は、すでに実行中のプロセスのnice値を変更するために使用するコマンドです。新しいnice値に基づいてCPU時間の割り当てを増減させ、プロセスの優先度を動的に調整できます。
- 例えば、プロセスが一時的により多くのCPUリソースを必要とする場合、`renice`を使用してそのnice値を下げることができます。

#### Quality of Service（QoS）クラス

QoSクラスは、特に**Grand Central Dispatch（GCD）**をサポートするmacOSのようなシステムで、スレッドの優先度を扱うより現代的な方法です。QoSクラスを使用すると、開発者は重要度や緊急度に基づいて作業を異なるレベルに**分類**できます。macOSは、これらのQoSクラスに基づいてスレッドの優先順位付けを自動的に管理します。

1. **User Interactive:**
- 現在ユーザーと対話しているタスク、または優れたユーザー体験を提供するために即時の結果が必要なタスク向けのクラスです。インターフェースの応答性を維持するため、これらのタスクには最高の優先度が与えられます（アニメーションやイベント処理など）。
2. **User Initiated:**
- ドキュメントを開く、計算が必要なボタンをクリックするなど、ユーザーが開始し、即時の結果を期待するタスク向けです。高い優先度ですが、User Interactiveよりは低くなります。
3. **Utility:**
- 長時間実行され、通常は進捗インジケーターを表示するタスク向けです（ファイルのダウンロードやデータのインポートなど）。User Initiatedのタスクより優先度が低く、直ちに完了する必要はありません。
4. **Background:**
- バックグラウンドで動作し、ユーザーには表示されないタスク向けのクラスです。インデックス作成、同期、バックアップなどが該当します。優先度が最も低く、システムパフォーマンスへの影響も最小限です。

QoSクラスを使用すると、開発者は正確な優先度の数値を管理する必要がなく、タスクの性質に集中できます。システムはそれに応じてCPUリソースを最適化します。

さらに、スケジューラが考慮するスケジューリングパラメータの組を指定する、さまざまな**thread scheduling policies**があります。これは`thread_policy_[set/get]`を使用して設定できます。これはrace condition attacksで役立つ可能性があります。

## macOS Process Abuse

macOSには、**プロセスが相互に作用し、通信し、データを共有する**ための多くのメカニズムがあります。これらのメカニズムは通常のシステム動作に不可欠ですが、攻撃者はこれらをinjection、code execution、データアクセスに悪用できます。

### Library Injection

Library Injectionは、攻撃者が**プロセスに悪意のあるライブラリを強制的にロードさせる**techniqueです。injection後、ライブラリは対象プロセスのコンテキストで実行され、攻撃者にそのプロセスと同じ権限およびアクセス権を与えます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hookingは、ソフトウェアコード内の**function call**またはメッセージを**intercept**することです。functionをhookすると、攻撃者はプロセスの**挙動を変更**したり、機密データを監視したり、実行フローを制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication（IPC）は、分離されたプロセスが**データを共有および交換する**さまざまな方法を指します。IPCは多くの正当なアプリケーションにとって基本的なものですが、プロセス分離のsubvert、機密情報のleak、不正な操作の実行にも悪用できます。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定のenv variablesを指定して実行されたElectron applicationsは、process injectionに対して脆弱になる可能性があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension`および`--use-fake-ui-for-media-stream` flagsを使用して**man in the browser attack**を実行し、keystrokes、traffic、cookiesを盗んだり、ページにscriptsをinjectしたりできます。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB filesは、アプリケーション内の**user interface（UI）elements**とそのinteractionを**定義**します。しかし、任意のcommandsを**実行でき**、**NIB fileが変更されても**、Gatekeeperはすでに実行されたアプリケーションの再実行を**阻止しません**。そのため、任意のprogramsに任意のcommandsを実行させるために使用できます。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`**、または**`JDK_JAVA_OPTIONS`**を通じてJVM optionsをinjectし、アプリケーションの開始前にJavaまたはnative agentをロードできます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

`Main`の前に**`DOTNET_STARTUP_HOOKS`**を通じて.NET applicationsへcodeをinjectしたり、必要な前提条件が存在する場合に.NET debugging functionalityを悪用したりできます。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Non-interactive Bashは**`BASH_ENV`**を読み込み、zshは**`$ZDOTDIR/.zshenv`**を読み込み、fishは**`XDG_CONFIG_HOME`**または**`XDG_DATA_DIRS`**以下のconfigurationを読み込みます。それぞれが、意図されたcommandの前に制御下のstartup fileを実行できます。

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`**または**`PHP_INI_SCAN_DIR`**によって制御下のPHP configurationをロードでき、その**`auto_prepend_file`**がtarget scriptの前に実行されます。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

standalone Lua interpreterは、target scriptを処理する前に**`LUA_INIT`**（またはversion-specific variant）からcodeまたは`@file`を実行します。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`**および**`R_PROFILE`**は、R codeを含むstartup profilesへリダイレクトします。**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**とR library pathを組み合わせることで、インストール済みのpackageをauto-loadすることもできます。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**は、`config/startup.jl`が自動実行されるdepotへリダイレクトします。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`**、または**`ERL_ZFLAGS`**によって、payload fileを必要とせずにErlang VMの**`-eval`** expressionをinjectできます。Elixir workloadsは通常、同じVMを起動します。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`**および**`OCTAVE_VERSION_INITFILE`**は、Octave startup scriptsをリダイレクトします。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

macOSおよびLinuxでは、**`XDG_CONFIG_HOME`**によって、`pwsh`の起動時に実行されるPowerShell user profilesをリダイレクトできます。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl scriptに任意のcodeを実行させるためのさまざまなoptionsを、以下で確認できます。


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

rubyのenv variablesを悪用して、任意のscriptsに任意のcodeを実行させることもできます。


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`**および**`BROWSER`** standard-library chainは、warning-filter parsing中にcommandを実行できます。file-backed alternativeでは、**`PYTHONPATH`**上に`sitecustomize.py`を配置することで、通常の`site` initialization時にtarget scriptより前にimportさせます。**`PYTHONSTARTUP`**などのinteractive-only variablesは、適用範囲がより限定されます。

なお、**`pyinstaller`**でコンパイルされたexecutablesは、embedded pythonを使用して実行されている場合でも、これらのenvironmental variablesを使用しません。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

これとは別に、Homebrewは通常、Pythonを`/opt/homebrew`以下にインストールします。この場合、ローカルの`admin` groupのメンバーがlauncherを置き換えられる可能性があります。これはenvironment-variable injectionではなくwritable-binary hijackであるため、exploit可能と判断する前にownershipとACLsを確認してください。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield)は、process injectionを検出およびblockする、open-sourceの**EndpointSecurity**ベースのapplicationです。Endpoint Securityを通じてどのsignalが観測可能かを知るための良いreferenceであり、以下をalertします。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- process exec時の**Injection environment variables**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** calls — あるprocessが別のprocessのtask portを要求する処理であり、そのprocessへinjectするための前提条件です。
- **Electron debugging arguments** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらはElectron appをdebug modeで起動し、誰でもattachしてcodeを実行できるようにします。<sup>[[3]](#references)</sup>
- **権限レベルをまたぐsymlink/hardlink creation** — 「通常のuserとしてlinkを作成し、privileged locationを指す」という古典的なprimitiveです。なお、**symlinkはalertできますがblockはできません**。EndpointSecurityは、作成前のlink destinationを公開しないためです。

### Calls made by other processes

[**このblog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、function **`task_name_for_pid`**を使用して、**あるprocessにcodeをinjectしている他のprocess**に関する情報を取得し、その後、その別のprocessに関する情報を取得する方法を確認できます。<sup>[[4]](#references)</sup>

このfunctionをcallするには、対象processを実行しているuserと**同じuid**であるか、**root**である必要があります（このfunctionが返すのはprocessに関する情報であり、codeをinjectする方法ではありません）。

## References

- [1] [Shield — open-sourceのmacOS process-injection detection（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron appsがsecretsをconfidentialに保存できない理由: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task modificationsの検出](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
