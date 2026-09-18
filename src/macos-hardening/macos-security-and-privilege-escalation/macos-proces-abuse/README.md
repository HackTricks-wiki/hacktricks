# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## プロセスの基本情報

プロセスは実行中の実行ファイルのインスタンスですが、プロセスはコードを実行せず、実行するのはスレッドです。したがって、**プロセスは実行中のスレッド用の単なるコンテナ**であり、メモリ、ディスクリプタ、ポート、権限などを提供します。

従来、プロセスは（PID 1を除き）**`fork`**を呼び出すことで他のプロセス内から開始されていました。`fork`は現在のプロセスの完全なコピーを作成し、その後、**子プロセス**は通常、**`execve`**を呼び出して新しい実行ファイルをロードし、実行していました。その後、メモリコピーなしでこの処理を高速化するために**`vfork`**が導入されました。\
次に、**`vfork`**と**`execve`**を1回の呼び出しに統合し、フラグを受け付ける**`posix_spawn`**が導入されました。

- `POSIX_SPAWN_RESETIDS`: 実効IDを実IDにリセット
- `POSIX_SPAWN_SETPGROUP`: プロセスグループへの所属を設定
- `POSUX_SPAWN_SETSIGDEF`: シグナルのデフォルト動作を設定
- `POSIX_SPAWN_SETSIGMASK`: シグナルマスクを設定
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内でExec（より多くのオプションを持つ`execve`と同様）
- `POSIX_SPAWN_START_SUSPENDED`: サスペンド状態で開始
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLRなしで開始
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmallocのNano allocatorを使用
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` データセグメントで`rwx`を許可
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトでexec(2)時にすべてのファイルディスクリプションを閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLRスライドの上位ビットをランダム化

さらに、`posix_spawn`は、生成されるプロセスの各種要素を制御する**`posix_spawnattr`**設定と、ファイルディスクリプタを変更する**`posix_spawn_file_actions`**エントリを受け付けます。

プロセスが終了すると、シグナル`SIGCHLD`によって**親プロセスに終了コードを送信**します（親プロセスが終了していた場合、新しい親プロセスはPID 1です）。親プロセスは`wait4()`または`waitid()`を呼び出してこの値を取得する必要があり、それが行われるまで子プロセスはゾンビ状態になります。この状態でも子プロセスは一覧に表示されますが、リソースは消費しません。

### PIDs

PIDs（プロセス識別子）は、一意のプロセスを識別します。XNUでは、**PIDs**は**64ビット**で単調増加し、**ラップアラウンドしません**（abuseを防ぐため）。

### プロセスグループ、セッション、Coalations

**プロセス**は、扱いやすくするために**グループ**に入れることができます。例えば、shell script内のコマンドは同じプロセスグループに属するため、killなどを使って**まとめてシグナルを送信**できます。\
プロセスを**セッションにグループ化**することもできます。プロセスがセッション（`setsid(2)`）を開始すると、その子プロセスは独自のセッションを開始しない限り、そのセッション内に配置されます。

Coalitionは、Darwinでプロセスをグループ化する別の方法です。プロセスがcoalitionに参加すると、プールリソースにアクセスし、ledgerを共有したり、Jetsamの対象になったりします。Coalitionには、Leader、XPC service、Extensionという異なるroleがあります。

### CredentialsとPersonae

各プロセスは、システム上の**権限を識別する** **credentials**を保持しています。各プロセスには1つのプライマリ`uid`と1つのプライマリ`gid`があります（ただし、複数のグループに所属する場合があります）。\
バイナリに`setuid/setgid`ビットが設定されている場合、ユーザーIDとグループIDを変更することもできます。\
**新しいuid/gidを設定する**ための関数がいくつか存在します。

syscall **`persona`**は、**credentials**の**代替**セットを提供します。personaを採用すると、そのuid、gid、グループメンバーシップを**同時に**引き継ぎます。[**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)には、structがあります。
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
## Threads の基本情報

1. **POSIX Threads (pthreads):** macOS は POSIX threads (`pthreads`) をサポートしています。これは C/C++ 用の標準 threading API の一部です。macOS における pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、公開されている `libpthread` project に由来します。この library は、thread の作成および管理に必要な関数を提供します。
2. **Creating Threads:** `pthread_create()` function は、新しい thread の作成に使用されます。内部的には、この function は `bsdthread_create()` を呼び出します。これは XNU kernel（macOS の基盤となる kernel）固有の低レベル system call です。この system call は、thread の動作（scheduling policies や stack size など）を指定する `pthread_attr`（attributes）から派生した各種 flags を受け取ります。
- **Default Stack Size:** 新しい thread の default stack size は 512 KB です。一般的な操作には十分なサイズですが、より多く、または少ない領域が必要な場合は、thread attributes によって調整できます。
3. **Thread Initialization:** `__pthread_init()` function は thread setup 中に重要な役割を果たし、`env[]` argument を使用して environment variables を解析します。これらには stack の location や size に関する詳細を含めることができます。

#### macOS における Thread Termination

1. **Exiting Threads:** Thread は通常、`pthread_exit()` を呼び出して終了します。この function により、thread は必要な cleanup を実行し、正常に終了できます。また、joiner に return value を返すこともできます。
2. **Thread Cleanup:** `pthread_exit()` の呼び出し時には `pthread_terminate()` function が呼び出され、関連するすべての thread structures の削除を処理します。この function は Mach thread ports（Mach は XNU kernel 内の通信 subsystem）を deallocate し、`bsdthread_terminate` を呼び出します。これは thread に関連付けられた kernel-level structures を削除する syscall です。

#### Synchronization Mechanisms

共有 resources への access を管理し、race conditions を回避するため、macOS は複数の synchronization primitives を提供しています。これらは multi-threading environments において、data integrity と system stability を確保するために重要です。

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** 60 bytes の memory footprint を持つ標準的な mutex です（mutex に 56 bytes、signature に 4 bytes）。
- **Fast Mutex (Signature: 0x4d55545A):** regular mutex と同様ですが、より高速な操作向けに最適化されており、サイズも 60 bytes です。
2. **Condition Variables:**
- 特定の conditions が発生するまで待機するために使用され、サイズは 44 bytes です（40 bytes と 4-byte signature）。
- **Condition Variable Attributes (Signature: 0x434e4441):** condition variables の configuration attributes で、サイズは 12 bytes です。
3. **Once Variable (Signature: 0x4f4e4345):**
- initialization code の一部が一度だけ実行されることを保証します。サイズは 12 bytes です。
4. **Read-Write Locks:**
- 複数の reader、または一度に 1 つの writer を許可し、共有 data への効率的な access を実現します。
- **Read Write Lock (Signature: 0x52574c4b):** サイズは 196 bytes です。
- **Read Write Lock Attributes (Signature: 0x52574c41):** read-write locks の attributes で、サイズは 20 bytes です。

> [!TIP]
> これらの objects の最後の 4 bytes は、overflows を検出するために使用されます。

### Thread Local Variables (TLV)

Mach-O files（macOS の executables 用 format）のコンテキストにおける **Thread Local Variables (TLV)** は、multi-threaded application 内の **各 thread** に固有の variables を宣言するために使用されます。これにより、各 thread が variable の独立した instance を持つことができ、mutexes のような明示的な synchronization mechanisms を必要とせずに conflicts を回避し、data integrity を維持できます。

C および関連する languages では、**`__thread`** keyword を使用して thread-local variable を宣言できます。以下の例では、次のように動作します：
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
このスニペットでは、`tlv_var`をthread-local variableとして定義しています。このコードを実行する各threadは、それぞれ独自の`tlv_var`を持ち、あるthreadによる`tlv_var`への変更が別のthreadの`tlv_var`に影響することはありません。

Mach-O binaryでは、thread local variablesに関連するデータが特定のsectionに整理されています。

- **`__DATA.__thread_vars`**: このsectionには、型や初期化状態など、thread-local variablesに関するmetadataが含まれます。
- **`__DATA.__thread_bss`**: このsectionは、明示的に初期化されていないthread-local variablesに使用されます。zero-initialized data用に確保されたmemoryの一部です。

Mach-Oには、thread終了時にthread-local variablesを管理するための**`tlv_atexit`**という専用APIもあります。このAPIを使用すると、thread終了時にthread-local dataをクリーンアップする**destructors**（特殊なcleanup function）を**register**できます。

### Threading Priorities

Thread prioritiesを理解するには、operating systemがいつどのthreadを実行するかをどのように決定するかを見る必要があります。この決定には、各threadに割り当てられたpriority levelが影響します。macOSやUnix-like systemsでは、これは`nice`、`renice`、Quality of Service (QoS) classesなどの概念を使用して処理されます。

#### Nice and Renice

1. **Nice:**
- processの`nice` valueは、そのpriorityに影響するnumberです。すべてのprocessには、-20（最高priority）から19（最低priority）までのnice valueがあります。process作成時のdefault nice valueは通常0です。
- より低いnice value（-20に近い値）にすると、processはより「selfish」になり、より高いnice valueを持つ他のprocessと比較して、より多くのCPU timeを得ます。
2. **Renice:**
- `renice`は、すでに実行中のprocessのnice valueを変更するためのcommandです。これにより、新しいnice valueに基づいてCPU timeの割り当てを増減し、processのpriorityを動的に調整できます。
- 例えば、processが一時的により多くのCPU resourcesを必要とする場合、`renice`を使用してnice valueを下げることができます。

#### Quality of Service (QoS) Classes

QoS classesは、特に**Grand Central Dispatch (GCD)**をサポートするmacOSのようなsystemsで、thread prioritiesを処理するためのよりmodernなapproachです。QoS classesにより、developersは重要度や緊急度に基づいてworkを異なるlevelに**categorize**できます。macOSは、これらのQoS classesに基づいてthread prioritizationを自動的に管理します。

1. **User Interactive:**
- このclassは、現在userとinteractionしているtaskや、良好なuser experienceを提供するために即時の結果を必要とするtask向けです。interfaceのresponsive性を維持するため、これらのtaskには最高priorityが与えられます（例: animationsやevent handling）。
2. **User Initiated:**
- documentを開く、計算が必要なbuttonをclickするなど、userが開始し、即時の結果を期待するtaskです。high priorityですが、User Interactiveよりは下です。
3. **Utility:**
- これらのtaskは長時間実行され、通常はprogress indicatorを表示します（例: filesのdownloadやdataのimport）。user-initiated taskよりpriorityが低く、即時に完了する必要はありません。
4. **Background:**
- このclassは、backgroundで動作しuserには表示されないtask向けです。indexing、syncing、backupsなどが該当します。priorityが最も低く、system performanceへの影響も最小限です。

QoS classesを使用すると、developersは正確なpriority numberを管理するのではなく、taskの性質に集中でき、systemがそれに応じてCPU resourcesを最適化します。

さらに、schedulerが考慮する一連のscheduling parametersを指定する、異なる**thread scheduling policies**もあります。これは`thread_policy_[set/get]`を使用して実行できます。これはrace condition attacksで役立つ可能性があります。

## macOS Process Abuse

macOSには、**processが相互にinteraction、communication、data sharingを行う**ための多くのmechanismがあります。これらのmechanismは通常のsystem operationに不可欠ですが、attackersはこれらをinjection、code execution、data accessに悪用できます。

### Library Injection

Library Injectionは、attackerが**processにmalicious libraryをloadさせる**techniqueです。injection後、libraryはtarget processのcontextで実行され、そのprocessと同じpermissionsおよびaccessをattackerに提供します。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hookingは、software code内の**function calls**またはmessagesを**intercept**するtechniqueです。functionsをhookすることで、attackerはprocessの**behaviorを変更**したり、sensitive dataを監視したり、execution flowを制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC)は、分離されたprocess間で**dataをshareおよびexchange**するためのさまざまなmethodを指します。IPCは多くのlegitimate applicationsにとって基本的なものですが、process isolationのsubvert、sensitive informationのleak、unauthorized actionsの実行にも悪用できます。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定のenv variablesを使用して実行されたElectron applicationsは、process injectionに対してvulnerableになる可能性があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

flagsの`--load-extension`と`--use-fake-ui-for-media-stream`を使用して、**man in the browser attack**を実行できます。これにより、keystrokes、traffic、cookiesのstealや、pagesへのscriptsのinjectionなどが可能になります。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB filesは、application内の**user interface (UI) elements**とそのinteractionを**define**します。ただし、arbitrary commandsを**execute**でき、**NIB fileがmodified**された場合でも、**Gatekeeperはすでに実行されたapplicationの再実行を阻止しません**。そのため、arbitrary programsにarbitrary commandsを実行させるために使用できます。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`**、または**`JDK_JAVA_OPTIONS`**を介してJVM optionsをinjectionし、application開始前にJavaまたはnative agentをloadできます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**は、`--require`（file）または`--import data:text/javascript,…`（fileless、Node ≥ 20.6）を介してattackerのJavaScriptをpreloadします。**`NODE_REPL_EXTERNAL_MODULE`**はinteractive REPLにmoduleをloadし、**`ELECTRON_RUN_AS_NODE`**はElectron binaries上でこれらすべてを再有効化します。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main`の前に**`DOTNET_STARTUP_HOOKS`**を通じて.NET applicationsへcodeをinjectionできます。また、prerequisitesが存在する場合は、.NET debugging functionalityをabuseすることもできます。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

non-interactive Bashは**`BASH_ENV`**を読み込みます。interactive POSIX shellsは**`ENV`**を読み込み、zshは**`$ZDOTDIR/.zshenv`**を読み込み、fishは**`XDG_CONFIG_HOME`**または**`XDG_DATA_DIRS`**以下のconfigurationを読み込みます。それぞれ、意図されたcommandの前にcontrolled startup fileを実行できます。Bashは、xtraceがenabledの場合（例: 継承された**`SHELLOPTS=xtrace`**）、**`PS4`**に配置されたcommand substitutionも実行します。

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`**または**`PHP_INI_SCAN_DIR`**によってcontrolled PHP configurationをloadでき、そのconfigurationの**`auto_prepend_file`**がtarget scriptの前に実行されます。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

standalone Lua interpreterは、target scriptを処理する前に**`LUA_INIT`**（またはversion-specific variant）からcodeまたは`@file`を実行します。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`**および**`R_PROFILE`**は、R codeを含むstartup profilesへredirectします。**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**とR library pathを組み合わせることで、installed packageをauto-loadすることもできます。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**は、`config/startup.jl`が自動実行されるdepotへredirectします。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`**、または**`ERL_ZFLAGS`**を使用すると、payload fileを必要とせずにErlang VMの**`-eval`** expressionをinjectionできます。Elixir workloadsは通常、同じVMをstartします。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`**および**`OCTAVE_VERSION_INITFILE`**は、Octave startup scriptsへredirectします。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh`はcross-platform .NET appであるため、複数のenvironment variablesによってpre-command executionが可能です。**`XDG_CONFIG_HOME`**はstartup時に実行されるprofile scriptsへredirectし、**`PSModulePath`**はmodule auto-loadingをhijackします（配置された`.psm1`はimport時に実行され、built-in cmdletsをshadowできます）。また、.NETの**`CORECLR_PROFILER`**/**`COR_PROFILER`**および**`DOTNET_STARTUP_HOOKS`** variablesは、`Main`の前にattacker codeをprocessへloadします。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl scriptにarbitrary codeをexecuteさせるためのさまざまなoptionsを確認してください:

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Ruby env variables（**`RUBYOPT`**、**`RUBYLIB`**）をabuseして、arbitrary scriptsにarbitrary codeをexecuteさせることもできます:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`**と**`BROWSER`**のstandard-library chainは、warning-filter parsing中にcommandをexecuteできます。file-backed alternativeでは、**`PYTHONPATH`**上に`sitecustomize.py`を配置することで、通常の`site` initialization時にtarget scriptより前にimportさせます。**`PYTHONBREAKPOINT`**は、codeが`breakpoint()`に到達した際に指定されたcallable/moduleを実行します。**`PYTHONSTARTUP`**などのinteractive-only variablesは、適用範囲がより限定されます。

なお、**`pyinstaller`**でcompileされたexecutablesは、embedded pythonを使用して実行している場合でも、これらのenvironmental variablesを使用しません。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`**（およびfallbackの`EXINIT`）は通常のstartup時にEx commandsとして実行されるため、victimがcontrolled environmentでVim/Neovimを開くと、`:!cmd` / `:call system(...)`によってcode executionが発生します:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

これとは別に、Homebrewは通常、`/opt/homebrew`以下にPythonをinstallします。この場合、local `admin` groupのmembersがlauncherをreplaceできる可能性があります。これはenvironment-variable injectionではなく、writable-binary hijackです。exploitableとして扱う前に、ownershipとACLsを確認してください。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield)は、process injectionをdetectおよびblockする、open-sourceの**EndpointSecurity**-based applicationです。Endpoint Securityを通じてどのsignalがobservableかを知るための良いreferenceであり、以下をalertします:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- process exec時の**Injection environment variables**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** calls — あるprocessが別のprocessのtask portを要求するもので、対象へinjectionするためのprerequisiteです。
- **Electron debugging arguments** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらはElectron appをdebug modeでstartし、誰でもattachしてその中でcodeを実行できるようにします。<sup>[[3]](#references)</sup>
- **privilege levelsをまたぐsymlink/hardlink creation** — 「normal userとしてlinkをplantし、privileged locationを指す」というclassicなprimitiveです。なお、**symlinksはalertできますがblockはできません**。EndpointSecurityは、creation前にlink destinationをexposeしないためです。

### Calls made by other processes

[**このblog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、**`task_name_for_pid`** functionを使用して、**processへcodeをinjectionしている他のprocess**に関するinformationを取得し、その後、その別のprocessに関するinformationを取得する方法を確認できます。<sup>[[4]](#references)</sup>

このfunctionをcallするには、そのprocessを実行しているuserと**同じuid**であるか、**root**である必要があります（返されるのはprocessに関するinformationであり、code injectionの方法ではありません）。

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
