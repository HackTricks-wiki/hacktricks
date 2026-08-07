# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

プロセスは実行中の executable のインスタンスですが、コードを実行するのはプロセスではなく thread です。したがって、**processes are just containers for running threads** であり、メモリ、descriptor、port、permission などを提供します。

従来、プロセスは PID 1 を除き、**`fork`** を呼び出して別のプロセス内で開始されていました。`fork` は現在のプロセスの完全なコピーを作成し、その後、**child process** は通常 **`execve`** を呼び出して新しい executable をロードし、実行していました。その後、メモリコピーなしでこの処理を高速化するために **`vfork`** が導入されました。\
次に、**`vfork`** と **`execve`** を1回の呼び出しに組み合わせ、flags を受け付ける **`posix_spawn`** が導入されました。

- `POSIX_SPAWN_RESETIDS`: effective ids を real ids にリセット
- `POSIX_SPAWN_SETPGROUP`: process group affiliation を設定
- `POSUX_SPAWN_SETSIGDEF`: signal のデフォルト動作を設定
- `POSIX_SPAWN_SETSIGMASK`: signal mask を設定
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内で Exec（より多くのオプションを持つ `execve` と同様）
- `POSIX_SPAWN_START_SUSPENDED`: suspended 状態で開始
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR なしで開始
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc の Nano allocator を使用
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segment 上で `rwx` を許可
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトで exec(2) 時にすべての file description を閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide の high bits をランダム化

さらに、`posix_spawn` では、spawn されたプロセスの一部の側面を制御する **`posix_spawnattr`** の array と、descriptor の状態を変更する **`posix_spawn_file_actions`** を指定できます。

プロセスが終了すると、signal `SIGCHLD` とともに **return code を parent process に送信**します（parent が終了していた場合、新しい parent は PID 1 です）。parent は `wait4()` または `waitid()` を呼び出してこの値を取得する必要があり、取得されるまで child は zombie 状態になります。この状態でも一覧には残りますが、resource は消費しません。

### PIDs

PIDs（process identifiers）は、一意のプロセスを識別します。XNU では **PIDs** は **64bits** で、単調増加し、**wrap しません**（abuse を防ぐため）。

### Process Groups, Sessions & Coalations

**Processes** は、扱いやすくするために **groups** に挿入できます。例えば、shell script 内の commands は同じ process group に属するため、kill などを使用して **まとめて signal を送信**できます。\
**processes を sessions に group 化**することもできます。プロセスが session (`setsid(2)`) を開始すると、自身の session を開始しない限り、child processes はその session 内に設定されます。

Coalition は、Darwin におけるプロセスを group 化する別の方法です。プロセスが coalition に参加すると、pool resources にアクセスし、ledger を共有したり、Jetsam の対象になったりできます。Coalitions には、Leader、XPC service、Extension という異なる roles があります。

### Credentials & Personae

各プロセスは、システム上の **privileges を識別する** **credentials** を保持します。各プロセスには primary `uid` と primary `gid` が1つずつあります（ただし、複数の groups に所属する場合があります）。\
binary に `setuid/setgid` bit が設定されている場合、user と group id を変更することもできます。\
**新しい uids/gids を設定する**ための functions が複数存在します。

syscall **`persona`** は、**credentials** の **alternate** set を提供します。persona を採用すると、その uid、gid、group memberships を**同時に**引き継ぎます。[**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) では、struct を確認できます。
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
## Thread の基本情報

1. **POSIX Threads (pthreads):** macOS は POSIX thread (`pthreads`) をサポートしています。これは C/C++ 用の標準的な threading API の一部です。macOS における pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、公開されている `libpthread` project に由来します。この library は、thread の作成と管理に必要な functions を提供します。
2. **Creating Threads:** 新しい thread の作成には `pthread_create()` function が使用されます。内部的には、この function は `bsdthread_create()` を呼び出します。これは XNU kernel（macOS の基盤となる kernel）固有の低レベル system call です。この system call は、thread の動作を指定する `pthread_attr`（attributes）から派生したさまざまな flags を受け取ります。これには scheduling policies や stack size などが含まれます。
- **Default Stack Size:** 新しい thread の default stack size は 512 KB です。一般的な operation には十分ですが、必要に応じて thread attributes により容量を増減できます。
3. **Thread Initialization:** `__pthread_init()` function は thread setup において重要な役割を果たします。`env[]` argument を使用して environment variables を解析し、stack の location や size などの情報を取得できます。

#### macOS における Thread Termination

1. **Exiting Threads:** Thread は通常、`pthread_exit()` を呼び出して terminate します。この function により、thread は必要な cleanup を実行して正常に終了し、joiner に return value を返すことができます。
2. **Thread Cleanup:** `pthread_exit()` を呼び出すと、`pthread_terminate()` function が呼び出され、関連するすべての thread structures の削除を処理します。この function は Mach thread ports（Mach は XNU kernel 内の communication subsystem）を deallocate し、thread に関連付けられた kernel-level structures を削除する syscall である `bsdthread_terminate` を呼び出します。

#### Synchronization Mechanisms

共有 resources への access を管理し、race conditions を回避するため、macOS は複数の synchronization primitives を提供しています。これらは、data integrity と system stability を確保するために、multi-threading environments で重要です。

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** memory footprint が 60 bytes（mutex 用の 56 bytes と signature 用の 4 bytes）の標準 mutex です。
- **Fast Mutex (Signature: 0x4d55545A):** regular mutex に似ていますが、より高速な operation 向けに最適化されており、size も 60 bytes です。
2. **Condition Variables:**
- 特定の conditions が発生するまで待機するために使用され、size は 44 bytes（40 bytes と 4-byte signature）です。
- **Condition Variable Attributes (Signature: 0x434e4441):** condition variables の configuration attributes で、size は 12 bytes です。
3. **Once Variable (Signature: 0x4f4e4345):**
- initialization code の一部が一度だけ実行されることを保証します。size は 12 bytes です。
4. **Read-Write Locks:**
- 複数の reader または一度に 1 つの writer を許可し、shared data への効率的な access を実現します。
- **Read Write Lock (Signature: 0x52574c4b):** size は 196 bytes です。
- **Read Write Lock Attributes (Signature: 0x52574c41):** read-write locks 用の attributes で、size は 20 bytes です。

> [!TIP]
> これらの objects の最後の 4 bytes は、overflow を検出するために使用されます。

### Thread Local Variables (TLV)

Mach-O files（macOS における executables の format）の context における **Thread Local Variables (TLV)** は、multi-threaded application の **各 thread** に固有の variables を宣言するために使用されます。これにより、各 thread が variable の独立した instance を持つことができ、mutex のような明示的な synchronization mechanisms を必要とせずに、conflicts を回避して data integrity を維持できます。

C および関連する languages では、**`__thread`** keyword を使用して thread-local variable を宣言できます。以下の example では、次のように動作します：
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
このスニペットでは、`tlv_var` を thread-local variable として定義しています。このコードを実行する各スレッドは、それぞれ独自の `tlv_var` を持ち、あるスレッドによる `tlv_var` への変更が、別のスレッドの `tlv_var` に影響することはありません。

Mach-O binary では、thread local variables に関連するデータが特定のセクションに整理されています。

- **`__DATA.__thread_vars`**: このセクションには、型や初期化状態など、thread-local variables に関するメタデータが含まれます。
- **`__DATA.__thread_bss`**: このセクションは、明示的に初期化されていない thread-local variables に使用されます。ゼロ初期化データ用に確保されたメモリの一部です。

Mach-O には、スレッド終了時に thread-local variables を管理するための専用 API **`tlv_atexit`** も用意されています。この API を使用すると、スレッド終了時に thread-local data をクリーンアップする **destructors**（デストラクタ）を**登録**できます。

### Threading Priorities

Thread priorities を理解するには、オペレーティングシステムがどのスレッドをいつ実行するかを決定する仕組みを確認する必要があります。この決定には、各スレッドに割り当てられた priority level が影響します。macOS や Unix-like systems では、これは `nice`、`renice`、Quality of Service（QoS）classes などの概念を使って処理されます。

#### Nice and Renice

1. **Nice:**
- プロセスの `nice` value は、その priority に影響する数値です。すべてのプロセスには、-20（最高 priority）から 19（最低 priority）までの nice value があります。プロセス作成時のデフォルトの nice value は通常 0 です。
- より低い nice value（-20 に近い値）にすると、プロセスはより「自己中心的」になり、より高い nice value を持つ他のプロセスと比較して、より多くの CPU time が与えられます。
2. **Renice:**
- `renice` は、すでに実行中のプロセスの nice value を変更する command です。新しい nice value に基づいて CPU time の割り当てを増減し、プロセスの priority を動的に調整できます。
- 例えば、プロセスが一時的により多くの CPU resources を必要とする場合、`renice` を使用して nice value を下げることができます。

#### Quality of Service (QoS) Classes

QoS classes は、特に **Grand Central Dispatch (GCD)** をサポートする macOS のような systems において、thread priorities を扱うためのより現代的な approach です。QoS classes を使うと、developers は重要度や緊急度に応じて work を異なる levels に**分類**できます。macOS は、これらの QoS classes に基づいて thread prioritization を自動的に管理します。

1. **User Interactive:**
- 現在 user と interaction している、または良好な user experience のために即時の結果が必要な tasks 用の class です。interface の応答性を維持するため、これらの tasks には最高の priority が与えられます（例: animations や event handling）。
2. **User Initiated:**
- document を開く、計算が必要な button をクリックするなど、user が開始し、即時の結果を期待する tasks 用です。priority は高いものの、User Interactive より下位です。
3. **Utility:**
- 長時間実行され、通常は progress indicator を表示する tasks 用です（例: files の downloading や data の importing）。User Initiated tasks より priority は低く、即座に終了する必要はありません。
4. **Background:**
- user には表示されない background で動作する tasks 用の class です。indexing、syncing、backups などが該当します。priority は最低で、system performance への影響も最小限です。

QoS classes を使用すると、developers は正確な priority numbers を管理する必要がなく、task の性質に集中できます。そして system がそれに応じて CPU resources を最適化します。

さらに、scheduler が考慮する scheduling parameters の集合を指定する、さまざまな **thread scheduling policies** があります。これは `thread_policy_[set/get]` を使用して設定できます。これは race condition attacks に役立つ可能性があります。

## MacOS Process Abuse

MacOS は他のすべての operating systems と同様に、**processes が相互作用、通信、data の共有を行う**ためのさまざまな methods と mechanisms を提供します。これらの techniques は効率的な system operation に不可欠ですが、threat actors によって**悪意のある活動を実行する**ために abuse される可能性もあります。

### Library Injection

Library Injection は、attacker が**malicious library を process に load させる** technique です。injection 後、library は target process の context で実行されるため、attacker はその process と同じ permissions と access を得られます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking は、software code 内の **function calls** や messages を**intercept**する手法です。functions を hooking することで、attacker は process の**挙動を変更**したり、sensitive data を監視したり、execution flow を制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) は、分離された processes が **data を共有・交換する**ためのさまざまな methods を指します。IPC は多くの legitimate applications にとって基本的な仕組みですが、process isolation の回避、sensitive information の leak、unauthorized actions の実行に悪用される可能性もあります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定の env variables とともに実行される Electron applications は、process injection に対して vulnerable になる可能性があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

flags `--load-extension` と `--use-fake-ui-for-media-stream` を使用して、**man in the browser attack** を実行できます。これにより、keystrokes や traffic、cookies の窃取、pages への scripts の injection などが可能になります。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files は、application 内の **user interface (UI) elements** とその interactions を**定義**します。しかし、arbitrary commands を**実行**でき、**NIB file が変更**されても、Gatekeeper はすでに実行された application の再実行を**阻止しません**。したがって、arbitrary programs に arbitrary commands を実行させるために利用できます。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

特定の java capabilities（**`_JAVA_OPTS`** env variable など）を abuse して、java application に **arbitrary code/commands** を実行させることができます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

**.Net debugging functionality を abuse**することで、.Net applications に code を inject できます（runtime hardening などの macOS protections によって保護されていません）。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Perl script に arbitrary code を実行させるためのさまざまな options は、以下を確認してください。


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

ruby env variables を abuse して、arbitrary scripts に arbitrary code を実行させることも可能です。


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

environment variable **`PYTHONINSPECT`** が設定されている場合、python process は終了時に python cli に移行します。また、**`PYTHONSTARTUP`** を使用して、interactive session の開始時に実行する python script を指定することもできます。\
ただし、**`PYTHONINSPECT`** によって interactive session が作成された場合、**`PYTHONSTARTUP`** script は実行されない点に注意してください。

**`PYTHONPATH`** や **`PYTHONHOME`** などの他の env variables も、python command に arbitrary code を実行させるために役立つ可能性があります。

**`pyinstaller`** で compiled された executables は、embedded python を使用して実行されている場合でも、これらの environmental variables を使用しない点に注意してください。

> [!CAUTION]
> 全体として、environment variables を abuse して python に arbitrary code を実行させる方法は見つけられませんでした。\
> ただし、多くの人は **Hombrew** を使って pyhton を install しており、その場合、デフォルトの admin user が **writable location** に pyhton を install することになります。次のような方法で hijack できます。
>
> ```bash
> mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
> cat > /opt/homebrew/bin/python3 <<EOF
> #!/bin/bash
> # Extra hijack code
> /opt/homebrew/bin/python3.old "$@"
> EOF
> chmod +x /opt/homebrew/bin/python3
> ```
>
> **root** であっても、python を実行するとこの code が実行されます。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) は、process injection を detect して block する、open source の **EndpointSecurity**-based application です。ES から実際に observable な signals を確認するための良い reference であり、以下の events に対して alert を出します。<sup>[[1]](#references)[[2]](#references)</sup>

- process exec 時の **Injection environment variables**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** calls — ある process が別の process の task port を要求する処理です。これは、その process に injection を行うための prerequisite です。
- **Electron debugging arguments** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらは Electron app を debug mode で起動し、誰でも attach して code を実行できるようにします。<sup>[[3]](#references)</sup>
- **privilege levels をまたぐ Symlink/hardlink creation** — normal user として link を作成し、それを privileged location に point する古典的な primitive です。なお、**symlinks は alert の対象にはできますが block はできません**。EndpointSecurity は、link creation 前に link destination を公開しないためです。

### Calls made by other processes

[**この blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) では、function **`task_name_for_pid`** を使用して、**process に code を injecting している他の processes** に関する information を取得し、その後、その別の process に関する information を取得する方法を確認できます。<sup>[[4]](#references)</sup>

この function を call するには、process を実行している user と**同じ uid**であるか、**root** である必要があります（この function が返すのは process に関する info であり、code を inject する方法ではありません）。

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
