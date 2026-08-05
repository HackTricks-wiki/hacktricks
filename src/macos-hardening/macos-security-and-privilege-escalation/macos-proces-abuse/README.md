# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## プロセスの基本情報

プロセスは実行中の executable のインスタンスですが、プロセスは code を実行せず、実行するのは thread です。したがって、**プロセスは実行中の thread のための単なるコンテナ**であり、memory、descriptor、port、permission などを提供します。

従来、プロセスは PID 1 を除き、**`fork`** を呼び出して他のプロセス内で開始されていました。`fork` は現在のプロセスの完全なコピーを作成し、その後、**child process** は通常、**`execve`** を呼び出して新しい executable をロードし、実行していました。その後、memory のコピーを行わずにこの処理を高速化するため、**`vfork`** が導入されました。\
続いて、`vfork` と **`execve`** を1回の call にまとめ、flags を受け付ける **`posix_spawn`** が導入されました。

- `POSIX_SPAWN_RESETIDS`: effective id を real id にリセット
- `POSIX_SPAWN_SETPGROUP`: process group の所属を設定
- `POSUX_SPAWN_SETSIGDEF`: signal のデフォルト動作を設定
- `POSIX_SPAWN_SETSIGMASK`: signal mask を設定
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内で Exec（より多くの options を持つ `execve` と同様）
- `POSIX_SPAWN_START_SUSPENDED`: suspended 状態で開始
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR なしで開始
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc の Nano allocator を使用
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segment で `rwx` を許可
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトで exec(2) 時にすべての file description を閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slide の上位 bits を randomize

さらに、`posix_spawn` では、spawn されたプロセスのいくつかの側面を制御する **`posix_spawnattr`** の array と、descriptor の状態を変更する **`posix_spawn_file_actions`** を指定できます。

プロセスが終了すると、signal `SIGCHLD` によって **return code を parent process に送信**します（parent が終了している場合、新しい parent は PID 1 です）。parent は `wait4()` または `waitid()` を呼び出してこの値を取得する必要があり、それが行われるまで child は zombie 状態になります。この状態でも child は一覧に表示されますが、resource は消費しません。

### PIDs

PIDs（process identifiers）は、一意のプロセスを識別します。XNU では **PIDs** は **64bits** で、単調増加し、**wrap しません**（abuse を防ぐため）。

### Process Groups、Sessions、Coalations

**プロセス**は、管理しやすくするために**groups**に追加できます。たとえば、shell script 内の commands は同じ process group に属するため、kill などを使用して**まとめて signal を送信**できます。\
プロセスを**sessions にまとめる**こともできます。プロセスが session（`setsid(2)`）を開始すると、その child processes は独自の session を開始しない限り、その session 内に設定されます。

Coalition は、Darwin におけるプロセスを group 化する別の方法です。プロセスが coalition に参加すると、pool resources にアクセスし、ledger を共有したり、Jetsam の対象になったりできます。Coalition には、Leader、XPC service、Extension という異なる roles があります。

### Credentials と Personae

各プロセスは、システム上の**privileges を識別する** **credentials** を保持します。各プロセスには primary `uid` と primary `gid` が1つずつあります（ただし、複数の groups に所属する場合があります）。\
binary に `setuid/setgid` bit が設定されている場合は、user と group id を変更することもできます。\
新しい uid/gid を**設定する**ための functions がいくつか存在します。

syscall **`persona`** は、**credentials** の**alternate** set を提供します。persona を採用すると、その uid、gid、group memberships が**同時に**引き継がれます。[**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) では、struct を確認できます。
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

1. **POSIX Threads (pthreads):** macOS は POSIX threads (`pthreads`) をサポートしています。これは C/C++ 用の標準的な threading API の一部です。macOS における pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、公開されている `libpthread` project に由来します。この library は、threads の作成と管理に必要な functions を提供します。
2. **Creating Threads:** `pthread_create()` function は、新しい threads の作成に使用されます。内部では、この function は `bsdthread_create()` を呼び出します。これは XNU kernel（macOS の基盤となる kernel）固有の、より低レベルな system call です。この system call は、thread の動作（scheduling policies や stack size など）を指定する `pthread_attr`（attributes）から派生したさまざまな flags を受け取ります。
- **Default Stack Size:** 新しい threads の default stack size は 512 KB です。通常の操作には十分なサイズですが、より多く、またはより少ない領域が必要な場合は、thread attributes によって調整できます。
3. **Thread Initialization:** `__pthread_init()` function は thread の setup において重要です。この function は `env[]` argument を使用して environment variables を解析します。environment variables には、stack の location や size に関する情報を含めることができます。

#### macOS における Thread Termination

1. **Exiting Threads:** Threads は通常、`pthread_exit()` を呼び出して終了します。この function により、thread は必要な cleanup を実行して正常に終了し、joiners に return value を返せます。
2. **Thread Cleanup:** `pthread_exit()` を呼び出すと、`pthread_terminate()` function が呼び出され、関連するすべての thread structures の削除を処理します。この function は Mach thread ports（Mach は XNU kernel における communication subsystem）を deallocate し、thread に関連付けられた kernel-level structures を削除する syscall である `bsdthread_terminate` を呼び出します。

#### Synchronization Mechanisms

共有 resources への access を管理し、race conditions を回避するため、macOS には複数の synchronization primitives が用意されています。これらは multi-threading environments において、data integrity と system stability を確保するために重要です。

1. **Mutexes:**
- **Regular Mutex (Signature: 0x4D555458):** 60 bytes の memory footprint を持つ標準的な mutex です（mutex 用 56 bytes、signature 用 4 bytes）。
- **Fast Mutex (Signature: 0x4d55545A):** Regular mutex に似ていますが、より高速な operations 向けに最適化されており、サイズも 60 bytes です。
2. **Condition Variables:**
- 特定の conditions が発生するまで待機するために使用され、サイズは 44 bytes です（40 bytes + 4-byte signature）。
- **Condition Variable Attributes (Signature: 0x434e4441):** Condition variables の configuration attributes で、サイズは 12 bytes です。
3. **Once Variable (Signature: 0x4f4e4345):**
- initialization code の一部が一度だけ実行されることを保証します。サイズは 12 bytes です。
4. **Read-Write Locks:**
- 複数の readers、または一度に 1 つの writer を許可し、shared data への効率的な access を実現します。
- **Read Write Lock (Signature: 0x52574c4b):** サイズは 196 bytes です。
- **Read Write Lock Attributes (Signature: 0x52574c41):** read-write locks 用の attributes で、サイズは 20 bytes です。

> [!TIP]
> これらの objects の最後の 4 bytes は、overflows を検出するために使用されます。

### Thread Local Variables (TLV)

Mach-O files（macOS の executables の format）の context における **Thread Local Variables (TLV)** は、multi-threaded application において **各 thread** に固有の variables を宣言するために使用されます。これにより、各 thread は variable の独立した instance を持つことができ、mutexes のような明示的な synchronization mechanisms を必要とせずに、conflicts を回避して data integrity を維持できます。

C および関連する languages では、**`__thread`** keyword を使用して thread-local variable を宣言できます。次の example では、以下のように動作します：
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
このスニペットでは、`tlv_var`を thread-local variable として定義しています。このコードを実行する各 thread は、それぞれ独自の`tlv_var`を持ち、ある thread による`tlv_var`への変更が、別の thread の`tlv_var`に影響することはありません。

Mach-O binary では、thread local variables に関連するデータが特定のセクションに整理されています。

- **`__DATA.__thread_vars`**: このセクションには、型や初期化状態など、thread-local variables に関する metadata が含まれます。
- **`__DATA.__thread_bss`**: このセクションは、明示的に初期化されていない thread-local variables に使用されます。zero-initialized data 用に確保された memory の一部です。

Mach-O には、thread の終了時に thread-local variables を管理するための専用 API である **`tlv_atexit`** も用意されています。この API を使用すると、thread の終了時に thread-local data をクリーンアップする **destructors**（特殊な関数）を**登録**できます。

### Threading Priorities

Thread priorities を理解するには、operating system がどの thread をいつ実行するかを決定する仕組みを確認する必要があります。この決定には、各 thread に割り当てられた priority level が影響します。macOS や Unix-like systems では、これは`nice`、`renice`、Quality of Service (QoS) classes などの概念を使用して処理されます。

#### Nice and Renice

1. **Nice:**
- process の`nice` value は、その priority に影響する数値です。すべての process には、-20（highest priority）から19（lowest priority）までの nice value があります。process が作成されたときの default nice value は、通常0です。
- より低い nice value（-20に近い値）にすると、process はより「selfish」になり、より高い nice value を持つ他の process と比べて、より多くの CPU time を取得します。
2. **Renice:**
- `renice`は、すでに実行中の process の nice value を変更するための command です。新しい nice value に基づいて CPU time の割り当てを増減させ、process の priority を動的に調整できます。
- 例えば、process が一時的により多くの CPU resources を必要とする場合、`renice`を使用して nice value を下げることができます。

#### Quality of Service (QoS) Classes

QoS classes は、特に **Grand Central Dispatch (GCD)** をサポートする macOS のような systems において、thread priorities を扱うより現代的な方法です。QoS classes を使うと、developers は重要度や緊急度に基づいて work を異なる level に**分類**できます。macOS は、これらの QoS classes に基づいて thread prioritization を自動的に管理します。

1. **User Interactive:**
- この class は、現在 user とやり取りしている task や、良好な user experience のために immediate results を必要とする task 用です。interface の応答性を維持するため、これらの task には最も高い priority が与えられます（例: animations や event handling）。
2. **User Initiated:**
- document を開く、計算を必要とする button をクリックするなど、user が開始し、immediate results を期待する task 用です。high priority ですが、user interactive より下です。
3. **Utility:**
- これらの task は long-running で、通常は progress indicator を表示します（例: files の downloading、data の importing）。user-initiated tasks より priority が低く、immediately に完了する必要はありません。
4. **Background:**
- この class は background で動作し、user には表示されない task 用です。indexing、syncing、backups などが該当します。priority が最も低く、system performance への影響も最小限です。

QoS classes を使用すると、developers は正確な priority numbers を管理するのではなく、task の性質に集中できます。そして system がそれに応じて CPU resources を最適化します。

さらに、scheduler が考慮する scheduling parameters の set を指定する、さまざまな **thread scheduling policies** があります。これは`thread_policy_[set/get]`を使用して実行できます。これは race condition attacks に役立つ可能性があります。

## MacOS Process Abuse

MacOS は他の operating system と同様に、**processes が相互に操作、通信、data の共有を行う**ためのさまざまな methods と mechanisms を提供します。これらの techniques は efficient system functioning に不可欠ですが、threat actors によって**malicious activities を実行する**ために abuse される可能性もあります。

### Library Injection

Library Injection は、attacker が**process に malicious library を load させる** technique です。inject された library は target process の context で実行され、attacker に process と同じ permissions と access を与えます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking は、software code 内の **function calls** や messages を**intercept**することです。functions を hook することで、attacker は process の **behavior を変更**したり、sensitive data を監視したり、execution flow を control したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) は、分離された processes が**data を共有・交換**するためのさまざまな methods を指します。IPC は多くの legitimate applications にとって fundamental ですが、process isolation の subvert、sensitive information の leak、unauthorized actions の実行に misuse される可能性もあります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定の env variables を使用して実行された Electron applications は、process injection に vulnerable になる可能性があります:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

flags `--load-extension` と`--use-fake-ui-for-media-stream`を使用して、**man in the browser attack** を実行できます。これにより、keystrokes や traffic、cookies の盗難、pages への scripts の inject などが可能になります:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files は application 内の **user interface (UI) elements** とその interactions を**定義**します。しかし、arbitrary commands を**execute**でき、**NIB file が modified** されても、Gatekeeper はすでに実行された application の再実行を**阻止しません**。そのため、arbitrary programs に arbitrary commands を実行させるために使用できます:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

特定の java capabilities（**`_JAVA_OPTS`** env variable など）を abuse して、java application に **arbitrary code/commands** を実行させることができます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

**.Net debugging functionality** を abuse することで、.Net applications に code を inject できます（runtime hardening などの macOS protections によって保護されていません）。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Perl script に arbitrary code を実行させるためのさまざまな options を、以下で確認してください:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

ruby env variables を abuse して、arbitrary scripts に arbitrary code を実行させることもできます:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

environment variable **`PYTHONINSPECT`** が set されている場合、python process は終了時に python cli に移行します。また、**`PYTHONSTARTUP`** を使用して、interactive session の開始時に実行する python script を指定することもできます。\
ただし、**`PYTHONINSPECT`** が interactive session を作成した場合、**`PYTHONSTARTUP`** script は実行されないことに注意してください。

**`PYTHONPATH`** や **`PYTHONHOME`** などの他の env variables も、python command に arbitrary code を実行させるために役立つ可能性があります。

**`pyinstaller`** で compiled された executables は、embedded python を使用して実行されている場合でも、これらの environmental variables を使用しないことに注意してください。

> [!CAUTION]
> 全体として、environment variables を abuse して python に arbitrary code を実行させる方法は見つけられませんでした。\
> しかし、多くの人は **Hombrew** を使用して pyhton を install します。これは、default admin user が **writable location** に pyhton を install します。次のような方法で hijack できます:
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

[**Shield**](https://github.com/theevilbit/Shield) は、process injection を detect および block する、open source の **EndpointSecurity**-based application です。以下の signal に対して alert を出すため、ES から実際に observable な signal を確認するための良い reference です:<sup>[1]</sup>

- process exec 時の **Injection environment variables**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** calls — ある process が別の process の task port を要求するもの。これは、その process に inject するための prerequisite です。
- **Electron debugging arguments** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらは Electron app を debug mode で起動し、誰でも attach して code を実行できるようにします。
- privilege levels をまたぐ symlink/hardlink creation — 通常の user として link を作成し、privileged location を指す、古典的な primitive です。**symlinks は alert の対象にはできますが block はできない**ことに注意してください: EndpointSecurity は creation 前に link destination を expose しません。

### Calls made by other processes

[**この blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) では、function **`task_name_for_pid`** を使用して、**process に code を inject している他の processes** に関する information を取得し、その後、その別の process に関する information を取得する方法を確認できます。<sup>[4]</sup>

この function を call するには、process を実行している user と **same uid** であるか、**root** である必要があります（この function が返すのは process に関する info であり、code を inject する方法ではありません）。

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
