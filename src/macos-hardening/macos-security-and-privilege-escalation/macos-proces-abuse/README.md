# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processes Basic Information

プロセスは実行中の実行可能ファイルのインスタンスです。ただし、プロセスはコードを実行するのではなく、コードを実行するのはスレッドです。したがって、**プロセスは実行中のスレッドのための単なるコンテナ**であり、メモリ、ディスクリプタ、ポート、権限などを提供します。

従来、プロセスはPID 1を除き、**`fork`**を呼び出して別のプロセス内で起動されていました。`fork`は現在のプロセスの完全なコピーを作成し、その後、**子プロセス**は通常、**`execve`**を呼び出して新しい実行可能ファイルをロードし、実行していました。その後、メモリコピーなしでこの処理を高速化するために**`vfork`**が導入されました。\
次に、**`posix_spawn`**が導入され、**`vfork`**と**`execve`**を1回の呼び出しに組み合わせ、以下のフラグを受け取るようになりました。

- `POSIX_SPAWN_RESETIDS`: 実効IDを実IDにリセット
- `POSIX_SPAWN_SETPGROUP`: プロセスグループへの所属を設定
- `POSUX_SPAWN_SETSIGDEF`: シグナルのデフォルト動作を設定
- `POSIX_SPAWN_SETSIGMASK`: シグナルマスクを設定
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内でExec（より多くのオプションを持つ`execve`と同様）
- `POSIX_SPAWN_START_SUSPENDED`: 停止状態で開始
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLRなしで開始
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmallocのNano allocatorを使用
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` データセグメントで`rwx`を許可
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトでexec(2)時にすべてのファイル記述子を閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLRスライドの上位ビットをランダム化

さらに、`posix_spawn`では、生成されたプロセスの一部の側面を制御する**`posix_spawnattr`**の配列と、ディスクリプタの状態を変更する**`posix_spawn_file_actions`**を指定できます。

プロセスが終了すると、シグナル`SIGCHLD`とともに**親プロセスへ終了コードを送信**します（親プロセスが終了していた場合、新しい親プロセスはPID 1です）。親プロセスは`wait4()`または`waitid()`を呼び出してこの値を取得する必要があり、それが行われるまで子プロセスはゾンビ状態になります。この状態でも一覧には表示されますが、リソースは消費しません。

### PIDs

PID（プロセス識別子）は、一意のプロセスを識別します。XNUでは、**PID**は**64ビット**で、単調増加し、**ラップアラウンドしません**（abuseを防止するため）。

### Process Groups, Sessions & Coalations

**プロセス**は、管理を容易にするために**グループ**へ入れることができます。たとえば、シェルスクリプト内のコマンドは同じプロセスグループに属するため、killなどを使用して**まとめてシグナルを送信**できます。\
プロセスを**セッション**にまとめることもできます。プロセスがセッションを開始すると（`setsid(2)`）、子プロセスは独自のセッションを開始しない限り、そのセッション内に設定されます。

Coalitionは、Darwinにおけるプロセスをグループ化するもう1つの方法です。プロセスがCoalitionに参加すると、プールされたリソースへのアクセス、ledgerの共有、またはJetsamの対象となることが可能になります。Coalitionには、Leader、XPC service、Extensionという異なるロールがあります。

### Credentials & Personae

各プロセスは、システム上の**権限を識別する****credentials**を保持しています。各プロセスには、1つのプライマリ`uid`と1つのプライマリ`gid`があります（ただし、複数のグループに所属する場合があります）。\
バイナリに`setuid/setgid`ビットが設定されている場合、ユーザーIDとグループIDを変更することもできます。\
**新しいuid/gidを設定する**ための関数はいくつか存在します。

syscall **`persona`**は、**credentials**の**代替**セットを提供します。personaを採用すると、そのuid、gid、グループメンバーシップを**同時に**引き継ぎます。[**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)では、structを確認できます。
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

1. **POSIX Threads (pthreads):** macOS は POSIX threads（`pthreads`）をサポートしています。これは C/C++ 用の標準的な threading API の一部です。macOS における pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、公開されている `libpthread` project に由来します。この library は、スレッドの作成と管理に必要な function を提供します。
2. **スレッドの作成:** 新しいスレッドの作成には `pthread_create()` function を使用します。内部的には、この function は `bsdthread_create()` を呼び出します。これは XNU kernel（macOS の基盤となる kernel）固有の低レベルな system call です。この system call は、`pthread_attr`（attributes）から派生した各種 flags を受け取り、scheduling policy や stack size などのスレッドの動作を指定します。
- **デフォルトの Stack Size:** 新しいスレッドのデフォルトの stack size は 512 KB です。一般的な処理には十分ですが、必要に応じて thread attributes で増減できます。
3. **スレッドの初期化:** `__pthread_init()` function はスレッドのセットアップ時に重要な役割を果たし、`env[]` argument を使用して、stack の location や size などの情報を含む可能性がある environment variables を解析します。

#### macOS におけるスレッドの終了

1. **スレッドの終了:** スレッドは通常、`pthread_exit()` を呼び出して終了します。この function により、スレッドは必要な cleanup を実行して正常に終了し、joiner に return value を返せます。
2. **スレッドの cleanup:** `pthread_exit()` を呼び出すと、`pthread_terminate()` function が呼び出され、関連するすべてのスレッド構造体の削除を処理します。Mach thread port（Mach は XNU kernel における communication subsystem）を deallocate し、スレッドに関連付けられた kernel-level の構造体を削除する syscall である `bsdthread_terminate` を呼び出します。

#### Synchronization Mechanisms

shared resource への access を管理し、race condition を回避するため、macOS は複数の synchronization primitive を提供しています。これらは multi-threading environment において、data integrity と system stability を確保するために重要です。

1. **Mutex:**
- **Regular Mutex (Signature: 0x4D555458):** 標準的な mutex で、memory footprint は 60 bytes（mutex が 56 bytes、signature が 4 bytes）です。
- **Fast Mutex (Signature: 0x4d55545A):** regular mutex に似ていますが、より高速な operation 向けに最適化されており、size も 60 bytes です。
2. **Condition Variables:**
- 特定の condition が発生するまで待機するために使用され、size は 44 bytes（40 bytes と 4-byte signature）です。
- **Condition Variable Attributes (Signature: 0x434e4441):** condition variable の configuration attributes で、size は 12 bytes です。
3. **Once Variable (Signature: 0x4f4e4345):**
- initialization code の一部が一度だけ実行されることを保証します。size は 12 bytes です。
4. **Read-Write Locks:**
- 複数の reader または 1 つの writer が同時に access でき、shared data への効率的な access を可能にします。
- **Read Write Lock (Signature: 0x52574c4b):** size は 196 bytes です。
- **Read Write Lock Attributes (Signature: 0x52574c41):** read-write lock 用の attributes で、size は 20 bytes です。

> [!TIP]
> これらの object の最後の 4 bytes は、overflow を検出するために使用されます。

### Thread Local Variables (TLV)

Mach-O files（macOS の executable の format）の context における **Thread Local Variables (TLV)** は、multi-threaded application の **各 thread** に固有の variable を宣言するために使用されます。これにより、各 thread が variable の独立した instance を持てるため、mutex のような明示的な synchronization mechanism を必要とせずに conflict を回避し、data integrity を維持できます。

C および関連する language では、**`__thread`** keyword を使用して thread-local variable を宣言できます。以下の example では、次のように動作します:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
このスニペットでは、`tlv_var` を thread-local variable として定義しています。このコードを実行する各 thread はそれぞれ独自の `tlv_var` を持ち、ある thread が `tlv_var` に加えた変更は、別の thread の `tlv_var` には影響しません。

Mach-O binary では、thread local variables に関連するデータが特定の section に整理されています。

- **`__DATA.__thread_vars`**: この section には、thread-local variables の型や初期化状態などの metadata が含まれます。
- **`__DATA.__thread_bss`**: この section は、明示的に初期化されていない thread-local variables に使用されます。zero-initialized data 用に確保された memory の一部です。

Mach-O には、thread 終了時に thread-local variables を管理するための **`tlv_atexit`** という専用 API も用意されています。この API を使用すると、thread の終了時に thread-local data をクリーンアップする **destructors**（特殊な関数）を **register** できます。

### Threading Priorities

Thread priorities を理解するには、operating system がどの thread をいつ実行するかをどのように決定しているかを見る必要があります。この決定には、各 thread に割り当てられた priority level が影響します。macOS や Unix-like systems では、これは `nice`、`renice`、Quality of Service (QoS) classes などの概念を使用して処理されます。

#### Nice and Renice

1. **Nice:**
- process の `nice` value は、その priority に影響する数値です。すべての process は -20（最も高い priority）から 19（最も低い priority）までの nice value を持ちます。process 作成時の default nice value は通常 0 です。
- より低い nice value（-20 に近い値）にすると、process はより「selfish」になり、より高い nice value を持つ他の process より多くの CPU time が与えられます。
2. **Renice:**
- `renice` は、すでに実行中の process の nice value を変更する command です。新しい nice value に基づいて、process の CPU time の割り当てを増減し、priority を動的に調整できます。
- 例えば、process が一時的により多くの CPU resources を必要とする場合、`renice` を使用して nice value を下げることができます。

#### Quality of Service (QoS) Classes

QoS classes は、特に **Grand Central Dispatch (GCD)** をサポートする macOS のような systems で、thread priorities を処理するためのより現代的な approach です。QoS classes を使用すると、developers は重要度や緊急度に基づいて work を異なる level に **categorize** できます。macOS は、これらの QoS classes に基づいて thread prioritization を自動的に管理します。

1. **User Interactive:**
- この class は、現在 user と対話している task、または良好な user experience を提供するために即時の結果が必要な task 向けです。interface の応答性を維持するため、これらの task には最高の priority が与えられます（例: animations や event handling）。
2. **User Initiated:**
- document を開く、計算が必要な button をクリックするなど、user が開始し、即時の結果を期待する task 向けです。priority は高いものの、user interactive より下です。
3. **Utility:**
- 長時間実行され、通常は progress indicator を表示する task 向けです（例: files の downloading、data の importing）。user-initiated tasks より priority は低く、即時に完了する必要はありません。
4. **Background:**
- user には表示されない background で動作する task 向けです。indexing、syncing、backups などが該当します。priority は最も低く、system performance への影響も最小限です。

QoS classes を使用すると、developers は正確な priority numbers を管理する必要がなく、task の性質に集中できます。そのうえで system が CPU resources を適切に最適化します。

さらに、scheduler が考慮する scheduling parameters の set を指定する、異なる **thread scheduling policies** があります。これは `thread_policy_[set/get]` を使用して実行できます。これは race condition attacks に役立つ可能性があります。

## MacOS Process Abuse

MacOS は他の operating system と同様に、**process が相互作用、通信、data の共有を行う**ためのさまざまな methods と mechanisms を提供しています。これらの techniques は効率的な system operation に不可欠ですが、threat actors によって **malicious activities を実行する**ために abuse される可能性もあります。

### Library Injection

Library Injection は、attacker が **process に malicious library を load させる** technique です。injection 後、library は target process の context で実行され、attacker に process と同じ permissions と access を与えます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking は、software code 内の **function calls** または messages を **intercept** する手法です。functions を hook することで、attacker は process の **behavior を変更**したり、sensitive data を監視したり、execution flow を制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) は、別々の processes が **data を共有・交換する**ためのさまざまな methods を指します。IPC は多くの正当な applications にとって基本的な機能ですが、process isolation を subvert したり、sensitive information を leak したり、unauthorized actions を実行したりするために misuse される可能性もあります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定の env variables とともに実行された Electron applications は、process injection に対して vulnerable になる可能性があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

flags `--load-extension` と `--use-fake-ui-for-media-stream` を使用して **man in the browser attack** を実行し、keystrokes、traffic、cookies を steal したり、pages に scripts を inject したりできます:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB files は、application 内の **user interface (UI) elements** とその interactions を **define** します。しかし、arbitrary commands を **execute** でき、**NIB file が modified** されても、Gatekeeper はすでに実行された application の再実行を **stop しません**。そのため、arbitrary programs に arbitrary commands を実行させるために使用できます:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

特定の Java capabilities（**`_JAVA_OPTS`** env variable など）を abuse して、Java application に **arbitrary code/commands** を実行させることができます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### .Net Applications Injection

**.Net debugging functionality を abuse** することで、.Net applications に code を inject できます（runtime hardening などの macOS protections によって保護されていません）。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Perl Injection

Perl script に arbitrary code を execute させるためのさまざまな options は、以下を確認してください:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Ruby env variables を abuse して、arbitrary scripts に arbitrary code を execute させることも可能です:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

environment variable **`PYTHONINSPECT`** が set されている場合、Python process は終了時に Python CLI に移行します。また、**`PYTHONSTARTUP`** を使用して、interactive session の開始時に実行する Python script を指定することもできます。\
ただし、**`PYTHONINSPECT`** が interactive session を作成した場合、**`PYTHONSTARTUP`** script は実行されないことに注意してください。

**`PYTHONPATH`** や **`PYTHONHOME`** などの他の env variables も、Python command に arbitrary code を execute させるために役立つ可能性があります。

**`pyinstaller`** で compiled された executables は、embedded Python を使用して実行されている場合でも、これらの environmental variables を使用しないことに注意してください。

> [!CAUTION]
> 全体として、environment variables を abuse して Python に arbitrary code を execute させる方法は見つけられませんでした。\
> ただし、多くの人は **Hombrew** を使用して Python を install しており、default admin user に対して **writable location** に Python が install されます。次のような方法で hijack できます:
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
> **root** であっても、Python を実行するとこの code を実行します。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) は、process injection を detect および block する、open source の **EndpointSecurity**-based application です。次の alert を生成するため、ES から実際に observable な signals を確認するための良い reference です:<sup>[[1]](#references)</sup>

- process exec 時の **Injection environment variables**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** calls — ある process が別の process の task port を要求する処理で、対象 process に code を inject するための prerequisite です。
- **Electron debugging arguments** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらは Electron app を debug mode で起動し、誰でも attach して code を実行できるようにします。
- **privilege levels をまたぐ symlink/hardlink creation** — normal user として link を plant し、privileged location を指すという classic な primitive です。**symlinks は alert できますが block はできない**ことに注意してください。EndpointSecurity は creation 前の link destination を expose しません。

### Calls made by other processes

[**この blog post**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) では、function **`task_name_for_pid`** を使用して、**process に code を inject している他の processes** に関する information を取得し、その別の process に関する information を取得する方法を確認できます。<sup>[[4]](#references)</sup>

この function を call するには、その process を実行している user と **同じ uid** であるか、**root** である必要があります（この function が返すのは process に関する information であり、code を inject する方法ではありません）。

## References

- [1] [Shield — open source macOS process-injection detection (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Detecting task modifications](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)

{{#include ../../../banners/hacktricks-training.md}}
