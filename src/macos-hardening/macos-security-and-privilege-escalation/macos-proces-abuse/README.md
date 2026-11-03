# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## プロセスの基本情報

プロセスとは、実行中の実行可能ファイルのインスタンスです。ただし、コードを実行するのはプロセスではなくスレッドです。したがって、**プロセスはスレッドを実行するためのコンテナにすぎず**、メモリ、ディスクリプタ、ポート、権限などを提供します。

従来、プロセスは（PID 1を除く）別のプロセス内で **`fork`** を呼び出して起動されていました。これにより現在のプロセスの完全なコピーが作成され、その後、**子プロセス**は通常 **`execve`** を呼び出して新しい実行可能ファイルを読み込み、実行していました。その後、メモリコピーを行わずにこの処理を高速化するため、**`vfork`** が導入されました。\
続いて、**`vfork`** と **`execve`** を1回の呼び出しにまとめ、フラグを受け取る **`posix_spawn`** が導入されました。

- `POSIX_SPAWN_RESETIDS`: 実効IDを実IDにリセットする
- `POSIX_SPAWN_SETPGROUP`: プロセスグループへの所属を設定する
- `POSUX_SPAWN_SETSIGDEF`: シグナルのデフォルト動作を設定する
- `POSIX_SPAWN_SETSIGMASK`: シグナルマスクを設定する
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内でexecする（より多くのオプションを持つ `execve` のようなもの）
- `POSIX_SPAWN_START_SUSPENDED`: 一時停止状態で起動する
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLRを無効にして起動する
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmallocのNano allocatorを使用する
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` データセグメントで `rwx` を許可する
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトでexec(2)時にすべてのファイル記述子を閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLRスライドの上位ビットをランダム化する

さらに、`posix_spawn` は、生成されたプロセスの動作を制御する **`posix_spawnattr`** 設定と、ファイル記述子を変更する **`posix_spawn_file_actions`** エントリを受け取ります。

プロセスが終了すると、シグナル `SIGCHLD` とともに **終了コードを親プロセスに送信します**（親が終了している場合、新しい親はPID 1です）。親は `wait4()` または `waitid()` を呼び出してこの値を取得する必要があります。それまで子プロセスはゾンビ状態にあり、リストには表示されますが、リソースは消費しません。

### PIDs

PID（プロセス識別子）は、個々のプロセスを識別します。XNUでは **PID** は **64ビット**で、単調増加し、**ラップしません**（悪用を防ぐため）。

### プロセスグループ、セッション、Coalations

**プロセス**は、管理しやすくするために**グループ**にまとめることができます。たとえば、シェルスクリプト内のコマンドは同じプロセスグループに属するため、killなどを使って**まとめてシグナルを送信**できます。\
プロセスを**セッションにまとめる**こともできます。プロセスがセッションを開始すると（`setsid(2)`）、独自のセッションを開始しない限り、その子プロセスは同じセッションに設定されます。

Darwinでは、Coalitionもプロセスをグループ化する方法の1つです。プロセスがCoalitionに参加すると、プールリソースにアクセスし、台帳を共有したり、Jetsamの対象になったりします。Coalitionには、Leader、XPC service、Extensionという異なるロールがあります。

### 認証情報とPersonae

各プロセスは、システム上の**権限を識別する** **認証情報**を保持します。各プロセスには1つのプライマリ `uid` と1つのプライマリ `gid` があります（複数のグループに所属する場合もあります）。\
バイナリに `setuid/setgid` ビットが設定されている場合、ユーザーIDとグループIDを変更することもできます。\
**新しいuid/gidを設定する**関数はいくつかあります。

syscall **`persona`** は、**代替の** **認証情報**セットを提供します。personaを採用すると、そのuid、gid、グループ所属が**一度に**適用されます。[**ソースコード**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)には、次の構造体があります:

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

1. **POSIX Threads (pthreads):** macOS は POSIX threads（`pthreads`）をサポートしています。これは C/C++ 向けの標準スレッド API の一部です。macOS の pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、一般公開されている `libpthread` プロジェクトに由来します。このライブラリは、スレッドの作成と管理に必要な関数を提供します。
2. **スレッドの作成:** `pthread_create()` 関数を使用して新しいスレッドを作成します。内部では、この関数は `bsdthread_create()` を呼び出します。これは XNU kernel（macOS の基盤となる kernel）固有の低レベル system call です。この system call は、スレッドの動作（スケジューリングポリシーや stack サイズなど）を指定する、`pthread_attr`（属性）から得られるさまざまな flags を受け取ります。
   - **デフォルトの stack サイズ:** 新しいスレッドのデフォルトの stack サイズは 512 KB です。一般的な処理には十分ですが、必要に応じてスレッド属性で増減できます。
3. **スレッドの初期化:** スレッドのセットアップでは `__pthread_init()` 関数が重要な役割を果たします。この関数は `env[]` 引数を使用して環境変数を解析し、stack の位置やサイズに関する情報を含む場合があります。

#### macOS でのスレッド終了

1. **スレッドの終了:** 通常、スレッドは `pthread_exit()` を呼び出して終了します。この関数により、スレッドは必要なクリーンアップを行って正常に終了し、join するスレッドに戻り値を返すことができます。
2. **スレッドのクリーンアップ:** `pthread_exit()` を呼び出すと `pthread_terminate()` 関数が呼び出され、関連するすべてのスレッド構造体の削除を処理します。Mach thread ports（Mach は XNU kernel の通信サブシステム）を解放し、スレッドに関連付けられた kernel レベルの構造体を削除する syscall である `bsdthread_terminate` を呼び出します。

#### 同期メカニズム

共有リソースへのアクセスを管理し、race condition を防ぐために、macOS は複数の同期プリミティブを提供しています。これらは、データの整合性とシステムの安定性を確保するうえで、マルチスレッド環境に不可欠です。

1. **Mutexes:**
   - **Regular Mutex (Signature: 0x4D555458):** 標準の mutex で、メモリ使用量は 60 bytes（mutex が 56 bytes、signature が 4 bytes）です。
   - **Fast Mutex (Signature: 0x4d55545A):** 標準の mutex と同様ですが、より高速な操作向けに最適化されており、サイズも 60 bytes です。
2. **Condition Variables:**
   - 特定の条件が発生するのを待つために使用されます。サイズは 44 bytes（40 bytes と 4-byte signature）です。
   - **Condition Variable Attributes (Signature: 0x434e4441):** condition variables の設定属性で、サイズは 12 bytes です。
3. **Once Variable (Signature: 0x4f4e4345):**
   - 初期化コードが一度だけ実行されるようにします。サイズは 12 bytes です。
4. **Read-Write Locks:**
   - 複数の reader または一度に 1 つの writer によるアクセスを許可し、共有データへの効率的なアクセスを実現します。
   - **Read Write Lock (Signature: 0x52574c4b):** サイズは 196 bytes です。
   - **Read Write Lock Attributes (Signature: 0x52574c41):** read-write locks の属性で、サイズは 20 bytes です。

> [!TIP]
> これらのオブジェクトの最後の 4 bytes は、overflow の検出に使用されます。

### スレッドローカル変数 (TLV)

Mach-O ファイル（macOS の実行ファイル形式）における **スレッドローカル変数 (TLV)** は、マルチスレッドアプリケーションで **各スレッド専用** の変数を宣言するために使われます。これにより、各スレッドが変数の独立したインスタンスを持つため、mutex のような明示的な同期メカニズムを使わずに競合を避け、データの整合性を保てます。

C および関連する言語では、**`__thread`** キーワードを使ってスレッドローカル変数を宣言できます。例では次のように動作します。

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

このスニペットでは、`tlv_var`をスレッドローカル変数として定義しています。このコードを実行する各スレッドは、それぞれ独自の`tlv_var`を持ち、あるスレッドが`tlv_var`に加えた変更は、別のスレッドの`tlv_var`には影響しません。

Mach-Oバイナリでは、スレッドローカル変数に関連するデータは、特定のセクションに整理されています。

- **`__DATA.__thread_vars`**: スレッドローカル変数の型や初期化状態などのメタデータが格納されるセクションです。
- **`__DATA.__thread_bss`**: 明示的に初期化されていないスレッドローカル変数に使用されるセクションです。ゼロ初期化データ用に確保されたメモリ領域の一部です。

Mach-Oには、スレッドの終了時にスレッドローカル変数を管理するための`tlv_atexit`という専用APIもあります。このAPIを使うと、**デストラクタを登録**できます。デストラクタは、スレッドの終了時にスレッドローカルデータをクリーンアップする特殊な関数です。

### スレッドの優先順位

スレッドの優先順位を理解するには、オペレーティングシステムが、どのスレッドをいつ実行するかを決定する仕組みを確認する必要があります。この決定は、各スレッドに割り当てられた優先度の影響を受けます。macOSやUnix系システムでは、`nice`、`renice`、Quality of Service (QoS) クラスなどの概念を使って管理します。

#### NiceとRenice

1. **Nice:**
   - プロセスの`nice`値は、優先度に影響する数値です。各プロセスのnice値は-20（最高優先度）から19（最低優先度）までで、新しく作成されたプロセスのデフォルト値は通常0です。
   - nice値が低い（-20に近い）ほど、プロセスはより「自己中心的」になり、nice値の高い他のプロセスより多くのCPU時間を得ます。
2. **Renice:**
   - `renice`は、実行中のプロセスのnice値を変更するコマンドです。新しいnice値に応じてCPU時間の割り当てを増減させ、プロセスの優先度を動的に調整できます。
   - たとえば、プロセスが一時的により多くのCPUリソースを必要とする場合、`renice`を使ってnice値を下げることができます。

#### Quality of Service (QoS) クラス

QoSクラスは、特に**Grand Central Dispatch (GCD)**をサポートするmacOSのようなシステムで、スレッドの優先順位を管理するための、より現代的な方法です。QoSクラスを使うと、開発者は作業の重要度や緊急度に応じて、作業を異なるレベルに**分類**できます。macOSは、これらのQoSクラスに基づいてスレッドの優先順位を自動的に管理します。

1. **User Interactive:**
   - ユーザーと現在やり取りしているタスクや、良好なユーザー体験のために即座に結果を返す必要があるタスク向けのクラスです。インターフェイスの応答性を保つため、アニメーションやイベント処理などのタスクに最高の優先度が与えられます。
2. **User Initiated:**
   - ドキュメントを開く、計算が必要なボタンをクリックするなど、ユーザーが開始し、すぐに結果が得られることを期待するタスク向けです。優先度は高いものの、User Interactiveより低くなります。
3. **Utility:**
   - ダウンロードやデータのインポートなど、長時間実行され、通常は進捗状況が表示されるタスク向けです。User Initiatedより優先度が低く、すぐに完了する必要はありません。
4. **Background:**
   - ユーザーには見えないバックグラウンド処理向けのクラスです。インデックス作成、同期、バックアップなどが該当します。優先度は最も低く、システムパフォーマンスへの影響も最小限です。

QoSクラスを使えば、開発者は正確な優先度の数値を管理する必要がなく、タスクの性質に注力できます。システムはそれに応じてCPUリソースを最適化します。

また、スケジューラが考慮するスケジューリングパラメータのセットを指定する、さまざまな**スレッドスケジューリングポリシー**もあります。これは`thread_policy_[set/get]`を使って設定できます。race condition攻撃で役立つ場合があります。

## macOSプロセスの悪用

macOSには、**プロセス間でやり取り、通信、データ共有を行う**ための仕組みが数多くあります。これらの仕組みは通常のシステム動作に不可欠ですが、攻撃者はインジェクション、コード実行、データアクセスに悪用できます。

### Library Injection

Library Injectionは、攻撃者が**プロセスに悪意のあるライブラリを強制的に読み込ませる**手法です。インジェクションされたライブラリは標的プロセスのコンテキストで実行されるため、攻撃者はそのプロセスと同じ権限やアクセス権を得られます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hookingでは、ソフトウェアコード内の関数呼び出しやメッセージを**傍受**します。関数をhookすることで、攻撃者はプロセスの**動作を変更**したり、機密データを監視したり、実行フローを制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

このページでは、ARM64のunwind metadata、arm64eのPAC制約、合成call chainについて説明します。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### プロセス間通信

プロセス間通信（IPC）は、別々のプロセスが**データを共有、交換する**ためのさまざまな方法を指します。IPCは多くの正規アプリケーションに不可欠ですが、プロセス分離の無効化、機密情報のleak、不正な操作にも悪用される可能性があります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定の環境変数を設定して実行されたElectronアプリケーションは、プロセスインジェクションに対して脆弱な場合があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

フラグ`--load-extension`と`--use-fake-ui-for-media-stream`を使うと、**man in the browser攻撃**を実行できます。これにより、キーストローク、通信、cookieの窃取や、ページへのスクリプト注入などが可能になります。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIBファイルは、アプリケーション内の**ユーザーインターフェイス（UI）要素とその動作を定義**します。しかし、NIBファイルは**任意のコマンドを実行でき**、**NIBファイルが変更されても、Gatekeeperは一度実行されたアプリケーションの再実行を阻止しません**。そのため、任意のプログラムに任意のコマンドを実行させるために悪用できます。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`**、または**`JDK_JAVA_OPTIONS`**を通じてJVMオプションを注入し、アプリケーションの起動前にJavaまたはnative agentを読み込ませることができます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**は、`--require`（ファイル）または`--import data:text/javascript,…`（ファイルレス、Node ≥ 20.6）を介して攻撃者のJavaScriptをpreloadします。**`NODE_REPL_EXTERNAL_MODULE`**は対話型REPLにモジュールを読み込ませ、**`ELECTRON_RUN_AS_NODE`**はElectronバイナリでこれらすべてを再び有効にします。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main`の実行前に**`DOTNET_STARTUP_HOOKS`**を通じて、または前提条件が満たされている場合に.NETのデバッグ機能を悪用して、.NETアプリケーションにコードを注入できます。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非対話型のBashは**`BASH_ENV`**を読み込みます。対話型のPOSIX shellは**`ENV`**を読み込み、zshは**`$ZDOTDIR/.zshenv`**を読み込み、fishは**`XDG_CONFIG_HOME`**または**`XDG_DATA_DIRS`**以下の設定ファイルを読み込みます。いずれも、意図されたコマンドの実行前に、制御されたstartup fileを実行させることができます。また、xtraceが有効な場合、Bashは**`PS4`**に設定されたcommand substitutionを実行します（例：**`SHELLOPTS=xtrace`**が継承されている場合）。

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s`を起動すると、shellは標準入力からプログラムを読み込みます。そのため、信頼できない構造化ドキュメントを解析せずに子プロセスのstdinへコピーするdownloaderは、そのドキュメント全体をshellのソースコードに変えてしまいます。実際に確認されたあるloaderは、公開されているiCalendarファイルを匿名pipe経由で1行ずつ渡していました。カレンダーのメタデータはコマンドとして失敗しましたが、zshは処理を続け、`DESCRIPTION:`の後に配置された実行可能な行に到達しました。その行は次のアプリケーションバンドルをダウンロードして起動しました。ファイルの想定content typeや信頼されたホスティング元によって安全になるわけではありません。危険な境界は、そのバイト列をinterpreterに渡すことです。<sup>[[5]](#references)</sup>

関連する段階については、[Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)、[Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md)、[macOS auto-start locations](../../macos-auto-start-locations.md)を参照してください。

### PHP Injection

**`PHPRC`**または**`PHP_INI_SCAN_DIR`**を使うと、**`auto_prepend_file`**で対象スクリプトの実行前にコードを実行する、制御されたPHP設定を読み込ませることができます。

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

単体のLua interpreterは、対象スクリプトの処理前に**`LUA_INIT`**（またはバージョン固有の変数）からコードや`@file`を実行します。

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`**と**`R_PROFILE`**を使うと、Rコードを含むstartup profileの読み込み先を変更できます。**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**とRのlibrary pathを組み合わせると、インストール済みのpackageを自動的に読み込ませることもできます。

[R startup profiles and package loading](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`**を使うと、`config/startup.jl`が自動実行されるdepotの場所を変更できます。

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`**、または**`ERL_ZFLAGS`**を使うと、payload fileを必要とせずにErlang VMの**`-eval`**式を注入できます。Elixirの処理でも、通常は同じVMが起動します。

[Erlang/Elixir VM flag injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`**と**`OCTAVE_VERSION_INITFILE`**を使うと、Octave startup scriptの読み込み先を変更できます。

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh`はクロスプラットフォームの.NETアプリケーションであるため、いくつかの環境変数を使ってコマンド実行前にコードを実行できます。**`XDG_CONFIG_HOME`**は起動時に実行されるprofile scriptの読み込み先を変更し、**`PSModulePath`**はmoduleの自動読み込みを乗っ取ります（配置した`.psm1`はimport時に実行され、組み込みcmdletをshadowできます）。さらに、.NETの**`CORECLR_PROFILER`**/**`COR_PROFILER`**と**`DOTNET_STARTUP_HOOKS`**変数は、`Main`の実行前に攻撃者のコードをプロセスに読み込ませます。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl scriptに任意のコードを実行させるための各種オプションについては、以下を確認してください。


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Rubyの環境変数（**`RUBYOPT`**、**`RUBYLIB`**）を悪用して、任意のscriptに任意のコードを実行させることもできます。


[Ruby `RUBYOPT`/`RUBYLIB` loader options](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

**`PYTHONWARNINGS`**と**`BROWSER`**を使った標準ライブラリの連鎖により、warning-filterの解析中にコマンドを実行できます。ファイルを使う別の方法として、**`PYTHONPATH`**に`sitecustomize.py`を配置すると、通常の`site`初期化時に対象スクリプトより先にimportされます。**`PYTHONBREAKPOINT`**は、コードが`breakpoint()`に到達したときに指定したcallable/moduleを実行します。**`PYTHONSTARTUP`**など対話型専用の変数は、適用できる範囲が限られます。

**`pyinstaller`**でコンパイルされた実行ファイルは、組み込みのPythonを使って実行されていても、これらの環境変数を使用しない点に注意してください。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`**（および代替の`EXINIT`）は通常の起動時にExコマンドとして実行されるため、被害者が制御された環境でVim/Neovimを開くと、`:!cmd` / `:call system(...)`によってコード実行が可能になります。

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

これとは別に、HomebrewはPythonを`/opt/homebrew`以下にインストールすることがよくあります。この場所では、ローカルの`admin`グループのメンバーがlauncherを置き換えられる場合があります。これは環境変数インジェクションではなく、書き込み可能なバイナリの乗っ取りです。悪用可能と判断する前に、所有者とACLを確認してください。


## 検出

### Shield

[**Shield**](https://github.com/theevilbit/Shield)は、プロセスインジェクションを検出してブロックする、オープンソースの**EndpointSecurity**ベースのアプリケーションです。Endpoint Securityを通じてどのようなシグナルを観測できるかを知るための参考になります。次のイベントを警告するためです。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- プロセス実行時の**インジェクション用環境変数**：`DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`**呼び出し — あるプロセスが別のプロセスのtask portを要求する処理で、対象へのインジェクションに必要な前提条件です。
- **Electronのデバッグ引数** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらの引数はElectronアプリをデバッグモードで起動し、誰でも接続してコードを実行できるようにします。<sup>[[3]](#references)</sup>
- **権限レベルをまたぐsymlink/hardlinkの作成** — 一般ユーザーとしてリンクを作成し、特権のある場所を指すようにする古典的な手法です。なお、**symlinkは警告の対象にはできますが、ブロックはできません**。EndpointSecurityは、リンクの作成前にリンク先を公開しないためです。

### 他のプロセスによる呼び出し

[**このブログ記事**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、関数**`task_name_for_pid`**を使って、他の**プロセスにコードを注入しているプロセス**に関する情報を取得し、そのプロセスについてさらに情報を得る方法を確認できます。<sup>[[4]](#references)</sup>

この関数を呼び出すには、対象プロセスを実行しているユーザーと**同じuid**であるか、**root**である必要があります（返されるのはプロセスに関する情報であり、コードを注入する方法ではありません）。

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — オープンソースのmacOSプロセスインジェクション検出（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurityフレームワーク](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electronアプリが秘密情報を機密に保管できない理由：--inspectオプション](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - taskの変更の検出](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - 新バージョンのMacSync macOS stealerが暗号資産愛好家と開発者を標的に](https://securelist.com/macsync-new-version/121383/)
