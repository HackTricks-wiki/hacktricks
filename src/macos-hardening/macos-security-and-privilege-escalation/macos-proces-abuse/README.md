# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## プロセスの基本情報

プロセスは実行中の実行ファイルのインスタンスですが、プロセスはコードを実行せず、コードを実行するのはスレッドです。したがって、**プロセスはスレッドを実行するための単なるコンテナ**であり、メモリ、ディスクリプタ、ポート、権限などを提供します。

従来、プロセスは（PID 1を除き）**`fork`** を呼び出して別のプロセス内で開始されていました。`fork` は現在のプロセスの完全なコピーを作成し、その後、通常は**子プロセス**が **`execve`** を呼び出して新しい実行ファイルを読み込み、実行します。その後、メモリコピーを行わずにこの処理を高速化するため、**`vfork`** が導入されました。\
続いて、**`vfork`** と **`execve`** を1回の呼び出しにまとめ、フラグを指定できる **`posix_spawn`** が導入されました。

- `POSIX_SPAWN_RESETIDS`: 実効IDを実IDにリセットする
- `POSIX_SPAWN_SETPGROUP`: プロセスグループへの所属を設定する
- `POSUX_SPAWN_SETSIGDEF`: シグナルのデフォルト動作を設定する
- `POSIX_SPAWN_SETSIGMASK`: シグナルマスクを設定する
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内で exec する（オプションを追加した `execve` のようなもの）
- `POSIX_SPAWN_START_SUSPENDED`: 一時停止状態で開始する
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR を無効にして開始する
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc の Nano アロケータを使用する
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` データセグメントで `rwx` を許可する
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトで exec(2) 時にすべてのファイル記述子を閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR スライドの上位ビットをランダム化する

さらに、`posix_spawn` は、生成されるプロセスの動作を制御する **`posix_spawnattr`** 設定と、ファイルディスクリプタを変更する **`posix_spawn_file_actions`** エントリを受け取ります。

プロセスが終了すると、シグナル `SIGCHLD` とともに**終了コードを親プロセスに送信**します（親プロセスが終了していた場合、新しい親は PID 1 になります）。親プロセスは `wait4()` または `waitid()` を呼び出してこの値を取得する必要があります。それまで子プロセスはゾンビ状態に留まり、リストには表示されますが、リソースは消費しません。

### PIDs

PID（プロセス識別子）は、一意のプロセスを識別します。XNU の **PIDs** は **64ビット**で、単調に増加し、（悪用を防ぐため）**ラップアラウンドしません**。

### プロセスグループ、セッション、Coalations

**プロセス**は、管理しやすくするために**グループ**にまとめることができます。たとえば、シェルスクリプト内のコマンドは同じプロセスグループに属するため、`kill` などを使って**まとめてシグナルを送信**できます。\
プロセスを**セッションにまとめる**こともできます。プロセスがセッション（`setsid(2)`）を開始すると、子プロセスは独自のセッションを開始しない限り、そのセッションに属します。

Coalition は、Darwin でプロセスをグループ化するもう1つの方法です。プロセスが Coalition に参加すると、プールリソースにアクセスできるようになり、台帳を共有したり、Jetsam の対象になったりします。Coalition には、Leader、XPC service、Extension などの異なるロールがあります。

### 認証情報とペルソナ

各プロセスは、システム上の**権限を識別する**ための**認証情報**を保持します。各プロセスには主たる `uid` と `gid` が1つずつあります（複数のグループに属する場合もあります）。\
バイナリに `setuid/setgid` ビットが設定されていれば、ユーザー ID とグループ ID を変更することもできます。\
**新しい uid/gid を設定する**関数はいくつかあります。

システムコール **`persona`** は、**代替の** **認証情報**セットを提供します。ペルソナを採用すると、その uid、gid、グループメンバーシップが**一度に**引き継がれます。[**ソースコード**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)では、次の構造体を確認できます。

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

1. **POSIX Threads (pthreads):** macOS は POSIX threads（`pthreads`）をサポートしています。これは C/C++ 用の標準スレッド API の一部です。macOS における pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、公開されている `libpthread` プロジェクトに由来します。このライブラリは、スレッドの作成と管理に必要な関数を提供します。
2. **スレッドの作成:** `pthread_create()` 関数を使って新しいスレッドを作成します。内部では、この関数は `bsdthread_create()` を呼び出します。これは XNU カーネル（macOS の基盤となるカーネル）固有の低レベルなシステムコールです。このシステムコールは、スケジューリングポリシーやスタックサイズなど、スレッドの動作を指定する `pthread_attr`（属性）由来のさまざまなフラグを受け取ります。
   - **デフォルトのスタックサイズ:** 新しいスレッドのデフォルトのスタックサイズは 512 KB です。通常の処理には十分なサイズですが、必要に応じてスレッド属性で増減できます。
3. **スレッドの初期化:** `__pthread_init()` 関数はスレッドのセットアップ時に重要な役割を果たし、`env[]` 引数を使って、スタックの位置やサイズなどの情報を含む環境変数を解析します。

#### macOS でのスレッド終了

1. **スレッドの終了:** 通常、スレッドは `pthread_exit()` を呼び出して終了します。この関数により、スレッドは必要なクリーンアップを実行して正常に終了し、join する側のスレッドに戻り値を返せます。
2. **スレッドのクリーンアップ:** `pthread_exit()` を呼び出すと、`pthread_terminate()` 関数が実行され、関連するすべてのスレッド構造体を削除します。Mach thread port（Mach は XNU カーネルの通信サブシステム）を解放し、スレッドに関連するカーネルレベルの構造体を削除する syscall である `bsdthread_terminate` を呼び出します。

#### 同期メカニズム

共有リソースへのアクセスを管理し、race condition を避けるために、macOS は複数の同期プリミティブを提供しています。これらは、データの整合性とシステムの安定性を確保するうえで、マルチスレッド環境に欠かせません。

1. **Mutex:**
   - **通常の Mutex（シグネチャ: 0x4D555458）:** メモリ使用量は 60 bytes（Mutex に 56 bytes、シグネチャに 4 bytes）の標準的な Mutex です。
   - **Fast Mutex（シグネチャ: 0x4d55545A）:** 通常の Mutex と同様ですが、処理が高速になるよう最適化されており、サイズも 60 bytes です。
2. **Condition Variables:**
   - 特定の条件が満たされるまで待機するために使われます。サイズは 44 bytes（40 bytes と 4-byte のシグネチャ）です。
   - **Condition Variable Attributes（シグネチャ: 0x434e4441）:** Condition Variable の設定属性で、サイズは 12 bytes です。
3. **Once Variable（シグネチャ: 0x4f4e4345）:**
   - 初期化コードを一度だけ実行することを保証します。サイズは 12 bytes です。
4. **Read-Write Locks:**
   - 複数の読み取り側、または一度に 1 つの書き込み側を許可し、共有データへの効率的なアクセスを可能にします。
   - **Read Write Lock（シグネチャ: 0x52574c4b）:** サイズは 196 bytes です。
   - **Read Write Lock Attributes（シグネチャ: 0x52574c41）:** Read-Write Lock の属性で、サイズは 20 bytes です。

> [!TIP]
> これらのオブジェクトの最後の 4 bytes は、overflow の検出に使われます。

### Thread Local Variables (TLV)

Mach-O ファイル（macOS の実行ファイル形式）における **Thread Local Variables (TLV)** は、マルチスレッドアプリケーションで**各スレッド専用**の変数を宣言するために使われます。これにより、各スレッドが変数の個別のインスタンスを持てるため、Mutex などの明示的な同期メカニズムを使わずに競合を避け、データの整合性を維持できます。

C および関連言語では、**`__thread`** キーワードを使って thread-local variable を宣言できます。以下の例では、次のように動作します。

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

このスニペットでは、`tlv_var` をスレッドローカル変数として定義しています。このコードを実行する各スレッドはそれぞれ独自の `tlv_var` を持ち、あるスレッドが `tlv_var` に加えた変更は、別のスレッドの `tlv_var` には影響しません。

Mach-O バイナリでは、スレッドローカル変数に関連するデータは特定のセクションに整理されています。

- **`__DATA.__thread_vars`**: スレッドローカル変数の型や初期化状態などのメタデータが格納されます。
- **`__DATA.__thread_bss`**: 明示的に初期化されていないスレッドローカル変数に使用されます。ゼロ初期化データ用に確保されたメモリ領域の一部です。

Mach-O には、スレッド終了時にスレッドローカル変数を管理するための専用API **`tlv_atexit`** も用意されています。このAPIを使うと、スレッドが終了する際にスレッドローカルデータをクリーンアップする特別な関数である**デストラクタを登録**できます。

### スレッドの優先度

スレッドの優先度を理解するには、オペレーティングシステムがどのスレッドをいつ実行するかを決定する仕組みを確認する必要があります。この決定には、各スレッドに割り当てられた優先度が影響します。macOSやUnix系システムでは、`nice`、`renice`、Quality of Service（QoS）クラスなどの概念を使って管理されます。

#### NiceとRenice

1. **Nice:**
   - プロセスの `nice` 値は、優先度に影響する数値です。各プロセスの `nice` 値は -20（最優先）から 19（最低優先度）までの範囲で、プロセス作成時のデフォルト値は通常 0 です。
   - `nice` 値が低い（-20に近い）ほど、プロセスはより「自分本位」になり、`nice` 値の高い他のプロセスより多くのCPU時間を得ます。
2. **Renice:**
   - `renice` は、実行中のプロセスの `nice` 値を変更するコマンドです。新しい `nice` 値に基づいてCPU時間の割り当てを増減させ、プロセスの優先度を動的に調整できます。
   - たとえば、プロセスが一時的に多くのCPUリソースを必要とする場合、`renice` を使って `nice` 値を下げることができます。

#### Quality of Service（QoS）クラス

QoSクラスは、特に **Grand Central Dispatch（GCD）** をサポートするmacOSのようなシステムで、スレッドの優先度を管理するための、より現代的な方法です。QoSクラスを使うと、開発者は作業の重要度や緊急度に応じて、異なるレベルに**分類**できます。macOSはQoSクラスに基づいてスレッドの優先度を自動的に管理します。

1. **User Interactive:**
   - ユーザーが現在操作しているタスクや、優れたユーザー体験のために即座に結果を返す必要があるタスク向けのクラスです。インターフェースの応答性を維持するため、最優先で実行されます（例: アニメーションやイベント処理）。
2. **User Initiated:**
   - ドキュメントを開く、計算が必要なボタンをクリックするなど、ユーザーが開始し、即座の結果を期待するタスク向けです。優先度は高いものの、User Interactiveよりは低くなります。
3. **Utility:**
   - 長時間実行され、通常は進捗インジケーターが表示されるタスク向けです（例: ファイルのダウンロードやデータのインポート）。ユーザーが開始したタスクより優先度は低く、すぐに完了する必要はありません。
4. **Background:**
   - バックグラウンドで動作し、ユーザーには表示されないタスク向けのクラスです。インデックス作成、同期、バックアップなどが該当します。優先度は最も低く、システムパフォーマンスへの影響も最小限です。

QoSクラスを使えば、開発者は正確な優先度の数値を管理する必要がなく、タスクの性質に注力できます。システムはそれに応じてCPUリソースを最適化します。

また、スケジューラが考慮するスケジューリングパラメーターを指定する、さまざまな**スレッドスケジューリングポリシー**もあります。これは `thread_policy_[set/get]` を使って設定できます。レースコンディション攻撃で役立つ場合があります。

## macOS Process Abuse

macOSには、**プロセスが相互に作用し、通信し、データを共有する**ための仕組みが多数あります。これらの仕組みは通常のシステム動作に不可欠ですが、攻撃者はインジェクション、コード実行、データアクセスに悪用できます。

### Library Injection

Library Injectionは、攻撃者が**プロセスに悪意のあるライブラリを強制的に読み込ませる**手法です。インジェクションされたライブラリは対象プロセスのコンテキストで実行されるため、攻撃者はそのプロセスと同じ権限やアクセス権を得られます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hookingは、ソフトウェアコード内の関数呼び出しやメッセージを**傍受する**手法です。関数をフックすることで、攻撃者はプロセスの**動作を変更**したり、機密データを監視したり、実行フローを制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

このページでは、ARM64のunwindメタデータ、arm64eのPAC制約、合成call chainについて解説します。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication（IPC）とは、別々のプロセスが**データを共有・交換する**ためのさまざまな方法を指します。IPCは多くの正規アプリケーションにとって基本的な仕組みですが、プロセス分離の回避、機密情報のleak、不正な操作にも悪用される可能性があります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定の環境変数を指定して実行されたElectronアプリケーションは、プロセスインジェクションに対して脆弱な場合があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

フラグ `--load-extension` と `--use-fake-ui-for-media-stream` を使い、キーストローク、通信、Cookieの窃取やページへのスクリプトインジェクションを可能にする**man in the browser attack**を実行できます。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIBファイルは、アプリケーション内の**ユーザーインターフェース（UI）要素とその動作を定義**します。しかし、NIBファイルは**任意のコマンドを実行でき**、**NIBファイルが変更されていても、Gatekeeperはすでに実行されたアプリケーションの再実行を阻止しません**。そのため、任意のプログラムに任意のコマンドを実行させるために悪用される可能性があります。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`**、または **`JDK_JAVA_OPTIONS`** を通じてJVMオプションをインジェクションし、アプリケーションの起動前にJava agentまたはnative agentを読み込ませることができます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** は、`--require`（ファイル）または `--import data:text/javascript,…`（fileless、Node ≥ 20.6）を使って攻撃者のJavaScriptを先行読み込みします。**`NODE_REPL_EXTERNAL_MODULE`** は対話型REPLにモジュールを読み込み、**`ELECTRON_RUN_AS_NODE`** はElectronバイナリでこれらすべてを再び有効にします。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

.NETアプリケーションでは、`Main` の実行前に **`DOTNET_STARTUP_HOOKS`** を使ってコードをインジェクションできます。また、前提条件が満たされている場合は、.NETのデバッグ機能を悪用することもできます。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非対話型Bashは **`BASH_ENV`** を読み込み、対話型POSIXシェルは **`ENV`** を読み込みます。zshは **`$ZDOTDIR/.zshenv`** を読み込み、fishは **`XDG_CONFIG_HOME`** または **`XDG_DATA_DIRS`** 以下の設定を読み込みます。いずれも、制御された起動ファイルを意図されたコマンドの前に実行できます。また、xtraceが有効な場合（例: **`SHELLOPTS=xtrace`** が継承されている場合）、Bashは **`PS4`** に設定されたコマンド置換も実行します。

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`** または **`PHP_INI_SCAN_DIR`** を使って、対象スクリプトより前に **`auto_prepend_file`** を実行する、制御されたPHP設定を読み込ませることができます。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

スタンドアロンのLuaインタープリターは、対象スクリプトの処理前に **`LUA_INIT`**（またはバージョン固有の変数）からコードまたは `@file` を実行します。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** と **`R_PROFILE`** は、Rコードを含む起動プロファイルの参照先を変更します。**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** とRライブラリパスを組み合わせると、インストール済みパッケージを自動的に読み込ませることもできます。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** は、`config/startup.jl` が自動実行されるdepotの参照先を変更します。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`**、または **`ERL_ZFLAGS`** を使うと、payloadファイルを必要とせずにErlang VMの **`-eval`** 式をインジェクションできます。Elixirのワークロードも、一般に同じVMを起動します。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** と **`OCTAVE_VERSION_INITFILE`** は、Octaveの起動スクリプトの参照先を変更します。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` はクロスプラットフォームの.NETアプリであるため、複数の環境変数を使ってコマンド実行前にコードを実行できます。**`XDG_CONFIG_HOME`** は起動時に実行されるプロファイルスクリプトの参照先を変更します。**`PSModulePath`** はモジュールの自動読み込みを乗っ取り（配置された `.psm1` はインポート時に実行され、組み込みcmdletをシャドウできます）、.NETの **`CORECLR_PROFILER`**/**`COR_PROFILER`** および **`DOTNET_STARTUP_HOOKS`** 変数は `Main` の実行前に攻撃者のコードをプロセスに読み込みます。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perlスクリプトに任意のコードを実行させる方法について、さまざまなオプションを確認してください。


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Rubyの環境変数（**`RUBYOPT`**、**`RUBYLIB`**）を悪用して、任意のスクリプトに任意のコードを実行させることもできます。


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

標準ライブラリの **`PYTHONWARNINGS`** と **`BROWSER`** を組み合わせると、warning-filterの解析中にコマンドを実行できます。ファイルを使う方法では、**`PYTHONPATH`** 上に `sitecustomize.py` を配置すると、通常の `site` 初期化時に対象スクリプトより前にインポートされます。**`PYTHONBREAKPOINT`** は、コードが `breakpoint()` に到達したときに指定されたcallable/moduleを実行します。**`PYTHONSTARTUP`** などの対話型専用変数は、適用できる状況が限られます。

**pyinstaller** でコンパイルされた実行ファイルは、組み込みのPythonを使って実行されていても、これらの環境変数を使用しないことに注意してください。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`**（およびフォールバックの `EXINIT`）は通常の起動時にExコマンドとして実行されます。そのため、制御された環境で被害者がVim/Neovimを開くと、`:!cmd` / `:call system(...)` によってコードを実行できます。

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

別途、HomebrewはPythonを `/opt/homebrew` 以下にインストールすることが多く、ローカルの `admin` グループのメンバーがランチャーを置き換えられる場合があります。これは環境変数インジェクションではなく、書き込み可能なバイナリの乗っ取りです。悪用可能と判断する前に、所有者とACLを確認してください。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) は、プロセスインジェクションを検出・ブロックする、**EndpointSecurity** ベースのオープンソースアプリケーションです。Endpoint Securityで観測可能なシグナルを知るうえで参考になり、次のイベントを検知します。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- プロセス実行時の**インジェクション用環境変数**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** 呼び出し — あるプロセスが別のプロセスのtask portを要求する操作で、そのプロセスへのインジェクションに必要です。
- **Electronのデバッグ引数** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらはElectronアプリをデバッグモードで起動し、誰でも接続してコードを実行できるようにします。<sup>[[3]](#references)</sup>
- **異なる権限レベル間でのシンボリックリンク/ハードリンク作成** — 通常ユーザーとしてリンクを仕掛け、特権のある場所を指すようにする典型的な手法です。**シンボリックリンクは検知できますが、ブロックはできません**。EndpointSecurityはリンク作成前にリンク先を取得できないためです。

### Calls made by other processes

[**このブログ記事**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、関数 **`task_name_for_pid`** を使って、**プロセスにコードをインジェクションしている他のプロセス**の情報を取得し、そのプロセスに関する情報を得る方法が解説されています。<sup>[[4]](#references)</sup>

この関数を呼び出すには、対象プロセスを実行しているユーザーと**同じuid**であるか、**root**である必要があります（この関数が返すのはプロセスの情報であり、コードをインジェクションする方法ではありません）。

## References

- [1] [Shield — オープンソースのmacOSプロセスインジェクション検出ツール（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electronアプリが秘密情報を機密に保持できない理由: --inspectオプション](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - taskの変更を検出する](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
