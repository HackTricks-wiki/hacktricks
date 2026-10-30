# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## プロセスの基本情報

プロセスは実行中の実行可能ファイルのインスタンスですが、プロセスではなくスレッドがコードを実行します。したがって、**プロセスは実行スレッドのコンテナにすぎず**、メモリ、ディスクリプタ、ポート、権限などを提供します。

従来、プロセスは（PID 1を除き）別のプロセス内で**`fork`**を呼び出して起動されていました。`fork`は現在のプロセスの完全なコピーを作成し、その後、通常は**子プロセス**が**`execve`**を呼び出して新しい実行可能ファイルを読み込み、実行します。その後、メモリのコピーなしでこの処理を高速化するために**`vfork`**が導入されました。\
続いて、**`vfork`**と**`execve`**を1回の呼び出しに統合し、フラグを指定できる**`posix_spawn`**が導入されました。

- `POSIX_SPAWN_RESETIDS`: 実効IDを実IDにリセットする
- `POSIX_SPAWN_SETPGROUP`: プロセスグループへの所属を設定する
- `POSUX_SPAWN_SETSIGDEF`: シグナルのデフォルト動作を設定する
- `POSIX_SPAWN_SETSIGMASK`: シグナルマスクを設定する
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内でexecする（オプションを追加した`execve`と同様）
- `POSIX_SPAWN_START_SUSPENDED`: 一時停止状態で起動する
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLRなしで起動する
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmallocのNanoアロケータを使用する
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` データセグメントで`rwx`を許可する
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトでexec(2)時にすべてのファイル記述子を閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLRスライドの上位ビットをランダム化する

さらに、`posix_spawn`は、生成されたプロセスの動作を制御する**`posix_spawnattr`**設定と、ファイルディスクリプタを変更する**`posix_spawn_file_actions`**エントリを受け取ります。

プロセスが終了すると、シグナル`SIGCHLD`とともに**終了コードを親プロセスに送信**します（親プロセスが終了している場合、新しい親プロセスはPID 1です）。親プロセスは`wait4()`または`waitid()`を呼び出してこの値を取得する必要があり、それまでは子プロセスはゾンビ状態にとどまります。この状態では一覧に表示されたままですが、リソースは消費しません。

### PIDs

PID（プロセス識別子）は、個々のプロセスを識別します。XNUでは**PID**は**64ビット**で、単調増加し、（悪用を防ぐため）**ラップアラウンドしません**。

### プロセスグループ、セッション、Coalitions

**プロセス**は、管理しやすくするために**グループ**にまとめることができます。たとえば、シェルスクリプト内のコマンドは同じプロセスグループに属するため、killなどを使って**まとめてシグナルを送信**できます。\
プロセスを**セッションにまとめる**こともできます。プロセスがセッションを開始すると（`setsid(2)`）、独自のセッションを開始しない限り、その子プロセスはそのセッションに属します。

Coalitionは、Darwinでプロセスをグループ化するもう1つの方法です。プロセスがCoalitionに参加すると、プールリソースにアクセスできるようになり、台帳を共有したり、Jetsamの対象になったりします。Coalitionには、Leader、XPC service、Extensionという異なる役割があります。

### 認証情報とPersonae

各プロセスは、システム上の**権限を識別する****認証情報**を保持します。各プロセスには1つのプライマリ`uid`と1つのプライマリ`gid`があります（ただし、複数のグループに所属することもあります）。\
バイナリに`setuid/setgid`ビットが設定されていれば、ユーザーIDとグループIDを変更することもできます。\
**新しいuid/gidを設定する**関数はいくつかあります。

システムコール**`persona`**は、**代替の****認証情報**セットを提供します。personaを採用すると、そのuid、gid、グループ所属が**一度に**引き継がれます。[**ソースコード**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)で、次の構造体を確認できます。

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

1. **POSIX Threads (pthreads):** macOS は POSIX threads（`pthreads`）をサポートしています。これは C/C++ 用の標準スレッド API の一部です。macOS の pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、公開されている `libpthread` プロジェクトに由来します。このライブラリは、スレッドの作成と管理に必要な関数を提供します。
2. **スレッドの作成:** 新しいスレッドの作成には `pthread_create()` 関数を使用します。この関数は内部で `bsdthread_create()` を呼び出します。これは XNU カーネル（macOS の基盤となるカーネル）固有の低レベルなシステムコールです。このシステムコールは、スケジューリングポリシーやスタックサイズなど、スレッドの動作を指定する `pthread_attr`（属性）に基づく各種フラグを受け取ります。
   - **デフォルトのスタックサイズ:** 新しいスレッドのデフォルトのスタックサイズは 512 KB です。一般的な処理には十分なサイズですが、必要に応じてスレッド属性で増減できます。
3. **スレッドの初期化:** `__pthread_init()` 関数はスレッドのセットアップで重要な役割を果たし、`env[]` 引数を使用して、スタックの位置やサイズなどの情報を含む環境変数を解析します。

#### macOS でのスレッド終了

1. **スレッドの終了:** スレッドは通常、`pthread_exit()` を呼び出して終了します。この関数によりスレッドは正常に終了し、必要なクリーンアップが行われます。また、join を行うスレッドに戻り値を返すこともできます。
2. **スレッドのクリーンアップ:** `pthread_exit()` が呼び出されると、関連するすべてのスレッド構造体の削除を処理する `pthread_terminate()` 関数が呼び出されます。この関数は Mach thread port（Mach は XNU カーネルの通信サブシステム）を解放し、スレッドに関連するカーネルレベルの構造体を削除するシステムコール `bsdthread_terminate` を呼び出します。

#### 同期メカニズム

共有リソースへのアクセスを管理し、競合状態を避けるために、macOS は複数の同期プリミティブを提供しています。これらはマルチスレッド環境でデータの整合性とシステムの安定性を確保するうえで重要です。

1. **Mutex:**
   - **通常の Mutex（シグネチャ: 0x4D555458）:** 標準的な mutex で、メモリ使用量は 60 バイトです（mutex に 56 バイト、シグネチャに 4 バイト）。
   - **Fast Mutex（シグネチャ: 0x4d55545A）:** 通常の mutex と似ていますが、より高速な操作向けに最適化されており、サイズも 60 バイトです。
2. **Condition Variable:**
   - 特定の条件が発生するまで待機するために使用します。サイズは 44 バイトです（40 バイトと 4 バイトのシグネチャ）。
   - **Condition Variable Attributes（シグネチャ: 0x434e4441）:** condition variable の設定属性で、サイズは 12 バイトです。
3. **Once Variable（シグネチャ: 0x4f4e4345）:**
   - 初期化コードが一度だけ実行されることを保証します。サイズは 12 バイトです。
4. **Read-Write Lock:**
   - 複数の reader、または一度に 1 つの writer を許可し、共有データへの効率的なアクセスを実現します。
   - **Read Write Lock（シグネチャ: 0x52574c4b）:** サイズは 196 バイトです。
   - **Read Write Lock Attributes（シグネチャ: 0x52574c41）:** read-write lock の属性で、サイズは 20 バイトです。

> [!TIP]
> これらのオブジェクトの最後の 4 バイトは、オーバーフローの検出に使用されます。

### Thread Local Variables (TLV)

Mach-O ファイル（macOS の実行ファイル形式）における **Thread Local Variables (TLV)** は、マルチスレッドアプリケーションで**各スレッド固有**の変数を宣言するために使用されます。これにより各スレッドは変数の独立したインスタンスを持つことができ、mutex のような明示的な同期メカニズムを使わずに、競合を避けてデータの整合性を維持できます。

C および関連する言語では、**`__thread`** キーワードを使用してスレッドローカル変数を宣言できます。以下に例を示します。

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

このスニペットでは、`tlv_var`をスレッドローカル変数として定義しています。このコードを実行する各スレッドは、それぞれ独自の`tlv_var`を持ち、あるスレッドによる`tlv_var`の変更は、別のスレッドの`tlv_var`には影響しません。

Mach-Oバイナリでは、スレッドローカル変数に関連するデータは、特定のセクションに格納されます。

- **`__DATA.__thread_vars`**: スレッドローカル変数の型や初期化状態などのメタデータを格納します。
- **`__DATA.__thread_bss`**: 明示的に初期化されていないスレッドローカル変数に使用されます。ゼロ初期化データ用に確保されたメモリ領域の一部です。

Mach-Oには、スレッド終了時にスレッドローカル変数を管理するための専用API、**`tlv_atexit`**もあります。このAPIでは、スレッド終了時にスレッドローカルデータをクリーンアップする特殊な関数、**デストラクタを登録**できます。

### スレッドの優先度

スレッドの優先度を理解するには、オペレーティングシステムがどのスレッドをいつ実行するかを決定する仕組みを把握する必要があります。この決定は、各スレッドに割り当てられた優先度レベルの影響を受けます。macOSやUnix系システムでは、`nice`、`renice`、Quality of Service（QoS）クラスなどの概念を使って管理されます。

#### NiceとRenice

1. **Nice:**
   - プロセスの`nice`値は、優先度に影響する数値です。各プロセスの`nice`値は-20（最優先）から19（最低優先度）の範囲で、通常、プロセス作成時のデフォルト値は0です。
   - `nice`値が低い（-20に近い）ほど、そのプロセスは他の`nice`値の高いプロセスより多くのCPU時間を得るため、より「自己中心的」になります。
2. **Renice:**
   - `renice`は、実行中のプロセスの`nice`値を変更するコマンドです。新しい`nice`値に応じてCPU時間の割り当てを増減し、プロセスの優先度を動的に調整できます。
   - たとえば、一時的により多くのCPUリソースが必要なプロセスの`nice`値を、`renice`で下げることができます。

#### Quality of Service（QoS）クラス

QoSクラスは、特に**Grand Central Dispatch（GCD）**に対応するmacOSのようなシステムで、スレッドの優先度を扱うための、より新しい方法です。QoSクラスを使うと、開発者は作業の重要度や緊急度に応じて、異なるレベルに**分類**できます。macOSは、QoSクラスに基づいてスレッドの優先順位を自動的に管理します。

1. **User Interactive:**
   - ユーザーと現在やり取りしている、または良好なユーザー体験のために即時の結果が必要なタスク向けのクラスです。インターフェースの応答性を保つため、最も高い優先度が与えられます（アニメーションやイベント処理など）。
2. **User Initiated:**
   - ドキュメントを開く、計算が必要なボタンをクリックするなど、ユーザーが開始し、すぐに結果が得られることを期待するタスク向けです。優先度は高いものの、User Interactiveより低くなります。
3. **Utility:**
   - 長時間実行され、通常は進捗インジケーターを表示するタスク向けです（ファイルのダウンロードやデータのインポートなど）。ユーザーが開始したタスクより優先度が低く、すぐに完了する必要もありません。
4. **Background:**
   - バックグラウンドで動作し、ユーザーには見えないタスク向けのクラスです。インデックス作成、同期、バックアップなどが該当します。優先度は最も低く、システムパフォーマンスへの影響も最小限です。

QoSクラスを使えば、開発者は正確な優先度の数値を管理せず、タスクの性質に集中できます。システムはそれに応じてCPUリソースを最適化します。

また、スケジューラが考慮するスケジューリングパラメータを指定する、さまざまな**スレッドスケジューリングポリシー**があります。これは`thread_policy_[set/get]`を使って設定できます。race condition攻撃で役立つ場合があります。

## macOSプロセスの悪用

macOSには、**プロセス間で相互作用、通信、データ共有を行う**ための仕組みが数多くあります。これらは通常のシステム動作に不可欠ですが、攻撃者はインジェクション、コード実行、データアクセスに悪用できます。

### Library Injection

Library Injectionは、攻撃者が**プロセスに悪意のあるライブラリを強制的にロードさせる**手法です。インジェクションされたライブラリは対象プロセスのコンテキストで実行されるため、攻撃者はそのプロセスと同じ権限やアクセス権を得られます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hookingは、ソフトウェアコード内の関数呼び出しやメッセージを**傍受する**手法です。関数をhookすることで、攻撃者はプロセスの**動作を変更**したり、機密データを監視したり、実行フローを制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

このページでは、ARM64のunwindメタデータ、arm64eのPAC制約、合成call chainについて説明します。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### プロセス間通信

プロセス間通信（IPC）は、別々のプロセス間で**データを共有・交換する**さまざまな方法を指します。IPCは多くの正当なアプリケーションに不可欠ですが、プロセス分離の回避、機密情報のleak、不正な操作にも悪用される可能性があります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electronアプリケーションのインジェクション

特定の環境変数を設定して実行されたElectronアプリケーションは、プロセスインジェクションに対して脆弱な場合があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

フラグ`--load-extension`と`--use-fake-ui-for-media-stream`を使うと、**man in the browser攻撃**を実行できます。これにより、キーストロークや通信、Cookieの窃取、ページへのスクリプトインジェクションなどが可能になります。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIBファイルは、アプリケーション内の**ユーザーインターフェース（UI）要素とその相互作用を定義**します。しかし、**任意のコマンドを実行できる**場合があり、**NIBファイルが変更されても、Gatekeeperは一度実行されたアプリケーションの再実行を阻止しません**。そのため、任意のプログラムに任意のコマンドを実行させるために利用される可能性があります。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Javaアプリケーションのインジェクション

**`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`**、**`JDK_JAVA_OPTIONS`**を通じてJVMオプションをインジェクションし、アプリケーションの起動前にJavaエージェントまたはネイティブエージェントをロードできます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**は、`--require`（ファイル）または`--import data:text/javascript,…`（ファイルレス、Node ≥ 20.6）を使って攻撃者のJavaScriptを事前ロードします。**`NODE_REPL_EXTERNAL_MODULE`**は対話型REPLにモジュールをロードし、**`ELECTRON_RUN_AS_NODE`**はElectronバイナリでこれらすべてを再び有効にします。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Netアプリケーションのインジェクション

**`DOTNET_STARTUP_HOOKS`**を使って`Main`の前に.NETアプリケーションへコードをインジェクションできます。また、前提条件が満たされている場合は、.NETのデバッグ機能を悪用する方法もあります。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非対話型Bashは**`BASH_ENV`**を読み込みます。対話型POSIX shellは**`ENV`**を読み込み、zshは**`$ZDOTDIR/.zshenv`**を読み込み、fishは**`XDG_CONFIG_HOME`**または**`XDG_DATA_DIRS`**以下の設定を読み込みます。いずれも、意図されたコマンドの前に、制御された起動ファイルを実行できます。また、xtraceが有効な場合、Bashは**`PS4`**に設定されたコマンド置換も実行します（例: 継承された**`SHELLOPTS=xtrace`**）。

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s`を起動すると、shellは標準入力からプログラムを読み込みます。そのため、信頼できない構造化ドキュメントを解析せずに子プロセスのstdinへコピーするダウンローダーは、そのドキュメント全体をshellのソースコードにしてしまいます。確認されたあるloaderは、公開iCalendarファイルを匿名pipe経由で1行ずつ渡していました。カレンダーのメタデータはコマンドとして失敗しましたが、zshは実行可能な行が`DESCRIPTION:`の後に現れるまで処理を続けました。これらの行は次のアプリケーションバンドルをダウンロードして起動しました。データの想定Content-Typeやホスティング元の信頼性が安全性を保証するわけではありません。危険なのは、そのデータをインタープリターに渡すことです。<sup>[[5]](#references)</sup>

関連するステージについては、[Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)、[Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md)、[macOS auto-start locations](../../macos-auto-start-locations.md)を参照してください。

### PHP Injection

**`PHPRC`**または**`PHP_INI_SCAN_DIR`**を使うと、対象スクリプトより前に**`auto_prepend_file`**を実行する、制御されたPHP設定をロードできます。

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

スタンドアロンのLuaインタープリターは、対象スクリプトの処理前に**`LUA_INIT`**（またはバージョン固有の変数）からコードまたは`@file`を実行します。

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`**と**`R_PROFILE`**を使うと、Rコードを含む起動プロファイルを別の場所に指定できます。また、**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**とRのライブラリパスを使って、インストール済みパッケージを自動ロードすることもできます。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**を使うと、`config/startup.jl`が自動実行されるdepotの場所を変更できます。

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`**、**`ERL_ZFLAGS`**を使うと、payloadファイルなしでErlang VMの**`-eval`**式をインジェクションできます。Elixirのワークロードも通常、同じVMを起動します。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`**と**`OCTAVE_VERSION_INITFILE`**を使うと、Octaveの起動スクリプトの場所を変更できます。

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh`はクロスプラットフォームの.NETアプリケーションであるため、いくつかの環境変数を使ってコマンド実行前に処理を実行できます。**`XDG_CONFIG_HOME`**は起動時に実行されるプロファイルスクリプトの場所を変更し、**`PSModulePath`**はモジュールの自動ロードを乗っ取ります（配置した`.psm1`はimport時に実行され、組み込みcmdletをshadowできます）。また、.NETの**`CORECLR_PROFILER`**/**`COR_PROFILER`**や**`DOTNET_STARTUP_HOOKS`**を使うと、`Main`の前に攻撃者のコードをプロセスへロードできます。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perlスクリプトに任意のコードを実行させるためのさまざまな方法については、以下を参照してください。


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Rubyの環境変数（**`RUBYOPT`**、**`RUBYLIB`**）を悪用して、任意のスクリプトに任意のコードを実行させることもできます。


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`**と標準ライブラリの**`BROWSER`**を組み合わせると、warning-filterの解析中にコマンドを実行できます。ファイルを使う別の方法では、**`PYTHONPATH`**上に`sitecustomize.py`を置き、通常の`site`初期化で対象スクリプトより前にimportさせます。**`PYTHONBREAKPOINT`**は、コードが`breakpoint()`に到達したときに指定されたcallable/moduleを実行します。**`PYTHONSTARTUP`**などの対話型専用変数は、適用範囲が限定されます。

**`pyinstaller`**でコンパイルされた実行ファイルは、組み込みPythonを使って実行されていても、これらの環境変数を使用しない点に注意してください。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

通常の起動時に**`VIMINIT`**（および代替の`EXINIT`）がExコマンドとして実行されます。そのため、制御された環境で被害者がVim/Neovimを開くと、`:!cmd` / `:call system(...)`によってコード実行が可能になります。

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

これとは別に、HomebrewはPythonを`/opt/homebrew`以下にインストールすることが多く、ローカルの`admin`グループのメンバーがlauncherを置き換えられる場合があります。これは環境変数インジェクションではなく、書き込み可能なバイナリの乗っ取りです。悪用可能と判断する前に、所有者とACLを確認してください。


## 検知

### Shield

[**Shield**](https://github.com/theevilbit/Shield)は、プロセスインジェクションを検知してブロックする、**EndpointSecurity**ベースのオープンソースアプリケーションです。以下のような通知を行うため、Endpoint Securityで観測可能なシグナルを把握する参考になります。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- プロセス実行時の**インジェクション用環境変数**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`**の呼び出し — あるプロセスが別のプロセスのtask portを要求する操作で、対象へのインジェクションに必要な前提条件です。
- **Electronのデバッグ引数** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。Electronアプリをdebug modeで起動し、誰でも接続してコードを実行できるようにします。<sup>[[3]](#references)</sup>
- **異なる権限レベル間でのsymlink/hardlink作成** — 通常ユーザーとしてlinkを作成し、特権のある場所を指すようにする古典的な手法です。なお、**symlinkは検知できてもブロックできません**。EndpointSecurityは、作成前にlinkの参照先を公開しないためです。

### 他のプロセスによる呼び出し

[**このブログ記事**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、関数**`task_name_for_pid`**を使って、**プロセスにコードをインジェクションしている他のプロセス**に関する情報を取得し、そのプロセス自体の情報も取得する方法を紹介しています。<sup>[[4]](#references)</sup>

この関数を呼び出すには、対象プロセスを実行しているユーザーと**同じuid**であるか、**root**である必要があります（この関数が返すのはプロセスに関する情報であり、コードをインジェクションする方法ではありません）。

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — オープンソースのmacOSプロセスインジェクション検知（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurityフレームワーク](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electronアプリが秘密情報を機密に保てない理由: --inspectオプション](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - taskの変更を検知する](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealerの新バージョン、暗号資産愛好家と開発者を標的に](https://securelist.com/macsync-new-version/121383/)
