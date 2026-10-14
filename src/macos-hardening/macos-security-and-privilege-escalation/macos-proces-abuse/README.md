# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## プロセスの基本情報

プロセスは実行中の実行ファイルのインスタンスですが、コードを実行するのはプロセスではなくスレッドです。したがって、**プロセスは実行中のスレッドを格納するコンテナにすぎず**、メモリ、ディスクリプタ、ポート、権限などを提供します。

従来、プロセスは（PID 1を除き）**`fork`** を呼び出して別のプロセス内で起動されていました。`fork` は現在のプロセスの完全なコピーを作成し、その後、通常は**子プロセス**が **`execve`** を呼び出して新しい実行ファイルを読み込み、実行します。その後、メモリコピーなしでこのプロセスを高速化するために **`vfork`** が導入されました。\
続いて、**`vfork`** と **`execve`** を1回の呼び出しにまとめ、フラグを受け取る **`posix_spawn`** が導入されました。

- `POSIX_SPAWN_RESETIDS`: 実効IDを実IDにリセットする
- `POSIX_SPAWN_SETPGROUP`: プロセスグループへの所属を設定する
- `POSUX_SPAWN_SETSIGDEF`: シグナルのデフォルト動作を設定する
- `POSIX_SPAWN_SETSIGMASK`: シグナルマスクを設定する
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内でexecする（オプションを追加した `execve` のようなもの）
- `POSIX_SPAWN_START_SUSPENDED`: サスペンド状態で起動する
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLRなしで起動する
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmallocのNano allocatorを使用する
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` データセグメント上で `rwx` を許可する
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトでexec(2)時にすべてのファイル記述を閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slideの上位ビットをランダム化する

さらに、`posix_spawn` は、生成されるプロセスの動作を制御する **`posix_spawnattr`** 設定と、ファイルディスクリプタを変更する **`posix_spawn_file_actions`** エントリを受け取ります。

プロセスが終了すると、シグナル `SIGCHLD` とともに**親プロセスへ終了コードを送信します**（親プロセスが終了していた場合、新しい親プロセスはPID 1です）。親プロセスは `wait4()` または `waitid()` を呼び出してこの値を取得する必要があります。それまで子プロセスはゾンビ状態に留まり、一覧には表示されますが、リソースは消費しません。

### PID

PID（プロセス識別子）は、個々のプロセスを識別します。XNUの **PID** は **64ビット**で、単調に増加し、（悪用を防ぐため）**ラップアラウンドしません**。

### プロセスグループ、セッション、Coalition

**プロセス**は、管理しやすくするために**グループ**にまとめることができます。たとえば、シェルスクリプト内のコマンドは同じプロセスグループに属するため、killなどを使って**まとめてシグナルを送る**ことができます。\
プロセスを**セッションにまとめる**こともできます。プロセスがセッションを開始すると（`setsid(2)`）、子プロセスは自分自身のセッションを開始しない限り、そのセッションに属します。

Coalitionは、Darwinにおけるもう1つのプロセスグループ化の仕組みです。Coalitionに参加したプロセスは、プールリソースにアクセスでき、ledgerを共有したり、Jetsamの対象になったりします。Coalitionには、Leader、XPC service、Extensionという異なるロールがあります。

### CredentialsとPersonae

各プロセスは、システム上の**権限を特定する** **credentials** を保持します。各プロセスはプライマリ `uid` とプライマリ `gid` を1つずつ持ちます（ただし、複数のグループに属することがあります）。\
バイナリに `setuid/setgid` ビットが設定されていれば、ユーザーIDとグループIDを変更することもできます。\
新しいuid/gidを**設定する**関数はいくつかあります。

システムコール **`persona`** は、**代替の** **credentials** セットを提供します。personaeを採用すると、そのuid、gid、グループメンバーシップが**一度に**適用されます。[**ソースコード**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)には、次の構造体があります。

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

1. **POSIX Threads (pthreads):** macOS は POSIX スレッド（`pthreads`）をサポートしています。これは C/C++ 向けの標準スレッド API の一部です。macOS の pthreads 実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、公開されている `libpthread` プロジェクトに由来します。このライブラリは、スレッドの作成と管理に必要な関数を提供します。
2. **スレッドの作成:** 新しいスレッドの作成には `pthread_create()` 関数を使用します。この関数は内部で `bsdthread_create()` を呼び出します。これは、XNU カーネル（macOS の基盤となるカーネル）固有の低レベルシステムコールです。このシステムコールは、スケジューリングポリシーやスタックサイズなど、スレッドの動作を指定する `pthread_attr`（属性）由来の各種フラグを受け取ります。
   - **デフォルトのスタックサイズ:** 新しいスレッドのデフォルトのスタックサイズは 512 KB です。一般的な処理には十分ですが、必要に応じてスレッド属性で増減できます。
3. **スレッドの初期化:** `__pthread_init()` 関数はスレッドのセットアップで重要な役割を果たし、`env[]` 引数を使用して、スタックの位置やサイズなどの情報を含む環境変数を解析します。

#### macOS でのスレッド終了

1. **スレッドの終了:** スレッドは通常、`pthread_exit()` を呼び出して終了します。この関数によりスレッドは適切に終了し、必要なクリーンアップを実行して、join するスレッドに戻り値を渡せます。
2. **スレッドのクリーンアップ:** `pthread_exit()` を呼び出すと `pthread_terminate()` 関数が呼び出され、関連するすべてのスレッド構造体が削除されます。Mach スレッドポート（Mach は XNU カーネルの通信サブシステム）を解放し、スレッドに関連するカーネルレベルの構造体を削除するシステムコール `bsdthread_terminate` を呼び出します。

#### 同期メカニズム

共有リソースへのアクセスを管理し、競合状態を防ぐため、macOS は複数の同期プリミティブを提供します。これらはマルチスレッド環境でデータの整合性とシステムの安定性を確保するうえで重要です。

1. **Mutex:**
   - **通常の Mutex（シグネチャ: 0x4D555458）:** 標準的な mutex で、メモリ使用量は 60 バイト（mutex に 56 バイト、シグネチャに 4 バイト）です。
   - **Fast Mutex（シグネチャ: 0x4d55545A）:** 通常の mutex と同様ですが、より高速な処理向けに最適化されており、サイズも 60 バイトです。
2. **Condition Variables:**
   - 特定の条件が発生するまで待機するために使用され、サイズは 44 バイト（40 バイトと 4 バイトのシグネチャ）です。
   - **Condition Variable Attributes（シグネチャ: 0x434e4441）:** condition variable の設定属性で、サイズは 12 バイトです。
3. **Once Variable（シグネチャ: 0x4f4e4345）:**
   - 初期化コードを一度だけ実行するために使用します。サイズは 12 バイトです。
4. **Read-Write Locks:**
   - 複数の reader、または一度に 1 つの writer によるアクセスを許可し、共有データへの効率的なアクセスを可能にします。
   - **Read Write Lock（シグネチャ: 0x52574c4b）:** サイズは 196 バイトです。
   - **Read Write Lock Attributes（シグネチャ: 0x52574c41）:** read-write lock の属性で、サイズは 20 バイトです。

> [!TIP]
> これらのオブジェクトの最後の 4 バイトは、オーバーフローの検出に使用されます。

### スレッドローカル変数 (TLV)

Mach-O ファイル（macOS の実行ファイル形式）における **スレッドローカル変数 (TLV)** は、マルチスレッドアプリケーションで **各スレッド専用** の変数を宣言するために使用されます。これにより、各スレッドは変数の独立したインスタンスを持つことができ、mutex などの明示的な同期メカニズムを使わずに競合を避け、データの整合性を維持できます。

C および関連言語では、**`__thread`** キーワードを使ってスレッドローカル変数を宣言できます。以下の例では、次のように動作します。

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

このスニペットでは、`tlv_var`をスレッドローカル変数として定義しています。このコードを実行する各スレッドは、それぞれ独自の`tlv_var`を持ち、あるスレッドが`tlv_var`に加えた変更は、別のスレッドの`tlv_var`には影響しません。

Mach-Oバイナリでは、スレッドローカル変数に関連するデータは、特定のセクションに整理されています。

- **`__DATA.__thread_vars`**: スレッドローカル変数の型や初期化状態などのメタデータが格納されます。
- **`__DATA.__thread_bss`**: 明示的に初期化されていないスレッドローカル変数に使用されます。ゼロ初期化データ用に確保されたメモリ領域の一部です。

Mach-Oには、スレッド終了時にスレッドローカル変数を管理するための専用API **`tlv_atexit`** も用意されています。このAPIを使うと、スレッドの終了時にスレッドローカルデータをクリーンアップする特別な関数である**デストラクタを登録**できます。

### スレッドの優先順位

スレッドの優先順位を理解するには、オペレーティングシステムがスレッドをいつ実行するかをどのように決定するかを確認する必要があります。この決定は、各スレッドに割り当てられた優先度に左右されます。macOSやUnix系システムでは、`nice`、`renice`、Quality of Service (QoS)クラスなどの仕組みを使って制御します。

#### NiceとRenice

1. **Nice:**
   - プロセスの`nice`値は、優先度に影響する数値です。各プロセスのnice値は-20（最優先）から19（最低優先度）までで、プロセス作成時のデフォルト値は通常0です。
   - nice値が低い（-20に近い）ほど、プロセスはより「利己的」になり、nice値の高い他のプロセスより多くのCPU時間を割り当てられます。
2. **Renice:**
   - `renice`は、実行中のプロセスのnice値を変更するコマンドです。新しいnice値に応じてCPU時間の割り当てを増減し、プロセスの優先度を動的に調整できます。
   - たとえば、プロセスが一時的により多くのCPUリソースを必要とする場合、`renice`を使ってnice値を下げます。

#### Quality of Service (QoS)クラス

QoSクラスは、特に**Grand Central Dispatch (GCD)**をサポートするmacOSのようなシステムで使われる、より現代的なスレッド優先順位の管理方法です。QoSクラスを使うと、開発者は重要度や緊急度に応じて作業を異なるレベルに**分類**できます。macOSは、次のQoSクラスに基づいてスレッドの優先順位を自動的に管理します。

1. **User Interactive:**
   - ユーザーが操作中、または快適な操作性のために即時の結果が必要なタスクに使います。インターフェースの応答性を保つため、アニメーションやイベント処理などのタスクに最高の優先度が与えられます。
2. **User Initiated:**
   - ドキュメントを開く、計算を必要とするボタンをクリックするなど、ユーザーが開始し、すぐに結果を期待するタスクに使います。優先度は高いものの、User Interactiveよりは低くなります。
3. **Utility:**
   - ダウンロードやデータの読み込みなど、長時間実行され、通常は進捗状況が表示されるタスクに使います。User Initiatedより優先度は低く、すぐに完了する必要はありません。
4. **Background:**
   - バックグラウンドで動作し、ユーザーには見えないタスクに使います。インデックス作成、同期、バックアップなどが該当します。優先度は最も低く、システムパフォーマンスへの影響も最小限です。

QoSクラスを使うと、開発者は具体的な優先度の数値を管理する必要がなく、タスクの性質に集中できます。システムはそれに応じてCPUリソースを最適化します。

さらに、スケジューラが考慮するスケジューリングパラメータを指定する、さまざまな**スレッドスケジューリングポリシー**があります。これは`thread_policy_[set/get]`を使って設定できます。レースコンディション攻撃で役立つ場合があります。

## macOSプロセスの悪用

macOSには、**プロセス間で相互作用、通信、データ共有を行う**ための仕組みが数多く用意されています。これらは通常のシステム動作に不可欠ですが、攻撃者はインジェクション、コード実行、データアクセスに悪用できます。

### Library Injection

Library Injectionは、攻撃者が**プロセスに悪意のあるライブラリを強制的に読み込ませる**手法です。インジェクションされたライブラリは対象プロセスのコンテキストで実行されるため、攻撃者はそのプロセスと同じ権限やアクセス権を得られます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hookingは、ソフトウェアコード内の**関数呼び出し**やメッセージを**傍受する**手法です。関数をフックすることで、攻撃者はプロセスの**動作を変更**したり、機密データを監視したり、実行フローを制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

このページでは、ARM64のアンワインドメタデータ、arm64eのPAC制約、合成コールチェーンについて説明します。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC)は、別々のプロセスが**データを共有・交換する**ためのさまざまな方法を指します。IPCは多くの正規アプリケーションの基盤ですが、プロセス分離の回避、機密情報のleak、不正な操作にも悪用される可能性があります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定の環境変数を設定して実行されたElectronアプリケーションは、プロセスインジェクションに対して脆弱な場合があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

フラグ`--load-extension`と`--use-fake-ui-for-media-stream`を使うと、キーストロークや通信、Cookieを盗んだり、ページにスクリプトを注入したりできる**man in the browser attack**を実行できます。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIBファイルは、アプリケーション内の**ユーザーインターフェース (UI) 要素**とその操作を**定義します**。しかし、NIBファイルは**任意のコマンドを実行でき**、**NIBファイルが変更されても、Gatekeeperは一度実行されたアプリケーションの再実行を阻止しません**。そのため、任意のプログラムに任意のコマンドを実行させるために利用できます。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`**、または**`JDK_JAVA_OPTIONS`**を介してJVMオプションを注入し、アプリケーションの起動前にJavaまたはネイティブエージェントを読み込ませることができます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**は、`--require`（ファイル）または`--import data:text/javascript,…`（ファイルレス、Node ≥ 20.6）を使って攻撃者のJavaScriptを事前読み込みします。**`NODE_REPL_EXTERNAL_MODULE`**は対話型REPLにモジュールを読み込ませ、**`ELECTRON_RUN_AS_NODE`**はElectronバイナリでこれらすべてを再び有効にします。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

**`DOTNET_STARTUP_HOOKS`**を使って`Main`の前にコードを.NETアプリケーションへ注入したり、前提条件がそろっている場合に.NETのデバッグ機能を悪用したりできます。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非対話型のBashは**`BASH_ENV`**を読み込み、対話型のPOSIXシェルは**`ENV`**を読み込みます。zshは**`$ZDOTDIR/.zshenv`**を読み込み、fishは**`XDG_CONFIG_HOME`**または**`XDG_DATA_DIRS`**以下の設定を読み込みます。いずれも、制御された起動ファイルを意図したコマンドの前に実行できます。また、xtraceが有効なとき（たとえば**`SHELLOPTS=xtrace`**を継承した場合）、Bashは**`PS4`**に設定されたコマンド置換も実行します。

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s`を起動すると、シェルは標準入力からプログラムを読み込みます。そのため、信頼できない構造化ドキュメントを解析せずに子プロセスのstdinへコピーするダウンローダーは、そのドキュメント全体をシェルのソースコードにしてしまいます。確認されたあるローダーは、公開されたiCalendarファイルを匿名パイプ経由で1行ずつ渡していました。カレンダーのメタデータはコマンドとして失敗しましたが、zshは処理を続け、`DESCRIPTION:`の後に置かれた実行可能な行に到達しました。それらの行は次のアプリケーションバンドルをダウンロードして起動しました。配信元の想定コンテンツタイプや信頼できるホスティング元は、この処理を安全にはしません。危険なのは、バイト列をインタープリターに渡す境界です。<sup>[[5]](#references)</sup>

関連する段階については、[Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)、[Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md)、[macOS auto-start locations](../../macos-auto-start-locations.md)を参照してください。

### PHP Injection

**`PHPRC`**または**`PHP_INI_SCAN_DIR`**を使うと、**`auto_prepend_file`**によって対象スクリプトの実行前に処理を実行する、制御されたPHP設定を読み込ませることができます。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

スタンドアロンのLuaインタープリターは、対象スクリプトの処理前に**`LUA_INIT`**（またはバージョン固有の変数）で指定されたコードまたは`@file`を実行します。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`**と**`R_PROFILE`**を使うと、Rコードを含む起動プロファイルの読み込み先を変更できます。代わりに、**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**とRライブラリパスを組み合わせて、インストール済みパッケージを自動読み込みさせることもできます。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**を変更すると、`config/startup.jl`が自動実行されるデポの場所を変更できます。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`**、または**`ERL_ZFLAGS`**を使うと、ペイロードファイルなしでErlang VMの**`-eval`**式を注入できます。Elixirのワークロードも、通常は同じVMを起動します。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`**と**`OCTAVE_VERSION_INITFILE`**を使うと、Octaveの起動スクリプトの読み込み先を変更できます。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh`はクロスプラットフォームの.NETアプリケーションであるため、いくつかの環境変数を使ってコマンド実行前に処理を実行できます。**`XDG_CONFIG_HOME`**は起動時に実行されるプロファイルスクリプトの場所を変更し、**`PSModulePath`**はモジュールの自動読み込みを乗っ取ります（設置した`.psm1`はインポート時に実行され、組み込みのcmdletをシャドーイングできます）。また、.NETの**`CORECLR_PROFILER`**/**`COR_PROFILER`**や**`DOTNET_STARTUP_HOOKS`**変数は、`Main`の前に攻撃者のコードをプロセスへ読み込みます。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perlスクリプトに任意のコードを実行させるためのさまざまな方法を確認してください。

{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Rubyの環境変数（**`RUBYOPT`**、**`RUBYLIB`**）を悪用して、任意のスクリプトに任意のコードを実行させることもできます。

{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`**と標準ライブラリの**`BROWSER`**を組み合わせると、警告フィルターの解析中にコマンドを実行できます。ファイルを使う方法では、**`PYTHONPATH`**上に`sitecustomize.py`を配置すると、通常の`site`初期化で対象スクリプトより前にインポートされます。コードが`breakpoint()`に到達したとき、**`PYTHONBREAKPOINT`**は指定されたcallable/moduleを実行します。**`PYTHONSTARTUP`**など、対話型セッションでのみ使われる変数の適用範囲はより限定的です。

**`pyinstaller`**でコンパイルされた実行ファイルは、埋め込みPythonを使って実行されていても、これらの環境変数を使用しないことに注意してください。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

通常の起動時に**`VIMINIT`**（およびそのフォールバックである`EXINIT`）はExコマンドとして実行されます。そのため、攻撃者が制御する環境で被害者がVim/Neovimを開くと、`:!cmd` / `:call system(...)`によってコードを実行できます。

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

これとは別に、HomebrewはPythonを一般に`/opt/homebrew`以下にインストールします。この場所では、ローカルの`admin`グループのメンバーがランチャーを置き換えられる場合があります。これは環境変数インジェクションではなく、書き込み可能なバイナリの乗っ取りです。悪用可能と判断する前に、所有者とACLを確認してください。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield)は、**EndpointSecurity**ベースのオープンソースアプリケーションで、プロセスインジェクションを検知してブロックします。Endpoint Securityを通じてどのシグナルを観測できるかを知るための参考になり、次の項目を警告します。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- プロセス実行時の**インジェクション用環境変数**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`**の呼び出し — あるプロセスが別のプロセスのtask portを要求する操作。これは、そのプロセスへインジェクションするための前提条件です。
- **Electronのデバッグ引数** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらはElectronアプリをデバッグモードで起動し、誰でも接続してコードを実行できるようにします。<sup>[[3]](#references)</sup>
- **異なる権限レベル間でのシンボリックリンク／ハードリンクの作成** — 一般ユーザーとしてリンクを作成し、特権が必要な場所を指すようにする古典的な手法です。**シンボリックリンクは警告対象にはできても、ブロックはできません**。EndpointSecurityはリンク作成前にリンク先を公開しないためです。

### 他のプロセスによる呼び出し

[**このブログ記事**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、関数**`task_name_for_pid`**を使って、**プロセスにコードをインジェクションしている他のプロセス**に関する情報を取得し、さらにそのプロセスについて調べる方法を紹介しています。<sup>[[4]](#references)</sup>

この関数を呼び出すには、対象プロセスを実行しているユーザーと**同じuid**であるか、**root**である必要があります（この関数が返すのはプロセスに関する情報であり、コードをインジェクションする方法ではありません）。

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — オープンソースのmacOSプロセスインジェクション検知 (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurityフレームワーク](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electronアプリは秘密を機密に保管できない理由: --inspectオプション](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - taskの変更を検知する](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealerの新バージョンが暗号資産愛好家と開発者を標的に](https://securelist.com/macsync-new-version/121383/)
