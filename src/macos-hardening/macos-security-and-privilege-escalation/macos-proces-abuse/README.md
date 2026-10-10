# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Processの基本情報

processは実行中の実行ファイルのインスタンスですが、processがコードを実行するわけではありません。コードを実行するのはthreadです。したがって、**processはthreadを実行するためのcontainerにすぎず**、メモリ、descriptor、port、permissionなどを提供します。

従来、processは（PID 1を除き）**`fork`**を呼び出して別のprocess内で開始されていました。`fork`は現在のprocessの完全なコピーを作成し、その後、**child process**が通常**`execve`**を呼び出して新しい実行ファイルをロードし、実行します。その後、メモリをコピーせずにこの処理を高速化するため、**`vfork`**が導入されました。\
続いて、**`vfork`**と**`execve`**を1回の呼び出しにまとめ、次のflagsを受け付ける**`posix_spawn`**が導入されました。

- `POSIX_SPAWN_RESETIDS`: effective idをreal idにリセット
- `POSIX_SPAWN_SETPGROUP`: process groupへの所属を設定
- `POSUX_SPAWN_SETSIGDEF`: signalのデフォルト動作を設定
- `POSIX_SPAWN_SETSIGMASK`: signal maskを設定
- `POSIX_SPAWN_SETEXEC`: 同じprocess内でexecする（追加オプション付きの`execve`のようなもの）
- `POSIX_SPAWN_START_SUSPENDED`: suspend状態で開始
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLRなしで開始
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmallocのNano allocatorを使用
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` data segmentで`rwx`を許可
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトでexec(2)時にすべてのfile descriptionを閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR slideの上位bitをランダム化

さらに、`posix_spawn`は、生成されるprocessの各種動作を制御する**`posix_spawnattr`**設定と、file descriptorを変更する**`posix_spawn_file_actions`**エントリを受け付けます。

processが終了すると、signal `SIGCHLD`とともに**return codeをparent processに送信**します（parentが終了している場合、新しいparentはPID 1です）。parentは`wait4()`または`waitid()`を呼び出してこの値を取得する必要があり、取得されるまではchildはzombie状態のまま一覧に表示されますが、resourceは消費しません。

### PIDs

PID（process identifier）は、一意のprocessを識別します。XNUでは**PID**は**64bits**で、単調に増加し、（abuseを防ぐため）**wrapしません**。

### Process Group、Session、Coalition

**process**は扱いやすくするために**group**にまとめることができます。たとえば、shell script内のcommandは同じprocess groupに属するため、たとえばkillを使って**まとめてsignalを送信**できます。\
processを**sessionにまとめる**こともできます。processがsession（`setsid(2)`）を開始すると、独自のsessionを開始しない限り、そのchild processはそのsessionに属します。

Coalitionは、Darwinでprocessをまとめるもう1つの方法です。processがcoalitionに参加すると、pool resourceにアクセスし、ledgerを共有したり、Jetsamの対象になったりできます。CoalitionにはLeader、XPC service、Extensionという異なるroleがあります。

### CredentialとPersona

各processは、システム上の**privilegeを識別する****credential**を保持しています。各processにはprimary `uid`とprimary `gid`が1つずつあります（ただし、複数のgroupに所属する場合があります）。\
binaryに`setuid/setgid` bitが設定されていれば、user IDとgroup IDを変更することもできます。\
**新しいuid/gidを設定する**関数はいくつかあります。

syscall **`persona`**は、**alternate**な**credential**のセットを提供します。personaを採用すると、そのuid、gid、group membershipが**同時に**適用されます。[**source code**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)では、次のstructを確認できます。

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

1. **POSIX Threads (pthreads):** macOS は POSIX threads（`pthreads`）をサポートしています。これは C/C++ 用の標準スレッド API の一部です。macOS における pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、一般公開されている `libpthread` プロジェクトに由来します。このライブラリは、スレッドの作成と管理に必要な関数を提供します。
2. **スレッドの作成:** `pthread_create()` 関数を使って新しいスレッドを作成します。内部では、この関数は `bsdthread_create()` を呼び出します。これは XNU カーネル（macOS の基盤となるカーネル）固有の低レベルシステムコールです。このシステムコールは、スレッドの動作を指定する `pthread_attr`（属性）に由来するさまざまなフラグを受け取ります。これにはスケジューリングポリシーやスタックサイズなどが含まれます。
   - **デフォルトのスタックサイズ:** 新しいスレッドのデフォルトのスタックサイズは 512 KB です。一般的な処理には十分なサイズですが、必要に応じてスレッド属性で増減できます。
3. **スレッドの初期化:** `__pthread_init()` 関数はスレッドのセットアップにおいて重要な役割を果たし、`env[]` 引数を使用して、スタックの位置やサイズなどを含む環境変数を解析します。

#### macOS でのスレッド終了

1. **スレッドの終了:** スレッドは通常、`pthread_exit()` を呼び出して終了します。この関数により、スレッドは必要なクリーンアップを実行して正常に終了し、join するスレッドに戻り値を返せます。
2. **スレッドのクリーンアップ:** `pthread_exit()` を呼び出すと、`pthread_terminate()` 関数が呼び出され、関連するすべてのスレッド構造体の削除が処理されます。Mach スレッドポート（Mach は XNU カーネル内の通信サブシステム）を解放し、スレッドに関連付けられたカーネルレベルの構造体を削除するシステムコール `bsdthread_terminate` を呼び出します。

#### 同期メカニズム

共有リソースへのアクセスを管理し、競合状態を防ぐため、macOS は複数の同期プリミティブを提供しています。これらは、データの整合性とシステムの安定性を確保するうえで、マルチスレッド環境において重要です。

1. **Mutexes:**
   - **通常の Mutex（シグネチャ: 0x4D555458）:** メモリ使用量は 60 バイト（Mutex に 56 バイト、シグネチャに 4 バイト）の標準的な Mutex です。
   - **Fast Mutex（シグネチャ: 0x4d55545A）:** 通常の Mutex と同様ですが、より高速な操作向けに最適化されており、サイズも 60 バイトです。
2. **Condition Variables:**
   - 特定の条件が満たされるまで待機するために使われ、サイズは 44 バイト（40 バイトと 4 バイトのシグネチャ）です。
   - **Condition Variable Attributes（シグネチャ: 0x434e4441）:** Condition Variables の設定属性で、サイズは 12 バイトです。
3. **Once Variable（シグネチャ: 0x4f4e4345）:**
   - 初期化コードが一度だけ実行されるようにします。サイズは 12 バイトです。
4. **Read-Write Locks:**
   - 複数の読み取りスレッド、または一度に 1 つの書き込みスレッドを許可し、共有データへの効率的なアクセスを実現します。
   - **Read Write Lock（シグネチャ: 0x52574c4b）:** サイズは 196 バイトです。
   - **Read Write Lock Attributes（シグネチャ: 0x52574c41）:** Read-Write Locks の属性で、サイズは 20 バイトです。

> [!TIP]
> これらのオブジェクトの最後の 4 バイトは、オーバーフローの検出に使用されます。

### スレッドローカル変数 (TLV)

Mach-O ファイル（macOS の実行ファイル形式）における**スレッドローカル変数 (TLV)** は、マルチスレッドアプリケーションで**各スレッド固有**の変数を宣言するために使われます。これにより各スレッドが変数の個別のインスタンスを持ち、Mutex のような明示的な同期メカニズムを必要とせずに、競合を避けてデータの整合性を維持できます。

C および関連する言語では、**`__thread`** キーワードを使ってスレッドローカル変数を宣言できます。例を使って説明します。

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

このスニペットでは、`tlv_var`をスレッドローカル変数として定義しています。このコードを実行する各スレッドは、それぞれ独自の`tlv_var`を持ちます。そのため、あるスレッドが`tlv_var`に加えた変更は、別のスレッドの`tlv_var`には影響しません。

Mach-Oバイナリでは、スレッドローカル変数に関連するデータは、特定のセクションに格納されます。

- **`__DATA.__thread_vars`**: スレッドローカル変数の型や初期化状態などのメタデータを格納します。
- **`__DATA.__thread_bss`**: 明示的に初期化されていないスレッドローカル変数に使用されます。ゼロ初期化データ用に確保されたメモリ領域の一部です。

Mach-Oには、スレッド終了時にスレッドローカル変数を管理するための専用API **`tlv_atexit`** もあります。このAPIを使うと、スレッド終了時にスレッドローカルデータをクリーンアップする特殊な関数である**デストラクタを登録**できます。

### スレッドの優先度

スレッドの優先度を理解するには、オペレーティングシステムがどのスレッドをいつ実行するかを決定する仕組みを知る必要があります。この決定は、各スレッドに割り当てられた優先度レベルの影響を受けます。macOSやUnix系システムでは、`nice`、`renice`、Quality of Service（QoS）クラスなどの概念を使って優先度を制御します。

#### NiceとRenice

1. **Nice:**
   - プロセスの`nice`値は、優先度に影響する数値です。各プロセスは-20（最高優先度）から19（最低優先度）までの値を持ちます。プロセス作成時のデフォルト値は通常0です。
   - `nice`値が低い（-20に近い）ほど、プロセスはより「自己中心的」になり、`nice`値の高い他のプロセスよりも多くのCPU時間を割り当てられます。
2. **Renice:**
   - `renice`は、実行中のプロセスの`nice`値を変更するコマンドです。新しい`nice`値に応じてCPU時間の割り当てを増減し、プロセスの優先度を動的に調整できます。
   - たとえば、プロセスが一時的に多くのCPUリソースを必要とする場合、`renice`を使って`nice`値を下げることができます。

#### Quality of Service（QoS）クラス

QoSクラスは、特に**Grand Central Dispatch（GCD）**をサポートするmacOSなどのシステムで、スレッドの優先度を管理するためのより新しい方法です。QoSクラスを使うと、開発者は作業を重要度や緊急度に応じたレベルに**分類**できます。macOSはQoSクラスに基づいてスレッドの優先度を自動的に管理します。

1. **User Interactive:**
   - ユーザーと現在やり取りしているタスクや、良好なユーザー体験のために即座に結果を必要とするタスク向けのクラスです。インターフェースの応答性を保つため、これらのタスクには最も高い優先度が与えられます（アニメーションやイベント処理など）。
2. **User Initiated:**
   - ドキュメントを開く、計算を必要とするボタンをクリックするなど、ユーザーが開始し、すぐに結果を期待するタスク向けです。優先度は高いものの、User Interactiveよりは低くなります。
3. **Utility:**
   - 長時間実行され、通常は進捗状況を表示するタスク向けです（ファイルのダウンロードやデータのインポートなど）。User Initiatedのタスクより優先度は低く、すぐに完了する必要はありません。
4. **Background:**
   - バックグラウンドで動作し、ユーザーから見えないタスク向けのクラスです。インデックス作成、同期、バックアップなどが該当します。優先度は最も低く、システムパフォーマンスへの影響も最小限です。

QoSクラスを使うと、開発者は具体的な優先度の数値を管理する必要がなく、タスクの性質に集中できます。システムはそれに応じてCPUリソースを最適化します。

また、スケジューラが考慮する一連のスケジューリングパラメータを指定する、さまざまな**スレッドスケジューリングポリシー**もあります。これは`thread_policy_[set/get]`を使って設定できます。レースコンディション攻撃で役立つ場合があります。

## macOSのプロセス悪用

macOSには、**プロセスが相互にやり取りし、通信し、データを共有する**ための仕組みが数多くあります。これらは通常のシステム動作に不可欠ですが、攻撃者はインジェクション、コード実行、データアクセスに悪用できます。

### Library Injection

Library Injectionは、攻撃者が**プロセスに悪意のあるライブラリを強制的に読み込ませる**手法です。インジェクションされたライブラリは標的プロセスのコンテキスト内で実行され、攻撃者はそのプロセスと同じ権限およびアクセス権を得ます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hookingは、ソフトウェアコード内の**関数呼び出しやメッセージを傍受する**手法です。関数をフックすると、攻撃者はプロセスの**動作を変更**したり、機密データを監視したり、実行フローを制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### Inter Process Communication

Inter Process Communication（IPC）とは、別々のプロセスが**データを共有し、やり取りする**ためのさまざまな方法を指します。IPCは多くの正当なアプリケーションに不可欠ですが、プロセス分離の回避、機密情報のleak、不正な操作にも悪用される可能性があります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定の環境変数を指定して実行されるElectronアプリケーションは、プロセスインジェクションに対して脆弱な場合があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

フラグ`--load-extension`と`--use-fake-ui-for-media-stream`を使うと、**man in the browser攻撃**を実行できます。これにより、キーストロークや通信、Cookieの窃取、ページへのスクリプトインジェクションなどが可能になります。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIBファイルは、アプリケーション内の**ユーザーインターフェース（UI）要素とその操作を定義します**。しかし、任意のコマンドを**実行できる**うえ、**NIBファイルが変更されても、Gatekeeperは一度実行されたアプリケーションの再実行を阻止しません**。そのため、任意のプログラムに任意のコマンドを実行させる用途に悪用できます。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

アプリケーションの起動前に、**`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`**、**`JDK_JAVA_OPTIONS`**を通じてJVMオプションをインジェクションし、Javaエージェントまたはネイティブエージェントを読み込ませることができます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**は、`--require`（ファイル）または`--import data:text/javascript,…`（ファイルレス、Node ≥ 20.6）を使って攻撃者のJavaScriptを事前読み込みします。**`NODE_REPL_EXTERNAL_MODULE`**はインタラクティブなREPLにモジュールを読み込み、**`ELECTRON_RUN_AS_NODE`**はElectronバイナリでこれらすべてを再び有効にします。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main`の実行前に**`DOTNET_STARTUP_HOOKS`**を使うか、前提条件が満たされている場合に.NETのデバッグ機能を悪用することで、.NETアプリケーションにコードをインジェクションできます。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非対話型Bashは**`BASH_ENV`**を読み込みます。対話型POSIXシェルは**`ENV`**を読み込み、zshは**`$ZDOTDIR/.zshenv`**を読み込み、fishは**`XDG_CONFIG_HOME`**または**`XDG_DATA_DIRS`**以下の設定を読み込みます。いずれも、制御された起動ファイルを意図されたコマンドの前に実行できます。またBashでは、xtraceが有効なとき（継承された**`SHELLOPTS=xtrace`**など）、**`PS4`**に設定されたコマンド置換が実行されます。

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### PHP Injection

**`PHPRC`**または**`PHP_INI_SCAN_DIR`**を使うと、制御されたPHP設定を読み込ませることができます。その設定の**`auto_prepend_file`**は、標的スクリプトの実行前に実行されます。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

スタンドアロンのLuaインタープリターは、標的スクリプトを処理する前に、**`LUA_INIT`**（またはバージョン固有の変数）で指定されたコードまたは`@file`を実行します。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`**と**`R_PROFILE`**を使うと、Rコードを含む起動プロファイルの読み込み先を変更できます。代わりに、**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**とRライブラリパスを使って、インストール済みパッケージを自動読み込みすることもできます。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**を使うと、`config/startup.jl`が自動実行されるデポの参照先を変更できます。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`**、**`ERL_ZFLAGS`**を使うと、ペイロードファイルを必要とせずに、Erlang VMの**`-eval`**式をインジェクションできます。Elixirのワークロードも、一般に同じVMを起動します。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`**と**`OCTAVE_VERSION_INITFILE`**を使うと、Octaveの起動スクリプトの参照先を変更できます。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh`はクロスプラットフォームの.NETアプリケーションであるため、複数の環境変数を使ってコマンド実行前にコードを実行できます。**`XDG_CONFIG_HOME`**は起動時に実行されるプロファイルスクリプトの参照先を変更します。**`PSModulePath`**はモジュールの自動読み込みを乗っ取り（仕込んだ`.psm1`はインポート時に実行され、組み込みコマンドレットをシャドウできます）、.NETの**`CORECLR_PROFILER`**/**`COR_PROFILER`**および**`DOTNET_STARTUP_HOOKS`**は、`Main`の実行前に攻撃者のコードをプロセスに読み込みます。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perlスクリプトで任意のコードを実行させる方法について、以下でさまざまなオプションを確認してください。


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Rubyの環境変数（**`RUBYOPT`**、**`RUBYLIB`**）を悪用して、任意のスクリプトに任意のコードを実行させることもできます。


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

標準ライブラリの**`PYTHONWARNINGS`**と**`BROWSER`**を連鎖させると、警告フィルターの解析中にコマンドを実行できます。ファイルを使う方法では、**`PYTHONPATH`**上に`sitecustomize.py`を配置すると、通常の`site`初期化時に標的スクリプトより先にインポートされます。**`PYTHONBREAKPOINT`**は、コードが`breakpoint()`に到達したときに、指定した呼び出し可能オブジェクトまたはモジュールを実行します。**`PYTHONSTARTUP`**などの対話型環境専用の変数は、利用できる場面が限られます。

**`pyinstaller`**でコンパイルされた実行ファイルは、埋め込みPythonを使って実行されていても、これらの環境変数を使用しない点に注意してください。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`**（および代替の`EXINIT`）は通常の起動時にExコマンドとして実行されます。そのため、被害者が制御された環境でVim/Neovimを開くと、`:!cmd` / `:call system(...)`によってコードを実行できます。

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

これとは別に、HomebrewはPythonを`/opt/homebrew`以下にインストールすることが多く、ローカルの`admin`グループのメンバーがランチャーを置き換えられる場合があります。これは環境変数のインジェクションではなく、書き込み可能なバイナリの乗っ取りです。悪用可能と判断する前に、所有者とACLを確認してください。


## 検出

### Shield

[**Shield**](https://github.com/theevilbit/Shield)は、プロセスインジェクションを検出してブロックする、**EndpointSecurity**ベースのオープンソースアプリケーションです。Endpoint Securityを通じて観測可能なシグナルを知るうえで参考になります。次のイベントを警告するためです。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- プロセス実行時の**インジェクション用環境変数**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`**呼び出し。あるプロセスが別のプロセスのタスクポートを要求するもので、対象へのインジェクションに必要な前提条件です。
- **Electronのデバッグ引数**: `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらはElectronアプリをデバッグモードで起動し、誰でも接続してコードを実行できるようにします。<sup>[[3]](#references)</sup>
- **異なる権限レベル間でのシンボリックリンク／ハードリンクの作成**。通常ユーザーがリンクを仕掛け、特権のある場所を参照させる典型的な手法です。なお、**シンボリックリンクは検出して警告できますが、ブロックはできません**。EndpointSecurityは、リンクが作成される前にリンク先を取得できないためです。

### 他のプロセスによる呼び出し

[**こちらのブログ記事**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、関数**`task_name_for_pid`**を使って、他の**プロセスにコードをインジェクションしているプロセス**の情報を取得し、さらにそのプロセスに関する情報を得る方法を紹介しています。<sup>[[4]](#references)</sup>

この関数を呼び出すには、対象プロセスの実行ユーザーと**同じuid**であるか、**root**である必要があります（返されるのはプロセスに関する情報であり、コードをインジェクションする方法ではありません）。

## References

- [1] [Shield — macOSのオープンソースプロセスインジェクション検出ツール（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurityフレームワーク](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electronアプリが秘密情報を機密に保管できない理由: --inspectオプション](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - taskの変更を検出する](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
{{#include ../../../banners/hacktricks-training.md}}
