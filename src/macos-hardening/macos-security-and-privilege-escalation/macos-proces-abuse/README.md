# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## プロセスの基本情報

プロセスは実行中の実行ファイルのインスタンスですが、コードを実行するのはプロセスではなくスレッドです。つまり、**プロセスは実行中のスレッドのコンテナにすぎず**、メモリ、ファイルディスクリプタ、ポート、権限などを提供します。

従来、プロセスは（PID 1を除き）他のプロセス内で **`fork`** を呼び出して起動されていました。これにより現在のプロセスの完全なコピーが作成され、その後、通常は **子プロセス** が **`execve`** を呼び出して新しい実行ファイルを読み込み、実行していました。その後、メモリのコピーなしでこの処理を高速化するために **`vfork`** が導入されました。\
続いて、**`vfork`** と **`execve`** を1回の呼び出しにまとめ、フラグを指定できる **`posix_spawn`** が導入されました。

- `POSIX_SPAWN_RESETIDS`: 実効IDを実IDにリセット
- `POSIX_SPAWN_SETPGROUP`: プロセスグループへの所属を設定
- `POSUX_SPAWN_SETSIGDEF`: シグナルのデフォルト動作を設定
- `POSIX_SPAWN_SETSIGMASK`: シグナルマスクを設定
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内でExecを実行（オプションを追加した `execve` のようなもの）
- `POSIX_SPAWN_START_SUSPENDED`: 一時停止状態で起動
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLRなしで起動
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmallocのNano allocatorを使用
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` データセグメントで `rwx` を許可
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトでexec(2)時にすべてのファイル記述子を閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLRスライドの上位ビットをランダム化

さらに、`posix_spawn` は、生成されるプロセスの動作を制御する **`posix_spawnattr`** 設定と、ファイルディスクリプタを変更する **`posix_spawn_file_actions`** エントリを受け取ります。

プロセスが終了すると、シグナル `SIGCHLD` とともに **終了コードを親プロセスに送信** します（親プロセスが終了している場合、新しい親はPID 1です）。親プロセスは `wait4()` または `waitid()` を呼び出してこの値を取得する必要があります。それまで子プロセスはゾンビ状態にあり、一覧には表示されますが、リソースは消費しません。

### PIDs

PID（プロセス識別子）は、一意のプロセスを識別します。XNUでは **PID** は **64ビット**で、単調に増加し、（悪用を防ぐため）**折り返しません**。

### プロセスグループ、セッション、Coalations

**プロセス** は、管理しやすくするために **グループ** にまとめることができます。たとえば、シェルスクリプト内のコマンドは同じプロセスグループに属するため、killなどを使って**まとめてシグナルを送信**できます。\
プロセスを **セッション** にまとめることもできます。プロセスがセッションを開始すると（`setsid(2)`）、独自のセッションを開始しない限り、その子プロセスは同じセッションに属します。

Coalitionは、Darwinでプロセスをグループ化するもう1つの方法です。プロセスがcoalationに参加すると、リソースプールにアクセスし、台帳を共有したり、Jetsamの対象になったりします。Coalationには、Leader、XPC service、Extensionという異なる役割があります。

### CredentialsとPersonae

各プロセスは、システム上の**権限を特定する** **credentials** を保持します。各プロセスにはプライマリ `uid` とプライマリ `gid` が1つずつあります（ただし、複数のグループに属する場合があります）。\
バイナリに `setuid/setgid` ビットが設定されている場合、ユーザーIDとグループIDを変更することもできます。\
**新しいuid/gidを設定する**関数はいくつかあります。

システムコール **`persona`** は、**代替の** **credentials** セットを提供します。personaを採用すると、そのuid、gid、グループメンバーシップが**一度に**適用されます。[**ソースコード**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)では、次の構造体を確認できます。

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

1. **POSIX Threads (pthreads):** macOS は POSIX スレッド（`pthreads`）をサポートしています。これは C/C++ 向けの標準スレッド API の一部です。macOS における pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、一般公開されている `libpthread` プロジェクトに由来します。このライブラリは、スレッドの作成と管理に必要な関数を提供します。
2. **スレッドの作成:** 新しいスレッドの作成には `pthread_create()` 関数を使用します。この関数は内部で、XNU カーネル（macOS の基盤となるカーネル）固有の下位レベルのシステムコールである `bsdthread_create()` を呼び出します。このシステムコールは、スレッドの動作（スケジューリングポリシーやスタックサイズなど）を指定する、`pthread_attr`（属性）に由来する各種フラグを受け取ります。
   - **デフォルトのスタックサイズ:** 新しいスレッドのデフォルトのスタックサイズは 512 KB です。一般的な操作には十分なサイズですが、必要に応じてスレッド属性で増減できます。
3. **スレッドの初期化:** `__pthread_init()` 関数はスレッドのセットアップで重要な役割を果たします。`env[]` 引数を使用して環境変数を解析し、スタックの位置やサイズなどの情報を取得できます。

#### macOS におけるスレッドの終了

1. **スレッドの終了:** 通常、スレッドは `pthread_exit()` を呼び出して終了します。この関数を使うと、スレッドは適切なクリーンアップを行って終了し、join するスレッドに戻り値を渡せます。
2. **スレッドのクリーンアップ:** `pthread_exit()` を呼び出すと、関連するすべてのスレッド構造体の削除を処理する `pthread_terminate()` が呼び出されます。この関数は Mach スレッドポート（Mach は XNU カーネルの通信サブシステム）の割り当てを解除し、スレッドに関連付けられたカーネルレベルの構造体を削除するシステムコール `bsdthread_terminate` を呼び出します。

#### 同期メカニズム

共有リソースへのアクセスを管理し、競合状態を防ぐために、macOS はいくつかの同期プリミティブを提供しています。これらは、データの整合性とシステムの安定性を確保するうえで、マルチスレッド環境に欠かせません。

1. **Mutex:**
   - **通常の Mutex（シグネチャ: 0x4D555458）:** メモリサイズは 60 バイト（Mutex に 56 バイト、シグネチャに 4 バイト）です。
   - **Fast Mutex（シグネチャ: 0x4d55545A）:** 通常の Mutex と似ていますが、より高速な操作向けに最適化されており、サイズも 60 バイトです。
2. **Condition Variable:**
   - 特定の条件が満たされるのを待つために使用され、サイズは 44 バイト（40 バイトと 4 バイトのシグネチャ）です。
   - **Condition Variable Attributes（シグネチャ: 0x434e4441）:** Condition Variable の設定属性で、サイズは 12 バイトです。
3. **Once Variable（シグネチャ: 0x4f4e4345）:**
   - 初期化コードを一度だけ実行するために使用されます。サイズは 12 バイトです。
4. **Read-Write Lock:**
   - 複数の読み取り側、または一度に 1 つの書き込み側がロックを取得できるようにし、共有データへの効率的なアクセスを可能にします。
   - **Read Write Lock（シグネチャ: 0x52574c4b）:** サイズは 196 バイトです。
   - **Read Write Lock Attributes（シグネチャ: 0x52574c41）:** Read-Write Lock の属性で、サイズは 20 バイトです。

> [!TIP]
> これらのオブジェクトの最後の 4 バイトは、オーバーフローの検出に使用されます。

### Thread Local Variables (TLV)

Mach-O ファイル（macOS の実行ファイル形式）における **Thread Local Variables (TLV)** は、マルチスレッドアプリケーション内で**各スレッドに固有の**変数を宣言するために使用されます。これにより、各スレッドが変数の独立したインスタンスを持てるため、Mutex のような明示的な同期メカニズムを使わずに、競合を避けてデータの整合性を保てます。

C や関連言語では、**`__thread`** キーワードを使用してスレッドローカル変数を宣言できます。例のコードでは、次のように動作します。

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

このスニペットでは、`tlv_var`をスレッドローカル変数として定義しています。このコードを実行する各スレッドは、それぞれ独自の`tlv_var`を持ち、あるスレッドによる`tlv_var`の変更は、別のスレッドの`tlv_var`には影響しません。

Mach-Oバイナリでは、スレッドローカル変数に関連するデータは、特定のセクションに整理されています。

- **`__DATA.__thread_vars`**: スレッドローカル変数の型や初期化状態などのメタデータを格納します。
- **`__DATA.__thread_bss`**: 明示的に初期化されていないスレッドローカル変数に使用されます。ゼロ初期化データ用に確保されたメモリ領域です。

Mach-Oには、スレッド終了時にスレッドローカル変数を管理するための専用API **`tlv_atexit`** も用意されています。このAPIでは、**デストラクタを登録**できます。デストラクタは、スレッド終了時にスレッドローカルデータをクリーンアップする特別な関数です。

### スレッドの優先度

スレッドの優先度を理解するには、オペレーティングシステムがどのスレッドをいつ実行するかを決定する方法を確認する必要があります。この判断には、各スレッドに割り当てられた優先度が影響します。macOSやUnix系システムでは、`nice`、`renice`、Quality of Service（QoS）クラスなどの概念を使ってこれを処理します。

#### NiceとRenice

1. **Nice:**
   - プロセスの`nice`値は、優先度に影響する数値です。各プロセスの`nice`値は-20（最高優先度）から19（最低優先度）の範囲で、プロセス作成時のデフォルト値は通常0です。
   - `nice`値が低い（-20に近い）ほど、プロセスはより「自分本位」になり、`nice`値が高い他のプロセスよりも多くのCPU時間を得ます。
2. **Renice:**
   - `renice`は、実行中のプロセスの`nice`値を変更するコマンドです。新しい`nice`値に基づいてCPU時間の割り当てを増減させ、プロセスの優先度を動的に調整できます。
   - たとえば、プロセスが一時的により多くのCPUリソースを必要とする場合、`renice`で`nice`値を下げます。

#### Quality of Service（QoS）クラス

QoSクラスは、特に**Grand Central Dispatch（GCD）**に対応するmacOSのようなシステムで使われる、より現代的なスレッド優先度の管理方法です。QoSクラスを使うと、開発者は作業の重要度や緊急度に応じて、さまざまなレベルに**分類**できます。macOSは、これらのQoSクラスに基づいてスレッドの優先度を自動的に管理します。

1. **User Interactive:**
   - ユーザーと現在やり取りしている、または良好なユーザー体験のために即時の結果が必要なタスク向けのクラスです。インターフェースの応答性を保つため、最も高い優先度が割り当てられます（例: アニメーションやイベント処理）。
2. **User Initiated:**
   - ドキュメントを開く、計算が必要なボタンをクリックするなど、ユーザーが開始し、すぐに結果を期待するタスク向けです。優先度は高いものの、User Interactiveよりは低くなります。
3. **Utility:**
   - 長時間実行され、通常は進捗インジケーターを表示するタスク向けです（例: ファイルのダウンロードやデータのインポート）。ユーザーが開始したタスクより優先度は低く、すぐに完了する必要はありません。
4. **Background:**
   - バックグラウンドで動作し、ユーザーには見えないタスク向けです。インデックス作成、同期、バックアップなどが該当します。優先度は最も低く、システムパフォーマンスへの影響も最小限です。

QoSクラスを使えば、開発者は具体的な優先度の数値を管理する必要がなく、タスクの性質に集中できます。システムがそれに応じてCPUリソースを最適化します。

さらに、スケジューラが考慮するスケジューリングパラメータを指定する、さまざまな**スレッドスケジューリングポリシー**があります。これは`thread_policy_[set/get]`を使って設定できます。Race Condition攻撃で役立つ場合があります。

## macOSプロセスの悪用

macOSには、**プロセス間のやり取り、通信、データ共有**のための仕組みが数多くあります。これらは通常のシステム動作に不可欠ですが、攻撃者がインジェクション、コード実行、データアクセスに悪用する可能性があります。

### Library Injection

Library Injectionは、攻撃者が**プロセスに悪意のあるライブラリを強制的に読み込ませる**手法です。インジェクションされたライブラリは標的プロセスのコンテキスト内で動作するため、攻撃者はそのプロセスと同じ権限やアクセス権を得られます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hookingでは、ソフトウェアコード内の関数呼び出しやメッセージを**傍受**します。関数をフックすることで、攻撃者はプロセスの**動作を変更**したり、機密データを監視したり、実行フローを制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

このページでは、ARM64のunwindメタデータ、arm64eのPAC制約、および合成コールチェーンについて説明します。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### プロセス間通信

プロセス間通信（IPC）とは、別々のプロセスが**データを共有し、やり取りする**ためのさまざまな方法を指します。IPCは多くの正当なアプリケーションに不可欠ですが、プロセス分離の回避、機密情報のleak、不正な操作にも悪用される可能性があります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electronアプリケーションのインジェクション

特定の環境変数を設定して実行されたElectronアプリケーションは、プロセスインジェクションに対して脆弱な場合があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

フラグ`--load-extension`と`--use-fake-ui-for-media-stream`を使って、キーストロークやトラフィック、cookieの窃取、ページへのスクリプトインジェクションなどを可能にする**man in the browser攻撃**を実行できます。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIBファイルは、アプリケーション内の**ユーザーインターフェース（UI）要素**とその相互作用を定義します。しかし、**任意のコマンドを実行できる**うえ、**NIBファイルが変更されても、Gatekeeperは一度実行されたアプリケーションの再実行を阻止しません**。そのため、任意のプログラムに任意のコマンドを実行させるために悪用される可能性があります。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Javaアプリケーションのインジェクション

**`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`**、または**`JDK_JAVA_OPTIONS`**を通じてJVMオプションをインジェクションし、アプリケーションの起動前にJava agentやnative agentを読み込ませることができます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**は、`--require`（ファイル）または`--import data:text/javascript,…`（ファイルレス、Node ≥ 20.6）を使って攻撃者のJavaScriptを事前読み込みします。**`NODE_REPL_EXTERNAL_MODULE`**は対話型REPLにモジュールを読み込み、**`ELECTRON_RUN_AS_NODE`**はElectronバイナリ上でこれらすべてを再び有効にします。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Netアプリケーションのインジェクション

`Main`の実行前に**`DOTNET_STARTUP_HOOKS`**を使う方法や、前提条件が満たされている場合に.NETのデバッグ機能を悪用する方法で、.NETアプリケーションにコードをインジェクションできます。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非対話型Bashは**`BASH_ENV`**を読み込み、対話型POSIXシェルは**`ENV`**を読み込みます。zshは**`$ZDOTDIR/.zshenv`**を読み込み、fishは**`XDG_CONFIG_HOME`**または**`XDG_DATA_DIRS`**以下の設定を読み込みます。いずれも、指定した起動ファイルを意図したコマンドの前に実行できます。また、xtraceが有効なとき（例: **`SHELLOPTS=xtrace`**が継承された場合）、Bashは**`PS4`**に設定されたコマンド置換も実行します。

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s`を起動すると、シェルは標準入力からプログラムを読み込みます。そのため、信頼できない構造化ドキュメントを解析せずに子プロセスのstdinへコピーするダウンローダーは、ドキュメント全体をシェルのソースコードにしてしまいます。あるローダーでは、公開されているiCalendarファイルが匿名パイプを通じて1行ずつ渡されていました。カレンダーのメタデータはコマンドとして失敗しましたが、zshは処理を続け、`DESCRIPTION:`の後に置かれた実行可能な行に到達しました。それらの行が次のアプリケーションバンドルをダウンロードして起動しました。コンテンツタイプが想定どおりでホスティング元が信頼できても、安全とは限りません。危険な境界は、そのデータをインタプリタに渡したことです。<sup>[[5]](#references)</sup>

関連する段階については、[Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)、[Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md)、[macOS auto-start locations](../../macos-auto-start-locations.md)を参照してください。

### PHP Injection

**`PHPRC`**または**`PHP_INI_SCAN_DIR`**を使うと、制御可能なPHP設定を読み込ませ、その中の**`auto_prepend_file`**によって標的スクリプトの実行前にコードを実行できます。

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

スタンドアロンのLuaインタプリタは、標的スクリプトを処理する前に**`LUA_INIT`**（またはバージョン固有の変数）からコードや`@file`を実行します。

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`**と**`R_PROFILE`**を使うと、Rコードを含む起動プロファイルの読み込み先を変更できます。**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`**とRライブラリパスを組み合わせれば、インストール済みパッケージを自動的に読み込ませることもできます。

[R startup profiles and package loading](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`**を使うと、`config/startup.jl`が自動実行されるdepotの場所を変更できます。

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`**、または**`ERL_ZFLAGS`**を使うと、payloadファイルなしでErlang VMの**`-eval`**式をインジェクションできます。Elixirのワークロードも通常、同じVMを起動します。

[Erlang/Elixir VM flag injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`**と**`OCTAVE_VERSION_INITFILE`**を使うと、Octaveの起動スクリプトの読み込み先を変更できます。

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh`はクロスプラットフォームの.NETアプリであるため、複数の環境変数を使ってコマンド実行前にコードを実行できます。**`XDG_CONFIG_HOME`**は起動時に実行されるプロファイルスクリプトの場所を変更し、**`PSModulePath`**はモジュールの自動読み込みを乗っ取ります（配置した`.psm1`はインポート時に実行され、組み込みcmdletを偽装できます）。また、.NETの**`CORECLR_PROFILER`**/**`COR_PROFILER`**や**`DOTNET_STARTUP_HOOKS`**を使うと、`Main`の実行前に攻撃者のコードをプロセスに読み込ませることができます。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perlスクリプトに任意のコードを実行させるさまざまな方法については、こちらを確認してください。


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Rubyの環境変数（**`RUBYOPT`**、**`RUBYLIB`**）を悪用して、任意のスクリプトに任意のコードを実行させることもできます。


[Ruby `RUBYOPT`/`RUBYLIB` loader options](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

**`PYTHONWARNINGS`**と**`BROWSER`**を組み合わせた標準ライブラリの連鎖により、warning filterの解析中にコマンドを実行できます。ファイルを使う方法では、**`PYTHONPATH`**上に`sitecustomize.py`を配置すると、通常の`site`初期化時に標的スクリプトより前にインポートされます。**`PYTHONBREAKPOINT`**は、コードが`breakpoint()`に到達したときに指定したcallable/moduleを実行します。

CPython 3.13以降では、PyREPLが端末上で起動した際に、スクリプト実行後に**`PYTHONINSPECT`**から**`PYTHONSTARTUP`**ファイルを実行させることもできます。<sup>[[6]](#references)</sup>

**`pyinstaller`**でコンパイルされた実行ファイルは、組み込みPythonを使って実行されていても、これらの環境変数を使用しないことに注意してください。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

通常の起動時には、**`VIMINIT`**（およびその代替となる`EXINIT`）がExコマンドとして実行されます。そのため、被害者が制御された環境でVim/Neovimを開くと、`:!cmd` / `:call system(...)`によってコードを実行できます。

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

これとは別に、HomebrewはPythonを`/opt/homebrew`以下にインストールすることが多く、ローカルの`admin`グループのメンバーがランチャーを置き換えられる場合があります。これは環境変数インジェクションではなく、書き込み可能なバイナリの乗っ取りです。悪用可能と判断する前に、所有者とACLを確認してください。


## 検出

### Shield

[**Shield**](https://github.com/theevilbit/Shield)は、プロセスインジェクションを検出してブロックする、EndpointSecurityベースのオープンソースアプリケーションです。Endpoint Securityで観測できるシグナルを知るうえで参考になります。Shieldは次の動作を検知して警告します。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- プロセスのexec時における**インジェクション用環境変数**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`**呼び出し — あるプロセスが別のプロセスのtask portを要求する操作。これは、そのプロセスにインジェクションするための前提条件です。
- **Electronのデバッグ引数** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。これらはElectronアプリをデバッグモードで起動し、誰でも接続してコードを実行できるようにします。<sup>[[3]](#references)</sup>
- **異なる権限レベルをまたぐsymlink/hardlinkの作成** — 一般ユーザーとしてリンクを作成し、特権のある場所を指すようにする典型的な手法です。ただし、**symlinkは警告対象にはできても、ブロックはできません**。EndpointSecurityは、リンク作成前にリンク先を参照できないためです。

### 他のプロセスが行う呼び出し

[**このブログ記事**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、関数**`task_name_for_pid`**を使って、あるプロセスにコードをインジェクションしている別の**プロセス**に関する情報と、そのプロセス自体の情報を取得する方法が紹介されています。<sup>[[4]](#references)</sup>

この関数を呼び出すには、対象プロセスを実行しているユーザーと**同じuid**であるか、**root**である必要があります（返されるのはプロセスに関する情報であり、コードをインジェクションする方法ではありません）。



## References

- [1] [Shield — オープンソースのmacOSプロセスインジェクション検出ツール（GitHub）](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurityフレームワーク](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electronアプリが秘密情報を機密に保管できない理由: --inspectオプション](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task modificationの検出](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealerの新バージョンが暗号資産愛好家と開発者を標的に](https://securelist.com/macsync-new-version/121383/)
- [6] [Pythonのコマンドラインと環境変数 — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
