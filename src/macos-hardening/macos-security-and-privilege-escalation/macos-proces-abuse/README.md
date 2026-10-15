# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## プロセスの基本情報

プロセスは、実行中の実行可能ファイルのインスタンスです。ただし、コードを実行するのはプロセスではなくスレッドです。したがって、**プロセスはスレッドを実行するためのコンテナにすぎず**、メモリ、ファイルディスクリプタ、ポート、権限などを提供します。

従来、プロセスは（PID 1 を除き）**`fork`** を呼び出して別のプロセス内で開始されていました。これにより現在のプロセスの完全なコピーが作成され、その後、一般に**子プロセス**が **`execve`** を呼び出して新しい実行可能ファイルを読み込み、実行していました。次に、メモリをコピーせずにこの処理を高速化するため、**`vfork`** が導入されました。\
その後、**`vfork`** と **`execve`** を1回の呼び出しにまとめ、フラグを受け取る **`posix_spawn`** が導入されました。

- `POSIX_SPAWN_RESETIDS`: 実効 ID を実 ID にリセットする
- `POSIX_SPAWN_SETPGROUP`: プロセスグループへの所属を設定する
- `POSUX_SPAWN_SETSIGDEF`: シグナルのデフォルト動作を設定する
- `POSIX_SPAWN_SETSIGMASK`: シグナルマスクを設定する
- `POSIX_SPAWN_SETEXEC`: 同じプロセス内で exec する（オプションを追加した `execve` のようなもの）
- `POSIX_SPAWN_START_SUSPENDED`: 停止状態で起動する
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR を無効にして起動する
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc の Nano allocator を使用する
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` データセグメントで `rwx` を許可する
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: デフォルトで exec(2) 時にすべてのファイルディスクリプタを閉じる
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR スライドの上位ビットをランダム化する

さらに、`posix_spawn` は、生成されるプロセスの動作を制御する **`posix_spawnattr`** 設定と、ファイルディスクリプタを変更する **`posix_spawn_file_actions`** エントリを受け取ります。

プロセスが終了すると、シグナル `SIGCHLD` を使って**終了コードを親プロセスに送信**します（親が終了している場合、新しい親は PID 1 です）。親は `wait4()` または `waitid()` を呼び出してこの値を取得する必要があります。それまで子プロセスはゾンビ状態で残り、一覧には表示されますが、リソースは消費しません。

### PIDs

PID（プロセス識別子）は、一意のプロセスを識別します。XNU では **PID** は **64ビット**で、単調に増加し、（悪用を防ぐため）**ラップアラウンドしません**。

### プロセスグループ、セッション、Coalations

**プロセス**は、管理を容易にするために**グループ**にまとめることができます。たとえば、シェルスクリプト内のコマンドは同じプロセスグループに属するため、たとえば kill を使って**まとめてシグナルを送信**できます。\
プロセスを**セッションにまとめる**こともできます。プロセスがセッションを開始すると（`setsid(2)`）、独自のセッションを開始しない限り、その子プロセスはそのセッションに属します。

Coalition は、Darwin でプロセスをグループ化するもう1つの方法です。プロセスが Coalition に参加すると、リソースプールにアクセスできるようになり、ledger を共有したり、Jetsam の対象になったりします。Coalition には、Leader、XPC service、Extension という異なる役割があります。

### Credentials と Personae

各プロセスは、システム上の**権限を特定する** **credentials** を保持します。各プロセスには1つのプライマリ `uid` と1つのプライマリ `gid` があります（ただし、複数のグループに所属する場合があります）。\
バイナリに `setuid/setgid` ビットが設定されている場合、ユーザー ID とグループ ID を変更することもできます。\
**新しい uid/gid を設定する**ための関数はいくつかあります。

システムコール **`persona`** は、**代替の** **credentials** セットを提供します。persona を採用すると、その uid、gid、グループ所属が**同時に**適用されます。[**ソースコード**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h)では、次の構造体を確認できます。

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

1. **POSIX Threads (pthreads):** macOS は POSIX スレッド（`pthreads`）をサポートしています。これは C/C++ 用の標準スレッド API の一部です。macOS における pthreads の実装は `/usr/lib/system/libsystem_pthread.dylib` にあり、公開されている `libpthread` プロジェクトに由来します。このライブラリは、スレッドの作成と管理に必要な関数を提供します。
2. **スレッドの作成:** `pthread_create()` 関数は新しいスレッドを作成するために使用されます。内部では、この関数は `bsdthread_create()` を呼び出します。これは、macOS の基盤となる XNU カーネル固有の低レベルシステムコールです。このシステムコールは、スケジューリングポリシーやスタックサイズなど、スレッドの動作を指定する `pthread_attr`（属性）に由来するさまざまなフラグを受け取ります。
   - **デフォルトのスタックサイズ:** 新しいスレッドのデフォルトのスタックサイズは 512 KB です。一般的な処理には十分なサイズですが、必要に応じてスレッド属性で増減できます。
3. **スレッドの初期化:** `__pthread_init()` 関数はスレッドのセットアップ時に重要な役割を果たし、`env[]` 引数を使用して、スタックの位置やサイズなどの情報を含む環境変数を解析します。

#### macOS でのスレッドの終了

1. **スレッドの終了:** 通常、スレッドは `pthread_exit()` を呼び出して終了します。この関数を使うとスレッドを正常に終了でき、必要なクリーンアップを実行し、join するスレッドに戻り値を返せます。
2. **スレッドのクリーンアップ:** `pthread_exit()` を呼び出すと、`pthread_terminate()` 関数が実行され、関連するすべてのスレッド構造体を削除します。Mach スレッドポート（Mach は XNU カーネルの通信サブシステム）を解放し、スレッドに関連するカーネルレベルの構造体を削除する syscall である `bsdthread_terminate` を呼び出します。

#### 同期メカニズム

共有リソースへのアクセスを管理し、競合状態を防ぐため、macOS は複数の同期プリミティブを提供しています。これらは、データの整合性とシステムの安定性を確保するうえで、マルチスレッド環境において重要です。

1. **Mutex:**
   - **通常の Mutex（シグネチャ: 0x4D555458）:** 標準的な Mutex で、メモリ使用量は 60 バイト（Mutex に 56 バイト、シグネチャに 4 バイト）です。
   - **Fast Mutex（シグネチャ: 0x4d55545A）:** 通常の Mutex と同様ですが、処理が高速になるよう最適化されており、サイズも 60 バイトです。
2. **Condition Variables:**
   - 特定の条件が発生するまで待機するために使用され、サイズは 44 バイト（40 バイトと 4 バイトのシグネチャ）です。
   - **Condition Variable Attributes（シグネチャ: 0x434e4441）:** Condition Variables の設定属性で、サイズは 12 バイトです。
3. **Once Variable（シグネチャ: 0x4f4e4345）:**
   - 初期化コードを一度だけ実行することを保証します。サイズは 12 バイトです。
4. **Read-Write Locks:**
   - 複数の読み取り側、または一度に 1 つの書き込み側を許可し、共有データへの効率的なアクセスを実現します。
   - **Read Write Lock（シグネチャ: 0x52574c4b）:** サイズは 196 バイトです。
   - **Read Write Lock Attributes（シグネチャ: 0x52574c41）:** Read-Write Locks の属性で、サイズは 20 バイトです。

> [!TIP]
> これらのオブジェクトの最後の 4 バイトは、オーバーフローの検出に使用されます。

### スレッドローカル変数 (TLV)

Mach-O ファイル（macOS の実行ファイル形式）における **スレッドローカル変数 (TLV)** は、マルチスレッドアプリケーションで**各スレッド専用**の変数を宣言するために使用されます。これにより、各スレッドは変数の独立したインスタンスを持てるため、Mutex などの明示的な同期メカニズムを使わずに競合を回避し、データの整合性を維持できます。

C および関連言語では、**`__thread`** キーワードを使用してスレッドローカル変数を宣言できます。以下の例では、次のように動作します。

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

このスニペットでは、`tlv_var` をスレッドローカル変数として定義しています。このコードを実行する各スレッドは、それぞれ独自の `tlv_var` を持ち、あるスレッドによる `tlv_var` の変更が別のスレッドの `tlv_var` に影響することはありません。

Mach-O バイナリでは、スレッドローカル変数に関連するデータは、次の専用セクションに格納されます。

- **`__DATA.__thread_vars`**: スレッドローカル変数の型や初期化状態などのメタデータを格納します。
- **`__DATA.__thread_bss`**: 明示的に初期化されていないスレッドローカル変数に使用されます。ゼロ初期化データ用に確保されたメモリ領域の一部です。

Mach-O には、スレッド終了時にスレッドローカル変数を管理するための専用 API **`tlv_atexit`** もあります。この API では、スレッドの終了時にスレッドローカルデータをクリーンアップする特別な関数である**デストラクタを登録**できます。

### スレッドの優先度

スレッドの優先度を理解するには、オペレーティングシステムがどのスレッドをいつ実行するか決める仕組みを確認する必要があります。この判断は、各スレッドに割り当てられた優先度レベルに左右されます。macOS や Unix 系システムでは、`nice`、`renice`、Quality of Service (QoS) クラスなどの概念を使って優先度を管理します。

#### Nice と Renice

1. **Nice:**
   - プロセスの `nice` 値は、優先度に影響する数値です。各プロセスは -20（最も高い優先度）から 19（最も低い優先度）までの値を持ちます。プロセス作成時のデフォルト値は通常 0 です。
   - `nice` 値が低い（-20 に近い）ほど、プロセスはより「自己中心的」に動作し、`nice` 値が高い他のプロセスより多くの CPU 時間を割り当てられます。
2. **Renice:**
   - `renice` は、実行中のプロセスの `nice` 値を変更するコマンドです。新しい `nice` 値に基づいて CPU 時間の割り当てを増減し、プロセスの優先度を動的に調整できます。
   - たとえば、一時的に多くの CPU リソースが必要なプロセスでは、`renice` を使って `nice` 値を下げることができます。

#### Quality of Service (QoS) クラス

QoS クラスは、特に **Grand Central Dispatch (GCD)** をサポートする macOS などで使われる、より新しいスレッド優先度管理の方式です。QoS クラスを使うと、開発者は作業の重要度や緊急度に応じて、異なるレベルに**分類**できます。macOS は、次の QoS クラスに基づいてスレッドの優先度を自動的に管理します。

1. **User Interactive:**
   - 現在ユーザーとやり取りしているタスクや、良好なユーザー体験のために即座に結果を返す必要があるタスク向けのクラスです。インターフェースの応答性を保つため、最も高い優先度が割り当てられます（例: アニメーションやイベント処理）。
2. **User Initiated:**
   - ドキュメントを開く、計算を伴うボタンをクリックするといった、ユーザーが開始し、すぐに結果を期待するタスク向けです。優先度は高いものの、User Interactive よりは低くなります。
3. **Utility:**
   - 長時間実行され、通常は進捗状況が表示されるタスク向けです（例: ファイルのダウンロード、データのインポート）。User Initiated より優先度は低く、即座に完了する必要はありません。
4. **Background:**
   - バックグラウンドで動作し、ユーザーには見えないタスク向けのクラスです。インデックス作成、同期、バックアップなどが該当します。優先度は最も低く、システムパフォーマンスへの影響も最小限です。

QoS クラスを使うと、開発者は具体的な優先度の数値を管理する代わりに、タスクの性質に集中できます。システムはそれに応じて CPU リソースを最適化します。

また、スケジューラが考慮するスケジューリングパラメータの集合を指定する、さまざまな**スレッドスケジューリングポリシー**もあります。これは `thread_policy_[set/get]` を使って設定できます。race condition attacks に役立つ可能性があります。

## macOS Process Abuse

macOS には、**プロセス間で相互に作用し、通信し、データを共有する**ための仕組みが数多くあります。これらは通常のシステム動作に不可欠ですが、攻撃者が injection、code execution、データアクセスに悪用することもできます。

### Library Injection

Library Injection は、攻撃者が**プロセスに悪意のあるライブラリを強制的に読み込ませる**手法です。注入されたライブラリは標的プロセスのコンテキスト内で実行されるため、攻撃者はそのプロセスと同じ権限やアクセス権を得られます。


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking は、ソフトウェアコード内の関数呼び出しやメッセージを**傍受する**手法です。関数を hook することで、攻撃者はプロセスの**動作を変更**したり、機密データを監視したり、実行フローを制御したりできます。


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

このページでは、ARM64 unwind metadata、arm64e PAC の制約、合成 call chain について説明します。

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC) は、個別のプロセス間で**データを共有・交換する**さまざまな方法を指します。IPC は多くの正規アプリケーションに不可欠ですが、プロセス分離の回避、機密情報の leak、不正な操作にも悪用される可能性があります。


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

特定の環境変数を使って実行された Electron アプリケーションは、process injection に対して脆弱な場合があります。


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` と `--use-fake-ui-for-media-stream` のフラグを使って、**man in the browser attack** を実行できます。これにより、キーストローク、通信、cookie の窃取や、ページへのスクリプト注入などが可能になります。


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB ファイルは、アプリケーション内の**ユーザーインターフェース (UI) 要素とその動作を定義**します。しかし、NIB ファイルは**任意のコマンドを実行でき**、**NIB ファイルが改変されても、Gatekeeper はすでに実行されたアプリケーションの再実行を阻止しません**。そのため、任意のプログラムに任意のコマンドを実行させる目的で悪用される可能性があります。


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**、**`JAVA_TOOL_OPTIONS`**、**`JDK_JAVA_OPTIONS`** を介して JVM オプションを注入し、アプリケーションの起動前に Java agent または native agent を読み込ませることができます。


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`** は `--require`（ファイル）または `--import data:text/javascript,…`（fileless、Node ≥ 20.6）を介して攻撃者の JavaScript を preload します。**`NODE_REPL_EXTERNAL_MODULE`** はインタラクティブな REPL にモジュールを読み込み、**`ELECTRON_RUN_AS_NODE`** は Electron バイナリでこれらの機能を再び有効にします。

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

**`DOTNET_STARTUP_HOOKS`** を使って `Main` の実行前に .NET アプリケーションへコードを注入したり、前提条件が満たされている場合に .NET の debugging 機能を悪用したりできます。


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

非対話型 Bash は **`BASH_ENV`** を読み込みます。対話型 POSIX shell は **`ENV`** を読み込み、zsh は **`$ZDOTDIR/.zshenv`** を読み込み、fish は **`XDG_CONFIG_HOME`** または **`XDG_DATA_DIRS`** 以下の設定を読み込みます。いずれも、意図されたコマンドの前に、制御下の起動ファイルを実行できます。また、xtrace が有効な場合（例: **`SHELLOPTS=xtrace`** が継承されている場合）、Bash は **`PS4`** に指定された command substitution も実行します。

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` を起動すると、shell は標準入力からプログラムを読み込みます。そのため、信頼できない構造化ドキュメントを解析せずに子プロセスの stdin にコピーする downloader は、ドキュメント全体を shell source に変えてしまいます。実際に確認された loader は、公開されている iCalendar ファイルを匿名 pipe 経由で1行ずつ渡していました。カレンダーのメタデータはコマンドとして失敗しましたが、zsh は処理を続け、`DESCRIPTION:` の後に置かれた実行可能な行に到達しました。それらの行は次の application bundle をダウンロードして起動しました。carrier の想定された content type や信頼できるホスティング先が、この処理を安全にするわけではありません。危険な境界は、データを interpreter に渡したことです。<sup>[[5]](#references)</sup>

関連する段階については、[Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md)、[Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md)、[macOS auto-start locations](../../macos-auto-start-locations.md) を参照してください。

### PHP Injection

**`PHPRC`** または **`PHP_INI_SCAN_DIR`** を使って、**`auto_prepend_file`** が対象スクリプトより先に実行される、制御下の PHP 設定を読み込ませることができます。

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

スタンドアロンの Lua interpreter は、対象スクリプトを処理する前に **`LUA_INIT`**（またはバージョン固有の変数）からコードまたは `@file` を実行します。

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** と **`R_PROFILE`** を使うと、R code を含む起動プロファイルにリダイレクトできます。**`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** と R library path を組み合わせると、インストール済みパッケージを自動読み込みさせることもできます。

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`** を使うと、`config/startup.jl` が自動実行される depot の場所を変更できます。

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**、**`ERL_FLAGS`**、**`ERL_ZFLAGS`** を使うと、payload file を必要とせずに Erlang VM の **`-eval`** expression を注入できます。Elixir のワークロードも、通常は同じ VM を起動します。

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** と **`OCTAVE_VERSION_INITFILE`** を使うと、Octave の startup script の場所を変更できます。

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` は cross-platform .NET app であるため、複数の環境変数を使ってコマンド実行前に処理を実行できます。**`XDG_CONFIG_HOME`** は起動時に実行される profile script の場所を変更し、**`PSModulePath`** は module の自動読み込みを hijack します（配置した `.psm1` は import 時に実行され、組み込み cmdlet を shadow できます）。また、.NET の **`CORECLR_PROFILER`**/**`COR_PROFILER`** と **`DOTNET_STARTUP_HOOKS`** 変数は、`Main` の実行前に攻撃者の code をプロセスへ読み込みます。

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Perl script に任意の code を実行させる方法については、各種オプションを確認してください。


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Ruby の環境変数（**`RUBYOPT`**、**`RUBYLIB`**）を悪用して、任意の script に任意の code を実行させることもできます。


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** と標準ライブラリの **`BROWSER`** を組み合わせると、warning-filter の解析中にコマンドを実行できます。ファイルを使う方法では、**`PYTHONPATH`** 上に `sitecustomize.py` を配置すると、通常の `site` 初期化中に対象スクリプトより先に import されます。**`PYTHONBREAKPOINT`** は、コードが `breakpoint()` に到達した際に、指定した callable/module を実行します。**`PYTHONSTARTUP`** など、対話型の実行時に限られる変数は、適用範囲がより限定されます。

**`pyinstaller`** でコンパイルされた実行ファイルは、embedded Python を使って実行されていても、これらの環境変数を使用しない点に注意してください。

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`**（および代替の `EXINIT`）は通常の起動時に Ex command として実行されます。そのため、攻撃者が制御する環境で被害者が Vim/Neovim を開くと、`:!cmd` / `:call system(...)` によって code execution が可能です。

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

別の問題として、Homebrew は Python を `/opt/homebrew` 以下にインストールすることが多く、ローカルの `admin` グループのメンバーが launcher を置き換えられる場合があります。これは環境変数 injection ではなく、書き込み可能なバイナリの hijack です。悪用可能と判断する前に、所有者と ACL を確認してください。


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield) は、process injection を検出してブロックする、**EndpointSecurity** ベースの open-source application です。Endpoint Security を通じて観測できる signal を知るうえで、参考になります。次の項目を alert します。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- プロセスの exec 時に使われる **injection environment variable**: `DYLD_INSERT_LIBRARIES`、`CFNETWORK_LIBRARY_PATH`、`RAWCAMERA_BUNDLE_PATH`、`ELECTRON_RUN_AS_NODE`。
- **`task_for_pid`** 呼び出し — あるプロセスが別のプロセスの task port を要求する操作で、対象への injection に必要です。
- **Electron debugging argument** — `--inspect`、`--inspect-brk`、`--remote-debugging-port`。Electron app を debug mode で起動し、誰でも接続して code を実行できるようにします。<sup>[[3]](#references)</sup>
- **異なる権限レベル間での symlink/hardlink 作成** — 通常ユーザーとして link を仕掛け、特権のある場所を指すようにする古典的な手法です。ただし、**symlink は alert の対象にはできますが、block はできません**。EndpointSecurity は、link の作成前にリンク先を公開しないためです。

### Calls made by other processes

[**このブログ記事**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、**`task_name_for_pid`** 関数を使って、**プロセスに code を injection している他のプロセス**についての情報を取得し、そのプロセスの情報を得る方法が説明されています。<sup>[[4]](#references)</sup>

この関数を呼び出すには、対象プロセスを実行しているユーザーと**同じ uid**であるか、**root**である必要があります（この関数が返すのはプロセスに関する情報であり、code を injection する手段ではありません）。

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — macOS の process-injection を検出する open-source ツール (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron app が secret を機密に保管できない理由: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - task modification の検出](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS stealer の新版、暗号資産愛好家と開発者を標的に](https://securelist.com/macsync-new-version/121383/)
