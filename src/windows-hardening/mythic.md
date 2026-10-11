# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythicとは？

Mythicは、red teaming向けに設計されたオープンソースのモジュール式コラボレーション command and control (C2) frameworkです。オペレーターは、Windows、Linux、macOSなど、さまざまなOS上でエージェント（payload）を管理・展開できます。Mythicは、複数オペレーターによるタスク実行、ファイル処理、SOCKS/rpfwdの管理、payloadの生成に対応したブラウザーUIを提供します。

モノリシックなframeworkとは異なり、Mythicリポジトリ自体にはpayloadタイプやC2プロファイルは含まれていません。エージェント、wrapper、C2プロファイルは通常、外部コンポーネントとしてインストールされ、Mythic coreとは独立して更新できます。

### インストール

Mythicをインストールするには、公式の**[Mythic repo](https://github.com/its-a-feature/Mythic)**の手順に従ってください。Mythicディレクトリから実行する一般的なbootstrapコマンドは次のとおりです。

```bash
sudo make
sudo ./mythic-cli start
```

Mythic がすでに実行中であれば、通常は `./mythic-cli install github ...` で新しい agent または profile を追加し、その後 Mythic を再起動するか、新しいコンポーネントを直接起動するだけで済みます。

### Agents

Mythic は複数の agent をサポートしています。agent は、侵害されたシステム上でタスクを実行する **payload** です。それぞれの agent は特定のニーズに合わせて調整でき、さまざまなオペレーティングシステム上で実行できます。

デフォルトでは、Mythic に agent はインストールされていません。オープンソースのコミュニティ agent は [**https://github.com/MythicAgents**](https://github.com/MythicAgents) にあり、[**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) を使うと、対応するオペレーティングシステム、payload 形式、wrapper、C2 profile をすばやく確認できます。<sup>[[1]](#references)</sup>

その org から agent をインストールするには、次のコマンドを実行します。

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

`sudo -E`形式は、root以外の環境からインストールする場合に便利です。Mythicがすでに起動していても、前述のコマンドで新しいエージェントを追加できます。

### C2 Profiles

MythicのC2 Profilesは、**エージェントがMythicサーバーとどのように通信するか**を定義します。通信プロトコル、暗号化方式、その他の設定を指定します。MythicのWebインターフェースからC2 Profilesを作成、管理できます。

デフォルトでは、MythicはProfilesなしでインストールされますが、リポジトリ [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) から次のコマンドを実行してProfilesをダウンロードできます。

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

現在、operatorが把握しておくべきprofile:

- [`http`](https://github.com/MythicC2Profiles/http): 基本的な非同期GET/POSTトラフィック。
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 複数のcallbackドメイン、fail-over/round-robinローテーション、カスタムヘッダー/query parameter、cookie、ヘッダー、query parameter、またはbodyに配置するmessage transform（`base64`、`base64url`、`xor`、`netbios`、`prepend`、`append`）に対応した、より柔軟なHTTPトラフィック。
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): 静的な`http` profileが認識されやすすぎる場合に使える、JSON/TOML駆動のHTTP message shaping。

### 現在のplatformに関する注意点

- 多くの公開agentやprofileは、現在、ビルド済みのremote container imageを使ってインストールされます。
  componentをforkしたりローカルでpatchしたりしたのに、Mythicの動作が古いままの場合は、生成された`.env`内の`*_REMOTE_IMAGE`、`*_USE_BUILD_CONTEXT`、`*_USE_VOLUME`の設定を確認してください。通常、`*_USE_BUILD_CONTEXT="true"`を有効にすると、remote imageを暗黙に再利用せず、MythicがローカルのDocker contextから再ビルドするようになります。
- Browser scriptは、operatorの利便性を大きく高めるMythicの機能の1つです。生のcommand出力を、表、screenshot viewer、download link、検索link、UIから後続taskingを発行するボタンに変換できます。現在のMythic buildでは、各operatorが独自のscriptを保持し、全体またはtaskごとに有効・無効を切り替えられます。agentがplaintextではなく構造化JSONを返すと、最も効果を発揮します。繰り返し発生する`ls`、`ps`、triage、file browserのworkflowで特に便利です。<sup>[[4]](#references)[[6]](#references)</sup>
- 新しいMythic buildでは、interactive taskingとPush C2 patternにも対応しており、PTY/SOCKS/rpfwdを多用するoperationで`sleep 0` pollingを減らせます。agent/profileが対応している場合、interactive channelを使える状態に保つためだけにserverへ頻繁にcheck-inするより、通常はこちらの方がoverheadを抑えられます。<sup>[[3]](#references)</sup>
- 現在の3.4系Mythic builderは、古い解説から想像されるよりもcontextを考慮します。build parameterは、選択したOSやその他のbuild optionに基づいてグループ化または非表示にできるようになりました。また、payload typeは、1つのbuildで複数のC2 profileや同じC2の複数instanceに対応するかどうかを宣言でき、C2 parameter deviationを使うと、agentが実装していないfieldを非表示にできます。`http`、`httpx`、`smb`、`tcp`、`websocket`を切り替える場合、妥当で安全なbuildの選択肢は固定のフォームではなくなったため、この点が重要です。<sup>[[5]](#references)</sup>
- カスタムagent/profileの組み合わせを構築する際に、MythicのJSON message formatやデフォルトのwire上のcryptoを使いたくない場合は、`translation_container`を使用してください。MythicはUUIDを取り除き、暗号化されたblobとkey materialをgRPC経由でtranslatorに渡し、agent固有のbyte列を受け取ります。binary protocol、カスタムframing、またはagent側の暗号化に対応する場合に、server全体を書き直さずに実現できる方法です。
- linked/P2P callbackは、taskingを中継するだけではありません。Mythicの`get_tasking`フローでは、responseに加えて`delegates`、`socks`、`rpfwd`、`interactive`のデータも運べます。実際には、1つのegress callbackで、同じpolling loop内のinner callbackやpivot channelにも対応できます。子agentが独自に定期check-inする場合、`get_delegate_tasks=false`を設定すると、親がinner callbackのキューにあるjobを誤って取得するのを防げます。

### Wrapper payload

Wrapper payloadを使うと、同じagent logicを維持したまま、配信または永続化されるon-disk representationを変更できます。

- `service_wrapper`: 別のpayloadをWindows service executableに変換します。実行経路で有効なservice binaryが必要な場合に便利です。
- `scarecrow_wrapper`: 互換性のあるshellcodeをScareCrow loaderでwrapし、EXE/DLL/CPLなどのloader-backed outputを生成します。

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apolloは、SpecterOpsのトレーニングでの使用を想定して設計された、4.0 .NET Frameworkを使用するC#製のWindows agentです。<sup>[[2]](#references)</sup>

インストール方法:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### 現在のビルド／プロファイルに関する注意事項

- Apolloは現在、`WinExe`、`Shellcode`、`Service`、`Source`のpayloadを生成できます。
- よく使われるApolloのプロファイルは`http`、`httpx`、`smb`、`tcp`、`websocket`です。
- ドメインローテーション、プロキシサポート、カスタムメッセージ配置、メッセージ変換が必要な場合、古い静的な`http`プロファイルよりも、通常は`httpx`のほうが柔軟です。
- Apolloは機能が特に充実したコミュニティエージェントの1つで、現在はブラウザスクリプト、ファイル／プロセスのブラウザビュー、スクリーンショット、キーロギング、SOCKS、rpfwd、Push C2、P2Pルーティングなど、Mythic側の統合機能を提供しています。
- Apolloは`service_wrapper`や`scarecrow_wrapper`などのラッパーpayloadをサポートしています。
- Apolloは動的なコマンド読み込みをサポートしているため、初期payloadを軽量に保ち、最初のビルドにすべてのpost-ex機能をコンパイルする代わりに、後から追加のコマンドやForgeモジュールを読み込めます。
- shellcode出力を生成する場合、現在のApollo builderではDonutの形式（`Binary`、`Base64`、`C`、`Ruby`、`Python`、`Powershell`、`C#`、`Hex`）と、Donutのbypass動作（`None`、`Abort on fail`、`Continue on fail`）も選択できます。これは、最終的にshellcodeを`service_wrapper`、`scarecrow_wrapper`、またはカスタムローダーで再度ラップする場合に便利です。
- `register_file`と`register_assembly`は、`execute_assembly`、`execute_pe`、`inline_assembly`、`execute_coff`、`powershell_import`、`powerpick`で使うステージング用プリミティブです。現在のApolloビルドでは、ステージングされたこれらのアーティファクトは、クライアント側でDPAPI保護されたAES256 blobとしてキャッシュされます。
- `ls`と`ps`の結果は、Mythicのブラウザスクリプトやファイル／プロセスブラウザと特に相性がよく、共同作戦でのオペレーターによるトリアージを大幅に速めます。
- Apolloのfork-and-runジョブは、使い捨てプロセスの設定を`spawnto_x86`／`spawnto_x64`から引き継ぎ、`ppid`から親プロセスの選択を引き継いだ後、現在選択されているinjectionプリミティブを使用します。実際には、あるコマンドに対するOPSEC調整が、多くの場合、`execute_assembly`、`powerpick`、`mimikatz`、`pth`、`dcsync`、`execute_pe`、`spawn`に同時に影響します。
- 現在のApolloのドキュメントに記載されているinjection backendには、`CreateRemoteThread`、（early-bird形式の）`QueueUserAPC`、syscall経由の`NtCreateThreadEx`があります。目立つpost-exを実行する前に`get_injection_techniques`を使い、ターゲットや実行したいコマンドと相性の悪いプリミティブから切り替える必要がある場合は`set_injection_technique`を使ってください。
- `blockdlls`が影響するのは、post-exジョブ用に作成される使い捨てプロセスのみです。デフォルトの単体`rundll32.exe`より疑わしさの少ない`spawnto_x64`のターゲットと組み合わせると、assembly／PowerShell中心のタスクを実行する前にできる、Apollo側の最も簡単な変更の1つです。

### 検知を考慮した.NETエージェントのビルドパイプライン

検知を考慮したApolloのforkは、最終段階の`obfuscate.exe`処理ではなく、**ビルドシステム全体の問題**として扱う必要があります。このケーススタディは、一般的な[AV回避手法](av-bypass.md)と[.NET検査ツール](../reversing/reversing-tools-basic-methods/README.md)を補足するものです。wire identifier、IL metadata、dependency packaging、reflection、動的にコンパイルされるタスクへの変更は、1つの互換性境界を形成します。<sup>[[8]](#references)</sup>

#### YARAを考慮したプロトコルの変更

コードを変更する前に、公開されているファイル／メモリのルールを監査してください。たとえば、Elasticの`Multi_Trojan_Mythic_4beb7e17`は、`task_id`、`post_response`、`c2_profile`、`get_tasking`、`get_delegate_tasks`を含む、11個中7個以上のMythic JSON／action文字列が存在する場合にマッチします。十分な数のフィールド名を変更すれば、このしきい値を回避できますが、これらは見た目だけのシンボルではなくプロトコル値です。エージェントと対応するserver／profile実装を一緒に変更する必要があります。<sup>[[7]](#references)[[8]](#references)</sup>

これで取り除けるのは、静的な特徴の1セットだけです。チェックインの間隔、メッセージの形式、タスク／レスポンスのフロー、実行時の文字列再構成は、依然として振る舞いやメモリ上の指標になり得ます。そのため、文字列スキャンがクリーンだったことを成功とみなさず、ビルドしたアーティファクトと実際にcallbackを行わせた結果の両方を検証してください。<sup>[[8]](#references)</sup>

#### グローバル変換を適用する前にマージする

Costuraなどのツールでリソースに埋め込むと、関連アセンブリは圧縮リソースとして残ります。そのため、外側のモジュールだけを処理するobfuscatorでは、それらの型名やmetadataが見落とされます。一方、各DLLを個別にobfuscateすると、アセンブリ間の契約に互換性のない名前が割り当てられることがあります。まずILレベルでビルド出力をマージし（たとえば[ILRepack](https://github.com/gluck/il-repack)を使用）、その後、生成されたモジュールに1つのrename mapを適用してください。<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

カスタムパスでは、managed IL/metadata の変換に [dnlib](https://github.com/0xd4d/dnlib) を、書き込み後の PE/resource のパッチ適用に [AsmResolver](https://github.com/Washi1337/AsmResolver) を使用できます。ケーススタディでは、対象となる `ldstr` 命令を、新たに生成した16バイトの rolling-XOR key を使う integer-token/decryptor 呼び出しに置き換えました。また、シンボルと namespace は、短い連番の識別子ではなく、もっともらしいエンタープライズ風の名前にマッピングしました。他のパスでは、選択した compiler/debugger attribute の削除、merger/embedding 参照の除去、resource の名前変更、version information のパッチ適用を行いました。独立したビルドごとに、名前、dead code、暗号化素材を再生成してください。ciphertext を変更すれば安定したバイト列はなくなりますが、安定した decryptor や認識可能な変換パターン自体がシグネチャになります。<sup>[[8]](#references)</sup>

#### 動的タスクを payload と同期させる

Apollo は task source をサーバー側でコンパイルし、DLL のバイト列を送信して、`Assembly.Load()` でロードできます。ベースエージェントの public type の名前を変更すると、元の API を前提に後からコンパイルされたタスクは解決できなくなります。エクスポートされた rename map は、payload 固有の ABI アーティファクトとして扱ってください。<sup>[[8]](#references)</sup>

1. map と type context を、正確な payload/build identifier に紐付ける。
2. タスクをビルドするたびにその map を取得し、一時的な source tree を書き換える。
3. 解決済みの namespace、type、nested/generic type、field、property の参照だけを書き換え、難読化してマージした assembly を参照してコンパイルする。
4. map がない場合や一致しない場合は、タスクを配信する前に拒否し、コンパイル後に初期化テストを実行する。

無差別なグローバル置換は安全ではありません。識別子は、文字列、ローカル宣言、メンバーアクセス、framework type、無関係な namespace にも現れる可能性があるためです。テキスト/regex リライターを使い続ける場合は、これらのコンテキストを明示的に保護し、map の schema や rename pass が変更されるたびに回帰テストを実行してください。<sup>[[8]](#references)</sup>

#### reflection の契約を namespace に依存させない

`t.FullName.StartsWith("Tasks.")` をチェックする discovery code は namespace に依存するため、namespace の remapping 後に失敗します。代わりに、安定した型の関係性を使って discovery を行い、dispatch で `t.Name` を使っている場合は command class name を維持してください。<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

リフレクションで参照される名前、シリアライザーのフィールド、エントリーポイント、アセンブリ間 API のうち、名前を変更してはならないものを明示的な allowlist で管理してください。最後に、ILSpy/dnSpy で結果を逆コンパイルし、ファイルとメモリの両方の表現をスキャンして、EDR ラボですべてのコマンドと loader の経路を実行して確認してください。正常に起動するビルドでも、名前変更によってタスクが壊れたり、実行後にしか検出されない動作が含まれていたりすることがあります。<sup>[[8]](#references)</sup>

この agent には多くのコマンドがあり、いくつかの追加機能を備えた Cobalt Strike の Beacon によく似ています。主なコマンドは次のとおりです。

### Common actions

- `cat`: ファイルの内容を表示する
- `cd`: 現在の作業ディレクトリを変更する
- `cp`: ファイルを別の場所にコピーする
- `ls`: 現在のディレクトリまたは指定したパスにあるファイルとディレクトリを一覧表示する
- `ifconfig`: ネットワークアダプターとインターフェースを取得する
- `netstat`: TCP および UDP の接続情報を取得する
- `pwd`: 現在の作業ディレクトリを表示する
- `ps`: ターゲットシステムで実行中のプロセスを一覧表示する（追加情報付き）
- `jobs`: 長時間実行されるタスクに関連付けられた、実行中のすべての job を一覧表示する
- `download`: ターゲットシステムからローカルマシンにファイルをダウンロードする
- `upload`: ローカルマシンからターゲットシステムにファイルをアップロードする
- `reg_query`: ターゲットシステムのレジストリキーと値を照会する
- `reg_write_value`: 指定したレジストリキーに新しい値を書き込む
- `sleep`: agent の sleep 間隔を変更する。これは Mythic server へのチェックイン頻度を決定する
- その他にも多数のコマンドがあります。利用可能なコマンドの全一覧を見るには `help` を使用してください。

### Privilege escalation

- `getprivs`: 現在のスレッドトークンで可能な限り多くの権限を有効にする
- `getsystem`: winlogon へのハンドルを開いてトークンを複製し、権限を実質的に SYSTEM レベルまで昇格させる
- `make_token`: 新しいログオンセッションを作成して agent に適用し、別のユーザーになりすませるようにする
- `steal_token`: 別のプロセスからプライマリトークンを盗み、agent がそのプロセスのユーザーになりすませるようにする
- `pth`: Pass-the-Hash 攻撃。平文パスワードを使わず、NTLM hash を使ってユーザーとして認証できる
- `mimikatz`: Mimikatz コマンドを実行して、メモリまたは SAM database から認証情報、hash、その他の機密情報を抽出する
- `rev2self`: agent のトークンをプライマリトークンに戻し、権限を実質的に元のレベルまで下げる
- `ppid`: 新しい親プロセス ID を指定して post-exploitation job の親プロセスを変更し、job の実行コンテキストをより細かく制御できるようにする
- `printspoofer`: PrintSpoofer コマンドを実行して print spooler のセキュリティ対策を回避し、権限昇格やコード実行を可能にする
- `dcsync`: ユーザーの Kerberos key をローカルマシンに同期し、オフラインでのパスワードクラッキングやさらなる攻撃を可能にする
- `ticket_cache_add`: 現在または指定したログオンセッションに Kerberos ticket を追加し、ticket の再利用やなりすましを可能にする

### Process execution

- `assembly_inject`: .NET assembly loader をリモートプロセスに inject する
- `blockdlls`: Microsoft 署名のない DLL が post-exploitation job に読み込まれないようにする
- `execute_assembly`: agent のコンテキストで .NET assembly を実行する
- `execute_coff`: COFF file をメモリ内で実行し、コンパイル済みコードをメモリ内で実行できるようにする
- `execute_pe`: unmanaged executable（PE）を実行する
- `keylog_inject`: keylogger を別のプロセスに inject し、キーストロークを Mythic の keylog view にストリームする
- `screenshot` / `screenshot_inject`: 現在のデスクトップを直接キャプチャするか、
  screenshot assembly をターゲットのプロセスまたはセッションに inject してキャプチャする
- `get_injection_techniques`: 利用可能な injection technique と、現在選択されている technique を表示する
- `inline_assembly`: .NET assembly を破棄可能な AppDomain で実行し、agent のメインプロセスに影響を与えずに一時的にコードを実行する
- `register_assembly`: 後で実行するために .NET assembly を登録する
- `register_file`: 後で `execute_*` または PowerShell tasking に使用できるよう、agent cache にファイルを登録する
- `run`: システムの PATH を使って実行ファイルを検索し、ターゲットシステムで実行する
- `set_injection_technique`: post-exploitation job で使用する injection primitive を変更する
- `shinject`: shellcode をリモートプロセスに inject し、任意のコードをメモリ内で実行できるようにする
- `inject`: agent shellcode をリモートプロセスに inject し、agent のコードをメモリ内で実行できるようにする
- `spawn`: 指定した実行ファイル内で新しい agent session を起動し、新しいプロセスで shellcode を実行できるようにする
- `spawnto_x64` と `spawnto_x86`: post-exploitation job で使用するデフォルトの binary を指定したパスに変更する。これにより、非常に目立つ引数なしの `rundll32.exe` の使用を避けられる

### Mythic Forge

これにより、ターゲットシステムで実行できる、事前コンパイル済みの payload や tool の repository である Mythic Forge から **COFF/BOF** file を **load** できます。load できるコマンドを使えば、別プロセスを起動するより通常は OPSEC に優れた方法で、現在の agent プロセス内で BOF として実行し、一般的な操作を実行できます。

インストールを開始するには、次のようにします。

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

次に、`forge_collections` を使って Mythic Forge の COFF/BOF modules を表示し、選択して agent のメモリにロードし、実行できるようにします。デフォルトでは、Apollo に次の2つの collections が追加されています。

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

module をロードすると、`forge_bof_sa-whoami` や `forge_bof_sa-netuser` のような別の command として一覧に表示されます。

BOF については、Forge が Apollo に単一のフラットな引数文字列を渡すわけではないことに注意してください。BOF のパラメーターを Mythic の typed-array 形式にマッピングしたうえで、Apollo の `execute_coff` flow に転送します。Forge からロードした BOF の動作がおかしい場合は、入力した command line だけでなく、想定されている BOF の引数型や entrypoint も確認してください。また、Apollo の新しい BOF loader では、かなり古い 2.3.1 世代の build と比べて引数の処理方法が変更されています。そのため、古い BOF や collections は、marshaling の想定が変わっただけで失敗することがあります。

### PowerShell と scripting の実行

- `powershell_import`: 新しい PowerShell script (.ps1) を agent の cache にインポートし、後で実行できるようにします
- `powershell`: agent のコンテキストで PowerShell command を実行し、高度な scripting や自動化を可能にします
- `powerpick`: PowerShell loader assembly を犠牲プロセスに inject し、PowerShell command を実行します（powershell logging なし）。
- `psinject`: 指定した process で PowerShell を実行し、別の process のコンテキストで script を対象を絞って実行できます
- `shell`: agent のコンテキストで shell command を実行します。cmd.exe で command を実行するのと同様です

### 横展開

- `jump_psexec`: まず Apollo agent executable (apollo.exe) をコピーして実行することで、PsExec technique を使って新しい host に横展開します。
- `jump_wmi`: まず Apollo agent executable (apollo.exe) をコピーして実行することで、WMI technique を使って新しい host に横展開します。
- `link` and `unlink`: callback 間の P2P link（例: SMB/TCP 経由）を確立および切断します。
- `wmiexecute`: WMI を使ってローカルまたは指定したリモートシステムで command を実行します。偽装用の認証情報を指定することもできます。
- `net_dclist`: 指定した domain の domain controller 一覧を取得します。横展開の候補となる target の特定に役立ちます。
- `net_localgroup`: 指定した computer の local group を一覧表示します。computer が指定されていない場合は localhost が対象になります。
- `net_localgroup_member`: ローカルまたはリモート computer 上の指定した group の local group メンバーシップを取得し、特定の group に属する user を列挙できます。
- `net_shares`: 指定した computer 上のリモート share とそのアクセス可否を一覧表示します。横展開の候補となる target の特定に役立ちます。
- `socks`: target network 上で SOCKS 5 準拠の proxy を有効にし、侵害した host 経由で traffic を tunnel できるようにします。proxychains などの tool と互換性があります。
- `rpfwd`: target host の指定した port で listen し、Mythic 経由で traffic をリモート IP と port に転送します。これにより、target network 上の service にリモートアクセスできます。
- `listpipes`: ローカルシステム上のすべての named pipe を一覧表示します。IPC mechanism を介したやり取りによる横展開や権限昇格に役立つことがあります。

`jump_wmi` や `wmiexecute` の内部で使用される低レベルの WMI execution primitive については、[WmiExec](lateral-movement/wmiexec.md) を確認してください。より広範な pivoting pattern については、[Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) を確認してください。

### その他の Command
- `help`: 特定の command に関する詳細情報、または agent で利用可能なすべての command に関する一般情報を表示します。
- `clear`: task を「cleared」としてマークし、agent が取得できないようにします。すべての task を clear するには `all`、特定の task を clear するには `task Num` を指定できます。  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon は、**Linux と macOS** 向けの executable にコンパイルされる Golang agent です。

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### 現在のビルド／プロファイルに関するメモ

- 現在の Poseidon ビルドは、`x86_64` と `arm64` の両方で Linux と macOS を対象としています。
- 対応する出力形式には、ネイティブ実行ファイルのほか、`dylib` や `so` などの共有ライブラリ形式の出力も含まれます。
- Poseidon は `http`、`websocket`、`tcp`、`dynamichttp` に対応しており、現在の builder では `egress_order` や failover threshold などの複数 egress 設定も利用できます。
- Poseidon の現在の capability metadata では、browser scripts、file/process browser integration、interactive tasking、keylogging、screenshots、Push C2、SOCKS、rpfwd、P2P もサポート対象として示されているため、単純な remote shell にとどまらず、実用的な Linux/macOS pivot node として機能します。
- ネットワーク動作をよりクリーンにしたい場合や、Go binary に追加の obfuscation を施したい場合は、`proxy_bypass` や `garble` などのビルド時オプションを確認するとよいでしょう。
- `pty` は Linux/macOS の操作で特に便利な、比較的新しい利便性向上コマンドのひとつです。対話型 PTY を開き、Mythic 側のポートを公開して、以前の `sleep 0` + SOCKS の回避策を使わずに、より本格的なターミナル操作を可能にします。
- Poseidon の現在のドキュメントは、macOS を中心とした tradecraft に特に有用です。`jxa` は JavaScript for Automation をメモリ内で実行し、`screencapture` はログイン中のデスクトップを取得し、`clipboard_monitor` は pasteboard の変更をストリーミングし、`execute_library` はローカルの dylib をロードして関数を呼び出し、`libinject` はリモートプロセスにディスク上の dylib をロードさせます。
- 長時間実行するジョブでは、Poseidon が post-exploitation の処理を、強制終了できるものではなく協調的に動作する goroutine/thread 内で実行することを覚えておいてください。また、現在は組み込みの agent obfuscation がないこともドキュメントに明記されています。そのため、高度に obfuscation された商用 implant と比べ、ビルド／プロファイルレベルの tradecraft がより重要になります。

Mythic を利用した macOS の操作、JAMF の悪用、または MDM-as-C2 のアイデアに関する macOS 固有の tradecraft については、[macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) を確認してください。

Linux または macOS で使用する場合、次のような興味深いコマンドがあります。

### 一般的な操作

- `cat`: ファイルの内容を出力する
- `cd`: 現在の作業ディレクトリを変更する
- `chmod`: ファイルの権限を変更する
- `config`: 現在の設定とホスト情報を表示する
- `cp`: ファイルをある場所から別の場所にコピーする
- `curl`: オプションのヘッダーとメソッドを指定して、単一の web request を実行する
- `upload`: ファイルをターゲットにアップロードする
- `download`: ターゲットシステムからローカルマシンにファイルをダウンロードする
- その他多数

### 機密情報の検索

- `triagedirectory`: ホスト上のディレクトリから、機密ファイルや認証情報などの興味深いファイルを探す。
- `getenv`: 現在の環境変数をすべて取得する。

### macOS 固有の tradecraft

- `jxa`: `OSAScript` 経由で JavaScript for Automation をメモリ内で実行します。別個のスクリプトファイルを配置せずに、macOS ネイティブの post-exploitation を行う際に便利です。
- `clipboard_monitor`: pasteboard をポーリングして変更を Mythic に報告します。コピー＆ペーストに依存する認証情報／token 窃取のワークフローに便利です。
- `screencapture`: macOS 上でユーザーのデスクトップをキャプチャします。
- `execute_library`: ディスク上の dylib をロードし、指定された export function を呼び出します。
- `libinject`: shellcode stub を注入し、別の macOS プロセスにディスク上の dylib をロードさせます。
- `persist_launchd`: agent から直接 LaunchAgent / LaunchDaemon の persistence を作成します。

### 横方向への移動

- `ssh`: 指定された認証情報を使ってホストに SSH 接続し、ssh を起動せずに PTY を開きます。
- `sshauth`: 指定された認証情報を使って、指定したホストに SSH 接続します。これを使って SSH 経由でリモートホスト上の特定のコマンドを実行したり、ファイルを SCP で転送したりすることもできます。
- `link_tcp`: TCP 経由で別の agent に接続し、agent 間の直接通信を可能にします。
- `link_webshell`: webshell P2P profile を使って agent に接続し、agent の web interface へのリモートアクセスを可能にします。
- `rpfwd`: Reverse Port Forward を開始または停止し、ターゲットネットワーク上のサービスへのリモートアクセスを可能にします。
- `socks`: ターゲットネットワーク上で SOCKS5 proxy を開始または停止し、侵害したホスト経由の traffic tunneling を可能にします。proxychains などのツールと互換性があります。
- `portscan`: ホストの open port をスキャンします。横方向への移動やさらなる攻撃に向けた潜在的なターゲットの特定に役立ちます。

### プロセスの実行

- `shell`: /bin/sh 経由で単一の shell command を実行し、ターゲットシステム上で command を直接実行します。
- `run`: 引数を指定してディスク上の command を実行し、ターゲットシステム上で binary や script を実行します。
- `pty`: 対話型 PTY を開き、ターゲットシステム上の shell を直接操作できるようにします。

## References

- [1] [Mythic Community Agent 機能マトリックス](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 の主な変更点: Interactive Tasking、Push C2、Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic ドキュメント](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3 から 3.4 への更新](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Mythic の隠れた機能で Red Team Ops を変革する: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: Multi_Trojan_Mythic YARA ルール](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Fork から Framework へ: Apollo の改変から学んだ Agent Invasion](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
