# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythicとは？

Mythicは、red teaming向けに設計された、オープンソースのモジュラーで共同作業可能なcommand and control (C2) フレームワークです。Windows、Linux、macOSを含むさまざまなオペレーティングシステム上で、operatorがagent（payload）を管理・展開できるようにします。Mythicは、複数operatorでのtasking、ファイル処理、SOCKS/rpfwd管理、payload生成のためのブラウザUIを提供します。

単一構成のフレームワークとは異なり、Mythicのリポジトリ自体にはpayload typeやC2 profileは**含まれていません**。agent、wrapper、C2 profileは通常、外部コンポーネントとしてインストールされ、Mythic coreとは独立して更新できます。

### インストール

Mythicをインストールするには、公式の**[Mythic repo](https://github.com/its-a-feature/Mythic)**の手順に従ってください。Mythicディレクトリからの一般的なbootstrapは次のとおりです:
```bash
sudo make
sudo ./mythic-cli start
```
Mythic がすでに実行中なら、通常は `./mythic-cli install github ...` で新しい agent または profile を追加し、その後 Mythic を再起動するか、新しい component を直接起動できます。

### Agents

Mythic は複数の agent をサポートしており、これは**侵害されたシステム上で task を実行する payloads**です。各 agent は特定のニーズに合わせて調整でき、異なる operating systems 上で動作できます。

デフォルトでは Mythic には agent はインストールされていません。オープンソースの community agents は [**https://github.com/MythicAgents**](https://github.com/MythicAgents) にあり、[**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) は、対応する operating systems、payload formats、wrappers、C2 profiles を素早く確認するのに便利です。

その org から agent をインストールするには、次を実行できます:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudoo -E` 形式は、root 以外の環境からインストールする場合に便利です。Mythic がすでに実行中でも、前のコマンドで新しい agent を追加できます。

### C2 Profiles

Mythic の C2 profiles は、**agent が Mythic server とどのように通信するか**を定義します。通信プロトコル、暗号化方式、その他の設定を指定します。Mythic web interface から C2 profiles を作成および管理できます。

デフォルトでは Mythic は profiles なしでインストールされますが、repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) からいくつかの profiles をダウンロードすることも可能です。実行:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
現在、念頭に置いておくべき operator 関連の profile:

- [`http`](https://github.com/MythicC2Profiles/http): basic な asynchronous GET/POST traffic。
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 複数の callback domains、fail-over/round-robin rotation、custom headers/query parameters、そして cookies、headers、query parameters、または body に配置される message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) を備えた、より柔軟な HTTP traffic。
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): static な `http` profile が目立ちすぎる場合の、JSON/TOML-driven な HTTP message shaping。

### 現在の platform notes

- 多くの public agents と profiles は、今では pre-built remote container images でインストールされます。
コンポーネントを fork したりローカルで patch したのに Mythic が古い
behavior を使い続ける場合は、生成された `.env` エントリの `*_REMOTE_IMAGE`、
`*_USE_BUILD_CONTEXT`、`*_USE_VOLUME` を確認してください。
`*_USE_BUILD_CONTEXT="true"` を有効にすると、Mythic が remote image を黙って再利用するのではなく、
local Docker context から再ビルドするようになることが多いです。
- Browser scripts は、operator にとって Mythic の中でも特に価値の高い quality-of-life 機能の一つです:
生の command output を table、screenshot viewer、download link に変換でき、
UI から直接 follow-on tasking を発行する buttons も追加できます。
これは、繰り返し行う `ls`、`ps`、triage、file-browser のワークフローで特に有用です。
- 新しい Mythic ビルドは interactive tasking と Push C2 パターンもサポートしており、
PTY/SOCKS/rpfwd を多用する操作中に `sleep 0` polling を減らせます。
agent/profile がこれをサポートしている場合、通常は、interactive channel を使える状態に保つためだけに
server へ constant な check-ins を打ち続けるよりも low-overhead です。

### Wrapper payloads

Wrapper payloads を使うと、同じ agent logic を保ちながら、配信または永続化される on-disk representation を変更できます。

- `service_wrapper`: 別の payload を Windows service executable に変換します。execution path に valid な service binary が必要な場合に便利です。
- `scarecrow_wrapper`: 互換性のある shellcode を ScareCrow loader でラップし、EXE/DLL/CPL などの loader-backed output を生成します。

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo は、SpecterOps の training offerings で使うことを目的として設計された、4.0 .NET Framework を使用する C# 製の Windows agent です。

インストール方法:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo は現在、`WinExe`、`Shellcode`、`Service`、`Source` payloads を出力できます。
- よく使われる Apollo profiles は `http`、`httpx`、`smb`、`tcp`、`websocket` です。
- `httpx` は、domain rotation、proxy support、custom message placement、古い静的な `http` profile の代わりに message transforms が必要な場合、通常こちらのほうが柔軟です。
- Apollo は `service_wrapper` や `scarecrow_wrapper` のような wrapper payloads をサポートしています。
- `register_file` と `register_assembly` は `execute_assembly`、`execute_pe`、`inline_assembly`、`execute_coff`、`powershell_import`、`powerpick` の staging primitives です。現在の Apollo builds では、それらの staged artifacts は client-side に DPAPI-protected AES256 blobs として cached されます。
- `ls` と `ps` の結果は Mythic の browser scripts と file/process browser と特によく統合されるため、協調運用での operator triage がかなり速くなります。
- Apollo の fork-and-run jobs は、sacrificial process settings を `spawnto_x86` / `spawnto_x64` から継承し、parent selection を `ppid` から継承し、その後、現在選択されている injection primitive を使います。実際には、これは1つの command に対する OPSEC tuning が `execute_assembly`、`powerpick`、`mimikatz`、`pth`、`dcsync`、`execute_pe`、`spawn` にも同時に影響することを意味します。
- 現在文書化されている Apollo の injection backends には `CreateRemoteThread`、`QueueUserAPC`（early-bird style）、および syscalls 経由の `NtCreateThreadEx` が含まれます。ノイジーな post-exploitation の前には `get_injection_techniques` を使い、ターゲットや実行したい command と衝突する primitive から切り替えたい場合は `set_injection_technique` を使ってください。
- `blockdlls` は post-exploitation jobs 用に作成された sacrificial processes にのみ影響します。デフォルトの bare な `rundll32.exe` よりも疑わしくない `spawnto_x64` target と組み合わせると、assembly/PowerShell-heavy な tasking を実行する前に Apollo 側で行える変更としては最も簡単なものの1つです。

この agent には多くの commands があり、いくつかの追加機能を備えた Cobalt Strike の Beacon に非常によく似ています。その中には以下が含まれます:

### Common actions

- `cat`: ファイルの内容を表示する
- `cd`: 現在の working directory を変更する
- `cp`: ある場所から別の場所へファイルをコピーする
- `ls`: 現在の directory または指定した path のファイルと directory を一覧表示する
- `ifconfig`: network adapters と interfaces を取得する
- `netstat`: TCP と UDP の connection information を取得する
- `pwd`: 現在の working directory を表示する
- `ps`: 対象システムで実行中の processes を一覧表示する（追加情報付き）
- `jobs`: 長時間 tasking に関連付けられた実行中の jobs を一覧表示する
- `download`: 対象システムからローカルマシンへファイルをダウンロードする
- `upload`: ローカルマシンから対象システムへファイルをアップロードする
- `reg_query`: 対象システムの registry keys と values を問い合わせる
- `reg_write_value`: 指定した registry key に新しい value を書き込む
- `sleep`: agent の sleep interval を変更する。これは Mythic server への check-in 頻度を決定する
- その他多数。利用可能な commands の全一覧は `help` を使ってください。

### Privilege escalation

- `getprivs`: 現在の thread token で可能な限り多くの privileges を有効化する
- `getsystem`: winlogon への handle を開いて token を duplicate し、実質的に privileges を SYSTEM level まで昇格させる
- `make_token`: 新しい logon session を作成して agent に適用し、別の user の impersonation を可能にする
- `steal_token`: 別の process から primary token を盗み、その process の user を agent が impersonate できるようにする
- `pth`: Pass-the-Hash attack。平文 password を必要とせず、NTLM hash を使って user として認証できるようにする
- `mimikatz`: Mimikatz commands を実行して memory または SAM database から credentials、hashes、その他の機微な情報を抽出する
- `rev2self`: agent の token を primary token に戻し、実質的に privileges を元の level まで下げる
- `ppid`: 新しい parent process ID を指定して post-exploitation jobs の parent process を変更し、job execution context をより細かく制御できるようにする
- `printspoofer`: PrintSpoofer commands を実行して print spooler security measures を回避し、privilege escalation または code execution を可能にする
- `dcsync`: ユーザーの Kerberos keys を local machine に同期し、オフラインでの password cracking やさらなる attacks を可能にする
- `ticket_cache_add`: 現在の logon session または指定した session に Kerberos ticket を追加し、ticket reuse または impersonation を可能にする

### Process execution

- `assembly_inject`: .NET assembly loader を remote process に inject できる
- `blockdlls`: post-exploitation jobs に非 Microsoft 署名の DLL がロードされるのを block する
- `execute_assembly`: agent の context で .NET assembly を実行する
- `execute_coff`: COFF file を memory 上で実行し、compiled code の in-memory execution を可能にする
- `execute_pe`: unmanaged executable (PE) を実行する
- `keylog_inject`: 別の process に keylogger を inject し、keystrokes を Mythic の keylog view にストリーム送信する
- `screenshot` / `screenshot_inject`: 現在の desktop を直接キャプチャするか、
target process/session に screenshot assembly を inject してキャプチャする
- `get_injection_techniques`: 利用可能な injection techniques と現在選択中のものを表示する
- `inline_assembly`: disposable AppDomain で .NET assembly を実行し、agent の main process に影響を与えずに一時的な code 実行を可能にする
- `register_assembly`: 後で実行するために .NET assembly を登録する
- `register_file`: 後で `execute_*` または PowerShell tasking に使うため、agent cache に file を登録する
- `run`: system の PATH を使って executable を探し、対象システム上で binary を実行する
- `set_injection_technique`: post-exploitation jobs で使う injection primitive を変更する
- `shinject`: shellcode を remote process に inject し、任意 code の in-memory execution を可能にする
- `inject`: agent shellcode を remote process に inject し、agent の code の in-memory execution を可能にする
- `spawn`: 指定した executable 内に新しい agent session を生成し、新しい process で shellcode の実行を可能にする
- `spawnto_x64` and `spawnto_x86`: params なしの `rundll32.exe` を使う代わりに、post-exploitation jobs で使う default binary を指定した path に変更し、ノイズをかなり減らす。

### Mythic Forge

これにより、Mythic Forge から **COFF/BOF を load** できます。Mythic Forge は、対象システム上で実行できる事前コンパイル済み payloads と tools の repository です。load できるすべての commands により、現在の agent process 内で BOFs としてそれらを実行しながら common actions を実行できるようになります（通常、別の process を spawn するよりも OPSEC が良好です）。

次の方法でインストールを開始します:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, `forge_collections` を使って Mythic Forge の COFF/BOF modules を表示し、agent の memory に load して実行できるようにします。デフォルトでは、Apollo に次の 2 つの collections が追加されています:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

1 つの module が load されると、`forge_bof_sa-whoami` や `forge_bof_sa-netuser` のような別の command として list に表示されます。

BOF については、Forge は Apollo に対して単一の flat な argument string をそのまま渡すだけではないことに注意してください。BOF parameters を Mythic の typed-array format に map し、それを Apollo の `execute_coff` flow に forward します。Forge-loaded BOF の挙動が奇妙な場合は、入力した command line だけでなく、期待される BOF argument types / entrypoint を確認してください。

### PowerShell & scripting execution

- `powershell_import`: 後で実行するために、新しい PowerShell script (.ps1) を agent cache に import します
- `powershell`: agent の context で PowerShell command を実行し、高度な scripting と automation を可能にします
- `powerpick`: PowerShell loader assembly を sacrificial process に inject し、PowerShell command を実行します（powershell logging なし）
- `psinject`: 指定した process で PowerShell を実行し、別の process の context で script を targeted execution できます
- `shell`: agent の context で shell command を実行します。cmd.exe で実行するのと同様です

### Lateral Movement

- `jump_psexec`: PsExec technique を使って、新しい host へ lateral movement します。まず Apollo agent executable (apollo.exe) をコピーして実行します
- `jump_wmi`: WMI technique を使って、新しい host へ lateral movement します。まず Apollo agent executable (apollo.exe) をコピーして実行します
- `link` and `unlink`: callback 間で P2P links（たとえば SMB/TCP 経由）を作成・解除します
- `wmiexecute`: 省略可能な impersonation 用 credentials を使って、local または指定した remote system 上で WMI を使用して command を実行します
- `net_dclist`: 指定した domain の domain controllers の list を取得します。lateral movement の potential targets を識別するのに役立ちます
- `net_localgroup`: 指定した computer 上の local groups を list 表示します。computer が指定されない場合は localhost が default です
- `net_localgroup_member`: local または remote computer 上の指定した group の local group membership を取得し、特定の group に属する users を enumerate できます
- `net_shares`: 指定した computer 上の remote shares とその accessibility を list 表示します。lateral movement の potential targets を識別するのに役立ちます
- `socks`: target network 上で SOCKS 5 準拠の proxy を有効にし、compromised host 経由で traffic を tunnel できます。proxychains のような tools と互換性があります
- `rpfwd`: target host 上の指定した port で listen を開始し、traffic を Mythic 経由で remote IP と port に forward します。target network 上の services へ remote access できます
- `listpipes`: local system 上のすべての named pipes を list 表示します。IPC mechanisms とやり取りすることで、lateral movement や privilege escalation に役立つことがあります

`jump_wmi` または `wmiexecute` の下で使われる lower-level の WMI execution primitives については、[WmiExec](lateral-movement/wmiexec.md) を確認してください。より広範な pivoting patterns については、[Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) を確認してください。

### Miscellaneous Commands
- `help`: agent で利用可能なすべての command に関する general information、または特定の command の詳細情報を表示します
- `clear`: task を 'cleared' としてマークし、agents が取り出せないようにします。`all` を指定するとすべての task を clear でき、`task Num` を指定すると特定の task を clear できます


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon は **Linux と macOS** の executable にコンパイルされる Golang agent です。
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- 現在の Poseidon ビルドは、Linux と macOS の両方で `x86_64` と `arm64` を対象としています。
- サポートされる出力形式には、ネイティブ実行ファイルに加えて、`dylib` や `so` のような shared-library 形式の出力が含まれます。
- Poseidon は `http`、`websocket`、`tcp`、`dynamichttp` をサポートしており、現在の builder は `egress_order` や failover thresholds のような multi-egress 設定を公開しています。
- `proxy_bypass` や `garble` のような build-time オプションは、よりクリーンなネットワーク挙動や追加の Go binary obfuscation が必要なときに確認する価値があります。
- `pty` は Linux/macOS の運用で最も便利な新しめの quality-of-life コマンドの1つです。インタラクティブな PTY を開き、旧来の `sleep 0` + SOCKS workaround に頼らずに、より完全な terminal interaction のための Mythic 側の port を公開できます。
- Poseidon の現在の docs は、macOS-heavy な tradecraft に特に興味深い内容です: `jxa` は JavaScript for Automation を in-memory で実行し、`screencapture` はログイン中の desktop を取得し、`clipboard_monitor` は pasteboard の変更をストリームし、`execute_library` はローカルの dylib を読み込んでその中の function を呼び出し、`libinject` は remote process に on-disk の dylib を読み込ませます。
- 長時間実行される jobs では、Poseidon は post-exploitation work を goroutines/threads 内で実行し、それらは hard-killable ではなく cooperative であることを覚えておいてください。docs には、現在 built-in の agent obfuscation がないことも明記されているため、重く obfuscation された commercial implants よりも build/profile-level の tradecraft が重要になります。

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Linux または macOS で使用すると、いくつか興味深い commands があります:

### Common actions

- `cat`: ファイルの内容を表示する
- `cd`: 現在の working directory を変更する
- `chmod`: ファイルの permissions を変更する
- `config`: 現在の config と host information を表示する
- `cp`: ある場所から別の場所へファイルをコピーする
- `curl`: 任意の headers と method を指定して単一の web request を実行する
- `upload`: ターゲットへファイルを upload する
- `download`: ターゲット system から local machine へファイルを download する
- ほか多数

### Search Sensitive Information

- `triagedirectory`: host 上の directory 内から、sensitive files や credentials などの興味深いファイルを見つける。
- `getenv`: 現在のすべての environment variables を取得する。

### macOS-specific tradecraft

- `jxa`: `OSAScript` 経由で JavaScript for Automation を in-memory で実行する。別の script files を配置せずに native macOS post-exploitation を行うのに便利です。
- `clipboard_monitor`: pasteboard を poll し、変更を Mythic に報告する。copy/paste に依存する credentials/token theft workflows に便利です。
- `screencapture`: macOS 上でユーザーの desktop を capture する。
- `execute_library`: disk から dylib を読み込み、特定の exported function を呼び出す。
- `libinject`: shellcode stub を inject して、別の macOS process に disk 上の dylib を読み込ませる。
- `persist_launchd`: agent から直接 LaunchAgent / LaunchDaemon persistence を作成する。

### Move laterally

- `ssh`: 指定された credentials を使って host に SSH し、ssh を起動せずに PTY を開く。
- `sshauth`: 指定された credentials を使って指定 host(s) に SSH する。これを使って SSH 経由で remote hosts 上で特定の command を実行したり、ファイルを SCP したりすることもできます。
- `link_tcp`: TCP 経由で別の agent に link し、agent 間の direct communication を可能にする。
- `link_webshell`: webshell P2P profile を使って agent に link し、agent の web interface へ remote access できるようにする。
- `rpfwd`: Reverse Port Forward を開始または停止し、target network 上の services へ remote access できるようにする。
- `socks`: target network 上で SOCKS5 proxy を開始または停止し、compromised host を通じた traffic の tunneling を可能にする。proxychains のような tools と互換性があります。
- `portscan`: host(s) の open ports を scan する。lateral movement やさらなる attack の潜在的 targets を特定するのに役立ちます。

### Process execution

- `shell`: /bin/sh 経由で単一の shell command を実行し、target system 上で commands を直接実行できるようにする。
- `run`: arguments 付きで disk 上の command を実行し、target system 上で binaries や scripts を実行できるようにする。
- `pty`: インタラクティブな PTY を開き、target system 上の shell と直接対話できるようにする。




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
