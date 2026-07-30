# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythicとは？

Mythicは、red teaming向けに設計された、オープンソースでモジュール型の共同 command and control (C2) frameworkです。Windows、Linux、macOSなど、さまざまなOS上でエージェント（payloads）を管理および展開できます。Mythicは、複数オペレーターによるtasking、ファイル処理、SOCKS/rpfwd管理、payload生成のためのブラウザUIを提供します。

モノリシックなframeworkとは異なり、Mythicリポジトリ自体にはpayloadタイプやC2 profilesは含まれていません。エージェント、wrapper、C2 profilesは通常、外部コンポーネントとしてインストールされ、Mythic coreとは独立して更新できます。

### インストール

Mythicをインストールするには、公式の **[Mythic repo](https://github.com/its-a-feature/Mythic)** の手順に従ってください。Mythicディレクトリからの一般的なbootstrapは次のとおりです。
```bash
sudo make
sudo ./mythic-cli start
```
Mythicがすでに実行中の場合、通常は `./mythic-cli install github ...` で新しいagentまたはprofileを追加し、その後Mythicを再起動するか、新しいcomponentを直接起動できます。

### Agents

Mythicは複数のagentをサポートしています。agentは、**侵害されたシステム上でタスクを実行するpayload**です。各agentは特定のニーズに合わせて調整でき、異なるオペレーティングシステム上で実行できます。

デフォルトでは、Mythicにagentはインストールされていません。オープンソースのコミュニティagentは[**https://github.com/MythicAgents**](https://github.com/MythicAgents) にあり、[**コミュニティ機能マトリックス**](https://mythicmeta.github.io/overview/agent_matrix.html)を使うと、対応しているオペレーティングシステム、payload形式、wrapper、C2 profileをすばやく確認できます。

そのorgからagentをインストールするには、次を実行します。
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E`形式は、root以外の環境からインストールする場合に便利です。Mythicがすでに実行中であっても、前述のコマンドで新しいagentを追加できます。

### C2 Profiles

MythicのC2 profilesは、**agentsがMythic serverと通信する方法**を定義します。通信プロトコル、暗号化方式、その他の設定を指定します。MythicのWebインターフェースからC2 profilesを作成および管理できます。

デフォルトでは、Mythicはprofilesなしでインストールされます。ただし、次のコマンドを実行して、repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles)からいくつかのprofilesをdownloadできます：
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
現在の operator に関連する、把握しておくべき profiles:

- [`http`](https://github.com/MythicC2Profiles/http): 基本的な非同期 GET/POST traffic。
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 複数の callback domains、fail-over/round-robin rotation、custom headers/query parameters、さらに cookies、headers、query parameters、body に配置できる message transforms（`base64`、`base64url`、`xor`、`netbios`、`prepend`、`append`）を備えた、より柔軟な HTTP traffic。
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): static な `http` profile が認識されやすい場合に使用する、JSON/TOML による HTTP message shaping。

### 現在の platform に関する注意点

- 多くの public agents と profiles は現在、pre-built remote container images を使って install されます。
  component を fork したり、local で patch したりした後も Mythic が古い
  behavior を使い続ける場合は、生成された `.env` の
  `*_REMOTE_IMAGE`、`*_USE_BUILD_CONTEXT`、`*_USE_VOLUME` の entries を確認してください。
  `*_USE_BUILD_CONTEXT="true"` を有効にすることで、通常は Mythic が remote image を黙って再利用せず、
  local の Docker context から rebuild するようになります。
- Browser scripts は operators にとって Mythic の最も価値の高い quality-of-life features の一つです。
  raw command output を tables、screenshot viewers、download links、search links、
  および UI から follow-on tasking を直接発行する buttons に変換できます。
  現在の Mythic builds では、各 operator が自分用の scripts を保持し、
  global または task ごとに toggle できます。また、agents が plaintext ではなく
  structured JSON を返す場合に最良の結果が得られます。
  これは、反復的な `ls`、`ps`、triage、file-browser workflows に特に有用です。
- より新しい Mythic builds は、interactive tasking と Push C2 patterns にも対応しており、
  PTY/SOCKS/rpfwd を多用する operations で、`sleep 0` polling の必要性を減らせます。
  agent/profile が対応している場合、interactive channel を使える状態に保つためだけに
  constant check-ins で server を hammering するよりも、通常はこちらの overhead が低くなります。
- 現在の 3.4-era Mythic builders は、古い writeups が示すよりも context-aware です。
  build parameters は、選択した OS やその他の build options に基づいて grouped または hidden にでき、
  payload types は、1 回の build で複数の C2 profiles または同じ C2 の複数 instances を
  support するかどうかを宣言できます。また、C2 parameter deviations により、
  agent が実際には implement していない fields を隠せます。
  これは `http`、`httpx`、`smb`、`tcp`、`websocket` の間を切り替える際に重要です。
  safe/valid な build surface は、もはや flat な static form ではありません。
- custom agent/profile pair を build していて、wire 上で Mythic の JSON message format や
  default crypto を使用したくない場合は、`translation_container` を使用してください。
  Mythic は UUID を strip し、encrypted blob と key material を gRPC 経由で translator に渡し、
  agent-native bytes が返されることを想定します。
  これは、binary protocols、custom framing、または agent-side encryption を、
  server 全体を書き換えずにサポートするための clean な方法です。
- linked/P2P callbacks は tasking だけを shuttle するわけではないことを覚えておいてください。
  Mythic の `get_tasking` flow は、responses に加えて `delegates`、`socks`、`rpfwd`、
  `interactive` data も運べます。
  実際には、1 つの egress callback で、同じ polling loop 内の inner callbacks と pivot channels
  に対応できます。child agents が独自に periodic check-ins を実行する場合は、
  `get_delegate_tasks=false` によって、parent が inner callback の queued jobs を
  誤って consume するのを防げます。

### Wrapper payloads

Wrapper payloads を使うと、同じ agent logic を維持したまま、delivery または persistence される
on-disk representation を変更できます。

- `service_wrapper`: 別の payload を Windows service executable に変換します。
  execution path が有効な service binary を要求する場合に便利です。
- `scarecrow_wrapper`: compatible な shellcode を ScareCrow loader で wrap し、
  EXE/DLL/CPL などの loader-backed outputs を生成します。

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo は、SpecterOps の training offerings で使用するために設計された、
4.0 .NET Framework を使用する C# 製の Windows agent です。

次のコマンドで install します:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo は現在、`WinExe`、`Shellcode`、`Service`、`Source` の payload を生成できます。
- 一般的に使用される Apollo profiles は `http`、`httpx`、`smb`、`tcp`、`websocket` です。
- `httpx` は、旧来の static な `http` profile の代わりに、domain rotation、proxy support、custom message placement、message transforms が必要な場合に、通常はより柔軟な選択肢です。
- Apollo は機能が充実した community agent の1つであり、現在は browser scripts、file/process browser views、screenshots、keylogging、SOCKS、rpfwd、Push C2、P2P routing など、Mythic-side integrations を提供しています。
- Apollo は `service_wrapper` や `scarecrow_wrapper` などの wrapper payloads をサポートしています。
- Apollo は dynamic command loading をサポートしているため、初期 payload を軽量に保ち、最初の build にすべての post-ex capability をコンパイルする代わりに、後から追加の commands や Forge modules を load できます。
- shellcode output を生成する際、Apollo の現在の builder は Donut format choices（`Binary`、`Base64`、`C`、`Ruby`、`Python`、`Powershell`、`C#`、`Hex`）と Donut bypass behavior（`None`、`Abort on fail`、`Continue on fail`）も提供します。これは、最終的な目的が shellcode を `service_wrapper`、`scarecrow_wrapper`、または custom loader で再度 wrap する場合に便利です。
- `register_file` と `register_assembly` は、`execute_assembly`、`execute_pe`、`inline_assembly`、`execute_coff`、`powershell_import`、`powerpick` の staging primitives です。現在の Apollo builds では、これらの staged artifacts は client-side で DPAPI-protected AES256 blobs として cache されます。
- `ls` と `ps` の results は Mythic の browser scripts および file/process browser と特に相性がよく、collaborative operations における operator triage を大幅に高速化します。
- Apollo の fork-and-run jobs は、`spawnto_x86` / `spawnto_x64` から sacrificial process settings を継承し、`ppid` から parent selection を継承した後、現在選択されている injection primitive を使用します。実際には、ある command に対する OPSEC tuning が、`execute_assembly`、`powerpick`、`mimikatz`、`pth`、`dcsync`、`execute_pe`、`spawn` に同時に影響することを意味します。
- 現在 documented な Apollo injection backends には、syscalls 経由の `CreateRemoteThread`、`QueueUserAPC`（early-bird style）、`NtCreateThreadEx` が含まれます。noisy な post-exploitation の前に `get_injection_techniques` を使用し、target または実行したい command と衝突する primitive から切り替える必要がある場合は `set_injection_technique` を使用してください。
- `blockdlls` は post-exploitation jobs 用に作成された sacrificial processes にのみ影響します。default の bare な `rundll32.exe` よりも疑わしくない `spawnto_x64` target と組み合わせることで、assembly/PowerShell-heavy tasking の実行前に行える、Apollo-side で最も簡単な変更の1つです。

この agent には多くの commands があり、いくつかの追加機能を備えた Cobalt Strike の Beacon と非常によく似ています。主なものは以下のとおりです。

### Common actions

- `cat`: file の contents を表示
- `cd`: current working directory を変更
- `cp`: ある location から別の location に file を copy
- `ls`: current directory または指定した path 内の files と directories を一覧表示
- `ifconfig`: network adapters と interfaces を取得
- `netstat`: TCP および UDP connection information を取得
- `pwd`: current working directory を表示
- `ps`: target system 上で running 中の processes を一覧表示（追加情報付き）
- `jobs`: long-running tasking に関連付けられた、現在 running 中のすべての jobs を一覧表示
- `download`: target system から local machine に file を download
- `upload`: local machine から target system に file を upload
- `reg_query`: target system 上の registry keys と values を query
- `reg_write_value`: 指定した registry key に新しい value を write
- `sleep`: agent の sleep interval を変更。これは Mythic server に check in する頻度を決定します
- その他にも多数あります。利用可能な commands の完全な一覧を確認するには `help` を使用してください。

### Privilege escalation

- `getprivs`: current thread token で可能な限り多くの privileges を enable
- `getsystem`: winlogon への handle を open して token を duplicate し、実質的に SYSTEM level へ privilege escalation
- `make_token`: 新しい logon session を作成して agent に適用し、別の user の impersonation を可能にする
- `steal_token`: 別の process から primary token を steal し、agent がその process の user を impersonate できるようにする
- `pth`: Pass-the-Hash attack。plaintext password を必要とせず、NTLM hash を使用して user として authenticate できるようにする
- `mimikatz`: Mimikatz commands を実行し、memory または SAM database から credentials、hashes、その他の sensitive information を extract
- `rev2self`: agent の token を primary token に revert し、privileges を元の level まで実質的に drop
- `ppid`: 新しい parent process ID を指定して post-exploitation jobs の parent process を変更し、job execution context をより適切に制御できるようにする
- `printspoofer`: PrintSpoofer commands を実行して print spooler の security measures を bypass し、privilege escalation または code execution を可能にする
- `dcsync`: user の Kerberos keys を local machine に sync し、offline password cracking またはさらなる attacks を可能にする
- `ticket_cache_add`: current logon session または指定した session に Kerberos ticket を add し、ticket reuse または impersonation を可能にする

### Process execution

- `assembly_inject`: .NET assembly loader を remote process に inject
- `blockdlls`: post-exploitation jobs への non-Microsoft signed DLLs の load を block
- `execute_assembly`: agent の context で .NET assembly を execute
- `execute_coff`: COFF file を memory 内で execute し、compiled code の in-memory execution を可能にする
- `execute_pe`: unmanaged executable（PE）を execute
- `keylog_inject`: keylogger を別の process に inject し、keystrokes を Mythic の keylog view に stream
- `screenshot` / `screenshot_inject`: current desktop を直接 capture、または screenshot assembly を target process/session に inject して capture
- `get_injection_techniques`: 利用可能な injection techniques と現在選択されている technique を表示
- `inline_assembly`: disposable AppDomain 内で .NET assembly を execute し、agent の main process に影響を与えずに一時的な code execution を可能にする
- `register_assembly`: 後で execution できるよう .NET assembly を register
- `register_file`: 後で `execute_*` または PowerShell tasking に使用できるよう、agent cache に file を register
- `run`: system の PATH を使用して executable を検索し、target system 上で binary を execute
- `set_injection_technique`: post-exploitation jobs が使用する injection primitive を変更
- `shinject`: shellcode を remote process に inject し、arbitrary code の in-memory execution を可能にする
- `inject`: agent shellcode を remote process に inject し、agent code の in-memory execution を可能にする
- `spawn`: 指定した executable 内で新しい agent session を spawn し、新しい process 内で shellcode を実行できるようにする
- `spawnto_x64` および `spawnto_x86`: post-exploitation jobs で使用する default binary を指定した path に変更。非常に noisy な、params なしの `rundll32.exe` の使用を避けます。

### Mythic Forge

これは、target system 上で execute できる pre-compiled payloads と tools の repository である Mythic Forge から、**COFF/BOF** files を **load** できるようにします。load できるすべての commands を使用すれば、current agent process 内で BOFs として execute して common actions を実行できます（通常は別の process を spawn するより優れた OPSEC が得られます）。

次のコマンドで install を開始します。
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
その後、`forge_collections` を使用して Mythic Forge の COFF/BOF modules を表示し、選択したものを agent のメモリにロードして実行できるようにします。デフォルトでは、Apollo に以下の 2 つの collections が追加されます。

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

module を 1 つロードすると、`forge_bof_sa-whoami` や `forge_bof_sa-netuser` のような別の command としてリストに表示されます。

BOF については、Forge が単一のフラットな argument string を
Apollo に渡すだけではないことに注意してください。BOF parameters を Mythic の typed-array format にマッピングし、
その後 Apollo の `execute_coff` flow に転送します。Forge でロードした BOF の動作が
不安定な場合は、入力した command line だけでなく、想定される BOF argument types / entrypoint を確認してください。また、Apollo の新しい BOF loader では、
かなり古い 2.3.1-era builds と比べて argument handling が変更されている点にも注意してください。そのため、古い BOF や
old collections は、marshaling の期待値が変更されたというだけの理由で失敗することがあります。

### PowerShell & scripting execution

- `powershell_import`: 新しい PowerShell script (.ps1) を agent の cache に import し、後で実行できるようにします
- `powershell`: agent の context で PowerShell command を実行し、高度な scripting と automation を可能にします
- `powerpick`: PowerShell loader assembly を sacrificial process に inject し、PowerShell command を実行します（PowerShell logging なし）。
- `psinject`: 指定した process 内で PowerShell を実行し、別の process の context で script を対象を絞って実行できるようにします
- `shell`: agent の context で shell command を実行します。cmd.exe で command を実行する場合と同様です

### Lateral Movement

- `jump_psexec`: PsExec technique を使用して、まず Apollo agent executable (apollo.exe) をコピーし、実行することで新しい host へ lateral movement します。
- `jump_wmi`: WMI technique を使用して、まず Apollo agent executable (apollo.exe) をコピーし、実行することで新しい host へ lateral movement します。
- `link` and `unlink`: callbacks 間に P2P links（SMB/TCP など）を作成および切断します。
- `wmiexecute`: WMI を使用して local または指定した remote system 上で command を実行します。impersonation 用の credentials も指定できます。
- `net_dclist`: 指定した domain の domain controllers のリストを取得します。lateral movement の潜在的な targets の特定に役立ちます。
- `net_localgroup`: 指定した computer 上の local groups を一覧表示します。computer を指定しない場合は localhost がデフォルトになります。
- `net_localgroup_member`: local または remote computer 上にある指定した group の local group membership を取得し、特定の groups に所属する users を enumeration できるようにします。
- `net_shares`: 指定した computer 上の remote shares とその accessibility を一覧表示します。lateral movement の潜在的な targets の特定に役立ちます。
- `socks`: target network 上で SOCKS 5 compliant proxy を有効にし、compromised host 経由で traffic を tunneling できるようにします。proxychains などの tools と互換性があります。
- `rpfwd`: target host 上の指定した port で listening を開始し、Mythic 経由で remote IP と port に traffic を forward します。target network 上の services への remote access が可能になります。
- `listpipes`: local system 上のすべての named pipes を一覧表示します。IPC mechanisms との interaction による lateral movement や privilege escalation に役立ちます。

`jump_wmi` または `wmiexecute` の内部で使用される lower-level WMI execution primitives については、[WmiExec](lateral-movement/wmiexec.md) を確認してください。より広範な pivoting patterns については、[Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) を確認してください。

### Miscellaneous Commands
- `help`: 特定の commands に関する詳細情報、または agent で利用可能なすべての commands に関する一般情報を表示します。
- `clear`: tasks を 'cleared' としてマークし、agents が取得できないようにします。`all` を指定するとすべての tasks が clear され、`task Num` を指定すると特定の task が clear されます。


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon は、**Linux and macOS** executables に compile される Golang agent です。
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### 現在の build/profile に関するメモ

- 現在の Poseidon build は、`x86_64` と `arm64` の両方で Linux および macOS を対象としている。
- 対応する出力形式には、native executable に加えて、`dylib` や `so` などの shared-library 形式の出力も含まれる。
- Poseidon は `http`、`websocket`、`tcp`、`dynamichttp` をサポートしており、現在の builder は `egress_order` や failover threshold などの multi-egress 設定を公開している。
- Poseidon の現在の capability metadata には、browser scripts、file/process browser integration、interactive tasking、keylogging、screenshots、Push C2、SOCKS、rpfwd、P2P も含まれている。そのため、単純な remote shell ではなく、実際の Linux/macOS pivot node として機能できる。
- `proxy_bypass` や `garble` などの build-time option は、よりクリーンな network behavior や追加の Go binary obfuscation が必要な場合に確認する価値がある。
- `pty` は Linux/macOS の操作において、最も有用な新しい quality-of-life command の一つである。interactive PTY を開き、古い `sleep 0` + SOCKS workaround に頼らず、より完全な terminal interaction のために Mythic 側の port を公開できる。
- Poseidon の現在の docs は、macOS を重視した tradecraft において特に興味深い。`jxa` は JavaScript for Automation を in-memory で実行し、`screencapture` は logged-in desktop を取得し、`clipboard_monitor` は pasteboard の変更を stream し、`execute_library` はローカルの dylib を load してその function を呼び出し、`libinject` は remote process に on-disk dylib を load させる。
- 長時間実行する job では、Poseidon が post-exploitation work を cooperative であり、hard-kill できない goroutine/thread 内で実行することを覚えておくこと。また、docs には built-in agent obfuscation が現在存在しないことも明記されているため、高度に obfuscated な commercial implant と比べて build/profile-level tradecraft の重要性が高い。

Mythic-backed operations、JAMF abuse、または MDM-as-C2 のアイデアに関する macOS 固有の tradecraft については、[macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) を確認すること。

Linux または macOS で使用すると、いくつかの興味深い command が利用できる。

### Common actions

- `cat`: file の内容を出力する
- `cd`: 現在の working directory を変更する
- `chmod`: file の permission を変更する
- `config`: 現在の config と host information を表示する
- `cp`: file をある場所から別の場所へ copy する
- `curl`: optional header と method を指定して単一の web request を実行する
- `upload`: target に file を upload する
- `download`: target system から local machine に file を download する
- その他多数

### Sensitive Information の検索

- `triagedirectory`: host 上の directory 内から、sensitive file や credential などの興味深い file を見つける。
- `getenv`: 現在のすべての environment variable を取得する。

### macOS-specific tradecraft

- `jxa`: `OSAScript` を介して JavaScript for Automation を in-memory で実行する。個別の script file を drop せずに native macOS post-exploitation を行う場合に有用。
- `clipboard_monitor`: pasteboard を poll し、変更を Mythic に報告する。copy/paste に依存する credential/token theft workflow に便利。
- `screencapture`: macOS 上で user の desktop を capture する。
- `execute_library`: disk 上の dylib を load し、特定の exported function を呼び出す。
- `libinject`: 別の macOS process に disk 上の dylib を load させる shellcode stub を inject する。
- `persist_launchd`: agent から直接、LaunchAgent / LaunchDaemon persistence を作成する。

### Laterally move

- `ssh`: 指定された credential を使用して host に SSH 接続し、ssh を spawn せずに PTY を開く。
- `sshauth`: 指定された credential を使用して指定 host に SSH 接続する。これを使用して SSH 経由で remote host 上の特定の command を実行したり、file を SCP したりすることもできる。
- `link_tcp`: TCP 経由で別の agent に link し、agent 間の直接 communication を可能にする。
- `link_webshell`: webshell P2P profile を使用して agent に link し、agent の web interface への remote access を可能にする。
- `rpfwd`: Reverse Port Forward を Start または Stop し、target network 上の service への remote access を可能にする。
- `socks`: target network 上で SOCKS5 proxy を Start または Stop し、compromised host を介した traffic の tunneling を可能にする。proxychains などの tool と互換性がある。
- `portscan`: host の open port を scan し、lateral movement やさらなる attack の潜在的な target を特定するのに役立つ。

### Process execution

- `shell`: /bin/sh 経由で単一の shell command を実行し、target system 上で command を直接実行できるようにする。
- `run`: disk 上の command を argument 付きで実行し、target system 上で binary や script を実行できるようにする。
- `pty`: interactive PTY を開き、target system 上の shell を直接操作できるようにする。






## 参考資料

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
