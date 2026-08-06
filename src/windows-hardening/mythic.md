# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythicとは？

Mythicは、red teaming向けに設計された、open-sourceでmodularかつcollaborativeなcommand and control (C2) frameworkです。Windows、Linux、macOSなど、異なるoperating system上でagents (payloads)を管理およびdeployできます。Mythicは、multi-operator tasking、file handling、SOCKS/rpfwd management、payload generationのためのbrowser UIを提供します。

monolithic frameworkとは異なり、Mythic repository自体にはpayload typesやC2 profilesは含まれていません。Agents、wrappers、C2 profilesは通常、external componentsとしてinstallされ、Mythic coreとは独立して更新できます。

### Installation

Mythicをinstallするには、公式の**[Mythic repo](https://github.com/its-a-feature/Mythic)**の手順に従ってください。Mythic directoryからの一般的なbootstrapは次のとおりです。
```bash
sudo make
sudo ./mythic-cli start
```
Mythicがすでに実行中であれば、通常は`./mythic-cli install github ...`で新しいagentまたはprofileを追加し、その後Mythicを再起動するか、新しいcomponentを直接起動できます。

### Agents

Mythicは複数のagentをサポートしています。agentは、**侵害されたシステム上でタスクを実行するpayload**です。各agentは特定のニーズに合わせて調整でき、異なるオペレーティングシステム上で実行できます。

デフォルトでは、Mythicにagentはインストールされていません。オープンソースコミュニティのagentは[**https://github.com/MythicAgents**](https://github.com/MythicAgents)にあり、[**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html)を使うと、サポートされているオペレーティングシステム、payload formats、wrappers、C2 profilesをすばやく確認できます。<sup>[[1]](#references)</sup>

そのorgからagentをインストールするには、次のコマンドを実行します。
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E`形式は、非root環境からインストールする場合に便利です。Mythicがすでに実行中であっても、前のコマンドを使って新しいagentを追加できます。

### C2 Profiles

MythicのC2 profilesは、**agentがMythic serverと通信する方法**を定義します。通信プロトコル、暗号化方式、その他の設定を指定します。Mythicのweb interfaceからC2 profilesを作成および管理できます。

デフォルトでは、Mythicはprofilesなしでインストールされますが、次のコマンドを実行してrepo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles)からいくつかのprofilesをdownloadできます：
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): 基本的な非同期 GET/POST traffic。
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 複数の callback domains、fail-over/round-robin rotation、custom headers/query parameters、および cookies、headers、query parameters、または body に配置する message transforms (`base64`、`base64url`、`xor`、`netbios`、`prepend`、`append`) に対応した、より柔軟な HTTP traffic。
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): static な `http` profile が認識されやすすぎる場合に使用できる、JSON/TOML-driven HTTP message shaping。

### Current platform notes

- 多くの public agents と profiles は現在、pre-built remote container images を使ってインストールされます。
コンポーネントを fork したり、ローカルで patch を適用したりした後も Mythic が古い
behavior を使い続ける場合は、生成された `.env` entries で
`*_REMOTE_IMAGE`、`*_USE_BUILD_CONTEXT`、`*_USE_VOLUME` を確認してください。
通常、`*_USE_BUILD_CONTEXT="true"` を有効にすると、Mythic は
remote image を黙って再利用する代わりに、ローカルの Docker context から再 build します。
- Browser scripts は operators にとって Mythic の最も価値の高い quality-of-life features の一つです。
raw command output を tables、screenshot viewers、download links、search links、さらに UI から follow-on
tasking を直接発行する buttons に変換できます。現在の Mythic builds では、各 operator が
独自の scripts を保持し、それらを global または task ごとに toggle できます。また、agents が plaintext
ではなく structured JSON を返す場合に最良の結果が得られます。これは、繰り返し行う `ls`、`ps`、triage、
および file-browser workflows で特に有用です。<sup>[[4]](#references)[[6]](#references)</sup>
- 新しい Mythic builds は interactive tasking と Push C2 patterns にも対応しており、PTY/SOCKS/rpfwd-heavy
operations で `sleep 0` polling に依存する必要性を減らします。agent/profile がこれに対応している場合、
interactive channel を使える状態に保つためだけに constant check-ins で server を叩き続けるより、
通常は overhead が低くなります。<sup>[[3]](#references)</sup>
- 現在の 3.4-era Mythic builders は、古い writeups が示唆するよりも context-aware です。
build parameters は、選択された OS やその他の build options に基づいて grouped または hidden にでき、
payload types は一つの build で複数の C2 profiles、または同じ C2 の複数 instances を
support するかどうかを宣言できます。また、C2 parameter deviations により、agent が実際には
implement していない fields を隠すこともできます。これは `http`、`httpx`、`smb`、
`tcp`、`websocket` の間を切り替える際に重要です。safe/valid build surface はもはや
flat な static form ではないためです。<sup>[[5]](#references)</sup>
- custom agent/profile pair を build しており、wire 上で Mythic の
JSON message format や default crypto を使いたくない場合は、
`translation_container` を使用してください。Mythic は UUID を取り除き、encrypted blob と key material を
gRPC 経由で translator に渡し、agent-native bytes が返されることを期待します。これは
binary protocols、custom framing、または agent-side encryption を、server 全体を書き換えずに
サポートするための clean な方法です。
- linked/P2P callbacks は単に tasking を中継するだけではないことに注意してください。Mythic の
`get_tasking` flow は、responses に加えて `delegates`、
`socks`、`rpfwd`、`interactive` data も運べます。実際には、1 つの egress callback で
同じ polling loop 内の inner callbacks と pivot channels を処理できます。child
agents が独自に periodic check-ins を実行する場合、`get_delegate_tasks=false` により
parent が inner callback の queued jobs を誤って消費するのを防げます。

### Wrapper payloads

Wrapper payloads を使うと、同じ agent logic を維持したまま、delivery または persistence 用に on-disk representation を変更できます。

- `service_wrapper`: 別の payload を Windows service executable に変換します。execution path が有効な service binary を要求する場合に便利です。
- `scarecrow_wrapper`: compatible shellcode を ScareCrow loader で wrap し、EXE/DLL/CPL などの loader-backed outputs を生成します。

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo は、SpecterOps の training offerings で使用するために設計された、4.0 .NET Framework を使用する C# 製の Windows agent です。<sup>[[2]](#references)</sup>

次のコマンドで install します:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### 現在の build/profile に関する注意事項

- Apollo は現在、`WinExe`、`Shellcode`、`Service`、`Source` の payload を生成できます。
- 一般的に使用される Apollo profiles は `http`、`httpx`、`smb`、`tcp`、`websocket` です。
- `httpx` は、古い static な `http` profile の代わりに、domain rotation、proxy support、custom message placement、message transforms が必要な場合に、通常はより柔軟な選択肢です。
- Apollo はより feature-complete な community agents の 1 つで、現在、browser scripts、file/process browser views、screenshots、keylogging、SOCKS、rpfwd、Push C2、P2P routing など、Mythic-side integrations を提供しています。
- Apollo は `service_wrapper` や `scarecrow_wrapper` などの wrapper payloads をサポートしています。
- Apollo は dynamic command loading をサポートしているため、初期 payload を軽量に保ち、すべての post-ex capabilities を最初の build にコンパイルする代わりに、後から追加の commands や Forge modules を load できます。
- shellcode output を生成する場合、Apollo の現在の builder は Donut format の選択肢（`Binary`、`Base64`、`C`、`Ruby`、`Python`、`Powershell`、`C#`、`Hex`）と Donut bypass behavior（`None`、`Abort on fail`、`Continue on fail`）も提供します。これは、shellcode を `service_wrapper`、`scarecrow_wrapper`、または custom loader で再度 wrap することが最終目的の場合に便利です。
- `register_file` と `register_assembly` は、`execute_assembly`、`execute_pe`、`inline_assembly`、`execute_coff`、`powershell_import`、`powerpick` の staging primitives です。現在の Apollo builds では、これらの staged artifacts は、DPAPI で保護された AES256 blobs として client-side に cache されます。
- `ls` と `ps` の結果は、Mythic の browser scripts および file/process browser と特にうまく統合されるため、collaborative operations における operator triage が大幅に高速化されます。
- Apollo の fork-and-run jobs は、`spawnto_x86` / `spawnto_x64` から sacrificial process settings を継承し、`ppid` から parent selection を継承して、その後、現在選択されている injection primitive を使用します。実際には、ある command に対する OPSEC tuning が、`execute_assembly`、`powerpick`、`mimikatz`、`pth`、`dcsync`、`execute_pe`、`spawn` に同時に影響することを意味します。
- 現在 documented されている Apollo の injection backends には、syscalls 経由の `CreateRemoteThread`、`QueueUserAPC`（early-bird style）、`NtCreateThreadEx` が含まれます。noisy な post-exploitation の前に `get_injection_techniques` を使用し、target または実行したい command と衝突する primitive から切り替える必要がある場合は `set_injection_technique` を使用してください。
- `blockdlls` は、post-exploitation jobs 用に作成された sacrificial processes にのみ影響します。default の bare `rundll32.exe` よりも suspicious でない `spawnto_x64` target と組み合わせることで、assembly/PowerShell-heavy tasking を実行する前に行える、Apollo-side で最も簡単な変更の 1 つです。

この agent には多くの commands があり、いくつかの extras を備えた Cobalt Strike の Beacon と非常によく似ています。主なサポート内容は次のとおりです。

### Common actions

- `cat`: ファイルの内容を表示
- `cd`: 現在の working directory を変更
- `cp`: ある場所から別の場所へファイルをコピー
- `ls`: 現在の directory または指定した path 内の files と directories を一覧表示
- `ifconfig`: network adapters と interfaces を取得
- `netstat`: TCP および UDP connection information を取得
- `pwd`: 現在の working directory を表示
- `ps`: target system 上で実行中の processes を一覧表示（追加情報付き）
- `jobs`: long-running tasking に関連付けられた、実行中のすべての jobs を一覧表示
- `download`: target system から local machine へファイルを download
- `upload`: local machine から target system へファイルを upload
- `reg_query`: target system 上の registry keys と values を query
- `reg_write_value`: 指定した registry key に新しい value を書き込み
- `sleep`: agent の sleep interval を変更。これは Mythic server に check in する頻度を決定します
- その他にも多数あります。利用可能な commands の完全な一覧を確認するには `help` を使用してください。

### Privilege escalation

- `getprivs`: current thread token で可能な限り多くの privileges を有効化
- `getsystem`: winlogon への handle を開いて token を duplicate し、実質的に privileges を SYSTEM level へ escalate
- `make_token`: 新しい logon session を作成して agent に適用し、別の user の impersonation を可能にする
- `steal_token`: 別の process から primary token を steal し、agent がその process の user を impersonate できるようにする
- `pth`: Pass-the-Hash attack。plaintext password を必要とせず、NTLM hash を使用して user として authenticate できるようにする
- `mimikatz`: Mimikatz commands を実行し、memory または SAM database から credentials、hashes、その他の sensitive information を extract
- `rev2self`: agent の token を primary token に revert し、privileges を元の level へ effectively drop
- `ppid`: 新しい parent process ID を指定して post-exploitation jobs の parent process を変更し、job execution context をより適切に制御
- `printspoofer`: PrintSpoofer commands を実行して print spooler security measures を bypass し、privilege escalation または code execution を可能にする
- `dcsync`: user の Kerberos keys を local machine に sync し、offline password cracking またはさらなる attacks を可能にする
- `ticket_cache_add`: current logon session または指定した session に Kerberos ticket を追加し、ticket reuse または impersonation を可能にする

### Process execution

- `assembly_inject`: .NET assembly loader を remote process に inject
- `blockdlls`: post-exploitation jobs への non-Microsoft signed DLLs の load を block
- `execute_assembly`: agent の context で .NET assembly を execute
- `execute_coff`: COFF file を memory 内で execute し、compiled code の in-memory execution を可能にする
- `execute_pe`: unmanaged executable（PE）を execute
- `keylog_inject`: keylogger を別の process に inject し、keystrokes を Mythic の keylog view に stream
- `screenshot` / `screenshot_inject`: 現在の desktop を直接 capture、または screenshot assembly を target process/session に inject して capture
- `get_injection_techniques`: 利用可能な injection techniques と現在選択されている technique を表示
- `inline_assembly`: disposable AppDomain で .NET assembly を execute し、agent の main process に影響を与えずに code を一時的に execute
- `register_assembly`: 後で execute するために .NET assembly を register
- `register_file`: 後で `execute_*` または PowerShell tasking に使用するため、agent cache に file を register
- `run`: system の PATH を使用して executable を探し、target system 上で binary を execute
- `set_injection_technique`: post-exploitation jobs が使用する injection primitive を変更
- `shinject`: shellcode を remote process に inject し、arbitrary code の in-memory execution を可能にする
- `inject`: agent shellcode を remote process に inject し、agent code の in-memory execution を可能にする
- `spawn`: 指定した executable 内で新しい agent session を spawn し、新しい process で shellcode を execute
- `spawnto_x64` と `spawnto_x86`: post-exploitation jobs で使用する default binary を指定した path に変更。非常に noisy な、params なしの `rundll32.exe` の使用を避けます。

### Mythic Forge

これは、target system 上で execute できる pre-compiled payloads と tools の repository である Mythic Forge から、**COFF/BOF** files を load できるようにします。load できるすべての commands により、current agent process 内で BOFs として execute して common actions を実行できます（通常、separate process を spawn するよりも優れた OPSEC を実現できます）。

次のコマンドで install を開始します：
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
次に、`forge_collections` を使用して Mythic Forge の COFF/BOF modules を表示し、選択して agent のメモリにロードし、実行できるようにします。デフォルトでは、Apollo に次の 2 つの collections が追加されています。

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

1 つの module がロードされると、`forge_bof_sa-whoami` や `forge_bof_sa-netuser` のような別の command としてリストに表示されます。

BOF については、Forge が Apollo に単一のフラットな引数文字列を渡すだけではないことに注意してください。BOF parameters を Mythic の typed-array format にマッピングし、それらを Apollo の `execute_coff` flow に転送します。Forge でロードした BOF の動作が不安定な場合は、入力した command line だけでなく、想定される BOF argument types / entrypoint を確認してください。また、Apollo の新しい BOF loader では、かなり古い 2.3.1-era builds と比べて argument handling が変更されています。そのため、古い BOF や old collections は、marshaling の想定が変更されたことだけが原因で失敗する場合があります。

### PowerShell & scripting execution

- `powershell_import`: 新しい PowerShell script (.ps1) を agent cache に import し、後で実行できるようにします
- `powershell`: agent の context で PowerShell command を実行し、高度な scripting と automation を可能にします
- `powerpick`: PowerShell loader assembly を sacrificial process に inject し、PowerShell command を実行します（PowerShell logging なし）。
- `psinject`: 指定した process で PowerShell を実行し、別の process の context で script を対象を絞って実行できるようにします
- `shell`: agent の context で shell command を実行します。cmd.exe で command を実行する場合と同様です

### Lateral Movement

- `jump_psexec`: 最初に Apollo agent executable (apollo.exe) をコピーして実行することで、PsExec technique を使用して新しい host へ lateral movement を行います。
- `jump_wmi`: 最初に Apollo agent executable (apollo.exe) をコピーして実行することで、WMI technique を使用して新しい host へ lateral movement を行います。
- `link` と `unlink`: callbacks 間に P2P links（SMB/TCP など）を作成および切断します。
- `wmiexecute`: WMI を使用して local または指定した remote system 上で command を実行します。impersonation 用の credentials も指定できます。
- `net_dclist`: 指定した domain の domain controllers のリストを取得します。lateral movement の潜在的な targets の特定に役立ちます。
- `net_localgroup`: 指定した computer 上の local groups を一覧表示します。computer を指定しない場合は localhost がデフォルトになります。
- `net_localgroup_member`: local または remote computer 上の指定した group の local group membership を取得し、特定の groups に所属する users を enumeration できるようにします。
- `net_shares`: 指定した computer 上の remote shares とその accessibility を一覧表示します。lateral movement の潜在的な targets の特定に役立ちます。
- `socks`: target network 上で SOCKS 5 compliant proxy を有効にし、compromised host 経由で traffic を tunneling できるようにします。proxychains などの tools と互換性があります。
- `rpfwd`: target host 上の指定した port で listening を開始し、Mythic 経由で traffic を remote IP と port に forward します。target network 上の services への remote access を可能にします。
- `listpipes`: local system 上のすべての named pipes を一覧表示します。IPC mechanisms との interaction による lateral movement や privilege escalation に役立ちます。

`jump_wmi` または `wmiexecute` の内部で使用される lower-level WMI execution primitives については、[WmiExec](lateral-movement/wmiexec.md) を確認してください。より広範な pivoting patterns については、[Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) を確認してください。

### Miscellaneous Commands
- `help`: 特定の commands に関する詳細情報、または agent で利用可能なすべての commands に関する一般情報を表示します。
- `clear`: tasks を 'cleared' としてマークし、agents が取得できないようにします。`all` を指定するとすべての tasks を clear でき、`task Num` を指定すると特定の task を clear できます。


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon は、**Linux and macOS** executables に compile される Golang agent です。
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### 現在の build/profile に関する注記

- 現在の Poseidon build は、`x86_64` と `arm64` の両方で Linux および macOS を対象としている。
- 対応する出力形式には、ネイティブ実行ファイルに加えて、`dylib` や `so` などの shared-library 形式の出力が含まれる。
- Poseidon は `http`、`websocket`、`tcp`、`dynamichttp` をサポートしており、現在の builder は `egress_order` や failover のしきい値など、複数 egress の設定を公開している。
- Poseidon の現在の capability metadata では、browser scripts、file/process browser integration、interactive tasking、keylogging、screenshots、Push C2、SOCKS、rpfwd、P2P も提供されている。そのため、単純な remote shell にとどまらず、実際の Linux/macOS pivot node として動作できる。
- `proxy_bypass` や `garble` などの build-time オプションは、よりクリーンなネットワーク動作や、追加の Go binary obfuscation が必要な場合に確認する価値がある。
- `pty` は Linux/macOS のオペレーションで特に便利な、より新しい quality-of-life コマンドの 1 つである。interactive PTY を開き、従来の `sleep 0` + SOCKS workaround に頼ることなく、より完全な terminal interaction のための Mythic 側 port を公開できる。
- Poseidon の現在の docs は、macOS を中心とした tradecraft において特に興味深い。`jxa` は JavaScript for Automation を in-memory で実行し、`screencapture` はログイン中の desktop を取得し、`clipboard_monitor` は pasteboard の変更を stream し、`execute_library` はローカルの dylib を load してその function を呼び出し、`libinject` はリモート process に disk 上の dylib を load させる。
- 長時間実行する job では、Poseidon が post-exploitation の処理を、強制 kill ではなく協調的に動作する goroutine/thread で実行することに注意する。また、docs には現在 built-in agent obfuscation がないことも明記されているため、高度に obfuscated な commercial implant と比べて、build/profile レベルの tradecraft がより重要になる。

Mythic を基盤としたオペレーション、JAMF abuse、または MDM-as-C2 のアイデアに関する macOS 固有の tradecraft については、[macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) を確認すること。

Linux または macOS で使用すると、いくつかの興味深い command を利用できる。

### Common actions

- `cat`: ファイルの内容を表示する
- `cd`: 現在の working directory を変更する
- `chmod`: ファイルの permissions を変更する
- `config`: 現在の config と host 情報を表示する
- `cp`: ファイルを 1 つの場所から別の場所へコピーする
- `curl`: 任意の headers と method を指定して、単一の web request を実行する
- `upload`: target にファイルを upload する
- `download`: target system から local machine にファイルを download する
- その他多数

### Search Sensitive Information

- `triagedirectory`: host 上の directory 内から、sensitive files や credentials などの興味深いファイルを探す。
- `getenv`: 現在のすべての environment variables を取得する。

### macOS-specific tradecraft

- `jxa`: `OSAScript` 経由で JavaScript for Automation を in-memory で実行する。個別の script files を drop せずに、macOS native の post-exploitation を行う場合に便利である。
- `clipboard_monitor`: pasteboard を polling し、変更を Mythic に報告する。copy/paste に依存する credential/token theft workflows に便利である。
- `screencapture`: macOS 上で user の desktop を capture する。
- `execute_library`: disk 上の dylib を load し、指定した exported function を呼び出す。
- `libinject`: 別の macOS process に disk 上の dylib を load させる shellcode stub を inject する。
- `persist_launchd`: agent から直接、LaunchAgent / LaunchDaemon persistence を作成する。

### Move laterally

- `ssh`: 指定された credentials を使用して host に SSH 接続し、ssh を spawn せずに PTY を開く。
- `sshauth`: 指定された credentials を使用して、指定した host(s) に SSH 接続する。これを使用して、SSH 経由で remote hosts 上の特定の command を実行したり、SCP で files を転送したりすることもできる。
- `link_tcp`: TCP 経由で別の agent に link し、agent 間の直接 communication を可能にする。
- `link_webshell`: webshell P2P profile を使用して agent に link し、agent の web interface への remote access を可能にする。
- `rpfwd`: Reverse Port Forward を Start または Stop し、target network 上の services への remote access を可能にする。
- `socks`: target network 上で SOCKS5 proxy を Start または Stop し、compromised host 経由で traffic を tunnel できるようにする。proxychains などの tools と互換性がある。
- `portscan`: host(s) の open ports を scan する。lateral movement や追加の attacks における potential targets の特定に役立つ。

### Process execution

- `shell`: `/bin/sh` 経由で単一の shell command を実行し、target system 上で直接 command を実行できるようにする。
- `run`: disk 上の command を arguments 付きで実行し、target system 上で binaries や scripts を実行できるようにする。
- `pty`: interactive PTY を開き、target system 上の shell を直接操作できるようにする。

## References

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
