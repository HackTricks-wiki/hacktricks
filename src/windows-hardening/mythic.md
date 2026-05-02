# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythicとは？

Mythicは、red teaming向けに設計された、オープンソースのモジュール式・協調型のcommand and control (C2) frameworkです。オペレーターがWindows、Linux、macOSを含む異なるOS上でagents（payloads）を管理・展開できるようにします。Mythicは、マルチオペレーターのtasking、file handling、SOCKS/rpfwd management、payload generationのためのブラウザUIを提供します。

単一体型のframeworkとは異なり、Mythicのrepository自体にはpayload typesやC2 profilesは**含まれていません**。Agents、wrappers、C2 profilesは通常、外部コンポーネントとしてインストールされ、Mythic coreとは独立して更新できます。

### Installation

Mythicをinstallするには、公式の**[Mythic repo](https://github.com/its-a-feature/Mythic)** の手順に従ってください。Mythic directoryからの一般的なbootstrapは次のとおりです:
```bash
sudo make
sudo ./mythic-cli start
```
Mythic がすでに動作している場合、通常は `./mythic-cli install github ...` で新しい agent または profile を追加し、その後 Mythic を再起動するか、新しいコンポーネントを直接起動できます。

### Agents

Mythic は複数の agents をサポートしており、これは**侵害されたシステム上でタスクを実行する payloads**です。各 agent は特定のニーズに合わせて調整でき、異なる operating systems 上で動作できます。

デフォルトでは Mythic には agents はインストールされていません。オープンソースのコミュニティ agents は [**https://github.com/MythicAgents**](https://github.com/MythicAgents) にあり、[**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) は、対応している operating systems、payload formats、wrappers、C2 profiles を素早く確認するのに便利です。

その org から agent を install するには、次を実行できます:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` 形式は、root 以外の環境からインストールする場合に便利です。Mythic がすでに実行中でも、前のコマンドで新しい agent を追加できます。

### C2 Profiles

Mythic の C2 profiles は、**agent が Mythic server とどのように通信するか**を定義します。通信プロトコル、暗号化方式、その他の設定を指定します。Mythic web interface から C2 profiles を作成・管理できます。

デフォルトでは Mythic は profiles なしでインストールされますが、repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) からいくつかの profiles をダウンロードすることも可能です。running:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): 基本的な非同期 GET/POST トラフィック。
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 複数の callback domains、fail-over/round-robin rotation、カスタムヘッダー/クエリパラメータ、メッセージ変換（`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`）を、cookies、headers、query parameters、または body に配置できる、より柔軟な HTTP トラフィック。
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): 静的な `http` profile が目立ちすぎる場合の、JSON/TOML ベースの HTTP message shaping。

### Wrapper payloads

Wrapper payloads は、同じ agent logic を保ったまま、配布または永続化される on-disk representation を変更できます。

- `service_wrapper`: 別の payload を Windows service executable に変換します。実行パスで有効な service binary が必要な場合に便利です。
- `scarecrow_wrapper`: 互換性のある shellcode を ScareCrow loader でラップし、EXE/DLL/CPL などの loader-backed outputs を生成します。

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo は、SpecterOps の training offerings で使うために設計された、4.0 .NET Framework を使用して C# で書かれた Windows agent です。

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo は現在 `WinExe`, `Shellcode`, `Service`, `Source` payloads を出力できます。
- よく使われる Apollo profiles は `http`, `httpx`, `smb`, `tcp`, `websocket` です。
- `httpx` は、domain rotation、proxy support、custom message placement、message transforms が必要で、古い static な `http` profile より柔軟な選択肢として通常使われます。
- Apollo は `service_wrapper` や `scarecrow_wrapper` のような wrapper payloads をサポートします。
- `register_file` と `register_assembly` は、`execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, `powerpick` の staging primitives です。現在の Apollo builds では、それらの staged artifacts は DPAPI-protected AES256 blobs として client-side に cache されます。
- `ls` と `ps` の結果は Mythic の browser scripts と file/process browser と特に相性がよく、これにより collaborative operations での operator triage がかなり速くなります。

This agent has a lot of commands that makes it very similar to Cobalt Strike's Beacon with some extras. Among them, it supports:

### Common actions

- `cat`: ファイルの内容を表示する
- `cd`: 現在の working directory を変更する
- `cp`: ある場所から別の場所へファイルをコピーする
- `ls`: 現在のディレクトリまたは指定した path 内のファイルとディレクトリを一覧表示する
- `ifconfig`: network adapters と interfaces を取得する
- `netstat`: TCP と UDP の connection information を取得する
- `pwd`: 現在の working directory を表示する
- `ps`: ターゲットシステム上で実行中の processes を一覧表示する（追加情報付き）
- `jobs`: 長時間実行される tasking に関連付けられたすべての running jobs を一覧表示する
- `download`: ターゲットシステムから local machine にファイルをダウンロードする
- `upload`: local machine からターゲットシステムへファイルをアップロードする
- `reg_query`: ターゲットシステム上の registry keys と values を問い合わせる
- `reg_write_value`: 指定した registry key に新しい value を書き込む
- `sleep`: agent の sleep interval を変更する。これは Mythic server への check-in の頻度を決定する
- ほかにも多数あります。利用可能な command の全一覧は `help` を参照してください。

### Privilege escalation

- `getprivs`: 現在の thread token で可能な限り多くの privileges を有効化する
- `getsystem`: winlogon を開いて token を duplicate し、事実上 SYSTEM level まで privileges を昇格する
- `make_token`: 新しい logon session を作成して agent に適用し、他の user になりすますことを可能にする
- `steal_token`: 別の process から primary token を盗み、その process の user になりすますことを可能にする
- `pth`: Pass-the-Hash attack。plaintext password を使わずに NTLM hash で user として認証できる
- `mimikatz`: Mimikatz commands を実行して credentials、hashes、その他の sensitive information を memory や SAM database から抽出する
- `rev2self`: agent の token を primary token に戻し、権限を元の level に戻す
- `ppid`: 新しい parent process ID を指定して post-exploitation jobs の parent process を変更し、job execution context をより適切に制御できるようにする
- `printspoofer`: PrintSpoofer commands を実行して print spooler security measures を回避し、privilege escalation や code execution を可能にする
- `dcsync`: user の Kerberos keys を local machine に sync し、offline password cracking やさらなる attacks を可能にする
- `ticket_cache_add`: Kerberos ticket を現在の logon session または指定した session に追加し、ticket reuse や impersonation を可能にする

### Process execution

- `assembly_inject`: .NET assembly loader を remote process に inject できるようにする
- `blockdlls`: Microsoft 署名以外の DLL が post-exploitation jobs に読み込まれるのを block する
- `execute_assembly`: agent の context で .NET assembly を実行する
- `execute_coff`: COFF file を memory 上で実行し、compiled code の in-memory execution を可能にする
- `execute_pe`: unmanaged executable (PE) を実行する
- `get_injection_techniques`: 利用可能な injection techniques と現在選択中のものを表示する
- `inline_assembly`: 使い捨ての AppDomain 内で .NET assembly を実行し、agent の main process に影響を与えずに code を一時的に実行できるようにする
- `register_assembly`: 後で実行するために .NET assembly を登録する
- `register_file`: 後で `execute_*` または PowerShell tasking に使うため、agent cache に file を登録する
- `run`: system の PATH を使って executable を探し、target system 上で binary を実行する
- `set_injection_technique`: post-exploitation jobs で使う injection primitive を変更する
- `shinject`: shellcode を remote process に inject し、任意の code の in-memory execution を可能にする
- `inject`: agent shellcode を remote process に inject し、agent の code を in-memory で実行できるようにする
- `spawn`: 指定した executable で新しい agent session を生成し、新しい process で shellcode を実行できるようにする
- `spawnto_x64` と `spawnto_x86`: `rundll32.exe` を引数なしで使うのはかなり noisy なので、その代わりに post-exploitation jobs で使う default binary を指定した path に変更する

### Mythic Forge

これにより、Mythic Forge から **COFF/BOF** files を `load` できます。Mythic Forge は、target system 上で実行できる pre-compiled payloads と tools の repository です。読み込める command がそろっているので、それらを current agent process 内で BOFs として実行し、common actions を実施できます（通常は別 process を spawn するより OPSEC が良いです）。

Start installing them with:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, `forge_collections` を使って Mythic Forge の COFF/BOF モジュールを表示し、エージェントのメモリに選択してロードして実行できるようにします。デフォルトでは、Apollo に以下の 2 つの collections が追加されています:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

1つの module がロードされると、`forge_bof_sa-whoami` や `forge_bof_sa-netuser` のような別の command として一覧に表示されます。

### PowerShell & scripting execution

- `powershell_import`: 後で実行するために、新しい PowerShell script (.ps1) をエージェントの cache に import する
- `powershell`: エージェントの context で PowerShell command を実行し、高度な scripting と automation を可能にする
- `powerpick`: PowerShell loader assembly を sacrificial process に inject して PowerShell command を実行する（powershell logging なし）。
- `psinject`: 指定した process で PowerShell を実行し、別の process の context で script を targeted に実行できるようにする
- `shell`: cmd.exe で実行するのと同様に、エージェントの context で shell command を実行する

### Lateral Movement

- `jump_psexec`: PsExec technique を使って、まず Apollo agent executable（apollo.exe）をコピーして実行することで、新しい host へ lateral に移動する
- `jump_wmi`: WMI technique を使って、まず Apollo agent executable（apollo.exe）をコピーして実行することで、新しい host へ lateral に移動する
- `link` and `unlink`: callbacks 間に P2P links（たとえば SMB/TCP 経由）を作成・解除する
- `wmiexecute`: impersonation のための optional credentials 付きで、WMI を使って local または指定した remote system で command を実行する
- `net_dclist`: 指定した domain の domain controllers の list を取得する。lateral movement の potential targets の特定に役立つ
- `net_localgroup`: 指定した computer 上の local groups を一覧表示する。computer が指定されない場合は localhost が default
- `net_localgroup_member`: local または remote computer 上の指定した group の local group membership を取得し、特定の groups に属する users を enumerate できるようにする
- `net_shares`: 指定した computer 上の remote shares とその accessibility を一覧表示する。lateral movement の potential targets の特定に役立つ
- `socks`: target network 上で SOCKS 5 compliant proxy を有効にし、compromised host 経由で traffic を tunneling できるようにする。proxychains のような tools と互換性がある
- `rpfwd`: target host 上の指定した port で listening を開始し、traffic を Mythic 経由で remote IP と port に forward することで、target network 上の services へ remote access できるようにする
- `listpipes`: local system 上のすべての named pipes を一覧表示する。IPC mechanisms と interaction することで、lateral movement や privilege escalation に役立つことがある

`jump_wmi` や `wmiexecute` の下で使われる低レベルの WMI execution primitives については、[WmiExec](lateral-movement/wmiexec.md) を確認してください。より広い pivoting patterns については、[Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md) を確認してください。

### Miscellaneous Commands
- `help`: エージェント内の特定の command についての詳細情報、または利用可能なすべての command の一般情報を表示する
- `clear`: task を 'cleared' としてマークし、agents が取得できないようにする。すべての task を消去するには `all`、特定の task を消去するには `task Num` を指定できる


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon は **Linux and macOS** executables に compile される Golang agent です。
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### 現在の build/profile ノート

- 現在の Poseidon builds は Linux と macOS の両方で、`x86_64` と `arm64` を対象にしています。
- 対応する出力形式には、ネイティブ実行ファイルに加えて、`dylib` や `so` のような shared-library 形式の出力が含まれます。
- Poseidon は `http`, `websocket`, `tcp`, `dynamichttp` をサポートしており、現在の builders は `egress_order` や failover thresholds のような multi-egress 設定を公開しています。
- `proxy_bypass` や `garble` のような build-time オプションは、よりクリーンな network behavior や追加の Go binary obfuscation が必要なときに確認する価値があります。

Mythic ベースの operation における macOS 特有の tradecraft、JAMF abuse、または MDM-as-C2 のアイデアについては、[macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md) を確認してください。

Linux または macOS で使用すると、いくつか興味深いコマンドがあります:

### Common actions

- `cat`: ファイルの内容を表示する
- `cd`: 現在の作業ディレクトリを変更する
- `chmod`: ファイルの権限を変更する
- `config`: 現在の config と host information を表示する
- `cp`: ある場所から別の場所へファイルをコピーする
- `curl`: オプションのヘッダーや method を指定して単一の web request を実行する
- `upload`: ターゲットへファイルをアップロードする
- `download`: ターゲットシステムからローカルマシンへファイルをダウンロードする
- その他多数

### Search Sensitive Information

- `triagedirectory`: ホスト上の directory 内で、sensitive files や credentials などの興味深いファイルを探す。
- `getenv`: 現在のすべての environment variables を取得する。

### Move laterally

- `ssh`: 指定された credentials を使用して host に SSH し、ssh を起動せずに PTY を開く。
- `sshauth`: 指定された credentials を使用して、指定した host(s) に SSH する。これを使って SSH 経由で remote hosts 上の特定の command を実行したり、SCP でファイルを使用したりすることもできます。
- `link_tcp`: TCP 経由で別の agent にリンクし、agent 間で直接通信できるようにする。
- `link_webshell`: webshell P2P profile を使用して agent にリンクし、agent の web interface へ remote access できるようにする。
- `rpfwd`: Reverse Port Forward を開始または停止し、target network 上の services へ remote access できるようにする。
- `socks`: target network 上で SOCKS5 proxy を開始または停止し、compromised host を経由して traffic を tunneling する。proxychains のような tools と互換性があります。
- `portscan`: host(s) の open ports をスキャンし、lateral movement やさらなる attacks の potential targets を特定するのに役立つ。

### Process execution

- `shell`: /bin/sh 経由で単一の shell command を実行し、target system 上で command を直接実行できるようにする。
- `run`: arguments 付きで disk 上の command を実行し、target system 上で binaries や scripts を実行できるようにする。
- `pty`: インタラクティブな PTY を開き、target system 上の shell と直接やり取りできるようにする。




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
