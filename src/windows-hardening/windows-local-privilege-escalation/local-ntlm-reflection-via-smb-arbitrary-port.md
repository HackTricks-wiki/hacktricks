# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

最近的 Windows 构建引入了 **SMB client support for alternative TCP ports**。这个特性可被滥用于将 **local NTLM authentication** 变成 **SYSTEM local privilege escalation**，前提是攻击者可以：

1. 建立到由攻击者控制的监听器的 SMB connection，使用 **non-445 port**
2. 保持该 TCP connection 存活
3. 诱导一个 **privileged local client** 访问 **相同的 SMB share path**
4. 将产生的 **local NTLM authentication** 中继回机器的真实 SMB service

这就是 **CVE-2026-24294** 的原语，该漏洞已在 **March 2026** 修补。

## Why it works

较旧的 CMTI / serialized-SPN reflection trick 这里有说明：

{{#ref}}
../ntlm/README.md
{{#endref}}

这个更新的变体不需要 marshalled hostname。它改为滥用两个 SMB client 行为：

- **Alternative port support**，适用于 **Windows 11 24H2** 和 **Windows Server 2025**，可通过 `net use \\host\share /tcpport:<port>` 向用户暴露
- **SMB connection reuse / multiplexing**，多个 authenticated sessions 可以搭载在同一条 TCP connection 上

这意味着，低权限用户可以先让 SMB client 到攻击者 SMB server 的高端口建立一条 TCP connection，然后诱导一个特权服务访问 **完全相同的 UNC path**。如果 Windows 决定重用现有的 TCP connection，那么特权 NTLM exchange 会通过攻击者控制的 transport 发送出去，并且可以被中继到本地 SMB server。

## Preconditions

- Target 支持 SMB alternative ports:
- **Windows 11 24H2** 或更高版本
- **Windows Server 2025** 或更高版本
- 攻击者可以在指定的高端口上运行本地或远程 SMB server
- 攻击者可以诱导特权服务访问一个 UNC path
- 特权认证必须是 **NTLM local authentication**
- Target 必须可 relay:
- Synacktiv 报告称它在 **Windows Server 2025** 上默认可用
- 他们的链在 **Windows 11 24H2** 上 **不** 可用，因为那里默认强制 outbound SMB signing

## Userland and internals

从命令行看，这个特性很简单：
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatically，client 使用带有未公开 `lpUseOptions` 数据的 `WNetAddConnection4W`。相关的选项是 `TraP`（transport parameters），它最终通过 FSCTL 到达 kernel SMB client，并由 `mrxsmb` 解析。

重要实践说明：

- **UNC 语法仍然没有端口字段**
- **`net use` 是按 logon-session 生效的**
- 该 bypass 仍然有效，因为 **TCP connection 和 SMB session 是分离的对象**
- 如果 exploit 依赖 SMB client 复用之前创建的 TCP connection，那么必须复用 **相同的 share path**

## Exploitation flow

### 1. 创建 attacker-controlled 的 SMB transport

在一个高端口上运行 SMB server，并让 Windows 连接到它：
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
服务器可以接受你控制的任意凭据对，例如 `user:user`。这一步的目标还不是提权，而只是让 Windows SMB 客户端打开并保持一条可复用的 TCP 连接到你的监听器。

### 2. 通过 coercion 让特权服务访问同一个 UNC 路径

使用像 **PetitPotam** 这样的 coercion primitive，针对 **同一个** `\\192.168.56.3\share` 路径。如果被强制的客户端具有特权，并且目标名称是本地的（`localhost` 或本地 IP/主机名），Windows 会执行 **NTLM local authentication**。

由于 TCP 连接会被复用，这次特权 NTLM 交换会被发送到攻击者的 SMB 服务，而不是直接发往真正的本地 SMB 服务器。

### 3. 将特权认证转发回本地 SMB

攻击者控制的 SMB 服务把捕获到的特权 NTLM 交换转发给 `ntlmrelayx.py`，后者再把它中继到机器真实的 SMB 监听器，并以 `NT AUTHORITY\SYSTEM` 获取会话。

公开文章中的典型工具链：

- 在自定义端口上运行 `smbserver.py`，通过复用的 TCP 连接接收特权认证
- 使用 `ntlmrelayx.py` 将捕获到的 NTLM 中继到本地 SMB
- 使用 `PetitPotam.exe` 或其他 coercion primitive 强制触发特权认证

## 操作说明

- 这是一个 **local privilege escalation** 技术，不是通用的远程 relay 技巧
- 攻击者控制的 SMB 服务必须在 **同一个 TCP 连接** 上处理最初用于挂载共享的特权认证
- 如果被强制的访问命中了 **不同的共享路径**，Windows 可能会建立不同的连接，链路就会断掉
- 即使 arbitrary-port 步骤成功，SMB signing 要求也可能导致 relay 失败
- 如果你只有 Kerberos material，或者无法强制触发 local NTLM，这个特定变种就不够

## 检测与加固

- 修补 **2026 年 3 月 Patch Tuesday** 的 **CVE-2026-24294**
- 监控使用 **non-default SMB ports** 的 `net use` 或 `New-SmbMapping`
- 对工作站或服务器向 **高 TCP 端口** 的异常出站 SMB 流量告警
- 审查诸如 **EFSRPC / PetitPotam-style** 之类的 coercion 机会
- 尽可能强制启用 SMB signing；Synacktiv 明确指出这在 Windows 11 24H2 上阻止了他们的 relay

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
