# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

近期的 Windows 构建版本引入了 **SMB client 对备用 TCP 端口的支持**。当攻击者能够：<sup>[[1]](#references)</sup>

1. 在**非 445 端口**上向攻击者控制的 listener 打开 SMB connection
2. 保持该 TCP connection 存活
3. 诱导**特权本地 client**访问**相同的 SMB share path**
4. 将产生的**本地 NTLM authentication** relay 回机器真实的 SMB service

此 primitive 是 **CVE-2026-24294** 背后的基础，该漏洞已在 **2026 年 3 月**修复。<sup>[[1]](#references)[[4]](#references)</sup>

## 原理

较早的 CMTI / serialized-SPN reflection 技巧介绍于此：

{{#ref}}
../ntlm/README.md
{{#endref}}

这一新 variant **不需要 marshalled hostname**。相反，它利用了两种 SMB client 行为：<sup>[[1]](#references)</sup>

- **Windows 11 24H2** 和 **Windows Server 2025** 上的**备用端口支持**，用户可通过 `net use \\host\share /tcpport:<port>` 使用该功能
- **SMB connection reuse / multiplexing**，多个 authenticated session 可以复用同一个 TCP connection

这意味着低权限用户可以先让 SMB client 在高端口上与攻击者的 SMB server 建立 TCP connection，然后诱导特权 service 访问**完全相同的 UNC path**。如果 Windows 决定复用现有的 TCP connection，特权 NTLM exchange 就会通过攻击者控制的 transport 发送，并可 relay 到本地 SMB server。<sup>[[1]](#references)</sup>

## 前置条件

- Target 支持 SMB 备用端口：<sup>[[2]](#references)</sup>
- **Windows 11 24H2** 或更高版本
- **Windows Server 2025** 或更高版本
- 攻击者可以在指定的高端口上运行本地或远程 SMB server
- 攻击者可以诱导特权 service 访问 UNC path
- 特权 authentication 必须是**本地 NTLM authentication**
- Target 必须可进行 relay：<sup>[[1]](#references)</sup>
- Synacktiv 报告称，该方法在 **Windows Server 2025** 上默认即可工作
- 他们的 chain 在 **Windows 11 24H2** 上无法工作，因为该系统默认强制启用 outbound SMB signing

## Userland 与内部机制

从命令行来看，该功能很简单：
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
以编程方式，client 使用带有未公开 `lpUseOptions` 数据的 `WNetAddConnection4W`。相关选项是 `TraP`（transport parameters），它最终会通过 FSCTL 到达 kernel SMB client，并由 `mrxsmb` 解析。<sup>[[1]](#references)[[3]](#references)</sup>

重要的实际注意事项：<sup>[[1]](#references)</sup>

- **UNC syntax 仍然没有 port 字段**
- **`net use` 按 logon session 区分**
- 绕过仍然有效，因为 **TCP connection 和 SMB session 是两个独立的对象**
- 如果 exploit 依赖 SMB client 重用之前创建的 TCP connection，则必须重用 **相同的 share path**

## Exploitation flow

### 1. 创建由 attacker 控制的 SMB transport

在 high port 上运行 SMB server，并让 Windows 连接到它：
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
服务器可以接受你控制的任意凭据对，例如 `user:user`。此步骤的目标还不是进行提权，而只是让 Windows SMB client 打开并保持一个指向你的 listener、可重复使用的 TCP connection。<sup>[[1]](#references)</sup>

### 2. 将 privileged service 强制访问相同的 UNC path

使用 **PetitPotam** 等 coercion primitive，针对相同的 `\\192.168.56.3\share` path 执行操作。如果被 coercion 的 client 具有 privileged 权限，且目标名称是本地目标（`localhost` 或本地 IP/host），Windows 将执行 **NTLM local authentication**。

由于 TCP connection 会被复用，该 privileged NTLM exchange 会传输到 attacker SMB service，而不是直接传输到真正的本地 SMB server。<sup>[[1]](#references)</sup>

### 3. 将 privileged authentication relay 回本地 SMB

由攻击者控制的 SMB service 将 privileged NTLM exchange 转发给 `ntlmrelayx.py`，后者再将其 relay 到该机器真正的 SMB listener，并获取一个身份为 `NT AUTHORITY\SYSTEM` 的 session。<sup>[[1]](#references)</sup>

公开 writeup 中使用的典型 tooling：<sup>[[1]](#references)</sup>

- 在 custom port 上运行 `smbserver.py`，通过复用的 TCP connection 接收 privileged auth
- 使用 `ntlmrelayx.py` 将捕获的 NTLM relay 到本地 SMB
- 使用 `PetitPotam.exe` 或其他 coercion primitive，强制触发 privileged authentication

## 操作者须知

- 这是一种 **local privilege escalation** technique，而不是通用的 remote relay 技巧<sup>[[1]](#references)</sup>
- 攻击者控制的 SMB service 必须在最初用于挂载 share 的**同一 TCP connection**上处理 privileged authentication<sup>[[1]](#references)</sup>
- 如果被 coercion 的访问命中了**不同的 share path**，Windows 可能会建立不同的 connection，从而导致该 chain 中断<sup>[[1]](#references)</sup>
- 即使 arbitrary-port 步骤能够正常工作，SMB signing requirements 仍可能使 relay 失败<sup>[[1]](#references)</sup>
- 如果你只有 Kerberos material，或无法强制执行 local NTLM，则此 exact variant 不够用<sup>[[1]](#references)</sup>

## 检测与加固

- 安装 **March 2026 Patch Tuesday** 中的 **CVE-2026-24294** 补丁<sup>[[4]](#references)</sup>
- 监控使用**非默认 SMB ports**的 `net use` 或 `New-SmbMapping`<sup>[[1]](#references)</sup>
- 对 workstation 或 server 向**高 TCP ports**发起的异常 outbound SMB 流量进行告警<sup>[[1]](#references)</sup>
- 检查 **EFSRPC / PetitPotam-style** triggers 等 coercion opportunities<sup>[[1]](#references)</sup>
- 在可能的情况下强制启用 SMB signing；Synacktiv 特别指出，这会阻止其在 Windows 11 24H2 上执行 relay<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
