# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#3f17" id="3f17"></a>

**请查看原始文章，了解[有关此技术的全部信息](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。**<sup>[[1]](#references)</sup>

简而言之，控制用户或计算机的 **`msDS-KeyCredentialLink`** 后，攻击者可以添加 key credential，使用 PKINIT 以该对象身份进行身份验证，并且在 KDC 和账户支持必要流程时，使用生成的票据配合 `S4U2Self`/user-to-user 来获取该对象的 NT hash。<sup>[[1]](#references)</sup>

文章中介绍了一种设置**公钥-私钥身份验证凭据**的方法，用于获取包含目标 NTLM hash 的唯一 **Service Ticket**。此过程涉及特权属性证书（PAC）中经过加密的 NTLM_SUPPLEMENTAL_CREDENTIAL，而该凭据可以被解密。<sup>[[1]](#references)</sup>

### 要求

要应用此技术，必须满足以下条件：<sup>[[1]](#references)</sup>

- 至少需要一个 Windows Server 2016 Domain Controller。
- Domain Controller 必须安装服务器身份验证数字证书。
- 目录架构必须包含 `msDS-KeyCredentialLink`；研究中描述的实际平台要求是 Windows Server 2016 或更高版本的 DC，以及 KDC 上支持 PKINIT 的证书。应验证域的架构/DC 组合，而不能仅根据域功能级别标签判断是否具备利用条件。
- 需要一个拥有委派权限、能够修改目标对象的 msDS-KeyCredentialLink 属性的账户。

## 滥用

对计算机对象滥用 Key Trust 所涉及的步骤不止是获取 Ticket Granting Ticket（TGT）和 NTLM hash。可选操作包括：<sup>[[1]](#references)</sup>

1. 创建 **RC4 silver ticket**，以便在目标主机上充当特权用户。
2. 使用 TGT 配合 **S4U2Self** 模拟 **特权用户**，这需要修改 Service Ticket，在 service name 中添加 service class。

Key Trust abuse 的一个重要优势是仅限于攻击者生成的私钥，无需将委派权限授予可能存在漏洞的账户，也不需要创建计算机账户，而计算机账户可能难以删除。<sup>[[1]](#references)</sup>

## 工具

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker 使用 DSInternals 通过 C# 操作 `msDS-KeyCredentialLink`。Whisker 及其 Python 对应工具 **pyWhisker** 支持添加、列出、删除和清除 key credentials。<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** 的功能包括：

- **Add**：生成密钥对并添加 key credential。
- **List**：显示所有 key credential 条目。
- **Remove**：删除指定的 key credential。
- **Clear**：清除所有 key credentials，可能会中断合法的 WHfB 使用。
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker 借助 Impacket 和 PyDSInternals 将该工作流带到了 **UNIX-like 系统**，包括 list/add/remove 以及 JSON import/export 操作。<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray 会枚举 operator 拥有 `GenericWrite`/`GenericAll` 等权限的域对象，尝试广泛添加 key credentials，并包含 cleanup/recursive 模式。广泛 spraying 具有破坏性且容易被发现；请使用明确的目标，并保留每个添加的 DeviceID 以便精确移除。<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials：滥用 Key Trust Account Mapping 接管账户](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - 通过操纵 msDS-KeyCredentialLink 接管 AD 账户的工具](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - 在域内 spraying Shadow Credentials 的工具](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials 工具的 Python 版本](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
