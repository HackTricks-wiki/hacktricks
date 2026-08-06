# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## 介绍 <a href="#3f17" id="3f17"></a>

**请查看原始文章，了解[有关此技术的所有信息](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。**<sup>[[1]](#references)</sup>

**总结**：如果你可以写入用户或计算机的 **msDS-KeyCredentialLink** 属性，就可以获取该对象的 **NT hash**。<sup>[[1]](#references)</sup>

文章中概述了一种设置**公钥-私钥身份验证凭据**的方法，用于获取唯一的 **Service Ticket**，其中包含目标的 NTLM hash。此过程涉及 Privilege Attribute Certificate (PAC) 中经过加密的 NTLM_SUPPLEMENTAL_CREDENTIAL，而该凭据可以被解密。<sup>[[1]](#references)</sup>

### 要求

要应用此技术，必须满足以下条件：<sup>[[1]](#references)</sup>

- 至少需要一个 Windows Server 2016 Domain Controller。
- Domain Controller 必须安装服务器身份验证数字证书。
- Active Directory 必须处于 Windows Server 2016 Functional Level。
- 需要一个具有委派权限、可以修改目标对象的 msDS-KeyCredentialLink 属性的账户。

## 滥用

对计算机对象滥用 Key Trust，除了获取 Ticket Granting Ticket (TGT) 和 NTLM hash 外，还包括其他步骤。可选方案包括：<sup>[[1]](#references)</sup>

1. 创建 **RC4 silver ticket**，以目标主机上的特权用户身份执行操作。
2. 使用 TGT 配合 **S4U2Self** 冒充**特权用户**，这需要修改 Service Ticket，以便向服务名称添加 service class。

Key Trust abuse 的一个重要优势是仅限于攻击者生成的私钥，不需要将委派权限授予可能存在漏洞的账户，也不需要创建计算机账户，而计算机账户可能很难删除。<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

它基于 DSInternals，为此攻击提供了 C# 接口。Whisker 及其 Python 对应工具 **pyWhisker** 可以操作 `msDS-KeyCredentialLink` 属性，从而控制 Active Directory 账户。这些工具支持对目标对象的 key credentials 执行添加、列出、删除和清除等操作。

**Whisker** 的功能包括：

- **Add**：生成密钥对并添加 key credential。
- **List**：显示所有 key credential 条目。
- **Remove**：删除指定的 key credential。
- **Clear**：清除所有 key credential，可能会干扰合法的 WHfB 使用。
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

它将 Whisker 的功能扩展到 **基于 UNIX 的系统**，利用 Impacket 和 PyDSInternals 提供全面的 exploitation 能力，包括列出、添加和移除 KeyCredentials，以及以 JSON 格式导入和导出这些凭据。
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray 旨在**利用广泛用户组可能对 domain objects 拥有的 GenericWrite/GenericAll permissions**，以广泛应用 ShadowCredentials。它包括登录 domain、验证 domain's functional level、枚举 domain objects，并尝试添加 KeyCredentials 以获取 TGT 和揭示 NT hash。Cleanup options 和 recursive exploitation tactics 进一步增强了其实用性。

## References

- [1] [Shadow Credentials: 滥用 Key Trust Account Mapping 进行 Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - 通过操纵 msDS-KeyCredentialLink 接管 AD accounts 的 Tool](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - 用于在 domain 中 spray Shadow Credentials 的 Tool](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials tool 的 Python 版本](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
