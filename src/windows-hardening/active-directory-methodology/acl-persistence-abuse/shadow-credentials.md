# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#3f17" id="3f17"></a>

**请查看原文，了解[有关此技术的全部信息](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)。**<sup>[[1]](#references)</sup>

简而言之，控制用户或计算机的 **`msDS-KeyCredentialLink`**，可以让攻击者添加密钥凭据，通过 PKINIT 以该对象的身份进行身份验证；如果 KDC 和账户支持必要的流程，还可以使用生成的票据，通过 `S4U2Self`/user-to-user 获取该对象的 NT hash。<sup>[[1]](#references)</sup>

原文介绍了一种设置**公私钥认证凭据**的方法，用于获取包含目标 NTLM hash 的唯一 **Service Ticket**。此过程涉及 Privilege Attribute Certificate (PAC) 中经过加密的 NTLM_SUPPLEMENTAL_CREDENTIAL，该凭据可以被解密。<sup>[[1]](#references)</sup>

### 要求

要使用此技术，必须满足以下条件：<sup>[[1]](#references)</sup>

- 至少需要一台 Windows Server 2016 Domain Controller。
- Domain Controller 必须安装服务器身份验证数字证书。
- 目录架构必须包含 `msDS-KeyCredentialLink`；研究中提到的实际平台要求是 Windows Server 2016 或更新版本的 DC，以及 KDC 上支持 PKINIT 的证书。请核实域中的架构/DC 组合，而不要仅凭域功能级别标签判断是否可利用。
- 账户必须具有修改目标对象的 msDS-KeyCredentialLink 属性的委派权限。

## 滥用

针对计算机对象滥用 Key Trust，除了获取 Ticket Granting Ticket (TGT) 和 NTLM hash 外，还可以执行其他步骤。选项包括：<sup>[[1]](#references)</sup>

1. 创建 **RC4 silver ticket**，以目标主机上的特权用户身份执行操作。
2. 使用 TGT 通过 **S4U2Self** 冒充**特权用户**；这需要修改 Service Ticket，将服务类添加到服务名称中。

滥用 Key Trust 的一个重要优势是，攻击仅依赖攻击者生成的私钥，不需要委派给可能存在漏洞的账户，也不需要创建可能难以删除的计算机账户。<sup>[[1]](#references)</sup>

## 工具

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker 使用 DSInternals 从 C# 操作 `msDS-KeyCredentialLink`。Whisker 及其 Python 对应工具 **pyWhisker** 支持添加、列出、移除和清除密钥凭据。<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** 的功能包括：

- **Add**：生成密钥对并添加密钥凭据。
- **List**：显示所有密钥凭据条目。
- **Remove**：删除指定的密钥凭据。
- **Clear**：清除所有密钥凭据，可能会影响合法的 WHfB 使用。

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker 借助 Impacket 和 PyDSInternals 将此工作流带到**类 UNIX 系统**，支持列出/添加/删除以及 JSON 导入/导出操作。<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray 会枚举操作员拥有 `GenericWrite`/`GenericAll` 等权限的域对象，尝试广泛添加 key credentials，并提供清理/递归模式。大范围 spraying 会造成干扰且容易引人注意；请使用明确指定的目标，并记录每个添加的 DeviceID，以便精确移除。<sup>[[3]](#references)</sup>

如果直接 LDAP 流量受到过滤，可以通过 ADWS 执行 key-credential 写入。参见 [SOAPy ADWS workflow](../adws-enumeration.md#shadow-credentials-over-adws)。<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials：滥用 Key Trust Account Mapping 接管账户](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - 通过操纵 msDS-KeyCredentialLink 接管 AD 账户的工具](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - 用于在域中 spray Shadow Credentials 的工具](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Shadow Credentials 工具的 Python 版本](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
