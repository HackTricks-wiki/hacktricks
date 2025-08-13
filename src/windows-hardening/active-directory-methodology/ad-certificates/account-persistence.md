# AD CS 账户持久性

{{#include ../../../banners/hacktricks-training.md}}

**这是对[https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)中精彩研究的机器持久性章节的小总结**

## **理解通过证书进行的活动用户凭证盗窃 – PERSIST1**

在用户可以请求允许域身份验证的证书的场景中，攻击者有机会**请求**并**窃取**此证书以**维持在网络上的持久性**。默认情况下，Active Directory中的`User`模板允许此类请求，尽管有时可能会被禁用。

使用名为[**Certify**](https://github.com/GhostPack/Certify)的工具，可以搜索启用持久访问的有效证书：
```bash
Certify.exe find /clientauth
```
强调了证书的力量在于它能够**作为其所属用户进行身份验证**，无论任何密码更改，只要证书保持**有效**。

可以通过图形界面使用 `certmgr.msc` 或通过命令行使用 `certreq.exe` 请求证书。使用**Certify**，请求证书的过程简化如下：
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
成功请求后，将生成一个证书及其私钥，格式为 `.pem`。要将其转换为可在 Windows 系统上使用的 `.pfx` 文件，使用以下命令：
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
`.pfx` 文件可以上传到目标系统，并与一个名为 [**Rubeus**](https://github.com/GhostPack/Rubeus) 的工具一起使用，以请求用户的票据授权票证 (TGT)，从而延长攻击者的访问权限，直到证书 **有效**（通常为一年）：
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
一个重要的警告是，这种技术与**THEFT5**部分中概述的另一种方法结合使用时，允许攻击者在不与本地安全授权子系统服务（LSASS）交互的情况下，持久性地获取账户的**NTLM hash**，并且在非提升的上下文中提供了一种更隐蔽的长期凭证窃取方法。

## **通过证书获得机器持久性 - PERSIST2**

另一种方法涉及为被攻陷系统的机器账户注册证书，利用默认的`Machine`模板允许此类操作。如果攻击者在系统上获得提升的权限，他们可以使用**SYSTEM**账户请求证书，从而提供一种**持久性**形式：
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
此访问权限使攻击者能够以机器帐户身份对**Kerberos**进行身份验证，并利用**S4U2Self**为主机上的任何服务获取Kerberos服务票证，从而有效地授予攻击者对该机器的持久访问权限。

## **通过证书续订扩展持久性 - PERSIST3**

最后讨论的方法涉及利用证书模板的**有效性**和**续订周期**。通过在证书到期之前**续订**证书，攻击者可以保持对Active Directory的身份验证，而无需额外的票证注册，这可能会在证书授权（CA）服务器上留下痕迹。

### 使用 Certify 2.0 进行证书续订

从**Certify 2.0**开始，续订工作流程通过新的`request-renew`命令完全自动化。给定一个先前签发的证书（以**base-64 PKCS#12**格式），攻击者可以在不与原始所有者互动的情况下续订它——非常适合隐秘的长期持久性：
```powershell
Certify.exe request-renew --ca SERVER\\CA-NAME \
--cert-pfx MIACAQMwgAYJKoZIhvcNAQcBoIAkgA...   # original PFX
```
该命令将返回一个新的 PFX，有效期为另一个完整的生命周期，使您能够在第一个证书过期或被撤销后继续进行身份验证。

## 参考

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}
