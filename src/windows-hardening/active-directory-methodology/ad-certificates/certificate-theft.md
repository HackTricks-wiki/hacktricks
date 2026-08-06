# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**这是对 [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) 中精彩研究的 Certificate Theft 章节的小结**<sup>[[1]](#references)</sup>

## 我可以用证书做什么

在了解如何窃取证书之前，先了解如何查找证书的用途：
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## 使用 Crypto APIs 导出 Certificates – THEFT1

在**interactive desktop session**中，提取用户或机器 certificate 及其 private key 通常很容易，尤其是在 **private key 可导出**的情况下。可以在 `certmgr.msc` 中找到该 certificate，右键单击它，然后选择 `All Tasks → Export`，以生成受密码保护的 .pfx 文件。<sup>[[1]](#references)</sup>

对于**programmatic approach**，可以使用 PowerShell 的 `ExportPfxCertificate` cmdlet，或 [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) 等项目。这些工具利用 **Microsoft CryptoAPI** (CAPI) 或 Cryptography API: Next Generation (CNG) 与 certificate store 交互。这些 API 提供一系列 cryptographic services，包括 certificate storage 和 authentication 所需的服务。

但是，如果 private key 被设置为不可导出，CAPI 和 CNG 通常都会阻止提取此类 certificates。为了绕过此限制，可以使用 **Mimikatz** 等工具。Mimikatz 提供 `crypto::capi` 和 `crypto::cng` 命令，用于 patch 相应的 APIs，从而允许导出 private keys。具体而言，`crypto::capi` 会 patch 当前 process 中的 CAPI，而 `crypto::cng` 则会针对 **lsass.exe** 的 memory 进行 patch。

## 通过 DPAPI 窃取 User Certificate – THEFT2

有关 DPAPI 的更多信息：


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

在 Windows 中，**certificate private keys 由 DPAPI 保护**。需要注意的是，**user 和 machine private keys 的存储位置**不同，并且其 file structures 会根据操作系统所使用的 cryptographic API 而有所不同。**SharpDPAPI** 是一种能够在 decrypting DPAPI blobs 时自动处理这些差异的工具。<sup>[[1]](#references)</sup>

**User certificates** 主要存储在 registry 的 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` 下，但其中一部分也可能位于目录 `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` 中。这些 certificates 对应的 **private keys** 通常存储在 `%APPDATA%\Microsoft\Crypto\RSA\User SID\`（用于 **CAPI** keys）和 `%APPDATA%\Microsoft\Crypto\Keys\`（用于 **CNG** keys）中。

要**提取 certificate 及其关联的 private key**，需要执行以下步骤：

1. 从 user store 中**选择目标 certificate**，并获取其 key store name。
2. **定位所需的 DPAPI masterkey**，以 decrypt 对应的 private key。
3. 使用明文 DPAPI masterkey **decrypt private key**。

要**获取明文 DPAPI masterkey**，可以使用以下方法：
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
为了简化 masterkey 文件和 private key 文件的解密，[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) 的 `certificates` 命令非常有用。它接受 `/pvk`、`/mkfile`、`/password` 或 `{GUID}:KEY` 作为参数，用于解密 private keys 及其关联的 certificates，随后生成一个 `.pem` 文件。
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## 通过 DPAPI 窃取机器证书 – THEFT3

Windows 将存储在注册表 `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` 中的机器证书，以及位于 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`（用于 CAPI）和 `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`（用于 CNG）的关联私钥，使用机器的 DPAPI master keys 进行加密。这些密钥无法使用域的 DPAPI backup key 解密；相反，需要 **DPAPI_SYSTEM LSA secret**，而该 secret 只有 SYSTEM 用户可以访问。<sup>[[1]](#references)</sup>

可以通过在 **Mimikatz** 中执行 `lsadump::secrets` 命令提取 DPAPI_SYSTEM LSA secret，然后使用该密钥解密机器 masterkeys，从而实现手动解密。或者，如前文所述，在 patch CAPI/CNG 后，使用 Mimikatz 的 `crypto::certificates /export /systemstore:LOCAL_MACHINE` 命令。

**SharpDPAPI** 通过其 certificates command 提供了更自动化的方法。使用具有 elevated permissions 的 `/machine` flag 时，它会提权至 SYSTEM，dump DPAPI_SYSTEM LSA secret，使用该 secret 解密机器 DPAPI masterkeys，然后将这些明文密钥作为 lookup table，用于解密任意机器证书的私钥。

## 查找证书文件 – THEFT4

有时可以直接在文件系统中找到证书，例如在 file shares 或 Downloads 文件夹中。面向 Windows 环境的证书文件中，最常见的目标类型是 `.pfx` 和 `.p12` 文件。虽然不太常见，但也会出现扩展名为 `.pkcs12` 和 `.pem` 的文件。其他值得注意的证书相关文件扩展名包括：<sup>[[1]](#references)</sup>

- `.key` 用于私钥，
- `.crt`/`.cer` 仅用于证书，
- `.csr` 用于 Certificate Signing Requests，其中不包含证书或私钥，
- `.jks`/`.keystore`/`.keys` 用于 Java Keystores，其中可能包含证书以及 Java applications 使用的私钥。

可以使用 PowerShell 或 command prompt，通过搜索上述扩展名来查找这些文件。

如果找到 PKCS#12 证书文件且该文件受密码保护，则可以使用 [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) 提供的 `pfx2john.py` 提取 hash。随后，可以使用 JohnTheRipper 尝试 crack 该密码。
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## 通过 PKINIT 窃取 NTLM 凭据 – THEFT5（UnPAC the hash）

给定内容解释了一种通过 PKINIT 窃取 NTLM 凭据的方法，具体对应标记为 THEFT5 的窃取方法。以下内容以被动语态重新表述，并在适用情况下进行了匿名化和概括：<sup>[[1]](#references)</sup>

为了支持不支持 Kerberos authentication 的应用所使用的 NTLM authentication `MS-NLMP`，在使用 PKCA 时，KDC 被设计为在 privilege attribute certificate（PAC）中返回用户的 NTLM one-way function（OWF），具体位于 `PAC_CREDENTIAL_INFO` buffer 中。因此，如果某个账户通过 PKINIT 完成 authentication 并获取 Ticket-Granting Ticket（TGT），当前主机便会获得一种内置机制，可以从 TGT 中提取 NTLM hash，以维持 legacy authentication protocols。此过程需要解密 `PAC_CREDENTIAL_DATA` structure，该 structure 本质上是 NTLM plaintext 的 NDR serialized 表示。

文中提到，位于 [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) 的工具 **Kekeo** 能够请求包含此特定数据的 TGT，从而帮助获取用户的 NTLM。为此使用的 command 如下：
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** 也可以使用选项 **`asktgt [...] /getcredentials`** 获取此信息。

此外，据 noted，Kekeo 可以处理受 smartcard 保护的 certificates，前提是能够获取 pin，相关参考见 [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe)。据称 **Rubeus** 也支持相同功能，项目地址为 [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)。

此说明概述了通过 PKINIT 窃取 NTLM credentials 所涉及的过程和工具，重点是通过 PKINIT 获取的 TGT 提取 NTLM hashes，以及用于实现这一过程的 utilities。

## 参考资料

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
