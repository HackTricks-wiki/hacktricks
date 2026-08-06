# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) の素晴らしい研究における、盗取に関する章の簡単なまとめです**<sup>[[1]](#references)</sup>

## 証明書で何ができるか

証明書の盗み方を確認する前に、その証明書が何に役立つかを調べる方法について、いくつか情報を紹介します：
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
## Crypto APIs を使用した証明書のエクスポート – THEFT1

**interactive desktop session** では、ユーザーまたはマシンの証明書を秘密鍵とともに簡単に抽出できます。特に、**private key が exportable** である場合は容易です。`certmgr.msc` で証明書に移動し、右クリックして `All Tasks → Export` を選択すると、パスワードで保護された .pfx ファイルを生成できます。<sup>[[1]](#references)</sup>

**programmatic approach** では、PowerShell の `ExportPfxCertificate` cmdlet や、[TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer) などのプロジェクトを利用できます。これらは **Microsoft CryptoAPI**（CAPI）または Cryptography API: Next Generation（CNG）を使用して、certificate store とやり取りします。これらの API は、証明書の保存や認証に必要なものを含む、さまざまな暗号サービスを提供します。

ただし、private key が non-exportable に設定されている場合、CAPI と CNG は通常、そのような証明書の抽出をブロックします。この制限を回避するには、**Mimikatz** などのツールを使用できます。Mimikatz には `crypto::capi` と `crypto::cng` コマンドがあり、それぞれの API にパッチを適用して private key をエクスポートできます。具体的には、`crypto::capi` は現在のプロセス内の CAPI にパッチを適用し、`crypto::cng` は **lsass.exe** のメモリを対象としてパッチを適用します。

## DPAPI による User Certificate Theft – THEFT2

DPAPI の詳細:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Windows では、**certificate private keys は DPAPI によって保護されています**。**user と machine の private keys の保存場所**は異なり、ファイル構造もオペレーティングシステムが使用する cryptographic API によって変わる点に注意が必要です。**SharpDPAPI** は、DPAPI blobs を復号する際に、これらの違いを自動的に処理できます。<sup>[[1]](#references)</sup>

**User certificates** は主にレジストリの `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates` に保存されていますが、一部は `%APPDATA%\Microsoft\SystemCertificates\My\Certificates` ディレクトリにも存在します。これらの証明書に対応する **private keys** は通常、**CAPI** keys の場合は `%APPDATA%\Microsoft\Crypto\RSA\User SID\` に、**CNG** keys の場合は `%APPDATA%\Microsoft\Crypto\Keys\` に保存されます。

**certificate と関連する private key を抽出する**には、次の手順を実行します。

1. ユーザーの store から **target certificate を選択**し、その key store name を取得する。
2. 対応する private key を復号するために必要な **DPAPI masterkey を特定**する。
3. plaintext DPAPI masterkey を使用して **private key を復号**する。

**plaintext DPAPI masterkey を取得する**には、次の方法を使用できます。
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
masterkey ファイルと private key ファイルの復号を効率化するには、[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) の `certificates` command が役立ちます。`/pvk`、`/mkfile`、`/password`、または `{GUID}:KEY` を引数として受け取り、private keys と関連する certificates を復号した後、`.pem` ファイルを生成します。
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## DPAPI による Machine Certificate Theft – THEFT3

Windows がレジストリの `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` に保存する Machine certificates と、`%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys`（CAPI 用）および `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys`（CNG 用）に配置される関連する private keys は、machine の DPAPI master keys を使用して暗号化されます。これらの keys は domain の DPAPI backup key では復号できず、SYSTEM user のみがアクセスできる **DPAPI_SYSTEM LSA secret** が必要です。<sup>[[1]](#references)</sup>

手動での復号は、**Mimikatz** で `lsadump::secrets` command を実行して DPAPI_SYSTEM LSA secret を抽出し、その後この key を使用して machine masterkeys を復号することで実行できます。別の方法として、前述のように CAPI/CNG を patch した後、Mimikatz の `crypto::certificates /export /systemstore:LOCAL_MACHINE` command を使用できます。

**SharpDPAPI** は、certificates command によって、より自動化された方法を提供します。昇格した permissions で `/machine` flag を使用すると、SYSTEM に escalate し、DPAPI_SYSTEM LSA secret を dump して、それを使用して machine DPAPI masterkeys を復号します。その後、これらの plaintext keys を lookup table として使用し、machine certificate の private keys を復号します。

## Certificate Files の検索 – THEFT4

Certificates は、file shares や Downloads folder など、filesystem 内に直接存在することがあります。Windows environments を対象とした certificate files で最も一般的に見つかる types は `.pfx` および `.p12` files です。頻度は低いものの、`.pkcs12` および `.pem` extensions の files も存在します。その他の注目すべき certificate 関連の file extensions は次のとおりです。<sup>[[1]](#references)</sup>

- private keys 用の `.key`、
- certificates のみを含む `.crt`/`.cer`、
- certificates や private keys を含まない Certificate Signing Requests 用の `.csr`、
- Java Keystores 用の `.jks`/`.keystore`/`.keys`。Java applications で使用される certificates と private keys を保持している場合があります。

これらの files は、記載されている extensions を検索することで、PowerShell または command prompt を使用して探すことができます。

PKCS#12 certificate file が見つかり、password で保護されている場合、[fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) で提供されている `pfx2john.py` を使用して hash を抽出できます。その後、JohnTheRipper を使用して password の crack を試行できます。
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## PKINIT 経由の NTLM Credential Theft – THEFT5 (UnPAC the hash)

以下の内容では、PKINIT 経由で NTLM credential を theft する方法、特に THEFT5 として分類される theft 方式について説明されています。内容は受動態で再説明され、該当箇所は匿名化および要約されています。<sup>[[1]](#references)</sup>

Kerberos authentication に対応していないアプリケーションで NTLM authentication `MS-NLMP` をサポートするため、PKCA が使用される場合、KDC はユーザーの NTLM one-way function (OWF) を privilege attribute certificate (PAC) 内、具体的には `PAC_CREDENTIAL_INFO` buffer に返すよう設計されています。その結果、アカウントが PKINIT 経由で認証され、Ticket-Granting Ticket (TGT) を取得すると、legacy authentication protocols を維持する目的で、現在の host が TGT から NTLM hash を抽出できる仕組みが本質的に提供されます。このプロセスでは、基本的に NTLM plaintext を NDR serialized した形式である `PAC_CREDENTIAL_DATA` structure が復号されます。

[https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo) から入手できる utility **Kekeo** は、この特定の data を含む TGT を要求でき、それによってユーザーの NTLM を取得できるものとして紹介されています。この目的で使用される command は次のとおりです。
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** でも、オプション **`asktgt [...] /getcredentials`** を使用してこの情報を取得できます。

さらに、PINを取得できる場合、Kekeoはsmartcardで保護された証明書を処理できることが記載されています。これについては [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) が参照されています。同じ機能は **Rubeus** でもサポートされているとされており、[https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) から利用できます。

この説明では、PKINITを介したNTLM credential theftに関係するプロセスとツールについてまとめています。具体的には、PKINITを使用して取得したTGTを通じてNTLM hashを取得する方法と、このプロセスを容易にするユーティリティに焦点を当てています。

## 参考文献

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
