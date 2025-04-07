# AD CS 証明書の盗難

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) の素晴らしい研究の盗難章の小さな要約です。**

## 証明書で何ができるか

証明書を盗む方法を確認する前に、証明書が何に役立つかを見つけるための情報があります:
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
## 証明書のエクスポート – THEFT1

**インタラクティブデスクトップセッション**では、ユーザーまたはマシンの証明書をプライベートキーと共に抽出することは簡単に行えます。特に、**プライベートキーがエクスポート可能な場合**はそうです。これは、`certmgr.msc`で証明書に移動し、右クリックして`すべてのタスク → エクスポート`を選択することで、パスワード保護された.pfxファイルを生成することで実現できます。

**プログラム的アプローチ**では、PowerShellの`ExportPfxCertificate`コマンドレットや、[TheWoverのCertStealer C#プロジェクト](https://github.com/TheWover/CertStealer)のようなツールが利用可能です。これらは、証明書ストアと対話するために**Microsoft CryptoAPI** (CAPI) またはCryptography API: Next Generation (CNG)を利用します。これらのAPIは、証明書の保存と認証に必要なさまざまな暗号サービスを提供します。

ただし、プライベートキーがエクスポート不可に設定されている場合、通常CAPIとCNGはそのような証明書の抽出をブロックします。この制限を回避するために、**Mimikatz**のようなツールを使用できます。Mimikatzは、プライベートキーのエクスポートを可能にするために、各APIをパッチする`crypto::capi`および`crypto::cng`コマンドを提供します。具体的には、`crypto::capi`は現在のプロセス内のCAPIをパッチし、`crypto::cng`は**lsass.exe**のメモリをターゲットにしてパッチを適用します。

## DPAPIを介したユーザー証明書の盗難 – THEFT2

DPAPIに関する詳細は以下を参照してください：

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Windowsでは、**証明書のプライベートキーはDPAPIによって保護されています**。ユーザーとマシンのプライベートキーの**保存場所が異なる**ことを認識することが重要であり、ファイル構造はオペレーティングシステムによって利用される暗号APIによって異なります。**SharpDPAPI**は、DPAPIブロブを復号化する際にこれらの違いを自動的にナビゲートできるツールです。

**ユーザー証明書**は主に`HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`のレジストリに格納されていますが、一部は`%APPDATA%\Microsoft\SystemCertificates\My\Certificates`ディレクトリにも見つかります。これらの証明書に対応する**プライベートキー**は、通常、**CAPI**キーの場合は`%APPDATA%\Microsoft\Crypto\RSA\User SID\`に、**CNG**キーの場合は`%APPDATA%\Microsoft\Crypto\Keys\`に保存されています。

**証明書とその関連するプライベートキーを抽出する**プロセスは以下の通りです：

1. ユーザーのストアから**ターゲット証明書を選択**し、そのキー ストア名を取得します。
2. 対応するプライベートキーを復号化するために必要な**DPAPIマスタキーを特定**します。
3. プレーンテキストのDPAPIマスタキーを利用して**プライベートキーを復号化**します。

**プレーンテキストのDPAPIマスタキーを取得する**ために、以下のアプローチを使用できます：
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
マスターキーファイルとプライベートキーファイルの復号化を効率化するために、[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) の `certificates` コマンドが有益です。これは、プライベートキーと関連する証明書を復号化するために、`/pvk`、`/mkfile`、`/password`、または `{GUID}:KEY` を引数として受け取り、その後 `.pem` ファイルを生成します。
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## マシン証明書の窃盗 via DPAPI – THEFT3

Windowsによってレジストリの `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` に保存されているマシン証明書と、`%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI用) および `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG用) に位置する関連する秘密鍵は、マシンのDPAPIマスタキーを使用して暗号化されています。これらのキーはドメインのDPAPIバックアップキーで復号化することはできず、代わりに**DPAPI_SYSTEM LSAシークレット**が必要で、これはSYSTEMユーザーのみがアクセスできます。

手動での復号化は、**Mimikatz**で `lsadump::secrets` コマンドを実行してDPAPI_SYSTEM LSAシークレットを抽出し、その後このキーを使用してマシンマスタキーを復号化することで達成できます。あるいは、前述のようにCAPI/CNGをパッチした後にMimikatzの `crypto::certificates /export /systemstore:LOCAL_MACHINE` コマンドを使用することもできます。

**SharpDPAPI** は、証明書コマンドを使用したより自動化されたアプローチを提供します。 `/machine` フラグを昇格した権限で使用すると、SYSTEMに昇格し、DPAPI_SYSTEM LSAシークレットをダンプし、それを使用してマシンDPAPIマスタキーを復号化し、これらの平文キーをルックアップテーブルとして使用して任意のマシン証明書の秘密鍵を復号化します。

## 証明書ファイルの検索 – THEFT4

証明書は、ファイル共有やダウンロードフォルダなど、ファイルシステム内に直接見つかることがあります。Windows環境を対象とした最も一般的に遭遇する証明書ファイルの種類は、`.pfx` および `.p12` ファイルです。頻度は低いですが、`.pkcs12` および `.pem` 拡張子のファイルも現れます。その他の注目すべき証明書関連のファイル拡張子には以下が含まれます：

- 秘密鍵用の `.key`
- 証明書のみのための `.crt`/`.cer`
- 証明書や秘密鍵を含まない証明書署名要求用の `.csr`
- Javaアプリケーションで使用される証明書と秘密鍵を保持する可能性のある Javaキーストア用の `.jks`/`.keystore`/`.keys`

これらのファイルは、PowerShellやコマンドプロンプトを使用して、前述の拡張子を探すことで検索できます。

PKCS#12証明書ファイルが見つかり、パスワードで保護されている場合、`pfx2john.py` を使用してハッシュを抽出することが可能です。このスクリプトは [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html) で入手できます。その後、JohnTheRipperを使用してパスワードのクラッキングを試みることができます。
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5 (UnPAC the hash)

与えられた内容は、PKINITを介したNTLM資格情報の盗難方法、特にTHEFT5とラベル付けされた盗難方法について説明しています。以下は、受動態での再説明であり、内容は匿名化され、適用可能な場合は要約されています。

NTLM認証`MS-NLMP`をサポートするために、Kerberos認証を促進しないアプリケーション向けに、KDCはPKCAが利用される際に、特に`PAC_CREDENTIAL_INFO`バッファ内でユーザーのNTLM一方向関数（OWF）を返すように設計されています。したがって、アカウントがPKINITを介してチケット授与チケット（TGT）を認証し取得すると、現在のホストがレガシー認証プロトコルを維持するためにTGTからNTLMハッシュを抽出できるメカニズムが本質的に提供されます。このプロセスは、NTLMプレーンテキストのNDRシリアライズされた表現である`PAC_CREDENTIAL_DATA`構造体の復号化を含みます。

ユーティリティ**Kekeo**は、[https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo)でアクセス可能であり、この特定のデータを含むTGTを要求できることが言及されており、ユーザーのNTLMの取得を容易にします。この目的で使用されるコマンドは次のとおりです：
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** は、オプション **`asktgt [...] /getcredentials`** を使用してこの情報を取得することもできます。

さらに、Kekeoは、PINが取得できる場合に限り、スマートカード保護された証明書を処理できることが記載されており、[https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe) に言及されています。同様の機能は **Rubeus** にもサポートされており、[https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) で入手可能です。

この説明は、PKINITを介したNTLM資格情報の盗難に関与するプロセスとツールを要約しており、PKINITを使用して取得したTGTを通じてNTLMハッシュを取得することに焦点を当て、これを促進するユーティリティについて説明しています。

{{#include ../../../banners/hacktricks-training.md}}
