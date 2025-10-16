# AD CS ドメイン永続化

{{#include ../../../banners/hacktricks-training.md}}

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Check it for further details.

## 盗まれた CA 証明書を用いた証明書偽造 (Golden Certificate) - DPERSIST1

どのようにして証明書が CA 証明書であると判断できますか？

いくつかの条件が満たされていれば、それが CA 証明書であると判断できます：

- 証明書は CA サーバ上に保存され、その秘密鍵はマシンの DPAPI によって保護されているか、OS がサポートしていれば TPM/HSM のようなハードウェアで保護されている。
- 証明書の Issuer と Subject の両方のフィールドが CA の distinguished name と一致する。
- CA 証明書にのみ "CA Version" 拡張が存在する。
- 証明書に Extended Key Usage (EKU) フィールドが存在しない。

この証明書の秘密鍵を抽出するために、CA サーバ上で内蔵 GUI 経由にサポートされた方法は `certsrv.msc` ツールです。ただし、この証明書はシステム内に保存されている他の証明書と本質的に異ならないため、[THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) のような方法を使って抽出することもできます。

証明書と秘密鍵は、次のコマンドで Certipy を使って取得することもできます：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA証明書とその秘密鍵を `.pfx` 形式で取得した後は、[ForgeCert](https://github.com/GhostPack/ForgeCert) のようなツールを使って有効な証明書を生成できます：
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
> 証明書偽造の対象となるユーザーは、プロセスを成功させるために Active Directory 内でアクティブであり、認証可能でなければなりません。krbtgt のような特別なアカウントに対する証明書偽造は効果がありません。

この偽造された証明書は、指定された終了日まで、そしてルート CA 証明書が有効である限り（通常は5年〜**10年以上**）**有効**です。これは **マシン** にも有効であるため、**S4U2Self** と組み合わせることで、攻撃者は CA 証明書が有効な限り **任意のドメインマシン上で永続性を維持** できます。\
さらに、この方法で **生成された証明書** は CA がそれらを認識していないため **取り消すことはできません**。

### Operating under Strong Certificate Mapping Enforcement (2025+)

2025年2月11日以降（KB5014754 の展開後）、ドメインコントローラーは証明書マッピングに対してデフォルトで **Full Enforcement** を適用します。実務的にはこれは、あなたの偽造証明書が次のいずれかを満たす必要があることを意味します:

- 対象アカウントへの強いバインディングを含む（例えば、SID security extension）、または
- 対象オブジェクトの `altSecurityIdentities` 属性に対する強く明示的なマッピングと組み合わせること。

永続化のための信頼できるアプローチは、盗まれた Enterprise CA にチェーンされた偽造証明書を発行し、その後被害者プリンシパルに対して強い明示的マッピングを追加することです:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注意
- SID セキュリティ拡張を含む偽造証明書を作成できる場合、それらは Full Enforcement 下でも暗黙にマップされます。そうでない場合は、明示的な強力なマッピングを優先してください。詳しくは [account-persistence](account-persistence.md) を参照してください。
- 失効はここでは防御側の助けになりません: 偽造証明書は CA データベースに存在しないため、取り消すことができません。

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` オブジェクトは、Active Directory (AD) が利用する `cacertificate` 属性内に 1 件以上の **CA certificates** を含むよう定義されています。**ドメインコントローラー** による検証プロセスでは、認証対象の **証明書** の Issuer フィールドで指定された **CA** と一致するエントリが `NTAuthCertificates` オブジェクトに存在するか確認します。一致が見つかれば認証は進みます。

攻撃者がこの AD オブジェクトを制御している場合、自己署名の CA 証明書を `NTAuthCertificates` オブジェクトに追加できます。通常、このオブジェクトを変更できるのは **Enterprise Admin** グループのメンバー、ならびに **forest root’s domain** の **Domain Admins** または **Administrators** に限定されます。`certutil.exe` を使って `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` のコマンドで `NTAuthCertificates` オブジェクトを編集するか、[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) を使用できます。

この手法に役立つ追加のコマンド:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
この機能は、ForgeCert を用いて証明書を動的に生成する前述の手法と組み合わせた場合に特に有用です。

> Post-2025 mapping considerations: NTAuth に rogue CA を配置しても発行元 CA に対する信頼が確立されるだけです。DCs が **Full Enforcement** の場合にログオンに leaf 証明書を使うには、leaf が SID セキュリティ拡張を含むか、ターゲットオブジェクトに強力な明示的マッピング（例えば、`altSecurityIdentities` における Issuer+Serial）が必要です。参照: {{#ref}}account-persistence.md{{#endref}}。

## Malicious Misconfiguration - DPERSIST3

AD CS コンポーネントの **security descriptor** を修正することで得られる **persistence** の機会は多数あります。"[Domain Escalation](domain-escalation.md)" セクションで説明されている修正は、ドメイン内で **elevated access** を持つ攻撃者によって悪意を持って実行され得ます。これには、次のような敏感なコンポーネントへの「control rights」（例: WriteOwner/WriteDACL/etc.）の追加が含まれます:

- **CA server’s AD computer** object
- **CA server’s RPC/DCOM server**
- **CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>** 内の任意の **descendant AD object or container**（例えば、Certificate Templates コンテナ、Certification Authorities コンテナ、NTAuthCertificates オブジェクトなど）
- 組織によって既定または委譲された **AD groups delegated rights to control AD CS**（組み込みの Cert Publishers グループやそのメンバーなど）

悪意ある実装の例としては、ドメインで **elevated permissions** を持つ攻撃者が既定の **`User`** certificate template に **`WriteOwner`** 権限を追加し、攻撃者をその権利のプリンシパルに設定する、というものがあります。これを悪用するには、まず攻撃者が **`User`** テンプレートの所有権を自分に変更します。次にテンプレート上で **`mspki-certificate-name-flag`** を **1** に設定して **`ENROLLEE_SUPPLIES_SUBJECT`** を有効化し、リクエスト時に Subject Alternative Name を指定できるようにします。その後、攻撃者はその **template** を使って **enroll** し、代替名として **domain administrator** の名前を選択し、取得した証明書を DA としての認証に利用できます。

長期的なドメイン永続化のために攻撃者が設定し得る実用的な調整（詳細と検出は {{#ref}}domain-escalation.md{{#endref}} を参照）:

- リクエスタからの SAN を許可する CA ポリシーフラグ（例: `EDITF_ATTRIBUTESUBJECTALTNAME2` の有効化）。これにより ESC1-like の経路が悪用可能なままになります。
- 認証可能な発行を許すテンプレートの DACL や設定（例: Client Authentication EKU の追加、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` の有効化）。
- `NTAuthCertificates` オブジェクトや CA コンテナを制御して、守備側がクリーンアップを試みても悪意ある発行元を継続的に再導入する。

> [!TIP]
> KB5014754 適用後の強化環境では、これらの誤設定を明示的な強いマッピング（`altSecurityIdentities`）と組み合わせることで、DCs が強いマッピングを強制しても発行または偽造した証明書が引き続き使用可能になります。



## References

- Microsoft KB5014754 – Windows domain controllers における証明書ベースの認証の変更（強制化スケジュールと強いマッピング）。https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – コマンドリファレンスと forge/auth の使用法。https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
