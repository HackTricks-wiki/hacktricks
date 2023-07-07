# AD証明書

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

### 証明書のパーツ

* **Subject** - 証明書の所有者。
* **Public Key** - Subjectを個別に保存された秘密鍵と関連付けます。
* **NotBeforeとNotAfterの日付** - 証明書の有効期間を定義します。
* **Serial Number** - CAによって割り当てられた証明書の識別子。
* **Issuer** - 証明書を発行したものを識別します（一般的にはCA）。
* **SubjectAlternativeName** - Subjectが使用することができる1つ以上の代替名を定義します（_以下を確認してください_）。
* **Basic Constraints** - 証明書がCAまたはエンドエンティティであるか、証明書を使用する際の制約があるかを識別します。
* **Extended Key Usages（EKU）** - 証明書の使用方法を説明するオブジェクト識別子（OID）。Microsoftの用語ではEnhanced Key Usageとも呼ばれます。一般的なEKU OIDには次のものがあります：
* Code Signing（OID 1.3.6.1.5.5.7.3.3）- 証明書は実行可能なコードに署名するためです。
* Encrypting File System（OID 1.3.6.1.4.1.311.10.3.4）- 証明書はファイルシステムを暗号化するためです。
* Secure Email（1.3.6.1.5.5.7.3.4）- 証明書は電子メールを暗号化するためです。
* Client Authentication（OID 1.3.6.1.5.5.7.3.2）- 証明書は別のサーバー（例：ADへの認証）への認証に使用されます。
* Smart Card Logon（OID 1.3.6.1.4.1.311.20.2.2）- 証明書はスマートカード認証に使用されます。
* Server Authentication（OID 1.3.6.1.5.5.7.3.1）- 証明書はサーバーを識別するためです（例：HTTPS証明書）。
* **Signature Algorithm** - 証明書に署名するために使用されるアルゴリズムを指定します。
* **Signature** - 発行者（例：CA）の秘密鍵を使用して作成された証明書の本体の署名。

#### Subject Alternative Names

**Subject Alternative Name**（SAN）はX.509v3拡張です。これにより、**証明書に追加の識別子**をバインドすることができます。たとえば、ウェブサーバーが**複数のドメインのコンテンツ**をホストする場合、**各ドメイン**が**SAN**に**含まれる**ようにして、ウェブサーバーは単一のHTTPS証明書のみを必要とします。

デフォルトでは、証明書ベースの認証中に、ADはSANで指定されたUPNに基づいて証明書をユーザーアカウントにマッピングします。攻撃者が**クライアント認証を有効にするEKUを持つ証明書を要求する際に任意のSANを指定**し、CAが攻撃者が指定したSANを使用して証明書を作成して署名する場合、**攻撃者はドメイン内の任意のユーザーになることができます**。

### CA

AD CSは、ADフォレストが信頼するCA証明書を`CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`の下に4つの場所で定義します。それぞれの目的によって異なります。

* **Certification Authorities**コンテナは**信頼されたルートCA証明書**を定義します。これらのCAはPKIツリー階層の**トップ**にあり、AD CS環境での信頼の基盤です。各CAは、**`certificationAuthority`**という**objectClass**が設定され、**`cACertificate`**プロパティには**CAの証明書のバイト**が含まれています。WindowsはこれらのCA証明書を各WindowsマシンのTrusted Root Certification Authorities証明書ストアに伝播します。ADが証明書を**信頼する**ためには、証明書の信頼**チェーン**が最終的にこのコンテナで定義された**ルートCAのいずれか**で**終了**する必要があります。
* **Enrolment Services**コンテナは、**Enterprise CA**（つまり、AD CSでEnterprise CAロールが有効になっているCA）を定義します。各Enterprise CAには、次の属性を持つADオブジェクトがあります：
* **`pKIEnrollmentService`**に**objectClass**属性
* **CAの証明書のバイト**を含む**`cACertificate`**属性
* **CAのDNSホスト**を設定する**`dNSHostName`**プロパティ
* 有効な証明書テンプレートを定義する**certificateTemplates**フィールド。証明書テンプレートは、証明書の作成時にCAが使用する設定の「設計図」であり、EKU、登録許可、証明書の有効期限、発行要件、暗号設定などが含まれます。証明書テンプレートについては後ほど詳しく説明します。

{% hint style="info" %}
AD環境では、**クライアントは証明書テンプレートで定義され
* **AIA**（Authority Information Access）コンテナには、中間およびクロスCAのADオブジェクトが格納されています。**中間CAはルートCAの「子」**であり、このコンテナは**証明書チェーンの検証**を支援するために存在します。認証機関コンテナと同様に、各**CAはADオブジェクトとして表され**、オブジェクトクラス属性がcertificationAuthorityに設定され、**`cACertificate`**プロパティには**CAの証明書のバイト**が含まれています。これらのCAは、Windowsマシンの中間認証機関証明書ストアに伝播されます。

### クライアント証明書リクエストのフロー

<figure><img src="../../.gitbook/assets/image (5) (2) (2).png" alt=""><figcaption></figcaption></figure>

これはAD CSから証明書を取得するプロセスです。大まかに言うと、登録時にクライアントはまず上記で説明した**登録サービスのオブジェクト**に基づいて**エンタープライズCAを見つけます**。

1. クライアントは**公開-秘密鍵ペア**を生成し、
2. クライアントは、証明書のサブジェクトや**証明書テンプレート名**などの他の詳細と共に、**証明書署名リクエスト（CSR）**メッセージに公開鍵を配置します。クライアントはその後、CSRをプライベートキーで**署名**し、CSRをエンタープライズCAサーバーに送信します。
3. **CA**サーバーは、クライアントが**証明書を要求できるかどうか**をチェックします。そうであれば、CSRで指定された**証明書テンプレート**ADオブジェクトを参照して、証明書テンプレートのADオブジェクトの**アクセス許可が**認証アカウントが**証明書を取得できるかどうか**を確認します。
4. もし許可されていれば、**CAは証明書を生成**し、証明書テンプレートで定義された「設計図」の設定（例：EKU、暗号化設定、発行要件）を使用し、CSRで提供された他の情報を証明書のテンプレート設定で許可されている場合に使用します。**CAはプライベートキーで証明書に署名**し、それをクライアントに返します。

### 証明書テンプレート

AD CSは、次のコンテナにある**`pKICertificateTemplate`**という**objectClass**を持つADオブジェクトとして利用可能な証明書テンプレートを保存します。

`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

AD証明書テンプレートオブジェクトの属性は、その設定を定義し、セキュリティ記述子は証明書を**登録することができる主体**または証明書テンプレートを**編集することができる主体**を制御します。

AD証明書テンプレートオブジェクトの**`pKIExtendedKeyUsage`**属性には、テンプレートで有効になっている**OIDの配列**が含まれています。これらのEKU OIDは、証明書の**使用目的に影響を与えます**。[ここで可能なOIDのリストを見つけることができます](https://www.pkisolutions.com/object-identifiers-oid-in-pki/)。

#### 認証用のOID

* `1.3.6.1.5.5.7.3.2`：クライアント認証
* `1.3.6.1.5.2.3.4`：PKINITクライアント認証（手動で追加する必要があります）
* `1.3.6.1.4.1.311.20.2.2`：スマートカードログオン
* `2.5.29.37.0`：任意の目的
* （EKUなし）：サブCA
* 追加の悪用できるEKU OIDは、証明書リクエストエージェントOID（`1.3.6.1.4.1.311.20.2.1`）です。このOIDを持つ証明書は、特定の制限が設定されていない限り、他のユーザーの代わりに証明書を要求するために使用できます。

## 証明書の登録

管理者はまず証明書テンプレートを**作成**し、その後エンタープライズCAがテンプレートを**「公開」**して、クライアントが登録できるようにします。AD CSでは、証明書テンプレートがエンタープライズCAで有効になるように、テンプレートの名前をADオブジェクトの`certificatetemplates`フィールドに追加することで指定されます。

<figure><img src="../../.gitbook/assets/image (11) (2) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
AD CSは、証明書を**要求できる主体**を定義するために、証明書テンプレートADオブジェクトとエンタープライズCA自体の2つのセキュリティ記述子を使用します。\
証明書を要求できるためには、クライアントは両方のセキュリティ記述子に付与される必要があります。
{% endhint %}

### 証明書テンプレートの登録権限

* **ACEは主体にCertificate-Enrollment拡張権限を付与**します。raw ACEは、**ObjectType**が`0e10c968-78fb-11d2-90d4-00c04f79dc5547`に設定された`RIGHT_DS_CONTROL_ACCESS45`アクセス権を主体に付与します。このGUIDは**Certificate-Enrollment**拡張権限に対応します。
* **ACEは主体にCertificate-AutoEnrollment拡張権限を付与**します。raw ACEは、**ObjectType**が`a05b8cc2-17bc-4802-a710-e7c15ab866a249`に設定された`RIGHT_DS_CONTROL_ACCESS48`アクセス権を主体に付与します。このGUIDは**Certificate-AutoEnrollment**拡張権限に対応します。
* **ACEは主体にすべてのExtendedRightsを付与**します。raw ACEは、**ObjectType**が`00000000-0000-0000-0000-000000000000`に設定された`RIGHT_DS_CONTROL_ACCESS`アクセス権を有効にします。このGUIDは**すべての拡張権限**に対応します。
* **ACEは主体にFullControl/GenericAllを付与**します。raw ACEは、FullControl/GenericAllアクセス権を有効にします。

### エンタープライズCAの登録権限

エンタープライズCAに設定された**セキュリティ記述子**は、証明書機関MMCスナップイン`certsrv.msc`でCAを右クリックしてプロパティ→セキュリティを表示することで確認できます。

<figure><img src="../../.gitbook/assets/image (7) (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

これにより、CAサーバーの**`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration<CA NAME>`**キーのSecurityレジストリ値が設定されます。私たちは、いくつかのAD CSサーバーで、低特権ユーザーがリモートレジストリを介してこのキーに対するリモートアクセス権限を付与されていることを確認しました。

<figure><img src="../../.gitbook/assets/image (6) (2) (1).png" alt=""><figcaption></figcaption></figure>

低特権ユーザーは、`ICertAdminD2` COMインターフェースの`GetCASecurity`メソッドを使用して、DCOMを介してこれを列挙することもできます。ただし、通常のWindowsクライアントは、COMインターフェースとそれを実装するCOMオブジェク
### 発行要件

証明書を取得できる人を制御するために、他の要件が存在する場合があります。

#### マネージャーの承認

**CA証明書マネージャーの承認**により、証明書テンプレートはADオブジェクトの`msPKI-EnrollmentFlag`属性の`CT_FLAG_PEND_ALL_REQUESTS`（0x2）ビットを設定します。これにより、テンプレートに基づくすべての**証明書リクエスト**が**保留状態**になります（`certsrv.msc`の「保留中のリクエスト」セクションで表示されます）。証明書が発行される前に、証明書マネージャーがリクエストを**承認または拒否**する必要があります。

<figure><img src="../../.gitbook/assets/image (13) (2).png" alt=""><figcaption></figcaption></figure>

#### 登録エージェント、承認署名、およびアプリケーションポリシー

**承認署名の数**と**アプリケーションポリシー**が設定されることもあります。前者は、CAが受け入れるためにCSRに必要な**署名の数**を制御します。後者は、CSRの署名証明書が持っている必要のある**EKU OID**を定義します。

これらの設定の一般的な使用法は、**登録エージェント**です。登録エージェントは、他のユーザーの代わりに証明書を**リクエストできる**AD CS用語です。そのためには、CAは登録エージェントアカウントに、少なくとも**証明書リクエストエージェントEKU**（OID 1.3.6.1.4.1.311.20.2.1）を含む証明書を発行する必要があります。発行された後、登録エージェントは他のユーザーのためにCSRに署名し、証明書をリクエストすることができます。CAは、以下の非網羅的な一連の**条件**（主にデフォルトのポリシーモジュール`certpdef.dll`で実装されています）の下で、登録エージェントに**別のユーザーとして証明書**を発行します。

* CAに認証するWindowsユーザーが、対象の証明書テンプレートに対する登録権限を持っている場合。
* 証明書テンプレートのスキーマバージョンが1の場合、CAは証明書の発行前に署名証明書に証明書リクエストエージェントOIDが必要です。テンプレートのスキーマバージョンは、ADオブジェクトのmsPKI-Template-Schema-Versionプロパティで指定されます。
* 証明書テンプレートのスキーマバージョンが2の場合：
* テンプレートは「承認署名の数」設定を行い、指定された数の登録エージェントがCSRに署名する必要があります（テンプレートのmspkira-signature AD属性がこの設定を定義します）。つまり、この設定は、CAが証明書を発行する前にいくつの登録エージェントがCSRに署名する必要があるかを指定します。
* テンプレートの「アプリケーションポリシー」発行制限は「証明書リクエストエージェント」に設定する必要があります。

### 証明書のリクエスト

1. Windowsの**クライアント証明書登録プロトコル**（MS-WCCE）を使用して、さまざまなAD CSの機能（登録を含む）と対話する一連の分散コンポーネントオブジェクトモデル（DCOM）インターフェースを介して証明書をリクエストします。**DCOMサーバーはデフォルトですべてのAD CSサーバーで有効になっており**、クライアントが証明書をリクエストする最も一般的な方法です。
2. **ICertPassageリモートプロトコル**（MS-ICPR）を介した**リモートプロシージャコール**（RPC）プロトコルは、名前付きパイプまたはTCP/IP上で動作することができます。
3. **証明書登録Webインターフェース**にアクセスします。これを使用するには、ADCSサーバーに**証明書機関Web登録ロール**をインストールする必要があります。有効になると、ユーザーは`http:///certsrv/`で実行されているIISホストされたASP Web登録アプリケーションに移動できます。
* `certipy req -ca 'corp-DC-CA' -username john@corp.local -password Passw0rd -web -debug`
4. **証明書登録サービス**（CES）との対話。これを使用するには、サーバーに**証明書登録Webサービスロール**をインストールする必要があります。有効になると、ユーザーは`https:///_CES_Kerberos/service.svc`でWebサービスにアクセスして証明書をリクエストできます。このサービスは、証明書登録ポリシー（証明書登録ポリシーウェブサービスロールを介してインストールされる）と連携して動作し、クライアントはURL `https:///ADPolicyProvider_CEP_Kerberos/service.svc` で証明書テンプレートをリストするために使用します。証明書登録およびポリシーウェブサービスは、それぞれMS-WSTEPおよびMS-XCEP（SOAPベースのプロトコル）を実装しています。
5. **ネットワークデバイス登録サービス**を使用します。これを使用するには、サーバーに**ネットワークデバイス登録サービスロール**をインストールする必要があります。これにより、クライアント（主にネットワークデバイス）が**シンプル証明書登録プロトコル**（SCEP）を介して証明書を取得できます。有効になると、管理者はURL `http:///CertSrv/mscep_admin/`からワンタイムパスワード（OTP）を取得できます。管理者はOTPをネットワークデバイスに提供し、デバイスはURL `http://NDESSERVER/CertSrv/mscep/`を使用してSCEPを使用して証明書をリクエストします。

Windowsマシンでは、ユーザーはGUIを使用して証明書をリクエストできます。ユーザー証明書の場合は`certmgr.msc`を起動し、パーソナル証明書ストアを展開して`Certificates`を右クリックし、`All Tasks`を選択し、`Request New Certificate`を選択します。

証明書の登録には、組み込みの**`certreq.exe`**コマンドまたはPowerShellの**`Get-Certificate`**コマンドも使用できます。

## 証明書の認証

ADはデフォルトで**2つのプロトコル**を介した証明書認証をサポートしています：**Kerberos**と**Secure Channel**（Schannel）。

### Kerberos認証とNTAuthCertificatesコンテナ

要約すると、ユーザーは自分の証明書の**秘密鍵**を使用して**TGTリクエスト**の認証
### セキュアチャネル（Schannel）認証

Schannelは、TLS/SSL接続を確立する際にWindowsが利用するセキュリティサポートプロバイダ（SSP）です。Schannelは、**クライアント認証**（その他多くの機能の中で）をサポートし、リモートサーバが接続するユーザの**身元を確認**することができます。これは、証明書を主要な資格情報として使用するPKIを使用して行われます。\
**TLSハンドシェイク**中、サーバは認証のためにクライアントから証明書を要求します。サーバが信頼するCAからクライアント認証証明書を事前に発行されたクライアントは、証明書をサーバに送信します。サーバはその後、証明書が正しいことを検証し、すべてが正常であればユーザにアクセスを許可します。

<figure><img src="../../.gitbook/assets/image (8) (2) (1).png" alt=""><figcaption></figcaption></figure>

ADに証明書を使用してアカウントが認証される場合、DCは証明書の資格情報をADアカウントにマッピングする必要があります。Schannelは、最初にKerberosの**S4U2Self**機能を使用して資格情報をユーザアカウントにマッピングしようとします。\
それが**失敗した場合**、証明書をユーザアカウントにマッピングするために、証明書の**SAN拡張**、**サブジェクト**と**発行者**のフィールドの組み合わせ、または発行者のみを使用します。デフォルトでは、AD環境の多くのプロトコルは、Schannelを使用したAD認証をそのままサポートしていません。WinRM、RDP、およびIISは、Schannelを使用したクライアント認証をサポートしていますが、**追加の設定が必要**であり、WinRMのような場合はActive Directoryと統合されていません。\
一般的に動作するプロトコルは、AD CSがセットアップされている場合に**LDAPS**です。コマンドレット`Get-LdapCurrentUser`は、.NETライブラリを使用してLDAPに認証する方法を示しています。このコマンドレットは、LDAPの「Who am I？」拡張操作を実行して現在認証中のユーザを表示します。

<figure><img src="../../.gitbook/assets/image (2) (4).png" alt=""><figcaption></figcaption></figure>

## AD CS列挙

ADのほとんどの情報と同様に、これまでにカバーした情報は、ドメイン認証されたが特権のないユーザとしてLDAPをクエリすることで利用できます。

エンタープライズCAとその設定を**列挙**するには、`CN=Configuration,DC=<domain>,DC=<com>`の検索ベース（この検索ベースはADフォレストの構成名前空間に対応します）でLDAPをクエリし、`(objectCategory=pKIEnrollmentService)`のLDAPフィルタを使用します。結果には、CAサーバのDNSホスト名、CA名自体、証明書の開始日と終了日、さまざまなフラグ、公開された証明書テンプレートなどが表示されます。

**脆弱な証明書を列挙するためのツール:**

* [**Certify**](https://github.com/GhostPack/Certify)は、AD CS環境に関する有用な設定とインフラ情報を列挙し、さまざまな方法で証明書を要求できるC#ツールです。
* [**Certipy**](https://github.com/ly4k/Certipy)は、Active Directory証明書サービス（AD CS）を**任意のシステム**（DCへのアクセス権がある）から列挙および悪用できる**Python**ツールで、[**Lyak**](https://twitter.com/ly4k\_)（良い人で優れたハッカー）が作成したBloodHoundの出力を生成できます。
```bash
# https://github.com/GhostPack/Certify
Certify.exe cas #enumerate trusted root CA certificates, certificates defined by the NTAuthCertificates object, and various information about Enterprise CAs
Certify.exe find #enumerate certificate templates
Certify.exe find /vulnerable #Enumerate vulenrable certificate templater

# https://github.com/ly4k/Certipy
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
certipy find -vulnerable [-hide-admins] -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128 #Search vulnerable templates

certutil.exe -TCAInfo #enumerate Enterprise CAs
certutil -v -dstemplate #enumerate certificate templates
```
## 参考文献

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
