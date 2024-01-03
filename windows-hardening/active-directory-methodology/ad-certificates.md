# AD 証明書

<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法：

* **HackTricks に広告を掲載したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFT**](https://opensea.io/collection/the-peass-family) のコレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に **参加する** か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* **HackTricks** の [**GitHub リポジトリ**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) に PR を提出して、ハッキングのコツを共有する。

</details>

## 基本情報

### 証明書の構成要素

* **Subject** - 証明書の所有者。
* **Public Key** - Subject を別に保存されている秘密鍵と関連付ける。
* **NotBefore および NotAfter 日付** - 証明書が有効である期間を定義する。
* **Serial Number** - CA によって割り当てられた証明書の識別子。
* **Issuer** - 証明書を発行した人（通常は CA）を識別する。
* **SubjectAlternativeName** - Subject が使用する可能性のある 1 つ以上の代替名を定義する。(_以下を参照_)
* **Basic Constraints** - 証明書が CA であるかエンドエンティティであるかを識別し、証明書を使用する際の制約があるかどうかを示す。
* **Extended Key Usages (EKUs)** - 証明書の使用方法を記述するオブジェクト識別子（OID）。Microsoft の用語では Enhanced Key Usage とも呼ばれる。一般的な EKU OID には以下が含まれる：
* Code Signing (OID 1.3.6.1.5.5.7.3.3) - 実行可能コードの署名用の証明書。
* Encrypting File System (OID 1.3.6.1.4.1.311.10.3.4) - ファイルシステムの暗号化用の証明書。
* Secure Email (1.3.6.1.5.5.7.3.4) - 電子メールの暗号化用の証明書。
* Client Authentication (OID 1.3.6.1.5.5.7.3.2) - 他のサーバー（例：AD）への認証用の証明書。
* Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2) - スマートカード認証に使用する証明書。
* Server Authentication (OID 1.3.6.1.5.5.7.3.1) - サーバー（例：HTTPS 証明書）を識別するための証明書。
* **Signature Algorithm** - 証明書に署名するために使用されるアルゴリズムを指定する。
* **Signature** - 発行者（例：CA）の秘密鍵を使用して証明書本体の署名。

#### Subject Alternative Names

**Subject Alternative Name**（SAN）は X.509v3 拡張機能です。これにより、**追加のアイデンティティ**を**証明書**にバインドすることができます。例えば、Web サーバーが**複数のドメインのコンテンツ**をホストしている場合、**各**適用される**ドメイン**を**SAN**に**含める**ことができ、Web サーバーは単一の HTTPS 証明書のみを必要とします。

デフォルトでは、証明書ベースの認証中に、AD は SAN に指定された UPN に基づいて証明書をユーザーアカウントにマッピングする方法の一つです。攻撃者がクライアント認証を可能にする EKU を持つ証明書のリクエスト時に**任意の SAN**を**指定できる**場合、CA が攻撃者が提供した SAN を使用して証明書を作成して署名すると、**攻撃者はドメイン内の任意のユーザーになることができます**。

### CAs

AD CS は、`CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>` のコンテナの下にある 4 つの場所で、AD フォレストが信頼する CA 証明書を定義します。それぞれの目的によって異なります：

* **Certification Authorities** コンテナは、**信頼されるルート CA 証明書**を定義します。これらの CA は PKI ツリー階層の**最上位**にあり、AD CS 環境での信頼の基盤です。各 CA はコンテナ内の AD オブジェクトとして表され、**objectClass** は **`certificationAuthority`** に設定され、**`cACertificate`** プロパティには **CA の証明書のバイト**が含まれます。Windows はこれらの CA 証明書を**各 Windows マシン**の信頼されたルート証明機関の証明書ストアに伝播します。AD が証明書を**信頼されたものとして考慮する**ためには、証明書の信頼**チェーン**は最終的にこのコンテナで定義された**ルート CA のいずれかで**終わる必要があります。
* **Enrolment Services** コンテナは、**Enterprise CA**（つまり、Enterprise CA ロールが有効になっている AD CS で作成された CA）を定義します。各 Enterprise CA には、以下の属性を持つ AD オブジェクトがあります：
* **objectClass** 属性を **`pKIEnrollmentService`** に設定
* **`cACertificate`** 属性には **CA の証明書のバイト**が含まれる
* **`dNSHostName`** プロパティには **CA の DNS ホスト**が設定されている
* **certificateTemplates** フィールドには **有効な証明書テンプレート**が定義されています。証明書テンプレートは、CA が証明書を作成する際に使用する設定の「設計図」であり、EKU、登録権限、証明書の有効期限、発行要件、暗号化設定などが含まれます。証明書テンプレートについては後で詳しく説明します。

{% hint style="info" %}
AD 環境では、**クライアントは Enterprise CA と対話して、証明書テンプレートで定義された設定に基づいて証明書をリクエストします**。Enterprise CA の証明書は、各 Windows マシンの中間証明機関の証明書ストアに伝播されます。
{% endhint %}

* **NTAuthCertificates** AD オブジェクトは、AD への認証を可能にする CA 証明書を定義します。このオブジェクトには **objectClass** が **`certificationAuthority`** であり、オブジェクトの **`cACertificate`** プロパティは **信頼される CA 証明書の配列**を定義します。AD に参加している Windows マシンは、これらの CA を各マシンの中間証明機関の証明書ストアに伝播します。**クライアント** アプリケーションは、NTAuthCertificates オブジェクトによって定義された **CA のいずれかが** 認証クライアントの証明書に**署名している場合に限り**、AD に対して証明書を使用して**認証**することができます。
* **AIA**（Authority Information Access）コンテナは、中間およびクロス CA の AD オブジェクトを保持します。**中間 CA はルート CA の「子」**であり、PKI ツリー階層内で、このコンテナは**証明書チェーンの検証**を支援するために存在します。Certification Authorities コンテナと同様に、各**CA は AIA コンテナ内の AD オブジェクト**として表され、objectClass 属性は certificationAuthority に設定され、**`cACertificate`** プロパティには **CA の証明書のバイト**が含まれます。これらの CA は、各 Windows マシンの中間証明機関の証明書ストアに伝播されます。

### クライアント証明書リクエストフロー

<figure><img src="../../.gitbook/assets/image (5) (2) (2).png" alt=""><figcaption></figcaption></figure>

AD CS から**証明書を取得する**プロセスです。概要を説明すると、登録中にクライアントはまず上記で説明した**Enrolment Services** コンテナのオブジェクトに基づいて **Enterprise CA を見つけます**。

1. クライアントは次に **公開鍵-秘密鍵ペア**を生成し、
2. 公開鍵を **証明書署名リクエスト（CSR）** メッセージに配置し、証明書の主体や**証明書テンプレート名**などの詳細とともに配置します。クライアントは CSR を自分の秘密鍵で**署名**し、CSR を Enterprise CA サーバーに送信します。
3. **CA** サーバーは、クライアントが**証明書をリクエストできるかどうかを確認します**。そうであれば、CSR で指定された**証明書テンプレート** AD オブジェクトを参照して、証明書を発行するかどうかを決定します。CA は、証明書テンプレート AD オブジェクトの**権限が**認証アカウントが**証明書を取得できるかどうかを確認します**。
4. そうであれば、**CA は証明書を生成**します。これは、**証明書テンプレート**で定義された「設計図」設定（例：EKU、暗号化設定、発行要件など）を使用し、証明書のテンプレート設定で許可されている場合は CSR に提供されたその他の情報を使用します。**CA は証明書に自分の秘密鍵で署名**し、それをクライアントに返します。

### 証明書テンプレート

AD CS は、利用可能な証明書テンプレートを以下のコンテナにある **`pKICertificateTemplate`** の **objectClass** を持つ AD オブジェクトとして格納します：

`CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>`

AD 証明書テンプレートオブジェクトの属性はその**設定を定義し、セキュリティ記述子は**どの**プリンシパルが**証明書に登録できるか、または証明書テンプレートを**編集**できるかを制御します。

AD 証明書テンプレートオブジェクトの **`pKIExtendedKeyUsage`** 属性には、テンプレートで有効になっている **OID の配列**が含まれます。これらの EKU OID は、**証明書を使用できる内容に影響を与えます**。[可能な OID のリストはこちら](https://www.pkisolutions.com/object-identifiers-oid-in-pki/)で見つけることができます。

#### 認証 OID

* `1.3.6.1.5.5.7.3.2`: クライアント認証
* `1.3.6.1.5.2.3.4`: PKINIT クライアント認証（手動で追加する必要がある）
* `1.3.6.1.4.1.311.20.2.2`: スマートカードログオン
* `2.5.29.37.0`: 任意の目的
* `(no EKUs)`: SubCA
* 私たちが悪用できると判断した追加の EKU OID は、Certificate Request Agent OID (`1.3.6.1.4.1.311.20.2.1`) です。この OID を持つ証明書は、特定の制限が設けられていない限り、**他のユーザーに代わって証明書をリクエストするために使用できます**。

## 証明書登録

管理者は**証明書テンプレートを作成する必要があり**、その後、**Enterprise CA がテンプレートを「公開」**し、クライアントが登録できるようにします。AD CS は、**Enterprise CA
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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
