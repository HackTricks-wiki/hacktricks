# AD 証明書

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks を PDF でダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションをご覧ください
* **💬 [Discord グループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegram グループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローしてください [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングテクニックを共有してください。

</details>

## はじめに

### 証明書の構成要素

- 証明書の **Subject** は所有者を示します。
- **Public Key** は証明書を正当な所有者にリンクするために、秘密鍵とペアになっています。
- **有効期間** は、**NotBefore** と **NotAfter** の日付によって定義され、証明書の有効期間を示します。
- 証明書毎に提供される一意の **Serial Number** は、Certificate Authority（CA）によって識別されます。
- **Issuer** は証明書を発行した CA を指します。
- **SubjectAlternativeName** は、サブジェクトの追加名を許可し、識別の柔軟性を向上させます。
- **Basic Constraints** は、証明書が CA 用かエンドエンティティ用かを識別し、使用制限を定義します。
- **Extended Key Usages (EKUs)** は、コード署名やメール暗号化などの特定の目的を、Object Identifiers（OIDs）を通じて証明書に明示します。
- **Signature Algorithm** は、証明書に署名するための方法を指定します。
- **Signature** は、発行者の秘密鍵で作成され、証明書の信頼性を保証します。

### 特別な考慮事項

- **Subject Alternative Names (SANs)** は、複数の識別子に証明書を適用するために拡張され、複数のドメインを持つサーバーにとって重要です。SAN 仕様を操作する攻撃者によるなりすましリスクを回避するために、安全な発行プロセスが重要です。

### Active Directory（AD）の証明書機関（CAs）

AD CS は、AD フォレスト内の CA 証明書を指定されたコンテナを介して認識し、それぞれが固有の役割を果たします:

- **Certification Authorities** コンテナには信頼されたルート CA 証明書が保持されます。
- **Enrolment Services** コンテナにはエンタープライズ CA とその証明書テンプレートの詳細が記載されます。
- **NTAuthCertificates** オブジェクトには、AD 認証に認証された CA 証明書が含まれます。
- **AIA (Authority Information Access)** コンテナは、中間およびクロス CA 証明書を使用して証明書チェーンの検証を容易にします。

### 証明書取得: クライアント証明書リクエストフロー

1. リクエストプロセスは、クライアントがエンタープライズ CA を見つけることから始まります。
2. パブリック-プライベートキーペアを生成した後、公開鍵などを含む CSR が作成されます。
3. CA は CSR を利用可能な証明書テンプレートと照合し、テンプレートの権限に基づいて証明書を発行します。
4. 承認されると、CA は証明書に自身の秘密鍵で署名し、クライアントに返します。

### 証明書テンプレート

AD 内で定義されたこれらのテンプレートは、証明書の発行に関する設定と権限を概説し、証明書サービスへのアクセスを管理するために重要です。

## 証明書の登録

証明書の登録プロセスは、管理者が **証明書テンプレートを作成** し、それがエンタープライズ証明書機関（CA）によって **公開** されることで開始されます。これにより、テンプレートの名前が Active Directory オブジェクトの `certificatetemplates` フィールドに追加され、クライアントの登録が可能になります。

証明書をリクエストするためには、 **登録権限** が付与されている必要があります。これらの権限は、証明書テンプレートとエンタープライズ CA 自体のセキュリティ記述子で定義されます。リクエストが成功するには、両方の場所で権限が付与されている必要があります。

### テンプレートの登録権限

これらの権限は、Access Control Entries（ACEs）を介して指定され、次のような権限が詳細に記載されています:
- **Certificate-Enrollment** および **Certificate-AutoEnrollment** 権限は、それぞれ特定の GUID に関連付けられています。
- **ExtendedRights** は、すべての拡張権限を許可します。
- **FullControl/GenericAll** は、テンプレートに対する完全な制御を提供します。

### エンタープライズ CA の登録権限

CA の権限は、証明書機関管理コンソールからアクセス可能なセキュリティ記述子に記載されています。一部の設定では、低特権ユーザーにリモートアクセスを許可することができ、これはセキュリティ上の懸念となる可能性があります。

### 追加の発行コントロール

次のようなコントロールが適用される場合があります:
- **マネージャー承認**: 証明書マネージャーによる承認までリクエストを保留状態にします。
- **Enrolment Agents および Authorized Signatures**: CSR に必要な署名の数と必要な Application Policy OIDs を指定します。

### 証明書をリクエストする方法

証明書は、次の方法でリクエストできます:
1. **Windows クライアント証明書登録プロトコル**（MS-WCCE）、DCOM インターフェースを使用します。
2. **ICertPassage リモートプロトコル**（MS-ICPR）、名前付きパイプまたは TCP/IP を介して使用します。
3. 証明書登録 Web インターフェース、Certificate Authority Web Enrollment ロールがインストールされている場合。
4. **Certificate Enrollment Service**（CES）と **Certificate Enrollment Policy**（CEP）サービスと共に使用します。
5. ネットワークデバイス向けの **Network Device Enrollment Service**（NDES）、Simple Certificate Enrollment Protocol（SCEP）を使用します。

Windows ユーザーは、GUI（`certmgr.msc` または `certlm.msc`）またはコマンドラインツール（`certreq.exe` または PowerShell の `Get-Certificate` コマンド）を使用して証明書をリクエストすることもできます。
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 証明書認証

Active Directory（AD）は、主に**Kerberos**および**Secure Channel（Schannel）**プロトコルを利用して証明書認証をサポートしています。

### Kerberos認証プロセス

Kerberos認証プロセスでは、ユーザーのチケット発行チケット（TGT）のリクエストは、ユーザーの証明書の**秘密鍵**を使用して署名されます。このリクエストは、ドメインコントローラーによって証明書の**有効性**、**パス**、および**失効状態**を含む複数の検証を受けます。検証には、証明書が信頼されるソースから来ていることの確認や、**NTAUTH証明書ストア**内の発行者の存在の確認も含まれます。成功した検証により、TGTが発行されます。AD内の**`NTAuthCertificates`**オブジェクトは、次の場所にあります：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
証明書認証の信頼を確立するための中心的な役割を果たします。

### セキュア チャネル (Schannel) 認証

Schannel はセキュアな TLS/SSL 接続を容易にし、ハンドシェイク中にクライアントが証明書を提示し、成功裏に検証されるとアクセスが許可されます。証明書を AD アカウントにマッピングする際には、Kerberos の **S4U2Self** 関数や証明書の **Subject Alternative Name (SAN)** などの方法が関与する可能性があります。

### AD 証明書サービスの列挙

AD の証明書サービスは LDAP クエリを介して列挙でき、**Enterprise Certificate Authorities (CAs)** およびそれらの構成に関する情報が明らかになります。これは特別な特権を持たないドメイン認証ユーザーでもアクセス可能です。**[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** のようなツールは、AD CS 環境での列挙や脆弱性評価に使用されます。

これらのツールを使用するためのコマンドは次のとおりです：
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## 参考文献

* [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)
* [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする。
* **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
