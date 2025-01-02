# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **証明書の主題**はその所有者を示します。
- **公開鍵**は、証明書を正当な所有者にリンクするために、プライベートキーとペアになっています。
- **有効期間**は、**NotBefore**および**NotAfter**の日付によって定義され、証明書の有効な期間を示します。
- 一意の**シリアル番号**は、証明書機関（CA）によって提供され、各証明書を識別します。
- **発行者**は、証明書を発行したCAを指します。
- **SubjectAlternativeName**は、主題の追加名を許可し、識別の柔軟性を高めます。
- **基本制約**は、証明書がCA用かエンドエンティティ用かを識別し、使用制限を定義します。
- **拡張キー使用法（EKU）**は、オブジェクト識別子（OID）を通じて、コード署名やメール暗号化など、証明書の特定の目的を区別します。
- **署名アルゴリズム**は、証明書に署名する方法を指定します。
- **署名**は、発行者のプライベートキーで作成され、証明書の真正性を保証します。

### Special Considerations

- **Subject Alternative Names (SANs)**は、証明書の適用範囲を複数のアイデンティティに拡張し、複数のドメインを持つサーバーにとって重要です。攻撃者がSAN仕様を操作することによる偽装リスクを避けるために、安全な発行プロセスが重要です。

### Certificate Authorities (CAs) in Active Directory (AD)

AD CSは、ADフォレスト内のCA証明書を指定されたコンテナを通じて認識し、それぞれが独自の役割を果たします：

- **Certification Authorities**コンテナは、信頼されたルートCA証明書を保持します。
- **Enrolment Services**コンテナは、エンタープライズCAとその証明書テンプレートの詳細を示します。
- **NTAuthCertificates**オブジェクトは、AD認証のために承認されたCA証明書を含みます。
- **AIA (Authority Information Access)**コンテナは、中間CAおよびクロスCA証明書を使用して証明書チェーンの検証を促進します。

### Certificate Acquisition: Client Certificate Request Flow

1. リクエストプロセスは、クライアントがエンタープライズCAを見つけることから始まります。
2. 公開鍵とその他の詳細を含むCSRが作成され、公開-プライベートキーのペアが生成された後に行われます。
3. CAは、利用可能な証明書テンプレートに対してCSRを評価し、テンプレートの権限に基づいて証明書を発行します。
4. 承認後、CAはプライベートキーで証明書に署名し、クライアントに返します。

### Certificate Templates

AD内で定義されたこれらのテンプレートは、証明書を発行するための設定と権限を概説し、許可されたEKUや登録または変更権限を含み、証明書サービスへのアクセス管理において重要です。

## Certificate Enrollment

証明書の登録プロセスは、管理者が**証明書テンプレートを作成**し、それがエンタープライズ証明書機関（CA）によって**公開**されることから始まります。これにより、クライアントの登録に利用可能なテンプレートが作成され、Active Directoryオブジェクトの`certificatetemplates`フィールドにテンプレート名を追加することで達成されます。

クライアントが証明書をリクエストするには、**登録権限**が付与されている必要があります。これらの権限は、証明書テンプレートおよびエンタープライズCA自体のセキュリティ記述子によって定義されます。リクエストが成功するためには、両方の場所で権限が付与される必要があります。

### Template Enrollment Rights

これらの権限は、アクセス制御エントリ（ACE）を通じて指定され、次のような権限が詳細に示されます：

- **Certificate-Enrollment**および**Certificate-AutoEnrollment**権限は、それぞれ特定のGUIDに関連付けられています。
- **ExtendedRights**は、すべての拡張権限を許可します。
- **FullControl/GenericAll**は、テンプレートに対する完全な制御を提供します。

### Enterprise CA Enrollment Rights

CAの権限は、そのセキュリティ記述子に記載されており、証明書機関管理コンソールを介してアクセス可能です。一部の設定では、低権限のユーザーにリモートアクセスを許可することもあり、これはセキュリティ上の懸念となる可能性があります。

### Additional Issuance Controls

特定の制御が適用される場合があります。たとえば：

- **マネージャーの承認**：リクエストを保留状態にし、証明書マネージャーによって承認されるまで待機します。
- **登録エージェントおよび承認された署名**：CSRに必要な署名の数と必要なアプリケーションポリシーOIDを指定します。

### Methods to Request Certificates

証明書は次の方法でリクエストできます：

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)、DCOMインターフェースを使用。
2. **ICertPassage Remote Protocol** (MS-ICPR)、名前付きパイプまたはTCP/IPを介して。
3. **証明書登録ウェブインターフェース**、証明書機関ウェブ登録役割がインストールされていること。
4. **Certificate Enrollment Service** (CES)、証明書登録ポリシー（CEP）サービスと連携。
5. **Network Device Enrollment Service** (NDES)、ネットワークデバイス用、シンプル証明書登録プロトコル（SCEP）を使用。

Windowsユーザーは、GUI（`certmgr.msc`または`certlm.msc`）またはコマンドラインツール（`certreq.exe`またはPowerShellの`Get-Certificate`コマンド）を介しても証明書をリクエストできます。
```powershell
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 証明書認証

Active Directory (AD) は、主に **Kerberos** と **Secure Channel (Schannel)** プロトコルを利用して証明書認証をサポートしています。

### Kerberos 認証プロセス

Kerberos 認証プロセスでは、ユーザーの Ticket Granting Ticket (TGT) の要求がユーザーの証明書の **秘密鍵** を使用して署名されます。この要求は、ドメインコントローラーによって、証明書の **有効性**、**パス**、および **失効状況** を含むいくつかの検証を受けます。検証には、証明書が信頼できるソースから来ていることの確認や、**NTAUTH 証明書ストア** に発行者が存在することの確認も含まれます。検証が成功すると、TGT が発行されます。AD の **`NTAuthCertificates`** オブジェクトは、次の場所にあります:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
信頼を確立するために中心的な役割を果たします。

### セキュアチャネル (Schannel) 認証

Schannelは、安全なTLS/SSL接続を促進し、ハンドシェイク中にクライアントが証明書を提示します。証明書が正常に検証されると、アクセスが許可されます。証明書をADアカウントにマッピングするには、Kerberosの**S4U2Self**機能や証明書の**Subject Alternative Name (SAN)**など、他の方法が関与する場合があります。

### AD証明書サービスの列挙

ADの証明書サービスはLDAPクエリを通じて列挙でき、**Enterprise Certificate Authorities (CAs)**およびその構成に関する情報を明らかにします。これは特別な権限なしに、ドメイン認証されたユーザーによってアクセス可能です。**[Certify](https://github.com/GhostPack/Certify)**や**[Certipy](https://github.com/ly4k/Certipy)**のようなツールは、AD CS環境での列挙と脆弱性評価に使用されます。

これらのツールを使用するためのコマンドには次のものが含まれます:
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

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)

{{#include ../../banners/hacktricks-training.md}}
