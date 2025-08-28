# AD 証明書

{{#include ../../../banners/hacktricks-training.md}}

## はじめに

### 証明書の構成要素

- **Subject** は証明書の所有者を示します。
- **Public Key** は秘密鍵と対になり、証明書を正当な所有者に結び付けます。
- **Validity Period**（**NotBefore** と **NotAfter** によって定義）は、証明書の有効期間を示します。
- 一意の **Serial Number** は Certificate Authority (CA) によって付与され、各証明書を識別します。
- **Issuer** は証明書を発行した CA を指します。
- **SubjectAlternativeName** は主体に追加の名前を許可し、識別の柔軟性を高めます。
- **Basic Constraints** は証明書が CA 向けかエンドエンティティ向けかを識別し、使用制限を定義します。
- **Extended Key Usages (EKUs)** は、**Object Identifiers (OIDs)** を通じてコード署名やメール暗号化など証明書の特定の用途を示します。
- **Signature Algorithm** は証明書に署名するための方法を指定します。
- **Signature** は Issuer の秘密鍵で作成され、証明書の真正性を保証します。

### 特別な考慮事項

- **Subject Alternative Names (SANs)** は複数の識別子に対して証明書の適用範囲を拡大し、複数ドメインを持つサーバーにとって重要です。発行プロセスを適切に保護しないと、攻撃者が SAN の仕様を操作してなりすましを行うリスクが生じます。

### Active Directory (AD) における Certificate Authorities (CAs)

AD CS は、AD フォレスト内の指定コンテナを通じて CA 証明書を認識し、各コンテナは固有の役割を果たします：

- **Certification Authorities** コンテナは信頼されたルート CA 証明書を格納します。
- **Enrolment Services** コンテナは Enterprise CAs とその証明書テンプレートに関する情報を保持します。
- **NTAuthCertificates** オブジェクトは AD 認証で許可された CA 証明書を含みます。
- **AIA (Authority Information Access)** コンテナは中間 CA やクロス CA の証明書を用いた証明書チェーン検証を容易にします。

### 証明書取得：クライアントによる証明書要求のフロー

1. 要求プロセスはクライアントが Enterprise CA を発見することから始まります。
2. 公開/秘密鍵ペアを生成した後、公開鍵やその他の詳細を含む CSR が作成されます。
3. CA は利用可能な証明書テンプレートに対して CSR を評価し、テンプレートの権限に基づいて証明書を発行します。
4. 承認されると、CA は自身の秘密鍵で証明書に署名し、クライアントに返します。

### 証明書テンプレート

AD 内で定義されるこれらのテンプレートは、許可される EKU や登録・変更の権限など、証明書発行に関する設定と権限を定義し、証明書サービスへのアクセス管理において重要です。

## 証明書登録

証明書の登録プロセスは、管理者が **証明書テンプレートを作成** することで開始され、Enterprise Certificate Authority (CA) によって **公開（published）** されます。これによりテンプレートはクライアントの登録に利用可能になり、Active Directory オブジェクトの `certificatetemplates` フィールドにテンプレート名を追加することで行われます。

クライアントが証明書を要求するには、**enrollment rights** が付与されている必要があります。これらの権利は証明書テンプレートおよび Enterprise CA 自身のセキュリティ記述子によって定義されます。要求を成功させるには両方に権限が付与されている必要があります。

### テンプレートのエンロールメント権限

これらの権利は Access Control Entries (ACEs) で指定され、次のような権限を含みます：

- **Certificate-Enrollment** および **Certificate-AutoEnrollment** の権利（それぞれ特定の GUID に紐づく）。
- **ExtendedRights**（全ての拡張権限を許可）。
- **FullControl/GenericAll**（テンプレートに対する完全な制御）。

### Enterprise CA のエンロールメント権限

CA の権利はそのセキュリティ記述子に明記されており、Certificate Authority management console からアクセスできます。一部の設定は権限の低いユーザーに遠隔アクセスを許可することがあり、これはセキュリティ上の懸念となります。

### 追加の発行制御

特定の制御が適用される場合があります。例えば：

- **Manager Approval**：要求を保留状態にし、証明書マネージャーの承認を待ちます。
- **Enrolment Agents and Authorized Signatures**：CSR に必要な署名数や、必要な Application Policy OIDs を指定します。

### 証明書要求の方法

証明書は以下の方法で要求できます：

1. Windows Client Certificate Enrollment Protocol (MS-WCCE)（DCOM インターフェースを使用）。
2. ICertPassage Remote Protocol (MS-ICPR)、named pipes または TCP/IP 経由。
3. Certificate Authority Web Enrollment ロールがインストールされた証明書登録のウェブインターフェース。
4. Certificate Enrollment Service (CES) と Certificate Enrollment Policy (CEP) サービスを組み合わせた方法。
5. ネットワーク機器向けの Network Device Enrollment Service (NDES)、Simple Certificate Enrollment Protocol (SCEP) を使用。

Windows ユーザーは GUI（certmgr.msc または certlm.msc）やコマンドラインツール（certreq.exe や PowerShell の Get-Certificate コマンド）を使って証明書を要求することもできます。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 証明書認証

Active Directory (AD) は主に **Kerberos** と **Secure Channel (Schannel)** プロトコルを利用して証明書認証をサポートします。

### Kerberos 認証プロセス

Kerberos 認証プロセスでは、ユーザーの Ticket Granting Ticket (TGT) 取得要求はユーザーの証明書の **秘密鍵** で署名されます。この要求はドメインコントローラーによっていくつかの検証を受け、検証項目には証明書の **有効性**、**パス（証明書チェーン）**、および **失効状況** が含まれます。さらに、証明書が信頼できる発行元からのものであることの確認や、発行者が **NTAUTH 証明書ストア** に存在することの確認も行われます。検証が成功すると TGT が発行されます。AD の **`NTAuthCertificates`** オブジェクトは次の場所にあります:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
証明書認証の信頼を確立する上で中心的な役割を果たす。

### Secure Channel (Schannel) 認証

Schannel は TLS/SSL によるセキュアな接続を促進します。ハンドシェイク中にクライアントが証明書を提示し、それが検証に成功すればアクセスが許可されます。証明書を AD アカウントにマッピングする方法には、Kerberos の **S4U2Self** 機能や証明書の **Subject Alternative Name (SAN)** などが含まれます。

### AD Certificate Services の列挙

AD の証明書サービスは LDAP クエリで列挙でき、**Enterprise Certificate Authorities (CAs)** やその設定に関する情報が明らかになります。これは特別な権限を必要とせず、ドメイン認証済みの任意のユーザーがアクセス可能です。ツールとしては **[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** のようなものが、AD CS 環境での列挙や脆弱性評価に使用されます。

これらのツールを使用するためのコマンドには次のようなものがあります：
```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
## 参考資料

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
