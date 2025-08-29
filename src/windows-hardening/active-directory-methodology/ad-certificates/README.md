# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- 証明書の **Subject** はその所有者を示します。
- **Public Key** は、証明書を正当な所有者に結びつけるための秘密鍵とペアになります。
- **Validity Period**（**NotBefore** および **NotAfter** 日付で定義）は、証明書の有効期間を示します。
- 各証明書を識別する一意の **Serial Number** は、Certificate Authority (CA) によって付与されます。
- **Issuer** は証明書を発行した CA を指します。
- **SubjectAlternativeName** は、被験者の追加の名前を許可し、識別の柔軟性を高めます。
- **Basic Constraints** は、証明書が CA 用かエンドエンティティ用かを識別し、使用制限を定義します。
- **Extended Key Usages (EKUs)** は、Object Identifiers (OIDs) を通じて、code signing や email encryption のような証明書の具体的な用途を区別します。
- **Signature Algorithm** は証明書を署名する方法を指定します。
- 発行者の秘密鍵で作成された **Signature** は、証明書の真正性を保証します。

### Special Considerations

- **Subject Alternative Names (SANs)** は、複数の識別子に対する証明書の適用性を拡張し、複数ドメインを持つサーバにとって重要です。SAN の仕様を攻撃者が操作してなりすましを行うリスクを避けるため、発行プロセスのセキュリティが重要です。

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS は、AD フォレスト内の特定コンテナを通じて CA 証明書を認識します。各コンテナはそれぞれ固有の役割を持ちます：

- **Certification Authorities** コンテナは信頼されたルート CA 証明書を保持します。
- **Enrolment Services** コンテナは Enterprise CA とその certificate templates に関する情報を保持します。
- **NTAuthCertificates** オブジェクトには、AD 認証に許可された CA 証明書が含まれます。
- **AIA (Authority Information Access)** コンテナは、中間 CA やクロス CA 証明書とともに証明書チェーンの検証を容易にします。

### Certificate Acquisition: Client Certificate Request Flow

1. クライアントは Enterprise CA を見つけることから要求プロセスを開始します。
2. 公開鍵とその他の詳細を含む CSR が、公私鍵ペアの生成後に作成されます。
3. CA は利用可能な certificate templates と照らし合わせて CSR を評価し、テンプレートの権限に基づいて証明書を発行します。
4. 承認されると、CA は自らの秘密鍵で証明書に署名し、それをクライアントに返します。

### Certificate Templates

AD 内で定義されたこれらのテンプレートは、発行時の設定と権限（許可された EKU、enrollment や modification の権利など）を概説しており、証明書サービスへのアクセス管理にとって重要です。

## Certificate Enrollment

証明書の enrollment プロセスは、管理者が **certificate template** を作成することで開始され、Enterprise Certificate Authority (CA) によって **published** されます。これによりテンプレートがクライアントの enrollment に利用可能になり、テンプレート名を Active Directory オブジェクトの `certificatetemplates` フィールドに追加することで実現されます。

クライアントが証明書を要求するには、**enrollment rights** が付与されている必要があります。これらの権利は certificate template および Enterprise CA 自体のセキュリティ記述子によって定義されます。要求を成功させるには、両方の場所で権限が付与されていなければなりません。

### Template Enrollment Rights

これらの権利は Access Control Entries (ACEs) を通じて指定され、次のような権限を詳細に示します：

- 特定の GUID に関連づけられた **Certificate-Enrollment** および **Certificate-AutoEnrollment** 権利。
- すべての拡張権限を許可する **ExtendedRights**。
- テンプレートに対する完全な制御を提供する **FullControl/GenericAll**。

### Enterprise CA Enrollment Rights

CA の権利は、そのセキュリティ記述子に概説されており、Certificate Authority 管理コンソールからアクセス可能です。一部の設定では低特権ユーザにリモートアクセスを許可するものもあり、これはセキュリティ上の懸念となり得ます。

### Additional Issuance Controls

適用される場合の制御には、次のようなものがあります：

- **Manager Approval**：要求を保留状態にし、証明書マネージャの承認まで待機させます。
- **Enrolment Agents and Authorized Signatures**：CSR に必要な署名数や必要な Application Policy OID を指定します。

### Methods to Request Certificates

証明書は次の方法で要求できます：

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)、DCOM インターフェイスを使用。
2. **ICertPassage Remote Protocol** (MS-ICPR)、named pipes または TCP/IP 経由。
3. Certificate Authority Web Enrollment role をインストールした **certificate enrollment web interface**。
4. **Certificate Enrollment Service (CES)**、および Certificate Enrollment Policy (CEP) サービスと連携。
5. ネットワークデバイス向けの **Network Device Enrollment Service (NDES)**、Simple Certificate Enrollment Protocol (SCEP) を使用。

Windows ユーザは GUI (`certmgr.msc` または `certlm.msc`) やコマンドラインツール (`certreq.exe` や PowerShell の `Get-Certificate` コマンド) を通じても証明書を要求できます。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 証明書認証

Active Directory (AD) は証明書認証をサポートしており、主に **Kerberos** と **Secure Channel (Schannel)** プロトコルを利用します。

### Kerberos 認証プロセス

Kerberos 認証プロセスでは、ユーザーが Ticket Granting Ticket (TGT) を要求する際、その要求はユーザーの証明書の **秘密鍵** で署名されます。この要求はドメインコントローラーによっていくつかの検証を受けます。これには証明書の **有効性**、**パス**、および **失効状態** の確認が含まれます。検証にはまた、証明書が信頼できる発行元からのものであることの確認と、発行者が **NTAUTH 証明書ストア** に存在することの確認も含まれます。検証が成功すると、TGT が発行されます。AD 内の **`NTAuthCertificates`** オブジェクトは、次の場所にあります:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
証明書認証の信頼確立にとって中心的である。

### Secure Channel (Schannel) 認証

Schannel は TLS/SSL の安全な接続を仲介し、ハンドシェイク中にクライアントが証明書を提示します。提示された証明書が有効と検証されれば、アクセスが許可されます。証明書を AD アカウントに紐付ける方法としては、Kerberos の **S4U2Self** 関数や証明書の **Subject Alternative Name (SAN)** などが用いられます。

### AD Certificate Services 列挙

AD の Certificate Services は LDAP クエリによって列挙でき、**Enterprise Certificate Authorities (CAs)** やその構成に関する情報が明らかになります。これは特別な権限なしにドメイン認証済みユーザーなら誰でもアクセス可能です。**[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** のようなツールは、AD CS 環境の列挙や脆弱性評価に用いられます。

これらのツールを使用するコマンドには次のものがあります：
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
