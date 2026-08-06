# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### 証明書の構成要素

- 証明書の **Subject** は、その所有者を示します。
- **Public Key** は非公開で保持される鍵と対になり、証明書を正当な所有者に結び付けます。
- **NotBefore** と **NotAfter** の日付で定義される **Validity Period** は、証明書の有効期間を示します。
- Certificate Authority (CA) によって付与される一意の **Serial Number** は、各証明書を識別します。
- **Issuer** は、証明書を発行した CA を示します。
- **SubjectAlternativeName** により、Subject に追加の名前を設定でき、識別の柔軟性が高まります。
- **Basic Constraints** は、証明書が CA 用か end entity 用かを示し、使用制限を定義します。
- **Extended Key Usages (EKUs)** は、Object Identifiers (OIDs) を通じて、コード署名やメール暗号化など、証明書の具体的な用途を定義します。
- **Signature Algorithm** は、証明書への署名方法を指定します。
- 発行者の非公開鍵で作成される **Signature** は、証明書の真正性を保証します。<sup>[[1]](#references)</sup>

### 特別な考慮事項

- **Subject Alternative Names (SANs)** により、証明書を複数の ID に適用できるようになります。これは複数のドメインを持つサーバーにとって重要です。SAN の指定を攻撃者に操作され、なりすましのリスクが生じるのを防ぐには、安全な発行プロセスが不可欠です。<sup>[[1]](#references)</sup>

### Active Directory (AD) の Certificate Authorities (CAs)

AD CS は、専用のコンテナーを通じて AD forest 内の CA 証明書を認識し、それぞれが固有の役割を果たします。<sup>[[1]](#references)</sup>

- **Certification Authorities** コンテナーには、信頼された root CA 証明書が格納されます。
- **Enrolment Services** コンテナーには、Enterprise CAs とその certificate templates の詳細が格納されます。
- **NTAuthCertificates** オブジェクトには、AD authentication に使用することを許可された CA 証明書が含まれます。
- **AIA (Authority Information Access)** コンテナーは、intermediate CA 証明書および cross CA 証明書を使用した証明書チェーンの検証を支援します。

### 証明書の取得: Client Certificate Request Flow

1. リクエストプロセスは、client が Enterprise CA を検索することから始まります。
2. public-private key pair を生成した後、public key やその他の詳細を含む CSR が作成されます。
3. CA は、利用可能な certificate templates に照らして CSR を評価し、template の権限に基づいて証明書を発行します。
4. 承認されると、CA は自身の非公開鍵で証明書に署名し、client に返します。<sup>[[1]](#references)</sup>

### Certificate Templates

AD 内で定義されるこれらの template は、許可される EKUs、enrollment 権限、変更権限など、証明書の発行に関する設定と権限を定めます。これは certificate services へのアクセスを管理する上で重要です。<sup>[[1]](#references)</sup>

## Certificate Enrollment

証明書の enrollment プロセスは、administrator が **certificate template を作成**することで開始され、その後 Enterprise Certificate Authority (CA) によって **publish** されます。これにより、その template が client enrollment で利用可能になります。この処理は、Active Directory オブジェクトの `certificatetemplates` フィールドに template の名前を追加することで実行されます。<sup>[[1]](#references)</sup>

client が証明書をリクエストするには、**enrollment rights** が付与されている必要があります。これらの権限は、certificate template と Enterprise CA 自体の security descriptor によって定義されます。リクエストを成功させるには、両方の場所で権限を付与する必要があります。<sup>[[1]](#references)</sup>

### Template Enrollment Rights

これらの権限は Access Control Entries (ACEs) を通じて指定され、次のような権限が定義されます。<sup>[[1]](#references)</sup>

- **Certificate-Enrollment** および **Certificate-AutoEnrollment** 権限。各権限には固有の GUID が関連付けられています。
- すべての拡張権限を許可する **ExtendedRights**。
- template に対する完全な制御を提供する **FullControl/GenericAll**。

### Enterprise CA Enrollment Rights

CA の権限は、その security descriptor に記述されており、Certificate Authority management console からアクセスできます。一部の設定では、low-privileged users に remote access まで許可できるため、セキュリティ上の懸念となる可能性があります。<sup>[[1]](#references)</sup>

### 追加の発行制御

次のような制御が適用される場合があります。<sup>[[1]](#references)</sup>

- **Manager Approval**: certificate manager によって承認されるまで、リクエストを pending 状態にします。
- **Enrolment Agents and Authorized Signatures**: CSR に必要な署名数と、必要な Application Policy OIDs を指定します。

### 証明書をリクエストする方法

証明書は、次の方法でリクエストできます。<sup>[[1]](#references)</sup>

1. DCOM interfaces を使用する **Windows Client Certificate Enrollment Protocol** (MS-WCCE)。
2. named pipes または TCP/IP を介する **ICertPassage Remote Protocol** (MS-ICPR)。
3. Certificate Authority Web Enrollment role がインストールされた **certificate enrollment web interface**。
4. Certificate Enrollment Policy (CEP) service と組み合わせて使用する **Certificate Enrollment Service** (CES)。
5. Simple Certificate Enrollment Protocol (SCEP) を使用する network devices 向けの **Network Device Enrollment Service** (NDES)。

Windows users は、GUI (`certmgr.msc` または `certlm.msc`) や command-line tools (`certreq.exe` または PowerShell の `Get-Certificate` command) からも証明書をリクエストできます。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) は、主に **Kerberos** および **Secure Channel (Schannel)** プロトコルを使用した証明書認証をサポートしています。<sup>[[1]](#references)</sup>

### Kerberos Authentication Process

Kerberos 認証プロセスでは、ユーザーが Ticket Granting Ticket (TGT) を要求する際、その要求はユーザーの証明書の **private key** を使用して署名されます。この要求は、証明書の **validity**、**path**、**revocation status** など、ドメインコントローラーによる複数の検証を受けます。検証には、証明書が信頼できるソースから発行されたものであることの確認や、発行者が **NTAUTH certificate store** に存在することの確認も含まれます。検証に成功すると、TGT が発行されます。AD の **`NTAuthCertificates`** オブジェクトは、次の場所にあります。
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
は、certificate authentication における trust の確立の中核となります。<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) Authentication

Schannel は安全な TLS/SSL 接続を実現します。handshake の際、client は certificate を提示し、それが正常に検証されると access が認可されます。<sup>[[2]](#references)</sup> certificate と AD account の mapping には、Kerberos の **S4U2Self** function や certificate の **Subject Alternative Name (SAN)** などの methods が使用されます。<sup>[[1]](#references)</sup>

### AD Certificate Services Enumeration

AD の certificate services は LDAP queries を通じて enumeration でき、**Enterprise Certificate Authorities (CAs)** とその configurations に関する information が明らかになります。これは special privileges を持たない domain-authenticated user であれば access できます。<sup>[[1]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** などの tools は、AD CS environments における enumeration と vulnerability assessment に使用されます。<sup>[[3]](#references)</sup>

これらの tools を使用する commands は次のとおりです。
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

- [1] [Certified Pre-Owned: Active Directory Certificate Services の悪用](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [SSL/TLS Client Authentication とは何か、どのように機能するのか？](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
