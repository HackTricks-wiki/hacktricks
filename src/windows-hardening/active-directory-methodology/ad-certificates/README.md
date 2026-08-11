# AD Certificates

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **Subject** は証明書の所有者を示します。
- **Public Key** は非公開で保持される鍵と対になり、証明書を正当な所有者に結び付けます。
- **Validity Period** は **NotBefore** と **NotAfter** の日付で定義され、証明書の有効期間を示します。
- **Serial Number** は Certificate Authority (CA) によって付与され、各証明書を一意に識別します。
- **Issuer** は証明書を発行した CA を示します。
- **SubjectAlternativeName** により、subject に追加の名前を指定でき、識別の柔軟性が向上します。
- **Basic Constraints** は証明書が CA 用か end entity 用かを識別し、使用制限を定義します。
- **Extended Key Usages (EKUs)** は、Object Identifiers (OIDs) を通じて、コード署名やメール暗号化など、証明書の具体的な用途を定義します。
- **Signature Algorithm** は証明書への署名方法を指定します。
- **Signature** は issuer の秘密鍵で作成され、証明書の真正性を保証します。<sup>[[1]](#references)</sup>

### Special Considerations

- **Subject Alternative Names (SANs)** により、証明書を複数の ID に適用できるようになります。これは複数のドメインを持つサーバーにとって重要です。攻撃者が SAN の指定を操作してなりすますリスクを避けるには、安全な発行プロセスが不可欠です。<sup>[[1]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS は、専用のコンテナーを通じて AD forest 内の CA 証明書を認識します。各コンテナーには固有の役割があります。<sup>[[1]](#references)</sup>

- **Certification Authorities** コンテナーには、信頼された root CA 証明書が格納されます。
- **Enrolment Services** コンテナーには、Enterprise CA とその certificate templates の詳細が格納されます。
- **NTAuthCertificates** オブジェクトには、AD authentication に使用できる CA 証明書が含まれます。
- **AIA (Authority Information Access)** コンテナーは、intermediate および cross CA 証明書を使用した証明書チェーンの検証を可能にします。

### Certificate Acquisition: Client Certificate Request Flow

1. 要求プロセスは、client が Enterprise CA を見つけることから始まります。
2. public-private key pair の生成後、public key とその他の情報を含む CSR が作成されます。
3. CA は利用可能な certificate templates に照らして CSR を評価し、template の権限に基づいて証明書を発行します。
4. 承認されると、CA は秘密鍵で証明書に署名し、client に返します。<sup>[[1]](#references)</sup>

### Certificate Templates

AD 内で定義されるこれらの templates は、許可される EKUs、enrollment 権限、変更権限など、証明書発行時の設定と権限を定めます。これは certificate services へのアクセス管理に不可欠です。<sup>[[1]](#references)</sup>

## Certificate Enrollment

証明書の enrollment プロセスは、administrator が **certificate template を作成**することで開始され、その後 Enterprise Certificate Authority (CA) によって **公開**されます。これにより template が client の enrollment に利用可能になります。この処理は、Active Directory オブジェクトの `certificatetemplates` フィールドに template 名を追加することで実行されます。<sup>[[1]](#references)</sup>

client が証明書を要求するには、**enrollment rights** が付与されている必要があります。これらの権限は、certificate template と Enterprise CA 自体の security descriptors によって定義されます。要求を成功させるには、両方の場所で権限を付与する必要があります。<sup>[[1]](#references)</sup>

### Template Enrollment Rights

これらの権限は Access Control Entries (ACEs) によって指定され、次のような権限を定義します。<sup>[[1]](#references)</sup>

- **Certificate-Enrollment** および **Certificate-AutoEnrollment** rights。それぞれ固有の GUID に関連付けられています。
- **ExtendedRights**。すべての拡張権限を許可します。
- **FullControl/GenericAll**。template を完全に制御できます。

### Enterprise CA Enrollment Rights

CA の権限は、その security descriptor に記述されており、Certificate Authority management console から確認できます。一部の設定では、低権限ユーザーに remote access まで許可されるため、セキュリティ上の懸念となる可能性があります。<sup>[[1]](#references)</sup>

### Additional Issuance Controls

次のような追加の制御が適用される場合があります。<sup>[[1]](#references)</sup>

- **Manager Approval**: certificate manager によって承認されるまで、要求を pending 状態にします。
- **Enrolment Agents and Authorized Signatures**: CSR に必要な署名数と、必要な Application Policy OIDs を指定します。

### Methods to Request Certificates

証明書は次の方法で要求できます。<sup>[[1]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)。DCOM interfaces を使用します。
2. **ICertPassage Remote Protocol** (MS-ICPR)。named pipes または TCP/IP を介して使用します。
3. **certificate enrollment web interface**。Certificate Authority Web Enrollment role がインストールされている必要があります。
4. **Certificate Enrollment Service** (CES)。Certificate Enrollment Policy (CEP) service と組み合わせて使用します。
5. **Network Device Enrollment Service** (NDES)。Simple Certificate Enrollment Protocol (SCEP) を使用して network devices 向けに利用します。

Windows users は、GUI (`certmgr.msc` または `certlm.msc`) や command-line tools (`certreq.exe` または PowerShell の `Get-Certificate` command) を使用して証明書を要求することもできます。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## 証明書認証

Active Directory (AD) は、主に **Kerberos** および **Secure Channel (Schannel)** プロトコルを利用した証明書認証をサポートしています。<sup>[[1]](#references)</sup>

### Kerberos 認証プロセス

Kerberos 認証プロセスでは、ユーザーが Ticket Granting Ticket (TGT) を要求する際、その要求はユーザーの証明書の **private key** を使用して署名されます。この要求は、証明書の **validity**、**path**、**revocation status** など、ドメインコントローラーによる複数の検証を受けます。検証には、証明書が信頼されたソースから発行されたものであることの確認や、発行者が **NTAUTH certificate store** に存在することの確認も含まれます。検証に成功すると、TGT が発行されます。AD 内の **`NTAuthCertificates`** オブジェクトは、次の場所にあります。
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
証明書認証の信頼確立において中心的な役割を果たします。<sup>[[1]](#references)</sup>

### Secure Channel (Schannel) Authentication

Schannel は安全な TLS/SSL 接続を実現します。ハンドシェイク中にクライアントが証明書を提示し、その証明書の検証に成功するとアクセスが認可されます。<sup>[[2]](#references)</sup> 証明書を AD アカウントにマッピングする方法には、Kerberos の **S4U2Self** 機能や証明書の **Subject Alternative Name (SAN)** などがあります。<sup>[[1]](#references)</sup>

### AD Certificate Services Enumeration

AD の certificate services は LDAP クエリを通じて列挙でき、**Enterprise Certificate Authorities (CAs)** とその構成に関する情報が明らかになります。これは特別な権限を持たない、ドメイン認証済みのユーザーであれば誰でも利用できます。<sup>[[1]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** などのツールは、AD CS 環境での列挙および脆弱性評価に使用されます。<sup>[[3]](#references)</sup>

これらのツールを使用するコマンドは次のとおりです。
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
Rubeus は、パスワードで保護された PFX 証明書を PKINIT authentication に使用して、TGT を要求することもできます。オプションの `/getcredentials` switch は U2U service ticket を要求し、アカウントの NT hash の復元を試みます:<sup>[[4]](#references)</sup>
```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```
## References

- [1] [Certified Pre-Owned: Active Directory Certificate Servicesの悪用](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [2] [SSL/TLSクライアント認証とは何か？どのように機能するのか？](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [3] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../../banners/hacktricks-training.md}}
