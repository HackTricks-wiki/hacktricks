# AD 証明書

{{#include ../../banners/hacktricks-training.md}}

## はじめに

### 証明書の構成要素

- **Subject**: 証明書の所有者を示します。
- **Public Key**: 秘密鍵と対になり、証明書を正当な所有者に結びつけます。
- **Validity Period**: **NotBefore** と **NotAfter** 日付で定義され、証明書の有効期間を示します。
- **Serial Number**: 証明書ごとに CA が付与する一意の識別子です。
- **Issuer**: 証明書を発行した CA を指します。
- **SubjectAlternativeName**: サブジェクトに対する追加の名前を許可し、識別の柔軟性を高めます。
- **Basic Constraints**: 証明書が CA 用かエンドエンティティ用かを識別し、使用制限を定義します。
- **Extended Key Usages (EKUs)**: OID を通じて、コード署名やメール暗号化など証明書の具体的な目的を区別します。
- **Signature Algorithm**: 証明書の署名に使用されるアルゴリズムを指定します。
- **Signature**: 発行者の秘密鍵で作られ、証明書の真正性を保証します。

### 特別な考慮事項

- **Subject Alternative Names (SANs)** は、複数の識別子に対して証明書を適用可能にし、複数ドメインを持つサーバーで重要です。SAN 仕様を攻撃者が操作してなりすましを行うリスクを避けるため、発行プロセスの堅牢化が必須です。

### Active Directory (AD) における Certificate Authorities (CAs)

AD CS はフォレスト内の CA 証明書を特定のコンテナで認識します。各コンテナはそれぞれ異なる役割を持ちます:

- **Certification Authorities** コンテナは信頼されたルート CA 証明書を保持します。
- **Enrolment Services** コンテナは Enterprise CA とその証明書テンプレートの情報を保持します。
- **NTAuthCertificates** オブジェクトには AD 認証に承認された CA 証明書が含まれます。
- **AIA (Authority Information Access)** コンテナは中間 CA やクロス CA 証明書を介した証明書チェーン検証を支援します。

### 証明書取得: クライアント証明書リクエストのフロー

1. クライアントは Enterprise CA を見つけることからプロセスが始まります。
2. 公開鍵とその他の情報を含む CSR が、公開鍵と秘密鍵のペアを生成した後に作成されます。
3. CA は利用可能な証明書テンプレートに対して CSR を評価し、テンプレートの権限に基づいて証明書を発行します。
4. 承認されると CA は自分の秘密鍵で証明書に署名してクライアントに返します。

### 証明書テンプレート

AD 内で定義されるテンプレートは、発行設定や権限（許可される EKU、登録または変更権限など）を概説し、証明書サービスへのアクセス管理に重要です。

テンプレートのスキーマバージョンは重要です。レガシーな **v1** テンプレート（例えば組み込みの **WebServer** テンプレート）は多くの現代的な制御機構を欠きます。**ESC15/EKUwu** の研究は、**v1 テンプレート** 上ではリクエスターが CSR に **Application Policies/EKUs** を埋め込み、それがテンプレートで設定された EKU よりも優先されることで、enrollment 権のみで client-auth、enrollment agent、または code-signing 証明書を取得できることを示しました。可能であれば **v2/v3 テンプレート** を利用し、v1 のデフォルトを削除または上書きし、EKU を意図した用途に厳密に限定してください。

## 証明書の登録 (Enrollment)

証明書の登録プロセスは管理者が **証明書テンプレートを作成** し、それを Enterprise CA が **公開** することから始まります。これによりテンプレートはクライアントが登録できる状態になり、Active Directory オブジェクトの `certificatetemplates` フィールドにテンプレート名を追加することで達成されます。

クライアントが証明書を要求するには、**enrollment 権限** が付与されている必要があります。これらの権限は証明書テンプレートと Enterprise CA 自体のセキュリティ記述子で定義されます。リクエストを成功させるには、両方の場所で適切な許可が与えられている必要があります。

### テンプレートの登録権限

これらの権限は ACE（アクセス制御エントリ）を通じて指定され、以下のような許可を含みます:

- **Certificate-Enrollment** および **Certificate-AutoEnrollment** 権限（それぞれ特定の GUID に関連付けられます）。
- **ExtendedRights**（すべての拡張権限を許可）。
- **FullControl/GenericAll**（テンプレートに対する完全な制御を提供）。

### Enterprise CA の登録権限

CA の権限は Certificate Authority 管理コンソールからアクセスできるセキュリティ記述子に記載されています。いくつかの設定は低権限ユーザーにリモートアクセスを許可することもあり、これはセキュリティ上の懸念となり得ます。

### 追加の発行制御

適用される可能性のある制御には次のようなものがあります:

- **Manager Approval**: リクエストを保留状態にし、証明書マネージャーによる承認を要求します。
- **Enrolment Agents and Authorized Signatures**: CSR に必要な署名数や必要な Application Policy OID を指定します。

### 証明書を要求する方法

証明書は次の方法で要求できます:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)、DCOM インターフェースを使用。
2. **ICertPassage Remote Protocol** (MS-ICPR)、named pipes または TCP/IP 経由。
3. Certificate Authority Web Enrollment ロールがインストールされた証明書登録の web インターフェース。
4. **Certificate Enrollment Service** (CES) と **Certificate Enrollment Policy** (CEP) サービスの組み合わせ。
5. ネットワークデバイス用の **Network Device Enrollment Service** (NDES)、Simple Certificate Enrollment Protocol (SCEP) を使用。

Windows ユーザーは GUI（certmgr.msc または certlm.msc）やコマンドラインツール（certreq.exe や PowerShell の Get-Certificate コマンド）を介して証明書を要求することもできます。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) は証明書認証をサポートしており、主に **Kerberos** と **Secure Channel (Schannel)** プロトコルを利用します。

### Kerberos Authentication Process

Kerberos 認証プロセスでは、ユーザーの Ticket Granting Ticket (TGT) 取得要求がユーザーの証明書の **秘密鍵** により署名されます。この要求はドメインコントローラーによって複数の検証を受けます。検証には証明書の **有効性**、**パス**、および **失効状態** の確認が含まれます。さらに、証明書が信頼できる発行元から発行されていることや、発行者が **NTAUTH 証明書ストア** に存在することの確認も行われます。検証に成功すると TGT が発行されます。AD 内の **`NTAuthCertificates`** オブジェクトは、次の場所にあります:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
は証明書認証の信頼を確立する上で中心的な役割を果たします。

### Secure Channel (Schannel) 認証

Schannel は安全な TLS/SSL 接続を提供します。ハンドシェイク中にクライアントは証明書を提示し、それが正常に検証されればアクセスが許可されます。証明書を AD アカウントにマッピングする方法としては、Kerberos の **S4U2Self** 機能や証明書の **Subject Alternative Name (SAN)** などが用いられます。

### AD Certificate Services の列挙

AD の証明書サービス (AD CS) は LDAP クエリを通じて列挙でき、**Enterprise Certificate Authorities (CAs)** やその構成に関する情報を明らかにします。これは特別な権限を必要とせず、ドメイン認証済みの任意のユーザーがアクセス可能です。AD CS 環境の列挙や脆弱性評価には **[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** といったツールが使われます。

Commands for using these tools include:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Recent Vulnerabilities & Security Updates (2022-2025)

| Year | ID / Name | Impact | Key Take-aways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* by spoofing machine account certificates during PKINIT. | Patch is included in the **May 10 2022** security updates. Auditing & strong-mapping controls were introduced via **KB5014754**; environments should now be in *Full Enforcement* mode.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in the AD CS Web Enrollment (certsrv) and CES roles. | Public PoCs are limited, but the vulnerable IIS components are often exposed internally. Patch as of **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | On **v1 templates**, a requester with enrollment rights can embed **Application Policies/EKUs** in the CSR that are preferred over the template EKUs, producing client-auth, enrollment agent, or code-signing certificates. | Patched as of **November 12, 2024**. Replace or supersede v1 templates (e.g., default WebServer), restrict EKUs to intent, and limit enrollment rights. |

### Microsoft hardening timeline (KB5014754)

Microsoft introduced a three-phase rollout (Compatibility → Audit → Enforcement) to move Kerberos certificate authentication away from weak implicit mappings. As of **February 11 2025**, domain controllers automatically switch to **Full Enforcement** if the `StrongCertificateBindingEnforcement` registry value is not set. Administrators should:

1. Patch all DCs & AD CS servers (May 2022 or later).
2. Monitor Event ID 39/41 for weak mappings during the *Audit* phase.
3. Re-issue client-auth certificates with the new **SID extension** or configure strong manual mappings before February 2025.

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** now surfaces posture assessments for ESC1-ESC8/ESC11 and generates real-time alerts such as *“Domain-controller certificate issuance for a non-DC”* (ESC8) and *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Ensure sensors are deployed to all AD CS servers to benefit from these detections.
* Disable or tightly scope the **“Supply in the request”** option on all templates; prefer explicitly defined SAN/EKU values.
* Remove **Any Purpose** or **No EKU** from templates unless absolutely required (addresses ESC2 scenarios).
* Require **manager approval** or dedicated Enrollment Agent workflows for sensitive templates (e.g., WebServer / CodeSigning).
* Restrict web enrollment (`certsrv`) and CES/NDES endpoints to trusted networks or behind client-certificate authentication.
* Enforce RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) to mitigate ESC11 (RPC relay). The flag is **on by default**, but is often disabled for legacy clients, which re-opens relay risk.
* Secure **IIS-based enrollment endpoints** (CES/Certsrv): disable NTLM where possible or require HTTPS + Extended Protection to block ESC8 relays.

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
