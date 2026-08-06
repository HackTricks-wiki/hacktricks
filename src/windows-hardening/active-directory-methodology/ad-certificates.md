# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## はじめに

### Certificate のコンポーネント

- **Subject** は、certificate の所有者を示します。
- **Public Key** は非公開で保持される key とペアになり、certificate を正当な所有者に関連付けます。
- **Validity Period** は **NotBefore** と **NotAfter** の日付で定義され、certificate の有効期間を示します。
- Certificate Authority (CA) によって提供される一意の **Serial Number** は、各 certificate を識別します。
- **Issuer** は certificate を発行した CA を指します。
- **SubjectAlternativeName** は subject に追加の名前を指定でき、識別の柔軟性を高めます。
- **Basic Constraints** は certificate が CA 用か end entity 用かを識別し、使用制限を定義します。
- **Extended Key Usages (EKUs)** は、Object Identifiers (OIDs) を使用して、code signing や email encryption など、certificate の具体的な用途を定めます。
- **Signature Algorithm** は certificate の署名に使用する method を指定します。
- Issuer の private key で作成される **Signature** は、certificate の真正性を保証します。<sup>[[4]](#references)</sup>

### 特別な考慮事項

- **Subject Alternative Names (SANs)** は certificate を複数の identity に適用できるように拡張します。これは複数の domain を持つ server にとって重要です。攻撃者が SAN の指定を操作して impersonation を行うリスクを避けるには、安全な発行プロセスが不可欠です。<sup>[[4]](#references)</sup>

### Active Directory (AD) における Certificate Authorities (CAs)

AD CS は、専用の container を通じて AD forest 内の CA certificate を認識します。それぞれの container は固有の役割を持ちます。<sup>[[4]](#references)</sup>

- **Certification Authorities** container には、信頼された root CA certificate が格納されます。
- **Enrolment Services** container には、Enterprise CA とその certificate template の詳細が含まれます。
- **NTAuthCertificates** object には、AD authentication に使用することを許可された CA certificate が含まれます。
- **AIA (Authority Information Access)** container は、intermediate CA certificate および cross CA certificate を使用した certificate chain の検証を可能にします。

### Certificate の取得: Client Certificate Request の flow

1. request process は、client が Enterprise CA を検索することから始まります。
2. public-private key pair の生成後、public key とその他の詳細を含む CSR が作成されます。
3. CA は CSR を利用可能な certificate template と照合して評価し、template の permission に基づいて certificate を発行します。
4. 承認されると、CA は private key で certificate に署名し、client に返します。<sup>[[4]](#references)</sup>

### Certificate Template

AD 内で定義されるこれらの template は、許可される EKU、enrollment 権限、変更権限など、certificate の発行に関する設定と permission を定義します。これは certificate service への access を管理するうえで重要です。<sup>[[4]](#references)</sup>

**Template の schema version は重要です。** Legacy の **v1** template（組み込みの **WebServer** template など）には、複数の modern な enforcement 設定がありません。**ESC15/EKUwu** の research により、**v1 template** では requester が CSR に **Application Policies/EKUs** を埋め込むことができ、それらが template に設定された EKU より**優先される**ことが示されました。これにより、enrollment 権限だけで client-auth、enrollment agent、または code-signing certificate を発行できます。**v2/v3 template** を優先し、v1 の default を削除または置き換え、EKU を意図した用途に厳密に限定してください。<sup>[[1]](#references)</sup>

## Certificate Enrollment

certificate の enrollment process は、administrator が **certificate template を作成**することで開始され、その後 Enterprise Certificate Authority (CA) によって **publish** されます。これにより template が client enrollment に利用可能になります。この処理は、Active Directory object の `certificatetemplates` field に template の名前を追加することで実行されます。<sup>[[4]](#references)</sup>

client が certificate を request するには、**enrollment 権限**を付与する必要があります。これらの権限は、certificate template と Enterprise CA 自体の security descriptor によって定義されます。request を成功させるには、両方の場所で permission を付与する必要があります。

### Template Enrollment 権限

これらの権限は Access Control Entries (ACEs) を通じて指定され、次のような permission が定義されます。

- **Certificate-Enrollment** および **Certificate-AutoEnrollment** 権限。それぞれ特定の GUID に関連付けられています。
- **ExtendedRights**。すべての拡張 permission を許可します。
- **FullControl/GenericAll**。template に対する完全な control を提供します。

### Enterprise CA Enrollment 権限

CA の権限は、その security descriptor に記述されており、Certificate Authority management console から access できます。一部の設定では low-privileged user に remote access まで許可されるため、security 上の懸念となる可能性があります。

### 追加の発行制御

次のような control が適用される場合があります。

- **Manager Approval**: certificate manager による承認が完了するまで request を pending 状態にします。
- **Enrolment Agents and Authorized Signatures**: CSR に必要な signature 数と、必要な Application Policy OID を指定します。

### Certificate を request する method

certificate は次の方法で request できます。

1. DCOM interface を使用する **Windows Client Certificate Enrollment Protocol** (MS-WCCE)。
2. named pipe または TCP/IP を介した **ICertPassage Remote Protocol** (MS-ICPR)。
3. Certificate Authority Web Enrollment role が install された **certificate enrollment web interface**。
4. Certificate Enrollment Policy (CEP) service と組み合わせた **Certificate Enrollment Service** (CES)。
5. Simple Certificate Enrollment Protocol (SCEP) を使用して network device 用の certificate を発行する **Network Device Enrollment Service** (NDES)。

Windows user は GUI（`certmgr.msc` または `certlm.msc`）や command-line tool（`certreq.exe` または PowerShell の `Get-Certificate` command）からも certificate を request できます。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) は、主に **Kerberos** および **Secure Channel (Schannel)** protocol を利用した certificate authentication をサポートします。

### Kerberos Authentication Process

Kerberos authentication process では、ユーザーの Ticket Granting Ticket (TGT) の要求が、ユーザーの certificate の **private key** を使用して署名されます。この要求は、domain controller によって複数の検証を受けます。検証には、certificate の **validity**、**path**、**revocation status** が含まれます。また、certificate が trusted source から発行されたものであること、および issuer が **NTAUTH certificate store** に存在することも確認されます。検証に成功すると、TGT が発行されます。AD 内の **`NTAuthCertificates`** object は、次の場所にあります：
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
は、certificate authentication における trust の確立の中心となります。<sup>[[4]](#references)</sup>

**KB5014754** の rollout 以降、modern Kerberos certificate auth では、単に EKU だけでなく、主に **mapping strength** が重視されます。<sup>[[2]](#references)</sup> hardened forest では:

- **UPN/DNS SAN** のみを含む certificate では、logon に不十分な場合があります。
- KDC は **strong binding** を優先します。通常は **SID security extension** (`1.3.6.1.4.1.311.25.2`) または `altSecurityIdentities` における strong explicit mapping が使用されます。
- certificate に strong mapping がない場合、DC は compatibility mode では **Kdcsvc Event ID 39/41** を log に記録し、enforcement mode では auth を拒否します。
- 複合した attack path では、発行された certificate から SID extension を削除する **ESC9/ESC16** が重要になります。その後、operator は explicit mappings、または attack path が対応している場合は SAN URL SID format に依存します。

### Secure Channel (Schannel) Authentication

Schannel は安全な TLS/SSL 接続を実現します。handshake 中に client が certificate を提示し、その certificate が正常に検証されると access が認可されます。certificate から AD account への mapping には、Kerberos の **S4U2Self** function や certificate の **Subject Alternative Name (SAN)** などが使用されます。<sup>[[4]](#references)</sup>

**PKINIT** が利用できない場合、Schannel は実用的な fallback としても機能します。たとえば、domain controller に適切な **Smart Card Logon** certificate がない場合、`certipy auth`/PKINIT tooling は TGT の取得に失敗する可能性があります。しかし、同じ certificate を **LDAPS** または **LDAP StartTLS** に対する authentication や LDAP operations に使用できる場合があります。

### AD Certificate Services Enumeration

AD の certificate services は LDAP queries を通じて enumeration でき、**Enterprise Certificate Authorities (CAs)** とその configurations に関する情報が明らかになります。これは special privileges のない、domain-authenticated user であれば誰でも利用できます。**[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** などの tools は、AD CS environments における enumeration と vulnerability assessment に使用されます。

これらの tools を使用する commands は次のとおりです:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## 最近の脆弱性とセキュリティ更新（2022-2025）

| 年 | ID / 名前 | 影響 | 主なポイント |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT 中に machine account の証明書を spoofing することによる *Privilege escalation*。 | **2022 年 5 月 10 日**の security updates に patch が含まれています。監査と strong-mapping controls は **KB5014754** により導入されました。現在、環境は *Full Enforcement* mode である必要があります。 |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment（certsrv）および CES roles における *Remote code-execution*。 | 公開 PoC は限定的ですが、脆弱な IIS components が内部で公開されていることは少なくありません。2023 年 7 月の Patch Tuesday 時点で patch 済みです。 |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** では、enrollment rights を持つ requester が CSR に **Application Policies/EKUs** を埋め込むことができ、template EKUs より優先されます。その結果、client-auth、enrollment agent、または code-signing certificates を生成できます。 | **2024 年 11 月 12 日**時点で patch 済みです。v1 templates（例: default WebServer）を置き換えるか supersede し、EKUs を用途に限定して、enrollment rights を制限してください。 |

### Microsoft hardening timeline（KB5014754）

Microsoft は、Kerberos certificate authentication を weak implicit mappings から移行するため、Compatibility → Audit → Enforcement の 3 段階の rollout を導入しました。`StrongCertificateBindingEnforcement` registry value が設定されていない場合、**2025 年 2 月 11 日**時点で domain controllers は自動的に **Full Enforcement** に切り替わります。Microsoft はその後 timeline を更新し、**2025 年 9 月 9 日**の security update までは compatibility mode への fallback を可能にしました。<sup>[[2]](#references)</sup> Administrators は次を実施してください。

1. すべての DC と AD CS servers に patch を適用する（2022 年 5 月以降）。
2. *Audit* phase 中に Event ID 39/41 を監視し、weak mappings を検出する。
3. enforcement により weak mappings が block される前に、新しい **SID extension** を使用して client-auth certificates を再発行するか、strong manual mappings を設定する。

### Hardened forests における operator notes

- **ESC1/ESC6 だけでは、2025 年以降の environments における全体像ではありません**。別の principal 用に cert を request する場合、通常は SID extension や明示的な mapping などの strong mapping artifact も必要です。
- **ESC15（EKUwu）**は、主に unpatched environments で有効です。これは **WebServer** などの無害な **v1** templates に **Application Policies** を inject することで、authentication または enrollment-agent 機能を持つ cert に変えます。Kerberos PKINIT は引き続き EKUs を評価しますが、**LDAP Schannel** も Application Policies を honor するため、LDAP-based abuse が引き続き relevant になります。<sup>[[1]](#references)</sup>
- **ESC16** は CA-wide knob です。CA が SID security extension を globally disable すると、attack chain が別の supported format で SID を inject しない限り、発行されるすべての certificate は weaker mapping behavior に fallback します。

---

## Detection と Hardening の強化

* **Defender for Identity AD CS sensor（2023-2024）**は現在、ESC1-ESC8/ESC11 の posture assessments を表示し、*“Domain-controller certificate issuance for a non-DC”*（ESC8）や *“Prevent Certificate Enrollment with arbitrary Application Policies”*（ESC15）などの real-time alerts を生成します。これらの detections を活用するため、すべての AD CS servers に sensors が deploy されていることを確認してください。<sup>[[3]](#references)</sup>
* すべての templates で **“Supply in the request”** option を disable するか、厳密に scope してください。明示的に定義された SAN/EKU を優先します。
* 絶対に必要な場合を除き、templates から **Any Purpose** または **No EKU** を削除します（ESC2 scenarios に対応）。
* sensitive templates（例: WebServer / CodeSigning）には **manager approval** または専用の Enrollment Agent workflows を要求します。
* web enrollment（`certsrv`）および CES/NDES endpoints を trusted networks に限定するか、client-certificate authentication の背後に配置します。
* RPC enrollment encryption（`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`）を enforce して ESC11（RPC relay）を mitigate します。この flag は **デフォルトで on** ですが、legacy clients のために disable されていることが多く、relay risk が再び発生します。
* **IIS-based enrollment endpoints**（CES/Certsrv）を secure にします。可能な場合は NTLM を disable するか、HTTPS + Extended Protection を要求して ESC8 relays を block します。

---

## References

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
