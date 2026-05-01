# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## はじめに

### 証明書の構成要素

- 証明書の **Subject** は、その所有者を示す。
- **Public Key** は、証明書を正当な所有者に結び付けるために、秘密鍵と対になっている。
- **Validity Period** は、**NotBefore** と **NotAfter** の日付で定義され、証明書の有効期間を示す。
- Certificate Authority (CA) によって提供される一意の **Serial Number** が、各証明書を識別する。
- **Issuer** は、証明書を発行した CA を指す。
- **SubjectAlternativeName** は、Subject に追加の名前を許可し、識別の柔軟性を高める。
- **Basic Constraints** は、証明書が CA 用かエンドエンティティ用かを識別し、使用制限を定義する。
- **Extended Key Usages (EKUs)** は、Object Identifiers (OIDs) を通じて、code signing や email encryption など証明書の具体的な用途を示す。
- **Signature Algorithm** は、証明書の署名方法を指定する。
- 発行者の秘密鍵で作成された **Signature** は、証明書の真正性を保証する。

### 特記事項

- **Subject Alternative Names (SANs)** は、証明書の適用範囲を複数の identity に拡張し、複数の domain を持つ server で重要となる。攻撃者が SAN の指定を操作して impersonation を行うリスクを避けるため、secure な発行プロセスが不可欠である。

### Active Directory (AD) における Certificate Authorities (CAs)

AD CS は、AD forest 内で指定された container を通じて CA 証明書を認識し、それぞれが固有の役割を果たす:

- **Certification Authorities** container は、信頼された root CA 証明書を保持する。
- **Enrolment Services** container は、Enterprise CA とその certificate templates の詳細を保持する。
- **NTAuthCertificates** object は、AD authentication 用に認可された CA 証明書を含む。
- **AIA (Authority Information Access)** container は、intermediate CA と cross CA 証明書を使った証明書 chain validation を支援する。

### 証明書取得: Client Certificate Request Flow

1. request process は、client が Enterprise CA を見つけることから始まる。
2. public-private key pair を生成した後、public key とその他の詳細を含む CSR が作成される。
3. CA は CSR を利用可能な certificate templates と照合し、template の permissions に基づいて証明書を発行する。
4. 承認されると、CA は自身の秘密鍵で証明書に署名し、client に返す。

### Certificate Templates

AD 内で定義されるこれらの template は、証明書発行の設定と permissions を定める。許可された EKUs や enrollment / modification 権限も含まれ、certificate services への access 管理に重要である。

**Template schema version matters.** 旧式の **v1** templates（たとえば標準搭載の **WebServer** template）は、現代的な enforcement knobs をいくつか欠いている。**ESC15/EKUwu** の research により、**v1 templates** では requester が CSR 内に **Application Policies/EKUs** を埋め込むことができ、これらは template の設定済み EKUs より **優先される** ため、client-auth、enrollment agent、code-signing 証明書を enrollment 権限だけで有効化できる。**v2/v3 templates** を優先し、v1 の default を削除または置き換え、EKUs を目的に合わせて厳密に限定すること。

## Certificate Enrollment

証明書の enrollment process は、administrator が **certificate template を作成**し、それを Enterprise Certificate Authority (CA) が **published** することで開始される。これにより template は client enrollment で利用可能になり、Active Directory object の `certificatetemplates` field に template 名を追加することで実現される。

client が証明書を request するには、**enrollment rights** が付与されていなければならない。これらの rights は、certificate template と Enterprise CA 自体にある security descriptor によって定義される。request を成功させるには、両方の場所で permissions が付与されている必要がある。

### Template Enrollment Rights

これらの rights は Access Control Entries (ACEs) を通じて指定され、以下のような permissions を含む:

- **Certificate-Enrollment** と **Certificate-AutoEnrollment** rights。各々が特定の GUID に関連付けられている。
- **ExtendedRights**。すべての extended permissions を許可する。
- **FullControl/GenericAll**。template を完全に制御する。

### Enterprise CA Enrollment Rights

CA の rights は、その security descriptor に示されており、Certificate Authority management console から参照できる。設定によっては low-privileged users に remote access を許可するものもあり、security concern となり得る。

### 追加の発行制御

以下のような control が適用される場合がある:

- **Manager Approval**: certificate manager によって承認されるまで request を pending state に置く。
- **Enrolment Agents and Authorized Signatures**: CSR に必要な signature 数と、必要な Application Policy OIDs を指定する。

### 証明書を request する方法

証明書は以下の方法で request できる:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE) を、DCOM interfaces 経由で使用する。
2. **ICertPassage Remote Protocol** (MS-ICPR) を、named pipes または TCP/IP 経由で使用する。
3. **certificate enrollment web interface**。Certificate Authority Web Enrollment role がインストールされている場合。
4. **Certificate Enrollment Service** (CES) を、Certificate Enrollment Policy (CEP) service と組み合わせて使用する。
5. **Network Device Enrollment Service** (NDES) を network devices 向けに使用し、Simple Certificate Enrollment Protocol (SCEP) を用いる。

Windows users は、GUI (`certmgr.msc` または `certlm.msc`) や command-line tools (`certreq.exe` または PowerShell の `Get-Certificate` command) でも証明書を request できる。
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Certificate Authentication

Active Directory (AD) は、主に **Kerberos** と **Secure Channel (Schannel)** プロトコルを利用した certificate authentication をサポートします。

### Kerberos Authentication Process

Kerberos authentication process では、ユーザーの Ticket Granting Ticket (TGT) への request は、ユーザーの certificate の **private key** を使って署名されます。この request は、domain controller によって certificate の **validity**、**path**、および **revocation status** を含むいくつかの validation を受けます。さらに validation には、その certificate が trusted source から来ていることの確認と、issuer が **NTAUTH certificate store** に存在することの確認も含まれます。これらの validation に成功すると、TGT が発行されます。AD 内の **`NTAuthCertificates`** object は、以下にあります:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
認証の信頼を確立するうえで中心的です。

**KB5014754** の展開以降、現代の Kerberos certificate auth は主に **mapping strength** が重要で、単なる EKUs だけではありません。ハードニングされたフォレストでは:

- **UPN/DNS SAN** しか持たない certificate は、logon に十分でない場合があります。
- KDC はより強い **binding** を優先し、通常は **SID security extension** (`1.3.6.1.4.1.311.25.2`) か、`altSecurityIdentities` における強い明示的 mapping を使います。
- cert に強い mapping がない場合、DC は compatibility mode では **Kdcsvc Event ID 39/41** を記録し、enforcement mode では auth を拒否します。
- 混在した attack path では、**ESC9/ESC16** が重要です。これらは発行済み cert から SID extension を削除するため、operators はその後、明示的 mapping か、attack path が対応している場合は SAN URL SID 形式に依存します。

### Secure Channel (Schannel) Authentication

Schannel は安全な TLS/SSL 接続を実現し、handshake の間に client が certificate を提示し、それが正常に検証されるとアクセスが許可されます。certificate と AD account の mapping には、Kerberos の **S4U2Self** 機能や certificate の **Subject Alternative Name (SAN)** など、複数の方法が関与することがあります。

Schannel は **PKINIT** が利用できない場合の実用的な fallback でもあります。たとえば、domain controller に適切な **Smart Card Logon** certificate がない場合、`certipy auth`/PKINIT tooling は TGT を取得できないことがありますが、同じ certificate を **LDAPS** や **LDAP StartTLS** に対して authentication や LDAP operations に使用できることがあります。

### AD Certificate Services Enumeration

AD の certificate services は LDAP queries で列挙でき、**Enterprise Certificate Authorities (CAs)** とその configuration に関する情報が明らかになります。これは、特別な privileges なしで domain-authenticated user なら誰でもアクセスできます。**[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** のような tools は、AD CS 環境での enumeration と vulnerability assessment に使用されます。

これらの tools を使うための commands には:
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

## 最近の脆弱性 & セキュリティ更新 (2022-2025)

| Year | ID / Name | Impact | Key- takeaways |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT中にマシンアカウント証明書を偽装することでの *Privilege escalation*。 | パッチは **2022年5月10日** のセキュリティ更新に含まれています。監査と強いマッピング制御は **KB5014754** により導入されました。環境は現在 *Full Enforcement* モードであるべきです。  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) と CES ロールでの *Remote code-execution*。 | 公開PoCは限られていますが、脆弱なIISコンポーネントは内部で露出していることがよくあります。パッチは **2023年7月** の Patch Tuesday 時点で提供されています。  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 templates** では、Enrollment権限を持つ要求者が CSR に **Application Policies/EKUs** を埋め込め、これは template EKUs より優先され、client-auth、enrollment agent、または code-signing 証明書を生成します。 | **2024年11月12日** 時点で修正済みです。v1 templates（例: default WebServer）を置き換えるか廃止し、EKUs を意図した用途に制限し、Enrollment権限を制限してください。 |

### Microsoft hardening timeline (KB5014754)

Microsoft は、Kerberos の証明書認証を弱い暗黙的マッピングから移行するために、3段階の展開（Compatibility → Audit → Enforcement）を導入しました。**2025年2月11日** 時点では、`StrongCertificateBindingEnforcement` レジストリ値が設定されていない場合、ドメインコントローラーは自動的に **Full Enforcement** に切り替わります。その後 Microsoft はタイムラインを更新し、**2025年9月9日** のセキュリティ更新までは互換モードへのフォールバックが可能な状態を維持しました。管理者は次を実施すべきです:

1. すべての DCs & AD CS servers にパッチを適用する (2022年5月以降)。
2. *Audit* フェーズ中に Event ID 39/41 を監視し、弱いマッピングを検出する。
3. enforcement により弱いマッピングがブロックされる前に、新しい **SID extension** を使って client-auth 証明書を再発行するか、強い手動マッピングを構成する。

### hardened forests 向けの operator notes

- **ESC1/ESC6 だけでは、2025年以降の環境ではもはや全体像ではありません**。別の principal 用の cert を要求する場合、通常は SID extension のような強いマッピング成果物、または明示的な mapping も必要です。
- **ESC15 (EKUwu)** は主に未修正環境で有用です。なぜなら、**WebServer** のような無害な **v1** templates を、**Application Policies** を注入することで authentication- や enrollment-agent-capable な cert に変えるからです。Kerberos PKINIT は引き続き EKUs を評価しますが、**LDAP Schannel** も Application Policies を許可するため、LDAPベースの abuse は依然として有効です。
- **ESC16** は CA 全体に効く設定です。CA が SID security extension をグローバルに無効化すると、別のサポートされた形式で attack chain が SID を注入しない限り、発行されるすべての証明書はより弱い mapping behavior に戻ります。

---

## Detection & Hardening Enhancements

* **Defender for Identity AD CS sensor (2023-2024)** は現在、ESC1-ESC8/ESC11 の posture assessments を表示し、*“Domain-controller certificate issuance for a non-DC”* (ESC8) や *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15) のようなリアルタイムアラートを生成します。これらの検出を活用するため、すべての AD CS servers に sensor を展開してください。
* すべての templates で **“Supply in the request”** オプションを無効化するか、厳しく範囲を限定してください。明示的に定義された SAN/EKU 値を優先してください。
* **Any Purpose** または **No EKU** は、絶対に必要でない限り templates から削除してください (ESC2 シナリオに対応)。
* 機密性の高い templates (例: WebServer / CodeSigning) には **manager approval** または専用の Enrollment Agent ワークフローを要求してください。
* web enrollment (`certsrv`) と CES/NDES endpoints は、信頼できるネットワークに限定するか、client-certificate authentication の背後に配置してください。
* ESC11 (RPC relay) を軽減するため、RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) を強制してください。このフラグは **on by default** ですが、古いクライアントのためにしばしば無効化され、その結果 relay risk が再び開きます。
* **IIS-based enrollment endpoints** (CES/Certsrv) を保護してください: 可能であれば NTLM を無効化するか、HTTPS + Extended Protection を要求して ESC8 relays をブロックしてください。

---



## References

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
