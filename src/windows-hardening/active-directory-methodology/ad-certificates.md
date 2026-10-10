# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Introduction

### Components of a Certificate

- **Subject** は証明書の所有者を示します。
- **Public Key** は秘密鍵と対になり、証明書と正当な所有者を結び付けます。
- **Validity Period** は **NotBefore** と **NotAfter** の日付で定義され、証明書の有効期間を示します。
- Certificate Authority (CA) が付与する一意の **Serial Number** により、各証明書を識別します。
- **Issuer** は証明書を発行した CA を指します。
- **SubjectAlternativeName** を使用すると、対象に追加の名前を設定でき、識別の柔軟性が高まります。
- **Basic Constraints** は、証明書が CA 用かエンドエンティティ用かを示し、使用制限を定義します。
- **Extended Key Usages (EKUs)** は、Object Identifiers (OIDs) を通じて、コード署名やメール暗号化など、証明書の具体的な用途を定義します。
- **Signature Algorithm** は証明書の署名に使用する方法を指定します。
- 発行者の秘密鍵で作成される **Signature** により、証明書の真正性が保証されます。<sup>[[4]](#references)</sup>

### Special Considerations

- **Subject Alternative Names (SANs)** によって証明書を複数の識別情報に適用できるため、複数のドメインを持つサーバーでは特に重要です。攻撃者が SAN の指定を操作してなりすますリスクを避けるには、安全な発行プロセスが不可欠です。<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS は、AD フォレスト内の CA 証明書を指定されたコンテナーで管理します。それぞれのコンテナーには固有の役割があります。<sup>[[4]](#references)</sup>

- **Certification Authorities** コンテナーには、信頼されたルート CA 証明書が格納されます。
- **Enrolment Services** コンテナーには、Enterprise CA とその証明書テンプレートに関する情報が格納されます。
- **NTAuthCertificates** オブジェクトには、AD 認証で使用を許可された CA 証明書が含まれます。
- **AIA (Authority Information Access)** コンテナーは、中間 CA 証明書やクロス CA 証明書を使用した証明書チェーンの検証を可能にします。

### Certificate Acquisition: Client Certificate Request Flow

1. クライアントが Enterprise CA を見つけることで、要求プロセスが始まります。
2. 公開鍵とその他の情報を含む CSR は、公開鍵と秘密鍵のペアを生成した後に作成されます。
3. CA は、利用可能な証明書テンプレートに照らして CSR を評価し、テンプレートの権限に基づいて証明書を発行します。
4. 承認されると、CA は秘密鍵で証明書に署名し、クライアントに返します。<sup>[[4]](#references)</sup>

### Certificate Templates

AD 内で定義されるこれらのテンプレートは、証明書の発行に関する設定と権限を規定します。許可される EKU、登録権限や変更権限などが含まれ、証明書サービスへのアクセス管理に欠かせません。<sup>[[4]](#references)</sup>

**テンプレートのスキーマバージョンは重要です。** レガシーな **v1** テンプレート（組み込みの **WebServer** テンプレートなど）には、最新の強制設定がいくつかありません。**ESC15/EKUwu** の調査で示されたように、**v1 テンプレート**では、要求者が CSR に埋め込んだ **Application Policies/EKUs** が、テンプレートに設定された EKU より**優先される**ことがあります。その結果、登録権限しかなくても、client-auth、enrollment agent、またはコード署名用の証明書を取得できる可能性があります。**v2/v3 テンプレート**を優先し、v1 のデフォルト設定を削除または置き換え、EKU を意図した用途に厳密に限定してください。<sup>[[1]](#references)</sup>

## Certificate Enrollment

証明書の登録プロセスは、管理者が**証明書テンプレートを作成**し、Enterprise Certificate Authority (CA) がそれを**公開**することで開始されます。これによりテンプレートがクライアントの登録に利用できるようになります。これは、Active Directory オブジェクトの `certificatetemplates` フィールドにテンプレート名を追加して行います。<sup>[[4]](#references)</sup>

クライアントが証明書を要求するには、**登録権限**が必要です。この権限は、証明書テンプレート自体と Enterprise CA 自体に設定されたセキュリティ記述子によって定義されます。要求を成功させるには、両方の場所で権限を付与する必要があります。

### Template Enrollment Rights

これらの権限は Access Control Entries (ACEs) で指定され、以下のようなアクセス許可が含まれます。

- **Certificate-Enrollment** と **Certificate-AutoEnrollment** の権限。それぞれ固有の GUID が関連付けられています。
- すべての拡張権限を許可する **ExtendedRights**。
- テンプレートを完全に制御できる **FullControl/GenericAll**。

### Enterprise CA Enrollment Rights

CA の権限は、そのセキュリティ記述子に記載されており、Certificate Authority 管理コンソールから確認できます。一部の設定では、低い権限のユーザーにリモートアクセスを許可することもでき、セキュリティ上の懸念となる可能性があります。

### Additional Issuance Controls

次のような追加の制御が適用される場合があります。

- **Manager Approval**: 証明書マネージャーが承認するまで、要求を保留状態にします。
- **Enrolment Agents and Authorized Signatures**: CSR に必要な署名数と、必要な Application Policy OIDs を指定します。

### Methods to Request Certificates

証明書は、次の方法で要求できます。

1. DCOM インターフェイスを使用する **Windows Client Certificate Enrollment Protocol** (MS-WCCE)。
2. 名前付きパイプまたは TCP/IP を使用する **ICertPassage Remote Protocol** (MS-ICPR)。
3. Certificate Authority Web Enrollment ロールがインストールされた **certificate enrollment web interface**。
4. **Certificate Enrollment Policy (CEP)** サービスと連携する **Certificate Enrollment Service** (CES)。
5. **Simple Certificate Enrollment Protocol** (SCEP) を使用するネットワークデバイス向けの **Network Device Enrollment Service** (NDES)。

Windows ユーザーは、GUI（`certmgr.msc` または `certlm.msc`）やコマンドラインツール（`certreq.exe` または PowerShell の `Get-Certificate` コマンド）からも証明書を要求できます。

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## 証明書認証

Active Directory (AD) は、主に **Kerberos** および **Secure Channel (Schannel)** プロトコルを利用した証明書認証をサポートしています。

### Kerberos 認証プロセス

Kerberos 認証プロセスでは、ユーザーの Ticket Granting Ticket (TGT) 要求は、ユーザーの証明書の **private key** を使用して署名されます。この要求は、ドメインコントローラーによって、証明書の **有効性**、**パス**、**失効状態**など、いくつかの検証を受けます。また、証明書が信頼できるソースから発行されたこと、および発行者が **NTAUTH 証明書ストア**に存在することも確認されます。検証に成功すると、TGT が発行されます。AD 内の **`NTAuthCertificates`** オブジェクトは、次の場所にあります:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

は、証明書認証の信頼を確立するうえで中心的な役割を果たします。<sup>[[4]](#references)</sup>

**KB5014754** の展開以降、最新の Kerberos 証明書認証では、EKU だけでなく、主に**マッピングの強度**が重要になっています。<sup>[[2]](#references)</sup> 強化されたフォレストでは、次のようになります。

- **UPN/DNS SAN** のみを含む証明書では、ログオンに不十分な場合があります。
- KDC は、通常は **SID セキュリティ拡張**（`1.3.6.1.4.1.311.25.2`）または `altSecurityIdentities` の強力な明示的マッピングによる、**強いバインディング**を優先します。
- 証明書に強いマッピングがない場合、互換モードでは DC が **Kdcsvc Event ID 39/41** をログに記録し、強制モードでは認証を拒否します。
- 複合的な攻撃経路では、発行される証明書から SID 拡張を削除する **ESC9/ESC16** が重要です。その後、攻撃経路が対応していれば、攻撃者は明示的なマッピングや SAN URL の SID 形式に依存します。

### Secure Channel (Schannel) 認証

Schannel は安全な TLS/SSL 接続を実現します。ハンドシェイク中にクライアントが証明書を提示し、その証明書が正常に検証されると、アクセスが許可されます。証明書を AD アカウントにマッピングする方法としては、Kerberos の **S4U2Self** 機能や、証明書の **Subject Alternative Name (SAN)** などがあります。<sup>[[4]](#references)</sup>

**PKINIT** が利用できない場合、Schannel は実用的なフォールバックにもなります。たとえば、ドメインコントローラーに適切な **Smart Card Logon** 証明書がない場合、`certipy auth`/PKINIT ツールでは TGT の取得に失敗することがあります。しかし、同じ証明書を **LDAPS** または **LDAP StartTLS** での認証や LDAP 操作に利用できる場合があります。

### AD Certificate Services の列挙

AD の証明書サービスは LDAP クエリで列挙でき、**Enterprise Certificate Authorities (CAs)** とその構成に関する情報を取得できます。これは、特別な権限のないドメイン認証済みユーザーであれば誰でも利用できます。**[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** などのツールは、AD CS 環境での列挙や脆弱性評価に使用されます。

これらのツールを使用するコマンドは次のとおりです。

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

## 最近の脆弱性とセキュリティ更新プログラム（2022-2025）

| 年 | ID / 名前 | 影響 | 主なポイント |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT中にマシンアカウントの証明書を偽装することによる*権限昇格*。 | パッチは**2022年5月10日**のセキュリティ更新プログラムに含まれています。監査と強力なマッピングの制御は**KB5014754**で導入されました。環境は現在、*Full Enforcement* モードになっている必要があります。 |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment（certsrv）およびCESロールにおける*リモートコード実行*。 | 公開PoCは限られていますが、脆弱なIISコンポーネントが内部ネットワークに公開されていることはよくあります。**2023年7月**のPatch Tuesdayの更新プログラムを適用してください。 |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1テンプレート**では、登録権限を持つ要求者がCSRに**Application Policies/EKUs**を埋め込むと、テンプレートのEKUより優先され、クライアント認証、Enrollment Agent、またはコード署名用の証明書が発行される可能性があります。 | **2024年11月12日**時点でパッチが提供されています。v1テンプレート（デフォルトのWebServerなど）を置き換えるか後継テンプレートを用意し、EKUを用途に合わせて制限し、登録権限を限定してください。 |

### Microsoftのハードニングタイムライン（KB5014754）

Microsoftは、Kerberos証明書認証を脆弱な暗黙的マッピングから移行するため、3段階（Compatibility → Audit → Enforcement）の展開を導入しました。**2025年2月11日**時点では、`StrongCertificateBindingEnforcement`レジストリ値が設定されていない場合、ドメインコントローラーは自動的に**Full Enforcement**へ切り替わります。その後Microsoftはタイムラインを更新し、**2025年9月9日**のセキュリティ更新プログラムまでは互換モードへのフォールバックが可能となりました。<sup>[[2]](#references)</sup> 管理者は次の対応を行ってください。

1. すべてのDCとAD CSサーバーにパッチを適用する（2022年5月以降）。
2. *Audit*段階で、脆弱なマッピングを示すイベントID 39/41を監視する。
3. Enforcementによって脆弱なマッピングがブロックされる前に、新しい**SID extension**を含むクライアント認証証明書を再発行するか、強力な手動マッピングを設定する。

### ハードニングされたフォレストでのオペレーター向け注意事項

- **2025年以降の環境では、ESC1/ESC6だけが全てではありません**。別のプリンシパルの証明書を要求する場合、通常はSID extensionや明示的なマッピングなど、強力なマッピングを示す情報も必要です。
- **ESC15（EKUwu）**は、未パッチ環境で特に有効です。**Application Policies**を挿入することで、**WebServer**などの無害な**v1**テンプレートを、認証またはEnrollment Agentに利用できる証明書に変えられます。Kerberos PKINITは引き続きEKUを評価しますが、**LDAP Schannel**もApplication Policiesを参照するため、LDAPを介した悪用の可能性は残ります。<sup>[[1]](#references)</sup>
- **ESC16**はCA全体に適用される設定です。CAがSID security extensionを全体的に無効にすると、攻撃チェーンが別のサポート対象形式でSIDを挿入しない限り、発行されるすべての証明書で脆弱なマッピングが使われる可能性が高まります。
- **ESC7の権限は別々のものです**。CAの`ManageCA`権限があれば、`EDITF_ATTRIBUTESUBJECTALTNAME2`（ESC6）などの設定を変更できる一方、`ManageCertificates`は要求の承認を制御します。証明書マネージャー権限に明示的なDenyが設定されていると、Allowも存在する場合でも承認経路がブロックされることがあります。設定やテンプレートを連鎖させる前に、CA ACLの実効権限を評価してください。[MicrosoftによるCA ACLの評価](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting)を参照してください。

---

## 検出とハードニングの強化

* **Defender for Identity AD CS sensor（2023-2024）**では、ESC1-ESC8/ESC11のセキュリティ態勢評価が表示されるようになり、「*Domain-controller certificate issuance for a non-DC*」（ESC8）や「*Prevent Certificate Enrollment with arbitrary Application Policies*」（ESC15）などのリアルタイムアラートが生成されます。これらの検出を利用するには、すべてのAD CSサーバーにsensorを展開してください。<sup>[[3]](#references)</sup>
* すべてのテンプレートで**「Supply in the request」**オプションを無効にするか、適用範囲を厳しく制限してください。SAN/EKUは明示的に定義することを推奨します。
* 絶対に必要な場合を除き、テンプレートから**Any Purpose**または**No EKU**を削除してください（ESC2のシナリオに対処）。
* 機密性の高いテンプレート（WebServer / CodeSigningなど）には、**manager approval**または専用のEnrollment Agentワークフローを必須にしてください。
* Web enrollment（`certsrv`）とCES/NDESエンドポイントを信頼できるネットワークに限定するか、クライアント証明書認証の背後に配置してください。
* RPC enrollment encryption（`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`）を強制し、ESC11（RPC relay）を軽減してください。このフラグは**デフォルトで有効**ですが、レガシークライアントのために無効化されていることが多く、その場合はrelayのリスクが再び生じます。
* **IISベースのenrollmentエンドポイント**（CES/Certsrv）を保護してください。可能であればNTLMを無効にするか、HTTPSとExtended Protectionを必須にしてESC8 relayを防いでください。

CAが稼働しているホストでESC11を評価してください。このホストはドメインコントローラーではなく、ドメインメンバーサーバーの場合があります。アクティブなCAの`InterfaceFlags`を`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`で確認してください。値を読み取れない、または見つからない場合は結果不明であり、RPC encryptionが無効である証拠にはなりません。`IF_ENFORCEENCRYPTICERTREQUEST`ビットがクリアされている場合は設定上の手掛かりになりますが、実際に悪用するには、到達可能なenrollment RPCエンドポイント、強制可能な認証情報、および利用可能な証明書テンプレートが必要です。ESC8では、HTTP NTLM challengeだけでは不十分です。機能するenrollmentエンドポイントが存在することを確認してください。

---

## References

- [1] [EKUwu: もうひとつのAD CS ESCではない](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windowsドメインコントローラーにおける証明書ベース認証の変更](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [証明書のセキュリティ態勢評価 - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Servicesの悪用](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
