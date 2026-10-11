# AD証明書

{{#include ../../banners/hacktricks-training.md}}

## はじめに

### 証明書の構成要素

- 証明書の**Subject**は、その所有者を示します。
- **Public Key**は、秘密に保持される鍵と対を成し、証明書と正当な所有者を結び付けます。
- **NotBefore**と**NotAfter**の日付で定義される**Validity Period**は、証明書の有効期間を示します。
- Certificate Authority (CA) が付与する一意の**Serial Number**によって、各証明書を識別します。
- **Issuer**は、証明書を発行したCAを示します。
- **SubjectAlternativeName**を使用すると、Subjectに追加の名前を指定でき、識別の柔軟性が高まります。
- **Basic Constraints**は、証明書がCA用かエンドエンティティ用かを示し、使用制限を定義します。
- **Extended Key Usages (EKUs)**は、Object Identifier (OID)を使用して、コード署名やメール暗号化など、証明書の具体的な用途を定義します。
- **Signature Algorithm**は、証明書の署名に使用する方式を指定します。
- 発行者の秘密鍵で作成される**Signature**は、証明書の真正性を保証します。<sup>[[4]](#references)</sup>

### 特別な考慮事項

- **Subject Alternative Names (SANs)**を使うと、証明書を複数のIDに適用できます。これは複数のドメインを持つサーバーで特に重要です。攻撃者がSANの指定を操作してなりすましを行うリスクを避けるには、安全な発行プロセスが不可欠です。<sup>[[4]](#references)</sup>

### Active Directory (AD) の Certificate Authorities (CAs)

AD CSは、ADフォレスト内のCA証明書を、固有の役割を持つ指定コンテナーを通じて認識します。<sup>[[4]](#references)</sup>

- **Certification Authorities**コンテナーには、信頼されたルートCA証明書が格納されます。
- **Enrolment Services**コンテナーには、Enterprise CAとその証明書テンプレートの情報が含まれます。
- **NTAuthCertificates**オブジェクトには、AD認証で使用を許可されたCA証明書が含まれます。
- **AIA (Authority Information Access)**コンテナーは、中間CAおよびクロスCA証明書を使用した証明書チェーンの検証を可能にします。

### 証明書の取得: クライアント証明書の要求フロー

1. クライアントがEnterprise CAを見つけるところから要求プロセスが始まります。
2. 公開鍵とその他の情報を含むCSRを、公開鍵と秘密鍵のペアを生成した後に作成します。
3. CAはCSRを利用可能な証明書テンプレートと照合して評価し、テンプレートの権限に基づいて証明書を発行します。
4. 承認されると、CAは秘密鍵で証明書に署名し、クライアントに返します。<sup>[[4]](#references)</sup>

### 証明書テンプレート

AD内で定義されるこれらのテンプレートは、許可されるEKUや登録権限、変更権限など、証明書を発行するための設定と権限を定めます。証明書サービスへのアクセスを管理するうえで重要です。<sup>[[4]](#references)</sup>

**テンプレートのスキーマバージョンは重要です。** 従来の**v1**テンプレート（組み込みの**WebServer**テンプレートなど）には、最新の強制設定項目がいくつかありません。**ESC15/EKUwu**の調査によると、**v1テンプレート**では、要求者がCSRに埋め込んだ**Application Policies/EKUs**が、テンプレートに設定されたEKUより**優先される**場合があります。これにより、登録権限しか持たないユーザーでも、client-auth、enrollment agent、またはコード署名用の証明書を取得できます。**v2/v3テンプレート**を優先し、v1の既定テンプレートを削除または置き換え、EKUの範囲を意図した用途に厳密に限定してください。<sup>[[1]](#references)</sup>

## 証明書の登録

証明書の登録プロセスは、管理者が**証明書テンプレートを作成**し、それをEnterprise Certificate Authority (CA)が**公開**することで開始されます。これによりテンプレートがクライアントの登録に利用可能になります。これは、Active Directoryオブジェクトの`certificatetemplates`フィールドにテンプレート名を追加して行います。<sup>[[4]](#references)</sup>

クライアントが証明書を要求するには、**登録権限**が付与されている必要があります。これらの権限は、証明書テンプレートとEnterprise CA自体のセキュリティ記述子で定義されます。要求を成功させるには、両方の場所で権限を付与する必要があります。

### テンプレートの登録権限

これらの権限はAccess Control Entry (ACE)で指定され、次のような権限が含まれます。

- **Certificate-Enrollment**および**Certificate-AutoEnrollment**権限。それぞれ特定のGUIDに関連付けられています。
- すべての拡張権限を許可する**ExtendedRights**。
- テンプレートを完全に制御できる**FullControl/GenericAll**。

### Enterprise CAの登録権限

CAの権限は、そのセキュリティ記述子に記載されており、Certificate Authority管理コンソールからアクセスできます。一部の設定では、権限の低いユーザーにもリモートアクセスが許可されるため、セキュリティ上の懸念となる可能性があります。

### 追加の発行制御

次のような制御が適用される場合があります。

- **Manager Approval**: 証明書マネージャーが承認するまで、要求を保留状態にします。
- **Enrolment Agents and Authorized Signatures**: CSRに必要な署名数と、必要なApplication Policy OIDを指定します。

### 証明書を要求する方法

証明書は、次の方法で要求できます。

1. DCOMインターフェイスを使用する**Windows Client Certificate Enrollment Protocol** (MS-WCCE)。
2. 名前付きパイプまたはTCP/IPを使用する**ICertPassage Remote Protocol** (MS-ICPR)。
3. Certificate Authority Web Enrollmentロールがインストールされている場合の**証明書登録Webインターフェイス**。
4. Certificate Enrollment Policy (CEP)サービスと連携する**Certificate Enrollment Service** (CES)。
5. Simple Certificate Enrollment Protocol (SCEP)を使用する、ネットワークデバイス向けの**Network Device Enrollment Service** (NDES)。

Windowsユーザーは、GUI（`certmgr.msc`または`certlm.msc`）やコマンドラインツール（`certreq.exe`またはPowerShellの`Get-Certificate`コマンド）を使って証明書を要求することもできます。

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## 証明書認証

Active Directory (AD) は、主に **Kerberos** および **Secure Channel (Schannel)** プロトコルを使用した証明書認証をサポートしています。

### Kerberos 認証プロセス

Kerberos 認証プロセスでは、ユーザーの Ticket Granting Ticket (TGT) の要求は、ユーザーの証明書の **秘密鍵** を使用して署名されます。この要求は、ドメインコントローラーによって、証明書の **有効性**、**パス**、**失効状態** など、複数の検証を受けます。また、証明書が信頼できるソースから発行されたこと、および発行者が **NTAUTH 証明書ストア** に存在することも確認されます。検証に成功すると、TGT が発行されます。AD の **`NTAuthCertificates`** オブジェクトは、次の場所にあります:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

は、証明書認証の信頼を確立するうえで中心的な役割を果たします。<sup>[[4]](#references)</sup>

**KB5014754** の展開以降、最新の Kerberos 証明書認証では、EKU だけでなく、主に **mapping strength** が重要になっています。<sup>[[2]](#references)</sup> 強化されたフォレストでは:

- **UPN/DNS SAN** だけを持つ証明書では、ログオンに不十分な場合があります。
- KDC は **strong binding** を優先します。通常は **SID security extension** (`1.3.6.1.4.1.311.25.2`)、または `altSecurityIdentities` による強力な明示的マッピングが使われます。
- 証明書に強力なマッピングがない場合、互換モードでは DC が **Kdcsvc Event ID 39/41** を記録し、強制モードでは認証を拒否します。
- 複合的な攻撃経路では、発行された証明書から SID extension を取り除く **ESC9/ESC16** が重要です。その後、攻撃経路が対応していれば、攻撃者は明示的なマッピングや SAN URL SID 形式を利用します。

### Secure Channel (Schannel) Authentication

Schannel はセキュアな TLS/SSL 接続を実現します。ハンドシェイク中にクライアントが証明書を提示し、検証に成功すると、その証明書によってアクセスが許可されます。証明書を AD アカウントにマッピングする方法には、Kerberos の **S4U2Self** 機能や、証明書の **Subject Alternative Name (SAN)** などがあります。<sup>[[4]](#references)</sup>

**PKINIT** が利用できない場合、Schannel は実用的な代替手段にもなります。たとえば、ドメインコントローラーに適切な **Smart Card Logon** 証明書がない場合、`certipy auth` や PKINIT ツールでは TGT の取得に失敗することがありますが、同じ証明書を **LDAPS** や **LDAP StartTLS** に対する認証や LDAP 操作に利用できる場合があります。

### AD Certificate Services Enumeration

AD の証明書サービスは LDAP クエリで列挙でき、**Enterprise Certificate Authorities (CAs)** とその構成に関する情報を取得できます。これは、特別な権限を持たないドメイン認証済みユーザーなら誰でも利用できます。**[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** などのツールは、AD CS 環境の列挙や脆弱性評価に使用されます。

これらのツールを使用するコマンドは次のとおりです:

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

## 最近の脆弱性とセキュリティ更新 (2022-2025)

| 年 | ID / 名前 | 影響 | 主なポイント |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT 中にマシンアカウントの証明書を偽装することによる *Privilege escalation*。 | パッチは **2022 年 5 月 10 日**のセキュリティ更新に含まれています。監査と強力なマッピング制御は **KB5014754** で導入されました。現在、環境は *Full Enforcement* モードにする必要があります。  |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) および CES ロールにおける *Remote code-execution*。 | 公開 PoC は限られていますが、脆弱な IIS コンポーネントが内部ネットワークに公開されていることはよくあります。**2023 年 7 月**の Patch Tuesday の更新を適用してください。  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 テンプレート**では、登録権限を持つ要求者が CSR に **Application Policies/EKUs** を埋め込むことで、テンプレートの EKU より優先される値を設定し、client-auth、enrollment agent、または code-signing の証明書を生成できます。 | **2024 年 11 月 12 日**時点でパッチが適用されています。v1 テンプレート (既定の WebServer など) を置き換えるか新しいテンプレートで代替し、EKU を用途に応じて制限し、登録権限を制限してください。 |

### Microsoft の強化タイムライン (KB5014754)

Microsoft は、Kerberos 証明書認証を弱い暗黙的マッピングから移行するため、3 段階 (Compatibility → Audit → Enforcement) のロールアウトを導入しました。**2025 年 2 月 11 日**以降、`StrongCertificateBindingEnforcement` レジストリ値が設定されていない場合、ドメイン コントローラーは自動的に **Full Enforcement** に切り替わります。その後 Microsoft はタイムラインを更新し、**2025 年 9 月 9 日**のセキュリティ更新までは互換モードへのフォールバックが可能となりました。<sup>[[2]](#references)</sup> 管理者は以下を実施してください。

1. すべての DC と AD CS サーバーに (2022 年 5 月以降の) パッチを適用する。
2. *Audit* フェーズ中に、弱いマッピングに関する Event ID 39/41 を監視する。
3. client-auth 証明書を新しい **SID extension** 付きで再発行するか、強制適用によって弱いマッピングがブロックされる前に、強力な手動マッピングを設定する。

### 強化されたフォレストでのオペレーター向けメモ

- 2025 年以降の環境では、**ESC1/ESC6 だけが問題のすべてではありません**。別のプリンシパル用の証明書を要求する場合、通常は SID extension や明示的なマッピングなど、強力なマッピングを可能にする要素も必要です。
- **ESC15 (EKUwu)** が主に有効なのは、未パッチ環境です。**Application Policies** を挿入して **WebServer** などの無害な **v1** テンプレートを、認証や enrollment agent に使用可能な証明書に変えます。Kerberos PKINIT は引き続き EKU を評価しますが、**LDAP Schannel** も Application Policies を尊重するため、LDAP ベースの悪用は依然として可能です。<sup>[[1]](#references)</sup>
- **ESC16** は CA 全体に適用される設定です。CA が SID security extension を全体的に無効にすると、攻撃チェーンが別のサポート対象形式で SID を挿入しない限り、発行されるすべての証明書で弱いマッピング動作に近づきます。
- **ESC7 の権限は別個のものです:** CA の `ManageCA` 権限があれば、`EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) などの設定を変更できる場合があります。一方、`ManageCertificates` は要求の承認を管理します。証明書マネージャー権限に対する明示的な Deny がある場合、Allow も設定されていてもその承認経路はブロックされる可能性があります。設定やテンプレートを組み合わせる前に、実効 CA ACL を評価してください。[Microsoft の CA ACL 評価](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting)を参照してください。

---

## 検出と強化に関する追加策

* **Defender for Identity AD CS sensor** (2023-2024) は、ESC1-ESC8/ESC11 のセキュリティ態勢評価を表示し、*“非 DC へのドメイン コントローラー証明書の発行”* (ESC8) や *“任意の Application Policies による証明書登録を防止”* (ESC15) などのリアルタイム アラートを生成します。これらの検出を利用するには、すべての AD CS サーバーに sensor を展開してください。<sup>[[3]](#references)</sup>
* すべてのテンプレートで **“Supply in the request”** オプションを無効にするか、厳しく制限してください。SAN/EKU は明示的に定義することを推奨します。
* 絶対に必要な場合を除き、テンプレートから **Any Purpose** または **No EKU** を削除してください (ESC2 のシナリオに対処)。
* 機密性の高いテンプレート (WebServer / CodeSigning など) には、**manager approval** または専用の Enrollment Agent ワークフローを必須にしてください。
* Web enrollment (`certsrv`) および CES/NDES エンドポイントを信頼済みネットワークに制限するか、クライアント証明書認証の背後に配置してください。
* RPC enrollment の暗号化 (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) を強制し、ESC11 (RPC relay) を緩和してください。このフラグは**既定で有効**ですが、レガシー クライアントのために無効化されていることが多く、その場合 relay のリスクが再び生じます。
* **IIS ベースの enrollment エンドポイント** (CES/Certsrv) を保護してください。可能な場合は NTLM を無効にするか、HTTPS と Extended Protection を必須にして ESC8 relay をブロックします。

ESC11 は CA が稼働しているホストで評価してください。CA はドメイン コントローラーではなく、ドメイン メンバー サーバー上で稼働している場合があります。`HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` にあるアクティブな CA の `InterfaceFlags` を確認してください。値が読み取れない、または存在しない場合は結果が不明であり、RPC 暗号化が無効である証拠にはなりません。`IF_ENFORCEENCRYPTICERTREQUEST` ビットがクリアされている場合、それは設定上の調査の手がかりです。ただし、攻撃には到達可能な enrollment RPC エンドポイント、強制可能な資格情報、利用可能な証明書テンプレートも必要です。ESC8 では、HTTP NTLM challenge だけでは不十分です。動作する enrollment エンドポイントが存在することを確認してください。

---

## References

- [1] [EKUwu: 単なる別の AD CS ESC ではない](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows ドメイン コントローラーにおける証明書ベース認証の変更](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [証明書のセキュリティ態勢評価 - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services の悪用](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
