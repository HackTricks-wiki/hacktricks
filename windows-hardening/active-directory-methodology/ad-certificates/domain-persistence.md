# AD CS ドメイン永続性

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 盗まれたCA証明書での証明書偽造 - DPERSIST1

証明書がCA証明書であることをどうやって判断できますか？

* CA証明書は**CAサーバー自体**に存在し、その**秘密鍵はマシンDPAPIによって保護されています**（OSがTPM/HSM/その他のハードウェアを保護に使用していない限り）。
* 証明書の**Issuer**と**Subject**は、両方とも**CAの識別名**に設定されています。
* CA証明書（そしてCA証明書のみ）には**「CAバージョン」拡張機能**があります。
* EKUは**ありません**

この証明書の秘密鍵を**抽出する**ためのビルトインGUIサポートされた方法は、CAサーバー上の`certsrv.msc`を使用します。\
しかし、この証明書はシステムに保存されている他の証明書と**違いはありません**ので、例えば[**THEFT2テクニック**](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)をチェックして、それらを**抽出する**方法を確認してください。

また、[**certipy**](https://github.com/ly4k/Certipy)を使用して証明書と秘密鍵を取得することもできます：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
一度 **CA証明書** とプライベートキーを `.pfx` 形式で取得したら、有効な証明書を作成するために [**ForgeCert**](https://github.com/GhostPack/ForgeCert) を使用できます：
```bash
# Create new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Create new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Use new certificate with Rubeus to authenticate
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# User new certi with certipy to authenticate
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
{% hint style="warning" %}
**注記**: 証明書を偽造する際に指定する**ユーザー**は、AD内で**アクティブ/有効**であり、認証交換がそのユーザーとして行われるため、**認証が可能**である必要があります。例えば、krbtgtアカウントの証明書を偽造しようとしても機能しません。
{% endhint %}

この偽造された証明書は、指定された終了日まで**有効**であり、ルートCA証明書が有効である限り（通常は5年から**10年以上**）有効です。また、**マシン**に対しても有効なので、**S4U2Self**と組み合わせることで、攻撃者はCA証明書が有効である限り、任意のドメインマシンに対する**持続性を維持**することができます。
さらに、この方法で**生成された証明書**は、CAがそれらを認識していないため、**取り消すことができません**。

## Rogue CA証明書の信頼 - DPERSIST2

オブジェクト`NTAuthCertificates`は、その`cacertificate`**属性**に一つ以上の**CA証明書**を定義し、ADはそれを使用します：認証中、**ドメインコントローラー**は**`NTAuthCertificates`**オブジェクトが認証中の**証明書**のIssuerフィールドに指定された**CA**のエントリを**含んでいるかどうかをチェックします。もし**含まれていれば、認証が進行します**。

攻撃者は、**自己署名されたCA証明書**を生成し、それを**`NTAuthCertificates`**オブジェクトに**追加**することができます。攻撃者が**`NTAuthCertificates`** ADオブジェクトを**制御**している場合（デフォルトの設定では、**エンタープライズ管理者**グループのメンバーや、**フォレストルートのドメイン**内の**ドメイン管理者**または**管理者**のメンバーのみがこの権限を持っています）、この操作が可能です。権限を持っていれば、`certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`を使用して、または[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)を使用して、任意のシステムから**`NTAuthCertificates`**オブジェクトを**編集**することができます。

指定された証明書は、以前に詳細に説明されたForgeCertを使用した偽造方法と**連携して動作**するはずです。

## 悪意のある誤設定 - DPERSIST3

AD CSコンポーネントの**セキュリティ記述子の変更**を通じて、**持続性**を確保する機会は無数にあります。"[ドメインエスカレーション](domain-escalation.md)"セクションで説明されているシナリオは、権限を持つ攻撃者によって悪意を持って実装される可能性があります。これには、"制御権"（つまり、WriteOwner/WriteDACLなど）を以下のような敏感なコンポーネントに追加することが含まれます：

* **CAサーバーのADコンピューター**オブジェクト
* **CAサーバーのRPC/DCOMサーバー**
* コンテナ**`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`**内の任意の**子孫ADオブジェクトまたはコンテナー**（例：証明書テンプレートコンテナ、認証局コンテナ、NTAuthCertificatesオブジェクトなど）
* **デフォルトまたは現在の組織によってAD CSの制御権を委任されたADグループ**（例：組み込みのCert Publishersグループとそのメンバー）

例えば、ドメイン内で**権限を持つ攻撃者**は、攻撃者が権利の主体であるデフォルトの**`User`**証明書テンプレートに**`WriteOwner`**権限を追加することができます。これを後で悪用するために、攻撃者はまず**`User`**テンプレートの所有権を自分自身に変更し、次にテンプレート上で**`mspki-certificate-name-flag`**を**1**に設定して**`ENROLLEE_SUPPLIES_SUBJECT`**を有効にします（つまり、ユーザーがリクエストにSubject Alternative Nameを指定できるようにします）。その後、攻撃者は**テンプレート**に**登録**し、代替名として**ドメイン管理者**の名前を指定し、DAとして認証に使用するための証明書を使用することができます。

## 参考文献

* このページの情報はすべて[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)から取得しました

<details>

<summary><strong>AWSのハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
