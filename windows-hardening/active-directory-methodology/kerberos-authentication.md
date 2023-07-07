# Kerberos認証

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

**この情報は、次の投稿から抽出されました：** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## Kerberos（I）：Kerberosはどのように機能するのか？ - 理論

20 - MAR - 2019 - ELOY PÉREZ

この一連の投稿の目的は、攻撃を紹介するだけでなく、Kerberosがどのように機能するのかを明確にすることです。これは、多くの場合、いくつかのテクニックがなぜ機能するのか、しないのかが明確ではないためです。この知識を持つことで、ペンテストでこれらの攻撃のいずれかを使用するタイミングを知ることができます。

したがって、ドキュメントにダイビングし、トピックに関するいくつかの投稿を読んだ後、Kerberosプロトコルを利用するための重要な詳細をこの投稿にまとめました。

この最初の投稿では、基本的な機能のみが議論されます。後の投稿では、攻撃の実行方法やより複雑な側面（委任など）の動作方法について説明します。

説明が不十分なトピックについて疑問がある場合は、コメントや質問を残すことを恐れないでください。それでは、トピックに移りましょう。

### Kerberosとは？

まず、Kerberosは認証プロトコルであり、認可ではありません。つまり、ユーザーを識別するために秘密のパスワードを提供することができますが、このユーザーがどのリソースやサービスにアクセスできるかを検証しません。

KerberosはActive Directoryで使用されます。このプラットフォームでは、Kerberosは各ユーザーの特権に関する情報を提供しますが、各サービスはユーザーがリソースにアクセスできるかどうかを判断する責任があります。

### Kerberosの要素

このセクションでは、Kerberos環境のいくつかのコンポーネントについて説明します。

**トランスポート層**

Kerberosは、データをクリアテキストで送信するUDPまたはTCPをトランスポートプロトコルとして使用します。そのため、Kerberosは暗号化を提供します。

Kerberosが使用するポートはUDP/88およびTCP/88であり、これらはKDC（次のセクションで説明します）でリッスンする必要があります。

**エージェント**

Kerberosでは、認証を提供するためにいくつかのエージェントが連携して動作します。これらは次のとおりです。

* サービスにアクセスしたい**クライアントまたはユーザー**。
* ユーザーが必要とするサービスを提供する**AP**（アプリケーションサーバー）。
* Kerberosの主要なサービスである**KDC**（キー配布センター）。チケットを発行する責任があり、DC（ドメインコントローラー）にインストールされています。**AS**（認証サービス）によってサポートされており、TGTを発行します。

**暗号化キー**

Kerberosでは、チケットなどのいくつかの構造が処理されます。これらの構造の多くは、第三者による改ざんを防ぐために暗号化または署名されています。これらのキーは次のとおりです。

* **KDCまたはkrbtgtキー**は、krbtgtアカウントのNTLMハッシュから派生します。
* **ユーザーキー**は、ユーザーのNTLMハッシュから派生します。
* **サービスキー**は、サービス所有者のNTLMハッシュから派生します。サービス所有者はユーザーアカウントまたはコンピューターアカウントである場合があります。
* **セッションキー**は、ユーザーとKDCの間で交渉されます。
* **サービスセッションキー**は、ユーザーとサービスの間で使用されます。

**チケット**

Kerberosが処理する主要な構造はチケットです。これらのチケットは、ユーザーに配布され、Kerberosレルムで複数のアクションを実行するために使用されます。2つのタイプがあります。

* **TGS**（チケットグラントサービス）は、ユーザーがサービスに対して認証するために使用できるチケットです。サービスキーで暗号化されています。
* **TGT**（チケットグラントチケット）は、TGSを要求するためにKDCに提示されるチケットです。KDCキーで暗号化されています。

**PAC**

**PAC**（特権属性証明書）は、ほとんどのチケットに含まれる構造です。この構造にはユーザーの特権が含まれており、KDCキーで署名されています。

サービスは、KDCと通信してPACを検証することができますが、これはあまり頻繁には行われません。ただし、PACの検証は、PAC内の特権が正しいかどうかを検査せずに、その署名のみをチェックすることで行われます。
### 認証プロセス

このセクションでは、認証を実行するためのメッセージのシーケンスが、チケットを持たないユーザーから目的のサービスに対して認証されるまでの手順について調査されます。

**KRB\_AS\_REQ**

まず、ユーザーはKDCからTGTを取得する必要があります。これを実現するために、KRB\_AS\_REQを送信する必要があります。

![KRB\_AS\_REQスキーマメッセージ](<../../.gitbook/assets/image (175) (1).png>)

_KRB\_AS\_REQ_には、以下のフィールドが含まれます。

* ユーザーを認証し、リプレイ攻撃を防ぐために、クライアントキーで暗号化された**タイムスタンプ**
* 認証されたユーザーの**ユーザー名**
* **krbtgt**アカウントに関連付けられたサービス**SPN**
* ユーザーが生成した**Nonce**

注意：ユーザーアカウントで[_DONT\_REQ\_PREAUTH_](https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro)フラグが設定されていない限り、暗号化されたタイムスタンプはユーザーが事前認証を要求する場合にのみ必要です。

**KRB\_AS\_REP**

リクエストを受け取った後、KDCはタイムスタンプを復号化してユーザーの身元を検証します。メッセージが正しい場合、KDCは_KRB\_AS\_REP_で応答する必要があります。

![KRB\_AS\_REPスキーマメッセージ](<../../.gitbook/assets/image (176) (1).png>)

_KRB\_AS\_REP_には、次の情報が含まれます。

* **ユーザー名**
* TGTは以下を含みます：
* **ユーザー名**
* **セッションキー**
* TGTの**有効期限**
* KDCによって署名されたユーザーの特権を持つ**PAC**
* ユーザーキーで暗号化されたいくつかの**データ**が含まれています：
* **セッションキー**
* TGTの**有効期限**
* ユーザーのリプレイ攻撃を防ぐための**Nonce**

これでユーザーはTGTを持っており、TGSを要求し、その後サービスにアクセスすることができます。

**KRB\_TGS\_REQ**

TGSを要求するためには、KDCに_KRB\_TGS\_REQ_メッセージを送信する必要があります。

![KRB\_TGS\_REQスキーマメッセージ](<../../.gitbook/assets/image (177).png>)

_KRB\_TGS\_REQ_には、以下が含まれます。

* セッションキーで暗号化された**データ**：
* **ユーザー名**
* **タイムスタンプ**
* **TGT**
* 要求されたサービスの**SPN**
* ユーザーが生成した**Nonce**

**KRB\_TGS\_REP**

_KRB\_TGS\_REQ_メッセージを受け取った後、KDCは_KRB\_TGS\_REP_内のTGSを返します。

![KRB\_TGS\_REPスキーマメッセージ](<../../.gitbook/assets/image (178) (1).png>)

_KRB\_TGS\_REP_には、以下が含まれます。

* **ユーザー名**
* TGSには以下が含まれます：
* **サービスセッションキー**
* **ユーザー名**
* TGSの**有効期限**
* KDCによって署名されたユーザーの特権を持つ**PAC**
* セッションキーで暗号化された**データ**：
* **サービスセッションキー**
* TGSの**有効期限**
* ユーザーのリプレイ攻撃を防ぐための**Nonce**

**KRB\_AP\_REQ**

最後に、すべてがうまくいった場合、ユーザーは既に有効なTGSを使用してサービスとやり取りすることができます。それを使用するために、ユーザーはAPに_KRB\_AP\_REQ_メッセージを送信する必要があります。

![KRB\_AP\_REQスキーマメッセージ](<../../.gitbook/assets/image (179) (1).png>)

_KRB\_AP\_REQ_には、以下が含まれます。

* **TGS**
* サービスセッションキーで暗号化された**データ**：
* **ユーザー名**
* リプレイ攻撃を防ぐための**タイムスタンプ**

その後、ユーザーの特権が正しい場合、ユーザーはサービスにアクセスできます。通常は起こりませんが、APはKDCに対してPACを検証する必要があり、相互認証が必要な場合は_KRB\_AP\_REP_メッセージでユーザーに応答します。

### 参考文献

* Kerberos v5 RFC: [https://tools.ietf.org/html/rfc4120](https://tools.ietf.org/html/rfc4120)
* \[MS-KILE\] – Kerberos拡張: [https://msdn.microsoft.com/en-us/library/cc233855.aspx](https://msdn.microsoft.com/en-us/library/cc233855.aspx)
* \[MS-APDS\] – 認証プロトコルドメインサポート: [https://msdn.microsoft.com/en-us/library/cc223948.aspx](https://msdn.microsoft.com/en-us/library/cc223948.aspx)
* MimikatzとActive Directory Kerberos攻撃: [https://adsecurity.org/?p=556](https://adsecurity.org/?p=556)
* 5歳向けに説明するKerberos: [https://www.roguelynn.com/words/explain-like-im-5-kerberos/](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* Kerberos＆KRBTGT: [https://adsecurity.org/?p=483](https://adsecurity.org/?p=483)
* Mastering Windows Network Forensics and Investigation, 2 Edition . Autores: S. Anson , S. Bunting, R. Johnson y S. Pearson. Editorial Sibex.
* Active Directory , 5 Edition. Autores: B. Desmond, J. Richards, R. Allen y A.G. Lowe-Norris
* サービスプリンシパル名: [https://msdn.microsoft.com/en-us/library/ms677949(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/ms677949\(v=vs.85\).aspx)
* Active Directoryの機能レベル: [https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0](https://technet.microsoft.com/en-us/library/dbf0cdec-d72f-4ba3-bc7a-46410e02abb0)
* OverPass The Hash – Gentilkiwi Blog: [https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash](https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash)
* Pass The Ticket – Gentilkiwi Blog: [https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos](https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos)
* Golden Ticket – Gentilkiwi Blog: [https://blog.gentilkiwi.com/securite/mimikatz/golden-ticket-kerberos](https://blog.gentilkiwi.com/securite/mimikatz/golden-ticket-kerberos)
* Mimikatz Golden Ticket Walkthrough: [https://www.beneaththewaves.net/Projects/Mimikatz\_20\_-\_Golden\_Ticket\_Walkthrough.html](https://www.beneaththewaves.net/Projects/Mimik
* Kerberoasting – Part 2: [https://room362.com/post/2016/kerberoast-pt2/](https://room362.com/post/2016/kerberoast-pt2/)
* Roasting AS-REPs: [https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
* PAC Validation: [https://passing-the-hash.blogspot.com.es/2014/09/pac-validation-20-minute-rule-and.html](https://passing-the-hash.blogspot.com.es/2014/09/pac-validation-20-minute-rule-and.html)
* Understanding PAC Validation: [https://blogs.msdn.microsoft.com/openspecification/2009/04/24/understanding-microsoft-kerberos-pac-validation/](https://blogs.msdn.microsoft.com/openspecification/2009/04/24/understanding-microsoft-kerberos-pac-validation/)
* Reset the krbtgt acoount password/keys: [https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51)
* Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft: [https://www.microsoft.com/en-us/download/details.aspx?id=36036](https://www.microsoft.com/en-us/download/details.aspx?id=36036)
* Fun with LDAP, Kerberos (and MSRPC) in AD Environments: [https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments?slide=58](https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments?slide=58)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
