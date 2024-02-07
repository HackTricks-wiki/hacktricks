# フィッシングの検出

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で私たちを**フォロー**する：[**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## はじめに

フィッシング試行を検出するには、**現在使用されているフィッシング技術を理解することが重要**です。この投稿の親ページには、この情報が記載されていますので、今日使用されている技術がわからない場合は、親ページに移動して少なくともそのセクションを読むことをお勧めします。

この投稿は、**攻撃者がなんらかの方法で被害者のドメイン名を模倣または使用しようとする**という考えに基づいています。たとえば、あなたのドメインが`example.com`と呼ばれ、`youwonthelottery.com`のような完全に異なるドメイン名を使用してフィッシングされた場合、これらの技術はそれを発見しません。

## ドメイン名の変種

メール内で**類似したドメイン名**を使用する**フィッシング**試行を**発見**するのは**簡単**です。\
攻撃者が使用する可能性のある**最もありそうなフィッシング名のリストを生成**し、それが**登録**されているかどうかを**チェック**するだけで十分です。

### 疑わしいドメインの検出

この目的のために、次のツールのいずれかを使用できます。これらのツールは、ドメインにIPが割り当てられているかどうかを自動的にチェックするため、DNSリクエストも実行します：

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### ビットフリップ

**この技術の短い説明は親ページにあります。または、オリジナルの研究を[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)で読むことができます**

たとえば、ドメインmicrosoft.comの1ビットの変更は、_windnws.com._に変換できます。\
**攻撃者は、被害者に関連するビットフリップドメインを可能な限り登録して、合法的なユーザーを自分たちのインフラストラクチャにリダイレクトする可能性があります**。

**すべての可能なビットフリップドメイン名も監視されるべきです。**

### 基本的なチェック

潜在的な疑わしいドメイン名のリストができたら、それらを（主にHTTPおよびHTTPSのポート）**チェック**して、被害者のドメインのいずれかに似たログインフォームを使用しているかどうかを**確認**する必要があります。\
ポート3333もチェックして、`gophish`のインスタンスが実行されているかどうかを確認できます。\
また、発見された疑わしいドメインの**年齢を知ること**も興味深いです。若ければリスクが高まります。\
HTTPおよび/またはHTTPSの疑わしいWebページの**スクリーンショット**を取得して、疑わしいかどうかを確認し、その場合は**アクセスして詳しく調べる**こともできます。

### 高度なチェック

さらに進む場合は、定期的に（毎日？数秒/数分しかかかりません）**これらの疑わしいドメインを監視し、さらに検索**することをお勧めします。関連するIPの**オープンポートをチェック**し、`gophish`や類似のツールのインスタンスを**検索**します（はい、攻撃者も間違えます）そして、疑わしいドメインとサブドメインのHTTPおよびHTTPSのWebページを**監視**して、被害者のWebページからログインフォームをコピーしているかどうかを確認します。\
これを**自動化**するためには、被害者のドメインのログインフォームのリストを持っておくことをお勧めし、疑わしいWebページをスパイダリングして、各疑わしいドメイン内で見つかったログインフォームを`ssdeep`のようなものを使用して被害者のドメインの各ログインフォームと比較します。\
疑わしいドメインのログインフォームを特定した場合は、**ダミーの資格情報を送信**して、**被害者のドメインにリダイレクトされるかどうか**を確認できます。

## キーワードを使用したドメイン名

親ページでは、被害者のドメイン名を**より大きなドメイン**（たとえばpaypal.comのpaypal-financial.com）に入れるというドメイン名の変種技術についても言及されています。

### 証明書透明性

以前の「ブルートフォース」アプローチを取ることはできませんが、証明書透明性のおかげで、**キーワードを使用したフィッシング試行を発見**することが実際に**可能**です。CAによって証明書が発行されるたびに、詳細が公開されます。これは、証明書透明性を読んだり、監視したりすることで、**名前にキーワードを使用しているドメインを見つけることができる**ことを意味します。たとえば、攻撃者が[https://paypal-financial.com](https://paypal-financial.com)の証明書を生成した場合、証明書を見ることで「paypal」というキーワードを見つけ、疑わしいメールが使用されていることがわかります。

投稿[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)では、特定のキーワードに影響を与える証明書を検索し、日付（「新しい」証明書のみ）とCA発行者「Let's Encrypt」でフィルタリングするためにCensysを使用できると述べています：

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../.gitbook/assets/image (390).png>)

ただし、無料のWeb [**crt.sh**](https://crt.sh)を使用して「同じ」ことができます。**キーワードを検索**し、必要に応じて結果を**日付とCAでフィルタリング**できます。

![](<../../.gitbook/assets/image (391).png>)

この最後のオプションを使用すると、実際のドメインのいずれかのアイデンティティが疑わしいドメインのいずれかと一致するかどうかを確認するために、一致するアイデンティティフィールドを使用できます（疑わしいドメインが誤検知される可能性があることに注意してください）。

**別の選択肢**は、[**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)という素晴らしいプロジェクトです。CertStreamは、新しく生成された証明書のリアルタイムストリームを提供し、指定されたキーワードを（ほぼ）リアルタイムで検出するために使用できます。実際、[**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher)というプロジェクトがそれを行っています。

### **新しいドメイン**

**最後の選択肢**は、いくつかのTLD（Top Level Domain）の**新しく登録されたドメインのリスト**を収集し、これらのドメインで**キーワードをチェック**することです（[Whoxy](https://www.whoxy.com/newly-registered-domains/)がそのようなサービスを提供しています）。ただし、長いドメインは通常1つ以上のサブドメインを使用するため、キーワードはFLD内に表示されず、フィッシングサブドメインを見つけることができません。
