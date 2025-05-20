# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricksのロゴとモーションデザインは_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_によるものです。_

### HackTricksをローカルで実行する
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export LANG="master" # Leave master for english
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
あなたのローカルコピーのHackTricksは、**[http://localhost:3337](http://localhost:3337)**で**5分以内に**利用可能になります（本をビルドする必要があるため、しばらくお待ちください）。

## 企業スポンサー

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com)は、**HACK THE UNHACKABLE**というスローガンを持つ素晴らしいサイバーセキュリティ会社です。彼らは独自の研究を行い、**ペンテスト、レッドチーム、トレーニング**などの価値あるサイバーセキュリティサービスを提供するために独自のハッキングツールを開発しています。

彼らの**ブログ**は[**https://blog.stmcyber.com**](https://blog.stmcyber.com)で確認できます。

**STM Cyber**は、HackTricksのようなサイバーセキュリティのオープンソースプロジェクトもサポートしています :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com)は、**スペイン**で最も重要なサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの一つです。**技術的知識の促進**を使命とし、この会議はあらゆる分野の技術とサイバーセキュリティの専門家が集まる熱い交流の場です。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti**は、**ヨーロッパの#1**エシカルハッキングおよび**バグバウンティプラットフォーム**です。

**バグバウンティのヒント**: **Intigriti**に**サインアップ**してください。これは、ハッカーによって、ハッカーのために作られたプレミアム**バグバウンティプラットフォーム**です！今日、[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加し、最大**$100,000**の報酬を得始めましょう！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も**高度な**コミュニティツールによって**ワークフローを簡単に構築および自動化**します。

今すぐアクセスを取得：

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

- **ハッキングの洞察:** ハッキングのスリルと課題に関するコンテンツに参加
- **リアルタイムハックニュース:** リアルタイムのニュースと洞察を通じて、急速に変化するハッキングの世界を把握
- **最新の発表:** 新しいバグバウンティの開始や重要なプラットフォームの更新について最新情報を入手

**私たちと一緒に** [**Discord**](https://discord.com/invite/N3FrSbmwdy)に参加し、今日からトップハッカーとコラボレーションを始めましょう！

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - 必須のペネトレーションテストツールキット

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**あなたのウェブアプリ、ネットワーク、クラウドに対するハッカーの視点を得る**

**実際のビジネスに影響を与える重大で悪用可能な脆弱性を見つけて報告します。** 20以上のカスタムツールを使用して攻撃面をマッピングし、特権を昇格させるセキュリティ問題を見つけ、自動化されたエクスプロイトを使用して重要な証拠を収集し、あなたの努力を説得力のある報告に変えます。

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi**は、**検索エンジンの結果**にアクセスするための迅速で簡単なリアルタイムAPIを提供します。彼らは検索エンジンをスクレイピングし、プロキシを処理し、キャプチャを解決し、すべてのリッチな構造化データを解析します。

SerpApiのプランのサブスクリプションには、Google、Bing、Baidu、Yahoo、Yandexなど、さまざまな検索エンジンをスクレイピングするための50以上の異なるAPIへのアクセスが含まれます。\
他のプロバイダーとは異なり、**SerpApiはオーガニック結果だけをスクレイピングするわけではありません**。SerpApiの応答には、常にすべての広告、インライン画像や動画、ナレッジグラフ、検索結果に存在する他の要素や機能が含まれます。

現在のSerpApiの顧客には、**Apple、Shopify、GrubHub**が含まれます。\
詳細については、彼らの[**ブログ**](https://serpapi.com/blog/)をチェックするか、[**プレイグラウンド**](https://serpapi.com/playground)で例を試してみてください。\
**無料アカウントを作成**するには、[**こちら**](https://serpapi.com/users/sign_up)をクリックしてください。**

---

### [8kSec Academy – 深層モバイルセキュリティコース](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

脆弱性研究、ペネトレーションテスト、リバースエンジニアリングを実施するために必要な技術とスキルを学び、モバイルアプリケーションとデバイスを保護します。**iOSとAndroidのセキュリティをマスター**し、オンデマンドコースを通じて**認定を取得**します：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net)は、**アムステルダム**に拠点を置くプロフェッショナルなサイバーセキュリティ会社で、最新のサイバーセキュリティ脅威から**世界中のビジネスを保護する**ために、**攻撃的セキュリティサービス**を**現代的**なアプローチで提供しています。

WebSecは、アムステルダムとワイオミングにオフィスを持つ国際的なセキュリティ会社です。彼らは**オールインワンサービス**を提供しており、ペンテスト、**セキュリティ**監査、意識向上トレーニング、フィッシングキャンペーン、コードレビュー、エクスプロイト開発、セキュリティ専門家のアウトソーシングなど、すべてを行います。

WebSecのもう一つの素晴らしい点は、業界の平均とは異なり、WebSecは**自分たちのスキルに非常に自信を持っている**ことであり、そのため、**最高の品質の結果を保証します**。彼らのウェブサイトには「**私たちがハッキングできなければ、あなたは支払わない！**」と記載されています。詳細については、彼らの[**ウェブサイト**](https://websec.net/en/)と[**ブログ**](https://websec.net/blog/)を見てください！

上記に加えて、WebSecは**HackTricksの熱心なサポーターでもあります。**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)は、データ漏洩（leak）検索エンジンです。\
私たちは、すべてのタイプのデータ漏洩に対してランダムな文字列検索（Googleのように）を提供します。\
人々の検索、AI検索、組織検索、API（OpenAPI）アクセス、theHarvester統合、ペンテスターが必要とするすべての機能を提供します。\
**HackTricksは私たち全員にとって素晴らしい学習プラットフォームであり、私たちはそれをスポンサーできることを誇りに思っています！**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutionsは、**教育**および**フィンテック**機関向けに特化したサイバーセキュリティサービスを提供し、**ペネトレーションテスト、クラウドセキュリティ評価**、および**コンプライアンス準備**（SOC 2、PCI-DSS、NIST）に焦点を当てています。私たちのチームには、**OSCPおよびCISSP認定の専門家**が含まれており、すべてのエンゲージメントに深い技術的専門知識と業界標準の洞察を提供します。

私たちは、**手動でのインテリジェンス駆動のテスト**を通じて自動スキャンを超え、高リスク環境に合わせたテストを行います。学生の記録を保護することから、金融取引を守ることまで、私たちは組織が最も重要なものを守る手助けをします。

_「質の高い防御には攻撃を知ることが必要です。私たちは理解を通じてセキュリティを提供します。」_

最新のサイバーセキュリティ情報を得るために、私たちの[**ブログ**](https://www.lasttowersolutions.com/blog)を訪れてください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

## ライセンスと免責事項

以下で確認してください：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github統計

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
