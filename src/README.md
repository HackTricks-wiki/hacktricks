# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks ロゴとモーションデザイン：_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### ローカルで HackTricks を実行
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
# "hi" for HindiP
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
HackTricks のローカルコピーは **[http://localhost:3337](http://localhost:3337) で利用可能になります**（約5分以内に反映されます。書籍をビルドする必要があるため、しばらくお待ちください）。

## 企業スポンサー

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) は優れたサイバーセキュリティ企業で、スローガンは **HACK THE UNHACKABLE** です。彼らは独自に研究を行い、自社の hacking ツールを開発して、pentesting、Red teams、トレーニングのような **価値ある複数のサイバーセキュリティサービスを提供**しています。

彼らの **ブログ** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) でご覧になれます。

**STM Cyber** は HackTricks のようなサイバーセキュリティのオープンソースプロジェクトもサポートしています :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) は **スペイン** で最も重要なサイバーセキュリティイベントであり、**ヨーロッパ** の中でも重要なイベントの一つです。**技術知識の普及を使命とする** このカンファレンスは、あらゆる分野の技術者やサイバーセキュリティ専門家が集まる熱い交流の場です。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** はヨーロッパで No.1 の ethical hacking と **bug bounty platform** です。

**Bug bounty tip**: **Intigriti にサインアップ**してみてください。ハッカーによって作られた、ハッカーのためのプレミアムな bug bounty platform です！今すぐ [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) に参加して、最大 **$100,000** の賞金を獲得し始めましょう！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
世界で最も **高度な** コミュニティツールを活用して、ワークフローを簡単に構築・**自動化**するには [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) を利用してください。

今日アクセスを取得：

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** ハッキングの興奮や課題に深く踏み込んだコンテンツを扱っています
- **Real-Time Hack News:** リアルタイムのニュースとインサイトで急速に変化するハッキングの世界を把握できます
- **Latest Announcements:** 新しい bug bounty の開始や重要なプラットフォーム更新を常に把握できます

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

重要で実用的なビジネス影響のある脆弱性を発見して報告しましょう。攻撃対象のマッピング、権限昇格を許すセキュリティ問題の発見、証拠収集のための自動化されたエクスプロイトの利用など、20以上のカスタムツールを使って効率的に調査できます。これにより、あなたの作業を説得力のあるレポートに変換できます。

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は検索エンジンの結果に **リアルタイムで高速かつ簡単にアクセスする** API を提供します。検索エンジンのスクレイピング、プロキシ処理、キャプチャ解決、リッチな構造化データの解析を代行します。

SerpApi のプランに加入すると、Google、Bing、Baidu、Yahoo、Yandex など、さまざまな検索エンジン向けの 50 種類以上の API にアクセスできます。\
他のプロバイダとは異なり、**SerpApi はオーガニックな結果だけをスクレイピングするのではありません**。SerpApi のレスポンスには広告、インライン画像や動画、ナレッジグラフなど、検索結果に表示される要素が一貫して含まれます。

現在の SerpApi の顧客には **Apple, Shopify, and GrubHub** が含まれます。\
詳細は彼らの [**blog**](https://serpapi.com/blog/) をご覧いただくか、[**playground**](https://serpapi.com/playground) で試してみてください。\
無料アカウントは [**こちら**](https://serpapi.com/users/sign_up) から作成できます。

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

モバイルアプリとデバイスを保護するために必要な技術とスキルを学びましょう。脆弱性調査、penetration testing、リバースエンジニアリングを習得し、オンデマンドコースで iOS と Android のセキュリティをマスターして **認定** を取得できます。

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) は **Amsterdam** に拠点を置くプロフェッショナルなサイバーセキュリティ企業で、**攻撃的セキュリティサービス** を通じて世界中の企業を最新のサイバー脅威から守る手助けをしています。現代的なアプローチでサービスを提供しています。

WebSec は Amsterdam と Wyoming にオフィスを持つ国際的なセキュリティ企業で、Pentesting、**Security** Audits、Awareness Trainings、Phishing Campaigns、Code Review、Exploit Development、Security Experts Outsourcing など、オールインワンのセキュリティサービスを提供しています。

業界平均とは異なり、WebSec は自社のスキルに非常に自信を持っており、**最高品質の結果を保証**すると明言しています。彼らのウェブサイトには「**If we can't hack it, You don't pay it!**」と記載されています。詳細は彼らの [**website**](https://websec.net/en/) と [**blog**](https://websec.net/blog/) をご覧ください！

さらに、WebSec は HackTricks の熱心なサポーターでもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**現場のために。あなたを中心に。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は業界の専門家が構築・指導する実践的なサイバーセキュリティ研修を提供します。彼らのプログラムは理論を超え、実世界の脅威を反映したカスタム環境を用いて、深い理解と実行可能なスキルをチームに提供します。カスタム研修の問い合わせは [**こちら**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) から。

**彼らの研修の特徴:**
* カスタム作成のコンテンツとラボ
* 一流のツールとプラットフォームに裏打ちされた内容
* 実務経験者による設計と指導

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は **教育機関** と **FinTech** 向けに特化したサイバーセキュリティサービスを提供しており、特に **penetration testing, cloud security assessments**、および **compliance readiness**（SOC 2、PCI-DSS、NIST）に注力しています。チームには **OSCP と CISSP** 認定の専門家が在籍しており、深い技術的専門知識と業界標準の知見を提供します。

自動化スキャンを超えた **インテリジェンス駆動の手動テスト** を行い、学籍記録の保護から金融取引の保護まで、重要な資産を守る支援を行います。

_「質の高い防御は攻撃を知ることから始まる。私たちは理解を通じてセキュリティを提供します。」_

最新のサイバーセキュリティ情報は彼らの [**blog**](https://www.lasttowersolutions.com/blog) をご覧ください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE は DevOps、DevSecOps、および開発者が Kubernetes クラスターを効率的に管理、監視、保護することを支援します。AI駆動のインサイト、先進的なセキュリティフレームワーク、直感的な CloudMaps GUI を活用してクラスターを可視化し、状態を把握し、自信を持って対応できます。

さらに、K8Studio は主要なすべての kubernetes ディストリビューション（AWS、GCP、Azure、DO、Rancher、K3s、Openshift など）と **互換性があります**。

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## ライセンスと免責事項

詳細は以下をご確認ください：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## GitHub 統計

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
