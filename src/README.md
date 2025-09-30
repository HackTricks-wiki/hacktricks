# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_HackTricks のロゴとモーションデザイン制作:_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks をローカルで実行する
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
ローカルの HackTricks は **[http://localhost:3337](http://localhost:3337)** で <5 分後に利用可能になります（ブックのビルドが必要です。少々お待ちください）。

## 企業スポンサー

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) は優れたサイバーセキュリティ企業で、スローガンは **HACK THE UNHACKABLE** です。彼らは独自に研究を行い、独自の hacking tools を開発して、pentesting、Red teams、training といった **複数の価値あるサイバーセキュリティサービスを提供しています**。

彼らの **ブログ** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) で確認できます

**STM Cyber** は HackTricks のようなサイバーセキュリティのオープンソースプロジェクトも支援しています :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) は **スペイン** で最も重要なサイバーセキュリティイベントで、**欧州** でも屈指の大会です。**技術知識の普及を使命とし**、この会議はあらゆる分野の技術・サイバーセキュリティ専門家にとって活発な交流の場です。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** は **Europe's #1** の ethical hacking かつ **bug bounty platform** です。

**Bug bounty tip**: **Intigriti** にサインアップして、hackers によって作られたプレミアムな **bug bounty platform** を活用しましょう！[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) で今すぐ参加して、最大 **$100,000** のバウンティを獲得し始めましょう！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) を使って、世界で最も **advanced** なコミュニティツールによるワークフローを簡単に構築・**automate** できます。

今すぐアクセス：

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** ハッキングのスリルや課題に踏み込んだコンテンツに触れられます
- **Real-Time Hack News:** リアルタイムのニュースやインサイトで速いテンポのハッキング界の情報を追えます
- **Latest Announcements:** 新しい bug bounty の開始や重要なプラットフォーム更新の情報を受け取れます

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** 20 を超えるカスタムツールを使ってアタックサーフェスをマップし、権限昇格を許すセキュリティ問題を発見し、automated exploits を使って必要な証拠を収集し、あなたの作業を説得力のあるレポートに変換します。

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は検索エンジン結果へ迅速かつ簡単にリアルタイムでアクセスするための API を提供します。検索エンジンのスクレイピング、プロキシ処理、キャプチャの解決、リッチな構造化データの解析を代行します。

SerpApi のプランに加入すると、Google、Bing、Baidu、Yahoo、Yandex など、さまざまな検索エンジンをスクレイピングする 50 以上の異なる API にアクセスできます。\
他のプロバイダとは異なり、**SerpApi doesn’t just scrape organic results**。SerpApi のレスポンスには常に広告、インライン画像や動画、Knowledge Graph など検索結果に含まれる全ての要素や機能が含まれます。

現在の SerpApi の顧客には **Apple, Shopify, and GrubHub** が含まれます。\
詳細は彼らの [**blog**](https://serpapi.com/blog/)**,** または [**playground**](https://serpapi.com/playground) でサンプルを試してみてください。\
[**ここ**](https://serpapi.com/users/sign_up) で無料アカウントを作成できます。

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

モバイルアプリケーションとデバイスを保護するための脆弱性調査、penetration testing、reverse engineering に必要な技術とスキルを学びます。オンデマンドコースで iOS と Android のセキュリティを習得し、**認定** を取得しましょう：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) は **アムステルダム** に拠点を置くプロフェッショナルなサイバーセキュリティ企業で、**世界中** の企業を最新のサイバー脅威から守るために、**offensive-security services** をモダンなアプローチで提供しています。

WebSec はアムステルダムとワイオミングにオフィスを持つ国際的なセキュリティ企業です。彼らは **all-in-one security services** を提供しており、Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing など幅広く対応します。

WebSec のもう一つの特徴は、業界平均とは異なり彼らが自分たちのスキルに**非常に自信を持っている**ことで、その自信は提供する成果物の品質保証にも表れており、ウェブサイトには「**If we can't hack it, You don't pay it!**」と記載されています。詳細は彼らの [**website**](https://websec.net/en/) と [**blog**](https://websec.net/blog/) をご覧ください。

さらに、WebSec は HackTricks の **献身的なサポーター** でもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) はデータブリーチ (leak) 検索エンジンです。\
大規模なものだけでなくあらゆる種類のデータ leak を対象に、ランダム文字列検索（google のような）を提供します — 複数ソースからのデータを横断検索します。\
人、AI、組織、API (OpenAPI) アクセス、theHarvester 統合など、pentester に必要な全ての機能を備えています。\
**HackTricks は私たち全員にとって素晴らしい学習プラットフォームであり、スポンサーとして支援できることを誇りに思います！**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は業界の専門家が構築・指導する効果的なサイバーセキュリティトレーニングを提供します。彼らのプログラムは理論を超えて、実践的な脅威を反映したカスタム環境を用い、チームに深い理解と実行可能なスキルを身につけさせます。カスタムトレーニングの問い合わせは [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) へ。

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は **Education** と **FinTech** 機関向けに特化したサイバーセキュリティサービスを提供しており、特に **penetration testing、cloud security assessments**、および **compliance readiness**（SOC 2、PCI-DSS、NIST）に注力しています。私たちのチームには **OSCP and CISSP certified professionals** が在籍し、深い技術的専門知識と業界標準の知見を各案件にもたらします。

自動スキャンを超えた、重要度の高い環境向けにカスタマイズされた **manual, intelligence-driven testing** を提供します。学生記録の保護から金融取引の保護まで、組織が最も重要視するものを守るお手伝いをします。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

最新のサイバーセキュリティ情報は彼らの [**blog**](https://www.lasttowersolutions.com/blog) をご覧ください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE は DevOps、DevSecOps、開発者が Kubernetes クラスターを効率的に管理、監視、保護するのを支援します。AI 駆動のインサイト、高度なセキュリティフレームワーク、直感的な CloudMaps GUI を利用してクラスターを可視化し、状態を把握し、自信を持って行動できます。

さらに、K8Studio は **すべての主要な kubernetes distributions**（AWS, GCP, Azure, DO, Rancher, K3s, Openshift など）と互換性があります。

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## ライセンスと免責事項

以下を参照してください：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## GitHub 統計

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
