# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks のロゴとモーションデザインは_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

あなたのローカルのHackTricksは <5 分以内に **[http://localhost:3337](http://localhost:3337)** で利用可能になります（書籍のビルドに時間がかかるので、しばらくお待ちください）。

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) is a great cybersecurity company whose slogan is **HACK THE UNHACKABLE**. They perform their own research and develop their own hacking tools to **offer several valuable cybersecurity services** like pentesting, Red teams and training.

[**STM Cyber**](https://www.stmcyber.com) はスローガンが **HACK THE UNHACKABLE** の優れたサイバーセキュリティ企業です。独自のリサーチを行い、自社のハッキングツールを開発して、pentesting、Red teams、トレーニングなどの**価値の高いサイバーセキュリティサービス**を提供しています。

You can check their **blog** in [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

彼らの**ブログ**は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) でご覧いただけます。

**STM Cyber** also support cybersecurity open source projects like HackTricks :)

**STM Cyber** は HackTricks のようなサイバーセキュリティのオープンソースプロジェクトも支援しています :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

[**RootedCON**](https://www.rootedcon.com) は **スペイン** で最も重要なサイバーセキュリティイベントであり、**ヨーロッパ** においても最も重要な大会の一つです。**技術知識の普及を使命** とし、このカンファレンスはあらゆる分野の技術者やサイバーセキュリティ専門家が集まる熱い交流の場です。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** is the **Europe's #1** ethical hacking and **bug bounty platform.**

**Intigriti** は **ヨーロッパでNo.1** のエシカルハッキングおよび **bug bounty platform** です。

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

**Bug bounty tip**: ハッカーによって、ハッカーのために作られたプレミアムな **bug bounty platform**、**Intigriti** に**sign up**しましょう！今日 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) に参加して、最大 **$100,000** のバウンティを獲得しましょう！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) を使えば、世界で最も**先進的な**コミュニティツールを活用して、ワークフローを簡単に構築し**自動化**できます。

Get Access Today:

今すぐアクセスしてみてください:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーや bug bounty ハンターと交流しましょう！

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Stay informed with the newest bug bounties launching and crucial platform updates

- **Hacking Insights:** ハッキングのスリルと課題に踏み込むコンテンツに参加
- **Real-Time Hack News:** リアルタイムのニュースと洞察で変化の速いハッキング界の最新情報をキャッチ
- **Latest Announcements:** 最新のbug bounty開始情報や重要なプラットフォーム更新を受け取る

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

**Discord** 上で参加して、トップハッカーと協力を始めましょう！

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Use our 20+ custom tools to map the attack surface, find security issues that let you escalate privileges, and use automated exploits to collect essential evidence, turning your hard work into persuasive reports.

**Webアプリ、ネットワーク、クラウドに対してハッカー視点を得ましょう**

**実際のビジネス影響を与える重大で悪用可能な脆弱性を発見して報告します。** 20以上のカスタムツールを使用して攻撃面をマッピングし、権限昇格を許すセキュリティ問題を発見し、自動化されたエクスプロイトで重要な証拠を収集して、頑張りを説得力のあるレポートに変換します。

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** offers fast and easy real-time APIs to **access search engine results**. They scrape search engines, handle proxies, solve captchas, and parse all rich structured data for you.

**SerpApi** は検索エンジン結果に**リアルタイムでアクセスできる**高速で簡単なAPIを提供します。検索エンジンのスクレイピング、プロキシの処理、キャプチャの解決、そしてリッチな構造化データの解析を代行します。

A subscription to one of SerpApi’s plans includes access to over 50 different APIs for scraping different search engines, including Google, Bing, Baidu, Yahoo, Yandex, and more.\
Unlike other providers, **SerpApi doesn’t just scrape organic results**. SerpApi responses consistently include all ads, inline images and videos, knowledge graphs, and other elements and features present in the search results.

SerpApi のサブスクリプションには、Google、Bing、Baidu、Yahoo、Yandex など、さまざまな検索エンジンをスクレイピングするための50以上の異なるAPIへのアクセスが含まれます。\
他のプロバイダとは異なり、**SerpApi はオーガニック結果だけをスクレイピングするわけではありません**。SerpApi のレスポンスには一貫して広告、インライン画像や動画、ナレッジグラフ、検索結果に含まれるその他の要素や機能が含まれます。

Current SerpApi customers include **Apple, Shopify, and GrubHub**.\
For more information check out their [**blog**](https://serpapi.com/blog/)**,** or try an example in their [**playground**](https://serpapi.com/playground)**.**\
You can **create a free account** [**here**](https://serpapi.com/users/sign_up)**.**

現在の SerpApi の顧客には **Apple、Shopify、GrubHub** などが含まれます。\
詳細は彼らの [**blog**](https://serpapi.com/blog/) をご覧いただくか、[**playground**](https://serpapi.com/playground) で例を試してみてください。\
[**こちら**](https://serpapi.com/users/sign_up) から**無料アカウントを作成**できます。

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Learn the technologies and skills required to perform vulnerability research, penetration testing, and reverse engineering to protect mobile applications and devices. **Master iOS and Android security** through our on-demand courses and **get certified**:

脆弱性リサーチ、penetration testing、リバースエンジニアリングを行い、モバイルアプリやデバイスを保護するために必要な技術とスキルを学びます。オンデマンドコースで**iOS と Android のセキュリティを習得**し、**認定**を取得しましょう：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) is a professional cybersecurity company based in **Amsterdam** which helps **protecting** businesses **all over the world** against the latest cybersecurity threats by providing **offensive-security services** with a **modern** approach.

[**WebSec**](https://websec.net) は **アムステルダム** に拠点を置くプロのサイバーセキュリティ企業であり、**モダンな**アプローチで **offensive-security services** を提供することで、世界中の企業を最新のサイバー脅威から**保護**する手助けをしています。

WebSec is an intenational security company with offices in Amsterdam and Wyoming. They offer **all-in-one security services** which means they do it all; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing and much more.

WebSec はアムステルダムとワイオミングにオフィスを持つ国際的なセキュリティ企業です。彼らは **all-in-one security services** を提供しており、Pentesting、**Security** Audits、Awareness Trainings、Phishing Campaigns、Code Review、Exploit Development、Security Experts Outsourcing など幅広く対応します。

Another cool thing about WebSec is that unlike the industry average WebSec is **very confident in their skills**, to such an extent that they **guarantee the best quality results**, it states on their website "**If we can't hack it, You don't pay it!**". For more info take a look at their [**website**](https://websec.net/en/) and [**blog**](https://websec.net/blog/)!

さらに興味深い点として、業界平均とは異なり WebSec は**自分たちのスキルに非常に自信を持っており**、そのために**最高品質の結果を保証する**とされています。ウェブサイトには「**If we can't hack it, You don't pay it!**」と記載されています。詳細は彼らの [**website**](https://websec.net/en/) と [**blog**](https://websec.net/blog/) をご覧ください！

In addition to the above WebSec is also a **committed supporter of HackTricks.**

上記に加え、WebSec は HackTricks の**熱心なサポーター**でもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) is a data breach (leak) search engine. \
We provide random string search (like google) over all types of data leaks big and small --not only the big ones-- over data from multiple sources. \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration, all features a pentester needs.\
**HackTricks continues to be a great learning platform for us all and we're proud to be sponsoring it!**

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) はデータ侵害 (leak) の検索エンジンです。\
大手から小規模まであらゆる種類のデータ leak を複数のソースから集め、ランダム文字列検索（Googleのような）を提供します。\
People search、AI search、organization search、API (OpenAPI) アクセス、theHarvester 統合など、pentester に必要な機能がすべて揃っています。\
**HackTricks は私たちにとって引き続き素晴らしい学習プラットフォームであり、スポンサーを務められることを誇りに思います！**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) develops and delivers effective cybersecurity training built and led by
industry experts. Their programs go beyond theory to equip teams with deep
understanding and actionable skills, using custom environments that reflect real-world
threats. For custom training inquiries, reach out to us [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**現場のために作られ、あなたのために設計されています。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は業界の専門家が設計・指導する実践的なサイバーセキュリティトレーニングを開発・提供しています。彼らのプログラムは理論を超え、実世界の脅威を反映したカスタム環境を用いてチームに深い理解と実行可能なスキルを提供します。カスタムトレーニングの問い合わせは [**こちら**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) からご連絡ください。

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

**彼らのトレーニングの特長:**
* カスタム作成されたコンテンツとラボ
* 一流のツールとプラットフォームによるサポート
* 実務家による設計と指導

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions delivers specialized cybersecurity services for **Education** and **FinTech**
institutions, with a focus on **penetration testing, cloud security assessments**, and
**compliance readiness** (SOC 2, PCI-DSS, NIST). Our team includes **OSCP and CISSP
certified professionals**, bringing deep technical expertise and industry-standard insight to
every engagement.

Last Tower Solutions は **教育機関** と **FinTech** 機関向けに特化したサイバーセキュリティサービスを提供しており、特に **penetration testing、cloud security assessments**、および **compliance readiness**（SOC 2、PCI-DSS、NIST）に注力しています。私たちのチームには **OSCP および CISSP 認定の専門家** が在籍しており、各案件に深い技術的専門知識と業界標準の洞察をもたらします。

We go beyond automated scans with **manual, intelligence-driven testing** tailored to
high-stakes environments. From securing student records to protecting financial transactions,
we help organizations defend what matters most.

自動スキャンだけでなく、ハイリスク環境に合わせた**手動でのインテリジェンス駆動のテスト**を提供します。学生記録の保護から金融取引の保護まで、重要なものを守るお手伝いをします。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

_「質の高い防御は攻撃を知ることを要する。私たちは理解を通じてセキュリティを提供します。」_

Stay informed and up to date with the latest in cybersecurity by visiting our [**blog**](https://www.lasttowersolutions.com/blog).

最新のサイバーセキュリティ情報は私たちの [**blog**](https://www.lasttowersolutions.com/blog) でご確認ください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE empowers DevOps, DevSecOps, and developers to manage, monitor, and secure Kubernetes clusters efficiently. Leverage our AI-driven insights, advanced security framework, and intuitive CloudMaps GUI to visualize your clusters, understand their state, and act with confidence.

K8Studio IDE は DevOps、DevSecOps、開発者が Kubernetes クラスターを効率的に管理、監視、保護できるよう支援します。AI駆動のインサイト、高度なセキュリティフレームワーク、直感的な CloudMaps GUI を活用してクラスターを可視化し、状態を把握し、自信を持って対処できます。

Moreover, K8Studio is **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

さらに、K8Studio は **主要なすべての kubernetes ディストリビューション**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift など）に**対応**しています。

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Check them in:

## ライセンスと免責事項

詳細は以下を確認してください:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
