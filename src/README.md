# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks のロゴとモーションデザイン（制作）_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### ローカルで HackTricks を実行する
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

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) はスローガンが **HACK THE UNHACKABLE** の優れたサイバーセキュリティ企業です。独自のリサーチを行い、自社のハッキングツールを開発して、**pentesting、Red teams、training** のような価値ある複数のサイバーセキュリティサービスを提供しています。

彼らの**blog**は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) でご覧いただけます。

**STM Cyber** は HackTricks のようなオープンソースのサイバーセキュリティプロジェクトもサポートしています :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) は**スペイン**で最も重要なサイバーセキュリティイベントであり、**ヨーロッパ**でも有数のイベントです。**技術的知識の普及を使命**としており、このカンファレンスはあらゆる分野のテクノロジーとサイバーセキュリティ専門家が集まる活気ある場です。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** は **Europe's #1** の ethical hacking かつ **bug bounty platform** です。

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は**エンジニアリング重視のハンズオンラボアプローチ**で**実践的なAI Security training**を提供します。コースはセキュリティエンジニア、AppSecプロフェッショナル、開発者向けに作られており、実際のAI/LLMを活用したアプリケーションを**構築、破壊、保護**するための内容です。

**AI Security Certification** は実務的なスキルに焦点を当てています。内容には以下が含まれます：
- Securing LLM and AI-powered applications
- Threat modeling for AI systems
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns and deployment considerations

すべてのコースは**on-demand**で**lab-driven**、そして**real-world security tradeoffs**に基づいて設計されています。理論だけではありません。

👉 AI Securityコースの詳細:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は検索エンジンの結果に**リアルタイムで簡単にアクセスできる高速API**を提供します。検索エンジンのスクレイピング、プロキシの扱い、キャプチャの解決、リッチな構造データのパースを代行します。

SerpApi のサブスクリプションには、Google、Bing、Baidu、Yahoo、Yandex など、さまざまな検索エンジン向けの50以上のAPIへのアクセスが含まれます。\
他のプロバイダと異なり、**SerpApi はオーガニック結果だけをスクレイプするわけではありません**。SerpApi のレスポンスには一貫して広告、インライン画像や動画、ナレッジグラフ、検索結果に含まれるその他の要素や機能が含まれます。

Current SerpApi customers include **Apple, Shopify, and GrubHub**.\
詳しくは彼らの[**blog**](https://serpapi.com/blog/)**、**または[**playground**](https://serpapi.com/playground)でサンプルを試してみてください。\
**Create a free account** はこちらから: [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

モバイルアプリケーションやデバイスを保護するための脆弱性調査、penetration testing、リバースエンジニアリングに必要な技術とスキルを学びます。**iOS と Android のセキュリティを習得**できるオンデマンドコースで**認定**を取得できます。

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) は**Amsterdam**に拠点を置くプロフェッショナルなサイバーセキュリティ企業で、**世界中の**企業を最新のサイバーセキュリティ脅威から守るために、**offensive-security services** をモダンなアプローチで提供しています。

WebSec はアムステルダムとワイオミングにオフィスを持つ国際的なセキュリティ企業です。彼らは Pentesting、**Security Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing** などの**オールインワンのセキュリティサービス**を提供しています。

WebSec のもう一つの特徴は、業界平均と比べて非常に自信を持っている点で、ウェブサイトには「**If we can't hack it, You don't pay it!**」と記載しており、最高品質の結果を保証するとしています。詳細は彼らの[**website**](https://websec.net/en/) と[**blog**](https://websec.net/blog/) をご覧ください。

さらに、WebSec は HackTricks の**熱心なサポーター**でもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は業界の専門家により構築・指導される効果的なサイバーセキュリティトレーニングを開発・提供します。彼らのプログラムは理論を超え、実世界の脅威を反映したカスタム環境を使って、チームに深い理解と実行可能なスキルを提供します。カスタムトレーニングの問い合わせは [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) からご連絡ください。

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

Last Tower Solutions は **Education** と **FinTech** 機関向けに特化したサイバーセキュリティサービスを提供しており、特に **penetration testing、cloud security assessments**、および **compliance readiness** (SOC 2, PCI-DSS, NIST) に注力しています。チームには **OSCP and CISSP certified professionals** が含まれ、深い技術的専門知識と業界標準の洞察を各エンゲージメントにもたらします。

自動スキャンに頼らない、**manual, intelligence-driven testing** を提供し、ハイリスク環境に合わせたテストを行います。学生記録の保護から金融取引の保護まで、組織が最も重要なものを守る手助けをします。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

最新のサイバーセキュリティ情報については彼らの[**blog**](https://www.lasttowersolutions.com/blog) をご覧ください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE は DevOps、DevSecOps、開発者が Kubernetes クラスターを効率的に管理、監視、保護するための機能を提供します。AI駆動のインサイト、高度なセキュリティフレームワーク、直感的な CloudMaps GUI を活用してクラスターを可視化し、状態を把握して自信を持って対応できます。

さらに、K8Studio は **all major kubernetes distributions**（AWS, GCP, Azure, DO, Rancher, K3s, Openshift など）と互換性があります。

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
