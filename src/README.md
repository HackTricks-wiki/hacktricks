# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks のロゴとモーションデザインは_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_によるものです。_

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
Your local copy of HackTricks will be **http://localhost:3337** で **5分未満** で利用可能になります（書籍のビルドが必要です。しばらくお待ちください）。

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) は、**HACK THE UNHACKABLE** をスローガンに掲げる優れたサイバーセキュリティ企業です。独自の調査を行い、独自の hacking tools を開発して、**pentesting**、Red teams、training など、いくつかの価値あるサイバーセキュリティサービスを **提供** しています。

**blog** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) で確認できます。

**STM Cyber** は HackTricks のようなサイバーセキュリティのオープンソースプロジェクトも支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** は **Europe's #1** の ethical hacking および **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

経験豊富な hackers や bug bounty hunters とやり取りするために、[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server に参加しましょう！

- **Hacking Insights:** hacking の興奮や課題を掘り下げるコンテンツに参加する
- **Real-Time Hack News:** リアルタイムのニュースと洞察で、スピード感のある hacking world の最新情報を把握する
- **Latest Announcements:** 新しく開始される bug bounties や重要な platform updates をいち早く把握する

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、**engineering-first, hands-on lab approach** に基づく **実践的な AI Security training** を提供します。私たちのコースは、security engineers、AppSec professionals、developers が **build, break, and secure real AI/LLM-powered applications** できるように作られています。

**AI Security Certification** は、次を含む実践的なスキルに重点を置いています:
- LLM と AI-powered applications の保護
- AI systems の threat modeling
- Embeddings、vector databases、RAG security
- LLM attacks、abuse scenarios、そして実践的な defenses
- Secure design patterns と deployment considerations

すべてのコースは **on-demand**、**lab-driven** で、単なる理論ではなく **real-world security tradeoffs** を中心に設計されています。

👉 AI Security course の詳細:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は、**search engine results** に高速かつ簡単にアクセスできる real-time APIs を提供します。search engines のスクレイピング、proxy の処理、captcha の解決、そして豊富な構造化データの解析を代行します。

SerpApi のいずれかの plan の subscription には、Google、Bing、Baidu、Yahoo、Yandex などを含む、さまざまな search engine をスクレイピングするための 50 以上の異なる APIs へのアクセスが含まれます。\
他の provider と違い、**SerpApi は organic results だけをスクレイピングするわけではありません**。SerpApi の responses には、広告、inline images、videos、knowledge graphs、そして search results に含まれるその他の要素や機能が一貫して含まれます。

現在の SerpApi の customers には **Apple, Shopify, and GrubHub** が含まれます。\
詳細は [**blog**](https://serpapi.com/blog/)**,** を確認するか、[**playground**](https://serpapi.com/playground)**.** で例を試してください。\
[**here**](https://serpapi.com/users/sign_up)**.** から **create a free account** できます。

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

vulnerability research、penetration testing、reverse engineering を行い、mobile applications と devices を保護するために必要な technologies と skills を学びましょう。**Master iOS and Android security** を、私たちの on-demand courses で習得し、**get certified** してください:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** は、攻撃者より先に exploitable vulnerabilities を見つけるための AI-powered security platform です。

**Code security tip**: 開発者と security teams のために作られた smart vulnerability monitoring platform、NaxusAI に sign up しましょう！今すぐ参加して、**detecting, validating, and fixing real security risks before they reach production** のために AI を使い始めましょう！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) は **Amsterdam** を拠点とする professional cybersecurity company で、**modern** なアプローチの **offensive-security services** を提供し、**all over the world** の企業を最新のサイバーセキュリティ脅威から **protecting** しています。

WebSec は Amsterdam と Wyoming にオフィスを持つ国際的な security company です。**all-in-one security services** を提供しており、Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing など、すべてを行います。

WebSec のもうひとつのクールな点は、業界平均と違って WebSec は自社の skills に **very confident** であり、そのため **the best quality results** を保証していることです。サイトには "**If we can't hack it, You don't pay it!**" と記載されています。詳細は [**website**](https://websec.net/en/) と [**blog**](https://websec.net/blog/) をご覧ください！

上記に加えて、WebSec は HackTricks の **committed supporter** でもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、業界 experts によって構築され、主導される効果的な cybersecurity training を開発・提供しています。彼らのプログラムは theory を超え、custom environments を使って、real-world threats を反映した深い理解と実行可能な skills をチームに提供します。custom training の問い合わせは、[**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) から連絡してください。

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は、**Education** と **FinTech** 機関向けに特化した cybersecurity services を提供しており、**penetration testing, cloud security assessments**、および **compliance readiness**（SOC 2, PCI-DSS, NIST）に重点を置いています。私たちのチームには **OSCP and CISSP certified professionals** が含まれ、すべての engagement に深い技術的専門知識と業界標準の洞察をもたらします。

私たちは、高リスクな環境に合わせた **manual, intelligence-driven testing** で、automated scans を超えて対応します。学生記録の保護から金融取引の保護まで、最も重要なものを守るために組織を支援します。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

最新の cybersecurity 情報を把握し続けるために、[**blog**](https://www.lasttowersolutions.com/blog) をご覧ください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE は、DevOps、DevSecOps、developers が Kubernetes clusters を効率的に管理、監視、保護できるようにします。AI-driven insights、高度な security framework、直感的な CloudMaps GUI を活用して、clusters を可視化し、その状態を理解し、自信を持って対応してください。

さらに、K8Studio は **all major kubernetes distributions**（AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more）と互換性があります。

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

次をご確認ください:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
