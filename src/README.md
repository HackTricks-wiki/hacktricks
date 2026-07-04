# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricksのロゴ＆モーションデザイン by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks will be **[http://localhost:3337](http://localhost:3337)** で利用可能になります。5分未満で完了します（book をビルドする必要があります。少し待ってください）。

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) は、スローガンが **HACK THE UNHACKABLE** の優れた cybersecurity 企業です。彼らは独自に research を行い、独自の hacking tools を開発して、**pentesting**, Red teams, training などの **複数の価値ある cybersecurity services** を提供しています。

彼らの **blog** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) で確認できます

**STM Cyber** は HackTricks のような cybersecurity open source projects も support しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** は **Europe's #1** ethical hacking and **bug bounty platform.**

**Bug bounty tip**: **Intigriti に sign up** しましょう。これは hackers によって hackers のために作られた premium な **bug bounty platform** です！今すぐ [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) に参加して、最大 **$100,000** の bounty を獲得し始めましょう！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

経験豊富な hackers と bug bounty hunters と交流するために、[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加しましょう！

- **Hacking Insights:** hacking の興奮と challenges を深く掘り下げるコンテンツに参加できます
- **Real-Time Hack News:** リアルタイムの news と insights で、変化の速い hacking world の最新情報を把握できます
- **Latest Announcements:** 新しく開始される bug bounties と重要な platform updates の最新情報を入手できます

**[**Discord**](https://discord.com/invite/N3FrSbmwdy) で私たちに参加し、今日からトップ hackers と協力し始めましょう！**

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、**engineering-first, hands-on lab approach** に基づいた **実践的な AI Security training** を提供します。私たちの courses は、security engineers、AppSec professionals、developers が **実際の AI/LLM-powered applications を build, break, and secure** したい場合のために作られています。

**AI Security Certification** は、次のような実践的スキルに重点を置いています:
- LLM と AI-powered applications の保護
- AI systems の threat modeling
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns と deployment considerations

すべての courses は **on-demand** で **lab-driven**、そして単なる理論ではなく **real-world security tradeoffs** を中心に設計されています。

👉 AI Security course の詳細:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は、**search engine results** にアクセスするための高速で簡単な real-time APIs を提供します。彼らは search engines を scrape し、proxies を処理し、captchas を解決し、すべてのリッチな structured data を解析してくれます。

SerpApi のプランのいずれかを購読すると、Google, Bing, Baidu, Yahoo, Yandex など、さまざまな search engines を scraping するための 50 以上の異なる APIs にアクセスできます。\
他の providers と違い、**SerpApi は単に organic results を scrape するだけではありません**。SerpApi の responses には、広告、inline images と videos、knowledge graphs、そして search results に含まれる他の要素や機能も一貫して含まれます。

現在の SerpApi customers には **Apple, Shopify, and GrubHub** が含まれます。\
詳細は [**blog**](https://serpapi.com/blog/)**,** または [**playground**](https://serpapi.com/playground) の example を試してください。\
[**here**](https://serpapi.com/users/sign_up) で **free account** を作成できます。**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

vulnerability research, penetration testing, reverse engineering に必要な technologies と skills を学び、mobile applications と devices を保護しましょう。オンデマンド courses を通じて **iOS と Android security をマスター**し、**認定を取得**できます:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** は、attacker より先に exploit 可能な vulnerabilities を見つけるための AI-powered security platform です。

**Code security tip**: 開発者と security teams のために作られた smart vulnerability monitoring platform、NaxusAI に sign up しましょう！今すぐ参加して、**production に到達する前に real security risks を detect, validate, and fix** するために AI を使い始めましょう！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) は **Amsterdam** に拠点を置く professional cybersecurity company で、**modern** なアプローチによる **offensive-security services** を提供し、**世界中の** businesses を最新の cybersecurity threats から **protecting** しています。

WebSec は Amsterdam と Wyoming にオフィスを持つ国際的な security company です。彼らは **all-in-one security services** を提供しており、Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing など、すべてを行います。

WebSec のもう 1 つの素晴らしい点は、業界平均とは異なり、WebSec は自分たちの skills に **非常に自信**を持っており、そのため **最高品質の results を保証**していることです。彼らの website には "**If we can't hack it, You don't pay it!**" と記載されています。詳細は [**website**](https://websec.net/en/) と [**blog**](https://websec.net/blog/) をご覧ください！

上記に加えて、WebSec は HackTricks の **committted supporter** でもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、業界 experts によって構築・主導される効果的な cybersecurity training を開発・提供します。彼らの programs は theory を超え、custom environments を使用して real-world threats を反映した、深い理解と実行可能な skills を teams に提供します。custom training の問い合わせは、[**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) から連絡してください。

**彼らの training を際立たせるもの:**
* Custom-built content and labs
* Top-tier tools and platforms によるサポート
* Practitioners によって設計・指導

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は、**Education** と **FinTech** 機関向けに特化した cybersecurity services を提供しており、**penetration testing, cloud security assessments**、および **compliance readiness**（SOC 2, PCI-DSS, NIST）に重点を置いています。私たちの team には **OSCP and CISSP certified professionals** が含まれており、すべての engagement に深い technical expertise と industry-standard insight をもたらします。

私たちは、自動スキャンを超えて、ハイリスクな environments に合わせた **manual, intelligence-driven testing** を行います。student records の保護から financial transactions の保護まで、私たちは organizations が最も重要なものを守る手助けをします。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

最新の cybersecurity 情報を確認するには、[**blog**](https://www.lasttowersolutions.com/blog) を訪れて、最新情報を入手してください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE は、DevOps, DevSecOps, and developers が Kubernetes clusters を効率的に manage, monitor, and secure できるようにします。AI-driven insights, advanced security framework, そして直感的な CloudMaps GUI を活用して clusters を可視化し、状態を理解し、自信を持って行動できます。

さらに、K8Studio は **all major kubernetes distributions**（AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more）と互換性があります。

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

これは cybersecurity free wiki: <b>Hacktricks Book </b> を紹介するテキストです。今すぐここからあらゆる種類の hacking tricks を無料で学びましょう！

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
