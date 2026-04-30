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
Your local copy of HackTricks will be **http://localhost:3337** で **5分以内** に利用可能になります（book をビルドする必要があるため、少し待ってください）。

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) は、スローガンが **HACK THE UNHACKABLE** の優れた cybersecurity 企業です。彼らは独自に research を行い、独自の hacking tools を開発して、**pentesting、Red teams、training などの複数の価値ある cybersecurity services を提供**しています。

彼らの **blog** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) で確認できます。

**STM Cyber** は HackTricks のような cybersecurity open source projects も支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** は、**Europe's #1** の ethical hacking および **bug bounty platform.**

**Bug bounty tip**: **sign up** して **Intigriti** を使いましょう。これは hackers によって、hackers のために作られたプレミアムな **bug bounty platform** です！今すぐ [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) に参加して、最大 **$100,000** の bounty を獲得し始めましょう！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

経験豊富な hackers や bug bounty hunters と交流するために、[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加しましょう！

- **Hacking Insights:** hacking のスリルと課題を掘り下げる content を楽しめます
- **Real-Time Hack News:** リアルタイムの news と insights で、スピードの速い hacking world の最新情報を把握できます
- **Latest Announcements:** 新しく始まる bug bounties や重要な platform updates の最新情報を入手できます

[**Discord**](https://discord.com/invite/N3FrSbmwdy) で私たちに参加して、今すぐトップ hackers との collaboration を始めましょう！

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、**engineering-first の hands-on lab approach** による **実践的な AI Security training** を提供します。私たちの courses は、**build, break, and secure real AI/LLM-powered applications** を行いたい security engineers、AppSec professionals、developers 向けに作られています。

**AI Security Certification** は、次のような実世界の skills に重点を置いています:
- LLM と AI-powered applications の保護
- AI systems の threat modeling
- Embeddings、vector databases、RAG security
- LLM attacks、abuse scenarios、そして実践的な defenses
- Secure design patterns と deployment considerations

すべての courses は **on-demand**、**lab-driven** であり、単なる理論ではなく **real-world security tradeoffs** に基づいて設計されています。

👉 AI Security course の詳細:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は、**search engine results にアクセスする**ための高速で簡単な real-time APIs を提供します。彼らは search engines を scrape し、proxies を扱い、captchas を解き、すべての rich structured data を解析してくれます。

SerpApi のいずれかの plan を購読すると、Google、Bing、Baidu、Yahoo、Yandex などを含む、さまざまな search engines を scrape するための 50 以上の異なる APIs にアクセスできます。\
他の providers とは異なり、**SerpApi は organic results だけを scrape するわけではありません**。SerpApi の responses には、ads、inline images and videos、knowledge graphs、そして search results に存在する他の elements や features が一貫してすべて含まれています。

現在の SerpApi customers には **Apple、Shopify、GrubHub** が含まれます。\
詳細は [**blog**](https://serpapi.com/blog/)**,** を確認するか、[**playground**](https://serpapi.com/playground)**.** で example を試してください。\
[**ここ**](https://serpapi.com/users/sign_up)**.** で無料 account を **create** できます。

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

mobile applications と devices を保護するために、vulnerability research、penetration testing、reverse engineering を行うのに必要な technologies と skills を学びましょう。オンデマンド courses を通じて **iOS と Android security を習得**し、**certified** を取得できます:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** は、attackers より先に exploitable vulnerabilities を見つけるための AI-powered security platform です。

**Code security tip**: NaxusAI に sign up しましょう。これは developers と security teams のために構築された、smart vulnerability monitoring platform です！今すぐ参加して、AI を使って **production に到達する前に real security risks を検出、検証、修正** しましょう！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) は **Amsterdam** を拠点とする professional cybersecurity company で、**modern** な approach の **offensive-security services** を提供し、**世界中** の businesses を最新の cybersecurity threats から **protecting** します。

WebSec は Amsterdam と Wyoming に offices を持つ intenational security company です。彼らは **all-in-one security services** を提供しており、Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing など、すべてを行います。

WebSec のもう一つの素晴らしい点は、業界平均と異なり、WebSec は自社の skills に **非常に自信を持っている** ことです。そのため、**最高品質の結果を保証** し、website には "**If we can't hack it, You don't pay it!**" と記載されています。詳細は [**website**](https://websec.net/en/) と [**blog**](https://websec.net/blog/) をご覧ください！

上記に加えて、WebSec は **HackTricks の熱心な supporter** でもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、業界 experts によって作成され、指導される効果的な cybersecurity training を開発・提供します。彼らの programs は theory を超え、custom environments を使って、real-world threats を反映した深い理解と実践的な skills をチームに身につけさせます。custom training の問い合わせは、[**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) からご連絡ください。

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

Last Tower Solutions は、**Education** と **FinTech** の institutions 向けに特化した cybersecurity services を提供し、**penetration testing、cloud security assessments**、および **compliance readiness**（SOC 2、PCI-DSS、NIST）に重点を置いています。私たちの team には **OSCP と CISSP 認定 professionals** が含まれており、すべての engagement に深い technical expertise と industry-standard の insight をもたらします。

私たちは、高リスクな environments に合わせた **manual、intelligence-driven testing** で automated scans を超えた対応をします。student records の保護から financial transactions の保護まで、最も重要なものを守るために organizations を支援します。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

最新の cybersecurity 情報を blog で確認し、最新情報を入手してください。[**blog**](https://www.lasttowersolutions.com/blog)。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE は、DevOps、DevSecOps、developers が Kubernetes clusters を効率的に manage、monitor、secure できるようにします。AI-driven insights、advanced security framework、直感的な CloudMaps GUI を活用して clusters を可視化し、その state を理解し、自信を持って行動できます。

さらに、K8Studio は **all major kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift など）と **compatible** です。

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

以下で確認してください:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
