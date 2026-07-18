# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricksのロゴとモーションデザイン by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
HackTricksのローカルコピーは、書籍のビルドに5分未満かかるため、しばらく待つと **[http://localhost:3337](http://localhost:3337)** で利用できるようになります。

または、Docker Composeがある場合は、リポジトリのルートから次のコマンドを実行するだけです。
```bash
docker compose up
```
これは同梱の `docker-compose.yml` を使用して、ローカル checkout を [http://localhost:3337](http://localhost:3337) で live reload 付きで提供します。

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) は、**HACK THE UNHACKABLE** をスローガンとする優れた cybersecurity company です。独自の research を行い、独自の hacking tools を開発して、pentesting、Red teams、training などの**有益な cybersecurity services を複数提供**しています。

**blog** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) で確認できます。

**STM Cyber** は HackTricks などの cybersecurity open source projects も支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** は、**Europe's #1** の ethical hacking および **bug bounty platform** です。

**Bug bounty tip**: **Intigriti** に **sign up** しましょう。これは、**hackers によって hackers のために作られた** premium **bug bounty platform** です！今すぐ [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) から参加して、最大 **$100,000** の bounties を獲得しましょう！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、**engineering-first** かつ hands-on lab approach による**実践的な AI Security training** を提供しています。security engineers、AppSec professionals、そして**実際の AI/LLM-powered applications を構築、攻撃、防御したい** developers 向けに、courses を設計しています。

**AI Security Certification** では、次のような real-world skills に重点を置いています。
- LLM および AI-powered applications の保護
- AI systems の threat modeling
- Embeddings、vector databases、RAG security
- LLM attacks、abuse scenarios、実践的な defenses
- Secure design patterns と deployment considerations

すべての courses は **on-demand**、**lab-driven** であり、理論だけでなく**現実の security tradeoffs** を中心に設計されています。

👉 AI Security course の詳細:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は、**search engine results にアクセス**するための、高速で使いやすい real-time APIs を提供しています。search engines の scraping、proxies の処理、captchas の解決、豊富な structured data の parsing をすべて代行します。

SerpApi のいずれかの plans に subscription すると、Google、Bing、Baidu、Yahoo、Yandex など、さまざまな search engines を scraping するための 50 種類以上の APIs にアクセスできます。\
他の providers と異なり、**SerpApi は organic results だけを scrape するわけではありません**。SerpApi の responses には、search results に表示されるすべての ads、inline images and videos、knowledge graphs、その他の elements と features が常に含まれます。

現在の SerpApi customers には **Apple、Shopify、GrubHub** などが含まれます。\
詳細については [**blog**](https://serpapi.com/blog/)** を確認するか、[**playground**](https://serpapi.com/playground)** で example を試してください。**\
[**こちら**](https://serpapi.com/users/sign_up) から **free account を作成**できます**。**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** は、現役 researchers が指導する offensive mobile および AI security をトレーニングします。講師陣は、Black Hat、HITB、Zer0con での CVE writeups や talks を担当している team と同じです。courses は self-paced で、実際の targets を使った labs を中心に構成され、hands-on certification も提供されます。

catalog は 2 つの tracks で構成されています。

**Mobile Security** – app layer から下位レイヤーまでの iOS と Android：Ghidra と LLDB による reverse engineering、ARM64 exploitation、kernel internals、最新の mitigations（PAC、MTE、SELinux）、jailbreak と rooting の仕組み。

**AI Security** – この分野を網羅する 2 つの full courses。Practical AI Security では、LLMs、RAG pipelines、AI agents、MCP の仕組みと、それらを攻撃・防御する方法を扱います。Advanced AI Security では、最先端の build-heavy な内容として、Garak と PyRIT による AI systems の大規模な red teaming、MCP servers の exploitation、model backdoors の planting と detection、Apple Silicon 上での fine-tuning attacks と defenses を扱います。

Courses と certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** は、attackers より先に exploitable vulnerabilities を発見するための AI-powered security platform です。

**Code security tip**: developers と security teams 向けに構築された smart vulnerability monitoring platform、NaxusAI に sign up しましょう！今すぐ参加して、**production に到達する前に real security risks を detecting、validating、fixing する**ために AI を使い始めましょう！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) は **Amsterdam** を拠点とする professional cybersecurity company で、**modern** な approach による **offensive-security services** を提供し、**世界中の** businesses を最新の cybersecurity threats から**保護**しています。

WebSec は Amsterdam と Wyoming に offices を持つ intenational security company です。**all-in-one security services** を提供しており、Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing など、あらゆるサービスを扱っています。

WebSec のもう 1 つの魅力は、industry average とは異なり、**自社の skills に非常に自信を持っている**ことです。その自信は、**最高品質の results を保証**するほどで、website には "**If we can't hack it, You don't pay it!**" と記載されています。詳細は [**website**](https://websec.net/en/) と [**blog**](https://websec.net/blog/) をご覧ください！

上記に加えて、WebSec は HackTricks の**熱心な supporter**でもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**現場のために。あなたを中心に。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、industry experts が開発・指導する effective cybersecurity training を提供しています。programs は theory にとどまらず、real-world threats を反映した custom environments を使用して、teams に深い understanding と actionable skills を身につけさせます。custom training に関するお問い合わせは [**こちら**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) からご連絡ください。

**training の特徴:**
* Custom-built content と labs
* top-tier tools と platforms による支援
* practitioners が設計・指導

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は、**Education** および **FinTech** institutions 向けに specialized cybersecurity services を提供しており、**penetration testing、cloud security assessments**、**compliance readiness**（SOC 2、PCI-DSS、NIST）に重点を置いています。team には **OSCP および CISSP
certified professionals** が所属し、すべての engagements に高度な technical expertise と industry-standard insight を提供します。

automated scans にとどまらず、high-stakes environments に合わせた **manual、intelligence-driven testing** を実施します。student records の保護から financial transactions の防御まで、organizations が最も重要なものを守れるよう支援します。

_「質の高い defense には offense の理解が必要です。私たちは理解を通じて security を提供します。」_

最新の cybersecurity 情報を入手するには、[**blog**](https://www.lasttowersolutions.com/blog) をご覧ください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE は、DevOps、DevSecOps、developers が Kubernetes clusters を効率的に manage、monitor、secure できるようにします。AI-driven insights、advanced security framework、直感的な CloudMaps GUI を活用して、clusters を可視化し、その state を理解し、自信を持って対応できます。

さらに、K8Studio は **主要なすべての kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift など）と**互換性があります**。

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

以下で確認できます。

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
