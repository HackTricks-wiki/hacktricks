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
Your local copy of HackTricks will be **[http://localhost:3337](http://localhost:3337)** で **利用可能** です after <5 minutes (本をビルドする必要があるので、気長にお待ちください)。

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) は、**HACK THE UNHACKABLE** をスローガンに掲げる優れたサイバーセキュリティ企業です。独自の研究を行い、自社の hacking tools を開発して、**pentesting**、Red teams、training などの、価値の高い複数のサイバーセキュリティサービスを**提供**しています。

彼らの **blog** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) で確認できます

**STM Cyber** は HackTricks のようなサイバーセキュリティのオープンソースプロジェクトも支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** は、ヨーロッパで **#1** の ethical hacking および **bug bounty platform** です。

**Bug bounty tip**: **sign up** して **Intigriti** を利用しましょう。ハッカーがハッカーのために作ったプレミアムな **bug bounty platform** です！今すぐ [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) に参加して、最大 **$100,000** の bounty を獲得し始めましょう！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、**engineering-first** で **hands-on lab approach** の **実践的な AI Security training** を提供します。私たちのコースは、security engineers、AppSec professionals、developers が **real AI/LLM-powered applications を構築し、壊し、保護する** ことを望む人向けに作られています。

**AI Security Certification** は、次のような実践スキルに重点を置いています:
- LLM および AI-powered applications の保護
- AI systems の Threat modeling
- Embeddings、vector databases、RAG security
- LLM attacks、abuse scenarios、実践的な防御
- Secure design patterns と deployment considerations

すべてのコースは **on-demand**、**lab-driven** で、単なる理論ではなく **real-world security tradeoffs** を中心に設計されています。

👉 AI Security コースの詳細:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は、**search engine results** に高速かつ簡単にアクセスできるリアルタイム API を提供します。検索エンジンのスクレイピング、プロキシの処理、captcha の解決、そしてあらゆるリッチな構造化データの解析を代行します。

SerpApi のいずれかのプランを契約すると、Google、Bing、Baidu、Yahoo、Yandex など、さまざまな検索エンジン向けの 50 以上の異なる API にアクセスできます。\
他のプロバイダと違い、**SerpApi は organic results だけを scrape するわけではありません**。SerpApi のレスポンスには、広告、インライン画像や動画、knowledge graphs、その他検索結果に含まれる要素や機能が一貫してすべて含まれます。

現在の SerpApi の顧客には **Apple、Shopify、GrubHub** が含まれます。\
詳細は [**blog**](https://serpapi.com/blog/)**、** または [**playground**](https://serpapi.com/playground)**.** で例を試してみてください。\
[**here**](https://serpapi.com/users/sign_up)**.** で **free account** を作成できます。

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** は、Black Hat、HITB、Zer0con での CVE writeups や talks を手がけた同じチームである現役研究者によって、offensive mobile および AI security を教えます。コースは self-paced で、実際の対象を使った labs を中心に構成され、hands-on certification が付属します。

カタログは 2 つのトラックで構成されています:

**Mobile Security** – app layer から下層までの iOS と Android: Ghidra と LLDB を使った reverse engineering、ARM64 exploitation、kernel internals と modern mitigations（PAC、MTE、SELinux）、jailbreak と rooting の仕組み。

**AI Security** – この分野を横断する 2 つの完全なコース。Practical AI Security では、LLMs、RAG pipelines、AI agents、MCP がどのように動作し、それらをどう攻撃し防御するかを扱います。Advanced AI Security は最先端に寄せた build-heavy の内容で、Garak と PyRIT を使った大規模な AI systems への red teaming、MCP servers の悪用、model backdoors の埋め込みと検出、Apple Silicon 上での fine-tuning attacks と defenses を扱います。

コースと certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** は、攻撃者より先に exploit 可能な vulnerabilities を見つけるための AI-powered security platform です。

**Code security tip**: sign up して NaxusAI を利用しましょう。開発者とセキュリティチーム向けに作られた smart vulnerability monitoring platform です！今すぐ参加して、AI を使って **production に届く前に real security risks を検知、検証、修正** しましょう！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) は **Amsterdam** を拠点とする professional cybersecurity company で、**modern** なアプローチによる **offensive-security services** を提供し、**世界中** の企業を最新のサイバーセキュリティ脅威から**保護**します。

WebSec は Amsterdam と Wyoming にオフィスを持つ国際的なセキュリティ企業です。**all-in-one security services** を提供しており、Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing など、すべてを行います。

WebSec のもう一つの素晴らしい点は、業界平均と異なり WebSec は自分たちのスキルに**非常に自信がある**ことです。そのため、**最高品質の結果を保証**し、サイトには "**If we can't hack it, You don't pay it!**" と記載されています。詳細は [**website**](https://websec.net/en/) と [**blog**](https://websec.net/blog/) をご覧ください！

上記に加えて、WebSec は HackTricks の **熱心な支援者** でもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**現場のために作られ、あなたのために作られた。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、業界の専門家によって構築・指導される効果的なサイバーセキュリティ training を開発・提供しています。彼らのプログラムは理論を超えて、カスタム環境を使い、実世界の脅威を反映した深い理解と実行可能なスキルをチームに身につけさせます。カスタム training の問い合わせは、[**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) からご連絡ください。

**彼らの training を際立たせるもの:**
* カスタム構築されたコンテンツと labs
* 一流の tools と platforms によって支えられている
* 実践者によって設計・指導される

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は、**Education** と **FinTech** 向けの専門的なサイバーセキュリティサービスを提供し、特に **penetration testing, cloud security assessments**、および **compliance readiness**（SOC 2、PCI-DSS、NIST）に注力しています。私たちのチームには **OSCP と CISSP 認定の専門家** が含まれており、各案件に深い技術的専門知識と業界標準の知見をもたらします。

私たちは自動スキャンを超えた、**manual, intelligence-driven testing** を高リスクな環境向けにカスタマイズして提供します。学生記録の保護から金融取引の防御まで、最も重要なものを守るお手伝いをします。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

最新のサイバーセキュリティ情報を確認し、把握し続けるには [**blog**](https://www.lasttowersolutions.com/blog) をご覧ください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE は、DevOps、DevSecOps、developers が Kubernetes clusters を効率的に管理、監視、保護できるようにします。AI-driven insights、高度な security framework、直感的な CloudMaps GUI を活用して、clusters を可視化し、状態を理解し、自信を持って対応できます。

さらに、K8Studio は **すべての主要な kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift など）と **互換性があります**。

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
