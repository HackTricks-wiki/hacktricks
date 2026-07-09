# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks のロゴ & モーションデザイン by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks will be **[http://localhost:3337](http://localhost:3337)** で **利用可能** になります <5分後（書籍のビルドが必要です。気長にお待ちください）。

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) は、**HACK THE UNHACKABLE** をスローガンに掲げる優れた cybersecurity 企業です。独自の調査を行い、自社の hacking ツールを開発して、pentesting、Red teams、training などの**複数の価値ある cybersecurity サービス**を提供しています。

彼らの **blog** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) で確認できます。

**STM Cyber** は HackTricks のような cybersecurity の open source プロジェクトも支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** は、**Europe's #1** の ethical hacking および **bug bounty platform** です。

**Bug bounty tip**: **sign up** して **Intigriti** を使いましょう。これは hackers によって、hackers のために作られたプレミアムな **bug bounty platform** です！今すぐ [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) に参加して、最大 **$100,000** の bounty を獲得し始めましょう！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

経験豊富な hackers と bug bounty hunters と交流するために、[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加しましょう！

- **Hacking Insights:** hacking の興奮や課題を掘り下げるコンテンツに触れられます
- **Real-Time Hack News:** リアルタイムのニュースとインサイトで、変化の速い hacking の世界を追いかけられます
- **Latest Announcements:** 新しく始まる bug bounties や重要な platform 更新情報を把握できます

[**Discord**](https://discord.com/invite/N3FrSbmwdy) で私たちに参加し、今日からトップ hackers と協力し始めましょう！

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、**engineering-first, hands-on lab approach** に基づく **実践的な AI Security training** を提供します。私たちのコースは、security engineers、AppSec professionals、developers が **実際の AI/LLM-powered applications を build, break, and secure** したい場合のために作られています。

**AI Security Certification** は、次のような実践的スキルに重点を置いています:
- LLM and AI-powered applications の保護
- AI systems の threat modeling
- Embeddings、vector databases、RAG security
- LLM attacks、abuse scenarios、実践的な defenses
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

**SerpApi** は、**search engine results** に**高速で簡単に**アクセスできるリアルタイム API を提供します。検索エンジンのスクレイピング、proxy の処理、captcha の解決、そして豊富な構造化データの解析まで行ってくれます。

SerpApi のいずれかのプランを購読すると、Google、Bing、Baidu、Yahoo、Yandex などを含む、さまざまな検索エンジンをスクレイピングするための 50 以上の異なる API にアクセスできます。\
他の provider とは異なり、**SerpApi は単に organic results をスクレイピングするだけではありません**。SerpApi のレスポンスには、広告、インライン画像や videos、knowledge graphs、その他 search results に含まれる要素や機能が一貫してすべて含まれます。

現在の SerpApi の顧客には **Apple, Shopify, and GrubHub** が含まれます。\
詳細は [**blog**](https://serpapi.com/blog/)**,** を確認するか、[**playground**](https://serpapi.com/playground)**.** で例を試してください。\
[**here**](https://serpapi.com/users/sign_up)**.** から **free account** を作成できます。

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** は、現役の researchers による指導で offensive mobile および AI security を教えています。CVE の writeups や Black Hat、HITB、Zer0con での talks を手がけたのと同じチームです。コースは self-paced で、実際の targets を使った labs を中心に構成され、hands-on certification が付属します。

カリキュラムは 2 つの track で構成されています:

**Mobile Security** – app layer から下層までの iOS と Android: Ghidra と LLDB を使った reverse engineering、ARM64 exploitation、kernel internals と modern mitigations（PAC、MTE、SELinux）、jailbreak と rooting の仕組み。

**AI Security** – この分野全体をカバーする 2 つの完全なコース。Practical AI Security では、LLMs、RAG pipelines、AI agents、MCP がどのように動作し、それらをどう attack し防御するかを学びます。Advanced AI Security では最先端をより構築寄りに掘り下げ、Garak と PyRIT を使った大規模な AI systems の red teaming、MCP servers の exploitation、model backdoors の仕込みと検知、Apple Silicon 上での fine-tuning attacks と defenses を扱います。

コースと certifications:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** は、攻撃者に先んじて exploit 可能な vulnerabilities を見つけるための AI-powered security platform です。

**Code security tip**: NaxusAI に sign up しましょう。これは developers と security teams のために作られた、賢い vulnerability monitoring platform です！今日参加して、AI を使って **production に到達する前に real security risks を検出、検証、修正** し始めましょう！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) は **Amsterdam** に拠点を置く professional cybersecurity company で、**modern** なアプローチによる **offensive-security services** を提供し、**世界中** の企業を最新の cybersecurity threats から**保護**することを支援しています。

WebSec は Amsterdam と Wyoming にオフィスを持つ国際的な security company です。**all-in-one security services** を提供しており、Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing など、すべてを行います。

WebSec のもう 1 つのすごい点は、業界平均とは異なり、WebSec が自分たちのスキルに**非常に自信を持っている**ことであり、その結果として**最高品質の結果を保証する**とまで言っていることです。website には "**If we can't hack it, You don't pay it!**" とあります。詳細は [**website**](https://websec.net/en/) と [**blog**](https://websec.net/blog/) をご覧ください！

上記に加えて、WebSec は HackTricks の **熱心な supporter** でもあります。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**現場のために作られた。あなたのために作られた。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、業界 experts によって構築・主導される効果的な cybersecurity training を開発・提供しています。彼らのプログラムは theory を超えて、実際の threats を反映した custom environments を使い、チームに深い理解と実践可能な skills を身につけさせます。custom training に関する問い合わせは、[**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) からご連絡ください。

**彼らの training を際立たせているもの:**
* Custom-built content と labs
* Top-tier tools と platforms に支えられている
* Practitioners によって設計・指導されている

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は、**Education** と **FinTech** 機関向けに特化した cybersecurity services を提供しており、**penetration testing, cloud security assessments**、および **compliance readiness**（SOC 2、PCI-DSS、NIST）に重点を置いています。私たちのチームには **OSCP と CISSP
certified professionals** が含まれており、すべての engagement に深い technical expertise と industry-standard な知見をもたらします。

私たちは自動スキャンを超えて、重要性の高い環境に合わせた **manual, intelligence-driven testing** を行います。学生記録の保護から financial transactions の保護まで、組織が最も大切なものを守るのを支援します。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

最新の cybersecurity 情報を把握し続けるには、[**blog**](https://www.lasttowersolutions.com/blog) をご覧ください。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE は、DevOps、DevSecOps、developers が Kubernetes clusters を効率的に管理、監視、保護することを可能にします。AI-driven insights、advanced security framework、直感的な CloudMaps GUI を活用して、clusters を可視化し、その状態を理解し、自信を持って対応できます。

さらに、K8Studio は **all major kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift など）と互換性があります。

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

以下をご確認ください:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
