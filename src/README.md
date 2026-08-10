# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_HackTricksのロゴとモーションデザイン：_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_。_

### HackTricksをローカルで実行する
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
HackTricks のローカルコピーは、5 分未満で **[http://localhost:3337](http://localhost:3337)** から利用できるようになります（book のビルドが必要なため、しばらくお待ちください）。

また、Docker Compose がある場合は、リポジトリのルートから次のコマンドを実行するだけです：
```bash
docker compose up
```
これは同梱の `docker-compose.yml` を使用して、ホスト上で現在 checkout されている branch を live reload 付きで [http://localhost:3337](http://localhost:3337) に提供します。Compose の使用中に言語を変更するには、service を起動する前に目的の言語の branch を checkout してください。

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber は、penetration testing、security audits、exploit および research work、tools、security-awareness services を提供しています。同社のサイトによると、10年以上の経験を持つ penetration tester、programmer、security researcher で構成された team です。<sup>[[1]](#references)</sup>

同社の **blog** は [**https://blog.stmcyber.com**](https://blog.stmcyber.com) で確認できます。

**STM Cyber** は HackTricks のような cybersecurity の open source projects も支援しています :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti は、世界中の researcher community を通じて bug bounty と penetration-testing services を提供する crowdsourced security provider です。同社の platform は、継続的な bug bounty coverage と、on-demand PTaaS および managed vulnerability disclosure programs を組み合わせています。<sup>[[2]](#references)</sup>

**Bug bounty tip**: [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) から Intigriti に参加し、その bug bounty programs を確認してください。

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security は、security engineer、AppSec professional、developer 向けに、self-paced の hands-on AI security training を提供しています。同社の AI Security Certification では、LLM と agent の fundamentals、RAG と vector database、threat modeling、prompt-injection と MCP attacks、defensive architecture を扱います。<sup>[[3]](#references)</sup>

👉 AI Security course の詳細:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** は Google やその他の search engine 向けの API を提供し、location-aware results、Maps、Shopping、Knowledge Graph results などの機能を備えた構造化 SERP data を返します。<sup>[[4]](#references)</sup>

詳細については、同社の [**blog**](https://serpapi.com/blog/) を確認するか、[**playground**](https://serpapi.com/playground) で example を試すか、[**create a free account**](https://serpapi.com/users/sign_up) を利用してください。

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** は、self-paced の mobile および AI-security courses を提供しています。その catalog では、Ghidra、Frida、LLDB などの tools を使用した mobile application auditing と reversing に加え、AI/LLM attack and defense labs も扱っています。<sup>[[5]](#references)[[6]](#references)</sup>

[8kSec Academy course catalog](https://academy.8ksec.io/) をご覧ください。

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** は offensive-AI platform を提供しています。code と infrastructure を mapping し、static および dynamic agents を使用して、proof-of-concept evidence と remediation guidance を伴う exploit 可能な weakness を発見・検証します。<sup>[[7]](#references)</sup>

**Code security tip**: code と infrastructure に特化した vulnerability discovery のために Naxus を確認してください。

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec は、penetration testing、security subscriptions、staffing、vulnerability-assessment services を提供しています。同社のサイトによると、international に事業を展開し、offensive security、defensive security、governance、risk、compliance work をカバーしています。<sup>[[8]](#references)</sup>

詳細については、[**website**](https://websec.net/en/) または [**blog**](https://websec.net/blog/) をご覧ください。

上記に加えて、WebSec は **HackTricks の熱心な supporter** でもあります。

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**現場のために。あなたを中心に。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) は、実際の infrastructure に基づいて custom-built content と labs を提供する、expert-led cybersecurity training provider です。同社の programs は組織のニーズに合わせて設計され、assessment から implementation までをカバーします。<sup>[[9]](#references)</sup> custom training に関する問い合わせは [**こちら**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) からご連絡ください。

**training の特徴:**
* Custom-built content と labs
* トップクラスの tools と platforms による support
* Practitioner が設計・指導

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions は **Education** と **FinTech** 向けの cybersecurity consulting に注力しており、cloud assessments、internal および external penetration tests、vulnerability assessments、compliance support などを提供しています。<sup>[[10]](#references)</sup>

[**blog**](https://www.lasttowersolutions.com/blog) にアクセスして、cybersecurity の最新情報を確認してください。

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio は、CloudMaps visualization、multi-cluster navigation、RBAC、Helm、logs、YAML、terminal views を備えた desktop Kubernetes IDE です。vendor によると、agent を install せず kubeconfig 経由で接続でき、macOS、Windows、Linux、air-gapped clusters をサポートしています。<sup>[[11]](#references)</sup>

---

## License & Disclaimer

以下の References にある HackTricks Values & FAQ entry をご覧ください。

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Practical AI Security: Attacks, Defenses, and Applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks referral](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec sponsorship video](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets courses](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
