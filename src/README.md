# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 标志与动态设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_完成。_

### 本地运行 HackTricks
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
Your local copy of HackTricks will be **可在 [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) 是一家很棒的 cybersecurity 公司，口号是 **HACK THE UNHACKABLE**。他们进行自己的 research 并开发自己的 hacking tools，以 **offer several valuable cybersecurity services**，例如 pentesting、Red teams 和 training。

你可以在 [**https://blog.stmcyber.com**](https://blog.stmcyber.com) 查看他们的 **blog**

**STM Cyber** 也支持像 HackTricks 这样的 cybersecurity open source projects :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是 **Europe's #1** ethical hacking 和 **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**，一个由 hackers 为 hackers 创建的 premium **bug bounty platform**！今天就加入我们 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取最高 **$100,000** 的 bounty！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server，与有经验的 hackers 和 bug bounty hunters 交流！

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** 通过实时 news 和 insights 及时了解快节奏的 hacking world
- **Latest Announcements:** 及时获取最新发布的 bug bounties 和关键 platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并立即开始与顶尖 hackers 协作！

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 提供 **practical AI Security training**，采用 **engineering-first, hands-on lab approach**。我们的 courses 专为 security engineers、AppSec professionals 和 developers 打造，帮助他们 **build, break, and secure real AI/LLM-powered applications**。

**AI Security Certification** 专注于真实世界技能，包括：
- Securing LLM and AI-powered applications
- AI systems 的 threat modeling
- Embeddings、vector databases 和 RAG security
- LLM attacks、abuse scenarios 和 practical defenses
- Secure design patterns 和 deployment considerations

所有 courses 都是 **on-demand**、**lab-driven**，并围绕 **real-world security tradeoffs** 设计，而不只是 theory。

👉 AI Security course 的更多详情：
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速、易用的实时 APIs，用于 **access search engine results**。他们负责抓取 search engines、处理 proxies、解决 captchas，并为你解析所有丰富的结构化 data。

订阅 SerpApi 任一 plan 即可访问超过 50 种不同的 APIs，用于抓取不同的 search engines，包括 Google、Bing、Baidu、Yahoo、Yandex 等。\
与其他 providers 不同，**SerpApi 不只是抓取 organic results**。SerpApi 的 responses 一贯包含所有 ads、inline images 和 videos、knowledge graphs，以及 search results 中存在的其他 elements 和 features。

SerpApi 当前客户包括 **Apple、Shopify 和 GrubHub**。\
更多信息请查看他们的 [**blog**](https://serpapi.com/blog/)**，**或者在他们的 [**playground**](https://serpapi.com/playground) 里试用一个 example**。**\
你可以在 [**here**](https://serpapi.com/users/sign_up) **创建一个免费 account**。**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** 由活跃的 researchers 教授 offensive mobile 和 AI security——同一团队还负责 Black Hat、HITB 和 Zer0con 上的 CVE writeups 和 talks。Courses 采用自定进度学习，围绕真实 targets 上的 labs 构建，并提供 hands-on certification。

课程目录分为两个方向：

**Mobile Security** – 从 app layer 到下层的 iOS 和 Android：使用 Ghidra 和 LLDB 进行 reverse engineering、ARM64 exploitation、kernel internals 和现代 mitigations（PAC、MTE、SELinux）、jailbreak 和 rooting 机制。

**AI Security** – 两门完整 courses 覆盖整个领域。Practical AI Security 讲解 LLMs、RAG pipelines、AI agents 和 MCP 如何工作，以及如何攻击和防御它们。Advanced AI Security 则更偏 build-heavy，聚焦前沿：使用 Garak 和 PyRIT 在大规模下 red teaming AI systems、exploiting MCP servers、植入和检测 model backdoors，以及在 Apple Silicon 上进行 fine-tuning attacks 和 defenses。

Courses 和 certifications：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** 是一个 AI-powered security platform，用于在 attackers 之前发现可被利用的 vulnerabilities。

**Code security tip**: sign up for NaxusAI，一个面向 developers 和 security teams 的智能 vulnerability monitoring platform！今天就加入我们，开始使用 AI 在 **detecting, validating, and fixing real security risks before they reach production** 方面提供帮助！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家位于 **Amsterdam** 的专业 cybersecurity company，通过提供带有 **modern** 方法的 **offensive-security services**，帮助 **protecting** 全世界的 businesses 免受最新 cybersecurity threats 影响。

WebSec 是一家总部位于 Amsterdam 和 Wyoming 的国际 security company。他们提供 **all-in-one security services**，这意味着他们什么都做；Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing 以及更多服务。

WebSec 的另一个亮点是，和行业平均水平不同，WebSec 对自己的能力 **very confident**，甚至 **guarantee the best quality results**，他们的网站上写着 "**If we can't hack it, You don't pay it!**"。更多信息请查看他们的 [**website**](https://websec.net/en/) 和 [**blog**](https://websec.net/blog/)！

除此之外，WebSec 也是 HackTricks 的 **committed supporter**。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 开发并交付有效的 cybersecurity training，由行业 experts 构建并主导。他们的 programs 超越 theory，通过定制 environments 为 teams 配备深度理解和可执行 skills，以反映真实世界 threats。有关 custom training inquiries，请在 [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) 联系我们。

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

Last Tower Solutions 为 **Education** 和 **FinTech** 机构提供 specialized cybersecurity services，重点是 **penetration testing, cloud security assessments** 和
**compliance readiness**（SOC 2、PCI-DSS、NIST）。我们的 team 包括 **OSCP 和 CISSP
certified professionals**，为每次 engagement 带来深厚的 technical expertise 和 industry-standard insight。

我们不仅依赖 automated scans，还会针对高风险 environments 进行 **manual, intelligence-driven testing**。从保护 student records 到 safeguarding financial transactions，
我们帮助 organizations defend 最重要的资产。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

欢迎访问我们的 [**blog**](https://www.lasttowersolutions.com/blog)，及时了解最新 cybersecurity 动态。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE 让 DevOps、DevSecOps 和 developers 能够高效地 manage、monitor 和 secure Kubernetes clusters。借助我们的 AI-driven insights、advanced security framework 和直观的 CloudMaps GUI，可将你的 clusters 可视化、理解其状态，并充满信心地采取行动。

此外，K8Studio **compatible with all major kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift 等）。

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
