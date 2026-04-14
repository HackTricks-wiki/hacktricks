# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### 在本地运行 HackTricks
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

[**STM Cyber**](https://www.stmcyber.com) 是一家很棒的 cybersecurity 公司，其口号是 **HACK THE UNHACKABLE**。他们进行自己的 research 并开发自己的 hacking tools，以 **提供多项有价值的 cybersecurity services**，如 pentesting、Red teams 和 training。

你可以在 [**https://blog.stmcyber.com**](https://blog.stmcyber.com) 查看他们的 **blog**

**STM Cyber** 也支持像 HackTricks 这样的 cybersecurity open source projects :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是 **Europe's #1** ethical hacking 和 **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**，一个由 hackers 为 hackers 创建的高级 **bug bounty platform**！今天就加入我们：[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取最高 **$100,000** 的赏金！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与有经验的 hackers 和 bug bounty hunters 交流！

- **Hacking Insights:** 接触深入探讨 hacking 的刺激与挑战的内容
- **Real-Time Hack News:** 通过实时新闻和洞察，紧跟快速变化的 hacking 世界
- **Latest Announcements:** 及时了解最新上线的 bug bounties 和关键平台更新

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并从今天开始与顶级 hackers 协作！

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 提供 **practical AI Security training**，采用 **engineering-first、hands-on lab approach**。我们的课程面向 security engineers、AppSec professionals 和 developers，帮助他们 **build, break, and secure real AI/LLM-powered applications**。

**AI Security Certification** 重点关注真实世界技能，包括：
- Securing LLM and AI-powered applications
- AI systems 的 Threat modeling
- Embeddings、vector databases 和 RAG security
- LLM attacks、abuse scenarios 和 practical defenses
- Secure design patterns 和 deployment considerations

所有课程都是 **on-demand**、**lab-driven** 的，并围绕 **real-world security tradeoffs** 设计，而不仅仅是理论。

👉 AI Security 课程更多详情：
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速、简单的实时 APIs，用于 **access search engine results**。他们抓取 search engines，处理 proxies，解决 captchas，并为你解析所有 rich structured data。

订阅 SerpApi 任一方案即可访问 50 多种不同的 APIs，用于抓取不同的 search engines，包括 Google、Bing、Baidu、Yahoo、Yandex 等。\
与其他提供商不同，**SerpApi 不仅仅抓取 organic results**。SerpApi 的响应始终包含所有 ads、inline images 和 videos、knowledge graphs，以及 search results 中存在的其他元素和功能。

SerpApi 当前客户包括 **Apple、Shopify 和 GrubHub**。\
更多信息请查看他们的 [**blog**](https://serpapi.com/blog/)**,** 或在他们的 [**playground**](https://serpapi.com/playground)**.** 中试用示例。\
你可以在 [**这里**](https://serpapi.com/users/sign_up)**创建一个免费账户**。

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

学习进行 vulnerability research、penetration testing 和 reverse engineering 所需的技术与技能，以保护移动应用和设备。通过我们的 on-demand 课程 **Master iOS and Android security** 并 **get certified**：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家位于 **Amsterdam** 的专业 cybersecurity 公司，通过提供带有 **modern** 方法的 **offensive-security services**，帮助**保护**全球各地的企业免受最新 cybersecurity threats 影响。

WebSec 是一家国际 security 公司，在 Amsterdam 和 Wyoming 设有办公室。他们提供 **all-in-one security services**，也就是说他们什么都做；Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing 等等。

WebSec 另一个很酷的地方是，与行业平均水平不同，WebSec 对自己的技能 **very confident**，以至于他们 **guarantee the best quality results**，他们的网站上写着 "**If we can't hack it, You don't pay it!**"。更多信息请查看他们的 [**website**](https://websec.net/en/) 和 [**blog**](https://websec.net/blog/)！

除了以上内容，WebSec 也是 HackTricks 的 **committed supporter**。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) develops and delivers effective cybersecurity training built and led by
industry experts. Their programs go beyond theory to equip teams with deep
understanding and actionable skills, using custom environments that reflect real-world
threats. For custom training inquiries, reach out to us [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

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

Last Tower Solutions 为 **Education** 和 **FinTech** 机构提供专业 cybersecurity services，重点是 **penetration testing, cloud security assessments**，以及
**compliance readiness**（SOC 2、PCI-DSS、NIST）。我们的团队包括 **OSCP 和 CISSP
certified professionals**，为每次服务带来深厚的 technical expertise 和 industry-standard insight。

我们不仅仅依赖 automated scans，而是提供面向
高风险环境定制的 **manual, intelligence-driven testing**。从保护 student records 到保护 financial transactions，
我们帮助组织守护最重要的资产。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

通过访问我们的 [**blog**](https://www.lasttowersolutions.com/blog) 获取 cybersecurity 最新动态并保持信息更新。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE 赋能 DevOps、DevSecOps 和 developers 高效地管理、监控并保护 Kubernetes clusters。借助我们的 AI-driven insights、advanced security framework 和直观的 CloudMaps GUI，可视化你的 clusters、理解其状态，并自信地采取行动。

此外，K8Studio **兼容所有主流 kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift 等）。

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

在以下位置查看：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
