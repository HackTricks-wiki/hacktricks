# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 标志与动效设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks 将在 <5 分钟后 **可用，访问 [http://localhost:3337](http://localhost:3337)**（需要构建书籍，请耐心等待）。

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) 是一家很棒的 cybersecurity 公司，其口号是 **HACK THE UNHACKABLE**。他们进行自己的研究并开发自己的 hacking tools，以 **提供多种有价值的 cybersecurity 服务**，例如 pentesting、Red teams 和 training。

你可以在 [**https://blog.stmcyber.com**](https://blog.stmcyber.com) 查看他们的 **blog**

**STM Cyber** 也支持 HackTricks 这类 cybersecurity 开源项目 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是 **欧洲第一** 的 ethical hacking 和 **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**，一个由 hackers 为 hackers 创建的高级 **bug bounty platform**！今天就加入我们 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取最高可达 **$100,000** 的赏金！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与有经验的 hackers 和 bug bounty hunters 交流！

- **Hacking Insights:** 参与深入探讨 hacking 的刺激与挑战的内容
- **Real-Time Hack News:** 通过实时新闻和洞察，紧跟快速变化的 hacking 世界
- **Latest Announcements:** 了解最新上线的 bug bounties 和关键平台更新

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) ，今天就开始与顶尖 hackers 协作！

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 提供 **实用的 AI Security training**，采用 **engineering-first、hands-on lab** 方法。我们的课程面向 security engineers、AppSec professionals 和 developers，帮助他们 **构建、破坏并保护真实的 AI/LLM 驱动应用**。

**AI Security Certification** 重点关注真实世界技能，包括：
- 保护 LLM 和 AI 驱动的应用
- AI 系统的 Threat modeling
- Embeddings、vector databases 和 RAG security
- LLM attacks、abuse scenarios 和实用防御
- Secure design patterns 和 deployment 考量

所有课程均为 **on-demand**、**lab-driven**，并围绕 **真实世界的 security tradeoffs** 设计，而不只是理论。

👉 AI Security 课程更多详情：
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速、易用的实时 APIs，用于 **访问搜索引擎结果**。他们抓取搜索引擎、处理 proxies、解决 captchas，并为你解析所有丰富的结构化数据。

订阅 SerpApi 任一方案即可使用 50 多种不同的 APIs 来抓取不同的搜索引擎，包括 Google、Bing、Baidu、Yahoo、Yandex 等。\
与其他提供商不同，**SerpApi 不只是抓取 organic results**。SerpApi 的响应始终包含所有 ads、inline images 和 videos、knowledge graphs，以及搜索结果中存在的其他元素和特性。

SerpApi 的现有客户包括 **Apple、Shopify 和 GrubHub**。\
更多信息请查看他们的 [**blog**](https://serpapi.com/blog/)**,** 或在他们的 [**playground**](https://serpapi.com/playground)**.** 中试用示例。\
你可以在 [**这里**](https://serpapi.com/users/sign_up)**.** 创建一个免费账号。

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

学习进行 vulnerability research、penetration testing 和 reverse engineering 所需的技术与技能，以保护 mobile applications 和 devices。通过我们的 on-demand courses **掌握 iOS 和 Android security** 并 **获得认证**：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** 是一个由 AI 驱动的 security platform，用于在 attackers 之前发现可被利用的 vulnerabilities。

**Code security tip**: sign up for NaxusAI，一个为 developers 和 security teams 构建的智能 vulnerability monitoring platform！今天就加入我们，开始使用 AI 在 **detecting、validating 和 fixing real security risks before they reach production**！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家位于 **Amsterdam** 的专业 cybersecurity 公司，通过提供 **offensive-security services** 并采用 **modern** 的方法，帮助 **保护** **全世界** 的企业免受最新 cybersecurity threats 影响。

WebSec 是一家在 Amsterdam 和 Wyoming 设有办公室的国际 security company。他们提供 **all-in-one security services**，也就是说他们什么都做；Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing 以及更多服务。

WebSec 的另一个很酷之处在于，不同于行业平均水平，WebSec 对自己的技能 **非常有信心**，甚至 **保证最佳质量结果**，其网站上写着 "**If we can't hack it, You don't pay it!**"。更多信息请查看他们的 [**website**](https://websec.net/en/) 和 [**blog**](https://websec.net/blog/)！

除了上述内容，WebSec 也是 HackTricks 的 **坚定支持者**。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**为实战而生。围绕你而建。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 开发并提供由行业专家构建和主导的高效 cybersecurity training。他们的项目超越理论，通过使用反映真实世界 threats 的自定义环境，为团队提供深入理解和可执行技能。有关定制培训咨询，请在 [**这里**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) 联系我们。

**他们的 training 与众不同之处：**
* 定制内容和 labs
* 由顶级 tools 和 platforms 支持
* 由从业者设计并授课

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 为 **Education** 和 **FinTech**
机构提供专业的 cybersecurity services，重点包括 **penetration testing、cloud security assessments**，以及
**compliance readiness**（SOC 2、PCI-DSS、NIST）。我们的团队包括 **OSCP 和 CISSP
认证专业人士**，为每一次项目带来深厚的技术专业知识和行业标准洞察。

我们不止于自动化扫描，还提供面向高风险环境定制的 **manual、intelligence-driven testing**。从保护学生记录到保障金融交易，
我们帮助组织守护最重要的东西。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

欢迎访问我们的 [**blog**](https://www.lasttowersolutions.com/blog)，及时了解最新 cybersecurity 动态。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE 让 DevOps、DevSecOps 和 developers 能够高效地管理、监控和保护 Kubernetes clusters。利用我们的 AI 驱动洞察、先进 security framework 和直观的 CloudMaps GUI，可视化你的 clusters，理解其状态，并自信地采取行动。

此外，K8Studio **兼容所有主要 kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift 等）。

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
