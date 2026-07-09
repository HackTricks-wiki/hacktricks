# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 标志与动效设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_。_

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
你的本地 HackTricks 副本将在 <5 分钟后 **可用，地址为 [http://localhost:3337](http://localhost:3337)**（它需要构建这本书，请耐心等待）。

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) 是一家很棒的 cybersecurity 公司，其口号是 **HACK THE UNHACKABLE**。他们开展自己的研究并开发自己的 hacking tools，以 **提供多项有价值的 cybersecurity services**，例如 pentesting、Red teams 和 training。

你可以在 [**https://blog.stmcyber.com**](https://blog.stmcyber.com) 查看他们的 **blog**

**STM Cyber** 也支持像 HackTricks 这样的 cybersecurity 开源项目 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是 **欧洲排名第一** 的 ethical hacking 和 **bug bounty platform。**

**Bug bounty tip**: **sign up** for **Intigriti**，一个由 hackers 为 hackers 打造的高级 **bug bounty platform**！今天就加入我们：[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取最高 **$100,000** 的 bounty！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 提供**实战型 AI Security training**，采用**以工程为先、动手实验室驱动**的方法。我们的课程面向 security engineers、AppSec professionals 和 developers，帮助他们**构建、攻破并保护真实的 AI/LLM 驱动应用**。

**AI Security Certification** 侧重真实世界技能，包括：
- 保护 LLM 和 AI-powered applications
- AI systems 的 Threat modeling
- Embeddings、vector databases 和 RAG security
- LLM attacks、滥用场景以及实用防御
- Secure design patterns 和部署考虑

所有课程都**按需提供**、**以实验室为中心**，并围绕**真实世界的安全取舍**设计，而不只是理论。

👉 AI Security 课程更多详情：
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速、易用的实时 API，用于**访问搜索引擎结果**。他们会抓取搜索引擎、处理 proxies、解决 captchas，并为你解析所有丰富的结构化数据。

订阅 SerpApi 的任一套餐即可访问 50 多种不同的 API，用于抓取不同的搜索引擎，包括 Google、Bing、Baidu、Yahoo、Yandex 等。\
与其他提供商不同，**SerpApi 不只是抓取 organic results**。SerpApi 的响应始终包含所有 ads、inline images 和 videos、knowledge graphs，以及搜索结果中存在的其他元素和功能。

SerpApi 的现有客户包括 **Apple、Shopify 和 GrubHub**。\
更多信息请查看他们的 [**blog**](https://serpapi.com/blog/)**，**或在他们的 [**playground**](https://serpapi.com/playground)**.** 中试用示例。\
你可以在 [**这里**](https://serpapi.com/users/sign_up) **创建免费账户**。**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** 由活跃研究员教授 offensive mobile 和 AI security——同一团队也撰写了 CVE writeups，并在 Black Hat、HITB 和 Zer0con 上做过演讲。课程可自定进度，以真实目标的 labs 为核心，并提供动手认证。

课程目录分为两条主线：

**Mobile Security** – 从应用层到下层的 iOS 和 Android：使用 Ghidra 和 LLDB 进行 reverse engineering、ARM64 exploitation、kernel internals 和现代缓解机制（PAC、MTE、SELinux）、jailbreak 和 rooting 机制。

**AI Security** – 两门完整课程覆盖该领域。Practical AI Security 讲解 LLMs、RAG pipelines、AI agents 和 MCP 的工作方式，以及如何攻击和防御它们。Advanced AI Security 则更偏前沿、强调实战构建：使用 Garak 和 PyRIT 大规模 red teaming AI systems、exploiting MCP servers、植入和检测 model backdoors，以及在 Apple Silicon 上进行 fine-tuning attacks and defenses。

课程与认证：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** 是一个由 AI 驱动的 security platform，可在攻击者之前发现可被利用的 vulnerabilities。

**Code security tip**: sign up for NaxusAI，一个面向 developers 和 security teams 构建的智能 vulnerability monitoring platform！今天就加入我们，开始使用 AI 来**在真实 security risks 到达 production 之前检测、验证并修复它们**！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家位于 **Amsterdam** 的专业 cybersecurity 公司，通过提供具有**现代**方法的 **offensive-security services**，帮助**保护**全球各地的企业免受最新 cybersecurity threats 影响。

WebSec 是一家国际 security company，在 Amsterdam 和 Wyoming 设有办公室。他们提供 **all-in-one security services**，也就是说他们什么都做；Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing 以及更多服务。

WebSec 另一个很酷的地方是，与行业平均水平不同，WebSec 对自己的能力**非常自信**，以至于他们**保证最佳质量结果**；他们的网站上写着：**“If we can't hack it, You don't pay it!”**。更多信息请查看他们的 [**website**](https://websec.net/en/) 和 [**blog**](https://websec.net/blog/)！

除了上述内容之外，WebSec 还是 HackTricks 的 **坚定支持者**。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 开发并提供由行业专家构建和主导的高效 cybersecurity training。它们的项目超越理论，通过定制环境反映真实威胁，为团队提供深度理解和可执行技能。有关定制培训咨询，请在 [**这里**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) 联系我们。

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

Last Tower Solutions 为 **Education** 和 **FinTech** 机构提供专业 cybersecurity services，重点是 **penetration testing、cloud security assessments** 和
**compliance readiness**（SOC 2、PCI-DSS、NIST）。我们的团队包括 **OSCP 和 CISSP
认证专业人士**，为每次合作带来深厚的技术专长和行业标准洞察。

我们超越自动化扫描，采用**手动、情报驱动的测试**，并针对
高风险环境量身定制。从保护学生记录到保护金融交易，
我们帮助组织守护最重要的东西。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

欢迎访问我们的 [**blog**](https://www.lasttowersolutions.com/blog)，及时了解 cybersecurity 的最新动态。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE 赋能 DevOps、DevSecOps 和 developers，高效管理、监控并保护 Kubernetes clusters。利用我们的 AI-driven insights、advanced security framework 和直观的 CloudMaps GUI，可视化你的 clusters，理解其状态，并自信地采取行动。

此外，K8Studio **兼容所有主流 kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift 等）。

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

请在以下位置查看：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
