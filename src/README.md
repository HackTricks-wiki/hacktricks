# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 标志与动态设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_ 制作。_

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
你的 HackTricks 本地副本将在不到 5 分钟后通过 [http://localhost:3337](http://localhost:3337) 提供（需要构建书籍，请耐心等待）。

或者，如果你安装了 Docker Compose，可以直接在仓库根目录运行以下命令：
```bash
docker compose up
```
This uses the bundled `docker-compose.yml` to serve your local checkout at [http://localhost:3337](http://localhost:3337) with live reload.

## HackTricks 合作伙伴

---

## HackTricks 朋友

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) 是一家优秀的 cybersecurity 公司，口号是 **HACK THE UNHACKABLE**。他们进行自主研究并开发自己的 hacking tools，以**提供多种有价值的 cybersecurity 服务**，例如 pentesting、Red teams 和培训。

你可以在 [**https://blog.stmcyber.com**](https://blog.stmcyber.com) 查看他们的**博客**。

**STM Cyber** 也支持 HackTricks 等 cybersecurity open source 项目 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是**欧洲第一**的 ethical hacking 和 **bug bounty platform**。

**Bug bounty 提示**：注册 **Intigriti**，这是一个**由 hackers 为 hackers 创建的高级 bug bounty platform**！立即通过 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) 加入我们，开始赚取最高达 **$100,000** 的奖金！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 通过**以工程为先、以实践实验室为核心的方法**，提供**实用的 AI Security 培训**。我们的课程面向 security engineers、AppSec 专业人员以及希望**构建、攻破并保护真实 AI/LLM-powered applications** 的开发者。

**AI Security Certification** 专注于现实世界技能，包括：
- 保护 LLM 和 AI-powered applications
- AI systems 的 threat modeling
- Embeddings、vector databases 和 RAG security
- LLM attacks、abuse scenarios 和实用防御
- Secure design patterns 和 deployment considerations

所有课程均为**按需学习**、**以实验室为驱动**，并围绕**现实世界中的 security tradeoffs** 设计，而不仅仅是理论。

👉 AI Security 课程详情：
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速、简单的实时 APIs，用于**访问搜索引擎结果**。他们负责 scrape 搜索引擎、处理 proxies、解决 captchas，并为你解析所有丰富的结构化数据。

订阅 SerpApi 的任一套餐，即可访问 50 多种不同的 APIs，用于 scrape 不同的搜索引擎，包括 Google、Bing、Baidu、Yahoo、Yandex 等。\
与其他提供商不同，**SerpApi 不仅 scrape organic results**。SerpApi 的响应始终包含搜索结果中的所有 ads、inline images 和 videos、knowledge graphs，以及其他元素和功能。

当前 SerpApi 客户包括 **Apple、Shopify 和 GrubHub**。\
如需了解更多信息，请查看他们的[**博客**](https://serpapi.com/blog/)**，**或在他们的[**playground**](https://serpapi.com/playground)**中尝试示例。**\
你可以[**在此**](https://serpapi.com/users/sign_up)**创建免费账户。**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** 提供 offensive mobile 和 AI security 培训，授课者是活跃的研究人员——也是 Black Hat、HITB 和 Zer0con 上 CVE writeups 与演讲背后的同一团队。课程支持自主学习，以真实目标上的实验室为核心，并配有实践型认证。

课程目录分为两条方向：

**Mobile Security** – 从 app layer 到更底层的 iOS 和 Android：使用 Ghidra 和 LLDB 进行 reverse engineering、ARM64 exploitation、kernel internals 和现代 mitigations（PAC、MTE、SELinux）、jailbreak 与 rooting 机制。

**AI Security** – 涵盖该领域的两门完整课程。Practical AI Security 介绍 LLMs、RAG pipelines、AI agents 和 MCP 的工作原理，以及如何攻击和防御它们。Advanced AI Security 专注于前沿实践：使用 Garak 和 PyRIT 对 AI systems 进行大规模 red teaming、利用 MCP servers、植入和检测 model backdoors，以及在 Apple Silicon 上进行 fine-tuning attacks 和 defenses。

课程与认证：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** 是一个 AI-powered security platform，可在攻击者之前发现可利用的 vulnerabilities。

**Code security 提示**：注册 NaxusAI，这是一个为 developers 和 security teams 打造的智能 vulnerability monitoring platform！立即加入我们，开始使用 AI **检测、验证并修复真实的 security risks，避免它们进入 production**！

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家总部位于**阿姆斯特丹**的专业 cybersecurity 公司，通过采用**现代化**方法提供**offensive-security services**，帮助**全球各地**的企业**防护**最新的 cybersecurity threats。

WebSec 是一家国际 security 公司，在阿姆斯特丹和 Wyoming 设有办公室。他们提供**一站式 security services**，也就是说几乎无所不包：Pentesting、**Security** Audits、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing 等。

WebSec 的另一个亮点是，与行业平均水平不同，他们对自己的能力**非常有信心**，甚至**保证提供最佳质量的结果**。其网站上写道：“**If we can't hack it, You don't pay it!**”。如需了解更多信息，请访问他们的[**网站**](https://websec.net/en/)和[**博客**](https://websec.net/blog/)！

除此之外，WebSec 还是 HackTricks 的**坚定支持者**。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**为实战而生，以你为中心。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 由行业专家开发并提供高效的 cybersecurity 培训。其课程不止于理论，通过反映现实世界 threats 的定制环境，为团队提供深入理解和可执行技能。如需定制培训，请[**联系我们**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)。

**其培训的优势：**
* 定制内容和实验室
* 由顶级工具和平台支持
* 由实践者设计并授课

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 为**教育**和**金融科技**机构提供专业的 cybersecurity services，重点包括**penetration testing、cloud security assessments** 和**合规准备**（SOC 2、PCI-DSS、NIST）。我们的团队包括**通过 OSCP 和 CISSP 认证的专业人员**，在每次服务中提供深厚的技术 expertise 和符合行业标准的洞察。

我们不止于 automated scans，而是针对高风险环境进行**手动、基于 intelligence 的 testing**。从保护学生记录到保障金融交易，我们帮助组织守护最重要的资产。

_“高质量的防御需要了解进攻，我们通过理解来提供 security。”_

如需了解 cybersecurity 的最新信息，请访问我们的[**博客**](https://www.lasttowersolutions.com/blog)。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE 帮助 DevOps、DevSecOps 和 developers 高效地管理、监控和保护 Kubernetes clusters。利用我们的 AI-driven insights、advanced security framework 和直观的 CloudMaps GUI，可视化 clusters、了解其状态并自信地采取行动。

此外，K8Studio **兼容所有主流的 kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift 等）。

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## 许可证与免责声明

请在此查看：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github 统计

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
