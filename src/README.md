# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 标志和动态设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_ 制作。_

### 在本地运行 HackTricks

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
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

等待不到 5 分钟后，你本地的 HackTricks 副本就会**在 [http://localhost:3337](http://localhost:3337) 上可用**（需要构建书籍，请耐心等待）。

或者，如果你安装了 Docker Compose，只需在仓库根目录运行以下命令：

```bash
docker compose up
```

这会使用捆绑的 `docker-compose.yml`，通过 [http://localhost:3337](http://localhost:3337) 提供主机上当前检出的分支，并启用实时重载。使用 Compose 时要切换语言，请在启动服务前检出所需的语言分支。

## HackTricks 合作伙伴

---

## HackTricks 伙伴

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber 提供渗透测试、安全审计、漏洞利用与研究、工具以及安全意识服务。其网站介绍，团队成员包括渗透测试人员、程序员和安全研究人员，拥有十多年的经验。<sup>[[1]](#references)</sup>

你可以在他们的 **博客** 中了解更多：[**https://blog.stmcyber.com**](https://blog.stmcyber.com)。

**STM Cyber** 也支持 HackTricks 等网络安全开源项目 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti 是一家众包安全服务提供商，通过全球研究人员社区提供漏洞赏金和渗透测试服务。其平台将持续性的漏洞赏金覆盖与按需 PTaaS 及托管漏洞披露计划相结合。<sup>[[2]](#references)</sup>

**漏洞赏金提示**：通过 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) 加入 Intigriti，探索其漏洞赏金计划。

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 为安全工程师、AppSec 专业人员和开发者提供自定进度、动手实践的 AI 安全培训。其 AI Security Certification 涵盖 LLM 和 agent 基础知识、RAG 和向量数据库、威胁建模、prompt injection 和 MCP 攻击，以及防御架构。<sup>[[3]](#references)</sup>

👉 查看 AI Security 课程详情：  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 为 Google 和其他搜索引擎提供 API，返回结构化 SERP 数据，支持位置相关结果、Maps、Shopping 和 Knowledge Graph 结果等功能。<sup>[[4]](#references)</sup>

如需了解更多信息，请访问他们的[**博客**](https://serpapi.com/blog/)、在他们的[**演练场**](https://serpapi.com/playground)中试用示例，或[**创建免费账户**](https://serpapi.com/users/sign_up)。

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** 提供自定进度的移动安全和 AI 安全课程。课程涵盖使用 Ghidra、Frida 和 LLDB 等工具进行移动应用审计与逆向，以及 AI/LLM 攻防实验。<sup>[[5]](#references)[[6]](#references)</sup>

浏览 [8kSec Academy 课程目录](https://academy.8ksec.io/)。

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** 是一个 AI 驱动的攻防安全平台，可执行完整的外部攻击面扫描、移动应用审计、Web 黑盒测试和源代码审查。其 agents 会验证可利用的发现，并提供可追溯的证据、概念验证漏洞利用和可执行的修复建议。<sup>[[7]](#references)</sup>

**安全审计提示**：使用 Naxus 对外部资产、移动应用、Web 应用和源代码进行端到端的自主审计。

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec 提供渗透测试、安全订阅、人员配置和漏洞评估服务。其网站称，该公司业务遍及国际市场，涵盖攻防安全以及治理、风险与合规工作。<sup>[[8]](#references)</sup>

如需了解更多信息，请访问他们的[**网站**](https://websec.net/en/)或[**博客**](https://websec.net/blog/)。

除了上述服务之外，WebSec 还是 HackTricks 的**坚定支持者**。

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**为实战而打造，以你为中心。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 提供由专家主导的网络安全培训，课程内容和实验环境均为定制打造，并以真实基础设施为基础。其培训项目根据组织需求量身定制，覆盖从评估到实施的各个阶段。<sup>[[9]](#references)</sup> 如需咨询定制培训，请[**点击这里**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)。

**他们的培训特色：**
* 定制打造的课程内容和实验环境
* 由一流工具和平台提供支持
* 由一线从业者设计并授课

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 专注于为**教育**和**金融科技**领域提供网络安全咨询服务，包括云评估、内部和外部渗透测试、漏洞评估以及合规支持。<sup>[[10]](#references)</sup>

访问我们的[**博客**](https://www.lasttowersolutions.com/blog)，了解网络安全领域的最新动态。

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio 是一款桌面 Kubernetes IDE，提供 CloudMaps 可视化、多集群导航、RBAC、Helm、日志、YAML 和终端视图。供应商称，该工具通过 kubeconfig 连接，无需安装 agents，并支持 macOS、Windows、Linux 和隔离网络集群。<sup>[[11]](#references)</sup>

---

## 许可证与免责声明

请参阅下方 References 中的 HackTricks Values & FAQ 条目。

## Github 统计数据

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security（AI 安全认证 – Modern Security）](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [实用 AI 安全：攻击、防御与应用](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks 推荐链接](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec 赞助视频](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets 课程](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks 价值观与常见问题](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
