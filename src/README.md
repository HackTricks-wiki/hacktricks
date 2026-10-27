# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 标志与动态设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_创作。_

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

不到 5 分钟后，你的本地 HackTricks 副本将可通过 [http://localhost:3337](http://localhost:3337) 访问（需要构建手册，请耐心等待）。

或者，如果你有 Docker Compose，只需在仓库根目录运行以下命令：

```bash
docker compose up
```

这会使用随附的 `docker-compose.yml`，通过 [http://localhost:3337](http://localhost:3337) 提供主机上当前检出的分支，并支持实时重载。使用 Compose 时要切换语言，请在启动服务前检出所需语言分支。

## HackTricks 合作伙伴

---

## HackTricks 之友

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber 提供 penetration testing、安全审计、exploit 与研究工作、工具以及安全意识服务。其网站介绍了一支由 penetration tester、程序员和安全研究人员组成的团队，拥有十多年的经验。<sup>[[1]](#references)</sup>

你可以访问他们的 **博客**：[**https://blog.stmcyber.com**](https://blog.stmcyber.com)。

**STM Cyber** 也支持 HackTricks 等网络安全开源项目 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti 是一家众包安全服务提供商，通过全球研究人员社区提供 bug bounty 和 penetration-testing 服务。其平台结合了持续的 bug bounty 覆盖、按需 PTaaS 和托管漏洞披露计划。<sup>[[2]](#references)</sup>

**Bug bounty 提示**：通过 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) 加入 Intigriti 并探索其 bug bounty 项目。

---

### [Modern Security – AI 与应用安全培训平台](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 为安全工程师、AppSec 专业人员和开发者提供自主进度的实操 AI 安全培训。其 AI Security Certification 涵盖 LLM 和 agent 基础知识、RAG 与向量数据库、威胁建模、prompt-injection 和 MCP 攻击，以及防御架构。<sup>[[3]](#references)</sup>

👉 了解更多 AI Security 课程详情：  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 为 Google 和其他搜索引擎提供 API，返回结构化 SERP 数据，并支持位置相关结果、Maps、Shopping 和 Knowledge Graph 结果等功能。<sup>[[4]](#references)</sup>

如需了解更多信息，请访问他们的[**博客**](https://serpapi.com/blog/)，在他们的[**在线试用平台**](https://serpapi.com/playground)尝试示例，或[**创建免费账户**](https://serpapi.com/users/sign_up)。

---

### [8kSec Academy – 深入的移动与 AI 安全课程](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** 提供自主进度的移动和 AI 安全课程。课程目录涵盖使用 Ghidra、Frida 和 LLDB 等工具进行移动应用审计与逆向分析，以及 AI/LLM 攻击和防御实验。<sup>[[5]](#references)[[6]](#references)</sup>

浏览 [8kSec Academy 课程目录](https://academy.8ksec.io/)。

---

### [NaxusAI – AI 驱动的安全扫描器](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** 推出一款 offensive-AI 平台，可映射代码和基础设施，然后利用静态和动态 agent 查找并验证可利用的弱点，同时提供概念验证证据和修复指导。<sup>[[7]](#references)</sup>

**代码安全提示**：探索 Naxus，发现代码和基础设施中的漏洞。

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec 提供 penetration testing、安全订阅、人员配置和漏洞评估服务。其网站称，该公司在全球开展业务，涵盖 offensive security、defensive security，以及治理、风险和合规工作。<sup>[[8]](#references)</sup>

如需了解更多信息，请访问他们的[**网站**](https://websec.net/en/)或[**博客**](https://websec.net/blog/)。

除了上述服务，WebSec 还是 **HackTricks 的坚定支持者**。

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**为实战而生，以你为中心。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 提供由专家主导的网络安全培训，课程内容和实验环境均根据真实基础设施定制。其项目根据组织需求量身打造，涵盖从评估到实施的各个阶段。<sup>[[9]](#references)</sup> 如需咨询定制培训，请[**点击这里**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)。

**他们的培训特色：**
* 定制的课程内容和实验环境
* 由顶级工具和平台提供支持
* 由从业者设计并授课

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 专注于为**教育**和**金融科技**领域提供网络安全咨询服务，包括云评估、内部和外部 penetration tests、漏洞评估以及合规支持。<sup>[[10]](#references)</sup>

访问我们的[**博客**](https://www.lasttowersolutions.com/blog)，了解网络安全领域的最新动态。

---

### [K8Studio - 更智能的 Kubernetes 管理 GUI。](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio 是一款桌面 Kubernetes IDE，具备 CloudMaps 可视化、多集群导航、RBAC、Helm、日志、YAML 和终端视图。供应商称，它通过 kubeconfig 连接，无需安装 agent，并支持 macOS、Windows、Linux 和隔离网络集群。<sup>[[11]](#references)</sup>

---

## 许可证与免责声明

请参阅下方 References 中的 HackTricks Values & FAQ 条目。

## Github 统计数据

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
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
