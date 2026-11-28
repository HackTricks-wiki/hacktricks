# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 标志与动态设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_ 制作。_

### 本地运行 HackTricks

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

你的 HackTricks 本地副本将在不到 5 分钟后**可通过 [http://localhost:3337](http://localhost:3337) 访问**（需要构建书籍，请耐心等待）。

或者，如果你有 Docker Compose，只需在仓库根目录运行以下命令：

```bash
docker compose up
```

这会使用捆绑的 `docker-compose.yml`，通过 [http://localhost:3337](http://localhost:3337) 提供主机上当前检出的分支，并启用实时重新加载。使用 Compose 时要切换语言，请在启动服务前检出所需的语言分支。

## HackTricks 合作伙伴

---

## HackTricks 伙伴

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber 提供渗透测试、安全审计、exploit 和研究工作、工具以及安全意识服务。其网站介绍了一支由渗透测试人员、程序员和安全研究人员组成的团队，拥有十多年的经验。<sup>[[1]](#references)</sup>

你可以访问他们的[**博客**](https://blog.stmcyber.com)。

**STM Cyber** 也支持 HackTricks 等网络安全开源项目 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti 是一家 crowdsourced security 服务提供商，通过全球研究人员社区提供 bug bounty 和渗透测试服务。其平台将持续性的 bug bounty 覆盖与按需 PTaaS 和托管漏洞披露计划相结合。<sup>[[2]](#references)</sup>

**Bug bounty 提示**：通过 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) 加入 Intigriti，探索其 bug bounty 计划。

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 为安全工程师、AppSec 专业人员和开发者提供自主学习、实操型 AI 安全培训。其 AI Security Certification 涵盖 LLM 和 agent 基础、RAG 和向量数据库、威胁建模、prompt injection 和 MCP 攻击，以及防御架构。<sup>[[3]](#references)</sup>

👉 了解更多 AI Security 课程详情：  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 为 Google 和其他搜索引擎提供 API，返回结构化的 SERP 数据，并支持基于位置的结果、Maps、Shopping 和 Knowledge Graph 结果等功能。<sup>[[4]](#references)</sup>

如需了解更多信息，请查看他们的[**博客**](https://serpapi.com/blog/)、在他们的[**playground**](https://serpapi.com/playground)中尝试示例，或[**创建免费账户**](https://serpapi.com/users/sign_up)。

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** 提供自主学习的移动安全和 AI 安全课程。其课程目录涵盖使用 Ghidra、Frida 和 LLDB 等工具进行移动应用审计和逆向分析，以及 AI/LLM 攻防实验。<sup>[[5]](#references)[[6]](#references)</sup>

浏览 [8kSec Academy 课程目录](https://academy.8ksec.io/)。

---

### [NaxusAI – Autonomous Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** 是一个 AI 驱动的 offensive security 平台，可用于全面扫描外部攻击面、审计移动应用、进行 Web black-box 测试和源代码审查。其 agents 会验证可利用的发现，并提供可追溯的证据、proof-of-concept exploits 和可执行的修复建议。<sup>[[7]](#references)</sup>

**安全审计提示**：使用 Naxus 对外部资产、移动应用、Web 应用和源代码进行端到端自主审计。

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec 提供渗透测试、安全订阅、人员配置和漏洞评估服务。其网站称，公司在国际范围内运营，业务涵盖 offensive security、defensive security 以及治理、风险和合规工作。<sup>[[8]](#references)</sup>

如需了解更多信息，请访问他们的[**网站**](https://websec.net/en/)或[**博客**](https://websec.net/blog/)。

除此之外，WebSec 还是 **HackTricks 的坚定支持者。**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**为实战而造，以你为中心。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 提供由专家主导的网络安全培训，课程内容和实验环境均为定制，并基于真实基础设施构建。其项目根据组织需求量身定制，涵盖从评估到实施的各个阶段。<sup>[[9]](#references)</sup> 如需咨询定制培训，请[**点击此处**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)。

**他们的培训特色：**
* 定制的课程内容和实验环境
* 依托一流的工具和平台
* 由实战从业者设计并授课

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 专注于为**教育**和**金融科技**行业提供网络安全咨询服务，包括云评估、内部和外部渗透测试、漏洞评估以及合规支持。<sup>[[10]](#references)</sup>

访问我们的[**博客**](https://www.lasttowersolutions.com/blog)，了解网络安全领域的最新动态。

---

### [Beaki — Food that fits you](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki** 是一款个性化食品扫描器、卡路里计数器和营养追踪器。扫描条形码和超市货架，拍摄或描述餐食和餐厅菜单，即可获取根据你的目标、饮食、过敏情况和健康档案生成的可解释评分。Beaki 还可以追踪卡路里和宏量营养素，并创建包含购物清单的个性化膳食计划。<sup>[[11]](#references)</sup>

在 Android 或 iPhone 上[**免费下载 Beaki**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks)。

---

## 许可与免责声明

请参阅下方 References 中的 HackTricks Values & FAQ 条目。

## Github 统计数据

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI 安全认证 – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [实用 AI 安全：攻击、防御与应用](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Intigriti HackTricks 推荐链接](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec 赞助视频](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets 课程](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)

{{#include banners/hacktricks-training.md}}
