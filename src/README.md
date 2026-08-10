# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 标志与动态设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_完成。_

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
在不到 5 分钟后，你本地的 HackTricks 副本将可通过 [http://localhost:3337](http://localhost:3337) 访问（需要构建书籍，请耐心等待）。

或者，如果你有 Docker Compose，只需在仓库根目录运行以下命令：
```bash
docker compose up
```
此配置使用捆绑的 `docker-compose.yml`，通过 [http://localhost:3337](http://localhost:3337) 提供主机上当前检出的分支，并支持实时重新加载。使用 Compose 时，如需切换语言，请在启动服务前检出所需的语言分支。

## HackTricks 合作伙伴

---

## HackTricks 朋友

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber 提供 penetration testing、安全审计、exploit 与研究工作、工具及安全意识服务。其网站介绍称，该团队由 penetration testers、程序员和安全研究人员组成，拥有十多年的经验。<sup>[[1]](#references)</sup>

你可以在此查看他们的 **blog**：[**https://blog.stmcyber.com**](https://blog.stmcyber.com)。

**STM Cyber** 也支持 HackTricks 等网络安全开源项目 :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti 是一家众包安全服务提供商，通过全球研究人员社区提供 bug bounty 和 penetration-testing 服务。其平台将持续性的 bug bounty 覆盖与按需 PTaaS 及托管漏洞披露计划相结合。<sup>[[2]](#references)</sup>

**Bug bounty 提示**：通过 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) 加入 Intigriti，并探索其 bug bounty 计划。

---

### [Modern Security – AI 与应用安全培训平台](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 为 security engineers、AppSec 专业人员和开发者提供自主进度、实践型 AI security 培训。其 AI Security Certification 涵盖 LLM 和 agent 基础、RAG 与向量数据库、威胁建模、prompt-injection 和 MCP attacks，以及防御性架构。<sup>[[3]](#references)</sup>

👉 查看 AI Security 课程详情：
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 为 Google 及其他搜索引擎提供 API，返回结构化 SERP 数据，并支持位置感知结果、Maps、Shopping 和 Knowledge Graph 结果等功能。<sup>[[4]](#references)</sup>

如需了解更多信息，请查看他们的 [**blog**](https://serpapi.com/blog/)、在其 [**playground**](https://serpapi.com/playground) 中尝试示例，或[**创建免费账户**](https://serpapi.com/users/sign_up)。

---

### [8kSec Academy – 深入的移动与 AI Security 课程](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** 提供自主进度的移动和 AI-security 课程。其课程目录涵盖使用 Ghidra、Frida 和 LLDB 等工具进行移动应用审计与逆向，以及 AI/LLM attack 和 defense labs。<sup>[[5]](#references)[[6]](#references)</sup>

浏览 [8kSec Academy 课程目录](https://academy.8ksec.io/)。

---

### [NaxusAI – AI 驱动的 Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** 推出 offensive-AI 平台，可映射代码和基础设施，然后使用 static 和 dynamic agents 查找并验证可利用的弱点，同时提供 proof-of-concept 证据和修复指导。<sup>[[7]](#references)</sup>

**代码安全提示**：试用 Naxus，探索其面向代码和基础设施的漏洞发现功能。

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec 提供 penetration testing、安全订阅、人员配置和漏洞评估服务。其网站称，该公司在国际范围内运营，业务涵盖 offensive security、defensive security 以及 governance、risk 和 compliance 工作。<sup>[[8]](#references)</sup>

如需了解更多信息，请访问他们的 [**website**](https://websec.net/en/) 或 [**blog**](https://websec.net/blog/)。

除上述内容外，WebSec 还是 HackTricks 的**坚定支持者**。

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**为实战而建，以你为核心。**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 提供由专家授课的网络安全培训，内容和 labs 均为定制开发，并以真实基础设施为基础。其课程根据组织需求定制，覆盖从评估到实施的完整流程。<sup>[[9]](#references)</sup> 如需定制培训，请[**点击此处**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks)联系。

**其培训的特色：**
* 定制开发的内容和 labs
* 由顶级工具和平台支持
* 由实战从业者设计并授课

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 专注于为 **Education** 和 **FinTech** 提供网络安全咨询，包括 cloud assessments、内部和外部 penetration tests、漏洞评估及合规支持。<sup>[[10]](#references)</sup>

访问我们的 [**blog**](https://www.lasttowersolutions.com/blog)，了解网络安全领域的最新资讯和动态。

---

### [K8Studio - 管理 Kubernetes 的更智能 GUI。](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio 是一款桌面 Kubernetes IDE，提供 CloudMaps 可视化、多集群导航、RBAC、Helm、日志、YAML 和终端视图。供应商称，它通过 kubeconfig 连接而无需安装 agents，并支持 macOS、Windows、Linux 和 air-gapped clusters。<sup>[[11]](#references)</sup>

---

## 许可证与免责声明

请参阅下方 References 中的 HackTricks Values & FAQ 条目。

## Github 统计

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI Security Certification – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [实践型 AI Security：攻击、防御与应用](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti HackTricks 推荐链接](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec 赞助视频](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets 课程](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
