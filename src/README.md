# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 徽标与动态图由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

## 企业赞助商

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) 是一家优秀的网络安全公司，口号是 **HACK THE UNHACKABLE**。他们进行自主研究并开发自己的 hacking tools，以 **提供多种有价值的网络安全服务**，例如 pentesting、Red teams 和培训。

你可以查看他们的 **博客**： [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** 也支持像 HackTricks 这样的开源网络安全项目 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) 是西班牙最重要的网络安全活动，也是欧洲最重要的会议之一。以 **传播技术知识** 为使命，该大会是技术和网络安全各个领域专业人士的热门汇聚点。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是 **Europe's #1** 的 ethical hacking 和 **bug bounty platform。**

**Bug bounty tip**：**sign up** for **Intigriti**，一个由黑客为黑客创建的高级 **bug bounty platform**！今天加入我们 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达 **$100,000** 的赏金！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 可以轻松构建并 **自动化工作流**，由全球最 **先进** 的社区工具驱动。

立即获取访问权限：

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和 bug bounty 猎手交流！

- **Hacking Insights：** 参与深入探讨黑客刺激与挑战的内容
- **Real-Time Hack News：** 通过实时新闻与洞察，跟上快速变化的黑客世界
- **Latest Announcements：** 获取最新的 bug bounty 启动信息和重要平台更新

**加入我们的** [**Discord**](https://discord.com/invite/N3FrSbmwdy)，立即开始与顶级黑客协作！

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security 提供以 **工程为先、实操实验室为导向** 的 **实用 AI Security 培训**。我们的课程面向安全工程师、AppSec 专业人员和希望 **构建、攻破并保护真实 AI/LLM 驱动应用** 的开发者。

**AI Security Certification** 聚焦于实际技能，包括：
- Securing LLM and AI-powered applications
- Threat modeling for AI systems
- Embeddings, vector databases, and RAG security
- LLM attacks, abuse scenarios, and practical defenses
- Secure design patterns and deployment considerations

所有课程均为 **按需**、**以实验室为驱动**，并围绕 **真实世界的安全权衡** 设计，而不仅仅是理论。

👉 更多关于 AI Security 课程的详情：
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速且易用的实时 API，用于 **访问搜索引擎结果**。他们负责抓取搜索引擎、处理代理、解决验证码，并为你解析所有结构化的丰富数据。

订阅 SerpApi 的某个计划即可访问 50 多种不同的 API，用于抓取包括 Google、Bing、Baidu、Yahoo、Yandex 等在内的不同搜索引擎。\
与其他提供商不同，**SerpApi 不仅抓取自然搜索结果**。SerpApi 的响应始终包含所有广告、内联图片和视频、知识图谱以及搜索结果中存在的其他元素和功能。

当前 SerpApi 的客户包括 **Apple、Shopify 和 GrubHub**。\
更多信息请查看他们的 [**blog**](https://serpapi.com/blog/)**，**或在他们的 [**playground**](https://serpapi.com/playground) 试用示例。**\
你可以在 [**这里**](https://serpapi.com/users/sign_up) **创建一个免费账号**。**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

学习执行漏洞研究、penetration testing 和逆向工程以保护移动应用和设备所需的技术与技能。通过我们的按需课程掌握 iOS 和 Android 安全并 **获得认证**：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家总部位于 **Amsterdam** 的专业网络安全公司，帮助全球企业抵御最新的网络安全威胁，提供具有 **现代** 方法的 **offensive-security services**。

WebSec 是一家国际化的安全公司，在 Amsterdam 和 Wyoming 设有办公室。他们提供 **一体化安全服务**，涵盖 Pentesting、**Security** 审计、意识培训、钓鱼活动、代码审查、漏洞开发、外包安全专家等众多服务。

WebSec 的另一个优点是，与行业平均水平不同，WebSec 对自己的技能 **非常自信**，以至于他们在网站上保证“**If we can't hack it, You don't pay it!**”。欲了解更多信息，请查看他们的 [**website**](https://websec.net/en/) 和 [**blog**](https://websec.net/blog/)！

此外，WebSec 也是 HackTricks 的 **坚定支持者**。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 开发并提供由行业专家主导的高效网络安全培训。他们的项目超越理论，致力于通过反映真实世界威胁的自定义环境，为团队提供深刻的理解和可执行的技能。有关定制培训的询问，请通过 [**此处**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) 联系我们。

**他们培训的亮点：**
* 定制内容与实验室
* 依托顶级工具与平台
* 由实践者设计与授课

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 为 **教育** 和 **FinTech** 机构提供专业的网络安全服务，侧重于 **penetration testing、cloud security assessments** 以及 **合规准备**（SOC 2、PCI-DSS、NIST）。我们的团队拥有 **OSCP 和 CISSP 认证的专业人员**，为每次服务提供深厚的技术专长和行业标准见解。

我们不仅依赖自动化扫描，还提供针对高风险环境的 **人工、情报驱动的测试**。从保护学生记录到保障金融交易，我们帮助组织捍卫最重要的资产。

_“优质防御需要了解进攻，我们通过理解提供安全。”_

访问我们的 [**blog**](https://www.lasttowersolutions.com/blog)，获取最新的网络安全资讯。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE 赋能 DevOps、DevSecOps 和开发者，高效管理、监控和保护 Kubernetes 集群。利用我们的 AI 驱动洞察、高级安全框架和直观的 CloudMaps GUI 来可视化集群、了解其状态并自信地采取行动。

此外，K8Studio 与所有主流 kubernetes 发行版兼容（AWS, GCP, Azure, DO, Rancher, K3s, Openshift 等）。

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## 许可与免责声明

在以下位置查看：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
