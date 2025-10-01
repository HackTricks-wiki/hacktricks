# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 徽标与动效设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

[**STM Cyber**](https://www.stmcyber.com) 是一家优秀的网络安全公司，其口号是 **HACK THE UNHACKABLE**。他们进行自主研究并开发自己的 hacking tools，以 **提供多种有价值的网络安全服务**，例如 pentesting、Red teams 和培训。

您可以在 [**https://blog.stmcyber.com**](https://blog.stmcyber.com) 查看他们的 **blog**

**STM Cyber** 也支持像 HackTricks 这样的开源网络安全项目 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) 是 **西班牙** 最重要的网络安全活动，也是 **欧洲** 最有影响力的会议之一。该大会以 **促进技术知识** 为使命，是各类技术和网络安全专业人士的热烈汇聚点。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是 **Europe's #1** 的 ethical hacking 和 **bug bounty platform.**

**Bug bounty tip**：**sign up** 加入 **Intigriti**，这是一个由黑客为黑客打造的高级 **bug bounty platform**！现在就访问 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达 **$100,000** 的赏金！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 可以轻松构建并 **自动化工作流**，由全球 **最先进** 的社区工具提供支持。

立即获取访问权限：

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和 bug bounty 猎人交流！

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶级黑客协作！

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** 使用我们 20+ 的自定义工具来绘制攻击面，发现可导致权限升级的安全问题，并使用 automated exploits 收集必要证据，将你的工作转化为有说服力的报告。

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速且易用的实时 API 来 **访问搜索引擎结果**。他们负责抓取搜索引擎、处理代理、解决验证码，并为你解析所有丰富的结构化数据。

订阅 SerpApi 的计划可访问超过 50 个不同的 API，用于抓取不同的搜索引擎，包括 Google、Bing、Baidu、Yahoo、Yandex 等。\
与其他提供商不同，**SerpApi 不只是抓取 organic results**。SerpApi 的响应始终包含所有广告、内联图片和视频、知识图谱以及搜索结果中存在的其他元素和功能。

当前 SerpApi 的客户包括 **Apple、Shopify 和 GrubHub**。\
更多信息请查看他们的 [**blog**](https://serpapi.com/blog/)**，** 或在他们的 [**playground**](https://serpapi.com/playground) 试用示例。\
你可以在 [**这里**](https://serpapi.com/users/sign_up)** 创建一个免费账户。**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

学习进行漏洞研究、penetration testing 和逆向工程以保护移动应用和设备所需的技术与技能。通过我们的按需课程掌握 iOS 与 Android 安全，并 **获取认证**：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家总部位于 **Amsterdam** 的专业网络安全公司，帮助 **全球** 企业抵御最新的网络安全威胁，提供带有 **现代化** 方法的 **offensive-security services**。

WebSec 是一家国际安全公司，在 Amsterdam 和 Wyoming 设有办公室。他们提供 **全方位安全服务**，涵盖 Pentesting、**Security** 审计、意识培训、钓鱼活动、代码审查、Exploit 开发、安全专家外包等诸多服务。

WebSec 的另一大特点是与行业平均水平不同，他们对自己的技能 **非常自信**，以至于在网站上承诺“**If we can't hack it, You don't pay it!**”。想了解更多请访问他们的 [**website**](https://websec.net/en/) 和 [**blog**](https://websec.net/blog/)！

此外，WebSec 也是 HackTricks 的 **坚定支持者。**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) 是一个 data breach (leak) 搜索引擎。\
我们提供类似 google 的随机字符串搜索，覆盖各种规模的数据 leak —— 不仅限于大型泄露 —— 来源于多个数据源。\
People search、AI search、organization search、API (OpenAPI) 访问、theHarvester integration，所有 pentester 需要的功能一应俱全。\
**HackTricks 持续是我们大家的优秀学习平台，我们很自豪能赞助它！**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 开发并提供由业界专家构建和领导的高效网络安全培训。他们的课程超越理论，通过反映真实世界威胁的定制环境，为团队提供深入理解和可操作技能。若需定制培训，请通过 [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) 与我们联系。

**他们培训的特点：**
* 定制内容与实验室
* 依托顶级工具与平台
* 由实务从业者设计与授课

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 为 **教育 (Education)** 和 **金融科技 (FinTech)** 机构提供专门的网络安全服务，重点包括 **penetration testing、cloud security assessments** 和 **compliance readiness**（如 SOC 2、PCI-DSS、NIST）。我们的团队包括持有 **OSCP 和 CISSP** 认证的专业人员，能为每次项目带来深厚的技术专长和行业视角。

我们超越自动化扫描，提供针对高风险环境的 **手动、情报驱动的测试**。从保护学生记录到保障金融交易，我们帮助组织守护最重要的资产。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

通过访问我们的 [**blog**](https://www.lasttowersolutions.com/blog) 保持对最新网络安全动态的了解。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE 帮助 DevOps、DevSecOps 和开发者高效地管理、监控和保护 Kubernetes 集群。利用我们的 AI 驱动洞察、高级安全框架和直观的 CloudMaps GUI，可视化集群、了解状态并自信地采取行动。

此外，K8Studio 与所有主流 kubernetes 发行版兼容 (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more)。

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## 许可证与免责声明

查看它们：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
