# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_HackTricks 徽标与动效设计：_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
你的本地副本 HackTricks 将在 <5 分钟后通过 **[http://localhost:3337](http://localhost:3337)** 可用（需要构建书籍，请耐心等待）。

## 企业赞助商

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) 是一家出色的网络安全公司，口号是 **HACK THE UNHACKABLE**。他们开展自主研究并开发自己的 hacking tools，以提供多种有价值的网络安全服务，例如 pentesting、Red teams 和培训。

你可以在 [**https://blog.stmcyber.com**](https://blog.stmcyber.com) 查看他们的 **博客**

**STM Cyber** 也支持像 HackTricks 这样的网络安全开源项目 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) 是 **Spain** 最相关的网络安全活动，也是 **Europe** 最重要的活动之一。其使命是 **促进技术知识的传播**，这个大会是技术和网络安全各领域专业人士的活跃聚集点。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是 **Europe's #1** 的道德黑客和 **bug bounty platform.**

Bug bounty 小贴士：**sign up** for **Intigriti**，这是一个由黑客为黑客创建的高级 **bug bounty 平台**！今天就加入我们 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达 **$100,000** 的赏金！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 可以轻松构建并自动化由世界上最**先进**的社区工具驱动的工作流程。

立即获取访问：

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与有经验的黑客和 bug bounty 猎人交流！

- **Hacking Insights:** 参与深入探讨黑客刺激与挑战的内容
- **Real-Time Hack News:** 通过实时新闻和见解随时了解快速变化的黑客世界
- **Latest Announcements:** 关注最新发布的 bug bounty 和重要平台更新

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶级黑客协作吧！

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - 必备的 penetration testing 工具包

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**从黑客的角度审视你的 web 应用、网络与 cloud**

**发现并报告具有真实业务影响的关键可利用漏洞。** 使用我们 20+ 自定义工具来绘制攻击面，发现可导致特权升级的安全问题，并使用自动化 exploits 收集关键证据，将你的辛勤工作转化为有说服力的报告。

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速且简便的实时 API 来 **访问搜索引擎结果**。他们抓取搜索引擎、处理代理、解决验证码，并为你解析所有丰富的结构化数据。

订阅 SerpApi 的任一计划可访问 50 多个不同的 API，用于抓取不同的搜索引擎，包括 Google、Bing、Baidu、Yahoo、Yandex 等。\
与其他提供商不同，**SerpApi 不仅抓取自然搜索结果**。SerpApi 的响应始终包含所有广告、内嵌图片和视频、知识图谱以及搜索结果中存在的其他元素和功能。

SerpApi 目前的客户包括 **Apple, Shopify, and GrubHub**。\
欲了解更多信息，请查看他们的 [**blog**](https://serpapi.com/blog)**，**或在他们的 [**playground**](https://serpapi.com/playground) 中尝试示例。\
你可以在 [**here**](https://serpapi.com/users/sign_up) 创建一个 **免费账号**。

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

学习执行漏洞研究、penetration testing 和逆向工程以保护移动应用和设备所需的技术与技能。通过我们的按需课程 **掌握 iOS 与 Android 安全** 并 **获取认证**：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家总部位于 **Amsterdam** 的专业网络安全公司，通过采用 **现代** 方法提供 **offensive-security services**，帮助全球各地的企业抵御最新的网络安全威胁。

WebSec 是一家国际安全公司，在 Amsterdam 和 Wyoming 设有办事处。他们提供 **一体化的安全服务**，也就是说涵盖所有内容；Pentesting、**Security** 审计、Awareness Trainings、Phishing Campagnes、Code Review、Exploit Development、Security Experts Outsourcing 等等。

WebSec 的另一个很酷的地方是，与行业平均水平不同，WebSec 对自己的技能 **非常有信心**，以至于他们 **保证最佳质量的结果**，其网站上写着“**If we can't hack it, You don't pay it!**”。欲了解更多信息，请查看他们的 [**website**](https://websec.net/en/) 和 [**blog**](https://websec.net/blog/)！

此外，WebSec 还是 HackTricks 的**坚定支持者**。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 开发并提供由行业专家构建与主导的高效网络安全培训。他们的课程超越理论，使用反映真实威胁的定制环境，旨在为团队提供深入的理解和可落地的技能。有关定制培训的咨询，请通过 [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) 联系我们。

**他们培训的优势：**
* 定制内容与实验室
* 由顶级工具和平台支持
* 由实务专家设计和授课

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 为 **Education** 和 **FinTech** 机构提供专业的网络安全服务，重点关注 **penetration testing、cloud security assessments** 和 **合规准备**（SOC 2、PCI-DSS、NIST）。我们的团队包含 **OSCP and CISSP certified professionals**，为每次项目带来深厚的技术专业知识和行业标准洞见。

我们超越自动化扫描，提供针对高风险环境量身定制的 **手工、情报驱动测试**。从保护学生记录到保障金融交易，我们帮助组织保卫最重要的资产。

_“A quality defense requires knowing the offense, we provide security through understanding.”_

访问我们的 [**blog**](https://www.lasttowersolutions.com/blog) 以获取最新的网络安全资讯。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE 使 DevOps、DevSecOps 和开发者能够高效地管理、监控和保护 Kubernetes 集群。利用我们的 AI 驱动洞察、先进的安全框架和直观的 CloudMaps GUI 可视化集群、了解集群状态并自信地采取行动。

此外，K8Studio **兼容所有主流 kubernetes distributions**（AWS、GCP、Azure、DO、Rancher、K3s、Openshift 等）。

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## 许可与免责声明

查看它们：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github 统计

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
