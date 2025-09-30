# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 徽标和动效设计由_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
你的本地 HackTricks 副本将在 <5 分钟后 **可在 [http://localhost:3337](http://localhost:3337) 访问**（需要构建书籍，请耐心等待）。

## 企业赞助商

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) 是一家优秀的网络安全公司，口号为 **HACK THE UNHACKABLE**。他们开展自己的研究并开发自己的黑客工具，以便 **提供多种有价值的网络安全服务**，例如 pentesting、Red teams 和培训。

你可以在 [**https://blog.stmcyber.com**](https://blog.stmcyber.com) 查看他们的 **博客**

**STM Cyber** 也支持像 HackTricks 这样的网络安全开源项目 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) 是 **西班牙** 最重要的网络安全活动，也是 **欧洲** 最重要的会议之一。怀着 **推广技术知识的使命**，这个大会是技术与网络安全各领域专业人士的重要汇聚点。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是 **Europe's #1** 的 ethical hacking 与 **bug bounty platform.**

**Bug bounty tip**：**sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 可以轻松构建并 **自动化工作流**，由世界上**最先进**的社区工具驱动。

立即获取访问权限：

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和 bug bounty 猎人交流！

- **Hacking Insights:** 参与深入探讨黑客世界刺激与挑战的内容
- **Real-Time Hack News:** 通过实时新闻和洞见及时了解快速变化的黑客世界
- **Latest Announcements:** 获取最新启动的 bug bounty 和重要平台更新

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 并开始与顶尖黑客协作！

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**从黑客视角审视你的 Web 应用、网络与云**

**发现并报告具有真实业务影响的关键可利用漏洞。** 使用我们 20+ 的自定义工具绘制攻击面，发现可导致权限升级的安全问题，并使用自动化利用收集关键证据，将你的工作成果转化为有说服力的报告。

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速且简便的实时 API 以 **访问搜索引擎结果**。他们负责抓取搜索引擎、处理代理、解决验证码，并为你解析所有丰富的结构化数据。

订阅 SerpApi 的任一计划可访问 50 多种不同的 API，用于抓取不同的搜索引擎，包括 Google、Bing、Baidu、Yahoo、Yandex 等。\
与其他提供商不同，**SerpApi 不仅抓取自然结果**。SerpApi 的响应始终包含所有广告、内联图片与视频、知识图谱以及搜索结果中存在的其他元素与特性。

当前 SerpApi 的客户包括 **Apple, Shopify, and GrubHub**。\
欲了解更多信息请查看他们的 [**blog**](https://serpapi.com/blog/)**,** 或在他们的 [**playground**](https://serpapi.com/playground)** 中尝试示例。**\
你可以在 [**here**](https://serpapi.com/users/sign_up)** 创建一个免费帐户**。

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

学习进行漏洞研究、渗透测试和逆向工程以保护移动应用与设备所需的技术与技能。通过我们的点播课程 **掌握 iOS 与 Android 安全** 并 **获得认证**：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家位于 **Amsterdam** 的专业网络安全公司，帮助全球企业应对最新的网络安全威胁，提供带有**现代**方法的 **offensive-security services**。

WebSec 是一家国际性安全公司，在 Amsterdam 和 Wyoming 设有办事处。他们提供 **一体化安全服务**，涵盖渗透测试、**Security** 审计、意识培训、网络钓鱼活动、代码审计、漏洞利用开发、安全专家外包等诸多服务。

WebSec 的另一大特点是，与行业平均水平不同，WebSec 对自己的技能 **非常有信心**，以至于他们在网站上承诺“**If we can't hack it, You don't pay it!**”。更多信息请查看他们的 [**website**](https://websec.net/en/) 和 [**blog**](https://websec.net/blog/)！

除了上述内容外，WebSec 也是 HackTricks 的 **坚定支持者**。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) 是一个数据泄露 (leak) 搜索引擎。\
我们提供类似 Google 的随机字符串搜索，覆盖各类大小数据泄露 — 不仅限于大型泄露 — 来自多个来源的数据。\
人名搜索、AI 搜索、组织搜索、API (OpenAPI) 访问、theHarvester 集成，包含所有 pentester 所需的功能。\
**HackTricks 继续为我们所有人提供很棒的学习平台，我们很自豪能赞助它！**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) 开发并提供由业内专家构建和领导的高效网络安全培训。他们的课程超越理论，使用反映真实世界威胁的定制环境，赋能团队掌握深入的理解与可付诸实践的技能。若需定制培训，请通过 [**here**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) 与我们联系。

**使其培训与众不同的要点：**
* 定制构建的内容与实验室
* 支持顶级工具与平台
* 由实践者设计与授课

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 为 **教育** 与 **金融科技 (FinTech)** 机构提供专业化的网络安全服务，重点关注 **渗透测试、云安全评估** 和 **合规准备**（SOC 2、PCI-DSS、NIST）。我们的团队包含 **OSCP 和 CISSP 认证的专业人员**，为每次服务提供深厚的技术专长与行业标准洞见。

我们不仅依赖自动化扫描，还提供 **人工、情报驱动的测试**，为高风险环境量身定制。从保护学生记录到保障金融交易，我们帮助组织守护最重要的资产。

_“高质量的防御来源于了解进攻，我们通过理解来提供安全。”_

想了解更多网络安全的最新动态，请访问我们的 [**blog**](https://www.lasttowersolutions.com/blog)。

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE 使 DevOps、DevSecOps 和开发人员能够高效地管理、监控和保护 Kubernetes 集群。利用我们的 AI 驱动洞见、先进的安全框架和直观的 CloudMaps GUI 来可视化集群、了解其状态并自信地采取行动。

此外，K8Studio 与所有主流 kubernetes 发行版兼容（AWS, GCP, Azure, DO, Rancher, K3s, Openshift 等）。

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## 许可证与免责声明

请查看：

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github 统计

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
