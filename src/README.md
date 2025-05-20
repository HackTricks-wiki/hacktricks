# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks 标志和动态设计由_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._ 

### 本地运行 HackTricks
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
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
您的本地 HackTricks 副本将在 **[http://localhost:3337](http://localhost:3337)** 后 <5 分钟内可用（它需要构建书籍，请耐心等待）。

## 企业赞助商

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) 是一家优秀的网络安全公司，其口号是 **HACK THE UNHACKABLE**。他们进行自己的研究并开发自己的黑客工具，以 **提供多种有价值的网络安全服务**，如渗透测试、红队和培训。

您可以查看他们的 **博客** 在 [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** 还支持像 HackTricks 这样的网络安全开源项目 :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) 是 **西班牙** 最相关的网络安全事件，也是 **欧洲** 最重要的活动之一。以 **促进技术知识** 为使命，这个大会是各个学科技术和网络安全专业人士的热烈交流点。

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** 是 **欧洲第一** 的道德黑客和 **漏洞赏金平台**。

**漏洞赏金提示**：**注册** **Intigriti**，这是一个由黑客为黑客创建的高级 **漏洞赏金平台**！今天就加入我们，访问 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)，开始赚取高达 **$100,000** 的赏金！

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 轻松构建和 **自动化工作流程**，由世界上 **最先进** 的社区工具提供支持。

今天就获取访问权限：

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

加入 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 服务器，与经验丰富的黑客和漏洞赏金猎人交流！

- **黑客见解**：参与深入探讨黑客的刺激和挑战的内容
- **实时黑客新闻**：通过实时新闻和见解，跟上快速变化的黑客世界
- **最新公告**：了解最新的漏洞赏金发布和重要平台更新

**今天就加入我们，** [**Discord**](https://discord.com/invite/N3FrSbmwdy)，开始与顶级黑客合作吧！

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - 必备的渗透测试工具包

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**从黑客的角度看待您的网络应用、网络和云**

**查找并报告具有实际商业影响的关键、可利用的漏洞。** 使用我们 20 多个自定义工具来映射攻击面，查找让您提升权限的安全问题，并使用自动化漏洞利用收集重要证据，将您的辛勤工作转化为有说服力的报告。

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** 提供快速且简单的实时 API，以 **访问搜索引擎结果**。他们抓取搜索引擎，处理代理，解决验证码，并为您解析所有丰富的结构化数据。

订阅 SerpApi 的计划之一可访问超过 50 个不同的 API，用于抓取不同的搜索引擎，包括 Google、Bing、百度、Yahoo、Yandex 等。\
与其他提供商不同，**SerpApi 不仅仅抓取自然结果**。SerpApi 的响应始终包括所有广告、内联图像和视频、知识图谱以及搜索结果中存在的其他元素和功能。

当前的 SerpApi 客户包括 **Apple、Shopify 和 GrubHub**。\
有关更多信息，请查看他们的 [**博客**](https://serpapi.com/blog/)**，**或在他们的 [**游乐场**](https://serpapi.com/playground)** 尝试示例。**\
您可以在 [**这里**](https://serpapi.com/users/sign_up)** 创建一个免费帐户。**

---

### [8kSec Academy – 深入的移动安全课程](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

学习执行漏洞研究、渗透测试和逆向工程所需的技术和技能，以保护移动应用和设备。通过我们的按需课程 **掌握 iOS 和 Android 安全** 并 **获得认证**：

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) 是一家总部位于 **阿姆斯特丹** 的专业网络安全公司，帮助 **保护** 全球各地的企业免受最新网络安全威胁，通过提供 **进攻性安全服务** 采用 **现代** 方法。

WebSec 是一家国际安全公司，在阿姆斯特丹和怀俄明州设有办事处。他们提供 **一体化安全服务**，这意味着他们可以做所有事情；渗透测试、**安全** 审计、意识培训、网络钓鱼活动、代码审查、漏洞开发、安全专家外包等等。

WebSec 的另一个酷点是，与行业平均水平不同，WebSec 对他们的技能 **非常自信**，以至于他们 **保证最佳质量结果**，他们在网站上声明“**如果我们无法攻破它，您就不需要支付！**”。有关更多信息，请查看他们的 [**网站**](https://websec.net/en/) 和 [**博客**](https://websec.net/blog/)！

除了上述内容，WebSec 还是 **HackTricks 的坚定支持者**。

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) 是一个数据泄露（leak）搜索引擎。\
我们提供随机字符串搜索（类似于谷歌），覆盖所有类型的大大小小的数据泄露——不仅仅是大的——来自多个来源的数据。\
人们搜索、AI 搜索、组织搜索、API（OpenAPI）访问、theHarvester 集成，所有渗透测试人员所需的功能。\
**HackTricks 继续成为我们所有人的优秀学习平台，我们为赞助它感到自豪！**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions 提供专门的网络安全服务，面向 **教育** 和 **金融科技** 机构，重点关注 **渗透测试、云安全评估** 和 **合规准备**（SOC 2、PCI-DSS、NIST）。我们的团队包括 **OSCP 和 CISSP 认证专业人员**，为每次合作带来深厚的技术专长和行业标准的见解。

我们超越自动化扫描，提供 **手动、基于情报的测试**，针对高风险环境量身定制。从保护学生记录到保护金融交易，我们帮助组织捍卫最重要的事务。

_“高质量的防御需要了解进攻，我们通过理解提供安全。”_

通过访问我们的 [**博客**](https://www.lasttowersolutions.com/blog) 保持对网络安全最新动态的了解。

{{#ref}}
https://www.lasttowersolutions.com/
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
