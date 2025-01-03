# 检测钓鱼

{{#include ../../banners/hacktricks-training.md}}

## 介绍

要检测钓鱼尝试，重要的是**了解当前使用的钓鱼技术**。在此帖子的父页面上，您可以找到这些信息，因此如果您不知道今天使用了哪些技术，我建议您访问父页面并至少阅读该部分。

这篇文章基于这样的想法：**攻击者会试图以某种方式模仿或使用受害者的域名**。如果您的域名是`example.com`，而您被使用完全不同的域名钓鱼，例如`youwonthelottery.com`，这些技术将无法揭示它。

## 域名变体

揭露那些在电子邮件中使用**相似域名**的**钓鱼**尝试是相对**简单**的。\
只需**生成攻击者可能使用的最可能的钓鱼名称列表**，并**检查**它是否**已注册**，或者检查是否有任何**IP**在使用它。

### 查找可疑域名

为此，您可以使用以下任何工具。请注意，这些工具还会自动执行DNS请求，以检查域名是否有任何IP分配给它：

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### 位翻转

**您可以在父页面找到此技术的简短解释。或者阅读原始研究** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

例如，对域名microsoft.com进行1位修改可以将其转换为_windnws.com._\
**攻击者可能会注册尽可能多的与受害者相关的位翻转域名，以将合法用户重定向到他们的基础设施**。

**所有可能的位翻转域名也应进行监控。**

### 基本检查

一旦您有了一份潜在可疑域名的列表，您应该**检查**它们（主要是HTTP和HTTPS端口），以**查看它们是否使用与受害者域名相似的登录表单**。\
您还可以检查端口3333，以查看它是否开放并运行`gophish`实例。\
了解**每个发现的可疑域名的年龄**也很有趣，越年轻的域名风险越大。\
您还可以获取可疑网页的**截图**，以查看它是否可疑，如果是，则**访问它以进行更深入的查看**。

### 高级检查

如果您想更进一步，我建议您**监控这些可疑域名，并不时搜索更多**（每天？只需几秒钟/分钟）。您还应该**检查**相关IP的开放**端口**，并**搜索`gophish`或类似工具的实例**（是的，攻击者也会犯错误），并**监控可疑域名和子域名的HTTP和HTTPS网页**，以查看它们是否复制了受害者网页的任何登录表单。\
为了**自动化这一过程**，我建议您拥有一份受害者域名的登录表单列表，爬取可疑网页，并使用类似`ssdeep`的工具将可疑域名中的每个登录表单与受害者域名的每个登录表单进行比较。\
如果您找到了可疑域名的登录表单，您可以尝试**发送垃圾凭据**并**检查它是否将您重定向到受害者的域名**。

## 使用关键字的域名

父页面还提到了一种域名变体技术，即将**受害者的域名放入更大的域名中**（例如paypal-financial.com用于paypal.com）。

### 证书透明度

无法采用之前的“暴力破解”方法，但实际上**也可以通过证书透明度揭露此类钓鱼尝试**。每当CA发出证书时，详细信息会公开。这意味着通过阅读证书透明度或甚至监控它，**可以找到在其名称中使用关键字的域名**。例如，如果攻击者生成了[https://paypal-financial.com](https://paypal-financial.com)的证书，通过查看证书可以找到关键字“paypal”，并知道正在使用可疑电子邮件。

帖子[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)建议您可以使用Censys搜索影响特定关键字的证书，并按日期（仅“新”证书）和CA发行者“Let's Encrypt”进行过滤：

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

然而，您可以使用免费的网页[**crt.sh**](https://crt.sh)做“同样的事情”。您可以**搜索关键字**，并根据需要**按日期和CA过滤**结果。

![](<../../images/image (519).png>)

使用最后一个选项，您甚至可以使用匹配身份字段查看真实域名的任何身份是否与任何可疑域名匹配（请注意，可疑域名可能是误报）。

**另一个替代方案**是名为[**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)的精彩项目。CertStream提供新生成证书的实时流，您可以使用它来实时检测指定关键字。实际上，有一个名为[**phishing_catcher**](https://github.com/x0rz/phishing_catcher)的项目就是这样做的。

### **新域名**

**最后一个替代方案**是收集一些TLD的新注册域名列表（[Whoxy](https://www.whoxy.com/newly-registered-domains/)提供此服务），并**检查这些域名中的关键字**。然而，长域名通常使用一个或多个子域，因此关键字不会出现在FLD中，您将无法找到钓鱼子域。

{{#include ../../banners/hacktricks-training.md}}
