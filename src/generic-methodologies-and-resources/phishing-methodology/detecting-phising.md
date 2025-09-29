# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## 介绍

要检测一次 phishing 尝试，重要的是要**了解当今正在使用的 phishing 技术**。在本帖的父页面里你可以找到这些信息，所以如果你不知道现在都有哪些技术在被使用，建议你先去父页面至少阅读那一节。

本帖基于一个假设：**攻击者会尝试以某种方式模仿或使用受害者的域名**。如果你的域名是 `example.com`，而你遭到钓鱼却使用了一个完全不同的域名，例如 `youwonthelottery.com`，这些技术就不会发现它。

## 域名变体

对于那些在邮件中使用**相似域名**的 phishing 尝试，**发现它们相对比较容易**。\
只需**生成一份攻击者可能使用的最可能的 phishing 名称列表**，并**检查**这些域名是否已经**被注册**，或者仅检查是否有任何**IP**在使用它们。

### 查找可疑域名

为此，你可以使用以下任意工具。注意这些工具也会自动执行 DNS 请求以检查域名是否被分配了 IP：

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

提示：如果你生成了候选列表，也把它送入你的 DNS resolver logs 以检测来自组织内部的 **NXDOMAIN lookups**（用户在攻击者实际注册之前尝试访问的拼写错误）。如果策略允许，Sinkhole 或预先屏蔽这些域名。

### Bitflipping

**你可以在父页面找到该技术的简短说明。或者阅读原始研究：** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

例如，对域名 microsoft.com 做 1 bit 的修改可以把它变成 _windnws.com._\
**攻击者可能会尽可能注册与受害者相关的许多 bit-flipping 域名，以便把合法用户重定向到他们的基础设施**。

**所有可能的 bit-flipping 域名也都应该被监控。**

如果你还需要考虑 homoglyph/IDN 类似域名（例如混用 Latin/Cyrillic 字符），请查看：

{{#ref}}
homograph-attacks.md
{{#endref}}

### 基本检查

一旦你有了一份潜在可疑域名的列表，你应该**检查**它们（主要是 HTTP 和 HTTPS 端口）以**查看它们是否使用了类似于受害者域名的登录表单**。\
你也可以检查端口 3333 是否开放并运行着 `gophish` 的实例。\
了解每个发现的可疑域名的**年龄**也很有趣，域名越新风险越高。\
你还可以获取可疑 HTTP 和/或 HTTPS 网页的**截图**，来判断它是否可疑，如果可疑则**访问它以做更深入的查看**。

### 高级检查

如果你想更进一步，我建议你**持续监控这些可疑域名并定期（比如每天？）搜索更多**（这只需几秒/分钟）。你还应该**检查相关 IP 的开放端口**并**搜索 `gophish` 或类似工具的实例**（是的，攻击者也会犯错），并**监控可疑域名和子域名的 HTTP 和 HTTPS 网页**以查看它们是否复制了受害者网页的任何登录表单。\
为了**自动化**这一过程，我建议维护一份受害者域名的登录表单列表，对可疑网页进行爬取，然后使用类似 `ssdeep` 的工具把可疑域名中找到的每个登录表单与受害者域名的每个登录表单进行比较。\
如果你已经定位到了可疑域名的登录表单，你可以尝试**发送垃圾凭证**并**检查它是否把你重定向到受害者的域名**。

---

### 通过 favicon 和 web 指纹进行狩猎（Shodan/ZoomEye/Censys）

许多钓鱼套件会重用其冒充品牌的 favicon。Internet-wide 扫描器会对 base64 编码的 favicon 计算 MurmurHash3。你可以生成该 hash 并据此 pivot：

Python 示例（mmh3）：
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- 查询 Shodan: `http.favicon.hash:309020573`
- 使用工具：查看社区工具，如 favfreak，用于为 Shodan/ZoomEye/Censys 生成 hashes 和 dorks。

注意
- Favicons 经常被重用；将匹配视为线索，在采取行动前验证内容和 certs。
- 结合 domain-age 和 keyword heuristics 可提高准确性。

### URL 遥测搜寻 (urlscan.io)

`urlscan.io` 存储已提交 URL 的历史截图、DOM、requests 和 TLS 元数据。你可以用它来搜索品牌滥用和克隆站点：

示例查询（UI 或 API）:
- 查找类似站点，排除你的合法域：`page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 查找热链接你资源的网站：`domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 限制为最近结果：追加 `AND date:>now-7d`

API 示例:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
从 JSON 中着眼于：
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` 用于发现用于仿冒/相似域名的非常新的证书
- `task.source` 的值（例如 `certstream-suspicious`）用于将发现与 CT 监控关联

### 通过 RDAP 获取域名年龄（可脚本化）

RDAP 返回机器可读的创建事件。可用于标记 **新注册域名 (NRDs)**。
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enrich your pipeline by tagging domains with registration age buckets (e.g., <7 days, <30 days) and prioritise triage accordingly.

### TLS/JAx fingerprints to spot AiTM infrastructure

现代的 credential-phishing 越来越多地使用 **Adversary-in-the-Middle (AiTM)** reverse proxies（例如 Evilginx）来窃取会话令牌。你可以增加网络侧的检测：

- 在出口处记录 TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H)。一些 Evilginx 构建被观察到具有稳定的 JA4 客户端/服务器值。仅将已知恶意指纹作为弱信号触发告警，并始终通过内容和域名情报确认。
- 主动记录 TLS 证书元数据（签发者、SAN count、通配符使用、有效期）用于通过 CT 或 urlscan 发现的相似域名，并与 DNS age 和地理位置进行关联。

> Note: Treat fingerprints as enrichment, not as sole blockers; frameworks evolve and may randomise or obfuscate.

### Domain names using keywords

父页面还提到一种域名变体技术，即将 **受害者的域名嵌入到更大的域名中**（例如 paypal-financial.com 对应 paypal.com）。

#### Certificate Transparency

无法使用之前的“Brute-Force”方法，但实际上也可以通过 certificate transparency 发现此类钓鱼尝试。每次 CA 颁发证书时，细节都会被公开。这意味着通过读取 certificate transparency 或监控它，**可以找到在其名称中使用特定关键词的域名**。例如，如果攻击者生成了 [https://paypal-financial.com](https://paypal-financial.com) 的证书，通过查看证书可以发现关键字 "paypal"，从而知道存在可疑使用。

帖子 [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) 建议你可以使用 Censys 搜索包含特定关键字的证书，并按日期筛选（仅“new”证书）以及按 CA 签发者 "Let's Encrypt" 过滤：

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

不过，你也可以使用免费的网页 [**crt.sh**](https://crt.sh) 做“同样的事”。你可以 **搜索关键字**，并且如需可以 **按日期和 CA 筛选** 结果。

![](<../../images/image (519).png>)

使用此选项你甚至可以使用 Matching Identities 字段来查看真实域名的任何 identity 是否与可疑域名匹配（注意可疑域名可能是误报）。

**Another alternative** 是一个很棒的项目 [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)。CertStream 提供新生成证书的实时流，你可以用它在（近）实时检测指定关键字。事实上，有一个名为 [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) 的项目正是这么做的。

Practical tip: when triaging CT hits, prioritise NRDs, untrusted/unknown registrars, privacy-proxy WHOIS, and certs with very recent `NotBefore` times. Maintain an allowlist of your owned domains/brands to reduce noise.

#### **New domains**

**One last alternative** 是收集某些 TLD 的 **newly registered domains** 列表（[Whoxy](https://www.whoxy.com/newly-registered-domains/) 提供此类服务），并 **检查这些域名中的关键字**。然而，较长的域名通常使用一个或多个子域，因此关键字不会出现在 FLD 中，你将无法找到钓鱼子域。

附加启发式方法：在告警时对某些 **file-extension TLDs**（例如 `.zip`, `.mov`）提高警惕。这些 TLD 常被诱饵中的文件名混淆；将 TLD 信号与品牌关键字和 NRD age 结合可以提高精确度。

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
