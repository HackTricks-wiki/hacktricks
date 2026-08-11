# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## 简介

要检测一次 phishing 尝试，了解**当前使用的 phishing 技术**非常重要。在本文的父页面中可以找到这些信息，因此如果你不了解如今正在使用哪些技术，我建议你前往父页面，至少阅读相关部分。

本文基于这样一个前提：**攻击者会尝试以某种方式模仿或使用受害者的域名**。如果你的域名是 `example.com`，但由于某种原因，你使用了完全不同的域名（例如 `youwonthelottery.com`）进行 phishing，那么这些技术将无法发现它。

## 域名变体

发现邮件中使用的**相似域名**进行 phishing 的尝试相对**容易**。\
只需**生成攻击者最有可能使用的 phishing 域名列表**，然后**检查**这些域名是否已被**注册**，或者直接检查是否有任何 **IP** 正在使用它们。

### 查找可疑域名

为此，你可以使用以下任一工具。两者都会解析候选域名，以检查它们是否正在使用。<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

提示：如果你生成了候选域名列表，也可以将其输入 DNS resolver 日志中，以检测**来自组织内部的 NXDOMAIN 查询**（用户在攻击者实际注册域名之前尝试访问拼写错误的域名）。如果策略允许，可以将这些域名 Sinkhole 或预先阻止。

### Bitflipping

**简短说明请参见父页面；有关主要的 Windows.com bitsquatting 研究，请参见 [Remy Hax 的文章](https://remyhax.xyz/posts/bitsquatting-windows/)和 [BleepingComputer 的报告](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**。<sup>[[1]](#references)[[2]](#references)</sup>

例如，对域名 microsoft.com 进行 1 bit 修改，可以将其转换为 _windnws.com._\
**攻击者可能会注册尽可能多的与受害者相关的 bit-flipping 域名，将合法用户重定向到其基础设施**。<sup>[[1]](#references)[[2]](#references)</sup>

**还应监控所有可能的 bit-flipping 域名。**

如果还需要考虑 homoglyph/IDN lookalikes（例如混用拉丁字母和西里尔字母），请查看：

{{#ref}}
homograph-attacks.md
{{#endref}}

### 基本检查

获得潜在可疑域名列表后，应对其进行**检查**（主要检查 HTTP 和 HTTPS 端口），以**确认它们是否使用了与受害者域名中某个登录表单相似的登录表单**。\
你还可以检查 3333 端口，确认该端口是否开放并运行着一个 `gophish` 实例。\
了解每个发现的可疑域名**注册时间有多久**也很有意义；域名越新，风险越高。\
你还可以获取可疑 HTTP 和/或 HTTPS 网页的**截图**，判断其是否可疑，并在确认可疑时**访问它以进行更深入的分析**。

### 高级检查

如果你想更进一步，我建议你**监控这些可疑域名，并不时搜索更多域名**（每天一次？这只需要几秒或几分钟）。你还应**检查**相关 IP 的开放**端口**，并**搜索 `gophish` 或类似工具的实例**（是的，攻击者也会犯错），同时**监控可疑域名和子域名的 HTTP 和 HTTPS 网页**，以确认它们是否复制了受害者网页中的登录表单。\
为了**实现自动化**，我建议维护一份受害者域名登录表单的列表，spider 可疑网页，并使用类似 `ssdeep` 的工具，将可疑域名中发现的每个登录表单与受害者域名中的每个登录表单进行比较。\
如果你已经定位了可疑域名中的登录表单，可以尝试**发送垃圾凭据**，并**检查它是否会将你重定向到受害者的域名**。

---

### 通过 favicon 和 Web 指纹进行 Hunting（Shodan/Censys）

许多 phishing kits 会复用其冒充品牌的 favicon。Shodan 使用 MurmurHash3 对 base64 编码的 favicon 数据进行哈希处理，而 Censys 则公开其自身的 favicon hash 字段。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>你可以生成与 Shodan 兼容的 hash，并通过它进行 pivot：

Python 示例（mmh3）：
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- 查询 Shodan：`http.favicon.hash:309020573`
- 使用 tooling：查看 favfreak 等 community tools，以计算 hashes 并生成 Shodan dorks。<sup>[[16]](#references)</sup>

注意事项
- Favicons 会被重复使用；将匹配结果视为线索，并在采取行动前验证内容和证书。
- 结合 domain-age 和关键词 heuristics，以获得更高的精确度。

### URL telemetry hunting（urlscan.io）

`urlscan.io` 会存储所提交 URL 的历史 screenshots、DOM、requests 和 TLS metadata。你可以用它来 hunting brand abuse 和 clones：<sup>[[8]](#references)</sup>

示例查询（UI 或 API）：
- 查找排除自身合法 domains 的 lookalikes：`page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 查找 hotlinking 你 assets 的 sites：`domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 限制为最近的结果：追加 `AND date:>now-7d`

API 示例：
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
从 JSON 中围绕以下字段进行关联分析：
- `page.tlsIssuer`、`page.tlsValidFrom`、`page.tlsAgeDays`，用于发现 lookalike 域名所使用的最新证书
- `task.source` 中的 `certstream-suspicious` 等值，用于将发现结果与 CT monitoring 关联起来

### 通过 RDAP 获取域名年龄（可脚本化）

RDAP 会返回机器可读的注册事件。可用于标记**新注册域名（NRD）**。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
通过为域名添加注册年龄分桶标签（例如 <7 天、<30 天）来丰富你的 pipeline，并据此确定 triage 优先级。

### TLS/JAx fingerprints to spot AiTM infrastructure

Credential-phishing can 使用 **Adversary-in-the-Middle (AiTM)** reverse proxies（例如 Evilginx）窃取 session tokens。<sup>[[11]](#references)</sup> 你可以添加网络侧 detections：

- 在 egress 处记录 TLS/HTTP fingerprints（JA3/JA4/JA4S/JA4H）。一些 Evilginx builds 已被观察到使用稳定的 JA4 client/server values。仅将已知恶意 fingerprints 作为弱信号触发告警，并始终结合 content 和 domain intel 进行确认。<sup>[[12]](#references)</sup>
- 主动记录通过 CT 或 urlscan 发现的相似域名主机的 TLS certificate metadata（issuer、SAN 数量、wildcard 使用情况、validity），并与 DNS age 和 geolocation 进行关联。

> 注意：将 fingerprints 视为 enrichment，而不是唯一的 blockers；frameworks 会不断演进，也可能随机化或 obfuscate。

### 使用关键词的域名

父页面还提到一种域名变体技术，即将 **victim's domain name 放入更大的域名中**（例如使用 paypal-financial.com 代替 paypal.com）。

#### Certificate Transparency

Certificate Transparency（CT）logs 会公开 certificate identities，因此搜索 Subject 或 SAN names 中的 brand keywords 可以发现相似域名（例如，`paypal-financial.com` 的 certificate 会暴露 `paypal` 关键词）。必要时，可以按 issuance date 和 CA 过滤结果，并对候选项进行验证，因为关键词匹配可能产生 false positives。<sup>[[13]](#references)</sup>

Patrik Hudak 的原始 [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) 在 Censys 中演示了这一 workflow，其中包括按 certificate date 和 issuer（例如 Let's Encrypt）进行过滤。<sup>[[13]](#references)</sup>

![用于识别相似域名的 Censys certificate search results](<../../images/image (1115).png>)

你也可以使用免费的 [**crt.sh**](https://crt.sh) service 搜索关键词，并按 date 和 CA 过滤结果。<sup>[[13]](#references)</sup>

![针对可疑 certificate identities 的 crt.sh keyword search](<../../images/image (519).png>)

其 Matching Identities field 可用于比较真实域名与可疑域名的 identities，但应将匹配结果视为 leads，而不是 proof。<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) 会近乎实时地 stream CT updates，而 [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) 会使用该 stream 对可疑 certificate names 进行评分。<sup>[[14]](#references)[[15]](#references)</sup>

实用建议：对 CT hits 进行 triage 时，优先关注 NRDs、untrusted/unknown registrars、privacy-proxy WHOIS，以及 `NotBefore` 时间非常近的 certs。维护一份自有 domains/brands 的 allowlist，以减少 noise。

#### **New domains**

另一种方案是按 TLD 收集 newly registered domains（例如通过 [Whoxy](https://www.whoxy.com/newly-registered-domains/)），然后按 brand keywords 进行过滤。如果关键词不在 registered domain 中，这种方法会漏掉托管在 subdomains 上的 phishing。<sup>[[13]](#references)</sup>

附加 heuristic：在 alerting 中对某些 **file-extension TLDs**（例如 `.zip`、`.mov`）提高警惕。这些 TLD 在 lures 中很容易被误认为 filenames；将 TLD signal 与 brand keywords 和 NRD age 结合，可获得更高的 precision。

## References

- [1] [Remy Hax – Windows.com 的 Bitsquatting](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [通过 bitflipping 劫持 Microsoft windows.com 的流量](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [深度解析：http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 文档](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API 参考](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol 帮助](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083：Registration Data Access Protocol 的 JSON 响应](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics：如何防止、检测和响应 cloud token theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – 发现 Phishing：工具和技术](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream 介绍](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
