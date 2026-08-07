# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

要检测一次 phishing 尝试，重要的是**了解如今正在使用的 phishing techniques**。在本帖的父页面中可以找到相关信息，因此如果你不了解当前使用的 techniques，我建议你前往父页面，至少阅读该部分内容。

本文基于这样一个理念：**攻击者会尝试以某种方式模拟或使用受害者的 domain name**。如果你的 domain 叫作 `example.com`，但由于某种原因，你使用完全不同的 domain name（例如 `youwonthelottery.com`）遭遇 phishing，那么这些 techniques 将无法发现它。

## Domain name variations

发现那些会在邮件中使用**相似 domain name** 的 **phishing** 尝试相当**容易**。\
只需**生成攻击者可能使用的最可能的 phishing names 列表**，并**检查**这些名称是否已**注册**，或者直接检查是否有任何 **IP** 正在使用它。

### Finding suspicious domains

为此，你可以使用以下任意工具。请注意，这些工具还会自动执行 DNS requests，以检查该 domain 是否分配了任何 IP：

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

提示：如果你生成了候选列表，也应将其输入 DNS resolver logs，以检测**来自组织内部的 NXDOMAIN 查询**（用户试图访问某个 typo，而攻击者尚未实际注册它）。如果 policy 允许，可以对这些 domains 进行 Sinkhole 或预先 block。

### Bitflipping

**你可以在父页面中找到对此 technique 的简短说明，也可以在** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>**中阅读原始研究。**

例如，对 domain microsoft.com 进行 1 bit 修改，可以将其转换为 _windnws.com._\
**攻击者可能会注册尽可能多的、与受害者相关的 bit-flipping domains，以将合法用户重定向到其 infrastructure**。<sup>[[1]](#references)</sup>

**还应监控所有可能的 bit-flipping domain names。**

如果还需要考虑 homoglyph/IDN lookalikes（例如混用 Latin/Cyrillic 字符），请查看：

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

获得潜在的 suspicious domain names 列表后，应对它们进行**检查**（主要检查 HTTP 和 HTTPS ports），以**确认它们是否使用了与受害者 domain 中某个登录表单相似的表单**。\
你还可以检查 port 3333，确认其是否开放并运行着 `gophish` 实例。\
了解每个发现的 suspicious domain 的**注册时间**也很有价值；domain 越新，风险越高。\
你还可以获取 suspicious web page 的 HTTP 和/或 HTTPS **screenshots**，以判断其是否可疑；如果确实可疑，则**访问它并进行更深入的检查**。

### Advanced checks

如果你想更进一步，我建议你**监控这些 suspicious domains，并不时搜索更多相关 domain**（每天一次？这只需要几秒钟或几分钟）。你还应**检查**相关 IP 的开放 **ports**，并**搜索 `gophish` 或类似 tools 的实例**（没错，攻击者也会犯错），同时**监控 suspicious domains 和 subdomains 的 HTTP 与 HTTPS web pages**，以确认它们是否复制了受害者 web pages 中的登录表单。\
为了**实现自动化**，我建议维护受害者 domains 的登录表单列表，对 suspicious web pages 进行 spider，并使用类似 `ssdeep` 的工具，将 suspicious domains 中发现的每个登录表单与受害者 domain 的每个登录表单进行比较。\
如果你已经定位了 suspicious domains 的登录表单，可以尝试**发送 junk credentials**，并**检查它是否会将你重定向到受害者 domain**。

---

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

许多 phishing kits 会复用其冒充品牌的 favicons。Internet-wide scanners 会对 base64-encoded favicon 计算 MurmurHash3。你可以生成该 hash 并基于它进行 pivot：

Python example (mmh3)：
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- 查询 Shodan：`http.favicon.hash:309020573`
- 使用 tooling：查看 favfreak 等 community tools，以生成用于 Shodan/ZoomEye/Censys 的 hashes 和 dorks。

Notes
- Favicons 会被重复使用；将匹配结果视为线索，并在采取行动前验证内容和证书。
- 结合 domain-age 和 keyword heuristics，以获得更高的精确度。

### URL telemetry hunting (urlscan.io)

`urlscan.io` 存储已提交 URL 的历史 screenshots、DOM、requests 和 TLS metadata。你可以用它来 hunting brand abuse 和 clones：<sup>[[2]](#references)</sup>

Example queries (UI or API):
- 查找排除你的 legit domains 的 lookalikes：`page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 查找 hotlinking 你的 assets 的 sites：`domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 限制为最近的 results：追加 `AND date:>now-7d`

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
从 JSON 中基于以下字段进行 pivot：
- `page.tlsIssuer`、`page.tlsValidFrom`、`page.tlsAgeDays`：发现 lookalikes 使用的非常新的证书
- `task.source` 值（如 `certstream-suspicious`）：将发现结果与 CT monitoring 关联起来

### 通过 RDAP 获取域名年龄（可编写脚本）

RDAP 返回机器可读的创建事件。可用于标记**新注册域名（NRDs）**。
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
通过为域名标记注册时长分段（例如 <7 days、<30 days）来丰富你的 pipeline，并据此确定 triage 优先级。

### TLS/JAx fingerprints to spot AiTM infrastructure

现代 credential-phishing 越来越多地使用 **Adversary-in-the-Middle (AiTM)** reverse proxies（例如 Evilginx）来窃取 session tokens。你可以添加 network-side detections：

- 在 egress 处记录 TLS/HTTP fingerprints（JA3/JA4/JA4S/JA4H）。已观察到部分 Evilginx builds 使用稳定的 JA4 client/server values。仅将已知恶意 fingerprints 作为弱信号触发告警，并始终结合 content 和 domain intel 进行确认。<sup>[[3]](#references)</sup>
- 主动记录通过 CT 或 urlscan 发现的 lookalike hosts 的 TLS certificate metadata（issuer、SAN 数量、wildcard 使用情况、有效期），并与 DNS age 和 geolocation 进行关联。

> 注意：应将 fingerprints 作为 enrichment，而不是唯一的 blockers；frameworks 会不断演进，也可能对其进行 randomise 或 obfuscate。

### Domain names using keywords

父页面还提到一种 domain name variation technique，即将 **victim's domain name 放入一个更大的 domain 中**（例如使用 paypal-financial.com 代替 paypal.com）。

#### Certificate Transparency

虽然无法采用之前的 “Brute-Force” 方法，但借助 certificate transparency，实际上也**可以发现此类 phishing attempts**。每当 CA 签发 certificate 时，其详细信息都会被公开。这意味着，通过读取甚至监控 certificate transparency，**可以找到名称中包含某个 keyword 的 domains**。例如，如果攻击者为 [https://paypal-financial.com](https://paypal-financial.com) 生成 certificate，通过查看该 certificate，就可以找到 “paypal” 这个 keyword，并知晓有人正在使用可疑 email。

文章 [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) 建议使用 Censys 搜索影响特定 keyword 的 certificates，并按日期（仅搜索 “new” certificates）以及 CA issuer “Let's Encrypt” 进行过滤：<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

不过，你也可以使用免费 web 服务 [**crt.sh**](https://crt.sh) 来执行“相同”的操作。你可以**搜索 keyword**，并根据需要按**日期和 CA 过滤**结果。

![Domain names using keywords - Certificate Transparency: 不过，你也可以使用免费 web 服务 crt.sh 来执行“相同”的操作。你可以搜索 keyword，并根据日期和...](<../../images/image (519).png>)

使用最后这个选项时，你甚至可以利用 Matching Identities 字段，查看真实 domain 中的某个 identity 是否与任何可疑 domains 匹配（注意，可疑 domain 可能是 false positive）。

**另一个替代方案**是名为 [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) 的优秀项目。CertStream 提供新生成 certificates 的 real-time stream，你可以使用它来检测其中是否包含指定 keywords，并实现（接近）real-time 的检测。事实上，有一个名为 [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) 的项目正是这样做的。

实用建议：对 CT hits 进行 triage 时，优先关注 NRDs、不受信任/未知 registrars、privacy-proxy WHOIS，以及 `NotBefore` 时间非常近的 certs。维护一个包含自有 domains/brands 的 allowlist，以减少噪声。

#### **New domains**

**最后一个替代方案**是收集某些 TLDs 的**新注册 domains**列表（[Whoxy](https://www.whoxy.com/newly-registered-domains/) 提供此类服务），并**检查这些 domains 中的 keywords**。但是，较长的 domains 通常会使用一个或多个 subdomains，因此 keyword 不会出现在 FLD 中，你也就无法找到 phishing subdomain。

Additional heuristic：在 alerting 中对某些**file-extension TLDs**（例如 `.zip`、`.mov`）保持更高警惕。这些 TLDs 在 lures 中很容易被误认为 filenames；将 TLD signal 与 brand keywords 及 NRD age 结合，可以获得更高的 precision。

## References

- [1] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
