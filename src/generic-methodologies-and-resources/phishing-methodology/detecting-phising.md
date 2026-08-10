# Detecting Phishing

## 简介

要检测 phishing 尝试，**了解如今正在使用的 phishing 技术非常重要**。在本文的父页面上可以找到相关信息，因此如果你不了解当前正在使用哪些技术，我建议你前往父页面，至少阅读该部分内容。

本文基于这样一个理念：**攻击者会尝试以某种方式仿冒或使用受害者的域名**。如果你的域名是 `example.com`，但由于某种原因，你遭遇 phishing 时使用的是完全不同的域名，例如 `youwonthelottery.com`，那么这些技术无法发现这种情况。

## 域名变体

通过电子邮件中的**相似域名**来进行的 **phishing** 尝试通常**很容易被发现**。\
只需**生成攻击者最有可能使用的 phishing 域名列表**，然后**检查**这些域名是否已被**注册**，或者直接检查是否有任何 **IP** 正在使用它们。

### 查找可疑域名

为此，你可以使用以下任一工具。两者都会将候选域名解析，以检查它们是否正在使用。<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

提示：如果你生成了候选域名列表，也应将其输入 DNS resolver logs，以检测**来自组织内部的 NXDOMAIN 查询**（用户尝试访问拼写错误的域名，而攻击者尚未实际注册该域名）。如果策略允许，可以对这些域名进行 Sinkhole 或预先阻止。

### Bitflipping

**简要说明请参见父页面；有关 Windows.com bitsquatting 的主要研究，请参见 [Remy Hax 的文章](https://remyhax.xyz/posts/bitsquatting-windows/)和 [BleepingComputer 的报告](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**。<sup>[[1]](#references)[[2]](#references)</sup>

例如，对域名 microsoft.com 进行 1 bit 修改，可以将其转换为 _windnws.com._\
**攻击者可能会注册尽可能多的、与受害者相关的 bit-flipping 域名，将合法用户重定向到其基础设施**。<sup>[[1]](#references)[[2]](#references)</sup>

**还应监控所有可能的 bit-flipping 域名。**

如果还需要考虑 homoglyph/IDN 相似域名（例如混用 Latin/Cyrillic 字符），请查看：

{{#ref}}
homograph-attacks.md
{{#endref}}

### 基本检查

获得潜在可疑域名列表后，应当对其进行**检查**（主要检查 HTTP 和 HTTPS 端口），以**确认它们是否使用了与受害者域名相似的登录表单**。\
你还可以检查 3333 端口，以确认该端口是否开放并运行着 `gophish` 实例。\
了解每个发现的可疑域名**注册时间有多久**也很有意义；域名越新，风险越高。\
你还可以获取可疑 HTTP 和/或 HTTPS 网页的**屏幕截图**，以确认其是否可疑；如果确实可疑，**可以访问它进行更深入的检查**。

### 高级检查

如果你希望更进一步，我建议你**监控这些可疑域名，并定期搜索更多域名**（每天一次？这只需要几秒或几分钟）。你还应当**检查**相关 IP 的开放**端口**，并**搜索 `gophish` 或类似工具的实例**（是的，攻击者也会犯错），同时**监控可疑域名及其子域名的 HTTP 和 HTTPS 网页**，以确认它们是否复制了受害者网页中的登录表单。\
为了**实现自动化**，我建议维护一份受害者域名登录表单列表，对可疑网页进行 spider，并使用类似 `ssdeep` 的工具，将可疑域名中发现的每个登录表单与受害者域名中的每个登录表单进行比较。\
如果你已经定位到可疑域名中的登录表单，可以尝试**发送无效凭据**，并**检查它是否会将你重定向到受害者的域名**。

---

### 通过 favicon 和 web fingerprints 进行 Hunting（Shodan/Censys）

许多 phishing kits 会复用其仿冒品牌的 favicon。Shodan 使用 MurmurHash3 对经过 base64 编码的 favicon 数据进行哈希处理，而 Censys 则公开其自身的 favicon hash 字段。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>你可以生成与 Shodan 兼容的 hash，并据此进行 pivot：

Python 示例（mmh3）：
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- 查询 Shodan：`http.favicon.hash:309020573`
- 使用 tooling：查看 favfreak 等 community tools，以计算 hashes 并生成 Shodan dorks。<sup>[[16]](#references)</sup>

注意
- Favicons 会被重复使用；将匹配结果视为线索，并在采取行动前验证内容和证书。
- 结合 domain-age 和关键词启发式方法，以获得更高的精确度。

### URL telemetry hunting (urlscan.io)

`urlscan.io` 会存储已提交 URL 的历史 screenshots、DOM、requests 和 TLS metadata。你可以用它来寻找品牌滥用和克隆站点：<sup>[[8]](#references)</sup>

示例查询（UI 或 API）：
- 查找排除合法域名后的相似站点：`page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 查找 hotlinking 你的 assets 的站点：`domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 限制为近期结果：追加 `AND date:>now-7d`

API 示例：
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
从 JSON 中按以下字段进行透视：
- `page.tlsIssuer`、`page.tlsValidFrom`、`page.tlsAgeDays`：发现仿冒域名中非常新的证书
- `task.source` 值（如 `certstream-suspicious`）：将发现结果与 CT 监控关联起来

### 通过 RDAP 获取域名年龄（可脚本化）

RDAP 会返回机器可读的注册事件。可用于标记**新注册域名（NRD）**。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
通过为域名标记注册时间段（例如 <7 天、<30 天）来丰富你的 pipeline，并据此确定 triage 优先级。

### 用于发现 AiTM 基础设施的 TLS/JAx 指纹

凭据 phishing 可以使用 **Adversary-in-the-Middle (AiTM)** reverse proxy（例如 Evilginx）窃取 session token。<sup>[[11]](#references)</sup> 你可以添加网络侧检测：

- 在 egress 处记录 TLS/HTTP 指纹（JA3/JA4/JA4S/JA4H）。据观察，某些 Evilginx 构建版本具有稳定的 JA4 client/server 值。仅将已知恶意指纹作为较弱信号触发告警，并始终结合内容和域名情报进行确认。<sup>[[12]](#references)</sup>
- 主动记录通过 CT 或 urlscan 发现的相似域名主机的 TLS certificate 元数据（issuer、SAN 数量、wildcard 使用情况、有效期），并与 DNS age 和 geolocation 进行关联。

> 注意：将指纹视为 enrichment，而不是唯一的阻断依据；framework 会不断演进，并且可能随机化或混淆指纹。

### 使用关键词的域名

父页面还提到一种域名变体技术，即将**受害者的域名放在更大的域名中**（例如针对 paypal.com 使用 paypal-financial.com）。

#### Certificate Transparency

Certificate Transparency (CT) 日志会公开 certificate identity，因此搜索 Subject 或 SAN 名称中的品牌关键词可以发现相似域名（例如，paypal-financial.com 的 certificate 会公开 `paypal` 关键词）。在有用时，可以按签发日期和 CA 过滤结果，并对候选项进行验证，因为关键词匹配可能产生误报。<sup>[[13]](#references)</sup>

Patrik Hudak 的原始 [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) 在 Censys 中演示了这一工作流，包括按 certificate 日期和 issuer（例如 Let's Encrypt）进行过滤。<sup>[[13]](#references)</sup>

你还可以使用免费的 [**crt.sh**](https://crt.sh) 服务搜索关键词，并按日期和 CA 过滤结果。<sup>[[13]](#references)</sup>

其 Matching Identities 字段有助于比较真实域名与可疑域名的 identity，但应将匹配结果视为线索，而非证据。<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) 以近实时方式流式传输 CT 更新，而 [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) 会使用该数据流对可疑 certificate 名称进行评分。<sup>[[14]](#references)[[15]](#references)</sup>

实用建议：对 CT 命中结果进行 triage 时，优先关注 NRD、不受信任/未知 registrar、privacy-proxy WHOIS，以及 `NotBefore` 时间非常近的 cert。维护你所拥有的域名/品牌 allowlist，以减少噪声。

#### **新域名**

另一种方法是按 TLD 收集新注册域名（例如通过 [Whoxy](https://www.whoxy.com/newly-registered-domains/)），然后筛选品牌关键词。当关键词不在 registered domain 中时，这种方法会漏掉托管在 subdomain 上的 phishing。<sup>[[13]](#references)</sup>

额外 heuristic：在 alerting 中对某些**文件扩展名 TLD**（例如 `.zip`、`.mov`）提高警惕。这些 TLD 在 lure 中很容易被误认为文件名；将 TLD 信号与品牌关键词和 NRD age 结合，可以获得更高的 precision。

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [通过 bitflipping 劫持指向 Microsoft windows.com 的流量](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [深度解析：http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 文档](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083：Registration Data Access Protocol 的 JSON Responses](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics：如何防止、检测和响应 cloud token theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Finding Phishing：Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Introducing CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
