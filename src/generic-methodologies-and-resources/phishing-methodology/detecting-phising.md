# 检测钓鱼攻击

{{#include ../../banners/hacktricks-training.md}}

## 介绍

要检测钓鱼攻击，**了解如今正在使用的钓鱼技术**很重要。本文的上级页面介绍了这些信息；如果你不了解如今使用的技术，我建议你前往上级页面，至少阅读相关章节。

本文基于这样一个设想：**攻击者会尝试以某种方式仿冒或使用受害者的域名**。如果你的域名是 `example.com`，但你遭遇钓鱼攻击时使用的是完全不同的域名，比如 `youwonthelottery.com`，那么这些技术就无法发现它。

## 域名变体

要**发现**那些会在邮件中使用**相似域名**的**钓鱼**攻击，通常**很容易**。\
只需**生成一份攻击者可能使用的最可能的钓鱼域名列表**，并**检查**这些域名是否已**注册**，或者检查是否有任何**IP**正在使用它们。

### 查找可疑域名

为此，你可以使用以下任一工具。两者都会解析候选域名，以检查它们是否正在使用。<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

提示：如果你生成了候选域名列表，也可以将其与 DNS resolver 日志进行比对，以检测**组织内部发出的 NXDOMAIN 查询**（用户尝试访问拼写错误的域名，而攻击者尚未注册该域名）。如果策略允许，可以将这些域名 sinkhole 或预先阻止。

### Bitflipping

**简要说明请参阅上级页面；有关 Windows.com bitsquatting 的原始研究，请参阅 [Remy Hax 的文章](https://remyhax.xyz/posts/bitsquatting-windows/)和 [BleepingComputer 的报道](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**。<sup>[[1]](#references)[[2]](#references)</sup>

例如，在域名 microsoft.com 中修改 1 个 bit，就能将其变为 _windnws.com._\
**攻击者可能会注册尽可能多的与受害者相关的 bit-flipping 域名，将合法用户重定向到他们的基础设施**。<sup>[[1]](#references)[[2]](#references)</sup>

**还应监控所有可能的 bit-flipping 域名。**

如果还需要考虑 homoglyph/IDN 仿冒域名（例如混用拉丁字母和西里尔字母），请参阅：

{{#ref}}
homograph-attacks.md
{{#endref}}

### 基本检查

获取潜在可疑域名列表后，你应该**检查**这些域名（主要检查 HTTP 和 HTTPS 端口），以**查看它们是否使用了与受害者域名类似的登录表单**。\
你也可以检查 3333 端口是否开放，以及是否正在运行 `gophish` 实例。\
了解每个发现的可疑域名**注册时间有多久**也很有用；域名越新，风险越高。\
你还可以获取可疑网页的 HTTP 和/或 HTTPS **截图**，判断它们是否可疑；如果确实可疑，就**访问网页进行深入检查**。

### 高级检查

如果你想更进一步，我建议你**持续监控这些可疑域名，并不时查找更多域名**（比如每天一次？只需几秒钟或几分钟）。你还应该**检查**相关 IP 开放的**端口**，并**查找 `gophish` 或类似工具的实例**（没错，攻击者也会犯错）；同时**监控可疑域名和子域名上的 HTTP 和 HTTPS 网页**，查看它们是否复制了受害者网页中的登录表单。\
要**自动化这一过程**，我建议整理一份受害者域名的登录表单列表，对可疑网页进行 spider 抓取，并使用 `ssdeep` 之类的工具，将在可疑域名中找到的每个登录表单与受害者域名的每个登录表单进行比较。\
如果你找到了可疑域名上的登录表单，可以尝试**发送无效凭据**，并**检查它是否会将你重定向到受害者的域名**。

---

### 通过 favicon 和 Web 指纹进行搜索（Shodan/Censys）

许多钓鱼套件会重复使用被仿冒品牌的 favicon。Shodan 使用 MurmurHash3 对 base64 编码的 favicon 数据进行哈希处理，而 Censys 则提供自己的 favicon 哈希字段。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>你可以生成兼容 Shodan 的哈希并据此进行检索：

Python 示例（mmh3）：

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- 查询 Shodan：`http.favicon.hash:309020573`
- 使用工具：查看 favfreak 等社区工具，以计算哈希并生成 Shodan dorks。<sup>[[16]](#references)</sup>

注意事项
- 网站图标可能被多个网站复用；将匹配结果视为线索，并在采取行动前验证内容和证书。
- 结合域名年龄和关键词启发式规则，以提高精确度。

### URL telemetry 狩猎（urlscan.io）

`urlscan.io` 会存储已提交 URL 的历史截图、DOM、请求和 TLS 元数据。你可以据此搜寻品牌滥用和克隆网站：<sup>[[8]](#references)</sup>

示例查询（UI 或 API）：
- 查找仿冒网站，同时排除你的合法域名：`page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 查找热链你资源的网站：`domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 限定为近期结果：追加 `AND date:>now-7d`

API 示例：

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

从 JSON 中，基于以下字段进行排查：
- `page.tlsIssuer`、`page.tlsValidFrom`、`page.tlsAgeDays`，以发现用于仿冒域名的全新证书
- `task.source` 中的 `certstream-suspicious` 等值，以便将发现结果关联到 CT 监控

### 通过 RDAP 查询域名年龄（可脚本化）

RDAP 会返回机器可读的注册事件，可用于标记**新注册域名（NRDs）**。<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

通过为域名标记注册时间段（例如 <7 天、<30 天）来丰富你的 pipeline，并据此确定分流优先级。

### 用于发现 AiTM 基础设施的 TLS/JAx 指纹

凭据钓鱼可能会使用**对手中间人（AiTM）**反向代理（例如 Evilginx）窃取会话令牌。<sup>[[11]](#references)</sup>你可以添加网络侧检测：

- 在出口流量记录 TLS/HTTP 指纹（JA3/JA4/JA4S/JA4H）。据观察，某些 Evilginx 版本使用稳定的 JA4 客户端/服务器值。仅将已知恶意指纹作为弱信号触发告警，并始终结合内容和域名情报进行确认。<sup>[[12]](#references)</sup>
- 主动记录通过 CT 或 urlscan 发现的相似域名主机的 TLS 证书元数据（颁发者、SAN 数量、通配符使用情况、有效期），并与 DNS 年限和地理位置进行关联。

> 注意：将指纹作为补充信息，而非唯一的拦截依据；框架会不断演进，也可能随机化或混淆指纹。

### 使用关键词的域名

父页面还提到一种域名变体技术：将**受害者的域名放进一个更大的域名中**（例如，用于仿冒 paypal.com 的 paypal-financial.com）。

#### Certificate Transparency

Certificate Transparency（CT）日志会公开证书身份信息，因此搜索 Subject 或 SAN 名称中的品牌关键词可以发现相似域名（例如，`paypal-financial.com` 的证书会显示 `paypal` 关键词）。需要时可按颁发日期和 CA 筛选结果；并验证候选域名，因为关键词匹配可能产生误报。<sup>[[13]](#references)</sup>

Patrik Hudak 最初的[钓鱼域名搜寻文章](https://0xpatrik.com/phishing-domains/)展示了在 Censys 中使用此工作流程的示例，包括按证书日期和颁发者（如 Let's Encrypt）筛选。<sup>[[13]](#references)</sup>

![用于识别相似域名的 Censys 证书搜索结果](<../../images/image (1115).png>)

你也可以使用免费的 [**crt.sh**](https://crt.sh) 服务搜索关键词，并按日期和 CA 筛选结果。<sup>[[13]](#references)</sup>

![crt.sh 对可疑证书身份进行关键词搜索](<../../images/image (519).png>)

其 Matching Identities 字段有助于比较真实域名与可疑域名的身份信息，但应将匹配结果视为线索，而非证据。<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) 近乎实时地推送 CT 更新，而 [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) 会使用该数据流为可疑证书名称评分。<sup>[[14]](#references)[[15]](#references)</sup>

实用建议：对 CT 命中结果进行分流时，优先关注 NRD、不可信/未知注册商、使用隐私代理的 WHOIS 信息，以及 `NotBefore` 时间非常近的证书。维护自有域名/品牌的允许列表，以减少噪声。

#### **新注册域名**

另一种方法是按 TLD 收集新注册域名（例如，通过 [Whoxy](https://www.whoxy.com/newly-registered-domains/)），然后筛选品牌关键词。如果已注册域名中没有关键词，这种方法会漏掉托管在子域名上的钓鱼网站。<sup>[[13]](#references)</sup>

附加启发式规则：在告警中对某些**文件扩展名形式的 TLD**（例如 `.zip`、`.mov`）提高警惕。诱饵中常将这些 TLD 误认为文件名；结合 TLD 信号、品牌关键词和 NRD 年限，可提高准确率。

## References

- [1] [Remy Hax – Windows.com 位翻转域名抢注](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [通过位翻转劫持指向 Microsoft windows.com 的流量](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [深入解析：http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 文档](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property 数据集](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API 参考](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol 帮助](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083：Registration Data Access Protocol 的 JSON 响应](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [令牌战术：如何防范、检测和应对云令牌盗窃](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ 网络指纹识别](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – 发现钓鱼网站：工具与技术](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream 介绍](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
