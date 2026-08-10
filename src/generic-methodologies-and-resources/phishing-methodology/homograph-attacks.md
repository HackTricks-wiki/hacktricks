# Phishing 中的 Homograph / Homoglyph Attacks

## 概述

Homograph（又称 homoglyph）attack 利用了这样一个事实：许多**来自非拉丁文字的 Unicode code points，在视觉上与 ASCII 字符完全相同或极其相似**。通过将一个或多个拉丁字符替换为外观相似的对应字符，攻击者可以构造：

* 对人眼看起来合法、但能够绕过基于关键词检测的显示名称、主题或消息正文。
* 欺骗受害者，使其相信自己正在访问可信站点的域名、子域名或 URL 路径。<sup>[[1]](#references)</sup>

由于每个 glyph 在内部都由其**Unicode code point** 标识，因此只需替换一个字符，就足以绕过简单的字符串比较（例如，`"Παypal.com"` 与 `"Paypal.com"`）。<sup>[[1]](#references)[[3]](#references)</sup>

## 典型 Phishing 工作流程

1. **构造消息内容** – 将冒充品牌 / 关键词中的特定拉丁字母替换为来自其他文字系统（Greek、Cyrillic、Armenian、Cherokee 等）的视觉上无法区分的字符。
2. **注册配套基础设施** – 可选：注册一个 homoglyph 域名并获取 TLS 证书（大多数 CA 不会进行视觉相似性检查）。
3. **发送 email / SMS** – 消息会在以下一个或多个位置包含 homoglyph：
* 发件人显示名称（例如，`Ηеlрdеѕk`）
* 主题行（`Urgеnt Аctіon Rеquіrеd`）
* 超链接文本或完全限定域名
4. **Redirect chain** – 受害者会先经过看似正常的网站或 URL shortener，随后才到达用于窃取凭据 / 投递 malware 的恶意主机。<sup>[[1]](#references)</sup>

## 常被滥用的 Unicode 范围

以下示例是一些包含常用于创建跨文字系统相似字符的字符的 Unicode blocks。<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | 看起来像 |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> 提示：使用 Unicode code charts 查找 blocks 和 code points。

## Detection Techniques

### 1. Mixed-Script Inspection

针对英语组织的 Phishing email 很少应当混用多种文字系统中的字符。一个简单但有效的启发式方法是：

1. 遍历待检查字符串中的每个字符。
2. 将 code point 映射到其 script 名称或 Unicode block。
3. 如果存在多个 script，**或**在非预期位置（显示名称、域名、主题、URL 等）出现非拉丁文字，则触发 alert。<sup>[[3]](#references)</sup>

Python proof-of-concept：
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Punycode 规范化（域名）

国际化域名（IDN）具有 Unicode 形式和以 `xn--` 为前缀、与 ASCII 兼容的 **Punycode** 形式。在加入 allow-list 或进行比较之前，将主机名转换为 IDNA/Punycode 形式，同时保留 Unicode 形式用于显示。<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph 字典 / Algorithms

诸如 **dnstwist**（`--fuzzers homoglyph`）或 **urlcrazy** 之类的工具可以枚举视觉上相似的域名变体，对于主动下架 / 监控非常有用。<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* 强制执行严格的 DMARC/DKIM/SPF 策略——防止来自未授权域名的 spoofing。
* 在 **Secure Email Gateways** 和 **SIEM/XSOAR** playbooks 中实现上述检测逻辑。
* 标记或隔离 display name domain ≠ sender domain 的消息。
* 培训用户：将可疑文本复制粘贴到 Unicode inspector 中，悬停查看链接，永远不要信任 URL shorteners。

## Real-World Examples

* Display name：`Сonfidеntiаl Ꭲiꮯkеt`（Cyrillic `С`、`е`、`а`；Cherokee `Ꭲ`；Latin small capital `ꮯ`）。
* Domain chain：`bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ 位于 `mlcorsftpsswddprotcct.approaches.it.com` 的 fake Microsoft login，由 custom OTP CAPTCHA 保护。
* Spotify impersonation：发送者为 `Sρօtifս`，链接隐藏在 `redirects.ca` 后面。

这些样本源自 Unit 42 于 2025 年 7 月开展的研究，说明 homograph abuse 如何与 URL redirection 和 CAPTCHA evasion 结合，从而绕过 automated analysis。<sup>[[1]](#references)</sup>

## References

- [1] [Homograph 幻觉：并非一切都如表面所见](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode 字符代码表](https://www.unicode.org/charts/)
- [3] [Unicode 技术标准 #39：Unicode 安全机制](https://unicode.org/reports/tr39/)
- [4] [dnstwist – 域名变体引擎](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – 域名拼写错误和变体生成器](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890：面向应用的国际化域名（IDNA）：定义和文档框架](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
