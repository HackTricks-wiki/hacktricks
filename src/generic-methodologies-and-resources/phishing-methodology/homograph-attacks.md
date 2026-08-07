# Phishing 中的 Homograph / Homoglyph Attacks

{{#include ../../banners/hacktricks-training.md}}

## 概述

Homograph（也称为 homoglyph）attack 利用了这样一个事实：许多**来自非拉丁脚本的 Unicode code points 在视觉上与 ASCII 字符相同或极其相似**。通过将一个或多个拉丁字符替换为外观相似的字符，攻击者可以构造：

* 对人眼而言看似合法、但能够绕过基于关键词检测的显示名称、主题或消息正文。
* 欺骗受害者，使其相信自己正在访问受信任站点的域名、子域名或 URL 路径。

由于每个 glyph 在内部都由其**Unicode code point**标识，因此只需替换一个字符，就足以击败简单的字符串比较（例如，`"Παypal.com"` 与 `"Paypal.com"`）。

## 常见的 Phishing 工作流程

1. **构造消息内容** – 将被冒充品牌 / 关键词中的特定拉丁字母替换为来自其他脚本（Greek、Cyrillic、Armenian、Cherokee 等）的视觉上无法区分的字符。
2. **注册配套基础设施** – 可选地注册一个 homoglyph domain 并获取 TLS certificate（大多数 CA 不会进行视觉相似性检查）。
3. **发送 email / SMS** – 消息会在以下一个或多个位置包含 homoglyphs：
* Sender display name（例如，`Ηеlрdеѕk`）
* Subject line（`Urgеnt Аctіon Rеquіrеd`）
* Hyperlink text 或 fully qualified domain name
4. **Redirect chain** – 受害者会先被跳转到看似无害的网站或 URL shorteners，随后才到达用于窃取凭据 / 投递 malware 的恶意主机。

## 常被滥用的 Unicode 范围

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: 完整的 Unicode charts 可在 [unicode.org](https://home.unicode.org/) 查看。<sup>[[2]](#references)</sup>

## Detection Techniques

### 1. Mixed-Script Inspection

针对英语组织的 Phishing emails 通常不应混用多个 scripts。一个简单但有效的 heuristic 是：

1. 遍历被检查字符串中的每个字符。
2. 将 code point 映射到其 Unicode block。
3. 如果存在多个 script，**或**在不应出现非拉丁 scripts 的位置（display name、domain、subject、URL 等）发现了它们，则触发 alert。

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
### 2. Punycode 规范化（Domains）

国际化域名（IDN）使用 **punycode**（`xn--`）进行编码。将每个 hostname 转换为 punycode，然后再转换回 Unicode，即可在字符串完成规范化后，与 whitelist 进行匹配或执行相似度检查（例如 Levenshtein distance）。
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph 字典 / 算法

诸如 **dnstwist**（`--homoglyph`）或 **urlcrazy** 之类的工具可以枚举视觉上相似的域名变体，对于主动下架 / 监控非常有用。<sup>[[3]](#references)</sup>

## Prevention & Mitigation

* 强制执行严格的 DMARC/DKIM/SPF 策略，防止来自未经授权域名的 spoofing。
* 在 **Secure Email Gateways** 和 **SIEM/XSOAR** playbooks 中实现上述检测逻辑。
* 对 display name domain ≠ sender domain 的消息进行标记或隔离。
* 教育用户：将可疑文本复制粘贴到 Unicode inspector 中，悬停查看链接，永远不要信任 URL shorteners。

## Real-World Examples

* Display name：`Сonfidеntiаl Ꭲiꮯkеt`（Cyrillic `С`、`е`、`а`；Cherokee `Ꭲ`；Latin small capital `ꮯ`）。
* Domain chain：`bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ 位于 `mlcorsftpsswddprotcct.approaches.it.com` 的 fake Microsoft login，并由 custom OTP CAPTCHA 保护。
* Spotify impersonation：发送者为 `Sρօtifս`，链接隐藏在 `redirects.ca` 后面。

这些样本源自 Unit 42 的研究（2025 年 7 月），展示了 homograph abuse 如何与 URL redirection 和 CAPTCHA evasion 结合，以绕过 automated analysis。<sup>[[1]](#references)</sup>

## References

- [1] [Homograph Illusion：并非一切都如表面所见](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
