# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## 概述

同形异义词（又称同形字）攻击利用了许多**来自非拉丁脚本的Unicode代码点在视觉上与ASCII字符完全相同或极为相似**的事实。通过用一个或多个外观相似的字符替换拉丁字符，攻击者可以制作：

* 看起来对人眼合法的显示名称、主题或消息正文，但可以绕过基于关键字的检测。
* 让受害者相信他们正在访问受信任网站的域名、子域名或URL路径。

因为每个字形在内部是通过其**Unicode代码点**来识别的，单个替换字符就足以击败简单的字符串比较（例如，`"Παypal.com"`与`"Paypal.com"`）。

## 典型钓鱼工作流程

1. **制作消息内容** – 用来自另一种脚本（希腊文、斯拉夫文、亚美尼亚文、切罗基文等）中视觉上无法区分的字符替换被模仿品牌/关键字中的特定拉丁字母。
2. **注册支持基础设施** – 可选地注册一个同形字域名并获得TLS证书（大多数CA不进行视觉相似性检查）。
3. **发送电子邮件/SMS** – 消息在以下一个或多个位置包含同形字：
* 发件人显示名称（例如，`Ηеlрdеѕk`）
* 主题行（`Urgеnt Аctіon Rеquіrеd`）
* 超链接文本或完全合格的域名
4. **重定向链** – 受害者通过看似无害的网站或URL缩短器被转发，然后落在收集凭据/投放恶意软件的恶意主机上。

## 常被滥用的Unicode范围

| 脚本   | 范围         | 示例字形     | 看起来像   |
|--------|--------------|--------------|------------|
| 希腊文 | U+0370-03FF | `Η` (U+0397) | 拉丁字母 `H` |
| 希腊文 | U+0370-03FF | `ρ` (U+03C1) | 拉丁字母 `p` |
| 斯拉夫文 | U+0400-04FF | `а` (U+0430) | 拉丁字母 `a` |
| 斯拉夫文 | U+0400-04FF | `е` (U+0435) | 拉丁字母 `e` |
| 亚美尼亚文 | U+0530-058F | `օ` (U+0585) | 拉丁字母 `o` |
| 切罗基文 | U+13A0-13FF | `Ꭲ` (U+13A2) | 拉丁字母 `T` |

> 提示：完整的Unicode图表可在 [unicode.org](https://home.unicode.org/) 获取。

## 检测技术

### 1. 混合脚本检查

针对英语组织的钓鱼电子邮件应该很少混合来自多个脚本的字符。一个简单但有效的启发式方法是：

1. 遍历被检查字符串的每个字符。
2. 将代码点映射到其Unicode块。
3. 如果存在多个脚本**或**在不应出现的地方（显示名称、域名、主题、URL等）出现非拉丁脚本，则发出警报。

Python概念验证：
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
### 2. Punycode 正规化 (域名)

国际化域名 (IDN) 使用 **punycode** 编码 (`xn--`)。将每个主机名转换为 punycode 然后再转换回 Unicode 允许在字符串被正规化 **后** 进行白名单匹配或相似性检查（例如，Levenshtein 距离）。
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. 同形字典 / 算法

工具如 **dnstwist** (`--homoglyph`) 或 **urlcrazy** 可以枚举视觉上相似的域名排列，对于主动下架 / 监控非常有用。

## 预防与缓解

* 强制执行严格的 DMARC/DKIM/SPF 策略 – 防止来自未授权域的欺骗。
* 在 **Secure Email Gateways** 和 **SIEM/XSOAR** 方案中实施上述检测逻辑。
* 标记或隔离显示名称域名 ≠ 发件人域名的消息。
* 教育用户：将可疑文本复制粘贴到 Unicode 检查器中，悬停链接，永远不要信任 URL 短链接。

## 现实世界示例

* 显示名称: `Сonfidеntiаl Ꭲiꮯkеt` (西里尔字母 `С`, `е`, `а`; 切罗基 `Ꭲ`; 拉丁小写大写 `ꮯ`)。
* 域名链: `bestseoservices.com` ➜ 市政 `/templates` 目录 ➜ `kig.skyvaulyt.ru` ➜ 假冒的 Microsoft 登录在 `mlcorsftpsswddprotcct.approaches.it.com` 受自定义 OTP CAPTCHA 保护。
* Spotify 冒充: `Sρօtifŭ` 发件人，链接隐藏在 `redirects.ca` 后面。

这些示例来源于 Unit 42 研究（2025 年 7 月），展示了同形字滥用如何与 URL 重定向和 CAPTCHA 规避结合，以绕过自动分析。

## 参考文献

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
