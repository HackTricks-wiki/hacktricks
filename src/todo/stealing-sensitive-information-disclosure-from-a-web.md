# 从 Web 页面窃取敏感信息

{{#include ../banners/hacktricks-training.md}}

如果一个 **Web 页面根据当前会话显示敏感信息**，例如 cookies、账户数据或信用卡详细信息，攻击者可能会尝试将其 exfiltrate。主要技术包括：

- [**CORS bypass**](../pentesting-web/cors-bypass.md)：CORS 配置错误可能允许恶意 origin 通过跨源请求读取敏感响应。
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html)：目标 origin 中的 XSS 漏洞可能允许注入的 JavaScript 读取并 exfiltrate 相关信息。
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html)：当无法进行 script 注入时，注入的 HTML 元素仍可能捕获敏感内容。
- [**Clickjacking**](../pentesting-web/clickjacking.md)：如果缺少 frame 防护，攻击者可能诱骗用户与敏感页面进行交互。链接的案例研究演示了这一技术。<sup>[[1]](#references)</sup>

## References

- [1] [Apache 示例 servlet 导致 Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
