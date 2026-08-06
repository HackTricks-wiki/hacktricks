# 从 Web 窃取敏感信息泄露

{{#include ../banners/hacktricks-training.md}}

如果你在某个时候发现一个**根据你的 session 向你呈现敏感信息的 web 页面**：可能是反射 cookies，或者打印密码、CC 详细信息或任何其他敏感信息，你可以尝试窃取这些信息。\
下面介绍实现这一目标时可以尝试的主要方法：

- [**CORS bypass**](../pentesting-web/cors-bypass.md)：如果你可以绕过 CORS headers，就能够通过向恶意页面执行 Ajax 请求来窃取信息。
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html)：如果你在页面上发现 XSS 漏洞，可能可以滥用它来窃取信息。
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html)：即使无法注入 XSS tags，你仍然可能通过使用其他常规 HTML tags 来窃取信息。
- [**Clickjaking**](../pentesting-web/clickjacking.md)：如果没有针对该攻击的保护措施，你可能可以诱骗用户向你发送敏感数据（示例见[这里](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)）。<sup>[[1]](#references)</sup>

## 参考资料

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
