# 从网页窃取敏感信息泄露

{{#include ../banners/hacktricks-training.md}}

如果在某个时刻你发现一个**根据你的会话向你展示敏感信息的网页**：也许它反映了 cookies，或者打印了信用卡详情或其他任何敏感信息，你可以尝试窃取它。\
在这里，我向你展示主要的几种尝试实现这一目标的方法：

- [**CORS 绕过**](../pentesting-web/cors-bypass.md)：如果你可以绕过 CORS 头，你将能够通过对恶意页面执行 Ajax 请求来窃取信息。
- [**XSS**](../pentesting-web/xss-cross-site-scripting/): 如果你在页面上发现 XSS 漏洞，你可能能够利用它来窃取信息。
- [**悬挂标记**](../pentesting-web/dangling-markup-html-scriptless-injection/): 如果你无法注入 XSS 标签，你仍然可以使用其他常规 HTML 标签来窃取信息。
- [**点击劫持**](../pentesting-web/clickjacking.md)：如果没有针对这种攻击的保护，你可能能够欺骗用户向你发送敏感数据（示例[在这里](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)）。

{{#include ../banners/hacktricks-training.md}}
