# 其他 Web Tricks

{{#include ../banners/hacktricks-training.md}}

## Host header

后端有时会信任 HTTP `Host` 字段来构造绝对链接。如果密码重置邮件使用了攻击者提供的主机名，攻击者可以为受害者请求重置，使包含 token 的链接通过攻击者控制的域名发送出去。还应在每个代理跃点测试 forwarded-host 字段、重复 Host 的处理方式，以及 absolute-form 请求目标。<sup>[[1]](#references)</sup>

> [!WARNING]
> 可能不需要用户点击：**邮件安全扫描器、预览服务或其他中间件可能会自动请求攻击者控制的链接**，从而泄露重置 token。

## Session booleans

某些应用会在 session 中将完成验证记录为布尔值，然后让其他 endpoint 依赖该标志。针对某个资源合法通过检查后，测试同一个标志是否会错误地授权访问其他用户、对象或工作流。这属于二阶授权/状态复用漏洞，而不只是 IDOR。<sup>[[2]](#references)</sup>

## Registration functionality

尝试注册一个已经存在的用户。还可以尝试使用等价字符（点号、大量空格和 Unicode）。

## Email-change state confusion

注册一个 email 地址，并在确认前修改它。检查新地址的确认邮件是否被发送到旧地址，或者确认旧 token 是否会激活新地址。确认 token 必须绑定到确切的账户、待确认地址、用途和当前状态。

## Exposed Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

HTTP `TRACE` method 会请求回显收到的请求，用于诊断。RFC 9110 要求接收方从回显内容中省略凭据和 cookies 等敏感字段，但不安全的实现或由中间件添加的 headers 仍可能泄露内部请求转换过程。浏览器会阻止脚本生成 TRACE 请求，因此历史上的跨站追踪攻击还依赖另一种注入受保护字段的方式。<sup>[[3]](#references)</sup>![显示 TRACE 响应的图片](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![post 图片](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [我如何通过 Host Header Injection 接管任意用户的账户](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [一个较少人知的攻击向量：Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110，第 9.3.8 节 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
