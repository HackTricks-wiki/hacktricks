# 其他 Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

后端有时会信任 **Host header** 来执行某些操作。例如，它可能会将其值用作**发送密码重置链接的域名**。因此，当你收到一封包含密码重置链接的邮件时，所使用的域名就是你在 Host header 中设置的域名。然后，你可以请求重置其他用户的密码，并将域名修改为由你控制的域名，从而窃取他们的密码重置代码。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)。<sup>[[1]](#references)</sup>

> [!WARNING]
> 注意，你甚至可能不需要等待用户点击密码重置链接就能获取 token，因为**spam filters 或其他中间设备/bots 可能会点击该链接来分析它**。

### Session booleans

有时，当你正确完成某项验证后，后端**只会向你 session 的某个安全属性添加一个值为 "True" 的 boolean**。随后，另一个 endpoint 会判断你是否成功通过了该检查。\
但是，如果你**通过了检查**，并且你的 session 在该安全属性中获得了 "True" 值，那么你可以尝试**访问其他依赖同一属性的资源**，尽管你**本不应该拥有访问权限**。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)。<sup>[[2]](#references)</sup>

### Register functionality

尝试注册为一个已经存在的用户。也可以尝试使用等效字符（点号、大量空格和 Unicode）。

### Takeover emails

注册一个 email，在确认它之前修改该 email；如果新的确认 email 被发送到最初注册的 email，你就可以 takeover 任意 email。或者，如果你可以通过确认第一个 email 来启用第二个 email，那么你也可以 takeover 任意 account。

### 使用 atlassian 访问公司的内部 servicedesk


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

开发人员可能会忘记在 production environment 中禁用各种 debugging 选项。例如，HTTP `TRACE` method 用于诊断目的。如果启用，web server 将通过在响应中回显收到的完整 request，来响应使用 `TRACE` method 的请求。这种行为通常无害，但有时会导致 information disclosure，例如泄露 reverse proxies 可能附加到请求中的内部 authentication headers 的名称。![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
