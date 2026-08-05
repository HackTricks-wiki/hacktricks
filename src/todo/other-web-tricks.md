# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

有时后端会信任 **Host header** 来执行某些操作。例如，它可能会将其值用作**发送密码重置邮件的域名**。因此，当你收到一封包含密码重置链接的邮件时，其中使用的域名就是你在 Host header 中设置的域名。然后，你可以请求重置其他用户的密码，并将域名修改为由你控制的域名，以窃取他们的密码重置代码。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)。<sup>[[1]](#references)</sup>

> [!WARNING]
> 请注意，你甚至可能不需要等待用户点击密码重置链接即可获取 token，因为**spam filters 或其他中间设备/bots 可能会点击该链接来分析它**。

### Session booleans

有时，当你正确完成某项验证后，后端**只会向 session 的某个安全属性添加一个值为 "True" 的 boolean**。随后，另一个 endpoint 会通过该属性判断你是否成功通过了检查。\
然而，如果你**通过了检查**，并且 session 的安全属性获得了 "True" 值，那么你可以尝试**访问其他依赖相同属性的资源**，即使你**本不应具有访问权限**。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)。<sup>[[2]](#references)</sup>

### Register functionality

尝试注册一个已经存在的用户。也可以尝试使用等价字符（点号、大量空格和 Unicode）。

### Takeover emails

注册一个 email，在确认之前修改该 email；然后，如果新的确认邮件被发送到第一个注册的 email，你就可以 takeover 任意 email。或者，如果你可以通过确认第一个 email 来启用第二个 email，那么你也可以 takeover 任意 account。

### Access Internal servicedesk of companies using atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

开发人员可能会忘记在 production environment 中禁用各种 debugging 选项。例如，HTTP `TRACE` method 是为诊断目的而设计的。如果启用，web server 会响应使用 `TRACE` method 的请求，并在响应中原样回显收到的完整请求。这种行为通常无害，但有时会导致信息泄露，例如暴露可能由 reverse proxies 附加到请求中的内部 authentication headers 名称。![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
