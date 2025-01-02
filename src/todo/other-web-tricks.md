# 其他网络技巧

{{#include ../banners/hacktricks-training.md}}

### 主机头

几次后端信任 **Host header** 来执行某些操作。例如，它可能会使用其值作为 **发送密码重置的域**。因此，当您收到一封包含重置密码链接的电子邮件时，使用的域是您在 Host header 中输入的域。然后，您可以请求其他用户的密码重置，并将域更改为您控制的域，以窃取他们的密码重置代码。 [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)。

> [!WARNING]
> 请注意，您甚至可能不需要等待用户点击重置密码链接来获取令牌，因为 **垃圾邮件过滤器或其他中介设备/机器人可能会点击它以进行分析**。

### 会话布尔值

有时，当您正确完成某些验证时，后端会 **仅将值为 "True" 的布尔值添加到您的会话的安全属性中**。然后，另一个端点将知道您是否成功通过了该检查。\
然而，如果您 **通过检查** 并且您的会话在安全属性中获得了 "True" 值，您可以尝试 **访问其他资源**，这些资源 **依赖于相同的属性**，但您 **不应该有权限** 访问。 [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)。

### 注册功能

尝试以已存在用户的身份注册。还可以尝试使用等效字符（点、多个空格和 Unicode）。

### 接管电子邮件

注册一个电子邮件，在确认之前更改电子邮件，然后，如果新的确认电子邮件发送到第一个注册的电子邮件，您可以接管任何电子邮件。或者，如果您可以启用第二个电子邮件以确认第一个电子邮件，您也可以接管任何账户。

### 访问使用 Atlassian 的公司的内部服务台

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE 方法

开发人员可能会忘记在生产环境中禁用各种调试选项。例如，HTTP `TRACE` 方法是为诊断目的而设计的。如果启用，web 服务器将通过在响应中回显收到的确切请求来响应使用 `TRACE` 方法的请求。这种行为通常是无害的，但偶尔会导致信息泄露，例如可能由反向代理附加到请求的内部身份验证头的名称。![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
