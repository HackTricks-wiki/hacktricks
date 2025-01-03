{{#include ../../banners/hacktricks-training.md}}

互联网上有几个博客**强调了将打印机配置为使用默认/弱**登录凭据的LDAP的危险。\
这是因为攻击者可能会**欺骗打印机向一个恶意的LDAP服务器进行身份验证**（通常`nc -vv -l -p 444`就足够了），并捕获打印机**以明文形式传输的凭据**。

此外，一些打印机将包含**带有用户名的日志**，甚至可能能够**从域控制器下载所有用户名**。

所有这些**敏感信息**和普遍的**安全缺失**使得打印机对攻击者非常有吸引力。

关于该主题的一些博客：

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## 打印机配置

- **位置**：LDAP服务器列表位于：`Network > LDAP Setting > Setting Up LDAP`。
- **行为**：该界面允许在不重新输入凭据的情况下修改LDAP服务器，旨在方便用户，但带来了安全风险。
- **利用**：该利用涉及将LDAP服务器地址重定向到受控机器，并利用“测试连接”功能捕获凭据。

## 捕获凭据

**有关更详细的步骤，请参阅原始[来源](https://grimhacker.com/2018/03/09/just-a-printer/)。**

### 方法 1：Netcat 监听器

一个简单的netcat监听器可能就足够了：
```bash
sudo nc -k -v -l -p 386
```
然而，这种方法的成功率有所不同。

### 方法 2：完整的 LDAP 服务器与 Slapd

一种更可靠的方法是设置一个完整的 LDAP 服务器，因为打印机在尝试凭证绑定之前会执行空绑定，然后进行查询。

1. **LDAP 服务器设置**：该指南遵循来自 [this source](https://www.server-world.info/en/note?os=Fedora_26&p=openldap) 的步骤。
2. **关键步骤**：
- 安装 OpenLDAP。
- 配置管理员密码。
- 导入基本架构。
- 在 LDAP 数据库上设置域名。
- 配置 LDAP TLS。
3. **LDAP 服务执行**：设置完成后，可以使用以下命令运行 LDAP 服务：
```bash
slapd -d 2
```
## 参考文献

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
